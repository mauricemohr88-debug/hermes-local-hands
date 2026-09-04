"""Private, transaction-safe SQLite persistence.

The database stores hashes of bearer credentials, never the credentials themselves. A
single connection is shared deliberately, so every access is serialized with an ``RLock``.
SQLite's ``BEGIN IMMEDIATE`` additionally serializes writers that use separate ``Store``
instances or processes.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .errors import ConflictError, NotFoundError
from .models import PendingRequest, RequestKind, RequestState, WorkspacePolicy

DEFAULT_CLIENT_PENDING_LIMIT = 32
DEFAULT_GLOBAL_PENDING_LIMIT = 256
DEFAULT_CLIENT_TOTAL_REQUEST_LIMIT = 512
DEFAULT_TOTAL_REQUEST_LIMIT = 2_048
_GENESIS_HASH = "0" * 64


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def request_fingerprint(request: PendingRequest) -> str:
    """Fingerprint all caller-controlled, immutable request semantics.

    Server-generated identifiers and timestamps are intentionally excluded: retrying an
    idempotent operation can produce a new candidate ID/time before this store discovers the
    original row. Client identity and the idempotency key are included even though the lookup
    is already client-scoped, making corruption or an incorrect query fail closed.
    """

    body = {
        "schema": 1,
        "client_id": request.client_id,
        "idempotency_key": request.idempotency_key,
        "kind": request.kind.value,
        "workspace_id": request.workspace_id,
        "payload": request.payload,
        "base_head": request.base_head,
        "policy_hash": request.policy_hash,
    }
    return sha256_text(canonical_json(body))


class Store:
    def __init__(self, path: str) -> None:
        file_path = Path(path).expanduser()
        self.path = str(file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.RLock()
        self._transaction_state = threading.local()
        self.connection = sqlite3.connect(
            str(file_path), isolation_level=None, check_same_thread=False, timeout=5.0
        )
        if os.name == "posix":
            os.chmod(file_path, 0o600)
        self.connection.row_factory = sqlite3.Row
        with self._lock:
            self.connection.execute("PRAGMA foreign_keys = ON")
            self.connection.execute("PRAGMA busy_timeout = 5000")
            self.connection.execute("PRAGMA journal_mode = WAL")
            self.connection.execute("PRAGMA synchronous = FULL")
        self._migrate()

    @contextmanager
    def transaction(self) -> Iterator[Store]:
        """Run a nested-safe immediate transaction while holding the connection lock.

        Callers can wrap a state transition and a receipt append in this context; nested store
        calls and ``ReceiptLedger.append`` use savepoints and remain part of the outer commit.
        """

        with self._lock:
            depth = int(getattr(self._transaction_state, "depth", 0))
            savepoint = f"local_hands_{depth}"
            if depth == 0:
                self.connection.execute("BEGIN IMMEDIATE")
            else:
                self.connection.execute(f"SAVEPOINT {savepoint}")
            self._transaction_state.depth = depth + 1
            try:
                yield self
            except BaseException:
                if depth == 0:
                    self.connection.execute("ROLLBACK")
                else:
                    self.connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                    self.connection.execute(f"RELEASE SAVEPOINT {savepoint}")
                raise
            else:
                if depth == 0:
                    self.connection.execute("COMMIT")
                else:
                    self.connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            finally:
                self._transaction_state.depth = depth

    def _migrate(self) -> None:
        with self.transaction():
            self.connection.execute("""
                CREATE TABLE IF NOT EXISTS clients (
                  client_id TEXT PRIMARY KEY,
                  token_hash TEXT NOT NULL UNIQUE,
                  created_at TEXT NOT NULL
                )
            """)
            self.connection.execute("""
                CREATE TABLE IF NOT EXISTS workspaces (
                  workspace_id TEXT PRIMARY KEY,
                  root TEXT NOT NULL UNIQUE,
                  policy_json TEXT NOT NULL,
                  policy_hash TEXT NOT NULL
                )
            """)
            self.connection.execute("""
                CREATE TABLE IF NOT EXISTS client_workspace_grants (
                  client_id TEXT NOT NULL,
                  workspace_id TEXT NOT NULL,
                  granted_at TEXT NOT NULL,
                  PRIMARY KEY(client_id, workspace_id),
                  FOREIGN KEY(client_id) REFERENCES clients(client_id) ON DELETE CASCADE,
                  FOREIGN KEY(workspace_id) REFERENCES workspaces(workspace_id) ON DELETE CASCADE
                )
            """)
            self.connection.execute("""
                CREATE TABLE IF NOT EXISTS metadata (
                  key TEXT PRIMARY KEY,
                  value TEXT NOT NULL
                )
            """)
            self._ensure_requests_schema()
            self._ensure_receipts_schema()

    def _create_requests_table(self, table: str = "requests") -> None:
        if table not in {"requests", "requests_v2"}:  # table names cannot bind
            raise ValueError("unsupported migration table")
        self.connection.execute(f"""
            CREATE TABLE {table} (
              request_id TEXT PRIMARY KEY,
              kind TEXT NOT NULL,
              workspace_id TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              idempotency_key TEXT NOT NULL,
              base_head TEXT NOT NULL,
              policy_hash TEXT NOT NULL,
              state TEXT NOT NULL,
              created_at TEXT NOT NULL,
              client_id TEXT NOT NULL DEFAULT '',
              expires_at TEXT NOT NULL DEFAULT '',
              request_fingerprint TEXT NOT NULL,
              result_json TEXT,
              FOREIGN KEY(workspace_id) REFERENCES workspaces(workspace_id),
              UNIQUE(client_id, idempotency_key)
            )
        """)

    def _ensure_requests_schema(self) -> None:
        exists = self.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='requests'"
        ).fetchone()
        if exists is None:
            self._create_requests_table()
            return

        columns = {
            str(row["name"]) for row in self.connection.execute("PRAGMA table_info(requests)")
        }
        required = {"client_id", "expires_at", "request_fingerprint", "result_json"}
        scoped_unique = False
        global_unique = False
        for index in self.connection.execute("PRAGMA index_list(requests)"):
            if not int(index["unique"]):
                continue
            index_name = str(index["name"]).replace("'", "''")
            names = [
                str(row["name"])
                for row in self.connection.execute(f"PRAGMA index_info('{index_name}')")
            ]
            scoped_unique = scoped_unique or names == ["client_id", "idempotency_key"]
            global_unique = global_unique or names == ["idempotency_key"]
        if required.issubset(columns) and scoped_unique and not global_unique:
            return

        rows = list(self.connection.execute("SELECT * FROM requests"))
        self._create_requests_table("requests_v2")
        for row in rows:
            keys = set(row.keys())
            client_id = str(row["client_id"]) if "client_id" in keys else ""
            expires_at = (
                str(row["expires_at"])
                if "expires_at" in keys and row["expires_at"]
                else str(row["created_at"])
            )
            request = PendingRequest(
                request_id=str(row["request_id"]),
                kind=RequestKind(str(row["kind"])),
                workspace_id=str(row["workspace_id"]),
                payload=json.loads(str(row["payload_json"])),
                idempotency_key=str(row["idempotency_key"]),
                base_head=str(row["base_head"]),
                policy_hash=str(row["policy_hash"]),
                state=RequestState(str(row["state"])),
                created_at=str(row["created_at"]),
                client_id=client_id,
                expires_at=expires_at,
                result=(
                    json.loads(str(row["result_json"]))
                    if "result_json" in keys and row["result_json"] is not None
                    else None
                ),
            )
            self._insert_request("requests_v2", request, request_fingerprint(request))
        self.connection.execute("DROP TABLE requests")
        self.connection.execute("ALTER TABLE requests_v2 RENAME TO requests")

    def _ensure_receipts_schema(self) -> None:
        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS receipts (
              sequence INTEGER PRIMARY KEY AUTOINCREMENT,
              schema INTEGER NOT NULL DEFAULT 1,
              receipt_id TEXT NOT NULL UNIQUE,
              occurred_at TEXT NOT NULL,
              event TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              previous_hash TEXT NOT NULL,
              receipt_hash TEXT NOT NULL UNIQUE,
              signature TEXT NOT NULL
            )
        """)
        columns = {
            str(row["name"]) for row in self.connection.execute("PRAGMA table_info(receipts)")
        }
        if "schema" not in columns:
            self.connection.execute(
                "ALTER TABLE receipts ADD COLUMN schema INTEGER NOT NULL DEFAULT 1"
            )
        # One parent can have only one successor. Combined with an immediate transaction in
        # append_receipt this prevents concurrent writers from forking the ledger.
        self.connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS receipts_one_child ON receipts(previous_hash)"
        )

    def close(self) -> None:
        with self._lock:
            self.connection.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def add_client(self, client_id: str, bearer_token: str, created_at: str) -> None:
        if not client_id or not bearer_token:
            raise ValueError("client id and bearer token are required")
        try:
            with self._lock:
                self.connection.execute(
                    "INSERT INTO clients VALUES (?, ?, ?)",
                    (client_id, sha256_text(bearer_token), created_at),
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("client id or credential already exists") from exc

    def authenticate(self, bearer_token: str) -> str | None:
        with self._lock:
            row = self.connection.execute(
                "SELECT client_id FROM clients WHERE token_hash=?",
                (sha256_text(bearer_token),),
            ).fetchone()
        return None if row is None else str(row["client_id"])

    def list_clients(self) -> list[dict[str, str]]:
        with self._lock:
            rows = list(
                self.connection.execute(
                    "SELECT client_id, created_at FROM clients ORDER BY client_id"
                )
            )
        return [
            {"client_id": str(row["client_id"]), "created_at": str(row["created_at"])}
            for row in rows
        ]

    def revoke_client(self, client_id: str) -> bool:
        with self._lock:
            deleted = self.connection.execute(
                "DELETE FROM clients WHERE client_id=?", (client_id,)
            ).rowcount
        if deleted != 1:
            raise NotFoundError("client not found")
        return True

    def save_workspace(
        self,
        policy: WorkspacePolicy,
        policy_hash: str,
        *,
        grant_existing_clients: bool = False,
        granted_at: str | None = None,
    ) -> None:
        if grant_existing_clients and not granted_at:
            raise ValueError("granted_at is required when granting existing clients")
        try:
            with self.transaction():
                self.connection.execute(
                    "INSERT INTO workspaces VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(workspace_id) DO UPDATE SET "
                    "root=excluded.root, policy_json=excluded.policy_json, "
                    "policy_hash=excluded.policy_hash",
                    (
                        policy.workspace_id,
                        policy.root,
                        canonical_json(policy.to_dict()),
                        policy_hash,
                    ),
                )
                if grant_existing_clients:
                    self.connection.execute(
                        "INSERT OR IGNORE INTO client_workspace_grants "
                        "(client_id, workspace_id, granted_at) "
                        "SELECT client_id, ?, ? FROM clients",
                        (policy.workspace_id, granted_at),
                    )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("workspace id or root is already registered") from exc

    def workspace(self, workspace_id: str) -> tuple[WorkspacePolicy, str]:
        with self._lock:
            row = self.connection.execute(
                "SELECT policy_json, policy_hash FROM workspaces WHERE workspace_id=?",
                (workspace_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError("workspace not registered")
        return self._workspace_from_row(row)

    @staticmethod
    def _workspace_from_row(row: sqlite3.Row) -> tuple[WorkspacePolicy, str]:
        raw = json.loads(str(row["policy_json"]))
        policy = WorkspacePolicy(
            workspace_id=raw["workspace_id"],
            root=raw["root"],
            read_allowlist=tuple(raw["read_allowlist"]),
            test_profiles={k: tuple(v) for k, v in raw.get("test_profiles", {}).items()},
            max_read_bytes=raw.get("max_read_bytes", 262_144),
            write_allowlist=tuple(raw.get("write_allowlist", ())),
        )
        return policy, str(row["policy_hash"])

    def workspace_for_client(
        self, client_id: str, workspace_id: str
    ) -> tuple[WorkspacePolicy, str]:
        """Load a granted policy through one atomic joined read."""

        with self._lock:
            row = self.connection.execute(
                "SELECT w.policy_json, w.policy_hash "
                "FROM workspaces AS w "
                "JOIN client_workspace_grants AS g ON g.workspace_id=w.workspace_id "
                "JOIN clients AS c ON c.client_id=g.client_id "
                "WHERE w.workspace_id=? AND g.client_id=?",
                (workspace_id, client_id),
            ).fetchone()
        if row is None:
            raise NotFoundError("workspace grant not found")
        return self._workspace_from_row(row)

    def list_workspaces(self) -> list[WorkspacePolicy]:
        with self._lock:
            ids = [
                str(row["workspace_id"])
                for row in self.connection.execute(
                    "SELECT workspace_id FROM workspaces ORDER BY workspace_id"
                )
            ]
        return [self.workspace(workspace_id)[0] for workspace_id in ids]

    def grant_workspace(self, client_id: str, workspace_id: str, granted_at: str) -> bool:
        with self.transaction():
            if (
                self.connection.execute(
                    "SELECT 1 FROM clients WHERE client_id=?", (client_id,)
                ).fetchone()
                is None
            ):
                raise NotFoundError("client not found")
            if (
                self.connection.execute(
                    "SELECT 1 FROM workspaces WHERE workspace_id=?", (workspace_id,)
                ).fetchone()
                is None
            ):
                raise NotFoundError("workspace not registered")
            cursor = self.connection.execute(
                "INSERT OR IGNORE INTO client_workspace_grants "
                "(client_id, workspace_id, granted_at) VALUES (?, ?, ?)",
                (client_id, workspace_id, granted_at),
            )
        return cursor.rowcount == 1

    def replace_workspace_grants(
        self, workspace_id: str, client_ids: tuple[str, ...], granted_at: str
    ) -> None:
        """Replace a workspace's grants exactly, within the caller's transaction."""

        with self.transaction():
            if (
                self.connection.execute(
                    "SELECT 1 FROM workspaces WHERE workspace_id=?", (workspace_id,)
                ).fetchone()
                is None
            ):
                raise NotFoundError("workspace not registered")
            for client_id in client_ids:
                if (
                    self.connection.execute(
                        "SELECT 1 FROM clients WHERE client_id=?", (client_id,)
                    ).fetchone()
                    is None
                ):
                    raise NotFoundError("client not found")
            self.connection.execute(
                "DELETE FROM client_workspace_grants WHERE workspace_id=?", (workspace_id,)
            )
            self.connection.executemany(
                "INSERT INTO client_workspace_grants "
                "(client_id, workspace_id, granted_at) VALUES (?, ?, ?)",
                ((client_id, workspace_id, granted_at) for client_id in client_ids),
            )

    def revoke_workspace_grant(self, client_id: str, workspace_id: str) -> bool:
        with self._lock:
            return (
                self.connection.execute(
                    "DELETE FROM client_workspace_grants WHERE client_id=? AND workspace_id=?",
                    (client_id, workspace_id),
                ).rowcount
                == 1
            )

    def client_has_workspace_access(self, client_id: str, workspace_id: str) -> bool:
        with self._lock:
            return (
                self.connection.execute(
                    "SELECT 1 FROM client_workspace_grants WHERE client_id=? AND workspace_id=?",
                    (client_id, workspace_id),
                ).fetchone()
                is not None
            )

    def workspace_ids_for_client(self, client_id: str) -> list[str]:
        with self._lock:
            return [
                str(row["workspace_id"])
                for row in self.connection.execute(
                    "SELECT workspace_id FROM client_workspace_grants "
                    "WHERE client_id=? ORDER BY workspace_id",
                    (client_id,),
                )
            ]

    def client_ids_for_workspace(self, workspace_id: str) -> list[str]:
        with self._lock:
            return [
                str(row["client_id"])
                for row in self.connection.execute(
                    "SELECT client_id FROM client_workspace_grants "
                    "WHERE workspace_id=? ORDER BY client_id",
                    (workspace_id,),
                )
            ]

    def _insert_request(
        self, table: str, request: PendingRequest, fingerprint: str
    ) -> sqlite3.Cursor:
        if table not in {"requests", "requests_v2"}:
            raise ValueError("unsupported request table")
        result_json = None if request.result is None else canonical_json(request.result)
        return self.connection.execute(
            f"INSERT INTO {table} "  # noqa: S608 -- table is validated above
            "(request_id,kind,workspace_id,payload_json,idempotency_key,base_head,"
            "policy_hash,state,created_at,client_id,expires_at,request_fingerprint,result_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                request.request_id,
                request.kind.value,
                request.workspace_id,
                canonical_json(request.payload),
                request.idempotency_key,
                request.base_head,
                request.policy_hash,
                request.state.value,
                request.created_at,
                request.client_id,
                request.expires_at,
                fingerprint,
                result_json,
            ),
        )

    def add_request(
        self,
        request: PendingRequest,
        *,
        max_pending_per_client: int = DEFAULT_CLIENT_PENDING_LIMIT,
        max_pending_global: int = DEFAULT_GLOBAL_PENDING_LIMIT,
        max_total_per_client: int = DEFAULT_CLIENT_TOTAL_REQUEST_LIMIT,
        max_total_requests: int = DEFAULT_TOTAL_REQUEST_LIMIT,
    ) -> PendingRequest:
        if not request.idempotency_key:
            raise ValueError("idempotency key is required")
        if not request.expires_at:
            raise ValueError("request expiry is required")
        if (
            min(
                max_pending_per_client,
                max_pending_global,
                max_total_per_client,
                max_total_requests,
            )
            < 1
        ):
            raise ValueError("request limits must be positive")
        fingerprint = request_fingerprint(request)
        with self.transaction():
            existing = self.connection.execute(
                "SELECT * FROM requests WHERE client_id=? AND idempotency_key=?",
                (request.client_id, request.idempotency_key),
            ).fetchone()
            if existing is not None:
                if str(existing["request_fingerprint"]) != fingerprint:
                    raise ConflictError("idempotency key was already used with another request")
                return self._row_request(existing)
            if self.total_request_count() >= max_total_requests:
                raise ConflictError("total retained request quota exceeded")
            if self.total_request_count(client_id=request.client_id) >= max_total_per_client:
                raise ConflictError("client retained request quota exceeded")
            if self.count_pending_requests(client_id=request.client_id) >= max_pending_per_client:
                raise ConflictError("client pending request quota exceeded")
            if self.count_pending_requests() >= max_pending_global:
                raise ConflictError("global pending request quota exceeded")
            try:
                self._insert_request("requests", request, fingerprint)
            except sqlite3.IntegrityError as exc:
                # Never resolve a collision through an unscoped query: a colliding request ID
                # or another client's idempotency key must not disclose their row.
                raise ConflictError("request identity conflict") from exc
        return request

    def request(self, request_id: str, client_id: str | None = None) -> PendingRequest:
        query = "SELECT * FROM requests WHERE request_id=?"
        parameters: tuple[str, ...] = (request_id,)
        if client_id is not None:
            query += " AND client_id=?"
            parameters += (client_id,)
        with self._lock:
            row = self.connection.execute(query, parameters).fetchone()
        if row is None:
            raise NotFoundError("request not found")
        return self._row_request(row)

    def list_requests(
        self,
        workspace_id: str | None = None,
        *,
        state: RequestState | str | None = None,
        client_id: str | None = None,
    ) -> list[PendingRequest]:
        clauses: list[str] = []
        parameters: list[str] = []
        if workspace_id is not None:
            clauses.append("workspace_id=?")
            parameters.append(workspace_id)
        if state is not None:
            clauses.append("state=?")
            parameters.append(RequestState(state).value)
        if client_id is not None:
            clauses.append("client_id=?")
            parameters.append(client_id)
        query = "SELECT * FROM requests"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC, request_id DESC"
        with self._lock:
            rows = list(self.connection.execute(query, tuple(parameters)))
        return [self._row_request(row) for row in rows]

    def count_requests_since(self, client_id: str, created_after: str) -> int:
        """Count all new request records for one client at/after an ISO-8601 boundary."""

        with self._lock:
            row = self.connection.execute(
                "SELECT COUNT(*) AS count FROM requests WHERE client_id=? AND created_at>=?",
                (client_id, created_after),
            ).fetchone()
        return int(row["count"])

    def total_request_count(self, *, client_id: str | None = None) -> int:
        with self._lock:
            if client_id is None:
                row = self.connection.execute("SELECT COUNT(*) AS count FROM requests").fetchone()
            else:
                row = self.connection.execute(
                    "SELECT COUNT(*) AS count FROM requests WHERE client_id=?",
                    (client_id,),
                ).fetchone()
        return int(row["count"])

    def count_pending_requests(
        self, *, client_id: str | None = None, workspace_id: str | None = None
    ) -> int:
        clauses = ["state=?"]
        parameters = [RequestState.PENDING.value]
        if client_id is not None:
            clauses.append("client_id=?")
            parameters.append(client_id)
        if workspace_id is not None:
            clauses.append("workspace_id=?")
            parameters.append(workspace_id)
        with self._lock:
            row = self.connection.execute(
                "SELECT COUNT(*) AS count FROM requests WHERE "  # noqa: S608
                + " AND ".join(clauses),
                tuple(parameters),
            ).fetchone()
        return int(row["count"])

    def set_request_state(
        self,
        request_id: str,
        expected: RequestState,
        next_state: RequestState,
        result: dict[str, Any] | None = None,
    ) -> None:
        result_json = None if result is None else canonical_json(result)
        with self._lock:
            cursor = self.connection.execute(
                "UPDATE requests SET state=?, result_json=? WHERE request_id=? AND state=?",
                (next_state.value, result_json, request_id, expected.value),
            )
        if cursor.rowcount != 1:
            raise ConflictError("request state changed; reload before acting")

    def claim_request_for_execution(
        self, request_id: str, now: str, execution_result: dict[str, Any]
    ) -> None:
        """Atomically claim an unexpired request with its current client grant."""

        with self._lock:
            updated = self.connection.execute(
                "UPDATE requests SET state=?, result_json=? "
                "WHERE request_id=? AND state=? "
                "AND julianday(expires_at)>julianday(?) "
                "AND EXISTS ("
                "SELECT 1 FROM workspaces AS w "
                "JOIN client_workspace_grants AS g ON g.workspace_id=w.workspace_id "
                "JOIN clients AS c ON c.client_id=g.client_id "
                "WHERE w.workspace_id=requests.workspace_id "
                "AND w.policy_hash=requests.policy_hash "
                "AND g.client_id=requests.client_id"
                ")",
                (
                    RequestState.EXECUTING.value,
                    canonical_json(execution_result),
                    request_id,
                    RequestState.PENDING.value,
                    now,
                ),
            ).rowcount
        if updated != 1:
            raise ConflictError("request is no longer eligible for local execution")

    def expire_pending(self, now: str) -> list[str]:
        with self.transaction():
            rows = list(
                self.connection.execute(
                    "SELECT request_id FROM requests WHERE state=? "
                    "AND expires_at<>'' AND expires_at<=? ORDER BY request_id",
                    (RequestState.PENDING.value, now),
                )
            )
            ids = [str(row["request_id"]) for row in rows]
            if ids:
                self.connection.executemany(
                    "UPDATE requests SET state=?, result_json=? WHERE request_id=? AND state=?",
                    [
                        (
                            RequestState.EXPIRED.value,
                            canonical_json({"reason": "approval window expired"}),
                            request_id,
                            RequestState.PENDING.value,
                        )
                        for request_id in ids
                    ],
                )
        return ids

    def mark_executing_uncertain(self) -> list[str]:
        """Fail closed after startup: interrupted executions are never called failed/successful."""

        with self.transaction():
            rows = list(
                self.connection.execute(
                    "SELECT request_id FROM requests WHERE state=? ORDER BY request_id",
                    (RequestState.EXECUTING.value,),
                )
            )
            ids = [str(row["request_id"]) for row in rows]
            if ids:
                self.connection.executemany(
                    "UPDATE requests SET state=?, result_json=? WHERE request_id=? AND state=?",
                    [
                        (
                            RequestState.UNCERTAIN.value,
                            canonical_json(
                                {"reason": "execution interrupted; outcome requires local review"}
                            ),
                            request_id,
                            RequestState.EXECUTING.value,
                        )
                        for request_id in ids
                    ],
                )
        return ids

    def _row_request(self, row: sqlite3.Row) -> PendingRequest:
        return PendingRequest(
            request_id=str(row["request_id"]),
            kind=RequestKind(str(row["kind"])),
            workspace_id=str(row["workspace_id"]),
            payload=json.loads(str(row["payload_json"])),
            idempotency_key=str(row["idempotency_key"]),
            base_head=str(row["base_head"]),
            policy_hash=str(row["policy_hash"]),
            state=RequestState(str(row["state"])),
            created_at=str(row["created_at"]),
            client_id=str(row["client_id"]),
            expires_at=str(row["expires_at"]),
            result=(
                json.loads(str(row["result_json"])) if row["result_json"] is not None else None
            ),
        )

    def last_receipt_hash(self) -> str:
        with self._lock:
            row = self.connection.execute(
                "SELECT receipt_hash FROM receipts ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
        return _GENESIS_HASH if row is None else str(row["receipt_hash"])

    def append_receipt(self, values: tuple[int, str, str, str, str, str, str, str]) -> int:
        schema, receipt_id, occurred_at, event, payload, previous, digest, signature = values
        with self.transaction():
            if self.last_receipt_hash() != previous:
                raise ConflictError("receipt chain head changed")
            try:
                cursor = self.connection.execute(
                    "INSERT INTO receipts "
                    "(schema,receipt_id,occurred_at,event,payload_json,previous_hash,"
                    "receipt_hash,signature) VALUES (?,?,?,?,?,?,?,?)",
                    (
                        schema,
                        receipt_id,
                        occurred_at,
                        event,
                        payload,
                        previous,
                        digest,
                        signature,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("receipt chain append conflict") from exc
        return int(cursor.lastrowid)

    def receipts(self) -> list[sqlite3.Row]:
        with self._lock:
            return list(self.connection.execute("SELECT * FROM receipts ORDER BY sequence"))

    def receipt_count(self) -> int:
        with self._lock:
            row = self.connection.execute("SELECT COUNT(*) AS count FROM receipts").fetchone()
        return int(row["count"])

    def receipt_signing_key_fingerprint(self) -> str | None:
        with self._lock:
            row = self.connection.execute(
                "SELECT value FROM metadata WHERE key='receipt_signing_key_fingerprint'"
            ).fetchone()
        return None if row is None else str(row["value"])

    def pin_receipt_signing_key(self, fingerprint: str) -> None:
        if len(fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in fingerprint
        ):
            raise ValueError("invalid signing-key fingerprint")
        with self.transaction():
            existing = self.receipt_signing_key_fingerprint()
            if existing is None:
                self.connection.execute(
                    "INSERT INTO metadata (key,value) VALUES ('receipt_signing_key_fingerprint',?)",
                    (fingerprint,),
                )
            elif existing != fingerprint:
                raise ConflictError("receipt signing key does not match the pinned key")

    def assert_integrity(self) -> None:
        """Run storage-level startup checks; cryptographic receipts are checked by their ledger."""

        with self._lock:
            checks = [str(row[0]) for row in self.connection.execute("PRAGMA quick_check")]
            if checks != ["ok"]:
                raise ConflictError("SQLite integrity check failed")
            if self.connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise ConflictError("SQLite foreign-key integrity check failed")
            for row in self.connection.execute("SELECT * FROM requests"):
                if str(row["request_fingerprint"]) != request_fingerprint(self._row_request(row)):
                    raise ConflictError("stored request fingerprint mismatch")
            previous = _GENESIS_HASH
            for row in self.connection.execute("SELECT * FROM receipts ORDER BY sequence"):
                if str(row["previous_hash"]) != previous:
                    raise ConflictError("stored receipt chain is forked or discontinuous")
                previous = str(row["receipt_hash"])
