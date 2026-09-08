"""The fail-closed local approval boundary for Hermes Local Hands."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import shutil
import stat
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .errors import (
    AuthenticationError,
    ConflictError,
    ExecutionError,
    NotFoundError,
    PolicyError,
    UncertainExecutionError,
)
from .gitops import (
    SNAPSHOT_COMPLETION_MARKER,
    SNAPSHOT_PENDING_MARKER,
    PatchPlan,
    apply_patch,
    check_patch_applies,
    managed_worktree,
    require_git_root,
    run_profile,
    sanitized_status,
    snapshot_deletion_marker_state,
    validate_patch,
)
from .models import PendingRequest, RequestKind, RequestState, WorkspacePolicy
from .paths import allowed_relative, normalise_relative, safe_read
from .receipts import ReceiptLedger, ReceiptSigner
from .storage import Store, canonical_json, request_fingerprint

_REQUEST_TTL = timedelta(minutes=15)
_REQUESTS_PER_HOUR = 60
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{8,200}$")
_MAX_SNAPSHOT_TOMBSTONES = 128
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9:])/(?!/)[^\s:'\"<>]+")
_KNOWN_SECRET = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"AKIA[0-9A-Z]{16})\b"
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key)\s*[:=]\s*([^\s,;]+)"
)
_PRIVATE_KEY = re.compile(r"-----BEGIN [^-\r\n]*PRIVATE KEY-----")
_PUBLIC_FAILURE_RESULT_FIELDS = frozenset({"code", "detail_sha256", "summary"})
_PUBLIC_PATCH_RESULT_FIELDS = (
    frozenset(
        {
            "affected_paths",
            "changed_lines",
            "patch_sha256",
            "snapshot_id",
        }
    )
    | _PUBLIC_FAILURE_RESULT_FIELDS
)
_PUBLIC_TEST_RESULT_FIELDS = (
    frozenset(
        {
            "exit_code",
            "output_bytes",
            "output_sha256",
            "output_truncated",
            "passed",
            "patch_request_id",
            "patch_sha256",
            "process_cleanup_guaranteed",
            "process_group_kill_attempted",
            "snapshot_id",
            "source_status_observation",
            "temporary_home_removed",
            "timed_out",
        }
    )
    | _PUBLIC_FAILURE_RESULT_FIELDS
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _policy_hash(policy: WorkspacePolicy) -> str:
    return hashlib.sha256(canonical_json(policy.to_dict()).encode()).hexdigest()


def _validated_identifier(value: str, label: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise PolicyError(f"{label} must use 1-64 letters, digits, dot, underscore, or hyphen")
    return value


def _safe_operator_text(value: str) -> str:
    """Bound and redact human-entered text before it reaches the signed ledger."""
    text = "".join(character for character in value if character in "\t " or ord(character) >= 32)
    text = text.replace("\n", " ").replace("\r", " ")
    text = _KNOWN_SECRET.sub("<REDACTED_TOKEN>", text)
    text = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=<REDACTED>", text)
    text = _ABSOLUTE_PATH.sub("<LOCAL_PATH>", text)
    return text.strip()[:300] or "rejected locally"


def _safe_failure(exc: BaseException) -> dict[str, str]:
    """Persist a useful error class and opaque detail hash, never raw exception text."""
    if isinstance(exc, UncertainExecutionError):
        code, summary = "execution_outcome_uncertain", "local execution outcome is uncertain"
    elif isinstance(exc, PolicyError):
        code, summary = "policy_denied", "local policy denied the operation"
    elif isinstance(exc, FileNotFoundError):
        code, summary = "executable_unavailable", "configured executable is unavailable"
    elif isinstance(exc, (ExecutionError, OSError)):
        code, summary = "local_execution_error", "local execution could not be completed"
    else:
        code, summary = "internal_error", "local execution failed"
    detail = f"{type(exc).__module__}.{type(exc).__qualname__}:{exc!s}"
    return {
        "code": code,
        "summary": summary,
        "detail_sha256": hashlib.sha256(detail.encode("utf-8", "replace")).hexdigest(),
    }


def _contains_high_confidence_secret(text: str) -> bool:
    return bool(_PRIVATE_KEY.search(text) or _KNOWN_SECRET.search(text))


def _clear_bound_snapshot(directory_fd: int, preserve: frozenset[str] = frozenset()) -> None:
    """Remove only entries reached through an already-bound snapshot directory fd."""

    with os.scandir(directory_fd) as entries:
        for entry in list(entries):
            if entry.name in preserve:
                continue
            try:
                is_directory = entry.is_dir(follow_symlinks=False)
            except OSError as exc:
                raise ConflictError("managed snapshot changed during deletion") from exc
            if is_directory:
                shutil.rmtree(entry.name, dir_fd=directory_fd)
            else:
                os.unlink(entry.name, dir_fd=directory_fd)


def _write_snapshot_marker(
    directory_fd: int,
    marker_name: str,
    attempt_id: str,
    target_identity: str,
) -> None:
    """Persist one tiny state marker through the bound directory descriptor."""

    data = f"{attempt_id}\n{target_identity}\n".encode("ascii")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(marker_name, flags, 0o600, dir_fd=directory_fd)
    except OSError as exc:
        raise ExecutionError("snapshot deletion state marker could not be created") from exc
    try:
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count < 1:  # pragma: no cover - defensive OS failure
                raise OSError("completion marker write made no progress")
            written += count
        os.fsync(descriptor)
    except BaseException:
        try:
            os.unlink(marker_name, dir_fd=directory_fd)
        except BaseException:  # noqa: S110 -- preserve the marker write failure
            pass
        raise
    finally:
        os.close(descriptor)


def _remove_snapshot_marker_best_effort(directory_fd: int, marker_name: str) -> None:
    try:
        os.unlink(marker_name, dir_fd=directory_fd)
    except BaseException:  # noqa: S110 -- cleanup must preserve the triggering failure
        pass


def _snapshot_has_reserved_marker(directory_fd: int) -> bool:
    """Reject any pre-existing deletion state, including malformed marker files."""

    with os.scandir(directory_fd) as entries:
        return any(
            entry.name in {SNAPSHOT_PENDING_MARKER, SNAPSHOT_COMPLETION_MARKER} for entry in entries
        )


class LocalHandsService:
    """Core service shared by the local CLI and authenticated MCP transport."""

    def __init__(
        self,
        store: Store,
        signer: ReceiptSigner | None = None,
        *,
        ledger: ReceiptLedger | None = None,
    ) -> None:
        if signer is not None and ledger is not None:
            raise ValueError("provide either a signer or an opened ledger, not both")
        self.store = store
        self.ledger = ledger or (
            ReceiptLedger(store, signer) if signer is not None else ReceiptLedger.open(store)
        )
        self.signer = self.ledger.signer

    def _expire_due(self) -> list[str]:
        with self.store.transaction():
            expired = self.store.expire_pending(_now())
            for request_id in expired:
                self.ledger.append(
                    "request.expired",
                    {"request_id": request_id, "reason": "approval window expired"},
                )
        return expired

    def recover_interrupted(self) -> dict[str, list[str]]:
        """Explicit startup recovery; never guesses that interrupted work succeeded."""
        with self.store.transaction():
            expired = self.store.expire_pending(_now())
            interrupted = self.store.mark_executing_uncertain()
            for request_id in expired:
                self.ledger.append(
                    "request.expired",
                    {"request_id": request_id, "reason": "approval window expired"},
                )
            for request_id in interrupted:
                self.ledger.append(
                    "request.uncertain",
                    {"request_id": request_id, "reason": "execution was interrupted"},
                )
        return {"expired": expired, "uncertain": interrupted}

    def bootstrap_client(self, client_id: str) -> str:
        client_id = _validated_identifier(client_id, "client id")
        token = secrets.token_urlsafe(32)
        with self.store.transaction():
            self.store.add_client(client_id, token, _now())
            self.ledger.append("client.created", {"client_id": client_id})
        return token

    def revoke_client(self, client_id: str) -> bool:
        client_id = _validated_identifier(client_id, "client id")
        with self.store.transaction():
            revoked = self.store.revoke_client(client_id)
            self.ledger.append("client.revoked", {"client_id": client_id})
        return revoked

    def authenticate(self, bearer_token: str) -> str:
        if not 32 <= len(bearer_token) <= 128 or not bearer_token.isascii():
            raise AuthenticationError("invalid bearer credential")
        client_id = self.store.authenticate(bearer_token)
        if not client_id:
            raise AuthenticationError("invalid bearer credential")
        return client_id

    def _canonical_profile(self, root: str, profile: str, argv: tuple[str, ...]) -> tuple[str, ...]:
        _validated_identifier(profile, "check profile")
        if not argv or len(argv) > 32 or sum(len(item) for item in argv) > 8_192:
            raise PolicyError("check profiles need a bounded fixed argument vector")
        if any(not item or "\x00" in item or "\n" in item or "\r" in item for item in argv):
            raise PolicyError("check profile arguments contain unsupported characters")

        executable = argv[0]
        root_path = Path(root)
        if executable.startswith("./"):
            relative = normalise_relative(executable[2:])
            candidate = (root_path / relative).resolve(strict=True)
            if not candidate.is_relative_to(root_path):
                raise PolicyError("check executable escapes the workspace")
            executable = f"./{relative}"
            metadata = candidate.stat()
        else:
            resolved = shutil.which(executable) if not os.path.isabs(executable) else executable
            if not resolved:
                raise PolicyError("check executable could not be resolved during registration")
            candidate = Path(resolved).resolve(strict=True)
            metadata = candidate.stat()
            if candidate.is_relative_to(root_path):
                executable = f"./{candidate.relative_to(root_path).as_posix()}"
            else:
                executable = str(candidate)
        if not stat.S_ISREG(metadata.st_mode) or not os.access(candidate, os.X_OK):
            raise PolicyError("check executable must be a regular executable file")
        for argument in argv[1:]:
            if root in argument:
                raise PolicyError("check arguments must address workspace files relatively")
        return (executable, *argv[1:])

    def register_workspace(
        self,
        policy: WorkspacePolicy,
        *,
        client_ids: Sequence[str] = (),
    ) -> WorkspacePolicy:
        workspace_id = _validated_identifier(policy.workspace_id, "workspace id")
        root = require_git_root(policy.root)
        state_root = Path(self.store.path).parent.resolve()
        source_root = Path(root).resolve()
        if (
            state_root == source_root
            or state_root.is_relative_to(source_root)
            or source_root.is_relative_to(state_root)
        ):
            raise PolicyError("private state and registered workspace must not overlap")
        if not policy.read_allowlist:
            raise PolicyError("a workspace needs an explicit read allowlist")
        reads = tuple(dict.fromkeys(normalise_relative(item) for item in policy.read_allowlist))
        writes = tuple(dict.fromkeys(normalise_relative(item) for item in policy.write_allowlist))
        for write in writes:
            if not any(write == read or write.startswith(read + "/") for read in reads):
                raise PolicyError("every write path must also be covered by the read allowlist")
        if not isinstance(policy.max_read_bytes, int) or isinstance(policy.max_read_bytes, bool):
            raise PolicyError("read limit must be an integer")
        if policy.max_read_bytes < 1 or policy.max_read_bytes > 1_048_576:
            raise PolicyError("read limit must be between 1 and 1048576")
        profiles = {
            name: self._canonical_profile(root, name, tuple(argv))
            for name, argv in policy.test_profiles.items()
        }
        clients = tuple(
            dict.fromkeys(_validated_identifier(item, "client id") for item in client_ids)
        )
        canonical = WorkspacePolicy(
            workspace_id=workspace_id,
            root=root,
            read_allowlist=reads,
            test_profiles=profiles,
            max_read_bytes=policy.max_read_bytes,
            write_allowlist=writes,
        )
        policy_hash = _policy_hash(canonical)
        now = _now()
        with self.store.transaction():
            self.store.save_workspace(canonical, policy_hash)
            self.store.replace_workspace_grants(workspace_id, clients, now)
            self.ledger.append(
                "workspace.registered",
                {
                    "workspace_id": workspace_id,
                    "policy_hash": policy_hash,
                    "read_scope_count": len(reads),
                    "write_scope_count": len(writes),
                    "check_profile_count": len(profiles),
                    "granted_client_count": len(clients),
                    "granted_client_ids": sorted(clients),
                },
            )
        return canonical

    def grant_workspace(self, client_id: str, workspace_id: str) -> bool:
        client_id = _validated_identifier(client_id, "client id")
        workspace_id = _validated_identifier(workspace_id, "workspace id")
        with self.store.transaction():
            created = self.store.grant_workspace(client_id, workspace_id, _now())
            if created:
                self.ledger.append(
                    "workspace.granted",
                    {"client_id": client_id, "workspace_id": workspace_id},
                )
        return created

    def workspace_grants(self, workspace_id: str) -> list[str]:
        workspace_id = _validated_identifier(workspace_id, "workspace id")
        self.store.workspace(workspace_id)
        return self.store.client_ids_for_workspace(workspace_id)

    def revoke_workspace(self, client_id: str, workspace_id: str) -> bool:
        client_id = _validated_identifier(client_id, "client id")
        workspace_id = _validated_identifier(workspace_id, "workspace id")
        with self.store.transaction():
            revoked = self.store.revoke_workspace_grant(client_id, workspace_id)
            if revoked:
                self.ledger.append(
                    "workspace.revoked",
                    {"client_id": client_id, "workspace_id": workspace_id},
                )
        return revoked

    def list_snapshots(self) -> list[dict[str, str]]:
        """List retained managed snapshots without exposing their local path."""

        parent = Path(self.store.path).parent / "snapshots"
        if not parent.exists():
            return []
        snapshots: list[dict[str, str]] = []
        for entry in os.scandir(parent):
            if not entry.is_dir(follow_symlinks=False) or not _REQUEST_ID.fullmatch(entry.name):
                continue
            marker = snapshot_deletion_marker_state(entry.path, entry.name)
            if marker is not None and marker[0] == "complete":
                continue
            try:
                state = self.store.request(entry.name).state.value
            except NotFoundError:
                state = "orphaned"
            item = {"request_id": entry.name, "request_state": state}
            if marker is not None:
                item["storage_state"] = "deletion-incomplete"
                if marker[1]:
                    item["deletion_attempt_id"] = marker[1]
            snapshots.append(item)
        return sorted(
            snapshots,
            key=lambda item: (item["request_id"], item.get("storage_state", "snapshot")),
        )

    def delete_snapshot(self, request_id: str, confirmation: str) -> None:
        """Delete one reviewed terminal snapshot through a local-only exact-ID gate."""

        if not _REQUEST_ID.fullmatch(request_id):
            raise PolicyError("request id is unsafe for snapshot storage")
        if not secrets.compare_digest(request_id, confirmation):
            raise PolicyError("snapshot deletion requires --confirm with the exact request id")
        request = self.store.request(request_id)
        if request.state not in {
            RequestState.SUCCEEDED,
            RequestState.FAILED,
            RequestState.UNCERTAIN,
        }:
            raise ConflictError(
                "only a succeeded, failed, or locally reviewed uncertain snapshot may be deleted"
            )
        parent = Path(self.store.path).parent / "snapshots"
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not shutil.rmtree.avoids_symlink_attacks:
            raise PolicyError("safe snapshot deletion is unavailable on this platform")

        import fcntl

        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            parent_fd = os.open(parent, directory_flags)
        except OSError as exc:
            raise PolicyError("managed snapshot storage could not be opened safely") from exc
        lock_fd: int | None = None
        target_fd: int | None = None
        lock_held = False
        pending_marker_written = False
        deletion_requested = False
        target_metadata: os.stat_result | None = None
        attempt_id = secrets.token_urlsafe(12)
        try:
            try:
                lock_fd = os.open(
                    ".retention.lock",
                    os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=parent_fd,
                )
            except OSError as exc:
                raise PolicyError("unable to lock snapshot retention state") from exc
            lock_metadata = os.fstat(lock_fd)
            if not stat.S_ISREG(lock_metadata.st_mode):
                raise PolicyError("snapshot retention lock is not a regular file")
            os.fchmod(lock_fd, 0o600)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            lock_held = True

            try:
                target_fd = os.open(request_id, directory_flags, dir_fd=parent_fd)
            except FileNotFoundError:
                raise NotFoundError("managed snapshot not found") from None
            except OSError as exc:
                raise PolicyError("managed snapshot target could not be opened safely") from exc
            target_metadata = os.fstat(target_fd)
            if not stat.S_ISDIR(target_metadata.st_mode):  # pragma: no cover - O_DIRECTORY gate
                raise PolicyError("managed snapshot target is not a directory")

            with os.scandir(parent_fd) as entries:
                tombstone_count = sum(
                    1
                    for entry in entries
                    if entry.is_dir(follow_symlinks=False)
                    and _REQUEST_ID.fullmatch(entry.name)
                    and snapshot_deletion_marker_state(
                        entry.name,
                        entry.name,
                        parent_fd=parent_fd,
                    )
                    is not None
                )
            if tombstone_count >= _MAX_SNAPSHOT_TOMBSTONES:
                raise PolicyError(
                    "snapshot deletion marker limit reached; inspect retained markers locally"
                )

            current_metadata = os.stat(request_id, dir_fd=parent_fd, follow_symlinks=False)
            if not os.path.samestat(target_metadata, current_metadata):
                raise ConflictError("managed snapshot changed while deletion was being bound")
            if _snapshot_has_reserved_marker(target_fd):
                raise ConflictError("managed snapshot already has deletion state")

            target_identity = hashlib.sha256(
                f"{request_id}:{target_metadata.st_dev}:{target_metadata.st_ino}".encode()
            ).hexdigest()
            receipt_payload = {
                "request_id": request_id,
                "request_state": request.state.value,
                "deletion_attempt_id": attempt_id,
                "target_identity_sha256": target_identity,
                "marker_directory": request_id,
            }
            _write_snapshot_marker(
                target_fd,
                SNAPSHOT_PENDING_MARKER,
                attempt_id,
                target_identity,
            )
            pending_marker_written = True
            self.ledger.append("snapshot.deletion_requested", receipt_payload)
            deletion_requested = True

            _clear_bound_snapshot(target_fd, frozenset({SNAPSHOT_PENDING_MARKER}))
            pending_state = snapshot_deletion_marker_state(
                request_id,
                request_id,
                parent_fd=parent_fd,
                expected_identity=target_identity,
            )
            if pending_state != ("pending", attempt_id):
                raise ConflictError("managed snapshot changed during deletion")
            _write_snapshot_marker(
                target_fd,
                SNAPSHOT_COMPLETION_MARKER,
                attempt_id,
                target_identity,
            )
            with self.store.transaction():
                self.ledger.append("snapshot.deleted", receipt_payload)
                committing_state = snapshot_deletion_marker_state(
                    request_id,
                    request_id,
                    parent_fd=parent_fd,
                    expected_identity=target_identity,
                )
                if committing_state != ("committing", attempt_id):
                    raise ConflictError("managed snapshot changed during deletion")
            _remove_snapshot_marker_best_effort(target_fd, SNAPSHOT_PENDING_MARKER)
        except BaseException:
            if pending_marker_written and not deletion_requested and target_fd is not None:
                _remove_snapshot_marker_best_effort(target_fd, SNAPSHOT_PENDING_MARKER)
            raise
        finally:
            if target_fd is not None:
                try:
                    os.close(target_fd)
                except OSError:  # noqa: S110 -- best-effort descriptor cleanup
                    pass
            if lock_fd is not None:
                if lock_held:
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    except OSError:  # noqa: S110 -- close below also releases the lock
                        pass
                try:
                    os.close(lock_fd)
                except OSError:  # noqa: S110 -- best-effort descriptor cleanup
                    pass
            try:
                os.close(parent_fd)
            except OSError:  # noqa: S110 -- best-effort descriptor cleanup
                pass

    def _workspace(
        self, workspace_id: str, client_id: str | None = None
    ) -> tuple[WorkspacePolicy, str]:
        workspace_id = _validated_identifier(workspace_id, "workspace id")
        if client_id is not None:
            client_id = _validated_identifier(client_id, "client id")
            try:
                return self.store.workspace_for_client(client_id, workspace_id)
            except NotFoundError:
                raise AuthenticationError("workspace is unavailable to this client") from None
        return self.store.workspace(workspace_id)

    def repo_status(self, workspace_id: str, *, client_id: str | None = None) -> dict[str, object]:
        policy, _ = self._workspace(workspace_id, client_id)
        return sanitized_status(policy.root)

    def read_file(
        self,
        workspace_id: str,
        relative_path: str,
        *,
        client_id: str | None = None,
    ) -> dict[str, object]:
        policy, _ = self._workspace(workspace_id, client_id)
        path = allowed_relative(relative_path, policy.read_allowlist)
        content = safe_read(policy.root, path, policy.read_allowlist, policy.max_read_bytes)
        if b"\x00" in content:
            raise PolicyError("binary files are not returned")
        try:
            text = content.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise PolicyError("only strict UTF-8 text files are returned") from exc
        if _contains_high_confidence_secret(text):
            raise PolicyError("file appears to contain credential material and was not returned")
        return {"path": path, "content": text, "bytes": len(content)}

    @staticmethod
    def _require_clean(status: dict[str, object]) -> None:
        if status.get("change_count") != 0:
            raise PolicyError("patch and check requests require a clean registered checkout")

    def propose_patch(
        self,
        workspace_id: str,
        patch: str,
        idempotency_key: str,
        client_id: str,
    ) -> PendingRequest:
        self._expire_due()
        policy, policy_hash = self._workspace(workspace_id, client_id)
        if not policy.write_allowlist:
            raise PolicyError("this workspace is read-only; no write allowlist is registered")
        status = sanitized_status(policy.root)
        self._require_clean(status)
        base_head = str(status["head"])
        plan = check_patch_applies(
            policy.root,
            patch,
            base_head=base_head,
            allowlist=policy.write_allowlist,
        )
        return self._pending(
            RequestKind.PATCH,
            workspace_id,
            {
                "patch": patch,
                "patch_sha256": plan.sha256,
                "affected_paths": list(plan.paths),
                "changed_lines": plan.changed_lines,
                "patch_bytes": plan.byte_count,
            },
            idempotency_key,
            client_id,
            base_head,
            policy_hash,
        )

    def request_test(
        self,
        workspace_id: str,
        profile: str,
        idempotency_key: str,
        timeout_seconds: int = 120,
        client_id: str = "",
        patch_request_id: str | None = None,
    ) -> PendingRequest:
        self._expire_due()
        policy, policy_hash = self._workspace(workspace_id, client_id)
        if profile not in policy.test_profiles:
            raise PolicyError("unknown check profile")
        if (
            not isinstance(timeout_seconds, int)
            or isinstance(timeout_seconds, bool)
            or timeout_seconds < 1
            or timeout_seconds > 900
        ):
            raise PolicyError("timeout is outside allowed range")
        status = sanitized_status(policy.root)
        self._require_clean(status)
        base_head = str(status["head"])
        payload: dict[str, Any] = {
            "profile": profile,
            "timeout_seconds": timeout_seconds,
        }
        if patch_request_id is not None:
            patch_request = self.store.request(patch_request_id, client_id=client_id)
            if (
                patch_request.kind is not RequestKind.PATCH
                or patch_request.state is not RequestState.SUCCEEDED
                or patch_request.workspace_id != workspace_id
                or patch_request.policy_hash != policy_hash
                or patch_request.base_head != base_head
            ):
                raise PolicyError("linked patch request is not an approved compatible snapshot")
            payload["patch_request_id"] = patch_request.request_id
        return self._pending(
            RequestKind.TEST,
            workspace_id,
            payload,
            idempotency_key,
            client_id,
            base_head,
            policy_hash,
        )

    def _pending(
        self,
        kind: RequestKind,
        workspace_id: str,
        payload: dict[str, Any],
        idempotency_key: str,
        client_id: str,
        base_head: str,
        policy_hash: str,
    ) -> PendingRequest:
        if not _IDEMPOTENCY_KEY.fullmatch(idempotency_key):
            raise PolicyError("idempotency key contains unsupported characters")
        created = datetime.now(UTC)
        request = PendingRequest(
            request_id=f"r_{secrets.token_urlsafe(16)}",
            kind=kind,
            workspace_id=workspace_id,
            payload=payload,
            idempotency_key=idempotency_key,
            base_head=base_head,
            policy_hash=policy_hash,
            state=RequestState.PENDING,
            created_at=created.isoformat(),
            client_id=client_id,
            expires_at=(created + _REQUEST_TTL).isoformat(),
            result=None,
        )
        one_hour_ago = (created - timedelta(hours=1)).isoformat()
        with self.store.transaction():
            recent_before = self.store.count_requests_since(client_id, one_hour_ago)
            saved = self.store.add_request(request)
            is_new = saved.request_id == request.request_id
            if is_new and recent_before >= _REQUESTS_PER_HOUR:
                raise ConflictError("client hourly request quota exceeded")
            if is_new:
                receipt_payload: dict[str, Any] = {
                    "request_id": request.request_id,
                    "kind": kind.value,
                    "workspace_id": workspace_id,
                    "request_fingerprint": request_fingerprint(request),
                    "expires_at": request.expires_at,
                }
                if kind is RequestKind.PATCH:
                    receipt_payload["patch_sha256"] = payload["patch_sha256"]
                if payload.get("patch_request_id"):
                    receipt_payload["patch_request_id"] = payload["patch_request_id"]
                self.ledger.append("request.pending", receipt_payload)
        return saved

    def approval_code(self, request_id: str) -> str:
        request = self.store.request(request_id)
        return request_fingerprint(request)[:12].upper()

    def local_request_view(self, request_id: str) -> dict[str, Any]:
        self._expire_due()
        request = self.store.request(request_id)
        return {
            "request_id": request.request_id,
            "kind": request.kind.value,
            "workspace_id": request.workspace_id,
            "state": request.state.value,
            "created_at": request.created_at,
            "expires_at": request.expires_at,
            "base_head": request.base_head,
            "policy_hash": request.policy_hash,
            "client_id": request.client_id,
            "payload": request.payload,
            "result": request.result,
            "approval_code": self.approval_code(request_id)
            if request.state is RequestState.PENDING
            else None,
        }

    def public_request(self, request_id: str, client_id: str) -> dict[str, Any]:
        """Return the owning client metadata without patches or check output."""
        self._expire_due()
        request = self.store.request(request_id, client_id=client_id)
        if request.kind is RequestKind.PATCH:
            request_details = {
                "patch_sha256": request.payload["patch_sha256"],
                "affected_paths": request.payload["affected_paths"],
                "changed_lines": request.payload["changed_lines"],
                "patch_bytes": request.payload["patch_bytes"],
            }
        else:
            request_details = {
                key: request.payload[key]
                for key in ("profile", "timeout_seconds", "patch_request_id")
                if key in request.payload
            }
        public_result = None
        if request.result is not None:
            allowed_result_fields = (
                _PUBLIC_PATCH_RESULT_FIELDS
                if request.kind is RequestKind.PATCH
                else _PUBLIC_TEST_RESULT_FIELDS
            )
            public_result = {
                key: request.result[key] for key in allowed_result_fields if key in request.result
            }
        return {
            "request_id": request.request_id,
            "kind": request.kind.value,
            "workspace_id": request.workspace_id,
            "state": request.state.value,
            "created_at": request.created_at,
            "expires_at": request.expires_at,
            "base_head": request.base_head,
            "policy_hash": request.policy_hash,
            "request": request_details,
            "result": public_result,
        }

    def reject(self, request_id: str, reason: str = "rejected locally") -> None:
        self._expire_due()
        request = self.store.request(request_id)
        safe_reason = _safe_operator_text(reason)
        with self.store.transaction():
            self.store.set_request_state(
                request_id,
                RequestState.PENDING,
                RequestState.REJECTED,
                {"reason": safe_reason},
            )
            self.ledger.append(
                "request.rejected",
                {
                    "request_id": request.request_id,
                    "kind": request.kind.value,
                    "reason": safe_reason,
                },
            )

    def _approval_preflight(
        self, request: PendingRequest, confirmation: str
    ) -> tuple[WorkspacePolicy, dict[str, object], PatchPlan | None]:
        expected = request_fingerprint(request)[:12].upper()
        if not confirmation or not secrets.compare_digest(confirmation.upper(), expected):
            raise PolicyError("approval confirmation does not match the reviewed request")
        policy, policy_hash = self._workspace(request.workspace_id, request.client_id)
        status = sanitized_status(policy.root)
        self._require_clean(status)
        if policy_hash != request.policy_hash or str(status["head"]) != request.base_head:
            raise PolicyError("workspace policy or Git HEAD changed; create a new request")
        plan = None
        if request.kind is RequestKind.PATCH:
            plan = check_patch_applies(
                policy.root,
                str(request.payload["patch"]),
                base_head=request.base_head,
                allowlist=policy.write_allowlist,
            )
            if plan.sha256 != request.payload.get("patch_sha256"):
                raise ConflictError("stored patch digest does not match the approved request")
        return policy, status, plan

    def _linked_patch(
        self, request: PendingRequest, policy: WorkspacePolicy
    ) -> PendingRequest | None:
        linked_id = request.payload.get("patch_request_id")
        if linked_id is None:
            return None
        linked = self.store.request(str(linked_id), client_id=request.client_id)
        if (
            linked.kind is not RequestKind.PATCH
            or linked.state is not RequestState.SUCCEEDED
            or linked.workspace_id != request.workspace_id
            or linked.base_head != request.base_head
            or linked.policy_hash != request.policy_hash
        ):
            raise PolicyError("linked patch request is no longer compatible")
        plan = validate_patch(str(linked.payload["patch"]), allowlist=policy.write_allowlist)
        if plan.sha256 != linked.payload.get("patch_sha256"):
            raise ConflictError("linked patch digest is inconsistent")
        return linked

    def approve(self, request_id: str, confirmation: str) -> dict[str, Any]:
        """Execute one locally reviewed request; this method has no remote MCP route."""
        self._expire_due()
        request = self.store.request(request_id)
        if request.state is not RequestState.PENDING:
            raise ConflictError("only a pending request can be approved")
        policy, source_before, plan = self._approval_preflight(request, confirmation)
        linked = self._linked_patch(request, policy) if request.kind is RequestKind.TEST else None
        attempt_id = secrets.token_urlsafe(12)
        started_at = _now()
        with self.store.transaction():
            self.store.claim_request_for_execution(
                request_id,
                started_at,
                {"attempt_id": attempt_id, "started_at": started_at},
            )
            self.ledger.append(
                "request.approved",
                {
                    "request_id": request_id,
                    "kind": request.kind.value,
                    "attempt_id": attempt_id,
                    "request_fingerprint": request_fingerprint(request),
                },
            )

        try:
            worktree = managed_worktree(
                policy.root,
                request_id,
                request.base_head,
                str(Path(self.store.path).parent),
            )
            if request.kind is RequestKind.PATCH:
                assert plan is not None
                apply_patch(worktree, str(request.payload["patch"]))
                result: dict[str, Any] = {
                    "snapshot_id": request_id,
                    "patch_sha256": plan.sha256,
                    "affected_paths": list(plan.paths),
                    "changed_lines": plan.changed_lines,
                }
                terminal_state = RequestState.SUCCEEDED
                terminal_event = "request.succeeded"
            else:
                if linked is not None:
                    apply_patch(worktree, str(linked.payload["patch"]))
                profile = str(request.payload["profile"])
                result = run_profile(
                    worktree,
                    policy.test_profiles[profile],
                    timeout_seconds=int(request.payload["timeout_seconds"]),
                )
                result.pop("worktree", None)
                result["snapshot_id"] = request_id
                if linked is not None:
                    result["patch_request_id"] = linked.request_id
                    result["patch_sha256"] = linked.payload["patch_sha256"]
                try:
                    source_after = sanitized_status(policy.root)
                    observation = "same" if source_after == source_before else "changed"
                except Exception:
                    observation = "unavailable"
                result["source_status_observation"] = observation
                passed = bool(
                    result.get("exit_code") == 0
                    and not result.get("timed_out")
                    and not result.get("output_truncated")
                    and observation == "same"
                )
                result["passed"] = passed
                terminal_state = RequestState.SUCCEEDED if passed else RequestState.FAILED
                terminal_event = "check.passed" if passed else "check.failed"
        except Exception as exc:
            failure = _safe_failure(exc)
            failure_state = (
                RequestState.UNCERTAIN
                if isinstance(exc, UncertainExecutionError)
                else RequestState.FAILED
            )
            failure_event = (
                "request.uncertain" if failure_state is RequestState.UNCERTAIN else "request.failed"
            )
            with self.store.transaction():
                self.store.set_request_state(
                    request_id,
                    RequestState.EXECUTING,
                    failure_state,
                    failure,
                )
                self.ledger.append(
                    failure_event,
                    {
                        "request_id": request_id,
                        "kind": request.kind.value,
                        "attempt_id": attempt_id,
                        **failure,
                    },
                )
            raise

        result_hash = hashlib.sha256(canonical_json(result).encode()).hexdigest()
        with self.store.transaction():
            self.store.set_request_state(
                request_id,
                RequestState.EXECUTING,
                terminal_state,
                result,
            )
            self.ledger.append(
                terminal_event,
                {
                    "request_id": request_id,
                    "kind": request.kind.value,
                    "attempt_id": attempt_id,
                    "terminal_state": terminal_state.value,
                    "result_hash": result_hash,
                },
            )
        return {"request_id": request_id, "state": terminal_state.value, **result}
