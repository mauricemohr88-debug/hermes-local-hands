from __future__ import annotations

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from hermes_local_hands.errors import ConflictError, NotFoundError
from hermes_local_hands.models import PendingRequest, RequestKind, RequestState, WorkspacePolicy
from hermes_local_hands.receipts import ReceiptLedger, ReceiptSigner
from hermes_local_hands.storage import Store

NOW = "2026-09-04T10:00:00+00:00"
LATER = "2026-09-04T10:15:00+00:00"


def save_workspace(store: Store, workspace_id: str = "demo") -> None:
    store.save_workspace(
        WorkspacePolicy(
            workspace_id=workspace_id,
            root=f"/private/{workspace_id}",
            read_allowlist=("src",),
            write_allowlist=("src",),
        ),
        f"policy-{workspace_id}",
    )


def request(
    request_id: str,
    client_id: str,
    idempotency_key: str,
    *,
    workspace_id: str = "demo",
    payload: dict[str, object] | None = None,
    state: RequestState = RequestState.PENDING,
    expires_at: str = LATER,
) -> PendingRequest:
    return PendingRequest(
        request_id=request_id,
        kind=RequestKind.PATCH,
        workspace_id=workspace_id,
        payload=payload or {"patch": "example"},
        idempotency_key=idempotency_key,
        base_head="a" * 40,
        policy_hash=f"policy-{workspace_id}",
        state=state,
        created_at=NOW,
        client_id=client_id,
        expires_at=expires_at,
    )


def test_client_scoped_idempotency_never_discloses_another_clients_request(tmp_path: Path):
    store = Store(str(tmp_path / "hands.sqlite3"))
    save_workspace(store)
    first = store.add_request(request("request-a", "alice", "same-key"))
    second = store.add_request(request("request-b", "bob", "same-key"))

    assert first.request_id == "request-a"
    assert second.request_id == "request-b"
    retry = request("new-candidate-id", "alice", "same-key")
    assert store.add_request(retry).request_id == "request-a"
    with pytest.raises(NotFoundError):
        store.request("request-a", client_id="bob")
    assert store.request("request-b", client_id="bob").client_id == "bob"


def test_idempotency_fingerprint_covers_request_semantics(tmp_path: Path):
    store = Store(str(tmp_path / "hands.sqlite3"))
    save_workspace(store)
    store.add_request(request("one", "alice", "key"))
    changed = request("two", "alice", "key", payload={"patch": "different"})
    with pytest.raises(ConflictError, match="another request"):
        store.add_request(changed)


def test_request_expiry_result_and_state_filters_survive_reopen(tmp_path: Path):
    database = tmp_path / "hands.sqlite3"
    store = Store(str(database))
    save_workspace(store)
    store.add_request(request("one", "alice", "key"))
    store.set_request_state("one", RequestState.PENDING, RequestState.SUCCEEDED, {"exit_code": 0})
    store.close()

    reopened = Store(str(database))
    loaded = reopened.request("one")
    assert loaded.expires_at == LATER
    assert loaded.result == {"exit_code": 0}
    assert reopened.list_requests(state=RequestState.SUCCEEDED) == [loaded]
    assert reopened.list_requests(state=RequestState.PENDING) == []


def test_workspace_grants_are_explicit_and_revocation_cascades(tmp_path: Path):
    store = Store(str(tmp_path / "hands.sqlite3"))
    store.add_client("alice", "token-a", NOW)
    store.add_client("bob", "token-b", NOW)
    store.save_workspace(
        WorkspacePolicy("demo", "/private/demo", ("src",), write_allowlist=("src",)),
        "policy-demo",
        grant_existing_clients=True,
        granted_at=NOW,
    )

    assert store.workspace_ids_for_client("alice") == ["demo"]
    assert store.client_has_workspace_access("bob", "demo")
    assert store.workspace("demo")[0].write_allowlist == ("src",)
    store.add_client("later", "token-c", NOW)
    assert not store.client_has_workspace_access("later", "demo")
    assert store.grant_workspace("later", "demo", NOW)
    assert not store.grant_workspace("later", "demo", NOW)
    assert store.revoke_client("alice") is True
    assert not store.client_has_workspace_access("alice", "demo")
    with pytest.raises(NotFoundError):
        store.revoke_client("alice")


def test_pending_quotas_are_atomic_and_idempotent_retries_do_not_consume_slots(
    tmp_path: Path,
):
    store = Store(str(tmp_path / "hands.sqlite3"))
    save_workspace(store)
    first = request("one", "alice", "one")
    store.add_request(first, max_pending_per_client=1, max_pending_global=2)
    assert (
        store.add_request(
            request("retry", "alice", "one"),
            max_pending_per_client=1,
            max_pending_global=2,
        ).request_id
        == "one"
    )
    with pytest.raises(ConflictError, match="client pending"):
        store.add_request(
            request("two", "alice", "two"),
            max_pending_per_client=1,
            max_pending_global=2,
        )
    store.add_request(
        request("three", "bob", "three"),
        max_pending_per_client=1,
        max_pending_global=2,
    )
    with pytest.raises(ConflictError, match="global pending"):
        store.add_request(
            request("four", "carol", "four"),
            max_pending_per_client=1,
            max_pending_global=2,
        )


def test_rate_count_and_retention_caps_include_terminal_requests_without_deleting(
    tmp_path: Path,
):
    store = Store(str(tmp_path / "hands.sqlite3"))
    save_workspace(store)
    first = request("one", "alice", "one")
    store.add_request(first, max_total_per_client=1, max_total_requests=2)
    store.set_request_state("one", RequestState.PENDING, RequestState.SUCCEEDED)

    assert store.count_requests_since("alice", "2026-09-04T09:59:59+00:00") == 1
    assert store.count_requests_since("alice", "2026-09-04T10:00:01+00:00") == 0
    assert store.total_request_count() == 1
    assert store.total_request_count(client_id="alice") == 1
    assert (
        store.add_request(
            request("retry", "alice", "one"),
            max_total_per_client=1,
            max_total_requests=2,
        ).request_id
        == "one"
    )
    with pytest.raises(ConflictError, match="client retained"):
        store.add_request(
            request("two", "alice", "two"),
            max_total_per_client=1,
            max_total_requests=2,
        )
    store.add_request(
        request("three", "bob", "three"),
        max_total_per_client=1,
        max_total_requests=2,
    )
    with pytest.raises(ConflictError, match="total retained"):
        store.add_request(
            request("four", "carol", "four"),
            max_total_per_client=1,
            max_total_requests=2,
        )
    assert store.total_request_count() == 2


def test_nested_transaction_rolls_back_state_and_receipt_together(tmp_path: Path):
    store = Store(str(tmp_path / "hands.sqlite3"))
    save_workspace(store)
    store.add_request(request("one", "alice", "key"))
    ledger = ReceiptLedger(store, ReceiptSigner(b"x" * 32))

    with pytest.raises(RuntimeError, match="simulated crash"):
        with store.transaction():
            store.set_request_state("one", RequestState.PENDING, RequestState.EXECUTING)
            ledger.append("request.approved", {"request_id": "one"}, NOW)
            raise RuntimeError("simulated crash")

    assert store.request("one").state is RequestState.PENDING
    assert store.receipt_count() == 0


def test_expired_and_interrupted_requests_fail_closed(tmp_path: Path):
    store = Store(str(tmp_path / "hands.sqlite3"))
    save_workspace(store)
    store.add_request(
        request("expired", "alice", "expired", expires_at="2026-09-04T09:00:00+00:00")
    )
    store.add_request(request("running", "alice", "running"))
    store.set_request_state("running", RequestState.PENDING, RequestState.EXECUTING)

    assert store.expire_pending(NOW) == ["expired"]
    assert store.request("expired").state is RequestState.EXPIRED
    assert store.mark_executing_uncertain() == ["running"]
    interrupted = store.request("running")
    assert interrupted.state is RequestState.UNCERTAIN
    assert interrupted.result == {"reason": "execution interrupted; outcome requires local review"}


def test_persistent_signing_key_reopens_and_missing_or_replaced_key_fails_closed(
    tmp_path: Path,
):
    database = tmp_path / "hands.sqlite3"
    key = tmp_path / "receipt-signing-key.ed25519"
    store = Store(str(database))
    ledger = ReceiptLedger.open(store, str(key))
    original_fingerprint = ledger.signer.public_key_fingerprint
    ledger.append("one", {"safe": True}, NOW)
    store.close()

    reopened_store = Store(str(database))
    reopened = ReceiptLedger.open(reopened_store, str(key))
    assert reopened.signer.public_key_fingerprint == original_fingerprint
    assert reopened.verify()

    key.unlink()
    with pytest.raises(RuntimeError, match="missing"):
        ReceiptLedger.open(reopened_store, str(key))

    replacement = ReceiptSigner(b"y" * 32)
    key.write_bytes(replacement._private_seed())
    os.chmod(key, 0o600)
    with pytest.raises(ConflictError, match="pinned"):
        ReceiptLedger.open(reopened_store, str(key))


def test_receipt_id_is_signed_and_tampering_is_detected(tmp_path: Path):
    store = Store(str(tmp_path / "hands.sqlite3"))
    ledger = ReceiptLedger(store, ReceiptSigner(b"x" * 32))
    receipt = ledger.append("one", {"safe": True}, NOW)
    assert receipt.schema == 1
    store.connection.execute("UPDATE receipts SET receipt_id='substituted' WHERE sequence=1")
    assert not ledger.verify()


def test_wrong_key_cannot_poison_an_unpinned_legacy_ledger(tmp_path: Path):
    store = Store(str(tmp_path / "hands.sqlite3"))
    correct = ReceiptSigner(b"x" * 32)
    ledger = ReceiptLedger(store, correct)
    ledger.append("one", {"safe": True}, NOW)
    store.connection.execute("DELETE FROM metadata WHERE key='receipt_signing_key_fingerprint'")

    with pytest.raises(ConflictError, match="cannot verify"):
        ReceiptLedger(store, ReceiptSigner(b"y" * 32))
    assert store.receipt_signing_key_fingerprint() is None
    restored = ReceiptLedger(store, correct)
    assert restored.verify()


def test_concurrent_receipt_writers_serialize_without_forking(tmp_path: Path):
    database = tmp_path / "hands.sqlite3"
    first_store = Store(str(database))
    second_store = Store(str(database))
    seed = b"x" * 32
    first = ReceiptLedger(first_store, ReceiptSigner(seed))
    second = ReceiptLedger(second_store, ReceiptSigner(seed))

    def append(index: int) -> None:
        ledger = first if index % 2 else second
        ledger.append("parallel", {"index": index})

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(append, range(40)))

    assert first_store.receipt_count() == 40
    assert first.verify()
    previous_hashes = [str(row["previous_hash"]) for row in first_store.receipts()]
    assert len(previous_hashes) == len(set(previous_hashes))


def test_storage_integrity_detects_request_fingerprint_corruption(tmp_path: Path):
    store = Store(str(tmp_path / "hands.sqlite3"))
    save_workspace(store)
    store.add_request(request("one", "alice", "key"))
    store.connection.execute("UPDATE requests SET base_head=? WHERE request_id='one'", ("b" * 40,))
    with pytest.raises(ConflictError, match="fingerprint"):
        store.assert_integrity()


def test_migrates_the_unreleased_global_idempotency_schema(tmp_path: Path):
    database = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(database)
    connection.executescript("""
        CREATE TABLE workspaces (
          workspace_id TEXT PRIMARY KEY, root TEXT NOT NULL UNIQUE,
          policy_json TEXT NOT NULL, policy_hash TEXT NOT NULL
        );
        CREATE TABLE requests (
          request_id TEXT PRIMARY KEY, kind TEXT NOT NULL, workspace_id TEXT NOT NULL,
          payload_json TEXT NOT NULL, idempotency_key TEXT NOT NULL UNIQUE,
          base_head TEXT NOT NULL, policy_hash TEXT NOT NULL, state TEXT NOT NULL,
          created_at TEXT NOT NULL, client_id TEXT NOT NULL DEFAULT '', result_json TEXT,
          FOREIGN KEY(workspace_id) REFERENCES workspaces(workspace_id)
        );
    """)
    connection.execute(
        "INSERT INTO workspaces VALUES (?,?,?,?)",
        (
            "demo",
            "/private/demo",
            '{"max_read_bytes":262144,"read_allowlist":["src"],"root":"/private/demo",'
            '"test_profiles":{},"workspace_id":"demo"}',
            "policy-demo",
        ),
    )
    connection.execute(
        "INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            "old",
            "patch",
            "demo",
            '{"patch":"example"}',
            "legacy-key",
            "a" * 40,
            "policy-demo",
            "pending",
            NOW,
            "alice",
            None,
        ),
    )
    connection.commit()
    connection.close()

    migrated = Store(str(database))
    loaded = migrated.request("old", client_id="alice")
    assert loaded.expires_at == NOW  # old pending requests fail closed on migration
    assert migrated.workspace("demo")[0].write_allowlist == ()
    assert migrated.add_request(request("new", "bob", "legacy-key")).request_id == "new"
    migrated.assert_integrity()
