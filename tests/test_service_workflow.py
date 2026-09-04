"""End-to-end service invariants across grants, approval, snapshots, and checks."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import hermes_local_hands.service as service_module
from hermes_local_hands.errors import (
    AuthenticationError,
    ConflictError,
    PolicyError,
    UncertainExecutionError,
)
from hermes_local_hands.gitops import _GIT
from hermes_local_hands.models import RequestState, WorkspacePolicy
from hermes_local_hands.service import LocalHandsService
from hermes_local_hands.storage import Store


def git(root: Path, *args: str) -> str:
    result = subprocess.run(  # noqa: S603 -- controlled test repository
        [_GIT, "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def text_patch(path: str, before: str, after: str) -> str:
    return f"--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-{before}\n+{after}\n"


@pytest.fixture()
def workflow(tmp_path: Path) -> tuple[LocalHandsService, Path]:
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "value.txt").write_text("good\n", encoding="utf-8")
    (root / "README.md").write_text("private docs\n", encoding="utf-8")
    git(root, "init", "--quiet")
    git(root, "config", "user.email", "test@example.invalid")
    git(root, "config", "user.name", "Service Test")
    git(root, "add", ".")
    git(root, "commit", "--quiet", "-m", "fixture")

    service = LocalHandsService(Store(str(tmp_path / "state" / "hands.sqlite3")))
    service.bootstrap_client("hermes")
    service.bootstrap_client("other")
    check = (
        sys.executable,
        "-c",
        (
            "from pathlib import Path; "
            "raise SystemExit(0 if Path('src/value.txt').read_text() == 'good\\n' else 7)"
        ),
    )
    service.register_workspace(
        WorkspacePolicy(
            "demo",
            str(root),
            ("src",),
            {"value-is-good": check},
            write_allowlist=("src",),
        ),
        client_ids=("hermes",),
    )
    return service, root


def approve(service: LocalHandsService, request_id: str) -> dict[str, object]:
    return service.approve(request_id, service.approval_code(request_id))


def test_approved_patch_is_the_exact_patch_checked_and_failure_is_remotely_visible(workflow):
    service, root = workflow
    patch = text_patch("src/value.txt", "good", "bad")
    proposed = service.propose_patch("demo", patch, "patch-1", "hermes")

    public_pending = service.public_request(proposed.request_id, "hermes")
    assert public_pending["request"]["patch_sha256"]
    assert "patch" not in public_pending["request"]
    assert patch not in json.dumps(public_pending)
    with pytest.raises(PolicyError, match="confirmation"):
        service.approve(proposed.request_id, "WRONG-CODE")
    assert service.store.request(proposed.request_id).state is RequestState.PENDING

    patch_result = approve(service, proposed.request_id)
    assert patch_result["state"] == "succeeded"
    assert (root / "src" / "value.txt").read_text() == "good\n"
    patch_snapshot = Path(service.store.path).parent / "snapshots" / proposed.request_id
    assert (patch_snapshot / "src" / "value.txt").read_text() == "bad\n"

    unlinked = service.request_test("demo", "value-is-good", "base-check", client_id="hermes")
    assert approve(service, unlinked.request_id)["state"] == "succeeded"

    linked = service.request_test(
        "demo",
        "value-is-good",
        "patched-check",
        client_id="hermes",
        patch_request_id=proposed.request_id,
    )
    result = approve(service, linked.request_id)
    assert result["state"] == "failed"
    assert result["exit_code"] == 7
    assert result["passed"] is False
    assert result["patch_request_id"] == proposed.request_id
    assert result["patch_sha256"] == patch_result["patch_sha256"]
    persisted = service.store.request(linked.request_id)
    assert persisted.state is RequestState.FAILED
    remote = service.public_request(linked.request_id, "hermes")
    assert remote["result"]["exit_code"] == 7
    assert remote["result"]["passed"] is False


def test_write_allowlist_dirty_checkout_and_client_grant_fail_closed(workflow):
    service, root = workflow
    with pytest.raises((PolicyError, AuthenticationError)):
        service.repo_status("demo", client_id="other")
    with pytest.raises((PolicyError, AuthenticationError)):
        service.read_file("demo", "src/value.txt", client_id="other")
    with pytest.raises((PolicyError, AuthenticationError)):
        service.propose_patch(
            "demo", text_patch("src/value.txt", "good", "other"), "other-1", "other"
        )

    with pytest.raises(PolicyError):
        service.propose_patch(
            "demo", text_patch("README.md", "private docs", "changed"), "outside", "hermes"
        )
    (root / "src" / "value.txt").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="clean"):
        service.propose_patch(
            "demo", text_patch("src/value.txt", "good", "changed"), "dirty", "hermes"
        )


def test_timeout_and_output_limit_are_failed_check_states(workflow, monkeypatch):
    service, root = workflow
    current, _ = service.store.workspace("demo")
    service.register_workspace(
        WorkspacePolicy(
            "demo",
            str(root),
            ("src",),
            {
                **current.test_profiles,
                "slow": (sys.executable, "-c", "import time; time.sleep(5)"),
                "chatty": (sys.executable, "-c", "print('x' * 10000)"),
            },
            write_allowlist=("src",),
        ),
        client_ids=("hermes",),
    )
    slow = service.request_test("demo", "slow", "slow-1", 1, client_id="hermes")
    timed_out = approve(service, slow.request_id)
    assert timed_out["state"] == "failed"
    assert timed_out["timed_out"] is True
    assert service.store.request(slow.request_id).state is RequestState.FAILED

    monkeypatch.setattr("hermes_local_hands.gitops._MAX_OUTPUT_BYTES", 512)
    chatty = service.request_test("demo", "chatty", "chatty-1", client_id="hermes")
    clipped = approve(service, chatty.request_id)
    assert clipped["state"] == "failed"
    assert clipped["output_truncated"] is True


def test_internal_failure_after_check_start_is_recorded_as_uncertain(workflow, monkeypatch):
    service, _ = workflow
    request = service.request_test("demo", "value-is-good", "uncertain-check", client_id="hermes")

    def lose_execution_outcome(*_args, **_kwargs):
        raise UncertainExecutionError("synthetic uncertain execution")

    monkeypatch.setattr(service_module, "run_profile", lose_execution_outcome)
    with pytest.raises(UncertainExecutionError):
        approve(service, request.request_id)

    loaded = service.store.request(request.request_id)
    assert loaded.state is RequestState.UNCERTAIN
    assert loaded.result is not None
    assert loaded.result["code"] == "execution_outcome_uncertain"
    assert service.public_request(request.request_id, "hermes")["state"] == "uncertain"
    assert str(service.store.receipts()[-1]["event"]) == "request.uncertain"
    assert service.list_snapshots() == [
        {"request_id": request.request_id, "request_state": "uncertain"}
    ]
    service.delete_snapshot(request.request_id, request.request_id)
    assert service.list_snapshots() == []


def test_revoked_client_request_cannot_be_approved(workflow):
    service, _ = workflow
    request = service.request_test(
        "demo", "value-is-good", "revoked-client-check", client_id="hermes"
    )
    confirmation = service.approval_code(request.request_id)
    service.revoke_client("hermes")

    with pytest.raises(AuthenticationError, match="unavailable"):
        service.approve(request.request_id, confirmation)
    assert service.store.request(request.request_id).state is RequestState.PENDING


def test_request_must_still_be_unexpired_at_atomic_execution_claim(workflow, monkeypatch):
    service, _ = workflow
    request = service.request_test("demo", "value-is-good", "expired-at-claim", client_id="hermes")
    confirmation = service.approval_code(request.request_id)
    with service.store.transaction():
        service.store.connection.execute(
            "UPDATE requests SET expires_at=? WHERE request_id=?",
            ("2000-01-01T00:00:00+00:00", request.request_id),
        )
    monkeypatch.setattr(service, "_expire_due", lambda: [])

    with pytest.raises(ConflictError, match="no longer eligible"):
        service.approve(request.request_id, confirmation)
    assert service.store.request(request.request_id).state is RequestState.PENDING


def test_snapshot_management_uses_argparse_safe_request_id_prefix(workflow, monkeypatch):
    service, _ = workflow
    generated = iter(("_leading_request_001", "receipt_for_leading_request"))
    original = service_module.secrets.token_urlsafe

    def controlled_token(size: int) -> str:
        return next(generated, original(size))

    with monkeypatch.context() as context:
        context.setattr(service_module.secrets, "token_urlsafe", controlled_token)
        request = service.request_test(
            "demo", "value-is-good", "leading-request-id", client_id="hermes"
        )

    assert request.request_id == "r__leading_request_001"
    approve(service, request.request_id)
    assert service.list_snapshots() == [
        {"request_id": "r__leading_request_001", "request_state": "succeeded"}
    ]
    receipt_count = service.store.receipt_count()
    service.delete_snapshot(request.request_id, request.request_id)
    assert service.list_snapshots() == []
    assert service.store.receipt_count() == receipt_count + 2
    requested_receipt, deletion_receipt = service.store.receipts()[-2:]
    assert str(requested_receipt["event"]) == "snapshot.deletion_requested"
    assert str(deletion_receipt["event"]) == "snapshot.deleted"
    requested_payload = json.loads(str(requested_receipt["payload_json"]))
    deletion_payload = json.loads(str(deletion_receipt["payload_json"]))
    assert deletion_payload == requested_payload
    assert deletion_payload["request_id"] == request.request_id
    assert deletion_payload["request_state"] == "succeeded"
    assert len(deletion_payload["deletion_attempt_id"]) >= 12
    assert len(deletion_payload["target_identity_sha256"]) == 64
    assert deletion_payload["marker_directory"] == request.request_id
    retained_marker = Path(service.store.path).parent / "snapshots" / request.request_id
    assert {entry.name for entry in retained_marker.iterdir()} == {".deletion-complete"}


def test_new_request_id_cannot_begin_with_argparse_option_prefix(workflow, monkeypatch):
    service, _ = workflow
    original = service_module.secrets.token_urlsafe

    def unsafe_first_token(size: int) -> str:
        if size == 16:
            return "-looks-like-an-option"
        return original(size)

    with monkeypatch.context() as context:
        context.setattr(service_module.secrets, "token_urlsafe", unsafe_first_token)
        request = service.request_test(
            "demo", "value-is-good", "argparse-safe-request-id", client_id="hermes"
        )

    assert request.request_id == "r_-looks-like-an-option"
    assert request.request_id[0].isalnum()


def test_snapshot_deletion_detects_name_swap_and_deletes_nothing(workflow, monkeypatch):
    service, _ = workflow
    request = service.request_test(
        "demo", "value-is-good", "snapshot-name-swap", client_id="hermes"
    )
    approve(service, request.request_id)
    snapshots = Path(service.store.path).parent / "snapshots"
    displaced_name = ".attacker-displaced-original"
    original_stat = os.stat
    original_rename = os.rename
    injected = False

    def swap_before_binding(path, *, dir_fd=None, follow_symlinks=True):
        nonlocal injected
        if path == request.request_id and dir_fd is not None and not injected:
            injected = True
            original_rename(
                path,
                displaced_name,
                src_dir_fd=dir_fd,
                dst_dir_fd=dir_fd,
            )
            os.mkdir(path, dir_fd=dir_fd)
            replacement = snapshots / request.request_id / "replacement.txt"
            replacement.write_text("must not be deleted\n", encoding="utf-8")
        return original_stat(
            path,
            dir_fd=dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(service_module.os, "stat", swap_before_binding)
    receipt_count = service.store.receipt_count()

    with pytest.raises(ConflictError, match="changed while deletion was being bound"):
        service.delete_snapshot(request.request_id, request.request_id)

    assert injected is True
    assert (snapshots / displaced_name / "src" / "value.txt").read_text() == "good\n"
    assert (snapshots / request.request_id / "replacement.txt").read_text() == (
        "must not be deleted\n"
    )
    assert service.store.receipt_count() == receipt_count


def test_snapshot_deletion_never_renames_over_a_competing_directory(workflow, monkeypatch):
    service, _ = workflow
    request = service.request_test(
        "demo", "value-is-good", "snapshot-no-rename", client_id="hermes"
    )
    approve(service, request.request_id)
    competing = Path(service.store.path).parent / "snapshots" / ".competing-directory"
    competing.mkdir()

    def forbid_rename(*_args, **_kwargs):
        raise AssertionError("snapshot deletion must not use a name-based rename")

    monkeypatch.setattr(service_module.os, "rename", forbid_rename)
    service.delete_snapshot(request.request_id, request.request_id)

    assert competing.is_dir()
    assert service.list_snapshots() == []


def test_snapshot_deletion_failure_keeps_only_requested_receipt_and_visible_tombstone(
    workflow, monkeypatch
):
    service, _ = workflow
    request = service.request_test(
        "demo", "value-is-good", "snapshot-delete-failure", client_id="hermes"
    )
    approve(service, request.request_id)

    def fail_after_intent(_directory_fd: int, _preserve: frozenset[str]) -> None:
        raise OSError("synthetic deletion failure")

    monkeypatch.setattr(service_module, "_clear_bound_snapshot", fail_after_intent)
    receipt_count = service.store.receipt_count()

    with pytest.raises(OSError, match="synthetic deletion failure"):
        service.delete_snapshot(request.request_id, request.request_id)

    new_receipts = service.store.receipts()[receipt_count:]
    assert [str(row["event"]) for row in new_receipts] == ["snapshot.deletion_requested"]
    requested_payload = json.loads(str(new_receipts[0]["payload_json"]))
    assert service.list_snapshots() == [
        {
            "request_id": request.request_id,
            "request_state": "succeeded",
            "storage_state": "deletion-incomplete",
            "deletion_attempt_id": requested_payload["deletion_attempt_id"],
        }
    ]


def test_snapshot_deletion_intent_receipt_failure_leaves_snapshot_untouched(workflow, monkeypatch):
    service, _ = workflow
    request = service.request_test(
        "demo", "value-is-good", "snapshot-intent-receipt-failure", client_id="hermes"
    )
    approve(service, request.request_id)
    snapshot = Path(service.store.path).parent / "snapshots" / request.request_id
    receipt_count = service.store.receipt_count()
    original_append = service.ledger.append

    def reject_intent(event, payload, occurred_at=None):
        if event == "snapshot.deletion_requested":
            raise OSError("synthetic receipt failure")
        return original_append(event, payload, occurred_at)

    monkeypatch.setattr(service.ledger, "append", reject_intent)

    with pytest.raises(OSError, match="synthetic receipt failure"):
        service.delete_snapshot(request.request_id, request.request_id)

    assert (snapshot / "src" / "value.txt").read_text() == "good\n"
    assert not (snapshot / ".deletion-pending").exists()
    assert service.store.receipt_count() == receipt_count


def test_snapshot_deletion_never_removes_replacement_at_request_name(workflow, monkeypatch):
    service, _ = workflow
    request = service.request_test(
        "demo", "value-is-good", "snapshot-final-name-swap", client_id="hermes"
    )
    approve(service, request.request_id)
    snapshots = Path(service.store.path).parent / "snapshots"
    displaced = snapshots / ".attacker-displaced-bound-target"
    original_clear = service_module._clear_bound_snapshot

    def clear_then_swap(directory_fd: int, preserve: frozenset[str]) -> None:
        original_clear(directory_fd, preserve)
        target = snapshots / request.request_id
        target.rename(displaced)
        target.mkdir()
        (target / "replacement.txt").write_text("must remain\n", encoding="utf-8")

    monkeypatch.setattr(service_module, "_clear_bound_snapshot", clear_then_swap)
    receipt_count = service.store.receipt_count()

    with pytest.raises(ConflictError, match="changed during deletion"):
        service.delete_snapshot(request.request_id, request.request_id)

    assert {entry.name for entry in displaced.iterdir()} == {".deletion-pending"}
    assert (snapshots / request.request_id / "replacement.txt").read_text() == "must remain\n"
    new_receipts = service.store.receipts()[receipt_count:]
    assert [str(row["event"]) for row in new_receipts] == ["snapshot.deletion_requested"]


def test_snapshot_deletion_late_injection_rolls_back_completion_receipt(workflow, monkeypatch):
    service, _ = workflow
    request = service.request_test(
        "demo", "value-is-good", "snapshot-late-injection", client_id="hermes"
    )
    approve(service, request.request_id)
    snapshot = Path(service.store.path).parent / "snapshots" / request.request_id
    original_append = service.ledger.append
    receipt_count = service.store.receipt_count()

    def inject_during_completion(event, payload, occurred_at=None):
        receipt = original_append(event, payload, occurred_at)
        if event == "snapshot.deleted":
            (snapshot / "late.txt").write_text("must remain visible\n", encoding="utf-8")
        return receipt

    monkeypatch.setattr(service.ledger, "append", inject_during_completion)

    with pytest.raises(ConflictError, match="changed during deletion"):
        service.delete_snapshot(request.request_id, request.request_id)

    new_receipts = service.store.receipts()[receipt_count:]
    assert [str(row["event"]) for row in new_receipts] == ["snapshot.deletion_requested"]
    requested_payload = json.loads(str(new_receipts[0]["payload_json"]))
    assert (snapshot / "late.txt").read_text(encoding="utf-8") == "must remain visible\n"
    assert service.list_snapshots() == [
        {
            "request_id": request.request_id,
            "request_state": "succeeded",
            "storage_state": "deletion-incomplete",
            "deletion_attempt_id": requested_payload["deletion_attempt_id"],
        }
    ]


def test_forged_completion_marker_cannot_hide_active_snapshot(workflow):
    service, _ = workflow
    request = service.request_test(
        "demo", "value-is-good", "snapshot-forged-marker", client_id="hermes"
    )
    approve(service, request.request_id)
    snapshot = Path(service.store.path).parent / "snapshots" / request.request_id
    (snapshot / ".deletion-complete").write_text(
        f"abcdefghijklmnop\n{'0' * 64}\n", encoding="ascii"
    )

    assert service.list_snapshots() == [
        {
            "request_id": request.request_id,
            "request_state": "succeeded",
            "storage_state": "deletion-incomplete",
        }
    ]


def test_snapshot_deletion_marker_count_is_bounded(workflow, monkeypatch):
    service, _ = workflow
    first = service.request_test(
        "demo", "value-is-good", "snapshot-marker-cap-1", client_id="hermes"
    )
    second = service.request_test(
        "demo", "value-is-good", "snapshot-marker-cap-2", client_id="hermes"
    )
    approve(service, first.request_id)
    approve(service, second.request_id)
    monkeypatch.setattr(service_module, "_MAX_SNAPSHOT_TOMBSTONES", 1)

    service.delete_snapshot(first.request_id, first.request_id)
    with pytest.raises(PolicyError, match="marker limit"):
        service.delete_snapshot(second.request_id, second.request_id)

    snapshots = Path(service.store.path).parent / "snapshots"
    assert (snapshots / second.request_id / "src" / "value.txt").read_text() == "good\n"


def test_trusted_check_mutating_source_is_observed_and_never_called_success(tmp_path: Path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "value.txt").write_text("good\n")
    (root / "scripts").mkdir()
    script = root / "scripts" / "mutate.py"
    script.write_text(
        f"#!{sys.executable}\nfrom pathlib import Path\n"
        f"Path({str(root / 'src' / 'value.txt')!r}).write_text('changed\\n')\n"
    )
    script.chmod(0o755)
    git(root, "init", "--quiet")
    git(root, "config", "user.email", "test@example.invalid")
    git(root, "config", "user.name", "Mutation Test")
    git(root, "add", ".")
    git(root, "commit", "--quiet", "-m", "fixture")

    service = LocalHandsService(Store(str(tmp_path / "state" / "hands.sqlite3")))
    service.bootstrap_client("hermes")
    service.register_workspace(
        WorkspacePolicy(
            "demo",
            str(root),
            ("src", "scripts"),
            {"mutates-source": ("./scripts/mutate.py",)},
            write_allowlist=("src",),
        ),
        client_ids=("hermes",),
    )
    request = service.request_test("demo", "mutates-source", "mutation-check", client_id="hermes")
    result = approve(service, request.request_id)
    assert (root / "src" / "value.txt").read_text() == "changed\n"
    assert result["source_status_observation"] == "changed"
    assert result["passed"] is False
    assert result["state"] == "failed"
    assert "active_checkout_unchanged" not in result


def test_execution_failure_persists_only_structured_redacted_data(tmp_path: Path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "value.txt").write_text("good\n")
    git(root, "init", "--quiet")
    git(root, "config", "user.email", "test@example.invalid")
    git(root, "config", "user.name", "Failure Test")
    git(root, "add", ".")
    git(root, "commit", "--quiet", "-m", "fixture")
    executable = tmp_path / "private-bin" / "temporary-check"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)

    service = LocalHandsService(Store(str(tmp_path / "state" / "hands.sqlite3")))
    service.bootstrap_client("hermes")
    service.register_workspace(
        WorkspacePolicy("demo", str(root), ("src",), {"gone": (str(executable),)}),
        client_ids=("hermes",),
    )
    request = service.request_test("demo", "gone", "gone-1", client_id="hermes")
    executable.unlink()
    with pytest.raises(FileNotFoundError):
        approve(service, request.request_id)

    loaded = service.store.request(request.request_id)
    assert loaded.state is RequestState.FAILED
    assert loaded.result is not None and loaded.result["code"] == "executable_unavailable"
    persisted = json.dumps(loaded.result)
    receipts = "\n".join(str(row["payload_json"]) for row in service.store.receipts())
    assert str(executable) not in persisted
    assert str(executable) not in receipts


def test_receipt_failure_rolls_back_state_transition(workflow, monkeypatch):
    service, _ = workflow
    request = service.propose_patch(
        "demo", text_patch("src/value.txt", "good", "changed"), "atomic-1", "hermes"
    )
    original = service.ledger.append

    def fail_approval(event, payload, occurred_at=None):
        if event == "request.approved":
            raise RuntimeError("simulated receipt failure")
        return original(event, payload, occurred_at)

    monkeypatch.setattr(service.ledger, "append", fail_approval)
    with pytest.raises(RuntimeError, match="simulated"):
        approve(service, request.request_id)
    assert service.store.request(request.request_id).state is RequestState.PENDING


def test_hourly_request_limit_rolls_back_excess_request(workflow, monkeypatch):
    service, _ = workflow
    monkeypatch.setattr(service_module, "_REQUESTS_PER_HOUR", 1)
    first = service.propose_patch(
        "demo", text_patch("src/value.txt", "good", "one"), "rate-1", "hermes"
    )
    assert (
        service.propose_patch(
            "demo", text_patch("src/value.txt", "good", "one"), "rate-1", "hermes"
        ).request_id
        == first.request_id
    )
    with pytest.raises(ConflictError, match="hourly"):
        service.propose_patch(
            "demo", text_patch("src/value.txt", "good", "two"), "rate-2", "hermes"
        )
    assert service.store.total_request_count(client_id="hermes") == 1


def test_state_directory_overlap_and_secret_content_are_denied(tmp_path: Path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "secret.txt").write_text(
        "sk-abcdefghijklmnopqrstuvwxyz1234567890\n", encoding="utf-8"
    )
    git(root, "init", "--quiet")
    git(root, "config", "user.email", "test@example.invalid")
    git(root, "config", "user.name", "Overlap Test")
    git(root, "add", ".")
    git(root, "commit", "--quiet", "-m", "fixture")

    overlapping = LocalHandsService(Store(str(root / ".hands" / "hands.sqlite3")))
    with pytest.raises(PolicyError, match="overlap"):
        overlapping.register_workspace(WorkspacePolicy("demo", str(root), ("src",)))

    service = LocalHandsService(Store(str(tmp_path / "state" / "hands.sqlite3")))
    service.bootstrap_client("hermes")
    service.register_workspace(WorkspacePolicy("demo", str(root), ("src",)), client_ids=("hermes",))
    with pytest.raises(PolicyError, match="credential"):
        service.read_file("demo", "src/secret.txt", client_id="hermes")


def test_reregistering_workspace_replaces_grants_exactly(tmp_path: Path):
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    for root, content in ((first_root, "first\n"), (second_root, "second\n")):
        (root / "src").mkdir(parents=True)
        (root / "src" / "value.txt").write_text(content, encoding="utf-8")
        git(root, "init", "--quiet")
        git(root, "config", "user.email", "test@example.invalid")
        git(root, "config", "user.name", "Grant Replacement Test")
        git(root, "add", ".")
        git(root, "commit", "--quiet", "-m", "fixture")

    service = LocalHandsService(Store(str(tmp_path / "state" / "hands.sqlite3")))
    service.bootstrap_client("first-client")
    service.bootstrap_client("second-client")
    service.register_workspace(
        WorkspacePolicy("demo", str(first_root), ("src",)), client_ids=("first-client",)
    )
    assert (
        service.read_file("demo", "src/value.txt", client_id="first-client")["content"] == "first\n"
    )

    service.register_workspace(
        WorkspacePolicy("demo", str(second_root), ("src",)), client_ids=("second-client",)
    )
    with pytest.raises(AuthenticationError, match="unavailable"):
        service.repo_status("demo", client_id="first-client")
    assert (
        service.read_file("demo", "src/value.txt", client_id="second-client")["content"]
        == "second\n"
    )
