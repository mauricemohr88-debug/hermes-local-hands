from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from hermes_local_hands.errors import ConflictError, PolicyError, UnsafePathError
from hermes_local_hands.models import RequestState, WorkspacePolicy
from hermes_local_hands.service import LocalHandsService
from hermes_local_hands.storage import Store


def git(root: Path, *args: str) -> str:
    result = subprocess.run(  # noqa: S603, S607 -- controlled local test fixture
        ["git", "-C", str(root), *args],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


@pytest.fixture()
def service(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init")
    git(root, "config", "user.email", "test@example.invalid")
    git(root, "config", "user.name", "Test")
    (root / "src").mkdir()
    (root / "src" / "hello.txt").write_text("hello\n")
    (root / ".env").write_text("secret")
    git(root, "add", ".")
    git(root, "commit", "-m", "initial")
    app = LocalHandsService(Store(str(tmp_path / "state" / "state.sqlite")))
    app.bootstrap_client("remote")
    app.register_workspace(
        WorkspacePolicy(
            "demo",
            str(root),
            ("src",),
            {"verify": ("python3", "-c", "print('ok')")},
            write_allowlist=("src",),
        ),
        client_ids=("remote",),
    )
    return app, root


def test_private_client_credentials_are_hashed(service):
    app, _ = service
    token = app.bootstrap_client("remote-2")
    assert app.authenticate(token) == "remote-2"
    raw = app.store.connection.execute(
        "select token_hash from clients where client_id='remote-2'"
    ).fetchone()[0]
    assert raw != token and len(raw) == 64


def test_safe_read_requires_allowlist_and_denies_sensitive(service):
    app, _ = service
    assert app.read_file("demo", "src/hello.txt")["content"] == "hello\n"
    with pytest.raises(UnsafePathError):
        app.read_file("demo", ".env")
    with pytest.raises(UnsafePathError):
        app.read_file("demo", "src/../.env")


def test_safe_read_rejects_intermediate_symlink(service, tmp_path: Path):
    app, root = service
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "leak.txt").write_text("no")
    (root / "src" / "linked").symlink_to(outside, target_is_directory=True)
    with pytest.raises(UnsafePathError):
        app.read_file("demo", "src/linked/leak.txt")


def test_patch_is_pending_then_applies_only_in_managed_worktree(service):
    app, root = service
    patch = "--- a/src/hello.txt\n+++ b/src/hello.txt\n@@ -1 +1 @@\n-hello\n+changed\n"
    request = app.propose_patch("demo", patch, "one", "remote")
    assert request.state is RequestState.PENDING
    result = app.approve(request.request_id, app.approval_code(request.request_id))
    assert (root / "src" / "hello.txt").read_text() == "hello\n"
    snapshot = Path(app.store.path).parent / "snapshots" / result["snapshot_id"]
    assert (snapshot / "src/hello.txt").read_text() == "changed\n"
    assert app.store.request(request.request_id).state is RequestState.SUCCEEDED


def test_replay_and_changed_head_fail_closed(service):
    app, root = service
    first = app.request_test("demo", "verify", "same", client_id="remote")
    assert (
        app.request_test("demo", "verify", "same", client_id="remote").request_id
        == first.request_id
    )
    (root / "new.txt").write_text("x")
    git(root, "add", ".")
    git(root, "commit", "-m", "move")
    with pytest.raises(PolicyError):
        app.approve(first.request_id, app.approval_code(first.request_id))
    assert app.store.request(first.request_id).state is RequestState.PENDING


def test_test_profile_executes_without_shell_and_records_result(service):
    app, _ = service
    request = app.request_test("demo", "verify", "test-one", client_id="remote")
    result = app.approve(request.request_id, app.approval_code(request.request_id))
    assert result["exit_code"] == 0
    assert result["output"] == "ok\n"
    with pytest.raises(ConflictError):
        app.approve(request.request_id, app.approval_code(request.request_id))
