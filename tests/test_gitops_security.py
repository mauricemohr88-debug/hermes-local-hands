from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

from hermes_local_hands import gitops
from hermes_local_hands.errors import (
    ExecutionError,
    PolicyError,
    UncertainExecutionError,
    UnsafePathError,
)


def git(root: Path, *args: str) -> str:
    result = subprocess.run(  # noqa: S603, S607 -- controlled test fixture
        [gitops._GIT, "-C", str(root), *args],  # noqa: SLF001
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


@pytest.fixture()
def repository(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "--quiet")
    git(root, "config", "user.email", "test@example.invalid")
    git(root, "config", "user.name", "Test")
    (root / "src").mkdir()
    (root / "src" / "hello.txt").write_text("hello\n")
    (root / "tests").mkdir()
    (root / "tests" / "test_sample.py").write_text("def test_ok():\n    assert True\n")
    git(root, "add", ".")
    git(root, "commit", "--quiet", "-m", "initial")
    return root


def simple_patch(replacement: str = "changed") -> str:
    return (
        "diff --git a/src/hello.txt b/src/hello.txt\n"
        "index ce01362..0000001 100644\n"
        "--- a/src/hello.txt\n"
        "+++ b/src/hello.txt\n"
        "@@ -1 +1 @@\n"
        "-hello\n"
        f"+{replacement}\n"
    )


def test_git_ignores_caller_path_and_repo_fsmonitor(
    repository: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_git = fake_bin / "git"
    marker = tmp_path / "fake-git-ran"
    fake_git.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 99\n")
    fake_git.chmod(0o755)
    fsmonitor_marker = tmp_path / "fsmonitor-ran"
    hook = repository / ".git" / "fsmonitor"
    hook.write_text(f"#!/bin/sh\ntouch '{fsmonitor_marker}'\nexit 0\n")
    hook.chmod(0o755)
    git(repository, "config", "core.fsmonitor", str(hook))
    monkeypatch.setenv("PATH", str(fake_bin))

    index = repository / ".git" / "index"
    before = index.stat()
    status = gitops.sanitized_status(str(repository))
    after = index.stat()

    assert status["change_count"] == 0
    assert not marker.exists()
    assert not fsmonitor_marker.exists()
    assert (before.st_mtime_ns, before.st_ctime_ns, before.st_size) == (
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_size,
    )


def test_status_counts_a_rename_once_without_leaking_paths(repository: Path) -> None:
    git(repository, "mv", "src/hello.txt", "src/renamed.txt")
    status = gitops.sanitized_status(str(repository))
    assert status["change_count"] == 1
    assert status["changes"] == [{"index": "R", "worktree": " "}]
    assert "hello" not in repr(status) and "renamed" not in repr(status)


def test_strict_patch_returns_exact_plan_and_enforces_allowlist() -> None:
    patch = simple_patch()
    plan = gitops.validate_patch(patch, allowlist=("src",))
    assert plan.paths == ("src/hello.txt",)
    assert plan.changed_lines == 2
    assert plan.byte_count == len(patch.encode())
    assert len(plan.sha256) == 64
    with pytest.raises(UnsafePathError, match="outside"):
        gitops.validate_patch(patch, allowlist=("tests",))


@pytest.mark.parametrize(
    "patch",
    [
        (
            "diff --git a/src/new.txt b/src/new.txt\nnew file mode 100644\n"
            "--- /dev/null\n+++ b/src/new.txt\n@@ -0,0 +1 @@\n+x\n"
        ),
        (
            "diff --git a/src/hello.txt b/src/hello.txt\ndeleted file mode 100644\n"
            "--- a/src/hello.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-hello\n"
        ),
        "diff --git a/src/a b/src/b\nsimilarity index 100%\nrename from src/a\nrename to src/b\n",
        "diff --git a/src/hello.txt b/src/hello.txt\nGIT binary patch\nliteral 1\nA\n",
        (
            'diff --git "a/src/a b" "b/src/a b"\n--- "a/src/a b"\n'
            '+++ "b/src/a b"\n@@ -1 +1 @@\n-a\n+b\n'
        ),
        (
            "diff --git a/src/hello.txt b/src/hello.txt\n--- a/src/hello.txt\n"
            "+++ b/src/hello.txt\n@@ -1 +1 @@\n-hello\n+changed\n"
            "diff --git a/src/hidden b/src/hidden\n"
        ),
        "--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-a\n+b\n",
        "--- a/src/hello.txt\n+++ b/src/hello.txt\n@@ -2 +2 @@\n-hello\n+changed\ntrailing\n",
    ],
)
def test_strict_patch_rejects_unsupported_or_unaccounted_content(patch: str) -> None:
    with pytest.raises((PolicyError, UnsafePathError)):
        gitops.validate_patch(patch)


def test_patch_caps_files_and_changed_lines() -> None:
    with pytest.raises(PolicyError, match="file or changed-line"):
        gitops.validate_patch(simple_patch(), maximum_files=0)
    with pytest.raises(PolicyError, match="file or changed-line"):
        gitops.validate_patch(simple_patch(), maximum_changed_lines=1)


def test_patch_check_uses_temporary_index_and_never_changes_source(
    repository: Path, tmp_path: Path
) -> None:
    source = repository / "src" / "hello.txt"
    index = repository / ".git" / "index"
    before = (source.read_bytes(), index.stat().st_mtime_ns, index.stat().st_ctime_ns)
    plan = gitops.check_patch_applies(
        str(repository), simple_patch(), base_head=gitops.head(str(repository)), allowlist=("src",)
    )
    after = (source.read_bytes(), index.stat().st_mtime_ns, index.stat().st_ctime_ns)
    assert plan.paths == ("src/hello.txt",)
    assert before == after
    with pytest.raises(ExecutionError):
        gitops.check_patch_applies(
            str(repository), simple_patch("again").replace("-hello", "-not-present")
        )


def test_snapshot_is_external_exact_and_does_not_touch_source_index(
    repository: Path, tmp_path: Path
) -> None:
    index = repository / ".git" / "index"
    before = (index.stat().st_mtime_ns, index.stat().st_ctime_ns, index.stat().st_size)
    snapshot = Path(
        gitops.managed_worktree(
            str(repository), "request-123", gitops.head(str(repository)), str(tmp_path / "state")
        )
    )
    after = (index.stat().st_mtime_ns, index.stat().st_ctime_ns, index.stat().st_size)
    assert snapshot.is_relative_to(tmp_path / "state")
    assert not snapshot.is_relative_to(repository)
    assert (snapshot / "src" / "hello.txt").read_text() == "hello\n"
    assert before == after


def test_snapshot_rejects_symlink_and_export_omission(repository: Path, tmp_path: Path) -> None:
    (repository / "linked").symlink_to("src/hello.txt")
    git(repository, "add", "linked")
    git(repository, "commit", "--quiet", "-m", "symlink")
    with pytest.raises(PolicyError, match="symlink"):
        gitops.managed_worktree(
            str(repository), "request-124", gitops.head(str(repository)), str(tmp_path / "state")
        )

    git(repository, "rm", "linked")
    (repository / ".gitattributes").write_text("src/hello.txt export-ignore\n")
    git(repository, "add", ".gitattributes")
    git(repository, "commit", "--quiet", "-m", "export ignore")
    with pytest.raises(PolicyError, match="omitted"):
        gitops.managed_worktree(
            str(repository), "request-125", gitops.head(str(repository)), str(tmp_path / "state")
        )


def test_snapshot_rejects_export_substitution_even_when_member_is_present(
    repository: Path, tmp_path: Path
) -> None:
    (repository / "src" / "hello.txt").write_text("commit=$Format:%H$\n")
    (repository / ".gitattributes").write_text("src/hello.txt export-subst\n")
    git(repository, "add", ".")
    git(repository, "commit", "--quiet", "-m", "export substitution")
    with pytest.raises(PolicyError, match="does not (?:exactly match|match)"):
        gitops.managed_worktree(
            str(repository), "request-127", gitops.head(str(repository)), str(tmp_path / "state")
        )


def test_snapshot_total_size_is_enforced_before_archive(
    repository: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gitops, "_MAX_SNAPSHOT_TOTAL_BYTES", 5)
    with pytest.raises(PolicyError, match="total-size"):
        gitops.managed_worktree(
            str(repository), "request-126", gitops.head(str(repository)), str(tmp_path / "state")
        )


def test_snapshot_retention_limit_fails_closed_without_deleting(
    repository: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshots = tmp_path / "state" / "snapshots"
    existing = snapshots / "reviewed-snapshot"
    existing.mkdir(parents=True)
    marker = existing / "keep.txt"
    marker.write_text("keep")
    monkeypatch.setattr(gitops, "_MAX_RETAINED_SNAPSHOTS", 1)
    with pytest.raises(PolicyError, match="retention limit"):
        gitops.managed_worktree(
            str(repository), "request-128", gitops.head(str(repository)), str(tmp_path / "state")
        )
    assert marker.read_text() == "keep"
    assert not (snapshots / "request-128").exists()


def test_snapshot_retention_ignores_completed_deletion_marker(
    repository: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshots = tmp_path / "state" / "snapshots"
    completed = snapshots / "request-previous"
    completed.mkdir(parents=True)
    metadata = completed.stat()
    identity = hashlib.sha256(
        f"{completed.name}:{metadata.st_dev}:{metadata.st_ino}".encode()
    ).hexdigest()
    (completed / ".deletion-complete").write_text(
        f"abcdefghijklmnop\n{identity}\n", encoding="ascii"
    )
    monkeypatch.setattr(gitops, "_MAX_RETAINED_SNAPSHOTS", 1)

    created = Path(
        gitops.managed_worktree(
            str(repository), "request-132", gitops.head(str(repository)), str(tmp_path / "state")
        )
    )

    assert created.is_dir()
    assert completed.is_dir()


def test_snapshot_retention_counts_forged_completion_identity(
    repository: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshots = tmp_path / "state" / "snapshots"
    forged = snapshots / "request-forged"
    forged.mkdir(parents=True)
    (forged / ".deletion-complete").write_text(f"abcdefghijklmnop\n{'0' * 64}\n", encoding="ascii")
    monkeypatch.setattr(gitops, "_MAX_RETAINED_SNAPSHOTS", 1)

    with pytest.raises(PolicyError, match="retention limit"):
        gitops.managed_worktree(
            str(repository), "request-134", gitops.head(str(repository)), str(tmp_path / "state")
        )

    assert forged.is_dir()
    assert not (snapshots / "request-134").exists()


def test_snapshot_retention_counts_completed_marker_with_extra_payload(
    repository: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshots = tmp_path / "state" / "snapshots"
    incomplete = snapshots / "request-incomplete"
    incomplete.mkdir(parents=True)
    metadata = incomplete.stat()
    identity = hashlib.sha256(
        f"{incomplete.name}:{metadata.st_dev}:{metadata.st_ino}".encode()
    ).hexdigest()
    (incomplete / ".deletion-complete").write_text(
        f"abcdefghijklmnop\n{identity}\n", encoding="ascii"
    )
    (incomplete / "late.txt").write_text("must remain\n", encoding="utf-8")
    monkeypatch.setattr(gitops, "_MAX_RETAINED_SNAPSHOTS", 1)

    with pytest.raises(PolicyError, match="retention limit"):
        gitops.managed_worktree(
            str(repository), "request-135", gitops.head(str(repository)), str(tmp_path / "state")
        )

    assert (incomplete / "late.txt").read_text(encoding="utf-8") == "must remain\n"
    assert not (snapshots / "request-135").exists()


@pytest.mark.parametrize("marker_name", [".deletion-pending", ".deletion-complete"])
def test_snapshot_rejects_reserved_deletion_marker_paths(
    repository: Path, tmp_path: Path, marker_name: str
) -> None:
    (repository / marker_name).write_text("not service state\n")
    git(repository, "add", marker_name)
    git(repository, "commit", "--quiet", "-m", "reserved marker")

    with pytest.raises(PolicyError, match="reserved deletion marker"):
        gitops.managed_worktree(
            str(repository), "request-133", gitops.head(str(repository)), str(tmp_path / "state")
        )


def test_snapshot_base_exception_cleans_internal_staging_without_named_archive(
    repository: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"

    def interrupt_extract(_archive_path: Path, _destination: Path, _plan: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(gitops, "_extract_verified_archive", interrupt_extract)
    with pytest.raises(KeyboardInterrupt):
        gitops.managed_worktree(
            str(repository), "request-129", gitops.head(str(repository)), str(state)
        )

    assert not (state / "snapshots" / "request-129").exists()
    retained_staging = list((state / "snapshots").glob(".creating-*"))
    assert len(retained_staging) == 1
    assert list(retained_staging[0].iterdir()) == []
    assert not (state / "snapshots" / ".request-129.tar").exists()


def test_snapshot_cleanup_never_removes_preexisting_destination_or_archive(
    repository: Path, tmp_path: Path
) -> None:
    state = tmp_path / "state"
    snapshots = state / "snapshots"
    destination = snapshots / "request-130"
    destination.mkdir(parents=True)
    marker = destination / "keep.txt"
    marker.write_text("keep")

    with pytest.raises(ExecutionError, match="already exists"):
        gitops.managed_worktree(
            str(repository), "request-130", gitops.head(str(repository)), str(state)
        )
    assert marker.read_text() == "keep"

    other_archive = snapshots / ".request-131.tar"
    other_archive.write_bytes(b"preexisting")
    created = gitops.managed_worktree(
        str(repository), "request-131", gitops.head(str(repository)), str(state)
    )
    assert other_archive.read_bytes() == b"preexisting"
    assert Path(created).is_dir()


def test_completion_marker_entry_swap_is_not_treated_as_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "request-marker-swap"
    target.mkdir()
    metadata = target.stat()
    identity = hashlib.sha256(
        f"{target.name}:{metadata.st_dev}:{metadata.st_ino}".encode()
    ).hexdigest()
    marker = target / ".deletion-complete"
    marker.write_text(f"abcdefghijklmnop\n{identity}\n", encoding="ascii")
    original_names = gitops._bounded_snapshot_names
    calls = 0

    def swap_marker_before_second_scan(directory_fd: int):
        nonlocal calls
        calls += 1
        if calls == 2:
            marker.unlink()
            marker.mkdir()
            (marker / "payload.txt").write_text("must remain visible\n", encoding="utf-8")
        return original_names(directory_fd)

    monkeypatch.setattr(gitops, "_bounded_snapshot_names", swap_marker_before_second_scan)

    state = gitops.snapshot_deletion_marker_state(str(target), target.name)

    assert state is not None and state[0] != "complete"
    assert (marker / "payload.txt").read_text(encoding="utf-8") == "must remain visible\n"


def test_completion_marker_request_name_swap_is_not_treated_as_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "request-name-swap"
    moved = tmp_path / "moved-bound-marker"
    target.mkdir()
    metadata = target.stat()
    identity = hashlib.sha256(
        f"{target.name}:{metadata.st_dev}:{metadata.st_ino}".encode()
    ).hexdigest()
    (target / ".deletion-complete").write_text(f"abcdefghijklmnop\n{identity}\n", encoding="ascii")
    original_names = gitops._bounded_snapshot_names
    swapped = False

    def swap_request_name_before_first_scan(directory_fd: int):
        nonlocal swapped
        if not swapped:
            swapped = True
            target.rename(moved)
            target.mkdir()
            (target / "active.txt").write_text("must remain visible\n", encoding="utf-8")
        return original_names(directory_fd)

    monkeypatch.setattr(gitops, "_bounded_snapshot_names", swap_request_name_before_first_scan)

    state = gitops.snapshot_deletion_marker_state(str(target), target.name)

    assert state is not None and state[0] != "complete"
    assert (target / "active.txt").read_text(encoding="utf-8") == "must remain visible\n"
    assert (moved / ".deletion-complete").is_file()


def test_snapshot_failure_cleanup_never_deletes_request_name_replacement(
    repository: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    snapshots = state / "snapshots"
    moved = snapshots / "moved-original-staging"
    staging_replacement: Path | None = None

    def swap_staging_name_then_fail(_archive, staging: Path, _plan):
        nonlocal staging_replacement
        staging.rename(moved)
        staging.mkdir()
        staging_replacement = staging
        (staging / "foreign.txt").write_text("must survive\n", encoding="utf-8")
        raise RuntimeError("synthetic planning failure")

    monkeypatch.setattr(gitops, "_extract_verified_archive", swap_staging_name_then_fail)

    with pytest.raises(RuntimeError, match="synthetic planning failure"):
        gitops.managed_worktree(
            str(repository),
            "request-cleanup-race",
            gitops.head(str(repository)),
            str(state),
        )

    assert staging_replacement is not None
    assert (staging_replacement / "foreign.txt").read_text(encoding="utf-8") == "must survive\n"
    assert moved.is_dir()
    assert list(moved.iterdir()) == []


def test_snapshot_publish_never_overwrites_late_destination(
    repository: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    snapshots = state / "snapshots"
    destination = snapshots / "request-publish-race"
    original_extract = gitops._extract_verified_archive

    def extract_then_create_destination(archive, staging: Path, plan):
        original_extract(archive, staging, plan)
        destination.mkdir()
        (destination / "foreign.txt").write_text("must survive\n", encoding="utf-8")

    monkeypatch.setattr(gitops, "_extract_verified_archive", extract_then_create_destination)

    with pytest.raises(ExecutionError, match="destination already exists"):
        gitops.managed_worktree(
            str(repository),
            "request-publish-race",
            gitops.head(str(repository)),
            str(state),
        )

    assert (destination / "foreign.txt").read_text(encoding="utf-8") == "must survive\n"


def test_snapshot_publish_is_atomic_noreplace_at_publish_call(
    repository: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    destination = state / "snapshots" / "request-publish-noreplace"
    original_publish = gitops._publish_directory_noreplace
    competing_inode: int | None = None

    def create_competing_destination_then_publish(source: Path, target: Path) -> None:
        nonlocal competing_inode
        target.mkdir()
        competing_inode = target.stat().st_ino
        original_publish(source, target)

    monkeypatch.setattr(
        gitops,
        "_publish_directory_noreplace",
        create_competing_destination_then_publish,
    )

    with pytest.raises(ExecutionError, match="destination already exists"):
        gitops.managed_worktree(
            str(repository),
            "request-publish-noreplace",
            gitops.head(str(repository)),
            str(state),
        )

    assert competing_inode is not None
    assert destination.stat().st_ino == competing_inode
    assert list(destination.iterdir()) == []


def test_profile_output_is_bounded_redacted_hashed_and_cleanup_is_honest(tmp_path: Path) -> None:
    worktree = tmp_path / "snapshot"
    worktree.mkdir()
    secret = "sk-abcdefghijklmnopqrstuvwxyz123456"  # noqa: S105 -- synthetic fixture
    script = f"import os; print('{secret}'); print('token=super-secret-value'); print(os.getcwd())"
    result = gitops.run_profile(str(worktree), (sys.executable, "-c", script), timeout_seconds=10)
    output = str(result["output_excerpt"])
    assert result["exit_code"] == 0
    assert result["output_bytes"] > 0 and len(str(result["output_sha256"])) == 64
    assert secret not in output and "super-secret-value" not in output
    assert str(worktree) not in output
    assert "<REDACTED" in output and "<SNAPSHOT>" in output
    assert result["temporary_home_removed"] is True
    assert result["process_group_kill_attempted"] is False
    assert result["process_cleanup_guaranteed"] is False
    assert "argv" not in result
    assert not (worktree / ".home").exists()


def test_profile_kills_output_flood_and_marks_truncation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worktree = tmp_path / "snapshot"
    worktree.mkdir()
    monkeypatch.setattr(gitops, "_MAX_OUTPUT_BYTES", 1_024)
    result = gitops.run_profile(
        str(worktree),
        (sys.executable, "-c", "import sys; sys.stdout.write('x' * 100000)"),
        timeout_seconds=10,
    )
    assert result["output_truncated"] is True
    assert result["output_bytes"] == 1_024
    assert len(str(result["output"])) <= 1_024
    assert result["process_group_kill_attempted"] is True


def test_profile_timeout_kills_complete_process_group(tmp_path: Path) -> None:
    worktree = tmp_path / "snapshot"
    worktree.mkdir()
    result = gitops.run_profile(
        str(worktree),
        (sys.executable, "-c", "import time; time.sleep(5)"),
        timeout_seconds=1,
    )
    assert result["timed_out"] is True
    assert result["exit_code"] != 0
    assert result["process_group_kill_attempted"] is True
    assert result["process_cleanup_guaranteed"] is False


def test_profile_unexpected_read_failure_kills_and_reaps_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worktree = tmp_path / "snapshot"
    worktree.mkdir()
    processes: list[subprocess.Popen[bytes]] = []
    profile_stdout_fds: set[int] = set()
    real_popen = gitops.subprocess.Popen
    real_read = gitops.os.read

    def capture_process(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)
        processes.append(process)
        assert process.stdout is not None
        profile_stdout_fds.add(process.stdout.fileno())
        return process

    def fail_read(descriptor: int, maximum: int) -> bytes:
        if descriptor in profile_stdout_fds:
            raise RuntimeError("simulated profile read failure")
        return real_read(descriptor, maximum)

    monkeypatch.setattr(gitops.subprocess, "Popen", capture_process)
    monkeypatch.setattr(gitops.os, "read", fail_read)

    with pytest.raises(UncertainExecutionError, match="outcome is uncertain"):
        gitops.run_profile(
            str(worktree),
            (
                sys.executable,
                "-c",
                "import time; print('ready', flush=True); time.sleep(30)",
            ),
            timeout_seconds=10,
        )

    assert len(processes) == 1
    assert processes[0].poll() is not None
    assert not (worktree / ".home").exists()
