"""Narrow Git operations which never modify the registered source checkout."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from time import monotonic
from typing import BinaryIO

from .errors import ExecutionError, PolicyError, UncertainExecutionError
from .paths import allowed_relative, normalise_relative

_MAX_PATCH_BYTES = 262_144
_MAX_PATCH_FILES = 50
_MAX_CHANGED_LINES = 5_000
_MAX_GIT_OUTPUT_BYTES = 4 * 1024 * 1024
_MAX_OUTPUT_BYTES = 131_072
_MAX_OUTPUT_EXCERPT_BYTES = 16_384
# The current Hermes Agent tree is just over 10k files.  Keep a hard bound while
# leaving enough headroom for that real target and normal generated test data.
_MAX_SNAPSHOT_FILES = 25_000
_MAX_SNAPSHOT_FILE_BYTES = 20 * 1024 * 1024
_MAX_SNAPSHOT_TOTAL_BYTES = 256 * 1024 * 1024
_MAX_ARCHIVE_BYTES = 288 * 1024 * 1024
_MAX_RETAINED_SNAPSHOTS = 32
SNAPSHOT_PENDING_MARKER = ".deletion-pending"
SNAPSHOT_COMPLETION_MARKER = ".deletion-complete"
_SNAPSHOT_REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{8,200}$")
_SNAPSHOT_MARKER = re.compile(rb"([A-Za-z0-9_-]{16})\n([0-9a-f]{64})\n")

_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$")
_INDEX_HEADER = re.compile(
    r"^index ([0-9a-fA-F]{7,64})\.\.([0-9a-fA-F]{7,64})(?: (100644|100755))?$"
)
_SAFE_PATCH_PATH = re.compile(r"^[A-Za-z0-9_@+.,/-]+$")
_FORBIDDEN_PATCH_METADATA = (
    "GIT binary patch",
    "Binary files ",
    "old mode ",
    "new mode ",
    "new file mode ",
    "deleted file mode ",
    "similarity index ",
    "dissimilarity index ",
    "rename from ",
    "rename to ",
    "copy from ",
    "copy to ",
    "Submodule ",
)


def _resolve_git_executable() -> str:
    """Resolve Git from a small trusted path set, never from caller ``PATH``."""

    for candidate in ("/usr/bin/git", "/opt/homebrew/bin/git", "/usr/local/bin/git", "/bin/git"):
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path.resolve(strict=True))
    raise RuntimeError("no trusted Git executable is installed")


_GIT = _resolve_git_executable()


@dataclass(frozen=True)
class PatchPlan:
    """Validated facts bound to the exact patch bytes."""

    paths: tuple[str, ...]
    changed_lines: int
    byte_count: int
    sha256: str


@dataclass(frozen=True)
class _SnapshotFile:
    size: int
    mode: int
    object_id: str
    object_format: str


def _git_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    trusted_path = ":".join(
        dict.fromkeys((str(Path(_GIT).parent), "/usr/bin", "/bin", "/usr/sbin", "/sbin"))
    )
    environment = {
        "PATH": trusted_path,
        "HOME": os.devnull,
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "SSH_ASKPASS": "/bin/false",
        "GIT_PAGER": "cat",
        "PAGER": "cat",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    if extra:
        environment.update(extra)
    return environment


def _git_command(root: str, args: Sequence[str]) -> list[str]:
    return [
        _GIT,
        "--no-pager",
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "core.pager=cat",
        "-c",
        "credential.helper=",
        "-c",
        "diff.external=",
        "-c",
        "interactive.diffFilter=",
        "-c",
        f"core.attributesFile={os.devnull}",
        "-c",
        "commit.gpgSign=false",
        "-C",
        root,
        *args,
    ]


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:  # pragma: no cover - product currently targets macOS/Linux
            process.kill()
    except ProcessLookupError:
        pass
    except PermissionError:
        # macOS can report EPERM when a very short-lived process has already
        # exited between output capture and killpg. Ignore only with direct
        # evidence that this exact child is no longer running.
        if process.poll() is None:
            raise


def _stop_and_reap_best_effort(process: subprocess.Popen[bytes]) -> None:
    """Best-effort exceptional cleanup without masking the original failure."""

    try:
        _kill_process_group(process)
    except BaseException:  # noqa: S110 -- cleanup must preserve the triggering exception
        pass
    try:
        process.wait(timeout=10)
        return
    except BaseException:  # noqa: S110 -- cleanup must preserve the triggering exception
        pass
    try:
        process.kill()
    except BaseException:  # noqa: S110 -- cleanup must preserve the triggering exception
        pass
    try:
        process.wait(timeout=1)
    except BaseException:  # noqa: S110 -- cleanup must preserve the triggering exception
        pass


def _bounded_capture(
    command: Sequence[str],
    *,
    input_bytes: bytes | None,
    timeout: int,
    maximum: int,
    environment: Mapping[str, str],
    cwd: str | None = None,
) -> tuple[int, bytes, bytes]:
    """Capture stdout/stderr without allowing either stream to grow unbounded."""

    process = subprocess.Popen(  # noqa: S603 -- all callers supply fixed executable/argv
        list(command),
        cwd=cwd,
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env=dict(environment),
    )
    if input_bytes is not None:
        assert process.stdin is not None
        try:
            process.stdin.write(input_bytes)
        except BrokenPipeError:
            pass
        finally:
            process.stdin.close()

    stdout = bytearray()
    stderr = bytearray()
    deadline = monotonic() + timeout
    assert process.stdout is not None
    assert process.stderr is not None
    streams = {process.stdout.fileno(): stdout, process.stderr.fileno(): stderr}
    exceeded = False
    timed_out = False
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        selector.register(process.stderr, selectors.EVENT_READ)
        while selector.get_map():
            wait = deadline - monotonic()
            if wait <= 0:
                timed_out = True
                break
            events = selector.select(wait)
            if not events and process.poll() is not None:
                continue
            for key, _ in events:
                target = streams[key.fileobj.fileno()]
                chunk = os.read(key.fileobj.fileno(), 65_536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(target) + len(chunk) > maximum:
                    remaining = max(0, maximum - len(target))
                    target.extend(chunk[:remaining])
                    exceeded = True
                    break
                target.extend(chunk)
            if exceeded:
                break

    if timed_out or exceeded:
        _kill_process_group(process)
    try:
        return_code = process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)
        return_code = process.wait(timeout=10)
    if timed_out:
        raise ExecutionError("Git command timed out")
    if exceeded:
        raise ExecutionError("Git command output exceeds the safety limit")
    return return_code, bytes(stdout), bytes(stderr)


def _git_bytes(
    root: str,
    args: Sequence[str],
    *,
    timeout: int = 20,
    maximum: int = _MAX_GIT_OUTPUT_BYTES,
    input_bytes: bytes | None = None,
    extra_env: Mapping[str, str] | None = None,
) -> bytes:
    return_code, stdout, stderr = _bounded_capture(
        _git_command(root, args),
        input_bytes=input_bytes,
        timeout=timeout,
        maximum=maximum,
        environment=_git_environment(extra_env),
    )
    if return_code:
        message = (stderr or stdout or b"git command failed").decode("utf-8", "replace")
        raise ExecutionError(_redact_text(message, root)[:4096].strip())
    return stdout


def _git(root: str, args: Sequence[str], *, timeout: int = 20) -> str:
    return _git_bytes(root, args, timeout=timeout).decode("utf-8", "strict").strip()


def require_git_root(root: str) -> str:
    resolved = str(Path(root).resolve(strict=True))
    top = _git(resolved, ["rev-parse", "--show-toplevel"])
    if Path(top).resolve() != Path(resolved):
        raise PolicyError("workspace root must be the exact Git top-level directory")
    return resolved


def head(root: str) -> str:
    value = _git(root, ["rev-parse", "--verify", "HEAD^{commit}"])
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", value):
        raise ExecutionError("Git returned an invalid commit identifier")
    return value.lower()


def _parse_porcelain_status(raw: bytes) -> list[dict[str, str]]:
    records = raw.split(b"\0")
    changes: list[dict[str, str]] = []
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if not record:
            continue
        if len(record) < 4 or record[2:3] != b" ":
            raise ExecutionError("Git returned malformed status data")
        try:
            code = record[:2].decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise ExecutionError("Git returned malformed status data") from exc
        if any(character not in " MADRCU?!T" for character in code):
            raise ExecutionError("Git returned an unknown status code")
        changes.append({"index": code[0], "worktree": code[1]})
        # In porcelain v1 -z, rename/copy entries have an additional source-path
        # record.  Consume it without ever decoding or exposing either path.
        if code[0] in "RC" or code[1] in "RC":
            if index >= len(records) or not records[index]:
                raise ExecutionError("Git returned an incomplete rename status")
            index += 1
    return changes


def sanitized_status(root: str) -> dict[str, object]:
    """Return path-free status with all optional index writes and fsmonitor disabled."""

    branch = _git(root, ["branch", "--show-current"])
    raw_status = _git_bytes(
        root,
        ["status", "--porcelain=v1", "-z", "--untracked-files=normal", "--ignore-submodules=none"],
    )
    changes = _parse_porcelain_status(raw_status)
    return {
        "head": head(root),
        "branch": branch or "DETACHED",
        "change_count": len(changes),
        "changes": changes,
    }


def _patch_path(raw: str, expected_prefix: str) -> str:
    if not raw.startswith(expected_prefix) or not _SAFE_PATCH_PATH.fullmatch(raw):
        raise PolicyError("patch path is quoted, ambiguous, or malformed")
    value = raw[len(expected_prefix) :]
    if not value or any(character.isspace() for character in value):
        raise PolicyError("patch paths containing whitespace are not supported")
    return normalise_relative(value)


def _parse_hunks(lines: list[str], start: int) -> tuple[int, int]:
    index = start
    changed = 0
    hunk_count = 0
    while index < len(lines) and lines[index].startswith("@@ "):
        match = _HUNK_HEADER.fullmatch(lines[index])
        if not match:
            raise PolicyError("patch contains a malformed hunk header")
        old_expected = int(match.group(2) if match.group(2) is not None else "1")
        new_expected = int(match.group(4) if match.group(4) is not None else "1")
        index += 1
        old_seen = 0
        new_seen = 0
        body_line_seen = False
        marker_allowed = False
        while old_seen < old_expected or new_seen < new_expected:
            if index >= len(lines):
                raise PolicyError("patch hunk ended before its declared line counts")
            line = lines[index]
            marker = line[:1]
            if marker == " ":
                old_seen += 1
                new_seen += 1
            elif marker == "-":
                old_seen += 1
                changed += 1
            elif marker == "+":
                new_seen += 1
                changed += 1
            elif line == "\\ No newline at end of file" and body_line_seen and marker_allowed:
                marker_allowed = False
                index += 1
                continue
            else:
                raise PolicyError("patch hunk contains an invalid body line")
            body_line_seen = True
            marker_allowed = True
            if old_seen > old_expected or new_seen > new_expected:
                raise PolicyError("patch hunk exceeds its declared line counts")
            index += 1
        if index < len(lines) and lines[index] == "\\ No newline at end of file":
            index += 1
        hunk_count += 1
    if not hunk_count:
        raise PolicyError("each patch section must contain at least one hunk")
    return index, changed


def _headers(lines: list[str], index: int, expected: str | None) -> tuple[int, str]:
    if index + 1 >= len(lines) or not lines[index].startswith("--- "):
        raise PolicyError("patch section is missing the original-file header")
    if not lines[index + 1].startswith("+++ "):
        raise PolicyError("patch section is missing the updated-file header")
    before = _patch_path(lines[index][4:], "a/")
    after = _patch_path(lines[index + 1][4:], "b/")
    if before != after or (expected is not None and before != expected):
        raise PolicyError("rename or mismatched patch paths are not permitted")
    return index + 2, before


def validate_patch(
    patch: str,
    *,
    maximum: int = _MAX_PATCH_BYTES,
    allowlist: tuple[str, ...] | None = None,
    maximum_files: int = _MAX_PATCH_FILES,
    maximum_changed_lines: int = _MAX_CHANGED_LINES,
) -> PatchPlan:
    """Parse a complete, text-only, modification-only unified diff.

    Both normal ``git diff`` output and the minimal paired ``---``/``+++``
    unified form are accepted.  Every byte must belong to a validated header or
    hunk; unknown metadata is not ignored.
    """

    encoded = patch.encode("utf-8", "strict")
    if not patch or len(encoded) > maximum or "\x00" in patch:
        raise PolicyError("patch is empty, binary, or exceeds size limit")
    if "\r" in patch or not patch.endswith("\n"):
        raise PolicyError("patch must use LF line endings and end with a newline")
    lines = patch[:-1].split("\n")
    for line in lines:
        if line.startswith(_FORBIDDEN_PATCH_METADATA):
            raise PolicyError("patch contains unsupported binary, mode, or path metadata")

    paths: list[str] = []
    changed_lines = 0
    index = 0
    git_format = bool(lines and lines[0].startswith("diff --git "))
    while index < len(lines):
        expected_path: str | None = None
        if git_format:
            if not lines[index].startswith("diff --git "):
                raise PolicyError("every git-format patch section must start with diff --git")
            fields = lines[index].split(" ")
            if len(fields) != 4 or fields[:2] != ["diff", "--git"]:
                raise PolicyError("diff --git path is ambiguous")
            before = _patch_path(fields[2], "a/")
            after = _patch_path(fields[3], "b/")
            if before != after:
                raise PolicyError("rename or mismatched patch paths are not permitted")
            expected_path = before
            index += 1
            if index < len(lines) and lines[index].startswith("index "):
                match = _INDEX_HEADER.fullmatch(lines[index])
                if not match or set(match.group(1)) == {"0"} or set(match.group(2)) == {"0"}:
                    raise PolicyError("patch index header is malformed or creates/deletes a file")
                index += 1
        elif not lines[index].startswith("--- "):
            raise PolicyError("patch contains data outside a unified diff section")

        index, path = _headers(lines, index, expected_path)
        if path in paths:
            raise PolicyError("a file may appear only once in a patch")
        if allowlist is not None:
            allowed_relative(path, allowlist)
        paths.append(path)
        index, section_changes = _parse_hunks(lines, index)
        changed_lines += section_changes
        if len(paths) > maximum_files or changed_lines > maximum_changed_lines:
            raise PolicyError("patch exceeds the file or changed-line limit")
        if not git_format and index < len(lines) and not lines[index].startswith("--- "):
            raise PolicyError("patch contains trailing or unsupported metadata")

    if not paths or not changed_lines:
        raise PolicyError("patch must modify at least one text line")
    return PatchPlan(
        paths=tuple(paths),
        changed_lines=changed_lines,
        byte_count=len(encoded),
        sha256=hashlib.sha256(encoded).hexdigest(),
    )


def check_patch_applies(
    root: str,
    patch: str,
    *,
    base_head: str | None = None,
    allowlist: tuple[str, ...] | None = None,
) -> PatchPlan:
    """Check a patch against an isolated temporary index for an exact commit."""

    plan = validate_patch(patch, allowlist=allowlist)
    commit = base_head or head(root)
    with tempfile.TemporaryDirectory(prefix="hermes-local-hands-index-") as directory:
        index_file = str(Path(directory) / "index")
        environment = {"GIT_INDEX_FILE": index_file}
        _git_bytes(root, ["read-tree", commit], extra_env=environment)
        _git_bytes(
            root,
            ["apply", "--cached", "--check", "--whitespace=error-all", "-"],
            input_bytes=patch.encode("utf-8"),
            extra_env=environment,
        )
    return plan


def _archive_relative(raw: bytes, *, directory: bool = False) -> str:
    try:
        value = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise PolicyError("snapshot contains a non-UTF-8 path") from exc
    if directory:
        value = value.rstrip("/")
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise PolicyError("snapshot contains an unsafe path")
    raw_parts = value.split("/")
    path = PurePosixPath(value)
    if any(part in ("", ".", "..") for part in raw_parts) or path.is_absolute():
        raise PolicyError("snapshot contains path traversal")
    if any(part.lower() == ".git" for part in path.parts):
        raise PolicyError("snapshot tree contains a reserved .git path")
    if path.as_posix() in {SNAPSHOT_PENDING_MARKER, SNAPSHOT_COMPLETION_MARKER}:
        raise PolicyError("snapshot tree contains a reserved deletion marker path")
    return path.as_posix()


def _snapshot_plan(root: str, base_head: str) -> dict[str, _SnapshotFile]:
    object_format = _git(root, ["rev-parse", "--show-object-format"])
    if object_format not in ("sha1", "sha256"):
        raise PolicyError("repository uses an unsupported Git object format")
    raw = _git_bytes(
        root,
        ["ls-tree", "-r", "-l", "-z", base_head],
        maximum=8 * 1024 * 1024,
    )
    plan: dict[str, _SnapshotFile] = {}
    total = 0
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, raw_object_id, raw_size = metadata.split(b" ", 3)
            size = int(raw_size)
        except (ValueError, TypeError) as exc:
            raise PolicyError("Git tree contains malformed metadata") from exc
        if object_type != b"blob" or mode not in (b"100644", b"100755"):
            raise PolicyError("snapshot contains a symlink, submodule, or unsupported file mode")
        path = _archive_relative(raw_path)
        try:
            object_id = raw_object_id.decode("ascii", "strict").lower()
        except UnicodeDecodeError as exc:
            raise PolicyError("Git tree contains an invalid object identifier") from exc
        expected_hash_length = 40 if object_format == "sha1" else 64
        if not re.fullmatch(rf"[0-9a-f]{{{expected_hash_length}}}", object_id):
            raise PolicyError("Git tree contains an invalid object identifier")
        if path in plan:
            raise PolicyError("snapshot contains a duplicate path")
        if size < 0 or size > _MAX_SNAPSHOT_FILE_BYTES:
            raise PolicyError("snapshot file exceeds size limit")
        total += size
        if len(plan) >= _MAX_SNAPSHOT_FILES or total > _MAX_SNAPSHOT_TOTAL_BYTES:
            raise PolicyError("snapshot exceeds the file-count or total-size limit")
        plan[path] = _SnapshotFile(
            size,
            0o755 if mode == b"100755" else 0o644,
            object_id,
            object_format,
        )
    return plan


def _stream_archive(root: str, base_head: str, archive_file: BinaryIO) -> None:
    command = _git_command(root, ["archive", "--format=tar", base_head])
    process: subprocess.Popen[bytes] | None = None
    try:
        with tempfile.TemporaryFile() as error_file:
            process = subprocess.Popen(  # noqa: S603 -- fixed trusted Git and commit
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=error_file,
                start_new_session=True,
                env=_git_environment(),
            )
            assert process.stdout is not None
            deadline = monotonic() + 60
            total = 0
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    wait = deadline - monotonic()
                    if wait <= 0:
                        _kill_process_group(process)
                        process.wait(timeout=10)
                        raise ExecutionError("Git archive timed out")
                    events = selector.select(wait)
                    if not events and process.poll() is not None:
                        continue
                    for key, _ in events:
                        chunk = os.read(key.fileobj.fileno(), 65_536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > _MAX_ARCHIVE_BYTES:
                            _kill_process_group(process)
                            process.wait(timeout=10)
                            raise PolicyError("snapshot archive exceeds the total-size limit")
                        archive_file.write(chunk)
            return_code = process.wait(timeout=10)
            if return_code:
                error_file.seek(0)
                message = error_file.read(4096).decode("utf-8", "replace")
                raise ExecutionError(_redact_text(message or "unable to create snapshot", root))
            archive_file.flush()
            archive_file.seek(0)
    except BaseException:
        if process is not None:
            _stop_and_reap_best_effort(process)
        raise


def _extract_verified_archive(
    archive_file: BinaryIO, destination: Path, plan: Mapping[str, _SnapshotFile]
) -> None:
    seen: set[str] = set()
    extracted_total = 0
    member_count = 0
    archive_file.seek(0)
    with tarfile.open(fileobj=archive_file, mode="r:") as contents:
        for member in contents:
            member_count += 1
            if member_count > _MAX_SNAPSHOT_FILES * 2:
                raise PolicyError("snapshot archive has too many members")
            if member.isdir():
                path = _archive_relative(member.name.encode("utf-8"), directory=True)
                (destination / path).mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise PolicyError("snapshot contains a link or unsupported file type")
            path = _archive_relative(member.name.encode("utf-8"))
            expected = plan.get(path)
            if expected is None or path in seen or member.size != expected.size:
                raise PolicyError("snapshot archive does not exactly match the Git tree")
            extracted_total += member.size
            if extracted_total > _MAX_SNAPSHOT_TOTAL_BYTES:
                raise PolicyError("snapshot extracted data exceeds the total-size limit")
            target = destination / path
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = contents.extractfile(member)
            if source is None:
                raise PolicyError("snapshot file could not be read")
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                expected.mode,
            )
            written = 0
            digest = hashlib.new(expected.object_format)
            digest.update(f"blob {expected.size}\0".encode())
            try:
                while True:
                    chunk = source.read(min(65_536, expected.size + 1 - written))
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > expected.size:
                        raise PolicyError("snapshot file expanded beyond its Git tree size")
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        count = os.write(descriptor, view)
                        if count < 1:
                            raise ExecutionError("snapshot file write did not make progress")
                        view = view[count:]
            finally:
                os.close(descriptor)
                source.close()
            if written != expected.size:
                raise PolicyError("snapshot file was truncated")
            if digest.hexdigest() != expected.object_id:
                raise PolicyError("snapshot file content does not match its Git blob")
            os.chmod(target, expected.mode)
            seen.add(path)
    if seen != set(plan):
        raise PolicyError("snapshot archive omitted one or more tracked files")


def _read_bound_snapshot_marker(directory_fd: int, marker_name: str) -> tuple[str, str] | None:
    """Read one immutable-format marker without following a repository-controlled link."""

    try:
        marker_fd = os.open(
            marker_name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
    except OSError:
        return None
    try:
        before = os.fstat(marker_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 128:
            return None
        data = os.read(marker_fd, 129)
        after = os.fstat(marker_fd)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
            return None
        if len(data) != before.st_size:
            return None
        try:
            current = os.stat(marker_name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            return None
        if not os.path.samestat(after, current) or not stat.S_ISREG(current.st_mode):
            return None
    finally:
        os.close(marker_fd)
    match = _SNAPSHOT_MARKER.fullmatch(data)
    if match is None:
        return None
    return match.group(1).decode("ascii"), match.group(2).decode("ascii")


def _bounded_snapshot_names(directory_fd: int) -> tuple[frozenset[str], bool]:
    """Read enough names to prove a marker directory has no hidden payload."""

    names: set[str] = set()
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            names.add(entry.name)
            if len(names) > 2:
                return frozenset(names), True
    return frozenset(names), False


def snapshot_deletion_marker_state(
    path: str,
    request_id: str,
    *,
    parent_fd: int | None = None,
    expected_identity: str | None = None,
) -> tuple[str, str] | None:
    """Return a fail-closed deletion-marker state bound to the directory identity.

    A directory is complete only when its marker names its exact request/inode
    identity and is the directory's sole entry.  All other marker-bearing states
    remain visible to operators and count against retention.
    """

    if _SNAPSHOT_REQUEST_ID.fullmatch(request_id) is None:
        return None
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(path, directory_flags, dir_fd=parent_fd)
    except OSError:
        return None
    try:
        metadata = os.fstat(directory_fd)
        actual_identity = hashlib.sha256(
            f"{request_id}:{metadata.st_dev}:{metadata.st_ino}".encode()
        ).hexdigest()
        before_names, before_overflow = _bounded_snapshot_names(directory_fd)
        pending_before = _read_bound_snapshot_marker(directory_fd, SNAPSHOT_PENDING_MARKER)
        complete_before = _read_bound_snapshot_marker(directory_fd, SNAPSHOT_COMPLETION_MARKER)
        after_names, after_overflow = _bounded_snapshot_names(directory_fd)
        pending_after = _read_bound_snapshot_marker(directory_fd, SNAPSHOT_PENDING_MARKER)
        complete_after = _read_bound_snapshot_marker(directory_fd, SNAPSHOT_COMPLETION_MARKER)
        try:
            current_metadata = os.stat(path, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            current_metadata = None
    finally:
        os.close(directory_fd)

    marker_names = {SNAPSHOT_PENDING_MARKER, SNAPSHOT_COMPLETION_MARKER}
    observed_marker = bool(
        (before_names | after_names) & marker_names
        or pending_before is not None
        or pending_after is not None
        or complete_before is not None
        or complete_after is not None
    )
    if current_metadata is None or not os.path.samestat(metadata, current_metadata):
        return ("invalid", "") if observed_marker else None
    if expected_identity is not None and not secrets.compare_digest(
        actual_identity, expected_identity
    ):
        return ("invalid", "") if observed_marker else None
    stable_names = before_names == after_names and before_overflow == after_overflow
    stable_markers = pending_before == pending_after and complete_before == complete_after
    complete = complete_after
    pending = pending_after
    complete_valid = (
        stable_markers
        and complete is not None
        and secrets.compare_digest(complete[1], actual_identity)
    )
    pending_valid = (
        stable_markers
        and pending is not None
        and secrets.compare_digest(pending[1], actual_identity)
    )
    if complete_valid:
        if (
            stable_names
            and not before_overflow
            and before_names == frozenset({SNAPSHOT_COMPLETION_MARKER})
        ):
            return "complete", complete[0]
        if (
            stable_names
            and not before_overflow
            and before_names == frozenset({SNAPSHOT_PENDING_MARKER, SNAPSHOT_COMPLETION_MARKER})
            and pending_valid
            and pending == complete
        ):
            return "committing", complete[0]
        return "incomplete", complete[0]
    if pending_valid:
        return "pending", pending[0]
    if observed_marker:
        return "invalid", ""
    return None


def _reserve_snapshot_directory(destination: Path) -> tuple[Path, int, int]:
    """Reserve one retained slot and a high-entropy internal staging directory."""

    import fcntl

    lock_path = destination.parent / ".retention.lock"
    try:
        lock_fd = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError as exc:
        raise PolicyError("unable to lock snapshot retention state") from exc
    staging: Path | None = None
    directory_fd: int | None = None
    try:
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            os.stat(destination, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ExecutionError("managed snapshot destination already exists")
        retained = sum(
            1
            for entry in os.scandir(destination.parent)
            if entry.is_dir(follow_symlinks=False)
            and (
                entry.name.startswith(".creating-")
                or (
                    _SNAPSHOT_REQUEST_ID.fullmatch(entry.name)
                    and (
                        (marker := snapshot_deletion_marker_state(entry.path, entry.name)) is None
                        or marker[0] != "complete"
                    )
                )
            )
        )
        if retained >= _MAX_RETAINED_SNAPSHOTS:
            raise PolicyError(
                "snapshot retention limit reached; remove reviewed snapshots locally "
                "before retrying"
            )
        staging = destination.parent / f".creating-{secrets.token_urlsafe(24)}"
        staging.mkdir(mode=0o700)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        directory_fd = os.open(staging, directory_flags)
        bound_metadata = os.fstat(directory_fd)
        current_metadata = os.stat(staging, follow_symlinks=False)
        if not os.path.samestat(bound_metadata, current_metadata):
            raise ExecutionError("managed snapshot staging directory changed during reservation")
    except BaseException:
        if directory_fd is not None:
            try:
                os.close(directory_fd)
            except OSError:  # noqa: S110 -- cleanup must preserve triggering exception
                pass
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:  # noqa: S110 -- close below also releases the lock
            pass
        try:
            os.close(lock_fd)
        except OSError:  # noqa: S110 -- cleanup must preserve triggering exception
            pass
        raise
    assert staging is not None and directory_fd is not None
    return staging, directory_fd, lock_fd


def _clear_bound_snapshot_directory(directory_fd: int) -> None:
    """Best-effort cleanup confined to an already-bound snapshot directory."""

    if not shutil.rmtree.avoids_symlink_attacks:
        return
    with os.scandir(directory_fd) as entries:
        for entry in list(entries):
            if entry.is_dir(follow_symlinks=False):
                shutil.rmtree(entry.name, dir_fd=directory_fd)
            else:
                os.unlink(entry.name, dir_fd=directory_fd)


def _snapshot_name_matches_descriptor(destination: Path, directory_fd: int) -> bool:
    try:
        return os.path.samestat(
            os.fstat(directory_fd),
            os.stat(destination, follow_symlinks=False),
        )
    except OSError:
        return False


def _release_snapshot_lock(lock_fd: int) -> None:
    import fcntl

    try:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
    finally:
        os.close(lock_fd)


def _publish_directory_noreplace(source: Path, destination: Path) -> None:
    """Atomically publish a directory without replacing any existing entry."""

    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if sys.platform == "darwin":
        rename_exclusive = 0x00000004
        try:
            rename = libc.renamex_np
        except AttributeError as exc:  # pragma: no cover - supported macOS contract
            raise PolicyError("atomic no-replace snapshot publication is unavailable") from exc
        rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        result = rename(source_bytes, destination_bytes, rename_exclusive)
    elif sys.platform.startswith("linux"):
        at_fdcwd = -100
        rename_noreplace = 1
        try:
            rename = libc.renameat2
        except AttributeError as exc:  # pragma: no cover - old libc fails closed
            raise PolicyError("atomic no-replace snapshot publication is unavailable") from exc
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        result = rename(
            at_fdcwd,
            source_bytes,
            at_fdcwd,
            destination_bytes,
            rename_noreplace,
        )
    else:  # pragma: no cover - package supports macOS and POSIX Linux
        raise PolicyError("atomic no-replace snapshot publication is unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise ExecutionError("managed snapshot destination already exists")
    error = OSError(error_number, os.strerror(error_number))
    raise ExecutionError("managed snapshot could not be published safely") from error


def managed_worktree(root: str, request_id: str, base_head: str, state_dir: str) -> str:
    """Create a detached snapshot outside the source repository.

    ``git worktree`` changes source ``.git`` metadata.  A verified bounded
    archive plus a new local repository preserves the active checkout and all
    of its metadata.
    """

    if not re.fullmatch(r"[A-Za-z0-9_-]{8,200}", request_id):
        raise PolicyError("request id is unsafe for snapshot storage")
    state_root = Path(state_dir).resolve()
    destination = state_root / "snapshots" / request_id
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    source_root = Path(root).resolve()
    snapshot_parent = destination.parent.resolve()
    if snapshot_parent == source_root or snapshot_parent.is_relative_to(source_root):
        raise PolicyError("managed snapshots must be outside the source repository")

    staging: Path | None = None
    snapshot_fd: int | None = None
    lock_fd: int | None = None
    plan = _snapshot_plan(root, base_head)
    with tempfile.TemporaryFile(dir=destination.parent) as archive_file:
        _stream_archive(root, base_head, archive_file)
        try:
            staging, snapshot_fd, lock_fd = _reserve_snapshot_directory(destination)
            _extract_verified_archive(archive_file, staging, plan)
            _git(str(staging), ["init", "--quiet"])
            _git(str(staging), ["config", "user.email", "local-hands@invalid"])
            _git(str(staging), ["config", "user.name", "Hermes Local Hands"])
            _git(str(staging), ["add", "--all"], timeout=120)
            _git(
                str(staging),
                ["commit", "--quiet", "--no-verify", "--no-gpg-sign", "-m", "isolated snapshot"],
                timeout=120,
            )
            if not _snapshot_name_matches_descriptor(staging, snapshot_fd):
                raise ExecutionError("managed snapshot staging directory changed during creation")
            _publish_directory_noreplace(staging, destination)
            if not _snapshot_name_matches_descriptor(destination, snapshot_fd):
                raise ExecutionError("managed snapshot destination changed while publishing")
        except BaseException:
            if snapshot_fd is not None:
                try:
                    _clear_bound_snapshot_directory(snapshot_fd)
                except BaseException:  # noqa: S110 -- cleanup must preserve triggering exception
                    pass
            raise
        finally:
            if snapshot_fd is not None:
                try:
                    os.close(snapshot_fd)
                except OSError:  # noqa: S110 -- cleanup must preserve triggering exception
                    pass
            if lock_fd is not None:
                try:
                    _release_snapshot_lock(lock_fd)
                except OSError:  # noqa: S110 -- close still releases a POSIX flock
                    pass
    return str(destination)


def apply_patch(worktree: str, patch: str) -> None:
    """Apply an already validated patch only inside its managed snapshot."""

    validate_patch(patch)
    _git_bytes(
        worktree,
        ["apply", "--index", "--whitespace=error-all", "-"],
        input_bytes=patch.encode("utf-8"),
    )


_ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_PEM_BLOCK = re.compile(r"-----BEGIN [^-\r\n]+-----.*?-----END [^-\r\n]+-----", re.DOTALL)
_TOKEN_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key)\s*[:=]\s*([^\s,;]+)"
)
_KNOWN_TOKEN = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}")
_ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9:])/(?!/)[^\s:'\"<>]+")


def _redact_text(value: str, worktree: str) -> str:
    for spelling in {worktree, str(Path(worktree).resolve())}:
        if spelling:
            value = value.replace(spelling, "<SNAPSHOT>")
    value = _ANSI_ESCAPE.sub("", value)
    value = _PEM_BLOCK.sub("<REDACTED_PRIVATE_MATERIAL>", value)
    value = _BEARER.sub("Bearer <REDACTED>", value)
    value = _KNOWN_TOKEN.sub("<REDACTED_TOKEN>", value)
    value = _TOKEN_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=<REDACTED>", value)
    value = _ABSOLUTE_PATH.sub("<LOCAL_PATH>", value)
    return "".join(
        character for character in value if character in "\n\r\t" or ord(character) >= 32
    )


def run_profile(
    worktree: str, argv: tuple[str, ...], *, timeout_seconds: int = 120
) -> dict[str, object]:
    if not argv or timeout_seconds < 1 or timeout_seconds > 900:
        raise PolicyError("invalid test profile or timeout")
    home = Path(worktree) / ".home"
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
        "PAGER": "cat",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
    }
    home.mkdir(mode=0o700, exist_ok=True)
    process: subprocess.Popen[bytes] | None = None
    timed_out = False
    clipped = False
    process_group_kill_attempted = False
    captured = bytearray()
    result: dict[str, object]
    try:
        process = subprocess.Popen(  # noqa: S603 -- exact registered local profile
            list(argv),
            cwd=worktree,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            start_new_session=True,
            env=environment,
        )
        deadline = monotonic() + timeout_seconds
        assert process.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                wait = deadline - monotonic()
                if wait <= 0:
                    timed_out = True
                    break
                events = selector.select(wait)
                if not events and process.poll() is not None:
                    continue
                for key, _ in events:
                    chunk = os.read(key.fileobj.fileno(), 65_536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if len(captured) + len(chunk) > _MAX_OUTPUT_BYTES:
                        remaining = max(0, _MAX_OUTPUT_BYTES - len(captured))
                        captured.extend(chunk[:remaining])
                        clipped = True
                        break
                    captured.extend(chunk)
                if clipped:
                    break
        if timed_out or clipped:
            process_group_kill_attempted = True
            _kill_process_group(process)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process_group_kill_attempted = True
            _kill_process_group(process)
            process.wait(timeout=10)

        raw_output = bytes(captured)
        decoded = raw_output.decode("utf-8", "replace")
        redacted = _redact_text(decoded, worktree)
        excerpt_bytes = redacted.encode("utf-8")[:_MAX_OUTPUT_EXCERPT_BYTES]
        excerpt = excerpt_bytes.decode("utf-8", "ignore")
        result = {
            "exit_code": process.returncode,
            "timed_out": timed_out,
            "output": excerpt,
            "output_excerpt": excerpt,
            "output_sha256": hashlib.sha256(raw_output).hexdigest(),
            "output_bytes": len(raw_output),
            "output_truncated": clipped or len(redacted.encode("utf-8")) > len(excerpt_bytes),
            # A profile can deliberately double-fork/setsid.  The process group is
            # killed on timeout/output overflow, but this is not an OS sandbox and
            # must never be represented as a complete descendant-process guarantee.
            "process_group_kill_attempted": process_group_kill_attempted,
            "process_cleanup_guaranteed": False,
            "worktree": worktree,
        }
    except BaseException as exc:
        if process is not None:
            process_group_kill_attempted = True
            _stop_and_reap_best_effort(process)
            if isinstance(exc, Exception):
                raise UncertainExecutionError(
                    "test profile outcome is uncertain after an internal execution failure"
                ) from exc
        raise
    finally:
        try:
            shutil.rmtree(home, ignore_errors=True)
        except BaseException:  # noqa: S110 -- cleanup must preserve the triggering exception
            pass

    result["temporary_home_removed"] = not home.exists()
    return result
