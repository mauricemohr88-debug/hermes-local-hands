"""Bounded, read-only operator diagnostics; never bootstrap or repair state."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import sqlite3
import stat
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .errors import LocalHandsError
from .hermes_config import _validated_endpoint
from .paths import _unchanged

_IDENTIFIER = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_ENDPOINT_LIMIT = 5
_ENDPOINT_PROBE = """
import http.client
import ssl
import sys
from urllib.parse import urlsplit

connection = None
try:
    endpoint = urlsplit(sys.argv[1])
    if endpoint.scheme == "https":
        connection = http.client.HTTPSConnection(
            endpoint.hostname, endpoint.port, timeout=3,
            context=ssl.create_default_context(),
        )
    else:
        connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=3)
    connection.request("HEAD", "/mcp", headers={"Connection": "close"})
    response = connection.getresponse()
    print(response.status)
except Exception:
    sys.exit(2)
finally:
    if connection is not None:
        connection.close()
"""
_CHECK_IDS = (
    "python",
    "platform",
    "git",
    "state_directory",
    "state_database",
    "signing_key",
    "client",
    "client_token",
    "workspace",
    "workspace_directory",
    "workspace_grant",
    "workspace_git",
    "endpoint",
    "read_only",
)


def _check(status: str, message: str, hint: str = "") -> dict[str, str]:
    return {"status": status, "message": message, "hint": hint}


def _private(metadata: os.stat_result, *, directory: bool = False) -> None:
    expected = 0o700 if directory else 0o600
    correct_type = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode)
    if (
        not correct_type
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != expected
        or (not directory and metadata.st_nlink != 1)
    ):
        raise PermissionError("unsafe private state object")


@contextmanager
def _directory(path: Path, *, private: bool = False) -> Iterator[int]:
    """Keep traversal descriptor-relative and deny symlink or writable ancestors."""
    path = path.expanduser().absolute()
    if ".." in path.parts:
        raise PermissionError("ambiguous directory path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(path.anchor, flags)
    try:
        for component in path.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_fd
            metadata = os.fstat(descriptor)
            root_sticky = metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX
            if metadata.st_uid not in {0, os.getuid()} or (
                metadata.st_mode & 0o022 and not root_sticky
            ):
                raise PermissionError("unsafe directory ancestry")
        if private:
            _private(os.fstat(descriptor), directory=True)
        yield descriptor
    finally:
        os.close(descriptor)


@contextmanager
def _file(parent_fd: int, name: str, *, private: bool = True) -> Iterator[int]:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    try:
        metadata = os.fstat(descriptor)
        if private:
            _private(metadata)
        elif (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o022
            or metadata.st_nlink != 1
        ):
            raise PermissionError("unsafe regular file")
        yield descriptor
    finally:
        os.close(descriptor)


def _read(descriptor: int, maximum: int) -> bytes:
    before = os.fstat(descriptor)
    if before.st_size > maximum:
        raise ValueError("diagnostic read limit exceeded")
    data = bytearray()
    while len(data) <= maximum:
        chunk = os.read(descriptor, min(65_536, maximum + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    if len(data) != before.st_size or not _unchanged(before, os.fstat(descriptor)):
        raise ValueError("file changed during diagnosis")
    return bytes(data)


def _has_live_journal(state_fd: int) -> bool:
    for name in ("hands.sqlite3-wal", "hands.sqlite3-shm", "hands.sqlite3-journal"):
        try:
            with _file(state_fd, name) as descriptor:
                if os.fstat(descriptor).st_size:
                    return True
        except FileNotFoundError:
            continue
    return False


def _token_check(state_fd: int, client_id: str, expected_hash: str) -> dict[str, str]:
    hint = "Restore the selected client's private credential, or create a new client explicitly."
    try:
        descriptor = os.open(
            "clients", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=state_fd
        )
        try:
            _private(os.fstat(descriptor), directory=True)
            with _file(descriptor, f"{client_id}.token") as token_fd:
                raw = _read(token_fd, 4_096)
        finally:
            os.close(descriptor)
        if not raw or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_hash):
            return _check("fail", "The saved credential does not match the selected client.", hint)
        return _check("pass", "The selected client's credential is private and matches its digest.")
    except FileNotFoundError:
        return _check("fail", "The selected client's private credential is missing.", hint)
    except (OSError, ValueError, TypeError):
        return _check(
            "fail",
            "The selected client's credential could not be read safely.",
            "Check ownership, mode 0700 on the clients directory, and mode 0600 on the token file.",
        )


def _workspace_git(root: Path, directory_fd: int) -> dict[str, str]:
    from .gitops import _git_bytes, require_git_root, sanitized_status

    hint = "Inspect the selected repository locally; doctor will not modify or run its checks."
    try:
        git_fd = os.open(".git", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
        try:
            try:
                os.stat("commondir", dir_fd=git_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                return _check("warn", "Git status was skipped for shared Git metadata.", hint)
            with _file(git_fd, "config", private=False) as config_fd:
                config = _read(config_fd, 131_072)
        finally:
            os.close(git_fd)
        # Status can invoke clean filters. Refuse config indirection and filters before
        # using the existing status helper; its hardened environment disables global config.
        parsed = _git_bytes(
            str(root),
            ["config", "--no-includes", "--null", "--file", "-", "--list"],
            input_bytes=config,
            timeout=5,
            maximum=262_144,
        )
        keys = [entry.partition(b"\n")[0].lower() for entry in parsed.split(b"\0") if entry]
        if any(
            key.startswith((b"filter.", b"include.", b"includeif.", b"submodule."))
            or key in {b"core.worktree", b"extensions.worktreeconfig", b"extensions.partialclone"}
            or (key.startswith(b"remote.") and key.endswith((b".promisor", b".partialclonefilter")))
            for key in keys
        ):
            return _check(
                "warn", "Git status was skipped because repository config needs review.", hint
            )
        try:
            os.stat(".gitmodules", dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            return _check("warn", "Git status was skipped for a repository with submodules.", hint)
        require_git_root(str(root))
        result = sanitized_status(str(root))
        if result["change_count"]:
            return _check("warn", "The selected workspace has uncommitted Git changes.", hint)
        return _check(
            "pass",
            "The selected workspace has a commit and no Git-visible changes.",
            "Git status does not prove effects outside the checkout or execute a test profile.",
        )
    except (OSError, ValueError, RuntimeError, LocalHandsError):
        return _check(
            "fail", "The selected workspace's Git status could not be checked safely.", hint
        )


def _inspect_selection(
    connection: sqlite3.Connection,
    state_fd: int,
    checks: dict[str, dict[str, str]],
    *,
    workspace_id: str | None,
    client_id: str | None,
    git_available: bool,
) -> None:
    client = None
    workspace = None
    if client_id is not None:
        client = connection.execute(
            "SELECT token_hash FROM clients WHERE client_id = ?", (client_id,)
        ).fetchone()
        if client is None:
            checks["client"] = _check(
                "fail",
                "The selected client is not registered.",
                "Choose an existing client or add one explicitly.",
            )
        else:
            checks["client"] = _check("pass", "The selected client is registered.")
            checks["client_token"] = _token_check(state_fd, client_id, client[0])
    if workspace_id is not None:
        workspace = connection.execute(
            "SELECT root FROM workspaces WHERE workspace_id = ?", (workspace_id,)
        ).fetchone()
        if workspace is None:
            checks["workspace"] = _check(
                "fail",
                "The selected workspace is not registered.",
                "Choose an existing workspace or register its explicit allowlist and client grant.",
            )
        else:
            checks["workspace"] = _check("pass", "The selected workspace is registered.")
            try:
                if not isinstance(workspace[0], str) or not Path(workspace[0]).is_absolute():
                    raise ValueError("workspace root must be absolute")
                root = Path(workspace[0])
                with _directory(root) as directory_fd:
                    checks["workspace_directory"] = _check(
                        "pass", "The selected workspace directory exists with safe ancestry."
                    )
                    if git_available:
                        checks["workspace_git"] = _workspace_git(root, directory_fd)
            except (OSError, ValueError, RuntimeError):
                checks["workspace_directory"] = _check(
                    "fail",
                    "The selected workspace directory is missing or unsafe.",
                    "Check its local path, ownership and symlinks; re-register it if needed.",
                )
    if client is not None and workspace is not None:
        granted = connection.execute(
            "SELECT 1 FROM client_workspace_grants WHERE client_id = ? AND workspace_id = ?",
            (client_id, workspace_id),
        ).fetchone()
        checks["workspace_grant"] = (
            _check("pass", "The selected client has an explicit grant for the selected workspace.")
            if granted
            else _check(
                "fail",
                "The selected client has no grant for the selected workspace.",
                "Review the workspace scope before explicitly granting this client access.",
            )
        )


def _state_checks(
    state_fd: int,
    checks: dict[str, dict[str, str]],
    *,
    workspace_id: str | None,
    client_id: str | None,
    git_available: bool,
) -> None:
    try:
        with _file(state_fd, "receipt-signing-key.ed25519") as descriptor:
            if os.fstat(descriptor).st_size != 32:
                raise ValueError("invalid key size")
        checks["signing_key"] = _check(
            "pass",
            "A private signing-key file of the expected size is present.",
            "Key identity and receipt signatures are not verified by doctor.",
        )
    except FileNotFoundError:
        checks["signing_key"] = _check(
            "fail",
            "The signing key is missing.",
            "Restore the original key; do not replace an initialized ledger's identity.",
        )
    except (OSError, ValueError):
        checks["signing_key"] = _check(
            "fail",
            "The signing-key file is unsafe or malformed.",
            "Check ownership, regular-file type and mode 0600; doctor makes no repairs.",
        )
    try:
        with _file(state_fd, "hands.sqlite3") as database_fd:
            before = os.fstat(database_fd)
            if before.st_size > 64 * 1024 * 1024:
                raise ValueError("database diagnostic size limit exceeded")
            if _has_live_journal(state_fd):
                checks["state_database"] = _check(
                    "warn",
                    "A SQLite journal is present; live state and selections were not inspected.",
                    "Retry after an operator-controlled clean service shutdown; "
                    "doctor never checkpoints or stops it.",
                )
                return
            # A read-only connection alone may create WAL/SHM files. immutable avoids
            # that, and the already validated descriptor avoids reopening a symlink.
            uri = f"file:/dev/fd/{database_fd}?mode=ro&immutable=1"
            connection = sqlite3.connect(uri, uri=True, timeout=1)
            try:
                connection.set_progress_handler(lambda: 1, 100_000)
                connection.execute("PRAGMA query_only = ON")
                connection.execute("PRAGMA trusted_schema = OFF")
                for query in (
                    "SELECT client_id, token_hash FROM clients LIMIT 0",
                    "SELECT workspace_id, root FROM workspaces LIMIT 0",
                    "SELECT client_id, workspace_id FROM client_workspace_grants LIMIT 0",
                ):
                    connection.execute(query)
                selection = dict(checks)
                _inspect_selection(
                    connection,
                    state_fd,
                    selection,
                    workspace_id=workspace_id,
                    client_id=client_id,
                    git_available=git_available,
                )
            finally:
                connection.close()
            if not _unchanged(before, os.fstat(database_fd)) or _has_live_journal(state_fd):
                checks["state_database"] = _check(
                    "warn",
                    "SQLite changed during diagnosis; selection results were discarded.",
                    "Retry when local state is stable; no state was changed by doctor.",
                )
                return
            checks.update(selection)
            checks["state_database"] = _check(
                "pass", "The existing database supports read-only selection checks."
            )
    except FileNotFoundError:
        checks["state_database"] = _check(
            "fail",
            "Local state is not initialized: the database is missing.",
            "Run init explicitly when ready to create private state.",
        )
    except (OSError, ValueError, sqlite3.Error):
        checks["state_database"] = _check(
            "fail",
            "The existing database is unsafe, incompatible, or unreadable.",
            "Check ownership, mode 0600 and schema compatibility; "
            "doctor never migrates or repairs it.",
        )


def _endpoint_check(endpoint: str | None) -> dict[str, str]:
    limit = "This does not prove authenticated MCP or tunnel setup; no credential was sent."
    if endpoint is None:
        return _check(
            "skip",
            "No endpoint supplied; no network request was made.",
            "Use --endpoint only for an explicit unauthenticated reachability probe.",
        )
    try:
        validated = _validated_endpoint(endpoint)
    except (TypeError, ValueError):
        return _check(
            "fail",
            "The supplied endpoint is invalid; no network request was made.",
            "Use loopback HTTP or explicit remote HTTPS ending exactly in /mcp, "
            "without credentials or query parameters.",
        )
    try:
        result = subprocess.run(  # noqa: S603 -- fixed isolated interpreter and validated URL
            [sys.executable, "-I", "-c", _ENDPOINT_PROBE, validated],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=_ENDPOINT_LIMIT,
            check=False,
            env={"PATH": os.defpath},
        )
        if result.returncode or not re.fullmatch(rb"[1-5][0-9]{2}\n", result.stdout):
            raise ValueError("endpoint probe failed")
        status = int(result.stdout)
        if 300 <= status < 400:
            return _check("warn", "The endpoint returned a redirect; it was not followed.", limit)
        if status == 404 or status >= 500:
            return _check(
                "warn",
                "The endpoint responded but reported an unavailable route or service.",
                limit,
            )
        return _check(
            "pass",
            "The endpoint returned an HTTP response to an unauthenticated HEAD request.",
            limit,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return _check(
            "fail",
            "The endpoint did not produce a usable response within the bounded probe.",
            "Check the listener, DNS, TLS certificate and explicit tunnel configuration. " + limit,
        )


def doctor_report(
    state_dir: Path,
    *,
    workspace_id: str | None = None,
    client_id: str | None = None,
    endpoint: str | None = None,
) -> dict[str, Any]:
    """Return path/credential-free checks; ``ok`` means no failures, not readiness.

    Missing selections are never inferred. Live SQLite journals prevent inspecting
    stale immutable database pages. A pass is a bounded observation, not a full
    security audit, authenticated MCP test, or permission to alter local state.
    """
    checks = {
        name: _check(
            "skip",
            "Not checked because a prerequisite is unavailable.",
            "Resolve preceding checks and rerun doctor.",
        )
        for name in _CHECK_IDS
    }
    checks["python"] = (
        _check("pass", "Python 3.11 or newer is available.")
        if sys.version_info >= (3, 11)
        else _check(
            "fail", "Python 3.11 or newer is required.", "Install a supported Python runtime."
        )
    )
    supported = (
        os.name == "posix" and sys.platform in {"darwin", "linux"} and hasattr(os, "O_NOFOLLOW")
    )
    checks["platform"] = (
        _check("pass", "The platform supports descriptor-relative, no-follow local checks.")
        if supported
        else _check(
            "fail",
            "This platform lacks supported safe local checks.",
            "Run doctor on macOS or Linux with POSIX no-follow support.",
        )
    )
    git_available = False
    if supported:
        try:
            from .gitops import _git_bytes, _resolve_git_executable

            _resolve_git_executable()
            _git_bytes("/", ["--version"], timeout=5, maximum=4_096)
            git_available = True
            checks["git"] = _check("pass", "A trusted Git executable is available.")
        except (OSError, ValueError, RuntimeError, LocalHandsError):
            checks["git"] = _check(
                "fail",
                "A trusted Git executable is unavailable.",
                "Install Git in a supported system location and rerun doctor.",
            )
    valid_selection = True
    for name, value in (("client", client_id), ("workspace", workspace_id)):
        if value is None:
            checks[name] = _check(
                "skip",
                f"No {name} was selected.",
                f"Use --{name} to inspect an explicit selection.",
            )
        elif not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
            valid_selection = False
            checks[name] = _check(
                "fail",
                f"The selected {name} identifier is invalid.",
                "Use 1-64 letters, digits, dots, underscores, or hyphens.",
            )
    if supported:
        try:
            with _directory(state_dir, private=True) as state_fd:
                checks["state_directory"] = _check(
                    "pass", "The private state directory is safely owned with mode 0700."
                )
                if valid_selection:
                    _state_checks(
                        checks=checks,
                        state_fd=state_fd,
                        workspace_id=workspace_id,
                        client_id=client_id,
                        git_available=git_available,
                    )
        except FileNotFoundError:
            checks["state_directory"] = _check(
                "fail",
                "Local state is not initialized: the state directory is missing.",
                "Run init explicitly when ready to create private state; doctor created nothing.",
            )
        except (OSError, ValueError, RuntimeError):
            checks["state_directory"] = _check(
                "fail",
                "The state directory or its ancestry is unsafe or inaccessible.",
                "Check ownership, mode 0700, writable ancestors and symlinks; "
                "doctor makes no repairs.",
            )
    checks["endpoint"] = _endpoint_check(endpoint)
    checks["read_only"] = _check(
        "pass",
        "Doctor did not bootstrap, migrate, repair, approve, or execute repository checks.",
        "Warnings and skips are unverified, not ready. Receipt signatures, authenticated MCP "
        "and tunnel setup require separate verification.",
    )
    result = [{"id": name, **checks[name]} for name in _CHECK_IDS]
    return {
        "schema_version": 1,
        "ok": not any(check["status"] == "fail" for check in result),
        "checks": result,
    }
