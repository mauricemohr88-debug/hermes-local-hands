# ruff: noqa: S101, S106, S603, S607
from __future__ import annotations

import hashlib
import http.client
import json
import os
import sqlite3
import ssl
import subprocess
import sys
from types import SimpleNamespace

import pytest

from hermes_local_hands import doctor
from hermes_local_hands.doctor import doctor_report


def _checks(report):
    return {check["id"]: check for check in report["checks"]}


def _snapshot(root):
    result = {}
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.lstat()
        result[str(path.relative_to(root))] = (
            info.st_mode,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
            os.readlink(path)
            if path.is_symlink()
            else path.read_bytes()
            if path.is_file()
            else None,
        )
    return result


def _git(root, *args):
    from hermes_local_hands.gitops import _git_bytes

    return _git_bytes(str(root), args)


@pytest.fixture
def state(tmp_path):
    root = tmp_path / "private-state"
    root.mkdir(mode=0o700)
    clients = root / "clients"
    clients.mkdir(mode=0o700)
    token = "private-credential-must-never-appear"  # noqa: S105 -- synthetic fixture
    (clients / "test.token").write_text(token)
    (clients / "test.token").chmod(0o600)
    (root / "receipt-signing-key.ed25519").write_bytes(b"k" * 32)
    (root / "receipt-signing-key.ed25519").chmod(0o600)
    db = root / "hands.sqlite3"
    connection = sqlite3.connect(db)
    connection.executescript(
        "CREATE TABLE clients (client_id TEXT PRIMARY KEY, token_hash TEXT);"
        "CREATE TABLE workspaces (workspace_id TEXT PRIMARY KEY, root TEXT);"
        "CREATE TABLE client_workspace_grants (client_id TEXT, workspace_id TEXT);"
    )
    connection.execute(
        "INSERT INTO clients VALUES (?, ?)", ("test", hashlib.sha256(token.encode()).hexdigest())
    )
    connection.commit()
    connection.close()
    db.chmod(0o600)
    return root


@pytest.fixture
def workspace(state, tmp_path):
    root = tmp_path / "repository"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Test")
    _git(root, "config", "user.email", "test@example.invalid")
    (root / "fixture.txt").write_text("private source never included\n")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "fixture")
    connection = sqlite3.connect(state / "hands.sqlite3")
    connection.execute("INSERT INTO workspaces VALUES (?, ?)", ("demo", str(root)))
    connection.execute("INSERT INTO client_workspace_grants VALUES ('test', 'demo')")
    connection.commit()
    connection.close()
    return root


def test_missing_state_is_distinct_from_unsafe_and_creates_nothing(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("doctor must not open SQLite or probe a network endpoint")

    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    before = _snapshot(tmp_path)
    report = doctor_report(tmp_path / "missing", client_id="test", workspace_id="demo")
    assert report["ok"] is False
    checks = _checks(report)
    assert "not initialized" in checks["state_directory"]["message"]
    assert checks["client"]["status"] == checks["workspace"]["status"] == "skip"
    assert checks["endpoint"]["status"] == "skip"
    assert _snapshot(tmp_path) == before


def test_existing_state_and_workspace_are_read_only_and_output_is_shareable(state, workspace):
    before = _snapshot(state.parent)
    report = doctor_report(state, client_id="test", workspace_id="demo")
    assert report["ok"] is True
    checks = _checks(report)
    for key in (
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
    ):
        assert checks[key]["status"] == "pass", (key, checks[key])
    assert _snapshot(state.parent) == before
    output = json.dumps(report)
    assert str(state.parent) not in output
    assert "private-credential-must-never-appear" not in output
    assert "private source never included" not in output
    assert all(set(check) == {"id", "status", "message", "hint"} for check in report["checks"])
    assert report["schema_version"] == 1


def test_database_uses_read_only_immutable_uri(state, monkeypatch):
    original = sqlite3.connect
    observed = []

    def connect(database, **kwargs):
        observed.append((database, kwargs))
        return original(database, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", connect)
    assert doctor_report(state, client_id="test")["ok"] is True
    assert len(observed) == 1
    assert observed[0][0].startswith("file:/dev/fd/")
    assert "mode=ro&immutable=1" in observed[0][0]
    assert observed[0][1]["uri"] is True


@pytest.mark.parametrize("selected", ["client", "workspace"])
def test_selected_missing_object_is_never_green(state, selected):
    report = doctor_report(state, **{f"{selected}_id": "not-registered"})
    assert report["ok"] is False
    assert _checks(report)[selected]["status"] == "fail"


def test_missing_grant_is_failure(state, workspace):
    connection = sqlite3.connect(state / "hands.sqlite3")
    connection.execute("DELETE FROM client_workspace_grants")
    connection.commit()
    connection.close()
    report = doctor_report(state, client_id="test", workspace_id="demo")
    assert report["ok"] is False
    assert _checks(report)["workspace_grant"]["status"] == "fail"


@pytest.mark.parametrize(
    "name", ["hands.sqlite3", "clients/test.token", "receipt-signing-key.ed25519"]
)
def test_private_file_permissions_fail_without_repair(state, name):
    (state / name).chmod(0o644)
    before = _snapshot(state)
    report = doctor_report(state, client_id="test")
    assert report["ok"] is False
    assert _snapshot(state) == before
    assert str(state) not in json.dumps(report)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_unsafe_database_types_fail_without_following_or_blocking(state, tmp_path, kind):
    database = state / "hands.sqlite3"
    target = tmp_path / "original.sqlite3"
    database.rename(target)
    if kind == "symlink":
        database.symlink_to(target)
    elif kind == "hardlink":
        os.link(target, database)
    else:
        os.mkfifo(database, mode=0o600)
    report = doctor_report(state)
    assert report["ok"] is False
    assert _checks(report)["state_database"]["status"] == "fail"


def test_symlinked_state_ancestor_is_rejected(state, tmp_path):
    alias = tmp_path / "alias"
    alias.symlink_to(state.parent, target_is_directory=True)
    report = doctor_report(alias / state.name)
    assert _checks(report)["state_directory"]["status"] == "fail"
    assert "unsafe" in _checks(report)["state_directory"]["message"]


def test_public_state_directory_is_not_silently_fixed(state):
    state.chmod(0o755)
    before = _snapshot(state)
    report = doctor_report(state)
    assert _checks(report)["state_directory"]["status"] == "fail"
    assert _snapshot(state) == before


def test_wrong_owner_is_rejected(state, monkeypatch):
    owner = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: owner + 100)
    assert _checks(doctor_report(state))["state_directory"]["status"] == "fail"


def test_credential_mismatch_or_absence_does_not_leak_content(state):
    token = state / "clients" / "test.token"
    token.write_text("VERY-SECRET-MISMATCH")
    report = doctor_report(state, client_id="test")
    assert _checks(report)["client_token"]["status"] == "fail"
    assert "VERY-SECRET-MISMATCH" not in json.dumps(report)
    token.unlink()
    assert _checks(doctor_report(state, client_id="test"))["client_token"]["status"] == "fail"


def test_live_wal_is_not_opened_or_checkpointed(state, monkeypatch):
    connection = sqlite3.connect(state / "hands.sqlite3")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("INSERT INTO clients VALUES ('live', 'digest')")
    connection.commit()
    before = _snapshot(state)
    try:
        monkeypatch.setattr(sqlite3, "connect", lambda *a, **kw: pytest.fail("live WAL opened"))
        report = doctor_report(state, client_id="live", workspace_id="demo")
        checks = _checks(report)
        assert checks["state_database"]["status"] == "warn"
        assert checks["client"]["status"] == checks["workspace"]["status"] == "skip"
        assert _snapshot(state) == before
    finally:
        connection.close()


def test_incompatible_database_is_not_migrated(state):
    connection = sqlite3.connect(state / "hands.sqlite3")
    connection.execute("DROP TABLE clients")
    connection.commit()
    connection.close()
    before = _snapshot(state)
    report = doctor_report(state, client_id="test")
    assert _checks(report)["state_database"]["status"] == "fail"
    assert _snapshot(state) == before


def test_dirty_workspace_reports_warning_without_file_names(state, workspace):
    (workspace / "fixture.txt").write_text("private changed source")
    before = _snapshot(workspace)
    report = doctor_report(state, workspace_id="demo")
    assert _checks(report)["workspace_git"]["status"] == "warn"
    assert "fixture.txt" not in json.dumps(report)
    assert _snapshot(workspace) == before


def test_git_filter_configuration_is_not_executed(state, workspace, tmp_path):
    marker = tmp_path / "filter-executed"
    _git(workspace, "config", "filter.bad.clean", f"touch '{marker}'")
    (workspace / ".gitattributes").write_text("* filter=bad\n")
    (workspace / "fixture.txt").write_text("trigger clean filter")
    report = doctor_report(state, workspace_id="demo")
    assert _checks(report)["workspace_git"]["status"] == "warn"
    assert not marker.exists()


@pytest.mark.parametrize(
    "key",
    ["remote.origin.promisor", "remote.origin.partialclonefilter", "extensions.partialClone"],
)
def test_partial_clone_status_is_skipped_without_fetching(state, workspace, monkeypatch, key):
    from hermes_local_hands import gitops

    _git(workspace, "config", key, "true")
    monkeypatch.setattr(
        gitops, "sanitized_status", lambda *args: pytest.fail("partial clone status executed")
    )
    report = doctor_report(state, workspace_id="demo")
    assert _checks(report)["workspace_git"]["status"] == "warn"


def test_missing_git_is_a_structured_failure(state, monkeypatch):
    from hermes_local_hands import gitops

    def missing():
        raise RuntimeError("missing trusted executable at /private/SECRET")

    monkeypatch.setattr(gitops, "_resolve_git_executable", missing)
    report = doctor_report(state, client_id="test")
    assert report["ok"] is False
    assert _checks(report)["git"]["status"] == "fail"
    assert _checks(report)["client_token"]["status"] == "pass"
    assert "SECRET" not in json.dumps(report)


def test_unsupported_platform_does_not_attempt_state_inspection(state, monkeypatch):
    monkeypatch.setattr(sys, "platform", "unsupported")
    monkeypatch.setattr(
        doctor, "_directory", lambda *a, **kw: pytest.fail("unsupported platform opened state")
    )
    report = doctor_report(state)
    assert _checks(report)["platform"]["status"] == "fail"
    assert _checks(report)["state_directory"]["status"] == "skip"


def test_missing_workspace_directory_fails_without_recreating_it(state, workspace):
    parked = workspace.with_name("parked")
    workspace.rename(parked)
    report = doctor_report(state, workspace_id="demo")
    assert report["ok"] is False
    assert _checks(report)["workspace_directory"]["status"] == "fail"
    assert not workspace.exists()


def test_state_mutation_discards_potentially_stale_selection_results(state, monkeypatch):
    original = doctor._inspect_selection

    def inspect(*args, **kwargs):
        original(*args, **kwargs)
        database = state / "hands.sqlite3"
        metadata = database.stat()
        os.utime(database, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000))

    monkeypatch.setattr(doctor, "_inspect_selection", inspect)
    report = doctor_report(state, client_id="test")
    assert _checks(report)["state_database"]["status"] == "warn"
    assert _checks(report)["client"]["status"] == "skip"


def test_git_failure_does_not_leak_exception_details(state, workspace, monkeypatch):
    from hermes_local_hands import gitops

    def failure(*args, **kwargs):
        raise RuntimeError(f"{workspace}/private-source: SECRET-DETAIL")

    monkeypatch.setattr(gitops, "sanitized_status", failure)
    report = doctor_report(state, workspace_id="demo")
    assert _checks(report)["workspace_git"]["status"] == "fail"
    assert "SECRET-DETAIL" not in json.dumps(report)
    assert str(workspace) not in json.dumps(report)


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://user:secret@example.invalid/mcp",
        "http://example.invalid/mcp",
        "https://example.invalid/mcp?token=private",
        "https://2130706433/mcp",
        "https://example.invalid/mcp\n",
        "https://example.invalid/other",
    ],
)
def test_invalid_endpoint_never_starts_probe(endpoint, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("invalid endpoint probed"))
    result = doctor._endpoint_check(endpoint)
    assert result["status"] == "fail"
    assert endpoint not in json.dumps(result)


@pytest.mark.parametrize(
    ("code", "status"),
    [(200, "pass"), (401, "pass"), (405, "pass"), (302, "warn"), (404, "warn"), (503, "warn")],
)
def test_endpoint_probe_is_bounded_isolated_and_only_claims_reachability(code, status, monkeypatch):
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, f"{code}\n".encode(), b"")

    monkeypatch.setattr(subprocess, "run", run)
    result = doctor._endpoint_check("HTTPS://HOST.EXAMPLE:443/mcp")
    assert result["status"] == status
    assert "does not prove authenticated MCP or tunnel setup" in result["hint"]
    args, kwargs = calls[0]
    assert args[:3] == [sys.executable, "-I", "-c"]
    assert args[-1] == "https://host.example:443/mcp"
    assert kwargs["timeout"] == 5
    assert kwargs["env"] == {"PATH": os.defpath}
    assert kwargs["stdin"] == subprocess.DEVNULL
    assert len(calls) == 1


@pytest.mark.parametrize(
    "error", [OSError("/private/SECRET"), subprocess.TimeoutExpired("SECRET", 5)]
)
def test_endpoint_failures_are_sanitized(error, monkeypatch):
    def failure(*args, **kwargs):
        raise error

    monkeypatch.setattr(subprocess, "run", failure)
    result = doctor._endpoint_check("https://host.example/mcp")
    assert result["status"] == "fail"
    assert "SECRET" not in json.dumps(result)


def test_probe_script_verifies_tls_and_does_not_send_token_or_follow_redirect(monkeypatch, capsys):
    calls = []
    context = ssl.create_default_context()

    class Connection:
        def __init__(self, host, port, *, timeout, context):
            calls.append((host, port, timeout, context))

        def request(self, method, path, *, headers):
            calls.append((method, path, headers))

        def getresponse(self):
            return SimpleNamespace(status=302)

        def close(self):
            calls.append("closed")

    monkeypatch.setattr(http.client, "HTTPSConnection", Connection)
    monkeypatch.setattr(ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(sys, "argv", ["probe", "https://host.example:443/mcp"])
    exec(doctor._ENDPOINT_PROBE, {})  # noqa: S102 -- fixed internal probe code
    assert calls[0] == ("host.example", 443, 3, context)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert calls[1] == ("HEAD", "/mcp", {"Connection": "close"})
    assert calls[2:] == ["closed"]
    assert capsys.readouterr().out == "302\n"
