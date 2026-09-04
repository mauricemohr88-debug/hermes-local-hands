# ruff: noqa: S104, S106, S603, S607
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from hermes_local_hands.cli import _terminal_safe_line, build_service, run
from hermes_local_hands.hermes_config import render_hermes_config
from hermes_local_hands.mcp_server import validate_proxy_host


def test_rendered_hermes_yaml_is_token_free_and_narrow():
    rendered = render_hermes_config(
        endpoint="http://127.0.0.1:8741/mcp", token_env="HERMES_LOCAL_HANDS_TOKEN"
    )
    assert "mcp_servers:" in rendered
    assert "Bearer ${env:HERMES_LOCAL_HANDS_TOKEN}" in rendered
    assert "approve" not in rendered
    assert "deny" not in rendered
    assert "propose_patch" in rendered


def test_hermes_endpoint_validation_accepts_explicit_https_and_rejects_url_confusion():
    rendered = render_hermes_config(
        endpoint="HTTPS://STUDIO.EXAMPLE.NET:443/mcp", token_env="HERMES_LOCAL_HANDS_TOKEN"
    )
    assert "    url: https://studio.example.net:443/mcp\n" in rendered
    for malicious in (
        "http://127.0.0.1:8741@evil.example/mcp",
        "http://127.0.0.1:80.evil.example/mcp",
        "https://studio.example.net/mcp?token=bad",
        "http://studio.example.net/mcp",
    ):
        with pytest.raises(ValueError):
            render_hermes_config(endpoint=malicious, token_env="HERMES_LOCAL_HANDS_TOKEN")


@pytest.mark.parametrize(
    "malicious",
    [
        "\nhttps://studio.example.net/mcp",
        " https://studio.example.net/mcp",
        "https://studio. example.net/mcp",
        "https://studio.example.net\t/mcp",
        "https://studio.example.net\x00/mcp",
        "https://studio.example.net\x7f/mcp",
        "https://studio.example.net\r\n.invalid/mcp",
        "https://studio.example.net/mcp\nurl: https://evil.example/mcp",
        "https://stüdio.example.net/mcp",
        "https://studio。example.net/mcp",
        "https://-studio.example.net/mcp",
        "https://studio..example.net/mcp",
        "https://studio.example.net.:443/mcp",
        "https://studio_example.net/mcp",
        "https://studio.example.net:/mcp",
        "https://studio.example.net:0443/mcp",
        "https://studio.example.net:0/mcp",
        "https://studio.example.net:65536/mcp",
        "https://2130706433/mcp",
        "https://0x7f.0.0.1/mcp",
        "https://[::ffff:127.0.0.1]/mcp",
    ],
)
def test_hermes_endpoint_rejects_control_whitespace_and_ambiguous_hosts(malicious):
    with pytest.raises(ValueError):
        render_hermes_config(endpoint=malicious, token_env="HERMES_LOCAL_HANDS_TOKEN")


def test_rendered_endpoint_is_exactly_one_safe_yaml_line():
    rendered = render_hermes_config(
        endpoint="HTTP://[0:0:0:0:0:0:0:1]:8741/mcp",
        token_env="HERMES_LOCAL_HANDS_TOKEN",
    )
    url_lines = [line for line in rendered.splitlines() if line.lstrip().startswith("url:")]
    assert url_lines == ["    url: http://[::1]:8741/mcp"]


def test_proxy_host_is_exact_and_never_a_wildcard_or_url():
    assert validate_proxy_host("studio.tailnet.ts.net") == "studio.tailnet.ts.net"
    assert validate_proxy_host("studio.tailnet.ts.net:443") == "studio.tailnet.ts.net:443"
    for invalid in (
        "*.tailnet.ts.net",
        "https://studio.tailnet.ts.net",
        "127.0.0.1",
        "x@y",
        "a..example.net",
        "-a.example.net",
        "a-.example.net",
        f"{'a' * 64}.example.net",
        "studio.example.net:0",
    ):
        with pytest.raises(ValueError):
            validate_proxy_host(invalid)


def test_terminal_review_line_escapes_bidi_and_control_characters():
    rendered = _terminal_safe_line("safe\u202e\x1b[31m")
    assert rendered == r"safe\u202e\u001b[31m"
    assert "\u202e" not in rendered
    assert "\x1b" not in rendered


def test_cli_refuses_non_loopback_bind(tmp_path, capsys):
    status = run(["--state-dir", str(tmp_path), "serve", "--host", "0.0.0.0"])
    assert status == 2
    assert "only bind" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["serve", "hermes-config"])
@pytest.mark.parametrize("invalid_port", ["0", "65536", "70000", "not-a-port"])
def test_cli_rejects_invalid_ports_before_starting(command, invalid_port, tmp_path, capsys):
    with pytest.raises(SystemExit) as raised:
        run(["--state-dir", str(tmp_path), command, "--port", invalid_port])
    assert raised.value.code == 2
    assert "port must be an integer from 1 to 65535" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []


def test_cli_persists_signing_key_for_receipt_verification(tmp_path, capsys):
    assert run(["--state-dir", str(tmp_path), "init", "--client-id", "test"]) == 0
    init = json.loads(capsys.readouterr().out)
    assert init["credential_saved"] is True
    assert "token" not in init
    assert run(["--state-dir", str(tmp_path), "receipt-verify"]) == 0
    assert json.loads(capsys.readouterr().out) == {"receipts": 1, "valid": True}


def test_cli_complete_local_operator_workflow(tmp_path: Path, capsys):
    state = tmp_path / "state"
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    (repo / "src").mkdir()
    (repo / "src" / "hello.txt").write_text("hello\n")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
    service = build_service(state)

    assert run(["--state-dir", str(state), "init", "--client-id", "primary"], service=service) == 0
    initialized = json.loads(capsys.readouterr().out)
    assert initialized == {
        "client_id": "primary",
        "credential_saved": True,
        "initialized": True,
        "next": ("export the credential from the private token file into HERMES_LOCAL_HANDS_TOKEN"),
    }
    assert (state / "clients" / "primary.token").stat().st_mode & 0o777 == 0o600

    assert run(["--state-dir", str(state), "client", "add", "secondary"], service=service) == 0
    assert json.loads(capsys.readouterr().out)["created"] is True
    assert (
        run(
            [
                "--state-dir",
                str(state),
                "workspace",
                "add",
                "--id",
                "demo",
                "--root",
                str(repo),
                "--read",
                "src",
                "--write",
                "src",
                "--check",
                f"verify={sys.executable},-c,print('ok')",
                "--client",
                "primary",
            ],
            service=service,
        )
        == 0
    )
    workspace = json.loads(capsys.readouterr().out)
    assert workspace == {
        "checks": ["verify"],
        "clients": ["primary"],
        "read_allowlist": ["src"],
        "workspace_id": "demo",
        "write_allowlist": ["src"],
    }

    assert (
        run(
            ["--state-dir", str(state), "workspace", "grant", "demo", "secondary"],
            service=service,
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {
        "client_id": "secondary",
        "granted": True,
        "workspace_id": "demo",
    }
    assert run(["--state-dir", str(state), "workspace", "grants", "demo"], service=service) == 0
    assert json.loads(capsys.readouterr().out) == {
        "clients": ["primary", "secondary"],
        "workspace_id": "demo",
    }
    assert (
        run(
            ["--state-dir", str(state), "workspace", "revoke", "demo", "secondary"],
            service=service,
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {
        "client_id": "secondary",
        "revoked": True,
        "workspace_id": "demo",
    }
    assert (
        run(
            ["--state-dir", str(state), "workspace", "grant", "demo", "secondary"],
            service=service,
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["granted"] is True
    assert (
        run(
            [
                "--state-dir",
                str(state),
                "check",
                "add",
                "demo",
                "verify",
                "cli-workflow",
                "--client",
                "primary",
            ],
            service=service,
        )
        == 0
    )
    queued = json.loads(capsys.readouterr().out)
    request_id = queued["request_id"]
    assert queued["state"] == "pending"
    assert queued["client_id"] == "primary"

    assert run(["--state-dir", str(state), "request", "show", request_id], service=service) == 0
    human_review = capsys.readouterr().out
    assert human_review.startswith("Hermes Local Hands - LOCAL REQUEST REVIEW\n")
    assert "payload_metadata:\n" in human_review
    assert "approval_code:" in human_review

    assert (
        run(["--state-dir", str(state), "request", "show", request_id, "--json"], service=service)
        == 0
    )
    reviewed = json.loads(capsys.readouterr().out)
    confirmation = reviewed["approval_code"]
    assert len(confirmation) == 12
    assert reviewed["payload"] == {"profile": "verify", "timeout_seconds": 120}

    assert (
        run(
            [
                "--state-dir",
                str(state),
                "request",
                "approve",
                request_id,
                "--confirm",
                "000000000000",
            ],
            service=service,
        )
        == 2
    )
    assert "does not match" in json.loads(capsys.readouterr().err)["error"]
    assert service.store.request(request_id).state.value == "pending"

    assert (
        run(
            [
                "--state-dir",
                str(state),
                "request",
                "approve",
                request_id,
                "--confirm",
                confirmation,
            ],
            service=service,
        )
        == 0
    )
    approved = json.loads(capsys.readouterr().out)
    assert approved["state"] == "succeeded"
    assert approved["passed"] is True
    assert approved["output"] == "ok\n"

    assert (
        run(
            [
                "--state-dir",
                str(state),
                "request",
                "list",
                "--state",
                "succeeded",
            ],
            service=service,
        )
        == 0
    )
    listed = json.loads(capsys.readouterr().out)["requests"]
    assert [item["request_id"] for item in listed] == [request_id]
    assert listed[0]["state"] == "succeeded"

    assert run(["--state-dir", str(state), "snapshot", "list"], service=service) == 0
    snapshots = json.loads(capsys.readouterr().out)["snapshots"]
    assert snapshots == [{"request_id": request_id, "request_state": "succeeded"}]
    assert (
        run(
            [
                "--state-dir",
                str(state),
                "snapshot",
                "delete",
                request_id,
                "--confirm",
                "wrong-id",
            ],
            service=service,
        )
        == 2
    )
    assert "exact request id" in json.loads(capsys.readouterr().err)["error"]
    assert (
        run(
            [
                "--state-dir",
                str(state),
                "snapshot",
                "delete",
                request_id,
                "--confirm",
                request_id,
            ],
            service=service,
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {
        "deleted": True,
        "request_id": request_id,
    }
    assert run(["--state-dir", str(state), "snapshot", "list"], service=service) == 0
    assert json.loads(capsys.readouterr().out) == {"snapshots": []}

    assert run(["--state-dir", str(state), "client", "revoke", "secondary"], service=service) == 0
    revoked = json.loads(capsys.readouterr().out)
    assert revoked == {
        "client_id": "secondary",
        "credential_file_removed": True,
        "revoked": True,
    }
    assert not (state / "clients" / "secondary.token").exists()
    assert run(["--state-dir", str(state), "client", "list"], service=service) == 0
    clients = json.loads(capsys.readouterr().out)["clients"]
    assert [item["client_id"] for item in clients] == ["primary"]
    assert run(["--state-dir", str(state), "receipt-verify"], service=service) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
