"""Keep CLI diagnostics separate from state initialization."""

from __future__ import annotations

import json

import pytest

from hermes_local_hands import cli, doctor


@pytest.mark.parametrize("as_json", [False, True])
def test_doctor_missing_state_never_builds_service(tmp_path, monkeypatch, capsys, as_json):
    state = tmp_path / "missing"

    def forbidden(*args, **kwargs):
        pytest.fail("diagnostics must not initialize a service")

    monkeypatch.setattr(cli, "build_service", forbidden)
    args = ["--state-dir", str(state), "doctor"]
    if as_json:
        args.append("--json")
    assert cli.run(args) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    assert not state.exists()
    assert str(tmp_path) not in captured.out
    if as_json:
        report = json.loads(captured.out)
        assert report["schema_version"] == 1
        assert report["ok"] is False
        assert any(
            check["id"] == "state_directory" and check["status"] == "fail"
            for check in report["checks"]
        )
    else:
        assert "not initialized" in captured.out
        assert "not verified readiness" in captured.out


def test_doctor_forwards_explicit_options_and_warns_about_incomplete_checks(
    tmp_path, monkeypatch, capsys
):
    state = tmp_path / "not-created"
    observed = []

    def report(state_dir, **options):
        observed.append((state_dir, options))
        return {
            "schema_version": 1,
            "ok": True,
            "checks": [
                {
                    "id": "endpoint",
                    "status": "warn",
                    "message": "Reachability does not verify authentication.",
                    "hint": "Verify authenticated MCP separately.",
                }
            ],
        }

    monkeypatch.setattr(doctor, "doctor_report", report)
    assert (
        cli.run(
            [
                "--state-dir",
                str(state),
                "doctor",
                "--workspace",
                "toy",
                "--client",
                "demo",
                "--endpoint",
                "http://127.0.0.1:8741/mcp",
            ]
        )
        == 0
    )
    assert observed == [
        (
            state,
            {
                "workspace_id": "toy",
                "client_id": "demo",
                "endpoint": "http://127.0.0.1:8741/mcp",
            },
        )
    ]
    output = capsys.readouterr().out
    assert "[WARN] Reachability does not verify authentication." in output
    assert "Next: Verify authenticated MCP separately." in output
    assert "not verified readiness" in output
    assert not state.exists()
