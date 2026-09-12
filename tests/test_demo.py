"""Exercise the real demo workflow and its local approval boundaries."""

from __future__ import annotations

import io
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from hermes_local_hands import cli


class DemoTerminal(io.StringIO):
    def __init__(self, reviews: list[dict[str, Any]], decisions: list[str]) -> None:
        super().__init__()
        self.reviews = reviews
        self.decisions = iter(decisions)

    def isatty(self) -> bool:
        return True

    def readline(self, size: int = -1) -> str:
        decision = next(self.decisions, "")
        if decision == "interrupt":
            raise KeyboardInterrupt
        if decision == "approve":
            return str(self.reviews[-1]["approval_code"]) + "\n"
        return decision + "\n"


def terminal(monkeypatch, decisions: list[str]) -> list[dict[str, Any]]:
    reviews: list[dict[str, Any]] = []
    render = cli._emit_request_review

    def review(value: dict[str, Any]) -> None:
        reviews.append(value)
        render(value)

    monkeypatch.setattr(cli, "_emit_request_review", review)
    monkeypatch.setattr(sys, "stdin", DemoTerminal(reviews, decisions))
    return reviews


def requests(directory: Path) -> list[tuple[str, str, str]]:
    connection = sqlite3.connect(
        f"{(directory / 'state/hands.sqlite3').as_uri()}?mode=ro", uri=True
    )
    try:
        return connection.execute(
            "SELECT kind,state,result_json FROM requests ORDER BY created_at"
        ).fetchall()
    finally:
        connection.close()


def test_complete_demo_uses_two_approvals_and_never_touches_default_state(
    tmp_path, monkeypatch, capsys
):
    directory = tmp_path / "toy"
    unrelated = tmp_path / "normal-state"
    unrelated.mkdir()
    sentinel = unrelated / "sentinel"
    sentinel.write_text("keep me", encoding="utf-8")
    monkeypatch.setattr(cli, "default_state_dir", lambda: unrelated)
    reviews = terminal(monkeypatch, ["approve", "approve"])

    assert cli.run(["demo", "--directory", str(directory)]) == 0
    output = capsys.readouterr()
    assert output.err == ""
    assert "PASS: approved patch + linked check + receipt verification" in output.out
    assert "BEGIN UNTRUSTED PATCH" in output.out
    assert "not a two-machine, Hermes, or sandbox validation" in output.out
    assert "Check program:" in output.out
    assert len(reviews) == 2
    assert reviews[0]["kind"] == "patch"
    assert reviews[1]["kind"] == "test"
    assert reviews[0]["approval_code"] != reviews[1]["approval_code"]
    assert reviews[1]["payload"]["patch_request_id"] == reviews[0]["request_id"]
    assert (directory / "repository/src/greeting.txt").read_text() == "Hello from Hermes.\n"
    assert sorted(path.name for path in unrelated.iterdir()) == ["sentinel"]
    assert sentinel.read_text() == "keep me"
    assert os.stat(directory).st_mode & 0o777 == 0o700
    records = requests(directory)
    assert [(kind, state) for kind, state, _ in records] == [
        ("patch", "succeeded"),
        ("test", "succeeded"),
    ]
    assert json.loads(records[1][2])["passed"] is True
    assert "demo-client.token" not in output.out


@pytest.mark.parametrize("decision", ["", "yes", "WRONG-CODE", "interrupt"])
def test_declined_or_interrupted_patch_never_executes(tmp_path, monkeypatch, capsys, decision):
    directory = tmp_path / "toy"
    terminal(monkeypatch, [decision])
    assert cli.run(["demo", "--directory", str(directory)]) == 1
    capsys.readouterr()
    records = requests(directory)
    assert len(records) == 1
    assert records[0][0] == "patch"
    assert records[0][1] in {"rejected", "pending"}
    assert not (directory / "state/snapshots").exists()
    assert (directory / "repository/src/greeting.txt").read_text() == "Hello from Hermes.\n"


def test_check_needs_its_own_approval(tmp_path, monkeypatch, capsys):
    directory = tmp_path / "toy"
    terminal(monkeypatch, ["approve", ""])
    assert cli.run(["demo", "--directory", str(directory)]) == 1
    capsys.readouterr()
    assert [(kind, state) for kind, state, _ in requests(directory)] == [
        ("patch", "succeeded"),
        ("test", "rejected"),
    ]
    assert (directory / "repository/src/greeting.txt").read_text() == "Hello from Hermes.\n"


def test_noninteractive_demo_refuses_before_creating_any_files(tmp_path, monkeypatch, capsys):
    directory = tmp_path / "toy"
    monkeypatch.setattr(sys, "stdin", io.StringIO("yes\nyes\n"))
    assert cli.run(["demo", "--directory", str(directory)]) == 2
    assert "interactive terminal" in capsys.readouterr().err
    assert not directory.exists()


@pytest.mark.parametrize("symlink", [False, True])
def test_demo_never_reuses_existing_directory(tmp_path, monkeypatch, capsys, symlink):
    original = tmp_path / "original"
    original.mkdir()
    sentinel = original / "keep.txt"
    sentinel.write_text("untouched", encoding="utf-8")
    directory = tmp_path / "toy" if symlink else original
    if symlink:
        directory.symlink_to(original, target_is_directory=True)
    terminal(monkeypatch, [])
    assert cli.run(["demo", "--directory", str(directory)]) == 2
    assert capsys.readouterr().err
    assert sentinel.read_text() == "untouched"
    assert sorted(path.name for path in original.iterdir()) == ["keep.txt"]


def test_demo_refuses_existing_state_argument_before_changes(tmp_path, monkeypatch, capsys):
    terminal(monkeypatch, [])
    directory = tmp_path / "toy"
    state = tmp_path / "state"
    assert cli.run(["--state-dir", str(state), "demo", "--directory", str(directory)]) == 2
    assert "omit --state-dir" in capsys.readouterr().err
    assert not directory.exists()
    assert not state.exists()


def test_config_rendering_does_not_initialize_service(tmp_path, capsys):
    state = tmp_path / "missing"
    assert cli.run(["--state-dir", str(state), "hermes-config"]) == 0
    assert "mcp_servers:" in capsys.readouterr().out
    assert not state.exists()


def test_cli_import_does_not_require_git_or_bootstrap_service():
    result = subprocess.run(  # noqa: S603 -- fixed Python executable and diagnostic source
        [
            sys.executable,
            "-c",
            (
                "import sys; import hermes_local_hands.cli; "
                "assert 'hermes_local_hands.gitops' not in sys.modules; "
                "assert 'hermes_local_hands.service' not in sys.modules; "
                "assert 'hermes_local_hands.mcp_server' not in sys.modules"
            ),
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_lazy_package_exports_preserve_public_api():
    import hermes_local_hands as package
    from hermes_local_hands.receipts import ReceiptLedger
    from hermes_local_hands.service import LocalHandsService
    from hermes_local_hands.storage import Store

    assert package.LocalHandsService is LocalHandsService
    assert package.ReceiptLedger is ReceiptLedger
    assert package.Store is Store
    with pytest.raises(AttributeError):
        _ = package.not_an_export
