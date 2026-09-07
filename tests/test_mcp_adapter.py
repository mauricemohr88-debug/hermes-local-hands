"""Interface tests: token boundary, MCP exposure, and redacted output."""
# ruff: noqa: S104, S603, S607

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from hermes_local_hands.auth import BearerAuthenticationMiddleware, current_client_id
from hermes_local_hands.errors import LocalHandsError
from hermes_local_hands.mcp_server import (
    MCPAdapter,
    build_mcp_server,
    create_mcp_app,
    require_loopback,
)
from hermes_local_hands.models import WorkspacePolicy
from hermes_local_hands.service import LocalHandsService
from hermes_local_hands.storage import Store


async def _async_call(app, headers):
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    await app(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "scheme": "http",
            "server": ("127.0.0.1", 8741),
            "client": ("127.0.0.1", 54321),
            "headers": headers,
            "method": "POST",
            "path": "/mcp",
            "raw_path": b"/mcp",
            "query_string": b"",
        },
        receive,
        send,
    )
    return sent


def _call(app, headers):
    return asyncio.run(_async_call(app, headers))


def _service() -> tuple[LocalHandsService, TemporaryDirectory[str]]:
    directory = TemporaryDirectory()
    return (
        LocalHandsService(Store(str(Path(directory.name) / "state" / "hands.sqlite3"))),
        directory,
    )


async def _echo(scope, receive, send):
    await send({"type": "http.response.start", "status": 204, "headers": []})
    await send({"type": "http.response.body", "body": b""})


def test_bearer_middleware_denies_missing_malformed_duplicate_and_revoked_tokens():
    service, directory = _service()
    try:
        token = service.bootstrap_client("one")
        app = BearerAuthenticationMiddleware(_echo, service)
        cases = [
            [],
            [(b"authorization", b"Basic ignored")],
            [(b"authorization", f"Bearer {token}".encode()), (b"authorization", b"Bearer second")],
        ]
        for headers in cases:
            assert _call(app, headers)[0]["status"] == 401
        assert _call(app, [(b"authorization", f"Bearer {token}".encode())])[0]["status"] == 204
        service.store.revoke_client("one")
        assert _call(app, [(b"authorization", f"Bearer {token}".encode())])[0]["status"] == 401
    finally:
        directory.cleanup()


def test_remote_tools_are_narrow_and_requests_are_client_bound():
    service, directory = _service()
    try:
        repo = Path(directory.name) / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True
        )
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
        (repo / "src").mkdir()
        (repo / "src" / "hello.txt").write_text("hello\n")
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
        service.bootstrap_client("first")
        service.bootstrap_client("second")
        service.register_workspace(
            WorkspacePolicy("demo", str(repo), ("src",), write_allowlist=("src",)),
            client_ids=("first",),
        )
        adapter = MCPAdapter(service)
        exposed = {item["name"] for item in adapter.list_tools()}
        assert exposed == {
            "workspace_status",
            "read_file",
            "propose_patch",
            "request_check",
            "request_status",
        }
        assert not {"approve", "deny", "shell", "command"} & exposed
        first = current_client_id.set("first")
        try:
            request = adapter.propose_patch(
                workspace_id="demo",
                patch="--- a/src/hello.txt\n+++ b/src/hello.txt\n@@ -1 +1 @@\n-hello\n+hi\n",
                idempotency_key="test-patch",
            )
            assert request["request_id"]
            assert "root" not in request
            assert "patch" not in request["request"]
            assert "-hello" not in repr(request)
        finally:
            current_client_id.reset(first)
        second = current_client_id.set("second")
        try:
            with pytest.raises(LocalHandsError, match="not found"):
                adapter.request_status(request_id=request["request_id"])
        finally:
            current_client_id.reset(second)
    finally:
        directory.cleanup()


def test_official_mcp_server_and_loopback_guard():
    service, directory = _service()
    try:
        server = build_mcp_server(service)
        tools = {tool.name: tool for tool in server._tool_manager._tools.values()}
        names = set(tools)
        assert names == {
            "workspace_status",
            "read_file",
            "propose_patch",
            "request_check",
            "request_status",
        }
        for name in ("workspace_status", "read_file", "request_status"):
            annotations = tools[name].annotations
            assert annotations is not None
            assert annotations.read_only_hint is True
            assert annotations.destructive_hint is False
        assert tools["propose_patch"].annotations is None
        assert tools["request_check"].annotations is None
        assert require_loopback("127.0.0.1") == "127.0.0.1"
        assert require_loopback("::1") == "::1"
        for unsupported_host in ("localhost", "0.0.0.0"):
            with pytest.raises(ValueError, match="only bind"):
                require_loopback(unsupported_host)
    finally:
        directory.cleanup()


def test_asgi_proxy_host_allowlist_accepts_exact_host_and_rejects_foreign_host():
    service, directory = _service()
    try:
        token = service.bootstrap_client("proxy-client")
        app = create_mcp_app(
            service,
            bind_host="127.0.0.1",
            proxy_hosts=("studio.tailnet.ts.net",),
        )
        common = [
            (b"authorization", f"Bearer {token}".encode()),
            (b"content-type", b"application/json"),
            (b"accept", b"application/json, text/event-stream"),
        ]

        async def exercise_hosts():
            async with app.app.router.lifespan_context(app.app):
                allowed = await _async_call(app, [*common, (b"host", b"studio.tailnet.ts.net")])
                foreign = await _async_call(app, [*common, (b"host", b"evil.example")])
                return allowed, foreign

        allowed, foreign = asyncio.run(exercise_hosts())
        assert allowed[0]["status"] != 421
        assert foreign[0]["status"] == 421
    finally:
        directory.cleanup()
