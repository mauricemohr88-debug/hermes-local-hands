"""Real loopback Streamable HTTP interoperability test for the MCP adapter."""
# ruff: noqa: S603

from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
from pathlib import Path

import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

from hermes_local_hands.cli import build_service
from hermes_local_hands.mcp_server import create_mcp_app
from hermes_local_hands.models import WorkspacePolicy


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _git_fixture(root: Path) -> Path:
    repository = root / "repository"
    (repository / "src").mkdir(parents=True)
    (repository / "src" / "hello.txt").write_text("hello from Local Hands\n", encoding="utf-8")
    for command in (
        ["git", "init", "-q", str(repository)],
        ["git", "-C", str(repository), "config", "user.email", "test@example.invalid"],
        ["git", "-C", str(repository), "config", "user.name", "MCP E2E Test"],
        ["git", "-C", str(repository), "add", "."],
        ["git", "-C", str(repository), "commit", "-qm", "fixture"],
    ):
        subprocess.run(command, check=True)
    return repository


async def _exercise_mcp(tmp_path: Path) -> None:
    repository = _git_fixture(tmp_path)
    service = build_service(tmp_path / "state")
    token = service.bootstrap_client("mcp-e2e")
    service.register_workspace(
        WorkspacePolicy(
            "demo",
            str(repository),
            ("src",),
            {"smoke": (sys.executable, "-c", "print('mcp check')")},
            write_allowlist=("src",),
        ),
        client_ids=("mcp-e2e",),
    )

    port = _free_loopback_port()
    endpoint = f"http://127.0.0.1:{port}/mcp"
    server = uvicorn.Server(
        uvicorn.Config(create_mcp_app(service), host="127.0.0.1", port=port, log_level="error")
    )
    serve_task = asyncio.create_task(server.serve())
    try:
        for _ in range(300):
            if server.started:
                break
            await asyncio.sleep(0.01)
        assert server.started, "Uvicorn did not start in time"

        async with create_mcp_http_client() as unauthenticated_client:
            unauthorized = await unauthenticated_client.post(endpoint, content=b"{}")
        assert unauthorized.status_code == 401
        assert unauthorized.headers["www-authenticate"] == "Bearer"

        async with create_mcp_http_client(
            headers={"Authorization": f"Bearer {token}"}
        ) as authenticated_client:
            async with streamable_http_client(endpoint, http_client=authenticated_client) as (
                read_stream,
                write_stream,
            ):
                async with ClientSession(read_stream, write_stream) as session:
                    initialized = await session.initialize()
                    assert initialized.server_info.name == "hermes-local-hands"

                    tools = {tool.name: tool for tool in (await session.list_tools()).tools}
                    assert set(tools) == {
                        "workspace_status",
                        "read_file",
                        "propose_patch",
                        "request_check",
                        "request_status",
                    }
                    for name in {"workspace_status", "read_file", "request_status"}:
                        assert tools[name].annotations is not None
                        assert tools[name].annotations.read_only_hint is True
                    for name in {"propose_patch", "request_check"}:
                        assert tools[name].annotations is None

                    status = await session.call_tool("workspace_status", {"workspace_id": "demo"})
                    assert status.is_error is False
                    assert status.structured_content is not None
                    assert status.structured_content["branch"]

                    allowed_read = await session.call_tool(
                        "read_file", {"workspace_id": "demo", "path": "src/hello.txt"}
                    )
                    assert allowed_read.is_error is False
                    assert allowed_read.structured_content == {
                        "path": "src/hello.txt",
                        "content": "hello from Local Hands\n",
                        "bytes": 23,
                    }

                    denied_read = await session.call_tool(
                        "read_file", {"workspace_id": "demo", "path": "README.md"}
                    )
                    assert denied_read.is_error is True
                    denied_text = " ".join(
                        str(getattr(item, "text", "")) for item in denied_read.content
                    )
                    assert "path is outside this workspace read allowlist" in denied_text
                    assert str(repository) not in denied_text

                    patch_text = (
                        "--- a/src/hello.txt\n"
                        "+++ b/src/hello.txt\n"
                        "@@ -1 +1 @@\n"
                        "-hello from Local Hands\n"
                        "+hello from remote Hermes\n"
                    )
                    proposed = await session.call_tool(
                        "propose_patch",
                        {
                            "workspace_id": "demo",
                            "patch": patch_text,
                            "idempotency_key": "mcp-patch-1",
                        },
                    )
                    assert proposed.is_error is False
                    assert proposed.structured_content is not None
                    assert proposed.structured_content["state"] == "pending"
                    assert "patch" not in proposed.structured_content["request"]
                    request_id = proposed.structured_content["request_id"]

                    polled = await session.call_tool("request_status", {"request_id": request_id})
                    assert polled.is_error is False
                    assert polled.structured_content == proposed.structured_content

                    check = await session.call_tool(
                        "request_check",
                        {
                            "workspace_id": "demo",
                            "profile": "smoke",
                            "idempotency_key": "mcp-check-1",
                        },
                    )
                    assert check.is_error is False
                    assert check.structured_content is not None
                    assert check.structured_content["request"] == {
                        "profile": "smoke",
                        "timeout_seconds": 120,
                    }
    finally:
        server.should_exit = True
        await serve_task


def test_mcp_streamable_http_auth_and_workspace_boundary(tmp_path: Path) -> None:
    """MCP SDK 2.x interoperates over a real Uvicorn loopback listener."""
    asyncio.run(_exercise_mcp(tmp_path))
