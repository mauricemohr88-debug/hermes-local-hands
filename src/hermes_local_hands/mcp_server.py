"""Authenticated, loopback-only Streamable HTTP MCP adapter.

The adapter intentionally exposes five remote capabilities only.  Local
approval remains a CLI concern and no generic command execution surface exists.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import asdict, is_dataclass
from typing import Any
from urllib.parse import urlsplit

from .auth import BearerAuthenticationMiddleware, current_client_id
from .errors import LocalHandsError
from .service import LocalHandsService

try:  # Kept import-local so core-only consumers do not need the HTTP extra.
    from mcp.server import MCPServer
    from mcp.server.mcpserver.exceptions import ToolError
    from mcp.server.transport_security import TransportSecuritySettings
    from mcp.types import ToolAnnotations
except ImportError:  # pragma: no cover - exercised by installation behaviour
    MCPServer = None  # type: ignore[assignment,misc]
    ToolError = None  # type: ignore[assignment,misc]
    TransportSecuritySettings = None  # type: ignore[assignment,misc]
    ToolAnnotations = None  # type: ignore[assignment,misc]


_LOOPBACK_BIND_LITERALS = frozenset({"127.0.0.1", "::1"})
_LOOPBACK_HOSTS = _LOOPBACK_BIND_LITERALS | {"localhost"}
_MAX_BODY = 1_048_576


def require_loopback(host: str) -> str:
    """Validate a literal loopback bind target; no DNS resolution is trusted."""
    if host not in _LOOPBACK_BIND_LITERALS:
        raise ValueError("Hermes Local Hands may only bind to 127.0.0.1 or ::1")
    return host


def validate_proxy_host(value: str) -> str:
    """Validate one exact reverse-proxy Host value without wildcards or URL parts."""
    if not value or any(character.isspace() for character in value) or "*" in value:
        raise ValueError("proxy host must be an exact hostname with an optional port")
    parsed = urlsplit(f"//{value}")
    if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("proxy host must be an exact hostname with an optional port")
    hostname = (parsed.hostname or "").lower()
    if not hostname or hostname in _LOOPBACK_HOSTS:
        raise ValueError("proxy host must be a non-loopback hostname")
    labels = hostname.split(".")
    if len(hostname) > 253 or any(
        not label
        or len(label) > 63
        or not label[0].isalnum()
        or not label[-1].isalnum()
        or any(
            not (character.isascii() and (character.isalnum() or character == "-"))
            for character in label
        )
        for label in labels
    ):
        raise ValueError("proxy host contains unsupported characters")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("proxy host port is invalid") from exc
    if port == 0:
        raise ValueError("proxy host port is invalid")
    return hostname if port is None else f"{hostname}:{port}"


def _public(value: Any) -> Any:
    """Return JSON safe data without filesystem locations or accidental secrets."""
    if is_dataclass(value):
        value = asdict(value)
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered in {
                "root",
                "worktree",
                "token",
                "bearer_token",
                "credential",
                "secret",
                "password",
            }:
                continue
            result[str(key)] = _public(item)
        return result
    if isinstance(value, (list, tuple)):
        return [_public(item) for item in value]
    return value


def _error_message(exc: Exception) -> str:
    text = str(exc).replace("\\", "/")
    # Error messages must not turn a local filesystem path into remote output.
    text = re.sub(r"(?:[A-Za-z]:)?/(?:[^\s'\"]+/)+[^\s'\"]*", "[local path]", text)
    return text[:500] or "request denied"


def _official_tool_call(handler: Callable[..., dict[str, Any]], **arguments: Any) -> dict[str, Any]:
    """Translate expected domain denials into bounded MCP tool errors."""

    try:
        return handler(**arguments)
    except LocalHandsError as exc:
        if ToolError is None:  # pragma: no cover - build_mcp_server already guards this
            raise RuntimeError("MCP tool error support is unavailable") from None
        raise ToolError(_error_message(exc)) from None


class MCPAdapter:
    """Small MCP 2.x-compatible tool registry plus raw ASGI HTTP transport.

    Keeping the tool dispatch explicit makes the security surface auditable.
    The public ASGI endpoint itself is provided by the official MCP 2.x
    ``MCPServer`` below.
    """

    def __init__(self, service: LocalHandsService) -> None:
        self.service = service
        self._tools: dict[str, tuple[dict[str, Any], Callable[..., Any]]] = {}
        self._register_tools()

    def _register(
        self, name: str, description: str, schema: dict[str, Any], handler: Callable[..., Any]
    ) -> None:
        self._tools[name] = (
            {"name": name, "description": description, "inputSchema": schema},
            handler,
        )

    def _register_tools(self) -> None:
        required_workspace = {
            "type": "object",
            "properties": {"workspace_id": {"type": "string", "minLength": 1}},
            "required": ["workspace_id"],
            "additionalProperties": False,
        }
        self._register(
            "workspace_status",
            "Read Git status metadata for an approved workspace. Does not expose local paths.",
            required_workspace,
            self.workspace_status,
        )
        self._register(
            "read_file",
            "Read a UTF-8 file allowed by the workspace policy.",
            {
                "type": "object",
                "properties": {"workspace_id": {"type": "string"}, "path": {"type": "string"}},
                "required": ["workspace_id", "path"],
                "additionalProperties": False,
            },
            self.read_file,
        )
        self._register(
            "propose_patch",
            "Create a pending patch request. A local operator action is required to approve it.",
            {
                "type": "object",
                "properties": {
                    "workspace_id": {"type": "string"},
                    "patch": {"type": "string"},
                    "idempotency_key": {"type": "string"},
                },
                "required": ["workspace_id", "patch", "idempotency_key"],
                "additionalProperties": False,
            },
            self.propose_patch,
        )
        self._register(
            "request_check",
            "Create a pending fixed-profile test request. Local operator approval is required.",
            {
                "type": "object",
                "properties": {
                    "workspace_id": {"type": "string"},
                    "profile": {"type": "string"},
                    "idempotency_key": {"type": "string"},
                    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 900},
                    "patch_request_id": {"type": "string"},
                },
                "required": ["workspace_id", "profile", "idempotency_key"],
                "additionalProperties": False,
            },
            self.request_check,
        )
        self._register(
            "request_status",
            "Read the state of a previously created request.",
            {
                "type": "object",
                "properties": {"request_id": {"type": "string"}},
                "required": ["request_id"],
                "additionalProperties": False,
            },
            self.request_status,
        )

    def list_tools(self) -> list[dict[str, Any]]:
        return [definition for definition, _ in self._tools.values()]

    def _client(self) -> str:
        client_id = current_client_id.get()
        if not client_id:
            raise LocalHandsError("authenticated client context is required")
        return client_id

    def workspace_status(self, *, workspace_id: str) -> dict[str, Any]:
        client_id = self._client()
        return _public(self.service.repo_status(workspace_id, client_id=client_id))

    def read_file(self, *, workspace_id: str, path: str) -> dict[str, Any]:
        client_id = self._client()
        return _public(self.service.read_file(workspace_id, path, client_id=client_id))

    def propose_patch(
        self, *, workspace_id: str, patch: str, idempotency_key: str
    ) -> dict[str, Any]:
        client_id = self._client()
        request = self.service.propose_patch(
            workspace_id, patch, idempotency_key, client_id=client_id
        )
        return _public(self.service.public_request(request.request_id, client_id))

    def request_check(
        self,
        *,
        workspace_id: str,
        profile: str,
        idempotency_key: str,
        timeout_seconds: int = 120,
        patch_request_id: str | None = None,
    ) -> dict[str, Any]:
        client_id = self._client()
        request = self.service.request_test(
            workspace_id,
            profile,
            idempotency_key,
            timeout_seconds,
            client_id=client_id,
            patch_request_id=patch_request_id,
        )
        return _public(self.service.public_request(request.request_id, client_id))

    def request_status(self, *, request_id: str) -> dict[str, Any]:
        client_id = self._client()
        return _public(self.service.public_request(request_id, client_id))


def build_mcp_server(service: LocalHandsService) -> Any:
    """Create the official MCP 2.x server with the five intentionally narrow tools.

    ``MCPServer`` is used for protocol negotiation, schemas and Streamable HTTP;
    the raw ASGI bearer wrapper is applied later because it must run before the
    framework handles a request and must not use BaseHTTPMiddleware.
    """
    if MCPServer is None:
        raise RuntimeError(
            "MCP support is not installed; install hermes-local-hands with its dependencies"
        )
    adapter = MCPAdapter(service)
    if ToolAnnotations is None:  # Defensive guard for partial/broken MCP installs.
        raise RuntimeError(
            "MCP support is not installed; install hermes-local-hands with its dependencies"
        )
    server = MCPServer(
        "hermes-local-hands",
        title="Hermes Local Hands",
        description="Consent-gated local workspace companion. Approval is local-only.",
        version="0.1.0",
    )

    @server.tool(
        name="workspace_status",
        description=(
            "Read Git status metadata for an approved workspace. No local paths are exposed."
        ),
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
        structured_output=True,
    )
    async def workspace_status(workspace_id: str) -> dict[str, object]:
        return _official_tool_call(adapter.workspace_status, workspace_id=workspace_id)

    @server.tool(
        name="read_file",
        description="Read a UTF-8 file permitted by the workspace read allowlist.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
        structured_output=True,
    )
    async def read_file(workspace_id: str, path: str) -> dict[str, object]:
        return _official_tool_call(adapter.read_file, workspace_id=workspace_id, path=path)

    @server.tool(
        name="propose_patch",
        description="Create a pending patch request; local operator approval is required.",
        structured_output=True,
    )
    async def propose_patch(
        workspace_id: str, patch: str, idempotency_key: str
    ) -> dict[str, object]:
        return _official_tool_call(
            adapter.propose_patch,
            workspace_id=workspace_id,
            patch=patch,
            idempotency_key=idempotency_key,
        )

    @server.tool(
        name="request_check",
        description=(
            "Create a pending fixed-profile test request; local operator approval is required."
        ),
        structured_output=True,
    )
    async def request_check(
        workspace_id: str,
        profile: str,
        idempotency_key: str,
        timeout_seconds: int = 120,
        patch_request_id: str | None = None,
    ) -> dict[str, object]:
        return _official_tool_call(
            adapter.request_check,
            workspace_id=workspace_id,
            profile=profile,
            idempotency_key=idempotency_key,
            timeout_seconds=timeout_seconds,
            patch_request_id=patch_request_id,
        )

    @server.tool(
        name="request_status",
        description="Read the state of one request created by the authenticated client.",
        annotations=ToolAnnotations(
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
        structured_output=True,
    )
    async def request_status(request_id: str) -> dict[str, object]:
        return _official_tool_call(adapter.request_status, request_id=request_id)

    return server


def create_mcp_app(
    service: LocalHandsService,
    *,
    bind_host: str = "127.0.0.1",
    proxy_hosts: Sequence[str] = (),
) -> BearerAuthenticationMiddleware:
    """Build a loopback-only MCP app with an explicit reverse-proxy Host allowlist."""
    bind_host = require_loopback(bind_host)
    server = build_mcp_server(service)
    transport_security = None
    if proxy_hosts:
        if TransportSecuritySettings is None:  # pragma: no cover - import guard above
            raise RuntimeError("MCP transport security support is unavailable")
        trusted = [validate_proxy_host(item) for item in proxy_hosts]
        allowed_hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
        allowed_origins = [
            "http://127.0.0.1:*",
            "http://localhost:*",
            "http://[::1]:*",
        ]
        for host in trusted:
            allowed_hosts.append(host)
            if ":" not in host:
                allowed_hosts.append(f"{host}:*")
            allowed_origins.append(f"https://{host}")
        transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
            allowed_origins=allowed_origins,
        )
    app = server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        max_request_body_size=_MAX_BODY,
        transport_security=transport_security,
        host=bind_host,
    )
    return BearerAuthenticationMiddleware(app, service)
