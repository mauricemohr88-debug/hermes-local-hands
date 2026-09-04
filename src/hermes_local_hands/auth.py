"""Authentication primitives for the loopback MCP endpoint.

The raw bearer value is handled here only while authenticating a request.
The database receives a one-way digest through :class:`Store`; the operator
CLI keeps its separate credential copy in a protected local file.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from contextvars import ContextVar, Token

from .errors import AuthenticationError
from .service import LocalHandsService

current_client_id: ContextVar[str | None] = ContextVar("hermes_local_hands_client_id", default=None)


def bearer_from_headers(headers: list[tuple[bytes, bytes]]) -> str:
    """Return a strict RFC 6750 bearer token, or deny the request.

    Multiple Authorization headers and non-Bearer schemes are rejected.  This
    avoids ambiguous proxy behaviour and keeps the local endpoint fail-closed.
    """
    values = [
        value.decode("latin-1") for name, value in headers if name.lower() == b"authorization"
    ]
    if len(values) != 1:
        raise AuthenticationError("exactly one bearer credential is required")
    scheme, separator, token = values[0].partition(" ")
    if scheme.lower() != "bearer" or not separator or not token or token.strip() != token:
        raise AuthenticationError("a bearer credential is required")
    return token


def authenticate_headers(
    service: LocalHandsService, headers: list[tuple[bytes, bytes]]
) -> Token[str | None]:
    """Authenticate through core storage and bind the resulting client to context."""
    client_id = service.authenticate(bearer_from_headers(headers))
    return current_client_id.set(client_id)


ASGIApp = Callable[
    [dict, Callable[[], Awaitable[dict]], Callable[[dict], Awaitable[None]]], Awaitable[None]
]


class BearerAuthenticationMiddleware:
    """Tiny raw-ASGI guard; intentionally not Starlette ``BaseHTTPMiddleware``.

    It protects exactly the supplied app and resets its context variable even
    when the app raises.  Credential text is never included in a response.
    """

    def __init__(self, app: ASGIApp, service: LocalHandsService) -> None:
        self.app = app
        self.service = service

    async def __call__(
        self,
        scope: dict,
        receive: Callable[[], Awaitable[dict]],
        send: Callable[[dict], Awaitable[None]],
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        token: Token[str | None] | None = None
        try:
            token = authenticate_headers(self.service, list(scope.get("headers", [])))
        except AuthenticationError:
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"www-authenticate", b"Bearer"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": b'{"error":"unauthorized"}'})
            return
        try:
            await self.app(scope, receive, send)
        finally:
            if token is not None:
                current_client_id.reset(token)
