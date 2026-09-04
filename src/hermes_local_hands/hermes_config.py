"""Render a deliberately small Hermes MCP configuration fragment."""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

_TOKEN_ENV = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_ENDPOINT_SHAPE = re.compile(
    r"(?P<scheme>https?)://(?P<authority>[A-Z0-9.\-:\[\]]+)/mcp",
    flags=re.ASCII | re.IGNORECASE,
)
_DNS_LABEL = re.compile(r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?", re.ASCII | re.IGNORECASE)
_NUMERIC_HOST_LABEL = re.compile(r"(?:0x[0-9a-f]+|[0-9]+)", re.ASCII)


def _canonical_hostname(hostname: str) -> tuple[str, bool]:
    """Return a non-ambiguous ASCII host and whether it is an allowed loopback."""
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None

    if address is None:
        normalized = hostname.lower()
        if len(normalized) > 253:
            raise ValueError("endpoint hostname is invalid")
        labels = normalized.split(".")
        if not labels or any(not _DNS_LABEL.fullmatch(label) for label in labels):
            raise ValueError("endpoint hostname is invalid")
        # libc accepts historical decimal/octal/hex IPv4 spellings such as
        # 2130706433 and 0x7f.0.0.1. They are not DNS names for this protocol
        # and could otherwise disguise a loopback endpoint.
        if all(_NUMERIC_HOST_LABEL.fullmatch(label) for label in labels):
            raise ValueError("endpoint hostname uses an ambiguous numeric form")
        return normalized, normalized == "localhost"

    normalized = address.compressed
    is_supported_loopback = normalized in {"127.0.0.1", "::1"}
    mapped = getattr(address, "ipv4_mapped", None)
    if (address.is_loopback or (mapped is not None and mapped.is_loopback)) and not (
        is_supported_loopback
    ):
        raise ValueError("endpoint hostname uses an unsupported loopback form")
    return normalized, is_supported_loopback


def _validated_endpoint(endpoint: str) -> str:
    """Accept and canonicalize loopback HTTP or an explicit HTTPS tunnel URL."""
    if not isinstance(endpoint, str) or not endpoint:
        raise ValueError("endpoint must be a non-empty string")
    if not endpoint.isascii():
        raise ValueError("endpoint must contain ASCII characters only")
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in endpoint):
        raise ValueError("endpoint must not contain whitespace or control characters")

    match = _ENDPOINT_SHAPE.fullmatch(endpoint)
    if match is None:
        raise ValueError("endpoint must be an HTTP(S) URL ending exactly in /mcp")
    try:
        parsed = urlsplit(endpoint)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("endpoint authority is invalid") from exc

    if parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError("endpoint must not contain credentials, a query, or a fragment")
    if parsed.path != "/mcp":
        raise ValueError("endpoint path must be exactly /mcp")
    if hostname is None:
        raise ValueError("endpoint hostname is invalid")
    if port is not None and not (1 <= port <= 65_535):
        raise ValueError("endpoint port is invalid")

    # Verify that urllib did not reinterpret an ambiguous authority before we
    # use its parsed components. This also rejects empty and zero-padded ports.
    parsed_host = f"[{hostname}]" if ":" in hostname else hostname
    parsed_authority = parsed_host if port is None else f"{parsed_host}:{port}"
    if match.group("authority").lower() != parsed_authority.lower():
        raise ValueError("endpoint authority is invalid")

    hostname, is_loopback = _canonical_hostname(hostname)
    canonical_host = f"[{hostname}]" if ":" in hostname else hostname
    canonical_authority = canonical_host if port is None else f"{canonical_host}:{port}"
    if parsed.scheme == "http" and is_loopback:
        return f"http://{canonical_authority}/mcp"
    if parsed.scheme == "https" and hostname and not is_loopback:
        return f"https://{canonical_authority}/mcp"
    raise ValueError("endpoint must be loopback HTTP or an explicit HTTPS tunnel URL")


def mcp_config(
    *,
    endpoint: str = "http://127.0.0.1:8741/mcp",
    token_env: str = "HERMES_LOCAL_HANDS_TOKEN",  # noqa: S107 - environment variable name, not secret
) -> dict[str, Any]:
    """Return config that references an environment variable, never a token."""
    endpoint = _validated_endpoint(endpoint)
    if not _TOKEN_ENV.fullmatch(token_env):
        raise ValueError("token environment variable name is invalid")
    return {
        "mcp_servers": {
            "hermes-local-hands": {
                "url": endpoint,
                "headers": {"Authorization": f"Bearer ${{env:{token_env}}}"},
                "ssl_verify": True,
                "trust": "untrusted",
                "tools": {
                    "include": [
                        "workspace_status",
                        "read_file",
                        "propose_patch",
                        "request_check",
                        "request_status",
                    ]
                },
            }
        }
    }


def render_hermes_config(*, endpoint: str, token_env: str) -> str:
    """Render copyable Hermes YAML without materialising a credential."""
    config = mcp_config(endpoint=endpoint, token_env=token_env)
    server = config["mcp_servers"]["hermes-local-hands"]
    tools = server["tools"]["include"]
    lines = [
        "mcp_servers:",
        "  hermes-local-hands:",
        f"    url: {server['url']}",
        "    headers:",
        f'      Authorization: "{server["headers"]["Authorization"]}"',
        "    ssl_verify: true",
        "    trust: untrusted",
        "    tools:",
        "      include:",
    ]
    lines.extend(f"        - {name}" for name in tools)
    return "\n".join(lines) + "\n"
