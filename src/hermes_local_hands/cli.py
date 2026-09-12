"""Operator-only command line interface for Hermes Local Hands."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Sequence
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .errors import LocalHandsError
from .hermes_config import render_hermes_config
from .models import RequestState, WorkspacePolicy

if TYPE_CHECKING:
    from .service import LocalHandsService


def default_state_dir() -> Path:
    root = os.environ.get("XDG_STATE_HOME")
    return (
        Path(root) / "hermes-local-hands"
        if root
        else Path.home() / ".local" / "state" / "hermes-local-hands"
    )


def build_service(state_dir: str | Path | None = None) -> LocalHandsService:
    from .receipts import ReceiptLedger
    from .service import LocalHandsService
    from .storage import Store

    state = Path(state_dir) if state_dir is not None else default_state_dir()
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    store = Store(str(state / "hands.sqlite3"))
    ledger = ReceiptLedger.open(store, str(state / "receipt-signing-key.ed25519"))
    return LocalHandsService(store, ledger=ledger)


def _public(value: Any) -> Any:
    if is_dataclass(value):
        value = asdict(value)
    if isinstance(value, dict):
        return {
            str(key): _public(item)
            for key, item in value.items()
            if str(key).lower()
            not in {"root", "worktree", "token", "bearer_token", "credential", "secret", "password"}
        }
    if isinstance(value, (list, tuple)):
        return [_public(item) for item in value]
    return value


def _emit(value: Any) -> None:
    print(json.dumps(_public(value), ensure_ascii=True, sort_keys=True, default=str))


def _terminal_safe_line(value: str) -> str:
    """Render one untrusted line without terminal controls or bidi formatting."""

    return json.dumps(value, ensure_ascii=True)[1:-1]


def _emit_request_review(view: dict[str, Any]) -> None:
    """Render a bounded, visibly delimited local approval review."""

    print("Hermes Local Hands - LOCAL REQUEST REVIEW")
    for key in (
        "request_id",
        "kind",
        "workspace_id",
        "state",
        "client_id",
        "created_at",
        "expires_at",
        "base_head",
        "policy_hash",
    ):
        print(f"{key}: {_terminal_safe_line(str(view[key]))}")
    payload = dict(view.get("payload") or {})
    patch = payload.pop("patch", None)
    print("payload_metadata:")
    print(json.dumps(_public(payload), ensure_ascii=True, sort_keys=True, indent=2, default=str))
    if patch is not None:
        print("----- BEGIN UNTRUSTED PATCH (each line prefixed with '| ') -----")
        for line in str(patch).split("\n"):
            print(f"| {_terminal_safe_line(line)}")
        print("----- END UNTRUSTED PATCH -----")
    print(f"approval_code: {_terminal_safe_line(str(view.get('approval_code') or ''))}")
    print("Approve only after reviewing the complete delimited request above.")


def _error_text(exc: Exception) -> str:
    """Keep local filesystem details out of terminal output that may be shared."""
    text = str(exc).replace("\\", "/")
    text = re.sub(r"(?:[A-Za-z]:)?/(?:[^\s'\"]+/)+[^\s'\"]*", "[local path]", text)
    return text[:500] or "operation denied"


def _port(value: str) -> int:
    """Parse a TCP port before any state or server process is created."""

    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer from 1 to 65535") from exc
    if not 1 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be an integer from 1 to 65535")
    return port


def _token_file(state_dir: Path, client_id: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", client_id)
    return state_dir / "clients" / f"{safe}.token"


def _write_token(state_dir: Path, client_id: str, token: str) -> None:
    target = _token_file(state_dir, client_id)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        encoded = token.encode("utf-8")
        written = 0
        while written < len(encoded):
            count = os.write(descriptor, encoded[written:])
            if count < 1:  # pragma: no cover - defensive OS failure
                raise OSError("credential file write made no progress")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _checks(values: list[str]) -> dict[str, tuple[str, ...]]:
    profiles: dict[str, tuple[str, ...]] = {}
    for value in values:
        name, separator, command = value.partition("=")
        argv = tuple(part for part in command.split(",") if part)
        if not separator or not name or not argv or name in profiles:
            raise LocalHandsError("checks use name=command,arg syntax and names must be unique")
        profiles[name] = argv
    return profiles


def _clients(service: LocalHandsService) -> list[dict[str, str]]:
    method = getattr(service.store, "list_clients", None)
    if callable(method):
        return method()
    rows = service.store.connection.execute(
        "SELECT client_id, created_at FROM clients ORDER BY created_at"
    ).fetchall()
    return [
        {"client_id": str(row["client_id"]), "created_at": str(row["created_at"])} for row in rows
    ]


def _revoke_client(service: LocalHandsService, client_id: str) -> bool:
    return service.revoke_client(client_id)


def _workspaces(service: LocalHandsService) -> list[dict[str, Any]]:
    method = getattr(service.store, "list_workspaces", None)
    if callable(method):
        return method()
    rows = service.store.connection.execute(
        "SELECT workspace_id, policy_hash FROM workspaces ORDER BY workspace_id"
    ).fetchall()
    return [
        {"workspace_id": str(row["workspace_id"]), "policy_hash": str(row["policy_hash"])}
        for row in rows
    ]


def _requests(service: LocalHandsService, state: str | None = None) -> list[Any]:
    method = getattr(service.store, "list_requests", None)
    if callable(method):
        requests = method(state=state) if state else method()
        return [
            {
                "request_id": request.request_id,
                "kind": request.kind.value,
                "workspace_id": request.workspace_id,
                "state": request.state.value,
                "client_id": request.client_id,
                "created_at": request.created_at,
                "expires_at": request.expires_at,
            }
            for request in requests
        ]
    query = "SELECT * FROM requests"
    values: tuple[str, ...] = ()
    if state:
        query += " WHERE state=?"
        values = (state,)
    query += " ORDER BY created_at DESC"
    return [
        service.store._row_request(row)
        for row in service.store.connection.execute(query, values).fetchall()
    ]


def _verify_receipts(service: LocalHandsService) -> dict[str, Any]:
    method = getattr(service.ledger, "verify", None)
    if callable(method):
        return {"valid": bool(method()), "receipts": len(service.store.receipts())}
    # Without a public signature verifier, still verify the immutable hash chain.
    previous = "0" * 64
    for row in service.store.receipts():
        if str(row["previous_hash"]) != previous:
            return {"valid": False, "reason": "receipt chain discontinuity"}
        previous = str(row["receipt_hash"])
    return {
        "valid": True,
        "receipts": len(service.store.receipts()),
        "signature_verification": "unavailable",
    }


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="hermes-local-hands", description="Local approval boundary for remote Hermes work."
    )
    root.add_argument(
        "--state-dir", help="private state directory; defaults to the OS state directory"
    )
    commands = root.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor", help="read-only setup and connection diagnostics")
    doctor.add_argument("--workspace", help="check one registered workspace")
    doctor.add_argument("--client", help="check one client and its workspace grant")
    doctor.add_argument("--endpoint", help="optionally probe an explicit MCP HTTP(S) endpoint")
    doctor.add_argument("--json", action="store_true", dest="as_json")
    demo = commands.add_parser("demo", help="try local approval with an isolated toy repository")
    demo.add_argument(
        "--directory", type=Path, help="new directory; default: private temp directory"
    )
    commands.add_parser("init").add_argument("--client-id", default="hermes")
    client = commands.add_parser("client").add_subparsers(dest="client_command", required=True)
    add = client.add_parser("add")
    add.add_argument("client_id")
    client.add_parser("list")
    revoke = client.add_parser("revoke")
    revoke.add_argument("client_id")
    workspace = commands.add_parser("workspace").add_subparsers(
        dest="workspace_command", required=True
    )
    add_workspace = workspace.add_parser("add")
    add_workspace.add_argument("--id", required=True)
    add_workspace.add_argument("--root", required=True)
    add_workspace.add_argument(
        "--read", action="append", required=True, help="allowed relative directory; repeatable"
    )
    add_workspace.add_argument(
        "--write",
        action="append",
        default=[],
        help="allowed relative patch directory; repeatable; omit for read-only",
    )
    add_workspace.add_argument(
        "--check", action="append", default=[], help="fixed test profile: name=command,arg"
    )
    add_workspace.add_argument("--max-read-bytes", type=int, default=262_144)
    add_workspace.add_argument(
        "--client", action="append", required=True, help="client id to grant; repeatable"
    )
    workspace.add_parser("list")
    status = workspace.add_parser("status")
    status.add_argument("workspace_id")
    grant = workspace.add_parser("grant")
    grant.add_argument("workspace_id")
    grant.add_argument("client_id")
    grants = workspace.add_parser("grants")
    grants.add_argument("workspace_id")
    revoke_workspace = workspace.add_parser("revoke")
    revoke_workspace.add_argument("workspace_id")
    revoke_workspace.add_argument("client_id")
    read = commands.add_parser("read")
    read.add_argument("workspace_id")
    read.add_argument("path")
    check = commands.add_parser("check").add_subparsers(dest="check_command", required=True)
    add_check = check.add_parser("add")
    add_check.add_argument("workspace_id")
    add_check.add_argument("profile")
    add_check.add_argument("idempotency_key")
    add_check.add_argument("--timeout", type=int, default=120)
    add_check.add_argument("--client", required=True)
    add_check.add_argument("--patch-request")
    check_list = check.add_parser("list")
    check_list.add_argument("workspace_id")
    request = commands.add_parser("request").add_subparsers(dest="request_command", required=True)
    request_list = request.add_parser("list")
    request_list.add_argument("--state", choices=[item.value for item in RequestState])
    request_show = request.add_parser("show")
    request_show.add_argument("request_id")
    request_show.add_argument(
        "--json", action="store_true", dest="as_json", help="emit escaped machine-readable JSON"
    )
    approve = request.add_parser("approve")
    approve.add_argument("request_id")
    approve.add_argument(
        "--confirm", help="12-character code shown by `request show` after local review"
    )
    deny = request.add_parser("deny")
    deny.add_argument("request_id")
    deny.add_argument("--reason", default="rejected locally")
    request_status = request.add_parser("status")
    request_status.add_argument("request_id")
    request.add_parser("recover")
    snapshot = commands.add_parser("snapshot").add_subparsers(
        dest="snapshot_command", required=True
    )
    snapshot.add_parser("list")
    delete_snapshot = snapshot.add_parser("delete")
    delete_snapshot.add_argument("request_id")
    delete_snapshot.add_argument("--confirm", required=True)
    commands.add_parser("receipt-verify")
    config = commands.add_parser("hermes-config")
    config.add_argument("--port", type=_port, default=8741)
    config.add_argument(
        "--endpoint",
        help="explicit loopback HTTP or HTTPS tunnel endpoint ending in /mcp",
    )
    config.add_argument("--token-env", default="HERMES_LOCAL_HANDS_TOKEN")
    serve = commands.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=_port, default=8741)
    serve.add_argument(
        "--proxy-host",
        action="append",
        default=[],
        help="exact trusted reverse-proxy Host header; repeatable",
    )
    return root


def run(argv: Sequence[str] | None = None, *, service: LocalHandsService | None = None) -> int:
    args = parser().parse_args(argv)
    state_dir = Path(args.state_dir) if args.state_dir else default_state_dir()
    try:
        if args.command == "doctor":
            from .doctor import doctor_report

            report = doctor_report(
                state_dir,
                workspace_id=args.workspace,
                client_id=args.client,
                endpoint=args.endpoint,
            )
            if args.as_json:
                _emit(report)
            else:
                print("Hermes Local Hands - SETUP DIAGNOSTICS")
                for check in report["checks"]:
                    print(f"[{check['status'].upper()}] {check['message']}")
                    if check.get("hint"):
                        print(f"  Next: {check['hint']}")
                print(
                    "Diagnostics complete. Warnings and skipped checks are not verified readiness."
                )
            return 0 if report["ok"] else 1
        if args.command == "demo":
            if args.state_dir or service is not None:
                raise LocalHandsError("demo uses its own new state; omit --state-dir")
            from .demo import run_demo

            return run_demo(args.directory, review_request=_emit_request_review)
        if args.command == "hermes-config":
            print(
                render_hermes_config(
                    endpoint=args.endpoint or f"http://127.0.0.1:{args.port}/mcp",
                    token_env=args.token_env,
                ),
                end="",
            )
            return 0
        service = service or build_service(state_dir)
        exit_status = 0
        if args.command == "init":
            token = service.bootstrap_client(args.client_id)
            try:
                _write_token(state_dir, args.client_id, token)
            except BaseException:
                service.revoke_client(args.client_id)
                raise
            _emit(
                {
                    "initialized": True,
                    "client_id": args.client_id,
                    "credential_saved": True,
                    "next": (
                        "export the credential from the private token file into "
                        "HERMES_LOCAL_HANDS_TOKEN"
                    ),
                }
            )
        elif args.command == "client":
            if args.client_command == "add":
                token = service.bootstrap_client(args.client_id)
                try:
                    _write_token(state_dir, args.client_id, token)
                except BaseException:
                    service.revoke_client(args.client_id)
                    raise
                _emit({"client_id": args.client_id, "created": True, "credential_saved": True})
            elif args.client_command == "list":
                _emit({"clients": _clients(service)})
            else:
                revoked = _revoke_client(service, args.client_id)
                _token_file(state_dir, args.client_id).unlink(missing_ok=True)
                _emit(
                    {
                        "client_id": args.client_id,
                        "revoked": revoked,
                        "credential_file_removed": True,
                    }
                )
        elif args.command == "workspace":
            if args.workspace_command == "add":
                policy = WorkspacePolicy(
                    workspace_id=args.id,
                    root=args.root,
                    read_allowlist=tuple(args.read),
                    test_profiles=_checks(args.check),
                    max_read_bytes=args.max_read_bytes,
                    write_allowlist=tuple(args.write),
                )
                created = service.register_workspace(policy, client_ids=tuple(args.client))
                _emit(
                    {
                        "workspace_id": created.workspace_id,
                        "read_allowlist": list(created.read_allowlist),
                        "write_allowlist": list(created.write_allowlist),
                        "checks": sorted(created.test_profiles),
                        "clients": list(args.client),
                    }
                )
            elif args.workspace_command == "list":
                _emit({"workspaces": _workspaces(service)})
            elif args.workspace_command == "grant":
                _emit(
                    {
                        "workspace_id": args.workspace_id,
                        "client_id": args.client_id,
                        "granted": service.grant_workspace(args.client_id, args.workspace_id),
                    }
                )
            elif args.workspace_command == "grants":
                _emit(
                    {
                        "workspace_id": args.workspace_id,
                        "clients": service.workspace_grants(args.workspace_id),
                    }
                )
            elif args.workspace_command == "revoke":
                _emit(
                    {
                        "workspace_id": args.workspace_id,
                        "client_id": args.client_id,
                        "revoked": service.revoke_workspace(args.client_id, args.workspace_id),
                    }
                )
            else:
                _emit(service.repo_status(args.workspace_id))
        elif args.command == "read":
            _emit(service.read_file(args.workspace_id, args.path))
        elif args.command == "check":
            if args.check_command == "add":
                _emit(
                    service.request_test(
                        args.workspace_id,
                        args.profile,
                        args.idempotency_key,
                        args.timeout,
                        client_id=args.client,
                        patch_request_id=args.patch_request,
                    )
                )
            else:
                policy, _ = service.store.workspace(args.workspace_id)
                _emit({"workspace_id": args.workspace_id, "checks": sorted(policy.test_profiles)})
        elif args.command == "request":
            if args.request_command == "list":
                _emit({"requests": _requests(service, args.state)})
            elif args.request_command == "show":
                view = service.local_request_view(args.request_id)
                if args.as_json:
                    _emit(view)
                else:
                    _emit_request_review(view)
            elif args.request_command == "status":
                _emit(service.local_request_view(args.request_id))
            elif args.request_command == "deny":
                service.reject(args.request_id, args.reason)
                _emit({"request_id": args.request_id, "state": "rejected"})
            elif args.request_command == "approve":
                if not args.confirm:
                    raise LocalHandsError(
                        "local approval requires --confirm CODE after reviewing request show"
                    )
                result = service.approve(args.request_id, args.confirm)
                _emit(result)
                if result["state"] == RequestState.FAILED.value:
                    exit_status = 1
            else:
                _emit(service.recover_interrupted())
        elif args.command == "snapshot":
            if args.snapshot_command == "list":
                _emit({"snapshots": service.list_snapshots()})
            else:
                service.delete_snapshot(args.request_id, args.confirm)
                _emit({"request_id": args.request_id, "deleted": True})
        elif args.command == "receipt-verify":
            _emit(_verify_receipts(service))
        elif args.command == "serve":
            from .mcp_server import create_mcp_app, require_loopback

            require_loopback(args.host)
            service.recover_interrupted()
            try:
                import uvicorn
            except ImportError as exc:
                raise LocalHandsError(
                    "serve requires the installed uvicorn runtime dependency"
                ) from exc
            uvicorn.run(
                create_mcp_app(
                    service,
                    bind_host=args.host,
                    proxy_hosts=tuple(args.proxy_host),
                ),
                host=args.host,
                port=args.port,
                log_level="warning",
            )
        return exit_status
    except (LocalHandsError, OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({"error": _error_text(exc)}), file=sys.stderr)
        return 2


def main() -> None:
    raise SystemExit(run())
