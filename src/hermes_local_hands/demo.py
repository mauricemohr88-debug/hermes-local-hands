"""Interactive, local-only onboarding with a newly generated toy repository."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .errors import LocalHandsError

if TYPE_CHECKING:
    from .service import LocalHandsService

_BEFORE = "Hello from Hermes.\n"
_AFTER = "Hello from Local Hands.\n"
_PATCH = (
    "--- a/src/greeting.txt\n"
    "+++ b/src/greeting.txt\n"
    "@@ -1 +1 @@\n"
    "-Hello from Hermes.\n"
    "+Hello from Local Hands.\n"
)
_CHECK = (
    "from pathlib import Path; "
    "actual = Path('src/greeting.txt').read_text(encoding='utf-8'); "
    "print('Greeting matches the reviewed patch.' if actual == "
    f"{_AFTER!r} else 'Greeting did not match.'); "
    f"raise SystemExit(0 if actual == {_AFTER!r} else 1)"
)


def _new_directory(directory: Path | None) -> Path:
    if directory is None:
        return Path(tempfile.mkdtemp(prefix="hermes-local-hands-demo-")).resolve(strict=True)
    requested = directory.expanduser()
    if requested.name in {"", ".", ".."}:
        raise LocalHandsError("demo needs a new directory, not an existing parent")
    target = requested.parent.resolve(strict=True) / requested.name
    # Never reuse an existing directory, even an empty one or a symlink.
    target.mkdir(mode=0o700)
    return target


def _create_repository(directory: Path) -> Path:
    from .gitops import _git

    repository = directory / "repository"
    (repository / "src").mkdir(parents=True, mode=0o700)
    (repository / "src" / "greeting.txt").write_text(_BEFORE, encoding="utf-8")
    (repository / "README.md").write_text(
        "# Local Hands toy repository\n\n"
        "Generated demo data only. The original greeting should remain unchanged.\n",
        encoding="utf-8",
    )
    _git(str(repository), ["init", "--quiet", "--template=", "--initial-branch=main"])
    _git(str(repository), ["add", "--", "README.md", "src/greeting.txt"])
    _git(
        str(repository),
        [
            "-c",
            "user.name=Local Hands Demo",
            "-c",
            "user.email=demo@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "Create isolated demo fixture",
        ],
    )
    return repository


def _review_and_approve(
    service: LocalHandsService,
    request_id: str,
    review_request: Callable[[dict[str, Any]], None],
) -> dict[str, Any] | None:
    review_request(service.local_request_view(request_id))
    print("Type this request's approval_code, or press Enter to stop: ", end="", flush=True)
    try:
        confirmation = sys.stdin.readline(128).strip()
    except (KeyboardInterrupt, EOFError):
        print("\nDemo interrupted; this request was not approved.")
        return None
    if confirmation != service.approval_code(request_id):
        service.reject(request_id, "demo operator did not enter the request-specific code")
        print("Request not approved. No operation was executed for this request.")
        return None
    return service.approve(request_id, confirmation)


def run_demo(
    directory: Path | None,
    *,
    review_request: Callable[[dict[str, Any]], None],
) -> int:
    """Run real approval/snapshot code with fixed toy data and manual decisions."""
    if not sys.stdin.isatty():
        raise LocalHandsError(
            "demo requires an interactive terminal for each local approval; run it without a pipe"
        )
    if os.name != "posix" or sys.platform not in {"darwin", "linux"}:
        raise LocalHandsError("the local demo currently supports macOS and Linux")

    from .models import WorkspacePolicy
    from .receipts import ReceiptLedger
    from .service import LocalHandsService
    from .storage import Store

    demo_dir = _new_directory(directory)
    print("Hermes Local Hands - LOCAL DEMO")
    print("This creates a toy repository and private state. No network or Hermes is used.")
    print("Each patch/check still needs its own local approval.")
    print(f"Demo files retained at: {json.dumps(str(demo_dir), ensure_ascii=True)}")
    repository = _create_repository(demo_dir)
    state = demo_dir / "state"
    store = Store(str(state / "hands.sqlite3"))
    try:
        service = LocalHandsService(store, ledger=ReceiptLedger.open(store))
        service.bootstrap_client("demo-client")
        service.register_workspace(
            WorkspacePolicy(
                "demo",
                str(repository),
                ("src",),
                {"greeting": (sys.executable, "-I", "-c", _CHECK)},
                write_allowlist=("src",),
            ),
            client_ids=("demo-client",),
        )
        print("\n1/3 - Read one allowed file and propose a change.")
        original = service.read_file("demo", "src/greeting.txt", client_id="demo-client")
        print(f"Original greeting: {json.dumps(original['content'], ensure_ascii=True)}")
        patch = service.propose_patch("demo", _PATCH, "demo-patch", "demo-client")
        print("The proposal is pending. It has not changed the original repository.")
        if _review_and_approve(service, patch.request_id, review_request) is None:
            return 1
        patch_snapshot = state / "snapshots" / patch.request_id / "src" / "greeting.txt"
        if (
            store.request(patch.request_id).state.value != "succeeded"
            or patch_snapshot.read_text(encoding="utf-8") != _AFTER
            or (repository / "src" / "greeting.txt").read_text(encoding="utf-8") != _BEFORE
        ):
            raise LocalHandsError("demo patch verification failed; inspect the retained demo state")
        print("Patch verified in its snapshot. The original repository is unchanged.")

        print("\n2/3 - Review a check against that exact approved patch.")
        print("This fixed check reads only the toy greeting and compares its text.")
        print("Real check profiles execute as your local user; they are not sandboxed.")
        print(f"Check program: {json.dumps(_CHECK, ensure_ascii=True)}")
        check = service.request_test(
            "demo",
            "greeting",
            "demo-check",
            10,
            client_id="demo-client",
            patch_request_id=patch.request_id,
        )
        result = _review_and_approve(service, check.request_id, review_request)
        if result is None:
            return 1
        if result["state"] != "succeeded" or result.get("passed") is not True:
            raise LocalHandsError("demo check did not pass; inspect the retained demo state")
        remote = service.public_request(check.request_id, "demo-client")
        if "output" in remote["result"] or "output_excerpt" in remote["result"]:
            raise LocalHandsError("demo verification failed: check output reached the remote view")
        print("Check passed. Remote status exposes metadata; captured check output stays local.")

        print("\n3/3 - Verify the retained receipt chain and original repository.")
        unchanged = (repository / "src" / "greeting.txt").read_text(encoding="utf-8") == _BEFORE
        if not unchanged or not service.ledger.verify():
            raise LocalHandsError("demo final verification failed; inspect the retained demo state")
        print("PASS: approved patch + linked check + receipt verification; original unchanged.")
        print("This was a local demo, not a two-machine, Hermes, or sandbox validation.")
        print("Next: follow docs/TRY_IT.md to configure your real two-machine workflow.")
        return 0
    finally:
        store.connection.close()
