# Try one request, approval, and snapshot result

Start here if Hermes lives on one machine and your repository on another, but
you want to understand the local approval step before setting up a tunnel.
This guide separates a local example from a real two-machine test.

Prefer watching first? Open the local [recorded replay](demo.html) or view the
[GIF](assets/local-demo.gif). Both come from actual CLI output, not a mocked
success transcript. The recorder entered only the generated toy request codes;
the walkthrough below leaves each decision to you.

**Before any execution:** Local Hands is not a sandbox. Approved check code
runs as your local user with normal file and network access. A snapshot protects
the working directory used by Local Hands; it does not isolate arbitrary code
from your host. The remote protocol only creates requests. Approval stays with
the local operator.

## 1. Run the local demo

`demo` and `doctor` require **0.2.0 or newer**. On macOS or Linux with Python
3.11+, Git, and an interactive terminal, install the isolated command using uv:

```bash
uv tool install 'hermes-local-hands>=0.2.0'
hermes-local-hands demo
```

If already installed with uv, use `uv tool upgrade hermes-local-hands` first.
For development, run these commands from a checkout containing the changes:

```bash
cd /path/to/hermes-local-hands
python3.11 -m venv .venv
.venv/bin/python -m pip install --upgrade pip setuptools
.venv/bin/python -m pip install -e .
.venv/bin/hermes-local-hands demo
```

Installation may use the network to obtain dependencies. The demo itself needs
no Hermes instance, network, tunnel, real project, or external credentials. It
creates a tiny Git repository and private state in a new temporary directory.
It does not register or change an existing workspace or use your normal Local
Hands state.

During the demo:

1. Read the generated example and proposed patch. The request is pending; a
   proposal is not an applied change.
2. Inspect the local request review. To approve this exact patch, enter the
   request-specific code shown by the program. Skip or abort if you do not want
   it applied.
3. Inspect the patch result. It belongs to a managed snapshot, not the original
   example checkout; nothing is merged.
4. Read the linked check request. Its approval is separate from patch approval.
   Enter its own request-specific code only if you want that check to run.
5. Inspect the reported check result and receipt verification. A passed check
   is evidence about the generated snapshot, not your own repository or a
   remote Hermes connection.

There is no auto-approval switch. Noninteractive or piped stdin is refused
without approving a request. The generated check is small and inspectable, but
it is still executed as your user, not in an OS sandbox.

To choose a location, supply a **new, nonexistent directory** under an existing
parent rather than an existing project:

```bash
.venv/bin/hermes-local-hands demo --directory /absolute/path/to/new-local-hands-demo
```

The program prints its generated artifact directory and retains the files for
local inspection, including private state and receipts. Do not publish the
directory or screenshot credentials from any real setup. No automatic cleanup
removes the example.
If interrupted, use the printed location to inspect what was created; a partial
run is not a completed demo.

## 2. Check your local setup (read-only)

The remaining commands use the source-checkout executable. If installed with uv,
replace `.venv/bin/hermes-local-hands` with `hermes-local-hands` throughout.

For normal Local Hands state:

```bash
.venv/bin/hermes-local-hands doctor
.venv/bin/hermes-local-hands doctor --workspace demo --client hermes-mac-studio
```

For a separately configured state directory, the global option comes **before**
`doctor`. This example stays offline:

```bash
.venv/bin/hermes-local-hands --state-dir /absolute/path/to/private-state doctor \
  --workspace demo \
  --client hermes-mac-studio \
  --json
```

Use your actual registered IDs, not the example values.
`doctor` reads diagnostics; it does not initialize missing state, repair
configuration, rotate credentials, start a listener, approve requests, or run
check profiles. Missing setup is a diagnostic result, not permission to change
it. Inspect the output before sharing it and remove any identifying details.

If an active SQLite journal is present or local state changes during diagnosis,
`doctor` warns and skips dependent checks rather than reading a stale snapshot
or modifying the journal. It never stops the service. Warnings and skipped
checks remain unverified even when the command exits successfully; `ok` in JSON
means no failed check, not overall readiness or a verified receipt chain.

Only add `--endpoint` when you explicitly want an online reachability probe:

```bash
.venv/bin/hermes-local-hands doctor \
  --endpoint https://your-laptop.example.ts.net/mcp
```

This sends a bounded, unauthenticated HTTP `HEAD` request to the supplied `/mcp`
endpoint. HTTPS certificate verification stays enabled; it sends no token,
follows no redirects, and does not use environment proxies. An HTTP response
demonstrates transport reachability only, not an authenticated MCP call, correct
tunnel access policy, Hermes compatibility, or a completed workflow. Without
`--endpoint`, doctor makes no network request.

## 3. Move to two machines

Use a clean, non-sensitive test repository first. The local demo is not proof
that this connection works.

### A. On the computer that owns the repository

Follow the [repository registration steps](../README.md#connect-a-real-repository):
create a client, choose explicit read/write paths and a trusted named check, and
grant that client access to one workspace. Keep the credential file private.
For the example below, the workspace ID is `demo` and the client ID is
`hermes-mac-studio`.

Configure your own authenticated HTTPS tunnel or reverse proxy, then start the
local listener with the exact external hostname you selected:

```bash
.venv/bin/hermes-local-hands serve --host 127.0.0.1 --port 8741 \
  --proxy-host your-laptop.example.ts.net
```

Keep the listener on loopback; do not open port 8741 directly to the Internet.
Tunnel provisioning and access policy are outside Local Hands. The
[service guide](SERVICE.md) is optional after a manual session works; do not set
up autostart just to try the demo.

In a second local terminal, generate the MCP configuration fragment:

```bash
.venv/bin/hermes-local-hands hermes-config \
  --endpoint https://your-laptop.example.ts.net/mcp \
  --token-env HERMES_LOCAL_HANDS_TOKEN
```

### B. On the computer running Hermes

Add the generated fragment to your Hermes configuration and make the client
token available as `HERMES_LOCAL_HANDS_TOKEN` only in that runtime's private
environment. Transfer the credential through your own secure channel, never
through a prompt, issue, repository, or recording. Follow your installed Hermes
version's configuration/reload instructions; this guide is not a latest-version
compatibility claim. Keep the generated client trust policy unchanged unless
you have separately reviewed a change.

Give Hermes a bounded request, replacing the example path with an allowlisted
file that exists:

> Use only Local Hands for this task. Read the status of workspace `demo` and
> `src/example.py`. Propose one small, reviewable correction with a fresh
> idempotency key, then stop and report its request ID. Do not approve anything,
> run a shell, request a merge, or push.

### C. Back on the repository computer

```bash
.venv/bin/hermes-local-hands request list --state pending
.venv/bin/hermes-local-hands request show <request-id>
.venv/bin/hermes-local-hands request approve <request-id> --confirm <approval-code>
```

Run the last command only after reviewing the exact patch and code displayed by
`request show`. Alternatively, reject locally:

```bash
.venv/bin/hermes-local-hands request deny <request-id> --reason "not approved"
```

After a successful patch approval, ask Hermes to request your fixed check
profile with `patch_request_id` set to that approved patch's ID and a new
idempotency key. This creates another pending request. Review and approve it
separately, then inspect the result locally:

```bash
.venv/bin/hermes-local-hands request show <check-request-id>
.venv/bin/hermes-local-hands request approve <check-request-id> --confirm <check-approval-code>
.venv/bin/hermes-local-hands request status <check-request-id>
.venv/bin/hermes-local-hands receipt-verify
```

Check stdout/stderr stays local. Hermes receives bounded execution metadata,
not that output. The check replays the approved patch into a fresh snapshot;
nothing is merged into your registered checkout. See the
[full workflow and cleanup rules](../README.md#end-to-end-workflow) before
retaining or deleting snapshots.

## 4. Report what actually happened

We are looking for two independent testers, not claiming two completed tests.
A useful report can be a failed install or one confusing approval step. Share a
sanitized report in a
[GitHub issue](https://github.com/mauricemohr88-debug/hermes-local-hands/issues).
No call, payment, private code, or raw receipt is needed.

```text
Date and tool version / source commit:
Repository machine (OS, Python):
Hermes machine and Hermes version (or "local demo only"):
Connection type (no private hostnames or credentials):
Task I wanted to complete:
Last step completed:
First confusing step / sanitized error:
Needed help? What helped?
Outcome: local demo only / remote read / pending request /
         locally approved patch / linked check / receipt verification
Time to first useful result (or "not measured"):
Would I use it for a second session? Why / why not?
```

Do not count a local demo, a generated config, or a successful doctor result as
a two-machine workflow. Do not count one successful session as repeat adoption.
The [roadmap](../ROADMAP.md) keeps those evidence gates separate from any later
optional convenience layer.

## Maintainer: regenerate the local recording

From the source checkout with its `.venv` installed:

```bash
.venv/bin/python scripts/record_demo.py
```

The recorder has no arbitrary command, workspace, endpoint, or approval target
option. It launches only `.venv/bin/python -m hermes_local_hands demo` against a
new generated directory, checks the toy client/workspace and request kind, then
types those two request-specific codes. It saves the real output and times only
after exit 0, the final PASS line, and an unchanged original toy greeting.

Generated outputs are `docs/assets/local-demo.cast` and a self-contained
`docs/demo.html`. `--gif` also renders `docs/assets/local-demo.gif` when Pillow
is available in the recorder's Python environment; Pillow is not a Local Hands
runtime dependency. The child demo still uses the checkout's fixed `.venv`
interpreter. The cast preserves actual event timing; the GIF adds a final-frame
hold for readability. Only the generated artifact directory is redacted.
Private toy state is retained outside the repository for inspection and must
not be published. Recording does not publish or upload any artifact.
