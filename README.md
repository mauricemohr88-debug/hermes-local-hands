# Hermes Local Hands

[![CI](https://github.com/mauricemohr88-debug/hermes-local-hands/actions/workflows/ci.yml/badge.svg)](https://github.com/mauricemohr88-debug/hermes-local-hands/actions/workflows/ci.yml)
[![CodeQL](https://github.com/mauricemohr88-debug/hermes-local-hands/actions/workflows/codeql.yml/badge.svg)](https://github.com/mauricemohr88-debug/hermes-local-hands/actions/workflows/codeql.yml)
[![PyPI](https://img.shields.io/pypi/v/hermes-local-hands.svg)](https://pypi.org/project/hermes-local-hands/)

**Hermes runs on one computer. Your repository stays on another. You approve
changes where the code lives.**

Hermes Local Hands is an **alpha**, free, open-source companion for a remote
[Hermes](https://github.com/NousResearch/hermes-agent) agent. For example, Hermes
on your server can read an allowlisted source file on your laptop, propose a
small fix, and request a named check. You inspect and approve each request
locally. Local Hands applies the patch and runs the approved check in snapshots;
it does not merge the result into your working checkout.

Use it when the agent and repository live on different machines and you want a
specific read/request boundary. It is not another Hermes runtime, a general
remote shell, or an autonomous deployment service. The remote protocol cannot
approve requests, write the active checkout, merge, or push.

> **Security boundary.** `workspace_status` and `read_file` are remote
> inspection tools. `propose_patch` and `request_check` only create a pending,
> expiring request. Approval and rejection are local-operator actions. Local
> Hands applies patches and launches checks from an isolated snapshot rather
> than writing the registered checkout itself. Approved check code still has
> the local user's normal host and network access and can deliberately modify
> the registered checkout; this is **not** a sandbox. Check stdout/stderr stays
> local: remote `request_status` returns bounded execution metadata, never the
> captured output.

## Try the workflow before connecting a real repository

The `demo` and `doctor` commands require **0.2.0 or newer**. For an isolated
installation, use `uv tool install 'hermes-local-hands>=0.2.0'`, then run
`hermes-local-hands demo`. For development from this checkout:
Requirements: macOS or Linux, Python 3.11+, Git, and an interactive terminal.

```bash
cd /path/to/hermes-local-hands
python3.11 -m venv .venv
.venv/bin/python -m pip install --upgrade pip setuptools
.venv/bin/python -m pip install -e .
.venv/bin/hermes-local-hands demo
```

Installation may download dependencies. The demo itself needs no network,
Hermes instance, tunnel, account, or real repository. It creates its own tiny Git
repository and private state, shows a pending patch, and asks you to enter that
request's approval code. A linked check needs a second, separate approval. You
can skip or abort; piped/noninteractive input is refused, never auto-approved.

The demo keeps its generated files for inspection and prints their directory.
This is a local example of request → review → snapshot result, **not a
two-machine test or a sandbox**. Follow the [short walkthrough](https://github.com/mauricemohr88-debug/hermes-local-hands/blob/main/docs/TRY_IT.md)
for what to inspect, read-only diagnostics, and the separate two-machine setup.

![Recorded CLI output of the local toy demo: separate patch and check approvals, followed by a snapshot result](https://raw.githubusercontent.com/mauricemohr88-debug/hermes-local-hands/main/docs/assets/local-demo.gif)

This is an actual recording captured during development of 0.2.0; its
pre-release label describes when it was recorded. The
fixture-only recorder entered the two displayed toy codes; ordinary demo use
remains manual. The generated directory path is redacted. Download the
[cast](https://raw.githubusercontent.com/mauricemohr88-debug/hermes-local-hands/main/docs/assets/local-demo.cast) or download the self-contained
[replay page](https://raw.githubusercontent.com/mauricemohr88-debug/hermes-local-hands/main/docs/demo.html) and open it locally for the full transcript and timing. The GIF
holds its final frame briefly for readability; no remote connection was tested.

## What it does — and does not do

| Capability | Remote Hermes can do it | Local operator must do it |
| --- | --- | --- |
| See sanitised Git status | Yes, for a granted workspace | Register the workspace and grant the client |
| Read a text file | Yes, only inside the explicit read allowlist | Define the allowlist |
| Propose a textual patch | Create a pending request only | Review and approve it |
| Request a fixed check profile | Create a pending request only | Review and approve it |
| Apply or test | No | Local Hands launches it in a snapshot; approved code remains host-capable |
| Reject, merge, push, use a shell | No | Reject is local; merge/push/shell are outside the protocol |

Every request is tied to an authenticated client, an allowed workspace, the
current Git `HEAD`, the workspace-policy hash, an idempotency key scoped to the
client, and a short TTL. A changed policy or commit invalidates a request.
Re-registering an existing workspace ID replaces its client grants with exactly
the new `--client` list; old grants do not follow a changed root or policy.
Interrupted execution is recorded as **uncertain**, not silently reported as a
success. The local state store also writes a signed, append-only receipt chain
for requests and operator decisions.

<a id="install-and-local-only-quickstart"></a>

## Connect a real repository

Complete the [local demo](https://github.com/mauricemohr88-debug/hermes-local-hands/blob/main/docs/TRY_IT.md#1-run-the-local-demo) first if the
approval/snapshot distinction is new to you. Only register a repository and
check profiles you trust: approved check code has your normal host and network
access. Start with a non-sensitive test repository, not production code.

### Install the released CLI

Requirements: Python 3.11+ and Git. Install the isolated command with
[uv](https://docs.astral.sh/uv/) or pipx:

```bash
uv tool install hermes-local-hands
# Alternative: pipx install hermes-local-hands
```

For development from a source checkout, use the setup above and install the
additional development tools when needed:

```bash
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

The example below registers a real workspace named `demo`; this is separate
from the generated `demo` command above. It only exposes `src` and `tests`.
Replace the absolute path, check executable, and allowlists with deliberate
choices for your own repository. When using a source checkout without an
activated environment, invoke `.venv/bin/hermes-local-hands` instead.

```bash
# Creates private local state and a bearer credential file (mode 0600).
hermes-local-hands init --client-id hermes-mac-studio

# Register one Git repository and fixed, named check profiles.
hermes-local-hands workspace add \
  --id demo \
  --root /absolute/path/to/repository \
  --read src \
  --read tests \
  --write src \
  --write tests \
  --check syntax=/usr/bin/python3,-m,compileall,-q,src \
  --client hermes-mac-studio

# Start the listener. It refuses non-loopback bind addresses.
hermes-local-hands serve --host 127.0.0.1 --port 8741
```

`init` stores the token under the private state directory rather than printing
it. On macOS/Linux the default is
`~/.local/state/hermes-local-hands/clients/<client-id>.token`; set
`XDG_STATE_HOME` first to choose another private state location. Read the file
locally and export it only in the Hermes runtime's private environment:

```bash
export HERMES_LOCAL_HANDS_TOKEN="$(< "$HOME/.local/state/hermes-local-hands/clients/hermes-mac-studio.token")"
```

Do not put a real token in a repository, issue, screenshot, shell history, or
public configuration file.

Source-checkout users can inspect setup without changing it:

```bash
.venv/bin/hermes-local-hands doctor --workspace demo --client hermes-mac-studio
```

Diagnostics do not initialize or repair state, approve requests, execute check
profiles, or prove a remote Hermes connection. See the
[diagnostic examples](https://github.com/mauricemohr88-debug/hermes-local-hands/blob/main/docs/TRY_IT.md#2-check-your-local-setup-read-only).

### End-to-end workflow

1. The local operator registers a workspace, its explicit read/write allowlist,
   fixed check profiles, and the Hermes client grant.
   `workspace grants <workspace-id>` lists current grants; `workspace revoke
   <workspace-id> <client-id>` removes one and records the decision.
2. The local operator starts `serve` on loopback only.
3. A trusted reverse proxy/tunnel terminates HTTPS and forwards to that local
   listener. Local Hands still accepts only the exact proxy host(s) named at
   startup; it does not infer trust from arbitrary forwarded headers.
4. Hermes calls `workspace_status` or `read_file`, or creates a pending patch
   or check request.
   Patch and check requests require a clean registered checkout both when they
   are created and when they are approved; uncommitted changes are never copied
   into the managed snapshot.
5. The local operator inspects the request and chooses one of these local-only
   commands:

   ```bash
   hermes-local-hands request list --state pending
   # Default output is a multiline, control-escaped local review.
   hermes-local-hands request show <request-id>
   # Copy the approval_code shown above; it is intentionally request-specific.
   hermes-local-hands request approve <request-id> --confirm <approval-code>
   # or:
   hermes-local-hands request deny <request-id> --reason "not approved"
   ```

   Use `request show <request-id> --json` only when escaped machine-readable
   output is needed. The default review prefixes every untrusted patch line and
   escapes terminal/bidirectional controls so a patch cannot visually imitate
   the approval fields.

6. An approved operation is revalidated against the recorded `HEAD` and policy,
   then Local Hands applies or launches it from a managed snapshot. Approved
   check code is still host-capable. Inspect its full output locally with
   `hermes-local-hands request status <request-id>`. Remote `request_status`
   exposes only structured execution metadata such as exit state, output size,
   and output digest. Verify the receipt chain locally with
   `hermes-local-hands receipt-verify`.

7. After reviewing a succeeded or failed snapshot, free its retention slot only
   through the exact-ID local deletion gate:

   ```bash
   hermes-local-hands snapshot list
   hermes-local-hands snapshot delete <request-id> --confirm <request-id>
   ```

   The command records deletion-requested and deletion-completed receipts. It
   refuses pending, executing, missing, symlinked, or mismatched targets and
   never deletes snapshots automatically. An `uncertain` snapshot can be
   removed only after explicit local review and the same exact-ID confirmation.
   A successful deletion empties the already-open request directory in place
   and retains only a tiny completion marker instead of performing a final
   path-based directory removal. Completed marker directories are omitted from
   `snapshot list`; incomplete deletions remain visible there for local
   investigation.

For a check request linked to an approved patch, create it locally with the
patch request ID. The check then uses that patch's approved snapshot rather
than the mutable active checkout:

```bash
hermes-local-hands check add demo syntax check-after-patch-001 \
  --client hermes-mac-studio \
  --patch-request <approved-patch-request-id>
```

That approval creates a **fresh** snapshot at the recorded base commit and
replays the exact stored patch bytes whose digest was reviewed; it does not
reuse a mutable previous snapshot. A check result is evidence about that
snapshot only; it is not a merge, deployment, or production safety claim.

## Hermes MCP configuration

Generate the configuration fragment rather than hand-copying names:

```bash
# Local same-machine use:
hermes-local-hands hermes-config --port 8741

# Remote use: pass the exact, already configured HTTPS tunnel endpoint.
hermes-local-hands hermes-config \
  --endpoint https://mac-studio.example.ts.net/mcp \
  --token-env HERMES_LOCAL_HANDS_TOKEN
```

The generated YAML includes only these five tools:

- `workspace_status`
- `read_file`
- `propose_patch`
- `request_check`
- `request_status`

The two inspection tools advertise the MCP `readOnlyHint`. Hermes versions and
clients may still apply their own approval or policy gate to those tools; the
hint is useful metadata, not a compatibility guarantee or a bypass.

Hermes releases affected by upstream issue
[#88858](https://github.com/NousResearch/hermes-agent/issues/88858) may still
prompt for every read-only call while `trust: untrusted` is configured. That is
a fail-closed Hermes client behaviour, not additional Local Hands authority.
The upstream fix is tracked in
[#88372](https://github.com/NousResearch/hermes-agent/pull/88372). Keep the
generated `untrusted` setting unless you have reviewed the implications of
changing the client-side trust policy.

For a reverse proxy, bind Local Hands only to loopback and name every permitted
external Host exactly:

```bash
hermes-local-hands serve --host 127.0.0.1 --port 8741 \
  --proxy-host mac-studio.example.ts.net
```

The endpoint generator accepts loopback `http://.../mcp` or an explicit
non-loopback `https://.../mcp` URL. It rejects embedded credentials, query
strings, and unsafe schemes. Configure the tunnel's own identity,
authentication, and HTTPS separately; do not expose port 8741 directly to the
public Internet.

## Safety properties and limits

- **Explicit scope:** a client must have a workspace grant; path reads and
  patches must stay inside the workspace allowlist. Secret-looking and binary
  material is not returned as normal text.
- **No direct mutation:** no remote endpoint approves, denies, executes a
  shell, writes the registered checkout, merges, or pushes.
- **Snapshot working directory:** accepted patches and checks use a snapshot
  rooted at the recorded commit and do not include uncommitted checkout
  changes. This constrains Local Hands' own file operations, not what approved
  check code can access on the host.
- **Checks are not sandboxed:** fixed profiles limit what the protocol launches,
  but the selected program still runs as the local user. It can access that
  user's files, network, credentials, services, and can cause host-side
  effects. Only approve profiles and repositories you trust.
- **Check output is local-only:** stdout/stderr is retained for local review but
  omitted from the remote request view. The remote client receives bounded
  metadata and a digest, closing the direct output-content channel through
  `request_status`. Approved code is still not sandboxed and can influence
  metadata or communicate through its normal host and network access.
- **Checkout observation is limited:** after a check, Local Hands compares only
  Git-visible checkout status before and after. `same` does not prove that no
  non-Git file, service, network, credential, or other host-side effect
  occurred.
- **Audit evidence:** retained request/decision events form a signed receipt
  chain. Verification detects edits and reordering within that retained chain;
  without an externally anchored head it cannot detect deletion of a valid
  tail or rollback to an earlier valid database. Receipts also do not prove a
  host was not compromised.
- **Bounded alpha retention:** v0.1 permits at most 32 open requests per client,
  256 open requests globally, 512 retained requests per client, and 2,048
  retained requests globally. Managed storage also permits at most 128 snapshot
  deletion-marker directories. It never silently deletes requests, snapshots,
  or markers.
  Reviewed terminal snapshots can be removed one at a time through the local
  exact-ID command above, but there is no request-record or marker-prune command
  yet. Reaching a retained-request or deletion-marker cap is a deliberate
  fail-closed stop that needs a later reviewed retention/migration release, not
  a database or filesystem deletion workaround.
- **Failed creation markers:** snapshot construction uses a private,
  high-entropy `.creating-*` staging directory and atomic no-replace publication.
  If construction fails, Local Hands clears only the directory bound to its open
  descriptor and deliberately does not perform a race-prone path deletion. An
  empty or partially cleared staging marker can therefore remain and counts
  conservatively toward the 32-snapshot limit. v0.1 has no CLI prune operation
  for these internal markers; repeated build failures require a reviewed
  recovery/migration rather than manual deletion while evidence matters.

Read [THREAT_MODEL.md](https://github.com/mauricemohr88-debug/hermes-local-hands/blob/main/THREAT_MODEL.md) and [SECURITY.md](https://github.com/mauricemohr88-debug/hermes-local-hands/blob/main/SECURITY.md) before
using it with sensitive repositories.

## Development validation

```bash
ruff check .
ruff format --check .
pip-audit --local --skip-editable --progress-spinner off
pytest --cov=hermes_local_hands --cov-report=term-missing
python -m build
python -m twine check dist/*
```

CI additionally installs the built wheel into a clean environment. These are
release checks for the package, not proof of a safe production rollout.

On 2026-09-07 one real two-machine alpha flow was completed using Hermes on one
Mac, this service on another Mac, and HTTPS over a private Tailscale network.
The run covered unauthenticated rejection, status and file reads, a pending
patch, local approval, snapshot application, a linked check, and receipt-chain
verification. This is evidence for that exact environment only; it is not a
general compatibility, availability, or production-security claim.

For a durable local service setup, see [docs/SERVICE.md](https://github.com/mauricemohr88-debug/hermes-local-hands/blob/main/docs/SERVICE.md).

## Project direction

The complete local security core stays free and open source. This project does
not offer a paid plan or hosted service; tester adoption, paying customers, and
revenue must not be inferred from a release or a successful local demo.

We are looking for **two independent split-machine testers**. Try one small,
non-sensitive workflow and report the first confusing step using the
[feedback template](https://github.com/mauricemohr88-debug/hermes-local-hands/blob/main/docs/TRY_IT.md#4-report-what-actually-happened). No call,
payment, or private repository upload is needed. A failed setup is useful
feedback too; the invitation is not evidence that two testers have completed it.

Only actual, repeated use should justify an optional convenience layer, such as
a local approval inbox or later H3rm35 mobile approval support. H3rm35 is a
separate project, not a requirement or a completed integration. See
[ROADMAP.md](https://github.com/mauricemohr88-debug/hermes-local-hands/blob/main/ROADMAP.md) for the evidence gates.

### Related upstream context

Related upstream discussions include
[#18715](https://github.com/NousResearch/hermes-agent/issues/18715),
[#42807](https://github.com/NousResearch/hermes-agent/issues/42807), and
[#16462](https://github.com/NousResearch/hermes-agent/issues/16462), with related
implementation work in
[#63966](https://github.com/NousResearch/hermes-agent/pull/63966) and
[#43045](https://github.com/NousResearch/hermes-agent/pull/43045). These links
provide context, not a claim about their current status or endorsement of Local
Hands.

## Contributing and security

See [CONTRIBUTING.md](https://github.com/mauricemohr88-debug/hermes-local-hands/blob/main/CONTRIBUTING.md) for development expectations and
[SECURITY.md](https://github.com/mauricemohr88-debug/hermes-local-hands/blob/main/SECURITY.md) for private vulnerability reporting. Never put
credentials, private source, or real action receipts in a public issue or pull
request.

## License

Released under the [MIT License](https://github.com/mauricemohr88-debug/hermes-local-hands/blob/main/LICENSE).

Hermes Local Hands is an independent community project and is not affiliated
with or endorsed by Nous Research.
