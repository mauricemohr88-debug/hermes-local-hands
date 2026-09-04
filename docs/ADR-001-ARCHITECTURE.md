# ADR-001: Remote brain, local hands

**Status:** accepted for v0.1 alpha

## Decision

Hermes Local Hands is a standalone local companion, not a fork or replacement
for the Hermes runtime. It exposes a small MCP surface to one or more
authenticated remote clients:

- `workspace_status` and `read_file` inspect only client-granted workspaces;
- `propose_patch` and `request_check` create pending, expiring requests;
- `request_status` exposes only the caller's request state.

Approval and rejection are local-only CLI actions. Local Hands applies approved
patches and launches approved checks from a managed snapshot pinned to the
request's Git `HEAD` and policy hash. Approved code is not confined by that
working directory. The protocol has no raw shell, direct active-checkout write,
merge, or push operation.

The HTTP listener binds to literal loopback addresses. A remote deployment must
use an independently authenticated HTTPS tunnel/reverse proxy and explicitly
configure the exact proxy host(s) Local Hands accepts. The configuration helper
only generates loopback HTTP or explicit HTTPS `/mcp` endpoints.

## Context

A remote Hermes deployment can provide persistent reasoning while the local
machine owns source code, local services, and the decision to execute work. A
raw SSH or shell bridge would solve connectivity by turning the remote runtime
into an unrestricted local operator. Direct writes to the active checkout would
also risk destroying uncommitted changes.

The upstream conversations [#18715](https://github.com/NousResearch/hermes-agent/issues/18715),
[#42807](https://github.com/NousResearch/hermes-agent/issues/42807), and
[#16462](https://github.com/NousResearch/hermes-agent/issues/16462), alongside
PRs [#63966](https://github.com/NousResearch/hermes-agent/pull/63966) and
[#43045](https://github.com/NousResearch/hermes-agent/pull/43045), show why the
boundary should remain a companion integration rather than a new Hermes core.

## Consequences

Positive consequences:

- explicit ownership and auditability of the local execution decision;
- Local Hands' own file operations do not target the active checkout;
- a small, independently testable MCP and persistence surface;
- future Hermes changes do not require carrying a fork.

Negative consequences:

- a remote agent cannot finish arbitrary work without a local operator;
- check profiles run trusted code as the local user, are not sandboxed, and can
  cause host-side effects; their source-status observation is Git-visible only;
- the operator must securely configure the tunnel and protect client tokens;
- this does not yet prove a two-host Hermes deployment or every MCP-client
  compatibility detail.

## Rejected alternatives

- **Raw SSH/shell forwarding:** too broad for a consent-first v0.1 boundary.
- **Write directly into the active checkout:** unsafe for uncommitted work and
  makes execution state difficult to reconstruct.
- **Remote approval endpoint:** lets a remote compromise defeat the local
  operator gate.
- **Public hosted code execution:** outside the local-source ownership and
  privacy model.
- **WebView or second Hermes runtime:** duplicates the runtime instead of
  granting narrow local capabilities.
