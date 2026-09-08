# Threat model (v0.1)

## Goal

Hermes Local Hands lets a remote, authenticated Hermes client inspect an
explicitly selected local Git workspace and request bounded work, without
giving that remote client a generic shell or the ability to silently modify the
active checkout. It is a consent and audit boundary, not a sandbox.

The security invariant is:

> A remote client may read only explicitly granted material and may create a
> pending request. Only the local operator interface can approve or reject it.
> Local Hands performs its own patch/check workspace operations in a snapshot;
> approved check code remains capable of reaching the active checkout and host.

## Assets to protect

- Source, private configuration, credentials, and personal data near a repo
- The active checkout, especially uncommitted work
- The local user's host, network, services, and cloud credentials
- Operator approval decisions and receipt integrity
- Client bearer credentials and workspace grants

## Trust boundaries

1. **Remote Hermes client.** Authenticated but treated as capable of making
   malformed, excessive, or harmful requests. Its bearer credential grants only
   the workspace permissions assigned to that client.
2. **Tunnel/reverse proxy.** Responsible for HTTPS and remote-client access. It
   is explicitly configured by the operator; Local Hands uses loopback binding
   and an exact trusted proxy Host allowlist, not arbitrary forwarded headers.
3. **Local Hands service.** Enforces request shape, client/workspace grants,
   allowlists, request binding, TTL, and state transitions.
4. **Local operator.** Reviews and approves/denies queued work using the local
   CLI. Operator error remains possible.
5. **Managed snapshot.** Keeps Local Hands' own patch/check workspace operations
   away from the active checkout. It is not an operating-system security
   boundary and cannot confine approved code.
6. **Test process.** Runs fixed-profile repository code as the local user. It
   is fully trusted by the operator for v0.1 and is not sandboxed.

## Security controls in scope

| Threat | Control | Remaining risk |
| --- | --- | --- |
| Another client reads or requests work in a workspace | Client-to-workspace grants; exact grant replacement on re-registration; bearer authentication; request ownership checks | Stolen bearer token acts as that client until revoked |
| `../`, symlink, binary, or secret-file read | Canonical containment, no-follow reads, explicit allowlist, byte caps, binary/secret rejection | Unknown secret formats and host compromise are out of scope |
| Patch changes unrelated files or Git metadata | Text-only patch parser, explicit write allowlist, file/line caps, base-commit check | An allowed text patch may still be harmful |
| Replay or cross-client idempotency collision | Idempotency key is scoped to client and bound payload | A client can intentionally repeat a new key |
| Stale request approved after repo/policy changes | Head/policy binding and short request TTL | A trusted operator may still approve bad current code |
| Process crash mid-execution | Execution becomes `uncertain` for local review; it is never silently success | A process may have had external effects before interruption |
| Approved execution modifies active checkout | Local Hands writes only its managed snapshot and records a before/after Git-status observation | Approved check code is not confined and can still modify the checkout or host |
| Test profile compromises the host | Profiles are fixed locally and approval is explicit | **Not sandboxed:** trusted repo code gets normal user/network access and can cause host-side effects |
| Test profile prints host data | Captured stdout/stderr is available only through the local operator view; remote status exposes metadata and a digest | Approved code can still influence metadata or communicate through its normal host/network access; the local operator can view and copy output |
| Check reports source checkout unchanged | Before/after Git status is recorded | It observes Git-visible checkout changes only; other local/host effects can still occur |
| Public HTTP exposure or DNS rebinding | Literal loopback bind; exact proxy host allowlist; HTTPS endpoint generator | A misconfigured tunnel/proxy can still expose the service |
| Receipt edits/reordering inside the retained chain | Signed receipt chain with previous-hash links | With no external head anchor, valid tail deletion, empty-ledger replacement, or rollback is not detectable; a compromised local user/key can forge future receipts |

## State and recovery model

Requests are created as `pending` and include the client, workspace, policy
hash, Git `HEAD`, expiry, and client-scoped idempotency binding. They may become
`rejected`, `expired`, `executing`, `succeeded`, `failed`, or `uncertain`.

The alpha store retains at most 512 requests per client and 2,048 overall, in
addition to the smaller pending-request limits. v0.1 has no automatic deletion
or prune operation. At a retained-request cap it stops accepting new requests
until a reviewed retention/migration mechanism exists; operators must not erase
the database if its receipt/request history is evidence they need to keep.

Snapshot deletion opens and identity-checks the reviewed request directory
under the shared retention lock, then clears only that bound directory in place.
It retains a small completion marker rather than issuing a final path-based
rename or directory removal. Completed marker directories are hidden from
`snapshot list`; incomplete deletions stay visible there. At 128 retained
deletion-marker directories, further snapshot deletion fails closed until a
reviewed marker retention/migration mechanism exists.

Snapshot creation uses a high-entropy private staging directory and an atomic
no-replace publish operation. Exceptional cleanup clears only the already-bound
staging directory and does not remove its top-level name. A failed or crashed
creation can therefore leave a `.creating-*` marker that counts toward the
32-snapshot limit. v0.1 intentionally has no path-based automatic cleanup or CLI
prune for those markers; repeated failures require a reviewed recovery release.

An operator can only approve an unexpired pending request after Local Hands
rechecks the policy and base commit. Startup recovery does not guess the outcome
of a previous process: interrupted `executing` work is marked `uncertain` and
requires local inspection. A patch-linked check creates a fresh snapshot at the
bound commit and replays the exact stored patch bytes after verifying their
digest; it never relies on an evolving working directory or a mutable prior
snapshot.

## Explicit non-goals / claims we do not make

- Kernel, container, VM, or process sandboxing
- Protection from malicious code in an approved test profile or repository
- Protection if the local host, account, state directory, signing key, tunnel,
  or remote Hermes runtime is compromised
- Complete prevention of data exfiltration from source that an operator has
  allowed a client to read
- Multi-tenant isolation, SSO, compliance certification, or hosted uptime
- A proof that a receipt equals a safe change, successful merge, deployment, or
  production behavior
- Tested compatibility with every Hermes client, transport, proxy, or two-host
  deployment

## Operator checklist

Before each rollout, the operator should:

1. Give each client a separate credential and the minimum workspace grant.
2. Keep the listener on loopback; authenticate and encrypt the tunnel.
3. Use a small read/write allowlist and fixed checks whose commands are known.
4. Read a pending patch or check request before local approval.
5. Treat locally displayed test output as untrusted data; do not copy
   credentials into it or forward it to the remote client without review.
6. Inspect `uncertain` operations manually and create a new request instead of
   retrying blindly.
7. Verify the receipt chain after an important review period.
8. Review retained snapshots and remove only terminal ones with the local
   exact-request-ID deletion command before reaching the 32-snapshot cap.

## Required validation before a production claim

Independent reviewers should test path traversal and symlink races, secret
redaction, grant enforcement, cross-client replay, expired requests, crash
recovery, receipt-chain verification, reverse-proxy host checks, patch parser
limits, and snapshot working-directory behavior. Real two-host Hermes and tunnel
validation remain a deployment exercise; package tests alone cannot demonstrate
it.
