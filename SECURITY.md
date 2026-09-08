# Security policy

Hermes Local Hands is alpha software. v0.1 is a local consent and workflow
boundary, not a complete sandbox or production security control.

## Report a vulnerability privately

Do not open a public issue for a suspected vulnerability. Use the repository's
private GitHub security-advisory flow, or contact the maintainer through the
address listed in the GitHub profile. Include:

- affected release or commit;
- platform and Python version;
- a minimal, safe reproduction;
- expected versus observed behavior; and
- realistic impact and any known prerequisites.

Do **not** send bearer tokens, signing keys, private source, receipts containing
private data, customer data, or screenshots that expose them. Redact examples
and say what you removed.

We will acknowledge a report when practicable, investigate it, and coordinate
disclosure with the reporter. There is no response-time guarantee, bounty, or
guarantee that every configuration can be supported.

## Important v0.1 limits

- The service binds only to loopback. Put it behind an authenticated HTTPS
  tunnel/reverse proxy only after configuring exact trusted proxy host names.
  Never expose the listener directly to the public Internet.
- Remote tools can inspect granted workspaces and create pending requests. They
  cannot remotely approve/deny, invoke arbitrary shell commands, mutate the
  active checkout, merge, or push.
- Workspace read/write access is explicit and client-scoped. Treat a bearer
  credential as sensitive until it is locally revoked.
- Local Hands applies patches and launches checks from an isolated snapshot,
  so its own file operations do not target the active checkout. This does not
  make the snapshot or approved code safe to execute: a check can still reach
  or modify the active checkout through an absolute path or another process.
- A check executes trusted repository code with normal local user, network, and
  host access. It is **not sandboxed**. Do not approve untrusted repositories
  or profiles on a machine containing sensitive material. Such code can cause
  host-side effects; a post-check `same` observation compares Git-visible
  checkout status only and is not proof that no other effect occurred.
- Captured check stdout/stderr is local-only. Remote `request_status` receives
  bounded execution metadata and a digest, not the output text. This closes the
  direct output-content channel; it does not sandbox approved code or prevent
  it from influencing metadata or using its normal network access.
- Receipts form signed local audit evidence for the retained chain. With no
  externally anchored head, verification cannot detect a deleted valid tail,
  an empty replacement database, or rollback to an earlier valid copy. They
  are not a warranty of safety, a compliance record, or proof against host
  compromise.

See [THREAT_MODEL.md](THREAT_MODEL.md) for abuse cases, recovery behavior, and
the risks the design intentionally does not claim to solve.
