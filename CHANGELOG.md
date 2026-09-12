# Changelog

## 0.2.1 - 2026-09-12

- Use absolute GitHub documentation and raw asset URLs in the package README
  so links and the recorded demo image resolve correctly when viewed on PyPI.
- Add regression coverage for relative Markdown and HTML link/image targets in
  the README selected by package metadata. No runtime behavior or dependencies
  change.

## 0.2.0 - 2026-09-12

- Add a `demo` command with a generated toy Git repository and
  private state, separate manual patch/check approvals, no Hermes or network
  requirement, and retained artifacts for inspection. Noninteractive input
  cannot approve requests.
- Add read-only `doctor` diagnostics with optional workspace, client, endpoint,
  and JSON output; diagnostics do not initialize or repair state or execute
  requested checks. Only an explicit endpoint enables a bounded unauthenticated
  reachability probe; live SQLite journals cause dependent checks to be skipped.
- Put a concrete split-machine use case, local demo walkthrough, and separate
  two-machine tester path at the start of the documentation. Keep local
  approval, host-capable check execution, and evidence limits explicit.
- Include a real toy-demo CLI recording, self-contained replay, and a narrowly
  scoped fixture-only recorder. Recording automation is not a noninteractive
  approval feature of the CLI, and no remote connection is claimed.

These commands are new in 0.2.0. The remote protocol and local-only approval
boundary are unchanged; this remains alpha software, not an OS sandbox.

## 0.1.1 - 2026-09-08

- keep captured check stdout/stderr local while exposing only bounded execution
  metadata and a digest through remote `request_status`;
- grant `tests` write access in the quickstart so proposed implementation and
  proof changes can be reviewed together;
- No stable protocol, production-security claim, hosted service, or compatibility
  guarantee is made until a release explicitly says otherwise.

## 0.1.0 - 2026-09-04

Initial alpha release candidate:

- loopback-only MCP companion with explicit trusted reverse-proxy host settings;
- client-scoped workspace grants and narrow status/file-read tools;
- pending, expiring patch/check requests with local-only approval and rejection;
- snapshot-only patch/check execution, stale-request protection, and uncertain
  recovery after interrupted execution;
- anonymous archives, high-entropy staging, and atomic no-replace snapshot
  publication on supported macOS and Linux hosts;
- exact-ID snapshot cleanup with fd-bound deletion, retained completion markers,
  and explicit incomplete-deletion visibility;
- signed receipt chain and local verification command;
- source/build/test/package validation automation.
- one real two-machine alpha validation over tailnet HTTPS, covering remote
  status/read, a pending patch, local approval, snapshot execution, a linked
  check, and receipt verification.

This version is not a sandbox. Approved checks run trusted repository code with
the local user's normal host and network access and can cause host-side effects.
Its post-check source observation covers Git-visible checkout status only. It
has not established broad Hermes/tunnel compatibility or production readiness.
