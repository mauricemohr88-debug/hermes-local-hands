# Roadmap

Hermes Local Hands is an alpha security boundary, not a finished service. The
free local core comes first. No hosted plan, paid tier, customer, or revenue is
established by the roadmap or a local demo.

## Current onboarding focus

- Let a newcomer inspect one generated patch, approve it locally, and review a
  separately approved linked check without first configuring Hermes or a
  tunnel. The `demo` command retains this small example for inspection;
  it does not test a real workspace or a remote connection.
- Offer read-only `doctor` diagnostics that name missing setup without
  silently initializing state, executing checks, or changing approvals.
- Invite two independent split-machine testers to follow
  [TRY_IT.md](docs/TRY_IT.md) and report where they stop. Keep local demo, actual
  remote requests, complete approval workflows, and return use separate.

These onboarding commands are included from version 0.2.0. A release and a
maintainer demo do not establish independent tester completion or adoption.

## Before beta

- Reproduce installation and one approved snapshot workflow with at least two
  independent Hermes users.
- Record exact tested Hermes versions and document any observed MCP annotation
  compatibility gap; do not infer current compatibility from old issue links.
- Add reviewed retention and migration paths before the alpha caps become a
  practical limitation.
- Collect false-positive and operator-confusion reports around approvals,
  allowlists, and snapshot results.
- Keep the remote protocol unable to approve, deny, run an arbitrary shell,
  merge, or push.

## Possible convenience layers

Only repeated user evidence should move these onto an implementation roadmap:

- a native local approval inbox with clear diffs and device authentication;
- optional H3rm35 mobile approval convenience, only after real Local Hands
  adoption; H3rm35 stays separate and no completed integration is claimed;
- guided tunnel, workspace, and policy setup;
- multi-device policy and receipt views for small teams;
- externally anchored receipt heads and configurable retention.

Any later paid layer must remain optional. It must not weaken the free local
approval boundary or require source code to leave customer-controlled machines.

## Evidence gate

Before adding billing or a hosted control plane, the project should show:

1. three independent successful installs;
2. two complete remote-request/local-approval workflows;
3. one user returning for a second real session;
4. repeated demand for the same convenience problem;
5. no unresolved critical issue in grants, approval, path confinement, receipt
   integrity, or test execution.

Missing evidence means unknown, not zero. If the first three gates fail, use
short asynchronous feedback and documentation fixes before adding features.
Neither a paid review service with calls/turnaround commitments nor billing is
the current route to validating this free core.
