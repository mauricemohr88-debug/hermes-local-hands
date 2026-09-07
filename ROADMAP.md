# Roadmap

Hermes Local Hands is an alpha security boundary, not a finished service. The
free local core comes first. No hosted plan, paid tier, customer, or revenue is
claimed today.

## Before beta

- Reproduce installation and one approved snapshot workflow with at least two
  independent Hermes users.
- Resolve or document the current Hermes MCP annotation compatibility gap.
- Add reviewed retention and migration paths before the alpha caps become a
  practical limitation.
- Collect false-positive and operator-confusion reports around approvals,
  allowlists, and snapshot results.
- Keep the remote protocol unable to approve, deny, run an arbitrary shell,
  merge, or push.

## Possible convenience layers

Only repeated user evidence should move these onto an implementation roadmap:

- a native local approval inbox with clear diffs and device authentication;
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

Missing evidence means unknown, not zero. If the first three gates fail, the
next step is user interviews and documentation fixes rather than more features.
