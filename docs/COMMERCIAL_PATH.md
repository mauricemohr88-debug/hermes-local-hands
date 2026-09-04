# Commercial path (future hypotheses)

There is no paid service, hosted control plane, customer, revenue, or validated
price in v0.1. The free, open-source security core is the product being tested.
No security boundary should be weakened to create an upsell.

## Potential offers — not commitments

| Offer | Hypothesis | Indicative price | What must be true first |
| --- | --- | --- | --- |
| Guided setup | People want help configuring a secure tunnel, grants, policy, and first check profile | **149 EUR** one-time | At least three people ask for hands-on setup after trying docs |
| Pro | A solo user wants multi-device policies, durable local audit views, and a clearer approval inbox | **9–15 EUR/month** | At least five active users report recurring use and two state willingness to pay |
| Team | Teams need self-hosted roles, SSO, shared policies, retention, and fleet status without uploading source | **49–99 EUR/month** | At least two distinct teams describe the same governance need and one agrees to a discovery call |

These are price and demand hypotheses, not quotes or promises. The v0.1 core
remains usable without payment, and the present project has no billing,
telemetry, hosted relay, or uptime obligation.

## 30-day validation gates

Use a small, observable validation window before adding a cloud backend, payment
flow, or feature set:

1. **Install:** three independent Hermes users complete the documented local
   install without private support access.
2. **Real workflow:** two users register a workspace, inspect it remotely, and
   complete one locally approved snapshot request.
3. **Retention signal:** one user comes back for a second session or asks to
   keep the tool enabled.
4. **Paid signal:** two users explicitly choose one of the proposed offers at
   the indicative price, or explain a concrete lower-value alternative.
5. **Safety signal:** no unresolved critical issue in grants, approval, path
   confinement, receipt integrity, or test execution is discovered.

If gates 1–3 fail, stop promotion and interview users before implementing
monetisation. If the paid signal fails, keep the free tool useful and avoid
inventing a subscription. If the safety signal fails, fix or narrow the free
core before asking anyone to rely on it.

## Principles for any later paid layer

- Source stays on customer-controlled machines by default.
- The free local approval, no-shell, no-active-checkout-write boundary remains.
- Paid services may improve setup, policy management, multi-device visibility,
  retention, or support; they must not remotely bypass a local approval.
- Pricing and claims will be changed only after observed evidence, not because a
  roadmap needs revenue.
