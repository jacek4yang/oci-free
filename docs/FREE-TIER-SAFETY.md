# Free Tier safety

The question this tool exists to answer is "will this cost me money?", and the
honest answer is sometimes "I cannot tell". Everything below follows from
treating that third answer as a first-class result rather than rounding it to
"probably fine".

## Strict mode is the only mode

Every resource and operation is classified as one of:

| Classification | Meaning | Permitted? |
| --- | --- | --- |
| `VerifiedAlwaysFree` | OCI itself reports it as Always Free, a verified allowance covers it, and it provably fits what is left. | **Yes** |
| `LimitedFree` | Free only within a promotional or trial allowance. | No |
| `Paid` | Billed. | No |
| `Unknown` | Eligibility could not be proven. | No |

Only the first permits a mutation. `Unknown` blocks, which is the whole point:
a tool that guessed would be wrong exactly when it mattered.

## Where the evidence comes from

Three independent sources, combined into one auditable decision.

### 1. OCI's own billing classification

The Core Services `Shape` model carries a `billingType` field whose values are
`ALWAYS_FREE`, `LIMITED_FREE`, and `PAID`. That is live, machine-readable
evidence from Oracle, and it is the primary input.

Shape names are never matched against a list. Oracle renames and retires shapes,
and a historical name in a tutorial is not evidence of anything.

A `billingType` this build has never seen decodes to `Unknown` and therefore
blocks. A new Oracle billing category must never be silently read as "free".

### 2. The policy snapshot

`billingType` says *whether* a shape is Always Free. It does not say *how much*
of it a tenancy may use — the published allowances (4 OCPU and 24 GB of Ampere
A1; two AMD micro instances) live only in Oracle's documentation.

Those figures are recorded in `policy/free-tier-snapshot.json`, which ships with
the binary and changes only through code review. It carries:

- `provenance` — a citable source URL for every claim;
- `verified_on` — the date the allowances were last checked;
- `assumptions` — what the numbers mean, stated explicitly;
- `unknown_behaviour` — what happens to anything not listed.

The snapshot is **never fetched at runtime**. CLAUDE.md forbids turning scraped
web text into billing policy, and a network-sourced allowance would be a way to
be silently wrong about money.

The snapshot only ever *narrows*. A resource class it does not list is Unknown,
and Unknown blocks.

### 3. Live tenancy usage

Allowances are pooled across the tenancy, so the third input is what is already
consumed. This is computed from the live instance list, not remembered.

## Capacity is pooled, not counted

Counting instances would be wrong. `VM.Standard.A1.Flex` draws from a shared
pool, so one four-OCPU instance consumes the entire ARM allowance while a
tenancy with four one-OCPU instances is in exactly the same position.

Two rules govern the arithmetic:

- **A stopped instance still consumes its allocation.** Only termination
  releases it. `vm stop` says so, because "stop it to free up capacity" is a
  natural and wrong assumption.
- **Unmeasurable usage blocks everything.** If OCI does not report an
  instance's shape configuration, real usage is *at least* what was measured and
  possibly more — so no headroom can be proven and nothing fits. The instance is
  named in the blocker, so the gap is visible rather than mysterious.

Comparisons use a tolerance of 1e-9: large enough to absorb JSON float
representation error, far too small to hide a real overrun. There is no
generous rounding anywhere in the capacity path.

## Nothing is created before a plan exists

Every operation that could create, enlarge, attach, or reserve a billable
resource produces a structured plan first, showing the resource and region, the
classification and its evidence, before and after consumption, network exposure
changes, the billing risk, and any warnings.

This is enforced by the type system, not by discipline. Every write helper takes
an `Approval`, and the only way to obtain one is `MutationPlan::approve`, which
refuses if the plan has blockers, if the billing risk is anything but `none`, or
if the user did not confirm. A write path that skipped the plan would not
compile.

The tests prove the consequence directly: a paid shape, an over-allocation,
unmeasurable usage, an invalid size, a missing source, and an unconfirmed plan
each issue **zero** write requests to OCI.

## Seeing the reasoning

```console
$ oci-free policy explain VM.Standard.A1.Flex --ocpus 2 --memory 12
```

prints the whole chain — live billing type, snapshot allowance, current usage,
the projection, the classification, and the decision — because a safety engine
that answers "blocked" without saying why is one people learn to work around.

## Idle reclamation

OCI reclaims idle Always Free compute instances. oci-free will detect and
explain that risk, and will **never** generate artificial CPU, memory, or
network activity to avoid it. Manufacturing load to defeat a provider's
reclamation policy is abuse, and a tool that did it on your behalf would be
making that choice for you.

## Cost is never rounded down

`oci-free cost` reports an unavailable figure as unavailable. It is never shown
as `0.00`. Most Free Tier tenancies lack the Usage API grant, and printing zero
in that case would give exactly the wrong reassurance to the people most likely
to rely on it.

A genuine reported zero is stated as a fact, because that is the reassurance
worth having.
