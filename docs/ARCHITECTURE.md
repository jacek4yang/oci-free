# Architecture

## Design objective

`oci-free` should make the common Free Tier lifecycle simple without becoming a generic OCI SDK. The architecture therefore separates transport, OCI service adapters, domain models, safety policy, network reasoning, and user interaction.

## Module map

```text
src/
  main.rs            dispatch, exit codes, human/JSON rendering
  cli.rs             the clap command surface
  interactive/       prompts, and the rules for when prompting is allowed
  commands/          one module per command, plus shared discovery
  domain/            pure models: policy, capacity, exposure, ownership, plans
  policy/            the Free Tier engine and the dated snapshot
  oci/               typed adapters: identity, compute, network, limits, usage,
                     block storage, plus the signed transport
  auth/              key loading, fingerprint derivation, request signing
  config/            configuration loading and redaction
  output/            the versioned JSON envelope
  testing/           the in-process HTTPS mock, compiled only under cfg(test)
```

Dependencies point one way: `commands` may use `domain`, `policy`, and `oci`;
`domain` uses no adapter for anything but its response types; `oci` never
decides policy.

## Core layers

### Signed transport

Owns HTTP concerns only:

- region/service endpoint construction, with the realm taken from the tenancy
  OCID rather than guessed from a region table, so an unknown realm fails closed
  instead of sending a signed credential to a host Oracle does not control;
- OCI RSA-SHA256 request signing, via `ring` — see
  [`SECURITY.md`](SECURITY.md#dependency-advisories);
- headers and body digests;
- pagination;
- retry policy;
- request IDs;
- response decoding;
- redacted diagnostics.

Three properties are enforced here so no command can weaken them: HTTPS only,
redirects never followed (a signature is bound to one host and path), and
response bodies bounded. Only provably replay-safe requests are retried — a
write qualifies only when it carries an OCI retry token.

It must not decide whether a resource is free.

### OCI service adapters

Thin typed wrappers around the OCI endpoints the product actually needs:
identity, compute, virtual networking, block storage, limits, and usage/cost.

Response models carry only the fields in use, and `serde` ignores the rest, so a
field Oracle adds cannot break the client. Every model tolerates a minimal
response, and anything unrecognised decodes to a value that fails closed rather
than to a permissive default.

Adapters expose OCI facts, not product policy.

### Free policy engine

Combines evidence into a `FreeAssessment`.

Evidence priority should prefer current machine-readable OCI data. Compute shape metadata is especially valuable when OCI exposes billing classifications such as `ALWAYS_FREE`, `LIMITED_FREE`, or `PAID`.

Where no complete runtime classification exists, use conservative policy snapshots with provenance. Unknown eligibility fails closed.

### Effective exposure model

Computes what can actually reach one instance by resolving its VNIC, attached
NSGs, subnet Security Lists, public IP state, route table, and internet gateway.

NSG and Security List rules **compose**: traffic is allowed if either permits
it. Every effective rule therefore carries the OCI object responsible for it, so
an absent NSG rule is never reported as a closed port. Internet reachability is
evaluated link by link — address, route, gateway — so a warning can name the
missing one.

Normal write operations modify a managed per-instance NSG. Subnet-wide rules are
never the default implementation of `vm net open`. See
[`NETWORKING.md`](NETWORKING.md).

### Mutation plans and the approval token

`domain::plan` makes the mutation protocol structural rather than aspirational.
Every write helper takes an `Approval`, and the only way to obtain one is
`MutationPlan::approve`, which refuses on a blocker, on any billing risk other
than `none`, or without an explicit confirmation. A write path that skipped the
plan would not compile.

### Application commands

Commands orchestrate reads, build plans, invoke policy, request confirmation, perform writes, verify results, and render human or JSON output.

## Managed resources

Resources created by `oci-free` carry deterministic freeform tags so they can be
told apart from user-managed ones. Ownership is proven from those tags and
**never** from a display name: a name is user-editable and easy to collide with,
and mistaking somebody's VCN for ours would put it in scope for deletion.

`domain::ownership` classifies a resource as `created`, `reused`, `user_owned`,
or `unknown`. Only `created` permits deletion; `reused` permits narrow
modification but never destruction; the other two permit neither. A tag value
this build does not recognise is `unknown`, which fails closed.

A managed instance has one dedicated managed NSG. Shared network infrastructure
is reused only after the tool verifies it matches the expected topology, and a
reused network whose topology has since drifted is reported rather than silently
used.

## Partial failure

A creation spans several OCI objects. Each is recorded in `CreatedResources`
before the next step runs, so a failure can compensate against exactly what
exists. Compensation deletes in reverse creation order, touches **only** objects
this operation created, and never terminates an instance — that decision is the
user's. Anything that could not be removed is reported as a partial mutation
(exit code 7) naming the exact resources retained.

## Mutation protocol

Every risky mutation follows:

```text
Discover current state
        -> Build proposed state
        -> Gather free/billing evidence
        -> Evaluate policy
        -> Render preflight plan
        -> Confirm (interactive) or validate explicit flags
        -> Apply mutation
        -> Re-read OCI state
        -> Verify postcondition
        -> Report result and residual warnings
```

## JSON output

Human output may evolve for usability. JSON output is versioned and stable:
every payload is a purpose-built public DTO, never an internal struct serialized
by accident, so refactoring the implementation cannot silently change the
contract. The schema is documented in [`JSON.md`](JSON.md) and pinned by golden
tests that assert the exact field set of each payload.

## Testing

Policy, capacity, exposure, ownership, plans, and launch selection are pure
functions with no HTTP, and are tested exhaustively as such. Everything above
them runs against `testing::mock_oci`, an in-process HTTPS server that exercises
the real transport — signing, retries, error decoding — while recording every
request, including bodies.

That recording is what makes the central safety property directly testable: a
plan the policy engine rejected issues **zero** write requests. Several tests
assert exactly that, for a paid shape, an over-allocation, unmeasurable usage,
an invalid size, a missing ingress source, and an unconfirmed plan.
