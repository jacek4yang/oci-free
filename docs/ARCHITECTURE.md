# Architecture

## Design objective

`oci-free` should make the common Free Tier lifecycle simple without becoming a generic OCI SDK. The architecture therefore separates transport, OCI service adapters, domain models, safety policy, network reasoning, and user interaction.

## Core layers

### Signed transport

Owns HTTP concerns only:

- region/service endpoint construction;
- OCI RSA request signing;
- headers and body digests;
- pagination;
- retry policy;
- request IDs;
- response decoding;
- redacted diagnostics.

It must not decide whether a resource is free.

### OCI service adapters

Thin typed wrappers around the OCI endpoints actually needed by the product: identity, compute, virtual networking, block storage, limits, usage/cost, and monitoring.

Adapters expose OCI facts, not product policy.

### Free policy engine

Combines evidence into a `FreeAssessment`.

Evidence priority should prefer current machine-readable OCI data. Compute shape metadata is especially valuable when OCI exposes billing classifications such as `ALWAYS_FREE`, `LIMITED_FREE`, or `PAID`.

Where no complete runtime classification exists, use conservative policy snapshots with provenance. Unknown eligibility fails closed.

### Network planner

Computes effective exposure for one instance by resolving its VNIC, attached NSGs, subnet Security Lists, public IP state, and routes.

Normal write operations modify a managed per-instance NSG. Subnet-wide rules are never the default implementation of `vm net open`.

### Application commands

Commands orchestrate reads, build plans, invoke policy, request confirmation, perform writes, verify results, and render human or JSON output.

## Managed resources

Resources created by `oci-free` should use deterministic tags or defined tags when practical so they can be distinguished from user-managed OCI resources. Never assume ownership solely from a display name.

A managed instance should normally have one dedicated managed NSG. Shared network infrastructure may be reused only after the tool verifies that it matches the expected topology.

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

Human output may evolve for usability. JSON output should eventually be versioned and stable enough for scripts. Do not serialize arbitrary internal Rust structs as an accidental public API without thinking about compatibility.
