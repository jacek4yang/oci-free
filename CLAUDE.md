# Claude Code Development Contract

This repository is intentionally structured for agent-assisted development. Treat this file as the product and engineering contract unless a newer explicit instruction overrides it.

## Product

`oci-free` is a native Rust CLI for people who primarily use Oracle Cloud Infrastructure Free Tier and want a safer, simpler experience than the general OCI Console or official CLI.

The product must optimize for:

1. staying inside verifiable free eligibility;
2. understanding exactly what will change before mutation;
3. instance-scoped network management;
4. clear account, usage, cost, and exposure summaries;
5. one native binary with no Python or Node.js runtime dependency;
6. Windows, Linux, and macOS releases with simple installers.

It is not a general OCI SDK and should not attempt API completeness.

## Hard safety invariants

Do not weaken these without an explicit design change.

### Fail closed on billing uncertainty

The policy engine classifies resources or operations as:

- `VerifiedAlwaysFree`
- `LimitedFree`
- `Paid`
- `Unknown`

Strict mode is the default. Only `VerifiedAlwaysFree` mutations are allowed. `LimitedFree`, `Paid`, and `Unknown` must be blocked by default.

Never infer free eligibility only from a resource name or an old tutorial. Prefer live OCI machine-readable evidence. Where OCI exposes a compute shape billing classification such as `ALWAYS_FREE`, use it as evidence rather than hard-coding shape names.

For services without a complete machine-readable Free Tier classification, combine:

- live OCI service limits;
- current resource usage;
- current billing/usage data where available;
- a small, centrally maintained conservative policy snapshot with provenance and a verification date.

Do not scrape Oracle web pages at runtime and automatically convert arbitrary parsed text into billing policy.

### Preflight before mutation

Every operation that can create, enlarge, attach, reserve, or otherwise make a billable resource possible must first produce a structured plan. The plan should show:

- resource and region;
- current classification and evidence;
- relevant account limits and usage;
- before/after resource consumption;
- network exposure changes;
- billing risk;
- warnings.

Interactive mode asks for confirmation after the plan. Non-interactive mode requires all material choices to be explicit.

### Instance-scoped networking

Business ingress belongs on a per-instance Network Security Group attached to that instance's VNIC. Do not use a subnet-wide Security List as the normal `vm net open` implementation.

The network model must account for effective OCI behavior: Security List and NSG allow rules compose. Removing a rule from one instance NSG does not guarantee a port is closed if another applicable rule still allows it.

Therefore:

- `oci-free vm net <instance> open ...` modifies only that instance's managed NSG;
- `close` removes only the managed instance rule unless an explicitly advanced command says otherwise;
- after `close`, recompute effective exposure and warn if the traffic remains allowed elsewhere;
- `show` and `audit` identify the OCI object responsible for every effective rule;
- subnet-wide mutations belong in an advanced namespace and must never be a convenience default.

### No anti-reclamation abuse

Never generate artificial CPU, memory, or network activity merely to avoid OCI idle reclamation. The tool may detect and explain reclamation risk.

### Credentials

Private API keys are secrets.

- never log private key material;
- never upload credentials to GitHub;
- make file permissions as restrictive as the host platform reasonably supports;
- redact sensitive configuration in diagnostics;
- support existing OCI-style config where practical, but do not require the official OCI CLI;
- use HTTPS and OCI request signing directly from Rust.

## Architecture

Keep dependency direction simple:

```text
CLI / interactive UX
        |
        v
Application commands
        |
        +-----------> Network planner
        |
        +-----------> Free policy engine
        |                 |
        |                 +--> live shape metadata
        |                 +--> live service limits
        |                 +--> live usage/cost
        |                 +--> conservative policy snapshot
        |
        v
OCI service adapters
        |
        v
Signed HTTPS transport
```

Suggested modules as implementation grows:

```text
src/
  main.rs
  cli.rs
  config/
  auth/
    signer.rs
  oci/
    client.rs
    identity.rs
    compute.rs
    network.rs
    block_storage.rs
    limits.rs
    usage.rs
    monitoring.rs
  domain/
    free.rs
    network.rs
    instance.rs
    plan.rs
  policy/
    engine.rs
    snapshot.rs
  commands/
    status.rs
    doctor.rs
    account.rs
    free.rs
    vm.rs
    network.rs
    cost.rs
  output/
    human.rs
    json.rs
  interactive/
```

Do not create a large generic abstraction hierarchy before real OCI endpoints require it.

## Initial command surface

Preserve and evolve this user-facing shape:

```text
oci-free status
oci-free doctor
oci-free cost

oci-free account info
oci-free account limits
oci-free account usage

oci-free free list
oci-free policy explain <resource>

oci-free vm list
oci-free vm info <instance>
oci-free vm create
oci-free vm delete <instance>
oci-free vm start <instance>
oci-free vm stop <instance>
oci-free vm reboot <instance>
oci-free vm ip <instance>
oci-free vm ssh <instance>

oci-free vm net <instance> show
oci-free vm net <instance> audit
oci-free vm net <instance> open 443/tcp
oci-free vm net <instance> close 443/tcp
```

Interactive `vm create` should dynamically discover current choices and recommend safe defaults instead of making the user know availability domains, image OCIDs, subnet OCIDs, or current Free Tier shape names.

A later non-interactive selector may support semantic choices such as `free:x86` and `free:arm`, resolved from live OCI metadata rather than aliases permanently tied to a specific shape name.

## Smart UX requirements

The CLI should reduce OCI vocabulary when possible but never hide important consequences.

Examples:

- resolve instance name to OCID automatically, while detecting ambiguity;
- choose the home region automatically for Free Tier operations;
- discover the newest compatible platform image instead of asking for an image OCID;
- create or reuse an `oci-free` managed VCN/subnet/IGW/route setup through an explicit plan;
- create one managed NSG per instance;
- offer SSH ingress choices such as current public IP, any IPv4, custom CIDR, or disabled;
- show a final SSH command and public IP after creation;
- make destructive cleanup explicit, including boot volume, ephemeral public IP, and managed NSG behavior;
- support `--json` for stable automation output;
- errors should include what failed, why it matters, and the next corrective action.

Do not add a full-screen TUI until the CLI workflows are mature and tested. Interactive prompts are sufficient for the first production release.

## OCI implementation phases

### Phase 1: transport and read-only account discovery

Implement and test:

- config loading;
- RSA request signing compatible with OCI REST authentication;
- endpoint construction by region/service;
- retries for safe idempotent reads;
- pagination;
- tenancy/home-region discovery;
- availability domains;
- list compute instances;
- list shapes and retain live billing classification fields;
- service limit/usage reads;
- usage/cost reads where permissions permit.

`status`, `doctor`, `account`, `free list`, `policy explain`, and `vm list/info` should become useful before write operations are introduced.

### Phase 2: safe network inspection

Implement read-only effective network analysis first:

- VNIC and subnet resolution;
- attached NSGs;
- NSG rules;
- subnet Security Lists;
- route and public IP state;
- `vm net show`;
- `vm net audit`.

Represent provenance for each effective allow rule.

### Phase 3: managed networking writes

Implement:

- managed VCN initialization through a plan;
- per-instance managed NSG creation and attachment;
- open/close instance rules;
- effective-exposure verification after every mutation.

### Phase 4: compute lifecycle

Implement:

- dynamic free-eligible shape selection;
- compatible current platform-image discovery;
- create preflight;
- instance launch;
- start/stop/reboot;
- safe terminate and optional cleanup;
- public IP and SSH helper.

### Phase 5: production hardening

Add:

- stable JSON schemas;
- fixture-based OCI response tests;
- signer conformance tests;
- retry/idempotency tests;
- redaction tests;
- policy snapshot provenance/update mechanism;
- comprehensive docs;
- release automation;
- shell and PowerShell installers.

## Testing rules

No write-path feature is complete without tests for the plan and safety decision independently of the live OCI call.

Prefer:

- pure unit tests for policy and network calculations;
- JSON fixtures for OCI response mapping;
- deterministic signer vectors;
- mocked HTTP integration tests;
- optional live read-only tests behind an explicit environment flag;
- no live destructive test in normal CI.

CI must keep these gates green:

```console
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## Dependencies

Prefer mature, focused crates. Keep the binary native and self-contained. Expected categories include:

- `clap` for CLI parsing;
- `serde` / `serde_json` for protocol models;
- `reqwest` with rustls for HTTPS;
- `tokio` for async I/O;
- `ring` for RSA-SHA256 request signing, and RustCrypto crates for the SHA-256 and MD5 digests OCI's protocol requires;
- a small terminal prompt crate only when interactive flows need it.

Avoid OpenSSL system dependencies unless there is a strong reason. Avoid Python, Node.js, Java, or the official OCI CLI as runtime dependencies.

## Release requirements

Use `cargo-dist` as the default release system unless a concrete limitation appears. `dist-workspace.toml` is already present.

Before the first public release:

1. install the pinned cargo-dist version;
2. run `dist init` and review the generated GitHub Actions workflow;
3. commit the generated release workflow;
4. verify build/install on Windows x86_64, Linux x86_64, Linux ARM64, macOS Intel, and macOS Apple Silicon;
5. make tagged releases produce archives, checksums/attestations where supported, a shell installer, and a PowerShell installer;
6. document exact one-line installation commands in the README.

Do not publish a release claiming OCI management functionality while commands still only return scaffold placeholders.

## Definition of the first useful release

A first release candidate is useful when a new user with an OCI API key can:

1. initialize configuration without installing Python or OCI CLI;
2. run `doctor` successfully;
3. inspect account, limits, Free Tier evidence, instances, cost, and effective networking;
4. interactively create a verified free-eligible VM in the home region;
5. manage ingress on that VM only through its managed NSG;
6. SSH to the VM;
7. terminate it with clear cleanup choices;
8. install `oci-free` on all supported platforms from GitHub Releases.

Keep the project English-only: code, comments, identifiers, docs, errors, prompts, commit messages, release notes, and issue/PR text should all be English.

## Agent branch and pull request workflow

This repository uses protected `main` plus external review as the normal development gate. Claude Code, including Claude Code on the web, must follow this workflow for every implementation task unless the user explicitly overrides it.

### Branch discipline

- Treat `main` as protected and read-only.
- Start each task from the latest `main`.
- Work only on a dedicated task branch. One task should normally produce one branch and one pull request.
- Never push directly to `main`.
- Never force-push `main` or bypass repository rules, required checks, or review gates.
- Keep changes narrowly scoped. Do not mix unrelated refactors, dependency upgrades, formatting churn, or cleanup into the same pull request.
- Do not rewrite another agent's or contributor's branch unless explicitly asked.

### Required local validation before handoff

Before declaring implementation complete, run all of the following from the repository root:

```console
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build
```

If a required check fails because of the task's changes, fix the underlying issue rather than weakening, skipping, or deleting the check. If a failure is unrelated to the task, document it explicitly in the pull request instead of silently ignoring it.

### Pull request handoff

When the task is ready for review:

1. push the task branch;
2. open a pull request targeting `main`;
3. use a concise English title that describes the resulting change;
4. summarize the implementation, relevant design decisions, tests run, safety impact, and any known limitations;
5. keep the pull request open for external review;
6. do not merge the pull request yourself;
7. do not self-approve as a substitute for external review.

The repository's required GitHub Actions checks are authoritative. A task is not ready to merge while a required check is pending or failing.

### Review and auto-fix loop

When CI fails or an external reviewer requests changes:

- inspect the failure or review comment before editing;
- make the smallest correct fix on the existing pull request branch;
- do not broaden scope merely because additional cleanup is convenient;
- rerun the required local checks before pushing;
- push the fix to the same pull request and leave it open for re-review;
- address review threads substantively before marking them resolved;
- if a requested change conflicts with this contract, a hard safety invariant, or requires a product/design decision, stop and ask the user instead of guessing.

Claude Code Web auto-fix may respond to CI failures and review feedback, but it must obey the same scope, validation, and no-merge rules.

### Secrets and live OCI access in agent environments

- Do not request, commit, or persist OCI private keys, GitHub tokens, or other long-lived credentials in the repository.
- Do not add secrets to test fixtures, logs, pull request text, or diagnostics.
- Normal CI must remain credential-free and must not perform destructive live OCI operations.
- Live OCI tests, when introduced, must be explicitly opt-in and read-only unless the user deliberately authorizes a separate controlled test environment.

The intended responsibility split is: Claude Code implements and updates the pull request; GitHub Actions validates it; an external reviewer reviews and merges it.
