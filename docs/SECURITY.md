# Security Model

`oci-free` manages cloud resources and therefore treats billing safety, credential handling, and network exposure as security properties.

## Credentials

- API private keys must remain local and must never be logged.
- Diagnostics must redact secrets and sensitive configuration values.
- Credential files should use restrictive host permissions where the platform supports them.
- The project must not require the official OCI CLI, Python, Node.js, or Java at runtime.

## Billing safety

Strict mode fails closed. A resource that cannot be proven Always Free is blocked by default. Every potentially billable mutation requires a preflight assessment and explicit confirmation in interactive mode.

A non-zero current-period OCI cost is always surfaced prominently.

## Network safety

Normal ingress changes are instance-scoped and implemented with a managed Network Security Group attached to the target instance VNIC.

Effective exposure must account for both NSGs and subnet Security Lists. Removing an NSG rule is not reported as "closed" until the effective policy is recomputed.

## Destructive operations

Termination and cleanup commands must distinguish the instance from related resources such as boot volumes, reserved public IPs, and managed NSGs. The user should see exactly which resources will be deleted, retained, or released before confirmation.

## Release artifact integrity

Release binaries are built by GitHub Actions from a tagged commit, using the
`cargo-dist` version pinned in `dist-workspace.toml` and the committed
`Cargo.lock`. The release pipeline needs no OCI credentials and makes no OCI API
calls.

Each native binary archive ships with a SHA-256 sidecar. Release artifacts also
carry GitHub artifact attestations recording the workflow, commit, and repository
that produced them.

Artifacts are **not** Windows Authenticode signed and **not** Apple Developer ID
signed or notarised. Attestations are supply-chain provenance and are not a
substitute for either; the operating system will still warn on first run. See
[`RELEASE.md`](RELEASE.md#signing-status).

## Dependency advisories

`cargo audit` is run before each handoff. Advisories are recorded here with a
threat-model assessment rather than silently accepted or suppressed.

### RUSTSEC-2023-0071 — `rsa` 0.9.10, Marvin attack (medium, 5.9)

**Status: open. No fixed release of the `rsa` crate exists.**

The advisory describes a timing side-channel in RSA private-key operations. An
attacker who can submit many chosen inputs for private-key operations *and*
measure the timing of each response can, over many samples, recover the key.

How `oci-free` uses the key bounds the exposure:

- the key is used only to sign outbound requests, never to decrypt;
- the signed message is a request line, host, date, and body digest that
  `oci-free` constructs itself, so a remote party cannot choose it;
- signing happens locally and only the resulting signature is transmitted, so
  no remote party observes the timing of the operation.

There is therefore no remote timing oracle. The residual risk is a local
attacker who can measure this process's timing precisely — an attacker who can
generally just read the key file directly.

Assessment: **not exploitable in this product's threat model, but it does block
a stable 1.0.0.** Shipping a known medium crypto advisory in a stable release
should be a deliberate decision, not an inherited default.

Resolution path, in preference order:

1. Migrate the signer to `ring`'s `RsaKeyPair` (RSA PKCS#1 v1.5 SHA-256). Ring
   is already in the dependency graph via rustls, and is constant-time
   hardened. Cost: PEM/DER handling and SPKI encoding for the fingerprint move
   into our code, and the signer is the most safety-critical tested component,
   so the migration needs its existing conformance vectors kept green.
2. Adopt a fixed `rsa` release if one appears.

Note that CLAUDE.md currently specifies RustCrypto for signing, so option 1 is
a contract change and needs the maintainer's agreement.

### RUSTSEC-2026-0009 — `time` 0.3.45, stack exhaustion (medium, 6.8)

**Status: does not affect the shipped binary.**

`time` enters the dependency graph only through `rcgen`, which is a
dev-dependency used to generate a self-signed certificate for the in-process
HTTPS test server. `cargo tree --no-dev-dependencies` shows no `time` in the
release graph, so no released artifact contains the affected code.

The fixed version, 0.3.47, requires Rust 1.88 while this package declares an
MSRV of 1.85. Raising the MSRV to silence an advisory that cannot reach users
would be the wrong trade, so the dependency is left as it is and re-checked
whenever the MSRV moves for another reason.

## Reporting vulnerabilities

Until a dedicated private security reporting channel is configured, do not publish credentials, tenancy identifiers, or exploitable secrets in public issues. Use GitHub's private vulnerability reporting feature once enabled for the repository.
