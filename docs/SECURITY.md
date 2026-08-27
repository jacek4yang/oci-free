# Security Model

`oci-free` manages cloud resources and therefore treats billing safety, credential handling, and network exposure as security properties.

## Credentials

- API private keys must remain local and must never be logged.
- Diagnostics must redact secrets and sensitive configuration values.
- Credential files should use restrictive host permissions where the platform supports them.
- The project must not require the official OCI CLI, Python, Node.js, or Java at runtime.

## Signed-request destinations

Endpoint resolution is allowlisted and rule-driven. OCI services select an
explicit, reviewed hostname style for each known realm; an unknown or
unverified realm/service convention is refused before a request is signed or
sent. `oci-free` never discovers a signed-request destination by guessing DNS
names or following redirects.

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

`cargo audit` runs in CI on every pull request and push, and again before each
handoff. Advisories are recorded here with a threat-model assessment rather
than silently accepted or suppressed. An advisory is only left open when it
provably cannot reach a shipped artifact, and the reasoning is written down.

### RUSTSEC-2023-0071 — `rsa`, Marvin attack (medium, 5.9)

**Status: resolved. The `rsa` crate is no longer a dependency.**

The advisory describes a timing side-channel in RSA private-key operations, and
records no patched version — its stated workaround is to avoid the crate where
an attacker can observe timing.

How `oci-free` used the key already bounded the exposure: the key only ever
signed outbound requests, never decrypted; the signed message is a request
line, host, date, and body digest that `oci-free` constructs itself, so a
remote party could not choose it; and signing happens locally with only the
resulting signature transmitted, so no remote party observed the timing. There
was no remote timing oracle.

That analysis made the advisory unlikely to be exploitable here, but "unlikely"
is a poor foundation for the one component that handles private key material,
and a stable 1.0 should not inherit a known medium crypto advisory by default.

The signer therefore runs on `ring`'s `RsaKeyPair` (RSASSA-PKCS1-v1_5 over
SHA-256), which was already in the dependency graph as rustls's crypto
provider. The migration **removed** a dependency rather than adding one.

Two capabilities moved into this codebase as a result, both narrow and both
tested:

- **PEM decoding.** `ring` parses PKCS#8 and PKCS#1 DER but not the PEM
  envelope, so `src/auth/key.rs` locates the delimiters and base64-decodes the
  body. Tests cover CRLF line endings, unwrapped bodies, a truncated block, a
  mismatched label, and non-base64 content.
- **SubjectPublicKeyInfo construction.** OCI defines the API key fingerprint as
  the MD5 digest of the DER `SubjectPublicKeyInfo`, while `ring` exposes the
  public key as a PKCS#1 `RSAPublicKey`. The SPKI wrapper is rebuilt in
  `subject_public_key_info`, and pinned by a test against a fingerprint
  computed independently with OpenSSL. The DER length encoder has its own
  boundary tests at 127, 128, 255, 256, and 65535 bytes.

Compatibility is unchanged and covered by the existing conformance vectors:
PKCS#8 and PKCS#1 both load, both produce the same fingerprint, both produce
byte-identical signatures for the same message, and the `Signature` version 1
header is unchanged. MD5 remains in the tree solely to reproduce OCI's
fingerprint identifier and is never used as a security primitive.

`ring` cannot generate RSA keys. Nothing depends on that: `oci-free config
init` does not generate keys either, because the OCI Console's "Add API key"
flow produces the pair, shows the fingerprint, and hands over the private key
in one step with no local toolchain — see `docs/CONFIGURATION.md`.

### `time` — reachable only through a dev-dependency

**Status: does not affect any shipped artifact.**

`time` enters the dependency graph only through `rcgen`, which is a
dev-dependency used to generate a self-signed certificate for the in-process
HTTPS test server. `cargo tree --edges normal` — the graph that is actually
linked into a release binary — contains neither `rcgen` nor `time`, so no
released artifact contains that code under any advisory affecting it.

This is re-checked whenever the dependency graph changes. The MSRV is not
raised to move a dev-only dependency: raising it would narrow the toolchains
contributors can build with to silence something that cannot reach a user.

## Reporting vulnerabilities

Until a dedicated private security reporting channel is configured, do not publish credentials, tenancy identifiers, or exploitable secrets in public issues. Use GitHub's private vulnerability reporting feature once enabled for the repository.
