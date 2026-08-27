# oci-free

A smart, free-first, safety-focused command-line manager for Oracle Cloud Infrastructure Free Tier accounts.

> Status: the v1 command surface is implemented and covered by tests. It has
> not yet been validated against a live OCI tenancy — see
> [`docs/LIVE-VALIDATION.md`](docs/LIVE-VALIDATION.md) for the checklist that
> closes that gap, and [Current capability](#current-capability) below.

## Goals

`oci-free` is not a general-purpose OCI SDK or a clone of the official OCI CLI. It is an opinionated manager for users who primarily want to stay inside OCI Free Tier while keeping compute, networking, storage, usage, and cost easy to understand.

The default operating mode is **strict free-first**:

- discover free-eligible compute dynamically from OCI whenever the API exposes machine-readable billing metadata;
- combine live service limits, current usage, and conservative policy evidence before mutation;
- treat `UNKNOWN`, `LIMITED_FREE`, and `PAID` resources as blocked by default;
- run a preflight plan before every potentially billable create/resize/attach operation;
- prefer per-instance Network Security Groups over subnet-wide ingress rules;
- explain effective exposure when Security Lists and NSGs overlap;
- never silently create load, traffic, or resources to avoid idle reclamation;
- surface non-zero cost as a first-class warning.

## Intended UX

```console
$ oci-free status
$ oci-free doctor
$ oci-free free list
$ oci-free vm create
$ oci-free vm list
$ oci-free vm info oracle-01
$ oci-free vm ssh oracle-01
$ oci-free vm net oracle-01 show
$ oci-free vm net oracle-01 open 443/tcp
$ oci-free vm net oracle-01 audit
$ oci-free cost
```

Interactive commands should guide the user through safe choices. Non-interactive flags should remain available for automation.

## Getting started

`oci-free` reads the standard `~/.oci/config` file and its API signing key, but
it does not require the OCI CLI, Python, Node.js, or OpenSSL. Create an API key
in the OCI Console, then:

```console
$ oci-free config init
$ oci-free doctor
[     ok] Configuration: loaded profile [DEFAULT] of /home/me/.oci/config for region us-ashburn-1
[     ok] Private key: loaded an RSA private key from /home/me/.oci/oci_api_key.pem
[     ok] Key fingerprint: the private key matches the configured fingerprint 8d:54:...:8c
[     ok] Request signing: signed and verified a test request as ocid1.tenancy.oc1..…xk3q7a/...
[     ok] Signed authentication: OCI accepted the request signature
[     ok] Tenancy access: read tenancy ocid1.tenancy.oc1..…xk3q7a (example-tenancy)
[     ok] Home region: this profile targets the home region us-ashburn-1
[     ok] Availability domains: 3 domain(s) available: Uocm:US-ASHBURN-AD-1, ...
[     ok] Compute read permission: listed 2 instance(s)
[     ok] Networking read permission: listed 1 VCN(s)
[warning] Usage and cost permission: this tenancy does not grant the Usage API, so
          `oci-free cost` will report cost as unavailable rather than as zero
          next: optional: `allow group <g> to read usage-report in tenancy`
```

`doctor` exits non-zero when the setup is not usable, and names the next
corrective action for every failure. A missing **optional** capability is a
warning, not a failure — a Free Tier tenancy routinely lacks the Usage API
grant, and failing over it would teach users that a red `doctor` is normal.

See [`docs/QUICKSTART.md`](docs/QUICKSTART.md) to go from nothing to a running
VM, and [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) for the file format,
the supported environment variables, and what is redacted from diagnostics.

## Current capability

Every command in the v1 surface is implemented. There is no placeholder path: a
command that cannot do its job reports a classified failure with a next action,
never a success-shaped result.

| Command | What it does |
| --- | --- |
| `oci-free config init` / `show` | Write a profile with validation; show the configuration in use, redacted. |
| `oci-free doctor` | Local checks, then read-only live checks naming the IAM grant behind each capability. |
| `oci-free status` | Account, instances, free capacity, cost, and exposure in one screen, degrading section by section. |
| `oci-free cost` | Billing-period spend. Unavailable is reported as unavailable, never as `0.00`. |
| `oci-free account info` / `limits` / `usage` | Tenancy and home region; Free Tier-relevant limits with usage; consumption by service. |
| `oci-free free list` | Allowances, live `billingType`, current usage, remaining capacity, blockers. |
| `oci-free policy explain` | The whole evidence chain behind an allow or block. |
| `oci-free vm list` / `info` / `ip` | Instances, one instance in full, and addresses. |
| `oci-free vm create` | Discovery, capacity check, plan, confirmation, launch, then NSG and exposure verification. |
| `oci-free vm delete` | Ownership-proven cleanup with an explicit boot-volume choice. |
| `oci-free vm start` / `stop` / `reboot` | Lifecycle, with the current state validated first. |
| `oci-free vm ssh` | Connect using discovered details, via argv rather than a shell string. |
| `oci-free vm net show` / `audit` | Effective exposure with provenance, and explainable findings. |
| `oci-free vm net open` / `close` | Instance-scoped ingress, verified against a fresh read afterwards. |

What is **not** here, deliberately: API key generation (the OCI Console does it
in one step with no local toolchain), subnet-wide Security List edits (they
affect every instance in the subnet, so they belong in the Console), and any
form of activity generation to defeat idle reclamation.

Not yet done: validation against a live OCI tenancy. See
[`docs/LIVE-VALIDATION.md`](docs/LIVE-VALIDATION.md).

## Documentation

| Document | Contents |
| --- | --- |
| [`QUICKSTART.md`](docs/QUICKSTART.md) | Nothing to a running VM you can SSH into. |
| [`COMMANDS.md`](docs/COMMANDS.md) | Every command, and the stable exit codes. |
| [`CONFIGURATION.md`](docs/CONFIGURATION.md) | Profiles, environment variables, redaction. |
| [`FREE-TIER-SAFETY.md`](docs/FREE-TIER-SAFETY.md) | How "is this free?" is decided, and why unknown blocks. |
| [`NETWORKING.md`](docs/NETWORKING.md) | Why an NSG rule is not the whole story. |
| [`JSON.md`](docs/JSON.md) | The `--json` contract, field by field. |
| [`TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | Error by error, with the next action. |
| [`ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Layers, dependency direction, testing strategy. |
| [`SECURITY.md`](docs/SECURITY.md) | Threat model, credential handling, dependency advisories. |
| [`LIVE-VALIDATION.md`](docs/LIVE-VALIDATION.md) | What CI cannot prove, and the checklist that does. |
| [`INSTALLATION.md`](docs/INSTALLATION.md) | Every platform, online and offline. |
| [`RELEASE.md`](docs/RELEASE.md) | How a release is built and verified. |

## Installation

`oci-free` is distributed as a single native executable. End users do not need Rust, Cargo, Python, Node.js, Java, or the official OCI CLI.

**macOS and Linux**

For a published version, download and run the version-pinned installer:

```console
VERSION=v1.0.0
curl --proto '=https' --tlsv1.2 -LsSf "https://github.com/jacek4yang/oci-free/releases/download/${VERSION}/oci-free-installer.sh" | sh
```

**Windows**

For a published version, use the version-pinned PowerShell installer:

```powershell
$Version = "v1.0.0"
irm "https://github.com/jacek4yang/oci-free/releases/download/$Version/oci-free-installer.ps1" | iex
```

For offline Windows installation, download `oci-free-x86_64-pc-windows-msvc.msi` from the same GitHub Release and double-click it. The MSI installs the native executable under Program Files, integrates it with `PATH` by default, supports upgrades, and can be removed from Windows installed-app management.

Every supported platform also has a plain binary archive for offline transfer:

| Machine | Offline artifact |
| --- | --- |
| Windows x86_64 | `oci-free-x86_64-pc-windows-msvc.zip` or the `.msi` |
| macOS Apple Silicon | `oci-free-aarch64-apple-darwin.tar.xz` |
| macOS Intel | `oci-free-x86_64-apple-darwin.tar.xz` |
| Linux x86_64 | `oci-free-x86_64-unknown-linux-gnu.tar.xz` |
| Linux ARM64 | `oci-free-aarch64-unknown-linux-gnu.tar.xz` |

Archive artifacts have SHA-256 checksum sidecars and release artifacts have GitHub artifact attestations. Windows artifacts are not Authenticode signed and macOS artifacts are not Apple Developer ID signed or notarized, so operating-system warnings are expected for preview builds.

Once the project publishes a stable, non-prerelease release, the equivalent `/releases/latest/download/...` installer URLs can be used. GitHub intentionally excludes prereleases from `releases/latest`.

See [`docs/INSTALLATION.md`](docs/INSTALLATION.md) for detailed online, offline, PATH, verification, and uninstall instructions.

## Safety model

A resource is not safe to create merely because a tutorial says it is free. The
policy engine gathers evidence from OCI and classifies every planned operation
as `VerifiedAlwaysFree`, `LimitedFree`, `Paid`, or `Unknown`. Only the first is
permitted; `Unknown` blocks, which is the entire point.

Three properties are enforced structurally rather than by convention:

- **A write cannot bypass its plan.** Every write helper takes an `Approval`,
  and only `MutationPlan::approve` can mint one — it refuses on a blocker, on
  any billing risk other than `none`, or without an explicit confirmation. A
  write path that skipped the plan would not compile.
- **Ownership is proven from tags, never from a name.** Only a resource
  oci-free created may be deleted. A VCN called `oci-free-vcn` with no ownership
  tag belongs to somebody else and is left alone.
- **An absent rule is not a closed port.** NSG and Security List rules compose,
  so every effective rule carries the OCI object responsible for it, and `close`
  re-reads the state and reports what still allows the port.

See [`docs/FREE-TIER-SAFETY.md`](docs/FREE-TIER-SAFETY.md),
[`docs/NETWORKING.md`](docs/NETWORKING.md), and
[`docs/SECURITY.md`](docs/SECURITY.md).

## Development

The project is written in Rust 2024 edition and is designed to produce a single native binary with no Python, Node.js, or official OCI CLI runtime dependency.

```console
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo run -- --help
```

The test suite is offline and credential-free: it runs against an in-process
HTTPS server that exercises the real transport, so no test touches a network or
needs an OCI account.

Development priorities and agent instructions are in [`CLAUDE.md`](CLAUDE.md).

## Distribution

The release matrix is:

- Windows x86_64 (`x86_64-pc-windows-msvc`)
- Linux x86_64 (`x86_64-unknown-linux-gnu`)
- Linux ARM64 (`aarch64-unknown-linux-gnu`)
- macOS Intel (`x86_64-apple-darwin`)
- macOS Apple Silicon (`aarch64-apple-darwin`)

`cargo-dist` generates the release workflow, native archives, shell and PowerShell installers, and the Windows MSI. Release infrastructure is validated on pull requests before any tag is published.

## License

MIT. See [`LICENSE`](LICENSE).
