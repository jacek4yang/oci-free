# oci-free

A smart, free-first, safety-focused command-line manager for Oracle Cloud Infrastructure Free Tier accounts.

> Status: early development preview. Configuration loading, OCI request signing, and `oci-free doctor` are implemented; every command that talks to a live OCI endpoint is still a scaffold. The distribution pipeline may be release-ready before the OCI management feature set is complete.

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

`oci-free` reads the standard `~/.oci/config` file and its API signing key, but it does not require the OCI CLI, Python, or Node.js. Once a profile exists, check it:

```console
$ oci-free doctor
[     ok] Configuration: loaded profile [DEFAULT] of /home/me/.oci/config for region us-ashburn-1
[     ok] Private key: loaded an RSA private key from /home/me/.oci/oci_api_key.pem
[     ok] Key fingerprint: the private key matches the configured fingerprint 8d:54:...:8c
[     ok] Request signing: signed and verified a test request
[skipped] Live OCI verification: not implemented yet; doctor currently validates local configuration only
```

`doctor` exits non-zero when the configuration is not usable and names the next corrective action for every failure. See [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) for the file format, the supported environment variables, and what is redacted from diagnostics.

## Installation

`oci-free` is distributed as a single native executable. End users do not need Rust, Cargo, Python, Node.js, Java, or the official OCI CLI.

**macOS and Linux**

For a published version, download and run the version-pinned installer:

```console
VERSION=v0.1.0-preview.1
curl --proto '=https' --tlsv1.2 -LsSf "https://github.com/jacek4yang/oci-free/releases/download/${VERSION}/oci-free-installer.sh" | sh
```

**Windows**

For a published version, use the version-pinned PowerShell installer:

```powershell
$Version = "v0.1.0-preview.1"
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

A resource is not considered safe to create merely because a tutorial says it is free. The policy engine should gather evidence from OCI and classify a planned operation as one of:

- `VerifiedAlwaysFree`
- `LimitedFree`
- `Paid`
- `Unknown`

Only `VerifiedAlwaysFree` is allowed by default. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/SECURITY.md`](docs/SECURITY.md).

## Development

The project is written in Rust 2024 edition and is designed to produce a single native binary with no Python, Node.js, or official OCI CLI runtime dependency.

```console
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo run -- --help
```

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
