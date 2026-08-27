# oci-free

A smart, free-first, safety-focused command-line manager for Oracle Cloud Infrastructure Free Tier accounts.

> Status: early scaffold. The repository intentionally starts with a small, auditable core and a detailed product/architecture contract for agent-assisted development.

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

## Distribution target

The planned release matrix is:

- Windows x86_64
- Linux x86_64
- Linux ARM64
- macOS x86_64
- macOS Apple Silicon

The repository includes `cargo-dist` configuration so tagged releases can eventually publish archives plus shell and PowerShell installers.

## License

MIT. See [`LICENSE`](LICENSE).
