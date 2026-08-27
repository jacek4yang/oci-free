# Release Process

The project uses `cargo-dist` configuration from `dist-workspace.toml` as the intended release system.

## Supported release targets

- Windows x86_64 (`x86_64-pc-windows-msvc`)
- Linux x86_64 (`x86_64-unknown-linux-gnu`)
- Linux ARM64 (`aarch64-unknown-linux-gnu`)
- macOS x86_64 (`x86_64-apple-darwin`)
- macOS Apple Silicon (`aarch64-apple-darwin`)

## Before the first release

Install the cargo-dist version pinned in `dist-workspace.toml`, then run:

```console
dist init
```

Review and commit the generated GitHub Actions release workflow. Do not blindly regenerate it during unrelated changes.

The first public release must verify that generated shell and PowerShell installers install the expected binary and that `oci-free --version` works on every supported target.

## Versioning

Use semantic version tags such as:

```text
v0.1.0
v0.1.0-rc.1
```

Release candidates are appropriate until the core read/write OCI workflows and billing guards have been exercised against a real Free Tier tenancy.

## Release gate

Do not publish a release as functionally complete while the command still returns scaffold placeholder output. The minimum useful release criteria are maintained in `CLAUDE.md`.
