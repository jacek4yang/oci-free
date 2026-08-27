# Release Process

`oci-free` is distributed as prebuilt native binaries through GitHub Releases.
[cargo-dist](https://axodotdev.github.io/cargo-dist) owns the entire pipeline:
`dist-workspace.toml` is the source of truth, and
`.github/workflows/release.yml` is generated from it and must never be edited by
hand.

For installing a release, see [`docs/INSTALLATION.md`](INSTALLATION.md).

## What a release contains

Running `dist plan` prints the exact asset list. For version `X.Y.Z`:

| Asset | Purpose |
| --- | --- |
| `oci-free-x86_64-pc-windows-msvc.msi` | Windows offline installer, adds to `PATH`, upgrades and uninstalls |
| `oci-free-x86_64-pc-windows-msvc.zip` | Windows binary archive |
| `oci-free-x86_64-unknown-linux-gnu.tar.xz` | Linux x86_64 binary archive |
| `oci-free-aarch64-unknown-linux-gnu.tar.xz` | Linux ARM64 binary archive |
| `oci-free-x86_64-apple-darwin.tar.xz` | macOS Intel binary archive |
| `oci-free-aarch64-apple-darwin.tar.xz` | macOS Apple Silicon binary archive |
| `oci-free-installer.sh` | Online installer for macOS and Linux |
| `oci-free-installer.ps1` | Online installer for Windows PowerShell |
| `source.tar.gz` | Source snapshot |
| `<archive>.sha256` | SHA-256 sidecar for each native binary archive |

Each native binary archive contains exactly the executable, `LICENSE`, and `README.md`. The
release smoke test asserts that, so an accidental extra file fails CI rather
than shipping.

## Build matrix

Every target is built natively on a GitHub-hosted runner. Nothing is
cross-compiled.

| Target | Runner |
| --- | --- |
| `aarch64-apple-darwin` | `macos-14` |
| `x86_64-apple-darwin` | `macos-15-intel` |
| `x86_64-pc-windows-msvc` | `windows-2022` |
| `x86_64-unknown-linux-gnu` | `ubuntu-22.04` |
| `aarch64-unknown-linux-gnu` | `ubuntu-22.04-arm` |

## How the pipeline is wired

```text
git tag vX.Y.Z  ──►  Release workflow
                       │
                       ├─ plan            dist plan: asset list, config coherence
                       ├─ build-local     one job per target: binaries, archives, MSI
                       │                  each job attests its own artifacts
                       ├─ build-global    shell + PowerShell installers, checksums
                       ├─ host            uploads and creates the GitHub Release
                       └─ announce
```

`host` runs only when `plan`, `build-local-artifacts`, and
`build-global-artifacts` all succeeded, so a single failing platform blocks the
whole release instead of publishing a partial one.

## Pre-tag validation

Release infrastructure is testable before any tag exists.

- **Every pull request** runs the Release workflow in `pr-run-mode = "upload"`.
  It runs `dist plan` (which also fails if `release.yml` or `wix/main.wxs` are
  out of sync with `dist-workspace.toml`), builds all five targets and the MSI,
  and uploads them as workflow artifacts. It never creates a GitHub Release:
  the `host` job is gated on `!github.event.pull_request`.
- **Pull requests touching release infrastructure** additionally run the
  Release smoke test workflow, which installs the MSI on a Windows runner,
  checks `PATH` integration from a new process, uninstalls it, and runs each
  Unix binary.
- **Any time**, a maintainer can run the Release smoke test workflow manually
  from the Actions tab.

## Versioning and prerelease policy

The package is versioned `1.0.0`: the v1 command surface is implemented, the
JSON contract and exit codes are stable, and the offline suite covers them.

**The `v1.0.0` tag must not be pushed until
[`LIVE-VALIDATION.md`](LIVE-VALIDATION.md) has been worked through against a
real Free Tier tenancy and the results recorded.** A stable tag makes the
`releases/latest` installer URLs point at that build, and a binary that can
create and delete cloud resources but has never made a real API call is not
something to put behind `latest`.

If a build is wanted before that, cut a prerelease instead: set the version to
`1.0.0-rc.1`, which cargo-dist marks as a GitHub prerelease and keeps out of
`releases/latest`. The version in `Cargo.toml` and the tag must match, which the
release smoke test verifies by comparing `oci-free --version` against
`Cargo.toml`.

| Version and tag | Meaning |
| --- | --- |
| `1.0.0-rc.1` | Release candidate: the commands exist and the offline suite is green, the live checklist is not complete. |
| `1.0.0` | Stable: the live checklist has been completed and recorded. |

## Cutting a release

Nothing here happens automatically. Pushing the tag is the only irreversible
step.

1. **Green main.** CI passes on `main`.

2. **Lockfile committed and current.**

   ```console
   cargo fetch --locked
   ```

   Release builds run this too, so a stale `Cargo.lock` fails the release.

3. **Verify the dist configuration.** With the pinned version from
   `dist-workspace.toml` installed:

   ```console
   dist --version          # must match cargo-dist-version
   dist generate --check   # generated CI and wix/main.wxs are in sync
   dist plan               # every expected asset is listed
   ```

   If `dist generate --check` fails, run `dist init --yes` and commit the
   regenerated files in their own pull request.

4. **Decide the version.** Set `version` in `Cargo.toml`, following the
   prerelease policy above. Run `cargo build --locked` so `Cargo.lock` picks up
   the new version, and merge that through a pull request.

5. **Run the smoke test.** Trigger the Release smoke test workflow on `main`
   from the Actions tab and wait for it to pass on all five platforms.

6. **Tag and push.** This is the point of no return:

   ```console
   git checkout main && git pull
   git tag v1.0.0
   git push origin v1.0.0
   ```

7. **Watch the release run** in the Actions tab. If a platform fails, the
   release is not published; fix it and tag a new version rather than reusing
   the tag.

8. **Verify the assets.** The release page must list every asset from the table
   above, including the MSI and both installers.

9. **Test the published installers** on real machines: the MSI on Windows
   (install, `oci-free --version` in a new terminal, uninstall), and the shell
   installer on macOS or Linux. The shell and PowerShell installers download
   from the release, so this step can only be done after the release exists.

10. **Verify provenance.**

    ```console
    shasum -a 256 -c oci-free-x86_64-unknown-linux-gnu.tar.xz.sha256
    gh attestation verify oci-free-x86_64-unknown-linux-gnu.tar.xz --repo jacek4yang/oci-free
    ```

11. **Promote.** Confirm the release is marked prerelease while the CLI is still
    a preview. Only mark a release as latest once it is genuinely a stable tag.

## Signing status

Release artifacts are **not** code signed.

- Windows binaries and the MSI are **not Authenticode signed**. SmartScreen may
  warn on first run.
- macOS binaries are **not Developer ID signed and not notarised**. Gatekeeper
  may refuse a browser-downloaded binary until its quarantine attribute is
  cleared.
- Every native binary archive has a SHA-256 sidecar, and release artifacts are
  covered by GitHub artifact attestations.

Attestations record which workflow, commit, and repository produced an artifact.
That is supply-chain provenance; it is a different thing from Authenticode or
Apple notarisation and does not stop the operating system warnings above. Do not
describe these artifacts as signed.

Adding real code signing later does not require redesigning the pipeline.
cargo-dist has `ssldotcom-windows-sign` and `macos-sign` options that slot into
`dist-workspace.toml` and read credentials from GitHub Actions secrets. Signing
material must be supplied that way — never pasted into source, commits, pull
request text, or ordinary environment variables.

## Never in a release artifact

The release pipeline requires no OCI credentials and performs no OCI API calls.
Archives contain only the executable, `LICENSE`, and `README.md`; test fixtures
are never packaged. The smoke test asserts the exact file list on every
platform.

One known residue: Rust embeds the source paths of dependency crates into panic
messages, so strings such as
`/home/runner/.cargo/registry/src/index.crates.io-*/clap-*/src/...` appear in the
binaries. Those are ephemeral CI runner paths that expose no developer or secret
information. Cargo's `trim-paths` profile option would remove them but is not
stable in the toolchain this project targets.
