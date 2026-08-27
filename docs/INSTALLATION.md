# Installation

> `oci-free` is an early development preview. Configuration loading, OCI request
> signing, and `oci-free doctor` work; most OCI management commands still return
> scaffold placeholders. Installing it gives you a working binary, not a
> complete OCI management tool.

`oci-free` is a single native executable. It does not need Rust, Cargo, Python,
Node.js, Java, or the official OCI CLI, either to install or to run.

## Choosing the right build

You do not need to know Rust target triples; pick the row that matches your
machine.

| Your machine | Download |
| --- | --- |
| Windows 11 / 10, Intel or AMD 64-bit | `oci-free-x86_64-pc-windows-msvc.msi` (installer) or `oci-free-x86_64-pc-windows-msvc.zip` (archive) |
| macOS, Apple Silicon (M1 and later) | `oci-free-aarch64-apple-darwin.tar.xz` |
| macOS, Intel | `oci-free-x86_64-apple-darwin.tar.xz` |
| Linux, 64-bit Intel or AMD | `oci-free-x86_64-unknown-linux-gnu.tar.xz` |
| Linux, 64-bit ARM (Ampere, Graviton, Raspberry Pi 64-bit) | `oci-free-aarch64-unknown-linux-gnu.tar.xz` |

Windows on ARM is not built yet. There is no 32-bit build.

On macOS, `uname -m` prints `arm64` for Apple Silicon and `x86_64` for Intel.
On Linux, `uname -m` prints `aarch64` or `x86_64`.

Oracle Cloud Free Tier ARM instances (`VM.Standard.A1.Flex`) run Linux ARM64, so
use `oci-free-aarch64-unknown-linux-gnu.tar.xz` there.

## Online installation

### macOS and Linux

```console
VERSION=v0.1.0-preview.1
curl --proto '=https' --tlsv1.2 -LsSf "https://github.com/jacek4yang/oci-free/releases/download/${VERSION}/oci-free-installer.sh" | sh
```

The installer detects your platform, downloads the matching archive, and
installs `oci-free` into `~/.local/bin`. If that directory is not already on
your `PATH`, the installer adds it to your shell profile and tells you which
file it changed. Open a new terminal afterwards, then:

```console
oci-free --version
```

To install another specific version, change `VERSION` (or use that tag directly):

```console
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/jacek4yang/oci-free/releases/download/v0.1.0/oci-free-installer.sh | sh
```

Useful environment variables:

| Variable | Effect |
| --- | --- |
| `OCI_FREE_INSTALL_DIR` | Install somewhere other than `~/.local/bin` |
| `INSTALLER_NO_MODIFY_PATH=1` | Never touch your shell profile; you manage `PATH` yourself |

### Windows

```console
$Version = "v0.1.0-preview.1"
irm "https://github.com/jacek4yang/oci-free/releases/download/$Version/oci-free-installer.ps1" | iex
```

This installs into `%USERPROFILE%\.local\bin` and adds it to your user `PATH`.
Open a new terminal, then run `oci-free --version`.

For a machine-wide installation that appears in Windows installed-program
management, use the MSI described below instead.

## Offline installation

Every release artifact is a plain file. Download it on a connected machine,
copy it to the target machine by any means, and install it there. Nothing in the
steps below contacts the network.

### Windows, offline, with the MSI

1. On a connected machine, download `oci-free-x86_64-pc-windows-msvc.msi` from
   the release page.
2. Copy it to the offline machine.
3. Double-click the `.msi`.
4. Leave **PATH Environment Variable** selected — it is enabled by default and
   is what makes `oci-free` runnable from any terminal. You can deselect it on
   the customise screen if you prefer to manage `PATH` yourself.
5. Finish the installer. It installs `oci-free.exe` into
   `C:\Program Files\oci-free\bin`.
6. Open a **new** terminal (an already-open one still has the old `PATH`):

   ```console
   oci-free --version
   ```

Installing a newer MSI over an older one upgrades in place. Remove it from
**Settings → Apps → Installed apps**, which also removes the `PATH` entry.

An unattended install is also possible:

```console
msiexec /i oci-free-x86_64-pc-windows-msvc.msi /qn
```

### Windows, offline, with the archive

Prefer this when you cannot install software machine-wide.

1. Download `oci-free-x86_64-pc-windows-msvc.zip`.
2. Extract it. It contains `oci-free.exe`, `LICENSE`, and `README.md`.
3. Move `oci-free.exe` somewhere permanent, for example
   `%USERPROFILE%\.local\bin`.
4. Add that directory to your user `PATH`:

   ```console
   powershell -c "[Environment]::SetEnvironmentVariable('Path', [Environment]::GetEnvironmentVariable('Path','User') + ';' + \"$env:USERPROFILE\.local\bin\", 'User')"
   ```

5. Open a new terminal and run `oci-free --version`.

### macOS and Linux, offline

1. Download the archive for your platform from the table above.
2. Copy it to the offline machine and extract it:

   ```console
   tar -xf oci-free-x86_64-unknown-linux-gnu.tar.xz
   ```

   The archive expands into a directory containing `oci-free`, `LICENSE`, and
   `README.md`.

3. Install the binary into your user-level bin directory. No `sudo` is needed —
   `~/.local/bin` belongs to you:

   ```console
   mkdir -p ~/.local/bin
   install -m 755 oci-free-x86_64-unknown-linux-gnu/oci-free ~/.local/bin/oci-free
   ```

4. Check whether `~/.local/bin` is already on your `PATH`:

   ```console
   case ":$PATH:" in *":$HOME/.local/bin:"*) echo "already on PATH";; *) echo "not on PATH";; esac
   ```

5. If it is not on your `PATH`, add it yourself. Nothing here edits your shell
   profile without you asking. Append the line to the file your shell actually
   reads — `~/.zshrc` for zsh (the macOS default) or `~/.bashrc` for bash:

   ```console
   echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
   ```

6. Open a new terminal and run:

   ```console
   oci-free --version
   ```

If you would rather not touch `PATH` at all, keep the binary wherever you like
and run it by path, for example `~/tools/oci-free --version`.

#### macOS Gatekeeper

The macOS builds are not signed with an Apple Developer ID and are not
notarised. macOS quarantines files downloaded through a browser, so the first
run may be refused with a message about an unidentified developer. Either
download with `curl` (which does not set the quarantine attribute), or clear it
explicitly after inspecting the file:

```console
xattr -d com.apple.quarantine ~/.local/bin/oci-free
```

See [Verifying a download](#verifying-a-download) and
[`docs/SECURITY.md`](SECURITY.md) before removing a quarantine attribute.

#### Windows SmartScreen

The Windows builds are not Authenticode signed. SmartScreen may show a
"Windows protected your PC" prompt for the MSI. Choosing **More info → Run
anyway** proceeds. Verify the checksum first.

## Verifying a download

Each native binary archive ships with a `.sha256` sidecar. Installers such as the MSI are covered by GitHub artifact attestations, but cargo-dist does not generate a checksum sidecar for every installer type.

macOS and Linux:

```console
shasum -a 256 -c oci-free-x86_64-unknown-linux-gnu.tar.xz.sha256
```

Windows PowerShell, for the ZIP archive:

```console
(Get-FileHash .\oci-free-x86_64-pc-windows-msvc.zip -Algorithm SHA256).Hash
Get-Content .\oci-free-x86_64-pc-windows-msvc.zip.sha256
```

Release artifacts, including installers, also carry GitHub artifact attestations, which record the
workflow, commit, and repository that produced them. With the GitHub CLI:

```console
gh attestation verify oci-free-x86_64-unknown-linux-gnu.tar.xz --repo jacek4yang/oci-free
```

Attestations prove provenance. They are **not** Windows Authenticode signing or
Apple notarisation — see [Signing status](RELEASE.md#signing-status).

## Uninstalling

| Installed with | Remove it by |
| --- | --- |
| Windows MSI | Settings → Apps → Installed apps → oci-free → Uninstall |
| Shell installer | `rm ~/.local/bin/oci-free`, then remove the `PATH` line the installer added |
| PowerShell installer | Delete `%USERPROFILE%\.local\bin\oci-free.exe` and remove the `PATH` entry |
| Archive, by hand | Delete the binary you copied |

## Building from source

Only needed if you want an unreleased commit or an unsupported platform. This
does require a Rust toolchain:

```console
git clone https://github.com/jacek4yang/oci-free
cd oci-free
cargo build --release --locked
./target/release/oci-free --version
```
