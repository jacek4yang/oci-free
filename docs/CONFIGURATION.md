# Configuration

`oci-free` authenticates with an OCI API signing key. It reads the same
configuration file the official tooling uses, but it does not require the OCI
CLI, Python, or Node.js to be installed.

## Creating a profile

```console
$ oci-free config init
```

writes the file for you, prompting for anything not supplied as a flag and
validating each value before it is written. See
[`COMMANDS.md`](COMMANDS.md#oci-free-config-init).

`oci-free config show` prints the configuration that would be used, with the
tenancy and user OCIDs redacted and no secret material — safe to paste into an
issue.

## Obtaining an API key

oci-free does not generate keys. The OCI Console does it in one step, with no
Python, OpenSSL, or OCI CLI:

1. Profile menu → **My profile** → **API keys** → **Add API key**.
2. Keep **Generate API key pair**, click **Download private key**, then **Add**.
3. The Console shows a configuration preview with your tenancy OCID, user OCID,
   fingerprint, and region.
4. Store the private key somewhere only you can read:
   `chmod 600 ~/.oci/oci_api_key.pem`.

## Configuration file

The default location is `~/.oci/config` (`%USERPROFILE%\.oci\config` on
Windows). A minimal profile looks like this:

```ini
[DEFAULT]
user=ocid1.user.oc1..aaaaaaaa...
tenancy=ocid1.tenancy.oc1..aaaaaaaa...
fingerprint=8d:54:09:96:82:c3:b4:33:42:f9:31:40:70:6a:34:8c
key_file=~/.oci/oci_api_key.pem
region=us-ashburn-1
```

Notes:

- keys are case-insensitive, `#` and `;` start a comment, and entries before the
  first `[PROFILE]` header belong to `DEFAULT`;
- named profiles inherit fields they do not define from `[DEFAULT]`, matching the
  OCI SDK configuration convention; values explicitly set in the named profile win;
- a profile that defines the same key twice is rejected rather than silently
  resolved, because that mistake otherwise selects the wrong credentials;
- `~` in `key_file` is expanded against the home directory;
- `pass_phrase` is read but passphrase-protected keys cannot be used; supply an
  unencrypted PKCS#8 or PKCS#1 key (`openssl pkcs8 -topk8 -nocrypt` converts
  one, or generate a fresh API key in the Console);
- `security_token_file`, `delegation_token_file`, and `key_content` are
  recognised and rejected with an explanation instead of being ignored.

Select a different file or profile with the global flags:

```console
oci-free --config-file /path/to/config --profile ADMIN doctor
```

## Environment variables

Every field can come from the environment instead, so a machine with no
configuration file can still be used:

| Variable | Purpose |
| --- | --- |
| `OCI_CLI_CONFIG_FILE` | Path to the configuration file |
| `OCI_CLI_PROFILE` | Profile to read |
| `OCI_CLI_USER` | User OCID |
| `OCI_CLI_TENANCY` | Tenancy OCID |
| `OCI_CLI_FINGERPRINT` | API key fingerprint |
| `OCI_CLI_KEY_FILE` | Path to the private key |
| `OCI_CLI_REGION` | Region identifier |

An environment value overrides the configuration file, and `doctor` reports
which fields were overridden.

## Checking the setup

`oci-free doctor` validates everything that can be verified locally and exits
non-zero when the configuration is not usable:

```console
$ oci-free doctor
[     ok] Configuration: loaded profile [DEFAULT] of /home/me/.oci/config for region us-ashburn-1
[     ok] Private key file permissions: /home/me/.oci/oci_api_key.pem is only readable by its owner (0600)
[     ok] Private key: loaded an RSA private key from /home/me/.oci/oci_api_key.pem
[     ok] Key fingerprint: the private key matches the configured fingerprint 8d:54:...:8c
[     ok] Request signing: signed and verified a test request as ocid1.tenancy.oc1..…xk3q7a/ocid1.user.oc1..…4m2p8z/8d:54:...:8c
[skipped] Live OCI verification: not implemented yet; doctor currently validates local configuration only
```

The fingerprint check is the important one: it derives the fingerprint from the
private key and compares it with the configured value, which catches the common
case of a configuration file that points at the wrong key.

`--json` produces the same result as a versioned document for automation:

```console
oci-free doctor --json
```

## What is redacted

Diagnostics are meant to be safe to paste into a bug report:

- private key material is never read into output, and the key type's `Debug`
  rendering only exposes the fingerprint;
- `pass_phrase` is replaced with `<redacted>` wherever it is formatted, and JSON
  output reports only whether one is configured;
- tenancy and user OCIDs keep their structure but only the last six characters
  of the unique identifier, for example `ocid1.tenancy.oc1..…xk3q7a`;
- the fingerprint is shown in full, because it identifies a public key and
  seeing it is what makes a key/configuration mismatch obvious.
