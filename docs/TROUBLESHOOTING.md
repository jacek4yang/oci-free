# Troubleshooting

Start with `oci-free doctor`. It checks the configuration locally, then makes
read-only calls to OCI, and every failure names the next action.

Every error oci-free produces has three parts: what failed, why it matters, and
what to do next. If you see one without a `next:` line, that is a bug — please
report it.

## Setup

### `configuration is missing 'tenancy'`

No configuration file was found, or the profile does not set that field. Run
`oci-free config init`, or check `oci-free config show` to see which file and
profile are actually being used.

Environment variables (`OCI_CLI_TENANCY`, `OCI_CLI_REGION`, and so on) override
the file, and `config show` lists which fields came from the environment.

### `the configured fingerprint ... does not match the private key`

The `fingerprint` in the configuration is not the fingerprint of the key at
`key_file`. Signing with a mismatched pair produces requests OCI rejects with an
opaque authentication error, so oci-free refuses up front.

The message includes the key's real fingerprint. Either set `fingerprint` to
that, or point `key_file` at the key that matches.

### `the private key is protected by a passphrase`

oci-free cannot use encrypted keys. Convert it once:

```console
$ openssl pkcs8 -topk8 -nocrypt -in encrypted.pem -out ~/.oci/oci_api_key.pem
$ chmod 600 ~/.oci/oci_api_key.pem
```

Or generate a fresh API key in the OCI Console, which produces an unencrypted
one.

### `a public key was supplied where a private key is required`

`key_file` points at the `_public.pem` file that was uploaded to OCI. Point it at
the private key instead.

### `the key is in an unsupported format`

OCI API keys are RSA keys in PEM format. An OpenSSH key (`BEGIN OPENSSH PRIVATE
KEY`) or an elliptic-curve key will not work; generate an API key in the OCI
Console.

### `Private key file permissions: warning`

The key is readable by other users on the machine. On Unix:

```console
$ chmod 600 ~/.oci/oci_api_key.pem
```

## Authentication and permissions

Use the failure shape before changing IAM policy:

| Evidence | Meaning | Next action |
| --- | --- | --- |
| DNS/TCP/TLS failure, with an `endpoint:` and no HTTP status | OCI was not reached | Check the displayed hostname, DNS, HTTPS proxy, TLS interception, and TCP/443. |
| HTTP 401/403 without `opc-request-id` | A proxy or gateway probably answered | Check proxy and egress configuration; do not change IAM yet. |
| HTTP 403 with `opc-request-id` | OCI authenticated the caller and denied the operation | Add the optional IAM grant if that capability is wanted. |

### `OCI refused ... with HTTP 401`

The signature was rejected. The two usual causes:

- the key does not match the fingerprint registered in the Console — `doctor`
  checks this;
- the host clock is more than five minutes out. OCI rejects requests whose
  `date` header is too far from server time. Check with `date -u` and enable NTP.

### `OCI refused ... with HTTP 403` **with** an OCI request id

Authenticated, but the tenancy's IAM policy does not permit the operation. The
error names the operation; ask an administrator for a matching policy statement.

The grants oci-free uses:

| Capability | Policy statement |
| --- | --- |
| instances | `allow group <g> to read instance-family in tenancy` |
| networking | `allow group <g> to read virtual-network-family in tenancy` |
| creating instances | `allow group <g> to manage instance-family in tenancy` |
| managing networking | `allow group <g> to manage virtual-network-family in tenancy` |
| service limits | `allow group <g> to read limits in tenancy` |
| cost and usage | `allow group <g> to read usage-report in tenancy` |

The last two are optional. Without them `account limits` and `cost` report
unavailable, and everything else still works.

### `403` **without** an OCI request id

OCI replies normally carry `opc-request-id`. A 401 or 403 without one probably
came from something between you and OCI — a corporate proxy, a TLS-inspecting
gateway, or an egress allow-list — so oci-free points to networking first. The
header is a diagnostic signal, not proof of response authenticity.

Check `HTTPS_PROXY`, and whether the exact `endpoint:` shown by oci-free is
permitted. Commercial Limits and Usage endpoints include the `oci` label, for
example `limits.us-sanjose-1.oci.oraclecloud.com`.

### `could not connect to OCI`

DNS, the TCP connection, or the TLS handshake failed. Check connectivity, DNS,
and any HTTPS proxy or TLS interception. oci-free uses rustls with the system
trust store and will not accept a certificate it cannot verify.

The error includes only the endpoint authority, not the request path or query.
Test that exact hostname. For a commercial region:

```powershell
Resolve-DnsName usageapi.<region>.oci.oraclecloud.com
Test-NetConnection usageapi.<region>.oci.oraclecloud.com -Port 443
Resolve-DnsName limits.<region>.oci.oraclecloud.com
Test-NetConnection limits.<region>.oci.oraclecloud.com -Port 443
```

On Linux or macOS:

```console
$ dig +short usageapi.<region>.oci.oraclecloud.com
$ nc -vz usageapi.<region>.oci.oraclecloud.com 443
$ dig +short limits.<region>.oci.oraclecloud.com
$ nc -vz limits.<region>.oci.oraclecloud.com 443
```

For a government or sovereign realm, copy the exact endpoint from the error
instead of substituting `oraclecloud.com`. These commands need no OCI key and
must never be given private-key contents.

### `OCI redirected ... to <somewhere>`

oci-free never follows redirects: the `Authorization` header is a signature over
one exact host and path, and replaying it elsewhere would disclose a valid
credential. A redirect usually means the configured region is wrong for this
tenancy — check `oci-free account info`.

## Safety refusals

These are exit code 5. They are decisions, not faults, and **automation must not
retry them**.

### `... was blocked by the safety policy`

The plan's classification is not `VerifiedAlwaysFree`. Run:

```console
$ oci-free policy explain <shape> --ocpus N --memory N
```

for the full evidence chain: the live billing type, the allowance, current
usage, and the arithmetic.

### `current usage of ... could not be determined`

OCI did not report a shape configuration for one of your instances, so real
usage may exceed what was measured and no headroom can be proven. The instance
is named in the blocker. `oci-free vm info <that instance>` usually shows why —
often a shape that is no longer offered in the region.

### `no shape in this region is verified Always Free`

Either the region genuinely offers none — Always Free capacity lives in the
**home region**, so check `oci-free account info` — or OCI's `billingType` no
longer matches the shipped policy snapshot. `oci-free free list` shows which.

## Creating instances

### `Out of host capacity` / `Out of capacity for shape`

Oracle has no free Ampere capacity in that availability domain right now. This
is extremely common and is not something oci-free can fix. Try another
availability domain with `--availability-domain`, or try again later.

### `vm create stopped while creating ...` (exit code 7)

A multi-step creation stopped part-way and could not fully undo itself. The
error lists exactly which resources were created and retained. They carry
`oci-free:managed=created`, so you can remove them in the Console — or simply
re-run `oci-free vm create`, which will reuse them.

Nothing that existed before the operation is ever deleted during recovery, and
an instance that was created is never terminated automatically: that decision is
yours.

### `--source was not supplied and cannot be asked for`

A non-interactive run needs every material choice on the command line. oci-free
will not pick an ingress source for you, because the convenient answer
(`0.0.0.0/0`) and the safe one are not the same.

## Networking

### I closed the port but it is still reachable

That is the composition rule, working as designed. A subnet Security List
allows it, and Security Lists apply to every instance in the subnet. `close`
tells you this and names the object:

```console
$ oci-free vm net web-1 show
```

The rule has to be changed on that Security List, in the Console. oci-free will
not edit it for you, because doing so would silently affect every other instance
in the subnet.

### I opened the port but cannot connect

Check the reachability chain — `oci-free vm net <instance> show` reports it:

- no public IP: the instance is not addressable from outside;
- no `0.0.0.0/0` route: return traffic cannot leave;
- gateway not enabled: the route points somewhere unusable.

If all three are fine, the remaining suspects are inside the guest: its own
firewall (`firewalld` on Oracle Linux, `ufw` on Ubuntu) and whether the service
is actually listening.

### `has no oci-free-managed network security group`

`close` only removes rules oci-free created. An instance you made elsewhere has
no managed NSG, so there is nothing for oci-free to remove — `vm net show` will
tell you which object grants the access.

## SSH

### `no ssh client was found on this system`

oci-free uses the operating system's SSH client rather than embedding one. On
Windows: **Settings → Optional features → OpenSSH Client**. Or use `--print` to
get the command and run it from a machine that has one.

### Connection refused or timing out

In order: is port 22 open (`vm net show`), is the instance `RUNNING`
(`vm info`), and did you install a public key at creation time? An instance
created without `--ssh-key` has no way to log in, and `vm create` warns about
exactly that.

### `Permission denied (publickey)`

Usually the wrong login name. oci-free picks it from the image — `opc` for
Oracle Linux, `ubuntu` for Canonical Ubuntu — and warns when it had to guess.
Override with `-l`.

## Ambiguity and naming

### `<name> matches N instances`

Display names are not unique in OCI. oci-free will not guess which machine you
meant to stop or terminate. The error lists the candidates; pass the OCID.

## Output

### `--json` seems to hang

It should not: `--json` disables prompting precisely so it cannot. If a required
value is missing you get an error naming the flag. If you are seeing a genuine
hang, please report it with the command line.

### `vm ssh --json` did not connect

By design. A machine-readable command whose side effect is taking over the
terminal would be unusable in a pipeline, so `--json` reports the command
instead. The `command` field is the argv array.

## Reporting a problem

`oci-free config show` and `oci-free doctor --json` are both safe to paste: the
tenancy and user OCIDs are redacted and no key material, `Authorization` header,
or passphrase is ever included.

Include the OCI request id if the error carried one — it is the single most
useful thing for correlating with Oracle's own logs.
