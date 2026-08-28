# Commands

Every command accepts the global options `--json`, `--config-file <PATH>`, and
`--profile <NAME>`. Run `oci-free <command> --help` for the authoritative flag
list; this page explains what each command does and when to reach for it.

## Exit codes

Scripts should branch on these numbers. They are part of the public contract
and will not change within a major version.

| Code | Name | Meaning |
| --- | --- | --- |
| 0 | success | The command did what was asked. |
| 1 | failure | No more specific category applies. |
| 2 | invalid input | A supplied value was wrong, or a name was ambiguous. Matches clap's own usage-error code. |
| 3 | configuration | Configuration, credentials, or signing could not be used. |
| 4 | permission | OCI accepted the identity but refused the operation. |
| 5 | safety | The policy engine refused, **or** `vm net audit` found something. |
| 6 | transient | Network, timeout, or throttling. Safe to retry. |
| 7 | partial | A multi-step mutation stopped part-way, or `reset` retained at least one targeted resource. Needs attention. |

Two commands deliberately carry their verdict in the exit code:

- `doctor` exits 3 when any check fails, so a setup script can stop early;
- `vm net audit` exits 5 when the audit found anything at warning severity or
  above, so a scheduled run can alert without parsing output.

`reset` exits 7 rather than 0 when any resource in its approved cleanup plan
remains. Re-run it after OCI finishes asynchronous teardown or inspect the
reported dependency; a partial cleanup is never success-shaped.

`vm ssh` passes the SSH client's own exit code through, so wrapping
`oci-free vm ssh` behaves like wrapping `ssh`.

A safety refusal (5) is never reported as transient (6). Automation must not
retry an operation the policy engine deliberately blocked.

## Getting set up

### `oci-free config init`

Writes a standard `~/.oci/config` profile. Prompts for anything not supplied on
the command line; in a non-interactive run every required value must be a flag.

```console
$ oci-free config init \
    --tenancy ocid1.tenancy.oc1..aaaa... \
    --user ocid1.user.oc1..aaaa... \
    --region us-ashburn-1 \
    --key-file ~/.oci/oci_api_key.pem
```

The fingerprint is derived from the private key unless `--fingerprint` is given,
and a supplied fingerprint that disagrees with the key is refused rather than
written — that mismatch is otherwise an opaque authentication failure later.

An existing profile is never replaced without `--force`. Other profiles in the
file are preserved. The private key is referenced by path; its contents are
never copied into the configuration.

oci-free does not generate API keys. The OCI Console's **Profile → My profile →
API keys → Add API key** flow generates the pair, shows the fingerprint, and
hands over the private key in one step, with no Python, OpenSSL, or OCI CLI.

### `oci-free config show`

Prints the configuration oci-free would use, with the tenancy and user OCIDs
redacted and no secret material. Safe to paste into an issue.

### `oci-free doctor`

Validates the setup locally, then against OCI. Run it first; run it again when
anything is confusing.

Local checks: configuration loading, private key file permissions, the key
itself, the fingerprint match, and a signing self-test that signs and verifies a
representative request without sending anything.

Live checks: signed authentication, tenancy access, region subscriptions and the
home region, availability domains, and one read per capability — compute,
networking, service limits, and usage.

Every live check is read-only. The usage check is a `POST`, because the Usage
API models its query that way, but it changes nothing; `doctor` never creates,
modifies, or deletes anything.

A missing **optional** capability is a warning, not a failure. A Free Tier
tenancy routinely lacks the Usage API grant; failing `doctor` over it would
teach users that a red `doctor` is normal, which is exactly how a real failure
gets ignored.

## Understanding the account

### `oci-free status`

One screen: profile, tenancy, home region, credential state, instance counts,
remaining Free Tier capacity, current cost, and anything exposed to the
internet.

It aggregates five independent reads. If one is refused, that section reports
why and the rest still appears. What it never does is present a partial picture
as a complete one: unreadable capacity is *unknown*, not free headroom, and
unreadable cost is *unavailable*, not zero.

### `oci-free cost`

Current billing-period total, plus any service with a charge.

An unavailable figure is reported as unavailable. It is never rendered as
`0.00` — for a Free Tier user that would turn "we could not tell" into a false
reassurance. A genuine reported zero is stated as a fact.

### `oci-free account info`

Tenancy, home region, subscribed regions, and availability domains. Warns when
the configured region is not the home region, because that is where Always Free
resources live.

### `oci-free account limits [--all]`

Service limits with current usage where OCI offers it. By default only the
limits the policy snapshot marks as Free Tier relevant are shown; a tenancy
publishes hundreds, and dumping them all would bury the four that matter.
`--all` widens it.

A limit OCI reported without a value is shown as *not reported*, never as a
limit of zero.

### `oci-free account usage`

Consumption for the current billing period, by service.

### `oci-free free list`

What is free, what is used, and what is left, for each Always Free compute
allowance. Cross-checks the shipped policy snapshot against OCI's live
`billingType`: if OCI no longer calls a covered shape Always Free, the snapshot
is stale and the shape stops being recommended.

### `oci-free policy explain <shape> [--ocpus N --memory N]`

Why a resource is allowed or blocked, with the whole evidence chain: OCI's live
billing classification, the dated snapshot entry that supplies the allowance,
current tenancy usage, the projected launch, the classification, and the
decision.

`--ocpus` and `--memory` must be given together. Without them the shape's own
minimum is projected.

Explaining a blocked resource is a successful explanation: this command exits 0
either way.

## Instances

### `oci-free vm list`

Active instances with shape, size, Free Tier classification, and proven
ownership.

### `oci-free vm info <instance>`

Everything about one instance: identity, lifecycle, shape and size, availability
domain, image, creation time, VNIC and addresses, subnet, attached NSGs with
their ownership, boot volume, Free Tier evidence, and effective ingress.

`<instance>` is a display name or a full OCID. A name matching several active
instances is an error, not a guess.

### `oci-free vm create`

The full launch workflow. Interactive by default; `--non-interactive` turns
prompting off and every material choice must then be a flag.

```console
$ oci-free vm create \
    --shape free:arm --ocpus 2 --memory 12 \
    --name web-1 \
    --username deploy \
    --hostname web-1 \
    --ssh-key ~/.ssh/id_ed25519.pub \
    --ssh-source 198.51.100.7/32 \
    --non-interactive --yes
```

`--shape` accepts a shape name or a semantic selector, `free:arm` or
`free:x86`. Selectors resolve against OCI's live shape metadata — the processor
description and `billingType` — never against a hard-coded name.

Nothing is pinned: not the availability domain, not the image, not the shape.
The image is the newest compatible platform image from the current catalogue.

`--username USER` asks cloud-init to create a key-only Linux login account with
`/bin/bash` and passwordless sudo. A custom user requires `--ssh-key`, because
oci-free deliberately refuses to create an account that would have no supported
login credential. The chosen user is recorded in an oci-free ownership-adjacent
freeform tag so a later `vm ssh` invocation can recover it without local state.

`--hostname HOSTNAME` sets both the guest hostname through cloud-init and the
primary VNIC hostname label. It accepts a conservative OCI/RFC-style label: 1–63
lowercase ASCII letters, digits, or `-`, starting with a lowercase letter and
ending with a letter or digit.

The plan is shown and confirmed before anything is created. `--yes` accepts it
non-interactively; there is no way through the command-layer mutation workflow
without an approved plan.

`--ssh-source` accepts a CIDR, `myip`, or `none` to leave SSH closed. It is
never defaulted: a non-interactive run without it is an error, not an open
port.

### `oci-free vm delete <instance>`

Terminates an instance after a preflight plan that names every resource and its
fate.

The boot volume's fate is always explicit. OCI keeps it by default, and a
retained volume keeps consuming the Always Free storage allowance silently — so
a non-interactive run must pass `--delete-boot-volume` or `--keep-boot-volume`.

`--delete-nsg` also removes the instance's managed NSG. Only resources oci-free
created are ever deleted; a shared subnet, or an NSG somebody else made, is
reported as untouched.

The plan also states what happens to the public IP: an ephemeral address is
released with the instance, while a **reserved** one survives and keeps
consuming the Always Free reserved-IP allowance.

### `oci-free vm start | stop | reboot <instance>`

Lifecycle actions. `--force` makes `stop` an immediate power off and `reboot` an
immediate power cycle, neither of which shuts the guest down cleanly.

The current state is validated first: starting a running instance is a reported
no-op, and acting on a terminated one is refused before any request is sent.

Stopping does **not** free Free Tier capacity — the shape stays allocated. Only
termination releases it, and the command says so.

### `oci-free vm ip <instance>`

Prints the public IP on its own line, so `$(oci-free vm ip web-1)` works in a
shell. An instance with no public address says so plainly; in `--json`,
`has_public_ip` is `false` and `public_ip` is `null`.

### `oci-free vm ssh <instance> [-l USER] [-i KEY] [--print]`

Connects using the discovered address. If the instance was created with
`oci-free vm create --username`, that login name is recovered from the instance
tag; otherwise the image's usual login account is used. `--user`/`-l` remains an
explicit override.

The command is built as an argument vector and handed to the OS process API. No
shell is involved. The login name is supplied as the value of OpenSSH's `-l`
option, so even a hostile explicit value cannot become a separate SSH option.

`--print` shows the command instead of running it. `--json` implies `--print`: a
machine-readable command whose side effect is stealing the terminal would be
unusable in a pipeline.

## Networking

See [`NETWORKING.md`](NETWORKING.md) for the model these commands implement.

### `oci-free vm net <instance> show`

Effective inbound exposure, with the OCI object responsible for every rule, and
whether the instance is reachable from the internet at all.

### `oci-free vm net <instance> audit`

The same picture, turned into explainable findings. Exits 5 if anything is at
warning severity or above.

### `oci-free vm net <instance> open PORT/PROTOCOL [--source CIDR]`

Adds an ingress rule to this instance's own managed NSG, creating and attaching
one on first use. Subnet Security Lists are never modified.

`--source` is required in a non-interactive run. It accepts a CIDR, a bare
address (treated as a `/32`), or `myip` to look up this machine's own public
address.

Interactively you choose: your own address, a range you type, every IPv4 address
(behind a second confirmation), or cancel.

`myip` contacts a third-party echo service — OCI has no endpoint that reports
the caller's address — and the detected value is shown for confirmation before
it becomes a rule. The endpoint is named in the prompt. Nothing looks your
address up unless you ask for it.

### `oci-free vm net <instance> close PORT/PROTOCOL`

Removes the matching rule from the managed NSG, then re-reads the effective
state and reports anything that still allows the port. Removing the instance
rule is not the same as closing the port.

## Repeated test cleanup

### `oci-free reset [--yes]`

Returns the resources **created by oci-free** in the home region to a clean test
state. This is deliberately narrower than “delete everything in the tenancy”.
Names are never ownership evidence.

Before any write, `reset` inventories every target and renders one destructive
`MutationPlan`. Only resources carrying deletion-permitting oci-free ownership
tags are candidates; instances, NSGs, subnets, internet gateways, and VCNs must
also carry the recognized role for that resource type. Untagged resources,
reused resources, and user-owned lookalikes are not deleted.

The deletion order is dependency-aware: instances first, then proven managed
boot volumes, instance NSGs, subnets, internet gateways (after removing the
managed route reference when necessary), and VCNs last. OCI teardown is
asynchronous, so deletion uses bounded polling/retry rather than an unbounded
wait.

Interactive use asks for confirmation after the complete plan is printed.
`--yes` accepts that plan for automation. If OCI retains any targeted resource,
the command reports it and exits 7; re-running after dependencies settle is
safe because discovery starts from fresh OCI state and ownership is re-proven.
