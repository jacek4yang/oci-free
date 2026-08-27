# Quickstart

From nothing to a running Always Free VM you can SSH into. No Python, no
Node.js, no Java, no OpenSSL, and no official OCI CLI at any point.

## 1. Install

See [`INSTALLATION.md`](INSTALLATION.md) for every platform and the offline
options. The short version, for macOS and Linux:

```console
$ curl --proto '=https' --tlsv1.2 -LsSf \
    "https://github.com/jacek4yang/oci-free/releases/latest/download/oci-free-installer.sh" | sh
$ oci-free --version
```

## 2. Create an API key in the OCI Console

oci-free does not generate keys; the Console does it better and with no local
toolchain.

1. Sign in to the OCI Console.
2. Open the profile menu (top right) → **My profile** → **API keys**.
3. Click **Add API key**, keep **Generate API key pair** selected, and
   **Download private key**.
4. Click **Add**. The Console shows a configuration preview containing your
   tenancy OCID, user OCID, fingerprint, and region. Keep that page open.
5. Move the downloaded key somewhere only you can read it:

   ```console
   $ mkdir -p ~/.oci && mv ~/Downloads/*.pem ~/.oci/oci_api_key.pem
   $ chmod 600 ~/.oci/oci_api_key.pem
   ```

## 3. Write the configuration

```console
$ oci-free config init
```

It prompts for each value; paste them from the Console preview. The fingerprint
is derived from the key itself, so you can leave it blank.

To do it in one line instead:

```console
$ oci-free config init \
    --tenancy ocid1.tenancy.oc1..aaaa... \
    --user ocid1.user.oc1..aaaa... \
    --region us-ashburn-1 \
    --key-file ~/.oci/oci_api_key.pem
```

## 4. Check everything works

```console
$ oci-free doctor
```

This validates the configuration locally, then makes read-only calls to OCI to
prove the credentials work and to report which permissions you have.

A `warning` on **Usage and cost access** or **Service limits access** is
normal and expected on a Free Tier tenancy. Those are optional; the commands
that need them will say so rather than failing. Only a `failed` line needs
fixing, and each one names the next action.

## 5. See what you have

```console
$ oci-free status
```

Profile, tenancy, home region, instances, remaining Free Tier capacity, current
cost, and anything exposed to the internet — in one screen.

```console
$ oci-free free list
```

What is free, what is used, and what is left, with the evidence behind each
answer.

## 6. Create a VM

```console
$ oci-free vm create
```

Interactive by default. It discovers the availability domains, the currently
free-eligible shapes, and the newest compatible platform image, then shows you a
plan before it creates anything:

```text
Plan for vm.create in us-ashburn-1

  reuse   VCN oci-free-vcn: unchanged
          ownership: created by oci-free, so it can be cleaned up automatically
  reuse   subnet oci-free-subnet: unchanged
  create  network security group oci-free-web-1: attached to the new instance's VNIC
          note: ingress is scoped to this instance alone
  create  compute instance web-1: VM.Standard.A1.Flex with 2 OCPU and 12 GB in ...

  billing risk: none
  policy:       VM.Standard.A1.Flex is Always Free and this configuration fits ...
                - OCI Shape.billingType: OCI reports shape VM.Standard.A1.Flex as ALWAYS_FREE
                - oci-free policy snapshot v1, verified 2026-08-27: allowance ...
                - live tenancy usage: 0.00 of 4.00 OCPU and 0.00 of 24.00 GB ...

  network exposure
    + tcp 22 from 198.51.100.7/32

Apply this plan? [y/N]
```

Nothing is created until you answer yes. If the configuration would exceed the
Always Free allowance, or the shape is not provably free, the plan is blocked
and no request is sent at all.

For automation, supply every choice and accept the plan explicitly:

```console
$ oci-free vm create \
    --shape free:arm --ocpus 2 --memory 12 \
    --name web-1 \
    --ssh-key ~/.ssh/id_ed25519.pub \
    --ssh-source 198.51.100.7/32 \
    --non-interactive --yes
```

## 7. Connect

```console
$ oci-free vm ssh web-1
```

The address and login name are discovered from the instance and its image.

## 8. Open a port

```console
$ oci-free vm net web-1 open 443/tcp --source 0.0.0.0/0
```

This adds a rule to *this instance's* network security group and nothing else.
Afterwards, check what the whole world can actually reach:

```console
$ oci-free vm net web-1 audit
```

## 9. Clean up

```console
$ oci-free vm delete web-1
```

The plan names every resource and what will happen to it. The boot volume's fate
is always an explicit choice — OCI keeps it by default, and a kept volume goes
on consuming your Always Free storage allowance.

## Where to go next

- [`COMMANDS.md`](COMMANDS.md) — every command, and the exit codes.
- [`FREE-TIER-SAFETY.md`](FREE-TIER-SAFETY.md) — how "is this free?" is decided.
- [`NETWORKING.md`](NETWORKING.md) — why an NSG rule is not the whole story.
- [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — when something goes wrong.
