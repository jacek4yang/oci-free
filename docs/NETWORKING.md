# Networking

## The thing everyone gets wrong

OCI composes inbound access from two independent sources, and **both are
permissive**:

- a **Network Security Group** attached to the instance's VNIC;
- a **Security List** attached to the subnet.

Traffic is allowed if *either* permits it. So:

> "There is no NSG rule for port 22" does **not** mean port 22 is closed.

A subnet Security List may still allow it — and Security Lists apply to every
instance in the subnet, so the rule may have been added years ago for something
else entirely.

This is the single most misunderstood part of OCI networking, and the reason
`vm net show` reports the OCI object responsible for every effective rule rather
than a bare list of open ports.

## Instance-scoped by default

A normal `open` or `close` modifies exactly one object: the instance's own
oci-free-managed NSG.

```console
$ oci-free vm net web-1 open 443/tcp --source 0.0.0.0/0
```

On first use this creates an NSG named after the instance, stamps it with
ownership tags, and attaches it to the VNIC — preserving any NSG you attached
yourself rather than replacing it. Then it adds the rule.

Subnet Security Lists are **never** modified as a convenience. Changing one
would silently affect every other instance in the subnet, which is not a thing a
per-instance command should be able to do. When a Security List is what is
granting access, the audit says so and tells you to change it in the Console.

### Choosing a source

`--source` accepts a CIDR, a bare address (treated as a `/32`), or `myip`.

`myip` looks up this machine's public address. OCI has no endpoint that reports
the caller's address, so this contacts a third-party echo service — named in the
prompt — and the result is **shown for confirmation before it becomes a rule**.
That confirmation is not ceremony: a mistaken or hostile echo service would
otherwise open the port to somebody else's address.

Nothing looks your address up implicitly. Only an explicit interactive choice or
`--source myip` reaches that code.

## Closing a port is not the same as removing a rule

```console
$ oci-free vm net web-1 close 22/tcp
```

removes the matching rule from the managed NSG, then **re-reads the effective
state from OCI** and reports what still allows the port:

```text
oci-free-web-1 on web-1 no longer allows 22/tcp.
Verified against a fresh read of the effective state.

22/tcp is still allowed by:
  tcp 22 from 0.0.0.0/0 via security list Default Security List

warning: 22/tcp is still reachable: removing the instance rule does not close a
         port that another object allows
```

Reporting "closed" there would be a lie, and the kind of lie that gets a machine
compromised.

## Reachability is a chain

A rule allowing the world means nothing if packets cannot arrive. Three
conditions are evaluated separately so a warning can name the missing one:

1. the VNIC has a public IP address;
2. the subnet's route table has a `0.0.0.0/0` route;
3. that route points at an internet gateway which is **enabled**.

A disabled gateway still appears in a route rule, so the route alone proves
nothing. If any link is missing, `vm net show` says which one, and the audit
raises no exposure findings — a rule that cannot be used is not an exposure, and
reporting it as one would train you to ignore the audit.

## Ownership is proven, never assumed

oci-free tags every resource it creates:

| Tag | Meaning |
| --- | --- |
| `oci-free:managed` | `created` (oci-free made it) or `reused` (oci-free adopted it) |
| `oci-free:role` | `vcn`, `subnet`, `internet-gateway`, `instance-nsg`, `instance` |
| `oci-free:instance` | the instance a per-instance resource serves |
| `oci-free:version` | the version that created it |

Ownership decides what oci-free may do:

| Ownership | May reconfigure | May delete |
| --- | --- | --- |
| `created` | yes | yes |
| `reused` | yes, narrowly | **never** |
| `user_owned` | never | never |
| `unknown` | never | never |

**A display name is never evidence.** A VCN called `oci-free-vcn` that carries
no ownership tag belongs to somebody else, and oci-free will not adopt it,
reconfigure it, or delete it — it says so and creates its own instead. A tag
value this build does not recognise is `unknown`, which also blocks: it might
have been written by a newer oci-free, or by hand.

## The managed network

`vm create` reuses an existing oci-free-managed VCN and subnet if it can prove
ownership, and otherwise creates:

- a VCN, `10.0.0.0/16`;
- an enabled internet gateway;
- a default route through it;
- a public subnet, `10.0.0.0/24`;
- one NSG per instance.

The route is written before the subnet, so a subnet never briefly exists with no
path off the VCN.

A reused managed network is still checked for the topology `vm create` assumes.
If its subnet was later made private, or its gateway disabled, that is reported
rather than silently producing an instance nobody can reach.

## The audit

```console
$ oci-free vm net web-1 audit
```

Findings name a concrete condition, the object that causes it, and what to do:

| Finding | Severity |
| --- | --- |
| `ssh_open_to_internet` | critical |
| `sensitive_port_open_to_internet` | critical |
| `all_ports_open_to_internet` | critical |
| `broad_source_range` | warning |
| `inherited_subnet_exposure` | warning |
| `no_managed_instance_nsg` | warning |
| `rules_without_reachability` | info |
| `no_ingress_rules` | info |
| `stateless_rule` | info |
| `unrecognised_nsg_ownership` | info |

There is deliberately **no numeric score**. A number invented here would look
like a measurement and would hide the one thing you actually need, which is
*which object* to change.

Advice is phrased for whoever owns the offending object. oci-free will offer to
fix its own NSG; for one it did not create, it tells you to change it in the
Console rather than claiming it will do it for you.

The command exits 5 when anything reaches warning severity, so a scheduled run
can alert without parsing output.

## Advanced: subnet-wide changes

There is no command for them. Subnet Security Lists govern every instance in the
subnet, so editing one is a deliberate act that belongs in the OCI Console where
its blast radius is visible. `vm net show` and `vm net audit` will always tell
you when a Security List is the object responsible.
