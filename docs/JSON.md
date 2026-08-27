# JSON output contract

Every command accepts `--json`. This page is the contract: field names, enum
spellings, and nesting documented here are stable for the life of schema
version `1`, and changing any of them is a breaking change.

## The envelope

Every response, success or failure, is wrapped the same way.

```json
{
  "schema_version": "1",
  "command": "vm.net.show",
  "data": { },
  "warnings": []
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `schema_version` | string | Currently `"1"`. Bumped only for a breaking change. |
| `command` | string | Dotted command identifier, for example `vm.net.open`. |
| `data` | object | Present on success. Absent on failure. |
| `error` | object | Present on failure. Absent on success. |
| `warnings` | array of strings | **Always present**, possibly empty, so consumers can iterate without a null check. |

Exactly one of `data` and `error` is present.

## Errors

```json
{
  "schema_version": "1",
  "command": "vm.create",
  "error": {
    "kind": "policy_rejected",
    "message": "vm.create was blocked by the safety policy",
    "context": "VM.Standard3.Flex is a paid shape",
    "remediation": "run `oci-free policy explain` for the evidence, ...",
    "oci": {
      "status": 403,
      "code": "NotAuthorized",
      "request_id": "abc123",
      "operation": "ListInstances"
    },
    "exit_code": 4
  },
  "warnings": []
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `kind` | string | Stable category. See the table below. |
| `message` | string | What failed. |
| `context` | string | Why it matters. Absent when the message says everything. |
| `remediation` | string | The next corrective action. **Always present.** |
| `oci` | object | OCI call details. Absent for a purely local failure. |
| `exit_code` | number | The process exit code that accompanied this error. |

`oci.request_id` is the single most useful thing to quote to Oracle support, so
it is preserved on every failure that came from an OCI call.

### Error kinds

`configuration`, `authentication`, `authorization`, `not_found`, `conflict`,
`rate_limited`, `transient_server`, `network`, `timeout`, `invalid_input`,
`ambiguous`, `policy_rejected`, `billing_uncertain`, `unsupported_state`,
`partial_mutation`, `external_tool`, `malformed_response`.

These map onto exit codes as documented in
[`COMMANDS.md`](COMMANDS.md#exit-codes).

## Guarantees

- **No ANSI escapes.** Output is parsed by scripts and pasted into issues.
- **No secrets.** No private key material, no `Authorization` header, no
  passphrase ever appears. Tenancy and user OCIDs are redacted in the payloads
  that render them for humans (`account.info`, `status`, `config.show`); OCIDs
  that a script needs in order to address a resource — instance, VNIC, subnet,
  NSG — are full values.
- **Absent is not zero.** A figure OCI did not report is omitted or `null`,
  never `0`. `cost` carries an explicit `available` boolean for exactly this
  reason.
- **Enum spellings are stable.** `snake_case` for error kinds, ownership, audit
  severity, and change kinds. Free Tier classifications are the `PascalCase`
  variant names: `VerifiedAlwaysFree`, `LimitedFree`, `Paid`, `Unknown`.
- **Unknown fields may be added.** A consumer must ignore fields it does not
  recognise; adding one is not a breaking change.
- **Optional fields are omitted, not null**, except where a `null` is
  semantically meaningful (`vm.ip`'s `public_ip`).

## `--json` changes behaviour in two places

Both because a machine-readable command must be safe in a pipeline:

- prompting is disabled, so a missing required value is an error naming the
  flag rather than a hang;
- `vm ssh` prints the command instead of launching an interactive session.

## Payloads by command

### `status`

`profile`, `tenancy` (redacted), `tenancy_name`, `configured_region`,
`home_region`, `credentials_valid`, `instances` (`running`, `stopped`,
`transitioning`, `total`, `managed_by_oci_free`), `capacity` (array of
`allowance_id`, `description`, `remaining_ocpus`, `remaining_memory_gb`,
`remaining_instances`, `blockers`), `cost`, `network_warnings`,
`permission_warnings`, `warnings`.

A `capacity` entry omits its `remaining_*` fields when usage could not be
measured. That is *unknown*, not zero.

### `cost`

`period_start`, `period_end`, `available`, `total`, `currency`,
`charged_services` (array of `service`, `amount`), `has_charges`, `warnings`.

**Check `available` before reading `total`.** When `available` is `false`,
`total` is absent.

### `doctor`

`schema` (`oci-free.doctor/v1`), `status`, `checks` (array of `id`, `title`,
`status`, `detail`, `remediation`), `config`.

`status` and each check's `status` are one of `pass`, `skipped`, `warn`, `fail`.
Check `id` values are stable identifiers: `configuration`,
`key_file_permissions`, `private_key`, `key_fingerprint`, `request_signing`,
`live_authentication`, `live_tenancy`, `live_home_region`,
`live_availability_domains`, `live_compute_read`, `live_network_read`,
`live_limits_read`, `live_usage_read`.

### `account.info`

`profile`, `tenancy` (redacted), `tenancy_name`, `configured_region`,
`home_region`, `subscribed_regions`, `availability_domains`, `warnings`.

### `account.limits`

`region`, `free_tier` and `other` (arrays of `service`, `name`, `description`,
`scope`, `availability_domain`, `value`, `used`, `available`,
`free_tier_relevant`), `other_omitted`, `warnings`.

### `account.usage`

`region`, `period_start`, `period_end`, `available`, `rows` (array of `service`,
`quantity`, `unit`, `amount`), `currency`, `warnings`.

### `free.list`

`region`, `allowances` (array of `allowance_id`, `description`, `shapes`,
`billing_types`, `capacity`, `blockers`), `policy_snapshot`, `warnings`.

### `policy.explain`

`resource`, `region`, `resolved_as`, `live_billing_type`, `allowance`,
`policy_snapshot`, `current_usage`, `capacity`, `projected`, `classification`,
`allowed`, `reason`, `evidence` (array of `source`, `detail`), `warnings`.

The structured evidence is preserved here, not only the prose reason.

### `config.init`

`config_file`, `profile`, `replaced_existing`, `owner_only_permissions`,
`validated`, `next_steps`, `warnings`.

### `config.show`

`profile`, `config_file`, `env_overrides`, `region`, `tenancy` (redacted),
`user` (redacted), `fingerprint`, `key_file`, `pass_phrase_configured`.

### `vm.list`

`region`, `instances` (array of `name`, `id`, `lifecycle_state`, `shape`,
`ocpus`, `memory_gb`, `availability_domain`, `free_classification`,
`ownership`, `managed_by_oci_free`), `warnings`.

### `vm.info`

`name`, `id`, `region`, `lifecycle_state`, `availability_domain`, `shape`,
`ocpus`, `memory_gb`, `time_created`, `image`, `ownership`, `free`, `network`,
`boot_volume`, `warnings`.

`network` carries `vnic_id`, `private_ip`, `public_ip`, `subnet_id`,
`subnet_name`, `vcn_id`, `internet_reachable`, `reachability_reason`,
`network_security_groups`, and `effective_ingress`.

### `vm.ip`

`instance`, `instance_id`, `region`, `has_public_ip`, `public_ip`,
`private_ip`, `warnings`.

`public_ip` is `null` and `has_public_ip` is `false` when there is none. This is
the one place a `null` is deliberate: absence is the answer, not a gap.

### `vm.ssh`

`instance`, `instance_id`, `region`, `host`, `user`, `identity_file`,
`command` (the argv array), `launched`, `exit_code`, `warnings`.

Under `--json`, `launched` is always `false`.

### `vm.create`

`instance`, `instance_id`, `region`, `availability_domain`, `shape`, `ocpus`,
`memory_gb`, `image_id`, `image_name`, `lifecycle_state`, `public_ip`,
`private_ip`, `nsg_id`, `nsg_verified`, `ssh_reachable`, `ssh_command`,
`created`, `warnings`.

`created` records every OCI object this operation made (`vcn_id`, `subnet_id`,
`internet_gateway_id`, `nsg_id`, `instance_id`), so a script can clean up after
a partial failure.

### `vm.delete`

`instance`, `instance_id`, `region`, `lifecycle_state`, `verified`, `resources`
(array of `kind`, `id`, `name`, `ownership`, `outcome`, `reason`), `warnings`.

`outcome` is `deleted`, `retained`, or `failed`. Every considered resource
appears, including the ones deliberately left alone.

### `vm.start`, `vm.stop`, `vm.reboot`

`instance`, `instance_id`, `region`, `action`, `state_before`, `state_after`,
`reached_target`, `no_op`, `warnings`.

### `vm.net.show`

`instance`, `instance_id`, `region`, `exposure`, `unavailable`, `warnings`.

`exposure` carries `vnic_id`, `private_ip`, `subnet_id`, `subnet_name`,
`subnet_cidr`, `vcn_id`, `internet` (`public_ip`, `has_default_route`,
`internet_gateway_id`, `internet_gateway_enabled`, `reachable`, `reason`),
`attached_nsgs`, `subnet_security_lists`, `rules`, and `warnings`.

Each entry of `rules` carries `rule_id`, `protocol`, `ports`, `source`,
`source_cidr`, `source_type`, `stateless`, `description`, and `origin`.
`origin` is the provenance: `kind` (`network_security_group` or
`security_list`), `id`, `name`, and `ownership`.

`exposure` is absent when it could not be computed; `unavailable` then says why.
An absent `exposure` never means "nothing is exposed".

### `vm.net.audit`

`instance`, `instance_id`, `region`, `exposure`, `audit`, `unavailable`,
`warnings`.

`audit` carries `findings` (array of `id`, `severity`, `title`, `detail`,
`origin`, `remediation`), `highest_severity`, and `internet_reachable`.

`severity` is `info`, `warning`, or `critical`. There is deliberately **no
numeric score**: a number would look like a measurement and would hide the one
thing that matters, which is the object to change.

Finding `id` values are stable: `ssh_open_to_internet`,
`sensitive_port_open_to_internet`, `all_ports_open_to_internet`,
`broad_source_range`, `inherited_subnet_exposure`, `no_managed_instance_nsg`,
`rules_without_reachability`, `no_ingress_rules`, `stateless_rule`,
`unrecognised_nsg_ownership`.

### `vm.net.open`, `vm.net.close`

`instance`, `instance_id`, `region`, `rule`, `source`, `nsg_id`, `nsg_name`,
`nsg_created`, `verified`, `residual_exposure`, `warnings`.

`verified` reports whether the intended effect was confirmed against a fresh
read of OCI, not merely that the write was accepted.

`residual_exposure` lists what still allows the port after a `close`. An empty
array means nothing else does.
