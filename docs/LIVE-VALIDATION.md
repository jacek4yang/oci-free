# Live validation

The automated test suite runs entirely offline against an in-process HTTPS
server. That proves the request oci-free *builds* is correct — signing,
retries, pagination, error decoding, plan gating, ownership rules — but it
cannot prove OCI *accepts* it.

This page is the checklist for closing that gap against a real tenancy. It is
written to be run by a person with an OCI account, in order, and it says at each
step what should happen and what a failure would mean.

## What CI does and does not cover

**Covered offline, with no credentials:**

- OCI Signature v1 construction, pinned against deterministic vectors and
  verified against the key's public half;
- the fingerprint derivation, pinned against a value computed independently
  with OpenSSL;
- every response model, decoded from representative fixtures;
- retry and idempotency behaviour, including that an unsafe write is never
  replayed;
- pagination, body bounds, redirect refusal, and that no error path leaks the
  `Authorization` header;
- the whole policy engine and capacity arithmetic;
- effective-exposure composition across NSGs and Security Lists;
- that a rejected or unconfirmed plan issues **zero** write requests;
- ownership rules, including that a lookalike name is never adopted;
- partial-failure compensation, including that it removes only what the
  operation created;
- the JSON contract, field by field.

**Not covered, and only provable against a real tenancy:**

- that OCI accepts the signature over the wire;
- that request bodies match what the live API expects today;
- that the endpoints and API versions are correct for a real realm;
- how the live service behaves under capacity exhaustion and throttling;
- end-to-end timing of asynchronous operations.

CI is and must stay credential-free. No workflow in this repository makes an OCI
API call.

## Before you start

Use a **throwaway tenancy** if you can. Failing that, accept that this checklist
creates and destroys real resources.

```console
$ oci-free doctor
```

Everything must pass, except that `Service limits permission` and
`Usage and cost permission` may warn. Note which ones warn — the read-only
section below tells you what that changes.

Record the starting state so you can prove you got back to it:

```console
$ oci-free vm list --json > before-instances.json
$ oci-free free list --json > before-capacity.json
```

## Phase 1 — read-only

Nothing here changes anything. Safe on a production tenancy.

| # | Command | Expected |
| --- | --- | --- |
| 1.1 | `oci-free doctor` | Local checks pass; live checks report your real permissions. |
| 1.2 | `oci-free doctor --json` | Valid JSON; no key material, no `Authorization`; tenancy redacted. |
| 1.3 | `oci-free account info` | Correct tenancy name, home region, and availability domains. Warns if your profile's region is not the home region. |
| 1.4 | `oci-free account limits` | Free Tier limits with real values. `--all` shows more. |
| 1.5 | `oci-free account usage` | Real usage, or a clear "unavailable" if the grant is missing. |
| 1.6 | `oci-free cost` | Your real figure. **If the grant is missing it must say unavailable, never `0.00`.** |
| 1.7 | `oci-free free list` | Allowances, live `billingType` per shape, and remaining capacity that matches the Console. |
| 1.8 | `oci-free status` | Everything above in one screen, degrading section by section for any missing permission. |
| 1.9 | `oci-free policy explain VM.Standard.A1.Flex --ocpus 4 --memory 24` | Full evidence chain. Allowed or blocked according to your real usage. |
| 1.10 | `oci-free policy explain VM.Standard3.Flex` | Blocked, classification `Paid`. |
| 1.11 | `oci-free vm list` | Matches the Console. |
| 1.12 | `oci-free vm info <instance>` | Shape, image, addresses, NSGs, boot volume all match the Console. |
| 1.13 | `oci-free vm ip <instance>` | The bare address. For an instance with none: an explicit statement, not an error. |
| 1.14 | `oci-free vm net <instance> show` | **Compare every rule against the Console**, including subnet Security List rules. This is the highest-value check on the page. |
| 1.15 | `oci-free vm net <instance> audit` | Findings match reality. Exits 5 if anything is at warning or above. |

Cross-check 1.14 by hand. The exposure model is the part where being subtly
wrong would be most dangerous, and the Console is the reference.

## Phase 2 — safety refusals

These must all refuse, and none may send a write request. Watch the OCI audit
log to confirm nothing arrived.

| # | Command | Expected |
| --- | --- | --- |
| 2.1 | `oci-free vm create --shape VM.Standard3.Flex --non-interactive --yes` | Exit 5, `policy_rejected`, paid shape. |
| 2.2 | `oci-free vm create --shape free:arm --ocpus 200 --memory 12 --non-interactive --yes` | Exit 2, outside the shape's bounds. |
| 2.3 | `oci-free vm create --shape free:arm --ocpus 1 --memory 900 --non-interactive --yes` | Exit 2, memory bounds. |
| 2.4 | Fill the ARM allowance, then request more | Exit 5, with the arithmetic shown. |
| 2.5 | `oci-free vm net <instance> open 443/tcp --non-interactive` | Exit 2, names `--source`. |
| 2.6 | `oci-free vm create --shape free:arm --non-interactive` (no `--yes`) | Exit 2, names `--yes`. Nothing created. |
| 2.7 | Any interactive command with stdin closed (`< /dev/null`) | Fails immediately. **Must not hang.** |

## Phase 3 — creation

Now real resources appear.

1. **Create an instance.**

   ```console
   $ oci-free vm create \
       --shape free:arm --ocpus 1 --memory 6 \
       --name live-test-1 \
       --ssh-key ~/.ssh/id_ed25519.pub \
       --ssh-source <your address>/32
   ```

   Confirm at the prompt. Check that the plan showed the managed network
   (created or reused), the NSG, and a billing risk of `none`.

   Afterwards verify in the Console: the VCN, subnet, gateway, route, NSG, and
   instance all exist, and every one oci-free created carries
   `oci-free:managed=created`.

2. **Verify the result matches.** `vm info live-test-1` against the Console:
   shape, OCPU, memory, image, private IP, public IP, NSG attachment.

3. **Connect.** `oci-free vm ssh live-test-1`. Then `--print` and confirm the
   printed command is the same one.

4. **Idempotency.** Re-run the identical `vm create --yes`. It must not create a
   second instance; OCI's retry token collapses the duplicate.

5. **Reuse.** Create a second instance if capacity allows. The managed VCN and
   subnet must be **reused**, not duplicated, and it must get its own NSG.

## Phase 4 — networking

1. `oci-free vm net live-test-1 open 443/tcp --source 0.0.0.0/0`. Confirm in the
   Console that **only the instance NSG changed** and no Security List was
   touched.
2. `vm net show` — the new rule appears with the NSG as its origin.
3. `vm net audit` — flags the world-open port, exits 5.
4. Add a `22/tcp` rule from `0.0.0.0/0` to the **subnet Security List** by hand
   in the Console.
5. `oci-free vm net live-test-1 close 22/tcp`. It must remove the NSG rule and
   then **report that 22/tcp is still reachable via the Security List**. This is
   the single most important behaviour on this page.
6. Remove that Security List rule by hand again.
7. Attach an NSG of your own to the instance. `close` must refuse to touch it.

## Phase 5 — lifecycle

| # | Command | Expected |
| --- | --- | --- |
| 5.1 | `vm stop live-test-1` | Reaches `STOPPED`. Warns that capacity is not released. |
| 5.2 | `free list` | Capacity unchanged — the stopped instance still holds it. |
| 5.3 | `vm stop live-test-1` again | Reported no-op, no request sent. |
| 5.4 | `vm start live-test-1` | Reaches `RUNNING`. |
| 5.5 | `vm reboot live-test-1` | Returns to `RUNNING`. |

## Phase 6 — deletion

1. `oci-free vm delete live-test-1`. Check the plan names the boot volume, the
   NSG, and the shared subnet with the right fate for each.
2. Choose to delete the boot volume. Verify in the Console that it is gone.
3. Confirm the **subnet and VCN still exist** — a shared resource is never
   removed with one instance.
4. Delete the second instance with `--keep-boot-volume`, and confirm the volume
   survives and still consumes storage allowance.
5. Delete that retained volume by hand.
6. `oci-free free list` must match `before-capacity.json`.
7. Remove the managed VCN, subnet, gateway, and any NSGs by hand if you want a
   clean tenancy. oci-free never deletes shared managed infrastructure for you.

## Phase 7 — degraded conditions

| # | Condition | Expected |
| --- | --- | --- |
| 7.1 | Remove the `usage-report` grant | `cost` says unavailable, never `0.00`. `status` still reports everything else. |
| 7.2 | Remove the `read limits` grant | `account limits` degrades with a named warning. `doctor` warns, does not fail. |
| 7.3 | Remove `virtual-network-family` read | `vm net show` reports exposure unavailable. It must **never** report "nothing is exposed". |
| 7.4 | Set the host clock 10 minutes fast | 401, and the error mentions the clock. |
| 7.5 | Point at a region the tenancy is not subscribed to | A clear error, not a hang. |
| 7.6 | Run behind a proxy that returns 403 | Attributed to a proxy, not to your IAM policy, because there is no OCI request id. |

## Optional opt-in live tests

If a repeatable harness is wanted later, the shape it must take:

- gated behind an explicit environment variable, for example
  `OCI_FREE_LIVE_TESTS=1`, and `#[ignore]` by default so a plain `cargo test`
  never touches a network;
- read-only unless a second, separate variable authorises writes against a
  tenancy the operator has designated for the purpose;
- never part of the normal CI workflow, which stays credential-free.

Until then, this checklist is the live validation, and it is run by a person.

## Recording a run

Note the oci-free version, the commit, the tenancy realm and home region, the
date, which phases were run, and anything that did not match. A run against a
tenancy whose permissions differ from yours is a different data point and worth
recording separately.
