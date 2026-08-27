# Security Model

`oci-free` manages cloud resources and therefore treats billing safety, credential handling, and network exposure as security properties.

## Credentials

- API private keys must remain local and must never be logged.
- Diagnostics must redact secrets and sensitive configuration values.
- Credential files should use restrictive host permissions where the platform supports them.
- The project must not require the official OCI CLI, Python, Node.js, or Java at runtime.

## Billing safety

Strict mode fails closed. A resource that cannot be proven Always Free is blocked by default. Every potentially billable mutation requires a preflight assessment and explicit confirmation in interactive mode.

A non-zero current-period OCI cost is always surfaced prominently.

## Network safety

Normal ingress changes are instance-scoped and implemented with a managed Network Security Group attached to the target instance VNIC.

Effective exposure must account for both NSGs and subnet Security Lists. Removing an NSG rule is not reported as "closed" until the effective policy is recomputed.

## Destructive operations

Termination and cleanup commands must distinguish the instance from related resources such as boot volumes, reserved public IPs, and managed NSGs. The user should see exactly which resources will be deleted, retained, or released before confirmation.

## Reporting vulnerabilities

Until a dedicated private security reporting channel is configured, do not publish credentials, tenancy identifiers, or exploitable secrets in public issues. Use GitHub's private vulnerability reporting feature once enabled for the repository.
