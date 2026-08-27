//! `oci-free doctor`: prove the setup works, locally and then against OCI.
//!
//! Two phases, in this order:
//!
//! 1. **local** — configuration, key, fingerprint, permissions, and a signing
//!    self-test. These catch the mistakes that otherwise surface as an opaque
//!    `NotAuthenticated`, and they run before any credential touches the wire.
//! 2. **live** — one read per capability the product needs, so a user learns
//!    which IAM grant is missing *here* rather than half-way through `vm
//!    create`.
//!
//! Every live check is read-only. `doctor` never creates, modifies, or deletes
//! anything.
//!
//! An optional capability that is missing is a `WARN`, not a `FAIL`. A Free
//! Tier tenancy routinely lacks the Usage API grant, and failing `doctor` over
//! it would teach users that a red `doctor` is normal — which is exactly how a
//! real failure gets ignored.

use serde::Serialize;
use url::Url;

use crate::{
    auth::{
        PrivateKey, RequestSigner,
        signer::{HttpMethod, SignatureInput},
    },
    commands::context::CommandContext,
    config::{Config, ConfigOptions, Environment, RedactedConfig},
    domain::time::UtcDateTime,
    error::Result,
    oci::{
        compute::ComputeApi,
        identity::IdentityApi,
        limits::{LimitsApi, SERVICE_COMPUTE},
        network::NetworkApi,
        usage::{UsageApi, UsageQuery},
    },
};

/// Version marker for the `--json` payload, so automation can detect changes.
pub const SCHEMA: &str = "oci-free.doctor/v1";

/// Outcome of a single check.
///
/// Ordering matters: [`DoctorReport::status`] reports the most severe outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Skipped,
    Warn,
    Fail,
}

impl CheckStatus {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "ok",
            Self::Skipped => "skipped",
            Self::Warn => "warning",
            Self::Fail => "failed",
        }
    }
}

/// One diagnostic result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    /// Stable identifier for automation.
    pub id: &'static str,
    /// Short human-readable name.
    pub title: &'static str,
    pub status: CheckStatus,
    /// What was observed.
    pub detail: String,
    /// The next corrective action, when something needs fixing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl Check {
    fn new(id: &'static str, title: &'static str, status: CheckStatus, detail: String) -> Self {
        Self {
            id,
            title,
            status,
            detail,
            remediation: None,
        }
    }

    fn pass(id: &'static str, title: &'static str, detail: impl Into<String>) -> Self {
        Self::new(id, title, CheckStatus::Pass, detail.into())
    }

    fn skipped(id: &'static str, title: &'static str, detail: impl Into<String>) -> Self {
        Self::new(id, title, CheckStatus::Skipped, detail.into())
    }

    fn warn(
        id: &'static str,
        title: &'static str,
        detail: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self::new(id, title, CheckStatus::Warn, detail.into()).with_remediation(remediation.into())
    }

    fn fail(
        id: &'static str,
        title: &'static str,
        detail: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self::new(id, title, CheckStatus::Fail, detail.into()).with_remediation(remediation.into())
    }

    fn with_remediation(mut self, remediation: String) -> Self {
        self.remediation = Some(remediation);
        self
    }
}

/// The full result of a `doctor` run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorReport {
    pub schema: &'static str,
    /// The most severe status across all checks.
    pub status: CheckStatus,
    pub checks: Vec<Check>,
    /// Redacted configuration, present once configuration loading succeeds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<RedactedConfig>,
}

impl DoctorReport {
    fn new(checks: Vec<Check>, config: Option<RedactedConfig>) -> Self {
        // A skipped check never sets the overall status: a run where everything
        // that could be verified passed should report `pass`, not `skipped`.
        let status = checks
            .iter()
            .map(|check| check.status)
            .filter(|status| *status != CheckStatus::Skipped)
            .max()
            .unwrap_or(CheckStatus::Pass);
        Self {
            schema: SCHEMA,
            status,
            checks,
            config,
        }
    }

    /// Whether every check that ran was non-fatal.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.status != CheckStatus::Fail
    }
}

/// Run every offline check.
#[must_use]
pub fn run(env: &Environment, options: &ConfigOptions) -> DoctorReport {
    let mut checks = Vec::new();

    let config = match Config::load(env, options) {
        Ok(config) => {
            checks.push(Check::pass(
                "configuration",
                "Configuration",
                describe_configuration(&config),
            ));
            Some(config)
        }
        Err(error) => {
            checks.push(Check::fail(
                "configuration",
                "Configuration",
                error.to_string(),
                error.remediation(),
            ));
            None
        }
    };

    let Some(config) = config else {
        for (id, title) in DEPENDENT_CHECKS {
            checks.push(Check::skipped(
                id,
                title,
                "skipped because the configuration could not be loaded",
            ));
        }
        return DoctorReport::new(checks, None);
    };

    checks.push(check_key_file_permissions(&config));

    let key = match PrivateKey::from_pem_file(&config.key_file) {
        Ok(key) => {
            checks.push(Check::pass(
                "private_key",
                "Private key",
                format!(
                    "loaded an RSA private key from {}",
                    config.key_file.display()
                ),
            ));
            Some(key)
        }
        Err(error) => {
            checks.push(Check::fail(
                "private_key",
                "Private key",
                error.to_string(),
                error.remediation(),
            ));
            None
        }
    };

    match key {
        Some(key) => {
            checks.push(check_fingerprint(&config, &key));
            checks.push(check_request_signing(&config, key));
        }
        None => {
            checks.push(Check::skipped(
                "key_fingerprint",
                "Key fingerprint",
                "skipped because the private key could not be loaded",
            ));
            checks.push(Check::skipped(
                "request_signing",
                "Request signing",
                "skipped because the private key could not be loaded",
            ));
        }
    }

    DoctorReport::new(checks, Some(config.redacted()))
}

/// Run the local checks, then the live ones against OCI.
///
/// Live checks are skipped, not failed, when the local phase could not produce
/// usable credentials: there is nothing meaningful to ask OCI with.
pub async fn run_with_live(env: &Environment, options: &ConfigOptions) -> DoctorReport {
    let mut report = run(env, options);

    let local_ok = report
        .checks
        .iter()
        .all(|check| check.status != CheckStatus::Fail);

    if !local_ok {
        for (id, title) in LIVE_CHECKS {
            report.checks.push(Check::skipped(
                id,
                title,
                "skipped because the local configuration is not usable yet",
            ));
        }
        return DoctorReport::new(report.checks, report.config);
    }

    match CommandContext::load(env, options) {
        Ok(context) => report.checks.extend(live_checks(&context).await),
        Err(error) => {
            report.checks.push(Check::fail(
                "live_authentication",
                "Signed authentication",
                error.message().to_owned(),
                error.remediation().to_owned(),
            ));
            for (id, title) in LIVE_CHECKS.iter().skip(1) {
                report.checks.push(Check::skipped(
                    id,
                    title,
                    "skipped because no OCI client could be built",
                ));
            }
        }
    }

    DoctorReport::new(report.checks, report.config)
}

/// Every live read `doctor` performs, in the order it performs them.
const LIVE_CHECKS: [(&str, &str); 8] = [
    ("live_authentication", "Signed authentication"),
    ("live_tenancy", "Tenancy access"),
    ("live_home_region", "Home region"),
    ("live_availability_domains", "Availability domains"),
    ("live_compute_read", "Compute read permission"),
    ("live_network_read", "Networking read permission"),
    ("live_limits_read", "Service limits permission"),
    ("live_usage_read", "Usage and cost permission"),
];

/// Read-only probes against the live tenancy.
async fn live_checks(context: &CommandContext) -> Vec<Check> {
    let mut checks = Vec::new();
    let tenancy = context.tenancy();
    let identity = IdentityApi::new(context.client());

    // The tenancy read doubles as the authentication check: if OCI accepted the
    // signature, the credentials work, whatever else may be denied.
    let tenancy_record = identity.get_tenancy(tenancy).await;
    match &tenancy_record {
        Ok(record) => {
            checks.push(Check::pass(
                "live_authentication",
                "Signed authentication",
                "OCI accepted the request signature",
            ));
            checks.push(Check::pass(
                "live_tenancy",
                "Tenancy access",
                format!(
                    "read tenancy {} ({})",
                    tenancy.redacted(),
                    record.name.as_deref().unwrap_or("unnamed")
                ),
            ));
        }
        Err(error) => {
            let (id, title) = if error.kind() == crate::error::ErrorKind::Authorization {
                // Authenticated but denied: the signature worked.
                checks.push(Check::pass(
                    "live_authentication",
                    "Signed authentication",
                    "OCI accepted the request signature but denied the tenancy read",
                ));
                ("live_tenancy", "Tenancy access")
            } else {
                ("live_authentication", "Signed authentication")
            };
            checks.push(Check::fail(
                id,
                title,
                error.message().to_owned(),
                error.remediation().to_owned(),
            ));
            if id == "live_authentication" {
                checks.push(Check::skipped(
                    "live_tenancy",
                    "Tenancy access",
                    "skipped because OCI did not accept the credentials",
                ));
            }
        }
    }

    // The home region is where Free Tier capacity lives, so failing to resolve
    // it is a genuine problem rather than an optional extra.
    let home_region = identity.home_region(tenancy).await;
    match &home_region {
        Ok(region) => {
            let same = region.to_string() == context.region().to_string();
            checks.push(if same {
                Check::pass(
                    "live_home_region",
                    "Home region",
                    format!("this profile targets the home region {region}"),
                )
            } else {
                Check::warn(
                    "live_home_region",
                    "Home region",
                    format!(
                        "this profile targets {}, but the tenancy's home region is {region}",
                        context.region()
                    ),
                    format!("set 'region' to {region}, or pass --profile for a profile that does"),
                )
            });
        }
        Err(error) => checks.push(Check::fail(
            "live_home_region",
            "Home region",
            error.message().to_owned(),
            error.remediation().to_owned(),
        )),
    }

    // Availability domains come from the home region, which is where a launch
    // would actually happen.
    let home_context = match &home_region {
        Ok(region) => context.switch_region(region.clone()),
        Err(_) => context.switch_region(context.region().clone()),
    };
    match IdentityApi::new(home_context.client())
        .list_availability_domains(tenancy)
        .await
    {
        Ok(domains) if domains.is_empty() => checks.push(Check::warn(
            "live_availability_domains",
            "Availability domains",
            "OCI reported no availability domains for this tenancy",
            "check the tenancy's region subscriptions in the OCI Console",
        )),
        Ok(domains) => checks.push(Check::pass(
            "live_availability_domains",
            "Availability domains",
            format!(
                "{} domain(s) available: {}",
                domains.len(),
                domains
                    .iter()
                    .map(|domain| domain.name.as_str())
                    .collect::<Vec<&str>>()
                    .join(", ")
            ),
        )),
        Err(error) => checks.push(Check::fail(
            "live_availability_domains",
            "Availability domains",
            error.message().to_owned(),
            error.remediation().to_owned(),
        )),
    }

    checks.push(compute_check(context).await);
    checks.push(network_check(context).await);
    checks.push(limits_check(context).await);
    checks.push(usage_check(context).await);

    checks
}

async fn compute_check(context: &CommandContext) -> Check {
    match ComputeApi::new(context.client())
        .list_instances(context.tenancy())
        .await
    {
        Ok(instances) => Check::pass(
            "live_compute_read",
            "Compute read permission",
            format!("listed {} instance(s)", instances.len()),
        ),
        Err(error) => Check::fail(
            "live_compute_read",
            "Compute read permission",
            error.message().to_owned(),
            "ask for `allow group <g> to read instance-family in tenancy`",
        ),
    }
}

async fn network_check(context: &CommandContext) -> Check {
    match NetworkApi::new(context.client())
        .list_vcns(context.tenancy())
        .await
    {
        Ok(vcns) => Check::pass(
            "live_network_read",
            "Networking read permission",
            format!("listed {} VCN(s)", vcns.len()),
        ),
        Err(error) => Check::fail(
            "live_network_read",
            "Networking read permission",
            error.message().to_owned(),
            "ask for `allow group <g> to read virtual-network-family in tenancy`; without it              `vm net show` cannot report effective exposure",
        ),
    }
}

/// Service limits are how remaining Free Tier capacity is corroborated.
///
/// Useful but not load-bearing: the capacity model works from live usage and
/// the policy snapshot, so a denial here is a warning.
async fn limits_check(context: &CommandContext) -> Check {
    match LimitsApi::new(context.client())
        .list_limit_values(context.tenancy(), SERVICE_COMPUTE)
        .await
    {
        Ok(values) => Check::pass(
            "live_limits_read",
            "Service limits permission",
            format!("read {} compute limit value(s)", values.len()),
        ),
        Err(error) => Check::warn(
            "live_limits_read",
            "Service limits permission",
            format!("service limits are unavailable: {}", error.message()),
            "optional: `allow group <g> to read limits in tenancy` makes `account limits` work",
        ),
    }
}

/// Cost is genuinely optional, and very commonly denied.
async fn usage_check(context: &CommandContext) -> Check {
    let query = UsageQuery::billing_period(context.tenancy(), UtcDateTime::now());
    match UsageApi::new(context.client())
        .request_summarized_usages(&query)
        .await
    {
        Ok(aggregation) => Check::pass(
            "live_usage_read",
            "Usage and cost permission",
            match aggregation.total() {
                Some(total) => format!("read the current billing period; total {total:.2}"),
                None => "read the current billing period; OCI reported no amount".to_owned(),
            },
        ),
        Err(error) if error.kind() == crate::error::ErrorKind::Authorization => Check::warn(
            "live_usage_read",
            "Usage and cost permission",
            "this tenancy does not grant the Usage API, so `oci-free cost` will report cost as              unavailable rather than as zero",
            "optional: `allow group <g> to read usage-report in tenancy`",
        ),
        Err(error) => Check::warn(
            "live_usage_read",
            "Usage and cost permission",
            format!("usage could not be read: {}", error.message()),
            error.remediation().to_owned(),
        ),
    }
}

/// Checks that depend on a successfully loaded configuration.
const DEPENDENT_CHECKS: [(&str, &str); 4] = [
    ("key_file_permissions", "Private key file permissions"),
    ("private_key", "Private key"),
    ("key_fingerprint", "Key fingerprint"),
    ("request_signing", "Request signing"),
];

fn describe_configuration(config: &Config) -> String {
    let overrides = config.origin.env_overrides.join(", ");
    let Some(path) = config.origin.file.as_ref() else {
        return format!(
            "no configuration file found; loaded {overrides} from the environment for region {}",
            config.region
        );
    };

    let source = format!(
        "loaded profile [{}] of {} for region {}",
        config.origin.profile,
        path.display(),
        config.region
    );
    if overrides.is_empty() {
        source
    } else {
        format!("{source}; overridden from the environment: {overrides}")
    }
}

fn check_fingerprint(config: &Config, key: &PrivateKey) -> Check {
    if config.fingerprint == *key.fingerprint() {
        Check::pass(
            "key_fingerprint",
            "Key fingerprint",
            format!(
                "the private key matches the configured fingerprint {}",
                config.fingerprint
            ),
        )
    } else {
        Check::fail(
            "key_fingerprint",
            "Key fingerprint",
            format!(
                "the configured fingerprint is {} but the private key's fingerprint is {}",
                config.fingerprint,
                key.fingerprint()
            ),
            format!(
                "set 'fingerprint' to {}, or point 'key_file' at the key uploaded to OCI",
                key.fingerprint()
            ),
        )
    }
}

fn check_request_signing(config: &Config, key: PrivateKey) -> Check {
    let signer = match RequestSigner::from_config(config, key.clone()) {
        Ok(signer) => signer,
        Err(error) => {
            return Check::fail(
                "request_signing",
                "Request signing",
                error.to_string(),
                error.remediation(),
            );
        }
    };

    let Ok(url) = self_test_url(config) else {
        return Check::fail(
            "request_signing",
            "Request signing",
            format!(
                "could not build a self-test URL for region {}",
                config.region
            ),
            "check that 'region' is a valid OCI region identifier",
        );
    };

    match signer.sign_at(
        &SignatureInput::new(HttpMethod::Get, &url),
        std::time::SystemTime::now(),
    ) {
        Ok(signed) if key.verify(signed.signing_string.as_bytes(), &signed.signature) => {
            // The report is meant to be pasteable, so the keyId is shown in the
            // same redacted form as the rest of the configuration.
            Check::pass(
                "request_signing",
                "Request signing",
                format!(
                    "signed and verified a test request as {}/{}/{}",
                    config.tenancy.redacted(),
                    config.user.redacted(),
                    config.fingerprint
                ),
            )
        }
        Ok(_) => Check::fail(
            "request_signing",
            "Request signing",
            "the generated signature did not verify against the key's public half",
            "regenerate the API key pair and upload the public key in the OCI Console",
        ),
        Err(error) => Check::fail(
            "request_signing",
            "Request signing",
            error.to_string(),
            error.remediation(),
        ),
    }
}

/// A representative OCI URL used only to exercise the signing path locally.
///
/// Nothing is sent. Real endpoint construction arrives with the signed transport
/// layer; this keeps the self-test shaped like a request the tool will make.
fn self_test_url(config: &Config) -> std::result::Result<Url, url::ParseError> {
    Url::parse(&format!(
        "https://identity.{}.oraclecloud.com/20160918/tenancies/{}",
        config.region, config.tenancy
    ))
}

#[cfg(unix)]
fn check_key_file_permissions(config: &Config) -> Check {
    use std::os::unix::fs::PermissionsExt as _;

    let path = &config.key_file;
    let Ok(metadata) = std::fs::metadata(path) else {
        return Check::skipped(
            "key_file_permissions",
            "Private key file permissions",
            format!("skipped because {} could not be inspected", path.display()),
        );
    };

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 == 0 {
        Check::pass(
            "key_file_permissions",
            "Private key file permissions",
            format!(
                "{} is only readable by its owner ({mode:04o})",
                path.display()
            ),
        )
    } else {
        Check::warn(
            "key_file_permissions",
            "Private key file permissions",
            format!(
                "{} is readable by other users on this machine ({mode:04o})",
                path.display()
            ),
            format!("run: chmod 600 {}", path.display()),
        )
    }
}

#[cfg(not(unix))]
fn check_key_file_permissions(config: &Config) -> Check {
    let _ = config;
    Check::skipped(
        "key_file_permissions",
        "Private key file permissions",
        "skipped because this platform does not expose POSIX file modes",
    )
}

/// Render the report for a terminal.
#[must_use]
pub fn render_human(report: &DoctorReport) -> String {
    let mut out = String::new();
    for check in &report.checks {
        out.push_str(&format!(
            "[{status:>7}] {title}: {detail}\n",
            status = check.status.label(),
            title = check.title,
            detail = check.detail
        ));
        if let Some(remediation) = &check.remediation {
            out.push_str(&format!("           next: {remediation}\n"));
        }
    }

    out.push('\n');
    if report.is_healthy() {
        let warned = report
            .checks
            .iter()
            .any(|check| check.status == CheckStatus::Warn);
        out.push_str(if warned {
            "Everything required works. The warnings above are optional capabilities; commands \
             that need them will say so rather than failing.\n"
        } else {
            "Everything checked is working.\n"
        });
    } else {
        out.push_str(
            "This setup is not usable yet. Fix the failures above and run oci-free doctor again.\n",
        );
    }
    out
}

/// Whether the report proves the tool can do useful work.
///
/// Used by the caller to decide the process exit code.
pub fn is_usable(report: &DoctorReport) -> Result<()> {
    if report.is_healthy() {
        return Ok(());
    }
    let failures: Vec<&str> = report
        .checks
        .iter()
        .filter(|check| check.status == CheckStatus::Fail)
        .map(|check| check.title)
        .collect();
    Err(
        crate::error::Error::configuration("this setup is not usable yet")
            .with_context(format!("failing checks: {}", failures.join(", ")))
            .with_remediation("fix the failures reported by `oci-free doctor`"),
    )
}

/// Render the report as stable JSON.
pub fn render_json(report: &DoctorReport) -> std::result::Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

include!("doctor_tests.rs");
