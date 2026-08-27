//! `oci-free doctor`: validate everything that can be checked without calling OCI.
//!
//! The checks in this module are deliberately offline. They catch the setup
//! mistakes that otherwise surface as an opaque `NotAuthenticated` response from
//! OCI, and they run before any credential is used against a live endpoint.

use serde::Serialize;
use url::Url;

use crate::{
    auth::{
        PrivateKey, RequestSigner,
        signer::{HttpMethod, SignatureInput},
    },
    config::{Config, ConfigOptions, Environment, RedactedConfig},
};

/// Version marker for the `--json` payload, so automation can detect changes.
pub const SCHEMA: &str = "oci-free.doctor/v0";

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

    checks.push(Check::skipped(
        "live_verification",
        "Live OCI verification",
        "not implemented yet; doctor currently validates local configuration only",
    ));

    DoctorReport::new(checks, Some(config.redacted()))
}

/// Checks that depend on a successfully loaded configuration.
const DEPENDENT_CHECKS: [(&str, &str); 5] = [
    ("key_file_permissions", "Private key file permissions"),
    ("private_key", "Private key"),
    ("key_fingerprint", "Key fingerprint"),
    ("request_signing", "Request signing"),
    ("live_verification", "Live OCI verification"),
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
fn self_test_url(config: &Config) -> Result<Url, url::ParseError> {
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
        out.push_str(
            "Local configuration looks usable. Live OCI verification is not available yet.\n",
        );
    } else {
        out.push_str("Local configuration is not usable yet. Fix the failures above and run oci-free doctor again.\n");
    }
    out
}

/// Render the report as stable JSON.
pub fn render_json(report: &DoctorReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

include!("doctor_tests.rs");
