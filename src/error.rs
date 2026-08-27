//! The product error model.
//!
//! Every operational failure is classified into an [`ErrorKind`] so that the
//! human renderer can explain what to do next, the JSON renderer can emit a
//! stable structure, and the process can exit with a documented code.
//!
//! Nothing in this module ever carries secret material: OCI responses are
//! reduced to a status, an error code, a service message, and a request id
//! before an [`Error`] is built.

use std::{fmt, process::ExitCode};

use serde::Serialize;

/// Stable process exit codes.
///
/// Kept deliberately small; scripts branch on category, not on individual
/// failure modes. Documented in `docs/COMMANDS.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum ExitCodeKind {
    /// The command did what was asked.
    Success = 0,
    /// The command failed for a reason with no more specific category.
    Failure = 1,
    /// The user supplied something invalid. Matches clap's usage-error code.
    InvalidInput = 2,
    /// Configuration, credentials, or signing could not be used.
    Configuration = 3,
    /// OCI accepted the identity but refused the operation.
    Permission = 4,
    /// The safety policy refused to proceed.
    Safety = 5,
    /// A transient network, timeout, or throttling condition.
    Transient = 6,
    /// A mutation partially applied and needs operator attention.
    Partial = 7,
}

impl ExitCodeKind {
    #[must_use]
    pub fn code(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub fn exit_code(self) -> ExitCode {
        ExitCode::from(self.code())
    }
}

/// What category of thing went wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// Configuration is missing, malformed, or unusable.
    Configuration,
    /// The request could not be signed, or OCI rejected the signature.
    Authentication,
    /// OCI authenticated the caller but denied the operation.
    Authorization,
    /// The addressed OCI resource does not exist.
    NotFound,
    /// OCI reported a conflicting or incompatible state.
    Conflict,
    /// OCI throttled the request.
    RateLimited,
    /// OCI returned a server-side failure.
    TransientServer,
    /// The network could not be used (DNS, connect, TLS, reset).
    Network,
    /// An operation exceeded its deadline.
    Timeout,
    /// The user supplied an invalid value.
    InvalidInput,
    /// A name matched more than one resource.
    Ambiguous,
    /// The safety policy refused the operation.
    PolicyRejected,
    /// Free eligibility could not be proven, so the operation failed closed.
    BillingUncertain,
    /// The resource is in a state this operation cannot act on.
    UnsupportedState,
    /// A multi-step mutation stopped part-way through.
    PartialMutation,
    /// An external program (for example `ssh`) failed or is missing.
    ExternalTool,
    /// OCI returned a response this client could not understand.
    MalformedResponse,
}

impl ErrorKind {
    /// The process exit code this category maps to.
    #[must_use]
    pub fn exit_code_kind(self) -> ExitCodeKind {
        match self {
            Self::Configuration | Self::Authentication => ExitCodeKind::Configuration,
            Self::Authorization => ExitCodeKind::Permission,
            Self::InvalidInput | Self::Ambiguous => ExitCodeKind::InvalidInput,
            Self::PolicyRejected | Self::BillingUncertain => ExitCodeKind::Safety,
            Self::RateLimited | Self::TransientServer | Self::Network | Self::Timeout => {
                ExitCodeKind::Transient
            }
            Self::PartialMutation => ExitCodeKind::Partial,
            Self::NotFound
            | Self::Conflict
            | Self::UnsupportedState
            | Self::ExternalTool
            | Self::MalformedResponse => ExitCodeKind::Failure,
        }
    }

    /// Stable machine-readable identifier used in JSON output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::Authentication => "authentication",
            Self::Authorization => "authorization",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::RateLimited => "rate_limited",
            Self::TransientServer => "transient_server",
            Self::Network => "network",
            Self::Timeout => "timeout",
            Self::InvalidInput => "invalid_input",
            Self::Ambiguous => "ambiguous",
            Self::PolicyRejected => "policy_rejected",
            Self::BillingUncertain => "billing_uncertain",
            Self::UnsupportedState => "unsupported_state",
            Self::PartialMutation => "partial_mutation",
            Self::ExternalTool => "external_tool",
            Self::MalformedResponse => "malformed_response",
        }
    }

    /// Generic guidance used when a call site supplies nothing more specific.
    #[must_use]
    fn default_remediation(self) -> &'static str {
        match self {
            Self::Configuration => "run `oci-free config init`, then `oci-free doctor`",
            Self::Authentication => {
                "run `oci-free doctor`; the API key may not match the configured fingerprint"
            }
            Self::Authorization => {
                "ask a tenancy administrator for an IAM policy granting this operation"
            }
            Self::NotFound => "check the name or OCID, and that you are in the right region",
            Self::Conflict => "re-read the current state and retry once it settles",
            Self::RateLimited => "wait a moment and run the command again",
            Self::TransientServer => "retry shortly; if it persists, check the OCI status page",
            Self::Network => "check connectivity and any proxy configuration",
            Self::Timeout => "retry; if it persists the region may be degraded",
            Self::InvalidInput => "check the command's `--help` output",
            Self::Ambiguous => "pass the instance OCID instead of the display name",
            Self::PolicyRejected | Self::BillingUncertain => {
                "run `oci-free policy explain` to see the evidence behind this decision"
            }
            Self::UnsupportedState => "wait for the resource to reach a stable state",
            Self::PartialMutation => "re-run `oci-free vm info` and follow the recovery notes",
            Self::ExternalTool => "install the missing program, or pass an explicit path",
            Self::MalformedResponse => "re-run with `--json`; if it persists, please file an issue",
        }
    }
}

/// Context attached to an error that came from an OCI API call.
///
/// The request id is the single most useful thing to quote when asking Oracle
/// support about a failure, so it is preserved and surfaced.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OciContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
}

impl OciContext {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// A classified, user-presentable failure.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    /// What failed.
    message: String,
    /// Why it matters, when that is not obvious from `message`.
    context: Option<String>,
    /// The next corrective action.
    remediation: Option<String>,
    oci: OciContext,
}

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            context: None,
            remediation: None,
            oci: OciContext::default(),
        }
    }

    #[must_use]
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    #[must_use]
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    #[must_use]
    pub fn with_oci(mut self, oci: OciContext) -> Self {
        self.oci = oci;
        self
    }

    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub fn context(&self) -> Option<&str> {
        self.context.as_deref()
    }

    #[must_use]
    pub fn oci(&self) -> &OciContext {
        &self.oci
    }

    /// The corrective action, falling back to guidance for the category.
    #[must_use]
    pub fn remediation(&self) -> &str {
        self.remediation
            .as_deref()
            .unwrap_or_else(|| self.kind.default_remediation())
    }

    #[must_use]
    pub fn exit_code_kind(&self) -> ExitCodeKind {
        self.kind.exit_code_kind()
    }

    // Constructors for the categories used across the codebase. These exist so
    // call sites read as prose and cannot forget to classify a failure.

    pub fn configuration(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Configuration, message)
    }

    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidInput, message)
    }

    pub fn ambiguous(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Ambiguous, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotFound, message)
    }

    pub fn policy_rejected(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::PolicyRejected, message)
    }

    pub fn billing_uncertain(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::BillingUncertain, message)
    }

    pub fn unsupported_state(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::UnsupportedState, message)
    }

    pub fn partial_mutation(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::PartialMutation, message)
    }

    pub fn external_tool(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::ExternalTool, message)
    }

    pub fn malformed_response(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::MalformedResponse, message)
    }

    pub fn timeout(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Timeout, message)
    }

    pub fn network(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Network, message)
    }

    /// Render for a terminal: what failed, why, and what to do next.
    #[must_use]
    pub fn render_human(&self) -> String {
        let mut out = format!("error: {}\n", self.message);
        if let Some(context) = &self.context {
            out.push_str(&format!("  {context}\n"));
        }
        if let Some(request_id) = &self.oci.request_id {
            out.push_str(&format!("  OCI request id: {request_id}\n"));
        }
        out.push_str(&format!("  next: {}\n", self.remediation()));
        out
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

/// The result type used throughout the application layer.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::{Error, ErrorKind, ExitCodeKind, OciContext};

    /// Every kind must map to a code, and the mapping must stay stable: scripts
    /// branch on these numbers.
    #[test]
    fn exit_codes_are_stable() {
        let cases = [
            (ErrorKind::Configuration, 3),
            (ErrorKind::Authentication, 3),
            (ErrorKind::Authorization, 4),
            (ErrorKind::NotFound, 1),
            (ErrorKind::Conflict, 1),
            (ErrorKind::RateLimited, 6),
            (ErrorKind::TransientServer, 6),
            (ErrorKind::Network, 6),
            (ErrorKind::Timeout, 6),
            (ErrorKind::InvalidInput, 2),
            (ErrorKind::Ambiguous, 2),
            (ErrorKind::PolicyRejected, 5),
            (ErrorKind::BillingUncertain, 5),
            (ErrorKind::UnsupportedState, 1),
            (ErrorKind::PartialMutation, 7),
            (ErrorKind::ExternalTool, 1),
            (ErrorKind::MalformedResponse, 1),
        ];
        for (kind, expected) in cases {
            assert_eq!(
                kind.exit_code_kind().code(),
                expected,
                "{} must exit {expected}",
                kind.as_str()
            );
        }
        assert_eq!(ExitCodeKind::Success.code(), 0);
    }

    /// A safety refusal must never look like a transient failure, or automation
    /// will retry an operation the policy engine deliberately blocked.
    #[test]
    fn safety_refusals_are_not_retryable_codes() {
        for kind in [ErrorKind::PolicyRejected, ErrorKind::BillingUncertain] {
            assert_eq!(kind.exit_code_kind(), ExitCodeKind::Safety);
            assert_ne!(kind.exit_code_kind(), ExitCodeKind::Transient);
        }
    }

    #[test]
    fn machine_identifiers_are_unique() {
        let kinds = [
            ErrorKind::Configuration,
            ErrorKind::Authentication,
            ErrorKind::Authorization,
            ErrorKind::NotFound,
            ErrorKind::Conflict,
            ErrorKind::RateLimited,
            ErrorKind::TransientServer,
            ErrorKind::Network,
            ErrorKind::Timeout,
            ErrorKind::InvalidInput,
            ErrorKind::Ambiguous,
            ErrorKind::PolicyRejected,
            ErrorKind::BillingUncertain,
            ErrorKind::UnsupportedState,
            ErrorKind::PartialMutation,
            ErrorKind::ExternalTool,
            ErrorKind::MalformedResponse,
        ];
        let mut seen: Vec<&str> = kinds.iter().map(|k| k.as_str()).collect();
        seen.sort_unstable();
        let count = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), count, "error identifiers must be unique");
    }

    #[test]
    fn every_kind_has_actionable_guidance() {
        let error = Error::new(ErrorKind::Authorization, "denied");
        assert!(error.remediation().contains("policy"));

        let overridden = Error::new(ErrorKind::Authorization, "denied")
            .with_remediation("grant COMPUTE_INSTANCE_INSPECT");
        assert_eq!(overridden.remediation(), "grant COMPUTE_INSTANCE_INSPECT");
    }

    #[test]
    fn human_rendering_includes_the_request_id() {
        let error = Error::new(ErrorKind::Authorization, "not authorized")
            .with_context("the tenancy policy does not allow listing instances")
            .with_oci(OciContext {
                status: Some(403),
                code: Some("NotAuthorized".to_owned()),
                request_id: Some("abc123".to_owned()),
                operation: Some("ListInstances".to_owned()),
            });

        let rendered = error.render_human();
        assert!(rendered.contains("not authorized"));
        assert!(rendered.contains("the tenancy policy does not allow"));
        assert!(rendered.contains("OCI request id: abc123"));
        assert!(rendered.contains("next: "));
    }
}
