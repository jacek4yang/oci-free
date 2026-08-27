//! The stable machine-readable output contract.
//!
//! Every `--json` response is wrapped in [`Envelope`] so that scripts have one
//! shape to parse whether a command succeeded or failed. Command payloads are
//! purpose-built serializable types, never internal structs serialized by
//! accident, so refactoring the implementation cannot silently change the
//! public contract.
//!
//! The schema is documented in `docs/JSON.md`. Changing any field name, enum
//! spelling, or nesting here is a breaking change to that contract.

use serde::Serialize;

use crate::error::{Error, ErrorKind, OciContext};

/// The JSON contract version. Bumped only for a breaking change.
pub const SCHEMA_VERSION: &str = "1";

/// The serialized form of a failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorPayload {
    /// Stable category identifier, for example `authorization`.
    pub kind: &'static str,
    /// What failed.
    pub message: String,
    /// Why it matters. Absent when the message says everything.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// The next corrective action. Always present.
    pub remediation: String,
    /// OCI call details, absent for purely local failures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oci: Option<OciContext>,
    /// The process exit code that accompanies this error.
    pub exit_code: u8,
}

impl ErrorPayload {
    #[must_use]
    pub fn from_error(error: &Error) -> Self {
        let oci = if error.oci().is_empty() {
            None
        } else {
            Some(error.oci().clone())
        };
        Self {
            kind: error.kind().as_str(),
            message: error.message().to_owned(),
            context: error.context().map(str::to_owned),
            remediation: error.remediation().to_owned(),
            oci,
            exit_code: error.exit_code_kind().code(),
        }
    }

    #[must_use]
    pub fn kind_matches(&self, kind: ErrorKind) -> bool {
        self.kind == kind.as_str()
    }
}

/// The wrapper around every `--json` response.
///
/// Exactly one of `data` and `error` is present.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Envelope<T> {
    /// Contract version, currently `"1"`.
    pub schema_version: &'static str,
    /// Dotted command identifier, for example `vm.net.show`.
    pub command: String,
    /// The command payload on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    /// The failure on error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorPayload>,
    /// Non-fatal advisories. Always present, possibly empty, so consumers can
    /// iterate it without a null check.
    pub warnings: Vec<String>,
}

impl<T: Serialize> Envelope<T> {
    #[must_use]
    pub fn success(command: impl Into<String>, data: T) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            command: command.into(),
            data: Some(data),
            error: None,
            warnings: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_warnings(mut self, warnings: Vec<String>) -> Self {
        self.warnings = warnings;
        self
    }

    /// Serialize to the pretty form printed on stdout.
    pub fn render(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl Envelope<()> {
    /// A failure envelope. Typed as `Envelope<()>` because there is no payload.
    #[must_use]
    pub fn failure(command: impl Into<String>, error: &Error) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            command: command.into(),
            data: None,
            error: Some(ErrorPayload::from_error(error)),
            warnings: Vec::new(),
        }
    }
}

/// Render a failure envelope, falling back to a hand-built document if
/// serialization somehow fails, so `--json` always emits parseable JSON.
#[must_use]
pub fn render_failure(command: &str, error: &Error) -> String {
    Envelope::failure(command, error)
        .render()
        .unwrap_or_else(|_| {
            format!(
                "{{\"schema_version\":\"{SCHEMA_VERSION}\",\"command\":\"{command}\",\
             \"error\":{{\"kind\":\"{}\",\"message\":\"output serialization failed\",\
             \"remediation\":\"please file an issue\",\"exit_code\":1}},\"warnings\":[]}}",
                error.kind().as_str()
            )
        })
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{Envelope, SCHEMA_VERSION, render_failure};
    use crate::error::{Error, ErrorKind, OciContext};

    #[test]
    fn success_envelope_has_the_documented_shape() {
        let envelope = Envelope::success("vm.list", json!({"instances": []}));
        let value: Value = serde_json::from_str(&envelope.render().expect("render")).expect("json");

        assert_eq!(value["schema_version"], SCHEMA_VERSION);
        assert_eq!(value["command"], "vm.list");
        assert!(value["data"].is_object());
        assert!(value["warnings"].is_array());
        assert!(
            value.get("error").is_none(),
            "a success envelope must not carry an error key"
        );
    }

    #[test]
    fn failure_envelope_has_the_documented_shape() {
        let error = Error::new(ErrorKind::Authorization, "not authorized to list instances")
            .with_context("the tenancy IAM policy does not grant COMPUTE_INSTANCE_INSPECT")
            .with_oci(OciContext {
                status: Some(403),
                code: Some("NotAuthorized".to_owned()),
                request_id: Some("req-42".to_owned()),
                operation: Some("ListInstances".to_owned()),
            });

        let value: Value = serde_json::from_str(&render_failure("vm.list", &error)).expect("json");

        assert_eq!(value["schema_version"], SCHEMA_VERSION);
        assert_eq!(value["command"], "vm.list");
        assert!(value.get("data").is_none());
        assert_eq!(value["error"]["kind"], "authorization");
        assert_eq!(value["error"]["exit_code"], 4);
        assert_eq!(value["error"]["oci"]["request_id"], "req-42");
        assert_eq!(value["error"]["oci"]["status"], 403);
        assert!(value["error"]["remediation"].is_string());
        assert!(value["warnings"].is_array());
    }

    /// `warnings` is always present so consumers can iterate without a null
    /// check. This is part of the documented contract.
    #[test]
    fn warnings_are_always_present() {
        let plain = Envelope::success("status", json!({}));
        let value: Value = serde_json::from_str(&plain.render().expect("render")).expect("json");
        assert_eq!(value["warnings"], json!([]));

        let warned = Envelope::success("status", json!({}))
            .with_warnings(vec!["cost data unavailable".to_owned()]);
        let value: Value = serde_json::from_str(&warned.render().expect("render")).expect("json");
        assert_eq!(value["warnings"][0], "cost data unavailable");
    }

    /// Purely local failures carry no `oci` key rather than an empty object.
    #[test]
    fn local_failures_omit_oci_context() {
        let error = Error::configuration("no configuration file found");
        let value: Value = serde_json::from_str(&render_failure("doctor", &error)).expect("json");
        assert!(value["error"].get("oci").is_none());
        assert_eq!(value["error"]["exit_code"], 3);
    }

    /// JSON is consumed by scripts and pasted into issues; terminal styling in
    /// it would be both unparseable noise and a portability trap.
    #[test]
    fn json_never_contains_ansi_escapes() {
        let error = Error::new(ErrorKind::Timeout, "request timed out");
        let rendered = render_failure("vm.list", &error);
        assert!(!rendered.contains('\u{1b}'));

        let success = Envelope::success("vm.list", json!({"a": 1}))
            .render()
            .expect("render");
        assert!(!success.contains('\u{1b}'));
    }
}

#[cfg(test)]
#[path = "schema_tests.rs"]
mod schema_tests;
