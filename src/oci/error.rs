//! Decoding OCI error responses into the product error model.
//!
//! OCI returns a JSON body of the shape `{"code": "...", "message": "..."}` on
//! failure, and carries a correlation id in `opc-request-id`. Both are worth
//! preserving: the code is stable enough to branch on, and the request id is
//! what Oracle support asks for.
//!
//! The service message is included verbatim. OCI error messages describe the
//! caller's own resources and never echo the Authorization header, but bodies
//! are still truncated so a hostile or malfunctioning endpoint cannot flood the
//! terminal.

use serde::Deserialize;

use crate::error::{Error, ErrorKind, OciContext};

/// Longest service message retained. Real OCI messages are a line or two.
const MAX_MESSAGE_LEN: usize = 2000;

/// The documented OCI error body.
#[derive(Debug, Clone, Deserialize)]
pub struct OciErrorBody {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

impl OciErrorBody {
    /// Parse an error body, tolerating anything that is not the documented
    /// shape: a proxy or gateway may return HTML, and that must not panic.
    #[must_use]
    pub fn parse(body: &str) -> Self {
        serde_json::from_str::<Self>(body).unwrap_or(Self {
            code: None,
            message: None,
        })
    }

    #[must_use]
    fn safe_message(&self) -> Option<String> {
        self.message.as_ref().map(|message| truncate(message))
    }
}

fn truncate(value: &str) -> String {
    if value.chars().count() <= MAX_MESSAGE_LEN {
        return value.to_owned();
    }
    let kept: String = value.chars().take(MAX_MESSAGE_LEN).collect();
    format!("{kept}… (truncated)")
}

/// Map an HTTP status onto an error category.
///
/// 401 is reported as an authentication problem because for API-key auth it
/// almost always means the signing key, fingerprint, or clock is wrong rather
/// than that the user lacks a policy grant.
#[must_use]
pub fn kind_for_status(status: u16) -> ErrorKind {
    match status {
        401 => ErrorKind::Authentication,
        403 => ErrorKind::Authorization,
        404 => ErrorKind::NotFound,
        409 | 412 => ErrorKind::Conflict,
        429 => ErrorKind::RateLimited,
        400 | 422 => ErrorKind::InvalidInput,
        500..=599 => ErrorKind::TransientServer,
        // Anything else is a status this client does not know how to interpret.
        // Treating it as malformed keeps an unexpected 3xx or 2xx-in-an-error
        // path from being mistaken for something actionable.
        _ => ErrorKind::MalformedResponse,
    }
}

/// Build a product error from an OCI failure response.
#[must_use]
pub fn from_response(
    status: u16,
    body: &str,
    request_id: Option<String>,
    operation: &str,
) -> Error {
    let parsed = OciErrorBody::parse(body);
    let kind = kind_for_status(status);

    let message = match parsed.safe_message() {
        Some(message) if !message.trim().is_empty() => {
            format!("OCI refused {operation}: {message}")
        }
        _ => format!("OCI refused {operation} with HTTP {status}"),
    };

    let error = Error::new(kind, message).with_oci(OciContext {
        status: Some(status),
        code: parsed.code.clone(),
        request_id,
        operation: Some(operation.to_owned()),
    });

    match kind {
        ErrorKind::Authentication => error
            .with_context(
                "OCI rejected the request signature. The usual causes are a key that does not \
                 match the configured fingerprint, or a host clock more than five minutes out.",
            )
            .with_remediation("run `oci-free doctor` to check the key, fingerprint, and clock"),
        ErrorKind::Authorization => error
            .with_context(
                "the credentials are valid, but the tenancy's IAM policy does not permit this \
                 operation",
            )
            .with_remediation(format!(
                "ask a tenancy administrator for a policy statement allowing {operation}"
            )),
        ErrorKind::RateLimited => {
            error.with_context("OCI is throttling this tenancy; oci-free already retried")
        }
        _ => error,
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_MESSAGE_LEN, from_response, kind_for_status};
    use crate::error::ErrorKind;

    #[test]
    fn maps_statuses_to_categories() {
        assert_eq!(kind_for_status(401), ErrorKind::Authentication);
        assert_eq!(kind_for_status(403), ErrorKind::Authorization);
        assert_eq!(kind_for_status(404), ErrorKind::NotFound);
        assert_eq!(kind_for_status(409), ErrorKind::Conflict);
        assert_eq!(kind_for_status(429), ErrorKind::RateLimited);
        assert_eq!(kind_for_status(400), ErrorKind::InvalidInput);
        assert_eq!(kind_for_status(500), ErrorKind::TransientServer);
        assert_eq!(kind_for_status(503), ErrorKind::TransientServer);
    }

    #[test]
    fn extracts_code_message_and_request_id() {
        let error = from_response(
            404,
            r#"{"code":"NotAuthorizedOrNotFound","message":"Instance not found"}"#,
            Some("req-7".to_owned()),
            "GetInstance",
        );

        assert_eq!(error.kind(), ErrorKind::NotFound);
        assert!(error.message().contains("Instance not found"));
        assert_eq!(error.oci().code.as_deref(), Some("NotAuthorizedOrNotFound"));
        assert_eq!(error.oci().request_id.as_deref(), Some("req-7"));
        assert_eq!(error.oci().status, Some(404));
        assert_eq!(error.oci().operation.as_deref(), Some("GetInstance"));
    }

    /// A gateway can return HTML or an empty body. That must degrade to a
    /// useful message, never a panic.
    #[test]
    fn tolerates_bodies_that_are_not_oci_json() {
        for body in ["", "<html>502 Bad Gateway</html>", "null", "[]", "{"] {
            let error = from_response(502, body, None, "ListInstances");
            assert_eq!(error.kind(), ErrorKind::TransientServer);
            assert!(error.message().contains("502"));
        }
    }

    #[test]
    fn oversized_messages_are_truncated() {
        let huge = "x".repeat(MAX_MESSAGE_LEN * 3);
        let body = serde_json::json!({ "code": "Boom", "message": huge }).to_string();
        let error = from_response(400, &body, None, "LaunchInstance");
        assert!(error.message().contains("truncated"));
        assert!(error.message().chars().count() < MAX_MESSAGE_LEN + 200);
    }

    #[test]
    fn authentication_and_authorization_get_distinct_guidance() {
        let auth = from_response(401, "{}", None, "GetTenancy");
        assert!(auth.remediation().contains("doctor"));
        assert!(auth.context().expect("context").contains("clock"));

        let authz = from_response(403, "{}", None, "ListInstances");
        assert!(authz.remediation().contains("ListInstances"));
        assert!(authz.context().expect("context").contains("IAM policy"));
    }
}
