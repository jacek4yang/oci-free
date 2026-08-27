use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// An Oracle Cloud Identifier.
///
/// OCIDs are structured as `ocid1.<resource-type>.<realm>.<region>.<unique-id>`.
/// The region segment is empty for global resources such as a tenancy, so the
/// parser accepts an empty region but requires every other segment.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Ocid(String);

impl Ocid {
    /// Parse an OCID and require a specific resource type, for example `user`.
    pub fn parse_of_type(resource_type: &str, value: &str) -> Result<Self, ParseOcidError> {
        let ocid: Self = value.parse()?;
        if ocid.resource_type() != resource_type {
            return Err(ParseOcidError::UnexpectedResourceType {
                expected: resource_type.to_owned(),
                found: ocid.resource_type().to_owned(),
            });
        }
        Ok(ocid)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The `<resource-type>` segment, for example `tenancy`, `user`, or `instance`.
    #[must_use]
    pub fn resource_type(&self) -> &str {
        self.segments().1
    }

    /// The `<realm>` segment, for example `oc1`.
    #[must_use]
    pub fn realm(&self) -> &str {
        self.segments().2
    }

    /// The `<region>` segment, which is empty for global resources.
    #[must_use]
    pub fn region(&self) -> &str {
        self.segments().3
    }

    /// A diagnostics-safe rendering that keeps the structure of the OCID but
    /// only exposes the tail of the unique identifier.
    ///
    /// OCIDs are not credentials, but they identify a customer tenancy, so full
    /// values should not end up in pasted logs or bug reports by default.
    #[must_use]
    pub fn redacted(&self) -> String {
        let (prefix, resource_type, realm, region, unique) = self.segments();
        let tail: String = {
            let chars: Vec<char> = unique.chars().collect();
            let start = chars.len().saturating_sub(REDACTED_OCID_TAIL);
            chars[start..].iter().collect()
        };
        format!("{prefix}.{resource_type}.{realm}.{region}.\u{2026}{tail}")
    }

    /// Split the validated OCID into its five segments.
    fn segments(&self) -> (&str, &str, &str, &str, &str) {
        let mut parts = self.0.splitn(5, '.');
        let prefix = parts.next().unwrap_or_default();
        let resource_type = parts.next().unwrap_or_default();
        let realm = parts.next().unwrap_or_default();
        let region = parts.next().unwrap_or_default();
        let unique = parts.next().unwrap_or_default();
        (prefix, resource_type, realm, region, unique)
    }
}

/// Number of trailing unique-id characters kept by [`Ocid::redacted`].
const REDACTED_OCID_TAIL: usize = 6;

impl fmt::Display for Ocid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Ocid {
    type Err = ParseOcidError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        if value.is_empty() {
            return Err(ParseOcidError::Empty);
        }

        let parts: Vec<&str> = value.splitn(5, '.').collect();
        if parts.len() < 5 {
            return Err(ParseOcidError::InvalidFormat(value.to_owned()));
        }
        if parts[0] != "ocid1" {
            return Err(ParseOcidError::InvalidFormat(value.to_owned()));
        }
        // parts[3] is the region segment and is legitimately empty for global
        // resources such as a tenancy or a user.
        if parts[1].is_empty() || parts[2].is_empty() || parts[4].is_empty() {
            return Err(ParseOcidError::InvalidFormat(value.to_owned()));
        }
        if !parts[1].chars().all(|c| c.is_ascii_lowercase() || c == '_') {
            return Err(ParseOcidError::InvalidFormat(value.to_owned()));
        }

        Ok(Self(value.to_owned()))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseOcidError {
    #[error("OCID is empty")]
    Empty,
    #[error(
        "expected an OCID of the form ocid1.<resource-type>.<realm>.<region>.<unique-id>; got {0}"
    )]
    InvalidFormat(String),
    #[error("expected a {expected} OCID but found a {found} OCID")]
    UnexpectedResourceType { expected: String, found: String },
}

#[cfg(test)]
mod tests {
    use super::{Ocid, ParseOcidError};

    const TENANCY: &str = "ocid1.tenancy.oc1..aaaaaaaaexampletenancyid7xk3q7a";
    const INSTANCE: &str = "ocid1.instance.oc1.iad.anuwcljtexampleinstanceid";

    #[test]
    fn parses_global_ocid_with_empty_region() {
        let ocid: Ocid = TENANCY.parse().expect("tenancy OCID should parse");
        assert_eq!(ocid.resource_type(), "tenancy");
        assert_eq!(ocid.realm(), "oc1");
        assert_eq!(ocid.region(), "");
        assert_eq!(ocid.as_str(), TENANCY);
    }

    #[test]
    fn parses_regional_ocid() {
        let ocid: Ocid = INSTANCE.parse().expect("instance OCID should parse");
        assert_eq!(ocid.resource_type(), "instance");
        assert_eq!(ocid.region(), "iad");
    }

    #[test]
    fn rejects_non_ocid_values() {
        for value in [
            "",
            "not-an-ocid",
            "ocid1.tenancy.oc1..",
            "ocid1..oc1..aaaa",
            "ocid2.tenancy.oc1..aaaa",
            "ocid1.tenancy.oc1.aaaa",
        ] {
            assert!(
                value.parse::<Ocid>().is_err(),
                "expected {value:?} to be rejected"
            );
        }
    }

    #[test]
    fn typed_parsing_reports_the_wrong_resource_type() {
        let error = Ocid::parse_of_type("user", TENANCY).expect_err("tenancy is not a user OCID");
        assert_eq!(
            error,
            ParseOcidError::UnexpectedResourceType {
                expected: "user".to_owned(),
                found: "tenancy".to_owned(),
            }
        );
    }

    #[test]
    fn redaction_keeps_structure_and_hides_the_unique_id() {
        let ocid: Ocid = TENANCY.parse().expect("tenancy OCID should parse");
        let redacted = ocid.redacted();
        assert_eq!(redacted, "ocid1.tenancy.oc1..\u{2026}xk3q7a");
        assert!(!redacted.contains("aaaaaaaaexample"));
    }
}
