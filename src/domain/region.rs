use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// An OCI region identifier such as `us-ashburn-1` or `eu-frankfurt-1`.
///
/// The type validates shape only. It deliberately does not carry a hard-coded
/// catalogue of regions: OCI adds regions over time and the tool must not tell a
/// user their real region does not exist.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Region(String);

impl Region {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Region {
    type Err = ParseRegionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim().to_ascii_lowercase();
        if value.is_empty() {
            return Err(ParseRegionError::Empty);
        }
        if value.len() > MAX_REGION_LEN {
            return Err(ParseRegionError::InvalidFormat(value));
        }

        let segments: Vec<&str> = value.split('-').collect();
        if segments.len() < 2 {
            return Err(ParseRegionError::LooksLikeRegionKey(value));
        }
        let well_formed = segments.iter().all(|segment| {
            !segment.is_empty() && segment.chars().all(|c| c.is_ascii_alphanumeric())
        });
        if !well_formed {
            return Err(ParseRegionError::InvalidFormat(value));
        }

        Ok(Self(value))
    }
}

const MAX_REGION_LEN: usize = 63;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseRegionError {
    #[error("region is empty")]
    Empty,
    #[error("expected a region identifier such as us-ashburn-1; got {0}")]
    InvalidFormat(String),
    #[error(
        "{0} looks like a region key; use the full region identifier such as us-ashburn-1 instead"
    )]
    LooksLikeRegionKey(String),
}

#[cfg(test)]
mod tests {
    use super::{ParseRegionError, Region};

    #[test]
    fn accepts_current_and_future_region_identifiers() {
        for value in [
            "us-ashburn-1",
            "eu-frankfurt-1",
            "ap-tokyo-1",
            "uk-gov-london-1",
            "me-jeddah-1",
        ] {
            assert_eq!(
                value
                    .parse::<Region>()
                    .expect("region should parse")
                    .as_str(),
                value
            );
        }
    }

    #[test]
    fn normalises_case_and_whitespace() {
        let region: Region = "  US-Ashburn-1 ".parse().expect("region should parse");
        assert_eq!(region.as_str(), "us-ashburn-1");
    }

    #[test]
    fn reports_region_keys_with_actionable_guidance() {
        let error = "iad"
            .parse::<Region>()
            .expect_err("region key is not an identifier");
        assert_eq!(
            error,
            ParseRegionError::LooksLikeRegionKey("iad".to_owned())
        );
    }

    #[test]
    fn rejects_malformed_identifiers() {
        for value in ["", "us--1", "us-ashburn-", "us_ashburn_1"] {
            assert!(
                value.parse::<Region>().is_err(),
                "expected {value:?} to be rejected"
            );
        }
    }
}
