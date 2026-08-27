use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// An OCI API key fingerprint.
///
/// OCI defines the fingerprint as the MD5 digest of the DER-encoded public key,
/// rendered as colon-separated lowercase hex. MD5 is used here only because that
/// is how OCI identifies an uploaded API key; it is never used as a security
/// primitive.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Fingerprint(String);

/// An OCI fingerprint is an MD5 digest, so it always has 16 bytes.
const FINGERPRINT_BYTES: usize = 16;

impl Fingerprint {
    /// Build a fingerprint from the raw MD5 digest bytes.
    #[must_use]
    pub fn from_digest(digest: [u8; FINGERPRINT_BYTES]) -> Self {
        let hex: Vec<String> = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        Self(hex.join(":"))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Fingerprint {
    type Err = ParseFingerprintError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        if value.is_empty() {
            return Err(ParseFingerprintError::Empty);
        }

        // Accept both the colon-separated rendering shown in the OCI Console and
        // the bare hex form emitted by some key-generation scripts.
        let compact: String = value.chars().filter(|c| *c != ':').collect();
        if compact.len() != FINGERPRINT_BYTES * 2
            || !compact.chars().all(|c| c.is_ascii_hexdigit())
            || (value.contains(':') && value.split(':').any(|group| group.len() != 2))
        {
            return Err(ParseFingerprintError::InvalidFormat(value.to_owned()));
        }

        let mut digest = [0u8; FINGERPRINT_BYTES];
        for (index, byte) in digest.iter_mut().enumerate() {
            let pair = &compact[index * 2..index * 2 + 2];
            *byte = u8::from_str_radix(pair, 16)
                .map_err(|_| ParseFingerprintError::InvalidFormat(value.to_owned()))?;
        }

        Ok(Self::from_digest(digest))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseFingerprintError {
    #[error("fingerprint is empty")]
    Empty,
    #[error("expected a 16-byte hex fingerprint such as 8d:54:09:...:8c; got {0}")]
    InvalidFormat(String),
}

#[cfg(test)]
mod tests {
    use super::Fingerprint;

    const CANONICAL: &str = "8d:54:09:96:82:c3:b4:33:42:f9:31:40:70:6a:34:8c";

    #[test]
    fn parses_canonical_form() {
        let fingerprint: Fingerprint = CANONICAL.parse().expect("fingerprint should parse");
        assert_eq!(fingerprint.as_str(), CANONICAL);
    }

    #[test]
    fn normalises_uppercase_and_bare_hex() {
        let upper: Fingerprint = CANONICAL
            .to_ascii_uppercase()
            .parse()
            .expect("uppercase fingerprint should parse");
        let bare: Fingerprint = CANONICAL
            .replace(':', "")
            .parse()
            .expect("bare hex fingerprint should parse");
        assert_eq!(upper.as_str(), CANONICAL);
        assert_eq!(bare.as_str(), CANONICAL);
    }

    #[test]
    fn rejects_malformed_fingerprints() {
        for value in [
            "",
            "8d:54:09",
            "8d:54:09:96:82:c3:b4:33:42:f9:31:40:70:6a:34",
            "8d:54:09:96:82:c3:b4:33:42:f9:31:40:70:6a:34:8c:ff",
            "8d:5:409:96:82:c3:b4:33:42:f9:31:40:70:6a:34:8c",
            "zz:54:09:96:82:c3:b4:33:42:f9:31:40:70:6a:34:8c",
        ] {
            assert!(
                value.parse::<Fingerprint>().is_err(),
                "expected {value:?} to be rejected"
            );
        }
    }

    #[test]
    fn digest_rendering_is_lowercase_hex() {
        let fingerprint = Fingerprint::from_digest([0x0a; 16]);
        assert_eq!(fingerprint.as_str(), ["0a"; 16].join(":"));
    }
}
