use std::{fmt, path::Path};

use md5::{Digest as _, Md5};
use rsa::{
    RsaPrivateKey,
    pkcs1::DecodeRsaPrivateKey,
    pkcs1v15::{Signature, VerifyingKey},
    pkcs8::{DecodePrivateKey, EncodePublicKey},
    signature::Verifier as _,
};
use sha2::Sha256;
use thiserror::Error;

use crate::domain::fingerprint::Fingerprint;

/// An OCI API signing key loaded from PEM.
///
/// The key material is never rendered by `Debug`; only the fingerprint, which is
/// derived from the public half, is exposed.
#[derive(Clone)]
pub struct PrivateKey {
    inner: RsaPrivateKey,
    fingerprint: Fingerprint,
}

impl PrivateKey {
    /// Load a PKCS#8 or PKCS#1 PEM private key.
    pub fn from_pem(pem: &str) -> Result<Self, KeyError> {
        if pem.contains("ENCRYPTED PRIVATE KEY") || pem.contains("Proc-Type: 4,ENCRYPTED") {
            return Err(KeyError::PassphraseProtected);
        }
        if pem.contains("PUBLIC KEY") {
            return Err(KeyError::PublicKeySupplied);
        }
        if pem.contains("BEGIN OPENSSH PRIVATE KEY") {
            return Err(KeyError::UnsupportedFormat);
        }

        let inner = RsaPrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
            .map_err(|_| KeyError::Malformed)?;
        Self::from_rsa(inner)
    }

    /// Load a PEM private key from disk.
    pub fn from_pem_file(path: &Path) -> Result<Self, KeyError> {
        let pem = std::fs::read_to_string(path).map_err(|source| KeyError::ReadFailed {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_pem(&pem)
    }

    fn from_rsa(inner: RsaPrivateKey) -> Result<Self, KeyError> {
        let spki = inner
            .to_public_key()
            .to_public_key_der()
            .map_err(|_| KeyError::Malformed)?;
        // OCI defines the API key fingerprint as the MD5 digest of the DER
        // SubjectPublicKeyInfo. MD5 is used here purely to reproduce that
        // identifier and never as a security primitive.
        let digest: [u8; 16] = Md5::digest(spki.as_bytes()).into();
        Ok(Self {
            inner,
            fingerprint: Fingerprint::from_digest(digest),
        })
    }

    /// The fingerprint OCI expects for this key, derived from the public half.
    #[must_use]
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    /// Verify a signature produced by this key.
    ///
    /// Used by `oci-free doctor` to prove the signing path works end to end
    /// without sending anything to OCI.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(signature) = Signature::try_from(signature) else {
            return false;
        };
        VerifyingKey::<Sha256>::new(self.inner.to_public_key())
            .verify(message, &signature)
            .is_ok()
    }

    pub(crate) fn rsa(&self) -> &RsaPrivateKey {
        &self.inner
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render key material, not even in `{:#?}` diagnostics.
        f.debug_struct("PrivateKey")
            .field("fingerprint", &self.fingerprint.as_str())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("could not read private key file {path}: {source}")]
    ReadFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("the private key is protected by a passphrase")]
    PassphraseProtected,
    #[error("a public key was supplied where a private key is required")]
    PublicKeySupplied,
    #[error("the key is in an unsupported format")]
    UnsupportedFormat,
    #[error("the file is not a valid PEM-encoded RSA private key")]
    Malformed,
}

impl KeyError {
    /// The next corrective action a user can take.
    #[must_use]
    pub fn remediation(&self) -> String {
        match self {
            Self::ReadFailed { path, .. } => {
                format!("check that {path} exists and is readable by the current user")
            }
            Self::PassphraseProtected => {
                "oci-free cannot use passphrase-protected keys yet; supply an unencrypted \
                 PKCS#8 key, for example with 'openssl pkcs8 -topk8 -nocrypt'"
                    .to_owned()
            }
            Self::PublicKeySupplied => {
                "point 'key_file' at the private key, not the '_public.pem' file uploaded to OCI"
                    .to_owned()
            }
            Self::UnsupportedFormat => {
                "OCI API keys must be RSA keys in PEM format; OpenSSH keys are not accepted"
                    .to_owned()
            }
            Self::Malformed => {
                "regenerate the API key pair and upload the public key in the OCI Console"
                    .to_owned()
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use rsa::{
        RsaPrivateKey,
        pkcs1::{EncodeRsaPrivateKey, LineEnding},
        pkcs8::{DecodePrivateKey, EncodePrivateKey},
    };

    /// Base64-encoded PKCS#8 DER for the throwaway key used by signing tests.
    ///
    /// See `tests/fixtures/README.md` for why the fixture is not stored as PEM.
    const FIXTURE: &str = include_str!("../../tests/fixtures/test_api_key.pkcs8.der.b64");

    /// The fingerprint OCI would report for the fixture key, computed
    /// independently with `openssl rsa -pubout -outform DER | openssl md5 -c`.
    pub const FIXTURE_FINGERPRINT: &str = "8d:54:09:96:82:c3:b4:33:42:f9:31:40:70:6a:34:8c";

    fn fixture_key() -> RsaPrivateKey {
        let der = STANDARD
            .decode(FIXTURE.trim())
            .expect("fixture is valid base64");
        RsaPrivateKey::from_pkcs8_der(&der).expect("fixture is a valid PKCS#8 key")
    }

    pub fn pkcs8_pem() -> String {
        fixture_key()
            .to_pkcs8_pem(LineEnding::LF)
            .expect("key re-encodes as PKCS#8 PEM")
            .to_string()
    }

    pub fn pkcs1_pem() -> String {
        fixture_key()
            .to_pkcs1_pem(LineEnding::LF)
            .expect("key re-encodes as PKCS#1 PEM")
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        KeyError, PrivateKey,
        testing::{FIXTURE_FINGERPRINT, pkcs1_pem, pkcs8_pem},
    };

    #[test]
    fn loads_pkcs8_and_pkcs1_keys_to_the_same_fingerprint() {
        let pkcs8 = PrivateKey::from_pem(&pkcs8_pem()).expect("PKCS#8 key loads");
        let pkcs1 = PrivateKey::from_pem(&pkcs1_pem()).expect("PKCS#1 key loads");
        assert_eq!(pkcs8.fingerprint().as_str(), FIXTURE_FINGERPRINT);
        assert_eq!(pkcs1.fingerprint().as_str(), FIXTURE_FINGERPRINT);
    }

    #[test]
    fn loads_a_key_from_disk() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("oci_api_key.pem");
        std::fs::write(&path, pkcs8_pem()).expect("write key file");

        let key = PrivateKey::from_pem_file(&path).expect("key loads from disk");
        assert_eq!(key.fingerprint().as_str(), FIXTURE_FINGERPRINT);
    }

    #[test]
    fn a_missing_key_file_is_reported_with_its_path() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("absent.pem");
        let error = PrivateKey::from_pem_file(&path).expect_err("missing key file is fatal");
        assert!(matches!(error, KeyError::ReadFailed { .. }));
        assert!(error.to_string().contains("absent.pem"));
    }

    #[test]
    fn common_mistakes_get_specific_diagnostics() {
        let cases = [
            (
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
                "passphrase",
            ),
            (
                "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
                "public key",
            ),
            (
                "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
                "unsupported format",
            ),
            ("not a key at all", "valid PEM"),
        ];

        for (pem, expected) in cases {
            let error = PrivateKey::from_pem(pem).expect_err("input should be rejected");
            assert!(
                error.to_string().contains(expected),
                "{expected:?} missing from {error}"
            );
            assert!(!error.remediation().is_empty());
        }
    }

    #[test]
    fn debug_output_never_contains_key_material() {
        let pem = pkcs8_pem();
        let key = PrivateKey::from_pem(&pem).expect("key loads");
        let rendered = format!("{key:?} {key:#?}");
        assert!(rendered.contains(FIXTURE_FINGERPRINT));
        for line in pem.lines().filter(|line| !line.starts_with("-----")) {
            assert!(!rendered.contains(line), "key material leaked into Debug");
        }
    }
}
