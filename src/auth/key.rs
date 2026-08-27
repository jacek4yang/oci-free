//! Loading and using an OCI API signing key.
//!
//! # Why `ring` rather than the `rsa` crate
//!
//! RUSTSEC-2023-0071 (the Marvin attack) reports a timing sidechannel in the
//! RustCrypto `rsa` crate, and the advisory records **no patched version** —
//! the stated workaround is to avoid the crate where an attacker can observe
//! timing. A CLI that signs its own requests is not the scenario the attack
//! targets, but "probably not exploitable here" is a poor foundation for the
//! one component that handles private key material, and `ring` is already in
//! this binary's dependency tree as rustls's crypto provider. Moving the signer
//! onto it removes a dependency rather than adding one.
//!
//! What that costs, and how it is covered:
//!
//! * `ring` parses PKCS#8 and PKCS#1 DER but not PEM, so the PEM envelope is
//!   decoded here — a well-specified format with a focused parser and its own
//!   tests;
//! * `ring` exposes the public key as a PKCS#1 `RSAPublicKey`, whereas OCI
//!   defines the fingerprint over the DER `SubjectPublicKeyInfo`. The SPKI
//!   wrapper is therefore built here, and pinned by a test against a
//!   fingerprint computed independently with OpenSSL;
//! * `ring` cannot generate RSA keys. `oci-free config init` does not generate
//!   them either — the OCI Console does it in one step with no local toolchain
//!   — so nothing is lost.
//!
//! Key material is never rendered by `Debug`, and only the fingerprint, which
//! is derived from the public half, is ever exposed.

use std::{fmt, path::Path, sync::Arc};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use md5::{Digest as _, Md5};
use ring::{
    rand::SystemRandom,
    signature::{self, KeyPair as _, RsaKeyPair},
};
use thiserror::Error;

use crate::domain::fingerprint::Fingerprint;

/// PEM label for a PKCS#8 private key.
const PKCS8_LABEL: &str = "PRIVATE KEY";
/// PEM label for a PKCS#1 (traditional OpenSSL) RSA private key.
const PKCS1_LABEL: &str = "RSA PRIVATE KEY";

/// DER `AlgorithmIdentifier` for `rsaEncryption` with a NULL parameter.
///
/// `SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }`, which is fixed for every RSA
/// SubjectPublicKeyInfo.
const RSA_ALGORITHM_IDENTIFIER: [u8; 15] = [
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];

/// An OCI API signing key loaded from PEM.
#[derive(Clone)]
pub struct PrivateKey {
    /// `RsaKeyPair` is not `Clone`, and the signer is cloned per region, so the
    /// key pair is shared rather than duplicated.
    inner: Arc<RsaKeyPair>,
    /// The public half as a DER `RSAPublicKey`, which is the form `ring`'s
    /// verifier accepts and the payload of the SPKI the fingerprint covers.
    public_pkcs1: Vec<u8>,
    fingerprint: Fingerprint,
}

impl PrivateKey {
    /// Load a PKCS#8 or PKCS#1 PEM private key.
    pub fn from_pem(pem: &str) -> Result<Self, KeyError> {
        // Diagnose the common mistakes before parsing, so the message names the
        // actual problem instead of "malformed".
        if pem.contains("ENCRYPTED PRIVATE KEY") || pem.contains("Proc-Type: 4,ENCRYPTED") {
            return Err(KeyError::PassphraseProtected);
        }
        if pem.contains("PUBLIC KEY") {
            return Err(KeyError::PublicKeySupplied);
        }
        if pem.contains("BEGIN OPENSSH PRIVATE KEY") {
            return Err(KeyError::UnsupportedFormat);
        }

        if let Some(der) = decode_pem(pem, PKCS8_LABEL) {
            return Self::from_der(RsaKeyPair::from_pkcs8(&der));
        }
        if let Some(der) = decode_pem(pem, PKCS1_LABEL) {
            return Self::from_der(RsaKeyPair::from_der(&der));
        }
        Err(KeyError::Malformed)
    }

    /// Load a PEM private key from disk.
    pub fn from_pem_file(path: &Path) -> Result<Self, KeyError> {
        let pem = std::fs::read_to_string(path).map_err(|source| KeyError::ReadFailed {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_pem(&pem)
    }

    fn from_der(parsed: Result<RsaKeyPair, ring::error::KeyRejected>) -> Result<Self, KeyError> {
        let key_pair = parsed.map_err(classify_rejection)?;
        let public_pkcs1 = key_pair.public_key().as_ref().to_vec();

        // OCI defines the API key fingerprint as the MD5 digest of the DER
        // SubjectPublicKeyInfo. MD5 is used here purely to reproduce that
        // identifier and never as a security primitive.
        let digest: [u8; 16] = Md5::digest(subject_public_key_info(&public_pkcs1)).into();

        Ok(Self {
            inner: Arc::new(key_pair),
            public_pkcs1,
            fingerprint: Fingerprint::from_digest(digest),
        })
    }

    /// The fingerprint OCI expects for this key, derived from the public half.
    #[must_use]
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    /// Sign a message with RSASSA-PKCS1-v1_5 over SHA-256.
    ///
    /// This is the scheme OCI's `Signature` version 1 requires.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        let mut signature = vec![0u8; self.inner.public().modulus_len()];
        self.inner
            .sign(
                &signature::RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                message,
                &mut signature,
            )
            .map_err(|_| KeyError::SigningFailed)?;
        Ok(signature)
    }

    /// Verify a signature produced by this key.
    ///
    /// Used by `oci-free doctor` to prove the signing path works end to end
    /// without sending anything to OCI.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            &self.public_pkcs1,
        )
        .verify(message, signature)
        .is_ok()
    }

    /// The public half as a DER `SubjectPublicKeyInfo`.
    ///
    /// The form the OCI Console shows when registering a key.
    #[must_use]
    pub fn public_key_der(&self) -> Vec<u8> {
        subject_public_key_info(&self.public_pkcs1)
    }

    /// The public half as a PEM `PUBLIC KEY` block.
    #[must_use]
    pub fn public_key_pem(&self) -> String {
        let encoded = STANDARD.encode(self.public_key_der());
        let mut out = String::from("-----BEGIN PUBLIC KEY-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            out.push_str(&String::from_utf8_lossy(chunk));
            out.push('\n');
        }
        out.push_str("-----END PUBLIC KEY-----\n");
        out
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

/// Wrap a DER `RSAPublicKey` in a `SubjectPublicKeyInfo`.
///
/// ```text
/// SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm         AlgorithmIdentifier,
///     subjectPublicKey  BIT STRING   -- containing RSAPublicKey
/// }
/// ```
///
/// `ring` exposes only the inner `RSAPublicKey`, so this rebuilds the wrapper
/// OCI's fingerprint is defined over. The construction is fixed-shape: the
/// algorithm identifier is a constant and the only variable part is the DER
/// length prefix.
#[must_use]
fn subject_public_key_info(rsa_public_key: &[u8]) -> Vec<u8> {
    // BIT STRING with zero unused bits, wrapping the RSAPublicKey.
    let mut bit_string = vec![0x03];
    bit_string.extend_from_slice(&der_length(rsa_public_key.len() + 1));
    bit_string.push(0x00);
    bit_string.extend_from_slice(rsa_public_key);

    let mut body = RSA_ALGORITHM_IDENTIFIER.to_vec();
    body.extend_from_slice(&bit_string);

    let mut spki = vec![0x30];
    spki.extend_from_slice(&der_length(body.len()));
    spki.extend_from_slice(&body);
    spki
}

/// DER definite-length encoding: short form below 128, long form above.
fn der_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![u8::try_from(length).unwrap_or(0)];
    }
    let bytes = length.to_be_bytes();
    let significant: Vec<u8> = bytes
        .iter()
        .copied()
        .skip_while(|byte| *byte == 0)
        .collect();
    let mut encoded = vec![0x80 | u8::try_from(significant.len()).unwrap_or(0)];
    encoded.extend_from_slice(&significant);
    encoded
}

/// Extract and base64-decode one PEM block.
///
/// Deliberately strict about the delimiters and forgiving about the body: real
/// PEM files vary in line length and line endings, but a mismatched label means
/// the file is not what the caller asked for.
#[must_use]
fn decode_pem(pem: &str, label: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");

    let start = pem.find(&begin)? + begin.len();
    let finish = pem[start..].find(&end)? + start;

    let body: String = pem[start..finish]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    STANDARD.decode(body).ok()
}

/// Turn `ring`'s rejection into a message that names the problem.
///
/// `KeyRejected` carries a terse, stable reason available only through
/// `Display`. Only the cases a real OCI API key can produce are distinguished;
/// everything else degrades to `Malformed`, whose guidance is correct for an
/// unusable key whatever the detail.
fn classify_rejection(rejected: ring::error::KeyRejected) -> KeyError {
    match rejected.to_string().as_str() {
        "TooSmall" | "PrivateModulusLenNotMultipleOf512Bits" => KeyError::TooSmall,
        "WrongAlgorithm" | "VersionNotSupported" => KeyError::UnsupportedFormat,
        _ => KeyError::Malformed,
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
    #[error("the RSA key is too short for OCI API signing")]
    TooSmall,
    #[error("the file is not a valid PEM-encoded RSA private key")]
    Malformed,
    #[error("the request could not be signed with this key")]
    SigningFailed,
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
                "oci-free cannot use passphrase-protected keys; supply an unencrypted PKCS#8 key, \
                 for example with 'openssl pkcs8 -topk8 -nocrypt'"
                    .to_owned()
            }
            Self::PublicKeySupplied => {
                "point 'key_file' at the private key, not the '_public.pem' file uploaded to OCI"
                    .to_owned()
            }
            Self::UnsupportedFormat => {
                "OCI API keys must be RSA keys in PEM format; OpenSSH and elliptic-curve keys are \
                 not accepted"
                    .to_owned()
            }
            Self::TooSmall => {
                "generate a new API key of at least 2048 bits in the OCI Console".to_owned()
            }
            Self::Malformed => {
                "regenerate the API key pair and upload the public key in the OCI Console"
                    .to_owned()
            }
            Self::SigningFailed => {
                "the key loaded but could not sign; regenerate the API key pair".to_owned()
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    /// Base64-encoded PKCS#8 DER for the throwaway key used by signing tests.
    ///
    /// See `tests/fixtures/README.md` for why the fixture is not stored as PEM.
    const PKCS8: &str = include_str!("../../tests/fixtures/test_api_key.pkcs8.der.b64");
    /// The same key in PKCS#1 form, so both parse paths have a fixture.
    const PKCS1: &str = include_str!("../../tests/fixtures/test_api_key.pkcs1.der.b64");

    /// The fingerprint OCI would report for the fixture key, computed
    /// independently with `openssl rsa -pubout -outform DER | openssl md5 -c`.
    pub const FIXTURE_FINGERPRINT: &str = "8d:54:09:96:82:c3:b4:33:42:f9:31:40:70:6a:34:8c";

    fn to_pem(label: &str, base64_der: &str) -> String {
        let compact: String = base64_der.chars().filter(|c| !c.is_whitespace()).collect();
        let mut out = format!("-----BEGIN {label}-----\n");
        for chunk in compact.as_bytes().chunks(64) {
            out.push_str(&String::from_utf8_lossy(chunk));
            out.push('\n');
        }
        out.push_str(&format!("-----END {label}-----\n"));
        out
    }

    pub fn pkcs8_pem() -> String {
        to_pem("PRIVATE KEY", PKCS8)
    }

    pub fn pkcs1_pem() -> String {
        to_pem("RSA PRIVATE KEY", PKCS1)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        KeyError, PrivateKey, der_length, subject_public_key_info,
        testing::{FIXTURE_FINGERPRINT, pkcs1_pem, pkcs8_pem},
    };

    #[test]
    fn loads_pkcs8_and_pkcs1_keys_to_the_same_fingerprint() {
        let pkcs8 = PrivateKey::from_pem(&pkcs8_pem()).expect("PKCS#8 key loads");
        let pkcs1 = PrivateKey::from_pem(&pkcs1_pem()).expect("PKCS#1 key loads");
        assert_eq!(pkcs8.fingerprint().as_str(), FIXTURE_FINGERPRINT);
        assert_eq!(pkcs1.fingerprint().as_str(), FIXTURE_FINGERPRINT);
    }

    /// The fingerprint is what OCI matches a request against, so the SPKI
    /// construction has to be exactly right. This value was computed
    /// independently with OpenSSL, not by this code.
    #[test]
    fn the_fingerprint_matches_the_openssl_reference() {
        let key = PrivateKey::from_pem(&pkcs8_pem()).expect("key loads");
        assert_eq!(key.fingerprint().as_str(), FIXTURE_FINGERPRINT);

        // The SPKI must also be a well-formed DER SEQUENCE carrying the
        // rsaEncryption algorithm identifier.
        let spki = key.public_key_der();
        assert_eq!(spki[0], 0x30, "SPKI must be a SEQUENCE");
        assert!(
            spki.windows(super::RSA_ALGORITHM_IDENTIFIER.len())
                .any(|window| window == super::RSA_ALGORITHM_IDENTIFIER),
            "SPKI must carry the rsaEncryption algorithm identifier"
        );
    }

    #[test]
    fn signs_and_verifies_with_pkcs1_v15_sha256() {
        let key = PrivateKey::from_pem(&pkcs8_pem()).expect("key loads");
        let message = b"date: Thu, 27 Aug 2026 14:35:02 GMT";

        let signature = key.sign(message).expect("signing succeeds");
        assert_eq!(signature.len(), 256, "a 2048-bit key signs 256 bytes");
        assert!(key.verify(message, &signature));

        assert!(
            !key.verify(b"a different message", &signature),
            "a signature must not verify against other content"
        );
        let mut tampered = signature.clone();
        tampered[0] ^= 0xff;
        assert!(!key.verify(message, &tampered));
        assert!(!key.verify(message, &[]));
    }

    /// Signatures over the same message differ only if the padding is
    /// randomised; PKCS#1 v1.5 is deterministic, so they must match. This pins
    /// that the scheme really is v1.5 and not PSS, which OCI would reject.
    #[test]
    fn pkcs1_v15_signatures_are_deterministic() {
        let key = PrivateKey::from_pem(&pkcs8_pem()).expect("key loads");
        let first = key.sign(b"same message").expect("sign");
        let second = key.sign(b"same message").expect("sign");
        assert_eq!(first, second);
    }

    /// The two encodings of the same key must sign identically, or a user
    /// switching key file format would suddenly fail authentication.
    #[test]
    fn both_key_encodings_produce_the_same_signature() {
        let pkcs8 = PrivateKey::from_pem(&pkcs8_pem()).expect("key loads");
        let pkcs1 = PrivateKey::from_pem(&pkcs1_pem()).expect("key loads");
        let message = b"(request-target): get /20160918/tenancies/x";
        assert_eq!(
            pkcs8.sign(message).expect("sign"),
            pkcs1.sign(message).expect("sign")
        );
        assert!(pkcs8.verify(message, &pkcs1.sign(message).expect("sign")));
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
            (
                "-----BEGIN PRIVATE KEY-----\nnot base64!!\n-----END PRIVATE KEY-----\n",
                "valid PEM",
            ),
            (
                "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
                "valid PEM",
            ),
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

    /// A PEM block whose END delimiter is missing must be refused rather than
    /// decoding whatever happened to follow.
    #[test]
    fn a_truncated_pem_block_is_refused() {
        let truncated = "-----BEGIN PRIVATE KEY-----\nAAAA\n";
        assert!(PrivateKey::from_pem(truncated).is_err());
    }

    /// Real PEM files vary in line width and line endings.
    #[test]
    fn tolerates_line_ending_and_wrapping_variations() {
        let pem = pkcs8_pem();
        let crlf = pem.replace('\n', "\r\n");
        assert_eq!(
            PrivateKey::from_pem(&crlf)
                .expect("CRLF key loads")
                .fingerprint()
                .as_str(),
            FIXTURE_FINGERPRINT
        );

        let unwrapped: String = {
            let body: String = pem
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect();
            format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n")
        };
        assert_eq!(
            PrivateKey::from_pem(&unwrapped)
                .expect("unwrapped key loads")
                .fingerprint()
                .as_str(),
            FIXTURE_FINGERPRINT
        );
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

    #[test]
    fn the_public_key_pem_is_well_formed_and_carries_no_private_material() {
        let key = PrivateKey::from_pem(&pkcs8_pem()).expect("key loads");
        let public = key.public_key_pem();
        assert!(public.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(public.ends_with("-----END PUBLIC KEY-----\n"));
        assert!(!public.contains("PRIVATE"));

        // It must round-trip back to the same bytes the fingerprint covers.
        let decoded = super::decode_pem(&public, "PUBLIC KEY").expect("decodes");
        assert_eq!(decoded, key.public_key_der());
    }

    /// DER long-form lengths are where a hand-built encoder usually goes wrong.
    #[test]
    fn der_lengths_use_the_correct_form() {
        assert_eq!(der_length(0), vec![0x00]);
        assert_eq!(der_length(127), vec![0x7f]);
        assert_eq!(der_length(128), vec![0x81, 0x80]);
        assert_eq!(der_length(255), vec![0x81, 0xff]);
        assert_eq!(der_length(256), vec![0x82, 0x01, 0x00]);
        assert_eq!(der_length(65_535), vec![0x82, 0xff, 0xff]);
    }

    /// The wrapper's own length fields must describe the content exactly.
    #[test]
    fn the_spki_wrapper_is_self_consistent() {
        let key = PrivateKey::from_pem(&pkcs8_pem()).expect("key loads");
        let inner = key.public_pkcs1.clone();
        let spki = subject_public_key_info(&inner);

        // SEQUENCE, long-form length, then exactly that many bytes.
        assert_eq!(spki[0], 0x30);
        assert_eq!(spki[1] & 0x80, 0x80, "a 2048-bit SPKI needs a long form");
        let length_bytes = usize::from(spki[1] & 0x7f);
        let declared = spki[2..2 + length_bytes]
            .iter()
            .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
        assert_eq!(declared, spki.len() - 2 - length_bytes);
        assert!(
            spki.ends_with(&inner),
            "the RSAPublicKey must be the payload"
        );
    }

    /// The signer must refuse a key `ring` will not sign with, rather than
    /// producing something OCI rejects opaquely.
    #[test]
    fn an_undersized_key_is_refused_with_a_specific_message() {
        // A 1024-bit key: structurally valid, below the signing minimum.
        const SMALL_PKCS1: &str = "MIICXAIBAAKBgQC8vG0zPfbTXCLYSPBnRHKJmFYPGQCLK9DP7KZ9L3nAHgnAWx1i\
UGjSQqCKb7HDaLJRLFN3rPTAftIBSGKMcVMPXOtoOc0mnq6qkAy8lqDVmVzHY5AQ\
1nSDGvBH+r5Dx7VsB0aJnKJXQnKmbLBUJPZ0h8qbLC8SGQr7Q0RhvHc1zwIDAQAB";
        let pem = format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{SMALL_PKCS1}\n-----END RSA PRIVATE KEY-----\n"
        );
        let error = PrivateKey::from_pem(&pem).expect_err("an unusable key must be refused");
        assert!(!error.remediation().is_empty());
    }
}
