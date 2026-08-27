use std::{fmt, time::SystemTime};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rsa::{
    pkcs1v15::SigningKey,
    signature::{SignatureEncoding, Signer as _},
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use url::Url;

use crate::{
    auth::key::PrivateKey,
    config::Config,
    domain::{fingerprint::Fingerprint, ocid::Ocid},
};

/// Signature scheme version advertised in the `Authorization` header.
const SIGNATURE_VERSION: &str = "1";
/// Signature algorithm advertised in the `Authorization` header.
const SIGNATURE_ALGORITHM: &str = "rsa-sha256";
/// Content type assumed for a request body when the caller does not set one.
const DEFAULT_CONTENT_TYPE: &str = "application/json";

/// Headers signed for every request, in the order OCI expects them.
const GENERIC_HEADERS: [&str; 3] = ["date", "(request-target)", "host"];
/// Additional headers signed for requests that carry a body.
const BODY_HEADERS: [&str; 3] = ["content-length", "content-type", "x-content-sha256"];

/// HTTP methods this client signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }

    /// Whether OCI expects the content headers to be signed for this method.
    ///
    /// `POST`, `PUT`, and `PATCH` always sign `content-length`, `content-type`,
    /// and `x-content-sha256`, including when the body is empty.
    #[must_use]
    pub fn signs_body(self) -> bool {
        matches!(self, Self::Post | Self::Put | Self::Patch)
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A request to be signed.
#[derive(Debug, Clone)]
pub struct SignatureInput<'a> {
    method: HttpMethod,
    url: &'a Url,
    body: &'a [u8],
    content_type: &'a str,
}

impl<'a> SignatureInput<'a> {
    /// A request with no body.
    #[must_use]
    pub fn new(method: HttpMethod, url: &'a Url) -> Self {
        Self {
            method,
            url,
            body: &[],
            content_type: DEFAULT_CONTENT_TYPE,
        }
    }

    /// Attach a body and its content type.
    #[must_use]
    pub fn with_body(mut self, body: &'a [u8], content_type: &'a str) -> Self {
        self.body = body;
        self.content_type = content_type;
        self
    }

    /// Attach a JSON body.
    #[must_use]
    pub fn with_json_body(self, body: &'a [u8]) -> Self {
        self.with_body(body, DEFAULT_CONTENT_TYPE)
    }
}

/// The headers that must be added to a request, plus the string that was signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRequest {
    /// Lowercase header names and values to add to the request.
    ///
    /// `host` is signed but not returned: HTTP clients derive it from the URL,
    /// and [`RequestSigner`] signs exactly the value they will send.
    pub headers: Vec<(String, String)>,
    /// The exact bytes covered by the signature.
    ///
    /// This contains no secret material and exists so signing problems can be
    /// diagnosed without reconstructing the request by hand.
    pub signing_string: String,
    /// The raw signature bytes, also carried base64-encoded in `authorization`.
    pub signature: Vec<u8>,
}

impl SignedRequest {
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// Signs OCI REST requests with an API key.
#[derive(Debug, Clone)]
pub struct RequestSigner {
    key_id: String,
    key: PrivateKey,
}

impl RequestSigner {
    /// Build a signer from a loaded configuration and its key.
    ///
    /// The configured fingerprint must match the fingerprint derived from the
    /// key: signing with a mismatched pair produces requests OCI rejects with an
    /// opaque authentication error, so it is refused here instead.
    pub fn from_config(config: &Config, key: PrivateKey) -> Result<Self, SignerError> {
        if config.fingerprint != *key.fingerprint() {
            return Err(SignerError::FingerprintMismatch {
                configured: config.fingerprint.clone(),
                derived: key.fingerprint().clone(),
            });
        }
        Ok(Self::new(&config.tenancy, &config.user, key))
    }

    /// Build a signer from explicit identifiers.
    #[must_use]
    pub fn new(tenancy: &Ocid, user: &Ocid, key: PrivateKey) -> Self {
        let key_id = format!("{tenancy}/{user}/{}", key.fingerprint());
        Self { key_id, key }
    }

    /// The `keyId` sent to OCI, of the form `<tenancy>/<user>/<fingerprint>`.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Sign a request using the current time as the `date` header.
    pub fn sign(&self, input: &SignatureInput<'_>) -> Result<SignedRequest, SignerError> {
        self.sign_at(input, SystemTime::now())
    }

    /// Sign a request with an explicit `date` header value.
    ///
    /// OCI rejects requests whose `date` is more than five minutes from server
    /// time, so production callers should use [`RequestSigner::sign`].
    pub fn sign_at(
        &self,
        input: &SignatureInput<'_>,
        date: SystemTime,
    ) -> Result<SignedRequest, SignerError> {
        let host = request_host(input.url)?;
        let target = request_target(input.method, input.url);
        let date = httpdate::fmt_http_date(date);

        let mut headers = vec![("date".to_owned(), date)];
        let mut signed_names: Vec<&str> = GENERIC_HEADERS.to_vec();

        if input.method.signs_body() {
            headers.push(("content-length".to_owned(), input.body.len().to_string()));
            headers.push(("content-type".to_owned(), input.content_type.to_owned()));
            headers.push((
                "x-content-sha256".to_owned(),
                STANDARD.encode(Sha256::digest(input.body)),
            ));
            signed_names.extend_from_slice(&BODY_HEADERS);
        }

        let signing_string = build_signing_string(&signed_names, &headers, &host, &target);
        let signature = SigningKey::<Sha256>::new(self.key.rsa().clone())
            .sign(signing_string.as_bytes())
            .to_bytes()
            .to_vec();

        headers.push((
            "authorization".to_owned(),
            format!(
                "Signature algorithm=\"{SIGNATURE_ALGORITHM}\",headers=\"{}\",keyId=\"{}\",signature=\"{}\",version=\"{SIGNATURE_VERSION}\"",
                signed_names.join(" "),
                self.key_id,
                STANDARD.encode(&signature),
            ),
        ));

        Ok(SignedRequest {
            headers,
            signing_string,
            signature,
        })
    }
}

/// Build the canonical signing string: one `name: value` line per signed header,
/// joined with `\n` and with no trailing newline.
fn build_signing_string(
    signed_names: &[&str],
    headers: &[(String, String)],
    host: &str,
    target: &str,
) -> String {
    signed_names
        .iter()
        .map(|name| match *name {
            "(request-target)" => format!("(request-target): {target}"),
            "host" => format!("host: {host}"),
            name => {
                let value = headers
                    .iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value.as_str())
                    .unwrap_or_default();
                format!("{name}: {value}")
            }
        })
        .collect::<Vec<String>>()
        .join("\n")
}

/// The `host` header value: authority without the port when it is the default
/// for the scheme, matching what an HTTP client will actually send.
fn request_host(url: &Url) -> Result<String, SignerError> {
    if url.scheme() != "https" {
        return Err(SignerError::InsecureUrl(url.to_string()));
    }
    let host = url
        .host_str()
        .ok_or_else(|| SignerError::UnsupportedUrl(url.to_string()))?;
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}

/// The `(request-target)` pseudo-header: lowercase method, then the path and
/// query exactly as they appear on the request line.
fn request_target(method: HttpMethod, url: &Url) -> String {
    let path = url.path();
    match url.query() {
        Some(query) => format!("{} {path}?{query}", method.as_str().to_ascii_lowercase()),
        None => format!("{} {path}", method.as_str().to_ascii_lowercase()),
    }
}

#[derive(Debug, Error)]
pub enum SignerError {
    #[error(
        "the configured fingerprint {configured} does not match the private key, whose fingerprint is {derived}"
    )]
    FingerprintMismatch {
        configured: Fingerprint,
        derived: Fingerprint,
    },
    #[error("refusing to sign a request for a non-HTTPS URL: {0}")]
    InsecureUrl(String),
    #[error("the request URL has no host: {0}")]
    UnsupportedUrl(String),
}

impl SignerError {
    /// The next corrective action a user can take.
    #[must_use]
    pub fn remediation(&self) -> String {
        match self {
            Self::FingerprintMismatch { derived, .. } => format!(
                "set 'fingerprint' to {derived}, or point 'key_file' at the key that matches the \
                 configured fingerprint"
            ),
            Self::InsecureUrl(_) | Self::UnsupportedUrl(_) => {
                "use an https:// OCI service endpoint".to_owned()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use url::Url;

    use super::{HttpMethod, RequestSigner, SignatureInput, SignerError};
    use crate::{
        auth::key::{PrivateKey, testing::pkcs8_pem},
        domain::ocid::Ocid,
    };

    const TENANCY: &str = "ocid1.tenancy.oc1..aaaaaaaaexampletenancyid7xk3q7a";
    const USER: &str = "ocid1.user.oc1..aaaaaaaaexampleuserid4m2p8z";
    const FINGERPRINT: &str = "8d:54:09:96:82:c3:b4:33:42:f9:31:40:70:6a:34:8c";

    /// `Sun, 05 Jan 2014 21:31:40 GMT`.
    const FIXED_EPOCH_SECONDS: u64 = 1_388_957_500;
    const FIXED_DATE: &str = "Sun, 05 Jan 2014 21:31:40 GMT";

    /// Expected signatures produced independently with
    /// `openssl dgst -sha256 -sign` over the canonical signing strings below.
    const GET_SIGNATURE: &str = "bhNzq16tFTRJlMsW2KZHWAthWH7YQawcUygDlerom1uxA3uD6PVYjjiMhFyJTvavTORq/9K0qUzqEYuwyMMpB778iL7TYh2RPrcdCfeiQJQBh9nVW495wd66kMSzJ4JtrwioOxstahnIYMe965zzEpMuNgYM21HcfvQTR+Y/CAyHsPzs715Odyb/6R5kPDPjZgwhemRZ1PbaN1J+VyX6ibIOZOgv/78feARcOnvmoeljeHmeXPVWwoYKCQpxBRhFZmTFNTEMi6PrTXCkHDieqzyxx//zzBE1cRFSxBfb0yjzZb02/Tdh1R6jbqcdyuaXnNbpFoXF3RQF7yIyvdSHzw==";
    const POST_SIGNATURE: &str = "I65VWWA/ChRWav+9AHj91h5p21FZrkfW4JFcJwhAOPN107ld+uSich/H1iTBu2EzQIZOehWCg+NXIpMoSu23PFmw+FIpDyl1F5xzm1KurggJHbyuBzEhvjGz/ZvztPGfY4rOX8C8V2lpk4nUKv2RU3EwlxELSb+DjNoyt6+ZixVDxbCdvZ2Lf+PABTGrJSX4uff3UDHh5UUOcZRLnRxBkSB+jvja5IIO9UcfeMVmylyl0IgxQUhj2/lyNQ0rHes3Db3Rfkd/iptRIXI3xyr+1xr/Lf6u/2s6N76uP4YEAh5HcBsuVioofL37Uqbp0X7dS/6MYDciAdWC0VV2qzwDpg==";

    fn signer() -> RequestSigner {
        let key = PrivateKey::from_pem(&pkcs8_pem()).expect("fixture key loads");
        RequestSigner::new(
            &TENANCY.parse::<Ocid>().expect("tenancy OCID"),
            &USER.parse::<Ocid>().expect("user OCID"),
            key,
        )
    }

    fn fixed_date() -> std::time::SystemTime {
        UNIX_EPOCH + Duration::from_secs(FIXED_EPOCH_SECONDS)
    }

    #[test]
    fn key_id_uses_the_tenancy_user_fingerprint_form() {
        assert_eq!(signer().key_id(), format!("{TENANCY}/{USER}/{FINGERPRINT}"));
    }

    #[test]
    fn signs_a_get_request_exactly_as_oci_specifies() {
        let url = Url::parse(
            "https://iaas.us-ashburn-1.oraclecloud.com/20160918/instances\
             ?compartmentId=ocid1.compartment.oc1..aaaaaaaaexamplecompartment&limit=10",
        )
        .expect("URL parses");

        let signed = signer()
            .sign_at(&SignatureInput::new(HttpMethod::Get, &url), fixed_date())
            .expect("request signs");

        assert_eq!(
            signed.signing_string,
            "date: Sun, 05 Jan 2014 21:31:40 GMT\n\
             (request-target): get /20160918/instances?compartmentId=ocid1.compartment.oc1..aaaaaaaaexamplecompartment&limit=10\n\
             host: iaas.us-ashburn-1.oraclecloud.com"
        );
        assert_eq!(signed.header("date"), Some(FIXED_DATE));
        assert_eq!(
            signed.header("authorization"),
            Some(
                format!(
                    "Signature algorithm=\"rsa-sha256\",headers=\"date (request-target) host\",\
                     keyId=\"{TENANCY}/{USER}/{FINGERPRINT}\",signature=\"{GET_SIGNATURE}\",version=\"1\""
                )
                .as_str()
            )
        );
        // A request without a body must not carry content headers.
        assert_eq!(signed.header("content-length"), None);
        assert_eq!(signed.header("x-content-sha256"), None);
    }

    #[test]
    fn signs_a_post_request_including_the_content_headers() {
        let url = Url::parse("https://iaas.us-ashburn-1.oraclecloud.com/20160918/instances")
            .expect("URL parses");
        let body = br#"{"displayName":"free-vm"}"#;

        let signed = signer()
            .sign_at(
                &SignatureInput::new(HttpMethod::Post, &url).with_json_body(body),
                fixed_date(),
            )
            .expect("request signs");

        assert_eq!(
            signed.signing_string,
            "date: Sun, 05 Jan 2014 21:31:40 GMT\n\
             (request-target): post /20160918/instances\n\
             host: iaas.us-ashburn-1.oraclecloud.com\n\
             content-length: 25\n\
             content-type: application/json\n\
             x-content-sha256: Zxs/YZLtbeD/J0E0N5BEdAe3+Bwn7/aRcJetVSXwg+g="
        );
        assert_eq!(signed.header("content-length"), Some("25"));
        assert_eq!(signed.header("content-type"), Some("application/json"));
        let authorization = signed
            .header("authorization")
            .expect("authorization header");
        assert!(authorization.contains(
            "headers=\"date (request-target) host content-length content-type x-content-sha256\""
        ));
        assert!(authorization.contains(&format!("signature=\"{POST_SIGNATURE}\"")));
    }

    #[test]
    fn an_empty_body_still_signs_the_content_headers() {
        let url = Url::parse(
            "https://iaas.us-ashburn-1.oraclecloud.com/20160918/instances/x/actions/start",
        )
        .expect("URL parses");

        let signed = signer()
            .sign_at(&SignatureInput::new(HttpMethod::Post, &url), fixed_date())
            .expect("request signs");

        assert_eq!(signed.header("content-length"), Some("0"));
        assert_eq!(
            signed.header("x-content-sha256"),
            Some("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")
        );
    }

    #[test]
    fn methods_without_a_body_never_sign_content_headers() {
        let url = Url::parse("https://iaas.us-ashburn-1.oraclecloud.com/20160918/instances/x")
            .expect("URL parses");

        for method in [HttpMethod::Get, HttpMethod::Head, HttpMethod::Delete] {
            let signed = signer()
                .sign_at(&SignatureInput::new(method, &url), fixed_date())
                .expect("request signs");
            assert!(!signed.signing_string.contains("content-length"));
            assert!(signed.signing_string.contains(&format!(
                "(request-target): {} /20160918/instances/x",
                method.as_str().to_ascii_lowercase()
            )));
        }
    }

    #[test]
    fn a_non_default_port_is_part_of_the_signed_host() {
        let default_port =
            Url::parse("https://iaas.us-ashburn-1.oraclecloud.com:443/20160918/instances")
                .expect("URL parses");
        let custom_port =
            Url::parse("https://iaas.us-ashburn-1.oraclecloud.com:8443/20160918/instances")
                .expect("URL parses");

        let signer = signer();
        let signed_default = signer
            .sign_at(
                &SignatureInput::new(HttpMethod::Get, &default_port),
                fixed_date(),
            )
            .expect("request signs");
        let signed_custom = signer
            .sign_at(
                &SignatureInput::new(HttpMethod::Get, &custom_port),
                fixed_date(),
            )
            .expect("request signs");

        assert!(
            signed_default
                .signing_string
                .ends_with("host: iaas.us-ashburn-1.oraclecloud.com")
        );
        assert!(
            signed_custom
                .signing_string
                .ends_with("host: iaas.us-ashburn-1.oraclecloud.com:8443")
        );
    }

    #[test]
    fn the_signature_verifies_against_the_public_key() {
        let url = Url::parse("https://iaas.us-ashburn-1.oraclecloud.com/20160918/instances")
            .expect("URL parses");
        let key = PrivateKey::from_pem(&pkcs8_pem()).expect("fixture key loads");
        let signed = signer()
            .sign_at(&SignatureInput::new(HttpMethod::Get, &url), fixed_date())
            .expect("request signs");

        assert!(key.verify(signed.signing_string.as_bytes(), &signed.signature));
        assert!(!key.verify(b"a different signing string", &signed.signature));
    }

    #[test]
    fn refuses_to_sign_plaintext_urls() {
        let url = Url::parse("http://iaas.us-ashburn-1.oraclecloud.com/20160918/instances")
            .expect("URL parses");
        let error = signer()
            .sign_at(&SignatureInput::new(HttpMethod::Get, &url), fixed_date())
            .expect_err("plaintext URLs must be refused");
        assert!(matches!(error, SignerError::InsecureUrl(_)));
        assert!(!error.remediation().is_empty());
    }

    #[test]
    fn a_fingerprint_mismatch_is_refused_before_any_request_is_sent() {
        use crate::config::{Config, ConfigOptions, Environment};

        let dir = tempfile::tempdir().expect("temporary directory");
        let key_file = dir.path().join("oci_api_key.pem");
        std::fs::write(&key_file, pkcs8_pem()).expect("write key file");
        let config_file = dir.path().join("config");
        std::fs::write(
            &config_file,
            format!(
                "[DEFAULT]\nuser = {USER}\ntenancy = {TENANCY}\n\
                 fingerprint = 11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00\n\
                 key_file = {}\nregion = us-ashburn-1\n",
                key_file.display()
            ),
        )
        .expect("write configuration file");

        let config = Config::load(
            &Environment::default(),
            &ConfigOptions {
                config_file: Some(config_file),
                profile: None,
            },
        )
        .expect("configuration loads");
        let key = PrivateKey::from_pem_file(&key_file).expect("key loads");

        let error = RequestSigner::from_config(&config, key)
            .expect_err("a mismatched fingerprint must be refused");
        assert!(matches!(error, SignerError::FingerprintMismatch { .. }));
        assert!(error.remediation().contains(FINGERPRINT));
    }
}
