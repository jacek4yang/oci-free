//! The signed HTTPS transport.
//!
//! One [`OciClient`] owns the HTTP connection pool, the request signer, and the
//! retry policy for a single tenancy/region pair. Every OCI call in the product
//! goes through here, so the safety properties are enforced in one place:
//!
//! * requests are HTTPS only, and the signer refuses anything else;
//! * redirects are never followed automatically, because a signed
//!   `Authorization` header is bound to one host and path;
//! * response bodies are bounded;
//! * only provably replay-safe requests are retried;
//! * `opc-request-id` is captured for every call, including failures.

use std::time::{Duration, Instant};

use reqwest::{StatusCode, header};
use serde::{Serialize, de::DeserializeOwned};
use url::Url;

use crate::{
    auth::{
        PrivateKey, RequestSigner,
        signer::{HttpMethod, SignatureInput},
    },
    config::Config,
    error::{Error, ErrorKind, OciContext, Result},
    oci::{
        endpoint::{EndpointResolver, Service},
        error as oci_error,
        retry::{Decision, Outcome, RequestKind, RetryPolicy},
    },
};

/// Header OCI uses to correlate a request with its server-side logs.
const REQUEST_ID_HEADER: &str = "opc-request-id";
/// Header carrying the pagination cursor for the next page.
const NEXT_PAGE_HEADER: &str = "opc-next-page";

/// Transport tunables. The defaults are deliberately conservative: a CLI that
/// hangs is worse than one that reports a timeout the user can retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportLimits {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    /// Ceiling on a single response body. OCI list pages are far smaller; this
    /// exists so a malfunctioning endpoint cannot exhaust memory.
    pub max_response_bytes: usize,
    /// Ceiling on pages walked by [`OciClient::list_all`], so a server that
    /// keeps returning a cursor cannot loop forever.
    pub max_pages: usize,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            max_response_bytes: 16 * 1024 * 1024,
            max_pages: 200,
        }
    }
}

/// A successfully decoded response plus the metadata worth keeping.
#[derive(Debug, Clone)]
pub struct OciResponse<T> {
    pub body: T,
    pub request_id: Option<String>,
    /// Cursor for the next page, when the service returned one.
    pub next_page: Option<String>,
}

/// A signed OCI REST client bound to one tenancy, key, and region.
pub struct OciClient {
    http: reqwest::Client,
    signer: RequestSigner,
    endpoints: EndpointResolver,
    retry: RetryPolicy,
    limits: TransportLimits,
}

impl std::fmt::Debug for OciClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the signer: it owns private key material.
        f.debug_struct("OciClient")
            .field("region", self.endpoints.region())
            .field("realm", &self.endpoints.realm())
            .finish_non_exhaustive()
    }
}

impl OciClient {
    /// Build a client from a loaded configuration and its private key.
    pub fn new(config: &Config, key: PrivateKey) -> Result<Self> {
        let endpoints = EndpointResolver::new(&config.tenancy, config.region.clone())?;
        let signer = RequestSigner::from_config(config, key).map_err(|error| {
            Error::new(ErrorKind::Authentication, error.to_string())
                .with_remediation(error.remediation())
        })?;
        Self::with_parts(
            signer,
            endpoints,
            TransportLimits::default(),
            RetryPolicy::default(),
        )
    }

    /// Build a client from already-resolved parts. Used by tests to point the
    /// transport at a local mock server.
    pub fn with_parts(
        signer: RequestSigner,
        endpoints: EndpointResolver,
        limits: TransportLimits,
        retry: RetryPolicy,
    ) -> Result<Self> {
        Self::build(signer, endpoints, limits, retry, Vec::new())
    }

    /// Build a client that additionally trusts the supplied DER certificates.
    ///
    /// Test-only. The transport refuses plaintext HTTP, so transport tests run
    /// against a real TLS server whose self-signed certificate has to be
    /// trusted explicitly. Compiled out of release builds so no production path
    /// can widen the trust store.
    #[cfg(test)]
    pub fn with_extra_roots(
        signer: RequestSigner,
        endpoints: EndpointResolver,
        limits: TransportLimits,
        retry: RetryPolicy,
        roots: Vec<Vec<u8>>,
    ) -> Result<Self> {
        Self::build(signer, endpoints, limits, retry, roots)
    }

    fn build(
        signer: RequestSigner,
        endpoints: EndpointResolver,
        limits: TransportLimits,
        retry: RetryPolicy,
        extra_roots: Vec<Vec<u8>>,
    ) -> Result<Self> {
        // `rustls-no-provider` leaves the process default unset, so install the
        // ring provider explicitly. A second call is a no-op, and losing the
        // race simply means another caller installed the same provider.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let http = reqwest::Client::builder()
            .connect_timeout(limits.connect_timeout)
            .timeout(limits.request_timeout)
            // Never follow a redirect. The Authorization header is a signature
            // over this exact host, method, and path; replaying it against a
            // Location the client did not sign would leak a valid credential to
            // whatever host that header names.
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .user_agent(concat!("oci-free/", env!("CARGO_PKG_VERSION")));

        // Tests talk to an in-process listener on the loopback interface. A
        // proxy configured in the environment would intercept that, so it is
        // bypassed here. Release builds never compile this, and so continue to
        // honour the user's proxy settings.
        #[cfg(test)]
        let http = http.no_proxy();

        // `extra_roots` is only ever non-empty in tests; release builds get an
        // empty vector and leave the trust store untouched.
        let http = extra_roots.into_iter().try_fold(http, |builder, root| {
            let certificate = reqwest::Certificate::from_der(&root).map_err(|error| {
                Error::network(format!("could not load an additional trust root: {error}"))
            })?;
            Ok::<_, Error>(builder.add_root_certificate(certificate))
        })?;

        let http = http.build().map_err(|error| {
            Error::network(format!("could not initialise the HTTPS client: {error}"))
                .with_remediation("check the system TLS trust store and any proxy settings")
        })?;

        Ok(Self {
            http,
            signer,
            endpoints,
            retry,
            limits,
        })
    }

    #[must_use]
    pub fn endpoints(&self) -> &EndpointResolver {
        &self.endpoints
    }

    /// Point this client at another region in the same realm, reusing the
    /// connection pool and signer.
    #[must_use]
    pub fn in_region(&self, region: crate::domain::region::Region) -> Self {
        Self {
            http: self.http.clone(),
            signer: self.signer.clone(),
            endpoints: self.endpoints.in_region(region),
            retry: self.retry,
            limits: self.limits,
        }
    }

    /// GET a JSON document.
    pub async fn get_json<T: DeserializeOwned>(
        &self,
        service: Service,
        path: &str,
        operation: &str,
    ) -> Result<OciResponse<T>> {
        let url = self.endpoints.versioned_url(service, path)?;
        self.send_json(HttpMethod::Get, url, None, RequestKind::Read, operation)
            .await
    }

    /// GET one page of a list endpoint, passing an opaque pagination cursor.
    pub async fn get_page<T: DeserializeOwned>(
        &self,
        service: Service,
        path: &str,
        page: Option<&str>,
        operation: &str,
    ) -> Result<OciResponse<T>> {
        let mut url = self.endpoints.versioned_url(service, path)?;
        if let Some(page) = page {
            url.query_pairs_mut().append_pair("page", page);
        }
        self.send_json(HttpMethod::Get, url, None, RequestKind::Read, operation)
            .await
    }

    /// Walk every page of a list endpoint, concatenating the results.
    ///
    /// Returning only the first page would silently under-report resources, and
    /// under-reporting instances would make the Free Tier capacity calculation
    /// permit an over-allocation.
    pub async fn list_all<T: DeserializeOwned>(
        &self,
        service: Service,
        path: &str,
        operation: &str,
    ) -> Result<Vec<T>> {
        let mut items = Vec::new();
        let mut page: Option<String> = None;
        let mut seen_pages = 0usize;

        loop {
            let response: OciResponse<Vec<T>> = self
                .get_page(service, path, page.as_deref(), operation)
                .await?;
            items.extend(response.body);
            seen_pages += 1;

            match response.next_page {
                // OCI signals "no more pages" by omitting the header. Some
                // services send it back empty, which means the same thing.
                Some(next) if !next.is_empty() => {
                    if seen_pages >= self.limits.max_pages {
                        return Err(Error::malformed_response(format!(
                            "{operation} returned more than {} pages",
                            self.limits.max_pages
                        ))
                        .with_context(
                            "OCI kept supplying a pagination cursor, which usually means the \
                             cursor is not advancing",
                        ));
                    }
                    page = Some(next);
                }
                _ => return Ok(items),
            }
        }
    }

    /// POST a JSON body.
    ///
    /// `retry_token` must be `Some` only when OCI documents the operation as
    /// accepting `opc-retry-token`; supplying one is what makes the request
    /// safe to replay after a transport failure.
    pub async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        service: Service,
        path: &str,
        body: &B,
        retry_token: Option<&str>,
        operation: &str,
    ) -> Result<OciResponse<T>> {
        let url = self.endpoints.versioned_url(service, path)?;
        let encoded = serialize_body(body, operation)?;
        let kind = if retry_token.is_some() {
            RequestKind::IdempotentWrite
        } else {
            RequestKind::UnsafeWrite
        };
        self.send_json(
            HttpMethod::Post,
            url,
            Some(RequestBody {
                bytes: encoded,
                retry_token: retry_token.map(str::to_owned),
            }),
            kind,
            operation,
        )
        .await
    }

    /// PUT a JSON body. PUT is idempotent by definition in the OCI APIs this
    /// product uses, so it is replay-safe without a token.
    pub async fn put_json<B: Serialize, T: DeserializeOwned>(
        &self,
        service: Service,
        path: &str,
        body: &B,
        operation: &str,
    ) -> Result<OciResponse<T>> {
        let url = self.endpoints.versioned_url(service, path)?;
        let encoded = serialize_body(body, operation)?;
        self.send_json(
            HttpMethod::Put,
            url,
            Some(RequestBody {
                bytes: encoded,
                retry_token: None,
            }),
            RequestKind::IdempotentWrite,
            operation,
        )
        .await
    }

    /// DELETE a resource. Deleting an already-deleted resource is harmless, so
    /// this is treated as replay-safe.
    pub async fn delete(&self, service: Service, path: &str, operation: &str) -> Result<()> {
        let url = self.endpoints.versioned_url(service, path)?;
        self.send(
            HttpMethod::Delete,
            url,
            None,
            RequestKind::IdempotentWrite,
            operation,
        )
        .await?;
        Ok(())
    }

    /// Send a request and decode a JSON response.
    async fn send_json<T: DeserializeOwned>(
        &self,
        method: HttpMethod,
        url: Url,
        body: Option<RequestBody>,
        kind: RequestKind,
        operation: &str,
    ) -> Result<OciResponse<T>> {
        let raw = self.send(method, url, body, kind, operation).await?;

        // An empty body with a success status means "no content"; only attempt
        // that for types that can represent it.
        let decoded: T = serde_json::from_slice(&raw.body).map_err(|error| {
            Error::malformed_response(format!("could not decode the {operation} response"))
                .with_context(format!("{error}"))
                .with_oci(OciContext {
                    request_id: raw.request_id.clone(),
                    operation: Some(operation.to_owned()),
                    ..OciContext::default()
                })
        })?;

        Ok(OciResponse {
            body: decoded,
            request_id: raw.request_id,
            next_page: raw.next_page,
        })
    }

    /// Send a request, applying signing and the retry policy.
    async fn send(
        &self,
        method: HttpMethod,
        url: Url,
        body: Option<RequestBody>,
        kind: RequestKind,
        operation: &str,
    ) -> Result<RawResponse> {
        let mut attempt = 1u32;
        let mut spent = Duration::ZERO;

        loop {
            let started = Instant::now();
            let outcome = self.attempt(method, &url, body.as_ref(), operation).await;

            let (retry_outcome, result) = match outcome {
                Attempt::Completed(raw) => {
                    if raw.status.is_success() {
                        return Ok(raw.into_raw());
                    }
                    (
                        Outcome::Status {
                            code: raw.status.as_u16(),
                            retry_after: raw.retry_after,
                        },
                        Err(oci_error::from_response(
                            raw.status.as_u16(),
                            &String::from_utf8_lossy(&raw.body),
                            raw.request_id.clone(),
                            operation,
                        )),
                    )
                }
                Attempt::Failed { outcome, error } => (outcome, Err(error)),
            };

            spent = spent.saturating_add(started.elapsed());
            let jitter: f64 = rand::random_range(0.0..1.0);

            match self
                .retry
                .decide(kind, retry_outcome, attempt, spent, jitter)
            {
                Decision::RetryAfter(delay) => {
                    tokio::time::sleep(delay).await;
                    spent = spent.saturating_add(delay);
                    attempt += 1;
                }
                Decision::Stop => return result,
            }
        }
    }

    /// One signed request/response round trip.
    async fn attempt(
        &self,
        method: HttpMethod,
        url: &Url,
        body: Option<&RequestBody>,
        operation: &str,
    ) -> Attempt {
        let empty: &[u8] = &[];
        let payload = body.map_or(empty, |body| body.bytes.as_slice());

        let mut input = SignatureInput::new(method, url);
        if body.is_some() {
            input = input.with_json_body(payload);
        }

        let signed = match self.signer.sign(&input) {
            Ok(signed) => signed,
            Err(error) => {
                return Attempt::Failed {
                    // A signing failure is deterministic; retrying cannot help.
                    outcome: Outcome::Status {
                        code: 0,
                        retry_after: None,
                    },
                    error: Error::new(ErrorKind::Authentication, error.to_string())
                        .with_remediation(error.remediation()),
                };
            }
        };

        let mut request = self.http.request(method.into_reqwest(), url.clone());
        for (name, value) in &signed.headers {
            request = request.header(name, value);
        }
        if let Some(body) = body {
            if let Some(token) = &body.retry_token {
                request = request.header("opc-retry-token", token);
            }
            request = request.body(body.bytes.clone());
        }

        match request.send().await {
            Ok(response) => self.read_response(response, operation).await,
            Err(error) => Attempt::Failed {
                outcome: classify_transport_error(&error),
                error: transport_error(&error, operation),
            },
        }
    }

    /// Read a response, enforcing the body ceiling.
    async fn read_response(&self, mut response: reqwest::Response, operation: &str) -> Attempt {
        let status = response.status();
        let request_id = header_string(response.headers(), REQUEST_ID_HEADER);
        let next_page = header_string(response.headers(), NEXT_PAGE_HEADER);
        let retry_after = parse_retry_after(response.headers());

        // A redirect is never followed (the client is built with
        // `Policy::none()`), so surface it rather than silently returning an
        // empty body that would decode as a malformed response.
        if status.is_redirection() {
            let location = header_string(response.headers(), header::LOCATION.as_str())
                .unwrap_or_else(|| "an unspecified location".to_owned());
            return Attempt::Failed {
                outcome: Outcome::Status {
                    code: status.as_u16(),
                    retry_after: None,
                },
                error: Error::new(
                    ErrorKind::MalformedResponse,
                    format!("OCI redirected {operation} to {location}"),
                )
                .with_context(
                    "oci-free does not follow redirects: the request signature is bound to one \
                     host and path, so replaying it elsewhere would disclose a valid credential",
                )
                .with_remediation("check the configured region for this tenancy")
                .with_oci(OciContext {
                    status: Some(status.as_u16()),
                    request_id: request_id.clone(),
                    operation: Some(operation.to_owned()),
                    ..OciContext::default()
                }),
            };
        }

        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if body.len() + chunk.len() > self.limits.max_response_bytes {
                        return Attempt::Failed {
                            outcome: Outcome::Status {
                                code: status.as_u16(),
                                retry_after: None,
                            },
                            error: Error::malformed_response(format!(
                                "the {operation} response exceeded {} bytes",
                                self.limits.max_response_bytes
                            )),
                        };
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(error) => {
                    // The connection dropped mid-body. For a read this is worth
                    // retrying; the retry policy decides.
                    return Attempt::Failed {
                        outcome: Outcome::BodyIncomplete,
                        error: transport_error(&error, operation),
                    };
                }
            }
        }

        Attempt::Completed(CompletedAttempt {
            status,
            body,
            request_id,
            next_page,
            retry_after,
        })
    }
}

/// A body plus its optional OCI replay token.
struct RequestBody {
    bytes: Vec<u8>,
    retry_token: Option<String>,
}

/// The outcome of one round trip.
enum Attempt {
    Completed(CompletedAttempt),
    Failed { outcome: Outcome, error: Error },
}

struct CompletedAttempt {
    status: StatusCode,
    body: Vec<u8>,
    request_id: Option<String>,
    next_page: Option<String>,
    retry_after: Option<Duration>,
}

impl CompletedAttempt {
    fn into_raw(self) -> RawResponse {
        RawResponse {
            body: self.body,
            request_id: self.request_id,
            next_page: self.next_page,
        }
    }
}

struct RawResponse {
    body: Vec<u8>,
    request_id: Option<String>,
    next_page: Option<String>,
}

fn serialize_body<B: Serialize>(body: &B, operation: &str) -> Result<Vec<u8>> {
    serde_json::to_vec(body).map_err(|error| {
        Error::invalid_input(format!("could not encode the {operation} request body"))
            .with_context(error.to_string())
    })
}

fn header_string(headers: &header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .filter(|value| !value.is_empty())
}

/// Parse `Retry-After`, which OCI sends as whole seconds.
fn parse_retry_after(headers: &header::HeaderMap) -> Option<Duration> {
    header_string(headers, header::RETRY_AFTER.as_str())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

/// Classify a reqwest failure for the retry policy.
fn classify_transport_error(error: &reqwest::Error) -> Outcome {
    if error.is_timeout() {
        Outcome::Timeout
    } else if error.is_body() || error.is_decode() {
        Outcome::BodyIncomplete
    } else {
        // Connect, DNS, and TLS failures all land here. None of them delivered
        // a request, so they are safe to replay for a read.
        Outcome::Connect
    }
}

/// Turn a reqwest failure into a product error.
///
/// `reqwest::Error`'s own `Display` can include the request URL. That URL never
/// contains credentials for this client (OCI authenticates with a header, not a
/// query parameter), but the message is still rewritten rather than forwarded
/// so that no future URL shape can leak through this path.
fn transport_error(error: &reqwest::Error, operation: &str) -> Error {
    if error.is_timeout() {
        return Error::timeout(format!("{operation} timed out"))
            .with_context("OCI did not respond before the request deadline");
    }
    if error.is_connect() {
        return Error::network(format!("could not connect to OCI for {operation}"))
            .with_context("DNS resolution, the TCP connection, or the TLS handshake failed")
            .with_remediation(
                "check network connectivity, DNS, and any HTTPS proxy or TLS interception",
            );
    }
    Error::network(format!("the connection to OCI failed during {operation}"))
        .with_context("the response was interrupted before it completed")
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod client_tests;
