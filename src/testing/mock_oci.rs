//! An in-process HTTPS server that impersonates OCI.
//!
//! The transport refuses plaintext and never follows redirects, so a mock has
//! to be a real TLS listener with a certificate the client is told to trust.
//! That keeps `https_only` intact while still exercising the whole request
//! path end to end.
//!
//! Two shapes of test use this:
//!
//! * transport tests, which script a sequence of replies and assert on what was
//!   sent;
//! * command tests, which route by method and path so a command can walk a
//!   realistic sequence of OCI calls.
//!
//! Requests are recorded in full, including bodies, which is what lets a test
//! prove the central safety property: a rejected plan issues **zero** write
//! requests.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{TlsAcceptor, rustls::ServerConfig};

use crate::{
    auth::{
        RequestSigner,
        key::{PrivateKey, testing::pkcs8_pem},
    },
    domain::{ocid::Ocid, region::Region},
    oci::{
        client::{OciClient, TransportLimits},
        endpoint::EndpointResolver,
        retry::RetryPolicy,
    },
};

/// Tenancy OCID used by every mock-backed test.
pub const TENANCY: &str = "ocid1.tenancy.oc1..aaaaaaaaexampletenancyid7xk3q7a";
/// User OCID used by every mock-backed test.
pub const USER: &str = "ocid1.user.oc1..aaaaaaaaexampleuserid4m2p8z";

/// One canned HTTP response.
#[derive(Clone)]
pub struct Reply {
    pub status: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
    /// Delay before replying, used to trigger the client's request timeout.
    pub delay: Option<Duration>,
}

impl Reply {
    #[must_use]
    pub fn new(status: u16, body: &str) -> Self {
        Self {
            status,
            body: body.to_owned(),
            headers: Vec::new(),
            delay: None,
        }
    }

    #[must_use]
    pub fn ok(body: &str) -> Self {
        Self::new(200, body)
    }

    /// A 200 carrying a JSON value.
    #[must_use]
    pub fn json(value: &serde_json::Value) -> Self {
        Self::ok(&value.to_string())
    }

    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    #[must_use]
    pub fn delayed(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }
}

/// What the client actually sent.
#[derive(Debug, Clone, Default)]
pub struct CapturedRequest {
    pub request_line: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl CapturedRequest {
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The HTTP method, for example `GET`.
    #[must_use]
    pub fn method(&self) -> &str {
        self.request_line
            .split_whitespace()
            .next()
            .unwrap_or_default()
    }

    /// The request target, including any query string.
    #[must_use]
    pub fn target(&self) -> &str {
        self.request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
    }

    /// Whether this request could change server state.
    #[must_use]
    pub fn is_write(&self) -> bool {
        matches!(self.method(), "POST" | "PUT" | "PATCH" | "DELETE")
    }

    /// The request body decoded as JSON, when there is one.
    #[must_use]
    pub fn json_body(&self) -> Option<serde_json::Value> {
        serde_json::from_str(&self.body).ok()
    }
}

/// One routing rule: a method plus a substring the target must contain.
struct Route {
    method: Option<String>,
    contains: String,
    replies: Vec<Reply>,
    served: AtomicUsize,
}

impl Route {
    fn matches(&self, request: &CapturedRequest) -> bool {
        if let Some(method) = &self.method
            && !method.eq_ignore_ascii_case(request.method())
        {
            return false;
        }
        request.target().contains(&self.contains)
    }

    /// The next reply for this route, repeating the last one once exhausted.
    fn next_reply(&self) -> Reply {
        let index = self.served.fetch_add(1, Ordering::SeqCst);
        self.replies
            .get(index)
            .or_else(|| self.replies.last())
            .cloned()
            .unwrap_or_else(|| Reply::ok("{}"))
    }
}

/// Builds a routed mock server.
#[derive(Default)]
pub struct MockBuilder {
    routes: Vec<Route>,
    fallback: Vec<Reply>,
}

impl MockBuilder {
    /// Answer requests whose target contains `contains` with `replies`, in
    /// order, repeating the last entry once exhausted.
    #[must_use]
    pub fn route(mut self, method: &str, contains: &str, replies: Vec<Reply>) -> Self {
        self.routes.push(Route {
            method: Some(method.to_owned()),
            contains: contains.to_owned(),
            replies,
            served: AtomicUsize::new(0),
        });
        self
    }

    /// Answer a matching request with one reply.
    #[must_use]
    pub fn reply(self, method: &str, contains: &str, reply: Reply) -> Self {
        self.route(method, contains, vec![reply])
    }

    /// Answer a matching GET with a JSON document.
    #[must_use]
    pub fn get(self, contains: &str, body: &serde_json::Value) -> Self {
        self.reply("GET", contains, Reply::json(body))
    }

    /// Replies for requests no route matched.
    #[must_use]
    pub fn fallback(mut self, replies: Vec<Reply>) -> Self {
        self.fallback = replies;
        self
    }

    pub async fn start(self) -> MockOci {
        MockOci::spawn(self.routes, self.fallback).await
    }
}

/// A running mock OCI endpoint.
pub struct MockOci {
    port: u16,
    certificate_der: Vec<u8>,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    served: Arc<AtomicUsize>,
}

impl MockOci {
    #[must_use]
    pub fn builder() -> MockBuilder {
        MockBuilder::default()
    }

    /// Start a server that answers everything with `replies`, in order.
    pub async fn start(replies: Vec<Reply>) -> Self {
        Self::spawn(Vec::new(), replies).await
    }

    async fn spawn(routes: Vec<Route>, fallback: Vec<Reply>) -> Self {
        // The transport connects by IP, so the certificate must carry 127.0.0.1
        // as a subject alternative name or rustls rejects the handshake.
        let certificate = rcgen::generate_simple_self_signed(vec![
            "127.0.0.1".to_owned(),
            "localhost".to_owned(),
        ])
        .expect("certificate");
        let certificate_der = certificate.cert.der().to_vec();
        let key_der = certificate.signing_key.serialize_der();

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.cert.der().clone()],
                tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
            )
            .expect("server config");
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();

        let requests = Arc::new(Mutex::new(Vec::new()));
        let served = Arc::new(AtomicUsize::new(0));
        let routes = Arc::new(routes);
        let fallback = Arc::new(FallbackRoute {
            replies: fallback,
            served: AtomicUsize::new(0),
        });

        let task_requests = Arc::clone(&requests);
        let task_served = Arc::clone(&served);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let requests = Arc::clone(&task_requests);
                let served = Arc::clone(&task_served);
                let routes = Arc::clone(&routes);
                let fallback = Arc::clone(&fallback);
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let Some(request) = read_request(&mut tls).await else {
                        return;
                    };

                    requests.lock().expect("lock").push(request.clone());
                    served.fetch_add(1, Ordering::SeqCst);

                    let reply = routes
                        .iter()
                        .find(|route| route.matches(&request))
                        .map_or_else(|| fallback.next_reply(), Route::next_reply);

                    if let Some(delay) = reply.delay {
                        tokio::time::sleep(delay).await;
                    }
                    let _ = tls.write_all(&render(&reply)).await;
                    let _ = tls.flush().await;
                });
            }
        });

        Self {
            port,
            certificate_der,
            requests,
            served,
        }
    }

    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Total requests received.
    #[must_use]
    pub fn attempts(&self) -> usize {
        self.served.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn request(&self, index: usize) -> CapturedRequest {
        self.requests
            .lock()
            .expect("lock")
            .get(index)
            .cloned()
            .unwrap_or_default()
    }

    #[must_use]
    pub fn requests(&self) -> Vec<CapturedRequest> {
        self.requests.lock().expect("lock").clone()
    }

    /// Every state-changing request the client issued.
    ///
    /// The assertion that matters most in this codebase is that this is empty
    /// after a plan the policy engine rejected.
    #[must_use]
    pub fn writes(&self) -> Vec<CapturedRequest> {
        self.requests()
            .into_iter()
            .filter(CapturedRequest::is_write)
            .collect()
    }

    /// A client pointed at this server, with the default retry policy.
    #[must_use]
    pub fn client(&self) -> OciClient {
        self.client_with(fast_retry(), TransportLimits::default())
    }

    /// A client pointed at this server.
    ///
    /// The endpoint resolver produces real OCI hostnames, so the region is set
    /// to a literal that resolves to the loopback listener instead.
    #[must_use]
    pub fn client_with(&self, retry: RetryPolicy, limits: TransportLimits) -> OciClient {
        let key = PrivateKey::from_pem(&pkcs8_pem()).expect("key");
        let signer = RequestSigner::new(
            &TENANCY.parse::<Ocid>().expect("tenancy"),
            &USER.parse::<Ocid>().expect("user"),
            key,
        );
        OciClient::with_extra_roots(
            signer,
            test_resolver(self.port),
            limits,
            retry,
            vec![self.certificate_der.clone()],
        )
        .expect("client")
    }
}

struct FallbackRoute {
    replies: Vec<Reply>,
    served: AtomicUsize,
}

impl FallbackRoute {
    fn next_reply(&self) -> Reply {
        let index = self.served.fetch_add(1, Ordering::SeqCst);
        self.replies
            .get(index)
            .or_else(|| self.replies.last())
            .cloned()
            .unwrap_or_else(|| Reply::ok("{}"))
    }
}

/// An [`EndpointResolver`] whose every service resolves to `127.0.0.1:port`.
#[must_use]
pub fn test_resolver(port: u16) -> EndpointResolver {
    // `EndpointResolver` formats `{service}.{region}.{domain}`. Encoding the
    // loopback address and port in the region makes every service resolve to
    // the mock server without weakening the production code path.
    let region: Region = format!("x-127-0-0-1-{port}")
        .parse()
        .expect("synthetic test region");
    let mut resolver = EndpointResolver::new(&TENANCY.parse::<Ocid>().expect("tenancy"), region)
        .expect("resolver");
    resolver.override_authority_for_tests(&format!("127.0.0.1:{port}"));
    resolver
}

/// A retry policy with delays short enough to keep tests fast.
#[must_use]
pub fn fast_retry() -> RetryPolicy {
    RetryPolicy {
        max_attempts: 3,
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(5),
        max_total_delay: Duration::from_millis(200),
    }
}

/// Read one HTTP request: head, then exactly `Content-Length` body bytes.
async fn read_request<S>(stream: &mut S) -> Option<CapturedRequest>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 2048];

    let head_end = loop {
        if let Some(position) = find_head_end(&buffer) {
            break position;
        }
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    };

    let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default().to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect();

    let content_length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);

    let mut body = buffer.split_off(head_end + 4);
    while body.len() < content_length {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);

    Some(CapturedRequest {
        request_line,
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    })
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn render(reply: &Reply) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
        reply.status,
        reply.body.len()
    );
    for (name, value) in &reply.headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    response.push_str(&reply.body);
    response.into_bytes()
}
