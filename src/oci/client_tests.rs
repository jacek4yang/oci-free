//! Transport integration tests against an in-process HTTPS server.
//!
//! The transport refuses plaintext, so these run against a real TLS listener
//! using a self-signed certificate the test client is told to trust. That keeps
//! `https_only` intact while still exercising signing, retry, pagination,
//! redirect refusal, body bounds, and error decoding end to end.

use std::time::Duration;

use serde::Deserialize;

use tokio::net::TcpListener;

use super::*;
use crate::{
    auth::key::{PrivateKey, testing::pkcs8_pem},
    domain::ocid::Ocid,
    testing::mock_oci::{MockOci, Reply, TENANCY, USER, fast_retry},
};

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct Widget {
    id: String,
}

#[tokio::test]
async fn signs_and_decodes_a_successful_get() {
    let mock = MockOci::start(vec![
        Reply::ok(r#"{"id":"widget-1"}"#).header("opc-request-id", "req-abc"),
    ])
    .await;
    let client = mock.client_with(fast_retry(), TransportLimits::default());

    let response: OciResponse<Widget> = client
        .get_json(Service::Core, "/widgets/1", "GetWidget")
        .await
        .expect("request should succeed");

    assert_eq!(response.body.id, "widget-1");
    assert_eq!(response.request_id.as_deref(), Some("req-abc"));

    // The request must carry a complete OCI Signature v1 Authorization header.
    let sent = mock.request(0);
    let authorization = sent.header("authorization").expect("authorization header");
    assert!(authorization.starts_with("Signature "));
    assert!(authorization.contains("algorithm=\"rsa-sha256\""));
    assert!(authorization.contains("version=\"1\""));
    assert!(authorization.contains(&format!("keyId=\"{TENANCY}/{USER}/")));
    assert!(authorization.contains("headers=\"date (request-target) host\""));
    assert!(sent.header("date").is_some());
    assert!(sent.request_line.starts_with("GET /20160918/widgets/1"));
}

#[tokio::test]
async fn walks_every_page() {
    let mock = MockOci::start(vec![
        Reply::ok(r#"[{"id":"a"}]"#).header("opc-next-page", "cursor-2"),
        Reply::ok(r#"[{"id":"b"}]"#).header("opc-next-page", "cursor-3"),
        // Final page: no cursor header.
        Reply::ok(r#"[{"id":"c"}]"#),
    ])
    .await;
    let client = mock.client_with(fast_retry(), TransportLimits::default());

    let widgets: Vec<Widget> = client
        .list_all(Service::Core, "/widgets", "ListWidgets")
        .await
        .expect("pagination should succeed");

    assert_eq!(
        widgets,
        vec![
            Widget { id: "a".to_owned() },
            Widget { id: "b".to_owned() },
            Widget { id: "c".to_owned() },
        ],
        "every page must be returned, not just the first"
    );
    assert_eq!(mock.attempts(), 3);
    assert!(mock.request(1).request_line.contains("page=cursor-2"));
    assert!(mock.request(2).request_line.contains("page=cursor-3"));
}

#[tokio::test]
async fn an_empty_cursor_ends_pagination() {
    let mock = MockOci::start(vec![
        Reply::ok(r#"[{"id":"a"}]"#).header("opc-next-page", ""),
        Reply::ok(r#"[{"id":"unreachable"}]"#),
    ])
    .await;
    let client = mock.client_with(fast_retry(), TransportLimits::default());

    let widgets: Vec<Widget> = client
        .list_all(Service::Core, "/widgets", "ListWidgets")
        .await
        .expect("should stop after the first page");
    assert_eq!(widgets.len(), 1);
    assert_eq!(mock.attempts(), 1);
}

#[tokio::test]
async fn a_failing_later_page_surfaces_the_error() {
    let mock = MockOci::start(vec![
        Reply::ok(r#"[{"id":"a"}]"#).header("opc-next-page", "cursor-2"),
        Reply::new(403, r#"{"code":"NotAuthorized","message":"denied"}"#),
    ])
    .await;
    let client = mock.client_with(fast_retry(), TransportLimits::default());

    let error = client
        .list_all::<Widget>(Service::Core, "/widgets", "ListWidgets")
        .await
        .expect_err("a failure on page two must not be swallowed");
    assert_eq!(error.kind(), ErrorKind::Authorization);
}

#[tokio::test]
async fn a_runaway_cursor_is_bounded() {
    // A server that always returns a cursor would loop forever.
    let mock = MockOci::start(vec![
        Reply::ok(r#"[{"id":"a"}]"#).header("opc-next-page", "same-cursor"),
    ])
    .await;
    let limits = TransportLimits {
        max_pages: 4,
        ..TransportLimits::default()
    };
    let client = mock.client_with(fast_retry(), limits);

    let error = client
        .list_all::<Widget>(Service::Core, "/widgets", "ListWidgets")
        .await
        .expect_err("must stop rather than page forever");
    assert_eq!(error.kind(), ErrorKind::MalformedResponse);
    assert!(error.message().contains("more than 4 pages"));
}

#[tokio::test]
async fn status_codes_map_to_error_categories() {
    let cases = [
        (401, ErrorKind::Authentication),
        (403, ErrorKind::Authorization),
        (404, ErrorKind::NotFound),
        (409, ErrorKind::Conflict),
        (400, ErrorKind::InvalidInput),
    ];

    for (status, expected) in cases {
        let mock = MockOci::start(vec![
            Reply::new(status, r#"{"code":"Boom","message":"nope"}"#)
                .header("opc-request-id", "req-99"),
        ])
        .await;
        let client = mock.client_with(fast_retry(), TransportLimits::default());

        let error = client
            .get_json::<Widget>(Service::Core, "/widgets/1", "GetWidget")
            .await
            .expect_err("non-2xx must be an error");

        assert_eq!(error.kind(), expected, "status {status}");
        assert_eq!(error.oci().status, Some(status));
        assert_eq!(error.oci().request_id.as_deref(), Some("req-99"));
        assert_eq!(mock.attempts(), 1, "status {status} must not be retried");
    }
}

#[tokio::test]
async fn an_intermediary_denial_names_the_endpoint_without_exposing_the_path() {
    let mock = MockOci::start(vec![Reply::new(403, "Forbidden")]).await;
    let client = mock.client_with(fast_retry(), TransportLimits::default());

    let error = client
        .get_json::<Widget>(
            Service::Limits,
            "/limitValues?compartmentId=secret-resource-id",
            "ListLimitValues",
        )
        .await
        .expect_err("the intermediary denial must surface");

    assert_eq!(error.kind(), ErrorKind::Authorization);
    assert!(error.oci().request_id.is_none());
    let context = error.context().expect("diagnostic context");
    assert!(context.contains(&format!("endpoint: https://127.0.0.1:{}", mock.port())));
    assert!(context.contains("proxy or gateway"));
    assert!(!context.contains("limitValues"));
    assert!(!context.contains("secret-resource-id"));
    assert!(!error.remediation().contains("IAM"));
}

#[tokio::test]
async fn transient_server_errors_are_retried_then_surface() {
    for status in [500, 502, 503, 504] {
        let mock = MockOci::start(vec![Reply::new(status, r#"{"message":"later"}"#)]).await;
        let client = mock.client_with(fast_retry(), TransportLimits::default());

        let error = client
            .get_json::<Widget>(Service::Core, "/widgets/1", "GetWidget")
            .await
            .expect_err("retry exhaustion must surface the failure");

        assert_eq!(error.kind(), ErrorKind::TransientServer);
        assert_eq!(
            mock.attempts(),
            3,
            "status {status} should use every attempt"
        );
    }
}

#[tokio::test]
async fn a_retried_read_that_recovers_succeeds() {
    let mock = MockOci::start(vec![
        Reply::new(503, r#"{"message":"warming up"}"#),
        Reply::ok(r#"{"id":"widget-1"}"#),
    ])
    .await;
    let client = mock.client_with(fast_retry(), TransportLimits::default());

    let response: OciResponse<Widget> = client
        .get_json(Service::Core, "/widgets/1", "GetWidget")
        .await
        .expect("the second attempt should succeed");
    assert_eq!(response.body.id, "widget-1");
    assert_eq!(mock.attempts(), 2);
}

#[tokio::test]
async fn throttling_is_retried_and_honours_retry_after() {
    let mock = MockOci::start(vec![
        Reply::new(429, r#"{"code":"TooManyRequests"}"#).header("retry-after", "1"),
        Reply::ok(r#"{"id":"widget-1"}"#),
    ])
    .await;
    // max_delay caps the server's 1s request down to something a test can wait.
    let retry = RetryPolicy {
        max_attempts: 3,
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(20),
        max_total_delay: Duration::from_millis(500),
    };
    let client = mock.client_with(retry, TransportLimits::default());

    let response: OciResponse<Widget> = client
        .get_json(Service::Core, "/widgets/1", "GetWidget")
        .await
        .expect("should recover after throttling");
    assert_eq!(response.body.id, "widget-1");
    assert_eq!(mock.attempts(), 2);
}

/// An unprotected write must never be replayed, even on a transient status.
#[tokio::test]
async fn unsafe_writes_are_not_retried() {
    let mock = MockOci::start(vec![Reply::new(503, r#"{"message":"later"}"#)]).await;
    let client = mock.client_with(fast_retry(), TransportLimits::default());

    let error = client
        .post_json::<_, Widget>(
            Service::Core,
            "/widgets",
            &serde_json::json!({"name": "w"}),
            None,
            "CreateWidget",
        )
        .await
        .expect_err("should fail");

    assert_eq!(error.kind(), ErrorKind::TransientServer);
    assert_eq!(
        mock.attempts(),
        1,
        "a write without a retry token must be sent exactly once"
    );
}

/// A write carrying an OCI retry token is replay-safe, so it may retry.
#[tokio::test]
async fn writes_with_a_retry_token_are_retried_and_send_the_token() {
    let mock = MockOci::start(vec![
        Reply::new(503, r#"{"message":"later"}"#),
        Reply::ok(r#"{"id":"widget-1"}"#),
    ])
    .await;
    let client = mock.client_with(fast_retry(), TransportLimits::default());

    let response: OciResponse<Widget> = client
        .post_json(
            Service::Core,
            "/widgets",
            &serde_json::json!({"name": "w"}),
            Some("token-123"),
            "CreateWidget",
        )
        .await
        .expect("should recover");

    assert_eq!(response.body.id, "widget-1");
    assert_eq!(mock.attempts(), 2);
    assert_eq!(mock.request(0).header("opc-retry-token"), Some("token-123"));
    assert_eq!(mock.request(1).header("opc-retry-token"), Some("token-123"));
}

/// Bodies are signed: POST must carry the content headers OCI requires.
#[tokio::test]
async fn post_signs_the_content_headers() {
    let mock = MockOci::start(vec![Reply::ok(r#"{"id":"widget-1"}"#)]).await;
    let client = mock.client_with(fast_retry(), TransportLimits::default());

    let _: OciResponse<Widget> = client
        .post_json(
            Service::Core,
            "/widgets",
            &serde_json::json!({"name": "w"}),
            None,
            "CreateWidget",
        )
        .await
        .expect("should succeed");

    let sent = mock.request(0);
    let authorization = sent.header("authorization").expect("authorization");
    assert!(authorization.contains("content-length"));
    assert!(authorization.contains("content-type"));
    assert!(authorization.contains("x-content-sha256"));
    assert!(sent.header("x-content-sha256").is_some());
}

/// Following a redirect would replay a signed Authorization header against a
/// host the client never signed for.
#[tokio::test]
async fn redirects_are_refused_rather_than_followed() {
    let mock = MockOci::start(vec![
        Reply::new(302, "").header("location", "https://attacker.example/steal"),
    ])
    .await;
    let client = mock.client_with(fast_retry(), TransportLimits::default());

    let error = client
        .get_json::<Widget>(Service::Core, "/widgets/1", "GetWidget")
        .await
        .expect_err("a redirect must not be followed");

    assert_eq!(error.kind(), ErrorKind::MalformedResponse);
    assert!(error.message().contains("attacker.example"));
    assert!(
        error
            .context()
            .expect("context")
            .contains("does not follow redirects")
    );
    assert_eq!(
        mock.attempts(),
        1,
        "the redirect target must not be fetched"
    );
}

#[tokio::test]
async fn malformed_json_is_reported_not_panicked() {
    let mock = MockOci::start(vec![Reply::ok("{ this is not json")]).await;
    let client = mock.client_with(fast_retry(), TransportLimits::default());

    let error = client
        .get_json::<Widget>(Service::Core, "/widgets/1", "GetWidget")
        .await
        .expect_err("malformed JSON must be an error");
    assert_eq!(error.kind(), ErrorKind::MalformedResponse);
    assert!(error.message().contains("GetWidget"));
}

#[tokio::test]
async fn oversized_bodies_are_rejected() {
    let huge = format!(r#"{{"id":"{}"}}"#, "x".repeat(4096));
    let mock = MockOci::start(vec![Reply::ok(&huge)]).await;
    let limits = TransportLimits {
        max_response_bytes: 512,
        ..TransportLimits::default()
    };
    let client = mock.client_with(fast_retry(), limits);

    let error = client
        .get_json::<Widget>(Service::Core, "/widgets/1", "GetWidget")
        .await
        .expect_err("an oversized body must be refused");
    assert_eq!(error.kind(), ErrorKind::MalformedResponse);
    assert!(error.message().contains("exceeded"));
}

#[tokio::test]
async fn a_slow_response_times_out() {
    let mock = MockOci::start(vec![
        Reply::ok(r#"{"id":"widget-1"}"#).delayed(Duration::from_secs(5)),
    ])
    .await;
    let limits = TransportLimits {
        request_timeout: Duration::from_millis(150),
        ..TransportLimits::default()
    };
    // One attempt so the test does not wait for the whole retry ladder.
    let retry = RetryPolicy {
        max_attempts: 1,
        ..fast_retry()
    };
    let client = mock.client_with(retry, limits);

    let error = client
        .get_json::<Widget>(Service::Core, "/widgets/1", "GetWidget")
        .await
        .expect_err("a slow response must time out");
    assert_eq!(error.kind(), ErrorKind::Timeout);
    assert!(error.message().contains("GetWidget"));
}

#[tokio::test]
async fn connection_failures_are_classified_as_network_errors() {
    // Point at a port with nothing listening.
    let key = PrivateKey::from_pem(&pkcs8_pem()).expect("key");
    let signer = RequestSigner::new(
        &TENANCY.parse::<Ocid>().expect("tenancy"),
        &USER.parse::<Ocid>().expect("user"),
        key,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);

    let client = OciClient::with_parts(
        signer,
        crate::testing::mock_oci::test_resolver(port),
        TransportLimits::default(),
        RetryPolicy {
            max_attempts: 1,
            ..fast_retry()
        },
    )
    .expect("client");

    let error = client
        .get_json::<Widget>(Service::Core, "/widgets/1", "GetWidget")
        .await
        .expect_err("a refused connection must be an error");
    assert_eq!(error.kind(), ErrorKind::Network);
    assert!(error.message().contains("Core service"));
    let context = error.context().expect("endpoint context");
    assert!(context.contains(&format!("endpoint: https://127.0.0.1:{port}")));
    assert!(!context.contains("/widgets"));
    for expected in ["DNS", "proxy", "TLS", "connectivity"] {
        assert!(
            error.remediation().contains(expected),
            "remediation must name {expected}: {}",
            error.remediation()
        );
    }
}

/// The transport must never disclose signing material through an error path.
#[tokio::test]
async fn errors_never_leak_the_authorization_header() {
    let mock = MockOci::start(vec![Reply::new(
        500,
        r#"{"code":"Boom","message":"internal"}"#,
    )])
    .await;
    let client = mock.client_with(
        RetryPolicy {
            max_attempts: 1,
            ..fast_retry()
        },
        TransportLimits::default(),
    );

    let error = client
        .get_json::<Widget>(Service::Core, "/widgets/1", "GetWidget")
        .await
        .expect_err("should fail");

    let rendered = format!("{}{:?}{}", error.render_human(), error, error.remediation());
    assert!(!rendered.contains("Signature "));
    assert!(!rendered.contains("keyId"));
    assert!(!rendered.to_lowercase().contains("private key"));
}
