//! Discovering the caller's own public IPv4 address.
//!
//! `vm net open` and `vm create` offer "just my address" as an ingress source,
//! because typing a `/32` by hand is the step people skip on the way to
//! `0.0.0.0/0`.
//!
//! OCI has no endpoint that echoes the caller's address, so this contacts a
//! third-party echo service. That deserves three deliberate constraints:
//!
//! * **it never happens implicitly.** Only an explicit interactive choice, or
//!   `--source myip`, reaches this code. No command discovers your address as a
//!   side effect;
//! * **the answer is always shown and confirmed** before it becomes a firewall
//!   rule. A compromised or mistaken echo service would otherwise open the port
//!   to somebody else's address, which is a worse outcome than the manual
//!   typing this saves;
//! * **the endpoint is named** in the prompt, so the user knows what was
//!   contacted.
//!
//! A failure here is never fatal: the caller falls back to asking for an
//! address.

use std::time::Duration;

use crate::{
    domain::cidr::Cidr,
    error::{Error, Result},
};

/// The echo service contacted, named in the prompt so the user can see it.
///
/// A single well-known endpoint that returns the address as plain text and
/// nothing else. Trying several in turn would only multiply the number of
/// parties told about the request.
pub const ECHO_ENDPOINT: &str = "https://checkip.amazonaws.com";

/// Longest response accepted. An IPv4 address in text is at most 15 bytes.
const MAX_RESPONSE_BYTES: usize = 64;

/// How long to wait before giving up and asking the user instead.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Ask an echo service for this machine's public IPv4 address.
///
/// Returns it as a `/32`, ready to be shown for confirmation.
pub async fn detect() -> Result<Cidr> {
    let client = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("oci-free/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| {
            Error::network("could not build an HTTPS client to look up your address")
                .with_context(error.to_string())
        })?;

    let response = client.get(ECHO_ENDPOINT).send().await.map_err(|error| {
        Error::network(format!("could not reach {ECHO_ENDPOINT}"))
            .with_context(error.to_string())
            .with_remediation("pass --source with your address instead")
    })?;

    if !response.status().is_success() {
        return Err(
            Error::network(format!("{ECHO_ENDPOINT} answered {}", response.status()))
                .with_remediation("pass --source with your address instead"),
        );
    }

    let body = response.text().await.map_err(|error| {
        Error::network(format!("could not read the reply from {ECHO_ENDPOINT}"))
            .with_context(error.to_string())
    })?;

    parse(&body)
}

/// Parse an echo service's reply into a host route.
///
/// Split out so the validation is testable without a network. Deliberately
/// strict: this value becomes a firewall rule, so anything that is not exactly
/// one IPv4 address is refused rather than coerced.
pub fn parse(body: &str) -> Result<Cidr> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(Error::malformed_response(format!(
            "{ECHO_ENDPOINT} returned {} bytes where an address was expected",
            body.len()
        ))
        .with_remediation("pass --source with your address instead"));
    }

    let trimmed = body.trim();
    let address: std::net::Ipv4Addr = trimmed.parse().map_err(|_| {
        Error::malformed_response(format!("{ECHO_ENDPOINT} did not return an IPv4 address"))
            .with_context(format!("it returned {trimmed:?}"))
            .with_remediation("pass --source with your address instead")
    })?;

    // A private or loopback answer means something between here and the service
    // rewrote the reply, and using it would create a rule that does nothing.
    if address.is_private() || address.is_loopback() || address.is_unspecified() {
        return Err(Error::malformed_response(format!(
            "{ECHO_ENDPOINT} reported {address}, which is not a public address"
        ))
        .with_context("a proxy or captive portal probably answered instead of the echo service")
        .with_remediation("pass --source with your address instead"));
    }

    format!("{address}/32").parse::<Cidr>().map_err(|error| {
        Error::malformed_response("could not build a host route from the detected address")
            .with_context(error.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::{ECHO_ENDPOINT, parse};

    #[test]
    fn parses_a_plain_address_into_a_host_route() {
        let cidr = parse("198.51.100.7\n").expect("parses");
        assert_eq!(cidr.to_string(), "198.51.100.7/32");
        assert!(cidr.is_single_host());
        assert!(!cidr.is_broad());
    }

    #[test]
    fn tolerates_surrounding_whitespace() {
        for body in ["198.51.100.7", " 198.51.100.7 ", "198.51.100.7\r\n"] {
            assert_eq!(parse(body).expect("parses").to_string(), "198.51.100.7/32");
        }
    }

    /// This value becomes a firewall rule, so anything that is not exactly one
    /// address is refused rather than coerced into something plausible.
    #[test]
    fn refuses_anything_that_is_not_one_address() {
        for body in [
            "",
            "not an address",
            "<html>captive portal</html>",
            "198.51.100.7 198.51.100.8",
            "198.51.100.0/24",
            "2001:db8::1",
            "999.1.1.1",
        ] {
            assert!(parse(body).is_err(), "{body:?} must be refused");
        }
    }

    /// A private answer means something rewrote the reply; a rule built from it
    /// would silently do nothing.
    #[test]
    fn refuses_a_private_or_loopback_answer() {
        for body in [
            "10.0.0.7",
            "192.168.1.5",
            "172.16.0.1",
            "127.0.0.1",
            "0.0.0.0",
        ] {
            let error = parse(body).expect_err("{body} must be refused");
            assert!(
                error.message().contains("not a public address")
                    || error.context().unwrap_or_default().contains("proxy"),
                "unhelpful message for {body}: {}",
                error.message()
            );
        }
    }

    /// A very large body is refused before it is parsed.
    #[test]
    fn refuses_an_oversized_reply() {
        let error = parse(&"x".repeat(10_000)).expect_err("must refuse");
        assert!(error.message().contains("bytes"));
    }

    /// Every failure must point at the manual alternative rather than leaving
    /// the user stuck.
    #[test]
    fn every_failure_names_the_manual_alternative() {
        for body in ["", "nonsense", "10.0.0.1"] {
            let error = parse(body).expect_err("must refuse");
            assert!(
                error.remediation().contains("--source"),
                "{body:?} left the user with no alternative"
            );
        }
    }

    #[test]
    fn the_endpoint_is_https_and_nameable() {
        assert!(ECHO_ENDPOINT.starts_with("https://"));
    }
}
