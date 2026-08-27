//! Identity adapter: tenancy, region subscriptions, availability domains.
//!
//! Response models carry only the fields this product uses. OCI adds fields
//! over time; `serde` ignores unknown ones by default, so a new field in a
//! response cannot break the client.
//!
//! Endpoints follow the Core Services / Identity REST API at API version
//! 20160918.

use serde::Deserialize;

use crate::{
    domain::{ocid::Ocid, region::Region},
    error::{Error, Result},
    oci::{client::OciClient, endpoint::Service},
};

/// `GET /20160918/tenancies/{tenancyId}`
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tenancy {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Short key such as `iad`. Resolved to a full region identifier through
    /// the tenancy's region subscriptions.
    #[serde(default)]
    pub home_region_key: Option<String>,
}

/// One entry of `GET /20160918/regionSubscriptions`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegionSubscription {
    /// Short key, for example `iad`.
    pub region_key: String,
    /// Full identifier, for example `us-ashburn-1`.
    pub region_name: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub is_home_region: Option<bool>,
}

/// One entry of `GET /20160918/availabilityDomains`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvailabilityDomain {
    /// Fully qualified name, for example `Uocm:PHX-AD-1`.
    pub name: String,
    #[serde(default)]
    pub id: Option<String>,
}

/// Read-only identity operations.
#[derive(Debug)]
pub struct IdentityApi<'a> {
    client: &'a OciClient,
}

impl<'a> IdentityApi<'a> {
    #[must_use]
    pub fn new(client: &'a OciClient) -> Self {
        Self { client }
    }

    /// Fetch the tenancy record.
    pub async fn get_tenancy(&self, tenancy: &Ocid) -> Result<Tenancy> {
        let path = format!("/tenancies/{}", encode_path_segment(tenancy.as_str()));
        Ok(self
            .client
            .get_json::<Tenancy>(Service::Identity, &path, "GetTenancy")
            .await?
            .body)
    }

    /// List the regions this tenancy is subscribed to.
    pub async fn list_region_subscriptions(
        &self,
        tenancy: &Ocid,
    ) -> Result<Vec<RegionSubscription>> {
        let path = format!(
            "/tenancies/{}/regionSubscriptions",
            encode_path_segment(tenancy.as_str())
        );
        self.client
            .list_all(Service::Identity, &path, "ListRegionSubscriptions")
            .await
    }

    /// The tenancy's home region.
    ///
    /// Free Tier resources live in the home region, so this is resolved from
    /// live subscription data rather than assumed from configuration. The
    /// subscription list is authoritative: it carries both the short key the
    /// tenancy record reports and the full region identifier endpoints need.
    pub async fn home_region(&self, tenancy: &Ocid) -> Result<Region> {
        let subscriptions = self.list_region_subscriptions(tenancy).await?;

        let home = subscriptions
            .iter()
            .find(|subscription| subscription.is_home_region.unwrap_or(false))
            .ok_or_else(|| {
                Error::not_found("this tenancy reports no home region")
                    .with_context(
                        "every tenancy has exactly one home region; none of the region \
                         subscriptions returned by OCI is flagged as the home region",
                    )
                    .with_remediation("check the tenancy in the OCI Console under Regions")
            })?;

        home.region_name.parse::<Region>().map_err(|error| {
            Error::malformed_response(format!(
                "OCI reported an unusable home region name `{}`",
                home.region_name
            ))
            .with_context(error.to_string())
        })
    }

    /// List availability domains in a compartment.
    ///
    /// Free Tier capacity varies by domain, so callers must discover these
    /// rather than assume a single domain exists.
    pub async fn list_availability_domains(
        &self,
        compartment: &Ocid,
    ) -> Result<Vec<AvailabilityDomain>> {
        let path = format!(
            "/availabilityDomains?compartmentId={}",
            encode_query_value(compartment.as_str())
        );
        self.client
            .list_all(Service::Identity, &path, "ListAvailabilityDomains")
            .await
    }
}

/// Percent-encode a value used as a single path segment.
///
/// OCIDs contain only unreserved characters today, but encoding is applied
/// anyway: the signature covers the request target, so the encoded form must be
/// decided before signing, not by the HTTP layer afterwards.
#[must_use]
pub fn encode_path_segment(value: &str) -> String {
    encode(value)
}

/// Percent-encode a query parameter value.
#[must_use]
pub fn encode_query_value(value: &str) -> String {
    encode(value)
}

fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{AvailabilityDomain, RegionSubscription, Tenancy, encode_query_value};

    const TENANCY_JSON: &str = include_str!("../../tests/fixtures/oci/tenancy.json");
    const SUBSCRIPTIONS_JSON: &str =
        include_str!("../../tests/fixtures/oci/region_subscriptions.json");
    const DOMAINS_JSON: &str = include_str!("../../tests/fixtures/oci/availability_domains.json");

    #[test]
    fn decodes_a_tenancy() {
        let tenancy: Tenancy = serde_json::from_str(TENANCY_JSON).expect("tenancy fixture");
        assert!(tenancy.id.starts_with("ocid1.tenancy."));
        assert_eq!(tenancy.name.as_deref(), Some("example-tenancy"));
        assert_eq!(tenancy.home_region_key.as_deref(), Some("IAD"));
    }

    #[test]
    fn decodes_region_subscriptions() {
        let subscriptions: Vec<RegionSubscription> =
            serde_json::from_str(SUBSCRIPTIONS_JSON).expect("subscriptions fixture");
        assert_eq!(subscriptions.len(), 2);

        let home = subscriptions
            .iter()
            .find(|s| s.is_home_region.unwrap_or(false))
            .expect("a home region");
        assert_eq!(home.region_name, "us-ashburn-1");
        assert_eq!(home.region_key, "IAD");
    }

    #[test]
    fn decodes_availability_domains() {
        let domains: Vec<AvailabilityDomain> =
            serde_json::from_str(DOMAINS_JSON).expect("domains fixture");
        assert_eq!(domains.len(), 3);
        assert_eq!(domains[0].name, "Uocm:US-ASHBURN-AD-1");
    }

    /// OCI keeps adding fields; an unknown one must not break decoding.
    #[test]
    fn unknown_fields_are_ignored() {
        let json = r#"{"id":"ocid1.tenancy.oc1..aaa","name":"n","brandNewField":{"x":1}}"#;
        let tenancy: Tenancy = serde_json::from_str(json).expect("should tolerate new fields");
        assert_eq!(tenancy.name.as_deref(), Some("n"));
    }

    /// Optional fields really are optional: a minimal response must decode.
    #[test]
    fn minimal_responses_decode() {
        let tenancy: Tenancy =
            serde_json::from_str(r#"{"id":"ocid1.tenancy.oc1..aaa"}"#).expect("minimal tenancy");
        assert!(tenancy.name.is_none());
        assert!(tenancy.home_region_key.is_none());
    }

    /// The signature covers the request target, so encoding must happen before
    /// signing and must be stable.
    #[test]
    fn percent_encoding_is_applied_to_query_values() {
        assert_eq!(
            encode_query_value("ocid1.compartment.oc1..aaaa"),
            "ocid1.compartment.oc1..aaaa"
        );
        assert_eq!(encode_query_value("a b&c=d"), "a%20b%26c%3Dd");
        assert_eq!(encode_query_value("sl/ash"), "sl%2Fash");
    }
}
