//! Service limits and resource availability.
//!
//! The Limits API (version 20181025) answers two different questions, and
//! keeping them apart matters:
//!
//! * `limitValues` says how much of a resource the tenancy is *allowed*;
//! * `resourceAvailability` says how much is currently *used* and how much is
//!   left, and is only offered for some limits.
//!
//! A tenancy commonly lacks the IAM grant for one of these. Every call here can
//! therefore fail with an authorization error the caller is expected to degrade
//! on, rather than treating it as fatal.

use serde::Deserialize;

use crate::{
    domain::ocid::Ocid,
    error::Result,
    oci::{client::OciClient, endpoint::Service, identity::encode_query_value},
};

/// Limits service name for compute.
pub const SERVICE_COMPUTE: &str = "compute";
/// Limits service name for virtual networking.
pub const SERVICE_VCN: &str = "vcn";
/// Limits service name for block storage.
pub const SERVICE_BLOCK_STORAGE: &str = "block-storage";

/// One entry of `GET /20181025/services`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSummary {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// One entry of `GET /20181025/limitDefinitions`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LimitDefinition {
    pub name: String,
    #[serde(default)]
    pub service_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// `GLOBAL`, `REGION`, or `AD`.
    #[serde(default)]
    pub scope_type: Option<String>,
    #[serde(default)]
    pub is_resource_availability_supported: Option<bool>,
    #[serde(default)]
    pub is_deprecated: Option<bool>,
}

impl LimitDefinition {
    /// Whether `resourceAvailability` can be queried for this limit.
    #[must_use]
    pub fn supports_availability(&self) -> bool {
        self.is_resource_availability_supported.unwrap_or(false)
    }
}

/// One entry of `GET /20181025/limitValues`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LimitValue {
    pub name: String,
    #[serde(default)]
    pub scope_type: Option<String>,
    #[serde(default)]
    pub availability_domain: Option<String>,
    /// The allowed quantity. Absent for a limit OCI reports without a value.
    #[serde(default)]
    pub value: Option<i64>,
}

/// `GET /20181025/resourceAvailability`.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceAvailability {
    /// Whole units in use.
    #[serde(default)]
    pub used: Option<i64>,
    /// Whole units still available.
    #[serde(default)]
    pub available: Option<i64>,
    /// Fractional usage, used by limits measured in fractions of a core.
    #[serde(default)]
    pub fractional_usage: Option<f64>,
    #[serde(default)]
    pub fractional_availability: Option<f64>,
    #[serde(default)]
    pub effective_quota_value: Option<f64>,
}

impl ResourceAvailability {
    /// Usage as a number, preferring the fractional form when OCI supplies it.
    #[must_use]
    pub fn usage(&self) -> Option<f64> {
        self.fractional_usage
            .or_else(|| self.used.map(|used| used as f64))
    }

    /// Availability as a number, preferring the fractional form.
    #[must_use]
    pub fn availability(&self) -> Option<f64> {
        self.fractional_availability
            .or_else(|| self.available.map(|available| available as f64))
    }
}

/// Read-only limits operations.
#[derive(Debug)]
pub struct LimitsApi<'a> {
    client: &'a OciClient,
}

impl<'a> LimitsApi<'a> {
    #[must_use]
    pub fn new(client: &'a OciClient) -> Self {
        Self { client }
    }

    /// Services that publish limits for this tenancy.
    pub async fn list_services(&self, tenancy: &Ocid) -> Result<Vec<ServiceSummary>> {
        let path = format!(
            "/services?compartmentId={}",
            encode_query_value(tenancy.as_str())
        );
        self.client
            .list_all(Service::Limits, &path, "ListServices")
            .await
    }

    /// Limit definitions for one service.
    pub async fn list_limit_definitions(
        &self,
        tenancy: &Ocid,
        service_name: &str,
    ) -> Result<Vec<LimitDefinition>> {
        let path = format!(
            "/limitDefinitions?compartmentId={}&serviceName={}",
            encode_query_value(tenancy.as_str()),
            encode_query_value(service_name)
        );
        self.client
            .list_all(Service::Limits, &path, "ListLimitDefinitions")
            .await
    }

    /// Limit values for one service.
    pub async fn list_limit_values(
        &self,
        tenancy: &Ocid,
        service_name: &str,
    ) -> Result<Vec<LimitValue>> {
        let path = format!(
            "/limitValues?compartmentId={}&serviceName={}",
            encode_query_value(tenancy.as_str()),
            encode_query_value(service_name)
        );
        self.client
            .list_all(Service::Limits, &path, "ListLimitValues")
            .await
    }

    /// Current usage and headroom for one limit.
    ///
    /// `availability_domain` is required for an AD-scoped limit and must be
    /// omitted for a regional one; passing the wrong combination is what OCI
    /// answers with a 400.
    pub async fn get_resource_availability(
        &self,
        tenancy: &Ocid,
        service_name: &str,
        limit_name: &str,
        availability_domain: Option<&str>,
    ) -> Result<ResourceAvailability> {
        let mut path = format!(
            "/services/{}/limits/{}/resourceAvailability?compartmentId={}",
            encode_query_value(service_name),
            encode_query_value(limit_name),
            encode_query_value(tenancy.as_str())
        );
        if let Some(domain) = availability_domain {
            path.push_str(&format!(
                "&availabilityDomain={}",
                encode_query_value(domain)
            ));
        }
        Ok(self
            .client
            .get_json::<ResourceAvailability>(Service::Limits, &path, "GetResourceAvailability")
            .await?
            .body)
    }
}

#[cfg(test)]
mod tests {
    use super::{LimitDefinition, LimitValue, ResourceAvailability, ServiceSummary};

    const SERVICES: &str = include_str!("../../tests/fixtures/oci/limits_services.json");
    const DEFINITIONS: &str = include_str!("../../tests/fixtures/oci/limit_definitions.json");
    const VALUES: &str = include_str!("../../tests/fixtures/oci/limit_values.json");
    const AVAILABILITY: &str = include_str!("../../tests/fixtures/oci/resource_availability.json");

    #[test]
    fn decodes_services() {
        let services: Vec<ServiceSummary> =
            serde_json::from_str(SERVICES).expect("services fixture");
        assert!(services.iter().any(|service| service.name == "compute"));
    }

    #[test]
    fn decodes_limit_definitions() {
        let definitions: Vec<LimitDefinition> =
            serde_json::from_str(DEFINITIONS).expect("definitions fixture");
        let arm = definitions
            .iter()
            .find(|definition| definition.name == "standard-a1-core-count")
            .expect("the ARM core limit");
        assert_eq!(arm.scope_type.as_deref(), Some("AD"));
        assert!(arm.supports_availability());

        let unsupported = definitions
            .iter()
            .find(|definition| !definition.supports_availability())
            .expect("a limit without availability support");
        assert!(!unsupported.supports_availability());
    }

    #[test]
    fn decodes_limit_values() {
        let values: Vec<LimitValue> = serde_json::from_str(VALUES).expect("values fixture");
        let arm = values
            .iter()
            .find(|value| value.name == "standard-a1-core-count")
            .expect("the ARM core limit");
        assert_eq!(arm.value, Some(4));
        assert_eq!(arm.scope_type.as_deref(), Some("AD"));
        assert!(arm.availability_domain.is_some());
    }

    /// A limit OCI reports without a value must stay `None`. Showing it as 0
    /// would read as "no capacity", which is a different and wrong claim.
    #[test]
    fn a_missing_limit_value_stays_unknown() {
        let values: Vec<LimitValue> =
            serde_json::from_str(r#"[{"name":"mystery-limit"}]"#).expect("values");
        assert!(values[0].value.is_none());
    }

    #[test]
    fn decodes_resource_availability_with_fractional_cores() {
        let availability: ResourceAvailability =
            serde_json::from_str(AVAILABILITY).expect("availability fixture");
        assert_eq!(availability.usage(), Some(2.0));
        assert_eq!(availability.availability(), Some(2.0));
        assert_eq!(availability.effective_quota_value, Some(4.0));
    }

    /// The fractional form wins when both are present: it is the more precise
    /// one, and rounding up could approve capacity that is not there.
    #[test]
    fn fractional_values_take_precedence() {
        let availability: ResourceAvailability = serde_json::from_str(
            r#"{"used":1,"fractionalUsage":1.5,"available":2,"fractionalAvailability":2.5}"#,
        )
        .expect("availability");
        assert_eq!(availability.usage(), Some(1.5));
        assert_eq!(availability.availability(), Some(2.5));
    }

    #[test]
    fn an_empty_availability_response_is_unknown_not_zero() {
        let availability: ResourceAvailability = serde_json::from_str("{}").expect("availability");
        assert!(availability.usage().is_none());
        assert!(availability.availability().is_none());
    }
}
