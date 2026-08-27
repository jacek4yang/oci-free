//! Usage and cost reporting.
//!
//! The Usage API (version 20200107) models its query as a POST because the
//! filter does not fit in a query string. That is still a read: it changes
//! nothing, so it goes through [`OciClient::post_read_json`].
//!
//! One rule governs everything in this module: **an amount that OCI did not
//! report stays `None`.** Free Tier users check cost precisely because they
//! want to know that it is zero, and rendering a missing figure as `0.00`
//! would turn "we could not tell" into a false reassurance. The tenancy
//! usually lacks the `usage-report` IAM grant, so absent data is the common
//! case, not the exception.

use serde::{Deserialize, Serialize};

use crate::{
    domain::{ocid::Ocid, time::UtcDateTime},
    error::Result,
    oci::{client::OciClient, endpoint::Service},
};

/// Query for costs rather than raw consumption.
const QUERY_TYPE_COST: &str = "COST";
/// One row per period, which is what a billing-period total needs.
const GRANULARITY_MONTHLY: &str = "MONTHLY";
/// One row per day, used for the recent-days breakdown.
const GRANULARITY_DAILY: &str = "DAILY";

/// The `RequestSummarizedUsagesDetails` body.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageQuery {
    pub tenant_id: String,
    pub time_usage_started: String,
    pub time_usage_ended: String,
    pub granularity: String,
    pub query_type: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub group_by: Vec<String>,
}

impl UsageQuery {
    /// Total cost for the current billing period, grouped by service.
    #[must_use]
    pub fn billing_period(tenancy: &Ocid, now: UtcDateTime) -> Self {
        Self {
            tenant_id: tenancy.as_str().to_owned(),
            time_usage_started: now.start_of_month().to_rfc3339(),
            // The Usage API treats the end as exclusive, so asking for the
            // start of next month covers the whole period including today.
            time_usage_ended: now.start_of_next_month().to_rfc3339(),
            granularity: GRANULARITY_MONTHLY.to_owned(),
            query_type: QUERY_TYPE_COST.to_owned(),
            group_by: vec!["service".to_owned()],
        }
    }

    /// Daily cost over the last `days` complete days plus today.
    #[must_use]
    pub fn recent_days(tenancy: &Ocid, now: UtcDateTime, days: i64) -> Self {
        let start = UtcDateTime::from_unix(now.start_of_day().to_unix() - days * 86_400);
        Self {
            tenant_id: tenancy.as_str().to_owned(),
            time_usage_started: start.to_rfc3339(),
            time_usage_ended: UtcDateTime::from_unix(now.start_of_day().to_unix() + 86_400)
                .to_rfc3339(),
            granularity: GRANULARITY_DAILY.to_owned(),
            query_type: QUERY_TYPE_COST.to_owned(),
            group_by: Vec::new(),
        }
    }
}

/// One row of a usage aggregation.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageItem {
    #[serde(default)]
    pub time_usage_started: Option<String>,
    #[serde(default)]
    pub time_usage_ended: Option<String>,
    /// The money figure. `None` means OCI did not report one.
    #[serde(default)]
    pub computed_amount: Option<f64>,
    #[serde(default)]
    pub computed_quantity: Option<f64>,
    #[serde(default)]
    pub currency: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub sku_name: Option<String>,
    #[serde(default)]
    pub unit: Option<String>,
}

/// The `UsageAggregation` response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageAggregation {
    #[serde(default)]
    pub group_by: Vec<String>,
    #[serde(default)]
    pub items: Vec<UsageItem>,
}

impl UsageAggregation {
    /// Total of every reported amount, and whether anything was reported at
    /// all.
    ///
    /// Returns `None` when no row carried an amount: that is "unknown", and the
    /// caller must not render it as zero. A row that explicitly reports `0.0`
    /// does count, because a genuine zero is exactly what a Free Tier user
    /// wants to see confirmed.
    #[must_use]
    pub fn total(&self) -> Option<f64> {
        let mut total = None;
        for item in &self.items {
            if let Some(amount) = item.computed_amount {
                total = Some(total.unwrap_or(0.0) + amount);
            }
        }
        total
    }

    /// The currency OCI reported, if the rows agree on one.
    #[must_use]
    pub fn currency(&self) -> Option<&str> {
        let mut found: Option<&str> = None;
        for item in &self.items {
            let Some(currency) = item.currency.as_deref() else {
                continue;
            };
            match found {
                None => found = Some(currency),
                Some(existing) if existing == currency => {}
                // Mixed currencies cannot be summed into one figure, so the
                // caller is told there is no single currency.
                Some(_) => return None,
            }
        }
        found
    }

    /// Rows whose amount is greater than zero, largest first.
    #[must_use]
    pub fn charged_services(&self) -> Vec<(&str, f64)> {
        let mut charged: Vec<(&str, f64)> = self
            .items
            .iter()
            .filter_map(|item| {
                let amount = item.computed_amount?;
                (amount > 0.0).then(|| (item.service.as_deref().unwrap_or("unknown"), amount))
            })
            .collect();
        charged.sort_by(|a, b| b.1.total_cmp(&a.1));
        charged
    }
}

/// Read-only usage and cost operations.
#[derive(Debug)]
pub struct UsageApi<'a> {
    client: &'a OciClient,
}

impl<'a> UsageApi<'a> {
    #[must_use]
    pub fn new(client: &'a OciClient) -> Self {
        Self { client }
    }

    /// Run a summarized-usage query.
    pub async fn request_summarized_usages(&self, query: &UsageQuery) -> Result<UsageAggregation> {
        Ok(self
            .client
            .post_read_json::<_, UsageAggregation>(
                Service::Usage,
                "/usage",
                query,
                "RequestSummarizedUsages",
            )
            .await?
            .body)
    }
}

#[cfg(test)]
mod tests {
    use super::{UsageAggregation, UsageQuery};
    use crate::domain::{ocid::Ocid, time::UtcDateTime};

    const USAGE: &str = include_str!("../../tests/fixtures/oci/usage_cost.json");
    const ZERO_USAGE: &str = include_str!("../../tests/fixtures/oci/usage_cost_zero.json");

    fn tenancy() -> Ocid {
        "ocid1.tenancy.oc1..aaaaaaaaexampletenancyid7xk3q7a"
            .parse()
            .expect("tenancy")
    }

    fn now() -> UtcDateTime {
        UtcDateTime::parse_rfc3339("2026-08-27T14:35:02Z").expect("parses")
    }

    #[test]
    fn a_billing_period_query_covers_the_whole_month() {
        let query = UsageQuery::billing_period(&tenancy(), now());
        assert_eq!(query.time_usage_started, "2026-08-01T00:00:00Z");
        assert_eq!(query.time_usage_ended, "2026-09-01T00:00:00Z");
        assert_eq!(query.granularity, "MONTHLY");
        assert_eq!(query.query_type, "COST");
        assert_eq!(query.group_by, vec!["service".to_owned()]);
    }

    #[test]
    fn the_query_serializes_to_the_documented_field_names() {
        let value =
            serde_json::to_value(UsageQuery::billing_period(&tenancy(), now())).expect("serialize");
        assert!(
            value["tenantId"]
                .as_str()
                .expect("tenant")
                .starts_with("ocid1.tenancy.")
        );
        assert_eq!(value["timeUsageStarted"], "2026-08-01T00:00:00Z");
        assert_eq!(value["timeUsageEnded"], "2026-09-01T00:00:00Z");
        assert_eq!(value["queryType"], "COST");
    }

    #[test]
    fn a_recent_days_query_ends_after_today() {
        let query = UsageQuery::recent_days(&tenancy(), now(), 7);
        assert_eq!(query.time_usage_started, "2026-08-20T00:00:00Z");
        assert_eq!(query.time_usage_ended, "2026-08-28T00:00:00Z");
        assert_eq!(query.granularity, "DAILY");
    }

    #[test]
    fn totals_and_currency_come_from_the_reported_rows() {
        let aggregation: UsageAggregation = serde_json::from_str(USAGE).expect("usage fixture");
        let total = aggregation.total().expect("a total");
        assert!((total - 3.47).abs() < 1e-9, "expected 3.47, got {total}");
        assert_eq!(aggregation.currency(), Some("USD"));

        let charged = aggregation.charged_services();
        assert_eq!(charged.len(), 2);
        assert_eq!(charged[0].0, "BLOCK_STORAGE", "largest charge comes first");
    }

    /// A genuine zero is exactly the reassurance a Free Tier user wants, so it
    /// must be reported as zero and not confused with missing data.
    #[test]
    fn a_reported_zero_is_a_real_answer() {
        let aggregation: UsageAggregation =
            serde_json::from_str(ZERO_USAGE).expect("usage fixture");
        assert_eq!(aggregation.total(), Some(0.0));
        assert!(aggregation.charged_services().is_empty());
    }

    /// The central rule: unknown is never zero.
    #[test]
    fn missing_amounts_stay_unknown() {
        let aggregation: UsageAggregation =
            serde_json::from_str(r#"{"groupBy":["service"],"items":[{"service":"COMPUTE"}]}"#)
                .expect("usage");
        assert!(
            aggregation.total().is_none(),
            "an unreported amount must not become 0.00"
        );
        assert!(aggregation.currency().is_none());
    }

    #[test]
    fn an_empty_response_is_unknown() {
        let aggregation: UsageAggregation = serde_json::from_str("{}").expect("usage");
        assert!(aggregation.total().is_none());
        assert!(aggregation.items.is_empty());
    }

    /// Amounts in different currencies cannot be summed into one figure, so no
    /// single currency is claimed.
    #[test]
    fn mixed_currencies_report_no_single_currency() {
        let aggregation: UsageAggregation = serde_json::from_str(
            r#"{"items":[{"computedAmount":1.0,"currency":"USD"},{"computedAmount":2.0,"currency":"EUR"}]}"#,
        )
        .expect("usage");
        assert!(aggregation.currency().is_none());
        assert_eq!(aggregation.total(), Some(3.0));
    }
}
