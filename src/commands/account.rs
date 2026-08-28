//! `oci-free account info | limits | usage`.
//!
//! `info` discovers the tenancy and its home region. `limits` and `usage`
//! answer the two questions a Free Tier user actually has — how much am I
//! allowed, and how much have I used — from the Limits API rather than from
//! anything hard-coded.
//!
//! A tenancy commonly lacks the IAM grant for one of these reads. Every one of
//! them therefore degrades to a warning rather than failing the command: a
//! partial answer with the gaps named is far more useful than no answer.

use serde::Serialize;

use crate::{
    commands::context::CommandContext,
    domain::launch::format_quantity,
    error::Result,
    oci::{
        identity::IdentityApi,
        limits::{LimitDefinition, LimitValue, LimitsApi},
        usage::{UsageApi, UsageQuery},
    },
};

/// The `account info` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccountInfo {
    /// Configuration profile in use.
    pub profile: String,
    /// Redacted tenancy OCID. Full OCIDs are not printed by default.
    pub tenancy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenancy_name: Option<String>,
    /// Region the CLI is configured to talk to.
    pub configured_region: String,
    /// Region OCI reports as the tenancy home, where Free Tier resources live.
    pub home_region: String,
    /// Every region this tenancy is subscribed to.
    pub subscribed_regions: Vec<String>,
    /// Availability domains in the home region.
    pub availability_domains: Vec<String>,
    /// Advisories, for example a configured region that is not the home region.
    pub warnings: Vec<String>,
}

/// Gather account information.
pub async fn run(context: &CommandContext) -> Result<AccountInfo> {
    let identity = IdentityApi::new(context.client());
    let tenancy_ocid = context.tenancy();

    let tenancy = identity.get_tenancy(tenancy_ocid).await?;
    let subscriptions = identity.list_region_subscriptions(tenancy_ocid).await?;

    let home_region = subscriptions
        .iter()
        .find(|subscription| subscription.is_home_region.unwrap_or(false))
        .map(|subscription| subscription.region_name.clone())
        .unwrap_or_else(|| "unknown".to_owned());

    let mut warnings = Vec::new();
    let configured_region = context.config().region.to_string();
    if home_region != "unknown" && home_region != configured_region {
        warnings.push(format!(
            "the configured region is {configured_region}, but this tenancy's home region is \
             {home_region}. Always Free resources live in the home region, so most oci-free \
             operations should target it."
        ));
    }

    // Availability domains are read from the home region, since that is where
    // Free Tier capacity exists.
    let availability_domains = match home_region.parse() {
        Ok(region) => {
            let home_client = context.client().in_region(region);
            IdentityApi::new(&home_client)
                .list_availability_domains(tenancy_ocid)
                .await
                .map(|domains| domains.into_iter().map(|domain| domain.name).collect())
                .unwrap_or_else(|error| {
                    warnings.push(format!(
                        "could not list availability domains: {}",
                        diagnostic_error(&error)
                    ));
                    Vec::new()
                })
        }
        Err(_) => Vec::new(),
    };

    Ok(AccountInfo {
        profile: context.config().origin.profile.clone(),
        tenancy: context.config().tenancy.redacted(),
        tenancy_name: tenancy.name,
        configured_region,
        home_region,
        subscribed_regions: subscriptions
            .into_iter()
            .map(|subscription| subscription.region_name)
            .collect(),
        availability_domains,
        warnings,
    })
}

/// Render for a terminal.
#[must_use]
pub fn render_human(info: &AccountInfo) -> String {
    let mut out = String::new();
    out.push_str(&format!("Profile           {}\n", info.profile));
    out.push_str(&format!("Tenancy           {}\n", info.tenancy));
    if let Some(name) = &info.tenancy_name {
        out.push_str(&format!("Name              {name}\n"));
    }
    out.push_str(&format!("Configured region {}\n", info.configured_region));
    out.push_str(&format!("Home region       {}\n", info.home_region));
    out.push_str(&format!(
        "Subscribed        {}\n",
        if info.subscribed_regions.is_empty() {
            "none reported".to_owned()
        } else {
            info.subscribed_regions.join(", ")
        }
    ));
    if !info.availability_domains.is_empty() {
        out.push_str(&format!(
            "Domains           {}\n",
            info.availability_domains.join(", ")
        ));
    }
    for warning in &info.warnings {
        out.push_str(&format!("\nwarning: {warning}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{AccountInfo, render_human, usage_unavailable};

    fn info() -> AccountInfo {
        AccountInfo {
            profile: "DEFAULT".to_owned(),
            tenancy: "ocid1.tenancy.oc1..\u{2026}xk3q7a".to_owned(),
            tenancy_name: Some("example".to_owned()),
            configured_region: "us-ashburn-1".to_owned(),
            home_region: "us-ashburn-1".to_owned(),
            subscribed_regions: vec!["us-ashburn-1".to_owned()],
            availability_domains: vec!["Uocm:US-ASHBURN-AD-1".to_owned()],
            warnings: Vec::new(),
        }
    }

    /// Human output must not print a full tenancy OCID: it identifies the
    /// customer and this output is routinely pasted into issues.
    #[test]
    fn human_output_shows_a_redacted_tenancy() {
        let rendered = render_human(&info());
        assert!(rendered.contains("\u{2026}xk3q7a"));
        assert!(!rendered.contains("aaaaaaaaexampletenancyid"));
    }

    #[test]
    fn a_region_mismatch_is_surfaced_as_a_warning() {
        let mut info = info();
        info.configured_region = "eu-frankfurt-1".to_owned();
        info.warnings
            .push("the configured region is eu-frankfurt-1, but this tenancy's home region is us-ashburn-1".to_owned());

        let rendered = render_human(&info);
        assert!(rendered.contains("warning:"));
        assert!(rendered.contains("home region"));
    }

    #[test]
    fn serializes_with_stable_field_names() {
        let value = serde_json::to_value(info()).expect("serialize");
        for key in [
            "profile",
            "tenancy",
            "configured_region",
            "home_region",
            "subscribed_regions",
            "availability_domains",
            "warnings",
        ] {
            assert!(value.get(key).is_some(), "missing field {key}");
        }
    }

    #[test]
    fn usage_iam_guidance_requires_a_confirmed_oci_response() {
        let oci_denial = crate::oci::error::from_response(
            403,
            "{}",
            Some("req-usage-1".to_owned()),
            "RequestSummarizedUsages",
        );
        let guidance = usage_unavailable(&oci_denial);
        assert!(guidance.contains("IAM policy"));
        assert!(guidance.contains("req-usage-1"));

        let intermediary =
            crate::oci::error::from_response(403, "Forbidden", None, "RequestSummarizedUsages");
        let guidance = usage_unavailable(&intermediary);
        assert!(guidance.contains("proxy or gateway"));
        assert!(!guidance.contains("tenancy's IAM policy"));
    }
}

// ---------------------------------------------------------------------------
// account limits
// ---------------------------------------------------------------------------

/// One service limit, with usage where OCI offers it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LimitRow {
    pub service: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability_domain: Option<String>,
    /// The allowed quantity. `None` means OCI reported no value, which is not
    /// the same as a limit of zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available: Option<f64>,
    /// Whether the policy snapshot marks this limit as Free Tier relevant.
    pub free_tier_relevant: bool,
}

/// The `account limits` payload.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LimitsReport {
    pub region: String,
    /// Limits the policy snapshot marks as Free Tier relevant.
    pub free_tier: Vec<LimitRow>,
    /// Everything else with a non-zero allowance, when `--all` was passed.
    pub other: Vec<LimitRow>,
    /// How many further limits exist but were not listed.
    pub other_omitted: usize,
    pub warnings: Vec<String>,
}

/// Read service limits.
///
/// `include_all` widens the report past the Free Tier-relevant handful. A
/// tenancy publishes hundreds of limits and dumping them all by default would
/// bury the four figures that matter.
pub async fn limits(context: &CommandContext, include_all: bool) -> Result<LimitsReport> {
    let api = LimitsApi::new(context.client());
    let snapshot = context.policy().snapshot();
    let tenancy = context.tenancy();
    let mut warnings = Vec::new();
    let mut free_tier = Vec::new();
    let mut other = Vec::new();
    let mut omitted = 0usize;

    for service in snapshot.limit_services() {
        let definitions = match api.list_limit_definitions(tenancy, service).await {
            Ok(definitions) => definitions,
            Err(error) => {
                warnings.push(format!(
                    "could not read limit definitions for `{service}`: {}",
                    diagnostic_error(&error)
                ));
                Vec::new()
            }
        };
        let values = match api.list_limit_values(tenancy, service).await {
            Ok(values) => values,
            Err(error) => {
                warnings.push(format!(
                    "could not read limit values for `{service}`, so no {service} allowance is \
                     shown: {}",
                    diagnostic_error(&error)
                ));
                continue;
            }
        };

        for value in values {
            let relevant = snapshot.highlights_limit(service, &value.name);
            if !relevant && !include_all {
                omitted += 1;
                continue;
            }
            if !relevant && value.value.unwrap_or(0) == 0 {
                // A zero allowance for a service the tenancy does not use is
                // noise, not information.
                omitted += 1;
                continue;
            }

            let definition = definitions
                .iter()
                .find(|definition| definition.name == value.name);
            let row = build_row(
                context,
                &api,
                service,
                &value,
                definition,
                relevant,
                &mut warnings,
            )
            .await;

            if relevant {
                free_tier.push(row);
            } else {
                other.push(row);
            }
        }
    }

    free_tier.sort_by(|a, b| a.service.cmp(&b.service).then_with(|| a.name.cmp(&b.name)));
    other.sort_by(|a, b| a.service.cmp(&b.service).then_with(|| a.name.cmp(&b.name)));

    if free_tier.is_empty() && warnings.is_empty() {
        warnings.push(
            "none of the Free Tier limits this build knows about were reported by OCI; the limit \
             names may have changed, so check `--all`"
                .to_owned(),
        );
    }

    Ok(LimitsReport {
        region: context.region().to_string(),
        free_tier,
        other,
        other_omitted: omitted,
        warnings,
    })
}

async fn build_row(
    context: &CommandContext,
    api: &LimitsApi<'_>,
    service: &str,
    value: &LimitValue,
    definition: Option<&LimitDefinition>,
    relevant: bool,
    warnings: &mut Vec<String>,
) -> LimitRow {
    let mut used = None;
    let mut available = None;

    // Availability is a second call per limit, so it is only made for the
    // limits actually being highlighted.
    if relevant && definition.is_some_and(LimitDefinition::supports_availability) {
        match api
            .get_resource_availability(
                context.tenancy(),
                service,
                &value.name,
                value.availability_domain.as_deref(),
            )
            .await
        {
            Ok(availability) => {
                used = availability.usage();
                available = availability.availability();
            }
            Err(error) => warnings.push(format!(
                "could not read current usage for `{}`: {}",
                value.name,
                diagnostic_error(&error)
            )),
        }
    }

    LimitRow {
        service: service.to_owned(),
        name: value.name.clone(),
        description: definition.and_then(|definition| definition.description.clone()),
        scope: value.scope_type.clone(),
        availability_domain: value.availability_domain.clone(),
        value: value.value,
        used,
        available,
        free_tier_relevant: relevant,
    }
}

/// Render `account limits` for a terminal.
#[must_use]
pub fn render_limits(report: &LimitsReport) -> String {
    let mut out = format!("Service limits in {}\n\n", report.region);

    out.push_str("Free Tier relevant\n");
    if report.free_tier.is_empty() {
        out.push_str("  (none reported)\n");
    }
    for row in &report.free_tier {
        out.push_str(&format!("  {}\n", render_limit_row(row)));
    }

    if !report.other.is_empty() {
        out.push_str("\nOther limits\n");
        for row in &report.other {
            out.push_str(&format!("  {}\n", render_limit_row(row)));
        }
    }
    if report.other_omitted > 0 {
        out.push_str(&format!(
            "\n{} further limit(s) not shown; pass --all to include them\n",
            report.other_omitted
        ));
    }
    for warning in &report.warnings {
        out.push_str(&format!("\nwarning: {warning}\n"));
    }
    out
}

fn render_limit_row(row: &LimitRow) -> String {
    let allowed = row
        .value
        .map_or_else(|| "not reported".to_owned(), |value| value.to_string());
    let usage = match (row.used, row.available) {
        (Some(used), Some(available)) => format!(
            ", {} used, {} available",
            format_quantity(used),
            format_quantity(available)
        ),
        (Some(used), None) => format!(", {} used", format_quantity(used)),
        _ => String::new(),
    };
    let scope = row
        .availability_domain
        .as_deref()
        .map(|domain| format!(" [{domain}]"))
        .unwrap_or_default();
    format!(
        "{:<34} limit {allowed}{usage}{scope}\n    {}",
        row.name,
        row.description.as_deref().unwrap_or("no description"),
    )
}

// ---------------------------------------------------------------------------
// account usage
// ---------------------------------------------------------------------------

/// One service's consumption in the current billing period.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UsageRow {
    pub service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantity: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// The money figure. Absent means OCI did not report one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<f64>,
}

/// The `account usage` payload.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UsageReport {
    pub region: String,
    pub period_start: String,
    pub period_end: String,
    /// Whether OCI answered the usage query at all.
    pub available: bool,
    pub rows: Vec<UsageRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    pub warnings: Vec<String>,
}

/// Read current billing-period usage.
pub async fn usage(context: &CommandContext) -> Result<UsageReport> {
    let now = crate::domain::time::UtcDateTime::now();
    let query = UsageQuery::billing_period(context.tenancy(), now);
    let mut warnings = Vec::new();

    let aggregation = match UsageApi::new(context.client())
        .request_summarized_usages(&query)
        .await
    {
        Ok(aggregation) => Some(aggregation),
        Err(error) => {
            warnings.push(usage_unavailable(&error));
            None
        }
    };

    let (rows, currency) = aggregation.as_ref().map_or_else(
        || (Vec::new(), None),
        |aggregation| {
            let rows = aggregation
                .items
                .iter()
                .map(|item| UsageRow {
                    service: item.service.clone().unwrap_or_else(|| "unknown".to_owned()),
                    quantity: item.computed_quantity,
                    unit: item.unit.clone(),
                    amount: item.computed_amount,
                })
                .collect();
            (rows, aggregation.currency().map(str::to_owned))
        },
    );

    Ok(UsageReport {
        region: context.region().to_string(),
        period_start: query.time_usage_started.clone(),
        period_end: query.time_usage_ended.clone(),
        available: aggregation.is_some(),
        rows,
        currency,
        warnings,
    })
}

/// Explain an unusable usage response without blaming the wrong thing.
pub(crate) fn usage_unavailable(error: &crate::error::Error) -> String {
    match (error.kind(), error.oci().request_id.as_deref()) {
        (crate::error::ErrorKind::Authorization, Some(request_id)) => {
            "usage and cost data is unavailable: this tenancy's IAM policy does not grant the \
             Usage API. Ask an administrator for `allow group <g> to read usage-report in \
             tenancy`. OCI request id: "
                .to_owned()
                + request_id
        }
        _ => {
            format!(
                "usage and cost data could not be read: {}",
                diagnostic_error(error)
            )
        }
    }
}

fn diagnostic_error(error: &crate::error::Error) -> String {
    let mut detail = error.message().to_owned();
    if let Some(context) = error.context() {
        detail.push_str("; ");
        detail.push_str(context);
    }
    if let Some(request_id) = &error.oci().request_id {
        detail.push_str("; OCI request id: ");
        detail.push_str(request_id);
    }
    detail.push_str("; next: ");
    detail.push_str(error.remediation());
    detail
}

/// Render `account usage` for a terminal.
#[must_use]
pub fn render_usage(report: &UsageReport) -> String {
    let mut out = format!(
        "Usage for {} to {}\n\n",
        report.period_start, report.period_end
    );

    if !report.available {
        out.push_str("Usage is unavailable for this tenancy.\n");
        for warning in &report.warnings {
            out.push_str(&format!("\nwarning: {warning}\n"));
        }
        return out;
    }

    if report.rows.is_empty() {
        out.push_str("OCI reported no usage in this period.\n");
    }
    for row in &report.rows {
        let quantity = match (row.quantity, &row.unit) {
            (Some(quantity), Some(unit)) => format!("{} {unit}", format_quantity(quantity)),
            (Some(quantity), None) => format_quantity(quantity),
            _ => "quantity not reported".to_owned(),
        };
        let amount = match (row.amount, &report.currency) {
            (Some(amount), Some(currency)) => format!("{amount:.2} {currency}"),
            (Some(amount), None) => format!("{amount:.2}"),
            // Never render an unreported amount as 0.00.
            (None, _) => "amount not reported".to_owned(),
        };
        out.push_str(&format!("  {:<20} {quantity:<28} {amount}\n", row.service));
    }

    for warning in &report.warnings {
        out.push_str(&format!("\nwarning: {warning}\n"));
    }
    out
}
