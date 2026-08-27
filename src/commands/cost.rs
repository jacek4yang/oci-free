//! `oci-free cost` — current billing-period spend.
//!
//! The single rule this command exists to honour: **never show unknown as
//! zero.** A Free Tier user runs `cost` to confirm they are being charged
//! nothing. Printing `0.00` when the tenancy simply lacks the Usage API grant
//! would give exactly the wrong reassurance, so an unavailable figure is
//! reported as unavailable, with the IAM policy that would fix it.
//!
//! A genuine reported zero is different, and is stated as a fact.

use serde::Serialize;

use crate::{
    commands::{account::usage_unavailable, context::CommandContext},
    domain::time::UtcDateTime,
    error::Result,
    oci::usage::{UsageApi, UsageQuery},
};

/// One service with a non-zero charge.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChargedService {
    pub service: String,
    pub amount: f64,
}

/// The `cost` payload.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CostReport {
    pub period_start: String,
    pub period_end: String,
    /// Whether OCI reported a figure at all.
    ///
    /// Consumers must check this before reading `total`: absent is not zero.
    pub available: bool,
    /// Total for the period. `None` when nothing was reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    /// Services with a charge above zero, largest first.
    pub charged_services: Vec<ChargedService>,
    /// True when OCI reported a figure and it was not zero.
    pub has_charges: bool,
    pub warnings: Vec<String>,
}

impl CostReport {
    /// A one-line verdict suitable for `status`.
    #[must_use]
    pub fn headline(&self) -> String {
        match (self.available, self.total, &self.currency) {
            (true, Some(total), Some(currency)) if total > 0.0 => {
                format!("{total:.2} {currency} charged this billing period")
            }
            (true, Some(total), None) if total > 0.0 => {
                format!("{total:.2} charged this billing period")
            }
            (true, Some(_), _) => "no charges this billing period".to_owned(),
            _ => "cost is unavailable for this tenancy".to_owned(),
        }
    }
}

/// Read current billing-period cost.
pub async fn run(context: &CommandContext) -> Result<CostReport> {
    let now = UtcDateTime::now();
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

    let total = aggregation
        .as_ref()
        .and_then(super::super::oci::usage::UsageAggregation::total);
    let currency = aggregation
        .as_ref()
        .and_then(|aggregation| aggregation.currency().map(str::to_owned));
    let charged_services = aggregation
        .as_ref()
        .map(|aggregation| {
            aggregation
                .charged_services()
                .into_iter()
                .map(|(service, amount)| ChargedService {
                    service: service.to_owned(),
                    amount,
                })
                .collect()
        })
        .unwrap_or_default();

    let has_charges = total.is_some_and(|total| total > 0.0);
    if has_charges {
        warnings.push(
            "this tenancy is being charged. Run `oci-free free list` and `oci-free vm list` to \
             find the resource that is not Always Free."
                .to_owned(),
        );
    }
    if aggregation.is_some() && total.is_none() {
        warnings.push(
            "OCI answered the usage query but reported no amount, so the cost for this period is \
             unknown rather than zero"
                .to_owned(),
        );
    }

    Ok(CostReport {
        period_start: query.time_usage_started.clone(),
        period_end: query.time_usage_ended.clone(),
        available: total.is_some(),
        total,
        currency,
        charged_services,
        has_charges,
        warnings,
    })
}

/// Render `cost` for a terminal.
#[must_use]
pub fn render_human(report: &CostReport) -> String {
    let mut out = format!(
        "Billing period {} to {}\n\n",
        report.period_start, report.period_end
    );

    match (report.available, report.total) {
        (true, Some(total)) => {
            out.push_str(&format!(
                "  total  {total:.2}{}\n",
                report
                    .currency
                    .as_deref()
                    .map(|currency| format!(" {currency}"))
                    .unwrap_or_default()
            ));
        }
        _ => out.push_str("  total  unavailable\n"),
    }

    if !report.charged_services.is_empty() {
        out.push_str("\n  charged\n");
        for service in &report.charged_services {
            out.push_str(&format!(
                "    {:<20} {:.2}\n",
                service.service, service.amount
            ));
        }
    } else if report.available {
        out.push_str("\n  no service reported a charge\n");
    }

    for warning in &report.warnings {
        out.push_str(&format!("\nwarning: {warning}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::CostReport;

    fn report(available: bool, total: Option<f64>) -> CostReport {
        CostReport {
            period_start: "2026-08-01T00:00:00Z".to_owned(),
            period_end: "2026-09-01T00:00:00Z".to_owned(),
            available,
            total,
            currency: Some("USD".to_owned()),
            charged_services: Vec::new(),
            has_charges: total.is_some_and(|total| total > 0.0),
            warnings: Vec::new(),
        }
    }

    /// The defining rule of this command.
    #[test]
    fn an_unavailable_cost_is_never_rendered_as_zero() {
        let rendered = super::render_human(&report(false, None));
        assert!(rendered.contains("unavailable"));
        assert!(
            !rendered.contains("0.00"),
            "an unknown cost must never be shown as 0.00"
        );
        assert!(report(false, None).headline().contains("unavailable"));
    }

    /// A genuine zero is the reassurance the user came for, and is stated.
    #[test]
    fn a_reported_zero_is_stated_as_a_fact() {
        let rendered = super::render_human(&report(true, Some(0.0)));
        assert!(rendered.contains("0.00"));
        assert!(rendered.contains("no service reported a charge"));
        assert_eq!(
            report(true, Some(0.0)).headline(),
            "no charges this billing period"
        );
    }

    #[test]
    fn a_charge_is_surfaced_in_the_headline() {
        let mut charged = report(true, Some(3.47));
        charged.charged_services = vec![super::ChargedService {
            service: "BLOCK_STORAGE".to_owned(),
            amount: 3.47,
        }];
        assert!(charged.headline().contains("3.47 USD"));
        let rendered = super::render_human(&charged);
        assert!(rendered.contains("BLOCK_STORAGE"));
        assert!(rendered.contains("total  3.47 USD"));
    }

    /// The JSON contract must let a consumer tell absent from zero.
    #[test]
    fn json_distinguishes_absent_from_zero() {
        let unknown = serde_json::to_value(report(false, None)).expect("serialize");
        assert_eq!(unknown["available"], false);
        assert!(
            unknown.get("total").is_none(),
            "an unknown total must be omitted, not serialized as 0"
        );

        let zero = serde_json::to_value(report(true, Some(0.0))).expect("serialize");
        assert_eq!(zero["available"], true);
        assert_eq!(zero["total"], 0.0);
        assert_eq!(zero["has_charges"], false);
    }
}
