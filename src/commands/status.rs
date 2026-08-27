//! `oci-free status` — one screen answering "am I OK?".
//!
//! This command aggregates five independent OCI reads, and a Free Tier tenancy
//! very often lacks the IAM grant for at least one of them. So the design rule
//! is: **one missing permission must never blank the whole report.** Each
//! section is gathered independently, a failure becomes a named warning, and
//! everything that did work is still shown.
//!
//! What it must never do is present a partial picture as a complete one. An
//! unreadable cost is reported as unavailable, not as zero; unreadable
//! capacity is reported as unknown, not as free headroom.

use serde::Serialize;

use crate::{
    commands::{context::CommandContext, cost, free},
    domain::{launch::format_quantity, ownership::classify},
    error::Result,
    oci::{compute::ComputeApi, identity::IdentityApi},
};

/// Instance counts by lifecycle state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct InstanceSummary {
    pub running: usize,
    pub stopped: usize,
    /// Provisioning, starting, stopping, and other transient states.
    pub transitioning: usize,
    pub total: usize,
    /// How many oci-free created and may therefore clean up.
    pub managed_by_oci_free: usize,
}

/// Headroom under one Free Tier allowance, condensed for `status`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CapacityLine {
    pub allowance_id: String,
    pub description: String,
    /// `None` when usage could not be measured, which is not the same as zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_ocpus: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_memory_gb: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_instances: Option<u32>,
    pub blockers: Vec<String>,
}

/// The `status` payload.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Status {
    pub profile: String,
    /// Redacted tenancy OCID; a full one identifies the customer.
    pub tenancy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenancy_name: Option<String>,
    pub configured_region: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_region: Option<String>,
    /// Whether the configured credentials authenticated against OCI.
    pub credentials_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instances: Option<InstanceSummary>,
    pub capacity: Vec<CapacityLine>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<cost::CostReport>,
    /// Instances reachable from the whole internet on a sensitive port.
    pub network_warnings: Vec<String>,
    /// Reads that were refused, and what each omission means.
    pub permission_warnings: Vec<String>,
    pub warnings: Vec<String>,
}

impl Status {
    /// Whether anything in the report needs the user's attention.
    #[must_use]
    pub fn needs_attention(&self) -> bool {
        self.cost.as_ref().is_some_and(|cost| cost.has_charges)
            || !self.network_warnings.is_empty()
            || self.capacity.iter().any(|line| !line.blockers.is_empty())
    }
}

/// Build the status report.
pub async fn run(context: &CommandContext) -> Result<Status> {
    let mut warnings = Vec::new();
    let mut permission_warnings = Vec::new();

    // Identity first: it is the one read that must work, because it is what
    // proves the credentials are usable at all.
    let identity = IdentityApi::new(context.client());
    let tenancy_record = identity.get_tenancy(context.tenancy()).await;
    let credentials_valid = tenancy_record.is_ok();
    let tenancy_name = match &tenancy_record {
        Ok(tenancy) => tenancy.name.clone(),
        Err(error) => {
            permission_warnings.push(format!(
                "the tenancy record could not be read, so this report is limited: {error}"
            ));
            None
        }
    };

    let home_region = match identity.home_region(context.tenancy()).await {
        Ok(region) => Some(region.to_string()),
        Err(error) => {
            permission_warnings.push(format!("the home region could not be determined: {error}"));
            None
        }
    };
    if let Some(home) = &home_region
        && home != &context.region().to_string()
    {
        warnings.push(format!(
            "this profile targets {}, but Always Free resources live in the home region {home}",
            context.region()
        ));
    }

    let compute = ComputeApi::new(context.client());
    let instances = match compute.list_instances(context.tenancy()).await {
        Ok(instances) => Some(instances),
        Err(error) => {
            permission_warnings.push(format!(
                "instances could not be listed, so neither the instance summary nor free capacity \
                 can be shown: {error}"
            ));
            None
        }
    };

    let summary = instances.as_ref().map(|instances| {
        let mut summary = InstanceSummary::default();
        for instance in instances.iter().filter(|i| i.consumes_capacity()) {
            summary.total += 1;
            match instance.lifecycle_state.as_str() {
                "RUNNING" => summary.running += 1,
                "STOPPED" => summary.stopped += 1,
                _ => summary.transitioning += 1,
            }
            if classify(&instance.freeform_tags).permits_deletion() {
                summary.managed_by_oci_free += 1;
            }
        }
        summary
    });

    // Capacity needs both instances and shapes; without either it is reported
    // as unknown rather than as available headroom.
    let mut capacity = Vec::new();
    if let Some(instances) = &instances {
        match compute.list_shapes(context.tenancy(), None).await {
            Ok(shapes) => {
                let snapshot = context.policy().snapshot();
                let usage = free::usage_by_allowance(snapshot, instances, &shapes);
                for allowance in &snapshot.compute_allowances {
                    let used = usage.get(&allowance.id).cloned().unwrap_or_default();
                    let assessment = crate::domain::capacity::remaining(allowance, &used);
                    let certain = assessment.is_certain();
                    capacity.push(CapacityLine {
                        allowance_id: allowance.id.clone(),
                        description: allowance.description.clone(),
                        remaining_ocpus: certain.then_some(assessment.remaining_ocpus),
                        remaining_memory_gb: certain.then_some(assessment.remaining_memory_gb),
                        remaining_instances: certain
                            .then_some(())
                            .and(assessment.remaining_instances),
                        blockers: assessment.blockers,
                    });
                }
            }
            Err(error) => permission_warnings.push(format!(
                "shapes could not be listed, so free capacity is unknown: {error}"
            )),
        }
    }

    // Cost has its own unavailability handling and never fails the command.
    let cost_report = cost::run(context).await.ok();
    if let Some(report) = &cost_report {
        warnings.extend(report.warnings.iter().cloned());
    }

    let network_warnings = network_concerns(context, instances.as_deref()).await;

    Ok(Status {
        profile: context.config().origin.profile.clone(),
        tenancy: context.tenancy().redacted(),
        tenancy_name,
        configured_region: context.region().to_string(),
        home_region,
        credentials_valid,
        instances: summary,
        capacity,
        cost: cost_report,
        network_warnings,
        permission_warnings,
        warnings,
    })
}

/// Exposure concerns across every running instance.
///
/// Deliberately shallow: `status` names the instances worth looking at and
/// points at `vm net audit` for the detail, rather than re-rendering a full
/// audit for each one.
async fn network_concerns(
    context: &CommandContext,
    instances: Option<&[crate::oci::compute::Instance]>,
) -> Vec<String> {
    let Some(instances) = instances else {
        return Vec::new();
    };

    let mut concerns = Vec::new();
    for instance in instances
        .iter()
        .filter(|instance| instance.consumes_capacity())
    {
        let network = crate::commands::discovery::load_network(context, instance).await;
        let Some(exposure) = network.exposure() else {
            continue;
        };
        let report = crate::domain::audit::audit(&exposure);
        let critical = report
            .findings
            .iter()
            .filter(|finding| finding.severity == crate::domain::audit::Severity::Critical)
            .count();
        if critical > 0 {
            concerns.push(format!(
                "{}: {critical} critical exposure finding(s); run `oci-free vm net {} audit`",
                instance.label(),
                instance.label()
            ));
        }
    }
    concerns
}

/// Render `status` for a terminal.
#[must_use]
pub fn render_human(status: &Status) -> String {
    let mut out = String::from("oci-free status\n\n");

    out.push_str(&format!("  profile        {}\n", status.profile));
    out.push_str(&format!(
        "  tenancy        {}{}\n",
        status.tenancy,
        status
            .tenancy_name
            .as_deref()
            .map(|name| format!(" ({name})"))
            .unwrap_or_default()
    ));
    out.push_str(&format!("  region         {}\n", status.configured_region));
    out.push_str(&format!(
        "  home region    {}\n",
        status.home_region.as_deref().unwrap_or("unknown")
    ));
    out.push_str(&format!(
        "  credentials    {}\n",
        if status.credentials_valid {
            "accepted by OCI"
        } else {
            "not accepted"
        }
    ));

    match &status.instances {
        Some(summary) => out.push_str(&format!(
            "  instances      {} total ({} running, {} stopped, {} in transition), {} managed by \
             oci-free\n",
            summary.total,
            summary.running,
            summary.stopped,
            summary.transitioning,
            summary.managed_by_oci_free
        )),
        None => out.push_str("  instances      unavailable\n"),
    }

    out.push_str("\n  free tier capacity\n");
    if status.capacity.is_empty() {
        out.push_str("    unknown\n");
    }
    for line in &status.capacity {
        match (line.remaining_ocpus, line.remaining_memory_gb) {
            (Some(ocpus), Some(memory)) => out.push_str(&format!(
                "    {:<18} {} OCPU, {} GB{} remaining\n",
                line.allowance_id,
                format_quantity(ocpus),
                format_quantity(memory),
                line.remaining_instances
                    .map(|count| format!(", {count} instance(s)"))
                    .unwrap_or_default()
            )),
            _ => out.push_str(&format!(
                "    {:<18} remaining capacity cannot be determined\n",
                line.allowance_id
            )),
        }
        for blocker in &line.blockers {
            out.push_str(&format!("      blocked: {blocker}\n"));
        }
    }

    out.push_str("\n  cost\n");
    match &status.cost {
        Some(report) => out.push_str(&format!("    {}\n", report.headline())),
        None => out.push_str("    unavailable\n"),
    }

    if !status.network_warnings.is_empty() {
        out.push_str("\n  network\n");
        for concern in &status.network_warnings {
            out.push_str(&format!("    {concern}\n"));
        }
    }

    for warning in &status.warnings {
        out.push_str(&format!("\nwarning: {warning}\n"));
    }
    for warning in &status.permission_warnings {
        out.push_str(&format!("\npermission: {warning}\n"));
    }
    out
}

#[cfg(test)]
#[path = "status_tests.rs"]
mod status_tests;
