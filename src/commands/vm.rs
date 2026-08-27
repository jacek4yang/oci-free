//! `oci-free vm list` and instance resolution.

use serde::Serialize;

use crate::{
    commands::context::CommandContext,
    domain::free::FreeClassification,
    error::{Error, Result},
    oci::compute::{ComputeApi, Instance, Shape},
};

/// One row of `vm list`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VmSummary {
    pub name: String,
    /// Full OCID. Machine output needs it to address the instance.
    pub id: String,
    pub lifecycle_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shape: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ocpus: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_gb: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability_domain: Option<String>,
    /// Free Tier classification for this instance's shape.
    pub free_classification: String,
    /// Whether oci-free created this instance.
    pub managed_by_oci_free: bool,
}

/// The freeform tag oci-free stamps on resources it creates.
///
/// Ownership is never inferred from a display name: a user can rename anything,
/// and mistaking a user's instance for a managed one would put it in scope for
/// automated cleanup.
pub const MANAGED_TAG: &str = "oci-free:managed";

/// The `vm list` payload.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VmList {
    pub region: String,
    pub instances: Vec<VmSummary>,
    pub warnings: Vec<String>,
}

/// Build a summary row for one instance.
#[must_use]
pub fn summarise(
    instance: &Instance,
    shapes: &[Shape],
    policy: &crate::policy::engine::PolicyEngine,
) -> VmSummary {
    let shape_record = instance
        .shape
        .as_deref()
        .and_then(|name| shapes.iter().find(|s| s.shape.eq_ignore_ascii_case(name)));

    // With no shape record there is no billing evidence, so the classification
    // is Unknown rather than absent. Unknown is the safe reading.
    let classification = shape_record.map_or(FreeClassification::Unknown, |shape| {
        policy.classify_shape(shape).classification
    });

    VmSummary {
        name: instance.label().to_owned(),
        id: instance.id.clone(),
        lifecycle_state: instance.lifecycle_state.clone(),
        shape: instance.shape.clone(),
        ocpus: instance
            .shape_config
            .and_then(|c| c.ocpus)
            .or_else(|| shape_record.and_then(|s| s.ocpus)),
        memory_gb: instance
            .shape_config
            .and_then(|c| c.memory_in_g_bs)
            .or_else(|| shape_record.and_then(|s| s.memory_in_g_bs)),
        availability_domain: instance.availability_domain.clone(),
        free_classification: classification_label(classification).to_owned(),
        managed_by_oci_free: instance.freeform_tags.contains_key(MANAGED_TAG),
    }
}

/// Stable machine-readable classification names used in JSON output.
#[must_use]
pub fn classification_label(classification: FreeClassification) -> &'static str {
    match classification {
        FreeClassification::VerifiedAlwaysFree => "verified_always_free",
        FreeClassification::LimitedFree => "limited_free",
        FreeClassification::Paid => "paid",
        FreeClassification::Unknown => "unknown",
    }
}

/// Resolve a user-supplied instance reference to exactly one instance.
///
/// Accepts a full OCID or a display name. A name matching several instances is
/// an error: silently picking one could start, stop, or terminate the wrong
/// machine.
pub fn resolve<'a>(reference: &str, instances: &'a [Instance]) -> Result<&'a Instance> {
    if let Some(found) = instances.iter().find(|i| i.id == reference) {
        return Ok(found);
    }

    // Only consider live instances by name: a terminated instance keeps its
    // display name, and matching it would be a confusing false positive.
    let matches: Vec<&Instance> = instances
        .iter()
        .filter(|i| i.consumes_capacity())
        .filter(|i| i.display_name.as_deref() == Some(reference))
        .collect();

    match matches.as_slice() {
        [only] => Ok(only),
        [] => Err(Error::not_found(format!("no instance named `{reference}`"))
            .with_context("the name matched no active instance in this tenancy and region")
            .with_remediation("run `oci-free vm list` to see the available instances")),
        several => {
            let detail = several
                .iter()
                .map(|i| format!("  {} ({})", i.id, i.lifecycle_state))
                .collect::<Vec<_>>()
                .join("\n");
            Err(
                Error::ambiguous(format!("`{reference}` matches {} instances", several.len()))
                    .with_context(format!(
                        "oci-free will not guess which one you meant:\n{detail}"
                    ))
                    .with_remediation(
                        "re-run the command with the instance OCID instead of the name",
                    ),
            )
        }
    }
}

/// List instances.
pub async fn list(context: &CommandContext) -> Result<VmList> {
    let compute = ComputeApi::new(context.client());
    let tenancy = context.tenancy();

    let instances = compute.list_instances(tenancy).await?;
    let shapes = compute.list_shapes(tenancy, None).await?;

    let mut warnings = Vec::new();
    let summaries: Vec<VmSummary> = instances
        .iter()
        .filter(|instance| instance.consumes_capacity())
        .map(|instance| summarise(instance, &shapes, context.policy()))
        .collect();

    if summaries.iter().any(|s| s.free_classification == "unknown") {
        warnings.push(
            "some instances use a shape with no recognised billing classification; their Free \
             Tier status could not be proven"
                .to_owned(),
        );
    }

    Ok(VmList {
        region: context.config().region.to_string(),
        instances: summaries,
        warnings,
    })
}

/// Render for a terminal.
#[must_use]
pub fn render_human(list: &VmList) -> String {
    if list.instances.is_empty() {
        return format!("No active instances in {}.\n", list.region);
    }

    let mut out = format!("Instances in {}\n\n", list.region);
    for instance in &list.instances {
        let size = match (instance.ocpus, instance.memory_gb) {
            (Some(ocpus), Some(memory)) => format!("{ocpus:.0} OCPU / {memory:.0} GB"),
            _ => "size unknown".to_owned(),
        };
        out.push_str(&format!(
            "{}  {}\n  {}  {}  {}{}\n",
            instance.name,
            instance.lifecycle_state,
            instance.shape.as_deref().unwrap_or("shape unknown"),
            size,
            instance.free_classification,
            if instance.managed_by_oci_free {
                "  [managed by oci-free]"
            } else {
                ""
            }
        ));
    }
    for warning in &list.warnings {
        out.push_str(&format!("\nwarning: {warning}\n"));
    }
    out
}

#[cfg(test)]
#[path = "vm_tests.rs"]
mod vm_tests;
