//! `oci-free free list` — what is free, what is used, what is left.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::{
    commands::context::CommandContext,
    domain::capacity::{CapacityAssessment, ComputeUsage, InstanceDraw, remaining},
    error::Result,
    oci::compute::{ComputeApi, Instance, Shape},
    policy::snapshot::PolicySnapshot,
};

/// Headroom under one Free Tier allowance.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AllowanceReport {
    pub allowance_id: String,
    pub description: String,
    pub shapes: Vec<String>,
    /// OCI's billing classification for each covered shape, when known.
    pub billing_types: BTreeMap<String, String>,
    pub capacity: CapacityAssessment,
    /// Why this allowance cannot be recommended, if it cannot.
    pub blockers: Vec<String>,
}

/// The `free list` payload.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FreeReport {
    pub region: String,
    pub allowances: Vec<AllowanceReport>,
    /// The snapshot that supplied the allowance sizes.
    pub policy_snapshot: String,
    pub warnings: Vec<String>,
}

/// Compute current usage per allowance from live instances.
///
/// An instance whose shape configuration OCI did not report is recorded as
/// undetermined rather than skipped. Skipping it would understate usage, and
/// understated usage is exactly what would let a launch exceed the allowance.
#[must_use]
pub fn usage_by_allowance(
    snapshot: &PolicySnapshot,
    instances: &[Instance],
    shapes: &[Shape],
) -> BTreeMap<String, ComputeUsage> {
    let mut usage: BTreeMap<String, ComputeUsage> = BTreeMap::new();

    for instance in instances.iter().filter(|i| i.consumes_capacity()) {
        let Some(shape_name) = instance.shape.as_deref() else {
            continue;
        };
        let Some(allowance) = snapshot.allowance_for(shape_name) else {
            // Not a Free Tier shape: it consumes no free allowance.
            continue;
        };

        let entry = usage.entry(allowance.id.clone()).or_default();

        // Prefer the instance's own configuration. For a fixed-size shape it is
        // often absent, so fall back to the shape's published size.
        let ocpus = instance
            .shape_config
            .and_then(|config| config.ocpus)
            .or_else(|| shape_size(shapes, shape_name).0);
        let memory = instance
            .shape_config
            .and_then(|config| config.memory_in_g_bs)
            .or_else(|| shape_size(shapes, shape_name).1);

        match (ocpus, memory) {
            (Some(ocpus), Some(memory_gb)) => entry.add(InstanceDraw { ocpus, memory_gb }),
            _ => entry.add_undetermined(instance.label().to_owned()),
        }
    }

    usage
}

fn shape_size(shapes: &[Shape], name: &str) -> (Option<f64>, Option<f64>) {
    shapes
        .iter()
        .find(|shape| shape.shape.eq_ignore_ascii_case(name))
        .map_or((None, None), |shape| (shape.ocpus, shape.memory_in_g_bs))
}

/// Build the free-capacity report.
pub async fn run(context: &CommandContext) -> Result<FreeReport> {
    let compute = ComputeApi::new(context.client());
    let tenancy = context.tenancy();

    let instances = compute.list_instances(tenancy).await?;
    let shapes = compute.list_shapes(tenancy, None).await?;
    let snapshot = context.policy().snapshot();
    let usage = usage_by_allowance(snapshot, &instances, &shapes);
    let mut warnings = Vec::new();
    let mut allowances = Vec::new();

    for allowance in &snapshot.compute_allowances {
        let used = usage.get(&allowance.id).cloned().unwrap_or_default();
        let capacity = remaining(allowance, &used);

        // Cross-check the snapshot against OCI's live billing evidence. If OCI
        // no longer calls a covered shape Always Free, the snapshot is stale
        // and must not be used to recommend it.
        let mut billing_types = BTreeMap::new();
        let mut blockers = Vec::new();
        for shape_name in &allowance.shapes {
            match shapes
                .iter()
                .find(|shape| shape.shape.eq_ignore_ascii_case(shape_name))
            {
                Some(shape) => {
                    billing_types
                        .insert(shape_name.clone(), shape.billing_type.as_str().to_owned());
                    if !shape.is_always_free() {
                        blockers.push(format!(
                            "OCI now reports {shape_name} as {}, not ALWAYS_FREE; the policy \
                             snapshot is out of date and this shape is not being recommended",
                            shape.billing_type.as_str()
                        ));
                    }
                }
                None => blockers.push(format!(
                    "{shape_name} is not offered in this region, so it cannot be launched here"
                )),
            }
        }

        if !used.is_certain() {
            blockers.push(format!(
                "usage is not fully measurable: {}",
                used.undetermined_instances.join(", ")
            ));
        }

        blockers.extend(capacity.blockers.iter().cloned());
        allowances.push(AllowanceReport {
            allowance_id: allowance.id.clone(),
            description: allowance.description.clone(),
            shapes: allowance.shapes.clone(),
            billing_types,
            capacity,
            blockers,
        });
    }

    if instances.iter().any(|i| !i.consumes_capacity()) {
        warnings.push(
            "terminated instances are excluded from usage; they no longer hold an allowance"
                .to_owned(),
        );
    }

    Ok(FreeReport {
        region: context.config().region.to_string(),
        allowances,
        policy_snapshot: snapshot.citation(),
        warnings,
    })
}

/// Render for a terminal.
#[must_use]
pub fn render_human(report: &FreeReport) -> String {
    let mut out = format!("Free Tier capacity in {}\n\n", report.region);

    for allowance in &report.allowances {
        out.push_str(&format!("{}\n", allowance.description));
        out.push_str(&format!("  shapes     {}\n", allowance.shapes.join(", ")));

        let capacity = &allowance.capacity;
        out.push_str(&format!(
            "  used       {:.2} of {:.2} OCPU, {:.2} of {:.2} GB, {} instance(s)\n",
            capacity.used.ocpus,
            capacity.max_ocpus,
            capacity.used.memory_gb,
            capacity.max_memory_gb,
            capacity.used.instances
        ));

        if capacity.is_certain() {
            out.push_str(&format!(
                "  remaining  {:.2} OCPU, {:.2} GB{}\n",
                capacity.remaining_ocpus,
                capacity.remaining_memory_gb,
                capacity
                    .remaining_instances
                    .map(|n| format!(", {n} instance(s)"))
                    .unwrap_or_default()
            ));
        } else {
            out.push_str("  remaining  cannot be determined\n");
        }

        for blocker in &allowance.blockers {
            out.push_str(&format!("  blocked    {blocker}\n"));
        }
        out.push('\n');
    }

    out.push_str(&format!("Allowances from {}\n", report.policy_snapshot));
    for warning in &report.warnings {
        out.push_str(&format!("note: {warning}\n"));
    }
    out
}

#[cfg(test)]
#[path = "free_tests.rs"]
mod free_tests;
