//! `oci-free policy explain <resource>` — why a decision was reached.
//!
//! A safety engine that answers "blocked" without saying why is one users
//! learn to work around. This command exposes the whole chain: OCI's own
//! billing classification, the snapshot entry that supplies the allowance,
//! the tenancy's current consumption, and the projection if a launch were
//! attempted — then the classification and the final decision.
//!
//! The human rendering explains; the JSON keeps the structured evidence so a
//! script can act on the same facts.

use serde::Serialize;

use crate::{
    commands::{context::CommandContext, free::usage_by_allowance},
    domain::{
        capacity::{CapacityAssessment, ComputeUsage, InstanceDraw},
        free::{Evidence, FreeClassification},
        launch::{format_quantity, validate_shape_config},
    },
    error::{Error, Result},
    oci::compute::{ComputeApi, Shape},
    policy::{engine::SafetyDecision, snapshot::ComputeAllowance},
};

/// The `policy explain` payload.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PolicyExplanation {
    /// What the user asked about, echoed back.
    pub resource: String,
    pub region: String,
    /// The resource kind this build resolved the request to.
    pub resolved_as: String,
    /// OCI's live billing classification, when the resource is a shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_billing_type: Option<String>,
    /// The policy-snapshot entry that applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowance: Option<ComputeAllowance>,
    /// The snapshot's own citation, so the evidence is dated.
    pub policy_snapshot: String,
    /// Current tenancy consumption under that allowance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_usage: Option<ComputeUsage>,
    /// Headroom, and whether a launch of this shape would fit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capacity: Option<CapacityAssessment>,
    /// The size a projection was run for, when one was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projected: Option<InstanceDraw>,
    pub classification: FreeClassification,
    /// Whether a mutation involving this resource would be permitted.
    pub allowed: bool,
    pub reason: String,
    pub evidence: Vec<Evidence>,
    pub warnings: Vec<String>,
}

/// Explain the policy decision for a resource.
///
/// `resource` is a compute shape name today, matched case-insensitively. That
/// is the only resource class whose eligibility this build can prove, and
/// anything else is answered with an explicit "not covered" rather than a
/// guess.
pub async fn explain(
    context: &CommandContext,
    resource: &str,
    requested: Option<(f64, f64)>,
) -> Result<PolicyExplanation> {
    let compute = ComputeApi::new(context.client());
    let tenancy = context.tenancy();
    let snapshot = context.policy().snapshot();

    let shapes = compute.list_shapes(tenancy, None).await?;
    let instances = compute.list_instances(tenancy).await?;

    let Some(shape) = shapes
        .iter()
        .find(|shape| shape.shape.eq_ignore_ascii_case(resource))
    else {
        return Ok(uncovered(context, resource, &shapes));
    };

    let usage = usage_by_allowance(snapshot, &instances, &shapes);
    let allowance = snapshot.allowance_for(&shape.shape);
    let used = allowance
        .map(|allowance| usage.get(&allowance.id).cloned().unwrap_or_default())
        .unwrap_or_default();

    // Project a launch so the answer covers "could I create one?", not only
    // "is this shape free in principle?".
    let (draw, projection_warning) = projection(shape, requested)?;

    let (decision, projected): (SafetyDecision, Option<InstanceDraw>) = match draw {
        Some(draw) => (
            context.policy().evaluate_launch(shape, draw, &used),
            Some(draw),
        ),
        // Without a size there is nothing to check capacity against, but the
        // shape's own eligibility is still worth explaining. Answering "shape
        // not resolvable" here would hide the very evidence the user asked for.
        None => {
            let assessment = context.policy().classify_shape(shape);
            (
                SafetyDecision {
                    allowed: false,
                    classification: assessment.classification,
                    reason: format!(
                        "{}. OCI also reported no size for this shape, so no launch could be \
                         projected against the allowance.",
                        crate::policy::engine::reason_for(assessment.classification, &shape.shape)
                    ),
                    evidence: assessment.evidence,
                    warnings: assessment.warnings,
                    capacity: None,
                },
                None,
            )
        }
    };

    let SafetyDecision {
        classification,
        reason,
        evidence,
        mut warnings,
        capacity,
        ..
    } = decision;
    warnings.extend(projection_warning);
    let allowed = classification == FreeClassification::VerifiedAlwaysFree
        && capacity.as_ref().is_none_or(|capacity| capacity.fits);

    Ok(PolicyExplanation {
        resource: resource.to_owned(),
        region: context.region().to_string(),
        resolved_as: format!("compute shape {}", shape.shape),
        live_billing_type: Some(shape.billing_type.as_str().to_owned()),
        allowance: allowance.cloned(),
        policy_snapshot: snapshot.citation(),
        current_usage: allowance.map(|_| used),
        capacity,
        projected,
        classification,
        allowed,
        reason,
        evidence,
        warnings,
    })
}

/// The size to project, and any advisory about why there is none.
///
/// A size the user asked about explicitly must be validated: they posed a
/// specific question and a wrong answer would be worse than an error. A size
/// this build chose for them is best-effort, so a shape OCI describes without
/// one degrades to an eligibility-only explanation.
fn projection(
    shape: &Shape,
    requested: Option<(f64, f64)>,
) -> Result<(Option<InstanceDraw>, Option<String>)> {
    match validate_shape_config(shape, requested) {
        Ok(selection) => Ok((
            Some(InstanceDraw {
                ocpus: selection.ocpus,
                memory_gb: selection.memory_gb,
            }),
            None,
        )),
        Err(error) if requested.is_some() => Err(error),
        Err(error) => Ok((
            None,
            Some(format!(
                "no launch could be projected for {}: {error}",
                shape.shape
            )),
        )),
    }
}

/// The answer for a resource this build has no evidence about.
fn uncovered(context: &CommandContext, resource: &str, shapes: &[Shape]) -> PolicyExplanation {
    let snapshot = context.policy().snapshot();
    let mut warnings = vec![format!(
        "`{resource}` is not a compute shape offered in {}. oci-free can only prove eligibility \
         for resources OCI classifies, which today means compute shapes.",
        context.region()
    )];

    // A near miss is usually a typo; naming the closest shapes is more useful
    // than a bare refusal.
    let similar: Vec<&str> = shapes
        .iter()
        .filter(|shape| {
            shape
                .shape
                .to_ascii_lowercase()
                .contains(&resource.to_ascii_lowercase())
        })
        .map(|shape| shape.shape.as_str())
        .take(5)
        .collect();
    if !similar.is_empty() {
        warnings.push(format!(
            "shapes with a similar name: {}",
            similar.join(", ")
        ));
    }

    PolicyExplanation {
        resource: resource.to_owned(),
        region: context.region().to_string(),
        resolved_as: "not resolved".to_owned(),
        live_billing_type: None,
        allowance: None,
        policy_snapshot: snapshot.citation(),
        current_usage: None,
        capacity: None,
        projected: None,
        classification: FreeClassification::Unknown,
        allowed: false,
        reason: format!(
            "oci-free has no billing evidence for `{resource}`, so it is Unknown and strict mode \
             blocks it"
        ),
        evidence: Vec::new(),
        warnings,
    }
}

/// Whether an explanation should also fail the process.
///
/// It should not: explaining a blocked resource is a successful explanation.
#[must_use]
pub fn is_success(_explanation: &PolicyExplanation) -> bool {
    true
}

/// Render `policy explain` for a terminal.
#[must_use]
pub fn render_human(explanation: &PolicyExplanation) -> String {
    let mut out = format!(
        "Policy decision for {} in {}\n\n",
        explanation.resource, explanation.region
    );

    out.push_str(&format!("  resolved as      {}\n", explanation.resolved_as));
    out.push_str(&format!(
        "  classification   {}\n",
        classification_label(explanation.classification)
    ));
    out.push_str(&format!(
        "  decision         {}\n",
        if explanation.allowed {
            "allowed in strict mode"
        } else {
            "blocked in strict mode"
        }
    ));
    out.push_str(&format!("  because          {}\n", explanation.reason));

    out.push_str("\n  evidence\n");
    if let Some(billing) = &explanation.live_billing_type {
        out.push_str(&format!("    live OCI Shape.billingType: {billing}\n"));
    }
    if let Some(allowance) = &explanation.allowance {
        out.push_str(&format!(
            "    policy snapshot allowance `{}`: up to {} OCPU and {} GB{}\n",
            allowance.id,
            format_quantity(allowance.max_ocpus),
            format_quantity(allowance.max_memory_gb),
            allowance
                .max_instances
                .map(|max| format!(", at most {max} instances"))
                .unwrap_or_default()
        ));
    } else {
        out.push_str("    policy snapshot: no verified allowance covers this resource\n");
    }
    for evidence in &explanation.evidence {
        out.push_str(&format!("    {}: {}\n", evidence.source, evidence.detail));
    }
    out.push_str(&format!("    {}\n", explanation.policy_snapshot));

    if let Some(capacity) = &explanation.capacity {
        out.push_str("\n  capacity\n");
        out.push_str(&format!(
            "    used       {} of {} OCPU, {} of {} GB across {} instance(s)\n",
            format_quantity(capacity.used.ocpus),
            format_quantity(capacity.max_ocpus),
            format_quantity(capacity.used.memory_gb),
            format_quantity(capacity.max_memory_gb),
            capacity.used.instances
        ));
        if capacity.is_certain() {
            out.push_str(&format!(
                "    remaining  {} OCPU, {} GB\n",
                format_quantity(capacity.remaining_ocpus),
                format_quantity(capacity.remaining_memory_gb)
            ));
        } else {
            out.push_str("    remaining  cannot be determined\n");
        }
        if let Some(draw) = explanation.projected {
            out.push_str(&format!(
                "    projected  a launch of {} OCPU and {} GB {}\n",
                format_quantity(draw.ocpus),
                format_quantity(draw.memory_gb),
                if capacity.fits {
                    "would fit"
                } else {
                    "would not fit"
                }
            ));
        }
        for blocker in &capacity.blockers {
            out.push_str(&format!("    blocked    {blocker}\n"));
        }
    }

    for warning in &explanation.warnings {
        out.push_str(&format!("\nwarning: {warning}\n"));
    }
    out
}

/// Stable machine-readable classification names.
#[must_use]
pub fn classification_label(classification: FreeClassification) -> &'static str {
    crate::commands::vm::classification_label(classification)
}

/// Validate a `--ocpus`/`--memory` pair supplied on the command line.
pub fn parse_projection(ocpus: Option<f64>, memory: Option<f64>) -> Result<Option<(f64, f64)>> {
    match (ocpus, memory) {
        (None, None) => Ok(None),
        (Some(ocpus), Some(memory)) => Ok(Some((ocpus, memory))),
        _ => Err(Error::invalid_input(
            "--ocpus and --memory must be given together",
        )
        .with_context(
            "a flexible shape's memory is constrained by its OCPU count, so half a size cannot be \
             checked",
        )
        .with_remediation("pass both, or neither to use the shape's minimum")),
    }
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod policy_tests;
