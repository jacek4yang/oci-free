//! The Free Tier safety policy engine.
//!
//! The engine combines three independent sources into one auditable decision:
//!
//! 1. OCI's own `Shape.billingType`, the strongest evidence available;
//! 2. the dated policy snapshot, which supplies the allowance sizes the API
//!    does not report;
//! 3. live tenancy usage, which says how much of that allowance is left.
//!
//! Every decision keeps its evidence. A user asking "why was this blocked?"
//! gets the specific facts, not a bare boolean, which is what
//! `oci-free policy explain` renders.
//!
//! Strict mode is the default and the only mode: exactly one classification,
//! `VerifiedAlwaysFree`, permits a mutation. Everything else, including
//! anything uncertain, blocks.

use serde::Serialize;

use crate::{
    domain::{
        capacity::{CapacityAssessment, ComputeUsage, InstanceDraw, assess},
        free::{Evidence, FreeAssessment, FreeClassification},
    },
    oci::compute::{Shape, ShapeBillingType},
    policy::snapshot::PolicySnapshot,
};

/// The outcome of evaluating a proposed operation.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SafetyDecision {
    /// Whether the operation may proceed in strict mode.
    pub allowed: bool,
    /// The classification that produced this outcome.
    pub classification: FreeClassification,
    /// Why, in one sentence.
    pub reason: String,
    /// The facts behind the classification.
    pub evidence: Vec<Evidence>,
    /// Non-fatal advisories.
    pub warnings: Vec<String>,
    /// Capacity arithmetic, when a compute allowance applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capacity: Option<CapacityAssessment>,
}

impl SafetyDecision {
    /// Whether a mutation may proceed.
    ///
    /// The single gate every write path must consult.
    #[must_use]
    pub fn permits_mutation(&self) -> bool {
        self.allowed && self.classification == FreeClassification::VerifiedAlwaysFree
    }
}

/// Classify an existing resource or a proposed launch.
#[derive(Debug)]
pub struct PolicyEngine {
    snapshot: PolicySnapshot,
}

impl PolicyEngine {
    #[must_use]
    pub fn new(snapshot: PolicySnapshot) -> Self {
        Self { snapshot }
    }

    #[must_use]
    pub fn snapshot(&self) -> &PolicySnapshot {
        &self.snapshot
    }

    /// Classify a shape using OCI's billing evidence alone.
    ///
    /// This answers "is this shape free at all?", not "is there room for it?".
    #[must_use]
    pub fn classify_shape(&self, shape: &Shape) -> FreeAssessment {
        let mut evidence = vec![Evidence {
            source: "OCI Shape.billingType".to_owned(),
            detail: format!(
                "OCI reports shape {} as {}",
                shape.shape,
                shape.billing_type.as_str()
            ),
        }];
        let mut warnings = Vec::new();

        let classification = match shape.billing_type {
            ShapeBillingType::AlwaysFree => FreeClassification::VerifiedAlwaysFree,
            ShapeBillingType::LimitedFree => FreeClassification::LimitedFree,
            ShapeBillingType::Paid => FreeClassification::Paid,
            ShapeBillingType::Unknown => {
                warnings.push(format!(
                    "OCI did not report a recognised billing type for {}; treating it as \
                     unproven rather than free",
                    shape.shape
                ));
                FreeClassification::Unknown
            }
        };

        // Being Always Free is necessary but not sufficient: without a known
        // allowance this build cannot prove how much may be used.
        if classification == FreeClassification::VerifiedAlwaysFree {
            match self.snapshot.allowance_for(&shape.shape) {
                Some(allowance) => evidence.push(Evidence {
                    source: self.snapshot.citation(),
                    detail: format!(
                        "allowance `{}` covers this shape: up to {:.2} OCPU and {:.2} GB{}",
                        allowance.id,
                        allowance.max_ocpus,
                        allowance.max_memory_gb,
                        allowance
                            .max_instances
                            .map(|max| format!(", at most {max} instances"))
                            .unwrap_or_default()
                    ),
                }),
                None => warnings.push(format!(
                    "OCI reports {} as Always Free, but this build has no verified allowance \
                     for it, so the amount that stays free cannot be proven",
                    shape.shape
                )),
            }
        }

        FreeAssessment {
            classification,
            evidence,
            warnings,
        }
    }

    /// Evaluate a proposed launch: eligibility *and* remaining capacity.
    #[must_use]
    pub fn evaluate_launch(
        &self,
        shape: &Shape,
        request: InstanceDraw,
        used: &ComputeUsage,
    ) -> SafetyDecision {
        let assessment = self.classify_shape(shape);
        let mut evidence = assessment.evidence;
        let mut warnings = assessment.warnings;

        // Not free at all: stop here. Capacity is irrelevant.
        if assessment.classification != FreeClassification::VerifiedAlwaysFree {
            return SafetyDecision {
                allowed: false,
                classification: assessment.classification,
                reason: reason_for(assessment.classification, &shape.shape),
                evidence,
                warnings,
                capacity: None,
            };
        }

        // Always Free, but with no allowance this build cannot prove how much
        // remains free. Downgrade to Unknown rather than approving.
        let Some(allowance) = self.snapshot.allowance_for(&shape.shape) else {
            return SafetyDecision {
                allowed: false,
                classification: FreeClassification::Unknown,
                reason: format!(
                    "{} is Always Free, but oci-free has no verified allowance for it and \
                     cannot prove this launch stays inside the free limit",
                    shape.shape
                ),
                evidence,
                warnings,
                capacity: None,
            };
        };

        let capacity = assess(allowance, used, Some(request));

        evidence.push(Evidence {
            source: "live tenancy usage".to_owned(),
            detail: format!(
                "{:.2} of {:.2} OCPU and {:.2} of {:.2} GB are already committed across {} \
                 instance(s)",
                capacity.used.ocpus,
                capacity.max_ocpus,
                capacity.used.memory_gb,
                capacity.max_memory_gb,
                capacity.used.instances
            ),
        });

        if capacity.fits {
            return SafetyDecision {
                allowed: true,
                classification: FreeClassification::VerifiedAlwaysFree,
                reason: format!(
                    "{} is Always Free and this configuration fits the remaining allowance",
                    shape.shape
                ),
                evidence,
                warnings,
                capacity: Some(capacity),
            };
        }

        // It does not fit. Uncertain usage is a distinct failure from a plain
        // overrun: the first means we could not measure, the second means we
        // measured and it is too big.
        let classification = if capacity.is_certain() {
            FreeClassification::Paid
        } else {
            FreeClassification::Unknown
        };
        let reason = if capacity.is_certain() {
            format!(
                "{} is Always Free, but this configuration exceeds the remaining allowance and \
                 would be billed",
                shape.shape
            )
        } else {
            format!(
                "current usage of {} could not be determined, so oci-free cannot prove this \
                 launch stays free",
                shape.shape
            )
        };
        warnings.extend(capacity.blockers.iter().cloned());

        SafetyDecision {
            allowed: false,
            classification,
            reason,
            evidence,
            warnings,
            capacity: Some(capacity),
        }
    }
}

/// A one-sentence statement of what a classification means for a shape.
///
/// Public so `policy explain` can reuse the same wording rather than inventing
/// a second phrasing of the same verdict.
#[must_use]
pub fn reason_for(classification: FreeClassification, shape: &str) -> String {
    match classification {
        FreeClassification::VerifiedAlwaysFree => {
            format!("{shape} is verified Always Free")
        }
        FreeClassification::LimitedFree => format!(
            "{shape} is only free within a limited allowance, which strict mode does not permit"
        ),
        FreeClassification::Paid => format!("{shape} is a paid shape"),
        FreeClassification::Unknown => format!(
            "OCI did not report a recognised billing classification for {shape}, so free \
             eligibility could not be proven"
        ),
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod engine_tests;
