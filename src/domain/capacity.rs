//! Free Tier capacity accounting.
//!
//! OCI's `billingType` says whether a shape is Always Free. It does not say how
//! much of it a tenancy may use, and for flexible shapes like
//! `VM.Standard.A1.Flex` the allowance is a pool of OCPUs and memory shared by
//! every instance. Counting instances would be wrong: one four-OCPU instance
//! consumes the entire ARM allowance.
//!
//! Two rules govern the arithmetic here, both aimed at never permitting an
//! over-allocation:
//!
//! * usage that cannot be determined makes the whole assessment uncertain, and
//!   uncertain never fits;
//! * comparisons use a tolerance small enough to absorb float representation
//!   error but far too small to hide a real overrun.

use serde::Serialize;

use crate::policy::snapshot::ComputeAllowance;

/// Tolerance for comparing OCPU and memory quantities.
///
/// OCPU values arrive as JSON numbers and can be fractional, so `2.0` may
/// arrive as `1.9999999999999998`. This absorbs that without being large
/// enough to conceal a meaningful overrun.
const TOLERANCE: f64 = 1e-9;

/// What one instance draws from an allowance.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct InstanceDraw {
    pub ocpus: f64,
    pub memory_gb: f64,
}

/// Consumption already committed against an allowance.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ComputeUsage {
    pub ocpus: f64,
    pub memory_gb: f64,
    pub instances: u32,
    /// Instances whose consumption could not be determined.
    ///
    /// Any entry here makes the assessment uncertain: the true usage is at
    /// least what was measured and possibly more, so no headroom can be proven.
    pub undetermined_instances: Vec<String>,
}

impl ComputeUsage {
    /// Add a determinable instance.
    pub fn add(&mut self, draw: InstanceDraw) {
        self.ocpus += draw.ocpus;
        self.memory_gb += draw.memory_gb;
        self.instances += 1;
    }

    /// Record an instance whose shape configuration OCI did not report.
    pub fn add_undetermined(&mut self, label: impl Into<String>) {
        self.instances += 1;
        self.undetermined_instances.push(label.into());
    }

    /// Whether every contributing instance was measurable.
    #[must_use]
    pub fn is_certain(&self) -> bool {
        self.undetermined_instances.is_empty()
    }
}

/// The result of checking a proposed launch against an allowance.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CapacityAssessment {
    /// Allowance identifier from the policy snapshot.
    pub allowance_id: String,
    pub used: ComputeUsage,
    pub max_ocpus: f64,
    pub max_memory_gb: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_instances: Option<u32>,
    /// Headroom left, never negative and never rounded upward.
    pub remaining_ocpus: f64,
    pub remaining_memory_gb: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_instances: Option<u32>,
    /// Whether the request provably fits.
    pub fits: bool,
    /// Why it does not fit, or why the answer is uncertain.
    pub blockers: Vec<String>,
}

impl CapacityAssessment {
    /// Whether headroom is known exactly.
    #[must_use]
    pub fn is_certain(&self) -> bool {
        self.used.is_certain()
    }
}

/// Headroom remaining under an allowance, with no request applied.
#[must_use]
pub fn remaining(allowance: &ComputeAllowance, used: &ComputeUsage) -> CapacityAssessment {
    assess(allowance, used, None)
}

/// Check whether `request` fits in what is left of `allowance`.
///
/// `request` is `None` to report headroom only.
#[must_use]
pub fn assess(
    allowance: &ComputeAllowance,
    used: &ComputeUsage,
    request: Option<InstanceDraw>,
) -> CapacityAssessment {
    // Clamp at zero: OCI can report usage above a documented allowance (a
    // grandfathered instance, or an allowance Oracle reduced), and negative
    // headroom would read as though capacity were available.
    let remaining_ocpus = (allowance.max_ocpus - used.ocpus).max(0.0);
    let remaining_memory_gb = (allowance.max_memory_gb - used.memory_gb).max(0.0);
    let remaining_instances = allowance
        .max_instances
        .map(|max| max.saturating_sub(used.instances));

    let mut blockers = Vec::new();

    // Uncertainty is a blocker in its own right. If any instance's consumption
    // is unknown, real usage may exceed what was measured, so headroom cannot
    // be proven and the request must not be approved.
    if !used.is_certain() {
        blockers.push(format!(
            "OCI did not report a shape configuration for {}, so current usage cannot be \
             determined and free capacity cannot be proven",
            used.undetermined_instances.join(", ")
        ));
    }

    if let Some(request) = request {
        if request.ocpus < 0.0 || request.memory_gb < 0.0 {
            blockers.push("a request cannot ask for negative capacity".to_owned());
        }
        if used.ocpus + request.ocpus > allowance.max_ocpus + TOLERANCE {
            blockers.push(format!(
                "needs {:.2} OCPU but only {:.2} of the {:.2} OCPU allowance remains",
                request.ocpus, remaining_ocpus, allowance.max_ocpus
            ));
        }
        if used.memory_gb + request.memory_gb > allowance.max_memory_gb + TOLERANCE {
            blockers.push(format!(
                "needs {:.2} GB of memory but only {:.2} GB of the {:.2} GB allowance remains",
                request.memory_gb, remaining_memory_gb, allowance.max_memory_gb
            ));
        }
        if let Some(max) = allowance.max_instances
            && used.instances + 1 > max
        {
            blockers.push(format!(
                "the allowance permits {max} instances and {} already exist",
                used.instances
            ));
        }
    }

    CapacityAssessment {
        allowance_id: allowance.id.clone(),
        used: used.clone(),
        max_ocpus: allowance.max_ocpus,
        max_memory_gb: allowance.max_memory_gb,
        max_instances: allowance.max_instances,
        remaining_ocpus,
        remaining_memory_gb,
        remaining_instances,
        fits: blockers.is_empty(),
        blockers,
    }
}

#[cfg(test)]
mod tests {
    use super::{ComputeUsage, InstanceDraw, assess, remaining};
    use crate::policy::snapshot::ComputeAllowance;

    fn arm_allowance() -> ComputeAllowance {
        ComputeAllowance {
            id: "ampere-a1-flex".to_owned(),
            shapes: vec!["VM.Standard.A1.Flex".to_owned()],
            description: "Ampere A1".to_owned(),
            max_ocpus: 4.0,
            max_memory_gb: 24.0,
            max_instances: None,
            service_limits: None,
        }
    }

    fn micro_allowance() -> ComputeAllowance {
        ComputeAllowance {
            id: "amd-micro".to_owned(),
            shapes: vec!["VM.Standard.E2.1.Micro".to_owned()],
            description: "AMD micro".to_owned(),
            max_ocpus: 2.0,
            max_memory_gb: 2.0,
            max_instances: Some(2),
            service_limits: None,
        }
    }

    fn usage(ocpus: f64, memory_gb: f64, instances: u32) -> ComputeUsage {
        ComputeUsage {
            ocpus,
            memory_gb,
            instances,
            undetermined_instances: Vec::new(),
        }
    }

    #[test]
    fn an_empty_tenancy_has_the_whole_allowance() {
        let assessment = remaining(&arm_allowance(), &ComputeUsage::default());
        assert_eq!(assessment.remaining_ocpus, 4.0);
        assert_eq!(assessment.remaining_memory_gb, 24.0);
        assert!(assessment.fits);
        assert!(assessment.is_certain());
    }

    /// The point of pooled accounting: one large instance can exhaust the
    /// allowance even though only a single instance exists.
    #[test]
    fn flexible_capacity_is_pooled_not_counted_per_instance() {
        let used = usage(4.0, 24.0, 1);
        let request = InstanceDraw {
            ocpus: 1.0,
            memory_gb: 6.0,
        };
        let assessment = assess(&arm_allowance(), &used, Some(request));

        assert!(!assessment.fits, "the allowance is already fully consumed");
        assert_eq!(assessment.remaining_ocpus, 0.0);
        assert!(assessment.blockers.iter().any(|b| b.contains("OCPU")));
        assert!(assessment.blockers.iter().any(|b| b.contains("memory")));
    }

    #[test]
    fn a_request_that_exactly_fills_the_allowance_is_allowed() {
        let used = usage(2.0, 12.0, 1);
        let assessment = assess(
            &arm_allowance(),
            &used,
            Some(InstanceDraw {
                ocpus: 2.0,
                memory_gb: 12.0,
            }),
        );
        assert!(assessment.fits, "an exact fit must be permitted");
        assert!(assessment.blockers.is_empty());
    }

    /// Float representation must not reject an exact fit, and the tolerance
    /// must not hide a real overrun.
    #[test]
    fn tolerance_absorbs_float_error_but_not_real_overruns() {
        let used = usage(1.9999999999999998, 12.0, 1);
        let exact = assess(
            &arm_allowance(),
            &used,
            Some(InstanceDraw {
                ocpus: 2.0,
                memory_gb: 12.0,
            }),
        );
        assert!(exact.fits, "float noise must not reject an exact fit");

        let over = assess(
            &arm_allowance(),
            &usage(2.0, 12.0, 1),
            Some(InstanceDraw {
                ocpus: 2.001,
                memory_gb: 12.0,
            }),
        );
        assert!(!over.fits, "a real overrun must be caught");
    }

    /// Even a single OCPU over the line must be refused.
    #[test]
    fn a_marginal_overrun_is_refused() {
        let assessment = assess(
            &arm_allowance(),
            &usage(3.0, 18.0, 1),
            Some(InstanceDraw {
                ocpus: 2.0,
                memory_gb: 6.0,
            }),
        );
        assert!(!assessment.fits);
        assert!(assessment.blockers.iter().any(|b| b.contains("OCPU")));
    }

    /// Memory alone can block a request whose OCPU count fits.
    #[test]
    fn memory_is_checked_independently_of_ocpus() {
        let assessment = assess(
            &arm_allowance(),
            &usage(1.0, 22.0, 1),
            Some(InstanceDraw {
                ocpus: 1.0,
                memory_gb: 6.0,
            }),
        );
        assert!(!assessment.fits);
        assert!(assessment.blockers.iter().any(|b| b.contains("memory")));
        assert!(!assessment.blockers.iter().any(|b| b.contains("OCPU")));
    }

    #[test]
    fn instance_count_limits_are_enforced() {
        let allowance = micro_allowance();
        let request = InstanceDraw {
            ocpus: 1.0,
            memory_gb: 1.0,
        };

        let first = assess(&allowance, &usage(1.0, 1.0, 1), Some(request));
        assert!(first.fits, "a second micro instance is permitted");
        assert_eq!(first.remaining_instances, Some(1));

        let third = assess(&allowance, &usage(2.0, 2.0, 2), Some(request));
        assert!(!third.fits, "a third micro instance is not");
        assert_eq!(third.remaining_instances, Some(0));
        assert!(third.blockers.iter().any(|b| b.contains("2 instances")));
    }

    /// The central fail-closed rule: if any instance's consumption is unknown,
    /// headroom cannot be proven, so nothing fits.
    #[test]
    fn undetermined_usage_blocks_every_request() {
        let mut used = usage(1.0, 6.0, 1);
        used.add_undetermined("mystery-instance");

        let assessment = assess(
            &arm_allowance(),
            &used,
            Some(InstanceDraw {
                ocpus: 1.0,
                memory_gb: 1.0,
            }),
        );

        assert!(
            !assessment.fits,
            "unknown usage must never be treated as spare capacity"
        );
        assert!(!assessment.is_certain());
        assert!(
            assessment
                .blockers
                .iter()
                .any(|b| b.contains("mystery-instance"))
        );
    }

    /// Usage above the documented allowance must read as zero headroom, never
    /// as negative headroom that later arithmetic could treat as available.
    #[test]
    fn over_consumption_clamps_to_zero_headroom() {
        let assessment = remaining(&arm_allowance(), &usage(6.0, 30.0, 2));
        assert_eq!(assessment.remaining_ocpus, 0.0);
        assert_eq!(assessment.remaining_memory_gb, 0.0);
        assert!(assessment.remaining_ocpus >= 0.0);
    }

    #[test]
    fn negative_requests_are_refused() {
        let assessment = assess(
            &arm_allowance(),
            &ComputeUsage::default(),
            Some(InstanceDraw {
                ocpus: -1.0,
                memory_gb: -1.0,
            }),
        );
        assert!(!assessment.fits);
        assert!(assessment.blockers.iter().any(|b| b.contains("negative")));
    }

    #[test]
    fn usage_accumulates_across_instances() {
        let mut used = ComputeUsage::default();
        used.add(InstanceDraw {
            ocpus: 1.0,
            memory_gb: 6.0,
        });
        used.add(InstanceDraw {
            ocpus: 2.0,
            memory_gb: 12.0,
        });

        assert_eq!(used.ocpus, 3.0);
        assert_eq!(used.memory_gb, 18.0);
        assert_eq!(used.instances, 2);
        assert!(used.is_certain());
    }
}
