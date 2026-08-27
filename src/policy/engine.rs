use serde::{Deserialize, Serialize};

use crate::domain::free::{FreeAssessment, FreeClassification};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyDecision {
    pub allowed: bool,
    pub reason: String,
}

#[must_use]
pub fn decide(assessment: &FreeAssessment) -> SafetyDecision {
    match assessment.classification {
        FreeClassification::VerifiedAlwaysFree => SafetyDecision {
            allowed: true,
            reason: "resource is verified as Always Free by current policy evidence".to_owned(),
        },
        FreeClassification::LimitedFree => SafetyDecision {
            allowed: false,
            reason: "Limited Free resources are blocked in strict mode".to_owned(),
        },
        FreeClassification::Paid => SafetyDecision {
            allowed: false,
            reason: "paid resources are blocked in strict mode".to_owned(),
        },
        FreeClassification::Unknown => SafetyDecision {
            allowed: false,
            reason: "free eligibility could not be proven".to_owned(),
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::free::{FreeAssessment, FreeClassification};

    use super::decide;

    fn assessment(classification: FreeClassification) -> FreeAssessment {
        FreeAssessment {
            classification,
            evidence: Vec::new(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn unknown_is_fail_closed() {
        let decision = decide(&assessment(FreeClassification::Unknown));
        assert!(!decision.allowed);
    }

    #[test]
    fn verified_always_free_is_allowed() {
        let decision = decide(&assessment(FreeClassification::VerifiedAlwaysFree));
        assert!(decision.allowed);
    }
}
