use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FreeClassification {
    VerifiedAlwaysFree,
    LimitedFree,
    Paid,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub source: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreeAssessment {
    pub classification: FreeClassification,
    pub evidence: Vec<Evidence>,
    pub warnings: Vec<String>,
}

impl FreeAssessment {
    #[must_use]
    pub fn is_allowed_by_default(&self) -> bool {
        self.classification == FreeClassification::VerifiedAlwaysFree
    }
}

#[cfg(test)]
mod tests {
    use super::{FreeAssessment, FreeClassification};

    #[test]
    fn only_verified_always_free_is_allowed_by_default() {
        for classification in [
            FreeClassification::LimitedFree,
            FreeClassification::Paid,
            FreeClassification::Unknown,
        ] {
            let assessment = FreeAssessment {
                classification,
                evidence: Vec::new(),
                warnings: Vec::new(),
            };
            assert!(!assessment.is_allowed_by_default());
        }

        let assessment = FreeAssessment {
            classification: FreeClassification::VerifiedAlwaysFree,
            evidence: Vec::new(),
            warnings: Vec::new(),
        };
        assert!(assessment.is_allowed_by_default());
    }
}
