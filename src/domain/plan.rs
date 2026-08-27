//! Structured mutation plans.
//!
//! CLAUDE.md requires that nothing which could create a billable resource, or
//! change what can reach an instance, happens before the current state, the
//! proposed state, the policy evidence, and the safety decision have all been
//! calculated. This module is how that requirement is enforced rather than
//! merely intended.
//!
//! The mechanism is a capability token. Every write helper takes an
//! [`Approval`], and the only way to obtain one is [`MutationPlan::approve`],
//! which refuses if the plan has blockers, if the policy engine did not permit
//! the operation, or if the user did not confirm. A write path that skipped the
//! plan would not compile, so "the plan cannot be bypassed" is a property of
//! the type system, not of reviewer vigilance.

use serde::Serialize;

use crate::{
    domain::{free::FreeClassification, ownership::Ownership},
    error::{Error, Result},
    policy::engine::SafetyDecision,
};

/// What a planned step does to one resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// A new OCI object will be created.
    Create,
    /// An existing object will be changed in place.
    Modify,
    /// An existing object will be deleted.
    Delete,
    /// An existing object will be attached to another.
    Attach,
    /// An existing object will be detached.
    Detach,
    /// An existing object will be used as-is, with nothing changed.
    ///
    /// Listed explicitly so a plan shows the whole topology, including what it
    /// will *not* touch.
    Reuse,
}

impl ChangeKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Modify => "modify",
            Self::Delete => "delete",
            Self::Attach => "attach",
            Self::Detach => "detach",
            Self::Reuse => "reuse",
        }
    }

    /// Whether this step changes anything at all.
    #[must_use]
    pub fn is_mutation(self) -> bool {
        self != Self::Reuse
    }

    /// Whether this step is irreversible.
    #[must_use]
    pub fn is_destructive(self) -> bool {
        self == Self::Delete
    }
}

/// Whether a step can result in a charge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BillingRisk {
    /// Provably free: OCI reports the resource as Always Free and it fits the
    /// verified allowance.
    None,
    /// Free today, but the allowance is shared and could be exceeded later.
    Bounded,
    /// Free eligibility could not be proven. Strict mode blocks this.
    Unknown,
    /// This will be billed.
    Charged,
}

impl BillingRisk {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Bounded => "bounded",
            Self::Unknown => "unknown",
            Self::Charged => "charged",
        }
    }

    /// The risk implied by a Free Tier classification.
    #[must_use]
    pub fn from_classification(classification: FreeClassification) -> Self {
        match classification {
            FreeClassification::VerifiedAlwaysFree => Self::None,
            FreeClassification::LimitedFree => Self::Bounded,
            FreeClassification::Paid => Self::Charged,
            FreeClassification::Unknown => Self::Unknown,
        }
    }

    /// Whether strict mode permits this risk level.
    #[must_use]
    pub fn is_acceptable_in_strict_mode(self) -> bool {
        self == Self::None
    }
}

/// One step of a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlannedChange {
    pub kind: ChangeKind,
    /// What kind of OCI object, for example `compute instance`.
    pub resource_type: String,
    /// The name the user will recognise.
    pub name: String,
    /// The OCID, present for an object that already exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// State before the change, absent for a creation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    /// State after the change.
    pub after: String,
    /// Who owns the object, for anything that already exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ownership: Option<Ownership>,
    pub billing_risk: BillingRisk,
    /// Advisories specific to this step.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl PlannedChange {
    #[must_use]
    pub fn new(
        kind: ChangeKind,
        resource_type: impl Into<String>,
        name: impl Into<String>,
        after: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            resource_type: resource_type.into(),
            name: name.into(),
            id: None,
            before: None,
            after: after.into(),
            ownership: None,
            billing_risk: BillingRisk::None,
            notes: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    #[must_use]
    pub fn with_before(mut self, before: impl Into<String>) -> Self {
        self.before = Some(before.into());
        self
    }

    #[must_use]
    pub fn with_ownership(mut self, ownership: Ownership) -> Self {
        self.ownership = Some(ownership);
        self
    }

    #[must_use]
    pub fn with_billing_risk(mut self, risk: BillingRisk) -> Self {
        self.billing_risk = risk;
        self
    }

    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    /// A one-line rendering for the plan display.
    #[must_use]
    pub fn summary(&self) -> String {
        match &self.before {
            Some(before) => format!(
                "{:<7} {} {}: {before} -> {}",
                self.kind.as_str(),
                self.resource_type,
                self.name,
                self.after
            ),
            None => format!(
                "{:<7} {} {}: {}",
                self.kind.as_str(),
                self.resource_type,
                self.name,
                self.after
            ),
        }
    }
}

/// What a plan will change about who can reach an instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExposureDelta {
    /// Ingress allowances the plan adds, as human-readable summaries.
    pub added: Vec<String>,
    /// Ingress allowances the plan removes.
    pub removed: Vec<String>,
    /// Allowances that survive the change because another object grants them.
    pub unchanged_residual: Vec<String>,
}

impl ExposureDelta {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// A complete, reviewable description of a mutation.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MutationPlan {
    /// Dotted command identifier, for example `vm.create`.
    pub operation: String,
    pub region: String,
    pub changes: Vec<PlannedChange>,
    /// The policy engine's verdict, when the operation involves billing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safety: Option<SafetyDecision>,
    /// Network exposure before and after, for operations that change it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposure: Option<ExposureDelta>,
    /// Advisories the user should read but which do not stop the operation.
    pub warnings: Vec<String>,
    /// Reasons the operation must not proceed. A non-empty list is fatal.
    pub blockers: Vec<String>,
}

impl MutationPlan {
    #[must_use]
    pub fn new(operation: impl Into<String>, region: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            region: region.into(),
            changes: Vec::new(),
            safety: None,
            exposure: None,
            warnings: Vec::new(),
            blockers: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_change(mut self, change: PlannedChange) -> Self {
        self.changes.push(change);
        self
    }

    pub fn add_change(&mut self, change: PlannedChange) {
        self.changes.push(change);
    }

    pub fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }

    pub fn add_blocker(&mut self, blocker: impl Into<String>) {
        self.blockers.push(blocker.into());
    }

    /// Attach the policy engine's decision, adopting its warnings.
    ///
    /// A decision that does not permit a mutation becomes a blocker here, so a
    /// caller cannot record a refusal and then approve the plan anyway.
    #[must_use]
    pub fn with_safety(mut self, decision: SafetyDecision) -> Self {
        self.warnings.extend(decision.warnings.iter().cloned());
        if !decision.permits_mutation() {
            self.blockers.push(decision.reason.clone());
        }
        self.safety = Some(decision);
        self
    }

    #[must_use]
    pub fn with_exposure(mut self, delta: ExposureDelta) -> Self {
        self.exposure = Some(delta);
        self
    }

    /// The steps that actually change something.
    #[must_use]
    pub fn mutations(&self) -> Vec<&PlannedChange> {
        self.changes
            .iter()
            .filter(|change| change.kind.is_mutation())
            .collect()
    }

    /// Whether the plan destroys anything.
    #[must_use]
    pub fn is_destructive(&self) -> bool {
        self.changes
            .iter()
            .any(|change| change.kind.is_destructive())
    }

    /// The worst billing risk across every step.
    #[must_use]
    pub fn billing_risk(&self) -> BillingRisk {
        self.changes
            .iter()
            .map(|change| change.billing_risk)
            .max()
            .unwrap_or(BillingRisk::None)
    }

    /// Whether every safety condition is satisfied.
    ///
    /// Confirmation is deliberately *not* part of this: a plan can be safe and
    /// still need the user to say yes.
    #[must_use]
    pub fn is_safe(&self) -> bool {
        self.blockers.is_empty()
            && self.billing_risk().is_acceptable_in_strict_mode()
            && self
                .safety
                .as_ref()
                .is_none_or(SafetyDecision::permits_mutation)
    }

    /// Turn an approved plan into the token every write helper requires.
    ///
    /// `confirmed` must come from an explicit user decision: an interactive
    /// prompt, or `--yes` in a non-interactive run. Defaulting it to `true`
    /// anywhere would defeat the point of the plan.
    pub fn approve(&self, confirmed: bool) -> Result<Approval> {
        if !self.blockers.is_empty() {
            return Err(Error::policy_rejected(format!(
                "{} was blocked by the safety policy",
                self.operation
            ))
            .with_context(self.blockers.join("; "))
            .with_remediation(
                "run `oci-free policy explain` for the evidence, or change the request so it \
                 stays inside the verified free allowance",
            ));
        }

        let risk = self.billing_risk();
        if !risk.is_acceptable_in_strict_mode() {
            return Err(Error::billing_uncertain(format!(
                "{} could be billed and was refused",
                self.operation
            ))
            .with_context(format!(
                "the plan's billing risk is `{}`; strict mode allows only resources proven to be \
                 Always Free",
                risk.as_str()
            )));
        }

        if !confirmed {
            return Err(
                Error::unsupported_state(format!("{} was not confirmed", self.operation))
                    .with_context("nothing was changed")
                    .with_remediation(
                        "re-run and confirm at the prompt, or pass --yes to accept the plan in a \
                     non-interactive run",
                    ),
            );
        }

        Ok(Approval {
            operation: self.operation.clone(),
        })
    }

    /// Render the plan for a terminal.
    #[must_use]
    pub fn render_human(&self) -> String {
        let mut out = format!("Plan for {} in {}\n\n", self.operation, self.region);

        for change in &self.changes {
            out.push_str(&format!("  {}\n", change.summary()));
            if let Some(ownership) = change.ownership {
                out.push_str(&format!("          ownership: {}\n", ownership.explain()));
            }
            for note in &change.notes {
                out.push_str(&format!("          note: {note}\n"));
            }
        }

        out.push_str(&format!(
            "\n  billing risk: {}\n",
            self.billing_risk().as_str()
        ));

        if let Some(safety) = &self.safety {
            out.push_str(&format!("  policy:       {}\n", safety.reason));
            for evidence in &safety.evidence {
                out.push_str(&format!(
                    "                - {}: {}\n",
                    evidence.source, evidence.detail
                ));
            }
        }

        if let Some(exposure) = &self.exposure
            && !exposure.is_empty()
        {
            out.push_str("\n  network exposure\n");
            for added in &exposure.added {
                out.push_str(&format!("    + {added}\n"));
            }
            for removed in &exposure.removed {
                out.push_str(&format!("    - {removed}\n"));
            }
            for residual in &exposure.unchanged_residual {
                out.push_str(&format!(
                    "    = {residual} (unchanged; granted elsewhere)\n"
                ));
            }
        }

        for warning in &self.warnings {
            out.push_str(&format!("\nwarning: {warning}\n"));
        }
        for blocker in &self.blockers {
            out.push_str(&format!("\nblocked: {blocker}\n"));
        }
        out
    }
}

/// Proof that a [`MutationPlan`] was built, checked, and confirmed.
///
/// Held by value and required by every write helper. It cannot be constructed
/// outside this module, so there is no way to reach a write without first
/// producing and approving a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    operation: String,
}

impl Approval {
    /// The operation this approval was granted for.
    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }
}

#[cfg(test)]
mod tests {
    use super::{Approval, BillingRisk, ChangeKind, ExposureDelta, MutationPlan, PlannedChange};
    use crate::{
        domain::{
            free::{Evidence, FreeClassification},
            ownership::Ownership,
        },
        error::ErrorKind,
        policy::engine::SafetyDecision,
    };

    fn allowed_decision() -> SafetyDecision {
        SafetyDecision {
            allowed: true,
            classification: FreeClassification::VerifiedAlwaysFree,
            reason: "VM.Standard.A1.Flex is Always Free and fits the allowance".to_owned(),
            evidence: vec![Evidence {
                source: "OCI Shape.billingType".to_owned(),
                detail: "ALWAYS_FREE".to_owned(),
            }],
            warnings: Vec::new(),
            capacity: None,
        }
    }

    fn refused_decision() -> SafetyDecision {
        SafetyDecision {
            allowed: false,
            classification: FreeClassification::Paid,
            reason: "VM.Standard3.Flex is a paid shape".to_owned(),
            evidence: Vec::new(),
            warnings: vec!["this shape is billed hourly".to_owned()],
            capacity: None,
        }
    }

    fn create_instance() -> PlannedChange {
        PlannedChange::new(
            ChangeKind::Create,
            "compute instance",
            "free-arm-1",
            "VM.Standard.A1.Flex, 2 OCPU, 12 GB",
        )
    }

    #[test]
    fn a_clean_plan_can_be_approved() {
        let plan = MutationPlan::new("vm.create", "us-ashburn-1")
            .with_change(create_instance())
            .with_safety(allowed_decision());

        assert!(plan.is_safe());
        let approval: Approval = plan.approve(true).expect("a safe, confirmed plan approves");
        assert_eq!(approval.operation(), "vm.create");
    }

    /// The gate that matters: a refusal from the policy engine becomes a
    /// blocker, and a blocked plan can never produce an approval.
    #[test]
    fn a_policy_refusal_cannot_be_approved() {
        let plan = MutationPlan::new("vm.create", "us-ashburn-1")
            .with_change(create_instance())
            .with_safety(refused_decision());

        assert!(!plan.is_safe());
        assert!(!plan.blockers.is_empty());

        let error = plan
            .approve(true)
            .expect_err("a refused plan must never approve");
        assert_eq!(error.kind(), ErrorKind::PolicyRejected);
        assert!(error.context().expect("context").contains("paid shape"));
    }

    /// Confirming is not enough on its own; nor is safety without confirmation.
    #[test]
    fn an_unconfirmed_plan_is_refused() {
        let plan = MutationPlan::new("vm.delete", "us-ashburn-1").with_change(PlannedChange::new(
            ChangeKind::Delete,
            "compute instance",
            "free-arm-1",
            "terminated",
        ));

        let error = plan.approve(false).expect_err("must require confirmation");
        assert_eq!(error.kind(), ErrorKind::UnsupportedState);
        assert!(
            error
                .context()
                .expect("context")
                .contains("nothing was changed")
        );
        assert!(error.remediation().contains("--yes"));
    }

    /// A step whose billing risk is anything but `none` fails closed even when
    /// no explicit blocker was recorded.
    #[test]
    fn an_unproven_billing_risk_blocks_approval() {
        for risk in [
            BillingRisk::Bounded,
            BillingRisk::Unknown,
            BillingRisk::Charged,
        ] {
            let plan = MutationPlan::new("vm.create", "us-ashburn-1")
                .with_change(create_instance().with_billing_risk(risk));

            assert!(!plan.is_safe(), "{} must not be safe", risk.as_str());
            let error = plan.approve(true).expect_err("must refuse");
            assert_eq!(error.kind(), ErrorKind::BillingUncertain);
            assert!(error.context().expect("context").contains(risk.as_str()));
        }
    }

    #[test]
    fn billing_risk_is_the_worst_across_all_steps() {
        let plan = MutationPlan::new("vm.create", "us-ashburn-1")
            .with_change(create_instance().with_billing_risk(BillingRisk::None))
            .with_change(
                PlannedChange::new(ChangeKind::Create, "block volume", "extra", "100 GB")
                    .with_billing_risk(BillingRisk::Charged),
            );
        assert_eq!(plan.billing_risk(), BillingRisk::Charged);
    }

    #[test]
    fn classification_maps_onto_billing_risk() {
        assert_eq!(
            BillingRisk::from_classification(FreeClassification::VerifiedAlwaysFree),
            BillingRisk::None
        );
        assert_eq!(
            BillingRisk::from_classification(FreeClassification::LimitedFree),
            BillingRisk::Bounded
        );
        assert_eq!(
            BillingRisk::from_classification(FreeClassification::Paid),
            BillingRisk::Charged
        );
        assert_eq!(
            BillingRisk::from_classification(FreeClassification::Unknown),
            BillingRisk::Unknown
        );
        assert!(BillingRisk::None.is_acceptable_in_strict_mode());
        for risk in [
            BillingRisk::Bounded,
            BillingRisk::Unknown,
            BillingRisk::Charged,
        ] {
            assert!(!risk.is_acceptable_in_strict_mode());
        }
    }

    #[test]
    fn reuse_steps_are_shown_but_are_not_mutations() {
        let plan = MutationPlan::new("vm.create", "us-ashburn-1")
            .with_change(
                PlannedChange::new(ChangeKind::Reuse, "VCN", "oci-free-vcn", "unchanged")
                    .with_ownership(Ownership::Created),
            )
            .with_change(create_instance());

        assert_eq!(plan.changes.len(), 2);
        assert_eq!(plan.mutations().len(), 1);
        assert!(!plan.is_destructive());
    }

    #[test]
    fn the_rendered_plan_shows_state_evidence_and_exposure() {
        let plan = MutationPlan::new("vm.net.open", "us-ashburn-1")
            .with_change(
                PlannedChange::new(
                    ChangeKind::Modify,
                    "network security group",
                    "oci-free-web-1",
                    "1 ingress rule",
                )
                .with_before("0 ingress rules")
                .with_ownership(Ownership::Created)
                .with_note("only this instance's NSG is modified"),
            )
            .with_safety(allowed_decision())
            .with_exposure(ExposureDelta {
                added: vec!["tcp 443 from 0.0.0.0/0 via NSG oci-free-web-1".to_owned()],
                removed: Vec::new(),
                unchanged_residual: vec![
                    "tcp 22 from 0.0.0.0/0 via security list Default".to_owned(),
                ],
            });

        let rendered = plan.render_human();
        assert!(rendered.contains("Plan for vm.net.open in us-ashburn-1"));
        assert!(rendered.contains("0 ingress rules -> 1 ingress rule"));
        assert!(rendered.contains("OCI Shape.billingType"));
        assert!(rendered.contains("+ tcp 443 from 0.0.0.0/0"));
        assert!(rendered.contains("granted elsewhere"));
        assert!(rendered.contains("billing risk: none"));
    }

    #[test]
    fn blockers_are_rendered_so_a_refusal_is_never_silent() {
        let plan = MutationPlan::new("vm.create", "us-ashburn-1")
            .with_change(create_instance())
            .with_safety(refused_decision());
        let rendered = plan.render_human();
        assert!(rendered.contains("blocked: "));
        assert!(rendered.contains("paid shape"));
        assert!(rendered.contains("warning: this shape is billed hourly"));
    }

    #[test]
    fn destructive_plans_are_recognised() {
        let plan = MutationPlan::new("vm.delete", "us-ashburn-1").with_change(PlannedChange::new(
            ChangeKind::Delete,
            "boot volume",
            "free-arm-1 (Boot Volume)",
            "deleted",
        ));
        assert!(plan.is_destructive());
    }
}
