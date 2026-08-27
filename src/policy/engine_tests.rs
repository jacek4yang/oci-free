//! Policy engine tests.
//!
//! These encode the fail-closed contract from CLAUDE.md. Every case that is not
//! provably Always Free *and* provably within the allowance must refuse.

use super::*;
use crate::{
    domain::capacity::ComputeUsage,
    oci::compute::{MemoryOptions, OcpuOptions, Shape, ShapeBillingType},
};

fn engine() -> PolicyEngine {
    PolicyEngine::new(PolicySnapshot::load().expect("snapshot"))
}

fn shape(name: &str, billing: ShapeBillingType) -> Shape {
    Shape {
        shape: name.to_owned(),
        billing_type: billing,
        ocpus: Some(1.0),
        memory_in_g_bs: Some(6.0),
        processor_description: None,
        is_flexible: Some(true),
        ocpu_options: Some(OcpuOptions {
            min: Some(1.0),
            max: Some(80.0),
        }),
        memory_options: Some(MemoryOptions {
            min_in_g_bs: Some(1.0),
            max_in_g_bs: Some(512.0),
            min_per_ocpu_in_gbs: None,
            max_per_ocpu_in_gbs: None,
        }),
    }
}

fn arm(billing: ShapeBillingType) -> Shape {
    shape("VM.Standard.A1.Flex", billing)
}

fn draw(ocpus: f64, memory_gb: f64) -> InstanceDraw {
    InstanceDraw { ocpus, memory_gb }
}

fn used(ocpus: f64, memory_gb: f64, instances: u32) -> ComputeUsage {
    ComputeUsage {
        ocpus,
        memory_gb,
        instances,
        undetermined_instances: Vec::new(),
    }
}

#[test]
fn always_free_within_allowance_is_permitted() {
    let decision = engine().evaluate_launch(
        &arm(ShapeBillingType::AlwaysFree),
        draw(2.0, 12.0),
        &ComputeUsage::default(),
    );

    assert!(decision.allowed);
    assert!(decision.permits_mutation());
    assert_eq!(
        decision.classification,
        FreeClassification::VerifiedAlwaysFree
    );
    assert!(decision.capacity.expect("capacity").fits);
}

/// The three non-free classifications must all block. This is the core
/// invariant from CLAUDE.md.
#[test]
fn limited_free_paid_and_unknown_all_fail_closed() {
    let cases = [
        (
            ShapeBillingType::LimitedFree,
            FreeClassification::LimitedFree,
        ),
        (ShapeBillingType::Paid, FreeClassification::Paid),
        (ShapeBillingType::Unknown, FreeClassification::Unknown),
    ];

    for (billing, expected) in cases {
        let decision =
            engine().evaluate_launch(&arm(billing), draw(1.0, 6.0), &ComputeUsage::default());

        assert!(
            !decision.allowed,
            "{} must not be allowed",
            billing.as_str()
        );
        assert!(
            !decision.permits_mutation(),
            "{} must not permit a mutation",
            billing.as_str()
        );
        assert_eq!(decision.classification, expected);
        assert!(!decision.reason.is_empty());
    }
}

/// LimitedFree is explicitly not "free enough". It is a distinct category and
/// must never be silently upgraded.
#[test]
fn limited_free_is_never_treated_as_always_free() {
    let decision = engine().evaluate_launch(
        &arm(ShapeBillingType::LimitedFree),
        draw(1.0, 1.0),
        &ComputeUsage::default(),
    );
    assert_ne!(
        decision.classification,
        FreeClassification::VerifiedAlwaysFree
    );
    assert!(decision.reason.contains("limited allowance"));
}

/// A shape OCI calls Always Free but that this build has no allowance for
/// cannot be proven to stay free, so it is downgraded to Unknown.
#[test]
fn always_free_without_a_known_allowance_downgrades_to_unknown() {
    let unknown_shape = shape("VM.Standard.Future.Flex", ShapeBillingType::AlwaysFree);
    let decision =
        engine().evaluate_launch(&unknown_shape, draw(1.0, 1.0), &ComputeUsage::default());

    assert!(!decision.allowed);
    assert_eq!(decision.classification, FreeClassification::Unknown);
    assert!(decision.reason.contains("no verified allowance"));
}

/// Exceeding a known allowance is a *measured* overrun, so it classifies as
/// Paid: proceeding really would be billed.
#[test]
fn exceeding_a_known_allowance_classifies_as_paid() {
    let decision = engine().evaluate_launch(
        &arm(ShapeBillingType::AlwaysFree),
        draw(3.0, 18.0),
        &used(2.0, 12.0, 1),
    );

    assert!(!decision.allowed);
    assert_eq!(decision.classification, FreeClassification::Paid);
    assert!(decision.reason.contains("would be billed"));
    assert!(!decision.capacity.expect("capacity").fits);
}

/// Unmeasurable usage is a different failure from a measured overrun: we do not
/// know that it would be billed, only that we cannot prove it would not be.
#[test]
fn unmeasurable_usage_classifies_as_unknown_not_paid() {
    let mut usage = used(1.0, 6.0, 1);
    usage.add_undetermined("instance-without-shape-config");

    let decision =
        engine().evaluate_launch(&arm(ShapeBillingType::AlwaysFree), draw(1.0, 6.0), &usage);

    assert!(!decision.allowed);
    assert_eq!(
        decision.classification,
        FreeClassification::Unknown,
        "unmeasurable usage is unproven, not proven-paid"
    );
    assert!(decision.reason.contains("could not be determined"));
}

/// Every decision must carry the facts behind it, so `policy explain` can show
/// the user why rather than just what.
#[test]
fn decisions_retain_their_evidence() {
    let decision = engine().evaluate_launch(
        &arm(ShapeBillingType::AlwaysFree),
        draw(1.0, 6.0),
        &used(1.0, 6.0, 1),
    );

    let sources: Vec<&str> = decision
        .evidence
        .iter()
        .map(|e| e.source.as_str())
        .collect();

    assert!(
        sources.iter().any(|s| s.contains("Shape.billingType")),
        "must cite OCI's own billing classification"
    );
    assert!(
        sources.iter().any(|s| s.contains("policy snapshot")),
        "must cite the snapshot that supplied the allowance"
    );
    assert!(
        sources.iter().any(|s| s.contains("live tenancy usage")),
        "must cite the usage it measured"
    );

    // The snapshot citation has to be dated, or a reviewer cannot judge
    // staleness.
    let snapshot_evidence = decision
        .evidence
        .iter()
        .find(|e| e.source.contains("policy snapshot"))
        .expect("snapshot evidence");
    assert!(snapshot_evidence.source.contains("verified"));
}

#[test]
fn an_unrecognised_billing_type_warns_and_blocks() {
    let assessment = engine().classify_shape(&arm(ShapeBillingType::Unknown));
    assert_eq!(assessment.classification, FreeClassification::Unknown);
    assert!(!assessment.is_allowed_by_default());
    assert!(
        assessment
            .warnings
            .iter()
            .any(|w| w.contains("unproven rather than free"))
    );
}

/// An exact fill of the allowance is permitted; one step past it is not.
#[test]
fn the_allowance_boundary_is_exact() {
    let engine = engine();

    let exact = engine.evaluate_launch(
        &arm(ShapeBillingType::AlwaysFree),
        draw(2.0, 12.0),
        &used(2.0, 12.0, 1),
    );
    assert!(exact.allowed, "filling the allowance exactly is free");

    let over = engine.evaluate_launch(
        &arm(ShapeBillingType::AlwaysFree),
        draw(2.1, 12.0),
        &used(2.0, 12.0, 1),
    );
    assert!(!over.allowed, "one step past the allowance is not");
}

/// The micro allowance is bounded by instance count, not cores.
#[test]
fn instance_count_allowances_are_enforced() {
    let micro = shape("VM.Standard.E2.1.Micro", ShapeBillingType::AlwaysFree);
    let engine = engine();

    let second = engine.evaluate_launch(&micro, draw(1.0, 1.0), &used(1.0, 1.0, 1));
    assert!(second.allowed, "a second micro instance is free");

    let third = engine.evaluate_launch(&micro, draw(1.0, 1.0), &used(2.0, 2.0, 2));
    assert!(!third.allowed, "a third micro instance is not");
}

/// `permits_mutation` is the single gate write paths consult, so it must never
/// be true for anything other than a verified, in-allowance decision.
#[test]
fn permits_mutation_is_true_only_for_verified_always_free() {
    let engine = engine();

    let permitted = engine.evaluate_launch(
        &arm(ShapeBillingType::AlwaysFree),
        draw(1.0, 6.0),
        &ComputeUsage::default(),
    );
    assert!(permitted.permits_mutation());

    for billing in [
        ShapeBillingType::LimitedFree,
        ShapeBillingType::Paid,
        ShapeBillingType::Unknown,
    ] {
        let decision =
            engine.evaluate_launch(&arm(billing), draw(1.0, 6.0), &ComputeUsage::default());
        assert!(
            !decision.permits_mutation(),
            "{} must never permit a mutation",
            billing.as_str()
        );
    }

    // Even a hand-built decision claiming `allowed` must be gated on the
    // classification, so a future bug that flips one field cannot open the gate.
    let forged = SafetyDecision {
        allowed: true,
        classification: FreeClassification::Unknown,
        reason: "forged".to_owned(),
        evidence: Vec::new(),
        warnings: Vec::new(),
        capacity: None,
    };
    assert!(
        !forged.permits_mutation(),
        "allowed alone must not open the gate"
    );
}
