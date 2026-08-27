//! Capacity-reporting tests.
//!
//! These use fixture instances and shapes rather than a live client, so the
//! usage arithmetic that gates every launch is verified without a network.

use super::*;
use crate::policy::snapshot::PolicySnapshot;

fn snapshot() -> PolicySnapshot {
    PolicySnapshot::load().expect("snapshot")
}

fn instances() -> Vec<Instance> {
    serde_json::from_str(include_str!("../../tests/fixtures/oci/instances.json"))
        .expect("instances fixture")
}

fn shapes() -> Vec<Shape> {
    serde_json::from_str(include_str!("../../tests/fixtures/oci/shapes.json"))
        .expect("shapes fixture")
}

#[test]
fn usage_is_attributed_to_the_right_allowance() {
    let usage = usage_by_allowance(&snapshot(), &instances(), &shapes());

    // The running ARM instance is 2 OCPU / 12 GB. The terminated one, also ARM,
    // must not be counted.
    let arm = usage.get("ampere-a1-flex").expect("arm usage");
    assert_eq!(arm.ocpus, 2.0);
    assert_eq!(arm.memory_gb, 12.0);
    assert_eq!(arm.instances, 1);

    // The stopped micro instance still holds its allocation.
    let micro = usage.get("amd-micro").expect("micro usage");
    assert_eq!(micro.instances, 1);
    assert_eq!(micro.ocpus, 1.0);
}

/// Terminated instances release their allowance; counting them would
/// under-report available capacity and block legitimate launches.
#[test]
fn terminated_instances_are_excluded() {
    let usage = usage_by_allowance(&snapshot(), &instances(), &shapes());
    let arm = usage.get("ampere-a1-flex").expect("arm usage");
    assert_eq!(
        arm.ocpus, 2.0,
        "the terminated 4-OCPU instance must not be counted"
    );
}

/// Paid shapes consume no free allowance, so they must not appear.
#[test]
fn paid_shapes_do_not_consume_a_free_allowance() {
    let mut instances = instances();
    instances[0].shape = Some("VM.Standard3.Flex".to_owned());

    let usage = usage_by_allowance(&snapshot(), &instances, &shapes());
    assert!(
        usage.get("ampere-a1-flex").is_none_or(|u| u.instances == 0),
        "a paid shape must not draw on a free allowance"
    );
}

/// The safety-critical case: an instance with no shape configuration and no
/// matching shape record cannot be measured, and must be recorded as
/// undetermined so the capacity check fails closed.
#[test]
fn unmeasurable_instances_are_recorded_not_skipped() {
    let mut instances = instances();
    instances[0].shape_config = None;
    // A shape list that does not describe this shape, so no fallback exists.
    let shapes: Vec<Shape> = Vec::new();

    let usage = usage_by_allowance(&snapshot(), &instances, &shapes);
    let arm = usage.get("ampere-a1-flex").expect("arm usage");

    assert!(
        !arm.is_certain(),
        "an unmeasurable instance must make usage uncertain, not vanish"
    );
    assert!(
        arm.undetermined_instances
            .contains(&"free-arm-1".to_owned())
    );
    assert_eq!(arm.instances, 1, "it still counts as an instance");
}

/// A fixed-size shape often reports no per-instance config, so the shape's own
/// published size is the correct fallback.
#[test]
fn fixed_shapes_fall_back_to_the_published_shape_size() {
    let mut instances = instances();
    instances[1].shape_config = None;

    let usage = usage_by_allowance(&snapshot(), &instances, &shapes());
    let micro = usage.get("amd-micro").expect("micro usage");

    assert!(
        micro.is_certain(),
        "the shape record supplies the size, so this is measurable"
    );
    assert_eq!(micro.ocpus, 1.0);
    assert_eq!(micro.memory_gb, 1.0);
}

#[test]
fn an_empty_tenancy_reports_no_usage() {
    let usage = usage_by_allowance(&snapshot(), &[], &shapes());
    assert!(usage.is_empty());
}

#[test]
fn human_output_reports_remaining_capacity() {
    let snapshot = snapshot();
    let usage = usage_by_allowance(&snapshot, &instances(), &shapes());
    let allowance = snapshot
        .allowance_for("VM.Standard.A1.Flex")
        .expect("arm allowance");
    let capacity =
        crate::domain::capacity::remaining(allowance, usage.get("ampere-a1-flex").expect("usage"));

    let report = FreeReport {
        region: "us-ashburn-1".to_owned(),
        allowances: vec![AllowanceReport {
            allowance_id: allowance.id.clone(),
            description: allowance.description.clone(),
            shapes: allowance.shapes.clone(),
            billing_types: BTreeMap::new(),
            capacity,
            blockers: Vec::new(),
        }],
        policy_snapshot: snapshot.citation(),
        warnings: Vec::new(),
    };

    let rendered = render_human(&report);
    assert!(rendered.contains("2.00 of 4.00 OCPU"));
    assert!(rendered.contains("remaining  2.00 OCPU, 12.00 GB"));
    assert!(rendered.contains("policy snapshot"));
}

/// When usage cannot be measured the report must say so rather than printing a
/// headroom figure the user might act on.
#[test]
fn uncertain_usage_is_reported_as_undeterminable() {
    let snapshot = snapshot();
    let allowance = snapshot
        .allowance_for("VM.Standard.A1.Flex")
        .expect("arm allowance");
    let mut used = ComputeUsage::default();
    used.add_undetermined("mystery");

    let report = FreeReport {
        region: "us-ashburn-1".to_owned(),
        allowances: vec![AllowanceReport {
            allowance_id: allowance.id.clone(),
            description: allowance.description.clone(),
            shapes: allowance.shapes.clone(),
            billing_types: BTreeMap::new(),
            capacity: crate::domain::capacity::remaining(allowance, &used),
            blockers: vec!["usage is not fully measurable: mystery".to_owned()],
        }],
        policy_snapshot: snapshot.citation(),
        warnings: Vec::new(),
    };

    let rendered = render_human(&report);
    assert!(rendered.contains("remaining  cannot be determined"));
    assert!(rendered.contains("blocked"));
}
