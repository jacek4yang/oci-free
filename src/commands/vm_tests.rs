//! Instance summary and resolution tests.

use super::*;
use crate::policy::{engine::PolicyEngine, snapshot::PolicySnapshot};

fn instances() -> Vec<Instance> {
    serde_json::from_str(include_str!("../../tests/fixtures/oci/instances.json"))
        .expect("instances fixture")
}

fn shapes() -> Vec<Shape> {
    serde_json::from_str(include_str!("../../tests/fixtures/oci/shapes.json"))
        .expect("shapes fixture")
}

fn policy() -> PolicyEngine {
    PolicyEngine::new(PolicySnapshot::load().expect("snapshot"))
}

#[test]
fn resolves_by_ocid() {
    let instances = instances();
    let found = resolve(
        "ocid1.instance.oc1.iad.aaaaaaaarunninginstance1",
        &instances,
    )
    .expect("should resolve by OCID");
    assert_eq!(found.display_name.as_deref(), Some("free-arm-1"));
}

#[test]
fn resolves_by_unique_display_name() {
    let instances = instances();
    let found = resolve("free-arm-1", &instances).expect("should resolve by name");
    assert_eq!(found.id, "ocid1.instance.oc1.iad.aaaaaaaarunninginstance1");
}

/// The safety-critical case: never guess. Picking one of several matches could
/// terminate the wrong machine.
#[test]
fn ambiguous_names_are_refused_with_the_candidates() {
    let mut instances = instances();
    instances[1].display_name = Some("free-arm-1".to_owned());

    let error = resolve("free-arm-1", &instances).expect_err("must refuse to guess");
    assert_eq!(error.kind(), crate::error::ErrorKind::Ambiguous);

    let context = error.context().expect("context lists candidates");
    assert!(context.contains("ocid1.instance.oc1.iad.aaaaaaaarunninginstance1"));
    assert!(context.contains("ocid1.instance.oc1.iad.aaaaaaaastoppedinstance2"));
    assert!(error.remediation().contains("OCID"));
}

/// A terminated instance keeps its display name; matching it would be a
/// confusing false positive.
#[test]
fn terminated_instances_are_not_matched_by_name() {
    let instances = instances();
    let error = resolve("old-instance", &instances).expect_err("terminated must not match");
    assert_eq!(error.kind(), crate::error::ErrorKind::NotFound);
}

/// A terminated instance is still addressable by OCID, so `vm info` on one can
/// explain what happened to it.
#[test]
fn terminated_instances_remain_addressable_by_ocid() {
    let instances = instances();
    let found = resolve("ocid1.instance.oc1.iad.aaaaaaaaterminated3", &instances)
        .expect("OCID lookup should still work");
    assert_eq!(found.lifecycle_state, "TERMINATED");
}

#[test]
fn unknown_names_report_not_found() {
    let error = resolve("does-not-exist", &instances()).expect_err("should not resolve");
    assert_eq!(error.kind(), crate::error::ErrorKind::NotFound);
    assert!(error.remediation().contains("vm list"));
}

#[test]
fn summary_carries_the_free_classification() {
    let instances = instances();
    let summary = summarise(&instances[0], &shapes(), &policy());

    assert_eq!(summary.name, "free-arm-1");
    assert_eq!(summary.free_classification, "verified_always_free");
    assert_eq!(summary.ocpus, Some(2.0));
    assert_eq!(summary.memory_gb, Some(12.0));
}

/// Ownership comes from a tag, never from the display name.
#[test]
fn managed_ownership_comes_from_the_tag() {
    let instances = instances();
    let managed = summarise(&instances[0], &shapes(), &policy());
    assert!(
        managed.managed_by_oci_free,
        "fixture instance carries the tag"
    );

    let unmanaged = summarise(&instances[1], &shapes(), &policy());
    assert!(!unmanaged.managed_by_oci_free);

    // A user instance named to look managed must still read as unmanaged.
    let mut impostor = instances[1].clone();
    impostor.display_name = Some("oci-free-managed-instance".to_owned());
    assert!(
        !summarise(&impostor, &shapes(), &policy()).managed_by_oci_free,
        "ownership must not be inferred from a name"
    );
}

/// Without a shape record there is no billing evidence, so the safe reading is
/// Unknown rather than assuming free.
#[test]
fn an_unrecognised_shape_classifies_as_unknown() {
    let mut instance = instances()[0].clone();
    instance.shape = Some("VM.Mystery.Flex".to_owned());

    let summary = summarise(&instance, &shapes(), &policy());
    assert_eq!(summary.free_classification, "unknown");
}

#[test]
fn paid_shapes_are_labelled_paid() {
    let mut instance = instances()[0].clone();
    instance.shape = Some("VM.Standard3.Flex".to_owned());

    let summary = summarise(&instance, &shapes(), &policy());
    assert_eq!(summary.free_classification, "paid");
}

#[test]
fn human_output_lists_instances_and_an_empty_region_reads_clearly() {
    let policy = policy();
    let shapes = shapes();
    let list = VmList {
        region: "us-ashburn-1".to_owned(),
        instances: instances()
            .iter()
            .filter(|i| i.consumes_capacity())
            .map(|i| summarise(i, &shapes, &policy))
            .collect(),
        warnings: Vec::new(),
    };

    let rendered = render_human(&list);
    assert!(rendered.contains("free-arm-1"));
    assert!(rendered.contains("RUNNING"));
    assert!(rendered.contains("[managed by oci-free]"));
    assert!(!rendered.contains("old-instance"), "terminated is excluded");

    let empty = VmList {
        region: "us-ashburn-1".to_owned(),
        instances: Vec::new(),
        warnings: Vec::new(),
    };
    assert!(render_human(&empty).contains("No active instances"));
}
