//! `policy explain` tests.
//!
//! The command's whole purpose is that a decision comes with its evidence, so
//! these check the evidence chain, not just the verdict.

use serde_json::json;

use super::*;
use crate::testing::mock_oci::{MockOci, TENANCY};

fn shapes_json() -> serde_json::Value {
    json!([
        {
            "shape": "VM.Standard.A1.Flex",
            "billingType": "ALWAYS_FREE",
            "isFlexible": true,
            "ocpuOptions": { "min": 1.0, "max": 80.0 },
            "memoryOptions": {
                "minInGBs": 1.0,
                "maxInGBs": 512.0,
                "minPerOcpuInGBs": 1.0,
                "maxPerOcpuInGBs": 64.0
            }
        },
        {
            "shape": "VM.Standard3.Flex",
            "billingType": "PAID",
            "isFlexible": true,
            "ocpuOptions": { "min": 1.0, "max": 32.0 },
            "memoryOptions": { "minInGBs": 1.0, "maxInGBs": 512.0 }
        },
        { "shape": "VM.Future.X", "billingType": "SOME_NEW_CATEGORY" }
    ])
}

fn instance_json(ocpus: f64, memory: f64) -> serde_json::Value {
    json!({
        "id": "ocid1.instance.oc1.iad.existing",
        "compartmentId": TENANCY,
        "displayName": "existing",
        "lifecycleState": "RUNNING",
        "shape": "VM.Standard.A1.Flex",
        "shapeConfig": { "ocpus": ocpus, "memoryInGBs": memory }
    })
}

async fn mock(instances: serde_json::Value) -> MockOci {
    MockOci::builder()
        .get("/shapes", &shapes_json())
        .get("/instances", &instances)
        .start()
        .await
}

fn context(mock: &MockOci) -> CommandContext {
    CommandContext::for_tests(mock.client(), "us-ashburn-1")
}

#[tokio::test]
async fn an_always_free_shape_with_headroom_is_allowed_and_shows_its_evidence() {
    let mock = mock(json!([])).await;
    let explanation = explain(&context(&mock), "VM.Standard.A1.Flex", Some((2.0, 12.0)))
        .await
        .expect("explain succeeds");

    assert!(explanation.allowed);
    assert_eq!(
        explanation.classification,
        FreeClassification::VerifiedAlwaysFree
    );
    assert_eq!(
        explanation.live_billing_type.as_deref(),
        Some("ALWAYS_FREE")
    );
    assert_eq!(
        explanation.allowance.as_ref().expect("allowance").id,
        "ampere-a1-flex"
    );
    assert!(explanation.policy_snapshot.contains("verified"));

    let capacity = explanation.capacity.as_ref().expect("capacity");
    assert!(capacity.fits);
    assert_eq!(explanation.projected.expect("projection").ocpus, 2.0);

    let rendered = render_human(&explanation);
    assert!(rendered.contains("live OCI Shape.billingType: ALWAYS_FREE"));
    assert!(rendered.contains("policy snapshot allowance `ampere-a1-flex`"));
    assert!(rendered.contains("would fit"));
    assert!(rendered.contains("allowed in strict mode"));
}

/// The evidence must show *why* a launch that would exceed the allowance is
/// refused, not merely that it is.
#[tokio::test]
async fn a_launch_beyond_the_allowance_is_blocked_with_the_arithmetic_shown() {
    let mock = mock(json!([instance_json(3.0, 18.0)])).await;
    let explanation = explain(&context(&mock), "VM.Standard.A1.Flex", Some((2.0, 12.0)))
        .await
        .expect("explain succeeds");

    assert!(!explanation.allowed);
    let capacity = explanation.capacity.as_ref().expect("capacity");
    assert!(!capacity.fits);
    assert_eq!(capacity.used.ocpus, 3.0);
    assert_eq!(capacity.remaining_ocpus, 1.0);

    let rendered = render_human(&explanation);
    assert!(rendered.contains("3 of 4 OCPU"));
    assert!(rendered.contains("would not fit"));
    assert!(rendered.contains("blocked in strict mode"));
}

#[tokio::test]
async fn a_paid_shape_is_blocked_and_says_so_plainly() {
    let mock = mock(json!([])).await;
    let explanation = explain(&context(&mock), "VM.Standard3.Flex", None)
        .await
        .expect("explain succeeds");

    assert!(!explanation.allowed);
    assert_eq!(explanation.classification, FreeClassification::Paid);
    assert_eq!(explanation.live_billing_type.as_deref(), Some("PAID"));
    assert!(explanation.allowance.is_none());
    assert!(render_human(&explanation).contains("no verified allowance"));
}

/// The fail-closed case: a billing category this build has never seen must be
/// explained as unproven, never as free.
#[tokio::test]
async fn an_unrecognised_billing_type_is_explained_as_unknown() {
    let mock = mock(json!([])).await;
    let explanation = explain(&context(&mock), "VM.Future.X", None)
        .await
        .expect("explain succeeds");

    assert!(!explanation.allowed);
    assert_eq!(explanation.classification, FreeClassification::Unknown);
    assert_eq!(explanation.live_billing_type.as_deref(), Some("UNKNOWN"));
    assert!(explanation.reason.contains("could not be proven"));
}

/// Usage that cannot be measured must make the answer uncertain rather than
/// optimistic.
#[tokio::test]
async fn unmeasurable_usage_makes_the_decision_uncertain() {
    let mock = mock(json!([{
        "id": "ocid1.instance.oc1.iad.mystery",
        "compartmentId": TENANCY,
        "displayName": "mystery",
        "lifecycleState": "RUNNING",
        "shape": "VM.Standard.A1.Flex"
    }]))
    .await;

    let explanation = explain(&context(&mock), "VM.Standard.A1.Flex", Some((1.0, 6.0)))
        .await
        .expect("explain succeeds");

    assert!(!explanation.allowed);
    assert_eq!(explanation.classification, FreeClassification::Unknown);
    let capacity = explanation.capacity.as_ref().expect("capacity");
    assert!(!capacity.is_certain());
    assert!(render_human(&explanation).contains("cannot be determined"));
}

#[tokio::test]
async fn an_unknown_resource_is_refused_with_near_misses_named() {
    let mock = mock(json!([])).await;
    let explanation = explain(&context(&mock), "A1", None)
        .await
        .expect("explain succeeds");

    assert!(!explanation.allowed);
    assert_eq!(explanation.resolved_as, "not resolved");
    assert!(
        explanation
            .warnings
            .iter()
            .any(|warning| warning.contains("VM.Standard.A1.Flex")),
        "a near miss should be suggested: {:?}",
        explanation.warnings
    );
}

#[tokio::test]
async fn shape_names_are_matched_case_insensitively() {
    let mock = mock(json!([])).await;
    let explanation = explain(&context(&mock), "vm.standard.a1.flex", None)
        .await
        .expect("explain succeeds");
    assert!(explanation.allowed);
}

/// Explaining reads only; it must never touch a write endpoint.
#[tokio::test]
async fn explaining_never_writes() {
    let mock = mock(json!([])).await;
    let _ = explain(&context(&mock), "VM.Standard.A1.Flex", None).await;
    assert!(mock.writes().is_empty());
}

/// The JSON form must preserve the structured evidence, not only the prose.
#[tokio::test]
async fn json_preserves_the_structured_evidence() {
    let mock = mock(json!([instance_json(1.0, 6.0)])).await;
    let explanation = explain(&context(&mock), "VM.Standard.A1.Flex", Some((1.0, 6.0)))
        .await
        .expect("explain succeeds");

    let value = serde_json::to_value(&explanation).expect("serialize");
    assert_eq!(value["live_billing_type"], "ALWAYS_FREE");
    assert_eq!(value["allowance"]["id"], "ampere-a1-flex");
    assert_eq!(value["capacity"]["used"]["ocpus"], 1.0);
    assert_eq!(value["projected"]["ocpus"], 1.0);
    assert!(value["evidence"].is_array());
    assert!(!value["evidence"].as_array().expect("array").is_empty());
    assert_eq!(value["classification"], "VerifiedAlwaysFree");
}

#[test]
fn half_a_size_is_refused_rather_than_guessed() {
    let error = parse_projection(Some(2.0), None).expect_err("must refuse");
    assert!(error.message().contains("together"));
    assert!(
        parse_projection(None, None)
            .expect("none is fine")
            .is_none()
    );
    assert_eq!(
        parse_projection(Some(2.0), Some(12.0)).expect("both"),
        Some((2.0, 12.0))
    );
}
