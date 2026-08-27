//! `status` tests.
//!
//! The property under test is graceful degradation: one refused permission
//! must reduce the report, never blank it, and an unreadable figure must never
//! be presented as a reassuring zero.

use serde_json::json;

use super::*;
use crate::testing::mock_oci::{MockBuilder, MockOci, Reply, TENANCY};

fn tenancy_json() -> serde_json::Value {
    json!({
        "id": TENANCY,
        "name": "example-tenancy",
        "homeRegionKey": "IAD"
    })
}

fn subscriptions_json() -> serde_json::Value {
    json!([
        { "regionKey": "IAD", "regionName": "us-ashburn-1", "isHomeRegion": true, "status": "READY" }
    ])
}

fn shapes_json() -> serde_json::Value {
    json!([
        {
            "shape": "VM.Standard.A1.Flex",
            "billingType": "ALWAYS_FREE",
            "isFlexible": true,
            "ocpuOptions": { "min": 1.0, "max": 80.0 },
            "memoryOptions": { "minInGBs": 1.0, "maxInGBs": 512.0 }
        },
        { "shape": "VM.Standard.E2.1.Micro", "billingType": "ALWAYS_FREE", "ocpus": 1.0, "memoryInGBs": 1.0 }
    ])
}

fn instances_json() -> serde_json::Value {
    json!([
        {
            "id": "ocid1.instance.oc1.iad.running",
            "compartmentId": TENANCY,
            "displayName": "free-arm-1",
            "lifecycleState": "RUNNING",
            "shape": "VM.Standard.A1.Flex",
            "shapeConfig": { "ocpus": 2.0, "memoryInGBs": 12.0 },
            "freeformTags": { "oci-free:managed": "created", "oci-free:role": "instance" }
        },
        {
            "id": "ocid1.instance.oc1.iad.stopped",
            "compartmentId": TENANCY,
            "displayName": "theirs",
            "lifecycleState": "STOPPED",
            "shape": "VM.Standard.E2.1.Micro",
            "freeformTags": {}
        },
        {
            "id": "ocid1.instance.oc1.iad.gone",
            "compartmentId": TENANCY,
            "displayName": "old",
            "lifecycleState": "TERMINATED",
            "shape": "VM.Standard.A1.Flex"
        }
    ])
}

/// A tenancy where every read succeeds and nothing is exposed.
fn healthy() -> MockBuilder {
    MockOci::builder()
        // Registered before the tenancy route: both targets start with
        // `/tenancies/`, and routes match in registration order.
        .get("regionSubscriptions", &subscriptions_json())
        .get("/tenancies/", &tenancy_json())
        .get("/instances", &instances_json())
        .get("/shapes", &shapes_json())
        .get("/vnicAttachments", &json!([]))
        .reply(
            "POST",
            "/usage",
            Reply::json(&json!({
                "groupBy": ["service"],
                "items": [{
                    "service": "COMPUTE",
                    "computedAmount": 0.0,
                    "computedQuantity": 1464.0,
                    "currency": "USD",
                    "unit": "OCPU_HOURS"
                }]
            })),
        )
}

fn context(mock: &MockOci) -> CommandContext {
    CommandContext::for_tests(mock.client(), "us-ashburn-1")
}

#[tokio::test]
async fn a_healthy_tenancy_reports_every_section() {
    let mock = healthy().start().await;
    let status = run(&context(&mock)).await.expect("status succeeds");

    assert!(status.credentials_valid);
    assert_eq!(status.tenancy_name.as_deref(), Some("example-tenancy"));
    assert_eq!(status.home_region.as_deref(), Some("us-ashburn-1"));

    let instances = status.instances.as_ref().expect("an instance summary");
    assert_eq!(instances.total, 2, "a terminated instance is not counted");
    assert_eq!(instances.running, 1);
    assert_eq!(instances.stopped, 1);
    assert_eq!(instances.managed_by_oci_free, 1);

    let arm = status
        .capacity
        .iter()
        .find(|line| line.allowance_id == "ampere-a1-flex")
        .expect("the ARM allowance");
    assert_eq!(arm.remaining_ocpus, Some(2.0));
    assert_eq!(arm.remaining_memory_gb, Some(12.0));

    let cost = status.cost.as_ref().expect("a cost report");
    assert_eq!(cost.total, Some(0.0));
    assert!(!cost.has_charges);
    assert!(status.permission_warnings.is_empty());
    assert!(!status.needs_attention());

    let rendered = render_human(&status);
    assert!(rendered.contains("example-tenancy"));
    assert!(rendered.contains("no charges this billing period"));
    assert!(!rendered.contains("\u{1b}"));
}

/// The defining property: losing the cost grant must not blank the report.
#[tokio::test]
async fn a_missing_cost_permission_reduces_the_report_rather_than_failing_it() {
    let mock = healthy()
        .override_reply(
            "POST",
            "/usage",
            Reply::new(
                403,
                r#"{"code":"NotAuthorized","message":"no usage-report"}"#,
            )
            .header("opc-request-id", "req-1"),
        )
        .start()
        .await;

    let status = run(&context(&mock)).await.expect("status still succeeds");

    assert!(status.credentials_valid);
    assert!(status.instances.is_some(), "instances are still reported");
    assert!(!status.capacity.is_empty(), "capacity is still reported");

    let cost = status.cost.as_ref().expect("a cost report");
    assert!(!cost.available);
    assert!(cost.total.is_none());
    assert!(
        status
            .warnings
            .iter()
            .any(|warning| warning.contains("usage-report")),
        "the report must name the IAM policy that would fix it: {:?}",
        status.warnings
    );

    let rendered = render_human(&status);
    assert!(rendered.contains("unavailable"));
    assert!(
        !rendered.contains("0.00"),
        "an unreadable cost must never be shown as zero"
    );
}

/// Losing the compute grant costs the instance and capacity sections, and says
/// so, but the identity section survives.
#[tokio::test]
async fn a_missing_compute_permission_is_named_not_silently_dropped() {
    let mock = healthy()
        .override_reply(
            "GET",
            "/instances",
            Reply::new(
                403,
                r#"{"code":"NotAuthorized","message":"no instance inspect"}"#,
            )
            .header("opc-request-id", "req-2"),
        )
        .start()
        .await;

    let status = run(&context(&mock)).await.expect("status still succeeds");

    assert!(status.credentials_valid);
    assert!(status.instances.is_none());
    assert!(status.capacity.is_empty());
    assert!(
        status
            .permission_warnings
            .iter()
            .any(|warning| warning.contains("instances could not be listed")),
        "{:?}",
        status.permission_warnings
    );
    assert!(render_human(&status).contains("permission:"));
}

/// Capacity that cannot be measured must be reported as unknown, never as
/// available headroom.
#[tokio::test]
async fn unmeasurable_capacity_is_unknown_not_free() {
    let mock = healthy()
        .override_reply(
            "GET",
            "/instances",
            Reply::json(&json!([{
                "id": "ocid1.instance.oc1.iad.mystery",
                "compartmentId": TENANCY,
                "displayName": "mystery",
                "lifecycleState": "RUNNING",
                "shape": "VM.Standard.A1.Flex"
            }])),
        )
        .start()
        .await;

    let status = run(&context(&mock)).await.expect("status succeeds");
    let arm = status
        .capacity
        .iter()
        .find(|line| line.allowance_id == "ampere-a1-flex")
        .expect("the ARM allowance");

    assert!(arm.remaining_ocpus.is_none());
    assert!(arm.remaining_memory_gb.is_none());
    assert!(!arm.blockers.is_empty());
    assert!(status.needs_attention());
    assert!(render_human(&status).contains("cannot be determined"));
}

#[tokio::test]
async fn a_region_that_is_not_the_home_region_is_warned_about() {
    let mock = healthy()
        .override_reply(
            "GET",
            "regionSubscriptions",
            Reply::json(&json!([
                { "regionKey": "FRA", "regionName": "eu-frankfurt-1", "isHomeRegion": true },
                { "regionKey": "IAD", "regionName": "us-ashburn-1", "isHomeRegion": false }
            ])),
        )
        .start()
        .await;

    let status = run(&context(&mock)).await.expect("status succeeds");
    assert_eq!(status.home_region.as_deref(), Some("eu-frankfurt-1"));
    assert!(
        status
            .warnings
            .iter()
            .any(|warning| warning.contains("Always Free resources live in the home region"))
    );
}

#[tokio::test]
async fn a_charge_is_surfaced_as_needing_attention() {
    let mock = healthy()
        .override_reply(
            "POST",
            "/usage",
            Reply::json(&json!({
                "groupBy": ["service"],
                "items": [{ "service": "BLOCK_STORAGE", "computedAmount": 2.55, "currency": "USD" }]
            })),
        )
        .start()
        .await;

    let status = run(&context(&mock)).await.expect("status succeeds");
    assert!(status.needs_attention());
    let cost = status.cost.as_ref().expect("cost");
    assert!(cost.has_charges);
    assert!(render_human(&status).contains("2.55 USD"));
}

/// Rejected credentials must be reported plainly rather than as a crash.
#[tokio::test]
async fn rejected_credentials_are_reported_not_fatal() {
    let mock = MockOci::builder()
        .fallback(vec![
            Reply::new(
                401,
                r#"{"code":"NotAuthenticated","message":"bad signature"}"#,
            )
            .header("opc-request-id", "req-3"),
        ])
        .start()
        .await;

    let status = run(&context(&mock)).await.expect("status still succeeds");
    assert!(!status.credentials_valid);
    assert!(!status.permission_warnings.is_empty());
    assert!(render_human(&status).contains("not accepted"));
}

/// `status` is read-only.
#[tokio::test]
async fn status_never_writes() {
    let mock = healthy().start().await;
    let _ = run(&context(&mock)).await;
    for write in mock.writes() {
        assert!(
            write.target().contains("/usage"),
            "the only POST status makes is the read-only usage query, found {}",
            write.target()
        );
    }
}
