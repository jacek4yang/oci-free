//! `vm delete` tests.
//!
//! The properties that protect a user's resources: only what oci-free created
//! is deleted, a shared resource is never removed with one instance, and the
//! boot volume's fate is always an explicit choice.

use serde_json::json;

use super::*;
use crate::testing::mock_oci::{MockBuilder, MockOci, Reply, TENANCY};

const INSTANCE_ID: &str = "ocid1.instance.oc1.iad.anuwcljtexampleinstance1";
const VNIC_ID: &str = "ocid1.vnic.oc1.iad.v";
const SUBNET_ID: &str = "ocid1.subnet.oc1.iad.shared";
const MANAGED_NSG: &str = "ocid1.networksecuritygroup.oc1.iad.managed";
const THEIR_NSG: &str = "ocid1.networksecuritygroup.oc1.iad.theirs";
const BOOT_VOLUME_ID: &str = "ocid1.bootvolume.oc1.iad.b";

fn instance_json(state: &str) -> serde_json::Value {
    json!({
        "id": INSTANCE_ID,
        "compartmentId": TENANCY,
        "displayName": "free-arm-1",
        "lifecycleState": state,
        "availabilityDomain": "Uocm:US-ASHBURN-AD-1",
        "shape": "VM.Standard.A1.Flex",
        "freeformTags": { "oci-free:managed": "created", "oci-free:role": "instance" }
    })
}

fn nsg_json(id: &str, tags: serde_json::Value) -> serde_json::Value {
    json!({
        "id": id,
        "vcnId": "ocid1.vcn.oc1.iad.v",
        "displayName": if id == MANAGED_NSG { "oci-free-free-arm-1" } else { "their-nsg" },
        "lifecycleState": "AVAILABLE",
        "freeformTags": tags
    })
}

fn scenario(nsg_ids: &[&str]) -> MockBuilder {
    MockOci::builder()
        .get(
            "/vnicAttachments",
            &json!([{
                "id": "ocid1.vnicattachment.oc1.iad.a",
                "instanceId": INSTANCE_ID,
                "vnicId": VNIC_ID,
                "lifecycleState": "ATTACHED"
            }]),
        )
        .get(
            "/bootVolumeAttachments",
            &json!([{
                "id": "ocid1.bootvolumeattachment.oc1.iad.a",
                "instanceId": INSTANCE_ID,
                "bootVolumeId": BOOT_VOLUME_ID,
                "availabilityDomain": "Uocm:US-ASHBURN-AD-1",
                "lifecycleState": "ATTACHED"
            }]),
        )
        .get(
            &format!("/bootVolumes/{BOOT_VOLUME_ID}"),
            &json!({
                "id": BOOT_VOLUME_ID,
                "displayName": "free-arm-1 (Boot Volume)",
                "sizeInGBs": 50,
                "lifecycleState": "AVAILABLE",
                "freeformTags": { "oci-free:managed": "created", "oci-free:role": "boot-volume" }
            }),
        )
        .get(
            &format!("/instances/{INSTANCE_ID}"),
            &instance_json("TERMINATING"),
        )
        .get("/instances?", &json!([instance_json("RUNNING")]))
        .get(
            &format!("/vnics/{VNIC_ID}"),
            &json!({
                "id": VNIC_ID,
                "subnetId": SUBNET_ID,
                "privateIp": "10.0.0.42",
                "publicIp": "203.0.113.17",
                "isPrimary": true,
                "nsgIds": nsg_ids,
                "lifecycleState": "AVAILABLE"
            }),
        )
        .get(
            &format!("/subnets/{SUBNET_ID}"),
            &json!({
                "id": SUBNET_ID,
                "vcnId": "ocid1.vcn.oc1.iad.v",
                "displayName": "oci-free-subnet",
                "cidrBlock": "10.0.0.0/24",
                "securityListIds": [],
                "lifecycleState": "AVAILABLE",
                "freeformTags": { "oci-free:managed": "created", "oci-free:role": "subnet" }
            }),
        )
        .get(
            &format!("/networkSecurityGroups/{MANAGED_NSG}/securityRules"),
            &json!([]),
        )
        .get(
            &format!("/networkSecurityGroups/{MANAGED_NSG}"),
            &nsg_json(
                MANAGED_NSG,
                json!({
                    "oci-free:managed": "created",
                    "oci-free:role": "instance-nsg",
                    "oci-free:instance": INSTANCE_ID
                }),
            ),
        )
        .get(
            &format!("/networkSecurityGroups/{THEIR_NSG}/securityRules"),
            &json!([]),
        )
        .get(
            &format!("/networkSecurityGroups/{THEIR_NSG}"),
            &nsg_json(THEIR_NSG, json!({})),
        )
        .reply("DELETE", "/instances/", Reply::new(204, ""))
        .reply("DELETE", "/networkSecurityGroups/", Reply::new(204, ""))
}

fn context(mock: &MockOci) -> CommandContext {
    CommandContext::for_tests(mock.client(), "us-ashburn-1")
}

fn request(boot: BootVolumePolicy, delete_nsg: bool) -> DeleteRequest {
    DeleteRequest {
        boot_volume: Some(boot),
        delete_nsg,
        assume_yes: true,
    }
}

#[tokio::test]
async fn terminating_with_the_boot_volume_tells_oci_not_to_preserve_it() {
    let mock = scenario(&[MANAGED_NSG]).start().await;
    let (plan, result) = run(
        &context(&mock),
        "free-arm-1",
        request(BootVolumePolicy::Delete, false),
    )
    .await
    .expect("delete succeeds");

    assert!(result.verified);
    assert_eq!(result.lifecycle_state, "TERMINATING");

    let terminate = mock
        .writes()
        .into_iter()
        .find(|write| write.method() == "DELETE" && write.target().contains("/instances/"))
        .expect("the termination");
    assert!(
        terminate.target().contains("preserveBootVolume=false"),
        "unexpected target {}",
        terminate.target()
    );

    assert!(plan.is_destructive());
    assert!(plan.render_human().contains("50 GB returned"));
}

/// A retained boot volume keeps consuming the allowance, so the plan must say
/// so and the request must tell OCI to preserve it.
#[tokio::test]
async fn keeping_the_boot_volume_is_stated_and_warned_about() {
    let mock = scenario(&[MANAGED_NSG]).start().await;
    let (plan, result) = run(
        &context(&mock),
        "free-arm-1",
        request(BootVolumePolicy::Keep, false),
    )
    .await
    .expect("delete succeeds");

    let terminate = mock
        .writes()
        .into_iter()
        .find(|write| write.method() == "DELETE" && write.target().contains("/instances/"))
        .expect("the termination");
    assert!(terminate.target().contains("preserveBootVolume=true"));

    assert!(
        plan.warnings
            .iter()
            .any(|warning| warning.contains("storage allowance"))
    );
    let volume = result
        .resources
        .iter()
        .find(|resource| resource.kind == "boot volume")
        .expect("the boot volume");
    assert_eq!(volume.outcome, "retained");
    assert!(!result.retained().is_empty());
}

/// The defining safety property: an NSG oci-free did not create is never
/// deleted, even when --delete-nsg is passed.
#[tokio::test]
async fn an_nsg_oci_free_did_not_create_is_never_deleted() {
    let mock = scenario(&[THEIR_NSG]).start().await;
    let (plan, result) = run(
        &context(&mock),
        "free-arm-1",
        request(BootVolumePolicy::Delete, true),
    )
    .await
    .expect("delete succeeds");

    let deletes: Vec<String> = mock
        .writes()
        .iter()
        .filter(|write| write.method() == "DELETE")
        .map(|write| write.target().to_owned())
        .collect();
    assert!(
        !deletes
            .iter()
            .any(|target| target.contains("networkSecurityGroups")),
        "an unowned NSG must never be deleted: {deletes:?}"
    );

    assert!(
        plan.render_human().contains("never deleted"),
        "the plan must say the NSG is left alone"
    );
    assert!(
        result
            .resources
            .iter()
            .all(|resource| resource.kind != "network security group"
                || resource.outcome != "deleted")
    );
}

#[tokio::test]
async fn the_instances_own_managed_nsg_is_deleted_when_asked() {
    let mock = scenario(&[MANAGED_NSG]).start().await;
    let (_, result) = run(
        &context(&mock),
        "free-arm-1",
        request(BootVolumePolicy::Delete, true),
    )
    .await
    .expect("delete succeeds");

    let nsg = result
        .resources
        .iter()
        .find(|resource| resource.kind == "network security group")
        .expect("the NSG outcome");
    assert_eq!(nsg.outcome, "deleted");
    assert_eq!(nsg.ownership, Ownership::Created);

    assert!(mock.writes().iter().any(
        |write| write.method() == "DELETE" && write.target().contains("networkSecurityGroups")
    ));
}

#[tokio::test]
async fn the_managed_nsg_is_kept_unless_asked_for() {
    let mock = scenario(&[MANAGED_NSG]).start().await;
    let (_, result) = run(
        &context(&mock),
        "free-arm-1",
        request(BootVolumePolicy::Delete, false),
    )
    .await
    .expect("delete succeeds");

    let nsg = result
        .resources
        .iter()
        .find(|resource| resource.kind == "network security group")
        .expect("the NSG outcome");
    assert_eq!(nsg.outcome, "retained");
    assert!(nsg.reason.contains("--delete-nsg"));
    assert!(!mock.writes().iter().any(
        |write| write.method() == "DELETE" && write.target().contains("networkSecurityGroups")
    ));
}

/// A shared subnet serves other instances, so deleting one instance must never
/// remove it.
#[tokio::test]
async fn a_shared_subnet_is_reported_as_untouched() {
    let mock = scenario(&[MANAGED_NSG]).start().await;
    let (plan, result) = run(
        &context(&mock),
        "free-arm-1",
        request(BootVolumePolicy::Delete, true),
    )
    .await
    .expect("delete succeeds");

    let subnet = result
        .resources
        .iter()
        .find(|resource| resource.kind == "subnet")
        .expect("the subnet outcome");
    assert_eq!(subnet.outcome, "retained");
    assert!(subnet.reason.contains("shared"));

    assert!(
        !mock
            .writes()
            .iter()
            .any(|write| write.target().contains("/subnets/")),
        "a shared subnet must never be deleted"
    );
    assert!(plan.render_human().contains("shared by every instance"));
}

/// The boot volume decision has no default in a non-interactive run.
#[tokio::test]
async fn a_non_interactive_run_must_state_the_boot_volume_choice() {
    let mock = scenario(&[MANAGED_NSG]).start().await;
    let error = run(
        &context(&mock),
        "free-arm-1",
        DeleteRequest {
            boot_volume: None,
            delete_nsg: false,
            assume_yes: true,
        },
    )
    .await
    .expect_err("must refuse");

    assert!(error.remediation().contains("--delete-boot-volume"));
    assert!(
        error
            .context()
            .expect("context")
            .contains("will not choose for you")
    );
    assert!(mock.writes().is_empty());
}

#[tokio::test]
async fn an_unconfirmed_delete_issues_no_write() {
    let mock = scenario(&[MANAGED_NSG]).start().await;
    let error = run(
        &context(&mock),
        "free-arm-1",
        DeleteRequest {
            boot_volume: Some(BootVolumePolicy::Delete),
            delete_nsg: false,
            assume_yes: false,
        },
    )
    .await
    .expect_err("must refuse");

    assert!(error.remediation().contains("--yes"));
    assert!(mock.writes().is_empty());
}

/// A failed NSG deletion is reported, not swallowed.
#[tokio::test]
async fn a_failed_nsg_deletion_is_reported_rather_than_assumed() {
    let mock = scenario(&[MANAGED_NSG])
        .override_reply(
            "DELETE",
            "/networkSecurityGroups/",
            Reply::new(409, r#"{"code":"Conflict","message":"still attached"}"#)
                .header("opc-request-id", "req-1"),
        )
        .start()
        .await;

    let (_, result) = run(
        &context(&mock),
        "free-arm-1",
        request(BootVolumePolicy::Delete, true),
    )
    .await
    .expect("delete still succeeds; the instance is gone");

    let nsg = result
        .resources
        .iter()
        .find(|resource| resource.kind == "network security group")
        .expect("the NSG outcome");
    assert_eq!(nsg.outcome, "failed");
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("could not be deleted"))
    );
    assert!(render_human(&result).contains("still exist"));
}

/// An instance already gone reads as terminated, not as a failure.
#[tokio::test]
async fn an_instance_that_is_already_gone_verifies_as_terminated() {
    let mock = scenario(&[MANAGED_NSG])
        .override_reply(
            "GET",
            &format!("/instances/{INSTANCE_ID}"),
            Reply::new(
                404,
                r#"{"code":"NotAuthorizedOrNotFound","message":"gone"}"#,
            )
            .header("opc-request-id", "req-2"),
        )
        .start()
        .await;

    // The instance is resolved by name, so the 404 only affects verification.
    let (_, result) = run(
        &context(&mock),
        "free-arm-1",
        request(BootVolumePolicy::Delete, false),
    )
    .await
    .expect("delete succeeds");

    assert_eq!(result.lifecycle_state, "TERMINATED");
    assert!(result.verified);
}

#[test]
fn the_boot_volume_flags_map_onto_a_policy_only_when_unambiguous() {
    assert_eq!(boot_policy(true, false), Some(BootVolumePolicy::Keep));
    assert_eq!(boot_policy(false, true), Some(BootVolumePolicy::Delete));
    assert_eq!(boot_policy(false, false), None);
    assert_eq!(
        boot_policy(true, true),
        None,
        "contradictory flags express no choice"
    );
}
