//! `vm create` tests.
//!
//! The properties proved here are the ones a mistake would be expensive for: a
//! refused plan issues no write at all, nothing is hard-coded, an existing
//! managed network is reused rather than duplicated, and a failure part-way
//! through compensates only what this operation created.

use serde_json::json;

use super::*;
use crate::testing::mock_oci::{MockBuilder, MockOci, Reply, TENANCY};

const VCN_ID: &str = "ocid1.vcn.oc1.iad.managed";
const SUBNET_ID: &str = "ocid1.subnet.oc1.iad.managed";
const GATEWAY_ID: &str = "ocid1.internetgateway.oc1.iad.managed";
const ROUTE_TABLE_ID: &str = "ocid1.routetable.oc1.iad.managed";
const NSG_ID: &str = "ocid1.networksecuritygroup.oc1.iad.new";
const INSTANCE_ID: &str = "ocid1.instance.oc1.iad.new";
const VNIC_ID: &str = "ocid1.vnic.oc1.iad.new";
const IMAGE_ID: &str = "ocid1.image.oc1.iad.ol9";

fn shapes_json() -> serde_json::Value {
    json!([
        {
            "shape": "VM.Standard.A1.Flex",
            "billingType": "ALWAYS_FREE",
            "processorDescription": "2.8 GHz Ampere Altra",
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
            "shape": "VM.Standard.E2.1.Micro",
            "billingType": "ALWAYS_FREE",
            "processorDescription": "2.0 GHz AMD EPYC 7551",
            "ocpus": 1.0,
            "memoryInGBs": 1.0
        },
        {
            "shape": "VM.Standard3.Flex",
            "billingType": "PAID",
            "processorDescription": "Intel Xeon",
            "isFlexible": true,
            "ocpuOptions": { "min": 1.0, "max": 32.0 },
            "memoryOptions": { "minInGBs": 1.0, "maxInGBs": 512.0 }
        }
    ])
}

fn images_json() -> serde_json::Value {
    json!([
        {
            "id": IMAGE_ID,
            "displayName": "Oracle-Linux-9-aarch64-2026.08.01-0",
            "operatingSystem": "Oracle Linux",
            "operatingSystemVersion": "9",
            "lifecycleState": "AVAILABLE",
            "timeCreated": "2026-08-01T00:00:00Z"
        }
    ])
}

fn instance_json(state: &str) -> serde_json::Value {
    json!({
        "id": INSTANCE_ID,
        "compartmentId": TENANCY,
        "displayName": "oci-free-1",
        "lifecycleState": state,
        "availabilityDomain": "Uocm:US-ASHBURN-AD-1",
        "shape": "VM.Standard.A1.Flex",
        "shapeConfig": { "ocpus": 2.0, "memoryInGBs": 12.0 },
        "freeformTags": { "oci-free:managed": "created", "oci-free:role": "instance" }
    })
}

fn vnic_json() -> serde_json::Value {
    json!({
        "id": VNIC_ID,
        "subnetId": SUBNET_ID,
        "privateIp": "10.0.0.42",
        "publicIp": "203.0.113.17",
        "isPrimary": true,
        "nsgIds": [NSG_ID],
        "lifecycleState": "AVAILABLE"
    })
}

fn nsg_json() -> serde_json::Value {
    json!({
        "id": NSG_ID,
        "vcnId": VCN_ID,
        "displayName": "oci-free-oci-free-1",
        "lifecycleState": "AVAILABLE",
        "freeformTags": { "oci-free:managed": "created", "oci-free:role": "instance-nsg" }
    })
}

fn subnet_json() -> serde_json::Value {
    json!({
        "id": SUBNET_ID,
        "vcnId": VCN_ID,
        "displayName": "oci-free-subnet",
        "cidrBlock": "10.0.0.0/24",
        "routeTableId": ROUTE_TABLE_ID,
        "securityListIds": [],
        "prohibitPublicIpOnVnic": false,
        "lifecycleState": "AVAILABLE",
        "freeformTags": { "oci-free:managed": "created", "oci-free:role": "subnet" }
    })
}

fn vcn_json() -> serde_json::Value {
    json!({
        "id": VCN_ID,
        "displayName": "oci-free-vcn",
        "cidrBlock": "10.0.0.0/16",
        "defaultRouteTableId": ROUTE_TABLE_ID,
        "lifecycleState": "AVAILABLE",
        "freeformTags": { "oci-free:managed": "created", "oci-free:role": "vcn" }
    })
}

/// A tenancy that already has a complete managed network and no instances.
fn scenario(existing_instances: serde_json::Value) -> MockBuilder {
    MockOci::builder()
        .get(
            "regionSubscriptions",
            &json!([
                { "regionKey": "IAD", "regionName": "us-ashburn-1", "isHomeRegion": true }
            ]),
        )
        .get(
            "/availabilityDomains",
            &json!([
                { "name": "Uocm:US-ASHBURN-AD-1" },
                { "name": "Uocm:US-ASHBURN-AD-2" }
            ]),
        )
        .get("/shapes", &shapes_json())
        .get("/images", &images_json())
        .get("/instances?", &existing_instances)
        .get("/vcns", &json!([vcn_json()]))
        .get("/subnets?", &json!([subnet_json()]))
        // Registered before the list route: both targets share the prefix, and
        // routes match in registration order.
        .get(&format!("/internetGateways/{GATEWAY_ID}"), &gateway_json())
        .get("/internetGateways", &json!([gateway_json()]))
        .get(
            &format!("/routeTables/{ROUTE_TABLE_ID}"),
            &route_table_json(),
        )
        .get(
            "/vnicAttachments",
            &json!([{
                "id": "ocid1.vnicattachment.oc1.iad.a",
                "instanceId": INSTANCE_ID,
                "vnicId": VNIC_ID,
                "lifecycleState": "ATTACHED"
            }]),
        )
        .get(&format!("/vnics/{VNIC_ID}"), &vnic_json())
        .get(&format!("/subnets/{SUBNET_ID}"), &subnet_json())
        .get(
            &format!("/networkSecurityGroups/{NSG_ID}/securityRules"),
            &json!([{
                "id": "SSHRULE",
                "direction": "INGRESS",
                "protocol": "6",
                "source": "198.51.100.7/32",
                "sourceType": "CIDR_BLOCK",
                "isStateless": false,
                "tcpOptions": { "destinationPortRange": { "min": 22, "max": 22 } }
            }]),
        )
        .get(&format!("/networkSecurityGroups/{NSG_ID}"), &nsg_json())
        .get(
            &format!("/instances/{INSTANCE_ID}"),
            &instance_json("RUNNING"),
        )
        .reply("POST", "/networkSecurityGroups", Reply::json(&nsg_json()))
        .reply("POST", "addSecurityRules", Reply::new(200, ""))
        .reply(
            "POST",
            "/instances",
            Reply::json(&instance_json("PROVISIONING")),
        )
}

fn gateway_json() -> serde_json::Value {
    json!({
        "id": GATEWAY_ID,
        "vcnId": VCN_ID,
        "isEnabled": true,
        "lifecycleState": "AVAILABLE"
    })
}

fn route_table_json() -> serde_json::Value {
    json!({
        "id": ROUTE_TABLE_ID,
        "vcnId": VCN_ID,
        "routeRules": [{
            "destination": "0.0.0.0/0",
            "destinationType": "CIDR_BLOCK",
            "networkEntityId": GATEWAY_ID
        }],
        "lifecycleState": "AVAILABLE"
    })
}

fn context(mock: &MockOci) -> CommandContext {
    CommandContext::for_tests(mock.client(), "us-ashburn-1")
}

fn request() -> CreateRequest {
    CreateRequest {
        name: Some("oci-free-1".to_owned()),
        shape: Some("VM.Standard.A1.Flex".to_owned()),
        ocpus: Some(2.0),
        memory: Some(12.0),
        ssh_source: Some("198.51.100.7/32".to_owned()),
        assume_yes: true,
        ..CreateRequest::default()
    }
}

#[tokio::test]
async fn a_free_launch_reuses_the_managed_network_and_verifies_the_result() {
    let mock = scenario(json!([])).start().await;
    let (plan, result) = run(&context(&mock), &request())
        .await
        .expect("create succeeds");

    assert!(plan.is_safe());
    assert_eq!(plan.billing_risk(), BillingRisk::None);
    assert_eq!(result.instance_id, INSTANCE_ID);
    assert_eq!(result.shape, "VM.Standard.A1.Flex");
    assert_eq!(result.ocpus, 2.0);
    assert_eq!(result.public_ip.as_deref(), Some("203.0.113.17"));
    assert!(result.nsg_verified);
    assert!(result.ssh_reachable);
    assert!(result.ssh_command.is_some());

    // The managed network already existed, so nothing network-shaped was made.
    let writes = mock.writes();
    assert!(
        !writes.iter().any(|write| write.target().ends_with("/vcns")),
        "an existing managed VCN must be reused, not duplicated"
    );
    assert!(result.created.vcn_id.is_none());
    assert_eq!(result.created.instance_id.as_deref(), Some(INSTANCE_ID));

    // The launch must carry the discovered image, domain, and shape config.
    let launch = writes
        .iter()
        .find(|write| write.target().ends_with("/instances"))
        .expect("the launch");
    let body = launch.json_body().expect("body");
    assert_eq!(body["availabilityDomain"], "Uocm:US-ASHBURN-AD-1");
    assert_eq!(body["sourceDetails"]["imageId"], IMAGE_ID);
    assert_eq!(body["shapeConfig"]["ocpus"], 2.0);
    assert_eq!(body["shapeConfig"]["memoryInGBs"], 12.0);
    assert_eq!(body["createVnicDetails"]["subnetId"], SUBNET_ID);
    assert_eq!(body["createVnicDetails"]["assignPublicIp"], true);
    assert_eq!(body["createVnicDetails"]["nsgIds"][0], NSG_ID);
    assert_eq!(body["freeformTags"]["oci-free:managed"], "created");
    assert!(
        launch.header("opc-retry-token").is_some(),
        "a launch must be replay-safe or a lost response could bill twice"
    );

    let rendered = render_human(&result);
    assert!(rendered.contains("203.0.113.17"));
    assert!(rendered.contains("attached and verified"));
}

/// The single most important test in the file: a plan the policy refuses must
/// issue zero write requests.
#[tokio::test]
async fn a_paid_shape_is_refused_before_any_write() {
    let mock = scenario(json!([])).start().await;
    let mut request = request();
    request.shape = Some("VM.Standard3.Flex".to_owned());

    let error = run(&context(&mock), &request)
        .await
        .expect_err("a paid shape must be refused");

    assert_eq!(error.kind(), crate::error::ErrorKind::PolicyRejected);
    assert!(
        mock.writes().is_empty(),
        "a rejected plan must issue zero write requests, found {:?}",
        mock.writes()
            .iter()
            .map(|write| write.target().to_owned())
            .collect::<Vec<String>>()
    );
}

/// Nor may a launch that would exceed the free allowance reach OCI.
#[tokio::test]
async fn a_launch_beyond_the_allowance_is_refused_before_any_write() {
    let mock = scenario(json!([{
        "id": "ocid1.instance.oc1.iad.existing",
        "compartmentId": TENANCY,
        "displayName": "existing",
        "lifecycleState": "RUNNING",
        "shape": "VM.Standard.A1.Flex",
        "shapeConfig": { "ocpus": 3.0, "memoryInGBs": 18.0 }
    }]))
    .start()
    .await;

    let error = run(&context(&mock), &request())
        .await
        .expect_err("an over-allocation must be refused");

    assert_eq!(error.kind(), crate::error::ErrorKind::PolicyRejected);
    assert!(mock.writes().is_empty());
}

/// Usage that cannot be measured must block too: unproven is not free.
#[tokio::test]
async fn unmeasurable_usage_blocks_the_launch() {
    let mock = scenario(json!([{
        "id": "ocid1.instance.oc1.iad.mystery",
        "compartmentId": TENANCY,
        "displayName": "mystery",
        "lifecycleState": "RUNNING",
        "shape": "VM.Standard.A1.Flex"
    }]))
    .start()
    .await;

    let error = run(&context(&mock), &request())
        .await
        .expect_err("unproven capacity must be refused");
    assert_eq!(error.kind(), crate::error::ErrorKind::PolicyRejected);
    assert!(mock.writes().is_empty());
}

#[tokio::test]
async fn an_unconfirmed_plan_issues_no_write() {
    let mock = scenario(json!([])).start().await;
    let mut request = request();
    request.assume_yes = false;

    let error = run(&context(&mock), &request)
        .await
        .expect_err("a non-interactive run without --yes must refuse");
    assert!(error.remediation().contains("--yes"));
    assert!(mock.writes().is_empty());
}

/// A semantic selector resolves from live processor metadata, never a name.
#[tokio::test]
async fn the_arm_selector_resolves_from_live_processor_metadata() {
    let mock = scenario(json!([])).start().await;
    let mut request = request();
    request.shape = Some(SELECTOR_ARM.to_owned());

    let (_, result) = run(&context(&mock), &request)
        .await
        .expect("create succeeds");
    assert_eq!(result.shape, "VM.Standard.A1.Flex");
}

#[tokio::test]
async fn the_x86_selector_resolves_to_the_micro_shape() {
    let mock = scenario(json!([])).start().await;
    let mut request = request();
    request.shape = Some(SELECTOR_X86.to_owned());
    request.ocpus = None;
    request.memory = None;

    let (_, result) = run(&context(&mock), &request)
        .await
        .expect("create succeeds");
    assert_eq!(result.shape, "VM.Standard.E2.1.Micro");
    assert_eq!(result.ocpus, 1.0);

    // A fixed shape must not send a shapeConfig OCI would reject.
    let launch = mock
        .writes()
        .into_iter()
        .find(|write| write.target().ends_with("/instances"))
        .expect("the launch");
    assert!(
        launch
            .json_body()
            .expect("body")
            .get("shapeConfig")
            .is_none()
    );
}

/// The image is discovered, never pinned.
#[tokio::test]
async fn the_image_is_discovered_from_the_live_catalogue() {
    let mock = scenario(json!([])).start().await;
    let (_, result) = run(&context(&mock), &request())
        .await
        .expect("create succeeds");

    assert_eq!(result.image_id, IMAGE_ID);
    assert_eq!(
        result.image_name.as_deref(),
        Some("Oracle-Linux-9-aarch64-2026.08.01-0")
    );
}

#[tokio::test]
async fn an_invalid_flexible_size_is_refused_before_any_write() {
    let mock = scenario(json!([])).start().await;
    let mut request = request();
    request.ocpus = Some(200.0);
    request.memory = Some(12.0);

    let error = run(&context(&mock), &request)
        .await
        .expect_err("must refuse");
    assert_eq!(error.kind(), crate::error::ErrorKind::InvalidInput);
    assert!(mock.writes().is_empty());
}

#[tokio::test]
async fn opening_ssh_to_the_world_is_warned_about_in_the_plan() {
    let mock = scenario(json!([])).start().await;
    let mut request = request();
    request.ssh_source = Some("0.0.0.0/0".to_owned());

    let (plan, _) = run(&context(&mock), &request)
        .await
        .expect("create succeeds");
    assert!(
        plan.warnings
            .iter()
            .any(|warning| warning.contains("every address on the internet"))
    );
}

#[tokio::test]
async fn ssh_can_be_left_closed() {
    let mock = scenario(json!([])).start().await;
    let mut request = request();
    request.ssh_source = Some("none".to_owned());

    let (_, result) = run(&context(&mock), &request)
        .await
        .expect("create succeeds");
    assert!(!result.ssh_reachable);
    assert!(
        !mock
            .writes()
            .iter()
            .any(|write| write.target().contains("addSecurityRules")),
        "no ingress rule should be added when SSH is left closed"
    );
}

/// A failure after the NSG was created must remove the NSG and nothing else.
#[tokio::test]
async fn a_failed_launch_compensates_only_what_it_created() {
    let mock = scenario(json!([]))
        .override_reply(
            "POST",
            "/instances",
            Reply::new(
                500,
                r#"{"code":"InternalError","message":"capacity unavailable"}"#,
            )
            .header("opc-request-id", "req-9"),
        )
        .reply("DELETE", "/networkSecurityGroups/", Reply::new(204, ""))
        .start()
        .await;

    let error = run(&context(&mock), &request())
        .await
        .expect_err("the launch fails");

    // The NSG this operation created was removed again.
    let deletes: Vec<String> = mock
        .writes()
        .iter()
        .filter(|write| write.method() == "DELETE")
        .map(|write| write.target().to_owned())
        .collect();
    assert_eq!(
        deletes.len(),
        1,
        "exactly the NSG must be deleted: {deletes:?}"
    );
    assert!(deletes[0].contains("networkSecurityGroups"));
    assert!(
        !deletes.iter().any(|target| target.contains("/vcns/")
            || target.contains("/subnets/")
            || target.contains("/internetGateways/")),
        "the pre-existing managed network must never be deleted: {deletes:?}"
    );
    assert!(
        error
            .context()
            .unwrap_or_default()
            .contains("nothing that existed beforehand")
    );
}

/// A failure while building the managed network must remove the VCN and gateway
/// this operation created — and nothing else, since nothing else existed yet.
#[tokio::test]
async fn a_failure_building_the_network_compensates_the_objects_already_created() {
    let mock = scenario(json!([]))
        // No managed VCN exists, so one has to be built.
        .override_reply("GET", "/vcns", Reply::json(&json!([])))
        .reply("POST", "/vcns", Reply::json(&vcn_json()))
        .reply("POST", "/internetGateways", Reply::json(&gateway_json()))
        .reply("PUT", "/routeTables/", Reply::json(&route_table_json()))
        // The subnet is the last step, and it fails.
        .override_reply(
            "POST",
            "/subnets",
            Reply::new(409, r#"{"code":"Conflict","message":"cidr overlaps"}"#)
                .header("opc-request-id", "req-8"),
        )
        .reply("DELETE", "/", Reply::new(204, ""))
        .start()
        .await;

    let error = run(&context(&mock), &request())
        .await
        .expect_err("the subnet creation fails");

    let deletes: Vec<String> = mock
        .writes()
        .iter()
        .filter(|write| write.method() == "DELETE")
        .map(|write| write.target().to_owned())
        .collect();

    assert_eq!(
        deletes.len(),
        2,
        "exactly the gateway and VCN should be removed: {deletes:?}"
    );
    assert!(deletes[0].contains("/internetGateways/"));
    assert!(deletes[1].contains("/vcns/"));
    assert!(
        !mock
            .writes()
            .iter()
            .any(|write| write.method() == "DELETE" && write.target().contains("/instances/")),
        "no instance existed, so none may be terminated"
    );
    assert!(
        error
            .context()
            .unwrap_or_default()
            .contains("nothing that existed beforehand"),
        "the error must reassure that pre-existing resources were untouched"
    );
}

/// When compensation itself fails, the result is a partial mutation naming
/// exactly what is left behind.
#[tokio::test]
async fn a_failed_compensation_reports_a_partial_mutation() {
    let mock = scenario(json!([]))
        .override_reply(
            "POST",
            "/instances",
            Reply::new(500, r#"{"code":"InternalError","message":"boom"}"#)
                .header("opc-request-id", "req-9"),
        )
        .override_reply(
            "DELETE",
            "/networkSecurityGroups/",
            Reply::new(409, r#"{"code":"Conflict","message":"still in use"}"#)
                .header("opc-request-id", "req-10"),
        )
        .start()
        .await;

    let error = run(&context(&mock), &request())
        .await
        .expect_err("the launch fails");

    assert_eq!(error.kind(), crate::error::ErrorKind::PartialMutation);
    assert_eq!(error.exit_code_kind().code(), 7);
    let context_text = error.context().expect("context");
    assert!(context_text.contains("network security group"));
    assert!(error.remediation().contains("oci-free:managed=created"));
}

#[tokio::test]
async fn a_private_key_supplied_as_an_ssh_key_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("id_rsa");
    std::fs::write(
        &path,
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
    )
    .expect("write key");

    let mock = scenario(json!([])).start().await;
    let mut request = request();
    request.ssh_key = Some(path);

    let error = run(&context(&mock), &request)
        .await
        .expect_err("a private key must be refused");
    assert!(error.message().contains("private key"));
    assert!(error.remediation().contains(".pub"));
    assert!(mock.writes().is_empty());
}

#[tokio::test]
async fn a_public_key_is_installed_as_instance_metadata() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("id_ed25519.pub");
    std::fs::write(&path, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 me@example\n").expect("write key");

    let mock = scenario(json!([])).start().await;
    let mut request = request();
    request.ssh_key = Some(path);

    run(&context(&mock), &request)
        .await
        .expect("create succeeds");

    let launch = mock
        .writes()
        .into_iter()
        .find(|write| write.target().ends_with("/instances"))
        .expect("the launch");
    let body = launch.json_body().expect("body");
    assert!(
        body["metadata"]["ssh_authorized_keys"]
            .as_str()
            .expect("key")
            .starts_with("ssh-ed25519")
    );
}

#[tokio::test]
async fn an_unknown_availability_domain_is_refused_with_the_real_ones_listed() {
    let mock = scenario(json!([])).start().await;
    let mut request = request();
    request.availability_domain = Some("Uocm:US-ASHBURN-AD-9".to_owned());

    let error = run(&context(&mock), &request)
        .await
        .expect_err("must refuse");
    assert!(
        error
            .context()
            .expect("context")
            .contains("US-ASHBURN-AD-1")
    );
    assert!(mock.writes().is_empty());
}
