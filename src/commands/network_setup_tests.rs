//! Managed-network tests.
//!
//! The two properties that protect a user's existing infrastructure: a
//! lookalike name is never adopted, and compensation deletes only what this
//! operation created.

use serde_json::json;

use super::*;
use crate::{
    domain::plan::MutationPlan,
    testing::mock_oci::{MockOci, Reply, TENANCY},
};

const VCN_ID: &str = "ocid1.vcn.oc1.iad.managed";
const SUBNET_ID: &str = "ocid1.subnet.oc1.iad.managed";
const GATEWAY_ID: &str = "ocid1.internetgateway.oc1.iad.managed";
const ROUTE_TABLE_ID: &str = "ocid1.routetable.oc1.iad.managed";

fn vcn_json(tags: serde_json::Value) -> serde_json::Value {
    json!({
        "id": VCN_ID,
        "compartmentId": TENANCY,
        "displayName": MANAGED_VCN_NAME,
        "cidrBlock": MANAGED_VCN_CIDR,
        "defaultRouteTableId": ROUTE_TABLE_ID,
        "lifecycleState": "AVAILABLE",
        "freeformTags": tags
    })
}

fn subnet_json(private: bool) -> serde_json::Value {
    json!({
        "id": SUBNET_ID,
        "vcnId": VCN_ID,
        "compartmentId": TENANCY,
        "displayName": MANAGED_SUBNET_NAME,
        "cidrBlock": MANAGED_SUBNET_CIDR,
        "routeTableId": ROUTE_TABLE_ID,
        "securityListIds": [],
        "prohibitPublicIpOnVnic": private,
        "lifecycleState": "AVAILABLE",
        "freeformTags": { "oci-free:managed": "created", "oci-free:role": "subnet" }
    })
}

fn gateway_json(enabled: bool) -> serde_json::Value {
    json!({
        "id": GATEWAY_ID,
        "vcnId": VCN_ID,
        "displayName": MANAGED_GATEWAY_NAME,
        "isEnabled": enabled,
        "lifecycleState": "AVAILABLE",
        "freeformTags": { "oci-free:managed": "created", "oci-free:role": "internet-gateway" }
    })
}

fn route_table_json(routed: bool) -> serde_json::Value {
    json!({
        "id": ROUTE_TABLE_ID,
        "vcnId": VCN_ID,
        "routeRules": if routed {
            json!([{
                "destination": "0.0.0.0/0",
                "destinationType": "CIDR_BLOCK",
                "networkEntityId": GATEWAY_ID
            }])
        } else {
            json!([])
        },
        "lifecycleState": "AVAILABLE"
    })
}

fn context(mock: &MockOci) -> CommandContext {
    CommandContext::for_tests(mock.client(), "us-ashburn-1")
}

fn approval() -> Approval {
    MutationPlan::new("vm.create", "us-ashburn-1")
        .approve(true)
        .expect("an empty plan approves")
}

#[tokio::test]
async fn a_complete_managed_network_is_reused_untouched() {
    let mock = MockOci::builder()
        .get(
            "/vcns",
            &json!([vcn_json(
                json!({ "oci-free:managed": "created", "oci-free:role": "vcn" })
            )]),
        )
        .get("/subnets", &json!([subnet_json(false)]))
        .get("/internetGateways", &json!([gateway_json(true)]))
        .get(
            &format!("/routeTables/{ROUTE_TABLE_ID}"),
            &route_table_json(true),
        )
        .start()
        .await;

    let result = plan(&context(&mock)).await.expect("plan succeeds");
    let network = result.existing.expect("an existing managed network");

    assert_eq!(network.vcn_id, VCN_ID);
    assert_eq!(network.subnet_id, SUBNET_ID);
    assert!(network.internet_routed);
    assert!(network.public_addressing_allowed);
    assert_eq!(network.vcn_ownership, Ownership::Created);
    assert!(
        result
            .changes
            .iter()
            .all(|change| change.kind == ChangeKind::Reuse)
    );
    assert!(mock.writes().is_empty(), "planning must not write");
}

/// The property that protects a user's own infrastructure: a name is not
/// ownership.
#[tokio::test]
async fn a_lookalike_vcn_without_ownership_tags_is_never_adopted() {
    let mock = MockOci::builder()
        // Same display name, no ownership tag.
        .get("/vcns", &json!([vcn_json(json!({}))]))
        .get("/subnets", &json!([]))
        .start()
        .await;

    let result = plan(&context(&mock)).await.expect("plan succeeds");

    assert!(
        result.existing.is_none(),
        "an untagged VCN must not be adopted however it is named"
    );
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("will not be used or modified")),
        "{:?}",
        result.warnings
    );
    assert!(
        result
            .changes
            .iter()
            .any(|change| change.kind == ChangeKind::Create),
        "a fresh managed network must be planned instead"
    );
}

/// A tag value this build does not recognise is not ownership either.
#[tokio::test]
async fn an_unrecognised_ownership_tag_is_not_adopted() {
    let mock = MockOci::builder()
        .get(
            "/vcns",
            &json!([vcn_json(json!({ "oci-free:managed": "yes" }))]),
        )
        .get("/subnets", &json!([]))
        .start()
        .await;

    let result = plan(&context(&mock)).await.expect("plan succeeds");
    assert!(result.existing.is_none());
}

/// A reused managed network whose topology drifted must be reported, not
/// silently used to launch an unreachable instance.
#[tokio::test]
async fn a_reused_network_with_a_disabled_gateway_is_reported() {
    let mock = MockOci::builder()
        .get(
            "/vcns",
            &json!([vcn_json(json!({ "oci-free:managed": "created" }))]),
        )
        .get("/subnets", &json!([subnet_json(false)]))
        .get("/internetGateways", &json!([gateway_json(false)]))
        .get(
            &format!("/routeTables/{ROUTE_TABLE_ID}"),
            &route_table_json(true),
        )
        .start()
        .await;

    let result = plan(&context(&mock)).await.expect("plan succeeds");
    let network = result.existing.expect("the managed network");

    assert!(!network.internet_routed);
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("not enabled"))
    );
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("no internet connectivity"))
    );
}

#[tokio::test]
async fn a_reused_subnet_made_private_is_reported() {
    let mock = MockOci::builder()
        .get(
            "/vcns",
            &json!([vcn_json(json!({ "oci-free:managed": "created" }))]),
        )
        .get("/subnets", &json!([subnet_json(true)]))
        .get("/internetGateways", &json!([gateway_json(true)]))
        .get(
            &format!("/routeTables/{ROUTE_TABLE_ID}"),
            &route_table_json(true),
        )
        .start()
        .await;

    let result = plan(&context(&mock)).await.expect("plan succeeds");
    let network = result.existing.expect("the managed network");

    assert!(!network.public_addressing_allowed);
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("forbids public IP addresses"))
    );
}

#[tokio::test]
async fn provisioning_creates_the_whole_set_and_records_every_object() {
    let mock = MockOci::builder()
        .reply(
            "POST",
            "/vcns",
            Reply::json(&vcn_json(json!({ "oci-free:managed": "created" }))),
        )
        .reply(
            "POST",
            "/internetGateways",
            Reply::json(&gateway_json(true)),
        )
        .reply("PUT", "/routeTables/", Reply::json(&route_table_json(true)))
        .reply("POST", "/subnets", Reply::json(&subnet_json(false)))
        .start()
        .await;

    let mut created = CreatedResources::default();
    let network = provision(&context(&mock), &mut created, &approval())
        .await
        .expect("provision succeeds");

    assert_eq!(network.vcn_id, VCN_ID);
    assert!(network.internet_routed);
    assert_eq!(created.vcn_id.as_deref(), Some(VCN_ID));
    assert_eq!(created.subnet_id.as_deref(), Some(SUBNET_ID));
    assert_eq!(created.internet_gateway_id.as_deref(), Some(GATEWAY_ID));

    // Every created object must carry ownership tags, or cleanup could never
    // prove it may delete them.
    for write in mock.writes() {
        if write.method() != "POST" {
            continue;
        }
        let body = write.json_body().expect("a JSON body");
        assert_eq!(
            body["freeformTags"]["oci-free:managed"],
            "created",
            "{} was created without ownership tags",
            write.target()
        );
        assert!(
            write.header("opc-retry-token").is_some(),
            "{} was created without an idempotency token",
            write.target()
        );
    }
}

/// The route is written before the subnet, so a subnet never briefly exists
/// with no path off the VCN.
#[tokio::test]
async fn the_route_is_created_before_the_subnet() {
    let mock = MockOci::builder()
        .reply("POST", "/vcns", Reply::json(&vcn_json(json!({}))))
        .reply(
            "POST",
            "/internetGateways",
            Reply::json(&gateway_json(true)),
        )
        .reply("PUT", "/routeTables/", Reply::json(&route_table_json(true)))
        .reply("POST", "/subnets", Reply::json(&subnet_json(false)))
        .start()
        .await;

    let mut created = CreatedResources::default();
    provision(&context(&mock), &mut created, &approval())
        .await
        .expect("provision succeeds");

    let writes = mock.writes();
    let route_at = writes
        .iter()
        .position(|write| write.method() == "PUT")
        .expect("the route update");
    let subnet_at = writes
        .iter()
        .position(|write| write.target().ends_with("/subnets"))
        .expect("the subnet create");
    assert!(route_at < subnet_at);
}

/// Compensation deletes in reverse creation order and only what was created.
#[tokio::test]
async fn compensation_removes_only_what_was_created_in_reverse_order() {
    let mock = MockOci::builder()
        .reply("DELETE", "/", Reply::new(204, ""))
        .start()
        .await;

    let created = CreatedResources {
        vcn_id: Some(VCN_ID.to_owned()),
        subnet_id: Some(SUBNET_ID.to_owned()),
        internet_gateway_id: Some(GATEWAY_ID.to_owned()),
        nsg_id: Some("ocid1.networksecuritygroup.oc1.iad.n".to_owned()),
        instance_id: None,
    };

    let (retained, problems) = compensate(&context(&mock), &created).await;
    assert!(retained.is_empty());
    assert!(problems.is_empty());

    let targets: Vec<String> = mock
        .writes()
        .iter()
        .map(|write| write.target().to_owned())
        .collect();
    assert_eq!(targets.len(), 4);
    assert!(targets[0].contains("networkSecurityGroups"));
    assert!(targets[1].contains("/subnets/"));
    assert!(targets[2].contains("/internetGateways/"));
    assert!(targets[3].contains("/vcns/"));
}

/// Nothing that already existed is ever deleted during recovery.
#[tokio::test]
async fn compensation_touches_nothing_when_nothing_was_created() {
    let mock = MockOci::builder()
        .reply("DELETE", "/", Reply::new(204, ""))
        .start()
        .await;

    let (retained, problems) = compensate(&context(&mock), &CreatedResources::default()).await;
    assert!(retained.is_empty());
    assert!(problems.is_empty());
    assert!(
        mock.writes().is_empty(),
        "an empty record must produce no deletions"
    );
}

/// An instance is never terminated by compensation: that decision is the
/// user's, so it is reported instead.
#[tokio::test]
async fn a_created_instance_is_reported_rather_than_terminated() {
    let mock = MockOci::builder()
        .reply("DELETE", "/", Reply::new(204, ""))
        .start()
        .await;

    let created = CreatedResources {
        instance_id: Some("ocid1.instance.oc1.iad.new".to_owned()),
        ..CreatedResources::default()
    };
    let (retained, _) = compensate(&context(&mock), &created).await;

    assert_eq!(
        retained.instance_id.as_deref(),
        Some("ocid1.instance.oc1.iad.new")
    );
    assert!(
        mock.writes().is_empty(),
        "compensation must never terminate an instance"
    );
    assert!(retained.describe()[0].contains("compute instance"));
}

/// A deletion that fails must be reported as retained, not silently forgotten.
#[tokio::test]
async fn a_failed_deletion_is_reported_as_retained() {
    let mock = MockOci::builder()
        .reply(
            "DELETE",
            "/vcns/",
            Reply::new(
                409,
                r#"{"code":"Conflict","message":"the VCN still has resources"}"#,
            )
            .header("opc-request-id", "req-1"),
        )
        .reply("DELETE", "/", Reply::new(204, ""))
        .start()
        .await;

    let created = CreatedResources {
        vcn_id: Some(VCN_ID.to_owned()),
        subnet_id: Some(SUBNET_ID.to_owned()),
        ..CreatedResources::default()
    };
    let (retained, problems) = compensate(&context(&mock), &created).await;

    assert_eq!(retained.vcn_id.as_deref(), Some(VCN_ID));
    assert!(retained.subnet_id.is_none(), "the subnet was removed");
    assert_eq!(problems.len(), 1);
    assert!(problems[0].contains("VCN"));
}
