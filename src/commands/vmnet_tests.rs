//! `vm net` command tests, run against the in-process mock OCI server.
//!
//! These are the tests that prove the network safety contract end to end: a
//! change touches exactly one NSG, a refused plan issues no write at all, and
//! `close` reports what is still reachable.

use serde_json::json;

use super::*;
use crate::testing::mock_oci::{MockOci, Reply, TENANCY};

const INSTANCE_ID: &str = "ocid1.instance.oc1.iad.anuwcljtexampleinstance1";
const VNIC_ID: &str = "ocid1.vnic.oc1.iad.abuwcljrexamplevnic1";
const SUBNET_ID: &str = "ocid1.subnet.oc1.iad.aaaaaaaaexamplesubnet1";
const VCN_ID: &str = "ocid1.vcn.oc1.iad.aaaaaaaaexamplevcn1";
const MANAGED_NSG_ID: &str = "ocid1.networksecuritygroup.oc1.iad.managed";
const SECURITY_LIST_ID: &str = "ocid1.securitylist.oc1.iad.default";
const ROUTE_TABLE_ID: &str = "ocid1.routetable.oc1.iad.rt";
const GATEWAY_ID: &str = "ocid1.internetgateway.oc1.iad.igw";

fn instance_json() -> serde_json::Value {
    json!({
        "id": INSTANCE_ID,
        "compartmentId": TENANCY,
        "displayName": "free-arm-1",
        "lifecycleState": "RUNNING",
        "availabilityDomain": "Uocm:US-ASHBURN-AD-1",
        "shape": "VM.Standard.A1.Flex",
        "shapeConfig": { "ocpus": 2.0, "memoryInGBs": 12.0 },
        "timeCreated": "2026-02-01T09:15:00.000Z",
        "imageId": "ocid1.image.oc1.iad.aaaaaaaaexampleimage1",
        "freeformTags": { "oci-free:managed": "created", "oci-free:role": "instance" }
    })
}

fn vnic_json(nsg_ids: &[&str], public_ip: Option<&str>) -> serde_json::Value {
    json!({
        "id": VNIC_ID,
        "compartmentId": TENANCY,
        "subnetId": SUBNET_ID,
        "privateIp": "10.0.0.42",
        "publicIp": public_ip,
        "isPrimary": true,
        "nsgIds": nsg_ids,
        "lifecycleState": "AVAILABLE"
    })
}

fn subnet_json() -> serde_json::Value {
    json!({
        "id": SUBNET_ID,
        "vcnId": VCN_ID,
        "compartmentId": TENANCY,
        "displayName": "oci-free-public",
        "cidrBlock": "10.0.0.0/24",
        "routeTableId": ROUTE_TABLE_ID,
        "securityListIds": [SECURITY_LIST_ID],
        "prohibitPublicIpOnVnic": false,
        "lifecycleState": "AVAILABLE"
    })
}

fn managed_nsg_json() -> serde_json::Value {
    json!({
        "id": MANAGED_NSG_ID,
        "compartmentId": TENANCY,
        "vcnId": VCN_ID,
        "displayName": "oci-free-free-arm-1",
        "lifecycleState": "AVAILABLE",
        "freeformTags": {
            "oci-free:managed": "created",
            "oci-free:role": "instance-nsg",
            "oci-free:instance": INSTANCE_ID
        }
    })
}

fn ssh_rule_json() -> serde_json::Value {
    json!({
        "id": "SSHRULE",
        "direction": "INGRESS",
        "protocol": "6",
        "source": "0.0.0.0/0",
        "sourceType": "CIDR_BLOCK",
        "isStateless": false,
        "tcpOptions": { "destinationPortRange": { "min": 22, "max": 22 } },
        "description": "oci-free managed: 22/tcp"
    })
}

fn security_list_json(rules: serde_json::Value) -> serde_json::Value {
    json!({
        "id": SECURITY_LIST_ID,
        "vcnId": VCN_ID,
        "compartmentId": TENANCY,
        "displayName": "Default Security List",
        "lifecycleState": "AVAILABLE",
        "ingressSecurityRules": rules
    })
}

fn route_table_json() -> serde_json::Value {
    json!({
        "id": ROUTE_TABLE_ID,
        "vcnId": VCN_ID,
        "displayName": "default",
        "lifecycleState": "AVAILABLE",
        "routeRules": [{
            "destination": "0.0.0.0/0",
            "destinationType": "CIDR_BLOCK",
            "networkEntityId": GATEWAY_ID
        }]
    })
}

fn gateway_json() -> serde_json::Value {
    json!({
        "id": GATEWAY_ID,
        "vcnId": VCN_ID,
        "displayName": "oci-free-igw",
        "isEnabled": true,
        "lifecycleState": "AVAILABLE"
    })
}

/// A tenancy with one public instance behind a managed NSG.
///
/// `nsg_rules` and `list_rules` let each test vary only what it cares about.
fn scenario(
    nsg_ids: &[&str],
    nsg_rules: serde_json::Value,
    list_rules: serde_json::Value,
) -> crate::testing::mock_oci::MockBuilder {
    MockOci::builder()
        .get(
            "/vnicAttachments",
            &json!([{
                "id": "ocid1.vnicattachment.oc1.iad.a",
                "instanceId": INSTANCE_ID,
                "vnicId": VNIC_ID,
                "subnetId": SUBNET_ID,
                "lifecycleState": "ATTACHED"
            }]),
        )
        .get(&format!("/instances/{INSTANCE_ID}"), &instance_json())
        .get("/instances?", &json!([instance_json()]))
        .get(
            &format!("/vnics/{VNIC_ID}"),
            &vnic_json(nsg_ids, Some("203.0.113.17")),
        )
        .get(&format!("/subnets/{SUBNET_ID}"), &subnet_json())
        .get(
            &format!("/networkSecurityGroups/{MANAGED_NSG_ID}/securityRules"),
            &nsg_rules,
        )
        .get(
            &format!("/networkSecurityGroups/{MANAGED_NSG_ID}"),
            &managed_nsg_json(),
        )
        .get(
            &format!("/securityLists/{SECURITY_LIST_ID}"),
            &security_list_json(list_rules),
        )
        .get(
            &format!("/routeTables/{ROUTE_TABLE_ID}"),
            &route_table_json(),
        )
        .get(&format!("/internetGateways/{GATEWAY_ID}"), &gateway_json())
}

fn context(mock: &MockOci) -> CommandContext {
    CommandContext::for_tests(mock.client(), "us-ashburn-1")
}

fn ssh() -> PortRule {
    "22/tcp".parse().expect("rule")
}

fn https() -> PortRule {
    "443/tcp".parse().expect("rule")
}

// -- show -------------------------------------------------------------------

#[tokio::test]
async fn show_reports_composed_exposure_with_provenance() {
    let mock = scenario(
        &[MANAGED_NSG_ID],
        json!([ssh_rule_json()]),
        json!([{
            "protocol": "6",
            "source": "0.0.0.0/0",
            "sourceType": "CIDR_BLOCK",
            "isStateless": false,
            "tcpOptions": { "destinationPortRange": { "min": 443, "max": 443 } }
        }]),
    )
    .start()
    .await;

    let show = show(&context(&mock), "free-arm-1")
        .await
        .expect("show succeeds");
    let exposure = show.exposure.clone().expect("exposure");

    assert!(exposure.allows(ssh()), "the NSG allows 22");
    assert!(exposure.allows(https()), "the security list allows 443");
    assert_eq!(exposure.rules.len(), 2);
    assert!(exposure.internet.reachable);
    assert_eq!(
        exposure.managed_nsg().expect("managed NSG").id,
        MANAGED_NSG_ID
    );

    let rendered = render_show(&show);
    assert!(rendered.contains("NSG oci-free-free-arm-1"));
    assert!(rendered.contains("security list Default Security List"));
    assert!(mock.writes().is_empty(), "show must not write anything");
}

/// An instance whose network cannot be read must say so, not report "closed".
#[tokio::test]
async fn show_degrades_when_the_network_cannot_be_read() {
    let mock = MockOci::builder()
        .get(&format!("/instances/{INSTANCE_ID}"), &instance_json())
        .get("/instances?", &json!([instance_json()]))
        .reply(
            "GET",
            "/vnicAttachments",
            Reply::new(403, r#"{"code":"NotAuthorized","message":"no vcn read"}"#)
                .header("opc-request-id", "req-1"),
        )
        .start()
        .await;

    let show = show(&context(&mock), "free-arm-1")
        .await
        .expect("show still succeeds");
    assert!(show.exposure.is_none());
    assert!(show.unavailable.is_some());
    assert!(!show.warnings.is_empty());
    assert!(render_show(&show).contains("unavailable"));
}

// -- audit ------------------------------------------------------------------

#[tokio::test]
async fn audit_flags_ssh_open_to_the_world_and_names_the_object() {
    let mock = scenario(&[MANAGED_NSG_ID], json!([ssh_rule_json()]), json!([]))
        .start()
        .await;

    let result = run_audit(&context(&mock), "free-arm-1")
        .await
        .expect("audit succeeds");
    let report = result.audit.as_ref().expect("a report");

    assert_eq!(report.highest_severity, Severity::Critical);
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.id == "ssh_open_to_internet")
        .expect("the SSH finding");
    assert_eq!(
        finding.origin.as_ref().expect("origin").id,
        MANAGED_NSG_ID,
        "the finding must name the NSG responsible"
    );
    assert!(render_audit(&result).contains("critical"));
    assert_eq!(
        concerning_findings(&result).len(),
        report
            .findings
            .iter()
            .filter(|f| f.severity >= Severity::Warning)
            .count()
    );
    assert!(mock.writes().is_empty());
}

#[tokio::test]
async fn audit_flags_inherited_subnet_exposure() {
    let mock = scenario(
        &[MANAGED_NSG_ID],
        json!([]),
        json!([{
            "protocol": "6",
            "source": "0.0.0.0/0",
            "sourceType": "CIDR_BLOCK",
            "isStateless": false,
            "tcpOptions": { "destinationPortRange": { "min": 22, "max": 22 } }
        }]),
    )
    .start()
    .await;

    let result = run_audit(&context(&mock), "free-arm-1")
        .await
        .expect("audit succeeds");
    let report = result.audit.expect("a report");
    let inherited = report
        .findings
        .iter()
        .find(|finding| finding.id == "inherited_subnet_exposure")
        .expect("the inherited finding");
    assert_eq!(
        inherited.origin.as_ref().expect("origin").id,
        SECURITY_LIST_ID
    );
}

// -- open -------------------------------------------------------------------

#[tokio::test]
async fn open_modifies_only_the_instance_nsg() {
    let mock = scenario(&[MANAGED_NSG_ID], json!([]), json!([]))
        .reply("POST", "addSecurityRules", Reply::new(200, ""))
        .start()
        .await;

    let (plan, change) = open(
        &context(&mock),
        "free-arm-1",
        https(),
        Some("198.51.100.7/32"),
        true,
    )
    .await
    .expect("open succeeds");

    assert!(plan.is_safe());
    assert_eq!(change.nsg_id, MANAGED_NSG_ID);
    assert!(!change.nsg_created);

    let writes = mock.writes();
    assert_eq!(writes.len(), 1, "exactly one write: the NSG rule addition");
    let write = &writes[0];
    assert!(
        write.target().contains(&format!(
            "/networkSecurityGroups/{MANAGED_NSG_ID}/securityRules/actions/addSecurityRules"
        )),
        "unexpected target {}",
        write.target()
    );
    assert!(
        !write.target().contains("securityLists"),
        "a subnet Security List must never be modified by `open`"
    );

    let body = write.json_body().expect("a JSON body");
    let rule = &body["securityRules"][0];
    assert_eq!(rule["direction"], "INGRESS");
    assert_eq!(rule["protocol"], "6");
    assert_eq!(rule["source"], "198.51.100.7/32");
    assert_eq!(rule["tcpOptions"]["destinationPortRange"]["min"], 443);
    assert_eq!(rule["isStateless"], false);
}

/// With no managed NSG, `open` creates one, attaches it to the VNIC preserving
/// what was there, and only then adds the rule.
#[tokio::test]
async fn open_creates_and_attaches_a_managed_nsg_when_none_exists() {
    let other_nsg = "ocid1.networksecuritygroup.oc1.iad.theirs";
    let mock = MockOci::builder()
        .get(
            "/vnicAttachments",
            &json!([{
                "id": "ocid1.vnicattachment.oc1.iad.a",
                "instanceId": INSTANCE_ID,
                "vnicId": VNIC_ID,
                "lifecycleState": "ATTACHED"
            }]),
        )
        .get(&format!("/instances/{INSTANCE_ID}"), &instance_json())
        .get("/instances?", &json!([instance_json()]))
        .route(
            "GET",
            &format!("/vnics/{VNIC_ID}"),
            vec![
                // Before the change: only the user's own NSG.
                Reply::json(&vnic_json(&[other_nsg], Some("203.0.113.17"))),
                // After: the managed NSG has been attached alongside it.
                Reply::json(&vnic_json(
                    &[other_nsg, MANAGED_NSG_ID],
                    Some("203.0.113.17"),
                )),
            ],
        )
        .get(&format!("/subnets/{SUBNET_ID}"), &subnet_json())
        .get(
            &format!("/networkSecurityGroups/{other_nsg}/securityRules"),
            &json!([]),
        )
        .get(
            &format!("/networkSecurityGroups/{other_nsg}"),
            &json!({
                "id": other_nsg,
                "vcnId": VCN_ID,
                "displayName": "their-nsg",
                "lifecycleState": "AVAILABLE"
            }),
        )
        .get(
            &format!("/networkSecurityGroups/{MANAGED_NSG_ID}/securityRules"),
            &json!([{
                "id": "NEWRULE",
                "direction": "INGRESS",
                "protocol": "6",
                "source": "198.51.100.7/32",
                "sourceType": "CIDR_BLOCK",
                "isStateless": false,
                "tcpOptions": { "destinationPortRange": { "min": 443, "max": 443 } }
            }]),
        )
        .get(
            &format!("/networkSecurityGroups/{MANAGED_NSG_ID}"),
            &managed_nsg_json(),
        )
        .get(
            &format!("/securityLists/{SECURITY_LIST_ID}"),
            &security_list_json(json!([])),
        )
        .get(
            &format!("/routeTables/{ROUTE_TABLE_ID}"),
            &route_table_json(),
        )
        .get(&format!("/internetGateways/{GATEWAY_ID}"), &gateway_json())
        .reply(
            "POST",
            "/networkSecurityGroups",
            Reply::json(&managed_nsg_json()),
        )
        .reply(
            "PUT",
            &format!("/vnics/{VNIC_ID}"),
            Reply::json(&vnic_json(
                &[other_nsg, MANAGED_NSG_ID],
                Some("203.0.113.17"),
            )),
        )
        .start()
        .await;

    let (_, change) = open(
        &context(&mock),
        "free-arm-1",
        https(),
        Some("198.51.100.7/32"),
        true,
    )
    .await
    .expect("open succeeds");

    assert!(change.nsg_created);
    assert!(
        change.verified,
        "the rule must be confirmed by a fresh read"
    );

    let writes = mock.writes();
    let create = writes
        .iter()
        .find(|write| {
            write.method() == "POST" && write.target().ends_with("/networkSecurityGroups")
        })
        .expect("the NSG create");
    let body = create.json_body().expect("body");
    assert_eq!(body["freeformTags"]["oci-free:managed"], "created");
    assert_eq!(body["freeformTags"]["oci-free:role"], "instance-nsg");
    assert_eq!(body["freeformTags"]["oci-free:instance"], INSTANCE_ID);
    assert_eq!(body["vcnId"], VCN_ID);
    assert!(
        create.header("opc-retry-token").is_some(),
        "a create must carry an idempotency token"
    );

    let attach = writes
        .iter()
        .find(|write| write.method() == "PUT")
        .expect("the VNIC update");
    let nsg_ids = attach.json_body().expect("body")["nsgIds"]
        .as_array()
        .expect("array")
        .iter()
        .map(|value| value.as_str().unwrap_or_default().to_owned())
        .collect::<Vec<String>>();
    assert!(
        nsg_ids.contains(&other_nsg.to_owned()),
        "an NSG the user attached must be preserved, not replaced"
    );
    assert!(nsg_ids.contains(&MANAGED_NSG_ID.to_owned()));
}

/// The central write-safety property: no confirmation means no write at all.
#[tokio::test]
async fn an_unconfirmed_open_issues_no_write_request() {
    let mock = scenario(&[MANAGED_NSG_ID], json!([]), json!([]))
        .start()
        .await;

    let error = open(
        &context(&mock),
        "free-arm-1",
        https(),
        Some("198.51.100.7/32"),
        false,
    )
    .await
    .expect_err("a non-interactive run without --yes must refuse");

    assert!(error.remediation().contains("--yes"));
    assert!(
        mock.writes().is_empty(),
        "a refused plan must issue zero write requests, found {:?}",
        mock.writes()
    );
}

/// Nor may a non-interactive run silently choose a source.
#[tokio::test]
async fn a_missing_source_is_refused_rather_than_defaulted() {
    let mock = scenario(&[MANAGED_NSG_ID], json!([]), json!([]))
        .start()
        .await;

    let error = open(&context(&mock), "free-arm-1", https(), None, true)
        .await
        .expect_err("a missing source must refuse");
    assert!(error.remediation().contains("--source"));
    assert!(
        mock.writes().is_empty(),
        "no source means no write, found {:?}",
        mock.writes()
    );
}

#[tokio::test]
async fn an_invalid_source_is_refused_before_any_write() {
    let mock = scenario(&[MANAGED_NSG_ID], json!([]), json!([]))
        .start()
        .await;

    for source in ["not-an-ip", "10.0.0.7/24", "10.0.0.0/33"] {
        let error = open(&context(&mock), "free-arm-1", https(), Some(source), true)
            .await
            .expect_err("must refuse");
        assert!(!error.remediation().is_empty(), "{source} needs guidance");
    }
    assert!(mock.writes().is_empty());
}

#[tokio::test]
async fn opening_to_the_whole_internet_carries_a_warning() {
    let mock = scenario(&[MANAGED_NSG_ID], json!([]), json!([]))
        .reply("POST", "addSecurityRules", Reply::new(200, ""))
        .start()
        .await;

    let (plan, _) = open(
        &context(&mock),
        "free-arm-1",
        https(),
        Some("0.0.0.0/0"),
        true,
    )
    .await
    .expect("open succeeds");

    assert!(
        plan.warnings
            .iter()
            .any(|warning| warning.contains("every address on the internet"))
    );
    let body = mock.writes()[0].json_body().expect("body");
    assert_eq!(body["securityRules"][0]["source"], "0.0.0.0/0");
}

// -- close ------------------------------------------------------------------

#[tokio::test]
async fn close_removes_only_the_managed_rule() {
    let mock = MockOci::builder()
        .get(
            "/vnicAttachments",
            &json!([{
                "id": "ocid1.vnicattachment.oc1.iad.a",
                "instanceId": INSTANCE_ID,
                "vnicId": VNIC_ID,
                "lifecycleState": "ATTACHED"
            }]),
        )
        .get(&format!("/instances/{INSTANCE_ID}"), &instance_json())
        .get("/instances?", &json!([instance_json()]))
        .get(
            &format!("/vnics/{VNIC_ID}"),
            &vnic_json(&[MANAGED_NSG_ID], Some("203.0.113.17")),
        )
        .get(&format!("/subnets/{SUBNET_ID}"), &subnet_json())
        .route(
            "GET",
            &format!("/networkSecurityGroups/{MANAGED_NSG_ID}/securityRules"),
            vec![
                Reply::json(&json!([ssh_rule_json()])),
                Reply::json(&json!([])),
            ],
        )
        .get(
            &format!("/networkSecurityGroups/{MANAGED_NSG_ID}"),
            &managed_nsg_json(),
        )
        .get(
            &format!("/securityLists/{SECURITY_LIST_ID}"),
            &security_list_json(json!([])),
        )
        .get(
            &format!("/routeTables/{ROUTE_TABLE_ID}"),
            &route_table_json(),
        )
        .get(&format!("/internetGateways/{GATEWAY_ID}"), &gateway_json())
        .reply("POST", "removeSecurityRules", Reply::new(200, ""))
        .start()
        .await;

    let (_, change) = close(&context(&mock), "free-arm-1", ssh(), true)
        .await
        .expect("close succeeds");

    assert!(change.verified);
    assert!(change.residual_exposure.is_empty());

    let writes = mock.writes();
    assert_eq!(writes.len(), 1);
    assert!(writes[0].target().contains("removeSecurityRules"));
    assert_eq!(
        writes[0].json_body().expect("body")["securityRuleIds"][0],
        "SSHRULE"
    );
}

/// The rule the whole exposure model exists for: removing the instance rule
/// does not close a port a Security List still allows, and `close` must say so.
#[tokio::test]
async fn close_reports_residual_exposure_from_a_security_list() {
    let list_allows_ssh = json!([{
        "protocol": "6",
        "source": "0.0.0.0/0",
        "sourceType": "CIDR_BLOCK",
        "isStateless": false,
        "tcpOptions": { "destinationPortRange": { "min": 22, "max": 22 } }
    }]);
    let mock = MockOci::builder()
        .get(
            "/vnicAttachments",
            &json!([{
                "id": "ocid1.vnicattachment.oc1.iad.a",
                "instanceId": INSTANCE_ID,
                "vnicId": VNIC_ID,
                "lifecycleState": "ATTACHED"
            }]),
        )
        .get(&format!("/instances/{INSTANCE_ID}"), &instance_json())
        .get("/instances?", &json!([instance_json()]))
        .get(
            &format!("/vnics/{VNIC_ID}"),
            &vnic_json(&[MANAGED_NSG_ID], Some("203.0.113.17")),
        )
        .get(&format!("/subnets/{SUBNET_ID}"), &subnet_json())
        .route(
            "GET",
            &format!("/networkSecurityGroups/{MANAGED_NSG_ID}/securityRules"),
            vec![
                Reply::json(&json!([ssh_rule_json()])),
                Reply::json(&json!([])),
            ],
        )
        .get(
            &format!("/networkSecurityGroups/{MANAGED_NSG_ID}"),
            &managed_nsg_json(),
        )
        .get(
            &format!("/securityLists/{SECURITY_LIST_ID}"),
            &security_list_json(list_allows_ssh),
        )
        .get(
            &format!("/routeTables/{ROUTE_TABLE_ID}"),
            &route_table_json(),
        )
        .get(&format!("/internetGateways/{GATEWAY_ID}"), &gateway_json())
        .reply("POST", "removeSecurityRules", Reply::new(200, ""))
        .start()
        .await;

    let (plan, change) = close(&context(&mock), "free-arm-1", ssh(), true)
        .await
        .expect("close succeeds");

    assert!(
        plan.warnings
            .iter()
            .any(|warning| warning.contains("will remain reachable"))
    );
    assert_eq!(change.residual_exposure.len(), 1);
    assert!(change.residual_exposure[0].contains("security list"));
    assert!(
        change
            .warnings
            .iter()
            .any(|warning| warning.contains("does not close a port"))
    );
    assert!(render_change(&change).contains("still allowed by"));

    // Even with residual exposure, only the managed NSG was touched.
    for write in mock.writes() {
        assert!(
            !write.target().contains("securityLists"),
            "close must never edit a subnet Security List"
        );
    }
}

/// `close` on an instance oci-free does not manage must refuse, not reach for
/// somebody else's NSG.
#[tokio::test]
async fn close_refuses_when_there_is_no_managed_nsg() {
    let their_nsg = "ocid1.networksecuritygroup.oc1.iad.theirs";
    let mock = MockOci::builder()
        .get(
            "/vnicAttachments",
            &json!([{
                "id": "ocid1.vnicattachment.oc1.iad.a",
                "instanceId": INSTANCE_ID,
                "vnicId": VNIC_ID,
                "lifecycleState": "ATTACHED"
            }]),
        )
        .get(&format!("/instances/{INSTANCE_ID}"), &instance_json())
        .get("/instances?", &json!([instance_json()]))
        .get(
            &format!("/vnics/{VNIC_ID}"),
            &vnic_json(&[their_nsg], Some("203.0.113.17")),
        )
        .get(&format!("/subnets/{SUBNET_ID}"), &subnet_json())
        .get(
            &format!("/networkSecurityGroups/{their_nsg}/securityRules"),
            &json!([ssh_rule_json()]),
        )
        .get(
            &format!("/networkSecurityGroups/{their_nsg}"),
            &json!({
                "id": their_nsg,
                "vcnId": VCN_ID,
                "displayName": "their-nsg",
                "lifecycleState": "AVAILABLE"
            }),
        )
        .get(
            &format!("/securityLists/{SECURITY_LIST_ID}"),
            &security_list_json(json!([])),
        )
        .get(
            &format!("/routeTables/{ROUTE_TABLE_ID}"),
            &route_table_json(),
        )
        .get(&format!("/internetGateways/{GATEWAY_ID}"), &gateway_json())
        .start()
        .await;

    let error = close(&context(&mock), "free-arm-1", ssh(), true)
        .await
        .expect_err("must refuse");
    assert!(error.message().contains("no oci-free-managed"));
    assert!(
        error.context().expect("context").contains("never edits"),
        "the refusal must explain that oci-free will not touch an NSG it does not own"
    );
    assert!(mock.writes().is_empty());
}

// -- helpers ----------------------------------------------------------------

#[test]
fn a_source_of_zeroes_normalises_to_the_any_choice() {
    assert_eq!(
        SourceChoice::parse("0.0.0.0/0").expect("parses"),
        SourceChoice::AnyIpv4
    );
    assert!(
        SourceChoice::parse("0.0.0.0/0")
            .expect("parses")
            .warning()
            .is_some()
    );
    assert!(
        SourceChoice::parse("198.51.100.7/32")
            .expect("parses")
            .warning()
            .is_none()
    );
}

#[test]
fn a_bare_address_becomes_a_host_route() {
    let source = SourceChoice::parse("198.51.100.7").expect("parses");
    assert_eq!(source.as_oci_value(), "198.51.100.7/32");
}

#[test]
fn retry_tokens_are_stable_per_operation_and_distinct_across_them() {
    assert_eq!(
        retry_token("nsg", INSTANCE_ID),
        retry_token("nsg", INSTANCE_ID)
    );
    assert_ne!(
        retry_token("nsg", INSTANCE_ID),
        retry_token("vcn", INSTANCE_ID)
    );
    assert_ne!(retry_token("nsg", INSTANCE_ID), retry_token("nsg", "other"));
}

#[test]
fn managed_nsg_names_are_derived_safely_from_the_instance_label() {
    let mut instance: Instance = serde_json::from_value(instance_json()).expect("instance");
    assert_eq!(managed_nsg_name(&instance), "oci-free-free-arm-1");

    instance.display_name = Some("web server (prod)!".to_owned());
    let name = managed_nsg_name(&instance);
    assert!(
        name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
        "{name} must be safe for an OCI display name"
    );
}

#[test]
fn protocol_numbers_match_the_oci_wire_form() {
    assert_eq!(oci_protocol(Protocol::Tcp), "6");
    assert_eq!(oci_protocol(Protocol::Udp), "17");
}

/// An NSG created but not attached leaves an object the user did not have
/// before, so it is reported as a partial mutation naming the group — not as a
/// bare failure the user has to investigate.
#[tokio::test]
async fn an_nsg_created_but_not_attached_is_reported_as_a_partial_mutation() {
    let mock = MockOci::builder()
        .get(
            "/vnicAttachments",
            &json!([{
                "id": "ocid1.vnicattachment.oc1.iad.a",
                "instanceId": INSTANCE_ID,
                "vnicId": VNIC_ID,
                "lifecycleState": "ATTACHED"
            }]),
        )
        .get(&format!("/instances/{INSTANCE_ID}"), &instance_json())
        .get("/instances?", &json!([instance_json()]))
        .get(
            &format!("/vnics/{VNIC_ID}"),
            &vnic_json(&[], Some("203.0.113.17")),
        )
        .get(&format!("/subnets/{SUBNET_ID}"), &subnet_json())
        .get(
            &format!("/securityLists/{SECURITY_LIST_ID}"),
            &security_list_json(json!([])),
        )
        .get(
            &format!("/routeTables/{ROUTE_TABLE_ID}"),
            &route_table_json(),
        )
        .get(&format!("/internetGateways/{GATEWAY_ID}"), &gateway_json())
        .reply(
            "POST",
            "/networkSecurityGroups",
            Reply::json(&managed_nsg_json()),
        )
        // The VNIC update is what fails.
        .reply(
            "PUT",
            &format!("/vnics/{VNIC_ID}"),
            Reply::new(409, r#"{"code":"Conflict","message":"vnic is updating"}"#)
                .header("opc-request-id", "req-11"),
        )
        .start()
        .await;

    let error = open(
        &context(&mock),
        "free-arm-1",
        https(),
        Some("198.51.100.7/32"),
        true,
    )
    .await
    .expect_err("the attachment fails");

    assert_eq!(error.kind(), crate::error::ErrorKind::PartialMutation);
    assert_eq!(error.exit_code_kind().code(), 7);
    assert!(error.context().expect("context").contains(MANAGED_NSG_ID));
    assert!(
        error.remediation().contains("idempotency token"),
        "the user must be told that re-running reuses the group"
    );
    assert!(
        !mock
            .writes()
            .iter()
            .any(|write| write.target().contains("addSecurityRules")),
        "no rule may be added to an NSG that is not attached"
    );
}

/// OCI cannot subtract one port from a range, so closing 22 on a rule covering
/// 1-1024 closes the rest of it too. That consequence must be stated, not left
/// for the user to infer from the rule summary.
#[tokio::test]
async fn closing_a_port_inside_a_wider_rule_warns_that_the_whole_range_goes() {
    let wide_rule = json!({
        "id": "WIDERULE",
        "direction": "INGRESS",
        "protocol": "6",
        "source": "0.0.0.0/0",
        "sourceType": "CIDR_BLOCK",
        "isStateless": false,
        "tcpOptions": { "destinationPortRange": { "min": 1, "max": 1024 } }
    });
    let mock = MockOci::builder()
        .get(
            "/vnicAttachments",
            &json!([{
                "id": "ocid1.vnicattachment.oc1.iad.a",
                "instanceId": INSTANCE_ID,
                "vnicId": VNIC_ID,
                "lifecycleState": "ATTACHED"
            }]),
        )
        .get(&format!("/instances/{INSTANCE_ID}"), &instance_json())
        .get("/instances?", &json!([instance_json()]))
        .get(
            &format!("/vnics/{VNIC_ID}"),
            &vnic_json(&[MANAGED_NSG_ID], Some("203.0.113.17")),
        )
        .get(&format!("/subnets/{SUBNET_ID}"), &subnet_json())
        .route(
            "GET",
            &format!("/networkSecurityGroups/{MANAGED_NSG_ID}/securityRules"),
            vec![Reply::json(&json!([wide_rule])), Reply::json(&json!([]))],
        )
        .get(
            &format!("/networkSecurityGroups/{MANAGED_NSG_ID}"),
            &managed_nsg_json(),
        )
        .get(
            &format!("/securityLists/{SECURITY_LIST_ID}"),
            &security_list_json(json!([])),
        )
        .get(
            &format!("/routeTables/{ROUTE_TABLE_ID}"),
            &route_table_json(),
        )
        .get(&format!("/internetGateways/{GATEWAY_ID}"), &gateway_json())
        .reply("POST", "removeSecurityRules", Reply::new(200, ""))
        .start()
        .await;

    let (plan, _) = close(&context(&mock), "free-arm-1", ssh(), true)
        .await
        .expect("close succeeds");

    assert!(
        plan.warnings
            .iter()
            .any(|warning| warning.contains("also closes the rest of that range")),
        "the plan must say the whole range goes: {:?}",
        plan.warnings
    );
    assert!(
        plan.warnings
            .iter()
            .any(|warning| warning.contains("1-1024")),
        "the warning must name the range: {:?}",
        plan.warnings
    );
}

/// A rule that covers exactly the port asked about needs no such warning.
#[tokio::test]
async fn closing_an_exact_rule_carries_no_range_warning() {
    let mock = MockOci::builder()
        .get(
            "/vnicAttachments",
            &json!([{
                "id": "ocid1.vnicattachment.oc1.iad.a",
                "instanceId": INSTANCE_ID,
                "vnicId": VNIC_ID,
                "lifecycleState": "ATTACHED"
            }]),
        )
        .get(&format!("/instances/{INSTANCE_ID}"), &instance_json())
        .get("/instances?", &json!([instance_json()]))
        .get(
            &format!("/vnics/{VNIC_ID}"),
            &vnic_json(&[MANAGED_NSG_ID], Some("203.0.113.17")),
        )
        .get(&format!("/subnets/{SUBNET_ID}"), &subnet_json())
        .route(
            "GET",
            &format!("/networkSecurityGroups/{MANAGED_NSG_ID}/securityRules"),
            vec![
                Reply::json(&json!([ssh_rule_json()])),
                Reply::json(&json!([])),
            ],
        )
        .get(
            &format!("/networkSecurityGroups/{MANAGED_NSG_ID}"),
            &managed_nsg_json(),
        )
        .get(
            &format!("/securityLists/{SECURITY_LIST_ID}"),
            &security_list_json(json!([])),
        )
        .get(
            &format!("/routeTables/{ROUTE_TABLE_ID}"),
            &route_table_json(),
        )
        .get(&format!("/internetGateways/{GATEWAY_ID}"), &gateway_json())
        .reply("POST", "removeSecurityRules", Reply::new(200, ""))
        .start()
        .await;

    let (plan, _) = close(&context(&mock), "free-arm-1", ssh(), true)
        .await
        .expect("close succeeds");

    assert!(
        !plan
            .warnings
            .iter()
            .any(|warning| warning.contains("rest of that range")),
        "an exact rule needs no range warning: {:?}",
        plan.warnings
    );
}
