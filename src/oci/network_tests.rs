//! Fixture tests for the virtual-network response models.
//!
//! Every model the exposure calculation depends on is decoded from a
//! representative OCI response here, so a change to a field name is caught
//! before it becomes a wrong exposure verdict.

use super::*;

const VNIC: &str = include_str!("../../tests/fixtures/oci/vnic.json");
const VNIC_NO_PUBLIC: &str = include_str!("../../tests/fixtures/oci/vnic_no_public_ip.json");
const SUBNET: &str = include_str!("../../tests/fixtures/oci/subnet.json");
const VCN: &str = include_str!("../../tests/fixtures/oci/vcn.json");
const NSG: &str = include_str!("../../tests/fixtures/oci/nsg.json");
const NSG_RULES: &str = include_str!("../../tests/fixtures/oci/nsg_rules.json");
const SECURITY_LIST: &str = include_str!("../../tests/fixtures/oci/security_list.json");
const ROUTE_TABLE: &str = include_str!("../../tests/fixtures/oci/route_table.json");
const INTERNET_GATEWAY: &str = include_str!("../../tests/fixtures/oci/internet_gateway.json");

#[test]
fn decodes_a_vnic_with_its_nsgs_and_public_ip() {
    let vnic: Vnic = serde_json::from_str(VNIC).expect("vnic fixture");
    assert_eq!(vnic.private_ip.as_deref(), Some("10.0.0.42"));
    assert_eq!(vnic.public_ip.as_deref(), Some("203.0.113.17"));
    assert!(vnic.has_public_ip());
    assert_eq!(vnic.is_primary, Some(true));
    assert_eq!(vnic.nsg_ids.len(), 1);
    assert!(vnic.subnet_id.is_some());
}

/// A VNIC with no public address is an ordinary, expected state. Reading it as
/// a decoding failure would make `vm ip` report a malformed OCI response.
#[test]
fn a_vnic_without_a_public_ip_decodes_cleanly() {
    let vnic: Vnic = serde_json::from_str(VNIC_NO_PUBLIC).expect("vnic fixture");
    assert!(vnic.public_ip.is_none());
    assert!(!vnic.has_public_ip());
    assert!(vnic.nsg_ids.is_empty());
}

/// An empty string is not a usable address either.
#[test]
fn a_blank_public_ip_does_not_count_as_public() {
    let vnic: Vnic =
        serde_json::from_str(r#"{"id":"ocid1.vnic.oc1.iad.a","publicIp":"  "}"#).expect("vnic");
    assert!(!vnic.has_public_ip());
}

#[test]
fn decodes_a_subnet() {
    let subnet: Subnet = serde_json::from_str(SUBNET).expect("subnet fixture");
    assert_eq!(subnet.cidr_block.as_deref(), Some("10.0.0.0/24"));
    assert_eq!(subnet.security_list_ids.len(), 1);
    assert!(subnet.route_table_id.is_some());
    assert!(!subnet.is_private());
    assert!(subnet.is_regional(), "the fixture is a regional subnet");
}

#[test]
fn decodes_a_private_subnet() {
    let subnet: Subnet = serde_json::from_str(
        r#"{"id":"ocid1.subnet.oc1.iad.a","vcnId":"ocid1.vcn.oc1.iad.b","prohibitPublicIpOnVnic":true}"#,
    )
    .expect("subnet");
    assert!(subnet.is_private());
}

#[test]
fn decodes_a_vcn() {
    let vcn: Vcn = serde_json::from_str(VCN).expect("vcn fixture");
    assert_eq!(vcn.cidr_block.as_deref(), Some("10.0.0.0/16"));
    assert_eq!(
        vcn.default_route_table_id.as_deref(),
        Some("ocid1.routetable.oc1.iad.aaaaaaaaexamplert1")
    );
    assert_eq!(
        vcn.freeform_tags
            .get("oci-free:managed")
            .map(String::as_str),
        Some("1")
    );
}

#[test]
fn decodes_an_nsg_with_ownership_tags() {
    let nsg: NetworkSecurityGroup = serde_json::from_str(NSG).expect("nsg fixture");
    assert_eq!(
        nsg.vcn_id.as_deref(),
        Some("ocid1.vcn.oc1.iad.aaaaaaaaexamplevcn1")
    );
    assert_eq!(
        nsg.freeform_tags.get("oci-free:role").map(String::as_str),
        Some("instance-nsg")
    );
}

#[test]
fn decodes_nsg_security_rules() {
    let rules: Vec<SecurityRule> = serde_json::from_str(NSG_RULES).expect("rules fixture");
    assert_eq!(rules.len(), 4);

    let ssh = &rules[0];
    assert!(ssh.is_ingress());
    assert_eq!(ssh.protocol, "6");
    assert_eq!(ssh.source.as_deref(), Some("198.51.100.7/32"));
    assert_eq!(ssh.id.as_deref(), Some("3E9A1B"));
    let ports = ssh
        .tcp_options
        .and_then(|options| options.destination_port_range)
        .expect("port range");
    assert_eq!(ports.min, Some(22));
    assert_eq!(ports.max, Some(22));

    assert!(!rules[2].is_ingress(), "the third rule is egress");
    assert_eq!(rules[3].icmp_options.expect("icmp").icmp_type, 3);
}

#[test]
fn decodes_a_security_list() {
    let list: SecurityList = serde_json::from_str(SECURITY_LIST).expect("security list fixture");
    assert_eq!(list.ingress_security_rules.len(), 2);
    let ssh = &list.ingress_security_rules[0];
    assert_eq!(ssh.source.as_deref(), Some("0.0.0.0/0"));
    assert_eq!(
        ssh.tcp_options
            .and_then(|options| options.destination_port_range)
            .and_then(|range| range.max),
        Some(22)
    );
}

#[test]
fn decodes_a_route_table_with_a_default_route() {
    let table: RouteTable = serde_json::from_str(ROUTE_TABLE).expect("route table fixture");
    assert_eq!(table.route_rules.len(), 1);
    assert!(table.route_rules[0].is_default_ipv4());
    assert!(
        table.route_rules[0]
            .network_entity_id
            .as_deref()
            .expect("entity")
            .contains("internetgateway")
    );
}

#[test]
fn decodes_an_internet_gateway() {
    let gateway: InternetGateway = serde_json::from_str(INTERNET_GATEWAY).expect("gateway fixture");
    assert!(gateway.is_usable());
}

/// A disabled gateway must not be read as usable: a route pointing at it does
/// not make the instance reachable.
#[test]
fn a_disabled_gateway_is_not_usable() {
    let gateway: InternetGateway = serde_json::from_str(
        r#"{"id":"ocid1.internetgateway.oc1.iad.a","isEnabled":false,"lifecycleState":"AVAILABLE"}"#,
    )
    .expect("gateway");
    assert!(!gateway.is_usable());

    let terminated: InternetGateway = serde_json::from_str(
        r#"{"id":"ocid1.internetgateway.oc1.iad.a","isEnabled":true,"lifecycleState":"TERMINATED"}"#,
    )
    .expect("gateway");
    assert!(!terminated.is_usable());
}

#[test]
fn port_ranges_treat_an_absent_bound_as_unbounded() {
    let open_top = PortRange {
        min: Some(1024),
        max: None,
    };
    assert!(open_top.contains(65535));
    assert!(!open_top.contains(80));

    let open_bottom = PortRange {
        min: None,
        max: Some(1024),
    };
    assert!(open_bottom.contains(1));
    assert!(!open_bottom.contains(1025));

    let unbounded = PortRange {
        min: None,
        max: None,
    };
    assert!(unbounded.contains(22));

    assert!(PortRange::exactly(443).contains(443));
    assert!(!PortRange::exactly(443).contains(444));
}

/// The rule bodies sent to OCI must use the documented camelCase field names,
/// and must omit anything not set rather than sending nulls.
#[test]
fn add_rule_bodies_serialize_to_the_documented_shape() {
    let rule = AddSecurityRule {
        direction: "INGRESS".to_owned(),
        protocol: "6".to_owned(),
        source: Some("0.0.0.0/0".to_owned()),
        source_type: Some("CIDR_BLOCK".to_owned()),
        destination: None,
        destination_type: None,
        is_stateless: false,
        tcp_options: Some(TransportOptions {
            destination_port_range: Some(PortRange::exactly(443)),
            source_port_range: None,
        }),
        udp_options: None,
        description: Some("oci-free managed".to_owned()),
    };

    let value = serde_json::to_value(&rule).expect("serialize");
    assert_eq!(value["direction"], "INGRESS");
    assert_eq!(value["protocol"], "6");
    assert_eq!(value["sourceType"], "CIDR_BLOCK");
    assert_eq!(value["isStateless"], false);
    assert_eq!(value["tcpOptions"]["destinationPortRange"]["min"], 443);
    assert!(
        value.get("destination").is_none(),
        "unset fields must be omitted, not sent as null"
    );
    assert!(value.get("udpOptions").is_none());
}

#[test]
fn vnic_updates_send_only_the_nsg_list() {
    let value = serde_json::to_value(UpdateVnic {
        nsg_ids: vec!["ocid1.networksecuritygroup.oc1.iad.a".to_owned()],
    })
    .expect("serialize");
    assert_eq!(value["nsgIds"][0], "ocid1.networksecuritygroup.oc1.iad.a");
    assert_eq!(value.as_object().expect("object").len(), 1);
}

/// OCI keeps adding fields; decoding must tolerate them everywhere.
#[test]
fn unknown_fields_are_ignored_across_the_network_models() {
    let vnic: Vnic =
        serde_json::from_str(r#"{"id":"ocid1.vnic.oc1.iad.a","brandNew":{"x":1}}"#).expect("vnic");
    assert_eq!(vnic.id, "ocid1.vnic.oc1.iad.a");

    let table: RouteTable = serde_json::from_str(
        r#"{"id":"ocid1.routetable.oc1.iad.a","routeRules":[{"destination":"0.0.0.0/0","future":1}]}"#,
    )
    .expect("route table");
    assert!(table.route_rules[0].is_default_ipv4());
}
