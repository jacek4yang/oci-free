//! Effective-exposure tests.
//!
//! The properties proved here are the ones a wrong answer would be dangerous
//! for: composition across NSGs and Security Lists, provenance on every rule,
//! and the reachability chain being evaluated link by link.

use super::*;
use crate::{
    domain::ownership::{MANAGED_CREATED, TAG_MANAGED},
    oci::network::{PortRange, RouteRule, TransportOptions},
};

fn tags(pairs: &[(&str, &str)]) -> Tags {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn tcp(port: u16) -> Option<TransportOptions> {
    Some(TransportOptions {
        destination_port_range: Some(PortRange::exactly(port)),
        source_port_range: None,
    })
}

fn tcp_range(min: u16, max: u16) -> Option<TransportOptions> {
    Some(TransportOptions {
        destination_port_range: Some(PortRange {
            min: Some(min),
            max: Some(max),
        }),
        source_port_range: None,
    })
}

fn nsg_rule(protocol: &str, source: &str, options: Option<TransportOptions>) -> SecurityRule {
    SecurityRule {
        id: Some(format!("rule-{protocol}-{source}")),
        direction: "INGRESS".to_owned(),
        protocol: protocol.to_owned(),
        source: Some(source.to_owned()),
        source_type: Some("CIDR_BLOCK".to_owned()),
        destination: None,
        destination_type: None,
        is_stateless: Some(false),
        tcp_options: options,
        udp_options: None,
        icmp_options: None,
        description: None,
    }
}

fn list_rule(
    protocol: &str,
    source: &str,
    options: Option<TransportOptions>,
) -> IngressSecurityRule {
    IngressSecurityRule {
        protocol: protocol.to_owned(),
        source: Some(source.to_owned()),
        source_type: Some("CIDR_BLOCK".to_owned()),
        is_stateless: Some(false),
        tcp_options: options,
        udp_options: None,
        icmp_options: None,
        description: None,
    }
}

fn managed_nsg(rules: Vec<SecurityRule>) -> (NetworkSecurityGroup, Vec<SecurityRule>) {
    (
        NetworkSecurityGroup {
            id: "ocid1.networksecuritygroup.oc1.iad.managed".to_owned(),
            compartment_id: None,
            vcn_id: Some("ocid1.vcn.oc1.iad.v".to_owned()),
            display_name: Some("oci-free-web-1".to_owned()),
            lifecycle_state: Some("AVAILABLE".to_owned()),
            freeform_tags: tags(&[(TAG_MANAGED, MANAGED_CREATED)]),
        },
        rules,
    )
}

fn security_list(rules: Vec<IngressSecurityRule>) -> SecurityList {
    SecurityList {
        id: "ocid1.securitylist.oc1.iad.default".to_owned(),
        vcn_id: Some("ocid1.vcn.oc1.iad.v".to_owned()),
        compartment_id: None,
        display_name: Some("Default Security List".to_owned()),
        ingress_security_rules: rules,
        lifecycle_state: Some("AVAILABLE".to_owned()),
        freeform_tags: Tags::new(),
    }
}

fn vnic(public_ip: Option<&str>) -> Vnic {
    Vnic {
        id: "ocid1.vnic.oc1.iad.v".to_owned(),
        compartment_id: None,
        display_name: None,
        subnet_id: Some("ocid1.subnet.oc1.iad.s".to_owned()),
        private_ip: Some("10.0.0.42".to_owned()),
        public_ip: public_ip.map(str::to_owned),
        is_primary: Some(true),
        nsg_ids: Vec::new(),
        hostname_label: None,
        availability_domain: None,
        lifecycle_state: Some("AVAILABLE".to_owned()),
        freeform_tags: Tags::new(),
    }
}

fn subnet() -> Subnet {
    Subnet {
        id: "ocid1.subnet.oc1.iad.s".to_owned(),
        vcn_id: "ocid1.vcn.oc1.iad.v".to_owned(),
        compartment_id: None,
        display_name: Some("oci-free-public".to_owned()),
        cidr_block: Some("10.0.0.0/24".to_owned()),
        route_table_id: Some("ocid1.routetable.oc1.iad.r".to_owned()),
        security_list_ids: vec!["ocid1.securitylist.oc1.iad.default".to_owned()],
        prohibit_public_ip_on_vnic: Some(false),
        prohibit_internet_ingress: Some(false),
        availability_domain: None,
        lifecycle_state: Some("AVAILABLE".to_owned()),
        freeform_tags: Tags::new(),
    }
}

fn route_table(entity: Option<&str>) -> RouteTable {
    RouteTable {
        id: "ocid1.routetable.oc1.iad.r".to_owned(),
        vcn_id: Some("ocid1.vcn.oc1.iad.v".to_owned()),
        compartment_id: None,
        display_name: Some("default".to_owned()),
        route_rules: entity
            .map(|entity| {
                vec![RouteRule {
                    destination: Some("0.0.0.0/0".to_owned()),
                    destination_type: Some("CIDR_BLOCK".to_owned()),
                    network_entity_id: Some(entity.to_owned()),
                    description: None,
                }]
            })
            .unwrap_or_default(),
        lifecycle_state: Some("AVAILABLE".to_owned()),
        freeform_tags: Tags::new(),
    }
}

fn gateway(enabled: bool) -> InternetGateway {
    InternetGateway {
        id: "ocid1.internetgateway.oc1.iad.g".to_owned(),
        vcn_id: Some("ocid1.vcn.oc1.iad.v".to_owned()),
        compartment_id: None,
        display_name: Some("oci-free-igw".to_owned()),
        is_enabled: Some(enabled),
        lifecycle_state: Some("AVAILABLE".to_owned()),
        freeform_tags: Tags::new(),
    }
}

struct Scenario {
    vnic: Vnic,
    subnet: Subnet,
    nsgs: Vec<(NetworkSecurityGroup, Vec<SecurityRule>)>,
    lists: Vec<SecurityList>,
    route_table: Option<RouteTable>,
    gateway: Option<InternetGateway>,
}

impl Scenario {
    fn public() -> Self {
        Self {
            vnic: vnic(Some("203.0.113.17")),
            subnet: subnet(),
            nsgs: Vec::new(),
            lists: Vec::new(),
            route_table: Some(route_table(Some("ocid1.internetgateway.oc1.iad.g"))),
            gateway: Some(gateway(true)),
        }
    }

    fn compute(&self) -> EffectiveExposure {
        super::compute(&ExposureInputs {
            vnic: &self.vnic,
            subnet: &self.subnet,
            nsgs: &self.nsgs,
            security_lists: &self.lists,
            route_table: self.route_table.as_ref(),
            internet_gateway: self.gateway.as_ref(),
        })
    }
}

fn ssh() -> PortRule {
    "22/tcp".parse().expect("rule")
}

fn https() -> PortRule {
    "443/tcp".parse().expect("rule")
}

/// The property that makes `vm net close` honest: an NSG with no rule for a
/// port does not mean the port is closed, because a Security List may still
/// allow it.
#[test]
fn an_absent_nsg_rule_does_not_mean_the_port_is_closed() {
    let mut scenario = Scenario::public();
    // The instance NSG allows only 443.
    scenario.nsgs = vec![managed_nsg(vec![nsg_rule("6", "0.0.0.0/0", tcp(443))])];
    // The subnet Security List still allows 22 for everything in the subnet.
    scenario.lists = vec![security_list(vec![list_rule("6", "0.0.0.0/0", tcp(22))])];

    let exposure = scenario.compute();

    assert!(
        exposure.allows(ssh()),
        "port 22 is still reachable through the subnet Security List"
    );
    let responsible = exposure.allowing(ssh());
    assert_eq!(responsible.len(), 1);
    assert_eq!(responsible[0].origin.kind, OriginKind::SecurityList);
    assert!(!responsible[0].origin.kind.is_instance_scoped());
}

/// After removing the managed NSG rule, `close` must still report what is left.
#[test]
fn residual_exposure_outside_the_managed_nsg_is_reported() {
    let mut scenario = Scenario::public();
    scenario.nsgs = vec![managed_nsg(vec![nsg_rule("6", "0.0.0.0/0", tcp(22))])];
    scenario.lists = vec![security_list(vec![list_rule("6", "0.0.0.0/0", tcp(22))])];

    let exposure = scenario.compute();
    let managed = exposure.managed_nsg().expect("a managed NSG").id.clone();

    let residual = exposure.allowing_outside(ssh(), &managed);
    assert_eq!(residual.len(), 1);
    assert_eq!(residual[0].origin.kind, OriginKind::SecurityList);
    assert!(residual[0].summary().contains("security list"));
}

/// Every effective rule must name the object responsible for it.
#[test]
fn every_rule_carries_its_provenance() {
    let mut scenario = Scenario::public();
    scenario.nsgs = vec![managed_nsg(vec![nsg_rule("6", "198.51.100.7/32", tcp(22))])];
    scenario.lists = vec![security_list(vec![list_rule("6", "0.0.0.0/0", tcp(443))])];

    let exposure = scenario.compute();
    assert_eq!(exposure.rules.len(), 2);
    for rule in &exposure.rules {
        assert!(!rule.origin.id.is_empty());
        assert!(!rule.origin.label().is_empty());
    }

    let nsg_sourced = exposure
        .rules
        .iter()
        .find(|rule| rule.origin.kind == OriginKind::NetworkSecurityGroup)
        .expect("an NSG rule");
    assert_eq!(nsg_sourced.origin.ownership, Ownership::Created);
    assert_eq!(
        nsg_sourced.rule_id.as_deref(),
        Some("rule-6-198.51.100.7/32")
    );

    let list_sourced = exposure
        .rules
        .iter()
        .find(|rule| rule.origin.kind == OriginKind::SecurityList)
        .expect("a security list rule");
    assert!(
        list_sourced.rule_id.is_none(),
        "OCI does not identify Security List rules individually"
    );
    assert_eq!(list_sourced.origin.ownership, Ownership::UserOwned);
}

/// A rule with no port options covers everything, and reading it as "no ports"
/// would report an open instance as closed.
#[test]
fn a_rule_with_no_port_options_covers_every_port() {
    let mut scenario = Scenario::public();
    scenario.nsgs = vec![managed_nsg(vec![nsg_rule("6", "0.0.0.0/0", None)])];

    let exposure = scenario.compute();
    assert!(exposure.allows(ssh()));
    assert!(exposure.allows(https()));
    assert_eq!(exposure.rules[0].ports, PortSpan::All);
    assert!(exposure.rules[0].ports.is_everything());
}

#[test]
fn a_wildcard_protocol_rule_covers_tcp_and_udp() {
    let mut scenario = Scenario::public();
    scenario.nsgs = vec![managed_nsg(vec![nsg_rule("all", "0.0.0.0/0", None)])];

    let exposure = scenario.compute();
    assert!(exposure.allows(ssh()));
    assert!(exposure.allows("53/udp".parse().expect("rule")));
}

/// An ICMP rule must never answer a TCP question.
#[test]
fn icmp_rules_do_not_open_tcp_ports() {
    let mut scenario = Scenario::public();
    scenario.nsgs = vec![managed_nsg(vec![nsg_rule("1", "0.0.0.0/0", None)])];

    let exposure = scenario.compute();
    assert!(!exposure.allows(ssh()));
    assert_eq!(exposure.rules[0].protocol, RuleProtocol::Icmp);
}

#[test]
fn port_ranges_are_matched_inclusively() {
    let mut scenario = Scenario::public();
    scenario.nsgs = vec![managed_nsg(vec![nsg_rule(
        "6",
        "0.0.0.0/0",
        tcp_range(8000, 8100),
    )])];

    let exposure = scenario.compute();
    assert!(exposure.allows("8000/tcp".parse().expect("rule")));
    assert!(exposure.allows("8100/tcp".parse().expect("rule")));
    assert!(!exposure.allows("8101/tcp".parse().expect("rule")));
    assert_eq!(exposure.rules[0].ports.width(), 101);
}

// -- reachability -----------------------------------------------------------

#[test]
fn an_instance_with_a_public_ip_route_and_gateway_is_reachable() {
    let exposure = Scenario::public().compute();
    assert!(exposure.internet.reachable);
    assert!(exposure.internet.has_default_route);
    assert!(exposure.internet.internet_gateway_enabled);
    assert_eq!(exposure.internet.public_ip.as_deref(), Some("203.0.113.17"));
}

/// Each link in the chain is evaluated separately so the reason names the one
/// that is missing.
#[test]
fn each_missing_link_in_the_reachability_chain_is_named() {
    let mut no_ip = Scenario::public();
    no_ip.vnic = vnic(None);
    let exposure = no_ip.compute();
    assert!(!exposure.internet.reachable);
    assert!(exposure.internet.reason.contains("no public IP"));

    let mut no_route = Scenario::public();
    no_route.route_table = Some(route_table(None));
    let exposure = no_route.compute();
    assert!(!exposure.internet.reachable);
    assert!(exposure.internet.reason.contains("0.0.0.0/0"));

    let mut disabled = Scenario::public();
    disabled.gateway = Some(gateway(false));
    let exposure = disabled.compute();
    assert!(!exposure.internet.reachable);
    assert!(exposure.internet.reason.contains("not enabled"));
}

/// A rule allowing the world means nothing if nothing can reach the instance,
/// and the model must say so rather than reporting the rule as internet-facing.
#[test]
fn an_unreachable_instance_has_no_internet_facing_rules() {
    let mut scenario = Scenario::public();
    scenario.vnic = vnic(None);
    scenario.nsgs = vec![managed_nsg(vec![nsg_rule("6", "0.0.0.0/0", tcp(22))])];

    let exposure = scenario.compute();
    assert!(exposure.allows(ssh()), "the rule still exists");
    assert!(
        exposure.internet_facing_rules().is_empty(),
        "but nothing on the internet can use it"
    );
}

/// An unreadable route table must degrade to a warning, not a confident answer.
#[test]
fn a_missing_route_table_produces_a_warning() {
    let mut scenario = Scenario::public();
    scenario.route_table = None;
    scenario.gateway = None;

    let exposure = scenario.compute();
    assert!(!exposure.internet.reachable);
    assert!(
        exposure
            .warnings
            .iter()
            .any(|warning| warning.contains("route table"))
    );
}

#[test]
fn an_instance_with_no_nsg_is_warned_about_inherited_rules() {
    let mut scenario = Scenario::public();
    scenario.lists = vec![security_list(vec![list_rule("6", "0.0.0.0/0", tcp(22))])];

    let exposure = scenario.compute();
    assert!(exposure.attached_nsgs.is_empty());
    assert!(
        exposure
            .warnings
            .iter()
            .any(|warning| warning.contains("Security Lists"))
    );
}

/// A source that is not a CIDR (another NSG, or a service range) is reported
/// rather than silently dropped.
#[test]
fn non_cidr_sources_are_surfaced_as_warnings() {
    let mut rule = nsg_rule("6", "ocid1.networksecuritygroup.oc1.iad.other", tcp(22));
    rule.source_type = Some("NETWORK_SECURITY_GROUP".to_owned());
    let mut scenario = Scenario::public();
    scenario.nsgs = vec![managed_nsg(vec![rule])];

    let exposure = scenario.compute();
    assert!(exposure.rules[0].source_cidr.is_none());
    assert!(!exposure.rules[0].is_open_to_the_internet());
    assert!(
        exposure
            .warnings
            .iter()
            .any(|warning| warning.contains("cannot resolve"))
    );
}

#[test]
fn private_sources_are_distinguished_from_public_ones() {
    let mut scenario = Scenario::public();
    scenario.nsgs = vec![managed_nsg(vec![
        nsg_rule("6", "10.0.0.0/16", tcp(22)),
        nsg_rule("6", "0.0.0.0/0", tcp(443)),
    ])];

    let exposure = scenario.compute();
    let private = &exposure.rules[0];
    assert!(private.is_private_source());
    assert!(!private.is_open_to_the_internet());

    let public = &exposure.rules[1];
    assert!(public.is_open_to_the_internet());
    assert!(public.is_broad());
    assert_eq!(exposure.internet_facing_rules().len(), 1);
}

#[test]
fn egress_rules_are_not_counted_as_ingress() {
    let mut egress = nsg_rule("6", "0.0.0.0/0", tcp(22));
    egress.direction = "EGRESS".to_owned();
    let mut scenario = Scenario::public();
    scenario.nsgs = vec![managed_nsg(vec![egress])];

    let exposure = scenario.compute();
    assert!(exposure.rules.is_empty());
    assert!(!exposure.allows(ssh()));
    assert_eq!(exposure.attached_nsgs[0].ingress_rule_count, 0);
}

#[test]
fn protocol_values_round_trip_to_oci_wire_form() {
    assert_eq!(RuleProtocol::parse("6"), RuleProtocol::Tcp);
    assert_eq!(RuleProtocol::parse("17"), RuleProtocol::Udp);
    assert_eq!(RuleProtocol::parse("1"), RuleProtocol::Icmp);
    assert_eq!(RuleProtocol::parse("58"), RuleProtocol::IcmpV6);
    assert_eq!(RuleProtocol::parse("ALL"), RuleProtocol::All);
    assert_eq!(
        RuleProtocol::parse("132"),
        RuleProtocol::Other("132".to_owned())
    );

    for protocol in [
        RuleProtocol::Tcp,
        RuleProtocol::Udp,
        RuleProtocol::Icmp,
        RuleProtocol::IcmpV6,
        RuleProtocol::All,
    ] {
        assert_eq!(RuleProtocol::parse(protocol.as_oci_value()), protocol);
    }
}
