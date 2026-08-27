//! Effective inbound reachability.
//!
//! OCI composes ingress from two independent sources, and both are permissive:
//! a Network Security Group attached to the VNIC, and a Security List attached
//! to the subnet. Traffic is allowed if **either** permits it. That is the
//! single most misunderstood part of OCI networking and the reason this module
//! exists.
//!
//! Two consequences shape the design:
//!
//! * "the instance has no NSG rule for port 22" does **not** mean port 22 is
//!   closed. A subnet Security List may still allow it, so every answer carries
//!   the OCI object responsible for it — see [`RuleOrigin`];
//! * a rule that allows traffic is only meaningful if packets can arrive at
//!   all. [`InternetReachability`] tracks the public IP, the default route, and
//!   the internet gateway's enabled state separately, so a warning can say
//!   which link in that chain is missing.
//!
//! Nothing here scores or ranks risk numerically. Each finding names a concrete
//! condition, the object that causes it, and what to do about it.

use std::fmt;

use serde::Serialize;

use crate::{
    domain::{
        cidr::Cidr,
        network::{PortRule, Protocol},
        ownership::{Ownership, Tags, classify},
    },
    oci::network::{
        IngressSecurityRule, InternetGateway, NetworkSecurityGroup, RouteTable, SecurityList,
        SecurityRule, Subnet, TransportOptions, Vnic,
    },
};

/// IANA protocol number OCI uses for TCP.
const PROTOCOL_TCP: &str = "6";
/// IANA protocol number OCI uses for UDP.
const PROTOCOL_UDP: &str = "17";
/// IANA protocol number OCI uses for ICMP.
const PROTOCOL_ICMP: &str = "1";
/// IANA protocol number OCI uses for ICMPv6.
const PROTOCOL_ICMPV6: &str = "58";
/// OCI's wildcard protocol.
const PROTOCOL_ALL: &str = "all";

/// What a rule's `protocol` field means.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum RuleProtocol {
    /// Every protocol. Matches anything.
    All,
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
    /// An IANA number this build has no name for. Preserved rather than
    /// discarded, so an audit can still report it.
    Other(String),
}

impl RuleProtocol {
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            PROTOCOL_ALL => Self::All,
            PROTOCOL_TCP => Self::Tcp,
            PROTOCOL_UDP => Self::Udp,
            PROTOCOL_ICMP => Self::Icmp,
            PROTOCOL_ICMPV6 => Self::IcmpV6,
            other => Self::Other(other.to_owned()),
        }
    }

    /// The wire value OCI expects for this protocol.
    #[must_use]
    pub fn as_oci_value(&self) -> &str {
        match self {
            Self::All => PROTOCOL_ALL,
            Self::Tcp => PROTOCOL_TCP,
            Self::Udp => PROTOCOL_UDP,
            Self::Icmp => PROTOCOL_ICMP,
            Self::IcmpV6 => PROTOCOL_ICMPV6,
            Self::Other(value) => value,
        }
    }

    /// Whether this rule protocol covers the transport protocol asked about.
    #[must_use]
    pub fn covers(&self, wanted: Protocol) -> bool {
        match self {
            Self::All => true,
            Self::Tcp => wanted == Protocol::Tcp,
            Self::Udp => wanted == Protocol::Udp,
            Self::Icmp | Self::IcmpV6 | Self::Other(_) => false,
        }
    }
}

impl fmt::Display for RuleProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => f.write_str("all"),
            Self::Tcp => f.write_str("tcp"),
            Self::Udp => f.write_str("udp"),
            Self::Icmp => f.write_str("icmp"),
            Self::IcmpV6 => f.write_str("icmpv6"),
            Self::Other(value) => write!(f, "ip-protocol-{value}"),
        }
    }
}

/// The destination ports a rule covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PortSpan {
    /// Every port. This is what an OCI rule with no port options means.
    All,
    Range {
        min: u16,
        max: u16,
    },
}

impl PortSpan {
    #[must_use]
    pub fn contains(&self, port: u16) -> bool {
        match self {
            Self::All => true,
            Self::Range { min, max } => port >= *min && port <= *max,
        }
    }

    /// Whether this span covers effectively the whole port space.
    #[must_use]
    pub fn is_everything(&self) -> bool {
        match self {
            Self::All => true,
            Self::Range { min, max } => *min <= 1 && *max == u16::MAX,
        }
    }

    /// Number of ports covered.
    #[must_use]
    pub fn width(&self) -> u32 {
        match self {
            Self::All => u32::from(u16::MAX) + 1,
            Self::Range { min, max } => u32::from(*max) - u32::from(*min) + 1,
        }
    }

    fn from_options(options: Option<TransportOptions>) -> Self {
        // No options at all, or options with no destination range, means every
        // port. Reading that as "no ports" would report an open instance as
        // closed, which is the worst possible direction to be wrong in.
        let Some(range) = options.and_then(|options| options.destination_port_range) else {
            return Self::All;
        };
        Self::Range {
            min: range.min.unwrap_or(1),
            max: range.max.unwrap_or(u16::MAX),
        }
    }
}

impl fmt::Display for PortSpan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => f.write_str("all ports"),
            Self::Range { min, max } if min == max => write!(f, "{min}"),
            Self::Range { min, max } => write!(f, "{min}-{max}"),
        }
    }
}

/// Which kind of OCI object granted a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginKind {
    /// A Network Security Group attached to this instance's VNIC.
    NetworkSecurityGroup,
    /// A Security List attached to the subnet, which applies to every instance
    /// in that subnet, not just this one.
    SecurityList,
}

impl OriginKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NetworkSecurityGroup => "network_security_group",
            Self::SecurityList => "security_list",
        }
    }

    /// Whether a rule from this object affects only the instance in question.
    #[must_use]
    pub fn is_instance_scoped(self) -> bool {
        self == Self::NetworkSecurityGroup
    }
}

/// The specific OCI object responsible for an effective rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleOrigin {
    pub kind: OriginKind,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub ownership: Ownership,
}

impl RuleOrigin {
    /// A short human label, for example `NSG oci-free-web-1`.
    #[must_use]
    pub fn label(&self) -> String {
        let prefix = match self.kind {
            OriginKind::NetworkSecurityGroup => "NSG",
            OriginKind::SecurityList => "security list",
        };
        match &self.name {
            Some(name) => format!("{prefix} {name}"),
            None => format!("{prefix} {}", self.id),
        }
    }
}

/// One inbound allowance, resolved and attributed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EffectiveRule {
    /// OCI's rule id, present for NSG rules and absent for Security List rules,
    /// which OCI does not identify individually.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub protocol: RuleProtocol,
    pub ports: PortSpan,
    /// The source exactly as OCI reports it.
    pub source: String,
    /// Parsed source, absent when the source is not a CIDR (a service gateway
    /// range, or another NSG).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_cidr: Option<Cidr>,
    pub source_type: String,
    pub stateless: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub origin: RuleOrigin,
}

impl EffectiveRule {
    /// Whether this rule allows `rule`'s port and protocol.
    #[must_use]
    pub fn allows(&self, rule: PortRule) -> bool {
        self.protocol.covers(rule.protocol) && self.ports.contains(rule.port)
    }

    /// Whether the source is every address on the internet.
    #[must_use]
    pub fn is_open_to_the_internet(&self) -> bool {
        self.source_cidr
            .as_ref()
            .is_some_and(Cidr::is_entire_internet)
    }

    /// Whether the source is broad enough to be worth flagging.
    #[must_use]
    pub fn is_broad(&self) -> bool {
        self.source_cidr.as_ref().is_some_and(Cidr::is_broad)
    }

    /// Whether the source lies entirely inside private address space.
    #[must_use]
    pub fn is_private_source(&self) -> bool {
        self.source_cidr.as_ref().is_some_and(Cidr::is_private)
    }

    /// A one-line rendering: `tcp 22 from 0.0.0.0/0 via NSG oci-free-web-1`.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} {} from {} via {}",
            self.protocol,
            self.ports,
            self.source,
            self.origin.label()
        )
    }
}

/// Whether packets from the internet can arrive at this instance at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InternetReachability {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,
    pub has_default_route: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internet_gateway_id: Option<String>,
    pub internet_gateway_enabled: bool,
    /// The conjunction of the three conditions above.
    pub reachable: bool,
    /// Which link in the chain decided the answer.
    pub reason: String,
}

/// An NSG attached to the instance's VNIC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttachedNsg {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub ownership: Ownership,
    pub ingress_rule_count: usize,
}

/// A Security List applied to the instance's subnet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppliedSecurityList {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub ingress_rule_count: usize,
}

/// Everything that can reach one instance, with provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EffectiveExposure {
    pub vnic_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_ip: Option<String>,
    pub subnet_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet_cidr: Option<String>,
    pub vcn_id: String,
    pub internet: InternetReachability,
    pub attached_nsgs: Vec<AttachedNsg>,
    pub subnet_security_lists: Vec<AppliedSecurityList>,
    /// Every ingress allowance, NSG and Security List alike.
    pub rules: Vec<EffectiveRule>,
    pub warnings: Vec<String>,
}

impl EffectiveExposure {
    /// Every rule that permits `rule`'s port and protocol.
    #[must_use]
    pub fn allowing(&self, rule: PortRule) -> Vec<&EffectiveRule> {
        self.rules.iter().filter(|r| r.allows(rule)).collect()
    }

    /// Whether anything at all permits `rule`.
    ///
    /// This is what `close` re-checks: removing the managed NSG rule does not
    /// close a port that a Security List still allows.
    #[must_use]
    pub fn allows(&self, rule: PortRule) -> bool {
        self.rules.iter().any(|r| r.allows(rule))
    }

    /// Rules permitting `rule` that come from somewhere other than `nsg_id`.
    ///
    /// The residual exposure `vm net close` must report.
    #[must_use]
    pub fn allowing_outside(&self, rule: PortRule, nsg_id: &str) -> Vec<&EffectiveRule> {
        self.allowing(rule)
            .into_iter()
            .filter(|r| r.origin.id != nsg_id)
            .collect()
    }

    /// The oci-free-managed NSG for this instance, if one is attached.
    #[must_use]
    pub fn managed_nsg(&self) -> Option<&AttachedNsg> {
        self.attached_nsgs
            .iter()
            .find(|nsg| nsg.ownership == Ownership::Created)
    }

    /// Rules reachable from outside the tenancy's own address space.
    #[must_use]
    pub fn internet_facing_rules(&self) -> Vec<&EffectiveRule> {
        if !self.internet.reachable {
            return Vec::new();
        }
        self.rules
            .iter()
            .filter(|rule| !rule.is_private_source())
            .collect()
    }
}

/// Everything the calculation needs, gathered by the adapter layer.
#[derive(Debug, Clone)]
pub struct ExposureInputs<'a> {
    pub vnic: &'a Vnic,
    pub subnet: &'a Subnet,
    pub nsgs: &'a [(NetworkSecurityGroup, Vec<SecurityRule>)],
    pub security_lists: &'a [SecurityList],
    pub route_table: Option<&'a RouteTable>,
    pub internet_gateway: Option<&'a InternetGateway>,
}

/// Compute effective inbound exposure.
#[must_use]
pub fn compute(inputs: &ExposureInputs<'_>) -> EffectiveExposure {
    let mut rules = Vec::new();
    let mut warnings = Vec::new();

    let attached_nsgs: Vec<AttachedNsg> = inputs
        .nsgs
        .iter()
        .map(|(nsg, nsg_rules)| {
            let origin = RuleOrigin {
                kind: OriginKind::NetworkSecurityGroup,
                id: nsg.id.clone(),
                name: nsg.display_name.clone(),
                ownership: classify(&nsg.freeform_tags),
            };
            let mut ingress = 0usize;
            for rule in nsg_rules.iter().filter(|rule| rule.is_ingress()) {
                ingress += 1;
                rules.push(from_nsg_rule(rule, &origin));
            }
            AttachedNsg {
                id: nsg.id.clone(),
                name: nsg.display_name.clone(),
                ownership: origin.ownership,
                ingress_rule_count: ingress,
            }
        })
        .collect();

    let subnet_security_lists: Vec<AppliedSecurityList> = inputs
        .security_lists
        .iter()
        .map(|list| {
            let origin = RuleOrigin {
                kind: OriginKind::SecurityList,
                id: list.id.clone(),
                name: list.display_name.clone(),
                ownership: classify(&list.freeform_tags),
            };
            for rule in &list.ingress_security_rules {
                rules.push(from_security_list_rule(rule, &origin));
            }
            AppliedSecurityList {
                id: list.id.clone(),
                name: list.display_name.clone(),
                ingress_rule_count: list.ingress_security_rules.len(),
            }
        })
        .collect();

    if attached_nsgs.is_empty() && !subnet_security_lists.is_empty() {
        warnings.push(
            "no Network Security Group is attached to this instance, so all of its ingress comes \
             from subnet Security Lists, which apply to every instance in the subnet"
                .to_owned(),
        );
    }

    let internet = reachability(inputs, &mut warnings);

    for rule in &rules {
        if rule.source_cidr.is_none() && rule.source_type != "CIDR_BLOCK" {
            warnings.push(format!(
                "{} grants {} {} from {} ({}), which oci-free reports but cannot resolve to an \
                 address range",
                rule.origin.label(),
                rule.protocol,
                rule.ports,
                rule.source,
                rule.source_type
            ));
        }
    }

    EffectiveExposure {
        vnic_id: inputs.vnic.id.clone(),
        private_ip: inputs.vnic.private_ip.clone(),
        subnet_id: inputs.subnet.id.clone(),
        subnet_name: inputs.subnet.display_name.clone(),
        subnet_cidr: inputs.subnet.cidr_block.clone(),
        vcn_id: inputs.subnet.vcn_id.clone(),
        internet,
        attached_nsgs,
        subnet_security_lists,
        rules,
        warnings,
    }
}

fn reachability(inputs: &ExposureInputs<'_>, warnings: &mut Vec<String>) -> InternetReachability {
    let public_ip = inputs
        .vnic
        .public_ip
        .clone()
        .filter(|ip| !ip.trim().is_empty());

    let default_route = inputs.route_table.and_then(|table| {
        table
            .route_rules
            .iter()
            .find(|rule| rule.is_default_ipv4())
            .and_then(|rule| rule.network_entity_id.clone())
    });

    let gateway_enabled = inputs
        .internet_gateway
        .is_some_and(InternetGateway::is_usable);

    let has_default_route = default_route.is_some();
    let reachable = public_ip.is_some() && has_default_route && gateway_enabled;

    let reason = if public_ip.is_none() {
        "the instance has no public IP address, so nothing on the internet can address it"
            .to_owned()
    } else if !has_default_route {
        "the subnet's route table has no 0.0.0.0/0 route, so return traffic cannot leave".to_owned()
    } else if !gateway_enabled {
        "the default route points at an internet gateway that is not enabled".to_owned()
    } else {
        "the instance has a public IP and the subnet routes 0.0.0.0/0 through an enabled internet \
         gateway"
            .to_owned()
    };

    if inputs.route_table.is_none() {
        warnings.push(
            "the subnet's route table could not be read, so internet reachability is reported \
             from the public IP alone and may be incomplete"
                .to_owned(),
        );
    }

    InternetReachability {
        public_ip,
        has_default_route,
        internet_gateway_id: default_route,
        internet_gateway_enabled: gateway_enabled,
        reachable,
        reason,
    }
}

fn from_nsg_rule(rule: &SecurityRule, origin: &RuleOrigin) -> EffectiveRule {
    let protocol = RuleProtocol::parse(&rule.protocol);
    let source = rule.source.clone().unwrap_or_default();
    EffectiveRule {
        rule_id: rule.id.clone(),
        ports: port_span(&protocol, rule.tcp_options, rule.udp_options),
        source_cidr: source.parse().ok(),
        protocol,
        source,
        source_type: rule
            .source_type
            .clone()
            .unwrap_or_else(|| "CIDR_BLOCK".to_owned()),
        stateless: rule.is_stateless.unwrap_or(false),
        description: rule.description.clone(),
        origin: origin.clone(),
    }
}

fn from_security_list_rule(rule: &IngressSecurityRule, origin: &RuleOrigin) -> EffectiveRule {
    let protocol = RuleProtocol::parse(&rule.protocol);
    let source = rule.source.clone().unwrap_or_default();
    EffectiveRule {
        rule_id: None,
        ports: port_span(&protocol, rule.tcp_options, rule.udp_options),
        source_cidr: source.parse().ok(),
        protocol,
        source,
        source_type: rule
            .source_type
            .clone()
            .unwrap_or_else(|| "CIDR_BLOCK".to_owned()),
        stateless: rule.is_stateless.unwrap_or(false),
        description: rule.description.clone(),
        origin: origin.clone(),
    }
}

/// Which port span a rule covers, given its protocol and options.
fn port_span(
    protocol: &RuleProtocol,
    tcp: Option<TransportOptions>,
    udp: Option<TransportOptions>,
) -> PortSpan {
    match protocol {
        RuleProtocol::Tcp => PortSpan::from_options(tcp),
        RuleProtocol::Udp => PortSpan::from_options(udp),
        // A wildcard-protocol rule covers every port of every protocol. OCI
        // rejects port options on it, so there is nothing to narrow.
        RuleProtocol::All => PortSpan::All,
        // ICMP has no ports. `All` keeps the model total; protocol matching
        // already prevents an ICMP rule from answering a TCP question.
        RuleProtocol::Icmp | RuleProtocol::IcmpV6 | RuleProtocol::Other(_) => PortSpan::All,
    }
}

/// Ownership of a set of tags, re-exported for callers assembling inputs.
#[must_use]
pub fn ownership_of(tags: &Tags) -> Ownership {
    classify(tags)
}

#[cfg(test)]
#[path = "exposure_tests.rs"]
mod exposure_tests;
