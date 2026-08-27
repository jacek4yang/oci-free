//! Audit tests.
//!
//! Two properties dominate: a finding must only fire for traffic that can
//! actually arrive, and every finding must name the object a user has to
//! change.

use super::*;
use crate::domain::{
    cidr::Cidr,
    exposure::{
        AppliedSecurityList, AttachedNsg, EffectiveRule, InternetReachability, PortSpan,
        RuleProtocol,
    },
};

fn origin(kind: OriginKind, ownership: Ownership) -> RuleOrigin {
    RuleOrigin {
        kind,
        id: match kind {
            OriginKind::NetworkSecurityGroup => "ocid1.networksecuritygroup.oc1.iad.n".to_owned(),
            OriginKind::SecurityList => "ocid1.securitylist.oc1.iad.s".to_owned(),
        },
        name: Some(match kind {
            OriginKind::NetworkSecurityGroup => "oci-free-web-1".to_owned(),
            OriginKind::SecurityList => "Default Security List".to_owned(),
        }),
        ownership,
    }
}

fn rule(source: &str, ports: PortSpan, origin: RuleOrigin) -> EffectiveRule {
    EffectiveRule {
        rule_id: Some("rule-1".to_owned()),
        protocol: RuleProtocol::Tcp,
        ports,
        source_cidr: source.parse::<Cidr>().ok(),
        source: source.to_owned(),
        source_type: "CIDR_BLOCK".to_owned(),
        stateless: false,
        description: None,
        origin,
    }
}

fn exposure(rules: Vec<EffectiveRule>, reachable: bool, managed_nsg: bool) -> EffectiveExposure {
    EffectiveExposure {
        vnic_id: "ocid1.vnic.oc1.iad.v".to_owned(),
        private_ip: Some("10.0.0.42".to_owned()),
        subnet_id: "ocid1.subnet.oc1.iad.s".to_owned(),
        subnet_name: Some("oci-free-public".to_owned()),
        subnet_cidr: Some("10.0.0.0/24".to_owned()),
        vcn_id: "ocid1.vcn.oc1.iad.v".to_owned(),
        internet: InternetReachability {
            public_ip: reachable.then(|| "203.0.113.17".to_owned()),
            has_default_route: reachable,
            internet_gateway_id: reachable.then(|| "ocid1.internetgateway.oc1.iad.g".to_owned()),
            internet_gateway_enabled: reachable,
            reachable,
            reason: if reachable {
                "the instance has a public IP and a working route".to_owned()
            } else {
                "the instance has no public IP address".to_owned()
            },
        },
        attached_nsgs: if managed_nsg {
            vec![AttachedNsg {
                id: "ocid1.networksecuritygroup.oc1.iad.n".to_owned(),
                name: Some("oci-free-web-1".to_owned()),
                ownership: Ownership::Created,
                ingress_rule_count: rules.len(),
            }]
        } else {
            Vec::new()
        },
        subnet_security_lists: vec![AppliedSecurityList {
            id: "ocid1.securitylist.oc1.iad.s".to_owned(),
            name: Some("Default Security List".to_owned()),
            ingress_rule_count: 0,
        }],
        rules,
        warnings: Vec::new(),
    }
}

fn port(port: u16) -> PortSpan {
    PortSpan::Range {
        min: port,
        max: port,
    }
}

fn find<'a>(report: &'a AuditReport, id: &str) -> Option<&'a Finding> {
    report.findings.iter().find(|finding| finding.id == id)
}

#[test]
fn ssh_open_to_the_world_is_critical() {
    let report = audit(&exposure(
        vec![rule(
            "0.0.0.0/0",
            port(22),
            origin(OriginKind::NetworkSecurityGroup, Ownership::Created),
        )],
        true,
        true,
    ));

    let finding = find(&report, "ssh_open_to_internet").expect("the SSH finding");
    assert_eq!(finding.severity, Severity::Critical);
    assert!(finding.detail.contains("oci-free-web-1"));
    assert!(finding.remediation.contains("--source"));
    assert_eq!(report.highest_severity, Severity::Critical);
    assert!(report.has_concerns());
}

/// The single most important negative case: a rule allowing the world is not a
/// finding when nothing can reach the instance. Reporting it anyway would train
/// users to ignore the audit.
#[test]
fn an_unreachable_instance_raises_no_exposure_findings() {
    let report = audit(&exposure(
        vec![rule(
            "0.0.0.0/0",
            port(22),
            origin(OriginKind::NetworkSecurityGroup, Ownership::Created),
        )],
        false,
        true,
    ));

    assert!(find(&report, "ssh_open_to_internet").is_none());
    assert_eq!(report.highest_severity, Severity::Info);
    assert!(!report.has_concerns());
    assert!(find(&report, "rules_without_reachability").is_some());
    assert!(!report.internet_reachable);
}

/// Nor is a rule sourced from private space, which is unreachable from outside
/// however permissive the ports are.
#[test]
fn private_sources_do_not_raise_internet_findings() {
    let report = audit(&exposure(
        vec![rule(
            "10.0.0.0/16",
            port(22),
            origin(OriginKind::NetworkSecurityGroup, Ownership::Created),
        )],
        true,
        true,
    ));
    assert!(find(&report, "ssh_open_to_internet").is_none());
    assert!(find(&report, "broad_source_range").is_none());
    assert_eq!(report.highest_severity, Severity::Info);
}

#[test]
fn administrative_ports_are_named_not_just_numbered() {
    for (number, name) in [
        (3389u16, "Remote Desktop"),
        (5432, "PostgreSQL"),
        (6379, "Redis"),
    ] {
        let report = audit(&exposure(
            vec![rule(
                "0.0.0.0/0",
                port(number),
                origin(OriginKind::NetworkSecurityGroup, Ownership::Created),
            )],
            true,
            true,
        ));
        let finding = find(&report, "sensitive_port_open_to_internet")
            .unwrap_or_else(|| panic!("expected a finding for port {number}"));
        assert_eq!(finding.severity, Severity::Critical);
        assert!(
            finding.title.contains(name),
            "{} lacks {name}",
            finding.title
        );
    }
}

#[test]
fn an_all_ports_rule_is_reported_once_rather_than_per_service() {
    let report = audit(&exposure(
        vec![rule(
            "0.0.0.0/0",
            PortSpan::All,
            origin(OriginKind::NetworkSecurityGroup, Ownership::Created),
        )],
        true,
        true,
    ));

    assert!(find(&report, "all_ports_open_to_internet").is_some());
    assert!(
        find(&report, "sensitive_port_open_to_internet").is_none(),
        "an all-ports finding must not also produce one finding per known service"
    );
    assert_eq!(report.highest_severity, Severity::Critical);
}

/// The condition users miss most: the port stays open after closing the NSG
/// rule, because the Security List is what grants it.
#[test]
fn subnet_wide_exposure_is_called_out_as_inherited() {
    let report = audit(&exposure(
        vec![rule(
            "0.0.0.0/0",
            port(443),
            origin(OriginKind::SecurityList, Ownership::UserOwned),
        )],
        true,
        true,
    ));

    let finding = find(&report, "inherited_subnet_exposure").expect("the inherited finding");
    assert_eq!(finding.severity, Severity::Warning);
    assert!(finding.detail.contains("every instance in the"));
    assert!(finding.remediation.contains("OCI Console"));
    assert!(
        finding.remediation.contains("never edits it"),
        "the advice must say oci-free will not change a subnet-wide rule for you"
    );
}

#[test]
fn a_broad_but_not_universal_source_is_a_warning_not_a_critical() {
    let report = audit(&exposure(
        vec![rule(
            "11.0.0.0/8",
            port(443),
            origin(OriginKind::NetworkSecurityGroup, Ownership::Created),
        )],
        true,
        true,
    ));
    let finding = find(&report, "broad_source_range").expect("the broad-source finding");
    assert_eq!(finding.severity, Severity::Warning);
    assert!(finding.detail.contains("11.0.0.0/8"));
}

#[test]
fn a_narrow_source_raises_nothing() {
    let report = audit(&exposure(
        vec![rule(
            "198.51.100.7/32",
            port(22),
            origin(OriginKind::NetworkSecurityGroup, Ownership::Created),
        )],
        true,
        true,
    ));
    assert_eq!(report.highest_severity, Severity::Info);
    assert!(!report.has_concerns());
}

#[test]
fn a_public_instance_without_a_managed_nsg_is_flagged() {
    let report = audit(&exposure(
        vec![rule(
            "198.51.100.7/32",
            port(22),
            origin(OriginKind::SecurityList, Ownership::UserOwned),
        )],
        true,
        false,
    ));
    let finding = find(&report, "no_managed_instance_nsg").expect("the managed-NSG finding");
    assert_eq!(finding.severity, Severity::Warning);
    assert!(finding.detail.contains("subnet-wide"));
    assert!(finding.remediation.contains("vm net"));
}

#[test]
fn an_instance_with_no_ingress_says_so() {
    let report = audit(&exposure(Vec::new(), true, true));
    assert!(find(&report, "no_ingress_rules").is_some());
    assert_eq!(report.highest_severity, Severity::Info);
}

#[test]
fn stateless_rules_are_noted() {
    let mut stateless = rule(
        "198.51.100.7/32",
        port(22),
        origin(OriginKind::NetworkSecurityGroup, Ownership::Created),
    );
    stateless.stateless = true;
    let report = audit(&exposure(vec![stateless], true, true));
    let finding = find(&report, "stateless_rule").expect("the stateless finding");
    assert_eq!(finding.severity, Severity::Info);
    assert!(finding.detail.contains("egress"));
}

/// Advice must be phrased for the object that has to change: oci-free can fix
/// its own NSG, but must not claim it will edit somebody else's.
#[test]
fn remediation_matches_who_owns_the_offending_object() {
    let mine = audit(&exposure(
        vec![rule(
            "0.0.0.0/0",
            port(22),
            origin(OriginKind::NetworkSecurityGroup, Ownership::Created),
        )],
        true,
        true,
    ));
    assert!(
        find(&mine, "ssh_open_to_internet")
            .expect("finding")
            .remediation
            .contains("oci-free vm net")
    );

    let theirs = audit(&exposure(
        vec![rule(
            "0.0.0.0/0",
            port(22),
            origin(OriginKind::NetworkSecurityGroup, Ownership::UserOwned),
        )],
        true,
        false,
    ));
    let remediation = &find(&theirs, "ssh_open_to_internet")
        .expect("finding")
        .remediation;
    assert!(remediation.contains("does not modify NSGs it did not create"));
}

#[test]
fn findings_are_ordered_most_severe_first_and_stably() {
    let report = audit(&exposure(
        vec![
            rule(
                "11.0.0.0/8",
                port(443),
                origin(OriginKind::NetworkSecurityGroup, Ownership::Created),
            ),
            rule(
                "0.0.0.0/0",
                port(22),
                origin(OriginKind::NetworkSecurityGroup, Ownership::Created),
            ),
        ],
        true,
        true,
    ));

    assert_eq!(report.findings[0].severity, Severity::Critical);
    let severities: Vec<Severity> = report.findings.iter().map(|f| f.severity).collect();
    let mut sorted = severities.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(severities, sorted);
}

#[test]
fn every_finding_is_explainable_and_actionable() {
    let report = audit(&exposure(
        vec![
            rule(
                "0.0.0.0/0",
                port(22),
                origin(OriginKind::NetworkSecurityGroup, Ownership::Created),
            ),
            rule(
                "0.0.0.0/0",
                port(3306),
                origin(OriginKind::SecurityList, Ownership::UserOwned),
            ),
        ],
        true,
        true,
    ));

    assert!(!report.findings.is_empty());
    for finding in &report.findings {
        assert!(!finding.id.is_empty());
        assert!(!finding.title.is_empty());
        assert!(
            !finding.detail.is_empty(),
            "{} has no explanation",
            finding.id
        );
        assert!(
            !finding.remediation.is_empty(),
            "{} has no next action",
            finding.id
        );
    }
}

/// A findings list is data, not a score. This pins that nothing numeric leaks
/// into the serialized form.
#[test]
fn the_report_carries_no_invented_score() {
    let report = audit(&exposure(
        vec![rule(
            "0.0.0.0/0",
            port(22),
            origin(OriginKind::NetworkSecurityGroup, Ownership::Created),
        )],
        true,
        true,
    ));
    let value = serde_json::to_value(&report).expect("serialize");
    let object = value.as_object().expect("object");
    assert!(object.contains_key("findings"));
    assert!(object.contains_key("highest_severity"));
    for forbidden in ["score", "risk_score", "rating", "grade"] {
        assert!(
            !object.contains_key(forbidden),
            "the audit must not invent a {forbidden}"
        );
    }
}
