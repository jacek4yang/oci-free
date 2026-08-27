//! Auditing effective exposure.
//!
//! Every finding names a concrete condition, the OCI object that causes it, and
//! what to do about it. There is deliberately no score: a number invented here
//! would look like a measurement and would be nothing of the sort, and it would
//! hide the one thing a user actually needs, which is *which object* to change.
//!
//! Findings are only raised for traffic that can genuinely arrive. A rule
//! allowing the world means nothing on an instance with no public address, and
//! reporting it as a critical exposure would train users to ignore the audit.

use serde::Serialize;

use crate::domain::{
    exposure::{EffectiveExposure, EffectiveRule, OriginKind, RuleOrigin},
    network::{PortRule, Protocol},
    ownership::Ownership,
};

/// Ports whose exposure to the internet is almost never intended.
///
/// Each entry is named so a finding can say *what* is exposed rather than only
/// quoting a number.
const SENSITIVE_PORTS: [(u16, &str); 19] = [
    (23, "Telnet"),
    (135, "Windows RPC"),
    (139, "NetBIOS"),
    (445, "SMB"),
    (1433, "Microsoft SQL Server"),
    (1521, "Oracle Database"),
    (2375, "Docker daemon (unencrypted)"),
    (2376, "Docker daemon"),
    (2379, "etcd client"),
    (3306, "MySQL"),
    (3389, "Remote Desktop"),
    (5432, "PostgreSQL"),
    (5900, "VNC"),
    (5984, "CouchDB"),
    (6379, "Redis"),
    (9200, "Elasticsearch"),
    (9300, "Elasticsearch transport"),
    (10250, "Kubelet"),
    (27017, "MongoDB"),
];

/// How much attention a finding deserves.
///
/// Three levels, ordered. Not a score: the ordering only decides what is
/// printed first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Worth knowing; nothing is wrong.
    Info,
    /// Probably not what was intended.
    Warning,
    /// Reachable from the whole internet on something that should not be.
    Critical,
}

impl Severity {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

/// One audit result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Stable identifier for automation, for example `ssh_open_to_internet`.
    pub id: &'static str,
    pub severity: Severity,
    /// One line naming the condition.
    pub title: String,
    /// Why this is the case, in terms of the specific rule and object.
    pub detail: String,
    /// The OCI object responsible, when one rule causes the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<RuleOrigin>,
    /// The next corrective action.
    pub remediation: String,
}

/// The result of auditing one instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditReport {
    pub findings: Vec<Finding>,
    /// The most severe finding, or `info` when there are none.
    pub highest_severity: Severity,
    /// Whether anything at all can reach the instance from the internet.
    pub internet_reachable: bool,
}

impl AuditReport {
    /// Whether anything needs attention.
    #[must_use]
    pub fn has_concerns(&self) -> bool {
        self.highest_severity >= Severity::Warning
    }
}

/// Audit an instance's effective exposure.
#[must_use]
pub fn audit(exposure: &EffectiveExposure) -> AuditReport {
    let mut findings = Vec::new();
    let reachable = exposure.internet.reachable;

    for rule in &exposure.rules {
        findings.extend(audit_rule(rule, reachable));
    }

    findings.extend(audit_topology(exposure, reachable));

    // Most severe first, then by identifier so the order is stable between
    // runs and a diff of two audits is readable.
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(b.id)));

    let highest_severity = findings
        .iter()
        .map(|finding| finding.severity)
        .max()
        .unwrap_or(Severity::Info);

    AuditReport {
        findings,
        highest_severity,
        internet_reachable: reachable,
    }
}

fn audit_rule(rule: &EffectiveRule, reachable: bool) -> Vec<Finding> {
    let mut findings = Vec::new();

    // A rule sourced from private space cannot be used from the internet, and
    // one on an unreachable instance cannot be used at all.
    let internet_usable = reachable && !rule.is_private_source();

    if rule.is_open_to_the_internet() && internet_usable {
        if rule.ports.is_everything() {
            findings.push(Finding {
                id: "all_ports_open_to_internet",
                severity: Severity::Critical,
                title: format!(
                    "every port is reachable from the whole internet ({})",
                    rule.protocol
                ),
                detail: format!(
                    "{} allows {} on all ports from 0.0.0.0/0, and this instance has a public IP \
                     with a working internet route",
                    rule.origin.label(),
                    rule.protocol
                ),
                origin: Some(rule.origin.clone()),
                remediation: narrow_advice(&rule.origin),
            });
        } else if rule.allows(ssh()) {
            findings.push(Finding {
                id: "ssh_open_to_internet",
                severity: Severity::Critical,
                title: "SSH is reachable from the whole internet".to_owned(),
                detail: format!(
                    "{} allows tcp {} from 0.0.0.0/0. Every host on the internet can attempt to \
                     authenticate against this instance.",
                    rule.origin.label(),
                    rule.ports
                ),
                origin: Some(rule.origin.clone()),
                remediation: format!(
                    "restrict the source to your own address: {}",
                    narrow_advice(&rule.origin)
                ),
            });
        }

        for (port, name) in SENSITIVE_PORTS {
            let target = PortRule {
                port,
                protocol: Protocol::Tcp,
            };
            if rule.allows(target) && !rule.ports.is_everything() {
                findings.push(Finding {
                    id: "sensitive_port_open_to_internet",
                    severity: Severity::Critical,
                    title: format!("{name} (tcp {port}) is reachable from the whole internet"),
                    detail: format!(
                        "{} allows tcp {} from 0.0.0.0/0, which covers port {port}. Administrative \
                         and database services are not normally meant to be internet facing.",
                        rule.origin.label(),
                        rule.ports
                    ),
                    origin: Some(rule.origin.clone()),
                    remediation: narrow_advice(&rule.origin),
                });
            }
        }
    } else if rule.is_broad() && internet_usable {
        findings.push(Finding {
            id: "broad_source_range",
            severity: Severity::Warning,
            title: format!("a very broad source range can reach {}", rule.ports),
            detail: format!(
                "{} allows {} {} from {}, which covers millions of addresses",
                rule.origin.label(),
                rule.protocol,
                rule.ports,
                rule.source
            ),
            origin: Some(rule.origin.clone()),
            remediation: narrow_advice(&rule.origin),
        });
    }

    // Subnet-wide exposure is the finding users most often miss: they close a
    // port on the instance and it stays open, because the Security List is
    // what was granting it.
    if rule.origin.kind == OriginKind::SecurityList && internet_usable && !rule.is_private_source()
    {
        findings.push(Finding {
            id: "inherited_subnet_exposure",
            severity: Severity::Warning,
            title: format!("{} is granted subnet-wide, not per instance", rule.ports),
            detail: format!(
                "{} allows {} {} from {}. A Security List applies to every instance in the \
                 subnet, so removing this instance's NSG rule would not close it.",
                rule.origin.label(),
                rule.protocol,
                rule.ports,
                rule.source
            ),
            origin: Some(rule.origin.clone()),
            remediation: format!(
                "move the rule onto the instance's Network Security Group with `oci-free vm net \
                 <instance> open`, then {}",
                narrow_advice(&rule.origin)
            ),
        });
    }

    if rule.stateless {
        findings.push(Finding {
            id: "stateless_rule",
            severity: Severity::Info,
            title: format!("{} is allowed by a stateless rule", rule.ports),
            detail: format!(
                "{} allows {} {} statelessly, so return traffic needs a matching egress rule",
                rule.origin.label(),
                rule.protocol,
                rule.ports
            ),
            origin: Some(rule.origin.clone()),
            remediation: "confirm a matching egress rule exists, or make the rule stateful"
                .to_owned(),
        });
    }

    findings
}

fn audit_topology(exposure: &EffectiveExposure, reachable: bool) -> Vec<Finding> {
    let mut findings = Vec::new();

    if reachable && exposure.managed_nsg().is_none() {
        let detail = if exposure.attached_nsgs.is_empty() {
            "this instance has no Network Security Group at all, so every ingress rule that \
             applies to it is subnet-wide"
                .to_owned()
        } else {
            format!(
                "the {} attached NSG(s) were not created by oci-free, so `vm net open` and `vm \
                 net close` have no instance-scoped group to modify",
                exposure.attached_nsgs.len()
            )
        };
        findings.push(Finding {
            id: "no_managed_instance_nsg",
            severity: Severity::Warning,
            title: "this public instance has no oci-free-managed NSG".to_owned(),
            detail,
            origin: None,
            remediation:
                "run `oci-free vm net <instance> open <port>/<protocol>` to create and attach a \
                 managed NSG for this instance"
                    .to_owned(),
        });
    }

    if !reachable && !exposure.rules.is_empty() {
        findings.push(Finding {
            id: "rules_without_reachability",
            severity: Severity::Info,
            title: "ingress rules exist but nothing can reach this instance".to_owned(),
            detail: format!(
                "{} ingress rule(s) apply, but {}",
                exposure.rules.len(),
                exposure.internet.reason
            ),
            origin: None,
            remediation: "no action needed unless the instance is supposed to be reachable"
                .to_owned(),
        });
    }

    if exposure.rules.is_empty() {
        findings.push(Finding {
            id: "no_ingress_rules",
            severity: Severity::Info,
            title: "no ingress is allowed".to_owned(),
            detail: "no NSG or Security List rule permits inbound traffic to this instance"
                .to_owned(),
            origin: None,
            remediation: "no action needed".to_owned(),
        });
    }

    for nsg in &exposure.attached_nsgs {
        if nsg.ownership == Ownership::Unknown {
            findings.push(Finding {
                id: "unrecognised_nsg_ownership",
                severity: Severity::Info,
                title: format!(
                    "NSG {} carries an oci-free tag this build does not recognise",
                    nsg.name.as_deref().unwrap_or(&nsg.id)
                ),
                detail: Ownership::Unknown.explain().to_owned(),
                origin: None,
                remediation: "upgrade oci-free, or clear the unexpected tag in the OCI Console"
                    .to_owned(),
            });
        }
    }

    findings
}

/// Advice phrased for the object that actually has to change.
fn narrow_advice(origin: &RuleOrigin) -> String {
    match origin.kind {
        OriginKind::NetworkSecurityGroup if origin.ownership == Ownership::Created => {
            "run `oci-free vm net <instance> close <port>/<protocol>` and re-open it with \
             `--source <your-address>/32`"
                .to_owned()
        }
        OriginKind::NetworkSecurityGroup => format!(
            "narrow the source on {} in the OCI Console; oci-free does not modify NSGs it did not \
             create",
            origin.label()
        ),
        OriginKind::SecurityList => format!(
            "narrow or remove the rule on {} in the OCI Console; it applies to every instance in \
             the subnet, so oci-free never edits it as a convenience",
            origin.label()
        ),
    }
}

fn ssh() -> PortRule {
    PortRule {
        port: 22,
        protocol: Protocol::Tcp,
    }
}

#[cfg(test)]
#[path = "audit_tests.rs"]
mod audit_tests;
