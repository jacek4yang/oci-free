//! Golden tests for the public JSON contract.
//!
//! `docs/JSON.md` is a promise to script authors. These tests pin the parts of
//! it that a refactor could silently break: the envelope shape, the field names
//! of every command payload, the enum spellings, and the rule that an
//! unreported figure never becomes a zero.
//!
//! A failure here is not a test to fix — it is a breaking change to a
//! documented contract, and either the change or the documented schema version
//! has to be reconsidered.

use serde_json::Value;

use crate::{
    commands::{
        account::{AccountInfo, LimitRow, LimitsReport, UsageReport, UsageRow},
        cost::{ChargedService, CostReport},
        delete::{DeleteResult, ResourceOutcome},
        vm::VmIp,
        vmlifecycle::LifecycleResult,
        vmnet::NetChange,
    },
    domain::{
        audit::{AuditReport, Finding, Severity},
        exposure::{
            AppliedSecurityList, AttachedNsg, EffectiveExposure, EffectiveRule,
            InternetReachability, OriginKind, PortSpan, RuleOrigin, RuleProtocol,
        },
        free::FreeClassification,
        ownership::Ownership,
        plan::{BillingRisk, ChangeKind},
    },
    error::ErrorKind,
    output::{Envelope, SCHEMA_VERSION, render_failure},
};

/// Assert that a serialized value has exactly the documented top-level keys.
///
/// Exactly, not at least: a field that appears without being documented is how
/// a contract drifts.
fn assert_keys(value: &Value, expected: &[&str], what: &str) {
    let object = value
        .as_object()
        .unwrap_or_else(|| panic!("{what} must serialize to an object"));
    let mut actual: Vec<&str> = object.keys().map(String::as_str).collect();
    actual.sort_unstable();
    let mut expected: Vec<&str> = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(
        actual, expected,
        "{what} has undocumented or missing fields"
    );
}

fn to_value<T: serde::Serialize>(payload: &T) -> Value {
    serde_json::to_value(payload).expect("payload serializes")
}

#[test]
fn the_envelope_shape_is_stable() {
    let envelope = Envelope::success("vm.list", serde_json::json!({ "instances": [] }));
    let value: Value = serde_json::from_str(&envelope.render().expect("render")).expect("json");
    assert_keys(
        &value,
        &["schema_version", "command", "data", "warnings"],
        "a success envelope",
    );
    assert_eq!(value["schema_version"], SCHEMA_VERSION);
    assert_eq!(SCHEMA_VERSION, "1", "docs/JSON.md documents version 1");
}

#[test]
fn the_error_shape_is_stable() {
    let error = crate::error::Error::new(ErrorKind::Authorization, "not authorized")
        .with_context("the tenancy policy does not allow this")
        .with_oci(crate::error::OciContext {
            status: Some(403),
            code: Some("NotAuthorized".to_owned()),
            request_id: Some("req-1".to_owned()),
            operation: Some("ListInstances".to_owned()),
        });
    let value: Value = serde_json::from_str(&render_failure("vm.list", &error)).expect("json");

    assert_keys(
        &value,
        &["schema_version", "command", "error", "warnings"],
        "a failure envelope",
    );
    assert_keys(
        &value["error"],
        &[
            "kind",
            "message",
            "context",
            "remediation",
            "oci",
            "exit_code",
        ],
        "an error payload",
    );
    assert_keys(
        &value["error"]["oci"],
        &["status", "code", "request_id", "operation"],
        "an OCI context",
    );
}

/// Every documented error kind must keep its spelling: scripts branch on these.
#[test]
fn error_kind_spellings_are_stable() {
    let cases = [
        (ErrorKind::Configuration, "configuration"),
        (ErrorKind::Authentication, "authentication"),
        (ErrorKind::Authorization, "authorization"),
        (ErrorKind::NotFound, "not_found"),
        (ErrorKind::Conflict, "conflict"),
        (ErrorKind::RateLimited, "rate_limited"),
        (ErrorKind::TransientServer, "transient_server"),
        (ErrorKind::Network, "network"),
        (ErrorKind::Timeout, "timeout"),
        (ErrorKind::InvalidInput, "invalid_input"),
        (ErrorKind::Ambiguous, "ambiguous"),
        (ErrorKind::PolicyRejected, "policy_rejected"),
        (ErrorKind::BillingUncertain, "billing_uncertain"),
        (ErrorKind::UnsupportedState, "unsupported_state"),
        (ErrorKind::PartialMutation, "partial_mutation"),
        (ErrorKind::ExternalTool, "external_tool"),
        (ErrorKind::MalformedResponse, "malformed_response"),
    ];
    for (kind, expected) in cases {
        assert_eq!(kind.as_str(), expected);
    }
}

#[test]
fn enum_spellings_are_stable() {
    for (ownership, expected) in [
        (Ownership::Created, "created"),
        (Ownership::Reused, "reused"),
        (Ownership::UserOwned, "user_owned"),
        (Ownership::Unknown, "unknown"),
    ] {
        assert_eq!(to_value(&ownership), Value::String(expected.to_owned()));
    }

    for (severity, expected) in [
        (Severity::Info, "info"),
        (Severity::Warning, "warning"),
        (Severity::Critical, "critical"),
    ] {
        assert_eq!(to_value(&severity), Value::String(expected.to_owned()));
    }

    for (kind, expected) in [
        (OriginKind::NetworkSecurityGroup, "network_security_group"),
        (OriginKind::SecurityList, "security_list"),
    ] {
        assert_eq!(to_value(&kind), Value::String(expected.to_owned()));
        assert_eq!(kind.as_str(), expected);
    }

    for (kind, expected) in [
        (ChangeKind::Create, "create"),
        (ChangeKind::Modify, "modify"),
        (ChangeKind::Delete, "delete"),
        (ChangeKind::Attach, "attach"),
        (ChangeKind::Detach, "detach"),
        (ChangeKind::Reuse, "reuse"),
    ] {
        assert_eq!(to_value(&kind), Value::String(expected.to_owned()));
    }

    for (risk, expected) in [
        (BillingRisk::None, "none"),
        (BillingRisk::Bounded, "bounded"),
        (BillingRisk::Unknown, "unknown"),
        (BillingRisk::Charged, "charged"),
    ] {
        assert_eq!(to_value(&risk), Value::String(expected.to_owned()));
    }

    // Free Tier classifications keep their variant names, which is what
    // docs/JSON.md documents and what `policy explain` emits.
    for (classification, expected) in [
        (FreeClassification::VerifiedAlwaysFree, "VerifiedAlwaysFree"),
        (FreeClassification::LimitedFree, "LimitedFree"),
        (FreeClassification::Paid, "Paid"),
        (FreeClassification::Unknown, "Unknown"),
    ] {
        assert_eq!(
            to_value(&classification),
            Value::String(expected.to_owned())
        );
    }
}

#[test]
fn account_info_matches_the_documented_fields() {
    let payload = AccountInfo {
        profile: "DEFAULT".to_owned(),
        tenancy: "ocid1.tenancy.oc1..\u{2026}xk3q7a".to_owned(),
        tenancy_name: Some("example".to_owned()),
        configured_region: "us-ashburn-1".to_owned(),
        home_region: "us-ashburn-1".to_owned(),
        subscribed_regions: vec!["us-ashburn-1".to_owned()],
        availability_domains: vec!["Uocm:US-ASHBURN-AD-1".to_owned()],
        warnings: Vec::new(),
    };
    assert_keys(
        &to_value(&payload),
        &[
            "profile",
            "tenancy",
            "tenancy_name",
            "configured_region",
            "home_region",
            "subscribed_regions",
            "availability_domains",
            "warnings",
        ],
        "account.info",
    );
}

#[test]
fn cost_matches_the_documented_fields_and_distinguishes_absent_from_zero() {
    let charged = CostReport {
        period_start: "2026-08-01T00:00:00Z".to_owned(),
        period_end: "2026-09-01T00:00:00Z".to_owned(),
        available: true,
        total: Some(2.55),
        currency: Some("USD".to_owned()),
        charged_services: vec![ChargedService {
            service: "BLOCK_STORAGE".to_owned(),
            amount: 2.55,
        }],
        has_charges: true,
        warnings: Vec::new(),
    };
    assert_keys(
        &to_value(&charged),
        &[
            "period_start",
            "period_end",
            "available",
            "total",
            "currency",
            "charged_services",
            "has_charges",
            "warnings",
        ],
        "cost",
    );
    assert_keys(
        &to_value(&charged)["charged_services"][0],
        &["service", "amount"],
        "a charged service",
    );

    let unknown = CostReport {
        available: false,
        total: None,
        currency: None,
        charged_services: Vec::new(),
        has_charges: false,
        ..charged
    };
    let value = to_value(&unknown);
    assert_eq!(value["available"], false);
    assert!(
        value.get("total").is_none(),
        "an unknown total must be omitted, never serialized as 0"
    );
    assert!(!value.to_string().contains("0.0"));
}

#[test]
fn account_limits_matches_the_documented_fields() {
    let row = LimitRow {
        service: "compute".to_owned(),
        name: "standard-a1-core-count".to_owned(),
        description: Some("Ampere A1 cores".to_owned()),
        scope: Some("AD".to_owned()),
        availability_domain: Some("Uocm:US-ASHBURN-AD-1".to_owned()),
        value: Some(4),
        used: Some(2.0),
        available: Some(2.0),
        free_tier_relevant: true,
    };
    assert_keys(
        &to_value(&row),
        &[
            "service",
            "name",
            "description",
            "scope",
            "availability_domain",
            "value",
            "used",
            "available",
            "free_tier_relevant",
        ],
        "a limit row",
    );

    let report = LimitsReport {
        region: "us-ashburn-1".to_owned(),
        free_tier: vec![row],
        other: Vec::new(),
        other_omitted: 12,
        warnings: Vec::new(),
    };
    assert_keys(
        &to_value(&report),
        &["region", "free_tier", "other", "other_omitted", "warnings"],
        "account.limits",
    );

    // A limit OCI reported without a value must not become a limit of zero.
    let unreported = LimitRow {
        value: None,
        used: None,
        available: None,
        ..to_row()
    };
    let value = to_value(&unreported);
    assert!(value.get("value").is_none());
    assert!(value.get("used").is_none());
}

fn to_row() -> LimitRow {
    LimitRow {
        service: "compute".to_owned(),
        name: "mystery".to_owned(),
        description: None,
        scope: None,
        availability_domain: None,
        value: None,
        used: None,
        available: None,
        free_tier_relevant: false,
    }
}

#[test]
fn account_usage_matches_the_documented_fields() {
    let report = UsageReport {
        region: "us-ashburn-1".to_owned(),
        period_start: "2026-08-01T00:00:00Z".to_owned(),
        period_end: "2026-09-01T00:00:00Z".to_owned(),
        available: true,
        rows: vec![UsageRow {
            service: "COMPUTE".to_owned(),
            quantity: Some(1464.0),
            unit: Some("OCPU_HOURS".to_owned()),
            amount: Some(0.0),
        }],
        currency: Some("USD".to_owned()),
        warnings: Vec::new(),
    };
    assert_keys(
        &to_value(&report),
        &[
            "region",
            "period_start",
            "period_end",
            "available",
            "rows",
            "currency",
            "warnings",
        ],
        "account.usage",
    );
    assert_keys(
        &to_value(&report)["rows"][0],
        &["service", "quantity", "unit", "amount"],
        "a usage row",
    );
}

/// `vm.ip` is the one payload where a `null` is deliberate: absence is the
/// answer, so a consumer must never have to infer it from a missing key.
#[test]
fn vm_ip_makes_the_absence_of_a_public_address_explicit() {
    let without = VmIp {
        instance: "free-arm-1".to_owned(),
        instance_id: "ocid1.instance.oc1.iad.a".to_owned(),
        region: "us-ashburn-1".to_owned(),
        has_public_ip: false,
        public_ip: None,
        private_ip: Some("10.0.0.42".to_owned()),
        warnings: Vec::new(),
    };
    let value = to_value(&without);
    assert_keys(
        &value,
        &[
            "instance",
            "instance_id",
            "region",
            "has_public_ip",
            "public_ip",
            "private_ip",
            "warnings",
        ],
        "vm.ip",
    );
    assert_eq!(value["has_public_ip"], false);
    assert!(
        value["public_ip"].is_null(),
        "absence must be an explicit null here, not a missing key"
    );
}

#[test]
fn effective_exposure_carries_provenance_on_every_rule() {
    let exposure = EffectiveExposure {
        vnic_id: "ocid1.vnic.oc1.iad.v".to_owned(),
        private_ip: Some("10.0.0.42".to_owned()),
        subnet_id: "ocid1.subnet.oc1.iad.s".to_owned(),
        subnet_name: Some("oci-free-subnet".to_owned()),
        subnet_cidr: Some("10.0.0.0/24".to_owned()),
        vcn_id: "ocid1.vcn.oc1.iad.v".to_owned(),
        internet: InternetReachability {
            public_ip: Some("203.0.113.17".to_owned()),
            has_default_route: true,
            internet_gateway_id: Some("ocid1.internetgateway.oc1.iad.g".to_owned()),
            internet_gateway_enabled: true,
            reachable: true,
            reason: "reachable".to_owned(),
        },
        attached_nsgs: vec![AttachedNsg {
            id: "ocid1.networksecuritygroup.oc1.iad.n".to_owned(),
            name: Some("oci-free-web-1".to_owned()),
            ownership: Ownership::Created,
            ingress_rule_count: 1,
        }],
        subnet_security_lists: vec![AppliedSecurityList {
            id: "ocid1.securitylist.oc1.iad.s".to_owned(),
            name: Some("Default".to_owned()),
            ingress_rule_count: 0,
        }],
        rules: vec![EffectiveRule {
            rule_id: Some("RULE1".to_owned()),
            protocol: RuleProtocol::Tcp,
            ports: PortSpan::Range { min: 443, max: 443 },
            source: "0.0.0.0/0".to_owned(),
            source_cidr: "0.0.0.0/0".parse().ok(),
            source_type: "CIDR_BLOCK".to_owned(),
            stateless: false,
            description: Some("oci-free managed: 443/tcp".to_owned()),
            origin: RuleOrigin {
                kind: OriginKind::NetworkSecurityGroup,
                id: "ocid1.networksecuritygroup.oc1.iad.n".to_owned(),
                name: Some("oci-free-web-1".to_owned()),
                ownership: Ownership::Created,
            },
        }],
        warnings: Vec::new(),
    };

    let value = to_value(&exposure);
    assert_keys(
        &value,
        &[
            "vnic_id",
            "private_ip",
            "subnet_id",
            "subnet_name",
            "subnet_cidr",
            "vcn_id",
            "internet",
            "attached_nsgs",
            "subnet_security_lists",
            "rules",
            "warnings",
        ],
        "an effective exposure",
    );
    assert_keys(
        &value["internet"],
        &[
            "public_ip",
            "has_default_route",
            "internet_gateway_id",
            "internet_gateway_enabled",
            "reachable",
            "reason",
        ],
        "internet reachability",
    );
    assert_keys(
        &value["rules"][0],
        &[
            "rule_id",
            "protocol",
            "ports",
            "source",
            "source_cidr",
            "source_type",
            "stateless",
            "description",
            "origin",
        ],
        "an effective rule",
    );
    assert_keys(
        &value["rules"][0]["origin"],
        &["kind", "id", "name", "ownership"],
        "a rule origin",
    );
    assert_eq!(
        value["rules"][0]["origin"]["kind"],
        "network_security_group"
    );
    assert_eq!(value["rules"][0]["protocol"]["kind"], "tcp");
    assert_eq!(value["rules"][0]["ports"]["kind"], "range");
}

#[test]
fn audit_findings_match_the_documented_fields_and_carry_no_score() {
    let report = AuditReport {
        findings: vec![Finding {
            id: "ssh_open_to_internet",
            severity: Severity::Critical,
            title: "SSH is reachable from the whole internet".to_owned(),
            detail: "NSG oci-free-web-1 allows tcp 22 from 0.0.0.0/0".to_owned(),
            origin: Some(RuleOrigin {
                kind: OriginKind::NetworkSecurityGroup,
                id: "ocid1.networksecuritygroup.oc1.iad.n".to_owned(),
                name: Some("oci-free-web-1".to_owned()),
                ownership: Ownership::Created,
            }),
            remediation: "restrict the source".to_owned(),
        }],
        highest_severity: Severity::Critical,
        internet_reachable: true,
    };

    let value = to_value(&report);
    assert_keys(
        &value,
        &["findings", "highest_severity", "internet_reachable"],
        "an audit report",
    );
    assert_keys(
        &value["findings"][0],
        &["id", "severity", "title", "detail", "origin", "remediation"],
        "a finding",
    );
    for forbidden in ["score", "risk_score", "rating", "grade"] {
        assert!(
            !value.to_string().contains(forbidden),
            "the audit must not invent a {forbidden}"
        );
    }
}

#[test]
fn net_changes_match_the_documented_fields() {
    let change = NetChange {
        instance: "free-arm-1".to_owned(),
        instance_id: "ocid1.instance.oc1.iad.a".to_owned(),
        region: "us-ashburn-1".to_owned(),
        rule: "443/tcp".to_owned(),
        source: Some("198.51.100.7/32".to_owned()),
        nsg_id: "ocid1.networksecuritygroup.oc1.iad.n".to_owned(),
        nsg_name: "oci-free-web-1".to_owned(),
        nsg_created: false,
        verified: true,
        residual_exposure: Vec::new(),
        warnings: Vec::new(),
    };
    assert_keys(
        &to_value(&change),
        &[
            "instance",
            "instance_id",
            "region",
            "rule",
            "source",
            "nsg_id",
            "nsg_name",
            "nsg_created",
            "verified",
            "residual_exposure",
            "warnings",
        ],
        "vm.net.open / vm.net.close",
    );
}

#[test]
fn lifecycle_results_match_the_documented_fields() {
    let result = LifecycleResult {
        instance: "free-arm-1".to_owned(),
        instance_id: "ocid1.instance.oc1.iad.a".to_owned(),
        region: "us-ashburn-1".to_owned(),
        action: "START".to_owned(),
        state_before: "STOPPED".to_owned(),
        state_after: "RUNNING".to_owned(),
        reached_target: true,
        no_op: false,
        warnings: Vec::new(),
    };
    assert_keys(
        &to_value(&result),
        &[
            "instance",
            "instance_id",
            "region",
            "action",
            "state_before",
            "state_after",
            "reached_target",
            "no_op",
            "warnings",
        ],
        "vm.start / vm.stop / vm.reboot",
    );
}

#[test]
fn delete_results_report_every_resource_and_its_outcome() {
    let result = DeleteResult {
        instance: "free-arm-1".to_owned(),
        instance_id: "ocid1.instance.oc1.iad.a".to_owned(),
        region: "us-ashburn-1".to_owned(),
        lifecycle_state: "TERMINATING".to_owned(),
        verified: true,
        resources: vec![ResourceOutcome {
            kind: "boot volume".to_owned(),
            id: "ocid1.bootvolume.oc1.iad.b".to_owned(),
            name: Some("free-arm-1 (Boot Volume)".to_owned()),
            ownership: Ownership::Created,
            outcome: "deleted".to_owned(),
            reason: "terminated with the instance".to_owned(),
        }],
        warnings: Vec::new(),
    };
    let value = to_value(&result);
    assert_keys(
        &value,
        &[
            "instance",
            "instance_id",
            "region",
            "lifecycle_state",
            "verified",
            "resources",
            "warnings",
        ],
        "vm.delete",
    );
    assert_keys(
        &value["resources"][0],
        &["kind", "id", "name", "ownership", "outcome", "reason"],
        "a resource outcome",
    );
}

/// No payload may ever carry credential material. This checks the rendered
/// text of a representative set rather than trusting field-by-field review.
#[test]
fn no_payload_leaks_credential_material() {
    let rendered = format!(
        "{} {} {}",
        to_value(&AccountInfo {
            profile: "DEFAULT".to_owned(),
            tenancy: "ocid1.tenancy.oc1..\u{2026}xk3q7a".to_owned(),
            tenancy_name: None,
            configured_region: "us-ashburn-1".to_owned(),
            home_region: "us-ashburn-1".to_owned(),
            subscribed_regions: Vec::new(),
            availability_domains: Vec::new(),
            warnings: Vec::new(),
        }),
        render_failure(
            "vm.list",
            &crate::error::Error::new(ErrorKind::Authentication, "rejected")
        ),
        to_value(&to_row()),
    );

    for forbidden in [
        "PRIVATE KEY",
        "Authorization",
        "Signature ",
        "pass_phrase",
        "\u{1b}",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "a payload leaked {forbidden:?}"
        );
    }
}
