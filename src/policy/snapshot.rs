//! The conservative Free Tier policy snapshot.
//!
//! OCI reports a per-shape `billingType`, which tells us *whether* a shape is
//! Always Free. It does not tell us *how much* of that shape a tenancy may use.
//! The published allowances (4 OCPU / 24 GB of Ampere A1, two AMD micro
//! instances) live only in Oracle's documentation, so they are recorded here as
//! a reviewable, dated snapshot rather than scattered through command modules.
//!
//! The snapshot is deliberately narrow. It never widens eligibility: a resource
//! class it does not list is Unknown, and Unknown blocks. It is also never
//! fetched at runtime — CLAUDE.md forbids turning scraped web text into billing
//! policy, so this file ships with the binary and changes only through review.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The snapshot shipped with this build.
const SNAPSHOT_JSON: &str = include_str!("../../policy/free-tier-snapshot.json");

/// Schema version this build understands.
pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// Where a claim in the snapshot came from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Provenance {
    pub source: String,
    pub url: String,
    pub note: String,
}

/// The OCI service-limit names that correspond to an allowance.
///
/// Presentation hints, never policy. A tenancy publishes hundreds of limits;
/// these names decide which handful `account limits` highlights. A name Oracle
/// renames simply stops matching, which changes what is shown and never what is
/// permitted.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ServiceLimitHints {
    /// Limits-API service name, for example `compute`.
    pub service: String,
    #[serde(default)]
    pub ocpu: Option<String>,
    #[serde(default)]
    pub memory_gb: Option<String>,
    #[serde(default)]
    pub instances: Option<String>,
}

impl ServiceLimitHints {
    /// Every limit name this allowance refers to.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        [
            self.ocpu.as_deref(),
            self.memory_gb.as_deref(),
            self.instances.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

/// A network or storage limit worth showing alongside the compute allowances.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct NamedLimit {
    pub service: String,
    pub name: String,
    pub description: String,
}

/// A pooled Free Tier compute allowance.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ComputeAllowance {
    /// Stable identifier used in JSON output.
    pub id: String,
    /// Shape names this allowance covers.
    pub shapes: Vec<String>,
    pub description: String,
    /// Total OCPUs across the tenancy.
    pub max_ocpus: f64,
    /// Total memory in GB across the tenancy.
    pub max_memory_gb: f64,
    /// Instance-count ceiling, when the allowance is expressed that way.
    #[serde(default)]
    pub max_instances: Option<u32>,
    /// Which OCI service limits correspond to this allowance.
    #[serde(default)]
    pub service_limits: Option<ServiceLimitHints>,
}

impl ComputeAllowance {
    /// Whether this allowance governs `shape`.
    ///
    /// Compared case-insensitively because OCI shape names are case-stable in
    /// practice but nothing in the API guarantees it.
    #[must_use]
    pub fn covers(&self, shape: &str) -> bool {
        self.shapes
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(shape))
    }
}

/// The parsed snapshot.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct PolicySnapshot {
    pub schema_version: u32,
    /// ISO-8601 date the allowances were last checked against Oracle's docs.
    pub verified_on: String,
    pub provenance: Vec<Provenance>,
    pub assumptions: Vec<String>,
    pub unknown_behaviour: String,
    pub compute_allowances: Vec<ComputeAllowance>,
    /// Network and storage limits worth surfacing next to compute.
    #[serde(default)]
    pub network_limits: Vec<NamedLimit>,
}

impl PolicySnapshot {
    /// Load the snapshot compiled into this build.
    pub fn load() -> Result<Self> {
        let snapshot: Self = serde_json::from_str(SNAPSHOT_JSON).map_err(|error| {
            Error::configuration("the built-in Free Tier policy snapshot is unreadable")
                .with_context(error.to_string())
                .with_remediation("this is a packaging defect; please file an issue")
        })?;

        if snapshot.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(Error::configuration(format!(
                "the Free Tier policy snapshot uses schema version {} but this build understands {}",
                snapshot.schema_version, SUPPORTED_SCHEMA_VERSION
            ))
            .with_remediation("upgrade oci-free"));
        }

        Ok(snapshot)
    }

    /// The allowance governing `shape`, if the snapshot covers it.
    ///
    /// Returning `None` is meaningful: it means this build has no verified
    /// allowance for the shape, so capacity cannot be proven and the operation
    /// must fail closed.
    #[must_use]
    pub fn allowance_for(&self, shape: &str) -> Option<&ComputeAllowance> {
        self.compute_allowances
            .iter()
            .find(|allowance| allowance.covers(shape))
    }

    /// A short, human-readable citation for use in evidence.
    #[must_use]
    pub fn citation(&self) -> String {
        format!(
            "oci-free policy snapshot v{}, verified {}",
            self.schema_version, self.verified_on
        )
    }

    /// Every Limits-API service this snapshot refers to.
    #[must_use]
    pub fn limit_services(&self) -> Vec<&str> {
        let mut services: Vec<&str> = self
            .compute_allowances
            .iter()
            .filter_map(|allowance| allowance.service_limits.as_ref())
            .map(|hints| hints.service.as_str())
            .chain(
                self.network_limits
                    .iter()
                    .map(|limit| limit.service.as_str()),
            )
            .collect();
        services.sort_unstable();
        services.dedup();
        services
    }

    /// Whether a limit name is one the snapshot considers Free Tier relevant.
    #[must_use]
    pub fn highlights_limit(&self, service: &str, name: &str) -> bool {
        self.compute_allowances
            .iter()
            .filter_map(|allowance| allowance.service_limits.as_ref())
            .any(|hints| hints.service == service && hints.names().contains(&name))
            || self
                .network_limits
                .iter()
                .any(|limit| limit.service == service && limit.name == name)
    }

    /// Every shape the snapshot knows about, keyed by allowance id.
    #[must_use]
    pub fn shapes_by_allowance(&self) -> BTreeMap<&str, &[String]> {
        self.compute_allowances
            .iter()
            .map(|allowance| (allowance.id.as_str(), allowance.shapes.as_slice()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{PolicySnapshot, SUPPORTED_SCHEMA_VERSION};

    #[test]
    fn the_shipped_snapshot_loads() {
        let snapshot = PolicySnapshot::load().expect("the built-in snapshot must parse");
        assert_eq!(snapshot.schema_version, SUPPORTED_SCHEMA_VERSION);
    }

    /// CLAUDE.md requires provenance and a verification date. Without them a
    /// reviewer cannot tell whether the allowances are still accurate.
    #[test]
    fn the_snapshot_carries_provenance_and_a_verification_date() {
        let snapshot = PolicySnapshot::load().expect("snapshot");

        assert!(
            !snapshot.provenance.is_empty(),
            "every claim needs a citable source"
        );
        for entry in &snapshot.provenance {
            assert!(!entry.source.is_empty());
            assert!(entry.url.starts_with("https://"));
        }

        // A plain ISO date, so staleness is obvious at a glance.
        let parts: Vec<&str> = snapshot.verified_on.split('-').collect();
        assert_eq!(parts.len(), 3, "verified_on must be YYYY-MM-DD");
        assert!(parts[0].parse::<u32>().is_ok());

        assert!(!snapshot.assumptions.is_empty());
        assert!(!snapshot.unknown_behaviour.is_empty());
    }

    #[test]
    fn known_shapes_resolve_to_allowances() {
        let snapshot = PolicySnapshot::load().expect("snapshot");

        let arm = snapshot
            .allowance_for("VM.Standard.A1.Flex")
            .expect("the ARM allowance must be present");
        assert_eq!(arm.max_ocpus, 4.0);
        assert_eq!(arm.max_memory_gb, 24.0);
        assert_eq!(arm.max_instances, None);

        let micro = snapshot
            .allowance_for("VM.Standard.E2.1.Micro")
            .expect("the micro allowance must be present");
        assert_eq!(micro.max_instances, Some(2));
    }

    /// The snapshot must never widen eligibility. An unlisted shape has no
    /// allowance, which is what makes capacity unprovable and blocks it.
    #[test]
    fn unlisted_shapes_have_no_allowance() {
        let snapshot = PolicySnapshot::load().expect("snapshot");
        for shape in [
            "VM.Standard3.Flex",
            "BM.Standard.E4.128",
            "VM.Totally.Made.Up",
            "",
        ] {
            assert!(
                snapshot.allowance_for(shape).is_none(),
                "{shape} must not resolve to an allowance"
            );
        }
    }

    #[test]
    fn shape_matching_is_case_insensitive() {
        let snapshot = PolicySnapshot::load().expect("snapshot");
        assert!(snapshot.allowance_for("vm.standard.a1.flex").is_some());
        assert!(snapshot.allowance_for("VM.STANDARD.A1.FLEX").is_some());
    }

    /// A shape must not be claimed by two allowances, or capacity accounting
    /// would depend on iteration order.
    #[test]
    fn allowances_do_not_overlap() {
        let snapshot = PolicySnapshot::load().expect("snapshot");
        let mut seen: Vec<String> = Vec::new();
        for allowance in &snapshot.compute_allowances {
            for shape in &allowance.shapes {
                let lowered = shape.to_ascii_lowercase();
                assert!(
                    !seen.contains(&lowered),
                    "{shape} appears in more than one allowance"
                );
                seen.push(lowered);
            }
        }
    }

    /// The limit hints must resolve to real services and must never be empty
    /// for the compute allowances, or `account limits` would highlight nothing.
    #[test]
    fn limit_hints_cover_the_compute_allowances() {
        let snapshot = PolicySnapshot::load().expect("snapshot");
        for allowance in &snapshot.compute_allowances {
            let hints = allowance
                .service_limits
                .as_ref()
                .unwrap_or_else(|| panic!("{} needs service-limit hints", allowance.id));
            assert_eq!(hints.service, "compute");
            assert!(
                !hints.names().is_empty(),
                "{} names no limit at all",
                allowance.id
            );
        }

        assert!(snapshot.highlights_limit("compute", "standard-a1-core-count"));
        assert!(snapshot.highlights_limit("vcn", "vcn-count"));
        assert!(!snapshot.highlights_limit("compute", "vcn-count"));
        assert!(!snapshot.highlights_limit("compute", "some-unrelated-limit"));
    }

    #[test]
    fn limit_services_are_deduplicated() {
        let snapshot = PolicySnapshot::load().expect("snapshot");
        let services = snapshot.limit_services();
        let mut sorted = services.clone();
        sorted.dedup();
        assert_eq!(services, sorted);
        assert!(services.contains(&"compute"));
    }

    #[test]
    fn citation_identifies_version_and_date() {
        let snapshot = PolicySnapshot::load().expect("snapshot");
        let citation = snapshot.citation();
        assert!(citation.contains(&snapshot.verified_on));
        assert!(citation.contains("policy snapshot"));
    }
}
