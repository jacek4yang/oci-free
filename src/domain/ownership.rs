//! Proving who owns a resource.
//!
//! Deleting the wrong VCN, subnet, or NSG is the most damaging mistake this
//! tool could make, and OCI offers no "created by" field. So oci-free stamps
//! every resource it touches with freeform tags and proves ownership from
//! those tags alone.
//!
//! A display name is never evidence. Names are user-editable and easy to
//! collide with by accident, so a VCN called `oci-free-vcn` that carries no
//! ownership tag is treated as somebody else's and is never adopted, renamed,
//! reconfigured, or deleted.
//!
//! Four outcomes, and only one of them permits deletion:
//!
//! | [`Ownership`]      | oci-free may reconfigure | oci-free may delete |
//! |--------------------|--------------------------|---------------------|
//! | `Created`          | yes                      | yes                 |
//! | `Reused`           | yes, narrowly            | never               |
//! | `UserOwned`        | never                    | never               |
//! | `Unknown`          | never                    | never               |

use std::collections::BTreeMap;

use serde::Serialize;

/// Tag key marking a resource oci-free created or adopted.
pub const TAG_MANAGED: &str = "oci-free:managed";
/// Tag key naming what the resource is for, for example `instance-nsg`.
pub const TAG_ROLE: &str = "oci-free:role";
/// Tag key binding a resource to the instance it serves.
pub const TAG_INSTANCE: &str = "oci-free:instance";
/// Tag key recording the oci-free version that created the resource.
pub const TAG_VERSION: &str = "oci-free:version";

/// Value of [`TAG_MANAGED`] on a resource oci-free created itself.
pub const MANAGED_CREATED: &str = "created";
/// Value of [`TAG_MANAGED`] on a pre-existing resource oci-free adopted.
pub const MANAGED_REUSED: &str = "reused";

/// Role value for the per-instance Network Security Group.
pub const ROLE_INSTANCE_NSG: &str = "instance-nsg";
/// Role value for the managed VCN.
pub const ROLE_VCN: &str = "vcn";
/// Role value for the managed subnet.
pub const ROLE_SUBNET: &str = "subnet";
/// Role value for the managed internet gateway.
pub const ROLE_INTERNET_GATEWAY: &str = "internet-gateway";
/// Role value for a managed compute instance.
pub const ROLE_INSTANCE: &str = "instance";

/// Freeform tags as OCI returns them.
pub type Tags = BTreeMap<String, String>;

/// How confident oci-free is that it owns a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Ownership {
    /// oci-free created it. Only this value permits automated deletion.
    Created,
    /// A pre-existing resource oci-free adopted. Never deleted automatically.
    Reused,
    /// No oci-free tags at all: somebody else's resource.
    UserOwned,
    /// Tagged, but not in a way this build recognises. Fails closed.
    Unknown,
}

impl Ownership {
    /// Whether oci-free may delete this resource without an explicit override.
    #[must_use]
    pub fn permits_deletion(self) -> bool {
        self == Self::Created
    }

    /// Whether oci-free may modify this resource as part of normal operation.
    ///
    /// A reused resource can have a rule added to it, but not be destroyed.
    #[must_use]
    pub fn permits_modification(self) -> bool {
        matches!(self, Self::Created | Self::Reused)
    }

    /// Stable machine-readable identifier used in JSON output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Reused => "reused",
            Self::UserOwned => "user_owned",
            Self::Unknown => "unknown",
        }
    }

    /// A sentence explaining the classification and its consequence.
    #[must_use]
    pub fn explain(self) -> &'static str {
        match self {
            Self::Created => "created by oci-free, so it can be cleaned up automatically",
            Self::Reused => {
                "adopted by oci-free but created elsewhere, so it is never deleted automatically"
            }
            Self::UserOwned => "not managed by oci-free, so it is left untouched",
            Self::Unknown => {
                "carries an oci-free ownership tag this build does not recognise, so it is \
                 treated as not owned"
            }
        }
    }
}

/// Classify a resource from its freeform tags.
#[must_use]
pub fn classify(tags: &Tags) -> Ownership {
    match tags.get(TAG_MANAGED).map(String::as_str) {
        Some(MANAGED_CREATED) => Ownership::Created,
        Some(MANAGED_REUSED) => Ownership::Reused,
        // Tagged with something this build does not understand. It could have
        // been written by a newer oci-free, or by hand. Either way, refuse to
        // treat it as ours.
        Some(_) => Ownership::Unknown,
        None => {
            // A stray role or instance tag without the managed marker is also
            // not proof of ownership.
            if tags.contains_key(TAG_ROLE) || tags.contains_key(TAG_INSTANCE) {
                Ownership::Unknown
            } else {
                Ownership::UserOwned
            }
        }
    }
}

/// The tags to stamp on a resource oci-free is creating.
#[must_use]
pub fn created_tags(role: &str, instance_id: Option<&str>) -> Tags {
    tags_for(MANAGED_CREATED, role, instance_id)
}

/// The tags to stamp on a pre-existing resource oci-free is adopting.
#[must_use]
pub fn reused_tags(role: &str, instance_id: Option<&str>) -> Tags {
    tags_for(MANAGED_REUSED, role, instance_id)
}

fn tags_for(managed: &str, role: &str, instance_id: Option<&str>) -> Tags {
    let mut tags = Tags::new();
    tags.insert(TAG_MANAGED.to_owned(), managed.to_owned());
    tags.insert(TAG_ROLE.to_owned(), role.to_owned());
    tags.insert(TAG_VERSION.to_owned(), env!("CARGO_PKG_VERSION").to_owned());
    if let Some(instance) = instance_id {
        tags.insert(TAG_INSTANCE.to_owned(), instance.to_owned());
    }
    tags
}

/// Whether these tags mark a resource dedicated to `instance_id`.
#[must_use]
pub fn belongs_to_instance(tags: &Tags, instance_id: &str) -> bool {
    tags.get(TAG_INSTANCE).is_some_and(|id| id == instance_id)
}

/// The role recorded on a resource, if any.
#[must_use]
pub fn role_of(tags: &Tags) -> Option<&str> {
    tags.get(TAG_ROLE).map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::{
        MANAGED_CREATED, MANAGED_REUSED, Ownership, ROLE_INSTANCE_NSG, TAG_INSTANCE, TAG_MANAGED,
        TAG_ROLE, TAG_VERSION, Tags, belongs_to_instance, classify, created_tags, reused_tags,
        role_of,
    };

    fn tags(pairs: &[(&str, &str)]) -> Tags {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn a_created_resource_may_be_deleted() {
        let ownership = classify(&tags(&[(TAG_MANAGED, MANAGED_CREATED)]));
        assert_eq!(ownership, Ownership::Created);
        assert!(ownership.permits_deletion());
        assert!(ownership.permits_modification());
    }

    /// The central cleanup-safety rule: adopting somebody's existing VCN must
    /// never put it in scope for deletion.
    #[test]
    fn a_reused_resource_may_be_modified_but_never_deleted() {
        let ownership = classify(&tags(&[(TAG_MANAGED, MANAGED_REUSED)]));
        assert_eq!(ownership, Ownership::Reused);
        assert!(!ownership.permits_deletion());
        assert!(ownership.permits_modification());
    }

    #[test]
    fn an_untagged_resource_is_the_users() {
        let ownership = classify(&Tags::new());
        assert_eq!(ownership, Ownership::UserOwned);
        assert!(!ownership.permits_deletion());
        assert!(!ownership.permits_modification());
    }

    /// A newer oci-free, or a hand-edited tag, must fail closed rather than
    /// being read as "ours".
    #[test]
    fn an_unrecognised_managed_value_fails_closed() {
        for value in ["1", "true", "yes", "", "CREATED"] {
            let ownership = classify(&tags(&[(TAG_MANAGED, value)]));
            assert_eq!(
                ownership,
                Ownership::Unknown,
                "{value:?} must not be read as ownership"
            );
            assert!(!ownership.permits_deletion());
            assert!(!ownership.permits_modification());
        }
    }

    /// The most important negative case in the whole module: a name that looks
    /// like ours proves nothing.
    #[test]
    fn a_lookalike_name_is_never_ownership_evidence() {
        // These are the tags on a resource a user happened to call
        // "oci-free-vcn". No managed marker, so it stays theirs.
        let ownership = classify(&tags(&[("Name", "oci-free-vcn")]));
        assert_eq!(ownership, Ownership::UserOwned);
        assert!(!ownership.permits_deletion());
    }

    /// Half-written tags are suspicious, not proof.
    #[test]
    fn a_role_tag_alone_is_not_ownership() {
        let ownership = classify(&tags(&[(TAG_ROLE, ROLE_INSTANCE_NSG)]));
        assert_eq!(ownership, Ownership::Unknown);
        assert!(!ownership.permits_deletion());
    }

    #[test]
    fn created_tags_carry_role_version_and_instance() {
        let stamped = created_tags(ROLE_INSTANCE_NSG, Some("ocid1.instance.oc1.iad.a"));
        assert_eq!(classify(&stamped), Ownership::Created);
        assert_eq!(role_of(&stamped), Some(ROLE_INSTANCE_NSG));
        assert_eq!(
            stamped.get(TAG_VERSION).map(String::as_str),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(
            stamped.get(TAG_INSTANCE).map(String::as_str),
            Some("ocid1.instance.oc1.iad.a")
        );
        assert!(belongs_to_instance(&stamped, "ocid1.instance.oc1.iad.a"));
        assert!(!belongs_to_instance(&stamped, "ocid1.instance.oc1.iad.b"));
    }

    #[test]
    fn reused_tags_round_trip_to_reused() {
        let stamped = reused_tags(super::ROLE_VCN, None);
        assert_eq!(classify(&stamped), Ownership::Reused);
        assert!(!stamped.contains_key(TAG_INSTANCE));
    }

    #[test]
    fn machine_identifiers_are_stable() {
        assert_eq!(Ownership::Created.as_str(), "created");
        assert_eq!(Ownership::Reused.as_str(), "reused");
        assert_eq!(Ownership::UserOwned.as_str(), "user_owned");
        assert_eq!(Ownership::Unknown.as_str(), "unknown");
        for ownership in [
            Ownership::Created,
            Ownership::Reused,
            Ownership::UserOwned,
            Ownership::Unknown,
        ] {
            assert!(!ownership.explain().is_empty());
        }
    }
}
