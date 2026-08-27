//! Boot volumes and their attachments.
//!
//! Terminating an instance does not necessarily delete its boot volume, and a
//! retained boot volume keeps consuming the Always Free storage allowance
//! silently. `vm delete` therefore has to know about the volume before it acts,
//! and say what will happen to it.
//!
//! Block Volume is part of Core Services, so it shares the `iaas` host and the
//! 20160918 API version with compute and networking.

use serde::Deserialize;

use crate::{
    domain::{ocid::Ocid, ownership::Tags},
    error::Result,
    oci::{
        client::OciClient,
        endpoint::Service,
        identity::{encode_path_segment, encode_query_value},
    },
};

/// One entry of `GET /20160918/bootVolumeAttachments`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BootVolumeAttachment {
    pub id: String,
    pub instance_id: String,
    pub boot_volume_id: String,
    #[serde(default)]
    pub availability_domain: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    pub lifecycle_state: String,
}

impl BootVolumeAttachment {
    /// Whether the volume is currently attached to its instance.
    #[must_use]
    pub fn is_attached(&self) -> bool {
        self.lifecycle_state.eq_ignore_ascii_case("ATTACHED")
    }
}

/// `GET /20160918/bootVolumes/{bootVolumeId}`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BootVolume {
    pub id: String,
    #[serde(default)]
    pub compartment_id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub availability_domain: Option<String>,
    /// Size in GB. OCI returns it as a JSON number in a string-free field.
    #[serde(default)]
    pub size_in_g_bs: Option<i64>,
    #[serde(default)]
    pub lifecycle_state: Option<String>,
    #[serde(default)]
    pub time_created: Option<String>,
    #[serde(default)]
    pub image_id: Option<String>,
    #[serde(default)]
    pub freeform_tags: Tags,
}

impl BootVolume {
    /// Whether this volume still occupies storage allowance.
    #[must_use]
    pub fn consumes_storage(&self) -> bool {
        !self
            .lifecycle_state
            .as_deref()
            .is_some_and(|state| matches!(state, "TERMINATED" | "TERMINATING"))
    }

    #[must_use]
    pub fn label(&self) -> &str {
        self.display_name.as_deref().unwrap_or(&self.id)
    }
}

/// Boot-volume operations.
#[derive(Debug)]
pub struct BlockStorageApi<'a> {
    client: &'a OciClient,
}

impl<'a> BlockStorageApi<'a> {
    #[must_use]
    pub fn new(client: &'a OciClient) -> Self {
        Self { client }
    }

    /// Boot-volume attachments, optionally narrowed to one instance.
    ///
    /// OCI requires `availabilityDomain` unless `instanceId` is supplied, so
    /// callers that know the instance should pass it and omit the domain.
    pub async fn list_boot_volume_attachments(
        &self,
        compartment: &Ocid,
        availability_domain: Option<&str>,
        instance_id: Option<&str>,
    ) -> Result<Vec<BootVolumeAttachment>> {
        let mut path = format!(
            "/bootVolumeAttachments?compartmentId={}",
            encode_query_value(compartment.as_str())
        );
        if let Some(domain) = availability_domain {
            path.push_str(&format!(
                "&availabilityDomain={}",
                encode_query_value(domain)
            ));
        }
        if let Some(instance) = instance_id {
            path.push_str(&format!("&instanceId={}", encode_query_value(instance)));
        }
        self.client
            .list_all(Service::Core, &path, "ListBootVolumeAttachments")
            .await
    }

    pub async fn get_boot_volume(&self, boot_volume_id: &str) -> Result<BootVolume> {
        let path = format!("/bootVolumes/{}", encode_path_segment(boot_volume_id));
        Ok(self
            .client
            .get_json::<BootVolume>(Service::Core, &path, "GetBootVolume")
            .await?
            .body)
    }

    /// Boot volumes in one availability domain.
    pub async fn list_boot_volumes(
        &self,
        compartment: &Ocid,
        availability_domain: &str,
    ) -> Result<Vec<BootVolume>> {
        let path = format!(
            "/bootVolumes?compartmentId={}&availabilityDomain={}",
            encode_query_value(compartment.as_str()),
            encode_query_value(availability_domain)
        );
        self.client
            .list_all(Service::Core, &path, "ListBootVolumes")
            .await
    }

    /// Delete a boot volume.
    ///
    /// Only ever reached from a plan whose ownership check proved oci-free
    /// created the volume, and only when the user chose deletion explicitly.
    pub async fn delete_boot_volume(&self, boot_volume_id: &str) -> Result<()> {
        let path = format!("/bootVolumes/{}", encode_path_segment(boot_volume_id));
        self.client
            .delete(Service::Core, &path, "DeleteBootVolume")
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::{BootVolume, BootVolumeAttachment};

    const ATTACHMENTS: &str = include_str!("../../tests/fixtures/oci/boot_volume_attachments.json");
    const VOLUME: &str = include_str!("../../tests/fixtures/oci/boot_volume.json");

    #[test]
    fn decodes_boot_volume_attachments() {
        let attachments: Vec<BootVolumeAttachment> =
            serde_json::from_str(ATTACHMENTS).expect("attachments fixture");
        assert_eq!(attachments.len(), 1);
        assert!(attachments[0].is_attached());
        assert!(
            attachments[0]
                .boot_volume_id
                .starts_with("ocid1.bootvolume.")
        );
    }

    #[test]
    fn decodes_a_boot_volume() {
        let volume: BootVolume = serde_json::from_str(VOLUME).expect("volume fixture");
        assert_eq!(volume.size_in_g_bs, Some(50));
        assert_eq!(volume.label(), "free-arm-1 (Boot Volume)");
        assert!(volume.consumes_storage());
        assert_eq!(
            volume
                .freeform_tags
                .get("oci-free:managed")
                .map(String::as_str),
            Some("created")
        );
    }

    /// A terminated volume has released its storage, so it must not be counted
    /// against the allowance.
    #[test]
    fn a_terminated_volume_releases_storage() {
        let volume: BootVolume = serde_json::from_str(
            r#"{"id":"ocid1.bootvolume.oc1.iad.a","lifecycleState":"TERMINATED"}"#,
        )
        .expect("volume");
        assert!(!volume.consumes_storage());
    }

    /// A volume whose state OCI did not report must be assumed to still occupy
    /// storage; assuming the opposite would understate usage.
    #[test]
    fn an_unreported_state_still_counts_as_occupied() {
        let volume: BootVolume =
            serde_json::from_str(r#"{"id":"ocid1.bootvolume.oc1.iad.a"}"#).expect("volume");
        assert!(volume.consumes_storage());
        assert_eq!(volume.label(), "ocid1.bootvolume.oc1.iad.a");
    }
}
