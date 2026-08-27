//! Compute adapter: instances, shapes, images, and VNIC attachments.
//!
//! The most important type here is [`ShapeBillingType`]. The OCI Core Services
//! `Shape` model carries a `billingType` field whose values are `ALWAYS_FREE`,
//! `LIMITED_FREE`, and `PAID`. That is live, machine-readable billing evidence
//! straight from OCI, which is exactly what CLAUDE.md requires instead of
//! matching historical shape names.
//!
//! Any value this client does not recognise decodes to
//! [`ShapeBillingType::Unknown`], which the policy engine treats as blocking.
//! A new Oracle billing category must never be silently read as "free".

use serde::{Deserialize, Serialize};

use crate::{
    domain::ocid::Ocid,
    error::Result,
    oci::{
        client::OciClient,
        endpoint::Service,
        identity::{encode_path_segment, encode_query_value},
    },
};

/// OCI's own billing classification for a compute shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum ShapeBillingType {
    /// Always Free. The only value that can justify an unattended mutation.
    #[serde(rename = "ALWAYS_FREE")]
    AlwaysFree,
    /// Free only within a promotional or trial allowance.
    #[serde(rename = "LIMITED_FREE")]
    LimitedFree,
    /// Billed.
    #[serde(rename = "PAID")]
    Paid,
    /// Anything else, including the field being absent.
    ///
    /// Deserialized via `#[serde(other)]` so a billing category Oracle adds
    /// after this release fails closed rather than being mistaken for free.
    #[serde(other)]
    Unknown,
}

impl ShapeBillingType {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AlwaysFree => "ALWAYS_FREE",
            Self::LimitedFree => "LIMITED_FREE",
            Self::Paid => "PAID",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Bounds for a flexible shape's OCPU count.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OcpuOptions {
    #[serde(default)]
    pub min: Option<f64>,
    #[serde(default)]
    pub max: Option<f64>,
}

/// Bounds for a flexible shape's memory.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryOptions {
    #[serde(default)]
    pub min_in_g_bs: Option<f64>,
    #[serde(default)]
    pub max_in_g_bs: Option<f64>,
    #[serde(default)]
    pub min_per_ocpu_in_gbs: Option<f64>,
    #[serde(default)]
    pub max_per_ocpu_in_gbs: Option<f64>,
}

/// One entry of `GET /20160918/shapes`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Shape {
    /// Shape name, for example `VM.Standard.A1.Flex`.
    pub shape: String,
    /// OCI's billing classification. Absent on older responses, which decodes
    /// to `Unknown` and therefore blocks.
    #[serde(default = "unknown_billing")]
    pub billing_type: ShapeBillingType,
    #[serde(default)]
    pub ocpus: Option<f64>,
    #[serde(default)]
    pub memory_in_g_bs: Option<f64>,
    #[serde(default)]
    pub processor_description: Option<String>,
    #[serde(default)]
    pub is_flexible: Option<bool>,
    #[serde(default)]
    pub ocpu_options: Option<OcpuOptions>,
    #[serde(default)]
    pub memory_options: Option<MemoryOptions>,
}

fn unknown_billing() -> ShapeBillingType {
    ShapeBillingType::Unknown
}

impl Shape {
    /// Whether OCI itself reports this shape as Always Free.
    #[must_use]
    pub fn is_always_free(&self) -> bool {
        self.billing_type == ShapeBillingType::AlwaysFree
    }

    /// Whether the shape takes an OCPU/memory configuration at launch.
    #[must_use]
    pub fn is_flexible(&self) -> bool {
        self.is_flexible.unwrap_or(false)
    }
}

/// The shape configuration actually applied to an instance.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstanceShapeConfig {
    #[serde(default)]
    pub ocpus: Option<f64>,
    #[serde(default)]
    pub memory_in_g_bs: Option<f64>,
}

/// One entry of `GET /20160918/instances`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Instance {
    pub id: String,
    pub compartment_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    /// `PROVISIONING`, `RUNNING`, `STOPPED`, `TERMINATED`, and so on.
    pub lifecycle_state: String,
    #[serde(default)]
    pub availability_domain: Option<String>,
    #[serde(default)]
    pub shape: Option<String>,
    #[serde(default)]
    pub shape_config: Option<InstanceShapeConfig>,
    #[serde(default)]
    pub time_created: Option<String>,
    #[serde(default)]
    pub image_id: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    /// Freeform tags, used to recognise resources oci-free manages.
    #[serde(default)]
    pub freeform_tags: std::collections::BTreeMap<String, String>,
}

impl Instance {
    /// Whether this instance still consumes Free Tier capacity.
    ///
    /// A terminated instance releases its allowance; a stopped one does not,
    /// because the shape remains allocated.
    #[must_use]
    pub fn consumes_capacity(&self) -> bool {
        !matches!(self.lifecycle_state.as_str(), "TERMINATED" | "TERMINATING")
    }

    /// The name shown to users, falling back to the OCID.
    #[must_use]
    pub fn label(&self) -> &str {
        self.display_name.as_deref().unwrap_or(&self.id)
    }
}

/// One entry of `GET /20160918/images`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Image {
    pub id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub operating_system: Option<String>,
    #[serde(default)]
    pub operating_system_version: Option<String>,
    #[serde(default)]
    pub lifecycle_state: Option<String>,
    #[serde(default)]
    pub time_created: Option<String>,
}

/// One entry of `GET /20160918/vnicAttachments`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VnicAttachment {
    pub id: String,
    pub instance_id: String,
    #[serde(default)]
    pub vnic_id: Option<String>,
    #[serde(default)]
    pub subnet_id: Option<String>,
    pub lifecycle_state: String,
}

/// Read-only compute operations.
#[derive(Debug)]
pub struct ComputeApi<'a> {
    client: &'a OciClient,
}

impl<'a> ComputeApi<'a> {
    #[must_use]
    pub fn new(client: &'a OciClient) -> Self {
        Self { client }
    }

    /// List instances in a compartment.
    pub async fn list_instances(&self, compartment: &Ocid) -> Result<Vec<Instance>> {
        let path = format!(
            "/instances?compartmentId={}",
            encode_query_value(compartment.as_str())
        );
        self.client
            .list_all(Service::Core, &path, "ListInstances")
            .await
    }

    /// Fetch a single instance.
    pub async fn get_instance(&self, instance: &str) -> Result<Instance> {
        let path = format!("/instances/{}", encode_path_segment(instance));
        Ok(self
            .client
            .get_json::<Instance>(Service::Core, &path, "GetInstance")
            .await?
            .body)
    }

    /// List shapes available to a compartment.
    ///
    /// The result carries OCI's `billingType`, which is the evidence the policy
    /// engine uses instead of matching shape names.
    pub async fn list_shapes(
        &self,
        compartment: &Ocid,
        availability_domain: Option<&str>,
    ) -> Result<Vec<Shape>> {
        let mut path = format!(
            "/shapes?compartmentId={}",
            encode_query_value(compartment.as_str())
        );
        if let Some(domain) = availability_domain {
            path.push_str(&format!(
                "&availabilityDomain={}",
                encode_query_value(domain)
            ));
        }
        self.client
            .list_all(Service::Core, &path, "ListShapes")
            .await
    }

    /// List images available to a compartment, newest first.
    ///
    /// Image OCIDs are never hard-coded: Oracle replaces platform images
    /// regularly, so a pinned OCID would rot into a launch failure.
    pub async fn list_images(
        &self,
        compartment: &Ocid,
        operating_system: Option<&str>,
        shape: Option<&str>,
    ) -> Result<Vec<Image>> {
        let mut path = format!(
            "/images?compartmentId={}&sortBy=TIMECREATED&sortOrder=DESC&lifecycleState=AVAILABLE",
            encode_query_value(compartment.as_str())
        );
        if let Some(os) = operating_system {
            path.push_str(&format!("&operatingSystem={}", encode_query_value(os)));
        }
        if let Some(shape) = shape {
            path.push_str(&format!("&shape={}", encode_query_value(shape)));
        }
        self.client
            .list_all(Service::Core, &path, "ListImages")
            .await
    }

    /// List VNIC attachments, optionally narrowed to one instance.
    pub async fn list_vnic_attachments(
        &self,
        compartment: &Ocid,
        instance: Option<&str>,
    ) -> Result<Vec<VnicAttachment>> {
        let mut path = format!(
            "/vnicAttachments?compartmentId={}",
            encode_query_value(compartment.as_str())
        );
        if let Some(instance) = instance {
            path.push_str(&format!("&instanceId={}", encode_query_value(instance)));
        }
        self.client
            .list_all(Service::Core, &path, "ListVnicAttachments")
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::{Image, Instance, Shape, ShapeBillingType, VnicAttachment};

    const INSTANCES_JSON: &str = include_str!("../../tests/fixtures/oci/instances.json");
    const SHAPES_JSON: &str = include_str!("../../tests/fixtures/oci/shapes.json");
    const IMAGES_JSON: &str = include_str!("../../tests/fixtures/oci/images.json");
    const ATTACHMENTS_JSON: &str = include_str!("../../tests/fixtures/oci/vnic_attachments.json");

    fn shapes() -> Vec<Shape> {
        serde_json::from_str(SHAPES_JSON).expect("shapes fixture")
    }

    #[test]
    fn decodes_instances() {
        let instances: Vec<Instance> =
            serde_json::from_str(INSTANCES_JSON).expect("instances fixture");
        assert_eq!(instances.len(), 3);

        let running = &instances[0];
        assert_eq!(running.display_name.as_deref(), Some("free-arm-1"));
        assert_eq!(running.lifecycle_state, "RUNNING");
        assert_eq!(running.shape.as_deref(), Some("VM.Standard.A1.Flex"));
        let config = running.shape_config.expect("shape config");
        assert_eq!(config.ocpus, Some(2.0));
        assert_eq!(config.memory_in_g_bs, Some(12.0));
    }

    /// A stopped instance still holds its shape allocation, so it must count
    /// against Free Tier capacity. Only termination releases it.
    #[test]
    fn only_terminated_instances_release_capacity() {
        let instances: Vec<Instance> =
            serde_json::from_str(INSTANCES_JSON).expect("instances fixture");
        let by_state = |state: &str| {
            instances
                .iter()
                .find(|i| i.lifecycle_state == state)
                .unwrap_or_else(|| panic!("fixture needs a {state} instance"))
        };

        assert!(by_state("RUNNING").consumes_capacity());
        assert!(
            by_state("STOPPED").consumes_capacity(),
            "a stopped instance still occupies its shape allocation"
        );
        assert!(!by_state("TERMINATED").consumes_capacity());
    }

    #[test]
    fn decodes_shape_billing_types() {
        let shapes = shapes();
        let find = |name: &str| {
            shapes
                .iter()
                .find(|s| s.shape == name)
                .unwrap_or_else(|| panic!("fixture needs {name}"))
        };

        assert_eq!(
            find("VM.Standard.A1.Flex").billing_type,
            ShapeBillingType::AlwaysFree
        );
        assert_eq!(
            find("VM.Standard.E2.1.Micro").billing_type,
            ShapeBillingType::AlwaysFree
        );
        assert_eq!(
            find("VM.Standard3.Flex").billing_type,
            ShapeBillingType::Paid
        );
    }

    /// The central fail-closed property of the shape adapter: a billing value
    /// this client has never seen must not read as free.
    #[test]
    fn unrecognised_billing_types_decode_as_unknown() {
        let json = r#"[{"shape":"VM.Future.X","billingType":"SOME_NEW_CATEGORY"}]"#;
        let shapes: Vec<Shape> = serde_json::from_str(json).expect("should decode");
        assert_eq!(shapes[0].billing_type, ShapeBillingType::Unknown);
        assert!(!shapes[0].is_always_free());
    }

    /// An older response with no `billingType` at all must also fail closed.
    #[test]
    fn a_missing_billing_type_is_unknown() {
        let json = r#"[{"shape":"VM.Legacy.X","ocpus":1.0}]"#;
        let shapes: Vec<Shape> = serde_json::from_str(json).expect("should decode");
        assert_eq!(shapes[0].billing_type, ShapeBillingType::Unknown);
        assert!(!shapes[0].is_always_free());
    }

    #[test]
    fn decodes_flexible_shape_bounds() {
        let shapes = shapes();
        let arm = shapes
            .iter()
            .find(|s| s.shape == "VM.Standard.A1.Flex")
            .expect("arm shape");

        assert!(arm.is_flexible());
        let ocpu = arm.ocpu_options.expect("ocpu options");
        assert_eq!(ocpu.min, Some(1.0));
        assert_eq!(ocpu.max, Some(80.0));
        let memory = arm.memory_options.expect("memory options");
        assert_eq!(memory.min_in_g_bs, Some(1.0));
        assert_eq!(memory.max_in_g_bs, Some(512.0));

        let micro = shapes
            .iter()
            .find(|s| s.shape == "VM.Standard.E2.1.Micro")
            .expect("micro shape");
        assert!(!micro.is_flexible(), "the micro shape is fixed-size");
    }

    #[test]
    fn decodes_images_newest_first() {
        let images: Vec<Image> = serde_json::from_str(IMAGES_JSON).expect("images fixture");
        assert_eq!(images.len(), 3);
        assert_eq!(images[0].operating_system.as_deref(), Some("Oracle Linux"));
        assert_eq!(images[0].operating_system_version.as_deref(), Some("9"));
        assert!(images[0].id.starts_with("ocid1.image."));
    }

    #[test]
    fn decodes_vnic_attachments() {
        let attachments: Vec<VnicAttachment> =
            serde_json::from_str(ATTACHMENTS_JSON).expect("attachments fixture");
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].lifecycle_state, "ATTACHED");
        assert!(attachments[0].vnic_id.is_some());
    }

    #[test]
    fn instance_label_falls_back_to_the_ocid() {
        let json = r#"{"id":"ocid1.instance.oc1.iad.aaa","compartmentId":"ocid1.tenancy.oc1..b","lifecycleState":"RUNNING"}"#;
        let instance: Instance = serde_json::from_str(json).expect("instance");
        assert_eq!(instance.label(), "ocid1.instance.oc1.iad.aaa");
    }
}
