//! `oci-free vm list` and instance resolution.

use serde::Serialize;

use crate::{
    commands::{context::CommandContext, discovery},
    domain::{
        free::{Evidence, FreeClassification},
        launch::format_quantity,
        ownership::{Ownership, classify},
    },
    error::{Error, Result},
    oci::compute::{ComputeApi, Instance, Shape},
};

/// One row of `vm list`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VmSummary {
    pub name: String,
    /// Full OCID. Machine output needs it to address the instance.
    pub id: String,
    pub lifecycle_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shape: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ocpus: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_gb: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability_domain: Option<String>,
    /// Free Tier classification for this instance's shape.
    pub free_classification: String,
    /// Who owns this instance, proven from its freeform tags.
    ///
    /// Never inferred from a display name: a user can rename anything, and
    /// mistaking a user's instance for a managed one would put it in scope for
    /// automated cleanup. See `domain::ownership`.
    pub ownership: Ownership,
    /// Whether oci-free created this instance, and may therefore clean it up.
    pub managed_by_oci_free: bool,
}

/// The `vm list` payload.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VmList {
    pub region: String,
    pub instances: Vec<VmSummary>,
    pub warnings: Vec<String>,
}

/// Build a summary row for one instance.
#[must_use]
pub fn summarise(
    instance: &Instance,
    shapes: &[Shape],
    policy: &crate::policy::engine::PolicyEngine,
) -> VmSummary {
    let shape_record = instance
        .shape
        .as_deref()
        .and_then(|name| shapes.iter().find(|s| s.shape.eq_ignore_ascii_case(name)));

    // With no shape record there is no billing evidence, so the classification
    // is Unknown rather than absent. Unknown is the safe reading.
    let classification = shape_record.map_or(FreeClassification::Unknown, |shape| {
        policy.classify_shape(shape).classification
    });

    VmSummary {
        name: instance.label().to_owned(),
        id: instance.id.clone(),
        lifecycle_state: instance.lifecycle_state.clone(),
        shape: instance.shape.clone(),
        ocpus: instance
            .shape_config
            .and_then(|c| c.ocpus)
            .or_else(|| shape_record.and_then(|s| s.ocpus)),
        memory_gb: instance
            .shape_config
            .and_then(|c| c.memory_in_g_bs)
            .or_else(|| shape_record.and_then(|s| s.memory_in_g_bs)),
        availability_domain: instance.availability_domain.clone(),
        free_classification: classification_label(classification).to_owned(),
        ownership: classify(&instance.freeform_tags),
        managed_by_oci_free: classify(&instance.freeform_tags).permits_deletion(),
    }
}

/// Stable machine-readable classification names used in JSON output.
#[must_use]
pub fn classification_label(classification: FreeClassification) -> &'static str {
    match classification {
        FreeClassification::VerifiedAlwaysFree => "verified_always_free",
        FreeClassification::LimitedFree => "limited_free",
        FreeClassification::Paid => "paid",
        FreeClassification::Unknown => "unknown",
    }
}

/// Resolve a user-supplied instance reference to exactly one instance.
///
/// Accepts a full OCID or a display name. A name matching several instances is
/// an error: silently picking one could start, stop, or terminate the wrong
/// machine.
pub fn resolve<'a>(reference: &str, instances: &'a [Instance]) -> Result<&'a Instance> {
    if let Some(found) = instances.iter().find(|i| i.id == reference) {
        return Ok(found);
    }

    // Only consider live instances by name: a terminated instance keeps its
    // display name, and matching it would be a confusing false positive.
    let matches: Vec<&Instance> = instances
        .iter()
        .filter(|i| i.consumes_capacity())
        .filter(|i| i.display_name.as_deref() == Some(reference))
        .collect();

    match matches.as_slice() {
        [only] => Ok(only),
        [] => Err(Error::not_found(format!("no instance named `{reference}`"))
            .with_context("the name matched no active instance in this tenancy and region")
            .with_remediation("run `oci-free vm list` to see the available instances")),
        several => {
            let detail = several
                .iter()
                .map(|i| format!("  {} ({})", i.id, i.lifecycle_state))
                .collect::<Vec<_>>()
                .join("\n");
            Err(
                Error::ambiguous(format!("`{reference}` matches {} instances", several.len()))
                    .with_context(format!(
                        "oci-free will not guess which one you meant:\n{detail}"
                    ))
                    .with_remediation(
                        "re-run the command with the instance OCID instead of the name",
                    ),
            )
        }
    }
}

/// List instances.
pub async fn list(context: &CommandContext) -> Result<VmList> {
    let compute = ComputeApi::new(context.client());
    let tenancy = context.tenancy();

    let instances = compute.list_instances(tenancy).await?;
    let shapes = compute.list_shapes(tenancy, None).await?;

    let mut warnings = Vec::new();
    let summaries: Vec<VmSummary> = instances
        .iter()
        .filter(|instance| instance.consumes_capacity())
        .map(|instance| summarise(instance, &shapes, context.policy()))
        .collect();

    if summaries.iter().any(|s| s.free_classification == "unknown") {
        warnings.push(
            "some instances use a shape with no recognised billing classification; their Free \
             Tier status could not be proven"
                .to_owned(),
        );
    }

    Ok(VmList {
        region: context.config().region.to_string(),
        instances: summaries,
        warnings,
    })
}

/// Render for a terminal.
#[must_use]
pub fn render_human(list: &VmList) -> String {
    if list.instances.is_empty() {
        return format!("No active instances in {}.\n", list.region);
    }

    let mut out = format!("Instances in {}\n\n", list.region);
    for instance in &list.instances {
        let size = match (instance.ocpus, instance.memory_gb) {
            (Some(ocpus), Some(memory)) => format!("{ocpus:.0} OCPU / {memory:.0} GB"),
            _ => "size unknown".to_owned(),
        };
        out.push_str(&format!(
            "{}  {}\n  {}  {}  {}{}\n",
            instance.name,
            instance.lifecycle_state,
            instance.shape.as_deref().unwrap_or("shape unknown"),
            size,
            instance.free_classification,
            if instance.managed_by_oci_free {
                "  [managed by oci-free]"
            } else {
                ""
            }
        ));
    }
    for warning in &list.warnings {
        out.push_str(&format!("\nwarning: {warning}\n"));
    }
    out
}

#[cfg(test)]
#[path = "vm_tests.rs"]
mod vm_tests;

// ---------------------------------------------------------------------------
// vm info
// ---------------------------------------------------------------------------

/// The `vm info` payload.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VmInfo {
    pub name: String,
    pub id: String,
    pub region: String,
    pub lifecycle_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shape: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ocpus: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_gb: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_created: Option<String>,
    /// The image the instance was launched from, resolved to a name where the
    /// tenancy can still read it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<ImageInfo>,
    /// Who owns this instance, proven from tags.
    pub ownership: Ownership,
    /// Free Tier evidence for the instance's shape.
    pub free: FreeEvidence,
    /// Networking, when it could be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkInfo>,
    /// The boot volume, when it could be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_volume: Option<BootVolumeInfo>,
    pub warnings: Vec<String>,
}

/// The image an instance came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImageInfo {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operating_system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operating_system_version: Option<String>,
}

/// Free Tier evidence for one instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FreeEvidence {
    pub classification: String,
    /// OCI's live billing classification for the shape, when the shape is
    /// still offered in this region.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_billing_type: Option<String>,
    /// The policy-snapshot allowance that covers the shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowance_id: Option<String>,
    pub evidence: Vec<Evidence>,
}

/// The instance's effective networking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkInfo {
    pub vnic_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,
    pub subnet_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet_name: Option<String>,
    pub vcn_id: String,
    pub internet_reachable: bool,
    pub reachability_reason: String,
    /// NSGs attached to the VNIC, with their proven ownership.
    pub network_security_groups: Vec<NsgInfo>,
    /// A one-line summary of every effective ingress rule.
    pub effective_ingress: Vec<String>,
}

/// One NSG attached to an instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NsgInfo {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub ownership: Ownership,
    pub ingress_rule_count: usize,
}

/// The instance's boot volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BootVolumeInfo {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_gb: Option<i64>,
    pub ownership: Ownership,
}

/// Describe one instance in full.
pub async fn info(context: &CommandContext, reference: &str) -> Result<VmInfo> {
    let instance = discovery::resolve_instance(context, reference).await?;
    let shapes = discovery::list_shapes(context).await.unwrap_or_default();
    let network = discovery::load_network(context, &instance).await;
    let (boot_volume, mut warnings) = discovery::load_boot_volume(context, &instance).await;

    let shape_record = instance
        .shape
        .as_deref()
        .and_then(|name| shapes.iter().find(|s| s.shape.eq_ignore_ascii_case(name)));

    let assessment = shape_record.map(|shape| context.policy().classify_shape(shape));
    let allowance_id = instance
        .shape
        .as_deref()
        .and_then(|name| context.policy().snapshot().allowance_for(name))
        .map(|allowance| allowance.id.clone());

    let free = FreeEvidence {
        classification: classification_label(
            assessment
                .as_ref()
                .map_or(FreeClassification::Unknown, |a| a.classification),
        )
        .to_owned(),
        live_billing_type: shape_record.map(|shape| shape.billing_type.as_str().to_owned()),
        allowance_id,
        evidence: assessment
            .as_ref()
            .map(|a| a.evidence.clone())
            .unwrap_or_default(),
    };
    if let Some(assessment) = &assessment {
        warnings.extend(assessment.warnings.iter().cloned());
    } else if instance.shape.is_some() {
        warnings.push(
            "this instance's shape is no longer offered in this region, so OCI reports no live \
             billing classification for it"
                .to_owned(),
        );
    }

    let image = match instance.image_id.as_deref() {
        Some(image_id) => {
            match ComputeApi::new(context.client()).get_image(image_id).await {
                Ok(image) => Some(ImageInfo {
                    id: image.id,
                    name: image.display_name,
                    operating_system: image.operating_system,
                    operating_system_version: image.operating_system_version,
                }),
                // A platform image the tenancy can no longer read is normal
                // once Oracle retires it; keep the OCID rather than dropping it.
                Err(_) => Some(ImageInfo {
                    id: image_id.to_owned(),
                    name: None,
                    operating_system: None,
                    operating_system_version: None,
                }),
            }
        }
        None => None,
    };

    let exposure = network.exposure();
    let network_info = exposure.as_ref().map(|exposure| NetworkInfo {
        vnic_id: exposure.vnic_id.clone(),
        private_ip: exposure.private_ip.clone(),
        public_ip: exposure.internet.public_ip.clone(),
        subnet_id: exposure.subnet_id.clone(),
        subnet_name: exposure.subnet_name.clone(),
        vcn_id: exposure.vcn_id.clone(),
        internet_reachable: exposure.internet.reachable,
        reachability_reason: exposure.internet.reason.clone(),
        network_security_groups: exposure
            .attached_nsgs
            .iter()
            .map(|nsg| NsgInfo {
                id: nsg.id.clone(),
                name: nsg.name.clone(),
                ownership: nsg.ownership,
                ingress_rule_count: nsg.ingress_rule_count,
            })
            .collect(),
        effective_ingress: exposure
            .rules
            .iter()
            .map(crate::domain::exposure::EffectiveRule::summary)
            .collect(),
    });
    match &exposure {
        Some(exposure) => warnings.extend(exposure.warnings.iter().cloned()),
        None => warnings.extend(network.warnings.iter().cloned()),
    }

    Ok(VmInfo {
        name: instance.label().to_owned(),
        id: instance.id.clone(),
        region: context.region().to_string(),
        lifecycle_state: instance.lifecycle_state.clone(),
        availability_domain: instance.availability_domain.clone(),
        shape: instance.shape.clone(),
        ocpus: instance
            .shape_config
            .and_then(|config| config.ocpus)
            .or_else(|| shape_record.and_then(|shape| shape.ocpus)),
        memory_gb: instance
            .shape_config
            .and_then(|config| config.memory_in_g_bs)
            .or_else(|| shape_record.and_then(|shape| shape.memory_in_g_bs)),
        time_created: instance.time_created.clone(),
        image,
        ownership: classify(&instance.freeform_tags),
        free,
        network: network_info,
        boot_volume: boot_volume.map(|volume| BootVolumeInfo {
            ownership: classify(&volume.freeform_tags),
            id: volume.id,
            name: volume.display_name,
            size_gb: volume.size_in_g_bs,
        }),
        warnings,
    })
}

/// Render `vm info` for a terminal.
#[must_use]
pub fn render_info(info: &VmInfo) -> String {
    let mut out = format!("{} ({})\n\n", info.name, info.lifecycle_state);

    out.push_str(&format!("  OCID           {}\n", info.id));
    out.push_str(&format!("  region         {}\n", info.region));
    if let Some(domain) = &info.availability_domain {
        out.push_str(&format!("  domain         {domain}\n"));
    }
    let size = match (info.ocpus, info.memory_gb) {
        (Some(ocpus), Some(memory)) => format!(
            " ({} OCPU, {} GB)",
            format_quantity(ocpus),
            format_quantity(memory)
        ),
        _ => String::new(),
    };
    out.push_str(&format!(
        "  shape          {}{size}\n",
        info.shape.as_deref().unwrap_or("unknown")
    ));
    if let Some(created) = &info.time_created {
        out.push_str(&format!("  created        {created}\n"));
    }
    if let Some(image) = &info.image {
        let described = match (&image.operating_system, &image.operating_system_version) {
            (Some(os), Some(version)) => format!("{os} {version}"),
            _ => image.name.clone().unwrap_or_else(|| image.id.clone()),
        };
        out.push_str(&format!("  image          {described}\n"));
    }
    out.push_str(&format!("  ownership      {}\n", info.ownership.explain()));

    out.push_str("\n  free tier\n");
    out.push_str(&format!(
        "    classification {}\n",
        info.free.classification
    ));
    if let Some(billing) = &info.free.live_billing_type {
        out.push_str(&format!("    OCI billing    {billing}\n"));
    }
    if let Some(allowance) = &info.free.allowance_id {
        out.push_str(&format!("    allowance      {allowance}\n"));
    }
    for evidence in &info.free.evidence {
        out.push_str(&format!("    {}: {}\n", evidence.source, evidence.detail));
    }

    if let Some(network) = &info.network {
        out.push_str("\n  network\n");
        out.push_str(&format!(
            "    private IP     {}\n",
            network.private_ip.as_deref().unwrap_or("none")
        ));
        out.push_str(&format!(
            "    public IP      {}\n",
            network.public_ip.as_deref().unwrap_or("none")
        ));
        out.push_str(&format!(
            "    subnet         {}\n",
            network.subnet_name.as_deref().unwrap_or(&network.subnet_id)
        ));
        out.push_str(&format!(
            "    reachable      {}\n                   {}\n",
            if network.internet_reachable {
                "yes, from the internet"
            } else {
                "no"
            },
            network.reachability_reason
        ));
        for nsg in &network.network_security_groups {
            out.push_str(&format!(
                "    NSG            {} ({}, {} ingress rule(s))\n",
                nsg.name.as_deref().unwrap_or(&nsg.id),
                nsg.ownership.as_str(),
                nsg.ingress_rule_count
            ));
        }
        if network.effective_ingress.is_empty() {
            out.push_str("    ingress        nothing is allowed in\n");
        }
        for rule in &network.effective_ingress {
            out.push_str(&format!("    ingress        {rule}\n"));
        }
    }

    if let Some(volume) = &info.boot_volume {
        out.push_str("\n  boot volume\n");
        out.push_str(&format!(
            "    {}{}\n    {}\n",
            volume.name.as_deref().unwrap_or(&volume.id),
            volume
                .size_gb
                .map(|size| format!(" ({size} GB)"))
                .unwrap_or_default(),
            volume.ownership.explain()
        ));
    }

    for warning in &info.warnings {
        out.push_str(&format!("\nwarning: {warning}\n"));
    }
    out
}

// ---------------------------------------------------------------------------
// vm ip
// ---------------------------------------------------------------------------

/// The `vm ip` payload.
///
/// `public_ip` is `null` and `has_public_ip` is `false` when the instance has
/// no public address. That is an ordinary state, not an error, and the two
/// fields exist so a script never has to infer absence from a missing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VmIp {
    pub instance: String,
    pub instance_id: String,
    pub region: String,
    pub has_public_ip: bool,
    pub public_ip: Option<String>,
    pub private_ip: Option<String>,
    pub warnings: Vec<String>,
}

/// Report an instance's addresses.
pub async fn ip(context: &CommandContext, reference: &str) -> Result<VmIp> {
    let instance = discovery::resolve_instance(context, reference).await?;
    let network = discovery::load_network(context, &instance).await;

    let vnic = network.vnic.as_ref();
    let public_ip = vnic
        .and_then(|vnic| vnic.public_ip.clone())
        .filter(|ip| !ip.trim().is_empty());
    let private_ip = vnic.and_then(|vnic| vnic.private_ip.clone());

    let mut warnings = network.warnings.clone();
    if vnic.is_none() {
        warnings.push(
            "this instance has no readable VNIC, so neither address could be determined".to_owned(),
        );
    }

    Ok(VmIp {
        instance: instance.label().to_owned(),
        instance_id: instance.id.clone(),
        region: context.region().to_string(),
        has_public_ip: public_ip.is_some(),
        public_ip,
        private_ip,
        warnings,
    })
}

/// Render `vm ip` for a terminal.
///
/// Prints the bare address when there is one, so `$(oci-free vm ip web)` is
/// usable in a shell.
#[must_use]
pub fn render_ip(ip: &VmIp) -> String {
    let mut out = String::new();
    match &ip.public_ip {
        Some(address) => out.push_str(&format!("{address}\n")),
        None => {
            out.push_str(&format!("{} has no public IP address.\n", ip.instance));
            if let Some(private) = &ip.private_ip {
                out.push_str(&format!(
                    "Its private address is {private}, reachable only from inside the VCN.\n"
                ));
            }
        }
    }
    for warning in &ip.warnings {
        out.push_str(&format!("warning: {warning}\n"));
    }
    out
}
