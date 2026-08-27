//! Resolving an instance and gathering everything attached to it.
//!
//! `vm info`, `vm ip`, `vm ssh`, `vm net show`, `vm net audit`, `vm net
//! open`/`close`, and `vm delete` all need the same picture: the instance, its
//! primary VNIC, the subnet, the NSGs, the subnet's Security Lists, the route
//! table, and the internet gateway. Gathering it once here keeps the traversal
//! and its failure handling in one place.
//!
//! Partial failure is normal. A tenancy may grant `instance_inspect` and not
//! `vcn_read`, so every network read degrades to a warning rather than
//! aborting the command. What must never happen is a *silent* degrade: an
//! unreadable Security List means exposure is under-reported, and the caller
//! is told so.

use crate::{
    commands::context::CommandContext,
    domain::{
        exposure::{EffectiveExposure, ExposureInputs, compute},
        ocid::Ocid,
    },
    error::{Error, Result},
    oci::{
        block_storage::{BlockStorageApi, BootVolume},
        compute::{ComputeApi, Instance, Shape},
        network::{
            InternetGateway, NetworkApi, NetworkSecurityGroup, RouteTable, SecurityList,
            SecurityRule, Subnet, Vnic,
        },
    },
};

/// An instance plus every network object that governs it.
#[derive(Debug, Clone)]
pub struct InstanceNetwork {
    pub vnic: Option<Vnic>,
    pub subnet: Option<Subnet>,
    pub nsgs: Vec<(NetworkSecurityGroup, Vec<SecurityRule>)>,
    pub security_lists: Vec<SecurityList>,
    pub route_table: Option<RouteTable>,
    pub internet_gateway: Option<InternetGateway>,
    /// What could not be read, and what that means for the answer.
    pub warnings: Vec<String>,
}

impl InstanceNetwork {
    /// Effective inbound exposure, when enough was readable to compute it.
    #[must_use]
    pub fn exposure(&self) -> Option<EffectiveExposure> {
        let vnic = self.vnic.as_ref()?;
        let subnet = self.subnet.as_ref()?;
        let mut exposure = compute(&ExposureInputs {
            vnic,
            subnet,
            nsgs: &self.nsgs,
            security_lists: &self.security_lists,
            route_table: self.route_table.as_ref(),
            internet_gateway: self.internet_gateway.as_ref(),
        });
        // Carry the gathering warnings into the result, so a report never
        // presents a partial picture as a complete one.
        exposure.warnings.extend(self.warnings.iter().cloned());
        Some(exposure)
    }

    /// The reason exposure could not be computed, if it could not.
    #[must_use]
    pub fn unavailable_reason(&self) -> Option<&'static str> {
        if self.vnic.is_none() {
            Some("the instance's primary VNIC could not be read")
        } else if self.subnet.is_none() {
            Some("the instance's subnet could not be read")
        } else {
            None
        }
    }
}

/// Resolve a user-supplied reference to exactly one instance.
///
/// Accepts a full OCID (fetched directly, so an instance in another
/// compartment still resolves) or a display name (matched against the
/// tenancy's active instances, refusing an ambiguous match).
pub async fn resolve_instance(context: &CommandContext, reference: &str) -> Result<Instance> {
    let compute = ComputeApi::new(context.client());

    if let Ok(ocid) = reference.parse::<Ocid>() {
        if ocid.resource_type() != "instance" {
            return Err(Error::invalid_input(format!(
                "`{reference}` is a {} OCID, not an instance OCID",
                ocid.resource_type()
            ))
            .with_remediation("pass an instance OCID or its display name"));
        }
        return compute.get_instance(ocid.as_str()).await;
    }

    let instances = compute.list_instances(context.tenancy()).await?;
    crate::commands::vm::resolve(reference, &instances).cloned()
}

/// Shapes offered in this region, used to classify an instance's billing.
pub async fn list_shapes(context: &CommandContext) -> Result<Vec<Shape>> {
    ComputeApi::new(context.client())
        .list_shapes(context.tenancy(), None)
        .await
}

/// Gather everything attached to one instance.
pub async fn load_network(context: &CommandContext, instance: &Instance) -> InstanceNetwork {
    let compute = ComputeApi::new(context.client());
    let network = NetworkApi::new(context.client());
    let mut warnings = Vec::new();

    let attachments = match compute
        .list_vnic_attachments(context.tenancy(), Some(&instance.id))
        .await
    {
        Ok(attachments) => attachments,
        Err(error) => {
            warnings.push(format!(
                "could not list VNIC attachments, so no network information is available: {error}"
            ));
            Vec::new()
        }
    };

    // The primary VNIC is the one that carries the instance's addresses. OCI
    // does not mark it on the attachment, so each candidate is fetched and the
    // primary picked from the VNIC itself.
    let mut vnic = None;
    for attachment in attachments
        .iter()
        .filter(|attachment| attachment.lifecycle_state.eq_ignore_ascii_case("ATTACHED"))
    {
        let Some(vnic_id) = attachment.vnic_id.as_deref() else {
            continue;
        };
        match network.get_vnic(vnic_id).await {
            Ok(candidate) => {
                let is_primary = candidate.is_primary.unwrap_or(false);
                if is_primary || vnic.is_none() {
                    vnic = Some(candidate);
                }
                if is_primary {
                    break;
                }
            }
            Err(error) => warnings.push(format!("could not read VNIC {vnic_id}: {error}")),
        }
    }

    let Some(vnic) = vnic else {
        if warnings.is_empty() {
            warnings.push(
                "this instance has no attached VNIC, so it has no network exposure".to_owned(),
            );
        }
        return InstanceNetwork {
            vnic: None,
            subnet: None,
            nsgs: Vec::new(),
            security_lists: Vec::new(),
            route_table: None,
            internet_gateway: None,
            warnings,
        };
    };

    let mut nsgs = Vec::new();
    for nsg_id in &vnic.nsg_ids {
        match network.get_nsg(nsg_id).await {
            Ok(nsg) => {
                let rules = match network.list_nsg_rules(nsg_id).await {
                    Ok(rules) => rules,
                    Err(error) => {
                        warnings.push(format!(
                            "could not read the rules of NSG {nsg_id}, so its allowances are \
                             missing from this report: {error}"
                        ));
                        Vec::new()
                    }
                };
                nsgs.push((nsg, rules));
            }
            Err(error) => warnings.push(format!("could not read NSG {nsg_id}: {error}")),
        }
    }

    let subnet = match vnic.subnet_id.as_deref() {
        Some(subnet_id) => match network.get_subnet(subnet_id).await {
            Ok(subnet) => Some(subnet),
            Err(error) => {
                warnings.push(format!(
                    "could not read subnet {subnet_id}, so subnet-wide Security List rules are \
                     missing from this report: {error}"
                ));
                None
            }
        },
        None => {
            warnings.push("OCI did not report a subnet for this VNIC".to_owned());
            None
        }
    };

    let mut security_lists = Vec::new();
    let mut route_table = None;
    let mut internet_gateway = None;

    if let Some(subnet) = &subnet {
        for list_id in &subnet.security_list_ids {
            match network.get_security_list(list_id).await {
                Ok(list) => security_lists.push(list),
                Err(error) => warnings.push(format!(
                    "could not read Security List {list_id}, so exposure may be under-reported: \
                     {error}"
                )),
            }
        }

        if let Some(table_id) = subnet.route_table_id.as_deref() {
            match network.get_route_table(table_id).await {
                Ok(table) => {
                    // Only an internet gateway makes the instance reachable
                    // from outside; other default-route targets (a NAT or
                    // service gateway) carry no inbound reachability.
                    let gateway_id = table
                        .route_rules
                        .iter()
                        .filter(|rule| rule.is_default_ipv4())
                        .filter_map(|rule| rule.network_entity_id.clone())
                        .find(|entity| entity.contains(".internetgateway."));
                    if let Some(gateway_id) = gateway_id {
                        match network.get_internet_gateway(&gateway_id).await {
                            Ok(gateway) => internet_gateway = Some(gateway),
                            Err(error) => warnings.push(format!(
                                "could not read internet gateway {gateway_id}: {error}"
                            )),
                        }
                    }
                    route_table = Some(table);
                }
                Err(error) => warnings.push(format!(
                    "could not read route table {table_id}, so internet reachability is \
                     incomplete: {error}"
                )),
            }
        }
    }

    InstanceNetwork {
        vnic: Some(vnic),
        subnet,
        nsgs,
        security_lists,
        route_table,
        internet_gateway,
        warnings,
    }
}

/// The boot volume attached to an instance, if it can be read.
pub async fn load_boot_volume(
    context: &CommandContext,
    instance: &Instance,
) -> (Option<BootVolume>, Vec<String>) {
    let storage = BlockStorageApi::new(context.client());
    let mut warnings = Vec::new();

    let attachments = match storage
        .list_boot_volume_attachments(
            context.tenancy(),
            instance.availability_domain.as_deref(),
            Some(&instance.id),
        )
        .await
    {
        Ok(attachments) => attachments,
        Err(error) => {
            warnings.push(format!(
                "could not list boot volume attachments, so the boot volume's fate cannot be \
                 shown: {error}"
            ));
            return (None, warnings);
        }
    };

    let Some(attachment) = attachments.iter().find(|a| a.is_attached()) else {
        return (None, warnings);
    };

    match storage.get_boot_volume(&attachment.boot_volume_id).await {
        Ok(volume) => (Some(volume), warnings),
        Err(error) => {
            warnings.push(format!(
                "could not read boot volume {}: {error}",
                attachment.boot_volume_id
            ));
            (None, warnings)
        }
    }
}
