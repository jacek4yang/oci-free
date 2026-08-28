//! Managed network setup and reuse.
//!
//! `vm create` needs a VCN, a subnet, an internet gateway, and a route to it.
//! This module finds an existing oci-free-managed set, or plans to create one,
//! and never does either of two dangerous things:
//!
//! * it never adopts a resource on the strength of its name. A VCN called
//!   `oci-free-vcn` that carries no ownership tag belongs to somebody else and
//!   is left alone — see `domain::ownership`;
//! * it never reconfigures a resource it reused beyond what the instance needs.
//!   A reused VCN keeps its CIDR, its DNS label, and its other subnets.
//!
//! Reused managed resources are still checked for the topology `vm create`
//! assumes. A managed VCN whose subnet was later made private, or whose gateway
//! was disabled, is reported rather than silently producing an instance nobody
//! can reach.

use serde::Serialize;

use crate::{
    commands::{context::CommandContext, vmnet::retry_token},
    domain::{
        ownership::{
            Ownership, ROLE_INTERNET_GATEWAY, ROLE_SUBNET, ROLE_VCN, classify, created_tags,
        },
        plan::{Approval, ChangeKind, PlannedChange},
    },
    error::{Error, ErrorKind, Result},
    oci::network::{
        CreateInternetGateway, CreateSubnet, CreateVcn, InternetGateway, NetworkApi,
        RouteRuleUpdate, Subnet, UpdateRouteTable, Vcn,
    },
};

/// CIDR of the VCN oci-free creates.
///
/// A /16 out of RFC 1918 space, chosen to be large enough never to need
/// resizing and unlikely to collide with a home or office network.
pub const MANAGED_VCN_CIDR: &str = "10.0.0.0/16";
/// CIDR of the subnet oci-free creates inside that VCN.
pub const MANAGED_SUBNET_CIDR: &str = "10.0.0.0/24";
/// Display name of the managed VCN.
pub const MANAGED_VCN_NAME: &str = "oci-free-vcn";
/// Display name of the managed subnet.
pub const MANAGED_SUBNET_NAME: &str = "oci-free-subnet";
/// Display name of the managed internet gateway.
pub const MANAGED_GATEWAY_NAME: &str = "oci-free-internet-gateway";

/// The network `vm create` will launch into.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagedNetwork {
    pub vcn_id: String,
    pub vcn_ownership: Ownership,
    pub subnet_id: String,
    pub subnet_ownership: Ownership,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internet_gateway_id: Option<String>,
    /// Whether the subnet routes 0.0.0.0/0 through a working gateway.
    pub internet_routed: bool,
    /// Whether the subnet permits a public IP at all.
    pub public_addressing_allowed: bool,
    pub warnings: Vec<String>,
}

/// What was found, and what would have to be created.
#[derive(Debug, Clone)]
pub struct NetworkPlan {
    /// Present when a complete managed set already exists.
    pub existing: Option<ManagedNetwork>,
    /// Plan steps describing what will happen either way.
    pub changes: Vec<PlannedChange>,
    pub warnings: Vec<String>,
}

/// Resources this operation created, so a failure can compensate precisely.
///
/// Only objects recorded here are ever deleted during recovery. A resource that
/// already existed is never touched, whatever goes wrong afterwards.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CreatedResources {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vcn_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internet_gateway_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nsg_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
}

impl CreatedResources {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// A human list of everything created, newest first.
    #[must_use]
    pub fn describe(&self) -> Vec<String> {
        let mut described = Vec::new();
        if let Some(id) = &self.instance_id {
            described.push(format!("compute instance {id}"));
        }
        if let Some(id) = &self.nsg_id {
            described.push(format!("network security group {id}"));
        }
        if let Some(id) = &self.internet_gateway_id {
            described.push(format!("internet gateway {id}"));
        }
        if let Some(id) = &self.subnet_id {
            described.push(format!("subnet {id}"));
        }
        if let Some(id) = &self.vcn_id {
            described.push(format!("VCN {id}"));
        }
        described
    }
}

/// Find the managed network, or describe what creating one would involve.
pub async fn plan(context: &CommandContext) -> Result<NetworkPlan> {
    let api = NetworkApi::new(context.client());
    let vcns = api.list_vcns(context.tenancy()).await?;
    let mut warnings = Vec::new();

    // Ownership, never the name. A VCN called `oci-free-vcn` with no tag is
    // somebody else's and must not be adopted.
    let managed_vcn = vcns
        .iter()
        .find(|vcn| classify(&vcn.freeform_tags).permits_modification());

    if let Some(lookalike) = vcns.iter().find(|vcn| {
        vcn.display_name.as_deref() == Some(MANAGED_VCN_NAME)
            && !classify(&vcn.freeform_tags).permits_modification()
    }) {
        warnings.push(format!(
            "a VCN named {MANAGED_VCN_NAME} exists ({}) but carries no oci-free ownership tag, so \
             it is treated as yours and will not be used or modified",
            lookalike.id
        ));
    }

    let Some(vcn) = managed_vcn else {
        return Ok(NetworkPlan {
            existing: None,
            changes: create_changes(),
            warnings,
        });
    };

    let subnets = api.list_subnets(context.tenancy(), &vcn.id).await?;
    let managed_subnet = subnets
        .iter()
        .find(|subnet| classify(&subnet.freeform_tags).permits_modification());

    let Some(subnet) = managed_subnet else {
        warnings.push(format!(
            "the managed VCN {} has no oci-free-managed subnet, so one will be created in it",
            vcn.id
        ));
        let mut changes = create_changes();
        changes[0] = reuse_change(
            "VCN",
            vcn.display_name.as_deref().unwrap_or(&vcn.id),
            &vcn.id,
        )
        .with_ownership(classify(&vcn.freeform_tags));
        return Ok(NetworkPlan {
            existing: None,
            changes,
            warnings,
        });
    };

    // A reused managed set still has to have the topology `vm create` assumes.
    let (gateway_id, routed, mut topology_warnings) = verify_topology(context, vcn, subnet).await;
    warnings.append(&mut topology_warnings);

    let network = ManagedNetwork {
        vcn_id: vcn.id.clone(),
        vcn_ownership: classify(&vcn.freeform_tags),
        subnet_id: subnet.id.clone(),
        subnet_ownership: classify(&subnet.freeform_tags),
        internet_gateway_id: gateway_id,
        internet_routed: routed,
        public_addressing_allowed: !subnet.is_private(),
        warnings: warnings.clone(),
    };

    Ok(NetworkPlan {
        changes: vec![
            reuse_change(
                "VCN",
                vcn.display_name.as_deref().unwrap_or(&vcn.id),
                &vcn.id,
            )
            .with_ownership(network.vcn_ownership),
            reuse_change(
                "subnet",
                subnet.display_name.as_deref().unwrap_or(&subnet.id),
                &subnet.id,
            )
            .with_ownership(network.subnet_ownership),
        ],
        existing: Some(network),
        warnings,
    })
}

/// Check that a reused managed network still looks like one oci-free built.
async fn verify_topology(
    context: &CommandContext,
    vcn: &Vcn,
    subnet: &Subnet,
) -> (Option<String>, bool, Vec<String>) {
    let api = NetworkApi::new(context.client());
    let mut warnings = Vec::new();

    if subnet.is_private() {
        warnings.push(format!(
            "the managed subnet {} now forbids public IP addresses, so an instance launched into \
             it cannot be reached from the internet",
            subnet.id
        ));
    }

    let gateways = api
        .list_internet_gateways(context.tenancy(), &vcn.id)
        .await
        .unwrap_or_default();
    let usable_gateway = gateways.iter().find(|gateway| gateway.is_usable());

    if let Some(disabled) = gateways.iter().find(|gateway| !gateway.is_usable()) {
        warnings.push(format!(
            "internet gateway {} exists but is not enabled",
            disabled.id
        ));
    }

    let Some(table_id) = subnet.route_table_id.as_deref() else {
        warnings.push("the managed subnet has no route table".to_owned());
        return (
            usable_gateway.map(|gateway| gateway.id.clone()),
            false,
            warnings,
        );
    };

    let routed = match api.get_route_table(table_id).await {
        Ok(table) => table.route_rules.iter().any(|rule| {
            rule.is_default_ipv4()
                && rule
                    .network_entity_id
                    .as_deref()
                    .is_some_and(|entity| Some(entity) == usable_gateway.map(|g| g.id.as_str()))
        }),
        Err(error) => {
            warnings.push(format!(
                "the managed route table could not be read: {error}"
            ));
            false
        }
    };

    if !routed {
        warnings.push(
            "the managed subnet does not route 0.0.0.0/0 through an enabled internet gateway, so \
             a new instance would have no internet connectivity"
                .to_owned(),
        );
    }

    (
        usable_gateway.map(|gateway| gateway.id.clone()),
        routed,
        warnings,
    )
}

fn create_changes() -> Vec<PlannedChange> {
    vec![
        PlannedChange::new(
            ChangeKind::Create,
            "VCN",
            MANAGED_VCN_NAME,
            format!("{MANAGED_VCN_CIDR}, tagged as created by oci-free"),
        ),
        PlannedChange::new(
            ChangeKind::Create,
            "subnet",
            MANAGED_SUBNET_NAME,
            format!("{MANAGED_SUBNET_CIDR}, public addressing allowed"),
        ),
        PlannedChange::new(
            ChangeKind::Create,
            "internet gateway",
            MANAGED_GATEWAY_NAME,
            "enabled",
        ),
        PlannedChange::new(
            ChangeKind::Modify,
            "route table",
            "the VCN's default route table",
            format!("0.0.0.0/0 routed through {MANAGED_GATEWAY_NAME}"),
        )
        .with_before("no default route")
        .with_note("only the managed VCN's own route table is changed"),
    ]
}

fn reuse_change(kind: &str, name: &str, id: &str) -> PlannedChange {
    PlannedChange::new(ChangeKind::Reuse, kind, name, "unchanged").with_id(id)
}

/// Create the managed VCN, subnet, gateway, and route.
///
/// Every object created is recorded in `created` before the next step runs, so
/// a failure part-way through can be compensated precisely.
pub async fn provision(
    context: &CommandContext,
    created: &mut CreatedResources,
    approval: &Approval,
) -> Result<ManagedNetwork> {
    debug_assert!(approval.operation().starts_with("vm."));
    let api = NetworkApi::new(context.client());
    let compartment = context.tenancy().as_str().to_owned();
    let seed = context.tenancy().as_str();

    let vcn: Vcn = api
        .create_vcn(
            &CreateVcn {
                compartment_id: compartment.clone(),
                cidr_block: MANAGED_VCN_CIDR.to_owned(),
                display_name: MANAGED_VCN_NAME.to_owned(),
                dns_label: Some("ocifree".to_owned()),
                freeform_tags: created_tags(ROLE_VCN, None),
            },
            &retry_token("vcn", seed),
        )
        .await?;
    created.vcn_id = Some(vcn.id.clone());

    let gateway: InternetGateway = api
        .create_internet_gateway(
            &CreateInternetGateway {
                compartment_id: compartment.clone(),
                vcn_id: vcn.id.clone(),
                display_name: MANAGED_GATEWAY_NAME.to_owned(),
                is_enabled: true,
                freeform_tags: created_tags(ROLE_INTERNET_GATEWAY, None),
            },
            &retry_token("igw", seed),
        )
        .await?;
    created.internet_gateway_id = Some(gateway.id.clone());

    // Route before the subnet, so the subnet is never briefly usable with no
    // path off the VCN.
    let route_table_id = vcn.default_route_table_id.clone().ok_or_else(|| {
        Error::malformed_response("OCI created a VCN without a default route table")
            .with_context("oci-free cannot route the subnet without one")
    })?;
    api.update_route_table(
        &route_table_id,
        &UpdateRouteTable {
            route_rules: vec![RouteRuleUpdate {
                destination: "0.0.0.0/0".to_owned(),
                destination_type: "CIDR_BLOCK".to_owned(),
                network_entity_id: gateway.id.clone(),
                description: Some("oci-free managed: default route to the internet".to_owned()),
            }],
        },
    )
    .await?;

    let subnet: Subnet = api
        .create_subnet(
            &CreateSubnet {
                compartment_id: compartment,
                vcn_id: vcn.id.clone(),
                cidr_block: MANAGED_SUBNET_CIDR.to_owned(),
                display_name: MANAGED_SUBNET_NAME.to_owned(),
                dns_label: Some("free".to_owned()),
                route_table_id: Some(route_table_id),
                prohibit_public_ip_on_vnic: false,
                freeform_tags: created_tags(ROLE_SUBNET, None),
            },
            &retry_token("subnet", seed),
        )
        .await?;
    created.subnet_id = Some(subnet.id.clone());

    Ok(ManagedNetwork {
        vcn_id: vcn.id,
        vcn_ownership: Ownership::Created,
        subnet_id: subnet.id,
        subnet_ownership: Ownership::Created,
        internet_gateway_id: Some(gateway.id),
        internet_routed: true,
        public_addressing_allowed: true,
        warnings: Vec::new(),
    })
}

pub(crate) async fn detach_gateway_routes(
    context: &CommandContext,
    vcn_id: &str,
    gateway_id: &str,
) -> Result<()> {
    let api = NetworkApi::new(context.client());
    let vcn = api.get_vcn(vcn_id).await?;
    let route_table_id = vcn.default_route_table_id.ok_or_else(|| {
        Error::malformed_response("the managed VCN has no default route table during rollback")
            .with_context(format!("VCN {vcn_id}"))
    })?;
    let table = api.get_route_table(&route_table_id).await?;
    let mut remaining = Vec::new();

    for rule in table.route_rules {
        if rule.network_entity_id.as_deref() == Some(gateway_id) {
            continue;
        }
        let (Some(destination), Some(destination_type), Some(network_entity_id)) = (
            rule.destination,
            rule.destination_type,
            rule.network_entity_id,
        ) else {
            return Err(Error::malformed_response(
                "the managed route table contains a rule that cannot be preserved safely during rollback",
            )
            .with_context(format!("route table {route_table_id}")));
        };
        remaining.push(RouteRuleUpdate {
            destination,
            destination_type,
            network_entity_id,
            description: rule.description,
        });
    }

    api.update_route_table(
        &route_table_id,
        &UpdateRouteTable {
            route_rules: remaining,
        },
    )
    .await?;
    Ok(())
}

/// Delete, in reverse order, only what this operation created.
///
/// Returns whatever could not be removed, so the caller can report exactly what
/// is left behind rather than claiming a clean rollback.
pub async fn compensate(
    context: &CommandContext,
    created: &CreatedResources,
) -> (CreatedResources, Vec<String>) {
    let api = NetworkApi::new(context.client());
    let mut retained = CreatedResources::default();
    let mut problems = Vec::new();

    // Reverse creation order: a subnet cannot be deleted while the VCN is gone,
    // and a gateway cannot be deleted while a route still points at it.
    if let Some(id) = &created.nsg_id
        && let Err(error) = api.delete_nsg(id).await
    {
        retained.nsg_id = Some(id.clone());
        problems.push(format!(
            "network security group {id} could not be removed: {error}"
        ));
    }
    if let Some(id) = &created.subnet_id
        && let Err(error) = api.delete_subnet(id).await
    {
        retained.subnet_id = Some(id.clone());
        problems.push(format!("subnet {id} could not be removed: {error}"));
    }
    if let Some(id) = &created.internet_gateway_id {
        let mut deletion = api.delete_internet_gateway(id).await;
        let route_conflict = matches!(
            &deletion,
            Err(error) if error.kind() == ErrorKind::Conflict
        );
        if route_conflict && let Some(vcn_id) = created.vcn_id.as_deref() {
            match detach_gateway_routes(context, vcn_id, id).await {
                Ok(()) => deletion = api.delete_internet_gateway(id).await,
                Err(error) => problems.push(format!(
                    "route references to internet gateway {id} could not be removed: {error}"
                )),
            }
        }
        if let Err(error) = deletion {
            retained.internet_gateway_id = Some(id.clone());
            problems.push(format!(
                "internet gateway {id} could not be removed: {error}"
            ));
        }
    }
    if let Some(id) = &created.vcn_id
        && let Err(error) = api.delete_vcn(id).await
    {
        retained.vcn_id = Some(id.clone());
        problems.push(format!("VCN {id} could not be removed: {error}"));
    }

    // An instance is never deleted by compensation: terminating a machine that
    // may already be serving traffic is a bigger risk than leaving it, so it is
    // always reported for the user to decide.
    if let Some(id) = &created.instance_id {
        retained.instance_id = Some(id.clone());
    }

    (retained, problems)
}

#[cfg(test)]
#[path = "network_setup_tests.rs"]
mod network_setup_tests;

#[cfg(test)]
mod rollback_regression_tests {
    use serde_json::json;

    use super::*;
    use crate::testing::mock_oci::{MockOci, Reply, TENANCY};

    #[tokio::test]
    async fn a_gateway_route_conflict_is_detached_and_the_delete_is_retried() {
        let vcn_id = "ocid1.vcn.oc1.iad.rollback";
        let subnet_id = "ocid1.subnet.oc1.iad.rollback";
        let gateway_id = "ocid1.internetgateway.oc1.iad.rollback";
        let route_table_id = "ocid1.routetable.oc1.iad.rollback";

        let mock = MockOci::builder()
            .reply("DELETE", "/subnets/", Reply::new(204, ""))
            .route(
                "DELETE",
                "/internetGateways/",
                vec![
                    Reply::new(
                        409,
                        r#"{"code":"Conflict","message":"route table references gateway"}"#,
                    )
                    .header("opc-request-id", "req-conflict"),
                    Reply::new(204, ""),
                ],
            )
            .get(
                &format!("/vcns/{vcn_id}"),
                &json!({
                    "id": vcn_id,
                    "compartmentId": TENANCY,
                    "defaultRouteTableId": route_table_id,
                    "lifecycleState": "AVAILABLE"
                }),
            )
            .get(
                &format!("/routeTables/{route_table_id}"),
                &json!({
                    "id": route_table_id,
                    "vcnId": vcn_id,
                    "routeRules": [{
                        "destination": "0.0.0.0/0",
                        "destinationType": "CIDR_BLOCK",
                        "networkEntityId": gateway_id,
                        "description": "oci-free managed: default route to the internet"
                    }],
                    "lifecycleState": "AVAILABLE"
                }),
            )
            .reply(
                "PUT",
                &format!("/routeTables/{route_table_id}"),
                Reply::json(&json!({
                    "id": route_table_id,
                    "vcnId": vcn_id,
                    "routeRules": [],
                    "lifecycleState": "AVAILABLE"
                })),
            )
            .reply("DELETE", "/vcns/", Reply::new(204, ""))
            .start()
            .await;

        let created = CreatedResources {
            vcn_id: Some(vcn_id.to_owned()),
            subnet_id: Some(subnet_id.to_owned()),
            internet_gateway_id: Some(gateway_id.to_owned()),
            ..CreatedResources::default()
        };

        let (retained, problems) = compensate(
            &CommandContext::for_tests(mock.client(), "us-ashburn-1"),
            &created,
        )
        .await;
        assert!(retained.is_empty(), "retained: {:?}", retained.describe());
        assert!(problems.is_empty(), "problems: {problems:?}");

        let writes = mock.writes();
        let route_update = writes
            .iter()
            .find(|request| request.method() == "PUT")
            .expect("rollback must remove the gateway route");
        assert_eq!(
            route_update.json_body().expect("route body")["routeRules"],
            json!([])
        );
        assert_eq!(
            writes
                .iter()
                .filter(|request| request.target().contains("/internetGateways/"))
                .count(),
            2,
            "the gateway delete should be retried after detaching its route"
        );
    }
}
