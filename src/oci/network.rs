//! Virtual networking adapter: VNICs, subnets, VCNs, NSGs, Security Lists,
//! route tables, internet gateways, and public IPs.
//!
//! Everything needed to answer "what can actually reach this instance?" lives
//! here. The models keep only the fields the exposure calculation and the
//! managed-network writes use; `serde` ignores the rest, so Oracle adding a
//! field cannot break the client.
//!
//! Two conventions matter for safety:
//!
//! * OCI expresses a rule's protocol as the IANA number in a string (`"6"` for
//!   TCP, `"17"` for UDP, `"all"` for every protocol). That string is preserved
//!   verbatim so the exposure model can decide what it means rather than having
//!   a lossy enum decided at parse time.
//! * every object carries its freeform tags, because ownership is proven from
//!   tags and never from a display name.

use std::collections::BTreeMap;

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

/// Tags carried by most Core Services objects.
pub type Tags = BTreeMap<String, String>;

/// `GET /20160918/vnics/{vnicId}`
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vnic {
    pub id: String,
    #[serde(default)]
    pub compartment_id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub subnet_id: Option<String>,
    #[serde(default)]
    pub private_ip: Option<String>,
    /// The ephemeral or reserved public IP currently on this VNIC.
    ///
    /// Absent means no public address, which is a normal state, not a decoding
    /// failure.
    #[serde(default)]
    pub public_ip: Option<String>,
    #[serde(default)]
    pub is_primary: Option<bool>,
    /// Network Security Groups attached to this VNIC.
    #[serde(default)]
    pub nsg_ids: Vec<String>,
    #[serde(default)]
    pub hostname_label: Option<String>,
    #[serde(default)]
    pub availability_domain: Option<String>,
    #[serde(default)]
    pub lifecycle_state: Option<String>,
    #[serde(default)]
    pub freeform_tags: Tags,
}

impl Vnic {
    /// Whether OCI has given this VNIC a routable public address.
    #[must_use]
    pub fn has_public_ip(&self) -> bool {
        self.public_ip
            .as_deref()
            .is_some_and(|ip| !ip.trim().is_empty())
    }
}

/// `GET /20160918/subnets/{subnetId}`
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Subnet {
    pub id: String,
    pub vcn_id: String,
    #[serde(default)]
    pub compartment_id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub cidr_block: Option<String>,
    #[serde(default)]
    pub route_table_id: Option<String>,
    #[serde(default)]
    pub security_list_ids: Vec<String>,
    /// True for a private subnet: OCI refuses to assign public IPs in it.
    #[serde(default)]
    pub prohibit_public_ip_on_vnic: Option<bool>,
    #[serde(default)]
    pub prohibit_internet_ingress: Option<bool>,
    #[serde(default)]
    pub availability_domain: Option<String>,
    #[serde(default)]
    pub lifecycle_state: Option<String>,
    #[serde(default)]
    pub freeform_tags: Tags,
}

impl Subnet {
    /// Whether this subnet forbids public addressing.
    #[must_use]
    pub fn is_private(&self) -> bool {
        self.prohibit_public_ip_on_vnic.unwrap_or(false)
    }

    /// Whether the subnet spans the whole region rather than one domain.
    #[must_use]
    pub fn is_regional(&self) -> bool {
        self.availability_domain.is_none()
    }
}

/// `GET /20160918/vcns/{vcnId}`
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vcn {
    pub id: String,
    #[serde(default)]
    pub compartment_id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub cidr_block: Option<String>,
    #[serde(default)]
    pub cidr_blocks: Vec<String>,
    #[serde(default)]
    pub default_route_table_id: Option<String>,
    #[serde(default)]
    pub default_security_list_id: Option<String>,
    #[serde(default)]
    pub lifecycle_state: Option<String>,
    #[serde(default)]
    pub freeform_tags: Tags,
}

/// `GET /20160918/networkSecurityGroups/{id}`
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkSecurityGroup {
    pub id: String,
    #[serde(default)]
    pub compartment_id: Option<String>,
    #[serde(default)]
    pub vcn_id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub lifecycle_state: Option<String>,
    #[serde(default)]
    pub freeform_tags: Tags,
}

/// A port range in an NSG or Security List rule.
///
/// OCI omits `min` when the range is open-ended at the bottom, so both bounds
/// are optional and an absent bound is treated as wide open by the exposure
/// model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortRange {
    #[serde(default)]
    pub min: Option<u16>,
    #[serde(default)]
    pub max: Option<u16>,
}

impl PortRange {
    #[must_use]
    pub fn exactly(port: u16) -> Self {
        Self {
            min: Some(port),
            max: Some(port),
        }
    }

    /// Whether this range covers `port`, treating an absent bound as unbounded.
    #[must_use]
    pub fn contains(&self, port: u16) -> bool {
        self.min.is_none_or(|min| port >= min) && self.max.is_none_or(|max| port <= max)
    }
}

/// TCP or UDP options on a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_port_range: Option<PortRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_port_range: Option<PortRange>,
}

/// ICMP options on a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IcmpOptions {
    #[serde(rename = "type")]
    pub icmp_type: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
}

/// One rule of `GET /networkSecurityGroups/{id}/securityRules`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityRule {
    /// OCI-assigned rule id, needed to remove the rule again.
    #[serde(default)]
    pub id: Option<String>,
    pub direction: String,
    /// IANA protocol number as a string, or `all`.
    pub protocol: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub source_type: Option<String>,
    #[serde(default)]
    pub destination: Option<String>,
    #[serde(default)]
    pub destination_type: Option<String>,
    #[serde(default)]
    pub is_stateless: Option<bool>,
    #[serde(default)]
    pub tcp_options: Option<TransportOptions>,
    #[serde(default)]
    pub udp_options: Option<TransportOptions>,
    #[serde(default)]
    pub icmp_options: Option<IcmpOptions>,
    #[serde(default)]
    pub description: Option<String>,
}

impl SecurityRule {
    #[must_use]
    pub fn is_ingress(&self) -> bool {
        self.direction.eq_ignore_ascii_case("INGRESS")
    }
}

/// One ingress rule inside a Security List.
///
/// Security List rules have no identifier: the whole list is replaced on
/// update. That is one reason oci-free never edits them as a convenience.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IngressSecurityRule {
    pub protocol: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub source_type: Option<String>,
    #[serde(default)]
    pub is_stateless: Option<bool>,
    #[serde(default)]
    pub tcp_options: Option<TransportOptions>,
    #[serde(default)]
    pub udp_options: Option<TransportOptions>,
    #[serde(default)]
    pub icmp_options: Option<IcmpOptions>,
    #[serde(default)]
    pub description: Option<String>,
}

/// `GET /20160918/securityLists/{securityListId}`
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityList {
    pub id: String,
    #[serde(default)]
    pub vcn_id: Option<String>,
    #[serde(default)]
    pub compartment_id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub ingress_security_rules: Vec<IngressSecurityRule>,
    #[serde(default)]
    pub lifecycle_state: Option<String>,
    #[serde(default)]
    pub freeform_tags: Tags,
}

/// One rule of a route table.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteRule {
    #[serde(default)]
    pub destination: Option<String>,
    #[serde(default)]
    pub destination_type: Option<String>,
    #[serde(default)]
    pub network_entity_id: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

impl RouteRule {
    /// Whether this rule is a default route to the whole IPv4 internet.
    #[must_use]
    pub fn is_default_ipv4(&self) -> bool {
        self.destination.as_deref() == Some("0.0.0.0/0")
    }
}

/// `GET /20160918/routeTables/{rtId}`
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteTable {
    pub id: String,
    #[serde(default)]
    pub vcn_id: Option<String>,
    #[serde(default)]
    pub compartment_id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub route_rules: Vec<RouteRule>,
    #[serde(default)]
    pub lifecycle_state: Option<String>,
    #[serde(default)]
    pub freeform_tags: Tags,
}

/// `GET /20160918/internetGateways/{igwId}`
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InternetGateway {
    pub id: String,
    #[serde(default)]
    pub vcn_id: Option<String>,
    #[serde(default)]
    pub compartment_id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub is_enabled: Option<bool>,
    #[serde(default)]
    pub lifecycle_state: Option<String>,
    #[serde(default)]
    pub freeform_tags: Tags,
}

impl InternetGateway {
    /// Whether traffic can actually leave through this gateway.
    ///
    /// A disabled gateway still appears in a route rule, so a route alone does
    /// not prove reachability.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.is_enabled.unwrap_or(true)
            && self
                .lifecycle_state
                .as_deref()
                .is_none_or(|state| state.eq_ignore_ascii_case("AVAILABLE"))
    }
}

// ---------------------------------------------------------------------------
// Write request bodies
// ---------------------------------------------------------------------------

/// One rule submitted to `AddNetworkSecurityGroupSecurityRules`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddSecurityRule {
    pub direction: String,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_type: Option<String>,
    pub is_stateless: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_options: Option<TransportOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_options: Option<TransportOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AddSecurityRules {
    security_rules: Vec<AddSecurityRule>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoveSecurityRules {
    security_rule_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateNsg {
    pub compartment_id: String,
    pub vcn_id: String,
    pub display_name: String,
    pub freeform_tags: Tags,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateVcn {
    pub compartment_id: String,
    pub cidr_block: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_label: Option<String>,
    pub freeform_tags: Tags,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSubnet {
    pub compartment_id: String,
    pub vcn_id: String,
    pub cidr_block: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_table_id: Option<String>,
    pub prohibit_public_ip_on_vnic: bool,
    pub freeform_tags: Tags,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateInternetGateway {
    pub compartment_id: String,
    pub vcn_id: String,
    pub display_name: String,
    pub is_enabled: bool,
    pub freeform_tags: Tags,
}

/// A route rule as sent to `UpdateRouteTable`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteRuleUpdate {
    pub destination: String,
    pub destination_type: String,
    pub network_entity_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRouteTable {
    pub route_rules: Vec<RouteRuleUpdate>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateVnic {
    pub nsg_ids: Vec<String>,
}

/// Read and write operations against the virtual-network service.
#[derive(Debug)]
pub struct NetworkApi<'a> {
    client: &'a OciClient,
}

impl<'a> NetworkApi<'a> {
    #[must_use]
    pub fn new(client: &'a OciClient) -> Self {
        Self { client }
    }

    // -- reads --------------------------------------------------------------

    pub async fn get_vnic(&self, vnic_id: &str) -> Result<Vnic> {
        let path = format!("/vnics/{}", encode_path_segment(vnic_id));
        Ok(self
            .client
            .get_json::<Vnic>(Service::Core, &path, "GetVnic")
            .await?
            .body)
    }

    pub async fn get_subnet(&self, subnet_id: &str) -> Result<Subnet> {
        let path = format!("/subnets/{}", encode_path_segment(subnet_id));
        Ok(self
            .client
            .get_json::<Subnet>(Service::Core, &path, "GetSubnet")
            .await?
            .body)
    }

    pub async fn get_vcn(&self, vcn_id: &str) -> Result<Vcn> {
        let path = format!("/vcns/{}", encode_path_segment(vcn_id));
        Ok(self
            .client
            .get_json::<Vcn>(Service::Core, &path, "GetVcn")
            .await?
            .body)
    }

    pub async fn get_nsg(&self, nsg_id: &str) -> Result<NetworkSecurityGroup> {
        let path = format!("/networkSecurityGroups/{}", encode_path_segment(nsg_id));
        Ok(self
            .client
            .get_json::<NetworkSecurityGroup>(Service::Core, &path, "GetNetworkSecurityGroup")
            .await?
            .body)
    }

    pub async fn get_security_list(&self, id: &str) -> Result<SecurityList> {
        let path = format!("/securityLists/{}", encode_path_segment(id));
        Ok(self
            .client
            .get_json::<SecurityList>(Service::Core, &path, "GetSecurityList")
            .await?
            .body)
    }

    pub async fn get_route_table(&self, id: &str) -> Result<RouteTable> {
        let path = format!("/routeTables/{}", encode_path_segment(id));
        Ok(self
            .client
            .get_json::<RouteTable>(Service::Core, &path, "GetRouteTable")
            .await?
            .body)
    }

    pub async fn get_internet_gateway(&self, id: &str) -> Result<InternetGateway> {
        let path = format!("/internetGateways/{}", encode_path_segment(id));
        Ok(self
            .client
            .get_json::<InternetGateway>(Service::Core, &path, "GetInternetGateway")
            .await?
            .body)
    }

    /// Ingress rules of one NSG.
    pub async fn list_nsg_ingress_rules(&self, nsg_id: &str) -> Result<Vec<SecurityRule>> {
        let path = format!(
            "/networkSecurityGroups/{}/securityRules?direction=INGRESS",
            encode_path_segment(nsg_id)
        );
        self.client
            .list_all(
                Service::Core,
                &path,
                "ListNetworkSecurityGroupSecurityRules",
            )
            .await
    }

    /// Every rule of one NSG, both directions.
    pub async fn list_nsg_rules(&self, nsg_id: &str) -> Result<Vec<SecurityRule>> {
        let path = format!(
            "/networkSecurityGroups/{}/securityRules",
            encode_path_segment(nsg_id)
        );
        self.client
            .list_all(
                Service::Core,
                &path,
                "ListNetworkSecurityGroupSecurityRules",
            )
            .await
    }

    pub async fn list_nsgs(
        &self,
        compartment: &Ocid,
        vcn_id: Option<&str>,
    ) -> Result<Vec<NetworkSecurityGroup>> {
        let mut path = format!(
            "/networkSecurityGroups?compartmentId={}",
            encode_query_value(compartment.as_str())
        );
        if let Some(vcn) = vcn_id {
            path.push_str(&format!("&vcnId={}", encode_query_value(vcn)));
        }
        self.client
            .list_all(Service::Core, &path, "ListNetworkSecurityGroups")
            .await
    }

    pub async fn list_vcns(&self, compartment: &Ocid) -> Result<Vec<Vcn>> {
        let path = format!(
            "/vcns?compartmentId={}",
            encode_query_value(compartment.as_str())
        );
        self.client.list_all(Service::Core, &path, "ListVcns").await
    }

    pub async fn list_subnets(&self, compartment: &Ocid, vcn_id: &str) -> Result<Vec<Subnet>> {
        let path = format!(
            "/subnets?compartmentId={}&vcnId={}",
            encode_query_value(compartment.as_str()),
            encode_query_value(vcn_id)
        );
        self.client
            .list_all(Service::Core, &path, "ListSubnets")
            .await
    }

    pub async fn list_internet_gateways(
        &self,
        compartment: &Ocid,
        vcn_id: &str,
    ) -> Result<Vec<InternetGateway>> {
        let path = format!(
            "/internetGateways?compartmentId={}&vcnId={}",
            encode_query_value(compartment.as_str()),
            encode_query_value(vcn_id)
        );
        self.client
            .list_all(Service::Core, &path, "ListInternetGateways")
            .await
    }

    // -- writes -------------------------------------------------------------

    /// Add ingress rules to one NSG.
    ///
    /// This is the only rule-writing entry point used by `vm net open`, and it
    /// addresses exactly one NSG, which is what makes the change instance
    /// scoped.
    pub async fn add_nsg_rules(
        &self,
        nsg_id: &str,
        rules: Vec<AddSecurityRule>,
    ) -> Result<Option<String>> {
        let path = format!(
            "/networkSecurityGroups/{}/securityRules/actions/addSecurityRules",
            encode_path_segment(nsg_id)
        );
        self.client
            .post_action(
                Service::Core,
                &path,
                &AddSecurityRules {
                    security_rules: rules,
                },
                None,
                "AddNetworkSecurityGroupSecurityRules",
            )
            .await
    }

    /// Remove rules from one NSG by rule id.
    pub async fn remove_nsg_rules(&self, nsg_id: &str, rule_ids: Vec<String>) -> Result<()> {
        let path = format!(
            "/networkSecurityGroups/{}/securityRules/actions/removeSecurityRules",
            encode_path_segment(nsg_id)
        );
        self.client
            .post_action(
                Service::Core,
                &path,
                &RemoveSecurityRules {
                    security_rule_ids: rule_ids,
                },
                None,
                "RemoveNetworkSecurityGroupSecurityRules",
            )
            .await?;
        Ok(())
    }

    pub async fn create_nsg(
        &self,
        details: &CreateNsg,
        retry_token: &str,
    ) -> Result<NetworkSecurityGroup> {
        Ok(self
            .client
            .post_json::<_, NetworkSecurityGroup>(
                Service::Core,
                "/networkSecurityGroups",
                details,
                Some(retry_token),
                "CreateNetworkSecurityGroup",
            )
            .await?
            .body)
    }

    pub async fn delete_nsg(&self, nsg_id: &str) -> Result<()> {
        let path = format!("/networkSecurityGroups/{}", encode_path_segment(nsg_id));
        self.client
            .delete(Service::Core, &path, "DeleteNetworkSecurityGroup")
            .await
    }

    pub async fn create_vcn(&self, details: &CreateVcn, retry_token: &str) -> Result<Vcn> {
        Ok(self
            .client
            .post_json::<_, Vcn>(
                Service::Core,
                "/vcns",
                details,
                Some(retry_token),
                "CreateVcn",
            )
            .await?
            .body)
    }

    pub async fn create_subnet(&self, details: &CreateSubnet, retry_token: &str) -> Result<Subnet> {
        Ok(self
            .client
            .post_json::<_, Subnet>(
                Service::Core,
                "/subnets",
                details,
                Some(retry_token),
                "CreateSubnet",
            )
            .await?
            .body)
    }

    pub async fn create_internet_gateway(
        &self,
        details: &CreateInternetGateway,
        retry_token: &str,
    ) -> Result<InternetGateway> {
        Ok(self
            .client
            .post_json::<_, InternetGateway>(
                Service::Core,
                "/internetGateways",
                details,
                Some(retry_token),
                "CreateInternetGateway",
            )
            .await?
            .body)
    }

    pub async fn update_route_table(
        &self,
        route_table_id: &str,
        details: &UpdateRouteTable,
    ) -> Result<RouteTable> {
        let path = format!("/routeTables/{}", encode_path_segment(route_table_id));
        Ok(self
            .client
            .put_json::<_, RouteTable>(Service::Core, &path, details, "UpdateRouteTable")
            .await?
            .body)
    }

    /// Replace the set of NSGs attached to a VNIC.
    pub async fn update_vnic_nsgs(&self, vnic_id: &str, nsg_ids: Vec<String>) -> Result<Vnic> {
        let path = format!("/vnics/{}", encode_path_segment(vnic_id));
        Ok(self
            .client
            .put_json::<_, Vnic>(Service::Core, &path, &UpdateVnic { nsg_ids }, "UpdateVnic")
            .await?
            .body)
    }

    pub async fn delete_vcn(&self, vcn_id: &str) -> Result<()> {
        let path = format!("/vcns/{}", encode_path_segment(vcn_id));
        self.client.delete(Service::Core, &path, "DeleteVcn").await
    }

    pub async fn delete_subnet(&self, subnet_id: &str) -> Result<()> {
        let path = format!("/subnets/{}", encode_path_segment(subnet_id));
        self.client
            .delete(Service::Core, &path, "DeleteSubnet")
            .await
    }

    pub async fn delete_internet_gateway(&self, id: &str) -> Result<()> {
        let path = format!("/internetGateways/{}", encode_path_segment(id));
        self.client
            .delete(Service::Core, &path, "DeleteInternetGateway")
            .await
    }
}

#[cfg(test)]
#[path = "network_tests.rs"]
mod network_tests;
