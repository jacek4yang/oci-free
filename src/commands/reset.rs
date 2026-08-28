//! `oci-free reset` — return the resources created by oci-free to a clean slate.
//!
//! This is intentionally narrower than "delete everything in the tenancy". It
//! deletes every resource that carries oci-free's `managed=created` ownership
//! proof in the home region, and leaves untagged, user-owned, and reused
//! resources untouched. That makes it useful for repeated live validation
//! without turning a test helper into a tenancy-wide foot-gun.

use serde::Serialize;

use crate::{
    commands::{context::CommandContext, network_setup},
    domain::{
        ownership::{
            ROLE_INSTANCE, ROLE_INSTANCE_NSG, ROLE_INTERNET_GATEWAY, ROLE_SUBNET, ROLE_VCN,
            classify, role_of,
        },
        plan::{Approval, ChangeKind, MutationPlan, PlannedChange},
    },
    error::{Error, ErrorKind, Result},
    interactive,
    oci::{
        block_storage::BlockStorageApi,
        compute::{ComputeApi, Instance},
        identity::IdentityApi,
        network::NetworkApi,
    },
};

#[derive(Debug, Clone, Copy)]
pub struct ResetRequest {
    pub assume_yes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResetOutcome {
    pub kind: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub outcome: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResetResult {
    pub region: String,
    pub deleted: usize,
    pub retained: usize,
    pub resources: Vec<ResetOutcome>,
    pub warnings: Vec<String>,
}

struct Inventory {
    instances: Vec<Instance>,
    boot_volumes: Vec<crate::oci::block_storage::BootVolume>,
    nsgs: Vec<crate::oci::network::NetworkSecurityGroup>,
    vcns: Vec<crate::oci::network::Vcn>,
    subnets: Vec<crate::oci::network::Subnet>,
    gateways: Vec<crate::oci::network::InternetGateway>,
}

pub async fn run(
    context: &CommandContext,
    request: ResetRequest,
) -> Result<(MutationPlan, ResetResult)> {
    let context = &context.in_home_region().await?;
    let inventory = discover(context).await?;
    let plan = build_plan(context, &inventory);
    let approval = confirm(context, &plan, request.assume_yes)?;
    let result = apply(context, inventory, &approval).await?;
    Ok((plan, result))
}

async fn discover(context: &CommandContext) -> Result<Inventory> {
    let compute = ComputeApi::new(context.client());
    let network = NetworkApi::new(context.client());
    let identity = IdentityApi::new(context.client());
    let block = BlockStorageApi::new(context.client());

    let instances = compute
        .list_instances(context.tenancy())
        .await?
        .into_iter()
        .filter(|instance| {
            classify(&instance.freeform_tags).permits_deletion()
                && role_of(&instance.freeform_tags) == Some(ROLE_INSTANCE)
                && !instance.lifecycle_state.eq_ignore_ascii_case("TERMINATED")
        })
        .collect::<Vec<_>>();

    let mut boot_volumes = Vec::new();
    for domain in identity
        .list_availability_domains(context.tenancy())
        .await?
    {
        boot_volumes.extend(
            block
                .list_boot_volumes(context.tenancy(), &domain.name)
                .await?
                .into_iter()
                .filter(|volume| {
                    classify(&volume.freeform_tags).permits_deletion() && volume.consumes_storage()
                }),
        );
    }

    let nsgs = network
        .list_nsgs(context.tenancy(), None)
        .await?
        .into_iter()
        .filter(|nsg| {
            classify(&nsg.freeform_tags).permits_deletion()
                && role_of(&nsg.freeform_tags) == Some(ROLE_INSTANCE_NSG)
        })
        .collect::<Vec<_>>();

    let vcns = network
        .list_vcns(context.tenancy())
        .await?
        .into_iter()
        .filter(|vcn| {
            classify(&vcn.freeform_tags).permits_deletion()
                && role_of(&vcn.freeform_tags) == Some(ROLE_VCN)
        })
        .collect::<Vec<_>>();

    let mut subnets = Vec::new();
    let mut gateways = Vec::new();
    for vcn in &vcns {
        subnets.extend(
            network
                .list_subnets(context.tenancy(), &vcn.id)
                .await?
                .into_iter()
                .filter(|subnet| {
                    classify(&subnet.freeform_tags).permits_deletion()
                        && role_of(&subnet.freeform_tags) == Some(ROLE_SUBNET)
                }),
        );
        gateways.extend(
            network
                .list_internet_gateways(context.tenancy(), &vcn.id)
                .await?
                .into_iter()
                .filter(|gateway| {
                    classify(&gateway.freeform_tags).permits_deletion()
                        && role_of(&gateway.freeform_tags) == Some(ROLE_INTERNET_GATEWAY)
                }),
        );
    }

    Ok(Inventory {
        instances,
        boot_volumes,
        nsgs,
        vcns,
        subnets,
        gateways,
    })
}

fn build_plan(context: &CommandContext, inventory: &Inventory) -> MutationPlan {
    let mut plan = MutationPlan::new("reset", context.region().to_string());

    for instance in &inventory.instances {
        plan.add_change(
            PlannedChange::new(
                ChangeKind::Delete,
                "compute instance",
                instance.label(),
                "terminated with its boot volume deleted",
            )
            .with_id(instance.id.clone())
            .with_ownership(classify(&instance.freeform_tags)),
        );
    }
    for volume in &inventory.boot_volumes {
        plan.add_change(
            PlannedChange::new(
                ChangeKind::Delete,
                "boot volume",
                volume.label(),
                "deleted if it still exists after instance termination",
            )
            .with_id(volume.id.clone())
            .with_ownership(classify(&volume.freeform_tags)),
        );
    }
    for nsg in &inventory.nsgs {
        plan.add_change(
            PlannedChange::new(
                ChangeKind::Delete,
                "network security group",
                nsg.display_name.as_deref().unwrap_or(&nsg.id),
                "deleted",
            )
            .with_id(nsg.id.clone())
            .with_ownership(classify(&nsg.freeform_tags)),
        );
    }
    for subnet in &inventory.subnets {
        plan.add_change(
            PlannedChange::new(
                ChangeKind::Delete,
                "subnet",
                subnet.display_name.as_deref().unwrap_or(&subnet.id),
                "deleted",
            )
            .with_id(subnet.id.clone())
            .with_ownership(classify(&subnet.freeform_tags)),
        );
    }
    for gateway in &inventory.gateways {
        plan.add_change(
            PlannedChange::new(
                ChangeKind::Delete,
                "internet gateway",
                gateway.display_name.as_deref().unwrap_or(&gateway.id),
                "deleted after managed route references are removed",
            )
            .with_id(gateway.id.clone())
            .with_ownership(classify(&gateway.freeform_tags)),
        );
    }
    for vcn in &inventory.vcns {
        plan.add_change(
            PlannedChange::new(
                ChangeKind::Delete,
                "VCN",
                vcn.display_name.as_deref().unwrap_or(&vcn.id),
                "deleted last",
            )
            .with_id(vcn.id.clone())
            .with_ownership(classify(&vcn.freeform_tags)),
        );
    }

    plan.add_warning(
        "reset deletes every resource that oci-free can prove it created in the home region; \
         untagged and reused resources are never deleted"
            .to_owned(),
    );
    plan
}

fn confirm(context: &CommandContext, plan: &MutationPlan, assume_yes: bool) -> Result<Approval> {
    if assume_yes {
        return plan.approve(true);
    }
    if !context.is_interactive() {
        return Err(interactive::not_interactive(
            "confirmation for reset",
            "--yes",
        ));
    }
    print!("{}", plan.render_human());
    if !interactive::confirm("Delete all resources created by oci-free?")? {
        return Err(Error::unsupported_state("cancelled").with_context("nothing was changed"));
    }
    plan.approve(true)
}

async fn apply(
    context: &CommandContext,
    inventory: Inventory,
    approval: &Approval,
) -> Result<ResetResult> {
    debug_assert!(approval.operation() == "reset");
    let compute = ComputeApi::new(context.client());
    let network = NetworkApi::new(context.client());
    let mut resources = Vec::new();
    let mut warnings = Vec::new();

    // Instances go first so their VNICs and attached boot volumes can detach
    // before NSGs and subnets are removed.
    for instance in &inventory.instances {
        match compute.terminate_instance(&instance.id, false).await {
            Ok(()) => {
                let terminated = wait_instance_gone(context, instance).await;
                resources.push(ResetOutcome {
                    kind: "compute instance".to_owned(),
                    id: instance.id.clone(),
                    name: instance.display_name.clone(),
                    outcome: if terminated { "deleted" } else { "retained" }.to_owned(),
                    reason: if terminated {
                        "terminated; OCI was instructed to delete the boot volume".to_owned()
                    } else {
                        "termination was accepted but did not settle before the reset deadline"
                            .to_owned()
                    },
                });
                if !terminated {
                    warnings.push(format!(
                        "instance {} is still terminating; re-run `oci-free reset` after it settles",
                        instance.id
                    ));
                }
            }
            Err(error) => {
                warnings.push(format!(
                    "instance {} could not be terminated: {error}",
                    instance.id
                ));
                resources.push(failed(
                    "compute instance",
                    &instance.id,
                    instance.display_name.clone(),
                    &error,
                ));
            }
        }
    }

    // Every destructive target below was inventoried before confirmation. A
    // successful DELETE is not enough to call a resource deleted: OCI cleanup
    // is asynchronous, so each helper follows the accepted request with fresh
    // GETs until the resource is actually gone (or a terminal deleted state is
    // reported for boot storage).
    let block = BlockStorageApi::new(context.client());
    for volume in &inventory.boot_volumes {
        match delete_boot_until_gone(context, &block, &volume.id).await {
            Ok(()) => resources.push(deleted_outcome(
                "boot volume",
                &volume.id,
                volume.display_name.clone(),
            )),
            Err(error) => {
                warnings.push(format!(
                    "boot volume {} could not be verified deleted: {error}",
                    volume.id
                ));
                resources.push(failed(
                    "boot volume",
                    &volume.id,
                    volume.display_name.clone(),
                    &error,
                ));
            }
        }
    }

    for nsg in &inventory.nsgs {
        match delete_nsg_until_gone(context, &network, &nsg.id).await {
            Ok(()) => resources.push(deleted_outcome(
                "network security group",
                &nsg.id,
                nsg.display_name.clone(),
            )),
            Err(error) => {
                warnings.push(format!(
                    "network security group {} could not be verified deleted: {error}",
                    nsg.id
                ));
                resources.push(failed(
                    "network security group",
                    &nsg.id,
                    nsg.display_name.clone(),
                    &error,
                ));
            }
        }
    }

    for subnet in &inventory.subnets {
        match delete_subnet_until_gone(context, &network, &subnet.id).await {
            Ok(()) => resources.push(deleted_outcome(
                "subnet",
                &subnet.id,
                subnet.display_name.clone(),
            )),
            Err(error) => {
                warnings.push(format!(
                    "subnet {} could not be verified deleted: {error}",
                    subnet.id
                ));
                resources.push(failed(
                    "subnet",
                    &subnet.id,
                    subnet.display_name.clone(),
                    &error,
                ));
            }
        }
    }

    for gateway in &inventory.gateways {
        let vcn_id = gateway.vcn_id.as_deref().unwrap_or_default();
        match delete_gateway_until_gone(context, &network, vcn_id, &gateway.id).await {
            Ok(()) => resources.push(deleted_outcome(
                "internet gateway",
                &gateway.id,
                gateway.display_name.clone(),
            )),
            Err(error) => {
                warnings.push(format!(
                    "internet gateway {} could not be verified deleted: {error}",
                    gateway.id
                ));
                resources.push(failed(
                    "internet gateway",
                    &gateway.id,
                    gateway.display_name.clone(),
                    &error,
                ));
            }
        }
    }

    for vcn in &inventory.vcns {
        match delete_vcn_until_gone(context, &network, &vcn.id).await {
            Ok(()) => resources.push(deleted_outcome("VCN", &vcn.id, vcn.display_name.clone())),
            Err(error) => {
                warnings.push(format!(
                    "VCN {} could not be verified deleted: {error}",
                    vcn.id
                ));
                resources.push(failed("VCN", &vcn.id, vcn.display_name.clone(), &error));
            }
        }
    }

    let deleted = resources.iter().filter(|r| r.outcome == "deleted").count();
    let retained = resources.len().saturating_sub(deleted);
    Ok(ResetResult {
        region: context.region().to_string(),
        deleted,
        retained,
        resources,
        warnings,
    })
}

async fn wait_instance_gone(context: &CommandContext, instance: &Instance) -> bool {
    let compute = ComputeApi::new(context.client());
    let poll = context.poll();
    let deadline = std::time::Instant::now() + poll.timeout;
    loop {
        match compute.get_instance(&instance.id).await {
            Ok(current) if current.lifecycle_state.eq_ignore_ascii_case("TERMINATED") => {
                return true;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(poll.interval).await;
    }
}

async fn request_delete<F, Fut>(context: &CommandContext, mut delete: F) -> Result<bool>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let poll = context.poll();
    let deadline = std::time::Instant::now() + poll.timeout;
    loop {
        match delete().await {
            Ok(()) => return Ok(false),
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(true),
            Err(error) if retryable_delete(&error) && std::time::Instant::now() < deadline => {
                tokio::time::sleep(poll.interval).await;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn wait_until_absent<F, Fut>(
    context: &CommandContext,
    kind: &str,
    id: &str,
    mut probe: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<bool>>,
{
    let poll = context.poll();
    let deadline = std::time::Instant::now() + poll.timeout;
    loop {
        match probe().await {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) if retryable_probe(&error) && std::time::Instant::now() < deadline => {}
            Err(error) => return Err(error),
        }

        if std::time::Instant::now() >= deadline {
            return Err(Error::timeout(format!(
                "{kind} {id} did not disappear before the reset deadline"
            ))
            .with_context(
                "OCI accepted the delete request, but a fresh read still reports the resource",
            )
            .with_remediation(
                "wait for OCI to settle, then re-run `oci-free reset`; ownership will be re-proven before any retry",
            ));
        }
        tokio::time::sleep(poll.interval).await;
    }
}

async fn delete_boot_until_gone(
    context: &CommandContext,
    api: &BlockStorageApi<'_>,
    id: &str,
) -> Result<()> {
    if request_delete(context, || api.delete_boot_volume(id)).await? {
        return Ok(());
    }

    wait_until_absent(context, "boot volume", id, || async {
        match api.get_boot_volume(id).await {
            Ok(volume)
                if volume
                    .lifecycle_state
                    .as_deref()
                    .is_some_and(|state| state.eq_ignore_ascii_case("TERMINATED")) =>
            {
                Ok(true)
            }
            Ok(_) => Ok(false),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error),
        }
    })
    .await
}

async fn delete_nsg_until_gone(
    context: &CommandContext,
    api: &NetworkApi<'_>,
    id: &str,
) -> Result<()> {
    if request_delete(context, || api.delete_nsg(id)).await? {
        return Ok(());
    }
    wait_until_absent(context, "network security group", id, || async {
        match api.get_nsg(id).await {
            Ok(_) => Ok(false),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error),
        }
    })
    .await
}

async fn delete_subnet_until_gone(
    context: &CommandContext,
    api: &NetworkApi<'_>,
    id: &str,
) -> Result<()> {
    if request_delete(context, || api.delete_subnet(id)).await? {
        return Ok(());
    }
    wait_until_absent(context, "subnet", id, || async {
        match api.get_subnet(id).await {
            Ok(_) => Ok(false),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error),
        }
    })
    .await
}

async fn delete_vcn_until_gone(
    context: &CommandContext,
    api: &NetworkApi<'_>,
    id: &str,
) -> Result<()> {
    if request_delete(context, || api.delete_vcn(id)).await? {
        return Ok(());
    }
    wait_until_absent(context, "VCN", id, || async {
        match api.get_vcn(id).await {
            Ok(_) => Ok(false),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error),
        }
    })
    .await
}

async fn delete_gateway_until_gone(
    context: &CommandContext,
    api: &NetworkApi<'_>,
    vcn_id: &str,
    gateway_id: &str,
) -> Result<()> {
    let poll = context.poll();
    let deadline = std::time::Instant::now() + poll.timeout;
    let mut detached = false;
    loop {
        match api.delete_internet_gateway(gateway_id).await {
            Ok(()) => break,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error)
                if error.kind() == ErrorKind::Conflict && !detached && !vcn_id.is_empty() =>
            {
                network_setup::detach_gateway_routes(context, vcn_id, gateway_id).await?;
                detached = true;
            }
            Err(error) if retryable_delete(&error) && std::time::Instant::now() < deadline => {
                tokio::time::sleep(poll.interval).await;
            }
            Err(error) => return Err(error),
        }
    }

    wait_until_absent(context, "internet gateway", gateway_id, || async {
        match api.get_internet_gateway(gateway_id).await {
            Ok(_) => Ok(false),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error),
        }
    })
    .await
}

fn retryable_delete(error: &Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::Conflict
            | ErrorKind::InvalidInput
            | ErrorKind::TransientServer
            | ErrorKind::RateLimited
            | ErrorKind::Network
            | ErrorKind::Timeout
    )
}

fn retryable_probe(error: &Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::TransientServer
            | ErrorKind::RateLimited
            | ErrorKind::Network
            | ErrorKind::Timeout
    )
}

fn deleted_outcome(kind: &str, id: &str, name: Option<String>) -> ResetOutcome {
    ResetOutcome {
        kind: kind.to_owned(),
        id: id.to_owned(),
        name,
        outcome: "deleted".to_owned(),
        reason: "created by oci-free; deletion verified by a fresh OCI read".to_owned(),
    }
}

fn failed(kind: &str, id: &str, name: Option<String>, error: &Error) -> ResetOutcome {
    ResetOutcome {
        kind: kind.to_owned(),
        id: id.to_owned(),
        name,
        outcome: "retained".to_owned(),
        reason: error.message().to_owned(),
    }
}

#[must_use]
pub fn render_human(result: &ResetResult) -> String {
    let mut out = format!(
        "Reset oci-free-managed resources in {}: {} deleted, {} retained\n",
        result.region, result.deleted, result.retained
    );
    for resource in &result.resources {
        out.push_str(&format!(
            "  {:8} {:24} {}\n",
            resource.outcome,
            resource.kind,
            resource.name.as_deref().unwrap_or(&resource.id)
        ));
    }
    for warning in &result.warnings {
        out.push_str(&format!("warning: {warning}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::testing::mock_oci::{MockOci, Reply};

    #[tokio::test]
    async fn accepted_nsg_delete_is_not_complete_until_a_fresh_read_says_gone() {
        let id = "ocid1.networksecuritygroup.oc1.iad.resetwait";
        let path = format!("/networkSecurityGroups/{id}");
        let mock = MockOci::builder()
            .reply("DELETE", &path, Reply::new(204, ""))
            .route(
                "GET",
                &path,
                vec![
                    Reply::json(&json!({
                        "id": id,
                        "vcnId": "ocid1.vcn.oc1.iad.a",
                        "lifecycleState": "TERMINATING"
                    })),
                    Reply::new(
                        404,
                        r#"{"code":"NotAuthorizedOrNotFound","message":"gone"}"#,
                    ),
                ],
            )
            .start()
            .await;
        let context = CommandContext::for_tests(mock.client(), "us-ashburn-1");
        let api = NetworkApi::new(context.client());

        delete_nsg_until_gone(&context, &api, id)
            .await
            .expect("delete settles");

        let requests = mock.requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].method(), "DELETE");
        assert_eq!(requests[1].method(), "GET");
        assert_eq!(requests[2].method(), "GET");
    }

    #[tokio::test]
    async fn accepted_delete_that_never_disappears_times_out_instead_of_claiming_success() {
        let id = "ocid1.networksecuritygroup.oc1.iad.resetstuck";
        let path = format!("/networkSecurityGroups/{id}");
        let mock = MockOci::builder()
            .reply("DELETE", &path, Reply::new(204, ""))
            .get(
                &path,
                &json!({
                    "id": id,
                    "vcnId": "ocid1.vcn.oc1.iad.a",
                    "lifecycleState": "TERMINATING"
                }),
            )
            .start()
            .await;
        let context = CommandContext::for_tests(mock.client(), "us-ashburn-1");
        let api = NetworkApi::new(context.client());

        let error = delete_nsg_until_gone(&context, &api, id)
            .await
            .expect_err("a stuck resource must not be reported deleted");
        assert_eq!(error.kind(), ErrorKind::Timeout);
        assert!(error.message().contains("did not disappear"));
        assert!(error.remediation().contains("re-run `oci-free reset`"));
    }
}
