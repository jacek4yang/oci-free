//! `oci-free vm delete` — terminate an instance and clean up safely.
//!
//! Deletion is the operation with the least margin for error, so the rules are
//! strict:
//!
//! * **only what oci-free created may be deleted.** Ownership is proven from
//!   freeform tags. A boot volume, NSG, or VCN that oci-free merely used is
//!   left alone, however it is named;
//! * **the boot volume's fate is always explicit.** OCI retains it by default,
//!   and a retained volume keeps consuming the Always Free storage allowance
//!   silently. The plan states which way it will go, and a non-interactive run
//!   must say so on the command line;
//! * **shared resources are never removed.** The managed VCN and subnet serve
//!   every instance oci-free created, so they survive the deletion of one;
//! * **the result is verified.** After the termination the state is re-read and
//!   anything retained is reported, rather than assumed gone.

use serde::Serialize;

use crate::{
    commands::{
        context::CommandContext,
        discovery::{load_boot_volume, load_network, resolve_instance},
    },
    domain::{
        ownership::{Ownership, classify},
        plan::{Approval, ChangeKind, MutationPlan, PlannedChange},
    },
    error::{Error, Result},
    interactive,
    oci::{
        compute::{ComputeApi, Instance},
        network::NetworkApi,
    },
};

/// What the user chose for the boot volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootVolumePolicy {
    /// Delete it along with the instance.
    Delete,
    /// Keep it. It continues to consume the storage allowance.
    Keep,
}

/// What `vm delete` was asked to do.
#[derive(Debug, Clone, Copy)]
pub struct DeleteRequest {
    pub boot_volume: Option<BootVolumePolicy>,
    pub delete_nsg: bool,
    pub assume_yes: bool,
}

/// One resource the deletion considered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResourceOutcome {
    pub kind: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub ownership: Ownership,
    /// `deleted`, `retained`, or `failed`.
    pub outcome: String,
    /// Why, in one sentence.
    pub reason: String,
}

/// The `vm delete` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeleteResult {
    pub instance: String,
    pub instance_id: String,
    pub region: String,
    pub lifecycle_state: String,
    /// Whether OCI confirmed the instance is terminating or terminated.
    pub verified: bool,
    pub resources: Vec<ResourceOutcome>,
    pub warnings: Vec<String>,
}

impl DeleteResult {
    /// Resources that still exist after the operation.
    #[must_use]
    pub fn retained(&self) -> Vec<&ResourceOutcome> {
        self.resources
            .iter()
            .filter(|resource| resource.outcome != "deleted")
            .collect()
    }
}

/// Terminate an instance.
pub async fn run(
    context: &CommandContext,
    reference: &str,
    request: DeleteRequest,
) -> Result<(MutationPlan, DeleteResult)> {
    let instance = resolve_instance(context, reference).await?;
    let (boot_volume, mut warnings) = load_boot_volume(context, &instance).await;
    let network = load_network(context, &instance).await;
    warnings.extend(network.warnings.iter().cloned());

    let boot_policy = choose_boot_policy(context, request, boot_volume.as_ref())?;

    let managed_nsgs: Vec<crate::oci::network::NetworkSecurityGroup> = network
        .nsgs
        .iter()
        .filter(|(nsg, _)| {
            classify(&nsg.freeform_tags).permits_deletion()
                && crate::domain::ownership::belongs_to_instance(&nsg.freeform_tags, &instance.id)
        })
        .map(|(nsg, _)| nsg.clone())
        .collect();

    let plan = build_plan(
        context,
        &instance,
        boot_volume.as_ref(),
        boot_policy,
        &managed_nsgs,
        request.delete_nsg,
        &network,
    );
    let approval = confirm(context, &plan, request.assume_yes)?;

    let mut resources = Vec::new();
    let compute = ComputeApi::new(context.client());

    // Terminate first. If it fails, nothing else has been touched.
    compute
        .terminate_instance(&instance.id, boot_policy == BootVolumePolicy::Keep)
        .await?;

    // The boot volume goes with the instance when OCI was told to delete it, so
    // no separate call is needed. It is still reported.
    if let Some(volume) = &boot_volume {
        let ownership = classify(&volume.freeform_tags);
        resources.push(match boot_policy {
            BootVolumePolicy::Delete => ResourceOutcome {
                kind: "boot volume".to_owned(),
                id: volume.id.clone(),
                name: volume.display_name.clone(),
                ownership,
                outcome: "deleted".to_owned(),
                reason: "terminated with the instance, as chosen".to_owned(),
            },
            BootVolumePolicy::Keep => ResourceOutcome {
                kind: "boot volume".to_owned(),
                id: volume.id.clone(),
                name: volume.display_name.clone(),
                ownership,
                outcome: "retained".to_owned(),
                reason: "kept, as chosen; it continues to consume the storage allowance".to_owned(),
            },
        });
    }

    resources.extend(
        clean_up_nsgs(
            context,
            &managed_nsgs,
            request.delete_nsg,
            &approval,
            &mut warnings,
        )
        .await,
    );
    resources.extend(report_shared(&network));

    // Verify rather than assume.
    let (state, verified) = verify(context, &instance).await;
    if !verified {
        warnings.push(format!(
            "OCI still reports {} as {state}; termination can take a few minutes",
            instance.label()
        ));
    }

    Ok((
        plan,
        DeleteResult {
            instance: instance.label().to_owned(),
            instance_id: instance.id.clone(),
            region: context.region().to_string(),
            lifecycle_state: state,
            verified,
            resources,
            warnings,
        },
    ))
}

/// Build the preflight plan.
#[allow(clippy::too_many_arguments)]
fn build_plan(
    context: &CommandContext,
    instance: &Instance,
    boot_volume: Option<&crate::oci::block_storage::BootVolume>,
    boot_policy: BootVolumePolicy,
    managed_nsgs: &[crate::oci::network::NetworkSecurityGroup],
    delete_nsg: bool,
    network: &crate::commands::discovery::InstanceNetwork,
) -> MutationPlan {
    let mut plan = MutationPlan::new("vm.delete", context.region().to_string());

    plan.add_change(
        PlannedChange::new(
            ChangeKind::Delete,
            "compute instance",
            instance.label(),
            "terminated",
        )
        .with_id(instance.id.clone())
        .with_before(instance.lifecycle_state.clone())
        .with_ownership(classify(&instance.freeform_tags)),
    );

    match (boot_volume, boot_policy) {
        (Some(volume), BootVolumePolicy::Delete) => plan.add_change(
            PlannedChange::new(
                ChangeKind::Delete,
                "boot volume",
                volume.label(),
                "deleted with the instance",
            )
            .with_id(volume.id.clone())
            .with_ownership(classify(&volume.freeform_tags))
            .with_note(
                volume
                    .size_in_g_bs
                    .map_or_else(
                        || "size unknown".to_owned(),
                        |size| format!("{size} GB returned to the storage allowance"),
                    ),
            ),
        ),
        (Some(volume), BootVolumePolicy::Keep) => plan.add_change(
            PlannedChange::new(
                ChangeKind::Reuse,
                "boot volume",
                volume.label(),
                "kept",
            )
            .with_id(volume.id.clone())
            .with_ownership(classify(&volume.freeform_tags))
            .with_note(
                "a retained boot volume keeps consuming the Always Free storage allowance and is \
                 billed once that allowance is exceeded",
            ),
        ),
        (None, _) => {}
    }

    for nsg in managed_nsgs {
        plan.add_change(
            PlannedChange::new(
                if delete_nsg {
                    ChangeKind::Delete
                } else {
                    ChangeKind::Reuse
                },
                "network security group",
                nsg.display_name.clone().unwrap_or_else(|| nsg.id.clone()),
                if delete_nsg { "deleted" } else { "kept" },
            )
            .with_id(nsg.id.clone())
            .with_ownership(classify(&nsg.freeform_tags))
            .with_note(if delete_nsg {
                "created by oci-free for this instance alone"
            } else {
                "kept; pass --delete-nsg to remove it too"
            }),
        );
    }

    // The public IP is the resource users most often forget. An ephemeral one
    // is released with the instance and costs nothing; a reserved one survives
    // and keeps consuming the Always Free reserved-IP allowance, so the two
    // cases are stated separately rather than glossed as "the IP goes away".
    if let Some(vnic) = &network.vnic
        && let Some(address) = vnic.public_ip.as_deref().filter(|ip| !ip.trim().is_empty())
    {
        plan.add_change(
            PlannedChange::new(
                ChangeKind::Detach,
                "public IP",
                address,
                "released with the instance if it is ephemeral",
            )
            .with_note(
                "a reserved public IP is not released by terminating an instance; check Networking \
                 -> Reserved public IPs in the Console if you allocated one",
            ),
        );
    }

    // Shared resources are shown so the plan is a complete picture of the
    // topology, and marked as untouched so nobody expects them to go.
    if let Some(subnet) = &network.subnet {
        plan.add_change(
            PlannedChange::new(
                ChangeKind::Reuse,
                "subnet",
                subnet
                    .display_name
                    .clone()
                    .unwrap_or_else(|| subnet.id.clone()),
                "unchanged",
            )
            .with_id(subnet.id.clone())
            .with_ownership(classify(&subnet.freeform_tags))
            .with_note("shared by every instance in it, so deleting one instance never removes it"),
        );
    }

    for (nsg, _) in &network.nsgs {
        let ownership = classify(&nsg.freeform_tags);
        if !ownership.permits_deletion() {
            plan.add_change(
                PlannedChange::new(
                    ChangeKind::Reuse,
                    "network security group",
                    nsg.display_name.clone().unwrap_or_else(|| nsg.id.clone()),
                    "unchanged",
                )
                .with_id(nsg.id.clone())
                .with_ownership(ownership)
                .with_note("oci-free did not create this, so it is never deleted"),
            );
        }
    }

    if boot_policy == BootVolumePolicy::Keep && boot_volume.is_some() {
        plan.add_warning(
            "the boot volume will survive this deletion and keeps its share of the Always Free \
             storage allowance; run `oci-free free list` afterwards to see the effect"
                .to_owned(),
        );
    }

    plan
}

/// Decide what happens to the boot volume.
///
/// There is deliberately no default. OCI's own default is to keep it, which
/// surprises people into silently exhausting their storage allowance, so a
/// non-interactive run must state its choice.
fn choose_boot_policy(
    context: &CommandContext,
    request: DeleteRequest,
    boot_volume: Option<&crate::oci::block_storage::BootVolume>,
) -> Result<BootVolumePolicy> {
    if let Some(policy) = request.boot_volume {
        return Ok(policy);
    }
    if boot_volume.is_none() {
        // Nothing to decide about.
        return Ok(BootVolumePolicy::Keep);
    }
    if !context.is_interactive() {
        return Err(interactive::not_interactive(
            "what to do with the boot volume",
            "--delete-boot-volume or --keep-boot-volume",
        )
        .with_context(
            "OCI keeps the boot volume by default, and a retained volume keeps consuming the \
             Always Free storage allowance, so oci-free will not choose for you",
        ));
    }

    let size = boot_volume
        .and_then(|volume| volume.size_in_g_bs)
        .map(|size| format!(" ({size} GB)"))
        .unwrap_or_default();
    let options = vec![
        format!("delete the boot volume{size} as well"),
        format!("keep the boot volume{size}; it keeps using the storage allowance"),
    ];
    let choice = interactive::select(
        "What should happen to the boot volume?",
        &options,
        0,
        "--delete-boot-volume",
    )?;
    Ok(if choice == 0 {
        BootVolumePolicy::Delete
    } else {
        BootVolumePolicy::Keep
    })
}

/// Delete the instance's managed NSG, if asked and if ownership allows.
async fn clean_up_nsgs(
    context: &CommandContext,
    managed: &[crate::oci::network::NetworkSecurityGroup],
    delete: bool,
    approval: &Approval,
    warnings: &mut Vec<String>,
) -> Vec<ResourceOutcome> {
    debug_assert!(approval.operation() == "vm.delete");
    let api = NetworkApi::new(context.client());
    let mut outcomes = Vec::new();

    for nsg in managed {
        let ownership = classify(&nsg.freeform_tags);
        if !delete {
            outcomes.push(ResourceOutcome {
                kind: "network security group".to_owned(),
                id: nsg.id.clone(),
                name: nsg.display_name.clone(),
                ownership,
                outcome: "retained".to_owned(),
                reason: "kept; pass --delete-nsg to remove it".to_owned(),
            });
            continue;
        }

        // Belt and braces: the caller already filtered on ownership, but this
        // is the last point before an irreversible call.
        if !ownership.permits_deletion() {
            outcomes.push(ResourceOutcome {
                kind: "network security group".to_owned(),
                id: nsg.id.clone(),
                name: nsg.display_name.clone(),
                ownership,
                outcome: "retained".to_owned(),
                reason: ownership.explain().to_owned(),
            });
            continue;
        }

        match api.delete_nsg(&nsg.id).await {
            Ok(()) => outcomes.push(ResourceOutcome {
                kind: "network security group".to_owned(),
                id: nsg.id.clone(),
                name: nsg.display_name.clone(),
                ownership,
                outcome: "deleted".to_owned(),
                reason: "created by oci-free for this instance".to_owned(),
            }),
            Err(error) => {
                warnings.push(format!(
                    "the network security group {} could not be deleted: {error}. OCI often \
                     refuses until the instance's VNIC has finished detaching; re-run in a moment.",
                    nsg.id
                ));
                outcomes.push(ResourceOutcome {
                    kind: "network security group".to_owned(),
                    id: nsg.id.clone(),
                    name: nsg.display_name.clone(),
                    ownership,
                    outcome: "failed".to_owned(),
                    reason: error.message().to_owned(),
                });
            }
        }
    }

    outcomes
}

/// Report shared resources as explicitly untouched.
fn report_shared(network: &crate::commands::discovery::InstanceNetwork) -> Vec<ResourceOutcome> {
    let mut outcomes = Vec::new();
    if let Some(subnet) = &network.subnet {
        outcomes.push(ResourceOutcome {
            kind: "subnet".to_owned(),
            id: subnet.id.clone(),
            name: subnet.display_name.clone(),
            ownership: classify(&subnet.freeform_tags),
            outcome: "retained".to_owned(),
            reason: "shared with any other instance in it, so it is never removed with one \
                     instance"
                .to_owned(),
        });
    }
    outcomes
}

/// Re-read the instance to confirm the termination took.
async fn verify(context: &CommandContext, instance: &Instance) -> (String, bool) {
    match ComputeApi::new(context.client())
        .get_instance(&instance.id)
        .await
    {
        Ok(updated) => {
            let terminating = matches!(
                updated.lifecycle_state.as_str(),
                "TERMINATED" | "TERMINATING"
            );
            (updated.lifecycle_state, terminating)
        }
        // A 404 after a termination means it is already gone.
        Err(error) if error.kind() == crate::error::ErrorKind::NotFound => {
            ("TERMINATED".to_owned(), true)
        }
        Err(_) => (instance.lifecycle_state.clone(), false),
    }
}

/// Show the plan and obtain an approval.
fn confirm(context: &CommandContext, plan: &MutationPlan, assume_yes: bool) -> Result<Approval> {
    if assume_yes {
        return plan.approve(true);
    }
    if !context.is_interactive() {
        return Err(interactive::not_interactive(
            "confirmation for vm.delete",
            "--yes",
        ));
    }
    print!("{}", plan.render_human());
    let confirmed = interactive::confirm("Terminate this instance?")?;
    plan.approve(confirmed)
}

/// Map the CLI's mutually exclusive flags onto a policy.
#[must_use]
pub fn boot_policy(keep: bool, delete: bool) -> Option<BootVolumePolicy> {
    match (keep, delete) {
        (true, false) => Some(BootVolumePolicy::Keep),
        (false, true) => Some(BootVolumePolicy::Delete),
        // Both or neither: no choice was expressed.
        _ => None,
    }
}

/// Render `vm delete` for a terminal.
#[must_use]
pub fn render_human(result: &DeleteResult) -> String {
    let mut out = format!("{} is {}\n\n", result.instance, result.lifecycle_state);

    for resource in &result.resources {
        out.push_str(&format!(
            "  {:<9} {} {}\n            {}\n",
            resource.outcome,
            resource.kind,
            resource.name.as_deref().unwrap_or(&resource.id),
            resource.reason
        ));
    }

    let retained = result.retained();
    if !retained.is_empty() {
        out.push_str(&format!(
            "\n{} resource(s) still exist after this deletion.\n",
            retained.len()
        ));
    }

    for warning in &result.warnings {
        out.push_str(&format!("\nwarning: {warning}\n"));
    }
    out
}

/// Refuse a deletion whose plan is blocked.
pub fn refuse_if_blocked(plan: &MutationPlan) -> Result<()> {
    if plan.blockers.is_empty() {
        return Ok(());
    }
    Err(Error::policy_rejected("vm delete was blocked").with_context(plan.blockers.join("; ")))
}

#[cfg(test)]
#[path = "delete_tests.rs"]
mod delete_tests;
