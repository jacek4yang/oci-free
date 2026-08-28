//! `oci-free vm net <instance> show | audit | open | close`.
//!
//! The network contract from CLAUDE.md lives here:
//!
//! * a normal `open` or `close` touches exactly one object — the instance's own
//!   oci-free-managed Network Security Group. Subnet Security Lists are never
//!   modified as a convenience, because they govern every instance in the
//!   subnet;
//! * after every mutation the effective state is re-read from OCI and the
//!   result verified. A rule that was added but did not take effect, or a rule
//!   that was removed while the port stayed open through a Security List, is
//!   reported rather than assumed;
//! * `close` reports residual exposure. Removing the managed rule is not the
//!   same as closing the port.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;

use crate::{
    commands::{
        context::CommandContext,
        discovery::{InstanceNetwork, load_network, resolve_instance},
        myip,
    },
    domain::{
        audit::{AuditReport, Finding, Severity, audit},
        cidr::{ANY_IPV4, Cidr},
        exposure::EffectiveExposure,
        network::{PortRule, Protocol},
        ownership::{Ownership, ROLE_INSTANCE_NSG, created_tags},
        plan::{Approval, ChangeKind, ExposureDelta, MutationPlan, PlannedChange},
    },
    error::{Error, Result},
    interactive,
    oci::{
        compute::Instance,
        network::{
            AddSecurityRule, CreateNsg, NetworkApi, NetworkSecurityGroup, PortRange,
            TransportOptions,
        },
    },
};

/// Marker written into every rule oci-free adds, so a rule it created can be
/// told apart from one a user added to the same NSG by hand.
pub const MANAGED_RULE_PREFIX: &str = "oci-free managed:";

/// The `vm net show` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetShow {
    pub instance: String,
    pub instance_id: String,
    pub region: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposure: Option<EffectiveExposure>,
    /// Why exposure is absent, when it is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<String>,
    pub warnings: Vec<String>,
}

/// The `vm net audit` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetAudit {
    pub instance: String,
    pub instance_id: String,
    pub region: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposure: Option<EffectiveExposure>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<String>,
    pub warnings: Vec<String>,
}

/// The result of an `open` or `close`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetChange {
    pub instance: String,
    pub instance_id: String,
    pub region: String,
    pub rule: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// The NSG that was modified.
    pub nsg_id: String,
    pub nsg_name: String,
    /// Whether the NSG was created by this command.
    pub nsg_created: bool,
    /// Whether the intended effect was verified against a fresh read.
    pub verified: bool,
    /// Rules that still permit this port through some other object.
    pub residual_exposure: Vec<String>,
    pub warnings: Vec<String>,
}

/// Where an `open` should accept traffic from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceChoice {
    /// A specific range, already validated.
    Cidr(Cidr),
    /// Every IPv4 address. Only reachable through an explicit choice.
    AnyIpv4,
}

/// The literal `--source` value meaning "look up my own public address".
pub const SOURCE_MYIP: &str = "myip";

impl SourceChoice {
    /// Parse a `--source` value.
    ///
    /// `myip` is handled by the caller, which has to make a network lookup and
    /// confirm the result, so reaching here with it is a bug rather than
    /// something to silently ignore.
    pub fn parse(value: &str) -> Result<Self> {
        if value.eq_ignore_ascii_case(SOURCE_MYIP) {
            return Err(Error::invalid_input(
                "`myip` must be resolved before it can be used as a source",
            )
            .with_context("this is an internal error; please report it"));
        }
        let cidr: Cidr = value
            .parse()
            .map_err(|error: crate::domain::cidr::ParseCidrError| {
                Error::invalid_input(format!("`{value}` is not a valid address range"))
                    .with_context(error.to_string())
                    .with_remediation(
                        "pass an address such as 198.51.100.7 or a block such as 198.51.100.0/24",
                    )
            })?;
        if cidr.is_entire_internet() {
            return Ok(Self::AnyIpv4);
        }
        Ok(Self::Cidr(cidr))
    }

    #[must_use]
    pub fn as_oci_value(&self) -> String {
        match self {
            Self::Cidr(cidr) => cidr.to_string(),
            Self::AnyIpv4 => ANY_IPV4.to_owned(),
        }
    }

    /// The warning to attach to a plan that uses this source.
    #[must_use]
    pub fn warning(&self) -> Option<String> {
        match self {
            Self::AnyIpv4 => Some(
                "this rule will accept traffic from every address on the internet; anyone will \
                 be able to reach the port"
                    .to_owned(),
            ),
            Self::Cidr(cidr) if cidr.is_broad() => Some(format!(
                "{cidr} covers millions of addresses; consider narrowing it to the hosts that \
                 need access"
            )),
            Self::Cidr(_) => None,
        }
    }
}

/// Show effective exposure.
pub async fn show(context: &CommandContext, reference: &str) -> Result<NetShow> {
    let instance = resolve_instance(context, reference).await?;
    let network = load_network(context, &instance).await;
    let exposure = network.exposure();

    Ok(NetShow {
        instance: instance.label().to_owned(),
        instance_id: instance.id.clone(),
        region: context.region().to_string(),
        unavailable: exposure
            .is_none()
            .then(|| network.unavailable_reason().unwrap_or("unknown").to_owned()),
        warnings: if exposure.is_some() {
            Vec::new()
        } else {
            network.warnings.clone()
        },
        exposure,
    })
}

/// Audit effective exposure.
pub async fn run_audit(context: &CommandContext, reference: &str) -> Result<NetAudit> {
    let instance = resolve_instance(context, reference).await?;
    let network = load_network(context, &instance).await;
    let exposure = network.exposure();
    let report = exposure.as_ref().map(audit);

    Ok(NetAudit {
        instance: instance.label().to_owned(),
        instance_id: instance.id.clone(),
        region: context.region().to_string(),
        unavailable: exposure
            .is_none()
            .then(|| network.unavailable_reason().unwrap_or("unknown").to_owned()),
        warnings: if exposure.is_some() {
            Vec::new()
        } else {
            network.warnings.clone()
        },
        exposure,
        audit: report,
    })
}

/// Build the plan for opening a port, without performing any write.
///
/// Split out from [`open`] so a test can prove that a plan the policy refuses
/// issues no write request at all.
#[must_use]
pub fn plan_open(
    context: &CommandContext,
    instance: &Instance,
    network: &InstanceNetwork,
    rule: PortRule,
    source: &SourceChoice,
) -> MutationPlan {
    let mut plan = MutationPlan::new("vm.net.open", context.region().to_string());
    let exposure = network.exposure();

    let managed = exposure.as_ref().and_then(EffectiveExposure::managed_nsg);
    match managed {
        Some(nsg) => plan.add_change(
            PlannedChange::new(
                ChangeKind::Modify,
                "network security group",
                nsg.name.clone().unwrap_or_else(|| nsg.id.clone()),
                format!("{} ingress rule(s)", nsg.ingress_rule_count + 1),
            )
            .with_id(nsg.id.clone())
            .with_before(format!("{} ingress rule(s)", nsg.ingress_rule_count))
            .with_ownership(Ownership::Created)
            .with_note("only this instance's NSG is modified; subnet Security Lists are untouched"),
        ),
        None => plan.add_change(
            PlannedChange::new(
                ChangeKind::Create,
                "network security group",
                managed_nsg_name(instance),
                "1 ingress rule, attached to this instance's VNIC",
            )
            .with_note("a per-instance NSG scopes the change to this instance alone"),
        ),
    }

    if managed.is_none() {
        plan.add_change(
            PlannedChange::new(
                ChangeKind::Attach,
                "VNIC",
                network
                    .vnic
                    .as_ref()
                    .map_or_else(|| "primary".to_owned(), |vnic| vnic.id.clone()),
                "the new NSG is attached",
            )
            .with_note("existing NSG attachments are preserved"),
        );
    }

    let added = format!(
        "{} {} from {}",
        rule.protocol,
        rule.port,
        source.as_oci_value()
    );
    let residual = exposure
        .as_ref()
        .map(|exposure| {
            exposure
                .allowing(rule)
                .into_iter()
                .map(crate::domain::exposure::EffectiveRule::summary)
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();

    plan = plan.with_exposure(ExposureDelta {
        added: vec![added],
        removed: Vec::new(),
        unchanged_residual: residual.clone(),
    });

    if let Some(warning) = source.warning() {
        plan.add_warning(warning);
    }
    if !residual.is_empty() {
        plan.add_warning(format!(
            "{}/{} is already reachable through {} other rule(s); this change adds to that rather \
             than replacing it",
            rule.port,
            rule.protocol,
            residual.len()
        ));
    }
    if exposure.is_none() {
        plan.add_blocker(
            network
                .unavailable_reason()
                .unwrap_or("the instance's network could not be read")
                .to_owned(),
        );
    }
    for warning in &network.warnings {
        plan.add_warning(warning.clone());
    }

    plan
}

/// Open a port on the instance's managed NSG.
pub async fn open(
    context: &CommandContext,
    reference: &str,
    rule: PortRule,
    source: Option<&str>,
    assume_yes: bool,
) -> Result<(MutationPlan, NetChange)> {
    let instance = resolve_instance(context, reference).await?;
    let network = load_network(context, &instance).await;

    let source = choose_source(context, source, rule).await?;
    let plan = plan_open(context, &instance, &network, rule, &source);
    let approval = confirm_plan(context, &plan, assume_yes)?;

    let change = apply_open(context, &instance, &network, rule, &source, &approval).await?;
    Ok((plan, change))
}

/// Close a port on the instance's managed NSG.
pub async fn close(
    context: &CommandContext,
    reference: &str,
    rule: PortRule,
    assume_yes: bool,
) -> Result<(MutationPlan, NetChange)> {
    let instance = resolve_instance(context, reference).await?;
    let network = load_network(context, &instance).await;
    let exposure = network.exposure();

    let Some(exposure) = exposure else {
        return Err(
            Error::not_found("the instance's effective network state could not be read")
                .with_context(
                    network
                        .unavailable_reason()
                        .unwrap_or("the VNIC or subnet was unreadable")
                        .to_owned(),
                )
                .with_remediation("run `oci-free doctor` to check networking read permissions"),
        );
    };

    let Some(managed) = exposure.managed_nsg() else {
        return Err(Error::not_found(format!(
            "{} has no oci-free-managed network security group",
            instance.label()
        ))
        .with_context(
            "`close` only removes rules oci-free created; it never edits an NSG or Security List \
             it does not own",
        )
        .with_remediation(
            "remove the rule in the OCI Console, or run `oci-free vm net <instance> show` to see \
             which object grants it",
        ));
    };

    let matching: Vec<&crate::domain::exposure::EffectiveRule> = exposure
        .allowing(rule)
        .into_iter()
        .filter(|candidate| candidate.origin.id == managed.id)
        .collect();

    let mut plan = MutationPlan::new("vm.net.close", context.region().to_string());
    plan.add_change(
        PlannedChange::new(
            ChangeKind::Modify,
            "network security group",
            managed.name.clone().unwrap_or_else(|| managed.id.clone()),
            format!(
                "{} ingress rule(s)",
                managed.ingress_rule_count.saturating_sub(matching.len())
            ),
        )
        .with_id(managed.id.clone())
        .with_before(format!("{} ingress rule(s)", managed.ingress_rule_count))
        .with_ownership(Ownership::Created)
        .with_note("only rules on this instance's own NSG are removed"),
    );

    let residual: Vec<String> = exposure
        .allowing_outside(rule, &managed.id)
        .into_iter()
        .map(crate::domain::exposure::EffectiveRule::summary)
        .collect();

    plan = plan.with_exposure(ExposureDelta {
        added: Vec::new(),
        removed: matching
            .iter()
            .map(|candidate| candidate.summary())
            .collect(),
        unchanged_residual: residual.clone(),
    });

    if matching.is_empty() {
        plan.add_warning(format!(
            "the managed NSG has no rule for {rule}; nothing will be removed"
        ));
    }

    // A rule covering more than the port asked about is removed whole — OCI has
    // no way to subtract one port from a range — so closing 22 can also close
    // 80 and 443. The plan lists the rule, but that is easy to skim past, so
    // the consequence is spelled out.
    for wider in matching
        .iter()
        .filter(|candidate| candidate.ports.width() > 1)
    {
        plan.add_warning(format!(
            "the rule granting {rule} covers {} ({}), and OCI can only remove it whole; closing \
             {rule} therefore also closes the rest of that range",
            wider.ports,
            wider.summary()
        ));
    }
    if !residual.is_empty() {
        plan.add_warning(format!(
            "{rule} will remain reachable after this change: {}",
            residual.join("; ")
        ));
    }

    let approval = confirm_plan(context, &plan, assume_yes)?;

    let rule_ids: Vec<String> = matching
        .iter()
        .filter_map(|candidate| candidate.rule_id.clone())
        .collect();

    let network_api = NetworkApi::new(context.client());
    if !rule_ids.is_empty() {
        remove_rules(&network_api, &managed.id, rule_ids, &approval).await?;
    }

    // Re-read rather than assume. A rule OCI accepted but did not apply, or a
    // port still open through a Security List, must be reported as such.
    let after = load_network(context, &instance).await;
    let mut warnings = after.warnings.clone();
    let mut verified = false;
    let mut residual_after = residual;

    if let Some(exposure) = after.exposure() {
        let still_on_managed = exposure
            .allowing(rule)
            .into_iter()
            .any(|candidate| candidate.origin.id == managed.id);
        verified = !still_on_managed;
        if still_on_managed {
            warnings.push(format!(
                "OCI still reports {rule} as allowed by the managed NSG after the removal"
            ));
        }
        residual_after = exposure
            .allowing_outside(rule, &managed.id)
            .into_iter()
            .map(crate::domain::exposure::EffectiveRule::summary)
            .collect();
        if !residual_after.is_empty() {
            warnings.push(format!(
                "{rule} is still reachable: removing the instance rule does not close a port that \
                 another object allows"
            ));
        }
    } else {
        warnings.push(
            "the effective state could not be re-read, so the result of this change is unverified"
                .to_owned(),
        );
    }

    Ok((
        plan,
        NetChange {
            instance: instance.label().to_owned(),
            instance_id: instance.id.clone(),
            region: context.region().to_string(),
            rule: rule.to_string(),
            source: None,
            nsg_id: managed.id.clone(),
            nsg_name: managed.name.clone().unwrap_or_else(|| managed.id.clone()),
            nsg_created: false,
            verified,
            residual_exposure: residual_after,
            warnings,
        },
    ))
}

/// Perform the writes an approved `open` plan describes.
async fn apply_open(
    context: &CommandContext,
    instance: &Instance,
    network: &InstanceNetwork,
    rule: PortRule,
    source: &SourceChoice,
    approval: &Approval,
) -> Result<NetChange> {
    let api = NetworkApi::new(context.client());
    let exposure = network.exposure();
    let mut warnings = network.warnings.clone();

    let (nsg_id, nsg_name, created) =
        match exposure.as_ref().and_then(EffectiveExposure::managed_nsg) {
            Some(nsg) => (
                nsg.id.clone(),
                nsg.name.clone().unwrap_or_else(|| nsg.id.clone()),
                false,
            ),
            None => {
                let nsg = create_managed_nsg(context, instance, network, approval).await?;
                let name = nsg.display_name.clone().unwrap_or_else(|| nsg.id.clone());
                // The NSG now exists. If attaching it fails, say so rather than
                // leaving behind an object the user has no reason to expect:
                // the create carries a stable idempotency token, so re-running
                // the command reuses this group instead of making a second one.
                attach_nsg(context, network, &nsg.id, approval)
                    .await
                    .map_err(|error| orphaned_nsg(&nsg.id, &name, &error))?;
                (nsg.id, name, true)
            }
        };

    match add_rule(&api, &nsg_id, rule, source, approval).await {
        Ok(()) => {}
        // The rule failed on an NSG this command had just created, so report
        // the group too: it exists, it is empty, and that is not obvious from
        // the rule failure alone.
        Err(error) if created => return Err(orphaned_nsg(&nsg_id, &nsg_name, &error)),
        Err(error) => return Err(error),
    }

    // Verify against a fresh read; never report success from the write alone.
    let after = load_network(context, instance).await;
    warnings.extend(after.warnings.iter().cloned());
    let mut verified = false;
    let mut residual = Vec::new();

    if let Some(exposure) = after.exposure() {
        verified = exposure
            .allowing(rule)
            .into_iter()
            .any(|candidate| candidate.origin.id == nsg_id);
        if !verified {
            warnings.push(format!(
                "OCI accepted the rule but does not yet report {rule} as allowed by {nsg_name}; \
                 re-run `oci-free vm net {} show` in a moment",
                instance.label()
            ));
        }
        residual = exposure
            .allowing_outside(rule, &nsg_id)
            .into_iter()
            .map(crate::domain::exposure::EffectiveRule::summary)
            .collect();
        if !exposure.internet.reachable {
            warnings.push(format!(
                "the rule is in place, but nothing can reach this instance from the internet: {}",
                exposure.internet.reason
            ));
        }
    } else {
        warnings.push(
            "the effective state could not be re-read, so the result of this change is unverified"
                .to_owned(),
        );
    }

    Ok(NetChange {
        instance: instance.label().to_owned(),
        instance_id: instance.id.clone(),
        region: context.region().to_string(),
        rule: rule.to_string(),
        source: Some(source.as_oci_value()),
        nsg_id,
        nsg_name,
        nsg_created: created,
        verified,
        residual_exposure: residual,
        warnings,
    })
}

/// Report a managed NSG that was created but could not be finished.
///
/// A partial mutation rather than a plain failure: an OCI object exists that
/// the user did not have before, so the exit code says so (7) and the message
/// names it.
fn orphaned_nsg(nsg_id: &str, nsg_name: &str, cause: &Error) -> Error {
    Error::partial_mutation(format!(
        "the network security group {nsg_name} was created but could not be finished"
    ))
    .with_context(format!(
        "{}. The group exists as {nsg_id} and is tagged `oci-free:managed=created`.",
        cause.message()
    ))
    .with_remediation(
        "re-run the same command: discovery reuses the tagged group if it still exists; if \
         it was deleted, the new create receives a fresh OCI retry token",
    )
}

/// Create the per-instance managed NSG.
async fn create_managed_nsg(
    context: &CommandContext,
    instance: &Instance,
    network: &InstanceNetwork,
    approval: &Approval,
) -> Result<NetworkSecurityGroup> {
    debug_assert!(approval.operation().starts_with("vm."));
    let vcn_id = network
        .subnet
        .as_ref()
        .map(|subnet| subnet.vcn_id.clone())
        .ok_or_else(|| {
            Error::not_found("the instance's VCN could not be determined")
                .with_context("an NSG belongs to a VCN, so the subnet must be readable first")
        })?;

    NetworkApi::new(context.client())
        .create_nsg(
            &CreateNsg {
                compartment_id: instance.compartment_id.clone(),
                vcn_id,
                display_name: managed_nsg_name(instance),
                freeform_tags: created_tags(ROLE_INSTANCE_NSG, Some(&instance.id)),
            },
            &retry_token("nsg", &instance.id),
        )
        .await
}

/// Attach an NSG to the instance's VNIC, preserving existing attachments.
async fn attach_nsg(
    context: &CommandContext,
    network: &InstanceNetwork,
    nsg_id: &str,
    approval: &Approval,
) -> Result<()> {
    debug_assert!(approval.operation().starts_with("vm."));
    let vnic = network.vnic.as_ref().ok_or_else(|| {
        Error::not_found("the instance has no VNIC to attach the NSG to")
            .with_remediation("wait for the instance to finish provisioning and try again")
    })?;

    let mut nsg_ids = vnic.nsg_ids.clone();
    if !nsg_ids.iter().any(|existing| existing == nsg_id) {
        nsg_ids.push(nsg_id.to_owned());
    }
    NetworkApi::new(context.client())
        .update_vnic_nsgs(&vnic.id, nsg_ids)
        .await?;
    Ok(())
}

async fn add_rule(
    api: &NetworkApi<'_>,
    nsg_id: &str,
    rule: PortRule,
    source: &SourceChoice,
    approval: &Approval,
) -> Result<()> {
    debug_assert!(approval.operation().starts_with("vm."));
    let options = Some(TransportOptions {
        destination_port_range: Some(PortRange::exactly(rule.port)),
        source_port_range: None,
    });
    let (tcp_options, udp_options) = match rule.protocol {
        Protocol::Tcp => (options, None),
        Protocol::Udp => (None, options),
    };

    api.add_nsg_rules(
        nsg_id,
        vec![AddSecurityRule {
            direction: "INGRESS".to_owned(),
            protocol: oci_protocol(rule.protocol).to_owned(),
            source: Some(source.as_oci_value()),
            source_type: Some("CIDR_BLOCK".to_owned()),
            destination: None,
            destination_type: None,
            is_stateless: false,
            tcp_options,
            udp_options,
            description: Some(format!("{MANAGED_RULE_PREFIX} {rule}")),
        }],
    )
    .await?;
    Ok(())
}

async fn remove_rules(
    api: &NetworkApi<'_>,
    nsg_id: &str,
    rule_ids: Vec<String>,
    approval: &Approval,
) -> Result<()> {
    debug_assert!(approval.operation().starts_with("vm."));
    api.remove_nsg_rules(nsg_id, rule_ids).await
}

/// Ask for, or validate, the source of an `open`.
pub async fn choose_source(
    context: &CommandContext,
    supplied: Option<&str>,
    rule: PortRule,
) -> Result<SourceChoice> {
    if let Some(value) = supplied {
        if value.eq_ignore_ascii_case(SOURCE_MYIP) {
            return resolve_my_address(context.is_interactive()).await;
        }
        return SourceChoice::parse(value);
    }
    if !context.is_interactive() {
        return Err(interactive::not_interactive(
            "the ingress source",
            "--source <CIDR>, for example --source 198.51.100.7/32, --source myip, or --source \
             0.0.0.0/0",
        ));
    }

    let options = vec![
        format!(
            "just this machine - look up my public address via {}",
            myip::ECHO_ENDPOINT
        ),
        "a specific address or range I will type".to_owned(),
        format!("every IPv4 address (0.0.0.0/0) - anyone can reach {rule}"),
        "cancel".to_owned(),
    ];
    let choice = interactive::select(
        &format!("Who should be able to reach {rule}?"),
        &options,
        0,
        "--source",
    )?;

    match choice {
        0 => resolve_my_address(true).await,
        1 => {
            let value = interactive::input("Source address or CIDR block", None, "--source")?;
            SourceChoice::parse(&value)
        }
        2 => {
            if !interactive::confirm(
                "This will let every host on the internet reach the port. Continue?",
            )? {
                return Err(cancelled());
            }
            Ok(SourceChoice::AnyIpv4)
        }
        _ => Err(cancelled()),
    }
}

/// Look up this machine's public address, and confirm it before it is used.
///
/// The confirmation is not ceremony: a mistaken or hostile echo service would
/// otherwise open the port to somebody else's address, and showing the value is
/// what makes that visible. In a non-interactive run there is nobody to show it
/// to, so the address is used as-is - the user asked for `myip` explicitly,
/// which is the acceptance.
pub async fn resolve_my_address(interactive: bool) -> Result<SourceChoice> {
    let cidr = myip::detect().await?;
    if interactive
        && !interactive::confirm(&format!(
            "{} reports your address as {cidr}. Use it?",
            myip::ECHO_ENDPOINT
        ))?
    {
        return Err(cancelled());
    }
    Ok(SourceChoice::Cidr(cidr))
}

fn cancelled() -> Error {
    Error::unsupported_state("cancelled").with_context("nothing was changed")
}

/// Show the plan and obtain an approval.
fn confirm_plan(
    context: &CommandContext,
    plan: &MutationPlan,
    assume_yes: bool,
) -> Result<Approval> {
    if assume_yes {
        return plan.approve(true);
    }
    if !context.is_interactive() {
        // Refuse rather than prompt. The plan is still surfaced through the
        // error so the user can see what would have happened.
        return Err(interactive::not_interactive(
            format!("confirmation for {}", plan.operation).as_str(),
            "--yes",
        ));
    }
    // Print the plan before asking: a confirmation prompt with nothing to
    // review is not consent.
    print!("{}", plan.render_human());
    let confirmed = interactive::confirm("Apply this plan?")?;
    plan.approve(confirmed)
}

/// The deterministic name of an instance's managed NSG.
#[must_use]
pub fn managed_nsg_name(instance: &Instance) -> String {
    // The name is for humans only; ownership is proven from tags, never here.
    let label: String = instance
        .label()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("oci-free-{}", label.trim_matches('-'))
}

/// The OCI wire value for a transport protocol.
#[must_use]
pub fn oci_protocol(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "6",
        Protocol::Udp => "17",
    }
}

/// Fallback uniqueness when the operating-system RNG is temporarily unavailable.
static RETRY_NONCE_FALLBACK: AtomicU64 = AtomicU64::new(1);

fn retry_nonce() -> u64 {
    let mut bytes = [0_u8; 8];
    if SystemRandom::new().fill(&mut bytes).is_ok() {
        return u64::from_le_bytes(bytes);
    }

    // The retry token is not a credential. This fallback only prevents
    // accidental token reuse when OS randomness is temporarily unavailable.
    let clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_secs().rotate_left(32) ^ u64::from(duration.subsec_nanos())
        });
    clock ^ RETRY_NONCE_FALLBACK.fetch_add(1, Ordering::Relaxed)
}

/// An OCI idempotency token scoped to one logical create invocation.
///
/// The caller constructs this once and passes it into `OciClient`, whose
/// transport retries therefore reuse the same token. A later CLI invocation
/// gets a fresh nonce, which matters because OCI can invalidate an old retry
/// token after the resource created with it is deleted.
#[must_use]
pub fn retry_token(kind: &str, seed: &str) -> String {
    let digest = seed.bytes().fold(0_u32, |acc, byte| {
        acc.wrapping_mul(31).wrapping_add(u32::from(byte))
    });
    format!("oci-free-{kind}-{digest:08x}-{:016x}", retry_nonce())
}

/// Render `vm net show` for a terminal.
#[must_use]
pub fn render_show(show: &NetShow) -> String {
    let mut out = format!(
        "Effective ingress for {} in {}\n\n",
        show.instance, show.region
    );

    let Some(exposure) = &show.exposure else {
        out.push_str(&format!(
            "Exposure is unavailable: {}\n",
            show.unavailable.as_deref().unwrap_or("unknown reason")
        ));
        for warning in &show.warnings {
            out.push_str(&format!("warning: {warning}\n"));
        }
        return out;
    };

    out.push_str(&format!(
        "  private IP   {}\n",
        exposure.private_ip.as_deref().unwrap_or("none")
    ));
    out.push_str(&format!(
        "  public IP    {}\n",
        exposure.internet.public_ip.as_deref().unwrap_or("none")
    ));
    out.push_str(&format!(
        "  subnet       {}\n",
        exposure
            .subnet_name
            .as_deref()
            .unwrap_or(&exposure.subnet_id)
    ));
    out.push_str(&format!(
        "  reachable    {}\n               {}\n",
        if exposure.internet.reachable {
            "yes, from the internet"
        } else {
            "no"
        },
        exposure.internet.reason
    ));

    out.push_str("\n  ingress\n");
    if exposure.rules.is_empty() {
        out.push_str("    (nothing is allowed in)\n");
    }
    for rule in &exposure.rules {
        out.push_str(&format!("    {}\n", rule.summary()));
        if let Some(description) = &rule.description {
            out.push_str(&format!("      {description}\n"));
        }
    }

    out.push_str("\n  governed by\n");
    for nsg in &exposure.attached_nsgs {
        out.push_str(&format!(
            "    NSG {} ({}, {} ingress rule(s))\n",
            nsg.name.as_deref().unwrap_or(&nsg.id),
            nsg.ownership.as_str(),
            nsg.ingress_rule_count
        ));
    }
    if exposure.attached_nsgs.is_empty() {
        out.push_str("    no NSG is attached to this instance\n");
    }
    for list in &exposure.subnet_security_lists {
        out.push_str(&format!(
            "    security list {} ({} ingress rule(s), applies to the whole subnet)\n",
            list.name.as_deref().unwrap_or(&list.id),
            list.ingress_rule_count
        ));
    }

    for warning in &exposure.warnings {
        out.push_str(&format!("\nwarning: {warning}\n"));
    }
    out
}

/// Render `vm net audit` for a terminal.
#[must_use]
pub fn render_audit(result: &NetAudit) -> String {
    let mut out = format!(
        "Exposure audit for {} in {}\n\n",
        result.instance, result.region
    );

    let (Some(exposure), Some(report)) = (&result.exposure, &result.audit) else {
        out.push_str(&format!(
            "Exposure is unavailable: {}\n",
            result.unavailable.as_deref().unwrap_or("unknown reason")
        ));
        for warning in &result.warnings {
            out.push_str(&format!("warning: {warning}\n"));
        }
        return out;
    };

    out.push_str(&format!(
        "  internet reachable: {}\n\n",
        if report.internet_reachable {
            "yes"
        } else {
            "no"
        }
    ));

    if report.findings.is_empty() {
        out.push_str("  nothing to report\n");
    }
    for finding in &report.findings {
        out.push_str(&format!(
            "  [{:>8}] {}\n            {}\n            next: {}\n",
            finding.severity.as_str(),
            finding.title,
            finding.detail,
            finding.remediation
        ));
        if let Some(origin) = &finding.origin {
            out.push_str(&format!("            object: {}\n", origin.label()));
        }
        out.push('\n');
    }

    for warning in &exposure.warnings {
        out.push_str(&format!("warning: {warning}\n"));
    }
    out
}

/// Render an `open` or `close` result for a terminal.
#[must_use]
pub fn render_change(change: &NetChange) -> String {
    let mut out = String::new();
    if change.nsg_created {
        out.push_str(&format!(
            "Created network security group {} for {}.\n",
            change.nsg_name, change.instance
        ));
    }
    match &change.source {
        Some(source) => out.push_str(&format!(
            "{} on {} now allows {} from {}.\n",
            change.nsg_name, change.instance, change.rule, source
        )),
        None => out.push_str(&format!(
            "{} on {} no longer allows {}.\n",
            change.nsg_name, change.instance, change.rule
        )),
    }

    out.push_str(if change.verified {
        "Verified against a fresh read of the effective state.\n"
    } else {
        "The effective state could not be confirmed; re-run `vm net show` to check.\n"
    });

    if !change.residual_exposure.is_empty() {
        out.push_str(&format!("\n{} is still allowed by:\n", change.rule));
        for residual in &change.residual_exposure {
            out.push_str(&format!("  {residual}\n"));
        }
    }
    for warning in &change.warnings {
        out.push_str(&format!("\nwarning: {warning}\n"));
    }
    out
}

/// The worst severity in an audit, for the process exit decision.
#[must_use]
pub fn audit_severity(result: &NetAudit) -> Severity {
    result
        .audit
        .as_ref()
        .map_or(Severity::Info, |report| report.highest_severity)
}

/// Findings of at least warning severity.
#[must_use]
pub fn concerning_findings(result: &NetAudit) -> Vec<&Finding> {
    result.audit.as_ref().map_or_else(Vec::new, |report| {
        report
            .findings
            .iter()
            .filter(|finding| finding.severity >= Severity::Warning)
            .collect()
    })
}

#[cfg(test)]
#[path = "vmnet_tests.rs"]
mod vmnet_tests;
