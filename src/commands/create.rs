//! `oci-free vm create` — the production launch workflow.
//!
//! The sequence is fixed and every step feeds the next:
//!
//! ```text
//! home region -> availability domains -> shapes -> live billing evidence
//!   -> limits and current usage -> allowed OCPU/memory -> images
//!   -> managed network (reuse or create) -> SSH settings
//!   -> structured plan -> confirmation -> launch with an idempotency token
//!   -> bounded polling -> VNIC and public IP -> NSG verification
//!   -> effective exposure verification -> final SSH information
//! ```
//!
//! Nothing in it is hard-coded: not the shape, not the availability domain, not
//! the image. The shape's eligibility comes from OCI's own `billingType`, the
//! size from the shape's own bounds, the domain from what OCI reports, and the
//! image from the current platform catalogue.
//!
//! Every OCI object this command creates is recorded before the next step runs,
//! so a failure part-way through can either be compensated precisely or
//! reported as a partial mutation with the exact resources retained. It never
//! deletes anything that existed beforehand.

use std::path::Path;

use serde::Serialize;

use crate::{
    commands::{
        context::CommandContext,
        discovery::load_network,
        free::usage_by_allowance,
        network_setup::{self, CreatedResources, ManagedNetwork},
        vmnet::{self, SourceChoice},
    },
    domain::{
        capacity::InstanceDraw,
        exposure::EffectiveExposure,
        launch::{ShapeSelection, default_image, format_quantity, validate_shape_config},
        network::PortRule,
        ownership::{ROLE_INSTANCE, ROLE_INSTANCE_NSG, created_tags},
        plan::{Approval, BillingRisk, ChangeKind, ExposureDelta, MutationPlan, PlannedChange},
    },
    error::{Error, ErrorKind, Result},
    interactive,
    oci::{
        compute::{
            ComputeApi, Image, Instance, LaunchInstanceDetails, LaunchShapeConfig,
            LaunchSourceDetails, LaunchVnicDetails, Shape,
        },
        identity::IdentityApi,
        network::{CreateNsg, NetworkApi, NetworkSecurityGroup},
    },
};

/// Semantic shape selector for the ARM Always Free shape.
pub const SELECTOR_ARM: &str = "free:arm";
/// Semantic shape selector for the x86 Always Free shape.
pub const SELECTOR_X86: &str = "free:x86";

/// What the user asked for.
#[derive(Debug, Clone, Default)]
pub struct CreateRequest {
    pub name: Option<String>,
    pub shape: Option<String>,
    pub ocpus: Option<f64>,
    pub memory: Option<f64>,
    pub image: Option<String>,
    pub availability_domain: Option<String>,
    pub ssh_key: Option<std::path::PathBuf>,
    pub ssh_source: Option<String>,
    pub no_public_ip: bool,
    pub assume_yes: bool,
}

/// The `vm create` payload.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CreateResult {
    pub instance: String,
    pub instance_id: String,
    pub region: String,
    pub availability_domain: String,
    pub shape: String,
    pub ocpus: f64,
    pub memory_gb: f64,
    pub image_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_name: Option<String>,
    pub lifecycle_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nsg_id: Option<String>,
    /// Whether the managed NSG was found attached after the launch.
    pub nsg_verified: bool,
    /// Whether SSH is reachable according to a fresh exposure read.
    pub ssh_reachable: bool,
    /// The command to connect, when there is an address to connect to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_command: Option<String>,
    /// Everything this operation created, for the user's records.
    pub created: CreatedResources,
    pub warnings: Vec<String>,
}

/// Everything the plan was built from, carried into the apply phase.
struct Decision {
    availability_domain: String,
    shape: Shape,
    selection: ShapeSelection,
    image: Image,
    name: String,
    ssh_key: Option<String>,
    ssh_source: Option<SourceChoice>,
    assign_public_ip: bool,
    network: network_setup::NetworkPlan,
}

/// Create an instance.
pub async fn run(
    context: &CommandContext,
    request: &CreateRequest,
) -> Result<(MutationPlan, CreateResult)> {
    // Free Tier capacity lives in the home region, so the whole workflow moves
    // there rather than trusting whatever region the profile names.
    let context = &context.in_home_region().await?;

    let decision = decide(context, request).await?;
    let plan = build_plan(context, &decision).await?;
    let approval = confirm(context, &plan, request.assume_yes)?;

    let result = apply(context, &decision, &approval).await?;
    Ok((plan, result))
}

/// Resolve every choice, from live OCI metadata and the user's flags.
async fn decide(context: &CommandContext, request: &CreateRequest) -> Result<Decision> {
    let compute = ComputeApi::new(context.client());
    let identity = IdentityApi::new(context.client());
    let tenancy = context.tenancy();

    let domains = identity.list_availability_domains(tenancy).await?;
    if domains.is_empty() {
        return Err(
            Error::not_found("OCI reported no availability domains for this tenancy")
                .with_remediation("check the tenancy's region subscriptions in the OCI Console"),
        );
    }

    let availability_domain = match &request.availability_domain {
        Some(requested) => domains
            .iter()
            .find(|domain| domain.name.eq_ignore_ascii_case(requested))
            .map(|domain| domain.name.clone())
            .ok_or_else(|| {
                Error::invalid_input(format!("`{requested}` is not an availability domain here"))
                    .with_context(format!(
                        "this region offers: {}",
                        domains
                            .iter()
                            .map(|domain| domain.name.as_str())
                            .collect::<Vec<&str>>()
                            .join(", ")
                    ))
            })?,
        None => domains[0].name.clone(),
    };

    let shapes = compute
        .list_shapes(tenancy, Some(&availability_domain))
        .await?;
    let shape = choose_shape(context, request, &shapes)?;
    let selection = validate_shape_config(&shape, requested_size(request)?)?;

    let images = compute
        .list_images(tenancy, None, Some(&shape.shape))
        .await?;
    let image = match &request.image {
        Some(requested) => images
            .iter()
            .find(|image| image.id == *requested)
            .cloned()
            .ok_or_else(|| {
                Error::not_found(format!(
                    "no image `{requested}` is compatible with {}",
                    shape.shape
                ))
                .with_remediation("run `oci-free vm create` without --image to see the default")
            })?,
        None => default_image(&images).cloned().ok_or_else(|| {
            Error::not_found(format!(
                "no platform image is available for {}",
                shape.shape
            ))
            .with_context("OCI returned no compatible image in this region")
        })?,
    };

    let name = match &request.name {
        Some(name) => name.clone(),
        None if context.is_interactive() => {
            interactive::input("Instance name", Some("oci-free-1"), "--name")?
        }
        None => "oci-free-1".to_owned(),
    };

    let ssh_key = read_ssh_key(request.ssh_key.as_deref())?;
    let ssh_source = choose_ssh_source(context, request).await?;
    let network = network_setup::plan(context).await?;

    Ok(Decision {
        availability_domain,
        shape,
        selection,
        image,
        name,
        ssh_key,
        ssh_source,
        assign_public_ip: !request.no_public_ip,
        network,
    })
}

/// Resolve a shape name or semantic selector against live metadata.
///
/// A selector such as `free:arm` resolves to whichever shape OCI *currently*
/// reports as Always Free with that architecture — never to a hard-coded name,
/// which would rot the moment Oracle changes the catalogue.
fn choose_shape(
    context: &CommandContext,
    request: &CreateRequest,
    shapes: &[Shape],
) -> Result<Shape> {
    let free_shapes: Vec<&Shape> = shapes
        .iter()
        .filter(|shape| shape.is_always_free())
        .filter(|shape| {
            context
                .policy()
                .snapshot()
                .allowance_for(&shape.shape)
                .is_some()
        })
        .collect();

    let requested = match &request.shape {
        Some(requested) => requested.clone(),
        None => {
            if free_shapes.is_empty() {
                return Err(no_free_shape(shapes));
            }
            if !context.is_interactive() {
                return Err(interactive::not_interactive(
                    "the shape",
                    &format!("--shape, for example --shape {}", free_shapes[0].shape),
                ));
            }
            let options: Vec<String> = free_shapes
                .iter()
                .map(|shape| describe_shape(shape))
                .collect();
            let index = interactive::select("Shape", &options, 0, "--shape")?;
            free_shapes[index].shape.clone()
        }
    };

    let resolved = match requested.to_ascii_lowercase().as_str() {
        SELECTOR_ARM => free_shapes
            .iter()
            .find(|shape| is_arm(shape))
            .map(|shape| (*shape).clone()),
        SELECTOR_X86 => free_shapes
            .iter()
            .find(|shape| !is_arm(shape))
            .map(|shape| (*shape).clone()),
        _ => shapes
            .iter()
            .find(|shape| shape.shape.eq_ignore_ascii_case(&requested))
            .cloned(),
    };

    resolved.ok_or_else(|| {
        Error::not_found(format!("`{requested}` is not offered in this region"))
            .with_context(format!(
                "OCI currently offers these Always Free shapes here: {}",
                if free_shapes.is_empty() {
                    "none".to_owned()
                } else {
                    free_shapes
                        .iter()
                        .map(|shape| shape.shape.as_str())
                        .collect::<Vec<&str>>()
                        .join(", ")
                }
            ))
            .with_remediation("pass --shape with one of the names above, or free:arm / free:x86")
    })
}

/// Whether OCI describes this shape's processor as an Ampere/ARM part.
///
/// Read from the live processor description rather than matched against a
/// shape name, so a renamed shape still resolves correctly.
fn is_arm(shape: &Shape) -> bool {
    let description = shape
        .processor_description
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    description.contains("ampere") || description.contains("arm")
}

fn describe_shape(shape: &Shape) -> String {
    let size = match (shape.ocpus, shape.memory_in_g_bs) {
        (Some(ocpus), Some(memory)) => format!(
            " ({} OCPU, {} GB)",
            format_quantity(ocpus),
            format_quantity(memory)
        ),
        _ if shape.is_flexible() => " (flexible)".to_owned(),
        _ => String::new(),
    };
    format!(
        "{}{size} - {}",
        shape.shape,
        shape
            .processor_description
            .as_deref()
            .unwrap_or("processor unknown")
    )
}

fn no_free_shape(shapes: &[Shape]) -> Error {
    Error::billing_uncertain("no shape in this region is verified Always Free")
        .with_context(format!(
            "OCI offers {} shape(s) here, none of which is both reported as ALWAYS_FREE and \
             covered by a verified allowance",
            shapes.len()
        ))
        .with_remediation("run `oci-free free list` to see the evidence")
}

fn requested_size(request: &CreateRequest) -> Result<Option<(f64, f64)>> {
    crate::commands::policy::parse_projection(request.ocpus, request.memory)
}

fn read_ssh_key(path: Option<&Path>) -> Result<Option<String>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let key = std::fs::read_to_string(path).map_err(|error| {
        Error::invalid_input(format!(
            "could not read the SSH public key {}",
            path.display()
        ))
        .with_context(error.to_string())
        .with_remediation("point --ssh-key at a .pub file, for example ~/.ssh/id_ed25519.pub")
    })?;
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return Err(Error::invalid_input(format!("{} is empty", path.display())));
    }
    if trimmed.contains("PRIVATE KEY") {
        return Err(
            Error::invalid_input("that is a private key, not a public key").with_remediation(
                "pass the matching .pub file; a private key must never be uploaded to an instance",
            ),
        );
    }
    if !trimmed.starts_with("ssh-") && !trimmed.starts_with("ecdsa-") {
        return Err(Error::invalid_input(format!(
            "{} does not look like an OpenSSH public key",
            path.display()
        ))
        .with_context("an OpenSSH public key starts with `ssh-` or `ecdsa-`"));
    }
    Ok(Some(trimmed.to_owned()))
}

/// Decide where SSH may be reached from.
async fn choose_ssh_source(
    context: &CommandContext,
    request: &CreateRequest,
) -> Result<Option<SourceChoice>> {
    match request.ssh_source.as_deref() {
        Some("none") => Ok(None),
        Some(value) if value.eq_ignore_ascii_case(vmnet::SOURCE_MYIP) => {
            vmnet::resolve_my_address(context.is_interactive())
                .await
                .map(Some)
        }
        Some(value) => SourceChoice::parse(value).map(Some),
        // No key means no way to log in, so there is nothing to open.
        None if request.ssh_key.is_none() => Ok(None),
        None if !context.is_interactive() => Err(interactive::not_interactive(
            "the SSH ingress source",
            "--ssh-source <CIDR>, --ssh-source myip, or --ssh-source none to leave SSH closed",
        )),
        None => {
            let options = vec![
                format!(
                    "just this machine - look up my public address via {}",
                    crate::commands::myip::ECHO_ENDPOINT
                ),
                "a specific address or range I will type".to_owned(),
                "every IPv4 address (0.0.0.0/0) - anyone can attempt to log in".to_owned(),
                "leave SSH closed for now".to_owned(),
            ];
            match interactive::select(
                "Who should be able to reach SSH?",
                &options,
                0,
                "--ssh-source",
            )? {
                0 => vmnet::resolve_my_address(true).await.map(Some),
                1 => {
                    let value =
                        interactive::input("Source address or CIDR block", None, "--ssh-source")?;
                    SourceChoice::parse(&value).map(Some)
                }
                2 => {
                    if interactive::confirm(
                        "This lets every host on the internet attempt to log in. Continue?",
                    )? {
                        Ok(Some(SourceChoice::AnyIpv4))
                    } else {
                        Ok(None)
                    }
                }
                _ => Ok(None),
            }
        }
    }
}

/// Build the plan, including the policy decision and the capacity arithmetic.
async fn build_plan(context: &CommandContext, decision: &Decision) -> Result<MutationPlan> {
    let compute = ComputeApi::new(context.client());
    let instances = compute.list_instances(context.tenancy()).await?;
    let shapes = compute.list_shapes(context.tenancy(), None).await?;
    let snapshot = context.policy().snapshot();

    let usage = usage_by_allowance(snapshot, &instances, &shapes);
    let used = snapshot
        .allowance_for(&decision.shape.shape)
        .and_then(|allowance| usage.get(&allowance.id).cloned())
        .unwrap_or_default();

    let draw = InstanceDraw {
        ocpus: decision.selection.ocpus,
        memory_gb: decision.selection.memory_gb,
    };
    let safety = context
        .policy()
        .evaluate_launch(&decision.shape, draw, &used);

    let mut plan = MutationPlan::new("vm.create", context.region().to_string());

    for change in &decision.network.changes {
        plan.add_change(change.clone());
    }

    plan.add_change(
        PlannedChange::new(
            ChangeKind::Create,
            "network security group",
            format!("oci-free-{}", decision.name),
            "attached to the new instance's VNIC",
        )
        .with_note("ingress is scoped to this instance alone"),
    );

    plan.add_change(
        PlannedChange::new(
            ChangeKind::Create,
            "compute instance",
            decision.name.clone(),
            format!(
                "{} in {}, from {}",
                decision.selection,
                decision.availability_domain,
                decision
                    .image
                    .display_name
                    .as_deref()
                    .unwrap_or(&decision.image.id)
            ),
        )
        .with_billing_risk(BillingRisk::from_classification(safety.classification))
        .with_note(if decision.assign_public_ip {
            "an ephemeral public IP will be assigned"
        } else {
            "no public IP will be assigned; the instance will be reachable only inside the VCN"
        }),
    );

    let added = match &decision.ssh_source {
        Some(source) => vec![format!("tcp 22 from {}", source.as_oci_value())],
        None => Vec::new(),
    };
    plan = plan.with_exposure(ExposureDelta {
        added,
        removed: Vec::new(),
        unchanged_residual: Vec::new(),
    });

    for note in &decision.selection.notes {
        plan.add_warning(note.clone());
    }
    for warning in &decision.network.warnings {
        plan.add_warning(warning.clone());
    }
    if let Some(source) = &decision.ssh_source
        && let Some(warning) = source.warning()
    {
        plan.add_warning(warning);
    }
    if decision.ssh_key.is_none() {
        plan.add_warning(
            "no SSH public key was supplied, so the instance will have no way to log in; pass \
             --ssh-key <path to a .pub file> to add one"
                .to_owned(),
        );
    }
    if !decision.assign_public_ip && decision.ssh_source.is_some() {
        plan.add_warning(
            "SSH ingress was requested but the instance will have no public IP, so the rule will \
             only apply inside the VCN"
                .to_owned(),
        );
    }

    Ok(plan.with_safety(safety))
}

/// Show the plan and obtain an approval.
fn confirm(context: &CommandContext, plan: &MutationPlan, assume_yes: bool) -> Result<Approval> {
    if assume_yes {
        return plan.approve(true);
    }
    if !context.is_interactive() {
        if !plan.blockers.is_empty() {
            // Surface the safety refusal rather than the missing terminal.
            return plan.approve(true);
        }
        return Err(interactive::not_interactive(
            "confirmation for vm.create",
            "--yes",
        ));
    }
    print!("{}", plan.render_human());
    let confirmed = interactive::confirm("Create this instance?")?;
    plan.approve(confirmed)
}

/// Perform the writes the approved plan describes.
async fn apply(
    context: &CommandContext,
    decision: &Decision,
    approval: &Approval,
) -> Result<CreateResult> {
    let mut created = CreatedResources::default();

    // Each step records what it created before the next runs, so a failure can
    // be compensated against exactly what exists.
    let network = match &decision.network.existing {
        Some(network) => network.clone(),
        None => match network_setup::provision(context, &mut created, approval).await {
            Ok(network) => network,
            Err(error) => {
                return Err(recover(context, &created, error, "the managed network").await);
            }
        },
    };

    if let Err(error) = await_subnet_available(context, &network.subnet_id).await {
        return Err(recover(context, &created, error, "the managed subnet").await);
    }

    let nsg = match create_nsg(context, decision, &network, approval).await {
        Ok(nsg) => nsg,
        Err(error) => {
            return Err(recover(
                context,
                &created,
                error,
                "the instance's network security group",
            )
            .await);
        }
    };
    created.nsg_id = Some(nsg.id.clone());

    if let Err(error) = await_nsg_available(context, &nsg).await {
        return Err(recover(
            context,
            &created,
            error,
            "the instance's network security group",
        )
        .await);
    }
    let nsg_id = nsg.id;

    if let Some(source) = &decision.ssh_source
        && let Err(error) = add_ssh_rule(context, &nsg_id, source, approval).await
    {
        return Err(recover(context, &created, error, "the SSH ingress rule").await);
    }

    let instance = match launch(context, decision, &network, &nsg_id, approval).await {
        Ok(instance) => instance,
        Err(error) => return Err(recover(context, &created, error, "the instance").await),
    };
    created.instance_id = Some(instance.id.clone());

    // From here on the instance exists. A failure is reported, never rolled
    // back: terminating a machine that may already be running is worse than
    // leaving it with a clear description of its state.
    let (state, mut warnings) =
        crate::commands::vmlifecycle::await_state(context, &instance.id, "RUNNING", &instance)
            .await;

    let after = load_network(context, &instance).await;
    warnings.extend(after.warnings.iter().cloned());
    let exposure = after.exposure();

    let nsg_verified = exposure.as_ref().is_some_and(|exposure| {
        exposure
            .attached_nsgs
            .iter()
            .any(|attached| attached.id == nsg_id)
    });
    if !nsg_verified {
        warnings.push(format!(
            "the managed network security group {nsg_id} was not found attached to the instance's \
             VNIC; run `oci-free vm net {} show` to check",
            decision.name
        ));
    }

    let ssh_reachable = decision.ssh_source.is_some()
        && exposure
            .as_ref()
            .is_some_and(|exposure| exposure.internet.reachable && exposure.allows(ssh_rule()));
    if decision.ssh_source.is_some() && !ssh_reachable {
        warnings.push(verification_note(exposure.as_ref()));
    }

    let public_ip = after
        .vnic
        .as_ref()
        .and_then(|vnic| vnic.public_ip.clone())
        .filter(|ip| !ip.trim().is_empty());
    let private_ip = after.vnic.as_ref().and_then(|vnic| vnic.private_ip.clone());

    Ok(CreateResult {
        instance: instance.label().to_owned(),
        instance_id: instance.id.clone(),
        region: context.region().to_string(),
        availability_domain: decision.availability_domain.clone(),
        shape: decision.selection.shape.clone(),
        ocpus: decision.selection.ocpus,
        memory_gb: decision.selection.memory_gb,
        image_id: decision.image.id.clone(),
        image_name: decision.image.display_name.clone(),
        lifecycle_state: state,
        ssh_command: public_ip
            .as_ref()
            .map(|address| format!("ssh opc@{address}")),
        public_ip,
        private_ip,
        nsg_id: Some(nsg_id),
        nsg_verified,
        ssh_reachable,
        created,
        warnings,
    })
}

fn ssh_rule() -> PortRule {
    "22/tcp".parse().expect("a valid rule")
}

fn verification_note(exposure: Option<&EffectiveExposure>) -> String {
    match exposure {
        Some(exposure) if !exposure.internet.reachable => format!(
            "the SSH rule is in place, but nothing can reach the instance yet: {}",
            exposure.internet.reason
        ),
        Some(_) => "OCI has not yet reported the SSH rule as effective; it usually appears within \
                    a few seconds"
            .to_owned(),
        None => "the instance's effective exposure could not be read, so the SSH rule is \
                 unverified"
            .to_owned(),
    }
}

async fn await_subnet_available(context: &CommandContext, subnet_id: &str) -> Result<()> {
    let api = NetworkApi::new(context.client());
    let poll = context.poll();
    let deadline = std::time::Instant::now() + poll.timeout;

    loop {
        let state = match api.get_subnet(subnet_id).await {
            Ok(subnet) => {
                let state = subnet
                    .lifecycle_state
                    .unwrap_or_else(|| "UNKNOWN".to_owned());
                if state.eq_ignore_ascii_case("AVAILABLE") {
                    return Ok(());
                }
                if matches!(state.as_str(), "TERMINATING" | "TERMINATED") {
                    return Err(Error::malformed_response(format!(
                        "the managed subnet reached {state} before the instance could be launched"
                    ))
                    .with_context(format!("subnet {subnet_id}"))
                    .with_remediation(
                        "run `oci-free vm create` again after checking the managed network",
                    ));
                }
                state
            }
            Err(error) if error.kind() == ErrorKind::NotFound => "not yet visible".to_owned(),
            Err(error) => return Err(error),
        };

        if std::time::Instant::now() >= deadline {
            return Err(Error::timeout(
                "the managed subnet did not become AVAILABLE before the network readiness deadline",
            )
            .with_context(format!("subnet {subnet_id} was {state}"))
            .with_remediation(
                "wait for OCI networking to finish provisioning, then retry `oci-free vm create`",
            ));
        }
        tokio::time::sleep(poll.interval).await;
    }
}

async fn await_nsg_available(context: &CommandContext, nsg: &NetworkSecurityGroup) -> Result<()> {
    if nsg
        .lifecycle_state
        .as_deref()
        .is_some_and(|state| state.eq_ignore_ascii_case("AVAILABLE"))
    {
        return Ok(());
    }

    let api = NetworkApi::new(context.client());
    let poll = context.poll();
    let deadline = std::time::Instant::now() + poll.timeout;

    loop {
        let state = match api.get_nsg(&nsg.id).await {
            Ok(current) => {
                let state = current
                    .lifecycle_state
                    .unwrap_or_else(|| "UNKNOWN".to_owned());
                if state.eq_ignore_ascii_case("AVAILABLE") {
                    return Ok(());
                }
                if matches!(state.as_str(), "TERMINATING" | "TERMINATED") {
                    return Err(Error::malformed_response(format!(
                        "the network security group reached {state} before its rules could be configured"
                    ))
                    .with_context(format!("network security group {}", nsg.id))
                    .with_remediation("retry `oci-free vm create`; the failed operation will only reuse resources it can prove it owns"));
                }
                state
            }
            Err(error) if error.kind() == ErrorKind::NotFound => "not yet visible".to_owned(),
            Err(error) => return Err(error),
        };

        if std::time::Instant::now() >= deadline {
            return Err(Error::timeout(
                "the network security group did not become AVAILABLE before the readiness deadline",
            )
            .with_context(format!("network security group {} was {state}", nsg.id))
            .with_remediation(
                "wait for OCI networking to finish provisioning, then retry `oci-free vm create`",
            ));
        }
        tokio::time::sleep(poll.interval).await;
    }
}

async fn create_nsg(
    context: &CommandContext,
    decision: &Decision,
    network: &ManagedNetwork,
    approval: &Approval,
) -> Result<NetworkSecurityGroup> {
    debug_assert!(approval.operation() == "vm.create");
    NetworkApi::new(context.client())
        .create_nsg(
            &CreateNsg {
                compartment_id: context.tenancy().as_str().to_owned(),
                vcn_id: network.vcn_id.clone(),
                display_name: format!("oci-free-{}", decision.name),
                freeform_tags: created_tags(ROLE_INSTANCE_NSG, None),
            },
            &vmnet::retry_token("nsg", &decision.name),
        )
        .await
}

async fn add_ssh_rule(
    context: &CommandContext,
    nsg_id: &str,
    source: &SourceChoice,
    approval: &Approval,
) -> Result<()> {
    debug_assert!(approval.operation() == "vm.create");
    NetworkApi::new(context.client())
        .add_nsg_rules(
            nsg_id,
            vec![crate::oci::network::AddSecurityRule {
                direction: "INGRESS".to_owned(),
                protocol: vmnet::oci_protocol(crate::domain::network::Protocol::Tcp).to_owned(),
                source: Some(source.as_oci_value()),
                source_type: Some("CIDR_BLOCK".to_owned()),
                destination: None,
                destination_type: None,
                is_stateless: false,
                tcp_options: Some(crate::oci::network::TransportOptions {
                    destination_port_range: Some(crate::oci::network::PortRange::exactly(22)),
                    source_port_range: None,
                }),
                udp_options: None,
                description: Some(format!("{} 22/tcp", vmnet::MANAGED_RULE_PREFIX)),
            }],
        )
        .await?;
    Ok(())
}

async fn launch(
    context: &CommandContext,
    decision: &Decision,
    network: &ManagedNetwork,
    nsg_id: &str,
    approval: &Approval,
) -> Result<Instance> {
    debug_assert!(approval.operation() == "vm.create");
    let mut metadata = std::collections::BTreeMap::new();
    if let Some(key) = &decision.ssh_key {
        metadata.insert("ssh_authorized_keys".to_owned(), key.clone());
    }

    ComputeApi::new(context.client())
        .launch_instance(
            &LaunchInstanceDetails {
                availability_domain: decision.availability_domain.clone(),
                compartment_id: context.tenancy().as_str().to_owned(),
                shape: decision.selection.shape.clone(),
                shape_config: decision.selection.is_flexible.then_some(LaunchShapeConfig {
                    ocpus: decision.selection.ocpus,
                    memory_in_g_bs: decision.selection.memory_gb,
                }),
                display_name: decision.name.clone(),
                source_details: LaunchSourceDetails::from_image(decision.image.id.clone(), None),
                create_vnic_details: LaunchVnicDetails {
                    subnet_id: network.subnet_id.clone(),
                    assign_public_ip: decision.assign_public_ip
                        && network.public_addressing_allowed,
                    // Attached at launch, so the instance is never briefly live
                    // with only subnet-wide rules governing it.
                    nsg_ids: vec![nsg_id.to_owned()],
                    display_name: Some(format!("{} primary vnic", decision.name)),
                    hostname_label: None,
                },
                metadata,
                freeform_tags: created_tags(ROLE_INSTANCE, None),
            },
            &vmnet::retry_token("instance", &decision.name),
        )
        .await
}

/// Undo what this operation created, and report anything that survived.
async fn recover(
    context: &CommandContext,
    created: &CreatedResources,
    cause: Error,
    step: &str,
) -> Error {
    if created.is_empty() {
        return cause;
    }

    let (retained, problems) = network_setup::compensate(context, created).await;
    if retained.is_empty() && problems.is_empty() {
        return cause.with_context(format!(
            "{step} could not be created; everything oci-free had created for this operation was \
             removed again, and nothing that existed beforehand was touched"
        ));
    }

    Error::partial_mutation(format!("vm create stopped while creating {step}"))
        .with_context(format!(
            "{}. These resources were created and could not be removed: {}. {}",
            cause.message(),
            retained.describe().join(", "),
            problems.join("; ")
        ))
        .with_remediation(
            "the retained resources are listed above and are tagged `oci-free:managed=created`; \
             remove them in the OCI Console, or re-run `oci-free vm create` which will reuse them",
        )
}

/// Render `vm create` for a terminal.
#[must_use]
pub fn render_human(result: &CreateResult) -> String {
    let mut out = format!(
        "Created {} ({}) in {}\n\n",
        result.instance, result.lifecycle_state, result.region
    );

    out.push_str(&format!("  OCID           {}\n", result.instance_id));
    out.push_str(&format!(
        "  domain         {}\n",
        result.availability_domain
    ));
    out.push_str(&format!(
        "  shape          {} ({} OCPU, {} GB)\n",
        result.shape,
        format_quantity(result.ocpus),
        format_quantity(result.memory_gb)
    ));
    out.push_str(&format!(
        "  image          {}\n",
        result.image_name.as_deref().unwrap_or(&result.image_id)
    ));
    out.push_str(&format!(
        "  private IP     {}\n",
        result.private_ip.as_deref().unwrap_or("none")
    ));
    out.push_str(&format!(
        "  public IP      {}\n",
        result.public_ip.as_deref().unwrap_or("none")
    ));
    if let Some(nsg) = &result.nsg_id {
        out.push_str(&format!(
            "  NSG            {nsg} ({})\n",
            if result.nsg_verified {
                "attached and verified"
            } else {
                "not yet confirmed attached"
            }
        ));
    }

    if let Some(command) = &result.ssh_command {
        out.push_str(&format!(
            "\nConnect with:\n  {command}\n{}",
            if result.ssh_reachable {
                ""
            } else {
                "  (SSH is not reachable yet; see the warnings below)\n"
            }
        ));
    }

    for warning in &result.warnings {
        out.push_str(&format!("\nwarning: {warning}\n"));
    }
    out
}

#[cfg(test)]
#[path = "create_tests.rs"]
mod create_tests;

#[cfg(test)]
mod provisioning_regression_tests {
    use serde_json::json;

    use super::*;
    use crate::testing::mock_oci::{MockOci, Reply};

    #[tokio::test]
    async fn waits_for_a_new_nsg_to_become_available_before_configuring_it() {
        let nsg_id = "ocid1.networksecuritygroup.oc1.iad.provisioning";
        let initial: NetworkSecurityGroup = serde_json::from_value(json!({
            "id": nsg_id,
            "vcnId": "ocid1.vcn.oc1.iad.a",
            "lifecycleState": "PROVISIONING"
        }))
        .expect("nsg");

        let mock = MockOci::builder()
            .route(
                "GET",
                nsg_id,
                vec![
                    Reply::json(&json!({
                        "id": nsg_id,
                        "vcnId": "ocid1.vcn.oc1.iad.a",
                        "lifecycleState": "PROVISIONING"
                    })),
                    Reply::json(&json!({
                        "id": nsg_id,
                        "vcnId": "ocid1.vcn.oc1.iad.a",
                        "lifecycleState": "AVAILABLE"
                    })),
                ],
            )
            .start()
            .await;
        let context = CommandContext::for_tests(mock.client(), "us-ashburn-1");

        await_nsg_available(&context, &initial)
            .await
            .expect("the NSG becomes available");

        let reads = mock
            .requests()
            .into_iter()
            .filter(|request| request.method() == "GET")
            .count();
        assert_eq!(reads, 2, "the provisioning state must be polled");
    }

    #[tokio::test]
    async fn waits_for_a_subnet_to_become_available_before_launch() {
        let subnet_id = "ocid1.subnet.oc1.iad.provisioning";
        let mock = MockOci::builder()
            .route(
                "GET",
                subnet_id,
                vec![
                    Reply::json(&json!({
                        "id": subnet_id,
                        "vcnId": "ocid1.vcn.oc1.iad.a",
                        "lifecycleState": "PROVISIONING"
                    })),
                    Reply::json(&json!({
                        "id": subnet_id,
                        "vcnId": "ocid1.vcn.oc1.iad.a",
                        "lifecycleState": "AVAILABLE"
                    })),
                ],
            )
            .start()
            .await;
        let context = CommandContext::for_tests(mock.client(), "us-ashburn-1");

        await_subnet_available(&context, subnet_id)
            .await
            .expect("the subnet becomes available");

        let reads = mock
            .requests()
            .into_iter()
            .filter(|request| request.method() == "GET")
            .count();
        assert_eq!(reads, 2, "the provisioning state must be polled");
    }
}
