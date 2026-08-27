//! `oci-free vm start | stop | reboot` — instance lifecycle.
//!
//! Lifecycle actions are cheap to get wrong in confusing ways, so three rules
//! apply:
//!
//! * the current state is validated first. Starting an already-running
//!   instance, or stopping a terminated one, is reported as a no-op or a
//!   refusal rather than sent to OCI to fail obscurely;
//! * every action carries an OCI retry token, so a replay after a lost
//!   response cannot double-apply;
//! * polling is bounded, and an unexpected terminal state ends the wait with a
//!   clear message rather than spinning until the timeout.
//!
//! These are not billing mutations — a stopped Always Free instance keeps its
//! allocation — so they still go through a plan, but the plan's billing risk is
//! `none` and the confirmation exists to prevent acting on the wrong machine.

use serde::Serialize;

use crate::{
    commands::{context::CommandContext, discovery::resolve_instance, vmnet::retry_token},
    domain::{
        ownership::classify,
        plan::{Approval, ChangeKind, MutationPlan, PlannedChange},
    },
    error::{Error, Result},
    interactive,
    oci::compute::{ComputeApi, Instance, InstanceAction},
};

/// States an instance can never leave on its own.
const TERMINAL_STATES: [&str; 2] = ["TERMINATED", "TERMINATING"];

/// The result of a lifecycle action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LifecycleResult {
    pub instance: String,
    pub instance_id: String,
    pub region: String,
    pub action: String,
    pub state_before: String,
    pub state_after: String,
    /// Whether the instance reached the state the action targets.
    pub reached_target: bool,
    /// True when the instance was already in the target state.
    pub no_op: bool,
    pub warnings: Vec<String>,
}

/// Run a lifecycle action against one instance.
pub async fn run(
    context: &CommandContext,
    reference: &str,
    action: InstanceAction,
    assume_yes: bool,
) -> Result<(MutationPlan, LifecycleResult)> {
    let instance = resolve_instance(context, reference).await?;
    let plan = plan_action(context, &instance, action)?;

    // Already in the target state: nothing to do, and nothing to confirm.
    if instance.lifecycle_state == action.target_state() {
        return Ok((
            plan,
            LifecycleResult {
                instance: instance.label().to_owned(),
                instance_id: instance.id.clone(),
                region: context.region().to_string(),
                action: action.as_str().to_owned(),
                state_before: instance.lifecycle_state.clone(),
                state_after: instance.lifecycle_state.clone(),
                reached_target: true,
                no_op: true,
                warnings: vec![format!(
                    "{} is already {}; nothing was changed",
                    instance.label(),
                    action.target_state()
                )],
            },
        ));
    }

    let approval = confirm(context, &plan, assume_yes)?;
    apply(context, &instance, action, &approval).await
}

/// Build the plan for a lifecycle action.
pub fn plan_action(
    context: &CommandContext,
    instance: &Instance,
    action: InstanceAction,
) -> Result<MutationPlan> {
    let mut plan = MutationPlan::new(
        format!("vm.{}", action_command(action)),
        context.region().to_string(),
    );

    plan.add_change(
        PlannedChange::new(
            ChangeKind::Modify,
            "compute instance",
            instance.label(),
            action.target_state(),
        )
        .with_id(instance.id.clone())
        .with_before(instance.lifecycle_state.clone())
        .with_ownership(classify(&instance.freeform_tags))
        .with_note(match action {
            InstanceAction::Stop => {
                "an immediate power off does not flush the guest's filesystem buffers"
            }
            InstanceAction::Reset => "an immediate power cycle does not shut the guest down first",
            _ => "the guest operating system is asked to shut down or start cleanly",
        }),
    );

    if TERMINAL_STATES.contains(&instance.lifecycle_state.as_str()) {
        plan.add_blocker(format!(
            "{} is {} and cannot be acted on",
            instance.label(),
            instance.lifecycle_state
        ));
        return Ok(plan);
    }

    if instance.lifecycle_state != action.target_state()
        && !action
            .valid_from()
            .contains(&instance.lifecycle_state.as_str())
    {
        plan.add_blocker(format!(
            "{} is {}, and {} applies only to an instance that is {}",
            instance.label(),
            instance.lifecycle_state,
            action.as_str(),
            action.valid_from().join(" or ")
        ));
    }

    if matches!(action, InstanceAction::Stop | InstanceAction::SoftStop) {
        plan.add_warning(
            "a stopped instance keeps its shape allocation, so stopping does not free capacity \
             for another Always Free instance"
                .to_owned(),
        );
    }

    Ok(plan)
}

async fn apply(
    context: &CommandContext,
    instance: &Instance,
    action: InstanceAction,
    approval: &Approval,
) -> Result<(MutationPlan, LifecycleResult)> {
    debug_assert!(approval.operation().starts_with("vm."));
    let api = ComputeApi::new(context.client());

    // The token is derived from the instance and the action, so a replayed
    // request is collapsed by OCI rather than applied twice.
    let token = retry_token(action.as_str(), &instance.id);
    let updated = api.instance_action(&instance.id, action, &token).await?;

    let (state_after, mut warnings) =
        await_state(context, &instance.id, action.target_state(), &updated).await;

    let reached_target = state_after == action.target_state();
    if !reached_target {
        warnings.push(format!(
            "{} is {state_after} rather than {}; re-run `oci-free vm info {}` to follow it",
            instance.label(),
            action.target_state(),
            instance.label()
        ));
    }

    Ok((
        plan_action(context, instance, action)?,
        LifecycleResult {
            instance: instance.label().to_owned(),
            instance_id: instance.id.clone(),
            region: context.region().to_string(),
            action: action.as_str().to_owned(),
            state_before: instance.lifecycle_state.clone(),
            state_after,
            reached_target,
            no_op: false,
            warnings,
        },
    ))
}

/// Poll until the instance reaches `target`, the deadline passes, or it lands
/// somewhere it can never leave.
pub async fn await_state(
    context: &CommandContext,
    instance_id: &str,
    target: &str,
    current: &Instance,
) -> (String, Vec<String>) {
    let api = ComputeApi::new(context.client());
    let poll = context.poll();
    let mut state = current.lifecycle_state.clone();
    let mut warnings = Vec::new();
    let deadline = std::time::Instant::now() + poll.timeout;

    while state != target {
        if TERMINAL_STATES.contains(&state.as_str()) && target != state {
            warnings.push(format!(
                "the instance reached {state}, which it cannot leave, so waiting stopped"
            ));
            break;
        }
        if std::time::Instant::now() >= deadline {
            warnings.push(format!(
                "the instance was still {state} after {:?}; OCI may still be working on it",
                poll.timeout
            ));
            break;
        }

        tokio::time::sleep(poll.interval).await;
        match api.get_instance(instance_id).await {
            Ok(instance) => state = instance.lifecycle_state,
            Err(error) => {
                warnings.push(format!(
                    "the instance state could not be re-read while waiting: {error}"
                ));
                break;
            }
        }
    }

    (state, warnings)
}

/// The dotted command name for an action.
#[must_use]
pub fn action_command(action: InstanceAction) -> &'static str {
    match action {
        InstanceAction::Start => "start",
        InstanceAction::Stop | InstanceAction::SoftStop => "stop",
        InstanceAction::Reset | InstanceAction::SoftReset => "reboot",
    }
}

/// Show the plan and obtain an approval.
pub fn confirm(
    context: &CommandContext,
    plan: &MutationPlan,
    assume_yes: bool,
) -> Result<Approval> {
    if assume_yes {
        return plan.approve(true);
    }
    if !context.is_interactive() {
        // Surface the blockers even when refusing for lack of a terminal: the
        // user should learn the plan is impossible, not only that it was not
        // confirmed.
        if !plan.blockers.is_empty() {
            return plan.approve(true);
        }
        return Err(interactive::not_interactive(
            &format!("confirmation for {}", plan.operation),
            "--yes",
        ));
    }
    print!("{}", plan.render_human());
    let confirmed = interactive::confirm("Apply this plan?")?;
    plan.approve(confirmed)
}

/// Render a lifecycle result for a terminal.
#[must_use]
pub fn render_human(result: &LifecycleResult) -> String {
    let mut out = if result.no_op {
        format!(
            "{} is already {}; nothing was changed.\n",
            result.instance, result.state_after
        )
    } else {
        format!(
            "{}: {} -> {}\n",
            result.instance, result.state_before, result.state_after
        )
    };
    if !result.reached_target && !result.no_op {
        out.push_str("The instance has not reached the target state yet.\n");
    }
    for warning in &result.warnings {
        out.push_str(&format!("\nwarning: {warning}\n"));
    }
    out
}

/// Map the CLI's flags onto an OCI action.
#[must_use]
pub fn stop_action(force: bool) -> InstanceAction {
    if force {
        InstanceAction::Stop
    } else {
        InstanceAction::SoftStop
    }
}

/// Map the CLI's flags onto an OCI action.
#[must_use]
pub fn reboot_action(force: bool) -> InstanceAction {
    if force {
        InstanceAction::Reset
    } else {
        InstanceAction::SoftReset
    }
}

/// Wrap an unmet-state refusal so the exit code says "wrong state".
pub fn refuse_if_blocked(plan: &MutationPlan) -> Result<()> {
    if plan.blockers.is_empty() {
        return Ok(());
    }
    Err(
        Error::unsupported_state(format!("{} cannot proceed", plan.operation))
            .with_context(plan.blockers.join("; "))
            .with_remediation("run `oci-free vm info <instance>` to see the current state"),
    )
}

#[cfg(test)]
#[path = "vmlifecycle_tests.rs"]
mod vmlifecycle_tests;
