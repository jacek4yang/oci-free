//! Lifecycle tests.
//!
//! The properties: a state that makes the action meaningless is caught before
//! any request is sent, every action carries an idempotency token, and an
//! unconfirmed plan writes nothing.

use serde_json::json;

use super::*;
use crate::testing::mock_oci::{MockOci, Reply, TENANCY};

const INSTANCE_ID: &str = "ocid1.instance.oc1.iad.anuwcljtexampleinstance1";

fn instance_json(state: &str) -> serde_json::Value {
    json!({
        "id": INSTANCE_ID,
        "compartmentId": TENANCY,
        "displayName": "free-arm-1",
        "lifecycleState": state,
        "shape": "VM.Standard.A1.Flex",
        "shapeConfig": { "ocpus": 2.0, "memoryInGBs": 12.0 },
        "freeformTags": { "oci-free:managed": "created", "oci-free:role": "instance" }
    })
}

async fn mock(states: &[&str]) -> MockOci {
    let replies: Vec<Reply> = states
        .iter()
        .map(|state| Reply::json(&instance_json(state)))
        .collect();
    MockOci::builder()
        .route("GET", &format!("/instances/{INSTANCE_ID}"), replies.clone())
        .get("/instances?", &json!([instance_json(states[0])]))
        .route("POST", "/instances/", replies)
        .start()
        .await
}

fn context(mock: &MockOci) -> CommandContext {
    CommandContext::for_tests(mock.client(), "us-ashburn-1")
}

#[tokio::test]
async fn starting_a_stopped_instance_reaches_running() {
    let mock = mock(&["STOPPED", "RUNNING"]).await;
    let (plan, result) = run(&context(&mock), "free-arm-1", InstanceAction::Start, true)
        .await
        .expect("start succeeds");

    assert!(plan.is_safe());
    assert_eq!(result.state_before, "STOPPED");
    assert_eq!(result.state_after, "RUNNING");
    assert!(result.reached_target);
    assert!(!result.no_op);

    let writes = mock.writes();
    assert_eq!(writes.len(), 1);
    assert!(writes[0].target().contains("action=START"));
    assert!(
        writes[0].header("opc-retry-token").is_some(),
        "a lifecycle action must be replay-safe"
    );
}

/// An instance already in the target state is a no-op, not a request.
#[tokio::test]
async fn starting_a_running_instance_is_a_no_op() {
    let mock = mock(&["RUNNING"]).await;
    let (_, result) = run(&context(&mock), "free-arm-1", InstanceAction::Start, true)
        .await
        .expect("start succeeds");

    assert!(result.no_op);
    assert!(result.reached_target);
    assert!(
        mock.writes().is_empty(),
        "a no-op must not send a request: {:?}",
        mock.writes()
    );
    assert!(render_human(&result).contains("already RUNNING"));
}

/// Acting on a terminated instance is refused before anything is sent.
#[tokio::test]
async fn a_terminated_instance_is_refused_without_a_request() {
    let mock = mock(&["TERMINATED"]).await;
    let error = run(&context(&mock), INSTANCE_ID, InstanceAction::Start, true)
        .await
        .expect_err("must refuse");

    assert!(error.context().unwrap_or_default().contains("TERMINATED"));
    assert!(mock.writes().is_empty());
}

/// Stopping an instance that is not running is a state error, not a request.
#[tokio::test]
async fn an_action_invalid_for_the_current_state_is_refused() {
    let mock = mock(&["PROVISIONING"]).await;
    let error = run(&context(&mock), INSTANCE_ID, InstanceAction::SoftStop, true)
        .await
        .expect_err("must refuse");

    assert!(error.context().unwrap_or_default().contains("PROVISIONING"));
    assert!(mock.writes().is_empty());
}

/// The write-safety property, again: no confirmation, no request.
#[tokio::test]
async fn an_unconfirmed_action_issues_no_request() {
    let mock = mock(&["STOPPED"]).await;
    let error = run(&context(&mock), "free-arm-1", InstanceAction::Start, false)
        .await
        .expect_err("a non-interactive run without --yes must refuse");

    assert!(error.remediation().contains("--yes"));
    assert!(mock.writes().is_empty());
}

#[tokio::test]
async fn stopping_warns_that_capacity_is_not_released() {
    let mock = mock(&["RUNNING", "STOPPED"]).await;
    let (plan, _) = run(
        &context(&mock),
        "free-arm-1",
        InstanceAction::SoftStop,
        true,
    )
    .await
    .expect("stop succeeds");

    assert!(
        plan.warnings
            .iter()
            .any(|warning| warning.contains("keeps its shape allocation")),
        "{:?}",
        plan.warnings
    );
}

#[tokio::test]
async fn a_forced_stop_is_reported_as_an_immediate_power_off() {
    let mock = mock(&["RUNNING", "STOPPED"]).await;
    let (plan, result) = run(&context(&mock), "free-arm-1", stop_action(true), true)
        .await
        .expect("stop succeeds");

    assert_eq!(result.action, "STOP");
    assert!(mock.writes()[0].target().contains("action=STOP"));
    assert!(
        plan.render_human().contains("filesystem buffers"),
        "the plan must say what an immediate power off risks"
    );
}

#[test]
fn flags_map_onto_the_documented_oci_actions() {
    assert_eq!(stop_action(false), InstanceAction::SoftStop);
    assert_eq!(stop_action(true), InstanceAction::Stop);
    assert_eq!(reboot_action(false), InstanceAction::SoftReset);
    assert_eq!(reboot_action(true), InstanceAction::Reset);

    assert_eq!(InstanceAction::SoftStop.as_str(), "SOFTSTOP");
    assert_eq!(InstanceAction::SoftReset.as_str(), "SOFTRESET");
    assert_eq!(InstanceAction::Start.target_state(), "RUNNING");
    assert_eq!(InstanceAction::SoftStop.target_state(), "STOPPED");
    assert_eq!(InstanceAction::SoftReset.target_state(), "RUNNING");
}

#[test]
fn command_names_group_the_two_stop_and_reboot_variants() {
    assert_eq!(action_command(InstanceAction::Start), "start");
    assert_eq!(action_command(InstanceAction::Stop), "stop");
    assert_eq!(action_command(InstanceAction::SoftStop), "stop");
    assert_eq!(action_command(InstanceAction::Reset), "reboot");
    assert_eq!(action_command(InstanceAction::SoftReset), "reboot");
}
