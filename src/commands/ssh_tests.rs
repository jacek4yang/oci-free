//! SSH tests.
//!
//! The safety property under test is that the command is an argument vector,
//! never a shell string, so a hostile display name cannot become a command.

use serde_json::json;

use super::*;
use crate::testing::mock_oci::{MockOci, TENANCY};

const INSTANCE_ID: &str = "ocid1.instance.oc1.iad.anuwcljtexampleinstance1";
const VNIC_ID: &str = "ocid1.vnic.oc1.iad.abuwcljrexamplevnic1";
const SUBNET_ID: &str = "ocid1.subnet.oc1.iad.aaaaaaaaexamplesubnet1";
const IMAGE_ID: &str = "ocid1.image.oc1.iad.aaaaaaaaexampleimage1";

fn instance_json() -> serde_json::Value {
    json!({
        "id": INSTANCE_ID,
        "compartmentId": TENANCY,
        "displayName": "free-arm-1",
        "lifecycleState": "RUNNING",
        "shape": "VM.Standard.A1.Flex",
        "imageId": IMAGE_ID
    })
}

fn vnic_json(public_ip: Option<&str>) -> serde_json::Value {
    json!({
        "id": VNIC_ID,
        "subnetId": SUBNET_ID,
        "privateIp": "10.0.0.42",
        "publicIp": public_ip,
        "isPrimary": true,
        "nsgIds": [],
        "lifecycleState": "AVAILABLE"
    })
}

fn subnet_json() -> serde_json::Value {
    json!({
        "id": SUBNET_ID,
        "vcnId": "ocid1.vcn.oc1.iad.v",
        "cidrBlock": "10.0.0.0/24",
        "securityListIds": [],
        "lifecycleState": "AVAILABLE"
    })
}

async fn mock(public_ip: Option<&str>, os: &str) -> MockOci {
    MockOci::builder()
        .get(
            "/vnicAttachments",
            &json!([{
                "id": "ocid1.vnicattachment.oc1.iad.a",
                "instanceId": INSTANCE_ID,
                "vnicId": VNIC_ID,
                "lifecycleState": "ATTACHED"
            }]),
        )
        .get(&format!("/instances/{INSTANCE_ID}"), &instance_json())
        .get("/instances?", &json!([instance_json()]))
        .get(&format!("/vnics/{VNIC_ID}"), &vnic_json(public_ip))
        .get(&format!("/subnets/{SUBNET_ID}"), &subnet_json())
        .get(
            &format!("/images/{IMAGE_ID}"),
            &json!({
                "id": IMAGE_ID,
                "displayName": "Oracle-Linux-9-aarch64-2026.08.01-0",
                "operatingSystem": os,
                "operatingSystemVersion": "9",
                "lifecycleState": "AVAILABLE"
            }),
        )
        .start()
        .await
}

fn context(mock: &MockOci) -> CommandContext {
    CommandContext::for_tests(mock.client(), "us-ashburn-1")
}

#[tokio::test]
async fn discovers_the_address_and_the_images_default_login_name() {
    let mock = mock(Some("203.0.113.17"), "Oracle Linux").await;
    let target = run(&context(&mock), "free-arm-1", None, None, SshMode::Print)
        .await
        .expect("ssh target resolves");

    assert_eq!(target.host, "203.0.113.17");
    assert_eq!(target.user, "opc");
    assert_eq!(target.command, vec!["ssh", "opc@203.0.113.17"]);
    assert!(!target.launched, "print mode must not launch anything");
}

#[tokio::test]
async fn a_custom_launch_username_is_reused_by_vm_ssh() {
    let mock = mock(Some("203.0.113.17"), "Oracle Linux").await;
    let mut instance: crate::oci::compute::Instance =
        serde_json::from_value(instance_json()).expect("instance");
    instance
        .freeform_tags
        .insert("oci-free:ssh-user".to_owned(), "jacek".to_owned());

    let (user, warning) = default_user(&context(&mock), &instance).await;
    assert_eq!(user, "jacek");
    assert!(warning.is_none());
}

#[tokio::test]
async fn ubuntu_images_use_the_ubuntu_login_name() {
    let mock = mock(Some("203.0.113.17"), "Canonical Ubuntu").await;
    let target = run(&context(&mock), "free-arm-1", None, None, SshMode::Print)
        .await
        .expect("ssh target resolves");
    assert_eq!(target.user, "ubuntu");
    assert!(
        !target
            .warnings
            .iter()
            .any(|warning| warning.contains("--user")),
        "a known operating system needs no login-name warning: {:?}",
        target.warnings
    );
}

/// An unknown operating system gets a documented assumption plus a warning,
/// never a silent guess.
#[tokio::test]
async fn an_unknown_operating_system_warns_about_the_assumed_login_name() {
    let mock = mock(Some("203.0.113.17"), "Some New Distro").await;
    let target = run(&context(&mock), "free-arm-1", None, None, SshMode::Print)
        .await
        .expect("ssh target resolves");

    assert_eq!(target.user, "opc");
    assert!(
        target
            .warnings
            .iter()
            .any(|warning| warning.contains("--user")),
        "{:?}",
        target.warnings
    );
}

#[tokio::test]
async fn an_explicit_user_and_identity_are_used_verbatim() {
    let mock = mock(Some("203.0.113.17"), "Oracle Linux").await;
    let identity = PathBuf::from("/home/me/.ssh/id_ed25519");
    let target = run(
        &context(&mock),
        "free-arm-1",
        Some("deploy"),
        Some(&identity),
        SshMode::Print,
    )
    .await
    .expect("ssh target resolves");

    assert_eq!(
        target.command,
        vec![
            "ssh",
            "-i",
            "/home/me/.ssh/id_ed25519",
            "deploy@203.0.113.17"
        ]
    );
}

/// An instance with no public address is a clear refusal, not a malformed
/// response or an attempt to connect to nothing.
#[tokio::test]
async fn an_instance_without_a_public_ip_is_refused_with_guidance() {
    let mock = mock(None, "Oracle Linux").await;
    let error = run(&context(&mock), "free-arm-1", None, None, SshMode::Print)
        .await
        .expect_err("must refuse");

    assert!(error.message().contains("no public IP"));
    assert!(
        error
            .context()
            .expect("context")
            .contains("private address")
    );
    assert!(!error.remediation().is_empty());
}

/// The instance is reachable only if something opens port 22, and the command
/// says so rather than letting the user watch a connection time out.
#[tokio::test]
async fn a_closed_ssh_port_is_warned_about() {
    let mock = mock(Some("203.0.113.17"), "Oracle Linux").await;
    let target = run(&context(&mock), "free-arm-1", None, None, SshMode::Print)
        .await
        .expect("ssh target resolves");

    assert!(
        target
            .warnings
            .iter()
            .any(|warning| warning.contains("open 22/tcp")),
        "{:?}",
        target.warnings
    );
}

/// The central injection property: every value goes into its own argv slot.
#[tokio::test]
async fn hostile_metacharacters_stay_inside_one_argument() {
    let mock = mock(Some("203.0.113.17"), "Oracle Linux").await;
    let target = run(
        &context(&mock),
        "free-arm-1",
        Some("evil; rm -rf /"),
        None,
        SshMode::Print,
    )
    .await
    .expect("ssh target resolves");

    assert_eq!(
        target.command,
        vec!["ssh", "evil; rm -rf /@203.0.113.17"],
        "the whole user@host must be one argument"
    );
    assert_eq!(
        target.command.len(),
        2,
        "no metacharacter may split the command into more arguments"
    );
}

/// The displayed command is quoted so that copy-pasting it is also safe.
#[test]
fn the_displayed_command_is_shell_quoted() {
    let quoted = shell_quote(&["ssh".to_owned(), "evil; rm -rf /@203.0.113.17".to_owned()]);
    assert_eq!(quoted, "ssh 'evil; rm -rf /@203.0.113.17'");

    let plain = shell_quote(&["ssh".to_owned(), "opc@203.0.113.17".to_owned()]);
    assert_eq!(plain, "ssh opc@203.0.113.17");

    let apostrophe = shell_quote(&["it's".to_owned()]);
    assert!(apostrophe.starts_with('\'') && apostrophe.ends_with('\''));
}

/// JSON mode must be safe to run in a pipeline, so it never takes the terminal.
#[tokio::test]
async fn json_mode_reports_the_command_without_launching_it() {
    let mock = mock(Some("203.0.113.17"), "Oracle Linux").await;
    let target = run(&context(&mock), "free-arm-1", None, None, SshMode::Print)
        .await
        .expect("ssh target resolves");

    let value = serde_json::to_value(&target).expect("serialize");
    assert_eq!(value["launched"], false);
    assert!(value.get("exit_code").is_none());
    assert_eq!(value["command"][0], "ssh");
    assert_eq!(value["host"], "203.0.113.17");
}
