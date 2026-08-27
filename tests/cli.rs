//! End-to-end tests of the built binary.
//!
//! Everything here runs the real executable with **stdin closed**, which is the
//! condition that matters most for automation: a command that would prompt has
//! nothing to read, so a bug that reaches a prompt shows up as a hung test
//! rather than as a surprise in someone's CI pipeline.
//!
//! No OCI credentials are involved. Every command is pointed at a configuration
//! file that does not exist, so each one fails at the same well-defined place —
//! which is exactly what makes the exit-code contract testable without a
//! tenancy.

use std::{
    path::PathBuf,
    process::{Command, Output, Stdio},
};

/// Exit codes from `docs/COMMANDS.md`. Duplicated deliberately: this test
/// asserts the *documented* numbers, so importing the enum would let a change
/// to it silently change the contract too.
const SUCCESS: i32 = 0;
const INVALID_INPUT: i32 = 2;
const CONFIGURATION: i32 = 3;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_oci-free"))
}

/// Run the binary with stdin closed and an empty environment.
///
/// The environment is cleared so a developer's real `~/.oci/config` or
/// `OCI_CLI_*` variables cannot make these tests pass or fail by accident.
fn run(args: &[&str]) -> Output {
    let mut command = Command::new(binary());
    command
        .args(args)
        .env_clear()
        // A home directory that exists but holds no OCI configuration.
        .env("HOME", std::env::temp_dir())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.output().expect("the binary runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

/// A configuration path that certainly does not exist.
fn missing_config() -> String {
    std::env::temp_dir()
        .join("oci-free-tests-no-such-config")
        .display()
        .to_string()
}

/// Every command in the v1 surface, with arguments that parse.
///
/// Kept as one list so a command added without a test here is obvious.
const EVERY_COMMAND: [&[&str]; 22] = [
    &["status"],
    &["doctor"],
    &["cost"],
    &["account", "info"],
    &["account", "limits"],
    &["account", "usage"],
    &["free", "list"],
    &["policy", "explain", "VM.Standard.A1.Flex"],
    &["config", "show"],
    &["vm", "list"],
    &["vm", "info", "web-1"],
    &["vm", "ip", "web-1"],
    &["vm", "ssh", "web-1"],
    &["vm", "create"],
    &["vm", "delete", "web-1"],
    &["vm", "start", "web-1"],
    &["vm", "stop", "web-1"],
    &["vm", "reboot", "web-1"],
    &["vm", "net", "web-1", "show"],
    &["vm", "net", "web-1", "audit"],
    &["vm", "net", "web-1", "open", "443/tcp"],
    &["vm", "net", "web-1", "close", "443/tcp"],
];

#[test]
fn help_and_version_work() {
    let help = run(&["--help"]);
    assert_eq!(code(&help), SUCCESS);
    let text = stdout(&help);
    for command in [
        "status", "doctor", "cost", "free", "account", "policy", "config", "vm",
    ] {
        assert!(text.contains(command), "`{command}` missing from --help");
    }

    let version = run(&["--version"]);
    assert_eq!(code(&version), SUCCESS);
    assert!(stdout(&version).contains(env!("CARGO_PKG_VERSION")));
}

/// Every subcommand must have usable help, which is also a cheap proof that the
/// whole command tree parses.
#[test]
fn every_command_has_help() {
    for args in EVERY_COMMAND {
        let mut with_help: Vec<&str> = args.to_vec();
        // `--help` on the leaf, so subcommand groups resolve too.
        with_help.push("--help");
        let output = run(&with_help);
        assert_eq!(
            code(&output),
            SUCCESS,
            "`{}` --help failed: {}",
            args.join(" "),
            stderr(&output)
        );
        assert!(!stdout(&output).is_empty());
    }
}

/// The property this whole file exists for: with no terminal and no
/// configuration, every command exits promptly with a documented code. A
/// regression that reached a prompt would hang here instead.
#[test]
fn no_command_hangs_or_prompts_without_a_terminal() {
    let config = missing_config();
    for args in EVERY_COMMAND {
        let mut full: Vec<&str> = vec!["--config-file", &config];
        full.extend_from_slice(args);
        let output = run(&full);

        assert_eq!(
            code(&output),
            CONFIGURATION,
            "`{}` should exit {CONFIGURATION} with no configuration; got {} and stderr: {}",
            args.join(" "),
            code(&output),
            stderr(&output)
        );
        // `doctor` renders its report, including each check's next action, on
        // stdout; everything else reports the failure on stderr.
        let combined = format!("{}{}", stdout(&output), stderr(&output));
        assert!(
            combined.contains("next: "),
            "`{}` failed without saying what to do next",
            args.join(" ")
        );
    }
}

/// The same, under `--json`: exactly one parseable document, and never a
/// prompt.
#[test]
fn json_mode_always_emits_one_parseable_document() {
    let config = missing_config();
    for args in EVERY_COMMAND {
        let mut full: Vec<&str> = vec!["--json", "--config-file", &config];
        full.extend_from_slice(args);
        let output = run(&full);

        let text = stdout(&output);
        let value: serde_json::Value = serde_json::from_str(text.trim()).unwrap_or_else(|error| {
            panic!(
                "`{}` did not emit one JSON document ({error}): {text}",
                args.join(" ")
            )
        });

        assert_eq!(value["schema_version"], "1");
        assert!(value["command"].is_string());
        assert!(
            value["warnings"].is_array(),
            "`{}` omitted the always-present warnings array",
            args.join(" ")
        );
        assert!(
            !text.contains('\u{1b}'),
            "`{}` emitted ANSI escapes in JSON",
            args.join(" ")
        );
    }
}

/// `doctor` reports a bad verdict in its payload, not as an error envelope, so
/// there is still exactly one document and it carries the report.
#[test]
fn doctor_reports_its_verdict_in_the_payload() {
    let config = missing_config();
    let output = run(&["--json", "--config-file", &config, "doctor"]);

    assert_eq!(code(&output), CONFIGURATION);
    let value: serde_json::Value =
        serde_json::from_str(stdout(&output).trim()).expect("one JSON document");

    assert_eq!(value["command"], "doctor");
    assert!(
        value.get("error").is_none(),
        "doctor must not emit an error envelope alongside its report"
    );
    assert_eq!(value["data"]["status"], "fail");
    assert_eq!(value["data"]["schema"], "oci-free.doctor/v1");
    assert!(
        !value["warnings"].as_array().expect("warnings").is_empty(),
        "the failing check should surface as a warning"
    );

    // The dependent checks are skipped, not silently absent.
    let checks = value["data"]["checks"].as_array().expect("checks");
    let ids: Vec<&str> = checks
        .iter()
        .map(|check| check["id"].as_str().unwrap_or_default())
        .collect();
    for expected in [
        "configuration",
        "private_key",
        "key_fingerprint",
        "request_signing",
    ] {
        assert!(ids.contains(&expected), "check {expected} is missing");
    }
}

/// A usage error is exit 2, distinct from a configuration failure.
#[test]
fn usage_errors_exit_two() {
    for args in [
        vec!["not-a-command"],
        vec!["vm", "not-a-subcommand"],
        vec!["vm", "net"],
        vec!["policy", "explain"],
    ] {
        let output = run(&args);
        assert_eq!(
            code(&output),
            INVALID_INPUT,
            "`{}` should be a usage error",
            args.join(" ")
        );
    }
}

/// A malformed rule is caught by the product's own parser, with guidance.
#[test]
fn a_malformed_port_rule_is_rejected_with_guidance() {
    let config = missing_config();
    for rule in ["443", "443/sctp", "0/tcp", "notaport/tcp", "99999/tcp"] {
        let output = run(&["--config-file", &config, "vm", "net", "web-1", "open", rule]);
        assert_eq!(
            code(&output),
            INVALID_INPUT,
            "`{rule}` should be rejected as invalid input"
        );
        assert!(
            stderr(&output).contains("PORT/PROTOCOL"),
            "`{rule}` was rejected without explaining the expected form"
        );
    }
}

/// `--ocpus` without `--memory` cannot be checked, so it is refused rather than
/// half-answered.
#[test]
fn half_a_size_is_refused() {
    let config = missing_config();
    let output = run(&[
        "--config-file",
        &config,
        "policy",
        "explain",
        "VM.Standard.A1.Flex",
        "--ocpus",
        "2",
    ]);
    assert_eq!(code(&output), INVALID_INPUT);
    assert!(stderr(&output).contains("together"));
}

/// Key generation is not offered, and the refusal explains the alternative
/// rather than leaving the user stuck.
#[test]
fn generate_key_explains_the_console_flow() {
    let config = missing_config();
    let output = run(&["--config-file", &config, "config", "init", "--generate-key"]);
    assert_eq!(code(&output), INVALID_INPUT);

    let text = stderr(&output);
    assert!(text.contains("API key"));
    assert!(text.contains("next: "));
    assert!(
        text.contains("OCI Console"),
        "the refusal must point at the alternative, not just decline"
    );
}

/// `config init` will not prompt without a terminal, and names the flag that
/// would have supplied each missing value.
#[test]
fn config_init_names_the_missing_flag_instead_of_prompting() {
    let config = missing_config();
    let output = run(&[
        "--config-file",
        &config,
        "config",
        "init",
        "--non-interactive",
    ]);
    assert_eq!(code(&output), INVALID_INPUT);
    assert!(stderr(&output).contains("--tenancy"));
}

/// No output path may ever carry credential material.
#[test]
fn no_output_leaks_credential_material() {
    let config = missing_config();
    for args in EVERY_COMMAND {
        for extra in [vec![], vec!["--json"]] {
            let mut full: Vec<&str> = extra;
            full.extend_from_slice(&["--config-file", &config]);
            full.extend_from_slice(args);
            let output = run(&full);
            let combined = format!("{}{}", stdout(&output), stderr(&output));
            for forbidden in ["PRIVATE KEY", "Authorization:", "Signature keyId"] {
                assert!(
                    !combined.contains(forbidden),
                    "`{}` leaked {forbidden:?}",
                    args.join(" ")
                );
            }
        }
    }
}
