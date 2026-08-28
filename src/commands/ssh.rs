//! `oci-free vm ssh <instance>` — connect to an instance.
//!
//! The connection details are discovered rather than asked for: the public
//! address comes from the instance's VNIC, and the login name first comes from
//! the oci-free launch metadata tag, then falls back to the image's operating
//! system default.
//!
//! The command line is built as an **argument vector and handed to the OS
//! process API directly**. Nothing is ever concatenated into a shell string, so
//! a display name, hostname, or user name containing shell metacharacters is
//! passed through as one opaque argument and cannot become a command.
//!
//! In `--json` mode the process is not launched. A machine-readable command
//! whose side effect is stealing the terminal would be unusable in a pipeline,
//! so JSON returns the argument vector and the caller decides.

use std::path::PathBuf;

use serde::Serialize;

use crate::{
    commands::{
        context::CommandContext,
        discovery::{load_network, resolve_instance},
    },
    error::{Error, Result},
    oci::compute::ComputeApi,
};

/// Written by `vm create --username`; using a tag keeps `vm ssh` stateless and
/// lets it recover the intended login user after a later process invocation.
const TAG_SSH_USER: &str = "oci-free:ssh-user";

/// Default login names by operating system.
///
/// Oracle's platform images use `opc`; Canonical's use `ubuntu`. Anything else
/// is asked for rather than guessed, because connecting as the wrong user is a
/// confusing failure.
const DEFAULT_USERS: [(&str, &str); 4] = [
    ("Oracle Linux", "opc"),
    ("Oracle Autonomous Linux", "opc"),
    ("Canonical Ubuntu", "ubuntu"),
    ("CentOS", "opc"),
];

/// The connection oci-free would make.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SshTarget {
    pub instance: String,
    pub instance_id: String,
    pub region: String,
    pub host: String,
    pub user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_file: Option<String>,
    /// The exact argv oci-free would execute. Never a shell string.
    pub command: Vec<String>,
    /// Whether the process was actually launched.
    pub launched: bool,
    /// The child's exit status, when it ran and reported one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub warnings: Vec<String>,
}

/// What the caller wants done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshMode {
    /// Launch the SSH client, replacing this process's terminal.
    Connect,
    /// Report the command without running it.
    Print,
}

/// Resolve, and optionally open, an SSH connection.
pub async fn run(
    context: &CommandContext,
    reference: &str,
    user: Option<&str>,
    identity: Option<&PathBuf>,
    mode: SshMode,
) -> Result<SshTarget> {
    let instance = resolve_instance(context, reference).await?;
    let network = load_network(context, &instance).await;
    let mut warnings = network.warnings.clone();

    let host = network
        .vnic
        .as_ref()
        .and_then(|vnic| vnic.public_ip.clone())
        .filter(|ip| !ip.trim().is_empty())
        .ok_or_else(|| {
            Error::not_found(format!("{} has no public IP address", instance.label()))
                .with_context(
                    "SSH needs a routable address; this instance has only a private address, \
                     reachable from inside the VCN",
                )
                .with_remediation(
                    "connect from a host inside the VCN, or recreate the instance with a public \
                     IP",
                )
        })?;

    let user = match user {
        Some(user) => user.to_owned(),
        None => {
            let (resolved, note) = default_user(context, &instance).await;
            if let Some(note) = note {
                warnings.push(note);
            }
            resolved
        }
    };

    let mut command = vec!["ssh".to_owned()];
    if let Some(identity) = identity {
        command.push("-i".to_owned());
        command.push(identity.display().to_string());
    }
    command.push(format!("{user}@{host}"));

    if let Some(exposure) = network.exposure()
        && !exposure.allows("22/tcp".parse().expect("a valid rule"))
    {
        warnings.push(format!(
            "no NSG or Security List rule allows tcp 22 to this instance; run `oci-free vm net {} \
             open 22/tcp --source <your-address>` first",
            instance.label()
        ));
    }

    let target = SshTarget {
        instance: instance.label().to_owned(),
        instance_id: instance.id.clone(),
        region: context.region().to_string(),
        host,
        user,
        identity_file: identity.map(|path| path.display().to_string()),
        command,
        launched: false,
        exit_code: None,
        warnings,
    };

    match mode {
        SshMode::Print => Ok(target),
        SshMode::Connect => launch(target).await,
    }
}

/// Run the SSH client.
async fn launch(mut target: SshTarget) -> Result<SshTarget> {
    let (program, arguments) = target
        .command
        .split_first()
        .expect("the command always starts with the program name");

    // Arguments are passed as a vector: no shell is involved, so nothing in a
    // host name or user name can be interpreted as a command.
    let status = tokio::process::Command::new(program)
        .args(arguments)
        .status()
        .await
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Error::external_tool("no `ssh` client was found on this system")
                    .with_context(
                        "oci-free uses the operating system's SSH client rather than embedding \
                         one",
                    )
                    .with_remediation(
                        "install OpenSSH (on Windows: Settings -> Optional features -> OpenSSH \
                         Client), or run the printed command from a machine that has it",
                    )
            } else {
                Error::external_tool("the SSH client could not be started")
                    .with_context(error.to_string())
            }
        })?;

    target.launched = true;
    target.exit_code = status.code();
    Ok(target)
}

/// The login name for an instance.
async fn default_user(
    context: &CommandContext,
    instance: &crate::oci::compute::Instance,
) -> (String, Option<String>) {
    if let Some(user) = instance
        .freeform_tags
        .get(TAG_SSH_USER)
        .filter(|value| !value.trim().is_empty())
    {
        return (user.clone(), None);
    }

    let Some(image_id) = instance.image_id.as_deref() else {
        return (
            "opc".to_owned(),
            Some(
                "the instance's image is unknown, so the Oracle Linux default `opc` was assumed; \
                 pass --user if that is wrong"
                    .to_owned(),
            ),
        );
    };

    match ComputeApi::new(context.client()).get_image(image_id).await {
        Ok(image) => {
            let os = image.operating_system.unwrap_or_default();
            match DEFAULT_USERS
                .iter()
                .find(|(family, _)| os.starts_with(family))
            {
                Some((_, user)) => ((*user).to_owned(), None),
                None => (
                    "opc".to_owned(),
                    Some(format!(
                        "no default login name is known for `{os}`, so `opc` was assumed; pass \
                         --user if that is wrong"
                    )),
                ),
            }
        }
        Err(_) => (
            "opc".to_owned(),
            Some(
                "the instance's image could not be read, so the Oracle Linux default `opc` was \
                 assumed; pass --user if that is wrong"
                    .to_owned(),
            ),
        ),
    }
}

/// Render the SSH target for a terminal.
#[must_use]
pub fn render_human(target: &SshTarget) -> String {
    let mut out = String::new();
    if !target.launched {
        out.push_str(&format!("{}\n", shell_quote(&target.command)));
    }
    for warning in &target.warnings {
        out.push_str(&format!("warning: {warning}\n"));
    }
    out
}

/// Render the argv as a copy-pasteable shell command.
///
/// Only ever used for display. The command oci-free runs is the argument
/// vector, not this string.
#[must_use]
pub fn shell_quote(command: &[String]) -> String {
    command
        .iter()
        .map(|argument| {
            if argument
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "@.-_/:".contains(c))
            {
                argument.clone()
            } else {
                format!("'{}'", argument.replace('\'', r"'\''"))
            }
        })
        .collect::<Vec<String>>()
        .join(" ")
}

#[cfg(test)]
#[path = "ssh_tests.rs"]
mod ssh_tests;
