//! `oci-free config init` and `config show`.
//!
//! Getting started must not require Python, the official OCI CLI, or OpenSSL.
//! `config init` writes a standard `~/.oci/config` profile from values the user
//! supplies or is prompted for, validating each one before it is written so a
//! typo is caught here rather than as an opaque `NotAuthenticated` later.
//!
//! Three rules:
//!
//! * an existing profile is never silently replaced — `--force` is required;
//! * the file is created with owner-only permissions where the platform
//!   supports them;
//! * nothing secret is ever echoed. The private key is referenced by path and
//!   its contents are never read into the configuration.
//!
//! Key generation is deliberately out of scope. The OCI Console's "Add API
//! key" flow generates the pair, shows the fingerprint, and hands over the
//! private key in one step, with no local toolchain at all — so [`key_advice`]
//! points there instead of shipping a second, weaker way to make a key.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::{
    auth::PrivateKey,
    config::{Config, ConfigOptions, DEFAULT_PROFILE, Environment, RedactedConfig, ini},
    domain::{fingerprint::Fingerprint, ocid::Ocid, region::Region},
    error::{Error, Result},
    interactive,
};

/// What `config init` was asked to write.
#[derive(Debug, Clone, Default)]
pub struct InitRequest {
    pub profile: Option<String>,
    pub config_file: Option<PathBuf>,
    pub tenancy: Option<String>,
    pub user: Option<String>,
    pub region: Option<String>,
    pub fingerprint: Option<String>,
    pub key_file: Option<PathBuf>,
    pub force: bool,
    pub interactive: bool,
}

/// The `config init` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InitResult {
    pub config_file: String,
    pub profile: String,
    /// Whether an existing profile of this name was replaced.
    pub replaced_existing: bool,
    /// Whether the file is readable only by its owner.
    pub owner_only_permissions: bool,
    /// Checks run against the values before writing.
    pub validated: Vec<String>,
    pub next_steps: Vec<String>,
    pub warnings: Vec<String>,
}

/// Write a configuration profile.
pub async fn init(env: &Environment, request: &InitRequest) -> Result<InitResult> {
    let profile = request
        .profile
        .clone()
        .unwrap_or_else(|| DEFAULT_PROFILE.to_owned());
    let path = config_path(env, request)?;

    let existing = read_existing(&path)?;
    let replacing = existing.contains_key(&profile);
    if replacing && !request.force {
        return Err(Error::invalid_input(format!(
            "profile [{profile}] already exists in {}",
            path.display()
        ))
        .with_context(
            "oci-free will not overwrite an existing profile: the private key it names may be the \
             only copy",
        )
        .with_remediation("pass --force to replace it, or --profile with a different name"));
    }

    let mut validated = Vec::new();
    let mut warnings = Vec::new();

    let tenancy = ask_ocid(
        request.tenancy.as_deref(),
        "tenancy",
        "Tenancy OCID",
        "--tenancy",
        request.interactive,
    )?;
    validated.push("tenancy is a well-formed tenancy OCID".to_owned());

    let user = ask_ocid(
        request.user.as_deref(),
        "user",
        "User OCID",
        "--user",
        request.interactive,
    )?;
    validated.push("user is a well-formed user OCID".to_owned());

    let region: Region = ask_parsed(
        request.region.as_deref(),
        "Region, for example us-ashburn-1",
        "--region",
        request.interactive,
    )?;
    validated.push(format!("region {region} is well formed"));

    let key_file = match &request.key_file {
        Some(path) => env.expand_home(path),
        None if request.interactive => {
            let entered = interactive::input(
                "Path to the API private key (.pem)",
                default_key_path(env).as_deref(),
                "--key-file",
            )?;
            env.expand_home(Path::new(&entered))
        }
        None => {
            return Err(interactive::not_interactive(
                "the private key path",
                "--key-file",
            ));
        }
    };

    // Load the key now. Its fingerprint is derived from the key itself, which
    // is the value OCI will actually match against, so a mistyped fingerprint
    // is caught here rather than on the first signed request.
    let derived = match PrivateKey::from_pem_file(&key_file) {
        Ok(key) => {
            validated.push(format!(
                "the private key at {} loaded, fingerprint {}",
                key_file.display(),
                key.fingerprint()
            ));
            Some(key.fingerprint().clone())
        }
        Err(error) => {
            warnings.push(format!(
                "the private key could not be read yet: {error}. {}",
                error.remediation()
            ));
            None
        }
    };

    let fingerprint = resolve_fingerprint(
        request.fingerprint.as_deref(),
        derived.as_ref(),
        request.interactive,
        &mut validated,
    )?;

    let entries = vec![
        ("user", user.to_string()),
        ("fingerprint", fingerprint.to_string()),
        ("tenancy", tenancy.to_string()),
        ("region", region.to_string()),
        ("key_file", key_file.display().to_string()),
    ];

    let owner_only = write_profile(&path, &profile, &entries, existing)?;
    if !owner_only {
        warnings.push(format!(
            "{} could not be restricted to its owner on this platform; check its permissions \
             yourself",
            path.display()
        ));
    }

    Ok(InitResult {
        config_file: path.display().to_string(),
        profile,
        replaced_existing: replacing,
        owner_only_permissions: owner_only,
        validated,
        next_steps: vec![
            "run `oci-free doctor` to verify the credentials against OCI".to_owned(),
            "run `oci-free status` for an account and cost summary".to_owned(),
        ],
        warnings,
    })
}

/// How to obtain an API key without any local toolchain.
#[must_use]
pub fn key_advice() -> Vec<String> {
    vec![
        "In the OCI Console, open Profile -> My profile -> API keys -> Add API key.".to_owned(),
        "Choose 'Generate API key pair', download the private key, and click Add.".to_owned(),
        "The Console then shows the configuration preview, including the fingerprint.".to_owned(),
        "Save the private key somewhere only you can read, then run `oci-free config init`."
            .to_owned(),
    ]
}

/// Show the configuration oci-free would use.
pub fn show(env: &Environment, options: &ConfigOptions) -> Result<RedactedConfig> {
    Config::load(env, options)
        .map(|config| config.redacted())
        .map_err(|error| {
            Error::new(crate::error::ErrorKind::Configuration, error.to_string())
                .with_remediation(error.remediation())
        })
}

fn config_path(env: &Environment, request: &InitRequest) -> Result<PathBuf> {
    if let Some(path) = &request.config_file {
        return Ok(env.expand_home(path));
    }
    env.home_dir()
        .map(|home| home.join(".oci/config"))
        .ok_or_else(|| {
            Error::configuration("no home directory could be determined")
                .with_remediation("pass --config-file with an explicit path")
        })
}

fn default_key_path(env: &Environment) -> Option<String> {
    env.home_dir()
        .map(|home| home.join(".oci/oci_api_key.pem").display().to_string())
}

fn read_existing(
    path: &Path,
) -> Result<std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>> {
    if !path.is_file() {
        return Ok(std::collections::BTreeMap::new());
    }
    let text = std::fs::read_to_string(path).map_err(|error| {
        Error::configuration(format!("could not read {}", path.display()))
            .with_context(error.to_string())
    })?;
    ini::parse(&text).map_err(|error| {
        Error::configuration(format!("could not parse {}", path.display()))
            .with_context(error.to_string())
            .with_remediation("fix the reported line, or pass --config-file to write elsewhere")
    })
}

fn ask_ocid(
    supplied: Option<&str>,
    resource_type: &'static str,
    prompt: &str,
    flag: &str,
    interactive: bool,
) -> Result<Ocid> {
    let value = match supplied {
        Some(value) => value.to_owned(),
        None if interactive => interactive::input(prompt, None, flag)?,
        None => return Err(interactive::not_interactive(prompt, flag)),
    };
    Ocid::parse_of_type(resource_type, value.trim()).map_err(|error| {
        Error::invalid_input(format!(
            "`{}` is not a valid {resource_type} OCID",
            value.trim()
        ))
        .with_context(error.to_string())
        .with_remediation(format!(
            "copy the {resource_type} OCID from the OCI Console; it starts with \
                 `ocid1.{resource_type}.`"
        ))
    })
}

fn ask_parsed<T>(supplied: Option<&str>, prompt: &str, flag: &str, interactive: bool) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let value = match supplied {
        Some(value) => value.to_owned(),
        None if interactive => interactive::input(prompt, None, flag)?,
        None => return Err(interactive::not_interactive(prompt, flag)),
    };
    value.trim().parse::<T>().map_err(|error| {
        Error::invalid_input(format!("`{}` is not valid", value.trim()))
            .with_context(error.to_string())
            .with_remediation(format!("correct the value and pass {flag}"))
    })
}

/// Decide the fingerprint to record.
///
/// The key's own fingerprint wins where the two disagree, because it is what
/// OCI matches against. A mismatch is reported rather than silently corrected.
fn resolve_fingerprint(
    supplied: Option<&str>,
    derived: Option<&Fingerprint>,
    interactive: bool,
    validated: &mut Vec<String>,
) -> Result<Fingerprint> {
    match (supplied, derived) {
        (Some(supplied), Some(derived)) => {
            let parsed: Fingerprint = supplied.trim().parse().map_err(
                |error: crate::domain::fingerprint::ParseFingerprintError| {
                    Error::invalid_input(format!(
                        "`{}` is not a valid fingerprint",
                        supplied.trim()
                    ))
                    .with_context(error.to_string())
                },
            )?;
            if &parsed != derived {
                return Err(Error::invalid_input(
                    "the fingerprint given does not match the private key",
                )
                .with_context(format!(
                    "the key at the given path has fingerprint {derived}, but {parsed} was \
                     supplied; OCI would reject every request signed with this pair"
                ))
                .with_remediation(format!(
                    "drop --fingerprint so it is taken from the key, or set it to {derived}"
                )));
            }
            validated.push("the supplied fingerprint matches the private key".to_owned());
            Ok(parsed)
        }
        (None, Some(derived)) => {
            validated.push("the fingerprint was derived from the private key".to_owned());
            Ok(derived.clone())
        }
        (Some(supplied), None) => supplied.trim().parse().map_err(
            |error: crate::domain::fingerprint::ParseFingerprintError| {
                Error::invalid_input(format!("`{}` is not a valid fingerprint", supplied.trim()))
                    .with_context(error.to_string())
            },
        ),
        (None, None) if interactive => {
            let entered = interactive::input(
                "API key fingerprint, as shown in the OCI Console",
                None,
                "--fingerprint",
            )?;
            entered.trim().parse().map_err(
                |error: crate::domain::fingerprint::ParseFingerprintError| {
                    Error::invalid_input("that is not a valid fingerprint")
                        .with_context(error.to_string())
                },
            )
        }
        (None, None) => Err(interactive::not_interactive(
            "the API key fingerprint",
            "--fingerprint",
        )),
    }
}

/// Write the profile, preserving every other profile in the file.
fn write_profile(
    path: &Path,
    profile: &str,
    entries: &[(&str, String)],
    mut existing: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
) -> Result<bool> {
    existing.insert(
        profile.to_owned(),
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect(),
    );

    let mut rendered = String::from(
        "# Written by oci-free. Standard OCI configuration format.\n\
         # The private key is referenced by path; its contents are never copied here.\n",
    );
    for (name, fields) in &existing {
        rendered.push_str(&format!("\n[{name}]\n"));
        for (key, value) in fields {
            rendered.push_str(&format!("{key}={value}\n"));
        }
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            Error::configuration(format!("could not create {}", parent.display()))
                .with_context(error.to_string())
        })?;
    }
    std::fs::write(path, rendered).map_err(|error| {
        Error::configuration(format!("could not write {}", path.display()))
            .with_context(error.to_string())
            .with_remediation("check that the directory exists and is writable")
    })?;

    Ok(restrict_permissions(path))
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).is_ok()
}

#[cfg(not(unix))]
fn restrict_permissions(path: &Path) -> bool {
    // Windows inherits the user profile directory's ACL, which is already
    // owner-only for the default location. Claiming otherwise would be worse
    // than admitting the platform is not being checked.
    let _ = path;
    false
}

/// Render `config init` for a terminal.
#[must_use]
pub fn render_init(result: &InitResult) -> String {
    let mut out = format!(
        "{} profile [{}] in {}\n\n",
        if result.replaced_existing {
            "Replaced"
        } else {
            "Wrote"
        },
        result.profile,
        result.config_file
    );
    for check in &result.validated {
        out.push_str(&format!("  checked: {check}\n"));
    }
    if result.owner_only_permissions {
        out.push_str("  checked: the configuration file is readable only by its owner\n");
    }
    out.push_str("\nNext\n");
    for step in &result.next_steps {
        out.push_str(&format!("  {step}\n"));
    }
    for warning in &result.warnings {
        out.push_str(&format!("\nwarning: {warning}\n"));
    }
    out
}

/// Render `config show` for a terminal.
#[must_use]
pub fn render_show(config: &RedactedConfig) -> String {
    let mut out = String::from("Configuration oci-free would use\n\n");
    out.push_str(&format!("  profile        {}\n", config.profile));
    out.push_str(&format!(
        "  file           {}\n",
        config
            .config_file
            .as_deref()
            .unwrap_or("none (environment only)")
    ));
    out.push_str(&format!("  region         {}\n", config.region));
    out.push_str(&format!("  tenancy        {}\n", config.tenancy));
    out.push_str(&format!("  user           {}\n", config.user));
    out.push_str(&format!("  fingerprint    {}\n", config.fingerprint));
    out.push_str(&format!("  key_file       {}\n", config.key_file));
    out.push_str(&format!(
        "  pass phrase    {}\n",
        if config.pass_phrase_configured {
            "configured"
        } else {
            "not configured"
        }
    ));
    if !config.env_overrides.is_empty() {
        out.push_str(&format!(
            "  from env       {}\n",
            config.env_overrides.join(", ")
        ));
    }
    out
}

#[cfg(test)]
#[path = "config_init_tests.rs"]
mod config_init_tests;
