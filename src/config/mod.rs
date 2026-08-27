pub mod env;
pub mod ini;
pub mod secret;

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use serde::Serialize;
use thiserror::Error;

use crate::domain::{
    fingerprint::Fingerprint,
    ocid::{Ocid, ParseOcidError},
    region::Region,
};

pub use env::Environment;
pub use ini::DEFAULT_PROFILE;
pub use secret::Secret;

/// Environment variable holding an alternative configuration file path.
pub const ENV_CONFIG_FILE: &str = "OCI_CLI_CONFIG_FILE";
/// Environment variable selecting the profile to read.
pub const ENV_PROFILE: &str = "OCI_CLI_PROFILE";

/// Configuration file path relative to the user's home directory.
const DEFAULT_CONFIG_RELATIVE_PATH: &str = ".oci/config";

/// Caller-supplied overrides, normally coming from global CLI flags.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigOptions {
    pub config_file: Option<PathBuf>,
    pub profile: Option<String>,
}

/// Where a loaded configuration came from, for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigOrigin {
    /// The configuration file that was read, if one existed.
    pub file: Option<PathBuf>,
    /// The profile that was selected.
    pub profile: String,
    /// Fields whose value came from an environment variable.
    pub env_overrides: Vec<String>,
}

/// A validated OCI API-key configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub user: Ocid,
    pub tenancy: Ocid,
    pub fingerprint: Fingerprint,
    pub region: Region,
    pub key_file: PathBuf,
    pub pass_phrase: Option<Secret>,
    pub origin: ConfigOrigin,
}

impl Config {
    /// Load and validate configuration from the environment and, when present,
    /// the OCI configuration file.
    pub fn load(env: &Environment, options: &ConfigOptions) -> Result<Self, ConfigError> {
        let profile = options
            .profile
            .clone()
            .or_else(|| env.get(ENV_PROFILE).map(str::to_owned))
            .unwrap_or_else(|| DEFAULT_PROFILE.to_owned());

        let (path, explicit) = resolve_config_path(env, options);
        let mut file_read = false;
        let entries = match (path.as_ref(), explicit) {
            (Some(path), _) if path.is_file() => {
                file_read = true;
                read_profile(path, &profile)?
            }
            (Some(path), true) => {
                return Err(ConfigError::ConfigFileNotFound { path: path.clone() });
            }
            // A missing default configuration file is not fatal on its own:
            // every field may still be supplied through the environment.
            _ => BTreeMap::new(),
        };

        let mut resolver =
            FieldResolver::new(entries, env, path.clone(), file_read, profile.clone());
        resolver.reject_unsupported_authentication()?;

        Ok(Self {
            user: resolver.ocid("user", "OCI_CLI_USER")?,
            tenancy: resolver.ocid("tenancy", "OCI_CLI_TENANCY")?,
            fingerprint: resolver.parsed("fingerprint", "OCI_CLI_FINGERPRINT")?,
            region: resolver.parsed("region", "OCI_CLI_REGION")?,
            key_file: resolver.key_file()?,
            pass_phrase: resolver.pass_phrase(),
            origin: ConfigOrigin {
                // Only report a file that was actually read, so an environment-only
                // setup is not described as coming from a file that does not exist.
                file: file_read.then_some(path).flatten(),
                profile,
                env_overrides: resolver.env_overrides.clone(),
            },
        })
    }

    /// A view that is safe to print in diagnostics or serialize to JSON.
    #[must_use]
    pub fn redacted(&self) -> RedactedConfig {
        RedactedConfig {
            profile: self.origin.profile.clone(),
            config_file: self
                .origin
                .file
                .as_ref()
                .map(|path| path.display().to_string()),
            env_overrides: self.origin.env_overrides.clone(),
            region: self.region.to_string(),
            tenancy: self.tenancy.redacted(),
            user: self.user.redacted(),
            // The fingerprint identifies a public key, so it is shown in full:
            // seeing it is what lets a user spot a key/config mismatch.
            fingerprint: self.fingerprint.to_string(),
            key_file: self.key_file.display().to_string(),
            pass_phrase_configured: self.pass_phrase.is_some(),
        }
    }
}

/// A redacted rendering of [`Config`] for `--json` output and diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RedactedConfig {
    pub profile: String,
    pub config_file: Option<String>,
    pub env_overrides: Vec<String>,
    pub region: String,
    pub tenancy: String,
    pub user: String,
    pub fingerprint: String,
    pub key_file: String,
    pub pass_phrase_configured: bool,
}

/// Decide which configuration file to read.
///
/// Returns the resolved path and whether the user asked for it explicitly. An
/// explicit request that cannot be satisfied is an error; a missing default file
/// is not.
fn resolve_config_path(env: &Environment, options: &ConfigOptions) -> (Option<PathBuf>, bool) {
    if let Some(path) = options.config_file.as_ref() {
        return (Some(env.expand_home(path)), true);
    }
    if let Some(path) = env.get(ENV_CONFIG_FILE) {
        return (Some(env.expand_home(Path::new(path))), true);
    }
    (
        env.home_dir()
            .map(|home| home.join(DEFAULT_CONFIG_RELATIVE_PATH)),
        false,
    )
}

fn read_profile(path: &Path, profile: &str) -> Result<BTreeMap<String, String>, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::ReadFailed {
        path: path.to_path_buf(),
        source,
    })?;
    let profiles = ini::parse(&text).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })?;

    let selected = profiles
        .get(profile)
        .cloned()
        .ok_or_else(|| ConfigError::ProfileNotFound {
            path: path.to_path_buf(),
            profile: profile.to_owned(),
            available: profiles.keys().cloned().collect(),
        })?;

    if profile == DEFAULT_PROFILE {
        return Ok(selected);
    }

    // Match OCI SDK configuration semantics: named profiles inherit fields
    // from [DEFAULT], while explicitly defined values in the selected profile
    // take precedence.
    let mut merged = profiles.get(DEFAULT_PROFILE).cloned().unwrap_or_default();
    merged.extend(selected);
    Ok(merged)
}

/// Resolves individual fields from the profile with environment overrides.
struct FieldResolver<'a> {
    entries: BTreeMap<String, String>,
    env: &'a Environment,
    file: Option<PathBuf>,
    /// Whether `file` was present and parsed, as opposed to merely being the
    /// path the tool would use.
    file_read: bool,
    profile: String,
    env_overrides: Vec<String>,
}

impl<'a> FieldResolver<'a> {
    fn new(
        entries: BTreeMap<String, String>,
        env: &'a Environment,
        file: Option<PathBuf>,
        file_read: bool,
        profile: String,
    ) -> Self {
        Self {
            entries,
            env,
            file,
            file_read,
            profile,
            env_overrides: Vec::new(),
        }
    }

    /// Look up one field, preferring the environment over the configuration file.
    fn raw(&mut self, field: &'static str, env_var: &'static str) -> Option<String> {
        if let Some(value) = self.env.get(env_var) {
            self.env_overrides.push(field.to_owned());
            return Some(value.to_owned());
        }
        self.entries
            .get(field)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    }

    fn required(
        &mut self,
        field: &'static str,
        env_var: &'static str,
    ) -> Result<String, ConfigError> {
        self.raw(field, env_var)
            .ok_or_else(|| ConfigError::MissingField {
                field,
                env_var,
                profile: self.profile.clone(),
                file: self.file.clone(),
                file_read: self.file_read,
            })
    }

    fn parsed<T>(&mut self, field: &'static str, env_var: &'static str) -> Result<T, ConfigError>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        let value = self.required(field, env_var)?;
        value
            .parse::<T>()
            .map_err(|source| ConfigError::InvalidField {
                field,
                message: source.to_string(),
            })
    }

    fn ocid(&mut self, field: &'static str, env_var: &'static str) -> Result<Ocid, ConfigError> {
        let value = self.required(field, env_var)?;
        Ocid::parse_of_type(field, &value).map_err(|source| match source {
            ParseOcidError::UnexpectedResourceType { .. } => ConfigError::InvalidField {
                field,
                message: format!("{source}; check that 'user' and 'tenancy' are not swapped"),
            },
            ParseOcidError::InvalidFormat(_) => ConfigError::InvalidField {
                field,
                message: "expected an OCID of the form ocid1.<resource-type>.<realm>.<region>.<unique-id>"
                    .to_owned(),
            },
            ParseOcidError::Empty => ConfigError::InvalidField {
                field,
                message: ParseOcidError::Empty.to_string(),
            },
        })
    }

    fn key_file(&mut self) -> Result<PathBuf, ConfigError> {
        match self.raw("key_file", "OCI_CLI_KEY_FILE") {
            Some(value) => Ok(self.env.expand_home(Path::new(&value))),
            None if self.entries.contains_key("key_content") => {
                Err(ConfigError::UnsupportedAuthentication {
                    field: "key_content",
                    profile: self.profile.clone(),
                })
            }
            None => Err(ConfigError::MissingField {
                field: "key_file",
                env_var: "OCI_CLI_KEY_FILE",
                profile: self.profile.clone(),
                file: self.file.clone(),
                file_read: self.file_read,
            }),
        }
    }

    fn pass_phrase(&self) -> Option<Secret> {
        self.entries
            .get("pass_phrase")
            .filter(|value| !value.is_empty())
            .map(Secret::new)
    }

    /// Reject profiles that select an authentication mode this tool does not
    /// implement yet, instead of silently signing with the wrong credentials.
    fn reject_unsupported_authentication(&self) -> Result<(), ConfigError> {
        for field in ["security_token_file", "delegation_token_file"] {
            if self.entries.contains_key(field) {
                return Err(ConfigError::UnsupportedAuthentication {
                    field,
                    profile: self.profile.clone(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration file {} does not exist", path.display())]
    ConfigFileNotFound { path: PathBuf },
    #[error("could not read configuration file {}: {source}", path.display())]
    ReadFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("could not parse configuration file {}: {source}", path.display())]
    Parse {
        path: PathBuf,
        #[source]
        source: ini::IniError,
    },
    #[error("profile [{profile}] was not found in {}", path.display())]
    ProfileNotFound {
        path: PathBuf,
        profile: String,
        available: Vec<String>,
    },
    #[error("configuration is missing '{field}'")]
    MissingField {
        field: &'static str,
        env_var: &'static str,
        profile: String,
        file: Option<PathBuf>,
        file_read: bool,
    },
    #[error("configuration field '{field}' is not valid: {message}")]
    InvalidField {
        field: &'static str,
        message: String,
    },
    #[error(
        "'{field}' in profile [{profile}] selects an authentication mode oci-free does not support yet"
    )]
    UnsupportedAuthentication {
        field: &'static str,
        profile: String,
    },
}

impl ConfigError {
    /// The next corrective action a user can take.
    #[must_use]
    pub fn remediation(&self) -> String {
        match self {
            Self::ConfigFileNotFound { path } => format!(
                "create {} or pass --config-file with the correct path",
                path.display()
            ),
            Self::ReadFailed { path, .. } => format!(
                "check that {} exists and is readable by the current user",
                path.display()
            ),
            Self::Parse { .. } => {
                "fix the reported line; each entry must be 'key = value' under a [PROFILE] header"
                    .to_owned()
            }
            Self::ProfileNotFound {
                available, profile, ..
            } => {
                if available.is_empty() {
                    format!("add a [{profile}] section to the configuration file")
                } else {
                    format!(
                        "pass --profile with one of the profiles present in the file: {}",
                        available.join(", ")
                    )
                }
            }
            Self::MissingField {
                field,
                env_var,
                profile,
                file,
                file_read,
            } => match (file, file_read) {
                (Some(path), true) => format!(
                    "set '{field}' in profile [{profile}] of {}, or set {env_var}",
                    path.display()
                ),
                (Some(path), false) => format!(
                    "create {} with a [{profile}] profile that sets '{field}', or set {env_var}",
                    path.display()
                ),
                (None, _) => format!("set {env_var}, or create an OCI configuration file"),
            },
            Self::InvalidField { field, .. } => {
                format!("correct the '{field}' value and run oci-free doctor again")
            }
            Self::UnsupportedAuthentication { field, .. } => format!(
                "remove '{field}' and configure an API key with 'user', 'tenancy', 'fingerprint', and 'key_file'"
            ),
        }
    }
}

include!("config_tests.rs");
