//! Shared command execution context.
//!
//! Assembling a working OCI client means loading configuration, reading the
//! private key, building the signer, and resolving endpoints. Every live
//! command needs all four, and each step has its own failure mode worth
//! reporting precisely, so the sequence lives here once.

use crate::{
    auth::PrivateKey,
    config::{Config, ConfigOptions, Environment},
    domain::ocid::Ocid,
    error::{Error, ErrorKind, Result},
    oci::client::OciClient,
    policy::{engine::PolicyEngine, snapshot::PolicySnapshot},
};

/// Everything a live command needs.
pub struct CommandContext {
    config: Config,
    client: OciClient,
    policy: PolicyEngine,
}

impl std::fmt::Debug for CommandContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Config's own Debug redacts secrets, but the client owns the signer,
        // so it is deliberately not rendered here either.
        f.debug_struct("CommandContext")
            .field("profile", &self.config.origin.profile)
            .field("region", &self.config.region)
            .finish_non_exhaustive()
    }
}

impl CommandContext {
    /// Load configuration and build a client for it.
    pub fn load(env: &Environment, options: &ConfigOptions) -> Result<Self> {
        let config = Config::load(env, options).map_err(|error| {
            Error::new(ErrorKind::Configuration, error.to_string())
                .with_remediation(error.remediation())
        })?;

        let key = PrivateKey::from_pem_file(&config.key_file).map_err(|error| {
            Error::new(ErrorKind::Configuration, error.to_string())
                .with_remediation(error.remediation())
        })?;

        let client = OciClient::new(&config, key)?;
        let policy = PolicyEngine::new(PolicySnapshot::load()?);

        Ok(Self {
            config,
            client,
            policy,
        })
    }

    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    #[must_use]
    pub fn client(&self) -> &OciClient {
        &self.client
    }

    #[must_use]
    pub fn policy(&self) -> &PolicyEngine {
        &self.policy
    }

    /// The tenancy OCID, which is also the root compartment.
    ///
    /// oci-free works at the tenancy root because Free Tier allowances are
    /// tenancy-wide: scoping to a child compartment would under-count usage and
    /// could let the capacity check approve an over-allocation.
    #[must_use]
    pub fn tenancy(&self) -> &Ocid {
        &self.config.tenancy
    }
}
