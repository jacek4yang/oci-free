//! Shared command execution context.
//!
//! Assembling a working OCI client means loading configuration, reading the
//! private key, building the signer, and resolving endpoints. Every live
//! command needs all four, and each step has its own failure mode worth
//! reporting precisely, so the sequence lives here once.

use crate::{
    auth::PrivateKey,
    config::{Config, ConfigOptions, Environment},
    domain::{ocid::Ocid, region::Region},
    error::{Error, ErrorKind, Result},
    oci::{client::OciClient, identity::IdentityApi},
    policy::{engine::PolicyEngine, snapshot::PolicySnapshot},
};

/// Everything a live command needs.
pub struct CommandContext {
    config: Config,
    client: OciClient,
    policy: PolicyEngine,
    /// Whether a prompt can reach a human.
    interactive: bool,
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
            interactive: crate::interactive::stdin_is_a_terminal(),
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

    /// The region this context talks to.
    #[must_use]
    pub fn region(&self) -> &Region {
        &self.config.region
    }

    /// Whether interactive prompting is possible.
    ///
    /// False under a pipe, in CI, or when `--yes` made the run explicit. A
    /// command that cannot prompt must fail with a specific error rather than
    /// blocking on a stdin that will never arrive.
    #[must_use]
    pub fn is_interactive(&self) -> bool {
        self.interactive
    }

    /// Turn interactive prompting off, for a non-interactive run.
    #[must_use]
    pub fn non_interactive(mut self) -> Self {
        self.interactive = false;
        self
    }

    /// A context pointed at the tenancy's home region.
    ///
    /// Always Free capacity lives in the home region, so every write path
    /// resolves it from live subscription data rather than trusting whatever
    /// region the configuration happens to name.
    pub async fn in_home_region(&self) -> Result<Self> {
        let home = IdentityApi::new(&self.client)
            .home_region(&self.config.tenancy)
            .await?;
        Ok(self.switch_region(home))
    }

    /// The same context pointed at another region in the same realm.
    #[must_use]
    pub fn switch_region(&self, region: Region) -> Self {
        let mut config = self.config.clone();
        config.region = region.clone();
        Self {
            client: self.client.in_region(region),
            config,
            policy: PolicyEngine::new(self.policy.snapshot().clone()),
            interactive: self.interactive,
        }
    }

    /// Build a context around an already-constructed client.
    ///
    /// Test-only: it is how a command test points the whole command stack at
    /// the in-process mock server.
    #[cfg(test)]
    pub fn for_tests(client: OciClient, region: &str) -> Self {
        use std::path::PathBuf;

        use crate::{
            config::ConfigOrigin,
            domain::fingerprint::Fingerprint,
            testing::mock_oci::{TENANCY, USER},
        };

        let config = Config {
            user: USER.parse().expect("user"),
            tenancy: TENANCY.parse().expect("tenancy"),
            fingerprint: Fingerprint::from_digest([0u8; 16]),
            region: region.parse().expect("region"),
            key_file: PathBuf::from("/nonexistent/oci_api_key.pem"),
            pass_phrase: None,
            origin: ConfigOrigin {
                file: None,
                profile: "DEFAULT".to_owned(),
                env_overrides: Vec::new(),
            },
        };
        Self {
            config,
            client,
            policy: PolicyEngine::new(PolicySnapshot::load().expect("snapshot")),
            interactive: false,
        }
    }
}
