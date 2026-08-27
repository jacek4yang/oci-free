use std::path::PathBuf;

use clap::{Parser, Subcommand};
use oci_free::config::ConfigOptions;

#[derive(Debug, Parser)]
#[command(
    name = "oci-free",
    version,
    about = "A smart, free-first manager for Oracle Cloud Free Tier accounts",
    long_about = None
)]
pub struct Cli {
    /// Emit machine-readable JSON where supported.
    #[arg(long, global = true)]
    pub json: bool,

    /// Path to the OCI configuration file. Defaults to ~/.oci/config.
    #[arg(long, global = true, value_name = "PATH")]
    pub config_file: Option<PathBuf>,

    /// Configuration profile to read. Defaults to DEFAULT.
    #[arg(long, global = true, value_name = "NAME")]
    pub profile: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    /// Configuration overrides selected on the command line.
    #[must_use]
    pub fn config_options(&self) -> ConfigOptions {
        ConfigOptions {
            config_file: self.config_file.clone(),
            profile: self.profile.clone(),
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show a concise account, resource, exposure, and billing summary.
    Status,
    /// Validate credentials, permissions, region, limits, and local configuration.
    Doctor,
    /// Show current billing-period cost and highlight non-zero spend.
    Cost,
    /// Inspect resources that are currently considered free-eligible.
    Free {
        #[command(subcommand)]
        command: FreeCommand,
    },
    /// Inspect tenancy-level information.
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
    /// Explain safety-policy decisions.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Create or inspect the local oci-free configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Manage compute instances.
    Vm {
        #[command(subcommand)]
        command: VmCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Write an OCI configuration profile, optionally generating an API key.
    Init(Box<ConfigInitArgs>),
    /// Show the configuration oci-free would use, with secrets redacted.
    Show,
}

/// Arguments for `config init`.
#[derive(Debug, clap::Args)]
pub struct ConfigInitArgs {
    /// Tenancy OCID.
    #[arg(long)]
    pub tenancy: Option<String>,
    /// User OCID.
    #[arg(long)]
    pub user: Option<String>,
    /// Region identifier, for example us-ashburn-1.
    #[arg(long)]
    pub region: Option<String>,
    /// Fingerprint of the API key uploaded to OCI.
    #[arg(long)]
    pub fingerprint: Option<String>,
    /// Path to the private key file.
    #[arg(long, value_name = "PATH")]
    pub key_file: Option<PathBuf>,
    /// Generate a new RSA API key pair instead of using an existing one.
    #[arg(long)]
    pub generate_key: bool,
    /// Replace an existing profile of the same name.
    #[arg(long)]
    pub force: bool,
    /// Do not prompt. Every required value must be supplied as a flag.
    #[arg(long)]
    pub non_interactive: bool,
}

#[derive(Debug, Subcommand)]
pub enum FreeCommand {
    /// List currently verified free-eligible resources and remaining capacity.
    List,
}

#[derive(Debug, Subcommand)]
pub enum AccountCommand {
    /// Show tenancy and home-region information.
    Info,
    /// Show relevant service limits and current usage.
    Limits {
        /// Include every limit, not only the Free Tier-relevant ones.
        #[arg(long)]
        all: bool,
    },
    /// Show current usage information.
    Usage,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Explain why a resource is allowed, blocked, or unknown.
    Explain {
        /// A compute shape name, for example VM.Standard.A1.Flex.
        resource: String,
        /// OCPU count to project a launch against. Requires --memory.
        #[arg(long)]
        ocpus: Option<f64>,
        /// Memory in GB to project a launch against. Requires --ocpus.
        #[arg(long)]
        memory: Option<f64>,
    },
}

#[derive(Debug, Subcommand)]
pub enum VmCommand {
    /// List compute instances.
    List,
    /// Show detailed information for one instance.
    Info { instance: String },
    /// Create a free-eligible instance using an interactive safe plan by default.
    Create(Box<CreateArgs>),
    /// Terminate an instance after an explicit plan and confirmation.
    Delete {
        instance: String,
        /// Keep the boot volume after the instance is terminated.
        ///
        /// A retained boot volume keeps consuming the Always Free storage
        /// allowance, so this is never the silent default.
        #[arg(long, conflicts_with = "delete_boot_volume")]
        keep_boot_volume: bool,
        /// Delete the boot volume along with the instance.
        #[arg(long)]
        delete_boot_volume: bool,
        /// Also delete the instance's oci-free-managed network security group.
        #[arg(long)]
        delete_nsg: bool,
        /// Accept the plan without prompting.
        #[arg(long)]
        yes: bool,
    },
    /// Start an instance.
    Start {
        instance: String,
        /// Accept the plan without prompting.
        #[arg(long)]
        yes: bool,
    },
    /// Stop an instance.
    Stop {
        instance: String,
        /// Power off immediately instead of shutting down gracefully.
        #[arg(long)]
        force: bool,
        /// Accept the plan without prompting.
        #[arg(long)]
        yes: bool,
    },
    /// Reboot an instance.
    Reboot {
        instance: String,
        /// Power cycle immediately instead of restarting gracefully.
        #[arg(long)]
        force: bool,
        /// Accept the plan without prompting.
        #[arg(long)]
        yes: bool,
    },
    /// Print the primary public IP for an instance.
    Ip { instance: String },
    /// Open an SSH session using the instance's discovered connection data.
    Ssh {
        instance: String,
        /// Login name. Defaults to the image's usual account.
        #[arg(long, short = 'l')]
        user: Option<String>,
        /// Private key to authenticate with.
        #[arg(long, short = 'i', value_name = "PATH")]
        identity: Option<PathBuf>,
        /// Print the command instead of running it.
        #[arg(long)]
        print: bool,
    },
    /// Inspect or modify network exposure for exactly one instance.
    Net {
        instance: String,
        #[command(subcommand)]
        command: VmNetCommand,
    },
}

/// Arguments for `vm create`.
///
/// Boxed at the call site: this is by far the largest variant, and inlining it
/// would make every other subcommand pay for its size.
#[derive(Debug, clap::Args)]
pub struct CreateArgs {
    /// Instance display name.
    #[arg(long)]
    pub name: Option<String>,
    /// Shape name, or a semantic selector such as `free:arm` or `free:x86`.
    #[arg(long)]
    pub shape: Option<String>,
    /// OCPU count for a flexible shape.
    #[arg(long)]
    pub ocpus: Option<f64>,
    /// Memory in GB for a flexible shape.
    #[arg(long)]
    pub memory: Option<f64>,
    /// Image OCID. Defaults to the newest compatible platform image.
    #[arg(long)]
    pub image: Option<String>,
    /// Availability domain. Defaults to the first with free capacity.
    #[arg(long)]
    pub availability_domain: Option<String>,
    /// SSH public key file to install on the instance.
    #[arg(long, value_name = "PATH")]
    pub ssh_key: Option<PathBuf>,
    /// CIDR allowed to reach SSH, or `none` for no SSH ingress.
    #[arg(long)]
    pub ssh_source: Option<String>,
    /// Do not give the instance a public IP address.
    #[arg(long)]
    pub no_public_ip: bool,
    /// Disable interactive prompts. Missing required choices become errors.
    #[arg(long)]
    pub non_interactive: bool,
    /// Accept the plan without prompting.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Subcommand)]
pub enum VmNetCommand {
    /// Show effective ingress and the OCI object that grants each rule.
    Show,
    /// Audit effective exposure and flag risky or inherited rules.
    Audit,
    /// Open a rule on the instance-scoped NSG.
    Open {
        /// Rule in the form PORT/PROTOCOL, for example 443/tcp.
        rule: String,
        /// Optional CIDR source. If omitted, interactive mode asks for a safe choice.
        #[arg(long)]
        source: Option<String>,
        /// Accept the plan without prompting.
        #[arg(long)]
        yes: bool,
    },
    /// Remove a rule from the instance-scoped NSG.
    Close {
        /// Rule in the form PORT/PROTOCOL, for example 443/tcp.
        rule: String,
        /// Accept the plan without prompting.
        #[arg(long)]
        yes: bool,
    },
}
