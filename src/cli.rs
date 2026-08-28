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
    /// Delete every resource that oci-free can prove it created in the home region.
    Reset {
        /// Accept the destructive plan without prompting.
        #[arg(long)]
        yes: bool,
    },
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

#[derive(Debug, clap::Args)]
pub struct ConfigInitArgs {
    #[arg(long)]
    pub tenancy: Option<String>,
    #[arg(long)]
    pub user: Option<String>,
    #[arg(long)]
    pub region: Option<String>,
    #[arg(long)]
    pub fingerprint: Option<String>,
    #[arg(long, value_name = "PATH")]
    pub key_file: Option<PathBuf>,
    #[arg(long)]
    pub generate_key: bool,
    #[arg(long)]
    pub force: bool,
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
        resource: String,
        #[arg(long)]
        ocpus: Option<f64>,
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
        #[arg(long, conflicts_with = "delete_boot_volume")]
        keep_boot_volume: bool,
        #[arg(long)]
        delete_boot_volume: bool,
        #[arg(long)]
        delete_nsg: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Start an instance.
    Start {
        instance: String,
        #[arg(long)]
        yes: bool,
    },
    /// Stop an instance.
    Stop {
        instance: String,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Reboot an instance.
    Reboot {
        instance: String,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Print the primary public IP for an instance.
    Ip { instance: String },
    /// Open an SSH session using the instance's discovered connection data.
    Ssh {
        instance: String,
        #[arg(long, short = 'l')]
        user: Option<String>,
        #[arg(long, short = 'i', value_name = "PATH")]
        identity: Option<PathBuf>,
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

#[derive(Debug, clap::Args)]
pub struct CreateArgs {
    /// Instance display name in OCI.
    #[arg(long)]
    pub name: Option<String>,
    /// Linux login user created by cloud-init. Defaults to the image default user.
    #[arg(long, value_name = "USER")]
    pub username: Option<String>,
    /// Hostname used by both the primary VNIC DNS label and cloud-init.
    #[arg(long, value_name = "HOSTNAME")]
    pub hostname: Option<String>,
    /// Shape name, or a semantic selector such as `free:arm` or `free:x86`.
    #[arg(long)]
    pub shape: Option<String>,
    #[arg(long)]
    pub ocpus: Option<f64>,
    #[arg(long)]
    pub memory: Option<f64>,
    #[arg(long)]
    pub image: Option<String>,
    #[arg(long)]
    pub availability_domain: Option<String>,
    /// SSH public key file to install on the instance.
    #[arg(long, value_name = "PATH")]
    pub ssh_key: Option<PathBuf>,
    /// CIDR allowed to reach SSH, or `none` for no SSH ingress.
    #[arg(long)]
    pub ssh_source: Option<String>,
    #[arg(long)]
    pub no_public_ip: bool,
    #[arg(long)]
    pub non_interactive: bool,
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Subcommand)]
pub enum VmNetCommand {
    Show,
    Audit,
    Open {
        rule: String,
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    Close {
        rule: String,
        #[arg(long)]
        yes: bool,
    },
}
