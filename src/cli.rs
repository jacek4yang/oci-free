use clap::{Parser, Subcommand};

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

    #[command(subcommand)]
    pub command: Command,
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
    /// Manage compute instances.
    Vm {
        #[command(subcommand)]
        command: VmCommand,
    },
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
    Limits,
    /// Show current usage information.
    Usage,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Explain why a resource is allowed, blocked, or unknown.
    Explain { resource: String },
}

#[derive(Debug, Subcommand)]
pub enum VmCommand {
    /// List compute instances.
    List,
    /// Show detailed information for one instance.
    Info { instance: String },
    /// Create a free-eligible instance using an interactive safe plan by default.
    Create {
        /// Disable interactive prompts. Missing required choices become errors.
        #[arg(long)]
        non_interactive: bool,
    },
    /// Terminate an instance after an explicit plan and confirmation.
    Delete { instance: String },
    /// Start an instance.
    Start { instance: String },
    /// Stop an instance.
    Stop { instance: String },
    /// Reboot an instance.
    Reboot { instance: String },
    /// Print the primary public IP for an instance.
    Ip { instance: String },
    /// Open an SSH session using the instance's discovered connection data.
    Ssh { instance: String },
    /// Inspect or modify network exposure for exactly one instance.
    Net {
        instance: String,
        #[command(subcommand)]
        command: VmNetCommand,
    },
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
    },
    /// Remove a rule from the instance-scoped NSG.
    Close {
        /// Rule in the form PORT/PROTOCOL, for example 443/tcp.
        rule: String,
    },
}
