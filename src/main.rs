mod cli;
mod domain;
mod policy;

use anyhow::Result;
use clap::Parser;
use cli::{AccountCommand, Cli, Command, FreeCommand, PolicyCommand, VmCommand, VmNetCommand};
use serde_json::json;

fn main() -> Result<()> {
    let cli = Cli::parse();
    dispatch(cli)
}

fn dispatch(cli: Cli) -> Result<()> {
    let action = match cli.command {
        Command::Status => "status".to_owned(),
        Command::Doctor => "doctor".to_owned(),
        Command::Cost => "cost".to_owned(),
        Command::Free { command } => match command {
            FreeCommand::List => "free list".to_owned(),
        },
        Command::Account { command } => match command {
            AccountCommand::Info => "account info".to_owned(),
            AccountCommand::Limits => "account limits".to_owned(),
            AccountCommand::Usage => "account usage".to_owned(),
        },
        Command::Policy { command } => match command {
            PolicyCommand::Explain { resource } => format!("policy explain {resource}"),
        },
        Command::Vm { command } => match command {
            VmCommand::List => "vm list".to_owned(),
            VmCommand::Info { instance } => format!("vm info {instance}"),
            VmCommand::Create { non_interactive } => {
                format!("vm create (non_interactive={non_interactive})")
            }
            VmCommand::Delete { instance } => format!("vm delete {instance}"),
            VmCommand::Start { instance } => format!("vm start {instance}"),
            VmCommand::Stop { instance } => format!("vm stop {instance}"),
            VmCommand::Reboot { instance } => format!("vm reboot {instance}"),
            VmCommand::Ip { instance } => format!("vm ip {instance}"),
            VmCommand::Ssh { instance } => format!("vm ssh {instance}"),
            VmCommand::Net { instance, command } => match command {
                VmNetCommand::Show => format!("vm net {instance} show"),
                VmNetCommand::Audit => format!("vm net {instance} audit"),
                VmNetCommand::Open { rule, source } => {
                    let source = source.unwrap_or_else(|| "interactive".to_owned());
                    format!("vm net {instance} open {rule} source={source}")
                }
                VmNetCommand::Close { rule } => format!("vm net {instance} close {rule}"),
            },
        },
    };

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "status": "scaffold",
                "action": action,
                "message": "OCI transport is not implemented yet. See CLAUDE.md for the implementation contract."
            }))?
        );
    } else {
        println!("oci-free scaffold: {action}");
        println!("OCI transport is not implemented yet. See CLAUDE.md for the implementation contract.");
    }

    Ok(())
}
