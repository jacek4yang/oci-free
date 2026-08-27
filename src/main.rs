mod cli;

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;
use cli::{AccountCommand, Cli, Command, FreeCommand, PolicyCommand, VmCommand, VmNetCommand};
use oci_free::{commands::doctor, config::Environment};
use serde_json::json;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(&cli) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: &Cli) -> Result<ExitCode> {
    match &cli.command {
        Command::Doctor => run_doctor(cli),
        other => {
            scaffold(cli, &describe(other));
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn run_doctor(cli: &Cli) -> Result<ExitCode> {
    let report = doctor::run(&Environment::from_process(), &cli.config_options());

    if cli.json {
        println!("{}", doctor::render_json(&report)?);
    } else {
        print!("{}", doctor::render_human(&report));
    }

    Ok(if report.is_healthy() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Placeholder output for commands that still need the OCI transport layer.
fn scaffold(cli: &Cli, action: &str) {
    const MESSAGE: &str =
        "OCI transport is not implemented yet. See CLAUDE.md for the implementation contract.";

    if cli.json {
        let payload = json!({
            "status": "scaffold",
            "action": action,
            "message": MESSAGE,
        });
        match serde_json::to_string_pretty(&payload) {
            Ok(rendered) => println!("{rendered}"),
            Err(error) => eprintln!("error: {error}"),
        }
    } else {
        println!("oci-free scaffold: {action}");
        println!("{MESSAGE}");
    }
}

fn describe(command: &Command) -> String {
    match command {
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
                    let source = source.as_deref().unwrap_or("interactive");
                    format!("vm net {instance} open {rule} source={source}")
                }
                VmNetCommand::Close { rule } => format!("vm net {instance} close {rule}"),
            },
        },
    }
}
