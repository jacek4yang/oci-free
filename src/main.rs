//! `oci-free` entry point.
//!
//! Dispatch keeps three responsibilities in one place: choose human or JSON
//! rendering, map every failure onto a documented exit code, and never let a
//! command print a bare error without guidance.
//!
//! Commands that still need OCI write support report that explicitly through
//! the normal error path rather than printing a success-looking placeholder, so
//! a script can distinguish "not implemented" from "did nothing".

mod cli;

use std::process::ExitCode;

use clap::Parser;
use cli::{AccountCommand, Cli, Command, FreeCommand, PolicyCommand, VmCommand, VmNetCommand};
use oci_free::{
    commands::{account, context::CommandContext, doctor, free, vm},
    config::Environment,
    error::{Error, ErrorKind, ExitCodeKind, Result},
    output::{Envelope, render_failure},
};
use serde::Serialize;

fn main() -> ExitCode {
    let cli = Cli::parse();

    // A single multi-threaded runtime for the whole process. Building it here
    // rather than with #[tokio::main] keeps startup cheap for commands like
    // `--help` that never touch the network.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: could not start the async runtime: {error}");
            return ExitCodeKind::Failure.exit_code();
        }
    };

    runtime.block_on(dispatch(&cli))
}

async fn dispatch(cli: &Cli) -> ExitCode {
    let command = command_id(&cli.command);

    match run(cli).await {
        Ok(()) => ExitCodeKind::Success.exit_code(),
        Err(error) => {
            if cli.json {
                println!("{}", render_failure(&command, &error));
            } else {
                eprint!("{}", error.render_human());
            }
            error.exit_code_kind().exit_code()
        }
    }
}

async fn run(cli: &Cli) -> Result<()> {
    match &cli.command {
        Command::Doctor => run_doctor(cli),

        Command::Account {
            command: AccountCommand::Info,
        } => {
            let context = context(cli)?;
            let info = account::run(&context).await?;
            emit(cli, "account.info", &info, account::render_human(&info))
        }

        Command::Free {
            command: FreeCommand::List,
        } => {
            let context = context(cli)?;
            let report = free::run(&context).await?;
            emit(cli, "free.list", &report, free::render_human(&report))
        }

        Command::Vm {
            command: VmCommand::List,
        } => {
            let context = context(cli)?;
            let list = vm::list(&context).await?;
            emit(cli, "vm.list", &list, vm::render_human(&list))
        }

        other => Err(not_yet_available(&command_id(other))),
    }
}

fn context(cli: &Cli) -> Result<CommandContext> {
    CommandContext::load(&Environment::from_process(), &cli.config_options())
}

/// Print a payload as JSON or human text.
fn emit<T: Serialize>(cli: &Cli, command: &str, data: &T, human: String) -> Result<()> {
    if cli.json {
        let envelope = Envelope::success(command, data);
        let rendered = envelope.render().map_err(|error| {
            Error::new(
                ErrorKind::MalformedResponse,
                "could not serialize the response",
            )
            .with_context(error.to_string())
        })?;
        println!("{rendered}");
    } else {
        print!("{human}");
    }
    Ok(())
}

fn run_doctor(cli: &Cli) -> Result<()> {
    let report = doctor::run(&Environment::from_process(), &cli.config_options());

    if cli.json {
        let rendered = doctor::render_json(&report).map_err(|error| {
            Error::new(
                ErrorKind::MalformedResponse,
                "could not serialize the report",
            )
            .with_context(error.to_string())
        })?;
        println!("{rendered}");
    } else {
        print!("{}", doctor::render_human(&report));
    }

    if report.is_healthy() {
        Ok(())
    } else {
        Err(
            Error::configuration("the local configuration is not usable")
                .with_context("see the failing checks above")
                .with_remediation("fix the failures reported by `oci-free doctor`"),
        )
    }
}

/// Report a command whose OCI support is not in this build.
///
/// Deliberately an error, not a friendly message on stdout: a script must be
/// able to tell that nothing happened. The exit code is `Failure`, distinct
/// from a safety refusal or a transient fault.
fn not_yet_available(command: &str) -> Error {
    Error::new(
        ErrorKind::UnsupportedState,
        format!("`{command}` is not available in this build"),
    )
    .with_context(
        "the OCI transport, policy engine, and read commands are implemented; this command's \
         OCI support is not yet wired up",
    )
    .with_remediation(
        "run `oci-free --help` to see the commands this build supports, or check the project \
         README for current status",
    )
}

/// Stable dotted command identifier used in JSON output.
fn command_id(command: &Command) -> String {
    match command {
        Command::Status => "status".to_owned(),
        Command::Doctor => "doctor".to_owned(),
        Command::Cost => "cost".to_owned(),
        Command::Free { command } => match command {
            FreeCommand::List => "free.list".to_owned(),
        },
        Command::Account { command } => match command {
            AccountCommand::Info => "account.info".to_owned(),
            AccountCommand::Limits => "account.limits".to_owned(),
            AccountCommand::Usage => "account.usage".to_owned(),
        },
        Command::Policy { command } => match command {
            PolicyCommand::Explain { .. } => "policy.explain".to_owned(),
        },
        Command::Vm { command } => match command {
            VmCommand::List => "vm.list".to_owned(),
            VmCommand::Info { .. } => "vm.info".to_owned(),
            VmCommand::Create { .. } => "vm.create".to_owned(),
            VmCommand::Delete { .. } => "vm.delete".to_owned(),
            VmCommand::Start { .. } => "vm.start".to_owned(),
            VmCommand::Stop { .. } => "vm.stop".to_owned(),
            VmCommand::Reboot { .. } => "vm.reboot".to_owned(),
            VmCommand::Ip { .. } => "vm.ip".to_owned(),
            VmCommand::Ssh { .. } => "vm.ssh".to_owned(),
            VmCommand::Net { command, .. } => match command {
                VmNetCommand::Show => "vm.net.show".to_owned(),
                VmNetCommand::Audit => "vm.net.audit".to_owned(),
                VmNetCommand::Open { .. } => "vm.net.open".to_owned(),
                VmNetCommand::Close { .. } => "vm.net.close".to_owned(),
            },
        },
    }
}
