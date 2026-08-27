//! `oci-free` entry point.
//!
//! Dispatch keeps three responsibilities in one place: choose human or JSON
//! rendering, map every failure onto a documented exit code, and never let a
//! command print a bare error without guidance.
//!
//! Every command in the v1 surface is wired to a real implementation. There is
//! no placeholder path: a command that cannot do its job reports a classified
//! failure with a next action, never a success-shaped result.

mod cli;

use std::process::ExitCode;

use clap::Parser;
use cli::{
    AccountCommand, Cli, Command, ConfigCommand, CreateArgs, FreeCommand, PolicyCommand, VmCommand,
    VmNetCommand,
};
use oci_free::{
    commands::{
        account, config_init, context::CommandContext, cost, create, delete, doctor, free, policy,
        ssh, status, vm, vmlifecycle, vmnet,
    },
    config::Environment,
    domain::{audit::Severity, network::PortRule},
    error::{Error, ErrorKind, ExitCodeKind, Result},
    interactive,
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
        Ok(code) => code,
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

/// Run the selected command, returning the process exit code.
///
/// Most commands exit 0 on success. `doctor` and `vm net audit` are the
/// exceptions: their whole purpose is to report a problem, so they carry the
/// verdict in the exit code as well as the output.
#[allow(clippy::too_many_lines)]
async fn run(cli: &Cli) -> Result<ExitCode> {
    let success = ExitCodeKind::Success.exit_code();

    match &cli.command {
        Command::Doctor => run_doctor(cli).await,

        Command::Status => {
            let context = context(cli)?;
            let report = status::run(&context).await?;
            emit(cli, "status", &report, status::render_human(&report))?;
            Ok(success)
        }

        Command::Cost => {
            let context = context(cli)?;
            let report = cost::run(&context).await?;
            emit(cli, "cost", &report, cost::render_human(&report))?;
            Ok(success)
        }

        Command::Account { command } => match command {
            AccountCommand::Info => {
                let context = context(cli)?;
                let info = account::run(&context).await?;
                emit(cli, "account.info", &info, account::render_human(&info))?;
                Ok(success)
            }
            AccountCommand::Limits { all } => {
                let context = context(cli)?;
                let report = account::limits(&context, *all).await?;
                emit(
                    cli,
                    "account.limits",
                    &report,
                    account::render_limits(&report),
                )?;
                Ok(success)
            }
            AccountCommand::Usage => {
                let context = context(cli)?;
                let report = account::usage(&context).await?;
                emit(
                    cli,
                    "account.usage",
                    &report,
                    account::render_usage(&report),
                )?;
                Ok(success)
            }
        },

        Command::Free {
            command: FreeCommand::List,
        } => {
            let context = context(cli)?;
            let report = free::run(&context).await?;
            emit(cli, "free.list", &report, free::render_human(&report))?;
            Ok(success)
        }

        Command::Policy {
            command:
                PolicyCommand::Explain {
                    resource,
                    ocpus,
                    memory,
                },
        } => {
            let context = context(cli)?;
            let projection = policy::parse_projection(*ocpus, *memory)?;
            let explanation = policy::explain(&context, resource, projection).await?;
            emit(
                cli,
                "policy.explain",
                &explanation,
                policy::render_human(&explanation),
            )?;
            Ok(success)
        }

        Command::Config { command } => match command {
            ConfigCommand::Init(args) => {
                let env = Environment::from_process();
                let request = config_init::InitRequest {
                    profile: cli.profile.clone(),
                    config_file: cli.config_file.clone(),
                    tenancy: args.tenancy.clone(),
                    user: args.user.clone(),
                    region: args.region.clone(),
                    fingerprint: args.fingerprint.clone(),
                    key_file: args.key_file.clone(),
                    force: args.force,
                    interactive: !args.non_interactive
                        && !cli.json
                        && interactive::stdin_is_a_terminal(),
                };
                if args.generate_key {
                    return Err(key_generation_unsupported());
                }
                let result = config_init::init(&env, &request).await?;
                emit(
                    cli,
                    "config.init",
                    &result,
                    config_init::render_init(&result),
                )?;
                Ok(success)
            }
            ConfigCommand::Show => {
                let config =
                    config_init::show(&Environment::from_process(), &cli.config_options())?;
                emit(
                    cli,
                    "config.show",
                    &config,
                    config_init::render_show(&config),
                )?;
                Ok(success)
            }
        },

        Command::Vm { command } => run_vm(cli, command).await,
    }
}

#[allow(clippy::too_many_lines)]
async fn run_vm(cli: &Cli, command: &VmCommand) -> Result<ExitCode> {
    let success = ExitCodeKind::Success.exit_code();

    match command {
        VmCommand::List => {
            let context = context(cli)?;
            let list = vm::list(&context).await?;
            emit(cli, "vm.list", &list, vm::render_human(&list))?;
            Ok(success)
        }

        VmCommand::Info { instance } => {
            let context = context(cli)?;
            let info = vm::info(&context, instance).await?;
            emit(cli, "vm.info", &info, vm::render_info(&info))?;
            Ok(success)
        }

        VmCommand::Ip { instance } => {
            let context = context(cli)?;
            let ip = vm::ip(&context, instance).await?;
            emit(cli, "vm.ip", &ip, vm::render_ip(&ip))?;
            Ok(success)
        }

        VmCommand::Ssh {
            instance,
            user,
            identity,
            print,
        } => {
            let context = context(cli)?;
            // JSON mode must be usable in a pipeline, so it never takes over the
            // terminal with an interactive session.
            let mode = if *print || cli.json {
                ssh::SshMode::Print
            } else {
                ssh::SshMode::Connect
            };
            let target =
                ssh::run(&context, instance, user.as_deref(), identity.as_ref(), mode).await?;
            emit(cli, "vm.ssh", &target, ssh::render_human(&target))?;
            // Pass the SSH client's own exit code through, so a script wrapping
            // `oci-free vm ssh` behaves like one wrapping `ssh`.
            Ok(match target.exit_code {
                Some(code) if code != 0 => {
                    ExitCode::from(u8::try_from(code).unwrap_or(ExitCodeKind::Failure.code()))
                }
                _ => success,
            })
        }

        VmCommand::Create(args) => {
            let context = create_context(cli, args)?;
            let request = create::CreateRequest {
                name: args.name.clone(),
                shape: args.shape.clone(),
                ocpus: args.ocpus,
                memory: args.memory,
                image: args.image.clone(),
                availability_domain: args.availability_domain.clone(),
                ssh_key: args.ssh_key.clone(),
                ssh_source: args.ssh_source.clone(),
                no_public_ip: args.no_public_ip,
                assume_yes: args.yes,
            };
            let (_, result) = create::run(&context, &request).await?;
            emit(cli, "vm.create", &result, create::render_human(&result))?;
            Ok(success)
        }

        VmCommand::Delete {
            instance,
            keep_boot_volume,
            delete_boot_volume,
            delete_nsg,
            yes,
        } => {
            let context = context(cli)?;
            let request = delete::DeleteRequest {
                boot_volume: delete::boot_policy(*keep_boot_volume, *delete_boot_volume),
                delete_nsg: *delete_nsg,
                assume_yes: *yes,
            };
            let (plan, result) = delete::run(&context, instance, request).await?;
            delete::refuse_if_blocked(&plan)?;
            emit(cli, "vm.delete", &result, delete::render_human(&result))?;
            Ok(success)
        }

        VmCommand::Start { instance, yes } => {
            lifecycle(
                cli,
                instance,
                oci_free::oci::compute::InstanceAction::Start,
                *yes,
            )
            .await
        }

        VmCommand::Stop {
            instance,
            force,
            yes,
        } => lifecycle(cli, instance, vmlifecycle::stop_action(*force), *yes).await,

        VmCommand::Reboot {
            instance,
            force,
            yes,
        } => lifecycle(cli, instance, vmlifecycle::reboot_action(*force), *yes).await,

        VmCommand::Net { instance, command } => run_vm_net(cli, instance, command).await,
    }
}

async fn run_vm_net(cli: &Cli, instance: &str, command: &VmNetCommand) -> Result<ExitCode> {
    let success = ExitCodeKind::Success.exit_code();
    let context = context(cli)?;

    match command {
        VmNetCommand::Show => {
            let show = vmnet::show(&context, instance).await?;
            emit(cli, "vm.net.show", &show, vmnet::render_show(&show))?;
            Ok(success)
        }

        VmNetCommand::Audit => {
            let result = vmnet::run_audit(&context, instance).await?;
            emit(cli, "vm.net.audit", &result, vmnet::render_audit(&result))?;
            // An audit that found something exits non-zero so a scheduled run
            // can alert on it without parsing the output.
            Ok(if vmnet::audit_severity(&result) >= Severity::Warning {
                ExitCodeKind::Safety.exit_code()
            } else {
                success
            })
        }

        VmNetCommand::Open { rule, source, yes } => {
            let rule = parse_rule(rule)?;
            let (_, change) =
                vmnet::open(&context, instance, rule, source.as_deref(), *yes).await?;
            emit(cli, "vm.net.open", &change, vmnet::render_change(&change))?;
            Ok(success)
        }

        VmNetCommand::Close { rule, yes } => {
            let rule = parse_rule(rule)?;
            let (_, change) = vmnet::close(&context, instance, rule, *yes).await?;
            emit(cli, "vm.net.close", &change, vmnet::render_change(&change))?;
            Ok(success)
        }
    }
}

async fn lifecycle(
    cli: &Cli,
    instance: &str,
    action: oci_free::oci::compute::InstanceAction,
    assume_yes: bool,
) -> Result<ExitCode> {
    let context = context(cli)?;
    let (plan, result) = vmlifecycle::run(&context, instance, action, assume_yes).await?;
    vmlifecycle::refuse_if_blocked(&plan)?;
    let command = format!("vm.{}", vmlifecycle::action_command(action));
    emit(cli, &command, &result, vmlifecycle::render_human(&result))?;
    Ok(ExitCodeKind::Success.exit_code())
}

fn parse_rule(rule: &str) -> Result<PortRule> {
    rule.parse::<PortRule>().map_err(|error| {
        Error::invalid_input(format!("`{rule}` is not a valid rule"))
            .with_context(error.to_string())
            .with_remediation("use PORT/PROTOCOL, for example 443/tcp or 51820/udp")
    })
}

fn context(cli: &Cli) -> Result<CommandContext> {
    let context = CommandContext::load(&Environment::from_process(), &cli.config_options())?;
    // JSON output implies automation: prompting into a pipe would hang.
    Ok(if cli.json {
        context.non_interactive()
    } else {
        context
    })
}

fn create_context(cli: &Cli, args: &CreateArgs) -> Result<CommandContext> {
    let context = context(cli)?;
    Ok(if args.non_interactive {
        context.non_interactive()
    } else {
        context
    })
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

async fn run_doctor(cli: &Cli) -> Result<ExitCode> {
    let report = doctor::run_with_live(&Environment::from_process(), &cli.config_options()).await;

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

    doctor::is_usable(&report)?;
    Ok(ExitCodeKind::Success.exit_code())
}

/// Explain why `--generate-key` is not offered.
///
/// The OCI Console generates the pair, shows the fingerprint, and hands over
/// the private key in one step with no local toolchain, so shipping a second
/// way to make a key would add risk without adding capability.
fn key_generation_unsupported() -> Error {
    let mut context = String::from(
        "oci-free does not generate API keys. The OCI Console does it in one step, with no \
         Python, OpenSSL, or OCI CLI needed:",
    );
    for step in config_init::key_advice() {
        context.push_str(&format!("\n  - {step}"));
    }
    Error::invalid_input("--generate-key is not supported")
        .with_context(context)
        .with_remediation("create the key in the OCI Console, then re-run `oci-free config init`")
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
            AccountCommand::Limits { .. } => "account.limits".to_owned(),
            AccountCommand::Usage => "account.usage".to_owned(),
        },
        Command::Policy { command } => match command {
            PolicyCommand::Explain { .. } => "policy.explain".to_owned(),
        },
        Command::Config { command } => match command {
            ConfigCommand::Init(_) => "config.init".to_owned(),
            ConfigCommand::Show => "config.show".to_owned(),
        },
        Command::Vm { command } => match command {
            VmCommand::List => "vm.list".to_owned(),
            VmCommand::Info { .. } => "vm.info".to_owned(),
            VmCommand::Create(_) => "vm.create".to_owned(),
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
