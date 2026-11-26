//! The `fob` / `omnifob` command line.
//!
//! `main` parses the command line and hands each command to a method of
//! [`App`], which holds the config and the discovered profiles. The commands
//! live in modules named after them.

mod agent;
mod browser;
mod cli;
mod clipboard;
mod console;
mod exec;
mod files;
mod import_export;
mod logging;
mod login;
mod rename;
mod renew;
mod shell;
mod status;
mod sync;
mod templates;

use std::io::IsTerminal;
use std::process::ExitCode;

use anyhow::bail;
use clap::{CommandFactory, FromArgMatches};
use dialoguer::console::Term;
use jiff::Timestamp;
use omnifob_core::history::{self, History};
use omnifob_core::profile::ProfileCache;
use omnifob_core::providers;
use omnifob_core::{Config, Error, paths};

use crate::cli::{Cli, CloudflareCommand, Command, CredsFormat, ExportCommand, ImportCommand};
use crate::exec::{creds_output, exec, expiry_note};
use crate::import_export::{export_aws_config, import_aws};
use crate::logging::log_subscriber;
use crate::shell::Shell;

pub fn main() -> ExitCode {
    // Like other command-line tools, end quietly when the reader of stdout
    // goes away (`fob list | head`) instead of panicking on a broken pipe.
    #[cfg(unix)]
    // SAFETY: called first thing in main, before any thread exists.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    // Answers the shell's completion requests (COMPLETE=<shell>) and exits.
    clap_complete::CompleteEnv::with_factory(command).complete();

    use tracing_subscriber::util::SubscriberInitExt;
    log_subscriber(
        tracing_subscriber::EnvFilter::try_from_env("OMNIFOB_LOG")
            .unwrap_or_else(|_| "warn".into()),
        std::io::stderr,
    )
    .init();

    let cli = Cli::from_arg_matches(&command().get_matches()).unwrap_or_else(|e| e.exit());
    // One thread: concurrent work (`fob check`, `fob sync`) is all waiting
    // on the network, and a worker per core would only cost start-up time.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("starting the async runtime");
    match runtime.block_on(run(cli)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("fob: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// The command line, named after the binary that was run (`fob` or `omnifob`),
/// so help, errors and `--version` say what the user typed.
fn command() -> clap::Command {
    let invoked = std::env::args_os()
        .next()
        .map(std::path::PathBuf::from)
        .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()));
    match invoked.as_deref() {
        Some("omnifob") => Cli::command().name("omnifob").bin_name("omnifob"),
        _ => Cli::command(),
    }
}

/// Whether someone can answer prompts: a terminal, and not an agent (some
/// harnesses give commands a terminal no one watches).
fn interactive() -> bool {
    !agent::active() && std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

struct App {
    config: Config,
    cache: ProfileCache,
}

async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    if interactive() {
        omnifob_core::prompt::set_mfa_prompt(|serial| {
            Ok(dialoguer::Input::<String>::new()
                .with_prompt(format!("MFA code for {serial}"))
                .interact_text_on(&Term::stderr())?)
        });
    }
    // `fob rename` has to open a config with a name the rule refuses, to fix it.
    let config = if matches!(cli.command, Command::Rename { .. }) {
        Config::load_allowing_any_names(&paths::config_file())?
    } else {
        Config::load(&paths::config_file())?
    };
    let cache = ProfileCache::load(&profiles_file())?;
    let mut app = App { config, cache };

    match cli.command {
        Command::Login {
            integration,
            no_browser,
            device_code,
            token_stdin,
            from_clipboard,
            force,
        } => {
            let integration = app.pick_integration(integration.as_deref(), "login")?;
            app.login(
                &integration,
                no_browser,
                device_code,
                token_stdin,
                from_clipboard,
                force,
            )
            .await?;
            app.sync(std::slice::from_ref(&integration)).await?;
        }
        Command::Logout { integration } => {
            let integration = app.pick_integration(integration.as_deref(), "logout")?;
            app.logout(&integration).await?;
        }
        Command::Status => app.status()?,
        Command::Check { profile, quiet } => {
            return app.check(query(&profile).as_deref(), quiet).await;
        }
        Command::Rename { old, new } => app.rename(&old, &new)?,
        Command::Sync { integrations } => app.sync(&integrations).await?,
        Command::List { query, json } => app.list(query.as_deref(), json).await?,
        Command::Env {
            profile,
            shell,
            unset,
            no_cache,
            ttl,
        } => {
            let previous = std::env::var("OMNIFOB_VARS").unwrap_or_default();
            let previous: Vec<&str> = previous.split(',').filter(|v| !v.is_empty()).collect();
            if unset {
                print!("{}", shell::unset(shell, &previous));
            } else {
                let profile = app.select(query(&profile).as_deref()).await?;
                if agent::active() {
                    return Err(agent::refuse_to_print(&profile.id));
                }
                let creds = app.credentials(&profile, !no_cache, ttl).await?;
                print!("{}", shell::export(shell, &profile.id, &creds, &previous)?);
                eprintln!("fob: using {}{}", profile.id, expiry_note(&creds));
            }
        }
        Command::Exec {
            profile,
            no_cache,
            ttl,
            revoke,
            command,
        } => {
            let result = async {
                let profile = app.select(query(&profile).as_deref()).await?;
                if revoke {
                    return app.exec_and_revoke(&profile, ttl, &command).await;
                }
                let creds = app.credentials(&profile, !no_cache, ttl).await?;
                exec(&profile, &creds, &command)
            }
            .await;
            // As `env` does: 125 when fob fails, so it is not mistaken for the
            // command's own status.
            return Ok(result.unwrap_or_else(|e| {
                eprintln!("fob: {e:#}");
                ExitCode::from(exec::FOB_FAILED)
            }));
        }
        Command::Console {
            profile,
            print,
            duration,
            service,
            region,
        } => {
            let options = providers::ConsoleOptions {
                duration,
                service,
                region,
            };
            app.console(query(&profile).as_deref(), print, &options)
                .await?
        }
        Command::Creds {
            profile,
            format,
            no_cache,
            ttl,
        } => {
            let profile = app.select(query(&profile).as_deref()).await?;
            // credential_process and fnox run fob inside the agent's own
            // commands and hand the output to a program, not to the agent.
            if agent::active() && matches!(format, CredsFormat::Json) {
                return Err(agent::refuse_to_print(&profile.id));
            }
            let creds = app.credentials(&profile, !no_cache, ttl).await?;
            println!("{}", creds_output(&profile, &creds, format)?);
        }
        Command::Revoke { profile } => app.revoke(query(&profile).as_deref()).await?,
        Command::Use { .. } | Command::Unuse if agent::active() => {
            bail!(
                "each command an agent runs starts in a new shell, so `fob use` cannot carry over; run commands as `fob exec <profile> -- <command>`"
            );
        }
        Command::Use { .. } | Command::Unuse => {
            let shell = Shell::detect();
            bail!(
                "`fob use` and `fob unuse` change the current shell, which needs the shell integration. Add this to your shell's startup file:\n  {}",
                shell::activation_line(shell)
            );
        }
        Command::Activate { shell } => print!("{}", shell::activate(shell)),
        Command::Cloudflare(CloudflareCommand::AddTemplate {
            integration,
            name,
            permissions,
            ttl,
            replace,
        }) => {
            app.add_template(&integration, &name, permissions, ttl, replace)
                .await?
        }
        Command::Cloudflare(command) => app.cloudflare(command).await?,
        Command::Import(ImportCommand::Aws { file, write }) => {
            import_aws(&app.config, file, write)?
        }
        Command::Export(ExportCommand::AwsConfig {
            prefix,
            absolute,
            write,
            file,
        }) => {
            app.ensure_synced().await?.report();
            export_aws_config(&app, &prefix, absolute, write, file)?;
        }
        Command::Renew { profile } => app.renew(&profile).await?,
    }
    Ok(ExitCode::SUCCESS)
}

/// Joins profile words into one query; `None` when no words were given.
fn query(words: &[String]) -> Option<String> {
    (!words.is_empty()).then(|| words.join(" "))
}

/// Remembers that a profile was used, for the picker's ordering.
fn record_use(profile_id: &str) {
    let path = history::file();
    let mut history = History::load(&path);
    history.record(profile_id, Timestamp::now());
    if let Err(e) = history.save(&path) {
        tracing::debug!("could not save the usage history: {e:#}");
    }
}

fn profiles_file() -> std::path::PathBuf {
    paths::state_dir().join("profiles.json")
}

impl App {
    /// Runs `f`, signing in first and retrying once if the integration needs it.
    pub(crate) async fn with_login<T, F, Fut>(&self, f: F) -> anyhow::Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = omnifob_core::Result<T>>,
    {
        match f().await {
            Err(Error::NeedsLogin {
                integration,
                reason,
            }) if interactive() => {
                self.sign_in_again(&integration, &reason).await?;
                Ok(f().await?)
            }
            other => Ok(other?),
        }
    }

    /// Signs in to `integration` again, since `reason` found its sign-in
    /// lacking (which is why it is not kept).
    pub(crate) async fn sign_in_again(
        &self,
        integration: &str,
        reason: &str,
    ) -> anyhow::Result<()> {
        eprintln!("fob: {reason}; signing in again");
        self.login(integration, false, false, false, false, true)
            .await
    }
}
