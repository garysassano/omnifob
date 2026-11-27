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
mod skill;
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
use crate::import_export::{export_aws_config, export_gcp_adc, import_aws};
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
    if let Some(path) = &cli.config {
        // Through the variable, so every reader of the config (and `fob
        // renew`, which fob starts) uses the same file.
        let path = std::path::absolute(path).unwrap_or_else(|_| path.clone());
        // SAFETY: no other thread exists yet; the runtime starts below.
        unsafe { std::env::set_var("OMNIFOB_CONFIG", path) };
    }
    // One thread: concurrent work (`fob check`, `fob sync`) is all waiting
    // on the network, and a worker per core would only cost start-up time.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("starting the async runtime");
    // `fob exec` fails with 125 whatever went wrong before the command ran,
    // a config that does not load included, as `env` does.
    let failed = if matches!(cli.command, Command::Exec { .. }) {
        ExitCode::from(exec::FOB_FAILED)
    } else {
        ExitCode::FAILURE
    };
    match runtime.block_on(run(cli)) {
        Ok(code) => code,
        Err(e) => {
            report(&e);
            failed
        }
    }
}

/// Prints a failure for the person, and under an agent (or with
/// `OMNIFOB_ERROR_FORMAT=json`) a last line for programs: `fob-error: ` and
/// JSON with the failure's `code`, its `message` and the values that go with
/// the code, such as the command to `run`.
fn report(e: &anyhow::Error) {
    eprintln!("fob: {e:#}");
    if agent::active() || std::env::var("OMNIFOB_ERROR_FORMAT").is_ok_and(|v| v == "json") {
        eprintln!("fob-error: {}", error_json(e));
    }
}

/// A failure as JSON: `code`, `message`, and the code's values.
fn error_json(e: &anyhow::Error) -> serde_json::Value {
    let (code, details) = omnifob_core::classify(e);
    let mut object = serde_json::Map::new();
    object.insert("code".into(), code.as_str().into());
    object.insert("message".into(), format!("{e:#}").into());
    object.extend(details);
    object.into()
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
    /// The command's name, for the audit log.
    command: &'static str,
}

async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    // The library's context for the whole process: the standard files,
    // keychain and endpoints from the environment, one HTTP client for
    // this runtime, and a terminal prompt for MFA codes when someone can
    // answer. Nothing has used the library yet, so the install takes.
    let mut context = omnifob_core::Context::builder_from_env().agent(agent::context_agent());
    if interactive() {
        context = context
            .mfa_prompt(|serial| {
                Ok(dialoguer::Input::<String>::new()
                    .with_prompt(format!("MFA code for {serial}"))
                    .interact_text_on(&Term::stderr())?)
            })
            .passphrase_prompt(|request| {
                let vault = request.vault.display();
                let mut prompt = dialoguer::Password::new();
                if request.new {
                    eprintln!(
                        "fob: creating an encrypted vault in {vault}; it opens only with this passphrase, which omnifob cannot recover"
                    );
                    prompt = prompt
                        .with_prompt("New vault passphrase")
                        .with_confirmation("Repeat it", "the passphrases differ");
                } else {
                    prompt = prompt.with_prompt(format!("Passphrase for the vault in {vault}"));
                }
                Ok(prompt.interact_on(&Term::stderr())?)
            });
    }
    if context.build().install().is_err() {
        tracing::debug!("the library's context was already chosen");
    }
    // Commands that need neither the config nor the profiles, so a broken
    // config.toml or profiles.json does not break every new shell's
    // `fob activate`, or `fob unuse`.
    match &cli.command {
        Command::Activate { shell } => {
            print!("{}", shell::activate(*shell));
            return Ok(ExitCode::SUCCESS);
        }
        Command::Env {
            shell, unset: true, ..
        } => {
            let previous = std::env::var("OMNIFOB_VARS").unwrap_or_default();
            let previous: Vec<&str> = previous.split(',').filter(|v| !v.is_empty()).collect();
            print!("{}", shell::unset(*shell, &previous));
            return Ok(ExitCode::SUCCESS);
        }
        Command::Use { .. } | Command::Unuse if agent::active() => {
            return Err(omnifob_core::Coded::new(
                omnifob_core::Code::UseExec,
                "each command an agent runs starts in a new shell, so `fob use` cannot carry over; run commands as `fob exec <profile> -- <command>`",
            )
            .with("run", "fob exec <profile> -- <command>")
            .into());
        }
        Command::Use { .. } | Command::Unuse => {
            let shell = Shell::detect();
            bail!(
                "`fob use` and `fob unuse` change the current shell, which needs the shell integration. Add this to your shell's startup file:\n  {}",
                shell::activation_line(shell)
            );
        }
        _ => {}
    }
    // A config named with `--config` has to exist, so a mistyped path is not
    // taken for an empty config. `fob import --write` may create it.
    let config_file = paths::config_file()?;
    if cli.config.is_some()
        && !matches!(cli.command, Command::Import(_))
        && matches!(std::fs::metadata(&config_file), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    {
        bail!("the config file {} does not exist", config_file.display());
    }
    // `fob rename` has to open a config with a name the rule refuses, to fix it.
    let config = if matches!(cli.command, Command::Rename { .. }) {
        Config::load_allowing_any_names(&config_file)?
    } else {
        Config::load(&config_file)?
    };
    let cache = load_profiles(&cli.command)?;
    let command = match &cli.command {
        Command::Exec { .. } => "exec",
        Command::Creds { .. } => "creds",
        Command::Env { .. } => "env",
        Command::Console { .. } => "console",
        _ => "other",
    };
    let mut app = App {
        config,
        cache,
        command,
    };

    match cli.command {
        Command::Login {
            integration,
            no_browser,
            device_code,
            token_stdin,
            from_clipboard,
            force,
            start,
            wait,
        } => {
            let integration = app.pick_integration(integration.as_deref(), "login")?;
            if start {
                app.login_start(&integration, no_browser, force).await?;
                return Ok(ExitCode::SUCCESS);
            }
            if wait {
                app.login_wait(&integration).await?;
                app.sync(std::slice::from_ref(&integration)).await?;
                return Ok(ExitCode::SUCCESS);
            }
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
        Command::Logout { all: true, .. } => app.logout_all().await?,
        Command::Logout { integration, .. } => {
            let integration = app.pick_integration(integration.as_deref(), "logout")?;
            app.logout(&integration).await?;
        }
        Command::Status { json, check } => return app.status(json, check).await,
        Command::Check {
            profile,
            integration,
            quiet,
            json,
        } => {
            let output = if json {
                status::Output::Json
            } else if quiet {
                status::Output::Quiet
            } else {
                status::Output::Text
            };
            return app
                .check(query(&profile).as_deref(), &integration, output)
                .await;
        }
        Command::Rename { old, new } => app.rename(&old, &new)?,
        Command::Sync { integrations } => app.sync(&integrations).await?,
        Command::List { query: words, json } => app.list(query(&words).as_deref(), json).await?,
        Command::Env {
            profile,
            by,
            shell,
            unset,
            no_cache,
            ttl,
        } => {
            debug_assert!(!unset, "handled before loading the config");
            let previous = std::env::var("OMNIFOB_VARS").unwrap_or_default();
            let previous: Vec<&str> = previous.split(',').filter(|v| !v.is_empty()).collect();
            // `fob use` runs `fob env`, so both take the directory's default.
            let words = query(&profile);
            let pick = sync::Pick {
                directory_default: true,
                ..by.pick(&words)
            };
            let profile = app.select(pick).await?;
            if agent::active() {
                return Err(agent::refuse_to_print(&profile.id));
            }
            let creds = app.credentials(&profile, !no_cache, ttl, "shell").await?;
            print!("{}", shell::export(shell, &profile.id, &creds, &previous)?);
            eprintln!("fob: using {}{}", profile.id, expiry_note(&creds));
        }
        Command::Exec {
            profile,
            by,
            no_cache,
            ttl,
            revoke,
            server,
            no_server,
            token_file,
            command,
        } => {
            let options = exec::ExecOptions {
                server,
                no_server,
                token_file,
            };
            let words = query(&profile);
            let result = async {
                let pick = sync::Pick {
                    directory_default: true,
                    ..by.pick(&words)
                };
                let profile = app.select(pick).await?;
                // Under an agent with `[agent] auto_revoke`, each command
                // gets a Cloudflare token of its own, deleted afterwards.
                let auto_revoke = agent::active()
                    && app.config.agent.auto_revoke
                    && !no_cache
                    && matches!(profile.target, omnifob_core::Target::Cloudflare { .. });
                if revoke || auto_revoke {
                    return app.exec_and_revoke(&profile, ttl, &command).await;
                }
                // With `--server` too, so a sign-in it needs happens now and
                // the endpoint starts from cached credentials.
                let creds = app.credentials(&profile, !no_cache, ttl, "env").await?;
                let (provision, via) = app.provision(&profile, &creds, ttl, options).await?;
                if via.is_empty() {
                    return exec(&profile, &creds, &command);
                }
                app.audit(&profile, &via.join(", "), creds.expires_at, None);
                exec::run_to_end(&profile, &creds, &command, provision).await
            }
            .await;
            // As `env` does: 125 when fob fails, so it is not mistaken for the
            // command's own status.
            return Ok(result.unwrap_or_else(|e| {
                report(&e);
                ExitCode::from(exec::FOB_FAILED)
            }));
        }
        Command::Console {
            profile,
            by,
            print,
            copy,
            duration,
            service,
            region,
        } => {
            let options = providers::ConsoleOptions {
                duration,
                service,
                region,
            };
            let action = if print {
                console::Action::Print
            } else if copy {
                console::Action::Copy
            } else {
                console::Action::Open
            };
            let words = query(&profile);
            app.console(by.pick(&words), action, &options).await?
        }
        Command::Creds {
            profile,
            by,
            format,
            cluster,
            region,
            no_cache,
            ttl,
        } => {
            let words = query(&profile);
            let profile = app.select(by.pick(&words)).await?;
            // credential_process, fnox, Google's libraries and kubectl run
            // fob inside the agent's own commands and hand the output to a
            // program, not to the agent.
            if agent::active() && matches!(format, CredsFormat::Json) {
                return Err(agent::refuse_to_print(&profile.id));
            }
            if matches!(format, CredsFormat::GcpExecutable | CredsFormat::K8sExec) {
                if ttl.is_some() {
                    bail!("--ttl does not apply to --format gcp-executable or k8s-exec");
                }
                let output = app
                    .tool_creds(
                        &profile,
                        format,
                        cluster.as_deref(),
                        region.as_deref(),
                        !no_cache,
                    )
                    .await?;
                println!("{output}");
                return Ok(ExitCode::SUCCESS);
            }
            let via = match format {
                CredsFormat::Json => "json",
                CredsFormat::Fnox => "fnox",
                _ => "credential-process",
            };
            let creds = app.credentials(&profile, !no_cache, ttl, via).await?;
            println!("{}", creds_output(&profile, &creds, format)?);
        }
        Command::Revoke { all: true, .. } => app.revoke_all().await?,
        Command::Revoke { profile, .. } => app.revoke(query(&profile).as_deref()).await?,
        Command::Use { .. } | Command::Unuse | Command::Activate { .. } => {
            unreachable!("handled before loading the config")
        }
        Command::Cloudflare(CloudflareCommand::AddTemplate {
            integration,
            name,
            permissions,
            optional,
            r2_buckets,
            zones,
            s3,
            ips,
            ttl,
            replace,
        }) => {
            let template = omnifob_core::config::CloudflareTemplate {
                permissions,
                optional,
                ttl,
                r2_buckets,
                s3,
                ips: (!ips.is_empty()).then_some(ips),
                zones,
            };
            app.add_template(&integration, &name, template, replace)
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
        Command::Export(ExportCommand::GcpAdc {
            profile,
            audience,
            absolute,
            write,
        }) => {
            let profile = app.select(query(&profile).as_deref()).await?;
            export_gcp_adc(&app, &profile, &audience, absolute, write.as_deref())?;
        }
        Command::Renew { profile } => app.renew(&profile).await?,
    }
    Ok(ExitCode::SUCCESS)
}

/// Loads `profiles.json` for the commands that use it. Those that discover
/// profiles anyway (and rewrite the file), or only report on it, carry on
/// from no profiles when it cannot be read, so a corrupt file can be fixed
/// with `fob sync`. Commands that never look at profiles do not read it.
fn load_profiles(command: &Command) -> anyhow::Result<ProfileCache> {
    let tolerant = match command {
        Command::Import(_)
        | Command::Cloudflare(CloudflareCommand::Permissions { .. })
        | Command::Cloudflare(CloudflareCommand::Templates { .. }) => {
            return Ok(ProfileCache::default());
        }
        Command::Check { profile, .. } if profile.is_empty() => {
            return Ok(ProfileCache::default());
        }
        Command::Login { .. }
        | Command::Sync { .. }
        | Command::Status { .. }
        | Command::Logout { .. }
        | Command::Revoke { all: true, .. } => true,
        _ => false,
    };
    match profiles_file().and_then(|file| ProfileCache::load(&file)) {
        Err(e) if tolerant => {
            eprintln!("fob: ignoring the discovered profiles: {e:#}");
            Ok(ProfileCache::default())
        }
        other => other,
    }
}

/// Joins profile words into one query; `None` when no words were given.
fn query(words: &[String]) -> Option<String> {
    (!words.is_empty()).then(|| words.join(" "))
}

/// Remembers that a profile was used, for the picker's ordering.
fn record_use(profile_id: &str) {
    let Ok(path) = history::file() else {
        return;
    };
    let mut history = History::load(&path);
    history.record(profile_id, Timestamp::now());
    if let Err(e) = history.save(&path) {
        tracing::debug!("could not save the usage history: {e:#}");
    }
}

fn profiles_file() -> anyhow::Result<std::path::PathBuf> {
    Ok(paths::state_dir()?.join("profiles.json"))
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
