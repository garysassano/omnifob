//! The `fob` / `omnifob` command line.

mod clipboard;
mod shell;

use std::io::{IsTerminal, Read};
use std::process::ExitCode;

use anyhow::{Context, bail};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use clap_complete::{ArgValueCandidates, CompletionCandidate};
use dialoguer::console::Term;
use jiff::Timestamp;
use omnifob_core::config::CloudflareTokenType;
use omnifob_core::history::{self, History};
use omnifob_core::profile::{ProfileCache, SyncedProfiles};
use omnifob_core::providers::{self, SignIn, aws_sso, cloudflare, token};
use omnifob_core::{Config, Credentials, Error, Integration, Profile, paths};

use crate::shell::Shell;

#[derive(Parser)]
#[command(
    name = "fob",
    version,
    about = "One sign-in for every cloud: short-lived credentials for AWS IAM Identity Center, Cloudflare and more",
    after_help = "Config: $OMNIFOB_CONFIG or ~/.config/omnifob/config.toml"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sign in to an integration, then discover its profiles
    Login {
        #[arg(add = ArgValueCandidates::new(integration_candidates))]
        integration: String,
        /// Print the sign-in URL instead of opening a browser
        #[arg(long)]
        no_browser: bool,
        /// Read the token (a Cloudflare bootstrap token, or a token integration's
        /// single secret) from stdin instead of prompting
        #[arg(long, conflicts_with = "from_clipboard")]
        token_stdin: bool,
        /// Read the Cloudflare bootstrap token from the clipboard instead of prompting
        #[arg(long)]
        from_clipboard: bool,
    },
    /// Forget an integration's sign-in and cached credentials
    Logout { integration: String },
    /// Show integrations and whether you are signed in
    Status,
    /// Check that sign-ins work, or that a profile's credentials do (never signs in)
    Check {
        #[arg(add = ArgValueCandidates::new(profile_candidates))]
        profile: Vec<String>,
        /// Print nothing; only the exit status tells whether everything works
        #[arg(long, short)]
        quiet: bool,
    },
    /// Rename an integration, keeping its sign-in and discovered profiles
    Rename {
        #[arg(add = ArgValueCandidates::new(integration_candidates))]
        old: String,
        new: String,
    },
    /// Discover profiles (every integration when none is given)
    Sync {
        #[arg(add = ArgValueCandidates::new(integration_candidates))]
        integrations: Vec<String>,
    },
    /// List profiles, optionally filtered
    #[command(visible_alias = "ls")]
    List {
        query: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Print shell code exporting a profile's credentials (pick one when omitted)
    Env {
        #[arg(add = ArgValueCandidates::new(profile_candidates))]
        profile: Vec<String>,
        #[arg(long, value_enum, default_value_t = Shell::detect())]
        shell: Shell,
        /// Print code that removes the variables of the active profile instead
        #[arg(long, conflicts_with = "profile")]
        unset: bool,
        /// Get new credentials even if cached ones are still valid
        #[arg(long)]
        no_cache: bool,
        /// Lifetime of minted credentials, overriding the template (Cloudflare), e.g. "4h"
        #[arg(long, value_parser = parse_ttl)]
        ttl: Option<jiff::SignedDuration>,
    },
    /// Run a command with a profile's credentials
    Exec {
        #[arg(add = ArgValueCandidates::new(profile_candidates))]
        profile: Vec<String>,
        #[arg(long)]
        no_cache: bool,
        /// Lifetime of minted credentials, overriding the template (Cloudflare), e.g. "4h"
        #[arg(long, value_parser = parse_ttl)]
        ttl: Option<jiff::SignedDuration>,
        /// Mint a token for this command only and revoke it when the command
        /// ends (Cloudflare)
        #[arg(long, conflicts_with = "no_cache")]
        revoke: bool,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Open the provider's web console as a profile
    Console {
        #[arg(add = ArgValueCandidates::new(profile_candidates))]
        profile: Vec<String>,
        /// Print the URL instead of opening it
        #[arg(long)]
        print: bool,
    },
    /// Print credentials for other tools (fnox, AWS credential_process, scripts)
    Creds {
        #[arg(required = true, add = ArgValueCandidates::new(profile_candidates))]
        profile: Vec<String>,
        #[arg(long, value_enum, default_value_t = CredsFormat::Json)]
        format: CredsFormat,
        #[arg(long)]
        no_cache: bool,
        /// Lifetime of minted credentials, overriding the template (Cloudflare), e.g. "4h"
        #[arg(long, value_parser = parse_ttl)]
        ttl: Option<jiff::SignedDuration>,
    },
    /// Revoke the credentials omnifob handed out for a profile (Cloudflare
    /// tokens are deleted; AWS role credentials can only be forgotten)
    Revoke {
        #[arg(add = ArgValueCandidates::new(profile_candidates))]
        profile: Vec<String>,
    },
    /// Switch the current shell to a profile (needs the shell integration from `fob activate`)
    Use {
        #[arg(add = ArgValueCandidates::new(profile_candidates))]
        profile: Vec<String>,
    },
    /// Remove the active profile's variables from the current shell (needs `fob activate`)
    Unuse,
    /// Print shell integration: adds `fob use <profile>` and `fob unuse`
    Activate { shell: Shell },
    /// Create integrations from other tools' configuration
    #[command(subcommand)]
    Import(ImportCommand),
    /// Write configuration for other tools
    #[command(subcommand)]
    Export(ExportCommand),
    /// Cloudflare helpers
    #[command(subcommand, visible_alias = "cf")]
    Cloudflare(CloudflareCommand),
    /// Get replacement credentials for a profile (started by fob in the background)
    #[command(hide = true)]
    Renew { profile: String },
}

#[derive(Subcommand)]
enum ImportCommand {
    /// IAM Identity Center portals used by profiles in ~/.aws/config
    /// (standard sso_* keys, sso-session sections and granted's keys)
    Aws {
        /// The AWS config file; defaults to $AWS_CONFIG_FILE or ~/.aws/config
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        /// Append the new integrations to the omnifob config instead of printing them
        #[arg(long)]
        write: bool,
    },
}

#[derive(Subcommand)]
enum ExportCommand {
    /// AWS CLI profiles that get credentials from `fob creds`, for tools that
    /// want --profile or AWS_PROFILE (needs `fob` on PATH)
    AwsConfig {
        /// Prefix for the generated profile names
        #[arg(long, default_value = "fob-")]
        prefix: String,
        /// Replace omnifob's marked block in the AWS config file instead of printing it
        #[arg(long)]
        write: bool,
        /// The AWS config file; defaults to $AWS_CONFIG_FILE or ~/.aws/config
        #[arg(long)]
        file: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum CloudflareCommand {
    /// List the permission names templates can use
    Permissions {
        #[arg(add = ArgValueCandidates::new(integration_candidates))]
        integration: String,
        /// Only show permissions whose name contains this
        filter: Option<String>,
    },
    /// List templates and their permissions
    Templates { integration: String },
    /// Create a template: pick services and their access level from the
    /// account's permissions, or name the permissions with --permission
    AddTemplate {
        #[arg(add = ArgValueCandidates::new(integration_candidates))]
        integration: String,
        /// Template name; profiles become <integration>/<account>/<name>
        name: String,
        /// A permission, as `fob cf permissions` lists it ("Pages Write");
        /// repeat for more. Without it, fob asks interactively.
        #[arg(long = "permission", short)]
        permissions: Vec<String>,
        /// Lifetime of the template's tokens, e.g. "30m" (default: the integration's)
        #[arg(long, value_parser = parse_ttl)]
        ttl: Option<jiff::SignedDuration>,
        /// Replace a template of that name in the config
        #[arg(long)]
        replace: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum CredsFormat {
    /// `{"profile", "env", "expires_at"}`
    Json,
    /// The output a fnox `command` lease expects
    Fnox,
    /// The output AWS `credential_process` expects
    CredentialProcess,
}

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

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("OMNIFOB_LOG")
                .unwrap_or_else(|_| "warn".into()),
        )
        .without_time()
        .init();

    let cli = Cli::from_arg_matches(&command().get_matches()).unwrap_or_else(|e| e.exit());
    let runtime = tokio::runtime::Runtime::new().expect("starting the async runtime");
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

fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

struct App {
    config: Config,
    cache: ProfileCache,
}

async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let config = Config::load(&paths::config_file())?;
    let cache = ProfileCache::load(&profiles_file())?;
    let mut app = App { config, cache };

    match cli.command {
        Command::Login {
            integration,
            no_browser,
            token_stdin,
            from_clipboard,
        } => {
            app.login(&integration, no_browser, token_stdin, from_clipboard)
                .await?;
            app.sync(std::slice::from_ref(&integration)).await?;
        }
        Command::Logout { integration } => app.logout(&integration).await?,
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
                let creds = app.credentials(&profile, !no_cache, ttl).await?;
                print!("{}", shell::export(shell, &profile.id, &creds, &previous));
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
            let profile = app.select(query(&profile).as_deref()).await?;
            if revoke {
                return app.exec_and_revoke(&profile, ttl, &command).await;
            }
            let creds = app.credentials(&profile, !no_cache, ttl).await?;
            return exec(&profile, &creds, &command);
        }
        Command::Console { profile, print } => {
            let profile = app.select(query(&profile).as_deref()).await?;
            // Only AWS needs credentials to sign in to its console.
            let creds = if matches!(
                profile.target,
                omnifob_core::Target::Aws { .. } | omnifob_core::Target::AwsChained { .. }
            ) {
                app.credentials(&profile, true, None).await?
            } else {
                Credentials::default()
            };
            let url = providers::console_url(&app.config, &profile, &creds).await?;
            record_use(&profile.id);
            if print {
                println!("{url}");
            } else {
                open::that(&url).context("opening the browser; use --print to get the URL")?;
                eprintln!("fob: opened the console for {}", profile.id);
            }
        }
        Command::Creds {
            profile,
            format,
            no_cache,
            ttl,
        } => {
            let profile = app.select(query(&profile).as_deref()).await?;
            let creds = app.credentials(&profile, !no_cache, ttl).await?;
            println!("{}", creds_output(&profile, &creds, format)?);
        }
        Command::Revoke { profile } => {
            let profile = app.select(query(&profile).as_deref()).await?;
            let revoked = app
                .with_login(|| providers::revoke(&app.config, &profile))
                .await?;
            match revoked {
                providers::Revoked::Tokens(n) => {
                    eprintln!(
                        "fob: deleted {n} token(s) for {} and cleared its cache",
                        profile.id
                    )
                }
                providers::Revoked::CacheOnly => eprintln!(
                    "fob: cleared the cache for {}; credentials already handed out stay valid until they expire",
                    profile.id
                ),
            }
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
            write,
            file,
        }) => {
            app.ensure_synced().await?;
            export_aws_config(&app, &prefix, write, file)?;
        }
        Command::Renew { profile } => app.renew(&profile).await?,
    }
    Ok(ExitCode::SUCCESS)
}

fn parse_ttl(s: &str) -> anyhow::Result<jiff::SignedDuration> {
    omnifob_core::config::parse_duration(s)
}

/// Joins profile words into one query; `None` when no words were given.
fn query(words: &[String]) -> Option<String> {
    (!words.is_empty()).then(|| words.join(" "))
}

/// Profile ids for shell completion, with the provider kind as a hint.
fn profile_candidates() -> Vec<CompletionCandidate> {
    let Ok(cache) = ProfileCache::load(&profiles_file()) else {
        return Vec::new();
    };
    cache
        .all()
        .map(|p| {
            let kind = match p.target {
                omnifob_core::Target::Aws { .. } => "aws",
                omnifob_core::Target::AwsChained { .. } => "aws (chained)",
                omnifob_core::Target::Cloudflare { .. } => "cloudflare",
                omnifob_core::Target::Token {} => "token",
            };
            CompletionCandidate::new(&p.id).help(Some(kind.into()))
        })
        .collect()
}

/// Integration names for shell completion.
fn integration_candidates() -> Vec<CompletionCandidate> {
    let Ok(config) = Config::load(&paths::config_file()) else {
        return Vec::new();
    };
    config
        .integrations
        .iter()
        .map(|(name, i)| CompletionCandidate::new(name).help(Some(i.kind().into())))
        .collect()
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

fn expiry_note(creds: &Credentials) -> String {
    match creds.expires_at {
        Some(at) => {
            let left = at
                .duration_since(Timestamp::now())
                .round(jiff::Unit::Minute)
                .unwrap_or_default();
            format!(" (expires in {left:#})")
        }
        None => String::new(),
    }
}

impl App {
    async fn login(
        &self,
        name: &str,
        no_browser: bool,
        token_stdin: bool,
        from_clipboard: bool,
    ) -> anyhow::Result<()> {
        match self.config.integration(name)? {
            Integration::AwsSso(config) => {
                aws_sso::login(name, config, |prompt| {
                    eprintln!("fob: approve the sign-in for '{name}' in your browser");
                    eprintln!("     {}", prompt.url);
                    eprintln!("     code: {}", prompt.user_code);
                    if !no_browser && let Err(e) = open::that(&prompt.url) {
                        eprintln!("fob: could not open a browser ({e}); open the URL above");
                    }
                })
                .await?;
            }
            Integration::Cloudflare(config) => {
                let token = if token_stdin {
                    let mut token = String::new();
                    std::io::stdin().read_to_string(&mut token)?;
                    token
                } else if from_clipboard {
                    clipboard::read_token()?
                } else {
                    if !interactive() {
                        bail!(
                            "no terminal to prompt for the token; copy it and use --from-clipboard, or pipe it to --token-stdin"
                        );
                    }
                    let url = cloudflare::bootstrap_url(config);
                    eprintln!("{}", cloudflare_bootstrap_help(config.token_type));
                    eprintln!("     {url}");
                    if !no_browser && let Err(e) = open::that(&url) {
                        eprintln!("fob: could not open a browser ({e}); open the URL above");
                    }
                    let typed = dialoguer::Password::new()
                        .with_prompt("Paste the token, or copy it and press Enter")
                        .allow_empty_password(true)
                        .interact_on(&Term::stderr())?;
                    if typed.trim().is_empty() {
                        clipboard::read_token()?
                    } else {
                        typed
                    }
                };
                if let Some(expires_at) = cloudflare::login(name, config, &token).await? {
                    eprintln!(
                        "fob: Cloudflare session for '{name}' lasts until {} (the bootstrap token expires then)",
                        expires_at.strftime("%Y-%m-%d %H:%M UTC")
                    );
                }
            }
            Integration::Token(config) => {
                let names: Vec<String> = token::secrets(config)?
                    .into_iter()
                    .map(|(name, _)| name)
                    .collect();
                let mut values = std::collections::BTreeMap::new();
                if token_stdin {
                    let [only] = names.as_slice() else {
                        bail!(
                            "--token-stdin works for a single secret; '{name}' has {}",
                            names.len()
                        );
                    };
                    let mut value = String::new();
                    std::io::stdin().read_to_string(&mut value)?;
                    values.insert(only.clone(), value);
                } else {
                    if !interactive() {
                        bail!(
                            "no terminal to prompt for secrets; pass a single one with --token-stdin"
                        );
                    }
                    for secret in &names {
                        let value = dialoguer::Password::new()
                            .with_prompt(format!("{name} {secret}"))
                            .interact_on(&Term::stderr())?;
                        values.insert(secret.clone(), value);
                    }
                }
                token::login(name, config, values).await?;
            }
        }
        eprintln!("fob: signed in to '{name}'");
        Ok(())
    }

    async fn logout(&mut self, name: &str) -> anyhow::Result<()> {
        let integration = self.config.integration(name)?.clone();
        let accounts: Vec<String> = self
            .cache
            .integrations
            .get(name)
            .map(|s| {
                let mut ids: Vec<String> = s
                    .profiles
                    .iter()
                    .filter_map(|p| match &p.target {
                        omnifob_core::Target::Cloudflare { account_id, .. } => {
                            Some(account_id.clone())
                        }
                        _ => None,
                    })
                    .collect();
                ids.dedup();
                ids
            })
            .unwrap_or_default();
        // Signing out also ends the access omnifob handed out.
        match providers::revoke_all(name, &integration, &accounts).await {
            Ok(0) | Err(Error::NeedsLogin { .. }) => {}
            Ok(n) => eprintln!("fob: deleted {n} token(s) omnifob had minted"),
            Err(e) => eprintln!("fob: could not delete minted tokens: {e:#}"),
        }
        if let Integration::Cloudflare(config) = &integration {
            match cloudflare::end_session(name, config).await {
                Ok(true) => eprintln!("fob: deleted the session's bootstrap token"),
                Ok(false) | Err(Error::NeedsLogin { .. }) => {}
                Err(e) => eprintln!("fob: could not delete the session's bootstrap token: {e:#}"),
            }
        }
        let existed = providers::logout(name, &integration)?;
        if let Some(synced) = self.cache.integrations.get(name) {
            providers::forget_credentials(&synced.profiles);
        }
        eprintln!(
            "fob: {}",
            if existed {
                "signed out"
            } else {
                "was not signed in"
            }
        );
        Ok(())
    }

    fn rename(&mut self, old: &str, new: &str) -> anyhow::Result<()> {
        let path = paths::config_file();
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let renamed = omnifob_core::config::rename_integration(&text, old, new)?;
        let integration = self.config.integration(old)?.clone();

        if let Some(synced) = self.cache.integrations.get(old) {
            providers::forget_credentials(&synced.profiles);
        }
        let moved = providers::rename_sign_in(old, new, &integration)?;
        let tmp = path.with_extension("toml.tmp");
        let written = std::fs::write(&tmp, &renamed).and_then(|()| std::fs::rename(&tmp, &path));
        if let Err(e) = written {
            // Put the sign-in back so nothing is left half renamed.
            let _ = providers::rename_sign_in(new, old, &integration);
            return Err(e).with_context(|| format!("writing {}", path.display()));
        }
        self.cache.rename_integration(old, new);
        self.cache.save(&profiles_file())?;

        let kept = if moved {
            "kept the sign-in"
        } else {
            "no sign-in to keep"
        };
        eprintln!("fob: renamed '{old}' to '{new}' ({kept}); profiles are now {new}/...");
        let aws_config = aws_config_file(None)
            .ok()
            .and_then(|p| std::fs::read_to_string(p).ok());
        if aws_config.is_some_and(|t| t.contains(&format!("fob creds {old}/"))) {
            eprintln!(
                "fob: ~/.aws/config still has profiles for '{old}'; run `fob export aws-config --write` to update them"
            );
        }
        Ok(())
    }

    /// Checks every integration's sign-in, or one profile's credentials.
    async fn check(&mut self, query: Option<&str>, quiet: bool) -> anyhow::Result<ExitCode> {
        let report = |ok: bool, what: &str, detail: &str| {
            if !quiet {
                println!("{} {what}: {detail}", if ok { "ok  " } else { "FAIL" });
            }
        };
        let mut failed = false;
        if let Some(query) = query {
            let profile = self.select(Some(query)).await?;
            match providers::check_profile(&self.config, &profile).await {
                Ok(detail) => report(true, &profile.id, &detail),
                Err(e) => {
                    failed = true;
                    report(false, &profile.id, &format!("{e:#}"));
                }
            }
        } else {
            if self.config.integrations.is_empty() {
                bail!(
                    "no integrations configured in {}",
                    paths::config_file().display()
                );
            }
            for (name, integration) in &self.config.integrations {
                match providers::check_sign_in(name, integration).await {
                    Ok(detail) => report(true, name, &detail),
                    Err(e) => {
                        failed = true;
                        report(false, name, &format!("{e:#}"));
                    }
                }
            }
        }
        Ok(if failed {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        })
    }

    fn status(&self) -> anyhow::Result<()> {
        if self.config.integrations.is_empty() {
            println!(
                "No integrations configured in {}",
                paths::config_file().display()
            );
            return Ok(());
        }
        println!("Secrets: {}", omnifob_core::store::description()?);
        let now = Timestamp::now();
        for (name, integration) in &self.config.integrations {
            let state = match providers::sign_in(name, integration)? {
                SignIn::SignedOut => "signed out".to_string(),
                SignIn::Token if matches!(integration, Integration::Cloudflare(_)) => {
                    "signed in (bootstrap token)".to_string()
                }
                SignIn::Token => "signed in (stored token)".to_string(),
                SignIn::Session {
                    expires_at,
                    refreshable,
                } if expires_at > now => {
                    let renew = if refreshable {
                        ", renews automatically"
                    } else {
                        ""
                    };
                    format!(
                        "signed in until {}{renew}",
                        expires_at.strftime("%Y-%m-%d %H:%M UTC")
                    )
                }
                SignIn::Session {
                    refreshable: true, ..
                } => "signed in; renews on next use while the portal session lasts".to_string(),
                SignIn::Session { .. } => "session expired".to_string(),
            };
            let profiles = self
                .cache
                .integrations
                .get(name)
                .map_or(0, |s| s.profiles.len());
            println!(
                "{name:<20} {:<11} {state}, {profiles} profiles",
                integration.kind()
            );
        }
        Ok(())
    }

    /// Runs `f`, signing in first and retrying once if the integration needs it.
    async fn with_login<T, F, Fut>(&self, f: F) -> anyhow::Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = omnifob_core::Result<T>>,
    {
        match f().await {
            Err(Error::NeedsLogin {
                integration,
                reason,
            }) if interactive() => {
                eprintln!("fob: {reason}; signing in again");
                self.login(&integration, false, false, false).await?;
                Ok(f().await?)
            }
            other => Ok(other?),
        }
    }

    async fn sync(&mut self, names: &[String]) -> anyhow::Result<()> {
        let names: Vec<String> = if names.is_empty() {
            self.config.integrations.keys().cloned().collect()
        } else {
            names.to_vec()
        };
        if names.is_empty() {
            bail!(
                "no integrations configured in {}",
                paths::config_file().display()
            );
        }
        for name in &names {
            let integration = self.config.integration(name)?.clone();
            let profiles = self
                .with_login(|| providers::discover(name, &integration))
                .await
                .with_context(|| format!("syncing '{name}'"))?;
            eprintln!("fob: {name}: {} profiles", profiles.len());
            self.cache.integrations.insert(
                name.clone(),
                SyncedProfiles {
                    synced_at: Timestamp::now(),
                    profiles,
                },
            );
        }
        // Drop profiles of integrations removed from the config.
        self.cache
            .integrations
            .retain(|name, _| self.config.integrations.contains_key(name));
        self.cache.save(&profiles_file())
    }

    async fn ensure_synced(&mut self) -> anyhow::Result<()> {
        let missing: Vec<String> = self
            .config
            .integrations
            .keys()
            .filter(|name| !self.cache.integrations.contains_key(*name))
            .cloned()
            .collect();
        if !missing.is_empty() {
            self.sync(&missing).await?;
        }
        Ok(())
    }

    async fn list(&mut self, query: Option<&str>, json: bool) -> anyhow::Result<()> {
        self.ensure_synced().await?;
        let profiles: Vec<&Profile> = match query {
            Some(q) => self.cache.find(q),
            None => self.cache.all().collect(),
        };
        if json {
            println!("{}", serde_json::to_string_pretty(&profiles)?);
        } else {
            for profile in profiles {
                println!("{}", profile.id);
            }
        }
        Ok(())
    }

    /// Resolves a profile query, asking the user to pick when it is missing
    /// or ambiguous and a terminal is available.
    async fn select(&mut self, query: Option<&str>) -> anyhow::Result<Profile> {
        self.ensure_synced().await?;
        let mut candidates: Vec<&Profile> = match query {
            Some(q) => self.cache.find(q),
            None => self.cache.all().collect(),
        };
        // Recently used profiles first, in the picker and in error messages.
        History::load(&history::file()).sort_recent_first(&mut candidates, |p| p.id.as_str());
        match candidates.as_slice() {
            [] if query.is_some() => bail!(
                "no profile matches '{}'; see `fob list`",
                query.unwrap_or_default()
            ),
            [] => bail!("no profiles yet; run `fob login <integration>`"),
            [one] => return Ok((*one).clone()),
            _ => {}
        }
        if !interactive() {
            let shown: Vec<_> = candidates.iter().take(10).map(|p| p.id.as_str()).collect();
            bail!(
                "'{}' matches several profiles: {}",
                query.unwrap_or(""),
                shown.join(", ")
            );
        }
        let ids: Vec<&str> = candidates.iter().map(|p| p.id.as_str()).collect();
        let picked = dialoguer::FuzzySelect::new()
            .with_prompt("Profile")
            .items(&ids)
            .default(0)
            .interact_on_opt(&Term::stderr())?
            .context("no profile selected")?;
        Ok(candidates[picked].clone())
    }

    async fn credentials(
        &self,
        profile: &Profile,
        use_cache: bool,
        ttl: Option<jiff::SignedDuration>,
    ) -> anyhow::Result<Credentials> {
        let creds = self
            .with_login(|| providers::credentials(&self.config, profile, use_cache, ttl))
            .await
            .with_context(|| format!("getting credentials for {}", profile.id))?;
        if use_cache && creds.wants_renewal(Timestamp::now()) {
            spawn_renewal(&profile.id);
        }
        record_use(&profile.id);
        Ok(creds)
    }

    /// Runs a command with a token minted for it alone, and revokes the token
    /// when the command ends, also after Ctrl-C.
    async fn exec_and_revoke(
        &self,
        profile: &Profile,
        ttl: Option<jiff::SignedDuration>,
        command: &[String],
    ) -> anyhow::Result<ExitCode> {
        let creds = self
            .with_login(|| providers::one_off_credentials(&self.config, profile, ttl))
            .await
            .with_context(|| format!("getting credentials for {}", profile.id))?;
        record_use(&profile.id);
        let status = run_to_end(profile, &creds, command).await;
        if let Some(id) = &creds.token_id {
            match providers::revoke_token(&self.config, profile, id).await {
                Ok(()) => eprintln!("fob: revoked the token for {}", profile.id),
                Err(e) => eprintln!(
                    "fob: could not revoke the token for {} ({e:#}); run `fob revoke {}`",
                    profile.id, profile.id
                ),
            }
        }
        status
    }

    /// Fetches new credentials for a profile, unless another renewal of the
    /// same profile is already running. Never prompts.
    async fn renew(&self, id: &str) -> anyhow::Result<()> {
        let Some(profile) = self.cache.all().find(|p| p.id == id).cloned() else {
            return Ok(());
        };
        let Some(_lock) = RenewalLock::acquire(id)? else {
            return Ok(());
        };
        providers::credentials(&self.config, &profile, false, None).await?;
        Ok(())
    }

    async fn cloudflare(&self, command: CloudflareCommand) -> anyhow::Result<()> {
        let cloudflare_config = |name: &str| match self.config.integration(name)? {
            Integration::Cloudflare(c) => Ok(c.clone()),
            other => bail!(
                "'{name}' is an {} integration, not cloudflare",
                other.kind()
            ),
        };
        match command {
            CloudflareCommand::Permissions {
                integration,
                filter,
            } => {
                let config = cloudflare_config(&integration)?;
                let groups = self
                    .with_login(|| cloudflare::permission_groups(&integration, &config))
                    .await?;
                let filter = filter.map(|f| f.to_lowercase());
                for group in groups {
                    if filter
                        .as_ref()
                        .is_none_or(|f| group.name.to_lowercase().contains(f))
                    {
                        let scope = group
                            .scopes
                            .first()
                            .map_or("", |s| s.rsplit('.').next().unwrap_or(s));
                        println!("{:<50} {scope}", group.name);
                    }
                }
            }
            CloudflareCommand::Templates { integration } => {
                let config = cloudflare_config(&integration)?;
                let mut templates = cloudflare::builtin_templates();
                templates.extend(config.templates.clone());
                for (name, template) in templates {
                    let ttl = template.ttl.unwrap_or(config.ttl);
                    println!("{name} ({ttl:#}): {}", template.permissions.join(", "));
                    if !template.optional.is_empty() {
                        println!("  when available: {}", template.optional.join(", "));
                    }
                    if !template.r2_buckets.is_empty() {
                        println!("  R2 buckets: {}", template.r2_buckets.join(", "));
                    }
                    if template.s3 {
                        println!("  with R2 S3 credentials");
                    }
                    let ips = template.ips.as_ref().unwrap_or(&config.ips);
                    if !ips.is_empty() {
                        println!("  usable from: {}", ips.join(", "));
                    }
                }
            }
            CloudflareCommand::AddTemplate { .. } => unreachable!("handled in run"),
        }
        Ok(())
    }

    /// Writes a new Cloudflare template to the config and syncs, so its
    /// profiles can be used at once.
    async fn add_template(
        &mut self,
        integration: &str,
        name: &str,
        permissions: Vec<String>,
        ttl: Option<jiff::SignedDuration>,
        replace: bool,
    ) -> anyhow::Result<()> {
        let config = match self.config.integration(integration)? {
            Integration::Cloudflare(c) => c.clone(),
            other => bail!(
                "'{integration}' is an {} integration, not cloudflare",
                other.kind()
            ),
        };
        if config.templates.contains_key(name) && !replace {
            bail!(
                "'{integration}' already has a template named '{name}'; add --replace to overwrite it"
            );
        }
        let groups = self
            .with_login(|| cloudflare::permission_groups(integration, &config))
            .await?;
        let permissions = if permissions.is_empty() {
            if !std::io::stdin().is_terminal() {
                bail!(
                    "name the permissions with --permission, or run this in a terminal to pick them"
                );
            }
            pick_permissions(&cloudflare::services(&groups, config.token_type))?
        } else {
            // Check the names now rather than at the first mint, and store
            // them as Cloudflare spells them.
            cloudflare::resolve_permissions(&permissions, &groups)?
                .into_iter()
                .map(|g| g.name.clone())
                .collect()
        };
        if permissions.is_empty() {
            bail!("no permissions picked; nothing was saved");
        }
        if cloudflare::builtin_templates().contains_key(name) {
            eprintln!(
                "fob: '{name}' replaces the built-in template of that name for '{integration}'"
            );
        }

        let template = omnifob_core::config::CloudflareTemplate {
            permissions,
            ttl,
            ..Default::default()
        };
        let path = paths::config_file();
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let text = omnifob_core::config::add_cloudflare_template(
            &text,
            integration,
            name,
            &template,
            replace,
        )?;
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, &text)
            .and_then(|()| std::fs::rename(&tmp, &path))
            .with_context(|| format!("writing {}", path.display()))?;
        self.config = Config::parse(&text)?;
        eprintln!(
            "fob: added template '{name}' to '{integration}' ({}):",
            path.display()
        );
        for permission in &template.permissions {
            eprintln!("       {permission}");
        }
        self.sync(&[integration.to_string()]).await
    }
}

/// Lets the user pick services and an access level for each, the way the
/// dashboard's token form does, but searchable. Returns permission names.
fn pick_permissions(services: &[cloudflare::Service]) -> anyhow::Result<Vec<String>> {
    // Index of the chosen permission per service: read, write or another.
    let mut chosen: std::collections::BTreeMap<usize, String> = std::collections::BTreeMap::new();
    let mut cursor = 0;
    let term = Term::stderr();
    eprintln!("fob: pick a service, then its access; pick \"Done\" to save.");
    loop {
        let mut items = vec![match chosen.len() {
            0 => "Done (cancel: nothing picked yet)".to_string(),
            n => format!("Done: save {n} permission{}", if n == 1 { "" } else { "s" }),
        }];
        items.extend(services.iter().enumerate().map(|(i, s)| {
            let picked = chosen.get(&i).map_or(String::new(), |p| format!("  [{p}]"));
            format!("{:<44} {:<8}{picked}", s.name, s.scope())
        }));
        let Some(picked) = dialoguer::FuzzySelect::new()
            .with_prompt(format!("Services ({} picked)", chosen.len()))
            .items(&items)
            .default(cursor)
            .interact_on_opt(&term)?
        else {
            bail!("cancelled; nothing was saved");
        };
        if picked == 0 {
            return Ok(chosen.into_values().collect());
        }
        cursor = picked;
        let index = picked - 1;
        let service = &services[index];
        let mut options: Vec<(String, Option<String>)> = Vec::new();
        if let Some(g) = &service.read {
            options.push(("Read".into(), Some(g.name.clone())));
        }
        if let Some(g) = &service.write {
            options.push(("Edit (read and write)".into(), Some(g.name.clone())));
        }
        for g in &service.other {
            options.push((g.name.clone(), Some(g.name.clone())));
        }
        if chosen.contains_key(&index) {
            options.push(("None (remove)".into(), None));
        }
        let labels: Vec<&str> = options.iter().map(|(label, _)| label.as_str()).collect();
        let Some(level) = dialoguer::Select::new()
            .with_prompt(service.name.as_str())
            .items(&labels)
            .default(0)
            .interact_on_opt(&term)?
        else {
            continue;
        };
        match &options[level].1 {
            Some(name) => chosen.insert(index, name.clone()),
            None => chosen.remove(&index),
        };
    }
}

fn cloudflare_bootstrap_help(token_type: CloudflareTokenType) -> &'static str {
    match token_type {
        CloudflareTokenType::User => {
            "\
fob: omnifob needs one token that can create other tokens. In the page that opens:
     Create Token > \"Create Additional Tokens\" > Use template, name it \"omnifob bootstrap\",
     then create it and copy the token."
        }
        CloudflareTokenType::Account => {
            "\
fob: omnifob needs one token that can create other tokens. The page that opens is
     pre-filled (name \"omnifob bootstrap\", permission Account API Tokens: Edit):
     Review token > Create token > copy the token with the copy icon."
        }
    }
}

fn aws_config_file(file: Option<std::path::PathBuf>) -> anyhow::Result<std::path::PathBuf> {
    file.or_else(|| std::env::var_os("AWS_CONFIG_FILE").map(Into::into))
        .or_else(|| std::env::home_dir().map(|h| h.join(".aws/config")))
        .context("cannot find the AWS config file; pass --file")
}

fn export_aws_config(
    app: &App,
    prefix: &str,
    write: bool,
    file: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    use omnifob_core::import::{aws_config_block, replace_aws_block};
    let profiles: Vec<&Profile> = app
        .cache
        .all()
        .filter(|p| {
            matches!(
                p.target,
                omnifob_core::Target::Aws { .. } | omnifob_core::Target::AwsChained { .. }
            )
        })
        .collect();
    let regions: std::collections::BTreeMap<String, String> = profiles
        .iter()
        .filter_map(|p| {
            let Ok(Integration::AwsSso(c)) = app.config.integration(&p.integration) else {
                return None;
            };
            let region = match &p.target {
                omnifob_core::Target::AwsChained { label, .. } => c
                    .chained
                    .get(label)
                    .and_then(|r| r.region.clone())
                    .or_else(|| c.default_region.clone()),
                _ => c.default_region.clone(),
            }?;
            Some((p.id.clone(), region))
        })
        .collect();
    let block = aws_config_block(&profiles, prefix, &regions);
    if !write {
        print!("{block}");
        return Ok(());
    }
    let path = aws_config_file(file)?;
    let existing = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let updated = replace_aws_block(&existing, &block);
    if updated == existing {
        eprintln!("fob: {} is up to date", path.display());
        return Ok(());
    }
    if !existing.is_empty() {
        let backup = path.with_extension("omnifob-backup");
        std::fs::write(&backup, &existing)
            .with_context(|| format!("writing {}", backup.display()))?;
        eprintln!("fob: backed up the previous file to {}", backup.display());
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, updated).with_context(|| format!("writing {}", path.display()))?;
    eprintln!(
        "fob: wrote {} profile(s) to omnifob's block in {}; use them with --profile {prefix}<integration>-<account>-<role>",
        profiles.len(),
        path.display()
    );
    Ok(())
}

fn import_aws(
    config: &Config,
    file: Option<std::path::PathBuf>,
    write: bool,
) -> anyhow::Result<()> {
    use omnifob_core::import::{aws_portal_toml, aws_portals, chained_toml, normalize_start_url};
    let file = aws_config_file(file)?;
    let text =
        std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;

    // Configured portals, by normalised start URL.
    let configured: std::collections::BTreeMap<
        String,
        (&String, &omnifob_core::config::AwsSsoConfig),
    > = config
        .integrations
        .iter()
        .filter_map(|(name, i)| match i {
            Integration::AwsSso(c) => Some((normalize_start_url(&c.start_url), (name, c))),
            _ => None,
        })
        .collect();
    let mut taken: Vec<String> = config.integrations.keys().cloned().collect();
    let mut sections = Vec::new();
    let (mut new_portals, mut new_chained) = (0, 0);
    for mut portal in aws_portals(&text) {
        for (profile, reason) in &portal.skipped {
            eprintln!("fob: skipped chained profile '{profile}': {reason}");
        }
        if let Some((name, existing)) = configured.get(&portal.start_url) {
            portal
                .chained
                .retain(|label, _| !existing.chained.contains_key(label));
            if portal.chained.is_empty() {
                eprintln!(
                    "fob: {} is already configured as '{name}'",
                    portal.start_url
                );
            } else {
                eprintln!(
                    "fob: {} is configured as '{name}'; {} chained role(s) to add",
                    portal.start_url,
                    portal.chained.len()
                );
                new_chained += portal.chained.len();
                sections.push(chained_toml(name, &portal.chained).trim_start().to_string());
            }
            continue;
        }
        let base = portal.name.clone();
        let mut n = 1;
        while taken.contains(&portal.name) {
            n += 1;
            portal.name = format!("{base}-{n}");
        }
        taken.push(portal.name.clone());
        eprintln!(
            "fob: {} as '{}': {} profile(s), {} chained role(s)",
            portal.start_url,
            portal.name,
            portal.profiles,
            portal.chained.len()
        );
        new_portals += 1;
        new_chained += portal.chained.len();
        sections.push(aws_portal_toml(&portal));
    }
    if sections.is_empty() {
        eprintln!("fob: nothing new to import");
        return Ok(());
    }
    let toml = sections.join("\n");
    if !write {
        print!("{toml}");
        eprintln!(
            "fob: review the names, then run again with --write to append them to {}",
            paths::config_file().display()
        );
        return Ok(());
    }
    let path = paths::config_file();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let separator = if existing.is_empty() || existing.ends_with("\n\n") {
        ""
    } else if existing.ends_with('\n') {
        "\n"
    } else {
        "\n\n"
    };
    let updated = format!("{existing}{separator}{toml}");
    Config::parse(&updated).context("the result would not be a valid config; nothing written")?;
    std::fs::write(&path, updated).with_context(|| format!("writing {}", path.display()))?;
    eprintln!(
        "fob: added {new_portals} integration(s) and {new_chained} chained role(s) to {}; run `fob sync`, or `fob login <name>` for new portals",
        path.display()
    );
    Ok(())
}

/// Starts `fob renew <profile>` detached from the terminal, so the next
/// command finds fresh credentials instead of waiting for them.
fn spawn_renewal(profile_id: &str) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["renew", profile_id])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Its own process group: Ctrl-C in the terminal does not reach it.
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        cmd.creation_flags(DETACHED_PROCESS);
    }
    match cmd.spawn() {
        Ok(_) => tracing::debug!("renewing {profile_id} in the background"),
        Err(e) => tracing::debug!("could not start a background renewal: {e}"),
    }
}

/// A lock file per profile so concurrent commands start one renewal only.
/// A lock older than two minutes is considered abandoned.
struct RenewalLock(std::path::PathBuf);

impl RenewalLock {
    fn acquire(profile_id: &str) -> anyhow::Result<Option<Self>> {
        let dir = paths::state_dir().join("locks");
        std::fs::create_dir_all(&dir)?;
        let name: String = profile_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let path = dir.join(format!("renew-{name}.lock"));
        for _ in 0..2 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => return Ok(Some(Self(path))),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let age = std::fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok());
                    if age.is_some_and(|a| a < std::time::Duration::from_secs(120)) {
                        return Ok(None);
                    }
                    let _ = std::fs::remove_file(&path);
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(None)
    }
}

impl Drop for RenewalLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn creds_output(
    profile: &Profile,
    creds: &Credentials,
    format: CredsFormat,
) -> anyhow::Result<String> {
    let value = match format {
        CredsFormat::Json => serde_json::json!({
            "profile": profile.id,
            "env": creds.env,
            "expires_at": creds.expires_at,
        }),
        CredsFormat::Fnox => serde_json::json!({
            "credentials": creds.env,
            "expires_at": creds.expires_at,
            "lease_id": format!("omnifob:{}", profile.id),
        }),
        CredsFormat::CredentialProcess => {
            let get = |k: &str| {
                creds
                    .env
                    .get(k)
                    .with_context(|| format!("{} is not an AWS profile", profile.id))
            };
            serde_json::json!({
                "Version": 1,
                "AccessKeyId": get("AWS_ACCESS_KEY_ID")?,
                "SecretAccessKey": get("AWS_SECRET_ACCESS_KEY")?,
                "SessionToken": get("AWS_SESSION_TOKEN")?,
                "Expiration": creds.expires_at,
            })
        }
    };
    Ok(serde_json::to_string(&value)?)
}

/// Runs a command to its end and returns its exit status. Ctrl-C reaches the
/// command, not omnifob, so omnifob can clean up after it.
async fn run_to_end(
    profile: &Profile,
    creds: &Credentials,
    command: &[String],
) -> anyhow::Result<ExitCode> {
    let mut child = tokio::process::Command::new(&command[0])
        .args(&command[1..])
        .envs(&creds.env)
        .env("OMNIFOB_PROFILE", &profile.id)
        .spawn()
        .with_context(|| format!("running {}", command[0]))?;
    // The terminal sends Ctrl-C, and a hangup when it closes, to the command
    // too; omnifob waits for the command to end instead of ending first.
    #[cfg(unix)]
    let (mut hangup, mut terminate) = {
        use tokio::signal::unix::{SignalKind, signal};
        (
            signal(SignalKind::hangup())?,
            signal(SignalKind::terminate())?,
        )
    };
    let status = loop {
        #[cfg(unix)]
        tokio::select! {
            status = child.wait() => break status?,
            _ = tokio::signal::ctrl_c() => {}
            _ = hangup.recv() => {}
            _ = terminate.recv() => {
                // Unlike Ctrl-C, nobody else told the command to stop.
                if let Some(pid) = child.id() {
                    // SAFETY: sends a signal to the child, which has not been reaped.
                    unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
                }
            }
        }
        #[cfg(not(unix))]
        tokio::select! {
            status = child.wait() => break status?,
            _ = tokio::signal::ctrl_c() => {}
        }
    };
    #[cfg(unix)]
    if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&status) {
        return Ok(ExitCode::from(128 + signal as u8));
    }
    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
}

fn exec(profile: &Profile, creds: &Credentials, command: &[String]) -> anyhow::Result<ExitCode> {
    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..])
        .envs(&creds.env)
        .env("OMNIFOB_PROFILE", &profile.id);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        Err(err).with_context(|| format!("running {}", command[0]))
    }
    #[cfg(not(unix))]
    {
        let status = cmd
            .status()
            .with_context(|| format!("running {}", command[0]))?;
        Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
    }
}
