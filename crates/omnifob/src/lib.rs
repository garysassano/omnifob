//! The `fob` / `omnifob` command line.

mod shell;

use std::io::{IsTerminal, Read};
use std::process::ExitCode;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand, ValueEnum};
use dialoguer::console::Term;
use jiff::Timestamp;
use omnifob_core::config::CloudflareTokenType;
use omnifob_core::profile::{ProfileCache, SyncedProfiles};
use omnifob_core::providers::{self, SignIn, aws_sso, cloudflare};
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
        integration: String,
        /// Print the sign-in URL instead of opening a browser
        #[arg(long)]
        no_browser: bool,
        /// Read a Cloudflare bootstrap token from stdin instead of prompting
        #[arg(long)]
        token_stdin: bool,
    },
    /// Forget an integration's sign-in and cached credentials
    Logout { integration: String },
    /// Show integrations and whether you are signed in
    Status,
    /// Discover profiles (every integration when none is given)
    Sync { integrations: Vec<String> },
    /// List profiles, optionally filtered
    #[command(visible_alias = "ls")]
    List {
        query: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Print shell code exporting a profile's credentials (pick one when omitted)
    Env {
        profile: Vec<String>,
        #[arg(long, value_enum, default_value_t = Shell::detect())]
        shell: Shell,
        /// Print code that removes the variables of the active profile instead
        #[arg(long, conflicts_with = "profile")]
        unset: bool,
        /// Get new credentials even if cached ones are still valid
        #[arg(long)]
        no_cache: bool,
    },
    /// Run a command with a profile's credentials
    Exec {
        profile: Vec<String>,
        #[arg(long)]
        no_cache: bool,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Open the provider's web console as a profile
    Console {
        profile: Vec<String>,
        /// Print the URL instead of opening it
        #[arg(long)]
        print: bool,
    },
    /// Print credentials for other tools (fnox, AWS credential_process, scripts)
    Creds {
        #[arg(required = true)]
        profile: Vec<String>,
        #[arg(long, value_enum, default_value_t = CredsFormat::Json)]
        format: CredsFormat,
        #[arg(long)]
        no_cache: bool,
    },
    /// Revoke the credentials omnifob handed out for a profile (Cloudflare
    /// tokens are deleted; AWS role credentials can only be forgotten)
    Revoke { profile: Vec<String> },
    /// Print shell integration: adds `fob use <profile>` and `fob unuse`
    Activate { shell: Shell },
    /// Cloudflare helpers
    #[command(subcommand, visible_alias = "cf")]
    Cloudflare(CloudflareCommand),
    /// Get replacement credentials for a profile (started by fob in the background)
    #[command(hide = true)]
    Renew { profile: String },
}

#[derive(Subcommand)]
enum CloudflareCommand {
    /// List the permission names templates can use
    Permissions {
        integration: String,
        /// Only show permissions whose name contains this
        filter: Option<String>,
    },
    /// List templates and their permissions
    Templates { integration: String },
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
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("OMNIFOB_LOG")
                .unwrap_or_else(|_| "warn".into()),
        )
        .without_time()
        .init();

    let cli = Cli::parse();
    let runtime = tokio::runtime::Runtime::new().expect("starting the async runtime");
    match runtime.block_on(run(cli)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("fob: {e:#}");
            ExitCode::FAILURE
        }
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
        } => {
            app.login(&integration, no_browser, token_stdin).await?;
            app.sync(std::slice::from_ref(&integration)).await?;
        }
        Command::Logout { integration } => app.logout(&integration)?,
        Command::Status => app.status()?,
        Command::Sync { integrations } => app.sync(&integrations).await?,
        Command::List { query, json } => app.list(query.as_deref(), json).await?,
        Command::Env {
            profile,
            shell,
            unset,
            no_cache,
        } => {
            let previous = std::env::var("OMNIFOB_VARS").unwrap_or_default();
            let previous: Vec<&str> = previous.split(',').filter(|v| !v.is_empty()).collect();
            if unset {
                print!("{}", shell::unset(shell, &previous));
            } else {
                let profile = app.select(query(&profile).as_deref()).await?;
                let creds = app.credentials(&profile, !no_cache).await?;
                print!("{}", shell::export(shell, &profile.id, &creds, &previous));
                eprintln!("fob: using {}{}", profile.id, expiry_note(&creds));
            }
        }
        Command::Exec {
            profile,
            no_cache,
            command,
        } => {
            let profile = app.select(query(&profile).as_deref()).await?;
            let creds = app.credentials(&profile, !no_cache).await?;
            return exec(&profile, &creds, &command);
        }
        Command::Console { profile, print } => {
            let profile = app.select(query(&profile).as_deref()).await?;
            let creds = app.credentials(&profile, true).await?;
            let url = providers::console_url(&app.config, &profile, &creds).await?;
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
        } => {
            let profile = app.select(query(&profile).as_deref()).await?;
            let creds = app.credentials(&profile, !no_cache).await?;
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
        Command::Activate { shell } => print!("{}", shell::activate(shell)),
        Command::Cloudflare(command) => app.cloudflare(command).await?,
        Command::Renew { profile } => app.renew(&profile).await?,
    }
    Ok(ExitCode::SUCCESS)
}

/// Joins profile words into one query; `None` when no words were given.
fn query(words: &[String]) -> Option<String> {
    (!words.is_empty()).then(|| words.join(" "))
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
    async fn login(&self, name: &str, no_browser: bool, token_stdin: bool) -> anyhow::Result<()> {
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
                } else {
                    if !interactive() {
                        bail!("no terminal to prompt for the token; pass it with --token-stdin");
                    }
                    eprintln!(
                        "{}",
                        cloudflare_bootstrap_help(config.token_type, config.account_id.as_deref())
                    );
                    dialoguer::Password::new()
                        .with_prompt("Bootstrap token")
                        .interact_on(&Term::stderr())?
                };
                cloudflare::login(name, config, &token).await?;
            }
        }
        eprintln!("fob: signed in to '{name}'");
        Ok(())
    }

    fn logout(&mut self, name: &str) -> anyhow::Result<()> {
        let integration = self.config.integration(name)?;
        let existed = providers::logout(name, integration)?;
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
                SignIn::Token => "signed in (bootstrap token)".to_string(),
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
                } => "signed in, token renews on next use".to_string(),
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
            Err(Error::NeedsLogin { integration }) if interactive() => {
                eprintln!("fob: '{integration}' needs a sign-in");
                self.login(&integration, false, false).await?;
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
        let candidates: Vec<&Profile> = match query {
            Some(q) => self.cache.find(q),
            None => self.cache.all().collect(),
        };
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

    async fn credentials(&self, profile: &Profile, use_cache: bool) -> anyhow::Result<Credentials> {
        let creds = self
            .with_login(|| providers::credentials(&self.config, profile, use_cache))
            .await
            .with_context(|| format!("getting credentials for {}", profile.id))?;
        if use_cache && creds.wants_renewal(Timestamp::now()) {
            spawn_renewal(&profile.id);
        }
        Ok(creds)
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
        providers::credentials(&self.config, &profile, false).await?;
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
                }
            }
        }
        Ok(())
    }
}

fn cloudflare_bootstrap_help(token_type: CloudflareTokenType, account_id: Option<&str>) -> String {
    match token_type {
        CloudflareTokenType::User => "\
omnifob needs one token that can create other tokens. Create it once:
  1. Open https://dash.cloudflare.com/profile/api-tokens
  2. Create Token > \"Create additional tokens\" template > Use template
  3. Optionally restrict it to your IP addresses, then create it and paste it below"
            .to_string(),
        CloudflareTokenType::Account => format!(
            "\
omnifob needs one account-owned token that can create other tokens. Create it once:
  1. Open https://dash.cloudflare.com/{}/api-tokens
  2. Create Token > Custom token > permission \"Account API Tokens\" Edit
  3. Create it and paste it below",
            account_id.unwrap_or(":account")
        ),
    }
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
