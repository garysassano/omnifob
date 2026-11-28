//! `fob exec`, `fob creds`, `fob env` and `fob revoke`: getting a profile's
//! credentials and handing them to a command, another tool or the shell.

use std::process::ExitCode;

use anyhow::{Context, bail};
use jiff::Timestamp;
use omnifob_core::credentials::AWS_CREDENTIAL_VARS;
use omnifob_core::provision::{self, Provision};
use omnifob_core::{Credentials, Integration, Profile, Target, providers};

use crate::cli::CredsFormat;
use crate::renew::spawn_renewal;
use crate::{App, record_use};

/// `fob exec`'s status when fob itself fails, before the command runs (as
/// `env` and `nohup` use it).
pub(crate) const FOB_FAILED: u8 = 125;

/// `fob exec`'s status when the command cannot be started: 127 when it is not
/// found, 126 when it is found but cannot run, as the shell and `env` report.
fn could_not_start(program: &str, e: &std::io::Error) -> ExitCode {
    eprintln!("fob: running {program}: {e}");
    ExitCode::from(match e.kind() {
        std::io::ErrorKind::NotFound => 127,
        _ => 126,
    })
}

pub(crate) fn expiry_note(creds: &Credentials) -> String {
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

/// What `fob exec` hands the command besides variables.
#[derive(Clone, Copy, Default)]
pub(crate) struct ExecOptions {
    /// An AWS container credentials endpoint (`--server`).
    pub(crate) server: bool,
    /// No Azure or Google endpoint (`--no-server`).
    pub(crate) no_server: bool,
    /// gcloud's token in a file (`--token-file`).
    pub(crate) token_file: bool,
}

impl ExecOptions {
    /// Fails when an option does not fit the profile, before any credential
    /// is fetched or minted.
    pub(crate) fn check(&self, profile: &Profile) -> anyhow::Result<()> {
        if self.server && !profile.target.is_aws() {
            bail!(
                "--server serves AWS credentials; {} is not an AWS profile",
                profile.id
            );
        }
        let google = matches!(
            profile.target,
            Target::Gcp { .. } | Target::GcpServiceAccount { .. }
        );
        if self.token_file && !google {
            bail!(
                "--token-file is for Google Cloud profiles; {} is not one",
                profile.id
            );
        }
        Ok(())
    }
}

impl App {
    /// `[agent] max_ttl`, when an agent runs fob.
    pub(crate) fn agent_max_ttl(&self) -> Option<jiff::SignedDuration> {
        self.config.agent.max_ttl.filter(|_| crate::agent::active())
    }

    /// The lifetime to ask for: `ttl`, capped at `[agent] max_ttl` for an
    /// agent where the profile's lifetime is omnifob's to choose.
    pub(crate) fn agent_ttl(
        &self,
        profile: &Profile,
        ttl: Option<jiff::SignedDuration>,
    ) -> Option<jiff::SignedDuration> {
        match self.config.agent.max_ttl {
            Some(max) if crate::agent::active() => {
                providers::capped_ttl(&self.config, profile, ttl, max)
            }
            _ => ttl,
        }
    }

    /// Gets a profile's credentials for a command, which hands them over
    /// `via` (for the audit log).
    pub(crate) async fn credentials(
        &self,
        profile: &Profile,
        use_cache: bool,
        ttl: Option<jiff::SignedDuration>,
        via: &str,
    ) -> anyhow::Result<Credentials> {
        let creds = self.unaudited_credentials(profile, use_cache, ttl).await?;
        self.audit(profile, via, creds.expires_at, creds.token_id.as_deref());
        Ok(creds)
    }

    /// [`App::credentials`] for a caller that writes the audit entry itself,
    /// once it knows every way they are handed over.
    pub(crate) async fn unaudited_credentials(
        &self,
        profile: &Profile,
        use_cache: bool,
        ttl: Option<jiff::SignedDuration>,
    ) -> anyhow::Result<Credentials> {
        let ttl = self.agent_ttl(profile, ttl);
        let creds = self
            .with_login(|| providers::credentials(&self.config, profile, use_cache, ttl))
            .await
            .with_context(|| format!("getting credentials for {}", profile.id))?;
        // An AWS session the provider sets the length of (an Identity Center
        // role's, a console sign-in's) is shortened for an agent instead.
        // `fob console` signs in with them, which needs the session itself.
        let creds = match self.agent_max_ttl() {
            Some(max) if self.command != "console" => providers::scoped_for_agent(
                &self.config,
                profile,
                creds,
                max,
                &format!("fob {} (agent)", self.command),
            )
            .await
            .with_context(|| format!("getting credentials for {}", profile.id))?,
            _ => creds,
        };
        if use_cache && ttl.is_none() && creds.wants_renewal(Timestamp::now()) {
            spawn_renewal(&self.config, profile);
        }
        record_use(&profile.id);
        Ok(creds)
    }

    /// Appends a line to the audit log when `[audit] enabled` says so. A
    /// log that cannot be written is reported and does not stop the command.
    pub(crate) fn audit(
        &self,
        profile: &Profile,
        via: &str,
        expires_at: Option<Timestamp>,
        token_id: Option<&str>,
    ) {
        if !self.config.audit.enabled {
            return;
        }
        let entry = omnifob_core::audit::Entry {
            timestamp: Timestamp::now(),
            command: self.command,
            profile: &profile.id,
            integration: &profile.integration,
            agent: crate::agent::marker(),
            via,
            expires_at,
            token_id,
        };
        if let Err(e) = omnifob_core::audit::record(&entry) {
            eprintln!("fob: could not write the audit log: {e:#}");
        }
    }

    /// The endpoints and files `fob exec` adds for a profile: Azure's
    /// managed identity and Google's ADC endpoint unless `--no-server`, an
    /// AWS container endpoint with `--server`, and gcloud's token file with
    /// `--token-file`. Also names them, for the audit log.
    pub(crate) async fn provision(
        &self,
        profile: &Profile,
        creds: &Credentials,
        ttl: Option<jiff::SignedDuration>,
        options: ExecOptions,
    ) -> anyhow::Result<(Provision, Vec<&'static str>)> {
        options.check(profile)?;
        let mut provision = Provision::default();
        let mut via = Vec::new();
        let target = &profile.target;
        // The agent's cap, as for the variables.
        let ttl = self.agent_ttl(profile, ttl);
        if options.server {
            provision.merge(
                provision::aws_container_endpoint(
                    self.config.clone(),
                    profile.clone(),
                    ttl,
                    self.agent_max_ttl(),
                )
                .await?,
            );
            via.push("aws-container");
        }
        let google = matches!(
            target,
            Target::Gcp { .. } | Target::GcpServiceAccount { .. }
        );
        if options.token_file {
            provision.merge(provision::gcp_token_file(
                self.config.clone(),
                profile.clone(),
                creds,
                ttl,
            )?);
            via.push("gcloud-token-file");
        }
        if !options.no_server {
            if let Some((integration, tenant)) = provision::azure_tenant(profile) {
                provision.merge(
                    provision::azure_identity_endpoint(integration.to_string(), tenant.to_string())
                        .await?,
                );
                via.push("azure-identity");
            } else if google {
                provision.merge(
                    provision::gcp_adc_endpoint(self.config.clone(), profile.clone(), ttl).await?,
                );
                via.push("gcp-adc");
            }
        }
        Ok((provision, via))
    }

    /// Output for a tool that runs `fob creds` itself: Google's
    /// executable-sourced credentials and kubectl's exec plugins.
    pub(crate) async fn tool_creds(
        &self,
        profile: &Profile,
        format: CredsFormat,
        cluster: Option<&str>,
        region: Option<&str>,
        use_cache: bool,
    ) -> anyhow::Result<String> {
        let value = match (format, &profile.target) {
            (CredsFormat::GcpExecutable, Target::Gcp { .. } | Target::GcpServiceAccount { .. }) => {
                let Integration::Gcp(config) = self.config.integration(&profile.integration)?
                else {
                    bail!(
                        "{} does not match its integration; run `fob sync`",
                        profile.id
                    );
                };
                let (token, expires_at) = self
                    .with_login(|| providers::gcp::id_token(&profile.integration, config))
                    .await?;
                record_use(&profile.id);
                self.audit(profile, "gcp-executable", Some(expires_at), None);
                provision::gcp_executable_response(&token, expires_at)
            }
            (CredsFormat::GcpExecutable, _) => {
                bail!(
                    "--format gcp-executable is for Google Cloud profiles; {} is not one",
                    profile.id
                )
            }
            (CredsFormat::K8sExec, target) => {
                let api_version = provision::exec_api_version(
                    std::env::var("KUBERNETES_EXEC_INFO").ok().as_deref(),
                )?;
                let (token, expires_at) = match target {
                    Target::Azure { tenant_id, .. } => {
                        let (token, at) = self
                            .with_login(|| {
                                providers::azure::resource_token(
                                    &profile.integration,
                                    tenant_id,
                                    provision::AKS_SERVER_APP,
                                )
                            })
                            .await?;
                        record_use(&profile.id);
                        self.audit(profile, "k8s-exec", Some(at), None);
                        (token, Some(at))
                    }
                    Target::Gcp { .. } | Target::GcpServiceAccount { .. } => {
                        let creds = self
                            .credentials(profile, use_cache, None, "k8s-exec")
                            .await?;
                        let token = creds
                            .env
                            .get("CLOUDSDK_AUTH_ACCESS_TOKEN")
                            .context("no Google access token in the credentials")?
                            .clone();
                        (token, creds.expires_at)
                    }
                    target if target.is_aws() => {
                        let cluster = cluster
                            .context("an EKS token is for one cluster: add --cluster <name>")?;
                        let creds = self
                            .credentials(profile, use_cache, None, "k8s-exec")
                            .await?;
                        let region = region
                            .or_else(|| provision::aws_region(&creds))
                            .unwrap_or("us-east-1");
                        let (token, at) = provision::eks_token(&creds, cluster, region)?;
                        // The token ends before the credentials that signed it
                        // when they end sooner.
                        let at = creds.expires_at.map_or(at, |end| end.min(at));
                        (token, Some(at))
                    }
                    _ => bail!(
                        "--format k8s-exec is for AWS (EKS), Google Cloud (GKE) and Azure (AKS) profiles; {} is none of them",
                        profile.id
                    ),
                };
                provision::exec_credential(&api_version, &token, expires_at)
            }
            _ => unreachable!("other formats print the credentials themselves"),
        };
        Ok(serde_json::to_string(&value)?)
    }

    /// Runs a command with a token minted for it alone, and revokes the token
    /// when the command ends, also after Ctrl-C.
    pub(crate) async fn exec_and_revoke(
        &self,
        profile: &Profile,
        ttl: Option<jiff::SignedDuration>,
        command: &[String],
    ) -> anyhow::Result<ExitCode> {
        let ttl = self.agent_ttl(profile, ttl);
        let creds = self
            .with_login(|| providers::one_off_credentials(&self.config, profile, ttl))
            .await
            .with_context(|| format!("getting credentials for {}", profile.id))?;
        record_use(&profile.id);
        self.audit(
            profile,
            "env, revoked after",
            creds.expires_at,
            creds.token_id.as_deref(),
        );
        let status = run_to_end(profile, &creds, command, Provision::default()).await;
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

    /// Revokes everything omnifob handed out: deletes the tokens every
    /// Cloudflare integration minted, and clears every profile's cached
    /// credentials. Sign-ins stay.
    pub(crate) async fn revoke_all(&mut self) -> anyhow::Result<()> {
        let mut failed = Vec::new();
        let mut deleted = 0;
        for (name, integration) in &self.config.integrations {
            if !matches!(integration, omnifob_core::Integration::Cloudflare(_)) {
                continue;
            }
            let accounts = self.cloudflare_accounts(name);
            match providers::revoke_all(name, integration, &accounts).await {
                Ok(n) => deleted += n,
                // Not signing in just for this: `fob logout` deleted them
                // when the sign-in ended, unless it lapsed on its own.
                Err(omnifob_core::Error::NeedsLogin { .. }) => eprintln!(
                    "fob: '{name}' is not signed in, so its tokens were not deleted; `fob login {name}` and run this again"
                ),
                Err(e) => {
                    eprintln!("fob: deleting the tokens of '{name}': {e:#}");
                    failed.push(name.as_str());
                }
            }
        }
        let profiles: Vec<&Profile> = self.cache.all().collect();
        providers::forget_credentials(profiles.iter().copied());
        eprintln!(
            "fob: deleted {deleted} token(s) and cleared the cache of {} profile(s); other credentials already handed out stay valid until they expire",
            profiles.len()
        );
        if !failed.is_empty() {
            anyhow::bail!("could not delete the tokens of {}", failed.join(", "));
        }
        Ok(())
    }

    pub(crate) async fn revoke(&mut self, query: Option<&str>) -> anyhow::Result<()> {
        let profile = self.select(query).await?;
        let revoked = self
            .with_login(|| providers::revoke(&self.config, &profile))
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
        Ok(())
    }
}

pub(crate) fn creds_output(
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
        CredsFormat::GcpExecutable | CredsFormat::K8sExec => {
            unreachable!("written by App::tool_creds")
        }
        CredsFormat::CredentialProcess => {
            let get = |k: &str| {
                creds
                    .env
                    .get(k)
                    .with_context(|| format!("{} is not an AWS profile", profile.id))
            };
            let mut value = serde_json::json!({
                "Version": 1,
                "AccessKeyId": get("AWS_ACCESS_KEY_ID")?,
                "SecretAccessKey": get("AWS_SECRET_ACCESS_KEY")?,
                "SessionToken": get("AWS_SESSION_TOKEN")?,
                "Expiration": creds.expires_at,
            });
            // Optional in the process credential format; omitted, not null.
            if let Some(account) = creds.env.get("AWS_ACCOUNT_ID") {
                value["AccountId"] = account.clone().into();
            }
            value
        }
    };
    Ok(serde_json::to_string(&value)?)
}

/// Variables fob puts into AWS profiles' environments besides the
/// credentials, which go stale with them: the account, and R2's S3
/// endpoint. Region variables are not here: see [`child_env`].
const AWS_COMPANION_VARS: &[&str] = &["AWS_ACCOUNT_ID", "AWS_ENDPOINT_URL_S3"];

/// The command's environment: the variables to remove from fob's own
/// environment, and the ones to set.
///
/// Removed are the variables a previous `fob use` set (`previous`, from
/// `OMNIFOB_VARS`) that this profile does not, `OMNIFOB_VARS` itself, and,
/// when the profile hands out an AWS access key, the other sources of AWS
/// credentials ([`AWS_CREDENTIAL_VARS`]: a profile, web identity, a
/// container endpoint) and the account and endpoint variables it does not
/// set. A Region variable is removed only
/// when the profile sets the other one (R2 sets `AWS_REGION` alone), since
/// for a profile with no Region of its own the one in the shell is the
/// user's choice.
pub(crate) fn child_env(
    profile: &Profile,
    creds: &Credentials,
    previous: &str,
) -> (Vec<String>, Vec<(String, String)>) {
    let sets = |name: &str| creds.env.contains_key(name);
    let mut remove: Vec<String> = previous
        .split(',')
        .filter(|name| !name.is_empty() && !sets(name))
        .map(str::to_string)
        .collect();
    remove.push("OMNIFOB_VARS".to_string());
    // The vault's passphrase opens every stored secret; the command never
    // needs it.
    remove.push(omnifob_core::context::VAULT_PASSPHRASE_VAR.to_string());
    remove.extend(stale_vars(creds));
    let mut set: Vec<(String, String)> = creds
        .env
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    set.push(("OMNIFOB_PROFILE".to_string(), profile.id.clone()));
    match creds.expires_at {
        Some(at) => set.push(("OMNIFOB_EXPIRES_AT".to_string(), at.to_string())),
        None => remove.push("OMNIFOB_EXPIRES_AT".to_string()),
    }
    remove.sort();
    remove.dedup();
    (remove, set)
}

/// Variables from another source of AWS credentials (a profile, a session
/// token, an endpoint) that would mix with `creds`' own, when they are AWS
/// credentials; also the Region variables when they set one. `fob exec`
/// removes them from the command's environment and `fob use` from the
/// shell's.
pub(crate) fn stale_vars(creds: &Credentials) -> Vec<String> {
    let sets = |name: &str| creds.env.contains_key(name);
    if !sets("AWS_ACCESS_KEY_ID") {
        return Vec::new();
    }
    let mut stale: Vec<&str> = AWS_CREDENTIAL_VARS.to_vec();
    stale.extend(AWS_COMPANION_VARS);
    if sets("AWS_REGION") || sets("AWS_DEFAULT_REGION") {
        stale.extend(["AWS_REGION", "AWS_DEFAULT_REGION"]);
    }
    stale
        .into_iter()
        .filter(|name| !sets(name))
        .map(str::to_string)
        .collect()
}

/// [`child_env`] for this process's `OMNIFOB_VARS`.
fn command_env(profile: &Profile, creds: &Credentials) -> (Vec<String>, Vec<(String, String)>) {
    let previous = std::env::var("OMNIFOB_VARS").unwrap_or_default();
    child_env(profile, creds, &previous)
}

/// The exit code that reports a command's `status`: its own code where it
/// fits in a byte. A larger code (Windows has 32-bit ones) whose low byte is
/// 0 would read as success, so it becomes 1.
fn exit_code(status: std::process::ExitStatus) -> ExitCode {
    #[cfg(unix)]
    if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&status) {
        return ExitCode::from(128 + signal as u8);
    }
    ExitCode::from(code_byte(status.code().unwrap_or(1)))
}

fn code_byte(code: i32) -> u8 {
    match code as u8 {
        0 if code != 0 => 1,
        byte => byte,
    }
}

/// Runs a command to its end and returns its exit status. Ctrl-C reaches the
/// command, not omnifob, so omnifob can clean up after it; `SIGINT`,
/// `SIGHUP` and `SIGTERM` sent to omnifob alone are passed on to it.
pub(crate) async fn run_to_end(
    profile: &Profile,
    creds: &Credentials,
    command: &[String],
    provision: Provision,
) -> anyhow::Result<ExitCode> {
    let (remove, set) = with_provision(command_env(profile, creds), &provision);
    let mut cmd = tokio::process::Command::new(&command[0]);
    cmd.args(&command[1..]);
    for name in &remove {
        cmd.env_remove(name);
    }
    cmd.envs(set);
    // The endpoints serve while the command runs, on this thread, and close
    // with it; the files go when `provision` is dropped at the end.
    let Provision { files, tasks, .. } = provision;
    let mut serving = std::pin::pin!(Provision::run(tasks));
    // The terminal sends Ctrl-C, and a hangup when it closes, to the command
    // too; omnifob waits for the command to end instead of ending first.
    // Listening for them, from before the command starts, keeps them from
    // ending omnifob; those sent to omnifob alone are passed on.
    #[cfg(unix)]
    let (mut interrupt, mut hangup, mut terminate) = {
        use tokio::signal::unix::{SignalKind, signal};
        (
            signal(SignalKind::interrupt())?,
            signal(SignalKind::hangup())?,
            signal(SignalKind::terminate())?,
        )
    };
    #[cfg(windows)]
    let (mut interrupt, mut ctrl_break) = (
        tokio::signal::windows::ctrl_c()?,
        tokio::signal::windows::ctrl_break()?,
    );
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => return Ok(could_not_start(&command[0], &e)),
    };
    let status = loop {
        #[cfg(unix)]
        tokio::select! {
            status = child.wait() => break status?,
            () = &mut serving => {}
            _ = interrupt.recv() => {
                if !terminal_signals_group() {
                    forward(&child, libc::SIGINT);
                }
            }
            _ = hangup.recv() => {
                if !terminal_signals_group() {
                    forward(&child, libc::SIGHUP);
                }
            }
            // Unlike Ctrl-C, nobody else told the command to stop.
            _ = terminate.recv() => forward(&child, libc::SIGTERM),
        }
        #[cfg(windows)]
        tokio::select! {
            status = child.wait() => break status?,
            () = &mut serving => {}
            _ = interrupt.recv() => {}
            _ = ctrl_break.recv() => {}
        }
        #[cfg(not(any(unix, windows)))]
        tokio::select! {
            status = child.wait() => break status?,
            () = &mut serving => {}
        }
    };
    drop(files);
    // Windows exit codes are 32-bit; `main` exits with the whole code once
    // the cleanup after the command (revoking a token) is done.
    #[cfg(windows)]
    if let Some(code) = status.code() {
        let _ = WHOLE_EXIT_CODE.set(code);
    }
    Ok(exit_code(status))
}

/// The command's whole exit code, kept by [`run_to_end`] on Windows, where
/// [`ExitCode`] holds only a byte.
#[cfg(windows)]
pub(crate) static WHOLE_EXIT_CODE: std::sync::OnceLock<i32> = std::sync::OnceLock::new();

/// Sends `signal` to the command, unless it has ended.
#[cfg(unix)]
fn forward(child: &tokio::process::Child, signal: libc::c_int) {
    if let Some(pid) = child.id() {
        // SAFETY: sends a signal to the child, which has not been reaped.
        unsafe { libc::kill(pid as libc::pid_t, signal) };
    }
}

/// Whether a `SIGINT` or `SIGHUP` fob got most likely came from its
/// terminal, which sends it to the whole foreground process group, the
/// command included: fob is in that group. Otherwise (no terminal, as in
/// CI and agents, or fob in the background) someone sent it to fob alone,
/// and fob passes it on.
#[cfg(unix)]
fn terminal_signals_group() -> bool {
    // SAFETY: plain queries of this process and its terminal.
    unsafe {
        let group = libc::getpgrp();
        [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO]
            .into_iter()
            .any(|fd| libc::isatty(fd) == 1 && libc::tcgetpgrp(fd) == group)
    }
}

/// The command's environment with a provisioner's changes: the variables
/// it replaces are removed, also from those the profile sets.
fn with_provision(
    (mut remove, mut set): (Vec<String>, Vec<(String, String)>),
    provision: &Provision,
) -> (Vec<String>, Vec<(String, String)>) {
    set.retain(|(name, _)| !provision.remove.contains(name));
    remove.extend(provision.remove.iter().cloned());
    set.extend(provision.set.iter().cloned());
    remove.retain(|name| !set.iter().any(|(n, _)| n == name));
    remove.sort();
    remove.dedup();
    (remove, set)
}

pub(crate) fn exec(
    profile: &Profile,
    creds: &Credentials,
    command: &[String],
) -> anyhow::Result<ExitCode> {
    let (remove, set) = command_env(profile, creds);
    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]);
    for name in &remove {
        cmd.env_remove(name);
    }
    cmd.envs(set);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        Ok(could_not_start(&command[0], &err))
    }
    #[cfg(not(unix))]
    {
        // Ctrl-C reaches the command, which shares the console; while a
        // handler is registered it does not end fob, which waits for the
        // command and then reports its status.
        #[cfg(windows)]
        let _ignored = (
            tokio::signal::windows::ctrl_c()?,
            tokio::signal::windows::ctrl_break()?,
        );
        let status = match cmd.status() {
            Ok(status) => status,
            Err(e) => return Ok(could_not_start(&command[0], &e)),
        };
        // Windows exit codes are 32-bit; nothing is left to clean up, so
        // pass the command's code on whole.
        #[cfg(windows)]
        if let Some(code) = status.code() {
            std::process::exit(code);
        }
        Ok(exit_code(status))
    }
}

#[cfg(test)]
mod tests {
    use omnifob_core::Target;

    use super::*;

    fn aws_creds(account: Option<&str>) -> Credentials {
        let mut creds = Credentials {
            expires_at: Some("2100-01-01T00:00:00Z".parse().unwrap()),
            ..Default::default()
        };
        for (k, v) in [
            ("AWS_ACCESS_KEY_ID", "ASIAEXAMPLE"),
            ("AWS_SECRET_ACCESS_KEY", "secret"),
            ("AWS_SESSION_TOKEN", "token"),
        ] {
            creds.env.insert(k.into(), v.into());
        }
        if let Some(account) = account {
            creds.env.insert("AWS_ACCOUNT_ID".into(), account.into());
        }
        creds
    }

    #[test]
    fn credential_process_output_names_the_account_when_known() {
        let profile = Profile::new(
            "portal",
            "dev",
            "Admin",
            Target::Aws {
                account_id: "111111111111".into(),
                account_name: "Dev".into(),
                role_name: "Admin".into(),
            },
        );
        let output = |creds| {
            let text = creds_output(&profile, &creds, CredsFormat::CredentialProcess).unwrap();
            serde_json::from_str::<serde_json::Value>(&text).unwrap()
        };
        let value = output(aws_creds(Some("111111111111")));
        assert_eq!(value["Version"], 1);
        assert_eq!(value["AccessKeyId"], "ASIAEXAMPLE");
        assert_eq!(value["Expiration"], "2100-01-01T00:00:00Z");
        assert_eq!(value["AccountId"], "111111111111");
        // Optional in the format: left out rather than null.
        let value = output(aws_creds(None));
        assert!(value.get("AccountId").is_none(), "{value}");
    }

    fn profile() -> Profile {
        Profile::new(
            "cf",
            "acct",
            "r2",
            Target::Cloudflare {
                account_id: "a".into(),
                account_name: "acct".into(),
                template: "r2".into(),
            },
        )
    }

    #[test]
    fn the_command_gets_no_stale_variables() {
        // R2's S3 credentials after an AWS profile's `fob use`.
        let mut creds = Credentials::default();
        for (k, v) in [
            ("AWS_ACCESS_KEY_ID", "r2-key"),
            ("AWS_SECRET_ACCESS_KEY", "r2-secret"),
            ("AWS_ENDPOINT_URL_S3", "https://a.r2.cloudflarestorage.com"),
            ("AWS_REGION", "auto"),
            ("CLOUDFLARE_API_TOKEN", "t"),
        ] {
            creds.env.insert(k.into(), v.into());
        }
        let previous = "AWS_ACCESS_KEY_ID,AWS_REGION,AWS_SESSION_TOKEN,GOOGLE_CLOUD_PROJECT";
        let (remove, set) = child_env(&profile(), &creds, previous);
        assert_eq!(
            remove,
            [
                "AWS_ACCOUNT_ID",
                "AWS_CONTAINER_AUTHORIZATION_TOKEN",
                "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
                "AWS_CREDENTIAL_EXPIRATION",
                "AWS_DEFAULT_PROFILE",
                "AWS_DEFAULT_REGION",
                "AWS_PROFILE",
                "AWS_ROLE_ARN",
                "AWS_ROLE_SESSION_NAME",
                "AWS_SECURITY_TOKEN",
                "AWS_SESSION_TOKEN",
                "AWS_WEB_IDENTITY_TOKEN_FILE",
                "GOOGLE_CLOUD_PROJECT",
                "OMNIFOB_EXPIRES_AT",
                "OMNIFOB_VARS",
                "OMNIFOB_VAULT_PASSPHRASE",
            ]
        );
        assert!(set.contains(&("OMNIFOB_PROFILE".into(), "cf/acct/r2".into())));

        // An AWS profile without a Region keeps the user's, but not an R2
        // endpoint, or another source of credentials, left in the shell.
        let creds = aws_creds(Some("111111111111"));
        let (remove, set) = child_env(&profile(), &creds, "");
        assert_eq!(
            remove,
            [
                "AWS_CONTAINER_AUTHORIZATION_TOKEN",
                "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
                "AWS_CREDENTIAL_EXPIRATION",
                "AWS_DEFAULT_PROFILE",
                "AWS_ENDPOINT_URL_S3",
                "AWS_PROFILE",
                "AWS_ROLE_ARN",
                "AWS_ROLE_SESSION_NAME",
                "AWS_SECURITY_TOKEN",
                "AWS_WEB_IDENTITY_TOKEN_FILE",
                "OMNIFOB_VARS",
                "OMNIFOB_VAULT_PASSPHRASE",
            ]
        );
        assert!(set.contains(&("OMNIFOB_EXPIRES_AT".into(), "2100-01-01T00:00:00Z".into())));

        // A token profile leaves AWS variables alone unless `fob use` set them.
        let mut creds = Credentials::default();
        creds.env.insert("MODAL_TOKEN_ID".into(), "m".into());
        let (remove, _) = child_env(&profile(), &creds, "");
        assert_eq!(
            remove,
            [
                "OMNIFOB_EXPIRES_AT",
                "OMNIFOB_VARS",
                "OMNIFOB_VAULT_PASSPHRASE"
            ]
        );
    }

    #[test]
    fn exit_codes_that_would_read_as_success_become_failures() {
        assert_eq!(code_byte(0), 0);
        assert_eq!(code_byte(3), 3);
        assert_eq!(code_byte(256), 1);
        assert_eq!(code_byte(257), 1);
        assert_eq!(code_byte(-1073741510), 0x3a);
        assert_eq!(code_byte(0x1_0000), 1);
    }
}
