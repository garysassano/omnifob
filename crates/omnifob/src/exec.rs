//! `fob exec`, `fob creds`, `fob env` and `fob revoke`: getting a profile's
//! credentials and handing them to a command, another tool or the shell.

use std::process::ExitCode;

use anyhow::Context;
use jiff::Timestamp;
use omnifob_core::providers;
use omnifob_core::{Credentials, Profile};

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

impl App {
    pub(crate) async fn credentials(
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
    pub(crate) async fn exec_and_revoke(
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

/// Runs a command to its end and returns its exit status. Ctrl-C reaches the
/// command, not omnifob, so omnifob can clean up after it.
pub(crate) async fn run_to_end(
    profile: &Profile,
    creds: &Credentials,
    command: &[String],
) -> anyhow::Result<ExitCode> {
    let mut child = match tokio::process::Command::new(&command[0])
        .args(&command[1..])
        .envs(&creds.env)
        .env("OMNIFOB_PROFILE", &profile.id)
        .spawn()
    {
        Ok(child) => child,
        Err(e) => return Ok(could_not_start(&command[0], &e)),
    };
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

pub(crate) fn exec(
    profile: &Profile,
    creds: &Credentials,
    command: &[String],
) -> anyhow::Result<ExitCode> {
    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..])
        .envs(&creds.env)
        .env("OMNIFOB_PROFILE", &profile.id);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        Ok(could_not_start(&command[0], &err))
    }
    #[cfg(not(unix))]
    {
        let status = match cmd.status() {
            Ok(status) => status,
            Err(e) => return Ok(could_not_start(&command[0], &e)),
        };
        Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
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
}
