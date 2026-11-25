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
            spawn_renewal(&self.config, profile);
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

/// Variables fob puts into AWS profiles' environments. When a profile hands
/// out an access key, the ones among these it does not set are removed from
/// the command's environment, so a session token, account or S3 endpoint
/// left in the shell (by `fob use`, another tool or by hand) is not mixed
/// with the new key. Region variables are not here: see [`child_env`].
const AWS_CREDENTIAL_VARS: &[&str] = &[
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    // The older name of AWS_SESSION_TOKEN, which botocore still reads.
    "AWS_SECURITY_TOKEN",
    "AWS_CREDENTIAL_EXPIRATION",
    "AWS_ACCOUNT_ID",
    "AWS_ENDPOINT_URL_S3",
];

/// The command's environment: the variables to remove from fob's own
/// environment, and the ones to set.
///
/// Removed are the variables a previous `fob use` set (`previous`, from
/// `OMNIFOB_VARS`) that this profile does not, `OMNIFOB_VARS` itself, and,
/// when the profile hands out an AWS access key, the AWS credential and
/// endpoint variables it does not set. A Region variable is removed only
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
    if sets("AWS_ACCESS_KEY_ID") {
        let mut stale: Vec<&str> = AWS_CREDENTIAL_VARS.to_vec();
        if sets("AWS_REGION") || sets("AWS_DEFAULT_REGION") {
            stale.extend(["AWS_REGION", "AWS_DEFAULT_REGION"]);
        }
        remove.extend(
            stale
                .into_iter()
                .filter(|name| !sets(name))
                .map(str::to_string),
        );
    }
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
/// command, not omnifob, so omnifob can clean up after it.
pub(crate) async fn run_to_end(
    profile: &Profile,
    creds: &Credentials,
    command: &[String],
) -> anyhow::Result<ExitCode> {
    let (remove, set) = command_env(profile, creds);
    let mut cmd = tokio::process::Command::new(&command[0]);
    cmd.args(&command[1..]);
    for name in &remove {
        cmd.env_remove(name);
    }
    cmd.envs(set);
    // The terminal sends Ctrl-C, and a hangup when it closes, to the command
    // too; omnifob waits for the command to end instead of ending first.
    // Listening for them, from before the command starts, keeps them from
    // ending omnifob.
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
            _ = interrupt.recv() => {}
            _ = hangup.recv() => {}
            _ = terminate.recv() => {
                // Unlike Ctrl-C, nobody else told the command to stop.
                if let Some(pid) = child.id() {
                    // SAFETY: sends a signal to the child, which has not been reaped.
                    unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
                }
            }
        }
        #[cfg(windows)]
        tokio::select! {
            status = child.wait() => break status?,
            _ = interrupt.recv() => {}
            _ = ctrl_break.recv() => {}
        }
        #[cfg(not(any(unix, windows)))]
        break child.wait().await?;
    };
    Ok(exit_code(status))
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
                "AWS_CREDENTIAL_EXPIRATION",
                "AWS_DEFAULT_REGION",
                "AWS_SECURITY_TOKEN",
                "AWS_SESSION_TOKEN",
                "GOOGLE_CLOUD_PROJECT",
                "OMNIFOB_EXPIRES_AT",
                "OMNIFOB_VARS",
            ]
        );
        assert!(set.contains(&("OMNIFOB_PROFILE".into(), "cf/acct/r2".into())));

        // An AWS profile without a Region keeps the user's, but not an R2
        // endpoint left in the shell.
        let creds = aws_creds(Some("111111111111"));
        let (remove, set) = child_env(&profile(), &creds, "");
        assert_eq!(
            remove,
            [
                "AWS_CREDENTIAL_EXPIRATION",
                "AWS_ENDPOINT_URL_S3",
                "AWS_SECURITY_TOKEN",
                "OMNIFOB_VARS",
            ]
        );
        assert!(set.contains(&("OMNIFOB_EXPIRES_AT".into(), "2100-01-01T00:00:00Z".into())));

        // A token profile leaves AWS variables alone unless `fob use` set them.
        let mut creds = Credentials::default();
        creds.env.insert("MODAL_TOKEN_ID".into(), "m".into());
        let (remove, _) = child_env(&profile(), &creds, "");
        assert_eq!(remove, ["OMNIFOB_EXPIRES_AT", "OMNIFOB_VARS"]);
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
