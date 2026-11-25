//! An external program that prints credentials (`type = "command"`).
//!
//! The program runs without a shell, with omnifob's environment plus
//! `OMNIFOB_PROFILE` (and `OMNIFOB_TTL_SECONDS` when a lifetime is asked
//! for), the terminal's stdin and stderr, so it can prompt and report, and
//! a time limit. Only its stdout is read, and it never appears in an error
//! message, since it holds the credentials.

use std::collections::BTreeMap;
use std::process::Stdio;

use anyhow::{Context, anyhow, bail};
use jiff::{SignedDuration, Timestamp};
use serde::Deserialize;

use crate::config::{CommandConfig, CommandFormat, TTL_PLACEHOLDER};
use crate::{Credentials, Profile, Result, Target};

/// More output than any credentials take.
const MAX_OUTPUT: usize = 1 << 20;

/// One profile per integration: `<integration>/<account>/<name>`.
pub fn discover(integration: &str, config: &CommandConfig) -> Vec<Profile> {
    let account = config.account.as_deref().unwrap_or("default");
    vec![Profile::new(
        integration,
        account,
        &config.leaf(),
        Target::Command {
            aws: config.format == CommandFormat::CredentialProcess,
        },
    )]
}

pub fn console_url(config: &CommandConfig) -> Option<String> {
    config.console.clone()
}

/// Runs the program; `ttl` is the lifetime to ask it for.
pub async fn credentials(
    integration: &str,
    config: &CommandConfig,
    profile_id: &str,
    ttl: Option<SignedDuration>,
) -> Result<Credentials> {
    let stdout = run(integration, config, profile_id, ttl).await?;
    let program = program_name(config);
    let creds = parse(config, &stdout).map_err(|e| {
        anyhow!("the output of {program} for '{integration}' is not credentials: {e:#}")
    })?;
    if let Some(at) = creds.expires_at
        && at <= Timestamp::now()
    {
        return Err(anyhow!(
            "{program} for '{integration}' printed credentials that expired at {at}"
        )
        .into());
    }
    Ok(creds)
}

/// Runs the program once and says what it printed, without the values.
pub async fn check(integration: &str, config: &CommandConfig) -> Result<String> {
    let id = discover(integration, config)
        .pop()
        .map(|p| p.id)
        .unwrap_or_default();
    let creds = credentials(integration, config, &id, config.ttl).await?;
    let names: Vec<&str> = creds.env.keys().map(String::as_str).collect();
    let expiry = match creds.expires_at {
        Some(at) => format!(", expiring {}", at.strftime("%Y-%m-%d %H:%M UTC")),
        None => ", without an expiry".to_string(),
    };
    Ok(format!(
        "{} printed {}{expiry}",
        program_name(config),
        names.join(", ")
    ))
}

fn program_name(config: &CommandConfig) -> &str {
    config
        .command
        .first()
        .map(String::as_str)
        .unwrap_or_default()
}

/// The program as configured, with `~/` made the home directory.
fn program_path(config: &CommandConfig) -> anyhow::Result<std::path::PathBuf> {
    let program = program_name(config);
    match program.strip_prefix("~/") {
        Some(rest) => Ok(std::env::home_dir()
            .filter(|home| home.is_absolute())
            .context("there is no home directory to find ~/ in")?
            .join(rest)),
        None => Ok(program.into()),
    }
}

async fn run(
    integration: &str,
    config: &CommandConfig,
    profile_id: &str,
    ttl: Option<SignedDuration>,
) -> anyhow::Result<Vec<u8>> {
    let program = program_name(config);
    let seconds = ttl.map(|t| t.as_secs().max(1).to_string());
    let args = config.command[1..].iter().map(|arg| match &seconds {
        Some(s) => arg.replace(TTL_PLACEHOLDER, s),
        None => arg.clone(),
    });
    let mut command = tokio::process::Command::new(program_path(config)?);
    command
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .env("OMNIFOB_PROFILE", profile_id);
    match &seconds {
        Some(s) => command.env("OMNIFOB_TTL_SECONDS", s),
        None => command.env_remove("OMNIFOB_TTL_SECONDS"),
    };
    let child = command.spawn().map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            anyhow!("{program}, the command of '{integration}', was not found")
        }
        _ => anyhow!("running {program} for '{integration}': {e}"),
    })?;
    let timeout = config.timeout();
    let output = tokio::time::timeout(timeout.unsigned_abs(), child.wait_with_output())
        .await
        .map_err(|_| {
            anyhow!(
                "{program} for '{integration}' did not finish within {timeout:#}; it was stopped (raise `timeout` if it needs longer)"
            )
        })?
        .with_context(|| format!("running {program} for '{integration}'"))?;
    if !output.status.success() {
        bail!(
            "{program} for '{integration}' failed ({}); what it said is above",
            output.status
        );
    }
    if output.stdout.len() > MAX_OUTPUT {
        bail!("{program} for '{integration}' printed more than 1 MiB");
    }
    Ok(output.stdout)
}

/// What the program printed as credentials, by `format`. Errors name the
/// place and kind of a problem, never a value.
fn parse(config: &CommandConfig, stdout: &[u8]) -> anyhow::Result<Credentials> {
    let json = |e: serde_json::Error| {
        anyhow!(
            "{} at line {}, column {}",
            match e.classify() {
                serde_json::error::Category::Data => "unexpected keys or types",
                serde_json::error::Category::Eof => "it ends early",
                _ => "not JSON",
            },
            e.line(),
            e.column()
        )
    };
    match config.format {
        CommandFormat::Omnifob => {
            #[derive(Deserialize)]
            struct Output {
                env: BTreeMap<String, String>,
                #[serde(default)]
                expires_at: Option<Timestamp>,
            }
            let output: Output = serde_json::from_slice(stdout).map_err(json)?;
            if output.env.is_empty() {
                bail!("`env` is empty");
            }
            if let Some(name) = output
                .env
                .keys()
                .find(|n| !crate::credentials::is_var_name(n))
            {
                bail!("`env` has '{name}', which is not an environment variable name");
            }
            Ok(Credentials {
                env: output.env,
                expires_at: output.expires_at,
                ..Default::default()
            })
        }
        CommandFormat::CredentialProcess => {
            #[derive(Deserialize)]
            #[serde(rename_all = "PascalCase")]
            struct Output {
                version: u32,
                access_key_id: String,
                secret_access_key: String,
                #[serde(default)]
                session_token: Option<String>,
                #[serde(default)]
                expiration: Option<Timestamp>,
                #[serde(default)]
                account_id: Option<String>,
            }
            let output: Output = serde_json::from_slice(stdout).map_err(json)?;
            if output.version != 1 {
                bail!("credential_process Version {} is not 1", output.version);
            }
            if output.access_key_id.is_empty() || output.secret_access_key.is_empty() {
                bail!("AccessKeyId and SecretAccessKey must not be empty");
            }
            let mut env = BTreeMap::new();
            env.insert("AWS_ACCESS_KEY_ID".to_string(), output.access_key_id);
            env.insert(
                "AWS_SECRET_ACCESS_KEY".to_string(),
                output.secret_access_key,
            );
            if let Some(token) = output.session_token.filter(|t| !t.is_empty()) {
                env.insert("AWS_SESSION_TOKEN".to_string(), token);
            }
            if let Some(at) = output.expiration {
                env.insert("AWS_CREDENTIAL_EXPIRATION".to_string(), at.to_string());
            }
            if let Some(account) = output.account_id.filter(|a| !a.is_empty()) {
                env.insert("AWS_ACCOUNT_ID".to_string(), account);
            }
            if let Some(region) = &config.region {
                env.insert("AWS_REGION".to_string(), region.clone());
                env.insert("AWS_DEFAULT_REGION".to_string(), region.clone());
            }
            Ok(Credentials {
                env,
                expires_at: output.expiration,
                ..Default::default()
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(format: CommandFormat) -> CommandConfig {
        CommandConfig {
            command: vec!["helper".into()],
            format,
            account: None,
            name: None,
            timeout: None,
            ttl: None,
            region: Some("eu-west-1".into()),
            console: None,
            browser: None,
        }
    }

    #[test]
    fn both_formats_become_variables_and_errors_hide_values() {
        let omnifob = config(CommandFormat::Omnifob);
        let creds = parse(
            &omnifob,
            br#"{"profile":"x","env":{"TOKEN":"t"},"expires_at":"2100-01-01T00:00:00Z"}"#,
        )
        .unwrap();
        assert_eq!(creds.env["TOKEN"], "t");
        assert_eq!(
            creds.expires_at.unwrap().to_string(),
            "2100-01-01T00:00:00Z"
        );
        assert!(
            parse(&omnifob, br#"{"env":{"TOKEN":"t"}}"#)
                .unwrap()
                .expires_at
                .is_none()
        );
        for (out, message) in [
            (&br#"{"env":{}}"#[..], "`env` is empty"),
            (
                br#"{"env":{"A-B":"x"}}"#,
                "not an environment variable name",
            ),
            (
                br#"{"env":{"A":"hunter2-secret"},"expires_at":"hunter2-secret"}"#,
                "unexpected keys or types",
            ),
            (br#"{"env":{"A":"#, "ends early"),
            (b"hunter2-secret", "not JSON"),
        ] {
            let error = format!("{:#}", parse(&omnifob, out).unwrap_err());
            assert!(error.contains(message), "{error}");
            assert!(!error.contains("hunter2"), "{error}");
        }

        let process = config(CommandFormat::CredentialProcess);
        let creds = parse(
            &process,
            br#"{"Version":1,"AccessKeyId":"ASIA1","SecretAccessKey":"s","SessionToken":"t","Expiration":"2100-01-01T00:00:00Z","AccountId":"123456789012"}"#,
        )
        .unwrap();
        let names: Vec<&str> = creds.env.keys().map(String::as_str).collect();
        assert_eq!(
            names,
            [
                "AWS_ACCESS_KEY_ID",
                "AWS_ACCOUNT_ID",
                "AWS_CREDENTIAL_EXPIRATION",
                "AWS_DEFAULT_REGION",
                "AWS_REGION",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN"
            ]
        );
        assert!(creds.expires_at.is_some());
        let long_lived = parse(
            &process,
            br#"{"Version":1,"AccessKeyId":"AKIA1","SecretAccessKey":"s"}"#,
        )
        .unwrap();
        assert!(
            long_lived.expires_at.is_none() && !long_lived.env.contains_key("AWS_SESSION_TOKEN")
        );
        let error = parse(
            &process,
            br#"{"Version":2,"AccessKeyId":"a","SecretAccessKey":"s"}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("Version 2 is not 1"), "{error}");
    }
}
