//! `fob status` and `fob check`: what is configured and whether it works.

use std::process::ExitCode;

use anyhow::bail;
use jiff::Timestamp;
use omnifob_core::providers::{self, SignIn, azure, gcp};
use omnifob_core::{Integration, paths};
use serde_json::json;

use crate::App;

/// How `fob check` reports.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Output {
    Text,
    Quiet,
    Json,
}

impl App {
    /// Checks every integration's sign-in (or those named), or one profile's
    /// credentials.
    pub(crate) async fn check(
        &mut self,
        query: Option<&str>,
        integrations: &[String],
        output: Output,
    ) -> anyhow::Result<ExitCode> {
        // (what, is it a profile, the result)
        let mut results: Vec<(String, bool, Result<String, String>)> = Vec::new();
        if let Some(query) = query {
            let profile = self.select(Some(query)).await?;
            let result = providers::check_profile(&self.config, &profile)
                .await
                .map_err(|e| format!("{e:#}"));
            results.push((profile.id, true, result));
        } else {
            if self.config.integrations.is_empty() {
                bail!(
                    "no integrations configured in {}",
                    paths::config_file()?.display()
                );
            }
            let names: Vec<&str> = if integrations.is_empty() {
                self.config
                    .integrations
                    .keys()
                    .map(String::as_str)
                    .collect()
            } else {
                integrations.iter().map(String::as_str).collect()
            };
            let checked = names
                .iter()
                .map(|name| Ok((*name, self.config.integration(name)?)))
                .collect::<anyhow::Result<Vec<_>>>()?;
            // All at once, reported in the order given (config order).
            let outcomes = futures::future::join_all(
                checked
                    .iter()
                    .map(|(name, integration)| providers::check_sign_in(name, integration)),
            )
            .await;
            for ((name, _), result) in checked.iter().zip(outcomes) {
                results.push((
                    name.to_string(),
                    false,
                    result.map_err(|e| format!("{e:#}")),
                ));
            }
        }
        let failed = results.iter().any(|(_, _, r)| r.is_err());
        match output {
            Output::Quiet => {}
            Output::Text => {
                for (what, _, result) in &results {
                    match result {
                        Ok(detail) => println!("ok   {what}: {detail}"),
                        Err(error) => println!("FAIL {what}: {error}"),
                    }
                }
            }
            Output::Json => {
                let rows: Vec<serde_json::Value> = results
                    .iter()
                    .map(|(what, is_profile, result)| {
                        let mut row = json!({
                            "ok": result.is_ok(),
                            "detail": match result {
                                Ok(d) | Err(d) => d,
                            },
                        });
                        row[if *is_profile {
                            "profile"
                        } else {
                            "integration"
                        }] = what.as_str().into();
                        row
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&rows)?);
            }
        }
        Ok(if failed {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        })
    }

    /// What is configured and whether each sign-in is stored; with `check`,
    /// whether each one works, asking the providers as `fob check` does.
    pub(crate) async fn status(&self, json: bool, check: bool) -> anyhow::Result<ExitCode> {
        let now = Timestamp::now();
        let active = active_profile();
        if self.config.integrations.is_empty() && !json {
            println!(
                "No integrations configured in {}",
                paths::config_file()?.display()
            );
            return Ok(ExitCode::SUCCESS);
        }
        let secrets = omnifob_core::store::description()?;
        // Before reading the stored state, which a check may renew.
        let mut checked: Vec<Option<Result<String, String>>> = if check {
            futures::future::join_all(
                self.config
                    .integrations
                    .iter()
                    .map(|(name, integration)| providers::check_sign_in(name, integration)),
            )
            .await
            .into_iter()
            .map(|r| Some(r.map_err(|e| format!("{e:#}"))))
            .collect()
        } else {
            vec![None; self.config.integrations.len()]
        };
        let mut rows = Vec::new();
        for ((name, integration), checked) in self.config.integrations.iter().zip(checked.drain(..))
        {
            let sign_in = providers::sign_in(name, integration)?;
            let account = match (sign_in, integration) {
                (SignIn::Token, Integration::Gcp(_)) => gcp::account(name)?,
                (SignIn::Token, Integration::Azure(_)) => azure::account(name)?,
                _ => None,
            };
            let synced = self.cache.integrations.get(name);
            let state = match &checked {
                Some(Ok(detail)) => format!("works: {detail}"),
                Some(Err(error)) => format!("FAILS: {error}"),
                None => describe(integration, sign_in, account.as_deref(), now),
            };
            rows.push(Row {
                name,
                kind: integration.kind(),
                state,
                sign_in,
                account,
                profiles: synced.map_or(0, |s| s.profiles.len()),
                synced_at: synced.map(|s| s.synced_at),
                checked,
            });
        }
        let skills = crate::skill::installed();
        let failed = rows.iter().any(|row| matches!(row.checked, Some(Err(_))));
        let code = if failed {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        };
        if json {
            let integrations: Vec<serde_json::Value> = rows
                .iter()
                .map(|row| {
                    let (mut signed_in, expires_at, renews) = match row.sign_in {
                        SignIn::SignedOut => (false, None, false),
                        SignIn::Token => (true, None, false),
                        SignIn::Session {
                            expires_at,
                            refreshable,
                        } => (
                            expires_at > now || refreshable,
                            Some(expires_at),
                            refreshable,
                        ),
                    };
                    let mut needs_check = needs_check(row.sign_in, now);
                    if let Some(result) = &row.checked {
                        signed_in = result.is_ok();
                        needs_check = false;
                    }
                    json!({
                        "name": row.name,
                        "type": row.kind,
                        "signed_in": signed_in,
                        "needs_check": needs_check,
                        "expires_at": expires_at,
                        "renews": renews,
                        "account": row.account,
                        "state": row.state,
                        "check": row.checked.as_ref().map(|result| json!({
                            "ok": result.is_ok(),
                            "detail": match result {
                                Ok(d) | Err(d) => d,
                            },
                        })),
                        "profiles": row.profiles,
                        "synced_at": row.synced_at,
                    })
                })
                .collect();
            let skills: Vec<serde_json::Value> = skills
                .iter()
                .map(|copy| {
                    json!({
                        "path": copy.path,
                        "fob_version": copy.version,
                        "current": copy.is_current(),
                    })
                })
                .collect();
            let value = json!({
                "config": paths::config_file()?,
                "secrets": secrets,
                "active_profile": active.as_ref().map(|a| &a.0),
                "active_expires_at": active.as_ref().and_then(|a| a.1),
                "integrations": integrations,
                "skills": skills,
            });
            println!("{}", serde_json::to_string_pretty(&value)?);
            return Ok(code);
        }
        println!("Secrets: {secrets}");
        if let Some((id, expires_at)) = &active {
            let until = match expires_at {
                Some(at) if *at <= now => " (expired)".to_string(),
                Some(at) => format!(" (expires in {})", age(at.duration_since(now))),
                None => String::new(),
            };
            println!("Active in this shell: {id}{until}");
        }
        for problem in skills.iter().filter_map(crate::skill::Copy::problem) {
            println!("Note: {problem}");
        }
        let name_width = rows
            .iter()
            .map(|r| r.name.chars().count())
            .max()
            .unwrap_or(0);
        let kind_width = rows.iter().map(|r| r.kind.len()).max().unwrap_or(0);
        for row in &rows {
            let synced = match row.synced_at {
                Some(at) => format!("synced {} ago", age(now.duration_since(at))),
                None => "not synced".to_string(),
            };
            println!(
                "{:<name_width$}  {:<kind_width$}  {}, {} profiles, {synced}",
                row.name, row.kind, row.state, row.profiles
            );
        }
        if rows
            .iter()
            .any(|row| row.checked.is_none() && needs_check(row.sign_in, now))
        {
            println!(
                "Sign-ins that renew \"if still open\" may have ended since; `fob status --check` asks the providers."
            );
        }
        Ok(code)
    }
}

/// Whether the stored state cannot tell if the sign-in still works: its
/// token expired and renews only while a session fob cannot see lasts.
fn needs_check(sign_in: SignIn, now: Timestamp) -> bool {
    matches!(sign_in, SignIn::Session { expires_at, refreshable: true } if expires_at <= now)
}

struct Row<'a> {
    name: &'a str,
    kind: &'static str,
    state: String,
    sign_in: SignIn,
    account: Option<String>,
    profiles: usize,
    synced_at: Option<Timestamp>,
    /// What `--check` found.
    checked: Option<Result<String, String>>,
}

/// The profile `fob use` made active in this shell, and when its
/// credentials expire.
fn active_profile() -> Option<(String, Option<Timestamp>)> {
    let id = std::env::var("OMNIFOB_PROFILE")
        .ok()
        .filter(|v| !v.is_empty())?;
    let expires_at = std::env::var("OMNIFOB_EXPIRES_AT")
        .ok()
        .and_then(|v| v.parse().ok());
    Some((id, expires_at))
}

/// A sign-in's state in words.
fn describe(
    integration: &Integration,
    sign_in: SignIn,
    account: Option<&str>,
    now: Timestamp,
) -> String {
    match sign_in {
        SignIn::SignedOut => "signed out".to_string(),
        SignIn::Token => match integration {
            Integration::Cloudflare(_) => "signed in (bootstrap token)".to_string(),
            Integration::AwsIam(_) => "signed in (access key)".to_string(),
            Integration::Command(_) => "runs a program; nothing stored".to_string(),
            Integration::Gcp(_) | Integration::Azure(_) => match account {
                Some(email) => format!("signed in as {email}, renews automatically"),
                None => "signed in".to_string(),
            },
            _ => "signed in (stored token)".to_string(),
        },
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
            expires_at,
            refreshable: true,
        } => {
            let session = match integration {
                Integration::AwsSso(_) => "the portal session",
                Integration::AwsLogin(_) => "the console sign-in",
                Integration::Cloudflare(_) => "the browser sign-in",
                _ => "the sign-in",
            };
            // Saying "signed in" here misled: the portal session usually
            // ends after 8 hours, and only the provider knows whether it has.
            format!(
                "token expired {} ago; renews on next use if {session} is still open",
                age(now.duration_since(expires_at))
            )
        }
        SignIn::Session { .. } => "session expired".to_string(),
    }
}

/// A duration in its largest whole unit: "40s", "5m", "3h", "2d".
fn age(d: jiff::SignedDuration) -> String {
    let secs = d.as_secs().max(0);
    match secs {
        0..60 => format!("{secs}s"),
        60..3600 => format!("{}m", secs / 60),
        3600..86400 => format!("{}h", secs / 3600),
        _ => format!("{}d", secs / 86400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ages_use_their_largest_unit() {
        let s = jiff::SignedDuration::from_secs;
        assert_eq!(age(s(-5)), "0s");
        assert_eq!(age(s(59)), "59s");
        assert_eq!(age(s(61)), "1m");
        assert_eq!(age(s(3 * 3600 + 5)), "3h");
        assert_eq!(age(s(2 * 86400 + 7)), "2d");
    }
}
