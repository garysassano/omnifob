//! `fob status` and `fob check`: what is configured and whether it works.

use std::process::ExitCode;

use anyhow::bail;
use jiff::Timestamp;
use omnifob_core::providers::{self, SignIn, azure, gcp};
use omnifob_core::{Integration, paths};

use crate::App;

impl App {
    /// Checks every integration's sign-in, or one profile's credentials.
    pub(crate) async fn check(
        &mut self,
        query: Option<&str>,
        quiet: bool,
    ) -> anyhow::Result<ExitCode> {
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
            // All at once, reported in config order.
            let results = futures::future::join_all(
                self.config
                    .integrations
                    .iter()
                    .map(|(name, integration)| providers::check_sign_in(name, integration)),
            )
            .await;
            for (name, result) in self.config.integrations.keys().zip(results) {
                match result {
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

    pub(crate) fn status(&self) -> anyhow::Result<()> {
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
                SignIn::Token if matches!(integration, Integration::AwsIam(_)) => {
                    "signed in (access key)".to_string()
                }
                SignIn::Token
                    if matches!(integration, Integration::Gcp(_) | Integration::Azure(_)) =>
                {
                    let account = match integration {
                        Integration::Gcp(_) => gcp::account(name)?,
                        _ => azure::account(name)?,
                    };
                    match account {
                        Some(email) => format!("signed in as {email}, renews automatically"),
                        None => "signed in".to_string(),
                    }
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
}
