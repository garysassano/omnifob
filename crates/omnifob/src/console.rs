//! `fob console`: open the provider's web console as a profile.

use anyhow::{Context, bail};
use omnifob_core::providers;

use crate::{App, clipboard, record_use};

/// What `fob console` does with the sign-in URL.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Open,
    Print,
    Copy,
}

impl App {
    pub(crate) async fn console(
        &mut self,
        query: Option<&str>,
        action: Action,
        options: &providers::ConsoleOptions,
    ) -> anyhow::Result<()> {
        let profile = self.select(query).await?;
        // The URL signs in as the profile: a credential like any other.
        // Over SSH, copying writes it to the terminal, which an agent reads.
        if crate::agent::active()
            && (action == Action::Print || (action == Action::Copy && clipboard::over_ssh()))
        {
            bail!(
                "not printing the console sign-in URL into an agent's output; `fob console {}` opens it in the user's browser",
                profile.id
            );
        }
        providers::check_console_options(&self.config, &profile, options)?;
        // New credentials, not cached ones: without a session length the
        // console signs out when they expire, and cached ones are handed
        // out until minutes before that.
        let creds = self
            .with_login(|| providers::console_credentials(&self.config, &profile))
            .await
            .with_context(|| format!("getting credentials for {}", profile.id))?;
        let url = providers::console_url(&self.config, &profile, &creds, options).await?;
        record_use(&profile.id);
        let via = match action {
            Action::Open => "console",
            Action::Print => "console-url",
            Action::Copy => "console-url-copied",
        };
        self.audit(&profile, via, creds.expires_at, None);
        match action {
            Action::Print => println!("{url}"),
            Action::Copy => {
                let place = clipboard::write(&url)?;
                eprintln!(
                    "fob: copied the console sign-in URL for {} {place}",
                    profile.id
                );
            }
            Action::Open => {
                crate::browser::open_console(&self.config, &profile, &url)
                    .context("opening the browser; use --print or --copy to get the URL")?;
                eprintln!("fob: opened the console for {}", profile.id);
            }
        }
        Ok(())
    }
}
