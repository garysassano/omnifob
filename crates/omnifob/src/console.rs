//! `fob console`: open the provider's web console as a profile.

use anyhow::{Context, bail};
use omnifob_core::providers;

use crate::{App, record_use};

impl App {
    pub(crate) async fn console(
        &mut self,
        query: Option<&str>,
        print: bool,
        options: &providers::ConsoleOptions,
    ) -> anyhow::Result<()> {
        let profile = self.select(query).await?;
        // The URL signs in as the profile: a credential like any other.
        if print && crate::agent::active() {
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
        if print {
            println!("{url}");
        } else {
            crate::browser::open_console(&self.config, &profile, &url)
                .context("opening the browser; use --print to get the URL")?;
            eprintln!("fob: opened the console for {}", profile.id);
        }
        Ok(())
    }
}
