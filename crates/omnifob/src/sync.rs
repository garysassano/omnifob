//! `fob sync` and `fob list`, and picking a profile for the commands that use
//! one (`fob exec`, `fob use` and the rest).

use anyhow::{Context, bail};
use dialoguer::console::Term;
use jiff::Timestamp;
use omnifob_core::history::{self, History};
use omnifob_core::profile::SyncedProfiles;
use omnifob_core::{Error, Profile, paths, providers};

use crate::{App, interactive, profiles_file};

impl App {
    pub(crate) async fn sync(&mut self, names: &[String]) -> anyhow::Result<()> {
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
        let before: Vec<Profile> = self
            .cache
            .integrations
            .values()
            .flat_map(|synced| synced.profiles.iter().cloned())
            .collect();
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
        self.cache.save(&profiles_file())?;
        // Profiles that went away leave no cached credentials behind.
        providers::forget_removed_credentials(
            &before,
            self.cache.integrations.values().flat_map(|s| &s.profiles),
        );
        Ok(())
    }

    /// Discovers the profiles of integrations never synced. One that cannot
    /// be synced (not signed in, offline) is skipped with a note rather than
    /// failing a command that may not need it, and is tried again next time.
    pub(crate) async fn ensure_synced(&mut self) -> anyhow::Result<()> {
        let missing: Vec<String> = self
            .config
            .integrations
            .keys()
            .filter(|name| !self.cache.integrations.contains_key(*name))
            .cloned()
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        for name in &missing {
            let integration = self.config.integration(name)?.clone();
            match providers::discover(name, &integration).await {
                Ok(profiles) => {
                    eprintln!("fob: {name}: {} profiles", profiles.len());
                    self.cache.integrations.insert(
                        name.clone(),
                        SyncedProfiles {
                            synced_at: Timestamp::now(),
                            profiles,
                        },
                    );
                }
                Err(Error::NeedsLogin { .. }) => {
                    eprintln!("fob: skipping '{name}': not signed in (`fob login {name}`)");
                }
                Err(e) => eprintln!("fob: skipping '{name}': {e:#}"),
            }
        }
        self.cache.save(&profiles_file())
    }

    pub(crate) async fn list(&mut self, query: Option<&str>, json: bool) -> anyhow::Result<()> {
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
    pub(crate) async fn select(&mut self, query: Option<&str>) -> anyhow::Result<Profile> {
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
}
