//! `fob sync` and `fob list`, and picking a profile for the commands that use
//! one (`fob exec`, `fob use` and the rest).

use anyhow::{Context, bail};
use dialoguer::console::Term;
use jiff::Timestamp;
use omnifob_core::history::{self, History};
use omnifob_core::profile::SyncedProfiles;
use omnifob_core::{Error, Profile, paths, providers};

use crate::{App, agent, interactive, profiles_file};

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
    /// be synced (not signed in, offline) is skipped rather than failing a
    /// command that may not need it, and is tried again next time; the
    /// caller decides whether the skips are worth a note.
    pub(crate) async fn ensure_synced(&mut self) -> anyhow::Result<Skipped> {
        let missing: Vec<String> = self
            .config
            .integrations
            .keys()
            .filter(|name| !self.cache.integrations.contains_key(*name))
            .cloned()
            .collect();
        let mut skipped = Skipped::default();
        if missing.is_empty() {
            return Ok(skipped);
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
                Err(Error::NeedsLogin { .. }) => skipped.0.push(format!(
                    "skipping '{name}': not signed in (`fob login {name}`)"
                )),
                Err(e) => skipped.0.push(format!("skipping '{name}': {e:#}")),
            }
        }
        self.cache.save(&profiles_file())?;
        Ok(skipped)
    }

    pub(crate) async fn list(&mut self, query: Option<&str>, json: bool) -> anyhow::Result<()> {
        self.ensure_synced().await?.report();
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
    /// or ambiguous and a terminal is available. Under an agent the query must
    /// be a full profile id that `[agent] profiles` allows, so a command does
    /// what it says and permission rules can match it.
    pub(crate) async fn select(&mut self, query: Option<&str>) -> anyhow::Result<Profile> {
        let skipped = self.ensure_synced().await?;
        let mut candidates: Vec<&Profile> = match query {
            Some(q) => self.cache.find(q),
            None => self.cache.all().collect(),
        };
        // Recently used profiles first, in the picker and in error messages.
        History::load(&history::file()).sort_recent_first(&mut candidates, |p| p.id.as_str());
        if candidates.is_empty() {
            // Only now can a skipped integration be the reason.
            skipped.report();
        }
        let profile = match candidates.as_slice() {
            [] if query.is_some() => bail!(
                "no profile matches '{}'; see `fob list`",
                query.unwrap_or_default()
            ),
            [] => bail!("no profiles yet; run `fob login <integration>`"),
            [one] if !agent::active() || query == Some(one.id.as_str()) => (*one).clone(),
            _ if agent::active() => match query {
                None => bail!("name a profile by its full id; `fob list` shows them"),
                Some(q) => bail!(
                    "name the profile by its full id: '{q}' matches {}",
                    listing(&candidates)
                ),
            },
            _ if !interactive() => match query {
                None => bail!("name a profile; `fob list` shows them"),
                Some(q) => bail!("'{q}' matches {}; name one in full", listing(&candidates)),
            },
            _ => {
                let picked = dialoguer::FuzzySelect::new()
                    .with_prompt("Profile")
                    .items(picker_rows(&candidates))
                    .default(0)
                    .interact_on_opt(&Term::stderr())?
                    .context("no profile selected")?;
                candidates[picked].clone()
            }
        };
        if agent::active() && !self.config.agent.allows(&profile.id) {
            bail!(
                "{} is not open to agents; ask the user to run the command or to give agents access",
                profile.id
            );
        }
        Ok(profile)
    }
}

/// Integrations [`App::ensure_synced`] could not sync, as notes for the user.
#[derive(Default)]
#[must_use]
pub(crate) struct Skipped(Vec<String>);

impl Skipped {
    /// Prints the notes.
    pub(crate) fn report(self) {
        for note in self.0 {
            eprintln!("fob: {note}");
        }
    }
}

/// The picker's rows: the parts of each id (integration, account, role) in
/// aligned columns, then the account ID, so a long list is easy to scan.
/// Typing still filters, and words separated by spaces now match across parts.
fn picker_rows(profiles: &[&Profile]) -> Vec<String> {
    let parts: Vec<Vec<&str>> = profiles.iter().map(|p| p.id.split('/').collect()).collect();
    let columns = parts.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..columns)
        .map(|i| {
            parts
                .iter()
                .filter_map(|p| p.get(i))
                .map(|part| part.chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    profiles
        .iter()
        .zip(&parts)
        .map(|(profile, parts)| {
            let mut row = String::new();
            for (i, width) in widths.iter().enumerate() {
                let part = parts.get(i).copied().unwrap_or_default();
                row.push_str(&format!("{part:width$}  "));
            }
            row.push_str(profile.target.account_id().unwrap_or_default());
            row.trim_end().to_string()
        })
        .collect()
}

/// "3 profiles: a, b, c", up to ten ids, then how many more.
fn listing(profiles: &[&Profile]) -> String {
    const SHOWN: usize = 10;
    let ids: Vec<&str> = profiles.iter().take(SHOWN).map(|p| p.id.as_str()).collect();
    let more = profiles.len().saturating_sub(SHOWN);
    let noun = if profiles.len() == 1 {
        "profile"
    } else {
        "profiles"
    };
    let mut text = format!("{} {noun}: {}", profiles.len(), ids.join(", "));
    if more > 0 {
        text.push_str(&format!(", and {more} more"));
    }
    text
}

#[cfg(test)]
mod tests {
    use omnifob_core::profile::Target;

    use super::*;

    fn aws(integration: &str, account: &str, role: &str, account_id: &str) -> Profile {
        Profile::new(
            integration,
            account,
            role,
            Target::Aws {
                account_id: account_id.into(),
                account_name: account.into(),
                role_name: role.into(),
            },
        )
    }

    #[test]
    fn picker_rows_align_the_parts_of_each_id() {
        let a = aws("gary", "management", "AdministratorAccess", "111111111111");
        let b = aws("itvstudios", "am-dev", "itvstudios-pe", "222222222222");
        let token = Profile {
            id: "tok/prod".into(),
            integration: "tok".into(),
            target: Target::Token {},
        };
        assert_eq!(
            picker_rows(&[&a, &b, &token]),
            [
                "gary        management  AdministratorAccess  111111111111",
                "itvstudios  am-dev      itvstudios-pe        222222222222",
                "tok         prod",
            ]
        );
    }
}
