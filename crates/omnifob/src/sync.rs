//! `fob sync` and `fob list`, and picking a profile for the commands that use
//! one (`fob exec`, `fob use` and the rest).

use anyhow::{Context, bail};
use dialoguer::console::Term;
use jiff::Timestamp;
use omnifob_core::history::{self, History};
use omnifob_core::profile::SyncedProfiles;
use omnifob_core::{Error, Integration, Profile, paths, providers};

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
                paths::config_file()?.display()
            );
        }
        let integrations = names
            .iter()
            .map(|name| Ok((name.clone(), self.config.integration(name)?.clone())))
            .collect::<anyhow::Result<Vec<(String, Integration)>>>()?;
        let before: Vec<Profile> = self
            .cache
            .integrations
            .values()
            .flat_map(|synced| synced.profiles.iter().cloned())
            .collect();
        // Every integration is discovered at once. The ones that need a new
        // sign-in then sign in one at a time, since each may open a browser
        // or ask in the terminal.
        let discovered = futures::future::join_all(
            integrations
                .iter()
                .map(|(name, integration)| providers::discover(name, integration)),
        )
        .await;
        let mut failures: Vec<(String, anyhow::Error)> = Vec::new();
        for ((name, integration), result) in integrations.iter().zip(discovered) {
            let result = match result {
                Err(Error::NeedsLogin {
                    integration: login,
                    reason,
                }) if interactive() => match self.sign_in_again(&login, &reason).await {
                    Ok(()) => providers::discover(name, integration)
                        .await
                        .map_err(anyhow::Error::from),
                    Err(e) => Err(e),
                },
                other => other.map_err(anyhow::Error::from),
            };
            match result {
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
                Err(e) => failures.push((name.clone(), e)),
            }
        }
        // Drop profiles of integrations removed from the config.
        self.cache
            .integrations
            .retain(|name, _| self.config.integrations.contains_key(name));
        self.cache.save(&profiles_file()?)?;
        // Profiles that went away leave no cached credentials behind.
        providers::forget_removed_credentials(
            &before,
            self.cache.integrations.values().flat_map(|s| &s.profiles),
        );
        // The integrations that synced are saved; the others keep their old
        // profiles and are reported last, so none of them scrolls away.
        match failures.as_slice() {
            [] => Ok(()),
            [(name, e)] => Err(anyhow::anyhow!("syncing '{name}': {e:#}")),
            _ => {
                for (name, e) in &failures {
                    eprintln!("fob: syncing '{name}': {e:#}");
                }
                bail!(
                    "{} of {} integrations did not sync",
                    failures.len(),
                    integrations.len()
                )
            }
        }
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
        let integrations = missing
            .iter()
            .map(|name| self.config.integration(name))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let discovered = futures::future::join_all(
            missing
                .iter()
                .zip(&integrations)
                .map(|(name, integration)| providers::discover(name, integration)),
        )
        .await;
        for (name, result) in missing.iter().zip(discovered) {
            match result {
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
        self.cache.save(&profiles_file()?)?;
        Ok(skipped)
    }

    pub(crate) async fn list(&mut self, query: Option<&str>, json: bool) -> anyhow::Result<()> {
        self.ensure_synced().await?.report();
        let profiles: Vec<&Profile> = match query {
            Some(q) => self.cache.find(q),
            None => self.cache.all().collect(),
        };
        // An agent sees every profile, so it can tell the user which one to
        // open to it, but the ones `[agent] profiles` keeps from it are
        // marked, so it does not try them.
        let marks = agent::active() && self.config.agent.profiles.is_some();
        let closed = |p: &Profile| marks && !self.config.agent.allows(&p.id);
        if json {
            let rows = profiles
                .iter()
                .map(|p| {
                    let mut row = serde_json::to_value(p)?;
                    if marks {
                        row["open_to_agents"] = (!closed(p)).into();
                    }
                    Ok(row)
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            println!("{}", serde_json::to_string_pretty(&rows)?);
        } else {
            for profile in profiles {
                if closed(profile) {
                    println!("{} (not open to agents)", profile.id);
                } else {
                    println!("{}", profile.id);
                }
            }
        }
        Ok(())
    }

    /// Resolves a profile query, asking the user to pick when it is missing
    /// or ambiguous and a terminal is available. Under an agent the query must
    /// be a full profile id that `[agent] profiles` allows, so a command does
    /// what it says and permission rules can match it; `--account-id` and
    /// `--role` count when they name one profile.
    pub(crate) async fn select<'a>(
        &mut self,
        pick: impl Into<Pick<'a>>,
    ) -> anyhow::Result<Profile> {
        let pick = pick.into();
        let skipped = self.ensure_synced().await?;
        let mut query = pick.query;
        let mut from_directory = None;
        if query.is_none() && !pick.by_account() && pick.directory_default {
            from_directory = self.directory_default()?;
            if let Some((dir, id)) = &from_directory {
                if agent::active() {
                    bail!(
                        "name a profile by its full id; this directory's default ({dir}) is {id}"
                    );
                }
                if !self.cache.all().any(|p| p.id == *id) {
                    bail!(
                        "{id}, the default profile of {dir} in [directories], is not a profile; see `fob list`"
                    );
                }
            }
        }
        if let Some((_, id)) = &from_directory {
            query = Some(id.as_str());
        }
        let mut candidates: Vec<&Profile> = match query {
            Some(q) => self.cache.find(q),
            None => self.cache.all().filter(|p| pick.matches(p)).collect(),
        };
        let precise = pick.by_account() && candidates.len() == 1;
        let query_text = if pick.by_account() {
            Some(pick.describe())
        } else {
            query.map(str::to_string)
        };
        let query = query_text.as_deref();
        // Recently used profiles first, in the picker and in error messages.
        History::load(&history::file()?).sort_recent_first(&mut candidates, |p| p.id.as_str());
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
            [one] if !agent::active() || precise || query == Some(one.id.as_str()) => {
                (*one).clone()
            }
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

impl App {
    /// The `[directories]` entry for the working directory: the directory
    /// as configured and its profile id.
    fn directory_default(&self) -> anyhow::Result<Option<(String, String)>> {
        if self.config.directories.is_empty() {
            return Ok(None);
        }
        let cwd = std::env::current_dir().context("reading the working directory")?;
        Ok(self
            .config
            .directory_profile(&cwd, std::env::home_dir().as_deref())
            .map(|(dir, id)| (dir.to_string(), id.to_string())))
    }
}

/// How a command names its profile: words of its id, or the account and
/// role, or nothing (a directory's default when the command takes one, else
/// the picker).
#[derive(Default)]
pub(crate) struct Pick<'a> {
    pub(crate) query: Option<&'a str>,
    pub(crate) account_id: Option<&'a str>,
    pub(crate) role: Option<&'a str>,
    /// Whether, with nothing named, `[directories]` gives the profile.
    pub(crate) directory_default: bool,
}

impl<'a> From<Option<&'a str>> for Pick<'a> {
    fn from(query: Option<&'a str>) -> Self {
        Self {
            query,
            ..Self::default()
        }
    }
}

impl Pick<'_> {
    fn by_account(&self) -> bool {
        self.account_id.is_some() || self.role.is_some()
    }

    /// Whether `profile` is in the account and has the role asked for. The
    /// account is the provider's (AWS account, Azure subscription, Google
    /// project, Cloudflare account); the role is the last part of the id (a
    /// role, a Cloudflare template), ignoring case.
    fn matches(&self, profile: &Profile) -> bool {
        let account = self.account_id.is_none_or(|wanted| {
            profile
                .target
                .account_id()
                .is_some_and(|id| id.eq_ignore_ascii_case(wanted.trim()))
        });
        let role = self.role.is_none_or(|wanted| {
            let leaf = profile.id.rsplit('/').next().unwrap_or_default();
            let role_name = match &profile.target {
                omnifob_core::Target::Aws { role_name, .. } => role_name.as_str(),
                _ => leaf,
            };
            leaf.eq_ignore_ascii_case(wanted) || role_name.eq_ignore_ascii_case(wanted)
        });
        account && role
    }

    /// The account and role asked for, for messages.
    fn describe(&self) -> String {
        match (self.account_id, self.role) {
            (Some(account), Some(role)) => format!("--account-id {account} --role {role}"),
            (Some(account), None) => format!("--account-id {account}"),
            (None, Some(role)) => format!("--role {role}"),
            (None, None) => String::new(),
        }
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
