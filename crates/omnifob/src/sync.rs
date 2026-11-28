//! `fob sync` and `fob list`, and picking a profile for the commands that use
//! one (`fob exec`, `fob use` and the rest).

use std::collections::HashMap;
use std::io::IsTerminal;

use anyhow::{Context, bail};
use dialoguer::console::{Term, style};
use jiff::Timestamp;
use omnifob_core::history::{self, History};
use omnifob_core::profile::SyncedProfiles;
use omnifob_core::{Code, Coded, Error, Integration, Profile, Target, labels, paths, providers};

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
        let discovered = futures_util::future::join_all(
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
                    eprintln!("fob: {name}: {}", crate::profiles_count(profiles.len()));
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
        if failures.len() == 1 {
            // As context, so a needed login or a locked vault keeps its code.
            let (name, e) = failures.remove(0);
            return Err(e.context(format!("syncing '{name}'")));
        }
        match failures.as_slice() {
            [] => Ok(()),
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
        let discovered = futures_util::future::join_all(
            missing
                .iter()
                .zip(&integrations)
                .map(|(name, integration)| providers::discover(name, integration)),
        )
        .await;
        for (name, result) in missing.iter().zip(discovered) {
            match result {
                Ok(profiles) => {
                    eprintln!("fob: {name}: {}", crate::profiles_count(profiles.len()));
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

    pub(crate) async fn list(
        &mut self,
        query: Option<&str>,
        json: bool,
        account: Option<&str>,
    ) -> anyhow::Result<()> {
        self.ensure_synced().await?.report();
        // The skill has agents start here, so an out-of-date copy of it,
        // which teaches commands and messages that changed, is noticed.
        if agent::active() {
            for problem in crate::skill::installed()
                .iter()
                .filter_map(crate::skill::Copy::problem)
            {
                eprintln!("fob: {problem}");
            }
        }
        let mut profiles: Vec<&Profile> = match query {
            Some(q) => self.cache.find(q),
            None => self.cache.all().collect(),
        };
        if let Some(account) = account {
            let account = self.account_of(account)?;
            profiles.retain(|p| p.target.account_id() == Some(account.as_str()));
            // Least access first, so the next role up follows the one
            // denied. A profile without a label may be anything, so it
            // comes last rather than first.
            let rank = |p: &&Profile| match labels::of(&self.config, p).access {
                Some((a, _)) => (false, Some(a)),
                None => (true, None),
            };
            profiles.sort_by_key(|p| rank(p));
        }
        let via = |p: &Profile| self.via_profile(p);
        // An agent sees every profile, so it can tell the user which one to
        // open to it, but the ones `[agent] profiles` keeps from it are
        // marked, so it does not try them.
        let marks = agent::active() && self.config.agent.profiles.is_some();
        let closed = |p: &Profile| marks && !self.config.agent.allows(&p.id);
        // Each integration's sign-in, read once.
        let mut sign_ins: HashMap<&str, SignInState> = HashMap::new();
        for profile in &profiles {
            sign_ins
                .entry(profile.integration.as_str())
                .or_insert_with(|| sign_in_state(&self.config, &profile.integration));
        }
        if json {
            let rows = profiles
                .iter()
                .map(|p| {
                    let mut row = serde_json::to_value(p)?;
                    let found = labels::of(&self.config, p);
                    row["env"] = found.env.as_ref().map(|(env, _)| env.as_str()).into();
                    row["env_source"] = found.env.as_ref().map(|(_, s)| s.as_str()).into();
                    row["access"] = found.access.map(|(a, _)| a.as_str()).into();
                    row["access_source"] = found.access.map(|(_, s)| s.as_str()).into();
                    row["sign_in"] = sign_ins[p.integration.as_str()].as_str().into();
                    if let Some(via) = via(p) {
                        row["via"] = via.into();
                    }
                    if marks {
                        row["open_to_agents"] = (!closed(p)).into();
                    }
                    Ok(row)
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            println!("{}", serde_json::to_string_pretty(&rows)?);
            return Ok(());
        }
        // Plain ids for scripts (`fob list | fzf`); labels and notes for
        // people at a terminal and for agents.
        if !std::io::stdout().is_terminal() && !agent::active() {
            for profile in profiles {
                println!("{}", profile.id);
            }
            return Ok(());
        }
        let mut guessed = false;
        let rows: Vec<[String; 4]> = profiles
            .iter()
            .map(|p| {
                let found = labels::of(&self.config, p);
                let mut mark = |source: labels::Source| {
                    if source == labels::Source::Name {
                        guessed = true;
                        "?"
                    } else {
                        ""
                    }
                };
                let env = found
                    .env
                    .as_ref()
                    .map(|(env, source)| format!("{env}{}", mark(*source)))
                    .unwrap_or_default();
                let access = found
                    .access
                    .map(|(access, source)| format!("{}{}", access.as_str(), mark(source)))
                    .unwrap_or_default();
                let mut notes = Vec::new();
                match sign_ins[p.integration.as_str()] {
                    SignInState::SignedIn => {}
                    state => notes.push(state.describe().to_string()),
                }
                if closed(p) {
                    notes.push("not open to agents".to_string());
                }
                if let Some(via) = via(p) {
                    notes.push(format!("via {via}"));
                }
                let notes = if notes.is_empty() {
                    String::new()
                } else {
                    format!("({})", notes.join(", "))
                };
                [p.id.clone(), env, access, notes]
            })
            .collect();
        let widths: Vec<usize> = (0..4)
            .map(|i| rows.iter().map(|r| r[i].chars().count()).max().unwrap_or(0))
            .collect();
        for row in &rows {
            let mut line = String::new();
            for (i, cell) in row.iter().enumerate() {
                // Columns no profile has are left out.
                if widths[i] == 0 {
                    continue;
                }
                let padded = format!("{cell:width$}  ", width = widths[i]);
                let styled = match i {
                    1 if is_production(cell) => style(padded).red().bold().to_string(),
                    3 => style(padded).dim().to_string(),
                    _ => padded,
                };
                line.push_str(&styled);
            }
            println!("{}", line.trim_end());
        }
        if guessed {
            eprintln!(
                "fob: ? marks a guess from the profile's name; [[labels]] in the config states them"
            );
        }
        Ok(())
    }

    /// The account `account` names for `fob list --account`: itself when a
    /// profile acts in it, else the account of the one profile it matches.
    fn account_of(&self, account: &str) -> anyhow::Result<String> {
        if self
            .cache
            .all()
            .any(|p| p.target.account_id() == Some(account))
        {
            return Ok(account.to_string());
        }
        let found = self.cache.find(account);
        match found.as_slice() {
            [profile] => profile
                .target
                .account_id()
                .map(str::to_string)
                .with_context(|| format!("{} has no account", profile.id)),
            [] => Err(Coded::new(
                Code::ProfileNotFound,
                format!("no profile or account matches '{account}'; see `fob list`"),
            )
            .with("query", account)
            .into()),
            many => Err(Coded::new(
                Code::ProfileAmbiguous,
                format!(
                    "'{account}' matches {} profiles; give an account ID or a full profile id",
                    many.len()
                ),
            )
            .with("query", account)
            .with("candidates", candidate_ids(many))
            .into()),
        }
    }

    /// The id of the profile a chained or cross-partition profile is
    /// reached from, when that Identity Center role is a profile too.
    fn via_profile(&self, profile: &Profile) -> Option<String> {
        let (via_account, via_role) = providers::via_role(&self.config, profile)?;
        self.cache
            .all()
            .find(|p| {
                p.integration == profile.integration
                    && matches!(&p.target, Target::Aws { account_id, role_name, .. }
                        if *account_id == via_account && *role_name == via_role)
            })
            .map(|p| p.id.clone())
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
                // A default that is gone, or kept from agents, says so before
                // an agent is asked to name it.
                if !self.cache.all().any(|p| p.id == *id) {
                    return Err(Coded::new(
                        Code::ProfileNotFound,
                        format!(
                            "{id}, the default profile of {dir} in [directories], is not a profile; see `fob list`"
                        ),
                    )
                    .with("query", id.as_str())
                    .into());
                }
                if agent::active() && !self.config.agent.allows(id) {
                    return Err(Coded::new(
                        Code::NotOpenToAgents,
                        format!(
                            "{id}, this directory's default ({dir}), is not open to agents; ask the user to run the command or to give agents access"
                        ),
                    )
                    .with("profile", id.as_str())
                    .into());
                }
                if agent::active() {
                    return Err(Coded::new(
                        Code::ProfileAmbiguous,
                        format!(
                            "name a profile by its full id; this directory's default ({dir}) is {id}"
                        ),
                    )
                    .with("matches", 1)
                    .with("candidates", vec![id.clone()])
                    .into());
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
        // The failure for a query that names no single profile, with the
        // candidates a caller can choose from.
        let ambiguous = |message: String| -> anyhow::Error {
            let mut error = Coded::new(Code::ProfileAmbiguous, message)
                .with("matches", candidates.len())
                .with("candidates", candidate_ids(&candidates));
            if let Some(q) = query {
                error = error.with("query", q);
            }
            error.into()
        };
        let profile = match candidates.as_slice() {
            [] if query.is_some() => {
                let q = query.unwrap_or_default();
                return Err(Coded::new(
                    Code::ProfileNotFound,
                    format!("no profile matches '{q}'; see `fob list`"),
                )
                .with("query", q)
                .into());
            }
            [] => {
                return Err(Coded::new(
                    Code::ProfileNotFound,
                    "no profiles yet; run `fob login <integration>`",
                )
                .into());
            }
            [one] if !agent::active() || precise || query == Some(one.id.as_str()) => {
                (*one).clone()
            }
            _ if agent::active() => {
                return Err(ambiguous(match query {
                    None => "name a profile by its full id; `fob list` shows them".to_string(),
                    Some(q) => format!(
                        "name the profile by its full id: '{q}' matches {}",
                        listing(&candidates)
                    ),
                }));
            }
            _ if !interactive() => {
                return Err(ambiguous(match query {
                    None => "name a profile; `fob list` shows them".to_string(),
                    Some(q) => format!("'{q}' matches {}; name one in full", listing(&candidates)),
                }));
            }
            _ => {
                let mut sign_ins: HashMap<&str, SignInState> = HashMap::new();
                for profile in &candidates {
                    sign_ins
                        .entry(profile.integration.as_str())
                        .or_insert_with(|| sign_in_state(&self.config, &profile.integration));
                }
                let details = |p: &Profile| {
                    let found = labels::of(&self.config, p);
                    let mut cells = Vec::new();
                    if let Some((env, _)) = &found.env {
                        cells.push(env.clone());
                    }
                    if let Some((access, _)) = found.access {
                        cells.push(access.as_str().to_string());
                    }
                    let mut notes = Vec::new();
                    match sign_ins[p.integration.as_str()] {
                        SignInState::SignedIn => {}
                        state => notes.push(state.describe().to_string()),
                    }
                    if let Some(via) = self.via_profile(p) {
                        notes.push(format!("via {via}"));
                    }
                    if !notes.is_empty() {
                        cells.push(format!("({})", notes.join(", ")));
                    }
                    cells.join("  ")
                };
                let picked = dialoguer::FuzzySelect::new()
                    .with_prompt("Profile")
                    .items(picker_rows(&candidates, details))
                    .default(0)
                    .interact_on_opt(&Term::stderr())?
                    .context("no profile selected")?;
                candidates[picked].clone()
            }
        };
        if agent::active() && !self.config.agent.allows(&profile.id) {
            return Err(Coded::new(
                Code::NotOpenToAgents,
                format!(
                    "{} is not open to agents; ask the user to run the command or to give agents access",
                    profile.id
                ),
            )
            .with("profile", profile.id.as_str())
            .into());
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

/// Whether an integration's sign-in can give credentials, as `fob list`
/// reports it for each profile.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SignInState {
    SignedIn,
    /// The token expired and renews only while a session fob cannot see
    /// lasts; `fob status --check` asks the provider.
    NeedsCheck,
    SignedOut,
    /// The stored sign-in could not be read (a locked vault).
    Unknown,
}

impl SignInState {
    fn as_str(self) -> &'static str {
        match self {
            SignInState::SignedIn => "signed_in",
            SignInState::NeedsCheck => "needs_check",
            SignInState::SignedOut => "signed_out",
            SignInState::Unknown => "unknown",
        }
    }

    fn describe(self) -> &'static str {
        match self {
            SignInState::SignedIn => "signed in",
            SignInState::NeedsCheck => "sign-in may have ended",
            SignInState::SignedOut => "signed out",
            SignInState::Unknown => "sign-in unreadable",
        }
    }
}

fn sign_in_state(config: &omnifob_core::Config, integration: &str) -> SignInState {
    let Ok(found) = config.integration(integration) else {
        return SignInState::Unknown;
    };
    match providers::sign_in(integration, found) {
        Ok(providers::SignIn::SignedOut) => SignInState::SignedOut,
        Ok(providers::SignIn::Token) => SignInState::SignedIn,
        Ok(providers::SignIn::Session { expires_at, .. }) if expires_at > Timestamp::now() => {
            SignInState::SignedIn
        }
        Ok(providers::SignIn::Session {
            refreshable: true, ..
        }) => SignInState::NeedsCheck,
        Ok(providers::SignIn::Session { .. }) => SignInState::SignedOut,
        Err(_) => SignInState::Unknown,
    }
}

/// An integration's sign-in in words, for the integration picker.
pub(crate) fn describe_sign_in(config: &omnifob_core::Config, integration: &str) -> &'static str {
    sign_in_state(config, integration).describe()
}

/// Whether an environment label is production's, which `fob list` marks.
fn is_production(env: &str) -> bool {
    let env = env.trim().trim_end_matches('?');
    env.eq_ignore_ascii_case("prod") || env.eq_ignore_ascii_case("production")
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
/// aligned columns, then the account ID and `details` (the environment,
/// access and notes `fob list` shows), so a long list is easy to scan.
/// Typing still filters, and words separated by spaces now match across parts.
fn picker_rows(profiles: &[&Profile], details: impl Fn(&Profile) -> String) -> Vec<String> {
    let parts: Vec<Vec<&str>> = profiles.iter().map(|p| p.id.split('/').collect()).collect();
    let account_width = profiles
        .iter()
        .map(|p| p.target.account_id().unwrap_or_default().chars().count())
        .max()
        .unwrap_or(0);
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
            let account = profile.target.account_id().unwrap_or_default();
            row.push_str(&format!("{account:account_width$}  "));
            row.push_str(&details(profile));
            row.trim_end().to_string()
        })
        .collect()
}

/// The ids a caller can pick from, as many as [`listing`] shows.
fn candidate_ids(profiles: &[&Profile]) -> Vec<String> {
    profiles.iter().take(LISTED).map(|p| p.id.clone()).collect()
}

/// How many profiles an error lists.
const LISTED: usize = 10;

/// "3 profiles: a, b, c", up to ten ids, then how many more.
fn listing(profiles: &[&Profile]) -> String {
    const SHOWN: usize = LISTED;
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
        let a = aws("mine", "management", "AdministratorAccess", "111111111111");
        let b = aws("acme-media", "am-dev", "acme-media-pe", "222222222222");
        let token = Profile {
            id: "tok/prod".into(),
            integration: "tok".into(),
            target: Target::Token {},
        };
        assert_eq!(
            picker_rows(&[&a, &b, &token], |_| String::new()),
            [
                "mine        management  AdministratorAccess  111111111111",
                "acme-media  am-dev      acme-media-pe        222222222222",
                "tok         prod",
            ]
        );
        let details = |p: &Profile| {
            if p.id.starts_with("tok") {
                "(signed out)".to_string()
            } else {
                "prod  admin".to_string()
            }
        };
        assert_eq!(
            picker_rows(&[&a, &token], details),
            [
                "mine  management  AdministratorAccess  111111111111  prod  admin",
                "tok   prod                                           (signed out)",
            ]
        );
    }
}
