//! The catalog: the permission groups each account offers, and the tokens
//! omnifob minted, kept in the state directory and changed under a lock.

use std::collections::BTreeMap;

use anyhow::Context;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use super::{PermissionGroup, accounts, bootstrap_client};
use crate::config::{CloudflareConfig, CloudflareTokenType};
use crate::{Result, store};

/// Lists the permissions templates can use, for `fob cloudflare permissions`.
pub async fn permission_groups(
    integration: &str,
    config: &CloudflareConfig,
) -> Result<Vec<PermissionGroup>> {
    let client = bootstrap_client(integration, config).await?;
    // Account-owned tokens list the groups per account; any account will do.
    let account_id = match (&config.account_id, config.uses_oauth()) {
        (Some(id), _) => id.clone(),
        (None, true) => accounts(&client).await?.remove(0).id,
        (None, false) => String::new(),
    };
    let mut groups = client
        .permission_groups(config.minting(), &account_id)
        .await?;
    groups.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(groups)
}

/// What minting needs to know about the bootstrap token's accounts but which
/// rarely changes: the permission groups (about 400) and the user tag. Kept on
/// disk, without secrets, to save two to three API calls per mint.
///
/// Every update goes through [`update_catalog`], under a lock per
/// integration, so concurrent mints never lose each other's token IDs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Catalog {
    /// The permission groups tokens can carry, per [`groups_key`]: user
    /// tokens share one list, while each account offers its own (a product
    /// enabled in one account only).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub permission_groups: BTreeMap<String, Groups>,
    #[serde(default)]
    pub user_tag: Option<String>,
    /// IDs of the tokens minted for each profile that may still exist.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub minted: BTreeMap<String, Vec<String>>,
    /// The stored bootstrap token's ID and expiry, when it has a session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap: Option<Bootstrap>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Bootstrap {
    pub id: String,
    pub expires_at: Option<Timestamp>,
}

/// One list of permission groups and when it was fetched.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Groups {
    pub fetched_at: Timestamp,
    pub groups: Vec<PermissionGroup>,
}

/// The key of the permission groups a token of `token_type` in `account_id`
/// can carry, in [`Catalog::permission_groups`].
pub fn groups_key(token_type: CloudflareTokenType, account_id: &str) -> String {
    match token_type {
        CloudflareTokenType::User => "user".to_string(),
        CloudflareTokenType::Account => format!("account/{account_id}"),
    }
}

impl Catalog {
    pub(super) fn track(&mut self, profile_id: &str, token_id: &str) {
        self.minted
            .entry(profile_id.to_string())
            .or_default()
            .push(token_id.to_string());
    }

    pub(super) fn untrack(&mut self, token_id: &str) {
        for ids in self.minted.values_mut() {
            ids.retain(|id| id != token_id);
        }
        self.minted.retain(|_, ids| !ids.is_empty());
    }

    /// Forgets the tracked IDs that `listed` (every account's tokens) lacks:
    /// those tokens were deleted outside omnifob.
    pub fn forget_missing(&mut self, listed: &[String]) {
        for ids in self.minted.values_mut() {
            ids.retain(|id| listed.contains(id));
        }
        self.minted.retain(|_, ids| !ids.is_empty());
    }

    pub(super) fn is_tracked(&self, token_id: &str) -> bool {
        self.minted
            .values()
            .any(|ids| ids.iter().any(|id| id == token_id))
    }
}

/// How long a stored catalog is trusted before it is fetched again.
const CATALOG_MAX_AGE: jiff::SignedDuration = jiff::SignedDuration::from_hours(24);

impl Catalog {
    pub(super) fn is_current(&self, key: &str, now: Timestamp) -> bool {
        self.permission_groups.get(key).is_some_and(|g| {
            !g.groups.is_empty() && now.duration_since(g.fetched_at) < CATALOG_MAX_AGE
        })
    }
}

/// The groups stored under `key`; takes the field rather than the catalog,
/// so the rest of the catalog stays free to change while they are in use.
pub(super) fn groups_in<'a>(
    groups: &'a BTreeMap<String, Groups>,
    key: &str,
) -> &'a [PermissionGroup] {
    groups.get(key).map_or(&[], |g| g.groups.as_slice())
}

/// What a mint, revocation or cleanup changed in the catalog it loaded,
/// applied to the catalog as it is on disk once the lock is held: another
/// process may have tracked or untracked tokens meanwhile, and both
/// processes' changes are kept.
#[derive(Debug, Default)]
struct CatalogChanges {
    groups: BTreeMap<String, Groups>,
    pub(super) user_tag: Option<Option<String>>,
    tracked: Vec<(String, String)>,
    untracked: Vec<String>,
}

impl CatalogChanges {
    fn between(before: &Catalog, after: &Catalog) -> Self {
        let ids = |c: &Catalog| -> Vec<String> { c.minted.values().flatten().cloned().collect() };
        let (was, is) = (ids(before), ids(after));
        Self {
            groups: after
                .permission_groups
                .iter()
                .filter(|(k, g)| before.permission_groups.get(*k) != Some(g))
                .map(|(k, g)| (k.clone(), g.clone()))
                .collect(),
            user_tag: (before.user_tag != after.user_tag).then(|| after.user_tag.clone()),
            tracked: after
                .minted
                .iter()
                .flat_map(|(p, ids)| ids.iter().map(move |id| (p, id)))
                .filter(|(_, id)| !was.contains(id))
                .map(|(p, id)| (p.clone(), id.clone()))
                .collect(),
            untracked: was.into_iter().filter(|id| !is.contains(id)).collect(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.groups.is_empty()
            && self.user_tag.is_none()
            && self.tracked.is_empty()
            && self.untracked.is_empty()
    }

    pub(super) fn apply(self, catalog: &mut Catalog) {
        catalog.permission_groups.extend(self.groups);
        if let Some(tag) = self.user_tag {
            catalog.user_tag = tag;
        }
        for (profile, id) in &self.tracked {
            if !catalog.is_tracked(id) {
                catalog.track(profile, id);
            }
        }
        for id in &self.untracked {
            catalog.untrack(id);
        }
    }
}

fn catalog_file(integration: &str) -> anyhow::Result<std::path::PathBuf> {
    Ok(crate::paths::state_dir()?.join(format!("cloudflare-{integration}.json")))
}

/// The catalog for reading only, such as the copy a mint starts from:
/// empty when it is missing or unreadable. Never written back as it is;
/// updates go through [`update_catalog`], which reads with [`read_catalog`].
pub(super) fn load_catalog(integration: &str) -> Catalog {
    read_catalog(integration).unwrap_or_else(|e| {
        tracing::debug!("reading the Cloudflare catalog: {e:#}");
        Catalog::default()
    })
}

/// The catalog as stored: empty only when there is no file. A file that
/// cannot be read or parsed is an error, never an empty catalog, so an
/// update cannot replace token IDs it failed to see.
pub(super) fn read_catalog(integration: &str) -> anyhow::Result<Catalog> {
    let file = catalog_file(integration)?;
    let text = match crate::files::retry_busy(|| std::fs::read_to_string(&file)) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Catalog::default()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", file.display())),
    };
    serde_json::from_str(&text).with_context(|| {
        format!(
            "{} is not a Cloudflare catalog omnifob can read; delete it to start over (tokens it tracks are then no longer cleaned up)",
            file.display()
        )
    })
}

pub(super) fn save_catalog(integration: &str, catalog: &Catalog) -> anyhow::Result<()> {
    let text = serde_json::to_string(catalog)?;
    // The writer tries a refused replace again on Windows.
    crate::files::write_private(&catalog_file(integration)?, text)
}

/// How long to wait for other processes updating the same catalog, each of
/// which holds the lock only while it reads and writes the file.
const CATALOG_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Holds the catalog lock of an integration. Synchronous, and never held
/// across an API call. Unlike renewal locks it fails rather than going
/// ahead without the lock: an unguarded update can drop the token IDs
/// another process tracked meanwhile, and those tokens are never cleaned up.
pub(super) fn lock_catalog(integration: &str) -> anyhow::Result<store::Lock> {
    let name = format!("cloudflare-catalog-{integration}");
    store::lock_blocking(&name, CATALOG_LOCK_TIMEOUT)?.with_context(|| {
        format!(
            "another omnifob process held the Cloudflare catalog lock of '{integration}' for {} s",
            CATALOG_LOCK_TIMEOUT.as_secs()
        )
    })
}

/// Reads the catalog, lets `change` update it, and writes it back, under
/// the integration's catalog lock. Fails, changing nothing, when the lock
/// cannot be had or the stored catalog cannot be read.
pub fn update_catalog(integration: &str, change: impl FnOnce(&mut Catalog)) -> anyhow::Result<()> {
    let _lock = lock_catalog(integration)?;
    let mut catalog = read_catalog(integration)?;
    let before = catalog.clone();
    change(&mut catalog);
    if catalog == before && catalog_file(integration)?.exists() {
        return Ok(());
    }
    save_catalog(integration, &catalog)
}

/// Stores what changed between `before` (as loaded) and `after`, merged
/// into the catalog as it is now.
pub(super) fn save_changes(
    integration: &str,
    before: &Catalog,
    after: &Catalog,
) -> anyhow::Result<()> {
    let changes = CatalogChanges::between(before, after);
    if changes.is_empty() {
        return Ok(());
    }
    update_catalog(integration, |c| changes.apply(c))
}

/// Moves the stored catalog to a renamed integration, with the IDs of the
/// tokens minted for its profiles filed under their new IDs (`<new>/...`),
/// so `fob revoke` still finds them. Renaming back undoes it exactly.
pub fn rename_catalog(old: &str, new: &str) -> anyhow::Result<()> {
    // Both locks, always in the same order, so two renames cannot deadlock.
    let (first, second) = if old < new { (old, new) } else { (new, old) };
    let _first = lock_catalog(first)?;
    let _second = lock_catalog(second)?;
    let from = catalog_file(old)?;
    if !from.exists() {
        return Ok(());
    }
    let mut catalog = read_catalog(old)?;
    let prefix = format!("{old}/");
    catalog.minted = std::mem::take(&mut catalog.minted)
        .into_iter()
        .map(|(profile, ids)| match profile.strip_prefix(&prefix) {
            Some(rest) => (format!("{new}/{rest}"), ids),
            None => (profile, ids),
        })
        .collect();
    save_catalog(new, &catalog)?;
    crate::files::retry_busy(|| std::fs::remove_file(&from))
        .with_context(|| format!("removing {}", from.display()))
}

/// Removes the stored catalog, for example after signing out.
pub fn forget_catalog(integration: &str) {
    if let Ok(file) = catalog_file(integration) {
        let _ = std::fs::remove_file(file);
    }
}

/// Forgets every tracked token ID, once all the accounts' minted tokens are
/// deleted: the IDs left belong to tokens no listing showed.
/// Whether the catalog tracks any token omnifob minted.
pub fn has_minted(integration: &str) -> bool {
    !load_catalog(integration).minted.is_empty()
}

pub fn forget_minted(integration: &str) -> anyhow::Result<()> {
    update_catalog(integration, |c| c.minted.clear())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_changes_merge_into_what_others_stored_meanwhile() {
        let mut before = Catalog::default();
        before.track("cf/a/t", "old");
        before.track("cf/a/t", "expired");
        // This process mints `mine` and prunes `expired`.
        let mut ours = before.clone();
        ours.track("cf/a/t", "mine");
        ours.untrack("expired");
        ours.user_tag = Some("tag".into());
        // Meanwhile another process minted `theirs` and revoked `old`.
        let mut on_disk = before.clone();
        on_disk.track("cf/b/t", "theirs");
        on_disk.untrack("old");

        CatalogChanges::between(&before, &ours).apply(&mut on_disk);
        let mut ids: Vec<_> = on_disk.minted.values().flatten().cloned().collect();
        ids.sort();
        assert_eq!(ids, ["mine", "theirs"]);
        assert_eq!(on_disk.user_tag.as_deref(), Some("tag"));
        assert!(CatalogChanges::between(&ours, &ours).is_empty());
    }
}
