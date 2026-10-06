//! Profiles: concrete identities discovered from integrations, such as one
//! AWS role in one account, or one Cloudflare token template in one account.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// `<integration>/<account>/<role or template>`, e.g. `acme/prod/AdministratorAccess`.
    pub id: String,
    pub integration: String,
    #[serde(flatten)]
    pub target: Target,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Target {
    Aws {
        account_id: String,
        account_name: String,
        role_name: String,
    },
    Cloudflare {
        account_id: String,
        account_name: String,
        template: String,
    },
}

impl Profile {
    pub fn new(integration: &str, account_name: &str, leaf: &str, target: Target) -> Self {
        Self {
            id: format!("{integration}/{}/{leaf}", slug(account_name)),
            integration: integration.to_string(),
            target,
        }
    }
}

/// Lowercases and replaces anything outside `[a-z0-9._-]` with `-`, so account
/// names like "Acme Prod (EU)" become typeable ids like `acme-prod-eu`.
pub fn slug(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "unnamed".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Profiles discovered by `sync`, kept on disk per integration. Contains no
/// secrets.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProfileCache {
    #[serde(default)]
    pub integrations: BTreeMap<String, SyncedProfiles>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncedProfiles {
    pub synced_at: Timestamp,
    pub profiles: Vec<Profile>,
}

impl ProfileCache {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).with_context(|| {
                format!("parsing {}; delete it and run `fob sync`", path.display())
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(self)?)?;
        std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))
    }

    pub fn all(&self) -> impl Iterator<Item = &Profile> {
        self.integrations.values().flat_map(|s| s.profiles.iter())
    }

    /// Finds profiles matching `query`: an exact id wins; otherwise every
    /// profile whose id contains all whitespace- or `/`-separated words of the
    /// query, case-insensitively. When some profiles match better, only those
    /// are returned: a word equal to a whole id segment beats one starting a
    /// segment, which beats one found anywhere. So `acme/test` picks
    /// `acme/test/...` over `acme2/test/...`.
    pub fn find(&self, query: &str) -> Vec<&Profile> {
        if let Some(exact) = self.all().find(|p| p.id == query) {
            return vec![exact];
        }
        let words: Vec<String> = query
            .split(|c: char| c.is_whitespace() || c == '/')
            .filter(|w| !w.is_empty())
            .map(str::to_lowercase)
            .collect();
        let scored: Vec<(u8, &Profile)> = self
            .all()
            .filter_map(|p| match_quality(&p.id, &words).map(|q| (q, p)))
            .collect();
        let best = scored.iter().map(|(q, _)| *q).min();
        scored
            .into_iter()
            .filter(|(q, _)| Some(*q) == best)
            .map(|(_, p)| p)
            .collect()
    }
}

/// How well `words` match `id`: 0 when every word is a whole segment, 1 when
/// every word at least starts a segment, 2 when every word appears somewhere,
/// `None` when some word does not appear.
fn match_quality(id: &str, words: &[String]) -> Option<u8> {
    let id = id.to_lowercase();
    let segments: Vec<&str> = id.split('/').collect();
    words
        .iter()
        .map(|w| {
            if segments.iter().any(|s| s == w) {
                Some(0)
            } else if segments.iter().any(|s| s.starts_with(w.as_str())) {
                Some(1)
            } else if id.contains(w.as_str()) {
                Some(2)
            } else {
                None
            }
        })
        .try_fold(0, |worst, q| q.map(|q| worst.max(q)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aws(integration: &str, account: &str, role: &str) -> Profile {
        Profile::new(
            integration,
            account,
            role,
            Target::Aws {
                account_id: "123456789012".into(),
                account_name: account.into(),
                role_name: role.into(),
            },
        )
    }

    #[test]
    fn slugs() {
        assert_eq!(slug("Acme Prod (EU)"), "acme-prod-eu");
        assert_eq!(slug("already-fine_1.2"), "already-fine_1.2");
        assert_eq!(slug("  !!  "), "unnamed");
    }

    #[test]
    fn find_prefers_exact_then_all_words() {
        let mut cache = ProfileCache::default();
        cache.integrations.insert(
            "acme".into(),
            SyncedProfiles {
                synced_at: Timestamp::UNIX_EPOCH,
                profiles: vec![
                    aws("acme", "Prod", "AdministratorAccess"),
                    aws("acme", "Prod", "ReadOnly"),
                    aws("acme", "Staging", "AdministratorAccess"),
                ],
            },
        );

        assert_eq!(cache.find("acme/prod/ReadOnly").len(), 1);
        assert_eq!(cache.find("prod admin").len(), 1);
        assert_eq!(
            cache.find("prod admin")[0].id,
            "acme/prod/AdministratorAccess"
        );
        assert_eq!(cache.find("admin").len(), 2);
        assert!(cache.find("dev").is_empty());
    }

    #[test]
    fn find_prefers_whole_segments_over_prefixes() {
        let mut cache = ProfileCache::default();
        for integration in ["acme", "acme2"] {
            cache.integrations.insert(
                integration.into(),
                SyncedProfiles {
                    synced_at: Timestamp::UNIX_EPOCH,
                    profiles: vec![aws(integration, "test", "AdministratorAccess")],
                },
            );
        }
        let ids = |q: &str| {
            cache
                .find(q)
                .iter()
                .map(|p| p.id.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(ids("acme/test"), ["acme/test/AdministratorAccess"]);
        assert_eq!(ids("acme2 admin"), ["acme2/test/AdministratorAccess"]);
        assert_eq!(ids("test admin").len(), 2);
        assert_eq!(ids("cm").len(), 2);
    }
}
