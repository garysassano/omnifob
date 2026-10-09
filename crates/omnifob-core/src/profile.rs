//! Profiles: concrete identities discovered from integrations, such as one
//! AWS role in one account, or one Cloudflare token template in one account.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, bail};
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
    Token {},
    /// A role assumed from an Identity Center role; details live in the
    /// integration's `chained` table under `label`.
    AwsChained {
        label: String,
        /// The account of the assumed role, for searching by account ID.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account_id: Option<String>,
    },
}

impl Target {
    /// The provider account this profile acts in, when it has one.
    pub fn account_id(&self) -> Option<&str> {
        match self {
            Target::Aws { account_id, .. } | Target::Cloudflare { account_id, .. } => {
                Some(account_id)
            }
            Target::AwsChained { account_id, .. } => account_id.as_deref(),
            Target::Token {} => None,
        }
    }
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

    /// Moves an integration's discovered profiles to a new name, rewriting
    /// their ids (`old/...` becomes `new/...`).
    pub fn rename_integration(&mut self, old: &str, new: &str) {
        let Some(mut synced) = self.integrations.remove(old) else {
            return;
        };
        for p in &mut synced.profiles {
            p.integration = new.to_string();
            if let Some(rest) = p.id.strip_prefix(&format!("{old}/")) {
                p.id = format!("{new}/{rest}");
            }
        }
        self.integrations.insert(new.to_string(), synced);
    }

    pub fn all(&self) -> impl Iterator<Item = &Profile> {
        self.integrations.values().flat_map(|s| s.profiles.iter())
    }

    /// Finds profiles matching `query`: an exact id wins; otherwise every
    /// profile whose id, or account ID, contains all whitespace- or
    /// `/`-separated words of the query, case-insensitively. When some
    /// profiles match better, only those are returned: a word equal to a
    /// whole id segment or the account ID beats one starting a segment, which
    /// beats one found anywhere. So `acme/test` picks `acme/test/...` over
    /// `acme2/test/...`, and `123456789012 admin` finds that account's admin role.
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
            .filter_map(|p| match_quality(p, &words).map(|q| (q, p)))
            .collect();
        let best = scored.iter().map(|(q, _)| *q).min();
        scored
            .into_iter()
            .filter(|(q, _)| Some(*q) == best)
            .map(|(_, p)| p)
            .collect()
    }

    /// The profile each query names. Fails unless every query names exactly
    /// one, so a stale or vague entry is reported instead of guessed at.
    pub fn resolve(&self, queries: &[String]) -> anyhow::Result<Vec<&Profile>> {
        let mut profiles: Vec<&Profile> = Vec::new();
        for query in queries {
            match self.find(query).as_slice() {
                [one] => {
                    if !profiles.iter().any(|p| p.id == one.id) {
                        profiles.push(one);
                    }
                }
                [] => bail!("'{query}' matches no profile; see `fob list`"),
                several => {
                    let ids: Vec<_> = several.iter().take(10).map(|p| p.id.as_str()).collect();
                    bail!("'{query}' matches several profiles: {}", ids.join(", "))
                }
            }
        }
        Ok(profiles)
    }
}

/// How well `words` match a profile: 0 when every word is a whole id
/// segment (or the account ID), 1 when every word at least starts one, 2 when
/// every word appears somewhere, `None` when some word does not appear.
fn match_quality(profile: &Profile, words: &[String]) -> Option<u8> {
    let mut id = profile.id.to_lowercase();
    let mut segments: Vec<String> = id.split('/').map(str::to_string).collect();
    if let Some(account) = profile.target.account_id() {
        segments.push(account.to_string());
        id.push('/');
        id.push_str(account);
    }
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
    fn find_by_account_id() {
        let role = |account: &str, id: &str, role: &str| {
            Profile::new(
                "acme",
                account,
                role,
                Target::Aws {
                    account_id: id.into(),
                    account_name: account.into(),
                    role_name: role.into(),
                },
            )
        };
        let mut cache = ProfileCache::default();
        cache.integrations.insert(
            "acme".into(),
            SyncedProfiles {
                synced_at: Timestamp::UNIX_EPOCH,
                profiles: vec![
                    role("prod", "111122223333", "Admin"),
                    role("prod", "111122223333", "ReadOnly"),
                    role("dev", "444455556666", "Admin"),
                    Profile::new(
                        "acme",
                        "deploy",
                        "Deploy",
                        Target::AwsChained {
                            label: "deploy".into(),
                            account_id: Some("777788889999".into()),
                        },
                    ),
                ],
            },
        );
        let ids = |q: &str| {
            cache
                .find(q)
                .iter()
                .map(|p| p.id.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(ids("111122223333 admin"), ["acme/prod/Admin"]);
        assert_eq!(ids("111122223333").len(), 2);
        assert_eq!(ids("4444"), ["acme/dev/Admin"], "an ID prefix works too");
        assert_eq!(
            ids("777788889999"),
            ["acme/deploy/Deploy"],
            "chained roles too"
        );
        assert!(ids("999999999999").is_empty());
    }

    #[test]
    fn resolve_needs_one_profile_per_query() {
        let mut cache = ProfileCache::default();
        cache.integrations.insert(
            "acme".into(),
            SyncedProfiles {
                synced_at: Timestamp::UNIX_EPOCH,
                profiles: vec![
                    aws("acme", "Prod", "AdministratorAccess"),
                    aws("acme", "Prod", "ReadOnly"),
                ],
            },
        );
        let ids = |queries: &[&str]| {
            let queries: Vec<String> = queries.iter().map(|q| q.to_string()).collect();
            cache
                .resolve(&queries)
                .map(|ps| ps.iter().map(|p| p.id.clone()).collect::<Vec<_>>())
                .map_err(|e| e.to_string())
        };
        assert_eq!(
            ids(&["readonly", "prod admin", "acme/prod/ReadOnly"]).unwrap(),
            ["acme/prod/ReadOnly", "acme/prod/AdministratorAccess"]
        );
        assert!(ids(&["dev"]).unwrap_err().contains("matches no profile"));
        assert!(ids(&["prod"]).unwrap_err().contains("several"));
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
