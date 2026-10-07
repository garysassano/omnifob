//! When each profile was last used, so pickers can list recent ones first.
//! Kept in the state directory; it holds profile ids and times only.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// Older entries are dropped beyond this many profiles.
const LIMIT: usize = 100;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct History {
    #[serde(default)]
    pub used: BTreeMap<String, Timestamp>,
}

pub fn file() -> PathBuf {
    crate::paths::state_dir().join("history.json")
}

impl History {
    /// Loads the history; a missing or unreadable file is an empty history.
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string(self)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn record(&mut self, profile_id: &str, now: Timestamp) {
        self.used.insert(profile_id.to_string(), now);
        if self.used.len() > LIMIT {
            let mut by_age: Vec<(Timestamp, String)> =
                self.used.iter().map(|(id, at)| (*at, id.clone())).collect();
            by_age.sort();
            for (_, id) in by_age.into_iter().take(self.used.len() - LIMIT) {
                self.used.remove(&id);
            }
        }
    }

    /// Sorts ids so the most recently used come first; the others keep their
    /// order after them.
    pub fn sort_recent_first<T>(&self, items: &mut [T], id: impl Fn(&T) -> &str) {
        items.sort_by(|a, b| {
            let (a, b) = (self.used.get(id(a)), self.used.get(id(b)));
            b.cmp(&a)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::SignedDuration;

    #[test]
    fn recent_first_then_original_order() {
        let t0: Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
        let mut h = History::default();
        h.record("b", t0);
        h.record("d", t0 + SignedDuration::from_mins(5));
        let mut ids = vec!["a", "b", "c", "d"];
        h.sort_recent_first(&mut ids, |s| s);
        assert_eq!(ids, ["d", "b", "a", "c"]);
    }

    #[test]
    fn keeps_the_most_recent_entries() {
        let t0: Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
        let mut h = History::default();
        for i in 0..(LIMIT as i64 + 5) {
            h.record(&format!("p{i}"), t0 + SignedDuration::from_secs(i));
        }
        assert_eq!(h.used.len(), LIMIT);
        assert!(!h.used.contains_key("p0"));
        assert!(h.used.contains_key(&format!("p{}", LIMIT + 4)));
    }
}
