//! Short-lived credentials, expressed as the environment variables a tool
//! needs, plus when they stop working.

use std::collections::BTreeMap;

use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};

/// Credentials are treated as expired this long before they really expire,
/// so a command started with them does not fail halfway through.
pub const EXPIRY_MARGIN: SignedDuration = SignedDuration::from_mins(5);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    pub env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
}

impl Credentials {
    /// Whether these credentials are still good for at least [`EXPIRY_MARGIN`].
    pub fn is_fresh(&self, now: Timestamp) -> bool {
        match self.expires_at {
            Some(at) => now.saturating_add(EXPIRY_MARGIN).is_ok_and(|t| t < at),
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freshness_respects_margin() {
        let now: Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
        let creds = |mins: i64| Credentials {
            env: BTreeMap::new(),
            expires_at: Some(now + SignedDuration::from_mins(mins)),
        };
        assert!(creds(6).is_fresh(now));
        assert!(!creds(4).is_fresh(now));
        assert!(
            Credentials {
                env: BTreeMap::new(),
                expires_at: None
            }
            .is_fresh(now)
        );
    }
}
