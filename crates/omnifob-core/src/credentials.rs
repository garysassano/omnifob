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
    /// When omnifob obtained them; with `expires_at` this gives the lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<Timestamp>,
}

impl Credentials {
    /// Whether it is time to get replacements in the background: the last
    /// quarter of the lifetime plus [`EXPIRY_MARGIN`], since credentials are
    /// no longer handed out within that margin (20 minutes of a one-hour token).
    pub fn wants_renewal(&self, now: Timestamp) -> bool {
        let (Some(issued), Some(expires)) = (self.issued_at, self.expires_at) else {
            return false;
        };
        let lifetime = expires.duration_since(issued);
        expires.duration_since(now) < lifetime / 4 + EXPIRY_MARGIN
    }

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
            issued_at: None,
        };
        assert!(creds(6).is_fresh(now));
        assert!(!creds(4).is_fresh(now));
        assert!(
            Credentials {
                env: BTreeMap::new(),
                expires_at: None,
                issued_at: None,
            }
            .is_fresh(now)
        );
    }

    #[test]
    fn renewal_starts_before_the_expiry_margin() {
        let issued: Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
        let creds = Credentials {
            env: BTreeMap::new(),
            issued_at: Some(issued),
            expires_at: Some(issued + SignedDuration::from_hours(1)),
        };
        assert!(!creds.wants_renewal(issued + SignedDuration::from_mins(39)));
        assert!(creds.wants_renewal(issued + SignedDuration::from_mins(41)));
        let unknown = Credentials {
            issued_at: None,
            ..creds
        };
        assert!(!unknown.wants_renewal(issued + SignedDuration::from_mins(59)));
    }
}
