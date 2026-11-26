//! Short-lived credentials, expressed as the environment variables a tool
//! needs, plus when they stop working.

use std::collections::BTreeMap;

use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};

/// Credentials are treated as expired this long before they really expire,
/// so a command started with them does not fail halfway through.
pub const EXPIRY_MARGIN: SignedDuration = SignedDuration::from_mins(5);

/// Not `Debug`-derived: its [`Debug`](std::fmt::Debug) shows the variable
/// names but never their values.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    pub env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    /// When omnifob obtained them; with `expires_at` this gives the lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<Timestamp>,
    /// The provider's ID for these credentials when they can be revoked
    /// before they expire (a minted Cloudflare token).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
}

/// Every variable through which the AWS SDKs and CLI find credentials:
/// the access key and its session, a profile, web identity, and a
/// container endpoint. `fob exec` removes those a profile does not set, so
/// one left in the shell is not mixed with the profile's credentials or
/// taken before them.
pub const AWS_CREDENTIAL_VARS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    // The older name of AWS_SESSION_TOKEN, which botocore still reads.
    "AWS_SECURITY_TOKEN",
    "AWS_CREDENTIAL_EXPIRATION",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
];

/// Whether `name` is a portable environment variable name
/// (`[A-Za-z_][A-Za-z0-9_]*`), the only kind omnifob puts into shell code.
pub fn is_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Stands in for a secret value in `Debug` output.
struct Redacted;

impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let env: BTreeMap<&str, Redacted> =
            self.env.keys().map(|k| (k.as_str(), Redacted)).collect();
        f.debug_struct("Credentials")
            .field("env", &env)
            .field("expires_at", &self.expires_at)
            .field("issued_at", &self.issued_at)
            .field("token_id", &self.token_id)
            .finish()
    }
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
    fn variable_names_are_portable() {
        for ok in ["AWS_REGION", "_x", "a1", "Z"] {
            assert!(is_var_name(ok), "{ok}");
        }
        for bad in ["", "1A", "A-B", "A B", "A;rm", "$(x)", "A=B", "É", "A,B"] {
            assert!(!is_var_name(bad), "{bad}");
        }
    }

    #[test]
    fn debug_names_the_variables_but_never_their_values() {
        let creds = Credentials {
            env: BTreeMap::from([
                ("AWS_ACCESS_KEY_ID".into(), "AKIAEXAMPLE".into()),
                ("AWS_SECRET_ACCESS_KEY".into(), "s3cr3t-value".into()),
            ]),
            expires_at: None,
            issued_at: None,
            token_id: Some("tok-1".into()),
        };
        for shown in [format!("{creds:?}"), format!("{creds:#?}")] {
            assert!(shown.contains("AWS_SECRET_ACCESS_KEY"), "{shown}");
            assert!(shown.contains("<redacted>"), "{shown}");
            assert!(shown.contains("tok-1"), "{shown}");
            assert!(!shown.contains("AKIAEXAMPLE"), "{shown}");
            assert!(!shown.contains("s3cr3t-value"), "{shown}");
        }
    }

    #[test]
    fn freshness_respects_margin() {
        let now: Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
        let creds = |mins: i64| Credentials {
            env: BTreeMap::new(),
            expires_at: Some(now + SignedDuration::from_mins(mins)),
            issued_at: None,
            token_id: None,
        };
        assert!(creds(6).is_fresh(now));
        assert!(!creds(4).is_fresh(now));
        assert!(
            Credentials {
                env: BTreeMap::new(),
                expires_at: None,
                issued_at: None,
                token_id: None,
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
            token_id: None,
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
