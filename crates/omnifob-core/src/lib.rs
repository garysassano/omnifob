//! Core of omnifob: integrations (identity sources you sign in to once),
//! the profiles they discover, and the short-lived credentials each profile
//! produces.
//!
//! The command-line crate only does presentation; everything that talks to a
//! provider or to the keychain lives here so it can be reused elsewhere.
//! What it works with (files, keychain, HTTP client, MFA prompt, endpoint
//! overrides) comes from a [`Context`].

#![deny(clippy::print_stdout, clippy::print_stderr)]

pub mod audit;
pub mod config;
pub mod context;
pub mod credentials;
pub mod files;
pub mod history;
pub(crate) mod http;
pub mod import;
pub mod oauth;
pub mod paths;
pub mod platform;
pub mod profile;
pub mod prompt;
pub mod providers;
pub mod provision;
pub mod serve;
pub mod store;

pub use config::{Config, Integration};
pub use context::{Agent, Context, Endpoints, PassphraseRequest};
pub use credentials::Credentials;
pub use profile::{Profile, Target};

/// Errors a caller may want to react to differently from plain failures.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The integration has no usable sign-in; the caller should run a login.
    /// `reason` says why, for the user.
    #[error("{reason}; run `fob login {integration}`")]
    NeedsLogin { integration: String, reason: String },

    #[error(transparent)]
    Other(anyhow::Error),
}

/// A [`Error::NeedsLogin`] that passed through code returning
/// `anyhow::Result` (a renewal deep in an API call) comes out as itself, so
/// callers can still offer the sign-in.
impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        match e.downcast::<Error>() {
            Ok(e) => e,
            Err(e) => Self::Other(e),
        }
    }
}

impl Error {
    /// No sign-in is stored for the integration.
    pub fn not_signed_in(integration: &str) -> Self {
        Self::needs_login(integration, format!("not signed in to '{integration}'"))
    }

    pub fn needs_login(integration: &str, reason: impl Into<String>) -> Self {
        Self::NeedsLogin {
            integration: integration.to_string(),
            reason: reason.into(),
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// What went wrong, for callers that act on a failure without reading its
/// message: agents, scripts. A code keeps its meaning across releases; new
/// ones may be added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Code {
    /// The integration has no usable sign-in: run `fob login <integration>`.
    LoginRequired,
    /// The role needs a code from the MFA device, which only a person at a
    /// terminal can enter.
    MfaRequired,
    /// The encrypted vault has not been unlocked since boot; only a person
    /// at a terminal can enter its passphrase.
    VaultLocked,
    /// The profile was not named precisely enough: several match, or, under
    /// an agent, the words were not a full id.
    ProfileAmbiguous,
    /// No profile matches.
    ProfileNotFound,
    /// `[agent] profiles` keeps the profile from agents.
    NotOpenToAgents,
    /// The command would print credentials into an agent's output, or change
    /// a shell the agent does not keep: run the command with `fob exec`.
    UseExec,
    /// The config file does not load.
    ConfigInvalid,
    /// No integration of that name is configured.
    IntegrationNotFound,
    /// Anything else; the message says what.
    Other,
}

impl Code {
    /// The code as callers match it, e.g. `login_required`.
    pub fn as_str(self) -> &'static str {
        match self {
            Code::LoginRequired => "login_required",
            Code::MfaRequired => "mfa_required",
            Code::VaultLocked => "vault_locked",
            Code::ProfileAmbiguous => "profile_ambiguous",
            Code::ProfileNotFound => "profile_not_found",
            Code::NotOpenToAgents => "not_open_to_agents",
            Code::UseExec => "use_exec",
            Code::ConfigInvalid => "config_invalid",
            Code::IntegrationNotFound => "integration_not_found",
            Code::Other => "other",
        }
    }
}

/// An error with a [`Code`] and the values a caller needs to act on it (the
/// profile, the command to run). It reads as its message, followed by its
/// source's when it wraps one.
#[derive(Debug)]
pub struct Coded {
    code: Code,
    message: String,
    details: serde_json::Map<String, serde_json::Value>,
    source: Option<anyhow::Error>,
}

impl Coded {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: serde_json::Map::new(),
            source: None,
        }
    }

    /// `message`, caused by `source`.
    pub fn wrap(code: Code, message: impl Into<String>, source: anyhow::Error) -> Self {
        Self {
            source: Some(source),
            ..Self::new(code, message)
        }
    }

    /// Adds a value for callers, such as `("profile", id)`.
    pub fn with(mut self, key: &str, value: impl Into<serde_json::Value>) -> Self {
        self.details.insert(key.to_string(), value.into());
        self
    }

    pub fn code(&self) -> Code {
        self.code
    }

    pub fn details(&self) -> &serde_json::Map<String, serde_json::Value> {
        &self.details
    }
}

impl std::fmt::Display for Coded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Coded {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as _)
    }
}

/// The code of a failure and its values: from the first [`Coded`] in its
/// chain, from a needed login, or [`Code::Other`] with none.
pub fn classify(error: &anyhow::Error) -> (Code, serde_json::Map<String, serde_json::Value>) {
    for cause in error.chain() {
        if let Some(coded) = cause.downcast_ref::<Coded>() {
            return (coded.code, coded.details.clone());
        }
        match cause.downcast_ref::<Error>() {
            Some(Error::NeedsLogin { integration, .. }) => {
                let mut details = serde_json::Map::new();
                details.insert("integration".into(), integration.as_str().into());
                details.insert("run".into(), format!("fob login {integration}").into());
                return (Code::LoginRequired, details);
            }
            // Transparent, so its chain skips the error it holds.
            Some(Error::Other(inner)) => return classify(inner),
            None => {}
        }
    }
    (Code::Other, serde_json::Map::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn failures_are_classified_through_context_and_conversions() {
        let login: anyhow::Error = Error::needs_login("cf", "it ended").into();
        let (code, details) = classify(&login.context("minting a token"));
        assert_eq!(code, Code::LoginRequired);
        assert_eq!(details["run"], "fob login cf");

        let mfa = anyhow::Error::new(
            Coded::new(Code::MfaRequired, "needs a code").with("profile", "a/b/c"),
        )
        .context("getting credentials");
        // Through the library's error type, as providers return it.
        let through: anyhow::Error = Error::from(mfa).into();
        let (code, details) = classify(&through.context("outer"));
        assert_eq!(code, Code::MfaRequired);
        assert_eq!(details["profile"], "a/b/c");

        let wrapped = anyhow::Error::new(Coded::wrap(
            Code::ConfigInvalid,
            "parsing config.toml",
            anyhow::anyhow!("bad key"),
        ));
        assert_eq!(format!("{wrapped:#}"), "parsing config.toml: bad key");
        assert_eq!(classify(&wrapped).0, Code::ConfigInvalid);
        assert_eq!(classify(&anyhow::anyhow!("boom")).0, Code::Other);
        assert_eq!(Code::NotOpenToAgents.as_str(), "not_open_to_agents");
    }

    #[test]
    fn a_needed_login_survives_anyhow() {
        let wrapped: anyhow::Result<()> =
            Err(Error::needs_login("cf", "it ended")).context("minting a token");
        let err: Error = wrapped.unwrap_err().into();
        assert!(matches!(err, Error::NeedsLogin { .. }), "{err}");
        let plain: Error = anyhow::anyhow!("boom").into();
        assert!(matches!(plain, Error::Other(_)));
    }
}
