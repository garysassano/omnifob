//! Core of omnifob: integrations (identity sources you sign in to once),
//! the profiles they discover, and the short-lived credentials each profile
//! produces.
//!
//! The command-line crate only does presentation; everything that talks to a
//! provider or to the keychain lives here so it can be reused elsewhere.
//! What it works with (files, keychain, HTTP client, MFA prompt, endpoint
//! overrides) comes from a [`Context`].

#![deny(clippy::print_stdout, clippy::print_stderr)]

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
pub mod store;

pub use config::{Config, Integration};
pub use context::{Context, Endpoints};
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

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

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
