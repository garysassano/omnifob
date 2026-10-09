//! Core of omnifob: integrations (identity sources you sign in to once),
//! the profiles they discover, and the short-lived credentials each profile
//! produces.
//!
//! The command-line crate only does presentation; everything that talks to a
//! provider or to the keychain lives here so it can be reused elsewhere.

pub mod config;
pub mod credentials;
pub mod git;
pub mod history;
pub mod import;
pub mod paths;
pub mod profile;
pub mod providers;
pub mod store;

pub use config::{Config, Integration};
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
    Other(#[from] anyhow::Error),
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
