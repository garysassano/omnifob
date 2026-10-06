//! Core of omnifob: integrations (identity sources you sign in to once),
//! the profiles they discover, and the short-lived credentials each profile
//! produces.
//!
//! The command-line crate only does presentation; everything that talks to a
//! provider or to the keychain lives here so it can be reused elsewhere.

pub mod config;
pub mod credentials;
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
    #[error("not signed in to '{integration}'; run `fob login {integration}`")]
    NeedsLogin { integration: String },

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
