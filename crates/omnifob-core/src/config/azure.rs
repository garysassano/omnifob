//! The keys of the `azure` integration.

use serde::Deserialize;

/// A Microsoft Entra ID account (`type = "azure"`), signed in the way
/// `az login` signs in. Profiles are the account in each subscription.
#[derive(Debug, Clone, Default, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct AzureConfig {
    /// The tenant to sign in to (ID or domain); by default `organizations`,
    /// which finds every tenant the account belongs to.
    #[serde(default)]
    pub tenant: Option<String>,
    /// The subscriptions to offer (IDs); by default every one the account
    /// can see, listed at `fob sync`.
    #[serde(default)]
    pub subscriptions: Option<Vec<String>>,
    /// The browser in `[browsers]` that this integration's sign-ins and
    /// consoles open in; by default the system's.
    #[serde(default)]
    pub browser: Option<String>,
}
