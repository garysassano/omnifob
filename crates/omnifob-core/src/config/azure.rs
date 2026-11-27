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

impl AzureConfig {
    /// The checks the config gets when it loads. `tenant` becomes part of
    /// Entra ID's URLs, so it must be a tenant ID or domain.
    pub(crate) fn validate(&self) -> Result<(), String> {
        if let Some(tenant) = &self.tenant
            && (tenant.is_empty()
                || !tenant
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-')))
        {
            return Err(format!(
                "tenant '{tenant}' must be a tenant ID or domain, such as contoso.onmicrosoft.com"
            ));
        }
        if let Some(subscriptions) = &self.subscriptions
            && subscriptions.iter().any(|s| s.trim().is_empty())
        {
            return Err("subscriptions must not hold an empty ID".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenants_are_ids_or_domains() {
        let config = |tenant: &str| AzureConfig {
            tenant: Some(tenant.into()),
            ..Default::default()
        };
        assert!(config("contoso.onmicrosoft.com").validate().is_ok());
        assert!(
            config("11111111-2222-3333-4444-555555555555")
                .validate()
                .is_ok()
        );
        for bad in ["", "a/b", "x?y", "../oauth2"] {
            assert!(config(bad).validate().is_err(), "{bad:?}");
        }
    }
}
