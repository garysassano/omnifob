//! The keys of the `gcp` integration.

use std::collections::BTreeMap;

use jiff::SignedDuration;
use serde::Deserialize;

use super::{check_unique_ids, opt_duration};

/// A Google account (`type = "gcp"`), signed in the way `gcloud auth login`
/// signs in. Profiles are the account itself in each project, and service
/// accounts it may impersonate.
#[derive(Debug, Clone, Default, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct GcpConfig {
    /// The projects to offer; by default every active project the account
    /// can see, listed at `fob sync`.
    #[serde(default)]
    pub projects: Option<Vec<String>>,
    /// An OAuth client of your own (a Desktop app client) instead of the one
    /// gcloud ships. Both or neither.
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Service accounts to impersonate, keyed by a label that becomes the
    /// middle of the profile id.
    #[serde(default)]
    pub service_accounts: BTreeMap<String, GcpServiceAccount>,
    /// The browser in `[browsers]` that this integration's sign-ins and
    /// consoles open in; by default the system's.
    #[serde(default)]
    pub browser: Option<String>,
}

impl GcpConfig {
    pub(super) fn validate(&self) -> Result<(), String> {
        if self.client_id.is_some() != self.client_secret.is_some() {
            return Err("client_id and client_secret go together".to_string());
        }
        for (label, sa) in &self.service_accounts {
            check_service_account_email(&format!("service_accounts.{label}.email"), &sa.email)?;
            for delegate in &sa.delegates {
                check_service_account_email(
                    &format!("service_accounts.{label}.delegates"),
                    delegate,
                )?;
            }
            if let Some(d) = sa.lifetime
                && !(SignedDuration::from_mins(15)..=SignedDuration::from_hours(12)).contains(&d)
            {
                return Err(format!(
                    "service_accounts.{label}.lifetime must be between 15m and 12h"
                ));
            }
        }
        check_unique_ids(
            self.service_accounts
                .iter()
                .map(|(label, sa)| ("service_accounts", label, sa.name())),
        )
    }
}

/// Fails unless `email` looks like a service account's email: one `@`
/// between non-empty parts, and none of the characters that would change
/// the IAM Credentials URL it goes into (`/`, `?`, `#`, `%`, and `:`, which
/// would turn `.../serviceAccounts/<email>:generateAccessToken` into another
/// method), whitespace or control characters.
fn check_service_account_email(key: &str, email: &str) -> Result<(), String> {
    let well_formed = email.split_once('@').is_some_and(|(name, domain)| {
        !name.is_empty() && !domain.is_empty() && !domain.contains('@')
    }) && !email
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '?' | '#' | '%' | ':'));
    if !well_formed {
        return Err(format!(
            "{key} '{email}' must be a service account's email, such as \
             name@project.iam.gserviceaccount.com"
        ));
    }
    Ok(())
}

/// A service account the signed-in account impersonates, which needs the
/// Service Account Token Creator role on it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct GcpServiceAccount {
    pub email: String,
    /// Exported as the project; defaults to the one in the email.
    #[serde(default)]
    pub project: Option<String>,
    /// Token lifetime; defaults to one hour, the most Google allows unless the
    /// organization policy `iam.allowServiceAccountCredentialLifetimeExtension`
    /// lists the account (then up to 12 hours).
    #[serde(default, with = "opt_duration")]
    #[cfg_attr(test, schemars(with = "Option<String>"))]
    pub lifetime: Option<SignedDuration>,
    /// Service accounts to go through, in order, when the account may only
    /// impersonate this one by way of others.
    #[serde(default)]
    pub delegates: Vec<String>,
    /// OAuth scopes for the token; defaults to cloud-platform and
    /// userinfo.email, as gcloud asks.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
}

impl GcpServiceAccount {
    /// The part of the email before `@`.
    pub fn name(&self) -> &str {
        self.email.split('@').next().unwrap_or(&self.email)
    }

    /// `project`, or the project in a user-managed account's email
    /// (`name@PROJECT.iam.gserviceaccount.com`).
    pub fn project(&self) -> Option<&str> {
        self.project.as_deref().or_else(|| {
            self.email
                .split_once('@')?
                .1
                .strip_suffix(".iam.gserviceaccount.com")
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::config::tests::parse_error;
    use crate::config::*;

    #[test]
    fn gcp_service_accounts_are_checked() {
        let gcp = |sa: &str| {
            Config::parse(&format!(
                "[integrations.g]\ntype = \"gcp\"\n[integrations.g.service_accounts.ci]\n{sa}\n"
            ))
            .map_err(|e| format!("{e:#}"))
        };
        assert!(gcp("email = \"ci@p.iam.gserviceaccount.com\"\ndelegates = [\"hop@p.iam.gserviceaccount.com\"]").is_ok());
        for bad in [
            "ci", "@p", "ci@", "ci@p/x", "ci@p?x", "ci@p#x", "c i@p", "ci@p%2F", "a@b@c",
        ] {
            let error = gcp(&format!("email = \"{bad}\"")).unwrap_err();
            assert!(
                error.contains(&format!("service_accounts.ci.email '{bad}' must be")),
                "{error}"
            );
        }
        let error =
            gcp("email = \"ci@p.iam.gserviceaccount.com\"\ndelegates = [\"x/y@p\"]").unwrap_err();
        assert!(
            error.contains("service_accounts.ci.delegates 'x/y@p'"),
            "{error}"
        );
        let error = parse_error(
            "[integrations.g]\ntype = \"gcp\"\n[integrations.g.service_accounts.CI]\nemail = \"ci@p.iam.gserviceaccount.com\"\n[integrations.g.service_accounts.ci]\nemail = \"ci@q.iam.gserviceaccount.com\"\n",
        );
        assert!(error.contains("service_accounts.CI and service_accounts.ci would both be the profile <integration>/ci/ci"), "{error}");
    }
}
