//! The keys of the `cloudflare` integration and its templates.

use std::collections::BTreeMap;

use jiff::SignedDuration;
use serde::Deserialize;

use super::{check_name, duration, opt_duration};

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct CloudflareConfig {
    /// Account to mint tokens for. When omitted, every account the bootstrap
    /// token can list is discovered.
    #[serde(default)]
    pub account_id: Option<String>,
    /// Display name for `account_id`; defaults to the ID.
    #[serde(default)]
    pub account_name: Option<String>,
    /// The configured owner of minted tokens (`cloudflare-token` only). OAuth
    /// leaves it at the default yet mints account-owned tokens, so code that
    /// acts on the owner reads [`CloudflareConfig::minting`] instead.
    #[serde(default)]
    pub token_type: CloudflareTokenType,
    /// Lifetime of minted tokens unless a template overrides it.
    #[serde(default = "default_cloudflare_ttl", with = "duration")]
    #[cfg_attr(test, schemars(with = "String"))]
    pub ttl: SignedDuration,
    /// Extra templates, added to (or replacing) the built-in ones.
    #[serde(default)]
    pub templates: BTreeMap<String, CloudflareTemplate>,
    /// Addresses minted tokens may be used from, unless a template sets its
    /// own: IPs or CIDR ranges, or "current" for this machine's public
    /// addresses at minting time. Empty means anywhere.
    #[serde(default)]
    pub ips: Vec<String>,
    /// Sign-in session length. When set, `fob login` makes the new bootstrap
    /// token expire after this long, so it works like an SSO session: a
    /// stolen copy stops working, and a new one needs the dashboard sign-in.
    #[serde(default, with = "opt_duration")]
    #[cfg_attr(test, schemars(with = "Option<String>"))]
    pub session: Option<SignedDuration>,
    /// `cloudflare-oauth`: the OAuth client to sign in with.
    #[serde(default)]
    pub client_id: Option<String>,
    /// `cloudflare-oauth`: scopes requested at sign-in; defaults to the ones
    /// minting needs.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// Set from the integration's `type`.
    #[serde(skip)]
    pub sign_in: CloudflareSignIn,
    /// The browser in `[browsers]` that this integration's sign-ins and
    /// consoles open in; by default the system's.
    #[serde(default)]
    pub browser: Option<String>,
}

/// How a Cloudflare integration signs in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CloudflareSignIn {
    /// `cloudflare-token`: a bootstrap API token made in the dashboard.
    #[default]
    Token,
    /// `cloudflare-oauth`: the browser, through an OAuth client, as wrangler
    /// signs in. Tokens are minted as account-owned tokens in each account
    /// approved on the consent page.
    Oauth,
}

impl CloudflareConfig {
    /// Whether this integration signs in through the browser (OAuth).
    pub fn uses_oauth(&self) -> bool {
        self.sign_in == CloudflareSignIn::Oauth
    }

    pub(super) fn validate(&self) -> Result<(), String> {
        if self.uses_oauth()
            && self
                .client_id
                .as_deref()
                .is_none_or(|id| id.trim().is_empty())
        {
            return Err(
                "client_id is required: register an OAuth client for omnifob in the dashboard \
                 (Manage Account > OAuth clients) and put its ID here"
                    .to_string(),
            );
        }
        if self.minting() == CloudflareTokenType::Account
            && !self.uses_oauth()
            && self.account_id.is_none()
        {
            return Err(
                "token_type = \"account\" needs account_id: account-owned tokens are made in \
                 one account"
                    .to_string(),
            );
        }
        if self
            .account_id
            .as_deref()
            .is_some_and(|id| id.trim().is_empty())
        {
            return Err("account_id must not be empty".to_string());
        }
        check_cloudflare_ttl("ttl", self.ttl)?;
        check_ips("ips", &self.ips)?;
        if let Some(scopes) = &self.scopes
            && (scopes.is_empty() || scopes.iter().any(|s| s.trim().is_empty()))
        {
            return Err("scopes must name at least one scope, and none may be empty".to_string());
        }
        for (name, template) in &self.templates {
            check_name("template name", name).map_err(|e| format!("templates: {e}"))?;
            template
                .validate()
                .map_err(|e| format!("templates.{name}.{e}"))?;
        }
        Ok(())
    }

    /// Who owns the tokens omnifob mints. With OAuth sign-in they are
    /// account-owned, created in each approved account.
    pub fn minting(&self) -> CloudflareTokenType {
        if self.uses_oauth() {
            CloudflareTokenType::Account
        } else {
            self.token_type
        }
    }
}

fn default_cloudflare_ttl() -> SignedDuration {
    SignedDuration::from_hours(1)
}

/// Fails unless a minted token's lifetime is longer than
/// [`crate::credentials::EXPIRY_MARGIN`]: a token that is never fresh would
/// be minted again on every use.
fn check_cloudflare_ttl(key: &str, ttl: SignedDuration) -> Result<(), String> {
    if ttl <= crate::credentials::EXPIRY_MARGIN {
        return Err(format!(
            "{key} must be longer than {:#}, which is when omnifob mints a token again",
            crate::credentials::EXPIRY_MARGIN
        ));
    }
    Ok(())
}

/// Fails unless each entry of `ips` is `current`, an IP address or a CIDR
/// range.
fn check_ips(key: &str, ips: &[String]) -> Result<(), String> {
    for ip in ips {
        if ip != "current" {
            crate::providers::cloudflare::ip_range(ip).map_err(|e| format!("{key}: {e:#}"))?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum CloudflareTokenType {
    /// Minted with a user-owned bootstrap token ("Create additional tokens").
    #[default]
    User,
    /// Minted with an account-owned bootstrap token ("Account API Tokens Edit").
    Account,
}

/// A named set of permissions, written as they appear in the dashboard's API
/// names (e.g. "Workers Scripts Write"), never as IDs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct CloudflareTemplate {
    pub permissions: Vec<String>,
    /// Permissions added when the account offers them and skipped otherwise,
    /// for products that are new, renamed or not enabled everywhere.
    #[serde(default)]
    pub optional: Vec<String>,
    #[serde(default, with = "opt_duration")]
    #[cfg_attr(test, schemars(with = "Option<String>"))]
    pub ttl: Option<SignedDuration>,
    /// R2 buckets that bucket-level permissions ("Workers R2 Storage Bucket
    /// Item Write") apply to; "eu/name" for a bucket in a jurisdiction.
    #[serde(default)]
    pub r2_buckets: Vec<String>,
    /// Also hand out the S3-compatible credentials R2 derives from the token
    /// (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_ENDPOINT_URL_S3`).
    #[serde(default)]
    pub s3: bool,
    /// Overrides the integration's `ips` for this template.
    #[serde(default)]
    pub ips: Option<Vec<String>>,
    /// Zones that zone-level permissions ("DNS Write") apply to, as domain
    /// names ("example.com", looked up in the account when a token is
    /// minted) or zone IDs. Empty means every zone in the account.
    #[serde(default)]
    pub zones: Vec<String>,
}

impl CloudflareTemplate {
    /// The checks a template gets when the config loads; errors start with
    /// the key, to follow `templates.<name>.`.
    fn validate(&self) -> Result<(), String> {
        if self.permissions.is_empty() {
            return Err("permissions must name at least one permission".to_string());
        }
        for (key, list) in [
            ("permissions", &self.permissions),
            ("optional", &self.optional),
        ] {
            if list.iter().any(|p| p.trim().is_empty()) {
                return Err(format!("{key} must not contain an empty name"));
            }
        }
        if self.r2_buckets.iter().any(|b| b.trim().is_empty()) {
            return Err("r2_buckets must not contain an empty name".to_string());
        }
        for zone in &self.zones {
            if zone.trim().is_empty() || zone.contains(['/', ' ', '*']) {
                return Err(format!(
                    "zones: '{zone}' is neither a domain name nor a zone ID"
                ));
            }
        }
        if let Some(ttl) = self.ttl {
            check_cloudflare_ttl("ttl", ttl)?;
        }
        if let Some(ips) = &self.ips {
            check_ips("ips", ips)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    #[test]
    fn cloudflare_types_pick_the_sign_in() {
        let cf = |text: &str| match Config::parse(text)?.integrations.remove("c").unwrap() {
            Integration::Cloudflare(c) => Ok::<_, anyhow::Error>(c),
            _ => unreachable!(),
        };
        let oauth =
            cf("[integrations.c]\ntype = \"cloudflare-oauth\"\nclient_id = \"x\"\n").unwrap();
        assert!(oauth.uses_oauth());
        assert_eq!(oauth.minting(), CloudflareTokenType::Account);
        let token = cf("[integrations.c]\ntype = \"cloudflare-token\"\n").unwrap();
        assert!(!token.uses_oauth());
        assert_eq!(token.minting(), CloudflareTokenType::User);
        assert!(cf("[integrations.c]\ntype = \"cloudflare-token\"\nclient_id = \"x\"\n").is_err());
        assert!(
            cf("[integrations.c]\ntype = \"cloudflare-oauth\"\ntoken_type = \"account\"\n")
                .is_err()
        );
        assert!(Config::parse("[integrations.c]\ntype = \"cloudflare\"\n").is_err());
    }

    #[test]
    fn cloudflare_keys_are_checked() {
        let cf = |kind: &str, extra: &str| {
            Config::parse(&format!(
                "[integrations.c]\ntype = \"cloudflare-{kind}\"\n{extra}\n"
            ))
            .map_err(|e| format!("{e:#}"))
        };
        assert!(
            cf(
                "token",
                "ttl = \"6m\"\nips = [\"current\", \"203.0.113.7\", \"2001:db8::/32\"]"
            )
            .is_ok()
        );
        for (kind, extra, message) in [
            ("oauth", "", "client_id is required"),
            ("oauth", "client_id = \" \"", "client_id is required"),
            (
                "token",
                "token_type = \"account\"",
                "token_type = \"account\" needs account_id",
            ),
            ("token", "ttl = \"5m\"", "ttl must be longer than 5m"),
            (
                "token",
                "ips = [\"10.0.0.0/33\"]",
                "ips: '10.0.0.0/33' has an invalid prefix length",
            ),
            (
                "token",
                "ips = [\"example.com\"]",
                "ips: 'example.com' is not an IP address",
            ),
            (
                "token",
                "[integrations.c.templates.\"my pages\"]\npermissions = [\"Pages Write\"]",
                "templates: template name 'my pages' may contain only",
            ),
            (
                "token",
                "[integrations.c.templates.p]\npermissions = []",
                "templates.p.permissions must name at least one permission",
            ),
            (
                "token",
                "[integrations.c.templates.p]\npermissions = [\"Pages Write\"]\noptional = [\"\"]",
                "templates.p.optional must not contain an empty name",
            ),
            (
                "token",
                "[integrations.c.templates.p]\npermissions = [\"Pages Write\"]\nttl = \"4m\"",
                "templates.p.ttl must be longer than 5m",
            ),
            (
                "token",
                "[integrations.c.templates.p]\npermissions = [\"Pages Write\"]\nips = [\"1.2.3\"]",
                "templates.p.ips: '1.2.3'",
            ),
            (
                "token",
                "[integrations.c.templates.p]\npermissions = [\"DNS Write\"]\nzones = [\"*.example.com\"]",
                "templates.p.zones: '*.example.com' is neither",
            ),
        ] {
            let error = cf(kind, extra).unwrap_err();
            assert!(error.contains(message), "{extra}: {error}");
        }
        assert!(cf("token", "token_type = \"account\"\naccount_id = \"abc\"").is_ok());
    }
}
