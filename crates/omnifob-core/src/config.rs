//! User configuration: the integrations to sign in to.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, bail};
use jiff::SignedDuration;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub integrations: BTreeMap<String, Integration>,
}

/// An identity source: something you sign in to once and that yields many
/// profiles.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Integration {
    AwsSso(AwsSsoConfig),
    Cloudflare(CloudflareConfig),
}

impl Integration {
    pub fn kind(&self) -> &'static str {
        match self {
            Integration::AwsSso(_) => "aws-sso",
            Integration::Cloudflare(_) => "cloudflare",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsSsoConfig {
    /// The AWS access portal URL, e.g. `https://acme.awsapps.com/start`.
    pub start_url: String,
    /// The region IAM Identity Center runs in.
    pub region: String,
    /// Region exported as `AWS_REGION` for every profile of this integration.
    #[serde(default)]
    pub default_region: Option<String>,
    /// OIDC scopes. `sso:account:access` makes Identity Center issue a refresh
    /// token, so sessions renew without a browser until the portal session ends.
    #[serde(default = "default_sso_scopes")]
    pub scopes: Vec<String>,
}

fn default_sso_scopes() -> Vec<String> {
    vec!["sso:account:access".to_string()]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareConfig {
    /// Account to mint tokens for. When omitted, every account the bootstrap
    /// token can list is discovered.
    #[serde(default)]
    pub account_id: Option<String>,
    /// Display name for `account_id`; defaults to the ID.
    #[serde(default)]
    pub account_name: Option<String>,
    #[serde(default)]
    pub token_type: CloudflareTokenType,
    /// Lifetime of minted tokens unless a template overrides it.
    #[serde(default = "default_cloudflare_ttl", with = "duration")]
    pub ttl: SignedDuration,
    /// Extra templates, added to (or replacing) the built-in ones.
    #[serde(default)]
    pub templates: BTreeMap<String, CloudflareTemplate>,
}

fn default_cloudflare_ttl() -> SignedDuration {
    SignedDuration::from_hours(1)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTemplate {
    pub permissions: Vec<String>,
    /// Permissions added when the account offers them and skipped otherwise,
    /// for products that are new, renamed or not enabled everywhere.
    #[serde(default)]
    pub optional: Vec<String>,
    #[serde(default, with = "opt_duration")]
    pub ttl: Option<SignedDuration>,
}

impl Config {
    /// Loads the config file; a missing file is an empty config.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Self::parse(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let config: Self = toml::from_str(text)?;
        for name in config.integrations.keys() {
            if name.is_empty() || name.contains('/') {
                bail!("integration name '{name}' must be non-empty and contain no '/'");
            }
        }
        Ok(config)
    }

    pub fn integration(&self, name: &str) -> anyhow::Result<&Integration> {
        self.integrations.get(name).with_context(|| {
            let known: Vec<_> = self.integrations.keys().map(String::as_str).collect();
            format!(
                "no integration named '{name}' (configured: {})",
                known.join(", ")
            )
        })
    }
}

/// Parses durations written like "1h", "30m" or "1h 30m".
pub fn parse_duration(s: &str) -> anyhow::Result<SignedDuration> {
    let d: SignedDuration = s
        .parse()
        .with_context(|| format!("invalid duration '{s}' (try \"1h\" or \"30m\")"))?;
    if d.is_negative() || d.is_zero() {
        bail!("duration '{s}' must be positive");
    }
    Ok(d)
}

mod duration {
    use jiff::SignedDuration;
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SignedDuration, D::Error> {
        let s = String::deserialize(d)?;
        super::parse_duration(&s).map_err(serde::de::Error::custom)
    }
}

mod opt_duration {
    use jiff::SignedDuration;
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<SignedDuration>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| super::parse_duration(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_integration_kinds() {
        let config = Config::parse(
            r#"
            [integrations.acme]
            type = "aws-sso"
            start_url = "https://acme.awsapps.com/start"
            region = "eu-central-1"

            [integrations.cf]
            type = "cloudflare"
            account_id = "abc"
            ttl = "8h"

            [integrations.cf.templates.pages]
            permissions = ["Pages Write"]
            ttl = "30m"
            "#,
        )
        .unwrap();

        let Integration::AwsSso(aws) = &config.integrations["acme"] else {
            panic!()
        };
        assert_eq!(aws.scopes, ["sso:account:access"]);

        let Integration::Cloudflare(cf) = &config.integrations["cf"] else {
            panic!()
        };
        assert_eq!(cf.ttl, SignedDuration::from_hours(8));
        assert_eq!(cf.token_type, CloudflareTokenType::User);
        assert_eq!(
            cf.templates["pages"].ttl,
            Some(SignedDuration::from_mins(30))
        );
    }

    #[test]
    fn rejects_slash_in_integration_name() {
        let err = Config::parse("[integrations.\"a/b\"]\ntype = \"cloudflare\"\n").unwrap_err();
        assert!(err.to_string().contains("no '/'"));
    }

    #[test]
    fn durations() {
        assert_eq!(
            parse_duration("1h 30m").unwrap(),
            SignedDuration::from_mins(90)
        );
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("soon").is_err());
    }
}
