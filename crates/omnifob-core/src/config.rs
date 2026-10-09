//! User configuration: the integrations to sign in to.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, bail};
use jiff::SignedDuration;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub integrations: BTreeMap<String, Integration>,
}

/// An identity source: something you sign in to once and that yields many
/// profiles.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "RawIntegration")]
pub enum Integration {
    AwsSso(AwsSsoConfig),
    /// Either Cloudflare type; `CloudflareConfig::sign_in` says which.
    Cloudflare(CloudflareConfig),
    Token(TokenConfig),
}

impl Integration {
    pub fn kind(&self) -> &'static str {
        match self {
            Integration::AwsSso(_) => "aws-sso",
            Integration::Cloudflare(c) => match c.sign_in {
                CloudflareSignIn::Token => "cloudflare-token",
                CloudflareSignIn::Oauth => "cloudflare-oauth",
            },
            Integration::Token(_) => "token",
        }
    }
}

/// The `type` values as written in the config file. Both Cloudflare types
/// share one configuration and differ only in how omnifob signs in.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum RawIntegration {
    AwsSso(AwsSsoConfig),
    CloudflareToken(CloudflareConfig),
    CloudflareOauth(CloudflareConfig),
    Token(TokenConfig),
}

impl TryFrom<RawIntegration> for Integration {
    type Error = String;

    fn try_from(raw: RawIntegration) -> Result<Self, Self::Error> {
        Ok(match raw {
            RawIntegration::AwsSso(c) => Integration::AwsSso(c),
            RawIntegration::Token(c) => Integration::Token(c),
            RawIntegration::CloudflareToken(c) => {
                if c.client_id.is_some() || c.scopes.is_some() {
                    return Err(
                        "client_id and scopes belong to type = \"cloudflare-oauth\"".to_string()
                    );
                }
                Integration::Cloudflare(c)
            }
            RawIntegration::CloudflareOauth(mut c) => {
                if c.token_type != CloudflareTokenType::default() {
                    return Err("token_type only applies to type = \"cloudflare-token\"; \
                         cloudflare-oauth mints account-owned tokens"
                        .to_string());
                }
                c.sign_in = CloudflareSignIn::Oauth;
                Integration::Cloudflare(c)
            }
        })
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
    /// Roles reached by assuming them from one of this portal's roles
    /// (`role_arn` + `source_profile` in `~/.aws/config`), keyed by a label
    /// that becomes the middle of the profile id.
    #[serde(default)]
    pub chained: BTreeMap<String, ChainedRole>,
}

/// A role assumed with the credentials of an Identity Center role.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChainedRole {
    /// Account of the Identity Center role to start from.
    pub via_account_id: String,
    /// Name of the Identity Center role (permission set) to start from.
    pub via_role: String,
    pub role_arn: String,
    /// `RoleSessionName`; defaults to "omnifob".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// Region exported for this role; defaults to the integration's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

impl ChainedRole {
    /// The role name at the end of `role_arn` (after any path).
    pub fn role_name(&self) -> &str {
        self.role_arn.rsplit('/').next().unwrap_or(&self.role_arn)
    }

    /// The account in `role_arn`.
    pub fn account_id(&self) -> Option<&str> {
        self.role_arn.split(':').nth(4).filter(|a| !a.is_empty())
    }
}

fn default_sso_scopes() -> Vec<String> {
    vec!["sso:account:access".to_string()]
}

/// Long-lived tokens for providers without short-lived credentials.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenConfig {
    /// A known provider: its variable names, token check and console URL.
    #[serde(default)]
    pub preset: Option<String>,
    /// Secret name → environment variables that receive it; replaces the
    /// preset's secrets.
    #[serde(default)]
    pub secrets: BTreeMap<String, Vec<String>>,
    /// Non-secret variables exported along with the secrets.
    #[serde(default)]
    pub vars: BTreeMap<String, String>,
    /// Middle segment of the profile id; defaults to "default".
    #[serde(default)]
    pub account: Option<String>,
    #[serde(default)]
    pub console: Option<String>,
    /// URL that answers 2xx when the token is sent as a bearer token.
    #[serde(default)]
    pub verify_url: Option<String>,
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
    /// Addresses minted tokens may be used from, unless a template sets its
    /// own: IPs or CIDR ranges, or "current" for this machine's public
    /// addresses at minting time. Empty means anywhere.
    #[serde(default)]
    pub ips: Vec<String>,
    /// Sign-in session length. When set, `fob login` makes the new bootstrap
    /// token expire after this long, so it works like an SSO session: a
    /// stolen copy stops working, and a new one needs the dashboard sign-in.
    #[serde(default, with = "opt_duration")]
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTemplate {
    pub permissions: Vec<String>,
    /// Permissions added when the account offers them and skipped otherwise,
    /// for products that are new, renamed or not enabled everywhere.
    #[serde(default)]
    pub optional: Vec<String>,
    #[serde(default, with = "opt_duration")]
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

/// Renames an integration in the text of a config file, keeping comments,
/// layout and its sub-tables (chained roles, templates).
pub fn rename_integration(text: &str, old: &str, new: &str) -> anyhow::Result<String> {
    if new.is_empty() || new.contains('/') {
        bail!("integration name '{new}' must be non-empty and contain no '/'");
    }
    let mut doc: toml_edit::DocumentMut = text.parse().context("parsing the config")?;
    let integrations = doc
        .get_mut("integrations")
        .and_then(|i| i.as_table_mut())
        .context("the config has no [integrations] table")?;
    if integrations.contains_key(new) {
        bail!("an integration named '{new}' already exists");
    }
    let (key, item) = integrations
        .remove_entry(old)
        .with_context(|| format!("no integration named '{old}'"))?;
    let renamed = toml_edit::Key::new(new)
        .with_leaf_decor(key.leaf_decor().clone())
        .with_dotted_decor(key.dotted_decor().clone());
    integrations.insert_formatted(&renamed, item);
    let text = doc.to_string();
    Config::parse(&text).context("the renamed config is not valid")?;
    Ok(text)
}

/// Adds a template to a Cloudflare integration in the config text, keeping
/// the rest of the file as it is. An existing template of that name is
/// replaced only with `replace`.
pub fn add_cloudflare_template(
    text: &str,
    integration: &str,
    name: &str,
    template: &CloudflareTemplate,
    replace: bool,
) -> anyhow::Result<String> {
    if name.is_empty() || name.contains('/') {
        bail!("template name '{name}' must be non-empty and contain no '/'");
    }
    let mut doc: toml_edit::DocumentMut = text.parse().context("parsing the config")?;
    let table = doc
        .get_mut("integrations")
        .and_then(|i| i.get_mut(integration))
        .and_then(|i| i.as_table_mut())
        .with_context(|| format!("no integration named '{integration}'"))?;
    if table
        .get("type")
        .and_then(|t| t.as_str())
        .is_none_or(|t| !t.starts_with("cloudflare-"))
    {
        bail!("'{integration}' is not a cloudflare integration");
    }
    let templates = table
        .entry("templates")
        .or_insert_with(|| {
            let mut t = toml_edit::Table::new();
            t.set_implicit(true);
            toml_edit::Item::Table(t)
        })
        .as_table_mut()
        .context("`templates` must be a table")?;
    if templates.contains_key(name) && !replace {
        bail!("integration '{integration}' already has a template named '{name}'");
    }
    let mut new = toml_edit::Table::new();
    new["permissions"] =
        toml_edit::value(template.permissions.iter().collect::<toml_edit::Array>());
    if !template.optional.is_empty() {
        new["optional"] = toml_edit::value(template.optional.iter().collect::<toml_edit::Array>());
    }
    if let Some(ttl) = template.ttl {
        new["ttl"] = toml_edit::value(format!("{ttl:#}"));
    }
    if !template.r2_buckets.is_empty() {
        new["r2_buckets"] =
            toml_edit::value(template.r2_buckets.iter().collect::<toml_edit::Array>());
    }
    if template.s3 {
        new["s3"] = toml_edit::value(true);
    }
    if let Some(ips) = &template.ips {
        new["ips"] = toml_edit::value(ips.iter().collect::<toml_edit::Array>());
    }
    templates.insert(name, toml_edit::Item::Table(new));
    let text = doc.to_string();
    Config::parse(&text).context("the new template does not make a valid config")?;
    Ok(text)
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
            type = "cloudflare-token"
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
        let err =
            Config::parse("[integrations.\"a/b\"]\ntype = \"cloudflare-token\"\n").unwrap_err();
        assert!(err.to_string().contains("no '/'"));
    }

    #[test]
    fn renames_keep_comments_order_and_subtables() {
        let text = "# mine\n[integrations.gary] # personal\ntype = \"aws-sso\"\nstart_url = \"https://a.awsapps.com/start\"\nregion = \"eu-west-1\"\n\n[integrations.gary.chained.lab]\nvia_account_id = \"1\"\nvia_role = \"A\"\nrole_arn = \"arn:aws:iam::2:role/R\"\n\n[integrations.cf]\ntype = \"cloudflare-token\"\n";
        let renamed = rename_integration(text, "gary", "aws").unwrap();
        assert_eq!(
            renamed,
            text.replace("integrations.gary", "integrations.aws")
        );
        assert!(
            rename_integration(text, "gary", "cf")
                .unwrap_err()
                .to_string()
                .contains("already exists")
        );
        assert!(
            rename_integration(text, "nope", "x")
                .unwrap_err()
                .to_string()
                .contains("no integration")
        );
        assert!(rename_integration(text, "gary", "a/b").is_err());
    }

    #[test]
    fn adds_cloudflare_templates() {
        let text = "# mine\n[integrations.cf] # work\ntype = \"cloudflare-token\"\n\n[integrations.gary]\ntype = \"aws-sso\"\nstart_url = \"https://a.awsapps.com/start\"\nregion = \"eu-west-1\"\n";
        let template = CloudflareTemplate {
            permissions: vec!["Pages Write".into(), "Zone Read".into()],
            optional: vec![],
            ttl: Some(SignedDuration::from_mins(90)),
            ..Default::default()
        };
        let added = add_cloudflare_template(text, "cf", "pages", &template, false).unwrap();
        assert!(
            added.starts_with("# mine\n[integrations.cf] # work\n"),
            "{added}"
        );
        let config = Config::parse(&added).unwrap();
        let Integration::Cloudflare(cf) = config.integration("cf").unwrap() else {
            panic!("not cloudflare");
        };
        assert_eq!(cf.templates["pages"], template);
        let err = |r: anyhow::Result<String>| r.unwrap_err().to_string();
        assert!(
            err(add_cloudflare_template(
                &added, "cf", "pages", &template, false
            ))
            .contains("already has")
        );
        assert!(add_cloudflare_template(&added, "cf", "pages", &template, true).is_ok());
        assert!(
            err(add_cloudflare_template(text, "gary", "x", &template, false))
                .contains("not a cloudflare")
        );
        assert!(
            err(add_cloudflare_template(text, "nope", "x", &template, false))
                .contains("no integration")
        );
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
}
