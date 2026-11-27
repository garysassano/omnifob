//! User configuration: the integrations to sign in to.
//!
//! Each integration type's keys live in their own module; this one holds
//! the file as a whole, the checks every type shares, and durations.

mod agent;
mod aws;
mod azure;
mod browser;
mod cloudflare;
mod command;
mod edit;
mod gcp;
mod token;

pub use self::agent::*;
pub use self::aws::*;
pub use self::azure::*;
pub use self::browser::*;
pub use self::cloudflare::*;
pub use self::command::*;
pub use self::edit::*;
pub use self::gcp::*;
pub use self::token::*;

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, bail};
use jiff::SignedDuration;
use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Browsers, or profiles of one browser, that integrations open in,
    /// keyed by the name their `browser` key refers to.
    #[serde(default)]
    pub browsers: BTreeMap<String, Browser>,
    #[serde(default)]
    pub integrations: BTreeMap<String, Integration>,
    /// What commands run by a coding agent may use.
    #[serde(default)]
    pub agent: AgentConfig,
    /// The local audit log of credentials handed out.
    #[serde(default)]
    pub audit: AuditConfig,
    /// Default profiles per directory: a directory (absolute, or starting
    /// with `~/`) and the id of the profile that `fob exec` and `fob use`
    /// pick in it, and in every directory below it, when no profile is
    /// named. The longest matching directory wins.
    #[serde(default)]
    pub directories: BTreeMap<String, String>,
}

/// An identity source: something you sign in to once and that yields many
/// profiles.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "RawIntegration")]
pub enum Integration {
    AwsSso(AwsSsoConfig),
    AwsIam(AwsIamConfig),
    AwsLogin(AwsLoginConfig),
    Gcp(GcpConfig),
    Azure(AzureConfig),
    /// Either Cloudflare type; `CloudflareConfig::sign_in` says which.
    Cloudflare(CloudflareConfig),
    Token(TokenConfig),
    Command(CommandConfig),
}

impl Integration {
    pub fn kind(&self) -> &'static str {
        match self {
            Integration::AwsSso(_) => "aws-sso",
            Integration::AwsIam(_) => "aws-iam",
            Integration::AwsLogin(_) => "aws-login",
            Integration::Gcp(_) => "gcp",
            Integration::Azure(_) => "azure",
            Integration::Cloudflare(c) => match c.sign_in {
                CloudflareSignIn::Token => "cloudflare-token",
                CloudflareSignIn::Oauth => "cloudflare-oauth",
            },
            Integration::Token(_) => "token",
            Integration::Command(_) => "command",
        }
    }

    /// The name of the browser this integration opens in, if it sets one.
    pub fn browser(&self) -> Option<&str> {
        match self {
            Integration::AwsSso(c) => c.browser.as_deref(),
            Integration::AwsIam(c) => c.browser.as_deref(),
            Integration::AwsLogin(c) => c.browser.as_deref(),
            Integration::Gcp(c) => c.browser.as_deref(),
            Integration::Azure(c) => c.browser.as_deref(),
            Integration::Cloudflare(c) => c.browser.as_deref(),
            Integration::Token(c) => c.browser.as_deref(),
            Integration::Command(c) => c.browser.as_deref(),
        }
    }
}

/// The schema of an integration is that of the table written in the config
/// file, [`RawIntegration`], which it is converted from.
#[cfg(test)]
impl schemars::JsonSchema for Integration {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Integration".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        RawIntegration::json_schema(generator)
    }
}

/// The `type` values as written in the config file. Both Cloudflare types
/// share one configuration and differ only in how omnifob signs in.
#[derive(Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(tag = "type", rename_all = "kebab-case")]
enum RawIntegration {
    AwsSso(AwsSsoConfig),
    AwsIam(AwsIamConfig),
    AwsLogin(AwsLoginConfig),
    Gcp(GcpConfig),
    Azure(AzureConfig),
    CloudflareToken(CloudflareConfig),
    CloudflareOauth(CloudflareConfig),
    Token(TokenConfig),
    Command(CommandConfig),
}

impl TryFrom<RawIntegration> for Integration {
    type Error = String;

    fn try_from(raw: RawIntegration) -> Result<Self, Self::Error> {
        Ok(match raw {
            RawIntegration::AwsSso(c) => {
                c.validate()?;
                Integration::AwsSso(c)
            }
            RawIntegration::AwsIam(c) => {
                c.validate()?;
                Integration::AwsIam(c)
            }
            RawIntegration::AwsLogin(c) => {
                c.validate()?;
                Integration::AwsLogin(c)
            }
            RawIntegration::Gcp(c) => {
                c.validate()?;
                Integration::Gcp(c)
            }
            RawIntegration::Azure(c) => Integration::Azure(c),
            RawIntegration::Token(c) => {
                c.validate()?;
                Integration::Token(c)
            }
            RawIntegration::Command(c) => {
                c.validate()?;
                Integration::Command(c)
            }
            RawIntegration::CloudflareToken(c) => {
                if c.client_id.is_some() || c.scopes.is_some() {
                    return Err(
                        "client_id and scopes belong to type = \"cloudflare-oauth\"".to_string()
                    );
                }
                c.validate()?;
                Integration::Cloudflare(c)
            }
            RawIntegration::CloudflareOauth(mut c) => {
                if c.token_type != CloudflareTokenType::default() {
                    return Err("token_type only applies to type = \"cloudflare-token\"; \
                         cloudflare-oauth mints account-owned tokens"
                        .to_string());
                }
                c.sign_in = CloudflareSignIn::Oauth;
                c.validate()?;
                Integration::Cloudflare(c)
            }
        })
    }
}

/// Fails when two configured entries, given as `(table, label, leaf)`,
/// would get the same profile id `<integration>/<slug of label>/<leaf>`,
/// naming both keys.
fn check_unique_ids<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a String, &'a str)>,
) -> Result<(), String> {
    let mut seen: BTreeMap<String, (&str, &String)> = BTreeMap::new();
    for (table, label, leaf) in entries {
        let id = format!("{}/{leaf}", crate::profile::slug(label));
        if let Some((other_table, other_label)) = seen.insert(id.clone(), (table, label)) {
            return Err(format!(
                "{other_table}.{other_label} and {table}.{label} would both be the profile \
                 <integration>/{id}; rename one of them"
            ));
        }
    }
    Ok(())
}

/// Fails unless `value` is an `https://` URL with a host, naming the key.
pub(crate) fn check_https_url(key: &str, value: &str) -> Result<(), String> {
    let url = parse_url(key, value)?;
    if url.scheme() != "https" {
        return Err(format!("{key} '{value}' must be an https:// URL"));
    }
    Ok(())
}

/// `value` as an absolute `http(s)://` URL with a host, naming the key.
fn parse_url(key: &str, value: &str) -> Result<reqwest::Url, String> {
    let url =
        reqwest::Url::parse(value).map_err(|e| format!("{key} '{value}' is not a URL: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none_or(str::is_empty) {
        return Err(format!(
            "{key} '{value}' must be an http:// or https:// URL"
        ));
    }
    Ok(url)
}

impl Config {
    /// Loads the config file; a missing file is an empty config.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        Self::load_with(path, Self::parse)
    }

    /// Loads the config file without checking integration names, for
    /// `fob rename`, which has to open a config with a name that breaks the
    /// rule in order to fix it.
    pub fn load_allowing_any_names(path: &Path) -> anyhow::Result<Self> {
        Self::load_with(path, Self::parse_allowing_any_names)
    }

    fn load_with(path: &Path, parse: fn(&str) -> anyhow::Result<Self>) -> anyhow::Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        parse(&text).map_err(|e| {
            crate::Coded::wrap(
                crate::Code::ConfigInvalid,
                format!("parsing {}", path.display()),
                e,
            )
            .with("path", path.display().to_string())
            .into()
        })
    }

    /// Parses a config. Integration names may contain only letters, digits,
    /// `.`, `_` and `-` (see [`check_name`]); the error for another name says
    /// how to rename it.
    ///
    /// ```
    /// use omnifob_core::{Config, Integration};
    ///
    /// let config = Config::parse(
    ///     r#"
    ///     [integrations.acme]
    ///     type = "aws-sso"
    ///     start_url = "https://acme.awsapps.com/start"
    ///     region = "eu-west-1"
    ///     "#,
    /// )?;
    /// assert!(matches!(config.integration("acme")?, Integration::AwsSso(_)));
    ///
    /// // Every key is checked as the config loads, and the error names it.
    /// let err = Config::parse(
    ///     "[integrations.acme]\ntype = \"aws-sso\"\nstart_url = \"http://acme\"\nregion = \"eu-west-1\"",
    /// )
    /// .unwrap_err();
    /// assert!(format!("{err:#}").contains("start_url"));
    /// # anyhow::Ok(())
    /// ```
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let config = Self::parse_allowing_any_names(text)?;
        for name in config.integrations.keys() {
            if let Err(e) = check_name("integration name", name) {
                bail!("{e}; rename it with `fob rename \"{name}\" <new-name>`");
            }
        }
        Ok(config)
    }

    /// Parses a config without checking integration names.
    pub fn parse_allowing_any_names(text: &str) -> anyhow::Result<Self> {
        let config: Self = toml::from_str(text)?;
        if let Err(e) = config.agent.validate() {
            bail!("[agent] {e}");
        }
        for (dir, profile) in &config.directories {
            if let Err(e) = check_directory(dir, profile) {
                bail!("[directories] {e}");
            }
        }
        for (name, browser) in &config.browsers {
            if let Err(e) = browser.validate() {
                bail!("browser '{name}': {e}");
            }
        }
        for (name, integration) in &config.integrations {
            if let Some(browser) = integration.browser()
                && !config.browsers.contains_key(browser)
            {
                let known: Vec<_> = config.browsers.keys().map(String::as_str).collect();
                bail!(
                    "integration '{name}' opens in browser '{browser}', which [browsers] does not define (defined: {})",
                    if known.is_empty() {
                        "none".to_string()
                    } else {
                        known.join(", ")
                    }
                );
            }
        }
        Ok(config)
    }

    /// The browser that integration `name` opens in, or `None` for the
    /// system's default browser.
    pub fn browser_for(&self, name: &str) -> anyhow::Result<Option<&Browser>> {
        Ok(self
            .integration(name)?
            .browser()
            .and_then(|browser| self.browsers.get(browser)))
    }

    /// The default profile for directory `cwd` from `[directories]`: the
    /// entry of the longest directory that is `cwd` or contains it, with the
    /// directory as written. `~` stands for `home`. Directories compare by
    /// whole components, and also as their real path when they hold a
    /// symbolic link, since the working directory has none.
    pub fn directory_profile(&self, cwd: &Path, home: Option<&Path>) -> Option<(&str, &str)> {
        self.directories
            .iter()
            .filter_map(|(dir, profile)| {
                let path = match dir.strip_prefix('~') {
                    Some(rest) => home?.join(rest.trim_start_matches(['/', '\\'])),
                    None => std::path::PathBuf::from(dir),
                };
                let real = std::fs::canonicalize(&path).ok();
                let depth = [Some(path), real]
                    .into_iter()
                    .flatten()
                    .filter(|p| cwd.starts_with(p))
                    .map(|p| p.components().count())
                    .max()?;
                Some((depth, dir.as_str(), profile.as_str()))
            })
            .max_by_key(|(depth, ..)| *depth)
            .map(|(_, dir, profile)| (dir, profile))
    }

    pub fn integration(&self, name: &str) -> anyhow::Result<&Integration> {
        self.integrations.get(name).ok_or_else(|| {
            let known: Vec<_> = self.integrations.keys().map(String::as_str).collect();
            crate::Coded::new(
                crate::Code::IntegrationNotFound,
                format!(
                    "no integration named '{name}' (configured: {})",
                    known.join(", ")
                ),
            )
            .with("integration", name)
            .with("configured", known)
            .into()
        })
    }
}

/// Fails unless a `[directories]` entry names an absolute directory, or
/// one under `~/`, and a profile id.
fn check_directory(dir: &str, profile: &str) -> Result<(), String> {
    let home_relative = dir == "~" || dir.starts_with("~/") || dir.starts_with("~\\");
    if !home_relative && !Path::new(dir).is_absolute() {
        return Err(format!(
            "'{dir}' must be an absolute directory or start with ~/"
        ));
    }
    if profile.is_empty() || profile.split('/').any(str::is_empty) {
        return Err(format!(
            "'{dir}' must name a profile id, such as \"acme/prod/ReadOnly\""
        ));
    }
    Ok(())
}

/// Fails unless `name` is non-empty, made of ASCII letters, digits, `.`, `_`
/// and `-`, and does not start with `-` (the command line would read it as
/// an option). Integration names go into profile ids, the AWS config's
/// `credential_process` lines, keychain keys, lock files and the WSL vault's
/// file names; template names into profile ids.
pub fn check_name(what: &str, name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        bail!("{what} must not be empty");
    }
    if name.starts_with('-') {
        bail!("{what} '{name}' must not start with '-'");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        bail!("{what} '{name}' may contain only letters, digits, '.', '_' and '-'");
    }
    Ok(())
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
    use serde::{Deserialize, Deserializer, Serializer};

    /// Written the way it is read, as "1h" or "30m" (the schema's default).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn serialize<S: Serializer>(d: &SignedDuration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{d:#}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SignedDuration, D::Error> {
        let s = String::deserialize(d)?;
        super::parse_duration(&s).map_err(serde::de::Error::custom)
    }
}

mod opt_duration {
    use jiff::SignedDuration;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Written the way it is read, as "1h" or "30m".
    pub fn serialize<S: Serializer>(d: &Option<SignedDuration>, s: S) -> Result<S::Ok, S::Error> {
        match d {
            Some(d) => s.serialize_str(&format!("{d:#}")),
            None => s.serialize_none(),
        }
    }

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
    fn integration_names_are_letters_digits_dots_underscores_and_hyphens() {
        let parse = |name: &str| {
            Config::parse(&format!(
                "[integrations.\"{name}\"]\ntype = \"cloudflare-token\"\n"
            ))
        };
        assert!(parse("Acme_prod-2.eu").is_ok());
        for bad in ["a/b", "a b", "a\"b", "é", "a:b", "", "-a"] {
            let err = parse(&bad.replace('"', "\\\"")).unwrap_err().to_string();
            assert!(err.contains("fob rename"), "{bad}: {err}");
        }
        let err = parse("my portal").unwrap_err().to_string();
        assert_eq!(
            err,
            "integration name 'my portal' may contain only letters, digits, '.', '_' and '-'; \
             rename it with `fob rename \"my portal\" <new-name>`"
        );
        // `fob rename` reads such a config to fix it.
        let text = "[integrations.\"my portal\"]\ntype = \"cloudflare-token\"\n\n[integrations.\"b c\"]\ntype = \"cloudflare-token\"\n";
        assert!(Config::parse_allowing_any_names(text).is_ok());
        let renamed = rename_integration(text, "my portal", "portal").unwrap();
        assert!(renamed.contains("[integrations.portal]"), "{renamed}");
        assert!(Config::parse(&renamed).is_err(), "'b c' is still to fix");
        let renamed = rename_integration(&renamed, "b c", "b-c").unwrap();
        assert!(Config::parse(&renamed).is_ok());
    }

    #[test]
    fn directories_pick_a_default_profile_by_longest_prefix() {
        let root = std::env::temp_dir().join(format!("omnifob-dirs-{}", std::process::id()));
        let home = root.join("home");
        std::fs::create_dir_all(home.join("git/acme/api")).unwrap();
        let text = format!(
            r#"
            [directories]
            "~/git/acme" = "acme/dev/Admin"
            "~/git/acme/api" = "acme/prod/ReadOnly"
            "{}" = "cf/personal/workers"
            "#,
            root.join("other").display().to_string().replace('\\', "/")
        );
        let config = Config::parse(&text).unwrap();
        let pick = |cwd: &Path| config.directory_profile(cwd, Some(&home)).map(|(_, p)| p);
        assert_eq!(pick(&home.join("git/acme")), Some("acme/dev/Admin"));
        assert_eq!(pick(&home.join("git/acme/web/src")), Some("acme/dev/Admin"));
        assert_eq!(
            pick(&home.join("git/acme/api/src")),
            Some("acme/prod/ReadOnly")
        );
        // Whole components only: acme-old is not under acme.
        assert_eq!(pick(&home.join("git/acme-old")), None);
        assert_eq!(pick(&root.join("other/x")), Some("cf/personal/workers"));
        // Without a home directory, `~` entries match nothing.
        assert_eq!(config.directory_profile(&home.join("git/acme"), None), None);
        #[cfg(unix)]
        {
            // A configured directory that is a symbolic link matches its target.
            std::os::unix::fs::symlink(home.join("git"), home.join("code")).unwrap();
            let linked =
                Config::parse("[directories]\n\"~/code/acme\" = \"acme/dev/Admin\"\n").unwrap();
            // The working directory as the OS reports it, with links
            // resolved: macOS's temporary directory is under a link.
            let cwd = std::fs::canonicalize(home.join("git/acme"))
                .unwrap()
                .join("x");
            assert_eq!(
                linked.directory_profile(&cwd, Some(&home)),
                Some(("~/code/acme", "acme/dev/Admin"))
            );
        }
        std::fs::remove_dir_all(&root).unwrap();

        for (entry, message) in [
            ("\"git/acme\" = \"a/b/c\"", "must be an absolute directory"),
            ("\"~/x\" = \"\"", "must name a profile id"),
            ("\"~/x\" = \"a//c\"", "must name a profile id"),
        ] {
            let error = parse_error(&format!("[directories]\n{entry}\n"));
            assert!(error.contains(message), "{entry}: {error}");
        }
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

    /// The error a config made of `text` fails with, with its causes.
    pub(super) fn parse_error(text: &str) -> String {
        format!("{:#}", Config::parse(text).unwrap_err())
    }

    /// The JSON Schema published for editors and taplo, generated from the
    /// types the config is read into, so it cannot drift from them.
    fn config_schema() -> String {
        let schema = schemars::generate::SchemaSettings::draft07()
            .into_generator()
            .into_root_schema_for::<Config>();
        let mut value = serde_json::to_value(&schema).unwrap();
        without_null(&mut value);
        let object = value.as_object_mut().unwrap();
        object.insert(
            "$id".into(),
            "https://raw.githubusercontent.com/garysassano/omnifob/main/schema/config.schema.json"
                .into(),
        );
        object.insert("title".into(), "omnifob config.toml".into());
        serde_json::to_string_pretty(&value).unwrap() + "\n"
    }

    /// Takes `null` out of a schema: TOML has none, and an optional key is
    /// one that may be left out, which `required` already says.
    fn without_null(value: &mut serde_json::Value) {
        use serde_json::Value;
        match value {
            Value::Object(object) => {
                if object.get("default") == Some(&Value::Null) {
                    object.remove("default");
                }
                if let Some(Value::Array(types)) = object.get_mut("type") {
                    types.retain(|t| t != "null");
                    if let [only] = types.as_slice() {
                        let only = only.clone();
                        object.insert("type".into(), only);
                    }
                }
                if let Some(Value::Array(any)) = object.get_mut("anyOf") {
                    any.retain(|s| s.get("type").is_none_or(|t| t != "null"));
                    if let [only] = any.as_slice() {
                        let only = only.as_object().cloned().unwrap_or_default();
                        object.remove("anyOf");
                        object.extend(only);
                    }
                }
                object.values_mut().for_each(without_null);
            }
            Value::Array(items) => items.iter_mut().for_each(without_null),
            _ => {}
        }
    }

    #[test]
    fn the_published_schema_matches_the_config() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schema/config.schema.json");
        let schema = config_schema();
        if std::env::var_os("OMNIFOB_WRITE_SCHEMA").is_some() {
            std::fs::write(&path, &schema).unwrap();
        }
        let published = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            published.replace("\r\n", "\n") == schema,
            "schema/config.schema.json is out of date; regenerate it with \
             `OMNIFOB_WRITE_SCHEMA=1 cargo test -p omnifob-core --lib published_schema`"
        );
    }
}
