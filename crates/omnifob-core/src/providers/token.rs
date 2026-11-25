//! Long-lived tokens for providers that cannot mint short-lived ones
//! (Hetzner, DigitalOcean, Vultr, Upstash...).
//!
//! Their own CLIs keep these tokens in plain-text config files. omnifob keeps
//! them in the keychain, checks them at sign-in where the provider allows it,
//! and exports them under every variable name the provider's tools read.

use std::collections::BTreeMap;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

use crate::config::TokenConfig;
use crate::{Credentials, Error, Profile, Result, Target, store};

/// What omnifob knows about a provider: which variables its tools read, how
/// to check a token, and where its console is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preset {
    pub name: &'static str,
    /// Secret name → environment variables that receive it.
    pub secrets: &'static [(&'static str, &'static [&'static str])],
    /// Fixed variables the provider's tools need alongside the secrets;
    /// the integration's `vars` override them, and a `secrets` table
    /// replaces them together with the preset's secrets.
    pub vars: &'static [(&'static str, &'static str)],
    /// How to check the secrets with the provider, when it has a call every
    /// valid token may make.
    pub verify: Option<Verify>,
    pub console: Option<&'static str>,
}

/// A call that succeeds only with a valid token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verify {
    /// The URL to `GET`. `{name}` stands for the secret `name`,
    /// percent-encoded (Scaleway's access key).
    pub url: &'static str,
    /// The secret that authenticates the call.
    pub secret: &'static str,
    pub scheme: AuthScheme,
    /// Whether a 403 still proves the token valid: Scaleway answers 401 for
    /// an unknown key and 403 for a key whose policies do not cover the
    /// call.
    pub forbidden_is_valid: bool,
}

/// How a token check sends the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthScheme {
    /// `Authorization: Bearer <secret>`.
    Bearer,
    /// `<header>: <secret>`, as Scaleway's `X-Auth-Token`.
    Header(&'static str),
    /// HTTP Basic with the value of the variable `user_var` from the
    /// integration's `vars` as the user and the secret as the password, as
    /// Upstash's API takes the account email and API key.
    Basic { user_var: &'static str },
}

const fn bearer(url: &'static str, secret: &'static str) -> Option<Verify> {
    Some(Verify {
        url,
        secret,
        scheme: AuthScheme::Bearer,
        forbidden_is_valid: false,
    })
}

pub const PRESETS: &[Preset] = &[
    Preset {
        name: "hetzner",
        secrets: &[("token", &["HCLOUD_TOKEN"])],
        vars: &[],
        verify: bearer("https://api.hetzner.cloud/v1/locations", "token"),
        console: Some("https://console.hetzner.cloud/projects"),
    },
    Preset {
        name: "digitalocean",
        // doctl reads the first, Terraform's provider the second.
        secrets: &[(
            "token",
            &["DIGITALOCEAN_ACCESS_TOKEN", "DIGITALOCEAN_TOKEN"],
        )],
        vars: &[],
        verify: bearer("https://api.digitalocean.com/v2/account", "token"),
        console: Some("https://cloud.digitalocean.com"),
    },
    Preset {
        name: "vultr",
        secrets: &[("api_key", &["VULTR_API_KEY"])],
        vars: &[],
        verify: bearer("https://api.vultr.com/v2/account", "api_key"),
        console: Some("https://my.vultr.com"),
    },
    Preset {
        name: "linode",
        // Akamai Cloud. linode-cli reads the second, Terraform the first.
        secrets: &[("token", &["LINODE_TOKEN", "LINODE_CLI_TOKEN"])],
        vars: &[],
        verify: bearer("https://api.linode.com/v4/profile", "token"),
        console: Some("https://cloud.linode.com"),
    },
    Preset {
        name: "upstash",
        // Set UPSTASH_EMAIL under `vars`; the API key is the secret. The
        // Developer API takes both as HTTP Basic credentials, as the
        // Upstash CLI sends them.
        secrets: &[("api_key", &["UPSTASH_API_KEY"])],
        vars: &[],
        verify: Some(Verify {
            url: "https://api.upstash.com/v2/redis/databases",
            secret: "api_key",
            scheme: AuthScheme::Basic {
                user_var: "UPSTASH_EMAIL",
            },
            forbidden_is_valid: false,
        }),
        console: Some("https://console.upstash.com"),
    },
    Preset {
        name: "akamai-edgegrid",
        secrets: &[
            ("client_token", &["AKAMAI_CLIENT_TOKEN"]),
            ("client_secret", &["AKAMAI_CLIENT_SECRET"]),
            ("access_token", &["AKAMAI_ACCESS_TOKEN"]),
        ],
        vars: &[],
        verify: None,
        console: Some("https://control.akamai.com"),
    },
    Preset {
        name: "scaleway",
        secrets: &[
            ("access_key", &["SCW_ACCESS_KEY"]),
            ("secret_key", &["SCW_SECRET_KEY"]),
        ],
        vars: &[],
        // The call `scw init` makes to look the key up: the secret key in
        // `X-Auth-Token`, the access key in the path. A key whose policies
        // do not allow reading API keys gets 403, which still proves it.
        verify: Some(Verify {
            url: "https://api.scaleway.com/iam/v1alpha1/api-keys/{access_key}",
            secret: "secret_key",
            scheme: AuthScheme::Header("X-Auth-Token"),
            forbidden_is_valid: true,
        }),
        console: Some("https://console.scaleway.com"),
    },
    Preset {
        name: "modal",
        // The Modal client reads both, overriding `~/.modal.toml`. Its API is
        // gRPC only, so there is no plain URL to check the token against.
        secrets: &[
            ("token_id", &["MODAL_TOKEN_ID"]),
            ("token_secret", &["MODAL_TOKEN_SECRET"]),
        ],
        vars: &[],
        verify: None,
        console: Some("https://modal.com/apps"),
    },
    Preset {
        name: "unikraft",
        // Unikraft Cloud: `kraft` reads UKC_TOKEN and UKC_METRO; the newer
        // `unikraft` CLI reads them only when UNIKRAFT_PROFILE_ENV is true.
        // Set UKC_METRO under `vars`.
        secrets: &[("token", &["UKC_TOKEN"])],
        vars: &[("UNIKRAFT_PROFILE_ENV", "true")],
        verify: bearer("https://controlplane.unikraft.cloud/v1/auth", "token"),
        console: Some("https://console.unikraft.com"),
    },
    Preset {
        name: "vercel",
        secrets: &[("token", &["VERCEL_TOKEN"])],
        vars: &[],
        verify: bearer("https://api.vercel.com/v2/user", "token"),
        console: Some("https://vercel.com/dashboard"),
    },
    Preset {
        name: "netlify",
        secrets: &[("token", &["NETLIFY_AUTH_TOKEN"])],
        vars: &[],
        verify: bearer("https://api.netlify.com/api/v1/user", "token"),
        console: Some("https://app.netlify.com"),
    },
    Preset {
        name: "fly",
        // No check: Fly.io has no call that every token may make. Deploy
        // tokens are limited to one app, listing apps needs an organization
        // slug, and flyctl's `fly auth whoami` asks GraphQL for the user,
        // which an app's token has none of.
        secrets: &[("token", &["FLY_API_TOKEN"])],
        vars: &[],
        verify: None,
        console: Some("https://fly.io/dashboard"),
    },
    Preset {
        name: "neon",
        secrets: &[("api_key", &["NEON_API_KEY"])],
        vars: &[],
        verify: bearer("https://console.neon.tech/api/v2/users/me", "api_key"),
        console: Some("https://console.neon.tech"),
    },
    Preset {
        name: "supabase",
        secrets: &[("token", &["SUPABASE_ACCESS_TOKEN"])],
        vars: &[],
        verify: bearer("https://api.supabase.com/v1/projects", "token"),
        console: Some("https://supabase.com/dashboard"),
    },
    Preset {
        name: "github",
        // gh prefers GH_TOKEN; most other tools read GITHUB_TOKEN.
        secrets: &[("token", &["GH_TOKEN", "GITHUB_TOKEN"])],
        vars: &[],
        verify: bearer("https://api.github.com/user", "token"),
        console: Some("https://github.com"),
    },
];

pub fn preset(name: &str) -> anyhow::Result<&'static Preset> {
    PRESETS.iter().find(|p| p.name == name).with_context(|| {
        let names: Vec<_> = PRESETS.iter().map(|p| p.name).collect();
        format!(
            "unknown token preset '{name}' (known: {})",
            names.join(", ")
        )
    })
}

/// The secrets of an integration and the variables each one fills, from the
/// config's `secrets` or else its preset.
pub fn secrets(config: &TokenConfig) -> anyhow::Result<Vec<(String, Vec<String>)>> {
    if !config.secrets.is_empty() {
        return Ok(config
            .secrets
            .iter()
            .map(|(name, vars)| (name.clone(), vars.clone()))
            .collect());
    }
    let Some(name) = &config.preset else {
        bail!("a token integration needs a `preset` or a `secrets` table");
    };
    Ok(preset(name)?
        .secrets
        .iter()
        .map(|(name, vars)| {
            (
                name.to_string(),
                vars.iter().map(|v| v.to_string()).collect(),
            )
        })
        .collect())
}

fn secrets_key(integration: &str) -> String {
    format!("token/{integration}/secrets")
}

/// Not `Debug`: it holds the secret values.
#[derive(Default, Serialize, Deserialize)]
struct Stored(BTreeMap<String, String>);

/// Checks the values where the preset allows it, then stores them.
pub async fn login(
    integration: &str,
    config: &TokenConfig,
    values: BTreeMap<String, String>,
) -> anyhow::Result<()> {
    let expected: Vec<String> = secrets(config)?.into_iter().map(|(name, _)| name).collect();
    for name in &expected {
        if values.get(name).is_none_or(|v| v.trim().is_empty()) {
            bail!("missing a value for '{name}'");
        }
    }
    let values: BTreeMap<String, String> = values
        .into_iter()
        .map(|(k, v)| (k, v.trim().to_string()))
        .collect();
    if let Some(check) = verification(config)? {
        match verify(&check, &values, &config.vars).await? {
            Verified::Accepted(_) => {}
            Verified::Skipped(why) => tracing::warn!("the token was not checked: {why}"),
        }
    }
    store::set(&secrets_key(integration), &Stored(values))
}

/// How an integration's token is checked: `verify_url` with the one secret
/// as a bearer token, else the preset's check when the integration has the
/// secrets it uses (a `secrets` table may name others).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Check {
    pub url: String,
    pub secret: String,
    pub scheme: AuthScheme,
    pub forbidden_is_valid: bool,
}

pub(crate) fn verification(config: &TokenConfig) -> anyhow::Result<Option<Check>> {
    let names: Vec<String> = secrets(config)?.into_iter().map(|(name, _)| name).collect();
    if let Some(url) = &config.verify_url {
        let [only] = names.as_slice() else {
            return Ok(None);
        };
        return Ok(Some(Check {
            url: url.clone(),
            secret: only.clone(),
            scheme: AuthScheme::Bearer,
            forbidden_is_valid: false,
        }));
    }
    let Some(verify) = config
        .preset
        .as_deref()
        .map(preset)
        .transpose()?
        .and_then(|p| p.verify)
    else {
        return Ok(None);
    };
    let has = |name: &str| names.iter().any(|n| n == name);
    if !has(verify.secret) || placeholders(verify.url).any(|name| !has(name)) {
        return Ok(None);
    }
    Ok(Some(Check {
        url: verify.url.to_string(),
        secret: verify.secret.to_string(),
        scheme: verify.scheme,
        forbidden_is_valid: verify.forbidden_is_valid,
    }))
}

/// The secret names a check URL refers to as `{name}`.
fn placeholders(url: &str) -> impl Iterator<Item = &str> {
    url.split('{')
        .skip(1)
        .filter_map(|part| part.split_once('}').map(|(name, _)| name))
}

/// What a check found out, short of an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verified {
    /// The provider took the token; what it said, for `fob check`.
    Accepted(String),
    /// The check could not be made, and why.
    Skipped(String),
}

/// Checks `values` with `check`. A token the provider refuses (401, or 403
/// unless that still proves it) fails as rejected; a provider that cannot
/// be reached or answers 5xx fails as not checked, since the token may be
/// fine.
pub(crate) async fn verify(
    check: &Check,
    values: &BTreeMap<String, String>,
    vars: &BTreeMap<String, String>,
) -> anyhow::Result<Verified> {
    let secret = values
        .get(&check.secret)
        .with_context(|| format!("missing a value for '{}'", check.secret))?;
    let mut url = check.url.clone();
    for name in placeholders(&check.url)
        .map(str::to_string)
        .collect::<Vec<_>>()
    {
        let value = values
            .get(&name)
            .with_context(|| format!("missing a value for '{name}'"))?;
        let encoded: String = form_urlencoded::byte_serialize(value.as_bytes()).collect();
        url = url.replace(&format!("{{{name}}}"), &encoded);
    }
    let request = crate::http::client().get(&url);
    let request = match check.scheme {
        AuthScheme::Bearer => request.bearer_auth(secret),
        AuthScheme::Header(header) => request.header(header, secret),
        AuthScheme::Basic { user_var } => match vars.get(user_var) {
            Some(user) => request.basic_auth(user, Some(secret)),
            None => {
                return Ok(Verified::Skipped(format!(
                    "set {user_var} under `vars` so omnifob can check the token"
                )));
            }
        },
    };
    let response = request
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("could not reach {} to check the token: {e}", check.url))?;
    let status = response.status();
    match status.as_u16() {
        _ if status.is_success() => Ok(Verified::Accepted(format!(
            "token accepted by {}",
            check.url
        ))),
        403 if check.forbidden_is_valid => Ok(Verified::Accepted(format!(
            "token accepted by {} (it may not read this URL, which needs no more)",
            check.url
        ))),
        401 | 403 => bail!("the token was rejected ({status} from {})", check.url),
        500.. => bail!(
            "could not check the token: {} answered {status}; try again later",
            check.url
        ),
        _ => bail!("could not check the token: {} answered {status}", check.url),
    }
}

/// Checks the stored token against the provider when a check is known.
pub async fn check(integration: &str, config: &TokenConfig) -> Result<String> {
    let Some(Stored(values)) = store::get(&secrets_key(integration))? else {
        return Err(Error::not_signed_in(integration));
    };
    let Some(check) = verification(config)? else {
        return Ok("token stored; this provider has no check".to_string());
    };
    if !values.contains_key(&check.secret) {
        return Err(Error::not_signed_in(integration));
    }
    Ok(match verify(&check, &values, &config.vars).await? {
        Verified::Accepted(said) => said,
        Verified::Skipped(why) => format!("token stored, not checked: {why}"),
    })
}

pub fn logout(integration: &str) -> anyhow::Result<bool> {
    store::delete(&secrets_key(integration))
}

pub fn has_secrets(integration: &str) -> anyhow::Result<bool> {
    Ok(store::get::<Stored>(&secrets_key(integration))?.is_some())
}

/// One profile per integration: `<integration>/<account>/<preset or "token">`.
pub fn discover(integration: &str, config: &TokenConfig) -> Vec<Profile> {
    let account = config.account.as_deref().unwrap_or("default");
    let leaf = config.preset.as_deref().unwrap_or("token");
    vec![Profile::new(integration, account, leaf, Target::Token {})]
}

pub fn credentials(integration: &str, config: &TokenConfig) -> Result<Credentials> {
    let Some(Stored(values)) = store::get(&secrets_key(integration))? else {
        return Err(Error::not_signed_in(integration));
    };
    let mut env: BTreeMap<String, String> = match &config.preset {
        Some(name) if config.secrets.is_empty() => preset(name)?
            .vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        _ => BTreeMap::new(),
    };
    env.extend(config.vars.clone());
    for (name, vars) in secrets(config)? {
        let value = values
            .get(&name)
            .ok_or_else(|| Error::not_signed_in(integration))?;
        for var in vars {
            env.insert(var, value.clone());
        }
    }
    Ok(Credentials {
        env,
        expires_at: None,
        ..Default::default()
    })
}

pub fn console_url(config: &TokenConfig) -> anyhow::Result<Option<String>> {
    if let Some(url) = &config.console {
        return Ok(Some(url.clone()));
    }
    Ok(match &config.preset {
        Some(name) => preset(name)?.console.map(str::to_string),
        None => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Integration};

    fn config(toml: &str) -> TokenConfig {
        let text = format!("[integrations.t]\ntype = \"token\"\n{toml}");
        match Config::parse(&text)
            .unwrap()
            .integrations
            .remove("t")
            .unwrap()
        {
            Integration::Token(c) => c,
            _ => unreachable!(),
        }
    }

    #[test]
    fn preset_secrets_fill_every_variable() {
        let s = secrets(&config("preset = \"digitalocean\"")).unwrap();
        assert_eq!(
            s,
            [(
                "token".to_string(),
                vec![
                    "DIGITALOCEAN_ACCESS_TOKEN".to_string(),
                    "DIGITALOCEAN_TOKEN".to_string()
                ]
            )]
        );
    }

    #[test]
    fn explicit_secrets_override_the_preset() {
        let c = config("preset = \"hetzner\"\n[integrations.t.secrets]\nkey = [\"MY_VAR\"]");
        assert_eq!(
            secrets(&c).unwrap(),
            [("key".to_string(), vec!["MY_VAR".to_string()])]
        );
    }

    #[test]
    fn unknown_preset_lists_known_ones() {
        let err = preset("nope").unwrap_err();
        assert!(err.to_string().contains("hetzner"), "{err}");
    }

    #[test]
    fn preset_vars_come_with_the_secrets_and_config_vars_win() {
        store::use_memory_store().unwrap();
        let c = config(
            "preset = \"unikraft\"\nvars = { UKC_METRO = \"fra\", UNIKRAFT_PROFILE_ENV = \"1\" }",
        );
        store::set(
            &secrets_key("uk-vars"),
            &Stored(BTreeMap::from([("token".to_string(), "t".to_string())])),
        )
        .unwrap();
        let env = credentials("uk-vars", &c).unwrap().env;
        assert_eq!(env["UKC_TOKEN"], "t");
        assert_eq!(env["UKC_METRO"], "fra");
        assert_eq!(env["UNIKRAFT_PROFILE_ENV"], "1");

        let plain = config("preset = \"unikraft\"");
        let env = credentials("uk-vars", &plain).unwrap().env;
        assert_eq!(env["UNIKRAFT_PROFILE_ENV"], "true");
    }

    #[test]
    fn profile_ids() {
        let ids: Vec<_> = discover("hz", &config("preset = \"hetzner\"\naccount = \"prod\""))
            .into_iter()
            .map(|p| p.id)
            .collect();
        assert_eq!(ids, ["hz/prod/hetzner"]);
        assert_eq!(
            discover("x", &config("[integrations.t.secrets]\nk = [\"V\"]"))[0].id,
            "x/default/token"
        );
    }

    #[test]
    fn every_preset_has_secrets_and_unique_name() {
        let mut names: Vec<_> = PRESETS.iter().map(|p| p.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), PRESETS.len());
        assert!(PRESETS.iter().all(|p| !p.secrets.is_empty()));
    }

    fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn check_at(server: &wiremock::MockServer, path: &str, verify: Verify) -> Check {
        Check {
            url: format!("{}{path}", server.uri()),
            secret: verify.secret.to_string(),
            scheme: verify.scheme,
            forbidden_is_valid: verify.forbidden_is_valid,
        }
    }

    #[test]
    fn presets_check_with_the_secrets_they_name() {
        let scaleway = verification(&config("preset = \"scaleway\""))
            .unwrap()
            .unwrap();
        assert_eq!(scaleway.scheme, AuthScheme::Header("X-Auth-Token"));
        assert_eq!(scaleway.secret, "secret_key");
        assert!(scaleway.forbidden_is_valid);
        let upstash = verification(&config("preset = \"upstash\""))
            .unwrap()
            .unwrap();
        assert_eq!(
            upstash.scheme,
            AuthScheme::Basic {
                user_var: "UPSTASH_EMAIL"
            }
        );
        assert_eq!(verification(&config("preset = \"fly\"")).unwrap(), None);
        // A `secrets` table without the secret the check sends: no check.
        let renamed =
            config("preset = \"hetzner\"\n[integrations.t.secrets]\nkey = [\"HCLOUD_TOKEN\"]");
        assert_eq!(verification(&renamed).unwrap(), None);
        // `verify_url` replaces the preset's check.
        let own = config("preset = \"hetzner\"\nverify_url = \"https://x.test/me\"");
        let own = verification(&own).unwrap().unwrap();
        assert_eq!(
            (own.url.as_str(), own.secret.as_str()),
            ("https://x.test/me", "token")
        );
        assert_eq!(own.scheme, AuthScheme::Bearer);
    }

    #[tokio::test]
    async fn each_scheme_sends_the_secret_its_way() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/iam/v1alpha1/api-keys/SCW%2FKEY"))
            .and(header("X-Auth-Token", "secret"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v2/redis/databases"))
            // me@example.com:key
            .and(header("Authorization", "Basic bWVAZXhhbXBsZS5jb206a2V5"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/me"))
            .and(header("Authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let scaleway = preset("scaleway").unwrap().verify.unwrap();
        let check = check_at(&server, "/iam/v1alpha1/api-keys/{access_key}", scaleway);
        let said = verify(
            &check,
            &values(&[("access_key", "SCW/KEY"), ("secret_key", "secret")]),
            &BTreeMap::new(),
        )
        .await
        .unwrap();
        assert!(
            matches!(said, Verified::Accepted(ref s) if s.contains("may not read")),
            "{said:?}"
        );

        let upstash = preset("upstash").unwrap().verify.unwrap();
        let check = check_at(&server, "/v2/redis/databases", upstash);
        let key = values(&[("api_key", "key")]);
        let vars = values(&[("UPSTASH_EMAIL", "me@example.com")]);
        assert!(matches!(
            verify(&check, &key, &vars).await.unwrap(),
            Verified::Accepted(_)
        ));
        // Without the email there is nothing to check with.
        let skipped = verify(&check, &key, &BTreeMap::new()).await.unwrap();
        assert_eq!(
            skipped,
            Verified::Skipped(
                "set UPSTASH_EMAIL under `vars` so omnifob can check the token".into()
            )
        );

        let hetzner = preset("hetzner").unwrap().verify.unwrap();
        let check = check_at(&server, "/me", hetzner);
        assert!(matches!(
            verify(&check, &values(&[("token", "tok")]), &BTreeMap::new())
                .await
                .unwrap(),
            Verified::Accepted(_)
        ));
    }

    #[tokio::test]
    async fn a_refusal_is_told_apart_from_an_outage() {
        use wiremock::matchers::path;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        for (route, status) in [("/401", 401), ("/403", 403), ("/503", 503), ("/404", 404)] {
            Mock::given(path(route))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;
        }
        let bearer = bearer("", "token").unwrap();
        let token = values(&[("token", "t")]);
        let error = |route: &str| {
            let check = check_at(&server, route, bearer);
            let token = token.clone();
            async move {
                verify(&check, &token, &BTreeMap::new())
                    .await
                    .unwrap_err()
                    .to_string()
            }
        };
        assert!(
            error("/401")
                .await
                .contains("the token was rejected (401 Unauthorized")
        );
        assert!(
            error("/403")
                .await
                .contains("the token was rejected (403 Forbidden")
        );
        let outage = error("/503").await;
        assert!(
            outage.contains("could not check the token")
                && outage.contains("503")
                && outage.contains("try again later"),
            "{outage}"
        );
        assert!(error("/404").await.contains("could not check the token"));
        let unreachable = Check {
            url: "http://127.0.0.1:9/me".into(),
            ..check_at(&server, "", bearer)
        };
        let error = verify(&unreachable, &token, &BTreeMap::new())
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("could not reach http://127.0.0.1:9/me"),
            "{error}"
        );
    }
}
