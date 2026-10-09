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
    /// A URL that answers 2xx for a valid token sent as a bearer token.
    pub verify_url: Option<&'static str>,
    pub console: Option<&'static str>,
}

pub const PRESETS: &[Preset] = &[
    Preset {
        name: "hetzner",
        secrets: &[("token", &["HCLOUD_TOKEN"])],
        verify_url: Some("https://api.hetzner.cloud/v1/locations"),
        console: Some("https://console.hetzner.cloud/projects"),
    },
    Preset {
        name: "digitalocean",
        // doctl reads the first, Terraform's provider the second.
        secrets: &[(
            "token",
            &["DIGITALOCEAN_ACCESS_TOKEN", "DIGITALOCEAN_TOKEN"],
        )],
        verify_url: Some("https://api.digitalocean.com/v2/account"),
        console: Some("https://cloud.digitalocean.com"),
    },
    Preset {
        name: "vultr",
        secrets: &[("api_key", &["VULTR_API_KEY"])],
        verify_url: Some("https://api.vultr.com/v2/account"),
        console: Some("https://my.vultr.com"),
    },
    Preset {
        name: "linode",
        // Akamai Cloud. linode-cli reads the second, Terraform the first.
        secrets: &[("token", &["LINODE_TOKEN", "LINODE_CLI_TOKEN"])],
        verify_url: Some("https://api.linode.com/v4/profile"),
        console: Some("https://cloud.linode.com"),
    },
    Preset {
        name: "upstash",
        // Set UPSTASH_EMAIL under `vars`; the API key is the secret.
        secrets: &[("api_key", &["UPSTASH_API_KEY"])],
        verify_url: None,
        console: Some("https://console.upstash.com"),
    },
    Preset {
        name: "akamai-edgegrid",
        secrets: &[
            ("client_token", &["AKAMAI_CLIENT_TOKEN"]),
            ("client_secret", &["AKAMAI_CLIENT_SECRET"]),
            ("access_token", &["AKAMAI_ACCESS_TOKEN"]),
        ],
        verify_url: None,
        console: Some("https://control.akamai.com"),
    },
    Preset {
        name: "scaleway",
        secrets: &[
            ("access_key", &["SCW_ACCESS_KEY"]),
            ("secret_key", &["SCW_SECRET_KEY"]),
        ],
        verify_url: None,
        console: Some("https://console.scaleway.com"),
    },
    Preset {
        name: "vercel",
        secrets: &[("token", &["VERCEL_TOKEN"])],
        verify_url: Some("https://api.vercel.com/v2/user"),
        console: Some("https://vercel.com/dashboard"),
    },
    Preset {
        name: "netlify",
        secrets: &[("token", &["NETLIFY_AUTH_TOKEN"])],
        verify_url: Some("https://api.netlify.com/api/v1/user"),
        console: Some("https://app.netlify.com"),
    },
    Preset {
        name: "fly",
        secrets: &[("token", &["FLY_API_TOKEN"])],
        verify_url: None,
        console: Some("https://fly.io/dashboard"),
    },
    Preset {
        name: "neon",
        secrets: &[("api_key", &["NEON_API_KEY"])],
        verify_url: Some("https://console.neon.tech/api/v2/users/me"),
        console: Some("https://console.neon.tech"),
    },
    Preset {
        name: "supabase",
        secrets: &[("token", &["SUPABASE_ACCESS_TOKEN"])],
        verify_url: Some("https://api.supabase.com/v1/projects"),
        console: Some("https://supabase.com/dashboard"),
    },
    Preset {
        name: "github",
        // gh prefers GH_TOKEN; most other tools read GITHUB_TOKEN.
        secrets: &[("token", &["GH_TOKEN", "GITHUB_TOKEN"])],
        verify_url: Some("https://api.github.com/user"),
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

#[derive(Debug, Default, Serialize, Deserialize)]
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
    if let [only] = expected.as_slice()
        && let Some(url) = verify_url(config)?
    {
        verify(url, &values[only]).await?;
    }
    store::set(&secrets_key(integration), &Stored(values))
}

async fn verify(url: &str, token: &str) -> anyhow::Result<()> {
    let response = reqwest::Client::new()
        .get(url)
        .bearer_auth(token)
        .header("user-agent", "omnifob")
        .send()
        .await
        .with_context(|| format!("checking the token against {url}"))?;
    if !response.status().is_success() {
        bail!("the token was rejected ({} from {url})", response.status());
    }
    Ok(())
}

/// Checks the stored token against the provider when a check is known.
pub async fn check(integration: &str, config: &TokenConfig) -> Result<String> {
    let Some(Stored(values)) = store::get(&secrets_key(integration))? else {
        return Err(Error::not_signed_in(integration));
    };
    let names: Vec<String> = secrets(config)?.into_iter().map(|(name, _)| name).collect();
    match (names.as_slice(), verify_url(config)?) {
        ([only], Some(url)) => {
            let token = values
                .get(only)
                .ok_or_else(|| Error::not_signed_in(integration))?;
            verify(url, token).await?;
            Ok(format!("token accepted by {url}"))
        }
        _ => Ok("token stored; this provider has no check".to_string()),
    }
}

fn verify_url(config: &TokenConfig) -> anyhow::Result<Option<&str>> {
    if let Some(url) = &config.verify_url {
        return Ok(Some(url.as_str()));
    }
    Ok(match &config.preset {
        Some(name) => preset(name)?.verify_url,
        None => None,
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
    let mut env: BTreeMap<String, String> = config.vars.clone();
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
        let err = secrets(&config("preset = \"nope\"")).unwrap_err();
        assert!(err.to_string().contains("hetzner"), "{err}");
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
}
