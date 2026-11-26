//! The keys of the `token` integration.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::parse_url;

/// Long-lived tokens for providers without short-lived credentials.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct TokenConfig {
    /// A known provider: its variable names, token check and console URL.
    #[serde(default)]
    pub preset: Option<String>,
    /// Secret name → environment variables that receive it. It replaces the
    /// preset's secrets and the fixed variables that come with them (such
    /// as unikraft's `UNIKRAFT_PROFILE_ENV`); set those under `vars`.
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
    /// URL that answers 2xx when the token is sent as a bearer token; it
    /// needs exactly one secret, and replaces the preset's check.
    #[serde(default)]
    pub verify_url: Option<String>,
    /// The browser in `[browsers]` that this integration's sign-ins and
    /// consoles open in; by default the system's.
    #[serde(default)]
    pub browser: Option<String>,
}

impl TokenConfig {
    pub(super) fn validate(&self) -> Result<(), String> {
        if let Some(name) = &self.preset {
            crate::providers::token::preset(name).map_err(|e| format!("preset: {e}"))?;
        } else if self.secrets.is_empty() {
            return Err(
                "a token integration needs a `preset` or a `secrets` table naming its secrets"
                    .to_string(),
            );
        }
        for (name, vars) in &self.secrets {
            if name.trim().is_empty() {
                return Err("secrets: a secret's name must not be empty".to_string());
            }
            if vars.is_empty() {
                return Err(format!(
                    "secrets.{name} must list the environment variables that receive it"
                ));
            }
            for var in vars {
                check_var_name(&format!("secrets.{name}"), var)?;
            }
        }
        for var in self.vars.keys() {
            check_var_name("vars", var)?;
        }
        if let Some(url) = &self.verify_url {
            let parsed = parse_url("verify_url", url)?;
            // The token goes to this URL: only over TLS, or to this machine.
            let host = parsed.host_str().unwrap_or_default();
            let loopback = host == "localhost"
                || host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback());
            if parsed.scheme() != "https" && !loopback {
                return Err(format!(
                    "verify_url '{url}' must be an https:// URL: the token is sent to it"
                ));
            }
            let secrets = if self.secrets.is_empty() {
                self.preset
                    .as_deref()
                    .and_then(|name| crate::providers::token::preset(name).ok())
                    .map_or(0, |preset| preset.secrets.len())
            } else {
                self.secrets.len()
            };
            if secrets != 1 {
                return Err(format!(
                    "verify_url sends the token as a bearer token, so it needs exactly one \
                     secret, not {secrets}"
                ));
            }
        }
        if let Some(url) = &self.console {
            parse_url("console", url)?;
        }
        Ok(())
    }
}

/// Fails unless `var` is an environment variable name a shell can set,
/// naming the key it is under.
fn check_var_name(key: &str, var: &str) -> Result<(), String> {
    if !crate::credentials::is_var_name(var) {
        return Err(format!(
            "{key}: '{var}' is not an environment variable name (letters, digits and _, not \
             starting with a digit)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::config::*;

    #[test]
    fn token_keys_are_checked() {
        let token = |extra: &str| {
            Config::parse(&format!("[integrations.t]\ntype = \"token\"\n{extra}\n"))
                .map_err(|e| format!("{e:#}"))
        };
        assert!(token("preset = \"hetzner\"\nvars = { HCLOUD_ENDPOINT = \"x\" }\nconsole = \"https://x.test/\"").is_ok());
        assert!(token("verify_url = \"http://127.0.0.1:8080/me\"\n[integrations.t.secrets]\nkey = [\"MY_KEY\"]").is_ok());
        for (extra, message) in [
            ("", "needs a `preset` or a `secrets` table"),
            (
                "preset = \"nope\"",
                "preset: unknown token preset 'nope' (known: hetzner",
            ),
            (
                "[integrations.t.secrets]\nkey = []",
                "secrets.key must list the environment variables",
            ),
            (
                "[integrations.t.secrets]\nkey = [\"MY-KEY\"]",
                "secrets.key: 'MY-KEY' is not an environment variable name",
            ),
            (
                "preset = \"hetzner\"\nvars = { \"1X\" = \"y\" }",
                "vars: '1X' is not an environment variable name",
            ),
            (
                "preset = \"hetzner\"\nverify_url = \"http://api.example.com/me\"",
                "verify_url 'http://api.example.com/me' must be an https:// URL",
            ),
            (
                "preset = \"hetzner\"\nverify_url = \"me\"",
                "verify_url 'me' is not a URL",
            ),
            (
                "preset = \"scaleway\"\nverify_url = \"https://x.test/\"",
                "needs exactly one secret, not 2",
            ),
            (
                "preset = \"hetzner\"\nconsole = \"ftp://x.test/\"",
                "console 'ftp://x.test/' must be an http:// or https:// URL",
            ),
        ] {
            let error = token(extra).unwrap_err();
            assert!(error.contains(message), "{extra}: {error}");
        }
    }
}
