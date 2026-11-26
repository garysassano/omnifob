//! `fob login` and `fob logout`: signing in to an integration and out again.

use std::io::Read;

use anyhow::{Context, bail};
use dialoguer::console::Term;
use omnifob_core::config::CloudflareTokenType;
use omnifob_core::history::{self, History};
use omnifob_core::providers::{self, aws, azure, cloudflare, gcp, token};
use omnifob_core::{Error, Integration};

use crate::{App, agent, clipboard, interactive};

impl App {
    /// The integration `fob login` or `fob logout` acts on: the one named, or
    /// one picked from a list when none is named and someone can answer. The
    /// list puts the integrations whose profiles were used most recently first.
    pub(crate) fn pick_integration(
        &self,
        name: Option<&str>,
        command: &str,
    ) -> anyhow::Result<String> {
        if let Some(name) = name {
            return Ok(name.to_string());
        }
        let mut names: Vec<&str> = self
            .config
            .integrations
            .keys()
            .map(String::as_str)
            .collect();
        if names.is_empty() {
            bail!(
                "no integrations configured in {}",
                omnifob_core::paths::config_file()?.display()
            );
        }
        if agent::active() || !interactive() {
            bail!(
                "name an integration: `fob {command} <integration>` (configured: {})",
                names.join(", ")
            );
        }
        let history = History::load(&history::file()?);
        let last_used = |name: &str| {
            self.cache
                .all()
                .filter(|p| p.integration == name)
                .filter_map(|p| history.used.get(&p.id))
                .max()
                .copied()
        };
        names.sort_by_cached_key(|n| std::cmp::Reverse(last_used(n)));
        let width = names.iter().map(|n| n.len()).max().unwrap_or(0);
        let items: Vec<String> = names
            .iter()
            .map(|n| format!("{n:width$}  {}", self.config.integrations[*n].kind()))
            .collect();
        let picked = dialoguer::FuzzySelect::new()
            .with_prompt("Integration")
            .items(&items)
            .default(0)
            .interact_on_opt(&Term::stderr())?
            .context("no integration selected")?;
        Ok(names[picked].to_string())
    }

    pub(crate) async fn login(
        &self,
        name: &str,
        no_browser: bool,
        device_code: bool,
        token_stdin: bool,
        from_clipboard: bool,
        force: bool,
    ) -> anyhow::Result<()> {
        let integration = self.config.integration(name)?;
        if device_code
            && !matches!(
                integration,
                Integration::AwsSso(_)
                    | Integration::AwsLogin(_)
                    | Integration::Gcp(_)
                    | Integration::Azure(_)
            )
        {
            bail!(
                "--device-code only applies to AWS IAM Identity Center, AWS console sign-in, Google and Azure integrations"
            );
        }
        match integration {
            Integration::AwsSso(config) => {
                if token_stdin || from_clipboard {
                    bail!("'{name}' signs in through IAM Identity Center; it takes no token");
                }
                if !force && self.keeps_sign_in(name, integration).await {
                    return Ok(());
                }
                let flow = if device_code {
                    aws::sso::Flow::DeviceCode
                } else {
                    aws::sso::Flow::for_this_session()
                };
                aws::sso::login(name, config, flow, |prompt| {
                    match &prompt.user_code {
                        Some(code) => {
                            eprintln!("fob: approve the sign-in for '{name}' on any device");
                            eprintln!("     {}", prompt.url);
                            eprintln!("     code: {code}");
                        }
                        None => {
                            eprintln!("fob: approve the sign-in for '{name}' in your browser");
                            eprintln!("     {}", prompt.url);
                            eprintln!(
                                "     The browser must run on this machine; elsewhere, use --device-code."
                            );
                        }
                    }
                    if !no_browser && let Err(e) = crate::browser::open(&self.config, name, &prompt.url) {
                        eprintln!("fob: could not open a browser ({e}); open the URL above");
                    }
                })
                .await?;
            }
            Integration::AwsLogin(config) => {
                if token_stdin || from_clipboard {
                    bail!("'{name}' signs in through the AWS console; it takes no token");
                }
                if !force && self.keeps_sign_in(name, integration).await {
                    return Ok(());
                }
                let browser_here = !device_code && !omnifob_core::oauth::browser_is_elsewhere();
                if !browser_here && !interactive() {
                    bail!("no terminal to paste the AWS code into; run `fob login {name}` in one");
                }
                let identity = aws::login::login(
                    name,
                    config,
                    browser_here,
                    |url| {
                        if browser_here {
                            eprintln!("fob: pick the console session for '{name}' in your browser");
                            eprintln!("     {url}");
                            eprintln!(
                                "     The browser must run on this machine; elsewhere, use --device-code."
                            );
                            if !no_browser && let Err(e) = crate::browser::open(&self.config, name, url) {
                                eprintln!(
                                    "fob: could not open a browser ({e}); open the URL above"
                                );
                            }
                        } else {
                            eprintln!(
                                "fob: open this on any device, pick the console session for '{name}', and copy the code AWS shows"
                            );
                            eprintln!("     {url}");
                        }
                    },
                    || {
                        Ok(dialoguer::Password::new()
                            .with_prompt("Code from AWS")
                            .interact_on(&Term::stderr())?)
                    },
                )
                .await?;
                eprintln!(
                    "fob: signed in to AWS as {identity}; credentials renew until the sign-in ends (12 hours by default)"
                );
            }
            Integration::Gcp(config) => {
                if token_stdin || from_clipboard {
                    bail!("'{name}' signs in through Google; it takes no token");
                }
                if !force && self.keeps_sign_in(name, integration).await {
                    return Ok(());
                }
                let browser_here = !device_code && !omnifob_core::oauth::browser_is_elsewhere();
                if !browser_here && !interactive() {
                    bail!("no terminal to paste Google's code into; run `fob login {name}` in one");
                }
                let email = gcp::login(
                    name,
                    config,
                    browser_here,
                    |url| {
                        if browser_here {
                            eprintln!("fob: approve the sign-in for '{name}' in your browser");
                            eprintln!("     {url}");
                            eprintln!(
                                "     The browser must run on this machine; elsewhere, use --device-code."
                            );
                            if !no_browser && let Err(e) = crate::browser::open(&self.config, name, url) {
                                eprintln!(
                                    "fob: could not open a browser ({e}); open the URL above"
                                );
                            }
                        } else {
                            eprintln!(
                                "fob: open this on any device, approve the sign-in for '{name}', and copy the code Google shows"
                            );
                            eprintln!("     {url}");
                        }
                    },
                    || {
                        Ok(dialoguer::Password::new()
                            .with_prompt("Code from Google")
                            .interact_on(&Term::stderr())?)
                    },
                )
                .await?;
                eprintln!("fob: signed in to Google as {email}");
            }
            Integration::Azure(config) => {
                if token_stdin || from_clipboard {
                    bail!("'{name}' signs in through Entra ID; it takes no token");
                }
                if !force && self.keeps_sign_in(name, integration).await {
                    return Ok(());
                }
                let browser_here = !device_code && !omnifob_core::oauth::browser_is_elsewhere();
                let username = azure::login(name, config, browser_here, |prompt| {
                    match prompt.user_code {
                        Some(code) => {
                            eprintln!("fob: approve the sign-in for '{name}' on any device");
                            eprintln!("     {}", prompt.url);
                            eprintln!("     code: {code}");
                        }
                        None => {
                            eprintln!("fob: approve the sign-in for '{name}' in your browser");
                            eprintln!("     {}", prompt.url);
                            eprintln!(
                                "     The browser must run on this machine; elsewhere, use --device-code."
                            );
                        }
                    }
                    if !no_browser && let Err(e) = crate::browser::open(&self.config, name, prompt.url) {
                        eprintln!("fob: could not open a browser ({e}); open the URL above");
                    }
                })
                .await?;
                eprintln!("fob: signed in to Entra ID as {username}");
            }
            Integration::Cloudflare(config) if config.uses_oauth() => {
                if token_stdin || from_clipboard {
                    bail!("'{name}' signs in through the browser; it takes no token");
                }
                if !force && self.keeps_sign_in(name, integration).await {
                    return Ok(());
                }
                let session = cloudflare::oauth::login(name, config, |url| {
                    eprintln!("fob: approve the sign-in for '{name}' in your browser");
                    eprintln!("     Pick the accounts, and turn on Account API Tokens Write under Sensitive scopes.");
                    eprintln!("     {url}");
                    if !no_browser && let Err(e) = crate::browser::open(&self.config, name, url) {
                        eprintln!("fob: could not open a browser ({e}); open the URL above");
                    }
                })
                .await?;
                if let Some(ends) = session {
                    eprintln!(
                        "fob: Cloudflare session for '{name}' lasts until {}",
                        ends.strftime("%Y-%m-%d %H:%M UTC")
                    );
                }
            }
            Integration::Cloudflare(config) => {
                let token = if token_stdin {
                    let mut token = String::new();
                    std::io::stdin().read_to_string(&mut token)?;
                    token
                } else if from_clipboard {
                    clipboard::read_token()?
                } else {
                    if !interactive() {
                        bail!(
                            "no terminal to prompt for the token; copy it and use --from-clipboard, or pipe it to --token-stdin"
                        );
                    }
                    let url = cloudflare::bootstrap_url(config);
                    eprintln!("{}", cloudflare_bootstrap_help(config.minting()));
                    eprintln!("     {url}");
                    if !no_browser && let Err(e) = crate::browser::open(&self.config, name, &url) {
                        eprintln!("fob: could not open a browser ({e}); open the URL above");
                    }
                    let typed = dialoguer::Password::new()
                        .with_prompt("Paste the token, or copy it and press Enter")
                        .allow_empty_password(true)
                        .interact_on(&Term::stderr())?;
                    if typed.trim().is_empty() {
                        clipboard::read_token()?
                    } else {
                        typed
                    }
                };
                if let Some(expires_at) = cloudflare::login(name, config, &token).await? {
                    eprintln!(
                        "fob: Cloudflare session for '{name}' lasts until {} (the bootstrap token expires then)",
                        expires_at.strftime("%Y-%m-%d %H:%M UTC")
                    );
                }
            }
            Integration::AwsIam(config) => {
                if from_clipboard {
                    bail!(
                        "'{name}' takes an access key ID and a secret access key, more than the clipboard holds; pipe both to --token-stdin"
                    );
                }
                let (key_id, secret) = if token_stdin {
                    // Two words: the access key ID, then the secret.
                    let mut text = String::new();
                    std::io::stdin().read_to_string(&mut text)?;
                    let mut words = text.split_whitespace();
                    match (words.next(), words.next(), words.next()) {
                        (Some(id), Some(secret), None) => (id.to_string(), secret.to_string()),
                        _ => bail!(
                            "--token-stdin for '{name}' reads the access key ID and the secret access key, separated by whitespace"
                        ),
                    }
                } else {
                    if !interactive() {
                        bail!("no terminal to prompt for the access key; use --token-stdin");
                    }
                    let id: String = dialoguer::Input::new()
                        .with_prompt(format!("{name} access key ID"))
                        .interact_text_on(&Term::stderr())?;
                    let secret = dialoguer::Password::new()
                        .with_prompt(format!("{name} secret access key"))
                        .interact_on(&Term::stderr())?;
                    (id, secret)
                };
                let arn = aws::iam::login(name, config, &key_id, &secret).await?;
                eprintln!("fob: the access key belongs to {arn}; it stays in the keychain");
            }
            Integration::Token(config) => {
                let names: Vec<String> = token::secrets(config)?
                    .into_iter()
                    .map(|(name, _)| name)
                    .collect();
                let mut values = std::collections::BTreeMap::new();
                if token_stdin || from_clipboard {
                    let flag = if token_stdin {
                        "--token-stdin"
                    } else {
                        "--from-clipboard"
                    };
                    let [only] = names.as_slice() else {
                        bail!(
                            "{flag} works for a single secret; '{name}' has {}",
                            names.len()
                        );
                    };
                    let value = if token_stdin {
                        let mut value = String::new();
                        std::io::stdin().read_to_string(&mut value)?;
                        value
                    } else {
                        clipboard::read_secret()?
                    };
                    values.insert(only.clone(), value);
                } else {
                    if !interactive() {
                        bail!(
                            "no terminal to prompt for secrets; pass a single one with --from-clipboard or --token-stdin"
                        );
                    }
                    for secret in &names {
                        let value = dialoguer::Password::new()
                            .with_prompt(format!("{name} {secret}"))
                            .interact_on(&Term::stderr())?;
                        values.insert(secret.clone(), value);
                    }
                }
                token::login(name, config, values).await?;
            }
        }
        eprintln!("fob: signed in to '{name}'");
        Ok(())
    }

    /// Keeps a browser sign-in that still works instead of opening the
    /// browser again; returns whether it did.
    async fn keeps_sign_in(&self, name: &str, integration: &Integration) -> bool {
        match providers::keepable_sign_in(name, integration).await {
            Some(detail) => {
                eprintln!("fob: kept the sign-in of '{name}' ({detail}); --force signs in again");
                true
            }
            None => false,
        }
    }

    /// The Cloudflare accounts integration `name`'s profiles are in.
    pub(crate) fn cloudflare_accounts(&self, name: &str) -> Vec<String> {
        let mut ids: Vec<String> = self
            .cache
            .integrations
            .get(name)
            .into_iter()
            .flat_map(|s| &s.profiles)
            .filter_map(|p| match &p.target {
                omnifob_core::Target::Cloudflare { account_id, .. } => Some(account_id.clone()),
                _ => None,
            })
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// Signs out of every configured integration, going on past one that
    /// fails and reporting the failures at the end.
    pub(crate) async fn logout_all(&mut self) -> anyhow::Result<()> {
        let names: Vec<String> = self.config.integrations.keys().cloned().collect();
        if names.is_empty() {
            bail!(
                "no integrations configured in {}",
                omnifob_core::paths::config_file()?.display()
            );
        }
        let mut failed = Vec::new();
        for name in &names {
            if let Err(e) = self.logout(name).await {
                eprintln!("fob: signing out of '{name}': {e:#}");
                failed.push(name.as_str());
            }
        }
        if !failed.is_empty() {
            bail!("could not sign out of {}", failed.join(", "));
        }
        Ok(())
    }

    pub(crate) async fn logout(&mut self, name: &str) -> anyhow::Result<()> {
        let integration = self.config.integration(name)?.clone();
        let accounts = self.cloudflare_accounts(name);
        // Signing out also ends the access omnifob handed out.
        match providers::revoke_all(name, &integration, &accounts).await {
            Ok(0) | Err(Error::NeedsLogin { .. }) => {}
            Ok(n) => eprintln!("fob: deleted {n} token(s) omnifob had minted"),
            Err(e) => eprintln!("fob: could not delete minted tokens: {e:#}"),
        }
        if let Integration::AwsSso(config) = &integration {
            match aws::sso::end_session(name, config).await {
                Ok(true) => eprintln!("fob: ended the IAM Identity Center session"),
                Ok(false) => {}
                Err(e) => eprintln!("fob: could not end the IAM Identity Center session: {e:#}"),
            }
        }
        if let Integration::Gcp(_) = &integration {
            match gcp::end_session(name).await {
                Ok(true) => eprintln!("fob: revoked the Google sign-in"),
                Ok(false) => {}
                Err(e) => eprintln!("fob: could not revoke the Google sign-in: {e:#}"),
            }
        }
        if let Integration::Cloudflare(config) = &integration {
            match cloudflare::end_session(name, config).await {
                Ok(true) if config.uses_oauth() => eprintln!("fob: revoked the browser sign-in"),
                Ok(true) => eprintln!("fob: deleted the session's bootstrap token"),
                Ok(false) | Err(Error::NeedsLogin { .. }) => {}
                Err(e) if config.uses_oauth() => {
                    eprintln!("fob: could not revoke the browser sign-in: {e:#}")
                }
                Err(e) => eprintln!("fob: could not delete the session's bootstrap token: {e:#}"),
            }
        }
        let existed = providers::logout(name, &integration)?;
        if let Some(synced) = self.cache.integrations.get(name) {
            providers::forget_credentials(&synced.profiles);
        }
        if existed {
            eprintln!("fob: signed out of '{name}'");
        } else {
            eprintln!("fob: '{name}' was not signed in");
        }
        Ok(())
    }
}

pub(crate) fn cloudflare_bootstrap_help(token_type: CloudflareTokenType) -> &'static str {
    match token_type {
        CloudflareTokenType::User => {
            "\
fob: omnifob needs one token that can create other tokens. In the page that opens:
     Create Token > \"Create Additional Tokens\" > Use template, name it \"omnifob bootstrap\",
     then create it and copy the token."
        }
        CloudflareTokenType::Account => {
            "\
fob: omnifob needs one token that can create other tokens. The page that opens is
     pre-filled (name \"omnifob bootstrap\", permission Account API Tokens: Edit):
     Review token > Create token > copy the token with the copy icon."
        }
    }
}
