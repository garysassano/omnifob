//! `fob login` and `fob logout`: signing in to an integration and out again.

use std::io::Read;

use anyhow::bail;
use dialoguer::console::Term;
use omnifob_core::config::CloudflareTokenType;
use omnifob_core::providers::{
    self, aws_iam, aws_sso, azure, cloudflare, cloudflare_oauth, gcp, token,
};
use omnifob_core::{Error, Integration};

use crate::{App, clipboard, interactive};

impl App {
    pub(crate) async fn login(
        &self,
        name: &str,
        no_browser: bool,
        device_code: bool,
        token_stdin: bool,
        from_clipboard: bool,
    ) -> anyhow::Result<()> {
        let integration = self.config.integration(name)?;
        if device_code
            && !matches!(
                integration,
                Integration::AwsSso(_) | Integration::Gcp(_) | Integration::Azure(_)
            )
        {
            bail!(
                "--device-code only applies to AWS IAM Identity Center, Google and Azure integrations"
            );
        }
        match integration {
            Integration::AwsSso(config) => {
                if token_stdin || from_clipboard {
                    bail!("'{name}' signs in through IAM Identity Center; it takes no token");
                }
                let flow = if device_code {
                    aws_sso::Flow::DeviceCode
                } else {
                    aws_sso::Flow::for_this_session()
                };
                aws_sso::login(name, config, flow, |prompt| {
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
                    if !no_browser && let Err(e) = open::that(&prompt.url) {
                        eprintln!("fob: could not open a browser ({e}); open the URL above");
                    }
                })
                .await?;
            }
            Integration::Gcp(config) => {
                if token_stdin || from_clipboard {
                    bail!("'{name}' signs in through Google; it takes no token");
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
                            if !no_browser && let Err(e) = open::that(url) {
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
                    if !no_browser && let Err(e) = open::that(prompt.url) {
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
                let session = cloudflare_oauth::login(name, config, |url| {
                    eprintln!("fob: approve the sign-in for '{name}' in your browser");
                    eprintln!("     Pick the accounts, and turn on Account API Tokens Write under Sensitive scopes.");
                    eprintln!("     {url}");
                    if !no_browser && let Err(e) = open::that(url) {
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
                    if !no_browser && let Err(e) = open::that(&url) {
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
                let arn = aws_iam::login(name, config, &key_id, &secret).await?;
                eprintln!("fob: the access key belongs to {arn}; it stays in the keychain");
            }
            Integration::Token(config) => {
                let names: Vec<String> = token::secrets(config)?
                    .into_iter()
                    .map(|(name, _)| name)
                    .collect();
                let mut values = std::collections::BTreeMap::new();
                if token_stdin {
                    let [only] = names.as_slice() else {
                        bail!(
                            "--token-stdin works for a single secret; '{name}' has {}",
                            names.len()
                        );
                    };
                    let mut value = String::new();
                    std::io::stdin().read_to_string(&mut value)?;
                    values.insert(only.clone(), value);
                } else {
                    if !interactive() {
                        bail!(
                            "no terminal to prompt for secrets; pass a single one with --token-stdin"
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

    pub(crate) async fn logout(&mut self, name: &str) -> anyhow::Result<()> {
        let integration = self.config.integration(name)?.clone();
        let accounts: Vec<String> = self
            .cache
            .integrations
            .get(name)
            .map(|s| {
                let mut ids: Vec<String> = s
                    .profiles
                    .iter()
                    .filter_map(|p| match &p.target {
                        omnifob_core::Target::Cloudflare { account_id, .. } => {
                            Some(account_id.clone())
                        }
                        _ => None,
                    })
                    .collect();
                ids.dedup();
                ids
            })
            .unwrap_or_default();
        // Signing out also ends the access omnifob handed out.
        match providers::revoke_all(name, &integration, &accounts).await {
            Ok(0) | Err(Error::NeedsLogin { .. }) => {}
            Ok(n) => eprintln!("fob: deleted {n} token(s) omnifob had minted"),
            Err(e) => eprintln!("fob: could not delete minted tokens: {e:#}"),
        }
        if let Integration::AwsSso(config) = &integration {
            match aws_sso::end_session(name, config).await {
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
                Err(e) => eprintln!("fob: could not delete the session's bootstrap token: {e:#}"),
            }
        }
        let existed = providers::logout(name, &integration)?;
        if let Some(synced) = self.cache.integrations.get(name) {
            providers::forget_credentials(&synced.profiles);
        }
        eprintln!(
            "fob: {}",
            if existed {
                "signed out"
            } else {
                "was not signed in"
            }
        );
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
