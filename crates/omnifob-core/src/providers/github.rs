//! GitHub sign-in (`type = "github-oauth"`).
//!
//! The same flow as `gh auth login`: OAuth device flow against an OAuth app,
//! asking for the scopes gh needs, so the token works for gh as well as git.
//! The token is then kept like any stored token (`token::login`), and every
//! other part of omnifob treats the integration as a `github` token.
//!
//! GitHub OAuth app tokens do not expire, and an app can only revoke one with
//! its client secret, which omnifob does not have; signing out forgets the
//! token, and the authorization stays listed under the account's Authorized
//! OAuth Apps until removed there.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, bail};
use serde::Deserialize;

use crate::config::TokenConfig;
use crate::providers::token;

/// What `gh auth login` asks for: `repo`, `read:org` and `gist` are gh's
/// minimum, and `workflow` lets git push changes to workflow files.
pub const DEFAULT_SCOPES: &[&str] = &["repo", "read:org", "gist", "workflow"];

/// The site serving the sign-in: `https://<git_host>`, github.com by default.
fn base(config: &TokenConfig) -> anyhow::Result<String> {
    let host = token::git_host(config)?.unwrap_or("github.com");
    Ok(format!("https://{host}"))
}

pub fn scopes(config: &TokenConfig) -> Vec<String> {
    config
        .scopes
        .clone()
        .unwrap_or_else(|| DEFAULT_SCOPES.iter().map(|s| s.to_string()).collect())
}

/// What the user has to do to approve the sign-in.
pub struct Prompt {
    pub url: String,
    pub user_code: String,
}

#[derive(Deserialize)]
struct DeviceCode {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Deserialize)]
struct TokenReply {
    access_token: Option<String>,
    scope: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
    interval: Option<u64>,
}

/// URL-encodes a form body.
fn form(pairs: &[(&str, &str)]) -> String {
    let mut url = reqwest::Url::parse("http://localhost/").expect("valid URL");
    url.query_pairs_mut().extend_pairs(pairs);
    url.query().unwrap_or_default().to_string()
}

fn http() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent(concat!("omnifob/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

/// Runs the device flow, then checks and stores the token. Returns the
/// scopes GitHub granted.
pub async fn login(
    integration: &str,
    config: &TokenConfig,
    prompt: impl FnOnce(&Prompt),
) -> anyhow::Result<Vec<String>> {
    let client_id = config
        .client_id
        .as_deref()
        .context("github-oauth needs a client_id")?;
    let (token, granted) = device_flow(&base(config)?, client_id, &scopes(config), prompt).await?;
    token::login(
        integration,
        config,
        BTreeMap::from([("token".to_string(), token)]),
    )
    .await?;
    Ok(granted)
}

/// The device flow against `base` (`https://github.com`): shows the user a
/// code to enter, then waits for the approval. Returns the token and the
/// scopes granted.
pub async fn device_flow(
    base: &str,
    client_id: &str,
    scopes: &[String],
    prompt: impl FnOnce(&Prompt),
) -> anyhow::Result<(String, Vec<String>)> {
    let http = http()?;
    let code: DeviceCode = http
        .post(format!("{base}/login/device/code"))
        .header("accept", "application/json")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form(&[
            ("client_id", client_id),
            ("scope", &scopes.join(" ")),
        ]))
        .send()
        .await
        .context("starting the GitHub sign-in")?
        .error_for_status()
        .context("starting the GitHub sign-in; is the client_id right?")?
        .json()
        .await
        .context("starting the GitHub sign-in; is device flow enabled for the OAuth app?")?;
    prompt(&Prompt {
        url: code.verification_uri.clone(),
        user_code: code.user_code.clone(),
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(code.expires_in);
    let mut interval = code.interval;
    let reply = loop {
        if std::time::Instant::now() >= deadline {
            bail!("the sign-in code expired before it was approved; run the login again");
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;
        let reply: TokenReply = http
            .post(format!("{base}/login/oauth/access_token"))
            .header("accept", "application/json")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form(&[
                ("client_id", client_id),
                ("device_code", &code.device_code),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ]))
            .send()
            .await
            .context("waiting for the GitHub sign-in")?
            .error_for_status()?
            .json()
            .await?;
        match reply.error.as_deref() {
            None => break reply,
            Some("authorization_pending") => {}
            // GitHub says how long to wait from now on.
            Some("slow_down") => interval = reply.interval.unwrap_or(interval + 5),
            Some("expired_token") => {
                bail!("the sign-in code expired before it was approved; run the login again")
            }
            Some("access_denied") => bail!("the sign-in was cancelled in the browser"),
            Some(error) => bail!(
                "GitHub refused the sign-in: {}",
                reply.error_description.as_deref().unwrap_or(error)
            ),
        }
    };
    let token = reply
        .access_token
        .context("GitHub answered the sign-in without a token")?;
    let granted = reply
        .scope
        .unwrap_or_default()
        .split([',', ' '])
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    Ok((token, granted))
}
