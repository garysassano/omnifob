//! A Google account (`type = "gcp"`), signed in the way `gcloud auth login`
//! signs in (read from the Cloud SDK's `googlecloudsdk/core/credentials` and
//! `api_lib/auth` on 2026-11-08):
//!
//! - gcloud's own OAuth client, which Google issues to the Cloud SDK as an
//!   installed app; its "secret" ships in gcloud and is not one. A config may
//!   name a Desktop client of its own instead.
//! - The scopes gcloud asks for: `openid`, `userinfo.email`, `cloud-platform`
//!   and `sqlservice.login`.
//! - Authorization code with PKCE and `access_type=offline`, redirected to a
//!   listener on `http://localhost:<port>/`; or, when the browser is on
//!   another machine, gcloud's `--no-launch-browser` flow: Google's page at
//!   `sdk.cloud.google.com/authcode.html` shows a code to paste back, with
//!   `prompt=consent` and `token_usage=remote`. That page only serves
//!   Google's own clients.
//! - A refresh token, which Google does not rotate, renews the access token.
//!   Under Google Cloud session control, renewal fails with `invalid_rapt`
//!   until the user signs in again.
//!
//! The account's access token is handed out per project (as gcloud's
//! `CLOUDSDK_AUTH_ACCESS_TOKEN` and Terraform's `GOOGLE_OAUTH_ACCESS_TOKEN`),
//! and service accounts are impersonated through the IAM Credentials API's
//! `generateAccessToken`, as `gcloud --impersonate-service-account` does.

use anyhow::{Context, anyhow, bail};
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};

use crate::config::{GcpConfig, GcpServiceAccount};
use crate::oauth::{Loopback, Pkce};
use crate::{Credentials, Error, Profile, Result, Target, store};

/// The Cloud SDK's OAuth client (`CLOUDSDK_CLIENT_ID` and
/// `CLOUDSDK_CLIENT_NOTSOSECRET` in gcloud's `core/config.py`).
const GCLOUD_CLIENT_ID: &str = "32555940559.apps.googleusercontent.com";
const GCLOUD_CLIENT_SECRET: &str = "ZmssLNjJy2998hD4CTg2ejr2";

/// gcloud's `DEFAULT_SCOPES`.
const SCOPES: &[&str] = &[
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/sqlservice.login",
];
const CLOUD_PLATFORM: &str = "https://www.googleapis.com/auth/cloud-platform";
const USERINFO_EMAIL: &str = "https://www.googleapis.com/auth/userinfo.email";

/// Where Google's page shows the code to paste, for Google's own clients.
const PASTE_REDIRECT: &str = "https://sdk.cloud.google.com/authcode.html";

/// Reuse a stored access token for omnifob's own calls while it has this long
/// left.
const RENEW_MARGIN: SignedDuration = SignedDuration::from_mins(10);

const DEFAULT_LIFETIME: SignedDuration = SignedDuration::from_hours(1);

/// Google's endpoints; `OMNIFOB_GOOGLE_ENDPOINT` replaces every host with one,
/// for tests.
enum Endpoint {
    Authorize,
    Token,
    Revoke,
    TokenInfo,
    Projects,
    GenerateAccessToken,
}

fn url(endpoint: Endpoint) -> String {
    let base = crate::Context::current().endpoints().google.clone();
    let (host, path) = match endpoint {
        Endpoint::Authorize => ("https://accounts.google.com", "/o/oauth2/auth"),
        Endpoint::Token => ("https://oauth2.googleapis.com", "/token"),
        Endpoint::Revoke => ("https://oauth2.googleapis.com", "/revoke"),
        Endpoint::TokenInfo => ("https://oauth2.googleapis.com", "/tokeninfo"),
        Endpoint::Projects => (
            "https://cloudresourcemanager.googleapis.com",
            "/v1/projects",
        ),
        Endpoint::GenerateAccessToken => (
            "https://iamcredentials.googleapis.com",
            "/v1/projects/-/serviceAccounts/",
        ),
    };
    format!("{}{path}", base.as_deref().unwrap_or(host))
}

fn token_key(integration: &str) -> String {
    format!("gcp/{integration}/oauth")
}

/// Every keychain key an integration uses, for renaming it.
pub fn keys(integration: &str) -> Vec<String> {
    vec![token_key(integration)]
}

/// What the keychain keeps for a signed-in integration. Not `Debug`: it holds
/// the tokens.
#[derive(Clone, Serialize, Deserialize)]
struct Stored {
    refresh_token: String,
    access_token: String,
    expires_at: Timestamp,
    email: String,
    /// The client the refresh token belongs to; it renews only with that one.
    client_id: String,
    /// The account's last ID token, which Google returns with each access
    /// token for the `openid` scope; for `fob creds --format gcp-executable`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

/// A token endpoint refusal.
#[derive(Debug, thiserror::Error)]
#[error("Google refused: {error} {description}")]
struct OauthError {
    error: String,
    /// `invalid_rapt` when session control wants the user to sign in again.
    subtype: Option<String>,
    description: String,
}

fn client(config: &GcpConfig) -> (&str, &str) {
    match (&config.client_id, &config.client_secret) {
        (Some(id), Some(secret)) => (id, secret),
        _ => (GCLOUD_CLIENT_ID, GCLOUD_CLIENT_SECRET),
    }
}

fn authorize_url(
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    challenge: &str,
    paste: bool,
) -> String {
    let mut url = reqwest::Url::parse(&url(Endpoint::Authorize)).expect("valid URL");
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &SCOPES.join(" "))
            .append_pair("state", state)
            .append_pair("access_type", "offline")
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256");
        if paste {
            // As gcloud's remote flow: always show consent (so a refresh token
            // comes back), and do not bind the token to the browser's device.
            q.append_pair("prompt", "consent")
                .append_pair("token_usage", "remote");
        }
    }
    url.to_string()
}

/// Signs in. With `browser_here`, `show` gets the consent page URL and a
/// listener on this machine waits for Google's redirect; otherwise `show`
/// gets a URL to open anywhere and `paste` asks for the code Google's page
/// then shows. Returns the account's email.
pub async fn login(
    integration: &str,
    config: &GcpConfig,
    browser_here: bool,
    show: impl FnOnce(&str),
    paste: impl FnOnce() -> anyhow::Result<String>,
) -> anyhow::Result<String> {
    let (client_id, client_secret) = client(config);
    if !browser_here && config.client_id.is_some() {
        bail!(
            "signing in from another device uses Google's code page, which only serves gcloud's \
             client; sign in on a machine with a browser, or drop client_id"
        );
    }
    let Pkce {
        verifier,
        challenge,
        state,
    } = Pkce::new()?;

    let (code, redirect_uri) = if browser_here {
        let loopback = Loopback::bind(0)?;
        // gcloud's redirect: `localhost`, any port, the root path.
        let redirect_uri = format!("http://localhost:{}/", loopback.port());
        show(&authorize_url(
            client_id,
            &redirect_uri,
            &state,
            &challenge,
            false,
        ));
        let code = loopback.code("/", &state, "Google").await?;
        (code, redirect_uri)
    } else {
        show(&authorize_url(
            client_id,
            PASTE_REDIRECT,
            &state,
            &challenge,
            true,
        ));
        let code = paste()?.trim().to_string();
        if code.is_empty() {
            bail!("no code was pasted");
        }
        (code, PASTE_REDIRECT.to_string())
    };

    let now = Timestamp::now();
    let response = exchange(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", &redirect_uri),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("code_verifier", &verifier),
    ])
    .await
    .map_err(anyhow::Error::from)
    .context("exchanging the sign-in code")?;
    if let Some(granted) = &response.scope
        && !granted.split(' ').any(|s| s == CLOUD_PLATFORM)
    {
        bail!(
            "the sign-in did not grant access to Google Cloud (cloud-platform); \
             sign in again and allow it on the consent page"
        );
    }
    let refresh_token = response
        .refresh_token
        .clone()
        .context("Google returned no refresh token; sign in again")?;
    let email = match response.id_token.as_deref().and_then(id_token_email) {
        Some(email) => email,
        None => token_info(&response.access_token)
            .await?
            .email
            .context("Google did not say which account signed in")?,
    };
    let stored = Stored {
        refresh_token,
        access_token: response.access_token,
        expires_at: expiry(now, response.expires_in)?,
        email: email.clone(),
        client_id: client_id.to_string(),
        id_token: response.id_token,
    };
    // Not while a renewal is under way, which would write back the sign-in
    // it read.
    let _lock = store::lock(&lock_name(integration), RENEW_LOCK_TIMEOUT).await?;
    store::set(&token_key(integration), &stored)?;
    Ok(email)
}

fn expiry(now: Timestamp, expires_in: Option<i64>) -> anyhow::Result<Timestamp> {
    Ok(now.checked_add(SignedDuration::from_secs(expires_in.unwrap_or(3600)))?)
}

/// The `email` claim of an ID token straight from the token endpoint (over
/// TLS, so its signature need not be checked to trust it).
fn id_token_email(id_token: &str) -> Option<String> {
    let claims: serde_json::Value = crate::oauth::decode_jwt_payload(id_token).ok()?;
    claims.get("email")?.as_str().map(str::to_string)
}

async fn exchange(form: &[(&str, &str)]) -> std::result::Result<TokenResponse, ExchangeError> {
    let response = crate::http::client()
        .post(url(Endpoint::Token))
        .form(form)
        .send()
        .await
        .map_err(|e| ExchangeError::Other(e.into()))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| ExchangeError::Other(e.into()))?;
    if !status.is_success() {
        #[derive(Deserialize)]
        struct Body {
            error: String,
            #[serde(default)]
            error_subtype: Option<String>,
            #[serde(default)]
            error_description: Option<String>,
        }
        return Err(match serde_json::from_str::<Body>(&text) {
            Ok(b) => ExchangeError::Refused(OauthError {
                error: b.error,
                subtype: b.error_subtype,
                description: b.error_description.unwrap_or_default(),
            }),
            Err(_) => ExchangeError::Other(anyhow!(
                "token endpoint answered {status}: {}",
                text.chars().take(200).collect::<String>()
            )),
        });
    }
    serde_json::from_str(&text)
        .context("unexpected token response")
        .map_err(ExchangeError::Other)
}

#[derive(Debug, thiserror::Error)]
enum ExchangeError {
    #[error(transparent)]
    Refused(OauthError),
    #[error(transparent)]
    Other(anyhow::Error),
}

fn stored(integration: &str) -> Result<Stored> {
    store::get::<Stored>(&token_key(integration))?.ok_or_else(|| Error::not_signed_in(integration))
}

fn lock_name(integration: &str) -> String {
    format!("gcp-{integration}")
}

/// How long to wait for another process that is renewing the same sign-in,
/// or storing a new one.
const RENEW_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// A new access token from the refresh token, stored for omnifob's own calls.
///
/// Under a lock that `login` takes too, so a sign-in stored while this one
/// renews is never overwritten with the renewed old one.
async fn renew(integration: &str, config: &GcpConfig) -> Result<Stored> {
    let _lock = store::lock(&lock_name(integration), RENEW_LOCK_TIMEOUT).await?;
    let mut stored = stored(integration)?;
    let (client_id, client_secret) = client(config);
    if stored.client_id != client_id {
        return Err(Error::needs_login(
            integration,
            format!("'{integration}' now names a different OAuth client than it signed in with"),
        ));
    }
    let now = Timestamp::now();
    let response = exchange(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", &stored.refresh_token),
        ("client_id", client_id),
        ("client_secret", client_secret),
    ])
    .await;
    let response = match response {
        Ok(r) => r,
        Err(ExchangeError::Refused(e)) if e.error == "invalid_grant" => {
            let reason = if e.subtype.as_deref() == Some("invalid_rapt") {
                "Google Cloud session control wants you to sign in again".to_string()
            } else {
                format!(
                    "the Google sign-in of '{integration}' ended ({})",
                    e.description
                )
            };
            return Err(Error::needs_login(integration, reason));
        }
        Err(e) => return Err(anyhow::Error::from(e).into()),
    };
    stored.expires_at = expiry(now, response.expires_in)?;
    stored.access_token = response.access_token;
    if let Some(refresh) = response.refresh_token {
        stored.refresh_token = refresh;
    }
    if response.id_token.is_some() {
        stored.id_token = response.id_token;
    }
    store::set(&token_key(integration), &stored)?;
    Ok(stored)
}

/// An access token for omnifob's own calls, reused while it lasts.
async fn access_token(integration: &str, config: &GcpConfig) -> Result<String> {
    let stored = stored(integration)?;
    if stored.expires_at.duration_since(Timestamp::now()) > RENEW_MARGIN {
        return Ok(stored.access_token);
    }
    Ok(renew(integration, config).await?.access_token)
}

/// Google rejected the access token (401), which happens before its time
/// when the grant is revoked or the token is replaced.
#[derive(Debug, thiserror::Error)]
#[error("Google rejected the access token (401 Unauthorized)")]
struct Unauthorized;

/// Runs `call` with the stored access token, and once more with a renewed
/// one if Google rejects it.
async fn with_access_token<T, F, Fut>(integration: &str, config: &GcpConfig, call: F) -> Result<T>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let token = access_token(integration, config).await?;
    match call(token).await {
        Err(e) if e.is::<Unauthorized>() => {
            tracing::debug!("Google rejected the stored access token; renewing it");
            let token = renew(integration, config).await?.access_token;
            Ok(call(token).await?)
        }
        result => Ok(result?),
    }
}

/// When an ID token expires: its `exp` claim.
fn id_token_expiry(id_token: &str) -> Option<Timestamp> {
    #[derive(Deserialize)]
    struct Exp {
        exp: i64,
    }
    let claims: Exp = crate::oauth::decode_jwt_payload(id_token).ok()?;
    Timestamp::from_second(claims.exp).ok()
}

/// The account's Google ID token (issuer `https://accounts.google.com`,
/// audience the OAuth client), renewed when it has less than
/// `RENEW_MARGIN` left: the subject token of executable-sourced
/// credentials, which Google's STS exchanges through a workload identity
/// pool that trusts Google as an OIDC provider.
pub async fn id_token(integration: &str, config: &GcpConfig) -> Result<(String, Timestamp)> {
    let current = |stored: &Stored| {
        let token = stored.id_token.clone()?;
        let expiry = id_token_expiry(&token)?;
        (expiry.duration_since(Timestamp::now()) > RENEW_MARGIN).then_some((token, expiry))
    };
    if let Some(found) = current(&stored(integration)?) {
        return Ok(found);
    }
    let renewed = renew(integration, config).await?;
    current(&renewed).ok_or_else(|| {
        anyhow!("Google returned no ID token; sign in again with `fob login {integration} --force`")
            .into()
    })
}

pub fn is_signed_in(integration: &str) -> anyhow::Result<bool> {
    Ok(store::get::<Stored>(&token_key(integration))?.is_some())
}

/// Whether the stored sign-in belongs to the configured OAuth client: its
/// refresh token renews only with that one. `false` when none is stored.
pub fn session_matches(integration: &str, config: &GcpConfig) -> anyhow::Result<bool> {
    Ok(store::get::<Stored>(&token_key(integration))?
        .is_some_and(|s| s.client_id == client(config).0))
}

/// The signed-in account's email.
pub fn account(integration: &str) -> anyhow::Result<Option<String>> {
    Ok(store::get::<Stored>(&token_key(integration))?.map(|s| s.email))
}

pub fn logout(integration: &str) -> anyhow::Result<bool> {
    store::delete(&token_key(integration))
}

/// Revokes the refresh token at Google, as `gcloud auth revoke` does.
/// Returns whether there was one.
pub async fn end_session(integration: &str) -> anyhow::Result<bool> {
    let Some(stored) = store::get::<Stored>(&token_key(integration))? else {
        return Ok(false);
    };
    let response = crate::http::client()
        .post(url(Endpoint::Revoke))
        .form(&[("token", stored.refresh_token.as_str())])
        .send()
        .await?;
    // 400 `invalid_token`: already revoked or expired, which is the goal.
    if !response.status().is_success() && response.status() != reqwest::StatusCode::BAD_REQUEST {
        bail!("Google answered {}", response.status());
    }
    Ok(true)
}

#[derive(Deserialize)]
struct TokenInfo {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    azp: Option<String>,
}

/// Asks Google whom an access token belongs to. The token goes in a POST
/// form body, never the URL, so it stays out of proxy logs and error messages.
async fn token_info(access_token: &str) -> anyhow::Result<TokenInfo> {
    let response = crate::http::client()
        .post(url(Endpoint::TokenInfo))
        .form(&[("access_token", access_token)])
        .send()
        .await?;
    if !response.status().is_success() {
        bail!("Google does not accept the token ({})", response.status());
    }
    Ok(response.json().await?)
}

/// Checks the stored sign-in by renewing it.
pub async fn check(integration: &str, config: &GcpConfig) -> Result<String> {
    let stored = renew(integration, config).await?;
    Ok(format!("signed in as {}", stored.email))
}

/// Says whom an access token acts as.
pub async fn check_token(creds: &Credentials) -> Result<String> {
    let token = creds
        .env
        .get("CLOUDSDK_AUTH_ACCESS_TOKEN")
        .context("no token in the credentials")?;
    let info = token_info(token).await?;
    Ok(format!(
        "acts as {}",
        info.email.or(info.azp).unwrap_or_else(|| "?".into())
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Project {
    project_id: String,
    #[serde(default)]
    name: Option<String>,
}

/// Every active project the account can see.
async fn list_projects(integration: &str, config: &GcpConfig) -> Result<Vec<Project>> {
    with_access_token(integration, config, |token| async move {
        list_projects_with(&token).await
    })
    .await
}

async fn list_projects_with(token: &str) -> anyhow::Result<Vec<Project>> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Page {
        #[serde(default)]
        projects: Vec<Project>,
        #[serde(default)]
        next_page_token: Option<String>,
    }
    let http = crate::http::client();
    let mut projects = Vec::new();
    let mut page_token: Option<String> = None;
    loop {
        let mut request = http
            .get(url(Endpoint::Projects))
            .bearer_auth(token)
            .query(&[("filter", "lifecycleState:ACTIVE")]);
        if let Some(t) = &page_token {
            request = request.query(&[("pageToken", t)]);
        }
        let response = request.send().await?;
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Unauthorized.into());
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            bail!(
                "listing projects failed ({status}): {}",
                body.chars().take(300).collect::<String>()
            );
        }
        let page: Page = response.json().await?;
        projects.extend(page.projects);
        match page.next_page_token.filter(|t| !t.is_empty()) {
            Some(t) => page_token = Some(t),
            None => break,
        }
    }
    projects.sort_by(|a, b| a.project_id.cmp(&b.project_id));
    Ok(projects)
}

/// The account in each project, and each configured service account.
pub async fn discover(integration: &str, config: &GcpConfig) -> Result<Vec<Profile>> {
    let projects = match &config.projects {
        Some(ids) => {
            // Proves the sign-in works even when nothing is listed.
            access_token(integration, config).await?;
            ids.iter()
                .map(|id| Project {
                    project_id: id.clone(),
                    name: None,
                })
                .collect()
        }
        None => list_projects(integration, config).await?,
    };
    let mut profiles: Vec<Profile> = projects
        .into_iter()
        .map(|p| {
            let target = Target::Gcp {
                project_name: p.name.unwrap_or_else(|| p.project_id.clone()),
                project_id: p.project_id.clone(),
            };
            Profile::new(integration, &p.project_id, "user", target)
        })
        .collect();
    for (label, sa) in &config.service_accounts {
        let profile = Profile::new(
            integration,
            label,
            sa.name(),
            Target::GcpServiceAccount {
                label: label.clone(),
                project_id: sa.project().map(str::to_string),
            },
        );
        // A label named like a project, for an account named `user`.
        if profiles.iter().any(|p| p.id == profile.id) {
            return Err(anyhow::anyhow!(
                "the service account '{label}' of '{integration}' would be {}, which the \
                 account's own profile in a project already is; give it another label in \
                 [integrations.{integration}.service_accounts]",
                profile.id
            )
            .into());
        }
        profiles.push(profile);
    }
    Ok(profiles)
}

fn token_credentials(token: String, project: Option<&str>, expires_at: Timestamp) -> Credentials {
    let mut creds = Credentials {
        expires_at: Some(expires_at),
        ..Credentials::default()
    };
    // gcloud reads the first, Terraform's google provider the second.
    creds
        .env
        .insert("CLOUDSDK_AUTH_ACCESS_TOKEN".into(), token.clone());
    creds.env.insert("GOOGLE_OAUTH_ACCESS_TOKEN".into(), token);
    if let Some(project) = project {
        creds
            .env
            .insert("CLOUDSDK_CORE_PROJECT".into(), project.to_string());
        creds
            .env
            .insert("GOOGLE_CLOUD_PROJECT".into(), project.to_string());
    }
    creds
}

/// The account's own access token, new, for a project.
pub async fn user_credentials(
    integration: &str,
    config: &GcpConfig,
    project_id: &str,
) -> Result<Credentials> {
    let stored = renew(integration, config).await?;
    Ok(token_credentials(
        stored.access_token,
        Some(project_id),
        stored.expires_at,
    ))
}

/// A token for a configured service account, from the IAM Credentials API.
pub async fn service_account_credentials(
    integration: &str,
    config: &GcpConfig,
    label: &str,
    ttl: Option<SignedDuration>,
) -> Result<Credentials> {
    let sa = config.service_accounts.get(label).with_context(|| {
        format!("no service account '{label}' in integration '{integration}'; run `fob sync`")
    })?;
    let lifetime = ttl.or(sa.lifetime).unwrap_or(DEFAULT_LIFETIME);
    if !(SignedDuration::from_mins(15)..=SignedDuration::from_hours(12)).contains(&lifetime) {
        return Err(anyhow!("a service account token lasts 15 minutes to 12 hours").into());
    }
    let (access_token, expires_at) = with_access_token(integration, config, |token| async move {
        impersonate(&token, sa, lifetime).await
    })
    .await?;
    Ok(token_credentials(access_token, sa.project(), expires_at))
}

async fn impersonate(
    token: &str,
    sa: &GcpServiceAccount,
    lifetime: SignedDuration,
) -> anyhow::Result<(String, Timestamp)> {
    #[derive(Serialize)]
    struct Request<'a> {
        scope: Vec<&'a str>,
        lifetime: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        delegates: Vec<String>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Response {
        access_token: String,
        expire_time: Timestamp,
    }
    let scope = match &sa.scopes {
        Some(scopes) => scopes.iter().map(String::as_str).collect(),
        None => vec![CLOUD_PLATFORM, USERINFO_EMAIL],
    };
    let request = Request {
        scope,
        lifetime: format!("{}s", lifetime.as_secs()),
        delegates: sa
            .delegates
            .iter()
            .map(|d| format!("projects/-/serviceAccounts/{d}"))
            .collect(),
    };
    let response = crate::http::client()
        .post(format!(
            "{}{}:generateAccessToken",
            url(Endpoint::GenerateAccessToken),
            sa.email
        ))
        .bearer_auth(token)
        .json(&request)
        .send()
        .await?;
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(Unauthorized.into());
    }
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        let hint = if status == reqwest::StatusCode::FORBIDDEN {
            " (impersonating needs the Service Account Token Creator role on it)"
        } else if status == reqwest::StatusCode::BAD_REQUEST && lifetime > DEFAULT_LIFETIME {
            " (over an hour needs the organization policy iam.allowServiceAccountCredentialLifetimeExtension)"
        } else {
            ""
        };
        bail!(
            "impersonating {} failed ({status}){hint}: {}",
            sa.email,
            body.chars().take(300).collect::<String>()
        );
    }
    let response: Response = response.json().await?;
    Ok((response.access_token, response.expire_time))
}

/// The Cloud console for a project, opened as the signed-in account (Google
/// has no way to open it as a service account).
pub fn console_url(integration: &str, project_id: Option<&str>) -> anyhow::Result<String> {
    let mut url = reqwest::Url::parse("https://console.cloud.google.com/home/dashboard")?;
    {
        let mut q = url.query_pairs_mut();
        if let Some(project) = project_id {
            q.append_pair("project", project);
        }
        if let Some(email) = account(integration)? {
            q.append_pair("authuser", &email);
        }
    }
    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn consent_url_follows_gcloud() {
        let url = reqwest::Url::parse(&authorize_url(
            GCLOUD_CLIENT_ID,
            "http://localhost:8085/",
            "st",
            "ch",
            false,
        ))
        .unwrap();
        let q: std::collections::BTreeMap<_, _> = url.query_pairs().collect();
        assert_eq!(q["client_id"], GCLOUD_CLIENT_ID);
        assert_eq!(q["redirect_uri"], "http://localhost:8085/");
        assert_eq!(q["access_type"], "offline");
        assert_eq!(q["code_challenge_method"], "S256");
        assert!(q["scope"].contains("cloud-platform"));
        assert!(!q.contains_key("prompt"));

        let url = reqwest::Url::parse(&authorize_url(
            GCLOUD_CLIENT_ID,
            PASTE_REDIRECT,
            "st",
            "ch",
            true,
        ))
        .unwrap();
        let q: std::collections::BTreeMap<_, _> = url.query_pairs().collect();
        assert_eq!(q["prompt"], "consent");
        assert_eq!(q["token_usage"], "remote");
    }

    #[test]
    fn email_comes_from_the_id_token() {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"email":"me@example.com","sub":"1"}"#);
        assert_eq!(
            id_token_email(&format!("h.{payload}.s")).as_deref(),
            Some("me@example.com")
        );
        assert_eq!(id_token_email("garbage"), None);
    }

    #[test]
    fn service_account_project_comes_from_its_email() {
        let sa = |email: &str| GcpServiceAccount {
            email: email.into(),
            project: None,
            lifetime: None,
            delegates: vec![],
            scopes: None,
        };
        let deploy = sa("deploy@my-proj.iam.gserviceaccount.com");
        assert_eq!(deploy.project(), Some("my-proj"));
        assert_eq!(deploy.name(), "deploy");
        assert_eq!(
            sa("123-compute@developer.gserviceaccount.com").project(),
            None
        );
    }
}
