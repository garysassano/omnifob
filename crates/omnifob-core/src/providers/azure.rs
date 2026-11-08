//! A Microsoft Entra ID account (`type = "azure"`), signed in the way
//! `az login` signs in (read from azure-cli's `azure/cli/core/auth` and
//! `_profile.py` on 2026-11-08):
//!
//! - The Azure CLI's public client, `04b07795-8ddb-461a-bbee-02f9e1bf7b46`,
//!   which Microsoft's Azure Identity libraries also use by default for
//!   interactive sign-in. Public clients have no secret.
//! - The `organizations` authority unless a tenant is configured, and the
//!   Resource Manager scope `https://management.core.windows.net//.default`
//!   with `offline_access`, `openid` and `profile`, as MSAL adds them.
//! - Authorization code with PKCE and `prompt=select_account`, redirected to
//!   `http://localhost:<any port>`; or the device flow
//!   (`az login --use-device-code`).
//! - Subscriptions found as `az` finds them: list the tenants, get a token
//!   for each from the refresh token, list each tenant's subscriptions, and
//!   skip tenants that refuse (MFA or conditional access may want more).
//!
//! Entra ID rotates refresh tokens: each renewal returns a new one, which is
//! stored. Azure's tools take no access token from the environment (they call
//! `az`), so profiles export the subscription and tenant for them, and the
//! raw Resource Manager token as `AZURE_ACCESS_TOKEN` for `curl` and scripts.

use std::net::TcpListener;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use base64::Engine;
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};

use crate::config::AzureConfig;
use crate::oauth::{pkce, random_string, wait_for_code};
use crate::{Credentials, Error, Profile, Result, Target, store};

/// The Azure CLI's client (`AZURE_CLI_CLIENT_ID` in `auth/constants.py`).
const CLIENT_ID: &str = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";

/// Resource Manager, as `az` asks for it (the double slash is right: the
/// resource is `https://management.core.windows.net/`).
const SCOPE: &str = "https://management.core.windows.net//.default offline_access openid profile";

const ARM_API_VERSION: &str = "2022-12-01";

const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

fn login_host() -> String {
    std::env::var("OMNIFOB_AZURE_ENDPOINT")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "https://login.microsoftonline.com".to_string())
}

fn arm_host() -> String {
    std::env::var("OMNIFOB_AZURE_ENDPOINT")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "https://management.azure.com".to_string())
}

fn authority(tenant: &str) -> String {
    format!("{}/{tenant}/oauth2/v2.0", login_host())
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(concat!("omnifob/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("HTTP client")
}

fn token_key(integration: &str) -> String {
    format!("azure/{integration}/oauth")
}

/// Every keychain key an integration uses, for renaming it.
pub fn keys(integration: &str) -> Vec<String> {
    vec![token_key(integration)]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Stored {
    refresh_token: String,
    username: String,
    /// The tenant the account signed in to.
    tenant_id: String,
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
}

#[derive(Debug, Deserialize)]
struct OauthError {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

impl OauthError {
    /// The first line of the description: `AADSTS50076: Due to a
    /// configuration change...`; the rest is trace and correlation IDs.
    fn detail(&self) -> String {
        let description = self.error_description.as_deref().unwrap_or_default();
        format!(
            "{} {}",
            self.error,
            description.lines().next().unwrap_or_default()
        )
        .trim()
        .to_string()
    }
}

enum Exchange {
    Ok(TokenResponse),
    Refused(OauthError),
}

async fn exchange(tenant: &str, form: &[(&str, &str)]) -> anyhow::Result<Exchange> {
    let response = http()
        .post(format!("{}/token", authority(tenant)))
        .form(form)
        .send()
        .await?;
    let status = response.status();
    let text = response.text().await?;
    if status.is_success() {
        return Ok(Exchange::Ok(
            serde_json::from_str(&text).context("unexpected token response")?,
        ));
    }
    match serde_json::from_str::<OauthError>(&text) {
        Ok(e) => Ok(Exchange::Refused(e)),
        Err(_) => bail!(
            "Entra ID answered {status}: {}",
            text.chars().take(200).collect::<String>()
        ),
    }
}

/// What the ID token says about the account.
#[derive(Deserialize)]
struct Claims {
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    upn: Option<String>,
    tid: String,
}

fn claims(id_token: &str) -> Option<Claims> {
    let payload = id_token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// What `fob login` shows: a URL, and with the device flow a code to enter.
pub struct SignInPrompt<'a> {
    pub url: &'a str,
    pub user_code: Option<&'a str>,
}

/// Signs in, with the browser on this machine when `browser_here`, else with
/// the device flow. Returns the account's user name.
pub async fn login(
    integration: &str,
    config: &AzureConfig,
    browser_here: bool,
    show: impl FnOnce(SignInPrompt),
) -> anyhow::Result<String> {
    let tenant = config.tenant.as_deref().unwrap_or("organizations");
    let response = if browser_here {
        browser_sign_in(tenant, show).await?
    } else {
        device_sign_in(tenant, show).await?
    };
    let claims = response
        .id_token
        .as_deref()
        .and_then(claims)
        .context("Entra ID did not say which account signed in")?;
    let username = claims
        .preferred_username
        .or(claims.upn)
        .unwrap_or_else(|| "?".to_string());
    let stored = Stored {
        refresh_token: response
            .refresh_token
            .context("Entra ID returned no refresh token")?,
        username: username.clone(),
        tenant_id: claims.tid,
    };
    store::set(&token_key(integration), &stored)?;
    Ok(username)
}

async fn browser_sign_in(
    tenant: &str,
    show: impl FnOnce(SignInPrompt),
) -> anyhow::Result<TokenResponse> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .context("listening on 127.0.0.1 for the sign-in callback")?;
    // MSAL's redirect for public clients: `localhost`, any port, no path.
    let redirect_uri = format!("http://localhost:{}", listener.local_addr()?.port());
    let (verifier, challenge) = pkce()?;
    let state = random_string(16)?;
    let mut url = reqwest::Url::parse(&format!("{}/authorize", authority(tenant)))?;
    url.query_pairs_mut()
        .append_pair("client_id", CLIENT_ID)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", SCOPE)
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("prompt", "select_account");
    show(SignInPrompt {
        url: url.as_str(),
        user_code: None,
    });
    let code = tokio::task::spawn_blocking(move || {
        wait_for_code(&listener, "/", &state, CALLBACK_TIMEOUT, "Azure")
    })
    .await??;
    match exchange(
        tenant,
        &[
            ("client_id", CLIENT_ID),
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("code_verifier", &verifier),
            ("scope", SCOPE),
        ],
    )
    .await?
    {
        Exchange::Ok(r) => Ok(r),
        Exchange::Refused(e) => bail!("Entra ID refused the sign-in: {}", e.detail()),
    }
}

async fn device_sign_in(
    tenant: &str,
    show: impl FnOnce(SignInPrompt),
) -> anyhow::Result<TokenResponse> {
    #[derive(Deserialize)]
    struct DeviceCode {
        device_code: String,
        user_code: String,
        verification_uri: String,
        expires_in: u64,
        #[serde(default)]
        interval: Option<u64>,
    }
    let response = http()
        .post(format!("{}/devicecode", authority(tenant)))
        .form(&[("client_id", CLIENT_ID), ("scope", SCOPE)])
        .send()
        .await?;
    if !response.status().is_success() {
        bail!(
            "starting the device sign-in failed ({}): {}",
            response.status(),
            response.text().await.unwrap_or_default()
        );
    }
    let device: DeviceCode = response.json().await?;
    show(SignInPrompt {
        url: &device.verification_uri,
        user_code: Some(&device.user_code),
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(device.expires_in);
    let mut interval = Duration::from_secs(device.interval.unwrap_or(5));
    loop {
        tokio::time::sleep(interval).await;
        let polled = exchange(
            tenant,
            &[
                ("client_id", CLIENT_ID),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", &device.device_code),
            ],
        )
        .await?;
        match polled {
            Exchange::Ok(r) => return Ok(r),
            Exchange::Refused(e) if e.error == "authorization_pending" => {}
            Exchange::Refused(e) if e.error == "slow_down" => interval += Duration::from_secs(5),
            Exchange::Refused(e) => bail!("Entra ID refused the sign-in: {}", e.detail()),
        }
        if std::time::Instant::now() >= deadline {
            bail!("the sign-in was not approved in time");
        }
    }
}

fn stored(integration: &str) -> Result<Stored> {
    store::get::<Stored>(&token_key(integration))?.ok_or_else(|| Error::not_signed_in(integration))
}

/// A Resource Manager token for `tenant`, from the refresh token; stores the
/// rotated refresh token. A refusal particular to the tenant (MFA, conditional
/// access) is an error for it alone; a refusal of the sign-in itself asks
/// for a new one.
async fn arm_token(integration: &str, tenant: &str) -> Result<(String, Timestamp)> {
    let mut stored = stored(integration)?;
    let now = Timestamp::now();
    let response = match exchange(
        tenant,
        &[
            ("client_id", CLIENT_ID),
            ("grant_type", "refresh_token"),
            ("refresh_token", &stored.refresh_token),
            ("scope", SCOPE),
        ],
    )
    .await?
    {
        Exchange::Ok(r) => r,
        Exchange::Refused(e) if e.error == "invalid_grant" && tenant == stored.tenant_id => {
            return Err(Error::needs_login(
                integration,
                format!(
                    "Entra ID ended the sign-in of '{integration}': {}",
                    e.detail()
                ),
            ));
        }
        Exchange::Refused(e) => {
            return Err(anyhow!(
                "Entra ID refused a token for tenant {tenant}: {}",
                e.detail()
            )
            .into());
        }
    };
    if let Some(rotated) = response.refresh_token {
        stored.refresh_token = rotated;
        store::set(&token_key(integration), &stored)?;
    }
    let expires_at = now
        .checked_add(SignedDuration::from_secs(
            response.expires_in.unwrap_or(3600),
        ))
        .map_err(anyhow::Error::from)?;
    Ok((response.access_token, expires_at))
}

pub fn is_signed_in(integration: &str) -> anyhow::Result<bool> {
    Ok(store::get::<Stored>(&token_key(integration))?.is_some())
}

pub fn account(integration: &str) -> anyhow::Result<Option<String>> {
    Ok(store::get::<Stored>(&token_key(integration))?.map(|s| s.username))
}

/// Forgets the sign-in. Entra ID offers public clients no revocation, so,
/// as with `az logout`, the refresh token is only deleted here.
pub fn logout(integration: &str) -> anyhow::Result<bool> {
    store::delete(&token_key(integration))
}

pub async fn check(integration: &str) -> Result<String> {
    let stored = stored(integration)?;
    arm_token(integration, &stored.tenant_id).await?;
    Ok(format!("signed in as {}", stored.username))
}

/// GETs every page of a Resource Manager list.
async fn arm_list<T: serde::de::DeserializeOwned>(
    token: &str,
    path: &str,
) -> anyhow::Result<Vec<T>> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Page<T> {
        #[serde(default = "Vec::new")]
        value: Vec<T>,
        #[serde(default)]
        next_link: Option<String>,
    }
    let mut items = Vec::new();
    let mut next = Some(format!(
        "{}{path}?api-version={ARM_API_VERSION}",
        arm_host()
    ));
    while let Some(url) = next {
        let response = http().get(&url).bearer_auth(token).send().await?;
        let status = response.status();
        if !status.is_success() {
            bail!(
                "Resource Manager answered {status} for {path}: {}",
                response
                    .text()
                    .await
                    .unwrap_or_default()
                    .chars()
                    .take(300)
                    .collect::<String>()
            );
        }
        let page: Page<T> = response.json().await?;
        items.extend(page.value);
        next = page.next_link.filter(|l| !l.is_empty());
    }
    Ok(items)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Subscription {
    subscription_id: String,
    display_name: String,
    #[serde(default)]
    state: Option<String>,
}

/// One profile per subscription, in every tenant that grants a token.
pub async fn discover(integration: &str, config: &AzureConfig) -> Result<Vec<Profile>> {
    let stored = stored(integration)?;
    let (home_token, _) = arm_token(integration, &stored.tenant_id).await?;
    let tenants: Vec<String> = if config.tenant.is_some() {
        vec![stored.tenant_id.clone()]
    } else {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Tenant {
            tenant_id: String,
        }
        arm_list::<Tenant>(&home_token, "/tenants")
            .await?
            .into_iter()
            .map(|t| t.tenant_id)
            .collect()
    };

    let mut profiles: Vec<Profile> = Vec::new();
    for tenant in tenants {
        let token = if tenant == stored.tenant_id {
            home_token.clone()
        } else {
            match arm_token(integration, &tenant).await {
                Ok((token, _)) => token,
                Err(e @ Error::NeedsLogin { .. }) => return Err(e),
                Err(e) => {
                    tracing::warn!("skipping tenant {tenant}: {e}");
                    continue;
                }
            }
        };
        for sub in arm_list::<Subscription>(&token, "/subscriptions").await? {
            let wanted = config.subscriptions.as_ref().is_none_or(|ids| {
                ids.iter()
                    .any(|id| id.eq_ignore_ascii_case(&sub.subscription_id))
            });
            let enabled = sub.state.as_deref().is_none_or(|s| s != "Disabled");
            // A subscription reachable from two tenants keeps the first, as az does.
            let seen = profiles.iter().any(|p| {
                matches!(&p.target, Target::Azure { subscription_id, .. } if *subscription_id == sub.subscription_id)
            });
            if wanted && enabled && !seen {
                let target = Target::Azure {
                    subscription_id: sub.subscription_id,
                    subscription_name: sub.display_name.clone(),
                    tenant_id: tenant.clone(),
                };
                profiles.push(Profile::new(integration, &sub.display_name, "user", target));
            }
        }
    }
    Ok(profiles)
}

/// A Resource Manager token for a subscription's tenant, with the IDs
/// Azure's tools read.
pub async fn credentials(
    integration: &str,
    subscription_id: &str,
    tenant_id: &str,
) -> Result<Credentials> {
    let (token, expires_at) = arm_token(integration, tenant_id).await?;
    let mut creds = Credentials {
        expires_at: Some(expires_at),
        ..Credentials::default()
    };
    for (name, value) in [
        ("AZURE_SUBSCRIPTION_ID", subscription_id),
        ("AZURE_TENANT_ID", tenant_id),
        ("ARM_SUBSCRIPTION_ID", subscription_id),
        ("ARM_TENANT_ID", tenant_id),
        ("AZURE_ACCESS_TOKEN", &token),
    ] {
        creds.env.insert(name.to_string(), value.to_string());
    }
    Ok(creds)
}

/// Proves a profile's token reads its subscription.
pub async fn check_subscription(creds: &Credentials) -> Result<String> {
    let token = creds
        .env
        .get("AZURE_ACCESS_TOKEN")
        .context("no token in the credentials")?;
    let id = creds
        .env
        .get("AZURE_SUBSCRIPTION_ID")
        .context("no subscription in the credentials")?;
    let response = http()
        .get(format!(
            "{}/subscriptions/{id}?api-version={ARM_API_VERSION}",
            arm_host()
        ))
        .bearer_auth(token)
        .send()
        .await
        .map_err(anyhow::Error::from)?;
    if !response.status().is_success() {
        return Err(anyhow!("Resource Manager answered {}", response.status()).into());
    }
    let sub: Subscription = response.json().await.map_err(anyhow::Error::from)?;
    Ok(format!("reads subscription {}", sub.display_name))
}

/// The portal, on the subscription, in its tenant.
pub fn console_url(subscription_id: &str, tenant_id: &str) -> String {
    format!(
        "https://portal.azure.com/#@{tenant_id}/resource/subscriptions/{subscription_id}/overview"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_name_the_account_and_tenant() {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"preferred_username":"me@contoso.com","tid":"t-1"}"#);
        let c = claims(&format!("h.{payload}.s")).unwrap();
        assert_eq!(c.preferred_username.as_deref(), Some("me@contoso.com"));
        assert_eq!(c.tid, "t-1");
    }

    #[test]
    fn refusals_keep_the_first_line() {
        let e = OauthError {
            error: "interaction_required".into(),
            error_description: Some("AADSTS50076: MFA needed.\r\nTrace ID: x".into()),
        };
        assert_eq!(e.detail(), "interaction_required AADSTS50076: MFA needed.");
    }
}
