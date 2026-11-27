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

use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};

use crate::config::AzureConfig;
use crate::oauth::{Loopback, Pkce};
use crate::{Credentials, Error, Profile, Result, Target, store};

/// The Azure CLI's client (`AZURE_CLI_CLIENT_ID` in `auth/constants.py`).
pub const CLIENT_ID: &str = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";

/// Resource Manager, as `az` asks for it (the double slash is right: the
/// resource is `https://management.core.windows.net/`).
const SCOPE: &str = "https://management.core.windows.net//.default offline_access openid profile";

const ARM_API_VERSION: &str = "2022-12-01";

fn login_host() -> String {
    crate::Context::current()
        .endpoints()
        .azure
        .clone()
        .unwrap_or_else(|| "https://login.microsoftonline.com".to_string())
}

fn arm_host() -> String {
    crate::Context::current()
        .endpoints()
        .azure
        .clone()
        .unwrap_or_else(|| "https://management.azure.com".to_string())
}

fn authority(tenant: &str) -> String {
    format!("{}/{tenant}/oauth2/v2.0", login_host())
}

fn token_key(integration: &str) -> String {
    format!("azure/{integration}/oauth")
}

fn pending_key(integration: &str) -> String {
    format!("azure/{integration}/pending")
}

/// Every keychain key an integration uses, for renaming it.
pub fn keys(integration: &str) -> Vec<String> {
    vec![token_key(integration), pending_key(integration)]
}

/// A device sign-in waiting for approval, kept between `fob login --start`
/// and `fob login --wait`. Not `Debug`: whoever polls with the device code
/// gets the tokens once the person approves.
#[derive(Clone, Serialize, Deserialize)]
struct PendingDevice {
    /// The authority's tenant the sign-in started with.
    tenant: String,
    device_code: String,
    interval_secs: u64,
    expires_at: jiff::Timestamp,
}

/// What the keychain keeps for a signed-in integration. Not `Debug`: it holds
/// the refresh token.
#[derive(Clone, Serialize, Deserialize)]
struct Stored {
    refresh_token: String,
    username: String,
    /// The tenant the account signed in to.
    tenant_id: String,
    /// The configured `tenant` signed in with; `None` for `organizations`.
    #[serde(default)]
    tenant: Option<String>,
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

async fn exchange(
    tenant: &str,
    form: &[(&str, &str)],
    client_session: Option<&str>,
) -> anyhow::Result<Exchange> {
    let mut request = crate::http::client().post(format!("{}/token", authority(tenant)));
    if let Some(session) = client_session {
        request = request.query(&[("client_session", session)]);
    }
    let response = request.form(form).send().await?;
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
    crate::oauth::decode_jwt_payload(id_token).ok()
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
        let (pending, user_code, url) = start_device(tenant).await?;
        show(SignInPrompt {
            url: &url,
            user_code: Some(&user_code),
        });
        poll_device(&pending).await?
    };
    keep_sign_in(integration, config, response).await
}

/// What `fob login --start` shows: where to approve, the code, and until when.
#[derive(Debug, Clone)]
pub struct DeviceStart {
    pub url: String,
    pub user_code: String,
    pub expires_at: jiff::Timestamp,
}

/// Starts a device sign-in and keeps it for [`finish_device_login`], so the
/// code can be shown and the process end while the person approves it.
pub async fn start_device_login(
    integration: &str,
    config: &AzureConfig,
) -> anyhow::Result<DeviceStart> {
    let tenant = config.tenant.as_deref().unwrap_or("organizations");
    let (pending, user_code, url) = start_device(tenant).await?;
    store::set(&pending_key(integration), &pending)?;
    Ok(DeviceStart {
        url,
        user_code,
        expires_at: pending.expires_at,
    })
}

/// Whether a device sign-in [`start_device_login`] started is waiting.
pub fn has_pending_login(integration: &str) -> anyhow::Result<bool> {
    Ok(store::get::<PendingDevice>(&pending_key(integration))?.is_some())
}

/// Waits for the sign-in [`start_device_login`] started to be approved,
/// then keeps it as `login` does; returns the account's user name. The
/// started sign-in is forgotten once it ends either way.
pub async fn finish_device_login(
    integration: &str,
    config: &AzureConfig,
) -> anyhow::Result<String> {
    let key = pending_key(integration);
    let Some(pending) = store::get::<PendingDevice>(&key)? else {
        bail!(
            "no device sign-in was started for '{integration}'; run `fob login {integration} --start` first"
        );
    };
    if pending.tenant != config.tenant.as_deref().unwrap_or("organizations") {
        store::delete(&key)?;
        bail!(
            "the sign-in started for '{integration}' was for another tenant; run `fob login {integration} --start` again"
        );
    }
    if pending.expires_at <= jiff::Timestamp::now() {
        store::delete(&key)?;
        bail!(
            "the code of the sign-in started for '{integration}' expired; run `fob login {integration} --start` again"
        );
    }
    let polled = poll_device(&pending).await;
    // Approved, refused or expired, the device code is spent.
    store::delete(&key)?;
    keep_sign_in(integration, config, polled?).await
}

/// Stores the sign-in a token response holds; returns the user name.
async fn keep_sign_in(
    integration: &str,
    config: &AzureConfig,
    response: TokenResponse,
) -> anyhow::Result<String> {
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
        tenant: config.tenant.clone(),
    };
    // Not while a token is being fetched, which would write back the
    // sign-in it read.
    let _lock = store::lock(&lock_name(integration), TOKEN_LOCK_TIMEOUT).await?;
    store::set(&token_key(integration), &stored)?;
    Ok(username)
}

async fn browser_sign_in(
    tenant: &str,
    show: impl FnOnce(SignInPrompt),
) -> anyhow::Result<TokenResponse> {
    let loopback = Loopback::bind(0)?;
    // MSAL's redirect for public clients: `localhost`, any port, no path.
    let redirect_uri = format!("http://localhost:{}", loopback.port());
    let Pkce {
        verifier,
        challenge,
        state,
    } = Pkce::new()?;
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
    let code = loopback.code("/", &state, "Azure").await?;
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
        None,
    )
    .await?
    {
        Exchange::Ok(r) => Ok(r),
        Exchange::Refused(e) => bail!("Entra ID refused the sign-in: {}", e.detail()),
    }
}

/// Starts the device flow: what polling needs, the code and where to enter it.
async fn start_device(tenant: &str) -> anyhow::Result<(PendingDevice, String, String)> {
    #[derive(Deserialize)]
    struct DeviceCode {
        device_code: String,
        user_code: String,
        verification_uri: String,
        expires_in: u64,
        #[serde(default)]
        interval: Option<u64>,
    }
    let response = crate::http::client()
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
    let expires_at = jiff::Timestamp::now()
        .saturating_add(jiff::SignedDuration::from_secs(device.expires_in as i64))
        .unwrap_or(jiff::Timestamp::MAX);
    let pending = PendingDevice {
        tenant: tenant.to_string(),
        device_code: device.device_code,
        interval_secs: device.interval.unwrap_or(5),
        expires_at,
    };
    Ok((pending, device.user_code, device.verification_uri))
}

/// Polls until the person approves the device sign-in, or its code expires.
async fn poll_device(pending: &PendingDevice) -> anyhow::Result<TokenResponse> {
    let mut interval = Duration::from_secs(pending.interval_secs);
    loop {
        tokio::time::sleep(interval).await;
        let polled = exchange(
            &pending.tenant,
            &[
                ("client_id", CLIENT_ID),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", &pending.device_code),
            ],
            None,
        )
        .await?;
        match polled {
            Exchange::Ok(r) => return Ok(r),
            Exchange::Refused(e) if e.error == "authorization_pending" => {}
            Exchange::Refused(e) if e.error == "slow_down" => interval += Duration::from_secs(5),
            Exchange::Refused(e) => bail!("Entra ID refused the sign-in: {}", e.detail()),
        }
        if jiff::Timestamp::now() >= pending.expires_at {
            bail!("the sign-in was not approved in time");
        }
    }
}

fn stored(integration: &str) -> Result<Stored> {
    store::get::<Stored>(&token_key(integration))?.ok_or_else(|| Error::not_signed_in(integration))
}

fn lock_name(integration: &str) -> String {
    format!("azure-{integration}")
}

/// How long to wait for another process that is using the same refresh
/// token, or storing a new sign-in.
const TOKEN_LOCK_TIMEOUT: Duration = Duration::from_secs(30);

/// Deletes the stored sign-in if it still holds `refresh_token`, so one
/// stored meanwhile is kept.
fn drop_if_current(integration: &str, refresh_token: &str) {
    if let Ok(Some(stored)) = store::get::<Stored>(&token_key(integration))
        && stored.refresh_token == refresh_token
    {
        let _ = store::delete(&token_key(integration));
    }
}

/// A Resource Manager token for `tenant`; see [`scope_token`].
async fn arm_token(integration: &str, tenant: &str) -> Result<(String, Timestamp)> {
    scope_token(integration, tenant, SCOPE).await
}

/// The scope that asks Entra ID for a token for `resource`, as the Azure
/// CLI's `resource_to_scopes` writes it (`<resource>/.default`, so a
/// resource that ends in a slash gets two), plus `offline_access`, so the
/// refresh token keeps rotating.
fn resource_scope(resource: &str) -> String {
    format!("{resource}/.default offline_access")
}

/// A token for `resource` (Key Vault, Storage, Graph, an AKS cluster's
/// server app) in `tenant`, from the stored sign-in; see `scope_token`.
/// The Azure CLI's client is pre-authorized for Azure's own resources.
pub async fn resource_token(
    integration: &str,
    tenant: &str,
    resource: &str,
) -> Result<(String, Timestamp)> {
    if resource.is_empty() || resource.chars().any(char::is_whitespace) {
        return Err(anyhow!("'{resource}' is not a resource URI or app ID").into());
    }
    scope_token(integration, tenant, &resource_scope(resource)).await
}

/// A token for `scope` in `tenant`, from the refresh token; stores the
/// rotated refresh token. A refusal particular to the tenant (MFA,
/// conditional access) is an error for it alone; a refusal of the sign-in
/// itself forgets it and asks for a new one.
///
/// Entra ID keeps the previous refresh token valid after a rotation, so
/// parallel commands lose nothing; the lock (which `login` takes too) keeps
/// a rotated token from overwriting a sign-in stored meanwhile.
///
/// For a coding agent with a session (`COPILOT_AGENT_SESSION_ID`), the
/// request carries it as `client_session`, in the body and the query, as
/// the Azure CLI sends it, so Entra ID marks the token as an agent's.
async fn scope_token(integration: &str, tenant: &str, scope: &str) -> Result<(String, Timestamp)> {
    let _lock = store::lock(&lock_name(integration), TOKEN_LOCK_TIMEOUT).await?;
    let mut stored = stored(integration)?;
    let now = Timestamp::now();
    let session = crate::Context::current()
        .agent()
        .and_then(|a| a.session_id.clone());
    let mut form = vec![
        ("client_id", CLIENT_ID),
        ("grant_type", "refresh_token"),
        ("refresh_token", stored.refresh_token.as_str()),
        ("scope", scope),
    ];
    if let Some(session) = &session {
        form.push(("client_session", session));
    }
    let response = match exchange(tenant, &form, session.as_deref()).await? {
        Exchange::Ok(r) => r,
        Exchange::Refused(e) if e.error == "invalid_grant" && tenant == stored.tenant_id => {
            drop_if_current(integration, &stored.refresh_token);
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

/// Whether the stored sign-in was made for the configured tenant (or the
/// tenant is the one it signed in to). `false` when none is stored.
pub fn session_matches(integration: &str, config: &AzureConfig) -> anyhow::Result<bool> {
    Ok(
        store::get::<Stored>(&token_key(integration))?.is_some_and(|s| {
            s.tenant == config.tenant || config.tenant.as_deref() == Some(s.tenant_id.as_str())
        }),
    )
}

pub fn account(integration: &str) -> anyhow::Result<Option<String>> {
    Ok(store::get::<Stored>(&token_key(integration))?.map(|s| s.username))
}

/// Forgets the sign-in. Entra ID offers public clients no revocation, so,
/// as with `az logout`, the refresh token is only deleted here.
pub fn logout(integration: &str) -> anyhow::Result<bool> {
    store::delete(&pending_key(integration))?;
    store::delete(&token_key(integration))
}

pub async fn check(integration: &str) -> Result<String> {
    let stored = stored(integration)?;
    arm_token(integration, &stored.tenant_id).await?;
    Ok(format!("signed in as {}", stored.username))
}

/// GETs every page of a Resource Manager list, all with one client.
async fn arm_list<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
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
        let response = http.get(&url).bearer_auth(token).send().await?;
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
        next = match page.next_link.filter(|l| !l.is_empty()) {
            Some(link) => Some(same_origin(&link, &arm_host())?),
            None => None,
        };
    }
    Ok(items)
}

/// Checks that a `nextLink` points at Resource Manager itself (the same
/// scheme, host and port as `arm`) before the bearer token is sent to it, so
/// a tampered or unexpected answer cannot send the token elsewhere.
fn same_origin(link: &str, arm: &str) -> anyhow::Result<String> {
    let url = reqwest::Url::parse(link)
        .with_context(|| format!("Resource Manager gave an invalid nextLink: {link}"))?;
    let arm = reqwest::Url::parse(arm).with_context(|| format!("invalid endpoint {arm}"))?;
    let origin = |u: &reqwest::Url| {
        (
            u.scheme().to_owned(),
            u.host_str().map(str::to_ascii_lowercase),
            u.port_or_known_default(),
        )
    };
    if origin(&url) != origin(&arm) {
        bail!(
            "Resource Manager's nextLink leaves {}: not following {}://{}",
            arm.origin().ascii_serialization(),
            url.scheme(),
            url.host_str().unwrap_or_default()
        );
    }
    Ok(url.into())
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
///
/// Tenants are worked on together: each one's token is obtained in tenant
/// order, one exchange at a time (each rotates the refresh token, and
/// `arm_token` holds the integration's lock), while the subscription lists
/// of the tenants that already have a token are fetched meanwhile. Results
/// are merged in tenant order, so a subscription reachable from two tenants
/// keeps the first, as `az` does. A tenant other than the home tenant that
/// refuses a token or fails to list its subscriptions is skipped with a
/// warning.
pub async fn discover(integration: &str, config: &AzureConfig) -> Result<Vec<Profile>> {
    let stored = stored(integration)?;
    let http = crate::http::client();
    let (home_token, _) = arm_token(integration, &stored.tenant_id).await?;
    let tenants: Vec<String> = if config.tenant.is_some() {
        vec![stored.tenant_id.clone()]
    } else {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Tenant {
            tenant_id: String,
        }
        arm_list::<Tenant>(&http, &home_token, "/tenants")
            .await?
            .into_iter()
            .map(|t| t.tenant_id)
            .collect()
    };

    // Taken in tenant order: `join_all` polls the futures in order, and a
    // Tokio mutex hands itself out first come, first served.
    let exchanges = tokio::sync::Mutex::new(());
    let per_tenant = futures_util::future::join_all(tenants.iter().map(|tenant| {
        let (http, home_token, exchanges) = (&http, &home_token, &exchanges);
        let home = *tenant == stored.tenant_id;
        async move {
            let token = if home {
                home_token.clone()
            } else {
                let _turn = exchanges.lock().await;
                match arm_token(integration, tenant).await {
                    Ok((token, _)) => token,
                    Err(e @ Error::NeedsLogin { .. }) => return Err(e),
                    Err(e) => {
                        tracing::warn!("skipping tenant {tenant}: {e}");
                        return Ok(Vec::new());
                    }
                }
            };
            match arm_list::<Subscription>(http, &token, "/subscriptions").await {
                Ok(subs) => Ok(subs),
                Err(e) if home => Err(e.into()),
                Err(e) => {
                    tracing::warn!("skipping tenant {tenant}: {e:#}");
                    Ok(Vec::new())
                }
            }
        }
    }))
    .await;

    let mut profiles: Vec<Profile> = Vec::new();
    for (tenant, subs) in tenants.iter().zip(per_tenant) {
        for sub in subs? {
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
    // "Pay-As-You-Go" in two tenants, or "Acme (EU)" and "ACME EU".
    crate::profile::disambiguate_accounts(&mut profiles, |target| match target {
        Target::Azure {
            subscription_id,
            subscription_name,
            ..
        } => Some((subscription_name, subscription_id)),
        _ => None,
    });
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
    let response = crate::http::client()
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
    use base64::Engine;

    #[test]
    fn claims_name_the_account_and_tenant() {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"preferred_username":"me@contoso.com","tid":"t-1"}"#);
        let c = claims(&format!("h.{payload}.s")).unwrap();
        assert_eq!(c.preferred_username.as_deref(), Some("me@contoso.com"));
        assert_eq!(c.tid, "t-1");
    }

    #[test]
    fn next_links_must_stay_on_resource_manager() {
        let arm = "https://management.azure.com";
        let ok = "https://Management.Azure.com:443/subscriptions?api-version=1&$skiptoken=2";
        assert!(same_origin(ok, arm).is_ok());
        for bad in [
            "http://management.azure.com/subscriptions",
            "https://management.azure.com:8443/subscriptions",
            "https://evil.example/subscriptions",
            "https://management.azure.com.evil.example/subscriptions",
            "https://user@evil.example/subscriptions",
            "/subscriptions?page=2",
        ] {
            assert!(same_origin(bad, arm).is_err(), "{bad}");
        }
        // A test endpoint keeps its own port.
        assert!(same_origin("http://127.0.0.1:4000/x", "http://127.0.0.1:4000").is_ok());
        assert!(same_origin("http://127.0.0.1:4001/x", "http://127.0.0.1:4000").is_err());
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
