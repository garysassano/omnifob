//! AWS IAM Identity Center.
//!
//! Sign-in follows the AWS CLI (2.22 and later): the authorization code flow
//! with PKCE and a loopback redirect by default, the device flow on remote and
//! container sessions or on request. Both register omnifob as an OIDC client
//! with the `sso:account:access` scope, so Identity Center issues a refresh
//! token and the session renews silently until the portal session ends. The
//! registration is kept apart from the session and reused while it is valid.
//!
//! The token is kept in the keychain per integration and renewed shortly
//! before it expires (the approach aws-vault takes), under a lock shared by
//! every omnifob process, since a refresh token is treated as single use. Discovery
//! lists every account and role the token can reach (the approach Leapp
//! takes), and each role becomes a profile.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::TcpListener;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use aws_sdk_sso::error::{DisplayErrorContext, ProvideErrorMetadata};
use aws_sdk_ssooidc::operation::create_token::{CreateTokenError, CreateTokenOutput};
use futures::StreamExt;
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};

use crate::config::AwsSsoConfig;
use crate::{Credentials, Error, Profile, Result, Target, oauth, store};

/// A token expiring within this window is refreshed before use. Matches the
/// AWS CLI, so a token is never handed out with seconds left.
const REFRESH_WINDOW: SignedDuration = SignedDuration::from_mins(15);

/// How many accounts to list roles for at once; Identity Center throttles
/// aggressively, which is why Leapp throttles this call too.
const ROLE_LISTING_CONCURRENCY: usize = 4;

/// Where Identity Center sends the browser back to.
const CALLBACK_PATH: &str = "/oauth/callback";

/// The redirect URI registered for the client, without a port: Identity
/// Center accepts any port on a loopback redirect (RFC 8252, section 7.3), so
/// each sign-in can listen on a free one. The AWS CLI does the same.
const REGISTERED_REDIRECT: &str = "http://127.0.0.1/oauth/callback";

/// How long `fob login` waits for the browser sign-in to be approved.
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(600);

/// A client registration is renewed when it has less than this left, so a
/// new session never starts on a registration about to stop refreshing.
const REGISTRATION_MARGIN: SignedDuration = SignedDuration::from_hours(24);

/// How often `GetRoleCredentials` is retried on 403, waiting 1s, then 2s.
const FORBIDDEN_RETRIES: u32 = 2;

/// How long to wait for another process that is renewing the same session.
const REFRESH_LOCK_TIMEOUT: Duration = Duration::from_secs(30);

/// How `fob login` signs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Flow {
    /// Authorization code with PKCE: the browser on this machine approves the
    /// sign-in and redirects back to a listener on `127.0.0.1`.
    Browser,
    /// Device authorization: approve on any device with a code.
    DeviceCode,
}

impl Flow {
    /// The browser flow, as the AWS CLI defaults to, unless this looks like
    /// a remote or container session, where a browser cannot reach a loopback
    /// listener here (Granted makes the same check).
    pub fn for_this_session() -> Self {
        if crate::oauth::browser_is_elsewhere() {
            Self::DeviceCode
        } else {
            Self::Browser
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::DeviceCode => "device-code",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SsoToken {
    start_url: String,
    region: String,
    access_token: String,
    expires_at: Timestamp,
    #[serde(default)]
    refresh_token: Option<String>,
    client_id: String,
    client_secret: String,
    client_expires_at: Timestamp,
}

impl SsoToken {
    fn can_refresh(&self, now: Timestamp) -> bool {
        self.refresh_token.is_some() && self.client_expires_at > now
    }
}

/// omnifob's OIDC client registration with Identity Center.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Registration {
    client_id: String,
    client_secret: String,
    expires_at: Timestamp,
    start_url: String,
    region: String,
    scopes: Vec<String>,
    /// The consent page, when `RegisterClient` named one.
    #[serde(default)]
    authorization_endpoint: Option<String>,
}

fn token_key(integration: &str) -> String {
    format!("aws-sso/{integration}/token")
}

fn registration_key(integration: &str, flow: Flow) -> String {
    format!("aws-sso/{integration}/client/{}", flow.as_str())
}

/// Every keychain key an integration uses, for renaming it.
pub fn keys(integration: &str) -> Vec<String> {
    vec![
        token_key(integration),
        registration_key(integration, Flow::Browser),
        registration_key(integration, Flow::DeviceCode),
    ]
}

/// What the user must do to approve a sign-in.
#[derive(Debug, Clone)]
pub struct SignInPrompt {
    /// Opens the approval page; for the device flow, with the code filled in.
    pub url: String,
    /// The code to compare on the approval page (device flow only).
    pub user_code: Option<String>,
}

/// `OMNIFOB_AWS_ENDPOINT` sends every AWS call to one URL, for tests.
fn endpoint_override() -> Option<String> {
    std::env::var("OMNIFOB_AWS_ENDPOINT")
        .ok()
        .filter(|v| !v.is_empty())
}

fn oidc_client(region: &str) -> aws_sdk_ssooidc::Client {
    let mut config = aws_sdk_ssooidc::Config::builder()
        .region(aws_sdk_ssooidc::config::Region::new(region.to_string()))
        .behavior_version(aws_sdk_ssooidc::config::BehaviorVersion::latest());
    if let Some(url) = endpoint_override() {
        config = config.endpoint_url(url);
    }
    aws_sdk_ssooidc::Client::from_conf(config.build())
}

fn portal_client(region: &str) -> aws_sdk_sso::Client {
    let mut config = aws_sdk_sso::Config::builder()
        .region(aws_sdk_sso::config::Region::new(region.to_string()))
        .behavior_version(aws_sdk_sso::config::BehaviorVersion::latest());
    if let Some(url) = endpoint_override() {
        config = config.endpoint_url(url);
    }
    aws_sdk_sso::Client::from_conf(config.build())
}

fn after_secs(now: Timestamp, secs: i64) -> Timestamp {
    now.saturating_add(SignedDuration::from_secs(secs))
        .unwrap_or(Timestamp::MAX)
}

/// Signs in with `flow`. `prompt` is called once with what to show the user;
/// the call then waits until they approve the sign-in.
pub async fn login(
    integration: &str,
    config: &AwsSsoConfig,
    flow: Flow,
    prompt: impl FnOnce(&SignInPrompt),
) -> anyhow::Result<()> {
    let oidc = oidc_client(&config.region);
    let (registration, token) = match flow {
        Flow::Browser => browser_sign_in(integration, config, &oidc, prompt).await?,
        Flow::DeviceCode => device_sign_in(integration, config, &oidc, prompt).await?,
    };
    let now = Timestamp::now();
    store::set(
        &token_key(integration),
        &SsoToken {
            start_url: config.start_url.clone(),
            region: config.region.clone(),
            access_token: token
                .access_token()
                .context("no access token returned")?
                .to_string(),
            expires_at: after_secs(now, token.expires_in().into()),
            refresh_token: token.refresh_token().map(str::to_string),
            client_id: registration.client_id,
            client_secret: registration.client_secret,
            client_expires_at: registration.expires_at,
        },
    )
}

/// The stored registration for `flow` while it is valid and matches the
/// portal, else a new one.
async fn registration(
    integration: &str,
    config: &AwsSsoConfig,
    oidc: &aws_sdk_ssooidc::Client,
    flow: Flow,
) -> anyhow::Result<Registration> {
    let key = registration_key(integration, flow);
    let now = Timestamp::now();
    let usable_until = now.saturating_add(REGISTRATION_MARGIN)?;
    match store::get::<Registration>(&key) {
        Ok(Some(r))
            if r.expires_at > usable_until
                && r.start_url == config.start_url
                && r.region == config.region
                && r.scopes == config.scopes =>
        {
            return Ok(r);
        }
        Ok(_) => {}
        Err(e) => tracing::debug!("ignoring an unreadable client registration: {e:#}"),
    }

    let mut request = oidc
        .register_client()
        .client_name("omnifob")
        .client_type("public")
        .set_scopes(Some(config.scopes.clone()));
    if flow == Flow::Browser {
        request = request
            .grant_types("authorization_code")
            .grant_types("refresh_token")
            .redirect_uris(REGISTERED_REDIRECT)
            .issuer_url(&config.start_url);
    }
    let client = request.send().await.map_err(|e| {
        anyhow!(
            "registering with IAM Identity Center: {}",
            DisplayErrorContext(&e)
        )
    })?;
    let registration = Registration {
        client_id: client
            .client_id()
            .context("no client id returned")?
            .to_string(),
        client_secret: client
            .client_secret()
            .context("no client secret returned")?
            .to_string(),
        expires_at: Timestamp::from_second(client.client_secret_expires_at())?,
        start_url: config.start_url.clone(),
        region: config.region.clone(),
        scopes: config.scopes.clone(),
        authorization_endpoint: client
            .authorization_endpoint()
            .filter(|e| !e.is_empty())
            .map(str::to_string),
    };
    if let Err(e) = store::set(&key, &registration) {
        tracing::warn!("could not keep the client registration: {e:#}");
    }
    Ok(registration)
}

/// The authorization code flow with PKCE, as `aws sso login` runs it.
async fn browser_sign_in(
    integration: &str,
    config: &AwsSsoConfig,
    oidc: &aws_sdk_ssooidc::Client,
    prompt: impl FnOnce(&SignInPrompt),
) -> anyhow::Result<(Registration, CreateTokenOutput)> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .context("listening on 127.0.0.1 for the sign-in callback")?;
    let redirect_uri = format!(
        "http://127.0.0.1:{}{CALLBACK_PATH}",
        listener.local_addr()?.port()
    );
    let registration = registration(integration, config, oidc, Flow::Browser).await?;
    let endpoint = match &registration.authorization_endpoint {
        Some(endpoint) => endpoint.clone(),
        None => authorization_endpoint(&config.region).await?,
    };
    let (verifier, challenge) = oauth::pkce()?;
    let state = oauth::random_string(16)?;
    prompt(&SignInPrompt {
        url: authorize_url(
            &endpoint,
            &registration.client_id,
            &redirect_uri,
            &state,
            &challenge,
            &config.scopes,
        ),
        user_code: None,
    });

    let code = tokio::task::spawn_blocking(move || {
        oauth::wait_for_code(&listener, CALLBACK_PATH, &state, CALLBACK_TIMEOUT, "AWS")
    })
    .await??;
    let token = oidc
        .create_token()
        .client_id(&registration.client_id)
        .client_secret(&registration.client_secret)
        .grant_type("authorization_code")
        .code(code)
        .code_verifier(verifier)
        .redirect_uri(redirect_uri)
        .send()
        .await
        .map_err(|e| anyhow!("exchanging the sign-in code: {}", DisplayErrorContext(&e)))?;
    Ok((registration, token))
}

/// The consent page of the OIDC service in `region`, as the SDK resolves its
/// endpoint (so other partitions work), the way the AWS CLI finds it.
async fn authorization_endpoint(region: &str) -> anyhow::Result<String> {
    if let Some(url) = endpoint_override() {
        return Ok(format!("{}/authorize", url.trim_end_matches('/')));
    }
    use aws_sdk_ssooidc::config::endpoint::{DefaultResolver, Params, ResolveEndpoint};
    let params = Params::builder().region(region).build()?;
    let endpoint = DefaultResolver::new()
        .resolve_endpoint(&params)
        .await
        .map_err(|e| anyhow!("resolving the IAM Identity Center endpoint: {e}"))?;
    Ok(format!(
        "{}/authorize",
        endpoint.url().trim_end_matches('/')
    ))
}

/// The consent page URL. Identity Center takes the scopes as `scopes`, not
/// OAuth's `scope`, and spaces encoded as `%20`, as the AWS CLI sends them.
fn authorize_url(
    endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    challenge: &str,
    scopes: &[String],
) -> String {
    let query = [
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("state", state),
        ("code_challenge_method", "S256"),
        ("scopes", &scopes.join(" ")),
        ("code_challenge", challenge),
    ]
    .iter()
    .map(|(k, v)| format!("{k}={}", percent_encode(v)))
    .collect::<Vec<_>>()
    .join("&");
    format!("{endpoint}?{query}")
}

/// Percent-encodes everything but RFC 3986's unreserved characters.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The device authorization flow: approve on any device with a code.
async fn device_sign_in(
    integration: &str,
    config: &AwsSsoConfig,
    oidc: &aws_sdk_ssooidc::Client,
    prompt: impl FnOnce(&SignInPrompt),
) -> anyhow::Result<(Registration, CreateTokenOutput)> {
    let registration = registration(integration, config, oidc, Flow::DeviceCode).await?;
    let device = oidc
        .start_device_authorization()
        .client_id(&registration.client_id)
        .client_secret(&registration.client_secret)
        .start_url(&config.start_url)
        .send()
        .await
        .map_err(|e| anyhow!("starting device sign-in: {}", DisplayErrorContext(&e)))?;
    let device_code = device.device_code().context("no device code returned")?;
    prompt(&SignInPrompt {
        url: device
            .verification_uri_complete()
            .or(device.verification_uri())
            .context("no verification URL returned")?
            .to_string(),
        user_code: device.user_code().map(str::to_string),
    });

    let deadline = after_secs(Timestamp::now(), device.expires_in().into());
    let mut interval = Duration::from_secs(device.interval().max(1) as u64);
    let token = loop {
        tokio::time::sleep(interval).await;
        let result = oidc
            .create_token()
            .client_id(&registration.client_id)
            .client_secret(&registration.client_secret)
            .grant_type("urn:ietf:params:oauth:grant-type:device_code")
            .device_code(device_code)
            .send()
            .await;
        match result {
            Ok(token) => break token,
            Err(e) => match e.as_service_error() {
                Some(CreateTokenError::AuthorizationPendingException(_)) => {}
                Some(CreateTokenError::SlowDownException(_)) => interval += Duration::from_secs(5),
                _ => bail!("waiting for sign-in approval: {}", DisplayErrorContext(&e)),
            },
        }
        if Timestamp::now() > deadline {
            bail!("sign-in was not approved before the code expired");
        }
    };
    Ok((registration, token))
}

/// Ends the portal session at Identity Center, as `aws sso logout` does, so
/// the stored tokens stop working everywhere. Best effort: returns whether
/// there was a session to end.
pub async fn end_session(integration: &str, config: &AwsSsoConfig) -> anyhow::Result<bool> {
    let Some(token) = store::get::<SsoToken>(&token_key(integration))? else {
        return Ok(false);
    };
    if token.expires_at <= Timestamp::now() {
        return Ok(false);
    }
    portal_client(&config.region)
        .logout()
        .access_token(&token.access_token)
        .send()
        .await
        .map_err(|e| anyhow!("{}", DisplayErrorContext(&e)))?;
    Ok(true)
}

/// Forgets the session. The client registration is kept, as the AWS CLI
/// keeps it, so the next sign-in reuses it.
pub fn logout(integration: &str) -> anyhow::Result<bool> {
    store::delete(&token_key(integration))
}

/// When the stored session expires and whether it can renew itself.
pub fn session(integration: &str) -> anyhow::Result<Option<(Timestamp, bool)>> {
    let now = Timestamp::now();
    Ok(store::get::<SsoToken>(&token_key(integration))?.map(|t| {
        let refreshable = t.can_refresh(now);
        (t.expires_at, refreshable)
    }))
}

fn load(integration: &str, config: &AwsSsoConfig) -> Result<SsoToken> {
    let Some(token) = store::get::<SsoToken>(&token_key(integration))? else {
        return Err(Error::not_signed_in(integration));
    };
    if token.start_url != config.start_url || token.region != config.region {
        return Err(Error::needs_login(
            integration,
            format!("the stored sign-in for '{integration}' is for another portal or region"),
        ));
    }
    Ok(token)
}

/// Whether `token` should be renewed before use: it expires soon or, when the
/// portal just refused an access token, it is still that token.
fn needs_renewal(token: &SsoToken, now: Timestamp, rejected: Option<&str>) -> bool {
    match rejected {
        Some(rejected) => token.access_token == rejected,
        None => token.expires_at < now.saturating_add(REFRESH_WINDOW).unwrap_or(Timestamp::MAX),
    }
}

/// Returns a usable token, renewing it when it is about to expire or when the
/// portal refused it (`rejected`).
///
/// Renewal runs under a lock shared by every omnifob process: each refresh
/// returns a new refresh token and the old one is treated as spent, so two
/// processes refreshing at once could leave one with a refused token. The token is read again under the lock, since another
/// process may have renewed it while this one waited.
async fn current_token(
    integration: &str,
    config: &AwsSsoConfig,
    rejected: Option<&str>,
) -> Result<SsoToken> {
    let token = load(integration, config)?;
    if !needs_renewal(&token, Timestamp::now(), rejected) {
        return Ok(token);
    }
    let _lock = store::lock(&format!("aws-sso-{integration}"), REFRESH_LOCK_TIMEOUT).await?;
    let token = load(integration, config)?;
    let now = Timestamp::now();
    if !needs_renewal(&token, now, rejected) {
        return Ok(token);
    }

    let mut refresh_failed = false;
    if token.can_refresh(now) {
        match refresh(&token).await {
            Ok(refreshed) => {
                store::set(&token_key(integration), &refreshed)?;
                return Ok(refreshed);
            }
            Err(e) => {
                tracing::debug!("refreshing the IAM Identity Center token failed: {e:#}");
                refresh_failed = true;
            }
        }
    }
    if rejected.is_some() {
        // Neither the token nor a refresh is accepted: the session is over.
        drop_if_current(integration, &token.access_token);
        return Err(Error::needs_login(
            integration,
            format!(
                "IAM Identity Center no longer accepts the sign-in for '{integration}' (revoked, or the session ended)"
            ),
        ));
    }
    if token.expires_at > now {
        // Still valid for a while; renewal is tried again on the next use.
        Ok(token)
    } else if refresh_failed {
        Err(Error::needs_login(
            integration,
            format!(
                "the IAM Identity Center session for '{integration}' has ended (sessions last 8 hours unless the administrator changed it)"
            ),
        ))
    } else {
        Err(Error::needs_login(
            integration,
            format!("the sign-in for '{integration}' has expired"),
        ))
    }
}

async fn refresh(token: &SsoToken) -> anyhow::Result<SsoToken> {
    let refreshed = oidc_client(&token.region)
        .create_token()
        .client_id(&token.client_id)
        .client_secret(&token.client_secret)
        .grant_type("refresh_token")
        .refresh_token(token.refresh_token.as_deref().unwrap_or_default())
        .send()
        .await
        .map_err(|e| anyhow!("{}", DisplayErrorContext(&e)))?;
    Ok(SsoToken {
        access_token: refreshed
            .access_token()
            .context("no access token returned")?
            .to_string(),
        expires_at: after_secs(Timestamp::now(), refreshed.expires_in().into()),
        refresh_token: refreshed
            .refresh_token()
            .map(str::to_string)
            .or_else(|| token.refresh_token.clone()),
        ..token.clone()
    })
}

/// How a portal call failed.
enum PortalError {
    /// HTTP 401: the access token is not accepted.
    Unauthorized,
    Other(anyhow::Error),
}

fn portal_error<E>(what: &str, e: E) -> PortalError
where
    E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
{
    if e.code() == Some("UnauthorizedException") {
        PortalError::Unauthorized
    } else {
        PortalError::Other(anyhow!("{what}: {}", DisplayErrorContext(&e)))
    }
}

/// Runs a portal call with a current access token. When the portal refuses
/// the token (revoked, the session ended, or another process renewed it), the
/// token is renewed once and the call retried; only when that fails too is
/// the session dropped and a new sign-in asked for.
async fn with_portal<T, F, Fut>(integration: &str, config: &AwsSsoConfig, call: F) -> Result<T>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = std::result::Result<T, PortalError>>,
{
    let token = current_token(integration, config, None).await?;
    match call(token.access_token.clone()).await {
        Ok(value) => return Ok(value),
        Err(PortalError::Other(e)) => return Err(e.into()),
        Err(PortalError::Unauthorized) => {}
    }
    let renewed = current_token(integration, config, Some(&token.access_token)).await?;
    match call(renewed.access_token.clone()).await {
        Ok(value) => Ok(value),
        Err(PortalError::Other(e)) => Err(e.into()),
        Err(PortalError::Unauthorized) => {
            drop_if_current(integration, &renewed.access_token);
            Err(Error::needs_login(
                integration,
                format!("IAM Identity Center refuses the sign-in for '{integration}'"),
            ))
        }
    }
}

/// Deletes the stored session if it still holds `access_token`, so a session
/// another process has just renewed is never thrown away.
fn drop_if_current(integration: &str, access_token: &str) {
    if let Ok(Some(stored)) = store::get::<SsoToken>(&token_key(integration))
        && stored.access_token == access_token
    {
        let _ = store::delete(&token_key(integration));
    }
}

/// Lists every account and role reachable through this integration.
pub async fn discover(integration: &str, config: &AwsSsoConfig) -> Result<Vec<Profile>> {
    let portal = portal_client(&config.region);
    let found = with_portal(integration, config, |token| {
        let portal = portal.clone();
        async move { list_roles(&portal, &token).await }
    })
    .await?;

    let mut profiles = Vec::new();
    for (account_id, account_name, roles) in found {
        for role_name in roles {
            profiles.push(Profile::new(
                integration,
                &account_name,
                &role_name,
                Target::Aws {
                    account_id: account_id.clone(),
                    account_name: account_name.clone(),
                    role_name: role_name.clone(),
                },
            ));
        }
    }
    profiles.sort_by(|a, b| a.id.cmp(&b.id));
    disambiguate(&mut profiles);
    add_chained(integration, config, &mut profiles);
    Ok(profiles)
}

/// Every account with its name and role names.
async fn list_roles(
    portal: &aws_sdk_sso::Client,
    token: &str,
) -> std::result::Result<Vec<(String, String, Vec<String>)>, PortalError> {
    let accounts: Vec<_> = portal
        .list_accounts()
        .access_token(token)
        .into_paginator()
        .items()
        .send()
        .try_collect()
        .await
        .map_err(|e| portal_error("listing accounts", e))?;

    let per_account = futures::stream::iter(accounts.iter().map(|account| async move {
        let account_id = account.account_id().unwrap_or_default();
        let roles = portal
            .list_account_roles()
            .access_token(token)
            .account_id(account_id)
            .into_paginator()
            .items()
            .send()
            .try_collect()
            .await
            .map_err(|e| portal_error("listing roles", e))?;
        Ok::<_, PortalError>((
            account_id.to_string(),
            account.account_name().unwrap_or(account_id).to_string(),
            roles
                .iter()
                .map(|r| r.role_name().unwrap_or_default().to_string())
                .collect(),
        ))
    }))
    .buffer_unordered(ROLE_LISTING_CONCURRENCY)
    .collect::<Vec<_>>()
    .await;
    per_account.into_iter().collect()
}

/// Two accounts whose names slug the same would collide; suffix their ids
/// with the account id.
fn disambiguate(profiles: &mut [Profile]) {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for p in profiles.iter() {
        *seen.entry(p.id.clone()).or_default() += 1;
    }
    for p in profiles.iter_mut() {
        if seen[&p.id] > 1
            && let Target::Aws {
                account_id,
                account_name,
                role_name,
            } = &p.target
        {
            p.id = format!(
                "{}/{}-{account_id}/{role_name}",
                p.integration,
                crate::profile::slug(account_name)
            );
        }
    }
}

/// Exchanges the SSO token for role credentials.
pub async fn credentials(
    integration: &str,
    config: &AwsSsoConfig,
    account_id: &str,
    role_name: &str,
) -> Result<Credentials> {
    let portal = portal_client(&config.region);
    let response = with_portal(integration, config, |token| {
        let portal = portal.clone();
        async move {
            // A new account assignment takes a moment to reach the portal,
            // which answers 403 until then; retry briefly, as granted can.
            let mut delay = Duration::from_secs(1);
            let mut attempt = 0;
            loop {
                let result = portal
                    .get_role_credentials()
                    .access_token(&token)
                    .account_id(account_id)
                    .role_name(role_name)
                    .send()
                    .await;
                match result {
                    Ok(response) => return Ok(response),
                    Err(e) if e.code() == Some("ForbiddenException") => {
                        if attempt == FORBIDDEN_RETRIES {
                            return Err(PortalError::Other(anyhow!(
                                "IAM Identity Center gives you no access to {role_name} in {account_id} \
                                 (a new assignment can take a minute to apply)"
                            )));
                        }
                        attempt += 1;
                        tokio::time::sleep(delay).await;
                        delay *= 2;
                    }
                    Err(e) => {
                        return Err(portal_error(
                            &format!("getting credentials for {role_name} in {account_id}"),
                            e,
                        ));
                    }
                }
            }
        }
    })
    .await?;
    let creds = response
        .role_credentials()
        .context("no role credentials returned")?;
    let expires_at = Timestamp::from_millisecond(creds.expiration()).context("invalid expiry")?;

    let mut env = BTreeMap::new();
    let mut put = |k: &str, v: &str| {
        env.insert(k.to_string(), v.to_string());
    };
    put(
        "AWS_ACCESS_KEY_ID",
        creds.access_key_id().unwrap_or_default(),
    );
    put(
        "AWS_SECRET_ACCESS_KEY",
        creds.secret_access_key().unwrap_or_default(),
    );
    put(
        "AWS_SESSION_TOKEN",
        creds.session_token().unwrap_or_default(),
    );
    put("AWS_CREDENTIAL_EXPIRATION", &expires_at.to_string());
    if let Some(region) = &config.default_region {
        put("AWS_REGION", region);
        put("AWS_DEFAULT_REGION", region);
    }
    Ok(Credentials {
        env,
        expires_at: Some(expires_at),
        ..Default::default()
    })
}

/// Adds a profile per chained role, `<integration>/<label>/<role name>`. A
/// label that collides with a discovered profile gets a `-chained` suffix.
fn add_chained(integration: &str, config: &AwsSsoConfig, profiles: &mut Vec<Profile>) {
    for (label, role) in &config.chained {
        let target = Target::AwsChained {
            label: label.clone(),
            account_id: role.account_id().map(str::to_string),
        };
        let mut profile = Profile::new(integration, label, role.role_name(), target.clone());
        if profiles.iter().any(|p| p.id == profile.id) {
            profile = Profile::new(
                integration,
                &format!("{label}-chained"),
                role.role_name(),
                target,
            );
        }
        profiles.push(profile);
    }
}

/// Credentials for a chained role: the Identity Center role's credentials,
/// then STS AssumeRole. AWS limits chained sessions to one hour.
///
/// `profile_id` names the profile in an MFA prompt; `ttl` overrides the
/// role's `duration`.
pub async fn chained_credentials(
    integration: &str,
    config: &AwsSsoConfig,
    label: &str,
    profile_id: &str,
    ttl: Option<SignedDuration>,
) -> Result<Credentials> {
    let role = config.chained.get(label).with_context(|| {
        format!("no chained role '{label}' in integration '{integration}'; run `fob sync`")
    })?;
    let duration = ttl.or(role.duration).unwrap_or(CHAINED_MAX);
    if !(SESSION_MIN..=CHAINED_MAX).contains(&duration) {
        return Err(anyhow!(
            "a chained role's session lasts 15 minutes to 1 hour (an AWS limit for role chaining)"
        )
        .into());
    }
    let source = credentials(integration, config, &role.via_account_id, &role.via_role).await?;
    // Only a configured region is exported; STS itself is called in the
    // portal's region when none is.
    let region = role.region.as_deref().or(config.default_region.as_deref());
    let request = RoleRequest {
        role_arn: &role.role_arn,
        session_name: role.session_name.as_deref(),
        external_id: role.external_id.as_deref(),
        mfa_serial: role.mfa_serial.as_deref(),
        duration,
        profile_id,
    };
    Ok(assume_role(&source, &request, region.unwrap_or(&config.region), region).await?)
}

/// The shortest session STS hands out.
pub(crate) const SESSION_MIN: SignedDuration = SignedDuration::from_mins(15);

/// AWS caps sessions of roles assumed with role credentials at one hour.
const CHAINED_MAX: SignedDuration = SignedDuration::from_hours(1);

/// An STS `AssumeRole` call.
pub(crate) struct RoleRequest<'a> {
    pub role_arn: &'a str,
    pub session_name: Option<&'a str>,
    pub external_id: Option<&'a str>,
    /// The MFA device whose code the role's trust policy requires.
    pub mfa_serial: Option<&'a str>,
    pub duration: SignedDuration,
    /// The profile, named when asking for an MFA code.
    pub profile_id: &'a str,
}

/// An STS client authenticated with `creds`, temporary (with a session token)
/// or an IAM user's access key (without).
pub(crate) fn sts_client(creds: &Credentials, region: &str) -> anyhow::Result<aws_sdk_sts::Client> {
    let get = |k: &str| {
        creds
            .env
            .get(k)
            .cloned()
            .with_context(|| format!("{k} missing from the credentials"))
    };
    let provider = aws_sdk_sts::config::Credentials::new(
        get("AWS_ACCESS_KEY_ID")?,
        get("AWS_SECRET_ACCESS_KEY")?,
        creds.env.get("AWS_SESSION_TOKEN").cloned(),
        None,
        "omnifob",
    );
    let mut config = aws_sdk_sts::Config::builder()
        .region(aws_sdk_sts::config::Region::new(region.to_string()))
        .credentials_provider(provider)
        .behavior_version(aws_sdk_sts::config::BehaviorVersion::latest());
    if let Some(url) = endpoint_override() {
        config = config.endpoint_url(url);
    }
    Ok(aws_sdk_sts::Client::from_conf(config.build()))
}

/// The ARN these credentials act as, from STS GetCallerIdentity.
pub async fn caller_identity(creds: &Credentials, region: &str) -> anyhow::Result<String> {
    let identity = sts_client(creds, region)?
        .get_caller_identity()
        .send()
        .await
        .map_err(|e| anyhow!("{}", aws_sdk_sts::error::DisplayErrorContext(&e)))?;
    Ok(identity.arn().unwrap_or("unknown").to_string())
}

/// Checks that the stored session works: it is refreshed when needed, and
/// the portal must answer with it.
pub async fn check(integration: &str, config: &AwsSsoConfig) -> Result<String> {
    let portal = portal_client(&config.region);
    with_portal(integration, config, |token| {
        let portal = portal.clone();
        async move {
            portal
                .list_accounts()
                .access_token(token)
                .max_results(1)
                .send()
                .await
                .map_err(|e| portal_error("the portal did not answer", e))
        }
    })
    .await?;
    Ok(format!("session valid for {}", config.start_url))
}

pub(crate) async fn assume_role(
    source: &Credentials,
    request: &RoleRequest<'_>,
    sts_region: &str,
    export_region: Option<&str>,
) -> anyhow::Result<Credentials> {
    let sts = sts_client(source, sts_region)?;
    let mut call = sts
        .assume_role()
        .role_arn(request.role_arn)
        .role_session_name(request.session_name.unwrap_or("omnifob"))
        .set_external_id(request.external_id.map(str::to_string))
        .duration_seconds(request.duration.as_secs().try_into()?);
    if let Some(serial) = request.mfa_serial {
        call = call
            .serial_number(serial)
            .token_code(crate::prompt::mfa_code(serial, request.profile_id)?);
    }
    let assumed = call.send().await.map_err(|e| {
        anyhow!(
            "assuming {}: {}",
            request.role_arn,
            aws_sdk_sts::error::DisplayErrorContext(&e)
        )
    })?;
    from_sts(
        assumed.credentials().context("no credentials returned")?,
        export_region,
    )
}

/// Temporary credentials from STS as the variables AWS tools read.
pub(crate) fn from_sts(
    creds: &aws_sdk_sts::types::Credentials,
    export_region: Option<&str>,
) -> anyhow::Result<Credentials> {
    let expires_at = Timestamp::from_second(creds.expiration().secs())?;
    let mut env = BTreeMap::new();
    let mut put = |k: &str, v: &str| {
        env.insert(k.to_string(), v.to_string());
    };
    put("AWS_ACCESS_KEY_ID", creds.access_key_id());
    put("AWS_SECRET_ACCESS_KEY", creds.secret_access_key());
    put("AWS_SESSION_TOKEN", creds.session_token());
    put("AWS_CREDENTIAL_EXPIRATION", &expires_at.to_string());
    if let Some(region) = export_region {
        put("AWS_REGION", region);
        put("AWS_DEFAULT_REGION", region);
    }
    Ok(Credentials {
        env,
        expires_at: Some(expires_at),
        ..Default::default()
    })
}

/// The AWS partitions with a public console.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Partition {
    Aws,
    UsGov,
    China,
    EuropeanSovereign,
}

impl Partition {
    fn of(region: &str) -> anyhow::Result<Self> {
        Ok(if region.starts_with("cn-") {
            Self::China
        } else if region.starts_with("us-gov-") {
            Self::UsGov
        } else if region.starts_with("eusc-") {
            Self::EuropeanSovereign
        } else if region.starts_with("us-iso") {
            bail!("{region} has no public AWS console");
        } else {
            Self::Aws
        })
    }

    /// The sign-in host, regional where AWS runs one, as AWS recommends for
    /// federation; the partition's first region uses the unprefixed host.
    fn signin_host(self, region: Option<&str>) -> String {
        let domain = match self {
            Self::Aws => "signin.aws.amazon.com",
            Self::UsGov => "signin.amazonaws-us-gov.com",
            Self::China => "signin.amazonaws.cn",
            Self::EuropeanSovereign => "signin.amazonaws-eusc.eu",
        };
        format!("{}{domain}", self.region_prefix(region))
    }

    fn console_host(self, region: Option<&str>) -> String {
        let domain = match self {
            Self::Aws => "console.aws.amazon.com",
            Self::UsGov => "console.amazonaws-us-gov.com",
            Self::China => "console.amazonaws.cn",
            Self::EuropeanSovereign => "console.amazonaws-eusc.eu",
        };
        format!("{}{domain}", self.region_prefix(region))
    }

    fn region_prefix(self, region: Option<&str>) -> String {
        match region {
            None | Some("us-east-1" | "us-gov-west-1" | "cn-north-1") => String::new(),
            Some(region) => format!("{region}."),
        }
    }
}

/// The federation endpoint and console destination for a console sign-in.
/// `home_region` (the portal's) picks the partition when `region` is unset.
fn console_endpoints(home_region: &str, region: Option<&str>) -> anyhow::Result<(String, String)> {
    let partition = Partition::of(region.unwrap_or(home_region))?;
    let endpoint = format!("https://{}/federation", partition.signin_host(region));
    let destination = match region {
        Some(r) => format!(
            "https://{}/console/home?region={r}",
            partition.console_host(region)
        ),
        None => format!("https://{}/", partition.console_host(None)),
    };
    Ok((endpoint, destination))
}

#[derive(Serialize)]
struct FederationSession<'a> {
    #[serde(rename = "sessionId")]
    session_id: &'a str,
    #[serde(rename = "sessionKey")]
    session_key: &'a str,
    #[serde(rename = "sessionToken")]
    session_token: &'a str,
}

/// Builds a sign-in URL for the AWS console using the federation endpoint of
/// the credentials' partition.
pub async fn console_url(
    creds: &Credentials,
    home_region: &str,
    region: Option<&str>,
) -> anyhow::Result<String> {
    let get = |k: &str| {
        creds
            .env
            .get(k)
            .map(String::as_str)
            .with_context(|| format!("{k} missing"))
    };
    let session = serde_json::to_string(&FederationSession {
        session_id: get("AWS_ACCESS_KEY_ID")?,
        session_key: get("AWS_SECRET_ACCESS_KEY")?,
        session_token: get("AWS_SESSION_TOKEN")?,
    })?;
    let (endpoint, destination) = console_endpoints(home_region, region)?;

    #[derive(Deserialize)]
    struct SigninToken {
        #[serde(rename = "SigninToken")]
        signin_token: String,
    }
    let token: SigninToken = reqwest::Client::new()
        .get(&endpoint)
        .query(&[("Action", "getSigninToken"), ("Session", session.as_str())])
        .send()
        .await?
        .error_for_status()
        .context("requesting a console sign-in token")?
        .json()
        .await?;

    let url = reqwest::Url::parse_with_params(
        &endpoint,
        &[
            ("Action", "login"),
            ("Issuer", "omnifob"),
            ("Destination", destination.as_str()),
            ("SigninToken", token.signin_token.as_str()),
        ],
    )?;
    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(account_name: &str, account_id: &str) -> Profile {
        Profile::new(
            "acme",
            account_name,
            "Admin",
            Target::Aws {
                account_id: account_id.into(),
                account_name: account_name.into(),
                role_name: "Admin".into(),
            },
        )
    }

    #[test]
    fn chained_roles_become_profiles() {
        let config = match crate::Config::parse(
            r#"
            [integrations.acme]
            type = "aws-sso"
            start_url = "https://acme.awsapps.com/start"
            region = "eu-west-1"
            [integrations.acme.chained.prod]
            via_account_id = "111"
            via_role = "Admin"
            role_arn = "arn:aws:iam::222222222222:role/path/Deploy"
            [integrations.acme.chained.Shared]
            via_account_id = "111"
            via_role = "Admin"
            role_arn = "arn:aws:iam::333333333333:role/Admin"
            "#,
        )
        .unwrap()
        .integrations
        .remove("acme")
        .unwrap()
        {
            crate::Integration::AwsSso(c) => c,
            _ => unreachable!(),
        };
        assert_eq!(config.chained["prod"].account_id(), Some("222222222222"));
        let mut profiles = vec![role("shared", "111")];
        add_chained("acme", &config, &mut profiles);
        let ids: Vec<_> = profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "acme/shared/Admin",
                "acme/shared-chained/Admin",
                "acme/prod/Deploy"
            ]
        );
    }

    #[test]
    fn colliding_account_names_get_account_id_suffix() {
        let mut profiles = vec![role("Prod", "111"), role("prod", "222"), role("Dev", "333")];
        disambiguate(&mut profiles);
        let ids: Vec<_> = profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "acme/prod-111/Admin",
                "acme/prod-222/Admin",
                "acme/dev/Admin"
            ]
        );
    }

    #[test]
    fn consent_url_matches_the_aws_cli() {
        let url = authorize_url(
            "https://oidc.eu-west-1.amazonaws.com/authorize",
            "client",
            "http://127.0.0.1:4321/oauth/callback",
            "st",
            "ch",
            &["sso:account:access".into(), "other".into()],
        );
        assert!(
            url.starts_with("https://oidc.eu-west-1.amazonaws.com/authorize?response_type=code&"),
            "{url}"
        );
        assert!(url.contains("&client_id=client&"), "{url}");
        assert!(
            url.contains("&redirect_uri=http%3A%2F%2F127.0.0.1%3A4321%2Foauth%2Fcallback&"),
            "{url}"
        );
        assert!(url.contains("&code_challenge_method=S256&"), "{url}");
        assert!(
            url.contains("&scopes=sso%3Aaccount%3Aaccess%20other&"),
            "{url}"
        );
        assert!(url.ends_with("&code_challenge=ch"), "{url}");
        assert!(!url.contains("&scope="), "{url}");
    }

    #[tokio::test]
    async fn consent_page_follows_the_partition() {
        if endpoint_override().is_some() {
            return;
        }
        assert_eq!(
            authorization_endpoint("eu-central-1").await.unwrap(),
            "https://oidc.eu-central-1.amazonaws.com/authorize"
        );
        assert_eq!(
            authorization_endpoint("cn-north-1").await.unwrap(),
            "https://oidc.cn-north-1.amazonaws.com.cn/authorize"
        );
    }

    #[test]
    fn console_sign_in_follows_partition_and_region() {
        let cases = [
            (
                "us-east-1",
                None,
                "https://signin.aws.amazon.com/federation",
                "https://console.aws.amazon.com/",
            ),
            (
                "us-east-1",
                Some("eu-west-1"),
                "https://eu-west-1.signin.aws.amazon.com/federation",
                "https://eu-west-1.console.aws.amazon.com/console/home?region=eu-west-1",
            ),
            (
                "us-gov-west-1",
                None,
                "https://signin.amazonaws-us-gov.com/federation",
                "https://console.amazonaws-us-gov.com/",
            ),
            (
                "us-gov-west-1",
                Some("us-gov-east-1"),
                "https://us-gov-east-1.signin.amazonaws-us-gov.com/federation",
                "https://us-gov-east-1.console.amazonaws-us-gov.com/console/home?region=us-gov-east-1",
            ),
            (
                "cn-north-1",
                Some("cn-north-1"),
                "https://signin.amazonaws.cn/federation",
                "https://console.amazonaws.cn/console/home?region=cn-north-1",
            ),
        ];
        for (home, region, endpoint, destination) in cases {
            assert_eq!(
                console_endpoints(home, region).unwrap(),
                (endpoint.to_string(), destination.to_string()),
                "{home} {region:?}"
            );
        }
        assert!(console_endpoints("us-iso-east-1", None).is_err());
    }

    #[test]
    fn renewal_is_due_near_expiry_or_for_a_refused_token() {
        let now: Timestamp = "2026-11-08T12:00:00Z".parse().unwrap();
        let token = |mins: i64| SsoToken {
            start_url: "u".into(),
            region: "r".into(),
            access_token: "a1".into(),
            expires_at: now + SignedDuration::from_mins(mins),
            refresh_token: Some("r1".into()),
            client_id: "c".into(),
            client_secret: "s".into(),
            client_expires_at: now + SignedDuration::from_hours(24),
        };
        assert!(!needs_renewal(&token(60), now, None));
        assert!(needs_renewal(&token(10), now, None));
        assert!(needs_renewal(&token(60), now, Some("a1")));
        // Another process already replaced the refused token.
        assert!(!needs_renewal(&token(60), now, Some("a0")));
    }
}
