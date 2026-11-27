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
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use aws_sdk_sso::config::http::HttpResponse;
use aws_sdk_sso::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
use aws_sdk_ssooidc::operation::create_token::{CreateTokenError, CreateTokenOutput};
use futures::StreamExt;
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};

use super::service_endpoint;
use super::sts::{CHAINED_MAX, RoleRequest, SESSION_MIN, assume_role};
use crate::config::AwsSsoConfig;
use crate::oauth::percent_encode;
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

/// Not `Debug`: it holds the tokens and the client secret.
#[derive(Clone, Serialize, Deserialize)]
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

/// omnifob's OIDC client registration with Identity Center. Not `Debug`: it
/// holds the client secret.
#[derive(Clone, Serialize, Deserialize)]
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

fn pending_key(integration: &str) -> String {
    format!("aws-sso/{integration}/pending")
}

/// Every keychain key an integration uses, for renaming it.
pub fn keys(integration: &str) -> Vec<String> {
    vec![
        token_key(integration),
        registration_key(integration, Flow::Browser),
        registration_key(integration, Flow::DeviceCode),
        pending_key(integration),
    ]
}

/// A device sign-in waiting for approval, kept between `fob login --start`
/// and `fob login --wait`, which may run in different processes: Identity
/// Center keeps the authorization, and the device code finds it again. Not
/// `Debug`: whoever polls with the device code gets the token once the
/// person approves, so it is kept in the keychain like the token itself.
#[derive(Clone, Serialize, Deserialize)]
struct PendingDevice {
    registration: Registration,
    device_code: String,
    interval_secs: u64,
    expires_at: Timestamp,
}

/// What the user must do to approve a sign-in.
#[derive(Debug, Clone)]
pub struct SignInPrompt {
    /// Opens the approval page; for the device flow, with the code filled in.
    pub url: String,
    /// The code to compare on the approval page (device flow only).
    pub user_code: Option<String>,
}

/// The variable the AWS CLI and SDKs read for the OIDC service's endpoint.
const OIDC_ENDPOINT_VARIABLE: &str = "AWS_ENDPOINT_URL_SSO_OIDC";

/// The variable the AWS CLI and SDKs read for the portal's endpoint.
const PORTAL_ENDPOINT_VARIABLE: &str = "AWS_ENDPOINT_URL_SSO";

/// The reason IAM Identity Center gives when its network controls refuse a
/// request that did not come through a VPC endpoint or network it allows.
const NETWORK_CONTROLS_DENIED: &str = "NETWORK_CONTROLS_ACCESS_DENIED";

/// Whether IAM Identity Center's network controls refused the call. The SDK
/// models do not name this reason yet, so the response body is searched.
fn network_controls_denied<E>(e: &SdkError<E, HttpResponse>) -> bool {
    let needle = NETWORK_CONTROLS_DENIED.as_bytes();
    e.raw_response()
        .and_then(|response| response.body().bytes())
        .is_some_and(|body| body.windows(needle.len()).any(|w| w == needle))
}

/// An SDK error as the user sees it, saying so when network controls refused
/// the call, since connecting to the right network fixes it and signing in
/// again does not.
fn describe<E>(e: &SdkError<E, HttpResponse>) -> String
where
    E: std::error::Error + 'static,
{
    if network_controls_denied(e) {
        format!(
            "IAM Identity Center's network controls refused the request, which has to come through a network or VPC endpoint your organization allows; connect to it (for example through the VPN) and try again ({})",
            DisplayErrorContext(e)
        )
    } else {
        DisplayErrorContext(e).to_string()
    }
}

fn oidc_client(region: &str) -> aws_sdk_ssooidc::Client {
    let mut config = aws_sdk_ssooidc::Config::builder()
        .region(aws_sdk_ssooidc::config::Region::new(region.to_string()))
        .behavior_version(aws_sdk_ssooidc::config::BehaviorVersion::latest());
    if let Some(url) = service_endpoint(OIDC_ENDPOINT_VARIABLE) {
        config = config.endpoint_url(url);
    }
    aws_sdk_ssooidc::Client::from_conf(config.build())
}

/// How many times a portal call is tried before a throttling or transient
/// error fails it, against the SDK's default of three: `fob sync` lists the
/// roles of every account, which throttles on organizations with hundreds.
const PORTAL_MAX_ATTEMPTS: u32 = 8;

/// The portal's client, with adaptive retries: besides backing off, the
/// client slows down once Identity Center throttles it, as the AWS CLI's
/// `retry_mode = adaptive` does.
fn portal_client(region: &str) -> aws_sdk_sso::Client {
    let mut config = aws_sdk_sso::Config::builder()
        .region(aws_sdk_sso::config::Region::new(region.to_string()))
        .retry_config(
            aws_sdk_sso::config::retry::RetryConfig::adaptive()
                .with_max_attempts(PORTAL_MAX_ATTEMPTS),
        )
        .behavior_version(aws_sdk_sso::config::BehaviorVersion::latest());
    if let Some(url) = service_endpoint(PORTAL_ENDPOINT_VARIABLE) {
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
        Flow::DeviceCode => {
            let (pending, shown) = start_device(integration, config, &oidc).await?;
            prompt(&shown);
            let token = poll_device(&oidc, &pending).await?;
            (pending.registration, token)
        }
    };
    keep_token(integration, config, registration, &token)
}

/// What `fob login --start` shows: where to approve, and until when.
#[derive(Debug, Clone)]
pub struct DeviceStart {
    pub prompt: SignInPrompt,
    pub expires_at: Timestamp,
}

/// Starts a device sign-in and keeps it for [`finish_device_login`], so the
/// code can be shown and the process end while the person approves it.
pub async fn start_device_login(
    integration: &str,
    config: &AwsSsoConfig,
) -> anyhow::Result<DeviceStart> {
    let oidc = oidc_client(&config.region);
    let (pending, prompt) = start_device(integration, config, &oidc).await?;
    store::set(&pending_key(integration), &pending)?;
    Ok(DeviceStart {
        prompt,
        expires_at: pending.expires_at,
    })
}

/// Whether a device sign-in [`start_device_login`] started is waiting.
pub fn has_pending_login(integration: &str) -> anyhow::Result<bool> {
    Ok(store::get::<PendingDevice>(&pending_key(integration))?.is_some())
}

/// Waits for the sign-in [`start_device_login`] started to be approved,
/// then keeps it as `login` does. The started sign-in is forgotten once it
/// ends either way.
pub async fn finish_device_login(integration: &str, config: &AwsSsoConfig) -> anyhow::Result<()> {
    let key = pending_key(integration);
    let Some(pending) = store::get::<PendingDevice>(&key)? else {
        bail!(
            "no device sign-in was started for '{integration}'; run `fob login {integration} --start` first"
        );
    };
    if pending.registration.start_url != config.start_url
        || pending.registration.region != config.region
    {
        store::delete(&key)?;
        bail!(
            "the sign-in started for '{integration}' was for another portal; run `fob login {integration} --start` again"
        );
    }
    if pending.expires_at <= Timestamp::now() {
        store::delete(&key)?;
        bail!(
            "the code of the sign-in started for '{integration}' expired; run `fob login {integration} --start` again"
        );
    }
    let oidc = oidc_client(&config.region);
    let polled = poll_device(&oidc, &pending).await;
    // Approved, refused or expired, the device code is spent.
    store::delete(&key)?;
    keep_token(integration, config, pending.registration, &polled?)
}

/// Stores the session a sign-in produced.
fn keep_token(
    integration: &str,
    config: &AwsSsoConfig,
    registration: Registration,
    token: &CreateTokenOutput,
) -> anyhow::Result<()> {
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
    let client = request
        .send()
        .await
        .map_err(|e| anyhow!("registering with IAM Identity Center: {}", describe(&e)))?;
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
    let loopback = oauth::Loopback::bind(0)?;
    let redirect_uri = format!("http://127.0.0.1:{}{CALLBACK_PATH}", loopback.port());
    let registration = registration(integration, config, oidc, Flow::Browser).await?;
    // A configured endpoint wins over the one the registration names, as in
    // the AWS CLI, which builds the consent URL from the client's endpoint.
    let endpoint = match &registration.authorization_endpoint {
        Some(endpoint) if service_endpoint(OIDC_ENDPOINT_VARIABLE).is_none() => endpoint.clone(),
        _ => authorization_endpoint(&config.region).await?,
    };
    let pkce = oauth::Pkce::new()?;
    prompt(&SignInPrompt {
        url: authorize_url(
            &endpoint,
            &registration.client_id,
            &redirect_uri,
            &pkce.state,
            &pkce.challenge,
            &config.scopes,
        ),
        user_code: None,
    });

    let code = loopback.code(CALLBACK_PATH, &pkce.state, "AWS").await?;
    let token = oidc
        .create_token()
        .client_id(&registration.client_id)
        .client_secret(&registration.client_secret)
        .grant_type("authorization_code")
        .code(code)
        .code_verifier(pkce.verifier)
        .redirect_uri(redirect_uri)
        .send()
        .await
        .map_err(|e| anyhow!("exchanging the sign-in code: {}", describe(&e)))?;
    Ok((registration, token))
}

/// The consent page of the OIDC service in `region`, as the SDK resolves its
/// endpoint (so other partitions work) or a configured one, the way the AWS
/// CLI finds it.
async fn authorization_endpoint(region: &str) -> anyhow::Result<String> {
    if let Some(url) = service_endpoint(OIDC_ENDPOINT_VARIABLE) {
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

/// Starts the device authorization flow: what to show, and what polling
/// for the approval needs.
async fn start_device(
    integration: &str,
    config: &AwsSsoConfig,
    oidc: &aws_sdk_ssooidc::Client,
) -> anyhow::Result<(PendingDevice, SignInPrompt)> {
    let registration = registration(integration, config, oidc, Flow::DeviceCode).await?;
    let device = oidc
        .start_device_authorization()
        .client_id(&registration.client_id)
        .client_secret(&registration.client_secret)
        .start_url(&config.start_url)
        .send()
        .await
        .map_err(|e| anyhow!("starting device sign-in: {}", describe(&e)))?;
    let prompt = SignInPrompt {
        url: device
            .verification_uri_complete()
            .or(device.verification_uri())
            .context("no verification URL returned")?
            .to_string(),
        user_code: device.user_code().map(str::to_string),
    };
    let pending = PendingDevice {
        device_code: device
            .device_code()
            .context("no device code returned")?
            .to_string(),
        interval_secs: device.interval().max(1) as u64,
        expires_at: after_secs(Timestamp::now(), device.expires_in().into()),
        registration,
    };
    Ok((pending, prompt))
}

/// Polls until the person approves the device sign-in, or its code expires.
async fn poll_device(
    oidc: &aws_sdk_ssooidc::Client,
    pending: &PendingDevice,
) -> anyhow::Result<CreateTokenOutput> {
    let mut interval = Duration::from_secs(pending.interval_secs);
    loop {
        tokio::time::sleep(interval).await;
        let result = oidc
            .create_token()
            .client_id(&pending.registration.client_id)
            .client_secret(&pending.registration.client_secret)
            .grant_type("urn:ietf:params:oauth:grant-type:device_code")
            .device_code(&pending.device_code)
            .send()
            .await;
        match result {
            Ok(token) => return Ok(token),
            Err(e) => match e.as_service_error() {
                Some(CreateTokenError::AuthorizationPendingException(_)) => {}
                Some(CreateTokenError::SlowDownException(_)) => interval += Duration::from_secs(5),
                _ => bail!("waiting for sign-in approval: {}", describe(&e)),
            },
        }
        if Timestamp::now() > pending.expires_at {
            bail!("sign-in was not approved before the code expired");
        }
    }
}

/// Ends the portal session at Identity Center, as `aws sso logout` does, so
/// the stored tokens stop working everywhere. Best effort: returns whether
/// there was a session to end.
///
/// An expired access token is renewed first, since its refresh token stays
/// valid at Identity Center until the portal session ends. When it cannot be
/// renewed, or Identity Center refuses the renewal, there is nothing left to
/// end.
pub async fn end_session(integration: &str, config: &AwsSsoConfig) -> anyhow::Result<bool> {
    let token = match renewed_token(integration, config, None).await {
        Ok(token) => token,
        Err(TokenError::Session(Error::NeedsLogin { .. })) => return Ok(false),
        Err(TokenError::Session(Error::Other(e))) => return Err(e),
        Err(TokenError::NotRenewed(cause)) => {
            return Err(anyhow!(
                "renewing the expired sign-in failed: {cause:#}; the portal session ends on its own when it expires"
            ));
        }
    };
    portal_client(&config.region)
        .logout()
        .access_token(&token.access_token)
        .send()
        .await
        .map_err(|e| anyhow!("{}", describe(&e)))?;
    Ok(true)
}

/// Forgets the session. The client registration is kept, as the AWS CLI
/// keeps it, so the next sign-in reuses it.
pub fn logout(integration: &str) -> anyhow::Result<bool> {
    store::delete(&pending_key(integration))?;
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

/// Whether the stored session was registered with the configured scopes, as
/// far as the stored client registrations tell; `false` when signed out.
pub fn session_has_scopes(integration: &str, config: &AwsSsoConfig) -> anyhow::Result<bool> {
    let Some(token) = store::get::<SsoToken>(&token_key(integration))? else {
        return Ok(false);
    };
    for flow in [Flow::Browser, Flow::DeviceCode] {
        if let Ok(Some(r)) = store::get::<Registration>(&registration_key(integration, flow))
            && r.client_id == token.client_id
        {
            return Ok(r.scopes == config.scopes);
        }
    }
    Ok(true)
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
/// processes refreshing at once could leave one with a refused token. The
/// token is read again under the lock, since another process may have renewed
/// it while this one waited.
///
/// The session is forgotten and a new sign-in asked for only when Identity
/// Center refuses the refresh with an error `CreateToken` documents as final.
/// A network error, a timeout, throttling or a server error leaves the session
/// stored, and the call fails without asking for a sign-in.
async fn current_token(
    integration: &str,
    config: &AwsSsoConfig,
    rejected: Option<&str>,
) -> Result<SsoToken> {
    renewed_token(integration, config, rejected)
        .await
        .map_err(|e| match e {
            TokenError::Session(e) => e,
            TokenError::NotRenewed(cause) => anyhow!(
                "could not renew the sign-in for '{integration}' with IAM Identity Center: {cause:#}; run `fob login {integration}` if this persists"
            )
            .into(),
        })
}

/// Why [`renewed_token`] has no token to give.
enum TokenError {
    /// No usable session, or another error unrelated to the renewal.
    Session(Error),
    /// The token is no longer usable and renewing it failed for a reason
    /// that may pass; the session is kept for the next try.
    NotRenewed(anyhow::Error),
}

impl From<Error> for TokenError {
    fn from(e: Error) -> Self {
        Self::Session(e)
    }
}

impl From<anyhow::Error> for TokenError {
    fn from(e: anyhow::Error) -> Self {
        Self::Session(e.into())
    }
}

/// [`current_token`], leaving the caller to word a renewal that failed for now.
async fn renewed_token(
    integration: &str,
    config: &AwsSsoConfig,
    rejected: Option<&str>,
) -> std::result::Result<SsoToken, TokenError> {
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

    let refused = if token.can_refresh(now) {
        match refresh(&token).await {
            Ok(refreshed) => {
                store::set(&token_key(integration), &refreshed)?;
                return Ok(refreshed);
            }
            Err(RefreshError::Transient(e)) => {
                if rejected.is_none() && token.expires_at > now {
                    // Still valid for a while; renewal is tried again on the next use.
                    tracing::debug!("renewing the IAM Identity Center token failed: {e:#}");
                    return Ok(token);
                }
                // The session at Identity Center may well be intact, so it is
                // kept for the next try rather than sending the user to sign in.
                return Err(TokenError::NotRenewed(e));
            }
            Err(RefreshError::Refused {
                client_refused,
                source,
            }) => {
                tracing::debug!("IAM Identity Center refused to renew the token: {source:#}");
                if client_refused {
                    // The next sign-in must not reuse the client just refused.
                    forget_registrations(integration, &token.client_id);
                }
                true
            }
        }
    } else {
        false
    };

    if rejected.is_none() && token.expires_at > now {
        // Still valid for a while; renewal is tried again on the next use.
        return Ok(token);
    }
    if rejected.is_some() || refused {
        // Neither the token nor a refresh is accepted: the session is over.
        drop_if_current(integration, &token.access_token);
    }
    let reason = if rejected.is_some() {
        format!(
            "IAM Identity Center no longer accepts the sign-in for '{integration}' (revoked, or the session ended)"
        )
    } else if refused {
        format!(
            "the IAM Identity Center session for '{integration}' has ended (sessions last 8 hours unless the administrator changed it)"
        )
    } else {
        format!("the sign-in for '{integration}' has expired")
    };
    Err(Error::needs_login(integration, reason).into())
}

/// How renewing a token failed.
enum RefreshError {
    /// Identity Center refused the refresh token or the client, which
    /// `CreateToken` documents as final: only a new sign-in helps.
    Refused {
        /// The client registration itself was refused
        /// (`InvalidClientException`, `UnauthorizedClientException`).
        client_refused: bool,
        source: anyhow::Error,
    },
    /// Anything else: a network error, a timeout, throttling, a server error
    /// or a request error not documented as final. The session may be intact
    /// and a later try may succeed.
    Transient(anyhow::Error),
}

async fn refresh(token: &SsoToken) -> std::result::Result<SsoToken, RefreshError> {
    let refreshed = oidc_client(&token.region)
        .create_token()
        .client_id(&token.client_id)
        .client_secret(&token.client_secret)
        .grant_type("refresh_token")
        .refresh_token(token.refresh_token.as_deref().unwrap_or_default())
        .send()
        .await
        .map_err(|e| {
            if network_controls_denied(&e) {
                // Connecting to the allowed network fixes this; the session
                // at Identity Center is intact.
                return RefreshError::Transient(anyhow!("{}", describe(&e)));
            }
            let refused = matches!(
                e.as_service_error(),
                Some(
                    CreateTokenError::InvalidGrantException(_)
                        | CreateTokenError::ExpiredTokenException(_)
                        | CreateTokenError::InvalidClientException(_)
                        | CreateTokenError::UnauthorizedClientException(_)
                        | CreateTokenError::AccessDeniedException(_)
                )
            );
            let client_refused = matches!(
                e.as_service_error(),
                Some(
                    CreateTokenError::InvalidClientException(_)
                        | CreateTokenError::UnauthorizedClientException(_)
                )
            );
            let source = anyhow!("{}", DisplayErrorContext(&e));
            if refused {
                RefreshError::Refused {
                    client_refused,
                    source,
                }
            } else {
                RefreshError::Transient(source)
            }
        })?;
    let access_token = refreshed
        .access_token()
        .context("no access token returned")
        .map_err(RefreshError::Transient)?;
    Ok(SsoToken {
        access_token: access_token.to_string(),
        expires_at: after_secs(Timestamp::now(), refreshed.expires_in().into()),
        refresh_token: refreshed
            .refresh_token()
            .map(str::to_string)
            .or_else(|| token.refresh_token.clone()),
        ..token.clone()
    })
}

/// Deletes the stored client registrations that hold `client_id`.
fn forget_registrations(integration: &str, client_id: &str) {
    for flow in [Flow::Browser, Flow::DeviceCode] {
        let key = registration_key(integration, flow);
        if let Ok(Some(stored)) = store::get::<Registration>(&key)
            && stored.client_id == client_id
            && let Err(e) = store::delete(&key)
        {
            tracing::warn!("could not forget the refused client registration: {e:#}");
        }
    }
}

/// How a portal call failed.
enum PortalError {
    /// HTTP 401: the access token is not accepted.
    Unauthorized,
    Other(anyhow::Error),
}

fn portal_error<E>(what: &str, e: SdkError<E, HttpResponse>) -> PortalError
where
    E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
{
    // A refusal by network controls says nothing about the token, so it must
    // not end the session, whatever status it comes with.
    if e.code() == Some("UnauthorizedException") && !network_controls_denied(&e) {
        PortalError::Unauthorized
    } else {
        PortalError::Other(anyhow!("{what}: {}", describe(&e)))
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
    add_configured(integration, config, &mut profiles)?;
    Ok(profiles)
}

/// The largest page `ListAccounts` and `ListAccountRoles` return.
const MAX_PAGE: i32 = 100;

/// Every account with its name and role names.
async fn list_roles(
    portal: &aws_sdk_sso::Client,
    token: &str,
) -> std::result::Result<Vec<(String, String, Vec<String>)>, PortalError> {
    let accounts: Vec<_> = portal
        .list_accounts()
        .access_token(token)
        // The most a page holds: fewer calls against an API that throttles.
        .max_results(MAX_PAGE)
        .into_paginator()
        .items()
        .send()
        .try_collect()
        .await
        .map_err(|e| portal_error("listing accounts", e))?;

    let per_account = futures::stream::iter(accounts.iter().map(|account| async move {
        let account_id = account.account_id().ok_or_else(|| {
            PortalError::Other(anyhow!("the portal listed an account without its ID"))
        })?;
        let roles = portal
            .list_account_roles()
            .access_token(token)
            .account_id(account_id)
            .max_results(MAX_PAGE)
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
                .map(|r| {
                    r.role_name().map(str::to_string).ok_or_else(|| {
                        PortalError::Other(anyhow!(
                            "the portal listed a role without its name in account {account_id}"
                        ))
                    })
                })
                .collect::<std::result::Result<Vec<_>, _>>()?,
        ))
    }))
    .buffer_unordered(ROLE_LISTING_CONCURRENCY)
    .collect::<Vec<_>>()
    .await;
    per_account.into_iter().collect()
}

/// Two accounts whose names slug the same would collide; suffix every id of
/// those accounts with the account ID.
fn disambiguate(profiles: &mut [Profile]) {
    crate::profile::disambiguate_accounts(profiles, |target| match target {
        Target::Aws {
            account_id,
            account_name,
            ..
        } => Some((account_name, account_id)),
        _ => None,
    });
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
                    Err(e)
                        if e.code() == Some("ForbiddenException")
                            && !network_controls_denied(&e) =>
                    {
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
    let missing =
        |what: &str| format!("IAM Identity Center returned role credentials without {what}");
    put(
        "AWS_ACCESS_KEY_ID",
        creds
            .access_key_id()
            .with_context(|| missing("an access key ID"))?,
    );
    put(
        "AWS_SECRET_ACCESS_KEY",
        creds
            .secret_access_key()
            .with_context(|| missing("a secret access key"))?,
    );
    put(
        "AWS_SESSION_TOKEN",
        creds
            .session_token()
            .with_context(|| missing("a session token"))?,
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

/// Adds a profile per configured role, chained and cross-partition, each
/// `<integration>/<label>/<role name>`. A role whose id a discovered
/// profile already has gets a suffix on its label, `-chained` or
/// `-cross-partition`, and a warning that says how to choose another label;
/// if that id is taken too, discovery fails. The config check refuses
/// collisions between configured roles, so only Identity Center roles (and
/// earlier suffixed ids) can take a configured role's id here.
fn add_configured(
    integration: &str,
    config: &AwsSsoConfig,
    profiles: &mut Vec<Profile>,
) -> anyhow::Result<()> {
    for (label, role) in &config.chained {
        let target = Target::AwsChained {
            label: label.clone(),
            account_id: role.account_id().map(str::to_string),
        };
        let profile = configured_profile(
            integration,
            ("chained", label, "-chained"),
            role.role_name(),
            target,
            profiles,
        )?;
        profiles.push(profile);
    }
    for (label, role) in &config.cross_partition {
        let target = Target::AwsCrossPartition {
            label: label.clone(),
            account_id: role.account_id().to_string(),
        };
        let profile = configured_profile(
            integration,
            ("cross_partition", label, "-cross-partition"),
            role.role_name(),
            target,
            profiles,
        )?;
        profiles.push(profile);
    }
    Ok(())
}

/// The profile of a configured role, `(table, label, suffix)`: its own id
/// when free, else the label with `suffix`, with a warning; fails when
/// both are taken.
fn configured_profile(
    integration: &str,
    (table, label, suffix): (&str, &str, &str),
    role_name: &str,
    target: Target,
    profiles: &[Profile],
) -> anyhow::Result<Profile> {
    let taken = |profile: &Profile| profiles.iter().any(|p| p.id == profile.id);
    let profile = Profile::new(integration, label, role_name, target.clone());
    if !taken(&profile) {
        return Ok(profile);
    }
    let suffixed = Profile::new(integration, &format!("{label}{suffix}"), role_name, target);
    if taken(&suffixed) {
        bail!(
            "the {table} role '{label}' of '{integration}' would be {} or {}, and both are taken \
             by other profiles; give it another label in [integrations.{integration}.{table}]",
            profile.id,
            suffixed.id
        );
    }
    tracing::warn!(
        "{} is already an Identity Center or configured profile, so the {table} role '{label}' \
         is {}; give it another label in [integrations.{integration}.{table}] to choose its id",
        profile.id,
        suffixed.id
    );
    Ok(suffixed)
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

#[cfg(test)]
mod tests {
    use super::super::endpoint_override;
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
            via_account_id = "111111111111"
            via_role = "Admin"
            role_arn = "arn:aws:iam::222222222222:role/path/Deploy"
            [integrations.acme.chained.Shared]
            via_account_id = "111111111111"
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
        add_configured("acme", &config, &mut profiles).unwrap();
        let ids: Vec<_> = profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "acme/shared/Admin",
                "acme/shared-chained/Admin",
                "acme/prod/Deploy"
            ]
        );

        // An account named like the suffixed label takes that id too.
        let mut profiles = vec![role("shared", "111"), role("shared-chained", "444")];
        let error = add_configured("acme", &config, &mut profiles).unwrap_err();
        assert_eq!(
            error.to_string(),
            "the chained role 'Shared' of 'acme' would be acme/shared/Admin or \
             acme/shared-chained/Admin, and both are taken by other profiles; give it another \
             label in [integrations.acme.chained]"
        );
    }

    #[test]
    fn cross_partition_roles_become_profiles() {
        let config = match crate::Config::parse(
            r#"
            [integrations.acme]
            type = "aws-sso"
            start_url = "https://acme.awsapps.com/start"
            region = "us-east-1"
            [integrations.acme.chained.ops]
            via_account_id = "111111111111"
            via_role = "Admin"
            role_arn = "arn:aws:iam::222222222222:role/Ops"
            [integrations.acme.cross_partition.gov-audit]
            via_account_id = "111111111111"
            via_role = "AdministratorAccess"
            role_arn = "arn:aws-us-gov:iam::222222222222:role/path/Audit"
            audience = "omnifob"
            region = "us-gov-west-1"
            [integrations.acme.cross_partition.Prod]
            via_account_id = "111111111111"
            via_role = "AdministratorAccess"
            role_arn = "arn:aws-cn:iam::333333333333:role/Admin"
            audience = "omnifob"
            region = "cn-north-1"
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
        let ids = |profiles: &[Profile]| -> Vec<String> {
            profiles.iter().map(|p| p.id.clone()).collect()
        };

        let mut profiles = vec![role("dev", "444444444444")];
        add_configured("acme", &config, &mut profiles).unwrap();
        assert_eq!(
            ids(&profiles),
            [
                "acme/dev/Admin",
                "acme/ops/Ops",
                "acme/prod/Admin",
                "acme/gov-audit/Audit"
            ]
        );
        assert_eq!(
            profiles[3].target,
            Target::AwsCrossPartition {
                label: "gov-audit".into(),
                account_id: "222222222222".into(),
            }
        );
        assert!(profiles[3].target.is_aws());
        assert_eq!(profiles[3].target.account_id(), Some("222222222222"));

        // An Identity Center role with the same id keeps it; the
        // cross-partition role is suffixed.
        let mut profiles = vec![role("prod", "444444444444")];
        add_configured("acme", &config, &mut profiles).unwrap();
        assert_eq!(
            ids(&profiles),
            [
                "acme/prod/Admin",
                "acme/ops/Ops",
                "acme/prod-cross-partition/Admin",
                "acme/gov-audit/Audit"
            ]
        );
        // With the suffixed id taken too, discovery says what to change.
        let mut profiles = vec![
            role("prod", "444444444444"),
            role("prod-cross-partition", "5"),
        ];
        let error = add_configured("acme", &config, &mut profiles).unwrap_err();
        assert!(
            error.to_string().contains(
                "would be acme/prod/Admin or acme/prod-cross-partition/Admin, and both are taken"
            ),
            "{error}"
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

        // Every role of an account moves with it, not just the roles whose
        // ids collide.
        let mut profiles = vec![
            role("Prod", "111"),
            role("prod", "222"),
            role("Prod", "111"),
        ];
        profiles[2].id = "acme/prod/ReadOnly".into();
        disambiguate(&mut profiles);
        let ids: Vec<_> = profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "acme/prod-111/Admin",
                "acme/prod-222/Admin",
                "acme/prod-111/ReadOnly"
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
