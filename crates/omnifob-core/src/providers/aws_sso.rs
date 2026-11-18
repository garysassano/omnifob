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
use aws_sdk_sso::config::http::HttpResponse;
use aws_sdk_sso::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
use aws_sdk_ssooidc::operation::create_token::{CreateTokenError, CreateTokenOutput};
use futures::StreamExt;
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};

use super::aws_partition::Partition;
use crate::config::{AwsSsoConfig, CrossPartitionRole};
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

/// The variable the AWS CLI and SDKs read for the OIDC service's endpoint.
const OIDC_ENDPOINT_VARIABLE: &str = "AWS_ENDPOINT_URL_SSO_OIDC";

/// The variable the AWS CLI and SDKs read for the portal's endpoint.
const PORTAL_ENDPOINT_VARIABLE: &str = "AWS_ENDPOINT_URL_SSO";

/// Where to send the calls of one Identity Center API: `OMNIFOB_AWS_ENDPOINT`,
/// else the service's own variable (`AWS_ENDPOINT_URL_SSO_OIDC` or
/// `AWS_ENDPOINT_URL_SSO`), which points the AWS CLI at a VPC endpoint whose
/// private DNS is off, unless `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS` is `true`.
/// The global `AWS_ENDPOINT_URL` is not read: it usually points the command
/// `fob exec` runs at a local emulator, which cannot sign anyone in.
fn service_endpoint(variable: &str) -> Option<String> {
    endpoint_override().or_else(|| {
        let ignored = std::env::var("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS")
            .is_ok_and(|v| v.eq_ignore_ascii_case("true"));
        if ignored {
            return None;
        }
        std::env::var(variable).ok().filter(|v| !v.is_empty())
    })
}

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

fn portal_client(region: &str) -> aws_sdk_sso::Client {
    let mut config = aws_sdk_sso::Config::builder()
        .region(aws_sdk_sso::config::Region::new(region.to_string()))
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
    let listener = TcpListener::bind("127.0.0.1:0")
        .context("listening on 127.0.0.1 for the sign-in callback")?;
    let redirect_uri = format!(
        "http://127.0.0.1:{}{CALLBACK_PATH}",
        listener.local_addr()?.port()
    );
    let registration = registration(integration, config, oidc, Flow::Browser).await?;
    // A configured endpoint wins over the one the registration names, as in
    // the AWS CLI, which builds the consent URL from the client's endpoint.
    let endpoint = match &registration.authorization_endpoint {
        Some(endpoint) if service_endpoint(OIDC_ENDPOINT_VARIABLE).is_none() => endpoint.clone(),
        _ => authorization_endpoint(&config.region).await?,
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
        .map_err(|e| anyhow!("starting device sign-in: {}", describe(&e)))?;
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
                _ => bail!("waiting for sign-in approval: {}", describe(&e)),
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
        let account_id = account.account_id().unwrap_or_default();
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

/// Adds a profile per configured role, chained and cross-partition, each
/// `<integration>/<label>/<role name>`. A chained role whose id a
/// discovered profile already has gets a `-chained` suffix on its label, as
/// it always has. A cross-partition role gets a `-cross-partition` suffix
/// and a warning that says how to choose another label; if that id is taken
/// too, discovery fails. The config check refuses collisions between the
/// two tables, so only Identity Center roles (and earlier suffixed ids) can
/// take a cross-partition role's id here.
fn add_configured(
    integration: &str,
    config: &AwsSsoConfig,
    profiles: &mut Vec<Profile>,
) -> anyhow::Result<()> {
    let taken =
        |profiles: &[Profile], profile: &Profile| profiles.iter().any(|p| p.id == profile.id);
    for (label, role) in &config.chained {
        let target = Target::AwsChained {
            label: label.clone(),
            account_id: role.account_id().map(str::to_string),
        };
        let mut profile = Profile::new(integration, label, role.role_name(), target.clone());
        if taken(profiles, &profile) {
            profile = Profile::new(
                integration,
                &format!("{label}-chained"),
                role.role_name(),
                target,
            );
        }
        profiles.push(profile);
    }
    for (label, role) in &config.cross_partition {
        let target = Target::AwsCrossPartition {
            label: label.clone(),
            account_id: role.account_id().to_string(),
        };
        let profile = Profile::new(integration, label, role.role_name(), target.clone());
        if !taken(profiles, &profile) {
            profiles.push(profile);
            continue;
        }
        let suffixed = Profile::new(
            integration,
            &format!("{label}-cross-partition"),
            role.role_name(),
            target,
        );
        if taken(profiles, &suffixed) {
            bail!(
                "the cross-partition role '{label}' of '{integration}' would be {} or {}, and \
                 both are taken by other profiles; give it another label in \
                 [integrations.{integration}.cross_partition]",
                profile.id,
                suffixed.id
            );
        }
        tracing::warn!(
            "{} is already an Identity Center or chained profile, so the cross-partition role \
             '{label}' is {}; give it another label in [integrations.{integration}.cross_partition] \
             to choose its id",
            profile.id,
            suffixed.id
        );
        profiles.push(suffixed);
    }
    Ok(())
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

/// How long a web identity token lives, in seconds: the least STS allows.
/// It is exchanged at once, so a minute is plenty; it stays within any
/// `sts:DurationSeconds` limit an administrator sets, and it never outlives
/// the Identity Center role's credentials, which are new for each request.
pub const WEB_IDENTITY_TOKEN_SECONDS: i32 = 60;

/// A JWT from `GetWebIdentityToken`. It is a bearer credential for its
/// lifetime, so it is never logged, cached or written anywhere, and `Debug`
/// does not show it.
struct WebIdentityToken(String);

impl std::fmt::Debug for WebIdentityToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WebIdentityToken(<redacted>)")
    }
}

/// The claims of a web identity token that an administrator needs for the
/// destination's OIDC provider and trust policy. Nothing else is read from
/// the token, and these are only ever displayed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct TokenClaims {
    /// The source account's issuer URL.
    #[serde(default)]
    pub iss: Option<String>,
    /// The principal that requested the token; for an Identity Center role,
    /// the reserved role's ARN.
    #[serde(default)]
    pub sub: Option<String>,
    /// The audience, a string or a list.
    #[serde(default)]
    pub aud: Option<serde_json::Value>,
}

impl TokenClaims {
    /// Reads `iss`, `sub` and `aud` from a JWT's payload. The signature is
    /// not checked: the claims are for display only.
    pub fn of(token: &str) -> Option<Self> {
        use base64::Engine;
        let payload = token.split('.').nth(1)?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload.trim_end_matches('='))
            .ok()?;
        serde_json::from_slice(&bytes).ok()
    }
}

impl std::fmt::Display for TokenClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let aud = match &self.aud {
            None => "(none)".to_string(),
            Some(serde_json::Value::String(aud)) => aud.clone(),
            Some(serde_json::Value::Array(auds)) => auds
                .iter()
                .map(|a| a.as_str().map_or_else(|| a.to_string(), str::to_string))
                .collect::<Vec<_>>()
                .join(", "),
            Some(other) => other.to_string(),
        };
        write!(
            f,
            "iss {}, sub {}, aud {aud}",
            self.iss.as_deref().unwrap_or("(none)"),
            self.sub.as_deref().unwrap_or("(none)")
        )
    }
}

/// An STS error code without the `Exception` suffix that some codes carry
/// on the wire and in the SDK model and others do not.
fn sts_code(code: Option<&str>) -> Option<&str> {
    code.map(|c| c.strip_suffix("Exception").unwrap_or(c))
}

/// Credentials for a role in another partition: the Identity Center role's
/// credentials, then STS `GetWebIdentityToken` with them in the source
/// Region for a token with one audience that lasts a minute, then STS
/// `AssumeRoleWithWebIdentity` in the destination Region, unsigned, with
/// that token. The destination Region is exported.
///
/// `ttl` overrides the role's `duration`. A `SessionDurationEscalation`
/// from the token request is retried once with new source credentials, and
/// an `ExpiredToken` from the exchange once with a new token. The SDK
/// itself retries an `IDPCommunicationError`, which it models as a server
/// error, with the same token. Errors name who has to act; those from the exchange show the
/// token's `iss`, `sub` and `aud`.
pub async fn cross_partition_credentials(
    integration: &str,
    config: &AwsSsoConfig,
    label: &str,
    ttl: Option<SignedDuration>,
) -> Result<Credentials> {
    let role = config.cross_partition.get(label).with_context(|| {
        format!("no cross-partition role '{label}' in integration '{integration}'; run `fob sync`")
    })?;
    let duration = ttl.unwrap_or_else(|| role.duration_or_default());
    if !CrossPartitionRole::DURATION.contains(&duration) {
        return Err(anyhow!(
            "a cross-partition role's session lasts 15 minutes to 12 hours, and at most the \
             role's maximum session duration"
        )
        .into());
    }
    let duration_seconds = whole_seconds(duration)?;
    let source_region = role.source_region(config);
    let destination = exchange_client(role);

    let source = credentials(integration, config, &role.via_account_id, &role.via_role).await?;
    let mut sts = sts_client(&source, source_region)?;
    let mut renewed_source = false;
    let mut retried_exchange = false;
    loop {
        // Signed with the Identity Center role's credentials. The SDK
        // resolves the Regional endpoint (`sts.<region>.<domain>`), which
        // the call needs: the global endpoint does not serve it.
        let requested = sts
            .get_web_identity_token()
            .audience(&role.audience)
            .signing_algorithm(role.signing_algorithm.as_str())
            .duration_seconds(WEB_IDENTITY_TOKEN_SECONDS)
            .send()
            .await;
        let token = match requested {
            Ok(response) => WebIdentityToken(
                response
                    .web_identity_token()
                    .context("no web identity token returned")?
                    .to_string(),
            ),
            Err(e)
                if !renewed_source && sts_code(e.code()) == Some("SessionDurationEscalation") =>
            {
                renewed_source = true;
                let source =
                    credentials(integration, config, &role.via_account_id, &role.via_role).await?;
                sts = sts_client(&source, source_region)?;
                continue;
            }
            Err(e) => return Err(token_error(&e, role, source_region).into()),
        };
        let claims = TokenClaims::of(&token.0);
        if let Some(claims) = &claims {
            tracing::debug!("web identity token for {}: {claims}", role.role_arn);
        }
        let exchanged = destination
            .assume_role_with_web_identity()
            .role_arn(&role.role_arn)
            .role_session_name(role.session_name())
            .web_identity_token(&token.0)
            .duration_seconds(duration_seconds)
            .send()
            .await;
        drop(token);
        match exchanged {
            Ok(assumed) => {
                return Ok(from_sts(
                    assumed.credentials().context("no credentials returned")?,
                    Some(&role.region),
                )?);
            }
            Err(e) if !retried_exchange && sts_code(e.code()) == Some("ExpiredToken") => {
                retried_exchange = true;
            }
            Err(e) => {
                return Err(exchange_error(&e, role, duration_seconds, claims.as_ref()).into());
            }
        }
    }
}

/// What a refused token request means, and who has to act.
fn token_error(
    e: &aws_sdk_sts::error::SdkError<
        aws_sdk_sts::operation::get_web_identity_token::GetWebIdentityTokenError,
    >,
    role: &CrossPartitionRole,
    region: &str,
) -> anyhow::Error {
    let (account, via_role) = (&role.via_account_id, &role.via_role);
    let detail = aws_sdk_sts::error::DisplayErrorContext(e);
    match sts_code(e.code()) {
        Some("OutboundWebIdentityFederationDisabled") => anyhow!(
            "outbound identity federation is not enabled in the source account {account}: an \
             administrator of that account must enable it (IAM account settings, or `aws iam \
             enable-outbound-web-identity-federation`) before {via_role} can request a web \
             identity token"
        ),
        Some("AccessDenied") => anyhow!(
            "{via_role} in {account} may not request a web identity token for the audience \
             '{}', signed with {}, lasting {WEB_IDENTITY_TOKEN_SECONDS} seconds: an \
             administrator of the source account must allow sts:GetWebIdentityToken in the \
             permission set {via_role}, with conditions that admit these values \
             (sts:IdentityTokenAudience, sts:SigningAlgorithm, sts:DurationSeconds) ({detail})",
            role.audience,
            role.signing_algorithm.as_str()
        ),
        Some("SessionDurationEscalation") => anyhow!(
            "STS refused a {WEB_IDENTITY_TOKEN_SECONDS}-second web identity token because the \
             credentials of {via_role} in {account} expire sooner, even new ones; an \
             administrator of the source account should check the permission set's session \
             duration ({detail})"
        ),
        _ => anyhow!(
            "requesting a web identity token in {region} as {via_role} in {account}: {detail}"
        ),
    }
}

/// What a refused exchange means, and who has to act. A refused token is
/// described by its `iss`, `sub` and `aud`, the values the destination's
/// OIDC provider and trust policy must match.
fn exchange_error(
    e: &aws_sdk_sts::error::SdkError<
        aws_sdk_sts::operation::assume_role_with_web_identity::AssumeRoleWithWebIdentityError,
    >,
    role: &CrossPartitionRole,
    duration_seconds: i32,
    claims: Option<&TokenClaims>,
) -> anyhow::Error {
    let (arn, region) = (&role.role_arn, &role.region);
    let detail = aws_sdk_sts::error::DisplayErrorContext(e);
    let token = match claims {
        Some(claims) => format!("the token has {claims}"),
        None => "the token's claims could not be read".to_string(),
    };
    match sts_code(e.code()) {
        Some("AccessDenied" | "InvalidIdentityToken" | "IDPRejectedClaim") => anyhow!(
            "{arn} does not accept the web identity token from {} in {}: an administrator of \
             the destination account must check that its IAM OIDC provider has the source \
             account's issuer URL and '{}' as a client ID, and that the role's trust policy \
             allows sts:AssumeRoleWithWebIdentity for this token; {token} ({detail})",
            role.via_role,
            role.via_account_id,
            role.audience
        ),
        Some("IDPCommunicationError") => anyhow!(
            "STS in {region} could not reach the source account's issuer to check the web \
             identity token, even after retrying; try again later ({detail})"
        ),
        Some("ExpiredToken") => anyhow!(
            "STS in {region} found the web identity token expired or not valid, twice, although \
             each one was exchanged as soon as it was issued: the source STS makes it expire \
             {WEB_IDENTITY_TOKEN_SECONDS} seconds after issuing it, so either more time than \
             that passed between the two calls (a slow network, or the SDK's retries with \
             backoff) or the token is not valid; try again later ({detail})"
        ),
        Some("ValidationError") if e.message().is_some_and(|m| m.contains("DurationSeconds")) => {
            anyhow!(
                "{arn} does not allow sessions of {duration_seconds} seconds: lower its \
                 `duration` (or --ttl), or ask an administrator of the destination account to \
                 raise the role's maximum session duration ({detail})"
            )
        }
        _ => anyhow!("assuming {arn} with a web identity token in {region}: {detail}"),
    }
}

/// `duration` in whole seconds, as STS takes `DurationSeconds`. A fraction
/// of a second rounds up, so a length checked against a minimum never falls
/// below it.
pub(crate) fn whole_seconds(duration: SignedDuration) -> anyhow::Result<i32> {
    let secs = duration.as_secs() + i64::from(duration.subsec_nanos() > 0);
    Ok(secs.try_into()?)
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

/// An STS client with no credentials provider, for calls that carry their
/// own proof of identity (`AssumeRoleWithWebIdentity`), so the request is
/// not signed and no AWS credentials leave this machine with it.
fn unsigned_sts_client(region: &str) -> aws_sdk_sts::Client {
    let mut config = aws_sdk_sts::Config::builder()
        .region(aws_sdk_sts::config::Region::new(region.to_string()))
        .behavior_version(aws_sdk_sts::config::BehaviorVersion::latest());
    if let Some(url) = endpoint_override() {
        config = config.endpoint_url(url);
    }
    aws_sdk_sts::Client::from_conf(config.build())
}

/// The STS client a cross-partition role's token is exchanged through: the
/// destination Region's, where the role's partition is, and unsigned.
fn exchange_client(role: &CrossPartitionRole) -> aws_sdk_sts::Client {
    unsigned_sts_client(&role.region)
}

/// Whom credentials act as, from STS `GetCallerIdentity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerIdentity {
    /// The ARN, `unknown` if STS sent none.
    pub arn: String,
    /// The account the credentials belong to, as STS states it.
    pub account: Option<String>,
}

/// Whom these credentials act as, from STS GetCallerIdentity.
pub async fn caller_identity(creds: &Credentials, region: &str) -> anyhow::Result<CallerIdentity> {
    let identity = sts_client(creds, region)?
        .get_caller_identity()
        .send()
        .await
        .map_err(|e| anyhow!("{}", aws_sdk_sts::error::DisplayErrorContext(&e)))?;
    Ok(CallerIdentity {
        arn: identity.arn().unwrap_or("unknown").to_string(),
        account: identity
            .account()
            .filter(|a| !a.is_empty())
            .map(str::to_string),
    })
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
        .duration_seconds(whole_seconds(request.duration)?);
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

/// The console session lengths the federation endpoint accepts as
/// `SessionDuration`.
pub const CONSOLE_SESSION: std::ops::RangeInclusive<SignedDuration> =
    SESSION_MIN..=SignedDuration::from_hours(12);

/// Fails unless `duration` is a console session length the federation
/// endpoint accepts.
pub fn check_console_duration(duration: SignedDuration) -> anyhow::Result<()> {
    if !CONSOLE_SESSION.contains(&duration) {
        bail!("a console session lasts 15 minutes to 12 hours");
    }
    Ok(())
}

/// Fails unless `service` can be the path of a console page: letters,
/// digits, `-`, `_` and `.` in segments separated by `/` (`ec2`,
/// `cloudformation`, `route53/v2`).
pub(crate) fn check_service(service: &str) -> anyhow::Result<()> {
    let service = service.trim_matches('/');
    let valid = !service.is_empty()
        && service.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        });
    if !valid {
        bail!(
            "'{service}' is not a console service; give the path after the console host, such as ec2, s3 or cloudformation"
        );
    }
    Ok(())
}

/// What a console sign-in opens and for how long.
#[derive(Debug, Clone, Copy)]
pub struct ConsoleRequest<'a> {
    /// The credentials' partition, whose federation endpoint signs in.
    pub partition: Partition,
    /// The Region the credentials came from; in the European Sovereign
    /// Cloud, which has no unprefixed sign-in host, it picks the sign-in
    /// host when `region` is unset.
    pub home_region: Option<&'a str>,
    /// The Region the console opens in, which must be in `partition`.
    pub region: Option<&'a str>,
    /// The console page, as the path after the host (`ec2`, `s3`); the
    /// console home when unset.
    pub service: Option<&'a str>,
    /// How long the console session lasts (`SessionDuration`); without it,
    /// as long as the credentials. Only credentials from `AssumeRole*` (and
    /// Identity Center) take it; role chaining and `GetFederationToken` do
    /// not.
    pub session_duration: Option<SignedDuration>,
}

/// The federation endpoint and console destination for a console sign-in to
/// `partition`. With `region` (the Region the console opens in, which must be
/// in the partition) both are regional. Without it, the console opens at the
/// unprefixed host and so does the sign-in where the partition has one; the
/// European Sovereign Cloud has none, so it signs in at `home_region` when
/// that is in the partition, else at the partition's first Region.
///
/// The destination is `https://<console host>/<service>/home?region=<region>`,
/// as granted builds it, with `console` as the service when only a Region is
/// given and the bare console host when neither is.
pub(crate) fn console_endpoints(request: &ConsoleRequest) -> anyhow::Result<(String, String)> {
    let ConsoleRequest {
        partition,
        home_region,
        region,
        service,
        ..
    } = *request;
    if let Some(region) = region {
        partition.check_region(region)?;
    }
    let service = service.map(|s| s.trim_matches('/'));
    if let Some(service) = service {
        check_service(service)?;
    }
    let signin_region = region
        .or(partition.unprefixed_region())
        .or(home_region.filter(|home| partition.contains(home)))
        .unwrap_or(partition.default_region());
    let endpoint = format!(
        "https://{}/federation",
        partition.signin_host(signin_region)?
    );
    let host = partition.console_host(region)?;
    let destination = match (service, region) {
        (None, None) => format!("https://{host}/"),
        (Some(service), None) => format!("https://{host}/{service}/home"),
        (service, Some(r)) => format!(
            "https://{host}/{}/home?region={r}",
            service.unwrap_or("console")
        ),
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

/// Builds a sign-in URL for the AWS console with the federation endpoint of
/// the credentials' partition.
///
/// The credentials go to `getSigninToken` in the body of a form POST, which
/// the federation endpoint accepts, so they stay out of proxy and access
/// logs and out of error messages, which name the URL. Neither they nor the
/// sign-in token are logged. `OMNIFOB_AWS_ENDPOINT` sends that call to a mock
/// at `<endpoint>/federation`; the returned URL keeps the real sign-in host.
pub async fn console_url(
    creds: &Credentials,
    request: &ConsoleRequest<'_>,
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
    if let Some(duration) = request.session_duration {
        check_console_duration(duration)?;
    }
    let (endpoint, destination) = console_endpoints(request)?;
    let token_endpoint = match endpoint_override() {
        Some(base) => format!("{}/federation", base.trim_end_matches('/')),
        None => endpoint.clone(),
    };

    let mut form = vec![("Action", "getSigninToken".to_string())];
    if let Some(duration) = request.session_duration {
        form.push(("SessionDuration", whole_seconds(duration)?.to_string()));
    }
    form.push(("Session", session));

    #[derive(Deserialize)]
    struct SigninToken {
        #[serde(rename = "SigninToken")]
        signin_token: String,
    }
    let response = crate::http::client()
        .post(&token_endpoint)
        .form(&form)
        .send()
        .await
        .context("requesting a console sign-in token")?;
    let status = response.status();
    if !status.is_success() {
        // The body is not shown: the endpoint documents no error format.
        let hint = match request.session_duration {
            Some(_) if status.is_client_error() => {
                "; the console session length must be shorter than the role's maximum session \
                 duration (for an Identity Center role, its permission set's session duration)"
            }
            _ => "",
        };
        bail!("the AWS federation endpoint refused a console sign-in token (HTTP {status}){hint}");
    }
    let token: SigninToken = response
        .json()
        .await
        .context("reading the console sign-in token")?;

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

    /// Records the URL a request would go to, and stops it there.
    #[derive(Debug, Default, Clone)]
    struct StopBeforeSending(std::sync::Arc<std::sync::Mutex<Option<(String, bool)>>>);

    impl aws_sdk_sts::config::Intercept for StopBeforeSending {
        fn name(&self) -> &'static str {
            "StopBeforeSending"
        }

        fn read_before_transmit(
            &self,
            context: &aws_sdk_sts::config::interceptors::BeforeTransmitInterceptorContextRef<'_>,
            _: &aws_sdk_sts::config::RuntimeComponents,
            _: &mut aws_sdk_sts::config::ConfigBag,
        ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let request = context.request();
            let signed = request.headers().contains_key("authorization");
            *self.0.lock().unwrap() = Some((request.uri().to_string(), signed));
            Err("stopped before sending".into())
        }
    }

    /// `GetWebIdentityToken` is not served by the global STS endpoint, so
    /// the client must resolve the Regional one, in us-east-1 too.
    #[tokio::test]
    async fn web_identity_tokens_are_requested_from_the_regional_endpoint() {
        assert!(
            endpoint_override().is_none(),
            "OMNIFOB_AWS_ENDPOINT must be unset for this test"
        );
        let mut creds = Credentials::default();
        for (k, v) in [
            ("AWS_ACCESS_KEY_ID", "ASIAEXAMPLE"),
            ("AWS_SECRET_ACCESS_KEY", "secret"),
            ("AWS_SESSION_TOKEN", "token"),
        ] {
            creds.env.insert(k.into(), v.into());
        }
        for (region, host) in [
            ("us-east-1", "https://sts.us-east-1.amazonaws.com"),
            ("eu-west-1", "https://sts.eu-west-1.amazonaws.com"),
            ("us-gov-west-1", "https://sts.us-gov-west-1.amazonaws.com"),
            ("cn-north-1", "https://sts.cn-north-1.amazonaws.com.cn"),
        ] {
            let stop = StopBeforeSending::default();
            let result = sts_client(&creds, region)
                .unwrap()
                .get_web_identity_token()
                .audience("omnifob")
                .signing_algorithm("ES384")
                .duration_seconds(WEB_IDENTITY_TOKEN_SECONDS)
                .customize()
                .interceptor(stop.clone())
                .send()
                .await;
            assert!(result.is_err());
            let (url, signed) = stop.0.lock().unwrap().clone().unwrap();
            assert_eq!(url.trim_end_matches('/'), host, "{region}");
            assert!(signed, "{region}");
        }
    }

    /// The exchange goes to STS in the destination Region, never the
    /// source's, and is not signed.
    #[tokio::test]
    async fn the_exchange_goes_to_the_destination_region_unsigned() {
        assert!(
            endpoint_override().is_none(),
            "OMNIFOB_AWS_ENDPOINT must be unset for this test"
        );
        let config = crate::Config::parse(
            r#"
            [integrations.portal]
            type = "aws-sso"
            start_url = "https://acme.awsapps.com/start"
            region = "us-east-1"
            [integrations.portal.cross_partition.gov]
            via_account_id = "111111111111"
            via_role = "Admin"
            role_arn = "arn:aws-us-gov:iam::222222222222:role/Audit"
            audience = "omnifob"
            region = "us-gov-east-1"
            source_region = "us-east-1"
            [integrations.portal.cross_partition.eusc]
            via_account_id = "111111111111"
            via_role = "Admin"
            role_arn = "arn:aws-eusc:iam::333333333333:role/Audit"
            audience = "omnifob"
            region = "eusc-de-east-1"
            "#,
        )
        .unwrap();
        let crate::Integration::AwsSso(portal) = config.integration("portal").unwrap() else {
            unreachable!()
        };
        for (label, host) in [
            ("gov", "https://sts.us-gov-east-1.amazonaws.com"),
            ("eusc", "https://sts.eusc-de-east-1.amazonaws.eu"),
        ] {
            let role = &portal.cross_partition[label];
            let stop = StopBeforeSending::default();
            let _ = exchange_client(role)
                .assume_role_with_web_identity()
                .role_arn(&role.role_arn)
                .role_session_name("omnifob")
                .web_identity_token("a.b.c")
                .customize()
                .interceptor(stop.clone())
                .send()
                .await;
            let (url, signed) = stop.0.lock().unwrap().clone().unwrap();
            assert_eq!(url.trim_end_matches('/'), host, "{label}");
            assert!(!signed, "{label}");
        }
    }

    #[test]
    fn token_claims_are_read_for_display() {
        use base64::Engine;
        let encode = |json: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        let token = format!(
            "{}.{}.signature",
            encode(r#"{"alg":"ES384"}"#),
            encode(
                r#"{"iss":"https://abc.tokens.sts.global.api.aws","sub":"arn:aws:iam::111111111111:role/Admin","aud":"omnifob","https://sts.amazonaws.com/":{"identity_store_user_id":"u"}}"#
            )
        );
        let claims = TokenClaims::of(&token).unwrap();
        assert_eq!(
            claims.to_string(),
            "iss https://abc.tokens.sts.global.api.aws, sub arn:aws:iam::111111111111:role/Admin, aud omnifob"
        );
        // A list of audiences, and padding some encoders add.
        let token = format!("h.{}==.s", encode(r#"{"aud":["a","b"]}"#));
        assert_eq!(
            TokenClaims::of(&token).unwrap().to_string(),
            "iss (none), sub (none), aud a, b"
        );
        for broken in [
            "",
            "only-one-part",
            "h.!!!.s",
            &format!("h.{}.s", encode("[1]")),
        ] {
            assert_eq!(TokenClaims::of(broken), None, "{broken}");
        }
        // The token itself never shows in Debug output.
        let secret = WebIdentityToken(token.clone());
        assert!(!format!("{secret:?}").contains(&token));
    }

    #[test]
    fn session_lengths_round_up_to_whole_seconds() {
        let d = |s: i64, n: i32| SignedDuration::new(s, n);
        assert_eq!(whole_seconds(d(900, 0)).unwrap(), 900);
        assert_eq!(whole_seconds(d(900, 1)).unwrap(), 901);
        assert_eq!(whole_seconds(d(43_199, 500_000_000)).unwrap(), 43_200);
        assert!(whole_seconds(SignedDuration::from_secs(i64::from(i32::MAX) + 1)).is_err());
    }

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
        use Partition::*;
        let cases = [
            (
                Aws,
                Some("us-east-1"),
                None,
                "https://signin.aws.amazon.com/federation",
                "https://console.aws.amazon.com/",
            ),
            // Without a console Region the sign-in stays on the unprefixed
            // host, whatever the portal's Region.
            (
                Aws,
                Some("eu-west-1"),
                None,
                "https://signin.aws.amazon.com/federation",
                "https://console.aws.amazon.com/",
            ),
            (
                UsGov,
                Some("us-gov-east-1"),
                None,
                "https://signin.amazonaws-us-gov.com/federation",
                "https://console.amazonaws-us-gov.com/",
            ),
            (
                China,
                Some("cn-northwest-1"),
                None,
                "https://signin.amazonaws.cn/federation",
                "https://console.amazonaws.cn/",
            ),
            (
                Aws,
                Some("us-east-1"),
                Some("eu-west-1"),
                "https://eu-west-1.signin.aws.amazon.com/federation",
                "https://eu-west-1.console.aws.amazon.com/console/home?region=eu-west-1",
            ),
            (
                Aws,
                None,
                None,
                "https://signin.aws.amazon.com/federation",
                "https://console.aws.amazon.com/",
            ),
            (
                UsGov,
                Some("us-gov-west-1"),
                None,
                "https://signin.amazonaws-us-gov.com/federation",
                "https://console.amazonaws-us-gov.com/",
            ),
            (
                UsGov,
                Some("us-gov-west-1"),
                Some("us-gov-east-1"),
                "https://us-gov-east-1.signin.amazonaws-us-gov.com/federation",
                "https://us-gov-east-1.console.amazonaws-us-gov.com/console/home?region=us-gov-east-1",
            ),
            (
                China,
                Some("cn-north-1"),
                Some("cn-north-1"),
                "https://signin.amazonaws.cn/federation",
                "https://console.amazonaws.cn/console/home?region=cn-north-1",
            ),
            (
                China,
                Some("cn-north-1"),
                Some("cn-northwest-1"),
                "https://cn-northwest-1.signin.amazonaws.cn/federation",
                "https://cn-northwest-1.console.amazonaws.cn/console/home?region=cn-northwest-1",
            ),
            // The European Sovereign Cloud has no unprefixed sign-in host.
            (
                EuropeanSovereign,
                Some("eusc-de-east-1"),
                None,
                "https://eusc-de-east-1.signin.amazonaws-eusc.eu/federation",
                "https://console.amazonaws-eusc.eu/",
            ),
            // A home Region in another partition (a cross-partition role)
            // does not pick the host.
            (
                EuropeanSovereign,
                Some("eu-central-1"),
                None,
                "https://eusc-de-east-1.signin.amazonaws-eusc.eu/federation",
                "https://console.amazonaws-eusc.eu/",
            ),
            (
                EuropeanSovereign,
                None,
                None,
                "https://eusc-de-east-1.signin.amazonaws-eusc.eu/federation",
                "https://console.amazonaws-eusc.eu/",
            ),
            (
                EuropeanSovereign,
                Some("eusc-de-east-1"),
                Some("eusc-de-east-1"),
                "https://eusc-de-east-1.signin.amazonaws-eusc.eu/federation",
                "https://eusc-de-east-1.console.amazonaws-eusc.eu/console/home?region=eusc-de-east-1",
            ),
        ];
        for (partition, home, region, endpoint, destination) in cases {
            assert_eq!(
                console_endpoints(&console(partition, home, region, None)).unwrap(),
                (endpoint.to_string(), destination.to_string()),
                "{partition} {home:?} {region:?}"
            );
        }
        // The console opens in the credentials' partition only.
        assert!(console_endpoints(&console(UsGov, None, Some("eu-west-1"), None)).is_err());
        assert!(console_endpoints(&console(Aws, None, Some("us-isob-east-1"), None)).is_err());
    }

    fn console<'a>(
        partition: Partition,
        home_region: Option<&'a str>,
        region: Option<&'a str>,
        service: Option<&'a str>,
    ) -> ConsoleRequest<'a> {
        ConsoleRequest {
            partition,
            home_region,
            region,
            service,
            session_duration: None,
        }
    }

    #[test]
    fn console_destination_opens_a_service_in_a_region() {
        use Partition::*;
        let cases = [
            (
                Aws,
                None,
                Some("s3"),
                "https://console.aws.amazon.com/s3/home",
            ),
            (
                Aws,
                Some("eu-west-1"),
                Some("ec2"),
                "https://eu-west-1.console.aws.amazon.com/ec2/home?region=eu-west-1",
            ),
            (
                Aws,
                Some("us-east-1"),
                Some("/route53/v2/"),
                "https://console.aws.amazon.com/route53/v2/home?region=us-east-1",
            ),
            (
                UsGov,
                Some("us-gov-east-1"),
                Some("cloudformation"),
                "https://us-gov-east-1.console.amazonaws-us-gov.com/cloudformation/home?region=us-gov-east-1",
            ),
            (
                China,
                None,
                Some("lambda"),
                "https://console.amazonaws.cn/lambda/home",
            ),
            (
                EuropeanSovereign,
                Some("eusc-de-east-1"),
                Some("iam"),
                "https://eusc-de-east-1.console.amazonaws-eusc.eu/iam/home?region=eusc-de-east-1",
            ),
        ];
        for (partition, region, service, destination) in cases {
            let (_, got) = console_endpoints(&console(partition, None, region, service)).unwrap();
            assert_eq!(got, destination, "{partition} {region:?} {service:?}");
        }
        for service in [
            "",
            "/",
            "ec2/../iam",
            "ec2?region=x",
            "s3#x",
            "a//b",
            "ec2 v2",
            "é",
        ] {
            let error = console_endpoints(&console(Aws, None, None, Some(service))).unwrap_err();
            assert!(
                error.to_string().contains("not a console service"),
                "{service}: {error}"
            );
        }
        // A Region becomes part of the sign-in host, so one that is not
        // shaped like a Region could send the credentials elsewhere.
        for region in [
            "attacker.example#",
            "attacker.example/",
            "eu-west-1.attacker.example",
            "eu-west-1@attacker.example",
            "EU-WEST-1",
        ] {
            let error =
                console_endpoints(&console(Aws, None, Some(region), Some("ec2"))).unwrap_err();
            assert!(
                error.to_string().contains("not an AWS Region name"),
                "{region}: {error}"
            );
        }
        // A malformed home Region never picks the sign-in host either.
        let (endpoint, _) = console_endpoints(&console(
            EuropeanSovereign,
            Some("attacker.example#"),
            None,
            None,
        ))
        .unwrap();
        assert_eq!(
            endpoint,
            "https://eusc-de-east-1.signin.amazonaws-eusc.eu/federation"
        );
        // The service does not lift the partition check on the Region.
        assert!(console_endpoints(&console(UsGov, None, Some("eu-west-1"), Some("ec2"))).is_err());
    }

    #[test]
    fn console_durations_are_15_minutes_to_12_hours() {
        for (duration, ok) in [
            (SignedDuration::from_mins(14), false),
            (SignedDuration::from_mins(15), true),
            (SignedDuration::from_hours(8), true),
            (SignedDuration::from_hours(12), true),
            (
                SignedDuration::from_hours(12) + SignedDuration::from_secs(1),
                false,
            ),
        ] {
            assert_eq!(check_console_duration(duration).is_ok(), ok, "{duration:#}");
        }
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
