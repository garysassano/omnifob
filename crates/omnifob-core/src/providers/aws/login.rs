//! AWS console credentials, the way `aws login` gets them.
//!
//! The browser signs in through AWS Sign-In with an existing console session
//! (an IAM user, the root user, or a role reached through federation), and
//! omnifob redeems the code for 15 minute credentials and a refresh token
//! that renews them until the sign-in ends (12 hours by default; an
//! administrator can allow up to 90 days per IAM user or role). As in the AWS
//! CLI, the code comes back to a loopback listener (`same-device`), or on
//! another device the user pastes what the page shows (`cross-device`), and
//! every token request carries a DPoP proof (RFC 9449) signed with a P-256
//! key made for the sign-in, so a stolen refresh token is useless without the
//! key. The session, key included, is kept in the keychain per integration
//! and renewed under a lock shared by every omnifob process, since each
//! refresh returns a new refresh token.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use aws_sdk_signin::config::http::HttpResponse;
use aws_sdk_signin::error::{DisplayErrorContext, SdkError};
use aws_sdk_signin::operation::create_o_auth2_token::CreateOAuth2TokenError;
use aws_sdk_signin::types::{
    CreateOAuth2TokenRequestBody, CreateOAuth2TokenResponseBody, OAuth2ErrorCode,
};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};

use super::partition::Partition;
use super::{service_endpoint, sts};
use crate::config::AwsLoginConfig;
use crate::profile::slug;
use crate::{Credentials, Error, Profile, Result, Target, oauth, store};

/// The OAuth clients AWS Sign-In knows the AWS CLI by, for a browser on this
/// machine and for one elsewhere.
const SAME_DEVICE_CLIENT: &str = "arn:aws:signin:::devtools/same-device";
const CROSS_DEVICE_CLIENT: &str = "arn:aws:signin:::devtools/cross-device";

/// Where AWS Sign-In sends the browser back to, as the AWS CLI listens.
const CALLBACK_PATH: &str = "/oauth/callback";

/// Credentials expiring within this window are renewed before use, as the
/// AWS CLI does.
const REFRESH_WINDOW: SignedDuration = SignedDuration::from_mins(5);

/// How long to wait for another process that is renewing the same session.
const REFRESH_LOCK_TIMEOUT: Duration = Duration::from_secs(30);

/// The variable the AWS CLI and SDKs read for the Sign-In service's endpoint.
const ENDPOINT_VARIABLE: &str = "AWS_ENDPOINT_URL_SIGNIN";

/// A signed-in console session, kept in the keychain. Not `Debug`: it holds
/// the refresh token, the credentials and the DPoP key.
#[derive(Clone, Serialize, Deserialize)]
struct Session {
    /// The console identity, the ID token's `sub`: an IAM user, root or
    /// assumed-role ARN.
    login_session: String,
    account_id: String,
    client_id: String,
    /// The Region signed in through; the refresh token works only there.
    region: String,
    refresh_token: String,
    /// The DPoP key as PKCS#8 DER in base64.
    dpop_key: String,
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expires_at: Timestamp,
    /// When AWS Sign-In issued the credentials, so their lifetime is known
    /// to background renewal. Missing in sessions stored before omnifob
    /// recorded it.
    #[serde(default)]
    issued_at: Option<Timestamp>,
}

fn session_key(integration: &str) -> String {
    format!("aws-login/{integration}/session")
}

/// Every keychain key an integration uses, for renaming it.
pub fn keys(integration: &str) -> Vec<String> {
    vec![session_key(integration)]
}

/// The P-256 key a sign-in's token requests are bound to.
struct DpopKey(EcdsaKeyPair);

/// The `htu` of a DPoP proof: `url` without its query and fragment.
fn htu(url: &str) -> &str {
    url.split(['?', '#']).next().unwrap_or(url)
}

impl DpopKey {
    /// A new key, and how to store it.
    fn generate() -> anyhow::Result<(Self, String)> {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .map_err(|_| anyhow!("could not make a key for the sign-in"))?;
        let stored = STANDARD.encode(pkcs8.as_ref());
        Ok((Self::load(&stored)?, stored))
    }

    fn load(stored: &str) -> anyhow::Result<Self> {
        let der = STANDARD
            .decode(stored)
            .context("the stored sign-in key is not base64")?;
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der)
            .map_err(|_| anyhow!("the stored sign-in key is not a P-256 key"))?;
        Ok(Self(key))
    }

    /// A DPoP proof for a POST to `url`: a JWT with the public key in its
    /// header, signed with ES256, as the AWS CLI builds it. The `htu` claim
    /// is the URL without its query and fragment (RFC 9449, section 4.2).
    fn proof(&self, url: &str) -> anyhow::Result<String> {
        let url = htu(url);
        // An uncompressed point: 0x04, then the 32-byte x and y.
        let point = self.0.public_key().as_ref();
        let (x, y) = point
            .get(1..)
            .filter(|xy| xy.len() == 64)
            .map(|xy| xy.split_at(32))
            .context("unexpected public key")?;
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": {
                "kty": "EC",
                "x": URL_SAFE_NO_PAD.encode(x),
                "y": URL_SAFE_NO_PAD.encode(y),
                "crv": "P-256",
            },
        });
        let payload = serde_json::json!({
            "jti": oauth::random_string(16)?,
            "htm": "POST",
            "htu": url,
            "iat": Timestamp::now().as_second(),
        });
        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(payload.to_string())
        );
        let signature = self
            .0
            .sign(&SystemRandom::new(), message.as_bytes())
            .map_err(|_| anyhow!("could not sign the DPoP proof"))?;
        Ok(format!(
            "{message}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        ))
    }
}

fn client(region: &str) -> aws_sdk_signin::Client {
    let mut config = aws_sdk_signin::Config::builder()
        .region(aws_sdk_signin::config::Region::new(region.to_string()))
        .behavior_version(aws_sdk_signin::config::BehaviorVersion::latest());
    if let Some(url) = service_endpoint(ENDPOINT_VARIABLE) {
        config = config.endpoint_url(url);
    }
    aws_sdk_signin::Client::from_conf(config.build())
}

/// The AWS Sign-In endpoint for `region` as the SDK resolves it (so other
/// partitions work), or a configured one; the AWS CLI builds the consent
/// page from it the same way.
async fn base_url(region: &str) -> anyhow::Result<String> {
    if let Some(url) = service_endpoint(ENDPOINT_VARIABLE) {
        return Ok(url.trim_end_matches('/').to_string());
    }
    use aws_sdk_signin::config::endpoint::{DefaultResolver, Params, ResolveEndpoint};
    let params = Params::builder().region(region).build()?;
    let endpoint = DefaultResolver::new()
        .resolve_endpoint(&params)
        .await
        .map_err(|e| anyhow!("resolving the AWS Sign-In endpoint: {e}"))?;
    Ok(endpoint.url().trim_end_matches('/').to_string())
}

/// Boxed: the SDK error is large, and it is only ever inspected.
type TokenError = Box<SdkError<CreateOAuth2TokenError, HttpResponse>>;

/// `CreateOAuth2Token` with a DPoP proof made for each attempt, after the
/// endpoint is known (the proof names the URL it is for).
async fn create_token(
    region: &str,
    key: DpopKey,
    body: CreateOAuth2TokenRequestBody,
) -> std::result::Result<CreateOAuth2TokenResponseBody, TokenError> {
    let key = Arc::new(key);
    let output = client(region)
        .create_o_auth2_token()
        .token_input(body)
        .customize()
        .mutate_request(move |request| match key.proof(request.uri()) {
            Ok(proof) => {
                request.headers_mut().insert("DPoP", proof);
            }
            // Sent without one, the request is refused and says why.
            Err(e) => tracing::warn!("could not make the DPoP proof: {e:#}"),
        })
        .send()
        .await
        .map_err(Box::new)?;
    output.token_output.ok_or_else(|| {
        Box::new(SdkError::construction_failure(anyhow!(
            "AWS Sign-In returned no token"
        )))
    })
}

/// The documented reason AWS Sign-In refused a token request, if it gave one.
fn refusal(e: &TokenError) -> Option<&OAuth2ErrorCode> {
    match e.as_service_error() {
        Some(CreateOAuth2TokenError::AccessDeniedException(denied)) => Some(denied.error()),
        // `invalid_grant`, for a refresh token AWS no longer knows.
        Some(CreateOAuth2TokenError::ValidationException(invalid)) => Some(invalid.error()),
        _ => None,
    }
}

const INSUFFICIENT_PERMISSIONS: &str = "the console identity may not sign in to developer tools: \
     it needs signin:AuthorizeOAuth2Access and signin:CreateOAuth2Token, which the \
     SignInLocalDevelopmentAccess managed policy grants";

/// Signs in with the console session the browser picks. `browser_here`
/// waits for the browser on a loopback listener; otherwise `show` gives a
/// page to open on any device and `paste` reads the code it shows. Returns
/// the console identity signed in.
pub async fn login(
    integration: &str,
    config: &AwsLoginConfig,
    browser_here: bool,
    show: impl FnOnce(&str),
    paste: impl FnOnce() -> anyhow::Result<String>,
) -> anyhow::Result<String> {
    let base = base_url(&config.region).await?;
    let oauth::Pkce {
        verifier,
        challenge,
        state,
    } = oauth::Pkce::new()?;

    let (client_id, code, redirect_uri) = if browser_here {
        let loopback = oauth::Loopback::bind(0)?;
        let redirect_uri = format!("http://127.0.0.1:{}{CALLBACK_PATH}", loopback.port());
        show(&authorize_url(
            &base,
            SAME_DEVICE_CLIENT,
            &redirect_uri,
            &state,
            &challenge,
        ));
        let code = loopback.code(CALLBACK_PATH, &state, "AWS").await?;
        (SAME_DEVICE_CLIENT, code, redirect_uri)
    } else {
        let redirect_uri = format!("{base}/v1/sessions/confirmation");
        show(&authorize_url(
            &base,
            CROSS_DEVICE_CLIENT,
            &redirect_uri,
            &state,
            &challenge,
        ));
        let code = pasted_code(&paste()?, &state)?;
        (CROSS_DEVICE_CLIENT, code, redirect_uri)
    };

    let (key, stored_key) = DpopKey::generate()?;
    let body = CreateOAuth2TokenRequestBody::builder()
        .client_id(client_id)
        .grant_type("authorization_code")
        .code(code)
        .code_verifier(verifier)
        .redirect_uri(redirect_uri)
        .build()?;
    let now = Timestamp::now();
    let token = create_token(&config.region, key, body)
        .await
        .map_err(|e| match refusal(&e) {
            Some(OAuth2ErrorCode::AuthcodeExpired) => {
                anyhow!("the sign-in code expired before it was redeemed; sign in again")
            }
            Some(OAuth2ErrorCode::InsufficientPermissions) => anyhow!("{INSUFFICIENT_PERMISSIONS}"),
            _ => anyhow!("exchanging the sign-in code: {}", DisplayErrorContext(&e)),
        })?;
    let id_token = token
        .id_token()
        .context("AWS Sign-In returned no ID token")?;
    let login_session = subject(id_token)?;
    let account_id = login_session
        .split(':')
        .nth(4)
        .filter(|a| a.len() == 12 && a.bytes().all(|b| b.is_ascii_digit()))
        .with_context(|| format!("no account in the signed-in identity {login_session}"))?
        .to_string();
    let session = Session {
        login_session: login_session.clone(),
        account_id,
        client_id: client_id.to_string(),
        region: config.region.clone(),
        dpop_key: stored_key,
        ..from_token(&token, now, None)?
    };
    // Under the renewal's lock, so a renewal of the previous sign-in that
    // is under way cannot store the old session over this one.
    let _lock = store::lock(&format!("aws-login-{integration}"), REFRESH_LOCK_TIMEOUT).await?;
    store::set(&session_key(integration), &session)?;
    Ok(login_session)
}

/// The consent page, with the parameters and encoding the AWS CLI sends:
/// `code_challenge_method` is `SHA-256`, not OAuth's `S256`.
fn authorize_url(
    base: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    challenge: &str,
) -> String {
    let query = [
        ("response_type", "code"),
        ("client_id", client_id),
        ("state", state),
        ("code_challenge_method", "SHA-256"),
        ("scope", "openid"),
        ("redirect_uri", redirect_uri),
        ("code_challenge", challenge),
    ]
    .iter()
    .map(|(k, v)| format!("{k}={}", oauth::percent_encode(v)))
    .collect::<Vec<_>>()
    .join("&");
    format!("{base}/v1/authorize?{query}")
}

/// The code from what the cross-device page shows: base64 of
/// `state=…&code=…`, whose `state` must be this sign-in's.
fn pasted_code(pasted: &str, state: &str) -> anyhow::Result<String> {
    let pasted = pasted.trim();
    if pasted.is_empty() {
        bail!("no code was pasted");
    }
    let decoded = STANDARD
        .decode(pasted)
        .or_else(|_| URL_SAFE_NO_PAD.decode(pasted.trim_end_matches('=')))
        .context("the pasted code is not the one AWS shows (base64)")?;
    let text = String::from_utf8(decoded).context("the pasted code is not text")?;
    let mut code = None;
    let mut returned_state = None;
    for (k, v) in reqwest::Url::parse(&format!("http://x/?{text}"))
        .context("the pasted code is not the one AWS shows")?
        .query_pairs()
    {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => returned_state = Some(v.into_owned()),
            _ => {}
        }
    }
    if returned_state.as_deref() != Some(state) {
        bail!("the pasted code belongs to another sign-in; paste the one this sign-in shows");
    }
    code.filter(|c| !c.is_empty())
        .context("the pasted code holds no authorization code")
}

/// The `sub` claim of the ID token, the signed-in identity's ARN. The token
/// comes straight from AWS Sign-In over TLS, so its signature is not checked,
/// as the AWS CLI does not.
fn subject(id_token: &str) -> anyhow::Result<String> {
    let claims: serde_json::Value =
        crate::oauth::decode_jwt_payload(id_token).context("reading the ID token")?;
    claims["sub"]
        .as_str()
        .filter(|s| s.starts_with("arn:"))
        .map(str::to_string)
        .context("the ID token names no identity")
}

/// The credential fields of a token response; the rest of the session is
/// the caller's. `previous` keeps the refresh token when none is returned.
fn from_token(
    token: &CreateOAuth2TokenResponseBody,
    now: Timestamp,
    previous: Option<&Session>,
) -> anyhow::Result<Session> {
    let creds = token
        .access_token()
        .context("AWS Sign-In returned no credentials")?;
    let refresh_token = if token.refresh_token().is_empty() {
        previous
            .map(|p| p.refresh_token.clone())
            .context("AWS Sign-In returned no refresh token")?
    } else {
        token.refresh_token().to_string()
    };
    let base = previous.cloned().unwrap_or_else(|| Session {
        login_session: String::new(),
        account_id: String::new(),
        client_id: String::new(),
        region: String::new(),
        refresh_token: String::new(),
        dpop_key: String::new(),
        access_key_id: String::new(),
        secret_access_key: String::new(),
        session_token: String::new(),
        expires_at: now,
        issued_at: None,
    });
    Ok(Session {
        refresh_token,
        access_key_id: creds.access_key_id().to_string(),
        secret_access_key: creds.secret_access_key().to_string(),
        session_token: creds.session_token().to_string(),
        expires_at: now
            .saturating_add(SignedDuration::from_secs(token.expires_in().into()))
            .unwrap_or(Timestamp::MAX),
        issued_at: Some(now),
        ..base
    })
}

fn load(integration: &str) -> Result<Session> {
    store::get::<Session>(&session_key(integration))?
        .ok_or_else(|| Error::needs_login(integration, format!("'{integration}' is not signed in")))
}

fn fresh(session: &Session, now: Timestamp) -> bool {
    session.expires_at > now.saturating_add(REFRESH_WINDOW).unwrap_or(Timestamp::MAX)
}

/// Deletes the stored session if it still holds `refresh_token`, so a
/// session another process has just renewed is never thrown away.
fn drop_if_current(integration: &str, refresh_token: &str) {
    if let Ok(Some(stored)) = store::get::<Session>(&session_key(integration))
        && stored.refresh_token == refresh_token
    {
        let _ = store::delete(&session_key(integration));
    }
}

/// The session with credentials good for a while, renewed if needed.
/// `renew` renews it even then, for callers that want credentials of the
/// full lifetime (`fob renew`, `--no-cache`, `fob console`): without it, a
/// background renewal would get back the credentials it is replacing.
///
/// Renewal runs under a lock shared by every omnifob process, since each
/// refresh spends the refresh token. A session that changed while waiting
/// for the lock was just renewed by another process, and is used as it is.
async fn current(integration: &str, renew: bool) -> Result<Session> {
    let seen = load(integration)?;
    if !renew && fresh(&seen, Timestamp::now()) {
        return Ok(seen);
    }
    let _lock = store::lock(&format!("aws-login-{integration}"), REFRESH_LOCK_TIMEOUT).await?;
    let session = load(integration)?;
    let now = Timestamp::now();
    let renewed_meanwhile =
        session.refresh_token != seen.refresh_token || session.expires_at != seen.expires_at;
    if (renew && renewed_meanwhile) || (!renew && fresh(&session, now)) {
        return Ok(session);
    }

    let key = DpopKey::load(&session.dpop_key)?;
    let body = CreateOAuth2TokenRequestBody::builder()
        .client_id(&session.client_id)
        .grant_type("refresh_token")
        .refresh_token(&session.refresh_token)
        .build()
        .map_err(anyhow::Error::from)?;
    match create_token(&session.region, key, body).await {
        Ok(token) => {
            let renewed = from_token(&token, now, Some(&session))?;
            store::set(&session_key(integration), &renewed)?;
            Ok(renewed)
        }
        Err(e) => {
            let ended = match refusal(&e) {
                Some(OAuth2ErrorCode::TokenExpired) => Some(format!(
                    "the console sign-in for '{integration}' has ended (12 hours by default, up to 90 days where the IAM user or role allows it)"
                )),
                Some(OAuth2ErrorCode::UserCredentialsChanged) => Some(format!(
                    "the password of the console identity for '{integration}' changed"
                )),
                Some(OAuth2ErrorCode::OauthInvalidGrant) => Some(format!(
                    "AWS Sign-In no longer accepts the sign-in for '{integration}'"
                )),
                _ => None,
            };
            if let Some(reason) = ended {
                tracing::debug!("AWS Sign-In refused to renew: {}", DisplayErrorContext(&e));
                drop_if_current(integration, &session.refresh_token);
                return Err(Error::needs_login(integration, reason));
            }
            if matches!(refusal(&e), Some(OAuth2ErrorCode::InsufficientPermissions)) {
                return Err(anyhow!(
                    "renewing the sign-in for '{integration}': {INSUFFICIENT_PERMISSIONS}"
                )
                .into());
            }
            if session.expires_at
                > now
                    .saturating_add(SignedDuration::from_mins(1))
                    .unwrap_or(Timestamp::MAX)
            {
                // Still valid for a while; renewal is tried again on the next use.
                tracing::debug!(
                    "renewing the console sign-in failed: {}",
                    DisplayErrorContext(&e)
                );
                return Ok(session);
            }
            // The session at AWS may well be intact, so it is kept.
            Err(anyhow!(
                "could not renew the sign-in for '{integration}' with AWS Sign-In: {}; run `fob login {integration}` if this persists",
                DisplayErrorContext(&e)
            )
            .into())
        }
    }
}

/// The signed-in identity's credentials, renewed when they are about to
/// expire, or always with `renew`. They always last 15 minutes from the last
/// renewal, so `--ttl` has nothing to shorten.
pub async fn credentials(
    integration: &str,
    config: &AwsLoginConfig,
    renew: bool,
) -> Result<Credentials> {
    let session = current(integration, renew).await?;
    let mut env = std::collections::BTreeMap::new();
    let mut put = |k: &str, v: &str| {
        env.insert(k.to_string(), v.to_string());
    };
    put("AWS_ACCESS_KEY_ID", &session.access_key_id);
    put("AWS_SECRET_ACCESS_KEY", &session.secret_access_key);
    put("AWS_SESSION_TOKEN", &session.session_token);
    put("AWS_CREDENTIAL_EXPIRATION", &session.expires_at.to_string());
    let region = config.default_region.as_deref().unwrap_or(&config.region);
    put("AWS_REGION", region);
    put("AWS_DEFAULT_REGION", region);
    Ok(Credentials {
        env,
        expires_at: Some(session.expires_at),
        issued_at: session.issued_at,
        ..Default::default()
    })
}

/// The signed-in console identity, named after it (`<user>`, `root`, or
/// the role name of an assumed role), and one profile per configured role.
pub fn discover(integration: &str, config: &AwsLoginConfig) -> Result<Vec<Profile>> {
    let session = load(integration)?;
    let account = config
        .account
        .clone()
        .unwrap_or_else(|| session.account_id.clone());
    let mut profiles = vec![Profile::new(
        integration,
        &account,
        &slug(identity_name(&session.login_session)),
        Target::AwsLogin {
            account_id: session.account_id,
        },
    )];
    for (label, role) in &config.roles {
        let profile = Profile::new(
            integration,
            label,
            role.role_name(),
            Target::AwsLoginRole {
                label: label.clone(),
                account_id: role.account_id().map(str::to_string),
            },
        );
        if profile.id == profiles[0].id {
            return Err(anyhow::anyhow!(
                "the role '{label}' of '{integration}' would be {}, the signed-in identity's profile; give it another label in [integrations.{integration}.roles]",
                profile.id
            )
            .into());
        }
        profiles.push(profile);
    }
    Ok(profiles)
}

/// A role assumed with the console sign-in's credentials, which STS counts
/// as role chaining: 15 minutes to an hour. `ttl` overrides its `duration`.
pub async fn role_credentials(
    integration: &str,
    config: &AwsLoginConfig,
    label: &str,
    profile_id: &str,
    ttl: Option<jiff::SignedDuration>,
) -> Result<Credentials> {
    use super::sts::{self, CHAINED_MAX, RoleRequest, SESSION_MIN};
    let role = config.roles.get(label).ok_or_else(|| {
        anyhow::anyhow!("no role '{label}' in integration '{integration}'; run `fob sync`")
    })?;
    let duration = ttl.or(role.duration).unwrap_or(CHAINED_MAX);
    if !(SESSION_MIN..=CHAINED_MAX).contains(&duration) {
        return Err(anyhow::anyhow!(
            "a role assumed with console sign-in credentials lasts 15 minutes to 1 hour: STS counts it as role chaining"
        )
        .into());
    }
    let request = RoleRequest {
        role_arn: &role.role_arn,
        session_name: role.session_name.as_deref(),
        external_id: role.external_id.as_deref(),
        mfa_serial: role.mfa_serial.as_deref(),
        duration,
        profile_id,
    };
    let region = role
        .region
        .as_deref()
        .or(config.default_region.as_deref())
        .unwrap_or(&config.region);
    let source = credentials(integration, config, false).await?;
    match sts::assume_role(&source, &request, &config.region, Some(region)).await {
        // Kept credentials STS no longer takes: renew them once.
        Err(e) if e.downcast_ref::<sts::CredentialsRejected>().is_some() => {
            tracing::debug!("renewing the console sign-in's credentials: {e:#}");
            let source = credentials(integration, config, true).await?;
            Ok(sts::assume_role(&source, &request, &config.region, Some(region)).await?)
        }
        result => Ok(result?),
    }
}

/// A short name for an identity ARN: the user name of `user/…/name`, the
/// role name of `assumed-role/role/session`, and `root` for the root user.
fn identity_name(arn: &str) -> &str {
    let resource = arn.splitn(6, ':').nth(5).unwrap_or(arn);
    let mut parts = resource.split('/');
    match parts.next() {
        Some("assumed-role") => parts.next().unwrap_or(resource),
        Some("root") | None => "root",
        Some(_) => resource.rsplit('/').next().unwrap_or(resource),
    }
}

/// Whether the stored session was signed in through the configured Region:
/// its refresh token renews only there. `false` when none is stored.
pub fn session_matches(integration: &str, config: &AwsLoginConfig) -> anyhow::Result<bool> {
    Ok(
        store::get::<Session>(&session_key(integration))?
            .is_some_and(|s| s.region == config.region),
    )
}

/// Whether a session is stored, and until when its credentials last.
pub fn session(integration: &str) -> anyhow::Result<Option<Timestamp>> {
    Ok(store::get::<Session>(&session_key(integration))?.map(|s| s.expires_at))
}

pub fn logout(integration: &str) -> anyhow::Result<bool> {
    store::delete(&session_key(integration))
}

/// Checks that the sign-in works; says whom it belongs to.
pub async fn check(integration: &str, config: &AwsLoginConfig) -> Result<String> {
    let creds = credentials(integration, config, false).await?;
    let identity = sts::caller_identity(&creds, &config.region).await?;
    Ok(format!("signed in as {}", identity.arn))
}

/// The partition of the signed-in Region.
pub fn partition(config: &AwsLoginConfig) -> anyhow::Result<Partition> {
    Partition::of_region(&config.region)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_are_named_by_their_arn() {
        assert_eq!(
            identity_name("arn:aws:iam::123456789012:user/alice"),
            "alice"
        );
        assert_eq!(
            identity_name("arn:aws:iam::123456789012:user/team/bob"),
            "bob"
        );
        assert_eq!(identity_name("arn:aws:iam::123456789012:root"), "root");
        assert_eq!(
            identity_name("arn:aws:sts::123456789012:assumed-role/Admin/me@example.com"),
            "Admin"
        );
    }

    #[test]
    fn the_dpop_htu_has_no_query_or_fragment() {
        let url = "https://us-east-1.signin.aws.amazon.com/v1/token";
        for with in [
            url.to_string(),
            format!("{url}?x=1"),
            format!("{url}#frag"),
            format!("{url}?x=1#frag"),
        ] {
            assert_eq!(htu(&with), url, "{with}");
        }
    }

    #[test]
    fn the_dpop_proof_names_the_url_and_verifies() {
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
        let (key, stored) = DpopKey::generate().unwrap();
        let proof = key
            .proof("https://us-east-1.signin.aws.amazon.com/v1/token?ignored=1")
            .unwrap();
        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["jwk"]["crv"], "P-256");
        assert_eq!(payload["htm"], "POST");
        assert_eq!(
            payload["htu"],
            "https://us-east-1.signin.aws.amazon.com/v1/token"
        );
        // The public key in the header verifies the signature, and a stored
        // key signs the same way.
        let mut point = vec![4u8];
        point.extend(
            URL_SAFE_NO_PAD
                .decode(header["jwk"]["x"].as_str().unwrap())
                .unwrap(),
        );
        point.extend(
            URL_SAFE_NO_PAD
                .decode(header["jwk"]["y"].as_str().unwrap())
                .unwrap(),
        );
        let message = format!("{}.{}", parts[0], parts[1]);
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
            .verify(message.as_bytes(), &signature)
            .unwrap();
        let reloaded = DpopKey::load(&stored).unwrap();
        assert_eq!(
            reloaded.0.public_key().as_ref(),
            key.0.public_key().as_ref()
        );
    }

    #[test]
    fn pasted_codes_must_carry_this_sign_ins_state() {
        let pasted = STANDARD.encode("state=s1&code=c1");
        assert_eq!(pasted_code(&pasted, "s1").unwrap(), "c1");
        assert!(pasted_code(&pasted, "s2").is_err());
        assert!(pasted_code("", "s1").is_err());
        assert!(pasted_code("not base64!", "s1").is_err());
    }

    #[test]
    fn the_consent_page_matches_the_aws_cli() {
        let url = authorize_url(
            "https://us-east-1.signin.aws.amazon.com",
            SAME_DEVICE_CLIENT,
            "http://127.0.0.1:4321/oauth/callback",
            "st",
            "ch",
        );
        assert_eq!(
            url,
            "https://us-east-1.signin.aws.amazon.com/v1/authorize?response_type=code\
             &client_id=arn%3Aaws%3Asignin%3A%3A%3Adevtools%2Fsame-device&state=st\
             &code_challenge_method=SHA-256&scope=openid\
             &redirect_uri=http%3A%2F%2F127.0.0.1%3A4321%2Foauth%2Fcallback&code_challenge=ch"
        );
    }
}
