//! Browser sign-in for Cloudflare (`type = "cloudflare-oauth"`).
//!
//! The same flow as `wrangler login`: Authorization Code with PKCE and a
//! localhost callback, then silent renewal with the refresh token. Cloudflare
//! offers third-party clients no device flow. The access token is never
//! handed out; it only mints the short-lived, account-owned tokens profiles
//! get, which needs the "Account API Tokens Write" scope (checked live on
//! 2026-10-09: an OAuth access token can create and delete account tokens in
//! every account approved on the consent page).

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::time::Duration;

use anyhow::{Context, bail};
use base64::Engine;
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};

use crate::config::CloudflareConfig;
use crate::{Error, Result, store};

const DASH: &str = "https://dash.cloudflare.com";

/// Where Cloudflare sends the browser back to. It must match a redirect URL
/// registered for the OAuth client.
pub const REDIRECT_URI: &str = "http://localhost:8977/callback";
const CALLBACK_ADDR: &str = "127.0.0.1:8977";

/// How long `fob login` waits for the consent page to be answered.
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

/// Renew the access token this long before it expires.
const RENEW_MARGIN: SignedDuration = SignedDuration::from_secs(60);

/// What minting needs whatever the templates: creating account tokens,
/// listing accounts, and a refresh token.
pub const BASE_SCOPES: &[&str] = &[
    "account-api-tokens.write",
    "account-settings.read",
    "memberships.read",
    "offline_access",
];

/// The OAuth scope that lets a sign-in mint each permission. A token minted
/// with OAuth may only carry permissions whose scope the consent granted
/// (Cloudflare refuses the rest, checked 2026-10-09). Scope IDs do not follow
/// the permission names, so they are listed here, from `GET /oauth/scopes`.
const PERMISSION_SCOPES: &[(&str, &str)] = &[
    ("Account Settings Read", "account-settings.read"),
    ("Agent Memory Write", "agent-memory.write"),
    ("AI Gateway Write", "aig.write"),
    ("AI Search Write", "ai-search.write"),
    ("Artifacts Write", "artifacts.write"),
    ("Browser Run Write", "browser-rendering.write"),
    ("CF Agents Write", "cf-agents.write"),
    ("Cloudchamber Write", "cloudchamber.write"),
    ("D1 Write", "d1.write"),
    ("DNS Read", "dns.read"),
    ("DNS Write", "dns.write"),
    ("Email Sending Write", "email-sending.write"),
    ("Flagship Write", "flagship.write"),
    ("Hyperdrive Write", "query-cache.write"),
    ("Images Write", "images.write"),
    ("Memberships Read", "memberships.read"),
    ("Pages Write", "page.write"),
    ("Pipelines Write", "pipelines.write"),
    ("Queues Write", "queues.write"),
    ("Secrets Store Write", "secrets-store.write"),
    ("User Details Read", "user-details.read"),
    ("Vectorize Write", "vectorize.write"),
    ("Workers AI Write", "ai.write"),
    ("Workers CI Write", "workers-ci.write"),
    ("Workers Containers Write", "containers.write"),
    ("Workers KV Storage Write", "workers-kv-storage.write"),
    ("Workers Observability Write", "workers-observability.write"),
    ("Workers R2 Storage Write", "workers-r2.write"),
    ("Workers Routes Write", "workers-routes.write"),
    ("Workers Scripts Read", "workers-scripts.read"),
    ("Workers Scripts Write", "workers-scripts.write"),
    ("Workers Tail Read", "workers-tail.read"),
    ("Zone Read", "zone.read"),
];

/// The scope a permission needs, accepting the dashboard's "Edit" for "Write".
pub fn scope_for(permission: &str) -> Option<&'static str> {
    let lower = permission.to_lowercase();
    let write = match lower.rsplit_once(' ') {
        Some((base, "edit")) => format!("{base} write"),
        _ => lower.clone(),
    };
    PERMISSION_SCOPES
        .iter()
        .find(|(name, _)| name.to_lowercase() == write)
        .map(|(_, scope)| *scope)
}

/// The dashboard's OAuth endpoints; `OMNIFOB_CLOUDFLARE_DASH` overrides the
/// host for testing.
fn dash() -> String {
    std::env::var("OMNIFOB_CLOUDFLARE_DASH")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DASH.to_string())
}

fn token_key(integration: &str) -> String {
    format!("cloudflare/{integration}/oauth")
}

/// What the keychain keeps for a signed-in integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Stored {
    access_token: String,
    expires_at: Timestamp,
    refresh_token: Option<String>,
    /// When `session` makes omnifob stop renewing and ask for a new sign-in.
    #[serde(default)]
    session_ends: Option<Timestamp>,
    /// The scopes the consent granted.
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

fn http() -> reqwest::Client {
    // Cloudflare's bot protection rejects requests without a user agent
    // (error 1010), and the token endpoint sits behind it.
    reqwest::Client::builder()
        .user_agent(concat!("omnifob/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("HTTP client")
}

fn client_id(integration: &str, config: &CloudflareConfig) -> anyhow::Result<String> {
    config.client_id.clone().with_context(|| {
        format!(
            "'{integration}' needs client_id: register an OAuth client for omnifob in the \
             dashboard (Manage Account > OAuth clients) with the redirect URL {REDIRECT_URI}"
        )
    })
}

/// The scopes to request: `scopes` from the config, or the base ones plus
/// every scope the integration's templates need, so a template mints the
/// same token whichever way the integration signs in.
pub fn scopes(config: &CloudflareConfig) -> Vec<String> {
    if let Some(scopes) = &config.scopes {
        return scopes.clone();
    }
    let mut scopes: Vec<String> = BASE_SCOPES.iter().map(|s| s.to_string()).collect();
    for template in super::cloudflare::templates(config).values() {
        for permission in template.permissions.iter().chain(&template.optional) {
            match scope_for(permission) {
                Some(scope) => scopes.push(scope.to_string()),
                None => tracing::warn!(
                    "no known OAuth scope for '{permission}'; add it to the integration's `scopes`"
                ),
            }
        }
    }
    scopes.sort();
    scopes.dedup();
    scopes
}

/// The scopes the stored sign-in was granted; `None` when not signed in.
pub fn granted_scopes(integration: &str) -> anyhow::Result<Option<Vec<String>>> {
    Ok(store::get::<Stored>(&token_key(integration))?.map(|s| s.scopes))
}

/// A PKCE verifier and its S256 challenge.
fn pkce() -> anyhow::Result<(String, String)> {
    let verifier = random_string(48)?;
    let challenge = challenge(&verifier);
    Ok((verifier, challenge))
}

fn challenge(verifier: &str) -> String {
    use sha2::Digest;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier))
}

fn random_string(bytes: usize) -> anyhow::Result<String> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).map_err(|e| anyhow::anyhow!("no system randomness: {e}"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf))
}

/// The consent page URL.
fn authorize_url(client_id: &str, scopes: &[String], state: &str, challenge: &str) -> String {
    let mut url = reqwest::Url::parse(&format!("{}/oauth2/auth", dash())).expect("valid URL");
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", REDIRECT_URI)
        .append_pair("scope", &scopes.join(" "))
        .append_pair("state", state)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256");
    url.to_string()
}

/// Signs in through the browser: calls `show` with the consent page URL,
/// waits for Cloudflare to redirect back, and stores the tokens. Returns
/// when the session ends, if the integration has a `session`.
pub async fn login(
    integration: &str,
    config: &CloudflareConfig,
    show: impl FnOnce(&str),
) -> anyhow::Result<Option<Timestamp>> {
    let client_id = client_id(integration, config)?;
    let listener = TcpListener::bind(CALLBACK_ADDR).with_context(|| {
        format!(
            "listening on {CALLBACK_ADDR} for the sign-in callback; is another sign-in running?"
        )
    })?;
    let (verifier, challenge) = pkce()?;
    let state = random_string(16)?;
    show(&authorize_url(
        &client_id,
        &scopes(config),
        &state,
        &challenge,
    ));

    let code =
        tokio::task::spawn_blocking(move || wait_for_code(&listener, &state, CALLBACK_TIMEOUT))
            .await??;

    let now = Timestamp::now();
    let response = exchange(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", &client_id),
        ("code_verifier", &verifier),
    ])
    .await
    .context("exchanging the sign-in code")?;
    if let Some(granted) = &response.scope
        && !granted.split(' ').any(|s| s == "account-api-tokens.write")
    {
        bail!(
            "the sign-in did not grant Account API Tokens Write, which minting needs; \
             sign in again and turn it on under Sensitive scopes"
        );
    }
    let session_ends = config.session.map(|s| now.checked_add(s)).transpose()?;
    let requested = scopes(config);
    let stored = stored(response, now, None, session_ends, &requested)?;
    store::set(&token_key(integration), &stored)?;
    Ok(session_ends)
}

/// Accepts connections until one carries the callback, answers the browser,
/// and returns the authorization code. Gives up after `timeout`; the listener
/// polls rather than blocks, so the process can exit then.
fn wait_for_code(listener: &TcpListener, state: &str, timeout: Duration) -> anyhow::Result<String> {
    listener.set_nonblocking(true)?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    bail!(
                        "the sign-in was not completed within {} minutes",
                        timeout.as_secs() / 60
                    );
                }
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line)?;
        let Some(query) = callback_query(&line) else {
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
            continue;
        };
        let result = parse_callback(&query, state);
        let message = match &result {
            Ok(_) => "Signed in to Cloudflare. You can close this tab and return to the terminal.",
            Err(_) => "The sign-in failed. Return to the terminal for details.",
        };
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{message}",
            message.len()
        );
        return result;
    }
}

/// The query of a `GET /callback?...` request line.
fn callback_query(request_line: &str) -> Option<String> {
    let target = request_line.strip_prefix("GET ")?.split(' ').next()?;
    let query = target.strip_prefix("/callback?")?;
    Some(query.to_string())
}

fn parse_callback(query: &str, state: &str) -> anyhow::Result<String> {
    let url = reqwest::Url::parse(&format!("http://localhost/?{query}"))?;
    let param = |name: &str| {
        url.query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    };
    if let Some(error) = param("error") {
        let detail = param("error_description").unwrap_or_default();
        bail!("Cloudflare refused the sign-in: {error} {detail}");
    }
    if param("state").as_deref() != Some(state) {
        bail!("the callback's state does not match this sign-in");
    }
    param("code").context("the callback carries no code")
}

async fn exchange(form: &[(&str, &str)]) -> anyhow::Result<TokenResponse> {
    let mut body = reqwest::Url::parse("http://localhost/").expect("valid URL");
    body.query_pairs_mut().extend_pairs(form);
    let response = http()
        .post(format!("{}/oauth2/token", dash()))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .body(body.query().unwrap_or_default().to_string())
        .send()
        .await?;
    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        #[derive(Deserialize)]
        struct OauthError {
            error: String,
            #[serde(default)]
            error_description: Option<String>,
        }
        let detail = match serde_json::from_str::<OauthError>(&text) {
            Ok(e) => format!("{} {}", e.error, e.error_description.unwrap_or_default()),
            Err(_) => text.chars().take(200).collect(),
        };
        bail!("token endpoint answered {status}: {}", detail.trim());
    }
    serde_json::from_str(&text).context("unexpected token response")
}

fn stored(
    response: TokenResponse,
    now: Timestamp,
    previous_refresh: Option<String>,
    session_ends: Option<Timestamp>,
    previous_scopes: &[String],
) -> anyhow::Result<Stored> {
    let lifetime = SignedDuration::from_secs(response.expires_in.unwrap_or(3600));
    let scopes = match &response.scope {
        Some(granted) => granted.split(' ').map(str::to_string).collect(),
        None => previous_scopes.to_vec(),
    };
    Ok(Stored {
        scopes,
        access_token: response.access_token,
        expires_at: now.checked_add(lifetime)?,
        // Cloudflare rotates refresh tokens; keep the old one only when no
        // new one came back.
        refresh_token: response.refresh_token.or(previous_refresh),
        session_ends,
    })
}

/// A current access token, renewed with the refresh token when it is about
/// to expire.
pub async fn access_token(integration: &str, config: &CloudflareConfig) -> Result<String> {
    let key = token_key(integration);
    let stored: Stored = store::get(&key)?.ok_or_else(|| Error::not_signed_in(integration))?;
    let now = Timestamp::now();
    if stored.session_ends.is_some_and(|end| end <= now) {
        return Err(Error::needs_login(
            integration,
            format!("the Cloudflare session of '{integration}' ended"),
        ));
    }
    if stored.expires_at.duration_since(now) > RENEW_MARGIN {
        return Ok(stored.access_token);
    }
    let Some(refresh) = stored.refresh_token.clone() else {
        return Err(Error::needs_login(
            integration,
            "the Cloudflare sign-in expired and cannot be renewed",
        ));
    };
    let client_id = client_id(integration, config)?;
    match exchange(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", &refresh),
        ("client_id", &client_id),
    ])
    .await
    {
        Ok(response) => {
            let renewed =
                stored_capped(response, now, refresh, stored.session_ends, &stored.scopes)?;
            store::set(&key, &renewed)?;
            Ok(renewed.access_token)
        }
        Err(e) => {
            // Another fob process may have renewed it first, which spends the
            // refresh token this one read.
            if let Some(latest) = store::get::<Stored>(&key)?
                && latest.refresh_token.as_deref() != Some(refresh.as_str())
                && latest.expires_at.duration_since(now) > RENEW_MARGIN
            {
                return Ok(latest.access_token);
            }
            Err(Error::needs_login(
                integration,
                format!("renewing the Cloudflare sign-in failed: {e:#}"),
            ))
        }
    }
}

/// [`stored`], but never past the end of the session.
fn stored_capped(
    response: TokenResponse,
    now: Timestamp,
    previous_refresh: String,
    session_ends: Option<Timestamp>,
    previous_scopes: &[String],
) -> anyhow::Result<Stored> {
    let mut renewed = stored(
        response,
        now,
        Some(previous_refresh),
        session_ends,
        previous_scopes,
    )?;
    if let Some(end) = session_ends {
        renewed.expires_at = renewed.expires_at.min(end);
    }
    Ok(renewed)
}

pub fn is_signed_in(integration: &str) -> anyhow::Result<bool> {
    Ok(store::get::<Stored>(&token_key(integration))?.is_some())
}

/// When the sign-in ends: the session's end, or, without a session, when the
/// access token expires (it renews on next use).
pub fn sign_in_ends(integration: &str) -> anyhow::Result<Option<(Timestamp, bool)>> {
    Ok(
        store::get::<Stored>(&token_key(integration))?.map(|s| match s.session_ends {
            Some(end) => (end, false),
            None => (s.expires_at, s.refresh_token.is_some()),
        }),
    )
}

/// Revokes the sign-in on Cloudflare, so the consent ends there too.
/// Returns whether there was one to revoke.
pub async fn revoke(integration: &str, config: &CloudflareConfig) -> anyhow::Result<bool> {
    let Some(stored) = store::get::<Stored>(&token_key(integration))? else {
        return Ok(false);
    };
    let client_id = client_id(integration, config)?;
    let mut tokens = vec![("access_token", stored.access_token)];
    if let Some(refresh) = stored.refresh_token {
        tokens.insert(0, ("refresh_token", refresh));
    }
    for (hint, token) in tokens {
        let mut body = reqwest::Url::parse("http://localhost/").expect("valid URL");
        body.query_pairs_mut()
            .append_pair("token", &token)
            .append_pair("token_type_hint", hint)
            .append_pair("client_id", &client_id);
        let response = http()
            .post(format!("{}/oauth2/revoke", dash()))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.query().unwrap_or_default().to_string())
            .send()
            .await?;
        if !response.status().is_success() {
            bail!("revoking the {hint} failed ({})", response.status());
        }
    }
    Ok(true)
}

pub fn logout(integration: &str) -> anyhow::Result<bool> {
    store::delete(&token_key(integration))
}

pub fn rename(old: &str, new: &str) -> anyhow::Result<bool> {
    store::rename(&token_key(old), &token_key(new))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_is_rfc_7636_s256() {
        // The example from RFC 7636, appendix B.
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let (verifier, _) = pkce().unwrap();
        assert!((43..=128).contains(&verifier.len()), "{}", verifier.len());
    }

    #[test]
    fn waiting_for_the_callback_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let err = wait_for_code(&listener, "s", Duration::from_millis(200))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not completed"), "{err}");
    }

    #[test]
    fn waiting_for_the_callback_returns_the_code() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let browser = std::thread::spawn(move || {
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.write_all(b"GET /callback?code=c1&state=s HTTP/1.1\r\nHost: x\r\n\r\n")
                .unwrap();
            let mut reply = String::new();
            std::io::Read::read_to_string(&mut s, &mut reply).unwrap();
            reply
        });
        let code = wait_for_code(&listener, "s", Duration::from_secs(5)).unwrap();
        assert_eq!(code, "c1");
        assert!(browser.join().unwrap().starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn permissions_map_to_scopes() {
        assert_eq!(scope_for("Pages Write"), Some("page.write"));
        assert_eq!(scope_for("hyperdrive edit"), Some("query-cache.write"));
        assert_eq!(scope_for("Cache Purge"), None);
    }

    #[test]
    fn builtin_templates_have_scopes() {
        for template in super::super::cloudflare::builtin_templates().values() {
            for permission in template.permissions.iter().chain(&template.optional) {
                assert!(scope_for(permission).is_some(), "{permission}");
            }
        }
    }

    #[test]
    fn callback_lines() {
        assert_eq!(
            callback_query("GET /callback?code=a&state=b HTTP/1.1\r\n").as_deref(),
            Some("code=a&state=b")
        );
        assert_eq!(callback_query("GET /favicon.ico HTTP/1.1\r\n"), None);
        assert_eq!(callback_query("POST /callback?code=a HTTP/1.1\r\n"), None);
    }

    #[test]
    fn callbacks_check_state_and_errors() {
        assert_eq!(parse_callback("code=abc&state=s1", "s1").unwrap(), "abc");
        assert!(parse_callback("code=abc&state=other", "s1").is_err());
        let err = parse_callback("error=access_denied&error_description=no&state=s1", "s1")
            .unwrap_err()
            .to_string();
        assert!(err.contains("access_denied"), "{err}");
    }

    #[test]
    fn consent_url_carries_pkce_and_scopes() {
        let url = reqwest::Url::parse(&authorize_url(
            "client",
            &["a.read".into(), "offline_access".into()],
            "st",
            "ch",
        ))
        .unwrap();
        let q: std::collections::BTreeMap<_, _> = url.query_pairs().collect();
        assert_eq!(q["client_id"], "client");
        assert_eq!(q["redirect_uri"], REDIRECT_URI);
        assert_eq!(q["scope"], "a.read offline_access");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["code_challenge"], "ch");
    }

    #[test]
    fn renewal_keeps_refresh_token_and_session_end() {
        let now: Timestamp = "2026-10-09T00:00:00Z".parse().unwrap();
        let end: Timestamp = "2026-10-09T00:30:00Z".parse().unwrap();
        let response = TokenResponse {
            access_token: "a".into(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None,
        };
        let renewed =
            stored_capped(response, now, "r".into(), Some(end), &["a.read".into()]).unwrap();
        assert_eq!(renewed.refresh_token.as_deref(), Some("r"));
        assert_eq!(renewed.scopes, ["a.read"]);
        assert_eq!(renewed.expires_at, end);
    }
}
