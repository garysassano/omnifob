//! Cloudflare browser sign-in (`cloudflare-oauth`) against a mock of the
//! dashboard's OAuth endpoints and the v4 API. Secrets go to an in-memory
//! store, never the keychain.

use std::collections::HashMap;
use std::io::{Read, Write};

use crate::support::Scratch;
use jiff::{SignedDuration, Timestamp};
use omnifob_core::config::{CloudflareConfig, Config, Integration};
use omnifob_core::providers::cloudflare::{self, oauth as cloudflare_oauth};
use omnifob_core::{Endpoints, Error, store};
use serde_json::{Value, json};
use tokio::sync::{Mutex, MutexGuard};
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The sign-in's callback port is fixed, so the tests run one at a time.
static SERIAL: Mutex<()> = Mutex::const_new(());

async fn setup() -> (Scratch, MutexGuard<'static, ()>, MockServer) {
    let guard = SERIAL.lock().await;
    let server = MockServer::start().await;
    let endpoints = Endpoints {
        cloudflare_api: Some(server.uri()),
        cloudflare_dash: Some(server.uri()),
        ..Default::default()
    };
    (
        Scratch::new("omnifob-cf-oauth-test", endpoints),
        guard,
        server,
    )
}

fn config() -> CloudflareConfig {
    let text = "[integrations.cf]\ntype = \"cloudflare-oauth\"\nclient_id = \"client-1\"\n";
    match Config::parse(text)
        .unwrap()
        .integrations
        .remove("cf")
        .unwrap()
    {
        Integration::Cloudflare(c) => c,
        _ => unreachable!(),
    }
}

fn form(body: &[u8]) -> HashMap<String, String> {
    reqwest::Url::parse(&format!("http://x/?{}", std::str::from_utf8(body).unwrap()))
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn tokens(access: &str, refresh: &str, scope: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "access_token": access,
        "token_type": "bearer",
        "expires_in": 3600,
        "refresh_token": refresh,
        "scope": scope,
    }))
}

/// Stores a sign-in whose access token expires in `expires_in`.
fn signed_in(access: &str, refresh: &str, expires_in: SignedDuration) {
    store::set(
        "cloudflare/cf/oauth",
        &json!({
            "access_token": access,
            "expires_at": Timestamp::now() + expires_in,
            "refresh_token": refresh,
            "scopes": ["account-api-tokens.write"],
        }),
    )
    .unwrap();
}

fn stored() -> Option<Value> {
    store::get::<Value>("cloudflare/cf/oauth").unwrap()
}

/// Signs in through the consent page, answered the way a browser would;
/// returns the consent page's query and the browser's reply.
async fn browser_login(
    config: &CloudflareConfig,
) -> (anyhow::Result<Option<Timestamp>>, HashMap<String, String>) {
    let opened = std::sync::Arc::new(std::sync::Mutex::new(None));
    let seen = opened.clone();
    let browser = std::sync::Arc::new(std::sync::Mutex::new(None));
    let started = browser.clone();
    let result = cloudflare_oauth::login("cf", config, move |url| {
        let url = reqwest::Url::parse(url).unwrap();
        assert_eq!(url.path(), "/oauth2/auth");
        let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
        let state = query["state"].clone();
        *seen.lock().unwrap() = Some(query);
        *started.lock().unwrap() = Some(std::thread::spawn(move || {
            let mut s = std::net::TcpStream::connect(("127.0.0.1", 8977)).unwrap();
            write!(
                s,
                "GET /callback?code=code-1&state={state} HTTP/1.1\r\nHost: x\r\n\r\n"
            )
            .unwrap();
            let mut reply = String::new();
            s.read_to_string(&mut reply).unwrap();
            reply
        }));
    })
    .await;
    // Joined, so a failure in the browser's thread fails the test.
    let reply = browser.lock().unwrap().take().unwrap().join().unwrap();
    assert!(reply.contains("Sign-in approved"), "{reply}");
    let query = opened.lock().unwrap().take().unwrap();
    (result, query)
}

#[tokio::test]
async fn browser_sign_in_redeems_the_code_with_pkce() {
    let (_scratch, _serial, server) = setup().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .and(body_string_contains("grant_type=authorization_code"))
        .respond_with(tokens(
            "access-1",
            "refresh-1",
            "account-api-tokens.write memberships.read offline_access",
        ))
        .expect(1)
        .mount(&server)
        .await;
    let (result, query) = browser_login(&config()).await;
    assert_eq!(result.unwrap(), None, "no session configured");

    assert_eq!(query["client_id"], "client-1");
    assert_eq!(query["redirect_uri"], cloudflare_oauth::REDIRECT_URI);
    assert_eq!(query["code_challenge_method"], "S256");
    assert!(
        query["scope"]
            .split(' ')
            .any(|s| s == "account-api-tokens.write"),
        "{}",
        query["scope"]
    );
    let requests = server.received_requests().await.unwrap();
    let exchanged = form(&requests[0].body);
    assert_eq!(exchanged["code"], "code-1");
    assert_eq!(
        omnifob_core::oauth::challenge(&exchanged["code_verifier"]),
        query["code_challenge"]
    );
    let stored = stored().unwrap();
    assert_eq!(stored["refresh_token"], "refresh-1");
    assert_eq!(
        cloudflare_oauth::granted_scopes("cf").unwrap().unwrap(),
        [
            "account-api-tokens.write",
            "memberships.read",
            "offline_access"
        ]
    );
}

#[tokio::test]
async fn a_sign_in_without_the_token_scope_is_refused() {
    let (_scratch, _serial, server) = setup().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(tokens("access-1", "refresh-1", "memberships.read"))
        .mount(&server)
        .await;
    let (result, _) = browser_login(&config()).await;
    let err = format!("{:#}", result.unwrap_err());
    assert!(err.contains("Account API Tokens Write"), "{err}");
    assert!(stored().is_none(), "nothing is stored");
}

#[tokio::test]
async fn an_expiring_access_token_is_renewed_and_the_refresh_token_rotated() {
    let (_scratch, _serial, server) = setup().await;
    signed_in("access-1", "refresh-1", SignedDuration::from_secs(30));
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("refresh_token=refresh-1"))
        .respond_with(tokens("access-2", "refresh-2", "account-api-tokens.write"))
        .expect(1)
        .mount(&server)
        .await;
    let token = cloudflare_oauth::access_token("cf", &config())
        .await
        .unwrap();
    assert_eq!(token, "access-2");
    assert_eq!(stored().unwrap()["refresh_token"], "refresh-2");
    // Fresh now: no second renewal.
    let token = cloudflare_oauth::access_token("cf", &config())
        .await
        .unwrap();
    assert_eq!(token, "access-2");
}

#[tokio::test]
async fn a_passing_failure_keeps_the_sign_in() {
    let (_scratch, _serial, server) = setup().await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(503).set_body_string("upstream unavailable"))
        .mount(&server)
        .await;
    // Expiring but still valid: handed out, renewal tried next time.
    signed_in("access-1", "refresh-1", SignedDuration::from_secs(30));
    let token = cloudflare_oauth::access_token("cf", &config())
        .await
        .unwrap();
    assert_eq!(token, "access-1");
    // Expired: an error, but no new sign-in is asked for, nor is it dropped.
    signed_in("access-1", "refresh-1", SignedDuration::from_secs(-30));
    let err = cloudflare_oauth::access_token("cf", &config())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Other(_)), "{err}");
    assert!(format!("{err:#}").contains("503"), "{err:#}");
    assert_eq!(stored().unwrap()["refresh_token"], "refresh-1", "kept");
}

#[tokio::test]
async fn a_final_refusal_forgets_the_sign_in() {
    let (_scratch, _serial, server) = setup().await;
    signed_in("access-1", "refresh-1", SignedDuration::from_secs(-30));
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "The refresh token was revoked.",
        })))
        .mount(&server)
        .await;
    let err = cloudflare_oauth::access_token("cf", &config())
        .await
        .unwrap_err();
    match &err {
        Error::NeedsLogin { reason, .. } => assert!(reason.contains("invalid_grant"), "{reason}"),
        other => panic!("{other:?}"),
    }
    assert!(stored().is_none(), "forgotten");
}

#[tokio::test]
async fn an_api_call_renews_a_rejected_access_token_once() {
    let (_scratch, _serial, server) = setup().await;
    // Valid for an hour, but revoked at Cloudflare, which answers 403.
    signed_in("access-1", "refresh-1", SignedDuration::from_hours(1));
    Mock::given(method("GET"))
        .and(path("/accounts"))
        .and(header("authorization", "Bearer access-1"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "success": false,
            "errors": [{ "code": 10000, "message": "Authentication error" }],
            "result": null,
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .and(body_string_contains("refresh_token=refresh-1"))
        .respond_with(tokens("access-2", "refresh-2", "account-api-tokens.write"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/accounts"))
        .and(header("authorization", "Bearer access-2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "errors": [],
            "result": [{ "id": "acct-1", "name": "Acme" }],
            "result_info": { "page": 1, "total_pages": 1 },
        })))
        .expect(1)
        .mount(&server)
        .await;
    let detail = cloudflare::check("cf", &config()).await.unwrap();
    assert!(detail.contains("1 account(s)"), "{detail}");
    assert_eq!(stored().unwrap()["refresh_token"], "refresh-2");
}

#[tokio::test]
async fn revoking_ends_both_tokens_at_cloudflare() {
    let (_scratch, _serial, server) = setup().await;
    assert!(!cloudflare_oauth::revoke("cf", &config()).await.unwrap());
    signed_in("access-1", "refresh-1", SignedDuration::from_hours(1));
    Mock::given(method("POST"))
        .and(path("/oauth2/revoke"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&server)
        .await;
    assert!(cloudflare_oauth::revoke("cf", &config()).await.unwrap());
    let requests = server.received_requests().await.unwrap();
    let revoked: Vec<_> = requests
        .iter()
        .map(|r| {
            let f = form(&r.body);
            (f["token_type_hint"].clone(), f["token"].clone())
        })
        .collect();
    assert_eq!(
        revoked,
        [
            ("refresh_token".to_string(), "refresh-1".to_string()),
            ("access_token".to_string(), "access-1".to_string()),
        ]
    );
}
