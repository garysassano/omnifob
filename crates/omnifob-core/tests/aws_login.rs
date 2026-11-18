//! AWS console sign-in (`aws login`) against a mock of AWS Sign-In. Secrets
//! go to an in-memory store, never the keychain.

use std::collections::HashMap;
use std::io::{Read, Write};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use omnifob_core::config::{AwsLoginConfig, Config, Integration};
use omnifob_core::providers::aws_login;
use omnifob_core::{Error, Target, store};
use serde_json::{Value, json};
use tokio::sync::{Mutex, MutexGuard};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// The tests share environment variables, so they run one at a time.
static SERIAL: Mutex<()> = Mutex::const_new(());

const IDENTITY: &str = "arn:aws:iam::123456789012:user/alice";

async fn setup() -> (MutexGuard<'static, ()>, MockServer) {
    let guard = SERIAL.lock().await;
    store::use_memory_store().unwrap();
    let server = MockServer::start().await;
    let state = std::env::temp_dir().join(format!("omnifob-login-test-{}", std::process::id()));
    // SAFETY: the tests run one at a time under SERIAL, and nothing else in
    // this process reads the environment concurrently.
    unsafe {
        std::env::set_var("OMNIFOB_AWS_ENDPOINT", server.uri());
        std::env::set_var("XDG_STATE_HOME", &state);
    }
    (guard, server)
}

fn config() -> AwsLoginConfig {
    let text = r#"
        [integrations.console]
        type = "aws-login"
        region = "eu-west-1"
        default_region = "eu-central-1"
    "#;
    match Config::parse(text)
        .unwrap()
        .integrations
        .remove("console")
        .unwrap()
    {
        Integration::AwsLogin(c) => c,
        _ => unreachable!(),
    }
}

/// An unsigned JWT whose `sub` is `sub`.
fn id_token(sub: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
    let claims = URL_SAFE_NO_PAD.encode(json!({ "sub": sub }).to_string());
    format!("{header}.{claims}.")
}

fn token(access_key: &str, refresh: &str, expires_in: i64) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "accessToken": {
            "accessKeyId": access_key,
            "secretAccessKey": "secret",
            "sessionToken": "session",
        },
        "tokenType": "aws_sigv4",
        "expiresIn": expires_in,
        "refreshToken": refresh,
        "idToken": id_token(IDENTITY),
    }))
}

fn refusal(status: u16, kind: &str, error: &str) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("x-amzn-errortype", kind)
        .set_body_json(json!({ "error": error, "message": error }))
}

fn body(request: &Request) -> Value {
    serde_json::from_slice(&request.body).unwrap()
}

/// The claims of the request's DPoP proof, after checking its header.
fn dpop_claims(request: &Request) -> Value {
    let proof = request
        .headers
        .get("dpop")
        .expect("a DPoP proof")
        .to_str()
        .unwrap();
    let parts: Vec<&str> = proof.split('.').collect();
    assert_eq!(parts.len(), 3, "{proof}");
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    assert_eq!(header["typ"], "dpop+jwt");
    assert_eq!(header["alg"], "ES256");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap()
}

/// The public key a proof carries, which must stay the same for a session.
fn dpop_key(request: &Request) -> String {
    let proof = request.headers.get("dpop").unwrap().to_str().unwrap();
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(proof.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    header["jwk"].to_string()
}

/// Signs in with a browser on this machine, the credentials valid for
/// `expires_in` seconds.
async fn browser_login(server: &MockServer, integration: &str, expires_in: i64) {
    Mock::given(method("POST"))
        .and(path("/v1/token"))
        .and(body_partial_json(
            json!({ "grantType": "authorization_code" }),
        ))
        .respond_with(token("ASIAFIRST", "refresh-1", expires_in))
        .expect(1)
        .mount(server)
        .await;
    let identity = aws_login::login(
        integration,
        &config(),
        true,
        |url| {
            let url = reqwest::Url::parse(url).unwrap();
            let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
            assert_eq!(url.path(), "/v1/authorize");
            assert_eq!(query["client_id"], "arn:aws:signin:::devtools/same-device");
            assert_eq!(query["code_challenge_method"], "SHA-256");
            assert_eq!(query["scope"], "openid");
            let redirect = reqwest::Url::parse(&query["redirect_uri"]).unwrap();
            assert_eq!(redirect.path(), "/oauth/callback");
            let state = query["state"].clone();
            // The browser signs in and AWS Sign-In redirects back.
            std::thread::spawn(move || {
                let mut s =
                    std::net::TcpStream::connect(("127.0.0.1", redirect.port().unwrap())).unwrap();
                write!(
                    s,
                    "GET /oauth/callback?code=code-1&state={state} HTTP/1.1\r\nHost: x\r\n\r\n"
                )
                .unwrap();
                let mut reply = String::new();
                s.read_to_string(&mut reply).unwrap();
            });
        },
        || unreachable!("nothing is pasted with a browser here"),
    )
    .await
    .unwrap();
    assert_eq!(identity, IDENTITY);
}

#[tokio::test]
async fn browser_sign_in_redeems_the_code_with_a_dpop_proof() {
    let (_guard, server) = setup().await;
    browser_login(&server, "browser", 900).await;

    let requests = server.received_requests().await.unwrap();
    let exchange = &requests[0];
    let sent = body(exchange);
    assert_eq!(sent["clientId"], "arn:aws:signin:::devtools/same-device");
    assert_eq!(sent["code"], "code-1");
    assert!(sent["codeVerifier"].as_str().unwrap().len() >= 43);
    assert!(
        sent["redirectUri"]
            .as_str()
            .unwrap()
            .ends_with("/oauth/callback")
    );
    let claims = dpop_claims(exchange);
    assert_eq!(claims["htm"], "POST");
    assert_eq!(claims["htu"], format!("{}/v1/token", server.uri()));

    let profiles = aws_login::discover("browser", &config()).unwrap();
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].id, "browser/123456789012/alice");
    assert_eq!(
        profiles[0].target,
        Target::AwsLogin {
            account_id: "123456789012".into()
        }
    );

    let creds = aws_login::credentials("browser", &config()).await.unwrap();
    assert_eq!(creds.env["AWS_ACCESS_KEY_ID"], "ASIAFIRST");
    assert_eq!(creds.env["AWS_SESSION_TOKEN"], "session");
    assert_eq!(creds.env["AWS_REGION"], "eu-central-1");
    // Fresh credentials are handed out without another request.
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_pasted_code_signs_in_from_another_device() {
    let (_guard, server) = setup().await;
    Mock::given(method("POST"))
        .and(path("/v1/token"))
        .and(body_partial_json(json!({
            "grantType": "authorization_code",
            "clientId": "arn:aws:signin:::devtools/cross-device",
            "code": "code-2",
        })))
        .respond_with(token("ASIAREMOTE", "refresh-1", 900))
        .expect(1)
        .mount(&server)
        .await;
    let state = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let shown = state.clone();
    aws_login::login(
        "remote",
        &config(),
        false,
        move |url| {
            let url = reqwest::Url::parse(url).unwrap();
            let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
            assert_eq!(
                query["redirect_uri"],
                format!(
                    "{}/v1/sessions/confirmation",
                    url.origin().ascii_serialization()
                )
            );
            *shown.lock().unwrap() = query["state"].clone();
        },
        move || {
            let state = state.lock().unwrap().clone();
            Ok(STANDARD.encode(format!("state={state}&code=code-2")))
        },
    )
    .await
    .unwrap();
    let creds = aws_login::credentials("remote", &config()).await.unwrap();
    assert_eq!(creds.env["AWS_ACCESS_KEY_ID"], "ASIAREMOTE");
}

#[tokio::test]
async fn expiring_credentials_are_renewed_with_the_same_key() {
    let (_guard, server) = setup().await;
    // Inside the five-minute window: the next use renews.
    browser_login(&server, "renew", 120).await;
    Mock::given(method("POST"))
        .and(path("/v1/token"))
        .and(body_partial_json(json!({
            "grantType": "refresh_token",
            "refreshToken": "refresh-1",
            "clientId": "arn:aws:signin:::devtools/same-device",
        })))
        .respond_with(token("ASIASECOND", "refresh-2", 900))
        .expect(1)
        .mount(&server)
        .await;

    let creds = aws_login::credentials("renew", &config()).await.unwrap();
    assert_eq!(creds.env["AWS_ACCESS_KEY_ID"], "ASIASECOND");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(dpop_key(&requests[0]), dpop_key(&requests[1]));
    // The new refresh token replaced the old one.
    Mock::given(method("POST"))
        .and(path("/v1/token"))
        .and(body_partial_json(json!({ "refreshToken": "refresh-2" })))
        .respond_with(token("ASIATHIRD", "refresh-3", 900))
        .mount(&server)
        .await;
    let creds = aws_login::credentials("renew", &config()).await.unwrap();
    assert_eq!(creds.env["AWS_ACCESS_KEY_ID"], "ASIASECOND", "still fresh");
}

#[tokio::test]
async fn an_ended_sign_in_asks_for_a_new_one_and_is_forgotten() {
    let (_guard, server) = setup().await;
    browser_login(&server, "ended", 0).await;
    Mock::given(method("POST"))
        .and(path("/v1/token"))
        .and(body_partial_json(json!({ "grantType": "refresh_token" })))
        .respond_with(refusal(401, "AccessDeniedException", "TOKEN_EXPIRED"))
        .mount(&server)
        .await;

    let err = aws_login::credentials("ended", &config())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NeedsLogin { .. }), "{err}");
    assert!(err.to_string().contains("has ended"), "{err}");
    assert!(aws_login::session("ended").unwrap().is_none(), "forgotten");
}

#[tokio::test]
async fn a_server_error_during_renewal_keeps_the_sign_in() {
    let (_guard, server) = setup().await;
    browser_login(&server, "outage", 0).await;
    Mock::given(method("POST"))
        .and(path("/v1/token"))
        .and(body_partial_json(json!({ "grantType": "refresh_token" })))
        .respond_with(refusal(500, "InternalServerException", "server_error"))
        .mount(&server)
        .await;

    let err = aws_login::credentials("outage", &config())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Other(_)), "{err}");
    assert!(
        format!("{err:#}").contains("could not renew the sign-in for 'outage'"),
        "{err:#}"
    );
    assert!(aws_login::session("outage").unwrap().is_some(), "kept");
}

#[tokio::test]
async fn missing_permissions_are_named() {
    let (_guard, server) = setup().await;
    Mock::given(method("POST"))
        .and(path("/v1/token"))
        .respond_with(refusal(
            403,
            "AccessDeniedException",
            "INSUFFICIENT_PERMISSIONS",
        ))
        .mount(&server)
        .await;
    let err = aws_login::login(
        "denied",
        &config(),
        false,
        |_| {},
        || Ok(STANDARD.encode("state=wrong&code=c")),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("another sign-in"), "{err}");

    let state = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let shown = state.clone();
    let err = aws_login::login(
        "denied",
        &config(),
        false,
        move |url| {
            let url = reqwest::Url::parse(url).unwrap();
            *shown.lock().unwrap() = url
                .query_pairs()
                .find(|(k, _)| k == "state")
                .unwrap()
                .1
                .into_owned();
        },
        move || {
            let state = state.lock().unwrap().clone();
            Ok(STANDARD.encode(format!("state={state}&code=c")))
        },
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("SignInLocalDevelopmentAccess"),
        "{err}"
    );
    assert!(aws_login::session("denied").unwrap().is_none());
}
