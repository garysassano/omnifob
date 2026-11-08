//! Google sign-in, renewal, discovery and impersonation against a mock of
//! Google's OAuth, Resource Manager and IAM Credentials APIs. Secrets go to
//! an in-memory store, never the keychain.

use std::collections::HashMap;
use std::io::{Read, Write};

use base64::Engine;
use omnifob_core::config::{Config, GcpConfig, Integration};
use omnifob_core::providers::gcp;
use omnifob_core::{Error, Target, store};
use serde_json::json;
use tokio::sync::{Mutex, MutexGuard};
use wiremock::matchers::{
    body_partial_json, body_string_contains, header, method, path, query_param,
};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The tests share environment variables, so they run one at a time.
static SERIAL: Mutex<()> = Mutex::const_new(());

async fn setup() -> (MutexGuard<'static, ()>, MockServer) {
    let guard = SERIAL.lock().await;
    store::use_memory_store().unwrap();
    let server = MockServer::start().await;
    let state = std::env::temp_dir().join(format!("omnifob-gcp-test-{}", std::process::id()));
    // SAFETY: the tests run one at a time under SERIAL, and nothing else in
    // this process reads the environment concurrently.
    unsafe {
        std::env::set_var("OMNIFOB_GOOGLE_ENDPOINT", server.uri());
        std::env::set_var("XDG_STATE_HOME", &state);
    }
    (guard, server)
}

fn gcp_config(extra: &str) -> GcpConfig {
    let text = format!(
        r#"
        [integrations.g]
        type = "gcp"
        {extra}

        [integrations.g.service_accounts.deploy]
        email = "deploy@proj-b.iam.gserviceaccount.com"
        lifetime = "2h"
        delegates = ["hop@proj-a.iam.gserviceaccount.com"]
        "#
    );
    match Config::parse(&text)
        .unwrap()
        .integrations
        .remove("g")
        .unwrap()
    {
        Integration::Gcp(c) => c,
        _ => unreachable!(),
    }
}

fn id_token(email: &str) -> String {
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(json!({ "email": email, "sub": "1" }).to_string());
    format!("h.{payload}.s")
}

fn form(body: &[u8]) -> HashMap<String, String> {
    url_pairs(std::str::from_utf8(body).unwrap())
}

fn url_pairs(query: &str) -> HashMap<String, String> {
    reqwest::Url::parse(&format!("http://x/?{query}"))
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

async fn mock_code_exchange(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=authorization_code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "user-access-1",
            "expires_in": 3599,
            "refresh_token": "refresh-1",
            "id_token": id_token("me@example.com"),
            "scope": "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/cloud-platform",
            "token_type": "Bearer",
        })))
        .mount(server)
        .await;
}

/// Signs in through the browser flow, answering the consent page the way a
/// browser would; returns the authorize URL's query.
async fn browser_login(
    server: &MockServer,
    integration: &str,
    config: &GcpConfig,
) -> HashMap<String, String> {
    mock_code_exchange(server).await;
    let opened = std::sync::Arc::new(std::sync::Mutex::new(None));
    let seen = opened.clone();
    let email = gcp::login(
        integration,
        config,
        true,
        move |url| {
            let url = reqwest::Url::parse(url).unwrap();
            let query = url_pairs(url.query().unwrap());
            let redirect = reqwest::Url::parse(&query["redirect_uri"]).unwrap();
            let state = query["state"].clone();
            *seen.lock().unwrap() = Some(query);
            std::thread::spawn(move || {
                let mut s =
                    std::net::TcpStream::connect(("127.0.0.1", redirect.port().unwrap())).unwrap();
                write!(
                    s,
                    "GET /?state={state}&code=code-1&scope=x HTTP/1.1\r\nHost: x\r\n\r\n"
                )
                .unwrap();
                let mut reply = String::new();
                s.read_to_string(&mut reply).unwrap();
                assert!(reply.contains("Signed in to Google"), "{reply}");
            });
        },
        || unreachable!("the browser flow pastes nothing"),
    )
    .await
    .unwrap();
    assert_eq!(email, "me@example.com");
    opened.lock().unwrap().take().unwrap()
}

#[tokio::test]
async fn browser_sign_in_follows_gcloud() {
    let (_guard, server) = setup().await;
    let config = gcp_config("");
    let query = browser_login(&server, "g", &config).await;
    assert_eq!(query["client_id"], "32555940559.apps.googleusercontent.com");
    assert!(query["redirect_uri"].starts_with("http://localhost:"));
    assert!(query["redirect_uri"].ends_with('/'));
    assert_eq!(query["access_type"], "offline");

    let requests = server.received_requests().await.unwrap();
    let exchanged = form(&requests.last().unwrap().body);
    assert_eq!(exchanged["code"], "code-1");
    assert_eq!(exchanged["redirect_uri"], query["redirect_uri"]);
    assert_eq!(exchanged["client_secret"], "ZmssLNjJy2998hD4CTg2ejr2");
    assert_eq!(
        omnifob_core::oauth::challenge(&exchanged["code_verifier"]),
        query["code_challenge"]
    );
    assert!(gcp::is_signed_in("g").unwrap());
    assert_eq!(
        gcp::account("g").unwrap().as_deref(),
        Some("me@example.com")
    );
}

#[tokio::test]
async fn sign_in_from_another_device_pastes_the_code() {
    let (_guard, server) = setup().await;
    let config = gcp_config("");
    mock_code_exchange(&server).await;
    let shown = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let seen = shown.clone();
    gcp::login(
        "remote",
        &config,
        false,
        move |url| *seen.lock().unwrap() = url.to_string(),
        || Ok(" pasted-code \n".to_string()),
    )
    .await
    .unwrap();
    let url = reqwest::Url::parse(&shown.lock().unwrap()).unwrap();
    let query = url_pairs(url.query().unwrap());
    assert_eq!(
        query["redirect_uri"],
        "https://sdk.cloud.google.com/authcode.html"
    );
    assert_eq!(query["prompt"], "consent");
    assert_eq!(query["token_usage"], "remote");
    let requests = server.received_requests().await.unwrap();
    let exchanged = form(&requests.last().unwrap().body);
    assert_eq!(exchanged["code"], "pasted-code");
    assert_eq!(
        exchanged["redirect_uri"],
        "https://sdk.cloud.google.com/authcode.html"
    );

    // Google's code page serves only its own clients.
    let own = gcp_config(
        r#"client_id = "mine.apps.googleusercontent.com"
        client_secret = "s""#,
    );
    let err = gcp::login("own", &own, false, |_| {}, || Ok("c".into()))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("client_id"), "{err}");
}

#[tokio::test]
async fn discovery_lists_projects_across_pages_and_service_accounts() {
    let (_guard, server) = setup().await;
    let config = gcp_config("");
    browser_login(&server, "g", &config).await;
    Mock::given(method("GET"))
        .and(path("/v1/projects"))
        .and(query_param("pageToken", "p2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "projects": [{ "projectId": "proj-a", "name": "Project A" }],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/projects"))
        .and(header("authorization", "Bearer user-access-1"))
        .and(query_param("filter", "lifecycleState:ACTIVE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "projects": [{ "projectId": "proj-c", "name": "C" }],
            "nextPageToken": "p2",
        })))
        .mount(&server)
        .await;

    let profiles = gcp::discover("g", &config).await.unwrap();
    let ids: Vec<_> = profiles.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids, ["g/proj-a/user", "g/proj-c/user", "g/deploy/deploy"]);
    assert_eq!(
        profiles[0].target,
        Target::Gcp {
            project_id: "proj-a".into(),
            project_name: "Project A".into()
        }
    );
    assert_eq!(
        profiles[2].target,
        Target::GcpServiceAccount {
            label: "deploy".into(),
            project_id: Some("proj-b".into())
        }
    );

    // Listed projects skip the API.
    let listed = config_with_projects();
    let profiles = gcp::discover("g", &listed).await.unwrap();
    assert_eq!(profiles[0].id, "g/only-this/user");
}

fn config_with_projects() -> GcpConfig {
    gcp_config(r#"projects = ["only-this"]"#)
}

#[tokio::test]
async fn credentials_carry_a_token_and_the_project() {
    let (_guard, server) = setup().await;
    let config = gcp_config("");
    browser_login(&server, "g", &config).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("refresh_token=refresh-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "user-access-2",
            "expires_in": 3599,
        })))
        .mount(&server)
        .await;
    let creds = gcp::user_credentials("g", &config, "proj-a").await.unwrap();
    assert_eq!(creds.env["CLOUDSDK_AUTH_ACCESS_TOKEN"], "user-access-2");
    assert_eq!(creds.env["GOOGLE_OAUTH_ACCESS_TOKEN"], "user-access-2");
    assert_eq!(creds.env["CLOUDSDK_CORE_PROJECT"], "proj-a");
    assert_eq!(creds.env["GOOGLE_CLOUD_PROJECT"], "proj-a");
    assert!(creds.expires_at.is_some());

    Mock::given(method("POST"))
        .and(path(
            "/v1/projects/-/serviceAccounts/deploy@proj-b.iam.gserviceaccount.com:generateAccessToken",
        ))
        .and(header("authorization", "Bearer user-access-2"))
        .and(body_partial_json(json!({
            "lifetime": "7200s",
            "delegates": ["projects/-/serviceAccounts/hop@proj-a.iam.gserviceaccount.com"],
            "scope": [
                "https://www.googleapis.com/auth/cloud-platform",
                "https://www.googleapis.com/auth/userinfo.email",
            ],
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accessToken": "sa-token",
            "expireTime": "2100-01-01T00:00:00Z",
        })))
        .expect(1)
        .mount(&server)
        .await;
    let sa = gcp::service_account_credentials("g", &config, "deploy", None)
        .await
        .unwrap();
    assert_eq!(sa.env["CLOUDSDK_AUTH_ACCESS_TOKEN"], "sa-token");
    assert_eq!(sa.env["CLOUDSDK_CORE_PROJECT"], "proj-b");
    assert_eq!(sa.expires_at, Some("2100-01-01T00:00:00Z".parse().unwrap()));

    let err = gcp::service_account_credentials(
        "g",
        &config,
        "deploy",
        Some(jiff::SignedDuration::from_hours(13)),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("12 hours"), "{err}");
}

#[tokio::test]
async fn impersonation_refused_names_the_role_it_needs() {
    let (_guard, server) = setup().await;
    let config = gcp_config("");
    browser_login(&server, "g", &config).await;
    Mock::given(method("POST"))
        .and(path(
            "/v1/projects/-/serviceAccounts/deploy@proj-b.iam.gserviceaccount.com:generateAccessToken",
        ))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": { "code": 403, "status": "PERMISSION_DENIED" }
        })))
        .mount(&server)
        .await;
    let err = gcp::service_account_credentials("g", &config, "deploy", None)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("Token Creator"), "{err}");
}

#[tokio::test]
async fn session_control_asks_for_a_new_sign_in() {
    let (_guard, server) = setup().await;
    let config = gcp_config("");
    browser_login(&server, "g", &config).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "reauth related error (invalid_rapt)",
            "error_subtype": "invalid_rapt",
        })))
        .mount(&server)
        .await;
    match gcp::user_credentials("g", &config, "proj-a").await {
        Err(Error::NeedsLogin { reason, .. }) => {
            assert!(reason.contains("session control"), "{reason}")
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn logout_revokes_the_refresh_token() {
    let (_guard, server) = setup().await;
    let config = gcp_config("");
    browser_login(&server, "g", &config).await;
    Mock::given(method("POST"))
        .and(path("/revoke"))
        .and(body_string_contains("token=refresh-1"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    assert!(gcp::end_session("g").await.unwrap());
    assert!(gcp::logout("g").unwrap());
    assert!(!gcp::is_signed_in("g").unwrap());
    assert!(!gcp::end_session("g").await.unwrap());
}

#[test]
fn config_checks() {
    let bad = |text: &str| format!("{:#}", Config::parse(text).unwrap_err());
    assert!(
        bad(r#"
            [integrations.g]
            type = "gcp"
            client_id = "x"
            "#)
        .contains("client_secret")
    );
    assert!(
        bad(r#"
            [integrations.g]
            type = "gcp"
            [integrations.g.service_accounts.x]
            email = "x@p.iam.gserviceaccount.com"
            lifetime = "13h"
            "#)
        .contains("12h")
    );
}
