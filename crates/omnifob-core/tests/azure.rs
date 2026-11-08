//! Entra ID sign-in and Resource Manager discovery against a mock. Secrets go
//! to an in-memory store, never the keychain.

use std::collections::HashMap;
use std::io::{Read, Write};

use base64::Engine;
use omnifob_core::config::{AzureConfig, Config, Integration};
use omnifob_core::providers::azure;
use omnifob_core::{Error, Target, store};
use serde_json::json;
use tokio::sync::{Mutex, MutexGuard};
use wiremock::matchers::{body_string_contains, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The tests share environment variables, so they run one at a time.
static SERIAL: Mutex<()> = Mutex::const_new(());

const HOME: &str = "11111111-1111-1111-1111-111111111111";
const GUEST: &str = "22222222-2222-2222-2222-222222222222";
const LOCKED: &str = "33333333-3333-3333-3333-333333333333";

async fn setup() -> (MutexGuard<'static, ()>, MockServer) {
    let guard = SERIAL.lock().await;
    store::use_memory_store().unwrap();
    let server = MockServer::start().await;
    let state = std::env::temp_dir().join(format!("omnifob-azure-test-{}", std::process::id()));
    // SAFETY: the tests run one at a time under SERIAL, and nothing else in
    // this process reads the environment concurrently.
    unsafe {
        std::env::set_var("OMNIFOB_AZURE_ENDPOINT", server.uri());
        std::env::set_var("XDG_STATE_HOME", &state);
    }
    (guard, server)
}

fn azure_config(extra: &str) -> AzureConfig {
    let text = format!(
        r#"
        [integrations.work]
        type = "azure"
        {extra}
        "#
    );
    match Config::parse(&text)
        .unwrap()
        .integrations
        .remove("work")
        .unwrap()
    {
        Integration::Azure(c) => c,
        _ => unreachable!(),
    }
}

fn id_token() -> String {
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(json!({ "preferred_username": "me@contoso.com", "tid": HOME }).to_string());
    format!("h.{payload}.s")
}

fn tokens(access: &str, refresh: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "token_type": "Bearer",
        "access_token": access,
        "expires_in": 3599,
        "refresh_token": refresh,
        "id_token": id_token(),
    }))
}

fn url_pairs(query: &str) -> HashMap<String, String> {
    reqwest::Url::parse(&format!("http://x/?{query}"))
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// Signs in with the device flow: pending once, then approved.
async fn device_login(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/organizations/oauth2/v2.0/devicecode"))
        .and(body_string_contains(
            "client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "device_code": "dev-1",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://microsoft.com/devicelogin",
            "expires_in": 60,
            "interval": 0,
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/organizations/oauth2/v2.0/token"))
        .and(body_string_contains("device_code=dev-1"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "authorization_pending",
        })))
        .up_to_n_times(1)
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/organizations/oauth2/v2.0/token"))
        .and(body_string_contains("device_code=dev-1"))
        .respond_with(tokens("home-1", "refresh-1"))
        .mount(server)
        .await;
    let mut shown = None;
    let user = azure::login("work", &azure_config(""), false, |p| {
        shown = Some((p.url.to_string(), p.user_code.map(str::to_string)));
    })
    .await
    .unwrap();
    assert_eq!(user, "me@contoso.com");
    assert_eq!(
        shown,
        Some((
            "https://microsoft.com/devicelogin".to_string(),
            Some("ABCD-EFGH".to_string())
        ))
    );
}

#[tokio::test]
async fn browser_sign_in_follows_az() {
    let (_guard, server) = setup().await;
    Mock::given(method("POST"))
        .and(path("/contoso.onmicrosoft.com/oauth2/v2.0/token"))
        .and(body_string_contains("grant_type=authorization_code"))
        .and(body_string_contains("code=code-1"))
        .respond_with(tokens("home-1", "refresh-1"))
        .expect(1)
        .mount(&server)
        .await;
    let config = azure_config(r#"tenant = "contoso.onmicrosoft.com""#);
    let opened = std::sync::Arc::new(std::sync::Mutex::new(None));
    let seen = opened.clone();
    azure::login("work", &config, true, move |p| {
        let url = reqwest::Url::parse(p.url).unwrap();
        assert_eq!(url.path(), "/contoso.onmicrosoft.com/oauth2/v2.0/authorize");
        let query = url_pairs(url.query().unwrap());
        let redirect = reqwest::Url::parse(&query["redirect_uri"]).unwrap();
        let state = query["state"].clone();
        *seen.lock().unwrap() = Some(query);
        std::thread::spawn(move || {
            let mut s =
                std::net::TcpStream::connect(("127.0.0.1", redirect.port().unwrap())).unwrap();
            write!(
                s,
                "GET /?code=code-1&state={state}&session_state=x HTTP/1.1\r\nHost: x\r\n\r\n"
            )
            .unwrap();
            let mut reply = String::new();
            s.read_to_string(&mut reply).unwrap();
        });
    })
    .await
    .unwrap();
    let query = opened.lock().unwrap().take().unwrap();
    assert_eq!(query["client_id"], "04b07795-8ddb-461a-bbee-02f9e1bf7b46");
    assert!(query["redirect_uri"].starts_with("http://localhost:"));
    assert_eq!(
        query["scope"],
        "https://management.core.windows.net//.default offline_access openid profile"
    );
    assert_eq!(query["prompt"], "select_account");
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(
        azure::account("work").unwrap().as_deref(),
        Some("me@contoso.com")
    );
}

#[tokio::test]
async fn discovery_walks_tenants_and_skips_refusing_ones() {
    let (_guard, server) = setup().await;
    device_login(&server).await;
    // Refresh tokens rotate: each tenant's renewal returns a new one.
    Mock::given(method("POST"))
        .and(path(format!("/{HOME}/oauth2/v2.0/token")))
        .and(body_string_contains("refresh_token=refresh-1"))
        .respond_with(tokens("home-2", "refresh-2"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/{GUEST}/oauth2/v2.0/token")))
        .and(body_string_contains("refresh_token=refresh-2"))
        .respond_with(tokens("guest-1", "refresh-3"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/{LOCKED}/oauth2/v2.0/token")))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "interaction_required",
            "error_description": "AADSTS50076: MFA needed.\r\nTrace ID: x",
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/tenants"))
        .and(header("authorization", "Bearer home-2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{ "tenantId": HOME }, { "tenantId": GUEST }, { "tenantId": LOCKED }],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/subscriptions"))
        .and(query_param("api-version", "2022-12-01"))
        .and(header("authorization", "Bearer home-2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [
                { "subscriptionId": "sub-a", "displayName": "Prod", "state": "Enabled" },
                { "subscriptionId": "sub-off", "displayName": "Old", "state": "Disabled" },
            ],
            "nextLink": format!("{}/subscriptions?api-version=2022-12-01&$skiptoken=2", server.uri()),
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/subscriptions"))
        .and(query_param("$skiptoken", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{ "subscriptionId": "sub-b", "displayName": "Dev Box" }],
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/subscriptions"))
        .and(header("authorization", "Bearer guest-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            // Also reachable from the home tenant: kept once.
            "value": [{ "subscriptionId": "sub-a", "displayName": "Prod" },
                      { "subscriptionId": "sub-c", "displayName": "Partner" }],
        })))
        .mount(&server)
        .await;

    let profiles = azure::discover("work", &azure_config("")).await.unwrap();
    let ids: Vec<_> = profiles.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(
        ids,
        ["work/prod/user", "work/dev-box/user", "work/partner/user"]
    );
    assert_eq!(
        profiles[2].target,
        Target::Azure {
            subscription_id: "sub-c".into(),
            subscription_name: "Partner".into(),
            tenant_id: GUEST.into(),
        }
    );
}

#[tokio::test]
async fn credentials_name_the_subscription_and_tenant() {
    let (_guard, server) = setup().await;
    device_login(&server).await;
    Mock::given(method("POST"))
        .and(path(format!("/{GUEST}/oauth2/v2.0/token")))
        .and(body_string_contains("refresh_token=refresh-1"))
        .respond_with(tokens("guest-1", "refresh-2"))
        .expect(1)
        .mount(&server)
        .await;
    let creds = azure::credentials("work", "sub-c", GUEST).await.unwrap();
    assert_eq!(creds.env["AZURE_ACCESS_TOKEN"], "guest-1");
    assert_eq!(creds.env["AZURE_SUBSCRIPTION_ID"], "sub-c");
    assert_eq!(creds.env["ARM_SUBSCRIPTION_ID"], "sub-c");
    assert_eq!(creds.env["AZURE_TENANT_ID"], GUEST);
    assert_eq!(creds.env["ARM_TENANT_ID"], GUEST);

    // The rotated refresh token is the one used next.
    Mock::given(method("POST"))
        .and(path(format!("/{HOME}/oauth2/v2.0/token")))
        .and(body_string_contains("refresh_token=refresh-2"))
        .respond_with(tokens("home-2", "refresh-3"))
        .expect(1)
        .mount(&server)
        .await;
    azure::credentials("work", "sub-a", HOME).await.unwrap();
}

#[tokio::test]
async fn an_ended_sign_in_asks_for_a_new_one() {
    let (_guard, server) = setup().await;
    device_login(&server).await;
    Mock::given(method("POST"))
        .and(path(format!("/{HOME}/oauth2/v2.0/token")))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "AADSTS700082: The refresh token has expired.",
        })))
        .mount(&server)
        .await;
    match azure::credentials("work", "sub-a", HOME).await {
        Err(Error::NeedsLogin { reason, .. }) => {
            assert!(reason.contains("AADSTS700082"), "{reason}")
        }
        other => panic!("{other:?}"),
    }
    assert!(azure::logout("work").unwrap());
    assert!(!azure::is_signed_in("work").unwrap());
}
