//! IAM Identity Center sign-in, renewal and portal calls against a mock of
//! the OIDC and portal APIs. Secrets go to an in-memory store, never the
//! keychain.

use std::collections::HashMap;
use std::io::{Read, Write};

use omnifob_core::config::{AwsSsoConfig, Config, Integration};
use omnifob_core::providers::aws_sso::{self, Flow};
use omnifob_core::{Error, store};
use serde_json::{Value, json};
use tokio::sync::{Mutex, MutexGuard};
use wiremock::matchers::{body_partial_json, body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// The tests share environment variables, so they run one at a time.
static SERIAL: Mutex<()> = Mutex::const_new(());

const START_URL: &str = "https://acme.awsapps.com/start";

async fn setup() -> (MutexGuard<'static, ()>, MockServer) {
    let guard = SERIAL.lock().await;
    store::use_memory_store().unwrap();
    omnifob_core::prompt::set_mfa_prompt(|_| Ok("123456".to_string()));
    let server = MockServer::start().await;
    let state = std::env::temp_dir().join(format!("omnifob-aws-test-{}", std::process::id()));
    // SAFETY: the tests run one at a time under SERIAL, and nothing else in
    // this process reads the environment concurrently.
    unsafe {
        std::env::set_var("OMNIFOB_AWS_ENDPOINT", server.uri());
        std::env::set_var("XDG_STATE_HOME", &state);
    }
    (guard, server)
}

fn config() -> AwsSsoConfig {
    let text = format!(
        r#"
        [integrations.acme]
        type = "aws-sso"
        start_url = "{START_URL}"
        region = "eu-west-1"
        "#
    );
    match Config::parse(&text)
        .unwrap()
        .integrations
        .remove("acme")
        .unwrap()
    {
        Integration::AwsSso(c) => c,
        _ => unreachable!(),
    }
}

fn registration() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "clientId": "client-1",
        "clientSecret": "secret-1",
        "clientIdIssuedAt": 1_700_000_000,
        "clientSecretExpiresAt": 4_102_444_800i64, // 2100
    }))
}

fn token(access: &str, refresh: &str, expires_in: i64) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "accessToken": access,
        "tokenType": "Bearer",
        "expiresIn": expires_in,
        "refreshToken": refresh,
    }))
}

fn aws_error(status: u16, kind: &str) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("x-amzn-errortype", kind)
        .set_body_json(json!({ "message": kind }))
}

fn role_credentials() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "roleCredentials": {
            "accessKeyId": "AKIAEXAMPLE",
            "secretAccessKey": "secret",
            "sessionToken": "session",
            "expiration": 4_102_444_800_000i64,
        }
    }))
}

fn body(request: &Request) -> Value {
    serde_json::from_slice(&request.body).unwrap()
}

/// Signs in with the device flow, the access token valid for `expires_in`.
async fn device_login(server: &MockServer, integration: &str, expires_in: i64) {
    Mock::given(method("POST"))
        .and(path("/client/register"))
        .respond_with(registration())
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/device_authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "deviceCode": "device-1",
            "userCode": "ABCD-EFGH",
            "verificationUri": "https://device.example/",
            "verificationUriComplete": "https://device.example/?code=ABCD-EFGH",
            "expiresIn": 600,
            "interval": 1,
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            json!({ "grantType": "urn:ietf:params:oauth:grant-type:device_code" }),
        ))
        .respond_with(token("a1", "r1", expires_in))
        .mount(server)
        .await;
    aws_sso::login(integration, &config(), Flow::DeviceCode, |_| {})
        .await
        .unwrap();
}

#[tokio::test]
async fn device_sign_in_reuses_the_client_registration() {
    let (_guard, server) = setup().await;
    device_login(&server, "device", 3600).await;
    aws_sso::login("device", &config(), Flow::DeviceCode, |prompt| {
        assert_eq!(prompt.user_code.as_deref(), Some("ABCD-EFGH"));
    })
    .await
    .unwrap();

    let requests = server.received_requests().await.unwrap();
    let registers: Vec<_> = requests
        .iter()
        .filter(|r| r.url.path() == "/client/register")
        .collect();
    assert_eq!(registers.len(), 1, "the second sign-in registers again");
    let registered = body(registers[0]);
    assert_eq!(registered["scopes"], json!(["sso:account:access"]));
    assert!(registered.get("grantTypes").is_none(), "{registered}");
    assert!(
        aws_sso::session("device").unwrap().unwrap().1,
        "refreshable"
    );
}

#[tokio::test]
async fn browser_sign_in_uses_pkce_and_a_loopback_redirect() {
    let (_guard, server) = setup().await;
    Mock::given(method("POST"))
        .and(path("/client/register"))
        .respond_with(registration())
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            json!({ "grantType": "authorization_code" }),
        ))
        .respond_with(token("a1", "r1", 3600))
        .expect(1)
        .mount(&server)
        .await;

    let browser = std::sync::Arc::new(std::sync::Mutex::new(None));
    let opened = browser.clone();
    aws_sso::login("browser", &config(), Flow::Browser, move |prompt| {
        assert!(prompt.user_code.is_none());
        let url = reqwest::Url::parse(&prompt.url).unwrap();
        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
        let redirect = reqwest::Url::parse(&query["redirect_uri"]).unwrap();
        let (state, challenge) = (query["state"].clone(), query["code_challenge"].clone());
        assert_eq!(url.path(), "/authorize");
        assert_eq!(query["scopes"], "sso:account:access");
        assert_eq!(query["code_challenge_method"], "S256");
        // The browser approves and Identity Center redirects back.
        *opened.lock().unwrap() = Some((query["redirect_uri"].clone(), challenge));
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
    })
    .await
    .unwrap();

    let (redirect_uri, challenge) = browser.lock().unwrap().clone().unwrap();
    let requests = server.received_requests().await.unwrap();
    let registered = body(
        requests
            .iter()
            .find(|r| r.url.path() == "/client/register")
            .unwrap(),
    );
    assert_eq!(
        registered["grantTypes"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(
        registered["redirectUris"],
        json!(["http://127.0.0.1/oauth/callback"])
    );
    assert_eq!(registered["issuerUrl"], START_URL);

    let exchanged = body(requests.iter().find(|r| r.url.path() == "/token").unwrap());
    assert_eq!(exchanged["code"], "code-1");
    assert_eq!(exchanged["redirectUri"], redirect_uri.as_str());
    let verifier = exchanged["codeVerifier"].as_str().unwrap();
    assert_eq!(omnifob_core::oauth::challenge(verifier), challenge);
}

#[tokio::test]
async fn concurrent_callers_refresh_an_expiring_session_once() {
    let (_guard, server) = setup().await;
    // Inside the 15-minute window: the next use refreshes.
    device_login(&server, "race", 300).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            json!({ "grantType": "refresh_token", "refreshToken": "r1" }),
        ))
        .respond_with(token("a2", "r2", 3600))
        .expect(1)
        .mount(&server)
        .await;
    // A second refresh would spend r1 again; Identity Center refuses that.
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(json!({ "grantType": "refresh_token" })))
        .respond_with(aws_error(400, "InvalidGrantException"))
        .with_priority(10)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/federation/credentials"))
        .and(header("x-amz-sso_bearer_token", "a2"))
        .respond_with(role_credentials())
        .expect(8)
        .mount(&server)
        .await;

    let config = config();
    let calls = (0..8).map(|_| aws_sso::credentials("race", &config, "111111111111", "Admin"));
    for result in futures::future::join_all(calls).await {
        let creds = result.unwrap();
        assert_eq!(creds.env["AWS_ACCESS_KEY_ID"], "AKIAEXAMPLE");
    }
}

#[tokio::test]
async fn a_refused_token_is_renewed_and_the_call_retried() {
    let (_guard, server) = setup().await;
    device_login(&server, "revoked", 3600).await;
    Mock::given(method("GET"))
        .and(path("/federation/credentials"))
        .and(header("x-amz-sso_bearer_token", "a1"))
        .respond_with(aws_error(401, "UnauthorizedException"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(json!({ "grantType": "refresh_token" })))
        .respond_with(token("a2", "r2", 3600))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/federation/credentials"))
        .and(header("x-amz-sso_bearer_token", "a2"))
        .respond_with(role_credentials())
        .expect(1)
        .mount(&server)
        .await;

    aws_sso::credentials("revoked", &config(), "111111111111", "Admin")
        .await
        .unwrap();
}

#[tokio::test]
async fn an_ended_session_asks_for_sign_in_and_is_forgotten() {
    let (_guard, server) = setup().await;
    device_login(&server, "ended", 3600).await;
    Mock::given(method("GET"))
        .and(path("/federation/credentials"))
        .respond_with(aws_error(401, "UnauthorizedException"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(json!({ "grantType": "refresh_token" })))
        .respond_with(aws_error(400, "InvalidGrantException"))
        .mount(&server)
        .await;

    let err = aws_sso::credentials("ended", &config(), "111111111111", "Admin")
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NeedsLogin { .. }), "{err}");
    assert!(aws_sso::session("ended").unwrap().is_none());
}

#[tokio::test]
async fn discovery_lists_every_account_and_role() {
    let (_guard, server) = setup().await;
    device_login(&server, "discover", 3600).await;
    Mock::given(method("GET"))
        .and(path("/assignment/accounts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accountList": [
                { "accountId": "111111111111", "accountName": "Prod" },
                { "accountId": "222222222222", "accountName": "Dev" },
            ]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/assignment/roles"))
        .respond_with(|r: &Request| {
            let account = r
                .url
                .query_pairs()
                .find(|(k, _)| k == "account_id")
                .unwrap()
                .1
                .into_owned();
            ResponseTemplate::new(200).set_body_json(json!({
                "roleList": [
                    { "roleName": "Admin", "accountId": account },
                    { "roleName": "ReadOnly", "accountId": account },
                ]
            }))
        })
        .mount(&server)
        .await;

    let profiles = aws_sso::discover("discover", &config()).await.unwrap();
    let ids: Vec<_> = profiles.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "discover/dev/Admin",
            "discover/dev/ReadOnly",
            "discover/prod/Admin",
            "discover/prod/ReadOnly"
        ]
    );
}

#[tokio::test]
async fn signing_out_ends_the_portal_session() {
    let (_guard, server) = setup().await;
    device_login(&server, "logout", 3600).await;
    Mock::given(method("POST"))
        .and(path("/logout"))
        .and(header("x-amz-sso_bearer_token", "a1"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    assert!(aws_sso::end_session("logout", &config()).await.unwrap());
    assert!(aws_sso::logout("logout").unwrap());
    assert!(aws_sso::session("logout").unwrap().is_none());
}

#[tokio::test]
async fn a_new_assignment_is_retried_until_it_applies() {
    let (_guard, server) = setup().await;
    device_login(&server, "fresh", 3600).await;
    Mock::given(method("GET"))
        .and(path("/federation/credentials"))
        .respond_with(aws_error(403, "ForbiddenException"))
        .up_to_n_times(2)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/federation/credentials"))
        .respond_with(role_credentials())
        .expect(1)
        .mount(&server)
        .await;

    aws_sso::credentials("fresh", &config(), "111111111111", "Admin")
        .await
        .unwrap();
}

#[tokio::test]
async fn a_lasting_403_says_there_is_no_access() {
    let (_guard, server) = setup().await;
    device_login(&server, "denied", 3600).await;
    Mock::given(method("GET"))
        .and(path("/federation/credentials"))
        .respond_with(aws_error(403, "ForbiddenException"))
        .expect(3)
        .mount(&server)
        .await;

    let err = aws_sso::credentials("denied", &config(), "111111111111", "Admin")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("no access to Admin"), "{err}");
}

fn sts_credentials(action: &str, access_key: &str) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("content-type", "text/xml")
        .set_body_string(format!(
            r#"<{action}Response xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><{action}Result><Credentials><AccessKeyId>{access_key}</AccessKeyId><SecretAccessKey>s</SecretAccessKey><SessionToken>t</SessionToken><Expiration>2100-01-01T00:00:00Z</Expiration></Credentials><AssumedRoleUser><AssumedRoleId>AROA:omnifob</AssumedRoleId><Arn>arn:aws:sts::222222222222:assumed-role/Deploy/omnifob</Arn></AssumedRoleUser></{action}Result><ResponseMetadata><RequestId>1</RequestId></ResponseMetadata></{action}Response>"#
        ))
}

#[tokio::test]
async fn chained_roles_send_the_mfa_code_and_duration() {
    let (_guard, server) = setup().await;
    device_login(&server, "chain", 3600).await;
    Mock::given(method("GET"))
        .and(path("/federation/credentials"))
        .respond_with(role_credentials())
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("Action=AssumeRole"))
        .and(body_string_contains(
            "SerialNumber=arn%3Aaws%3Aiam%3A%3A111111111111%3Amfa%2Fme",
        ))
        .and(body_string_contains("TokenCode=123456"))
        .and(body_string_contains("DurationSeconds=1800"))
        .respond_with(sts_credentials("AssumeRole", "ASIACHAINED"))
        .expect(1)
        .mount(&server)
        .await;

    let text = format!(
        r#"
        [integrations.chain]
        type = "aws-sso"
        start_url = "{START_URL}"
        region = "eu-west-1"
        [integrations.chain.chained.prod]
        via_account_id = "111111111111"
        via_role = "Admin"
        role_arn = "arn:aws:iam::222222222222:role/Deploy"
        mfa_serial = "arn:aws:iam::111111111111:mfa/me"
        duration = "30m"
        "#
    );
    let Integration::AwsSso(config) = Config::parse(&text)
        .unwrap()
        .integrations
        .remove("chain")
        .unwrap()
    else {
        unreachable!()
    };
    let creds = aws_sso::chained_credentials("chain", &config, "prod", "chain/prod/Deploy", None)
        .await
        .unwrap();
    assert_eq!(creds.env["AWS_ACCESS_KEY_ID"], "ASIACHAINED");
    assert!(
        !creds.env.contains_key("AWS_REGION"),
        "no region configured"
    );

    let err = aws_sso::chained_credentials(
        "chain",
        &config,
        "prod",
        "chain/prod/Deploy",
        Some(jiff::SignedDuration::from_hours(2)),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("1 hour"), "{err}");
}
