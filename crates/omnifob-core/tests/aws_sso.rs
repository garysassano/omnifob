//! IAM Identity Center sign-in, renewal and portal calls against a mock of
//! the OIDC and portal APIs. Secrets go to an in-memory store, never the
//! keychain.

mod support;

use std::collections::HashMap;
use std::io::{Read, Write};

use omnifob_core::config::{AwsSsoConfig, Config, Integration};
use omnifob_core::providers::aws_sso::{self, Flow};
use omnifob_core::{Error, store};
use serde_json::{Value, json};
use support::Scratch;
use tokio::sync::Mutex;
use wiremock::matchers::{
    body_partial_json, body_string_contains, header, method, path, query_param,
};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// The tests share environment variables, so they run one at a time.
static SERIAL: Mutex<()> = Mutex::const_new(());

const START_URL: &str = "https://acme.awsapps.com/start";

async fn setup() -> (Scratch, MockServer) {
    let guard = SERIAL.lock().await;
    store::use_memory_store().unwrap();
    omnifob_core::prompt::set_mfa_prompt(|_| Ok("123456".to_string()));
    let server = MockServer::start().await;
    // SAFETY: the tests run one at a time under SERIAL, and nothing else in
    // this process reads the environment concurrently.
    unsafe {
        std::env::set_var("OMNIFOB_AWS_ENDPOINT", server.uri());
    }
    (Scratch::new(guard, "omnifob-aws-test"), server)
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
async fn a_server_error_during_renewal_keeps_the_session() {
    let (_guard, server) = setup().await;
    device_login(&server, "outage", 3600).await;
    Mock::given(method("GET"))
        .and(path("/federation/credentials"))
        .respond_with(aws_error(401, "UnauthorizedException"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(json!({ "grantType": "refresh_token" })))
        .respond_with(aws_error(500, "InternalServerException"))
        .mount(&server)
        .await;

    let err = aws_sso::credentials("outage", &config(), "111111111111", "Admin")
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Other(_)), "{err}");
    assert!(
        format!("{err:#}").contains("could not renew the sign-in for 'outage'"),
        "{err:#}"
    );
    assert!(aws_sso::session("outage").unwrap().unwrap().1, "kept");
}

#[tokio::test]
async fn an_expired_token_that_cannot_be_renewed_now_does_not_ask_for_sign_in() {
    let (_guard, server) = setup().await;
    device_login(&server, "offline", 0).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(json!({ "grantType": "refresh_token" })))
        .respond_with(aws_error(429, "SlowDownException"))
        .mount(&server)
        .await;

    let err = aws_sso::credentials("offline", &config(), "111111111111", "Admin")
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Other(_)), "{err}");
    assert!(aws_sso::session("offline").unwrap().is_some(), "kept");
}

#[tokio::test]
async fn an_unreachable_identity_center_keeps_the_session() {
    let (_guard, server) = setup().await;
    device_login(&server, "unreachable", 0).await;
    // Nothing listens on this port once the listener is dropped.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    // SAFETY: the tests run one at a time under SERIAL.
    unsafe { std::env::set_var("OMNIFOB_AWS_ENDPOINT", url) };

    let err = aws_sso::credentials("unreachable", &config(), "111111111111", "Admin")
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Other(_)), "{err}");
    let message = format!("{err:#}");
    assert!(
        message.contains("could not renew the sign-in for 'unreachable'")
            && message.contains("run `fob login unreachable` if this persists"),
        "{message}"
    );
    assert!(aws_sso::session("unreachable").unwrap().is_some(), "kept");
}

#[tokio::test]
async fn a_refused_renewal_keeps_using_a_token_still_valid() {
    let (_guard, server) = setup().await;
    // Inside the 15-minute window: the next use tries to renew.
    device_login(&server, "valid", 300).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(json!({ "grantType": "refresh_token" })))
        .respond_with(aws_error(400, "InvalidGrantException"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/federation/credentials"))
        .and(header("x-amz-sso_bearer_token", "a1"))
        .respond_with(role_credentials())
        .expect(1)
        .mount(&server)
        .await;

    aws_sso::credentials("valid", &config(), "111111111111", "Admin")
        .await
        .unwrap();
    assert!(aws_sso::session("valid").unwrap().is_some(), "kept");
}

/// Identity Center refuses the client with `kind`: the session ends and the
/// next sign-in registers a new client instead of reusing the refused one.
async fn refused_client_is_registered_again(integration: &str, kind: &str) {
    let (_guard, server) = setup().await;
    device_login(&server, integration, 0).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(json!({ "grantType": "refresh_token" })))
        .respond_with(aws_error(400, kind))
        .mount(&server)
        .await;

    let err = aws_sso::credentials(integration, &config(), "111111111111", "Admin")
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NeedsLogin { .. }), "{err}");
    assert!(aws_sso::session(integration).unwrap().is_none());

    device_login(&server, integration, 3600).await;
    let registers = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == "/client/register")
        .count();
    assert_eq!(registers, 2, "the refused client was reused");
}

#[tokio::test]
async fn an_invalid_client_is_registered_again() {
    refused_client_is_registered_again("invalid-client", "InvalidClientException").await;
}

#[tokio::test]
async fn an_unauthorized_client_is_registered_again() {
    refused_client_is_registered_again("unauthorized-client", "UnauthorizedClientException").await;
}

#[tokio::test]
async fn discovery_lists_every_account_and_role() {
    let (_guard, server) = setup().await;
    device_login(&server, "discover", 3600).await;
    Mock::given(method("GET"))
        .and(path("/assignment/accounts"))
        // The largest page each API returns.
        .and(query_param("max_result", "100"))
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
        .and(query_param("max_result", "100"))
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
async fn signing_out_renews_an_expired_token_to_end_the_session() {
    let (_guard, server) = setup().await;
    device_login(&server, "stale", 0).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            json!({ "grantType": "refresh_token", "refreshToken": "r1" }),
        ))
        .respond_with(token("a2", "r2", 3600))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/logout"))
        .and(header("x-amz-sso_bearer_token", "a2"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    assert!(aws_sso::end_session("stale", &config()).await.unwrap());
}

#[tokio::test]
async fn signing_out_reports_a_renewal_that_fails_for_now() {
    let (_guard, server) = setup().await;
    device_login(&server, "later", 0).await;
    // A request error not documented as final, which the SDK does not retry.
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(json!({ "grantType": "refresh_token" })))
        .respond_with(aws_error(400, "InvalidRequestException"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/logout"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let err = aws_sso::end_session("later", &config()).await.unwrap_err();
    let message = format!("{err:#}");
    assert!(
        message.contains("renewing the expired sign-in failed")
            && message.contains("ends on its own")
            && !message.contains("fob login"),
        "{message}"
    );
    assert!(aws_sso::session("later").unwrap().is_some(), "kept");
}

#[tokio::test]
async fn signing_out_of_an_ended_session_has_nothing_to_end() {
    let (_guard, server) = setup().await;
    device_login(&server, "gone", 0).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(json!({ "grantType": "refresh_token" })))
        .respond_with(aws_error(400, "InvalidGrantException"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/logout"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    assert!(!aws_sso::end_session("gone", &config()).await.unwrap());
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

/// IAM Identity Center's answer when its network controls refuse a request.
fn network_controls_error(status: u16, kind: &str) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("x-amzn-errortype", kind)
        .set_body_json(json!({
            "error": "access_denied",
            "reason": "NETWORK_CONTROLS_ACCESS_DENIED",
            "error_description": "Access denied by network controls",
        }))
}

#[tokio::test]
async fn a_renewal_refused_by_network_controls_keeps_the_session() {
    let (_guard, server) = setup().await;
    device_login(&server, "offvpn", 0).await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(json!({ "grantType": "refresh_token" })))
        .respond_with(network_controls_error(400, "AccessDeniedException"))
        .mount(&server)
        .await;

    let err = aws_sso::credentials("offvpn", &config(), "111111111111", "Admin")
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Other(_)), "{err}");
    let message = format!("{err:#}");
    assert!(message.contains("network controls refused"), "{message}");
    assert!(aws_sso::session("offvpn").unwrap().is_some(), "kept");
}

#[tokio::test]
async fn a_portal_call_refused_by_network_controls_is_not_retried() {
    let (_guard, server) = setup().await;
    device_login(&server, "blocked", 3600).await;
    for (status, kind) in [(403, "ForbiddenException"), (401, "UnauthorizedException")] {
        let mock = Mock::given(method("GET"))
            .and(path("/federation/credentials"))
            .respond_with(network_controls_error(status, kind))
            .expect(1)
            .mount_as_scoped(&server)
            .await;

        let err = aws_sso::credentials("blocked", &config(), "111111111111", "Admin")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Other(_)), "{kind}: {err}");
        let message = format!("{err:#}");
        assert!(message.contains("network controls refused"), "{message}");
        assert!(
            aws_sso::session("blocked").unwrap().is_some(),
            "{kind}: kept"
        );
        drop(mock);
    }
}

#[tokio::test]
async fn the_aws_cli_endpoint_variables_reach_a_vpc_endpoint() {
    let (_guard, server) = setup().await;
    // SAFETY: the tests run one at a time under SERIAL.
    unsafe {
        std::env::remove_var("OMNIFOB_AWS_ENDPOINT");
        std::env::set_var("AWS_ENDPOINT_URL_SSO_OIDC", server.uri());
        std::env::set_var("AWS_ENDPOINT_URL_SSO", server.uri());
    }
    device_login(&server, "private", 3600).await;
    Mock::given(method("GET"))
        .and(path("/federation/credentials"))
        .respond_with(role_credentials())
        .expect(1)
        .mount(&server)
        .await;

    let result = aws_sso::credentials("private", &config(), "111111111111", "Admin").await;
    // SAFETY: as above.
    unsafe {
        std::env::remove_var("AWS_ENDPOINT_URL_SSO_OIDC");
        std::env::remove_var("AWS_ENDPOINT_URL_SSO");
    }
    result.unwrap();
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

#[tokio::test]
async fn credentials_carry_the_account_id() {
    use omnifob_core::providers;
    use omnifob_core::{Profile, Target};

    let (_guard, server) = setup().await;
    device_login(&server, "acct", 3600).await;
    Mock::given(method("GET"))
        .and(path("/federation/credentials"))
        .respond_with(role_credentials())
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("Action=AssumeRole"))
        .respond_with(sts_credentials("AssumeRole", "ASIACHAINED"))
        .mount(&server)
        .await;
    let config = Config::parse(&format!(
        r#"
        [integrations.acct]
        type = "aws-sso"
        start_url = "{START_URL}"
        region = "eu-west-1"
        [integrations.acct.chained.prod]
        via_account_id = "111111111111"
        via_role = "Admin"
        role_arn = "arn:aws:iam::222222222222:role/Deploy"
        "#
    ))
    .unwrap();
    let role = Profile::new(
        "acct",
        "dev",
        "Admin",
        Target::Aws {
            account_id: "111111111111".into(),
            account_name: "Dev".into(),
            role_name: "Admin".into(),
        },
    );
    let chained = Profile::new(
        "acct",
        "prod",
        "Deploy",
        Target::AwsChained {
            label: "prod".into(),
            account_id: None,
        },
    );

    let creds = providers::credentials(&config, &role, true, None)
        .await
        .unwrap();
    assert_eq!(creds.env["AWS_ACCOUNT_ID"], "111111111111");
    // From the role ARN in the config when the synced profile lacks it.
    let creds = providers::credentials(&config, &chained, true, None)
        .await
        .unwrap();
    assert_eq!(creds.env["AWS_ACCESS_KEY_ID"], "ASIACHAINED");
    assert_eq!(creds.env["AWS_ACCOUNT_ID"], "222222222222");
    // The profile's own account wins over a `role_arn` edited since the
    // sync: cached credentials belong to the account it was synced with.
    let synced = Profile::new(
        "acct",
        "prod",
        "Deploy",
        Target::AwsChained {
            label: "prod".into(),
            account_id: Some("444444444444".into()),
        },
    );
    let creds = providers::credentials(&config, &synced, true, None)
        .await
        .unwrap();
    assert_eq!(creds.env["AWS_ACCESS_KEY_ID"], "ASIACHAINED");
    assert_eq!(creds.env["AWS_ACCOUNT_ID"], "444444444444");

    // Credentials cached before omnifob exported the account get it too.
    let mut cached = creds.clone();
    cached.env.remove("AWS_ACCOUNT_ID");
    cached
        .env
        .insert("AWS_ACCESS_KEY_ID".into(), "ASIACACHED".into());
    store::set(&store::credentials_key(&chained.id), &cached).unwrap();
    let creds = providers::credentials(&config, &chained, true, None)
        .await
        .unwrap();
    assert_eq!(creds.env["AWS_ACCESS_KEY_ID"], "ASIACACHED");
    assert_eq!(creds.env["AWS_ACCOUNT_ID"], "222222222222");
}

fn role_creds() -> omnifob_core::Credentials {
    let mut creds = omnifob_core::Credentials::default();
    for (k, v) in [
        ("AWS_ACCESS_KEY_ID", "ASIACONSOLE"),
        ("AWS_SECRET_ACCESS_KEY", "console-secret"),
        ("AWS_SESSION_TOKEN", "console-token"),
    ] {
        creds.env.insert(k.into(), v.into());
    }
    creds
}

fn console_request(
    session_duration: Option<jiff::SignedDuration>,
) -> aws_sso::ConsoleRequest<'static> {
    aws_sso::ConsoleRequest {
        partition: omnifob_core::providers::aws_partition::Partition::Aws,
        home_region: Some("eu-west-1"),
        region: Some("eu-west-1"),
        service: Some("ec2"),
        session_duration,
    }
}

/// The form fields of a request body.
fn form(request: &Request) -> HashMap<String, String> {
    let body = std::str::from_utf8(&request.body).unwrap();
    reqwest::Url::parse(&format!("http://form/?{body}"))
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

#[tokio::test]
async fn console_sign_in_posts_the_credentials_in_a_form() {
    let (_guard, server) = setup().await;
    Mock::given(method("POST"))
        .and(path("/federation"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "SigninToken": "signin-token" })),
        )
        .expect(2)
        .mount(&server)
        .await;

    let url = aws_sso::console_url(&role_creds(), &console_request(None))
        .await
        .unwrap();
    let eight_hours = jiff::SignedDuration::from_hours(8);
    aws_sso::console_url(&role_creds(), &console_request(Some(eight_hours)))
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    for request in &requests {
        // Nothing travels in the query string.
        assert_eq!(request.url.query(), None);
        let fields = form(request);
        assert_eq!(fields["Action"], "getSigninToken");
        let session: Value = serde_json::from_str(&fields["Session"]).unwrap();
        assert_eq!(
            session,
            json!({
                "sessionId": "ASIACONSOLE",
                "sessionKey": "console-secret",
                "sessionToken": "console-token",
            })
        );
    }
    // SessionDuration only when a length is asked for, in seconds.
    assert!(!form(&requests[0]).contains_key("SessionDuration"));
    assert_eq!(form(&requests[1])["SessionDuration"], "28800");

    // The sign-in URL keeps the real, regional sign-in host and opens the
    // service in the Region.
    let url = reqwest::Url::parse(&url).unwrap();
    assert_eq!(url.host_str(), Some("eu-west-1.signin.aws.amazon.com"));
    assert_eq!(url.path(), "/federation");
    let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(query["Action"], "login");
    assert_eq!(query["SigninToken"], "signin-token");
    assert_eq!(
        query["Destination"],
        "https://eu-west-1.console.aws.amazon.com/ec2/home?region=eu-west-1"
    );
    assert!(!url.as_str().contains("console-secret"));
}

#[tokio::test]
async fn a_refused_console_session_length_says_why_without_the_credentials() {
    let (_guard, server) = setup().await;
    Mock::given(method("POST"))
        .and(path("/federation"))
        .respond_with(ResponseTemplate::new(400).set_body_string("<html>Bad Request</html>"))
        .mount(&server)
        .await;

    let twelve_hours = jiff::SignedDuration::from_hours(12);
    let error = aws_sso::console_url(&role_creds(), &console_request(Some(twelve_hours)))
        .await
        .unwrap_err();
    let error = format!("{error:#}");
    assert!(error.contains("HTTP 400"), "{error}");
    assert!(error.contains("maximum session duration"), "{error}");
    for secret in ["ASIACONSOLE", "console-secret", "console-token"] {
        assert!(!error.contains(secret), "{error}");
    }

    // A length the endpoint never accepts is refused before any request.
    let thirteen_hours = jiff::SignedDuration::from_hours(13);
    let error = aws_sso::console_url(&role_creds(), &console_request(Some(thirteen_hours)))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("12 hours"), "{error}");
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn the_console_gets_new_credentials_and_caches_them() {
    let (_guard, server) = setup().await;
    device_login(&server, "fresh", 3600).await;
    Mock::given(method("GET"))
        .and(path("/federation/credentials"))
        .respond_with(role_credentials())
        .expect(2)
        .mount(&server)
        .await;

    let text = format!(
        "[integrations.fresh]\ntype = \"aws-sso\"\nstart_url = \"{START_URL}\"\nregion = \"eu-west-1\"\n"
    );
    let config = Config::parse(&text).unwrap();
    let profile = omnifob_core::Profile::new(
        "fresh",
        "prod",
        "Admin",
        omnifob_core::Target::Aws {
            account_id: "111111111111".into(),
            account_name: "prod".into(),
            role_name: "Admin".into(),
        },
    );
    use omnifob_core::providers;
    // The first call caches the credentials, the second reuses them.
    let cached = providers::credentials(&config, &profile, true, None)
        .await
        .unwrap();
    providers::credentials(&config, &profile, true, None)
        .await
        .unwrap();
    // The console bypasses the cache, and its credentials replace the cached.
    let console = providers::console_credentials(&config, &profile)
        .await
        .unwrap();
    assert!(console.issued_at > cached.issued_at);
    let reused = providers::credentials(&config, &profile, true, None)
        .await
        .unwrap();
    assert_eq!(reused.issued_at, console.issued_at);
}

/// A token as `GetWebIdentityToken` returns one, with the claims an
/// Identity Center role's token carries. The signature is not checked.
fn web_identity_jwt() -> String {
    use base64::Engine;
    let encode =
        |json: Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.to_string());
    format!(
        "{}.{}.c2lnbmF0dXJl",
        encode(json!({ "alg": "ES384", "kid": "k1" })),
        encode(json!({
            "iss": "https://abc123.tokens.sts.global.api.aws",
            "sub": XP_SUB,
            "aud": "omnifob",
            "https://sts.amazonaws.com/": { "identity_store_user_id": "user-1" },
        }))
    )
}

const XP_SUB: &str = "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/eu-west-1/AWSReservedSSO_Admin_0123456789abcdef";

fn web_identity_token() -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("content-type", "text/xml")
        .set_body_string(format!(
            r#"<GetWebIdentityTokenResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetWebIdentityTokenResult><WebIdentityToken>{}</WebIdentityToken><Expiration>2100-01-01T00:00:00Z</Expiration></GetWebIdentityTokenResult><ResponseMetadata><RequestId>1</RequestId></ResponseMetadata></GetWebIdentityTokenResponse>"#,
            web_identity_jwt()
        ))
}

fn sts_error(status: u16, code: &str) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("content-type", "text/xml")
        .set_body_string(format!(
            r#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>{code}</Code><Message>{code} from STS</Message></Error><RequestId>1</RequestId></ErrorResponse>"#
        ))
}

/// A commercial portal with a GovCloud role, its token requested in
/// us-east-1 rather than the portal's Region.
fn cross_partition_config(integration: &str) -> Config {
    Config::parse(&format!(
        r#"
        [integrations.{integration}]
        type = "aws-sso"
        start_url = "{START_URL}"
        region = "eu-west-1"
        [integrations.{integration}.cross_partition.gov]
        via_account_id = "111111111111"
        via_role = "Admin"
        role_arn = "arn:aws-us-gov:iam::222222222222:role/Audit"
        audience = "omnifob"
        region = "us-gov-west-1"
        source_region = "us-east-1"
        duration = "2h"
        "#
    ))
    .unwrap()
}

fn sso_config(config: &Config, integration: &str) -> AwsSsoConfig {
    match config.integration(integration).unwrap() {
        Integration::AwsSso(c) => c.clone(),
        _ => unreachable!(),
    }
}

fn cross_partition_profile(integration: &str) -> omnifob_core::Profile {
    omnifob_core::Profile::new(
        integration,
        "gov",
        "Audit",
        omnifob_core::Target::AwsCrossPartition {
            label: "gov".into(),
            account_id: "222222222222".into(),
        },
    )
}

/// Mounts the Identity Center role's credentials for a signed-in portal.
async fn mount_source_credentials(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/federation/credentials"))
        .and(query_param("account_id", "111111111111"))
        .and(query_param("role_name", "Admin"))
        .respond_with(role_credentials())
        .mount(server)
        .await;
}

fn header_value<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request.headers.get(name).and_then(|v| v.to_str().ok())
}

#[tokio::test]
async fn cross_partition_roles_exchange_a_web_identity_token() {
    use omnifob_core::providers;

    let (_guard, server) = setup().await;
    device_login(&server, "xp", 3600).await;
    mount_source_credentials(&server).await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("Action=GetWebIdentityToken"))
        .respond_with(web_identity_token())
        .expect(2)
        .mount(&server)
        .await;
    for (seconds, access_key) in [("7200", "ASIAGOV"), ("1800", "ASIAGOVTTL")] {
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_string_contains("Action=AssumeRoleWithWebIdentity"))
            .and(body_string_contains(format!("DurationSeconds={seconds}")))
            .respond_with(sts_credentials("AssumeRoleWithWebIdentity", access_key))
            .expect(1)
            .mount(&server)
            .await;
    }
    let config = cross_partition_config("xp");
    let profile = cross_partition_profile("xp");

    let creds = providers::credentials(&config, &profile, true, None)
        .await
        .unwrap();
    assert_eq!(creds.env["AWS_ACCESS_KEY_ID"], "ASIAGOV");
    assert_eq!(creds.env["AWS_REGION"], "us-gov-west-1");
    assert_eq!(creds.env["AWS_DEFAULT_REGION"], "us-gov-west-1");
    assert_eq!(creds.env["AWS_ACCOUNT_ID"], "222222222222");

    let requests = server.received_requests().await.unwrap();
    let action = |name: &str| {
        requests
            .iter()
            .find(|r| form(r).get("Action").map(String::as_str) == Some(name))
            .unwrap_or_else(|| panic!("no {name} request"))
    };
    // One audience, the algorithm and a one-minute token, signed in the
    // source Region with the Identity Center role's key and session.
    let request = action("GetWebIdentityToken");
    let fields = form(request);
    assert_eq!(fields["Audience.member.1"], "omnifob");
    assert!(!fields.contains_key("Audience.member.2"), "{fields:?}");
    assert_eq!(fields["SigningAlgorithm"], "ES384");
    assert_eq!(fields["DurationSeconds"], "60");
    let authorization = header_value(request, "authorization").unwrap();
    assert!(
        authorization.contains("Credential=AKIAEXAMPLE/")
            && authorization.contains("/us-east-1/sts/aws4_request"),
        "{authorization}"
    );
    assert_eq!(
        header_value(request, "x-amz-security-token"),
        Some("session")
    );
    // The exchange carries the token, the role and the length, unsigned.
    let request = action("AssumeRoleWithWebIdentity");
    let fields = form(request);
    assert_eq!(fields["WebIdentityToken"], web_identity_jwt());
    assert_eq!(
        fields["RoleArn"],
        "arn:aws-us-gov:iam::222222222222:role/Audit"
    );
    assert_eq!(fields["RoleSessionName"], "omnifob");
    assert_eq!(fields["DurationSeconds"], "7200");
    assert_eq!(header_value(request, "authorization"), None);
    assert_eq!(header_value(request, "x-amz-security-token"), None);

    // Cached under the profile, like any other.
    let cached = store::get::<omnifob_core::Credentials>(&store::credentials_key(&profile.id))
        .unwrap()
        .unwrap();
    assert_eq!(cached.env["AWS_ACCESS_KEY_ID"], "ASIAGOV");
    assert!(
        !serde_json::to_string(&cached)
            .unwrap()
            .contains(&web_identity_jwt()),
        "the token is never cached"
    );
    let again = providers::credentials(&config, &profile, true, None)
        .await
        .unwrap();
    assert_eq!(again.issued_at, creds.issued_at);

    // --ttl asks for another length and leaves the cache alone.
    let ttl = providers::credentials(
        &config,
        &profile,
        true,
        Some(jiff::SignedDuration::from_mins(30)),
    )
    .await
    .unwrap();
    assert_eq!(ttl.env["AWS_ACCESS_KEY_ID"], "ASIAGOVTTL");
    let again = providers::credentials(&config, &profile, true, None)
        .await
        .unwrap();
    assert_eq!(again.env["AWS_ACCESS_KEY_ID"], "ASIAGOV");
    // A length STS never accepts is refused before any call.
    for hours in [0, 13] {
        let error = providers::credentials(
            &config,
            &profile,
            true,
            Some(jiff::SignedDuration::from_hours(hours)),
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("15 minutes to 12 hours"),
            "{error}"
        );
    }
}

/// Runs the flow once against what is mounted, and returns the error.
async fn cross_partition_error(config: &AwsSsoConfig, integration: &str) -> String {
    let error = aws_sso::cross_partition_credentials(integration, config, "gov", None)
        .await
        .unwrap_err();
    let error = format!("{error:#}");
    assert!(!error.contains(&web_identity_jwt()), "{error}");
    error
}

fn count(requests: &[Request], needle: &str) -> usize {
    requests
        .iter()
        .filter(|r| {
            r.url.path() == needle || std::str::from_utf8(&r.body).is_ok_and(|b| b.contains(needle))
        })
        .count()
}

#[tokio::test]
async fn refused_token_requests_say_who_has_to_act() {
    let (_guard, server) = setup().await;
    device_login(&server, "xp-token", 3600).await;
    let config = sso_config(&cross_partition_config("xp-token"), "xp-token");

    // The documented code, without the SDK model's `Exception` suffix.
    let cases = [
        (
            "OutboundWebIdentityFederationDisabled",
            "outbound identity federation is not enabled in the source account 111111111111",
        ),
        (
            "OutboundWebIdentityFederationDisabledException",
            "an administrator of that account must enable it",
        ),
        (
            "AccessDenied",
            "Admin in 111111111111 may not request a web identity token for the audience 'omnifob', signed with ES384, lasting 60 seconds",
        ),
    ];
    for (code, expected) in cases {
        server.reset().await;
        mount_source_credentials(&server).await;
        Mock::given(method("POST"))
            .and(body_string_contains("Action=GetWebIdentityToken"))
            .respond_with(sts_error(403, code))
            .expect(1)
            .mount(&server)
            .await;
        let error = cross_partition_error(&config, "xp-token").await;
        assert!(error.contains(expected), "{code}: {error}");
        let requests = server.received_requests().await.unwrap();
        assert_eq!(count(&requests, "AssumeRoleWithWebIdentity"), 0, "{code}");
    }
    let error = {
        server.reset().await;
        mount_source_credentials(&server).await;
        Mock::given(method("POST"))
            .and(body_string_contains("Action=GetWebIdentityToken"))
            .respond_with(sts_error(403, "AccessDenied"))
            .mount(&server)
            .await;
        cross_partition_error(&config, "xp-token").await
    };
    assert!(error.contains("sts:IdentityTokenAudience"), "{error}");

    // SessionDurationEscalation: retried once with new source credentials.
    server.reset().await;
    mount_source_credentials(&server).await;
    Mock::given(method("POST"))
        .and(body_string_contains("Action=GetWebIdentityToken"))
        .respond_with(sts_error(403, "SessionDurationEscalationException"))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("Action=GetWebIdentityToken"))
        .respond_with(web_identity_token())
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("Action=AssumeRoleWithWebIdentity"))
        .respond_with(sts_credentials("AssumeRoleWithWebIdentity", "ASIAGOV"))
        .expect(1)
        .mount(&server)
        .await;
    let creds = aws_sso::cross_partition_credentials("xp-token", &config, "gov", None)
        .await
        .unwrap();
    assert_eq!(creds.env["AWS_ACCESS_KEY_ID"], "ASIAGOV");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(count(&requests, "/federation/credentials"), 2);
    assert_eq!(count(&requests, "Action=GetWebIdentityToken"), 2);

    // Only once.
    server.reset().await;
    mount_source_credentials(&server).await;
    Mock::given(method("POST"))
        .and(body_string_contains("Action=GetWebIdentityToken"))
        .respond_with(sts_error(403, "SessionDurationEscalation"))
        .expect(2)
        .mount(&server)
        .await;
    let error = cross_partition_error(&config, "xp-token").await;
    assert!(error.contains("expire sooner, even new ones"), "{error}");
}

#[tokio::test]
async fn refused_exchanges_show_the_tokens_claims() {
    let (_guard, server) = setup().await;
    device_login(&server, "xp-exchange", 3600).await;
    let config = sso_config(&cross_partition_config("xp-exchange"), "xp-exchange");
    let mount = |code: &'static str, times: Option<u64>| {
        let server = &server;
        async move {
            server.reset().await;
            mount_source_credentials(server).await;
            Mock::given(method("POST"))
                .and(body_string_contains("Action=GetWebIdentityToken"))
                .respond_with(web_identity_token())
                .mount(server)
                .await;
            let mut refused = Mock::given(method("POST"))
                .and(body_string_contains("Action=AssumeRoleWithWebIdentity"))
                .respond_with(sts_error(400, code))
                .with_priority(1);
            if let Some(times) = times {
                refused = refused.up_to_n_times(times);
            }
            refused.mount(server).await;
            Mock::given(method("POST"))
                .and(body_string_contains("Action=AssumeRoleWithWebIdentity"))
                .respond_with(sts_credentials("AssumeRoleWithWebIdentity", "ASIAGOV"))
                .mount(server)
                .await;
        }
    };

    // Refused by the destination: the values its administrator must match.
    for code in ["AccessDenied", "InvalidIdentityToken", "IDPRejectedClaim"] {
        mount(code, None).await;
        let error = cross_partition_error(&config, "xp-exchange").await;
        for expected in [
            "arn:aws-us-gov:iam::222222222222:role/Audit does not accept the web identity token from Admin in 111111111111",
            "an administrator of the destination account",
            "'omnifob' as a client ID",
            "iss https://abc123.tokens.sts.global.api.aws",
            &format!("sub {XP_SUB}"),
            "aud omnifob",
        ] {
            assert!(error.contains(expected), "{code}: {error}");
        }
        assert!(!error.contains("user-1"), "only iss, sub and aud: {error}");
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            count(&requests, "Action=AssumeRoleWithWebIdentity"),
            1,
            "{code}"
        );
    }

    // The SDK retries an unreachable issuer with the same token, up to
    // three attempts in all.
    mount("IDPCommunicationError", Some(1)).await;
    let creds = aws_sso::cross_partition_credentials("xp-exchange", &config, "gov", None)
        .await
        .unwrap();
    assert_eq!(creds.env["AWS_ACCESS_KEY_ID"], "ASIAGOV");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(count(&requests, "Action=GetWebIdentityToken"), 1);
    assert_eq!(count(&requests, "Action=AssumeRoleWithWebIdentity"), 2);
    mount("IDPCommunicationError", None).await;
    let error = cross_partition_error(&config, "xp-exchange").await;
    assert!(
        error.contains("could not reach the source account's issuer"),
        "{error}"
    );
    let requests = server.received_requests().await.unwrap();
    assert_eq!(count(&requests, "Action=GetWebIdentityToken"), 1);
    assert_eq!(count(&requests, "Action=AssumeRoleWithWebIdentity"), 3);

    // An expired token needs a new one: retried once, then given up. The
    // API reference spells the code `ExpiredToken`, the SDK model
    // `ExpiredTokenException`.
    for code in ["ExpiredToken", "ExpiredTokenException"] {
        mount(code, Some(1)).await;
        let creds = aws_sso::cross_partition_credentials("xp-exchange", &config, "gov", None)
            .await
            .unwrap();
        assert_eq!(creds.env["AWS_ACCESS_KEY_ID"], "ASIAGOV");
        let requests = server.received_requests().await.unwrap();
        assert_eq!(count(&requests, "Action=GetWebIdentityToken"), 2, "{code}");
        assert_eq!(
            count(&requests, "Action=AssumeRoleWithWebIdentity"),
            2,
            "{code}"
        );
        mount(code, None).await;
        let error = cross_partition_error(&config, "xp-exchange").await;
        assert!(
            error.contains("expired or not valid, twice")
                && error.contains("expire 60 seconds after issuing it"),
            "{code}: {error}"
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            count(&requests, "Action=AssumeRoleWithWebIdentity"),
            2,
            "{code}"
        );
    }

    // A length above the role's maximum.
    server.reset().await;
    mount_source_credentials(&server).await;
    Mock::given(method("POST"))
        .and(body_string_contains("Action=GetWebIdentityToken"))
        .respond_with(web_identity_token())
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("Action=AssumeRoleWithWebIdentity"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "text/xml")
                .set_body_string(r#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>ValidationError</Code><Message>The requested DurationSeconds exceeds the MaxSessionDuration set for this role.</Message></Error><RequestId>1</RequestId></ErrorResponse>"#),
        )
        .mount(&server)
        .await;
    let error = cross_partition_error(&config, "xp-exchange").await;
    assert!(
        error.contains("does not allow sessions of 7200 seconds"),
        "{error}"
    );
}

#[tokio::test]
async fn cross_partition_profiles_check_in_the_destination_and_open_its_console() {
    use omnifob_core::providers;

    let (_guard, server) = setup().await;
    device_login(&server, "xp-check", 3600).await;
    mount_source_credentials(&server).await;
    Mock::given(method("POST"))
        .and(body_string_contains("Action=GetWebIdentityToken"))
        .respond_with(web_identity_token())
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("Action=AssumeRoleWithWebIdentity"))
        .respond_with(sts_credentials("AssumeRoleWithWebIdentity", "ASIAGOV"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("Action=GetCallerIdentity"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/xml")
                .set_body_string(r#"<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws-us-gov:sts::222222222222:assumed-role/Audit/omnifob</Arn><UserId>AROA:omnifob</UserId><Account>222222222222</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>1</RequestId></ResponseMetadata></GetCallerIdentityResponse>"#),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/federation"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "SigninToken": "signin-token" })),
        )
        .expect(1)
        .mount(&server)
        .await;
    let config = cross_partition_config("xp-check");
    let profile = cross_partition_profile("xp-check");

    let checked = providers::check_profile(&config, &profile).await.unwrap();
    assert_eq!(
        checked,
        "acts as arn:aws-us-gov:sts::222222222222:assumed-role/Audit/omnifob"
    );
    let requests = server.received_requests().await.unwrap();
    let identity = requests
        .iter()
        .find(|r| {
            std::str::from_utf8(&r.body)
                .unwrap()
                .contains("GetCallerIdentity")
        })
        .unwrap();
    let authorization = header_value(identity, "authorization").unwrap();
    assert!(
        authorization.contains("Credential=ASIAGOV/")
            && authorization.contains("/us-gov-west-1/sts/aws4_request"),
        "{authorization}"
    );

    let options = providers::ConsoleOptions::default();
    let creds = providers::console_credentials(&config, &profile)
        .await
        .unwrap();
    let url = providers::console_url(&config, &profile, &creds, &options)
        .await
        .unwrap();
    let url = reqwest::Url::parse(&url).unwrap();
    assert_eq!(url.host_str(), Some("signin.amazonaws-us-gov.com"));
    let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(
        query["Destination"],
        "https://console.amazonaws-us-gov.com/console/home?region=us-gov-west-1"
    );
    let federation = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.url.path() == "/federation")
        .unwrap();
    assert!(!form(&federation).contains_key("SessionDuration"));
}
