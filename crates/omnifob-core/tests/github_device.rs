//! GitHub's device flow against a mock of its OAuth endpoints.

use omnifob_core::providers::github::device_flow;
use serde_json::json;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn github(replies: Vec<serde_json::Value>) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/login/device/code"))
        .and(body_string_contains("client_id=app"))
        .and(body_string_contains("scope=repo+read%3Aorg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "device_code": "dev",
            "user_code": "ABCD-1234",
            "verification_uri": "https://github.com/login/device",
            "expires_in": 60,
            "interval": 0
        })))
        .mount(&server)
        .await;
    for (i, reply) in replies.into_iter().enumerate() {
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .and(body_string_contains("device_code=dev"))
            .respond_with(ResponseTemplate::new(200).set_body_json(reply))
            .up_to_n_times(1)
            .with_priority(i as u8 + 1)
            .mount(&server)
            .await;
    }
    server
}

fn scopes() -> Vec<String> {
    vec!["repo".into(), "read:org".into()]
}

#[tokio::test]
async fn waits_for_approval_and_returns_the_token() {
    let server = github(vec![
        json!({ "error": "authorization_pending" }),
        json!({ "error": "slow_down", "interval": 0 }),
        json!({ "access_token": "gho_x", "token_type": "bearer", "scope": "gist,read:org,repo" }),
    ])
    .await;
    let mut shown = None;
    let (token, granted) = device_flow(&server.uri(), "app", &scopes(), |p| {
        shown = Some((p.url.clone(), p.user_code.clone()))
    })
    .await
    .unwrap();
    assert_eq!(token, "gho_x");
    assert_eq!(granted, ["gist", "read:org", "repo"]);
    assert_eq!(
        shown.unwrap(),
        ("https://github.com/login/device".into(), "ABCD-1234".into())
    );
}

#[tokio::test]
async fn reports_a_cancelled_or_refused_sign_in() {
    let server = github(vec![json!({ "error": "access_denied" })]).await;
    let err = device_flow(&server.uri(), "app", &scopes(), |_| {})
        .await
        .unwrap_err();
    assert!(err.to_string().contains("cancelled"), "{err}");

    let server = github(vec![json!({
        "error": "device_flow_disabled",
        "error_description": "Device Flow must be explicitly enabled for this App"
    })])
    .await;
    let err = device_flow(&server.uri(), "app", &scopes(), |_| {})
        .await
        .unwrap_err();
    assert!(err.to_string().contains("explicitly enabled"), "{err}");
}
