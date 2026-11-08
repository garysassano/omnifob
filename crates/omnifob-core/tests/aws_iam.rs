//! IAM users' access keys against a mock of STS. Secrets go to an in-memory
//! store, never the keychain.

use std::sync::atomic::{AtomicUsize, Ordering};

use omnifob_core::config::{AwsIamConfig, Config, Integration};
use omnifob_core::providers::aws_iam;
use omnifob_core::{Target, store};
use tokio::sync::{Mutex, MutexGuard};
use wiremock::matchers::{body_string_contains, header_regex, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The tests share environment variables, so they run one at a time.
static SERIAL: Mutex<()> = Mutex::const_new(());

/// How often the MFA prompt was asked.
static MFA_PROMPTS: AtomicUsize = AtomicUsize::new(0);

async fn setup() -> (MutexGuard<'static, ()>, MockServer) {
    let guard = SERIAL.lock().await;
    store::use_memory_store().unwrap();
    omnifob_core::prompt::set_mfa_prompt(|_| {
        MFA_PROMPTS.fetch_add(1, Ordering::SeqCst);
        Ok("654321".to_string())
    });
    let server = MockServer::start().await;
    let state = std::env::temp_dir().join(format!("omnifob-iam-test-{}", std::process::id()));
    // SAFETY: the tests run one at a time under SERIAL, and nothing else in
    // this process reads the environment concurrently.
    unsafe {
        std::env::set_var("OMNIFOB_AWS_ENDPOINT", server.uri());
        std::env::set_var("XDG_STATE_HOME", &state);
    }
    (guard, server)
}

fn config(extra: &str) -> AwsIamConfig {
    let text = format!(
        r#"
        [integrations.legacy]
        type = "aws-iam"
        region = "eu-west-1"
        {extra}

        [integrations.legacy.roles.prod]
        role_arn = "arn:aws:iam::222222222222:role/Deploy"
        duration = "2h"
        "#
    );
    match Config::parse(&text)
        .unwrap()
        .integrations
        .remove("legacy")
        .unwrap()
    {
        Integration::AwsIam(c) => c,
        _ => unreachable!(),
    }
}

fn sts(action: &str, result: &str) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("content-type", "text/xml")
        .set_body_string(format!(
            r#"<{action}Response xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><{action}Result>{result}</{action}Result><ResponseMetadata><RequestId>1</RequestId></ResponseMetadata></{action}Response>"#
        ))
}

fn temporary(access_key: &str) -> String {
    format!(
        "<Credentials><AccessKeyId>{access_key}</AccessKeyId><SecretAccessKey>s</SecretAccessKey><SessionToken>t</SessionToken><Expiration>2100-01-01T00:00:00Z</Expiration></Credentials>"
    )
}

async fn mock_identity(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("Action=GetCallerIdentity"))
        .respond_with(sts(
            "GetCallerIdentity",
            "<Arn>arn:aws:iam::123456789012:user/me</Arn><UserId>AIDAEXAMPLE</UserId><Account>123456789012</Account>",
        ))
        .mount(server)
        .await;
}

async fn login(server: &MockServer, integration: &str, config: &AwsIamConfig) {
    mock_identity(server).await;
    let arn = aws_iam::login(integration, config, "AKIAEXAMPLE", "secret")
        .await
        .unwrap();
    assert_eq!(arn, "arn:aws:iam::123456789012:user/me");
}

#[tokio::test]
async fn login_checks_the_key_and_rejects_temporary_ones() {
    let (_guard, server) = setup().await;
    let config = config("");
    let err = aws_iam::login("tmp", &config, "ASIAEXAMPLE", "secret")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("AKIA"), "{err}");
    assert!(!aws_iam::has_key("tmp").unwrap());

    login(&server, "keyed", &config).await;
    assert!(aws_iam::has_key("keyed").unwrap());
    assert!(aws_iam::logout("keyed").unwrap());
    assert!(!aws_iam::has_key("keyed").unwrap());
}

#[tokio::test]
async fn discovery_lists_the_session_and_each_role() {
    let (_guard, server) = setup().await;
    let config = config("");
    login(&server, "found", &config).await;
    let profiles = aws_iam::discover("found", &config).await.unwrap();
    let ids: Vec<_> = profiles.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids, ["found/123456789012/session", "found/prod/Deploy"]);
    assert_eq!(
        profiles[0].target,
        Target::AwsIamSession {
            account_id: "123456789012".into()
        }
    );
}

#[tokio::test]
async fn one_mfa_code_covers_parallel_calls_and_every_role() {
    let (_guard, server) = setup().await;
    let config = config(
        r#"mfa_serial = "arn:aws:iam::123456789012:mfa/me"
        session_duration = "12h""#,
    );
    login(&server, "mfa", &config).await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("Action=GetSessionToken"))
        .and(body_string_contains("TokenCode=654321"))
        .and(body_string_contains("DurationSeconds=43200"))
        // Signed with the user's key.
        .and(header_regex("authorization", "Credential=AKIAEXAMPLE/"))
        .respond_with(sts("GetSessionToken", &temporary("ASIASESSION")))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("Action=AssumeRole"))
        .and(body_string_contains("DurationSeconds=7200"))
        // Signed with the session, which carries the MFA; no code is sent.
        .and(header_regex("authorization", "Credential=ASIASESSION/"))
        .respond_with(sts(
            "AssumeRole",
            &format!(
                "{}<AssumedRoleUser><AssumedRoleId>AROA:omnifob</AssumedRoleId><Arn>arn:aws:sts::222222222222:assumed-role/Deploy/omnifob</Arn></AssumedRoleUser>",
                temporary("ASIAROLE")
            ),
        ))
        .expect(4)
        .mount(&server)
        .await;

    let before = MFA_PROMPTS.load(Ordering::SeqCst);
    let calls =
        (0..4).map(|_| aws_iam::role_credentials("mfa", &config, "prod", "mfa/prod/Deploy", None));
    for result in futures::future::join_all(calls).await {
        let creds = result.unwrap();
        assert_eq!(creds.env["AWS_ACCESS_KEY_ID"], "ASIAROLE");
        assert_eq!(creds.env["AWS_REGION"], "eu-west-1");
    }
    let session = aws_iam::session_credentials("mfa", &config, "mfa/x/session", None)
        .await
        .unwrap();
    assert_eq!(session.env["AWS_ACCESS_KEY_ID"], "ASIASESSION");
    assert_eq!(MFA_PROMPTS.load(Ordering::SeqCst) - before, 1);
}

#[tokio::test]
async fn durations_outside_what_sts_allows_are_refused() {
    let (_guard, server) = setup().await;
    let config = config("");
    login(&server, "limits", &config).await;
    let err = aws_iam::role_credentials(
        "limits",
        &config,
        "prod",
        "limits/prod/Deploy",
        Some(jiff::SignedDuration::from_hours(13)),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("12 hours"), "{err}");

    let bad = Config::parse(
        r#"
        [integrations.x]
        type = "aws-iam"
        session_duration = "48h"
        "#,
    )
    .unwrap_err();
    assert!(format!("{bad:#}").contains("36h"), "{bad:#}");
}
