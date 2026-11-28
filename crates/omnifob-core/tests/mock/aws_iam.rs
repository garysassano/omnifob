//! IAM users' access keys against a mock of STS. Secrets go to an in-memory
//! store, never the keychain.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::support::Scratch;
use omnifob_core::config::{AwsIamConfig, Config, Integration};
use omnifob_core::providers::{self, aws};
use omnifob_core::{Context, Endpoints, Profile, Target};
use wiremock::matchers::{body_string_contains, header_regex, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn setup() -> (Scratch, MockServer) {
    setup_counting_prompts(Arc::default()).await
}

/// [`setup`], counting the MFA prompts in `prompts`.
async fn setup_counting_prompts(prompts: Arc<AtomicUsize>) -> (Scratch, MockServer) {
    let server = MockServer::start().await;
    let endpoints = Endpoints {
        aws: Some(server.uri()),
        ..Default::default()
    };
    let context = Context::builder()
        .endpoints(endpoints)
        .mfa_prompt(move |_| {
            prompts.fetch_add(1, Ordering::SeqCst);
            Ok("654321".to_string())
        });
    (Scratch::with("omnifob-iam-test", context), server)
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
        duration = "45m"
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
    let arn = aws::iam::login(integration, config, "AKIAEXAMPLE", "secret")
        .await
        .unwrap();
    assert_eq!(arn, "arn:aws:iam::123456789012:user/me");
}

#[tokio::test]
async fn login_checks_the_key_and_rejects_temporary_ones() {
    let (_guard, server) = setup().await;
    let config = config("");
    let err = aws::iam::login("tmp", &config, "ASIAEXAMPLE", "secret")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("AKIA"), "{err}");
    assert!(!aws::iam::has_key("tmp").unwrap());

    login(&server, "keyed", &config).await;
    assert!(aws::iam::has_key("keyed").unwrap());
    assert!(aws::iam::logout("keyed").unwrap());
    assert!(!aws::iam::has_key("keyed").unwrap());
}

#[tokio::test]
async fn discovery_lists_the_session_and_each_role() {
    let (_guard, server) = setup().await;
    let config = config("");
    login(&server, "found", &config).await;
    let profiles = aws::iam::discover("found", &config).await.unwrap();
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
    let prompts = Arc::new(AtomicUsize::new(0));
    let (_guard, server) = setup_counting_prompts(prompts.clone()).await;
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
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("Action=AssumeRole"))
        .and(body_string_contains("DurationSeconds=2700"))
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

    let calls =
        (0..4).map(|_| aws::iam::role_credentials("mfa", &config, "prod", "mfa/prod/Deploy", None));
    for result in futures_util::future::join_all(calls).await {
        let creds = result.unwrap();
        assert_eq!(creds.env["AWS_ACCESS_KEY_ID"], "ASIAROLE");
        assert_eq!(creds.env["AWS_REGION"], "eu-west-1");
    }
    let session = aws::iam::session_credentials("mfa", &config, "mfa/x/session", None, false)
        .await
        .unwrap();
    assert_eq!(session.env["AWS_ACCESS_KEY_ID"], "ASIASESSION");
    assert_eq!(prompts.load(Ordering::SeqCst), 1);
    // Renewing (`--no-cache`, `fob renew`) starts a new session, with a code.
    aws::iam::session_credentials("mfa", &config, "mfa/x/session", None, true)
        .await
        .unwrap();
    assert_eq!(prompts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn durations_outside_what_sts_allows_are_refused() {
    let (_guard, server) = setup().await;
    let config = config("");
    login(&server, "limits", &config).await;
    let err = aws::iam::role_credentials(
        "limits",
        &config,
        "prod",
        "limits/prod/Deploy",
        Some(jiff::SignedDuration::from_hours(2)),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("1 hour"), "{err}");

    // STS caps a role assumed with the user's session at an hour.
    let bad = Config::parse(
        r#"
        [integrations.x]
        type = "aws-iam"
        [integrations.x.roles.prod]
        role_arn = "arn:aws:iam::222222222222:role/Deploy"
        duration = "2h"
        "#,
    )
    .unwrap_err();
    assert!(format!("{bad:#}").contains("between 15m and 1h"), "{bad:#}");

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

#[tokio::test]
async fn discovery_takes_the_account_from_sts() {
    let (_guard, server) = setup().await;
    let config = config("");
    login(&server, "acct-sts", &config).await;
    server.reset().await;
    // An ARN without the account shows where the account comes from.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("Action=GetCallerIdentity"))
        .respond_with(sts(
            "GetCallerIdentity",
            "<Arn>arn:aws:iam:::user/me</Arn><UserId>AIDAEXAMPLE</UserId><Account>123456789012</Account>",
        ))
        .mount(&server)
        .await;
    let profiles = aws::iam::discover("acct-sts", &config).await.unwrap();
    assert_eq!(
        profiles[0].target,
        Target::AwsIamSession {
            account_id: "123456789012".into()
        }
    );
    // A role labelled with the account ID and named `session` would take
    // the session's id, which only STS's answer shows.
    let clash = self::config(
        "[integrations.legacy.roles.\"123456789012\"]\nrole_arn = \"arn:aws:iam::222222222222:role/session\"",
    );
    let error = aws::iam::discover("acct-sts", &clash)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("would be acct-sts/123456789012/session, the user's session profile"),
        "{error}"
    );

    server.reset().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("Action=GetCallerIdentity"))
        .respond_with(sts(
            "GetCallerIdentity",
            "<Arn>arn:aws:iam::123456789012:user/me</Arn><UserId>AIDAEXAMPLE</UserId>",
        ))
        .mount(&server)
        .await;
    let err = aws::iam::discover("acct-sts", &config)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("no account"), "{err}");
}

/// The `legacy` integration of [`config`] under another name, as a whole
/// config, with its session and role profiles.
fn whole_config(name: &str) -> (Config, Profile, Profile) {
    let config = Config::parse(&format!(
        r#"
        [integrations.{name}]
        type = "aws-iam"
        region = "eu-west-1"
        [integrations.{name}.roles.prod]
        role_arn = "arn:aws:iam::222222222222:role/Deploy"
        duration = "45m"
        "#
    ))
    .unwrap();
    let session = Profile::new(
        name,
        "123456789012",
        "session",
        Target::AwsIamSession {
            account_id: "123456789012".into(),
        },
    );
    let role = Profile::new(
        name,
        "prod",
        "Deploy",
        Target::AwsIamRole {
            label: "prod".into(),
            account_id: None,
        },
    );
    (config, session, role)
}

fn integration(config: &Config, name: &str) -> AwsIamConfig {
    match config.integration(name).unwrap() {
        Integration::AwsIam(c) => c.clone(),
        _ => unreachable!(),
    }
}

async fn mock_sts(server: &MockServer, action: &str, seconds: u32, access_key: &str) {
    let result = match action {
        "AssumeRole" => format!(
            "{}<AssumedRoleUser><AssumedRoleId>AROA:omnifob</AssumedRoleId><Arn>arn:aws:sts::222222222222:assumed-role/Deploy/omnifob</Arn></AssumedRoleUser>",
            temporary(access_key)
        ),
        _ => temporary(access_key),
    };
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains(format!("Action={action}")))
        .and(body_string_contains(format!("DurationSeconds={seconds}")))
        .respond_with(sts(action, &result))
        .expect(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn credentials_carry_the_account_id() {
    let (_guard, server) = setup().await;
    let (config, session, role) = whole_config("acct-id");
    login(&server, "acct-id", &integration(&config, "acct-id")).await;
    mock_sts(&server, "GetSessionToken", 28_800, "ASIASESSION").await;
    mock_sts(&server, "AssumeRole", 2_700, "ASIAROLE").await;

    let creds = providers::credentials(&config, &session, true, None)
        .await
        .unwrap();
    assert_eq!(creds.env["AWS_ACCOUNT_ID"], "123456789012");
    let creds = providers::credentials(&config, &role, true, None)
        .await
        .unwrap();
    assert_eq!(creds.env["AWS_ACCOUNT_ID"], "222222222222");
}

#[tokio::test]
async fn a_ttl_request_leaves_the_cache_alone() {
    let (_guard, server) = setup().await;
    let (config, session, role) = whole_config("ttl");
    login(&server, "ttl", &integration(&config, "ttl")).await;
    let short = Some(jiff::SignedDuration::from_mins(15));
    // Each is asked for once: the plain calls after a `ttl` one get the
    // configured lifetime, and the second plain call comes from the cache.
    mock_sts(&server, "GetSessionToken", 900, "ASIASHORTSESSION").await;
    mock_sts(&server, "GetSessionToken", 28_800, "ASIASESSION").await;
    mock_sts(&server, "AssumeRole", 900, "ASIASHORTROLE").await;
    mock_sts(&server, "AssumeRole", 2_700, "ASIAROLE").await;

    assert_eq!(key(&config, &session, short).await, "ASIASHORTSESSION");
    assert_eq!(key(&config, &session, None).await, "ASIASESSION");
    assert_eq!(key(&config, &role, short).await, "ASIASHORTROLE");
    assert_eq!(key(&config, &role, None).await, "ASIAROLE");
    assert_eq!(key(&config, &role, None).await, "ASIAROLE");
    assert_eq!(key(&config, &session, None).await, "ASIASESSION");
}

/// The access key ID of a profile's credentials, from the cache if fresh.
async fn key(config: &Config, profile: &Profile, ttl: Option<jiff::SignedDuration>) -> String {
    let creds = providers::credentials(config, profile, true, ttl)
        .await
        .unwrap();
    creds.env["AWS_ACCESS_KEY_ID"].clone()
}

/// A kept session that STS refuses is replaced once, and the role assumed
/// with the new one.
#[tokio::test]
async fn a_refused_session_is_started_again_once() {
    let (_guard, server) = setup().await;
    let (config, session, role) = whole_config("refused");
    login(&server, "refused", &integration(&config, "refused")).await;
    // The kept session, refused as expired although it looks fresh.
    mock_sts(&server, "GetSessionToken", 28_800, "ASIAOLDSESSION").await;
    assert_eq!(key(&config, &session, None).await, "ASIAOLDSESSION");
    server.reset().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("Action=AssumeRole"))
        .and(header_regex("authorization", "Credential=ASIAOLDSESSION/"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("content-type", "text/xml")
                .set_body_string(
                    r#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>ExpiredToken</Code><Message>The security token included in the request is expired</Message></Error><RequestId>1</RequestId></ErrorResponse>"#,
                ),
        )
        .expect(1)
        .mount(&server)
        .await;
    mock_sts(&server, "GetSessionToken", 28_800, "ASIANEWSESSION").await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("Action=AssumeRole"))
        .and(header_regex("authorization", "Credential=ASIANEWSESSION/"))
        .respond_with(sts(
            "AssumeRole",
            &format!(
                "{}<AssumedRoleUser><AssumedRoleId>AROA:omnifob</AssumedRoleId><Arn>arn:aws:sts::222222222222:assumed-role/Deploy/omnifob</Arn></AssumedRoleUser>",
                temporary("ASIAROLE")
            ),
        ))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(key(&config, &role, None).await, "ASIAROLE");
    // The new session is the one kept (past the profile's own cache).
    let kept = aws::iam::session_credentials(
        "refused",
        &integration(&config, "refused"),
        &session.id,
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(kept.env["AWS_ACCESS_KEY_ID"], "ASIANEWSESSION");
}

/// `AWS_ENDPOINT_URL_STS` sends STS calls to a VPC endpoint, as it does for
/// the AWS CLI.
#[tokio::test]
async fn sts_calls_follow_aws_endpoint_url_sts() {
    let (scratch, server) = setup().await;
    let _vpc = scratch.switch_endpoints(Endpoints::from_vars(|name| {
        (name == "AWS_ENDPOINT_URL_STS").then(|| server.uri())
    }));
    let config = config("");
    mock_identity(&server).await;
    let result = aws::iam::login("sts-endpoint", &config, "AKIAEXAMPLE", "secret").await;
    assert_eq!(result.unwrap(), "arn:aws:iam::123456789012:user/me");
}

#[tokio::test]
async fn a_no_session_role_is_assumed_with_the_key_for_up_to_twelve_hours() {
    let prompts = Arc::new(AtomicUsize::new(0));
    let (_guard, server) = setup_counting_prompts(prompts.clone()).await;
    let text = r#"
        [integrations.legacy]
        type = "aws-iam"
        region = "eu-west-1"
        mfa_serial = "arn:aws:iam::123456789012:mfa/me"

        [integrations.legacy.roles.prod]
        role_arn = "arn:aws:iam::222222222222:role/Deploy"
        duration = "12h"
        no_session = true
        "#;
    let config = integration(&Config::parse(text).unwrap(), "legacy");
    login(&server, "nosession", &config).await;
    // No session is started: the key signs AssumeRole and sends the code.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("Action=GetSessionToken"))
        .respond_with(sts("GetSessionToken", &temporary("ASIASESSION")))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("Action=AssumeRole"))
        .and(body_string_contains("DurationSeconds=43200"))
        .and(body_string_contains("SerialNumber=arn%3Aaws%3Aiam%3A%3A123456789012%3Amfa%2Fme"))
        .and(body_string_contains("TokenCode=654321"))
        .and(header_regex("authorization", "Credential=AKIAEXAMPLE/"))
        .respond_with(sts(
            "AssumeRole",
            &format!(
                "{}<AssumedRoleUser><AssumedRoleId>AROA:omnifob</AssumedRoleId><Arn>arn:aws:sts::222222222222:assumed-role/Deploy/omnifob</Arn></AssumedRoleUser>",
                temporary("ASIAROLE")
            ),
        ))
        .expect(2)
        .mount(&server)
        .await;
    for _ in 0..2 {
        let creds =
            aws::iam::role_credentials("nosession", &config, "prod", "nosession/prod/Deploy", None)
                .await
                .unwrap();
        assert_eq!(creds.env["AWS_ACCESS_KEY_ID"], "ASIAROLE");
    }
    // Each new session of the role asks for a code.
    assert_eq!(prompts.load(Ordering::SeqCst), 2);
    let err = aws::iam::role_credentials(
        "nosession",
        &config,
        "prod",
        "nosession/prod/Deploy",
        Some(jiff::SignedDuration::from_hours(13)),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("15 minutes to 12 hours"), "{err}");

    for (role, message) in [
        (
            "duration = \"13h\"\nno_session = true",
            "between 15m and 12h",
        ),
        ("duration = \"2h\"", "set no_session = true"),
    ] {
        let text = format!(
            "[integrations.x]\ntype = \"aws-iam\"\n[integrations.x.roles.prod]\nrole_arn = \"arn:aws:iam::222222222222:role/Deploy\"\n{role}\n"
        );
        let error = format!("{:#}", Config::parse(&text).unwrap_err());
        assert!(error.contains(message), "{role}: {error}");
    }
}

/// `fob discover aws` on an IAM user: the user's ARN is the simulator's
/// policy source, and a role in its account whose trust policy names the
/// user is found, labelled after the role alone.
#[tokio::test]
async fn discovery_searches_the_users_own_account() {
    use omnifob_core::providers::aws::discover::{Basis, Options, Origin, Source, discover_from};

    let (_guard, server) = setup().await;
    let text = r#"
        [integrations.legacy]
        type = "aws-iam"
        region = "eu-west-1"
    "#;
    let config = Config::parse(text).unwrap();
    let Integration::AwsIam(iam) = &config.integrations["legacy"] else {
        unreachable!()
    };
    login(&server, "legacy", iam).await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("Action=GetSessionToken"))
        .respond_with(sts("GetSessionToken", &temporary("ASIASESSION")))
        .mount(&server)
        .await;
    let user = "arn:aws:iam::123456789012:user/me";
    let encode = |json: &str| -> String {
        json.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    };
    let role = |name: &str, principal: &str| {
        let trust = encode(&format!(
            r#"{{"Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{principal}"}},"Action":"sts:AssumeRole"}}]}}"#
        ));
        format!(
            "<member><Path>/</Path><RoleName>{name}</RoleName><Arn>arn:aws:iam::123456789012:role/{name}</Arn><AssumeRolePolicyDocument>{trust}</AssumeRolePolicyDocument></member>"
        )
    };
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("Action=ListRoles"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "<ListRolesResponse><ListRolesResult><IsTruncated>false</IsTruncated><Roles>{}{}</Roles></ListRolesResult></ListRolesResponse>",
            role("Deploy", user),
            role("Other", "arn:aws:iam::999999999999:root"),
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("Action=SimulatePrincipalPolicy"))
        .and(body_string_contains("PolicySourceArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Auser%2Fme"))
        .and(body_string_contains("ContextKeyValues.member.1=User"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<SimulatePrincipalPolicyResponse><SimulatePrincipalPolicyResult><IsTruncated>false</IsTruncated><EvaluationResults><member><EvalActionName>sts:AssumeRole</EvalActionName><EvalResourceName>arn:aws:iam::123456789012:role/Deploy</EvalResourceName><EvalDecision>allowed</EvalDecision></member></EvaluationResults></SimulatePrincipalPolicyResult></SimulatePrincipalPolicyResponse>"#,
        ))
        .expect(1)
        .mount(&server)
        .await;

    let profiles = aws::iam::discover("legacy", iam).await.unwrap();
    let session = &profiles[0];
    let origin = Origin::identity(&config, session).unwrap();
    let discovery = discover_from(
        "legacy",
        &origin,
        vec![Source {
            account_id: "123456789012".into(),
            segment: "123456789012".into(),
            via_role: "session".into(),
            profile_id: session.id.clone(),
        }],
        Options::default(),
    )
    .await
    .unwrap();
    assert!(discovery.skipped.is_empty(), "{:?}", discovery.skipped);
    let found: Vec<_> = discovery
        .found
        .iter()
        .map(|f| (f.label.as_str(), f.role.role_arn.as_str(), f.basis))
        .collect();
    assert_eq!(
        found,
        [(
            "deploy",
            "arn:aws:iam::123456789012:role/Deploy",
            Basis::Simulated
        )]
    );
}
