//! Token integrations against a mock of the provider's check URL: what
//! `login` stores and what `check` reports for each answer. The secrets go
//! to an in-memory store, never the keychain.

use std::collections::BTreeMap;

use crate::support::Scratch;
use omnifob_core::config::{Config, Integration, TokenConfig};
use omnifob_core::providers::token;
use omnifob_core::{Endpoints, Error};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A token integration with one secret, checked at `<server>/me`, or at
/// whatever `extra` sets.
fn config(server: &MockServer, extra: &str) -> TokenConfig {
    let text = format!(
        r#"
        [integrations.t]
        type = "token"
        verify_url = "{}/me"
        {extra}

        [integrations.t.secrets]
        token = ["EXAMPLE_TOKEN", "EXAMPLE_API_TOKEN"]
        "#,
        server.uri()
    );
    match Config::parse(&text)
        .unwrap()
        .integrations
        .remove("t")
        .unwrap()
    {
        Integration::Token(c) => c,
        _ => unreachable!(),
    }
}

fn token(value: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("token".to_string(), value.to_string())])
}

/// `/me` answers `status` to the bearer token `value`.
async fn answer(server: &MockServer, value: &str, status: u16) {
    Mock::given(method("GET"))
        .and(path("/me"))
        .and(header("Authorization", format!("Bearer {value}").as_str()))
        .respond_with(ResponseTemplate::new(status))
        .mount(server)
        .await;
}

#[tokio::test]
async fn login_stores_an_accepted_token_and_check_reports_it() {
    let _scratch = Scratch::new("omnifob-token-test", Endpoints::default());
    let server = MockServer::start().await;
    answer(&server, "good", 200).await;
    let config = config(&server, "");

    // Surrounding whitespace, as a paste brings, is dropped.
    token::login("t", &config, token("  good\n")).await.unwrap();
    assert!(token::has_secrets("t").unwrap());
    let said = token::check("t", &config).await.unwrap();
    assert!(said.starts_with("token accepted by"), "{said}");
    let creds = token::credentials("t", &config).unwrap();
    assert_eq!(creds.env["EXAMPLE_TOKEN"], "good");
    assert_eq!(creds.env["EXAMPLE_API_TOKEN"], "good");
    assert_eq!(creds.expires_at, None);

    assert!(token::logout("t").unwrap());
    assert!(!token::has_secrets("t").unwrap());
    let err = token::check("t", &config).await.unwrap_err();
    assert!(matches!(err, Error::NeedsLogin { .. }), "{err}");
}

#[tokio::test]
async fn login_refuses_a_rejected_token_and_keeps_the_stored_one() {
    let _scratch = Scratch::new("omnifob-token-test", Endpoints::default());
    let server = MockServer::start().await;
    answer(&server, "good", 200).await;
    answer(&server, "revoked", 401).await;
    answer(&server, "scoped", 403).await;
    let config = config(&server, "");
    token::login("t", &config, token("good")).await.unwrap();

    for bad in ["revoked", "scoped"] {
        let err = token::login("t", &config, token(bad))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("the token was rejected"), "{err}");
    }
    // The working token is still the stored one.
    assert_eq!(
        token::credentials("t", &config).unwrap().env["EXAMPLE_TOKEN"],
        "good"
    );
    let err = token::login("t", &config, token(" "))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("missing a value for 'token'"), "{err}");
}

#[tokio::test]
async fn an_outage_is_not_a_rejection() {
    let _scratch = Scratch::new("omnifob-token-test", Endpoints::default());
    let server = MockServer::start().await;
    answer(&server, "good", 200).await;
    let config = config(&server, "");
    token::login("t", &config, token("good")).await.unwrap();

    // The provider goes down: a check says so and asks to try again, and a
    // new token is not stored unchecked.
    server.reset().await;
    answer(&server, "good", 503).await;
    answer(&server, "new", 503).await;
    let err = token::check("t", &config).await.unwrap_err().to_string();
    assert!(
        err.contains("could not check the token") && err.contains("try again later"),
        "{err}"
    );
    assert!(!err.contains("rejected"), "{err}");
    let err = token::login("t", &config, token("new"))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("503"), "{err}");
    assert_eq!(
        token::credentials("t", &config).unwrap().env["EXAMPLE_TOKEN"],
        "good"
    );

    // A token revoked at the provider since sign-in fails its check.
    server.reset().await;
    answer(&server, "good", 401).await;
    let err = token::check("t", &config).await.unwrap_err().to_string();
    assert!(err.contains("the token was rejected (401"), "{err}");
}

#[tokio::test]
async fn a_provider_without_a_check_stores_the_token_as_given() {
    let _scratch = Scratch::new("omnifob-token-test", Endpoints::default());
    // Fly.io has no call every token may make.
    let text = "[integrations.fly]\ntype = \"token\"\npreset = \"fly\"\n";
    let Integration::Token(config) = Config::parse(text)
        .unwrap()
        .integrations
        .remove("fly")
        .unwrap()
    else {
        unreachable!()
    };
    let (name, vars) = token::secrets(&config).unwrap().remove(0);
    token::login(
        "fly",
        &config,
        BTreeMap::from([(name, "FlyV1 fm2_x".into())]),
    )
    .await
    .unwrap();
    assert_eq!(
        token::check("fly", &config).await.unwrap(),
        "token stored; this provider has no check"
    );
    let creds = token::credentials("fly", &config).unwrap();
    for var in vars {
        assert_eq!(creds.env[&var], "FlyV1 fm2_x");
    }
}
