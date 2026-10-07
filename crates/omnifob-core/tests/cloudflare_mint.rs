//! Cloudflare minting against a mock of the v4 API.

use jiff::Timestamp;
use omnifob_core::config::{CloudflareConfig, Config, Integration};
use omnifob_core::providers::cloudflare::{Catalog, Client, mint, revoke_minted};
use serde_json::{Value, json};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const ACCOUNT: &str = "acct123";

fn ok(result: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "success": true,
        "errors": [],
        "messages": [],
        "result": result,
        "result_info": { "page": 1, "total_pages": 1 }
    }))
}

fn config(token_type: &str, permissions: &str) -> CloudflareConfig {
    config_with_optional(
        token_type,
        permissions,
        r#""Browser Run Write", "Not Offered Here Write""#,
    )
}

fn config_with_optional(token_type: &str, permissions: &str, optional: &str) -> CloudflareConfig {
    let text = format!(
        r#"
        [integrations.cf]
        type = "cloudflare"
        account_id = "{ACCOUNT}"
        token_type = "{token_type}"
        ttl = "1h"

        [integrations.cf.templates.t]
        permissions = [{permissions}]
        optional = [{optional}]
        ttl = "2h"
        "#
    );
    match Config::parse(&text)
        .unwrap()
        .integrations
        .remove("cf")
        .unwrap()
    {
        Integration::Cloudflare(c) => c,
        _ => unreachable!(),
    }
}

/// What the account-level endpoint returns: no user-level groups.
fn account_permission_groups() -> Value {
    let mut groups = permission_groups();
    groups
        .as_array_mut()
        .unwrap()
        .retain(|g| g["scopes"][0] != "com.cloudflare.api.user");
    groups
}

fn permission_groups() -> Value {
    json!([
        { "id": "g-workers", "name": "Workers Scripts Write", "scopes": ["com.cloudflare.api.account"] },
        { "id": "g-zone", "name": "Zone Read", "scopes": ["com.cloudflare.api.account.zone"] },
        { "id": "g-dns", "name": "DNS Write", "scopes": ["com.cloudflare.api.account.zone"] },
        { "id": "g-user", "name": "User Details Read", "scopes": ["com.cloudflare.api.user"] },
        { "id": "g-browser", "name": "Browser Run Edit", "scopes": ["com.cloudflare.api.account"] }
    ])
}

fn now() -> Timestamp {
    "2026-10-06T12:00:00.4Z".parse().unwrap()
}

fn posted_body(server_requests: &[Request], path_: &str) -> Value {
    let post = server_requests
        .iter()
        .find(|r| r.method.as_str() == "POST" && r.url.path() == path_)
        .expect("no token was created");
    serde_json::from_slice(&post.body).unwrap()
}

#[tokio::test]
async fn user_token_is_scoped_named_and_old_tokens_are_pruned() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user/tokens/permission_groups"))
        .respond_with(ok(permission_groups()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/user/tokens/verify"))
        .respond_with(ok(json!({ "id": "boot", "status": "active" })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/user/tokens/boot"))
        .respond_with(ok(json!({
            "id": "boot",
            "policies": [{ "resources": { "com.cloudflare.api.user.usertag9": "*" } }]
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/user/tokens"))
        .respond_with(ok(json!({ "id": "new", "value": "minted-secret" })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/user/tokens"))
        .and(query_param("page", "1"))
        .respond_with(ok(json!([
            { "id": "old-ours", "name": "omnifob:cf/a/t@2026-10-01T00:00:00Z", "status": "expired" },
            { "id": "old-expiry", "name": "omnifob:cf/a/t@x", "status": "active", "expires_on": "2026-10-06T11:00:00Z" },
            { "id": "fresh-ours", "name": "omnifob:cf/a/t@y", "status": "active", "expires_on": "2026-10-06T13:00:00Z" },
            { "id": "theirs", "name": "terraform", "status": "expired" },
            { "id": "tracked-old", "name": "omnifob t", "status": "expired" },
            { "id": "bootstrap", "name": "omnifob bootstrap", "status": "expired" }
        ])))
        .mount(&server)
        .await;
    for id in ["old-ours", "old-expiry", "tracked-old"] {
        Mock::given(method("DELETE"))
            .and(path(format!("/user/tokens/{id}")))
            .respond_with(ok(json!({ "id": id })))
            .expect(1)
            .mount(&server)
            .await;
    }
    // Never touched: a live legacy token, someone else's token, and an
    // omnifob-looking name that omnifob did not mint (the bootstrap).
    for id in ["fresh-ours", "theirs", "bootstrap"] {
        Mock::given(method("DELETE"))
            .and(path(format!("/user/tokens/{id}")))
            .respond_with(ok(json!({})))
            .expect(0)
            .mount(&server)
            .await;
    }

    let client = Client::new(server.uri(), "bootstrap");
    let config = config(
        "user",
        r#""Workers Scripts Edit", "DNS Write", "Zone Read", "User Details Read""#,
    );
    let mut catalog = Catalog::default();
    catalog
        .minted
        .insert("cf/a/t".into(), vec!["tracked-old".into()]);
    let creds = mint(
        &client,
        &config,
        "cf/a/t",
        ACCOUNT,
        "t",
        now(),
        &mut catalog,
    )
    .await
    .unwrap();
    assert_eq!(
        catalog.minted["cf/a/t"],
        ["new"],
        "the new token is tracked, the deleted one forgotten"
    );

    assert_eq!(creds.env["CLOUDFLARE_API_TOKEN"], "minted-secret");
    assert_eq!(
        creds.token_id.as_deref(),
        Some("new"),
        "the token ID is kept so the token can be revoked early"
    );
    assert_eq!(creds.env["CLOUDFLARE_ACCOUNT_ID"], ACCOUNT);
    assert_eq!(
        creds.expires_at.unwrap().to_string(),
        "2026-10-06T14:00:00Z"
    );

    let requests = server.received_requests().await.unwrap();
    let body = posted_body(&requests, "/user/tokens");
    assert_eq!(body["name"], "omnifob t");
    assert_eq!(body["expires_on"], "2026-10-06T14:00:00Z");
    assert!(body.get("not_before").is_none());

    let policies = body["policies"].as_array().unwrap();
    assert_eq!(policies.len(), 3, "{policies:#?}");
    let find = |id: &str| {
        policies
            .iter()
            .find(|p| {
                p["permission_groups"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|g| g["id"] == id)
            })
            .unwrap()
    };
    assert_eq!(
        find("g-workers")["resources"],
        json!({ "com.cloudflare.api.account.acct123": "*" })
    );
    // The optional permission is offered under its "Edit" name and joins the
    // other account permissions; the one not offered is skipped.
    assert_eq!(
        find("g-browser")["resources"],
        find("g-workers")["resources"]
    );
    let granted: Vec<&Value> = policies
        .iter()
        .flat_map(|p| p["permission_groups"].as_array().unwrap())
        .map(|g| &g["id"])
        .collect();
    assert_eq!(granted.len(), 5, "{granted:?}");
    assert_eq!(
        find("g-dns")["resources"],
        json!({ "com.cloudflare.api.account.acct123": { "com.cloudflare.api.account.zone.*": "*" } })
    );
    assert_eq!(
        find("g-dns")["permission_groups"].as_array().unwrap().len(),
        2
    );
    assert_eq!(
        find("g-user")["resources"],
        json!({ "com.cloudflare.api.user.usertag9": "*" })
    );
    assert!(policies.iter().all(|p| p["effect"] == "allow"));

    for request in &requests {
        assert_eq!(request.headers["authorization"], "Bearer bootstrap");
    }
}

#[tokio::test]
async fn account_tokens_use_account_endpoints() {
    let server = MockServer::start().await;
    let base = format!("/accounts/{ACCOUNT}/tokens");
    Mock::given(method("GET"))
        .and(path(format!("{base}/permission_groups")))
        .respond_with(ok(permission_groups()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(base.clone()))
        .respond_with(ok(json!({ "value": "acct-secret" })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(base.clone()))
        .respond_with(ok(json!([])))
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "bootstrap");
    let creds = mint(
        &client,
        &config("account", r#""Zone Read""#),
        "cf/a/t",
        ACCOUNT,
        "t",
        now(),
        &mut Catalog::default(),
    )
    .await
    .unwrap();
    assert_eq!(creds.env["CLOUDFLARE_API_TOKEN"], "acct-secret");
}

#[tokio::test]
async fn account_tokens_leave_out_user_permissions() {
    let server = MockServer::start().await;
    let base = format!("/accounts/{ACCOUNT}/tokens");
    Mock::given(method("GET"))
        .and(path(format!("{base}/permission_groups")))
        // Like the real API: the account endpoint offers no user-level groups.
        .respond_with(ok(account_permission_groups()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(base.clone()))
        .respond_with(ok(json!({ "id": "acct-tok", "value": "acct-secret" })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(base.clone()))
        .respond_with(ok(json!([])))
        .mount(&server)
        .await;

    // Like the built-in workers template: user-level permissions are optional,
    // so an account-owned bootstrap simply goes without them.
    let client = Client::new(server.uri(), "bootstrap");
    mint(
        &client,
        &config_with_optional(
            "account",
            r#""Workers Scripts Write""#,
            r#""User Details Read", "Browser Run Write""#,
        ),
        "p",
        ACCOUNT,
        "t",
        now(),
        &mut Catalog::default(),
    )
    .await
    .unwrap();

    let requests = server.received_requests().await.unwrap();
    let body = posted_body(&requests, &base);
    let policies = body["policies"].as_array().unwrap();
    assert_eq!(policies.len(), 1, "{policies:#?}");
    let mut ids: Vec<&str> = policies[0]["permission_groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["id"].as_str().unwrap())
        .collect();
    ids.sort_unstable();
    // The test config's optional "Browser Run Write" is account-level and stays.
    assert_eq!(ids, ["g-browser", "g-workers"]);
    assert!(!body.to_string().contains("com.cloudflare.api.user"));
}

#[tokio::test]
async fn unknown_permissions_fail_before_minting() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user/tokens/permission_groups"))
        .respond_with(ok(permission_groups()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ok(json!({})))
        .expect(0)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "bootstrap");
    let err = mint(
        &client,
        &config("user", r#""Workers Script Write""#),
        "p",
        ACCOUNT,
        "t",
        now(),
        &mut Catalog::default(),
    )
    .await
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("did you mean: Workers Scripts Write"), "{msg}");
}

#[tokio::test]
async fn api_errors_are_reported_with_their_message() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user/tokens/permission_groups"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "success": false,
            "errors": [{ "code": 9109, "message": "Unauthorized to access requested resource" }],
            "messages": [],
            "result": null
        })))
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "bootstrap");
    let err = mint(
        &client,
        &config("user", r#""Zone Read""#),
        "p",
        ACCOUNT,
        "t",
        now(),
        &mut Catalog::default(),
    )
    .await
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Unauthorized to access requested resource (code 9109)"),
        "{msg}"
    );
    assert!(msg.contains("403"), "{msg}");
}

#[tokio::test]
async fn unknown_template_is_an_error() {
    let client = Client::new("http://127.0.0.1:9", "bootstrap");
    let err = mint(
        &client,
        &config("user", r#""Zone Read""#),
        "p",
        ACCOUNT,
        "nope",
        now(),
        &mut Catalog::default(),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("no Cloudflare template named 'nope'")
    );
}

#[tokio::test]
async fn waits_until_d1_accepts_a_new_token() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user/tokens/permission_groups"))
        .respond_with(ok(json!([
            { "id": "g-d1", "name": "D1 Write", "scopes": ["com.cloudflare.api.account"] }
        ])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/user/tokens"))
        .respond_with(ok(json!({ "value": "fresh" })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/user/tokens"))
        .respond_with(ok(json!([])))
        .mount(&server)
        .await;
    let d1 = format!("/accounts/{ACCOUNT}/d1/database");
    // Rejected twice, as D1 does right after a token is created, then accepted;
    // omnifob waits for three acceptances in a row.
    Mock::given(method("GET"))
        .and(path(d1.clone()))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "success": false, "errors": [{ "code": 10000, "message": "Authentication error" }], "result": null
        })))
        .up_to_n_times(2)
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(d1.clone()))
        .respond_with(ok(json!([])))
        .expect(3)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "bootstrap");
    mint(
        &client,
        &config("user", r#""D1 Write""#),
        "p",
        ACCOUNT,
        "t",
        now(),
        &mut Catalog::default(),
    )
    .await
    .unwrap();

    let requests = server.received_requests().await.unwrap();
    let d1_auth: Vec<_> = requests
        .iter()
        .filter(|r| r.url.path() == d1)
        .map(|r| r.headers["authorization"].to_str().unwrap().to_string())
        .collect();
    assert_eq!(
        d1_auth, ["Bearer fresh"; 5],
        "polls with the new token, not the bootstrap one"
    );
}

#[tokio::test]
async fn a_current_catalog_saves_the_lookups() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user/tokens/permission_groups"))
        .respond_with(ok(permission_groups()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/user/tokens/verify"))
        .respond_with(ok(json!({ "id": "boot", "status": "active" })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/user/tokens/boot"))
        .respond_with(ok(json!({
            "id": "boot",
            "policies": [{ "resources": { "com.cloudflare.api.user.usertag9": "*" } }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/user/tokens"))
        .respond_with(ok(json!({ "value": "minted" })))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/user/tokens"))
        .respond_with(ok(json!([])))
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "bootstrap");
    let config = config("user", r#""Zone Read", "User Details Read""#);
    let mut catalog = Catalog::default();
    for _ in 0..2 {
        mint(&client, &config, "p", ACCOUNT, "t", now(), &mut catalog)
            .await
            .unwrap();
    }
    assert_eq!(catalog.user_tag.as_deref(), Some("usertag9"));
    assert_eq!(catalog.groups.len(), 5);
}

#[tokio::test]
async fn a_catalog_missing_a_permission_is_refreshed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user/tokens/permission_groups"))
        .respond_with(ok(permission_groups()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/user/tokens"))
        .respond_with(ok(json!({ "value": "minted" })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/user/tokens"))
        .respond_with(ok(json!([])))
        .mount(&server)
        .await;

    // Fetched an hour ago, before "DNS Write" existed.
    let mut catalog = Catalog {
        fetched_at: Some(now() - jiff::SignedDuration::from_hours(1)),
        groups: vec![serde_json::from_value(
            json!({ "id": "g-zone", "name": "Zone Read", "scopes": ["com.cloudflare.api.account.zone"] }),
        )
        .unwrap()],
        user_tag: None,
        minted: Default::default(),
    };
    let client = Client::new(server.uri(), "bootstrap");
    mint(
        &client,
        &config("user", r#""DNS Write""#),
        "p",
        ACCOUNT,
        "t",
        now(),
        &mut catalog,
    )
    .await
    .unwrap();
    assert_eq!(catalog.fetched_at, Some(now()));
}

#[tokio::test]
async fn revoke_deletes_only_this_profiles_tokens() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user/tokens"))
        .respond_with(ok(json!([
            { "id": "n1", "name": "omnifob workers", "status": "active" },
            { "id": "n2", "name": "omnifob workers", "status": "active" },
            { "id": "a1", "name": "omnifob:cf/acct/workers@2026-10-06T12:00:00Z", "status": "active" },
            { "id": "a2", "name": "omnifob:cf/acct/workers@2026-10-06T13:00:00Z", "status": "active" },
            { "id": "b1", "name": "omnifob:cf/acct/workers-2@2026-10-06T13:00:00Z", "status": "active" },
            { "id": "c1", "name": "omnifob:cf/acct/dns-edit@2026-10-06T13:00:00Z", "status": "active" },
            { "id": "d1", "name": "terraform", "status": "active" }
        ])))
        .mount(&server)
        .await;
    // n1 is tracked for this profile; n2 has the same name but belongs to
    // another profile; a1 and a2 are legacy names of this profile.
    for (id, times) in [
        ("n1", 1),
        ("n2", 0),
        ("a1", 1),
        ("a2", 1),
        ("b1", 0),
        ("c1", 0),
        ("d1", 0),
    ] {
        Mock::given(method("DELETE"))
            .and(path(format!("/user/tokens/{id}")))
            .respond_with(ok(json!({ "id": id })))
            .expect(times)
            .mount(&server)
            .await;
    }
    let mut catalog = Catalog::default();
    catalog
        .minted
        .insert("cf/acct/workers".into(), vec!["n1".into()]);
    catalog
        .minted
        .insert("cf/other/workers".into(), vec!["n2".into()]);
    let client = Client::new(server.uri(), "bootstrap");
    let n = revoke_minted(
        &client,
        "/user/tokens",
        Some("cf/acct/workers"),
        &mut catalog,
    )
    .await
    .unwrap();
    assert_eq!(n, 3);
    assert!(!catalog.minted.contains_key("cf/acct/workers"));
    assert_eq!(catalog.minted["cf/other/workers"], ["n2"]);
}
