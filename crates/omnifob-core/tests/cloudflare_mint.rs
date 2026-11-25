//! Cloudflare minting against a mock of the v4 API.

mod support;

use std::path::PathBuf;

use jiff::Timestamp;
use omnifob_core::config::{CloudflareConfig, Config, Integration};
use omnifob_core::providers::cloudflare::{
    self, Catalog, Client, Groups, mint, revoke_minted, start_session,
};
use omnifob_core::{Endpoints, paths, providers, store};
use serde_json::{Value, json};
use support::Scratch;
use wiremock::matchers::{header, method, path, query_param};
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
        type = "cloudflare-token"
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
    // Cloudflare's bot protection refuses requests without a user agent
    // (error 1010), so the API client must send the one `http::client` sets.
    let user_agent = concat!("omnifob/", env!("CARGO_PKG_VERSION"));
    Mock::given(method("GET"))
        .and(path(format!("{base}/permission_groups")))
        .and(header("user-agent", user_agent))
        .respond_with(ok(permission_groups()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(base.clone()))
        .and(header("user-agent", user_agent))
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
    assert_eq!(catalog.permission_groups["user"].groups.len(), 5);
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
        permission_groups: [(
            "user".to_string(),
            Groups {
                fetched_at: now() - jiff::SignedDuration::from_hours(1),
                groups: vec![serde_json::from_value(
                    json!({ "id": "g-zone", "name": "Zone Read", "scopes": ["com.cloudflare.api.account.zone"] }),
                )
                .unwrap()],
            },
        )]
        .into(),
        user_tag: None,
        ..Default::default()
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
    assert_eq!(catalog.permission_groups["user"].fetched_at, now());
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

#[tokio::test]
async fn narrow_tokens_carry_ip_conditions_buckets_and_s3_credentials() {
    let server = MockServer::start().await;
    let base = format!("/accounts/{ACCOUNT}/tokens");
    Mock::given(method("GET"))
        .and(path("/cdn-cgi/trace"))
        .respond_with(ResponseTemplate::new(200).set_body_string("fl=1\nip=203.0.113.9\nts=1\n"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("{base}/permission_groups")))
        .respond_with(ok(json!([
            { "id": "g-item", "name": "Workers R2 Storage Bucket Item Write", "scopes": ["com.cloudflare.edge.r2.bucket"] }
        ])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(base.clone()))
        .respond_with(ok(json!({ "id": "tok-id", "value": "abc" })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(base.clone()))
        .respond_with(ok(json!([])))
        .mount(&server)
        .await;

    let text = format!(
        r#"
        [integrations.cf]
        type = "cloudflare-token"
        account_id = "{ACCOUNT}"
        token_type = "account"
        ips = ["198.51.100.0/24"]

        [integrations.cf.templates.backup]
        permissions = ["Workers R2 Storage Bucket Item Edit"]
        r2_buckets = ["logs"]
        s3 = true
        ips = ["current", "2001:db8::/32"]
        "#
    );
    let Integration::Cloudflare(config) = Config::parse(&text)
        .unwrap()
        .integrations
        .remove("cf")
        .unwrap()
    else {
        unreachable!()
    };
    let client = Client::new(server.uri(), "bootstrap");
    let creds = mint(
        &client,
        &config,
        "cf/a/backup",
        ACCOUNT,
        "backup",
        now(),
        &mut Catalog::default(),
    )
    .await
    .unwrap();

    let body = posted_body(&server.received_requests().await.unwrap(), &base);
    assert_eq!(
        body["condition"],
        json!({ "request_ip": { "in": ["203.0.113.9/32", "2001:db8::/32"] } }),
        "the template's ips replace the integration's, and current is resolved"
    );
    assert_eq!(
        body["policies"][0]["resources"],
        json!({ format!("com.cloudflare.edge.r2.bucket.{ACCOUNT}_default_logs"): "*" })
    );
    assert_eq!(creds.env["AWS_ACCESS_KEY_ID"], "tok-id");
    assert_eq!(
        creds.env["AWS_SECRET_ACCESS_KEY"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(creds.env["CLOUDFLARE_API_TOKEN"], "abc");
}

#[tokio::test]
async fn a_session_makes_the_bootstrap_expire_and_ends_the_previous_one() {
    let server = MockServer::start().await;
    let tokens = format!("/accounts/{ACCOUNT}/tokens");
    Mock::given(method("GET"))
        .and(path(format!("{tokens}/boot")))
        .respond_with(ok(json!({
            "id": "boot", "name": "omnifob bootstrap", "status": "active",
            "policies": [{ "effect": "allow", "resources": {}, "permission_groups": [] }],
            "condition": { "request_ip": { "in": ["198.51.100.0/24"] } }
        })))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(format!("{tokens}/boot")))
        .respond_with(ok(json!({ "id": "boot" })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path(format!("{tokens}/old-boot")))
        .respond_with(ok(json!({ "id": "old-boot" })))
        .expect(1)
        .mount(&server)
        .await;

    let client = Client::new(server.uri(), "bootstrap");
    let session = jiff::SignedDuration::from_hours(12);
    let before = Timestamp::now();
    let expires_at = start_session(&client, &tokens, "boot", session, Some("old-boot"))
        .await
        .unwrap();
    assert!(expires_at > before + jiff::SignedDuration::from_mins(719));

    let requests = server.received_requests().await.unwrap();
    let put = requests
        .iter()
        .find(|r| r.method.as_str() == "PUT")
        .unwrap();
    let body: Value = serde_json::from_slice(&put.body).unwrap();
    assert_eq!(body["name"], "omnifob bootstrap");
    assert_eq!(
        body["policies"].as_array().unwrap().len(),
        1,
        "policies are kept"
    );
    assert_eq!(
        body["condition"]["request_ip"]["in"][0], "198.51.100.0/24",
        "an IP filter is kept"
    );
    assert_eq!(
        body["expires_on"]
            .as_str()
            .unwrap()
            .parse::<Timestamp>()
            .unwrap(),
        expires_at
    );
}

/// A signed-in OAuth integration `cf` against a mock, in a context of its
/// own (see [`Scratch`]).
struct SignedIn {
    _scratch: Scratch,
    server: MockServer,
    integration: Integration,
}

impl SignedIn {
    async fn new(test: &str) -> Self {
        let server = MockServer::start().await;
        let endpoints = Endpoints {
            cloudflare_api: Some(server.uri()),
            ..Default::default()
        };
        let scratch = Scratch::new(&format!("omnifob-cf-{test}"), endpoints);
        let integration =
            Config::parse("[integrations.cf]\ntype = \"cloudflare-oauth\"\nclient_id = \"x\"\n")
                .unwrap()
                .integrations
                .remove("cf")
                .unwrap();
        // A browser sign-in that is still valid, so no refresh is attempted.
        store::set(
            "cloudflare/cf/oauth",
            &json!({
                "access_token": "oauth-access",
                "expires_at": Timestamp::now() + jiff::SignedDuration::from_hours(1),
                "refresh_token": null,
                "scopes": [],
            }),
        )
        .unwrap();
        Self {
            _scratch: scratch,
            server,
            integration,
        }
    }

    fn catalog_file() -> PathBuf {
        paths::state_dir().unwrap().join("cloudflare-cf.json")
    }

    fn save_catalog(catalog: &Catalog) {
        std::fs::create_dir_all(paths::state_dir().unwrap()).unwrap();
        std::fs::write(
            Self::catalog_file(),
            serde_json::to_string(catalog).unwrap(),
        )
        .unwrap();
    }

    fn load_catalog() -> Option<Catalog> {
        let text = std::fs::read_to_string(Self::catalog_file()).ok()?;
        Some(serde_json::from_str(&text).unwrap())
    }

    /// Lists `tokens` in `account`, answering only to the OAuth access token.
    async fn lists(&self, account: &str, tokens: Value) {
        Mock::given(method("GET"))
            .and(path(format!("/accounts/{account}/tokens")))
            .and(header("authorization", "Bearer oauth-access"))
            .respond_with(ok(tokens))
            .expect(1)
            .mount(&self.server)
            .await;
    }

    async fn deletes(&self, account: &str, id: &str, response: ResponseTemplate, times: u64) {
        Mock::given(method("DELETE"))
            .and(path(format!("/accounts/{account}/tokens/{id}")))
            .respond_with(response)
            .expect(times)
            .mount(&self.server)
            .await;
    }

    async fn no_user_tokens(&self) {
        Mock::given(method("GET"))
            .and(path("/user/tokens"))
            .respond_with(ok(json!([])))
            .expect(0)
            .mount(&self.server)
            .await;
    }
}

fn tracked(entries: &[(&str, &str)]) -> Catalog {
    let mut catalog = Catalog::default();
    for (profile, id) in entries {
        catalog
            .minted
            .entry((*profile).into())
            .or_default()
            .push((*id).into());
    }
    catalog
}

#[tokio::test]
async fn logout_under_oauth_revokes_the_minted_tokens_of_every_account() {
    let cf = SignedIn::new("logout-all").await;
    SignedIn::save_catalog(&tracked(&[
        ("cf/acct-a/workers", "a1"),
        ("cf/acct-b/workers", "b1"),
        // Tracked, but no listing shows it any more.
        ("cf/acct-b/dns-edit", "gone"),
    ]));
    cf.lists(
        "acct-a",
        json!([
            { "id": "a1", "name": "omnifob workers", "status": "active" },
            { "id": "a9", "name": "terraform", "status": "active" }
        ]),
    )
    .await;
    cf.lists(
        "acct-b",
        json!([
            { "id": "b1", "name": "omnifob workers", "status": "active" },
            { "id": "b2", "name": "omnifob:cf/acct-b/dns@2026-10-06T13:00:00Z", "status": "active" }
        ]),
    )
    .await;
    for (account, id, times) in [
        ("acct-a", "a1", 1),
        ("acct-a", "a9", 0),
        ("acct-b", "b1", 1),
        ("acct-b", "b2", 1),
    ] {
        cf.deletes(account, id, ok(json!({ "id": id })), times)
            .await;
    }
    cf.no_user_tokens().await;

    let accounts = ["acct-a".to_string(), "acct-b".to_string()];
    let deleted = providers::revoke_all("cf", &cf.integration, &accounts)
        .await
        .unwrap();
    assert_eq!(deleted, 3);
    let saved = SignedIn::load_catalog().unwrap();
    assert!(saved.minted.is_empty(), "{:?}", saved.minted);

    assert!(cloudflare::logout("cf").unwrap());
    assert!(
        SignedIn::load_catalog().is_none(),
        "nothing left to remember"
    );
    cf.server.verify().await;
}

#[tokio::test]
async fn logout_goes_on_past_an_account_that_fails_and_remembers_what_is_left() {
    let cf = SignedIn::new("logout-partial").await;
    let mut catalog = tracked(&[
        ("cf/acct-a/workers", "a1"),
        ("cf/acct-a/dns-edit", "a2"),
        ("cf/acct-b/workers", "b1"),
    ]);
    catalog.user_tag = Some("tag".into());
    SignedIn::save_catalog(&catalog);
    cf.lists(
        "acct-a",
        json!([
            { "id": "a1", "name": "omnifob workers", "status": "active" },
            { "id": "a2", "name": "omnifob dns-edit", "status": "active" }
        ]),
    )
    .await;
    cf.lists(
        "acct-b",
        json!([{ "id": "b1", "name": "omnifob workers", "status": "active" }]),
    )
    .await;
    let refused = ResponseTemplate::new(500).set_body_json(json!({
        "success": false,
        "errors": [{ "code": 1000, "message": "try again later" }],
        "messages": [],
        "result": null
    }));
    cf.deletes("acct-a", "a1", refused, 1).await;
    cf.deletes("acct-a", "a2", ok(json!({ "id": "a2" })), 1)
        .await;
    cf.deletes("acct-b", "b1", ok(json!({ "id": "b1" })), 1)
        .await;
    cf.no_user_tokens().await;

    let accounts = ["acct-a".to_string(), "acct-b".to_string()];
    let err = providers::revoke_all("cf", &cf.integration, &accounts)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("try again later"), "{err:#}");
    cf.server.verify().await;

    // Only the token that could not be deleted is still tracked, and signing
    // out keeps that, so a later sign-in still recognises it.
    assert!(cloudflare::logout("cf").unwrap());
    let kept = SignedIn::load_catalog().unwrap();
    assert_eq!(
        kept.minted.into_iter().collect::<Vec<_>>(),
        [("cf/acct-a/workers".to_string(), vec!["a1".to_string()])]
    );
    assert_eq!(kept.user_tag, None, "the rest of the catalog is dropped");
}

#[tokio::test]
async fn sync_under_oauth_prunes_expired_tokens_of_every_account() {
    let cf = SignedIn::new("cleanup-all").await;
    SignedIn::save_catalog(&tracked(&[
        ("cf/acct-a/workers", "a1"),
        ("cf/acct-b/workers", "b1"),
        // Tracked, but deleted outside omnifob: no listing shows it.
        ("cf/acct-b/dns-edit", "gone"),
    ]));
    cf.lists(
        "acct-a",
        json!([{ "id": "a1", "name": "omnifob workers", "status": "active" }]),
    )
    .await;
    cf.lists(
        "acct-b",
        json!([{
            "id": "b1", "name": "omnifob workers", "status": "active",
            "expires_on": "2026-01-01T00:00:00Z"
        }]),
    )
    .await;
    cf.deletes("acct-a", "a1", ok(json!({ "id": "a1" })), 0)
        .await;
    cf.deletes("acct-b", "b1", ok(json!({ "id": "b1" })), 1)
        .await;
    cf.no_user_tokens().await;

    let Integration::Cloudflare(config) = &cf.integration else {
        unreachable!()
    };
    let accounts = ["acct-a".to_string(), "acct-b".to_string()];
    let deleted = cloudflare::cleanup("cf", config, &accounts).await.unwrap();
    assert_eq!(
        deleted, 1,
        "the second account's expired token is recognised"
    );
    cf.server.verify().await;
    let saved = SignedIn::load_catalog().unwrap();
    assert_eq!(
        saved.minted.into_iter().collect::<Vec<_>>(),
        [("cf/acct-a/workers".to_string(), vec!["a1".to_string()])],
        "the live token stays tracked; the pruned and the missing ones are forgotten"
    );
}

#[tokio::test]
async fn each_account_keeps_its_own_permission_groups() {
    let server = MockServer::start().await;
    for account in ["acct-a", "acct-b"] {
        let base = format!("/accounts/{account}/tokens");
        // Fetched once per account, then served from the catalog.
        Mock::given(method("GET"))
            .and(path(format!("{base}/permission_groups")))
            .respond_with(ok(account_permission_groups()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(base.clone()))
            .respond_with(ok(json!({ "value": "secret" })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(base))
            .respond_with(ok(json!([])))
            .mount(&server)
            .await;
    }
    let client = Client::new(server.uri(), "bootstrap");
    let config = config("account", r#""Zone Read""#);
    let mut catalog = Catalog::default();
    for account in ["acct-a", "acct-b", "acct-a", "acct-b"] {
        mint(&client, &config, "p", account, "t", now(), &mut catalog)
            .await
            .unwrap();
    }
    let keys: Vec<_> = catalog.permission_groups.keys().cloned().collect();
    assert_eq!(keys, ["account/acct-a", "account/acct-b"]);
}

#[tokio::test]
async fn an_answer_that_is_not_json_is_quoted() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/user/tokens/permission_groups"))
        .respond_with(
            ResponseTemplate::new(502)
                .set_body_string("<html>\n<title>502 Bad Gateway</title>\n</html>"),
        )
        .mount(&server)
        .await;
    let err = Client::new(server.uri(), "bootstrap")
        .permission_groups(omnifob_core::config::CloudflareTokenType::User, ACCOUNT)
        .await
        .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("502"), "{msg}");
    assert!(
        msg.contains("<html> <title>502 Bad Gateway</title> </html>"),
        "{msg}"
    );
}

#[tokio::test]
async fn renaming_files_the_minted_tokens_under_the_new_name_and_back() {
    let _cf = SignedIn::new("rename").await;
    let original = tracked(&[("cf/acct/workers", "w1"), ("cf/acct/dns", "d1")]);
    SignedIn::save_catalog(&original);

    cloudflare::rename_catalog("cf", "cf2").unwrap();
    assert!(!SignedIn::catalog_file().exists());
    let moved: Catalog = serde_json::from_str(
        &std::fs::read_to_string(paths::state_dir().unwrap().join("cloudflare-cf2.json")).unwrap(),
    )
    .unwrap();
    let keys: Vec<_> = moved.minted.keys().cloned().collect();
    assert_eq!(keys, ["cf2/acct/dns", "cf2/acct/workers"]);

    // As `fob rename` rolls back when the config cannot be written.
    cloudflare::rename_catalog("cf2", "cf").unwrap();
    assert_eq!(SignedIn::load_catalog().unwrap().minted, original.minted);
    // Nothing to move is no error.
    cloudflare::rename_catalog("none", "other").unwrap();
}

#[tokio::test]
async fn concurrent_catalog_updates_keep_every_tracked_token() {
    let _cf = SignedIn::new("concurrent").await;
    SignedIn::save_catalog(&Catalog::default());
    let threads: Vec<_> = (0..8)
        .map(|i| {
            // A thread starts outside the test's context.
            let context = omnifob_core::Context::current();
            std::thread::spawn(move || {
                let _context = context.enter();
                for j in 0..10 {
                    cloudflare::update_catalog("cf", |c| {
                        c.minted
                            .entry(format!("cf/acct/t{i}"))
                            .or_default()
                            .push(format!("id-{i}-{j}"));
                    })
                    .unwrap();
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    let catalog = SignedIn::load_catalog().unwrap();
    assert_eq!(catalog.minted.values().flatten().count(), 80);
}

#[tokio::test]
async fn an_unreadable_catalog_is_never_replaced() {
    let _cf = SignedIn::new("unreadable").await;
    std::fs::create_dir_all(paths::state_dir().unwrap()).unwrap();
    std::fs::write(SignedIn::catalog_file(), "{ not json").unwrap();
    let err = cloudflare::update_catalog("cf", |c| {
        c.minted
            .entry("cf/a/t".into())
            .or_default()
            .push("x".into());
    })
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("delete it to start over"),
        "{err:#}"
    );
    assert_eq!(
        std::fs::read_to_string(SignedIn::catalog_file()).unwrap(),
        "{ not json",
        "left as it was"
    );
    assert!(cloudflare::rename_catalog("cf", "cf2").is_err());
    assert!(SignedIn::catalog_file().exists());
}

/// Accounts whose names slug alike keep their profiles apart with their IDs,
/// every template of an account moving together.
#[tokio::test]
async fn accounts_named_alike_get_their_ids() {
    let cf = SignedIn::new("named-alike").await;
    Mock::given(method("GET"))
        .and(path("/accounts"))
        .respond_with(ok(json!([
            { "id": "aaa", "name": "Acme (EU)" },
            { "id": "bbb", "name": "ACME EU" },
            { "id": "ccc", "name": "Other" }
        ])))
        .mount(&cf.server)
        .await;
    let Integration::Cloudflare(config) = &cf.integration else {
        unreachable!()
    };
    let profiles = cloudflare::discover("cf", config).await.unwrap();
    let ids: Vec<&str> = profiles
        .iter()
        .filter(|p| p.id.ends_with("/read"))
        .map(|p| p.id.as_str())
        .collect();
    assert_eq!(
        ids,
        [
            "cf/acme-eu-aaa/read",
            "cf/acme-eu-bbb/read",
            "cf/other/read"
        ]
    );
    let mut all: Vec<&str> = profiles.iter().map(|p| p.id.as_str()).collect();
    let count = all.len();
    all.dedup();
    assert_eq!(all.len(), count, "no two profiles share an id");
    assert!(profiles.iter().all(|p| !p.id.starts_with("cf/acme-eu/")));
}
