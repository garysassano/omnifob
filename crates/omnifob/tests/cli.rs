//! End-to-end tests: each runs the built `fob` binary against its own
//! scratch config, state directory and plaintext test store
//! (`OMNIFOB_KEYRING=test-plaintext-files:<dir>`), with every AWS call sent to
//! a local mock (`OMNIFOB_AWS_ENDPOINT`). Nothing touches the real keychain,
//! a browser or the network beyond localhost, so the tests run in parallel.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const FOB: &str = env!("CARGO_BIN_EXE_fob");
const START_URL: &str = "https://acme.awsapps.com/start";

/// One isolated fob installation in a scratch directory, removed on drop.
struct Fob {
    root: PathBuf,
    endpoint: Option<String>,
}

impl Fob {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("omnifob-e2e-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("aws")).unwrap();
        Self {
            root,
            endpoint: None,
        }
    }

    /// Sends every AWS call to `server`.
    fn with_server(mut self, server: &MockServer) -> Self {
        self.endpoint = Some(server.uri());
        self
    }

    fn config_file(&self) -> PathBuf {
        self.root.join("config.toml")
    }

    fn keyring(&self) -> PathBuf {
        self.root.join("keyring")
    }

    fn aws_config(&self) -> PathBuf {
        self.root.join("aws").join("config")
    }

    fn write_config(&self, text: &str) {
        std::fs::write(self.config_file(), text).unwrap();
    }

    /// The store's file for a keychain key, as the test store names it.
    fn secret(&self, key: &str) -> PathBuf {
        self.keyring()
            .join(omnifob_core::files::encode_key_filename(key))
    }

    /// Stores an Identity Center sign-in for `integration`, valid until 2100,
    /// as `fob login` would.
    fn sign_in(&self, integration: &str) {
        std::fs::create_dir_all(self.keyring()).unwrap();
        let token = json!({
            "start_url": START_URL,
            "region": "eu-west-1",
            "access_token": "access-1",
            "expires_at": "2100-01-01T00:00:00Z",
            "refresh_token": null,
            "client_id": "client-1",
            "client_secret": "client-secret-1",
            "client_expires_at": "2100-01-01T00:00:00Z",
        });
        std::fs::write(
            self.secret(&format!("aws-sso/{integration}/token")),
            token.to_string(),
        )
        .unwrap();
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(FOB);
        cmd.args(args);
        // Nothing from the developer's or the CI runner's setup leaks in.
        for (name, _) in std::env::vars_os() {
            let name = name.to_string_lossy();
            let proxy = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"]
                .iter()
                .any(|p| name.eq_ignore_ascii_case(p));
            // Agents' markers too, so the tests run alike under an agent.
            let agent = [
                "AI_AGENT",
                "CLAUDECODE",
                "GEMINI_CLI",
                "CURSOR_AGENT",
                "CODEX_SANDBOX",
                "CODEX_THREAD_ID",
                "COPILOT_AGENT_SESSION_ID",
                "COPILOT_CLI",
                "OPENCODE",
                "CRUSH",
                "QWEN_CODE",
                "CLINE_ACTIVE",
                "GOOSE_TERMINAL",
                "PI_CODING_AGENT",
                "ANTIGRAVITY_AGENT",
            ]
            .contains(&&*name);
            if name.starts_with("AWS_")
                || name.starts_with("OMNIFOB_")
                || name == "COMPLETE"
                || proxy
                || agent
            {
                cmd.env_remove(&*name);
            }
        }
        // A proxy must not get between fob and the local mock.
        cmd.env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost");
        cmd.env("OMNIFOB_CONFIG", self.config_file())
            .env("XDG_STATE_HOME", self.root.join("state"))
            .env(
                "OMNIFOB_KEYRING",
                format!("test-plaintext-files:{}", self.keyring().display()),
            )
            .env("AWS_CONFIG_FILE", self.aws_config());
        if let Some(endpoint) = &self.endpoint {
            cmd.env("OMNIFOB_AWS_ENDPOINT", endpoint);
        }
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("running fob")
    }

    /// Runs fob as Claude Code runs commands.
    fn run_as_agent(&self, args: &[&str]) -> Output {
        self.command(args)
            .env("CLAUDECODE", "1")
            .output()
            .expect("running fob")
    }

    /// Runs fob, expecting success; returns stdout and stderr.
    fn ok(&self, args: &[&str]) -> (String, String) {
        let output = self.run(args);
        let (stdout, stderr) = texts(&output);
        assert!(
            output.status.success(),
            "fob {args:?} failed\nstdout: {stdout}\nstderr: {stderr}"
        );
        (stdout, stderr)
    }

    /// Runs fob, expecting failure; returns stderr.
    fn fails(&self, args: &[&str]) -> String {
        let output = self.run(args);
        let (stdout, stderr) = texts(&output);
        assert!(
            !output.status.success(),
            "fob {args:?} succeeded\nstdout: {stdout}\nstderr: {stderr}"
        );
        stderr
    }
}

impl Drop for Fob {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// stdout and stderr, with Windows line endings made Unix ones.
fn texts(output: &Output) -> (String, String) {
    let text = |b: &[u8]| String::from_utf8_lossy(b).replace("\r\n", "\n");
    (text(&output.stdout), text(&output.stderr))
}

fn lines(text: &str) -> Vec<&str> {
    text.lines().collect()
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn portal_config(name: &str) -> String {
    format!(
        r#"[integrations.{name}]
type = "aws-sso"
start_url = "{START_URL}"
region = "eu-west-1"
default_region = "eu-central-1"
"#
    )
}

/// The portal assigns `Admin` in each of `accounts` (id, name).
async fn mount_portal(server: &MockServer, accounts: &[(&str, &str)]) {
    let list: Vec<Value> = accounts
        .iter()
        .map(|(id, name)| json!({ "accountId": id, "accountName": name }))
        .collect();
    Mock::given(method("GET"))
        .and(path("/assignment/accounts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "accountList": list })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/assignment/roles"))
        .respond_with(|r: &Request| {
            let account = query(r, "account_id");
            ResponseTemplate::new(200).set_body_json(json!({
                "roleList": [{ "roleName": "Admin", "accountId": account }]
            }))
        })
        .mount(server)
        .await;
}

fn query(request: &Request, name: &str) -> String {
    request
        .url
        .query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

/// `GetRoleCredentials`: the access key names the account it is for.
async fn mount_role_credentials(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/federation/credentials"))
        .respond_with(|r: &Request| {
            let account = query(r, "account_id");
            ResponseTemplate::new(200).set_body_json(json!({
                "roleCredentials": {
                    "accessKeyId": format!("ASIA{account}"),
                    "secretAccessKey": "role-secret",
                    "sessionToken": "role-session",
                    "expiration": 4_102_444_800_000i64,
                }
            }))
        })
        .mount(server)
        .await;
}

/// An STS `AssumeRole` response with access key `key`.
fn assume_role(key: &str) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("content-type", "text/xml")
        .set_body_string(format!(
            r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>{key}</AccessKeyId><SecretAccessKey>s</SecretAccessKey><SessionToken>t</SessionToken><Expiration>2100-01-01T00:00:00Z</Expiration></Credentials><AssumedRoleUser><AssumedRoleId>AROA:omnifob</AssumedRoleId><Arn>arn:aws:sts::333333333333:assumed-role/Deploy/omnifob</Arn></AssumedRoleUser></AssumeRoleResult><ResponseMetadata><RequestId>1</RequestId></ResponseMetadata></AssumeRoleResponse>"#
        ))
}

/// A portal signed in and synced: `acme/dev/Admin` and `acme/prod/Admin`.
async fn synced_portal(name: &str) -> (Fob, MockServer) {
    let server = MockServer::start().await;
    let fob = Fob::new(name).with_server(&server);
    fob.write_config(&portal_config("acme"));
    fob.sign_in("acme");
    mount_portal(
        &server,
        &[("111111111111", "Dev"), ("222222222222", "Prod")],
    )
    .await;
    mount_role_credentials(&server).await;
    fob.ok(&["sync"]);
    (fob, server)
}

#[test]
fn help_and_version() {
    let fob = Fob::new("help");
    let (stdout, _) = fob.ok(&["--help"]);
    assert!(stdout.contains("One sign-in for every cloud"), "{stdout}");
    assert!(stdout.contains("Usage: fob"), "{stdout}");
    let (stdout, _) = fob.ok(&["--version"]);
    assert_eq!(stdout, format!("fob {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn the_test_store_needs_an_absolute_directory_and_says_it_is_unsafe() {
    let fob = Fob::new("store");
    fob.write_config(&portal_config("acme"));
    let (stdout, stderr) = fob.ok(&["status"]);
    assert!(stderr.contains("UNENCRYPTED"), "{stderr}");
    assert!(stdout.contains("unencrypted files in"), "{stdout}");
    for value in ["test-plaintext-files", "test-plaintext-files:relative"] {
        let output = fob
            .command(&["status"])
            .env("OMNIFOB_KEYRING", value)
            .output()
            .unwrap();
        let (_, stderr) = texts(&output);
        assert!(!output.status.success(), "{value}");
        assert!(stderr.contains("directory"), "{stderr}");
    }
}

#[test]
fn a_bad_integration_name_points_at_fob_rename_which_fixes_it() {
    let fob = Fob::new("rename");
    fob.write_config(&format!(
        "{}\n[agent]\nprofiles = [\"my portal/dev/*\", \"other/*/*\"]\n",
        portal_config("\"my portal\"")
    ));
    fob.sign_in("my portal");
    let stderr = fob.fails(&["status"]);
    assert!(
        stderr.contains("fob rename \"my portal\" <new-name>"),
        "{stderr}"
    );
    let stderr = fob.fails(&["rename", "my portal", "bad name"]);
    assert!(stderr.contains("'bad name'"), "{stderr}");

    let (_, stderr) = fob.ok(&["rename", "my portal", "acme"]);
    assert!(
        stderr.contains("renamed 'my portal' to 'acme' (kept the sign-in)"),
        "{stderr}"
    );
    assert!(
        stderr.contains("still names 'my portal' (my portal/dev/*)"),
        "{stderr}"
    );
    assert!(!stderr.contains("other/*/*"), "{stderr}");
    assert!(fob.secret("aws-sso/acme/token").exists());
    assert!(!fob.secret("aws-sso/my portal/token").exists());
    let config = std::fs::read_to_string(fob.config_file()).unwrap();
    assert!(config.contains("[integrations.acme]"), "{config}");
    let (stdout, _) = fob.ok(&["status"]);
    assert!(
        stdout.contains("signed in until 2100-01-01 00:00 UTC"),
        "{stdout}"
    );
}

/// Identity Center answers a device-flow sign-in at once: it registers
/// `client-1`, and the token comes back on the first poll.
async fn mount_device_sign_in(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/client/register"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "clientId": "client-1",
            "clientSecret": "client-secret-1",
            "clientIdIssuedAt": 1_700_000_000,
            "clientSecretExpiresAt": 4_102_444_800i64,
        })))
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
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accessToken": "access-1",
            "tokenType": "Bearer",
            "expiresIn": 3600,
            "refreshToken": "refresh-1",
        })))
        .mount(server)
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn login_signs_in_and_syncs() {
    let server = MockServer::start().await;
    let fob = Fob::new("login").with_server(&server);
    fob.write_config(&portal_config("acme"));
    mount_device_sign_in(&server).await;
    mount_portal(&server, &[("111111111111", "Dev")]).await;

    // fob creates the store's directory itself.
    assert!(!fob.keyring().exists());
    let (_, stderr) = fob.ok(&["login", "acme", "--device-code", "--no-browser"]);
    assert!(stderr.contains("code: ABCD-EFGH"), "{stderr}");
    assert!(stderr.contains("acme: 1 profiles"), "{stderr}");
    let token = fob.secret("aws-sso/acme/token");
    assert!(token.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&fob.keyring()), 0o700);
        assert_eq!(mode(&token), 0o600);
    }
    let (stdout, _) = fob.ok(&["list"]);
    assert_eq!(lines(&stdout), ["acme/dev/Admin"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn login_keeps_a_working_sign_in() {
    let server = MockServer::start().await;
    let fob = Fob::new("login-keeps").with_server(&server);
    fob.write_config(&portal_config("acme"));
    fob.sign_in("acme");
    mount_portal(&server, &[("111111111111", "Dev")]).await;
    // No sign-in endpoints are mounted, so a new sign-in would fail.
    let (_, stderr) = fob.ok(&["login", "acme", "--device-code", "--no-browser"]);
    assert!(
        stderr.contains("kept the sign-in of 'acme' (session valid for"),
        "{stderr}"
    );
    assert!(!stderr.contains("approve"), "{stderr}");
    assert!(stderr.contains("acme: 1 profiles"), "{stderr}");
}

#[test]
fn login_without_a_terminal_needs_the_integration_named() {
    let fob = Fob::new("login-unnamed");
    fob.write_config(&portal_config("acme"));
    for command in ["login", "logout"] {
        let stderr = fob.fails(&[command]);
        assert!(
            stderr.contains(&format!(
                "name an integration: `fob {command} <integration>` (configured: acme)"
            )),
            "{stderr}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn login_force_signs_in_again() {
    let server = MockServer::start().await;
    let fob = Fob::new("login-force").with_server(&server);
    fob.write_config(&portal_config("acme"));
    fob.sign_in("acme");
    mount_device_sign_in(&server).await;
    mount_portal(&server, &[("111111111111", "Dev")]).await;
    let (_, stderr) = fob.ok(&["login", "acme", "--force", "--device-code", "--no-browser"]);
    assert!(stderr.contains("code: ABCD-EFGH"), "{stderr}");
    assert!(!stderr.contains("kept the sign-in"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn login_replaces_a_sign_in_made_with_other_scopes() {
    let server = MockServer::start().await;
    let fob = Fob::new("login-scopes").with_server(&server);
    fob.write_config(&portal_config("acme"));
    fob.sign_in("acme");
    // The stored session's client was registered with scopes the config no
    // longer asks for.
    let registration = json!({
        "client_id": "client-1",
        "client_secret": "client-secret-1",
        "expires_at": "2100-01-01T00:00:00Z",
        "start_url": START_URL,
        "region": "eu-west-1",
        "scopes": ["sso:account:access", "codewhisperer:completions"],
    });
    std::fs::write(
        fob.secret("aws-sso/acme/client/device-code"),
        registration.to_string(),
    )
    .unwrap();
    mount_device_sign_in(&server).await;
    mount_portal(&server, &[("111111111111", "Dev")]).await;
    let (_, stderr) = fob.ok(&["login", "acme", "--device-code", "--no-browser"]);
    assert!(stderr.contains("code: ABCD-EFGH"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_and_list() {
    let (fob, _server) = synced_portal("list").await;
    let (stdout, _) = fob.ok(&["list"]);
    assert_eq!(lines(&stdout), ["acme/dev/Admin", "acme/prod/Admin"]);
    let (stdout, _) = fob.ok(&["ls", "prod"]);
    assert_eq!(lines(&stdout), ["acme/prod/Admin"]);
    // Several words, as every other profile command takes them.
    let (stdout, _) = fob.ok(&["list", "prod", "admin"]);
    assert_eq!(lines(&stdout), ["acme/prod/Admin"]);
    let (stdout, _) = fob.ok(&["list", "--json"]);
    let profiles: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(profiles[0]["id"], "acme/dev/Admin");
    assert_eq!(profiles.as_array().unwrap().len(), 2);
    let stderr = fob.fails(&["creds", "nothing-matches"]);
    assert!(
        stderr.contains("no profile matches 'nothing-matches'"),
        "{stderr}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_process_output_names_the_account() {
    let (fob, _server) = synced_portal("creds").await;
    let (stdout, _) = fob.ok(&["creds", "acme/prod/Admin", "--format", "credential-process"]);
    let value: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value["Version"], 1);
    assert_eq!(value["AccessKeyId"], "ASIA222222222222");
    assert_eq!(value["SecretAccessKey"], "role-secret");
    assert_eq!(value["SessionToken"], "role-session");
    assert_eq!(value["Expiration"], "2100-01-01T00:00:00Z");
    assert_eq!(value["AccountId"], "222222222222");
    // Cached under the profile.
    assert!(fob.secret("credentials/acme/prod/Admin").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn state_is_private_and_locks_are_named_by_the_whole_profile_id() {
    let (fob, _server) = synced_portal("state").await;
    fob.ok(&["creds", "acme/prod/Admin"]);
    let state = fob.root.join("state").join("omnifob");
    assert!(
        entries(&state.join("locks")).contains(&"credentials-acme%2Fprod%2FAdmin.lock".to_string()),
        "{:?}",
        entries(&state.join("locks"))
    );
    assert!(
        !entries(&state).iter().any(|name| name.ends_with(".tmp")),
        "{:?}",
        entries(&state)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&state), 0o700);
        assert_eq!(mode(&state.join("locks")), 0o700);
        assert_eq!(mode(&state.join("profiles.json")), 0o600);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_gets_no_credentials_printed() {
    let (fob, _server) = synced_portal("agent-print").await;
    for args in [
        &["creds", "acme/prod/Admin"][..],
        &["env", "acme/prod/Admin", "--shell", "bash"],
    ] {
        let output = fob.run_as_agent(args);
        let (stdout, stderr) = texts(&output);
        assert!(!output.status.success(), "{args:?}: {stdout}");
        assert!(stdout.is_empty(), "{args:?}: {stdout}");
        assert!(
            stderr.contains("not printing credentials into an agent's output; run the command as `fob exec acme/prod/Admin -- <command>`"),
            "{stderr}"
        );
    }
    let output = fob.run_as_agent(&["console", "acme/prod/Admin", "--print"]);
    let (stdout, stderr) = texts(&output);
    assert!(!output.status.success() && stdout.is_empty(), "{stdout}");
    assert!(
        stderr.contains("not printing the console sign-in URL"),
        "{stderr}"
    );
    // credential_process hands the output to the SDK, not to the agent.
    let args = ["creds", "acme/prod/Admin", "--format", "credential-process"];
    let output = fob.run_as_agent(&args);
    assert!(output.status.success(), "{:?}", texts(&output));
    assert_eq!(texts(&output).0, fob.ok(&args).0);
    // OMNIFOB_AGENT=0 turns the detection off.
    let output = fob
        .command(&["creds", "acme/prod/Admin"])
        .env("CLAUDECODE", "1")
        .env("OMNIFOB_AGENT", "0")
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", texts(&output));
    let stderr = texts(&fob.run_as_agent(&["use", "acme/prod/Admin"])).1;
    assert!(stderr.contains("starts in a new shell"), "{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_names_profiles_in_full_and_within_its_allowlist() {
    let (fob, _server) = synced_portal("agent-select").await;
    let creds = |query: &str| fob.run_as_agent(&["creds", query, "--format", "credential-process"]);
    // A query that a person may use picks one profile; an agent must be exact.
    fob.ok(&["creds", "prod", "--format", "credential-process"]);
    let stderr = texts(&creds("prod")).1;
    assert!(
        stderr
            .contains("name the profile by its full id: 'prod' matches 1 profile: acme/prod/Admin"),
        "{stderr}"
    );
    let stderr = texts(&fob.run_as_agent(&["exec", "--", "true"])).1;
    assert!(stderr.contains("name a profile by its full id"), "{stderr}");
    assert!(creds("acme/prod/Admin").status.success());

    let mut config = portal_config("acme");
    config.push_str("\n[agent]\nprofiles = [\"acme/dev/*\"]\n");
    fob.write_config(&config);
    assert!(creds("acme/dev/Admin").status.success());
    let output = creds("acme/prod/Admin");
    assert!(!output.status.success());
    assert!(
        texts(&output)
            .1
            .contains("acme/prod/Admin is not open to agents"),
        "{:?}",
        texts(&output)
    );
    // People are not limited by it.
    fob.ok(&["creds", "acme/prod/Admin", "--format", "credential-process"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn ambiguous_queries_list_the_matches() {
    let (fob, _server) = synced_portal("ambiguous").await;
    let stderr = fob.fails(&["creds", "Admin"]);
    assert!(
        stderr.contains(
            "'Admin' matches 2 profiles: acme/dev/Admin, acme/prod/Admin; name one in full"
        ) || stderr.contains(
            "'Admin' matches 2 profiles: acme/prod/Admin, acme/dev/Admin; name one in full"
        ),
        "{stderr}"
    );
    let stderr = fob.fails(&["env", "--shell", "bash"]);
    assert!(
        stderr.contains("name a profile; `fob list` shows them"),
        "{stderr}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn profiles_are_picked_by_account_and_role() {
    let (fob, _server) = synced_portal("by-account").await;
    let key = |args: &[&str]| {
        let mut all = vec!["creds", "--format", "credential-process"];
        all.extend_from_slice(args);
        let (stdout, _) = fob.ok(&all);
        serde_json::from_str::<Value>(&stdout).unwrap()["AccessKeyId"].clone()
    };
    assert_eq!(
        key(&["--account-id", "111111111111", "--role", "admin"]),
        "ASIA111111111111"
    );
    assert_eq!(key(&["--account-id", "222222222222"]), "ASIA222222222222");
    let stderr = fob.fails(&["creds", "--role", "Admin"]);
    assert!(
        stderr.contains("'--role Admin' matches 2 profiles"),
        "{stderr}"
    );
    let stderr = fob.fails(&["creds", "--account-id", "333333333333"]);
    assert!(
        stderr.contains("no profile matches '--account-id 333333333333'"),
        "{stderr}"
    );
    assert!(
        fob.fails(&["creds", "acme", "--role", "Admin"])
            .contains("cannot be used with")
    );
    // An account and role that name one profile are exact enough for an agent.
    let output = fob.run_as_agent(&[
        "creds",
        "--account-id",
        "222222222222",
        "--role",
        "Admin",
        "--format",
        "credential-process",
    ]);
    assert!(output.status.success(), "{:?}", texts(&output));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_directory_picks_its_default_profile() {
    let (fob, _server) = synced_portal("directories").await;
    let project = fob.root.join("project");
    std::fs::create_dir_all(project.join("src")).unwrap();
    let mut config = portal_config("acme");
    config.push_str(&format!(
        "\n[directories]\n'{}' = \"acme/prod/Admin\"\n'{}' = \"acme/dev/Admin\"\n",
        fob.root.display(),
        project.join("src").display()
    ));
    fob.write_config(&config);
    let env_in = |dir: &Path| {
        let output = fob
            .command(&["env", "--shell", "bash"])
            .current_dir(dir)
            .output()
            .unwrap();
        let (stdout, stderr) = texts(&output);
        assert!(output.status.success(), "{stdout}\n{stderr}");
        stdout
    };
    assert!(env_in(&project).contains("ASIA222222222222"));
    // The longest directory wins.
    assert!(env_in(&project.join("src")).contains("ASIA111111111111"));
    // A named profile still wins over the directory's.
    let output = fob
        .command(&["env", "acme/dev/Admin", "--shell", "bash"])
        .current_dir(&project)
        .output()
        .unwrap();
    assert!(texts(&output).0.contains("ASIA111111111111"));
    // An agent has to name it, and is told which one it is.
    let output = fob
        .command(&["exec", "--", "true"])
        .env("CLAUDECODE", "1")
        .current_dir(&project)
        .output()
        .unwrap();
    let stderr = texts(&output).1;
    assert!(!output.status.success());
    assert!(
        stderr.contains("name a profile by its full id; this directory's default")
            && stderr.contains("is acme/prod/Admin"),
        "{stderr}"
    );
    // A default that is not a profile says so.
    let mut config = portal_config("acme");
    config.push_str(&format!(
        "\n[directories]\n'{}' = \"acme/gone/Admin\"\n",
        project.display()
    ));
    fob.write_config(&config);
    let output = fob
        .command(&["env", "--shell", "bash"])
        .current_dir(&project)
        .output()
        .unwrap();
    assert!(
        texts(&output)
            .1
            .contains("acme/gone/Admin, the default profile of"),
        "{:?}",
        texts(&output)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_tells_its_own_failures_from_the_command() {
    let (fob, _server) = synced_portal("exec-status").await;
    let status = |args: &[&str]| fob.run(args).status.code();
    assert_eq!(
        status(&["exec", "nothing-matches", "--", "true"]),
        Some(125)
    );
    assert_eq!(
        status(&["exec", "acme/prod/Admin", "--", "fob-e2e-no-such-command"]),
        Some(127)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_integration_not_signed_in_is_mentioned_only_when_it_matters() {
    let (fob, _server) = synced_portal("skipped").await;
    let mut config = portal_config("acme");
    config.push_str(&portal_config("other").replace("acme.awsapps.com", "other.awsapps.com"));
    fob.write_config(&config);
    let note = "skipping 'other': not signed in (`fob login other`)";
    let (_, stderr) = fob.ok(&["creds", "acme/prod/Admin", "--format", "credential-process"]);
    assert!(!stderr.contains(note), "{stderr}");
    let (_, stderr) = fob.ok(&["list"]);
    assert!(stderr.contains(note), "{stderr}");
    let stderr = fob.fails(&["creds", "other/x/Admin"]);
    assert!(stderr.contains(note), "{stderr}");
}

/// `fob sync` keeps what synced when another integration fails, reports
/// every failure at the end, and `fob check` reports in config order.
#[tokio::test(flavor = "multi_thread")]
async fn sync_saves_what_synced_and_reports_the_rest() {
    let server = MockServer::start().await;
    let fob = Fob::new("sync-partial").with_server(&server);
    let mut config = String::new();
    for name in ["acme", "other", "zeta"] {
        config.push_str(
            &portal_config(name).replace("acme.awsapps.com", &format!("{name}.awsapps.com")),
        );
    }
    fob.write_config(&config);
    fob.sign_in("acme");
    mount_portal(&server, &[("111111111111", "Dev")]).await;

    let stderr = fob.fails(&["sync"]);
    assert!(stderr.contains("fob: acme: 1 profiles"), "{stderr}");
    for name in ["other", "zeta"] {
        assert!(stderr.contains(&format!("syncing '{name}'")), "{stderr}");
    }
    assert!(
        stderr.contains("2 of 3 integrations did not sync"),
        "{stderr}"
    );
    let profiles =
        std::fs::read_to_string(fob.root.join("state").join("omnifob").join("profiles.json"))
            .unwrap();
    assert!(profiles.contains("acme/dev/Admin"), "{profiles}");

    // One failure is the error itself.
    let stderr = fob.fails(&["sync", "acme", "other"]);
    assert!(stderr.contains("fob: syncing 'other': "), "{stderr}");

    let output = fob.run(&["check"]);
    let (stdout, _) = texts(&output);
    assert!(!output.status.success());
    let checked: Vec<&str> = stdout
        .lines()
        .map(|l| l.split(':').next().unwrap_or_default())
        .collect();
    assert_eq!(
        checked,
        ["ok   acme", "FAIL other", "FAIL zeta"],
        "{stdout}"
    );
}

/// Not a test of its own: `fob exec` runs this test binary with
/// `--ignored --exact` and `OMNIFOB_E2E_CHILD` set, as a child that works on
/// every platform, and it prints the variables `OMNIFOB_E2E_CHILD_VARS` names.
#[test]
#[ignore = "run by exec_child"]
fn child_prints_its_environment() {
    if std::env::var_os("OMNIFOB_E2E_CHILD").is_none() {
        return;
    }
    let names = std::env::var("OMNIFOB_E2E_CHILD_VARS").unwrap_or_default();
    for name in names.split(',') {
        match std::env::var(name) {
            Ok(value) => println!("child: {name}={value}"),
            Err(_) => println!("child: {name} unset"),
        }
    }
}

/// Runs `fob exec <profile> -- <this test binary>` with `env` added to
/// fob's environment; returns what the child printed of `names`.
fn exec_child(fob: &Fob, profile: &str, env: &[(&str, &str)], names: &[&str]) -> Vec<String> {
    let me = std::env::current_exe().unwrap();
    let mut cmd = fob.command(&[
        "exec",
        profile,
        "--",
        me.to_str().unwrap(),
        "child_prints_its_environment",
        "--exact",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]);
    cmd.env("OMNIFOB_E2E_CHILD", "1")
        .env("OMNIFOB_E2E_CHILD_VARS", names.join(","));
    for (k, v) in env {
        cmd.env(k, v);
    }
    let output = cmd.output().unwrap();
    let (stdout, stderr) = texts(&output);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    stdout
        .lines()
        .filter_map(|l| l.split_once("child: ").map(|(_, v)| v.to_string()))
        .collect()
}

#[test]
#[ignore = "run by exec_serves_aws_credentials_from_a_loopback_endpoint"]
fn child_fetches_container_credentials() {
    use std::io::{Read, Write};
    let Ok(uri) = std::env::var("AWS_CONTAINER_CREDENTIALS_FULL_URI") else {
        return;
    };
    let token = std::env::var("AWS_CONTAINER_AUTHORIZATION_TOKEN").unwrap();
    println!(
        "child: AWS_ACCESS_KEY_ID {}",
        if std::env::var_os("AWS_ACCESS_KEY_ID").is_some() {
            "set"
        } else {
            "unset"
        }
    );
    let addr = uri
        .strip_prefix("http://")
        .and_then(|rest| rest.strip_suffix('/'))
        .unwrap()
        .to_string();
    println!("child: loopback {}", addr.starts_with("127.0.0.1:"));
    let get = |authorization: &str| {
        let mut s = std::net::TcpStream::connect(&addr).unwrap();
        write!(
            s,
            "GET / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: {authorization}\r\n\r\n"
        )
        .unwrap();
        let mut reply = String::new();
        s.read_to_string(&mut reply).unwrap();
        reply
    };
    let refused = get("guess");
    println!("child: wrong token {}", refused.lines().next().unwrap());
    let reply = get(&token);
    println!("child: right token {}", reply.lines().next().unwrap());
    let body: serde_json::Value =
        serde_json::from_str(reply.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    println!(
        "child: AccessKeyId {}",
        body["AccessKeyId"].as_str().unwrap()
    );
    println!("child: AccountId {}", body["AccountId"].as_str().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_serves_aws_credentials_from_a_loopback_endpoint() {
    let (fob, _server) = synced_portal("exec-server").await;
    let me = std::env::current_exe().unwrap();
    let output = fob
        .command(&[
            "exec",
            "acme/dev/Admin",
            "--server",
            "--",
            me.to_str().unwrap(),
            "child_fetches_container_credentials",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("AWS_ACCESS_KEY_ID", "stale")
        .env("AWS_PROFILE", "stale")
        .output()
        .unwrap();
    let (stdout, stderr) = texts(&output);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    let printed: Vec<&str> = stdout
        .lines()
        .filter_map(|l| l.split_once("child: ").map(|(_, v)| v))
        .collect();
    assert_eq!(
        printed,
        [
            "AWS_ACCESS_KEY_ID unset",
            "loopback true",
            "wrong token HTTP/1.1 401 Unauthorized",
            "right token HTTP/1.1 200 OK",
            "AccessKeyId ASIA111111111111",
            "AccountId 111111111111",
        ]
    );
    // Only AWS profiles have one.
    let output = fob.run(&["exec", "acme/dev/Admin", "--token-file", "--", "true"]);
    assert_eq!(output.status.code(), Some(125));
}

/// kubectl's exec plugin output, which agents may run since kubectl reads it.
#[tokio::test(flavor = "multi_thread")]
async fn creds_write_an_eks_exec_credential() {
    let (fob, _server) = synced_portal("k8s").await;
    let output = fob
        .command(&["creds", "acme/dev/Admin", "--format", "k8s-exec", "--cluster", "dev"])
        .env("CLAUDECODE", "1")
        .env(
            "KUBERNETES_EXEC_INFO",
            r#"{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false}}"#,
        )
        .output()
        .unwrap();
    let (stdout, stderr) = texts(&output);
    assert!(output.status.success(), "{stderr}");
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value["kind"], "ExecCredential");
    assert_eq!(value["apiVersion"], "client.authentication.k8s.io/v1beta1");
    assert!(
        value["status"]["token"]
            .as_str()
            .unwrap()
            .starts_with("k8s-aws-v1.")
    );
    assert!(value["status"]["expirationTimestamp"].is_string());
    // The cluster is part of the token; Google's format is for Google.
    let (_, stderr) = texts(&fob.run(&["creds", "acme/dev/Admin", "--format", "k8s-exec"]));
    assert!(stderr.contains("--cluster"), "{stderr}");
    let (_, stderr) = texts(&fob.run(&["creds", "acme/dev/Admin", "--format", "gcp-executable"]));
    assert!(stderr.contains("Google Cloud profiles"), "{stderr}");
}

/// The audit log records what was handed out, under an agent too, and
/// never a secret.
#[tokio::test(flavor = "multi_thread")]
async fn the_audit_log_records_handouts_without_secrets() {
    let (fob, _server) = synced_portal("audit").await;
    let config = std::fs::read_to_string(fob.config_file()).unwrap();
    std::fs::write(
        fob.config_file(),
        format!("[audit]\nenabled = true\n\n{config}"),
    )
    .unwrap();
    fob.ok(&["creds", "acme/dev/Admin", "--format", "credential-process"]);
    let output = fob.run_as_agent(&["exec", "acme/dev/Admin", "--", "fob-e2e-no-such-command"]);
    assert_eq!(output.status.code(), Some(127));
    let log = std::fs::read_to_string(fob.root.join("state/omnifob/audit.jsonl")).unwrap();
    assert!(
        !log.contains("role-session") && !log.contains("ASIA"),
        "{log}"
    );
    let lines: Vec<serde_json::Value> = log
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2, "{log}");
    assert_eq!(lines[0]["command"], "creds");
    assert_eq!(lines[0]["via"], "credential-process");
    assert_eq!(lines[0]["profile"], "acme/dev/Admin");
    assert!(lines[0].get("agent").is_none());
    assert_eq!(lines[1]["command"], "exec");
    assert_eq!(lines[1]["agent"], "CLAUDECODE");
    assert_eq!(lines[1]["expires_at"], "2100-01-01T00:00:00Z");
}

/// What an earlier `fob use` or another tool left in the shell does not
/// reach the command next to the new profile's credentials.
#[tokio::test(flavor = "multi_thread")]
async fn exec_leaves_no_stale_variables_in_the_command() {
    let (fob, _server) = synced_portal("exec-stale").await;
    let printed = exec_child(
        &fob,
        "acme/dev/Admin",
        &[
            // An R2 profile's `fob use`, and a variable it set.
            ("OMNIFOB_VARS", "AWS_ENDPOINT_URL_S3,CLOUDFLARE_API_TOKEN"),
            (
                "AWS_ENDPOINT_URL_S3",
                "https://acct.r2.cloudflarestorage.com",
            ),
            ("CLOUDFLARE_API_TOKEN", "stale"),
            // Set by another tool, not by fob.
            ("AWS_SECURITY_TOKEN", "stale"),
            ("OMNIFOB_EXPIRES_AT", "2000-01-01T00:00:00Z"),
            ("UNRELATED", "kept"),
        ],
        &[
            "AWS_ACCESS_KEY_ID",
            "AWS_SESSION_TOKEN",
            "AWS_ENDPOINT_URL_S3",
            "AWS_SECURITY_TOKEN",
            "CLOUDFLARE_API_TOKEN",
            "OMNIFOB_VARS",
            "OMNIFOB_EXPIRES_AT",
            "UNRELATED",
        ],
    );
    assert_eq!(
        printed,
        [
            "AWS_ACCESS_KEY_ID=ASIA111111111111",
            "AWS_SESSION_TOKEN=role-session",
            "AWS_ENDPOINT_URL_S3 unset",
            "AWS_SECURITY_TOKEN unset",
            "CLOUDFLARE_API_TOKEN unset",
            "OMNIFOB_VARS unset",
            "OMNIFOB_EXPIRES_AT=2100-01-01T00:00:00Z",
            "UNRELATED=kept",
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_hands_the_account_and_region_to_the_command() {
    let (fob, _server) = synced_portal("exec").await;
    let printed = exec_child(
        &fob,
        "acme/dev/Admin",
        &[],
        &[
            "AWS_ACCESS_KEY_ID",
            "AWS_ACCOUNT_ID",
            "AWS_REGION",
            "OMNIFOB_PROFILE",
        ],
    );
    assert_eq!(
        printed,
        [
            "AWS_ACCESS_KEY_ID=ASIA111111111111",
            "AWS_ACCOUNT_ID=111111111111",
            "AWS_REGION=eu-central-1",
            "OMNIFOB_PROFILE=acme/dev/Admin",
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_ttl_request_leaves_the_cache_alone() {
    let server = MockServer::start().await;
    let fob = Fob::new("ttl").with_server(&server);
    fob.write_config(&format!(
        r#"{}
[integrations.acme.chained.deploy]
via_account_id = "111111111111"
via_role = "Admin"
role_arn = "arn:aws:iam::333333333333:role/Deploy"
duration = "1h"
"#,
        portal_config("acme")
    ));
    fob.sign_in("acme");
    mount_portal(&server, &[("111111111111", "Dev")]).await;
    mount_role_credentials(&server).await;
    // One request of each length: the third `creds` is served from the cache.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("Action=AssumeRole"))
        .and(body_string_contains("DurationSeconds=3600"))
        .respond_with(assume_role("ASIAFULL"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("Action=AssumeRole"))
        .and(body_string_contains("DurationSeconds=900"))
        .respond_with(assume_role("ASIATTL"))
        .expect(1)
        .mount(&server)
        .await;
    fob.ok(&["sync"]);
    let key = |args: &[&str]| {
        let (stdout, _) = fob.ok(args);
        let value: Value = serde_json::from_str(&stdout).unwrap();
        value["env"]["AWS_ACCESS_KEY_ID"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(key(&["creds", "acme/deploy/Deploy"]), "ASIAFULL");
    assert_eq!(
        key(&["creds", "acme/deploy/Deploy", "--ttl", "15m"]),
        "ASIATTL"
    );
    assert_eq!(key(&["creds", "acme/deploy/Deploy"]), "ASIAFULL");
    server.verify().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_forgets_the_credentials_of_profiles_that_went_away() {
    let (fob, server) = synced_portal("prune").await;
    fob.ok(&["creds", "acme/dev/Admin"]);
    fob.ok(&["creds", "acme/prod/Admin"]);
    let dev = fob.secret("credentials/acme/dev/Admin");
    let prod = fob.secret("credentials/acme/prod/Admin");
    assert!(dev.exists() && prod.exists());

    // The Prod assignment is removed.
    server.reset().await;
    mount_portal(&server, &[("111111111111", "Dev")]).await;
    let (_, stderr) = fob.ok(&["sync"]);
    assert!(stderr.contains("acme: 1 profiles"), "{stderr}");
    let (stdout, _) = fob.ok(&["list"]);
    assert_eq!(lines(&stdout), ["acme/dev/Admin"]);
    assert!(dev.exists());
    assert!(!prod.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn export_writes_the_aws_config_atomically_and_rename_warns_about_it() {
    let (fob, _server) = synced_portal("export").await;
    let original = "[profile mine]\nregion = us-east-1\n";
    std::fs::write(fob.aws_config(), original).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(fob.aws_config(), std::fs::Permissions::from_mode(0o640)).unwrap();
    }

    let (stdout, _) = fob.ok(&["export", "aws-config"]);
    assert!(
        stdout.contains(
            "[profile fob-acme-dev-Admin]\ncredential_process = fob creds acme/dev/Admin --format credential-process\nregion = eu-central-1\n"
        ),
        "{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(fob.aws_config()).unwrap(),
        original,
        "printed, not written"
    );

    let (_, stderr) = fob.ok(&["export", "aws-config", "--write"]);
    assert!(stderr.contains("wrote 2 profile(s)"), "{stderr}");
    let written = std::fs::read_to_string(fob.aws_config()).unwrap();
    assert_eq!(written, format!("{original}\n{stdout}"));
    // The previous file is backed up, and no temporary file is left.
    assert_eq!(
        entries(&fob.root.join("aws")),
        ["config", "config.omnifob-backup"]
    );
    assert_eq!(
        std::fs::read_to_string(fob.root.join("aws").join("config.omnifob-backup")).unwrap(),
        original
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for file in ["config", "config.omnifob-backup"] {
            let mode = std::fs::metadata(fob.root.join("aws").join(file))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o640, "{file}");
        }
    }
    let (_, stderr) = fob.ok(&["export", "aws-config", "--write"]);
    assert!(stderr.contains("is up to date"), "{stderr}");

    let (_, stderr) = fob.ok(&["rename", "acme", "corp"]);
    assert!(stderr.contains("profiles are now corp/..."), "{stderr}");
    assert!(stderr.contains("still has profiles for 'acme'"), "{stderr}");
    let (stdout, _) = fob.ok(&["list"]);
    assert_eq!(lines(&stdout), ["corp/dev/Admin", "corp/prod/Admin"]);
}

#[test]
fn export_gives_console_sign_in_profiles_their_region() {
    let fob = Fob::new("export-login");
    fob.write_config(
        "[integrations.console]\ntype = \"aws-login\"\nregion = \"eu-west-1\"\ndefault_region = \"eu-central-1\"\n",
    );
    std::fs::create_dir_all(fob.keyring()).unwrap();
    let session = json!({
        "login_session": "arn:aws:iam::123456789012:user/alice",
        "account_id": "123456789012",
        "client_id": "arn:aws:signin:::devtools/same-device",
        "region": "eu-west-1",
        "refresh_token": "refresh-1",
        "dpop_key": "",
        "access_key_id": "ASIAX",
        "secret_access_key": "secret",
        "session_token": "session",
        "expires_at": "2100-01-01T00:00:00Z",
    });
    std::fs::write(fob.secret("aws-login/console/session"), session.to_string()).unwrap();
    fob.ok(&["sync"]);
    let (stdout, _) = fob.ok(&["export", "aws-config"]);
    assert!(
        stdout.contains(
            "credential_process = fob creds console/123456789012/alice --format credential-process\nregion = eu-central-1\n"
        ),
        "{stdout}"
    );
}

/// Not a test of its own: `an_integration_opens_in_its_browser` names this test binary
/// as a browser, run with `--ignored --exact` and the URL as its last
/// argument, which it writes to `OMNIFOB_E2E_BROWSER_OUT`.
#[test]
#[ignore = "run by an_integration_opens_in_its_browser"]
fn browser_child_records_its_url() {
    let Some(out) = std::env::var_os("OMNIFOB_E2E_BROWSER_OUT") else {
        return;
    };
    let url = std::env::args().next_back().unwrap();
    std::fs::write(out, url).unwrap();
}

#[test]
fn an_integration_opens_in_its_browser() {
    let fob = Fob::new("browser");
    let me = std::env::current_exe().unwrap();
    fob.write_config(&format!(
        r#"
[browsers.work]
command = ['{}', "browser_child_records_its_url", "--exact", "--ignored", "{{url}}"]

[integrations.status]
type = "token"
console = "https://console.example.test/home?a=1&b=two words"
browser = "work"

[integrations.status.secrets]
token = ["STATUS_TOKEN"]
"#,
        me.display()
    ));
    let out = fob.root.join("opened");
    fob.ok(&["sync"]);
    let output = fob
        .command(&["console", "status"])
        .env("OMNIFOB_E2E_BROWSER_OUT", &out)
        .output()
        .unwrap();
    let (stdout, stderr) = texts(&output);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    // The browser runs on its own; fob does not wait for it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !out.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        "https://console.example.test/home?a=1&b=two words"
    );
}

/// A broken config.toml or profiles.json must not break the shell's
/// start-up (`fob activate`) or `fob unuse`, and `fob sync` rewrites a
/// corrupt profiles.json.
#[tokio::test(flavor = "multi_thread")]
async fn shell_commands_work_with_a_broken_config() {
    let (fob, _server) = synced_portal("broken").await;
    let profiles = fob.root.join("state").join("omnifob").join("profiles.json");
    std::fs::write(&profiles, "{ not json").unwrap();
    // Status reports, and sync starts over from no profiles.
    let (stdout, stderr) = fob.ok(&["status"]);
    assert!(
        stderr.contains("ignoring the discovered profiles"),
        "{stderr}"
    );
    assert!(stdout.contains("0 profiles"), "{stdout}");
    fob.fails(&["list"]);
    fob.ok(&["sync"]);
    let (stdout, _) = fob.ok(&["list"]);
    assert_eq!(lines(&stdout), ["acme/dev/Admin", "acme/prod/Admin"]);

    std::fs::write(&profiles, "{ not json").unwrap();
    fob.write_config("[integrations.acme\nbroken");
    let (stdout, _) = fob.ok(&["activate", "bash"]);
    assert!(stdout.contains("fob()"), "{stdout}");
    let output = fob
        .command(&["env", "--shell", "bash", "--unset"])
        .env("OMNIFOB_VARS", "AWS_REGION")
        .output()
        .unwrap();
    let (stdout, stderr) = texts(&output);
    assert!(output.status.success(), "{stderr}");
    assert!(stdout.contains("unset AWS_REGION\n"), "{stdout}");
    let stderr = fob.fails(&["use", "acme/prod/Admin"]);
    assert!(stderr.contains("needs the shell integration"), "{stderr}");
    // Commands that need the config still say what is wrong with it.
    let stderr = fob.fails(&["list"]);
    assert!(stderr.contains("parsing"), "{stderr}");
}

/// `--config` stands in for `OMNIFOB_CONFIG`.
#[tokio::test(flavor = "multi_thread")]
async fn the_config_flag_names_the_config_file() {
    let (fob, _server) = synced_portal("config-flag").await;
    let elsewhere = fob.root.join("elsewhere.toml");
    std::fs::rename(fob.config_file(), &elsewhere).unwrap();
    let (stdout, _) = fob.ok(&["status"]);
    assert!(stdout.contains("No integrations configured"), "{stdout}");
    let (stdout, _) = fob.ok(&["status", "--config", elsewhere.to_str().unwrap()]);
    assert!(stdout.starts_with("Secrets: "), "{stdout}");
    assert!(
        stdout.contains("acme  aws-sso  signed in until 2100-01-01"),
        "{stdout}"
    );
}

/// A path given with `--config` has to exist, and `fob exec` fails with 125
/// when the config does not load, as for its other failures.
#[tokio::test(flavor = "multi_thread")]
async fn a_missing_or_broken_config_is_an_error() {
    let (fob, _server) = synced_portal("config-missing").await;
    let missing = fob.root.join("missing.toml");
    let stderr = fob.fails(&["status", "--config", missing.to_str().unwrap()]);
    assert!(stderr.contains("does not exist"), "{stderr}");
    let output = fob.run(&[
        "--config",
        missing.to_str().unwrap(),
        "exec",
        "acme/prod/Admin",
        "--",
        "true",
    ]);
    assert_eq!(output.status.code(), Some(125));

    fob.write_config("[integrations.acme\nbroken");
    let output = fob.run(&["exec", "acme/prod/Admin", "--", "true"]);
    assert_eq!(output.status.code(), Some(125));
    let (_, stderr) = texts(&output);
    assert!(stderr.contains("parsing"), "{stderr}");
}

/// The shell wrapper recognises `use` and `unuse` after `--config`.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn the_shell_wrapper_sees_use_after_the_config_flag() {
    let (fob, _server) = synced_portal("wrapper-config").await;
    let elsewhere = fob.root.join("elsewhere.toml");
    std::fs::rename(fob.config_file(), &elsewhere).unwrap();
    let bin_dir = Path::new(FOB).parent().unwrap();
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let base = fob.command(&[]);
    let mut bash = Command::new("bash");
    for (name, value) in base.get_envs() {
        match value {
            Some(value) => bash.env(name, value),
            None => bash.env_remove(name),
        };
    }
    let script = r#"eval "$(fob activate bash)"
fob --config "$1" use acme/prod/Admin || exit 1
echo "profile=$OMNIFOB_PROFILE"
fob --config="$1" unuse || exit 1
echo "after=${OMNIFOB_PROFILE:-none}"
"#;
    let output = bash
        .env("PATH", path)
        .args(["-c", script, "bash", elsewhere.to_str().unwrap()])
        .output()
        .unwrap();
    let (stdout, stderr) = texts(&output);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert_eq!(lines(&stdout), ["profile=acme/prod/Admin", "after=none"]);
}

/// `fob status --json` and `fob check --json` for scripts and status bars,
/// and `fob check --integration` for one sign-in.
#[tokio::test(flavor = "multi_thread")]
async fn status_and_check_print_json() {
    let (fob, _server) = synced_portal("json").await;
    let mut config = portal_config("acme");
    config.push_str(&portal_config("other").replace("acme.awsapps.com", "other.awsapps.com"));
    fob.write_config(&config);

    let output = fob
        .command(&["status", "--json"])
        .env("OMNIFOB_PROFILE", "acme/prod/Admin")
        .env("OMNIFOB_EXPIRES_AT", "2100-01-01T00:00:00Z")
        .output()
        .unwrap();
    let (stdout, stderr) = texts(&output);
    assert!(output.status.success(), "{stderr}");
    let status: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(status["active_profile"], "acme/prod/Admin");
    assert_eq!(status["active_expires_at"], "2100-01-01T00:00:00Z");
    let integrations = status["integrations"].as_array().unwrap();
    assert_eq!(integrations[0]["name"], "acme");
    assert_eq!(integrations[0]["type"], "aws-sso");
    assert_eq!(integrations[0]["signed_in"], true);
    assert_eq!(integrations[0]["profiles"], 2);
    assert!(integrations[0]["synced_at"].is_string());
    assert_eq!(integrations[1]["name"], "other");
    assert_eq!(integrations[1]["signed_in"], false);
    assert!(integrations[1]["synced_at"].is_null());

    // The text form: aligned columns, the active profile and sync age.
    let output = fob
        .command(&["status"])
        .env("OMNIFOB_PROFILE", "acme/prod/Admin")
        .output()
        .unwrap();
    let (stdout, _) = texts(&output);
    assert!(
        stdout.contains("Active in this shell: acme/prod/Admin\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("acme   aws-sso  signed in until"),
        "{stdout}"
    );
    assert!(
        stdout.contains("other  aws-sso  signed out, 0 profiles, not synced"),
        "{stdout}"
    );

    let output = fob.run(&["check", "--json"]);
    assert!(!output.status.success());
    let checked: Value = serde_json::from_str(&texts(&output).0).unwrap();
    assert_eq!(checked[0]["integration"], "acme");
    assert_eq!(checked[0]["ok"], true);
    assert_eq!(checked[1]["integration"], "other");
    assert_eq!(checked[1]["ok"], false);
    assert!(
        checked[1]["detail"]
            .as_str()
            .unwrap()
            .contains("fob login other")
    );

    let (stdout, _) = fob.ok(&["check", "--integration", "acme"]);
    assert_eq!(lines(&stdout).len(), 1, "{stdout}");
    assert!(stdout.starts_with("ok   acme: "), "{stdout}");
    let stderr = fob.fails(&["check", "--integration", "nope"]);
    assert!(stderr.contains("nope"), "{stderr}");

    // The mock has no STS, so the profile's check fails, in JSON too.
    let output = fob.run(&["check", "acme/prod/Admin", "--json"]);
    assert!(!output.status.success());
    let checked: Value = serde_json::from_str(&texts(&output).0).unwrap();
    assert_eq!(checked[0]["profile"], "acme/prod/Admin");
    assert_eq!(checked[0]["ok"], false);
}

/// Under an agent, `fob list` shows every profile but marks the ones
/// `[agent] profiles` keeps from it.
#[tokio::test(flavor = "multi_thread")]
async fn an_agent_sees_which_profiles_are_closed_to_it() {
    let (fob, _server) = synced_portal("agent-list").await;
    let mut config = portal_config("acme");
    config.push_str("\n[agent]\nprofiles = [\"acme/dev/*\"]\n");
    fob.write_config(&config);
    let output = fob.run_as_agent(&["list"]);
    let (stdout, _) = texts(&output);
    assert_eq!(
        lines(&stdout),
        ["acme/dev/Admin", "acme/prod/Admin (not open to agents)"]
    );
    assert!(!stdout.contains("OMNIFOB_AGENT"), "{stdout}");
    let output = fob.run_as_agent(&["list", "--json"]);
    let profiles: Value = serde_json::from_str(&texts(&output).0).unwrap();
    assert_eq!(profiles[0]["open_to_agents"], true);
    assert_eq!(profiles[1]["open_to_agents"], false);
    // People see the list as it is.
    let (stdout, _) = fob.ok(&["list"]);
    assert_eq!(lines(&stdout), ["acme/dev/Admin", "acme/prod/Admin"]);
    let (stdout, _) = fob.ok(&["list", "--json"]);
    assert!(!stdout.contains("open_to_agents"), "{stdout}");
}

/// `fob revoke --all` clears every cached credential; `fob logout --all`
/// signs out of every integration and goes on past those not signed in.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_and_logout_all() {
    let (fob, server) = synced_portal("all").await;
    Mock::given(method("POST"))
        .and(path("/logout"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    for profile in ["acme/dev/Admin", "acme/prod/Admin"] {
        fob.ok(&["creds", profile, "--format", "credential-process"]);
        assert!(fob.secret(&format!("credentials/{profile}")).exists());
    }
    let (_, stderr) = fob.ok(&["revoke", "--all"]);
    assert!(
        stderr.contains("deleted 0 token(s) and cleared the cache of 2 profile(s)"),
        "{stderr}"
    );
    for profile in ["acme/dev/Admin", "acme/prod/Admin"] {
        assert!(!fob.secret(&format!("credentials/{profile}")).exists());
    }
    fob.fails(&["revoke", "--all", "acme/dev/Admin"]);
    // A corrupt profiles.json does not stop it: the Cloudflare tokens are
    // read from the catalog.
    let profiles = fob.root.join("state").join("omnifob").join("profiles.json");
    let saved = std::fs::read(&profiles).unwrap();
    std::fs::write(&profiles, "{ not json").unwrap();
    let (_, stderr) = fob.ok(&["revoke", "--all"]);
    assert!(
        stderr.contains("ignoring the discovered profiles"),
        "{stderr}"
    );
    std::fs::write(&profiles, saved).unwrap();

    let mut config = portal_config("acme");
    config.push_str(&portal_config("other").replace("acme.awsapps.com", "other.awsapps.com"));
    fob.write_config(&config);
    let (_, stderr) = fob.ok(&["logout", "--all"]);
    assert!(stderr.contains("fob: signed out of 'acme'"), "{stderr}");
    assert!(
        stderr.contains("fob: 'other' was not signed in"),
        "{stderr}"
    );
    assert!(!fob.secret("aws-sso/acme/token").exists());
}

#[test]
fn import_brings_in_console_sign_ins_and_skips_what_the_config_would_refuse() {
    let fob = Fob::new("import-aws");
    fob.write_config("[integrations.console]\ntype = \"aws-login\"\nregion = \"eu-west-1\"\n");
    std::fs::write(
        fob.aws_config(),
        "[profile p]\r\nsso_start_url = https://acme.awsapps.com/start\r\nsso_region = us-east-1\r\n\
         sso_account_id = 111111111111\r\nsso_role_name = Admin\r\n\
         [profile Deploy]\r\nrole_arn = arn:aws:iam::222222222222:role/Deploy\r\nsource_profile = p\r\n\
         [profile deploy]\r\nrole_arn = arn:aws:iam::333333333333:role/Deploy\r\nsource_profile = p\r\n\
         [profile typo]\r\nrole_arn = arn:aws:iam::2222:role/Deploy\r\nsource_profile = p\r\n\
         [profile console]\r\nlogin_session = arn:aws:iam::111111111111:user/me\r\nregion = eu-west-1\r\n\
         [profile laptop]\r\nlogin_session = arn:aws:iam::111111111111:user/me\r\nregion = us-west-2\r\n",
    )
    .unwrap();
    let (stdout, stderr) = fob.ok(&["import", "aws"]);
    assert!(stderr.contains("skipped profile 'typo'"), "{stderr}");
    assert!(
        stderr.contains(
            "profile 'console' (an `aws login` sign-in) is already configured as 'console'"
        ),
        "{stderr}"
    );
    assert!(
        stderr.contains(
            "profile 'laptop' (an `aws login` sign-in) as aws-login 'laptop' in us-west-2"
        ),
        "{stderr}"
    );
    assert!(
        stdout.contains("[integrations.laptop]\ntype = \"aws-login\"\nregion = \"us-west-2\"\n"),
        "{stdout}"
    );
    assert!(
        stdout.contains("chained.\"deploy\"]") && stdout.contains("chained.\"deploy-2\"]"),
        "{stdout}"
    );

    let (_, stderr) = fob.ok(&["import", "aws", "--write"]);
    assert!(
        stderr.contains("`fob login laptop` to sign in through omnifob"),
        "{stderr}"
    );
    let config = omnifob_core::Config::load(&fob.config_file()).unwrap();
    assert!(matches!(
        config.integrations["laptop"],
        omnifob_core::Integration::AwsLogin(_)
    ));
    let omnifob_core::Integration::AwsSso(portal) = &config.integrations["acme"] else {
        panic!("{:?}", config.integrations.keys());
    };
    assert_eq!(
        portal.chained.keys().collect::<Vec<_>>(),
        ["deploy", "deploy-2"]
    );
    let (_, stderr) = fob.ok(&["import", "aws"]);
    assert!(stderr.contains("nothing new to import"), "{stderr}");
}
