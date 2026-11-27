//! End-to-end tests: each runs the built `fob` binary against its own
//! scratch config, state directory and plaintext test store
//! (`OMNIFOB_KEYRING=test-plaintext-files:<dir>`), with every provider call
//! sent to a local mock (`OMNIFOB_AWS_ENDPOINT`, `OMNIFOB_AZURE_ENDPOINT`,
//! `OMNIFOB_GOOGLE_ENDPOINT`, `OMNIFOB_CLOUDFLARE_API` and `_DASH`). Nothing
//! touches the real keychain, a browser or the network beyond localhost, so
//! the tests run in parallel; browser sign-ins are answered on fob's
//! loopback listener as the browser would.

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
    /// Variables set for every command, such as the endpoints of providers
    /// other than AWS.
    vars: Vec<(String, String)>,
}

impl Fob {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("omnifob-e2e-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("aws")).unwrap();
        std::fs::create_dir_all(root.join("home")).unwrap();
        Self {
            root,
            endpoint: None,
            vars: Vec::new(),
        }
    }

    /// Sets `name` to `value` for every command.
    fn with_var(mut self, name: &str, value: &str) -> Self {
        self.vars.push((name.to_string(), value.to_string()));
        self
    }

    /// Stores `value` under the keychain key `key`, as a provider would.
    fn put_secret(&self, key: &str, value: &Value) {
        std::fs::create_dir_all(self.keyring()).unwrap();
        std::fs::write(self.secret(key), value.to_string()).unwrap();
    }

    /// Runs fob with `stdin` as its input, expecting success; returns
    /// stdout and stderr.
    fn ok_with_stdin(&self, args: &[&str], stdin: &str) -> (String, String) {
        let output = self.run_with_stdin(args, stdin);
        let (stdout, stderr) = texts(&output);
        assert!(
            output.status.success(),
            "fob {args:?} failed\nstdout: {stdout}\nstderr: {stderr}"
        );
        (stdout, stderr)
    }

    /// Runs fob with `stdin` as its input.
    fn run_with_stdin(&self, args: &[&str], stdin: &str) -> Output {
        use std::io::Write;
        let mut child = self
            .command(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    /// Sends every AWS call to `server`.
    fn with_server(mut self, server: &MockServer) -> Self {
        self.endpoint = Some(server.uri());
        self
    }

    fn config_file(&self) -> PathBuf {
        self.root.join("config.toml")
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
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
            // Where a browser sign-in opens is decided from these.
            let remote =
                ["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY", "CODESPACES"].contains(&&*name);
            if name.starts_with("AWS_")
                || name.starts_with("OMNIFOB_")
                || name.starts_with("AZURE_")
                || name.starts_with("ARM_")
                || name.starts_with("GOOGLE_")
                || name.starts_with("CLOUDSDK_")
                || name.starts_with("CLOUDFLARE_")
                || remote
                || name == "COMPLETE"
                // Where installed agent skills are looked for.
                || ["CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_CONFIG_HOME"].contains(&&*name)
                || proxy
                || agent
            {
                cmd.env_remove(&*name);
            }
        }
        // A proxy must not get between fob and the local mock.
        cmd.env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost");
        // A home of its own, so skills installed on the machine stay out.
        cmd.env("HOME", self.home()).env("USERPROFILE", self.home());
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
        cmd.envs(self.vars.iter().map(|(k, v)| (k, v)));
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

/// `fob login --start` shows the code and returns, so an agent can pass it
/// on; `--wait` then finishes the sign-in in another process.
#[tokio::test(flavor = "multi_thread")]
async fn a_device_sign_in_starts_and_finishes_in_two_steps() {
    let server = MockServer::start().await;
    let fob = Fob::new("login-two-step").with_server(&server);
    fob.write_config(&format!(
        "{}\n[integrations.tok]\ntype = \"token\"\npreset = \"github\"\n",
        portal_config("acme")
    ));
    mount_device_sign_in(&server).await;
    mount_portal(&server, &[("111111111111", "Dev")]).await;

    let stderr = fob.fails(&["login", "acme", "--wait"]);
    assert!(
        stderr.contains(
            "no device sign-in was started for 'acme'; run `fob login acme --start` first"
        ),
        "{stderr}"
    );
    let output = fob.run_as_agent(&["login", "acme", "--start", "--no-browser"]);
    let (_, stderr) = texts(&output);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("https://device.example/?code=ABCD-EFGH"),
        "{stderr}"
    );
    assert!(stderr.contains("code: ABCD-EFGH"), "{stderr}");
    assert!(
        stderr.contains("then run `fob login acme --wait`"),
        "{stderr}"
    );
    assert!(fob.secret("aws-sso/acme/pending").exists());
    assert!(!fob.secret("aws-sso/acme/token").exists());

    let output = fob.run_as_agent(&["login", "acme", "--wait"]);
    let (_, stderr) = texts(&output);
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("signed in to 'acme'"), "{stderr}");
    assert!(stderr.contains("acme: 1 profiles"), "{stderr}");
    assert!(fob.secret("aws-sso/acme/token").exists());
    assert!(!fob.secret("aws-sso/acme/pending").exists());

    // Signed in: both steps keep the sign-in rather than start another.
    for args in [
        &["login", "acme", "--start"][..],
        &["login", "acme", "--wait"],
    ] {
        let (_, stderr) = fob.ok(args);
        assert!(stderr.contains("kept the sign-in of 'acme'"), "{stderr}");
    }
    assert!(!fob.secret("aws-sso/acme/pending").exists());

    let stderr = fob.fails(&["login", "tok", "--start"]);
    assert!(
        stderr.contains("--start and --wait apply to device sign-ins"),
        "{stderr}"
    );
    let stderr = fob.fails(&["login", "acme", "--start", "--wait"]);
    assert!(stderr.contains("cannot be used with"), "{stderr}");
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
async fn one_account_is_listed_by_access_with_the_role_each_chained_one_comes_from() {
    let server = MockServer::start().await;
    let fob = Fob::new("account").with_server(&server);
    fob.write_config(&format!(
        "{}[integrations.acme.chained_rules.root]\nvia_role = \"Admin\"\nrole_name = \"root\"\n\
         [integrations.acme.chained_rules.ro]\nvia_role = \"Admin\"\nrole_name = \"ReadOnly\"\n\
         [integrations.acme.chained_rules.bg]\nvia_role = \"Admin\"\nrole_name = \"breakglass\"\n",
        portal_config("acme")
    ));
    fob.sign_in("acme");
    mount_portal(
        &server,
        &[("111111111111", "Dev"), ("222222222222", "Prod")],
    )
    .await;
    fob.ok(&["sync"]);

    let rows = |args: &[&str]| -> Vec<(String, Value, Value)> {
        let (stdout, _) = fob.ok(args);
        let rows: Value = serde_json::from_str(&stdout).unwrap();
        rows.as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["id"].as_str().unwrap().to_string(),
                    r["access"].clone(),
                    r["via"].clone(),
                )
            })
            .collect()
    };
    // Least access first; a role without a label may be anything, so last.
    let prod = vec![
        (
            "acme/prod/ReadOnly".to_string(),
            json!("read"),
            json!("acme/prod/Admin"),
        ),
        ("acme/prod/Admin".to_string(), json!("admin"), Value::Null),
        (
            "acme/prod/root".to_string(),
            json!("admin"),
            json!("acme/prod/Admin"),
        ),
        (
            "acme/prod/breakglass".to_string(),
            Value::Null,
            json!("acme/prod/Admin"),
        ),
    ];
    // By a profile in the account, or by the account ID.
    assert_eq!(
        rows(&["list", "--json", "--account", "acme/prod/Admin"]),
        prod
    );
    assert_eq!(rows(&["list", "--json", "--account", "222222222222"]), prod);
    // The rule covers every account with the permission set.
    assert_eq!(
        rows(&["list", "--json", "--account", "dev root"])[2].2,
        json!("acme/dev/Admin")
    );

    let stderr = fob.fails(&["list", "--account", "nothing"]);
    assert!(
        stderr.contains("no profile or account matches 'nothing'"),
        "{stderr}"
    );
    let stderr = fob.fails(&["list", "--account", "acme"]);
    assert!(stderr.contains("'acme' matches 8 profiles"), "{stderr}");
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

/// The `fob-error:` line that ends stderr under an agent, as JSON.
fn error_line(output: &Output) -> Value {
    let (_, stderr) = texts(output);
    let last = stderr.lines().last().unwrap_or_default();
    let json = last
        .strip_prefix("fob-error: ")
        .unwrap_or_else(|| panic!("no fob-error line: {stderr}"));
    serde_json::from_str(json).unwrap()
}

/// Under an agent, or with `OMNIFOB_ERROR_FORMAT=json`, a failure ends with
/// a line programs read: its code and the values to act on, so the agent
/// does not depend on the wording.
#[tokio::test(flavor = "multi_thread")]
async fn failures_carry_a_code_for_agents_and_scripts() {
    let (fob, _server) = synced_portal("error-codes").await;
    let output = fob.run_as_agent(&["exec", "prod", "--", "true"]);
    assert_eq!(output.status.code(), Some(125));
    let error = error_line(&output);
    assert_eq!(error["code"], "profile_ambiguous", "{error}");
    assert_eq!(error["query"], "prod", "{error}");
    assert_eq!(error["candidates"], json!(["acme/prod/Admin"]), "{error}");
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .starts_with("name the profile by its full id"),
        "{error}"
    );

    let error = error_line(&fob.run_as_agent(&["exec", "nothing-like-it", "--", "true"]));
    assert_eq!(error["code"], "profile_not_found", "{error}");
    let error = error_line(&fob.run_as_agent(&["creds", "acme/prod/Admin"]));
    assert_eq!(error["code"], "use_exec", "{error}");
    assert_eq!(
        error["run"], "fob exec acme/prod/Admin -- <command>",
        "{error}"
    );
    let error = error_line(&fob.run_as_agent(&["login", "nope"]));
    assert_eq!(error["code"], "integration_not_found", "{error}");
    assert_eq!(error["configured"], json!(["acme"]), "{error}");

    // People see the message alone, unless they ask for the line.
    let stderr = fob.fails(&["exec", "nothing-like-it", "--", "true"]);
    assert!(!stderr.contains("fob-error"), "{stderr}");
    let output = fob
        .command(&["exec", "nothing-like-it", "--", "true"])
        .env("OMNIFOB_ERROR_FORMAT", "json")
        .output()
        .unwrap();
    assert_eq!(error_line(&output)["code"], "profile_not_found");

    let mut config = portal_config("acme");
    config.push_str("\n[agent]\nprofiles = [\"acme/dev/*\"]\n");
    fob.write_config(&config);
    let error = error_line(&fob.run_as_agent(&["exec", "acme/prod/Admin", "--", "true"]));
    assert_eq!(error["code"], "not_open_to_agents", "{error}");
    assert_eq!(error["profile"], "acme/prod/Admin", "{error}");

    fob.write_config(&portal_config("acme"));
    std::fs::remove_file(fob.secret("aws-sso/acme/token")).unwrap();
    let error = error_line(&fob.run_as_agent(&["exec", "acme/dev/Admin", "--", "true"]));
    assert_eq!(error["code"], "login_required", "{error}");
    assert_eq!(error["integration"], "acme", "{error}");
    assert_eq!(error["run"], "fob login acme", "{error}");
    let (stdout, _) = texts(&fob.run(&["check", "--json"]));
    let rows: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(rows[0]["code"], "login_required", "{rows}");

    fob.write_config("[integrations.acme\nbroken");
    let error = error_line(&fob.run_as_agent(&["list"]));
    assert_eq!(error["code"], "config_invalid", "{error}");
    assert!(
        error["path"].as_str().unwrap().ends_with("config.toml"),
        "{error}"
    );
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
async fn a_command_integration_runs_its_program_and_caches_by_expiry() {
    let (fob, server) = synced_portal("command").await;
    // `fob creds` itself is the helper: it runs on every platform and
    // prints the AWS credential_process format.
    let mut config = portal_config("acme");
    config.push_str(&format!(
        "\n[integrations.wrapped]\ntype = \"command\"\ncommand = ['{FOB}', \"creds\", \"acme/prod/Admin\", \"--format\", \"credential-process\", \"--no-cache\"]\nformat = \"credential-process\"\nregion = \"eu-west-1\"\n"
    ));
    fob.write_config(&config);
    let stderr = fob.ok(&["login", "wrapped"]).1;
    assert!(stderr.contains("has nothing to sign in to"), "{stderr}");
    let (list, _) = fob.ok(&["list", "wrapped"]);
    assert!(list.contains("wrapped/default/fob"), "{list}");
    let fetches = || async {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == "/federation/credentials")
            .count()
    };
    let before = fetches().await;
    for _ in 0..2 {
        let (stdout, _) = fob.ok(&["creds", "wrapped/default/fob"]);
        let value: Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(value["env"]["AWS_ACCESS_KEY_ID"], "ASIA222222222222");
        assert_eq!(value["env"]["AWS_ACCOUNT_ID"], "222222222222");
        assert_eq!(value["env"]["AWS_REGION"], "eu-west-1");
        assert_eq!(value["expires_at"], "2100-01-01T00:00:00Z");
    }
    // The program ran once; the second call came from the cache.
    assert_eq!(fetches().await, before + 1);
    let stderr = fob.fails(&["creds", "wrapped/default/fob", "--ttl", "30m"]);
    assert!(stderr.contains("set `ttl` on 'wrapped'"), "{stderr}");
}

#[test]
fn the_encrypted_vault_keeps_secrets_sealed_with_a_passphrase() {
    let fob = Fob::new("vault");
    fob.write_config(
        "[integrations.t]\ntype = \"token\"\n[integrations.t.secrets]\nkey = [\"MY_KEY\"]\n",
    );
    let vault = fob.root.join("vault");
    let run = |args: &[&str], passphrase: Option<&str>, stdin: Option<&str>| {
        use std::io::Write;
        let mut cmd = fob.command(args);
        cmd.env(
            "OMNIFOB_KEYRING",
            format!("encrypted-file:{}", vault.display()),
        )
        .env("OMNIFOB_VAULT_KEY_CACHE", "0")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
        if let Some(p) = passphrase {
            cmd.env("OMNIFOB_VAULT_PASSPHRASE", p);
        }
        let mut child = cmd.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.unwrap_or_default().as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };
    let pass = Some("a vault passphrase");
    let output = run(
        &["login", "t", "--token-stdin"],
        pass,
        Some("vault-secret-123"),
    );
    assert!(output.status.success(), "{:?}", texts(&output));
    let output = run(&["creds", "t/default/token"], pass, None);
    assert!(output.status.success(), "{:?}", texts(&output));
    assert!(texts(&output).0.contains("vault-secret-123"));
    let names = entries(&vault);
    assert!(names.contains(&"vault.json".to_string()), "{names:?}");
    assert!(
        names.contains(&"token%2Ft%2Fsecrets.sealed".to_string()),
        "{names:?}"
    );
    for name in &names {
        let bytes = std::fs::read(vault.join(name)).unwrap();
        assert!(
            !String::from_utf8_lossy(&bytes).contains("vault-secret"),
            "{name}"
        );
    }
    let status = texts(&run(&["status"], pass, None)).0;
    assert!(
        status.contains("files encrypted with a passphrase in"),
        "{status}"
    );
    // The command gets the secret, never the vault's passphrase.
    let keyring = format!("encrypted-file:{}", vault.display());
    let seen = exec_child(
        &fob,
        "t/default/token",
        &[
            ("OMNIFOB_KEYRING", &keyring),
            ("OMNIFOB_VAULT_KEY_CACHE", "0"),
            ("OMNIFOB_VAULT_PASSPHRASE", "a vault passphrase"),
        ],
        &["MY_KEY", "OMNIFOB_VAULT_PASSPHRASE"],
    );
    assert_eq!(
        seen,
        ["MY_KEY=vault-secret-123", "OMNIFOB_VAULT_PASSPHRASE unset"]
    );

    let stderr = texts(&run(
        &["creds", "t/default/token"],
        Some("another passphrase"),
        None,
    ))
    .1;
    assert!(stderr.contains("wrong passphrase"), "{stderr}");
    // Without a terminal or a passphrase, the vault stays locked.
    let output = run(&["creds", "t/default/token"], None, None);
    assert!(!output.status.success());
    assert!(
        texts(&output).1.contains("is locked"),
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
type = "command"
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

/// `fob status` says when the token of a sign-in that renews has expired,
/// rather than "signed in", and `--check` asks the provider.
#[tokio::test(flavor = "multi_thread")]
async fn status_does_not_call_a_lapsed_portal_session_signed_in() {
    let (fob, _server) = synced_portal("status-lapsed").await;
    let token = fob.secret("aws-sso/acme/token");
    let mut stored: Value =
        serde_json::from_str(&std::fs::read_to_string(&token).unwrap()).unwrap();
    stored["expires_at"] = json!("2020-01-01T00:00:00Z");
    stored["refresh_token"] = json!("refresh-1");
    std::fs::write(&token, stored.to_string()).unwrap();
    let (stdout, _) = fob.ok(&["status"]);
    assert!(stdout.contains("acme  aws-sso  token expired"), "{stdout}");
    assert!(
        stdout.contains("if the portal session is still open"),
        "{stdout}"
    );
    assert!(stdout.contains("fob status --check"), "{stdout}");
    let (stdout, _) = fob.ok(&["status", "--json"]);
    let value: Value = serde_json::from_str(&stdout).unwrap();
    let acme = &value["integrations"][0];
    assert_eq!(acme["needs_check"], json!(true), "{acme}");
    assert_eq!(acme["renews"], json!(true), "{acme}");
    assert_eq!(acme["check"], Value::Null, "{acme}");
}

/// With `--check`, the state comes from the provider, as in `fob check`.
#[tokio::test(flavor = "multi_thread")]
async fn status_check_asks_the_provider() {
    let (fob, _server) = synced_portal("status-check").await;
    let (stdout, _) = fob.ok(&["status", "--check"]);
    assert!(stdout.contains("acme  aws-sso  works: "), "{stdout}");
    assert!(!stdout.contains("fob status --check"), "{stdout}");
    let (stdout, _) = fob.ok(&["status", "--check", "--json"]);
    let value: Value = serde_json::from_str(&stdout).unwrap();
    let acme = &value["integrations"][0];
    assert_eq!(acme["check"]["ok"], json!(true), "{acme}");
    assert_eq!(acme["signed_in"], json!(true), "{acme}");
    assert_eq!(acme["needs_check"], json!(false), "{acme}");

    std::fs::remove_file(fob.secret("aws-sso/acme/token")).unwrap();
    let output = fob.run(&["status", "--check"]);
    let (stdout, _) = texts(&output);
    assert!(!output.status.success(), "{stdout}");
    assert!(
        stdout.contains("FAILS: not signed in to 'acme'"),
        "{stdout}"
    );
}

/// A copy of the agent skill from another release is pointed out, once
/// however many skill folders link to it: by `fob status`, and to agents
/// by `fob list`, the first command the skill has them run.
#[tokio::test(flavor = "multi_thread")]
async fn an_out_of_date_agent_skill_is_pointed_out() {
    let (fob, _server) = synced_portal("skill").await;
    let skill = |dir: &str, version: &str| {
        let dir = fob.home().join(dir).join("omnifob");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("SKILL.md"),
            format!("---\nname: omnifob\nmetadata:\n  fob-version: \"{version}\"\n---\n"),
        )
        .unwrap();
    };
    skill(".claude/skills", env!("CARGO_PKG_VERSION"));
    let (stdout, _) = fob.ok(&["status"]);
    assert!(!stdout.contains("Note:"), "{stdout}");
    skill(".agents/skills", "0.0.1");
    let (stdout, _) = fob.ok(&["status"]);
    let notes: Vec<&str> = stdout.lines().filter(|l| l.starts_with("Note:")).collect();
    assert_eq!(notes.len(), 1, "{stdout}");
    assert!(notes[0].contains("describes fob 0.0.1"), "{stdout}");
    assert!(notes[0].contains("npx skills update"), "{stdout}");
    let (stdout, _) = fob.ok(&["status", "--json"]);
    let value: Value = serde_json::from_str(&stdout).unwrap();
    let current: Vec<bool> = value["skills"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["current"].as_bool().unwrap())
        .collect();
    assert_eq!(current, [false, true], "{value}");

    let (_, stderr) = fob.ok(&["list"]);
    assert!(!stderr.contains("describes fob"), "{stderr}");
    let output = fob.run_as_agent(&["list"]);
    let (_, stderr) = texts(&output);
    assert!(stderr.contains("describes fob 0.0.1"), "{stderr}");
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

/// `fob list` labels each profile's environment and access level, from
/// `[[labels]]` or guessed from its id, says where each came from, and
/// notes integrations whose sign-in lapsed; scripts reading plain output
/// still get bare ids.
#[tokio::test(flavor = "multi_thread")]
async fn profiles_are_listed_with_labels_and_sign_in_state() {
    let (fob, _server) = synced_portal("labels").await;
    let mut config = portal_config("acme");
    config.push_str(
        "\n[[labels]]\nprofiles = [\"acme/prod/*\"]\nenv = \"production\"\naccess = \"read\"\n",
    );
    fob.write_config(&config);
    let (stdout, _) = fob.ok(&["list", "--json"]);
    let profiles: Value = serde_json::from_str(&stdout).unwrap();
    let dev = &profiles[0];
    assert_eq!(dev["id"], "acme/dev/Admin");
    assert_eq!(dev["env"], "dev", "{dev}");
    assert_eq!(dev["env_source"], "name", "{dev}");
    assert_eq!(dev["access"], "admin", "{dev}");
    assert_eq!(dev["access_source"], "name", "{dev}");
    assert_eq!(dev["sign_in"], "signed_in", "{dev}");
    let prod = &profiles[1];
    assert_eq!(prod["env"], "production", "{prod}");
    assert_eq!(prod["env_source"], "config", "{prod}");
    assert_eq!(prod["access"], "read", "{prod}");
    assert_eq!(prod["access_source"], "config", "{prod}");

    let (stdout, _) = fob.ok(&["list"]);
    assert_eq!(lines(&stdout), ["acme/dev/Admin", "acme/prod/Admin"]);
    let output = fob.run_as_agent(&["list"]);
    let (stdout, stderr) = texts(&output);
    assert_eq!(
        lines(&stdout),
        [
            "acme/dev/Admin   dev?        admin?",
            "acme/prod/Admin  production  read"
        ]
    );
    assert!(stderr.contains("? marks a guess"), "{stderr}");

    std::fs::remove_file(fob.secret("aws-sso/acme/token")).unwrap();
    let (stdout, _) = texts(&fob.run_as_agent(&["list"]));
    assert!(lines(&stdout)[0].ends_with("(signed out)"), "{stdout}");
    let (stdout, _) = fob.ok(&["list", "--json"]);
    let profiles: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(profiles[0]["sign_in"], "signed_out");
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
        [
            "acme/dev/Admin   dev?   admin?",
            "acme/prod/Admin  prod?  admin?  (not open to agents)"
        ]
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

#[test]
fn import_folds_a_role_every_account_has_into_a_rule_once() {
    let fob = Fob::new("import-rules");
    fob.write_config("");
    let mut text = String::from(
        "[sso-session acme]\nsso_start_url = https://acme.awsapps.com/start\nsso_region = eu-west-1\n",
    );
    for (name, account) in [("dev", "111111111111"), ("prd", "222222222222")] {
        text.push_str(&format!(
            "[profile {name}-pe]\nsso_session = acme\nsso_account_id = {account}\nsso_role_name = pe\n\
             [profile {name}-root]\nsource_profile = {name}-pe\nrole_arn = arn:aws:iam::{account}:role/root\n"
        ));
    }
    std::fs::write(fob.aws_config(), &text).unwrap();
    let (_, stderr) = fob.ok(&["import", "aws", "--write"]);
    assert!(
        stderr.contains("0 chained role(s), 1 chained rule(s)"),
        "{stderr}"
    );
    let config = omnifob_core::Config::load(&fob.config_file()).unwrap();
    let omnifob_core::Integration::AwsSso(portal) = &config.integrations["acme"] else {
        panic!("{:?}", config.integrations.keys());
    };
    assert_eq!(
        portal.chained_rules["root"].accounts,
        ["111111111111", "222222222222"]
    );
    assert!(portal.chained.is_empty());

    // A third account's role is one the rule does not cover yet, so it comes
    // in as a table; the two the rule gives are not imported again.
    text.push_str(
        "[profile ops-pe]\nsso_session = acme\nsso_account_id = 333333333333\nsso_role_name = pe\n\
         [profile ops-root]\nsource_profile = ops-pe\nrole_arn = arn:aws:iam::333333333333:role/root\n",
    );
    std::fs::write(fob.aws_config(), &text).unwrap();
    let (stdout, stderr) = fob.ok(&["import", "aws"]);
    assert!(
        stderr.contains("1 chained role(s) and 0 chained rule(s) to add"),
        "{stderr}"
    );
    assert!(
        stdout.contains("chained.\"root-333333333333\"]")
            && stdout.contains("arn:aws:iam::333333333333:role/root"),
        "{stdout}"
    );
}

// Providers other than IAM Identity Center, each against a mock of its
// APIs: sign-in, discovery, `fob exec`, `fob console` and sign-out.

/// Decodes `application/x-www-form-urlencoded` text.
fn form_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap();
                out.push(u8::from_str_radix(hex, 16).unwrap());
                i += 2;
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8(out).unwrap()
}

/// The decoded pairs of a URL's query, or of a form body.
fn pairs(text: &str) -> std::collections::HashMap<String, String> {
    let query = text.split_once('?').map_or(text, |(_, q)| q);
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (form_decode(k), form_decode(v)))
        .collect()
}

/// Whether a sign-in opens a browser on this machine here: not in a
/// container, where fob signs in with a code instead.
fn browser_is_here() -> bool {
    !["/.dockerenv", "/run/.containerenv"]
        .iter()
        .any(|p| Path::new(p).exists())
}

/// What a browser sign-in left: fob's exit status and output, and the
/// authorize URL's query.
struct SignedInThroughBrowser {
    status: std::process::ExitStatus,
    stderr: String,
    query: std::collections::HashMap<String, String>,
}

/// Runs `fob <args>` (a browser sign-in, with `--no-browser` so nothing
/// opens), and answers it as the browser does once the user approved: it
/// calls the loopback redirect with `code=code-1`, the `state`, and
/// `extra`.
fn browser_sign_in(fob: &Fob, args: &[&str], extra: &str) -> SignedInThroughBrowser {
    use std::io::{BufRead, BufReader, Read, Write};
    let mut child = fob
        .command(args)
        // A display to open the browser on, as far as fob can tell.
        .env("BROWSER", "true")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut seen = String::new();
    let url = loop {
        let mut line = String::new();
        if stderr.read_line(&mut line).unwrap() == 0 {
            let _ = child.kill();
            panic!("fob {args:?} printed no sign-in URL:\n{seen}");
        }
        seen.push_str(&line);
        if let Some(url) = line
            .split_whitespace()
            .find(|w| w.starts_with("http") && w.contains("redirect_uri="))
        {
            break url.to_string();
        }
    };
    let query = pairs(&url);
    let redirect = &query["redirect_uri"];
    let rest = redirect
        .split_once("://")
        .map_or(redirect.as_str(), |(_, r)| r);
    let (authority, callback) = rest.split_once('/').unwrap_or((rest, ""));
    let port: u16 = authority.rsplit(':').next().unwrap().parse().unwrap();
    let mut socket = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        socket,
        "GET /{callback}?code=code-1&state={}{extra} HTTP/1.1\r\nHost: x\r\n\r\n",
        query["state"]
    )
    .unwrap();
    let mut reply = String::new();
    socket.read_to_string(&mut reply).unwrap();
    assert!(reply.contains("Sign-in approved"), "{reply}");
    stderr.read_to_string(&mut seen).unwrap();
    SignedInThroughBrowser {
        status: child.wait().unwrap(),
        stderr: seen,
        query,
    }
}

/// An STS response to `action` carrying `result`.
fn sts(action: &str, result: &str) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("content-type", "text/xml")
        .set_body_string(format!(
            r#"<{action}Response xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><{action}Result>{result}</{action}Result><ResponseMetadata><RequestId>1</RequestId></ResponseMetadata></{action}Response>"#
        ))
}

/// STS and the federation endpoint: the IAM user `me` in 123456789012, its
/// session `ASIASESSION`, roles `ASIAROLE`, and console sign-in tokens.
async fn mount_sts(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/federation"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "SigninToken": "signin-1" })),
        )
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(|r: &Request| {
            let body = pairs(&String::from_utf8_lossy(&r.body));
            let credentials = |key: &str| {
                format!("<Credentials><AccessKeyId>{key}</AccessKeyId><SecretAccessKey>s</SecretAccessKey><SessionToken>t</SessionToken><Expiration>2100-01-01T00:00:00Z</Expiration></Credentials>")
            };
            match body.get("Action").map(String::as_str) {
                Some("GetCallerIdentity") => sts(
                    "GetCallerIdentity",
                    "<Arn>arn:aws:iam::123456789012:user/me</Arn><UserId>AIDAEXAMPLE</UserId><Account>123456789012</Account>",
                ),
                Some("GetSessionToken") => sts("GetSessionToken", &credentials("ASIASESSION")),
                Some("AssumeRole") => sts(
                    "AssumeRole",
                    &format!(
                        "{}<AssumedRoleUser><AssumedRoleId>AROA:omnifob</AssumedRoleId><Arn>arn:aws:sts::222222222222:assumed-role/Deploy/omnifob</Arn></AssumedRoleUser>",
                        credentials("ASIAROLE")
                    ),
                ),
                _ => ResponseTemplate::new(400),
            }
        })
        .mount(server)
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_iam_user_signs_in_from_stdin_and_runs_commands() {
    let server = MockServer::start().await;
    mount_sts(&server).await;
    let fob = Fob::new("aws-iam").with_server(&server);
    fob.write_config(
        r#"[integrations.legacy]
type = "aws-iam"
region = "eu-west-1"

[integrations.legacy.roles.prod]
role_arn = "arn:aws:iam::222222222222:role/Deploy"
"#,
    );
    // The clipboard holds one value at most; the key has two.
    let stderr = fob.fails(&["login", "legacy", "--from-clipboard"]);
    assert!(stderr.contains("pipe both to --token-stdin"), "{stderr}");
    let (_, stderr) = fob.ok_with_stdin(
        &["login", "legacy", "--token-stdin"],
        "AKIAEXAMPLE\n  long-term-secret\n",
    );
    assert!(stderr.contains("legacy: 2 profiles"), "{stderr}");
    assert!(fob.secret("aws-iam/legacy/key").exists());
    let (stdout, _) = fob.ok(&["list"]);
    assert_eq!(
        lines(&stdout),
        ["legacy/123456789012/session", "legacy/prod/Deploy"]
    );

    let printed = exec_child(
        &fob,
        "legacy/prod/Deploy",
        &[],
        &["AWS_ACCESS_KEY_ID", "AWS_ACCOUNT_ID", "AWS_REGION"],
    );
    assert_eq!(
        printed,
        [
            "AWS_ACCESS_KEY_ID=ASIAROLE",
            "AWS_ACCOUNT_ID=222222222222",
            "AWS_REGION=eu-west-1"
        ]
    );
    let printed = exec_child(
        &fob,
        "legacy/123456789012/session",
        &[],
        &["AWS_ACCESS_KEY_ID"],
    );
    assert_eq!(printed, ["AWS_ACCESS_KEY_ID=ASIASESSION"]);
    // The long-term key is never handed out.
    let (stdout, _) = fob.ok(&["creds", "legacy/123456789012/session"]);
    assert!(!stdout.contains("AKIAEXAMPLE"), "{stdout}");

    let (stdout, _) = fob.ok(&["console", "legacy/prod/Deploy", "--print"]);
    assert!(stdout.contains("SigninToken=signin-1"), "{stdout}");

    let (_, stderr) = fob.ok(&["logout", "legacy"]);
    assert!(stderr.contains("signed out of 'legacy'"), "{stderr}");
    assert!(!fob.secret("aws-iam/legacy/key").exists());
    let stderr = fob.fails(&["exec", "legacy/prod/Deploy", "--no-cache", "--", "true"]);
    assert!(stderr.contains("fob login legacy"), "{stderr}");
}

/// AWS Sign-In's token endpoint: a code gives `ASIALOGIN1`, each refresh
/// `ASIALOGIN2`, both for an hour.
async fn mount_aws_sign_in(server: &MockServer) {
    let id_token = {
        use base64::Engine;
        let encode = |v: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
        format!(
            "{}.{}.",
            encode(r#"{"alg":"none"}"#),
            encode(r#"{"sub":"arn:aws:iam::123456789012:user/alice"}"#)
        )
    };
    Mock::given(method("POST"))
        .and(path("/v1/token"))
        .respond_with(move |r: &Request| {
            let body: Value = serde_json::from_slice(&r.body).unwrap();
            let key = match body["grantType"].as_str() {
                Some("authorization_code") => "ASIALOGIN1",
                _ => "ASIALOGIN2",
            };
            ResponseTemplate::new(200).set_body_json(json!({
                "accessToken": {
                    "accessKeyId": key,
                    "secretAccessKey": "secret",
                    "sessionToken": "session",
                },
                "tokenType": "aws_sigv4",
                "expiresIn": 3600,
                "refreshToken": "refresh-1",
                "idToken": id_token,
            }))
        })
        .mount(server)
        .await;
}

async fn token_requests(server: &MockServer, grant: &str) -> usize {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| {
            r.url.path() == "/v1/token"
                && serde_json::from_slice::<Value>(&r.body).unwrap()["grantType"] == grant
        })
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_console_sign_in_signs_in_in_the_browser_and_renews() {
    if !browser_is_here() {
        return;
    }
    let server = MockServer::start().await;
    mount_aws_sign_in(&server).await;
    mount_sts(&server).await;
    let fob = Fob::new("aws-login").with_server(&server);
    fob.write_config("[integrations.console]\ntype = \"aws-login\"\nregion = \"eu-west-1\"\n");
    let stderr = fob.fails(&["login", "console", "--token-stdin"]);
    assert!(stderr.contains("it takes no token"), "{stderr}");

    let signed_in = browser_sign_in(&fob, &["login", "console", "--no-browser"], "");
    assert!(signed_in.status.success(), "{}", signed_in.stderr);
    assert_eq!(
        signed_in.query["client_id"],
        "arn:aws:signin:::devtools/same-device"
    );
    assert!(
        signed_in
            .stderr
            .contains("signed in to AWS as arn:aws:iam::123456789012:user/alice"),
        "{}",
        signed_in.stderr
    );
    let (stdout, _) = fob.ok(&["list"]);
    assert_eq!(lines(&stdout), ["console/123456789012/alice"]);
    let profile = "console/123456789012/alice";
    let printed = exec_child(&fob, profile, &[], &["AWS_ACCESS_KEY_ID", "AWS_REGION"]);
    assert_eq!(
        printed,
        ["AWS_ACCESS_KEY_ID=ASIALOGIN1", "AWS_REGION=eu-west-1"]
    );

    // Background renewal refreshes the sign-in's credentials with its
    // refresh token and DPoP key, and the next command gets them.
    assert_eq!(token_requests(&server, "refresh_token").await, 0);
    fob.ok(&["renew", profile]);
    assert_eq!(token_requests(&server, "refresh_token").await, 1);
    let printed = exec_child(&fob, profile, &[], &["AWS_ACCESS_KEY_ID"]);
    assert_eq!(printed, ["AWS_ACCESS_KEY_ID=ASIALOGIN2"]);

    let (stdout, _) = fob.ok(&["console", profile, "--print"]);
    assert!(stdout.contains("SigninToken=signin-1"), "{stdout}");
    // A working sign-in is kept.
    let (_, stderr) = fob.ok(&["login", "console", "--no-browser"]);
    assert!(!stderr.contains("signed in to AWS"), "{stderr}");
    assert_eq!(token_requests(&server, "authorization_code").await, 1);

    fob.ok(&["logout", "console"]);
    assert!(!fob.secret("aws-login/console/session").exists());
}

fn unsigned_jwt(claims: &Value) -> String {
    use base64::Engine;
    let encode = |v: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
    format!(
        "{}.{}.s",
        encode(r#"{"alg":"none"}"#),
        encode(&claims.to_string())
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_google_account_signs_in_in_the_browser_and_runs_commands() {
    if !browser_is_here() {
        return;
    }
    let server = MockServer::start().await;
    let id_token = unsigned_jwt(&json!({ "email": "me@example.com", "sub": "1" }));
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "user-access-1",
            "expires_in": 3599,
            "refresh_token": "refresh-1",
            "id_token": id_token,
            "scope": "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/cloud-platform",
            "token_type": "Bearer",
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/projects"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "projects": [{ "projectId": "proj-a" }],
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/revoke"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let fob = Fob::new("gcp").with_var("OMNIFOB_GOOGLE_ENDPOINT", &server.uri());
    fob.write_config("[integrations.g]\ntype = \"gcp\"\n");

    let signed_in = browser_sign_in(&fob, &["login", "g", "--no-browser"], "&scope=x");
    assert!(signed_in.status.success(), "{}", signed_in.stderr);
    assert!(
        signed_in
            .stderr
            .contains("signed in to Google as me@example.com"),
        "{}",
        signed_in.stderr
    );
    let (stdout, _) = fob.ok(&["list"]);
    assert_eq!(lines(&stdout), ["g/proj-a/user"]);

    let printed = exec_child(
        &fob,
        "g/proj-a/user",
        &[],
        &[
            "CLOUDSDK_AUTH_ACCESS_TOKEN",
            "CLOUDSDK_CORE_PROJECT",
            "GOOGLE_CLOUD_PROJECT",
        ],
    );
    assert_eq!(
        printed,
        [
            "CLOUDSDK_AUTH_ACCESS_TOKEN=user-access-1",
            "CLOUDSDK_CORE_PROJECT=proj-a",
            "GOOGLE_CLOUD_PROJECT=proj-a"
        ]
    );
    let (stdout, _) = fob.ok(&["console", "g/proj-a/user", "--print"]);
    assert!(
        stdout.starts_with("https://console.cloud.google.com/") && stdout.contains("proj-a"),
        "{stdout}"
    );

    let (_, stderr) = fob.ok(&["logout", "g"]);
    assert!(stderr.contains("signed out of 'g'"), "{stderr}");
    assert!(!fob.secret("gcp/g/oauth").exists());
}

const TENANT: &str = "11111111-1111-1111-1111-111111111111";

/// Entra ID and Resource Manager: a device-flow sign-in that is approved
/// on the second poll, one tenant and one subscription.
async fn mount_azure(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/organizations/oauth2/v2.0/devicecode"))
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
        .and(body_string_contains("device_code=dev-1"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "authorization_pending",
        })))
        .up_to_n_times(1)
        .mount(server)
        .await;
    let id_token = unsigned_jwt(&json!({ "preferred_username": "me@contoso.com", "tid": TENANT }));
    Mock::given(method("POST"))
        .and(wiremock::matchers::path_regex("/oauth2/v2.0/token$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token_type": "Bearer",
            "access_token": "arm-1",
            "expires_in": 3599,
            "refresh_token": "refresh-1",
            "id_token": id_token,
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/tenants"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{ "tenantId": TENANT }],
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/subscriptions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "value": [{ "subscriptionId": "sub-a", "displayName": "Prod", "state": "Enabled" }],
        })))
        .mount(server)
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_entra_id_account_signs_in_with_a_code_and_runs_commands() {
    let server = MockServer::start().await;
    mount_azure(&server).await;
    let fob = Fob::new("azure").with_var("OMNIFOB_AZURE_ENDPOINT", &server.uri());
    fob.write_config("[integrations.work]\ntype = \"azure\"\n");
    let stderr = fob.fails(&["login", "work", "--token-stdin"]);
    assert!(stderr.contains("it takes no token"), "{stderr}");

    let (_, stderr) = fob.ok(&["login", "work", "--device-code", "--no-browser"]);
    assert!(stderr.contains("code: ABCD-EFGH"), "{stderr}");
    assert!(
        stderr.contains("signed in to Entra ID as me@contoso.com"),
        "{stderr}"
    );
    let (stdout, _) = fob.ok(&["list"]);
    assert_eq!(lines(&stdout), ["work/prod/user"]);

    let printed = exec_child(
        &fob,
        "work/prod/user",
        &[],
        &[
            "AZURE_SUBSCRIPTION_ID",
            "AZURE_TENANT_ID",
            "ARM_SUBSCRIPTION_ID",
        ],
    );
    assert_eq!(
        printed,
        [
            "AZURE_SUBSCRIPTION_ID=sub-a",
            format!("AZURE_TENANT_ID={TENANT}").as_str(),
            "ARM_SUBSCRIPTION_ID=sub-a"
        ]
    );
    let (stdout, _) = fob.ok(&["console", "work/prod/user", "--print"]);
    assert!(stdout.contains("portal.azure.com"), "{stdout}");
    let (_, stderr) = fob.ok(&["check", "--integration", "work"]);
    assert!(!stderr.contains("FAIL"), "{stderr}");

    fob.ok(&["logout", "work"]);
    assert!(!fob.secret("azure/work/oauth").exists());
}

/// Entra ID's device sign-in in two steps; `--wait` polls past a pending
/// answer, as the one-step sign-in does.
#[tokio::test(flavor = "multi_thread")]
async fn an_entra_id_sign_in_starts_and_finishes_in_two_steps() {
    let server = MockServer::start().await;
    mount_azure(&server).await;
    let fob = Fob::new("azure-two-step").with_var("OMNIFOB_AZURE_ENDPOINT", &server.uri());
    fob.write_config("[integrations.work]\ntype = \"azure\"\n");
    let (_, stderr) = fob.ok(&["login", "work", "--start", "--no-browser"]);
    assert!(stderr.contains("code: ABCD-EFGH"), "{stderr}");
    assert!(
        stderr.contains("https://microsoft.com/devicelogin"),
        "{stderr}"
    );
    assert!(fob.secret("azure/work/pending").exists());
    let (_, stderr) = fob.ok(&["login", "work", "--wait"]);
    assert!(
        stderr.contains("signed in to Entra ID as me@contoso.com"),
        "{stderr}"
    );
    assert!(!fob.secret("azure/work/pending").exists());
    let (stdout, _) = fob.ok(&["list"]);
    assert_eq!(lines(&stdout), ["work/prod/user"]);
}

const CF_ACCOUNT: &str = "acct123";

/// The Cloudflare API and dashboard: one account, "Acme", whose bootstrap
/// token `boot` may mint tokens there; each minted token is `minted-<n>`,
/// and listed until it is deleted.
async fn mount_cloudflare(server: &MockServer) {
    let minted = std::sync::atomic::AtomicUsize::new(0);
    let live = std::sync::Mutex::new(Vec::<String>::new());
    Mock::given(wiremock::matchers::any())
        .respond_with(move |r: &Request| {
            let p = r.url.path();
            let ok = |result: Value| {
                ResponseTemplate::new(200).set_body_json(json!({
                    "success": true,
                    "errors": [],
                    "messages": [],
                    "result": result,
                    "result_info": { "page": 1, "total_pages": 1 }
                }))
            };
            match (r.method.as_str(), p) {
                ("POST", "/oauth2/token") => ResponseTemplate::new(200).set_body_json(json!({
                    "access_token": "oauth-access-2",
                    "token_type": "bearer",
                    "expires_in": 3600,
                    "refresh_token": "oauth-refresh-2",
                    "scope": "account-api-tokens.write workers-scripts.write",
                })),
                ("POST", "/oauth2/revoke") => ResponseTemplate::new(200),
                ("GET", "/accounts") => ok(json!([{ "id": CF_ACCOUNT, "name": "Acme" }])),
                ("GET", "/zones") => ok(json!([])),
                ("GET", p) if p.ends_with("/tokens/permission_groups") => ok(json!([
                    { "id": "g-workers", "name": "Workers Scripts Write", "scopes": ["com.cloudflare.api.account"] },
                    { "id": "g-pages", "name": "Pages Write", "scopes": ["com.cloudflare.api.account"] },
                    { "id": "g-dns", "name": "DNS Write", "scopes": ["com.cloudflare.api.account.zone"] },
                ])),
                ("GET", p) if p.ends_with("/tokens/verify") => {
                    ok(json!({ "id": "boot", "status": "active" }))
                }
                ("GET", p) if p.ends_with("/tokens/boot") => ok(json!({
                    "id": "boot",
                    "policies": [{ "resources": { format!("com.cloudflare.api.account.{CF_ACCOUNT}"): "*" } }]
                })),
                ("GET", p) if p.ends_with("/tokens") => {
                    let live = live.lock().unwrap();
                    let tokens: Vec<Value> = live
                        .iter()
                        .map(|id| json!({ "id": id, "name": "omnifob dev", "status": "active" }))
                        .collect();
                    ok(json!(tokens))
                }
                ("POST", p) if p.ends_with("/tokens") => {
                    let n = minted.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    live.lock().unwrap().push(format!("minted-{n}"));
                    ok(json!({ "id": format!("minted-{n}"), "value": format!("minted-secret-{n}") }))
                }
                ("DELETE", p) if p.contains("/tokens/") => {
                    let id = p.rsplit('/').next().unwrap();
                    live.lock().unwrap().retain(|t| t != id);
                    ok(json!({ "id": id }))
                }
                _ => ResponseTemplate::new(404).set_body_json(json!({
                    "success": false,
                    "errors": [{ "code": 7003, "message": format!("no route for {p}") }],
                })),
            }
        })
        .mount(server)
        .await;
}

/// The IDs of the tokens deleted at `server`.
async fn deleted_tokens(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method.as_str() == "DELETE")
        .map(|r| r.url.path().rsplit('/').next().unwrap().to_string())
        .collect()
}

fn cloudflare_fob(name: &str, server: &MockServer) -> Fob {
    let fob = Fob::new(name)
        .with_var("OMNIFOB_CLOUDFLARE_API", &server.uri())
        .with_var("OMNIFOB_CLOUDFLARE_DASH", &server.uri());
    fob.write_config(
        r#"[integrations.cf]
type = "cloudflare-token"

[integrations.cf.templates.dev]
permissions = ["Workers Scripts Write"]
"#,
    );
    fob
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cloudflare_token_signs_in_from_stdin_and_mints_per_command() {
    let server = MockServer::start().await;
    mount_cloudflare(&server).await;
    let fob = cloudflare_fob("cf-token", &server);
    fob.ok_with_stdin(&["login", "cf", "--token-stdin"], "boot-secret\n");
    assert!(fob.secret("cloudflare/cf/bootstrap").exists());
    let (stdout, _) = fob.ok(&["list", "cf", "dev"]);
    assert_eq!(lines(&stdout), ["cf/acme/dev"]);

    let printed = exec_child(
        &fob,
        "cf/acme/dev",
        &[],
        &["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"],
    );
    assert_eq!(
        printed,
        [
            "CLOUDFLARE_API_TOKEN=minted-secret-1",
            format!("CLOUDFLARE_ACCOUNT_ID={CF_ACCOUNT}").as_str()
        ]
    );
    let (stdout, _) = fob.ok(&["console", "cf/acme/dev", "--print"]);
    assert_eq!(
        stdout.trim(),
        format!("https://dash.cloudflare.com/{CF_ACCOUNT}")
    );

    // `--revoke` mints a token for the command alone and deletes it after,
    // whatever the command's exit status.
    let output = fob.run(&[
        "exec",
        "cf/acme/dev",
        "--revoke",
        "--",
        FOB,
        "nonsense-command",
    ]);
    let (_, stderr) = texts(&output);
    assert!(!output.status.success());
    assert!(
        stderr.contains("fob: revoked the token for cf/acme/dev"),
        "{stderr}"
    );
    assert_eq!(deleted_tokens(&server).await, ["minted-2"]);
    // The cached token was left alone.
    let printed = exec_child(&fob, "cf/acme/dev", &[], &["CLOUDFLARE_API_TOKEN"]);
    assert_eq!(printed, ["CLOUDFLARE_API_TOKEN=minted-secret-1"]);

    let (_, stderr) = fob.ok(&["revoke", "cf/acme/dev"]);
    assert!(stderr.contains("cf/acme/dev"), "{stderr}");
    assert_eq!(deleted_tokens(&server).await, ["minted-2", "minted-1"]);
    fob.ok(&["logout", "cf"]);
    assert!(!fob.secret("cloudflare/cf/bootstrap").exists());
}

/// `fob exec --revoke` deletes the token when fob is stopped with SIGTERM,
/// which it passes on to the command, and after Ctrl-C, which the terminal
/// sends to both.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn exec_revokes_the_token_when_stopped() {
    let server = MockServer::start().await;
    mount_cloudflare(&server).await;
    let fob = cloudflare_fob("cf-signals", &server);
    fob.ok_with_stdin(&["login", "cf", "--token-stdin"], "boot-secret\n");
    for (n, signal) in [(1, libc::SIGTERM), (2, libc::SIGINT)] {
        use std::os::unix::process::CommandExt;
        let started = fob.root.join(format!("started-{n}"));
        let script = format!("echo > '{}'; exec sleep 30", started.display());
        let child = fob
            .command(&["exec", "cf/acme/dev", "--revoke", "--", "sh", "-c", &script])
            .process_group(0)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !started.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the command never started"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let pid = child.id() as libc::pid_t;
        // SAFETY: plain kill(2) calls on the child and its process group.
        if signal == libc::SIGTERM {
            unsafe { libc::kill(pid, signal) };
        } else {
            unsafe { libc::kill(-pid, signal) };
        }
        let output = child.wait_with_output().unwrap();
        let (_, stderr) = texts(&output);
        assert_eq!(output.status.code(), Some(128 + signal), "{stderr}");
        assert!(
            stderr.contains("fob: revoked the token for cf/acme/dev"),
            "{stderr}"
        );
        assert_eq!(
            deleted_tokens(&server).await.last().map(String::as_str),
            Some(format!("minted-{n}").as_str())
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cloudflare_templates_are_listed_and_added() {
    let server = MockServer::start().await;
    mount_cloudflare(&server).await;
    let fob = cloudflare_fob("cf-templates", &server);
    fob.ok_with_stdin(&["login", "cf", "--token-stdin"], "boot-secret\n");

    let (stdout, _) = fob.ok(&["cf", "permissions", "cf"]);
    assert!(
        stdout.contains("Workers Scripts Write") && stdout.contains("Pages Write"),
        "{stdout}"
    );
    let (stdout, _) = fob.ok(&["cf", "permissions", "cf", "pages"]);
    assert!(
        stdout.contains("Pages Write") && !stdout.contains("Workers"),
        "{stdout}"
    );
    let (stdout, _) = fob.ok(&["cf", "templates", "cf"]);
    assert!(
        stdout.contains("dev") && stdout.contains("Workers Scripts Write"),
        "{stdout}"
    );

    let stderr = fob.fails(&["cf", "add-template", "cf", "site", "-p", "No Such Write"]);
    assert!(stderr.contains("No Such Write"), "{stderr}");
    fob.ok(&[
        "cf",
        "add-template",
        "cf",
        "site",
        "-p",
        "Pages Write",
        "--optional",
        "DNS Write",
        "--ttl",
        "30m",
    ]);
    let config = omnifob_core::Config::load(&fob.config_file()).unwrap();
    let omnifob_core::Integration::Cloudflare(cf) = &config.integrations["cf"] else {
        panic!("{:?}", config.integrations.keys());
    };
    let site = &cf.templates["site"];
    assert_eq!(site.permissions, ["Pages Write"]);
    assert_eq!(site.optional, ["DNS Write"]);
    // The new template is a profile at once, and a second one of that name
    // needs --replace.
    let (stdout, _) = fob.ok(&["list", "cf", "site"]);
    assert_eq!(lines(&stdout), ["cf/acme/site"]);
    let stderr = fob.fails(&["cf", "add-template", "cf", "site", "-p", "Pages Write"]);
    assert!(stderr.contains("--replace"), "{stderr}");
    fob.ok(&[
        "cf",
        "add-template",
        "cf",
        "site",
        "-p",
        "Workers Scripts Write",
        "--replace",
    ]);
    let (stdout, _) = fob.ok(&["cf", "templates", "cf"]);
    assert!(
        stdout.contains("site (1h): Workers Scripts Write\n"),
        "{stdout}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cloudflare_browser_sign_in_mints_and_signs_out() {
    let server = MockServer::start().await;
    mount_cloudflare(&server).await;
    let fob = Fob::new("cf-oauth")
        .with_var("OMNIFOB_CLOUDFLARE_API", &server.uri())
        .with_var("OMNIFOB_CLOUDFLARE_DASH", &server.uri());
    fob.write_config(
        r#"[integrations.cf]
type = "cloudflare-oauth"
client_id = "client-1"

[integrations.cf.templates.dev]
permissions = ["Workers Scripts Write"]
"#,
    );
    let stderr = fob.fails(&["login", "cf", "--token-stdin"]);
    assert!(stderr.contains("it takes no token"), "{stderr}");
    // As `fob login` leaves it, with an access token that has expired.
    fob.put_secret(
        "cloudflare/cf/oauth",
        &json!({
            "access_token": "oauth-access-1",
            "expires_at": "2000-01-01T00:00:00Z",
            "refresh_token": "oauth-refresh-1",
            "scopes": ["account-api-tokens.write", "workers-scripts.write"],
        }),
    );
    fob.ok(&["sync"]);
    let (stdout, _) = fob.ok(&["list", "cf", "dev"]);
    assert_eq!(lines(&stdout), ["cf/acme/dev"]);
    let printed = exec_child(&fob, "cf/acme/dev", &[], &["CLOUDFLARE_API_TOKEN"]);
    assert_eq!(printed, ["CLOUDFLARE_API_TOKEN=minted-secret-1"]);
    // The access token was renewed, and minting used the new one.
    let requests = server.received_requests().await.unwrap();
    let mint = requests
        .iter()
        .find(|r| r.method.as_str() == "POST" && r.url.path().ends_with("/tokens"))
        .unwrap();
    assert_eq!(
        mint.headers.get("authorization").unwrap(),
        "Bearer oauth-access-2"
    );
    let (stdout, _) = fob.ok(&["console", "cf/acme/dev", "--print"]);
    assert_eq!(
        stdout.trim(),
        format!("https://dash.cloudflare.com/{CF_ACCOUNT}")
    );

    fob.ok(&["logout", "cf"]);
    assert!(!fob.secret("cloudflare/cf/oauth").exists());
    let requests = server.received_requests().await.unwrap();
    assert!(
        requests.iter().any(|r| r.url.path() == "/oauth2/revoke"),
        "the sign-in was not revoked"
    );
}

/// A token integration checked at a mock of its provider.
fn token_fob(name: &str, server: &MockServer) -> Fob {
    let fob = Fob::new(name);
    fob.write_config(&format!(
        r#"[integrations.tok]
type = "token"
verify_url = "{}/me"
console = "https://console.example.test/"

[integrations.tok.secrets]
token = ["EXAMPLE_TOKEN"]
"#,
        server.uri()
    ));
    fob
}

async fn mount_token_check(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/me"))
        .respond_with(|r: &Request| {
            let ok = r
                .headers
                .get("authorization")
                .is_some_and(|v| v.to_str().unwrap().starts_with("Bearer good"));
            ResponseTemplate::new(if ok { 200 } else { 401 })
        })
        .mount(server)
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_signs_in_from_stdin_and_is_checked() {
    let server = MockServer::start().await;
    mount_token_check(&server).await;
    let fob = token_fob("token", &server);
    let output = fob.run_with_stdin(&["login", "tok", "--token-stdin"], "");
    assert!(!output.status.success());
    let (_, stderr) = texts(&output);
    assert!(stderr.contains("missing a value for 'token'"), "{stderr}");
    fob.ok_with_stdin(&["login", "tok", "--token-stdin"], "good-1\n");
    let (stdout, _) = fob.ok(&["list"]);
    assert_eq!(lines(&stdout), ["tok/default/token"]);
    let printed = exec_child(&fob, "tok/default/token", &[], &["EXAMPLE_TOKEN"]);
    assert_eq!(printed, ["EXAMPLE_TOKEN=good-1"]);
    let (stdout, _) = fob.ok(&["console", "tok/default/token", "--print"]);
    assert_eq!(stdout.trim(), "https://console.example.test/");

    // `fob check` in its forms: a sign-in, a profile, and quietly.
    let (stdout, _) = fob.ok(&["check"]);
    assert!(stdout.contains("ok   tok"), "{stdout}");
    let (stdout, _) = fob.ok(&["check", "tok/default/token"]);
    assert!(stdout.contains("tok/default/token"), "{stdout}");
    // Nothing but the test store's warning.
    let quiet = |(stdout, stderr): (String, String)| {
        let stderr: Vec<String> = stderr
            .lines()
            .filter(|l| !l.contains("UNENCRYPTED"))
            .map(str::to_string)
            .collect();
        (stdout, stderr)
    };
    assert_eq!(quiet(fob.ok(&["check", "-q"])), (String::new(), vec![]));
    // The provider stops taking the token: the check fails, quietly too.
    let rejected = fob.secret("token/tok/secrets");
    std::fs::write(&rejected, r#"{"token":"revoked"}"#).unwrap();
    let output = fob.run(&["check", "-q"]);
    assert!(!output.status.success());
    assert_eq!(quiet(texts(&output)), (String::new(), vec![]));
    let output = fob.run(&["check"]);
    assert!(!output.status.success());
    assert!(
        texts(&output).0.contains("FAIL tok"),
        "{:?}",
        texts(&output)
    );
    // A rejected token is not stored.
    let output = fob.run_with_stdin(&["login", "tok", "--token-stdin"], "revoked-2\n");
    let (_, stderr) = texts(&output);
    assert!(!output.status.success());
    assert!(stderr.contains("the token was rejected (401"), "{stderr}");
    assert_eq!(
        std::fs::read_to_string(&rejected).unwrap(),
        r#"{"token":"revoked"}"#
    );

    fob.ok(&["logout", "tok"]);
    assert!(!rejected.exists());
}

/// `--from-clipboard` reads the token with the platform's clipboard tool,
/// here a stand-in on PATH.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_token_signs_in_from_the_clipboard() {
    use std::os::unix::fs::PermissionsExt;
    let server = MockServer::start().await;
    mount_token_check(&server).await;
    let fob = token_fob("clipboard", &server);
    let bin = fob.root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let clip = fob.root.join("clip");
    for tool in ["pbpaste", "wl-paste"] {
        let path = bin.join(tool);
        std::fs::write(&path, format!("#!/bin/sh\ncat '{}'\n", clip.display())).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    // The clipboard tool alone, not Windows' through WSL interop.
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let login = |text: &str| {
        std::fs::write(&clip, text).unwrap();
        fob.command(&["login", "tok", "--from-clipboard"])
            .env("PATH", &path)
            .output()
            .unwrap()
    };
    let output = login("good-2\n");
    assert!(output.status.success(), "{:?}", texts(&output));
    let printed = exec_child(&fob, "tok/default/token", &[], &["EXAMPLE_TOKEN"]);
    assert_eq!(printed, ["EXAMPLE_TOKEN=good-2"]);
    let output = login("");
    assert!(!output.status.success());
    let output = login("rejected");
    assert!(!output.status.success());
    assert!(
        texts(&output).1.contains("the token was rejected"),
        "{:?}",
        texts(&output)
    );
}

/// `fob env` prints each shell's code, `--unset` removes what the active
/// profile set, and `fob activate` defines `fob use` for each shell.
#[tokio::test(flavor = "multi_thread")]
async fn env_and_activate_speak_each_shell() {
    let server = MockServer::start().await;
    mount_token_check(&server).await;
    let fob = token_fob("shells", &server);
    fob.ok_with_stdin(&["login", "tok", "--token-stdin"], "good-1\n");
    let env = |shell: &str| fob.ok(&["env", "tok/default/token", "--shell", shell]).0;
    for shell in ["bash", "zsh"] {
        let code = env(shell);
        assert!(code.contains("export EXAMPLE_TOKEN='good-1'"), "{code}");
        assert!(
            code.contains("export OMNIFOB_PROFILE='tok/default/token'"),
            "{code}"
        );
    }
    let code = env("fish");
    assert!(code.contains("set -gx EXAMPLE_TOKEN 'good-1'"), "{code}");
    let code = env("powershell");
    assert!(code.contains("$Env:EXAMPLE_TOKEN = 'good-1'"), "{code}");

    let unset = |shell: &str| {
        let output = fob
            .command(&["env", "--unset", "--shell", shell])
            .env("OMNIFOB_VARS", "EXAMPLE_TOKEN,OMNIFOB_PROFILE")
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", texts(&output));
        texts(&output).0
    };
    let code = unset("bash");
    assert!(code.contains("unset EXAMPLE_TOKEN"), "{code}");
    let code = unset("fish");
    assert!(code.contains("set -e EXAMPLE_TOKEN"), "{code}");
    let code = unset("powershell");
    assert!(code.contains("Remove-Item"), "{code}");
    assert!(code.contains("EXAMPLE_TOKEN"), "{code}");

    for (shell, defines) in [
        ("bash", "fob()"),
        ("zsh", "fob()"),
        ("fish", "function fob"),
        ("powershell", "function fob"),
    ] {
        let (code, _) = fob.ok(&["activate", shell]);
        assert!(code.contains(defines), "{shell}: {code}");
    }
}

/// `fob renew`, which fob starts in the background: one renewal of a
/// profile at a time, the others returning at once.
#[tokio::test(flavor = "multi_thread")]
async fn renewals_of_one_profile_do_not_overlap() {
    let server = MockServer::start().await;
    let fob = Fob::new("renew").with_server(&server);
    fob.write_config(&portal_config("acme"));
    fob.sign_in("acme");
    mount_portal(&server, &[("111111111111", "Dev")]).await;
    Mock::given(method("GET"))
        .and(path("/federation/credentials"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "roleCredentials": {
                        "accessKeyId": "ASIARENEWED",
                        "secretAccessKey": "role-secret",
                        "sessionToken": "role-session",
                        "expiration": 4_102_444_800_000i64,
                    }
                }))
                .set_delay(std::time::Duration::from_secs(2)),
        )
        .mount(&server)
        .await;
    fob.ok(&["sync"]);
    let renewals: Vec<_> = (0..3)
        .map(|_| {
            fob.command(&["renew", "acme/dev/Admin"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    for renewal in renewals {
        let output = renewal.wait_with_output().unwrap();
        assert!(output.status.success(), "{:?}", texts(&output));
    }
    let fetched = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == "/federation/credentials")
        .count();
    assert_eq!(fetched, 1);
    // The renewal filled the cache, which the next command uses.
    assert!(fob.secret("credentials/acme/dev/Admin").exists());
    let (stdout, _) = fob.ok(&["creds", "acme/dev/Admin", "--format", "credential-process"]);
    assert!(stdout.contains("ASIARENEWED"), "{stdout}");
    // A profile that is gone is nothing to renew.
    fob.ok(&["renew", "acme/gone/Admin"]);
}
