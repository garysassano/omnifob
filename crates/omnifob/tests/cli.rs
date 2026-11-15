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
        let mut name = String::new();
        for b in key.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.') {
                name.push(b as char);
            } else {
                name.push_str(&format!("%{b:02X}"));
            }
        }
        self.keyring().join(name)
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
            if name.starts_with("AWS_")
                || name.starts_with("OMNIFOB_")
                || name == "COMPLETE"
                || proxy
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
    fob.write_config(&portal_config("\"my portal\""));
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

#[tokio::test(flavor = "multi_thread")]
async fn login_signs_in_and_syncs() {
    let server = MockServer::start().await;
    let fob = Fob::new("login").with_server(&server);
    fob.write_config(&portal_config("acme"));
    Mock::given(method("POST"))
        .and(path("/client/register"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "clientId": "client-1",
            "clientSecret": "client-secret-1",
            "clientIdIssuedAt": 1_700_000_000,
            "clientSecretExpiresAt": 4_102_444_800i64,
        })))
        .mount(&server)
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
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "accessToken": "access-1",
            "tokenType": "Bearer",
            "expiresIn": 3600,
            "refreshToken": "refresh-1",
        })))
        .mount(&server)
        .await;
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
async fn sync_and_list() {
    let (fob, _server) = synced_portal("list").await;
    let (stdout, _) = fob.ok(&["list"]);
    assert_eq!(lines(&stdout), ["acme/dev/Admin", "acme/prod/Admin"]);
    let (stdout, _) = fob.ok(&["ls", "prod"]);
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

/// Not a test of its own: `fob exec` runs this test binary with
/// `--ignored --exact` and `OMNIFOB_E2E_CHILD` set, as a child that works on
/// every platform, and it prints the variables it got.
#[test]
#[ignore = "run by exec_hands_the_account_and_region_to_the_command"]
fn child_prints_its_environment() {
    if std::env::var_os("OMNIFOB_E2E_CHILD").is_none() {
        return;
    }
    for name in [
        "AWS_ACCESS_KEY_ID",
        "AWS_ACCOUNT_ID",
        "AWS_REGION",
        "OMNIFOB_PROFILE",
    ] {
        println!("child: {name}={}", std::env::var(name).unwrap_or_default());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_hands_the_account_and_region_to_the_command() {
    let (fob, _server) = synced_portal("exec").await;
    let me = std::env::current_exe().unwrap();
    let output = fob
        .command(&[
            "exec",
            "acme/dev/Admin",
            "--",
            me.to_str().unwrap(),
            "child_prints_its_environment",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("OMNIFOB_E2E_CHILD", "1")
        .output()
        .unwrap();
    let (stdout, stderr) = texts(&output);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    // The harness writes "test <name> ... " before the first line.
    let printed: Vec<&str> = stdout
        .lines()
        .filter_map(|l| l.split_once("child: ").map(|(_, v)| v))
        .collect();
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
