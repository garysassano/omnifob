//! Provisioners: handing a profile's credentials to tools that do not take
//! them from environment variables, in the forms their SDKs read.
//!
//! - AWS: a container credentials endpoint (`AWS_CONTAINER_CREDENTIALS_FULL_URI`
//!   with `AWS_CONTAINER_AUTHORIZATION_TOKEN`), which the SDKs call again
//!   whenever their credentials near their end.
//! - Azure: a managed identity endpoint as App Service runs one
//!   (`IDENTITY_ENDPOINT` with `IDENTITY_HEADER`), answering for any
//!   resource from the stored sign-in.
//! - Google: Application Default Credentials of type
//!   `external_account_authorized_user` whose token URL is a loopback
//!   endpoint and whose "refresh token" is the endpoint's secret, a gcloud
//!   access token file kept fresh, executable-sourced credentials and their
//!   ADC file.
//! - Kubernetes: `ExecCredential` output for EKS, GKE and AKS.
//!
//! The endpoints listen on `127.0.0.1` only, each with a random secret that
//! the tool sends back and that is compared in constant time, and live as
//! long as the future that serves them. Their tasks work in the
//! [`Context`](crate::Context) current when they were made, wherever they
//! are polled, and never prompt: a request that needs an MFA code is
//! answered with an error. Files are written private, in the state
//! directory's `run` directory, and deleted when dropped.

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context as _, anyhow, bail};
use base64::Engine;
use jiff::{SignedDuration, Timestamp};
use serde_json::{Value, json};

use crate::serve::{self, Request, Response};
use crate::{Config, Credentials, Profile, Target, providers};

/// A future that serves an endpoint, or keeps a file fresh, until dropped.
pub type Task = Pin<Box<dyn Future<Output = ()> + Send>>;

/// `future` as a [`Task`]: in the context current now, and unattended.
fn task(future: impl Future<Output = ()> + Send + 'static) -> Task {
    Box::pin(crate::Context::current().scope(crate::prompt::unattended(future)))
}

/// What a provisioner adds to a command: variables to set and to remove,
/// files to delete when it ends, and a task to run while it runs.
#[derive(Default)]
pub struct Provision {
    pub set: Vec<(String, String)>,
    pub remove: Vec<String>,
    pub files: Vec<TempFile>,
    pub tasks: Vec<Task>,
}

impl Provision {
    /// Adds `other`'s variables, files and tasks to these.
    pub fn merge(&mut self, other: Provision) {
        self.set.extend(other.set);
        self.remove.extend(other.remove);
        self.files.extend(other.files);
        self.tasks.extend(other.tasks);
    }

    /// Runs every task until the future is dropped; never ends otherwise.
    pub async fn run(tasks: Vec<Task>) {
        futures_util::future::join_all(tasks).await;
        std::future::pending::<()>().await
    }
}

/// A private file that is deleted when this is dropped.
pub struct TempFile {
    path: PathBuf,
}

impl TempFile {
    /// Writes `contents` to a new private file named `<random><suffix>` in
    /// the state directory's `run` directory.
    pub fn create(suffix: &str, contents: &[u8]) -> anyhow::Result<Self> {
        let dir = run_dir()?;
        let path = dir.join(format!("{}{suffix}", crate::oauth::random_string(12)?));
        crate::files::write_private(&path, contents)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// How old a token file has to be before [`run_dir`] takes it for one a
/// killed `fob exec` left behind. A running command's file is rewritten at
/// least every [`TOKEN_FILE_REWRITE`], so it never gets this old.
const STALE_TOKEN_FILE: std::time::Duration = std::time::Duration::from_secs(2 * 3600);
const TOKEN_FILE_REWRITE: SignedDuration = SignedDuration::from_hours(1);

/// `<state>/run`, private. Token files a killed `fob exec` left behind are
/// deleted here: a running command's file is rewritten at least hourly,
/// whatever its token's lifetime, so a file not written for two hours
/// belongs to no running command.
fn run_dir() -> anyhow::Result<PathBuf> {
    let dir = crate::paths::state_dir()?.join("run");
    crate::files::create_private_dir(&dir)?;
    // `checked_sub`: a clock set to the first hours of 1970 skips cleaning.
    if let (Ok(entries), Some(stale)) = (
        std::fs::read_dir(&dir),
        std::time::SystemTime::now().checked_sub(STALE_TOKEN_FILE),
    ) {
        for entry in entries.flatten() {
            let old = entry
                .metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|t| t < stale);
            if old && entry.file_name().to_string_lossy().ends_with(".token") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    Ok(dir)
}

/// The SDKs refresh credentials from an endpoint well before they expire
/// (botocore from 15 minutes before, and it fails when refreshed ones still
/// end within 10), so the endpoints hand out credentials with at least this
/// long left.
const SERVE_MIN: SignedDuration = SignedDuration::from_mins(15);

/// A profile's credentials for an endpoint: the cached ones while
/// [`still_served`] keeps them, else new ones.
async fn served_credentials(
    config: &Config,
    profile: &Profile,
    ttl: Option<SignedDuration>,
) -> crate::Result<Credentials> {
    let creds = providers::credentials(config, profile, true, ttl).await?;
    if !still_served(&creds, Timestamp::now()) && ttl.is_none() {
        return providers::credentials(config, profile, false, None).await;
    }
    Ok(creds)
}

/// The credentials an endpoint last handed out, for the next requests while
/// [`still_served`] keeps them. With a
/// `ttl` (the agent's cap), [`providers::credentials`] skips its cache, so
/// without this every request would get new credentials. Requests that
/// arrive while new ones are fetched wait for them.
#[derive(Default)]
struct Served(tokio::sync::Mutex<Option<Credentials>>);

impl Served {
    async fn get(
        &self,
        config: &Config,
        profile: &Profile,
        ttl: Option<SignedDuration>,
        agent_max: Option<SignedDuration>,
    ) -> crate::Result<Credentials> {
        let mut held = self.0.lock().await;
        if let Some(creds) = held.as_ref().filter(|c| still_served(c, Timestamp::now())) {
            return Ok(creds.clone());
        }
        let creds = served_credentials(config, profile, ttl).await?;
        // Under `[agent] max_ttl`, the SDKs' refreshes stay as short as the
        // variables' credentials.
        let creds = match agent_max {
            Some(max) => {
                providers::scoped_for_agent(
                    config,
                    profile,
                    creds,
                    max,
                    "fob exec endpoint (agent)",
                )
                .await?
            }
            None => creds,
        };
        *held = Some(creds.clone());
        Ok(creds)
    }
}

/// Whether credentials an endpoint handed out can be handed out again:
/// while they last at least [`SERVE_MIN`], or, for credentials that never
/// last that long (console sign-in's 15 minutes), until they are due for
/// renewal, never once expired.
fn still_served(creds: &Credentials, now: Timestamp) -> bool {
    let Some(expires) = creds.expires_at else {
        return true;
    };
    if expires.duration_since(now) >= SERVE_MIN {
        return true;
    }
    let short_lived = creds
        .issued_at
        .is_some_and(|at| expires.duration_since(at) <= SERVE_MIN);
    short_lived && !creds.wants_renewal(now)
}

/// How a failure reads in an endpoint's answer: the error, without the
/// request that caused it. Errors never hold secrets.
fn failure(e: &crate::Error) -> String {
    match e {
        crate::Error::NeedsLogin {
            integration,
            reason,
        } => {
            format!("{reason}; run `fob login {integration}`")
        }
        other => format!("{other:#}"),
    }
}

// --- AWS -------------------------------------------------------------------

/// The body the container credential provider expects. `Token` is
/// required by botocore, so credentials without a session token fail.
pub fn aws_container_body(creds: &Credentials) -> anyhow::Result<Value> {
    let get = |k: &str| {
        creds
            .env
            .get(k)
            .with_context(|| format!("the credentials have no {k}"))
    };
    let mut body = json!({
        "AccessKeyId": get("AWS_ACCESS_KEY_ID")?,
        "SecretAccessKey": get("AWS_SECRET_ACCESS_KEY")?,
        "Token": get("AWS_SESSION_TOKEN")?,
    });
    // Left out rather than `null` for credentials that do not expire (a
    // `command` helper's), which some SDKs refuse to parse.
    if let Some(expires_at) = creds.expires_at {
        body["Expiration"] = expires_at.to_string().into();
    }
    if let Some(account) = creds.env.get("AWS_ACCOUNT_ID") {
        body["AccountId"] = account.clone().into();
    }
    Ok(body)
}

/// A container credentials endpoint for an AWS profile: the SDKs (and the
/// AWS CLI) get the profile's credentials from it, and come back for new
/// ones before they expire, so a long-running command keeps working. The
/// SDKs accept plain HTTP only to a loopback address, which this is.
pub async fn aws_container_endpoint(
    config: Config,
    profile: Profile,
    ttl: Option<SignedDuration>,
    agent_max: Option<SignedDuration>,
) -> anyhow::Result<Provision> {
    let listener = serve::bind().await?;
    let port = listener.local_addr()?.port();
    let secret = serve::secret()?;
    let state = Arc::new((config, profile, secret.clone(), Served::default()));
    let handler = move |request: Request| {
        let state = state.clone();
        async move {
            let (config, profile, secret, served) = &*state;
            if !serve::secret_matches(request.header("authorization"), secret) {
                return Response::error(401, "message", "wrong or missing authorization token");
            }
            if request.method != "GET" || request.path != "/" {
                return Response::error(404, "message", "GET / only");
            }
            let creds = match served.get(config, profile, ttl, agent_max).await {
                Ok(creds) => creds,
                Err(e) => return Response::error(500, "message", failure(&e)),
            };
            match aws_container_body(&creds) {
                Ok(body) => Response::ok(body),
                Err(e) => Response::error(500, "message", format!("{e:#}")),
            }
        }
    };
    Ok(Provision {
        set: vec![
            (
                "AWS_CONTAINER_CREDENTIALS_FULL_URI".into(),
                format!("http://127.0.0.1:{port}/"),
            ),
            ("AWS_CONTAINER_AUTHORIZATION_TOKEN".into(), secret),
        ],
        // Every other source of AWS credentials, which would win over the
        // container endpoint in the SDKs' chain or point it elsewhere. The
        // endpoint's own two variables are set again.
        remove: crate::credentials::AWS_CREDENTIAL_VARS
            .iter()
            .map(|v| v.to_string())
            .collect(),
        files: Vec::new(),
        tasks: vec![task(serve::serve(listener, handler))],
    })
}

// --- Azure -----------------------------------------------------------------

/// Where the managed identity endpoint answers.
const IDENTITY_PATH: &str = "/msi/token";

/// Variables that would make Azure Identity's `DefaultAzureCredential`
/// pick another credential before the managed identity, or make its managed
/// identity look for another kind of host (Service Fabric, Azure Arc,
/// Cloud Shell) or for a user-assigned identity.
const AZURE_SHADOWING: &[&str] = &[
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_CLIENT_CERTIFICATE_PATH",
    "AZURE_CLIENT_CERTIFICATE_PASSWORD",
    "AZURE_FEDERATED_TOKEN_FILE",
    "AZURE_USERNAME",
    "AZURE_PASSWORD",
    "IDENTITY_SERVER_THUMBPRINT",
    "IMDS_ENDPOINT",
    "MSI_ENDPOINT",
    "MSI_SECRET",
    // Terraform's azurerm provider prefers a service principal or OIDC
    // token from these over every other way in.
    "ARM_CLIENT_ID",
    "ARM_CLIENT_SECRET",
    "ARM_CLIENT_CERTIFICATE_PATH",
    "ARM_CLIENT_CERTIFICATE_PASSWORD",
    "ARM_OIDC_TOKEN",
    "ARM_OIDC_TOKEN_FILE_PATH",
    "ARM_OIDC_REQUEST_TOKEN",
    "ARM_OIDC_REQUEST_URL",
];

/// The body App Service's token endpoint answers with: `expires_on` in
/// seconds since the epoch, as a string.
pub fn azure_identity_body(token: &str, expires_at: Timestamp, resource: &str) -> Value {
    json!({
        "access_token": token,
        "expires_on": expires_at.as_second().to_string(),
        "resource": resource,
        "token_type": "Bearer",
        "client_id": providers::azure::CLIENT_ID,
    })
}

fn azure_error(status: u16, error: &str, description: impl Into<String>) -> Response {
    Response {
        status,
        body: json!({ "error": error, "error_description": description.into() }),
    }
}

/// A managed identity endpoint for an Azure profile, as App Service runs
/// one: `GET <IDENTITY_ENDPOINT>?resource=<uri>&api-version=2019-08-01` with
/// the `X-IDENTITY-HEADER` secret answers with a token for that resource in
/// the subscription's tenant, from the stored sign-in. The Azure Identity
/// libraries (and `DefaultAzureCredential`) use it. Tokens are kept per
/// resource while they last.
pub async fn azure_identity_endpoint(
    integration: String,
    tenant: String,
) -> anyhow::Result<Provision> {
    let listener = serve::bind().await?;
    let port = listener.local_addr()?.port();
    let secret = serve::secret()?;
    // One lock over the cache, held while a token is fetched, so requests
    // that miss together start one refresh at Entra ID, not one each
    // (`resource_token` takes the integration's lock anyway).
    type Cache = tokio::sync::Mutex<HashMap<String, (String, Timestamp)>>;
    let state: Arc<(String, String, String, Cache)> =
        Arc::new((integration, tenant, secret.clone(), Cache::default()));
    let handler = move |request: Request| {
        let state = state.clone();
        async move {
            let (integration, tenant, secret, cache) = &*state;
            if !serve::secret_matches(request.header("x-identity-header"), secret) {
                return azure_error(401, "unauthorized", "wrong or missing X-IDENTITY-HEADER");
            }
            if request.method != "GET" || request.path != IDENTITY_PATH {
                return azure_error(404, "not_found", format!("GET {IDENTITY_PATH} only"));
            }
            if [
                "client_id",
                "principal_id",
                "object_id",
                "mi_res_id",
                "msi_res_id",
            ]
            .iter()
            .any(|p| request.query(p).is_some())
            {
                return azure_error(
                    400,
                    "invalid_request",
                    "fob serves the signed-in account, not a user-assigned identity; unset AZURE_CLIENT_ID",
                );
            }
            let Some(resource) = request
                .query("resource")
                .filter(|r| !r.trim().is_empty())
                .map(str::to_string)
            else {
                return azure_error(400, "invalid_request", "no resource");
            };
            let mut cache = cache.lock().await;
            let now = Timestamp::now();
            cache.retain(|_, (_, at)| *at > now);
            let cached = cache.get(&resource).cloned();
            let (token, expires_at) = match cached {
                Some((token, at)) if at.duration_since(now) > SERVE_MIN => (token, at),
                _ => match providers::azure::resource_token(integration, tenant, &resource).await {
                    Ok(found) => {
                        cache.insert(resource.clone(), found.clone());
                        found
                    }
                    // Passed on as unavailable, so the SDKs try again.
                    Err(e) if transient(&e) => {
                        return azure_error(503, "temporarily_unavailable", failure(&e));
                    }
                    Err(e) => return azure_error(400, "invalid_resource", failure(&e)),
                },
            };
            drop(cache);
            Response::ok(azure_identity_body(&token, expires_at, &resource))
        }
    };
    Ok(Provision {
        set: vec![
            (
                "IDENTITY_ENDPOINT".into(),
                format!("http://127.0.0.1:{port}{IDENTITY_PATH}"),
            ),
            ("IDENTITY_HEADER".into(), secret),
        ],
        remove: AZURE_SHADOWING.iter().map(|v| v.to_string()).collect(),
        files: Vec::new(),
        tasks: vec![task(serve::serve(listener, handler))],
    })
}

/// Whether a failure may pass if tried again: the network, or a 5xx from
/// the provider.
fn transient(e: &crate::Error) -> bool {
    match e {
        crate::Error::NeedsLogin { .. } => false,
        crate::Error::Other(e) => e
            .chain()
            .any(|c| c.is::<reqwest::Error>() || c.is::<providers::azure::Unavailable>()),
    }
}

// --- Google ----------------------------------------------------------------

/// The ADC file `fob exec` writes for a Google profile: credentials of the
/// type gcloud writes for workforce identity federation, which the Google
/// client libraries refresh with a `refresh_token` grant at `token_url`.
/// Here the URL is the loopback endpoint and the "refresh token" its
/// secret, which means nothing anywhere else; no Google token is written.
pub fn gcp_adc_file_body(token_url: &str, secret: &str) -> Value {
    json!({
        "type": "external_account_authorized_user",
        "client_id": "omnifob",
        "client_secret": "omnifob",
        "refresh_token": secret,
        "token_url": token_url,
        "universe_domain": "googleapis.com",
    })
}

/// A profile's Google access token and when it ends.
fn gcp_token(creds: &Credentials) -> anyhow::Result<(&str, Option<Timestamp>)> {
    let token = creds
        .env
        .get("CLOUDSDK_AUTH_ACCESS_TOKEN")
        .context("not a Google Cloud profile")?;
    Ok((token, creds.expires_at))
}

/// A token endpoint and an ADC file (`GOOGLE_APPLICATION_CREDENTIALS`)
/// for a Google profile, so the client libraries get its access token and
/// come back for a new one when it nears its end. `ttl` caps the lifetime
/// of a service account's tokens, as for `fob exec`.
pub async fn gcp_adc_endpoint(
    config: Config,
    profile: Profile,
    ttl: Option<SignedDuration>,
) -> anyhow::Result<Provision> {
    let listener = serve::bind().await?;
    let port = listener.local_addr()?.port();
    let secret = serve::secret()?;
    let body = gcp_adc_file_body(&format!("http://127.0.0.1:{port}/token"), &secret);
    let file = TempFile::create(".json", &serde_json::to_vec_pretty(&body)?)?;
    let state = Arc::new((config, profile, secret, Served::default()));
    let handler = move |request: Request| {
        let state = state.clone();
        async move {
            let (config, profile, secret, served) = &*state;
            let error = |status, e: &str, d: String| Response {
                status,
                body: json!({ "error": e, "error_description": d }),
            };
            if request.method != "POST" || request.path != "/token" {
                return error(404, "not_found", "POST /token only".into());
            }
            if request.form("grant_type").as_deref() != Some("refresh_token")
                || !serve::secret_matches(request.form("refresh_token").as_deref(), secret)
            {
                return error(400, "invalid_grant", "wrong grant or refresh token".into());
            }
            let creds = match served.get(config, profile, ttl, None).await {
                Ok(creds) => creds,
                Err(e) => return error(400, "invalid_grant", failure(&e)),
            };
            let Ok((token, expires_at)) = gcp_token(&creds) else {
                return error(500, "server_error", "not a Google Cloud profile".into());
            };
            let expires_in = expires_at
                .map(|at| at.duration_since(Timestamp::now()).as_secs().max(0))
                .unwrap_or(3600);
            Response::ok(json!({
                "access_token": token,
                "expires_in": expires_in,
                "token_type": "Bearer",
            }))
        }
    };
    Ok(Provision {
        set: vec![(
            "GOOGLE_APPLICATION_CREDENTIALS".into(),
            file.path().display().to_string(),
        )],
        // Terraform's google provider takes a static access token here over
        // the ADC file, and stops working when it expires.
        remove: vec!["GOOGLE_OAUTH_ACCESS_TOKEN".into()],
        files: vec![file],
        tasks: vec![task(serve::serve(listener, handler))],
    })
}

/// gcloud's access token file (`auth/access_token_file`, so
/// `CLOUDSDK_AUTH_ACCESS_TOKEN_FILE`), written private and rewritten with a
/// new token ten minutes before the old one ends, since gcloud reads it on
/// every run. `CLOUDSDK_AUTH_ACCESS_TOKEN` is removed, because gcloud reads
/// it first. A token that lasts longer is written again every
/// `TOKEN_FILE_REWRITE`, so `run_dir` never takes the file for a stale
/// one. `ttl` caps the lifetime of a service account's new tokens, as for
/// `fob exec`.
pub fn gcp_token_file(
    config: Config,
    profile: Profile,
    creds: &Credentials,
    ttl: Option<SignedDuration>,
) -> anyhow::Result<Provision> {
    let (token, mut expires_at) = gcp_token(creds)?;
    let mut token = token.to_string();
    let file = TempFile::create(".token", token.as_bytes())?;
    let path = file.path().to_path_buf();
    let keep_fresh = async move {
        loop {
            let until_renewal = expires_at
                .map(|at| at.duration_since(Timestamp::now()) - SignedDuration::from_mins(10))
                .unwrap_or(SignedDuration::from_mins(50));
            let wait = until_renewal
                .min(TOKEN_FILE_REWRITE)
                .max(SignedDuration::from_secs(30));
            tokio::time::sleep(wait.unsigned_abs()).await;
            if until_renewal > TOKEN_FILE_REWRITE {
                if let Err(e) = crate::files::write_private(&path, &token) {
                    tracing::warn!("could not rewrite the gcloud token file: {e:#}");
                }
                continue;
            }
            match providers::credentials(&config, &profile, false, ttl).await {
                Ok(creds) => match gcp_token(&creds) {
                    Ok((new, at)) => {
                        if let Err(e) = crate::files::write_private(&path, new) {
                            tracing::warn!("could not rewrite the gcloud token file: {e:#}");
                        }
                        token = new.to_string();
                        expires_at = at;
                    }
                    Err(e) => tracing::warn!("{e:#}"),
                },
                Err(e) => tracing::warn!("could not renew the gcloud token file: {}", failure(&e)),
            }
        }
    };
    Ok(Provision {
        set: vec![(
            "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE".into(),
            file.path().display().to_string(),
        )],
        remove: vec!["CLOUDSDK_AUTH_ACCESS_TOKEN".into()],
        files: vec![file],
        tasks: vec![task(keep_fresh)],
    })
}

/// The subject token type of executable-sourced credentials that hand out
/// an OIDC ID token.
const ID_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:id_token";

/// What an executable-sourced credential's command prints: version 1 of
/// Google's executable response, with the account's ID token.
pub fn gcp_executable_response(id_token: &str, expires_at: Timestamp) -> Value {
    json!({
        "version": 1,
        "success": true,
        "token_type": ID_TOKEN_TYPE,
        "id_token": id_token,
        "expiration_time": expires_at.as_second(),
    })
}

/// An `external_account` ADC file whose subject token comes from
/// `command` (`fob creds <profile> --format gcp-executable`), exchanged by
/// Google's STS through the workload identity pool provider `audience`,
/// and optionally used to impersonate a service account. It holds no
/// token. The libraries run the command only with
/// `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1`.
pub fn gcp_executable_adc(command: &str, audience: &str, impersonate: Option<&str>) -> Value {
    let mut adc = json!({
        "type": "external_account",
        "audience": audience,
        "subject_token_type": ID_TOKEN_TYPE,
        "token_url": "https://sts.googleapis.com/v1/token",
        "credential_source": {
            "executable": {
                "command": command,
                "timeout_millis": 30000,
            }
        },
        "universe_domain": "googleapis.com",
    });
    if let Some(email) = impersonate {
        adc["service_account_impersonation_url"] = format!(
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{email}:generateAccessToken"
        )
        .into();
    }
    adc
}

/// Checks that `audience` names a workload identity pool provider, as
/// Google's STS wants it.
pub fn check_wif_audience(audience: &str) -> anyhow::Result<()> {
    let ok = audience.starts_with("//iam.googleapis.com/")
        && audience.contains("/workloadIdentityPools/")
        && audience.contains("/providers/")
        && !audience.chars().any(char::is_whitespace);
    if !ok {
        bail!(
            "'{audience}' is not a workload identity pool provider; write it as //iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>"
        );
    }
    Ok(())
}

// --- Kubernetes ------------------------------------------------------------

/// The Entra ID application of the AKS API servers (the "Azure Kubernetes
/// Service AAD Server"), whose tokens AKS clusters with Entra ID accept,
/// as `kubelogin` asks for them.
pub const AKS_SERVER_APP: &str = "6dae42f8-4368-4678-94ff-3960e28e3630";

/// The `ExecCredential` API version kubectl asked for in
/// `KUBERNETES_EXEC_INFO`, which the answer must use; `v1` without one.
pub fn exec_api_version(exec_info: Option<&str>) -> anyhow::Result<String> {
    let Some(info) = exec_info.filter(|i| !i.is_empty()) else {
        return Ok("client.authentication.k8s.io/v1".to_string());
    };
    let info: Value = serde_json::from_str(info).context("reading KUBERNETES_EXEC_INFO")?;
    match info["apiVersion"].as_str() {
        Some(v @ ("client.authentication.k8s.io/v1" | "client.authentication.k8s.io/v1beta1")) => {
            Ok(v.to_string())
        }
        other => bail!("kubectl asked for ExecCredential {other:?}, which fob does not write"),
    }
}

/// An `ExecCredential` with a bearer token, as kubectl's exec plugins
/// return it.
pub fn exec_credential(api_version: &str, token: &str, expires_at: Option<Timestamp>) -> Value {
    let mut status = json!({ "token": token });
    if let Some(at) = expires_at {
        status["expirationTimestamp"] = at.strftime("%Y-%m-%dT%H:%M:%SZ").to_string().into();
    }
    json!({
        "kind": "ExecCredential",
        "apiVersion": api_version,
        "spec": {},
        "status": status,
    })
}

/// How long EKS accepts a token: a presigned URL is valid for 15 minutes
/// from its signing time, and `aws-iam-authenticator` reports a minute less.
const EKS_TOKEN_LIFETIME: SignedDuration = SignedDuration::from_mins(14);

/// An EKS token, as `aws eks get-token` and `aws-iam-authenticator` make
/// it: `k8s-aws-v1.` and the unpadded base64url of an STS
/// `GetCallerIdentity` URL presigned for 60 seconds in `region`, whose
/// signed headers include `x-k8s-aws-id: <cluster>`. The cluster's
/// authenticator calls the URL to learn who signed it.
pub fn eks_token(
    creds: &Credentials,
    cluster: &str,
    region: &str,
) -> anyhow::Result<(String, Timestamp)> {
    eks_token_at(creds, cluster, region, std::time::SystemTime::now())
}

fn eks_token_at(
    creds: &Credentials,
    cluster: &str,
    region: &str,
    now: std::time::SystemTime,
) -> anyhow::Result<(String, Timestamp)> {
    use aws_sigv4::http_request::{
        SignableBody, SignableRequest, SignatureLocation, SigningSettings, sign,
    };
    if cluster.is_empty() || cluster.chars().any(|c| c.is_whitespace() || c.is_control()) {
        bail!("'{cluster}' is not a cluster name");
    }
    let get = |k: &str| {
        creds
            .env
            .get(k)
            .cloned()
            .with_context(|| format!("not an AWS profile: no {k}"))
    };
    let identity = aws_sdk_sts::config::Credentials::new(
        get("AWS_ACCESS_KEY_ID")?,
        get("AWS_SECRET_ACCESS_KEY")?,
        creds.env.get("AWS_SESSION_TOKEN").cloned(),
        None,
        "omnifob",
    )
    .into();
    let host = providers::aws::partition::Partition::of_region(region)?.sts_host(region)?;
    let url = format!("https://{host}/?Action=GetCallerIdentity&Version=2011-06-15");
    let mut settings = SigningSettings::default();
    settings.signature_location = SignatureLocation::QueryParams;
    settings.expires_in = Some(std::time::Duration::from_secs(60));
    let params = aws_sigv4::sign::v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name("sts")
        .time(now)
        .settings(settings)
        .build()
        .map_err(|e| anyhow!("signing the EKS token: {e}"))?
        .into();
    let request = SignableRequest::new(
        "GET",
        url.as_str(),
        [("x-k8s-aws-id", cluster)].into_iter(),
        SignableBody::Bytes(&[]),
    )
    .map_err(|e| anyhow!("signing the EKS token: {e}"))?;
    let (instructions, _) = sign(request, &params)
        .map_err(|e| anyhow!("signing the EKS token: {e}"))?
        .into_parts();
    let mut signed = reqwest::Url::parse(&url)?;
    {
        let mut query = signed.query_pairs_mut();
        for (name, value) in instructions.params() {
            query.append_pair(name, value);
        }
    }
    let token = format!(
        "k8s-aws-v1.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signed.as_str())
    );
    let issued = Timestamp::try_from(now)?;
    Ok((token, issued.checked_add(EKS_TOKEN_LIFETIME)?))
}

/// The Region an AWS profile's credentials name, for its EKS token.
pub fn aws_region(creds: &Credentials) -> Option<&str> {
    creds
        .env
        .get("AWS_REGION")
        .or_else(|| creds.env.get("AWS_DEFAULT_REGION"))
        .map(String::as_str)
}

/// Whether `profile` is an Azure subscription, and its integration and
/// tenant if so.
pub fn azure_tenant(profile: &Profile) -> Option<(&str, &str)> {
    match &profile.target {
        Target::Azure { tenant_id, .. } => Some((&profile.integration, tenant_id)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aws_creds() -> Credentials {
        let mut creds = Credentials {
            expires_at: Some("2100-01-01T00:00:00Z".parse().unwrap()),
            ..Default::default()
        };
        for (k, v) in [
            ("AWS_ACCESS_KEY_ID", "ASIAEXAMPLE"),
            ("AWS_SECRET_ACCESS_KEY", "secret"),
            ("AWS_SESSION_TOKEN", "session"),
            ("AWS_ACCOUNT_ID", "111111111111"),
        ] {
            creds.env.insert(k.into(), v.into());
        }
        creds
    }

    #[test]
    fn served_credentials_last_until_they_are_due_for_renewal() {
        let now: Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
        let creds = |issued_mins_ago: i64, lasts_mins: i64| Credentials {
            issued_at: Some(now - SignedDuration::from_mins(issued_mins_ago)),
            expires_at: Some(
                now - SignedDuration::from_mins(issued_mins_ago)
                    + SignedDuration::from_mins(lasts_mins),
            ),
            ..Default::default()
        };
        // An hour's credentials, while 15 minutes are left.
        assert!(still_served(&creds(30, 60), now));
        assert!(!still_served(&creds(50, 60), now));
        // 15-minute credentials are not fetched again every minute...
        assert!(still_served(&creds(3, 15), now));
        // ...but are near their end, and never served expired.
        assert!(!still_served(&creds(10, 15), now));
        assert!(!still_served(&creds(0, -1), now));
    }

    /// Embedders can run the tasks on a multi-threaded runtime.
    #[test]
    fn provisions_are_send() {
        fn send<T: Send>() {}
        send::<Provision>();
    }

    #[test]
    fn container_body_has_what_the_sdks_read() {
        let body = aws_container_body(&aws_creds()).unwrap();
        assert_eq!(body["AccessKeyId"], "ASIAEXAMPLE");
        assert_eq!(body["Token"], "session");
        assert_eq!(body["Expiration"], "2100-01-01T00:00:00Z");
        assert_eq!(body["AccountId"], "111111111111");
        let mut creds = aws_creds();
        creds.env.remove("AWS_SESSION_TOKEN");
        assert!(aws_container_body(&creds).is_err());
    }

    #[test]
    fn eks_tokens_presign_get_caller_identity_for_the_cluster() {
        let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000);
        let (token, expires) = eks_token_at(&aws_creds(), "dev", "eu-west-1", now).unwrap();
        let encoded = token.strip_prefix("k8s-aws-v1.").unwrap();
        assert!(!encoded.contains('='), "unpadded");
        let url = String::from_utf8(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(encoded)
                .unwrap(),
        )
        .unwrap();
        let url = reqwest::Url::parse(&url).unwrap();
        assert_eq!(url.host_str(), Some("sts.eu-west-1.amazonaws.com"));
        let q: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q["Action"], "GetCallerIdentity");
        assert_eq!(q["Version"], "2011-06-15");
        assert_eq!(q["X-Amz-Expires"], "60");
        assert_eq!(q["X-Amz-SignedHeaders"], "host;x-k8s-aws-id");
        assert_eq!(q["X-Amz-Security-Token"], "session");
        assert!(
            q["X-Amz-Credential"].starts_with("ASIAEXAMPLE/20270115/eu-west-1/sts/aws4_request")
        );
        assert_eq!(expires.as_second(), 1_800_000_000 + 14 * 60);
        // China's STS has its own domain.
        let (token, _) = eks_token_at(&aws_creds(), "dev", "cn-north-1", now).unwrap();
        let url = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token.strip_prefix("k8s-aws-v1.").unwrap())
            .unwrap();
        assert!(
            String::from_utf8(url)
                .unwrap()
                .starts_with("https://sts.cn-north-1.amazonaws.com.cn/")
        );
        assert!(eks_token_at(&aws_creds(), "a b", "eu-west-1", now).is_err());
    }

    #[test]
    fn exec_credentials_answer_in_the_version_asked_for() {
        assert_eq!(
            exec_api_version(None).unwrap(),
            "client.authentication.k8s.io/v1"
        );
        let info = r#"{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{"interactive":false}}"#;
        assert_eq!(
            exec_api_version(Some(info)).unwrap(),
            "client.authentication.k8s.io/v1beta1"
        );
        assert!(
            exec_api_version(Some(
                r#"{"apiVersion":"client.authentication.k8s.io/v1alpha1"}"#
            ))
            .is_err()
        );
        let value = exec_credential(
            "client.authentication.k8s.io/v1",
            "t",
            Some("2100-01-01T00:00:00.5Z".parse().unwrap()),
        );
        assert_eq!(value["kind"], "ExecCredential");
        assert_eq!(value["status"]["token"], "t");
        assert_eq!(
            value["status"]["expirationTimestamp"],
            "2100-01-01T00:00:00Z"
        );
    }

    #[test]
    fn google_files_hold_no_google_token() {
        let adc = gcp_adc_file_body("http://127.0.0.1:1/token", "s");
        assert_eq!(adc["type"], "external_account_authorized_user");
        assert_eq!(adc["refresh_token"], "s");
        let adc = gcp_executable_adc(
            "fob creds g/p/user --format gcp-executable",
            "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/g",
            Some("sa@p.iam.gserviceaccount.com"),
        );
        assert_eq!(
            adc["credential_source"]["executable"]["command"],
            "fob creds g/p/user --format gcp-executable"
        );
        assert!(
            adc["service_account_impersonation_url"]
                .as_str()
                .unwrap()
                .ends_with("sa@p.iam.gserviceaccount.com:generateAccessToken")
        );
        let out = gcp_executable_response("h.p.s", Timestamp::from_second(100).unwrap());
        assert_eq!(out["version"], 1);
        assert_eq!(out["success"], true);
        assert_eq!(out["expiration_time"], 100);
        assert!(check_wif_audience("//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/g").is_ok());
        assert!(check_wif_audience("https://example.com").is_err());
    }

    #[test]
    fn identity_body_reads_as_app_service_writes_it() {
        let body = azure_identity_body(
            "t",
            Timestamp::from_second(1586984735).unwrap(),
            "https://vault.azure.net",
        );
        assert_eq!(body["expires_on"], "1586984735");
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["resource"], "https://vault.azure.net");
    }
}
