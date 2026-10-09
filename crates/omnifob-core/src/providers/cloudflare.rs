//! Cloudflare.
//!
//! Cloudflare API tokens never expire on their own and are tedious to scope
//! in the dashboard. omnifob instead keeps one bootstrap token (made once
//! with the dashboard's "Create additional tokens" template, or an
//! account-owned token with "Account API Tokens Edit") and mints short-lived,
//! narrowly scoped tokens from templates that name permissions the way the
//! dashboard does ("Workers Scripts Write"), never by ID.
//!
//! Minted tokens get the same variables wrangler reads:
//! `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`.

use std::collections::{BTreeMap, HashMap};

use anyhow::{Context, bail};
use jiff::{Timestamp, Unit};
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::{CloudflareConfig, CloudflareTemplate, CloudflareTokenType};
use crate::{Credentials, Error, Profile, Result, Target, store};

pub const API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// The API base URL; `OMNIFOB_CLOUDFLARE_API` overrides it for testing.
fn api_base() -> String {
    std::env::var("OMNIFOB_CLOUDFLARE_API")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| API_BASE.to_string())
}

/// Minted tokens are named with this prefix so expired ones can be cleaned up
/// without touching tokens omnifob did not create.
/// Minted tokens are named `omnifob <template>`. The IDs of minted tokens are
/// tracked in the catalog, so cleanup and revocation never rely on names.
const TOKEN_NAME_PREFIX: &str = "omnifob";

/// Prefix of the names used before 0.3 (`omnifob:<profile>@<time>`); such
/// tokens are still cleaned up and revoked.
const LEGACY_NAME_PREFIX: &str = "omnifob:";

const SCOPE_ACCOUNT: &str = "com.cloudflare.api.account";
const SCOPE_ZONE: &str = "com.cloudflare.api.account.zone";
const SCOPE_USER: &str = "com.cloudflare.api.user";
const SCOPE_R2_BUCKET: &str = "com.cloudflare.edge.r2.bucket";

/// Templates available without configuration. A template in the config file
/// with the same name replaces the built-in one.
pub fn builtin_templates() -> BTreeMap<String, CloudflareTemplate> {
    let t = |permissions: &[&str], optional: &[&str]| CloudflareTemplate {
        permissions: permissions.iter().map(|p| p.to_string()).collect(),
        optional: optional.iter().map(|p| p.to_string()).collect(),
        ..Default::default()
    };
    BTreeMap::from([
        // Everything `wrangler deploy` and the usual Worker bindings need: the
        // dashboard's "Edit Cloudflare Workers" template plus the products it
        // never caught up with (D1, Queues, Workers AI, Vectorize, Hyperdrive,
        // Browser Run...). Names checked against a live account on 2026-10-06;
        // optional ones depend on what the account has enabled.
        (
            "workers".to_string(),
            t(
                &[
                    "Account Settings Read",
                    "Zone Read",
                    "Workers Scripts Write",
                    "Workers Routes Write",
                    "Workers Tail Read",
                    "Workers KV Storage Write",
                    "Workers R2 Storage Write",
                    "Pages Write",
                    "D1 Write",
                    "Queues Write",
                    "Workers AI Write",
                    "Vectorize Write",
                    "Hyperdrive Write",
                    "Workers Containers Write",
                    "Pipelines Write",
                ],
                &[
                    // User-level: only user-owned bootstraps offer these.
                    "User Details Read",
                    "Memberships Read",
                    "AI Gateway Write",
                    "AI Search Write",
                    "Agent Memory Write",
                    "Artifacts Write",
                    "Browser Run Write",
                    "CF Agents Write",
                    "Cloudchamber Write",
                    "Email Sending Write",
                    "Flagship Write",
                    "Images Write",
                    "Secrets Store Write",
                    "Workers CI Write",
                    "Workers Observability Write",
                ],
            ),
        ),
        ("dns-read".to_string(), t(&["Zone Read", "DNS Read"], &[])),
        ("dns-edit".to_string(), t(&["Zone Read", "DNS Write"], &[])),
        (
            "read".to_string(),
            t(
                &[
                    "Account Settings Read",
                    "Zone Read",
                    "DNS Read",
                    "Workers Scripts Read",
                ],
                &[],
            ),
        ),
    ])
}

pub(crate) fn templates(config: &CloudflareConfig) -> BTreeMap<String, CloudflareTemplate> {
    let mut all = builtin_templates();
    all.extend(config.templates.clone());
    all
}

fn bootstrap_key(integration: &str) -> String {
    format!("cloudflare/{integration}/bootstrap")
}

/// A thin client for the Cloudflare v4 API.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    base: String,
    token: String,
}

#[derive(Deserialize)]
struct Envelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<ApiMessage>,
    result: Option<T>,
    #[serde(default)]
    result_info: Option<ResultInfo>,
}

#[derive(Deserialize)]
struct ApiMessage {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct ResultInfo {
    #[serde(default)]
    page: Option<u32>,
    #[serde(default)]
    total_pages: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PermissionGroup {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Account {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct Token {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    expires_on: Option<Timestamp>,
    #[serde(default)]
    policies: Vec<Value>,
    #[serde(default)]
    condition: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct CreatedToken {
    #[serde(default)]
    id: String,
    value: String,
}

impl Client {
    /// The same API endpoint, authenticated with another token.
    pub fn with_token(&self, token: impl Into<String>) -> Self {
        Self {
            http: self.http.clone(),
            base: self.base.clone(),
            token: token.into(),
        }
    }

    pub fn new(base: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base: base.into(),
            token: token.into(),
        }
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> anyhow::Result<(T, Option<ResultInfo>)> {
        let mut request = self
            .http
            .request(method.clone(), format!("{}{path}", self.base))
            .bearer_auth(&self.token)
            .query(query);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .with_context(|| format!("{method} {path}"))?;
        let status = response.status();
        let text = response.text().await?;
        let envelope: Envelope<T> = serde_json::from_str(&text)
            .with_context(|| format!("{method} {path}: unexpected response ({status})"))?;
        if !envelope.success {
            let messages: Vec<_> = envelope
                .errors
                .iter()
                .map(|e| format!("{} (code {})", e.message, e.code))
                .collect();
            bail!("{method} {path} failed ({status}): {}", messages.join("; "));
        }
        let result = envelope
            .result
            .with_context(|| format!("{method} {path}: empty result"))?;
        Ok((result, envelope.result_info))
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        Ok(self.call(Method::GET, path, &[], None).await?.0)
    }

    async fn get_all<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<Vec<T>> {
        let mut all = Vec::new();
        let mut page = 1;
        loop {
            let query = [("page", page.to_string()), ("per_page", "50".to_string())];
            let (items, info): (Vec<T>, _) = self.call(Method::GET, path, &query, None).await?;
            let done = items.is_empty()
                || info
                    .and_then(|i| Some(i.page? >= i.total_pages?))
                    .unwrap_or(true);
            all.extend(items);
            if done {
                return Ok(all);
            }
            page += 1;
        }
    }

    /// Path prefix for the token endpoints of either ownership model.
    fn tokens_path(token_type: CloudflareTokenType, account_id: &str) -> String {
        match token_type {
            CloudflareTokenType::User => "/user/tokens".to_string(),
            CloudflareTokenType::Account => format!("/accounts/{account_id}/tokens"),
        }
    }

    /// Checks that the bootstrap token is active; returns its id.
    pub async fn verify(
        &self,
        token_type: CloudflareTokenType,
        account_id: &str,
    ) -> anyhow::Result<String> {
        #[derive(Deserialize)]
        struct Verified {
            id: String,
            status: String,
        }
        let path = format!("{}/verify", Self::tokens_path(token_type, account_id));
        let verified: Verified = self.get(&path).await?;
        if verified.status != "active" {
            bail!("the token is {}, not active", verified.status);
        }
        Ok(verified.id)
    }

    pub async fn permission_groups(
        &self,
        token_type: CloudflareTokenType,
        account_id: &str,
    ) -> anyhow::Result<Vec<PermissionGroup>> {
        let path = format!(
            "{}/permission_groups",
            Self::tokens_path(token_type, account_id)
        );
        self.get_all(&path).await
    }
}

/// Resolves permission names to groups, case-insensitively, and reports every
/// unknown name at once with suggestions.
pub fn resolve_permissions<'a>(
    names: &[String],
    groups: &'a [PermissionGroup],
) -> anyhow::Result<Vec<&'a PermissionGroup>> {
    let by_name: HashMap<String, &PermissionGroup> =
        groups.iter().map(|g| (g.name.to_lowercase(), g)).collect();
    let mut resolved = Vec::new();
    let mut unknown = Vec::new();
    // The dashboard says "Edit" where the API says "Write"; accept both.
    let lookup = |name: &str| {
        let lower = name.to_lowercase();
        by_name.get(&lower).copied().or_else(|| {
            let alias = match lower.rsplit_once(' ') {
                Some((base, "edit")) => format!("{base} write"),
                Some((base, "write")) => format!("{base} edit"),
                _ => return None,
            };
            by_name.get(&alias).copied()
        })
    };
    for name in names {
        match lookup(name) {
            Some(group) => resolved.push(group),
            None => {
                let words: Vec<String> = name
                    .to_lowercase()
                    .split_whitespace()
                    .map(str::to_string)
                    .collect();
                let mut close: Vec<&str> = groups
                    .iter()
                    .filter(|g| {
                        let g = g.name.to_lowercase();
                        words.iter().filter(|w| g.contains(w.as_str())).count()
                            >= words.len().max(2) - 1
                    })
                    .map(|g| g.name.as_str())
                    .collect();
                close.sort_unstable();
                close.truncate(5);
                if close.is_empty() {
                    unknown.push(format!("'{name}'"));
                } else {
                    unknown.push(format!("'{name}' (did you mean: {}?)", close.join(", ")));
                }
            }
        }
    }
    if !unknown.is_empty() {
        bail!(
            "unknown Cloudflare permission(s): {}. Run `fob cloudflare permissions` to list them.",
            unknown.join("; ")
        );
    }
    Ok(resolved)
}

/// The permissions of one service ("Workers Scripts"), as the dashboard
/// shows them: a Read and an Edit (API: Write) level, and any other ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub name: String,
    pub read: Option<PermissionGroup>,
    pub write: Option<PermissionGroup>,
    pub other: Vec<PermissionGroup>,
}

impl Service {
    /// What the service applies to: account, zone or user.
    pub fn scope(&self) -> &str {
        self.read
            .iter()
            .chain(&self.write)
            .chain(&self.other)
            .find_map(|g| g.scopes.first())
            .map_or("", |s| s.rsplit('.').next().unwrap_or(s))
    }
}

/// Groups permissions by service, sorted by name. Account-owned tokens
/// cannot carry user-level permissions, so those are left out for them.
pub fn services(groups: &[PermissionGroup], token_type: CloudflareTokenType) -> Vec<Service> {
    let mut by_name: BTreeMap<String, Service> = BTreeMap::new();
    for group in groups {
        if token_type == CloudflareTokenType::Account
            && group.scopes.iter().any(|s| s == SCOPE_USER)
        {
            continue;
        }
        let (base, level) = match group.name.rsplit_once(' ') {
            Some((base, "Read")) => (base, Some(false)),
            Some((base, "Write" | "Edit")) => (base, Some(true)),
            _ => (group.name.as_str(), None),
        };
        let service = by_name
            .entry(base.to_lowercase())
            .or_insert_with(|| Service {
                name: base.to_string(),
                read: None,
                write: None,
                other: Vec::new(),
            });
        match level {
            Some(false) if service.read.is_none() => service.read = Some(group.clone()),
            Some(true) if service.write.is_none() => service.write = Some(group.clone()),
            _ => service.other.push(group.clone()),
        }
    }
    by_name.into_values().collect()
}

/// Builds token policies: one per resource kind the permissions apply to,
/// each limited to the given account (and, for zone permissions, every zone
/// in that account; for R2 bucket permissions, the listed buckets).
pub fn build_policies(
    groups: &[&PermissionGroup],
    account_id: &str,
    user_tag: Option<&str>,
    r2_buckets: &[String],
) -> anyhow::Result<Vec<Value>> {
    let mut by_scope: BTreeMap<&str, Vec<Value>> = BTreeMap::new();
    for group in groups {
        let scope = group
            .scopes
            .first()
            .with_context(|| format!("permission '{}' has no scope", group.name))?;
        by_scope
            .entry(scope.as_str())
            .or_default()
            .push(json!({ "id": group.id, "name": group.name }));
    }

    let account = format!("{SCOPE_ACCOUNT}.{account_id}");
    by_scope
        .into_iter()
        .map(|(scope, permission_groups)| {
            let resources = match scope {
                SCOPE_ACCOUNT => json!({ account.clone(): "*" }),
                SCOPE_ZONE => json!({ account.clone(): { format!("{SCOPE_ZONE}.*"): "*" } }),
                SCOPE_USER => {
                    let tag = user_tag.context(
                        "user-level permissions (like 'User Details Read') need a user-owned bootstrap token",
                    )?;
                    json!({ format!("{SCOPE_USER}.{tag}"): "*" })
                }
                SCOPE_R2_BUCKET => {
                    if r2_buckets.is_empty() {
                        bail!(
                            "{} apply to single R2 buckets; list them in the template's `r2_buckets`",
                            names(&permission_groups)
                        );
                    }
                    let buckets: serde_json::Map<String, Value> = r2_buckets
                        .iter()
                        .map(|b| {
                            let (jurisdiction, name) = b.split_once('/').unwrap_or(("default", b));
                            (format!("{SCOPE_R2_BUCKET}.{account_id}_{jurisdiction}_{name}"), json!("*"))
                        })
                        .collect();
                    Value::Object(buckets)
                }
                other => bail!(
                    "{} apply to '{other}', which omnifob cannot scope yet",
                    names(&permission_groups)
                ),
            };
            Ok(json!({ "effect": "allow", "resources": resources, "permission_groups": permission_groups }))
        })
        .collect()
}

fn names(permission_groups: &[Value]) -> String {
    let names: Vec<&str> = permission_groups
        .iter()
        .filter_map(|g| g["name"].as_str())
        .collect();
    format!("'{}'", names.join("', '"))
}

/// Resolves the addresses a token may be used from to CIDR ranges.
/// "current" is this machine's public IPv4 and IPv6 address, as Cloudflare
/// sees them at `api_base`.
pub async fn resolve_ips(ips: &[String], api_base: &str) -> anyhow::Result<Vec<String>> {
    let mut resolved = Vec::new();
    for ip in ips {
        if ip == "current" {
            let current = current_ips(api_base).await;
            if current.is_empty() {
                bail!("could not find this machine's public address for `ips = [\"current\"]`");
            }
            resolved.extend(current.iter().map(|ip| cidr(*ip)));
            continue;
        }
        let (addr, prefix) = ip
            .split_once('/')
            .map_or((ip.as_str(), None), |(a, p)| (a, Some(p)));
        let addr: std::net::IpAddr = addr
            .parse()
            .with_context(|| format!("'{ip}' is not an IP address or CIDR range"))?;
        resolved.push(match prefix {
            Some(prefix) => {
                let max = if addr.is_ipv4() { 32 } else { 128 };
                match prefix.parse::<u8>() {
                    Ok(p) if p <= max => format!("{addr}/{p}"),
                    _ => bail!("'{ip}' has an invalid prefix length"),
                }
            }
            None => cidr(addr),
        });
    }
    resolved.dedup();
    Ok(resolved)
}

fn cidr(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(ip) => format!("{ip}/32"),
        std::net::IpAddr::V6(ip) => format!("{ip}/128"),
    }
}

/// This machine's public addresses, one per IP version that works, from
/// Cloudflare's trace endpoint. Tools may connect over either version, so
/// both are allowed.
async fn current_ips(api_base: &str) -> Vec<std::net::IpAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let trace = match api_base.find("/client/v4") {
        Some(i) => format!("{}/cdn-cgi/trace", &api_base[..i]),
        None => format!("{api_base}/cdn-cgi/trace"),
    };
    let lookup = |local: IpAddr| {
        let trace = trace.clone();
        async move {
            let client = reqwest::Client::builder()
                .local_address(local)
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .ok()?;
            let text = client.get(&trace).send().await.ok()?.text().await.ok()?;
            text.lines()
                .find_map(|l| l.strip_prefix("ip="))
                .and_then(|ip| ip.trim().parse::<IpAddr>().ok())
        }
    };
    let (v4, v6) = tokio::join!(
        lookup(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        lookup(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
    );
    v4.into_iter().chain(v6).collect()
}

/// The S3-compatible credentials R2 derives from an API token: the token ID
/// is the access key, the SHA-256 of the token the secret.
fn r2_s3_env(
    account_id: &str,
    token_id: &str,
    token: &str,
    r2_buckets: &[String],
) -> BTreeMap<String, String> {
    use sha2::Digest;
    let secret: String = sha2::Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    // Buckets in a jurisdiction have their own endpoint.
    let jurisdictions: std::collections::BTreeSet<&str> = r2_buckets
        .iter()
        .map(|b| b.split_once('/').map_or("default", |(j, _)| j))
        .collect();
    let host = match jurisdictions.iter().next() {
        Some(&j) if jurisdictions.len() == 1 && j != "default" => {
            format!("{account_id}.{j}.r2.cloudflarestorage.com")
        }
        _ => format!("{account_id}.r2.cloudflarestorage.com"),
    };
    BTreeMap::from([
        ("AWS_ACCESS_KEY_ID".to_string(), token_id.to_string()),
        ("AWS_SECRET_ACCESS_KEY".to_string(), secret),
        ("AWS_ENDPOINT_URL_S3".to_string(), format!("https://{host}")),
        ("AWS_REGION".to_string(), "auto".to_string()),
    ])
}

/// The user tag appears in the resources of the bootstrap token's own policy;
/// reading it there avoids needing the "User Details Read" permission.
fn user_tag_from_policies(policies: &[Value]) -> Option<String> {
    let prefix = format!("{SCOPE_USER}.");
    policies.iter().find_map(|policy| {
        policy["resources"].as_object()?.keys().find_map(|k| {
            k.strip_prefix(&prefix)
                .filter(|t| *t != "*")
                .map(str::to_string)
        })
    })
}

/// A client authenticated with what mints tokens: the bootstrap token, or
/// for `cloudflare-oauth` the browser sign-in's access token.
async fn bootstrap_client(integration: &str, config: &CloudflareConfig) -> Result<Client> {
    if config.uses_oauth() {
        let token = super::cloudflare_oauth::access_token(integration, config).await?;
        return Ok(Client::new(api_base(), token));
    }
    let token: String = store::get(&bootstrap_key(integration))?
        .ok_or_else(|| Error::not_signed_in(integration))?;
    if let Some(expires_at) = session_expiry(integration)
        && expires_at <= Timestamp::now()
    {
        return Err(Error::needs_login(
            integration,
            format!("the Cloudflare session of '{integration}' expired"),
        ));
    }
    Ok(Client::new(api_base(), token))
}

/// When the stored bootstrap token expires, if it was given a session.
pub fn session_expiry(integration: &str) -> Option<Timestamp> {
    load_catalog(integration).bootstrap?.expires_at
}

/// Verifies and stores the bootstrap token.
/// Returns when the token expires if the integration has a `session`.
pub async fn login(
    integration: &str,
    config: &CloudflareConfig,
    token: &str,
) -> anyhow::Result<Option<Timestamp>> {
    if config.minting() == CloudflareTokenType::Account && config.account_id.is_none() {
        bail!("token_type = \"account\" needs account_id in the integration config");
    }
    let account_id = config.account_id.as_deref().unwrap_or_default();
    let client = Client::new(api_base(), token.trim());
    let id = client
        .verify(config.minting(), account_id)
        .await
        .context("the token was rejected")?;
    let mut catalog = load_catalog(integration);
    let previous = catalog.bootstrap.take().map(|b| b.id).filter(|p| *p != id);
    let expires_at = match config.session {
        Some(session) => {
            let tokens = Client::tokens_path(config.minting(), account_id);
            Some(start_session(&client, &tokens, &id, session, previous.as_deref()).await?)
        }
        None => None,
    };
    store::set(&bootstrap_key(integration), &token.trim())?;
    catalog.bootstrap = Some(Bootstrap { id, expires_at });
    save_catalog(integration, &catalog)?;
    Ok(expires_at)
}

/// Makes the new bootstrap token expire after `session` (unless it already
/// expires sooner), deletes the previous session's bootstrap, and returns
/// when the new one expires. A dashboard-made token may edit itself.
pub async fn start_session(
    client: &Client,
    tokens: &str,
    id: &str,
    session: jiff::SignedDuration,
    previous: Option<&str>,
) -> anyhow::Result<Timestamp> {
    let own: Token = client.get(&format!("{tokens}/{id}")).await?;
    let wanted = Timestamp::now().round(Unit::Second)?.checked_add(session)?;
    let expires_at = match own.expires_on {
        Some(at) if at <= wanted => at,
        _ => {
            let mut body = json!({
                "name": own.name,
                "policies": own.policies,
                "status": "active",
                "expires_on": wanted.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
            if let Some(condition) = &own.condition {
                body["condition"] = condition.clone();
            }
            client
                .call::<Value>(Method::PUT, &format!("{tokens}/{id}"), &[], Some(&body))
                .await
                .context("setting the bootstrap token's expiry")?;
            wanted
        }
    };
    if let Some(previous) = previous {
        match delete_token(client, tokens, previous).await {
            Ok(()) => tracing::debug!("deleted the previous session's bootstrap token"),
            Err(e) => tracing::debug!("previous bootstrap token not deleted: {e:#}"),
        }
    }
    Ok(expires_at)
}

/// Deletes the bootstrap token of a session on Cloudflare, so signing out
/// ends the session there too. Bootstrap tokens without a session are the
/// user's own and are left alone. Returns whether one was deleted.
pub async fn end_session(integration: &str, config: &CloudflareConfig) -> Result<bool> {
    if config.uses_oauth() {
        return Ok(super::cloudflare_oauth::revoke(integration, config).await?);
    }
    let Some(Bootstrap {
        id,
        expires_at: Some(_),
    }) = load_catalog(integration).bootstrap
    else {
        return Ok(false);
    };
    let client = bootstrap_client(integration, config).await?;
    let tokens = Client::tokens_path(
        config.minting(),
        config.account_id.as_deref().unwrap_or_default(),
    );
    delete_token(&client, &tokens, &id).await?;
    Ok(true)
}

pub fn logout(integration: &str) -> anyhow::Result<bool> {
    forget_catalog(integration);
    let oauth = super::cloudflare_oauth::logout(integration)?;
    Ok(store::delete(&bootstrap_key(integration))? || oauth)
}

/// Checks that the stored bootstrap token, or the browser sign-in, works.
pub async fn check(integration: &str, config: &CloudflareConfig) -> Result<String> {
    let client = bootstrap_client(integration, config).await?;
    if config.uses_oauth() {
        let accounts = accounts(&client).await?;
        return Ok(format!(
            "browser sign-in active, {} account(s)",
            accounts.len()
        ));
    }
    client
        .verify(
            config.minting(),
            config.account_id.as_deref().unwrap_or_default(),
        )
        .await?;
    let kind = match config.minting() {
        CloudflareTokenType::User => "user-owned",
        CloudflareTokenType::Account => "account-owned",
    };
    Ok(format!("{kind} bootstrap token active"))
}

/// Checks that a minted token is active.
pub async fn check_token(
    config: &CloudflareConfig,
    account_id: &str,
    token: &str,
) -> anyhow::Result<()> {
    Client::new(api_base(), token)
        .verify(config.minting(), account_id)
        .await
        .map(|_| ())
}

pub fn has_bootstrap_token(integration: &str) -> anyhow::Result<bool> {
    Ok(store::get::<String>(&bootstrap_key(integration))?.is_some())
}

/// The accounts the token reaches: for a browser sign-in, those approved on
/// the consent page.
async fn accounts(client: &Client) -> anyhow::Result<Vec<Account>> {
    let accounts: Vec<Account> = client.get_all("/accounts").await.context(
        "listing accounts; set account_id in the integration config if the token cannot list them",
    )?;
    if accounts.is_empty() {
        bail!("the token cannot see any account; set account_id in the integration config");
    }
    Ok(accounts)
}

/// One profile per account and template.
pub async fn discover(integration: &str, config: &CloudflareConfig) -> Result<Vec<Profile>> {
    let accounts = match &config.account_id {
        Some(id) => vec![Account {
            id: id.clone(),
            name: config.account_name.clone().unwrap_or_else(|| id.clone()),
        }],
        None => accounts(&bootstrap_client(integration, config).await?).await?,
    };

    let mut profiles = Vec::new();
    for account in &accounts {
        for template in templates(config).keys() {
            profiles.push(Profile::new(
                integration,
                &account.name,
                template,
                Target::Cloudflare {
                    account_id: account.id.clone(),
                    account_name: account.name.clone(),
                    template: template.clone(),
                },
            ));
        }
    }
    Ok(profiles)
}

/// Lists the permissions templates can use, for `fob cloudflare permissions`.
pub async fn permission_groups(
    integration: &str,
    config: &CloudflareConfig,
) -> Result<Vec<PermissionGroup>> {
    let client = bootstrap_client(integration, config).await?;
    // Account-owned tokens list the groups per account; any account will do.
    let account_id = match (&config.account_id, config.uses_oauth()) {
        (Some(id), _) => id.clone(),
        (None, true) => accounts(&client).await?.remove(0).id,
        (None, false) => String::new(),
    };
    let mut groups = client
        .permission_groups(config.minting(), &account_id)
        .await?;
    groups.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(groups)
}

/// What minting needs to know about the bootstrap token's account but which
/// rarely changes: the permission groups (about 400) and the user tag. Kept on
/// disk, without secrets, to save two to three API calls per mint.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Catalog {
    #[serde(default)]
    pub fetched_at: Option<Timestamp>,
    #[serde(default)]
    pub groups: Vec<PermissionGroup>,
    #[serde(default)]
    pub user_tag: Option<String>,
    /// IDs of the tokens minted for each profile that may still exist.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub minted: BTreeMap<String, Vec<String>>,
    /// The stored bootstrap token's ID and expiry, when it has a session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap: Option<Bootstrap>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bootstrap {
    pub id: String,
    pub expires_at: Option<Timestamp>,
}

impl Catalog {
    fn track(&mut self, profile_id: &str, token_id: &str) {
        self.minted
            .entry(profile_id.to_string())
            .or_default()
            .push(token_id.to_string());
    }

    fn untrack(&mut self, token_id: &str) {
        for ids in self.minted.values_mut() {
            ids.retain(|id| id != token_id);
        }
        self.minted.retain(|_, ids| !ids.is_empty());
    }

    fn is_tracked(&self, token_id: &str) -> bool {
        self.minted
            .values()
            .any(|ids| ids.iter().any(|id| id == token_id))
    }
}

/// How long a stored catalog is trusted before it is fetched again.
const CATALOG_MAX_AGE: jiff::SignedDuration = jiff::SignedDuration::from_hours(24);

impl Catalog {
    fn is_current(&self, now: Timestamp) -> bool {
        !self.groups.is_empty()
            && self
                .fetched_at
                .is_some_and(|at| now.duration_since(at) < CATALOG_MAX_AGE)
    }
}

fn catalog_file(integration: &str) -> std::path::PathBuf {
    crate::paths::state_dir().join(format!("cloudflare-{integration}.json"))
}

fn load_catalog(integration: &str) -> Catalog {
    std::fs::read_to_string(catalog_file(integration))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn save_catalog(integration: &str, catalog: &Catalog) -> anyhow::Result<()> {
    let path = catalog_file(integration);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, serde_json::to_string(catalog)?)?;
    Ok(())
}

/// Mints a token for the template and cleans up expired omnifob tokens.
pub async fn credentials(
    integration: &str,
    config: &CloudflareConfig,
    profile_id: &str,
    account_id: &str,
    template_name: &str,
) -> Result<Credentials> {
    let client = bootstrap_client(integration, config).await?;
    let limited;
    let config = if config.uses_oauth() {
        limited = within_granted_scopes(integration, config, template_name)?;
        &limited
    } else {
        config
    };
    let mut catalog = load_catalog(integration);
    let before = serde_json::to_string(&catalog).unwrap_or_default();
    let minted = mint(
        &client,
        config,
        profile_id,
        account_id,
        template_name,
        Timestamp::now(),
        &mut catalog,
    )
    .await;
    if serde_json::to_string(&catalog).unwrap_or_default() != before
        && let Err(e) = save_catalog(integration, &catalog)
    {
        tracing::warn!("could not save the Cloudflare permission catalog: {e:#}");
    }
    Ok(minted?)
}

/// A browser sign-in can only mint permissions whose scope its consent
/// granted. Leaves out optional permissions without one, and names the
/// required ones that lack it.
fn within_granted_scopes(
    integration: &str,
    config: &CloudflareConfig,
    template_name: &str,
) -> Result<CloudflareConfig> {
    use super::cloudflare_oauth::{granted_scopes, scope_for};
    let mut config = config.clone();
    let Some(granted) = granted_scopes(integration)?.filter(|g| !g.is_empty()) else {
        return Ok(config);
    };
    let Some(mut template) = templates(&config).remove(template_name) else {
        return Ok(config);
    };
    let allowed = |p: &String| scope_for(p).is_none_or(|s| granted.iter().any(|g| g == s));
    let missing: Vec<&String> = template
        .permissions
        .iter()
        .filter(|p| !allowed(p))
        .collect();
    if !missing.is_empty() {
        let names: Vec<&str> = missing.iter().map(|s| s.as_str()).collect();
        return Err(Error::needs_login(
            integration,
            format!(
                "the browser sign-in was not granted the scopes for {}; add them to the OAuth client and sign in again",
                names.join(", ")
            ),
        ));
    }
    template.optional.retain(|p| {
        let keep = allowed(p);
        if !keep {
            tracing::debug!("optional permission '{p}' was not granted at sign-in; skipped");
        }
        keep
    });
    config.templates.insert(template_name.to_string(), template);
    Ok(config)
}

/// Moves the stored catalog to a renamed integration.
pub fn rename_catalog(old: &str, new: &str) {
    let _ = std::fs::rename(catalog_file(old), catalog_file(new));
}

/// Removes the stored catalog, for example after signing out.
pub fn forget_catalog(integration: &str) {
    let _ = std::fs::remove_file(catalog_file(integration));
}

/// Where to create the bootstrap token. For account-owned tokens this is a
/// template URL that pre-fills the form (name, the "Account API Tokens Edit"
/// permission and the account); user-owned tokens need the dashboard's
/// "Create Additional Tokens" template, which no URL can pre-fill.
pub fn bootstrap_url(config: &CloudflareConfig) -> String {
    match config.minting() {
        CloudflareTokenType::User => "https://dash.cloudflare.com/profile/api-tokens".to_string(),
        CloudflareTokenType::Account => {
            let account = config.account_id.as_deref().unwrap_or(":account");
            let mut url = reqwest::Url::parse("https://dash.cloudflare.com/").expect("valid URL");
            url.query_pairs_mut()
                .append_pair("to", &format!("/{account}/api-tokens"))
                .append_pair(
                    "permissionGroupKeys",
                    r#"[{"key":"account_api_tokens","type":"edit"}]"#,
                )
                .append_pair("name", "omnifob bootstrap");
            url.to_string()
        }
    }
}

/// Picks the template's permissions from the catalog: all required ones,
/// and the optional ones the account offers. Account-owned tokens cannot
/// carry user-level permissions, so those are left out for them.
fn select<'a>(
    template: &CloudflareTemplate,
    groups: &'a [PermissionGroup],
    token_type: CloudflareTokenType,
) -> anyhow::Result<Vec<&'a PermissionGroup>> {
    let mut selected = resolve_permissions(&template.permissions, groups)?;
    for name in &template.optional {
        match resolve_permissions(std::slice::from_ref(name), groups) {
            Ok(found) => selected.extend(found),
            Err(_) => tracing::debug!("optional permission '{name}' is not offered; skipped"),
        }
    }
    if token_type == CloudflareTokenType::Account {
        selected.retain(|g| {
            let user_level = g.scopes.iter().any(|s| s == SCOPE_USER);
            if user_level {
                tracing::debug!(
                    "'{}' is user-level; account-owned tokens leave it out",
                    g.name
                );
            }
            !user_level
        });
    }
    selected.sort_by(|a, b| a.id.cmp(&b.id));
    selected.dedup_by(|a, b| a.id == b.id);
    Ok(selected)
}

/// Mints a token with `client` (authenticated with the bootstrap token),
/// using and updating `catalog`.
pub async fn mint(
    client: &Client,
    config: &CloudflareConfig,
    profile_id: &str,
    account_id: &str,
    template_name: &str,
    now: Timestamp,
    catalog: &mut Catalog,
) -> anyhow::Result<Credentials> {
    let template = templates(config)
        .remove(template_name)
        .with_context(|| format!("no Cloudflare template named '{template_name}'"))?;
    let token_type = config.minting();
    let tokens = Client::tokens_path(token_type, account_id);

    let fetch = |catalog: &mut Catalog, groups: Vec<PermissionGroup>| {
        catalog.groups = groups;
        catalog.fetched_at = Some(now);
    };
    if !catalog.is_current(now) {
        fetch(
            catalog,
            client.permission_groups(token_type, account_id).await?,
        );
    }
    // A name missing from a stored catalog may be a product added since.
    let selected = match select(&template, &catalog.groups, token_type) {
        Ok(selected) => selected,
        Err(_) if catalog.fetched_at != Some(now) => {
            fetch(
                catalog,
                client.permission_groups(token_type, account_id).await?,
            );
            select(&template, &catalog.groups, token_type)?
        }
        Err(e) => return Err(e),
    };

    let needs_user_tag = token_type == CloudflareTokenType::User
        && selected
            .iter()
            .any(|g| g.scopes.iter().any(|s| s == SCOPE_USER));
    if needs_user_tag && catalog.user_tag.is_none() {
        let id = client.verify(token_type, account_id).await?;
        let own: Token = client.get(&format!("{tokens}/{id}")).await?;
        catalog.user_tag = user_tag_from_policies(&own.policies);
    }
    let user_tag = if needs_user_tag {
        catalog.user_tag.as_deref()
    } else {
        None
    };
    let policies = build_policies(&selected, account_id, user_tag, &template.r2_buckets)?;
    let ips = resolve_ips(template.ips.as_ref().unwrap_or(&config.ips), &client.base).await?;
    let uses_d1 = selected.iter().any(|g| g.name.starts_with("D1 "));
    let uses_ai = selected.iter().any(|g| g.name.starts_with("Workers AI "));

    let ttl = template.ttl.unwrap_or(config.ttl);
    let now = now.round(Unit::Second)?;
    let expires_at = now.checked_add(ttl)?;
    let mut body = json!({
        "name": format!("{TOKEN_NAME_PREFIX} {template_name}"),
        "policies": policies,
        "expires_on": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
    });
    if !ips.is_empty() {
        body["condition"] = json!({ "request_ip": { "in": ips } });
    }
    let (created, _): (CreatedToken, _) = client
        .call(Method::POST, &tokens, &[], Some(&body))
        .await
        .context("minting a Cloudflare token")?;
    let token_id = (!created.id.is_empty()).then(|| created.id.clone());
    if let Some(id) = &token_id {
        catalog.track(profile_id, id);
    }

    // Cleaning up overlaps with waiting for D1 to accept the new token.
    let minted = client.with_token(&created.value);
    let wait = async {
        if uses_d1 {
            wait_until_accepted(
                &minted,
                &format!("/accounts/{account_id}/d1/database"),
                "D1",
            )
            .await;
        }
        if uses_ai {
            let path = format!("/accounts/{account_id}/ai/models/search");
            wait_until_accepted(&minted, &path, "Workers AI").await;
        }
    };
    let (_, pruned) = tokio::join!(wait, prune_expired(client, &tokens, now, catalog, false));
    if let Err(e) = pruned {
        tracing::warn!("could not clean up expired omnifob tokens: {e:#}");
    }

    let mut env = BTreeMap::new();
    if template.s3 {
        let id = token_id
            .as_deref()
            .context("Cloudflare returned no token ID, which the S3 credentials need")?;
        env = r2_s3_env(account_id, id, &created.value, &template.r2_buckets);
    }
    env.insert("CLOUDFLARE_API_TOKEN".to_string(), created.value);
    env.insert("CLOUDFLARE_ACCOUNT_ID".to_string(), account_id.to_string());
    Ok(Credentials {
        env,
        expires_at: Some(expires_at),
        issued_at: None,
        token_id,
    })
}

/// A new token reaches some products a few seconds after it is created, and
/// for a while some requests accept it while others still reject it. D1
/// (measured on 2026-10-06: about 3 s, with rejections after the first
/// acceptance) and Workers AI (2026-10-09: rejected at once, accepted after
/// 3 s) do this; Workers, KV, Queues and R2 accept it at once. Waits until
/// `path` accepts it several times in a row, so the first command run with
/// it does not fail.
async fn wait_until_accepted(minted: &Client, path: &str, product: &str) {
    let query = [("per_page", "1".to_string())];
    let mut accepted_in_a_row = 0;
    for _ in 0..D1_WAIT_ATTEMPTS {
        match minted.call::<Value>(Method::GET, path, &query, None).await {
            Ok(_) => {
                accepted_in_a_row += 1;
                if accepted_in_a_row == D1_ACCEPTANCES_NEEDED {
                    return;
                }
            }
            Err(e) => {
                accepted_in_a_row = 0;
                tracing::debug!("{product} does not accept the new token yet: {e:#}");
            }
        }
        tokio::time::sleep(D1_WAIT_INTERVAL).await;
    }
    tracing::warn!(
        "{product} does not reliably accept the new token yet; its commands may fail for a few seconds"
    );
}

const D1_ACCEPTANCES_NEEDED: u32 = 3;
const D1_WAIT_ATTEMPTS: u32 = 60;
const D1_WAIT_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// Deletes tokens omnifob minted that have expired, so they do not pile up
/// in the dashboard: tracked ones, and legacy-named ones. With
/// `forget_missing`, tracked IDs absent from the list are forgotten; not
/// right after minting, when a new token may not be listed yet.
pub async fn prune_expired(
    client: &Client,
    tokens: &str,
    now: Timestamp,
    catalog: &mut Catalog,
    forget_missing: bool,
) -> anyhow::Result<usize> {
    let all: Vec<Token> = client.get_all(tokens).await?;
    let mut deleted = 0;
    for token in &all {
        let ours = catalog.is_tracked(&token.id) || token.name.starts_with(LEGACY_NAME_PREFIX);
        let expired = token.status == "expired" || token.expires_on.is_some_and(|at| at <= now);
        if ours && expired {
            delete_token(client, tokens, &token.id).await?;
            catalog.untrack(&token.id);
            deleted += 1;
        }
    }
    if forget_missing {
        let existing: Vec<&str> = all.iter().map(|t| t.id.as_str()).collect();
        for ids in catalog.minted.values_mut() {
            ids.retain(|id| existing.contains(&id.as_str()));
        }
        catalog.minted.retain(|_, ids| !ids.is_empty());
    }
    Ok(deleted)
}

async fn delete_token(client: &Client, tokens: &str, id: &str) -> anyhow::Result<()> {
    client
        .call::<Value>(Method::DELETE, &format!("{tokens}/{id}"), &[], None)
        .await?;
    Ok(())
}

/// Deletes the tokens omnifob minted for `profile_id` (or for every profile
/// when `None`), live or not; returns how many.
pub async fn revoke_minted(
    client: &Client,
    tokens: &str,
    profile_id: Option<&str>,
    catalog: &mut Catalog,
) -> anyhow::Result<usize> {
    let all: Vec<Token> = client.get_all(tokens).await?;
    let legacy = profile_id.map_or(LEGACY_NAME_PREFIX.to_string(), |p| {
        format!("{LEGACY_NAME_PREFIX}{p}@")
    });
    let tracked: Vec<String> = match profile_id {
        Some(p) => catalog.minted.get(p).cloned().unwrap_or_default(),
        None => catalog.minted.values().flatten().cloned().collect(),
    };
    let mut deleted = 0;
    for token in &all {
        if tracked.contains(&token.id) || token.name.starts_with(&legacy) {
            delete_token(client, tokens, &token.id).await?;
            deleted += 1;
        }
    }
    for id in tracked {
        catalog.untrack(&id);
    }
    Ok(deleted)
}

/// [`revoke_minted`] with the stored bootstrap token and catalog.
pub async fn revoke(
    integration: &str,
    config: &CloudflareConfig,
    profile_id: Option<&str>,
    account_id: &str,
) -> Result<usize> {
    let client = bootstrap_client(integration, config).await?;
    let tokens = Client::tokens_path(config.minting(), account_id);
    let mut catalog = load_catalog(integration);
    let deleted = revoke_minted(&client, &tokens, profile_id, &mut catalog).await;
    save_catalog(integration, &catalog)?;
    Ok(deleted?)
}

/// Deletes one token omnifob minted, for example when the command it was
/// minted for has ended.
pub async fn revoke_token(
    integration: &str,
    config: &CloudflareConfig,
    account_id: &str,
    token_id: &str,
) -> Result<()> {
    let client = bootstrap_client(integration, config).await?;
    let tokens = Client::tokens_path(config.minting(), account_id);
    delete_token(&client, &tokens, token_id).await?;
    let mut catalog = load_catalog(integration);
    catalog.untrack(token_id);
    save_catalog(integration, &catalog)?;
    Ok(())
}

/// Deletes expired tokens omnifob minted in each of the integration's accounts.
pub async fn cleanup(
    integration: &str,
    config: &CloudflareConfig,
    account_ids: &[String],
) -> Result<usize> {
    let client = bootstrap_client(integration, config).await?;
    let mut catalog = load_catalog(integration);
    let mut deleted = 0;
    let mut result = Ok(());
    for account_id in account_ids {
        let tokens = Client::tokens_path(config.minting(), account_id);
        match prune_expired(&client, &tokens, Timestamp::now(), &mut catalog, true).await {
            Ok(n) => deleted += n,
            Err(e) => result = Err(e),
        }
        if config.minting() == CloudflareTokenType::User {
            break; // user tokens are listed once, not per account
        }
    }
    save_catalog(integration, &catalog)?;
    result?;
    Ok(deleted)
}

pub fn console_url(account_id: &str) -> String {
    format!("https://dash.cloudflare.com/{account_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(id: &str, name: &str, scope: &str) -> PermissionGroup {
        PermissionGroup {
            id: id.into(),
            name: name.into(),
            scopes: vec![scope.into()],
        }
    }

    fn groups() -> Vec<PermissionGroup> {
        vec![
            group("w", "Workers Scripts Write", SCOPE_ACCOUNT),
            group("z", "Zone Read", SCOPE_ZONE),
            group("d", "DNS Write", SCOPE_ZONE),
            group("u", "User Details Read", SCOPE_USER),
        ]
    }

    #[test]
    fn resolves_names_case_insensitively() {
        let groups = groups();
        let names = vec!["workers scripts write".to_string(), "Zone Read".to_string()];
        let ids: Vec<_> = resolve_permissions(&names, &groups)
            .unwrap()
            .iter()
            .map(|g| g.id.as_str())
            .collect();
        assert_eq!(ids, ["w", "z"]);
    }

    #[test]
    fn unknown_names_suggest_close_matches() {
        let groups = groups();
        let err = resolve_permissions(&["Workers Script Write".to_string()], &groups).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("'Workers Script Write'"), "{msg}");
        assert!(msg.contains("Workers Scripts Write"), "{msg}");
    }

    #[test]
    fn dashboard_edit_names_mean_write() {
        let groups = groups();
        let names = vec!["Workers Scripts Edit".to_string(), "dns edit".to_string()];
        let ids: Vec<_> = resolve_permissions(&names, &groups)
            .unwrap()
            .iter()
            .map(|g| g.id.as_str())
            .collect();
        assert_eq!(ids, ["w", "d"]);
    }

    #[test]
    fn policies_group_by_scope_and_limit_to_account() {
        let groups = groups();
        let selected: Vec<_> = groups.iter().collect();
        let policies = build_policies(&selected, "acct", Some("tag"), &[]).unwrap();
        assert_eq!(policies.len(), 3);
        let resources: Vec<_> = policies.iter().map(|p| p["resources"].clone()).collect();
        assert!(resources.contains(&json!({ "com.cloudflare.api.account.acct": "*" })));
        assert!(resources.contains(&json!({
            "com.cloudflare.api.account.acct": { "com.cloudflare.api.account.zone.*": "*" }
        })));
        assert!(resources.contains(&json!({ "com.cloudflare.api.user.tag": "*" })));
        let zone = policies
            .iter()
            .find(|p| p["resources"].to_string().contains("zone"))
            .unwrap();
        assert_eq!(zone["permission_groups"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn user_permissions_need_a_user_tag() {
        let groups = groups();
        let user: Vec<_> = groups.iter().filter(|g| g.id == "u").collect();
        assert!(build_policies(&user, "acct", None, &[]).is_err());
    }

    #[test]
    fn finds_user_tag_in_bootstrap_policy() {
        let policies = vec![json!({
            "resources": { "com.cloudflare.api.user.abc123": "*" },
            "permission_groups": []
        })];
        assert_eq!(user_tag_from_policies(&policies).as_deref(), Some("abc123"));
    }

    #[test]
    fn bootstrap_urls() {
        let mut config: CloudflareConfig = match crate::Config::parse(
            "[integrations.c]\ntype = \"cloudflare-token\"\naccount_id = \"abc123\"\ntoken_type = \"account\"\n",
        )
        .unwrap()
        .integrations
        .remove("c")
        .unwrap()
        {
            crate::Integration::Cloudflare(c) => c,
            _ => unreachable!(),
        };
        let url = reqwest::Url::parse(&bootstrap_url(&config)).unwrap();
        let q: BTreeMap<_, _> = url.query_pairs().collect();
        assert_eq!(url.host_str(), Some("dash.cloudflare.com"));
        assert_eq!(q["to"], "/abc123/api-tokens");
        assert_eq!(q["name"], "omnifob bootstrap");
        assert_eq!(
            q["permissionGroupKeys"],
            r#"[{"key":"account_api_tokens","type":"edit"}]"#
        );
        config.token_type = CloudflareTokenType::User;
        assert_eq!(
            bootstrap_url(&config),
            "https://dash.cloudflare.com/profile/api-tokens"
        );
    }

    #[test]
    fn bucket_permissions_need_and_use_buckets() {
        let groups = [group(
            "b",
            "Workers R2 Storage Bucket Item Write",
            SCOPE_R2_BUCKET,
        )];
        let selected: Vec<&PermissionGroup> = groups.iter().collect();
        let err = build_policies(&selected, "acct", None, &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("r2_buckets"), "{err}");
        let policies = build_policies(
            &selected,
            "acct",
            None,
            &["logs".into(), "eu/backups".into()],
        )
        .unwrap();
        let resources = policies[0]["resources"].as_object().unwrap();
        let keys: Vec<&str> = resources.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "com.cloudflare.edge.r2.bucket.acct_default_logs",
                "com.cloudflare.edge.r2.bucket.acct_eu_backups"
            ]
        );
    }

    #[tokio::test]
    async fn ips_become_cidr_ranges() {
        let ips = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            resolve_ips(
                &ips(&["203.0.113.7", "198.51.100.0/24", "2001:db8::1"]),
                API_BASE
            )
            .await
            .unwrap(),
            ["203.0.113.7/32", "198.51.100.0/24", "2001:db8::1/128"]
        );
        assert!(resolve_ips(&ips(&["10.0.0.0/33"]), API_BASE).await.is_err());
        assert!(resolve_ips(&ips(&["example.com"]), API_BASE).await.is_err());
    }

    #[test]
    fn r2_s3_credentials_derive_from_the_token() {
        let env = r2_s3_env("acct", "token-id", "abc", &[]);
        assert_eq!(env["AWS_ACCESS_KEY_ID"], "token-id");
        assert_eq!(
            env["AWS_SECRET_ACCESS_KEY"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            env["AWS_ENDPOINT_URL_S3"],
            "https://acct.r2.cloudflarestorage.com"
        );
        let eu = r2_s3_env("acct", "id", "abc", &["eu/a".into(), "eu/b".into()]);
        assert_eq!(
            eu["AWS_ENDPOINT_URL_S3"],
            "https://acct.eu.r2.cloudflarestorage.com"
        );
    }

    #[test]
    fn services_pair_read_and_write() {
        let groups = vec![
            group("1", "Workers Scripts Read", SCOPE_ACCOUNT),
            group("2", "Workers Scripts Write", SCOPE_ACCOUNT),
            group("3", "DNS Read", SCOPE_ZONE),
            group("4", "Memberships Read", SCOPE_USER),
            group("5", "Cache Purge", SCOPE_ZONE),
        ];
        let all = services(&groups, CloudflareTokenType::User);
        let names: Vec<&str> = all.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            ["Cache Purge", "DNS", "Memberships", "Workers Scripts"]
        );
        let workers = &all[3];
        assert_eq!(workers.read.as_ref().unwrap().id, "1");
        assert_eq!(workers.write.as_ref().unwrap().id, "2");
        assert_eq!(all[0].other.len(), 1);
        assert_eq!(all[1].scope(), "zone");
        let account = services(&groups, CloudflareTokenType::Account);
        assert!(account.iter().all(|s| s.name != "Memberships"));
    }

    #[test]
    fn builtin_templates_exist() {
        let all = builtin_templates();
        assert!(all.contains_key("workers"));
        assert!(all.values().all(|t| !t.permissions.is_empty()));
    }
}
