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

use anyhow::{Context, anyhow, bail};
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

/// Templates available without configuration. A template in the config file
/// with the same name replaces the built-in one.
pub fn builtin_templates() -> BTreeMap<String, CloudflareTemplate> {
    let t = |permissions: &[&str], optional: &[&str]| CloudflareTemplate {
        permissions: permissions.iter().map(|p| p.to_string()).collect(),
        optional: optional.iter().map(|p| p.to_string()).collect(),
        ttl: None,
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
                    "User Details Read",
                    "Memberships Read",
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

fn templates(config: &CloudflareConfig) -> BTreeMap<String, CloudflareTemplate> {
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

/// Builds token policies: one per resource kind the permissions apply to,
/// each limited to the given account (and, for zone permissions, every zone
/// in that account).
pub fn build_policies(
    groups: &[&PermissionGroup],
    account_id: &str,
    user_tag: Option<&str>,
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
                other => bail!("permissions scoped to '{other}' are not supported yet"),
            };
            Ok(json!({ "effect": "allow", "resources": resources, "permission_groups": permission_groups }))
        })
        .collect()
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

fn bootstrap_client(integration: &str) -> Result<Client> {
    let token: String = store::get(&bootstrap_key(integration))?
        .ok_or_else(|| Error::not_signed_in(integration))?;
    Ok(Client::new(api_base(), token))
}

/// Verifies and stores the bootstrap token.
pub async fn login(
    integration: &str,
    config: &CloudflareConfig,
    token: &str,
) -> anyhow::Result<()> {
    if config.token_type == CloudflareTokenType::Account && config.account_id.is_none() {
        bail!("token_type = \"account\" needs account_id in the integration config");
    }
    let client = Client::new(api_base(), token.trim());
    client
        .verify(
            config.token_type,
            config.account_id.as_deref().unwrap_or_default(),
        )
        .await
        .context("the token was rejected")?;
    store::set(&bootstrap_key(integration), &token.trim())
}

pub fn logout(integration: &str) -> anyhow::Result<bool> {
    forget_catalog(integration);
    store::delete(&bootstrap_key(integration))
}

pub fn has_bootstrap_token(integration: &str) -> anyhow::Result<bool> {
    Ok(store::get::<String>(&bootstrap_key(integration))?.is_some())
}

/// One profile per account and template.
pub async fn discover(integration: &str, config: &CloudflareConfig) -> Result<Vec<Profile>> {
    let accounts = match &config.account_id {
        Some(id) => vec![Account {
            id: id.clone(),
            name: config.account_name.clone().unwrap_or_else(|| id.clone()),
        }],
        None => {
            let client = bootstrap_client(integration)?;
            let accounts: Vec<Account> = client.get_all("/accounts").await.context(
                "listing accounts; set account_id in the integration config if the token cannot list them",
            )?;
            if accounts.is_empty() {
                return Err(anyhow!(
                    "the bootstrap token cannot see any account; set account_id in the integration config"
                )
                .into());
            }
            accounts
        }
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
    let client = bootstrap_client(integration)?;
    let mut groups = client
        .permission_groups(
            config.token_type,
            config.account_id.as_deref().unwrap_or_default(),
        )
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
    let client = bootstrap_client(integration)?;
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

/// Moves the stored catalog to a renamed integration.
pub fn rename_catalog(old: &str, new: &str) {
    let _ = std::fs::rename(catalog_file(old), catalog_file(new));
}

/// Removes the stored catalog, for example after signing out.
pub fn forget_catalog(integration: &str) {
    let _ = std::fs::remove_file(catalog_file(integration));
}

/// Picks the template's permissions from the catalog: all required ones,
/// and the optional ones the account offers.
fn select<'a>(
    template: &CloudflareTemplate,
    groups: &'a [PermissionGroup],
) -> anyhow::Result<Vec<&'a PermissionGroup>> {
    let mut selected = resolve_permissions(&template.permissions, groups)?;
    for name in &template.optional {
        match resolve_permissions(std::slice::from_ref(name), groups) {
            Ok(found) => selected.extend(found),
            Err(_) => tracing::debug!("optional permission '{name}' is not offered; skipped"),
        }
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
    let token_type = config.token_type;
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
    let selected = match select(&template, &catalog.groups) {
        Ok(selected) => selected,
        Err(_) if catalog.fetched_at != Some(now) => {
            fetch(
                catalog,
                client.permission_groups(token_type, account_id).await?,
            );
            select(&template, &catalog.groups)?
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
    let policies = build_policies(&selected, account_id, user_tag)?;
    let uses_d1 = selected.iter().any(|g| g.name.starts_with("D1 "));

    let ttl = template.ttl.unwrap_or(config.ttl);
    let now = now.round(Unit::Second)?;
    let expires_at = now.checked_add(ttl)?;
    let body = json!({
        "name": format!("{TOKEN_NAME_PREFIX} {template_name}"),
        "policies": policies,
        "expires_on": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
    });
    let (created, _): (CreatedToken, _) = client
        .call(Method::POST, &tokens, &[], Some(&body))
        .await
        .context("minting a Cloudflare token")?;
    if !created.id.is_empty() {
        catalog.track(profile_id, &created.id);
    }

    // Cleaning up overlaps with waiting for D1 to accept the new token.
    let minted = client.with_token(&created.value);
    let wait = async {
        if uses_d1 {
            wait_for_d1(&minted, account_id).await;
        }
    };
    let (_, pruned) = tokio::join!(wait, prune_expired(client, &tokens, now, catalog, false));
    if let Err(e) = pruned {
        tracing::warn!("could not clean up expired omnifob tokens: {e:#}");
    }

    let env = BTreeMap::from([
        ("CLOUDFLARE_API_TOKEN".to_string(), created.value),
        ("CLOUDFLARE_ACCOUNT_ID".to_string(), account_id.to_string()),
    ]);
    Ok(Credentials {
        env,
        expires_at: Some(expires_at),
        issued_at: None,
    })
}

/// A new token reaches D1 a few seconds after it is created, and for a while
/// some requests accept it while others still reject it (measured on
/// 2026-10-06: about 3 s, with rejections after the first acceptance).
/// Workers, KV, Queues and R2 accept it at once. Waits until D1 accepts it
/// several times in a row, so the first command run with it does not fail.
async fn wait_for_d1(minted: &Client, account_id: &str) {
    let path = format!("/accounts/{account_id}/d1/database");
    let query = [("per_page", "1".to_string())];
    let mut accepted_in_a_row = 0;
    for _ in 0..D1_WAIT_ATTEMPTS {
        match minted.call::<Value>(Method::GET, &path, &query, None).await {
            Ok(_) => {
                accepted_in_a_row += 1;
                if accepted_in_a_row == D1_ACCEPTANCES_NEEDED {
                    return;
                }
            }
            Err(e) => {
                accepted_in_a_row = 0;
                tracing::debug!("D1 does not accept the new token yet: {e:#}");
            }
        }
        tokio::time::sleep(D1_WAIT_INTERVAL).await;
    }
    tracing::warn!(
        "D1 does not reliably accept the new token yet; D1 commands may fail for a few seconds"
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
    let client = bootstrap_client(integration)?;
    let tokens = Client::tokens_path(config.token_type, account_id);
    let mut catalog = load_catalog(integration);
    let deleted = revoke_minted(&client, &tokens, profile_id, &mut catalog).await;
    save_catalog(integration, &catalog)?;
    Ok(deleted?)
}

/// Deletes expired tokens omnifob minted in each of the integration's accounts.
pub async fn cleanup(
    integration: &str,
    config: &CloudflareConfig,
    account_ids: &[String],
) -> Result<usize> {
    let client = bootstrap_client(integration)?;
    let mut catalog = load_catalog(integration);
    let mut deleted = 0;
    let mut result = Ok(());
    for account_id in account_ids {
        let tokens = Client::tokens_path(config.token_type, account_id);
        match prune_expired(&client, &tokens, Timestamp::now(), &mut catalog, true).await {
            Ok(n) => deleted += n,
            Err(e) => result = Err(e),
        }
        if config.token_type == CloudflareTokenType::User {
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
        let policies = build_policies(&selected, "acct", Some("tag")).unwrap();
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
        assert!(build_policies(&user, "acct", None).is_err());
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
    fn builtin_templates_exist() {
        let all = builtin_templates();
        assert!(all.contains_key("workers"));
        assert!(all.values().all(|t| !t.permissions.is_empty()));
    }
}
