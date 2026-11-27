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

mod catalog;
mod client;
pub mod oauth;
mod policies;

pub use self::catalog::*;
pub use self::client::*;
pub use self::policies::*;

use std::collections::BTreeMap;

use anyhow::{Context, bail};
use jiff::{Timestamp, Unit};
use reqwest::Method;
use serde_json::{Value, json};

use crate::config::{CloudflareConfig, CloudflareTemplate, CloudflareTokenType};
use crate::{Credentials, Error, Profile, Result, Target, store};

/// Minted tokens are named with this prefix so expired ones can be cleaned up
/// without touching tokens omnifob did not create.
/// Minted tokens are named `omnifob <template>`. The IDs of minted tokens are
/// tracked in the catalog, so cleanup and revocation never rely on names.
const TOKEN_NAME_PREFIX: &str = "omnifob";

/// A minted token's name: `omnifob <template>`, or `omnifob-agent
/// <template>` for a coding agent, so the dashboard and the audit log tell
/// them apart.
fn token_name(template: &str) -> String {
    if crate::Context::current().agent().is_some() {
        format!("{TOKEN_NAME_PREFIX}-agent {template}")
    } else {
        format!("{TOKEN_NAME_PREFIX} {template}")
    }
}

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

/// The S3-compatible credentials R2 derives from an API token: the token ID
/// is the access key, the SHA-256 of the token the secret.
fn r2_s3_env(
    account_id: &str,
    token_id: &str,
    token: &str,
    r2_buckets: &[String],
) -> BTreeMap<String, String> {
    let secret: String = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, token.as_bytes())
        .as_ref()
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

/// A client authenticated with what mints tokens: the bootstrap token, or
/// for `cloudflare-oauth` the browser sign-in's access token.
async fn bootstrap_client(integration: &str, config: &CloudflareConfig) -> Result<Client> {
    if config.uses_oauth() {
        return Client::for_sign_in(api_base(), integration, config).await;
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
    let replaced = load_catalog(integration).bootstrap.filter(|b| b.id != id);
    let tokens = Client::tokens_path(config.minting(), account_id);
    let expires_at = match config.session {
        Some(session) => Some(start_session(&client, &tokens, &id, session, None).await?),
        None => None,
    };
    store::set(&bootstrap_key(integration), &token.trim())?;
    update_catalog(integration, |c| {
        c.bootstrap = Some(Bootstrap { id, expires_at });
        // Another token may belong to another user, with other groups.
        if replaced.is_some() {
            c.user_tag = None;
            c.permission_groups.clear();
        }
    })?;
    // Only once the new token is stored, and only a session's bootstrap: a
    // token without a session is the user's own, made in the dashboard,
    // and may be needed elsewhere.
    if let Some(Bootstrap {
        id: previous,
        expires_at: Some(_),
    }) = replaced
    {
        match delete_token(&client, &tokens, &previous).await {
            Ok(()) => tracing::debug!("deleted the previous session's bootstrap token"),
            Err(e) => tracing::debug!("previous bootstrap token not deleted: {e:#}"),
        }
    }
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
        return Ok(oauth::revoke(integration, config).await?);
    }
    let Some(Bootstrap {
        id,
        expires_at: Some(expires_at),
    }) = load_catalog(integration).bootstrap
    else {
        return Ok(false);
    };
    // An expired session's token can no longer sign the call, and Cloudflare
    // has ended it already.
    if expires_at <= Timestamp::now() {
        return Ok(false);
    }
    let client = bootstrap_client(integration, config).await?;
    let tokens = Client::tokens_path(
        config.minting(),
        config.account_id.as_deref().unwrap_or_default(),
    );
    delete_token(&client, &tokens, &id).await?;
    Ok(true)
}

pub fn logout(integration: &str) -> anyhow::Result<bool> {
    // Keep the IDs of minted tokens that could not be deleted, so a later
    // sign-in still recognises them (and deletes them once expired); drop
    // the rest, including the bootstrap's record.
    {
        let _lock = lock_catalog(integration)?;
        // An unreadable catalog is left as it is: it may hold IDs of tokens
        // that still exist.
        let minted = match read_catalog(integration) {
            Ok(catalog) => catalog.minted,
            Err(e) => {
                tracing::warn!("keeping the Cloudflare catalog as it is: {e:#}");
                return finish_logout(integration);
            }
        };
        let kept = !minted.is_empty()
            && save_catalog(
                integration,
                &Catalog {
                    minted,
                    ..Catalog::default()
                },
            )
            .inspect_err(|e| tracing::warn!("could not keep the IDs of undeleted tokens: {e:#}"))
            .is_ok();
        if !kept {
            forget_catalog(integration);
        }
    }
    finish_logout(integration)
}

/// Deletes the stored sign-in, browser or bootstrap token.
fn finish_logout(integration: &str) -> anyhow::Result<bool> {
    let oauth = oauth::logout(integration)?;
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
    // Two accounts named "Acme (EU)" and "ACME EU" both slug to acme-eu.
    crate::profile::disambiguate_accounts(&mut profiles, |target| match target {
        Target::Cloudflare {
            account_id,
            account_name,
            ..
        } => Some((account_name, account_id)),
        _ => None,
    });
    Ok(profiles)
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
    let before = load_catalog(integration);
    let mut catalog = before.clone();
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
    if let Err(e) = save_changes(integration, &before, &catalog) {
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
    use oauth::{granted_scopes, scope_for};
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

    let key = groups_key(token_type, account_id);
    let fetch = |catalog: &mut Catalog, groups: Vec<PermissionGroup>| {
        catalog.permission_groups.insert(
            key.clone(),
            Groups {
                fetched_at: now,
                groups,
            },
        );
    };
    let fetched_now =
        |catalog: &Catalog| catalog.permission_groups.get(&key).map(|g| g.fetched_at) == Some(now);
    if !catalog.is_current(&key, now) {
        fetch(
            catalog,
            client.permission_groups(token_type, account_id).await?,
        );
    }
    // A name missing from a stored catalog may be a product added since.
    let selected = match select(
        &template,
        groups_in(&catalog.permission_groups, &key),
        token_type,
    ) {
        Ok(selected) => selected,
        Err(_) if !fetched_now(catalog) => {
            fetch(
                catalog,
                client.permission_groups(token_type, account_id).await?,
            );
            select(
                &template,
                groups_in(&catalog.permission_groups, &key),
                token_type,
            )?
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
    let zone_ids = if template.zones.is_empty() {
        Vec::new()
    } else {
        if !selected
            .iter()
            .any(|g| g.scopes.iter().any(|s| s == SCOPE_ZONE))
        {
            tracing::warn!(
                "template '{template_name}' lists zones but has no zone permission for them to apply to"
            );
        }
        zone_ids(client, account_id, &template.zones).await?
    };
    let policies = build_policies(
        &selected,
        account_id,
        user_tag,
        &template.r2_buckets,
        &zone_ids,
    )?;
    let ips = resolve_ips(template.ips.as_ref().unwrap_or(&config.ips), &client.base).await?;
    let uses_d1 = selected.iter().any(|g| g.name.starts_with("D1 "));
    let uses_ai = selected.iter().any(|g| g.name.starts_with("Workers AI "));

    let ttl = template.ttl.unwrap_or(config.ttl);
    let now = now.round(Unit::Second)?;
    let expires_at = now.checked_add(ttl)?;
    let mut body = json!({
        "name": token_name(template_name),
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

    // Cleaning up overlaps with waiting for products to accept the new token.
    let minted = client.with_token(&created.value);
    // D1 and Workers AI each take a few seconds, waited for side by side.
    let wait = async {
        let d1 = async {
            if uses_d1 {
                let path = format!("/accounts/{account_id}/d1/database");
                wait_until_accepted(&minted, &path, "D1").await;
            }
        };
        let ai = async {
            if uses_ai {
                let path = format!("/accounts/{account_id}/ai/models/search");
                wait_until_accepted(&minted, &path, "Workers AI").await;
            }
        };
        tokio::join!(d1, ai);
    };
    // Tracked IDs missing from this listing are kept: a new token may not be
    // listed yet, and other accounts' tokens are listed elsewhere.
    let (_, pruned) = tokio::join!(wait, prune_expired(client, &tokens, now, catalog));
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

/// The IDs of a template's `zones`: IDs as written, and domain names looked
/// up in the account with `GET /zones?name=`, which the sign-in can answer
/// only for zones it may read.
async fn zone_ids(
    client: &Client,
    account_id: &str,
    zones: &[String],
) -> anyhow::Result<Vec<String>> {
    #[derive(serde::Deserialize)]
    struct Zone {
        id: String,
    }
    let mut ids = Vec::new();
    for zone in zones {
        if is_zone_id(zone) {
            ids.push(zone.to_ascii_lowercase());
            continue;
        }
        let query = [
            ("name", zone.to_lowercase()),
            ("account.id", account_id.to_string()),
        ];
        let (found, _): (Vec<Zone>, _) = client
            .call(Method::GET, "/zones", &query, None)
            .await
            .with_context(|| format!("looking up the zone '{zone}'"))?;
        match found.as_slice() {
            [one] => ids.push(one.id.clone()),
            [] => bail!(
                "no zone named '{zone}' in account {account_id} that this sign-in can read; give \
                 the bootstrap token \"Zone Read\" on it, or write the zone's ID in `zones`"
            ),
            _ => bail!("several zones are named '{zone}'; write the zone's ID in `zones`"),
        }
    }
    ids.sort();
    ids.dedup();
    Ok(ids)
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
/// in the dashboard: tracked ones, and legacy-named ones. Returns how many,
/// and the IDs of every token listed, for [`Catalog::forget_missing`].
pub async fn prune_expired(
    client: &Client,
    tokens: &str,
    now: Timestamp,
    catalog: &mut Catalog,
) -> anyhow::Result<(usize, Vec<String>)> {
    let all: Vec<Token> = client.get_all(tokens).await?;
    let mut deleted = 0;
    // One token that cannot be deleted (gone already, or refused) does not
    // keep the others; it stays tracked for the next cleanup.
    for token in &all {
        let ours = catalog.is_tracked(&token.id) || token.name.starts_with(LEGACY_NAME_PREFIX);
        let expired = token.status == "expired" || token.expires_on.is_some_and(|at| at <= now);
        if ours && expired {
            match delete_token(client, tokens, &token.id).await {
                Ok(()) => {
                    catalog.untrack(&token.id);
                    deleted += 1;
                }
                Err(e) => tracing::debug!("expired token {} not deleted: {e:#}", token.id),
            }
        }
    }
    Ok((deleted, all.into_iter().map(|t| t.id).collect()))
}

async fn delete_token(client: &Client, tokens: &str, id: &str) -> anyhow::Result<()> {
    client
        .call::<Value>(Method::DELETE, &format!("{tokens}/{id}"), &[], None)
        .await?;
    Ok(())
}

/// Deletes the tokens omnifob minted for `profile_id` (or for every profile
/// when `None`), live or not; returns how many. A failed delete does not stop
/// the others; the first error is returned at the end, and the IDs of the
/// tokens that could not be deleted stay tracked.
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
    let mut deleted = Vec::new();
    let mut failed = Vec::new();
    let mut result = Ok(());
    for token in &all {
        if tracked.contains(&token.id) || token.name.starts_with(&legacy) {
            match delete_token(client, tokens, &token.id).await {
                Ok(()) => deleted.push(token.id.clone()),
                Err(e) => {
                    failed.push(token.id.clone());
                    if result.is_ok() {
                        result = Err(e);
                    }
                }
            }
        }
    }
    // A profile's tokens all live in this listing, so its IDs can all go,
    // gone already or not. Without a profile the listing may cover one of
    // several accounts: forget only what it held, so the other accounts'
    // tokens are still recognised when their listings come.
    let forget = if profile_id.is_some() {
        tracked
    } else {
        deleted.clone()
    };
    for id in forget.iter().filter(|id| !failed.contains(id)) {
        catalog.untrack(id);
    }
    result?;
    Ok(deleted.len())
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
    let before = load_catalog(integration);
    let mut catalog = before.clone();
    let deleted = revoke_minted(&client, &tokens, profile_id, &mut catalog).await;
    save_changes(integration, &before, &catalog)?;
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
    update_catalog(integration, |c| c.untrack(token_id))?;
    Ok(())
}

/// Deletes expired tokens omnifob minted in each of the integration's accounts.
pub async fn cleanup(
    integration: &str,
    config: &CloudflareConfig,
    account_ids: &[String],
) -> Result<usize> {
    let client = bootstrap_client(integration, config).await?;
    let before = load_catalog(integration);
    let mut catalog = before.clone();
    let mut deleted = 0;
    let mut listed = Vec::new();
    let mut result = Ok(());
    for account_id in account_ids {
        let tokens = Client::tokens_path(config.minting(), account_id);
        match prune_expired(&client, &tokens, Timestamp::now(), &mut catalog).await {
            Ok((n, ids)) => {
                deleted += n;
                listed.extend(ids);
            }
            Err(e) => result = Err(e),
        }
        if config.minting() == CloudflareTokenType::User {
            break; // user tokens are listed once, not per account
        }
    }
    // Only once every account was listed: an ID missing from one account's
    // listing may belong to another account.
    if result.is_ok() {
        catalog.forget_missing(&listed);
    }
    save_changes(integration, &before, &catalog)?;
    result?;
    Ok(deleted)
}

pub fn console_url(account_id: &str) -> String {
    format!("https://dash.cloudflare.com/{account_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn builtin_templates_exist() {
        let all = builtin_templates();
        assert!(all.contains_key("workers"));
        assert!(all.values().all(|t| !t.permissions.is_empty()));
    }
}
