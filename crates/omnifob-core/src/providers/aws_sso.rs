//! AWS IAM Identity Center.
//!
//! Sign-in uses the OIDC device authorization flow. The resulting token is
//! kept in the keychain per integration and, when Identity Center issued a
//! refresh token, renewed silently shortly before it expires (the approach
//! aws-vault takes). Discovery lists every account and role the token can
//! reach (the approach Leapp takes), and each role becomes a profile.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use aws_sdk_sso::error::DisplayErrorContext;
use aws_sdk_sso::operation::get_role_credentials::GetRoleCredentialsError;
use aws_sdk_sso::operation::list_account_roles::ListAccountRolesError;
use aws_sdk_sso::operation::list_accounts::ListAccountsError;
use aws_sdk_ssooidc::operation::create_token::CreateTokenError;
use futures::StreamExt;
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};

use crate::config::{AwsSsoConfig, ChainedRole};
use crate::{Credentials, Error, Profile, Result, Target, store};

/// A token expiring within this window is refreshed before use. Matches the
/// AWS CLI, so a token is never handed out with seconds left.
const REFRESH_WINDOW: SignedDuration = SignedDuration::from_mins(15);

/// How many accounts to list roles for at once; Identity Center throttles
/// aggressively, which is why Leapp throttles this call too.
const ROLE_LISTING_CONCURRENCY: usize = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SsoToken {
    start_url: String,
    region: String,
    access_token: String,
    expires_at: Timestamp,
    #[serde(default)]
    refresh_token: Option<String>,
    client_id: String,
    client_secret: String,
    client_expires_at: Timestamp,
}

impl SsoToken {
    fn can_refresh(&self, now: Timestamp) -> bool {
        self.refresh_token.is_some() && self.client_expires_at > now
    }
}

fn token_key(integration: &str) -> String {
    format!("aws-sso/{integration}/token")
}

/// What the user must do to approve a device sign-in.
#[derive(Debug, Clone)]
pub struct DevicePrompt {
    /// Opens the approval page with the code already filled in.
    pub url: String,
    pub user_code: String,
}

fn oidc_client(region: &str) -> aws_sdk_ssooidc::Client {
    let config = aws_sdk_ssooidc::Config::builder()
        .region(aws_sdk_ssooidc::config::Region::new(region.to_string()))
        .behavior_version(aws_sdk_ssooidc::config::BehaviorVersion::latest())
        .build();
    aws_sdk_ssooidc::Client::from_conf(config)
}

fn portal_client(region: &str) -> aws_sdk_sso::Client {
    let config = aws_sdk_sso::Config::builder()
        .region(aws_sdk_sso::config::Region::new(region.to_string()))
        .behavior_version(aws_sdk_sso::config::BehaviorVersion::latest())
        .build();
    aws_sdk_sso::Client::from_conf(config)
}

fn after_secs(now: Timestamp, secs: i64) -> Timestamp {
    now.saturating_add(SignedDuration::from_secs(secs))
        .unwrap_or(Timestamp::MAX)
}

/// Signs in with the device flow. `prompt` is called once with the URL and
/// code to show the user; the call then waits until they approve it.
pub async fn login(
    integration: &str,
    config: &AwsSsoConfig,
    prompt: impl FnOnce(&DevicePrompt),
) -> anyhow::Result<()> {
    let oidc = oidc_client(&config.region);
    let now = Timestamp::now();

    // Reuse the client registration from an earlier sign-in while it is valid.
    let previous: Option<SsoToken> = store::get(&token_key(integration)).unwrap_or(None);
    let (client_id, client_secret, client_expires_at) = match previous {
        Some(t) if t.client_expires_at > now && t.start_url == config.start_url => {
            (t.client_id, t.client_secret, t.client_expires_at)
        }
        _ => {
            let client = oidc
                .register_client()
                .client_name("omnifob")
                .client_type("public")
                .set_scopes(Some(config.scopes.clone()))
                .send()
                .await
                .map_err(|e| {
                    anyhow!(
                        "registering with IAM Identity Center: {}",
                        DisplayErrorContext(&e)
                    )
                })?;
            (
                client
                    .client_id()
                    .context("no client id returned")?
                    .to_string(),
                client
                    .client_secret()
                    .context("no client secret returned")?
                    .to_string(),
                Timestamp::from_second(client.client_secret_expires_at())?,
            )
        }
    };

    let device = oidc
        .start_device_authorization()
        .client_id(&client_id)
        .client_secret(&client_secret)
        .start_url(&config.start_url)
        .send()
        .await
        .map_err(|e| anyhow!("starting device sign-in: {}", DisplayErrorContext(&e)))?;
    let device_code = device.device_code().context("no device code returned")?;
    prompt(&DevicePrompt {
        url: device
            .verification_uri_complete()
            .or(device.verification_uri())
            .context("no verification URL returned")?
            .to_string(),
        user_code: device.user_code().unwrap_or_default().to_string(),
    });

    let deadline = after_secs(Timestamp::now(), device.expires_in().into());
    let mut interval = Duration::from_secs(device.interval().max(1) as u64);
    let token = loop {
        tokio::time::sleep(interval).await;
        let result = oidc
            .create_token()
            .client_id(&client_id)
            .client_secret(&client_secret)
            .grant_type("urn:ietf:params:oauth:grant-type:device_code")
            .device_code(device_code)
            .send()
            .await;
        match result {
            Ok(token) => break token,
            Err(e) => match e.as_service_error() {
                Some(CreateTokenError::AuthorizationPendingException(_)) => {}
                Some(CreateTokenError::SlowDownException(_)) => interval += Duration::from_secs(5),
                _ => bail!("waiting for sign-in approval: {}", DisplayErrorContext(&e)),
            },
        }
        if Timestamp::now() > deadline {
            bail!("sign-in was not approved before the code expired");
        }
    };

    let now = Timestamp::now();
    store::set(
        &token_key(integration),
        &SsoToken {
            start_url: config.start_url.clone(),
            region: config.region.clone(),
            access_token: token
                .access_token()
                .context("no access token returned")?
                .to_string(),
            expires_at: after_secs(now, token.expires_in().into()),
            refresh_token: token.refresh_token().map(str::to_string),
            client_id,
            client_secret,
            client_expires_at,
        },
    )
}

pub fn logout(integration: &str) -> anyhow::Result<bool> {
    store::delete(&token_key(integration))
}

/// When the stored session expires and whether it can renew itself.
pub fn session(integration: &str) -> anyhow::Result<Option<(Timestamp, bool)>> {
    let now = Timestamp::now();
    Ok(store::get::<SsoToken>(&token_key(integration))?.map(|t| {
        let refreshable = t.can_refresh(now);
        (t.expires_at, refreshable)
    }))
}

/// Returns a usable access token, refreshing it when it is about to expire.
async fn access_token(integration: &str, config: &AwsSsoConfig) -> Result<String> {
    let needs_login = || Error::NeedsLogin {
        integration: integration.to_string(),
    };
    let Some(token) = store::get::<SsoToken>(&token_key(integration))? else {
        return Err(needs_login());
    };
    if token.start_url != config.start_url || token.region != config.region {
        return Err(needs_login());
    }

    let now = Timestamp::now();
    let expires_soon =
        token.expires_at < now.saturating_add(REFRESH_WINDOW).unwrap_or(Timestamp::MAX);
    if !expires_soon {
        return Ok(token.access_token);
    }
    if token.can_refresh(now) {
        match refresh(&token).await {
            Ok(refreshed) => {
                store::set(&token_key(integration), &refreshed)?;
                return Ok(refreshed.access_token);
            }
            // A refresh token is single use; another process may already have
            // used it. Keep the stored entry and fall through.
            Err(e) => tracing::debug!("refreshing the IAM Identity Center token failed: {e:#}"),
        }
    }
    if token.expires_at > now {
        Ok(token.access_token)
    } else {
        Err(needs_login())
    }
}

async fn refresh(token: &SsoToken) -> anyhow::Result<SsoToken> {
    let refreshed = oidc_client(&token.region)
        .create_token()
        .client_id(&token.client_id)
        .client_secret(&token.client_secret)
        .grant_type("refresh_token")
        .refresh_token(token.refresh_token.as_deref().unwrap_or_default())
        .send()
        .await
        .map_err(|e| anyhow!("{}", DisplayErrorContext(&e)))?;
    Ok(SsoToken {
        access_token: refreshed
            .access_token()
            .context("no access token returned")?
            .to_string(),
        expires_at: after_secs(Timestamp::now(), refreshed.expires_in().into()),
        refresh_token: refreshed
            .refresh_token()
            .map(str::to_string)
            .or_else(|| token.refresh_token.clone()),
        ..token.clone()
    })
}

/// A 401 from the portal means the token was revoked or the portal session
/// ended: drop it so the next attempt signs in again.
fn unauthorized(integration: &str) -> Error {
    let _ = store::delete(&token_key(integration));
    Error::NeedsLogin {
        integration: integration.to_string(),
    }
}

/// Lists every account and role reachable through this integration.
pub async fn discover(integration: &str, config: &AwsSsoConfig) -> Result<Vec<Profile>> {
    let token = access_token(integration, config).await?;
    let portal = portal_client(&config.region);

    let accounts: Vec<_> = match portal
        .list_accounts()
        .access_token(&token)
        .into_paginator()
        .items()
        .send()
        .try_collect()
        .await
    {
        Ok(accounts) => accounts,
        Err(e)
            if matches!(
                e.as_service_error(),
                Some(ListAccountsError::UnauthorizedException(_))
            ) =>
        {
            return Err(unauthorized(integration));
        }
        Err(e) => return Err(anyhow!("listing accounts: {}", DisplayErrorContext(&e)).into()),
    };

    let per_account = futures::stream::iter(accounts.iter().map(|account| {
        let portal = portal.clone();
        let token = token.clone();
        async move {
            let account_id = account.account_id().unwrap_or_default();
            let roles: Vec<_> = portal
                .list_account_roles()
                .access_token(&token)
                .account_id(account_id)
                .into_paginator()
                .items()
                .send()
                .try_collect()
                .await?;
            Ok::<_, aws_sdk_sso::error::SdkError<ListAccountRolesError, _>>((account, roles))
        }
    }))
    .buffer_unordered(ROLE_LISTING_CONCURRENCY)
    .collect::<Vec<_>>()
    .await;

    let mut profiles = Vec::new();
    for result in per_account {
        let (account, roles) = match result {
            Ok(found) => found,
            Err(e)
                if matches!(
                    e.as_service_error(),
                    Some(ListAccountRolesError::UnauthorizedException(_))
                ) =>
            {
                return Err(unauthorized(integration));
            }
            Err(e) => return Err(anyhow!("listing roles: {}", DisplayErrorContext(&e)).into()),
        };
        let account_id = account.account_id().unwrap_or_default();
        let account_name = account.account_name().unwrap_or(account_id);
        for role in roles {
            let role_name = role.role_name().unwrap_or_default();
            profiles.push(Profile::new(
                integration,
                account_name,
                role_name,
                Target::Aws {
                    account_id: account_id.to_string(),
                    account_name: account_name.to_string(),
                    role_name: role_name.to_string(),
                },
            ));
        }
    }
    profiles.sort_by(|a, b| a.id.cmp(&b.id));
    disambiguate(&mut profiles);
    add_chained(integration, config, &mut profiles);
    Ok(profiles)
}

/// Two accounts whose names slug the same would collide; suffix their ids
/// with the account id.
fn disambiguate(profiles: &mut [Profile]) {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for p in profiles.iter() {
        *seen.entry(p.id.clone()).or_default() += 1;
    }
    for p in profiles.iter_mut() {
        if seen[&p.id] > 1
            && let Target::Aws {
                account_id,
                account_name,
                role_name,
            } = &p.target
        {
            p.id = format!(
                "{}/{}-{account_id}/{role_name}",
                p.integration,
                crate::profile::slug(account_name)
            );
        }
    }
}

/// Exchanges the SSO token for role credentials.
pub async fn credentials(
    integration: &str,
    config: &AwsSsoConfig,
    account_id: &str,
    role_name: &str,
) -> Result<Credentials> {
    let token = access_token(integration, config).await?;
    let response = match portal_client(&config.region)
        .get_role_credentials()
        .access_token(token)
        .account_id(account_id)
        .role_name(role_name)
        .send()
        .await
    {
        Ok(response) => response,
        Err(e)
            if matches!(
                e.as_service_error(),
                Some(GetRoleCredentialsError::UnauthorizedException(_))
            ) =>
        {
            return Err(unauthorized(integration));
        }
        Err(e) => {
            return Err(anyhow!(
                "getting credentials for {role_name} in {account_id}: {}",
                DisplayErrorContext(&e)
            )
            .into());
        }
    };
    let creds = response
        .role_credentials()
        .context("no role credentials returned")?;
    let expires_at = Timestamp::from_millisecond(creds.expiration()).context("invalid expiry")?;

    let mut env = BTreeMap::new();
    let mut put = |k: &str, v: &str| {
        env.insert(k.to_string(), v.to_string());
    };
    put(
        "AWS_ACCESS_KEY_ID",
        creds.access_key_id().unwrap_or_default(),
    );
    put(
        "AWS_SECRET_ACCESS_KEY",
        creds.secret_access_key().unwrap_or_default(),
    );
    put(
        "AWS_SESSION_TOKEN",
        creds.session_token().unwrap_or_default(),
    );
    put("AWS_CREDENTIAL_EXPIRATION", &expires_at.to_string());
    if let Some(region) = &config.default_region {
        put("AWS_REGION", region);
        put("AWS_DEFAULT_REGION", region);
    }
    Ok(Credentials {
        env,
        expires_at: Some(expires_at),
        issued_at: None,
    })
}

/// Adds a profile per chained role, `<integration>/<label>/<role name>`. A
/// label that collides with a discovered profile gets a `-chained` suffix.
fn add_chained(integration: &str, config: &AwsSsoConfig, profiles: &mut Vec<Profile>) {
    for (label, role) in &config.chained {
        let target = Target::AwsChained {
            label: label.clone(),
        };
        let mut profile = Profile::new(integration, label, role.role_name(), target.clone());
        if profiles.iter().any(|p| p.id == profile.id) {
            profile = Profile::new(
                integration,
                &format!("{label}-chained"),
                role.role_name(),
                target,
            );
        }
        profiles.push(profile);
    }
}

/// Credentials for a chained role: the Identity Center role's credentials,
/// then STS AssumeRole. AWS limits chained sessions to one hour.
pub async fn chained_credentials(
    integration: &str,
    config: &AwsSsoConfig,
    label: &str,
) -> Result<Credentials> {
    let role = config.chained.get(label).with_context(|| {
        format!("no chained role '{label}' in integration '{integration}'; run `fob sync`")
    })?;
    let source = credentials(integration, config, &role.via_account_id, &role.via_role).await?;
    let region = role
        .region
        .as_deref()
        .or(config.default_region.as_deref())
        .unwrap_or(&config.region);
    Ok(assume_role(&source, role, region).await?)
}

async fn assume_role(
    source: &Credentials,
    role: &ChainedRole,
    region: &str,
) -> anyhow::Result<Credentials> {
    let get = |k: &str| {
        source
            .env
            .get(k)
            .cloned()
            .with_context(|| format!("{k} missing from the source credentials"))
    };
    let provider = aws_sdk_sts::config::Credentials::new(
        get("AWS_ACCESS_KEY_ID")?,
        get("AWS_SECRET_ACCESS_KEY")?,
        Some(get("AWS_SESSION_TOKEN")?),
        None,
        "omnifob",
    );
    let sts = aws_sdk_sts::Client::from_conf(
        aws_sdk_sts::Config::builder()
            .region(aws_sdk_sts::config::Region::new(region.to_string()))
            .credentials_provider(provider)
            .behavior_version(aws_sdk_sts::config::BehaviorVersion::latest())
            .build(),
    );
    let assumed = sts
        .assume_role()
        .role_arn(&role.role_arn)
        .role_session_name(role.session_name.as_deref().unwrap_or("omnifob"))
        .set_external_id(role.external_id.clone())
        .duration_seconds(3600)
        .send()
        .await
        .map_err(|e| {
            anyhow!(
                "assuming {}: {}",
                role.role_arn,
                aws_sdk_sts::error::DisplayErrorContext(&e)
            )
        })?;
    let creds = assumed.credentials().context("no credentials returned")?;
    let expires_at = Timestamp::from_second(creds.expiration().secs())?;

    let mut env = BTreeMap::new();
    let mut put = |k: &str, v: &str| {
        env.insert(k.to_string(), v.to_string());
    };
    put("AWS_ACCESS_KEY_ID", creds.access_key_id());
    put("AWS_SECRET_ACCESS_KEY", creds.secret_access_key());
    put("AWS_SESSION_TOKEN", creds.session_token());
    put("AWS_CREDENTIAL_EXPIRATION", &expires_at.to_string());
    put("AWS_REGION", region);
    put("AWS_DEFAULT_REGION", region);
    Ok(Credentials {
        env,
        expires_at: Some(expires_at),
        issued_at: None,
    })
}

#[derive(Serialize)]
struct FederationSession<'a> {
    #[serde(rename = "sessionId")]
    session_id: &'a str,
    #[serde(rename = "sessionKey")]
    session_key: &'a str,
    #[serde(rename = "sessionToken")]
    session_token: &'a str,
}

/// Builds a sign-in URL for the AWS console using the federation endpoint.
pub async fn console_url(creds: &Credentials, region: Option<&str>) -> anyhow::Result<String> {
    let get = |k: &str| {
        creds
            .env
            .get(k)
            .map(String::as_str)
            .with_context(|| format!("{k} missing"))
    };
    let session = serde_json::to_string(&FederationSession {
        session_id: get("AWS_ACCESS_KEY_ID")?,
        session_key: get("AWS_SECRET_ACCESS_KEY")?,
        session_token: get("AWS_SESSION_TOKEN")?,
    })?;

    #[derive(Deserialize)]
    struct SigninToken {
        #[serde(rename = "SigninToken")]
        signin_token: String,
    }
    let endpoint = "https://signin.aws.amazon.com/federation";
    let token: SigninToken = reqwest::Client::new()
        .get(endpoint)
        .query(&[("Action", "getSigninToken"), ("Session", session.as_str())])
        .send()
        .await?
        .error_for_status()
        .context("requesting a console sign-in token")?
        .json()
        .await?;

    let destination = match region {
        Some(r) => format!("https://{r}.console.aws.amazon.com/console/home?region={r}"),
        None => "https://console.aws.amazon.com/".to_string(),
    };
    let url = reqwest::Url::parse_with_params(
        endpoint,
        &[
            ("Action", "login"),
            ("Issuer", "omnifob"),
            ("Destination", destination.as_str()),
            ("SigninToken", token.signin_token.as_str()),
        ],
    )?;
    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(account_name: &str, account_id: &str) -> Profile {
        Profile::new(
            "acme",
            account_name,
            "Admin",
            Target::Aws {
                account_id: account_id.into(),
                account_name: account_name.into(),
                role_name: "Admin".into(),
            },
        )
    }

    #[test]
    fn chained_roles_become_profiles() {
        let config = match crate::Config::parse(
            r#"
            [integrations.acme]
            type = "aws-sso"
            start_url = "https://acme.awsapps.com/start"
            region = "eu-west-1"
            [integrations.acme.chained.prod]
            via_account_id = "111"
            via_role = "Admin"
            role_arn = "arn:aws:iam::222222222222:role/path/Deploy"
            [integrations.acme.chained.Shared]
            via_account_id = "111"
            via_role = "Admin"
            role_arn = "arn:aws:iam::333333333333:role/Admin"
            "#,
        )
        .unwrap()
        .integrations
        .remove("acme")
        .unwrap()
        {
            crate::Integration::AwsSso(c) => c,
            _ => unreachable!(),
        };
        assert_eq!(config.chained["prod"].account_id(), Some("222222222222"));
        let mut profiles = vec![role("shared", "111")];
        add_chained("acme", &config, &mut profiles);
        let ids: Vec<_> = profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "acme/shared/Admin",
                "acme/shared-chained/Admin",
                "acme/prod/Deploy"
            ]
        );
    }

    #[test]
    fn colliding_account_names_get_account_id_suffix() {
        let mut profiles = vec![role("Prod", "111"), role("prod", "222"), role("Dev", "333")];
        disambiguate(&mut profiles);
        let ids: Vec<_> = profiles.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "acme/prod-111/Admin",
                "acme/prod-222/Admin",
                "acme/dev/Admin"
            ]
        );
    }
}
