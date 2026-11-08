//! An IAM user's access key (`type = "aws-iam"`), handled the way aws-vault
//! handles it.
//!
//! The key lives in the keychain and is never handed out. Profiles get
//! temporary credentials instead: the user's session from STS
//! `GetSessionToken`, with an MFA code when `mfa_serial` is set, and roles
//! assumed with that session. Because the session is the user's own, assuming
//! a role from it is not role chaining, so roles get sessions of up to twelve
//! hours, and a session with MFA satisfies roles that require it. One MFA code
//! therefore covers every role until the session ends.

use anyhow::{Context, anyhow};
use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};

use super::aws_sso::{self, RoleRequest, SESSION_MIN};
use crate::config::AwsIamConfig;
use crate::credentials::EXPIRY_MARGIN;
use crate::{Credentials, Error, Profile, Result, Target, store};

/// STS when no region is configured.
const DEFAULT_STS_REGION: &str = "us-east-1";

/// The user's session unless `session_duration` says otherwise.
const DEFAULT_SESSION: SignedDuration = SignedDuration::from_hours(8);

/// A role's session unless its `duration` says otherwise.
const DEFAULT_ROLE_SESSION: SignedDuration = SignedDuration::from_hours(1);

/// How long to wait for another process that is starting the same session
/// (it may be waiting for an MFA code).
const SESSION_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

#[derive(Serialize, Deserialize)]
struct AccessKey {
    access_key_id: String,
    secret_access_key: String,
}

fn key_key(integration: &str) -> String {
    format!("aws-iam/{integration}/key")
}

fn session_key(integration: &str) -> String {
    format!("aws-iam/{integration}/session")
}

/// Every keychain key an integration uses, for renaming it.
pub fn keys(integration: &str) -> Vec<String> {
    vec![key_key(integration), session_key(integration)]
}

fn sts_region(config: &AwsIamConfig) -> &str {
    config.region.as_deref().unwrap_or(DEFAULT_STS_REGION)
}

fn key_credentials(key: &AccessKey) -> Credentials {
    let mut creds = Credentials::default();
    creds
        .env
        .insert("AWS_ACCESS_KEY_ID".into(), key.access_key_id.clone());
    creds.env.insert(
        "AWS_SECRET_ACCESS_KEY".into(),
        key.secret_access_key.clone(),
    );
    creds
}

fn stored_key(integration: &str) -> Result<AccessKey> {
    store::get::<AccessKey>(&key_key(integration))?.ok_or_else(|| Error::not_signed_in(integration))
}

/// Checks the access key with STS `GetCallerIdentity` and stores it; returns
/// the user's ARN.
pub async fn login(
    integration: &str,
    config: &AwsIamConfig,
    access_key_id: &str,
    secret_access_key: &str,
) -> anyhow::Result<String> {
    let key = AccessKey {
        access_key_id: access_key_id.trim().to_string(),
        secret_access_key: secret_access_key.trim().to_string(),
    };
    if !key.access_key_id.starts_with("AKIA") {
        anyhow::bail!(
            "an IAM user's access key ID starts with AKIA; temporary keys (ASIA) cannot be stored"
        );
    }
    let arn = aws_sso::caller_identity(&key_credentials(&key), sts_region(config))
        .await
        .context("checking the access key")?;
    store::set(&key_key(integration), &key)?;
    // A session from an earlier key must not outlive it.
    store::delete(&session_key(integration))?;
    Ok(arn)
}

pub fn logout(integration: &str) -> anyhow::Result<bool> {
    let session = store::delete(&session_key(integration))?;
    Ok(store::delete(&key_key(integration))? || session)
}

pub fn has_key(integration: &str) -> anyhow::Result<bool> {
    Ok(store::get::<AccessKey>(&key_key(integration))?.is_some())
}

/// Checks that the stored key works; says whom it belongs to.
pub async fn check(integration: &str, config: &AwsIamConfig) -> Result<String> {
    let key = stored_key(integration)?;
    let arn = aws_sso::caller_identity(&key_credentials(&key), sts_region(config)).await?;
    Ok(format!("access key valid for {arn}"))
}

/// The user's session profile and one profile per configured role.
pub async fn discover(integration: &str, config: &AwsIamConfig) -> Result<Vec<Profile>> {
    let key = stored_key(integration)?;
    let arn = aws_sso::caller_identity(&key_credentials(&key), sts_region(config)).await?;
    let account_id = arn
        .split(':')
        .nth(4)
        .filter(|a| !a.is_empty())
        .with_context(|| format!("no account in {arn}"))?
        .to_string();
    let account = config.account.clone().unwrap_or_else(|| account_id.clone());
    let mut profiles = vec![Profile::new(
        integration,
        &account,
        "session",
        Target::AwsIamSession { account_id },
    )];
    for (label, role) in &config.roles {
        profiles.push(Profile::new(
            integration,
            label,
            role.role_name(),
            Target::AwsIamRole {
                label: label.clone(),
                account_id: role.account_id().map(str::to_string),
            },
        ));
    }
    Ok(profiles)
}

/// The user's session: from the keychain while it lasts, else a new one from
/// `GetSessionToken`, asking for an MFA code when `mfa_serial` is set. `ttl`
/// asks for a new session of that length.
///
/// A new session is started under a lock shared by every omnifob process, so
/// parallel commands ask for one MFA code, not one each.
pub async fn session_credentials(
    integration: &str,
    config: &AwsIamConfig,
    profile_id: &str,
    ttl: Option<SignedDuration>,
) -> Result<Credentials> {
    if ttl.is_none()
        && let Some(session) = fresh_session(integration)
    {
        return Ok(session);
    }
    let _lock = store::lock(&format!("aws-iam-{integration}"), SESSION_LOCK_TIMEOUT).await?;
    if ttl.is_none()
        && let Some(session) = fresh_session(integration)
    {
        return Ok(session);
    }

    let duration = ttl.or(config.session_duration).unwrap_or(DEFAULT_SESSION);
    if !(SESSION_MIN..=SignedDuration::from_hours(36)).contains(&duration) {
        return Err(anyhow!("an IAM user's session lasts 15 minutes to 36 hours").into());
    }
    let key = stored_key(integration)?;
    let mut call = aws_sso::sts_client(&key_credentials(&key), sts_region(config))?
        .get_session_token()
        .duration_seconds(duration.as_secs().try_into().map_err(anyhow::Error::from)?);
    if let Some(serial) = &config.mfa_serial {
        call = call
            .serial_number(serial)
            .token_code(crate::prompt::mfa_code(serial, profile_id)?);
    }
    let response = call
        .send()
        .await
        .map_err(|e| anyhow!("{}", aws_sdk_sts::error::DisplayErrorContext(&e)))
        .context("starting a session with the access key")?;
    let session = aws_sso::from_sts(
        response.credentials().context("no credentials returned")?,
        config.region.as_deref(),
    )?;
    let session = Credentials {
        issued_at: Some(Timestamp::now()),
        ..session
    };
    store::set(&session_key(integration), &session)?;
    Ok(session)
}

fn fresh_session(integration: &str) -> Option<Credentials> {
    match store::get::<Credentials>(&session_key(integration)) {
        Ok(Some(session)) if session.is_fresh(Timestamp::now()) => Some(session),
        Ok(_) => None,
        Err(e) => {
            tracing::debug!("ignoring an unreadable session: {e:#}");
            None
        }
    }
}

/// A role assumed with the user's session. `ttl` overrides the role's
/// `duration`.
pub async fn role_credentials(
    integration: &str,
    config: &AwsIamConfig,
    label: &str,
    profile_id: &str,
    ttl: Option<SignedDuration>,
) -> Result<Credentials> {
    let role = config.roles.get(label).with_context(|| {
        format!("no role '{label}' in integration '{integration}'; run `fob sync`")
    })?;
    let duration = ttl.or(role.duration).unwrap_or(DEFAULT_ROLE_SESSION);
    if !(SESSION_MIN..=SignedDuration::from_hours(12)).contains(&duration) {
        return Err(anyhow!("a role's session lasts 15 minutes to 12 hours").into());
    }
    let session = session_credentials(integration, config, profile_id, None).await?;
    // The role's credentials cannot outlive the session they came from.
    let left = session
        .expires_at
        .map(|at| at.duration_since(Timestamp::now()) - EXPIRY_MARGIN);
    let duration = match left {
        Some(left) if left < duration => left.max(SESSION_MIN),
        _ => duration,
    };
    let region = role.region.as_deref().or(config.region.as_deref());
    let request = RoleRequest {
        role_arn: &role.role_arn,
        session_name: role.session_name.as_deref(),
        external_id: role.external_id.as_deref(),
        // The session already carries the MFA.
        mfa_serial: None,
        duration,
        profile_id,
    };
    Ok(aws_sso::assume_role(&session, &request, sts_region(config), region).await?)
}

/// A console sign-in URL for the user. Session credentials cannot sign in to
/// the console, so this asks STS `GetFederationToken` with the access key for
/// a federated session limited to the user's own permissions, as aws-vault
/// does. A user whose policies require MFA cannot sign in this way: use a
/// role instead.
pub async fn console_url(integration: &str, config: &AwsIamConfig) -> Result<String> {
    let key = stored_key(integration)?;
    let duration = config
        .session_duration
        .unwrap_or(DEFAULT_SESSION)
        .min(SignedDuration::from_hours(36));
    // Federated sessions get the intersection of this policy and the user's.
    let allow_all =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
    let response = aws_sso::sts_client(&key_credentials(&key), sts_region(config))?
        .get_federation_token()
        .name("omnifob")
        .policy(allow_all)
        .duration_seconds(duration.as_secs().try_into().map_err(anyhow::Error::from)?)
        .send()
        .await
        .map_err(|e| anyhow!("{}", aws_sdk_sts::error::DisplayErrorContext(&e)))
        .context("getting a federated session for the console")?;
    let creds = aws_sso::from_sts(
        response.credentials().context("no credentials returned")?,
        None,
    )?;
    Ok(aws_sso::console_url(&creds, sts_region(config), config.region.as_deref()).await?)
}
