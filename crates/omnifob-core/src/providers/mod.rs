//! Provider dispatch: each integration kind implements sign-in, discovery,
//! credentials and a console link.

pub mod aws_iam;
pub mod aws_partition;
pub mod aws_sso;
pub mod azure;
pub mod cloudflare;
pub mod cloudflare_oauth;
pub mod gcp;
pub mod token;

use anyhow::Context;
use jiff::Timestamp;

use self::aws_partition::Partition;
use crate::{Config, Credentials, Error, Integration, Profile, Result, Target, store};

/// Discovers every profile an integration offers.
pub async fn discover(name: &str, integration: &Integration) -> Result<Vec<Profile>> {
    match integration {
        Integration::AwsSso(config) => aws_sso::discover(name, config).await,
        Integration::AwsIam(config) => aws_iam::discover(name, config).await,
        Integration::Gcp(config) => gcp::discover(name, config).await,
        Integration::Azure(config) => azure::discover(name, config).await,
        Integration::Cloudflare(config) => {
            let profiles = cloudflare::discover(name, config).await?;
            // A good moment to delete expired tokens omnifob minted.
            let mut accounts: Vec<String> = profiles
                .iter()
                .filter_map(|p| match &p.target {
                    Target::Cloudflare { account_id, .. } => Some(account_id.clone()),
                    _ => None,
                })
                .collect();
            accounts.dedup();
            match cloudflare::cleanup(name, config, &accounts).await {
                Ok(_) | Err(Error::NeedsLogin { .. }) => {}
                Err(e) => tracing::warn!("could not clean up expired omnifob tokens: {e}"),
            }
            Ok(profiles)
        }
        Integration::Token(config) => Ok(token::discover(name, config)),
    }
}

/// Deletes every token omnifob minted through a Cloudflare integration, in
/// the given accounts; returns how many. Called before signing out. An
/// account that fails does not stop the others; the first error is returned
/// once every account has been tried.
pub async fn revoke_all(
    name: &str,
    integration: &Integration,
    account_ids: &[String],
) -> Result<usize> {
    let Integration::Cloudflare(config) = integration else {
        return Ok(0);
    };
    let mut deleted = 0;
    let mut result = Ok(());
    for account_id in account_ids {
        match cloudflare::revoke(name, config, None, account_id).await {
            Ok(n) => deleted += n,
            Err(e) => {
                // Without a sign-in no other account can be reached either.
                let stop = matches!(e, Error::NeedsLogin { .. });
                if result.is_ok() {
                    result = Err(e);
                }
                if stop {
                    break;
                }
            }
        }
        // `minting()`, not `token_type`: OAuth leaves `token_type` at its
        // default (user) but mints account-owned tokens, listed per account.
        if config.minting() == crate::config::CloudflareTokenType::User {
            break; // user tokens are listed once, not per account
        }
    }
    result?;
    cloudflare::forget_minted(name)?;
    Ok(deleted)
}

/// Removes the stored sign-in of an integration; returns whether one existed.
pub fn logout(name: &str, integration: &Integration) -> anyhow::Result<bool> {
    match integration {
        Integration::AwsSso(_) => aws_sso::logout(name),
        Integration::AwsIam(_) => aws_iam::logout(name),
        Integration::Gcp(_) => gcp::logout(name),
        Integration::Azure(_) => azure::logout(name),
        Integration::Cloudflare(_) => cloudflare::logout(name),
        Integration::Token(_) => token::logout(name),
    }
}

/// Whether an integration has a usable sign-in stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignIn {
    SignedOut,
    /// A long-lived secret (such as a Cloudflare bootstrap token) is stored.
    Token,
    /// A session that expires; `refreshable` sessions renew without a browser.
    Session {
        expires_at: Timestamp,
        refreshable: bool,
    },
}

pub fn sign_in(name: &str, integration: &Integration) -> anyhow::Result<SignIn> {
    Ok(match integration {
        Integration::AwsSso(_) => match aws_sso::session(name)? {
            Some((expires_at, refreshable)) => SignIn::Session {
                expires_at,
                refreshable,
            },
            None => SignIn::SignedOut,
        },
        Integration::AwsIam(_) => {
            if aws_iam::has_key(name)? {
                SignIn::Token
            } else {
                SignIn::SignedOut
            }
        }
        // A refresh token that lasts until revoked: like a stored token.
        Integration::Gcp(_) | Integration::Azure(_) => {
            let signed_in = match integration {
                Integration::Gcp(_) => gcp::is_signed_in(name)?,
                _ => azure::is_signed_in(name)?,
            };
            if signed_in {
                SignIn::Token
            } else {
                SignIn::SignedOut
            }
        }
        Integration::Token(_) => {
            if token::has_secrets(name)? {
                SignIn::Token
            } else {
                SignIn::SignedOut
            }
        }
        Integration::Cloudflare(c) if c.uses_oauth() => {
            match cloudflare_oauth::sign_in_ends(name)? {
                None => SignIn::SignedOut,
                Some((expires_at, refreshable)) => SignIn::Session {
                    expires_at,
                    refreshable,
                },
            }
        }
        Integration::Cloudflare(_) => {
            if !cloudflare::has_bootstrap_token(name)? {
                SignIn::SignedOut
            } else if let Some(expires_at) = cloudflare::session_expiry(name) {
                SignIn::Session {
                    expires_at,
                    refreshable: false,
                }
            } else {
                SignIn::Token
            }
        }
    })
}

/// Returns credentials for a profile, reusing cached ones while they are fresh.
///
/// `ttl` asks for a lifetime other than the configured one: minted
/// Cloudflare tokens, AWS sessions omnifob starts itself (chained roles,
/// IAM users and their roles) and Google service account tokens honour it,
/// and always get new credentials.
pub async fn credentials(
    config: &Config,
    profile: &Profile,
    use_cache: bool,
    ttl: Option<jiff::SignedDuration>,
) -> Result<Credentials> {
    if ttl.is_some() {
        match profile.target {
            Target::Aws { .. } => return Err(anyhow::anyhow!(
                "--ttl does not apply to IAM Identity Center roles: the permission set sets the session length"
            )
            .into()),
            Target::Token {} => return Err(anyhow::anyhow!(
                "--ttl does not apply to stored tokens; they do not expire"
            )
            .into()),
            Target::Gcp { .. } | Target::Azure { .. } => return Err(anyhow::anyhow!(
                "--ttl does not apply to {}: the provider sets its tokens' lifetime",
                profile.id
            )
            .into()),
            _ => {}
        }
    }
    let use_cache = use_cache && ttl.is_none();

    // Static tokens are read straight from the keychain; caching adds nothing.
    if let (Integration::Token(c), Target::Token {}) =
        (config.integration(&profile.integration)?, &profile.target)
    {
        return token::credentials(&profile.integration, c);
    }

    let key = store::credentials_key(&profile.id);
    if use_cache {
        match store::get::<Credentials>(&key) {
            Ok(Some(cached)) if cached.is_fresh(Timestamp::now()) => return Ok(cached),
            Ok(_) => {}
            Err(e) => tracing::debug!("ignoring unreadable cached credentials: {e:#}"),
        }
    }

    // One fetch per profile at a time: parallel commands (credential_process
    // calls from one tool) then share the result, and ask for one MFA code.
    let _lock = store::lock(
        &format!("credentials-{}", profile.id),
        std::time::Duration::from_secs(120),
    )
    .await?;
    if use_cache
        && let Ok(Some(cached)) = store::get::<Credentials>(&key)
        && cached.is_fresh(Timestamp::now())
    {
        return Ok(cached);
    }

    let fresh = fetch(config, profile, ttl).await?;
    let fresh = Credentials {
        issued_at: Some(Timestamp::now()),
        ..fresh
    };
    if let Err(e) = store::set(&key, &fresh) {
        tracing::warn!("could not cache credentials: {e:#}");
    }
    Ok(fresh)
}

/// Gets new credentials from the provider, bypassing the cache.
async fn fetch(
    config: &Config,
    profile: &Profile,
    ttl: Option<jiff::SignedDuration>,
) -> Result<Credentials> {
    let integration = config.integration(&profile.integration)?;
    let fresh = match (integration, &profile.target) {
        (
            Integration::AwsSso(c),
            Target::Aws {
                account_id,
                role_name,
                ..
            },
        ) => aws_sso::credentials(&profile.integration, c, account_id, role_name).await?,
        (Integration::AwsSso(c), Target::AwsChained { label, .. }) => {
            aws_sso::chained_credentials(&profile.integration, c, label, &profile.id, ttl).await?
        }
        (Integration::AwsIam(c), Target::AwsIamSession { .. }) => {
            aws_iam::session_credentials(&profile.integration, c, &profile.id, ttl).await?
        }
        (Integration::AwsIam(c), Target::AwsIamRole { label, .. }) => {
            aws_iam::role_credentials(&profile.integration, c, label, &profile.id, ttl).await?
        }
        (Integration::Gcp(c), Target::Gcp { project_id, .. }) => {
            gcp::user_credentials(&profile.integration, c, project_id).await?
        }
        (Integration::Gcp(c), Target::GcpServiceAccount { label, .. }) => {
            gcp::service_account_credentials(&profile.integration, c, label, ttl).await?
        }
        (
            Integration::Azure(_),
            Target::Azure {
                subscription_id,
                tenant_id,
                ..
            },
        ) => azure::credentials(&profile.integration, subscription_id, tenant_id).await?,
        (
            Integration::Cloudflare(c),
            Target::Cloudflare {
                account_id,
                template,
                ..
            },
        ) => {
            let c = match ttl {
                Some(ttl) => {
                    let mut c = c.clone();
                    c.ttl = ttl;
                    c.templates.values_mut().for_each(|t| t.ttl = None);
                    std::borrow::Cow::Owned(c)
                }
                None => std::borrow::Cow::Borrowed(c),
            };
            cloudflare::credentials(&profile.integration, &c, &profile.id, account_id, template)
                .await?
        }
        _ => {
            return Err(anyhow::anyhow!(
                "profile '{}' does not match integration type '{}'; run `fob sync`",
                profile.id,
                integration.kind()
            )
            .into());
        }
    };
    Ok(fresh)
}
/// Mints credentials for one command and does not cache them, so they can be
/// revoked with [`revoke_token`] when the command ends. Only Cloudflare
/// tokens can be revoked early.
pub async fn one_off_credentials(
    config: &Config,
    profile: &Profile,
    ttl: Option<jiff::SignedDuration>,
) -> Result<Credentials> {
    if !matches!(profile.target, Target::Cloudflare { .. }) {
        return Err(anyhow::anyhow!(
            "only Cloudflare tokens can be revoked when the command ends; {} expires on its own",
            profile.id
        )
        .into());
    }
    let mut fresh = fetch(config, profile, ttl).await?;
    fresh.issued_at = Some(Timestamp::now());
    Ok(fresh)
}

/// Revokes one set of credentials from [`one_off_credentials`].
pub async fn revoke_token(config: &Config, profile: &Profile, token_id: &str) -> Result<()> {
    match (config.integration(&profile.integration)?, &profile.target) {
        (Integration::Cloudflare(c), Target::Cloudflare { account_id, .. }) => {
            cloudflare::revoke_token(&profile.integration, c, account_id, token_id).await
        }
        _ => Ok(()),
    }
}

/// The partition an AWS profile's console opens in: the role ARN's for a
/// chained or IAM user's role, else the partition of the Region its
/// credentials come from (the portal's, or the IAM user's STS Region).
fn aws_console_partition(
    name: &str,
    integration: &Integration,
    target: &Target,
) -> anyhow::Result<Partition> {
    match (integration, target) {
        (Integration::AwsSso(c), Target::AwsChained { label, .. }) => c
            .chained
            .get(label)
            .with_context(|| {
                format!("no chained role '{label}' in integration '{name}'; run `fob sync`")
            })?
            .partition(),
        (Integration::AwsIam(c), Target::AwsIamRole { label, .. }) => c
            .roles
            .get(label)
            .with_context(|| format!("no role '{label}' in integration '{name}'; run `fob sync`"))?
            .partition(),
        (Integration::AwsSso(c), _) => Partition::of_region(&c.region),
        (Integration::AwsIam(c), _) => Partition::of_region(aws_iam::sts_region(c)),
        _ => anyhow::bail!("not an AWS profile"),
    }
}

/// What `fob console` asks of an AWS console beyond the profile. Other
/// providers take none of it.
#[derive(Debug, Clone, Default)]
pub struct ConsoleOptions {
    /// How long the console session lasts (`SessionDuration`, 15 minutes to
    /// 12 hours), overriding `console_duration`. Identity Center roles and
    /// an IAM user's roles only: the federation endpoint refuses it for
    /// chained roles and for the IAM user's own (`GetFederationToken`)
    /// session.
    pub duration: Option<jiff::SignedDuration>,
    /// The console page to open, as the path after the console host (`ec2`,
    /// `s3`, `cloudformation`).
    pub service: Option<String>,
    /// The Region the console opens in, overriding the profile's; it must
    /// be in the profile's partition.
    pub region: Option<String>,
}

/// Whether `fob console` needs credentials for this profile: AWS roles sign
/// in with them, an IAM user's own console session comes from its access key
/// and other providers' consoles need none.
pub fn console_needs_credentials(profile: &Profile) -> bool {
    profile.target.is_aws() && !matches!(profile.target, Target::AwsIamSession { .. })
}

/// The credentials to pass to [`console_url`]: always new ones, never cached,
/// where [`console_needs_credentials`] says the profile needs any, and none
/// otherwise. Without a `SessionDuration` the console session ends when they
/// expire, and cached credentials are handed out until five minutes before.
/// The new credentials also replace the cached ones.
pub async fn console_credentials(config: &Config, profile: &Profile) -> Result<Credentials> {
    if !console_needs_credentials(profile) {
        return Ok(Credentials::default());
    }
    credentials(config, profile, false, None).await
}

/// The console session length to ask for: `--duration`, else the
/// configured `console_duration` (Identity Center roles and an IAM user's
/// roles), else none. Fails where the federation endpoint would refuse one.
fn console_session_duration(
    integration: &Integration,
    profile: &Profile,
    options: &ConsoleOptions,
) -> anyhow::Result<Option<jiff::SignedDuration>> {
    let duration = match (integration, &profile.target) {
        (Integration::AwsSso(c), Target::Aws { .. }) => options.duration.or(c.console_duration),
        (Integration::AwsIam(c), Target::AwsIamRole { label, .. }) => options
            .duration
            .or(c.roles.get(label).and_then(|role| role.console_duration)),
        // `console_duration` on an aws-sso integration is for its Identity
        // Center roles only.
        (_, Target::AwsChained { .. }) if options.duration.is_some() => anyhow::bail!(
            "a chained role's console session cannot be given a length: the AWS federation \
             endpoint refuses SessionDuration for credentials from role chaining, so it lasts \
             as long as the role's credentials (`duration`, at most an hour)"
        ),
        (_, Target::AwsIamSession { .. }) if options.duration.is_some() => anyhow::bail!(
            "an IAM user's own console session cannot be given a length: the AWS federation \
             endpoint refuses SessionDuration for GetFederationToken credentials, so it lasts \
             the integration's `session_duration`; use one of its roles for another length"
        ),
        _ => None,
    };
    if let Some(duration) = duration {
        aws_sso::check_console_duration(duration)?;
    }
    Ok(duration)
}

/// Checks `options` against the profile, so `fob console` can refuse them
/// before it gets any credentials. [`console_url`] checks them too.
pub fn check_console_options(
    config: &Config,
    profile: &Profile,
    options: &ConsoleOptions,
) -> Result<()> {
    let integration = config.integration(&profile.integration)?;
    if !profile.target.is_aws() {
        if options.duration.is_some() || options.service.is_some() || options.region.is_some() {
            return Err(anyhow::anyhow!(
                "a console session length, service and Region apply only to AWS profiles, not {}",
                profile.id
            )
            .into());
        }
        return Ok(());
    }
    console_session_duration(integration, profile, options)?;
    if let Some(service) = &options.service {
        aws_sso::check_service(service)?;
    }
    if let Some(region) = &options.region {
        aws_console_partition(&profile.integration, integration, &profile.target)?
            .check_region(region)?;
    }
    Ok(())
}

/// Returns a URL that opens the provider's web console as this profile.
/// `creds` come from [`console_credentials`].
pub async fn console_url(
    config: &Config,
    profile: &Profile,
    creds: &Credentials,
    options: &ConsoleOptions,
) -> Result<String> {
    check_console_options(config, profile, options)?;
    let integration = config.integration(&profile.integration)?;
    let session_duration = console_session_duration(integration, profile, options)?;
    let service = options.service.as_deref();
    let region = options.region.as_deref();
    Ok(match (integration, &profile.target) {
        (Integration::AwsSso(c), target @ (Target::Aws { .. } | Target::AwsChained { .. })) => {
            let request = aws_sso::ConsoleRequest {
                partition: aws_console_partition(&profile.integration, integration, target)?,
                home_region: Some(&c.region),
                region: region.or(match target {
                    Target::Aws { .. } => c.default_region.as_deref(),
                    _ => creds.env.get("AWS_REGION").map(String::as_str),
                }),
                service,
                session_duration,
            };
            aws_sso::console_url(creds, &request).await?
        }
        (Integration::AwsIam(c), target @ Target::AwsIamSession { .. }) => {
            let partition = aws_console_partition(&profile.integration, integration, target)?;
            let region = region.or(c.region.as_deref());
            aws_iam::console_url(&profile.integration, c, partition, region, service).await?
        }
        (Integration::AwsIam(c), target @ Target::AwsIamRole { .. }) => {
            let request = aws_sso::ConsoleRequest {
                partition: aws_console_partition(&profile.integration, integration, target)?,
                home_region: c.region.as_deref(),
                region: region.or(creds.env.get("AWS_REGION").map(String::as_str)),
                service,
                session_duration,
            };
            aws_sso::console_url(creds, &request).await?
        }
        (Integration::Gcp(_), Target::Gcp { project_id, .. }) => {
            gcp::console_url(&profile.integration, Some(project_id))?
        }
        (Integration::Gcp(_), Target::GcpServiceAccount { project_id, .. }) => {
            gcp::console_url(&profile.integration, project_id.as_deref())?
        }
        (
            Integration::Azure(_),
            Target::Azure {
                subscription_id,
                tenant_id,
                ..
            },
        ) => azure::console_url(subscription_id, tenant_id),
        (Integration::Cloudflare(_), Target::Cloudflare { account_id, .. }) => {
            cloudflare::console_url(account_id)
        }
        (Integration::Token(c), Target::Token {}) => token::console_url(c)?.ok_or_else(|| {
            anyhow::anyhow!(
                "no console URL known for '{}'; set `console` in its config",
                profile.integration
            )
        })?,
        _ => {
            return Err(anyhow::anyhow!(
                "profile '{}' does not match integration type '{}'; run `fob sync`",
                profile.id,
                integration.kind()
            )
            .into());
        }
    })
}

/// Checks that an integration's stored sign-in works, without signing in.
pub async fn check_sign_in(name: &str, integration: &Integration) -> Result<String> {
    match integration {
        Integration::AwsSso(config) => aws_sso::check(name, config).await,
        Integration::AwsIam(config) => aws_iam::check(name, config).await,
        Integration::Gcp(config) => gcp::check(name, config).await,
        Integration::Azure(_) => azure::check(name).await,
        Integration::Cloudflare(config) => cloudflare::check(name, config).await,
        Integration::Token(config) => token::check(name, config).await,
    }
}

/// Gets a profile's credentials and proves they work; returns what they act as.
pub async fn check_profile(config: &Config, profile: &Profile) -> Result<String> {
    let creds = credentials(config, profile, true, None).await?;
    let integration = config.integration(&profile.integration)?;
    match (integration, &profile.target) {
        (Integration::AwsSso(c), Target::Aws { .. } | Target::AwsChained { .. }) => {
            let region = creds
                .env
                .get("AWS_REGION")
                .cloned()
                .unwrap_or_else(|| c.region.clone());
            Ok(format!(
                "acts as {}",
                aws_sso::caller_identity(&creds, &region).await?
            ))
        }
        (Integration::AwsIam(c), Target::AwsIamSession { .. } | Target::AwsIamRole { .. }) => {
            let region = creds
                .env
                .get("AWS_REGION")
                .cloned()
                .or_else(|| c.region.clone())
                .unwrap_or_else(|| "us-east-1".to_string());
            Ok(format!(
                "acts as {}",
                aws_sso::caller_identity(&creds, &region).await?
            ))
        }
        (Integration::Gcp(_), Target::Gcp { .. } | Target::GcpServiceAccount { .. }) => {
            gcp::check_token(&creds).await
        }
        (Integration::Azure(_), Target::Azure { .. }) => azure::check_subscription(&creds).await,
        (Integration::Cloudflare(c), Target::Cloudflare { account_id, .. }) => {
            let token = creds
                .env
                .get("CLOUDFLARE_API_TOKEN")
                .ok_or_else(|| anyhow::anyhow!("no token in the credentials"))?;
            cloudflare::check_token(c, account_id, token).await?;
            Ok("minted token active".to_string())
        }
        (Integration::Token(_), Target::Token {}) => {
            check_sign_in(&profile.integration, integration).await
        }
        _ => Err(anyhow::anyhow!(
            "profile '{}' does not match its integration; run `fob sync`",
            profile.id
        )
        .into()),
    }
}

/// What revoking a profile did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revoked {
    /// This many minted tokens were deleted at the provider.
    Tokens(usize),
    /// The provider cannot revoke these credentials early; only the cache was cleared.
    CacheOnly,
}

/// Revokes what omnifob handed out for a profile and clears its cache.
pub async fn revoke(config: &Config, profile: &Profile) -> Result<Revoked> {
    let integration = config.integration(&profile.integration)?;
    let revoked = match (integration, &profile.target) {
        (Integration::Cloudflare(c), Target::Cloudflare { account_id, .. }) => Revoked::Tokens(
            cloudflare::revoke(&profile.integration, c, Some(&profile.id), account_id).await?,
        ),
        _ => Revoked::CacheOnly,
    };
    store::delete(&store::credentials_key(&profile.id))?;
    Ok(revoked)
}

/// Moves an integration's stored sign-in to a new integration name.
pub fn rename_sign_in(old: &str, new: &str, integration: &Integration) -> anyhow::Result<bool> {
    match integration {
        Integration::AwsSso(_)
        | Integration::AwsIam(_)
        | Integration::Gcp(_)
        | Integration::Azure(_) => {
            let (from, to) = match integration {
                Integration::AwsSso(_) => (aws_sso::keys(old), aws_sso::keys(new)),
                Integration::AwsIam(_) => (aws_iam::keys(old), aws_iam::keys(new)),
                Integration::Gcp(_) => (gcp::keys(old), gcp::keys(new)),
                _ => (azure::keys(old), azure::keys(new)),
            };
            let mut moved = false;
            for (i, (from, to)) in from.iter().zip(to).enumerate() {
                // The first key is the sign-in itself: what "kept the sign-in" means.
                let renamed = store::rename(from, &to)?;
                moved = moved || (renamed && i == 0);
            }
            Ok(moved)
        }
        Integration::Cloudflare(_) => {
            cloudflare::rename_catalog(old, new);
            let oauth = cloudflare_oauth::rename(old, new)?;
            Ok(store::rename(
                &format!("cloudflare/{old}/bootstrap"),
                &format!("cloudflare/{new}/bootstrap"),
            )? || oauth)
        }
        Integration::Token(_) => store::rename(
            &format!("token/{old}/secrets"),
            &format!("token/{new}/secrets"),
        ),
    }
}

/// Drops cached credentials for every profile in `profiles`.
pub fn forget_credentials<'a>(profiles: impl IntoIterator<Item = &'a Profile>) {
    for profile in profiles {
        let _ = store::delete(&store::credentials_key(&profile.id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_partition_comes_from_the_role_arn() {
        let config = Config::parse(
            r#"
            [integrations.portal]
            type = "aws-sso"
            start_url = "https://acme.awsapps.com/start"
            region = "eu-west-1"
            [integrations.portal.chained.gov]
            via_account_id = "111111111111"
            via_role = "Admin"
            role_arn = "arn:aws-us-gov:iam::222222222222:role/Audit"

            [integrations.user]
            type = "aws-iam"
            [integrations.user.roles.cn]
            role_arn = "arn:aws-cn:iam::333333333333:role/Admin"
            "#,
        )
        .unwrap();
        let portal = config.integration("portal").unwrap();
        let user = config.integration("user").unwrap();
        let chained = |label: &str| Target::AwsChained {
            label: label.into(),
            account_id: None,
        };
        let cases = [
            (
                portal,
                Target::Aws {
                    account_id: "111111111111".into(),
                    account_name: "a".into(),
                    role_name: "Admin".into(),
                },
                Partition::Aws,
            ),
            (portal, chained("gov"), Partition::UsGov),
            (
                user,
                Target::AwsIamSession {
                    account_id: "444444444444".into(),
                },
                Partition::Aws,
            ),
            (
                user,
                Target::AwsIamRole {
                    label: "cn".into(),
                    account_id: None,
                },
                Partition::China,
            ),
        ];
        for (integration, target, partition) in cases {
            assert_eq!(
                aws_console_partition("i", integration, &target).unwrap(),
                partition,
                "{target:?}"
            );
        }
        let missing = aws_console_partition("portal", portal, &chained("missing")).unwrap_err();
        assert_eq!(
            missing.to_string(),
            "no chained role 'missing' in integration 'portal'; run `fob sync`"
        );
    }

    #[test]
    fn console_options_follow_what_the_federation_endpoint_accepts() {
        let config = Config::parse(
            r#"
            [integrations.portal]
            type = "aws-sso"
            start_url = "https://acme.awsapps.com/start"
            region = "eu-west-1"
            console_duration = "4h"
            [integrations.portal.chained.ops]
            via_account_id = "111111111111"
            via_role = "Admin"
            role_arn = "arn:aws:iam::222222222222:role/Ops"

            [integrations.user]
            type = "aws-iam"
            [integrations.user.roles.prod]
            role_arn = "arn:aws:iam::333333333333:role/Admin"
            console_duration = "2h"
            [integrations.user.roles.plain]
            role_arn = "arn:aws:iam::333333333333:role/Plain"

            [integrations.cf]
            type = "cloudflare-token"
            account_id = "abc"
            "#,
        )
        .unwrap();
        let sso_role = Profile::new(
            "portal",
            "a",
            "Admin",
            Target::Aws {
                account_id: "111111111111".into(),
                account_name: "a".into(),
                role_name: "Admin".into(),
            },
        );
        let chained = Profile::new(
            "portal",
            "ops",
            "Ops",
            Target::AwsChained {
                label: "ops".into(),
                account_id: None,
            },
        );
        let session = Profile::new(
            "user",
            "333333333333",
            "session",
            Target::AwsIamSession {
                account_id: "333333333333".into(),
            },
        );
        let iam_role = |label: &str| {
            Profile::new(
                "user",
                label,
                "Admin",
                Target::AwsIamRole {
                    label: label.into(),
                    account_id: None,
                },
            )
        };
        let cloudflare = Profile::new(
            "cf",
            "abc",
            "default",
            Target::Cloudflare {
                account_id: "abc".into(),
                account_name: "abc".into(),
                template: "default".into(),
            },
        );
        let hours = jiff::SignedDuration::from_hours;
        let with = |duration: Option<i64>| ConsoleOptions {
            duration: duration.map(hours),
            ..Default::default()
        };
        let duration = |profile: &Profile, options: &ConsoleOptions| {
            let integration = config.integration(&profile.integration).unwrap();
            console_session_duration(integration, profile, options)
        };

        // The flag overrides the configured length; unset, there is none.
        assert_eq!(duration(&sso_role, &with(None)).unwrap(), Some(hours(4)));
        assert_eq!(duration(&sso_role, &with(Some(8))).unwrap(), Some(hours(8)));
        assert_eq!(
            duration(&iam_role("prod"), &with(None)).unwrap(),
            Some(hours(2))
        );
        assert_eq!(duration(&iam_role("plain"), &with(None)).unwrap(), None);
        assert_eq!(
            duration(&iam_role("plain"), &with(Some(1))).unwrap(),
            Some(hours(1))
        );
        // The integration's length is not sent for its chained roles.
        assert_eq!(duration(&chained, &with(None)).unwrap(), None);
        assert_eq!(duration(&session, &with(None)).unwrap(), None);

        // Role chaining and GetFederationToken refuse SessionDuration.
        let error = check_console_options(&config, &chained, &with(Some(1))).unwrap_err();
        assert!(error.to_string().contains("role chaining"), "{error}");
        let error = check_console_options(&config, &session, &with(Some(1))).unwrap_err();
        assert!(error.to_string().contains("GetFederationToken"), "{error}");
        let error = check_console_options(&config, &sso_role, &with(Some(13))).unwrap_err();
        assert!(error.to_string().contains("12 hours"), "{error}");

        // The Region must be in the profile's partition, the service a path.
        let region = |r: &str| ConsoleOptions {
            region: Some(r.into()),
            service: Some("ec2".into()),
            ..Default::default()
        };
        assert!(check_console_options(&config, &chained, &region("eu-west-1")).is_ok());
        let error = check_console_options(&config, &session, &region("us-gov-west-1")).unwrap_err();
        assert!(error.to_string().contains("not aws"), "{error}");
        let service = ConsoleOptions {
            service: Some("ec2?x=1".into()),
            ..Default::default()
        };
        assert!(check_console_options(&config, &sso_role, &service).is_err());

        // Other providers take none of them.
        assert!(check_console_options(&config, &cloudflare, &ConsoleOptions::default()).is_ok());
        let error = check_console_options(&config, &cloudflare, &region("eu-west-1")).unwrap_err();
        assert!(error.to_string().contains("only to AWS"), "{error}");
        assert!(!console_needs_credentials(&cloudflare));
        assert!(!console_needs_credentials(&session));
        assert!(console_needs_credentials(&chained));
        assert!(console_needs_credentials(&iam_role("prod")));
    }
}
