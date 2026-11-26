//! Provider dispatch: each integration kind implements sign-in, discovery,
//! credentials and a console link.

pub mod aws;
pub mod azure;
pub mod cloudflare;
pub mod command;
pub mod gcp;
pub mod token;

use anyhow::Context;
use jiff::Timestamp;

use self::aws::partition::Partition;
use crate::{Config, Credentials, Error, Integration, Profile, Result, Target, store};

/// Discovers every profile an integration offers.
pub async fn discover(name: &str, integration: &Integration) -> Result<Vec<Profile>> {
    let profiles = discover_unchecked(name, integration).await?;
    crate::profile::check_unique_ids(name, &profiles)?;
    Ok(profiles)
}

async fn discover_unchecked(name: &str, integration: &Integration) -> Result<Vec<Profile>> {
    match integration {
        Integration::AwsSso(config) => aws::sso::discover(name, config).await,
        Integration::AwsIam(config) => aws::iam::discover(name, config).await,
        Integration::AwsLogin(config) => aws::login::discover(name, config),
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
        Integration::Command(config) => Ok(command::discover(name, config)),
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
        Integration::AwsSso(_) => aws::sso::logout(name),
        Integration::AwsIam(_) => aws::iam::logout(name),
        Integration::AwsLogin(_) => aws::login::logout(name),
        Integration::Gcp(_) => gcp::logout(name),
        Integration::Azure(_) => azure::logout(name),
        Integration::Cloudflare(_) => cloudflare::logout(name),
        Integration::Token(_) => token::logout(name),
        // Nothing is stored but cached credentials, which logout clears.
        Integration::Command(_) => Ok(false),
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
        Integration::AwsSso(_) => match aws::sso::session(name)? {
            Some((expires_at, refreshable)) => SignIn::Session {
                expires_at,
                refreshable,
            },
            None => SignIn::SignedOut,
        },
        // Renewed silently until the console sign-in ends (up to 12 hours),
        // which the session cannot tell.
        Integration::AwsLogin(_) => match aws::login::session(name)? {
            Some(expires_at) => SignIn::Session {
                expires_at,
                refreshable: true,
            },
            None => SignIn::SignedOut,
        },
        Integration::AwsIam(_) => {
            if aws::iam::has_key(name)? {
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
        // Nothing to sign in to: the program is run when needed.
        Integration::Command(_) => SignIn::Token,
        Integration::Token(_) => {
            if token::has_secrets(name)? {
                SignIn::Token
            } else {
                SignIn::SignedOut
            }
        }
        Integration::Cloudflare(c) if c.uses_oauth() => {
            match cloudflare::oauth::sign_in_ends(name)? {
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
/// Cloudflare tokens, AWS sessions omnifob starts itself (chained and
/// cross-partition roles, IAM users and their roles) and Google service
/// account tokens honour it, and always get new credentials. These are not
/// cached, so the next call without `ttl` gets the configured lifetime again.
///
/// AWS credentials carry `AWS_ACCOUNT_ID`, which the SDKs use for
/// account-based endpoints.
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
            Target::AwsLogin { .. } => return Err(anyhow::anyhow!(
                "--ttl does not apply to console sign-in credentials: AWS Sign-In always issues them for 15 minutes"
            )
            .into()),
            Target::Command { .. } if chosen_lifetime(config, profile).is_none() => {
                return Err(anyhow::anyhow!(
                    "--ttl does not apply to {}: set `ttl` on '{}' if its program takes a lifetime",
                    profile.id,
                    profile.integration
                )
                .into());
            }
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
            Ok(Some(cached)) if cached.is_fresh(Timestamp::now()) => {
                return Ok(with_aws_account(config, profile, cached));
            }
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
        return Ok(with_aws_account(config, profile, cached));
    }

    let fresh = fetch(config, profile, ttl, !use_cache).await?;
    // Console sign-in credentials may come from the stored session, issued
    // earlier; the others were issued now.
    let issued_at = match profile.target {
        Target::AwsLogin { .. } => fresh.issued_at.or(Some(Timestamp::now())),
        _ => Some(Timestamp::now()),
    };
    let fresh = Credentials { issued_at, ..fresh };
    // The cache holds credentials of the configured lifetime only: a `ttl`
    // request must not leave its shorter (or longer) ones for the next call.
    // New credentials without `ttl`, as `fob console` gets, replace it.
    // A program's credentials without an expiry are fetched for each use:
    // omnifob cannot tell when they stop working.
    let cacheable = fresh.expires_at.is_some() || !matches!(profile.target, Target::Command { .. });
    if ttl.is_none()
        && cacheable
        && let Err(e) = store::set(&key, &fresh)
    {
        tracing::warn!("could not cache credentials: {e:#}");
    }
    Ok(with_aws_account(config, profile, fresh))
}

/// The lifetime omnifob asks for when it gets a profile's credentials, for
/// the profiles whose lifetime it chooses and that take `ttl`: Cloudflare
/// tokens, chained, cross-partition, IAM users' and console sign-ins' roles,
/// and IAM user sessions, except those that ask for an MFA code (with MFA,
/// each new session asks for a code, and an agent's capped request, which is
/// not cached, would ask every time: IAM user sessions, `no_session` roles
/// of a user with `mfa_serial`, and chained and console sign-ins' roles with
/// `mfa_serial`), Google service accounts, and programs given a `ttl`. `None` for the others, whose provider sets it.
pub fn chosen_lifetime(config: &Config, profile: &Profile) -> Option<jiff::SignedDuration> {
    use jiff::SignedDuration;
    let hour = SignedDuration::from_hours(1);
    match (
        config.integration(&profile.integration).ok()?,
        &profile.target,
    ) {
        (Integration::Cloudflare(c), Target::Cloudflare { template, .. }) => Some(
            c.templates
                .get(template)
                .and_then(|t| t.ttl)
                .unwrap_or(c.ttl),
        ),
        (Integration::AwsSso(c), Target::AwsChained { label, .. }) => {
            let role = c.chained.get(label)?;
            if role.mfa_serial.is_some() {
                return None;
            }
            Some(role.duration.unwrap_or(hour))
        }
        (Integration::AwsSso(c), Target::AwsCrossPartition { label, .. }) => {
            Some(c.cross_partition.get(label)?.duration_or_default())
        }
        (Integration::AwsIam(c), Target::AwsIamRole { label, .. }) => {
            let role = c.roles.get(label)?;
            // Assumed with the access key, each session asks for the user's
            // MFA code.
            if role.no_session && c.mfa_serial.is_some() {
                return None;
            }
            Some(role.duration.unwrap_or(hour))
        }
        (Integration::AwsIam(c), Target::AwsIamSession { .. }) if c.mfa_serial.is_none() => {
            Some(c.session_duration.unwrap_or(SignedDuration::from_hours(8)))
        }
        (Integration::Gcp(c), Target::GcpServiceAccount { label, .. }) => {
            Some(c.service_accounts.get(label)?.lifetime.unwrap_or(hour))
        }
        (Integration::AwsLogin(c), Target::AwsLoginRole { label, .. }) => {
            let role = c.roles.get(label)?;
            if role.mfa_serial.is_some() {
                return None;
            }
            Some(role.duration.unwrap_or(hour))
        }
        (Integration::Command(c), Target::Command { .. }) => c.ttl,
        _ => None,
    }
}

/// The `ttl` to ask for so credentials last at most `max`: `max` when the
/// requested or chosen lifetime is longer, else the requested `ttl`. A
/// profile whose provider sets the lifetime keeps it.
pub fn capped_ttl(
    config: &Config,
    profile: &Profile,
    ttl: Option<jiff::SignedDuration>,
    max: jiff::SignedDuration,
) -> Option<jiff::SignedDuration> {
    match ttl.or_else(|| chosen_lifetime(config, profile)) {
        Some(lifetime) if lifetime > max && chosen_lifetime(config, profile).is_some() => Some(max),
        _ => ttl,
    }
}

/// The account an AWS profile's credentials belong to, as the profile states
/// it: the account of an Identity Center role and an IAM user's session, and
/// the role ARN's account, recorded at discovery, for chained,
/// cross-partition and IAM user roles. The profile's, not the current
/// config's: credentials cached before a `role_arn` edit belong to the
/// account the profile was synced with, and `fob sync` drops them along with
/// the old profile. Only a chained or IAM user's role profile synced before
/// omnifob recorded the account falls back to the config.
fn aws_account_id<'a>(config: &'a Config, profile: &'a Profile) -> Option<&'a str> {
    match &profile.target {
        Target::Aws { account_id, .. }
        | Target::AwsIamSession { account_id }
        | Target::AwsLogin { account_id }
        | Target::AwsCrossPartition { account_id, .. } => Some(account_id),
        Target::AwsChained {
            account_id: Some(account_id),
            ..
        }
        | Target::AwsIamRole {
            account_id: Some(account_id),
            ..
        }
        | Target::AwsLoginRole {
            account_id: Some(account_id),
            ..
        } => Some(account_id),
        Target::AwsChained { label, .. } => match config.integration(&profile.integration) {
            Ok(Integration::AwsSso(c)) => c.chained.get(label).and_then(|role| role.account_id()),
            _ => None,
        },
        Target::AwsIamRole { label, .. } => match config.integration(&profile.integration) {
            Ok(Integration::AwsIam(c)) => c.roles.get(label).and_then(|role| role.account_id()),
            _ => None,
        },
        Target::AwsLoginRole { label, .. } => match config.integration(&profile.integration) {
            Ok(Integration::AwsLogin(c)) => c.roles.get(label).and_then(|role| role.account_id()),
            _ => None,
        },
        _ => None,
    }
}

/// Adds `AWS_ACCOUNT_ID` to an AWS profile's credentials. Done on the way
/// out rather than by each provider, so credentials cached before omnifob
/// exported it carry it too.
fn with_aws_account(config: &Config, profile: &Profile, mut creds: Credentials) -> Credentials {
    if let Some(account) = aws_account_id(config, profile) {
        creds
            .env
            .insert("AWS_ACCOUNT_ID".to_string(), account.to_string());
    }
    creds
}

/// Gets new credentials from the provider, bypassing the cache. `renew`
/// makes providers that keep credentials of their own (console sign-in)
/// renew them rather than hand out the stored ones.
async fn fetch(
    config: &Config,
    profile: &Profile,
    ttl: Option<jiff::SignedDuration>,
    renew: bool,
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
        ) => aws::sso::credentials(&profile.integration, c, account_id, role_name).await?,
        (Integration::AwsSso(c), Target::AwsChained { label, .. }) => {
            aws::sso::chained_credentials(&profile.integration, c, label, &profile.id, ttl).await?
        }
        (Integration::AwsSso(c), Target::AwsCrossPartition { label, .. }) => {
            aws::cross_partition::cross_partition_credentials(&profile.integration, c, label, ttl)
                .await?
        }
        (Integration::AwsIam(c), Target::AwsIamSession { .. }) => {
            aws::iam::session_credentials(&profile.integration, c, &profile.id, ttl).await?
        }
        (Integration::AwsIam(c), Target::AwsIamRole { label, .. }) => {
            aws::iam::role_credentials(&profile.integration, c, label, &profile.id, ttl).await?
        }
        (Integration::AwsLogin(c), Target::AwsLogin { .. }) => {
            aws::login::credentials(&profile.integration, c, renew).await?
        }
        (Integration::AwsLogin(c), Target::AwsLoginRole { label, .. }) => {
            aws::login::role_credentials(&profile.integration, c, label, &profile.id, ttl).await?
        }
        (Integration::Command(c), Target::Command { .. }) => {
            command::credentials(&profile.integration, c, &profile.id, ttl.or(c.ttl)).await?
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
    let mut fresh = fetch(config, profile, ttl, true).await?;
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
/// chained, cross-partition or IAM user's role, else the partition of the Region its
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
        (Integration::AwsSso(c), Target::AwsCrossPartition { label, .. }) => c
            .cross_partition
            .get(label)
            .with_context(|| {
                format!("no cross-partition role '{label}' in integration '{name}'; run `fob sync`")
            })?
            .partition(),
        (Integration::AwsIam(c), Target::AwsIamRole { label, .. }) => c
            .roles
            .get(label)
            .with_context(|| format!("no role '{label}' in integration '{name}'; run `fob sync`"))?
            .partition(),
        (Integration::AwsLogin(c), Target::AwsLoginRole { label, .. }) => c
            .roles
            .get(label)
            .with_context(|| format!("no role '{label}' in integration '{name}'; run `fob sync`"))?
            .partition(),
        (Integration::Command(c), Target::Command { aws: true }) => {
            Partition::of_region(c.region.as_deref().unwrap_or("us-east-1"))
        }
        (Integration::AwsSso(c), _) => Partition::of_region(&c.region),
        (Integration::AwsIam(c), _) => Partition::of_region(aws::iam::sts_region(c)),
        (Integration::AwsLogin(c), _) => aws::login::partition(c),
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
    /// session, and cross-partition roles refuse it until it is confirmed
    /// that the endpoint accepts it for their credentials.
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
        // The federation endpoint takes SessionDuration for AssumeRole*
        // credentials unless they come from role chaining. Whether it counts
        // AssumeRoleWithWebIdentity with a token that role credentials
        // requested as chaining is not documented and not tried, so the
        // length is refused until it is; `duration` (up to 12 hours) sets
        // the console session's length instead. The integration's
        // `console_duration` is for its Identity Center roles.
        (_, Target::AwsCrossPartition { .. }) if options.duration.is_some() => anyhow::bail!(
            "a cross-partition role's console session cannot be given a length yet: whether the \
             AWS federation endpoint accepts SessionDuration for credentials from a web identity \
             token that a role requested has not been confirmed, so it lasts as long as the \
             role's credentials (its `duration`, up to 12 hours)"
        ),
        // `console_duration` on an aws-sso integration is for its Identity
        // Center roles only.
        (_, Target::AwsChained { .. }) if options.duration.is_some() => anyhow::bail!(
            "a chained role's console session cannot be given a length: the AWS federation \
             endpoint refuses SessionDuration for credentials from role chaining, so it lasts \
             as long as the role's credentials (`duration`, at most an hour)"
        ),
        (_, Target::AwsLoginRole { .. }) if options.duration.is_some() => anyhow::bail!(
            "a console sign-in role's console session cannot be given a length: the AWS \
             federation endpoint refuses SessionDuration for credentials from role chaining, so \
             it lasts as long as the role's credentials (`duration`, at most an hour)"
        ),
        // Whatever the program's credentials are, the federation endpoint
        // decides whether it takes a length for them.
        (Integration::Command(_), Target::Command { .. }) => options.duration,
        (_, Target::AwsLogin { .. }) if options.duration.is_some() => anyhow::bail!(
            "a console sign-in's own console session cannot be given a length: its \
             credentials are not from AssumeRole, which the AWS federation endpoint takes \
             SessionDuration for"
        ),
        (_, Target::AwsIamSession { .. }) if options.duration.is_some() => anyhow::bail!(
            "an IAM user's own console session cannot be given a length: the AWS federation \
             endpoint refuses SessionDuration for GetFederationToken credentials, so it lasts \
             the integration's `session_duration`; use one of its roles for another length"
        ),
        _ => None,
    };
    if let Some(duration) = duration {
        aws::console::check_console_duration(duration)?;
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
        aws::console::check_service(service)?;
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
            let request = aws::console::ConsoleRequest {
                partition: aws_console_partition(&profile.integration, integration, target)?,
                home_region: Some(&c.region),
                region: region.or(match target {
                    Target::Aws { .. } => c.default_region.as_deref(),
                    _ => creds.env.get("AWS_REGION").map(String::as_str),
                }),
                service,
                session_duration,
            };
            aws::console::console_url(creds, &request).await?
        }
        (Integration::AwsSso(c), target @ Target::AwsCrossPartition { label, .. }) => {
            let request = cross_partition_console_request(
                &profile.integration,
                integration,
                c,
                label,
                target,
                creds,
                options,
                session_duration,
            )?;
            aws::console::console_url(creds, &request).await?
        }
        (Integration::AwsIam(c), target @ Target::AwsIamSession { .. }) => {
            let partition = aws_console_partition(&profile.integration, integration, target)?;
            let region = region.or(c.region.as_deref());
            aws::iam::console_url(&profile.integration, c, partition, region, service).await?
        }
        (Integration::AwsIam(c), target @ Target::AwsIamRole { .. }) => {
            let request = aws::console::ConsoleRequest {
                partition: aws_console_partition(&profile.integration, integration, target)?,
                home_region: c.region.as_deref(),
                region: region.or(creds.env.get("AWS_REGION").map(String::as_str)),
                service,
                session_duration,
            };
            aws::console::console_url(creds, &request).await?
        }
        (
            Integration::AwsLogin(c),
            target @ (Target::AwsLogin { .. } | Target::AwsLoginRole { .. }),
        ) => {
            let request = aws::console::ConsoleRequest {
                partition: aws_console_partition(&profile.integration, integration, target)?,
                home_region: Some(&c.region),
                region: region.or(creds.env.get("AWS_REGION").map(String::as_str)),
                service,
                session_duration,
            };
            aws::console::console_url(creds, &request).await?
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
        (Integration::Command(c), Target::Command { aws }) => match command::console_url(c) {
            Some(url) => url,
            None if *aws => {
                let request = aws::console::ConsoleRequest {
                    partition: aws_console_partition(
                        &profile.integration,
                        integration,
                        &profile.target,
                    )?,
                    home_region: c.region.as_deref(),
                    region: region.or(c.region.as_deref()),
                    service,
                    session_duration,
                };
                aws::console::console_url(creds, &request).await?
            }
            None => {
                return Err(anyhow::anyhow!(
                    "no console URL known for '{}'; set `console` in its config",
                    profile.integration
                )
                .into());
            }
        },
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

/// The console sign-in for a cross-partition role: the destination
/// partition's federation endpoint, with the console in `--region` or else
/// the exported destination Region, so the sign-in host is the destination
/// partition's too.
#[allow(clippy::too_many_arguments)]
fn cross_partition_console_request<'a>(
    name: &str,
    integration: &Integration,
    config: &'a crate::config::AwsSsoConfig,
    label: &str,
    target: &Target,
    creds: &'a Credentials,
    options: &'a ConsoleOptions,
    session_duration: Option<jiff::SignedDuration>,
) -> anyhow::Result<aws::console::ConsoleRequest<'a>> {
    let role = config.cross_partition.get(label).with_context(|| {
        format!("no cross-partition role '{label}' in integration '{name}'; run `fob sync`")
    })?;
    Ok(aws::console::ConsoleRequest {
        partition: aws_console_partition(name, integration, target)?,
        home_region: Some(&role.region),
        region: options
            .region
            .as_deref()
            .or(creds.env.get("AWS_REGION").map(String::as_str))
            .or(Some(&role.region)),
        service: options.service.as_deref(),
        session_duration,
    })
}

/// How long a sign-in that cannot renew itself must still last for `fob login`
/// to keep it.
const KEEP_MARGIN: jiff::SignedDuration = jiff::SignedDuration::from_mins(15);

/// Whether `fob login` can keep the stored sign-in instead of opening the
/// browser again, as granted does: it works (checked as `fob check` does, so
/// it may renew), was made for the configured portal and scopes, and does not
/// end within [`KEEP_MARGIN`]. Returns the check's description when it can.
///
/// Only the browser sign-ins (Identity Center, console sign-in, Google,
/// Azure and Cloudflare OAuth) are kept; for the others `fob login` is how a
/// key or token is replaced. A console sign-in is kept only for the
/// configured Region, a Google one only for the configured OAuth client, and
/// an Azure one only for the configured tenant.
pub async fn keepable_sign_in(name: &str, integration: &Integration) -> Option<String> {
    let scopes_match = match integration {
        Integration::AwsSso(config) => aws::sso::session_has_scopes(name, config),
        Integration::AwsLogin(config) => aws::login::session_matches(name, config),
        Integration::Gcp(config) => gcp::session_matches(name, config),
        Integration::Azure(config) => azure::session_matches(name, config),
        Integration::Cloudflare(config) if config.uses_oauth() => {
            cloudflare::oauth::granted_scopes(name).map(|granted| {
                granted.is_some_and(|granted| {
                    cloudflare::oauth::scopes(config)
                        .iter()
                        .all(|s| granted.contains(s))
                })
            })
        }
        _ => return None,
    };
    if !scopes_match.unwrap_or(false) {
        return None;
    }
    match sign_in(name, integration) {
        Ok(SignIn::Token) => {}
        Ok(SignIn::Session {
            expires_at,
            refreshable,
        }) if refreshable || expires_at > Timestamp::now().saturating_add(KEEP_MARGIN).ok()? => {}
        _ => return None,
    }
    match check_sign_in(name, integration).await {
        Ok(detail) => Some(detail),
        Err(e) => {
            tracing::debug!("not keeping the stored sign-in of '{name}': {e:#}");
            None
        }
    }
}

/// Checks that an integration's stored sign-in works, without signing in.
pub async fn check_sign_in(name: &str, integration: &Integration) -> Result<String> {
    match integration {
        Integration::AwsSso(config) => aws::sso::check(name, config).await,
        Integration::AwsIam(config) => aws::iam::check(name, config).await,
        Integration::AwsLogin(config) => aws::login::check(name, config).await,
        Integration::Gcp(config) => gcp::check(name, config).await,
        Integration::Azure(_) => azure::check(name).await,
        Integration::Cloudflare(config) => cloudflare::check(name, config).await,
        Integration::Token(config) => token::check(name, config).await,
        Integration::Command(config) => command::check(name, config).await,
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
                aws::sts::caller_identity(&creds, &region).await?.arn
            ))
        }
        (Integration::AwsSso(c), Target::AwsCrossPartition { label, .. }) => {
            // The destination partition's STS: the credentials work nowhere
            // else.
            let role = c.cross_partition.get(label).ok_or_else(|| {
                anyhow::anyhow!(
                    "no cross-partition role '{label}' in integration '{}'; run `fob sync`",
                    profile.integration
                )
            })?;
            Ok(format!(
                "acts as {}",
                aws::sts::caller_identity(&creds, &role.region).await?.arn
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
                aws::sts::caller_identity(&creds, &region).await?.arn
            ))
        }
        (Integration::Command(c), Target::Command { aws: true }) => Ok(format!(
            "acts as {}",
            aws::sts::caller_identity(&creds, c.region.as_deref().unwrap_or("us-east-1"))
                .await?
                .arn
        )),
        (Integration::Command(_), Target::Command { aws: false }) => {
            let names: Vec<&str> = creds.env.keys().map(String::as_str).collect();
            Ok(format!(
                "the program printed {} (not checked with a provider)",
                names.join(", ")
            ))
        }
        (Integration::AwsLogin(c), Target::AwsLogin { .. } | Target::AwsLoginRole { .. }) => {
            Ok(format!(
                "acts as {}",
                aws::sts::caller_identity(&creds, &c.region).await?.arn
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
        | Integration::AwsLogin(_)
        | Integration::Gcp(_)
        | Integration::Azure(_) => {
            let (from, to) = match integration {
                Integration::AwsSso(_) => (aws::sso::keys(old), aws::sso::keys(new)),
                Integration::AwsIam(_) => (aws::iam::keys(old), aws::iam::keys(new)),
                Integration::AwsLogin(_) => (aws::login::keys(old), aws::login::keys(new)),
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
            cloudflare::rename_catalog(old, new)?;
            let oauth = cloudflare::oauth::rename(old, new)?;
            Ok(store::rename(
                &format!("cloudflare/{old}/bootstrap"),
                &format!("cloudflare/{new}/bootstrap"),
            )? || oauth)
        }
        Integration::Token(_) => store::rename(
            &format!("token/{old}/secrets"),
            &format!("token/{new}/secrets"),
        ),
        Integration::Command(_) => Ok(false),
    }
}

/// Drops cached credentials for every profile in `profiles`.
pub fn forget_credentials<'a>(profiles: impl IntoIterator<Item = &'a Profile>) {
    for profile in profiles {
        let _ = store::delete(&store::credentials_key(&profile.id));
    }
}

/// Drops cached credentials of the profiles in `before` that are not in
/// `after` unchanged, so a sync that loses a profile (an assignment removed,
/// a role taken out of the config, an integration deleted) leaves no
/// credentials behind in the keychain. A profile whose id stays but whose
/// target changed (a chained or IAM user's role moved to another account)
/// loses them too: they belong to the old target, and would otherwise be
/// handed out labelled with the new one's account. Returns how many
/// profiles' credentials were dropped.
pub fn forget_removed_credentials<'a>(
    before: impl IntoIterator<Item = &'a Profile>,
    after: impl IntoIterator<Item = &'a Profile>,
) -> usize {
    let kept: std::collections::BTreeMap<&str, &Profile> =
        after.into_iter().map(|p| (p.id.as_str(), p)).collect();
    let mut removed = 0;
    for profile in before {
        if kept.get(profile.id.as_str()) != Some(&profile) {
            removed += 1;
            if let Err(e) = store::delete(&store::credentials_key(&profile.id)) {
                tracing::warn!(
                    "could not delete the cached credentials of {}: {e:#}",
                    profile.id
                );
            }
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_that_need_mfa_keep_their_lifetime_under_a_cap() {
        let config = Config::parse(
            "[integrations.a]\ntype = \"aws-sso\"\nstart_url = \"https://a.awsapps.com/start\"\nregion = \"eu-west-1\"\n\
             [integrations.a.chained.plain]\nvia_account_id = \"111111111111\"\nvia_role = \"Admin\"\nrole_arn = \"arn:aws:iam::222222222222:role/R\"\nduration = \"1h\"\n\
             [integrations.a.chained.mfa]\nvia_account_id = \"111111111111\"\nvia_role = \"Admin\"\nrole_arn = \"arn:aws:iam::222222222222:role/M\"\nmfa_serial = \"arn:aws:iam::111111111111:mfa/me\"\n",
        )
        .unwrap();
        let chained = |label: &str| {
            Profile::new(
                "a",
                "x",
                label,
                Target::AwsChained {
                    label: label.into(),
                    account_id: None,
                },
            )
        };
        let max = jiff::SignedDuration::from_mins(15);
        assert_eq!(
            chosen_lifetime(&config, &chained("plain")),
            Some(jiff::SignedDuration::from_hours(1))
        );
        assert_eq!(capped_ttl(&config, &chained("plain"), None, max), Some(max));
        // Each capped request would ask for a code, which nobody can give
        // an agent.
        assert_eq!(chosen_lifetime(&config, &chained("mfa")), None);
        assert_eq!(capped_ttl(&config, &chained("mfa"), None, max), None);

        let config = Config::parse(
            "[integrations.u]\ntype = \"aws-iam\"\nmfa_serial = \"arn:aws:iam::111111111111:mfa/me\"\n\
             [integrations.u.roles.session]\nrole_arn = \"arn:aws:iam::222222222222:role/S\"\n\
             [integrations.u.roles.key]\nrole_arn = \"arn:aws:iam::222222222222:role/K\"\nno_session = true\n\
             [integrations.c]\ntype = \"aws-login\"\nregion = \"eu-west-1\"\n\
             [integrations.c.roles.plain]\nrole_arn = \"arn:aws:iam::222222222222:role/P\"\n\
             [integrations.c.roles.mfa]\nrole_arn = \"arn:aws:iam::222222222222:role/M\"\nmfa_serial = \"arn:aws:iam::111111111111:mfa/me\"\n",
        )
        .unwrap();
        let role = |integration: &str, label: &str| {
            let target = if integration == "u" {
                Target::AwsIamRole {
                    label: label.into(),
                    account_id: None,
                }
            } else {
                Target::AwsLoginRole {
                    label: label.into(),
                    account_id: None,
                }
            };
            Profile::new(integration, "x", label, target)
        };
        // Assumed with the session, whose code was asked for once.
        assert!(chosen_lifetime(&config, &role("u", "session")).is_some());
        assert_eq!(chosen_lifetime(&config, &role("u", "key")), None);
        assert!(chosen_lifetime(&config, &role("c", "plain")).is_some());
        assert_eq!(chosen_lifetime(&config, &role("c", "mfa")), None);
    }

    #[test]
    fn profiles_that_go_away_lose_their_cached_credentials() {
        let _cx = crate::Context::builder()
            .keychain(store::Keychain::Memory)
            .build()
            .enter();
        let profile = |integration: &str, account: &str| {
            Profile::new(
                integration,
                account,
                "Admin",
                Target::Aws {
                    account_id: "111111111111".into(),
                    account_name: account.into(),
                    role_name: "Admin".into(),
                },
            )
        };
        let kept = profile("prune", "kept");
        let gone = profile("prune", "gone");
        let removed_integration = profile("prune-removed", "a");
        let never_cached = profile("prune", "never");
        for p in [&kept, &gone, &removed_integration] {
            store::set(&store::credentials_key(&p.id), &Credentials::default()).unwrap();
        }
        let cached = |p: &Profile| {
            store::get::<Credentials>(&store::credentials_key(&p.id))
                .unwrap()
                .is_some()
        };

        let before = [&kept, &gone, &removed_integration, &never_cached];
        let after = [profile("prune", "kept"), profile("prune", "new")];
        let removed = forget_removed_credentials(before, &after);
        assert_eq!(removed, 3);
        assert!(cached(&kept));
        assert!(!cached(&gone));
        assert!(!cached(&removed_integration));
        // Nothing to drop when nothing went away.
        assert_eq!(forget_removed_credentials(&after, &after), 0);
        assert!(cached(&kept));

        // A role whose ARN moved to another account keeps its id, but its
        // credentials are the old account's.
        let role = |account: &str| {
            Profile::new(
                "prune",
                "ops",
                "Deploy",
                Target::AwsChained {
                    label: "ops".into(),
                    account_id: Some(account.into()),
                },
            )
        };
        let (old, moved) = (role("222222222222"), role("333333333333"));
        assert_eq!(old.id, moved.id);
        store::set(&store::credentials_key(&old.id), &Credentials::default()).unwrap();
        assert_eq!(forget_removed_credentials([&old], [&old]), 0);
        assert!(cached(&old));
        assert_eq!(forget_removed_credentials([&old], [&moved]), 1);
        assert!(!cached(&moved));
    }

    #[test]
    fn console_partition_comes_from_the_role_arn() {
        // The config check refuses a chained role outside the portal's
        // partition (it needs `cross_partition`), so this one is built
        // without it: the console still follows the ARN.
        let portal = &Integration::AwsSso(
            toml::from_str(
                r#"
                start_url = "https://acme.awsapps.com/start"
                region = "eu-west-1"
                [chained.gov]
                via_account_id = "111111111111"
                via_role = "Admin"
                role_arn = "arn:aws-us-gov:iam::222222222222:role/Audit"
                "#,
            )
            .unwrap(),
        );
        let config = Config::parse(
            r#"
            [integrations.user]
            type = "aws-iam"
            region = "cn-north-1"
            [integrations.user.roles.cn]
            role_arn = "arn:aws-cn:iam::333333333333:role/Admin"
            "#,
        )
        .unwrap();
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
                Partition::China,
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

    #[tokio::test]
    async fn cross_partition_profiles_are_aws_profiles_in_the_destination_partition() {
        let config = Config::parse(
            r#"
            [integrations.portal]
            type = "aws-sso"
            start_url = "https://acme.awsapps.com/start"
            region = "us-east-1"
            console_duration = "4h"
            [integrations.portal.cross_partition.gov-audit]
            via_account_id = "111111111111"
            via_role = "AdministratorAccess"
            role_arn = "arn:aws-us-gov:iam::222222222222:role/Audit"
            audience = "omnifob"
            region = "us-gov-west-1"
            "#,
        )
        .unwrap();
        let target = Target::AwsCrossPartition {
            label: "gov-audit".into(),
            account_id: "222222222222".into(),
        };
        let profile = Profile::new("portal", "gov-audit", "Audit", target.clone());
        let portal = config.integration("portal").unwrap();

        assert_eq!(aws_account_id(&config, &profile), Some("222222222222"));
        assert_eq!(
            aws_console_partition("portal", portal, &target).unwrap(),
            Partition::UsGov
        );
        assert!(console_needs_credentials(&profile));
        // The integration's console_duration is for Identity Center roles;
        // the flag applies.
        let hours = |h| ConsoleOptions {
            duration: Some(jiff::SignedDuration::from_hours(h)),
            ..Default::default()
        };
        assert_eq!(
            console_session_duration(portal, &profile, &ConsoleOptions::default()).unwrap(),
            None
        );
        // Whether the federation endpoint takes SessionDuration for these
        // credentials is unconfirmed, so a length is refused.
        let error = check_console_options(&config, &profile, &hours(2)).unwrap_err();
        assert!(
            error.to_string().contains("cannot be given a length yet"),
            "{error}"
        );
        // A console Region must be in the destination partition.
        let region = |r: &str| ConsoleOptions {
            region: Some(r.into()),
            ..Default::default()
        };
        assert!(check_console_options(&config, &profile, &region("us-gov-east-1")).is_ok());
        assert!(check_console_options(&config, &profile, &region("us-east-1")).is_err());
    }

    /// The sign-in host and console for a commercial portal's role in each
    /// other partition: the destination partition's, in the destination
    /// Region unless `--region` names another one there.
    #[test]
    fn cross_partition_consoles_open_in_the_destination_partition() {
        let config = Config::parse(
            r#"
            [integrations.portal]
            type = "aws-sso"
            start_url = "https://acme.awsapps.com/start"
            region = "us-east-1"
            [integrations.portal.cross_partition.gov]
            via_account_id = "111111111111"
            via_role = "Admin"
            role_arn = "arn:aws-us-gov:iam::222222222222:role/Audit"
            audience = "omnifob"
            region = "us-gov-east-1"
            [integrations.portal.cross_partition.cn]
            via_account_id = "111111111111"
            via_role = "Admin"
            role_arn = "arn:aws-cn:iam::333333333333:role/Audit"
            audience = "omnifob"
            region = "cn-northwest-1"
            [integrations.portal.cross_partition.eusc]
            via_account_id = "111111111111"
            via_role = "Admin"
            role_arn = "arn:aws-eusc:iam::444444444444:role/Audit"
            audience = "omnifob"
            region = "eusc-de-east-1"
            "#,
        )
        .unwrap();
        let integration = config.integration("portal").unwrap();
        let Integration::AwsSso(c) = integration else {
            unreachable!()
        };
        let endpoints = |label: &str, options: &ConsoleOptions, exported: bool| {
            let target = Target::AwsCrossPartition {
                label: label.into(),
                account_id: c.cross_partition[label].account_id().into(),
            };
            let mut creds = Credentials::default();
            if exported {
                creds
                    .env
                    .insert("AWS_REGION".into(), c.cross_partition[label].region.clone());
            }
            let request = cross_partition_console_request(
                "portal",
                integration,
                c,
                label,
                &target,
                &creds,
                options,
                None,
            )
            .unwrap();
            aws::console::console_endpoints(&request).unwrap()
        };
        let none = ConsoleOptions::default();
        for exported in [true, false] {
            assert_eq!(
                endpoints("gov", &none, exported),
                (
                    "https://us-gov-east-1.signin.amazonaws-us-gov.com/federation".to_string(),
                    "https://us-gov-east-1.console.amazonaws-us-gov.com/console/home?region=us-gov-east-1"
                        .to_string()
                ),
            );
            assert_eq!(
                endpoints("cn", &none, exported),
                (
                    "https://cn-northwest-1.signin.amazonaws.cn/federation".to_string(),
                    "https://cn-northwest-1.console.amazonaws.cn/console/home?region=cn-northwest-1"
                        .to_string()
                ),
            );
            assert_eq!(
                endpoints("eusc", &none, exported),
                (
                    "https://eusc-de-east-1.signin.amazonaws-eusc.eu/federation".to_string(),
                    "https://eusc-de-east-1.console.amazonaws-eusc.eu/console/home?region=eusc-de-east-1"
                        .to_string()
                ),
            );
        }
        // --region picks another Region of the destination partition.
        let west = ConsoleOptions {
            region: Some("us-gov-west-1".into()),
            service: Some("s3".into()),
            ..Default::default()
        };
        let (signin, destination) = endpoints("gov", &west, true);
        assert_eq!(signin, "https://signin.amazonaws-us-gov.com/federation");
        assert_eq!(
            destination,
            "https://console.amazonaws-us-gov.com/s3/home?region=us-gov-west-1"
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
