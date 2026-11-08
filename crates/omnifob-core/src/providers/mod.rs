//! Provider dispatch: each integration kind implements sign-in, discovery,
//! credentials and a console link.

pub mod aws_iam;
pub mod aws_sso;
pub mod cloudflare;
pub mod cloudflare_oauth;
pub mod token;

use jiff::Timestamp;

use crate::{Config, Credentials, Error, Integration, Profile, Result, Target, store};

/// Discovers every profile an integration offers.
pub async fn discover(name: &str, integration: &Integration) -> Result<Vec<Profile>> {
    match integration {
        Integration::AwsSso(config) => aws_sso::discover(name, config).await,
        Integration::AwsIam(config) => aws_iam::discover(name, config).await,
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
/// the given accounts; returns how many. Called before signing out.
pub async fn revoke_all(
    name: &str,
    integration: &Integration,
    account_ids: &[String],
) -> Result<usize> {
    let Integration::Cloudflare(config) = integration else {
        return Ok(0);
    };
    let mut deleted = 0;
    for account_id in account_ids {
        deleted += cloudflare::revoke(name, config, None, account_id).await?;
        if config.token_type == crate::config::CloudflareTokenType::User {
            break; // user tokens are listed once, not per account
        }
    }
    Ok(deleted)
}

/// Removes the stored sign-in of an integration; returns whether one existed.
pub fn logout(name: &str, integration: &Integration) -> anyhow::Result<bool> {
    match integration {
        Integration::AwsSso(_) => aws_sso::logout(name),
        Integration::AwsIam(_) => aws_iam::logout(name),
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
/// Cloudflare tokens and AWS sessions omnifob starts itself (chained roles,
/// IAM users and their roles) honour it, and always get new credentials.
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

/// Returns a URL that opens the provider's web console as this profile.
pub async fn console_url(
    config: &Config,
    profile: &Profile,
    creds: &Credentials,
) -> Result<String> {
    let integration = config.integration(&profile.integration)?;
    Ok(match (integration, &profile.target) {
        (Integration::AwsSso(c), Target::Aws { .. }) => {
            aws_sso::console_url(creds, &c.region, c.default_region.as_deref()).await?
        }
        (Integration::AwsSso(c), Target::AwsChained { .. }) => {
            let region = creds.env.get("AWS_REGION").map(String::as_str);
            aws_sso::console_url(creds, &c.region, region).await?
        }
        (Integration::AwsIam(c), Target::AwsIamSession { .. }) => {
            aws_iam::console_url(&profile.integration, c).await?
        }
        (Integration::AwsIam(c), Target::AwsIamRole { .. }) => {
            let region = creds.env.get("AWS_REGION").map(String::as_str);
            let home = c.region.as_deref().unwrap_or("us-east-1");
            aws_sso::console_url(creds, home, region).await?
        }
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
        Integration::AwsSso(_) | Integration::AwsIam(_) => {
            let (from, to) = match integration {
                Integration::AwsSso(_) => (aws_sso::keys(old), aws_sso::keys(new)),
                _ => (aws_iam::keys(old), aws_iam::keys(new)),
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
