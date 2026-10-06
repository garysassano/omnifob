//! Provider dispatch: each integration kind implements sign-in, discovery,
//! credentials and a console link.

pub mod aws_sso;
pub mod cloudflare;
pub mod token;

use jiff::Timestamp;

use crate::{Config, Credentials, Integration, Profile, Result, Target, store};

/// Discovers every profile an integration offers.
pub async fn discover(name: &str, integration: &Integration) -> Result<Vec<Profile>> {
    match integration {
        Integration::AwsSso(config) => aws_sso::discover(name, config).await,
        Integration::Cloudflare(config) => cloudflare::discover(name, config).await,
        Integration::Token(config) => Ok(token::discover(name, config)),
    }
}

/// Removes the stored sign-in of an integration; returns whether one existed.
pub fn logout(name: &str, integration: &Integration) -> anyhow::Result<bool> {
    match integration {
        Integration::AwsSso(_) => aws_sso::logout(name),
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
        Integration::Token(_) => {
            if token::has_secrets(name)? {
                SignIn::Token
            } else {
                SignIn::SignedOut
            }
        }
        Integration::Cloudflare(_) => {
            if cloudflare::has_bootstrap_token(name)? {
                SignIn::Token
            } else {
                SignIn::SignedOut
            }
        }
    })
}

/// Returns credentials for a profile, reusing cached ones while they are fresh.
///
/// `ttl` asks for a lifetime other than the configured one. Only minted
/// credentials (Cloudflare) can honour it; it always mints anew.
pub async fn credentials(
    config: &Config,
    profile: &Profile,
    use_cache: bool,
    ttl: Option<jiff::SignedDuration>,
) -> Result<Credentials> {
    if ttl.is_some() && !matches!(profile.target, Target::Cloudflare { .. }) {
        return Err(anyhow::anyhow!(match profile.target {
            Target::Aws { .. } => "--ttl does not apply to AWS: the session length is set by the permission set in IAM Identity Center",
            _ => "--ttl only applies to Cloudflare profiles; this token does not expire",
        })
        .into());
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

    let fresh = Credentials {
        issued_at: Some(Timestamp::now()),
        ..fresh
    };
    if let Err(e) = store::set(&key, &fresh) {
        tracing::warn!("could not cache credentials: {e:#}");
    }
    Ok(fresh)
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
            aws_sso::console_url(creds, c.default_region.as_deref()).await?
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
            cloudflare::revoke(&profile.integration, c, &profile.id, account_id).await?,
        ),
        _ => Revoked::CacheOnly,
    };
    store::delete(&store::credentials_key(&profile.id))?;
    Ok(revoked)
}

/// Drops cached credentials for every profile in `profiles`.
pub fn forget_credentials<'a>(profiles: impl IntoIterator<Item = &'a Profile>) {
    for profile in profiles {
        let _ = store::delete(&store::credentials_key(&profile.id));
    }
}
