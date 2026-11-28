//! `fob discover aws`: roles an Identity Center role may assume, in its own
//! account or another account of the integration, which Identity Center
//! does not list.
//!
//! For each account, the credentials of one of its sources (a permission
//! set) list its IAM roles (`iam:ListRoles`). For each source, fob keeps
//! the roles of every listed account whose trust policy lets the source's
//! account, or the source role itself, call `sts:AssumeRole`, and asks the
//! policy simulator
//! (`iam:SimulatePrincipalPolicy`) whether the source role's own policies
//! allow it. Nothing is assumed, so no `AssumeRole` reaches CloudTrail.
//!
//! The answer is a guess: the simulator evaluates the source role's
//! identity policies, permissions boundary and the organization's service
//! control policies it can see, but not resource control policies, and
//! fob evaluates only the trust-policy conditions on the source's own
//! principal keys (its ARN, account and type), describing the others (MFA,
//! tags, external IDs). A role it finds can still refuse, and one it misses
//! may work.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, anyhow};
use futures_util::StreamExt;
use serde_json::Value;

use super::partition::Partition;
use super::service_endpoint;
use crate::config::{AwsSsoConfig, ChainedRole};
use crate::{Code, Credentials, Result};

/// The variable the AWS CLI and SDKs read for IAM's endpoint.
pub(crate) const IAM_ENDPOINT_VARIABLE: &str = "AWS_ENDPOINT_URL_IAM";

/// How many accounts are searched at once: each is a handful of IAM calls,
/// and IAM throttles an account's callers together.
const CONCURRENCY: usize = 4;

/// How many roles one `SimulatePrincipalPolicy` call evaluates. IAM
/// documents no limit and answered 1,000 in one call when tried; 100 keeps
/// requests small.
const SIMULATED_PER_CALL: usize = 100;

/// The most items IAM returns in one page, instead of its default of 100.
const MAX_ITEMS: &str = "1000";

/// How many times an IAM call is tried when IAM throttles it or fails on
/// its side, as the AWS SDKs' adaptive retry mode does.
const ATTEMPTS: u32 = 8;

/// Where to look: an account, its segment in profile ids, and the
/// permission set whose credentials search it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub account_id: String,
    pub segment: String,
    pub via_role: String,
    /// The profile of the account and permission set, whose cached
    /// credentials are used while they are fresh.
    pub profile_id: String,
}

/// A role a source may assume, as a chained role, labelled after the
/// account segment and the role name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub label: String,
    pub role: ChainedRole,
    /// What the role needs that fob could not check, such as an external
    /// ID or MFA in its trust policy, or context the source's own policies
    /// check; empty when nothing.
    pub conditions: Vec<String>,
    /// Other permission sets of the account that may assume it too.
    pub also_via: Vec<String>,
    /// How fob decided the source may assume it.
    pub basis: Basis,
}

/// A source fob could not search, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub source: Source,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Discovery {
    pub found: Vec<Found>,
    pub skipped: Vec<Skipped>,
    /// Roles left out because their trust policy could not be read.
    pub unreadable: Vec<String>,
}

/// How fob decided that a source may assume a role it found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Basis {
    /// The policy simulator allowed it.
    #[default]
    Simulated,
    /// The simulator was refused, so fob read the source's own policies:
    /// SCPs, the permissions boundary and session policies are not checked.
    Estimated,
    /// Neither the simulator nor the source's policies could be read; only
    /// the role's trust policy lets the source in (`--trust-only`).
    TrustOnly,
}

impl Basis {
    pub fn as_str(self) -> &'static str {
        match self {
            Basis::Simulated => "simulated",
            Basis::Estimated => "estimated",
            Basis::TrustOnly => "trust-only",
        }
    }
}

/// Where the sources' credentials come from.
pub enum Origin<'a> {
    /// An `aws-sso` integration: each source is a permission set.
    Sso(&'a AwsSsoConfig),
    /// An `aws-iam` or `aws-login` integration: the one source is its own
    /// identity (an IAM user, or the console sign-in's user or role), with
    /// the credentials of `profile`, its session profile.
    Identity {
        config: &'a crate::Config,
        profile: &'a crate::Profile,
        partition: Partition,
        /// Where STS is asked whom the credentials act as.
        sts_region: String,
    },
}

impl<'a> Origin<'a> {
    /// The origin of an `aws-iam` or `aws-login` integration's session
    /// profile `profile`.
    pub fn identity(
        config: &'a crate::Config,
        profile: &'a crate::Profile,
    ) -> anyhow::Result<Self> {
        let (partition, sts_region) = match config.integration(&profile.integration)? {
            crate::Integration::AwsIam(c) => {
                let region = super::iam::sts_region(c);
                (Partition::of_region(region)?, region.to_string())
            }
            crate::Integration::AwsLogin(c) => (super::login::partition(c)?, c.region.clone()),
            other => anyhow::bail!(
                "'{}' is a {} integration; only aws-sso, aws-iam and aws-login are searched",
                profile.integration,
                other.kind()
            ),
        };
        Ok(Origin::Identity {
            config,
            profile,
            partition,
            sts_region,
        })
    }

    fn partition(&self) -> anyhow::Result<Partition> {
        match self {
            Origin::Sso(config) => config.partition(),
            Origin::Identity { partition, .. } => Ok(*partition),
        }
    }

    /// What a source is called in messages.
    fn who(&self) -> &'static str {
        match self {
            Origin::Sso(_) => "the permission set",
            Origin::Identity { .. } => "the identity",
        }
    }
}

/// How to search.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Options {
    /// When neither the simulator nor the source's policies can be read,
    /// keep the roles whose trust policy lets the source in, as
    /// [`Basis::TrustOnly`], instead of skipping the source.
    pub trust_only: bool,
}

/// Searches every source of an `aws-sso` integration; see [`discover_from`].
pub async fn discover(
    integration: &str,
    config: &AwsSsoConfig,
    sources: Vec<Source>,
) -> Result<Discovery> {
    discover_from(
        integration,
        &Origin::Sso(config),
        sources,
        Options::default(),
    )
    .await
}

/// Searches every source, a few accounts at a time. A sign-in that has
/// ended or a locked vault fails the whole search, since no source can
/// succeed and the caller can sign in or unlock; anything else skips the
/// sources it concerns, with the reason.
pub async fn discover_from(
    integration: &str,
    origin: &Origin<'_>,
    sources: Vec<Source>,
    options: Options,
) -> Result<Discovery> {
    let mut accounts: BTreeMap<String, Vec<Source>> = BTreeMap::new();
    for source in sources {
        accounts
            .entry(source.account_id.clone())
            .or_default()
            .push(source);
    }
    let partition = origin.partition()?;
    // Every account's roles first, so each source can be matched against the
    // roles of the integration's other accounts as well as its own.
    let listed: Vec<Result<(Lister, Option<AccountRoles>)>> = futures_util::stream::iter(
        accounts
            .into_values()
            .map(|sources| list_account(integration, origin, partition, sources)),
    )
    .buffer_unordered(CONCURRENCY)
    .collect()
    .await;
    let mut listers = Vec::new();
    let mut listings = Vec::new();
    for result in listed {
        let (lister, roles) = result?;
        listers.push(lister);
        listings.extend(roles);
    }
    let listings = &listings;
    let results: Vec<Result<Discovery>> = futures_util::stream::iter(
        listers
            .into_iter()
            .map(|lister| search_account(lister, listings, partition, options)),
    )
    .buffer_unordered(CONCURRENCY)
    .collect()
    .await;
    let mut discovery = Discovery::default();
    for result in results {
        let found = result?;
        discovery.found.extend(found.found);
        discovery.skipped.extend(found.skipped);
        discovery.unreadable.extend(found.unreadable);
    }
    // A role several permission sets of an account may assume is one table,
    // from the first of them by name, so the result does not depend on the
    // order the searches finished in.
    discovery
        .found
        .sort_by(|a, b| (&a.label, &a.role.via_role).cmp(&(&b.label, &b.role.via_role)));
    let mut kept: Vec<Found> = Vec::new();
    for found in discovery.found {
        match kept.last_mut() {
            Some(last) if last.label == found.label => last.also_via.push(found.role.via_role),
            _ => kept.push(found),
        }
    }
    discovery.found = kept;
    discovery.skipped.sort_by(|a, b| {
        (&a.source.segment, &a.source.via_role).cmp(&(&b.source.segment, &b.source.via_role))
    });
    discovery.unreadable.sort();
    discovery.unreadable.dedup();
    Ok(discovery)
}

/// Whether a role is one that tooling assumes for itself, which a person
/// rarely wants as a profile: the CDK bootstrap roles
/// (`cdk-<qualifier>-{deploy,file-publishing,image-publishing,lookup,cfn-exec}-role-<account>-<region>`),
/// which the CDK CLI assumes on its own, and CloudFormation's StackSet
/// execution role.
pub fn is_tooling(role_name: &str) -> bool {
    const CDK: [&str; 5] = [
        "-deploy-role-",
        "-file-publishing-role-",
        "-image-publishing-role-",
        "-lookup-role-",
        "-cfn-exec-role-",
    ];
    (role_name.starts_with("cdk-") && CDK.iter().any(|kind| role_name.contains(kind)))
        || role_name == "AWSCloudFormationStackSetExecutionRole"
}

/// Whether `error` concerns every source, not just the one it came from.
fn stops_everything(error: crate::Error) -> std::result::Result<String, crate::Error> {
    if matches!(error, crate::Error::NeedsLogin { .. }) {
        return Err(error);
    }
    let error = anyhow::Error::from(error);
    match crate::classify(&error).0 {
        Code::LoginRequired | Code::VaultLocked => Err(error.into()),
        _ => Ok(format!("{error:#}")),
    }
}

/// An account's roles, as one of its permission sets listed them.
struct AccountRoles {
    account_id: String,
    /// The account's segment in profile ids.
    segment: String,
    roles: Vec<Role>,
}

/// One account's sources and their clients, and the permission set that
/// listed its roles, or why none could, for each.
struct Lister<'a> {
    sources: Vec<Source>,
    clients: Clients<'a>,
    listed: std::result::Result<String, BTreeMap<String, String>>,
}

/// Lists an account's roles once, with the first of its sources by name
/// whose credentials may.
async fn list_account<'a>(
    integration: &'a str,
    origin: &'a Origin<'a>,
    partition: Partition,
    mut sources: Vec<Source>,
) -> Result<(Lister<'a>, Option<AccountRoles>)> {
    sources.sort_by(|a, b| a.via_role.cmp(&b.via_role));
    let mut clients = Clients {
        integration,
        origin,
        partition,
        made: BTreeMap::new(),
    };
    let mut refused = BTreeMap::new();
    let mut listed = None;
    for source in &sources {
        let iam = match clients.get(source).await? {
            Ok(iam) => iam,
            Err(reason) => {
                refused.insert(source.via_role.clone(), reason);
                continue;
            }
        };
        match iam.list_roles().await {
            Ok(roles) => {
                listed = Some((source.via_role.clone(), roles));
                break;
            }
            Err(e) => {
                refused.insert(source.via_role.clone(), stops_everything(e)?);
            }
        }
    }
    let (listed, roles) = match listed {
        Some((lister, roles)) => (
            Ok(lister),
            Some(AccountRoles {
                account_id: sources[0].account_id.clone(),
                segment: sources[0].segment.clone(),
                roles,
            }),
        ),
        None => (Err(refused), None),
    };
    Ok((
        Lister {
            sources,
            clients,
            listed,
        },
        roles,
    ))
}

/// The roles the sources of one account may assume, in their account or
/// another one listed. Every source is simulated, with the lister's
/// credentials or its own: a permission set that may not list roles can
/// still be simulated by one that may, and one that may list but not
/// simulate does not stop the others.
async fn search_account(
    lister: Lister<'_>,
    listings: &[AccountRoles],
    partition: Partition,
    options: Options,
) -> Result<Discovery> {
    let Lister {
        sources,
        mut clients,
        listed,
    } = lister;
    let mut discovery = Discovery::default();
    let lister = match listed {
        Ok(lister) => lister,
        Err(mut refused) => {
            discovery.skipped = sources
                .iter()
                .map(|source| Skipped {
                    source: source.clone(),
                    reason: refused.remove(&source.via_role).unwrap_or_default(),
                })
                .collect();
            return Ok(discovery);
        }
    };
    for source in &sources {
        match search(&mut clients, &lister, listings, partition, source, options).await {
            Ok((found, unreadable)) => {
                discovery.found.extend(found);
                discovery.unreadable.extend(unreadable);
            }
            Err(e) => discovery.skipped.push(Skipped {
                source: source.clone(),
                reason: stops_everything(e)?,
            }),
        }
    }
    Ok(discovery)
}

/// An IAM client per source of an account, made the first time it is
/// needed, or why it could not be.
struct Clients<'a> {
    integration: &'a str,
    origin: &'a Origin<'a>,
    partition: Partition,
    made: BTreeMap<String, std::result::Result<Iam, String>>,
}

impl Clients<'_> {
    /// The client of `source`; `Err` only for an error that stops every
    /// search.
    async fn get(&mut self, source: &Source) -> Result<std::result::Result<&Iam, String>> {
        if !self.made.contains_key(&source.via_role) {
            let made = async {
                let creds = source_credentials(self.integration, self.origin, source).await?;
                let mut iam = Iam::new(&creds, self.partition, self.origin.who())?;
                // An identity's ARN is not in its account's roles, as a
                // permission set's role is: STS says whom it acts as.
                if let Origin::Identity { sts_region, .. } = self.origin {
                    iam.caller = Some(super::sts::caller_identity(&creds, sts_region).await?.arn);
                }
                Ok::<_, crate::Error>(iam)
            }
            .await;
            let made = match made {
                Ok(iam) => Ok(iam),
                Err(e) => Err(stops_everything(e)?),
            };
            self.made.insert(source.via_role.clone(), made);
        }
        Ok(self.made[&source.via_role].as_ref().map_err(Clone::clone))
    }

    /// The client of a source already made.
    fn made(&self, via_role: &str) -> Option<&Iam> {
        self.made.get(via_role).and_then(|m| m.as_ref().ok())
    }
}

/// A source's credentials: those cached for its profile while they are
/// fresh, as `fob exec` would use them, or new ones, which are cached.
async fn source_credentials(
    integration: &str,
    origin: &Origin<'_>,
    source: &Source,
) -> Result<Credentials> {
    let config = match origin {
        Origin::Sso(config) => config,
        Origin::Identity {
            config, profile, ..
        } => return crate::providers::credentials(config, profile, true, None).await,
    };
    let key = crate::store::credentials_key(&source.profile_id);
    let now = jiff::Timestamp::now();
    match crate::store::get::<Credentials>(&key) {
        Ok(Some(cached)) if cached.is_fresh(now) => return Ok(cached),
        Ok(_) => {}
        Err(e) => tracing::debug!("ignoring unreadable cached credentials: {e:#}"),
    }
    let fresh =
        super::sso::credentials(integration, config, &source.account_id, &source.via_role).await?;
    let fresh = Credentials {
        issued_at: Some(now),
        ..fresh
    };
    if let Err(e) = crate::store::set(&key, &fresh) {
        tracing::warn!("could not cache credentials: {e:#}");
    }
    Ok(fresh)
}

/// The principal a source signs requests as: its ARN (a role's, path
/// included, for a role session) and whether it is an IAM user.
fn principal(
    clients: &Clients<'_>,
    roles: &[Role],
    source: &Source,
) -> anyhow::Result<(String, bool)> {
    if let Origin::Identity { .. } = clients.origin {
        let caller = clients
            .made(&source.via_role)
            .and_then(|iam| iam.caller.clone())
            .context("no caller identity for the source")?;
        return identity_principal(&caller, roles);
    }
    // The role Identity Center made for the permission set in this account:
    // `AWSReservedSSO_<permission set>_<16 hex digits>`, so a permission set
    // named `Admin` does not take `AWSReservedSSO_Admin_ReadOnly_...`.
    let prefix = format!("AWSReservedSSO_{}_", source.via_role);
    let arn = roles
        .iter()
        .find(|r| {
            r.path.starts_with("/aws-reserved/")
                && r.name
                    .strip_prefix(&prefix)
                    .is_some_and(|id| id.len() == 16 && id.bytes().all(|b| b.is_ascii_hexdigit()))
        })
        .map(|r| r.arn.clone())
        .with_context(|| {
            format!(
                "no {prefix}* role among the account's roles, so the permission set's role is \
                 unknown"
            )
        })?;
    Ok((arn, false))
}

/// The principal behind a caller ARN from `GetCallerIdentity`: an IAM user
/// as it is, and a role session (`arn:aws:sts::<account>:assumed-role/<name>/<session>`)
/// as its role, whose path only the account's roles tell. The simulator
/// takes no session ARNs.
fn identity_principal(caller: &str, roles: &[Role]) -> anyhow::Result<(String, bool)> {
    if caller.contains(":user/") {
        return Ok((caller.to_string(), true));
    }
    if let Some((_, rest)) = caller.split_once(":assumed-role/") {
        let name = rest.split('/').next().unwrap_or_default();
        return roles
            .iter()
            .find(|r| r.name == name)
            .map(|r| (r.arn.clone(), false))
            .with_context(|| {
                format!("the role {name} of {caller} is not among the account's roles")
            });
    }
    anyhow::bail!(
        "{caller} is neither an IAM user nor a role session, which discovery searches for"
    )
}

/// The roles of the listed accounts that one source may assume, and those
/// whose trust policy could not be read. The simulator is called with the
/// credentials of `lister`, the source that listed the source's account,
/// or with the source's own when `lister`'s may not call it.
async fn search(
    clients: &mut Clients<'_>,
    lister: &str,
    listings: &[AccountRoles],
    partition: Partition,
    source: &Source,
    options: Options,
) -> Result<(Vec<Found>, Vec<String>)> {
    let roles = &listings
        .iter()
        .find(|a| a.account_id == source.account_id)
        .context("the source's account was not listed")?
        .roles;
    let (source_arn, user) = principal(clients, roles, source)?;
    let root = format!(
        "arn:{}:iam::{}:root",
        partition.arn_name(),
        source.account_id
    );
    let requester = Requester {
        account_id: &source.account_id,
        root: &root,
        arn: &source_arn,
        user,
    };
    let mut candidates = Vec::new();
    let mut unreadable = Vec::new();
    for account in listings {
        for role in &account.roles {
            if role.arn == source_arn
                || role.path.starts_with("/aws-service-role/")
                || role.path.starts_with("/aws-reserved/")
            {
                continue;
            }
            let Some(document) = &role.trust else {
                continue;
            };
            match trusts(document, &requester) {
                Ok(Some(trust)) => candidates.push((account, role, trust)),
                Ok(None) => {}
                // One role's policy does not end the account's search.
                Err(e) => unreadable.push(format!("{} ({e:#})", role.arn)),
            }
        }
    }
    let arns: Vec<&str> = candidates.iter().map(|(_, r, _)| r.arn.as_str()).collect();
    let mut kept = Vec::new();
    match simulate(clients, lister, source, &requester, &arns).await? {
        Simulation::Decided(simulator, decisions) => {
            for (account, role, trust) in candidates {
                let Some(decision) = decisions.get(&role.arn) else {
                    continue;
                };
                let same_account = account.account_id == source.account_id;
                let mut conditions = trust.conditions;
                let assumable = match decision.decision.as_str() {
                    "allowed" => true,
                    // In its own account, a role whose trust policy names the
                    // source's ARN needs nothing from the source's policies,
                    // unless the organization's SCPs or the permissions
                    // boundary refuse, which the simulator reports for one
                    // role at a time. A boundary does not limit what a
                    // resource policy grants to a user's ARN. Another
                    // account's role always needs the source's policies too.
                    "implicitDeny"
                        if same_account
                            && trust.by_arn
                            && (user || decision.boundary != Some(false)) =>
                    {
                        let iam = clients
                            .made(&simulator)
                            .context("the simulating source has no client")?;
                        let alone = iam
                            .simulate_assume_role(&requester, &[role.arn.as_str()])
                            .await?;
                        alone.iter().any(|(_, d)| d.trust_alone_allows(user))
                    }
                    // Denied only for want of context the source's policies check.
                    "implicitDeny" if !decision.missing.is_empty() => {
                        conditions.push(format!(
                            "{}'s policies check {}, which the simulator was not given",
                            clients.origin.who(),
                            decision.missing.join(", ")
                        ));
                        true
                    }
                    _ => false,
                };
                if assumable {
                    kept.push((account, role, conditions, Basis::Simulated));
                }
            }
        }
        Simulation::Refused(reason) => {
            match estimate(clients, lister, source, &requester).await {
                Ok(statements) => {
                    let note = format!(
                        "estimated from {}'s own policies, since the simulator was refused: SCPs, \
                         the permissions boundary and session policies are not checked",
                        clients.origin.who()
                    );
                    for (account, role, trust) in candidates {
                        let same_account = account.account_id == source.account_id;
                        let mut conditions = trust.conditions;
                        let assumable = match allows(&statements, &role.arn) {
                            Answer::No => false,
                            // Its own trust naming the source is enough in
                            // its account, unless the source's policies deny.
                            _ if same_account && trust.by_arn => {
                                denies(&statements, &role.arn, &mut conditions)
                            }
                            Answer::Yes => denies(&statements, &role.arn, &mut conditions),
                            Answer::Unknown(notes) => {
                                conditions.extend(notes);
                                denies(&statements, &role.arn, &mut conditions)
                            }
                        };
                        if assumable {
                            conditions.push(note.clone());
                            kept.push((account, role, conditions, Basis::Estimated));
                        }
                    }
                }
                Err(e) if is_denied(&e) && options.trust_only => {
                    for (account, role, trust) in candidates {
                        let mut conditions = trust.conditions;
                        conditions.push(format!(
                            "not checked against {}'s policies: neither the simulator nor the \
                             policies could be read",
                            clients.origin.who()
                        ));
                        kept.push((account, role, conditions, Basis::TrustOnly));
                    }
                }
                Err(e) if is_denied(&e) => {
                    return Err(anyhow!(
                        "{reason}, nor read its policies; {} role(s) trust it (pass --trust-only \
                         to list them)",
                        arns.len()
                    )
                    .into());
                }
                Err(e) => return Err(e),
            }
        }
    }
    let identity = matches!(clients.origin, Origin::Identity { .. });
    let found = kept
        .into_iter()
        .map(|(account, role, conditions, basis)| {
            let same_account = account.account_id == source.account_id;
            // An identity's roles are labelled after the role alone; a
            // permission set's after its account, and another account's role
            // after both accounts.
            let label = match (identity, same_account) {
                (true, true) => crate::profile::slug(&role.name),
                (true, false) => {
                    format!("{}-{}", account.segment, crate::profile::slug(&role.name))
                }
                (false, true) => format!("{}-{}", source.segment, crate::profile::slug(&role.name)),
                (false, false) => format!(
                    "{}-{}-{}",
                    source.segment,
                    account.segment,
                    crate::profile::slug(&role.name)
                ),
            };
            Found {
                label,
                role: ChainedRole {
                    via_account_id: source.account_id.clone(),
                    via_role: source.via_role.clone(),
                    role_arn: role.arn.clone(),
                    session_name: None,
                    external_id: None,
                    region: None,
                    mfa_serial: None,
                    duration: None,
                },
                conditions,
                also_via: Vec::new(),
                basis,
            }
        })
        .collect();
    Ok((found, unreadable))
}

/// What the simulator answered, or why nobody could ask it.
enum Simulation {
    /// Each role's answer, and the source whose credentials asked.
    Decided(String, BTreeMap<String, Decision>),
    Refused(String),
}

/// The simulator's answer for each of `arns`, asked with `lister`'s
/// credentials, or with the source's own when `lister`'s may not call the
/// simulator.
async fn simulate(
    clients: &mut Clients<'_>,
    lister: &str,
    source: &Source,
    requester: &Requester<'_>,
    arns: &[&str],
) -> Result<Simulation> {
    if arns.is_empty() {
        return Ok(Simulation::Decided(lister.to_string(), BTreeMap::new()));
    }
    let iam = clients
        .made(lister)
        .context("the source that listed the roles has no client")?;
    match simulate_with(iam, requester, arns).await {
        Err(e) if is_denied(&e) && source.via_role != lister => {}
        Err(e) if is_denied(&e) => return Ok(Simulation::Refused(format!("{e:#}"))),
        other => return other.map(|d| Simulation::Decided(lister.to_string(), d)),
    }
    let own = match clients.get(source).await? {
        Ok(iam) => iam,
        Err(reason) => {
            return Ok(Simulation::Refused(format!(
                "{lister} may not call iam:SimulatePrincipalPolicy, and {reason}"
            )));
        }
    };
    match simulate_with(own, requester, arns).await {
        Ok(decisions) => Ok(Simulation::Decided(source.via_role.clone(), decisions)),
        Err(e) if is_denied(&e) => Ok(Simulation::Refused(format!(
            "neither it nor {lister} may call iam:SimulatePrincipalPolicy"
        ))),
        Err(e) => Err(e),
    }
}

/// The statements of the source principal's own policies (attached and
/// inline, and its groups' for an IAM user), read with `lister`'s
/// credentials or the source's own.
async fn estimate(
    clients: &mut Clients<'_>,
    lister: &str,
    source: &Source,
    requester: &Requester<'_>,
) -> Result<Vec<Value>> {
    if let Some(iam) = clients.made(lister) {
        match iam.principal_statements(requester).await {
            Err(e) if is_denied(&e) && source.via_role != lister => {}
            other => return other,
        }
    }
    match clients.get(source).await? {
        Ok(iam) => iam.principal_statements(requester).await,
        Err(reason) => {
            Err(anyhow::Error::new(Denied(format!("its policies ({reason})"), "the source")).into())
        }
    }
}

/// Whether the statements of an identity policy allow `sts:AssumeRole` on
/// `arn`; conditions are described, not evaluated.
fn allows(statements: &[Value], arn: &str) -> Answer {
    let mut answer = Answer::No;
    for statement in statements {
        if statement["Effect"] != "Allow" || !grants(statement, arn) {
            continue;
        }
        let here = match statement.get("Condition") {
            Some(Value::Object(c)) if !c.is_empty() => Answer::Unknown(BTreeSet::from([format!(
                "the policy that allows it has conditions ({})",
                condition_keys(c)
            )])),
            _ => Answer::Yes,
        };
        answer = match (answer, here) {
            (Answer::Yes, _) | (_, Answer::Yes) => Answer::Yes,
            (Answer::Unknown(mut a), Answer::Unknown(b)) => {
                a.extend(b);
                Answer::Unknown(a)
            }
            (_, here) => here,
        };
    }
    answer
}

/// Whether nothing denies `sts:AssumeRole` on `arn` outright; a `Deny` with
/// conditions is described in `conditions`.
fn denies(statements: &[Value], arn: &str, conditions: &mut Vec<String>) -> bool {
    for statement in statements {
        if statement["Effect"] != "Deny" || !grants(statement, arn) {
            continue;
        }
        match statement.get("Condition") {
            Some(Value::Object(c)) if !c.is_empty() => conditions.push(format!(
                "a Deny statement may apply ({})",
                condition_keys(c)
            )),
            _ => return false,
        }
    }
    true
}

/// Whether a statement covers `sts:AssumeRole` on `arn`, its effect and
/// conditions aside.
fn grants(statement: &Value, arn: &str) -> bool {
    let assume = |patterns: &Value| {
        strings(patterns)
            .iter()
            .any(|a| wildcard(&a.to_ascii_lowercase(), "sts:assumerole"))
    };
    let action = match (statement.get("Action"), statement.get("NotAction")) {
        (Some(action), _) => assume(action),
        (None, Some(not)) => !assume(not),
        (None, None) => false,
    };
    let on = |patterns: &Value| strings(patterns).iter().any(|r| wildcard(r, arn));
    let resource = match (statement.get("Resource"), statement.get("NotResource")) {
        (Some(resource), _) => on(resource),
        (None, Some(not)) => !on(not),
        (None, None) => false,
    };
    action && resource
}

/// The condition keys of a statement, for a note.
fn condition_keys(conditions: &serde_json::Map<String, Value>) -> String {
    let keys: BTreeSet<&str> = conditions
        .values()
        .filter_map(Value::as_object)
        .flat_map(|keys| keys.keys().map(String::as_str))
        .collect();
    keys.into_iter().collect::<Vec<_>>().join(", ")
}

async fn simulate_with(
    iam: &Iam,
    requester: &Requester<'_>,
    arns: &[&str],
) -> Result<BTreeMap<String, Decision>> {
    let mut decisions = BTreeMap::new();
    for chunk in arns.chunks(SIMULATED_PER_CALL) {
        decisions.extend(iam.simulate_assume_role(requester, chunk).await?);
    }
    Ok(decisions)
}

/// The simulator's answer for one role.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Decision {
    /// `allowed`, `explicitDeny` or `implicitDeny`.
    decision: String,
    /// Context keys the source's policies check that the simulation lacked.
    missing: Vec<String>,
    /// Whether the source's permissions boundary allows it, when it has one.
    boundary: Option<bool>,
    /// Whether the organization's SCPs allow it, when IAM says so for this
    /// role alone (it does only at the top of a result, so only when the
    /// simulation had one role).
    organizations: Option<bool>,
}

impl Decision {
    /// Whether a trust policy naming the source's role ARN is enough: the
    /// source's identity policies may lack an allow, but nothing denies it,
    /// and neither the SCPs nor the permissions boundary withhold it (a
    /// boundary limits what a policy grants to a role ARN, though not to a
    /// session ARN or, for `user`, to an IAM user's ARN).
    fn trust_alone_allows(&self, user: bool) -> bool {
        match self.decision.as_str() {
            "allowed" => true,
            "implicitDeny" => {
                self.organizations != Some(false) && (user || self.boundary != Some(false))
            }
            _ => false,
        }
    }
}

/// IAM refused the call: the source (the second field, "the permission
/// set" or "the identity") may not make it.
#[derive(Debug, thiserror::Error)]
#[error("{1} may not call {0}")]
struct Denied(String, &'static str);

fn is_denied(e: &crate::Error) -> bool {
    matches!(e, crate::Error::Other(e) if e.downcast_ref::<Denied>().is_some())
}

/// An IAM role as `ListRoles` gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Role {
    path: String,
    name: String,
    arn: String,
    /// The trust policy, URL-encoded JSON.
    trust: Option<String>,
}

/// IAM's Query API, signed with a source's credentials. Two calls do not
/// justify the IAM SDK, which compiles every IAM operation.
struct Iam {
    http: reqwest::Client,
    url: String,
    region: &'static str,
    creds: aws_sdk_sts::config::Credentials,
    /// Whose credentials these are, in messages.
    who: &'static str,
    /// The ARN STS gives for the credentials, for an identity source.
    caller: Option<String>,
}

impl Iam {
    fn new(creds: &Credentials, partition: Partition, who: &'static str) -> anyhow::Result<Self> {
        let get = |k: &str| {
            creds
                .env
                .get(k)
                .cloned()
                .with_context(|| format!("{k} missing from the credentials"))
        };
        let creds = aws_sdk_sts::config::Credentials::new(
            get("AWS_ACCESS_KEY_ID")?,
            get("AWS_SECRET_ACCESS_KEY")?,
            creds.env.get("AWS_SESSION_TOKEN").cloned(),
            None,
            "omnifob",
        );
        let url = service_endpoint(IAM_ENDPOINT_VARIABLE)
            .unwrap_or_else(|| format!("https://{}/", iam_host(partition)));
        Ok(Self {
            http: crate::http::client(),
            url,
            region: partition.default_region(),
            creds,
            who,
            caller: None,
        })
    }

    /// The statements of the requester's own policies: a role's attached
    /// and inline policies, and an IAM user's and its groups'.
    async fn principal_statements(&self, requester: &Requester<'_>) -> Result<Vec<Value>> {
        let name = requester
            .arn
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_string();
        let mut entities = vec![(if requester.user { "User" } else { "Role" }, name.clone())];
        if requester.user {
            for group in self
                .list_all(
                    "ListGroupsForUser",
                    &[("UserName", name.clone())],
                    "GroupName",
                )
                .await?
            {
                entities.push(("Group", group));
            }
        }
        let mut documents = Vec::new();
        for (kind, name) in entities {
            let key = format!("{kind}Name");
            for arn in self
                .list_all(
                    &format!("ListAttached{kind}Policies"),
                    &[(key.as_str(), name.clone())],
                    "PolicyArn",
                )
                .await?
            {
                let policy = self
                    .call("GetPolicy", &[("PolicyArn", arn.clone())])
                    .await?;
                let version = leaves(&policy, &["DefaultVersionId"])
                    .context("reading iam:GetPolicy")?
                    .into_iter()
                    .next()
                    .map(|(_, v)| v)
                    .with_context(|| format!("no default version of {arn}"))?;
                let body = self
                    .call(
                        "GetPolicyVersion",
                        &[("PolicyArn", arn), ("VersionId", version)],
                    )
                    .await?;
                documents.extend(
                    leaves(&body, &["Document"])
                        .context("reading iam:GetPolicyVersion")?
                        .into_iter()
                        .map(|(_, d)| d),
                );
            }
            for policy in self
                .list_all(
                    &format!("List{kind}Policies"),
                    &[(key.as_str(), name.clone())],
                    "member",
                )
                .await?
            {
                let body = self
                    .call(
                        &format!("Get{kind}Policy"),
                        &[(key.as_str(), name.clone()), ("PolicyName", policy)],
                    )
                    .await?;
                documents.extend(
                    leaves(&body, &["PolicyDocument"])
                        .with_context(|| format!("reading iam:Get{kind}Policy"))?
                        .into_iter()
                        .map(|(_, d)| d),
                );
            }
        }
        let mut statements = Vec::new();
        for document in documents {
            let json = percent_decode(&document)?;
            let policy: Value = serde_json::from_str(&json).context("a policy that is not JSON")?;
            match &policy["Statement"] {
                Value::Array(list) => statements.extend(list.iter().cloned()),
                statement @ Value::Object(_) => statements.push(statement.clone()),
                _ => {}
            }
        }
        Ok(statements)
    }

    /// Every `field` of a paginated listing (`operation`, all pages).
    async fn list_all(
        &self,
        operation: &str,
        params: &[(&str, String)],
        field: &str,
    ) -> Result<Vec<String>> {
        let mut values = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let mut all: Vec<(&str, String)> = params.to_vec();
            all.push(("MaxItems", MAX_ITEMS.to_string()));
            if let Some(m) = &marker {
                all.push(("Marker", m.clone()));
            }
            let body = self.call(operation, &all).await?;
            let mut truncated = false;
            marker = None;
            for (name, value) in leaves(&body, &[field, "IsTruncated", "Marker"])
                .with_context(|| format!("reading iam:{operation}"))?
            {
                match name.as_str() {
                    "IsTruncated" => truncated = value == "true",
                    "Marker" => marker = Some(value),
                    _ => values.push(value),
                }
            }
            if !truncated || marker.is_none() {
                return Ok(values);
            }
        }
    }

    /// Every role in the account (`iam:ListRoles`, all pages).
    async fn list_roles(&self) -> Result<Vec<Role>> {
        let action = "iam:ListRoles";
        let mut roles = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let mut params = vec![
                ("Action", "ListRoles".to_string()),
                ("MaxItems", MAX_ITEMS.to_string()),
            ];
            if let Some(m) = &marker {
                params.push(("Marker", m.clone()));
            }
            let body = self.call("ListRoles", &params).await?;
            let page = parse_list_roles(&body).with_context(|| format!("reading {action}"))?;
            roles.extend(page.roles);
            match page.marker {
                Some(m) if page.truncated => marker = Some(m),
                _ => return Ok(roles),
            }
        }
    }

    /// The policy simulator's answer for the requester's `sts:AssumeRole`
    /// on each of `resources`. The context fob knows of the request (the
    /// source role's ARN, its account and its principal type) is given, so
    /// policies and SCPs that check those keys see them rather than finding
    /// them missing.
    async fn simulate_assume_role(
        &self,
        requester: &Requester<'_>,
        resources: &[&str],
    ) -> Result<Vec<(String, Decision)>> {
        let action = "iam:SimulatePrincipalPolicy";
        let mut decisions = Vec::new();
        let mut marker: Option<String> = None;
        let context = [
            ("aws:PrincipalArn", requester.arn),
            ("aws:PrincipalAccount", requester.account_id),
            ("aws:PrincipalType", requester.principal_type()),
        ];
        let context_params: Vec<(String, String)> = context
            .iter()
            .enumerate()
            .flat_map(|(i, (key, value))| {
                let entry = format!("ContextEntries.member.{}", i + 1);
                [
                    (format!("{entry}.ContextKeyName"), key.to_string()),
                    (format!("{entry}.ContextKeyType"), "string".to_string()),
                    (
                        format!("{entry}.ContextKeyValues.member.1"),
                        value.to_string(),
                    ),
                ]
            })
            .collect();
        loop {
            let mut params = vec![
                ("Action", "SimulatePrincipalPolicy".to_string()),
                ("PolicySourceArn", requester.arn.to_string()),
                ("ActionNames.member.1", "sts:AssumeRole".to_string()),
            ];
            for (name, value) in &context_params {
                params.push((name.as_str(), value.clone()));
            }
            let names: Vec<String> = (1..=resources.len())
                .map(|i| format!("ResourceArns.member.{i}"))
                .collect();
            for (name, arn) in names.iter().zip(resources) {
                params.push((name.as_str(), arn.to_string()));
            }
            if let Some(m) = &marker {
                params.push(("Marker", m.clone()));
            }
            let body = self.call("SimulatePrincipalPolicy", &params).await?;
            let page = parse_simulation(&body).with_context(|| format!("reading {action}"))?;
            decisions.extend(page.decisions);
            match page.marker {
                Some(m) if page.truncated => marker = Some(m),
                _ => return Ok(decisions),
            }
        }
    }

    /// One signed Query call of `operation`, tried again with backoff while
    /// IAM throttles it or fails on its side. `Action` is added unless
    /// `params` has it.
    async fn call(&self, operation: &str, params: &[(&str, String)]) -> Result<String> {
        let action = format!("iam:{operation}");
        let action = action.as_str();
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        if !params.iter().any(|(k, _)| *k == "Action") {
            serializer.append_pair("Action", operation);
        }
        let body = serializer
            .extend_pairs(params.iter().map(|(k, v)| (*k, v.as_str())))
            .append_pair("Version", "2010-05-08")
            .finish();
        let mut attempt = 0;
        loop {
            attempt += 1;
            let outcome = self.send(&body).await;
            let retry = match &outcome {
                Err(e) => e.is_timeout() || e.is_connect(),
                Ok((status, text)) => {
                    status.as_u16() == 429
                        || status.is_server_error()
                        || matches!(
                            iam_failure(text).map(|(code, _)| code).as_deref(),
                            Some("Throttling" | "ThrottlingException" | "RequestLimitExceeded")
                        )
                }
            };
            if retry && attempt < ATTEMPTS {
                tokio::time::sleep(backoff(attempt)).await;
                continue;
            }
            let (status, text) = outcome.map_err(|e| anyhow!("{action} failed: {e}"))?;
            if status.is_success() {
                return Ok(text);
            }
            return Err(match iam_failure(&text) {
                Some((code, _)) if code == "AccessDenied" || code == "AccessDeniedException" => {
                    anyhow::Error::new(Denied(action.to_string(), self.who)).into()
                }
                Some((code, message)) => anyhow!("{action} failed: {code}: {message}").into(),
                None => anyhow!("{action} failed with HTTP {status}").into(),
            });
        }
    }

    async fn send(&self, body: &str) -> reqwest::Result<(reqwest::StatusCode, String)> {
        let headers = match self.sign(body) {
            Ok(headers) => headers,
            // Signing fails only on malformed input, which no retry fixes;
            // reported as the request IAM never saw.
            Err(e) => {
                tracing::warn!("signing an IAM request: {e:#}");
                Vec::new()
            }
        };
        let mut request = self
            .http
            .post(&self.url)
            .header("content-type", FORM)
            .body(body.to_string());
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let response = request.send().await?;
        let status = response.status();
        Ok((status, response.text().await?))
    }

    /// The SigV4 headers for a POST of `body`.
    fn sign(&self, body: &str) -> anyhow::Result<Vec<(String, String)>> {
        use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings, sign};
        let identity = self.creds.clone().into();
        let params = aws_sigv4::sign::v4::SigningParams::builder()
            .identity(&identity)
            .region(self.region)
            .name("iam")
            .time(std::time::SystemTime::now())
            .settings(SigningSettings::default())
            .build()
            .map_err(|e| anyhow!("{e}"))?
            .into();
        let request = SignableRequest::new(
            "POST",
            self.url.as_str(),
            [("content-type", FORM)].into_iter(),
            SignableBody::Bytes(body.as_bytes()),
        )
        .map_err(|e| anyhow!("{e}"))?;
        let (instructions, _) = sign(request, &params)
            .map_err(|e| anyhow!("{e}"))?
            .into_parts();
        Ok(instructions
            .headers()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect())
    }
}

const FORM: &str = "application/x-www-form-urlencoded; charset=utf-8";

/// IAM's global endpoint in a partition, as the AWS SDKs resolve it; its
/// signing Region is the partition's default Region.
fn iam_host(partition: Partition) -> &'static str {
    match partition {
        Partition::Aws => "iam.amazonaws.com",
        Partition::China => "iam.cn-north-1.amazonaws.com.cn",
        Partition::UsGov => "iam.us-gov.amazonaws.com",
        Partition::EuropeanSovereign => "iam.eusc-de-east-1.amazonaws.eu",
    }
}

/// How long to wait before attempt `attempt + 1`: exponential from 100 ms,
/// capped at 5 s, with up to half of it random so parallel searches spread.
fn backoff(attempt: u32) -> Duration {
    let base = Duration::from_millis(100 * 2u64.pow(attempt.min(6))).min(Duration::from_secs(5));
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    base / 2 + base / 2 * (nanos % 1000) / 1000
}

/// One page of `ListRoles`.
#[derive(Debug, Default)]
struct RolesPage {
    roles: Vec<Role>,
    truncated: bool,
    marker: Option<String>,
}

/// One page of `SimulatePrincipalPolicy`, as each resource's answer.
#[derive(Debug, Default)]
struct SimulationPage {
    decisions: Vec<(String, Decision)>,
    truncated: bool,
    marker: Option<String>,
}

type Decoder<'inp, 'a> = aws_smithy_xml::decode::ScopedDecoder<'inp, 'a>;

fn text(tag: &mut Decoder) -> anyhow::Result<String> {
    Ok(aws_smithy_xml::decode::try_data(tag)?.into_owned())
}

/// Calls `each` on every child element of `tag`.
fn children(
    tag: &mut Decoder,
    mut each: impl FnMut(&mut Decoder) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    while let Some(mut child) = tag.next_tag() {
        each(&mut child)?;
    }
    Ok(())
}

/// Calls `each` on the children of the `<name>` element (a Query
/// response's `<…Result>`) under the root of `body`.
fn result_children(
    body: &str,
    name: &str,
    each: impl FnMut(&mut Decoder) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut document = aws_smithy_xml::decode::Document::new(body);
    let mut root = document.root_element()?;
    while let Some(mut tag) = root.next_tag() {
        if tag.start_el().matches(name) {
            return children(&mut tag, each);
        }
    }
    anyhow::bail!("no {name} in the response")
}

/// The text of every element of `body` named one of `names`, in document
/// order, with its name; other elements are searched within.
fn leaves(body: &str, names: &[&str]) -> anyhow::Result<Vec<(String, String)>> {
    fn walk(
        tag: &mut Decoder,
        names: &[&str],
        out: &mut Vec<(String, String)>,
    ) -> anyhow::Result<()> {
        while let Some(mut child) = tag.next_tag() {
            match names.iter().find(|n| child.start_el().matches(n)) {
                Some(name) => out.push((name.to_string(), text(&mut child)?)),
                None => walk(&mut child, names, out)?,
            }
        }
        Ok(())
    }
    let mut document = aws_smithy_xml::decode::Document::new(body);
    let mut root = document.root_element()?;
    let mut out = Vec::new();
    walk(&mut root, names, &mut out)?;
    Ok(out)
}

fn parse_list_roles(body: &str) -> anyhow::Result<RolesPage> {
    let mut page = RolesPage::default();
    result_children(body, "ListRolesResult", |tag| {
        if tag.start_el().matches("IsTruncated") {
            page.truncated = text(tag)? == "true";
        } else if tag.start_el().matches("Marker") {
            page.marker = Some(text(tag)?);
        } else if tag.start_el().matches("Roles") {
            children(tag, |member| {
                let mut role = Role {
                    path: String::new(),
                    name: String::new(),
                    arn: String::new(),
                    trust: None,
                };
                children(member, |field| {
                    let el = field.start_el();
                    if el.matches("Path") {
                        role.path = text(field)?;
                    } else if el.matches("RoleName") {
                        role.name = text(field)?;
                    } else if el.matches("Arn") {
                        role.arn = text(field)?;
                    } else if el.matches("AssumeRolePolicyDocument") {
                        role.trust = Some(text(field)?);
                    }
                    Ok(())
                })?;
                page.roles.push(role);
                Ok(())
            })?;
        }
        Ok(())
    })?;
    Ok(page)
}

/// Each resource's answer. With several resources, IAM gives one result
/// per action whose own resource is the statement's pattern
/// (`arn:aws:iam::${Account}:${RelativeId}`) and whose decision is the
/// strictest, and the answer for each resource in `ResourceSpecificResults`;
/// with one resource, that resource and its decision are the result's own,
/// and it may be in `ResourceSpecificResults` too. The organization's
/// answer is only at the top, so it is a resource's only when it is alone.
fn parse_simulation(body: &str) -> anyhow::Result<SimulationPage> {
    let mut page = SimulationPage::default();
    result_children(body, "SimulatePrincipalPolicyResult", |tag| {
        if tag.start_el().matches("IsTruncated") {
            page.truncated = text(tag)? == "true";
        } else if tag.start_el().matches("Marker") {
            page.marker = Some(text(tag)?);
        } else if tag.start_el().matches("EvaluationResults") {
            children(tag, |member| {
                let mut resource = None;
                let mut top = Decision::default();
                let mut specific: Vec<(String, Decision)> = Vec::new();
                children(member, |field| {
                    let el = field.start_el();
                    if el.matches("EvalResourceName") {
                        resource = Some(text(field)?);
                    } else if el.matches("EvalDecision") {
                        top.decision = text(field)?;
                    } else if el.matches("MissingContextValues") {
                        top.missing = members(field)?;
                    } else if el.matches("OrganizationsDecisionDetail") {
                        top.organizations = flag(field, "AllowedByOrganizations")?;
                    } else if el.matches("PermissionsBoundaryDecisionDetail") {
                        top.boundary = flag(field, "AllowedByPermissionsBoundary")?;
                    } else if el.matches("ResourceSpecificResults") {
                        children(field, |each| {
                            let mut name = None;
                            let mut decision = Decision::default();
                            children(each, |f| {
                                let el = f.start_el();
                                if el.matches("EvalResourceName") {
                                    name = Some(text(f)?);
                                } else if el.matches("EvalResourceDecision") {
                                    decision.decision = text(f)?;
                                } else if el.matches("MissingContextValues") {
                                    decision.missing = members(f)?;
                                } else if el.matches("PermissionsBoundaryDecisionDetail") {
                                    decision.boundary = flag(f, "AllowedByPermissionsBoundary")?;
                                }
                                Ok(())
                            })?;
                            if let Some(name) = name
                                && !decision.decision.is_empty()
                            {
                                specific.push((name, decision));
                            }
                            Ok(())
                        })?;
                    }
                    Ok(())
                })?;
                match specific.len() {
                    0 => {
                        if let Some(arn) = resource
                            && !top.decision.is_empty()
                        {
                            page.decisions.push((arn, top));
                        }
                    }
                    1 => {
                        let (arn, mut decision) = specific.remove(0);
                        decision.organizations = top.organizations;
                        decision.boundary = decision.boundary.or(top.boundary);
                        page.decisions.push((arn, decision));
                    }
                    _ => page.decisions.extend(specific),
                }
                Ok(())
            })?;
        }
        Ok(())
    })?;
    Ok(page)
}

/// The text of each `<member>` of a list.
fn members(tag: &mut Decoder) -> anyhow::Result<Vec<String>> {
    let mut list = Vec::new();
    children(tag, |member| {
        list.push(text(member)?);
        Ok(())
    })?;
    Ok(list)
}

/// A boolean child of a structure, when present.
fn flag(tag: &mut Decoder, name: &str) -> anyhow::Result<Option<bool>> {
    let mut value = None;
    children(tag, |field| {
        if field.start_el().matches(name) {
            value = Some(text(field)? == "true");
        }
        Ok(())
    })?;
    Ok(value)
}

/// The code and message of an IAM `ErrorResponse`.
fn iam_failure(body: &str) -> Option<(String, String)> {
    let mut document = aws_smithy_xml::decode::Document::new(body);
    let mut root = document.root_element().ok()?;
    if !root.start_el().matches("ErrorResponse") {
        return None;
    }
    let mut found = None;
    while let Some(mut tag) = root.next_tag() {
        if !tag.start_el().matches("Error") {
            continue;
        }
        let (mut code, mut message) = (None, String::new());
        while let Some(mut field) = tag.next_tag() {
            if field.start_el().matches("Code") {
                code = text(&mut field).ok();
            } else if field.start_el().matches("Message") {
                message = text(&mut field).unwrap_or_default();
            }
        }
        found = code.map(|c| (c, message));
    }
    found
}

/// What fob knows of a source's `sts:AssumeRole` request, to read a trust
/// policy with: the principals it is (the account's root, the bare account
/// ID and the source role's ARN) and the condition keys it can answer.
struct Requester<'a> {
    account_id: &'a str,
    root: &'a str,
    arn: &'a str,
    /// An IAM user, rather than a role session.
    user: bool,
}

impl Requester<'_> {
    /// `aws:PrincipalType`.
    fn principal_type(&self) -> &'static str {
        if self.user { "User" } else { "AssumedRole" }
    }

    fn is(&self, principal: &str) -> bool {
        principal == "*" || [self.root, self.account_id, self.arn].contains(&principal)
    }

    /// The request's value for a condition key (lower case), when fob knows
    /// it: an Identity Center role session's principal keys.
    fn value(&self, key: &str) -> Option<&str> {
        match key {
            // The role's ARN, path included, not the session's.
            "aws:principalarn" => Some(self.arn),
            "aws:principalaccount" => Some(self.account_id),
            "aws:principaltype" => Some(self.principal_type()),
            "aws:principalisawsservice" => Some("false"),
            _ => None,
        }
    }
}

/// How a condition, a statement or a policy answers a request fob knows
/// only in part.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    Yes,
    No,
    /// It depends on what fob cannot check, described for the user.
    Unknown(BTreeSet<String>),
}

impl Answer {
    /// Both must hold.
    fn and(self, other: Answer) -> Answer {
        match (self, other) {
            (Answer::No, _) | (_, Answer::No) => Answer::No,
            (Answer::Yes, other) | (other, Answer::Yes) => other,
            (Answer::Unknown(mut a), Answer::Unknown(b)) => {
                a.extend(b);
                Answer::Unknown(a)
            }
        }
    }
}

/// What a trust policy that lets the requester in asks of it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Trust {
    /// What the allowing statements need that fob cannot check, empty when
    /// one needs nothing.
    conditions: Vec<String>,
    /// A statement that allows it names the requester's role ARN itself,
    /// not its account or `*`.
    by_arn: bool,
}

/// Whether a trust policy (URL-encoded JSON, as IAM returns it) lets the
/// requester call `sts:AssumeRole`: `None` when no statement allows it or
/// one denies it outright. Conditions on the
/// requester's principal keys (`aws:PrincipalArn`, `aws:PrincipalAccount`,
/// `aws:PrincipalType`, `aws:PrincipalIsAWSService`) are evaluated; the
/// others are described.
fn trusts(document: &str, requester: &Requester) -> anyhow::Result<Option<Trust>> {
    let json = percent_decode(document)?;
    let policy: Value = serde_json::from_str(&json).context("not JSON")?;
    let statements = match &policy["Statement"] {
        Value::Array(list) => list.clone(),
        Value::Object(_) => vec![policy["Statement"].clone()],
        _ => return Ok(None),
    };
    let mut allowed: Option<Answer> = None;
    let mut denied = BTreeSet::new();
    let mut by_arn = false;
    for statement in &statements {
        let answer = applies(statement, requester);
        if statement["Effect"] == "Allow" && answer != Answer::No {
            by_arn |= statement["Principal"]
                .get("AWS")
                .is_some_and(|aws| strings(aws).iter().any(|p| p == requester.arn));
        }
        match (statement["Effect"].as_str(), answer) {
            (_, Answer::No) => {}
            (Some("Deny"), Answer::Yes) => return Ok(None),
            (Some("Deny"), Answer::Unknown(notes)) => {
                denied.extend(
                    notes
                        .into_iter()
                        .map(|n| format!("a Deny statement may apply ({n})")),
                );
            }
            (Some("Allow"), answer) => {
                // Any statement that allows it is enough.
                allowed = Some(match (allowed, answer) {
                    (Some(Answer::Yes), _) | (_, Answer::Yes) => Answer::Yes,
                    (Some(Answer::Unknown(mut a)), Answer::Unknown(b)) => {
                        a.extend(b);
                        Answer::Unknown(a)
                    }
                    (_, answer) => answer,
                });
            }
            _ => {}
        }
    }
    let conditions: Vec<String> = match allowed {
        None | Some(Answer::No) => return Ok(None),
        Some(Answer::Yes) => denied.into_iter().collect(),
        Some(Answer::Unknown(mut notes)) => {
            notes.extend(denied);
            notes.into_iter().collect()
        }
    };
    Ok(Some(Trust { conditions, by_arn }))
}

/// Whether a statement concerns the requester's `sts:AssumeRole`, its
/// effect aside.
fn applies(statement: &Value, requester: &Requester) -> Answer {
    let assume = |patterns: &Value| {
        strings(patterns)
            .iter()
            .any(|a| wildcard(&a.to_ascii_lowercase(), "sts:assumerole"))
    };
    let action = match (statement.get("Action"), statement.get("NotAction")) {
        (Some(action), _) => assume(action),
        (None, Some(not)) => !assume(not),
        (None, None) => false,
    };
    // `NotPrincipal` is rare in trust policies and not read.
    let principal = match &statement["Principal"] {
        Value::String(s) => s == "*",
        Value::Object(map) => map
            .get("AWS")
            .map(strings)
            .unwrap_or_default()
            .iter()
            .any(|p| requester.is(p)),
        _ => false,
    };
    if !action || !principal {
        return Answer::No;
    }
    let Some(Value::Object(conditions)) = statement.get("Condition") else {
        return Answer::Yes;
    };
    let mut answer = Answer::Yes;
    for (operator, keys) in conditions {
        let Value::Object(keys) = keys else {
            continue;
        };
        for (key, values) in keys {
            answer = answer.and(condition(operator, key, &strings(values), requester));
        }
    }
    answer
}

/// One condition: an operator, a key and the values it is compared with.
fn condition(operator: &str, key: &str, values: &[String], requester: &Requester) -> Answer {
    let unknown = || Answer::Unknown(BTreeSet::from([needs(key, values)]));
    let key = key.to_ascii_lowercase();
    // A single-valued key answers a set operator as it would the plain one.
    let operator = operator
        .strip_prefix("ForAnyValue:")
        .or_else(|| operator.strip_prefix("ForAllValues:"))
        .unwrap_or(operator);
    let (operator, if_exists) = match operator.strip_suffix("IfExists") {
        Some(operator) => (operator, true),
        None => (operator, false),
    };
    // A role found is written without `external_id`, so its request has no
    // `sts:ExternalId`: a condition that it be absent holds, as in the CDK
    // bootstrap roles' trust policies, and an `IfExists` one is skipped.
    if key == "sts:externalid" {
        return match operator {
            "Null" if values.iter().any(|v| v.eq_ignore_ascii_case("true")) => Answer::Yes,
            _ if if_exists => Answer::Yes,
            _ => unknown(),
        };
    }
    // The keys fob answers are always present, so `IfExists` changes nothing.
    let Some(value) = requester.value(&key) else {
        return unknown();
    };
    // A policy variable is a value fob would have to resolve.
    if values.iter().any(|v| v.contains("${")) {
        return unknown();
    }
    let matches = |f: &dyn Fn(&str) -> bool| values.iter().any(|v| f(v));
    let result = match operator {
        "StringEquals" | "ArnEquals" => matches(&|v| v == value),
        "StringNotEquals" | "ArnNotEquals" => !matches(&|v| v == value),
        "StringEqualsIgnoreCase" => matches(&|v| v.eq_ignore_ascii_case(value)),
        "StringNotEqualsIgnoreCase" => !matches(&|v| v.eq_ignore_ascii_case(value)),
        "StringLike" | "ArnLike" => matches(&|v| wildcard(v, value)),
        "StringNotLike" | "ArnNotLike" => !matches(&|v| wildcard(v, value)),
        "Bool" => matches(&|v| v.eq_ignore_ascii_case(value)),
        "Null" => matches(&|v| v.eq_ignore_ascii_case("false")),
        _ => return unknown(),
    };
    if result { Answer::Yes } else { Answer::No }
}

/// What a condition fob cannot check asks of the requester, in words.
fn needs(key: &str, values: &[String]) -> String {
    let lower = key.to_ascii_lowercase();
    if lower == "sts:externalid" {
        "requires an external ID (set external_id)".into()
    } else if lower == "aws:multifactorauthpresent" || lower == "aws:multifactorauthage" {
        "requires MFA (set mfa_serial)".into()
    } else if let Some(tag) = key.get("aws:PrincipalTag/".len()..)
        && lower.starts_with("aws:principaltag/")
    {
        format!("requires the principal tag {tag}")
    } else if lower == "aws:principalorgid" && !values.is_empty() {
        format!("requires the organization {}", values.join(" or "))
    } else {
        format!("checks {key}")
    }
}

/// Whether `text` matches `pattern`, where `*` matches any run of
/// characters and `?` any one, as IAM's `Like` operators read them.
fn wildcard(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// A string or a list of strings in a policy, as a list.
fn strings(value: &Value) -> Vec<String> {
    match value {
        Value::String(s) => vec![s.clone()],
        Value::Array(list) => list
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// Decodes `%XX` escapes, as IAM encodes policy documents (RFC 3986, so a
/// `+` is a plus sign).
fn percent_decode(text: &str) -> anyhow::Result<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .context("a malformed %-escape")?;
            out.push(hex);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).context("not UTF-8 once decoded")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_answers_are_read() {
        let page = parse_list_roles(
            "<ListRolesResponse><ListRolesResult><IsTruncated>true</IsTruncated><Marker>m&amp;1</Marker>\
             <Roles><member><Path>/</Path><RoleName>r</RoleName><Arn>arn:aws:iam::1:role/r</Arn>\
             <AssumeRolePolicyDocument>%7B%7D</AssumeRolePolicyDocument></member></Roles>\
             </ListRolesResult></ListRolesResponse>",
        )
        .unwrap();
        assert!(page.truncated);
        assert_eq!(page.marker.as_deref(), Some("m&1"));
        assert_eq!(
            page.roles,
            [Role {
                path: "/".into(),
                name: "r".into(),
                arn: "arn:aws:iam::1:role/r".into(),
                trust: Some("%7B%7D".into()),
            }]
        );
        assert_eq!(
            iam_failure(
                "<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code>\
                 <Message>no</Message></Error><RequestId>1</RequestId></ErrorResponse>"
            ),
            Some(("AccessDenied".into(), "no".into()))
        );
        assert_eq!(iam_failure("not xml"), None);
        assert_eq!(iam_host(Partition::UsGov), "iam.us-gov.amazonaws.com");
    }

    #[test]
    fn simulator_answers_are_read_per_role() {
        let result = |inner: &str| {
            format!(
                "<SimulatePrincipalPolicyResponse><SimulatePrincipalPolicyResult>\
                 <IsTruncated>false</IsTruncated><EvaluationResults><member>{inner}</member>\
                 </EvaluationResults></SimulatePrincipalPolicyResult></SimulatePrincipalPolicyResponse>"
            )
        };
        // Several roles: each one's answer, without the organization's.
        let page = parse_simulation(&result(
            "<EvalActionName>sts:AssumeRole</EvalActionName>\
             <EvalResourceName>arn:aws:iam::${Account}:${RelativeId}</EvalResourceName>\
             <EvalDecision>implicitDeny</EvalDecision>\
             <OrganizationsDecisionDetail><AllowedByOrganizations>false</AllowedByOrganizations></OrganizationsDecisionDetail>\
             <ResourceSpecificResults>\
             <member><EvalResourceName>arn:aws:iam::1:role/a</EvalResourceName><EvalResourceDecision>allowed</EvalResourceDecision></member>\
             <member><EvalResourceName>arn:aws:iam::1:role/b</EvalResourceName><EvalResourceDecision>implicitDeny</EvalResourceDecision>\
             <MissingContextValues><member>aws:PrincipalTag/team</member></MissingContextValues>\
             <PermissionsBoundaryDecisionDetail><AllowedByPermissionsBoundary>true</AllowedByPermissionsBoundary></PermissionsBoundaryDecisionDetail></member>\
             </ResourceSpecificResults>",
        ))
        .unwrap();
        assert_eq!(
            page.decisions,
            [
                (
                    "arn:aws:iam::1:role/a".to_string(),
                    Decision {
                        decision: "allowed".into(),
                        ..Decision::default()
                    }
                ),
                (
                    "arn:aws:iam::1:role/b".to_string(),
                    Decision {
                        decision: "implicitDeny".into(),
                        missing: vec!["aws:PrincipalTag/team".into()],
                        boundary: Some(true),
                        organizations: None,
                    }
                ),
            ]
        );
        // One role: the organization's answer is its own.
        let page = parse_simulation(&result(
            "<EvalActionName>sts:AssumeRole</EvalActionName>\
             <EvalResourceName>arn:aws:iam::1:role/a</EvalResourceName>\
             <EvalDecision>implicitDeny</EvalDecision>\
             <OrganizationsDecisionDetail><AllowedByOrganizations>false</AllowedByOrganizations></OrganizationsDecisionDetail>\
             <ResourceSpecificResults><member><EvalResourceName>arn:aws:iam::1:role/a</EvalResourceName>\
             <EvalResourceDecision>implicitDeny</EvalResourceDecision></member></ResourceSpecificResults>",
        ))
        .unwrap();
        assert_eq!(page.decisions[0].1.organizations, Some(false));
        assert!(!page.decisions[0].1.trust_alone_allows(false));
        let alone = |decision: &str, organizations, boundary| Decision {
            decision: decision.into(),
            missing: Vec::new(),
            boundary,
            organizations,
        };
        assert!(alone("implicitDeny", Some(true), None).trust_alone_allows(false));
        assert!(alone("implicitDeny", None, Some(true)).trust_alone_allows(false));
        assert!(!alone("implicitDeny", Some(true), Some(false)).trust_alone_allows(false));
        assert!(!alone("explicitDeny", Some(true), Some(true)).trust_alone_allows(false));
    }

    #[test]
    fn a_users_boundary_does_not_limit_what_its_arn_is_granted() {
        let limited = Decision {
            decision: "implicitDeny".into(),
            boundary: Some(false),
            ..Default::default()
        };
        assert!(!limited.trust_alone_allows(false));
        assert!(limited.trust_alone_allows(true));
    }

    #[test]
    fn identities_are_users_or_the_roles_of_their_sessions() {
        let roles = [Role {
            path: "/team/".into(),
            name: "Dev".into(),
            arn: "arn:aws:iam::111111111111:role/team/Dev".into(),
            trust: None,
        }];
        assert_eq!(
            identity_principal("arn:aws:iam::111111111111:user/ops/alice", &roles).unwrap(),
            ("arn:aws:iam::111111111111:user/ops/alice".to_string(), true)
        );
        assert_eq!(
            identity_principal("arn:aws:sts::111111111111:assumed-role/Dev/alice", &roles).unwrap(),
            ("arn:aws:iam::111111111111:role/team/Dev".to_string(), false)
        );
        assert!(
            identity_principal("arn:aws:sts::111111111111:assumed-role/Gone/x", &roles).is_err()
        );
        assert!(identity_principal("arn:aws:iam::111111111111:root", &roles).is_err());
    }

    #[test]
    fn identity_policies_are_read_for_assume_role_on_the_role() {
        let role = "arn:aws:iam::111111111111:role/ops/deployer";
        let statements = |json: &str| -> Vec<Value> { serde_json::from_str(json).unwrap() };
        let allow_all = statements(r#"[{"Effect":"Allow","Action":"*","Resource":"*"}]"#);
        assert_eq!(allows(&allow_all, role), Answer::Yes);
        let read_only =
            statements(r#"[{"Effect":"Allow","Action":["s3:Get*","iam:List*"],"Resource":"*"}]"#);
        assert_eq!(allows(&read_only, role), Answer::No);
        let others = statements(
            r#"[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::*:role/ci-*"}]"#,
        );
        assert_eq!(allows(&others, role), Answer::No);
        let not_action = statements(r#"[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]"#);
        assert_eq!(allows(&not_action, role), Answer::Yes);
        let conditional = statements(
            r#"[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]"#,
        );
        assert!(matches!(allows(&conditional, role), Answer::Unknown(_)));

        let mut notes = Vec::new();
        let deny = statements(
            r#"[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"sts:*","Resource":"arn:aws:iam::*:role/ops/*"}]"#,
        );
        assert!(!denies(&deny, role, &mut notes));
        let deny_if = statements(
            r#"[{"Effect":"Deny","Action":"sts:AssumeRole","Resource":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":"eu-west-1"}}}]"#,
        );
        assert!(denies(&deny_if, role, &mut notes));
        assert_eq!(notes, ["a Deny statement may apply (aws:RequestedRegion)"]);
    }

    #[test]
    fn leaves_are_found_at_any_depth() {
        let body = "<R><X><IsTruncated>true</IsTruncated><Marker>m</Marker><PolicyNames><member>a</member><member>b</member></PolicyNames></X></R>";
        assert_eq!(
            leaves(body, &["member", "Marker"]).unwrap(),
            [
                ("Marker".to_string(), "m".to_string()),
                ("member".to_string(), "a".to_string()),
                ("member".to_string(), "b".to_string())
            ]
        );
    }

    fn encoded(json: &str) -> String {
        json.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    }

    const ROOT: &str = "arn:aws:iam::111111111111:root";
    const SOURCE: &str =
        "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_pe_1";
    const REQUESTER: Requester = Requester {
        account_id: "111111111111",
        root: ROOT,
        arn: SOURCE,
        user: false,
    };

    /// A trust policy of one statement, `fields` added to it.
    fn statement(effect: &str, principal: &str, fields: &str) -> String {
        format!(
            r#"{{"Effect":"{effect}","Principal":{{"AWS":{principal}}},"Action":"sts:AssumeRole"{fields}}}"#
        )
    }

    fn policy(statements: &[String]) -> Option<Vec<String>> {
        let doc = encoded(&format!(
            r#"{{"Version":"2012-10-17","Statement":[{}]}}"#,
            statements.join(",")
        ));
        trusts(&doc, &REQUESTER).unwrap().map(|t| t.conditions)
    }

    fn allow(principal: &str, fields: &str) -> Option<Vec<String>> {
        policy(&[statement("Allow", principal, fields)])
    }

    fn quoted(s: &str) -> String {
        format!("\"{s}\"")
    }

    #[test]
    fn tooling_roles_are_recognised() {
        for name in [
            "cdk-hnb659fds-deploy-role-111111111111-eu-west-1",
            "cdk-hnb659fds-file-publishing-role-111111111111-eu-west-1",
            "cdk-custom-image-publishing-role-111111111111-us-east-1",
            "cdk-hnb659fds-lookup-role-111111111111-eu-west-1",
            "AWSCloudFormationStackSetExecutionRole",
        ] {
            assert!(is_tooling(name), "{name}");
        }
        for name in [
            "OrganizationAccountAccessRole",
            "cdk-admin",
            "deploy-role-prod",
            "admin-root",
        ] {
            assert!(!is_tooling(name), "{name}");
        }
    }

    #[test]
    fn trust_policies_are_read_for_the_account_or_the_role() {
        let unconditional = Some(Vec::new());
        assert_eq!(allow(&quoted(ROOT), ""), unconditional);
        assert_eq!(
            allow(
                &format!("[\"arn:aws:iam::999999999999:root\",\"{SOURCE}\"]"),
                ""
            ),
            unconditional
        );
        assert_eq!(allow("\"111111111111\"", ""), unconditional);
        assert_eq!(allow("\"*\"", ""), unconditional);
        // Another account, a service, or another action: not this source.
        assert_eq!(allow("\"arn:aws:iam::999999999999:root\"", ""), None);
        let service = encoded(
            r#"{"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}"#,
        );
        assert_eq!(trusts(&service, &REQUESTER).unwrap(), None);
        // Named by its ARN, or only through its account.
        let by_arn = |principal: &str| {
            let doc = encoded(&format!(
                r#"{{"Statement":[{}]}}"#,
                statement("Allow", principal, "")
            ));
            trusts(&doc, &REQUESTER).unwrap().unwrap().by_arn
        };
        assert!(by_arn(&quoted(SOURCE)));
        assert!(by_arn(&format!("[\"{ROOT}\",\"{SOURCE}\"]")));
        assert!(!by_arn(&quoted(ROOT)));
        assert!(!by_arn("\"*\""));
        let tagging = encoded(&format!(
            r#"{{"Statement":{{"Effect":"Allow","Principal":{{"AWS":"{ROOT}"}},"Action":"sts:TagSession"}}}}"#
        ));
        assert_eq!(trusts(&tagging, &REQUESTER).unwrap(), None);
        // Action patterns and NotAction.
        let actions = |field: &str| {
            policy(&[format!(
                r#"{{"Effect":"Allow","Principal":{{"AWS":"{ROOT}"}},{field}}}"#
            )])
        };
        assert_eq!(actions(r#""Action":"sts:Assume*""#), unconditional);
        assert_eq!(actions(r#""Action":["STS:*"]"#), unconditional);
        assert_eq!(actions(r#""NotAction":"sts:TagSession""#), unconditional);
        assert_eq!(actions(r#""NotAction":"sts:*""#), None);
        assert!(trusts("%zz", &REQUESTER).is_err());
    }

    #[test]
    fn a_deny_statement_rejects_the_role_or_is_noted() {
        let allowed = statement("Allow", &quoted(ROOT), "");
        assert_eq!(
            policy(&[allowed.clone(), statement("Deny", &quoted(SOURCE), "")]),
            None
        );
        assert_eq!(
            policy(&[allowed.clone(), statement("Deny", "\"*\"", "")]),
            None
        );
        // A Deny for someone else does not concern this source.
        assert_eq!(
            policy(&[
                allowed.clone(),
                statement("Deny", "\"arn:aws:iam::999999999999:root\"", "")
            ]),
            Some(Vec::new())
        );
        // One whose condition fob cannot check is noted.
        assert_eq!(
            policy(&[
                allowed.clone(),
                statement(
                    "Deny",
                    "\"*\"",
                    r#","Condition":{"NotIpAddress":{"aws:SourceIp":"10.0.0.0/8"}}"#
                )
            ]),
            Some(vec![
                "a Deny statement may apply (checks aws:SourceIp)".to_string()
            ])
        );
        // One whose condition rules this source out does not apply.
        assert_eq!(
            policy(&[
                allowed,
                statement(
                    "Deny",
                    "\"*\"",
                    r#","Condition":{"StringNotLike":{"aws:PrincipalArn":"*AWSReservedSSO_pe_*"}}"#
                )
            ]),
            Some(Vec::new())
        );
    }

    #[test]
    fn conditions_on_the_principal_are_evaluated() {
        let condition = |c: &str| allow("\"*\"", &format!(r#","Condition":{c}"#));
        let unconditional = Some(Vec::new());
        assert_eq!(
            condition(
                r#"{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_pe_*"}}"#
            ),
            unconditional
        );
        assert_eq!(
            condition(
                r#"{"ArnLike":{"aws:PrincipalArn":["arn:aws:iam::*:role/*AWSReservedSSO_Admin_*","arn:aws:iam::*:role/*_pe_*"]}}"#
            ),
            unconditional
        );
        assert_eq!(
            condition(r#"{"ArnLike":{"aws:PrincipalArn":"*AWSReservedSSO_Admin_*"}}"#),
            None
        );
        assert_eq!(
            condition(
                r#"{"StringEquals":{"aws:PrincipalAccount":"111111111111","aws:PrincipalType":"AssumedRole"}}"#
            ),
            unconditional
        );
        assert_eq!(
            condition(r#"{"StringNotEqualsIfExists":{"aws:PrincipalAccount":"111111111111"}}"#),
            None
        );
        assert_eq!(
            condition(r#"{"ForAnyValue:StringLike":{"aws:PrincipalArn":"*_pe_*"}}"#),
            unconditional
        );
        assert_eq!(
            condition(r#"{"Bool":{"aws:PrincipalIsAWSService":"false"}}"#),
            unconditional
        );
        assert_eq!(condition(r#"{"Null":{"aws:PrincipalArn":"true"}}"#), None);
        // A policy variable is not resolved.
        assert_eq!(
            condition(r#"{"StringEquals":{"aws:PrincipalArn":"${aws:PrincipalTag/role}"}}"#),
            Some(vec!["checks aws:PrincipalArn".to_string()])
        );
    }

    #[test]
    fn other_conditions_say_what_they_need() {
        let condition = |c: &str| allow(&quoted(ROOT), &format!(r#","Condition":{c}"#));
        assert_eq!(
            condition(
                r#"{"StringEquals":{"sts:ExternalId":"x"},"Bool":{"aws:MultiFactorAuthPresent":"true"}}"#
            ),
            Some(vec![
                "requires MFA (set mfa_serial)".to_string(),
                "requires an external ID (set external_id)".to_string()
            ])
        );
        assert_eq!(
            condition(
                r#"{"StringEquals":{"aws:PrincipalTag/team":"ops","aws:PrincipalOrgID":"o-abc"}}"#
            ),
            Some(vec![
                "requires the organization o-abc".to_string(),
                "requires the principal tag team".to_string()
            ])
        );
        // No external ID is sent, so one that must be absent is no
        // condition, and one compared only if present is skipped.
        assert_eq!(
            condition(r#"{"Null":{"sts:ExternalId":"true"}}"#),
            Some(Vec::new())
        );
        assert_eq!(
            condition(r#"{"StringEqualsIfExists":{"sts:ExternalId":"x"}}"#),
            Some(Vec::new())
        );
        assert_eq!(
            condition(r#"{"Null":{"sts:ExternalId":"false"}}"#),
            Some(vec![
                "requires an external ID (set external_id)".to_string()
            ])
        );
        // A known condition that fails rules the statement out, whatever
        // the others.
        assert_eq!(
            condition(
                r#"{"StringEquals":{"sts:ExternalId":"x","aws:PrincipalAccount":"999999999999"}}"#
            ),
            None
        );
        // Unconditional once any statement that allows it is.
        assert_eq!(
            policy(&[
                statement("Allow", &quoted(ROOT), ""),
                statement(
                    "Allow",
                    &quoted(ROOT),
                    r#","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}"#
                )
            ]),
            Some(Vec::new())
        );
    }

    #[test]
    fn wildcards_match_as_iam_reads_them() {
        assert!(wildcard("a*c", "abbbc"));
        assert!(wildcard("a?c", "abc"));
        assert!(wildcard("*", ""));
        assert!(wildcard("*_pe_*", "AWSReservedSSO_pe_1"));
        assert!(!wildcard("a*c", "abcd"));
        assert!(!wildcard("abc", "ab"));
    }
}
