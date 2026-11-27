//! `fob discover aws`: roles an Identity Center role may assume in its own
//! account, which Identity Center does not list.
//!
//! For each account, the credentials of one of its sources (a permission
//! set) list its IAM roles (`iam:ListRoles`). For each source, fob keeps
//! the roles whose trust policy lets the account, or the source role
//! itself, call `sts:AssumeRole`, and asks the policy simulator
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

/// Searches every source, a few accounts at a time. A sign-in that has
/// ended or a locked vault fails the whole search, since no source can
/// succeed and the caller can sign in or unlock; anything else skips the
/// sources it concerns, with the reason.
pub async fn discover(
    integration: &str,
    config: &AwsSsoConfig,
    sources: Vec<Source>,
) -> Result<Discovery> {
    let mut accounts: BTreeMap<String, Vec<Source>> = BTreeMap::new();
    for source in sources {
        accounts
            .entry(source.account_id.clone())
            .or_default()
            .push(source);
    }
    let results: Vec<Result<Discovery>> =
        futures_util::stream::iter(accounts.into_values().map(|mut sources| async move {
            sources.sort_by(|a, b| a.via_role.cmp(&b.via_role));
            search_account(integration, config, sources).await
        }))
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

/// The roles the sources of one account may assume there. The account's
/// roles are listed once, with the first source whose credentials may, and
/// every source is then simulated, with the lister's credentials or its
/// own: a permission set that may not list roles can still be simulated by
/// one that may, and one that may list but not simulate does not stop the
/// others.
async fn search_account(
    integration: &str,
    config: &AwsSsoConfig,
    sources: Vec<Source>,
) -> Result<Discovery> {
    let partition = config.partition()?;
    let mut discovery = Discovery::default();
    let mut clients = Clients {
        integration,
        config,
        partition,
        made: BTreeMap::new(),
    };
    let mut refused: BTreeMap<&str, String> = BTreeMap::new();
    let mut listed = None;
    for source in &sources {
        let iam = match clients.get(source).await? {
            Ok(iam) => iam,
            Err(reason) => {
                refused.insert(&source.via_role, reason);
                continue;
            }
        };
        match iam.list_roles().await {
            Ok(roles) => {
                listed = Some((source.via_role.clone(), roles));
                break;
            }
            Err(e) => {
                refused.insert(&source.via_role, stops_everything(e)?);
            }
        }
    }
    let Some((lister, roles)) = listed else {
        discovery.skipped = sources
            .iter()
            .map(|source| Skipped {
                source: source.clone(),
                reason: refused.remove(source.via_role.as_str()).unwrap_or_default(),
            })
            .collect();
        return Ok(discovery);
    };
    for source in &sources {
        match search(&mut clients, &lister, &roles, partition, source).await {
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

/// An IAM client per permission set of an account, made the first time it
/// is needed, or why it could not be.
struct Clients<'a> {
    integration: &'a str,
    config: &'a AwsSsoConfig,
    partition: Partition,
    made: BTreeMap<String, std::result::Result<Iam, String>>,
}

impl Clients<'_> {
    /// The client of `source`'s permission set; `Err` only for an error that
    /// stops every search.
    async fn get(&mut self, source: &Source) -> Result<std::result::Result<&Iam, String>> {
        if !self.made.contains_key(&source.via_role) {
            let made = async {
                let creds = source_credentials(self.integration, self.config, source).await?;
                Ok::<_, crate::Error>(Iam::new(&creds, self.partition)?)
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

    /// The client of a permission set already made.
    fn made(&self, via_role: &str) -> Option<&Iam> {
        self.made.get(via_role).and_then(|m| m.as_ref().ok())
    }
}

/// A source's credentials: those cached for its profile while they are
/// fresh, as `fob exec` would use them, or new ones, which are cached.
async fn source_credentials(
    integration: &str,
    config: &AwsSsoConfig,
    source: &Source,
) -> Result<Credentials> {
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

/// The roles among `roles` that one source may assume, and those whose
/// trust policy could not be read. The simulator is called with the
/// credentials of `lister`, the permission set that listed the roles, or
/// with the source's own when `lister`'s may not call it.
async fn search(
    clients: &mut Clients<'_>,
    lister: &str,
    roles: &[Role],
    partition: Partition,
    source: &Source,
) -> Result<(Vec<Found>, Vec<String>)> {
    // The role Identity Center made for the permission set in this account:
    // `AWSReservedSSO_<permission set>_<16 hex digits>`, so a permission set
    // named `Admin` does not take `AWSReservedSSO_Admin_ReadOnly_...`.
    let prefix = format!("AWSReservedSSO_{}_", source.via_role);
    let source_arn = roles
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
    let root = format!(
        "arn:{}:iam::{}:root",
        partition.arn_name(),
        source.account_id
    );
    let requester = Requester {
        account_id: &source.account_id,
        root: &root,
        arn: &source_arn,
    };
    let mut candidates = Vec::new();
    let mut unreadable = Vec::new();
    for role in roles {
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
            Ok(Some(trust)) => candidates.push((role, trust)),
            Ok(None) => {}
            // One role's policy does not end the account's search.
            Err(e) => unreadable.push(format!("{} ({e:#})", role.arn)),
        }
    }
    let arns: Vec<&str> = candidates.iter().map(|(r, _)| r.arn.as_str()).collect();
    let (simulator, decisions) = simulate(clients, lister, source, &requester, &arns).await?;
    let mut kept = Vec::new();
    for (role, trust) in candidates {
        let Some(decision) = decisions.get(&role.arn) else {
            continue;
        };
        let mut conditions = trust.conditions;
        let assumable = match decision.decision.as_str() {
            "allowed" => true,
            // In its own account, a role whose trust policy names the
            // source's role ARN needs nothing from the source's policies,
            // unless the organization's SCPs or the permissions boundary
            // refuse, which the simulator reports for one role at a time.
            "implicitDeny" if trust.by_arn && decision.boundary != Some(false) => {
                let iam = clients
                    .made(&simulator)
                    .context("the simulating permission set has no client")?;
                let alone = iam
                    .simulate_assume_role(&requester, &[role.arn.as_str()])
                    .await?;
                alone.iter().any(|(_, d)| d.trust_alone_allows())
            }
            // Denied only for want of context the source's policies check.
            "implicitDeny" if !decision.missing.is_empty() => {
                conditions.push(format!(
                    "the permission set's policies check {}, which the simulator was not given",
                    decision.missing.join(", ")
                ));
                true
            }
            _ => false,
        };
        if assumable {
            kept.push((role, conditions));
        }
    }
    let found = kept
        .into_iter()
        .map(|(role, conditions)| Found {
            label: format!("{}-{}", source.segment, crate::profile::slug(&role.name)),
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
        })
        .collect();
    Ok((found, unreadable))
}

/// The simulator's answer for each of `arns`, asked with `lister`'s
/// credentials, or with the source's own when `lister`'s may not call the
/// simulator, and the permission set whose credentials answered.
async fn simulate(
    clients: &mut Clients<'_>,
    lister: &str,
    source: &Source,
    requester: &Requester<'_>,
    arns: &[&str],
) -> Result<(String, BTreeMap<String, Decision>)> {
    if arns.is_empty() {
        return Ok((lister.to_string(), BTreeMap::new()));
    }
    let iam = clients
        .made(lister)
        .context("the permission set that listed the roles has no client")?;
    match simulate_with(iam, requester, arns).await {
        Err(e) if is_denied(&e) && source.via_role != lister => {}
        Err(e) if is_denied(&e) => return Err(untested(e, arns.len())),
        other => return other.map(|d| (lister.to_string(), d)),
    }
    let own = match clients.get(source).await? {
        Ok(iam) => iam,
        Err(reason) => {
            return Err(anyhow!(
                "{lister} may not call iam:SimulatePrincipalPolicy, and {reason}; {} role(s) in \
                 the account trust it",
                arns.len()
            )
            .into());
        }
    };
    let decisions = simulate_with(own, requester, arns).await.map_err(|e| {
        if is_denied(&e) {
            anyhow!(
                "neither it nor {lister} may call iam:SimulatePrincipalPolicy; {} role(s) in the \
                 account trust it",
                arns.len()
            )
            .into()
        } else {
            e
        }
    })?;
    Ok((source.via_role.clone(), decisions))
}

/// `e`, a refused simulation, with how many roles it left untested.
fn untested(e: crate::Error, roles: usize) -> crate::Error {
    anyhow!("{e:#}; {roles} role(s) in the account trust it").into()
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
    /// session ARN).
    fn trust_alone_allows(&self) -> bool {
        match self.decision.as_str() {
            "allowed" => true,
            "implicitDeny" => self.organizations != Some(false) && self.boundary != Some(false),
            _ => false,
        }
    }
}

/// IAM refused the call: the permission set may not make it.
#[derive(Debug, thiserror::Error)]
#[error("the permission set may not call {0}")]
struct Denied(&'static str);

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
}

impl Iam {
    fn new(creds: &Credentials, partition: Partition) -> anyhow::Result<Self> {
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
        })
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
            let body = self.call(action, &params).await?;
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
            ("aws:PrincipalType", "AssumedRole"),
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
            let body = self.call(action, &params).await?;
            let page = parse_simulation(&body).with_context(|| format!("reading {action}"))?;
            decisions.extend(page.decisions);
            match page.marker {
                Some(m) if page.truncated => marker = Some(m),
                _ => return Ok(decisions),
            }
        }
    }

    /// One signed Query call, tried again with backoff while IAM throttles
    /// it or fails on its side.
    async fn call(&self, action: &'static str, params: &[(&str, String)]) -> Result<String> {
        let body = form_urlencoded::Serializer::new(String::new())
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
                    anyhow::Error::new(Denied(action)).into()
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
}

impl Requester<'_> {
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
            "aws:principaltype" => Some("AssumedRole"),
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
        assert!(!page.decisions[0].1.trust_alone_allows());
        let alone = |decision: &str, organizations, boundary| Decision {
            decision: decision.into(),
            missing: Vec::new(),
            boundary,
            organizations,
        };
        assert!(alone("implicitDeny", Some(true), None).trust_alone_allows());
        assert!(alone("implicitDeny", None, Some(true)).trust_alone_allows());
        assert!(!alone("implicitDeny", Some(true), Some(false)).trust_alone_allows());
        assert!(!alone("explicitDeny", Some(true), Some(true)).trust_alone_allows());
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
