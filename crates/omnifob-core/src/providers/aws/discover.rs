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
//! fob does not evaluate the conditions of a trust policy (MFA, tags,
//! external IDs). A role it finds can still refuse, and one it misses may
//! work.

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

/// How many roles one `SimulatePrincipalPolicy` call evaluates.
const SIMULATED_PER_CALL: usize = 20;

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
}

/// A role a source may assume, as a chained role, labelled after the
/// account segment and the role name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub label: String,
    pub role: ChainedRole,
    /// The trust policy has conditions fob did not evaluate.
    pub conditional: bool,
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
                let creds = super::sso::credentials(
                    self.integration,
                    self.config,
                    &source.account_id,
                    &source.via_role,
                )
                .await?;
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
        match trusts(document, &[&root, &source.account_id, &source_arn]) {
            Ok(Some(conditional)) => candidates.push((role, conditional)),
            Ok(None) => {}
            // One role's policy does not end the account's search.
            Err(e) => unreadable.push(format!("{} ({e:#})", role.arn)),
        }
    }
    let arns: Vec<&str> = candidates.iter().map(|(r, _)| r.arn.as_str()).collect();
    let allowed = simulate(clients, lister, source, &source_arn, &arns).await?;
    let found = candidates
        .into_iter()
        .filter(|(role, _)| allowed.contains(&role.arn))
        .map(|(role, conditional)| Found {
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
            conditional,
            also_via: Vec::new(),
        })
        .collect();
    Ok((found, unreadable))
}

/// The role ARNs among `arns` the simulator lets `source_arn` assume, asked
/// with `lister`'s credentials, or with the source's own when `lister`'s
/// may not call the simulator.
async fn simulate(
    clients: &mut Clients<'_>,
    lister: &str,
    source: &Source,
    source_arn: &str,
    arns: &[&str],
) -> Result<BTreeSet<String>> {
    if arns.is_empty() {
        return Ok(BTreeSet::new());
    }
    let iam = clients
        .made(lister)
        .context("the permission set that listed the roles has no client")?;
    match simulate_with(iam, source_arn, arns).await {
        Err(e) if is_denied(&e) && source.via_role != lister => {}
        Err(e) if is_denied(&e) => return Err(untested(e, arns.len())),
        other => return other,
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
    simulate_with(own, source_arn, arns).await.map_err(|e| {
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
    })
}

/// `e`, a refused simulation, with how many roles it left untested.
fn untested(e: crate::Error, roles: usize) -> crate::Error {
    anyhow!("{e:#}; {roles} role(s) in the account trust it").into()
}

async fn simulate_with(iam: &Iam, source_arn: &str, arns: &[&str]) -> Result<BTreeSet<String>> {
    let mut allowed = BTreeSet::new();
    for chunk in arns.chunks(SIMULATED_PER_CALL) {
        allowed.extend(iam.simulate_assume_role(source_arn, chunk).await?);
    }
    Ok(allowed)
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
            let mut params = vec![("Action", "ListRoles".to_string())];
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

    /// The role ARNs among `resources` the policy simulator lets
    /// `source_arn` call `sts:AssumeRole` on.
    async fn simulate_assume_role(
        &self,
        source_arn: &str,
        resources: &[&str],
    ) -> Result<Vec<String>> {
        let action = "iam:SimulatePrincipalPolicy";
        let mut allowed = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let mut params = vec![
                ("Action", "SimulatePrincipalPolicy".to_string()),
                ("PolicySourceArn", source_arn.to_string()),
                ("ActionNames.member.1", "sts:AssumeRole".to_string()),
            ];
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
            allowed.extend(page.allowed);
            match page.marker {
                Some(m) if page.truncated => marker = Some(m),
                _ => return Ok(allowed),
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

/// One page of `SimulatePrincipalPolicy`, as the resources it allows.
#[derive(Debug, Default)]
struct SimulationPage {
    allowed: Vec<String>,
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

/// The resources the simulator allows. With several resources, IAM gives
/// one result per action whose own resource is the statement's pattern
/// (`arn:aws:iam::${Account}:${RelativeId}`) and whose decision is the
/// strictest, and the answer for each resource in `ResourceSpecificResults`;
/// with one resource, that resource and its decision are the result's own.
fn parse_simulation(body: &str) -> anyhow::Result<SimulationPage> {
    let mut page = SimulationPage::default();
    result_children(body, "SimulatePrincipalPolicyResult", |tag| {
        if tag.start_el().matches("IsTruncated") {
            page.truncated = text(tag)? == "true";
        } else if tag.start_el().matches("Marker") {
            page.marker = Some(text(tag)?);
        } else if tag.start_el().matches("EvaluationResults") {
            children(tag, |member| {
                let (mut resource, mut decision) = (None, None);
                let mut specific = Vec::new();
                children(member, |field| {
                    let el = field.start_el();
                    if el.matches("EvalResourceName") {
                        resource = Some(text(field)?);
                    } else if el.matches("EvalDecision") {
                        decision = Some(text(field)?);
                    } else if el.matches("ResourceSpecificResults") {
                        children(field, |each| {
                            let (mut name, mut decision) = (None, None);
                            children(each, |f| {
                                if f.start_el().matches("EvalResourceName") {
                                    name = Some(text(f)?);
                                } else if f.start_el().matches("EvalResourceDecision") {
                                    decision = Some(text(f)?);
                                }
                                Ok(())
                            })?;
                            if let (Some(name), Some(decision)) = (name, decision) {
                                specific.push((name, decision));
                            }
                            Ok(())
                        })?;
                    }
                    Ok(())
                })?;
                if specific.is_empty() {
                    if decision.as_deref() == Some("allowed")
                        && let Some(arn) = resource
                    {
                        page.allowed.push(arn);
                    }
                } else {
                    page.allowed.extend(
                        specific
                            .into_iter()
                            .filter(|(_, d)| d == "allowed")
                            .map(|(name, _)| name),
                    );
                }
                Ok(())
            })?;
        }
        Ok(())
    })?;
    Ok(page)
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

/// Whether a trust policy (URL-encoded JSON, as IAM returns it) allows one
/// of `principals` to call `sts:AssumeRole`: `Some(true)` when every
/// allowing statement has conditions, `None` when none allows it. A `Deny`
/// is left to the simulator, which sees only the source's side, so a denied
/// role can still be listed; the simulator's answer is a guess either way.
fn trusts(document: &str, principals: &[&str]) -> anyhow::Result<Option<bool>> {
    let json = percent_decode(document)?;
    let policy: Value = serde_json::from_str(&json).context("not JSON")?;
    let statements = match &policy["Statement"] {
        Value::Array(list) => list.clone(),
        Value::Object(_) => vec![policy["Statement"].clone()],
        _ => return Ok(None),
    };
    let mut found = None;
    for statement in statements {
        if statement["Effect"] != "Allow" {
            continue;
        }
        let actions = strings(&statement["Action"]);
        if !actions.iter().any(|a| {
            matches!(
                a.to_ascii_lowercase().as_str(),
                "sts:assumerole" | "sts:*" | "*"
            )
        }) {
            continue;
        }
        let aws = match &statement["Principal"] {
            Value::String(s) if s == "*" => vec!["*".to_string()],
            Value::Object(map) => map.get("AWS").map(strings).unwrap_or_default(),
            _ => Vec::new(),
        };
        if aws
            .iter()
            .any(|p| p == "*" || principals.contains(&p.as_str()))
        {
            let conditional = statement
                .get("Condition")
                .is_some_and(|c| c.as_object().is_some_and(|o| !o.is_empty()));
            // Conditional only when every statement that allows it is.
            found = Some(found.unwrap_or(true) && conditional);
        }
    }
    Ok(found)
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

    #[test]
    fn trust_policies_are_read_for_the_account_or_the_role() {
        let root = "arn:aws:iam::111111111111:root";
        let source =
            "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_pe_1";
        let principals = [root, "111111111111", source];
        let doc = |principal: &str, extra: &str| {
            encoded(&format!(
                r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":{principal}}},"Action":"sts:AssumeRole"{extra}}}]}}"#
            ))
        };
        assert_eq!(
            trusts(&doc(&format!("\"{root}\""), ""), &principals).unwrap(),
            Some(false)
        );
        assert_eq!(
            trusts(
                &doc(
                    &format!("[\"arn:aws:iam::999999999999:root\",\"{source}\"]"),
                    ""
                ),
                &principals
            )
            .unwrap(),
            Some(false)
        );
        assert_eq!(
            trusts(&doc("\"111111111111\"", ""), &principals).unwrap(),
            Some(false)
        );
        // Conditions are reported, not evaluated.
        assert_eq!(
            trusts(
                &doc(
                    &format!("\"{root}\""),
                    r#","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}"#
                ),
                &principals
            )
            .unwrap(),
            Some(true)
        );
        // Another account, a service, or another action: not this source.
        assert_eq!(
            trusts(&doc("\"arn:aws:iam::999999999999:root\"", ""), &principals).unwrap(),
            None
        );
        let service = encoded(
            r#"{"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}"#,
        );
        assert_eq!(trusts(&service, &principals).unwrap(), None);
        let tagging = encoded(&format!(
            r#"{{"Statement":{{"Effect":"Allow","Principal":{{"AWS":"{root}"}},"Action":"sts:TagSession"}}}}"#
        ));
        assert_eq!(trusts(&tagging, &principals).unwrap(), None);
        // Unconditional once any statement that allows it is.
        let both = encoded(&format!(
            r#"{{"Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{root}"}},"Action":"sts:AssumeRole"}},{{"Effect":"Allow","Principal":{{"AWS":"{root}"}},"Action":"sts:AssumeRole","Condition":{{"Bool":{{"aws:MultiFactorAuthPresent":"true"}}}}}}]}}"#
        ));
        assert_eq!(trusts(&both, &principals).unwrap(), Some(false));
        assert!(trusts("%zz", &principals).is_err());
    }
}
