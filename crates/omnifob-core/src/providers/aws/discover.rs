//! `fob discover aws`: roles an Identity Center role may assume in its own
//! account, which Identity Center does not list.
//!
//! For each source (an account and a permission set), the role's
//! credentials list the account's IAM roles (`iam:ListRoles`), keep those
//! whose trust policy lets the account, or the source role itself, call
//! `sts:AssumeRole`, and ask the policy simulator
//! (`iam:SimulatePrincipalPolicy`) whether the source role's own policies
//! allow it. Nothing is assumed, so no `AssumeRole` reaches CloudTrail.
//!
//! The answer is a guess: the simulator evaluates the source role's
//! identity policies, permissions boundary and the organization's service
//! control policies it can see, but not resource control policies, and
//! fob does not evaluate the conditions of a trust policy (MFA, tags,
//! external IDs). A role it finds can still refuse, and one it misses may
//! work.

use anyhow::{Context, anyhow};
use aws_sdk_iam::error::ProvideErrorMetadata;
use futures::StreamExt;
use serde_json::Value;

use super::service_endpoint;
use crate::config::{AwsSsoConfig, ChainedRole};
use crate::{Credentials, Result};

/// The variable the AWS CLI and SDKs read for IAM's endpoint.
pub(crate) const IAM_ENDPOINT_VARIABLE: &str = "AWS_ENDPOINT_URL_IAM";

/// How many sources are searched at once: each is a handful of IAM calls,
/// and IAM throttles an account's callers together.
const CONCURRENCY: usize = 4;

/// How many roles one `SimulatePrincipalPolicy` call evaluates.
const SIMULATED_PER_CALL: usize = 20;

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
}

/// Searches every source, a few at a time.
pub async fn discover(integration: &str, config: &AwsSsoConfig, sources: Vec<Source>) -> Discovery {
    let results: Vec<(Source, Result<Vec<Found>>)> =
        futures::stream::iter(sources.into_iter().map(|source| async move {
            let found = search(integration, config, &source).await;
            (source, found)
        }))
        .buffer_unordered(CONCURRENCY)
        .collect()
        .await;
    let mut discovery = Discovery::default();
    for (source, result) in results {
        match result {
            Ok(found) => discovery.found.extend(found),
            Err(e) => discovery.skipped.push(Skipped {
                source,
                reason: format!("{e:#}"),
            }),
        }
    }
    discovery.found.sort_by(|a, b| a.label.cmp(&b.label));
    discovery.skipped.sort_by(|a, b| {
        (&a.source.segment, &a.source.via_role).cmp(&(&b.source.segment, &b.source.via_role))
    });
    discovery
}

/// The roles one source may assume in its account.
async fn search(integration: &str, config: &AwsSsoConfig, source: &Source) -> Result<Vec<Found>> {
    let partition = config.partition()?;
    let creds =
        super::sso::credentials(integration, config, &source.account_id, &source.via_role).await?;
    let iam = iam_client(&creds, partition.default_region())?;
    let roles: Vec<aws_sdk_iam::types::Role> = iam
        .list_roles()
        .into_paginator()
        .items()
        .send()
        .try_collect()
        .await
        .map_err(|e| iam_error("iam:ListRoles", e))?;
    // The role Identity Center made for the permission set in this account.
    let prefix = format!("AWSReservedSSO_{}_", source.via_role);
    let source_arn = roles
        .iter()
        .find(|r| r.role_name().starts_with(&prefix) && r.path().starts_with("/aws-reserved/"))
        .map(|r| r.arn().to_string())
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
    for role in &roles {
        if role.arn() == source_arn
            || role.path().starts_with("/aws-service-role/")
            || role.path().starts_with("/aws-reserved/")
        {
            continue;
        }
        let Some(document) = role.assume_role_policy_document() else {
            continue;
        };
        if let Some(conditional) = trusts(document, &[&root, &source.account_id, &source_arn])
            .with_context(|| format!("reading the trust policy of {}", role.role_name()))?
        {
            candidates.push((role, conditional));
        }
    }
    let mut allowed = std::collections::BTreeSet::new();
    for chunk in candidates.chunks(SIMULATED_PER_CALL) {
        let results: Vec<aws_sdk_iam::types::EvaluationResult> = iam
            .simulate_principal_policy()
            .policy_source_arn(&source_arn)
            .action_names("sts:AssumeRole")
            .set_resource_arns(Some(
                chunk.iter().map(|(r, _)| r.arn().to_string()).collect(),
            ))
            .into_paginator()
            .items()
            .send()
            .try_collect()
            .await
            .map_err(|e| iam_error("iam:SimulatePrincipalPolicy", e))?;
        allowed.extend(allowed_resources(&results));
    }
    Ok(candidates
        .into_iter()
        .filter(|(role, _)| allowed.contains(role.arn()))
        .map(|(role, conditional)| Found {
            label: format!(
                "{}-{}",
                source.segment,
                crate::profile::slug(role.role_name())
            ),
            role: ChainedRole {
                via_account_id: source.account_id.clone(),
                via_role: source.via_role.clone(),
                role_arn: role.arn().to_string(),
                session_name: None,
                external_id: None,
                region: None,
                mfa_serial: None,
                duration: None,
            },
            conditional,
        })
        .collect())
}

/// The resources the simulator allows. With several resources, IAM gives
/// one result per action whose own resource is the statement's pattern
/// (`arn:aws:iam::${Account}:${RelativeId}`) and whose decision is the
/// strictest, and the answer for each resource in `ResourceSpecificResults`;
/// with one resource, that resource and its decision are the result's own.
fn allowed_resources(results: &[aws_sdk_iam::types::EvaluationResult]) -> Vec<String> {
    use aws_sdk_iam::types::PolicyEvaluationDecisionType::Allowed;
    let mut allowed = Vec::new();
    for result in results {
        let specific = result.resource_specific_results();
        if specific.is_empty() {
            if result.eval_decision() == &Allowed
                && let Some(arn) = result.eval_resource_name()
            {
                allowed.push(arn.to_string());
            }
        } else {
            allowed.extend(
                specific
                    .iter()
                    .filter(|r| r.eval_resource_decision() == &Allowed)
                    .map(|r| r.eval_resource_name().to_string()),
            );
        }
    }
    allowed
}

/// An IAM client signed with `creds`, in the partition's IAM Region.
fn iam_client(creds: &Credentials, region: &str) -> anyhow::Result<aws_sdk_iam::Client> {
    let get = |k: &str| {
        creds
            .env
            .get(k)
            .cloned()
            .with_context(|| format!("{k} missing from the credentials"))
    };
    let provider = aws_sdk_iam::config::Credentials::new(
        get("AWS_ACCESS_KEY_ID")?,
        get("AWS_SECRET_ACCESS_KEY")?,
        creds.env.get("AWS_SESSION_TOKEN").cloned(),
        None,
        "omnifob",
    );
    let mut config = aws_sdk_iam::Config::builder()
        .region(aws_sdk_iam::config::Region::new(region.to_string()))
        .credentials_provider(provider)
        .behavior_version(aws_sdk_iam::config::BehaviorVersion::latest());
    if let Some(url) = service_endpoint(IAM_ENDPOINT_VARIABLE) {
        config = config.endpoint_url(url);
    }
    Ok(aws_sdk_iam::Client::from_conf(config.build()))
}

/// An IAM failure, naming the permission the source lacks when IAM says so.
fn iam_error<E>(action: &str, e: aws_sdk_iam::error::SdkError<E>) -> crate::Error
where
    E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
{
    match e.code() {
        Some("AccessDenied" | "AccessDeniedException") => {
            anyhow!("the permission set may not call {action}").into()
        }
        _ => anyhow!("{action} failed: {}", e.message().unwrap_or("no message")).into(),
    }
}

/// Whether a trust policy (URL-encoded JSON, as IAM returns it) allows one
/// of `principals` to call `sts:AssumeRole`: `Some(true)` when an allowing
/// statement has conditions, `None` when none allows it. A `Deny` is left
/// to the simulator, which sees only the source's side, so a denied role
/// can still be listed; the simulator's answer is a guess either way.
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
            found = Some(found.unwrap_or(false) || conditional);
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
        assert!(trusts("%zz", &principals).is_err());
    }
}
