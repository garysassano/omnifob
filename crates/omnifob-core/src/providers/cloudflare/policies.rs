//! Token policies from templates: permission names resolved against the
//! account's permission groups, resources, and client IP ranges.

use std::collections::{BTreeMap, HashMap};

use anyhow::{Context, bail};
use serde_json::{Value, json};

use super::{PermissionGroup, SCOPE_ACCOUNT, SCOPE_R2_BUCKET, SCOPE_USER, SCOPE_ZONE};
use crate::config::CloudflareTokenType;

/// Resolves permission names to groups, case-insensitively, and reports every
/// unknown name at once with suggestions.
pub fn resolve_permissions<'a>(
    names: &[String],
    groups: &'a [PermissionGroup],
) -> anyhow::Result<Vec<&'a PermissionGroup>> {
    let by_name: HashMap<String, &PermissionGroup> =
        groups.iter().map(|g| (g.name.to_lowercase(), g)).collect();
    let mut resolved = Vec::new();
    let mut unknown = Vec::new();
    // The dashboard says "Edit" where the API says "Write"; accept both.
    let lookup = |name: &str| {
        let lower = name.to_lowercase();
        by_name.get(&lower).copied().or_else(|| {
            let alias = match lower.rsplit_once(' ') {
                Some((base, "edit")) => format!("{base} write"),
                Some((base, "write")) => format!("{base} edit"),
                _ => return None,
            };
            by_name.get(&alias).copied()
        })
    };
    for name in names {
        match lookup(name) {
            Some(group) => resolved.push(group),
            None => {
                let words: Vec<String> = name
                    .to_lowercase()
                    .split_whitespace()
                    .map(str::to_string)
                    .collect();
                let mut close: Vec<&str> = groups
                    .iter()
                    .filter(|g| {
                        let g = g.name.to_lowercase();
                        words.iter().filter(|w| g.contains(w.as_str())).count()
                            >= words.len().max(2) - 1
                    })
                    .map(|g| g.name.as_str())
                    .collect();
                close.sort_unstable();
                close.truncate(5);
                if close.is_empty() {
                    unknown.push(format!("'{name}'"));
                } else {
                    unknown.push(format!("'{name}' (did you mean: {}?)", close.join(", ")));
                }
            }
        }
    }
    if !unknown.is_empty() {
        bail!(
            "unknown Cloudflare permission(s): {}. Run `fob cloudflare permissions` to list them.",
            unknown.join("; ")
        );
    }
    Ok(resolved)
}

/// The permissions of one service ("Workers Scripts"), as the dashboard
/// shows them: a Read and an Edit (API: Write) level, and any other ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub name: String,
    pub read: Option<PermissionGroup>,
    pub write: Option<PermissionGroup>,
    pub other: Vec<PermissionGroup>,
}

impl Service {
    /// What the service applies to: account, zone or user.
    pub fn scope(&self) -> &str {
        self.read
            .iter()
            .chain(&self.write)
            .chain(&self.other)
            .find_map(|g| g.scopes.first())
            .map_or("", |s| s.rsplit('.').next().unwrap_or(s))
    }
}

/// Groups permissions by service, sorted by name. Account-owned tokens
/// cannot carry user-level permissions, so those are left out for them.
pub fn services(groups: &[PermissionGroup], token_type: CloudflareTokenType) -> Vec<Service> {
    let mut by_name: BTreeMap<String, Service> = BTreeMap::new();
    for group in groups {
        if token_type == CloudflareTokenType::Account
            && group.scopes.iter().any(|s| s == SCOPE_USER)
        {
            continue;
        }
        let (base, level) = match group.name.rsplit_once(' ') {
            Some((base, "Read")) => (base, Some(false)),
            Some((base, "Write" | "Edit")) => (base, Some(true)),
            _ => (group.name.as_str(), None),
        };
        let service = by_name
            .entry(base.to_lowercase())
            .or_insert_with(|| Service {
                name: base.to_string(),
                read: None,
                write: None,
                other: Vec::new(),
            });
        match level {
            Some(false) if service.read.is_none() => service.read = Some(group.clone()),
            Some(true) if service.write.is_none() => service.write = Some(group.clone()),
            _ => service.other.push(group.clone()),
        }
    }
    by_name.into_values().collect()
}

/// Builds token policies: one per resource kind the permissions apply to,
/// each limited to the given account (and, for zone permissions, the zones
/// in `zone_ids`, or every zone in that account when it is empty; for R2
/// bucket permissions, the listed buckets).
pub fn build_policies(
    groups: &[&PermissionGroup],
    account_id: &str,
    user_tag: Option<&str>,
    r2_buckets: &[String],
    zone_ids: &[String],
) -> anyhow::Result<Vec<Value>> {
    let mut by_scope: BTreeMap<&str, Vec<Value>> = BTreeMap::new();
    for group in groups {
        let scope = group
            .scopes
            .first()
            .with_context(|| format!("permission '{}' has no scope", group.name))?;
        by_scope
            .entry(scope.as_str())
            .or_default()
            .push(json!({ "id": group.id, "name": group.name }));
    }

    let account = format!("{SCOPE_ACCOUNT}.{account_id}");
    by_scope
        .into_iter()
        .map(|(scope, permission_groups)| {
            let resources = match scope {
                SCOPE_ACCOUNT => json!({ account.clone(): "*" }),
                // Single zones are named on their own, not under the account.
                SCOPE_ZONE if !zone_ids.is_empty() => Value::Object(
                    zone_ids
                        .iter()
                        .map(|id| (format!("{SCOPE_ZONE}.{id}"), json!("*")))
                        .collect(),
                ),
                SCOPE_ZONE => json!({ account.clone(): { format!("{SCOPE_ZONE}.*"): "*" } }),
                SCOPE_USER => {
                    let tag = user_tag.context(
                        "user-level permissions (like 'User Details Read') need a user-owned bootstrap token",
                    )?;
                    json!({ format!("{SCOPE_USER}.{tag}"): "*" })
                }
                SCOPE_R2_BUCKET => {
                    if r2_buckets.is_empty() {
                        bail!(
                            "{} apply to single R2 buckets; list them in the template's `r2_buckets`",
                            names(&permission_groups)
                        );
                    }
                    let buckets: serde_json::Map<String, Value> = r2_buckets
                        .iter()
                        .map(|b| {
                            let (jurisdiction, name) = b.split_once('/').unwrap_or(("default", b));
                            (format!("{SCOPE_R2_BUCKET}.{account_id}_{jurisdiction}_{name}"), json!("*"))
                        })
                        .collect();
                    Value::Object(buckets)
                }
                other => bail!(
                    "{} apply to '{other}', which omnifob cannot scope yet",
                    names(&permission_groups)
                ),
            };
            Ok(json!({ "effect": "allow", "resources": resources, "permission_groups": permission_groups }))
        })
        .collect()
}

/// Whether `zone` is written as a zone ID (32 hexadecimal digits) rather
/// than as a domain name.
pub fn is_zone_id(zone: &str) -> bool {
    zone.len() == 32 && zone.bytes().all(|b| b.is_ascii_hexdigit())
}

pub(super) fn names(permission_groups: &[Value]) -> String {
    let names: Vec<&str> = permission_groups
        .iter()
        .filter_map(|g| g["name"].as_str())
        .collect();
    format!("'{}'", names.join("', '"))
}

/// Resolves the addresses a token may be used from to CIDR ranges.
/// "current" is this machine's public IPv4 and IPv6 address, as Cloudflare
/// sees them at `api_base`.
pub async fn resolve_ips(ips: &[String], api_base: &str) -> anyhow::Result<Vec<String>> {
    let mut resolved = Vec::new();
    for ip in ips {
        if ip == "current" {
            let current = current_ips(api_base).await;
            if current.is_empty() {
                bail!("could not find this machine's public address for `ips = [\"current\"]`");
            }
            resolved.extend(current.iter().map(|ip| cidr(*ip)));
            continue;
        }
        resolved.push(ip_range(ip)?);
    }
    resolved.dedup();
    Ok(resolved)
}

/// An IP address or CIDR range as the CIDR range Cloudflare takes: an
/// address alone becomes a `/32` or `/128`. The config check uses it too, so
/// a typo fails when the config loads rather than at the next mint.
pub(crate) fn ip_range(ip: &str) -> anyhow::Result<String> {
    let (addr, prefix) = ip.split_once('/').map_or((ip, None), |(a, p)| (a, Some(p)));
    let addr: std::net::IpAddr = addr
        .parse()
        .with_context(|| format!("'{ip}' is not an IP address, a CIDR range or \"current\""))?;
    Ok(match prefix {
        Some(prefix) => {
            let max = if addr.is_ipv4() { 32 } else { 128 };
            match prefix.parse::<u8>() {
                Ok(p) if p <= max => format!("{addr}/{p}"),
                _ => bail!("'{ip}' has an invalid prefix length"),
            }
        }
        None => cidr(addr),
    })
}

fn cidr(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(ip) => format!("{ip}/32"),
        std::net::IpAddr::V6(ip) => format!("{ip}/128"),
    }
}

/// This machine's public addresses, one per IP version that works, from
/// Cloudflare's trace endpoint. Tools may connect over either version, so
/// both are allowed.
async fn current_ips(api_base: &str) -> Vec<std::net::IpAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let trace = match api_base.find("/client/v4") {
        Some(i) => format!("{}/cdn-cgi/trace", &api_base[..i]),
        None => format!("{api_base}/cdn-cgi/trace"),
    };
    let lookup = |local: IpAddr| {
        let trace = trace.clone();
        async move {
            let client = crate::http::builder()
                .local_address(local)
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .ok()?;
            let text = client.get(&trace).send().await.ok()?.text().await.ok()?;
            text.lines()
                .find_map(|l| l.strip_prefix("ip="))
                .and_then(|ip| ip.trim().parse::<IpAddr>().ok())
        }
    };
    let (v4, v6) = tokio::join!(
        lookup(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        lookup(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
    );
    v4.into_iter().chain(v6).collect()
}

/// The user tag appears in the resources of the bootstrap token's own policy;
/// reading it there avoids needing the "User Details Read" permission.
pub(super) fn user_tag_from_policies(policies: &[Value]) -> Option<String> {
    let prefix = format!("{SCOPE_USER}.");
    policies.iter().find_map(|policy| {
        policy["resources"].as_object()?.keys().find_map(|k| {
            k.strip_prefix(&prefix)
                .filter(|t| *t != "*")
                .map(str::to_string)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::cloudflare::API_BASE;

    fn group(id: &str, name: &str, scope: &str) -> PermissionGroup {
        PermissionGroup {
            id: id.into(),
            name: name.into(),
            scopes: vec![scope.into()],
        }
    }

    fn groups() -> Vec<PermissionGroup> {
        vec![
            group("w", "Workers Scripts Write", SCOPE_ACCOUNT),
            group("z", "Zone Read", SCOPE_ZONE),
            group("d", "DNS Write", SCOPE_ZONE),
            group("u", "User Details Read", SCOPE_USER),
        ]
    }

    #[test]
    fn resolves_names_case_insensitively() {
        let groups = groups();
        let names = vec!["workers scripts write".to_string(), "Zone Read".to_string()];
        let ids: Vec<_> = resolve_permissions(&names, &groups)
            .unwrap()
            .iter()
            .map(|g| g.id.as_str())
            .collect();
        assert_eq!(ids, ["w", "z"]);
    }

    #[test]
    fn unknown_names_suggest_close_matches() {
        let groups = groups();
        let err = resolve_permissions(&["Workers Script Write".to_string()], &groups).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("'Workers Script Write'"), "{msg}");
        assert!(msg.contains("Workers Scripts Write"), "{msg}");
    }

    #[test]
    fn dashboard_edit_names_mean_write() {
        let groups = groups();
        let names = vec!["Workers Scripts Edit".to_string(), "dns edit".to_string()];
        let ids: Vec<_> = resolve_permissions(&names, &groups)
            .unwrap()
            .iter()
            .map(|g| g.id.as_str())
            .collect();
        assert_eq!(ids, ["w", "d"]);
    }

    #[test]
    fn policies_group_by_scope_and_limit_to_account() {
        let groups = groups();
        let selected: Vec<_> = groups.iter().collect();
        let policies = build_policies(&selected, "acct", Some("tag"), &[], &[]).unwrap();
        assert_eq!(policies.len(), 3);
        let resources: Vec<_> = policies.iter().map(|p| p["resources"].clone()).collect();
        assert!(resources.contains(&json!({ "com.cloudflare.api.account.acct": "*" })));
        assert!(resources.contains(&json!({
            "com.cloudflare.api.account.acct": { "com.cloudflare.api.account.zone.*": "*" }
        })));
        assert!(resources.contains(&json!({ "com.cloudflare.api.user.tag": "*" })));
        let zone = policies
            .iter()
            .find(|p| p["resources"].to_string().contains("zone"))
            .unwrap();
        assert_eq!(zone["permission_groups"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn zone_permissions_can_be_limited_to_zones() {
        let groups = groups();
        let selected: Vec<_> = groups.iter().filter(|g| g.id != "u").collect();
        let zones = [
            "0123456789abcdef0123456789abcdef".to_string(),
            "fedcba9876543210fedcba9876543210".to_string(),
        ];
        let policies = build_policies(&selected, "acct", None, &[], &zones).unwrap();
        let resources: Vec<_> = policies.iter().map(|p| p["resources"].clone()).collect();
        // Account permissions keep the account; zone ones name each zone.
        assert!(resources.contains(&json!({ "com.cloudflare.api.account.acct": "*" })));
        assert!(resources.contains(&json!({
            "com.cloudflare.api.account.zone.0123456789abcdef0123456789abcdef": "*",
            "com.cloudflare.api.account.zone.fedcba9876543210fedcba9876543210": "*"
        })));
        assert!(is_zone_id(&zones[0]));
        assert!(!is_zone_id("example.com"));
        assert!(!is_zone_id("0123456789abcdef0123456789abcdeg"));
    }

    #[test]
    fn user_permissions_need_a_user_tag() {
        let groups = groups();
        let user: Vec<_> = groups.iter().filter(|g| g.id == "u").collect();
        assert!(build_policies(&user, "acct", None, &[], &[]).is_err());
    }

    #[test]
    fn finds_user_tag_in_bootstrap_policy() {
        let policies = vec![json!({
            "resources": { "com.cloudflare.api.user.abc123": "*" },
            "permission_groups": []
        })];
        assert_eq!(user_tag_from_policies(&policies).as_deref(), Some("abc123"));
    }

    #[test]
    fn bucket_permissions_need_and_use_buckets() {
        let groups = [group(
            "b",
            "Workers R2 Storage Bucket Item Write",
            SCOPE_R2_BUCKET,
        )];
        let selected: Vec<&PermissionGroup> = groups.iter().collect();
        let err = build_policies(&selected, "acct", None, &[], &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("r2_buckets"), "{err}");
        let policies = build_policies(
            &selected,
            "acct",
            None,
            &["logs".into(), "eu/backups".into()],
            &[],
        )
        .unwrap();
        let resources = policies[0]["resources"].as_object().unwrap();
        let keys: Vec<&str> = resources.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "com.cloudflare.edge.r2.bucket.acct_default_logs",
                "com.cloudflare.edge.r2.bucket.acct_eu_backups"
            ]
        );
    }

    #[tokio::test]
    async fn ips_become_cidr_ranges() {
        let ips = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            resolve_ips(
                &ips(&["203.0.113.7", "198.51.100.0/24", "2001:db8::1"]),
                API_BASE
            )
            .await
            .unwrap(),
            ["203.0.113.7/32", "198.51.100.0/24", "2001:db8::1/128"]
        );
        assert!(resolve_ips(&ips(&["10.0.0.0/33"]), API_BASE).await.is_err());
        assert!(resolve_ips(&ips(&["example.com"]), API_BASE).await.is_err());
    }

    #[test]
    fn services_pair_read_and_write() {
        let groups = vec![
            group("1", "Workers Scripts Read", SCOPE_ACCOUNT),
            group("2", "Workers Scripts Write", SCOPE_ACCOUNT),
            group("3", "DNS Read", SCOPE_ZONE),
            group("4", "Memberships Read", SCOPE_USER),
            group("5", "Cache Purge", SCOPE_ZONE),
        ];
        let all = services(&groups, CloudflareTokenType::User);
        let names: Vec<&str> = all.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            ["Cache Purge", "DNS", "Memberships", "Workers Scripts"]
        );
        let workers = &all[3];
        assert_eq!(workers.read.as_ref().unwrap().id, "1");
        assert_eq!(workers.write.as_ref().unwrap().id, "2");
        assert_eq!(all[0].other.len(), 1);
        assert_eq!(all[1].scope(), "zone");
        let account = services(&groups, CloudflareTokenType::Account);
        assert!(account.iter().all(|s| s.name != "Memberships"));
    }
}
