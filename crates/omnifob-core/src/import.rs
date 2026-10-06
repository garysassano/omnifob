//! Imports from, and exports to, other tools' configuration.

use std::collections::BTreeMap;

/// An IAM Identity Center portal found in `~/.aws/config`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsPortal {
    /// Suggested integration name: the `sso-session` name, or the portal's
    /// subdomain.
    pub name: String,
    pub start_url: String,
    pub region: String,
    /// The region most of the portal's profiles use.
    pub default_region: Option<String>,
    /// How many profiles in the file use this portal.
    pub profiles: usize,
    /// Roles assumed from this portal's roles (`role_arn` + `source_profile`),
    /// keyed by a label made from the profile name.
    pub chained: BTreeMap<String, crate::config::ChainedRole>,
    /// Chained profiles that could not be imported, with the reason.
    pub skipped: Vec<(String, &'static str)>,
}

/// `https://Acme.awsapps.com/start/` and `https://acme.awsapps.com/start`
/// are the same portal.
pub fn normalize_start_url(url: &str) -> String {
    let url = url.trim().trim_end_matches('/');
    match url.split_once("://") {
        Some((scheme, rest)) => match rest.split_once('/') {
            Some((host, path)) => {
                format!("{}://{}/{path}", scheme.to_lowercase(), host.to_lowercase())
            }
            None => format!("{}://{}", scheme.to_lowercase(), rest.to_lowercase()),
        },
        None => url.to_string(),
    }
}

/// Parses an AWS config file into `section → key → value`.
fn parse_ini(text: &str) -> Vec<(String, BTreeMap<String, String>)> {
    let mut sections: Vec<(String, BTreeMap<String, String>)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            sections.push((name.trim().to_string(), BTreeMap::new()));
        } else if let Some((key, value)) = line.split_once('=')
            && let Some((_, keys)) = sections.last_mut()
        {
            keys.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    sections
}

/// The Identity Center role a profile signs in with.
struct SsoRef {
    start_url: String,
    sso_region: String,
    session_name: Option<String>,
    account_id: Option<String>,
    role_name: Option<String>,
}

fn sso_ref(
    keys: &BTreeMap<String, String>,
    sessions: &BTreeMap<&str, &BTreeMap<String, String>>,
) -> Option<SsoRef> {
    let get = |k: &str| keys.get(k).cloned();
    let (start_url, sso_region, session_name) = if let Some(session) = keys.get("sso_session") {
        let s = sessions.get(session.as_str())?;
        (
            s.get("sso_start_url")?.clone(),
            s.get("sso_region")?.clone(),
            Some(session.clone()),
        )
    } else if let (Some(u), Some(r)) = (get("sso_start_url"), get("sso_region")) {
        (u, r, None)
    } else if let (Some(u), Some(r)) = (get("granted_sso_start_url"), get("granted_sso_region")) {
        (u, r, None)
    } else {
        return None;
    };
    Some(SsoRef {
        start_url: normalize_start_url(&start_url),
        sso_region,
        session_name,
        account_id: get("sso_account_id").or_else(|| get("granted_sso_account_id")),
        role_name: get("sso_role_name").or_else(|| get("granted_sso_role_name")),
    })
}

/// Finds every Identity Center portal referenced by profiles in an AWS
/// config file (`sso_session` references, inline `sso_start_url` and
/// `sso_region`, granted's `granted_sso_*` keys), and the roles chained from
/// them through `role_arn` and `source_profile`.
pub fn aws_portals(text: &str) -> Vec<AwsPortal> {
    let sections = parse_ini(text);
    let sessions: BTreeMap<&str, &BTreeMap<String, String>> = sections
        .iter()
        .filter_map(|(name, keys)| Some((name.strip_prefix("sso-session")?.trim(), keys)))
        .collect();
    let profiles: BTreeMap<&str, &BTreeMap<String, String>> = sections
        .iter()
        .filter_map(|(name, keys)| {
            let profile = if name == "default" {
                "default"
            } else {
                name.strip_prefix("profile ")?.trim()
            };
            Some((profile, keys))
        })
        .collect();

    #[derive(Default)]
    struct Found {
        session_name: Option<String>,
        region: String,
        profiles: usize,
        regions: BTreeMap<String, usize>,
        chained: BTreeMap<String, crate::config::ChainedRole>,
        skipped: Vec<(String, &'static str)>,
    }
    let mut found: BTreeMap<String, Found> = BTreeMap::new();
    fn entry<'a>(found: &'a mut BTreeMap<String, Found>, sso: &SsoRef) -> &'a mut Found {
        let f = found.entry(sso.start_url.clone()).or_insert_with(|| Found {
            region: sso.sso_region.clone(),
            ..Found::default()
        });
        if f.session_name.is_none() {
            f.session_name = sso.session_name.clone();
        }
        f
    }

    for (name, keys) in &profiles {
        if let Some(sso) = sso_ref(keys, &sessions) {
            let f = entry(&mut found, &sso);
            f.profiles += 1;
            if let Some(region) = keys.get("region") {
                *f.regions.entry(region.clone()).or_default() += 1;
            }
        } else if let (Some(role_arn), Some(source)) =
            (keys.get("role_arn"), keys.get("source_profile"))
        {
            let Some(sso) = profiles
                .get(source.as_str())
                .and_then(|k| sso_ref(k, &sessions))
            else {
                continue; // chains from static keys or another chained role
            };
            let f = entry(&mut found, &sso);
            f.profiles += 1;
            let (Some(account_id), Some(role_name)) = (&sso.account_id, &sso.role_name) else {
                f.skipped.push((
                    name.to_string(),
                    "its source profile names no account and role",
                ));
                continue;
            };
            if keys.contains_key("mfa_serial") {
                f.skipped.push((
                    name.to_string(),
                    "it needs MFA, which omnifob does not support yet",
                ));
                continue;
            }
            f.chained.insert(
                crate::profile::slug(name),
                crate::config::ChainedRole {
                    via_account_id: account_id.clone(),
                    via_role: role_name.clone(),
                    role_arn: role_arn.clone(),
                    session_name: keys.get("role_session_name").cloned(),
                    external_id: keys.get("external_id").cloned(),
                    region: keys.get("region").cloned(),
                },
            );
        }
    }

    let mut used = BTreeMap::<String, usize>::new();
    found
        .into_iter()
        .map(|(start_url, f)| {
            let base = f.session_name.unwrap_or_else(|| subdomain(&start_url));
            let base = crate::profile::slug(&base);
            let n = used.entry(base.clone()).or_default();
            *n += 1;
            let name = if *n == 1 { base } else { format!("{base}-{n}") };
            let default_region = f
                .regions
                .into_iter()
                .max_by_key(|(region, count)| (*count, std::cmp::Reverse(region.clone())))
                .map(|(region, _)| region);
            AwsPortal {
                name,
                start_url,
                region: f.region,
                default_region,
                profiles: f.profiles,
                chained: f.chained,
                skipped: f.skipped,
            }
        })
        .collect()
}

fn subdomain(start_url: &str) -> String {
    start_url
        .split_once("://")
        .map_or(start_url, |(_, rest)| rest)
        .split(['.', '/'])
        .next()
        .unwrap_or("aws")
        .to_string()
}

/// TOML for an `aws-sso` integration and its chained roles, ready to append
/// to the config file.
pub fn aws_portal_toml(portal: &AwsPortal) -> String {
    let mut out = format!(
        "[integrations.{}]\ntype = \"aws-sso\"\nstart_url = \"{}\"\nregion = \"{}\"\n",
        portal.name, portal.start_url, portal.region
    );
    if let Some(region) = &portal.default_region {
        out.push_str(&format!("default_region = \"{region}\"\n"));
    }
    out.push_str(&chained_toml(&portal.name, &portal.chained));
    out
}

/// `[integrations.<name>.chained."<label>"]` tables.
pub fn chained_toml(
    integration: &str,
    chained: &BTreeMap<String, crate::config::ChainedRole>,
) -> String {
    let mut out = String::new();
    for (label, role) in chained {
        let table = toml::to_string(role).expect("a chained role serializes");
        out.push_str(&format!(
            "\n[integrations.{integration}.chained.\"{label}\"]\n{table}"
        ));
    }
    out
}

/// Lines that delimit the block omnifob manages in `~/.aws/config`.
pub const AWS_BLOCK_BEGIN: &str =
    "# BEGIN omnifob (generated by `fob export aws-config`; edits inside are overwritten)";
pub const AWS_BLOCK_END: &str = "# END omnifob";

/// `[profile ...]` sections that get credentials from `fob creds`, one per
/// AWS profile, named `<prefix><integration>-<account>-<role>`. `regions`
/// maps profile ids to the region to set.
pub fn aws_config_block(
    profiles: &[&crate::Profile],
    prefix: &str,
    regions: &BTreeMap<String, String>,
) -> String {
    let mut out = format!("{AWS_BLOCK_BEGIN}\n");
    for p in profiles {
        if !matches!(
            p.target,
            crate::Target::Aws { .. } | crate::Target::AwsChained { .. }
        ) {
            continue;
        }
        let name = format!("{prefix}{}", p.id.replace('/', "-"));
        out.push_str(&format!(
            "[profile {name}]\ncredential_process = fob creds {} --format credential-process\n",
            p.id
        ));
        if let Some(region) = regions.get(&p.id) {
            out.push_str(&format!("region = {region}\n"));
        }
        out.push('\n');
    }
    out.push_str(AWS_BLOCK_END);
    out.push('\n');
    out
}

/// Replaces omnifob's block in an AWS config file, or appends one.
pub fn replace_aws_block(existing: &str, block: &str) -> String {
    match (existing.find(AWS_BLOCK_BEGIN), existing.find(AWS_BLOCK_END)) {
        (Some(start), Some(end)) if end > start => {
            let after = &existing[end + AWS_BLOCK_END.len()..];
            let after = after.strip_prefix('\n').unwrap_or(after);
            format!("{}{block}{after}", &existing[..start])
        }
        _ => {
            let sep = if existing.is_empty() || existing.ends_with("\n\n") {
                ""
            } else if existing.ends_with('\n') {
                "\n"
            } else {
                "\n\n"
            };
            format!("{existing}{sep}{block}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
[default]
region = eu-west-1

# granted-style profiles
[profile gary-test]
granted_sso_start_url = https://d-111.awsapps.com/start/
granted_sso_region = eu-central-1
granted_sso_account_id = 111111111111
granted_sso_role_name = Admin
region = eu-central-1

[profile gary-mgmt]
granted_sso_start_url = https://D-111.awsapps.com/start
granted_sso_region = eu-central-1
region = eu-central-1

[profile gary-no-role]
granted_sso_start_url = https://d-111.awsapps.com/start
granted_sso_region = eu-central-1

[profile half-chained]
role_arn = arn:aws:iam::666666666666:role/X
source_profile = gary-no-role

; inline sso profile
[profile client-dev]
sso_start_url = https://client.awsapps.com/start
sso_region = eu-west-1
region = eu-west-1

[profile client-prd]
sso_session = client
sso_account_id = 999999999999
sso_role_name = Ops
region = eu-west-2

[profile client-prd2]
sso_session = client
region = eu-west-2

[sso-session client]
sso_start_url = https://client.awsapps.com/start/
sso_region = eu-west-1

[profile plain-keys]
aws_access_key_id = AKIA...

[profile gary-test-deploy]
role_arn = arn:aws:iam::222222222222:role/Deploy
source_profile = gary-test
role_session_name = gary
region = us-east-1

[profile client-prd-deploy]
role_arn = arn:aws:iam::333333333333:role/Deploy
source_profile = client-prd
external_id = xyz

[profile needs-mfa]
role_arn = arn:aws:iam::444444444444:role/Admin
source_profile = gary-test
mfa_serial = arn:aws:iam::111111111111:mfa/me

[profile from-static-keys]
role_arn = arn:aws:iam::555555555555:role/Admin
source_profile = plain-keys
"#;

    #[test]
    fn finds_each_portal_once() {
        let portals = aws_portals(CONFIG);
        assert_eq!(portals.len(), 2, "{portals:#?}");

        let client = portals
            .iter()
            .find(|p| p.start_url.contains("client"))
            .unwrap();
        assert_eq!(client.name, "client");
        assert_eq!(client.start_url, "https://client.awsapps.com/start");
        assert_eq!(client.region, "eu-west-1");
        assert_eq!(client.profiles, 4);
        assert_eq!(client.default_region.as_deref(), Some("eu-west-2"));

        let gary = portals
            .iter()
            .find(|p| p.start_url.contains("d-111"))
            .unwrap();
        assert_eq!(gary.name, "d-111");
        assert_eq!(gary.profiles, 6);
        assert_eq!(gary.default_region.as_deref(), Some("eu-central-1"));
    }

    #[test]
    fn imports_chained_roles() {
        let portals = aws_portals(CONFIG);
        let gary = portals
            .iter()
            .find(|p| p.start_url.contains("d-111"))
            .unwrap();
        let deploy = &gary.chained["gary-test-deploy"];
        assert_eq!(deploy.via_account_id, "111111111111");
        assert_eq!(deploy.via_role, "Admin");
        assert_eq!(deploy.session_name.as_deref(), Some("gary"));
        assert_eq!(deploy.region.as_deref(), Some("us-east-1"));
        assert_eq!(deploy.role_name(), "Deploy");
        let skipped: Vec<&str> = gary.skipped.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(skipped, ["half-chained", "needs-mfa"]);
        assert_eq!(gary.chained.len(), 1, "static-key sources are ignored");

        let client = portals
            .iter()
            .find(|p| p.start_url.contains("client"))
            .unwrap();
        let prd = &client.chained["client-prd-deploy"];
        assert_eq!(
            (prd.via_account_id.as_str(), prd.via_role.as_str()),
            ("999999999999", "Ops")
        );
        assert_eq!(prd.external_id.as_deref(), Some("xyz"));
    }

    #[test]
    fn toml_parses_as_config() {
        let toml: String = aws_portals(CONFIG)
            .iter()
            .map(aws_portal_toml)
            .collect::<Vec<_>>()
            .join("\n");
        let config = crate::Config::parse(&toml).unwrap();
        assert_eq!(config.integrations.len(), 2);
        let crate::Integration::AwsSso(client) = &config.integrations["client"] else {
            panic!()
        };
        assert_eq!(
            client.chained["client-prd-deploy"].external_id.as_deref(),
            Some("xyz")
        );
    }

    #[test]
    fn aws_block_is_replaced_in_place() {
        let p = crate::Profile::new(
            "acme",
            "prod",
            "Admin",
            crate::Target::Aws {
                account_id: "1".into(),
                account_name: "prod".into(),
                role_name: "Admin".into(),
            },
        );
        let regions = BTreeMap::from([("acme/prod/Admin".to_string(), "eu-west-1".to_string())]);
        let block = aws_config_block(&[&p], "fob-", &regions);
        assert!(block.contains("[profile fob-acme-prod-Admin]"));
        assert!(block.contains(
            "credential_process = fob creds acme/prod/Admin --format credential-process"
        ));
        assert!(block.contains("region = eu-west-1"));

        let original = "[default]\nregion = us-east-1\n";
        let once = replace_aws_block(original, &block);
        assert!(once.starts_with(original));
        let twice = replace_aws_block(&once, &block);
        assert_eq!(once, twice, "rewriting is idempotent");

        let mine = format!("{once}[profile mine]\nregion = eu-north-1\n");
        let empty = aws_config_block(&[], "fob-", &regions);
        let shrunk = replace_aws_block(&mine, &empty);
        assert!(
            shrunk.contains("[profile mine]"),
            "text after the block is kept"
        );
        assert!(!shrunk.contains("fob-acme"));
    }

    #[test]
    fn normalizes_urls() {
        assert_eq!(
            normalize_start_url(" https://Acme.AWSApps.com/start/ "),
            "https://acme.awsapps.com/start"
        );
    }
}
