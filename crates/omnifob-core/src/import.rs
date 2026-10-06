//! Imports from other tools' configuration.

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

/// Finds every Identity Center portal referenced by profiles in an AWS
/// config file: `sso_session` references, inline `sso_start_url` and
/// `sso_region`, and granted's `granted_sso_start_url` and `granted_sso_region`.
pub fn aws_portals(text: &str) -> Vec<AwsPortal> {
    let sections = parse_ini(text);
    let sessions: BTreeMap<&str, &BTreeMap<String, String>> = sections
        .iter()
        .filter_map(|(name, keys)| Some((name.strip_prefix("sso-session")?.trim(), keys)))
        .collect();

    struct Found {
        session_name: Option<String>,
        region: String,
        profiles: usize,
        regions: BTreeMap<String, usize>,
    }
    let mut found: BTreeMap<String, Found> = BTreeMap::new();
    for (name, keys) in &sections {
        if !(name == "default" || name.starts_with("profile ")) {
            continue;
        }
        let get = |k: &str| keys.get(k).map(String::as_str);
        let (start_url, sso_region, session_name) = if let Some(session) = get("sso_session") {
            let Some(s) = sessions.get(session) else {
                continue;
            };
            match (s.get("sso_start_url"), s.get("sso_region")) {
                (Some(u), Some(r)) => (u.as_str(), r.as_str(), Some(session.to_string())),
                _ => continue,
            }
        } else if let (Some(u), Some(r)) = (get("sso_start_url"), get("sso_region")) {
            (u, r, None)
        } else if let (Some(u), Some(r)) = (get("granted_sso_start_url"), get("granted_sso_region"))
        {
            (u, r, None)
        } else {
            continue;
        };
        let entry = found
            .entry(normalize_start_url(start_url))
            .or_insert_with(|| Found {
                session_name: None,
                region: sso_region.to_string(),
                profiles: 0,
                regions: BTreeMap::new(),
            });
        entry.profiles += 1;
        if entry.session_name.is_none() {
            entry.session_name = session_name;
        }
        if let Some(region) = get("region") {
            *entry.regions.entry(region.to_string()).or_default() += 1;
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

/// TOML for an `aws-sso` integration, ready to append to the config file.
pub fn aws_portal_toml(portal: &AwsPortal) -> String {
    let mut out = format!(
        "[integrations.{}]\ntype = \"aws-sso\"\nstart_url = \"{}\"\nregion = \"{}\"\n",
        portal.name, portal.start_url, portal.region
    );
    if let Some(region) = &portal.default_region {
        out.push_str(&format!("default_region = \"{region}\"\n"));
    }
    out
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
region = eu-central-1

[profile gary-mgmt]
granted_sso_start_url = https://D-111.awsapps.com/start
granted_sso_region = eu-central-1
region = eu-central-1

; inline sso profile
[profile client-dev]
sso_start_url = https://client.awsapps.com/start
sso_region = eu-west-1
region = eu-west-1

[profile client-prd]
sso_session = client
region = eu-west-2

[profile client-prd2]
sso_session = client
region = eu-west-2

[sso-session client]
sso_start_url = https://client.awsapps.com/start/
sso_region = eu-west-1

[profile plain-keys]
aws_access_key_id = AKIA...
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
        assert_eq!(client.profiles, 3);
        assert_eq!(client.default_region.as_deref(), Some("eu-west-2"));

        let gary = portals
            .iter()
            .find(|p| p.start_url.contains("d-111"))
            .unwrap();
        assert_eq!(gary.name, "d-111");
        assert_eq!(gary.profiles, 2);
        assert_eq!(gary.default_region.as_deref(), Some("eu-central-1"));
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
    }

    #[test]
    fn normalizes_urls() {
        assert_eq!(
            normalize_start_url(" https://Acme.AWSApps.com/start/ "),
            "https://acme.awsapps.com/start"
        );
    }
}
