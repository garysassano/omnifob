//! Imports from, and exports to, other tools' configuration.

use std::collections::BTreeMap;

/// What `fob import aws` found in an AWS config file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AwsImport {
    pub portals: Vec<AwsPortal>,
    /// IAM users whose access keys roles are assumed with.
    pub iam_users: Vec<AwsIamUser>,
    /// Console sign-ins made with `aws login` (`login_session`), which
    /// become `aws-login` integrations.
    pub logins: Vec<AwsLogin>,
    /// Profiles that could not be imported, with the reason.
    pub skipped: Vec<SkippedProfile>,
}

/// An IAM Identity Center portal found in `~/.aws/config`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsPortal {
    /// Suggested integration name: the `sso-session` name, or a name made
    /// from the portal's URL.
    pub name: String,
    pub start_url: String,
    pub region: String,
    /// The region most of the portal's profiles use.
    pub default_region: Option<String>,
    /// `sso_registration_scopes` of the portal's `sso-session` section.
    pub scopes: Option<Vec<String>>,
    /// How many profiles in the file use this portal.
    pub profiles: usize,
    /// Roles assumed from this portal's roles (`role_arn` + `source_profile`),
    /// keyed by a label made from the profile name.
    pub chained: BTreeMap<String, crate::config::ChainedRole>,
    /// Chained roles folded into rules: the same role name assumed from the
    /// same permission set in that permission set's own account, in two or
    /// more accounts.
    pub chained_rules: BTreeMap<String, crate::config::ChainedRule>,
}

/// A profile with an IAM user's access key that other profiles assume roles
/// from, which becomes an `aws-iam` integration. The key itself is not read:
/// `fob login` asks for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsIamUser {
    /// Suggested integration name, made from the profile name.
    pub name: String,
    /// The profile the roles name as `source_profile`.
    pub profile: String,
    /// The profile's `region`, used for STS and exported.
    pub region: Option<String>,
    /// The MFA device: the profile's `mfa_serial`, else the one its roles
    /// name. A session with MFA satisfies every role.
    pub mfa_serial: Option<String>,
    /// Roles assumed with the user's session, keyed by a label made from the
    /// profile name.
    pub roles: BTreeMap<String, crate::config::IamRole>,
}

/// A profile that `aws login` signed in (`login_session` with no role),
/// which becomes an `aws-login` integration. Its tokens stay in the AWS
/// CLI's cache, which is not read: `fob login` signs in again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsLogin {
    /// Suggested integration name, made from the profile name.
    pub name: String,
    pub profile: String,
    /// The profile's `region`, the one signed in through.
    pub region: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedProfile {
    pub profile: String,
    pub reason: String,
}

/// `https://Acme.awsapps.com/start/` and `https://acme.awsapps.com/start`
/// are the same portal. The regional portal URLs of a multi-Region instance
/// (`https://<instance>.<region>.portal.amazonaws.com`, and the dual-stack
/// `https://<instance>.portal.<region>.app.aws`) have no `/start`, and keep
/// none.
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

/// Keys whose values are secrets; [`parse_ini`] keeps that they are set, not
/// their values.
const SECRET_KEYS: [&str; 4] = [
    "aws_access_key_id",
    "aws_secret_access_key",
    "aws_session_token",
    // botocore's older name for the session token.
    "aws_security_token",
];

/// Parses an AWS config file into `section → key → value`, the way the AWS
/// SDKs read it: lines starting with `#` or `;` are comments, and so is the
/// rest of a line from a `#` or `;` that follows whitespace (`region =
/// eu-west-1 # home`); in a section header, from any `#` or `;` after the
/// `]`. A line indented more deeply than the property line above it
/// continues that property (`s3 =` and its sub-settings) and is skipped, as
/// botocore's `configparser` decides; a section whose keys are all indented
/// alike keeps every key. Secret values are dropped.
fn parse_ini(text: &str) -> Vec<(String, BTreeMap<String, String>)> {
    let mut sections: Vec<(String, BTreeMap<String, String>)> = Vec::new();
    // Indentation of the line that opened the current property.
    let mut property_indent: Option<usize> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if property_indent.is_some_and(|opened| indent > opened) {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            property_indent = None;
            let Some((name, _comment)) = rest.split_once(']') else {
                continue;
            };
            sections.push((name.trim().to_string(), BTreeMap::new()));
        } else if let Some((key, value)) = strip_comment(line).split_once('=')
            && let Some((_, keys)) = sections.last_mut()
        {
            property_indent = Some(indent);
            let key = key.trim().to_string();
            let value = if SECRET_KEYS.contains(&key.as_str()) {
                String::new()
            } else {
                value.trim().to_string()
            };
            keys.insert(key, value);
        }
    }
    sections
}

/// Sections by name, their keys merged.
type Sections = BTreeMap<String, BTreeMap<String, String>>;

/// The profiles and `sso-session` sections of a config file, as the AWS
/// SDKs' shared-config parsers read them: `[profile <name>]` and
/// `[sso-session <name>]` take any whitespace after the prefix (a tab too),
/// a header with no whitespace there (`[profilefoo]`, `[sso-session-x]`)
/// is ignored, and `[default]` is the default profile unless a `[profile
/// default]` section exists, which then wins. A section that appears twice
/// is merged, later keys replacing earlier ones, as the Rust, Go and
/// JavaScript SDKs do (botocore refuses the file instead).
fn sections(text: &str) -> (Sections, Sections) {
    let parsed = parse_ini(text);
    let explicit_default = parsed
        .iter()
        .any(|(name, _)| section_name(name) == Some(("profile", "default")));
    let (mut profiles, mut sessions) = (Sections::new(), Sections::new());
    for (header, keys) in parsed {
        let into = match section_name(&header) {
            Some(("profile", name)) => profiles.entry(name.to_string()),
            Some(("sso-session", name)) => sessions.entry(name.to_string()),
            None if header == "default" && !explicit_default => {
                profiles.entry("default".to_string())
            }
            _ => continue,
        };
        into.or_default().extend(keys);
    }
    (profiles, sessions)
}

/// `("profile", name)` or `("sso-session", name)` for a section header with
/// that prefix, whitespace, and a name.
fn section_name(header: &str) -> Option<(&str, &str)> {
    let (prefix, name) = header.split_once(char::is_whitespace)?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    match prefix {
        "profile" => Some(("profile", name)),
        "sso-session" => Some(("sso-session", name)),
        _ => None,
    }
}

/// `base` slugged, or with `-2`, `-3`... when `taken` already has it, so two
/// profile names that slug alike (`Prod`, `prod`) get labels of their own.
fn unique_label<V>(taken: &BTreeMap<String, V>, base: &str) -> String {
    let base = crate::profile::slug(base);
    let mut label = base.clone();
    let mut n = 1;
    while taken.contains_key(&label) {
        n += 1;
        label = format!("{base}-{n}");
    }
    label
}

/// The line up to a `#` or `;` that follows whitespace, trimmed.
fn strip_comment(line: &str) -> &str {
    let mut after_space = false;
    for (i, c) in line.char_indices() {
        if after_space && (c == '#' || c == ';') {
            return line[..i].trim_end();
        }
        after_space = c == ' ' || c == '\t';
    }
    line
}

/// The Identity Center role a profile signs in with.
struct SsoRef {
    start_url: String,
    sso_region: String,
    session_name: Option<String>,
    scopes: Option<Vec<String>>,
    account_id: Option<String>,
    role_name: Option<String>,
}

fn sso_ref(keys: &BTreeMap<String, String>, sessions: &Sections) -> Option<SsoRef> {
    let get = |k: &str| keys.get(k).cloned();
    let (start_url, sso_region, session_name, scopes) = if let Some(session) =
        keys.get("sso_session")
    {
        let s = sessions.get(session.as_str())?;
        let scopes = s.get("sso_registration_scopes").map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        });
        (
            s.get("sso_start_url")?.clone(),
            s.get("sso_region")?.clone(),
            Some(session.clone()),
            scopes.filter(|s| !s.is_empty()),
        )
    } else if let (Some(u), Some(r)) = (get("sso_start_url"), get("sso_region")) {
        (u, r, None, None)
    } else if let (Some(u), Some(r)) = (get("granted_sso_start_url"), get("granted_sso_region")) {
        (u, r, None, None)
    } else {
        return None;
    };
    Some(SsoRef {
        start_url: normalize_start_url(&start_url),
        sso_region,
        session_name,
        scopes,
        account_id: get("sso_account_id").or_else(|| get("granted_sso_account_id")),
        role_name: get("sso_role_name").or_else(|| get("granted_sso_role_name")),
    })
}

/// Keys of credential sources omnifob cannot import.
const OTHER_SOURCES: [&str; 4] = [
    "credential_process",
    "credential_source",
    "web_identity_token_file",
    "login_session",
];

/// The first of [`OTHER_SOURCES`] a profile sets.
fn other_source(keys: &BTreeMap<String, String>) -> Option<&'static str> {
    OTHER_SOURCES
        .iter()
        .copied()
        .find(|s| keys.contains_key(*s))
}

/// How long AWS lets a role session last when it is chained from an
/// Identity Center role, and when it is assumed with an IAM user's session.
const CHAINED_SECONDS: std::ops::RangeInclusive<i64> = 900..=3600;
const IAM_USER_ROLE_SECONDS: std::ops::RangeInclusive<i64> = 900..=3600;

/// `duration_seconds`, if set and within `range`.
fn duration(
    keys: &BTreeMap<String, String>,
    range: std::ops::RangeInclusive<i64>,
) -> Result<Option<jiff::SignedDuration>, ()> {
    match keys.get("duration_seconds").map(|s| s.parse::<i64>()) {
        None => Ok(None),
        Some(Ok(secs)) if range.contains(&secs) => Ok(Some(jiff::SignedDuration::from_secs(secs))),
        Some(_) => Err(()),
    }
}

/// Finds every Identity Center portal referenced by profiles in an AWS
/// config file (`sso_session` references, inline `sso_start_url` and
/// `sso_region`, granted's `granted_sso_*` keys), the roles chained from
/// them through `role_arn` and `source_profile`, the roles assumed from
/// profiles with an IAM user's access key, which become `aws-iam`
/// integrations, and the console sign-ins of `aws login`
/// (`login_session`), which become `aws-login` integrations.
///
/// A source profile with neither Identity Center keys, a role, nor another
/// credential source (`credential_process`, `credential_source`,
/// `web_identity_token_file`, `login_session`) is taken to hold an access
/// key, here or in the credentials file, which is not read.
///
/// Everything imported gets the checks the config gets when it loads, so
/// a role or Region that would make the config invalid is skipped with the
/// reason instead.
pub fn aws_import(text: &str) -> AwsImport {
    let (profiles, sessions) = sections(text);

    #[derive(Default)]
    struct Found {
        session_name: Option<String>,
        scopes: Option<Vec<String>>,
        region: String,
        profiles: usize,
        regions: BTreeMap<String, usize>,
        chained: BTreeMap<String, crate::config::ChainedRole>,
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
        if f.scopes.is_none() {
            f.scopes = sso.scopes.clone();
        }
        f
    }
    // Why a portal cannot be imported, checked as the config would.
    fn portal_problem(sso: &SsoRef) -> Option<String> {
        if let Err(e) = crate::config::check_https_url("sso_start_url", &sso.start_url) {
            return Some(e);
        }
        crate::providers::aws::partition::check_region_name(&sso.sso_region)
            .err()
            .map(|e| format!("sso_region: {e:#}"))
    }
    // Roles assumed from an IAM user's profile, by that profile, with the
    // `mfa_serial` each names.
    type IamRoles = Vec<(String, crate::config::IamRole, Option<String>)>;
    let mut iam: BTreeMap<String, IamRoles> = BTreeMap::new();
    let mut logins: Vec<AwsLogin> = Vec::new();
    // The login_session and Region of each imported sign-in, to import one
    // identity once.
    let mut signed_in: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut skipped = Vec::new();
    let mut skip = |profile: &str, reason: String| {
        skipped.push(SkippedProfile {
            profile: profile.to_string(),
            reason,
        })
    };

    for (name, keys) in &profiles {
        if let Some(sso) = sso_ref(keys, &sessions) {
            if let Some(why) = portal_problem(&sso) {
                skip(
                    name,
                    format!("its Identity Center settings are not valid: {why}"),
                );
                continue;
            }
            let f = entry(&mut found, &sso);
            f.profiles += 1;
            if let Some(region) = keys.get("region") {
                *f.regions.entry(region.clone()).or_default() += 1;
            }
            continue;
        }
        let Some(role_arn) = keys.get("role_arn") else {
            if let Some(session) = keys.get("login_session") {
                let Some(region) = keys.get("region") else {
                    skip(
                        name,
                        "it signs in with `aws login` but has no region, the Region AWS Sign-In renews in".into(),
                    );
                    continue;
                };
                if let Err(e) = crate::providers::aws::partition::check_region_name(region) {
                    skip(name, format!("its region: {e:#}"));
                    continue;
                }
                let identity = (session.clone(), region.clone());
                if let Some(first) = signed_in.get(&identity) {
                    skip(
                        name,
                        format!(
                            "it signs in as the same identity in the same Region as profile '{first}'"
                        ),
                    );
                    continue;
                }
                signed_in.insert(identity, name.clone());
                logins.push(AwsLogin {
                    name: crate::profile::slug(name),
                    profile: name.clone(),
                    region: region.clone(),
                });
            }
            continue;
        };
        let Some(source) = keys.get("source_profile") else {
            match other_source(keys) {
                Some(other) => skip(
                    name,
                    format!(
                        "it gets its source credentials through {other}, which omnifob cannot import"
                    ),
                ),
                None => skip(
                    name,
                    "it has a role_arn but no source_profile or credential_source to assume it with".into(),
                ),
            }
            continue;
        };
        let source_keys = profiles.get(source.as_str());
        if let Some(sso) = source_keys.and_then(|k| sso_ref(k, &sessions)) {
            if let Some(why) = portal_problem(&sso) {
                skip(
                    name,
                    format!("its source profile's Identity Center settings are not valid: {why}"),
                );
                continue;
            }
            let f = entry(&mut found, &sso);
            f.profiles += 1;
            let (Some(account_id), Some(role_name)) = (&sso.account_id, &sso.role_name) else {
                skip(name, "its source profile names no account and role".into());
                continue;
            };
            let Ok(duration) = duration(keys, CHAINED_SECONDS) else {
                skip(
                    name,
                    "its duration_seconds is not 900 to 3600, the range AWS allows for roles chained from an Identity Center role".into(),
                );
                continue;
            };
            let role = crate::config::ChainedRole {
                via_account_id: account_id.clone(),
                via_role: role_name.clone(),
                role_arn: role_arn.clone(),
                session_name: keys.get("role_session_name").cloned(),
                external_id: keys.get("external_id").cloned(),
                region: keys.get("region").cloned(),
                mfa_serial: keys.get("mfa_serial").cloned(),
                duration,
            };
            if let Err(why) = role.validate(&sso.sso_region) {
                skip(name, why);
                continue;
            }
            let label = unique_label(&f.chained, name);
            f.chained.insert(label, role);
            continue;
        }
        if let Some(other) = source_keys.and_then(other_source) {
            skip(
                name,
                format!(
                    "its source profile '{source}' gets credentials through {other}, which omnifob cannot import"
                ),
            );
            continue;
        }
        // A profile that names itself as its source assumes the role with its
        // own access key, as the AWS CLI allows.
        let source_is_self = source == name;
        if let Some(k) = source_keys
            && !source_is_self
            && k.contains_key("role_arn")
        {
            skip(
                name,
                format!(
                    "its source profile '{source}' is itself a role assumed from another profile; omnifob assumes roles from an Identity Center role or an IAM user only"
                ),
            );
            continue;
        }
        if source_keys.is_some_and(|k| {
            k.keys()
                .any(|key| key.starts_with("sso_") || key.starts_with("granted_sso_"))
        }) {
            skip(
                name,
                format!("its source profile '{source}' has incomplete Identity Center settings"),
            );
            continue;
        }
        let Ok(duration) = duration(keys, IAM_USER_ROLE_SECONDS) else {
            skip(
                name,
                "its duration_seconds is not 900 to 3600, the range AWS allows for roles assumed with an IAM user's session, which STS counts as role chaining".into(),
            );
            continue;
        };
        iam.entry(source.clone()).or_default().push((
            name.to_string(),
            crate::config::IamRole {
                role_arn: role_arn.clone(),
                session_name: keys.get("role_session_name").cloned(),
                external_id: keys.get("external_id").cloned(),
                region: keys.get("region").cloned(),
                duration,
                console_duration: None,
                no_session: false,
            },
            keys.get("mfa_serial").cloned(),
        ));
    }

    let mut used = BTreeMap::<String, usize>::new();
    let mut unique = |base: &str| {
        let base = crate::profile::slug(base);
        let n = used.entry(base.clone()).or_default();
        *n += 1;
        if *n == 1 { base } else { format!("{base}-{n}") }
    };
    let portals = found
        .into_iter()
        .map(|(start_url, f)| {
            let name = unique(&f.session_name.unwrap_or_else(|| subdomain(&start_url)));
            let default_region = f
                .regions
                .into_iter()
                .filter(|(region, _)| {
                    crate::providers::aws::partition::check_region_name(region).is_ok()
                })
                .max_by_key(|(region, count)| (*count, std::cmp::Reverse(region.clone())))
                .map(|(region, _)| region);
            let (chained, chained_rules) = fold_chained(f.chained);
            AwsPortal {
                name,
                start_url,
                region: f.region,
                default_region,
                scopes: f.scopes,
                profiles: f.profiles,
                chained,
                chained_rules,
            }
        })
        .collect();
    let iam_users = iam
        .into_iter()
        .filter_map(|(profile, roles)| {
            let source = profiles.get(profile.as_str());
            let region = source.and_then(|k| k.get("region").cloned());
            if let Some(Err(e)) = region
                .as_deref()
                .map(crate::providers::aws::partition::check_region_name)
            {
                for (name, _, _) in &roles {
                    skip(name, format!("its source profile '{profile}' has a region that is not valid: {e:#}"));
                }
                return None;
            }
            let mfa_serial = source
                .and_then(|k| k.get("mfa_serial").cloned())
                .or_else(|| roles.iter().find_map(|(_, _, mfa)| mfa.clone()));
            let mut kept = BTreeMap::new();
            for (name, role, mfa) in roles {
                if mfa.is_some() && mfa != mfa_serial {
                    skip(
                        &name,
                        format!(
                            "its mfa_serial is not the one the other roles of '{profile}' use; an aws-iam integration has one MFA device"
                        ),
                    );
                    continue;
                }
                if let Err(why) = role.validate(region.as_deref()) {
                    skip(&name, why);
                    continue;
                }
                kept.insert(unique_label(&kept, &name), role);
            }
            if kept.is_empty() {
                return None;
            }
            Some(AwsIamUser {
                name: unique(&profile),
                region,
                mfa_serial,
                profile,
                roles: kept,
            })
        })
        .collect();
    let logins = logins
        .into_iter()
        .map(|login| AwsLogin {
            name: unique(&login.name),
            ..login
        })
        .collect();
    AwsImport {
        portals,
        iam_users,
        logins,
        skipped,
    }
}

/// TOML for an `aws-login` integration, ready to append to the config
/// file. `fob login` signs it in: the AWS CLI's cached tokens are not read.
pub fn aws_login_toml(login: &AwsLogin) -> String {
    format!(
        "[integrations.{}]\ntype = \"aws-login\"\nregion = {}\n",
        toml_key(&login.name),
        toml_str(&login.region)
    )
}

/// A name for a portal without an `sso-session` name: the subdomain of an
/// `awsapps.com` URL, or the instance and Region of a regional URL
/// (`ssoins-1234-eu-west-1`), so a replica Region's portal gets a name of
/// its own.
fn subdomain(start_url: &str) -> String {
    let host = start_url
        .split_once("://")
        .map_or(start_url, |(_, rest)| rest)
        .split('/')
        .next()
        .unwrap_or_default();
    let labels: Vec<&str> = host.split('.').collect();
    match labels.as_slice() {
        // https://<instance>.<region>.portal.amazonaws.com
        [instance, region, "portal", ..] => format!("{instance}-{region}"),
        // https://<instance>.portal.<region>.app.aws
        [instance, "portal", region, ..] => format!("{instance}-{region}"),
        [first, ..] if !first.is_empty() => first.to_string(),
        _ => "aws".to_string(),
    }
}

/// A TOML string, quoted and escaped.
fn toml_str(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

/// A TOML key: bare when it can be, else quoted, so `john.doe` stays one key
/// rather than a nested table.
fn toml_key(s: &str) -> String {
    toml_edit::Key::new(s).display_repr().into_owned()
}

/// How many accounts must assume the same role from the same permission
/// set before `fob import aws` writes a rule for them instead of tables.
const FOLD_MIN: usize = 2;

/// Splits imported chained roles into the ones kept as tables and rules for
/// the rest: roles assumed in the source permission set's own account,
/// grouped by permission set, role name and path and every other key, become
/// one rule per group of `FOLD_MIN` or more, limited with `accounts` to
/// the accounts the file names, so the rule gives exactly the profiles the
/// tables would have. Removing `accounts` then covers every account.
pub fn fold_chained(
    chained: BTreeMap<String, crate::config::ChainedRole>,
) -> (
    BTreeMap<String, crate::config::ChainedRole>,
    BTreeMap<String, crate::config::ChainedRule>,
) {
    type Key = (
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<jiff::SignedDuration>,
    );
    let mut groups: BTreeMap<Key, Vec<String>> = BTreeMap::new();
    for (label, role) in &chained {
        let Some((account, path, name)) = same_account_role(role) else {
            continue;
        };
        if account != role.via_account_id {
            continue;
        }
        let key = (
            role.via_role.clone(),
            path,
            name,
            role.session_name.clone(),
            role.external_id.clone(),
            role.region.clone(),
            role.mfa_serial.clone(),
            role.duration,
        );
        groups.entry(key).or_default().push(label.clone());
    }
    let mut chained = chained;
    let mut rules = BTreeMap::new();
    for (key, labels) in groups {
        if labels.len() < FOLD_MIN {
            continue;
        }
        let (via_role, path, role_name, session_name, external_id, region, mfa_serial, duration) =
            key;
        let mut accounts: Vec<String> = labels
            .iter()
            .filter_map(|l| chained.remove(l))
            .map(|r| r.via_account_id)
            .collect();
        accounts.sort();
        accounts.dedup();
        let base = crate::profile::slug(&role_name);
        let mut label = base.clone();
        let mut n = 1;
        while rules.contains_key(&label) || chained.contains_key(&label) {
            n += 1;
            label = format!("{base}-{n}");
        }
        rules.insert(
            label,
            crate::config::ChainedRule {
                via_role,
                role_name,
                path: (path != "/").then_some(path),
                accounts,
                exclude_accounts: Vec::new(),
                session_name,
                external_id,
                region,
                mfa_serial,
                duration,
            },
        );
    }
    (chained, rules)
}

/// The account, IAM path and name of a chained role's `role_arn`
/// (`arn:aws:iam::<account>:role/<path><name>`), when it has that shape.
fn same_account_role(role: &crate::config::ChainedRole) -> Option<(String, String, String)> {
    let account = role.account_id()?.to_string();
    let resource = role.role_arn.split(':').nth(5)?.strip_prefix("role")?;
    let (path, name) = resource.rsplit_once('/')?;
    Some((account, format!("{path}/"), name.to_string()))
}

/// TOML for an `aws-sso` integration and its chained roles, ready to append
/// to the config file.
pub fn aws_portal_toml(portal: &AwsPortal) -> String {
    let mut out = format!(
        "[integrations.{}]\ntype = \"aws-sso\"\nstart_url = {}\nregion = {}\n",
        toml_key(&portal.name),
        toml_str(&portal.start_url),
        toml_str(&portal.region)
    );
    if let Some(region) = &portal.default_region {
        out.push_str(&format!("default_region = {}\n", toml_str(region)));
    }
    if let Some(scopes) = &portal.scopes
        && scopes != &["sso:account:access"]
    {
        let list: Vec<String> = scopes.iter().map(|s| toml_str(s)).collect();
        out.push_str(&format!("scopes = [{}]\n", list.join(", ")));
    }
    out.push_str(&chained_toml(&portal.name, &portal.chained));
    out.push_str(&chained_rules_toml(&portal.name, &portal.chained_rules));
    out
}

/// TOML for an `aws-iam` integration and its roles, ready to append to the
/// config file. It has no key: `fob login` asks for it.
pub fn aws_iam_user_toml(user: &AwsIamUser) -> String {
    let mut out = format!(
        "[integrations.{}]\ntype = \"aws-iam\"\n",
        toml_key(&user.name)
    );
    if let Some(region) = &user.region {
        out.push_str(&format!("region = {}\n", toml_str(region)));
    }
    if let Some(mfa) = &user.mfa_serial {
        out.push_str(&format!("mfa_serial = {}\n", toml_str(mfa)));
    }
    out.push_str(&iam_roles_toml(&user.name, &user.roles));
    out
}

/// `[integrations.<name>.roles."<label>"]` tables.
pub fn iam_roles_toml(
    integration: &str,
    roles: &BTreeMap<String, crate::config::IamRole>,
) -> String {
    let mut out = String::new();
    for (label, role) in roles {
        let table = toml::to_string(role).expect("a role serializes");
        out.push_str(&format!(
            "\n[integrations.{}.roles.{}]\n{table}",
            toml_key(integration),
            toml_str(label)
        ));
    }
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
            "\n[integrations.{}.chained.{}]\n{table}",
            toml_key(integration),
            toml_str(label)
        ));
    }
    out
}

/// `[integrations.<name>.chained_rules."<label>"]` tables.
pub fn chained_rules_toml(
    integration: &str,
    rules: &BTreeMap<String, crate::config::ChainedRule>,
) -> String {
    let mut out = String::new();
    for (label, rule) in rules {
        let table = toml::to_string(rule).expect("a chained rule serializes");
        out.push_str(&format!(
            "\n[integrations.{}.chained_rules.{}]\n{table}",
            toml_key(integration),
            toml_str(label)
        ));
    }
    out
}

/// Lines that delimit the block omnifob manages in `~/.aws/config`.
pub const AWS_BLOCK_BEGIN: &str =
    "# BEGIN omnifob (generated by `fob export aws-config`; edits inside are overwritten)";
pub const AWS_BLOCK_END: &str = "# END omnifob";

/// The program in a `credential_process` line: `path` as is when it is made
/// of letters, digits, `.`, `_`, `-`, `/` and `:` (and `\` on Windows).
///
/// Outside Windows any other path goes in double quotes, as the AWS guide
/// asks for a path with a space; the SDKs run the line with `sh -c` or split
/// it like a shell, so a path with a character that stays special inside
/// double quotes (`"`, `$`, `` ` ``, `\`, `%`, control characters) is
/// refused. On Windows a path that would need quotes is refused: the Rust
/// and Go SDKs hand the line to `cmd.exe /C` through an API that escapes
/// inner quotes as `\"`, which `cmd.exe` does not undo, so a quoted path is
/// not known to work there.
pub fn credential_process_program(path: &str, windows: bool) -> anyhow::Result<String> {
    let plain = |c: char| {
        c.is_ascii_alphanumeric()
            || matches!(c, '.' | '_' | '-' | '/' | ':')
            || (windows && c == '\\')
    };
    if !path.is_empty() && path.chars().all(plain) {
        return Ok(path.to_string());
    }
    let quotable = |c: char| !matches!(c, '"' | '$' | '`' | '\\' | '%') && !c.is_control();
    if windows || path.is_empty() || !path.chars().all(quotable) {
        anyhow::bail!(
            "the path {path:?} cannot be written in a credential_process line; leave out --absolute and put fob on PATH"
        );
    }
    Ok(format!("\"{path}\""))
}

/// `[profile ...]` sections that get credentials from `<program> creds`, one
/// per AWS profile, named `<prefix><integration>-<account>-<role>`.
/// `regions` maps profile ids to the region to set; `program` is `fob`, or
/// the path from [`credential_process_program`].
///
/// Flattening `/` to `-` can give two ids one name (`a-b/c/d` and
/// `a/b-c/d`). The first profile keeps the name and the others are left
/// out, returned as clashes: a suffix would depend on the order of the
/// profiles, so a later sync could point a name at another account.
pub fn aws_config_block(
    profiles: &[&crate::Profile],
    prefix: &str,
    regions: &BTreeMap<String, String>,
    program: &str,
) -> (String, Vec<ExportClash>) {
    let mut out = format!("{AWS_BLOCK_BEGIN}\n");
    let mut named: BTreeMap<String, &str> = BTreeMap::new();
    let mut clashes = Vec::new();
    for p in profiles {
        if !p.target.is_aws() {
            continue;
        }
        let name = format!("{prefix}{}", p.id.replace('/', "-"));
        if let Some(first) = named.get(&name) {
            clashes.push(ExportClash {
                name,
                kept: first.to_string(),
                left_out: p.id.clone(),
            });
            continue;
        }
        named.insert(name.clone(), &p.id);
        out.push_str(&format!(
            "[profile {name}]\ncredential_process = {program} creds {} --format credential-process\n",
            p.id
        ));
        if let Some(region) = regions.get(&p.id) {
            out.push_str(&format!("region = {region}\n"));
        }
        out.push('\n');
    }
    out.push_str(AWS_BLOCK_END);
    out.push('\n');
    (out, clashes)
}

/// Two profiles whose ids give the same AWS profile name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportClash {
    /// The AWS profile name.
    pub name: String,
    /// The profile that has it.
    pub kept: String,
    /// The profile left out of the block.
    pub left_out: String,
}

/// Replaces omnifob's block in an AWS config file, or appends one. A file
/// with Windows line endings (`\r\n`) keeps them, the block included.
pub fn replace_aws_block(existing: &str, block: &str) -> String {
    let crlf = existing.contains("\r\n");
    let block = if crlf {
        block.replace("\r\n", "\n").replace('\n', "\r\n")
    } else {
        block.to_string()
    };
    let newline = if crlf { "\r\n" } else { "\n" };
    let end = existing.find(AWS_BLOCK_BEGIN).and_then(|start| {
        let from = start + AWS_BLOCK_BEGIN.len();
        existing[from..]
            .find(AWS_BLOCK_END)
            .map(|end| (start, from + end))
    });
    match end {
        Some((start, end)) => {
            let after = &existing[end + AWS_BLOCK_END.len()..];
            let after = after
                .strip_prefix("\r\n")
                .or_else(|| after.strip_prefix('\n'))
                .unwrap_or(after);
            format!("{}{block}{after}", &existing[..start])
        }
        None => {
            let blank = format!("{newline}{newline}");
            let sep = if existing.is_empty() || existing.ends_with(&blank) {
                ""
            } else if existing.ends_with('\n') {
                newline
            } else {
                &blank
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
[profile me-test]
granted_sso_start_url = https://d-111.awsapps.com/start/
granted_sso_region = eu-central-1
granted_sso_account_id = 111111111111
granted_sso_role_name = Admin
region = eu-central-1

[profile me-mgmt]
granted_sso_start_url = https://D-111.awsapps.com/start
granted_sso_region = eu-central-1
region = eu-central-1 # the home Region

[profile me-no-role]
granted_sso_start_url = https://d-111.awsapps.com/start
granted_sso_region = eu-central-1

[profile half-chained]
role_arn = arn:aws:iam::666666666666:role/X
source_profile = me-no-role

; inline sso profile
[profile client-dev]
sso_start_url = https://client.awsapps.com/start
sso_region = eu-west-1
region = eu-west-1

[profile client-prd] ; production
sso_session = client
sso_account_id = 999999999999
sso_role_name = Ops
region = eu-west-2	; London
s3 =
  region = us-west-2

[profile client-prd2]
sso_session = client
region = eu-west-2

[sso-session client]
sso_start_url = https://client.awsapps.com/start/
sso_region = eu-west-1
sso_registration_scopes = sso:account:access, codewhisperer:completions

[profile plain-keys]
aws_access_key_id = AKIAEXAMPLEKEYID0001
aws_secret_access_key = do-not-print-this-secret
region = us-west-2
mfa_serial = arn:aws:iam::555555555555:mfa/user

[profile me-test-deploy]
role_arn = arn:aws:iam::222222222222:role/Deploy
source_profile = me-test
role_session_name = me
region = us-east-1

[profile client-prd-deploy]
role_arn = arn:aws:iam::333333333333:role/Deploy
source_profile = client-prd
external_id = xyz

[profile needs-mfa]
role_arn = arn:aws:iam::444444444444:role/Admin
source_profile = me-test
mfa_serial = arn:aws:iam::111111111111:mfa/me
duration_seconds = 1800

[profile too-long-from-sso]
role_arn = arn:aws:iam::444444444444:role/Admin
source_profile = me-test
duration_seconds = 7200

[profile from-static-keys]
role_arn = arn:aws:iam::555555555555:role/Admin
source_profile = plain-keys
duration_seconds = 3600
role_session_name = me
mfa_serial = arn:aws:iam::555555555555:mfa/user

[profile other-mfa]
role_arn = arn:aws:iam::555555555555:role/Other
source_profile = plain-keys
mfa_serial = arn:aws:iam::555555555555:mfa/another

[profile too-long-from-keys]
role_arn = arn:aws:iam::555555555555:role/Admin
source_profile = plain-keys
duration_seconds = 3601

[profile from-credentials-file]
role_arn = arn:aws:iam::777777777777:role/ReadOnly
source_profile = keys-elsewhere

[profile chain-of-chains]
role_arn = arn:aws:iam::888888888888:role/Deeper
source_profile = me-test-deploy

[profile from-process]
role_arn = arn:aws:iam::888888888888:role/X
source_profile = process

[profile process]
credential_process = /usr/bin/creds
"#;

    fn portal<'a>(import: &'a AwsImport, url: &str) -> &'a AwsPortal {
        import
            .portals
            .iter()
            .find(|p| p.start_url.contains(url))
            .unwrap()
    }

    fn skipped(import: &AwsImport) -> BTreeMap<&str, &str> {
        import
            .skipped
            .iter()
            .map(|s| (s.profile.as_str(), s.reason.as_str()))
            .collect()
    }

    #[test]
    fn finds_each_portal_once() {
        let import = aws_import(CONFIG);
        assert_eq!(import.portals.len(), 2, "{import:#?}");

        let client = portal(&import, "client");
        assert_eq!(client.name, "client");
        assert_eq!(client.start_url, "https://client.awsapps.com/start");
        assert_eq!(client.region, "eu-west-1");
        assert_eq!(client.profiles, 4);
        assert_eq!(client.default_region.as_deref(), Some("eu-west-2"));

        let mine = portal(&import, "d-111");
        assert_eq!(mine.name, "d-111");
        assert_eq!(mine.profiles, 7);
        assert_eq!(mine.default_region.as_deref(), Some("eu-central-1"));
    }

    #[test]
    fn imports_chained_roles() {
        let import = aws_import(CONFIG);
        let mine = portal(&import, "d-111");
        let deploy = &mine.chained["me-test-deploy"];
        assert_eq!(deploy.via_account_id, "111111111111");
        assert_eq!(deploy.via_role, "Admin");
        assert_eq!(deploy.session_name.as_deref(), Some("me"));
        assert_eq!(deploy.region.as_deref(), Some("us-east-1"));
        assert_eq!(deploy.role_name(), "Deploy");
        assert_eq!(mine.chained.len(), 2, "{:?}", mine.chained.keys());
        let mfa = &mine.chained["needs-mfa"];
        assert_eq!(
            mfa.mfa_serial.as_deref(),
            Some("arn:aws:iam::111111111111:mfa/me")
        );
        assert_eq!(mfa.duration, Some(jiff::SignedDuration::from_mins(30)));

        let client = portal(&import, "client");
        let prd = &client.chained["client-prd-deploy"];
        assert_eq!(
            (prd.via_account_id.as_str(), prd.via_role.as_str()),
            ("999999999999", "Ops")
        );
        assert_eq!(prd.external_id.as_deref(), Some("xyz"));
    }

    #[test]
    fn reports_every_profile_it_skips() {
        let import = aws_import(CONFIG);
        let skipped = skipped(&import);
        assert_eq!(
            skipped.keys().copied().collect::<Vec<_>>(),
            [
                "chain-of-chains",
                "from-process",
                "half-chained",
                "other-mfa",
                "too-long-from-keys",
                "too-long-from-sso",
            ]
        );
        assert!(
            skipped["chain-of-chains"].contains("'me-test-deploy' is itself a role"),
            "{}",
            skipped["chain-of-chains"]
        );
        assert!(skipped["from-process"].contains("credential_process"));
        assert!(skipped["half-chained"].contains("no account and role"));
        assert!(skipped["other-mfa"].contains("mfa_serial"));
        assert!(skipped["too-long-from-sso"].contains("900 to 3600"));
        assert!(skipped["too-long-from-keys"].contains("900 to 3600"));
    }

    #[test]
    fn skips_chained_roles_outside_the_portal_partition() {
        let import = aws_import(
            "[profile p]\nsso_start_url = https://acme.awsapps.com/start\nsso_region = us-east-1\n\
             sso_account_id = 111111111111\nsso_role_name = Admin\n\
             [profile gov]\nrole_arn = arn:aws-us-gov:iam::222222222222:role/Audit\nsource_profile = p\n\
             [profile typo]\nrole_arn = arn:aws:iam::22222222222:role/Audit\nsource_profile = p\n\
             [profile ok]\nrole_arn = arn:aws:iam::222222222222:role/Audit\nsource_profile = p\n",
        );
        let skipped = skipped(&import);
        assert!(skipped["gov"].contains("`cross_partition`"), "{skipped:?}");
        assert!(skipped["typo"].contains("12 digits"), "{skipped:?}");
        assert_eq!(import.portals[0].chained.keys().collect::<Vec<_>>(), ["ok"]);
    }

    #[test]
    fn reports_roles_from_other_credential_sources() {
        let import = aws_import(
            "[profile on-ec2]\nrole_arn = arn:aws:iam::1:role/A\ncredential_source = Ec2InstanceMetadata\n\
             [profile web]\nrole_arn = arn:aws:iam::1:role/B\nweb_identity_token_file = /t\n\
             [profile from-on-ec2]\nrole_arn = arn:aws:iam::1:role/C\nsource_profile = on-ec2\n",
        );
        let skipped = skipped(&import);
        assert!(
            skipped["on-ec2"].contains("credential_source"),
            "{skipped:?}"
        );
        assert!(skipped["web"].contains("web_identity_token_file"));
        // Its source has a role_arn too, but the reason is the credential source.
        assert!(
            skipped["from-on-ec2"].contains("'on-ec2' gets credentials through credential_source"),
            "{}",
            skipped["from-on-ec2"]
        );
        assert!(import.iam_users.is_empty());
    }

    #[test]
    fn roles_from_access_keys_become_iam_users() {
        let import = aws_import(CONFIG);
        let names: Vec<&str> = import.iam_users.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, ["keys-elsewhere", "plain-keys"]);

        let user = &import.iam_users[1];
        assert_eq!(user.profile, "plain-keys");
        assert_eq!(user.region.as_deref(), Some("us-west-2"));
        assert_eq!(
            user.mfa_serial.as_deref(),
            Some("arn:aws:iam::555555555555:mfa/user")
        );
        assert_eq!(user.roles.len(), 1);
        let role = &user.roles["from-static-keys"];
        assert_eq!(role.role_arn, "arn:aws:iam::555555555555:role/Admin");
        assert_eq!(role.session_name.as_deref(), Some("me"));
        assert_eq!(
            role.duration,
            Some(jiff::SignedDuration::from_hours(1)),
            "IAM users' roles last at most an hour"
        );

        // The key may sit in the credentials file, which is not read.
        let elsewhere = &import.iam_users[0];
        assert_eq!(elsewhere.region, None);
        assert_eq!(elsewhere.mfa_serial, None);
        assert_eq!(
            elsewhere.roles["from-credentials-file"].role_arn,
            "arn:aws:iam::777777777777:role/ReadOnly"
        );

        // A profile that is its own source assumes the role with its own key.
        let own = aws_import(
            "[profile self]\naws_access_key_id = AKIAEXAMPLEKEYID0002\nrole_arn = arn:aws:iam::111111111111:role/R\nsource_profile = self\n",
        );
        assert_eq!(own.iam_users.len(), 1, "{own:#?}");
        assert!(own.skipped.is_empty());
    }

    #[test]
    fn never_keeps_or_prints_secret_values() {
        let import = aws_import(CONFIG);
        let toml: String = import
            .iam_users
            .iter()
            .map(aws_iam_user_toml)
            .chain(import.portals.iter().map(aws_portal_toml))
            .collect();
        let debug = format!("{import:?}{toml}");
        assert!(!debug.contains("do-not-print-this-secret"));
        assert!(!debug.contains("AKIAEXAMPLEKEYID0001"));
        let sections = parse_ini(CONFIG);
        let (_, keys) = sections
            .iter()
            .find(|(name, _)| name == "profile plain-keys")
            .unwrap();
        assert_eq!(keys["aws_access_key_id"], "");
        assert_eq!(keys["aws_secret_access_key"], "");
        let legacy = parse_ini("[default]\naws_security_token = legacy-token-value\n");
        assert_eq!(legacy[0].1["aws_security_token"], "");
    }

    #[test]
    fn drops_inline_comments_as_the_sdks_do() {
        let import = aws_import(CONFIG);
        let mine = portal(&import, "d-111");
        assert_eq!(mine.default_region.as_deref(), Some("eu-central-1"));
        let client = portal(&import, "client");
        assert_eq!(client.default_region.as_deref(), Some("eu-west-2"));

        assert_eq!(
            strip_comment("region = eu-west-1 # home"),
            "region = eu-west-1"
        );
        assert_eq!(
            strip_comment("region = eu-west-1\t; home"),
            "region = eu-west-1"
        );
        assert_eq!(
            strip_comment("name = value#not # but this"),
            "name = value#not"
        );
        assert_eq!(strip_comment("url = https://x/#;y"), "url = https://x/#;y");
        let sections =
            parse_ini("[profile a] # note\nregion = eu-west-1 # x\ns3 =\n  region = us-east-1\n");
        assert_eq!(sections[0].0, "profile a");
        assert_eq!(
            sections[0].1["region"], "eu-west-1",
            "sub-settings are skipped"
        );
    }

    #[test]
    fn maps_registration_scopes() {
        let import = aws_import(CONFIG);
        let client = portal(&import, "client");
        assert_eq!(
            client.scopes.as_deref(),
            Some(
                &[
                    "sso:account:access".to_string(),
                    "codewhisperer:completions".to_string()
                ][..]
            )
        );
        let toml = aws_portal_toml(client);
        assert!(
            toml.contains("scopes = [\"sso:account:access\", \"codewhisperer:completions\"]"),
            "{toml}"
        );
        let config = crate::Config::parse(&toml).unwrap();
        let crate::Integration::AwsSso(c) = &config.integrations["client"] else {
            panic!()
        };
        assert_eq!(
            c.scopes,
            ["sso:account:access", "codewhisperer:completions"]
        );

        // The default is not repeated.
        let default = aws_import(
            "[profile p]\nsso_session = s\n[sso-session s]\nsso_start_url = https://s.awsapps.com/start\nsso_region = eu-west-1\nsso_registration_scopes = sso:account:access\n",
        );
        assert!(!aws_portal_toml(&default.portals[0]).contains("scopes"));
    }

    #[test]
    fn toml_parses_as_config() {
        let import = aws_import(CONFIG);
        let toml: String = import
            .portals
            .iter()
            .map(aws_portal_toml)
            .chain(import.iam_users.iter().map(aws_iam_user_toml))
            .collect::<Vec<_>>()
            .join("\n");
        let config = crate::Config::parse(&toml).unwrap();
        assert_eq!(config.integrations.len(), 4);
        let crate::Integration::AwsSso(client) = &config.integrations["client"] else {
            panic!()
        };
        assert_eq!(
            client.chained["client-prd-deploy"].external_id.as_deref(),
            Some("xyz")
        );
        let crate::Integration::AwsIam(user) = &config.integrations["plain-keys"] else {
            panic!()
        };
        assert_eq!(user.region.as_deref(), Some("us-west-2"));
        assert_eq!(
            user.roles["from-static-keys"],
            import.iam_users[1].roles["from-static-keys"]
        );
    }

    #[test]
    fn dotted_names_stay_one_key() {
        let import = aws_import(
            "[profile john.doe]\nregion = eu-west-1\n\
             [profile john.doe-admin]\nrole_arn = arn:aws:iam::111111111111:role/Admin\nsource_profile = john.doe\n\
             [profile p]\nsso_session = acme.prod\nsso_account_id = 111111111111\nsso_role_name = Admin\n\
             [profile p.deploy]\nrole_arn = arn:aws:iam::222222222222:role/Deploy\nsource_profile = p\n\
             [sso-session acme.prod]\nsso_start_url = https://acme.awsapps.com/start\nsso_region = eu-west-1\n",
        );
        assert_eq!(import.iam_users[0].name, "john.doe");
        assert_eq!(import.portals[0].name, "acme.prod");
        let toml: String = import
            .portals
            .iter()
            .map(aws_portal_toml)
            .chain(import.iam_users.iter().map(aws_iam_user_toml))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            toml.contains("[integrations.\"john.doe\".roles.\"john.doe-admin\"]"),
            "{toml}"
        );
        let config = crate::Config::parse(&toml).unwrap();
        assert_eq!(
            config.integrations.keys().collect::<Vec<_>>(),
            ["acme.prod", "john.doe"]
        );
        let crate::Integration::AwsSso(sso) = &config.integrations["acme.prod"] else {
            panic!()
        };
        assert_eq!(sso.chained["p.deploy"].via_role, "Admin");

        // Appending roles to an integration whose name is quoted in the config.
        let existing = "[integrations.\"acme.prod\"]\ntype = \"aws-sso\"\nstart_url = \"https://acme.awsapps.com/start\"\nregion = \"eu-west-1\"\n\n[integrations.\"john.doe\"]\ntype = \"aws-iam\"\n";
        let appended = format!(
            "{existing}{}{}",
            chained_toml("acme.prod", &import.portals[0].chained),
            iam_roles_toml("john.doe", &import.iam_users[0].roles)
        );
        let config = crate::Config::parse(&appended).unwrap();
        let crate::Integration::AwsIam(user) = &config.integrations["john.doe"] else {
            panic!()
        };
        assert_eq!(
            user.roles["john.doe-admin"].role_arn,
            "arn:aws:iam::111111111111:role/Admin"
        );
    }

    #[test]
    fn indented_keys_are_continuations_only_below_a_shallower_property() {
        // Every key indented alike: all are kept.
        let sections = parse_ini(
            "[profile a]\n  sso_start_url = https://a.awsapps.com/start\n  sso_region = eu-west-1\n  region = eu-west-2\n",
        );
        assert_eq!(sections[0].1.len(), 3, "{sections:?}");
        assert_eq!(sections[0].1["region"], "eu-west-2");
        // Deeper than the property above: a sub-setting, skipped.
        let sections = parse_ini(
            "[profile a]\n  s3 =\n      region = us-east-1\n  region = eu-west-1\n[profile b]\n    region = eu-north-1\n",
        );
        assert_eq!(sections[0].1["region"], "eu-west-1");
        assert_eq!(sections[0].1.len(), 2);
        assert_eq!(
            sections[1].1["region"], "eu-north-1",
            "a header resets the depth"
        );
    }

    #[test]
    fn regional_portal_urls_of_a_multi_region_instance() {
        let regional = "https://SSOINS-1111aaaa2222bbbb.eu-west-1.portal.amazonaws.com/";
        let dual = "https://ssoins-1111aaaa2222bbbb.portal.eu-west-1.app.aws";
        assert_eq!(
            normalize_start_url(regional),
            "https://ssoins-1111aaaa2222bbbb.eu-west-1.portal.amazonaws.com"
        );
        assert_eq!(normalize_start_url(dual), dual);
        assert_eq!(
            subdomain(&normalize_start_url(regional)),
            "ssoins-1111aaaa2222bbbb-eu-west-1"
        );
        assert_eq!(subdomain(dual), "ssoins-1111aaaa2222bbbb-eu-west-1");
        assert_eq!(subdomain("https://acme.awsapps.com/start"), "acme");

        // The primary Region's portal and a replica's are two integrations.
        let import = aws_import(&format!(
            "[profile primary]\nsso_start_url = https://acme.awsapps.com/start\nsso_region = us-east-1\n\
             [profile replica]\nsso_start_url = {regional}\nsso_region = eu-west-1\n\
             [profile dual]\nsso_start_url = https://ssoins-1111aaaa2222bbbb.portal.us-west-2.app.aws\nsso_region = us-west-2\n"
        ));
        let found: Vec<(&str, &str, &str)> = import
            .portals
            .iter()
            .map(|p| (p.name.as_str(), p.start_url.as_str(), p.region.as_str()))
            .collect();
        assert_eq!(
            found,
            [
                ("acme", "https://acme.awsapps.com/start", "us-east-1"),
                (
                    "ssoins-1111aaaa2222bbbb-eu-west-1",
                    "https://ssoins-1111aaaa2222bbbb.eu-west-1.portal.amazonaws.com",
                    "eu-west-1"
                ),
                (
                    "ssoins-1111aaaa2222bbbb-us-west-2",
                    "https://ssoins-1111aaaa2222bbbb.portal.us-west-2.app.aws",
                    "us-west-2"
                ),
            ]
        );
        let toml: String = import
            .portals
            .iter()
            .map(aws_portal_toml)
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(crate::Config::parse(&toml).unwrap().integrations.len(), 3);
    }

    #[test]
    fn credential_process_paths() {
        let unix = |p: &str| credential_process_program(p, false);
        let windows = |p: &str| credential_process_program(p, true);
        assert_eq!(
            unix("/home/me/.local/bin/fob").unwrap(),
            "/home/me/.local/bin/fob"
        );
        assert_eq!(
            unix("/Users/me/My Tools/fob").unwrap(),
            "\"/Users/me/My Tools/fob\""
        );
        assert_eq!(
            windows(r"C:\Users\me\bin\fob.exe").unwrap(),
            r"C:\Users\me\bin\fob.exe"
        );
        assert_eq!(unix("/opt/(tools)/fob").unwrap(), "\"/opt/(tools)/fob\"");
        for bad in [
            r#"/a"b/fob"#,
            "/a$b/fob",
            "/a`b`/fob",
            r"/a\b/fob",
            "/a\nb/fob",
            "",
        ] {
            assert!(unix(bad).is_err(), "{bad:?}");
        }
        for bad in [
            r"C:\Program Files (x86)\fob.exe",
            r"C:\%USERPROFILE%\fob.exe",
            r"C:\a&b\fob.exe",
            // Needs quotes, which cmd.exe /C is not known to keep.
            r"C:\Users\First Last\bin\fob.exe",
            "",
        ] {
            assert!(windows(bad).is_err(), "{bad:?}");
        }
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
        let (block, _) = aws_config_block(&[&p], "fob-", &regions, "fob");
        assert!(block.contains("[profile fob-acme-prod-Admin]"));
        assert!(block.contains(
            "credential_process = fob creds acme/prod/Admin --format credential-process"
        ));
        assert!(block.contains("region = eu-west-1"));
        let (absolute, _) = aws_config_block(&[&p], "fob-", &regions, "\"/opt/my tools/fob\"");
        assert!(absolute.contains(
            "credential_process = \"/opt/my tools/fob\" creds acme/prod/Admin --format credential-process"
        ));

        let original = "[default]\nregion = us-east-1\n";
        let once = replace_aws_block(original, &block);
        assert!(once.starts_with(original));
        let twice = replace_aws_block(&once, &block);
        assert_eq!(once, twice, "rewriting is idempotent");

        let mine = format!("{once}[profile mine]\nregion = eu-north-1\n");
        let (empty, _) = aws_config_block(&[], "fob-", &regions, "fob");
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

    #[test]
    fn section_prefixes_need_whitespace() {
        let import = aws_import(
            "[sso-session-foo]\nsso_start_url = https://wrong.awsapps.com/start\nsso_region = eu-west-1\n\
             [sso-session\tacme]\nsso_start_url = https://acme.awsapps.com/start\nsso_region = eu-west-1\n\
             [profile\ttabbed]\nsso_session = acme\nsso_account_id = 111111111111\nsso_role_name = Admin\n\
             [profilefoo]\nsso_session = acme\n\
             [profile foo-session]\nsso_session = foo\n",
        );
        assert_eq!(import.portals.len(), 1, "{import:#?}");
        assert_eq!(import.portals[0].name, "acme");
        // Only `tabbed` counts: `[profilefoo]` is no profile, and `foo` no session.
        assert_eq!(import.portals[0].profiles, 1);
        let (profiles, sessions) = sections("[profile\t x ]\n[profile]\n[sso-session ]\n");
        assert_eq!(profiles.keys().collect::<Vec<_>>(), ["x"]);
        assert!(sessions.is_empty());
    }

    #[test]
    fn repeated_sections_merge_and_profile_default_wins() {
        let (profiles, _) = sections(
            "[default]\nregion = us-east-1\noutput = json\n\
             [profile a]\nregion = eu-west-1\nrole_arn = x\n\
             [profile b]\nregion = eu-north-1\n\
             [profile  a]\nregion = eu-west-2\n\
             [profile default]\nregion = eu-central-1\n",
        );
        assert_eq!(profiles["a"]["region"], "eu-west-2", "later keys win");
        assert_eq!(profiles["a"]["role_arn"], "x", "earlier keys stay");
        assert_eq!(profiles["default"]["region"], "eu-central-1");
        assert!(
            !profiles["default"].contains_key("output"),
            "[default] is ignored next to [profile default]"
        );
        let (profiles, _) = sections("[default]\nregion = us-east-1\n");
        assert_eq!(profiles["default"]["region"], "us-east-1");

        // A role whose keys are split over two sections is imported whole.
        let import = aws_import(
            "[profile p]\nsso_start_url = https://acme.awsapps.com/start\nsso_region = us-east-1\n\
             sso_account_id = 111111111111\nsso_role_name = Admin\n\
             [profile deploy]\nrole_arn = arn:aws:iam::222222222222:role/Deploy\n\
             [profile deploy]\nsource_profile = p\n",
        );
        assert!(
            import.portals[0].chained.contains_key("deploy"),
            "{import:#?}"
        );
    }

    #[test]
    fn aws_login_profiles_become_aws_login_integrations() {
        let import = aws_import(
            "[profile console]\nlogin_session = arn:aws:iam::111111111111:user/me\nregion = eu-west-1\n\
             [profile Console]\nlogin_session = arn:aws:iam::111111111111:user/me\nregion = eu-west-1\n\
             [profile elsewhere]\nlogin_session = arn:aws:iam::111111111111:user/me\nregion = us-east-1\n\
             [profile no-region]\nlogin_session = arn:aws:iam::111111111111:user/me\n\
             [profile bad-region]\nlogin_session = arn:aws:iam::111111111111:user/me\nregion = eu_west_1\n\
             [profile from-login]\nrole_arn = arn:aws:iam::222222222222:role/R\nsource_profile = console\n\
             [profile no-source]\nrole_arn = arn:aws:iam::222222222222:role/R\n",
        );
        let logins: Vec<(&str, &str, &str)> = import
            .logins
            .iter()
            .map(|l| (l.name.as_str(), l.profile.as_str(), l.region.as_str()))
            .collect();
        assert_eq!(
            logins,
            [
                ("console", "Console", "eu-west-1"),
                ("elsewhere", "elsewhere", "us-east-1")
            ]
        );
        let skipped = skipped(&import);
        assert!(
            skipped["console"].contains("same identity in the same Region as profile 'Console'"),
            "{skipped:?}"
        );
        assert!(skipped["no-region"].contains("no region"), "{skipped:?}");
        assert!(
            skipped["bad-region"].contains("not an AWS Region name"),
            "{skipped:?}"
        );
        assert!(
            skipped["from-login"].contains("login_session"),
            "{skipped:?}"
        );
        assert!(
            skipped["no-source"].contains("no source_profile or credential_source"),
            "{skipped:?}"
        );

        let toml = aws_login_toml(&import.logins[0]);
        assert_eq!(
            toml,
            "[integrations.console]\ntype = \"aws-login\"\nregion = \"eu-west-1\"\n"
        );
        let all: String = import
            .logins
            .iter()
            .map(aws_login_toml)
            .collect::<Vec<_>>()
            .join("\n");
        let config = crate::Config::parse(&all).unwrap();
        assert!(matches!(
            config.integrations["elsewhere"],
            crate::Integration::AwsLogin(_)
        ));
    }

    #[test]
    fn the_same_role_in_each_permission_sets_own_account_becomes_a_rule() {
        let mut text = String::from(
            "[sso-session acme]\nsso_start_url = https://acme.awsapps.com/start\nsso_region = eu-west-1\n",
        );
        for (name, account) in [
            ("dev", "111111111111"),
            ("prd", "222222222222"),
            ("ops", "333333333333"),
        ] {
            text.push_str(&format!(
                "[profile {name}-pe]\nsso_session = acme\nsso_account_id = {account}\nsso_role_name = pe\n\
                 [profile {name}-root]\nsource_profile = {name}-pe\nrole_arn = arn:aws:iam::{account}:role/ops/root\n"
            ));
        }
        // Another account's role, and one whose session name differs, stay tables.
        text.push_str(
            "[profile cross]\nsource_profile = dev-pe\nrole_arn = arn:aws:iam::222222222222:role/ops/root\n\
             [profile ops-named]\nsource_profile = ops-pe\nrole_arn = arn:aws:iam::333333333333:role/Deploy\n\
             role_session_name = me\n",
        );
        let import = aws_import(&text);
        let portal = &import.portals[0];
        assert_eq!(
            portal.chained.keys().collect::<Vec<_>>(),
            ["cross", "ops-named"]
        );
        let rule = &portal.chained_rules["root"];
        assert_eq!(
            (
                rule.via_role.as_str(),
                rule.role_name.as_str(),
                rule.path.as_deref()
            ),
            ("pe", "root", Some("/ops/"))
        );
        assert_eq!(
            rule.accounts,
            ["111111111111", "222222222222", "333333333333"]
        );
        let toml = aws_portal_toml(portal);
        assert!(
            toml.contains("[integrations.acme.chained_rules.\"root\"]"),
            "{toml}"
        );
        let config = crate::Config::parse(&toml).unwrap();
        let crate::Integration::AwsSso(sso) = &config.integrations["acme"] else {
            unreachable!()
        };
        assert_eq!(sso.chained_rules["root"], *rule);

        // One account alone keeps its table.
        let (chained, rules) = fold_chained(BTreeMap::from([(
            "one".to_string(),
            portal.chained["ops-named"].clone(),
        )]));
        assert!(rules.is_empty());
        assert_eq!(chained.len(), 1);
    }

    #[test]
    fn profile_names_that_slug_alike_get_labels_of_their_own() {
        let import = aws_import(
            "[profile p]\nsso_start_url = https://acme.awsapps.com/start\nsso_region = us-east-1\n\
             sso_account_id = 111111111111\nsso_role_name = Admin\n\
             [profile Prod]\nrole_arn = arn:aws:iam::222222222222:role/Deploy\nsource_profile = p\n\
             [profile prod]\nrole_arn = arn:aws:iam::333333333333:role/Deploy\nsource_profile = p\n\
             [profile keys]\nregion = eu-west-1\n\
             [profile Ops]\nrole_arn = arn:aws:iam::444444444444:role/Ops\nsource_profile = keys\n\
             [profile ops]\nrole_arn = arn:aws:iam::555555555555:role/Ops\nsource_profile = keys\n",
        );
        let chained = &import.portals[0].chained;
        assert_eq!(chained.keys().collect::<Vec<_>>(), ["prod", "prod-2"]);
        assert_eq!(
            chained["prod"].role_arn,
            "arn:aws:iam::222222222222:role/Deploy"
        );
        assert_eq!(
            chained["prod-2"].role_arn,
            "arn:aws:iam::333333333333:role/Deploy"
        );
        let roles = &import.iam_users[0].roles;
        assert_eq!(roles.keys().collect::<Vec<_>>(), ["ops", "ops-2"]);
        let toml = format!(
            "{}\n{}",
            aws_portal_toml(&import.portals[0]),
            aws_iam_user_toml(&import.iam_users[0])
        );
        assert!(crate::Config::parse(&toml).is_ok(), "{toml}");
    }

    #[test]
    fn what_the_config_would_refuse_is_skipped_with_the_reason() {
        let import = aws_import(
            "[profile p]\nsso_start_url = https://acme.awsapps.com/start\nsso_region = us-east-1\n\
             sso_account_id = 111111111111\nsso_role_name = Admin\n\
             [profile bad-region]\nrole_arn = arn:aws:iam::222222222222:role/R\nsource_profile = p\nregion = eu_west_1\n\
             [profile bad-session]\nrole_arn = arn:aws:iam::222222222222:role/R\nsource_profile = p\nrole_session_name = a b\n\
             [profile http-portal]\nsso_start_url = http://acme.awsapps.com/start\nsso_region = us-east-1\n\
             [profile odd-portal]\nsso_start_url = https://odd.awsapps.com/start\nsso_region = mars-1#\n\
             [profile keys]\nregion = us-east-1\n\
             [profile bad-arn]\nrole_arn = arn:aws:iam::2222:role/R\nsource_profile = keys\n\
             [profile gov-from-commercial]\nrole_arn = arn:aws-us-gov:iam::222222222222:role/R\nsource_profile = keys\n\
             [profile ok]\nrole_arn = arn:aws:iam::222222222222:role/R\nsource_profile = keys\n\
             [profile odd-keys]\nregion = nowhere\n\
             [profile from-odd-keys]\nrole_arn = arn:aws:iam::222222222222:role/R\nsource_profile = odd-keys\n",
        );
        let skipped = skipped(&import);
        for (profile, reason) in [
            (
                "bad-region",
                "region: 'eu_west_1' is not an AWS Region name",
            ),
            ("bad-session", "session_name 'a b'"),
            (
                "http-portal",
                "sso_start_url 'http://acme.awsapps.com/start' must be an https:// URL",
            ),
            (
                "odd-portal",
                "sso_region: 'mars-1#' is not an AWS Region name",
            ),
            ("bad-arn", "the account must be 12 digits"),
            ("gov-from-commercial", "AssumeRole cannot cross partitions"),
            (
                "from-odd-keys",
                "its source profile 'odd-keys' has a region that is not valid",
            ),
        ] {
            assert!(
                skipped.get(profile).is_some_and(|r| r.contains(reason)),
                "{profile}: {skipped:?}"
            );
        }
        assert_eq!(import.portals.len(), 1);
        assert_eq!(import.iam_users.len(), 1);
        assert_eq!(import.iam_users[0].roles.keys().collect::<Vec<_>>(), ["ok"]);
        let toml: String = import
            .portals
            .iter()
            .map(aws_portal_toml)
            .chain(import.iam_users.iter().map(aws_iam_user_toml))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(crate::Config::parse(&toml).is_ok(), "{toml}");
    }

    #[test]
    fn exported_names_that_clash_keep_the_first_profile() {
        let role = |integration: &str, account: &str| {
            crate::Profile::new(
                integration,
                account,
                "d",
                crate::Target::Aws {
                    account_id: "111111111111".into(),
                    account_name: account.into(),
                    role_name: "d".into(),
                },
            )
        };
        let (first, second, other) = (role("a-b", "c"), role("a", "b-c"), role("x", "y"));
        let (block, clashes) =
            aws_config_block(&[&first, &second, &other], "fob-", &BTreeMap::new(), "fob");
        assert_eq!(block.matches("[profile fob-a-b-c-d]").count(), 1, "{block}");
        assert!(block.contains("creds a-b/c/d "));
        assert!(!block.contains("creds a/b-c/d "));
        assert!(block.contains("[profile fob-x-y-d]"));
        assert_eq!(
            clashes,
            [ExportClash {
                name: "fob-a-b-c-d".into(),
                kept: "a-b/c/d".into(),
                left_out: "a/b-c/d".into(),
            }]
        );
    }

    #[test]
    fn the_block_is_found_after_its_start_and_crlf_files_stay_crlf() {
        let block = format!("{AWS_BLOCK_BEGIN}\n[profile fob-a]\nregion = x\n\n{AWS_BLOCK_END}\n");
        // An END line above the block (a copy, a note) is not the block's end.
        let existing = format!(
            "# {AWS_BLOCK_END} was here\n[default]\n\n{AWS_BLOCK_BEGIN}\n[profile old]\n{AWS_BLOCK_END}\n[profile mine]\n"
        );
        let replaced = replace_aws_block(&existing, &block);
        assert_eq!(
            replaced,
            format!("# {AWS_BLOCK_END} was here\n[default]\n\n{block}[profile mine]\n")
        );

        let crlf = existing.replace('\n', "\r\n");
        let replaced = replace_aws_block(&crlf, &block);
        assert_eq!(
            replaced,
            format!(
                "# {AWS_BLOCK_END} was here\r\n[default]\r\n\r\n{}[profile mine]\r\n",
                block.replace('\n', "\r\n")
            )
        );
        assert!(
            !replaced.replace("\r\n", "").contains('\n'),
            "no bare newline: {replaced:?}"
        );
        assert_eq!(replace_aws_block(&replaced, &block), replaced, "idempotent");

        // Appended to a CRLF file without a block.
        let appended = replace_aws_block("[default]\r\nregion = x\r\n", &block);
        assert_eq!(
            appended,
            format!(
                "[default]\r\nregion = x\r\n\r\n{}",
                block.replace('\n', "\r\n")
            )
        );
    }
}
