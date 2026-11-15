//! Imports from, and exports to, other tools' configuration.

use std::collections::BTreeMap;

/// What `fob import aws` found in an AWS config file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AwsImport {
    pub portals: Vec<AwsPortal>,
    /// IAM users whose access keys roles are assumed with.
    pub iam_users: Vec<AwsIamUser>,
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

fn sso_ref(
    keys: &BTreeMap<String, String>,
    sessions: &BTreeMap<&str, &BTreeMap<String, String>>,
) -> Option<SsoRef> {
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
const IAM_USER_ROLE_SECONDS: std::ops::RangeInclusive<i64> = 900..=43200;

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
/// them through `role_arn` and `source_profile`, and the roles assumed from
/// profiles with an IAM user's access key, which become `aws-iam`
/// integrations.
///
/// A source profile with neither Identity Center keys, a role, nor another
/// credential source (`credential_process`, `credential_source`,
/// `web_identity_token_file`, `login_session`) is taken to hold an access
/// key, here or in the credentials file, which is not read.
pub fn aws_import(text: &str) -> AwsImport {
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
    // Roles assumed from an IAM user's profile, by that profile, with the
    // `mfa_serial` each names.
    type IamRoles = Vec<(String, crate::config::IamRole, Option<String>)>;
    let mut iam: BTreeMap<String, IamRoles> = BTreeMap::new();
    let mut skipped = Vec::new();
    let mut skip = |profile: &str, reason: String| {
        skipped.push(SkippedProfile {
            profile: profile.to_string(),
            reason,
        })
    };

    for (name, keys) in &profiles {
        if let Some(sso) = sso_ref(keys, &sessions) {
            let f = entry(&mut found, &sso);
            f.profiles += 1;
            if let Some(region) = keys.get("region") {
                *f.regions.entry(region.clone()).or_default() += 1;
            }
            continue;
        }
        let Some(role_arn) = keys.get("role_arn") else {
            continue;
        };
        let Some(source) = keys.get("source_profile") else {
            if let Some(other) = other_source(keys) {
                skip(
                    name,
                    format!(
                        "it gets its source credentials through {other}, which omnifob cannot import"
                    ),
                );
            }
            continue;
        };
        let source_keys = profiles.get(source.as_str());
        if let Some(sso) = source_keys.and_then(|k| sso_ref(k, &sessions)) {
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
            if let Err(why) = crate::config::check_chained_role_arn(role_arn, &sso.sso_region) {
                skip(name, why);
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
                    mfa_serial: keys.get("mfa_serial").cloned(),
                    duration,
                },
            );
            continue;
        }
        if let Some(other) = source_keys.and_then(|k| other_source(k)) {
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
                "its duration_seconds is not 900 to 43200, the range AWS allows for roles assumed by an IAM user".into(),
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
                .max_by_key(|(region, count)| (*count, std::cmp::Reverse(region.clone())))
                .map(|(region, _)| region);
            AwsPortal {
                name,
                start_url,
                region: f.region,
                default_region,
                scopes: f.scopes,
                profiles: f.profiles,
                chained: f.chained,
            }
        })
        .collect();
    let iam_users = iam
        .into_iter()
        .filter_map(|(profile, roles)| {
            let source = profiles.get(profile.as_str());
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
                kept.insert(crate::profile::slug(&name), role);
            }
            if kept.is_empty() {
                return None;
            }
            Some(AwsIamUser {
                name: unique(&profile),
                region: source.and_then(|k| k.get("region").cloned()),
                mfa_serial,
                profile,
                roles: kept,
            })
        })
        .collect();
    AwsImport {
        portals,
        iam_users,
        skipped,
    }
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
pub fn aws_config_block(
    profiles: &[&crate::Profile],
    prefix: &str,
    regions: &BTreeMap<String, String>,
    program: &str,
) -> String {
    let mut out = format!("{AWS_BLOCK_BEGIN}\n");
    for p in profiles {
        if !p.target.is_aws() {
            continue;
        }
        let name = format!("{prefix}{}", p.id.replace('/', "-"));
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
region = eu-central-1 # the home Region

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
duration_seconds = 1800

[profile too-long-from-sso]
role_arn = arn:aws:iam::444444444444:role/Admin
source_profile = gary-test
duration_seconds = 7200

[profile from-static-keys]
role_arn = arn:aws:iam::555555555555:role/Admin
source_profile = plain-keys
duration_seconds = 43200
role_session_name = me
mfa_serial = arn:aws:iam::555555555555:mfa/user

[profile other-mfa]
role_arn = arn:aws:iam::555555555555:role/Other
source_profile = plain-keys
mfa_serial = arn:aws:iam::555555555555:mfa/another

[profile too-long-from-keys]
role_arn = arn:aws:iam::555555555555:role/Admin
source_profile = plain-keys
duration_seconds = 43201

[profile from-credentials-file]
role_arn = arn:aws:iam::777777777777:role/ReadOnly
source_profile = keys-elsewhere

[profile chain-of-chains]
role_arn = arn:aws:iam::888888888888:role/Deeper
source_profile = gary-test-deploy

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

        let gary = portal(&import, "d-111");
        assert_eq!(gary.name, "d-111");
        assert_eq!(gary.profiles, 7);
        assert_eq!(gary.default_region.as_deref(), Some("eu-central-1"));
    }

    #[test]
    fn imports_chained_roles() {
        let import = aws_import(CONFIG);
        let gary = portal(&import, "d-111");
        let deploy = &gary.chained["gary-test-deploy"];
        assert_eq!(deploy.via_account_id, "111111111111");
        assert_eq!(deploy.via_role, "Admin");
        assert_eq!(deploy.session_name.as_deref(), Some("gary"));
        assert_eq!(deploy.region.as_deref(), Some("us-east-1"));
        assert_eq!(deploy.role_name(), "Deploy");
        assert_eq!(gary.chained.len(), 2, "{:?}", gary.chained.keys());
        let mfa = &gary.chained["needs-mfa"];
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
            skipped["chain-of-chains"].contains("'gary-test-deploy' is itself a role"),
            "{}",
            skipped["chain-of-chains"]
        );
        assert!(skipped["from-process"].contains("credential_process"));
        assert!(skipped["half-chained"].contains("no account and role"));
        assert!(skipped["other-mfa"].contains("mfa_serial"));
        assert!(skipped["too-long-from-sso"].contains("900 to 3600"));
        assert!(skipped["too-long-from-keys"].contains("900 to 43200"));
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
            Some(jiff::SignedDuration::from_hours(12)),
            "IAM users' roles may last 12 hours"
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
            "[profile self]\naws_access_key_id = AKIAEXAMPLEKEYID0002\nrole_arn = arn:aws:iam::1:role/R\nsource_profile = self\n",
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
        let gary = portal(&import, "d-111");
        assert_eq!(gary.default_region.as_deref(), Some("eu-central-1"));
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
             [profile john.doe-admin]\nrole_arn = arn:aws:iam::1:role/Admin\nsource_profile = john.doe\n\
             [profile p]\nsso_session = acme.prod\nsso_account_id = 1\nsso_role_name = Admin\n\
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
            "arn:aws:iam::1:role/Admin"
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
        let block = aws_config_block(&[&p], "fob-", &regions, "fob");
        assert!(block.contains("[profile fob-acme-prod-Admin]"));
        assert!(block.contains(
            "credential_process = fob creds acme/prod/Admin --format credential-process"
        ));
        assert!(block.contains("region = eu-west-1"));
        let absolute = aws_config_block(&[&p], "fob-", &regions, "\"/opt/my tools/fob\"");
        assert!(absolute.contains(
            "credential_process = \"/opt/my tools/fob\" creds acme/prod/Admin --format credential-process"
        ));

        let original = "[default]\nregion = us-east-1\n";
        let once = replace_aws_block(original, &block);
        assert!(once.starts_with(original));
        let twice = replace_aws_block(&once, &block);
        assert_eq!(once, twice, "rewriting is idempotent");

        let mine = format!("{once}[profile mine]\nregion = eu-north-1\n");
        let empty = aws_config_block(&[], "fob-", &regions, "fob");
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
