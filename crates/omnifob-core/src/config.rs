//! User configuration: the integrations to sign in to.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, bail};
use jiff::SignedDuration;
use serde::{Deserialize, Serialize};

use crate::providers::aws_partition::Partition;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Browsers, or profiles of one browser, that integrations open in,
    /// keyed by the name their `browser` key refers to.
    #[serde(default)]
    pub browsers: BTreeMap<String, Browser>,
    #[serde(default)]
    pub integrations: BTreeMap<String, Integration>,
}

/// How to open a URL in one browser, or one profile of a browser, so that
/// each integration's sign-in sessions stay in the profile it belongs to.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Browser {
    /// The program and its arguments, run without a shell; `{url}` in an
    /// argument is replaced by the URL, e.g.
    /// `["firefox", "-P", "work", "{url}"]`.
    pub command: Vec<String>,
}

impl Browser {
    /// The program and its arguments for opening `url`.
    pub fn command_for(&self, url: &str) -> (&str, Vec<String>) {
        let args = self.command[1..]
            .iter()
            .map(|arg| arg.replace("{url}", url))
            .collect();
        (&self.command[0], args)
    }

    fn validate(&self) -> Result<(), String> {
        match self.command.split_first() {
            None => Err("command must name a program".to_string()),
            Some((program, _)) if program.is_empty() => {
                Err("command must name a program".to_string())
            }
            Some((program, _)) if program.contains("{url}") => {
                Err("{url} belongs in an argument, not in the program".to_string())
            }
            Some((_, args)) if !args.iter().any(|arg| arg.contains("{url}")) => {
                Err("command must pass the URL: put {url} in an argument".to_string())
            }
            Some(_) => Ok(()),
        }
    }
}

/// An identity source: something you sign in to once and that yields many
/// profiles.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "RawIntegration")]
pub enum Integration {
    AwsSso(AwsSsoConfig),
    AwsIam(AwsIamConfig),
    Gcp(GcpConfig),
    Azure(AzureConfig),
    /// Either Cloudflare type; `CloudflareConfig::sign_in` says which.
    Cloudflare(CloudflareConfig),
    Token(TokenConfig),
}

impl Integration {
    pub fn kind(&self) -> &'static str {
        match self {
            Integration::AwsSso(_) => "aws-sso",
            Integration::AwsIam(_) => "aws-iam",
            Integration::Gcp(_) => "gcp",
            Integration::Azure(_) => "azure",
            Integration::Cloudflare(c) => match c.sign_in {
                CloudflareSignIn::Token => "cloudflare-token",
                CloudflareSignIn::Oauth => "cloudflare-oauth",
            },
            Integration::Token(_) => "token",
        }
    }

    /// The name of the browser this integration opens in, if it sets one.
    pub fn browser(&self) -> Option<&str> {
        match self {
            Integration::AwsSso(c) => c.browser.as_deref(),
            Integration::AwsIam(c) => c.browser.as_deref(),
            Integration::Gcp(c) => c.browser.as_deref(),
            Integration::Azure(c) => c.browser.as_deref(),
            Integration::Cloudflare(c) => c.browser.as_deref(),
            Integration::Token(c) => c.browser.as_deref(),
        }
    }
}

/// The `type` values as written in the config file. Both Cloudflare types
/// share one configuration and differ only in how omnifob signs in.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum RawIntegration {
    AwsSso(AwsSsoConfig),
    AwsIam(AwsIamConfig),
    Gcp(GcpConfig),
    Azure(AzureConfig),
    CloudflareToken(CloudflareConfig),
    CloudflareOauth(CloudflareConfig),
    Token(TokenConfig),
}

impl TryFrom<RawIntegration> for Integration {
    type Error = String;

    fn try_from(raw: RawIntegration) -> Result<Self, Self::Error> {
        Ok(match raw {
            RawIntegration::AwsSso(c) => {
                c.validate()?;
                Integration::AwsSso(c)
            }
            RawIntegration::AwsIam(c) => {
                c.validate()?;
                Integration::AwsIam(c)
            }
            RawIntegration::Gcp(c) => {
                c.validate()?;
                Integration::Gcp(c)
            }
            RawIntegration::Azure(c) => Integration::Azure(c),
            RawIntegration::Token(c) => Integration::Token(c),
            RawIntegration::CloudflareToken(c) => {
                if c.client_id.is_some() || c.scopes.is_some() {
                    return Err(
                        "client_id and scopes belong to type = \"cloudflare-oauth\"".to_string()
                    );
                }
                Integration::Cloudflare(c)
            }
            RawIntegration::CloudflareOauth(mut c) => {
                if c.token_type != CloudflareTokenType::default() {
                    return Err("token_type only applies to type = \"cloudflare-token\"; \
                         cloudflare-oauth mints account-owned tokens"
                        .to_string());
                }
                c.sign_in = CloudflareSignIn::Oauth;
                Integration::Cloudflare(c)
            }
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsSsoConfig {
    /// The AWS access portal URL, e.g. `https://acme.awsapps.com/start`.
    pub start_url: String,
    /// The region IAM Identity Center runs in.
    pub region: String,
    /// Region exported as `AWS_REGION` for every profile of this integration.
    #[serde(default)]
    pub default_region: Option<String>,
    /// OIDC scopes. `sso:account:access` makes Identity Center issue a refresh
    /// token, so sessions renew without a browser until the portal session ends.
    #[serde(default = "default_sso_scopes")]
    pub scopes: Vec<String>,
    /// Roles reached by assuming them from one of this portal's roles
    /// (`role_arn` + `source_profile` in `~/.aws/config`), keyed by a label
    /// that becomes the middle of the profile id.
    #[serde(default)]
    pub chained: BTreeMap<String, ChainedRole>,
    /// Roles in another AWS partition, reached with a web identity token
    /// that one of this portal's roles requests, keyed by a label that
    /// becomes the middle of the profile id.
    #[serde(default)]
    pub cross_partition: BTreeMap<String, CrossPartitionRole>,
    /// How long `fob console` sessions of this portal's roles last
    /// (`SessionDuration`), 15 minutes to 12 hours, and shorter than the
    /// permission set's session duration, which omnifob cannot see. Unset,
    /// a console session lasts as long as the role's credentials. Chained
    /// roles cannot take it.
    #[serde(default, with = "opt_duration")]
    pub console_duration: Option<SignedDuration>,
    /// The browser in `[browsers]` that this integration's sign-ins and
    /// consoles open in; by default the system's.
    #[serde(default)]
    pub browser: Option<String>,
}

impl AwsSsoConfig {
    fn validate(&self) -> Result<(), String> {
        check_region("region", &self.region)?;
        if let Some(region) = &self.default_region {
            check_region("default_region", region)?;
        }
        for (label, role) in &self.chained {
            if let Some(region) = &role.region {
                check_region(&format!("chained.{label}.region"), region)?;
            }
            self.check_chained_arn(role)
                .map_err(|e| format!("chained.{label}: {e}"))?;
        }
        for (label, role) in &self.cross_partition {
            role.validate(label, self)
                .map_err(|e| format!("cross_partition.{label}: {e}"))?;
        }
        self.check_profile_ids()?;
        check_console_duration("console_duration", self.console_duration)
    }

    fn check_chained_arn(&self, role: &ChainedRole) -> Result<(), String> {
        check_chained_role_arn(&role.role_arn, &self.region)
    }

    /// Fails when a cross-partition role would get the same profile id as a
    /// chained role or another cross-partition role, which the config alone
    /// shows. Collisions with Identity Center roles appear only at discovery.
    fn check_profile_ids(&self) -> Result<(), String> {
        let chained = self
            .chained
            .iter()
            .map(|(label, role)| ("chained", label, role.role_name()));
        let cross = self
            .cross_partition
            .iter()
            .map(|(label, role)| ("cross_partition", label, role.role_name()));
        let mut seen: BTreeMap<String, (&str, &String)> = BTreeMap::new();
        for (table, label, role_name) in chained.chain(cross) {
            let id = format!("{}/{role_name}", crate::profile::slug(label));
            if let Some((other_table, other_label)) = seen.insert(id.clone(), (table, label))
                && table == "cross_partition"
            {
                return Err(format!(
                    "{other_table}.{other_label} and {table}.{label} would both be the profile \
                     <integration>/{id}; rename one of them"
                ));
            }
        }
        Ok(())
    }

    /// The Region a cross-partition role's token is requested in, when the
    /// role sets none: `default_region`, else the portal's.
    pub fn default_source_region(&self) -> &str {
        self.default_region.as_deref().unwrap_or(&self.region)
    }

    /// The partition of the portal, which its roles' credentials belong to.
    pub fn partition(&self) -> anyhow::Result<Partition> {
        Partition::of_region(&self.region)
    }
}

/// Fails unless a chained role's `role_arn` is an IAM role ARN in the
/// partition of the portal in `portal_region`: `AssumeRole` stays within a
/// partition, so a role in another one needs `cross_partition`. A portal in
/// an isolated partition, which `Partition` does not model, gets the ARN
/// shape check only. `fob import aws` skips such roles with this reason.
pub(crate) fn check_chained_role_arn(role_arn: &str, portal_region: &str) -> Result<(), String> {
    check_role_arn(role_arn)?;
    let Ok(portal) = Partition::of_region(portal_region) else {
        return Ok(());
    };
    let partition = Partition::of_arn(role_arn).map_err(|e| format!("role_arn: {e:#}"))?;
    if partition != portal {
        return Err(format!(
            "role_arn is in the {partition} partition, but the portal and its roles are in \
             {portal}; AssumeRole cannot cross partitions, so configure this role under \
             `cross_partition` instead"
        ));
    }
    Ok(())
}

/// Fails unless `region` is shaped like an AWS Region, naming the key.
/// Regions become part of host names, so a malformed one is refused when
/// the config loads rather than when a command first uses it.
fn check_region(key: &str, region: &str) -> Result<(), String> {
    crate::providers::aws_partition::check_region_name(region).map_err(|e| format!("{key}: {e}"))
}

/// Fails unless a configured console session length is one the federation
/// endpoint accepts.
fn check_console_duration(key: &str, duration: Option<SignedDuration>) -> Result<(), String> {
    match duration {
        Some(d) if !crate::providers::aws_sso::CONSOLE_SESSION.contains(&d) => {
            Err(format!("{key} must be between 15m and 12h"))
        }
        _ => Ok(()),
    }
}

/// A role assumed with the credentials of an Identity Center role.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChainedRole {
    /// Account of the Identity Center role to start from.
    pub via_account_id: String,
    /// Name of the Identity Center role (permission set) to start from.
    pub via_role: String,
    pub role_arn: String,
    /// `RoleSessionName`; defaults to "omnifob".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// Region exported for this role; defaults to the integration's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// MFA device the role's trust policy requires (`mfa_serial` in
    /// `~/.aws/config`); a code is asked for each new session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfa_serial: Option<String>,
    /// Session length, 15 minutes to 1 hour (AWS caps role-chaining sessions
    /// at one hour); defaults to one hour.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_duration"
    )]
    pub duration: Option<SignedDuration>,
}

impl ChainedRole {
    /// The role name at the end of `role_arn` (after any path).
    pub fn role_name(&self) -> &str {
        self.role_arn.rsplit('/').next().unwrap_or(&self.role_arn)
    }

    /// The account in `role_arn`.
    pub fn account_id(&self) -> Option<&str> {
        self.role_arn.split(':').nth(4).filter(|a| !a.is_empty())
    }

    /// The partition in `role_arn`.
    pub fn partition(&self) -> anyhow::Result<Partition> {
        Partition::of_arn(&self.role_arn)
    }
}

/// A role in another AWS partition, reached from an Identity Center role
/// (`[integrations.<name>.cross_partition.<label>]`): the Identity Center
/// role requests a web identity token with STS `GetWebIdentityToken` in its
/// own partition, and `AssumeRoleWithWebIdentity` exchanges it for the
/// role's credentials in the other partition. Checked when the config loads,
/// so `role_arn` is an IAM role ARN in a partition other than the source
/// Region's, and `region` is in the partition of `role_arn`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrossPartitionRole {
    /// Account of the Identity Center role that requests the token.
    pub via_account_id: String,
    /// Name of the Identity Center role (permission set) that requests the
    /// token.
    pub via_role: String,
    /// The role to assume, in another partition.
    pub role_arn: String,
    /// The token's one audience: a client ID of the destination account's
    /// OIDC provider for the source account's issuer.
    pub audience: String,
    /// The destination partition's STS Region, exported as `AWS_REGION`.
    pub region: String,
    /// Where the token is requested; defaults to the integration's
    /// `default_region`, then the portal's Region
    /// ([`CrossPartitionRole::source_region`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_region: Option<String>,
    /// How the token is signed; ES384 unless set.
    #[serde(default)]
    pub signing_algorithm: SigningAlgorithm,
    /// `RoleSessionName`; defaults to "omnifob".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_name: Option<String>,
    /// Session length, 15 minutes to the destination role's maximum (at most
    /// 12 hours); defaults to one hour
    /// ([`CrossPartitionRole::DEFAULT_DURATION`]).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_duration"
    )]
    pub duration: Option<SignedDuration>,
}

/// The algorithm `GetWebIdentityToken` signs the token with
/// (`SigningAlgorithm`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum SigningAlgorithm {
    /// ECDSA with P-384 and SHA-384, the one AWS's examples use.
    #[default]
    #[serde(rename = "ES384")]
    Es384,
    /// RSA with SHA-256, for relying parties without ECDSA.
    #[serde(rename = "RS256")]
    Rs256,
}

impl SigningAlgorithm {
    /// The value STS takes, `ES384` or `RS256`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Es384 => "ES384",
            Self::Rs256 => "RS256",
        }
    }
}

impl CrossPartitionRole {
    /// The session length `AssumeRoleWithWebIdentity` accepts: 15 minutes to
    /// 12 hours, capped further by the role's maximum session duration.
    pub const DURATION: std::ops::RangeInclusive<SignedDuration> =
        SignedDuration::from_mins(15)..=SignedDuration::from_hours(12);

    /// The session length asked for when `duration` is unset, as STS
    /// itself defaults to.
    pub const DEFAULT_DURATION: SignedDuration = SignedDuration::from_hours(1);

    /// The role name at the end of `role_arn` (after any path).
    pub fn role_name(&self) -> &str {
        self.role_arn.rsplit('/').next().unwrap_or(&self.role_arn)
    }

    /// The account in `role_arn`, 12 digits once the config has loaded.
    pub fn account_id(&self) -> &str {
        self.role_arn.split(':').nth(4).unwrap_or_default()
    }

    /// The destination partition, the one in `role_arn`.
    pub fn partition(&self) -> anyhow::Result<Partition> {
        Partition::of_arn(&self.role_arn)
    }

    /// The Region the token is requested in: `source_region`, else the
    /// portal's `default_region`, else the portal's Region.
    pub fn source_region<'a>(&'a self, portal: &'a AwsSsoConfig) -> &'a str {
        self.source_region
            .as_deref()
            .unwrap_or_else(|| portal.default_source_region())
    }

    /// `RoleSessionName`: `session_name`, else "omnifob".
    pub fn session_name(&self) -> &str {
        self.session_name.as_deref().unwrap_or("omnifob")
    }

    /// The session length to ask for: `duration`, else one hour.
    pub fn duration_or_default(&self) -> SignedDuration {
        self.duration.unwrap_or(Self::DEFAULT_DURATION)
    }

    fn validate(&self, label: &str, portal: &AwsSsoConfig) -> Result<(), String> {
        check_name("the label", label).map_err(|e| e.to_string())?;
        if self.via_account_id.len() != 12
            || !self.via_account_id.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(format!(
                "via_account_id '{}' must be a 12-digit AWS account ID",
                self.via_account_id
            ));
        }
        if self.via_role.is_empty() {
            return Err("via_role must name the Identity Center role (permission set)".into());
        }
        check_role_arn(&self.role_arn)?;
        let destination = self.partition().map_err(|e| format!("role_arn: {e:#}"))?;

        check_region("region", &self.region)?;
        destination
            .check_region(&self.region)
            .map_err(|e| format!("region must be in the partition of role_arn: {e:#}"))?;

        if let Some(region) = &self.source_region {
            check_region("source_region", region)?;
        }
        let source_region = self.source_region(portal);
        let source_key = match (&self.source_region, &portal.default_region) {
            (Some(_), _) => "source_region",
            (None, Some(_)) => "default_region (the default source_region)",
            (None, None) => "the portal's region (the default source_region)",
        };
        let source =
            Partition::of_region(source_region).map_err(|e| format!("{source_key}: {e:#}"))?;
        let portal_partition = portal
            .partition()
            .map_err(|e| format!("the portal's region: {e:#}"))?;
        if source != portal_partition {
            return Err(format!(
                "{source_key} {source_region} is in the {source} partition, but the Identity \
                 Center role's credentials are for {portal_partition}, the portal's"
            ));
        }
        if source == destination {
            return Err(format!(
                "role_arn is in the {destination} partition, the same as the source Region \
                 {source_region}; a cross-partition role must be in another partition (use \
                 `chained` for a role in the same one)"
            ));
        }

        // The audience must equal a client ID of the destination's IAM OIDC
        // provider, which IAM's CreateOpenIDConnectProvider takes at 1 to 255
        // characters (ClientIDList); GetWebIdentityToken would take 1000.
        let audience = self.audience.chars().count();
        if !(1..=255).contains(&audience) {
            return Err(format!(
                "audience must be 1 to 255 characters (an IAM OIDC provider's client ID), \
                 not {audience}"
            ));
        }
        if let Some(name) = &self.session_name {
            check_session_name(name)?;
        }
        if let Some(d) = self.duration
            && !Self::DURATION.contains(&d)
        {
            return Err("duration must be between 15m and 12h".to_string());
        }
        Ok(())
    }
}

/// Fails unless `arn` is an IAM role ARN, `arn:<partition>:iam::<account>:
/// role/[<path>/]<name>`, with a 12-digit account and a role name IAM
/// allows. The role name ends up in a profile id.
fn check_role_arn(arn: &str) -> Result<(), String> {
    let bad = |why: &str| {
        Err(format!(
            "role_arn '{arn}' is not an IAM role ARN (arn:<partition>:iam::<account>:role/<name>): {why}"
        ))
    };
    let fields: Vec<&str> = arn.splitn(6, ':').collect();
    let [prefix, _partition, service, region, account, resource] = fields[..] else {
        return bad("it needs six ':'-separated fields");
    };
    if prefix != "arn" || service != "iam" || !region.is_empty() {
        return bad("it must start with arn:<partition>:iam::");
    }
    if account.len() != 12 || !account.bytes().all(|b| b.is_ascii_digit()) {
        return bad("the account must be 12 digits");
    }
    let Some(path_and_name) = resource.strip_prefix("role/") else {
        return bad("the resource must be role/<name>");
    };
    let name = path_and_name.rsplit('/').next().unwrap_or_default();
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+=,.@_-".contains(c))
    {
        return bad("the role name must be 1 to 64 letters, digits or +=,.@_-");
    }
    // IAM role paths (CreateRole `Path`) are `/`, or `/` + printable ASCII
    // + `/`, at most 512 characters. Empty segments (`role//Audit`) are
    // refused as the typo they almost always are.
    let inner = &path_and_name[..path_and_name.len() - name.len()];
    if !inner.bytes().all(|b| b.is_ascii_graphic()) {
        return bad("the role path may contain only printable ASCII");
    }
    if inner.split('/').rev().skip(1).any(str::is_empty) {
        return bad("the role path has an empty segment");
    }
    if 1 + inner.len() > 512 {
        return bad("the role path is longer than IAM's 512 characters");
    }
    Ok(())
}

/// Fails unless `name` is a `RoleSessionName` STS accepts: 2 to 64 letters,
/// digits or `+=,.@_-`.
fn check_session_name(name: &str) -> Result<(), String> {
    if !(2..=64).contains(&name.len())
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+=,.@_-".contains(c))
    {
        return Err(format!(
            "session_name '{name}' must be 2 to 64 letters, digits or +=,.@_-"
        ));
    }
    Ok(())
}

/// An IAM user's access key, kept in the keychain (`type = "aws-iam"`), the
/// way aws-vault keeps it. omnifob never hands the key out: it turns it into a
/// session with STS `GetSessionToken` (with an MFA code when `mfa_serial` is
/// set), and assumes `roles` with that session.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsIamConfig {
    /// Middle segment of the session profile's id; defaults to the account ID.
    #[serde(default)]
    pub account: Option<String>,
    /// Region exported as `AWS_REGION` and used for STS; STS defaults to
    /// us-east-1 when unset, and no region is exported.
    #[serde(default)]
    pub region: Option<String>,
    /// The user's MFA device; sessions then carry MFA, which roles requiring
    /// it accept.
    #[serde(default)]
    pub mfa_serial: Option<String>,
    /// Length of the user's session, 15 minutes to 36 hours; defaults to
    /// eight hours, a working day.
    #[serde(default, with = "opt_duration")]
    pub session_duration: Option<SignedDuration>,
    /// Roles assumed with the user's session, keyed by a label that becomes
    /// the middle of the profile id.
    #[serde(default)]
    pub roles: BTreeMap<String, IamRole>,
    /// The browser in `[browsers]` that this integration's sign-ins and
    /// consoles open in; by default the system's.
    #[serde(default)]
    pub browser: Option<String>,
}

impl AwsIamConfig {
    fn validate(&self) -> Result<(), String> {
        if let Some(region) = &self.region {
            check_region("region", region)?;
        }
        for (label, role) in &self.roles {
            if let Some(region) = &role.region {
                check_region(&format!("roles.{label}.region"), region)?;
            }
        }
        if let Some(d) = self.session_duration
            && !(SignedDuration::from_mins(15)..=SignedDuration::from_hours(36)).contains(&d)
        {
            return Err("session_duration must be between 15m and 36h".to_string());
        }
        for (label, role) in &self.roles {
            if let Some(d) = role.duration
                && !(SignedDuration::from_mins(15)..=SignedDuration::from_hours(12)).contains(&d)
            {
                return Err(format!(
                    "roles.{label}.duration must be between 15m and 12h"
                ));
            }
            check_console_duration(
                &format!("roles.{label}.console_duration"),
                role.console_duration,
            )?;
        }
        Ok(())
    }
}

/// A role assumed with an IAM user's session.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IamRole {
    pub role_arn: String,
    /// `RoleSessionName`; defaults to "omnifob".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// Region exported for this role; defaults to the integration's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Session length, 15 minutes to the role's maximum (at most 12 hours);
    /// defaults to one hour.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_duration"
    )]
    pub duration: Option<SignedDuration>,
    /// How long `fob console` sessions last (`SessionDuration`), 15 minutes
    /// to 12 hours and shorter than the role's maximum session duration.
    /// Unset, a console session lasts as long as the role's credentials.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_duration"
    )]
    pub console_duration: Option<SignedDuration>,
}

impl IamRole {
    /// The role name at the end of `role_arn` (after any path).
    pub fn role_name(&self) -> &str {
        self.role_arn.rsplit('/').next().unwrap_or(&self.role_arn)
    }

    /// The account in `role_arn`.
    pub fn account_id(&self) -> Option<&str> {
        self.role_arn.split(':').nth(4).filter(|a| !a.is_empty())
    }

    /// The partition in `role_arn`.
    pub fn partition(&self) -> anyhow::Result<Partition> {
        Partition::of_arn(&self.role_arn)
    }
}

/// A Google account (`type = "gcp"`), signed in the way `gcloud auth login`
/// signs in. Profiles are the account itself in each project, and service
/// accounts it may impersonate.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpConfig {
    /// The projects to offer; by default every active project the account
    /// can see, listed at `fob sync`.
    #[serde(default)]
    pub projects: Option<Vec<String>>,
    /// An OAuth client of your own (a Desktop app client) instead of the one
    /// gcloud ships. Both or neither.
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Service accounts to impersonate, keyed by a label that becomes the
    /// middle of the profile id.
    #[serde(default)]
    pub service_accounts: BTreeMap<String, GcpServiceAccount>,
    /// The browser in `[browsers]` that this integration's sign-ins and
    /// consoles open in; by default the system's.
    #[serde(default)]
    pub browser: Option<String>,
}

impl GcpConfig {
    fn validate(&self) -> Result<(), String> {
        if self.client_id.is_some() != self.client_secret.is_some() {
            return Err("client_id and client_secret go together".to_string());
        }
        for (label, sa) in &self.service_accounts {
            if !sa.email.contains('@') {
                return Err(format!(
                    "service_accounts.{label}.email must be a service account's email"
                ));
            }
            if let Some(d) = sa.lifetime
                && !(SignedDuration::from_mins(15)..=SignedDuration::from_hours(12)).contains(&d)
            {
                return Err(format!(
                    "service_accounts.{label}.lifetime must be between 15m and 12h"
                ));
            }
        }
        Ok(())
    }
}

/// A service account the signed-in account impersonates, which needs the
/// Service Account Token Creator role on it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpServiceAccount {
    pub email: String,
    /// Exported as the project; defaults to the one in the email.
    #[serde(default)]
    pub project: Option<String>,
    /// Token lifetime; defaults to one hour, the most Google allows unless the
    /// organization policy `iam.allowServiceAccountCredentialLifetimeExtension`
    /// lists the account (then up to 12 hours).
    #[serde(default, with = "opt_duration")]
    pub lifetime: Option<SignedDuration>,
    /// Service accounts to go through, in order, when the account may only
    /// impersonate this one by way of others.
    #[serde(default)]
    pub delegates: Vec<String>,
    /// OAuth scopes for the token; defaults to cloud-platform and
    /// userinfo.email, as gcloud asks.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
}

impl GcpServiceAccount {
    /// The part of the email before `@`.
    pub fn name(&self) -> &str {
        self.email.split('@').next().unwrap_or(&self.email)
    }

    /// `project`, or the project in a user-managed account's email
    /// (`name@PROJECT.iam.gserviceaccount.com`).
    pub fn project(&self) -> Option<&str> {
        self.project.as_deref().or_else(|| {
            self.email
                .split_once('@')?
                .1
                .strip_suffix(".iam.gserviceaccount.com")
        })
    }
}

/// A Microsoft Entra ID account (`type = "azure"`), signed in the way
/// `az login` signs in. Profiles are the account in each subscription.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AzureConfig {
    /// The tenant to sign in to (ID or domain); by default `organizations`,
    /// which finds every tenant the account belongs to.
    #[serde(default)]
    pub tenant: Option<String>,
    /// The subscriptions to offer (IDs); by default every one the account
    /// can see, listed at `fob sync`.
    #[serde(default)]
    pub subscriptions: Option<Vec<String>>,
    /// The browser in `[browsers]` that this integration's sign-ins and
    /// consoles open in; by default the system's.
    #[serde(default)]
    pub browser: Option<String>,
}

fn default_sso_scopes() -> Vec<String> {
    vec!["sso:account:access".to_string()]
}

/// Long-lived tokens for providers without short-lived credentials.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenConfig {
    /// A known provider: its variable names, token check and console URL.
    #[serde(default)]
    pub preset: Option<String>,
    /// Secret name → environment variables that receive it; replaces the
    /// preset's secrets.
    #[serde(default)]
    pub secrets: BTreeMap<String, Vec<String>>,
    /// Non-secret variables exported along with the secrets.
    #[serde(default)]
    pub vars: BTreeMap<String, String>,
    /// Middle segment of the profile id; defaults to "default".
    #[serde(default)]
    pub account: Option<String>,
    #[serde(default)]
    pub console: Option<String>,
    /// URL that answers 2xx when the token is sent as a bearer token.
    #[serde(default)]
    pub verify_url: Option<String>,
    /// The browser in `[browsers]` that this integration's sign-ins and
    /// consoles open in; by default the system's.
    #[serde(default)]
    pub browser: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareConfig {
    /// Account to mint tokens for. When omitted, every account the bootstrap
    /// token can list is discovered.
    #[serde(default)]
    pub account_id: Option<String>,
    /// Display name for `account_id`; defaults to the ID.
    #[serde(default)]
    pub account_name: Option<String>,
    /// The configured owner of minted tokens (`cloudflare-token` only). OAuth
    /// leaves it at the default yet mints account-owned tokens, so code that
    /// acts on the owner reads [`CloudflareConfig::minting`] instead.
    #[serde(default)]
    pub token_type: CloudflareTokenType,
    /// Lifetime of minted tokens unless a template overrides it.
    #[serde(default = "default_cloudflare_ttl", with = "duration")]
    pub ttl: SignedDuration,
    /// Extra templates, added to (or replacing) the built-in ones.
    #[serde(default)]
    pub templates: BTreeMap<String, CloudflareTemplate>,
    /// Addresses minted tokens may be used from, unless a template sets its
    /// own: IPs or CIDR ranges, or "current" for this machine's public
    /// addresses at minting time. Empty means anywhere.
    #[serde(default)]
    pub ips: Vec<String>,
    /// Sign-in session length. When set, `fob login` makes the new bootstrap
    /// token expire after this long, so it works like an SSO session: a
    /// stolen copy stops working, and a new one needs the dashboard sign-in.
    #[serde(default, with = "opt_duration")]
    pub session: Option<SignedDuration>,
    /// `cloudflare-oauth`: the OAuth client to sign in with.
    #[serde(default)]
    pub client_id: Option<String>,
    /// `cloudflare-oauth`: scopes requested at sign-in; defaults to the ones
    /// minting needs.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// Set from the integration's `type`.
    #[serde(skip)]
    pub sign_in: CloudflareSignIn,
    /// The browser in `[browsers]` that this integration's sign-ins and
    /// consoles open in; by default the system's.
    #[serde(default)]
    pub browser: Option<String>,
}

/// How a Cloudflare integration signs in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CloudflareSignIn {
    /// `cloudflare-token`: a bootstrap API token made in the dashboard.
    #[default]
    Token,
    /// `cloudflare-oauth`: the browser, through an OAuth client, as wrangler
    /// signs in. Tokens are minted as account-owned tokens in each account
    /// approved on the consent page.
    Oauth,
}

impl CloudflareConfig {
    /// Whether this integration signs in through the browser (OAuth).
    pub fn uses_oauth(&self) -> bool {
        self.sign_in == CloudflareSignIn::Oauth
    }

    /// Who owns the tokens omnifob mints. With OAuth sign-in they are
    /// account-owned, created in each approved account.
    pub fn minting(&self) -> CloudflareTokenType {
        if self.uses_oauth() {
            CloudflareTokenType::Account
        } else {
            self.token_type
        }
    }
}

fn default_cloudflare_ttl() -> SignedDuration {
    SignedDuration::from_hours(1)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CloudflareTokenType {
    /// Minted with a user-owned bootstrap token ("Create additional tokens").
    #[default]
    User,
    /// Minted with an account-owned bootstrap token ("Account API Tokens Edit").
    Account,
}

/// A named set of permissions, written as they appear in the dashboard's API
/// names (e.g. "Workers Scripts Write"), never as IDs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareTemplate {
    pub permissions: Vec<String>,
    /// Permissions added when the account offers them and skipped otherwise,
    /// for products that are new, renamed or not enabled everywhere.
    #[serde(default)]
    pub optional: Vec<String>,
    #[serde(default, with = "opt_duration")]
    pub ttl: Option<SignedDuration>,
    /// R2 buckets that bucket-level permissions ("Workers R2 Storage Bucket
    /// Item Write") apply to; "eu/name" for a bucket in a jurisdiction.
    #[serde(default)]
    pub r2_buckets: Vec<String>,
    /// Also hand out the S3-compatible credentials R2 derives from the token
    /// (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_ENDPOINT_URL_S3`).
    #[serde(default)]
    pub s3: bool,
    /// Overrides the integration's `ips` for this template.
    #[serde(default)]
    pub ips: Option<Vec<String>>,
}

impl Config {
    /// Loads the config file; a missing file is an empty config.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        Self::load_with(path, Self::parse)
    }

    /// Loads the config file without checking integration names, for
    /// `fob rename`, which has to open a config with a name that breaks the
    /// rule in order to fix it.
    pub fn load_allowing_any_names(path: &Path) -> anyhow::Result<Self> {
        Self::load_with(path, Self::parse_allowing_any_names)
    }

    fn load_with(path: &Path, parse: fn(&str) -> anyhow::Result<Self>) -> anyhow::Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        parse(&text).with_context(|| format!("parsing {}", path.display()))
    }

    /// Parses a config. Integration names may contain only letters, digits,
    /// `.`, `_` and `-` (see [`check_name`]); the error for another name says
    /// how to rename it.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let config = Self::parse_allowing_any_names(text)?;
        for name in config.integrations.keys() {
            if let Err(e) = check_name("integration name", name) {
                bail!("{e}; rename it with `fob rename \"{name}\" <new-name>`");
            }
        }
        Ok(config)
    }

    /// Parses a config without checking integration names.
    pub fn parse_allowing_any_names(text: &str) -> anyhow::Result<Self> {
        let config: Self = toml::from_str(text)?;
        for (name, browser) in &config.browsers {
            if let Err(e) = browser.validate() {
                bail!("browser '{name}': {e}");
            }
        }
        for (name, integration) in &config.integrations {
            if let Some(browser) = integration.browser()
                && !config.browsers.contains_key(browser)
            {
                let known: Vec<_> = config.browsers.keys().map(String::as_str).collect();
                bail!(
                    "integration '{name}' opens in browser '{browser}', which [browsers] does not define (defined: {})",
                    if known.is_empty() {
                        "none".to_string()
                    } else {
                        known.join(", ")
                    }
                );
            }
        }
        Ok(config)
    }

    /// The browser that integration `name` opens in, or `None` for the
    /// system's default browser.
    pub fn browser_for(&self, name: &str) -> anyhow::Result<Option<&Browser>> {
        Ok(self
            .integration(name)?
            .browser()
            .and_then(|browser| self.browsers.get(browser)))
    }

    pub fn integration(&self, name: &str) -> anyhow::Result<&Integration> {
        self.integrations.get(name).with_context(|| {
            let known: Vec<_> = self.integrations.keys().map(String::as_str).collect();
            format!(
                "no integration named '{name}' (configured: {})",
                known.join(", ")
            )
        })
    }
}

/// Renames an integration in the text of a config file, keeping comments,
/// layout and its sub-tables (chained roles, templates).
pub fn rename_integration(text: &str, old: &str, new: &str) -> anyhow::Result<String> {
    check_name("integration name", new)?;
    let mut doc: toml_edit::DocumentMut = text.parse().context("parsing the config")?;
    let integrations = doc
        .get_mut("integrations")
        .and_then(|i| i.as_table_mut())
        .context("the config has no [integrations] table")?;
    if integrations.contains_key(new) {
        bail!("an integration named '{new}' already exists");
    }
    let (key, item) = integrations
        .remove_entry(old)
        .with_context(|| format!("no integration named '{old}'"))?;
    let renamed = toml_edit::Key::new(new)
        .with_leaf_decor(key.leaf_decor().clone())
        .with_dotted_decor(key.dotted_decor().clone());
    integrations.insert_formatted(&renamed, item);
    let text = doc.to_string();
    // Other integrations may still have names to fix, one rename at a time.
    Config::parse_allowing_any_names(&text).context("the renamed config is not valid")?;
    Ok(text)
}

/// Fails unless `name` is non-empty, made of ASCII letters, digits, `.`, `_`
/// and `-`, and does not start with `-` (the command line would read it as
/// an option). Integration names go into profile ids, the AWS config's
/// `credential_process` lines, keychain keys, lock files and the WSL vault's
/// file names; template names into profile ids.
pub fn check_name(what: &str, name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        bail!("{what} must not be empty");
    }
    if name.starts_with('-') {
        bail!("{what} '{name}' must not start with '-'");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        bail!("{what} '{name}' may contain only letters, digits, '.', '_' and '-'");
    }
    Ok(())
}

/// Adds a template to a Cloudflare integration in the config text, keeping
/// the rest of the file as it is. An existing template of that name is
/// replaced only with `replace`.
pub fn add_cloudflare_template(
    text: &str,
    integration: &str,
    name: &str,
    template: &CloudflareTemplate,
    replace: bool,
) -> anyhow::Result<String> {
    check_name("template name", name)?;
    let mut doc: toml_edit::DocumentMut = text.parse().context("parsing the config")?;
    let table = doc
        .get_mut("integrations")
        .and_then(|i| i.get_mut(integration))
        .and_then(|i| i.as_table_mut())
        .with_context(|| format!("no integration named '{integration}'"))?;
    if table
        .get("type")
        .and_then(|t| t.as_str())
        .is_none_or(|t| !t.starts_with("cloudflare-"))
    {
        bail!("'{integration}' is not a cloudflare integration");
    }
    let templates = table
        .entry("templates")
        .or_insert_with(|| {
            let mut t = toml_edit::Table::new();
            t.set_implicit(true);
            toml_edit::Item::Table(t)
        })
        .as_table_mut()
        .context("`templates` must be a table")?;
    if templates.contains_key(name) && !replace {
        bail!("integration '{integration}' already has a template named '{name}'");
    }
    let mut new = toml_edit::Table::new();
    new["permissions"] =
        toml_edit::value(template.permissions.iter().collect::<toml_edit::Array>());
    if !template.optional.is_empty() {
        new["optional"] = toml_edit::value(template.optional.iter().collect::<toml_edit::Array>());
    }
    if let Some(ttl) = template.ttl {
        new["ttl"] = toml_edit::value(format!("{ttl:#}"));
    }
    if !template.r2_buckets.is_empty() {
        new["r2_buckets"] =
            toml_edit::value(template.r2_buckets.iter().collect::<toml_edit::Array>());
    }
    if template.s3 {
        new["s3"] = toml_edit::value(true);
    }
    if let Some(ips) = &template.ips {
        new["ips"] = toml_edit::value(ips.iter().collect::<toml_edit::Array>());
    }
    templates.insert(name, toml_edit::Item::Table(new));
    let text = doc.to_string();
    Config::parse(&text).context("the new template does not make a valid config")?;
    Ok(text)
}

/// Parses durations written like "1h", "30m" or "1h 30m".
pub fn parse_duration(s: &str) -> anyhow::Result<SignedDuration> {
    let d: SignedDuration = s
        .parse()
        .with_context(|| format!("invalid duration '{s}' (try \"1h\" or \"30m\")"))?;
    if d.is_negative() || d.is_zero() {
        bail!("duration '{s}' must be positive");
    }
    Ok(d)
}

mod duration {
    use jiff::SignedDuration;
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SignedDuration, D::Error> {
        let s = String::deserialize(d)?;
        super::parse_duration(&s).map_err(serde::de::Error::custom)
    }
}

mod opt_duration {
    use jiff::SignedDuration;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Written the way it is read, as "1h" or "30m".
    pub fn serialize<S: Serializer>(d: &Option<SignedDuration>, s: S) -> Result<S::Ok, S::Error> {
        match d {
            Some(d) => s.serialize_str(&format!("{d:#}")),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<SignedDuration>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| super::parse_duration(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_integration_kinds() {
        let config = Config::parse(
            r#"
            [integrations.acme]
            type = "aws-sso"
            start_url = "https://acme.awsapps.com/start"
            region = "eu-central-1"

            [integrations.cf]
            type = "cloudflare-token"
            account_id = "abc"
            ttl = "8h"

            [integrations.cf.templates.pages]
            permissions = ["Pages Write"]
            ttl = "30m"
            "#,
        )
        .unwrap();

        let Integration::AwsSso(aws) = &config.integrations["acme"] else {
            panic!()
        };
        assert_eq!(aws.scopes, ["sso:account:access"]);

        let Integration::Cloudflare(cf) = &config.integrations["cf"] else {
            panic!()
        };
        assert_eq!(cf.ttl, SignedDuration::from_hours(8));
        assert_eq!(cf.token_type, CloudflareTokenType::User);
        assert_eq!(
            cf.templates["pages"].ttl,
            Some(SignedDuration::from_mins(30))
        );
    }

    #[test]
    fn integration_names_are_letters_digits_dots_underscores_and_hyphens() {
        let parse = |name: &str| {
            Config::parse(&format!(
                "[integrations.\"{name}\"]\ntype = \"cloudflare-token\"\n"
            ))
        };
        assert!(parse("Acme_prod-2.eu").is_ok());
        for bad in ["a/b", "a b", "a\"b", "é", "a:b", "", "-a"] {
            let err = parse(&bad.replace('"', "\\\"")).unwrap_err().to_string();
            assert!(err.contains("fob rename"), "{bad}: {err}");
        }
        let err = parse("my portal").unwrap_err().to_string();
        assert_eq!(
            err,
            "integration name 'my portal' may contain only letters, digits, '.', '_' and '-'; \
             rename it with `fob rename \"my portal\" <new-name>`"
        );
        // `fob rename` reads such a config to fix it.
        let text = "[integrations.\"my portal\"]\ntype = \"cloudflare-token\"\n\n[integrations.\"b c\"]\ntype = \"cloudflare-token\"\n";
        assert!(Config::parse_allowing_any_names(text).is_ok());
        let renamed = rename_integration(text, "my portal", "portal").unwrap();
        assert!(renamed.contains("[integrations.portal]"), "{renamed}");
        assert!(Config::parse(&renamed).is_err(), "'b c' is still to fix");
        let renamed = rename_integration(&renamed, "b c", "b-c").unwrap();
        assert!(Config::parse(&renamed).is_ok());
    }

    #[test]
    fn renames_keep_comments_order_and_subtables() {
        let text = "# mine\n[integrations.gary] # personal\ntype = \"aws-sso\"\nstart_url = \"https://a.awsapps.com/start\"\nregion = \"eu-west-1\"\n\n[integrations.gary.chained.lab]\nvia_account_id = \"1\"\nvia_role = \"A\"\nrole_arn = \"arn:aws:iam::222222222222:role/R\"\n\n[integrations.cf]\ntype = \"cloudflare-token\"\n";
        let renamed = rename_integration(text, "gary", "aws").unwrap();
        assert_eq!(
            renamed,
            text.replace("integrations.gary", "integrations.aws")
        );
        assert!(
            rename_integration(text, "gary", "cf")
                .unwrap_err()
                .to_string()
                .contains("already exists")
        );
        assert!(
            rename_integration(text, "nope", "x")
                .unwrap_err()
                .to_string()
                .contains("no integration")
        );
        for bad in ["a/b", "a b", "", "a\"b"] {
            assert!(
                rename_integration(text, "gary", bad).is_err(),
                "{bad:?} is refused"
            );
        }
    }

    #[test]
    fn adds_cloudflare_templates() {
        let text = "# mine\n[integrations.cf] # work\ntype = \"cloudflare-token\"\n\n[integrations.gary]\ntype = \"aws-sso\"\nstart_url = \"https://a.awsapps.com/start\"\nregion = \"eu-west-1\"\n";
        let template = CloudflareTemplate {
            permissions: vec!["Pages Write".into(), "Zone Read".into()],
            optional: vec![],
            ttl: Some(SignedDuration::from_mins(90)),
            ..Default::default()
        };
        let added = add_cloudflare_template(text, "cf", "pages", &template, false).unwrap();
        assert!(
            added.starts_with("# mine\n[integrations.cf] # work\n"),
            "{added}"
        );
        let config = Config::parse(&added).unwrap();
        let Integration::Cloudflare(cf) = config.integration("cf").unwrap() else {
            panic!("not cloudflare");
        };
        assert_eq!(cf.templates["pages"], template);
        let err = |r: anyhow::Result<String>| r.unwrap_err().to_string();
        assert!(
            err(add_cloudflare_template(
                &added, "cf", "pages", &template, false
            ))
            .contains("already has")
        );
        assert!(add_cloudflare_template(&added, "cf", "pages", &template, true).is_ok());
        assert!(
            err(add_cloudflare_template(text, "gary", "x", &template, false))
                .contains("not a cloudflare")
        );
        assert!(
            err(add_cloudflare_template(text, "nope", "x", &template, false))
                .contains("no integration")
        );
        for bad in ["a/b", "my pages", ""] {
            assert!(
                add_cloudflare_template(text, "cf", bad, &template, false).is_err(),
                "{bad:?} is refused"
            );
        }
    }

    #[test]
    fn durations() {
        assert_eq!(
            parse_duration("1h 30m").unwrap(),
            SignedDuration::from_mins(90)
        );
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("soon").is_err());
    }

    #[test]
    fn console_durations_are_checked_and_have_no_default() {
        let sso = |extra: &str| {
            Config::parse(&format!(
                "[integrations.a]\ntype = \"aws-sso\"\nstart_url = \"https://a.awsapps.com/start\"\nregion = \"eu-west-1\"\n{extra}"
            ))
        };
        let Integration::AwsSso(c) = &sso("").unwrap().integrations["a"] else {
            panic!()
        };
        assert_eq!(c.console_duration, None);
        let Integration::AwsSso(c) = &sso("console_duration = \"8h\"").unwrap().integrations["a"]
        else {
            panic!()
        };
        assert_eq!(c.console_duration, Some(SignedDuration::from_hours(8)));
        let error = format!("{:#}", sso("console_duration = \"13h\"").unwrap_err());
        assert!(
            error.contains("console_duration must be between 15m and 12h"),
            "{error}"
        );

        let iam = |extra: &str| {
            Config::parse(&format!(
                "[integrations.u]\ntype = \"aws-iam\"\n[integrations.u.roles.prod]\nrole_arn = \"arn:aws:iam::2:role/R\"\n{extra}"
            ))
        };
        let Integration::AwsIam(c) = &iam("console_duration = \"4h\"").unwrap().integrations["u"]
        else {
            panic!()
        };
        assert_eq!(
            c.roles["prod"].console_duration,
            Some(SignedDuration::from_hours(4))
        );
        let error = format!("{:#}", iam("console_duration = \"10m\"").unwrap_err());
        assert!(
            error.contains("roles.prod.console_duration must be between 15m and 12h"),
            "{error}"
        );
        // Chained roles cannot take it: role chaining refuses SessionDuration.
        let chained = sso(
            "[integrations.a.chained.c]\nvia_account_id = \"1\"\nvia_role = \"Admin\"\nrole_arn = \"arn:aws:iam::222222222222:role/R\"\nconsole_duration = \"1h\"",
        );
        assert!(chained.is_err());
    }

    /// An aws-sso integration in `portal_region` with `extra` keys, and one
    /// cross-partition role made of `role` keys.
    fn cross_partition(
        portal_region: &str,
        extra: &str,
        role: &str,
    ) -> anyhow::Result<CrossPartitionRole> {
        let text = format!(
            "[integrations.acme]\ntype = \"aws-sso\"\nstart_url = \"https://acme.awsapps.com/start\"\n\
             region = \"{portal_region}\"\n{extra}\n\
             [integrations.acme.cross_partition.gov-audit]\n{role}\n"
        );
        match Config::parse(&text)?.integrations.remove("acme").unwrap() {
            Integration::AwsSso(mut c) => Ok(c.cross_partition.remove("gov-audit").unwrap()),
            _ => unreachable!(),
        }
    }

    const GOV_ROLE: &str = "via_account_id = \"111111111111\"\nvia_role = \"AdministratorAccess\"\n\
        role_arn = \"arn:aws-us-gov:iam::222222222222:role/Audit\"\naudience = \"omnifob\"\n\
        region = \"us-gov-west-1\"";

    fn cross_partition_error(portal_region: &str, extra: &str, role: &str) -> String {
        format!(
            "{:#}",
            cross_partition(portal_region, extra, role).unwrap_err()
        )
    }

    #[test]
    fn cross_partition_roles_have_defaults() {
        let role = cross_partition("us-east-1", "", GOV_ROLE).unwrap();
        assert_eq!(role.signing_algorithm, SigningAlgorithm::Es384);
        assert_eq!(role.signing_algorithm.as_str(), "ES384");
        assert_eq!(role.session_name(), "omnifob");
        assert_eq!(role.duration, None);
        assert_eq!(role.duration_or_default(), SignedDuration::from_hours(1));
        assert_eq!(role.role_name(), "Audit");
        assert_eq!(role.account_id(), "222222222222");
        assert_eq!(role.partition().unwrap(), Partition::UsGov);

        // The source Region: source_region, else default_region, else the portal's.
        let portal = |extra: &str| {
            let text = format!(
                "[integrations.acme]\ntype = \"aws-sso\"\nstart_url = \"https://acme.awsapps.com/start\"\n\
                 region = \"us-east-1\"\n{extra}\n[integrations.acme.cross_partition.gov-audit]\n{GOV_ROLE}\n"
            );
            match Config::parse(&text)
                .unwrap()
                .integrations
                .remove("acme")
                .unwrap()
            {
                Integration::AwsSso(c) => c,
                _ => unreachable!(),
            }
        };
        let c = portal("");
        assert_eq!(
            c.cross_partition["gov-audit"].source_region(&c),
            "us-east-1"
        );
        let c = portal("default_region = \"eu-west-1\"");
        assert_eq!(
            c.cross_partition["gov-audit"].source_region(&c),
            "eu-west-1"
        );
        let text = format!("{GOV_ROLE}\nsource_region = \"us-west-2\"");
        let role = cross_partition("us-east-1", "default_region = \"eu-west-1\"", &text).unwrap();
        assert_eq!(role.source_region(&c), "us-west-2");

        let all = format!(
            "{GOV_ROLE}\nsigning_algorithm = \"RS256\"\nsession_name = \"me@example.com\"\nduration = \"12h\""
        );
        let role = cross_partition("us-east-1", "", &all).unwrap();
        assert_eq!(role.signing_algorithm, SigningAlgorithm::Rs256);
        assert_eq!(role.session_name(), "me@example.com");
        assert_eq!(role.duration, Some(SignedDuration::from_hours(12)));
        // Written back the way it is read (for a later `fob import`).
        let back: CrossPartitionRole = toml::from_str(&toml::to_string(&role).unwrap()).unwrap();
        assert_eq!(back, role);
    }

    #[test]
    fn cross_partition_roles_must_change_partition() {
        // A role in the source Region's own partition is AssumeRole's job.
        let same = GOV_ROLE.replace("us-gov-west-1", "us-gov-east-1");
        let error = cross_partition_error("us-gov-west-1", "", &same);
        assert!(error.contains("same as the source Region"), "{error}");
        assert!(error.contains("cross_partition.gov-audit"), "{error}");
        let commercial = "via_account_id = \"111111111111\"\nvia_role = \"A\"\n\
            role_arn = \"arn:aws:iam::222222222222:role/R\"\naudience = \"x\"\nregion = \"eu-west-1\"";
        let error = cross_partition_error("us-east-1", "", commercial);
        assert!(error.contains("chained"), "{error}");
        // The other direction works: a GovCloud portal reaching commercial.
        assert!(cross_partition("us-gov-west-1", "", commercial).is_ok());
        // Each partition can reach each other one.
        for (arn, region) in [
            ("aws-cn", "cn-north-1"),
            ("aws-eusc", "eusc-de-east-1"),
            ("aws-us-gov", "us-gov-east-1"),
        ] {
            let role = GOV_ROLE
                .replace("aws-us-gov", arn)
                .replace("us-gov-west-1", region);
            assert!(cross_partition("eu-central-1", "", &role).is_ok(), "{arn}");
        }

        // The destination Region is in the role's partition.
        let error = cross_partition_error(
            "us-east-1",
            "",
            &GOV_ROLE.replace("\"us-gov-west-1\"", "\"cn-north-1\""),
        );
        assert!(
            error.contains("region must be in the partition of role_arn")
                && error.contains("cn-north-1 is in the aws-cn partition, not aws-us-gov"),
            "{error}"
        );

        // The source Region is where the Identity Center role's credentials work.
        let error = cross_partition_error(
            "us-east-1",
            "",
            &format!("{GOV_ROLE}\nsource_region = \"cn-north-1\""),
        );
        assert!(
            error.contains("source_region cn-north-1 is in the aws-cn partition"),
            "{error}"
        );
        // ...also when it comes from default_region.
        let error =
            cross_partition_error("us-east-1", "default_region = \"us-gov-west-1\"", GOV_ROLE);
        assert!(
            error.contains("default_region (the default source_region)"),
            "{error}"
        );

        // An isolated portal Region is blamed on the portal's key.
        for role in [
            GOV_ROLE.to_string(),
            format!("{GOV_ROLE}\nsource_region = \"us-east-1\""),
        ] {
            let error = cross_partition_error("us-isob-east-1", "", &role);
            assert!(
                error.contains("cross_partition.gov-audit: the portal's region")
                    && error.contains("isolated"),
                "{error}"
            );
        }

        // Isolated partitions have no cross-partition access.
        let error = cross_partition_error(
            "us-east-1",
            "",
            &GOV_ROLE.replace("aws-us-gov:", "aws-iso-b:"),
        );
        assert!(error.contains("isolated"), "{error}");
    }

    #[test]
    fn cross_partition_keys_are_checked() {
        let with = |key: &str, value: &str| {
            let mut lines: Vec<String> = GOV_ROLE
                .lines()
                .filter(|l| !l.starts_with(&format!("{key} =")))
                .map(str::to_string)
                .collect();
            lines.push(format!("{key} = {value}"));
            cross_partition("us-east-1", "", &lines.join("\n"))
        };
        let error = |key: &str, value: &str| format!("{:#}", with(key, value).unwrap_err());

        // The audience: 1 to 255 characters, an IAM OIDC provider's client ID.
        assert!(with("audience", &format!("\"{}\"", "é".repeat(255))).is_ok());
        assert!(error("audience", "\"\"").contains("audience must be 1 to 255 characters"));
        assert!(error("audience", &format!("\"{}\"", "é".repeat(256))).contains("not 256"));
        // The session: 15 minutes to 12 hours.
        assert!(with("duration", "\"15m\"").is_ok());
        assert!(with("duration", "\"12h\"").is_ok());
        for bad in ["\"14m\"", "\"12h 1s\"", "\"13h\""] {
            assert!(
                error("duration", bad).contains("duration must be between 15m and 12h"),
                "{bad}"
            );
        }
        // The source account: 12 digits.
        for bad in ["\"11111111111\"", "\"1111111111111\"", "\"11111111111a\""] {
            assert!(error("via_account_id", bad).contains("12-digit"), "{bad}");
        }
        assert!(error("via_role", "\"\"").contains("via_role"));
        // An IAM role ARN with a 12-digit account.
        assert!(
            with(
                "role_arn",
                "\"arn:aws-us-gov:iam::222222222222:role/path/to/Audit\""
            )
            .is_ok()
        );
        for bad in [
            "\"Audit\"",
            "\"arn:aws-us-gov:iam::222222222222:user/Audit\"",
            "\"arn:aws-us-gov:sts::222222222222:role/Audit\"",
            "\"arn:aws-us-gov:iam:us-gov-west-1:222222222222:role/Audit\"",
            "\"arn:aws-us-gov:iam::2222:role/Audit\"",
            "\"arn:aws-us-gov:iam::222222222222:role/\"",
            "\"arn:aws-us-gov:iam::222222222222:role/Au dit\"",
            "\"arn:aws-us-gov:iam::222222222222:role/Au/dit/\"",
            "\"arn:aws-us-gov:iam::222222222222:role//Audit\"",
            "\"arn:aws-us-gov:iam::222222222222:role/a//b/Audit\"",
        ] {
            assert!(
                error("role_arn", bad).contains("not an IAM role ARN"),
                "{bad}"
            );
        }
        assert!(
            error("role_arn", "\"arn:aws-mars:iam::222222222222:role/R\"").contains("aws-mars")
        );
        // A role path is at most 512 characters, its slashes included.
        let path = |len: usize| {
            format!(
                "\"arn:aws-us-gov:iam::222222222222:role/{}/Audit\"",
                "p".repeat(len - 2)
            )
        };
        assert!(with("role_arn", &path(512)).is_ok());
        assert!(error("role_arn", &path(513)).contains("512"));
        assert!(error("session_name", "\"a\"").contains("session_name"));
        assert!(error("session_name", "\"a b\"").contains("session_name"));
        assert!(error("signing_algorithm", "\"HS256\"").contains("ES384"));
        assert!(error("unknown", "1").contains("unknown field"));
        // `region` is required.
        let no_region = GOV_ROLE
            .lines()
            .filter(|l| !l.starts_with("region ="))
            .collect::<Vec<_>>()
            .join("\n");
        let missing = format!(
            "{:#}",
            cross_partition("us-east-1", "", &no_region).unwrap_err()
        );
        assert!(missing.contains("missing field `region`"), "{missing}");
    }

    #[test]
    fn cross_partition_labels_and_ids_are_checked() {
        let parse = |label: &str, chained_label: &str| {
            Config::parse(&format!(
                "[integrations.acme]\ntype = \"aws-sso\"\nstart_url = \"https://acme.awsapps.com/start\"\n\
                 region = \"us-east-1\"\n\
                 [integrations.acme.chained.\"{chained_label}\"]\nvia_account_id = \"1\"\nvia_role = \"A\"\n\
                 role_arn = \"arn:aws:iam::333333333333:role/Audit\"\n\
                 [integrations.acme.cross_partition.\"{label}\"]\n{GOV_ROLE}\n"
            ))
        };
        assert!(parse("gov-audit", "audit").is_ok());
        for bad in ["gov audit", "gov/audit", ""] {
            let error = format!("{:#}", parse(bad, "audit").unwrap_err());
            assert!(
                error.contains("may contain only") || error.contains("empty"),
                "{bad}: {error}"
            );
        }
        // A chained role with the same id is refused, case aside, since
        // labels become lowercase in ids.
        for chained in ["gov-audit", "Gov-Audit"] {
            let error = format!("{:#}", parse("gov-audit", chained).unwrap_err());
            assert!(
                error.contains(&format!(
                    "chained.{chained} and cross_partition.gov-audit would both be the profile \
                     <integration>/gov-audit/Audit"
                )),
                "{error}"
            );
        }
        // So are two cross-partition labels that differ only in case.
        let error = format!(
            "{:#}",
            Config::parse(&format!(
                "[integrations.acme]\ntype = \"aws-sso\"\nstart_url = \"https://acme.awsapps.com/start\"\n\
                 region = \"us-east-1\"\n\
                 [integrations.acme.cross_partition.Gov]\n{GOV_ROLE}\n\
                 [integrations.acme.cross_partition.gov]\n{GOV_ROLE}\n"
            ))
            .unwrap_err()
        );
        assert!(
            error.contains(
                "cross_partition.Gov and cross_partition.gov would both be the profile \
                 <integration>/gov/Audit"
            ),
            "{error}"
        );
    }

    #[test]
    fn chained_roles_stay_in_the_portal_partition() {
        let parse = |portal_region: &str, role_arn: &str| {
            Config::parse(&format!(
                "[integrations.acme]\ntype = \"aws-sso\"\nstart_url = \"https://acme.awsapps.com/start\"\n\
                 region = \"{portal_region}\"\n\
                 [integrations.acme.chained.audit]\nvia_account_id = \"111111111111\"\nvia_role = \"A\"\n\
                 role_arn = \"{role_arn}\"\n"
            ))
            .map(|_| ())
            .map_err(|e| format!("{e:#}"))
        };
        assert!(parse("eu-west-1", "arn:aws:iam::222222222222:role/path/Audit").is_ok());
        assert!(
            parse(
                "us-gov-west-1",
                "arn:aws-us-gov:iam::222222222222:role/Audit"
            )
            .is_ok()
        );
        let error = parse("eu-west-1", "arn:aws-us-gov:iam::222222222222:role/Audit").unwrap_err();
        assert!(
            error.contains(
                "chained.audit: role_arn is in the aws-us-gov partition, but the portal and its \
                 roles are in aws"
            ) && error.contains("under `cross_partition` instead"),
            "{error}"
        );
        for bad in [
            "Audit",
            "arn:aws:iam::222222222222:user/Audit",
            "arn:aws:iam::2222:role/Audit",
        ] {
            let error = parse("eu-west-1", bad).unwrap_err();
            assert!(
                error.contains("chained.audit: role_arn") && error.contains("not an IAM role ARN"),
                "{bad}: {error}"
            );
        }
        assert!(
            parse("eu-west-1", "arn:aws-mars:iam::222222222222:role/Audit")
                .unwrap_err()
                .contains("aws-mars")
        );
        // An isolated portal, which `Partition` does not model, gets the
        // shape check only.
        assert!(
            parse(
                "us-isob-east-1",
                "arn:aws-iso-b:iam::222222222222:role/Audit"
            )
            .is_ok()
        );
    }

    #[test]
    fn aws_regions_are_checked_when_the_config_loads() {
        let sso = |extra: &str| {
            Config::parse(&format!(
                "[integrations.a]\ntype = \"aws-sso\"\nstart_url = \"https://a.awsapps.com/start\"\n{extra}"
            ))
            .map(|_| ())
        };
        let iam = |extra: &str| {
            Config::parse(&format!("[integrations.u]\ntype = \"aws-iam\"\n{extra}")).map(|_| ())
        };
        let error = |result: anyhow::Result<()>| format!("{:#}", result.unwrap_err());
        assert!(sso("region = \"eu-west-1\"\ndefault_region = \"us-gov-west-1\"").is_ok());
        // Isolated Regions pass the shape check; the console refuses them later.
        assert!(sso("region = \"us-isob-east-1\"").is_ok());
        let bad = "attacker.example#";
        for (key, result) in [
            ("region", sso(&format!("region = \"{bad}\""))),
            (
                "default_region",
                sso(&format!(
                    "region = \"eu-west-1\"\ndefault_region = \"{bad}\""
                )),
            ),
            (
                "chained.c.region",
                sso(&format!(
                    "region = \"eu-west-1\"\n[integrations.a.chained.c]\nvia_account_id = \"1\"\nvia_role = \"A\"\n\
                     role_arn = \"arn:aws:iam::222222222222:role/R\"\nregion = \"{bad}\""
                )),
            ),
            (
                "cross_partition.gov-audit: region",
                sso(&format!(
                    "region = \"us-east-1\"\n[integrations.a.cross_partition.gov-audit]\n{}",
                    GOV_ROLE.replace("us-gov-west-1", bad)
                )),
            ),
            (
                "cross_partition.gov-audit: source_region",
                sso(&format!(
                    "region = \"us-east-1\"\n[integrations.a.cross_partition.gov-audit]\n{GOV_ROLE}\nsource_region = \"{bad}\""
                )),
            ),
            ("region", iam(&format!("region = \"{bad}\""))),
            (
                "roles.prod.region",
                iam(&format!(
                    "[integrations.u.roles.prod]\nrole_arn = \"arn:aws:iam::2:role/R\"\nregion = \"{bad}\""
                )),
            ),
        ] {
            let error = error(result);
            assert!(
                error.contains(&format!("{key}: '{bad}' is not an AWS Region name")),
                "{key}: {error}"
            );
        }
        assert!(error(sso("region = \"EU-WEST-1\"")).contains("not an AWS Region name"));
    }

    #[test]
    fn cloudflare_types_pick_the_sign_in() {
        let cf = |text: &str| match Config::parse(text)?.integrations.remove("c").unwrap() {
            Integration::Cloudflare(c) => Ok::<_, anyhow::Error>(c),
            _ => unreachable!(),
        };
        let oauth =
            cf("[integrations.c]\ntype = \"cloudflare-oauth\"\nclient_id = \"x\"\n").unwrap();
        assert!(oauth.uses_oauth());
        assert_eq!(oauth.minting(), CloudflareTokenType::Account);
        let token = cf("[integrations.c]\ntype = \"cloudflare-token\"\n").unwrap();
        assert!(!token.uses_oauth());
        assert_eq!(token.minting(), CloudflareTokenType::User);
        assert!(cf("[integrations.c]\ntype = \"cloudflare-token\"\nclient_id = \"x\"\n").is_err());
        assert!(
            cf("[integrations.c]\ntype = \"cloudflare-oauth\"\ntoken_type = \"account\"\n")
                .is_err()
        );
        assert!(Config::parse("[integrations.c]\ntype = \"cloudflare\"\n").is_err());
    }

    #[test]
    fn integrations_open_in_the_browser_they_name() {
        let config = Config::parse(
            r#"
            [browsers.work]
            command = ["chrome", "--profile-directory=Profile 1", "{url}"]

            [integrations.acme]
            type = "aws-sso"
            start_url = "https://acme.awsapps.com/start"
            region = "eu-central-1"
            browser = "work"

            [integrations.google]
            type = "gcp"
            "#,
        )
        .unwrap();
        let browser = config.browser_for("acme").unwrap().unwrap();
        assert_eq!(
            browser.command_for("https://x.test/?a=1&b={url}"),
            (
                "chrome",
                vec![
                    "--profile-directory=Profile 1".to_string(),
                    "https://x.test/?a=1&b={url}".to_string()
                ]
            )
        );
        assert!(config.browser_for("google").unwrap().is_none());
        assert!(config.browser_for("nope").is_err());
    }

    #[test]
    fn a_browser_must_exist_and_pass_the_url() {
        let error = |text: &str| Config::parse(text).unwrap_err().to_string();
        let integration = "[integrations.c]\ntype = \"cloudflare-token\"\nbrowser = \"work\"\n";
        assert_eq!(
            error(integration),
            "integration 'c' opens in browser 'work', which [browsers] does not define (defined: none)"
        );
        for (command, message) in [
            ("[]", "command must name a program"),
            ("[\"\", \"{url}\"]", "command must name a program"),
            (
                "[\"firefox\"]",
                "command must pass the URL: put {url} in an argument",
            ),
            (
                "[\"{url}\"]",
                "{url} belongs in an argument, not in the program",
            ),
        ] {
            let text = format!("[browsers.work]\ncommand = {command}\n{integration}");
            assert_eq!(
                error(&text),
                format!("browser 'work': {message}"),
                "{command}"
            );
        }
        assert!(
            Config::parse(&format!(
                "[browsers.work]\ncommand = [\"firefox\", \"--url={{url}}\"]\n{integration}"
            ))
            .is_ok()
        );
    }
}
