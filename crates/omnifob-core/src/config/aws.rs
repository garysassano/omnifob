//! The keys of the `aws-sso`, `aws-iam` and `aws-login` integrations.

use std::collections::BTreeMap;

use jiff::SignedDuration;
use serde::{Deserialize, Serialize};

use super::{check_https_url, check_name, check_unique_ids, opt_duration};
use crate::providers::aws::partition::Partition;

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
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
    #[cfg_attr(test, schemars(with = "Option<String>"))]
    pub console_duration: Option<SignedDuration>,
    /// The browser in `[browsers]` that this integration's sign-ins and
    /// consoles open in; by default the system's.
    #[serde(default)]
    pub browser: Option<String>,
}

impl AwsSsoConfig {
    pub(super) fn validate(&self) -> Result<(), String> {
        check_https_url("start_url", &self.start_url)?;
        check_region("region", &self.region)?;
        if let Some(region) = &self.default_region {
            check_region("default_region", region)?;
        }
        if self.scopes.is_empty() || self.scopes.iter().any(|s| s.trim().is_empty()) {
            return Err(
                "scopes must name at least one scope, and none may be empty; leave it out for                  the default, [\"sso:account:access\"]"
                    .to_string(),
            );
        }
        for (label, role) in &self.chained {
            if let Some(region) = &role.region {
                check_region(&format!("chained.{label}.region"), region)?;
            }
            role.validate(&self.region)
                .map_err(|e| format!("chained.{label}: {e}"))?;
        }
        for (label, role) in &self.cross_partition {
            role.validate(label, self)
                .map_err(|e| format!("cross_partition.{label}: {e}"))?;
        }
        self.check_profile_ids()?;
        check_console_duration("console_duration", self.console_duration)
    }

    /// Fails when two configured roles, chained or cross-partition, would get
    /// the same profile id, which the config alone shows: labels become
    /// lowercase in ids, so `Prod` and `prod` collide. Collisions with
    /// Identity Center roles appear only at discovery.
    fn check_profile_ids(&self) -> Result<(), String> {
        let chained = self
            .chained
            .iter()
            .map(|(label, role)| ("chained", label, role.role_name()));
        let cross = self
            .cross_partition
            .iter()
            .map(|(label, role)| ("cross_partition", label, role.role_name()));
        check_unique_ids(chained.chain(cross))
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

/// Fails unless `value` is a 12-digit AWS account ID, naming the key.
fn check_account_id(key: &str, value: &str) -> Result<(), String> {
    if value.len() != 12 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{key} '{value}' must be a 12-digit AWS account ID"));
    }
    Ok(())
}

/// Fails unless `region` is in the partition of `role_arn`, when both are
/// in partitions omnifob models: a role's credentials work only in its own
/// partition, and STS is called in that Region.
fn check_region_partition(key: &str, region: &str, role_arn: &str) -> Result<(), String> {
    let (Ok(role), Ok(of_region)) = (Partition::of_arn(role_arn), Partition::of_region(region))
    else {
        return Ok(());
    };
    if role != of_region {
        return Err(format!(
            "{key} {region} is in the {of_region} partition, but role_arn is in {role}"
        ));
    }
    Ok(())
}

/// Fails unless `region` is shaped like an AWS Region, naming the key.
/// Regions become part of host names, so a malformed one is refused when
/// the config loads rather than when a command first uses it.
fn check_region(key: &str, region: &str) -> Result<(), String> {
    crate::providers::aws::partition::check_region_name(region).map_err(|e| format!("{key}: {e}"))
}

/// Fails unless a configured console session length is one the federation
/// endpoint accepts.
fn check_console_duration(key: &str, duration: Option<SignedDuration>) -> Result<(), String> {
    match duration {
        Some(d) if !crate::providers::aws::console::CONSOLE_SESSION.contains(&d) => {
            Err(format!("{key} must be between 15m and 12h"))
        }
        _ => Ok(()),
    }
}

/// A role assumed with the credentials of an Identity Center role.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
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
    #[cfg_attr(test, schemars(with = "Option<String>"))]
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

    /// The checks `[integrations.<name>.chained.<label>]` gets when the
    /// config loads, for a portal in `portal_region`; `fob import aws`
    /// skips a role that fails them, with the reason. The shape of `region`
    /// is checked by the caller, which names the whole key.
    pub(crate) fn validate(&self, portal_region: &str) -> Result<(), String> {
        check_account_id("via_account_id", &self.via_account_id)?;
        if self.via_role.trim().is_empty() {
            return Err("via_role must name the Identity Center role (permission set)".into());
        }
        check_chained_role_arn(&self.role_arn, portal_region)?;
        if let Some(region) = &self.region {
            check_region("region", region)?;
            check_region_partition("region", region, &self.role_arn)?;
        }
        if let Some(name) = &self.session_name {
            check_session_name(name)?;
        }
        if let Some(d) = self.duration
            && !(SignedDuration::from_mins(15)..=SignedDuration::from_hours(1)).contains(&d)
        {
            return Err(
                "duration must be between 15m and 1h: AWS caps role-chaining sessions at one hour"
                    .to_string(),
            );
        }
        Ok(())
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
#[cfg_attr(test, derive(schemars::JsonSchema))]
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
    #[cfg_attr(test, schemars(with = "Option<String>"))]
    pub duration: Option<SignedDuration>,
}

/// The algorithm `GetWebIdentityToken` signs the token with
/// (`SigningAlgorithm`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
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
        check_account_id("via_account_id", &self.via_account_id)?;
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
/// set), and assumes `roles` with that session, which STS counts as role
/// chaining.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
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
    #[cfg_attr(test, schemars(with = "Option<String>"))]
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
    pub(super) fn validate(&self) -> Result<(), String> {
        if let Some(region) = &self.region {
            check_region("region", region)?;
        }
        for (label, role) in &self.roles {
            if let Some(region) = &role.region {
                check_region(&format!("roles.{label}.region"), region)?;
            }
            role.validate(self.region.as_deref())
                .map_err(|e| format!("roles.{label}: {e}"))?;
        }
        if let Some(d) = self.session_duration
            && !(SignedDuration::from_mins(15)..=SignedDuration::from_hours(36)).contains(&d)
        {
            return Err("session_duration must be between 15m and 36h".to_string());
        }
        for (label, role) in &self.roles {
            if let Some(d) = role.duration
                && !(SignedDuration::from_mins(15)..=SignedDuration::from_hours(1)).contains(&d)
            {
                return Err(format!(
                    "roles.{label}.duration must be between 15m and 1h: STS counts a role assumed with the user's session as role chaining"
                ));
            }
            check_console_duration(
                &format!("roles.{label}.console_duration"),
                role.console_duration,
            )?;
        }
        self.check_profile_ids()
    }

    /// Fails when two roles, or a role and the user's session profile
    /// (`<account>/session`), would get the same profile id. Without
    /// `account` the session's id holds the account ID, known only at
    /// discovery, which checks it then.
    fn check_profile_ids(&self) -> Result<(), String> {
        let session = self
            .account
            .as_ref()
            .map(|account| ("account", account, "session"));
        let roles = self
            .roles
            .iter()
            .map(|(label, role)| ("roles", label, role.role_name()));
        check_unique_ids(session.into_iter().chain(roles))
    }
}

/// AWS console credentials (`type = "aws-login"`), as `aws login` gets
/// them: the browser signs in with a console session (an IAM user, the root
/// user or a federated role), and omnifob keeps a refresh token that renews
/// 15 minute credentials for up to 12 hours, with no access key stored.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct AwsLoginConfig {
    /// The Region signed in through; the refresh token works only there. It
    /// is also exported as `AWS_REGION` unless `default_region` is set.
    pub region: String,
    /// Exported as `AWS_REGION` and `AWS_DEFAULT_REGION` instead of `region`.
    #[serde(default)]
    pub default_region: Option<String>,
    /// Middle segment of the profile's id; defaults to the account ID.
    #[serde(default)]
    pub account: Option<String>,
    /// The browser in `[browsers]` that this integration's sign-ins and
    /// consoles open in; by default the system's.
    #[serde(default)]
    pub browser: Option<String>,
}

impl AwsLoginConfig {
    pub(super) fn validate(&self) -> Result<(), String> {
        check_region("region", &self.region)?;
        if let Some(region) = &self.default_region {
            check_region("default_region", region)?;
        }
        Ok(())
    }
}

/// A role assumed with an IAM user's session.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
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
    /// Session length, 15 minutes to 1 hour (STS counts a role assumed with
    /// the user's `GetSessionToken` session as role chaining, which it caps
    /// at one hour); defaults to one hour.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_duration"
    )]
    #[cfg_attr(test, schemars(with = "Option<String>"))]
    pub duration: Option<SignedDuration>,
    /// How long `fob console` sessions last (`SessionDuration`), 15 minutes
    /// to 12 hours and shorter than the role's maximum session duration.
    /// Unset, a console session lasts as long as the role's credentials.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "opt_duration"
    )]
    #[cfg_attr(test, schemars(with = "Option<String>"))]
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

    /// The checks `[integrations.<name>.roles.<label>]` gets when the config
    /// loads, for a user whose STS Region is `user_region` (us-east-1 when
    /// unset); `fob import aws` skips a role that fails them, with the
    /// reason. The shape of `region` is checked by the caller, which names
    /// the whole key.
    pub(crate) fn validate(&self, user_region: Option<&str>) -> Result<(), String> {
        check_role_arn(&self.role_arn)?;
        // The role is assumed with the user's session, in the user's
        // partition; AssumeRole cannot leave it. A user in an isolated
        // partition, which `Partition` does not model, gets the shape check
        // only, as a chained role's portal does.
        let sts_region = user_region.unwrap_or("us-east-1");
        if let Ok(user) = Partition::of_region(sts_region) {
            let role = Partition::of_arn(&self.role_arn).map_err(|e| format!("role_arn: {e:#}"))?;
            if user != role {
                return Err(format!(
                    "role_arn is in the {role} partition, but the user's STS Region {sts_region} is \
                     in {user}; AssumeRole cannot cross partitions"
                ));
            }
        }
        if let Some(region) = &self.region {
            check_region("region", region)?;
            check_region_partition("region", region, &self.role_arn)?;
        }
        if let Some(name) = &self.session_name {
            check_session_name(name)?;
        }
        Ok(())
    }
}

fn default_sso_scopes() -> Vec<String> {
    vec!["sso:account:access".to_string()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::parse_error;
    use crate::config::*;

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
                "[integrations.u]\ntype = \"aws-iam\"\n[integrations.u.roles.prod]\nrole_arn = \"arn:aws:iam::222222222222:role/R\"\n{extra}"
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
            "[integrations.a.chained.c]\nvia_account_id = \"111111111111\"\nvia_role = \"Admin\"\nrole_arn = \"arn:aws:iam::222222222222:role/R\"\nconsole_duration = \"1h\"",
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
                 [integrations.acme.chained.\"{chained_label}\"]\nvia_account_id = \"111111111111\"\nvia_role = \"A\"\n\
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
                    "region = \"eu-west-1\"\n[integrations.a.chained.c]\nvia_account_id = \"111111111111\"\nvia_role = \"A\"\n\
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
                    "[integrations.u.roles.prod]\nrole_arn = \"arn:aws:iam::222222222222:role/R\"\nregion = \"{bad}\""
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

    const SSO: &str = "[integrations.a]\ntype = \"aws-sso\"\nstart_url = \"https://a.awsapps.com/start\"\nregion = \"eu-west-1\"\n";
    const CHAINED: &str = "via_account_id = \"111111111111\"\nvia_role = \"Admin\"\nrole_arn = \"arn:aws:iam::222222222222:role/R\"\n";

    #[test]
    fn aws_sso_keys_are_checked() {
        let with = |extra: &str| Config::parse(&format!("{SSO}{extra}"));
        let chained = |keys: &str| with(&format!("[integrations.a.chained.c]\n{CHAINED}{keys}"));
        let error = |r: anyhow::Result<Config>| format!("{:#}", r.unwrap_err());
        assert!(chained("duration = \"15m\"\nsession_name = \"me@example.com\"").is_ok());
        for (keys, message) in [
            (
                "duration = \"61m\"",
                "chained.c: duration must be between 15m and 1h",
            ),
            (
                "duration = \"10m\"",
                "chained.c: duration must be between 15m and 1h",
            ),
            (
                "session_name = \"a b\"",
                "chained.c: session_name 'a b' must be",
            ),
            (
                "region = \"us-gov-west-1\"",
                "chained.c: region us-gov-west-1 is in the aws-us-gov partition",
            ),
        ] {
            let error = error(chained(keys));
            assert!(error.contains(message), "{keys}: {error}");
        }
        for (key, value, message) in [
            (
                "via_account_id",
                "\"1\"",
                "chained.c: via_account_id '1' must be a 12-digit",
            ),
            ("via_role", "\"\"", "chained.c: via_role must name"),
        ] {
            let keys = CHAINED
                .lines()
                .filter(|l| !l.starts_with(key))
                .chain([format!("{key} = {value}").as_str()])
                .collect::<Vec<_>>()
                .join("\n");
            let error = error(with(&format!("[integrations.a.chained.c]\n{keys}\n")));
            assert!(error.contains(message), "{key}: {error}");
        }
        let start_url = |url: &str| {
            Config::parse(&SSO.replace("https://a.awsapps.com/start", url))
                .map_err(|e| format!("{e:#}"))
        };
        assert!(
            start_url("http://a.awsapps.com/start")
                .unwrap_err()
                .contains("start_url 'http://a.awsapps.com/start' must be an https:// URL")
        );
        assert!(
            start_url("a.awsapps.com/start")
                .unwrap_err()
                .contains("start_url 'a.awsapps.com/start' is not a URL")
        );
        assert!(error(with("scopes = []")).contains("scopes must name at least one scope"));
        assert!(error(with("scopes = [\"\"]")).contains("scopes must name"));

        // Two chained labels that differ only in case would share an id.
        let error = error(with(&format!(
            "[integrations.a.chained.Prod]\n{CHAINED}[integrations.a.chained.prod]\n{CHAINED}"
        )));
        assert!(
            error.contains(
                "chained.Prod and chained.prod would both be the profile <integration>/prod/R"
            ),
            "{error}"
        );
    }

    #[test]
    fn aws_iam_keys_are_checked() {
        let iam = |extra: &str, role: &str| {
            Config::parse(&format!(
                "[integrations.u]\ntype = \"aws-iam\"\n{extra}\n[integrations.u.roles.prod]\n{role}\n"
            ))
            .map_err(|e| format!("{e:#}"))
        };
        let arn = "role_arn = \"arn:aws:iam::222222222222:role/R\"";
        assert!(
            iam(
                "",
                &format!("{arn}\nsession_name = \"me\"\nregion = \"eu-west-1\"")
            )
            .is_ok()
        );
        for (extra, role, message) in [
            (
                "",
                "role_arn = \"R\"".to_string(),
                "roles.prod: role_arn 'R' is not an IAM role ARN",
            ),
            (
                "",
                "role_arn = \"arn:aws:iam::2:role/R\"".to_string(),
                "the account must be 12 digits",
            ),
            (
                "",
                format!("{arn}\nsession_name = \"x\""),
                "roles.prod: session_name 'x'",
            ),
            (
                "",
                format!("{arn}\nregion = \"cn-north-1\""),
                "roles.prod: region cn-north-1 is in the aws-cn partition, but role_arn is in aws",
            ),
            (
                "region = \"us-gov-west-1\"",
                arn.to_string(),
                "roles.prod: role_arn is in the aws partition, but the user's STS Region us-gov-west-1 is in aws-us-gov",
            ),
            (
                "account = \"prod\"",
                "role_arn = \"arn:aws:iam::222222222222:role/session\"".to_string(),
                "account.prod and roles.prod would both be the profile <integration>/prod/session",
            ),
        ] {
            let error = iam(extra, &role).unwrap_err();
            assert!(error.contains(message), "{role}: {error}");
        }
        // A GovCloud user assumes GovCloud roles.
        assert!(
            iam(
                "region = \"us-gov-west-1\"",
                "role_arn = \"arn:aws-us-gov:iam::222222222222:role/R\""
            )
            .is_ok()
        );
        let error = parse_error(&format!(
            "[integrations.u]\ntype = \"aws-iam\"\n[integrations.u.roles.A]\n{arn}\n[integrations.u.roles.a]\n{arn}\n"
        ));
        assert!(
            error.contains("roles.A and roles.a would both be"),
            "{error}"
        );
    }
}
