//! AWS STS, shared by every AWS integration: clients, `AssumeRole`,
//! `GetCallerIdentity`, and STS credentials as the variables AWS tools read.

use std::collections::BTreeMap;

use anyhow::{Context, anyhow};
use aws_sdk_sts::error::ProvideErrorMetadata;
use jiff::{SignedDuration, Timestamp};

use super::service_endpoint;
use crate::Credentials;

/// The variable the AWS CLI and SDKs read for STS's endpoint, a VPC
/// endpoint without private DNS for example.
pub(crate) const STS_ENDPOINT_VARIABLE: &str = "AWS_ENDPOINT_URL_STS";

/// An STS error code without the `Exception` suffix that some codes carry
/// on the wire and in the SDK model and others do not.
pub(crate) fn sts_code(code: Option<&str>) -> Option<&str> {
    code.map(|c| c.strip_suffix("Exception").unwrap_or(c))
}

/// `duration` in whole seconds, as STS takes `DurationSeconds`. A fraction
/// of a second rounds up, so a length checked against a minimum never falls
/// below it.
pub(crate) fn whole_seconds(duration: SignedDuration) -> anyhow::Result<i32> {
    let secs = duration.as_secs() + i64::from(duration.subsec_nanos() > 0);
    Ok(secs.try_into()?)
}

/// The shortest session STS hands out.
pub(crate) const SESSION_MIN: SignedDuration = SignedDuration::from_mins(15);

/// AWS caps sessions of roles assumed with role credentials at one hour.
pub(crate) const CHAINED_MAX: SignedDuration = SignedDuration::from_hours(1);

/// The longest role session AWS allows, when the role's maximum session
/// duration allows it.
pub(crate) const ROLE_MAX: SignedDuration = SignedDuration::from_hours(12);

/// An STS `AssumeRole` call.
pub(crate) struct RoleRequest<'a> {
    pub role_arn: &'a str,
    pub session_name: Option<&'a str>,
    pub external_id: Option<&'a str>,
    /// The MFA device whose code the role's trust policy requires.
    pub mfa_serial: Option<&'a str>,
    pub duration: SignedDuration,
    /// The profile, named when asking for an MFA code.
    pub profile_id: &'a str,
}

/// An STS client authenticated with `creds`, temporary (with a session token)
/// or an IAM user's access key (without).
pub(crate) fn sts_client(creds: &Credentials, region: &str) -> anyhow::Result<aws_sdk_sts::Client> {
    let get = |k: &str| {
        creds
            .env
            .get(k)
            .cloned()
            .with_context(|| format!("{k} missing from the credentials"))
    };
    let provider = aws_sdk_sts::config::Credentials::new(
        get("AWS_ACCESS_KEY_ID")?,
        get("AWS_SECRET_ACCESS_KEY")?,
        creds.env.get("AWS_SESSION_TOKEN").cloned(),
        None,
        "omnifob",
    );
    let mut config = aws_sdk_sts::Config::builder()
        .region(aws_sdk_sts::config::Region::new(region.to_string()))
        .credentials_provider(provider)
        .behavior_version(aws_sdk_sts::config::BehaviorVersion::latest());
    if let Some(url) = service_endpoint(STS_ENDPOINT_VARIABLE) {
        config = config.endpoint_url(url);
    }
    Ok(aws_sdk_sts::Client::from_conf(config.build()))
}

/// An STS client with no credentials provider, for calls that carry their
/// own proof of identity (`AssumeRoleWithWebIdentity`), so the request is
/// not signed and no AWS credentials leave this machine with it.
pub(crate) fn unsigned_sts_client(region: &str) -> aws_sdk_sts::Client {
    let mut config = aws_sdk_sts::Config::builder()
        .region(aws_sdk_sts::config::Region::new(region.to_string()))
        .behavior_version(aws_sdk_sts::config::BehaviorVersion::latest());
    if let Some(url) = service_endpoint(STS_ENDPOINT_VARIABLE) {
        config = config.endpoint_url(url);
    }
    aws_sdk_sts::Client::from_conf(config.build())
}

/// Whom credentials act as, from STS `GetCallerIdentity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerIdentity {
    /// The ARN, `unknown` if STS sent none.
    pub arn: String,
    /// The account the credentials belong to, as STS states it.
    pub account: Option<String>,
}

/// Whom these credentials act as, from STS GetCallerIdentity.
pub async fn caller_identity(creds: &Credentials, region: &str) -> anyhow::Result<CallerIdentity> {
    let identity = sts_client(creds, region)?
        .get_caller_identity()
        .send()
        .await
        .map_err(|e| anyhow!("{}", aws_sdk_sts::error::DisplayErrorContext(&e)))?;
    Ok(CallerIdentity {
        arn: identity.arn().unwrap_or("unknown").to_string(),
        account: identity
            .account()
            .filter(|a| !a.is_empty())
            .map(str::to_string),
    })
}

/// STS refused the credentials a call was signed with, as expired
/// (`ExpiredToken`) or unknown (`InvalidClientTokenId`, a revoked session):
/// new ones may work where retrying these cannot.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(crate) struct CredentialsRejected(pub String);

pub(crate) async fn assume_role(
    source: &Credentials,
    request: &RoleRequest<'_>,
    sts_region: &str,
    export_region: Option<&str>,
) -> anyhow::Result<Credentials> {
    let sts = sts_client(source, sts_region)?;
    let mut call = sts
        .assume_role()
        .role_arn(request.role_arn)
        .role_session_name(
            request
                .session_name
                .unwrap_or(super::default_session_name()),
        )
        .set_external_id(request.external_id.map(str::to_string))
        .duration_seconds(whole_seconds(request.duration)?);
    if let Some(serial) = request.mfa_serial {
        call = call
            .serial_number(serial)
            .token_code(crate::prompt::mfa_code(serial, request.profile_id)?);
    }
    let assumed = call.send().await.map_err(|e| {
        let message = format!(
            "assuming {}: {}",
            request.role_arn,
            aws_sdk_sts::error::DisplayErrorContext(&e)
        );
        if matches!(
            sts_code(e.code()),
            Some("ExpiredToken" | "InvalidClientTokenId")
        ) {
            anyhow::Error::new(CredentialsRejected(message))
        } else {
            anyhow!(message)
        }
    })?;
    from_sts(
        assumed.credentials().context("no credentials returned")?,
        export_region,
    )
}

/// Temporary credentials from STS as the variables AWS tools read.
pub(crate) fn from_sts(
    creds: &aws_sdk_sts::types::Credentials,
    export_region: Option<&str>,
) -> anyhow::Result<Credentials> {
    let expires_at = Timestamp::from_second(creds.expiration().secs())?;
    let mut env = BTreeMap::new();
    let mut put = |k: &str, v: &str| {
        env.insert(k.to_string(), v.to_string());
    };
    put("AWS_ACCESS_KEY_ID", creds.access_key_id());
    put("AWS_SECRET_ACCESS_KEY", creds.secret_access_key());
    put("AWS_SESSION_TOKEN", creds.session_token());
    put("AWS_CREDENTIAL_EXPIRATION", &expires_at.to_string());
    if let Some(region) = export_region {
        put("AWS_REGION", region);
        put("AWS_DEFAULT_REGION", region);
    }
    Ok(Credentials {
        env,
        expires_at: Some(expires_at),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_lengths_round_up_to_whole_seconds() {
        let d = |s: i64, n: i32| SignedDuration::new(s, n);
        assert_eq!(whole_seconds(d(900, 0)).unwrap(), 900);
        assert_eq!(whole_seconds(d(900, 1)).unwrap(), 901);
        assert_eq!(whole_seconds(d(43_199, 500_000_000)).unwrap(), 43_200);
        assert!(whole_seconds(SignedDuration::from_secs(i64::from(i32::MAX) + 1)).is_err());
    }
}
