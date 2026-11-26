//! Roles in another AWS partition, reached from an IAM Identity Center role
//! through outbound identity federation: STS `GetWebIdentityToken` in the
//! source partition, then `AssumeRoleWithWebIdentity` in the destination.

use anyhow::{Context, anyhow};
use aws_sdk_sts::error::ProvideErrorMetadata;
use jiff::SignedDuration;
use serde::Deserialize;

use super::sso::credentials;
use super::sts::{from_sts, sts_client, sts_code, unsigned_sts_client, whole_seconds};
use crate::config::{AwsSsoConfig, CrossPartitionRole};
use crate::{Credentials, Result};

/// How long a web identity token lives, in seconds: the least STS allows.
/// It is exchanged at once, so a minute is plenty; it stays within any
/// `sts:DurationSeconds` limit an administrator sets, and it never outlives
/// the Identity Center role's credentials, which are new for each request.
pub const WEB_IDENTITY_TOKEN_SECONDS: i32 = 60;

/// A JWT from `GetWebIdentityToken`. It is a bearer credential for its
/// lifetime, so it is never logged, cached or written anywhere, and `Debug`
/// does not show it.
struct WebIdentityToken(String);

impl std::fmt::Debug for WebIdentityToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WebIdentityToken(<redacted>)")
    }
}

/// The claims of a web identity token that an administrator needs for the
/// destination's OIDC provider and trust policy. Nothing else is read from
/// the token, and these are only ever displayed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct TokenClaims {
    /// The source account's issuer URL.
    #[serde(default)]
    pub iss: Option<String>,
    /// The principal that requested the token; for an Identity Center role,
    /// the reserved role's ARN.
    #[serde(default)]
    pub sub: Option<String>,
    /// The audience, a string or a list.
    #[serde(default)]
    pub aud: Option<serde_json::Value>,
}

impl TokenClaims {
    /// Reads `iss`, `sub` and `aud` from a JWT's payload. The signature is
    /// not checked: the claims are for display only.
    pub fn of(token: &str) -> Option<Self> {
        crate::oauth::decode_jwt_payload(token).ok()
    }
}

impl std::fmt::Display for TokenClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let aud = match &self.aud {
            None => "(none)".to_string(),
            Some(serde_json::Value::String(aud)) => aud.clone(),
            Some(serde_json::Value::Array(auds)) => auds
                .iter()
                .map(|a| a.as_str().map_or_else(|| a.to_string(), str::to_string))
                .collect::<Vec<_>>()
                .join(", "),
            Some(other) => other.to_string(),
        };
        write!(
            f,
            "iss {}, sub {}, aud {aud}",
            self.iss.as_deref().unwrap_or("(none)"),
            self.sub.as_deref().unwrap_or("(none)")
        )
    }
}

/// Credentials for a role in another partition: the Identity Center role's
/// credentials, then STS `GetWebIdentityToken` with them in the source
/// Region for a token with one audience that lasts a minute, then STS
/// `AssumeRoleWithWebIdentity` in the destination Region, unsigned, with
/// that token. The destination Region is exported.
///
/// `ttl` overrides the role's `duration`. A `SessionDurationEscalation`
/// from the token request is retried once with new source credentials, and
/// an `ExpiredToken` from the exchange once with a new token. The SDK
/// itself retries an `IDPCommunicationError`, which it models as a server
/// error, with the same token. Errors name who has to act; those from the exchange show the
/// token's `iss`, `sub` and `aud`.
pub async fn cross_partition_credentials(
    integration: &str,
    config: &AwsSsoConfig,
    label: &str,
    ttl: Option<SignedDuration>,
) -> Result<Credentials> {
    let role = config.cross_partition.get(label).with_context(|| {
        format!("no cross-partition role '{label}' in integration '{integration}'; run `fob sync`")
    })?;
    let duration = ttl.unwrap_or_else(|| role.duration_or_default());
    if !CrossPartitionRole::DURATION.contains(&duration) {
        return Err(anyhow!(
            "a cross-partition role's session lasts 15 minutes to 12 hours, and at most the \
             role's maximum session duration"
        )
        .into());
    }
    let duration_seconds = whole_seconds(duration)?;
    let source_region = role.source_region(config);
    let destination = exchange_client(role);

    let source = credentials(integration, config, &role.via_account_id, &role.via_role).await?;
    let mut sts = sts_client(&source, source_region)?;
    let mut renewed_source = false;
    let mut retried_exchange = false;
    loop {
        // Signed with the Identity Center role's credentials. The SDK
        // resolves the Regional endpoint (`sts.<region>.<domain>`), which
        // the call needs: the global endpoint does not serve it.
        let requested = sts
            .get_web_identity_token()
            .audience(&role.audience)
            .signing_algorithm(role.signing_algorithm.as_str())
            .duration_seconds(WEB_IDENTITY_TOKEN_SECONDS)
            .send()
            .await;
        let token = match requested {
            Ok(response) => WebIdentityToken(
                response
                    .web_identity_token()
                    .context("no web identity token returned")?
                    .to_string(),
            ),
            Err(e)
                if !renewed_source && sts_code(e.code()) == Some("SessionDurationEscalation") =>
            {
                renewed_source = true;
                let source =
                    credentials(integration, config, &role.via_account_id, &role.via_role).await?;
                sts = sts_client(&source, source_region)?;
                continue;
            }
            Err(e) => return Err(token_error(&e, role, source_region).into()),
        };
        let claims = TokenClaims::of(&token.0);
        if let Some(claims) = &claims {
            tracing::debug!("web identity token for {}: {claims}", role.role_arn);
        }
        let exchanged = destination
            .assume_role_with_web_identity()
            .role_arn(&role.role_arn)
            .role_session_name(role.session_name())
            .web_identity_token(&token.0)
            .duration_seconds(duration_seconds)
            .send()
            .await;
        drop(token);
        match exchanged {
            Ok(assumed) => {
                return Ok(from_sts(
                    assumed.credentials().context("no credentials returned")?,
                    Some(&role.region),
                )?);
            }
            Err(e) if !retried_exchange && sts_code(e.code()) == Some("ExpiredToken") => {
                retried_exchange = true;
            }
            Err(e) => {
                return Err(exchange_error(&e, role, duration_seconds, claims.as_ref()).into());
            }
        }
    }
}

/// What a refused token request means, and who has to act.
fn token_error(
    e: &aws_sdk_sts::error::SdkError<
        aws_sdk_sts::operation::get_web_identity_token::GetWebIdentityTokenError,
    >,
    role: &CrossPartitionRole,
    region: &str,
) -> anyhow::Error {
    let (account, via_role) = (&role.via_account_id, &role.via_role);
    let detail = aws_sdk_sts::error::DisplayErrorContext(e);
    match sts_code(e.code()) {
        Some("OutboundWebIdentityFederationDisabled") => anyhow!(
            "outbound identity federation is not enabled in the source account {account}: an \
             administrator of that account must enable it (IAM account settings, or `aws iam \
             enable-outbound-web-identity-federation`) before {via_role} can request a web \
             identity token"
        ),
        Some("AccessDenied") => anyhow!(
            "{via_role} in {account} may not request a web identity token for the audience \
             '{}', signed with {}, lasting {WEB_IDENTITY_TOKEN_SECONDS} seconds: an \
             administrator of the source account must allow sts:GetWebIdentityToken in the \
             permission set {via_role}, with conditions that admit these values \
             (sts:IdentityTokenAudience, sts:SigningAlgorithm, sts:DurationSeconds) ({detail})",
            role.audience,
            role.signing_algorithm.as_str()
        ),
        Some("SessionDurationEscalation") => anyhow!(
            "STS refused a {WEB_IDENTITY_TOKEN_SECONDS}-second web identity token because the \
             credentials of {via_role} in {account} expire sooner, even new ones; an \
             administrator of the source account should check the permission set's session \
             duration ({detail})"
        ),
        _ => anyhow!(
            "requesting a web identity token in {region} as {via_role} in {account}: {detail}"
        ),
    }
}

/// What a refused exchange means, and who has to act. A refused token is
/// described by its `iss`, `sub` and `aud`, the values the destination's
/// OIDC provider and trust policy must match.
fn exchange_error(
    e: &aws_sdk_sts::error::SdkError<
        aws_sdk_sts::operation::assume_role_with_web_identity::AssumeRoleWithWebIdentityError,
    >,
    role: &CrossPartitionRole,
    duration_seconds: i32,
    claims: Option<&TokenClaims>,
) -> anyhow::Error {
    let (arn, region) = (&role.role_arn, &role.region);
    let detail = aws_sdk_sts::error::DisplayErrorContext(e);
    let token = match claims {
        Some(claims) => format!("the token has {claims}"),
        None => "the token's claims could not be read".to_string(),
    };
    match sts_code(e.code()) {
        Some("AccessDenied" | "InvalidIdentityToken" | "IDPRejectedClaim") => anyhow!(
            "{arn} does not accept the web identity token from {} in {}: an administrator of \
             the destination account must check that its IAM OIDC provider has the source \
             account's issuer URL and '{}' as a client ID, and that the role's trust policy \
             allows sts:AssumeRoleWithWebIdentity for this token; {token} ({detail})",
            role.via_role,
            role.via_account_id,
            role.audience
        ),
        Some("IDPCommunicationError") => anyhow!(
            "STS in {region} could not reach the source account's issuer to check the web \
             identity token, even after retrying; try again later ({detail})"
        ),
        Some("ExpiredToken") => anyhow!(
            "STS in {region} found the web identity token expired or not valid, twice, although \
             each one was exchanged as soon as it was issued: the source STS makes it expire \
             {WEB_IDENTITY_TOKEN_SECONDS} seconds after issuing it, so either more time than \
             that passed between the two calls (a slow network, or the SDK's retries with \
             backoff) or the token is not valid; try again later ({detail})"
        ),
        Some("ValidationError") if e.message().is_some_and(|m| m.contains("DurationSeconds")) => {
            anyhow!(
                "{arn} does not allow sessions of {duration_seconds} seconds: lower its \
                 `duration` (or --ttl), or ask an administrator of the destination account to \
                 raise the role's maximum session duration ({detail})"
            )
        }
        _ => anyhow!("assuming {arn} with a web identity token in {region}: {detail}"),
    }
}

/// The STS client a cross-partition role's token is exchanged through: the
/// destination Region's, where the role's partition is, and unsigned.
fn exchange_client(role: &CrossPartitionRole) -> aws_sdk_sts::Client {
    unsigned_sts_client(&role.region)
}

#[cfg(test)]
mod tests {
    use super::super::service_endpoint;
    use super::super::sts::STS_ENDPOINT_VARIABLE;
    use super::*;

    /// Records the URL a request would go to, and stops it there.
    #[derive(Debug, Default, Clone)]
    struct StopBeforeSending(std::sync::Arc<std::sync::Mutex<Option<(String, bool)>>>);

    impl aws_sdk_sts::config::Intercept for StopBeforeSending {
        fn name(&self) -> &'static str {
            "StopBeforeSending"
        }

        fn read_before_transmit(
            &self,
            context: &aws_sdk_sts::config::interceptors::BeforeTransmitInterceptorContextRef<'_>,
            _: &aws_sdk_sts::config::RuntimeComponents,
            _: &mut aws_sdk_sts::config::ConfigBag,
        ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let request = context.request();
            let signed = request.headers().contains_key("authorization");
            *self.0.lock().unwrap() = Some((request.uri().to_string(), signed));
            Err("stopped before sending".into())
        }
    }

    /// `GetWebIdentityToken` is not served by the global STS endpoint, so
    /// the client must resolve the Regional one, in us-east-1 too.
    #[tokio::test]
    async fn web_identity_tokens_are_requested_from_the_regional_endpoint() {
        assert!(
            service_endpoint(STS_ENDPOINT_VARIABLE).is_none(),
            "OMNIFOB_AWS_ENDPOINT and AWS_ENDPOINT_URL_STS must be unset for this test"
        );
        let mut creds = Credentials::default();
        for (k, v) in [
            ("AWS_ACCESS_KEY_ID", "ASIAEXAMPLE"),
            ("AWS_SECRET_ACCESS_KEY", "secret"),
            ("AWS_SESSION_TOKEN", "token"),
        ] {
            creds.env.insert(k.into(), v.into());
        }
        for (region, host) in [
            ("us-east-1", "https://sts.us-east-1.amazonaws.com"),
            ("eu-west-1", "https://sts.eu-west-1.amazonaws.com"),
            ("us-gov-west-1", "https://sts.us-gov-west-1.amazonaws.com"),
            ("cn-north-1", "https://sts.cn-north-1.amazonaws.com.cn"),
        ] {
            let stop = StopBeforeSending::default();
            let result = sts_client(&creds, region)
                .unwrap()
                .get_web_identity_token()
                .audience("omnifob")
                .signing_algorithm("ES384")
                .duration_seconds(WEB_IDENTITY_TOKEN_SECONDS)
                .customize()
                .interceptor(stop.clone())
                .send()
                .await;
            assert!(result.is_err());
            let (url, signed) = stop.0.lock().unwrap().clone().unwrap();
            assert_eq!(url.trim_end_matches('/'), host, "{region}");
            assert!(signed, "{region}");
        }
    }

    /// The exchange goes to STS in the destination Region, never the
    /// source's, and is not signed.
    #[tokio::test]
    async fn the_exchange_goes_to_the_destination_region_unsigned() {
        assert!(
            service_endpoint(STS_ENDPOINT_VARIABLE).is_none(),
            "OMNIFOB_AWS_ENDPOINT and AWS_ENDPOINT_URL_STS must be unset for this test"
        );
        let config = crate::Config::parse(
            r#"
            [integrations.portal]
            type = "aws-sso"
            start_url = "https://acme.awsapps.com/start"
            region = "us-east-1"
            [integrations.portal.cross_partition.gov]
            via_account_id = "111111111111"
            via_role = "Admin"
            role_arn = "arn:aws-us-gov:iam::222222222222:role/Audit"
            audience = "omnifob"
            region = "us-gov-east-1"
            source_region = "us-east-1"
            [integrations.portal.cross_partition.eusc]
            via_account_id = "111111111111"
            via_role = "Admin"
            role_arn = "arn:aws-eusc:iam::333333333333:role/Audit"
            audience = "omnifob"
            region = "eusc-de-east-1"
            "#,
        )
        .unwrap();
        let crate::Integration::AwsSso(portal) = config.integration("portal").unwrap() else {
            unreachable!()
        };
        for (label, host) in [
            ("gov", "https://sts.us-gov-east-1.amazonaws.com"),
            ("eusc", "https://sts.eusc-de-east-1.amazonaws.eu"),
        ] {
            let role = &portal.cross_partition[label];
            let stop = StopBeforeSending::default();
            let _ = exchange_client(role)
                .assume_role_with_web_identity()
                .role_arn(&role.role_arn)
                .role_session_name("omnifob")
                .web_identity_token("a.b.c")
                .customize()
                .interceptor(stop.clone())
                .send()
                .await;
            let (url, signed) = stop.0.lock().unwrap().clone().unwrap();
            assert_eq!(url.trim_end_matches('/'), host, "{label}");
            assert!(!signed, "{label}");
        }
    }

    #[test]
    fn token_claims_are_read_for_display() {
        use base64::Engine;
        let encode = |json: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        let token = format!(
            "{}.{}.signature",
            encode(r#"{"alg":"ES384"}"#),
            encode(
                r#"{"iss":"https://abc.tokens.sts.global.api.aws","sub":"arn:aws:iam::111111111111:role/Admin","aud":"omnifob","https://sts.amazonaws.com/":{"identity_store_user_id":"u"}}"#
            )
        );
        let claims = TokenClaims::of(&token).unwrap();
        assert_eq!(
            claims.to_string(),
            "iss https://abc.tokens.sts.global.api.aws, sub arn:aws:iam::111111111111:role/Admin, aud omnifob"
        );
        // A list of audiences, and padding some encoders add.
        let token = format!("h.{}==.s", encode(r#"{"aud":["a","b"]}"#));
        assert_eq!(
            TokenClaims::of(&token).unwrap().to_string(),
            "iss (none), sub (none), aud a, b"
        );
        for broken in [
            "",
            "only-one-part",
            "h.!!!.s",
            &format!("h.{}.s", encode("[1]")),
        ] {
            assert_eq!(TokenClaims::of(broken), None, "{broken}");
        }
        // The token itself never shows in Debug output.
        let secret = WebIdentityToken(token.clone());
        assert!(!format!("{secret:?}").contains(&token));
    }
}
