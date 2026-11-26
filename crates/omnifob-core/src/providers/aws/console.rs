//! Signing in to the AWS console with temporary credentials, through the
//! federation endpoint of their partition.

use anyhow::{Context, bail};
use jiff::SignedDuration;
use serde::{Deserialize, Serialize};

use super::endpoint_override;
use super::partition::Partition;
use super::sts::{SESSION_MIN, whole_seconds};
use crate::Credentials;

/// The console session lengths the federation endpoint accepts as
/// `SessionDuration`.
pub const CONSOLE_SESSION: std::ops::RangeInclusive<SignedDuration> =
    SESSION_MIN..=SignedDuration::from_hours(12);

/// Fails unless `duration` is a console session length the federation
/// endpoint accepts.
pub fn check_console_duration(duration: SignedDuration) -> anyhow::Result<()> {
    if !CONSOLE_SESSION.contains(&duration) {
        bail!("a console session lasts 15 minutes to 12 hours");
    }
    Ok(())
}

/// Fails unless `service` can be the path of a console page: letters,
/// digits, `-`, `_` and `.` in segments separated by `/` (`ec2`,
/// `cloudformation`, `route53/v2`).
pub(crate) fn check_service(service: &str) -> anyhow::Result<()> {
    let service = service.trim_matches('/');
    let valid = !service.is_empty()
        && service.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        });
    if !valid {
        bail!(
            "'{service}' is not a console service; give the path after the console host, such as ec2, s3 or cloudformation"
        );
    }
    Ok(())
}

/// What a console sign-in opens and for how long.
#[derive(Debug, Clone, Copy)]
pub struct ConsoleRequest<'a> {
    /// The credentials' partition, whose federation endpoint signs in.
    pub partition: Partition,
    /// The Region the credentials came from; in the European Sovereign
    /// Cloud, which has no unprefixed sign-in host, it picks the sign-in
    /// host when `region` is unset.
    pub home_region: Option<&'a str>,
    /// The Region the console opens in, which must be in `partition`.
    pub region: Option<&'a str>,
    /// The console page, as the path after the host (`ec2`, `s3`); the
    /// console home when unset.
    pub service: Option<&'a str>,
    /// How long the console session lasts (`SessionDuration`); without it,
    /// as long as the credentials. Only credentials from `AssumeRole*` (and
    /// Identity Center) take it; role chaining and `GetFederationToken` do
    /// not.
    pub session_duration: Option<SignedDuration>,
}

/// The federation endpoint and console destination for a console sign-in to
/// `partition`. With `region` (the Region the console opens in, which must be
/// in the partition) both are regional. Without it, the console opens at the
/// unprefixed host and so does the sign-in where the partition has one; the
/// European Sovereign Cloud has none, so it signs in at `home_region` when
/// that is in the partition, else at the partition's first Region.
///
/// The destination is `https://<console host>/<service>/home?region=<region>`,
/// as granted builds it, with `console` as the service when only a Region is
/// given and the bare console host when neither is.
pub(crate) fn console_endpoints(request: &ConsoleRequest) -> anyhow::Result<(String, String)> {
    let ConsoleRequest {
        partition,
        home_region,
        region,
        service,
        ..
    } = *request;
    if let Some(region) = region {
        partition.check_region(region)?;
    }
    let service = service.map(|s| s.trim_matches('/'));
    if let Some(service) = service {
        check_service(service)?;
    }
    let signin_region = region
        .or(partition.unprefixed_region())
        .or(home_region.filter(|home| partition.contains(home)))
        .unwrap_or(partition.default_region());
    let endpoint = format!(
        "https://{}/federation",
        partition.signin_host(signin_region)?
    );
    let host = partition.console_host(region)?;
    let destination = match (service, region) {
        (None, None) => format!("https://{host}/"),
        (Some(service), None) => format!("https://{host}/{service}/home"),
        (service, Some(r)) => format!(
            "https://{host}/{}/home?region={r}",
            service.unwrap_or("console")
        ),
    };
    Ok((endpoint, destination))
}

#[derive(Serialize)]
struct FederationSession<'a> {
    #[serde(rename = "sessionId")]
    session_id: &'a str,
    #[serde(rename = "sessionKey")]
    session_key: &'a str,
    #[serde(rename = "sessionToken")]
    session_token: &'a str,
}

/// Builds a sign-in URL for the AWS console with the federation endpoint of
/// the credentials' partition.
///
/// The credentials go to `getSigninToken` in the body of a form POST, which
/// the federation endpoint accepts, so they stay out of proxy and access
/// logs and out of error messages, which name the URL. Neither they nor the
/// sign-in token are logged. `OMNIFOB_AWS_ENDPOINT` sends that call to a mock
/// at `<endpoint>/federation`; the returned URL keeps the real sign-in host.
pub async fn console_url(
    creds: &Credentials,
    request: &ConsoleRequest<'_>,
) -> anyhow::Result<String> {
    let get = |k: &str| {
        creds
            .env
            .get(k)
            .map(String::as_str)
            .with_context(|| format!("{k} missing"))
    };
    let session = serde_json::to_string(&FederationSession {
        session_id: get("AWS_ACCESS_KEY_ID")?,
        session_key: get("AWS_SECRET_ACCESS_KEY")?,
        session_token: get("AWS_SESSION_TOKEN")?,
    })?;
    if let Some(duration) = request.session_duration {
        check_console_duration(duration)?;
    }
    let (endpoint, destination) = console_endpoints(request)?;
    let token_endpoint = match endpoint_override() {
        Some(base) => format!("{}/federation", base.trim_end_matches('/')),
        None => endpoint.clone(),
    };

    let mut form = vec![("Action", "getSigninToken".to_string())];
    if let Some(duration) = request.session_duration {
        form.push(("SessionDuration", whole_seconds(duration)?.to_string()));
    }
    form.push(("Session", session));

    #[derive(Deserialize)]
    struct SigninToken {
        #[serde(rename = "SigninToken")]
        signin_token: String,
    }
    let response = crate::http::client()
        .post(&token_endpoint)
        .form(&form)
        .send()
        .await
        .context("requesting a console sign-in token")?;
    let status = response.status();
    if !status.is_success() {
        // The body is not shown: the endpoint documents no error format.
        let hint = match request.session_duration {
            Some(_) if status.is_client_error() => {
                "; the console session length must be shorter than the role's maximum session \
                 duration (for an Identity Center role, its permission set's session duration)"
            }
            _ => "",
        };
        bail!("the AWS federation endpoint refused a console sign-in token (HTTP {status}){hint}");
    }
    let token: SigninToken = response
        .json()
        .await
        .context("reading the console sign-in token")?;

    let url = reqwest::Url::parse_with_params(
        &endpoint,
        &[
            ("Action", "login"),
            ("Issuer", "omnifob"),
            ("Destination", destination.as_str()),
            ("SigninToken", token.signin_token.as_str()),
        ],
    )?;
    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_sign_in_follows_partition_and_region() {
        use Partition::*;
        let cases = [
            (
                Aws,
                Some("us-east-1"),
                None,
                "https://signin.aws.amazon.com/federation",
                "https://console.aws.amazon.com/",
            ),
            // Without a console Region the sign-in stays on the unprefixed
            // host, whatever the portal's Region.
            (
                Aws,
                Some("eu-west-1"),
                None,
                "https://signin.aws.amazon.com/federation",
                "https://console.aws.amazon.com/",
            ),
            (
                UsGov,
                Some("us-gov-east-1"),
                None,
                "https://signin.amazonaws-us-gov.com/federation",
                "https://console.amazonaws-us-gov.com/",
            ),
            (
                China,
                Some("cn-northwest-1"),
                None,
                "https://signin.amazonaws.cn/federation",
                "https://console.amazonaws.cn/",
            ),
            (
                Aws,
                Some("us-east-1"),
                Some("eu-west-1"),
                "https://eu-west-1.signin.aws.amazon.com/federation",
                "https://eu-west-1.console.aws.amazon.com/console/home?region=eu-west-1",
            ),
            (
                Aws,
                None,
                None,
                "https://signin.aws.amazon.com/federation",
                "https://console.aws.amazon.com/",
            ),
            (
                UsGov,
                Some("us-gov-west-1"),
                None,
                "https://signin.amazonaws-us-gov.com/federation",
                "https://console.amazonaws-us-gov.com/",
            ),
            (
                UsGov,
                Some("us-gov-west-1"),
                Some("us-gov-east-1"),
                "https://us-gov-east-1.signin.amazonaws-us-gov.com/federation",
                "https://us-gov-east-1.console.amazonaws-us-gov.com/console/home?region=us-gov-east-1",
            ),
            (
                China,
                Some("cn-north-1"),
                Some("cn-north-1"),
                "https://signin.amazonaws.cn/federation",
                "https://console.amazonaws.cn/console/home?region=cn-north-1",
            ),
            (
                China,
                Some("cn-north-1"),
                Some("cn-northwest-1"),
                "https://cn-northwest-1.signin.amazonaws.cn/federation",
                "https://cn-northwest-1.console.amazonaws.cn/console/home?region=cn-northwest-1",
            ),
            // The European Sovereign Cloud has no unprefixed sign-in host.
            (
                EuropeanSovereign,
                Some("eusc-de-east-1"),
                None,
                "https://eusc-de-east-1.signin.amazonaws-eusc.eu/federation",
                "https://console.amazonaws-eusc.eu/",
            ),
            // A home Region in another partition (a cross-partition role)
            // does not pick the host.
            (
                EuropeanSovereign,
                Some("eu-central-1"),
                None,
                "https://eusc-de-east-1.signin.amazonaws-eusc.eu/federation",
                "https://console.amazonaws-eusc.eu/",
            ),
            (
                EuropeanSovereign,
                None,
                None,
                "https://eusc-de-east-1.signin.amazonaws-eusc.eu/federation",
                "https://console.amazonaws-eusc.eu/",
            ),
            (
                EuropeanSovereign,
                Some("eusc-de-east-1"),
                Some("eusc-de-east-1"),
                "https://eusc-de-east-1.signin.amazonaws-eusc.eu/federation",
                "https://eusc-de-east-1.console.amazonaws-eusc.eu/console/home?region=eusc-de-east-1",
            ),
        ];
        for (partition, home, region, endpoint, destination) in cases {
            assert_eq!(
                console_endpoints(&console(partition, home, region, None)).unwrap(),
                (endpoint.to_string(), destination.to_string()),
                "{partition} {home:?} {region:?}"
            );
        }
        // The console opens in the credentials' partition only.
        assert!(console_endpoints(&console(UsGov, None, Some("eu-west-1"), None)).is_err());
        assert!(console_endpoints(&console(Aws, None, Some("us-isob-east-1"), None)).is_err());
    }

    fn console<'a>(
        partition: Partition,
        home_region: Option<&'a str>,
        region: Option<&'a str>,
        service: Option<&'a str>,
    ) -> ConsoleRequest<'a> {
        ConsoleRequest {
            partition,
            home_region,
            region,
            service,
            session_duration: None,
        }
    }

    #[test]
    fn console_destination_opens_a_service_in_a_region() {
        use Partition::*;
        let cases = [
            (
                Aws,
                None,
                Some("s3"),
                "https://console.aws.amazon.com/s3/home",
            ),
            (
                Aws,
                Some("eu-west-1"),
                Some("ec2"),
                "https://eu-west-1.console.aws.amazon.com/ec2/home?region=eu-west-1",
            ),
            (
                Aws,
                Some("us-east-1"),
                Some("/route53/v2/"),
                "https://console.aws.amazon.com/route53/v2/home?region=us-east-1",
            ),
            (
                UsGov,
                Some("us-gov-east-1"),
                Some("cloudformation"),
                "https://us-gov-east-1.console.amazonaws-us-gov.com/cloudformation/home?region=us-gov-east-1",
            ),
            (
                China,
                None,
                Some("lambda"),
                "https://console.amazonaws.cn/lambda/home",
            ),
            (
                EuropeanSovereign,
                Some("eusc-de-east-1"),
                Some("iam"),
                "https://eusc-de-east-1.console.amazonaws-eusc.eu/iam/home?region=eusc-de-east-1",
            ),
        ];
        for (partition, region, service, destination) in cases {
            let (_, got) = console_endpoints(&console(partition, None, region, service)).unwrap();
            assert_eq!(got, destination, "{partition} {region:?} {service:?}");
        }
        for service in [
            "",
            "/",
            "ec2/../iam",
            "ec2?region=x",
            "s3#x",
            "a//b",
            "ec2 v2",
            "é",
        ] {
            let error = console_endpoints(&console(Aws, None, None, Some(service))).unwrap_err();
            assert!(
                error.to_string().contains("not a console service"),
                "{service}: {error}"
            );
        }
        // A Region becomes part of the sign-in host, so one that is not
        // shaped like a Region could send the credentials elsewhere.
        for region in [
            "attacker.example#",
            "attacker.example/",
            "eu-west-1.attacker.example",
            "eu-west-1@attacker.example",
            "EU-WEST-1",
        ] {
            let error =
                console_endpoints(&console(Aws, None, Some(region), Some("ec2"))).unwrap_err();
            assert!(
                error.to_string().contains("not an AWS Region name"),
                "{region}: {error}"
            );
        }
        // A malformed home Region never picks the sign-in host either.
        let (endpoint, _) = console_endpoints(&console(
            EuropeanSovereign,
            Some("attacker.example#"),
            None,
            None,
        ))
        .unwrap();
        assert_eq!(
            endpoint,
            "https://eusc-de-east-1.signin.amazonaws-eusc.eu/federation"
        );
        // The service does not lift the partition check on the Region.
        assert!(console_endpoints(&console(UsGov, None, Some("eu-west-1"), Some("ec2"))).is_err());
    }

    #[test]
    fn console_durations_are_15_minutes_to_12_hours() {
        for (duration, ok) in [
            (SignedDuration::from_mins(14), false),
            (SignedDuration::from_mins(15), true),
            (SignedDuration::from_hours(8), true),
            (SignedDuration::from_hours(12), true),
            (
                SignedDuration::from_hours(12) + SignedDuration::from_secs(1),
                false,
            ),
        ] {
            assert_eq!(check_console_duration(duration).is_ok(), ok, "{duration:#}");
        }
    }
}
