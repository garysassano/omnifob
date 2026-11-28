//! The AWS integrations (`aws-sso`, `aws-iam`, `aws-login`) and what they
//! share: STS, console sign-in, partitions and endpoint overrides.

pub mod console;
pub mod cross_partition;
pub mod discover;
pub mod iam;
pub mod login;
pub mod partition;
pub mod sso;
pub mod sts;

/// Where every AWS call goes, for tests: the current context's
/// [`Endpoints::aws`](crate::Endpoints::aws), from `OMNIFOB_AWS_ENDPOINT`.
pub(crate) fn endpoint_override() -> Option<String> {
    crate::Context::current().endpoints().aws.clone()
}

/// Where to send the calls of one AWS API: `OMNIFOB_AWS_ENDPOINT`, else the
/// service's own variable (`AWS_ENDPOINT_URL_SSO_OIDC`, `AWS_ENDPOINT_URL_SSO`,
/// `AWS_ENDPOINT_URL_STS`, `AWS_ENDPOINT_URL_SIGNIN` or `AWS_ENDPOINT_URL_IAM`), which points the AWS
/// CLI at a VPC endpoint whose private DNS is off, as the current context's
/// [`Endpoints`](crate::Endpoints) hold them.
pub(crate) fn service_endpoint(variable: &str) -> Option<String> {
    crate::Context::current()
        .endpoints()
        .aws_service(variable)
        .map(str::to_string)
}

/// Points an AWS SDK client's config at the API's endpoint: the URL
/// [`service_endpoint`] gives, or else the SDK's own, dual-stack or FIPS as
/// `AWS_USE_DUALSTACK_ENDPOINT` and `AWS_USE_FIPS_ENDPOINT` ask. The SDKs
/// refuse FIPS or dual-stack with a custom URL, so the flags go only
/// without one; and like them, omnifob does not fall back to IPv4 where a
/// Region has no dual-stack endpoint.
macro_rules! aws_endpoint {
    ($config:expr, $variable:expr) => {{
        let config = $config;
        match crate::providers::aws::service_endpoint($variable) {
            Some(url) => config.endpoint_url(url),
            None => {
                let cx = crate::Context::current();
                let endpoints = cx.endpoints();
                config
                    .use_dual_stack(endpoints.aws_dual_stack)
                    .use_fips(endpoints.aws_fips)
            }
        }
    }};
}
pub(crate) use aws_endpoint;

/// The `RoleSessionName` of a role whose config names none: `omnifob`, or
/// `omnifob-agent` for a coding agent, so CloudTrail tells the sessions
/// agents started from the user's own.
pub(crate) fn default_session_name() -> &'static str {
    if crate::Context::current().agent().is_some() {
        "omnifob-agent"
    } else {
        "omnifob"
    }
}
