//! The AWS integrations (`aws-sso`, `aws-iam`, `aws-login`) and what they
//! share: STS, console sign-in, partitions and endpoint overrides.

pub mod console;
pub mod cross_partition;
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
/// `AWS_ENDPOINT_URL_STS` or `AWS_ENDPOINT_URL_SIGNIN`), which points the AWS
/// CLI at a VPC endpoint whose private DNS is off, as the current context's
/// [`Endpoints`](crate::Endpoints) hold them.
pub(crate) fn service_endpoint(variable: &str) -> Option<String> {
    crate::Context::current()
        .endpoints()
        .aws_service(variable)
        .map(str::to_string)
}
