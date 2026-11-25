//! The AWS integrations (`aws-sso`, `aws-iam`, `aws-login`) and what they
//! share: STS, console sign-in, partitions and endpoint overrides.

pub mod console;
pub mod cross_partition;
pub mod iam;
pub mod login;
pub mod partition;
pub mod sso;
pub mod sts;

/// `OMNIFOB_AWS_ENDPOINT` sends every AWS call to one URL, for tests.
pub(crate) fn endpoint_override() -> Option<String> {
    std::env::var("OMNIFOB_AWS_ENDPOINT")
        .ok()
        .filter(|v| !v.is_empty())
}

/// Where to send the calls of one AWS API: `OMNIFOB_AWS_ENDPOINT`, else the
/// service's own variable (`AWS_ENDPOINT_URL_SSO_OIDC`, `AWS_ENDPOINT_URL_SSO`,
/// `AWS_ENDPOINT_URL_STS` or `AWS_ENDPOINT_URL_SIGNIN`), which points the AWS
/// CLI at a VPC endpoint whose private DNS is off, unless
/// `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS` is `true`.
/// The global `AWS_ENDPOINT_URL` is not read: it usually points the command
/// `fob exec` runs at a local emulator, which cannot sign anyone in.
pub(crate) fn service_endpoint(variable: &str) -> Option<String> {
    endpoint_override().or_else(|| {
        let ignored = std::env::var("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS")
            .is_ok_and(|v| v.eq_ignore_ascii_case("true"));
        if ignored {
            return None;
        }
        std::env::var(variable).ok().filter(|v| !v.is_empty())
    })
}
