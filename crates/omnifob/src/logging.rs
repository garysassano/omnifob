//! The log subscriber, which keeps secrets out of `OMNIFOB_LOG` output.

/// The log subscriber: `filter` (from `OMNIFOB_LOG`) decides what is shown,
/// except that trace events from the HTTP and signing crates, which can dump
/// whole requests and responses, headers and bodies included (role
/// credentials, Identity Center tokens, web identity tokens, bearer tokens,
/// DPoP proofs), are dropped whatever it asks for, so no secret reaches the
/// log.
pub(crate) fn log_subscriber<W>(
    filter: tracing_subscriber::EnvFilter,
    writer: W,
) -> impl tracing::Subscriber + Send + Sync
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    use tracing_subscriber::layer::SubscriberExt;
    tracing_subscriber::fmt()
        .with_writer(writer)
        .with_ansi(colors_on_stderr())
        .with_env_filter(filter)
        .without_time()
        .finish()
        .with(tracing_subscriber::filter::filter_fn(|meta| {
            !logs_http_bodies(meta)
        }))
}

/// Whether stderr takes colour: a terminal, without `NO_COLOR`, and not a
/// coding agent's, whose transcript would keep the escape codes.
pub(crate) fn colors_on_stderr() -> bool {
    use std::io::IsTerminal;
    std::io::stderr().is_terminal()
        && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
        && !crate::agent::active()
}

/// Whether a log event may hold whole HTTP requests or responses: the AWS
/// SDK's orchestrator logs them, bodies and headers included, at trace
/// level, and SigV4 logs the request it signs.
pub(crate) fn logs_http_bodies(meta: &tracing::Metadata<'_>) -> bool {
    sdk_logs_http_bodies(meta.target(), *meta.level())
}

/// The crates whose trace events are never logged: the AWS SDK's runtime
/// and signing crates, and the HTTP stack under them and under `reqwest`.
/// Whole crates, not the modules known to dump requests today, so a new
/// dump in an update stays out of the log too. Their debug events are kept:
/// none of them carries headers or bodies.
const HTTP_CRATES: &[&str] = &[
    "aws_sigv4",
    "aws_runtime",
    "hyper",
    "hyper_util",
    "h2",
    "reqwest",
];

pub(crate) fn sdk_logs_http_bodies(target: &str, level: tracing::Level) -> bool {
    if level != tracing::Level::TRACE {
        return false;
    }
    let krate = target.split("::").next().unwrap_or(target);
    krate.starts_with("aws_smithy_") || HTTP_CRATES.contains(&krate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sdks_request_and_response_dumps_are_never_logged() {
        use tracing::Level;
        for target in [
            "aws_smithy_runtime::client::orchestrator",
            "aws_smithy_runtime::client::orchestrator::http",
            "aws_smithy_http_client::client",
            "aws_smithy_runtime_api",
            "aws_sigv4::http_request::sign",
            "aws_runtime::auth::sigv4",
            "hyper::proto::h1::io",
            "hyper_util::client::legacy::pool",
            "h2::codec::framed_write",
            "reqwest::connect",
            "reqwest",
        ] {
            assert!(sdk_logs_http_bodies(target, Level::TRACE), "{target}");
            assert!(!sdk_logs_http_bodies(target, Level::DEBUG), "{target}");
        }
        for target in [
            "omnifob_core::providers::aws::sso",
            "omnifob",
            "hyperlocal",
            "h2o",
            "reqwest_middleware",
            "aws_config::sso",
        ] {
            assert!(!sdk_logs_http_bodies(target, Level::TRACE), "{target}");
        }
    }

    /// The subscriber `main` installs drops the HTTP crates' trace events even when
    /// `OMNIFOB_LOG` asks for everything at trace level.
    #[test]
    fn the_log_subscriber_drops_the_sdks_dumps() {
        #[derive(Clone, Default)]
        struct Buffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Buffer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = log_subscriber("trace".into(), move || writer.clone());
        tracing::subscriber::with_default(subscriber, || {
            tracing::trace!(
                target: "aws_smithy_runtime::client::orchestrator",
                "transmitting request with secret-request-body"
            );
            tracing::trace!(
                target: "aws_smithy_runtime::client::orchestrator::http",
                "read HTTP response body secret-response-body"
            );
            tracing::trace!(
                target: "aws_sigv4::http_request::sign",
                "signing request with secret-signed-header"
            );
            tracing::trace!(target: "hyper::proto::h1::io", "secret-hyper-bytes");
            tracing::trace!(target: "hyper_util::client::legacy", "secret-pool");
            tracing::trace!(target: "h2::codec::framed_read", "secret-h2-frame");
            tracing::trace!(target: "reqwest::connect", "secret-reqwest");
            tracing::trace!(target: "aws_runtime::auth", "secret-aws-runtime");
            tracing::debug!(
                target: "aws_smithy_runtime::client::orchestrator",
                "beginning attempt #1"
            );
            tracing::trace!(target: "omnifob_core::providers::aws::sso", "our own trace");
        });
        let log = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert!(!log.contains("secret-request-body"), "{log}");
        assert!(!log.contains("secret-response-body"), "{log}");
        for secret in [
            "secret-signed-header",
            "secret-hyper-bytes",
            "secret-pool",
            "secret-h2-frame",
            "secret-reqwest",
            "secret-aws-runtime",
        ] {
            assert!(!log.contains(secret), "{secret} in {log}");
        }
        assert!(log.contains("beginning attempt #1"), "{log}");
        assert!(log.contains("our own trace"), "{log}");
    }
}
