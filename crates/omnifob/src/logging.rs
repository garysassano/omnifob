//! The log subscriber, which keeps secrets out of `OMNIFOB_LOG` output.

/// The log subscriber: `filter` (from `OMNIFOB_LOG`) decides what is shown,
/// except that the AWS SDK's dumps of whole HTTP requests and responses,
/// bodies included (role credentials, Identity Center tokens, web identity
/// tokens), are dropped whatever it asks for, so no secret reaches the log.
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
        .with_env_filter(filter)
        .without_time()
        .finish()
        .with(tracing_subscriber::filter::filter_fn(|meta| {
            !logs_http_bodies(meta)
        }))
}

/// Whether a log event may hold whole HTTP requests or responses: the AWS
/// SDK's orchestrator logs them, bodies and headers included, at trace
/// level.
pub(crate) fn logs_http_bodies(meta: &tracing::Metadata<'_>) -> bool {
    sdk_logs_http_bodies(meta.target(), *meta.level())
}

pub(crate) fn sdk_logs_http_bodies(target: &str, level: tracing::Level) -> bool {
    level == tracing::Level::TRACE && target.starts_with("aws_smithy_runtime::client::orchestrator")
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
        ] {
            assert!(sdk_logs_http_bodies(target, Level::TRACE), "{target}");
            assert!(!sdk_logs_http_bodies(target, Level::DEBUG), "{target}");
        }
        assert!(!sdk_logs_http_bodies(
            "omnifob_core::providers::aws_sso",
            Level::TRACE
        ));
    }

    /// The subscriber `main` installs drops the SDK's trace dumps even when
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
            tracing::debug!(
                target: "aws_smithy_runtime::client::orchestrator",
                "beginning attempt #1"
            );
            tracing::trace!(target: "omnifob_core::providers::aws_sso", "our own trace");
        });
        let log = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert!(!log.contains("secret-request-body"), "{log}");
        assert!(!log.contains("secret-response-body"), "{log}");
        assert!(log.contains("beginning attempt #1"), "{log}");
        assert!(log.contains("our own trace"), "{log}");
    }
}
