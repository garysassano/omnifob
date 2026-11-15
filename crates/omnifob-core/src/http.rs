//! The HTTP client every provider uses for calls outside the AWS SDK.

use std::time::Duration;

/// How long to wait for a connection before giving up.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a whole request, response body included, may take.
pub const TIMEOUT: Duration = Duration::from_secs(30);

/// The user agent sent with every request. Cloudflare's bot protection
/// rejects requests without one (error 1010).
pub const USER_AGENT: &str = concat!("omnifob/", env!("CARGO_PKG_VERSION"));

/// A builder with the user agent and timeouts set, for a caller that needs
/// more settings or a shorter timeout.
pub fn builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(TIMEOUT)
}

/// A client with the user agent and timeouts set, so no request can hang a
/// command.
pub fn client() -> reqwest::Client {
    builder().build().expect("HTTP client")
}
