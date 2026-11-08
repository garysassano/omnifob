//! The OAuth authorization code flow with PKCE (RFC 7636) and a loopback
//! redirect (RFC 8252), shared by the browser sign-ins: the browser is sent to
//! the provider's consent page, which redirects back to a listener on this
//! machine with a code that only this process can redeem.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::time::Duration;

use anyhow::{Context, bail};
use base64::Engine;

/// Whether this looks like a remote or container session, where a browser
/// cannot reach a loopback listener here (Granted makes the same check).
pub fn browser_is_elsewhere() -> bool {
    let remote = ["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY", "CODESPACES"]
        .iter()
        .any(|v| std::env::var_os(v).is_some_and(|v| !v.is_empty()));
    let container = ["/.dockerenv", "/run/.containerenv"]
        .iter()
        .any(|p| std::path::Path::new(p).exists());
    remote || container
}

/// A PKCE verifier and its S256 challenge.
pub fn pkce() -> anyhow::Result<(String, String)> {
    let verifier = random_string(48)?;
    let challenge = challenge(&verifier);
    Ok((verifier, challenge))
}

/// The S256 challenge of a verifier: base64url of its SHA-256, unpadded.
pub fn challenge(verifier: &str) -> String {
    use sha2::Digest;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier))
}

/// `bytes` random bytes as unpadded base64url, for verifiers and `state`.
pub fn random_string(bytes: usize) -> anyhow::Result<String> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).map_err(|e| anyhow::anyhow!("no system randomness: {e}"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf))
}

/// Accepts connections until one carries the callback on `path`, answers the
/// browser, and returns the authorization code. Gives up after `timeout`; the
/// listener polls rather than blocks, so the process can exit then.
/// `provider` names the provider in the page the browser shows.
pub fn wait_for_code(
    listener: &TcpListener,
    path: &str,
    state: &str,
    timeout: Duration,
    provider: &str,
) -> anyhow::Result<String> {
    listener.set_nonblocking(true)?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    bail!(
                        "the sign-in was not completed within {} minutes",
                        timeout.as_secs() / 60
                    );
                }
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line)?;
        let Some(query) = callback_query(&line, path) else {
            let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
            continue;
        };
        let result = parse_callback(&query, state, provider);
        let message = match &result {
            Ok(_) => format!(
                "Signed in to {provider}. You can close this tab and return to the terminal."
            ),
            Err(_) => "The sign-in failed. Return to the terminal for details.".to_string(),
        };
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{message}",
            message.len()
        );
        return result;
    }
}

/// The query of a `GET <path>?...` request line.
fn callback_query(request_line: &str, path: &str) -> Option<String> {
    let target = request_line.strip_prefix("GET ")?.split(' ').next()?;
    let query = target.strip_prefix(path)?.strip_prefix('?')?;
    Some(query.to_string())
}

fn parse_callback(query: &str, state: &str, provider: &str) -> anyhow::Result<String> {
    let url = reqwest::Url::parse(&format!("http://localhost/?{query}"))?;
    let param = |name: &str| {
        url.query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    };
    if let Some(error) = param("error") {
        let detail = param("error_description").unwrap_or_default();
        bail!("{provider} refused the sign-in: {error} {detail}");
    }
    if param("state").as_deref() != Some(state) {
        bail!("the callback's state does not match this sign-in");
    }
    param("code").context("the callback carries no code")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_is_rfc_7636_s256() {
        // The example from RFC 7636, appendix B.
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let (verifier, _) = pkce().unwrap();
        assert!((43..=128).contains(&verifier.len()), "{}", verifier.len());
    }

    #[test]
    fn waiting_for_the_callback_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let err = wait_for_code(&listener, "/callback", "s", Duration::from_millis(200), "X")
            .unwrap_err()
            .to_string();
        assert!(err.contains("not completed"), "{err}");
    }

    #[test]
    fn waiting_for_the_callback_returns_the_code() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let browser = std::thread::spawn(move || {
            // A stray request first, as browsers ask for a favicon.
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.write_all(b"GET /favicon.ico HTTP/1.1\r\nHost: x\r\n\r\n")
                .unwrap();
            let mut reply = String::new();
            std::io::Read::read_to_string(&mut s, &mut reply).unwrap();
            assert!(reply.starts_with("HTTP/1.1 404"), "{reply}");

            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.write_all(b"GET /oauth/callback?code=c1&state=s HTTP/1.1\r\nHost: x\r\n\r\n")
                .unwrap();
            let mut reply = String::new();
            std::io::Read::read_to_string(&mut s, &mut reply).unwrap();
            reply
        });
        let code = wait_for_code(
            &listener,
            "/oauth/callback",
            "s",
            Duration::from_secs(5),
            "AWS",
        )
        .unwrap();
        assert_eq!(code, "c1");
        let reply = browser.join().unwrap();
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        assert!(reply.contains("Signed in to AWS"), "{reply}");
    }

    #[test]
    fn callback_lines() {
        assert_eq!(
            callback_query("GET /callback?code=a&state=b HTTP/1.1\r\n", "/callback").as_deref(),
            Some("code=a&state=b")
        );
        assert_eq!(
            callback_query("GET /favicon.ico HTTP/1.1\r\n", "/callback"),
            None
        );
        assert_eq!(
            callback_query("POST /callback?code=a HTTP/1.1\r\n", "/callback"),
            None
        );
        // A longer path that merely starts with the callback path is not it.
        assert_eq!(
            callback_query("GET /callbackx?code=a HTTP/1.1\r\n", "/callback"),
            None
        );
    }

    #[test]
    fn callbacks_check_state_and_errors() {
        assert_eq!(
            parse_callback("code=abc&state=s1", "s1", "X").unwrap(),
            "abc"
        );
        assert!(parse_callback("code=abc&state=other", "s1", "X").is_err());
        let err = parse_callback(
            "error=access_denied&error_description=no&state=s1",
            "s1",
            "Cloudflare",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("Cloudflare refused"), "{err}");
        assert!(err.contains("access_denied"), "{err}");
    }
}
