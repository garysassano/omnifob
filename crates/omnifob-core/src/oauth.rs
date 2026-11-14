//! The OAuth authorization code flow with PKCE (RFC 7636) and a loopback
//! redirect (RFC 8252), shared by the browser sign-ins: the browser is sent to
//! the provider's consent page, which redirects back to a listener on this
//! machine with a code that only this process can redeem.

use std::io::{ErrorKind, Read as _, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

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

/// How long a connection may take to send its request. Browsers open
/// connections speculatively and may never use them; such a connection is
/// closed after this, without ending the sign-in.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// The most a request may send before its headers end; a callback is far
/// shorter, so a longer request is not one and is dropped.
const MAX_REQUEST: usize = 16 * 1024;

/// How often the listener looks for new connections and data when idle.
const POLL: Duration = Duration::from_millis(25);

/// A connection whose request has not fully arrived yet.
struct Pending {
    stream: TcpStream,
    request: Vec<u8>,
    until: Instant,
}

/// What reading from a pending connection gave.
enum Progress {
    /// The request is still arriving.
    Waiting,
    /// The request's headers are complete; the first line is the request line.
    Request(String),
    /// The connection closed, failed or sent more than a request: drop it.
    Gone,
}

/// Accepts connections until one carries the callback on `path` with this
/// sign-in's `state`, answers the browser, and returns the authorization code,
/// or the provider's refusal as an error. Gives up after `timeout`; the
/// listener polls rather than blocks, so the process can exit then.
///
/// Connections are served side by side, so one that stays silent cannot hold
/// up the callback; it is closed after [`REQUEST_TIMEOUT`]. A connection that
/// fails, a request for another path (404), and a callback with another
/// `state` (400) are answered or dropped, and the wait goes on: none of them
/// can end a sign-in. `provider` names the provider in the page the browser
/// shows.
pub fn wait_for_code(
    listener: &TcpListener,
    path: &str,
    state: &str,
    timeout: Duration,
    provider: &str,
) -> anyhow::Result<String> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + timeout;
    let mut pending: Vec<Pending> = Vec::new();
    loop {
        let now = Instant::now();
        if now >= deadline {
            bail!(
                "the sign-in was not completed within {} minutes",
                timeout.as_secs() / 60
            );
        }
        let mut busy = false;
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    busy = true;
                    // A connection that cannot be set up is dropped.
                    if stream.set_nonblocking(true).is_ok() {
                        pending.push(Pending {
                            stream,
                            request: Vec::new(),
                            until: now + REQUEST_TIMEOUT,
                        });
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                // Errors that belong to one connection, which a client can
                // cause by giving up before it was accepted.
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::Interrupted
                            | ErrorKind::ConnectionAborted
                            | ErrorKind::ConnectionReset
                    ) => {}
                Err(e) => {
                    return Err(e).context("accepting the sign-in callback on 127.0.0.1");
                }
            }
        }
        let mut i = 0;
        while i < pending.len() {
            match read_request(&mut pending[i]) {
                Progress::Waiting if now < pending[i].until => i += 1,
                Progress::Waiting | Progress::Gone => {
                    pending.swap_remove(i);
                }
                Progress::Request(line) => {
                    busy = true;
                    let conn = pending.swap_remove(i);
                    if let Some(result) = answer(conn.stream, &line, path, state, provider) {
                        return result;
                    }
                }
            }
        }
        if !busy {
            std::thread::sleep(POLL);
        }
    }
}

/// Reads what has arrived on a pending connection without blocking.
fn read_request(conn: &mut Pending) -> Progress {
    let mut buf = [0u8; 4096];
    loop {
        match conn.stream.read(&mut buf) {
            Ok(0) => {
                // A client may close its side right after the request line.
                return match request_line(&conn.request) {
                    Some(line) => Progress::Request(line),
                    None => Progress::Gone,
                };
            }
            Ok(n) => {
                conn.request.extend_from_slice(&buf[..n]);
                if conn.request.len() > MAX_REQUEST {
                    return Progress::Gone;
                }
                // Reading up to the end of the headers before answering, so no
                // unread data makes closing the socket reset the connection.
                let request = &conn.request;
                if request.windows(4).any(|w| w == b"\r\n\r\n")
                    || request.windows(2).any(|w| w == b"\n\n")
                {
                    return request_line(request).map_or(Progress::Gone, Progress::Request);
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Progress::Waiting,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Progress::Gone,
        }
    }
}

/// The first line of a request, once it is complete.
fn request_line(request: &[u8]) -> Option<String> {
    let end = request.iter().position(|&b| b == b'\n')?;
    Some(String::from_utf8_lossy(&request[..end]).into_owned())
}

/// Answers one request, and returns the outcome of the sign-in when the
/// request is this sign-in's callback.
fn answer(
    mut stream: TcpStream,
    request_line: &str,
    path: &str,
    state: &str,
    provider: &str,
) -> Option<anyhow::Result<String>> {
    let (status, message, result) = match callback_query(request_line, path) {
        None => ("404 Not Found", String::new(), None),
        Some(query) => match parse_callback(&query, state, provider) {
            None => (
                "400 Bad Request",
                "This page belongs to another sign-in. The sign-in in the terminal is still waiting; finish it from the link it shows.".to_string(),
                None,
            ),
            Some(result) => {
                let message = match &result {
                    Ok(_) => format!(
                        "Signed in to {provider}. You can close this tab and return to the terminal."
                    ),
                    Err(_) => "The sign-in failed. Return to the terminal for details.".to_string(),
                };
                ("200 OK", message, Some(result))
            }
        },
    };
    // The answer is best effort: the outcome stands whether or not the
    // browser receives it.
    if stream.set_nonblocking(false).is_ok() {
        let _ = stream.set_write_timeout(Some(REQUEST_TIMEOUT));
        let _ = write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{message}",
            message.len()
        );
        let _ = stream.flush();
    }
    result
}

/// The query of a `GET <path>?...` request line.
fn callback_query(request_line: &str, path: &str) -> Option<String> {
    let target = request_line.strip_prefix("GET ")?.split(' ').next()?;
    let query = target.strip_prefix(path)?.strip_prefix('?')?;
    Some(query.to_string())
}

/// The outcome a callback carries: `None` when its `state` is not this
/// sign-in's, so it is not this sign-in's callback and must not end it;
/// otherwise the code, or the provider's refusal as an error.
fn parse_callback(query: &str, state: &str, provider: &str) -> Option<anyhow::Result<String>> {
    let url = reqwest::Url::parse(&format!("http://localhost/?{query}")).ok()?;
    let param = |name: &str| {
        url.query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    };
    if param("state").as_deref() != Some(state) {
        return None;
    }
    if let Some(error) = param("error") {
        let detail = param("error_description").unwrap_or_default();
        return Some(Err(anyhow::anyhow!(
            "{provider} refused the sign-in: {error} {detail}"
        )));
    }
    Some(param("code").context("the callback carries no code"))
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

    /// Sends a request on a new connection and returns the reply.
    fn request(addr: std::net::SocketAddr, request: &str) -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(request.as_bytes()).unwrap();
        let mut reply = String::new();
        s.read_to_string(&mut reply).unwrap();
        reply
    }

    #[test]
    fn waiting_for_the_callback_returns_the_code() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let browser = std::thread::spawn(move || {
            // A stray request first, as browsers ask for a favicon.
            let reply = request(addr, "GET /favicon.ico HTTP/1.1\r\nHost: x\r\n\r\n");
            assert!(reply.starts_with("HTTP/1.1 404"), "{reply}");
            request(
                addr,
                "GET /oauth/callback?code=c1&state=s HTTP/1.1\r\nHost: x\r\n\r\n",
            )
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
    fn a_silent_connection_does_not_hold_up_the_callback() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let browser = std::thread::spawn(move || {
            // Browsers open connections they may never use; these stay open
            // and silent, or close without a request, while the callback
            // arrives on another.
            let silent = TcpStream::connect(addr).unwrap();
            let mut partial = TcpStream::connect(addr).unwrap();
            partial.write_all(b"GET /callback?co").unwrap();
            drop(TcpStream::connect(addr).unwrap());
            std::thread::sleep(Duration::from_millis(100));
            let reply = request(
                addr,
                "GET /callback?code=c1&state=s HTTP/1.1\r\nHost: x\r\n\r\n",
            );
            drop((silent, partial));
            reply
        });
        let started = Instant::now();
        let code = wait_for_code(&listener, "/callback", "s", Duration::from_secs(30), "X");
        let reply = browser.join().unwrap();
        assert_eq!(code.unwrap(), "c1");
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        // The callback was served while the silent connections were open,
        // not after they timed out.
        assert!(
            started.elapsed() < REQUEST_TIMEOUT,
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_silent_connection_is_closed_and_the_wait_goes_on() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let browser = std::thread::spawn(move || {
            let mut silent = TcpStream::connect(addr).unwrap();
            silent.set_read_timeout(Some(REQUEST_TIMEOUT * 5)).unwrap();
            let opened = Instant::now();
            // The listener closes it without an answer; a reset counts too.
            let mut reply = Vec::new();
            let _ = silent.read_to_end(&mut reply);
            let held = opened.elapsed();
            assert!(reply.is_empty(), "{}", String::from_utf8_lossy(&reply));
            assert!(held < REQUEST_TIMEOUT * 4, "held for {held:?}");
            request(
                addr,
                "GET /callback?code=c1&state=s HTTP/1.1\r\nHost: x\r\n\r\n",
            )
        });
        let code = wait_for_code(&listener, "/callback", "s", Duration::from_secs(30), "X");
        let reply = browser.join().unwrap();
        assert_eq!(code.unwrap(), "c1");
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    }

    #[test]
    fn a_callback_with_another_state_is_refused_and_the_wait_goes_on() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let browser = std::thread::spawn(move || {
            let replies = [
                // An old tab of an earlier sign-in, or any local page.
                "GET /?code=old&state=other HTTP/1.1\r\nHost: x\r\n\r\n",
                // A refusal is only this sign-in's when its state matches.
                "GET /?error=access_denied&state=other HTTP/1.1\r\nHost: x\r\n\r\n",
                "GET /?code=nostate HTTP/1.1\r\nHost: x\r\n\r\n",
            ]
            .map(|r| request(addr, r));
            for reply in &replies {
                assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
                assert!(reply.contains("still waiting"), "{reply}");
            }
            request(addr, "GET /?state=s&code=c1 HTTP/1.1\r\nHost: x\r\n\r\n")
        });
        let code = wait_for_code(&listener, "/", "s", Duration::from_secs(30), "X");
        let reply = browser.join().unwrap();
        assert_eq!(code.unwrap(), "c1");
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    }

    #[test]
    fn a_refusal_with_this_state_ends_the_wait() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let browser = std::thread::spawn(move || {
            request(
                addr,
                "GET /callback?error=access_denied&error_description=no&state=s HTTP/1.1\r\nHost: x\r\n\r\n",
            )
        });
        let err = wait_for_code(
            &listener,
            "/callback",
            "s",
            Duration::from_secs(30),
            "Cloudflare",
        )
        .unwrap_err()
        .to_string();
        let reply = browser.join().unwrap();
        assert!(
            err.contains("Cloudflare refused the sign-in: access_denied"),
            "{err}"
        );
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
        assert!(reply.contains("sign-in failed"), "{reply}");
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
            parse_callback("code=abc&state=s1", "s1", "X")
                .unwrap()
                .unwrap(),
            "abc"
        );
        assert!(parse_callback("code=abc&state=other", "s1", "X").is_none());
        assert!(parse_callback("error=access_denied&state=other", "s1", "X").is_none());
        assert!(parse_callback("state=s1", "s1", "X").unwrap().is_err());
        let err = parse_callback(
            "error=access_denied&error_description=no&state=s1",
            "s1",
            "Cloudflare",
        )
        .unwrap()
        .unwrap_err()
        .to_string();
        assert!(err.contains("Cloudflare refused"), "{err}");
        assert!(err.contains("access_denied"), "{err}");
    }
}
