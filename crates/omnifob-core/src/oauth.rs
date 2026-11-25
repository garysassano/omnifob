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
/// cannot reach a loopback listener here (Granted makes the same check), or
/// a Linux session with no display, where no browser can open: a text
/// console, a server, a container without the host's display. WSL opens
/// the Windows browser, so it never counts as headless, and neither does a
/// session whose `BROWSER` names a browser (a text one, say).
pub fn browser_is_elsewhere() -> bool {
    let set = |v: &str| std::env::var_os(v).is_some_and(|v| !v.is_empty());
    let remote = ["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY", "CODESPACES"]
        .iter()
        .any(|v| set(v));
    let container = ["/.dockerenv", "/run/.containerenv"]
        .iter()
        .any(|p| std::path::Path::new(p).exists());
    let display = set("DISPLAY") || set("WAYLAND_DISPLAY") || set("BROWSER");
    remote
        || container
        || headless(
            cfg!(target_os = "linux"),
            crate::platform::is_wsl(),
            display,
        )
}

/// Whether a session has no display to open a browser on: Linux other than
/// WSL, with neither `DISPLAY` nor `WAYLAND_DISPLAY` (nor `BROWSER`).
/// macOS and Windows always have one.
fn headless(linux: bool, wsl: bool, display: bool) -> bool {
    linux && !wsl && !display
}

/// How long a browser sign-in waits for the consent page to be answered,
/// for every provider.
pub const CALLBACK_TIMEOUT: Duration = Duration::from_secs(600);

/// What one authorization code request needs to be safe: a PKCE verifier,
/// its S256 challenge, and a `state` the callback must carry back.
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
    pub state: String,
}

impl Pkce {
    pub fn new() -> anyhow::Result<Self> {
        let (verifier, challenge) = pkce()?;
        Ok(Self {
            verifier,
            challenge,
            state: random_string(16)?,
        })
    }
}

/// A listener on 127.0.0.1 for one browser sign-in's redirect (RFC 8252).
pub struct Loopback {
    listener: TcpListener,
    port: u16,
}

impl Loopback {
    /// Listens on `port` of 127.0.0.1, or on a free port with 0.
    pub fn bind(port: u16) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", port)).with_context(|| {
            if port == 0 {
                "listening on 127.0.0.1 for the sign-in callback".to_string()
            } else {
                format!(
                    "listening on 127.0.0.1:{port} for the sign-in callback; is another sign-in running?"
                )
            }
        })?;
        let port = listener.local_addr()?.port();
        Ok(Self { listener, port })
    }

    /// The port listened on, for the redirect URI.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Waits up to [`CALLBACK_TIMEOUT`] for the callback on `path` with
    /// `state`, off the async runtime's threads, and returns the code. See
    /// [`wait_for_code`].
    pub async fn code(self, path: &str, state: &str, provider: &str) -> anyhow::Result<String> {
        let (path, state, provider) = (path.to_string(), state.to_string(), provider.to_string());
        tokio::task::spawn_blocking(move || {
            wait_for_code(&self.listener, &path, &state, CALLBACK_TIMEOUT, &provider)
        })
        .await?
    }
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

/// The payload of a JWT, the JSON between its first and second `.`, read
/// without checking the signature: for tokens that came straight from the
/// issuer over TLS, or whose claims are only shown. Padding is accepted
/// though JWTs leave it out.
pub fn decode_jwt_payload<T: serde::de::DeserializeOwned>(token: &str) -> anyhow::Result<T> {
    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(_)) = (parts.next(), parts.next(), parts.next()) else {
        bail!("the token is not a JWT");
    };
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .context("the token's payload is not base64url")?;
    serde_json::from_slice(&bytes).context("the token's payload is not the expected JSON")
}

/// How long a connection may take to send its request. Browsers open
/// connections speculatively and may never use them; such a connection is
/// closed after this, without ending the sign-in.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// The most a request may send before its headers end; a callback is far
/// shorter, so a longer request is not one and is dropped.
const MAX_REQUEST: usize = 16 * 1024;

/// The most connections kept waiting for their request; past this the oldest
/// is closed. Also the most connections accepted in one pass.
const MAX_PENDING: usize = 64;

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
                "the sign-in was not completed within {}",
                describe_wait(timeout)
            );
        }
        let mut busy = false;
        // Bounded, so a flood of connections still lets this loop read the
        // pending ones and reach the deadline.
        for _ in 0..MAX_PENDING {
            match listener.accept() {
                Ok((stream, _)) => {
                    busy = true;
                    // A connection that cannot be set up is dropped.
                    if stream.set_nonblocking(true).is_ok() {
                        if pending.len() >= MAX_PENDING {
                            drop_oldest(&mut pending);
                        }
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
                // Out of file descriptors: free one and try again next pass.
                Err(e) if out_of_descriptors(&e) => {
                    drop_oldest(&mut pending);
                    break;
                }
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

/// A wait in whole minutes, or in seconds when shorter than one.
fn describe_wait(timeout: Duration) -> String {
    match timeout.as_secs() {
        0 => format!("{} ms", timeout.as_millis()),
        1 => "1 second".to_string(),
        secs @ 2..60 => format!("{secs} seconds"),
        60..120 => "1 minute".to_string(),
        secs => format!("{} minutes", secs / 60),
    }
}

/// Closes the pending connection that was accepted first.
fn drop_oldest(pending: &mut Vec<Pending>) {
    if let Some(oldest) = (0..pending.len()).min_by_key(|&i| pending[i].until) {
        pending.swap_remove(oldest);
    }
}

/// Whether `accept` failed because this process or the system ran out of file
/// descriptors (`EMFILE`, `ENFILE`, `WSAEMFILE`), which passes once
/// connections are closed.
fn out_of_descriptors(e: &std::io::Error) -> bool {
    #[cfg(unix)]
    const CODES: &[i32] = &[23, 24];
    #[cfg(windows)]
    const CODES: &[i32] = &[10024];
    #[cfg(not(any(unix, windows)))]
    const CODES: &[i32] = &[];
    e.raw_os_error().is_some_and(|code| CODES.contains(&code))
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
    let (status, content_type, body, result) = match callback_query(request_line, path) {
        None => ("404 Not Found", "text/plain", String::new(), None),
        Some(query) => match parse_callback(&query, state, provider) {
            None => (
                "400 Bad Request",
                "text/html",
                page(
                    Outcome::Failed,
                    "This page belongs to another sign-in",
                    "The sign-in in the terminal is still waiting; finish it from the link it shows.",
                ),
                None,
            ),
            Some(result) => {
                let body = match &result {
                    // The code still has to be exchanged for tokens, so the
                    // terminal has the final word.
                    Ok(_) => page(
                        Outcome::Approved,
                        "Sign-in approved",
                        &format!(
                            "fob is finishing the sign-in to {provider}. You can close this tab and return to the terminal."
                        ),
                    ),
                    Err(_) => page(
                        Outcome::Failed,
                        "Sign-in failed",
                        "Return to the terminal for details.",
                    ),
                };
                ("200 OK", "text/html", body, Some(result))
            }
        },
    };
    // The answer is best effort: the outcome stands whether or not the
    // browser receives it.
    if stream.set_nonblocking(false).is_ok() {
        let _ = stream.set_write_timeout(Some(REQUEST_TIMEOUT));
        let _ = write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.flush();
    }
    result
}

#[derive(Clone, Copy)]
enum Outcome {
    Approved,
    Failed,
}

/// The page the browser shows after the provider sends it back: a green or
/// red box that follows the browser's light or dark theme. Self-contained, so
/// it needs nothing else from the listener.
fn page(outcome: Outcome, heading: &str, detail: &str) -> String {
    let (class, icon) = match outcome {
        Outcome::Approved => ("approved", r#"<path d="m8 12.5 2.5 2.5L16 9.5"/>"#),
        Outcome::Failed => ("failed", r#"<path d="m9 9 6 6m0-6-6 6"/>"#),
    };
    let heading = escape_html(heading);
    let detail = escape_html(detail);
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{heading} · fob</title>
<style>
:root {{ color-scheme: light dark; --page: #f3f4f6; --card: #ffffff; --text: #1f2328; --muted: #59636e; --line: #d1d9e0;
  --ok: #1a7f37; --ok-bg: #edfaef; --bad: #cf222e; --bad-bg: #fff1f0; }}
@media (prefers-color-scheme: dark) {{ :root {{ --page: #0d1117; --card: #161b22; --text: #e6edf3; --muted: #9198a1; --line: #30363d;
  --ok: #3fb950; --ok-bg: #12261e; --bad: #f85149; --bad-bg: #2a1215; }} }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 16px; background: var(--page); color: var(--text);
  font: 16px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }}
main {{ width: 100%; max-width: 440px; background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 24px; }}
.box {{ display: flex; gap: 12px; align-items: flex-start; padding: 16px; border-radius: 8px; border: 1px solid var(--accent); background: var(--tint); }}
.approved {{ --accent: var(--ok); --tint: var(--ok-bg); }}
.failed {{ --accent: var(--bad); --tint: var(--bad-bg); }}
svg {{ flex: none; width: 28px; height: 28px; color: var(--accent); }}
h1 {{ margin: 0 0 4px; font-size: 1.05rem; }}
p {{ margin: 0; color: var(--muted); }}
</style>
</head>
<body>
<main>
<div class="box {class}">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/>{icon}</svg>
<div><h1>{heading}</h1><p>{detail}</p></div>
</div>
</main>
</body>
</html>
"#
    )
}

fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
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

/// Percent-encodes everything but RFC 3986's unreserved characters.
pub(crate) fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_linux_without_a_display_is_headless() {
        assert!(super::headless(true, false, false));
        assert!(!super::headless(true, false, true), "a display");
        assert!(
            !super::headless(true, true, false),
            "WSL opens Windows' browser"
        );
        assert!(!super::headless(false, false, false), "macOS and Windows");
    }

    use super::*;

    #[test]
    fn jwt_payloads_are_decoded_without_their_signature() {
        let encode = |json: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        let token = format!("{}.{}.sig", encode("{}"), encode(r#"{"sub":"me","n":1}"#));
        let claims: serde_json::Value = decode_jwt_payload(&token).unwrap();
        assert_eq!(claims["sub"], "me");
        // Padding is tolerated.
        let padded = format!("h.{}==.s", encode(r#"{"a":1}"#));
        assert!(decode_jwt_payload::<serde_json::Value>(&padded).is_ok());
        for broken in ["", "one", "h.p", "h.!!!.s", "h.e30"] {
            assert!(
                decode_jwt_payload::<serde_json::Value>(broken).is_err(),
                "{broken}"
            );
        }
        #[derive(serde::Deserialize, Debug)]
        #[allow(dead_code)]
        struct Needs {
            tid: String,
        }
        assert!(
            decode_jwt_payload::<Needs>(&token).is_err(),
            "missing claim"
        );
    }

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
        assert!(err.contains("not completed within 200 ms"), "{err}");
    }

    #[test]
    fn waits_are_described_in_their_unit() {
        assert_eq!(describe_wait(Duration::from_secs(1)), "1 second");
        assert_eq!(describe_wait(Duration::from_secs(30)), "30 seconds");
        assert_eq!(describe_wait(Duration::from_secs(90)), "1 minute");
        assert_eq!(describe_wait(CALLBACK_TIMEOUT), "10 minutes");
    }

    #[tokio::test]
    async fn the_loopback_returns_the_code_of_its_callback() {
        let pkce = Pkce::new().unwrap();
        assert_eq!(pkce.challenge, challenge(&pkce.verifier));
        let loopback = Loopback::bind(0).unwrap();
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], loopback.port()));
        let state = pkce.state.clone();
        let browser = std::thread::spawn(move || {
            request(
                addr,
                &format!("GET /cb?code=c1&state={state} HTTP/1.1\r\n\r\n"),
            )
        });
        let code = loopback.code("/cb", &pkce.state, "X").await.unwrap();
        assert_eq!(code, "c1");
        assert!(browser.join().unwrap().contains("200"));
    }

    /// Sends a request on a new connection and returns the reply. Times out
    /// rather than hangs when nothing answers, as after `wait_for_code` has
    /// returned too early.
    fn request(addr: std::net::SocketAddr, request: &str) -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
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
        assert!(
            reply.contains("Content-Type: text/html; charset=utf-8"),
            "{reply}"
        );
        assert!(reply.contains("Sign-in approved"), "{reply}");
        assert!(reply.contains("the sign-in to AWS"), "{reply}");
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
        // Checked before joining, so a sign-in that ended early fails here.
        assert_eq!(code.unwrap(), "c1");
        let reply = browser.join().unwrap();
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
        // Checked before joining, so a sign-in that ended early fails here.
        assert_eq!(code.unwrap(), "c1");
        let reply = browser.join().unwrap();
        assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    }

    #[test]
    fn more_silent_connections_than_are_kept_do_not_hold_up_the_callback() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let browser = std::thread::spawn(move || {
            let silent: Vec<_> = (0..MAX_PENDING * 2)
                .map(|_| TcpStream::connect(addr).unwrap())
                .collect();
            let reply = request(
                addr,
                "GET /callback?code=c1&state=s HTTP/1.1\r\nHost: x\r\n\r\n",
            );
            drop(silent);
            reply
        });
        let code = wait_for_code(&listener, "/callback", "s", Duration::from_secs(30), "X");
        assert_eq!(code.unwrap(), "c1");
        let reply = browser.join().unwrap();
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
        // Checked before joining, so a sign-in that ended early fails here.
        assert_eq!(code.unwrap(), "c1");
        let reply = browser.join().unwrap();
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
        assert!(reply.contains("Sign-in failed"), "{reply}");
    }

    #[test]
    fn the_page_escapes_its_text() {
        let html = page(Outcome::Failed, "<b>&", "\"'");
        assert!(html.contains("&lt;b&gt;&amp;"), "{html}");
        assert!(html.contains("&quot;&#39;"), "{html}");
        assert!(!html.contains("<b>"), "{html}");
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
