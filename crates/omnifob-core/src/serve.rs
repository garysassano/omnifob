//! A small HTTP/1.1 server on `127.0.0.1`, for the endpoints `fob exec`
//! runs while its command does: AWS container credentials, an Azure
//! managed identity and a Google token endpoint. Tools reach them through
//! the variables their SDKs read, and every request must carry the secret
//! omnifob put next to the URL, compared in constant time.
//!
//! It answers one request per connection (`Connection: close`), up to
//! [`MAX_CONNECTIONS`] connections at once, so a request waiting for new
//! credentials does not hold up the others, with a timeout on reading each
//! request and on writing each answer. Requests and responses are never
//! logged: they carry the secret and the tokens.

use std::future::Future;
use std::time::Duration;

use anyhow::{Context as _, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The longest request head, and the largest body, read.
const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 64 * 1024;

/// How long a client has to send its request, and to take the answer.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// How many connections are answered at once; more wait to be accepted.
pub const MAX_CONNECTIONS: usize = 32;

/// How long to wait after `accept` fails, as it keeps failing while the
/// process is out of file descriptors, before trying again.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// One request: the method, the path without the query, the decoded query
/// pairs, the headers (names lowercased) and the body.
#[derive(Default)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// The first header named `name`, which is matched without case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The first query parameter named `name`.
    pub fn query(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// The first field named `name` of a form-encoded body.
    pub fn form(&self, name: &str) -> Option<String> {
        form_urlencoded::parse(&self.body)
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    }
}

/// A JSON response.
pub struct Response {
    pub status: u16,
    pub body: serde_json::Value,
}

impl Response {
    pub fn ok(body: serde_json::Value) -> Self {
        Self { status: 200, body }
    }

    /// An error with `message` under `field` (`message` for AWS, `error`
    /// for Azure and Google), which tools show.
    pub fn error(status: u16, field: &str, message: impl Into<String>) -> Self {
        let mut body = serde_json::Map::new();
        body.insert(field.to_string(), message.into().into());
        Self {
            status,
            body: body.into(),
        }
    }
}

/// A random secret for one endpoint: 32 random bytes as base64url.
pub fn secret() -> anyhow::Result<String> {
    crate::oauth::random_string(32)
}

/// Whether `given` is `secret`, compared in constant time. A missing
/// value is never it.
pub fn secret_matches(given: Option<&str>, secret: &str) -> bool {
    given.is_some_and(|given| {
        aws_lc_rs::constant_time::verify_slices_are_equal(given.as_bytes(), secret.as_bytes())
            .is_ok()
    })
}

/// A listener on a free port of `127.0.0.1`, never another address.
pub async fn bind() -> anyhow::Result<TcpListener> {
    TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("listening on 127.0.0.1")
}

/// Answers requests on `listener` with `handler` until the future is
/// dropped, several connections at once. A request that cannot be read
/// gets a 400 and the connection is closed; nothing a client sends ends the
/// server.
pub async fn serve<H, F>(listener: TcpListener, handler: H)
where
    H: Fn(Request) -> F,
    F: Future<Output = Response>,
{
    use futures_util::StreamExt;
    let mut connections = futures_util::stream::FuturesUnordered::new();
    // After a failed accept (out of file descriptors, say), accepting waits
    // a while; the open connections keep being answered meanwhile, which is
    // what frees descriptors again.
    let mut resume: Option<tokio::time::Instant> = None;
    loop {
        let accepting = resume.is_none() && connections.len() < MAX_CONNECTIONS;
        tokio::select! {
            accepted = listener.accept(), if accepting => match accepted {
                Ok((stream, _)) => connections.push(answer(stream, &handler)),
                Err(e) => {
                    tracing::debug!("accepting a connection: {e}");
                    resume = Some(tokio::time::Instant::now() + ACCEPT_BACKOFF);
                }
            },
            () = tokio::time::sleep_until(resume.unwrap_or_else(tokio::time::Instant::now)), if resume.is_some() => {
                resume = None;
            }
            Some(()) = connections.next(), if !connections.is_empty() => {}
        }
    }
}

/// Reads one request from `stream`, answers it with `handler`, and closes.
async fn answer<H, F>(mut stream: TcpStream, handler: &H)
where
    H: Fn(Request) -> F,
    F: Future<Output = Response>,
{
    let response = match tokio::time::timeout(READ_TIMEOUT, read_request(&mut stream)).await {
        Ok(Ok(request)) => handler(request).await,
        Ok(Err(e)) => Response::error(400, "message", format!("{e:#}")),
        Err(_) => return,
    };
    let _ = tokio::time::timeout(READ_TIMEOUT, write_response(&mut stream, &response)).await;
}

async fn read_request(stream: &mut TcpStream) -> anyhow::Result<Request> {
    let mut buf = Vec::with_capacity(1024);
    let head_end = loop {
        if let Some(end) = find(&buf, b"\r\n\r\n") {
            break end;
        }
        if buf.len() > MAX_HEAD {
            bail!("request head too large");
        }
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed before the request ended");
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = std::str::from_utf8(&buf[..head_end]).context("request head is not UTF-8")?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(_version)) = (parts.next(), parts.next(), parts.next())
    else {
        bail!("malformed request line");
    };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut request = Request {
        method: method.to_string(),
        path: path.to_string(),
        query: form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect(),
        ..Request::default()
    };
    for line in lines {
        let (name, value) = line.split_once(':').context("malformed header")?;
        request
            .headers
            .push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }
    if request.header("transfer-encoding").is_some() {
        bail!("chunked bodies are not accepted");
    }
    let length: usize = match request.header("content-length") {
        Some(n) => n.parse().context("bad Content-Length")?,
        None => 0,
    };
    if length > MAX_BODY {
        bail!("request body too large");
    }
    // The body in one buffer of its declared length, filled in place, so a
    // client sending a byte at a time costs no allocation per read.
    let mut body = buf[head_end + 4..].to_vec();
    if body.len() < length {
        let had = body.len();
        body.resize(length, 0);
        stream
            .read_exact(&mut body[had..])
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => {
                    anyhow::anyhow!("connection closed before the body ended")
                }
                _ => e.into(),
            })?;
    }
    body.truncate(length);
    request.body = body;
    Ok(request)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

async fn write_response(stream: &mut TcpStream, response: &Response) -> anyhow::Result<()> {
    let body = serde_json::to_vec(&response.body)?;
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        response.status,
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_compare_whole() {
        assert!(secret_matches(Some("abc"), "abc"));
        assert!(!secret_matches(Some("abd"), "abc"));
        assert!(!secret_matches(Some("ab"), "abc"));
        assert!(!secret_matches(Some(""), "abc"));
        assert!(!secret_matches(None, "abc"));
    }

    #[tokio::test]
    async fn answers_requests_and_survives_bad_ones() {
        let listener = bind().await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(addr.ip().is_loopback());
        let server = tokio::spawn(serve(listener, |request: Request| async move {
            Response::ok(serde_json::json!({
                "path": request.path,
                "resource": request.query("resource"),
                "secret": request.header("X-Secret"),
                "grant": request.form("grant_type"),
            }))
        }));
        let raw = |text: &'static str| async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(text.as_bytes()).await.unwrap();
            let mut out = String::new();
            stream.read_to_string(&mut out).await.unwrap();
            out
        };
        // A client that connects and sends nothing does not hold up the
        // others.
        let _silent = TcpStream::connect(addr).await.unwrap();
        let out = tokio::time::timeout(Duration::from_secs(5), raw("garbage\r\n\r\n"))
            .await
            .expect("answered while another connection waits");
        assert!(out.starts_with("HTTP/1.1 400"), "{out}");
        let out = raw(
            "POST /token?resource=https%3A%2F%2Fvault.azure.net HTTP/1.1\r\nHost: x\r\nx-secret: s\r\nContent-Length: 24\r\n\r\ngrant_type=refresh_token",
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 200 OK"), "{out}");
        let body: serde_json::Value =
            serde_json::from_str(out.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(body["path"], "/token");
        assert_eq!(body["resource"], "https://vault.azure.net");
        assert_eq!(body["secret"], "s");
        assert_eq!(body["grant"], "refresh_token");
        server.abort();
    }
}
