//! The Cloudflare API client: requests, pages, errors, and renewing an
//! OAuth sign-in when the API refuses its token.

use anyhow::{Context, bail};
use jiff::Timestamp;
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Result;
use crate::config::{CloudflareConfig, CloudflareTokenType};

pub const API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// The API base URL; `OMNIFOB_CLOUDFLARE_API` overrides it for testing.
pub(super) fn api_base() -> String {
    std::env::var("OMNIFOB_CLOUDFLARE_API")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| API_BASE.to_string())
}

/// A thin client for the Cloudflare v4 API.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    pub(super) base: String,
    /// Shared by clones, so a renewed access token serves them all.
    token: std::sync::Arc<std::sync::Mutex<String>>,
    /// The browser sign-in the token belongs to: renewed, and the request
    /// sent once more, when Cloudflare rejects it with 401.
    oauth: Option<std::sync::Arc<(String, CloudflareConfig)>>,
}

#[derive(Deserialize)]
struct Envelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<ApiMessage>,
    result: Option<T>,
    #[serde(default)]
    result_info: Option<ResultInfo>,
}

#[derive(Deserialize)]
struct ApiMessage {
    pub(super) code: i64,
    message: String,
}

#[derive(Deserialize)]
pub(super) struct ResultInfo {
    #[serde(default)]
    page: Option<u32>,
    #[serde(default)]
    total_pages: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PermissionGroup {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Account {
    pub(super) id: String,
    pub(super) name: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct Token {
    pub(super) id: String,
    #[serde(default)]
    pub(super) name: String,
    #[serde(default)]
    pub(super) status: String,
    #[serde(default)]
    pub(super) expires_on: Option<Timestamp>,
    #[serde(default)]
    pub(super) policies: Vec<Value>,
    #[serde(default)]
    pub(super) condition: Option<Value>,
}

/// Not `Debug`: it holds the new token's value.
#[derive(Deserialize)]
pub(super) struct CreatedToken {
    #[serde(default)]
    pub(super) id: String,
    pub(super) value: String,
}

impl Client {
    /// The same API endpoint, authenticated with another token.
    pub fn with_token(&self, token: impl Into<String>) -> Self {
        Self {
            http: self.http.clone(),
            base: self.base.clone(),
            token: std::sync::Arc::new(std::sync::Mutex::new(token.into())),
            oauth: None,
        }
    }

    pub fn new(base: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            http: crate::http::client(),
            base: base.into(),
            token: std::sync::Arc::new(std::sync::Mutex::new(token.into())),
            oauth: None,
        }
    }

    /// A client with the access token of `integration`'s browser sign-in,
    /// renewed once if Cloudflare rejects it.
    pub(super) async fn for_sign_in(
        base: String,
        integration: &str,
        config: &CloudflareConfig,
    ) -> Result<Self> {
        let token = super::oauth::access_token(integration, config).await?;
        Ok(Self {
            oauth: Some(std::sync::Arc::new((
                integration.to_string(),
                config.clone(),
            ))),
            ..Self::new(base, token)
        })
    }

    pub(super) fn token(&self) -> String {
        self.token.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub(super) async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> anyhow::Result<(T, Option<ResultInfo>)> {
        let mut renewed = false;
        let (status, text) = loop {
            let token = self.token();
            let mut request = self
                .http
                .request(method.clone(), format!("{}{path}", self.base))
                .bearer_auth(&token)
                .query(query);
            if let Some(body) = body {
                request = request.json(body);
            }
            let response = request
                .send()
                .await
                .with_context(|| format!("{method} {path}"))?;
            let status = response.status();
            let text = response.text().await?;
            if !renewed
                && let Some(oauth) = &self.oauth
                && rejects_token(status, &text)
            {
                // An access token can stop working before its time (rotated
                // by another renewal, or revoked); one renewal is worth a try.
                tracing::debug!(
                    "{method} {path}: Cloudflare rejected the access token; renewing it"
                );
                let (integration, config) = &**oauth;
                let fresh = super::oauth::renew_rejected(integration, config, &token).await?;
                *self.token.lock().unwrap_or_else(|e| e.into_inner()) = fresh;
                renewed = true;
                continue;
            }
            break (status, text);
        };
        let envelope: Envelope<T> = serde_json::from_str(&text).with_context(|| {
            format!(
                "{method} {path}: unexpected response ({status}): {}",
                snippet(&text)
            )
        })?;
        if !envelope.success {
            let messages: Vec<_> = envelope
                .errors
                .iter()
                .map(|e| format!("{} (code {})", e.message, e.code))
                .collect();
            bail!("{method} {path} failed ({status}): {}", messages.join("; "));
        }
        let result = envelope
            .result
            .with_context(|| format!("{method} {path}: empty result"))?;
        Ok((result, envelope.result_info))
    }

    pub(super) async fn get<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        Ok(self.call(Method::GET, path, &[], None).await?.0)
    }

    pub(super) async fn get_all<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<Vec<T>> {
        let mut all = Vec::new();
        let mut page = 1;
        loop {
            let query = [("page", page.to_string()), ("per_page", "50".to_string())];
            let (items, info): (Vec<T>, _) = self.call(Method::GET, path, &query, None).await?;
            let done = items.is_empty()
                || info
                    .and_then(|i| Some(i.page? >= i.total_pages?))
                    .unwrap_or(true);
            all.extend(items);
            if done {
                return Ok(all);
            }
            page += 1;
        }
    }

    /// Path prefix for the token endpoints of either ownership model.
    pub(super) fn tokens_path(token_type: CloudflareTokenType, account_id: &str) -> String {
        match token_type {
            CloudflareTokenType::User => "/user/tokens".to_string(),
            CloudflareTokenType::Account => format!("/accounts/{account_id}/tokens"),
        }
    }

    /// Checks that the bootstrap token is active; returns its id.
    pub async fn verify(
        &self,
        token_type: CloudflareTokenType,
        account_id: &str,
    ) -> anyhow::Result<String> {
        #[derive(Deserialize)]
        struct Verified {
            id: String,
            status: String,
        }
        let path = format!("{}/verify", Self::tokens_path(token_type, account_id));
        let verified: Verified = self.get(&path).await?;
        if verified.status != "active" {
            bail!("the token is {}, not active", verified.status);
        }
        Ok(verified.id)
    }

    pub async fn permission_groups(
        &self,
        token_type: CloudflareTokenType,
        account_id: &str,
    ) -> anyhow::Result<Vec<PermissionGroup>> {
        let path = format!(
            "{}/permission_groups",
            Self::tokens_path(token_type, account_id)
        );
        self.get_all(&path).await
    }
}

/// Whether an answer says the token itself is not accepted: 401, or 403
/// with error 10000 ("Authentication error"), which Cloudflare answers for
/// an access token that was revoked or replaced. Other 403s (a missing
/// permission) are not about the token.
fn rejects_token(status: reqwest::StatusCode, body: &str) -> bool {
    #[derive(Deserialize)]
    struct Errors {
        #[serde(default)]
        errors: Vec<ApiMessage>,
    }
    status == reqwest::StatusCode::UNAUTHORIZED
        || status == reqwest::StatusCode::FORBIDDEN
            && serde_json::from_str::<Errors>(body)
                .is_ok_and(|b| b.errors.iter().any(|e| e.code == 10000))
}

/// The start of a response body that is not the API's JSON, such as an
/// HTML error page from a proxy or the WAF, on one line.
fn snippet(text: &str) -> String {
    let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    match flat.char_indices().nth(200) {
        Some((at, _)) => format!("{}...", &flat[..at]),
        None if flat.is_empty() => "(empty body)".to_string(),
        None => flat,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_authentication_errors_reject_the_token() {
        use reqwest::StatusCode;
        let error = |code: i64| {
            json!({ "success": false, "errors": [{ "code": code, "message": "m" }] }).to_string()
        };
        assert!(rejects_token(StatusCode::UNAUTHORIZED, ""));
        assert!(rejects_token(StatusCode::FORBIDDEN, &error(10000)));
        assert!(!rejects_token(StatusCode::FORBIDDEN, &error(9109)));
        assert!(!rejects_token(StatusCode::FORBIDDEN, "<html>"));
        assert!(!rejects_token(StatusCode::BAD_REQUEST, &error(10000)));
    }
}
