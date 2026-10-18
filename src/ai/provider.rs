//! The provider client: one OpenAI-compatible chat-completions call.
//!
//! [`ChatProvider`] is the seam between the reviewer and any service that
//! speaks the chat-completions wire format. [`OpenAiCompatible`] is the
//! only production implementation: it owns a `reqwest` client with the
//! configured timeout as the total request deadline, sends one request,
//! and retries that request exactly once when the failure looks
//! transient.
//!
//! The API key never appears in a `Debug` output. [`KeyHolder`] has no
//! derived `Debug` and never will.

use std::fmt;

use anyhow::Context;
use async_trait::async_trait;

use crate::config::AiReviewConfig;

/// How many bytes of an error response body survive into a
/// [`ProviderError::Status`]. Provider error text is unbounded and
/// attacker-influenced, so it is capped before it can reach a log line.
const MAX_ERROR_BODY_BYTES: usize = 4 * 1024;

/// Sends one chat-completions request and returns the raw response body.
#[async_trait]
pub trait ChatProvider: Send + Sync {
    async fn complete(&self, request: &serde_json::Value) -> Result<String, ProviderError>;
}

/// Everything that can go wrong in one provider call.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("the provider request failed on the transport layer: {0}")]
    Transport(String),
    #[error("the provider returned status {code}")]
    Status { code: u16, body: String },
    #[error("the provider did not answer within the configured timeout")]
    Timeout,
}

/// An API key with no derived `Debug`.
///
/// `new` resolves the key from the named environment variable once and
/// stores it here. This struct has a manual `Debug` that shows only the
/// variable name, so the key cannot reach a log line through a `Debug`
/// output of anything that holds it.
#[derive(Clone)]
struct KeyHolder {
    env_name: String,
    value: String,
}

impl KeyHolder {
    fn resolve(env_name: &str) -> anyhow::Result<Self> {
        let value = std::env::var(env_name)
            .with_context(|| format!("reading the api key from {env_name:?}"))?;
        Ok(Self {
            env_name: env_name.to_string(),
            value,
        })
    }
}

impl fmt::Debug for KeyHolder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The value stays out on purpose. The variable name is safe: it
        // is already visible in the process environment.
        write!(
            f,
            "KeyHolder {{ env_name: {:?}, value: <hidden> }}",
            self.env_name
        )
    }
}

/// The production [`ChatProvider`]: any OpenAI-compatible endpoint.
pub struct OpenAiCompatible {
    client: reqwest::Client,
    endpoint: url::Url,
    key: Option<KeyHolder>,
}

impl fmt::Debug for OpenAiCompatible {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenAiCompatible")
            .field("endpoint", &self.endpoint.as_str())
            .finish_non_exhaustive()
    }
}

impl OpenAiCompatible {
    /// Builds the provider from `cfg`.
    ///
    /// `cfg.api_key_env` is resolved here and only here. The key lives in
    /// a [`KeyHolder`], whose `Debug` cannot leak it, so `OpenAiCompatible`
    /// has the same guarantee.
    ///
    /// The client's timeout is `cfg.timeout` as the total request
    /// deadline. That is the correct shape here, unlike the artifact
    /// download path: this is one small request/response pair, and
    /// bounding its whole duration is the entire point. A provider that
    /// accepts the connection and then hangs fails within the timeout.
    pub fn new(cfg: &AiReviewConfig) -> anyhow::Result<Self> {
        let endpoint = cfg
            .base_url
            .join("chat/completions")
            .with_context(|| format!("building the chat completions url from {cfg:?}"))?;
        let client = reqwest::Client::builder()
            .timeout(cfg.timeout)
            .build()
            .context("building the provider http client")
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let key = match &cfg.api_key_env {
            Some(name) => Some(
                KeyHolder::resolve(name)
                    .with_context(|| format!("resolving api_key_env {name:?}"))?,
            ),
            None => None,
        };
        Ok(Self {
            client,
            endpoint,
            key,
        })
    }

    /// Sends one request and classifies the outcome.
    async fn send_once(&self, request: &serde_json::Value) -> Result<String, ProviderError> {
        let mut attempt = self.client.post(self.endpoint.clone());
        if let Some(key) = &self.key {
            attempt = attempt.bearer_auth(&key.value);
        }
        let response = attempt
            .json(request)
            .send()
            .await
            .map_err(classify_transport)?;
        let status = response.status();
        if status.is_success() {
            return response
                .text()
                .await
                .map_err(|e| ProviderError::Transport(e.to_string()));
        }
        let code = status.as_u16();
        let body = response
            .text()
            .await
            .map(|text| self.redact_and_cap(&text))
            .unwrap_or_default();
        Err(ProviderError::Status { code, body })
    }

    /// Strips the key from an error body, then caps it.
    ///
    /// A hostile provider can echo the Authorization header back in
    /// its error body. Redacting the key here is what keeps the global
    /// rule true: the key never reaches a log line or a reason phrase.
    fn redact_and_cap(&self, text: &str) -> String {
        let redacted = match &self.key {
            Some(key) => text.replace(&key.value, "<redacted>"),
            None => text.to_string(),
        };
        cap_body(&redacted)
    }
}

#[async_trait]
impl ChatProvider for OpenAiCompatible {
    async fn complete(&self, request: &serde_json::Value) -> Result<String, ProviderError> {
        let first = self.send_once(request).await;
        match first {
            Ok(body) => return Ok(body),
            // The failures worth one retry: 429 and any 5xx. Another 4xx
            // is the provider answering the question, so repeating the
            // same question cannot help.
            Err(ProviderError::Status { code, .. }) if code == 429 || code >= 500 => {}
            Err(e) => return Err(e),
        }
        self.send_once(request).await
    }
}

/// Maps a send failure to [`ProviderError::Timeout`] when it is a
/// timeout, and to `Transport` otherwise.
fn classify_transport(err: reqwest::Error) -> ProviderError {
    if err.is_timeout() {
        return ProviderError::Timeout;
    }
    ProviderError::Transport(err.to_string())
}

/// Caps an error body to [`MAX_ERROR_BODY_BYTES`].
fn cap_body(body: &str) -> String {
    match body.char_indices().nth(MAX_ERROR_BODY_BYTES) {
        Some((idx, _)) => body[..idx].to_string(),
        None => body.to_string(),
    }
}
