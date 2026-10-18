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
use std::time::{Duration, Instant};

use anyhow::Context;
use async_trait::async_trait;

use crate::config::AiReviewConfig;

/// How many bytes of an error response body survive into a
/// [`ProviderError::Status`]. Provider error text is unbounded and
/// attacker-influenced, so it is capped before it can reach a log line.
const MAX_ERROR_BODY_BYTES: usize = 4 * 1024;

/// Sends one chat-completions request and returns the raw response body.
///
/// `remaining` is how much of the caller's overall review deadline is
/// left when the call starts. An implementation that retries must spend
/// no more than `remaining` in total across every attempt — a retry
/// that restarts the clock on a fresh, full-length timeout turns one
/// configured budget into a multiple of itself and can push a review
/// past the scan budget it was supposed to fit inside.
#[async_trait]
pub trait ChatProvider: Send + Sync {
    async fn complete(
        &self,
        request: &serde_json::Value,
        remaining: Duration,
    ) -> Result<String, ProviderError>;
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

    /// Sends one request, capped at `timeout` regardless of the
    /// client's own default, and classifies the outcome.
    async fn send_once(
        &self,
        request: &serde_json::Value,
        timeout: Duration,
    ) -> Result<String, ProviderError> {
        let mut attempt = self.client.post(self.endpoint.clone()).timeout(timeout);
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
    /// Spends no more than `remaining` in total across both attempts: the
    /// first attempt gets the whole of it, and a retry — when the
    /// failure looks transient — gets only what the first attempt did
    /// not use. A failure with nothing left to retry with returns the
    /// first attempt's own error rather than paying for a second call
    /// that would itself be issued with zero time to run.
    async fn complete(
        &self,
        request: &serde_json::Value,
        remaining: Duration,
    ) -> Result<String, ProviderError> {
        if remaining.is_zero() {
            return Err(ProviderError::Timeout);
        }

        let attempt_started = Instant::now();
        let first = self.send_once(request, remaining).await;
        let retryable = matches!(
            &first,
            Err(ProviderError::Status { code, .. }) if *code == 429 || *code >= 500
        );
        if first.is_ok() || !retryable {
            return first;
        }

        let left = remaining.saturating_sub(attempt_started.elapsed());
        if left.is_zero() {
            // The failures worth one retry: 429 and any 5xx. Another 4xx
            // is the provider answering the question, so repeating the
            // same question cannot help — but here there is also
            // nothing left in the budget to retry with.
            return first;
        }
        self.send_once(request, left).await
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

/// Caps an error body to [`MAX_ERROR_BODY_BYTES`] bytes, not characters:
/// a multi-byte-heavy body must not survive at a multiple of the named
/// limit. Backs off to the nearest earlier UTF-8 character boundary so
/// the result is never split mid-character.
fn cap_body(body: &str) -> String {
    if body.len() <= MAX_ERROR_BODY_BYTES {
        return body.to_string();
    }
    let mut end = MAX_ERROR_BODY_BYTES;
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    body[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::{cap_body, MAX_ERROR_BODY_BYTES};

    #[test]
    fn a_body_within_the_cap_is_unchanged() {
        assert_eq!(cap_body("short body"), "short body");
    }

    #[test]
    fn a_multi_byte_heavy_body_is_capped_in_bytes_not_characters() {
        // Each "e" with an acute accent is two UTF-8 bytes, so a byte cap
        // and a character cap diverge sharply here: a char-counting cap
        // would let this body survive at roughly twice the named limit.
        let body: String = std::iter::repeat_n('\u{e9}', MAX_ERROR_BODY_BYTES).collect();
        let capped = cap_body(&body);
        assert!(
            capped.len() <= MAX_ERROR_BODY_BYTES,
            "capped body is {} bytes, over the {MAX_ERROR_BODY_BYTES}-byte limit",
            capped.len()
        );
    }

    #[test]
    fn capping_never_splits_a_multi_byte_character() {
        let body: String = std::iter::repeat_n('\u{e9}', MAX_ERROR_BODY_BYTES).collect();
        // This panics on an invalid UTF-8 boundary, so merely reaching
        // the assertion proves the cap landed on a character edge.
        let capped = cap_body(&body);
        assert!(capped.chars().all(|c| c == '\u{e9}'));
    }
}
