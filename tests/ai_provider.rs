//! Integration tests for `supply_chain_scanner::ai::provider` (the
//! OpenAI-compatible chat-completions client) using `wiremock` as a
//! stand-in provider.

use std::time::{Duration, Instant};

use supply_chain_scanner::ai::provider::{ChatProvider, OpenAiCompatible, ProviderError};
use supply_chain_scanner::config::AiReviewConfig;
use url::Url;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The API key the tests set. Every assertion that looks at error text
/// checks for this exact string, so a leak fails the test.
const TEST_KEY: &str = "sk-test-value-that-must-not-leak";
/// The environment variable the key is read from. The name is unique, so
/// concurrent tests cannot fight over it.
const TEST_KEY_ENV: &str = "SCS_TEST_PROVIDER_KEY";

/// Builds an `AiReviewConfig` for a base url with `timeout`.
fn cfg_url(base: Url, timeout: Duration) -> AiReviewConfig {
    AiReviewConfig {
        base_url: base,
        model: "test-model".to_string(),
        api_key_env: Some(TEST_KEY_ENV.to_string()),
        timeout,
        max_payload_bytes: 262_144,
        max_output_tokens: 1024,
        coverage_threshold: 0.8,
        block_on: Default::default(),
        block_opaque_executables: false,
    }
}

/// Builds an `AiReviewConfig` for `server` with `timeout`.
fn cfg(server: &MockServer, timeout: Duration) -> AiReviewConfig {
    let mut base = Url::parse(&server.uri()).expect("mock server url parses");
    base.set_path("/v1/");
    cfg_url(base, timeout)
}

/// Serves the canned success body for `chat/completions`.
async fn mount_success(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SUCCESS_BODY))
        .mount(server)
        .await;
}

const SUCCESS_BODY: &str = r#"{"id":"resp_1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"{\"verdict\":\"clean\"}"},"finish_reason":"stop"}]}"#;

/// Builds the provider with the key set in the environment.
fn provider_with_key(cfg: &AiReviewConfig) -> OpenAiCompatible {
    std::env::set_var(TEST_KEY_ENV, TEST_KEY);
    OpenAiCompatible::new(cfg).expect("provider builds with a configured key")
}

#[tokio::test]
async fn a_successful_call_returns_the_response_body() {
    let server = MockServer::start().await;
    mount_success(&server).await;
    let provider = provider_with_key(&cfg(&server, Duration::from_secs(5)));

    let body = provider
        .complete(&serde_json::json!({"model": "test-model"}))
        .await
        .expect("a 200 with a body must succeed");
    assert_eq!(
        body, SUCCESS_BODY,
        "the caller gets the raw response body to parse itself"
    );
}

#[tokio::test]
async fn the_request_goes_to_chat_completions_under_the_base_url() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SUCCESS_BODY))
        .expect(1)
        .mount(&server)
        .await;
    // Anything hit through a mistaken path gets a distinct status, so a
    // wrong endpoint shows up as an assertion failure rather than a pass.
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&server)
        .await;
    let provider = provider_with_key(&cfg(&server, Duration::from_secs(5)));

    provider
        .complete(&serde_json::json!({"model": "test-model"}))
        .await
        .expect("the request must land under the configured base url");
}

#[tokio::test]
async fn a_configured_key_becomes_a_bearer_header() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header(
            "authorization",
            format!("Bearer {TEST_KEY}").as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string(SUCCESS_BODY))
        .expect(1)
        .mount(&server)
        .await;
    let provider = provider_with_key(&cfg(&server, Duration::from_secs(5)));

    provider
        .complete(&serde_json::json!({"model": "test-model"}))
        .await
        .expect("the bearer header must match the configured key");

    // The received requests confirm the header arrived. The matcher
    // above already proved it: a request without the header cannot
    // satisfy the mock, and the call has succeeded at this point.
}

#[tokio::test]
async fn no_configured_key_sends_no_authorization_header() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_string(SUCCESS_BODY))
        .expect(1)
        .mount(&server)
        .await;
    let mut c = cfg(&server, Duration::from_secs(5));
    c.api_key_env = None;
    let provider = OpenAiCompatible::new(&c).expect("provider builds without a key");

    provider
        .complete(&serde_json::json!({"model": "test-model"}))
        .await
        .expect("a keyless provider must still complete");

    let requests = server.received_requests().await.expect("collect requests");
    assert_eq!(requests.len(), 1, "exactly one request must arrive");
    assert!(
        !requests[0].headers.contains_key("authorization"),
        "no Authorization header may be sent when no key is configured"
    );
}

/// Mounts `once` first, then `then` for every later request. The initial
/// count of `Mock`, once mounted, is private in wiremock, so both
/// expectations are matched in order.
async fn mount_then(once: ResponseTemplate, then: ResponseTemplate, server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(once)
        .up_to_n_times(1)
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(then)
        .mount(server)
        .await;
}

#[tokio::test]
async fn a_429_is_retried_once_and_then_succeeds() {
    let server = MockServer::start().await;
    mount_then(
        ResponseTemplate::new(429),
        ResponseTemplate::new(200).set_body_string(SUCCESS_BODY),
        &server,
    )
    .await;
    let provider = provider_with_key(&cfg(&server, Duration::from_secs(5)));

    let body = provider
        .complete(&serde_json::json!({"model": "test-model"}))
        .await
        .expect("a single 429 followed by 200 must succeed");
    assert_eq!(body, SUCCESS_BODY);
}

#[tokio::test]
async fn a_500_is_retried_once_and_then_succeeds() {
    let server = MockServer::start().await;
    mount_then(
        ResponseTemplate::new(500),
        ResponseTemplate::new(200).set_body_string(SUCCESS_BODY),
        &server,
    )
    .await;
    let provider = provider_with_key(&cfg(&server, Duration::from_secs(5)));

    provider
        .complete(&serde_json::json!({"model": "test-model"}))
        .await
        .expect("a single 500 followed by 200 must succeed");
}

#[tokio::test]
async fn a_second_429_is_a_status_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(429).set_body_string("rate limited"))
        .mount(&server)
        .await;
    let provider = provider_with_key(&cfg(&server, Duration::from_secs(5)));

    let err = provider
        .complete(&serde_json::json!({"model": "test-model"}))
        .await
        .expect_err("a 429 on both attempts must fail");
    match &err {
        ProviderError::Status { code, body } => {
            assert_eq!(*code, 429, "the status error must name the code");
            assert!(
                body.contains("rate limited"),
                "the status error must carry the provider's body"
            );
        }
        other => panic!("expected Status, got {other:?}"),
    }
    // Exactly two requests: the first try and the one retry.
    assert_eq!(
        server
            .received_requests()
            .await
            .expect("collect requests")
            .len(),
        2,
        "exactly one retry may happen"
    );
}

#[tokio::test]
async fn a_400_is_not_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
        .expect(1)
        .mount(&server)
        .await;
    let provider = provider_with_key(&cfg(&server, Duration::from_secs(5)));

    let err = provider
        .complete(&serde_json::json!({"model": "test-model"}))
        .await
        .expect_err("a 400 must fail");
    match &err {
        ProviderError::Status { code, .. } => assert_eq!(*code, 400),
        other => panic!("expected Status, got {other:?}"),
    }
    // exactly one request: the mock's own expectation (1) verified this,
    // and a second request would have returned a 4xx from wiremock,
    // which the provider does not retry.
    assert_eq!(
        server
            .received_requests()
            .await
            .expect("collect requests")
            .len(),
        1,
        "a 400 must not be retried"
    );
}

#[tokio::test]
async fn a_provider_that_hangs_fails_with_timeout_inside_the_configured_timeout() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(SUCCESS_BODY)
                .set_delay(Duration::from_secs(5)),
        )
        .mount(&server)
        .await;
    let provider = provider_with_key(&cfg(&server, Duration::from_millis(300)));

    let started = Instant::now();
    let err = provider
        .complete(&serde_json::json!({"model": "test-model"}))
        .await
        .expect_err("a provider that accepts the connection and then hangs must fail");
    let elapsed = started.elapsed();
    assert!(matches!(err, ProviderError::Timeout), "got {err:?}");
    assert!(
        elapsed < Duration::from_secs(2),
        "a {elapsed:?} call breaks the scan budget; both attempts must stay inside the timeout"
    );
}

#[tokio::test]
async fn the_error_for_a_status_failure_does_not_contain_the_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(500).set_body_string(format!(
            "upstream exploded while authenticating with {TEST_KEY}"
        )))
        .mount(&server)
        .await;
    let provider = provider_with_key(&cfg(&server, Duration::from_secs(5)));

    let err = provider
        .complete(&serde_json::json!({"model": "test-model"}))
        .await
        .expect_err("5xx on both attempts must fail");
    let rendered = format!("{err:?}");
    assert!(
        !rendered.contains(TEST_KEY),
        "the error text must never contain the api key: {rendered}"
    );
    assert!(matches!(err, ProviderError::Status { .. }));
}

#[test]
fn debug_of_the_provider_never_contains_the_key() {
    // `OpenAiCompatible::new` reads the key only through `api_key_env`
    // and keeps it out of every Debug output by construction, because
    // the struct stores the key in a zero-Debug field.
    std::env::set_var(TEST_KEY_ENV, TEST_KEY);
    let base = Url::parse("http://127.0.0.1:9/v1/").expect("static url parses");
    // new() resolves the key and issues no requests, so the unroutable
    // loopback address is never contacted.
    let provider =
        OpenAiCompatible::new(&cfg_url(base, Duration::from_secs(5))).expect("provider builds");
    let rendered = format!("{provider:?}");
    assert!(
        !rendered.contains(TEST_KEY),
        "provider Debug output must never contain the api key: {rendered}"
    );
}
