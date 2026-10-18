//! `GET /api/reviews`: the unauthenticated JSON listing of every
//! completed AI review, newest first.
//!
//! This is the operator's audit surface: it walks the same append-only
//! `reviews` table the `/why` page reads one row of. A caller filters
//! with `verdict`, `package`, `since` and `before_id`, and caps the page
//! size with `limit` (default 50, maximum 200; an oversized limit clamps
//! to 200 rather than being refused — the caller asked for a lot, which
//! is a legal request, just not an unbounded one).
//!
//! A filter that cannot be honored is a filter that lies to its caller,
//! so an unparseable `limit` or `since`, or a `verdict` outside the
//! three known values, is a 400 — never a silently ignored parameter
//! that returns rows the caller believes were filtered. An empty result
//! is an empty list, never a 404: the query ran fine, nothing matched.
//!
//! Each review carries the stored `StoredReview` contents: the row id,
//! the artifact key, the model verdict, the block flag, the summary,
//! the findings, the coverage figure, the byte counts, the opaque
//! content figures, the reviewed paths, the model, the prompt version,
//! the collector version, and the timestamp. It never carries the
//! provider API key (which is not stored anywhere) and never carries
//! file payload content (which is not stored either).

use axum::body::Body;
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::Serialize;
use url::form_urlencoded;

use crate::db::review::ReviewFilter;
use crate::model::ArtifactKey;

use super::AppState;

/// The page size a request gets when it names none.
const DEFAULT_LIMIT: usize = 50;

/// The largest page this endpoint ever returns. An `limit` above this
/// clamps to it: the request is legal, just bounded.
const MAX_LIMIT: usize = 200;

/// The three verdict values a review row can hold. A `verdict` filter
/// outside this set is a 400, not a silently ignored filter.
const KNOWN_VERDICTS: [&str; 3] = ["clean", "suspicious", "malicious"];

/// One review row as this endpoint serializes it. Every field comes
/// straight out of [`StoredReview`](crate::db::review::StoredReview);
/// nothing is computed, guessed or enriched here.
#[derive(Serialize)]
struct ReviewJson {
    id: i64,
    key: ArtifactKeyJson,
    fingerprint: String,
    verdict: String,
    blocked: bool,
    summary: String,
    findings: Vec<serde_json::Value>,
    coverage: Option<f32>,
    reviewable_bytes_total: i64,
    reviewable_bytes_sent: i64,
    opaque: serde_json::Value,
    reviewed_paths: Vec<String>,
    model: String,
    prompt_version: String,
    collector_version: String,
    reviewed_at: i64,
}

/// The artifact a review judged. Mirrors [`ArtifactKey`] field for field.
#[derive(Serialize)]
struct ArtifactKeyJson {
    ecosystem: String,
    package: String,
    version: String,
    filename: String,
    sha256: String,
}

impl From<&ArtifactKey> for ArtifactKeyJson {
    fn from(key: &ArtifactKey) -> Self {
        ArtifactKeyJson {
            ecosystem: key.ecosystem.clone(),
            package: key.package.clone(),
            version: key.version.clone(),
            filename: key.filename.clone(),
            sha256: key.sha256.clone(),
        }
    }
}

/// The response body: the page of reviews, plus the cursor a caller
/// passes back as `before_id` to fetch the next page. The cursor is
/// `null` on the last page, so the caller stops.
#[derive(Serialize)]
struct ReviewsJson {
    reviews: Vec<ReviewJson>,
    next_before_id: Option<i64>,
}

/// `GET /api/reviews`.
pub async fn reviews_handler(State(state): State<AppState>, RawQuery(query): RawQuery) -> Response {
    let (filter, requested_limit) = match parse_filter(query.as_deref()) {
        Ok(parsed) => parsed,
        Err(detail) => return bad_request(&detail),
    };

    let store = state.reviews.clone();
    let listed = tokio::task::spawn_blocking(move || store.list(&filter)).await;
    let reviews = match listed {
        Ok(Ok(reviews)) => reviews,
        Ok(Err(_)) | Err(_) => return internal_error(),
    };

    // The cursor comes from this page's oldest row. A full page means
    // older rows may exist, so the caller gets the id to continue from.
    // A short page means the end of the history, so the cursor is null.
    let next_before_id = if reviews.len() < requested_limit {
        None
    } else {
        reviews.last().map(|review| review.id)
    };

    let body = ReviewsJson {
        reviews: reviews.iter().map(review_json).collect(),
        next_before_id,
    };
    match serde_json::to_string(&body) {
        Ok(json) => json_response(StatusCode::OK, json),
        Err(_) => internal_error(),
    }
}

/// Parses the query string into a filter, or names what was wrong.
///
/// Returns the filter plus the limit actually in force, so the caller
/// can apply the cursor law without re-parsing: a page that returned
/// exactly as many rows as the limit may have more behind it, so the
/// caller gets a `next_before_id`; a short page is the end.
///
/// Unknown parameters are ignored rather than rejected: the listing has
/// one consumer per deployment and new parameters must not break old
/// callers. The three documented filter parameters, plus `limit`, are
/// the ones a wrong value turns into a 400.
fn parse_filter(query: Option<&str>) -> Result<(ReviewFilter, usize), String> {
    let mut filter = ReviewFilter {
        limit: DEFAULT_LIMIT,
        ..ReviewFilter::default()
    };

    let pairs: Vec<(String, String)> = match query {
        Some(query) => form_urlencoded::parse(query.as_bytes())
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect(),
        None => Vec::new(),
    };

    for (key, value) in pairs {
        match key.as_str() {
            "verdict" => {
                if !KNOWN_VERDICTS.contains(&value.as_str()) {
                    return Err(format!(
                        "unknown verdict filter {value:?}: must be one of clean, suspicious, malicious"
                    ));
                }
                filter.verdict = Some(value);
            }
            "package" => filter.package = Some(value),
            "since" => match value.parse::<i64>() {
                Ok(secs) => filter.since = Some(secs),
                Err(_) => return Err(format!("unparseable since {value:?}: must be an integer")),
            },
            "before_id" => match value.parse::<i64>() {
                Ok(id) => filter.before_id = Some(id),
                Err(_) => {
                    return Err(format!(
                        "unparseable before_id {value:?}: must be an integer"
                    ))
                }
            },
            "limit" => match value.parse::<usize>() {
                Ok(limit) => filter.limit = limit.min(MAX_LIMIT),
                Err(_) => {
                    return Err(format!(
                        "unparseable limit {value:?}: must be a non-negative integer"
                    ))
                }
            },
            // Unknown parameters are not filters and cannot lie about
            // what the caller asked for.
            _ => {}
        }
    }

    let limit = filter.limit;
    Ok((filter, limit))
}

/// Maps one stored row onto its JSON shape. The three `*_json` fields
/// hold already-serialized JSON strings in the row, so they are parsed
/// back into values here; a row whose stored JSON no longer parses is
/// degraded to its empty value rather than failing the whole listing.
fn review_json(review: &crate::db::review::StoredReview) -> ReviewJson {
    let empty_findings: Vec<serde_json::Value> = Vec::new();
    let findings: Vec<serde_json::Value> =
        serde_json::from_str(&review.findings_json).unwrap_or(empty_findings);
    ReviewJson {
        id: review.id,
        key: ArtifactKeyJson::from(&review.key),
        fingerprint: review.fingerprint.clone(),
        verdict: review.verdict.clone(),
        blocked: review.blocked,
        summary: review.summary.clone(),
        findings,
        coverage: review.coverage,
        reviewable_bytes_total: review.reviewable_bytes_total,
        reviewable_bytes_sent: review.reviewable_bytes_sent,
        opaque: serde_json::from_str(&review.opaque_json).unwrap_or_else(|_| serde_json::json!({})),
        reviewed_paths: serde_json::from_str(&review.reviewed_paths_json)
            .unwrap_or_else(|_| serde_json::json!([]))
            .as_array()
            .map(|paths| {
                paths
                    .iter()
                    .filter_map(|path| path.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
        model: review.model.clone(),
        prompt_version: review.prompt_version.clone(),
        collector_version: review.collector_version.clone(),
        reviewed_at: review.reviewed_at,
    }
}

fn bad_request(detail: &str) -> Response {
    plain_response(StatusCode::BAD_REQUEST, detail)
}

fn internal_error() -> Response {
    let mut response = Response::new(Body::from("internal error"));
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
}

fn json_response(status: StatusCode, body: String) -> Response {
    Response::builder()
        .status(status)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| internal_error())
}

fn plain_response(status: StatusCode, body: &str) -> Response {
    Response::builder()
        .status(status)
        .header(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )
        .body(Body::from(format!("{body}\n")))
        .unwrap_or_else(|_| internal_error())
}
