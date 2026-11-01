# The HTTP surface

`src/http/` — the part of the system a blocked developer actually sees: refusal responses and the `/why/<id>` page.

> **Status:** the response builders and the `/why` handler are implemented and tested. The router wiring — the simple-index and artifact-download handlers that call them — is not yet built (see the [roadmap](./roadmap.md)).

## The reason phrase is the channel

pip never prints an HTTP response body (verified against pip 25.3: `pip/_internal/network/utils.py` builds its error message from the status code and reason phrase alone). What pip does print is the status line's reason phrase and the requested URL.

So the reason phrase carries the message: which check refused the request, and where to read the detail. This drives two design decisions:

- The client-facing protocol is **HTTP/1.1 only** — HTTP/2 has no reason phrase.
- The phrase is a **security boundary**. Package names, advisory summaries, and plugin stdout all flow into it. Unsanitized, that is HTTP response splitting.

## Sanitization

`sanitize_phrase` in `src/http/refusal.rs` keeps printable ASCII (0x20–0x7E) only. Every control byte (CR and LF in particular) and every non-ASCII byte is dropped. The result is then capped at 120 bytes. Filtering happens *before* the cap, so the cap only ever slices one-byte characters.

Every layer sanitizes independently: advisory matching, the plugin runner, and the scan pipeline each strip their own output. This module sanitizes again because it is the boundary that actually reaches the wire. No layer trusts another.

## Status codes, chosen for pip's behavior

| Status | Meaning | Why this code |
|---|---|---|
| **403** | Blocked. | The refusal status. pip surfaces the phrase. |
| **429** | Scan still running. | Deliberately not 503: pip's session auto-retries 500/503 (urllib3's `status_forcelist`), which would bury the message. 429 surfaces straight to the developer. |
| **503** | Cannot verify right now. | Here the automatic retry is desirable. The phrase always says `UNVERIFIABLE`, never `BLOCKED`. "We could not check" and "we checked and it is bad" must never look the same to a developer. |

## The BLOCKED phrase

A 403's phrase is shaped:

```text
BLOCKED <code> - why <public_url>/why/<id>
```

The length is budgeted. When the combined phrase would exceed 120 bytes, the variable-length `code` gets ellipsized, **never the why URL**. A truncated URL looks clickable and is not. The URL is the path to the detail page that exists to be clicked. If even the scaffold plus URL cannot fit (an absurdly long `public_url`), the code is dropped entirely. A developer with a link can always find the code on the page it points to.

A refusal with nothing stored behind it (a hash mismatch, never persisted as a verdict) sends just `BLOCKED <code>` — there is no `/why` page to link to.

Every response also repeats the same sanitized text in a plain-text body, for clients that are not pip: curl, browsers, other installers actually render bodies.

## The "why" page

`GET /why/<id>` (`src/http/why.rs`) resolves a `why_id` back to the artifact and verdict it was issued for. It renders a server-generated HTML explanation: which check failed, the full detail, the artifact identity (package, version, filename, sha256), and when it was scanned.

- Every stored field is **HTML-escaped** on render — including `RefusalReason.detail`, which can contain attacker-influenced text that originated inside the blocked package. The page must not become the delivery vehicle for what the scan caught.
- An unknown or expired `why_id` is a **404**. A `why_id` lives exactly as long as its verdict row. Once that row is gone, there is nothing to explain.
- A lookup failure is a generic **500**, never a fabricated 200 — it falls back rather than guessing at content that was never read.
- The page's "what you can do" section points a blocked developer at the two org-side remedies. For a reviewed-and-accepted package: an allowlist entry. For a wrongly severe finding: the CVE-line settings.

## Refused to render a refusal

Even the failure path fails closed. If response building itself somehow fails, the fallback sends the refusal status with a hardcoded safe phrase. Never a 200, never a pass-through. `tests/http_refusal.rs` pins the sanitization, the phrase budgeting, and the truncation-priority rules.

## No route exposes the audit log, or a client IP

This surface is deliberately missing a route: there is no HTTP endpoint, on any deployment, that reads back the fetch audit log described in [the audit log chapter](./audit-log.md). The client IP that log records exists in exactly one place in this proxy — that log file — and every route listed above, being unauthenticated and read by the same developers whose fetches are logged, must never become a way to read it back out. `/refusals`, `/why/<id>` and `/api/reviews` render package, version, filename and reason; none of them carries a `client_ip` field, because nothing upstream of rendering ever put one there — the verdict store itself has no IP column to read. This is a constraint by construction, not a filter applied at render time.