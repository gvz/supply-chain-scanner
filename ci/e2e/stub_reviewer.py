#!/usr/bin/env python3
"""Two stubs the end-to-end container test needs, in one dependency-free server.

`POST /v1/chat/completions` answers like an OpenAI-compatible provider that
reviewed the package and found nothing. npm's cascade has no fast path past AI
review -- `bootstrap_npm` refuses to start without an `[ai_review]` table --
so a reviewer has to exist for the npm leg to run at all. What this test
exercises is the proxy's plumbing, not a model's judgement, so a fixed clean
verdict is the right stand-in: it keeps the result deterministic and spends no
tokens.

`GET /osv/all.zip` answers with a valid, empty OSV archive. The proxy syncs an
advisory mirror on a ticker; pointed at the real feed it would pull tens of
megabytes on every run for data this test does not assert on. An empty mirror
means the CVE gate has nothing to match, which is what makes the *negative*
case below deterministic: that case is driven by release age, not by whichever
advisories happen to exist today.
"""

import io
import json
import os
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# The proxy requires `choices[0].message.content` to be a JSON *string*
# carrying `verdict`, `summary` and `findings`, and rejects any reply whose
# `finish_reason` is "length" (a truncated reply is never trusted).
# `clean` by default. The cargo negative case sets STUB_VERDICT=malicious:
# cargo's release-age gate cannot be relied on against the real crates.io
# (its API answers 403 to this proxy, and the gate then skips itself for that
# request), so the AI gate is the one that refuses deterministically there.
VERDICT = os.environ.get("STUB_VERDICT", "clean")
REVIEW = json.dumps(
    {
        "verdict": VERDICT,
        "summary": f"stub reviewer: fixed {VERDICT} verdict",
        "findings": (
            []
            if VERDICT == "clean"
            else [
                {
                    "path": "stub",
                    "behavior": "stub reviewer was configured to refuse",
                    "severity": "high",
                }
            ]
        ),
    }
)

EMPTY_OSV_ZIP = io.BytesIO()
with zipfile.ZipFile(EMPTY_OSV_ZIP, "w"):
    pass
EMPTY_OSV_ZIP = EMPTY_OSV_ZIP.getvalue()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, b"ok", "text/plain")
        if self.path.endswith("/all.zip"):
            return self._send(200, EMPTY_OSV_ZIP, "application/zip")
        self._send(404, b"not found", "text/plain")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        if not self.path.endswith("/chat/completions"):
            return self._send(404, b"not found", "text/plain")
        body = json.dumps(
            {
                "id": "stub",
                "object": "chat.completion",
                "model": "stub",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": REVIEW},
                    }
                ],
            }
        ).encode()
        self._send(200, body, "application/json")

    def log_message(self, fmt, *args):
        print("stub: " + (fmt % args), flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
