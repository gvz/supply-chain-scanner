# The artifact cache

`src/artifact_cache.rs` — a content-addressed, on-disk cache of scanned artifact bytes, with a sliding TTL. Purely a performance feature sitting in front of upstream downloads.

## Cache vs. verdicts — the important distinction

The verdict database is the **durable record** of whether an artifact may be served. The cache is **only bytes**. Emptying the cache never changes what the proxy decides to serve, only how long that takes. A cache miss just means a re-download, re-verify, re-insert.

## Layout

```text
<cache_dir>/<sha256[0..2]>/<sha256>
```

Paths are the content hash. Identical bytes shipped under different filenames (or by different packages entirely) are stored once. The two-character prefix keeps any one directory's fan-out sane.

The `artifact_cache` table is keyed by `sha256` alone for the same reason. Descriptive columns (ecosystem, package, version, filename, bytes) are kept anyway, so an operator inspecting the database can tell what a cached blob actually is.

## The sliding TTL

The TTL is sliding, not fixed: every `get` refreshes the entry's `last_access`. A package the org installs constantly is therefore never evicted, while one-off downloads age out. Default TTL is 24h (`cache_ttl`).

`evict_expired(ttl)` deletes both the database row and the file for entries whose `last_access` is older than the cutoff. It retries a file it could not delete. A transient lock or read-only mount must not prevent the next pass from trying again. This behavior is pinned by a dedicated test in `tests/artifact_cache.rs`.

## Who uses it

- The **full scan** checks the cache before downloading, so a rescan forced only by a policy change does not pay for a redundant download.
- The **allowlist and stored-clean paths** serve straight from a cache hit. A hit is content-addressed, so the bytes are already known to match the index-declared hash. A miss means download-verify-cache.
- A cached hit fed to unpacking goes through a **symlink carrying the real filename** (`src/scan/mod.rs`, `symlink_for_unpack`). This is needed because `unpack` recognizes the archive format by filename extension, and cache paths have none.