# syntax=docker/dockerfile:1

# Build stage. The tag matches rust-toolchain.toml's pinned 1.88.0 exactly:
# the image and the repository must not disagree about the compiler.
FROM rust:1.88.0-bookworm AS build

WORKDIR /src

# Dependencies first, so a source-only change does not re-fetch the registry.
COPY Cargo.toml Cargo.lock ./
# A stub main lets the dependency graph build before the real sources exist.
RUN mkdir -p src && \
    echo 'fn main() {}' > src/main.rs && \
    echo '' > src/lib.rs && \
    cargo build --release --locked --quiet 2>/dev/null || true

COPY . .
# `--locked` so a build that would rewrite Cargo.lock fails instead of
# resolving something new: Cargo.toml pins uuid = "=1.11.0" because uuid 1.28
# needs rustc 1.89, and this image is 1.88.0.
# `touch` defeats the stub's mtime, which would otherwise look newer.
RUN touch src/main.rs src/lib.rs && \
    cargo build --release --locked && \
    strip target/release/supply-chain-scanner

# Runtime stage. Debian 12 slim rather than the build image: the compiler,
# the registry cache and the sources have no business in a serving image.
FROM debian:12-slim AS runtime

# ca-certificates: the proxy fetches from registries over HTTPS and cannot
#   verify a chain without them.
# bubblewrap: the plugin sandbox and the AI reviewer's collector run under it.
#   Without it those checks refuse rather than silently pass, so it belongs in
#   the image even though the proxy starts without it.
RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates bubblewrap && \
    rm -rf /var/lib/apt/lists/*

# A dedicated unprivileged account. The proxy needs no root capability: it
# binds a high port, reads its config and writes its own state.
RUN useradd --system --create-home --home-dir /var/lib/supply-chain-scanner \
        --shell /usr/sbin/nologin scanner && \
    mkdir -p /var/lib/supply-chain-scanner/cache /var/log/scanner /etc/supply-chain-scanner && \
    chown -R scanner:scanner /var/lib/supply-chain-scanner /var/log/scanner && \
    # The audit log carries network-attributable data about developers, so its
    # directory is not world-readable — matching what the proxy does to the
    # file itself.
    chmod 0700 /var/log/scanner

COPY --from=build /src/target/release/supply-chain-scanner /usr/local/bin/supply-chain-scanner

USER scanner
WORKDIR /var/lib/supply-chain-scanner

# State and the audit log are the two things worth keeping across restarts.
VOLUME ["/var/lib/supply-chain-scanner", "/var/log/scanner"]

EXPOSE 8080

# No default config is baked in: which ecosystem this process serves is
# decided entirely by the config file mounted at this path.
ENTRYPOINT ["/usr/local/bin/supply-chain-scanner"]
CMD ["--config", "/etc/supply-chain-scanner/config.toml"]
