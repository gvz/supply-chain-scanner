//! Supply chain scanner binary: a thin wrapper around the library's own
//! fail-closed startup sequences ([`supply_chain_scanner::http::bootstrap`]
//! for a PyPI deployment, [`supply_chain_scanner::http::bootstrap_cargo`]
//! for a cargo one, [`supply_chain_scanner::http::bootstrap_npm`] for an
//! npm one), plus the operational concerns that only make sense
//! for a real running process — the periodic advisory-sync,
//! cargo-vet-sync and cache-eviction tickers, the `SIGHUP` config-reload
//! handler on the PyPI path, and binding the actual listener.
//!
//! Each deployment spawns only the tickers it needs. An npm deployment
//! syncs OSV's npm feed and evicts the artifact cache; a cargo deployment
//! syncs crates.io and cargo-vet as well; the PyPI deployment syncs its
//! own feed.
//!
//! # Three deployments, one binary
//!
//! `run` dispatches on which ecosystem table is present, checked in the
//! order npm, cargo, neither. A config file with an `[npm_registry]`
//! table is an npm deployment: a packument route, a `.tgz` download gate,
//! and a mandatory reviewer; it gets the npm bootstrap, the npm advisory
//! ticker, and the cache eviction ticker. A config file with a
//! `[cargo_registry]` table is a cargo deployment: a sparse index, a
//! crate-vet fast path, and a `.crate` download; it gets the cargo
//! bootstrap, the cargo advisory ticker for `"crates.io"`, a cargo-vet
//! ticker, and the cache eviction ticker. A config file with neither is
//! the PyPI deployment, unchanged: the PyPI bootstrap, its advisory
//! ticker, its cache eviction ticker, and the `SIGHUP` reload handler.
//!
//! The order is a lookup, not a precedence rule: `Config::validate`
//! already rejects a file carrying both `[cargo_registry]` and
//! `[npm_registry]`, so at most one of the first two branches can match.
//! No process serves two ecosystems, per the design spec.
//!
//! Served HTTP/1.1 only: `axum` and `hyper` are both built here with only
//! the `http1` Cargo feature enabled (see `Cargo.toml`), so this process
//! cannot speak HTTP/2 even if asked to — pip's error reporting depends
//! on the HTTP/1.1 status line's reason phrase, which has no HTTP/2
//! equivalent.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use supply_chain_scanner::ai::collect::collect;
use supply_chain_scanner::artifact_cache::ArtifactCache;
use supply_chain_scanner::config::Config;
use supply_chain_scanner::ecosystem::install_surface::install_surface_for;
use supply_chain_scanner::http::cargo_bootstrap::CARGO_ADVISORY_ECOSYSTEM;
use supply_chain_scanner::http::npm_packument::NPM_ECOSYSTEM;
use supply_chain_scanner::http::{
    bootstrap, bootstrap_cargo, bootstrap_npm, watch_for_reload, RELOADABLE_FIELDS,
    RESTART_ONLY_FIELDS,
};

/// An HTTP proxy that scans PyPI artifacts before serving them.
#[derive(Debug, Parser)]
#[command(name = "supply-chain-scanner", version)]
struct Cli {
    /// Path to the TOML configuration file. The server requires this
    /// flag. A subcommand reads no config.
    #[arg(long)]
    config: Option<PathBuf>,

    /// The subcommand to run. With no subcommand, the process is the
    /// proxy server and reads `--config`.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Collects a package's reviewable source into one JSON payload on
    /// stdout. Invoked by the proxy itself under the sandbox, with the
    /// package mounted read-only and no network. Reads no config file,
    /// opens no database, and starts no runtime.
    Collect {
        /// Package root as mounted inside the sandbox.
        #[arg(long)]
        package_dir: PathBuf,
        /// Ecosystem id, e.g. `pypi`.
        #[arg(long)]
        ecosystem: String,
        /// Cap on the sum of sent file-content bytes.
        #[arg(long)]
        max_payload_bytes: usize,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // The collector arm stays self-contained on purpose: inside the
    // sandbox there is no database, no config file, and no runtime, and
    // none of the server's startup path must run here.
    if let Some(Command::Collect {
        package_dir,
        ecosystem,
        max_payload_bytes,
    }) = cli.command
    {
        return run_collector(&package_dir, &ecosystem, max_payload_bytes);
    }

    let config_path = cli
        .config
        .ok_or_else(|| anyhow::anyhow!("--config is required when no subcommand is given"))?;
    let config = Config::load(&config_path)?;

    let runtime = tokio::runtime::Runtime::new().context("building the tokio runtime")?;
    runtime.block_on(run(config, config_path))
}

/// Runs the `collect` subcommand. `package_dir` is the packaged tree as
/// mounted, so `/pkg` inside the sandbox and a host cache directory
/// alike. An unknown ecosystem or a failed walk exits non-zero through
/// `main`'s error path.
///
/// This path writes the payload JSON to stdout and nothing else.
/// Stdout is the one channel the sandbox carries back to the proxy.
/// The proxy parses it with
/// [`supply_chain_scanner::ai::parse_collector_output`] as a whole
/// document. Stderr goes to a diagnostic log.
fn run_collector(
    package_dir: &Path,
    ecosystem: &str,
    max_payload_bytes: usize,
) -> anyhow::Result<()> {
    let surface = install_surface_for(ecosystem).unwrap_or_else(|| {
        eprintln!("unknown ecosystem: \"{ecosystem}\"");
        std::process::exit(2);
    });

    let payload = collect(package_dir, surface, max_payload_bytes)?;
    serde_json::to_writer(std::io::stdout().lock(), &payload)
        .context("writing the collected payload to stdout")?;
    Ok(())
}

/// Starts one deployment, whichever the configuration selects, and serves
/// it until the process ends.
///
/// The dispatch is a three-way lookup — `[npm_registry]`, then
/// `[cargo_registry]`, then neither — and it is the only place the three
/// deployments diverge in this function. `Config::validate` already
/// rejects a file carrying both ecosystem tables, so the order is a
/// lookup rather than a precedence rule. The PyPI branch below is
/// byte-for-byte the startup this binary has always performed.
async fn run(config: Config, config_path: PathBuf) -> anyhow::Result<()> {
    let bind = config.bind;
    let cache_dir = config.cache_dir.clone();
    let cache_ttl = config.cache_ttl;
    let db_path = config.db_path.clone();
    let advisory_sync_interval = config.advisory_sync_interval;
    let advisory_source_url = config.advisory_source_url.clone();
    let npm = config.npm_registry.clone();
    let cargo = config.cargo_registry.clone();

    tracing::info!(?bind, config = %config_path.display(), "starting up");

    match (npm, cargo) {
        (Some(npm_config), _) => {
            tracing::info!(
                upstream_registry_url = %npm_config.upstream_registry_url,
                min_release_age_days = ?npm_config.min_release_age_days,
                "starting an npm deployment ([npm_registry] is present)"
            );
            let wired = bootstrap_npm(config).await.context("startup failed")?;
            tracing::info!("startup sequence completed; every configured check is available");

            spawn_npm_advisory_sync_ticker(
                db_path.clone(),
                advisory_source_url,
                advisory_sync_interval,
            );
            spawn_cache_eviction_ticker(db_path, cache_dir, cache_ttl);

            // The npm path has no `Reloader` and installs no SIGHUP
            // handler. Say so once, at startup, rather than let an
            // operator send a signal that changes nothing.
            tracing::warn!(
                config = %config_path.display(),
                "SIGHUP configuration reload is a PyPI-path feature and is not \
                 implemented for an npm deployment; a change to this file needs a \
                 restart to take effect"
            );

            serve(bind, wired.router).await
        }
        (None, Some(cargo_config)) => {
            tracing::info!(
                upstream_index = %cargo_config.upstream_index_url,
                cargo_vet_sync_interval = ?cargo_config.cargo_vet_sync_interval,
                cargo_vet_sources = cargo_config.cargo_vet_sources.len(),
                "starting a cargo deployment ([cargo_registry] is present)"
            );
            let wired = bootstrap_cargo(config).await.context("startup failed")?;
            tracing::info!("startup sequence completed; every configured check is available");

            spawn_cargo_advisory_sync_ticker(
                db_path.clone(),
                advisory_source_url,
                advisory_sync_interval,
            );
            spawn_cargo_vet_sync_ticker(db_path.clone(), cargo_config.clone());
            spawn_cache_eviction_ticker(db_path, cache_dir, cache_ttl);

            // The cargo path has no `Reloader` and installs no SIGHUP
            // handler. Say so once, at startup, rather than let an
            // operator send a signal that changes nothing.
            tracing::warn!(
                config = %config_path.display(),
                "SIGHUP configuration reload is a PyPI-path feature and is not \
                 implemented for a cargo deployment; a change to this file needs a \
                 restart to take effect"
            );

            serve(bind, wired.router).await
        }
        (None, None) => {
            let wired = bootstrap(config).await.context("startup failed")?;
            tracing::info!("startup sequence completed; every configured check is available");

            spawn_advisory_sync_ticker(
                db_path.clone(),
                advisory_source_url,
                advisory_sync_interval,
            );
            spawn_cache_eviction_ticker(db_path, cache_dir, cache_ttl);

            // Say up front which fields a later SIGHUP can and cannot
            // change, so an operator learns it from the log rather than
            // from a reload that appeared to succeed.
            //
            // Read from the same constants the reload path enforces,
            // never from a copy of them: this banner once carried its own
            // hardcoded lists and silently fell out of date when `audit`
            // became restart-only, telling every operator the opposite of
            // what a SIGHUP would actually do.
            tracing::info!(
                reloadable = %RELOADABLE_FIELDS.join(", "),
                restart_only = %RESTART_ONLY_FIELDS.join(", "),
                "SIGHUP reloads the fields under `reloadable` (rebuilding the policy, the \
                 fingerprint, the plugin sandbox and, when present, the ai reviewer); a \
                 SIGHUP whose file changes any field under `restart_only` is rejected in \
                 full and names the field"
            );

            let reloader = Arc::clone(&wired.reloader);
            tokio::spawn(async move {
                if let Err(err) = watch_for_reload(reloader, config_path).await {
                    tracing::error!(error = %err, "SIGHUP reload handler exited");
                }
            });

            serve(bind, wired.router).await
        }
    }
}

/// Binds `bind` and serves `router` until the process ends.
///
/// `axum::serve` here only ever negotiates HTTP/1.1: neither `axum` nor
/// `hyper` were built with their `http2` Cargo feature, so the h2 crate is
/// not even compiled into this binary.
///
/// Served via `into_make_service_with_connect_info::<SocketAddr>()` rather
/// than the router directly: every handler that writes an audit record
/// needs the real TCP peer address, extracted via axum's `ConnectInfo`,
/// and that extractor only has something to extract when the service was
/// built this way. Nothing upstream of this process ever sits between it
/// and a client, and `X-Forwarded-For` is deliberately never read (a
/// header a client sent itself could only be a forgery) — the connection's
/// own peer address is the only client identity this proxy ever trusts.
async fn serve(bind: std::net::SocketAddr, router: axum::Router) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding listener on {bind}"))?;
    tracing::info!(%bind, "listening");

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .context("serving HTTP")
}

/// Periodically re-syncs the OSV advisory mirror, reusing one database
/// connection pool and HTTP client for the life of the ticker. A failed
/// sync is logged and simply tried again next tick, leaving the existing
/// mirror untouched in the meantime (see
/// [`supply_chain_scanner::advisory::osv::OsvSync::sync_pypi`]).
fn spawn_advisory_sync_ticker(db_path: PathBuf, source_url: url::Url, interval: Duration) {
    tokio::spawn(async move {
        let db = match supply_chain_scanner::db::Db::open(&db_path)
            .context("opening database for the advisory sync ticker")
        {
            Ok(db) => db,
            Err(err) => {
                tracing::error!(error = %err, "advisory sync ticker could not open the database; it will not run");
                return;
            }
        };
        let http = match reqwest::Client::builder()
            .build()
            .context("building the advisory sync HTTP client")
        {
            Ok(http) => http,
            Err(err) => {
                tracing::error!(error = %err, "advisory sync ticker could not build an HTTP client; it will not run");
                return;
            }
        };
        let store = supply_chain_scanner::db::advisory::AdvisoryStore::new(db);
        let sync = supply_chain_scanner::advisory::osv::OsvSync::new(store, http, source_url);

        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // the first tick fires immediately; bootstrap already synced once.
        loop {
            ticker.tick().await;
            match sync.sync_pypi().await {
                Ok(count) => tracing::info!(count, "advisory mirror synced"),
                Err(err) => tracing::warn!(
                    error = %err,
                    "periodic advisory sync failed; keeping the existing mirror"
                ),
            }
        }
    });
}

/// Periodically re-syncs the crates.io OSV advisory mirror, the cargo
/// deployment's counterpart to [`spawn_advisory_sync_ticker`].
///
/// Same shape, same failure contract: one database pool and one HTTP
/// client for the life of the ticker, a failed sync logged and retried
/// next tick, and the existing mirror left untouched in the meantime (see
/// [`supply_chain_scanner::advisory::osv::OsvSync::sync`]). The ecosystem
/// id and the name normalizer are the only differences, and they are the
/// two arguments `sync` is given.
fn spawn_cargo_advisory_sync_ticker(db_path: PathBuf, source_url: url::Url, interval: Duration) {
    tokio::spawn(async move {
        let db = match supply_chain_scanner::db::Db::open(&db_path)
            .context("opening database for the cargo advisory sync ticker")
        {
            Ok(db) => db,
            Err(err) => {
                tracing::error!(error = %err, "cargo advisory sync ticker could not open the database; it will not run");
                return;
            }
        };
        let http = match reqwest::Client::builder()
            .build()
            .context("building the cargo advisory sync HTTP client")
        {
            Ok(http) => http,
            Err(err) => {
                tracing::error!(error = %err, "cargo advisory sync ticker could not build an HTTP client; it will not run");
                return;
            }
        };
        let store = supply_chain_scanner::db::advisory::AdvisoryStore::new(db);
        let sync = supply_chain_scanner::advisory::osv::OsvSync::new(store, http, source_url);

        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // the first tick fires immediately; bootstrap already synced once.
        loop {
            ticker.tick().await;
            match sync
                .sync(
                    CARGO_ADVISORY_ECOSYSTEM,
                    supply_chain_scanner::ecosystem::cargo::normalize_name,
                )
                .await
            {
                Ok(count) => tracing::info!(count, "crates.io advisory mirror synced"),
                Err(err) => tracing::warn!(
                    error = %err,
                    "periodic crates.io advisory sync failed; keeping the existing mirror"
                ),
            }
        }
    });
}

/// Periodically re-syncs the npm OSV advisory mirror, the npm
/// deployment's counterpart to [`spawn_cargo_advisory_sync_ticker`].
///
/// Same shape, same failure contract: one database pool and one HTTP
/// client for the life of the ticker, a failed sync logged and retried
/// next tick, and the existing mirror left untouched in the meantime (see
/// [`supply_chain_scanner::advisory::osv::OsvSync::sync`]). Only the
/// ecosystem id and the name normalizer differ, and the id is the one
/// constant this deployment stores verdicts under: OSV publishes its npm
/// feed under `"npm"` too, so there is no second spelling to join
/// against.
fn spawn_npm_advisory_sync_ticker(db_path: PathBuf, source_url: url::Url, interval: Duration) {
    tokio::spawn(async move {
        let db = match supply_chain_scanner::db::Db::open(&db_path)
            .context("opening database for the npm advisory sync ticker")
        {
            Ok(db) => db,
            Err(err) => {
                tracing::error!(error = %err, "npm advisory sync ticker could not open the database; it will not run");
                return;
            }
        };
        let http = match reqwest::Client::builder()
            .build()
            .context("building the npm advisory sync HTTP client")
        {
            Ok(http) => http,
            Err(err) => {
                tracing::error!(error = %err, "npm advisory sync ticker could not build an HTTP client; it will not run");
                return;
            }
        };
        let store = supply_chain_scanner::db::advisory::AdvisoryStore::new(db);
        let sync = supply_chain_scanner::advisory::osv::OsvSync::new(store, http, source_url);

        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // the first tick fires immediately; bootstrap already synced once.
        loop {
            ticker.tick().await;
            match sync
                .sync(
                    NPM_ECOSYSTEM,
                    supply_chain_scanner::ecosystem::npm::normalize_name,
                )
                .await
            {
                Ok(count) => tracing::info!(count, "npm advisory mirror synced"),
                Err(err) => tracing::warn!(
                    error = %err,
                    "periodic npm advisory sync failed; keeping the existing mirror"
                ),
            }
        }
    });
}

/// Periodically re-fetches every configured cargo-vet audit source, the
/// cargo deployment's own ticker.
///
/// [`CargoVetSync::sync_all`] already logs and skips a single source's
/// failure and only returns `Err` when every source failed; that error is
/// logged here and retried next tick, exactly like a failed advisory sync.
/// The previous rows for each source stay in place meanwhile, because
/// `replace_source` is the only writer and a failed fetch never reaches
/// it.
fn spawn_cargo_vet_sync_ticker(
    db_path: PathBuf,
    cargo: supply_chain_scanner::config::CargoRegistryConfig,
) {
    tokio::spawn(async move {
        let db = match supply_chain_scanner::db::Db::open(&db_path)
            .context("opening database for the cargo-vet sync ticker")
        {
            Ok(db) => db,
            Err(err) => {
                tracing::error!(error = %err, "cargo-vet sync ticker could not open the database; it will not run");
                return;
            }
        };
        let store = Arc::new(supply_chain_scanner::db::cargo_vet::CargoVetStore::new(db));
        let sync = match supply_chain_scanner::cargovet::CargoVetSync::new(
            store,
            cargo.cargo_vet_sources.clone(),
        ) {
            Ok(sync) => sync,
            Err(err) => {
                tracing::error!(error = %err, "cargo-vet sync ticker could not build a sync; it will not run");
                return;
            }
        };

        let mut ticker = tokio::time::interval(cargo.cargo_vet_sync_interval);
        ticker.tick().await; // the first tick fires immediately; bootstrap already synced once.
        loop {
            ticker.tick().await;
            match sync.sync_all().await {
                Ok(count) => tracing::info!(count, "cargo-vet audit mirror synced"),
                Err(err) => tracing::warn!(
                    error = %err,
                    "periodic cargo-vet sync failed; keeping the existing audits"
                ),
            }
        }
    });
}

/// Periodically evicts artifact-cache entries whose sliding TTL has
/// expired, reusing one database connection pool for the life of the
/// ticker. Purely a performance feature (see
/// [`supply_chain_scanner::artifact_cache::ArtifactCache`]'s own docs):
/// a failed eviction sweep never affects what the scanner is willing to
/// serve.
fn spawn_cache_eviction_ticker(db_path: PathBuf, cache_dir: PathBuf, ttl: Duration) {
    tokio::spawn(async move {
        let cache = match supply_chain_scanner::db::Db::open(&db_path)
            .context("opening database for the cache eviction ticker")
            .and_then(|db| {
                ArtifactCache::new(db, cache_dir)
                    .context("opening artifact cache for the eviction ticker")
            }) {
            Ok(cache) => Arc::new(cache),
            Err(err) => {
                tracing::error!(error = %err, "cache eviction ticker could not start; it will not run");
                return;
            }
        };

        let mut ticker = tokio::time::interval(ttl.max(Duration::from_secs(60)));
        loop {
            ticker.tick().await;
            let cache = Arc::clone(&cache);
            let result = tokio::task::spawn_blocking(move || cache.evict_expired(ttl)).await;

            match result {
                Ok(Ok(removed)) => tracing::info!(removed, "artifact cache eviction swept"),
                Ok(Err(err)) => tracing::warn!(error = %err, "artifact cache eviction failed"),
                Err(join_err) => {
                    tracing::warn!(error = %join_err, "artifact cache eviction task panicked")
                }
            }
        }
    });
}
