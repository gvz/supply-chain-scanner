//! Supply chain scanner binary. This task only wires up config loading and
//! logging; the HTTP server itself arrives in a later task.

use std::path::PathBuf;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use supply_chain_scanner::config::Config;

/// An HTTP proxy that scans PyPI artifacts before serving them.
#[derive(Debug, Parser)]
#[command(name = "supply-chain-scanner", version)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long)]
    config: PathBuf,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;

    tracing::info!(?config, "configuration loaded");

    Ok(())
}
