mod blocklist;
mod cache;
mod cli;
mod config;
mod management;
mod metrics;
mod server;
mod upstream;

use crate::blocklist::ReloadableBlocklist;
use crate::cache::Cache;
use crate::cli::{BlocklistCommands, CacheCommands, Cli, Commands};
use crate::config::{Config, ManagementTransport};
use crate::management::{ManagementClient, ManagementServer};
use crate::metrics::MetricsRecorder;
use crate::server::Server;
use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() {
    // Ensure the rustls ring crypto provider is installed before any TLS usage.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("ring crypto provider install");

    let cli = Cli::parse();

    match cli.command {
        Commands::Serve { config } => {
            let source = fs::read_to_string(&config).unwrap_or_else(|e| {
                eprintln!("failed to read config {}: {}", config.display(), e);
                std::process::exit(1);
            });
            let cfg = Config::from_toml(&source).unwrap_or_else(|e| {
                eprintln!("config error: {}", e);
                std::process::exit(1);
            });
            init_logging(&cfg);
            run_serve(cfg).await;
        }
        Commands::Status { config } => {
            let transport = load_mgmt_transport(config);
            let client = ManagementClient::new(transport);
            match client.status().await {
                Ok(snap) => println!("{}", snap.to_human_string()),
                Err(e) => {
                    eprintln!("status: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Cache(sub) => match sub {
            CacheCommands::Stats { config } => {
                let transport = load_mgmt_transport(config);
                let client = ManagementClient::new(transport);
                match client.status().await {
                    Ok(snap) => {
                        println!(
                            "entries: {}\nhits: {}\nmisses: {}",
                            snap.cache_entries, snap.cache_hits, snap.cache_misses
                        );
                    }
                    Err(e) => {
                        eprintln!("cache stats: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            CacheCommands::Flush { config } => {
                let transport = load_mgmt_transport(config);
                let client = ManagementClient::new(transport);
                if let Err(e) = client.cache_flush().await {
                    eprintln!("cache flush: {}", e);
                    std::process::exit(1);
                }
                println!("cache flushed");
            }
        },
        Commands::Blocklist(sub) => match sub {
            BlocklistCommands::Reload { config } => {
                let transport = load_mgmt_transport(config);
                let client = ManagementClient::new(transport);
                if let Err(e) = client.blocklist_reload().await {
                    eprintln!("blocklist reload: {}", e);
                    std::process::exit(1);
                }
                println!("blocklist reload requested");
            }
        },
    }
}

fn init_logging(cfg: &Config) {
    let filter = tracing_subscriber::EnvFilter::new(&cfg.logging.level);
    match cfg.logging.format {
        config::LogFormat::Pretty => {
            tracing_subscriber::fmt()
                .pretty()
                .with_env_filter(filter)
                .init();
        }
        config::LogFormat::Json => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .init();
        }
        config::LogFormat::Compact => {
            tracing_subscriber::fmt()
                .compact()
                .with_env_filter(filter)
                .init();
        }
    }
}

fn load_mgmt_transport(config: Option<PathBuf>) -> ManagementTransport {
    match config {
        Some(path) => {
            let source = fs::read_to_string(&path).unwrap_or_else(|e| {
                eprintln!("failed to read config {}: {}", path.display(), e);
                std::process::exit(1);
            });
            let cfg = Config::from_toml(&source).unwrap_or_else(|e| {
                eprintln!("config error: {}", e);
                std::process::exit(1);
            });
            cfg.management.transport
        }
        None => ManagementTransport::default(),
    }
}

async fn run_serve(cfg: Config) {
    let cfg = Arc::new(cfg);
    let metrics = Arc::new(MetricsRecorder::new());
    let cache = Arc::new(Cache::new(cfg.cache.clone(), metrics.clone()));
    let blocklist = Arc::new(ReloadableBlocklist::new(cfg.blocklist.paths.clone()));
    if cfg.blocklist.enabled {
        match blocklist.reload() {
            Ok(report) => {
                tracing::info!("blocklist loaded: {}", report);
            }
            Err(e) => {
                tracing::warn!(error = %e, "initial blocklist load failed");
            }
        }
    }
    let pool = match upstream::pool_from_config(&cfg.upstreams, Some(metrics.clone())) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("failed to build upstream pool: {}", e);
            std::process::exit(1);
        }
    };
    let server = Server::new(
        cfg.clone(),
        metrics.clone(),
        cache.clone(),
        blocklist.clone(),
        pool,
    );
    let mgmt_server = ManagementServer::new(
        cfg.management.clone(),
        metrics.clone(),
        cache.clone(),
        blocklist.clone(),
    );

    info!("dotdns starting");
    info!("listening on {} (DoT)", cfg.server.bind);
    info!("upstreams: {}", cfg.upstreams.len());

    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                eprintln!("server error: {}", e);
                std::process::exit(1);
            }
        }
        result = mgmt_server.run() => {
            if let Err(e) = result {
                eprintln!("management server error: {}", e);
                std::process::exit(1);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("shutting down");
        }
    }
}
