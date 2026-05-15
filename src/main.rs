mod blocklist;
mod cache;
mod cli;
mod config;
mod doh;
mod management;
mod metrics;
mod observability;
mod server;
mod upstream;

use crate::blocklist::ReloadableBlocklist;
use crate::cache::Cache;
use crate::cli::{BlocklistCommands, CacheCommands, Cli, Commands};
use crate::config::{Config, ManagementTransport, UpstreamSelectionPolicy};
use crate::management::{ManagementClient, ManagementServer};
use crate::metrics::{load_stats, save_stats, MetricsRecorder};
use crate::observability::{ClientSnapshot, UpstreamSnapshot};
use crate::server::Server;
use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

#[tokio::main]
async fn main() {
    // rustls needs this explicitly in recent versions
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
        Commands::Tracking { config } => {
            let transport = load_mgmt_transport(config);
            let client = ManagementClient::new(transport);
            match client.tracking().await {
                Ok(snap) => println!("{}", snap.to_human_string()),
                Err(e) => {
                    eprintln!("tracking: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Sources { config } => {
            let (transport, policy) = load_mgmt_connection(config);
            let client = ManagementClient::new(transport);
            match client.sources().await {
                Ok(upstreams) => {
                    println!("{}", format_upstreams(&upstreams, policy.as_ref()));
                }
                Err(e) => {
                    eprintln!("sources: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Sourcestats { config } => {
            let (transport, policy) = load_mgmt_connection(config);
            let client = ManagementClient::new(transport);
            match client.sourcestats().await {
                Ok(upstreams) => {
                    println!("{}", format_upstreams(&upstreams, policy.as_ref()));
                }
                Err(e) => {
                    eprintln!("sourcestats: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Activity { config } => {
            let transport = load_mgmt_transport(config);
            let client = ManagementClient::new(transport);
            match client.activity().await {
                Ok(snap) => println!("{}", format_activity(&snap)),
                Err(e) => {
                    eprintln!("activity: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Clients { config } => {
            let transport = load_mgmt_transport(config);
            let client = ManagementClient::new(transport);
            match client.clients().await {
                Ok(clients) => println!("{}", format_clients(&clients)),
                Err(e) => {
                    eprintln!("clients: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}

fn format_upstreams(
    upstreams: &[UpstreamSnapshot],
    selection_policy: Option<&UpstreamSelectionPolicy>,
) -> String {
    if upstreams.is_empty() {
        return "no upstreams configured".into();
    }
    let mut lines = Vec::new();
    if let Some(policy) = selection_policy {
        lines.push(format!("selection policy: {}", policy));
    }
    lines.push(format!(
        "{:20} {:>10} {:>10} {:>10} {:>12} {:>12}",
        "name", "successes", "failures", "timeouts", "last_lat_ms", "avg_lat_ms"
    ));
    for u in upstreams {
        lines.push(format!(
            "{:20} {:>10} {:>10} {:>10} {:>12} {:>12}",
            u.name,
            u.success_count,
            u.failure_count,
            u.timeout_count,
            u.last_success_latency_ms
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            u.avg_success_latency_ms
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
        ));
    }
    lines.join("\n")
}

fn format_activity(snap: &crate::metrics::MetricsSnapshot) -> String {
    format!(
        "uptime: {}\n\
         total queries: {}\n\
         accepted connections: {}\n\
         active connections: {}\n\
         pending leaders: {}\n\
         pending followers: {}\n\
         pending follower timeouts: {}\n\
         pending follower successes: {}",
        crate::metrics::format_uptime(snap.uptime_secs),
        snap.total_queries,
        snap.accepted_connections,
        snap.active_connections,
        snap.pending_leaders,
        snap.pending_followers,
        snap.pending_follower_timeouts,
        snap.pending_follower_successes,
    )
}

fn format_clients(clients: &[ClientSnapshot]) -> String {
    if clients.is_empty() {
        return "no clients tracked".into();
    }
    let mut lines = vec![format!(
        "{:20} {:>12} {:>10} {:>10} {:>10} {:>10}",
        "ip", "queries", "blocked", "cache_hits", "cache_misses", "active_conn"
    )];
    for c in clients {
        lines.push(format!(
            "{:20} {:>12} {:>10} {:>10} {:>10} {:>10}",
            c.ip,
            c.total_queries,
            c.blocked_queries,
            c.cache_hits,
            c.cache_misses,
            c.active_connections,
        ));
    }
    lines.join("\n")
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
    load_mgmt_config(config)
        .map(|cfg| cfg.management.transport)
        .unwrap_or_default()
}

fn load_mgmt_connection(
    config: Option<PathBuf>,
) -> (ManagementTransport, Option<UpstreamSelectionPolicy>) {
    let cfg = load_mgmt_config(config);
    let policy = cfg.as_ref().map(|c| c.upstream_selection_policy);
    let transport = cfg.map(|c| c.management.transport).unwrap_or_default();
    (transport, policy)
}

fn load_mgmt_config(config: Option<PathBuf>) -> Option<Config> {
    match config.or_else(default_config_path) {
        Some(path) => {
            let source = fs::read_to_string(&path).unwrap_or_else(|e| {
                eprintln!("failed to read config {}: {}", path.display(), e);
                std::process::exit(1);
            });
            let cfg = Config::from_toml(&source).unwrap_or_else(|e| {
                eprintln!("config error: {}", e);
                std::process::exit(1);
            });
            Some(cfg)
        }
        None => None,
    }
}

fn default_config_path() -> Option<PathBuf> {
    let path = PathBuf::from("/etc/dotdns/dotdns.toml");
    path.exists().then_some(path)
}

async fn run_serve(cfg: Config) {
    let cfg = Arc::new(cfg);
    if let Err(e) = server::validate_tls_config(&cfg) {
        eprintln!("TLS certificate validation failed: {}", e);
        std::process::exit(1);
    }

    let metrics = match load_stats(&cfg.stats_path) {
        Some(persisted) => {
            tracing::info!("restored metrics from {}", cfg.stats_path.display());
            Arc::new(MetricsRecorder::from_persisted(&persisted))
        }
        None => Arc::new(MetricsRecorder::new()),
    };

    let cache = Arc::new(Cache::new(cfg.cache.clone(), metrics.clone()));
    let blocklist = Arc::new(ReloadableBlocklist::from_config(&cfg.blocklist));
    if cfg.blocklist.enabled {
        match blocklist.refresh_and_reload().await {
            Ok(report) => {
                tracing::info!("blocklist loaded: {}", report);
            }
            Err(e) => {
                tracing::warn!(error = %e, "initial blocklist load failed");
            }
        }
    }
    if let (true, Some(interval)) = (cfg.blocklist.enabled, cfg.blocklist.refresh_interval) {
        let blocklist = blocklist.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                match blocklist.refresh_and_reload().await {
                    Ok(report) => tracing::info!("blocklist refreshed: {}", report),
                    Err(e) => tracing::warn!(error = %e, "blocklist refresh failed"),
                }
            }
        });
    }
    let upstream_names: Vec<String> = cfg.upstreams.iter().map(|e| e.name.clone()).collect();
    let observability = Arc::new(crate::observability::ObservabilityRegistry::with_upstreams(
        &upstream_names,
    ));

    let pool = match upstream::pool_from_config(
        &cfg.upstreams,
        &cfg.bootstrap.dns,
        Some(metrics.clone()),
        Some(observability.clone()),
        cfg.upstream_selection_policy,
    ) {
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
        pool.clone(),
        Some(observability.clone()),
    );
    let mgmt_server = ManagementServer::new(
        cfg.management.clone(),
        metrics.clone(),
        cache.clone(),
        blocklist.clone(),
        Some(observability.clone()),
    );
    let doh_server = cfg.doh.as_ref().map(|_| {
        let doh_state = doh::DohState {
            metrics: metrics.clone(),
            cache: cache.clone(),
            blocklist: blocklist.clone(),
            pool: pool.clone(),
            pending: server::PendingQueries::new(metrics.clone()),
            edns: cfg.edns.clone(),
            blocklist_config: cfg.blocklist.clone(),
            observability: Some(observability.clone()),
        };
        match doh::DohServer::new(&cfg, doh_state) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("failed to build DoH server: {}", e);
                std::process::exit(1);
            }
        }
    });

    let metrics_for_save = metrics.clone();
    let stats_path = cfg.stats_path.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        loop {
            ticker.tick().await;
            let m = metrics_for_save.to_persisted();
            let p = stats_path.clone();
            match tokio::task::spawn_blocking(move || save_stats(&p, &m)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!(error = %e, "periodic stats save failed"),
                Err(e) => tracing::warn!(error = %e, "stats save task panicked"),
            }
        }
    });

    info!("dotdns starting");
    info!("listening on {:?} (DoT)", cfg.server.binds);
    info!("upstreams: {}", cfg.upstreams.len());

    if let Some(ref doh_cfg) = cfg.doh {
        info!("DoH listening on {:?}", doh_cfg.binds);
    }

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
        result = async {
            match doh_server {
                Some(s) => s.run().await,
                None => std::future::pending().await,
            }
        } => {
            if let Err(e) = result {
                eprintln!("DoH server error: {}", e);
                std::process::exit(1);
            }
        }
        _ = wait_for_shutdown() => {
            info!("shutting down");
        }
    }

    if let Err(e) = save_stats(&cfg.stats_path, &metrics.to_persisted()) {
        tracing::warn!(error = %e, "final stats save failed");
    }
}

#[cfg(unix)]
async fn wait_for_shutdown() {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = sigterm.recv() => {},
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown() {
    tokio::signal::ctrl_c().await.ok();
}
