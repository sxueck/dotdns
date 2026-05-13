use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "dotdns")]
#[command(about = "DNS-over-TLS forwarding cache resolver")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Start the DoT server.
    Serve {
        /// Path to the configuration file.
        #[arg(long, short = 'c')]
        config: PathBuf,
    },
    /// Show service status and counters.
    Status {
        /// Path to the configuration file (optional; uses default socket if omitted).
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,
    },
    /// Cache operations.
    #[command(subcommand)]
    Cache(CacheCommands),
    /// Blocklist operations.
    #[command(subcommand)]
    Blocklist(BlocklistCommands),
    /// Show global tracking summary (uptime, queries, cache).
    Tracking {
        /// Path to the configuration file (optional; uses default socket if omitted).
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,
    },
    /// List configured upstream sources.
    Sources {
        /// Path to the configuration file (optional; uses default socket if omitted).
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,
    },
    /// Show per-source statistics.
    Sourcestats {
        /// Path to the configuration file (optional; uses default socket if omitted).
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,
    },
    /// Show current activity (connections, queries, pending).
    Activity {
        /// Path to the configuration file (optional; uses default socket if omitted).
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,
    },
    /// Show per-client DNS statistics.
    Clients {
        /// Path to the configuration file (optional; uses default socket if omitted).
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub enum CacheCommands {
    /// Show cache statistics.
    Stats {
        /// Path to the configuration file (optional; uses default socket if omitted).
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,
    },
    /// Clear all cached entries.
    Flush {
        /// Path to the configuration file (optional; uses default socket if omitted).
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub enum BlocklistCommands {
    /// Reload blocklist files without restarting.
    Reload {
        /// Path to the configuration file (optional; uses default socket if omitted).
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }

    #[test]
    fn cli_parsing() {
        let cases = [
            vec!["dotdns", "serve", "--config", "dotdns.toml"],
            vec!["dotdns", "status"],
            vec!["dotdns", "status", "--config", "dotdns.toml"],
            vec!["dotdns", "cache", "stats"],
            vec!["dotdns", "cache", "stats", "--config", "dotdns.toml"],
            vec!["dotdns", "cache", "flush", "--config", "dotdns.toml"],
            vec!["dotdns", "blocklist", "reload"],
            vec!["dotdns", "blocklist", "reload", "--config", "dotdns.toml"],
            vec!["dotdns", "tracking"],
            vec!["dotdns", "tracking", "--config", "dotdns.toml"],
            vec!["dotdns", "sources"],
            vec!["dotdns", "sources", "--config", "dotdns.toml"],
            vec!["dotdns", "sourcestats"],
            vec!["dotdns", "sourcestats", "--config", "dotdns.toml"],
            vec!["dotdns", "activity"],
            vec!["dotdns", "activity", "--config", "dotdns.toml"],
            vec!["dotdns", "clients"],
            vec!["dotdns", "clients", "--config", "dotdns.toml"],
        ];

        for args in cases {
            Cli::try_parse_from(args).expect("documented CLI form should parse");
        }
    }

    #[test]
    fn rejects_old_flat_blocklist_reload_shape() {
        assert!(Cli::try_parse_from(["dotdns", "blocklist-reload"]).is_err());
    }
}
