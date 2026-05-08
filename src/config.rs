use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required field: {0}")]
    MissingField(String),
    #[error("invalid value for {field}: {message}")]
    InvalidValue { field: String, message: String },
    #[error("no upstreams configured")]
    NoUpstreams,
    #[error("blocklist path does not exist: {0}")]
    BlocklistPathNotFound(PathBuf),
    #[error("TLS certificate and private key are both required when TLS is enabled")]
    TlsIncomplete,
    #[error("management bind must be loopback when using TCP (found {0})")]
    ManagementNotLoopback(String),
}

/// Top-level configuration for dotdns.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub upstreams: Vec<UpstreamEntry>,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub blocklist: BlocklistConfig,
    #[serde(default)]
    pub management: ManagementConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

impl Config {
    /// Parse config from a TOML string.
    pub fn from_toml(source: &str) -> Result<Self, ConfigError> {
        let cfg: Config = toml::from_str(source).map_err(|e| ConfigError::InvalidValue {
            field: "config".into(),
            message: e.to_string(),
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate business rules beyond deserialization.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.upstreams.is_empty() {
            return Err(ConfigError::NoUpstreams);
        }
        for (i, u) in self.upstreams.iter().enumerate() {
            if u.address.is_empty() {
                return Err(ConfigError::InvalidValue {
                    field: format!("upstreams[{}].address", i),
                    message: "upstream address must not be empty".into(),
                });
            }
            if u.protocol == UpstreamProtocol::Tls {
                let host = host_from_address(&u.address);
                if host.parse::<IpAddr>().is_ok() {
                    return Err(ConfigError::InvalidValue {
                        field: format!("upstreams[{}].address", i),
                        message: "DoT upstream address must use a hostname, not an IP address, for TLS certificate validation".into(),
                    });
                }
            }
        }
        if self.tls.enabled {
            if self.tls.cert_path.is_none() || self.tls.key_path.is_none() {
                return Err(ConfigError::TlsIncomplete);
            }
        }
        if let ManagementTransport::Tcp { bind } = &self.management.transport {
            if !is_loopback(bind) {
                return Err(ConfigError::ManagementNotLoopback(bind.to_string()));
            }
        }
        for path in &self.blocklist.paths {
            if !path.exists() {
                return Err(ConfigError::BlocklistPathNotFound(path.clone()));
            }
        }
        Ok(())
    }
}

fn is_loopback(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

/// Extract the host portion from an address string that may include a port.
fn host_from_address(address: &str) -> &str {
    if let Some(rest) = address.strip_prefix('[') {
        if let Some((host, _)) = rest.split_once(']') {
            return host;
        }
    } else if let Some((host, _)) = address.rsplit_once(':') {
        return host;
    }
    address
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    /// Address to bind the DoT server.
    pub bind: SocketAddr,
    /// Connection idle timeout.
    #[serde(default = "default_idle_timeout", with = "humantime_serde")]
    pub idle_timeout: Duration,
}

fn default_idle_timeout() -> Duration {
    Duration::from_secs(60)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: None,
            key_path: None,
        }
    }
}

/// Supported upstream protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    Plain,
    #[serde(rename = "dot")]
    Tls,
    #[serde(rename = "doh")]
    Https,
}

impl Default for UpstreamProtocol {
    fn default() -> Self {
        UpstreamProtocol::Plain
    }
}

impl fmt::Display for UpstreamProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpstreamProtocol::Plain => write!(f, "plain"),
            UpstreamProtocol::Tls => write!(f, "dot"),
            UpstreamProtocol::Https => write!(f, "doh"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamEntry {
    /// Human-readable name.
    pub name: String,
    /// Endpoint address (e.g., `1.1.1.1:53`, `cloudflare-dns.com:853`).
    /// For DoT, use a hostname rather than an IP address so TLS SNI and
    /// certificate validation work correctly. IPv6 addresses must be wrapped
    /// in brackets (e.g., `[2001:db8::1]:853`).
    pub address: String,
    /// Protocol to use.
    #[serde(default)]
    pub protocol: UpstreamProtocol,
    /// Optional TLS certificate path for DoT/DoH when pinning is desired.
    pub tls_cert_path: Option<PathBuf>,
    /// Optional HTTP/2 settings for DoH (e.g., `h2_only`).
    #[serde(default)]
    pub extra: HashMap<String, toml::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CacheConfig {
    /// Maximum number of cached entries.
    #[serde(default = "default_cache_capacity")]
    pub capacity: usize,
    /// Minimum TTL to enforce (clamps response TTL).
    #[serde(default, with = "humantime_serde")]
    pub min_ttl: Option<Duration>,
    /// Maximum TTL to enforce (clamps response TTL).
    #[serde(default, with = "humantime_serde")]
    pub max_ttl: Option<Duration>,
    /// Whether to serve stale entries while refreshing in background.
    #[serde(default)]
    pub serve_stale: bool,
}

fn default_cache_capacity() -> usize {
    10_000
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            capacity: default_cache_capacity(),
            min_ttl: None,
            max_ttl: None,
            serve_stale: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlocklistConfig {
    /// Paths to AdGuard-compatible blocklist files.
    #[serde(default)]
    pub paths: Vec<PathBuf>,
    /// Enable blocklist matching.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            enabled: true,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ManagementConfig {
    #[serde(flatten, default)]
    pub transport: ManagementTransport,
}

impl Default for ManagementConfig {
    fn default() -> Self {
        Self {
            transport: ManagementTransport::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ManagementTransport {
    Unix { path: PathBuf },
    Tcp { bind: SocketAddr },
}

impl Default for ManagementTransport {
    fn default() -> Self {
        ManagementTransport::Unix {
            path: PathBuf::from("/tmp/dotdns.sock"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub format: LogFormat,
}

fn default_log_level() -> String {
    "info".into()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Pretty,
    Json,
    Compact,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parse_minimal_config() {
        let source = r#"
[server]
bind = "0.0.0.0:853"

[[upstreams]]
name = "cloudflare"
address = "1.1.1.1:53"
protocol = "plain"
"#;
        let cfg = Config::from_toml(source).unwrap();
        assert_eq!(cfg.server.bind.port(), 853);
        assert_eq!(cfg.upstreams.len(), 1);
        assert_eq!(cfg.upstreams[0].protocol, UpstreamProtocol::Plain);
    }

    #[test]
    fn reject_empty_upstreams() {
        let source = r#"
[server]
bind = "0.0.0.0:853"
"#;
        let err = Config::from_toml(source).unwrap_err();
        assert!(matches!(err, ConfigError::NoUpstreams));
    }

    #[test]
    fn reject_missing_tls_files_when_enabled() {
        let source = r#"
[server]
bind = "0.0.0.0:853"

[tls]
enabled = true

[[upstreams]]
name = "cf"
address = "1.1.1.1:53"
"#;
        let err = Config::from_toml(source).unwrap_err();
        assert!(matches!(err, ConfigError::TlsIncomplete));
    }

    #[test]
    fn reject_dot_upstream_with_ip_address() {
        let source = r#"
[server]
bind = "0.0.0.0:853"

[[upstreams]]
name = "cf-dot"
address = "1.1.1.1:853"
protocol = "dot"
"#;
        let err = Config::from_toml(source).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn reject_dot_upstream_with_ipv6_address() {
        let source = r#"
[server]
bind = "0.0.0.0:853"

[[upstreams]]
name = "cf-dot"
address = "[2001:db8::1]:853"
protocol = "dot"
"#;
        let err = Config::from_toml(source).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    #[test]
    fn reject_management_bind_non_loopback() {
        let source = r#"
[server]
bind = "0.0.0.0:853"

[management]
type = "tcp"
bind = "0.0.0.0:9953"

[[upstreams]]
name = "cf"
address = "1.1.1.1:53"
"#;
        let err = Config::from_toml(source).unwrap_err();
        assert!(matches!(err, ConfigError::ManagementNotLoopback(_)));
    }

    #[test]
    fn default_management_is_unix_socket() {
        let source = r#"
[server]
bind = "0.0.0.0:853"

[[upstreams]]
name = "cf"
address = "1.1.1.1:53"
"#;
        let cfg = Config::from_toml(source).unwrap();
        match &cfg.management.transport {
            ManagementTransport::Unix { path } => {
                assert_eq!(path, &PathBuf::from("/tmp/dotdns.sock"));
            }
            other => panic!("expected unix socket default, got {:?}", other),
        }
    }

    #[test]
    fn loopback_management_tcp_is_ok() {
        let source = r#"
[server]
bind = "0.0.0.0:853"

[management]
type = "tcp"
bind = "127.0.0.1:9953"

[[upstreams]]
name = "cf"
address = "1.1.1.1:53"
"#;
        let cfg = Config::from_toml(source).unwrap();
        match &cfg.management.transport {
            ManagementTransport::Tcp { bind } => {
                assert_eq!(bind.ip(), Ipv4Addr::new(127, 0, 0, 1));
            }
            other => panic!("expected tcp management, got {:?}", other),
        }
    }

    #[test]
    fn parse_full_config() {
        let source = r#"
[server]
bind = "0.0.0.0:853"
idle_timeout = "2m"

[tls]
enabled = true
cert_path = "/etc/dotdns/cert.pem"
key_path = "/etc/dotdns/key.pem"

[[upstreams]]
name = "cloudflare-dot"
address = "cloudflare-dns.com:853"
protocol = "dot"

[[upstreams]]
name = "cloudflare-doh"
address = "https://cloudflare-dns.com/dns-query"
protocol = "doh"

[cache]
capacity = 50000
min_ttl = "5s"
max_ttl = "1h"
serve_stale = true

[blocklist]
enabled = true
paths = []

[management]
type = "unix"
path = "/var/run/dotdns.sock"

[logging]
level = "debug"
format = "json"
"#;
        let cfg = Config::from_toml(source).unwrap();
        assert_eq!(cfg.cache.capacity, 50_000);
        assert_eq!(cfg.cache.min_ttl, Some(Duration::from_secs(5)));
        assert_eq!(
            cfg.tls.cert_path,
            Some(PathBuf::from("/etc/dotdns/cert.pem"))
        );
        assert_eq!(cfg.logging.format, LogFormat::Json);
    }

    #[test]
    fn example_config_matches_implemented_schema() {
        let cfg = Config::from_toml(include_str!("../examples/dotdns.toml")).unwrap();
        assert_eq!(cfg.server.bind.port(), 853);
        assert!(cfg.tls.enabled);
        assert_eq!(cfg.upstreams.len(), 3);
        assert_eq!(cfg.upstreams[0].protocol, UpstreamProtocol::Tls);
        assert_eq!(cfg.upstreams[1].protocol, UpstreamProtocol::Https);
        assert_eq!(cfg.upstreams[2].protocol, UpstreamProtocol::Plain);
        assert!(matches!(
            cfg.management.transport,
            ManagementTransport::Unix { .. }
        ));
    }
}
