use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid value for {field}: {message}")]
    InvalidValue { field: String, message: String },
    #[error("no upstreams configured")]
    NoUpstreams,
    #[error("blocklist path does not exist: {0}")]
    BlocklistPathNotFound(PathBuf),
    #[error("allowlist path does not exist: {0}")]
    AllowlistPathNotFound(PathBuf),
    #[error("invalid blocklist url: {0}")]
    InvalidBlocklistUrl(String),
    #[error("invalid allowlist url: {0}")]
    InvalidAllowlistUrl(String),
    #[error("tls cert and key required")]
    TlsIncomplete,
    #[error("management must bind to loopback, got {0}")]
    ManagementNotLoopback(String),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub upstreams: Vec<UpstreamEntry>,
    #[serde(default)]
    pub bootstrap: BootstrapConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub edns: EdnsConfig,
    #[serde(default)]
    pub blocklist: BlocklistConfig,
    #[serde(default)]
    pub management: ManagementConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

impl Config {
    pub fn from_toml(source: &str) -> Result<Self, ConfigError> {
        let cfg: Config = toml::from_str(source).map_err(|e| ConfigError::InvalidValue {
            field: "config".into(),
            message: e.to_string(),
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    // TODO: this got a bit long, maybe split up later
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.upstreams.is_empty() {
            return Err(ConfigError::NoUpstreams);
        }
        if self.server.binds.is_empty() {
            return Err(ConfigError::InvalidValue {
                field: "server.binds".into(),
                message: "at least one listen address is required".into(),
            });
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
                        message: "DoT upstream needs a hostname, not an IP".into(),
                    });
                }
            }
        }
        for (i, server) in self.bootstrap.dns.iter().enumerate() {
            if server.port() == 0 {
                return Err(ConfigError::InvalidValue {
                    field: format!("bootstrap.dns[{}]", i),
                    message: "bootstrap DNS server port must be greater than zero".into(),
                });
            }
        }
        if self.tls.cert_path.is_some() != self.tls.key_path.is_some() {
            return Err(ConfigError::TlsIncomplete);
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
        for path in &self.blocklist.allowlist_paths {
            if !path.exists() {
                return Err(ConfigError::AllowlistPathNotFound(path.clone()));
            }
        }
        for url in &self.blocklist.urls {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(ConfigError::InvalidBlocklistUrl(url.clone()));
            }
        }
        for url in &self.blocklist.allowlist_urls {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(ConfigError::InvalidAllowlistUrl(url.clone()));
            }
        }
        if let Some(interval) = self.blocklist.refresh_interval {
            if interval.is_zero() {
                return Err(ConfigError::InvalidValue {
                    field: "blocklist.refresh_interval".into(),
                    message: "refresh interval must be greater than zero".into(),
                });
            }
        }
        if self.blocklist.download_timeout.is_zero() {
            return Err(ConfigError::InvalidValue {
                field: "blocklist.download_timeout".into(),
                message: "download timeout must be greater than zero".into(),
            });
        }
        if self.blocklist.blocked_ttl.is_zero() {
            return Err(ConfigError::InvalidValue {
                field: "blocklist.blocked_ttl".into(),
                message: "blocked TTL must be greater than zero".into(),
            });
        }
        if self.edns.client_subnet.ipv4_prefix > 32 {
            return Err(ConfigError::InvalidValue {
                field: "edns.client_subnet.ipv4_prefix".into(),
                message: "IPv4 ECS prefix must be between 0 and 32".into(),
            });
        }
        if self.edns.client_subnet.ipv6_prefix > 128 {
            return Err(ConfigError::InvalidValue {
                field: "edns.client_subnet.ipv6_prefix".into(),
                message: "IPv6 ECS prefix must be between 0 and 128".into(),
            });
        }
        Ok(())
    }
}

fn is_loopback(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

// strip port from address
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
    pub binds: Vec<SocketAddr>,
    /// idle timeout
    #[serde(default = "default_idle_timeout", with = "humantime_serde")]
    pub idle_timeout: Duration,
}

fn default_idle_timeout() -> Duration {
    Duration::from_secs(60)
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct TlsConfig {
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    #[default]
    Plain,
    #[serde(rename = "dot")]
    Tls,
    #[serde(rename = "doh")]
    Https,
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
#[serde(deny_unknown_fields)]
pub struct UpstreamEntry {
    pub name: String,
    pub address: String,
    #[serde(default)]
    pub protocol: UpstreamProtocol,
    pub tls_cert_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct BootstrapConfig {
    #[serde(default)]
    pub dns: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CacheConfig {
    #[serde(default = "default_cache_capacity")]
    pub capacity: usize,
    #[serde(default, with = "humantime_serde")]
    pub min_ttl: Option<Duration>,
    #[serde(default, with = "humantime_serde")]
    pub max_ttl: Option<Duration>,
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
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EdnsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub preserve_client: bool,
    #[serde(default)]
    pub client_subnet: ClientSubnetConfig,
}

impl Default for EdnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            preserve_client: true,
            client_subnet: ClientSubnetConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientSubnetConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_ipv4_ecs_prefix")]
    pub ipv4_prefix: u8,
    #[serde(default = "default_ipv6_ecs_prefix")]
    pub ipv6_prefix: u8,
    #[serde(default = "default_true")]
    pub exclude_private: bool,
}

impl Default for ClientSubnetConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ipv4_prefix: default_ipv4_ecs_prefix(),
            ipv6_prefix: default_ipv6_ecs_prefix(),
            exclude_private: true,
        }
    }
}

fn default_ipv4_ecs_prefix() -> u8 {
    24
}

fn default_ipv6_ecs_prefix() -> u8 {
    56
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlocklistConfig {
    #[serde(default)]
    pub paths: Vec<PathBuf>,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub allowlist_paths: Vec<PathBuf>,
    #[serde(default)]
    pub allowlist_urls: Vec<String>,
    #[serde(default = "default_blocklist_download_dir")]
    pub download_dir: PathBuf,
    #[serde(default, with = "humantime_serde")]
    pub refresh_interval: Option<Duration>,
    #[serde(
        default = "default_blocklist_download_timeout",
        with = "humantime_serde"
    )]
    pub download_timeout: Duration,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub response_mode: BlocklistResponseMode,
    #[serde(default = "default_blocked_ttl", with = "humantime_serde")]
    pub blocked_ttl: Duration,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            urls: Vec::new(),
            allowlist_paths: Vec::new(),
            allowlist_urls: Vec::new(),
            download_dir: default_blocklist_download_dir(),
            refresh_interval: None,
            download_timeout: default_blocklist_download_timeout(),
            enabled: true,
            response_mode: BlocklistResponseMode::default(),
            blocked_ttl: default_blocked_ttl(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlocklistResponseMode {
    #[default]
    NullIp,
    NoData,
    NxDomain,
}

fn default_blocklist_download_dir() -> PathBuf {
    PathBuf::from("/var/lib/dotdns/blocklists")
}

fn default_blocklist_download_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_blocked_ttl() -> Duration {
    Duration::from_secs(300)
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ManagementConfig {
    #[serde(flatten, default)]
    pub transport: ManagementTransport,
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
binds = ["0.0.0.0:853", "[::]:853"]

[[upstreams]]
name = "cloudflare"
address = "1.1.1.1:53"
protocol = "plain"
"#;
        let cfg = Config::from_toml(source).unwrap();
        assert_eq!(cfg.server.binds.len(), 2);
        assert_eq!(cfg.server.binds[0].port(), 853);
        assert!(cfg.bootstrap.dns.is_empty());
        assert_eq!(cfg.upstreams.len(), 1);
        assert_eq!(cfg.upstreams[0].protocol, UpstreamProtocol::Plain);
    }

    #[test]
    fn reject_empty_upstreams() {
        let source = r#"
[server]
binds = ["0.0.0.0:853"]
"#;
        let err = Config::from_toml(source).unwrap_err();
        assert!(matches!(err, ConfigError::NoUpstreams));
    }

    #[test]
    fn reject_empty_server_binds() {
        let source = r#"
[server]
binds = []

[[upstreams]]
name = "cloudflare"
address = "1.1.1.1:53"
protocol = "plain"
"#;
        let err = Config::from_toml(source).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { field, .. } if field == "server.binds"));
    }

    #[test]
    fn reject_missing_tls_files_when_partial() {
        let source = r#"
[server]
binds = ["0.0.0.0:853"]

[tls]
cert_path = "/etc/dotdns/cert.pem"

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
binds = ["0.0.0.0:853"]

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
binds = ["0.0.0.0:853"]

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
binds = ["0.0.0.0:853"]

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
binds = ["0.0.0.0:853"]

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
binds = ["0.0.0.0:853"]

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
binds = ["0.0.0.0:853"]
idle_timeout = "2m"

[tls]
cert_path = "/etc/dotdns/cert.pem"
key_path = "/etc/dotdns/key.pem"

[bootstrap]
dns = ["1.1.1.1:53", "1.0.0.1:53"]

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

[edns]
enabled = true
preserve_client = true

[edns.client_subnet]
enabled = true
ipv4_prefix = 24
ipv6_prefix = 56
exclude_private = true

[blocklist]
enabled = true
paths = []
urls = ["https://example.com/adguard-dns.txt"]
allowlist_paths = []
allowlist_urls = ["https://example.com/allow.txt"]
download_dir = "/var/lib/dotdns/blocklists"
refresh_interval = "6h"
download_timeout = "30s"
response_mode = "no_data"
blocked_ttl = "10m"

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
        assert!(cfg.edns.client_subnet.enabled);
        assert_eq!(cfg.edns.client_subnet.ipv4_prefix, 24);
        assert_eq!(cfg.edns.client_subnet.ipv6_prefix, 56);
        assert_eq!(cfg.blocklist.urls.len(), 1);
        assert_eq!(cfg.blocklist.allowlist_urls.len(), 1);
        assert_eq!(
            cfg.blocklist.refresh_interval,
            Some(Duration::from_secs(6 * 60 * 60))
        );
        assert_eq!(cfg.blocklist.response_mode, BlocklistResponseMode::NoData);
        assert_eq!(cfg.blocklist.blocked_ttl, Duration::from_secs(600));
        assert_eq!(cfg.bootstrap.dns.len(), 2);
    }

    #[test]
    fn reject_zero_port_bootstrap_dns() {
        let source = r#"
[server]
binds = ["0.0.0.0:853"]

[bootstrap]
dns = ["1.1.1.1:0"]

[[upstreams]]
name = "cf"
address = "1.1.1.1:53"
"#;
        let err = Config::from_toml(source).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { field, .. } if field == "bootstrap.dns[0]")
        );
    }

    #[test]
    fn reject_per_upstream_bootstrap_dns() {
        let source = r#"
[server]
binds = ["0.0.0.0:853"]

[[upstreams]]
name = "cloudflare-doh"
address = "https://cloudflare-dns.com/dns-query"
protocol = "doh"
bootstrap = ["1.1.1.1:53"]
"#;
        let err = Config::from_toml(source).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue { field, .. } if field == "config"));
    }

    #[test]
    fn reject_non_http_blocklist_url() {
        let source = r#"
[server]
binds = ["0.0.0.0:853", "[::]:853"]

[blocklist]
urls = ["file:///tmp/list.txt"]

[[upstreams]]
name = "cf"
address = "1.1.1.1:53"
"#;
        let err = Config::from_toml(source).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidBlocklistUrl(_)));
    }

    #[test]
    fn reject_non_http_allowlist_url() {
        let source = r#"
[server]
binds = ["0.0.0.0:853"]

[blocklist]
allowlist_urls = ["file:///tmp/allow.txt"]

[[upstreams]]
name = "cf"
address = "1.1.1.1:53"
"#;
        let err = Config::from_toml(source).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidAllowlistUrl(_)));
    }

    #[test]
    fn reject_invalid_ecs_prefix() {
        let source = r#"
[server]
binds = ["0.0.0.0:853"]

[edns.client_subnet]
enabled = true
ipv4_prefix = 33

[[upstreams]]
name = "cf"
address = "1.1.1.1:53"
"#;
        let err = Config::from_toml(source).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidValue { field, .. } if field == "edns.client_subnet.ipv4_prefix")
        );
    }

    #[test]
    fn example_config_matches_implemented_schema() {
        let cfg = Config::from_toml(include_str!("../examples/dotdns.toml")).unwrap();
        assert_eq!(cfg.server.binds.len(), 2);
        assert_eq!(cfg.server.binds[0].port(), 853);
        assert_eq!(cfg.server.binds[1].port(), 853);
        assert!(cfg.tls.cert_path.is_some());
        assert!(cfg.tls.key_path.is_some());
        assert_eq!(cfg.upstreams.len(), 3);
        assert_eq!(cfg.bootstrap.dns.len(), 2);
        assert_eq!(cfg.upstreams[0].protocol, UpstreamProtocol::Tls);
        assert_eq!(cfg.upstreams[1].protocol, UpstreamProtocol::Https);
        assert_eq!(cfg.upstreams[2].protocol, UpstreamProtocol::Plain);
        assert!(matches!(
            cfg.management.transport,
            ManagementTransport::Unix { .. }
        ));
    }
}
