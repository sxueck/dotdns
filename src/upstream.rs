//! Upstream resolver transports.
//!
//! Supports plain DNS (UDP with TCP fallback), DNS-over-TLS (DoT),
//! and DNS-over-HTTPS (DoH). Upstreams are tried in order until one
//! succeeds (fallback behavior).

use crate::config::{UpstreamEntry, UpstreamProtocol};
use crate::metrics::MetricsRecorder;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::error::Error;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

// DoH
use reqwest::Client as HttpClient;

// DoT
use rustls::pki_types::ServerName;
use std::sync::Arc as RustlsArc;
use tokio_rustls::TlsConnector;

#[derive(Debug, thiserror::Error, Clone)]
pub enum UpstreamError {
    #[error("network error: {0}")]
    Network(String),
    #[error("timeout")]
    Timeout,
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("all upstreams failed")]
    AllFailed,
    #[error("unsupported protocol: {0}")]
    UnsupportedProtocol(String),
    #[error("unsupported feature: {0}")]
    UnsupportedFeature(String),
}

impl From<hickory_proto::error::ProtoError> for UpstreamError {
    fn from(e: hickory_proto::error::ProtoError) -> Self {
        UpstreamError::Serialization(e.to_string())
    }
}

impl From<std::io::Error> for UpstreamError {
    fn from(e: std::io::Error) -> Self {
        UpstreamError::Network(e.to_string())
    }
}

impl From<reqwest::Error> for UpstreamError {
    fn from(e: reqwest::Error) -> Self {
        UpstreamError::Network(format_error_chain(&e))
    }
}

fn format_error_chain(error: &dyn Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(err) = source {
        message.push_str(": ");
        message.push_str(&err.to_string());
        source = err.source();
    }
    message
}

// strip port for SNI
fn extract_host(address: &str) -> &str {
    if let Some(rest) = address.strip_prefix('[') {
        if let Some((host, _)) = rest.split_once(']') {
            return host;
        }
    } else if let Some((host, _)) = address.rsplit_once(':') {
        return host;
    }
    address
}

// --- Upstream Enum ---

/// Upstream wrapper enum.
#[derive(Debug, Clone)]
pub enum Upstream {
    Plain(PlainUpstream),
    Dot(DotUpstream),
    Doh(DohUpstream),
}

impl Upstream {
    pub fn from_entry(entry: &UpstreamEntry) -> Result<Self, UpstreamError> {
        if entry.tls_cert_path.is_some() {
            return Err(UpstreamError::UnsupportedFeature(
                "tls_cert_path is not supported".into(),
            ));
        }
        match entry.protocol {
            UpstreamProtocol::Plain => Ok(Upstream::Plain(PlainUpstream::new(&entry.address))),
            UpstreamProtocol::Tls => Ok(Upstream::Dot(DotUpstream::new(&entry.address))),
            UpstreamProtocol::Https => Ok(Upstream::Doh(DohUpstream::new(entry)?)),
        }
    }

    pub async fn query(&self, message: &Message) -> Result<Message, UpstreamError> {
        match self {
            Upstream::Plain(u) => u.query(message).await,
            Upstream::Dot(u) => u.query(message).await,
            Upstream::Doh(u) => u.query(message).await,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Upstream::Plain(u) => &u.address,
            Upstream::Dot(u) => &u.address,
            Upstream::Doh(u) => &u.url,
        }
    }
}

// --- Plain DNS ---

#[derive(Debug, Clone)]
pub struct PlainUpstream {
    address: String,
    timeout: Duration,
}

impl PlainUpstream {
    pub fn new(address: &str) -> Self {
        Self {
            address: address.to_string(),
            timeout: Duration::from_secs(5),
        }
    }

    pub async fn query(&self, message: &Message) -> Result<Message, UpstreamError> {
        // Try UDP first.
        match self.query_udp(message).await {
            Ok(response) => {
                // If truncated, fallback to TCP.
                if is_truncated(&response) {
                    return self.query_tcp(message).await;
                }
                Ok(response)
            }
            Err(e) => {
                tracing::debug!(error = %e, "UDP query failed, trying TCP");
                self.query_tcp(message).await
            }
        }
    }

    async fn query_udp(&self, message: &Message) -> Result<Message, UpstreamError> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let msg_bytes = message.to_bytes()?;

        tokio::time::timeout(self.timeout, async {
            socket.send_to(&msg_bytes, &self.address).await?;
            let mut buf = vec![0u8; 65535];
            let (len, _) = socket.recv_from(&mut buf).await?;
            buf.truncate(len);
            Message::from_bytes(&buf).map_err(UpstreamError::from)
        })
        .await
        .map_err(|_| UpstreamError::Timeout)?
    }

    async fn query_tcp(&self, message: &Message) -> Result<Message, UpstreamError> {
        let msg_bytes = message.to_bytes()?;

        tokio::time::timeout(self.timeout, async {
            let mut stream = TcpStream::connect(&self.address).await?;
            // DNS over TCP: 2-byte length prefix (big-endian).
            stream.write_u16(msg_bytes.len() as u16).await?;
            stream.write_all(&msg_bytes).await?;

            let resp_len = stream.read_u16().await? as usize;
            let mut resp_buf = vec![0u8; resp_len];
            stream.read_exact(&mut resp_buf).await?;

            Message::from_bytes(&resp_buf).map_err(UpstreamError::from)
        })
        .await
        .map_err(|_| UpstreamError::Timeout)?
    }
}

// check TC bit in DNS header
fn is_truncated(msg: &Message) -> bool {
    // Hickory Message doesn't expose raw header bytes directly in a stable way.
    // Serialize and inspect the wire-format header directly.
    match msg.to_bytes() {
        Ok(bytes) => bytes.len() >= 3 && (bytes[2] & 0x02) != 0,
        Err(_) => false,
    }
}

// --- DoT ---

#[derive(Debug, Clone)]
pub struct DotUpstream {
    address: String,
    timeout: Duration,
    tls_config: RustlsArc<rustls::ClientConfig>,
}

impl DotUpstream {
    pub fn new(address: &str) -> Self {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Self {
            address: address.to_string(),
            timeout: Duration::from_secs(5),
            tls_config: RustlsArc::new(tls_config),
        }
    }

    pub async fn query(&self, message: &Message) -> Result<Message, UpstreamError> {
        let msg_bytes = message.to_bytes()?;

        // Extract hostname for SNI (remove port).
        let hostname = extract_host(&self.address).to_string();

        tokio::time::timeout(self.timeout, async {
            let stream = TcpStream::connect(&self.address).await?;
            let connector = TlsConnector::from(self.tls_config.clone());
            let server_name = ServerName::try_from(hostname)
                .map_err(|e| UpstreamError::Network(format!("invalid server name: {}", e)))?;
            let mut tls_stream = connector.connect(server_name, stream).await?;

            // Same 2-byte length prefix as plain TCP.
            tls_stream.write_u16(msg_bytes.len() as u16).await?;
            tls_stream.write_all(&msg_bytes).await?;

            let resp_len = tls_stream.read_u16().await? as usize;
            let mut resp_buf = vec![0u8; resp_len];
            tls_stream.read_exact(&mut resp_buf).await?;

            Message::from_bytes(&resp_buf).map_err(UpstreamError::from)
        })
        .await
        .map_err(|_| UpstreamError::Timeout)?
    }
}

// --- DoH ---

#[derive(Debug, Clone)]
pub struct DohUpstream {
    url: String,
    timeout: Duration,
    client: HttpClient,
}

impl DohUpstream {
    pub fn new(entry: &UpstreamEntry) -> Result<Self, UpstreamError> {
        let url = normalize_doh_url(&entry.address)?;
        let mut builder = HttpClient::builder()
            .https_only(true)
            .timeout(Duration::from_secs(10));

        let url_parts = reqwest::Url::parse(&url)
            .map_err(|e| UpstreamError::InvalidResponse(format!("invalid DoH URL: {e}")))?;
        let host = url_parts
            .host_str()
            .ok_or_else(|| UpstreamError::InvalidResponse("DoH URL has no host".into()))?;
        let port = url_parts.port_or_known_default().unwrap_or(443);
        let resolved_addrs = match doh_bootstrap_addrs(entry)? {
            Some(addrs) => addrs,
            None => resolve_doh_host(host, port)?,
        };
        for addr in resolved_addrs {
            builder = builder.resolve(host, addr);
        }

        Ok(Self {
            url,
            timeout: Duration::from_secs(5),
            client: builder.build().expect("reqwest client build"),
        })
    }

    pub async fn query(&self, message: &Message) -> Result<Message, UpstreamError> {
        let msg_bytes = message.to_bytes()?;
        let response = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(msg_bytes)
            .timeout(self.timeout)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(UpstreamError::Network(format!(
                "HTTP error: {}",
                response.status()
            )));
        }

        let resp_bytes = response.bytes().await?;
        Message::from_bytes(&resp_bytes).map_err(UpstreamError::from)
    }
}

fn normalize_doh_url(address: &str) -> Result<String, UpstreamError> {
    let raw = address.trim();
    let with_scheme = if raw.starts_with("https://") || raw.starts_with("http://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };
    let mut url = reqwest::Url::parse(&with_scheme)
        .map_err(|e| UpstreamError::InvalidResponse(format!("invalid DoH URL: {e}")))?;
    if url.scheme() != "https" {
        return Err(UpstreamError::UnsupportedFeature(
            "DoH upstreams require https URLs".into(),
        ));
    }
    if url.path().is_empty() || url.path() == "/" {
        url.set_path("/dns-query");
    }
    Ok(url.to_string())
}

fn doh_bootstrap_addrs(entry: &UpstreamEntry) -> Result<Option<Vec<SocketAddr>>, UpstreamError> {
    let Some(value) = entry
        .extra
        .get("bootstrap")
        .or_else(|| entry.extra.get("bootstrap_addrs"))
    else {
        return Ok(None);
    };

    let addrs = match value {
        toml::Value::String(addr) => parse_bootstrap_addr(&entry.name, addr).map(|addr| vec![addr]),
        toml::Value::Array(values) => values
            .iter()
            .map(|value| match value {
                toml::Value::String(addr) => parse_bootstrap_addr(&entry.name, addr),
                _ => Err(UpstreamError::InvalidResponse(format!(
                    "upstream {} bootstrap entries must be strings",
                    entry.name
                ))),
            })
            .collect(),
        _ => Err(UpstreamError::InvalidResponse(format!(
            "upstream {} bootstrap must be a string or array",
            entry.name
        ))),
    }?;
    Ok(Some(addrs))
}

fn parse_bootstrap_addr(name: &str, addr: &str) -> Result<SocketAddr, UpstreamError> {
    let with_port = if addr.contains(':') {
        addr.to_string()
    } else {
        format!("{addr}:443")
    };
    with_port.parse().map_err(|e| {
        UpstreamError::InvalidResponse(format!("invalid DoH bootstrap for {name}: {e}"))
    })
}

fn resolve_doh_host(host: &str, port: u16) -> Result<Vec<SocketAddr>, UpstreamError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| UpstreamError::Network(format!("failed to resolve DoH host {host}: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(UpstreamError::Network(format!(
            "failed to resolve DoH host {host}: no addresses returned"
        )));
    }
    Ok(addrs)
}

// --- Upstream Pool (fallback) ---

#[derive(Debug, Clone)]
pub struct UpstreamPool {
    upstreams: Vec<(Upstream, String)>,
    metrics: Option<Arc<MetricsRecorder>>,
}

impl UpstreamPool {
    pub fn new(upstreams: Vec<(Upstream, String)>, metrics: Option<Arc<MetricsRecorder>>) -> Self {
        Self { upstreams, metrics }
    }

    pub async fn query(&self, message: &Message) -> Result<Message, UpstreamError> {
        let mut last_err = None;

        for (upstream, name) in &self.upstreams {
            match upstream.query(message).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    tracing::warn!(upstream = %name, error = %e, "upstream query failed");
                    last_err = Some(e);
                    if let Some(m) = &self.metrics {
                        m.record_upstream_failure();
                    }
                }
            }
        }

        Err(last_err.unwrap_or(UpstreamError::AllFailed))
    }

    pub fn len(&self) -> usize {
        self.upstreams.len()
    }

    pub fn is_empty(&self) -> bool {
        self.upstreams.is_empty()
    }
}

pub fn pool_from_config(
    entries: &[UpstreamEntry],
    metrics: Option<Arc<MetricsRecorder>>,
) -> Result<UpstreamPool, UpstreamError> {
    let mut upstreams = Vec::with_capacity(entries.len());
    for entry in entries {
        let upstream = Upstream::from_entry(entry)?;
        upstreams.push((upstream, entry.name.clone()));
    }
    Ok(UpstreamPool::new(upstreams, metrics))
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::sync::Once;
    use tokio::net::UdpSocket;

    static INIT_CRYPTO: Once = Once::new();

    fn init_crypto() {
        INIT_CRYPTO.call_once(|| {
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("ring crypto provider install");
        });
    }

    fn test_query() -> Message {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(true);
        msg.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        msg
    }

    async fn start_mock_udp_server(bind: &str) -> tokio::task::JoinHandle<()> {
        let socket = UdpSocket::bind(bind).await.unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (len, peer) = match socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let mut response = match Message::from_bytes(&buf[..len]) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                response.set_message_type(MessageType::Response);
                if let Ok(bytes) = response.to_bytes() {
                    let _ = socket.send_to(&bytes, peer).await;
                }
            }
        })
    }

    // ------------------------------------------------------------------
    // Config mapping
    // ------------------------------------------------------------------

    #[test]
    fn upstream_from_plain_config() {
        let entry = UpstreamEntry {
            name: "test".into(),
            address: "8.8.8.8:53".into(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            extra: Default::default(),
        };
        let upstream = Upstream::from_entry(&entry).unwrap();
        assert!(matches!(upstream, Upstream::Plain(_)));
        assert_eq!(upstream.name(), "8.8.8.8:53");
    }

    #[test]
    fn upstream_from_dot_config() {
        init_crypto();
        let entry = UpstreamEntry {
            name: "test".into(),
            address: "cloudflare-dns.com:853".into(),
            protocol: UpstreamProtocol::Tls,
            tls_cert_path: None,
            extra: Default::default(),
        };
        let upstream = Upstream::from_entry(&entry).unwrap();
        assert!(matches!(upstream, Upstream::Dot(_)));
        assert_eq!(upstream.name(), "cloudflare-dns.com:853");
    }

    #[test]
    fn upstream_from_doh_config() {
        let mut entry = UpstreamEntry {
            name: "test".into(),
            address: "https://cloudflare-dns.com/dns-query".into(),
            protocol: UpstreamProtocol::Https,
            tls_cert_path: None,
            extra: Default::default(),
        };
        entry
            .extra
            .insert("bootstrap".into(), toml::Value::String("1.1.1.1".into()));
        let upstream = Upstream::from_entry(&entry).unwrap();
        assert!(matches!(upstream, Upstream::Doh(_)));
        assert_eq!(upstream.name(), "https://cloudflare-dns.com/dns-query");
    }

    #[test]
    fn doh_url_defaults_to_https_dns_query_path() {
        assert_eq!(
            normalize_doh_url("dot.pub").unwrap(),
            "https://dot.pub/dns-query"
        );
        assert_eq!(
            normalize_doh_url("https://dot.pub").unwrap(),
            "https://dot.pub/dns-query"
        );
    }

    #[test]
    fn doh_url_rejects_plain_http() {
        let err = normalize_doh_url("http://dot.pub/dns-query").unwrap_err();
        assert!(matches!(err, UpstreamError::UnsupportedFeature(_)));
    }

    #[test]
    fn doh_bootstrap_accepts_single_ip_without_port() {
        let mut entry = UpstreamEntry {
            name: "tencent-doh".into(),
            address: "https://dot.pub/dns-query".into(),
            protocol: UpstreamProtocol::Https,
            tls_cert_path: None,
            extra: Default::default(),
        };
        entry
            .extra
            .insert("bootstrap".into(), toml::Value::String("1.12.12.12".into()));

        let addrs = doh_bootstrap_addrs(&entry).unwrap().unwrap();
        assert_eq!(addrs, vec!["1.12.12.12:443".parse().unwrap()]);
    }

    #[test]
    fn doh_bootstrap_accepts_array() {
        let mut entry = UpstreamEntry {
            name: "tencent-doh".into(),
            address: "https://dot.pub/dns-query".into(),
            protocol: UpstreamProtocol::Https,
            tls_cert_path: None,
            extra: Default::default(),
        };
        entry.extra.insert(
            "bootstrap".into(),
            toml::Value::Array(vec![
                toml::Value::String("1.12.12.12".into()),
                toml::Value::String("120.53.53.53:443".into()),
            ]),
        );

        let addrs = doh_bootstrap_addrs(&entry).unwrap().unwrap();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], "1.12.12.12:443".parse().unwrap());
        assert_eq!(addrs[1], "120.53.53.53:443".parse().unwrap());
    }

    #[test]
    fn doh_bootstrap_is_optional() {
        let entry = UpstreamEntry {
            name: "local-doh".into(),
            address: "https://127.0.0.1/dns-query".into(),
            protocol: UpstreamProtocol::Https,
            tls_cert_path: None,
            extra: Default::default(),
        };

        assert!(doh_bootstrap_addrs(&entry).unwrap().is_none());
        assert_eq!(
            resolve_doh_host("127.0.0.1", 443).unwrap(),
            vec!["127.0.0.1:443".parse().unwrap()]
        );
    }

    #[test]
    fn upstream_rejects_tls_cert_path() {
        let entry = UpstreamEntry {
            name: "test".into(),
            address: "cloudflare-dns.com:853".into(),
            protocol: UpstreamProtocol::Tls,
            tls_cert_path: Some(PathBuf::from("/some/cert.pem")),
            extra: Default::default(),
        };
        let err = Upstream::from_entry(&entry).unwrap_err();
        assert!(matches!(err, UpstreamError::UnsupportedFeature(_)));
    }

    #[test]
    fn host_extraction_cases() {
        assert_eq!(extract_host("cloudflare-dns.com:853"), "cloudflare-dns.com");
        assert_eq!(extract_host("[2001:db8::1]:853"), "2001:db8::1");
        assert_eq!(extract_host("8.8.8.8:53"), "8.8.8.8");
        assert_eq!(extract_host("cloudflare-dns.com"), "cloudflare-dns.com");
        assert_eq!(extract_host("[::1]:853"), "::1");
    }

    // ------------------------------------------------------------------
    // Plain transport
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn plain_udp_query_happy_path() {
        let handle = start_mock_udp_server("127.0.0.1:0").await;
        // Give the mock a moment to bind.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Discover the bound port by trying to connect... actually we can't easily.
        // Instead, bind to a known port.
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        drop(socket);

        // Restart mock on that port.
        handle.abort();
        let _handle = start_mock_udp_server(&addr.to_string()).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let upstream = PlainUpstream::new(&addr.to_string());
        let query = test_query();
        let response = upstream.query(&query).await.unwrap();

        assert_eq!(response.message_type(), MessageType::Response);
        assert_eq!(response.id(), query.id());
    }

    // ------------------------------------------------------------------
    // Fallback behaviour
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn pool_fallback_to_second_upstream() {
        // Build a mock pool manually using the enum variants.
        let entry1 = UpstreamEntry {
            name: "fail".into(),
            address: "127.0.0.1:1".into(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            extra: Default::default(),
        };
        let entry2 = UpstreamEntry {
            name: "ok".into(),
            address: "127.0.0.1:0".into(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            extra: Default::default(),
        };

        // Start a mock server for entry2.
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ok_addr = socket.local_addr().unwrap();
        drop(socket);

        let _handle = start_mock_udp_server(&ok_addr.to_string()).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Adjust entry2 address to the actual bound port.
        let mut entry2 = entry2;
        entry2.address = ok_addr.to_string();

        let pool = pool_from_config(&[entry1, entry2], None).unwrap();
        let query = test_query();

        // First upstream (127.0.0.1:1) will fail; second should succeed.
        let response = pool.query(&query).await.unwrap();
        assert_eq!(response.message_type(), MessageType::Response);
    }

    #[tokio::test]
    async fn pool_all_failed() {
        let entry = UpstreamEntry {
            name: "fail".into(),
            address: "127.0.0.1:1".into(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            extra: Default::default(),
        };

        let pool = pool_from_config(&[entry.clone(), entry], None).unwrap();
        let query = test_query();

        let err = pool.query(&query).await.unwrap_err();
        assert!(matches!(err, UpstreamError::Network(_)));
    }

    #[tokio::test]
    async fn metrics_increment_on_failure() {
        use crate::metrics::MetricsRecorder;

        let entry = UpstreamEntry {
            name: "fail".into(),
            address: "127.0.0.1:1".into(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            extra: Default::default(),
        };

        let metrics = Arc::new(MetricsRecorder::new());
        let pool = pool_from_config(&[entry.clone(), entry], Some(metrics.clone())).unwrap();
        let query = test_query();

        let _ = pool.query(&query).await;
        let snap = metrics.snapshot();
        assert_eq!(snap.upstream_failures, 2);
    }

    // ------------------------------------------------------------------
    // Truncation / TCP fallback (plain)
    // ------------------------------------------------------------------

    #[test]
    fn truncated_bit_detection() {
        // Build a message and manually set the TC bit by mutating raw bytes.
        let msg = test_query();
        let mut bytes = msg.to_bytes().unwrap();
        // Set TC bit (byte 2, bit 1).
        bytes[2] |= 0x02;
        let msg_with_tc = Message::from_bytes(&bytes).unwrap();
        assert!(is_truncated(&msg_with_tc));
    }
}
