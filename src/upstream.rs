use crate::config::{UpstreamEntry, UpstreamProtocol};
use crate::metrics::MetricsRecorder;
use crate::observability::ObservabilityRegistry;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::error::Error;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket as StdUdpSocket};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use reqwest::Client as HttpClient;
use rustls::pki_types::ServerName;
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

#[derive(Debug, Clone)]
pub enum Upstream {
    Plain(PlainUpstream),
    Dot(DotUpstream),
    Doh(DohUpstream),
}

impl Upstream {
    pub fn from_entry(
        entry: &UpstreamEntry,
        bootstrap_dns: &[SocketAddr],
    ) -> Result<Self, UpstreamError> {
        if entry.tls_cert_path.is_some() {
            return Err(UpstreamError::UnsupportedFeature(
                "tls_cert_path is not supported".into(),
            ));
        }
        match entry.protocol {
            UpstreamProtocol::Plain => Ok(Upstream::Plain(PlainUpstream::new(
                &entry.address,
                entry.timeout,
            ))),
            UpstreamProtocol::Tls => Ok(Upstream::Dot(DotUpstream::new(
                &entry.address,
                bootstrap_dns,
                entry.timeout,
            )?)),
            UpstreamProtocol::Https => Ok(Upstream::Doh(DohUpstream::new(entry, bootstrap_dns)?)),
        }
    }

    pub async fn query(&self, message: &Message) -> Result<Message, UpstreamError> {
        match self {
            Upstream::Plain(u) => u.query(message).await,
            Upstream::Dot(u) => u.query(message).await,
            Upstream::Doh(u) => u.query(message).await,
        }
    }

    #[cfg(test)]
    pub fn name(&self) -> &str {
        match self {
            Upstream::Plain(u) => &u.address,
            Upstream::Dot(u) => &u.address,
            Upstream::Doh(u) => &u.url,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PlainUpstream {
    address: String,
    timeout: Duration,
}

impl PlainUpstream {
    pub fn new(address: &str, timeout: Duration) -> Self {
        Self {
            address: address.to_string(),
            timeout,
        }
    }

    pub async fn query(&self, message: &Message) -> Result<Message, UpstreamError> {
        match self.query_udp(message).await {
            Ok(response) => {
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

fn is_truncated(msg: &Message) -> bool {
    // Hickory Message doesn't expose raw header bytes directly in a stable way.
    // Serialize and inspect the wire-format header directly.
    match msg.to_bytes() {
        Ok(bytes) => bytes.len() >= 3 && (bytes[2] & 0x02) != 0,
        Err(_) => false,
    }
}

#[derive(Debug, Clone)]
pub struct DotUpstream {
    address: String,
    hostname: String,
    endpoints: Vec<SocketAddr>,
    timeout: Duration,
    tls_config: Arc<rustls::ClientConfig>,
}

impl DotUpstream {
    pub fn new(
        address: &str,
        bootstrap_dns: &[SocketAddr],
        timeout: Duration,
    ) -> Result<Self, UpstreamError> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let hostname = extract_host(address).to_string();
        let port = port_from_address(address).unwrap_or(853);
        let endpoints = resolve_host(&hostname, port, bootstrap_dns)?;

        Ok(Self {
            address: address.to_string(),
            hostname,
            endpoints,
            timeout,
            tls_config: Arc::new(tls_config),
        })
    }

    pub async fn query(&self, message: &Message) -> Result<Message, UpstreamError> {
        let msg_bytes = message.to_bytes()?;
        let mut errors = Vec::new();

        for endpoint in &self.endpoints {
            match self.query_endpoint(*endpoint, msg_bytes.clone()).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    tracing::debug!(upstream = %self.address, endpoint = %endpoint, error = %e, "DoT endpoint failed");
                    errors.push(format!("{}: {}", endpoint, e));
                }
            }
        }

        if errors.is_empty() {
            return Err(UpstreamError::Network("no DoT endpoints configured".into()));
        }
        Err(UpstreamError::Network(errors.join("; ")))
    }

    async fn query_endpoint(
        &self,
        endpoint: SocketAddr,
        msg_bytes: Vec<u8>,
    ) -> Result<Message, UpstreamError> {
        tokio::time::timeout(self.timeout, async {
            let stream = TcpStream::connect(endpoint).await?;
            let connector = TlsConnector::from(self.tls_config.clone());
            let server_name = ServerName::try_from(self.hostname.clone())
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

#[derive(Debug, Clone)]
pub struct DohUpstream {
    url: String,
    timeout: Duration,
    endpoints: Vec<DohEndpoint>,
}

#[derive(Debug, Clone)]
struct DohEndpoint {
    addr: SocketAddr,
    client: HttpClient,
}

impl DohUpstream {
    pub fn new(entry: &UpstreamEntry, bootstrap_dns: &[SocketAddr]) -> Result<Self, UpstreamError> {
        let url = normalize_doh_url(&entry.address)?;
        let url_parts = reqwest::Url::parse(&url)
            .map_err(|e| UpstreamError::InvalidResponse(format!("invalid DoH URL: {e}")))?;
        let host = url_parts
            .host_str()
            .ok_or_else(|| UpstreamError::InvalidResponse("DoH URL has no host".into()))?;
        let port = url_parts.port_or_known_default().unwrap_or(443);
        let resolved_addrs = resolve_host(host, port, bootstrap_dns)?;
        let endpoints = resolved_addrs
            .into_iter()
            .map(|addr| build_doh_endpoint(host, addr, entry.timeout))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            url,
            timeout: entry.timeout,
            endpoints,
        })
    }

    pub async fn query(&self, message: &Message) -> Result<Message, UpstreamError> {
        let msg_bytes = message.to_bytes()?;
        let mut errors = Vec::new();

        for endpoint in &self.endpoints {
            match self.query_endpoint(endpoint, msg_bytes.clone()).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    tracing::debug!(upstream = %self.url, endpoint = %endpoint.addr, error = %e, "DoH endpoint failed");
                    errors.push(format!("{}: {}", endpoint.addr, e));
                }
            }
        }

        if errors.is_empty() {
            return Err(UpstreamError::Network("no DoH endpoints configured".into()));
        }
        Err(UpstreamError::Network(errors.join("; ")))
    }

    async fn query_endpoint(
        &self,
        endpoint: &DohEndpoint,
        msg_bytes: Vec<u8>,
    ) -> Result<Message, UpstreamError> {
        let response = endpoint
            .client
            .post(&self.url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(msg_bytes)
            .timeout(self.timeout)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .bytes()
                .await
                .map(|bytes| String::from_utf8_lossy(&bytes[..bytes.len().min(256)]).into_owned())
                .unwrap_or_else(|e| format!("failed to read response body: {e}"));
            return Err(UpstreamError::Network(format!(
                "HTTP error from {}: {} {}",
                endpoint.addr, status, body
            )));
        }

        let resp_bytes = response.bytes().await?;
        Message::from_bytes(&resp_bytes).map_err(UpstreamError::from)
    }
}

fn build_doh_endpoint(
    host: &str,
    addr: SocketAddr,
    request_timeout: Duration,
) -> Result<DohEndpoint, UpstreamError> {
    let client_timeout = request_timeout.saturating_add(Duration::from_secs(5));
    let client = HttpClient::builder()
        .https_only(true)
        .timeout(client_timeout.max(Duration::from_secs(10)))
        .resolve(host, addr)
        .build()
        .map_err(|e| UpstreamError::Network(format_error_chain(&e)))?;
    Ok(DohEndpoint { addr, client })
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

fn resolve_host(
    host: &str,
    port: u16,
    bootstrap_dns: &[SocketAddr],
) -> Result<Vec<SocketAddr>, UpstreamError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    if !bootstrap_dns.is_empty() {
        let ips = resolve_host_with_bootstrap(host, bootstrap_dns)?;
        return Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect());
    }

    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| UpstreamError::Network(format!("failed to resolve host {host}: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(UpstreamError::Network(format!(
            "failed to resolve host {host}: no addresses returned"
        )));
    }
    Ok(addrs)
}

fn resolve_host_with_bootstrap(
    host: &str,
    bootstrap_dns: &[SocketAddr],
) -> Result<Vec<IpAddr>, UpstreamError> {
    let mut addrs = Vec::new();
    let mut errors = Vec::new();

    for server in bootstrap_dns {
        match query_bootstrap_dns(*server, host, RecordType::A) {
            Ok(mut ips) => addrs.append(&mut ips),
            Err(e) => errors.push(format!("{} A: {}", server, e)),
        }
        match query_bootstrap_dns(*server, host, RecordType::AAAA) {
            Ok(mut ips) => addrs.append(&mut ips),
            Err(e) => errors.push(format!("{} AAAA: {}", server, e)),
        }
        if !addrs.is_empty() {
            addrs.dedup();
            return Ok(addrs);
        }
    }

    if errors.is_empty() {
        return Err(UpstreamError::Network(format!(
            "failed to resolve host {host}: no bootstrap DNS servers configured"
        )));
    }
    Err(UpstreamError::Network(format!(
        "failed to resolve host {host} via bootstrap DNS: {}",
        errors.join("; ")
    )))
}

fn query_bootstrap_dns(
    server: SocketAddr,
    host: &str,
    record_type: RecordType,
) -> Result<Vec<IpAddr>, UpstreamError> {
    let bind_addr = if server.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = StdUdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;

    let name = Name::from_str(host).or_else(|_| Name::from_str(&format!("{host}.")))?;
    let mut query = Message::new();
    query.set_id(0xD07D);
    query.set_message_type(MessageType::Query);
    query.set_op_code(OpCode::Query);
    query.set_recursion_desired(true);
    query.add_query(Query::query(name, record_type));

    let bytes = query.to_bytes()?;
    socket.send_to(&bytes, server)?;

    let mut buf = vec![0u8; 65535];
    let (len, _) = socket.recv_from(&mut buf)?;
    buf.truncate(len);
    let response = Message::from_bytes(&buf)?;
    if response.message_type() != MessageType::Response {
        return Err(UpstreamError::InvalidResponse(
            "bootstrap DNS returned a non-response message".into(),
        ));
    }

    let ips = response
        .answers()
        .iter()
        .filter_map(|record| match record.data()? {
            RData::A(ip) if record_type == RecordType::A => Some(IpAddr::V4(ip.0)),
            RData::AAAA(ip) if record_type == RecordType::AAAA => Some(IpAddr::V6(ip.0)),
            _ => None,
        })
        .collect();
    Ok(ips)
}

fn port_from_address(address: &str) -> Option<u16> {
    if address.starts_with('[') {
        return address.rsplit_once(':')?.1.parse().ok();
    }
    address.rsplit_once(':')?.1.parse().ok()
}

#[derive(Debug, Clone)]
pub struct UpstreamPool {
    upstreams: Vec<(Upstream, String)>,
    metrics: Option<Arc<MetricsRecorder>>,
    observability: Option<Arc<ObservabilityRegistry>>,
}

impl UpstreamPool {
    pub fn new(
        upstreams: Vec<(Upstream, String)>,
        metrics: Option<Arc<MetricsRecorder>>,
        observability: Option<Arc<ObservabilityRegistry>>,
    ) -> Self {
        Self {
            upstreams,
            metrics,
            observability,
        }
    }

    pub async fn query(&self, message: &Message) -> Result<Message, UpstreamError> {
        let mut last_err = None;

        for (upstream, name) in &self.upstreams {
            let start = std::time::Instant::now();
            match upstream.query(message).await {
                Ok(response) => {
                    let elapsed = start.elapsed().as_millis() as u64;
                    if let Some(m) = &self.metrics {
                        m.record_upstream_success();
                    }
                    if let Some(obs) = &self.observability {
                        obs.record_upstream_success(name, elapsed);
                    }
                    return Ok(response);
                }
                Err(e) => {
                    tracing::warn!(upstream = %name, error = %e, "upstream query failed");
                    last_err = Some(e.clone());
                    if let Some(m) = &self.metrics {
                        if matches!(e, UpstreamError::Timeout) {
                            m.record_upstream_timeout();
                        }
                        m.record_upstream_failure();
                    }
                    if let Some(obs) = &self.observability {
                        if matches!(e, UpstreamError::Timeout) {
                            obs.record_upstream_timeout(name);
                        } else {
                            obs.record_upstream_failure(name);
                        }
                    }
                }
            }
        }

        Err(last_err.unwrap_or(UpstreamError::AllFailed))
    }
}

pub fn pool_from_config(
    entries: &[UpstreamEntry],
    bootstrap_dns: &[SocketAddr],
    metrics: Option<Arc<MetricsRecorder>>,
    observability: Option<Arc<ObservabilityRegistry>>,
) -> Result<UpstreamPool, UpstreamError> {
    let mut upstreams = Vec::with_capacity(entries.len());
    for entry in entries {
        let upstream = Upstream::from_entry(entry, bootstrap_dns)?;
        upstreams.push((upstream, entry.name.clone()));
    }
    Ok(UpstreamPool::new(upstreams, metrics, observability))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Message;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::Record;
    use std::net::Ipv4Addr;
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

    async fn start_mock_udp_server(
        bind: &str,
    ) -> (tokio::task::JoinHandle<()>, std::net::SocketAddr) {
        let socket = UdpSocket::bind(bind).await.unwrap();
        let addr = socket.local_addr().unwrap();
        let handle = tokio::spawn(async move {
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
        });
        (handle, addr)
    }

    fn start_mock_bootstrap_server(
        bind: &str,
        answer: Ipv4Addr,
    ) -> (std::thread::JoinHandle<()>, std::net::SocketAddr) {
        let socket = std::net::UdpSocket::bind(bind).unwrap();
        let addr = socket.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            loop {
                let (len, peer) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let mut response = match Message::from_bytes(&buf[..len]) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                response.set_message_type(MessageType::Response);
                if let Some(q) = response.queries().first() {
                    if q.query_type() == RecordType::A {
                        response.add_answer(Record::from_rdata(
                            q.name().clone(),
                            60,
                            RData::A(A(answer)),
                        ));
                    }
                }
                if let Ok(bytes) = response.to_bytes() {
                    let _ = socket.send_to(&bytes, peer);
                }
            }
        });
        (handle, addr)
    }

    #[test]
    fn upstream_from_plain_config() {
        let entry = UpstreamEntry {
            name: "test".into(),
            address: "8.8.8.8:53".into(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            timeout: Duration::from_secs(5),
        };
        let upstream = Upstream::from_entry(&entry, &[]).unwrap();
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
            timeout: Duration::from_secs(5),
        };
        let upstream = Upstream::from_entry(&entry, &[]).unwrap();
        assert!(matches!(upstream, Upstream::Dot(_)));
        assert_eq!(upstream.name(), "cloudflare-dns.com:853");
    }

    #[test]
    fn upstream_from_doh_config() {
        let entry = UpstreamEntry {
            name: "test".into(),
            address: "https://cloudflare-dns.com/dns-query".into(),
            protocol: UpstreamProtocol::Https,
            tls_cert_path: None,
            timeout: Duration::from_secs(5),
        };
        let upstream = Upstream::from_entry(&entry, &[]).unwrap();
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
    fn global_bootstrap_resolves_ip_hosts_without_dns_query() {
        assert_eq!(
            resolve_host("127.0.0.1", 443, &["1.1.1.1:53".parse().unwrap()]).unwrap(),
            vec!["127.0.0.1:443".parse().unwrap()]
        );
    }

    #[test]
    fn global_bootstrap_resolves_named_hosts() {
        let (_handle, bootstrap_addr) =
            start_mock_bootstrap_server("127.0.0.1:0", Ipv4Addr::new(192, 0, 2, 10));

        assert_eq!(
            resolve_host("resolver.example", 853, &[bootstrap_addr]).unwrap(),
            vec!["192.0.2.10:853".parse().unwrap()]
        );
    }

    #[test]
    fn upstream_rejects_tls_cert_path() {
        let entry = UpstreamEntry {
            name: "test".into(),
            address: "cloudflare-dns.com:853".into(),
            protocol: UpstreamProtocol::Tls,
            tls_cert_path: Some(PathBuf::from("/some/cert.pem")),
            timeout: Duration::from_secs(5),
        };
        let err = Upstream::from_entry(&entry, &[]).unwrap_err();
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

    #[tokio::test]
    async fn plain_udp_query_happy_path() {
        let (_handle, addr) = start_mock_udp_server("127.0.0.1:0").await;

        let upstream = PlainUpstream::new(&addr.to_string(), Duration::from_secs(5));
        let query = test_query();
        let response = upstream.query(&query).await.unwrap();

        assert_eq!(response.message_type(), MessageType::Response);
        assert_eq!(response.id(), query.id());
    }

    #[tokio::test]
    async fn pool_fallback_to_second_upstream() {
        let entry1 = UpstreamEntry {
            name: "fail".into(),
            address: "127.0.0.1:1".into(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            timeout: Duration::from_secs(5),
        };
        let entry2 = UpstreamEntry {
            name: "ok".into(),
            address: "127.0.0.1:0".into(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            timeout: Duration::from_secs(5),
        };

        let (_handle, ok_addr) = start_mock_udp_server("127.0.0.1:0").await;

        // Adjust entry2 address to the actual bound port.
        let mut entry2 = entry2;
        entry2.address = ok_addr.to_string();

        let pool = pool_from_config(&[entry1, entry2], &[], None, None).unwrap();
        let query = test_query();

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
            timeout: Duration::from_secs(5),
        };

        let pool = pool_from_config(&[entry.clone(), entry], &[], None, None).unwrap();
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
            timeout: Duration::from_secs(5),
        };

        let metrics = Arc::new(MetricsRecorder::new());
        let pool =
            pool_from_config(&[entry.clone(), entry], &[], Some(metrics.clone()), None).unwrap();
        let query = test_query();

        let _ = pool.query(&query).await;
        let snap = metrics.snapshot();
        assert_eq!(snap.upstream_failures, 2);
    }

    #[test]
    fn truncated_bit_detection() {
        // Build a message and manually set the TC bit by mutating raw bytes.
        let msg = test_query();
        let mut bytes = msg.to_bytes().unwrap();
        bytes[2] |= 0x02;
        let msg_with_tc = Message::from_bytes(&bytes).unwrap();
        assert!(is_truncated(&msg_with_tc));
    }

    #[tokio::test]
    async fn observability_increments_on_failure() {
        let entry = UpstreamEntry {
            name: "fail".into(),
            address: "127.0.0.1:1".into(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            timeout: Duration::from_secs(5),
        };

        let obs = Arc::new(ObservabilityRegistry::with_upstreams(&["fail".into()]));
        let pool = pool_from_config(&[entry.clone(), entry], &[], None, Some(obs.clone())).unwrap();
        let query = test_query();

        let _ = pool.query(&query).await;
        let snap = obs.snapshot();
        assert_eq!(snap.upstreams.len(), 1);
        let u = &snap.upstreams[0];
        assert_eq!(u.name, "fail");
        assert_eq!(u.failure_count, 2);
        assert_eq!(u.timeout_count, 0);
        assert_eq!(u.success_count, 0);
    }

    #[tokio::test]
    async fn observability_records_success_and_latency() {
        let entry = UpstreamEntry {
            name: "ok".into(),
            address: "127.0.0.1:0".into(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            timeout: Duration::from_secs(5),
        };

        let (_handle, ok_addr) = start_mock_udp_server("127.0.0.1:0").await;
        let mut entry = entry;
        entry.address = ok_addr.to_string();

        let obs = Arc::new(ObservabilityRegistry::with_upstreams(&["ok".into()]));
        let pool = pool_from_config(&[entry], &[], None, Some(obs.clone())).unwrap();
        let query = test_query();

        let response = pool.query(&query).await.unwrap();
        assert_eq!(response.message_type(), MessageType::Response);

        let snap = obs.snapshot();
        assert_eq!(snap.upstreams.len(), 1);
        let u = &snap.upstreams[0];
        assert_eq!(u.name, "ok");
        assert_eq!(u.success_count, 1);
        assert_eq!(u.failure_count, 0);
        assert!(u.last_success_latency_ms.is_some());
        assert!(u.avg_success_latency_ms.is_some());
    }
}
