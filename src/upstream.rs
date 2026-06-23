use crate::config::{UpstreamEntry, UpstreamProtocol, UpstreamSelectionPolicy};
use crate::metrics::MetricsRecorder;
use crate::observability::ObservabilityRegistry;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::error::Error;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket as StdUdpSocket};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

use reqwest::Client as HttpClient;
use rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

/// Reusable TLS stream to a DoT upstream endpoint.
type DotTlsStream = tokio_rustls::client::TlsStream<TcpStream>;

/// Idle keep-alive connections keyed by endpoint, with the time each was returned
/// to the pool (used to discard stale connections).
type DotIdlePool = Arc<Mutex<HashMap<SocketAddr, Vec<(DotTlsStream, Instant)>>>>;

/// Maximum idle DoT connections kept per endpoint for reuse.
const DOT_MAX_IDLE_PER_ENDPOINT: usize = 8;

/// Idle DoT connections older than this are discarded rather than reused, since
/// upstreams typically close idle TLS sessions after a short period.
const DOT_IDLE_MAX_AGE: Duration = Duration::from_secs(30);

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

/// Upper bound for the UDP leg of a plain query. A UDP datagram either comes
/// back quickly or is lost, so waiting the full (often multi-second) upstream
/// timeout on UDP only delays the TCP retry and, ultimately, failover to the
/// next upstream. Capping UDP keeps a single dead upstream from stacking
/// `udp_timeout + tcp_timeout` of latency before the pool moves on.
const PLAIN_UDP_TIMEOUT_CAP: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct PlainUpstream {
    address: String,
    /// Timeout for the UDP attempt (kept short so a lost datagram fails over fast).
    udp_timeout: Duration,
    /// Timeout for the TCP attempt / retry (uses the full configured budget).
    tcp_timeout: Duration,
}

impl PlainUpstream {
    pub fn new(address: &str, timeout: Duration) -> Self {
        // UDP and TCP get distinct deadlines: UDP is capped so a black-holed
        // datagram doesn't burn the whole budget, while TCP keeps the full
        // timeout because a successful handshake legitimately takes longer.
        let udp_timeout = timeout.min(PLAIN_UDP_TIMEOUT_CAP);
        Self {
            address: address.to_string(),
            udp_timeout,
            tcp_timeout: timeout,
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

        tokio::time::timeout(self.udp_timeout, async {
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

        tokio::time::timeout(self.tcp_timeout, async {
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
    /// Idle keep-alive connections per endpoint, shared across clones so the
    /// whole process reuses TLS sessions instead of handshaking per query.
    idle: DotIdlePool,
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
            idle: Arc::new(Mutex::new(HashMap::new())),
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
            // Try a pooled keep-alive connection first to avoid a fresh TCP+TLS
            // handshake (often the dominant component of DoT latency).
            if let Some(stream) = self.checkout(endpoint).await {
                if let Ok((msg, stream)) = Self::exchange(stream, &msg_bytes).await {
                    self.checkin(endpoint, stream).await;
                    return Ok(msg);
                }
                // The pooled connection was stale/broken; fall through to a fresh one.
            }

            let stream = self.connect(endpoint).await?;
            let (msg, stream) = Self::exchange(stream, &msg_bytes).await?;
            self.checkin(endpoint, stream).await;
            Ok(msg)
        })
        .await
        .map_err(|_| UpstreamError::Timeout)?
    }

    async fn connect(&self, endpoint: SocketAddr) -> Result<DotTlsStream, UpstreamError> {
        let stream = TcpStream::connect(endpoint).await?;
        let _ = stream.set_nodelay(true);
        let connector = TlsConnector::from(self.tls_config.clone());
        let server_name = ServerName::try_from(self.hostname.clone())
            .map_err(|e| UpstreamError::Network(format!("invalid server name: {}", e)))?;
        let tls_stream = connector.connect(server_name, stream).await?;
        Ok(tls_stream)
    }

    /// Sends one query and reads one response over `stream`, returning the stream
    /// for reuse only when the full exchange succeeds.
    async fn exchange(
        mut stream: DotTlsStream,
        msg_bytes: &[u8],
    ) -> Result<(Message, DotTlsStream), UpstreamError> {
        // Same 2-byte length prefix as plain TCP.
        stream.write_u16(msg_bytes.len() as u16).await?;
        stream.write_all(msg_bytes).await?;

        let resp_len = stream.read_u16().await? as usize;
        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await?;

        let msg = Message::from_bytes(&resp_buf)?;
        Ok((msg, stream))
    }

    async fn checkout(&self, endpoint: SocketAddr) -> Option<DotTlsStream> {
        let mut idle = self.idle.lock().await;
        let conns = idle.get_mut(&endpoint)?;
        while let Some((stream, since)) = conns.pop() {
            if since.elapsed() < DOT_IDLE_MAX_AGE {
                return Some(stream);
            }
            // Otherwise the connection is too old; drop it and try the next.
        }
        None
    }

    async fn checkin(&self, endpoint: SocketAddr, stream: DotTlsStream) {
        let mut idle = self.idle.lock().await;
        let conns = idle.entry(endpoint).or_default();
        if conns.len() < DOT_MAX_IDLE_PER_ENDPOINT {
            conns.push((stream, Instant::now()));
        }
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

fn bootstrap_query_id() -> u16 {
    // No `rand` dependency is available; mix the high-resolution clock with a
    // process-wide counter to avoid a predictable, fixed transaction ID. This is
    // not cryptographic randomness, but combined with the connected UDP socket
    // (source filtering) it closes the practical off-path spoofing window.
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed) as u32;
    let mixed = nanos ^ counter.rotate_left(16);
    (mixed as u16) ^ ((mixed >> 16) as u16)
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
    // Connect so the kernel only delivers datagrams from the bootstrap server,
    // dropping spoofed responses from other sources.
    socket.connect(server)?;

    let name = Name::from_str(host).or_else(|_| Name::from_str(&format!("{host}.")))?;
    let query_id = bootstrap_query_id();
    let mut query = Message::new();
    query.set_id(query_id);
    query.set_message_type(MessageType::Query);
    query.set_op_code(OpCode::Query);
    query.set_recursion_desired(true);
    query.add_query(Query::query(name.clone(), record_type));

    let bytes = query.to_bytes()?;
    socket.send(&bytes)?;

    // Read until a datagram matching our transaction ID and question arrives, or
    // the deadline elapses. This rejects responses that don't correspond to our
    // query (off-path spoofing / stale replies).
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = vec![0u8; 65535];
    loop {
        if Instant::now() >= deadline {
            return Err(UpstreamError::Timeout);
        }
        let len = socket.recv(&mut buf)?;
        let response = match Message::from_bytes(&buf[..len]) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if response.id() != query_id {
            continue;
        }
        if response.message_type() != MessageType::Response {
            continue;
        }
        let question_matches = response
            .queries()
            .iter()
            .any(|q| q.query_type() == record_type && q.name() == &name);
        if !question_matches {
            continue;
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
        return Ok(ips);
    }
}

fn port_from_address(address: &str) -> Option<u16> {
    if address.starts_with('[') {
        return address.rsplit_once(':')?.1.parse().ok();
    }
    address.rsplit_once(':')?.1.parse().ok()
}

/// Consecutive failures before an upstream is temporarily degraded (tried only
/// as a last resort). Kept low so a flapping upstream like a congested plain
/// resolver is sidelined quickly, but high enough to tolerate a single blip.
const HEALTH_FAILURE_THRESHOLD: u32 = 3;

/// How long a degraded upstream stays sidelined before it is eligible again.
/// After the cooldown it is retried; a success immediately restores it.
const HEALTH_COOLDOWN: Duration = Duration::from_secs(30);

/// Brief pause after a failed attempt before trying the next upstream. Gives a
/// momentarily congested path a chance to drain without holding the client
/// query hostage, while still failing over promptly.
const FAILOVER_DELAY: Duration = Duration::from_millis(50);

/// Per-upstream passive health, shared across `UpstreamPool` clones so failure
/// state is process-wide. All fields are atomics, so concurrent queries update
/// health without locking and never block one another.
#[derive(Debug)]
struct UpstreamHealth {
    consecutive_failures: AtomicU32,
    /// Milliseconds (relative to the pool's monotonic base) until which this
    /// upstream is degraded. `0` means healthy.
    degraded_until_ms: AtomicU64,
}

impl UpstreamHealth {
    fn new() -> Self {
        Self {
            consecutive_failures: AtomicU32::new(0),
            degraded_until_ms: AtomicU64::new(0),
        }
    }

    fn is_degraded(&self, now_ms: u64) -> bool {
        self.degraded_until_ms.load(Ordering::Acquire) > now_ms
    }

    fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Release);
        self.degraded_until_ms.store(0, Ordering::Release);
    }

    /// Records a failure and returns `true` if this failure pushed the upstream
    /// into the degraded state (so the caller can log the transition once).
    fn record_failure(&self, now_ms: u64) -> bool {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::AcqRel) + 1;
        if failures >= HEALTH_FAILURE_THRESHOLD {
            let until = now_ms + HEALTH_COOLDOWN.as_millis() as u64;
            let was_healthy = self.degraded_until_ms.swap(until, Ordering::AcqRel) <= now_ms;
            return was_healthy;
        }
        false
    }
}

#[derive(Debug, Clone)]
pub struct UpstreamPool {
    upstreams: Vec<(Upstream, String)>,
    metrics: Option<Arc<MetricsRecorder>>,
    observability: Option<Arc<ObservabilityRegistry>>,
    policy: UpstreamSelectionPolicy,
    round_robin_next: Arc<AtomicUsize>,
    /// Passive health tracker, one entry per upstream (parallel to `upstreams`).
    health: Vec<Arc<UpstreamHealth>>,
    /// Monotonic reference point for `degraded_until_ms`.
    base: Instant,
}

impl UpstreamPool {
    pub fn new(
        upstreams: Vec<(Upstream, String)>,
        metrics: Option<Arc<MetricsRecorder>>,
        observability: Option<Arc<ObservabilityRegistry>>,
        policy: UpstreamSelectionPolicy,
    ) -> Self {
        let health = upstreams
            .iter()
            .map(|_| Arc::new(UpstreamHealth::new()))
            .collect();
        Self {
            upstreams,
            metrics,
            observability,
            policy,
            round_robin_next: Arc::new(AtomicUsize::new(0)),
            health,
            base: Instant::now(),
        }
    }

    /// Builds the order in which upstreams are tried for this query: honor the
    /// configured policy for the starting point, but float currently-healthy
    /// upstreams ahead of degraded ones so a sidelined resolver is only used as
    /// a last resort.
    fn attempt_order(&self, start: usize, now_ms: u64) -> Vec<usize> {
        let len = self.upstreams.len();
        let mut healthy = Vec::with_capacity(len);
        let mut degraded = Vec::new();
        for offset in 0..len {
            let idx = (start + offset) % len;
            if self.health[idx].is_degraded(now_ms) {
                degraded.push(idx);
            } else {
                healthy.push(idx);
            }
        }
        healthy.extend(degraded);
        healthy
    }

    pub async fn query(&self, message: &Message) -> Result<Message, UpstreamError> {
        let len = self.upstreams.len();
        if len == 0 {
            return Err(UpstreamError::AllFailed);
        }

        let start = match self.policy {
            UpstreamSelectionPolicy::Sequential => 0,
            UpstreamSelectionPolicy::RoundRobin => {
                self.round_robin_next.fetch_add(1, Ordering::Relaxed) % len
            }
        };

        let now_ms = self.base.elapsed().as_millis() as u64;
        let order = self.attempt_order(start, now_ms);

        let mut last_err = None;
        for (attempt, &idx) in order.iter().enumerate() {
            let (upstream, name) = &self.upstreams[idx];
            // After a failed attempt, pause briefly before failing over so a
            // momentarily congested upstream can recover. This sleep is async
            // and per-query, so it never blocks other concurrent queries.
            if attempt > 0 {
                tokio::time::sleep(FAILOVER_DELAY).await;
            }
            let start_time = std::time::Instant::now();
            match upstream.query(message).await {
                Ok(response) => {
                    let elapsed = start_time.elapsed().as_millis() as u64;
                    self.health[idx].record_success();
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
                    let now_ms = self.base.elapsed().as_millis() as u64;
                    if self.health[idx].record_failure(now_ms) {
                        tracing::warn!(
                            upstream = %name,
                            cooldown_secs = HEALTH_COOLDOWN.as_secs(),
                            "upstream degraded after consecutive failures; deprioritizing"
                        );
                    }
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
    policy: UpstreamSelectionPolicy,
) -> Result<UpstreamPool, UpstreamError> {
    let mut upstreams = Vec::with_capacity(entries.len());
    for entry in entries {
        let upstream = Upstream::from_entry(entry, bootstrap_dns)?;
        upstreams.push((upstream, entry.name.clone()));
    }
    Ok(UpstreamPool::new(upstreams, metrics, observability, policy))
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

        let pool = pool_from_config(
            &[entry1, entry2],
            &[],
            None,
            None,
            UpstreamSelectionPolicy::Sequential,
        )
        .unwrap();
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

        let pool = pool_from_config(
            &[entry.clone(), entry],
            &[],
            None,
            None,
            UpstreamSelectionPolicy::Sequential,
        )
        .unwrap();
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
        let pool = pool_from_config(
            &[entry.clone(), entry],
            &[],
            Some(metrics.clone()),
            None,
            UpstreamSelectionPolicy::Sequential,
        )
        .unwrap();
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
        let pool = pool_from_config(
            &[entry.clone(), entry],
            &[],
            None,
            Some(obs.clone()),
            UpstreamSelectionPolicy::Sequential,
        )
        .unwrap();
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
        let pool = pool_from_config(
            &[entry],
            &[],
            None,
            Some(obs.clone()),
            UpstreamSelectionPolicy::Sequential,
        )
        .unwrap();
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

    #[tokio::test]
    async fn round_robin_alternates_upstreams() {
        let entry1 = UpstreamEntry {
            name: "u1".into(),
            address: "127.0.0.1:0".into(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            timeout: Duration::from_secs(5),
        };
        let entry2 = UpstreamEntry {
            name: "u2".into(),
            address: "127.0.0.1:0".into(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            timeout: Duration::from_secs(5),
        };

        let (_handle1, addr1) = start_mock_udp_server("127.0.0.1:0").await;
        let (_handle2, addr2) = start_mock_udp_server("127.0.0.1:0").await;

        let mut entry1 = entry1;
        let mut entry2 = entry2;
        entry1.address = addr1.to_string();
        entry2.address = addr2.to_string();

        let obs = Arc::new(ObservabilityRegistry::with_upstreams(&[
            "u1".into(),
            "u2".into(),
        ]));
        let pool = pool_from_config(
            &[entry1, entry2],
            &[],
            None,
            Some(obs.clone()),
            UpstreamSelectionPolicy::RoundRobin,
        )
        .unwrap();
        let query = test_query();

        for _ in 0..4 {
            let response = pool.query(&query).await.unwrap();
            assert_eq!(response.message_type(), MessageType::Response);
        }

        let snap = obs.snapshot();
        let u1 = snap.upstreams.iter().find(|u| u.name == "u1").unwrap();
        let u2 = snap.upstreams.iter().find(|u| u.name == "u2").unwrap();
        assert_eq!(u1.success_count, 2);
        assert_eq!(u2.success_count, 2);
    }

    #[tokio::test]
    async fn round_robin_fallback_on_failure() {
        let entry1 = UpstreamEntry {
            name: "fail".into(),
            address: "127.0.0.1:1".into(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            timeout: Duration::from_secs(1),
        };
        let entry2 = UpstreamEntry {
            name: "ok".into(),
            address: "127.0.0.1:0".into(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            timeout: Duration::from_secs(5),
        };

        let (_handle, ok_addr) = start_mock_udp_server("127.0.0.1:0").await;
        let mut entry2 = entry2;
        entry2.address = ok_addr.to_string();

        let obs = Arc::new(ObservabilityRegistry::with_upstreams(&[
            "fail".into(),
            "ok".into(),
        ]));
        let pool = pool_from_config(
            &[entry1, entry2],
            &[],
            None,
            Some(obs.clone()),
            UpstreamSelectionPolicy::RoundRobin,
        )
        .unwrap();
        let query = test_query();

        // First query tries u1 (index 0), fails, falls back to u2
        let response = pool.query(&query).await.unwrap();
        assert_eq!(response.message_type(), MessageType::Response);

        // Second query tries u2 (index 1), succeeds directly
        let response = pool.query(&query).await.unwrap();
        assert_eq!(response.message_type(), MessageType::Response);

        let snap = obs.snapshot();
        let u_fail = snap.upstreams.iter().find(|u| u.name == "fail").unwrap();
        let u_ok = snap.upstreams.iter().find(|u| u.name == "ok").unwrap();
        assert_eq!(u_fail.failure_count, 1);
        assert_eq!(u_ok.success_count, 2);
    }

    #[tokio::test]
    async fn round_robin_single_upstream() {
        let entry = UpstreamEntry {
            name: "only".into(),
            address: "127.0.0.1:0".into(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            timeout: Duration::from_secs(5),
        };

        let (_handle, addr) = start_mock_udp_server("127.0.0.1:0").await;
        let mut entry = entry;
        entry.address = addr.to_string();

        let obs = Arc::new(ObservabilityRegistry::with_upstreams(&["only".into()]));
        let pool = pool_from_config(
            &[entry],
            &[],
            None,
            Some(obs.clone()),
            UpstreamSelectionPolicy::RoundRobin,
        )
        .unwrap();
        let query = test_query();

        let response = pool.query(&query).await.unwrap();
        assert_eq!(response.message_type(), MessageType::Response);

        let snap = obs.snapshot();
        assert_eq!(snap.upstreams[0].success_count, 1);
    }

    #[tokio::test]
    async fn round_robin_all_failed() {
        let entry = UpstreamEntry {
            name: "fail".into(),
            address: "127.0.0.1:1".into(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            timeout: Duration::from_secs(1),
        };

        let pool = pool_from_config(
            &[entry.clone(), entry],
            &[],
            None,
            None,
            UpstreamSelectionPolicy::RoundRobin,
        )
        .unwrap();
        let query = test_query();

        let err = pool.query(&query).await.unwrap_err();
        assert!(matches!(err, UpstreamError::Network(_)));
    }

    #[tokio::test]
    async fn round_robin_empty_pool_returns_all_failed() {
        let pool = UpstreamPool::new(vec![], None, None, UpstreamSelectionPolicy::RoundRobin);
        let query = test_query();

        let err = pool.query(&query).await.unwrap_err();
        assert!(matches!(err, UpstreamError::AllFailed));
    }

    #[test]
    fn plain_upstream_caps_udp_timeout_below_tcp() {
        // A long configured timeout should leave TCP untouched but cap UDP so a
        // black-holed datagram fails over quickly instead of burning the budget.
        let u = PlainUpstream::new("127.0.0.1:53", Duration::from_secs(10));
        assert_eq!(u.tcp_timeout, Duration::from_secs(10));
        assert_eq!(u.udp_timeout, PLAIN_UDP_TIMEOUT_CAP);

        // A short timeout uses the same (small) value for both legs.
        let u = PlainUpstream::new("127.0.0.1:53", Duration::from_millis(500));
        assert_eq!(u.udp_timeout, Duration::from_millis(500));
        assert_eq!(u.tcp_timeout, Duration::from_millis(500));
    }

    #[test]
    fn upstream_health_degrades_after_threshold_and_recovers() {
        let health = UpstreamHealth::new();
        assert!(!health.is_degraded(0));

        // Below the threshold, the upstream stays healthy.
        for _ in 0..(HEALTH_FAILURE_THRESHOLD - 1) {
            assert!(!health.record_failure(0));
            assert!(!health.is_degraded(0));
        }
        // The threshold-th failure degrades it and reports the transition once.
        assert!(health.record_failure(0));
        assert!(health.is_degraded(0));
        // A further failure while already degraded does not re-report.
        assert!(!health.record_failure(0));

        // It is eligible again once the cooldown has elapsed.
        let after_cooldown = HEALTH_COOLDOWN.as_millis() as u64 + 1;
        assert!(!health.is_degraded(after_cooldown));

        // A success fully restores health.
        health.record_success();
        assert!(!health.is_degraded(0));
        assert_eq!(health.consecutive_failures.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn degraded_upstream_is_deprioritized() {
        // A dead upstream at index 0 (sequential policy) should be sidelined
        // after repeated failures so later queries try the healthy one first.
        let (_handle, ok_addr) = start_mock_udp_server("127.0.0.1:0").await;
        let dead = UpstreamEntry {
            name: "dead".into(),
            address: "127.0.0.1:1".into(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            timeout: Duration::from_millis(200),
        };
        let healthy = UpstreamEntry {
            name: "healthy".into(),
            address: ok_addr.to_string(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            timeout: Duration::from_secs(5),
        };

        let obs = Arc::new(ObservabilityRegistry::with_upstreams(&[
            "dead".into(),
            "healthy".into(),
        ]));
        let pool = pool_from_config(
            &[dead, healthy],
            &[],
            None,
            Some(obs.clone()),
            UpstreamSelectionPolicy::Sequential,
        )
        .unwrap();
        let query = test_query();

        // Drive enough queries to push the dead upstream past the degradation
        // threshold; every query still succeeds via failover.
        for _ in 0..HEALTH_FAILURE_THRESHOLD {
            let response = pool.query(&query).await.unwrap();
            assert_eq!(response.message_type(), MessageType::Response);
        }

        // The dead upstream is now degraded: attempt order floats the healthy
        // one to the front even though sequential policy starts at index 0.
        let order = pool.attempt_order(0, pool.base.elapsed().as_millis() as u64);
        assert_eq!(order.first().copied(), Some(1), "healthy upstream should be tried first");

        let failures_before = obs
            .snapshot()
            .upstreams
            .iter()
            .find(|u| u.name == "dead")
            .unwrap()
            .failure_count;

        // A subsequent query should hit the healthy upstream directly and no
        // longer touch the degraded one.
        pool.query(&query).await.unwrap();
        let failures_after = obs
            .snapshot()
            .upstreams
            .iter()
            .find(|u| u.name == "dead")
            .unwrap()
            .failure_count;
        assert_eq!(
            failures_before, failures_after,
            "degraded upstream should be skipped while a healthy one answers"
        );
    }
}
