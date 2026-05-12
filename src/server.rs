//! DoT server.

use crate::blocklist::ReloadableBlocklist;
use crate::cache::Cache;
use crate::config::{BlocklistConfig, BlocklistResponseMode, Config, EdnsConfig};
use crate::metrics::MetricsRecorder;
use crate::upstream::{UpstreamError, UpstreamPool};
use hickory_proto::op::{Edns, Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_proto::rr::rdata::{A, AAAA, SOA};
use hickory_proto::rr::{Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex};
use tokio_rustls::TlsAcceptor;

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls error: {0}")]
    Tls(String),
    #[error("dns message error: {0}")]
    Dns(String),
    #[error("timeout")]
    Timeout,
}

impl From<UpstreamError> for ServerError {
    fn from(e: UpstreamError) -> Self {
        ServerError::Dns(e.to_string())
    }
}

type PendingResult = Result<Message, UpstreamError>;

#[derive(Debug, Clone, Default)]
pub(crate) struct PendingQueries {
    inner: Arc<Mutex<HashMap<Vec<u8>, PendingEntry>>>,
}

#[derive(Debug, Clone)]
struct PendingEntry {
    tx: watch::Sender<Option<PendingResult>>,
    rx: watch::Receiver<Option<PendingResult>>,
}

fn pending_key(query: &Message) -> Result<Vec<u8>, UpstreamError> {
    let mut clone = query.clone();
    clone.set_id(0);
    clone.to_bytes().map_err(UpstreamError::from)
}

impl PendingQueries {
    async fn query(&self, pool: &UpstreamPool, query: &Message) -> PendingResult {
        let key = pending_key(query)?;
        let (leader, mut rx) = {
            let mut inner = self.inner.lock().await;
            if let Some(entry) = inner.get(&key) {
                (false, entry.rx.clone())
            } else {
                let (tx, rx) = watch::channel(None);
                inner.insert(key.clone(), PendingEntry { tx, rx: rx.clone() });
                (true, rx)
            }
        };

        if !leader {
            loop {
                if let Some(result) = rx.borrow().clone() {
                    return result;
                }
                if rx.changed().await.is_err() {
                    return Err(UpstreamError::Network(
                        "pending upstream request was cancelled".into(),
                    ));
                }
            }
        }

        let result = pool.query(query).await;
        let tx = {
            let mut inner = self.inner.lock().await;
            inner.remove(&key).map(|entry| entry.tx)
        };
        if let Some(tx) = tx {
            let _ = tx.send(Some(result.clone()));
        }
        result
    }
}

#[derive(Debug, Clone)]
pub struct Server {
    config: Arc<Config>,
    metrics: Arc<MetricsRecorder>,
    cache: Arc<Cache>,
    blocklist: Arc<ReloadableBlocklist>,
    pool: UpstreamPool,
    pending: PendingQueries,
}

impl Server {
    pub fn new(
        config: Arc<Config>,
        metrics: Arc<MetricsRecorder>,
        cache: Arc<Cache>,
        blocklist: Arc<ReloadableBlocklist>,
        pool: UpstreamPool,
    ) -> Self {
        Self {
            config,
            metrics,
            cache,
            blocklist,
            pool,
            pending: PendingQueries::default(),
        }
    }

    pub async fn run(self) -> Result<(), ServerError> {
        let acceptor = self.build_acceptor().await?;
        let mut listeners = Vec::with_capacity(self.config.server.binds.len());
        for bind in &self.config.server.binds {
            let listener = bind_listener(*bind)?;
            tracing::info!("DoT server listening on {}", bind);
            listeners.push(listener);
        }

        let idle_timeout = self.config.server.idle_timeout;
        let mut tasks = tokio::task::JoinSet::new();

        for listener in listeners {
            tasks.spawn(accept_loop(
                listener,
                ConnectionContext {
                    acceptor: acceptor.clone(),
                    metrics: self.metrics.clone(),
                    cache: self.cache.clone(),
                    blocklist: self.blocklist.clone(),
                    pool: self.pool.clone(),
                    pending: self.pending.clone(),
                    edns: self.config.edns.clone(),
                    blocklist_config: self.config.blocklist.clone(),
                    idle_timeout,
                },
            ));
        }

        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(e) => return Err(ServerError::Tls(format!("listener task failed: {e}"))),
            }
        }

        Ok(())
    }

    async fn build_acceptor(&self) -> Result<TlsAcceptor, ServerError> {
        let config = build_tls_server_config(&self.config)?;

        Ok(TlsAcceptor::from(Arc::new(config)))
    }
}

pub fn validate_tls_config(config: &Config) -> Result<(), ServerError> {
    build_tls_server_config(config).map(|_| ())
}

fn build_tls_server_config(config: &Config) -> Result<rustls::ServerConfig, ServerError> {
    let cert_path = config
        .tls
        .cert_path
        .as_ref()
        .ok_or_else(|| ServerError::Tls("missing cert_path".into()))?;
    let key_path = config
        .tls
        .key_path
        .as_ref()
        .ok_or_else(|| ServerError::Tls("missing key_path".into()))?;

    let certs = load_certs(cert_path)?;
    if certs.is_empty() {
        return Err(ServerError::Tls(format!(
            "no certificates found in {}",
            cert_path.display()
        )));
    }
    let key = load_key(key_path)?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
        .map_err(|e| ServerError::Tls(e.to_string()))?;

    log_certificate_info(&certs);

    Ok(config)
}

fn log_certificate_info(certs: &[rustls::pki_types::CertificateDer<'static>]) {
    let cert = match certs.first() {
        Some(c) => c,
        None => return,
    };
    match x509_parser::parse_x509_certificate(cert.as_ref()) {
        Ok((_, cert)) => {
            let subject = cert.subject.to_string();
            let issuer = cert.issuer.to_string();
            let not_before = cert.validity.not_before.to_string();
            let not_after = cert.validity.not_after.to_string();
            tracing::info!(
                subject = %subject,
                issuer = %issuer,
                not_before = %not_before,
                not_after = %not_after,
                "TLS certificate verified successfully"
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to parse TLS certificate for logging");
        }
    }
}

#[derive(Clone)]
struct ConnectionContext {
    acceptor: TlsAcceptor,
    metrics: Arc<MetricsRecorder>,
    cache: Arc<Cache>,
    blocklist: Arc<ReloadableBlocklist>,
    pool: UpstreamPool,
    pending: PendingQueries,
    edns: EdnsConfig,
    blocklist_config: BlocklistConfig,
    idle_timeout: Duration,
}

async fn accept_loop(listener: TcpListener, ctx: ConnectionContext) -> Result<(), ServerError> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let conn_ctx = ctx.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer, conn_ctx).await {
                tracing::debug!(peer = %peer, error = %e, "connection closed");
            }
        });
    }
}

fn bind_listener(addr: SocketAddr) -> Result<TcpListener, ServerError> {
    let socket = if addr.is_ipv4() {
        Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?
    } else {
        let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_only_v6(true)?;
        socket
    };
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    let listener: std::net::TcpListener = socket.into();
    listener.set_nonblocking(true)?;
    TcpListener::from_std(listener).map_err(ServerError::Io)
}

fn load_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, ServerError> {
    let file = std::fs::File::open(path).map_err(ServerError::Io)?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ServerError::Tls(format!("failed to load certs: {}", e)))
}

fn load_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>, ServerError> {
    let file = std::fs::File::open(path).map_err(ServerError::Io)?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| ServerError::Tls(format!("failed to load key: {}", e)))?
        .ok_or_else(|| ServerError::Tls("no private key found".into()))
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    ctx: ConnectionContext,
) -> Result<(), ServerError> {
    let mut tls_stream = ctx
        .acceptor
        .accept(stream)
        .await
        .map_err(|e| ServerError::Tls(e.to_string()))?;

    loop {
        match read_message(&mut tls_stream, ctx.idle_timeout).await {
            Ok(Some(query)) => {
                let resolve_ctx = ResolveContext {
                    metrics: &ctx.metrics,
                    cache: &ctx.cache,
                    blocklist: &ctx.blocklist,
                    pool: &ctx.pool,
                    pending: &ctx.pending,
                    client_ip: Some(peer.ip()),
                    edns: &ctx.edns,
                    blocklist_config: &ctx.blocklist_config,
                };
                let response = resolve_with_context(query, &resolve_ctx).await;
                if let Err(e) = write_message(&mut tls_stream, &response, ctx.idle_timeout).await {
                    tracing::debug!(error = %e, "write error");
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                tracing::debug!(error = %e, "read error");
                break;
            }
        }
    }
    Ok(())
}

async fn read_message<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    timeout: Duration,
) -> Result<Option<Message>, ServerError> {
    let len = match tokio::time::timeout(timeout, reader.read_u16()).await {
        Ok(Ok(0)) => return Ok(None),
        Ok(Ok(n)) => n as usize,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err(ServerError::Timeout),
    };

    let mut buf = vec![0u8; len];
    match tokio::time::timeout(timeout, reader.read_exact(&mut buf)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err(ServerError::Timeout),
    }

    Message::from_bytes(&buf)
        .map_err(|e| ServerError::Dns(e.to_string()))
        .map(Some)
}

async fn write_message<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &Message,
    timeout: Duration,
) -> Result<(), ServerError> {
    let bytes = msg
        .to_bytes()
        .map_err(|e| ServerError::Dns(e.to_string()))?;
    let len = bytes.len() as u16;
    tokio::time::timeout(timeout, async {
        writer.write_u16(len).await?;
        writer.write_all(&bytes).await?;
        writer.flush().await?;
        Ok::<(), std::io::Error>(())
    })
    .await
    .map_err(|_| ServerError::Timeout)??;
    Ok(())
}

pub(crate) struct ResolveContext<'a> {
    pub(crate) metrics: &'a MetricsRecorder,
    pub(crate) cache: &'a Cache,
    pub(crate) blocklist: &'a ReloadableBlocklist,
    pub(crate) pool: &'a UpstreamPool,
    pub(crate) pending: &'a PendingQueries,
    pub(crate) client_ip: Option<IpAddr>,
    pub(crate) edns: &'a EdnsConfig,
    pub(crate) blocklist_config: &'a BlocklistConfig,
}

/// Main resolve path.
#[cfg(test)]
pub async fn resolve(
    query: Message,
    metrics: &MetricsRecorder,
    cache: &Cache,
    blocklist: &ReloadableBlocklist,
    pool: &UpstreamPool,
) -> Message {
    resolve_with_context(
        query,
        &ResolveContext {
            metrics,
            cache,
            blocklist,
            pool,
            pending: &PendingQueries::default(),
            client_ip: None,
            edns: &EdnsConfig::default(),
            blocklist_config: &BlocklistConfig::default(),
        },
    )
    .await
}

pub(crate) async fn resolve_with_context(query: Message, ctx: &ResolveContext<'_>) -> Message {
    ctx.metrics.record_query();

    let q = match query.queries().first() {
        Some(q) => q,
        None => {
            return make_error_response(&query, ResponseCode::FormErr);
        }
    };

    let domain = q.name().to_utf8();
    let domain = domain.trim_end_matches('.');

    // Blocklist check
    if ctx.blocklist.decide(domain).is_blocked() {
        ctx.metrics.record_blocked();
        return make_blocked_response(&query, ctx.blocklist_config);
    }

    let upstream_query = query_with_ecs(&query, ctx.client_ip, ctx.edns);

    // Cache check
    if let Some(cached) = ctx.cache.get(&upstream_query) {
        ctx.metrics.record_cache_hit();
        let mut resp = cached;
        resp.set_id(query.id());
        return resp;
    }

    ctx.metrics.record_cache_miss();

    // Forward to upstream
    match ctx.pending.query(ctx.pool, &upstream_query).await {
        Ok(mut response) => {
            response.set_id(query.id());
            ctx.cache.insert(&upstream_query, &response);
            response
        }
        Err(e) => {
            tracing::warn!(error = %e, "upstream query failed");
            make_error_response(&query, ResponseCode::ServFail)
        }
    }
}

fn query_with_ecs(query: &Message, client_ip: Option<IpAddr>, config: &EdnsConfig) -> Message {
    if !config.enabled || !config.client_subnet.enabled {
        return query.clone();
    }
    if config.preserve_client && query_has_ecs(query) {
        return query.clone();
    }
    let Some(ip) = client_ip else {
        return query.clone();
    };
    let Some(subnet) = client_subnet(ip, config) else {
        return query.clone();
    };

    let mut next = query.clone();
    let mut edns = next
        .extensions()
        .as_ref()
        .cloned()
        .unwrap_or_else(Edns::new);
    edns.options_mut().insert(EdnsOption::Subnet(subnet));
    next.set_edns(edns);
    next
}

fn query_has_ecs(query: &Message) -> bool {
    query
        .extensions()
        .as_ref()
        .and_then(|edns| edns.option(EdnsCode::Subnet))
        .is_some()
}

fn client_subnet(ip: IpAddr, config: &EdnsConfig) -> Option<ClientSubnet> {
    if config.client_subnet.exclude_private && !is_public_client_ip(ip) {
        return None;
    }

    let prefix = match ip {
        IpAddr::V4(_) => config.client_subnet.ipv4_prefix,
        IpAddr::V6(_) => config.client_subnet.ipv6_prefix,
    };
    Some(ClientSubnet::new(mask_ip(ip, prefix), prefix, 0))
}

fn is_public_client_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && !ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_unique_local()
                && !ip.is_unicast_link_local()
        }
    }
}

fn mask_ip(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from(mask_bits(u32::from(ip), prefix, 32))),
        IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(mask_bits(u128::from(ip), prefix, 128))),
    }
}

fn mask_bits<T>(value: T, prefix: u8, total_bits: u8) -> T
where
    T: Copy
        + From<u8>
        + std::ops::Not<Output = T>
        + std::ops::BitAnd<Output = T>
        + std::ops::Shl<u8, Output = T>,
{
    if prefix == 0 {
        return T::from(0);
    }
    value & (!T::from(0) << (total_bits - prefix))
}

fn make_blocked_response(query: &Message, config: &BlocklistConfig) -> Message {
    let mut resp = Message::new();
    apply_query_meta(query, &mut resp);
    let ttl = config.blocked_ttl.as_secs().min(u32::MAX as u64) as u32;
    let Some(q) = query.queries().first() else {
        resp.set_response_code(ResponseCode::FormErr);
        return resp;
    };

    match config.response_mode {
        BlocklistResponseMode::NullIp => {
            resp.set_response_code(ResponseCode::NoError);
            match q.query_type() {
                RecordType::A => {
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        ttl,
                        hickory_proto::rr::RData::A(A(Ipv4Addr::new(0, 0, 0, 0))),
                    ));
                }
                RecordType::AAAA => {
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        ttl,
                        hickory_proto::rr::RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)),
                    ));
                }
                _ => add_blocked_soa(&mut resp, q.name().clone(), ttl),
            }
        }
        BlocklistResponseMode::NoData => {
            resp.set_response_code(ResponseCode::NoError);
            add_blocked_soa(&mut resp, q.name().clone(), ttl);
        }
        BlocklistResponseMode::NxDomain => {
            resp.set_response_code(ResponseCode::NXDomain);
            add_blocked_soa(&mut resp, q.name().clone(), ttl);
        }
    }

    resp
}

fn add_blocked_soa(response: &mut Message, name: hickory_proto::rr::Name, ttl: u32) {
    let mname =
        hickory_proto::rr::Name::from_ascii("blocked.dotdns.").expect("static SOA mname is valid");
    let rname = hickory_proto::rr::Name::from_ascii("hostmaster.blocked.dotdns.")
        .expect("static SOA rname is valid");
    let soa = SOA::new(mname, rname, 1, 1800, 900, 604800, ttl);
    response.add_name_server(Record::from_rdata(
        name,
        ttl,
        hickory_proto::rr::RData::SOA(soa),
    ));
}

fn make_error_response(query: &Message, code: ResponseCode) -> Message {
    let mut resp = Message::new();
    apply_query_meta(query, &mut resp);
    resp.set_response_code(code);
    resp
}

fn apply_query_meta(query: &Message, response: &mut Message) {
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(query.op_code());
    response.set_recursion_desired(query.recursion_desired());
    if let Some(edns) = query.extensions().as_ref() {
        response.set_edns(edns.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocklist::BlocklistEngine;
    use crate::cache::Cache;
    use crate::config::{CacheConfig, ClientSubnetConfig, UpstreamEntry, UpstreamProtocol};
    use crate::metrics::MetricsRecorder;
    use crate::upstream::pool_from_config;
    use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::net::UdpSocket;

    fn test_query(name: &str, qtype: RecordType) -> Message {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(true);
        msg.add_query(Query::query(Name::from_str(name).unwrap(), qtype));
        msg
    }

    fn test_query_with_edns(name: &str, qtype: RecordType) -> Message {
        let mut msg = test_query(name, qtype);
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_dnssec_ok(true);
        msg.set_edns(edns);
        msg
    }

    fn ecs_config() -> EdnsConfig {
        EdnsConfig {
            enabled: true,
            preserve_client: true,
            client_subnet: ClientSubnetConfig {
                enabled: true,
                ipv4_prefix: 24,
                ipv6_prefix: 56,
                exclude_private: true,
            },
        }
    }

    fn ecs_bytes(query: &Message) -> Option<Vec<u8>> {
        match query
            .extensions()
            .as_ref()
            .and_then(|edns| edns.option(EdnsCode::Subnet))
        {
            Some(EdnsOption::Subnet(subnet)) => Vec::try_from(subnet).ok(),
            _ => None,
        }
    }

    #[test]
    fn adds_ecs_from_public_client_ip() {
        let query = test_query("example.com.", RecordType::A);
        let next = query_with_ecs(
            &query,
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            &ecs_config(),
        );

        assert_eq!(ecs_bytes(&next).unwrap(), vec![0, 1, 24, 0, 8, 8, 8]);
    }

    #[test]
    fn skips_ecs_for_private_client_ip() {
        let query = test_query("example.com.", RecordType::A);
        let next = query_with_ecs(
            &query,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 25))),
            &ecs_config(),
        );

        assert!(ecs_bytes(&next).is_none());
    }

    #[test]
    fn preserves_client_ecs_by_default() {
        let mut query = test_query("example.com.", RecordType::A);
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 0)),
                24,
                0,
            )));
        query.set_edns(edns);

        let next = query_with_ecs(
            &query,
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            &ecs_config(),
        );

        assert_eq!(ecs_bytes(&next).unwrap(), vec![0, 1, 24, 0, 1, 1, 1]);
    }

    #[test]
    fn masks_ipv6_client_subnet() {
        let ip = IpAddr::V6("2606:4700:4700::1111".parse().unwrap());
        assert_eq!(
            mask_ip(ip, 56),
            IpAddr::V6("2606:4700:4700::".parse().unwrap())
        );
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
                // Add a dummy A answer so cache insertion has records to cache in tests.
                if let Some(q) = response.queries().first() {
                    if q.query_type() == RecordType::A {
                        let record = Record::from_rdata(
                            q.name().clone(),
                            300,
                            hickory_proto::rr::RData::A(A(Ipv4Addr::new(127, 0, 0, 1))),
                        );
                        response.add_answer(record);
                    }
                }
                if let Ok(bytes) = response.to_bytes() {
                    let _ = socket.send_to(&bytes, peer).await;
                }
            }
        });
        (handle, addr)
    }

    async fn start_counting_udp_server(
        bind: &str,
        count: Arc<AtomicUsize>,
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
                count.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(100)).await;
                let mut response = match Message::from_bytes(&buf[..len]) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                response.set_message_type(MessageType::Response);
                if let Some(q) = response.queries().first() {
                    let record = Record::from_rdata(
                        q.name().clone(),
                        300,
                        hickory_proto::rr::RData::A(A(Ipv4Addr::new(127, 0, 0, 1))),
                    );
                    response.add_answer(record);
                }
                if let Ok(bytes) = response.to_bytes() {
                    let _ = socket.send_to(&bytes, peer).await;
                }
            }
        });
        (handle, addr)
    }

    #[tokio::test]
    async fn resolver_blocklist_before_upstream() {
        let mut engine = BlocklistEngine::empty();
        engine.add_block("blocked.com");
        let blocklist = Arc::new(ReloadableBlocklist::from_engine(engine, vec![]));
        let metrics = Arc::new(MetricsRecorder::new());
        let cache = Arc::new(Cache::new(CacheConfig::default(), metrics.clone()));

        let entry = UpstreamEntry {
            name: "fail".into(),
            address: "127.0.0.1:1".into(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
        };
        let pool = pool_from_config(&[entry], &[], None).unwrap();

        let query = test_query("blocked.com.", RecordType::A);
        let resp = resolve(query, &metrics, &cache, &blocklist, &pool).await;

        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        let snap = metrics.snapshot();
        assert_eq!(snap.blocked_queries, 1);
        assert_eq!(snap.total_queries, 1);
        assert_eq!(snap.upstream_failures, 0);
    }

    #[tokio::test]
    async fn resolver_blocked_a_returns_ipv4_zero() {
        let mut engine = BlocklistEngine::empty();
        engine.add_block("blocked.com");
        let blocklist = Arc::new(ReloadableBlocklist::from_engine(engine, vec![]));
        let metrics = Arc::new(MetricsRecorder::new());
        let cache = Arc::new(Cache::new(CacheConfig::default(), metrics.clone()));
        let pool = UpstreamPool::new(vec![], None);

        let query = test_query("blocked.com.", RecordType::A);
        let resp = resolve(query, &metrics, &cache, &blocklist, &pool).await;

        assert_eq!(resp.answers().len(), 1);
        let rdata = resp.answers()[0].data().unwrap();
        assert!(matches!(rdata, hickory_proto::rr::RData::A(a) if a.0 == Ipv4Addr::new(0,0,0,0)));
    }

    #[tokio::test]
    async fn resolver_blocked_aaaa_returns_ipv6_zero() {
        let mut engine = BlocklistEngine::empty();
        engine.add_block("blocked.com");
        let blocklist = Arc::new(ReloadableBlocklist::from_engine(engine, vec![]));
        let metrics = Arc::new(MetricsRecorder::new());
        let cache = Arc::new(Cache::new(CacheConfig::default(), metrics.clone()));
        let pool = UpstreamPool::new(vec![], None);

        let query = test_query("blocked.com.", RecordType::AAAA);
        let resp = resolve(query, &metrics, &cache, &blocklist, &pool).await;

        assert_eq!(resp.answers().len(), 1);
        let rdata = resp.answers()[0].data().unwrap();
        assert!(
            matches!(rdata, hickory_proto::rr::RData::AAAA(a) if a.0 == Ipv6Addr::new(0,0,0,0,0,0,0,0))
        );
    }

    #[tokio::test]
    async fn resolver_blocked_other_type_empty_success() {
        let mut engine = BlocklistEngine::empty();
        engine.add_block("blocked.com");
        let blocklist = Arc::new(ReloadableBlocklist::from_engine(engine, vec![]));
        let metrics = Arc::new(MetricsRecorder::new());
        let cache = Arc::new(Cache::new(CacheConfig::default(), metrics.clone()));
        let pool = UpstreamPool::new(vec![], None);

        let query = test_query("blocked.com.", RecordType::MX);
        let resp = resolve(query, &metrics, &cache, &blocklist, &pool).await;

        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 0);
        assert_eq!(resp.name_servers().len(), 1);
    }

    #[test]
    fn blocked_no_data_uses_soa_negative_cache() {
        let query = test_query("blocked.com.", RecordType::A);
        let config = BlocklistConfig {
            response_mode: BlocklistResponseMode::NoData,
            blocked_ttl: Duration::from_secs(60),
            ..BlocklistConfig::default()
        };

        let resp = make_blocked_response(&query, &config);

        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert!(resp.answers().is_empty());
        assert_eq!(resp.name_servers().len(), 1);
        assert_eq!(resp.name_servers()[0].ttl(), 60);
        assert!(matches!(
            resp.name_servers()[0].data().unwrap(),
            hickory_proto::rr::RData::SOA(_)
        ));
    }

    #[test]
    fn blocked_nx_domain_uses_soa_negative_cache() {
        let query = test_query("blocked.com.", RecordType::A);
        let config = BlocklistConfig {
            response_mode: BlocklistResponseMode::NxDomain,
            blocked_ttl: Duration::from_secs(120),
            ..BlocklistConfig::default()
        };

        let resp = make_blocked_response(&query, &config);

        assert_eq!(resp.response_code(), ResponseCode::NXDomain);
        assert!(resp.answers().is_empty());
        assert_eq!(resp.name_servers()[0].ttl(), 120);
    }

    #[tokio::test]
    async fn pending_queries_share_single_upstream_request() {
        let count = Arc::new(AtomicUsize::new(0));
        let (_handle, addr) = start_counting_udp_server("127.0.0.1:0", count.clone()).await;

        let entry = UpstreamEntry {
            name: "mock".into(),
            address: addr.to_string(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
        };
        let pool = pool_from_config(&[entry], &[], None).unwrap();
        let pending = PendingQueries::default();
        let mut query1 = test_query("example.com.", RecordType::A);
        query1.set_id(1000);
        let mut query2 = test_query("example.com.", RecordType::A);
        query2.set_id(2000);

        let (first, second) =
            tokio::join!(pending.query(&pool, &query1), pending.query(&pool, &query2));

        assert!(first.unwrap().answers().len() == 1);
        assert!(second.unwrap().answers().len() == 1);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn resolver_coalesces_different_ids_and_preserves_them() {
        let count = Arc::new(AtomicUsize::new(0));
        let (_handle, addr) = start_counting_udp_server("127.0.0.1:0", count.clone()).await;

        let entry = UpstreamEntry {
            name: "mock".into(),
            address: addr.to_string(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
        };
        let metrics = Arc::new(MetricsRecorder::new());
        let cache = Arc::new(Cache::new(CacheConfig::default(), metrics.clone()));
        let blocklist = Arc::new(ReloadableBlocklist::new(vec![]));
        let pool = pool_from_config(&[entry], &[], None).unwrap();
        let pending = PendingQueries::default();
        let edns = EdnsConfig::default();
        let blocklist_config = BlocklistConfig::default();

        let mut query1 = test_query("example.com.", RecordType::A);
        query1.set_id(1234);
        let mut query2 = test_query("example.com.", RecordType::A);
        query2.set_id(5678);

        let ctx = ResolveContext {
            metrics: &metrics,
            cache: &cache,
            blocklist: &blocklist,
            pool: &pool,
            pending: &pending,
            client_ip: None,
            edns: &edns,
            blocklist_config: &blocklist_config,
        };
        let (resp1, resp2) = tokio::join!(
            resolve_with_context(query1.clone(), &ctx),
            resolve_with_context(query2.clone(), &ctx),
        );

        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(resp1.id(), query1.id());
        assert_eq!(resp2.id(), query2.id());
    }

    #[tokio::test]
    async fn resolver_cache_hit_miss() {
        let (_handle, addr) = start_mock_udp_server("127.0.0.1:0").await;

        let entry = UpstreamEntry {
            name: "mock".into(),
            address: addr.to_string(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
        };
        let metrics = Arc::new(MetricsRecorder::new());
        let cache = Arc::new(Cache::new(CacheConfig::default(), metrics.clone()));
        let blocklist = Arc::new(ReloadableBlocklist::new(vec![]));
        let pool = pool_from_config(&[entry], &[], None).unwrap();

        let query = test_query("example.com.", RecordType::A);
        let resp1 = resolve(query.clone(), &metrics, &cache, &blocklist, &pool).await;
        assert_eq!(resp1.message_type(), MessageType::Response);
        let snap = metrics.snapshot();
        assert_eq!(snap.cache_misses, 1);
        assert_eq!(snap.cache_hits, 0);

        let resp2 = resolve(query.clone(), &metrics, &cache, &blocklist, &pool).await;
        assert_eq!(resp2.message_type(), MessageType::Response);
        let snap = metrics.snapshot();
        assert_eq!(snap.cache_hits, 1);
    }

    #[tokio::test]
    async fn resolver_preserves_edns() {
        let (_handle, addr) = start_mock_udp_server("127.0.0.1:0").await;

        let entry = UpstreamEntry {
            name: "mock".into(),
            address: addr.to_string(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
        };
        let metrics = Arc::new(MetricsRecorder::new());
        let cache = Arc::new(Cache::new(CacheConfig::default(), metrics.clone()));
        let blocklist = Arc::new(ReloadableBlocklist::new(vec![]));
        let pool = pool_from_config(&[entry], &[], None).unwrap();

        let query = test_query_with_edns("example.com.", RecordType::A);
        let resp = resolve(query.clone(), &metrics, &cache, &blocklist, &pool).await;

        assert!(resp.extensions().as_ref().is_some());
    }
}
