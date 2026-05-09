//! DoT server.

use crate::blocklist::ReloadableBlocklist;
use crate::cache::Cache;
use crate::config::{Config, EdnsConfig};
use crate::metrics::MetricsRecorder;
use crate::upstream::{UpstreamError, UpstreamPool};
use hickory_proto::op::{Edns, Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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

#[derive(Debug, Clone)]
pub struct Server {
    config: Arc<Config>,
    metrics: Arc<MetricsRecorder>,
    cache: Arc<Cache>,
    blocklist: Arc<ReloadableBlocklist>,
    pool: UpstreamPool,
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
        }
    }

    pub async fn run(self) -> Result<(), ServerError> {
        let acceptor = self.build_acceptor().await?;
        let listener = TcpListener::bind(self.config.server.bind).await?;
        let idle_timeout = self.config.server.idle_timeout;

        tracing::info!("DoT server listening on {}", self.config.server.bind);

        loop {
            let (stream, peer) = listener.accept().await?;
            let acceptor = acceptor.clone();
            let metrics = self.metrics.clone();
            let cache = self.cache.clone();
            let blocklist = self.blocklist.clone();
            let pool = self.pool.clone();
            let edns = self.config.edns.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_connection(
                    stream,
                    acceptor,
                    peer,
                    metrics,
                    cache,
                    blocklist,
                    pool,
                    edns,
                    idle_timeout,
                )
                .await
                {
                    tracing::debug!(peer = %peer, error = %e, "connection closed");
                }
            });
        }
    }

    async fn build_acceptor(&self) -> Result<TlsAcceptor, ServerError> {
        if !self.config.tls.enabled {
            return Err(ServerError::Tls("TLS is not enabled in config".into()));
        }
        let cert_path = self
            .config
            .tls
            .cert_path
            .as_ref()
            .ok_or_else(|| ServerError::Tls("missing cert_path".into()))?;
        let key_path = self
            .config
            .tls
            .key_path
            .as_ref()
            .ok_or_else(|| ServerError::Tls("missing key_path".into()))?;

        let certs = load_certs(cert_path)?;
        let key = load_key(key_path)?;

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| ServerError::Tls(e.to_string()))?;

        Ok(TlsAcceptor::from(Arc::new(config)))
    }
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
    acceptor: TlsAcceptor,
    peer: SocketAddr,
    metrics: Arc<MetricsRecorder>,
    cache: Arc<Cache>,
    blocklist: Arc<ReloadableBlocklist>,
    pool: UpstreamPool,
    edns: EdnsConfig,
    idle_timeout: Duration,
) -> Result<(), ServerError> {
    let mut tls_stream = acceptor
        .accept(stream)
        .await
        .map_err(|e| ServerError::Tls(e.to_string()))?;

    loop {
        match read_message(&mut tls_stream, idle_timeout).await {
            Ok(Some(query)) => {
                let response = resolve_with_context(
                    query,
                    &metrics,
                    &cache,
                    &blocklist,
                    &pool,
                    Some(peer.ip()),
                    &edns,
                )
                .await;
                if let Err(e) = write_message(&mut tls_stream, &response, idle_timeout).await {
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

/// Main resolve path.
pub async fn resolve(
    query: Message,
    metrics: &MetricsRecorder,
    cache: &Cache,
    blocklist: &ReloadableBlocklist,
    pool: &UpstreamPool,
) -> Message {
    resolve_with_context(
        query,
        metrics,
        cache,
        blocklist,
        pool,
        None,
        &EdnsConfig::default(),
    )
    .await
}

pub async fn resolve_with_context(
    query: Message,
    metrics: &MetricsRecorder,
    cache: &Cache,
    blocklist: &ReloadableBlocklist,
    pool: &UpstreamPool,
    client_ip: Option<IpAddr>,
    edns: &EdnsConfig,
) -> Message {
    metrics.record_query();

    let q = match query.queries().first() {
        Some(q) => q,
        None => {
            return make_error_response(&query, ResponseCode::FormErr);
        }
    };

    let domain = q.name().to_utf8();
    let domain = domain.trim_end_matches('.');

    // Blocklist check
    if blocklist.decide(domain).is_blocked() {
        metrics.record_blocked();
        let mut resp = Message::new();
        apply_query_meta(&query, &mut resp);
        resp.set_response_code(ResponseCode::NoError);
        match q.query_type() {
            RecordType::A => {
                let record = Record::from_rdata(
                    q.name().clone(),
                    0,
                    hickory_proto::rr::RData::A(A(Ipv4Addr::new(0, 0, 0, 0))),
                );
                resp.add_answer(record);
            }
            RecordType::AAAA => {
                let record = Record::from_rdata(
                    q.name().clone(),
                    0,
                    hickory_proto::rr::RData::AAAA(AAAA(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))),
                );
                resp.add_answer(record);
            }
            _ => {}
        }
        return resp;
    }

    let upstream_query = query_with_ecs(&query, client_ip, edns);

    // Cache check
    if let Some(cached) = cache.get(&upstream_query) {
        metrics.record_cache_hit();
        let mut resp = cached;
        resp.set_id(query.id());
        return resp;
    }

    metrics.record_cache_miss();

    // Forward to upstream
    match pool.query(&upstream_query).await {
        Ok(response) => {
            cache.insert(&upstream_query, &response);
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

    #[tokio::test]
    async fn resolver_blocklist_before_upstream() {
        let mut engine = BlocklistEngine::empty();
        engine.add_block("blocked.com");
        let blocklist = Arc::new(ReloadableBlocklist::from_engine(engine, vec![]));
        let metrics = Arc::new(MetricsRecorder::new());
        let cache = Arc::new(Cache::new(CacheConfig::default(), metrics.clone()));

        // Upstream that will fail if contacted.
        let entry = UpstreamEntry {
            name: "fail".into(),
            address: "127.0.0.1:1".into(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            extra: Default::default(),
        };
        let pool = pool_from_config(&[entry], None).unwrap();

        let query = test_query("blocked.com.", RecordType::A);
        let resp = resolve(query, &metrics, &cache, &blocklist, &pool).await;

        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        let snap = metrics.snapshot();
        assert_eq!(snap.blocked_queries, 1);
        assert_eq!(snap.total_queries, 1);
        assert_eq!(snap.upstream_failures, 0); // blocklist prevented upstream call
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
    }

    #[tokio::test]
    async fn resolver_cache_hit_miss() {
        let (_handle, addr) = start_mock_udp_server("127.0.0.1:0").await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let entry = UpstreamEntry {
            name: "mock".into(),
            address: addr.to_string(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            extra: Default::default(),
        };
        let metrics = Arc::new(MetricsRecorder::new());
        let cache = Arc::new(Cache::new(CacheConfig::default(), metrics.clone()));
        let blocklist = Arc::new(ReloadableBlocklist::new(vec![]));
        let pool = pool_from_config(&[entry], None).unwrap();

        let query = test_query("example.com.", RecordType::A);
        // First query -> miss
        let resp1 = resolve(query.clone(), &metrics, &cache, &blocklist, &pool).await;
        assert_eq!(resp1.message_type(), MessageType::Response);
        let snap = metrics.snapshot();
        assert_eq!(snap.cache_misses, 1);
        assert_eq!(snap.cache_hits, 0);

        // Second query -> hit
        let resp2 = resolve(query.clone(), &metrics, &cache, &blocklist, &pool).await;
        assert_eq!(resp2.message_type(), MessageType::Response);
        let snap = metrics.snapshot();
        assert_eq!(snap.cache_hits, 1);
    }

    #[tokio::test]
    async fn resolver_preserves_edns() {
        let (_handle, addr) = start_mock_udp_server("127.0.0.1:0").await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let entry = UpstreamEntry {
            name: "mock".into(),
            address: addr.to_string(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            extra: Default::default(),
        };
        let metrics = Arc::new(MetricsRecorder::new());
        let cache = Arc::new(Cache::new(CacheConfig::default(), metrics.clone()));
        let blocklist = Arc::new(ReloadableBlocklist::new(vec![]));
        let pool = pool_from_config(&[entry], None).unwrap();

        let query = test_query_with_edns("example.com.", RecordType::A);
        let resp = resolve(query.clone(), &metrics, &cache, &blocklist, &pool).await;

        // Response should have EDNS because the mock echoes the query (which had EDNS)
        // and resolve preserves it.
        assert!(resp.extensions().as_ref().is_some());
    }
}
