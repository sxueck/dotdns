//! DoT server.

use crate::blocklist::ReloadableBlocklist;
use crate::cache::Cache;
use crate::config::Config;
use crate::metrics::MetricsRecorder;
use crate::upstream::{UpstreamError, UpstreamPool};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::net::{Ipv4Addr, Ipv6Addr};
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

            tokio::spawn(async move {
                if let Err(e) = handle_connection(
                    stream,
                    acceptor,
                    metrics,
                    cache,
                    blocklist,
                    pool,
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
    metrics: Arc<MetricsRecorder>,
    cache: Arc<Cache>,
    blocklist: Arc<ReloadableBlocklist>,
    pool: UpstreamPool,
    idle_timeout: Duration,
) -> Result<(), ServerError> {
    let mut tls_stream = acceptor
        .accept(stream)
        .await
        .map_err(|e| ServerError::Tls(e.to_string()))?;

    loop {
        match read_message(&mut tls_stream, idle_timeout).await {
            Ok(Some(query)) => {
                let response = resolve(query, &metrics, &cache, &blocklist, &pool).await;
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

    // Cache check
    if let Some(cached) = cache.get(&query) {
        metrics.record_cache_hit();
        let mut resp = cached;
        resp.set_id(query.id());
        return resp;
    }

    metrics.record_cache_miss();

    // Forward to upstream
    match pool.query(&query).await {
        Ok(response) => {
            cache.insert(&query, &response);
            response
        }
        Err(e) => {
            tracing::warn!(error = %e, "upstream query failed");
            make_error_response(&query, ResponseCode::ServFail)
        }
    }
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
    use crate::config::{CacheConfig, UpstreamEntry, UpstreamProtocol};
    use crate::metrics::MetricsRecorder;
    use crate::upstream::pool_from_config;
    use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use std::net::{Ipv4Addr, Ipv6Addr};
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
