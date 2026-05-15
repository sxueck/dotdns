use axum::body::Bytes;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Extension, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::blocklist::ReloadableBlocklist;
use crate::cache::Cache;
use crate::config::{BlocklistConfig, Config, EdnsConfig};
use crate::metrics::MetricsRecorder;
use crate::observability::ObservabilityRegistry;
use crate::server::{
    bind_listener, build_tls_server_config, resolve_with_context, PendingQueries, ResolveContext,
};
use crate::upstream::UpstreamPool;

#[derive(Clone)]
pub(crate) struct DohState {
    pub(crate) metrics: Arc<MetricsRecorder>,
    pub(crate) cache: Arc<Cache>,
    pub(crate) blocklist: Arc<ReloadableBlocklist>,
    pub(crate) pool: UpstreamPool,
    pub(crate) pending: PendingQueries,
    pub(crate) edns: EdnsConfig,
    pub(crate) blocklist_config: BlocklistConfig,
    pub(crate) observability: Option<Arc<ObservabilityRegistry>>,
}

pub struct DohServer {
    binds: Vec<SocketAddr>,
    idle_timeout: Duration,
    state: DohState,
    tls_config: rustls::ServerConfig,
}

impl DohServer {
    pub fn new(config: &Config, state: DohState) -> Result<Self, crate::server::ServerError> {
        let tls_config = build_tls_server_config(config)?;
        let doh = config.doh.as_ref().expect("doh config present");
        Ok(Self {
            binds: doh.binds.clone(),
            idle_timeout: doh.idle_timeout,
            state,
            tls_config,
        })
    }

    pub async fn run(self) -> Result<(), crate::server::ServerError> {
        let acceptor = TlsAcceptor::from(Arc::new(self.tls_config));
        let mut listeners = Vec::with_capacity(self.binds.len());
        for bind in &self.binds {
            let listener = bind_listener(*bind)?;
            tracing::info!("DoH server listening on {}", bind);
            listeners.push(listener);
        }

        let mut tasks = tokio::task::JoinSet::new();
        for listener in listeners {
            tasks.spawn(accept_loop(
                listener,
                acceptor.clone(),
                self.state.clone(),
                self.idle_timeout,
            ));
        }

        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(e) => {
                    return Err(crate::server::ServerError::Tls(format!(
                        "listener task failed: {e}"
                    )))
                }
            }
        }

        Ok(())
    }
}

async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    state: DohState,
    idle_timeout: Duration,
) -> Result<(), crate::server::ServerError> {
    let app = router(state.clone());

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let service = TowerToHyperService::new(app.clone().layer(Extension(ConnectInfo(peer))));
        let metrics = state.metrics.clone();
        let observability = state.observability.clone();
        let peer_ip = peer.ip();
        metrics.record_accepted_connection();
        if let Some(obs) = &observability {
            obs.record_client_connection_opened(peer_ip);
        }

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => {
                    metrics.record_tls_handshake_success();
                    s
                }
                Err(e) => {
                    metrics.record_tls_handshake_failure();
                    tracing::debug!(peer = %peer, error = %e, "tls handshake failed");
                    metrics.record_active_connection_closed();
                    if let Some(obs) = observability {
                        obs.record_client_connection_closed(peer_ip);
                    }
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::tokio::TokioTimer::new())
                .header_read_timeout(idle_timeout)
                .keep_alive(true)
                .serve_connection(io, service);
            if let Err(e) = conn.await {
                tracing::debug!(peer = %peer, error = %e, "http connection error");
            }
            metrics.record_active_connection_closed();
            if let Some(obs) = observability {
                obs.record_client_connection_closed(peer_ip);
            }
        });
    }
}

fn router(state: DohState) -> Router {
    Router::new()
        .route("/dns-query", post(dns_query_post).get(dns_query_get))
        .with_state(state)
}

#[derive(serde::Deserialize)]
struct DnsQueryParams {
    dns: String,
}

async fn dns_query_post(
    addr: Option<ConnectInfo<SocketAddr>>,
    State(state): State<DohState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    if content_type != Some("application/dns-message") {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    let query = Message::from_bytes(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let peer = addr
        .map(|ConnectInfo(a)| a)
        .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
    let response = doh_resolve(query, peer, &state).await;
    let bytes = response
        .to_bytes()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/dns-message")],
        bytes,
    ))
}

async fn dns_query_get(
    addr: Option<ConnectInfo<SocketAddr>>,
    State(state): State<DohState>,
    Query(params): Query<DnsQueryParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let body = URL_SAFE_NO_PAD
        .decode(&params.dns)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let query = Message::from_bytes(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let peer = addr
        .map(|ConnectInfo(a)| a)
        .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
    let response = doh_resolve(query, peer, &state).await;
    let bytes = response
        .to_bytes()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/dns-message")],
        bytes,
    ))
}

async fn doh_resolve(query: Message, peer: SocketAddr, state: &DohState) -> Message {
    let ctx = ResolveContext {
        metrics: &state.metrics,
        cache: &state.cache,
        blocklist: &state.blocklist,
        pool: &state.pool,
        pending: &state.pending,
        client_ip: Some(peer.ip()),
        edns: &state.edns,
        blocklist_config: &state.blocklist_config,
        observability: state.observability.as_deref(),
    };
    resolve_with_context(query, &ctx).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocklist::ReloadableBlocklist;
    use crate::cache::Cache;
    use crate::config::{
        CacheConfig, ClientSubnetConfig, EdnsConfig, UpstreamEntry, UpstreamProtocol,
    };
    use crate::metrics::MetricsRecorder;
    use crate::upstream::{pool_from_config, UpstreamPool};
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
    use hickory_proto::rr::{Name, RecordType};
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use tokio::net::UdpSocket;
    use tokio::sync::oneshot;
    use tower::util::ServiceExt;

    fn test_query(name: &str, qtype: RecordType) -> Message {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(true);
        msg.add_query(Query::query(Name::from_str(name).unwrap(), qtype));
        msg
    }

    fn test_state() -> DohState {
        let metrics = Arc::new(MetricsRecorder::new());
        DohState {
            metrics: metrics.clone(),
            cache: Arc::new(Cache::new(CacheConfig::default(), metrics.clone())),
            blocklist: Arc::new(ReloadableBlocklist::new(vec![])),
            pool: UpstreamPool::new(
                vec![],
                None,
                None,
                crate::config::UpstreamSelectionPolicy::Sequential,
            ),
            pending: PendingQueries::new(metrics),
            edns: EdnsConfig::default(),
            blocklist_config: BlocklistConfig::default(),
            observability: None,
        }
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

    async fn start_capture_udp_server() -> (std::net::SocketAddr, oneshot::Receiver<Message>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let mut query = Message::from_bytes(&buf[..len]).unwrap();
            let _ = tx.send(query.clone());
            query.set_message_type(MessageType::Response);
            let bytes = query.to_bytes().unwrap();
            let _ = socket.send_to(&bytes, peer).await;
        });

        (addr, rx)
    }

    #[tokio::test]
    async fn doh_resolve_returns_response() {
        let state = test_state();
        let query = test_query("example.com.", RecordType::A);
        let resp = doh_resolve(query.clone(), "127.0.0.1:12345".parse().unwrap(), &state).await;
        assert_eq!(resp.id(), query.id());
        assert_eq!(
            resp.response_code(),
            hickory_proto::op::ResponseCode::ServFail
        );
    }

    #[tokio::test]
    async fn post_rejects_wrong_content_type() {
        let app = router(test_state());
        let resp = axum::http::Request::builder()
            .method("POST")
            .uri("/dns-query")
            .header("content-type", "text/plain")
            .body(axum::body::Body::empty())
            .unwrap();
        let status = app.oneshot(resp).await.unwrap().status();
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn post_rejects_invalid_dns_body() {
        let app = router(test_state());
        let resp = axum::http::Request::builder()
            .method("POST")
            .uri("/dns-query")
            .header("content-type", "application/dns-message")
            .body(axum::body::Body::from("not-dns"))
            .unwrap();
        let status = app.oneshot(resp).await.unwrap().status();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_rejects_invalid_base64() {
        let app = router(test_state());
        let resp = axum::http::Request::builder()
            .method("GET")
            .uri("/dns-query?dns=!!!")
            .body(axum::body::Body::empty())
            .unwrap();
        let status = app.oneshot(resp).await.unwrap().status();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_rejects_missing_dns_param() {
        let app = router(test_state());
        let resp = axum::http::Request::builder()
            .method("GET")
            .uri("/dns-query")
            .body(axum::body::Body::empty())
            .unwrap();
        let status = app.oneshot(resp).await.unwrap().status();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let app = router(test_state());
        let resp = axum::http::Request::builder()
            .method("GET")
            .uri("/other")
            .body(axum::body::Body::empty())
            .unwrap();
        let status = app.oneshot(resp).await.unwrap().status();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn post_valid_query_returns_dns_message() {
        let state = test_state();
        let query = test_query("example.com.", RecordType::A);
        let body = query.to_bytes().unwrap();

        let app = router(state);
        let resp = axum::http::Request::builder()
            .method("POST")
            .uri("/dns-query")
            .header("content-type", "application/dns-message")
            .body(axum::body::Body::from(body))
            .unwrap();
        let response = app.oneshot(resp).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/dns-message"
        );
    }

    #[tokio::test]
    async fn post_uses_connect_info_for_ecs() {
        let (upstream_addr, received_query) = start_capture_udp_server().await;
        let metrics = Arc::new(MetricsRecorder::new());
        let entry = UpstreamEntry {
            name: "capture".into(),
            address: upstream_addr.to_string(),
            protocol: UpstreamProtocol::Plain,
            tls_cert_path: None,
            timeout: Duration::from_secs(5),
        };
        let state = DohState {
            metrics: metrics.clone(),
            cache: Arc::new(Cache::new(CacheConfig::default(), metrics.clone())),
            blocklist: Arc::new(ReloadableBlocklist::new(vec![])),
            pool: pool_from_config(
                &[entry],
                &[],
                None,
                None,
                crate::config::UpstreamSelectionPolicy::Sequential,
            )
            .unwrap(),
            pending: PendingQueries::new(metrics),
            edns: ecs_config(),
            blocklist_config: BlocklistConfig::default(),
            observability: None,
        };

        let query = test_query("example.com.", RecordType::A);
        let body = query.to_bytes().unwrap();
        let app = router(state);
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri("/dns-query")
            .header("content-type", "application/dns-message")
            .body(axum::body::Body::from(body))
            .unwrap();
        let peer: SocketAddr = (IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 12345).into();
        req.extensions_mut().insert(ConnectInfo(peer));

        let response = app.oneshot(req).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let forwarded = received_query.await.unwrap();
        assert_eq!(ecs_bytes(&forwarded).unwrap(), vec![0, 1, 24, 0, 8, 8, 8]);
    }

    #[tokio::test]
    async fn get_valid_query_returns_dns_message() {
        let state = test_state();
        let query = test_query("example.com.", RecordType::A);
        let body = query.to_bytes().unwrap();
        let encoded = URL_SAFE_NO_PAD.encode(&body);

        let app = router(state);
        let resp = axum::http::Request::builder()
            .method("GET")
            .uri(format!("/dns-query?dns={}", encoded))
            .body(axum::body::Body::empty())
            .unwrap();
        let response = app.oneshot(resp).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/dns-message"
        );
    }
}
