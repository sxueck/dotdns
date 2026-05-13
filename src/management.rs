//! Management API over unix socket or TCP loopback.

use crate::blocklist::ReloadableBlocklist;
use crate::cache::Cache;
use crate::config::{ManagementConfig, ManagementTransport};
use crate::metrics::{MetricsRecorder, MetricsSnapshot};
use crate::observability::{ClientSnapshot, ObservabilityRegistry, UpstreamSnapshot};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ManagementRequest {
    Status,
    CacheFlush,
    BlocklistReload,
    Tracking,
    Sources,
    Sourcestats,
    Activity,
    Clients,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<MetricsSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstreams: Option<Vec<UpstreamSnapshot>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clients: Option<Vec<ClientSnapshot>>,
}

impl ManagementResponse {
    pub fn ok() -> Self {
        Self {
            status: "ok".into(),
            metrics: None,
            message: None,
            upstreams: None,
            clients: None,
        }
    }

    pub fn ok_with_metrics(metrics: MetricsSnapshot) -> Self {
        Self {
            status: "ok".into(),
            metrics: Some(metrics),
            message: None,
            upstreams: None,
            clients: None,
        }
    }

    pub fn ok_with_upstreams(upstreams: Vec<UpstreamSnapshot>) -> Self {
        Self {
            status: "ok".into(),
            metrics: None,
            message: None,
            upstreams: Some(upstreams),
            clients: None,
        }
    }

    pub fn ok_with_clients(clients: Vec<ClientSnapshot>) -> Self {
        Self {
            status: "ok".into(),
            metrics: None,
            message: None,
            upstreams: None,
            clients: Some(clients),
        }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            status: "error".into(),
            metrics: None,
            message: Some(msg.into()),
            upstreams: None,
            clients: None,
        }
    }
}

#[derive(Debug)]
pub struct ManagementServer {
    transport: ManagementTransport,
    metrics: Arc<MetricsRecorder>,
    cache: Arc<Cache>,
    blocklist: Arc<ReloadableBlocklist>,
    observability: Option<Arc<ObservabilityRegistry>>,
}

impl ManagementServer {
    pub fn new(
        config: ManagementConfig,
        metrics: Arc<MetricsRecorder>,
        cache: Arc<Cache>,
        blocklist: Arc<ReloadableBlocklist>,
        observability: Option<Arc<ObservabilityRegistry>>,
    ) -> Self {
        Self {
            transport: config.transport,
            metrics,
            cache,
            blocklist,
            observability,
        }
    }

    pub async fn run(&self) -> Result<(), ManagementError> {
        match &self.transport {
            ManagementTransport::Unix { path } => self.run_unix(path).await,
            ManagementTransport::Tcp { bind } => self.run_tcp(*bind).await,
        }
    }

    async fn run_unix(&self, path: &Path) -> Result<(), ManagementError> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                ManagementError::Connection(format!(
                    "failed to create socket directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        if path.exists() {
            std::fs::remove_file(path).map_err(|e| {
                ManagementError::Connection(format!(
                    "failed to remove stale socket {}: {}",
                    path.display(),
                    e
                ))
            })?;
        }

        let listener = UnixListener::bind(path).map_err(|e| {
            ManagementError::Connection(format!(
                "failed to bind unix socket {}: {}",
                path.display(),
                e
            ))
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            if let Err(e) = std::fs::set_permissions(path, perms) {
                tracing::warn!(error = %e, "failed to set management socket permissions");
            }
        }

        tracing::info!("management listening on unix:{}", path.display());

        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|e| ManagementError::Connection(format!("unix accept error: {e}")))?;
            let metrics = self.metrics.clone();
            let cache = self.cache.clone();
            let blocklist = self.blocklist.clone();
            let observability = self.observability.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_connection(stream, metrics, cache, blocklist, observability).await
                {
                    tracing::debug!(error = %e, "management connection closed");
                }
            });
        }
    }

    async fn run_tcp(&self, bind: std::net::SocketAddr) -> Result<(), ManagementError> {
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|e| ManagementError::Connection(format!("failed to bind tcp {bind}: {e}")))?;

        tracing::info!("management listening on tcp:{bind}");

        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|e| ManagementError::Connection(format!("tcp accept error: {e}")))?;
            let metrics = self.metrics.clone();
            let cache = self.cache.clone();
            let blocklist = self.blocklist.clone();
            let observability = self.observability.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_connection(stream, metrics, cache, blocklist, observability).await
                {
                    tracing::debug!(error = %e, "management connection closed");
                }
            });
        }
    }
}

async fn handle_connection<S>(
    stream: S,
    metrics: Arc<MetricsRecorder>,
    cache: Arc<Cache>,
    blocklist: Arc<ReloadableBlocklist>,
    observability: Option<Arc<ObservabilityRegistry>>,
) -> Result<(), ManagementError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let req: ManagementRequest = match serde_json::from_str(trimmed) {
                    Ok(r) => r,
                    Err(e) => {
                        let resp = ManagementResponse::error(format!("invalid request: {e}"));
                        send_response(&mut writer, &resp).await?;
                        continue;
                    }
                };
                let resp =
                    dispatch(req, &metrics, &cache, &blocklist, observability.as_ref()).await;
                send_response(&mut writer, &resp).await?;
            }
            Err(e) => return Err(ManagementError::Connection(e.to_string())),
        }
    }
    Ok(())
}

async fn send_response<W>(writer: &mut W, resp: &ManagementResponse) -> Result<(), ManagementError>
where
    W: AsyncWriteExt + Unpin,
{
    let json = serde_json::to_string(resp).map_err(|e| ManagementError::Request(e.to_string()))?;
    writer
        .write_all(json.as_bytes())
        .await
        .map_err(|e| ManagementError::Connection(e.to_string()))?;
    writer
        .write_all(b"\n")
        .await
        .map_err(|e| ManagementError::Connection(e.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|e| ManagementError::Connection(e.to_string()))?;
    Ok(())
}

async fn dispatch(
    req: ManagementRequest,
    metrics: &MetricsRecorder,
    cache: &Cache,
    blocklist: &ReloadableBlocklist,
    observability: Option<&Arc<ObservabilityRegistry>>,
) -> ManagementResponse {
    match req {
        ManagementRequest::Status => ManagementResponse::ok_with_metrics(metrics.snapshot()),
        ManagementRequest::CacheFlush => {
            cache.flush();
            ManagementResponse::ok()
        }
        ManagementRequest::BlocklistReload => match blocklist.refresh_and_reload().await {
            Ok(_) => ManagementResponse::ok(),
            Err(e) => ManagementResponse::error(format!("reload failed: {e}")),
        },
        ManagementRequest::Tracking => ManagementResponse::ok_with_metrics(metrics.snapshot()),
        ManagementRequest::Sources | ManagementRequest::Sourcestats => match observability {
            Some(reg) => ManagementResponse::ok_with_upstreams(reg.upstream_snapshot()),
            None => ManagementResponse::error("observability not available"),
        },
        ManagementRequest::Activity => ManagementResponse::ok_with_metrics(metrics.snapshot()),
        ManagementRequest::Clients => match observability {
            Some(reg) => ManagementResponse::ok_with_clients(reg.client_snapshot()),
            None => ManagementResponse::error("observability not available"),
        },
    }
}

#[derive(Debug, Clone)]
pub struct ManagementClient {
    transport: ManagementTransport,
}

impl ManagementClient {
    pub fn new(transport: ManagementTransport) -> Self {
        Self { transport }
    }

    pub async fn status(&self) -> Result<MetricsSnapshot, ManagementError> {
        let resp = self.send_request(ManagementRequest::Status).await?;
        if resp.status != "ok" {
            return Err(ManagementError::Request(resp.message.unwrap_or_default()));
        }
        resp.metrics
            .ok_or_else(|| ManagementError::Request("missing metrics in status response".into()))
    }

    pub async fn cache_flush(&self) -> Result<(), ManagementError> {
        let resp = self.send_request(ManagementRequest::CacheFlush).await?;
        if resp.status != "ok" {
            return Err(ManagementError::Request(resp.message.unwrap_or_default()));
        }
        Ok(())
    }

    pub async fn blocklist_reload(&self) -> Result<(), ManagementError> {
        let resp = self
            .send_request(ManagementRequest::BlocklistReload)
            .await?;
        if resp.status != "ok" {
            return Err(ManagementError::Request(resp.message.unwrap_or_default()));
        }
        Ok(())
    }

    pub async fn tracking(&self) -> Result<MetricsSnapshot, ManagementError> {
        let resp = self.send_request(ManagementRequest::Tracking).await?;
        if resp.status != "ok" {
            return Err(ManagementError::Request(resp.message.unwrap_or_default()));
        }
        resp.metrics
            .ok_or_else(|| ManagementError::Request("missing metrics in tracking response".into()))
    }

    pub async fn sources(&self) -> Result<Vec<UpstreamSnapshot>, ManagementError> {
        let resp = self.send_request(ManagementRequest::Sources).await?;
        if resp.status != "ok" {
            return Err(ManagementError::Request(resp.message.unwrap_or_default()));
        }
        resp.upstreams
            .ok_or_else(|| ManagementError::Request("missing upstreams in sources response".into()))
    }

    pub async fn sourcestats(&self) -> Result<Vec<UpstreamSnapshot>, ManagementError> {
        let resp = self.send_request(ManagementRequest::Sourcestats).await?;
        if resp.status != "ok" {
            return Err(ManagementError::Request(resp.message.unwrap_or_default()));
        }
        resp.upstreams.ok_or_else(|| {
            ManagementError::Request("missing upstreams in sourcestats response".into())
        })
    }

    pub async fn activity(&self) -> Result<MetricsSnapshot, ManagementError> {
        let resp = self.send_request(ManagementRequest::Activity).await?;
        if resp.status != "ok" {
            return Err(ManagementError::Request(resp.message.unwrap_or_default()));
        }
        resp.metrics
            .ok_or_else(|| ManagementError::Request("missing metrics in activity response".into()))
    }

    pub async fn clients(&self) -> Result<Vec<ClientSnapshot>, ManagementError> {
        let resp = self.send_request(ManagementRequest::Clients).await?;
        if resp.status != "ok" {
            return Err(ManagementError::Request(resp.message.unwrap_or_default()));
        }
        resp.clients
            .ok_or_else(|| ManagementError::Request("missing clients in clients response".into()))
    }

    async fn send_request(
        &self,
        req: ManagementRequest,
    ) -> Result<ManagementResponse, ManagementError> {
        let json =
            serde_json::to_string(&req).map_err(|e| ManagementError::Request(e.to_string()))?;

        match &self.transport {
            ManagementTransport::Unix { path } => {
                let stream = UnixStream::connect(path).await.map_err(|e| {
                    ManagementError::Connection(format!(
                        "failed to connect to {}: {}",
                        path.display(),
                        e
                    ))
                })?;
                self.exchange(stream, json).await
            }
            ManagementTransport::Tcp { bind } => {
                let stream = TcpStream::connect(bind).await.map_err(|e| {
                    ManagementError::Connection(format!("failed to connect to {bind}: {e}"))
                })?;
                self.exchange(stream, json).await
            }
        }
    }

    async fn exchange<S>(
        &self,
        stream: S,
        request_json: String,
    ) -> Result<ManagementResponse, ManagementError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut stream = stream;
        stream
            .write_all(request_json.as_bytes())
            .await
            .map_err(|e| ManagementError::Connection(e.to_string()))?;
        stream
            .write_all(b"\n")
            .await
            .map_err(|e| ManagementError::Connection(e.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|e| ManagementError::Connection(e.to_string()))?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        match reader.read_line(&mut line).await {
            Ok(0) => Err(ManagementError::Connection(
                "server closed connection".into(),
            )),
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    return Err(ManagementError::Connection("empty response".into()));
                }
                serde_json::from_str(trimmed)
                    .map_err(|e| ManagementError::Request(format!("invalid response: {e}")))
            }
            Err(e) => Err(ManagementError::Connection(e.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ManagementError {
    #[error("connection failed: {0}")]
    Connection(String),
    #[error("request failed: {0}")]
    Request(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocklist::{BlockDecision, BlocklistEngine, ReloadableBlocklist};
    use crate::cache::Cache;
    use crate::config::CacheConfig;
    use crate::metrics::MetricsRecorder;
    use crate::observability::ObservabilityRegistry;
    use std::io::Write;
    use std::sync::Arc;
    use std::time::Duration;

    fn temp_socket_path() -> std::path::PathBuf {
        tempfile::NamedTempFile::new().unwrap().path().to_path_buf()
    }

    async fn wait_for_unix_socket(path: &std::path::Path) -> UnixStream {
        for _ in 0..50 {
            match UnixStream::connect(path).await {
                Ok(stream) => return stream,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
        UnixStream::connect(path)
            .await
            .expect("management socket should be ready")
    }

    #[tokio::test]
    async fn client_returns_connection_error_when_no_server() {
        let path = temp_socket_path();
        let transport = ManagementTransport::Unix { path };
        let client = ManagementClient::new(transport);
        let err = client.status().await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("connection failed") || msg.contains("connect"),
            "expected connection error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn status_roundtrip_over_unix_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mgmt.sock");
        let transport = ManagementTransport::Unix { path: path.clone() };

        let metrics = Arc::new(MetricsRecorder::new());
        metrics.record_query();
        metrics.record_cache_hit();
        let cache = Arc::new(Cache::new(CacheConfig::default(), metrics.clone()));
        let blocklist = Arc::new(ReloadableBlocklist::new(vec![]));

        let server = ManagementServer::new(
            ManagementConfig {
                transport: transport.clone(),
            },
            metrics.clone(),
            cache.clone(),
            blocklist.clone(),
            None,
        );

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        drop(wait_for_unix_socket(&path).await);

        let client = ManagementClient::new(transport);
        let snap = client.status().await.expect("status should succeed");
        assert_eq!(snap.total_queries, 1);
        assert_eq!(snap.cache_hits, 1);
    }

    #[tokio::test]
    async fn unix_socket_parent_directory_is_created() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run/dotdns/mgmt.sock");
        let transport = ManagementTransport::Unix { path: path.clone() };

        let metrics = Arc::new(MetricsRecorder::new());
        let cache = Arc::new(Cache::new(CacheConfig::default(), metrics.clone()));
        let blocklist = Arc::new(ReloadableBlocklist::new(vec![]));
        let server = ManagementServer::new(
            ManagementConfig {
                transport: transport.clone(),
            },
            metrics.clone(),
            cache.clone(),
            blocklist.clone(),
            None,
        );

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        drop(wait_for_unix_socket(&path).await);
        assert!(path.exists());

        let client = ManagementClient::new(transport);
        client.status().await.expect("status should succeed");
    }

    #[tokio::test]
    async fn cache_flush_over_unix_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mgmt.sock");
        let transport = ManagementTransport::Unix { path: path.clone() };

        let metrics = Arc::new(MetricsRecorder::new());
        let cache = Arc::new(Cache::new(CacheConfig::default(), metrics.clone()));
        let blocklist = Arc::new(ReloadableBlocklist::new(vec![]));

        let server = ManagementServer::new(
            ManagementConfig {
                transport: transport.clone(),
            },
            metrics.clone(),
            cache.clone(),
            blocklist.clone(),
            None,
        );

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        drop(wait_for_unix_socket(&path).await);

        let client = ManagementClient::new(transport);
        client.cache_flush().await.expect("flush should succeed");
        assert_eq!(cache.len(), 0);
    }

    #[tokio::test]
    async fn blocklist_reload_preserves_old_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mgmt.sock");
        let transport = ManagementTransport::Unix { path: path.clone() };

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"blocked.com\n").unwrap();
        file.flush().unwrap();
        let good_path = file.path().to_path_buf();

        let engine = BlocklistEngine::from_paths(std::slice::from_ref(&good_path))
            .unwrap()
            .0;
        let blocklist = Arc::new(ReloadableBlocklist::from_engine(engine, vec![good_path]));
        drop(file);

        let metrics = Arc::new(MetricsRecorder::new());
        let cache = Arc::new(Cache::new(CacheConfig::default(), metrics.clone()));

        let server = ManagementServer::new(
            ManagementConfig {
                transport: transport.clone(),
            },
            metrics.clone(),
            cache.clone(),
            blocklist.clone(),
            None,
        );

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        drop(wait_for_unix_socket(&path).await);

        let client = ManagementClient::new(transport);

        assert_eq!(blocklist.decide("blocked.com"), BlockDecision::Block);

        let err = client
            .blocklist_reload()
            .await
            .expect_err("reload should fail");
        assert!(err.to_string().contains("reload failed"));
        assert_eq!(blocklist.decide("blocked.com"), BlockDecision::Block);
    }

    #[tokio::test]
    async fn invalid_request_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mgmt.sock");

        let metrics = Arc::new(MetricsRecorder::new());
        let cache = Arc::new(Cache::new(CacheConfig::default(), metrics.clone()));
        let blocklist = Arc::new(ReloadableBlocklist::new(vec![]));

        let server = ManagementServer::new(
            ManagementConfig {
                transport: ManagementTransport::Unix { path: path.clone() },
            },
            metrics.clone(),
            cache.clone(),
            blocklist.clone(),
            None,
        );

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        let mut stream = wait_for_unix_socket(&path).await;
        stream.write_all(b"not_json\n").await.unwrap();
        stream.flush().await.unwrap();

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let resp: ManagementResponse = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(resp.status, "error");
        assert!(resp.message.unwrap().contains("invalid request"));
    }

    #[tokio::test]
    async fn tracking_roundtrip_over_unix_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mgmt.sock");
        let transport = ManagementTransport::Unix { path: path.clone() };

        let metrics = Arc::new(MetricsRecorder::new());
        metrics.record_query();
        let cache = Arc::new(Cache::new(CacheConfig::default(), metrics.clone()));
        let blocklist = Arc::new(ReloadableBlocklist::new(vec![]));

        let server = ManagementServer::new(
            ManagementConfig {
                transport: transport.clone(),
            },
            metrics.clone(),
            cache.clone(),
            blocklist.clone(),
            None,
        );

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        drop(wait_for_unix_socket(&path).await);

        let client = ManagementClient::new(transport);
        let snap = client.tracking().await.expect("tracking should succeed");
        assert_eq!(snap.total_queries, 1);
    }

    #[tokio::test]
    async fn sources_and_sourcestats_roundtrip_over_unix_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mgmt.sock");
        let transport = ManagementTransport::Unix { path: path.clone() };

        let metrics = Arc::new(MetricsRecorder::new());
        let cache = Arc::new(Cache::new(CacheConfig::default(), metrics.clone()));
        let blocklist = Arc::new(ReloadableBlocklist::new(vec![]));
        let observability = Arc::new(ObservabilityRegistry::with_upstreams(&[
            "u1".into(),
            "u2".into(),
        ]));
        observability.record_upstream_success("u1", 42);

        let server = ManagementServer::new(
            ManagementConfig {
                transport: transport.clone(),
            },
            metrics.clone(),
            cache.clone(),
            blocklist.clone(),
            Some(observability),
        );

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        drop(wait_for_unix_socket(&path).await);

        let client = ManagementClient::new(transport.clone());
        let sources = client.sources().await.expect("sources should succeed");
        assert_eq!(sources.len(), 2);
        let u1 = sources.iter().find(|u| u.name == "u1").unwrap();
        assert_eq!(u1.success_count, 1);
        assert_eq!(u1.last_success_latency_ms, Some(42));

        let sourcestats = client
            .sourcestats()
            .await
            .expect("sourcestats should succeed");
        assert_eq!(sourcestats.len(), 2);
    }

    #[tokio::test]
    async fn activity_roundtrip_over_unix_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mgmt.sock");
        let transport = ManagementTransport::Unix { path: path.clone() };

        let metrics = Arc::new(MetricsRecorder::new());
        metrics.record_accepted_connection();
        let cache = Arc::new(Cache::new(CacheConfig::default(), metrics.clone()));
        let blocklist = Arc::new(ReloadableBlocklist::new(vec![]));

        let server = ManagementServer::new(
            ManagementConfig {
                transport: transport.clone(),
            },
            metrics.clone(),
            cache.clone(),
            blocklist.clone(),
            None,
        );

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        drop(wait_for_unix_socket(&path).await);

        let client = ManagementClient::new(transport);
        let snap = client.activity().await.expect("activity should succeed");
        assert_eq!(snap.accepted_connections, 1);
    }

    #[tokio::test]
    async fn clients_roundtrip_over_unix_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mgmt.sock");
        let transport = ManagementTransport::Unix { path: path.clone() };

        let metrics = Arc::new(MetricsRecorder::new());
        let cache = Arc::new(Cache::new(CacheConfig::default(), metrics.clone()));
        let blocklist = Arc::new(ReloadableBlocklist::new(vec![]));
        let observability = Arc::new(ObservabilityRegistry::with_capacity(100));
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        observability.record_client_query(ip);
        observability.record_client_cache_hit(ip);

        let server = ManagementServer::new(
            ManagementConfig {
                transport: transport.clone(),
            },
            metrics.clone(),
            cache.clone(),
            blocklist.clone(),
            Some(observability),
        );

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        drop(wait_for_unix_socket(&path).await);

        let client = ManagementClient::new(transport);
        let clients = client.clients().await.expect("clients should succeed");
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].ip, ip);
        assert_eq!(clients[0].total_queries, 1);
        assert_eq!(clients[0].cache_hits, 1);
    }

    #[tokio::test]
    async fn observability_commands_error_when_registry_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mgmt.sock");
        let transport = ManagementTransport::Unix { path: path.clone() };

        let metrics = Arc::new(MetricsRecorder::new());
        let cache = Arc::new(Cache::new(CacheConfig::default(), metrics.clone()));
        let blocklist = Arc::new(ReloadableBlocklist::new(vec![]));

        let server = ManagementServer::new(
            ManagementConfig {
                transport: transport.clone(),
            },
            metrics.clone(),
            cache.clone(),
            blocklist.clone(),
            None,
        );

        tokio::spawn(async move {
            let _ = server.run().await;
        });

        drop(wait_for_unix_socket(&path).await);

        let client = ManagementClient::new(transport);
        let err = client.sources().await.unwrap_err();
        assert!(err.to_string().contains("observability not available"));
    }
}
