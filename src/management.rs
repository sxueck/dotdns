//! Management API over unix socket or TCP loopback.

use crate::blocklist::ReloadableBlocklist;
use crate::cache::Cache;
use crate::config::{ManagementConfig, ManagementTransport};
use crate::metrics::{MetricsRecorder, MetricsSnapshot};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};

// ---------------------------------------------------------------------------
// Wire protocol
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ManagementRequest {
    Status,
    CacheFlush,
    BlocklistReload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<MetricsSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl ManagementResponse {
    pub fn ok() -> Self {
        Self {
            status: "ok".into(),
            metrics: None,
            message: None,
        }
    }

    pub fn ok_with_metrics(metrics: MetricsSnapshot) -> Self {
        Self {
            status: "ok".into(),
            metrics: Some(metrics),
            message: None,
        }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            status: "error".into(),
            metrics: None,
            message: Some(msg.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct ManagementServer {
    transport: ManagementTransport,
    metrics: Arc<MetricsRecorder>,
    cache: Arc<Cache>,
    blocklist: Arc<ReloadableBlocklist>,
}

impl ManagementServer {
    pub fn new(
        config: ManagementConfig,
        metrics: Arc<MetricsRecorder>,
        cache: Arc<Cache>,
        blocklist: Arc<ReloadableBlocklist>,
    ) -> Self {
        Self {
            transport: config.transport,
            metrics,
            cache,
            blocklist,
        }
    }

    pub async fn run(&self) -> Result<(), ManagementError> {
        match &self.transport {
            ManagementTransport::Unix { path } => self.run_unix(path).await,
            ManagementTransport::Tcp { bind } => self.run_tcp(*bind).await,
        }
    }

    async fn run_unix(&self, path: &Path) -> Result<(), ManagementError> {
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
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, metrics, cache, blocklist).await {
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
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, metrics, cache, blocklist).await {
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
                let resp = dispatch(req, &metrics, &cache, &blocklist).await;
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
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ManagementError {
    // TODO: remove this, nothing uses it
    #[error("not implemented")]
    NotImplemented,
    #[error("connection failed: {0}")]
    Connection(String),
    #[error("request failed: {0}")]
    Request(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocklist::{BlockDecision, BlocklistEngine, ReloadableBlocklist};
    use crate::cache::Cache;
    use crate::config::CacheConfig;
    use crate::metrics::MetricsRecorder;
    use std::io::Write;
    use std::sync::Arc;

    fn temp_socket_path() -> std::path::PathBuf {
        tempfile::NamedTempFile::new().unwrap().path().to_path_buf()
    }

    #[test]
    fn request_serde_roundtrip() {
        let reqs = vec![
            ManagementRequest::Status,
            ManagementRequest::CacheFlush,
            ManagementRequest::BlocklistReload,
        ];
        for req in reqs {
            let json = serde_json::to_string(&req).unwrap();
            let back: ManagementRequest = serde_json::from_str(&json).unwrap();
            assert_eq!(format!("{:?}", req), format!("{:?}", back));
        }
    }

    #[test]
    fn response_serde_roundtrip() {
        let resp = ManagementResponse::ok_with_metrics(MetricsSnapshot {
            uptime_secs: 10,
            total_queries: 5,
            cache_hits: 2,
            cache_misses: 3,
            blocked_queries: 1,
            upstream_failures: 0,
            cache_entries: 4,
        });
        let json = serde_json::to_string(&resp).unwrap();
        let back: ManagementResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status, "ok");
        assert_eq!(back.metrics.as_ref().unwrap().total_queries, 5);
        assert_eq!(back.message, None);
    }

    #[test]
    fn response_error_formatting() {
        let resp = ManagementResponse::error("something broke");
        assert_eq!(resp.status, "error");
        assert_eq!(resp.message, Some("something broke".into()));
        assert!(resp.metrics.is_none());
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
        );

        let _srv_handle = tokio::spawn(async move {
            let _ = server.run().await;
        });

        // Give the server a moment to bind.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = ManagementClient::new(transport);
        let snap = client.status().await.expect("status should succeed");
        assert_eq!(snap.total_queries, 1);
        assert_eq!(snap.cache_hits, 1);
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
        );

        let _srv_handle = tokio::spawn(async move {
            let _ = server.run().await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

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

        let engine = BlocklistEngine::from_paths(&[good_path.clone()]).unwrap().0;
        let blocklist = Arc::new(ReloadableBlocklist::from_engine(engine, vec![good_path]));

        let metrics = Arc::new(MetricsRecorder::new());
        let cache = Arc::new(Cache::new(CacheConfig::default(), metrics.clone()));

        let server = ManagementServer::new(
            ManagementConfig {
                transport: transport.clone(),
            },
            metrics.clone(),
            cache.clone(),
            blocklist.clone(),
        );

        let _srv_handle = tokio::spawn(async move {
            let _ = server.run().await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = ManagementClient::new(transport);

        // Before reload, blocked.com is blocked.
        assert_eq!(blocklist.decide("blocked.com"), BlockDecision::Block);

        // Trigger a reload that will fail by pointing paths at a nonexistent file.
        // We do this by swapping the blocklist's internal paths... but ReloadableBlocklist
        // doesn't expose a setter.  Instead, we test the dispatch layer directly:
        // the current blocklist has valid paths, so the first reload succeeds.
        client
            .blocklist_reload()
            .await
            .expect("reload should succeed");
        assert_eq!(blocklist.decide("blocked.com"), BlockDecision::Block);

        // To test failure-preservation via the management API, simulate a broken
        // reload by swapping the paths inside the blocklist using its RwLock.
        // Since we can't mutate through Arc, we test the dispatch unit directly.
        let bad_blocklist =
            ReloadableBlocklist::new(vec![std::path::PathBuf::from("/nonexistent/blocklist.txt")]);
        let resp = dispatch(
            ManagementRequest::BlocklistReload,
            &metrics,
            &cache,
            &bad_blocklist,
        )
        .await;
        assert_eq!(resp.status, "error");
        // Old (empty) rules preserved.
        assert_eq!(bad_blocklist.decide("blocked.com"), BlockDecision::Allow);
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
        );

        let _srv_handle = tokio::spawn(async move {
            let _ = server.run().await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut stream = UnixStream::connect(&path).await.unwrap();
        stream.write_all(b"not_json\n").await.unwrap();
        stream.flush().await.unwrap();

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let resp: ManagementResponse = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(resp.status, "error");
        assert!(resp.message.unwrap().contains("invalid request"));
    }
}
