use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[derive(Debug)]
pub struct MetricsRecorder {
    start_time: Instant,
    total_queries: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    blocked_queries: AtomicU64,
    upstream_failures: AtomicU64,
    upstream_successes: AtomicU64,
    upstream_timeouts: AtomicU64,
    cache_entries: AtomicU64,
    cache_evictions: AtomicU64,
    accepted_connections: AtomicU64,
    active_connections: AtomicU64,
    tls_handshake_success: AtomicU64,
    tls_handshake_failures: AtomicU64,
    dns_read_failures: AtomicU64,
    dns_write_failures: AtomicU64,
    pending_leaders: AtomicU64,
    pending_followers: AtomicU64,
    pending_follower_timeouts: AtomicU64,
    pending_follower_successes: AtomicU64,
}

impl Default for MetricsRecorder {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRecorder {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            total_queries: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            blocked_queries: AtomicU64::new(0),
            upstream_failures: AtomicU64::new(0),
            upstream_successes: AtomicU64::new(0),
            upstream_timeouts: AtomicU64::new(0),
            cache_entries: AtomicU64::new(0),
            cache_evictions: AtomicU64::new(0),
            accepted_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            tls_handshake_success: AtomicU64::new(0),
            tls_handshake_failures: AtomicU64::new(0),
            dns_read_failures: AtomicU64::new(0),
            dns_write_failures: AtomicU64::new(0),
            pending_leaders: AtomicU64::new(0),
            pending_followers: AtomicU64::new(0),
            pending_follower_timeouts: AtomicU64::new(0),
            pending_follower_successes: AtomicU64::new(0),
        }
    }

    pub fn from_persisted(persisted: &PersistedMetrics) -> Self {
        Self {
            start_time: Instant::now(),
            total_queries: AtomicU64::new(persisted.total_queries),
            cache_hits: AtomicU64::new(persisted.cache_hits),
            cache_misses: AtomicU64::new(persisted.cache_misses),
            blocked_queries: AtomicU64::new(persisted.blocked_queries),
            upstream_failures: AtomicU64::new(persisted.upstream_failures),
            upstream_successes: AtomicU64::new(persisted.upstream_successes),
            upstream_timeouts: AtomicU64::new(persisted.upstream_timeouts),
            cache_entries: AtomicU64::new(0),
            cache_evictions: AtomicU64::new(persisted.cache_evictions),
            accepted_connections: AtomicU64::new(persisted.accepted_connections),
            active_connections: AtomicU64::new(0),
            tls_handshake_success: AtomicU64::new(persisted.tls_handshake_success),
            tls_handshake_failures: AtomicU64::new(persisted.tls_handshake_failures),
            dns_read_failures: AtomicU64::new(persisted.dns_read_failures),
            dns_write_failures: AtomicU64::new(persisted.dns_write_failures),
            pending_leaders: AtomicU64::new(0),
            pending_followers: AtomicU64::new(0),
            pending_follower_timeouts: AtomicU64::new(persisted.pending_follower_timeouts),
            pending_follower_successes: AtomicU64::new(persisted.pending_follower_successes),
        }
    }

    pub fn record_query(&self) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_blocked(&self) {
        self.blocked_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_upstream_failure(&self) {
        self.upstream_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_upstream_success(&self) {
        self.upstream_successes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_upstream_timeout(&self) {
        self.upstream_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_cache_entries(&self, n: u64) {
        self.cache_entries.store(n, Ordering::Relaxed);
    }

    pub fn record_cache_eviction(&self) {
        self.cache_evictions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_accepted_connection(&self) {
        self.accepted_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_active_connection_closed(&self) {
        let current = self.active_connections.load(Ordering::Relaxed);
        if current > 0 {
            self.active_connections.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn record_tls_handshake_success(&self) {
        self.tls_handshake_success.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tls_handshake_failure(&self) {
        self.tls_handshake_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dns_read_failure(&self) {
        self.dns_read_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dns_write_failure(&self) {
        self.dns_write_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_pending_leader_started(&self) {
        self.pending_leaders.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_pending_leader_completed(&self) {
        self.pending_leaders.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_pending_follower_joined(&self) {
        self.pending_followers.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_pending_follower_resolved(&self) {
        self.pending_followers.fetch_sub(1, Ordering::Relaxed);
        self.pending_follower_successes
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_pending_follower_timeout(&self) {
        self.pending_followers.fetch_sub(1, Ordering::Relaxed);
        self.pending_follower_timeouts
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            uptime_secs: self.start_time.elapsed().as_secs(),
            total_queries: self.total_queries.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            blocked_queries: self.blocked_queries.load(Ordering::Relaxed),
            upstream_failures: self.upstream_failures.load(Ordering::Relaxed),
            upstream_successes: self.upstream_successes.load(Ordering::Relaxed),
            upstream_timeouts: self.upstream_timeouts.load(Ordering::Relaxed),
            cache_entries: self.cache_entries.load(Ordering::Relaxed),
            cache_evictions: self.cache_evictions.load(Ordering::Relaxed),
            accepted_connections: self.accepted_connections.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            tls_handshake_success: self.tls_handshake_success.load(Ordering::Relaxed),
            tls_handshake_failures: self.tls_handshake_failures.load(Ordering::Relaxed),
            dns_read_failures: self.dns_read_failures.load(Ordering::Relaxed),
            dns_write_failures: self.dns_write_failures.load(Ordering::Relaxed),
            pending_leaders: self.pending_leaders.load(Ordering::Relaxed),
            pending_followers: self.pending_followers.load(Ordering::Relaxed),
            pending_follower_timeouts: self.pending_follower_timeouts.load(Ordering::Relaxed),
            pending_follower_successes: self.pending_follower_successes.load(Ordering::Relaxed),
        }
    }

    pub fn to_persisted(&self) -> PersistedMetrics {
        PersistedMetrics {
            total_queries: self.total_queries.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            blocked_queries: self.blocked_queries.load(Ordering::Relaxed),
            upstream_failures: self.upstream_failures.load(Ordering::Relaxed),
            upstream_successes: self.upstream_successes.load(Ordering::Relaxed),
            upstream_timeouts: self.upstream_timeouts.load(Ordering::Relaxed),
            cache_evictions: self.cache_evictions.load(Ordering::Relaxed),
            accepted_connections: self.accepted_connections.load(Ordering::Relaxed),
            tls_handshake_success: self.tls_handshake_success.load(Ordering::Relaxed),
            tls_handshake_failures: self.tls_handshake_failures.load(Ordering::Relaxed),
            dns_read_failures: self.dns_read_failures.load(Ordering::Relaxed),
            dns_write_failures: self.dns_write_failures.load(Ordering::Relaxed),
            pending_follower_timeouts: self.pending_follower_timeouts.load(Ordering::Relaxed),
            pending_follower_successes: self.pending_follower_successes.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct MetricsSnapshot {
    pub uptime_secs: u64,
    pub total_queries: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub blocked_queries: u64,
    pub upstream_failures: u64,
    pub upstream_successes: u64,
    pub upstream_timeouts: u64,
    pub cache_entries: u64,
    pub cache_evictions: u64,
    pub accepted_connections: u64,
    pub active_connections: u64,
    pub tls_handshake_success: u64,
    pub tls_handshake_failures: u64,
    pub dns_read_failures: u64,
    pub dns_write_failures: u64,
    pub pending_leaders: u64,
    pub pending_followers: u64,
    pub pending_follower_timeouts: u64,
    pub pending_follower_successes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct PersistedMetrics {
    pub total_queries: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub blocked_queries: u64,
    pub upstream_failures: u64,
    pub upstream_successes: u64,
    pub upstream_timeouts: u64,
    pub cache_evictions: u64,
    pub accepted_connections: u64,
    pub tls_handshake_success: u64,
    pub tls_handshake_failures: u64,
    pub dns_read_failures: u64,
    pub dns_write_failures: u64,
    pub pending_follower_timeouts: u64,
    pub pending_follower_successes: u64,
}

impl MetricsSnapshot {
    pub fn to_human_string(&self) -> String {
        format!(
            "uptime: {}\n\
             total queries: {}\n\
             cache hits: {}\n\
             cache misses: {}\n\
             blocked: {}\n\
             upstream failures: {}\n\
             upstream successes: {}\n\
             upstream timeouts: {}\n\
             cache entries: {}\n\
             cache evictions: {}\n\
             accepted connections: {}\n\
             active connections: {}\n\
             tls handshake success: {}\n\
             tls handshake failures: {}\n\
             dns read failures: {}\n\
             dns write failures: {}\n\
             pending leaders: {}\n\
             pending followers: {}\n\
             pending follower timeouts: {}\n\
             pending follower successes: {}",
            format_uptime(self.uptime_secs),
            self.total_queries,
            self.cache_hits,
            self.cache_misses,
            self.blocked_queries,
            self.upstream_failures,
            self.upstream_successes,
            self.upstream_timeouts,
            self.cache_entries,
            self.cache_evictions,
            self.accepted_connections,
            self.active_connections,
            self.tls_handshake_success,
            self.tls_handshake_failures,
            self.dns_read_failures,
            self.dns_write_failures,
            self.pending_leaders,
            self.pending_followers,
            self.pending_follower_timeouts,
            self.pending_follower_successes,
        )
    }
}

pub fn format_uptime(secs: u64) -> String {
    if secs < 60 {
        return format!("{}s", secs);
    }
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;

    let mut parts = Vec::with_capacity(4);
    if days > 0 {
        parts.push(format!("{}d", days));
    }
    if hours > 0 {
        parts.push(format!("{}h", hours));
    }
    if minutes > 0 {
        parts.push(format!("{}m", minutes));
    }
    if seconds > 0 {
        parts.push(format!("{}s", seconds));
    }
    parts.join(" ")
}

pub fn load_stats(path: &Path) -> Option<PersistedMetrics> {
    match std::fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(persisted) => Some(persisted),
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "stats file corrupted, removing and starting fresh"
                );
                let _ = std::fs::remove_file(path);
                None
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "failed to read stats file"
            );
            None
        }
    }
}

pub fn save_stats(path: &Path, persisted: &PersistedMetrics) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temp_path = path.with_extension("tmp");
    let json = serde_json::to_vec(persisted)?;
    std::fs::write(&temp_path, json)?;
    std::fs::rename(&temp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_counters_increase() {
        let m = MetricsRecorder::new();
        m.record_query();
        m.record_query();
        m.record_cache_hit();
        m.record_cache_miss();
        m.record_blocked();
        m.record_upstream_failure();
        m.record_upstream_success();
        m.record_upstream_timeout();
        m.set_cache_entries(42);
        m.record_cache_eviction();
        m.record_accepted_connection();
        m.record_tls_handshake_success();
        m.record_tls_handshake_failure();
        m.record_dns_read_failure();
        m.record_dns_write_failure();
        m.record_pending_leader_started();
        m.record_pending_follower_joined();
        m.record_pending_follower_resolved();

        let snap = m.snapshot();
        assert_eq!(snap.total_queries, 2);
        assert_eq!(snap.cache_hits, 1);
        assert_eq!(snap.cache_misses, 1);
        assert_eq!(snap.blocked_queries, 1);
        assert_eq!(snap.upstream_failures, 1);
        assert_eq!(snap.upstream_successes, 1);
        assert_eq!(snap.upstream_timeouts, 1);
        assert_eq!(snap.cache_entries, 42);
        assert_eq!(snap.cache_evictions, 1);
        assert_eq!(snap.accepted_connections, 1);
        assert_eq!(snap.active_connections, 1);
        assert_eq!(snap.tls_handshake_success, 1);
        assert_eq!(snap.tls_handshake_failures, 1);
        assert_eq!(snap.dns_read_failures, 1);
        assert_eq!(snap.dns_write_failures, 1);
        assert_eq!(snap.pending_leaders, 1);
        assert_eq!(snap.pending_followers, 0);
        assert_eq!(snap.pending_follower_timeouts, 0);
        assert_eq!(snap.pending_follower_successes, 1);
    }

    #[test]
    fn active_connection_gauge() {
        let m = MetricsRecorder::new();
        m.record_accepted_connection();
        m.record_accepted_connection();
        assert_eq!(m.snapshot().active_connections, 2);
        m.record_active_connection_closed();
        assert_eq!(m.snapshot().active_connections, 1);
    }

    #[test]
    fn pending_leader_gauge() {
        let m = MetricsRecorder::new();
        m.record_pending_leader_started();
        m.record_pending_leader_started();
        assert_eq!(m.snapshot().pending_leaders, 2);
        m.record_pending_leader_completed();
        assert_eq!(m.snapshot().pending_leaders, 1);
    }

    #[test]
    fn format_uptime_less_than_60s() {
        assert_eq!(format_uptime(0), "0s");
        assert_eq!(format_uptime(45), "45s");
        assert_eq!(format_uptime(59), "59s");
    }

    #[test]
    fn format_uptime_minutes_and_seconds() {
        assert_eq!(format_uptime(60), "1m");
        assert_eq!(format_uptime(61), "1m 1s");
        assert_eq!(format_uptime(125), "2m 5s");
    }

    #[test]
    fn format_uptime_hours_minutes_seconds() {
        assert_eq!(format_uptime(3600), "1h");
        assert_eq!(format_uptime(3661), "1h 1m 1s");
        assert_eq!(format_uptime(51267), "14h 14m 27s");
    }

    #[test]
    fn format_uptime_days_hours_minutes_seconds() {
        assert_eq!(format_uptime(86400), "1d");
        assert_eq!(format_uptime(90061), "1d 1h 1m 1s");
        assert_eq!(format_uptime(172800), "2d");
    }

    #[test]
    fn format_uptime_omits_zero_units() {
        assert_eq!(format_uptime(3600 + 5), "1h 5s");
        assert_eq!(format_uptime(86400 + 3600), "1d 1h");
    }

    #[test]
    fn snapshot_to_human_string_uses_readable_uptime() {
        let snap = MetricsSnapshot {
            uptime_secs: 51267,
            total_queries: 100,
            cache_hits: 50,
            cache_misses: 50,
            blocked_queries: 0,
            upstream_failures: 0,
            upstream_successes: 0,
            upstream_timeouts: 0,
            cache_entries: 10,
            cache_evictions: 0,
            accepted_connections: 0,
            active_connections: 0,
            tls_handshake_success: 0,
            tls_handshake_failures: 0,
            dns_read_failures: 0,
            dns_write_failures: 0,
            pending_leaders: 0,
            pending_followers: 0,
            pending_follower_timeouts: 0,
            pending_follower_successes: 0,
        };
        let s = snap.to_human_string();
        assert!(s.contains("uptime: 14h 14m 27s"), "got: {}", s);
    }

    #[test]
    fn persisted_metrics_roundtrip() {
        let p = PersistedMetrics {
            total_queries: 42,
            cache_hits: 10,
            cache_misses: 5,
            blocked_queries: 2,
            upstream_failures: 1,
            upstream_successes: 3,
            upstream_timeouts: 0,
            cache_evictions: 1,
            accepted_connections: 5,
            tls_handshake_success: 4,
            tls_handshake_failures: 1,
            dns_read_failures: 0,
            dns_write_failures: 0,
            pending_follower_timeouts: 0,
            pending_follower_successes: 2,
        };
        let json = serde_json::to_string(&p).unwrap();
        let restored: PersistedMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(p, restored);
    }

    #[test]
    fn metrics_recorder_from_persisted_restores_counters() {
        let p = PersistedMetrics {
            total_queries: 100,
            cache_hits: 80,
            cache_misses: 20,
            blocked_queries: 5,
            upstream_failures: 1,
            upstream_successes: 10,
            upstream_timeouts: 2,
            cache_evictions: 3,
            accepted_connections: 50,
            tls_handshake_success: 48,
            tls_handshake_failures: 2,
            dns_read_failures: 1,
            dns_write_failures: 1,
            pending_follower_timeouts: 0,
            pending_follower_successes: 5,
        };
        let m = MetricsRecorder::from_persisted(&p);
        let snap = m.snapshot();
        assert_eq!(snap.total_queries, 100);
        assert_eq!(snap.cache_hits, 80);
        assert_eq!(snap.cache_misses, 20);
        assert_eq!(snap.blocked_queries, 5);
        assert_eq!(snap.upstream_failures, 1);
        assert_eq!(snap.upstream_successes, 10);
        assert_eq!(snap.upstream_timeouts, 2);
        assert_eq!(snap.cache_entries, 0);
        assert_eq!(snap.cache_evictions, 3);
        assert_eq!(snap.accepted_connections, 50);
        assert_eq!(snap.active_connections, 0);
        assert_eq!(snap.tls_handshake_success, 48);
        assert_eq!(snap.tls_handshake_failures, 2);
        assert_eq!(snap.dns_read_failures, 1);
        assert_eq!(snap.dns_write_failures, 1);
        assert_eq!(snap.pending_follower_timeouts, 0);
        assert_eq!(snap.pending_follower_successes, 5);
    }

    #[test]
    fn to_persisted_excludes_uptime_and_gauges() {
        let m = MetricsRecorder::new();
        m.record_query();
        m.set_cache_entries(42);
        m.record_accepted_connection();
        m.record_pending_leader_started();
        let p = m.to_persisted();
        assert_eq!(p.total_queries, 1);
        assert_eq!(p.cache_hits, 0);
        assert_eq!(p.cache_misses, 0);
        assert_eq!(p.blocked_queries, 0);
        assert_eq!(p.upstream_failures, 0);
        assert_eq!(p.upstream_successes, 0);
        assert_eq!(p.upstream_timeouts, 0);
        assert_eq!(p.cache_evictions, 0);
        assert_eq!(p.accepted_connections, 1);
        assert_eq!(p.tls_handshake_success, 0);
        assert_eq!(p.tls_handshake_failures, 0);
        assert_eq!(p.dns_read_failures, 0);
        assert_eq!(p.dns_write_failures, 0);
        assert_eq!(p.pending_follower_timeouts, 0);
        assert_eq!(p.pending_follower_successes, 0);
    }

    #[test]
    fn load_stats_missing_file_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        assert!(load_stats(&path).is_none());
    }

    #[test]
    fn save_and_load_stats_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.json");
        let persisted = PersistedMetrics {
            total_queries: 42,
            cache_hits: 10,
            cache_misses: 5,
            blocked_queries: 2,
            upstream_failures: 1,
            upstream_successes: 3,
            upstream_timeouts: 0,
            cache_evictions: 1,
            accepted_connections: 5,
            tls_handshake_success: 4,
            tls_handshake_failures: 1,
            dns_read_failures: 0,
            dns_write_failures: 0,
            pending_follower_timeouts: 0,
            pending_follower_successes: 2,
        };
        save_stats(&path, &persisted).unwrap();
        let loaded = load_stats(&path).unwrap();
        assert_eq!(persisted, loaded);
    }

    #[test]
    fn load_stats_corrupted_file_removes_and_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.json");
        std::fs::write(&path, b"not json").unwrap();
        assert!(load_stats(&path).is_none());
        assert!(!path.exists());
    }

    #[test]
    fn save_stats_creates_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("stats.json");
        let persisted = PersistedMetrics::default();
        save_stats(&path, &persisted).unwrap();
        assert!(path.exists());
    }
}
