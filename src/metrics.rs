use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Simple atomic metrics.
#[derive(Debug)]
pub struct MetricsRecorder {
    start_time: Instant,
    total_queries: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    blocked_queries: AtomicU64,
    upstream_failures: AtomicU64,
    cache_entries: AtomicU64,
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
            cache_entries: AtomicU64::new(0),
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
            cache_entries: AtomicU64::new(0),
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

    pub fn set_cache_entries(&self, n: u64) {
        self.cache_entries.store(n, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            uptime_secs: self.start_time.elapsed().as_secs(),
            total_queries: self.total_queries.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            blocked_queries: self.blocked_queries.load(Ordering::Relaxed),
            upstream_failures: self.upstream_failures.load(Ordering::Relaxed),
            cache_entries: self.cache_entries.load(Ordering::Relaxed),
        }
    }

    pub fn to_persisted(&self) -> PersistedMetrics {
        PersistedMetrics {
            total_queries: self.total_queries.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            blocked_queries: self.blocked_queries.load(Ordering::Relaxed),
            upstream_failures: self.upstream_failures.load(Ordering::Relaxed),
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
    pub cache_entries: u64,
}

/// Disk contract for persisting cumulative counters across restarts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct PersistedMetrics {
    pub total_queries: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub blocked_queries: u64,
    pub upstream_failures: u64,
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
             cache entries: {}",
            format_uptime(self.uptime_secs),
            self.total_queries,
            self.cache_hits,
            self.cache_misses,
            self.blocked_queries,
            self.upstream_failures,
            self.cache_entries,
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

/// Load persisted metrics from disk. Returns `None` if the file does not exist
/// or is corrupted; in the corrupted case the file is removed.
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

/// Atomically write persisted metrics to disk.
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
        m.set_cache_entries(42);

        let snap = m.snapshot();
        assert_eq!(snap.total_queries, 2);
        assert_eq!(snap.cache_hits, 1);
        assert_eq!(snap.cache_misses, 1);
        assert_eq!(snap.blocked_queries, 1);
        assert_eq!(snap.upstream_failures, 1);
        assert_eq!(snap.cache_entries, 42);
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
            cache_entries: 10,
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
        };
        let m = MetricsRecorder::from_persisted(&p);
        let snap = m.snapshot();
        assert_eq!(snap.total_queries, 100);
        assert_eq!(snap.cache_hits, 80);
        assert_eq!(snap.cache_misses, 20);
        assert_eq!(snap.blocked_queries, 5);
        assert_eq!(snap.upstream_failures, 1);
        assert_eq!(snap.cache_entries, 0);
    }

    #[test]
    fn to_persisted_excludes_uptime_and_cache_entries() {
        let m = MetricsRecorder::new();
        m.record_query();
        m.set_cache_entries(42);
        let p = m.to_persisted();
        assert_eq!(p.total_queries, 1);
        assert_eq!(p.cache_hits, 0);
        assert_eq!(p.cache_misses, 0);
        assert_eq!(p.blocked_queries, 0);
        assert_eq!(p.upstream_failures, 0);
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
