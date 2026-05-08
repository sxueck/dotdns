use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// A lightweight, lock-free metrics recorder.
///
/// Downstream workstreams (WS-003 cache, WS-005 management) depend on these counters.
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

    /// Produce a snapshot for management reporting.
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
}

/// Serializable metrics snapshot returned by management queries.
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

impl MetricsSnapshot {
    /// Human-readable summary for CLI output.
    pub fn to_human_string(&self) -> String {
        format!(
            "uptime: {}s\n\
             total queries: {}\n\
             cache hits: {}\n\
             cache misses: {}\n\
             blocked: {}\n\
             upstream failures: {}\n\
             cache entries: {}",
            self.uptime_secs,
            self.total_queries,
            self.cache_hits,
            self.cache_misses,
            self.blocked_queries,
            self.upstream_failures,
            self.cache_entries,
        )
    }
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
    fn snapshot_serde_roundtrip() {
        let snap = MetricsSnapshot {
            uptime_secs: 123,
            total_queries: 10,
            cache_hits: 4,
            cache_misses: 6,
            blocked_queries: 1,
            upstream_failures: 0,
            cache_entries: 3,
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: MetricsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }
}
