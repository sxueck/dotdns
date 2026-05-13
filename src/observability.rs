use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

const DEFAULT_CLIENT_CAPACITY: usize = 10_000;

#[derive(Debug)]
pub struct UpstreamStats {
    success_count: AtomicU64,
    failure_count: AtomicU64,
    timeout_count: AtomicU64,
    total_success_latency_ms: AtomicU64,
    last_success_latency_ms: AtomicU64,
}

impl Default for UpstreamStats {
    fn default() -> Self {
        Self::new()
    }
}

impl UpstreamStats {
    pub fn new() -> Self {
        Self {
            success_count: AtomicU64::new(0),
            failure_count: AtomicU64::new(0),
            timeout_count: AtomicU64::new(0),
            total_success_latency_ms: AtomicU64::new(0),
            last_success_latency_ms: AtomicU64::new(u64::MAX),
        }
    }

    pub fn record_success(&self, latency_ms: u64) {
        self.success_count.fetch_add(1, Ordering::Relaxed);
        self.total_success_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
        self.last_success_latency_ms
            .store(latency_ms, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.failure_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_timeout(&self) {
        self.timeout_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self, name: String) -> UpstreamSnapshot {
        let success_count = self.success_count.load(Ordering::Relaxed);
        let total_latency = self.total_success_latency_ms.load(Ordering::Relaxed);
        let last_latency = self.last_success_latency_ms.load(Ordering::Relaxed);
        UpstreamSnapshot {
            name,
            success_count,
            failure_count: self.failure_count.load(Ordering::Relaxed),
            timeout_count: self.timeout_count.load(Ordering::Relaxed),
            last_success_latency_ms: if last_latency == u64::MAX {
                None
            } else {
                Some(last_latency)
            },
            avg_success_latency_ms: if success_count > 0 {
                Some(total_latency / success_count)
            } else {
                None
            },
        }
    }
}

#[derive(Debug)]
pub struct ClientStats {
    total_queries: AtomicU64,
    blocked_queries: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    active_connections: AtomicU64,
    last_activity: AtomicU64,
}

impl Default for ClientStats {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientStats {
    pub fn new() -> Self {
        Self {
            total_queries: AtomicU64::new(0),
            blocked_queries: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            last_activity: AtomicU64::new(0),
        }
    }

    pub fn record_query(&self) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_blocked(&self) {
        self.blocked_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_connection_opened(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_connection_closed(&self) {
        // Avoid underflow if called without a matching open.
        let current = self.active_connections.load(Ordering::Relaxed);
        if current > 0 {
            self.active_connections.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn touch_activity(&self, tick: u64) {
        self.last_activity.store(tick, Ordering::Relaxed);
    }

    pub fn snapshot(&self, ip: IpAddr) -> ClientSnapshot {
        ClientSnapshot {
            ip,
            total_queries: self.total_queries.load(Ordering::Relaxed),
            blocked_queries: self.blocked_queries.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpstreamSnapshot {
    pub name: String,
    pub success_count: u64,
    pub failure_count: u64,
    pub timeout_count: u64,
    pub last_success_latency_ms: Option<u64>,
    pub avg_success_latency_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientSnapshot {
    pub ip: IpAddr,
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub active_connections: u64,
}

#[cfg(test)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObservabilitySnapshot {
    pub upstreams: Vec<UpstreamSnapshot>,
    pub clients: Vec<ClientSnapshot>,
    pub client_count: usize,
}

#[derive(Debug, Clone)]
pub struct ObservabilityRegistry {
    upstreams: Arc<HashMap<String, Arc<UpstreamStats>>>,
    clients: Arc<RwLock<HashMap<IpAddr, Arc<ClientStats>>>>,
    client_capacity: usize,
    activity_clock: Arc<AtomicU64>,
}

impl Default for ObservabilityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ObservabilityRegistry {
    pub fn new() -> Self {
        Self::with_upstreams_and_capacity(&[], DEFAULT_CLIENT_CAPACITY)
    }

    #[cfg(test)]
    pub fn with_capacity(client_capacity: usize) -> Self {
        Self::with_upstreams_and_capacity(&[], client_capacity)
    }

    pub fn with_upstreams(upstream_names: &[String]) -> Self {
        Self::with_upstreams_and_capacity(upstream_names, DEFAULT_CLIENT_CAPACITY)
    }

    pub fn with_upstreams_and_capacity(upstream_names: &[String], client_capacity: usize) -> Self {
        let mut map = HashMap::with_capacity(upstream_names.len());
        for name in upstream_names {
            map.insert(name.clone(), Arc::new(UpstreamStats::new()));
        }
        Self {
            upstreams: Arc::new(map),
            clients: Arc::new(RwLock::new(HashMap::with_capacity(client_capacity))),
            client_capacity,
            activity_clock: Arc::new(AtomicU64::new(1)),
        }
    }

    fn next_tick(&self) -> u64 {
        self.activity_clock.fetch_add(1, Ordering::Relaxed)
    }

    fn with_client<F>(&self, ip: IpAddr, f: F)
    where
        F: FnOnce(&ClientStats),
    {
        // Fast path: read lock to find existing client.
        {
            let clients = self.clients.read().expect("client map lock poisoned");
            if let Some(stats) = clients.get(&ip) {
                stats.touch_activity(self.next_tick());
                f(stats);
                return;
            }
        }

        // Slow path: write lock to insert.
        let mut clients = self.clients.write().expect("client map lock poisoned");

        // Double-check in case another thread inserted while we were waiting.
        if let Some(stats) = clients.get(&ip) {
            stats.touch_activity(self.next_tick());
            f(stats);
            return;
        }

        // Evict oldest if at capacity.
        if clients.len() >= self.client_capacity && !clients.is_empty() {
            let oldest_ip = clients
                .iter()
                .min_by_key(|(_, stats)| stats.last_activity.load(Ordering::Relaxed))
                .map(|(ip, _)| *ip);
            if let Some(oldest) = oldest_ip {
                clients.remove(&oldest);
            }
        }

        let stats = Arc::new(ClientStats::new());
        stats.touch_activity(self.next_tick());
        f(&stats);
        clients.insert(ip, stats);
    }

    // -- upstream recording --

    pub fn record_upstream_success(&self, name: &str, latency_ms: u64) {
        if let Some(stats) = self.upstreams.get(name) {
            stats.record_success(latency_ms);
        }
    }

    pub fn record_upstream_failure(&self, name: &str) {
        if let Some(stats) = self.upstreams.get(name) {
            stats.record_failure();
        }
    }

    pub fn record_upstream_timeout(&self, name: &str) {
        if let Some(stats) = self.upstreams.get(name) {
            stats.record_timeout();
        }
    }

    // -- client recording --

    pub fn record_client_query(&self, ip: IpAddr) {
        self.with_client(ip, |s| s.record_query());
    }

    pub fn record_client_blocked(&self, ip: IpAddr) {
        self.with_client(ip, |s| s.record_blocked());
    }

    pub fn record_client_cache_hit(&self, ip: IpAddr) {
        self.with_client(ip, |s| s.record_cache_hit());
    }

    pub fn record_client_cache_miss(&self, ip: IpAddr) {
        self.with_client(ip, |s| s.record_cache_miss());
    }

    pub fn record_client_connection_opened(&self, ip: IpAddr) {
        self.with_client(ip, |s| s.record_connection_opened());
    }

    pub fn record_client_connection_closed(&self, ip: IpAddr) {
        self.with_client(ip, |s| s.record_connection_closed());
    }

    // -- snapshots --

    pub fn upstream_snapshot(&self) -> Vec<UpstreamSnapshot> {
        self.upstreams
            .iter()
            .map(|(name, stats)| stats.snapshot(name.clone()))
            .collect()
    }

    pub fn client_snapshot(&self) -> Vec<ClientSnapshot> {
        let clients = self.clients.read().expect("client map lock poisoned");
        clients
            .iter()
            .map(|(ip, stats)| stats.snapshot(*ip))
            .collect()
    }

    #[cfg(test)]
    pub fn snapshot(&self) -> ObservabilitySnapshot {
        let upstreams = self.upstream_snapshot();
        let clients = self.client_snapshot();
        let client_count = clients.len();
        ObservabilitySnapshot {
            upstreams,
            clients,
            client_count,
        }
    }

    #[cfg(test)]
    pub fn client_count(&self) -> usize {
        self.clients.read().expect("client map lock poisoned").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Barrier;
    use std::thread;

    #[test]
    fn upstream_counters_increment() {
        let reg = ObservabilityRegistry::with_upstreams(&["u1".into(), "u2".into()]);
        reg.record_upstream_success("u1", 42);
        reg.record_upstream_success("u1", 58);
        reg.record_upstream_failure("u1");
        reg.record_upstream_timeout("u2");

        let snap = reg.snapshot();
        let u1 = snap.upstreams.iter().find(|u| u.name == "u1").unwrap();
        assert_eq!(u1.success_count, 2);
        assert_eq!(u1.failure_count, 1);
        assert_eq!(u1.timeout_count, 0);
        assert_eq!(u1.last_success_latency_ms, Some(58));
        assert_eq!(u1.avg_success_latency_ms, Some(50));

        let u2 = snap.upstreams.iter().find(|u| u.name == "u2").unwrap();
        assert_eq!(u2.success_count, 0);
        assert_eq!(u2.failure_count, 0);
        assert_eq!(u2.timeout_count, 1);
        assert_eq!(u2.last_success_latency_ms, None);
        assert_eq!(u2.avg_success_latency_ms, None);
    }

    #[test]
    fn upstream_unknown_name_is_noop() {
        let reg = ObservabilityRegistry::with_upstreams(&["u1".into()]);
        reg.record_upstream_success("unknown", 10);
        reg.record_upstream_failure("unknown");
        reg.record_upstream_timeout("unknown");

        let snap = reg.snapshot();
        assert_eq!(snap.upstreams.len(), 1);
        assert_eq!(snap.upstreams[0].success_count, 0);
    }

    #[test]
    fn client_counters_increment() {
        let reg = ObservabilityRegistry::with_capacity(100);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        reg.record_client_query(ip);
        reg.record_client_query(ip);
        reg.record_client_blocked(ip);
        reg.record_client_cache_hit(ip);
        reg.record_client_cache_miss(ip);
        reg.record_client_connection_opened(ip);

        let snap = reg.snapshot();
        assert_eq!(snap.client_count, 1);
        let client = &snap.clients[0];
        assert_eq!(client.ip, ip);
        assert_eq!(client.total_queries, 2);
        assert_eq!(client.blocked_queries, 1);
        assert_eq!(client.cache_hits, 1);
        assert_eq!(client.cache_misses, 1);
        assert_eq!(client.active_connections, 1);
    }

    #[test]
    fn client_connection_closed_decrements() {
        let reg = ObservabilityRegistry::with_capacity(100);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        reg.record_client_connection_opened(ip);
        reg.record_client_connection_opened(ip);
        assert_eq!(reg.snapshot().clients[0].active_connections, 2);

        reg.record_client_connection_closed(ip);
        assert_eq!(reg.snapshot().clients[0].active_connections, 1);
    }

    #[test]
    fn client_connection_close_without_open_does_not_underflow() {
        let reg = ObservabilityRegistry::with_capacity(100);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        reg.record_client_connection_closed(ip);
        assert_eq!(reg.snapshot().clients[0].active_connections, 0);
    }

    #[test]
    fn multiple_clients_are_tracked() {
        let reg = ObservabilityRegistry::with_capacity(100);
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        reg.record_client_query(ip1);
        reg.record_client_query(ip2);
        reg.record_client_query(ip2);

        let snap = reg.snapshot();
        assert_eq!(snap.client_count, 2);
        let c1 = snap.clients.iter().find(|c| c.ip == ip1).unwrap();
        let c2 = snap.clients.iter().find(|c| c.ip == ip2).unwrap();
        assert_eq!(c1.total_queries, 1);
        assert_eq!(c2.total_queries, 2);
    }

    #[test]
    fn client_map_is_bounded() {
        let reg = ObservabilityRegistry::with_capacity(3);
        let ips = [
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)),
        ];

        for ip in &ips {
            reg.record_client_query(*ip);
        }
        assert_eq!(reg.client_count(), 3);

        // Add a 4th client; one should be evicted.
        let ip4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4));
        reg.record_client_query(ip4);
        assert_eq!(reg.client_count(), 3);

        // The newest client must be present.
        let snap = reg.snapshot();
        assert!(snap.clients.iter().any(|c| c.ip == ip4));
    }

    #[test]
    fn client_eviction_prefers_least_recently_active() {
        let reg = ObservabilityRegistry::with_capacity(2);
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let ip3 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3));

        reg.record_client_query(ip1);
        reg.record_client_query(ip2);
        // ip2 is now more recently active.

        reg.record_client_query(ip3);
        // ip1 should be evicted because it is the oldest.
        let snap = reg.snapshot();
        assert!(!snap.clients.iter().any(|c| c.ip == ip1));
        assert!(snap.clients.iter().any(|c| c.ip == ip2));
        assert!(snap.clients.iter().any(|c| c.ip == ip3));
    }

    #[test]
    fn client_map_handles_ipv6() {
        let reg = ObservabilityRegistry::with_capacity(100);
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        reg.record_client_query(ip);
        let snap = reg.snapshot();
        assert_eq!(snap.client_count, 1);
        assert_eq!(snap.clients[0].ip, ip);
    }

    #[test]
    fn snapshot_is_cloneable_and_serde_roundtrips() {
        let reg = ObservabilityRegistry::with_upstreams(&["u1".into()]);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        reg.record_upstream_success("u1", 10);
        reg.record_client_query(ip);

        let snap = reg.snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let restored: ObservabilitySnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, restored);

        // Clone check.
        let cloned = snap.clone();
        assert_eq!(snap, cloned);
    }

    #[test]
    fn concurrent_client_updates_are_safe() {
        let reg = Arc::new(ObservabilityRegistry::with_capacity(100));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let threads = 8;
        let iterations = 1_000;
        let barrier = Arc::new(Barrier::new(threads));

        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let reg = reg.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..iterations {
                        reg.record_client_query(ip);
                        reg.record_client_cache_hit(ip);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let snap = reg.snapshot();
        assert_eq!(snap.client_count, 1);
        let client = &snap.clients[0];
        assert_eq!(client.total_queries, threads as u64 * iterations);
        assert_eq!(client.cache_hits, threads as u64 * iterations);
    }

    #[test]
    fn concurrent_new_client_inserts_are_safe() {
        let reg = Arc::new(ObservabilityRegistry::with_capacity(200));
        let threads = 8;
        let clients_per_thread = 50;
        let barrier = Arc::new(Barrier::new(threads));

        let handles: Vec<_> = (0..threads)
            .map(|t| {
                let reg = reg.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    for c in 0..clients_per_thread {
                        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, t as u8, c as u8));
                        reg.record_client_query(ip);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // Capacity is 200; some evictions may occur under heavy contention.
        assert!(reg.client_count() <= 200);
        // Every thread should have contributed at least some surviving entries.
        assert!(reg.client_count() >= threads);
    }
}
