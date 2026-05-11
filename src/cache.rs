//! Simple TTL cache.

use crate::config::CacheConfig;
use crate::metrics::MetricsRecorder;
use hickory_proto::op::Message;
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    name: Name,
    qtype: RecordType,
    qclass: DNSClass,
    rd: bool,
    do_bit: bool,
    ecs: Option<Vec<u8>>,
}

impl CacheKey {
    fn from_message(msg: &Message) -> Option<Self> {
        let q = msg.queries().first()?;
        let do_bit = msg.extensions().as_ref().is_some_and(|e| e.dnssec_ok());
        let ecs = msg
            .extensions()
            .as_ref()
            .and_then(|edns| match edns.option(EdnsCode::Subnet) {
                Some(EdnsOption::Subnet(subnet)) => Vec::try_from(subnet).ok(),
                _ => None,
            });
        Some(Self {
            name: q.name().clone(),
            qtype: q.query_type(),
            qclass: q.query_class(),
            rd: msg.recursion_desired(),
            do_bit,
            ecs,
        })
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    message: Message,
    inserted_at: Instant,
    ttl: Duration,
}

#[derive(Debug, Clone)]
pub struct Cache {
    inner: Arc<Mutex<CacheInner>>,
}

#[derive(Debug)]
struct CacheInner {
    config: CacheConfig,
    metrics: Arc<MetricsRecorder>,
    entries: HashMap<CacheKey, CacheEntry>,
}

impl Cache {
    pub fn new(config: CacheConfig, metrics: Arc<MetricsRecorder>) -> Self {
        metrics.set_cache_entries(0);
        Self {
            inner: Arc::new(Mutex::new(CacheInner {
                config,
                metrics,
                entries: HashMap::new(),
            })),
        }
    }

    // Returns None if expired or missing.
    pub fn get(&self, query: &Message) -> Option<Message> {
        let key = CacheKey::from_message(query)?;
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();

        let entry = inner.entries.get(&key)?;
        let elapsed = now.duration_since(entry.inserted_at);

        if elapsed >= entry.ttl {
            inner.entries.remove(&key);
            inner.update_metric();
            return None;
        }

        let remaining = entry.ttl.saturating_sub(elapsed);
        let remaining_secs = remaining.as_secs() as u32;

        let mut response = entry.message.clone();
        for record in response.answers_mut() {
            record.set_ttl(remaining_secs);
        }
        for record in response.name_servers_mut() {
            record.set_ttl(remaining_secs);
        }
        for record in response.additionals_mut() {
            record.set_ttl(remaining_secs);
        }

        Some(response)
    }

    pub fn insert(&self, query: &Message, response: &Message) {
        let key = match CacheKey::from_message(query) {
            Some(k) => k,
            None => return,
        };

        let mut min_ttl_secs: u64 = u64::MAX;
        let mut has_records = false;
        for record in response.answers() {
            has_records = true;
            min_ttl_secs = min_ttl_secs.min(record.ttl() as u64);
        }
        for record in response.name_servers() {
            has_records = true;
            min_ttl_secs = min_ttl_secs.min(record.ttl() as u64);
        }
        for record in response.additionals() {
            has_records = true;
            min_ttl_secs = min_ttl_secs.min(record.ttl() as u64);
        }

        if !has_records {
            return;
        }

        let mut ttl = Duration::from_secs(min_ttl_secs);
        let mut inner = self.inner.lock().unwrap();

        if let Some(min) = inner.config.min_ttl {
            if ttl < min {
                ttl = min;
            }
        }
        if let Some(max) = inner.config.max_ttl {
            if ttl > max {
                ttl = max;
            }
        }

        // naive eviction — just drop the first key. not LRU.
        if inner.entries.len() >= inner.config.capacity {
            if let Some(k) = inner.entries.keys().next().cloned() {
                inner.entries.remove(&k);
            }
        }

        inner.entries.insert(
            key,
            CacheEntry {
                message: response.clone(),
                inserted_at: Instant::now(),
                ttl,
            },
        );
        inner.update_metric();
    }

    pub fn flush(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.entries.clear();
        inner.update_metric();
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.entries.len()
    }
}

impl CacheInner {
    fn update_metric(&self) {
        self.metrics.set_cache_entries(self.entries.len() as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, Record, RecordType};
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    fn test_query(name: &str, qtype: RecordType) -> Message {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(true);
        msg.add_query(Query::query(Name::from_str(name).unwrap(), qtype));
        msg
    }

    fn test_response(query: &Message, ttl: u32) -> Message {
        let mut msg = Message::new();
        msg.set_id(query.id());
        msg.set_message_type(MessageType::Response);
        msg.set_op_code(OpCode::Query);
        msg.set_response_code(ResponseCode::NoError);
        let q = query.queries().first().unwrap();
        let record = Record::from_rdata(
            q.name().clone(),
            ttl,
            hickory_proto::rr::RData::A(A(Ipv4Addr::new(127, 0, 0, 1))),
        );
        msg.add_answer(record);
        msg
    }

    fn add_ecs(query: &mut Message, ip: Ipv4Addr) {
        let mut edns = query.extensions().as_ref().cloned().unwrap_or_default();
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(IpAddr::V4(ip), 24, 0)));
        query.set_edns(edns);
    }

    #[test]
    fn cache_insert_and_get() {
        let metrics = Arc::new(MetricsRecorder::new());
        let cache = Cache::new(CacheConfig::default(), metrics);
        let query = test_query("example.com.", RecordType::A);
        let response = test_response(&query, 300);

        assert!(cache.get(&query).is_none());
        cache.insert(&query, &response);
        let cached = cache.get(&query).expect("cache hit");
        assert_eq!(cached.answers().len(), 1);
        let ttl = cached.answers()[0].ttl();
        assert!(
            (299..=300).contains(&ttl),
            "expected ttl around 300, got {}",
            ttl
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_key_includes_ecs() {
        let metrics = Arc::new(MetricsRecorder::new());
        let cache = Cache::new(CacheConfig::default(), metrics);
        let mut query1 = test_query("example.com.", RecordType::A);
        let mut query2 = test_query("example.com.", RecordType::A);
        add_ecs(&mut query1, Ipv4Addr::new(8, 8, 8, 0));
        add_ecs(&mut query2, Ipv4Addr::new(1, 1, 1, 0));

        let response = test_response(&query1, 300);
        cache.insert(&query1, &response);

        assert!(cache.get(&query1).is_some());
        assert!(cache.get(&query2).is_none());
    }

    #[test]
    fn cache_ttl_expires() {
        let metrics = Arc::new(MetricsRecorder::new());
        let config = CacheConfig {
            capacity: 100,
            min_ttl: None,
            max_ttl: None,
        };
        let cache = Cache::new(config, metrics);
        let query = test_query("example.com.", RecordType::A);
        let response = test_response(&query, 0);

        cache.insert(&query, &response);
        assert!(cache.get(&query).is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn cache_flush() {
        let metrics = Arc::new(MetricsRecorder::new());
        let cache = Cache::new(CacheConfig::default(), metrics);
        let query = test_query("example.com.", RecordType::A);
        let response = test_response(&query, 300);

        cache.insert(&query, &response);
        assert_eq!(cache.len(), 1);
        cache.flush();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn cache_respects_capacity() {
        let metrics = Arc::new(MetricsRecorder::new());
        let config = CacheConfig {
            capacity: 2,
            min_ttl: None,
            max_ttl: None,
        };
        let cache = Cache::new(config, metrics);
        let q1 = test_query("a.com.", RecordType::A);
        let r1 = test_response(&q1, 300);
        let q2 = test_query("b.com.", RecordType::A);
        let r2 = test_response(&q2, 300);
        let q3 = test_query("c.com.", RecordType::A);
        let r3 = test_response(&q3, 300);

        cache.insert(&q1, &r1);
        cache.insert(&q2, &r2);
        cache.insert(&q3, &r3);
        assert!(cache.len() <= 2);
    }

    #[test]
    fn cache_clamps_ttl() {
        let metrics = Arc::new(MetricsRecorder::new());
        let config = CacheConfig {
            capacity: 100,
            min_ttl: Some(Duration::from_secs(10)),
            max_ttl: Some(Duration::from_secs(20)),
        };
        let cache = Cache::new(config, metrics);
        let query = test_query("example.com.", RecordType::A);
        let response = test_response(&query, 300); // 300s, should be clamped to 20

        cache.insert(&query, &response);
        let cached = cache.get(&query).unwrap();
        // Since we just inserted, remaining TTL should be clamped max = 20
        let ttl = cached.answers()[0].ttl();
        assert!(
            (19..=20).contains(&ttl),
            "expected ttl around 20, got {}",
            ttl
        );
    }

    #[test]
    fn cache_clamps_ttl_to_minimum() {
        let metrics = Arc::new(MetricsRecorder::new());
        let config = CacheConfig {
            capacity: 100,
            min_ttl: Some(Duration::from_secs(30)),
            max_ttl: Some(Duration::from_secs(60)),
        };
        let cache = Cache::new(config, metrics);
        let query = test_query("minimum.example.", RecordType::A);
        let response = test_response(&query, 5);

        cache.insert(&query, &response);

        let cached = cache.get(&query).unwrap();
        let ttl = cached.answers()[0].ttl();
        assert!(
            (29..=30).contains(&ttl),
            "expected ttl around 30, got {}",
            ttl
        );
    }
}
