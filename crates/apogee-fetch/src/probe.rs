//! Per-host range-capability probing and its session cache.
//!
//! Segmentation needs the server to honor `Range`. The first ranged request to a host reveals this:
//! a `206 Partial Content` means ranges work and the transfer can fan out; a `200` (the range
//! ignored, whole body returned) demotes the job to a single streaming connection, correct but
//! slower. The verdict is cached per `host:port` for the session, so later jobs to the same host skip
//! the probe.

use std::collections::HashMap;
use std::sync::Mutex;

use url::Url;

/// Whether a host serves byte ranges (segmentable) or ignores them (single connection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Capability {
    /// The host answered a ranged request with `206`; the transfer can segment.
    Segmentable,
    /// The host ignored the range (`200`); the transfer must stream on one connection.
    SingleConnection,
}

/// Classify a ranged probe response. Only `200`/`206` are expected here; any other status is a
/// transport error handled before classification. A `206` proves the server served the requested
/// range, so ranges are usable; anything else is treated as an ignored range.
pub(crate) fn classify(resp: &reqwest::Response) -> Capability {
    if resp.status() == reqwest::StatusCode::PARTIAL_CONTENT {
        Capability::Segmentable
    } else {
        Capability::SingleConnection
    }
}

/// A session cache of per-host range capability, keyed on `host:port`.
#[derive(Debug, Default)]
pub(crate) struct CapabilityCache {
    map: Mutex<HashMap<String, Capability>>,
}

impl CapabilityCache {
    /// The cached verdict for `url`'s host, if one was recorded this session.
    pub(crate) fn get(&self, url: &Url) -> Option<Capability> {
        let key = host_key(url)?;
        self.lock().get(&key).copied()
    }

    /// Record `url`'s host capability for the session.
    pub(crate) fn set(&self, url: &Url, capability: Capability) {
        if let Some(key) = host_key(url) {
            self.lock().insert(key, capability);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Capability>> {
        self.map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The `host:port` cache key, or `None` for a URL without a host (never a valid download source).
fn host_key(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    let port = url.port_or_known_default()?;
    Some(format!("{host}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use apogee_test_support::chaos::ChaosServer;
    use reqwest::header::RANGE;

    async fn probe_status(accept_ranges: bool) -> Capability {
        let server = ChaosServer::builder(1, 4096)
            .accept_ranges(accept_ranges)
            .start()
            .await
            .unwrap();
        let client = reqwest::Client::new();
        let resp = client
            .get(server.url("file.bin"))
            .header(RANGE, "bytes=0-1023")
            .send()
            .await
            .unwrap();
        classify(&resp)
    }

    #[tokio::test]
    async fn a_ranging_server_is_segmentable() {
        assert_eq!(probe_status(true).await, Capability::Segmentable);
    }

    #[tokio::test]
    async fn a_range_ignoring_server_is_single_connection() {
        assert_eq!(probe_status(false).await, Capability::SingleConnection);
    }

    #[test]
    fn the_cache_round_trips_per_host() {
        let cache = CapabilityCache::default();
        let a = Url::parse("http://patch.example.com/a").unwrap();
        let b = Url::parse("http://patch.example.com:8080/b").unwrap();
        assert_eq!(cache.get(&a), None);
        cache.set(&a, Capability::Segmentable);
        // Same host+default port, different path -> same verdict.
        let a2 = Url::parse("http://patch.example.com/other").unwrap();
        assert_eq!(cache.get(&a2), Some(Capability::Segmentable));
        // A different port is a different key.
        assert_eq!(cache.get(&b), None);
    }
}
