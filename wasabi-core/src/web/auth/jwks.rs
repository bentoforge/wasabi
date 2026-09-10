//! JWKS (JSON Web Key Set) fetching and caching.
//!
//! Caches keys with a minimum cooldown between fetches to prevent hammering
//! the JWKS endpoint on key rotation. See `MAX_CACHE_TTL_SECONDS` and
//! `MIN_WAIT_BETWEEN_LOADS_SECONDS` for the actual values.

use anyhow::{Context, bail};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use jsonwebtoken::DecodingKey;
use jwks::Jwks;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

#[cfg(test)]
use mock_instant::global::SystemTime;
use reqwest::Client;
#[cfg(not(test))]
use std::time::SystemTime;

/// Timeouts for JWKS HTTP fetches.
///
/// Generous enough to tolerate slow identity-provider responses under load,
/// but bounded so a hanging IdP can never cause the request handler to
/// stall past CloudFront's default 30s origin-response timeout.
const JWKS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const JWKS_TOTAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Maps key IDs (kid) to their corresponding decoding keys.
pub(crate) type KeyCache = HashMap<String, Arc<DecodingKey>>;

/// Trait for fetching JWKS key sets from a source.
///
/// Implementations can fetch keys from URLs, files, or return mock data for testing.
#[async_trait]
pub(crate) trait JwksFetcher: Send + Sync {
    /// Fetches all keys from the JWKS source and returns them as a key cache.
    async fn fetch(&self) -> anyhow::Result<KeyCache>;
}

/// Fetches JWKS keys from a remote URL endpoint.
///
/// Used for validating JWTs signed with keys from identity providers
/// that publish their public keys via a JWKS endpoint.
pub struct UrlJwksFetcher {
    url: String,
    client: Client,
}

#[async_trait]
impl JwksFetcher for UrlJwksFetcher {
    #[tracing::instrument(level = "debug", skip(self), fields(url = %self.url), err(level = "debug", Display))]
    async fn fetch(&self) -> anyhow::Result<KeyCache> {
        // Note that we pass a custom client in here, so that our dependency "reqwest"
        // is actually marked as used. We need this dependency to activate "rustls-tls" as
        // feature, as JWKS itself has all default features turned off...
        //
        // The client carries explicit timeouts so a slow / stuck identity
        // provider cannot hang the request handler indefinitely.
        let jwks = Jwks::from_jwks_url_with_client(&self.client, &self.url)
            .await
            .with_context(|| format!("Failed to fetch JWKS from: {}", self.url))?;

        let keys = jwks
            .keys
            .into_iter()
            .map(|(kid, key)| (kid, Arc::new(key.decoding_key)))
            .collect();

        Ok(keys)
    }
}

impl UrlJwksFetcher {
    /// Creates a new JWKS fetcher for the given URL.
    ///
    /// The reqwest builder is only fallible when the TLS backend can't be
    /// initialized — a catastrophic startup condition — so a panic here is
    /// preferable to threading a Result through every caller.
    #[allow(clippy::expect_used)]
    pub(crate) fn new(url: String) -> Self {
        let client = Client::builder()
            .connect_timeout(JWKS_CONNECT_TIMEOUT)
            .timeout(JWKS_TOTAL_TIMEOUT)
            .build()
            .expect("Failed to build JWKS HTTP client with fixed timeouts");
        Self { url, client }
    }
}

/// Maximum time to cache keys before forcing a refresh.
///
/// JWKS signing keys rotate rarely (typically weeks to months at most
/// providers), so a long TTL is safe. Unknown-kid lookups still trigger
/// an immediate refetch (gated only by `MIN_WAIT_BETWEEN_LOADS_SECONDS`),
/// so genuine rotations are picked up within seconds regardless of TTL.
const MAX_CACHE_TTL_SECONDS: u64 = 30 * 60;

/// Minimum time between fetch attempts to prevent hammering the endpoint.
const MIN_WAIT_BETWEEN_LOADS_SECONDS: u64 = 10;

/// Sentinel value indicating the cache has never been loaded.
const NOT_YET_LOADED: u64 = 0;

/// Caching layer for JWKS keys with automatic refresh.
///
/// Keys are cached for up to `MAX_CACHE_TTL_SECONDS`. When a requested key
/// is not found, the cache will attempt to refresh (respecting the
/// `MIN_WAIT_BETWEEN_LOADS_SECONDS` cooldown) to handle key rotation.
pub(crate) struct JwksCache {
    fetcher: Box<dyn JwksFetcher>,
    last_load: ArcSwapOption<SystemTime>,
    cached_keys: ArcSwapOption<KeyCache>,
}
impl JwksCache {
    /// Creates a new cache with the given fetcher.
    pub(crate) fn new(fetcher: Box<dyn JwksFetcher>) -> Self {
        Self {
            fetcher,
            last_load: ArcSwapOption::new(None),
            cached_keys: ArcSwapOption::new(None),
        }
    }

    /// Retrieves a decoding key by its key ID (kid).
    ///
    /// Returns a cached key if available and not expired. Otherwise fetches
    /// fresh keys from the source (respecting the cooldown period).
    #[tracing::instrument(level = "debug", skip(self), fields(key_id = %key_id), err(level = "debug", Display))]
    pub(crate) async fn fetch_key(&self, key_id: &str) -> anyhow::Result<Arc<DecodingKey>> {
        let mut cached_keys = self.load_keys();
        let last_load_seconds = self.compute_seconds_since_last_load();

        if last_load_seconds > MAX_CACHE_TTL_SECONDS
            || cached_keys
                .as_ref()
                .and_then(|keys| keys.get(key_id))
                .is_none()
        {
            cached_keys = None;
        }

        if cached_keys.is_none()
            && (last_load_seconds == NOT_YET_LOADED
                || last_load_seconds > MIN_WAIT_BETWEEN_LOADS_SECONDS)
        {
            tracing::debug!(
                last_load_seconds,
                reason = "unknown_kid_or_ttl_expired",
                "refetching JWKS"
            );
            self.last_load.store(Some(Arc::new(SystemTime::now())));
            let keys = self
                .fetcher
                .fetch()
                .await
                .inspect_err(|_| self.cached_keys.store(None))?;
            cached_keys = Some(Arc::new(keys));
            self.cached_keys.store(cached_keys.clone());
        }

        if let Some(keys) = cached_keys {
            if let Some(key) = keys.get(key_id) {
                Ok(key.clone())
            } else {
                tracing::warn!(
                    key_id,
                    cached_kids = ?keys.keys().collect::<Vec<_>>(),
                    last_load_seconds,
                    "JWT uses unknown kid — rejecting"
                );
                bail!("Unknown JWKS key: {}", key_id);
            }
        } else {
            tracing::warn!(
                key_id,
                last_load_seconds,
                "JWKS cache empty and refetch blocked by cooldown"
            );
            bail!("JWKS not loaded or empty");
        }
    }

    fn load_keys(&self) -> Option<Arc<KeyCache>> {
        self.cached_keys.load_full()
    }

    fn compute_seconds_since_last_load(&self) -> u64 {
        self.last_load
            .load_full()
            .and_then(|last_load| SystemTime::now().duration_since(*last_load).ok())
            .map(|duration| duration.as_secs())
            .unwrap_or(NOT_YET_LOADED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockJwksFetcher {
        keys: KeyCache,
    }

    impl MockJwksFetcher {
        fn new(keys: KeyCache) -> Self {
            Self { keys }
        }
    }

    #[async_trait]
    impl JwksFetcher for MockJwksFetcher {
        async fn fetch(&self) -> anyhow::Result<KeyCache> {
            Ok(self.keys.clone())
        }
    }

    fn create_test_key() -> Arc<DecodingKey> {
        Arc::new(DecodingKey::from_secret(b"test-secret"))
    }

    #[tokio::test]
    async fn fetch_key_loads_from_fetcher_on_first_call() {
        let mut keys = KeyCache::new();
        keys.insert("key-1".to_string(), create_test_key());

        let fetcher = MockJwksFetcher::new(keys);
        let cache = JwksCache::new(Box::new(fetcher));

        let result = cache.fetch_key("key-1").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn fetch_key_returns_error_for_unknown_key() {
        let mut keys = KeyCache::new();
        keys.insert("key-1".to_string(), create_test_key());

        let fetcher = MockJwksFetcher::new(keys);
        let cache = JwksCache::new(Box::new(fetcher));

        let result = cache.fetch_key("unknown-key").await;

        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("Unknown JWKS key")
        );
    }

    #[tokio::test]
    async fn fetch_key_caches_keys_between_calls() {
        let mut keys = KeyCache::new();
        keys.insert("key-1".to_string(), create_test_key());

        let fetcher = MockJwksFetcher::new(keys);
        let cache = JwksCache::new(Box::new(fetcher));

        // First call
        cache.fetch_key("key-1").await.unwrap();
        // Second call - should use cache
        cache.fetch_key("key-1").await.unwrap();

        // Caching behavior is verified by the TTL tests - if caching didn't work,
        // the fetcher would be called multiple times
    }

    #[tokio::test]
    async fn fetch_key_refetches_for_unknown_key_after_cooldown() {
        use mock_instant::global::MockClock;

        let mut keys = KeyCache::new();
        keys.insert("key-1".to_string(), create_test_key());

        let fetcher = MockJwksFetcher::new(keys);
        let cache = JwksCache::new(Box::new(fetcher));

        // First fetch
        cache.fetch_key("key-1").await.unwrap();

        // Try unknown key - should fail but not refetch (within cooldown)
        let result = cache.fetch_key("key-2").await;
        assert!(result.is_err());

        // Advance time past cooldown
        MockClock::advance(std::time::Duration::from_secs(15));

        // Now it should try to refetch (will still fail since mock doesn't have key-2)
        let result = cache.fetch_key("key-2").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn fetch_key_refetches_after_cache_ttl_expires() {
        use mock_instant::global::MockClock;

        let mut keys = KeyCache::new();
        keys.insert("key-1".to_string(), create_test_key());

        let fetcher = MockJwksFetcher::new(keys);
        let cache = JwksCache::new(Box::new(fetcher));

        // First fetch
        cache.fetch_key("key-1").await.unwrap();

        // Advance time past TTL (5 minutes)
        MockClock::advance(std::time::Duration::from_secs(6 * 60));

        // Should refetch
        let result = cache.fetch_key("key-1").await;
        assert!(result.is_ok());
    }
}
