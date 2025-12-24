//! Caching layer for commitments and proofs
//!
//! Provides in-memory caching with LRU eviction for frequently accessed data:
//! - Recent Merkle roots and commitments
//! - Computed proof paths
//! - Agent public keys

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::crypto::Hash256;
use crate::domain::{BatchCommitment, MerkleProof};
#[cfg(test)]
use crate::domain::{StoreId, TenantId};

// ============================================================================
// LRU Cache Implementation
// ============================================================================

/// A simple LRU cache with TTL support
pub struct LruCache<K, V> {
    /// Maximum number of entries
    max_entries: usize,
    /// Time-to-live for entries
    ttl: Duration,
    /// The cache entries
    entries: RwLock<HashMap<K, CacheEntry<V>>>,
    /// Cache statistics
    stats: CacheStats,
}

struct CacheEntry<V> {
    value: V,
    created_at: Instant,
    last_accessed: Instant,
}

/// Cache statistics
#[derive(Default)]
pub struct CacheStats {
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
    expirations: AtomicU64,
}

impl CacheStats {
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    pub fn evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    pub fn expirations(&self) -> u64 {
        self.expirations.load(Ordering::Relaxed)
    }

    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits() as f64;
        let total = hits + self.misses() as f64;
        if total > 0.0 {
            hits / total
        } else {
            0.0
        }
    }
}

impl<K, V> LruCache<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    /// Create a new LRU cache
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            max_entries,
            ttl,
            entries: RwLock::new(HashMap::new()),
            stats: CacheStats::default(),
        }
    }

    /// Get a value from the cache
    pub async fn get(&self, key: &K) -> Option<V> {
        let mut entries = self.entries.write().await;

        if let Some(entry) = entries.get_mut(key) {
            // Check if expired
            if entry.created_at.elapsed() > self.ttl {
                entries.remove(key);
                self.stats.expirations.fetch_add(1, Ordering::Relaxed);
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }

            // Update last accessed time
            entry.last_accessed = Instant::now();
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            return Some(entry.value.clone());
        }

        self.stats.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Insert a value into the cache
    pub async fn insert(&self, key: K, value: V) {
        let mut entries = self.entries.write().await;

        // Evict oldest entries if at capacity
        if entries.len() >= self.max_entries && !entries.contains_key(&key) {
            self.evict_oldest(&mut entries);
        }

        let now = Instant::now();
        entries.insert(
            key,
            CacheEntry {
                value,
                created_at: now,
                last_accessed: now,
            },
        );
    }

    /// Remove a value from the cache
    pub async fn remove(&self, key: &K) -> Option<V> {
        let mut entries = self.entries.write().await;
        entries.remove(key).map(|e| e.value)
    }

    /// Clear all entries
    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
    }

    /// Get the number of entries
    pub async fn len(&self) -> usize {
        let entries = self.entries.read().await;
        entries.len()
    }

    /// Check if the cache is empty
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Get cache statistics
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }

    /// Evict the oldest entry
    fn evict_oldest(&self, entries: &mut HashMap<K, CacheEntry<V>>) {
        if let Some(oldest_key) = entries
            .iter()
            .min_by_key(|(_, e)| e.last_accessed)
            .map(|(k, _)| k.clone())
        {
            entries.remove(&oldest_key);
            self.stats.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Remove expired entries
    pub async fn cleanup_expired(&self) {
        let mut entries = self.entries.write().await;
        let now = Instant::now();

        let expired_keys: Vec<K> = entries
            .iter()
            .filter(|(_, e)| now.duration_since(e.created_at) > self.ttl)
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired_keys {
            entries.remove(&key);
            self.stats.expirations.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ============================================================================
// Commitment Cache
// ============================================================================

/// Cache key for commitments
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[allow(dead_code)]
pub struct CommitmentCacheKey {
    pub tenant_id: Uuid,
    pub store_id: Uuid,
    pub batch_id: Uuid,
}

/// Cached commitment data
#[derive(Debug, Clone)]
pub struct CachedCommitment {
    pub commitment: BatchCommitment,
    pub merkle_root: Hash256,
}

/// Cache for batch commitments
pub struct CommitmentCache {
    /// Commitment by batch ID
    by_batch_id: LruCache<Uuid, CachedCommitment>,
    /// Latest commitment by tenant/store
    latest_by_stream: LruCache<(Uuid, Uuid), CachedCommitment>,
}

impl CommitmentCache {
    /// Create a new commitment cache
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            by_batch_id: LruCache::new(max_entries, ttl),
            latest_by_stream: LruCache::new(max_entries / 10, ttl),
        }
    }

    /// Get commitment by batch ID
    pub async fn get_by_batch_id(&self, batch_id: &Uuid) -> Option<CachedCommitment> {
        self.by_batch_id.get(batch_id).await
    }

    /// Get latest commitment for a stream
    pub async fn get_latest(&self, tenant_id: &Uuid, store_id: &Uuid) -> Option<CachedCommitment> {
        self.latest_by_stream.get(&(*tenant_id, *store_id)).await
    }

    /// Insert a commitment
    pub async fn insert(&self, commitment: BatchCommitment, merkle_root: Hash256) {
        let cached = CachedCommitment {
            commitment: commitment.clone(),
            merkle_root,
        };

        self.by_batch_id
            .insert(commitment.batch_id, cached.clone())
            .await;
        self.latest_by_stream
            .insert((commitment.tenant_id.0, commitment.store_id.0), cached)
            .await;
    }

    /// Invalidate commitment
    pub async fn invalidate(&self, batch_id: &Uuid) {
        self.by_batch_id.remove(batch_id).await;
    }

    /// Get statistics
    pub fn stats(&self) -> CacheStatsSummary {
        CacheStatsSummary {
            by_batch_id_hits: self.by_batch_id.stats().hits(),
            by_batch_id_misses: self.by_batch_id.stats().misses(),
            latest_by_stream_hits: self.latest_by_stream.stats().hits(),
            latest_by_stream_misses: self.latest_by_stream.stats().misses(),
        }
    }
}

impl Default for CommitmentCache {
    fn default() -> Self {
        Self::new(1000, Duration::from_secs(300)) // 5 minutes TTL
    }
}

// ============================================================================
// Proof Cache
// ============================================================================

/// Cache key for Merkle proofs
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ProofCacheKey {
    pub tenant_id: Uuid,
    pub store_id: Uuid,
    pub sequence_number: u64,
}

/// Cache for Merkle proofs
pub struct ProofCache {
    proofs: LruCache<ProofCacheKey, MerkleProof>,
}

impl ProofCache {
    /// Create a new proof cache
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            proofs: LruCache::new(max_entries, ttl),
        }
    }

    /// Get a proof from cache
    pub async fn get(
        &self,
        tenant_id: &Uuid,
        store_id: &Uuid,
        sequence_number: u64,
    ) -> Option<MerkleProof> {
        let key = ProofCacheKey {
            tenant_id: *tenant_id,
            store_id: *store_id,
            sequence_number,
        };
        self.proofs.get(&key).await
    }

    /// Insert a proof into cache
    pub async fn insert(
        &self,
        tenant_id: Uuid,
        store_id: Uuid,
        sequence_number: u64,
        proof: MerkleProof,
    ) {
        let key = ProofCacheKey {
            tenant_id,
            store_id,
            sequence_number,
        };
        self.proofs.insert(key, proof).await;
    }

    /// Get statistics
    pub fn stats(&self) -> &CacheStats {
        self.proofs.stats()
    }
}

impl Default for ProofCache {
    fn default() -> Self {
        Self::new(5000, Duration::from_secs(600)) // 10 minutes TTL
    }
}

// ============================================================================
// Agent Key Cache
// ============================================================================

/// Cache key for agent keys
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct AgentKeyCacheKey {
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
    pub key_id: u32,
}

/// Cached agent key
#[derive(Debug, Clone)]
pub struct CachedAgentKey {
    pub public_key: [u8; 32],
    pub algorithm: String,
    pub active: bool,
}

/// Cache for agent public keys
pub struct AgentKeyCache {
    keys: LruCache<AgentKeyCacheKey, CachedAgentKey>,
}

impl AgentKeyCache {
    /// Create a new agent key cache
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            keys: LruCache::new(max_entries, ttl),
        }
    }

    /// Get an agent key from cache
    pub async fn get(
        &self,
        tenant_id: &Uuid,
        agent_id: &Uuid,
        key_id: u32,
    ) -> Option<CachedAgentKey> {
        let key = AgentKeyCacheKey {
            tenant_id: *tenant_id,
            agent_id: *agent_id,
            key_id,
        };
        self.keys.get(&key).await
    }

    /// Insert an agent key into cache
    pub async fn insert(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        key_id: u32,
        cached_key: CachedAgentKey,
    ) {
        let key = AgentKeyCacheKey {
            tenant_id,
            agent_id,
            key_id,
        };
        self.keys.insert(key, cached_key).await;
    }

    /// Invalidate a specific key
    pub async fn invalidate(&self, tenant_id: &Uuid, agent_id: &Uuid, key_id: u32) {
        let key = AgentKeyCacheKey {
            tenant_id: *tenant_id,
            agent_id: *agent_id,
            key_id,
        };
        self.keys.remove(&key).await;
    }

    /// Get statistics
    pub fn stats(&self) -> &CacheStats {
        self.keys.stats()
    }
}

impl Default for AgentKeyCache {
    fn default() -> Self {
        Self::new(1000, Duration::from_secs(3600)) // 1 hour TTL
    }
}

// ============================================================================
// Combined Cache Manager
// ============================================================================

/// Statistics summary for all caches
#[derive(Debug, Clone, Default)]
pub struct CacheStatsSummary {
    pub by_batch_id_hits: u64,
    pub by_batch_id_misses: u64,
    pub latest_by_stream_hits: u64,
    pub latest_by_stream_misses: u64,
}

/// Combined cache manager for all caches
pub struct CacheManager {
    pub commitments: CommitmentCache,
    pub proofs: ProofCache,
    pub agent_keys: AgentKeyCache,
}

impl CacheManager {
    /// Create a new cache manager with default settings
    pub fn new() -> Self {
        Self {
            commitments: CommitmentCache::default(),
            proofs: ProofCache::default(),
            agent_keys: AgentKeyCache::default(),
        }
    }

    /// Create with custom settings
    pub fn with_config(
        commitment_max: usize,
        commitment_ttl: Duration,
        proof_max: usize,
        proof_ttl: Duration,
        agent_key_max: usize,
        agent_key_ttl: Duration,
    ) -> Self {
        Self {
            commitments: CommitmentCache::new(commitment_max, commitment_ttl),
            proofs: ProofCache::new(proof_max, proof_ttl),
            agent_keys: AgentKeyCache::new(agent_key_max, agent_key_ttl),
        }
    }

    /// Clear all caches
    pub async fn clear_all(&self) {
        self.commitments.by_batch_id.clear().await;
        self.commitments.latest_by_stream.clear().await;
        self.proofs.proofs.clear().await;
        self.agent_keys.keys.clear().await;
    }

    /// Run cleanup on all caches
    pub async fn cleanup_expired(&self) {
        self.commitments.by_batch_id.cleanup_expired().await;
        self.commitments.latest_by_stream.cleanup_expired().await;
        self.proofs.proofs.cleanup_expired().await;
        self.agent_keys.keys.cleanup_expired().await;
    }

    /// Get combined statistics as JSON
    pub fn stats_json(&self) -> serde_json::Value {
        serde_json::json!({
            "commitments": {
                "by_batch_id": {
                    "hits": self.commitments.by_batch_id.stats().hits(),
                    "misses": self.commitments.by_batch_id.stats().misses(),
                    "hit_rate": self.commitments.by_batch_id.stats().hit_rate(),
                    "evictions": self.commitments.by_batch_id.stats().evictions(),
                },
                "latest_by_stream": {
                    "hits": self.commitments.latest_by_stream.stats().hits(),
                    "misses": self.commitments.latest_by_stream.stats().misses(),
                    "hit_rate": self.commitments.latest_by_stream.stats().hit_rate(),
                    "evictions": self.commitments.latest_by_stream.stats().evictions(),
                }
            },
            "proofs": {
                "hits": self.proofs.stats().hits(),
                "misses": self.proofs.stats().misses(),
                "hit_rate": self.proofs.stats().hit_rate(),
                "evictions": self.proofs.stats().evictions(),
            },
            "agent_keys": {
                "hits": self.agent_keys.stats().hits(),
                "misses": self.agent_keys.stats().misses(),
                "hit_rate": self.agent_keys.stats().hit_rate(),
                "evictions": self.agent_keys.stats().evictions(),
            }
        })
    }
}

impl Default for CacheManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_lru_cache_basic() {
        let cache: LruCache<String, i32> = LruCache::new(10, Duration::from_secs(60));

        cache.insert("key1".to_string(), 100).await;
        cache.insert("key2".to_string(), 200).await;

        assert_eq!(cache.get(&"key1".to_string()).await, Some(100));
        assert_eq!(cache.get(&"key2".to_string()).await, Some(200));
        assert_eq!(cache.get(&"key3".to_string()).await, None);
    }

    #[tokio::test]
    async fn test_lru_cache_eviction() {
        let cache: LruCache<i32, i32> = LruCache::new(3, Duration::from_secs(60));

        cache.insert(1, 100).await;
        cache.insert(2, 200).await;
        cache.insert(3, 300).await;

        // Access key 1 to make it recently used
        cache.get(&1).await;

        // Insert key 4, should evict key 2 (oldest accessed)
        cache.insert(4, 400).await;

        assert_eq!(cache.get(&1).await, Some(100)); // Still present
        assert_eq!(cache.get(&2).await, None); // Evicted
        assert_eq!(cache.get(&3).await, Some(300)); // Still present
        assert_eq!(cache.get(&4).await, Some(400)); // Just inserted
    }

    #[tokio::test]
    async fn test_lru_cache_ttl() {
        let cache: LruCache<String, i32> = LruCache::new(10, Duration::from_millis(50));

        cache.insert("key".to_string(), 100).await;
        assert_eq!(cache.get(&"key".to_string()).await, Some(100));

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(cache.get(&"key".to_string()).await, None);
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache: LruCache<String, i32> = LruCache::new(10, Duration::from_secs(60));

        cache.insert("key".to_string(), 100).await;

        // Hit
        cache.get(&"key".to_string()).await;
        cache.get(&"key".to_string()).await;

        // Miss
        cache.get(&"missing".to_string()).await;

        assert_eq!(cache.stats().hits(), 2);
        assert_eq!(cache.stats().misses(), 1);
        assert!((cache.stats().hit_rate() - 0.666).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_commitment_cache() {
        let cache = CommitmentCache::default();

        let commitment = BatchCommitment {
            batch_id: Uuid::new_v4(),
            tenant_id: TenantId::from_uuid(Uuid::new_v4()),
            store_id: StoreId::from_uuid(Uuid::new_v4()),
            prev_state_root: [0u8; 32],
            new_state_root: [1u8; 32],
            events_root: [2u8; 32],
            event_count: 10,
            sequence_range: (1, 10),
            committed_at: chrono::Utc::now(),
            chain_tx_hash: None,
        };

        let merkle_root = [3u8; 32];

        cache.insert(commitment.clone(), merkle_root).await;

        let cached = cache.get_by_batch_id(&commitment.batch_id).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().merkle_root, merkle_root);
    }

    #[tokio::test]
    async fn test_proof_cache() {
        let cache = ProofCache::default();

        let tenant_id = Uuid::new_v4();
        let store_id = Uuid::new_v4();
        let proof = MerkleProof::new([1u8; 32], vec![[2u8; 32]], 0);

        cache.insert(tenant_id, store_id, 42, proof.clone()).await;

        let cached = cache.get(&tenant_id, &store_id, 42).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().leaf_index, proof.leaf_index);
    }

    #[tokio::test]
    async fn test_cache_manager() {
        let manager = CacheManager::new();

        // Verify all caches are initialized
        assert!(manager.proofs.proofs.is_empty().await);
        assert!(manager.commitments.by_batch_id.is_empty().await);
        assert!(manager.agent_keys.keys.is_empty().await);

        // Verify stats work
        let stats = manager.stats_json();
        assert!(stats.get("commitments").is_some());
        assert!(stats.get("proofs").is_some());
        assert!(stats.get("agent_keys").is_some());
    }
}
