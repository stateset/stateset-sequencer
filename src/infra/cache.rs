//! Caching layer for commitments and proofs
//!
//! Provides in-memory caching with LRU eviction for frequently accessed data:
//! - Recent Merkle roots and commitments
//! - Computed proof paths
//! - Agent public keys
//!
//! Features:
//! - Background refresh for frequently accessed entries (stale-while-revalidate)
//! - TTL-based expiration with configurable refresh thresholds
//! - LRU eviction when capacity is reached

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::crypto::Hash256;
use crate::domain::{BatchCommitment, MerkleProof, Schema, VesBatchCommitment};
use crate::auth::AgentKeyEntry;
#[cfg(test)]
use crate::domain::{StoreId, TenantId};

// ============================================================================
// LRU Cache Implementation
// ============================================================================

/// Configuration for cache refresh behavior
#[derive(Debug, Clone)]
pub struct CacheRefreshConfig {
    /// Percentage of TTL after which to trigger background refresh (0.0-1.0)
    /// e.g., 0.75 means refresh starts when 75% of TTL has elapsed
    pub refresh_threshold: f64,
    /// Whether to enable stale-while-revalidate pattern
    pub stale_while_revalidate: bool,
    /// Maximum age for stale entries (after TTL, entry can still be served for this duration while refreshing)
    pub max_stale_age: Duration,
}

impl Default for CacheRefreshConfig {
    fn default() -> Self {
        Self {
            refresh_threshold: 0.75,
            stale_while_revalidate: true,
            max_stale_age: Duration::from_secs(60),
        }
    }
}

/// A simple LRU cache with TTL support and background refresh
pub struct LruCache<K, V> {
    /// Maximum number of entries
    max_entries: usize,
    /// Time-to-live for entries
    ttl: Duration,
    /// The cache entries
    entries: RwLock<HashMap<K, CacheEntry<V>>>,
    /// Cache statistics
    stats: CacheStats,
    /// Refresh configuration
    refresh_config: CacheRefreshConfig,
    /// Keys currently being refreshed (to prevent duplicate refresh)
    refreshing: RwLock<std::collections::HashSet<K>>,
}

struct CacheEntry<V> {
    value: V,
    created_at: Instant,
    last_accessed: Instant,
    /// Whether this entry is stale but being kept for stale-while-revalidate
    is_stale: bool,
}

/// Cache statistics
#[derive(Default)]
pub struct CacheStats {
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
    expirations: AtomicU64,
    stale_hits: AtomicU64,
    background_refreshes: AtomicU64,
    refresh_failures: AtomicU64,
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

    pub fn stale_hits(&self) -> u64 {
        self.stale_hits.load(Ordering::Relaxed)
    }

    pub fn background_refreshes(&self) -> u64 {
        self.background_refreshes.load(Ordering::Relaxed)
    }

    pub fn refresh_failures(&self) -> u64 {
        self.refresh_failures.load(Ordering::Relaxed)
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
            refresh_config: CacheRefreshConfig::default(),
            refreshing: RwLock::new(std::collections::HashSet::new()),
        }
    }

    /// Create with custom refresh configuration
    pub fn with_refresh_config(
        max_entries: usize,
        ttl: Duration,
        refresh_config: CacheRefreshConfig,
    ) -> Self {
        Self {
            max_entries,
            ttl,
            entries: RwLock::new(HashMap::new()),
            stats: CacheStats::default(),
            refresh_config,
            refreshing: RwLock::new(std::collections::HashSet::new()),
        }
    }

    /// Get a value from the cache
    pub async fn get(&self, key: &K) -> Option<V> {
        let mut entries = self.entries.write().await;

        if let Some(entry) = entries.get_mut(key) {
            let age = entry.created_at.elapsed();

            // Check if completely expired (beyond stale grace period)
            if age > self.ttl + self.refresh_config.max_stale_age {
                entries.remove(key);
                self.stats.expirations.fetch_add(1, Ordering::Relaxed);
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }

            // Check if stale but within grace period (stale-while-revalidate)
            if age > self.ttl {
                if self.refresh_config.stale_while_revalidate {
                    entry.is_stale = true;
                    entry.last_accessed = Instant::now();
                    self.stats.stale_hits.fetch_add(1, Ordering::Relaxed);
                    return Some(entry.value.clone());
                } else {
                    entries.remove(key);
                    self.stats.expirations.fetch_add(1, Ordering::Relaxed);
                    self.stats.misses.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
            }

            // Update last accessed time
            entry.last_accessed = Instant::now();
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            return Some(entry.value.clone());
        }

        self.stats.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Check if an entry needs background refresh
    pub async fn needs_refresh(&self, key: &K) -> bool {
        let entries = self.entries.read().await;

        if let Some(entry) = entries.get(key) {
            let age = entry.created_at.elapsed();
            let refresh_threshold = Duration::from_secs_f64(
                self.ttl.as_secs_f64() * self.refresh_config.refresh_threshold,
            );
            return age >= refresh_threshold && age < self.ttl;
        }

        false
    }

    /// Try to acquire refresh lock for a key
    async fn try_acquire_refresh(&self, key: &K) -> bool
    where
        K: Eq + Hash,
    {
        let mut refreshing = self.refreshing.write().await;
        if refreshing.contains(key) {
            false
        } else {
            refreshing.insert(key.clone());
            true
        }
    }

    /// Release refresh lock for a key
    async fn release_refresh(&self, key: &K)
    where
        K: Eq + Hash,
    {
        let mut refreshing = self.refreshing.write().await;
        refreshing.remove(key);
    }

    /// Try to acquire a refresh lock for a key (used for cache miss stampede protection).
    pub async fn try_acquire_refresh_lock(&self, key: &K) -> bool
    where
        K: Eq + Hash,
    {
        self.try_acquire_refresh(key).await
    }

    /// Release a previously acquired refresh lock.
    pub async fn release_refresh_lock(&self, key: &K)
    where
        K: Eq + Hash,
    {
        self.release_refresh(key).await;
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
                is_stale: false,
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
        let max_age = self.ttl + self.refresh_config.max_stale_age;

        let expired_keys: Vec<K> = entries
            .iter()
            .filter(|(_, e)| e.created_at.elapsed() > max_age)
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired_keys {
            entries.remove(&key);
            self.stats.expirations.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get value with optional background refresh indication
    ///
    /// Returns the cached value (possibly stale) and indicates if a refresh is needed.
    /// The caller can then spawn a background task to refresh if needed.
    pub async fn get_with_refresh_check(&self, key: &K) -> (Option<V>, bool) {
        // First, try to get from cache
        let cached = self.get(key).await;

        // Check if we need to trigger background refresh
        let needs_refresh =
            self.needs_refresh(key).await && self.try_acquire_refresh(key).await;

        if needs_refresh {
            self.stats.background_refreshes.fetch_add(1, Ordering::Relaxed);
        }

        (cached, needs_refresh)
    }

    /// Refresh an entry in the background
    ///
    /// This is typically called when get_or_refresh detects the entry needs refresh.
    /// The caller should spawn this as a background task.
    pub async fn refresh<F, Fut, E>(&self, key: K, refresh_fn: F) -> Result<(), E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, E>>,
    {
        let result = refresh_fn().await;

        match result {
            Ok(value) => {
                self.insert(key.clone(), value).await;
                self.release_refresh(&key).await;
                Ok(())
            }
            Err(e) => {
                self.stats.refresh_failures.fetch_add(1, Ordering::Relaxed);
                self.release_refresh(&key).await;
                Err(e)
            }
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

    /// Get commitment by batch ID with a miss lock for stampede protection.
    pub async fn get_by_batch_id_with_lock(
        &self,
        batch_id: &Uuid,
    ) -> (Option<CachedCommitment>, bool) {
        if let Some(cached) = self.get_by_batch_id(batch_id).await {
            return (Some(cached), false);
        }

        let lock_acquired = self.by_batch_id.try_acquire_refresh_lock(batch_id).await;
        (None, lock_acquired)
    }

    /// Release a batch ID lock.
    pub async fn release_batch_id_lock(&self, batch_id: &Uuid) {
        self.by_batch_id.release_refresh_lock(batch_id).await;
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
        let stream_key = (commitment.tenant_id.0, commitment.store_id.0);
        let should_update = match self.latest_by_stream.get(&stream_key).await {
            Some(existing) => commitment.sequence_range.1 >= existing.commitment.sequence_range.1,
            None => true,
        };
        if should_update {
            self.latest_by_stream.insert(stream_key, cached).await;
        }
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
// VES Commitment Cache
// ============================================================================

/// Cache for VES batch commitments
pub struct VesCommitmentCache {
    /// Commitment by batch ID
    by_batch_id: LruCache<Uuid, VesBatchCommitment>,
    /// Latest commitment by tenant/store
    latest_by_stream: LruCache<(Uuid, Uuid), VesBatchCommitment>,
}

impl VesCommitmentCache {
    /// Create a new VES commitment cache
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            by_batch_id: LruCache::new(max_entries, ttl),
            latest_by_stream: LruCache::new(max_entries / 10, ttl),
        }
    }

    /// Get commitment by batch ID
    pub async fn get_by_batch_id(&self, batch_id: &Uuid) -> Option<VesBatchCommitment> {
        self.by_batch_id.get(batch_id).await
    }

    /// Get commitment by batch ID with a miss lock for stampede protection.
    pub async fn get_by_batch_id_with_lock(
        &self,
        batch_id: &Uuid,
    ) -> (Option<VesBatchCommitment>, bool) {
        if let Some(cached) = self.get_by_batch_id(batch_id).await {
            return (Some(cached), false);
        }

        let lock_acquired = self.by_batch_id.try_acquire_refresh_lock(batch_id).await;
        (None, lock_acquired)
    }

    /// Release a batch ID lock.
    pub async fn release_batch_id_lock(&self, batch_id: &Uuid) {
        self.by_batch_id.release_refresh_lock(batch_id).await;
    }

    /// Get latest commitment for a stream
    pub async fn get_latest(
        &self,
        tenant_id: &Uuid,
        store_id: &Uuid,
    ) -> Option<VesBatchCommitment> {
        self.latest_by_stream.get(&(*tenant_id, *store_id)).await
    }

    /// Get latest commitment with a miss lock for stampede protection.
    pub async fn get_latest_with_lock(
        &self,
        tenant_id: &Uuid,
        store_id: &Uuid,
    ) -> (Option<VesBatchCommitment>, bool) {
        if let Some(cached) = self.get_latest(tenant_id, store_id).await {
            return (Some(cached), false);
        }

        let key = (*tenant_id, *store_id);
        let lock_acquired = self.latest_by_stream.try_acquire_refresh_lock(&key).await;
        (None, lock_acquired)
    }

    /// Release a latest-by-stream lock.
    pub async fn release_latest_lock(&self, tenant_id: &Uuid, store_id: &Uuid) {
        let key = (*tenant_id, *store_id);
        self.latest_by_stream.release_refresh_lock(&key).await;
    }

    /// Insert a VES commitment
    pub async fn insert(&self, commitment: VesBatchCommitment) {
        let batch_id = commitment.batch_id;
        self.by_batch_id.insert(batch_id, commitment.clone()).await;

        let stream_key = (commitment.tenant_id.0, commitment.store_id.0);
        let should_update = match self.latest_by_stream.get(&stream_key).await {
            Some(existing) => commitment.sequence_range.1 >= existing.sequence_range.1,
            None => true,
        };
        if should_update {
            self.latest_by_stream.insert(stream_key, commitment).await;
        }
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

impl Default for VesCommitmentCache {
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

    /// Get a proof with a miss lock for stampede protection.
    pub async fn get_with_lock(
        &self,
        tenant_id: &Uuid,
        store_id: &Uuid,
        sequence_number: u64,
    ) -> (Option<MerkleProof>, bool) {
        let key = ProofCacheKey {
            tenant_id: *tenant_id,
            store_id: *store_id,
            sequence_number,
        };

        if let Some(proof) = self.proofs.get(&key).await {
            return (Some(proof), false);
        }

        let lock_acquired = self.proofs.try_acquire_refresh_lock(&key).await;
        (None, lock_acquired)
    }

    /// Release a previously acquired proof lock.
    pub async fn release_lock(
        &self,
        tenant_id: &Uuid,
        store_id: &Uuid,
        sequence_number: u64,
    ) {
        let key = ProofCacheKey {
            tenant_id: *tenant_id,
            store_id: *store_id,
            sequence_number,
        };
        self.proofs.release_refresh_lock(&key).await;
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

/// Cache for agent public keys
pub struct AgentKeyCache {
    keys: LruCache<AgentKeyCacheKey, AgentKeyEntry>,
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
    ) -> Option<AgentKeyEntry> {
        let key = AgentKeyCacheKey {
            tenant_id: *tenant_id,
            agent_id: *agent_id,
            key_id,
        };
        self.keys.get(&key).await
    }

    /// Get a key with a miss lock for stampede protection.
    pub async fn get_with_lock(
        &self,
        tenant_id: &Uuid,
        agent_id: &Uuid,
        key_id: u32,
    ) -> (Option<AgentKeyEntry>, bool) {
        let key = AgentKeyCacheKey {
            tenant_id: *tenant_id,
            agent_id: *agent_id,
            key_id,
        };

        if let Some(entry) = self.keys.get(&key).await {
            return (Some(entry), false);
        }

        let lock_acquired = self.keys.try_acquire_refresh_lock(&key).await;
        (None, lock_acquired)
    }

    /// Insert an agent key into cache
    pub async fn insert(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        key_id: u32,
        cached_key: AgentKeyEntry,
    ) {
        let key = AgentKeyCacheKey {
            tenant_id,
            agent_id,
            key_id,
        };
        self.keys.insert(key, cached_key).await;
    }

    /// Release a previously acquired lock.
    pub async fn release_lock(&self, tenant_id: &Uuid, agent_id: &Uuid, key_id: u32) {
        let key = AgentKeyCacheKey {
            tenant_id: *tenant_id,
            agent_id: *agent_id,
            key_id,
        };
        self.keys.release_refresh_lock(&key).await;
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
// Schema Cache
// ============================================================================

/// Cache key for schemas
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SchemaCacheKey {
    pub tenant_id: Uuid,
    pub event_type: String,
}

/// Cache for latest schemas
pub struct SchemaCache {
    latest: LruCache<SchemaCacheKey, Schema>,
}

impl SchemaCache {
    /// Create a new schema cache
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            latest: LruCache::new(max_entries, ttl),
        }
    }

    /// Get latest schema from cache
    pub async fn get_latest(&self, tenant_id: &Uuid, event_type: &str) -> Option<Schema> {
        let key = SchemaCacheKey {
            tenant_id: *tenant_id,
            event_type: event_type.to_string(),
        };
        self.latest.get(&key).await
    }

    /// Get latest schema with miss lock for stampede protection
    pub async fn get_latest_with_lock(
        &self,
        tenant_id: &Uuid,
        event_type: &str,
    ) -> (Option<Schema>, bool) {
        let key = SchemaCacheKey {
            tenant_id: *tenant_id,
            event_type: event_type.to_string(),
        };

        if let Some(schema) = self.latest.get(&key).await {
            return (Some(schema), false);
        }

        let lock_acquired = self.latest.try_acquire_refresh_lock(&key).await;
        (None, lock_acquired)
    }

    /// Insert latest schema into cache
    pub async fn insert_latest(&self, schema: Schema) {
        let key = SchemaCacheKey {
            tenant_id: schema.tenant_id.0,
            event_type: schema.event_type.as_str().to_string(),
        };
        self.latest.insert(key, schema).await;
    }

    /// Invalidate latest schema
    pub async fn invalidate_latest(&self, tenant_id: &Uuid, event_type: &str) {
        let key = SchemaCacheKey {
            tenant_id: *tenant_id,
            event_type: event_type.to_string(),
        };
        self.latest.remove(&key).await;
    }

    /// Release a previously acquired lock
    pub async fn release_latest_lock(&self, tenant_id: &Uuid, event_type: &str) {
        let key = SchemaCacheKey {
            tenant_id: *tenant_id,
            event_type: event_type.to_string(),
        };
        self.latest.release_refresh_lock(&key).await;
    }

    /// Get statistics
    pub fn stats(&self) -> &CacheStats {
        self.latest.stats()
    }
}

impl Default for SchemaCache {
    fn default() -> Self {
        Self::new(1000, Duration::from_secs(600)) // 10 minutes TTL
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
    pub commitments: Arc<CommitmentCache>,
    pub ves_commitments: Arc<VesCommitmentCache>,
    pub proofs: Arc<ProofCache>,
    pub ves_proofs: Arc<ProofCache>,
    pub agent_keys: Arc<AgentKeyCache>,
    pub schemas: Arc<SchemaCache>,
}

#[derive(Debug, Clone)]
pub struct CacheManagerConfig {
    pub commitment_max: usize,
    pub commitment_ttl: Duration,
    pub proof_max: usize,
    pub proof_ttl: Duration,
    pub ves_commitment_max: usize,
    pub ves_commitment_ttl: Duration,
    pub ves_proof_max: usize,
    pub ves_proof_ttl: Duration,
    pub agent_key_max: usize,
    pub agent_key_ttl: Duration,
    pub schema_max: usize,
    pub schema_ttl: Duration,
}

impl Default for CacheManagerConfig {
    fn default() -> Self {
        Self {
            commitment_max: 1000,
            commitment_ttl: Duration::from_secs(300),
            proof_max: 5000,
            proof_ttl: Duration::from_secs(600),
            ves_commitment_max: 1000,
            ves_commitment_ttl: Duration::from_secs(300),
            ves_proof_max: 5000,
            ves_proof_ttl: Duration::from_secs(600),
            agent_key_max: 1000,
            agent_key_ttl: Duration::from_secs(3600),
            schema_max: 1000,
            schema_ttl: Duration::from_secs(600),
        }
    }
}

impl CacheManager {
    /// Create a new cache manager with default settings
    pub fn new() -> Self {
        Self {
            commitments: Arc::new(CommitmentCache::default()),
            ves_commitments: Arc::new(VesCommitmentCache::default()),
            proofs: Arc::new(ProofCache::default()),
            ves_proofs: Arc::new(ProofCache::default()),
            agent_keys: Arc::new(AgentKeyCache::default()),
            schemas: Arc::new(SchemaCache::default()),
        }
    }

    /// Create with a configuration struct.
    pub fn with_manager_config(config: CacheManagerConfig) -> Self {
        Self {
            commitments: Arc::new(CommitmentCache::new(
                config.commitment_max,
                config.commitment_ttl,
            )),
            ves_commitments: Arc::new(VesCommitmentCache::new(
                config.ves_commitment_max,
                config.ves_commitment_ttl,
            )),
            proofs: Arc::new(ProofCache::new(config.proof_max, config.proof_ttl)),
            ves_proofs: Arc::new(ProofCache::new(config.ves_proof_max, config.ves_proof_ttl)),
            agent_keys: Arc::new(AgentKeyCache::new(
                config.agent_key_max,
                config.agent_key_ttl,
            )),
            schemas: Arc::new(SchemaCache::new(config.schema_max, config.schema_ttl)),
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
        schema_max: usize,
        schema_ttl: Duration,
    ) -> Self {
        Self::with_manager_config(CacheManagerConfig {
            commitment_max,
            commitment_ttl,
            proof_max,
            proof_ttl,
            ves_commitment_max: commitment_max,
            ves_commitment_ttl: commitment_ttl,
            ves_proof_max: proof_max,
            ves_proof_ttl: proof_ttl,
            agent_key_max,
            agent_key_ttl,
            schema_max,
            schema_ttl,
        })
    }

    /// Clear all caches
    pub async fn clear_all(&self) {
        self.commitments.by_batch_id.clear().await;
        self.commitments.latest_by_stream.clear().await;
        self.ves_commitments.by_batch_id.clear().await;
        self.ves_commitments.latest_by_stream.clear().await;
        self.proofs.proofs.clear().await;
        self.ves_proofs.proofs.clear().await;
        self.agent_keys.keys.clear().await;
        self.schemas.latest.clear().await;
    }

    /// Run cleanup on all caches
    pub async fn cleanup_expired(&self) {
        self.commitments.by_batch_id.cleanup_expired().await;
        self.commitments.latest_by_stream.cleanup_expired().await;
        self.ves_commitments.by_batch_id.cleanup_expired().await;
        self.ves_commitments.latest_by_stream.cleanup_expired().await;
        self.proofs.proofs.cleanup_expired().await;
        self.ves_proofs.proofs.cleanup_expired().await;
        self.agent_keys.keys.cleanup_expired().await;
        self.schemas.latest.cleanup_expired().await;
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
            "ves_commitments": {
                "by_batch_id": {
                    "hits": self.ves_commitments.by_batch_id.stats().hits(),
                    "misses": self.ves_commitments.by_batch_id.stats().misses(),
                    "hit_rate": self.ves_commitments.by_batch_id.stats().hit_rate(),
                    "evictions": self.ves_commitments.by_batch_id.stats().evictions(),
                },
                "latest_by_stream": {
                    "hits": self.ves_commitments.latest_by_stream.stats().hits(),
                    "misses": self.ves_commitments.latest_by_stream.stats().misses(),
                    "hit_rate": self.ves_commitments.latest_by_stream.stats().hit_rate(),
                    "evictions": self.ves_commitments.latest_by_stream.stats().evictions(),
                }
            },
            "proofs": {
                "hits": self.proofs.stats().hits(),
                "misses": self.proofs.stats().misses(),
                "hit_rate": self.proofs.stats().hit_rate(),
                "evictions": self.proofs.stats().evictions(),
            },
            "ves_proofs": {
                "hits": self.ves_proofs.stats().hits(),
                "misses": self.ves_proofs.stats().misses(),
                "hit_rate": self.ves_proofs.stats().hit_rate(),
                "evictions": self.ves_proofs.stats().evictions(),
            },
            "agent_keys": {
                "hits": self.agent_keys.stats().hits(),
                "misses": self.agent_keys.stats().misses(),
                "hit_rate": self.agent_keys.stats().hit_rate(),
                "evictions": self.agent_keys.stats().evictions(),
            },
            "schemas": {
                "hits": self.schemas.stats().hits(),
                "misses": self.schemas.stats().misses(),
                "hit_rate": self.schemas.stats().hit_rate(),
                "evictions": self.schemas.stats().evictions(),
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
        // Use config that disables stale-while-revalidate for predictable TTL testing
        let config = CacheRefreshConfig {
            stale_while_revalidate: false,
            max_stale_age: Duration::ZERO,
            ..Default::default()
        };
        let cache: LruCache<String, i32> =
            LruCache::with_refresh_config(10, Duration::from_millis(50), config);

        cache.insert("key".to_string(), 100).await;
        assert_eq!(cache.get(&"key".to_string()).await, Some(100));

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(cache.get(&"key".to_string()).await, None);
    }

    #[tokio::test]
    async fn test_stale_while_revalidate() {
        let config = CacheRefreshConfig {
            stale_while_revalidate: true,
            max_stale_age: Duration::from_millis(100),
            refresh_threshold: 0.5,
        };
        let cache: LruCache<String, i32> =
            LruCache::with_refresh_config(10, Duration::from_millis(50), config);

        cache.insert("key".to_string(), 100).await;
        assert_eq!(cache.get(&"key".to_string()).await, Some(100));

        // Wait for TTL to expire but within stale grace period
        tokio::time::sleep(Duration::from_millis(75)).await;

        // Should still return the stale value
        assert_eq!(cache.get(&"key".to_string()).await, Some(100));
        assert_eq!(cache.stats().stale_hits(), 1);

        // Wait beyond the max_stale_age
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Now it should be gone
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
        assert!(manager.ves_proofs.proofs.is_empty().await);
        assert!(manager.commitments.by_batch_id.is_empty().await);
        assert!(manager.ves_commitments.by_batch_id.is_empty().await);
        assert!(manager.agent_keys.keys.is_empty().await);

        // Verify stats work
        let stats = manager.stats_json();
        assert!(stats.get("commitments").is_some());
        assert!(stats.get("ves_commitments").is_some());
        assert!(stats.get("proofs").is_some());
        assert!(stats.get("ves_proofs").is_some());
        assert!(stats.get("agent_keys").is_some());
    }
}
