//! Batch processing utilities
//!
//! Provides optimized batch operations for database interactions:
//! - Batch INSERT with conflict handling
//! - Parallel validation with controlled concurrency
//! - Chunked processing for large batches

use std::collections::HashSet;
use std::hash::Hash;

use sqlx::{Executor, Postgres};
use uuid::Uuid;

use crate::domain::{StoreId, TenantId};
use super::error::Result;

/// Batch size for SQL operations to avoid exceeding parameter limits
/// PostgreSQL has a limit of ~32k parameters per query
pub const DEFAULT_BATCH_SIZE: usize = 1000;

/// Configuration for batch operations
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Maximum items per batch for SQL operations
    pub batch_size: usize,
    /// Maximum concurrent operations (for parallel processing)
    pub max_concurrency: usize,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_BATCH_SIZE,
            max_concurrency: 4,
        }
    }
}

/// Batch insert command IDs for deduplication
///
/// Uses PostgreSQL's UNNEST for efficient batch insertion.
/// Returns a tuple of (successfully_reserved, duplicates).
pub async fn batch_reserve_command_ids<'e, E>(
    executor: E,
    tenant_id: &TenantId,
    store_id: &StoreId,
    command_ids: &[Uuid],
) -> Result<(HashSet<Uuid>, HashSet<Uuid>)>
where
    E: Executor<'e, Database = Postgres>,
{
    if command_ids.is_empty() {
        return Ok((HashSet::new(), HashSet::new()));
    }

    // PostgreSQL's UNNEST allows us to insert multiple rows in a single query.
    // Use RETURNING to identify which command_ids were newly reserved.
    let cmd_ids: Vec<Uuid> = command_ids.to_vec();

    let inserted_rows: Vec<(Uuid,)> = sqlx::query_as(
        r#"
        INSERT INTO event_command_dedupe (tenant_id, store_id, command_id)
        SELECT $1, $2, unnest($3::uuid[])
        ON CONFLICT DO NOTHING
        RETURNING command_id
        "#,
    )
    .bind(tenant_id.0)
    .bind(store_id.0)
    .bind(&cmd_ids)
    .fetch_all(executor)
    .await?;

    let reserved: HashSet<Uuid> = inserted_rows.into_iter().map(|(id,)| id).collect();
    let duplicates: HashSet<Uuid> = cmd_ids
        .iter()
        .copied()
        .filter(|id| !reserved.contains(id))
        .collect();

    Ok((reserved, duplicates))
}

/// Batch check for existing command IDs
///
/// Returns the set of command IDs that already exist in the database.
pub async fn batch_check_existing_command_ids<'e, E>(
    executor: E,
    tenant_id: &TenantId,
    store_id: &StoreId,
    command_ids: &[Uuid],
) -> Result<HashSet<Uuid>>
where
    E: Executor<'e, Database = Postgres>,
{
    if command_ids.is_empty() {
        return Ok(HashSet::new());
    }

    let cmd_ids: Vec<Uuid> = command_ids.to_vec();

    let rows: Vec<(Uuid,)> = sqlx::query_as(
        r#"
        SELECT command_id
        FROM event_command_dedupe
        WHERE tenant_id = $1
          AND store_id = $2
          AND command_id = ANY($3)
        "#,
    )
    .bind(tenant_id.0)
    .bind(store_id.0)
    .bind(&cmd_ids)
    .fetch_all(executor)
    .await?;

    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Batch check for existing event IDs
///
/// Returns the set of event IDs that already exist in the database.
pub async fn batch_check_existing_event_ids<'e, E>(
    executor: E,
    event_ids: &[Uuid],
) -> Result<HashSet<Uuid>>
where
    E: Executor<'e, Database = Postgres>,
{
    if event_ids.is_empty() {
        return Ok(HashSet::new());
    }

    let ids: Vec<Uuid> = event_ids.to_vec();

    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT event_id FROM events WHERE event_id = ANY($1)",
    )
    .bind(&ids)
    .fetch_all(executor)
    .await?;

    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Process items in chunks to respect batch size limits
pub fn chunked<T: Clone>(items: &[T], chunk_size: usize) -> impl Iterator<Item = Vec<T>> + '_ {
    items.chunks(chunk_size).map(|chunk| chunk.to_vec())
}

/// Deduplicate a slice while preserving order
pub fn dedupe_preserve_order<T: Clone + Eq + Hash>(items: &[T]) -> Vec<T> {
    let mut seen = HashSet::new();
    items
        .iter()
        .filter(|item| seen.insert((*item).clone()))
        .cloned()
        .collect()
}

/// Partition items into chunks for parallel processing
pub fn partition_for_parallel<T: Clone>(items: Vec<T>, num_partitions: usize) -> Vec<Vec<T>> {
    if items.is_empty() || num_partitions == 0 {
        return vec![];
    }

    let chunk_size = items.len().div_ceil(num_partitions);
    items
        .chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect()
}

/// Statistics for batch operations
#[derive(Debug, Default, Clone)]
pub struct BatchStats {
    /// Number of items processed
    pub processed: usize,
    /// Number of items that succeeded
    pub succeeded: usize,
    /// Number of items that failed
    pub failed: usize,
    /// Number of items that were duplicates
    pub duplicates: usize,
    /// Processing time in milliseconds
    pub duration_ms: u64,
}

impl BatchStats {
    pub fn success_rate(&self) -> f64 {
        if self.processed == 0 {
            return 1.0;
        }
        self.succeeded as f64 / self.processed as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunked() {
        let items: Vec<i32> = (0..10).collect();
        let chunks: Vec<Vec<i32>> = chunked(&items, 3).collect();

        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0], vec![0, 1, 2]);
        assert_eq!(chunks[1], vec![3, 4, 5]);
        assert_eq!(chunks[2], vec![6, 7, 8]);
        assert_eq!(chunks[3], vec![9]);
    }

    #[test]
    fn test_dedupe_preserve_order() {
        let items = vec![1, 2, 2, 3, 1, 4, 3, 5];
        let deduped = dedupe_preserve_order(&items);
        assert_eq!(deduped, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_partition_for_parallel() {
        let items: Vec<i32> = (0..10).collect();
        let partitions = partition_for_parallel(items, 3);

        assert_eq!(partitions.len(), 3);
        // Verify all items are present
        let flattened: Vec<i32> = partitions.into_iter().flatten().collect();
        assert_eq!(flattened.len(), 10);
    }

    #[test]
    fn test_partition_empty() {
        let items: Vec<i32> = vec![];
        let partitions = partition_for_parallel(items, 3);
        assert!(partitions.is_empty());
    }

    #[test]
    fn test_batch_stats_success_rate() {
        let stats = BatchStats {
            processed: 100,
            succeeded: 90,
            failed: 5,
            duplicates: 5,
            duration_ms: 100,
        };
        assert!((stats.success_rate() - 0.9).abs() < 0.001);
    }

    #[test]
    fn test_batch_stats_empty() {
        let stats = BatchStats::default();
        assert!((stats.success_rate() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_batch_config_default() {
        let config = BatchConfig::default();
        assert_eq!(config.batch_size, DEFAULT_BATCH_SIZE);
        assert_eq!(config.max_concurrency, 4);
    }
}
