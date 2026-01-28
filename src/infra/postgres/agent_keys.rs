//! PostgreSQL-backed Agent Key Registry
//!
//! Production-ready implementation of the AgentKeyRegistry trait
//! using PostgreSQL for persistent storage.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::auth::{AgentKeyEntry, AgentKeyError, AgentKeyLookup, AgentKeyRegistry, KeyStatus};
use crate::crypto::PublicKey32;
use crate::infra::AgentKeyCache;

/// PostgreSQL-backed agent key registry
pub struct PgAgentKeyRegistry {
    pool: PgPool,
    cache: Option<Arc<AgentKeyCache>>,
}

impl PgAgentKeyRegistry {
    /// Create a new PostgreSQL agent key registry
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            cache: None,
        }
    }

    /// Enable caching for agent key lookups.
    pub fn with_cache(mut self, cache: Arc<AgentKeyCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Initialize the database schema for agent keys
    pub async fn initialize(&self) -> Result<(), AgentKeyError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS agent_signing_keys (
                tenant_id UUID NOT NULL,
                agent_id UUID NOT NULL,
                key_id INTEGER NOT NULL,
                public_key BYTEA NOT NULL,
                status VARCHAR(16) NOT NULL DEFAULT 'active',
                valid_from TIMESTAMPTZ,
                valid_to TIMESTAMPTZ,
                revoked_at TIMESTAMPTZ,
                metadata TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (tenant_id, agent_id, key_id)
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AgentKeyError::Internal(e.to_string()))?;

        // Create indexes for efficient lookup
        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_agent_keys_tenant_agent
            ON agent_signing_keys (tenant_id, agent_id)
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AgentKeyError::Internal(e.to_string()))?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_agent_keys_status
            ON agent_signing_keys (tenant_id, agent_id, status)
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AgentKeyError::Internal(e.to_string()))?;

        Ok(())
    }

    /// Convert database row to AgentKeyEntry
    fn row_to_entry(
        public_key: Vec<u8>,
        status: String,
        valid_from: Option<DateTime<Utc>>,
        valid_to: Option<DateTime<Utc>>,
        revoked_at: Option<DateTime<Utc>>,
        metadata: Option<String>,
        created_at: DateTime<Utc>,
    ) -> Result<AgentKeyEntry, AgentKeyError> {
        let public_key: PublicKey32 = public_key
            .try_into()
            .map_err(|_| AgentKeyError::Internal("invalid public key length".into()))?;

        let status = match status.as_str() {
            "active" => KeyStatus::Active,
            "revoked" => KeyStatus::Revoked,
            "expired" => KeyStatus::Expired,
            _ => KeyStatus::Active,
        };

        Ok(AgentKeyEntry {
            public_key,
            status,
            valid_from,
            valid_to,
            revoked_at,
            metadata,
            created_at,
        })
    }
}

#[async_trait]
impl AgentKeyRegistry for PgAgentKeyRegistry {
    async fn get_key(&self, lookup: &AgentKeyLookup) -> Result<AgentKeyEntry, AgentKeyError> {
        let mut lock_acquired = false;
        if let Some(cache) = &self.cache {
            let (cached, lock) = cache
                .get_with_lock(&lookup.tenant_id, &lookup.agent_id, lookup.key_id)
                .await;
            if let Some(entry) = cached {
                return Ok(entry);
            }
            lock_acquired = lock;
            if !lock_acquired {
                tokio::time::sleep(Duration::from_millis(25)).await;
                if let Some(entry) = cache
                    .get(&lookup.tenant_id, &lookup.agent_id, lookup.key_id)
                    .await
                {
                    return Ok(entry);
                }
            }
        }

        let row: Option<(
            Vec<u8>,
            String,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            Option<String>,
            DateTime<Utc>,
        )> = match sqlx::query_as(
            r#"
            SELECT public_key, status, valid_from, valid_to, revoked_at, metadata, created_at
            FROM agent_signing_keys
            WHERE tenant_id = $1 AND agent_id = $2 AND key_id = $3
            "#,
        )
        .bind(lookup.tenant_id)
        .bind(lookup.agent_id)
        .bind(lookup.key_id as i32)
        .fetch_optional(&self.pool)
        .await
        {
            Ok(row) => row,
            Err(e) => {
                if let Some(cache) = &self.cache {
                    if lock_acquired {
                        cache
                            .release_lock(&lookup.tenant_id, &lookup.agent_id, lookup.key_id)
                            .await;
                    }
                }
                return Err(AgentKeyError::Internal(e.to_string()));
            }
        };

        match row {
            Some((pk, status, valid_from, valid_to, revoked_at, metadata, created_at)) => {
                let entry = match Self::row_to_entry(
                    pk, status, valid_from, valid_to, revoked_at, metadata, created_at,
                ) {
                    Ok(entry) => entry,
                    Err(err) => {
                        if let Some(cache) = &self.cache {
                            if lock_acquired {
                                cache
                                    .release_lock(
                                        &lookup.tenant_id,
                                        &lookup.agent_id,
                                        lookup.key_id,
                                    )
                                    .await;
                            }
                        }
                        return Err(err);
                    }
                };
                if let Some(cache) = &self.cache {
                    cache
                        .insert(
                            lookup.tenant_id,
                            lookup.agent_id,
                            lookup.key_id,
                            entry.clone(),
                        )
                        .await;
                    if lock_acquired {
                        cache
                            .release_lock(&lookup.tenant_id, &lookup.agent_id, lookup.key_id)
                            .await;
                    }
                }
                Ok(entry)
            }
            None => {
                if let Some(cache) = &self.cache {
                    if lock_acquired {
                        cache
                            .release_lock(&lookup.tenant_id, &lookup.agent_id, lookup.key_id)
                            .await;
                    }
                }
                Err(AgentKeyError::KeyNotFound {
                    tenant_id: lookup.tenant_id,
                    agent_id: lookup.agent_id,
                    key_id: lookup.key_id,
                })
            }
        }
    }

    async fn get_valid_key_at(
        &self,
        lookup: &AgentKeyLookup,
        at: DateTime<Utc>,
    ) -> Result<AgentKeyEntry, AgentKeyError> {
        let entry = self.get_key(lookup).await?;

        match entry.status_at(at) {
            KeyStatus::Active => Ok(entry),
            KeyStatus::Revoked => Err(AgentKeyError::KeyRevoked),
            KeyStatus::Expired => Err(AgentKeyError::KeyExpired),
            KeyStatus::NotYetValid => Err(AgentKeyError::KeyNotYetValid),
        }
    }

    async fn register_key(
        &self,
        lookup: &AgentKeyLookup,
        entry: AgentKeyEntry,
    ) -> Result<(), AgentKeyError> {
        let status = match entry.status {
            KeyStatus::Active => "active",
            KeyStatus::Revoked => "revoked",
            KeyStatus::Expired => "expired",
            KeyStatus::NotYetValid => "active", // Will be determined by valid_from
        };

        let result = sqlx::query(
            r#"
            INSERT INTO agent_signing_keys
                (tenant_id, agent_id, key_id, public_key, status, valid_from, valid_to, metadata, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(lookup.tenant_id)
        .bind(lookup.agent_id)
        .bind(lookup.key_id as i32)
        .bind(entry.public_key.as_slice())
        .bind(status)
        .bind(entry.valid_from)
        .bind(entry.valid_to)
        .bind(&entry.metadata)
        .bind(entry.created_at)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => {
                if let Some(cache) = &self.cache {
                    cache
                        .insert(
                            lookup.tenant_id,
                            lookup.agent_id,
                            lookup.key_id,
                            entry.clone(),
                        )
                        .await;
                }
                Ok(())
            }
            Err(e) if e.to_string().contains("duplicate key") => {
                Err(AgentKeyError::KeyAlreadyExists)
            }
            Err(e) => Err(AgentKeyError::Internal(e.to_string())),
        }
    }

    async fn revoke_key(&self, lookup: &AgentKeyLookup) -> Result<(), AgentKeyError> {
        let result = sqlx::query(
            r#"
            UPDATE agent_signing_keys
            SET status = 'revoked', revoked_at = NOW()
            WHERE tenant_id = $1 AND agent_id = $2 AND key_id = $3
            "#,
        )
        .bind(lookup.tenant_id)
        .bind(lookup.agent_id)
        .bind(lookup.key_id as i32)
        .execute(&self.pool)
        .await
        .map_err(|e| AgentKeyError::Internal(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AgentKeyError::KeyNotFound {
                tenant_id: lookup.tenant_id,
                agent_id: lookup.agent_id,
                key_id: lookup.key_id,
            });
        }

        if let Some(cache) = &self.cache {
            cache
                .invalidate(&lookup.tenant_id, &lookup.agent_id, lookup.key_id)
                .await;
        }

        Ok(())
    }

    async fn list_agent_keys(
        &self,
        tenant_id: &Uuid,
        agent_id: &Uuid,
    ) -> Result<Vec<(u32, AgentKeyEntry)>, AgentKeyError> {
        let rows: Vec<(
            i32,
            Vec<u8>,
            String,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            Option<String>,
            DateTime<Utc>,
        )> = sqlx::query_as(
            r#"
            SELECT key_id, public_key, status, valid_from, valid_to, revoked_at, metadata, created_at
            FROM agent_signing_keys
            WHERE tenant_id = $1 AND agent_id = $2
            ORDER BY key_id ASC
            "#,
        )
        .bind(tenant_id)
        .bind(agent_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AgentKeyError::Internal(e.to_string()))?;

        let mut result = Vec::with_capacity(rows.len());
        for (key_id, pk, status, valid_from, valid_to, revoked_at, metadata, created_at) in rows {
            let entry = Self::row_to_entry(
                pk, status, valid_from, valid_to, revoked_at, metadata, created_at,
            )?;
            result.push((key_id as u32, entry));
        }

        Ok(result)
    }
}

/// Extension methods for PgAgentKeyRegistry
impl PgAgentKeyRegistry {
    /// Get the next available key_id for an agent
    pub async fn next_key_id(
        &self,
        tenant_id: &Uuid,
        agent_id: &Uuid,
    ) -> Result<u32, AgentKeyError> {
        let row: Option<(i32,)> = sqlx::query_as(
            r#"
            SELECT MAX(key_id) FROM agent_signing_keys
            WHERE tenant_id = $1 AND agent_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(agent_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AgentKeyError::Internal(e.to_string()))?;

        Ok(row.map(|r| r.0 as u32 + 1).unwrap_or(1))
    }

    /// Get all active keys for an agent
    pub async fn get_active_keys(
        &self,
        tenant_id: &Uuid,
        agent_id: &Uuid,
    ) -> Result<Vec<(u32, AgentKeyEntry)>, AgentKeyError> {
        let now = Utc::now();
        let all_keys = self.list_agent_keys(tenant_id, agent_id).await?;

        Ok(all_keys
            .into_iter()
            .filter(|(_, entry)| entry.status_at(now) == KeyStatus::Active)
            .collect())
    }

    /// Rotate agent key - creates new key and returns the key_id
    pub async fn rotate_key(
        &self,
        tenant_id: &Uuid,
        agent_id: &Uuid,
        new_public_key: PublicKey32,
    ) -> Result<u32, AgentKeyError> {
        let key_id = self.next_key_id(tenant_id, agent_id).await?;

        let lookup = AgentKeyLookup {
            tenant_id: *tenant_id,
            agent_id: *agent_id,
            key_id,
        };

        let entry = AgentKeyEntry::new(new_public_key);
        self.register_key(&lookup, entry).await?;

        Ok(key_id)
    }
}

#[cfg(test)]
mod tests {
    // Integration tests would require a PostgreSQL instance
    // See tests/agent_keys_integration_test.rs
}
