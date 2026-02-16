//! Admin dashboard handlers.

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Serialize;
use tracing::{instrument, warn};
use uuid::Uuid;

use crate::api::types::{
    AdminAgentSummary, AdminOverviewResponse, AdminStoreSummary, AdminTenantSummary,
};
use crate::auth::AuthContextExt;
use crate::server::AppState;

const DASHBOARD_HTML: &str = include_str!("../../admin/dashboard.html");

/// Hard max for admin list endpoints to prevent unbounded responses.
const MAX_ADMIN_LIST_RESULTS: usize = 200;

/// GET /admin - Admin dashboard UI.
#[instrument]
pub async fn admin_dashboard() -> impl IntoResponse {
    Html(DASHBOARD_HTML)
}

fn admin_scope(
    auth: &crate::auth::AuthContext,
) -> Result<Option<Uuid>, (StatusCode, Json<serde_json::Value>)> {
    if !auth.is_admin() {
        return Err(admin_error(
            StatusCode::FORBIDDEN,
            "Admin permission required",
            "FORBIDDEN",
        ));
    }

    if auth.tenant_id.is_nil() {
        Ok(None)
    } else {
        Ok(Some(auth.tenant_id))
    }
}

fn admin_error(
    status: StatusCode,
    message: &str,
    code: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(serde_json::json!({
            "success": false,
            "error": message,
            "code": code
        })),
    )
}

fn to_rfc3339(ts: Option<DateTime<Utc>>) -> Option<String> {
    ts.map(|value| value.to_rfc3339())
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct TenantRow {
    tenant_id: Uuid,
    agent_count: i64,
    api_key_count: i64,
    active_api_keys: i64,
    store_count: i64,
    total_head_sequence: i64,
    active_stores_24h: i64,
    max_projection_lag: i64,
    last_key_at: Option<DateTime<Utc>>,
    last_activity_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct StoreRow {
    tenant_id: Uuid,
    store_id: Uuid,
    current_sequence: i64,
    updated_at: DateTime<Utc>,
    last_projected_sequence: Option<i64>,
    projection_lag: i64,
    agent_count: i64,
    last_agent_sync_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct AgentRow {
    tenant_id: Uuid,
    agent_id: Uuid,
    has_admin: bool,
    has_write: bool,
    has_global_store_access: bool,
    api_key_count: i64,
    active_api_keys: i64,
    first_key_at: Option<DateTime<Utc>>,
    last_key_at: Option<DateTime<Utc>>,
    store_id: Option<Uuid>,
    last_sync_at: Option<DateTime<Utc>>,
    last_pushed_sequence: Option<i64>,
    last_pulled_sequence: Option<i64>,
}

async fn count_with_tenant(
    pool: &sqlx::PgPool,
    query: &str,
    tenant_id: Option<Uuid>,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(query)
        .bind(tenant_id)
        .fetch_one(pool)
        .await
}

async fn table_exists(pool: &sqlx::PgPool, table: &str) -> Result<bool, sqlx::Error> {
    let result: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(table)
        .fetch_one(pool)
        .await?;
    Ok(result)
}

/// GET /api/v1/admin/overview - Summary counts for the admin dashboard.
#[instrument(skip(state, auth))]
pub async fn admin_overview(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
) -> Result<Json<AdminOverviewResponse>, (StatusCode, Json<serde_json::Value>)> {
    let tenant_scope = admin_scope(&auth)?;
    let pool = &state.read_pool;

    let tenants = count_with_tenant(
        pool,
        "SELECT COUNT(DISTINCT tenant_id) FROM api_keys WHERE ($1::uuid IS NULL OR tenant_id = $1)",
        tenant_scope,
    )
    .await
    .map_err(|_| {
        admin_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Query failed",
            "DB_ERROR",
        )
    })?;

    let stores = count_with_tenant(
        pool,
        "SELECT COUNT(*) FROM sequence_counters WHERE ($1::uuid IS NULL OR tenant_id = $1)",
        tenant_scope,
    )
    .await
    .map_err(|_| {
        admin_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Query failed",
            "DB_ERROR",
        )
    })?;

    let agents = count_with_tenant(
        pool,
        "SELECT COUNT(DISTINCT agent_id) FROM api_keys WHERE agent_id IS NOT NULL AND ($1::uuid IS NULL OR tenant_id = $1)",
        tenant_scope,
    )
    .await
    .map_err(|_| admin_error(StatusCode::INTERNAL_SERVER_ERROR, "Query failed", "DB_ERROR"))?;

    let api_keys = count_with_tenant(
        pool,
        "SELECT COUNT(*) FROM api_keys WHERE ($1::uuid IS NULL OR tenant_id = $1)",
        tenant_scope,
    )
    .await
    .map_err(|_| {
        admin_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Query failed",
            "DB_ERROR",
        )
    })?;

    let active_api_keys = count_with_tenant(
        pool,
        "SELECT COUNT(*) FROM api_keys WHERE active = TRUE AND ($1::uuid IS NULL OR tenant_id = $1)",
        tenant_scope,
    )
    .await
    .map_err(|_| admin_error(StatusCode::INTERNAL_SERVER_ERROR, "Query failed", "DB_ERROR"))?;

    let last_activity_at: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT MAX(updated_at) FROM sequence_counters WHERE ($1::uuid IS NULL OR tenant_id = $1)",
    )
    .bind(tenant_scope)
    .fetch_one(pool)
    .await
    .map_err(|_| {
        admin_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Query failed",
            "DB_ERROR",
        )
    })?;

    let projection_available = match table_exists(pool, "public.projection_checkpoints").await {
        Ok(value) => value,
        Err(err) => {
            warn!("Admin overview table check failed: {}", err);
            false
        }
    };

    let total_head_sequence = match count_with_tenant(
        pool,
        "SELECT COALESCE(SUM(current_sequence), 0)::bigint FROM sequence_counters WHERE ($1::uuid IS NULL OR tenant_id = $1)",
        tenant_scope,
    )
    .await
    {
        Ok(value) => value,
        Err(err) => {
            warn!("Admin overview total head sequence failed: {}", err);
            0
        }
    };

    let active_stores_24h = match count_with_tenant(
        pool,
        "SELECT COUNT(*) FROM sequence_counters WHERE updated_at >= NOW() - INTERVAL '24 hours' AND ($1::uuid IS NULL OR tenant_id = $1)",
        tenant_scope,
    )
    .await
    {
        Ok(value) => value,
        Err(err) => {
            warn!("Admin overview active stores failed: {}", err);
            0
        }
    };

    let max_projection_lag: i64 = if projection_available {
        match sqlx::query_scalar(
            "SELECT COALESCE(MAX(sc.current_sequence::bigint - COALESCE(pc.last_projected_sequence, 0)::bigint), 0)\n         FROM sequence_counters sc\n         LEFT JOIN projection_checkpoints pc\n           ON pc.tenant_id = sc.tenant_id AND pc.store_id = sc.store_id\n         WHERE ($1::uuid IS NULL OR sc.tenant_id = $1)",
        )
        .bind(tenant_scope)
        .fetch_one(pool)
        .await
        {
            Ok(value) => value,
            Err(err) => {
                warn!("Admin overview projection lag failed: {}", err);
                0
            }
        }
    } else {
        0
    };

    Ok(Json(AdminOverviewResponse {
        tenants: tenants.max(0) as u64,
        stores: stores.max(0) as u64,
        agents: agents.max(0) as u64,
        api_keys: api_keys.max(0) as u64,
        active_api_keys: active_api_keys.max(0) as u64,
        total_head_sequence: total_head_sequence.max(0) as u64,
        active_stores_24h: active_stores_24h.max(0) as u64,
        max_projection_lag: max_projection_lag.max(0) as u64,
        last_activity_at: to_rfc3339(last_activity_at),
    }))
}

/// GET /api/v1/admin/tenants - Tenant summary list.
#[instrument(skip(state, auth))]
pub async fn admin_tenants(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
) -> Result<Json<Vec<AdminTenantSummary>>, (StatusCode, Json<serde_json::Value>)> {
    let tenant_scope = admin_scope(&auth)?;
    let projection_available =
        match table_exists(&state.read_pool, "public.projection_checkpoints").await {
            Ok(value) => value,
            Err(err) => {
                warn!("Admin tenants table check failed: {}", err);
                false
            }
        };

    let query = if projection_available {
        r#"
        SELECT
            t.tenant_id,
            COALESCE(a.agent_count, 0) AS agent_count,
            COALESCE(k.api_key_count, 0) AS api_key_count,
            COALESCE(k.active_api_keys, 0) AS active_api_keys,
            COALESCE(s.store_count, 0) AS store_count,
            COALESCE(s.total_head_sequence, 0) AS total_head_sequence,
            COALESCE(s.active_stores_24h, 0) AS active_stores_24h,
            COALESCE(s.max_projection_lag, 0) AS max_projection_lag,
            k.last_key_at,
            s.last_activity_at
        FROM (
            SELECT DISTINCT tenant_id
            FROM api_keys
            WHERE ($1::uuid IS NULL OR tenant_id = $1)
        ) t
        LEFT JOIN (
            SELECT tenant_id, COUNT(DISTINCT agent_id) AS agent_count
            FROM api_keys
            WHERE agent_id IS NOT NULL AND ($1::uuid IS NULL OR tenant_id = $1)
            GROUP BY tenant_id
        ) a ON t.tenant_id = a.tenant_id
        LEFT JOIN (
            SELECT tenant_id,
                   COUNT(*) AS api_key_count,
                   COUNT(*) FILTER (WHERE active) AS active_api_keys,
                   MAX(updated_at) AS last_key_at
            FROM api_keys
            WHERE ($1::uuid IS NULL OR tenant_id = $1)
            GROUP BY tenant_id
        ) k ON t.tenant_id = k.tenant_id
        LEFT JOIN (
            SELECT sc.tenant_id,
                   COUNT(*) AS store_count,
                   SUM(sc.current_sequence)::bigint AS total_head_sequence,
                   COUNT(*) FILTER (WHERE sc.updated_at >= NOW() - INTERVAL '24 hours') AS active_stores_24h,
                   MAX(sc.updated_at) AS last_activity_at,
                   MAX(sc.current_sequence::bigint - COALESCE(pc.last_projected_sequence, 0)::bigint) AS max_projection_lag
            FROM sequence_counters sc
            LEFT JOIN projection_checkpoints pc
              ON pc.tenant_id = sc.tenant_id
             AND pc.store_id = sc.store_id
            WHERE ($1::uuid IS NULL OR sc.tenant_id = $1)
            GROUP BY sc.tenant_id
        ) s ON t.tenant_id = s.tenant_id
        ORDER BY k.last_key_at DESC NULLS LAST
        "#
    } else {
        r#"
        SELECT
            t.tenant_id,
            COALESCE(a.agent_count, 0) AS agent_count,
            COALESCE(k.api_key_count, 0) AS api_key_count,
            COALESCE(k.active_api_keys, 0) AS active_api_keys,
            COALESCE(s.store_count, 0) AS store_count,
            COALESCE(s.total_head_sequence, 0) AS total_head_sequence,
            COALESCE(s.active_stores_24h, 0) AS active_stores_24h,
            0::bigint AS max_projection_lag,
            k.last_key_at,
            s.last_activity_at
        FROM (
            SELECT DISTINCT tenant_id
            FROM api_keys
            WHERE ($1::uuid IS NULL OR tenant_id = $1)
        ) t
        LEFT JOIN (
            SELECT tenant_id, COUNT(DISTINCT agent_id) AS agent_count
            FROM api_keys
            WHERE agent_id IS NOT NULL AND ($1::uuid IS NULL OR tenant_id = $1)
            GROUP BY tenant_id
        ) a ON t.tenant_id = a.tenant_id
        LEFT JOIN (
            SELECT tenant_id,
                   COUNT(*) AS api_key_count,
                   COUNT(*) FILTER (WHERE active) AS active_api_keys,
                   MAX(updated_at) AS last_key_at
            FROM api_keys
            WHERE ($1::uuid IS NULL OR tenant_id = $1)
            GROUP BY tenant_id
        ) k ON t.tenant_id = k.tenant_id
        LEFT JOIN (
            SELECT sc.tenant_id,
                   COUNT(*) AS store_count,
                   SUM(sc.current_sequence)::bigint AS total_head_sequence,
                   COUNT(*) FILTER (WHERE sc.updated_at >= NOW() - INTERVAL '24 hours') AS active_stores_24h,
                   MAX(sc.updated_at) AS last_activity_at
            FROM sequence_counters sc
            WHERE ($1::uuid IS NULL OR sc.tenant_id = $1)
            GROUP BY sc.tenant_id
        ) s ON t.tenant_id = s.tenant_id
        ORDER BY k.last_key_at DESC NULLS LAST
        "#
    };

    let rows: Vec<TenantRow> = match sqlx::query_as(query)
        .bind(tenant_scope)
        .fetch_all(&state.read_pool)
        .await
    {
        Ok(rows) => rows,
        Err(err) => {
            warn!("Admin tenants query failed, falling back: {}", err);
            sqlx::query_as(
                r#"
                SELECT
                    t.tenant_id,
                    COALESCE(a.agent_count, 0) AS agent_count,
                    COALESCE(k.api_key_count, 0) AS api_key_count,
                    COALESCE(k.active_api_keys, 0) AS active_api_keys,
                    COALESCE(s.store_count, 0) AS store_count,
                    COALESCE(s.total_head_sequence, 0) AS total_head_sequence,
                    COALESCE(s.active_stores_24h, 0) AS active_stores_24h,
                    0::bigint AS max_projection_lag,
                    k.last_key_at,
                    s.last_activity_at
                FROM (
                    SELECT DISTINCT tenant_id
                    FROM api_keys
                    WHERE ($1::uuid IS NULL OR tenant_id = $1)
                ) t
                LEFT JOIN (
                    SELECT tenant_id, COUNT(DISTINCT agent_id) AS agent_count
                    FROM api_keys
                    WHERE agent_id IS NOT NULL AND ($1::uuid IS NULL OR tenant_id = $1)
                    GROUP BY tenant_id
                ) a ON t.tenant_id = a.tenant_id
                LEFT JOIN (
                    SELECT tenant_id,
                           COUNT(*) AS api_key_count,
                           COUNT(*) FILTER (WHERE active) AS active_api_keys,
                           MAX(updated_at) AS last_key_at
                    FROM api_keys
                    WHERE ($1::uuid IS NULL OR tenant_id = $1)
                    GROUP BY tenant_id
                ) k ON t.tenant_id = k.tenant_id
                LEFT JOIN (
                    SELECT sc.tenant_id,
                           COUNT(*) AS store_count,
                           SUM(sc.current_sequence)::bigint AS total_head_sequence,
                           COUNT(*) FILTER (WHERE sc.updated_at >= NOW() - INTERVAL '24 hours') AS active_stores_24h,
                           MAX(sc.updated_at) AS last_activity_at
                    FROM sequence_counters sc
                    WHERE ($1::uuid IS NULL OR sc.tenant_id = $1)
                    GROUP BY sc.tenant_id
                ) s ON t.tenant_id = s.tenant_id
                ORDER BY k.last_key_at DESC NULLS LAST
                "#,
            )
            .bind(tenant_scope)
            .fetch_all(&state.read_pool)
            .await
            .map_err(|_| admin_error(StatusCode::INTERNAL_SERVER_ERROR, "Query failed", "DB_ERROR"))?
        }
    };

    let response = rows
        .into_iter()
        .take(MAX_ADMIN_LIST_RESULTS)
        .map(|row| AdminTenantSummary {
            tenant_id: row.tenant_id,
            agent_count: row.agent_count.max(0) as u64,
            api_key_count: row.api_key_count.max(0) as u64,
            active_api_keys: row.active_api_keys.max(0) as u64,
            store_count: row.store_count.max(0) as u64,
            total_head_sequence: row.total_head_sequence.max(0) as u64,
            active_stores_24h: row.active_stores_24h.max(0) as u64,
            max_projection_lag: row.max_projection_lag.max(0) as u64,
            last_key_at: to_rfc3339(row.last_key_at),
            last_activity_at: to_rfc3339(row.last_activity_at),
        })
        .collect();

    Ok(Json(response))
}

/// GET /api/v1/admin/stores - Store summary list.
#[instrument(skip(state, auth))]
pub async fn admin_stores(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
) -> Result<Json<Vec<AdminStoreSummary>>, (StatusCode, Json<serde_json::Value>)> {
    let tenant_scope = admin_scope(&auth)?;
    let projection_available =
        match table_exists(&state.read_pool, "public.projection_checkpoints").await {
            Ok(value) => value,
            Err(err) => {
                warn!("Admin stores projection check failed: {}", err);
                false
            }
        };
    let sync_available = match table_exists(&state.read_pool, "public.agent_sync_state").await {
        Ok(value) => value,
        Err(err) => {
            warn!("Admin stores sync check failed: {}", err);
            false
        }
    };

    let query = match (projection_available, sync_available) {
        (true, true) => {
            r#"
        SELECT
            sc.tenant_id,
            sc.store_id,
            sc.current_sequence::bigint AS current_sequence,
            sc.updated_at,
            pc.last_projected_sequence,
            sc.current_sequence::bigint - COALESCE(pc.last_projected_sequence, 0)::bigint AS projection_lag,
            COALESCE(a.agent_count, 0)::bigint AS agent_count,
            a.last_agent_sync_at
        FROM sequence_counters sc
        LEFT JOIN projection_checkpoints pc
          ON pc.tenant_id = sc.tenant_id AND pc.store_id = sc.store_id
        LEFT JOIN (
            SELECT tenant_id,
                   store_id,
                   COUNT(*) AS agent_count,
                   MAX(last_sync_at) AS last_agent_sync_at
            FROM agent_sync_state
            GROUP BY tenant_id, store_id
        ) a ON sc.tenant_id = a.tenant_id AND sc.store_id = a.store_id
        WHERE ($1::uuid IS NULL OR sc.tenant_id = $1)
        ORDER BY sc.updated_at DESC
        "#
        }
        (true, false) => {
            r#"
        SELECT
            sc.tenant_id,
            sc.store_id,
            sc.current_sequence::bigint AS current_sequence,
            sc.updated_at,
            pc.last_projected_sequence,
            sc.current_sequence::bigint - COALESCE(pc.last_projected_sequence, 0)::bigint AS projection_lag,
            0::bigint AS agent_count,
            NULL::timestamptz AS last_agent_sync_at
        FROM sequence_counters sc
        LEFT JOIN projection_checkpoints pc
          ON pc.tenant_id = sc.tenant_id AND pc.store_id = sc.store_id
        WHERE ($1::uuid IS NULL OR sc.tenant_id = $1)
        ORDER BY sc.updated_at DESC
        "#
        }
        (false, true) => {
            r#"
        SELECT
            sc.tenant_id,
            sc.store_id,
            sc.current_sequence::bigint AS current_sequence,
            sc.updated_at,
            NULL::bigint AS last_projected_sequence,
            0::bigint AS projection_lag,
            COALESCE(a.agent_count, 0)::bigint AS agent_count,
            a.last_agent_sync_at
        FROM sequence_counters sc
        LEFT JOIN (
            SELECT tenant_id,
                   store_id,
                   COUNT(*) AS agent_count,
                   MAX(last_sync_at) AS last_agent_sync_at
            FROM agent_sync_state
            GROUP BY tenant_id, store_id
        ) a ON sc.tenant_id = a.tenant_id AND sc.store_id = a.store_id
        WHERE ($1::uuid IS NULL OR sc.tenant_id = $1)
        ORDER BY sc.updated_at DESC
        "#
        }
        (false, false) => {
            r#"
        SELECT
            sc.tenant_id,
            sc.store_id,
            sc.current_sequence::bigint AS current_sequence,
            sc.updated_at,
            NULL::bigint AS last_projected_sequence,
            0::bigint AS projection_lag,
            0::bigint AS agent_count,
            NULL::timestamptz AS last_agent_sync_at
        FROM sequence_counters sc
        WHERE ($1::uuid IS NULL OR sc.tenant_id = $1)
        ORDER BY sc.updated_at DESC
        "#
        }
    };

    let rows: Vec<StoreRow> = match sqlx::query_as(query)
        .bind(tenant_scope)
        .fetch_all(&state.read_pool)
        .await
    {
        Ok(rows) => rows,
        Err(err) => {
            warn!("Admin stores query failed, falling back: {}", err);
            sqlx::query_as(
                r#"
                SELECT
                    sc.tenant_id,
                    sc.store_id,
                    sc.current_sequence::bigint AS current_sequence,
                    sc.updated_at,
                    NULL::bigint AS last_projected_sequence,
                    0::bigint AS projection_lag,
                    0::bigint AS agent_count,
                    NULL::timestamptz AS last_agent_sync_at
                FROM sequence_counters sc
                WHERE ($1::uuid IS NULL OR sc.tenant_id = $1)
                ORDER BY sc.updated_at DESC
                "#,
            )
            .bind(tenant_scope)
            .fetch_all(&state.read_pool)
            .await
            .map_err(|_| {
                admin_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Query failed",
                    "DB_ERROR",
                )
            })?
        }
    };

    let response = rows
        .into_iter()
        .take(MAX_ADMIN_LIST_RESULTS)
        .map(|row| AdminStoreSummary {
            tenant_id: row.tenant_id,
            store_id: row.store_id,
            head_sequence: row.current_sequence.max(0) as u64,
            last_projected_sequence: row.last_projected_sequence.unwrap_or_default().max(0) as u64,
            projection_lag: row.projection_lag.max(0) as u64,
            agent_count: row.agent_count.max(0) as u64,
            last_agent_sync_at: to_rfc3339(row.last_agent_sync_at),
            updated_at: row.updated_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(response))
}

/// GET /api/v1/admin/agents - Agent summary list.
#[instrument(skip(state, auth))]
pub async fn admin_agents(
    State(state): State<AppState>,
    Extension(AuthContextExt(auth)): Extension<AuthContextExt>,
) -> Result<Json<Vec<AdminAgentSummary>>, (StatusCode, Json<serde_json::Value>)> {
    let tenant_scope = admin_scope(&auth)?;
    let sync_available = match table_exists(&state.read_pool, "public.agent_sync_state").await {
        Ok(value) => value,
        Err(err) => {
            warn!("Admin agents sync check failed: {}", err);
            false
        }
    };

    let query = if sync_available {
        r#"
        SELECT
            ak.tenant_id,
            ak.agent_id,
            BOOL_OR(ak.can_admin) AS has_admin,
            BOOL_OR(ak.can_write) AS has_write,
            BOOL_OR(cardinality(ak.store_ids) = 0) AS has_global_store_access,
            COUNT(*) AS api_key_count,
            COUNT(*) FILTER (WHERE ak.active) AS active_api_keys,
            MIN(ak.created_at) AS first_key_at,
            MAX(ak.updated_at) AS last_key_at,
            sync.store_id,
            sync.last_sync_at,
            sync.last_pushed_sequence,
            sync.last_pulled_sequence
        FROM api_keys ak
        LEFT JOIN (
            SELECT agent_id, store_id, last_sync_at, last_pushed_sequence, last_pulled_sequence
            FROM agent_sync_state
        ) sync ON ak.agent_id = sync.agent_id
        WHERE ak.agent_id IS NOT NULL
          AND ($1::uuid IS NULL OR ak.tenant_id = $1)
        GROUP BY ak.tenant_id, ak.agent_id, sync.store_id, sync.last_sync_at, sync.last_pushed_sequence, sync.last_pulled_sequence
        ORDER BY last_key_at DESC NULLS LAST
        "#
    } else {
        r#"
        SELECT
            ak.tenant_id,
            ak.agent_id,
            BOOL_OR(ak.can_admin) AS has_admin,
            BOOL_OR(ak.can_write) AS has_write,
            BOOL_OR(cardinality(ak.store_ids) = 0) AS has_global_store_access,
            COUNT(*) AS api_key_count,
            COUNT(*) FILTER (WHERE ak.active) AS active_api_keys,
            MIN(ak.created_at) AS first_key_at,
            MAX(ak.updated_at) AS last_key_at,
            NULL::uuid AS store_id,
            NULL::timestamptz AS last_sync_at,
            NULL::bigint AS last_pushed_sequence,
            NULL::bigint AS last_pulled_sequence
        FROM api_keys ak
        WHERE ak.agent_id IS NOT NULL
          AND ($1::uuid IS NULL OR ak.tenant_id = $1)
        GROUP BY ak.tenant_id, ak.agent_id
        ORDER BY last_key_at DESC NULLS LAST
        "#
    };

    let rows: Vec<AgentRow> = match sqlx::query_as(query)
        .bind(tenant_scope)
        .fetch_all(&state.read_pool)
        .await
    {
        Ok(rows) => rows,
        Err(err) => {
            warn!("Admin agents query failed, falling back: {}", err);
            sqlx::query_as(
                r#"
                SELECT
                    ak.tenant_id,
                    ak.agent_id,
                    BOOL_OR(ak.can_admin) AS has_admin,
                    BOOL_OR(ak.can_write) AS has_write,
                    BOOL_OR(cardinality(ak.store_ids) = 0) AS has_global_store_access,
                    COUNT(*) AS api_key_count,
                    COUNT(*) FILTER (WHERE ak.active) AS active_api_keys,
                    MIN(ak.created_at) AS first_key_at,
                    MAX(ak.updated_at) AS last_key_at,
                    NULL::uuid AS store_id,
                    NULL::timestamptz AS last_sync_at,
                    NULL::bigint AS last_pushed_sequence,
                    NULL::bigint AS last_pulled_sequence
                FROM api_keys ak
                WHERE ak.agent_id IS NOT NULL
                  AND ($1::uuid IS NULL OR ak.tenant_id = $1)
                GROUP BY ak.tenant_id, ak.agent_id
                ORDER BY last_key_at DESC NULLS LAST
                "#,
            )
            .bind(tenant_scope)
            .fetch_all(&state.read_pool)
            .await
            .map_err(|_| {
                admin_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Query failed",
                    "DB_ERROR",
                )
            })?
        }
    };

    let response = rows
        .into_iter()
        .take(MAX_ADMIN_LIST_RESULTS)
        .map(|row| {
            let permissions = if row.has_admin {
                "admin".to_string()
            } else if row.has_write {
                "read_write".to_string()
            } else {
                "read".to_string()
            };

            let store_scope = if row.has_global_store_access {
                "all".to_string()
            } else {
                "scoped".to_string()
            };

            AdminAgentSummary {
                tenant_id: row.tenant_id,
                agent_id: row.agent_id,
                permissions,
                store_scope,
                api_key_count: row.api_key_count.max(0) as u64,
                active_api_keys: row.active_api_keys.max(0) as u64,
                first_key_at: to_rfc3339(row.first_key_at),
                last_key_at: to_rfc3339(row.last_key_at),
                store_id: row.store_id,
                last_sync_at: to_rfc3339(row.last_sync_at),
                last_pushed_sequence: row.last_pushed_sequence.and_then(|v| {
                    if v < 0 {
                        None
                    } else {
                        Some(v as u64)
                    }
                }),
                last_pulled_sequence: row.last_pulled_sequence.and_then(|v| {
                    if v < 0 {
                        None
                    } else {
                        Some(v as u64)
                    }
                }),
            }
        })
        .collect();

    Ok(Json(response))
}
