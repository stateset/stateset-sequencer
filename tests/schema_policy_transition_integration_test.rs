mod common;

use sqlx::postgres::PgPoolOptions;
use stateset_sequencer::domain::{EventType, Schema, TenantId};
use stateset_sequencer::infra::{PgSchemaStore, SchemaCache, SchemaStore};
use std::{sync::Arc, time::Duration};

#[tokio::test]
#[ignore]
async fn archive_on_another_replica_revokes_active_validation_schema() {
    let Some(admin) = common::connect_test_db(2).await else {
        return;
    };
    let schema = format!("schema_policy_test_{}", uuid::Uuid::new_v4().simple());
    sqlx::raw_sql(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let search_path = format!("{schema},public");
    let options = (*admin.connect_options())
        .clone()
        .options([("search_path", search_path.as_str())]);
    let pool_a = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options.clone())
        .await
        .unwrap();
    let pool_b = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options)
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("../migrations/postgres/018_event_schemas.sql"))
        .execute(&pool_a)
        .await
        .unwrap();
    let cache = Arc::new(SchemaCache::new(32, Duration::from_secs(3600)));
    let reader = PgSchemaStore::new(pool_a.clone()).with_cache(cache);
    let tenant = TenantId::new();
    let event_type = EventType::from("order.created");
    let registered = reader
        .register(Schema::new(
            tenant,
            event_type.clone(),
            1,
            serde_json::json!({"type": "object"}),
        ))
        .await
        .unwrap();
    assert!(reader
        .get_latest(&tenant, &event_type)
        .await
        .unwrap()
        .is_some());
    sqlx::query("UPDATE event_schemas SET status = 'archived' WHERE id = $1")
        .bind(registered.id.0)
        .execute(&pool_b)
        .await
        .unwrap();
    assert!(reader
        .get_latest(&tenant, &event_type)
        .await
        .unwrap()
        .is_none());
    pool_a.close().await;
    pool_b.close().await;
    sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
