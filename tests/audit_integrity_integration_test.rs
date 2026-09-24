mod common;

use sqlx::postgres::PgPoolOptions;
use stateset_sequencer::infra::{AuditAction, AuditLogBuilder, PgAuditLogger};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn audit_chain_is_serialized_and_append_only() {
    let Some(admin) = common::connect_test_db(2).await else {
        return;
    };
    let schema = format!("audit_test_{}", uuid::Uuid::new_v4().simple());
    sqlx::raw_sql(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let options = (*admin.connect_options())
        .clone()
        .options([("search_path", format!("{schema},public").as_str())]);
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await
        .unwrap();
    let logger = PgAuditLogger::new(pool.clone());
    logger.initialize().await.unwrap();
    logger
        .log(AuditLogBuilder::new(AuditAction::ApiKeyCreated, "legacy", "test").build())
        .await
        .unwrap();
    sqlx::raw_sql(include_str!(
        "../migrations/postgres/026_audit_integrity.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert!(logger.verify_chain().await.unwrap());
    let mut tasks = tokio::task::JoinSet::new();
    for n in 0..24 {
        let writer = PgAuditLogger::new(pool.clone());
        tasks.spawn(async move {
            writer
                .log(
                    AuditLogBuilder::new(
                        AuditAction::AgentPolicyUpdated,
                        format!("actor-{n}"),
                        "test",
                    )
                    .build(),
                )
                .await
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap().unwrap();
    }
    assert_eq!(logger.count(None).await.unwrap(), 25);
    assert!(logger.verify_chain().await.unwrap());
    let head = logger.chain_head().await.unwrap().unwrap();
    assert_eq!(head.0, 25);
    assert_eq!(head.1.len(), 32);
    assert!(logger.verify_checkpoint(head.0, &head.1).await.unwrap());
    assert_eq!(
        logger.verified_checkpoint().await.unwrap(),
        Some(head.clone())
    );
    logger
        .log(AuditLogBuilder::new(AuditAction::ApiKeyRevoked, "later", "test").build())
        .await
        .unwrap();
    assert!(logger.verify_checkpoint(head.0, &head.1).await.unwrap());
    assert!(!logger.verify_checkpoint(head.0, &[1; 32]).await.unwrap());
    assert_eq!(logger.cleanup(0).await.unwrap(), 0);
    assert!(sqlx::query("DELETE FROM audit_log WHERE chain_seq = 1")
        .execute(&pool)
        .await
        .is_err());
    assert!(
        sqlx::query("UPDATE audit_log SET actor = 'tampered' WHERE chain_seq = 1")
            .execute(&pool)
            .await
            .is_err()
    );
    let mut tampered = pool.begin().await.unwrap();
    sqlx::query("ALTER TABLE audit_log DISABLE TRIGGER audit_log_immutable")
        .execute(&mut *tampered)
        .await
        .unwrap();
    sqlx::query("UPDATE audit_log SET actor = 'tampered' WHERE chain_seq = 1")
        .execute(&mut *tampered)
        .await
        .unwrap();
    let valid: bool = sqlx::query_scalar("SELECT sequencer_verify_audit_chain()")
        .fetch_one(&mut *tampered)
        .await
        .unwrap();
    assert!(
        !valid,
        "verification must detect a changed historical entry"
    );
    tampered.rollback().await.unwrap();
    assert!(logger.verify_chain().await.unwrap());

    // A database owner can rewrite the last entry and recompute its hash so
    // local chain verification passes. The externally saved head detects it.
    let saved_head = logger.verified_checkpoint().await.unwrap().unwrap();
    sqlx::query("ALTER TABLE audit_log DISABLE TRIGGER audit_log_immutable")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE audit_log SET actor = 'rewritten' WHERE chain_seq = $1")
        .bind(saved_head.0)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE audit_log a SET entry_hash = digest(previous_hash || convert_to(\
         (to_jsonb(a) - 'previous_hash' - 'entry_hash')::text, 'UTF8'), 'sha256') \
         WHERE chain_seq = $1",
    )
    .bind(saved_head.0)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("ALTER TABLE audit_log ENABLE TRIGGER audit_log_immutable")
        .execute(&pool)
        .await
        .unwrap();
    assert!(logger.verify_chain().await.unwrap());
    assert!(!logger
        .verify_checkpoint(saved_head.0, &saved_head.1)
        .await
        .unwrap());
    pool.close().await;
    sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
