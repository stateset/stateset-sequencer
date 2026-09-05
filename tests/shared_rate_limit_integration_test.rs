//! Shared quota tests use an isolated schema, never the caller's quota records.
mod common;

use sqlx::postgres::PgPoolOptions;
use stateset_sequencer::auth::{AuthError, RateLimiter, RateLimiterConfig};
use std::sync::Arc;

fn limiter(pool: sqlx::PgPool, limit: u32, capacity: usize, window: u64) -> Arc<RateLimiter> {
    Arc::new(
        RateLimiter::with_config(RateLimiterConfig {
            requests_per_minute: limit,
            max_entries: capacity,
            window_seconds: window,
        })
        .with_postgres_backend(pool)
        .unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn shared_admission_is_atomic_bounded_and_fail_closed() {
    let Some(admin) = common::connect_test_db(2).await else {
        return;
    };
    let schema = format!("quota_test_{}", uuid::Uuid::new_v4().simple());
    sqlx::raw_sql(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let options = (*admin.connect_options())
        .clone()
        // This test measures admission concurrency, not crash durability. Avoid
        // host-wide WAL fsync stalls dominating the one-second admission budget.
        .options([
            ("search_path", schema.as_str()),
            ("synchronous_commit", "off"),
        ]);
    let pool_a = PgPoolOptions::new()
        .max_connections(10)
        .connect_with(options.clone())
        .await
        .unwrap();
    let pool_b = PgPoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await
        .unwrap();
    sqlx::raw_sql(include_str!(
        "../migrations/postgres/023_shared_rate_limits.sql"
    ))
    .execute(&pool_a)
    .await
    .unwrap();
    let a = limiter(pool_a.clone(), 7, 2, 60);
    let b = limiter(pool_b.clone(), 7, 2, 60);
    let mut attempts = tokio::task::JoinSet::new();
    for index in 0..50 {
        let replica = if index % 2 == 0 { a.clone() } else { b.clone() };
        attempts.spawn(async move { replica.check_async("tenant:hot").await });
    }
    let mut allowed = 0;
    while let Some(result) = attempts.join_next().await {
        match result.unwrap() {
            Ok(()) => allowed += 1,
            Err(AuthError::RateLimited) => {}
            Err(error) => panic!("unexpected backend failure: {error}"),
        }
    }
    assert_eq!(allowed, 7, "replicas must share one atomic budget");
    let restarted = limiter(pool_b.clone(), 7, 2, 60);
    assert!(matches!(
        restarted.check_async("tenant:hot").await,
        Err(AuthError::RateLimited)
    ));
    a.check_async("tenant:second").await.unwrap();
    let mut churn = tokio::task::JoinSet::new();
    for index in 0..12 {
        let replica = if index % 2 == 0 { a.clone() } else { b.clone() };
        churn.spawn(async move { replica.check_async(&format!("tenant:churn:{index}")).await });
    }
    while let Some(result) = churn.join_next().await {
        assert!(matches!(result.unwrap(), Err(AuthError::RateLimited)));
    }
    assert!(matches!(
        b.check_async("tenant:third").await,
        Err(AuthError::RateLimited)
    ));
    assert!(
        matches!(
            a.check_async("tenant:hot").await,
            Err(AuthError::RateLimited)
        ),
        "churn must not reset a live budget"
    );

    let hot_hash = stateset_sequencer::auth::ApiKeyValidator::hash_key("tenant:hot");
    sqlx::query("UPDATE sequencer_rate_limit_budgets SET expires_at = clock_timestamp() - interval '1 second' WHERE key_hash = $1")
        .bind(&hot_hash).execute(&pool_a).await.unwrap();
    b.check_async("tenant:hot").await.unwrap();
    let count: i64 =
        sqlx::query_scalar("SELECT used FROM sequencer_rate_limit_budgets WHERE key_hash = $1")
            .bind(&hot_hash)
            .fetch_one(&pool_a)
            .await
            .unwrap();
    assert_eq!(count, 1, "expiry starts a fresh window using database time");
    sqlx::query("UPDATE sequencer_rate_limit_budgets SET expires_at = clock_timestamp() - interval '1 second' WHERE key_hash <> $1")
        .bind(&hot_hash).execute(&pool_a).await.unwrap();
    a.check_async("tenant:third").await.unwrap();
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM sequencer_rate_limit_budgets")
        .fetch_one(&pool_a)
        .await
        .unwrap();
    assert_eq!(rows, 2);
    assert!(matches!(
        limiter(pool_b.clone(), 7, 2, 120)
            .check_async("tenant:hot")
            .await,
        Err(AuthError::BackendUnavailable(_))
    ));
    assert!(
        matches!(a.check("tenant:hot"), Err(AuthError::BackendUnavailable(_))),
        "sync callers cannot bypass shared admission"
    );

    // Both transports use independent limiter instances, not a shared local map.
    use axum::{body::Body, http::StatusCode, routing::get, Router};
    use stateset_sequencer::auth::{
        auth_middleware, ApiKeyRecord, ApiKeyValidator, AuthMiddlewareState, Authenticator,
        Permissions,
    };
    use stateset_sequencer::grpc::GrpcAuthInterceptor;
    use tower::ServiceExt;
    let validator = Arc::new(ApiKeyValidator::new());
    let api_key = "ss_test_shared_database_quota";
    validator.register_key(ApiKeyRecord {
        key_hash: ApiKeyValidator::hash_key(api_key),
        tenant_id: uuid::Uuid::new_v4(),
        store_ids: vec![],
        permissions: Permissions::read_only(),
        agent_id: None,
        active: true,
        rate_limit: Some(1),
    });
    let auth = Arc::new(Authenticator::new(validator));
    let app = Router::new().route("/", get(|| async { "ok" })).layer(
        axum::middleware::from_fn_with_state(
            AuthMiddlewareState {
                authenticator: auth.clone(),
                require_auth: true,
                rate_limiter: None,
                credential_rate_limiter: limiter(pool_a.clone(), 100, 100, 60),
                pool_monitor: None,
            },
            auth_middleware,
        ),
    );
    let grpc = GrpcAuthInterceptor::new(auth, true, None, limiter(pool_b.clone(), 100, 100, 60));
    let request = || {
        axum::http::Request::builder()
            .uri("/")
            .header("x-api-key", api_key)
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        app.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::OK
    );
    let mut grpc_request = tonic::Request::new(());
    grpc_request
        .metadata_mut()
        .insert("x-api-key", api_key.parse().unwrap());
    assert_eq!(
        grpc.authenticate(&grpc_request).unwrap_err().code(),
        tonic::Code::ResourceExhausted
    );

    let mut held = pool_a.begin().await.unwrap();
    sqlx::query("SELECT key_hash FROM sequencer_rate_limit_budgets WHERE key_hash = $1 FOR UPDATE")
        .bind(&hot_hash)
        .fetch_one(&mut *held)
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        assert!(matches!(
            b.check_async("tenant:hot").await,
            Err(AuthError::BackendUnavailable(_))
        ));
    })
    .await
    .expect("admission must not wait indefinitely for a locked row");
    held.rollback().await.unwrap();

    pool_a.close().await;
    pool_b.close().await;
    assert!(matches!(
        a.check_async("tenant:new").await,
        Err(AuthError::BackendUnavailable(_))
    ));
    assert_eq!(
        app.oneshot(request()).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        grpc.authenticate(&grpc_request).unwrap_err().code(),
        tonic::Code::Unavailable
    );
    sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
