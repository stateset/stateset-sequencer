//! Database migrations.
//!
//! Uses SQLx embedded migrations for both Postgres (server) and SQLite (local agent outbox).

use sqlx::{PgPool, SqlitePool};

static POSTGRES_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("migrations/postgres");
static SQLITE_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("migrations/sqlite");

pub async fn run_postgres(pool: &PgPool) -> anyhow::Result<()> {
    POSTGRES_MIGRATOR.run(pool).await?;
    Ok(())
}

pub async fn run_sqlite(pool: &SqlitePool) -> anyhow::Result<()> {
    SQLITE_MIGRATOR.run(pool).await?;
    Ok(())
}
