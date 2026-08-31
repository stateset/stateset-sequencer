//! Database migrations.
//!
//! Uses SQLx embedded migrations for both Postgres (server) and SQLite (local agent outbox).

use sqlx::{PgPool, SqlitePool};

static POSTGRES_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("migrations/postgres");
static SQLITE_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("migrations/sqlite");

pub async fn run_postgres(pool: &PgPool) -> anyhow::Result<()> {
    // Migrations 006/007 and some runtime-only tables rely on gen_random_uuid().
    // Ensure pgcrypto is available before SQLx applies those migrations.
    create_pgcrypto(pool).await?;
    POSTGRES_MIGRATOR.run(pool).await?;
    Ok(())
}

/// `CREATE EXTENSION IF NOT EXISTS`, tolerant of a concurrent creator.
///
/// This runs *outside* the migrator's advisory lock, and Postgres's
/// IF NOT EXISTS is not concurrency-safe: two sessions can both pass the
/// existence check and the loser fails on `pg_extension_name_index` (23505)
/// or `duplicate_object` (42710). Any two callers migrating a fresh database
/// at once -- parallel test binaries, or multiple nodes racing on first boot
/// -- hit this. Losing that race means the extension exists, which is the
/// outcome we wanted; treat it as success.
pub(crate) async fn create_pgcrypto(pool: &PgPool) -> Result<(), sqlx::Error> {
    if let Err(e) = sqlx::query("CREATE EXTENSION IF NOT EXISTS pgcrypto")
        .execute(pool)
        .await
    {
        let benign = e
            .as_database_error()
            .and_then(|d| d.code())
            .map(|c| c == "23505" || c == "42710")
            .unwrap_or(false);
        if !benign {
            return Err(e);
        }
    }
    Ok(())
}

pub async fn run_sqlite(pool: &SqlitePool) -> anyhow::Result<()> {
    SQLITE_MIGRATOR.run(pool).await?;
    Ok(())
}
