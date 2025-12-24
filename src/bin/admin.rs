use std::collections::VecDeque;

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use stateset_sequencer::anchor::{AnchorConfig, AnchorService};
use stateset_sequencer::crypto::{
    compute_stream_id, compute_ves_compliance_policy_hash,
    compute_ves_compliance_proof_at_rest_aad, compute_ves_compliance_proof_hash,
    compute_ves_state_root, compute_ves_validity_proof_at_rest_aad,
    compute_ves_validity_proof_hash, is_payload_at_rest_encrypted, Hash256,
};
use stateset_sequencer::infra::{PayloadEncryption, PayloadEncryptionMode};
use stateset_sequencer::{StoreId, TenantId};

fn print_help() {
    eprintln!(
        "\
stateset-sequencer-admin

USAGE:
  stateset-sequencer-admin <command> [options]

COMMANDS:
  migrate
  reencrypt-events
  reencrypt-ves-validity-proofs
  reencrypt-ves-compliance-proofs
  backfill-ves-state-roots
  ves-commit-and-anchor

COMMON OPTIONS:
  --database-url <postgres_url>    (defaults to env DATABASE_URL)

reencrypt-events OPTIONS:
  --tenant-id <uuid>              (optional)
  --store-id <uuid>               (optional)
  --batch-size <n>                (default: 500)
  --limit <n>                     (optional)
  --dry-run
  --force                         (reencrypt even if current key decrypts)

reencrypt-ves-validity-proofs OPTIONS:
  --tenant-id <uuid>              (optional)
  --store-id <uuid>               (optional)
  --batch-size <n>                (default: 200)
  --limit <n>                     (optional)
  --dry-run
  --force                         (reencrypt even if current key decrypts)

reencrypt-ves-compliance-proofs OPTIONS:
  --tenant-id <uuid>              (optional)
  --store-id <uuid>               (optional)
  --batch-size <n>                (default: 200)
  --limit <n>                     (optional)
  --dry-run
  --force                         (reencrypt even if current key decrypts)

backfill-ves-state-roots OPTIONS:
  --tenant-id <uuid>              (optional; otherwise all streams)
  --store-id <uuid>               (optional; requires --tenant-id)
  --dry-run
  --force                         (recompute from genesis; updates anchored)

ves-commit-and-anchor OPTIONS:
  --tenant-id <uuid>              (required)
  --store-id <uuid>               (required)
  --sequence-start <n>            (optional; requires --sequence-end)
  --sequence-end <n>              (optional; requires --sequence-start)
  --max-events <n>                (default: 1024; used when start/end omitted)

ENV (encryption at rest):
  PAYLOAD_ENCRYPTION_KEYS / PAYLOAD_ENCRYPTION_KEYS_BY_TENANT / PAYLOAD_ENCRYPTION_KEY
"
    );
}

fn require_database_url(database_url: Option<String>) -> anyhow::Result<String> {
    database_url
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .ok_or_else(|| anyhow::anyhow!("DATABASE_URL is required (or pass --database-url)"))
}

fn stream_lock_key(tenant_id: &Uuid, store_id: &Uuid) -> i64 {
    let stream_id = compute_stream_id(tenant_id, store_id);
    let bytes: [u8; 8] = stream_id[..8]
        .try_into()
        .expect("stream_id is always 32 bytes");
    i64::from_be_bytes(bytes)
}

fn bytes32(label: &str, bytes: &[u8]) -> anyhow::Result<Hash256> {
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid {label} length"))
}

async fn head_sequence(
    pool: &sqlx::PgPool,
    tenant_id: &Uuid,
    store_id: &Uuid,
) -> anyhow::Result<u64> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT current_sequence FROM ves_sequence_counters WHERE tenant_id = $1 AND store_id = $2",
    )
    .bind(tenant_id)
    .bind(store_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(v,)| v as u64).unwrap_or(0))
}

#[derive(Debug, sqlx::FromRow)]
struct EventRow {
    event_id: Uuid,
    tenant_id: Uuid,
    store_id: Uuid,
    sequence_number: i64,
    entity_type: String,
    entity_id: String,
    event_type: String,
    payload_encrypted: Vec<u8>,
}

#[derive(Debug, sqlx::FromRow)]
struct VesCommitmentRow {
    batch_id: Uuid,
    sequence_start: i64,
    sequence_end: i64,
    leaf_count: i64,
    merkle_root: Vec<u8>,
    prev_state_root: Vec<u8>,
    new_state_root: Vec<u8>,
    chain_tx_hash: Option<Vec<u8>>,
}

#[derive(Debug, sqlx::FromRow)]
struct VesValidityProofRow {
    proof_id: Uuid,
    batch_id: Uuid,
    tenant_id: Uuid,
    store_id: Uuid,
    proof_type: String,
    proof_version: i32,
    proof: Vec<u8>,
    proof_hash: Vec<u8>,
}

#[derive(Debug, sqlx::FromRow)]
struct VesComplianceProofRow {
    proof_id: Uuid,
    event_id: Uuid,
    tenant_id: Uuid,
    store_id: Uuid,
    proof_type: String,
    proof_version: i32,
    policy_id: String,
    policy_params: serde_json::Value,
    policy_hash: Vec<u8>,
    proof: Vec<u8>,
    proof_hash: Vec<u8>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args: VecDeque<String> = std::env::args().skip(1).collect();
    let Some(command) = args.pop_front() else {
        print_help();
        return Ok(());
    };

    if matches!(command.as_str(), "-h" | "--help" | "help") {
        print_help();
        return Ok(());
    }

    match command.as_str() {
        "migrate" => {
            let mut database_url: Option<String> = None;
            while let Some(arg) = args.pop_front() {
                match arg.as_str() {
                    "--database-url" => {
                        database_url =
                            Some(args.pop_front().ok_or_else(|| {
                                anyhow::anyhow!("missing value for --database-url")
                            })?);
                    }
                    "-h" | "--help" => {
                        print_help();
                        return Ok(());
                    }
                    other => anyhow::bail!("unexpected argument: {other}"),
                }
            }

            let database_url = require_database_url(database_url)?;
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&database_url)
                .await?;
            stateset_sequencer::migrations::run_postgres(&pool).await?;
            println!("ok: migrations applied");
            Ok(())
        }
        "reencrypt-events" => {
            let mut database_url: Option<String> = None;
            let mut tenant_id: Option<Uuid> = None;
            let mut store_id: Option<Uuid> = None;
            let mut batch_size: usize = 500;
            let mut limit: Option<u64> = None;
            let mut dry_run = false;
            let mut force = false;

            while let Some(arg) = args.pop_front() {
                match arg.as_str() {
                    "--database-url" => {
                        database_url =
                            Some(args.pop_front().ok_or_else(|| {
                                anyhow::anyhow!("missing value for --database-url")
                            })?);
                    }
                    "--tenant-id" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --tenant-id"))?;
                        tenant_id = Some(Uuid::parse_str(&raw)?);
                    }
                    "--store-id" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --store-id"))?;
                        store_id = Some(Uuid::parse_str(&raw)?);
                    }
                    "--batch-size" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --batch-size"))?;
                        batch_size = raw.parse()?;
                    }
                    "--limit" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --limit"))?;
                        limit = Some(raw.parse()?);
                    }
                    "--dry-run" => dry_run = true,
                    "--force" => force = true,
                    "-h" | "--help" => {
                        print_help();
                        return Ok(());
                    }
                    other => anyhow::bail!("unexpected argument: {other}"),
                }
            }

            let database_url = require_database_url(database_url)?;

            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&database_url)
                .await?;
            stateset_sequencer::migrations::run_postgres(&pool).await?;

            let payload_encryption =
                PayloadEncryption::from_env_with_mode(PayloadEncryptionMode::Optional)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;

            let mut last_event_id: Option<Uuid> = None;
            let mut scanned: u64 = 0;
            let mut would_update: u64 = 0;
            let mut updated: u64 = 0;
            let mut skipped_current_key: u64 = 0;

            loop {
                let rows: Vec<EventRow> = sqlx::query_as(
                    r#"
                    SELECT
                        event_id,
                        tenant_id,
                        store_id,
                        sequence_number,
                        entity_type,
                        entity_id,
                        event_type,
                        payload_encrypted
                    FROM events
                    WHERE ($1::uuid IS NULL OR tenant_id = $1)
                      AND ($2::uuid IS NULL OR store_id = $2)
                      AND ($3::uuid IS NULL OR event_id > $3)
                    ORDER BY event_id ASC
                    LIMIT $4
                    "#,
                )
                .bind(tenant_id)
                .bind(store_id)
                .bind(last_event_id)
                .bind(batch_size as i64)
                .fetch_all(&pool)
                .await?;

                if rows.is_empty() {
                    break;
                }

                let mut tx = if dry_run {
                    None
                } else {
                    Some(pool.begin().await?)
                };

                for row in rows {
                    scanned += 1;
                    last_event_id = Some(row.event_id);

                    if let Some(limit) = limit {
                        if scanned > limit {
                            break;
                        }
                    }

                    let sequence_number: u64 = row.sequence_number.try_into().map_err(|_| {
                        anyhow::anyhow!("invalid sequence_number for event {}", row.event_id)
                    })?;

                    let aad = PayloadEncryption::aad_for_row(
                        &row.tenant_id,
                        &row.store_id,
                        &row.event_id,
                        sequence_number,
                        &row.entity_type,
                        &row.entity_id,
                        &row.event_type,
                    );

                    let is_encrypted = is_payload_at_rest_encrypted(&row.payload_encrypted);

                    if is_encrypted && !force {
                        if payload_encryption
                            .decrypt_payload_with_current_key(
                                &row.tenant_id,
                                &aad,
                                &row.payload_encrypted,
                            )
                            .await
                            .is_ok()
                        {
                            skipped_current_key += 1;
                            continue;
                        }
                    }

                    let plaintext = if is_encrypted {
                        payload_encryption
                            .decrypt_payload(&row.tenant_id, &aad, &row.payload_encrypted)
                            .await?
                    } else {
                        row.payload_encrypted
                    };

                    let new_ciphertext = payload_encryption
                        .encrypt_payload(&row.tenant_id, &aad, &plaintext)
                        .await?;

                    would_update += 1;
                    if let Some(tx) = tx.as_mut() {
                        sqlx::query("UPDATE events SET payload_encrypted = $1 WHERE event_id = $2")
                            .bind(new_ciphertext)
                            .bind(row.event_id)
                            .execute(&mut **tx)
                            .await?;
                        updated += 1;
                    }
                }

                if let Some(limit) = limit {
                    if scanned >= limit {
                        break;
                    }
                }

                if let Some(tx) = tx {
                    tx.commit().await?;
                }
            }

            if dry_run {
                println!(
                    "ok: scanned={scanned} would_update={would_update} skipped_current_key={skipped_current_key} (dry run)"
                );
            } else {
                println!(
                    "ok: scanned={scanned} updated={updated} skipped_current_key={skipped_current_key}"
                );
            }

            Ok(())
        }
        "reencrypt-ves-validity-proofs" => {
            let mut database_url: Option<String> = None;
            let mut tenant_id: Option<Uuid> = None;
            let mut store_id: Option<Uuid> = None;
            let mut batch_size: usize = 200;
            let mut limit: Option<u64> = None;
            let mut dry_run = false;
            let mut force = false;

            while let Some(arg) = args.pop_front() {
                match arg.as_str() {
                    "--database-url" => {
                        database_url =
                            Some(args.pop_front().ok_or_else(|| {
                                anyhow::anyhow!("missing value for --database-url")
                            })?);
                    }
                    "--tenant-id" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --tenant-id"))?;
                        tenant_id = Some(Uuid::parse_str(&raw)?);
                    }
                    "--store-id" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --store-id"))?;
                        store_id = Some(Uuid::parse_str(&raw)?);
                    }
                    "--batch-size" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --batch-size"))?;
                        batch_size = raw.parse()?;
                    }
                    "--limit" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --limit"))?;
                        limit = Some(raw.parse()?);
                    }
                    "--dry-run" => dry_run = true,
                    "--force" => force = true,
                    "-h" | "--help" => {
                        print_help();
                        return Ok(());
                    }
                    other => anyhow::bail!("unexpected argument: {other}"),
                }
            }

            let database_url = require_database_url(database_url)?;
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&database_url)
                .await?;
            stateset_sequencer::migrations::run_postgres(&pool).await?;

            let payload_encryption =
                PayloadEncryption::from_env_with_mode(PayloadEncryptionMode::Optional)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;

            let mut last_proof_id: Option<Uuid> = None;
            let mut scanned: u64 = 0;
            let mut would_update: u64 = 0;
            let mut updated: u64 = 0;
            let mut skipped_current_key: u64 = 0;

            loop {
                let rows: Vec<VesValidityProofRow> = sqlx::query_as(
                    r#"
                    SELECT
                        proof_id,
                        batch_id,
                        tenant_id,
                        store_id,
                        proof_type,
                        proof_version,
                        proof,
                        proof_hash
                    FROM ves_validity_proofs
                    WHERE ($1::uuid IS NULL OR tenant_id = $1)
                      AND ($2::uuid IS NULL OR store_id = $2)
                      AND ($3::uuid IS NULL OR proof_id > $3)
                    ORDER BY proof_id ASC
                    LIMIT $4
                    "#,
                )
                .bind(tenant_id)
                .bind(store_id)
                .bind(last_proof_id)
                .bind(batch_size as i64)
                .fetch_all(&pool)
                .await?;

                if rows.is_empty() {
                    break;
                }

                let mut tx = if dry_run {
                    None
                } else {
                    Some(pool.begin().await?)
                };

                for row in rows {
                    scanned += 1;
                    last_proof_id = Some(row.proof_id);

                    if let Some(limit) = limit {
                        if scanned > limit {
                            break;
                        }
                    }

                    let proof_hash = bytes32("proof_hash", &row.proof_hash)?;
                    let aad = compute_ves_validity_proof_at_rest_aad(
                        &row.tenant_id,
                        &row.store_id,
                        &row.batch_id,
                        &row.proof_id,
                        &row.proof_type,
                        row.proof_version as u32,
                        &proof_hash,
                    );

                    let is_encrypted = is_payload_at_rest_encrypted(&row.proof);

                    if is_encrypted && !force {
                        if payload_encryption
                            .decrypt_payload_with_current_key(&row.tenant_id, &aad, &row.proof)
                            .await
                            .is_ok()
                        {
                            skipped_current_key += 1;
                            continue;
                        }
                    }

                    let plaintext = if is_encrypted {
                        payload_encryption
                            .decrypt_payload(&row.tenant_id, &aad, &row.proof)
                            .await?
                    } else {
                        row.proof
                    };

                    let recomputed = compute_ves_validity_proof_hash(&plaintext);
                    if recomputed != proof_hash {
                        anyhow::bail!(
                            "proof_hash mismatch for proof_id={} (batch_id={})",
                            row.proof_id,
                            row.batch_id
                        );
                    }

                    let new_ciphertext = payload_encryption
                        .encrypt_payload(&row.tenant_id, &aad, &plaintext)
                        .await?;

                    would_update += 1;
                    if let Some(tx) = tx.as_mut() {
                        sqlx::query(
                            "UPDATE ves_validity_proofs SET proof = $1 WHERE proof_id = $2",
                        )
                        .bind(new_ciphertext)
                        .bind(row.proof_id)
                        .execute(&mut **tx)
                        .await?;
                        updated += 1;
                    }
                }

                if let Some(limit) = limit {
                    if scanned >= limit {
                        break;
                    }
                }

                if let Some(tx) = tx {
                    tx.commit().await?;
                }
            }

            if dry_run {
                println!(
                    "ok: scanned={scanned} would_update={would_update} skipped_current_key={skipped_current_key} (dry run)"
                );
            } else {
                println!(
                    "ok: scanned={scanned} updated={updated} skipped_current_key={skipped_current_key}"
                );
            }

            Ok(())
        }
        "reencrypt-ves-compliance-proofs" => {
            let mut database_url: Option<String> = None;
            let mut tenant_id: Option<Uuid> = None;
            let mut store_id: Option<Uuid> = None;
            let mut batch_size: usize = 200;
            let mut limit: Option<u64> = None;
            let mut dry_run = false;
            let mut force = false;

            while let Some(arg) = args.pop_front() {
                match arg.as_str() {
                    "--database-url" => {
                        database_url =
                            Some(args.pop_front().ok_or_else(|| {
                                anyhow::anyhow!("missing value for --database-url")
                            })?);
                    }
                    "--tenant-id" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --tenant-id"))?;
                        tenant_id = Some(Uuid::parse_str(&raw)?);
                    }
                    "--store-id" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --store-id"))?;
                        store_id = Some(Uuid::parse_str(&raw)?);
                    }
                    "--batch-size" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --batch-size"))?;
                        batch_size = raw.parse()?;
                    }
                    "--limit" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --limit"))?;
                        limit = Some(raw.parse()?);
                    }
                    "--dry-run" => dry_run = true,
                    "--force" => force = true,
                    "-h" | "--help" => {
                        print_help();
                        return Ok(());
                    }
                    other => anyhow::bail!("unexpected argument: {other}"),
                }
            }

            let database_url = require_database_url(database_url)?;

            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&database_url)
                .await?;
            stateset_sequencer::migrations::run_postgres(&pool).await?;

            let payload_encryption =
                PayloadEncryption::from_env_with_mode(PayloadEncryptionMode::Optional)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;

            let mut last_proof_id: Option<Uuid> = None;
            let mut scanned: u64 = 0;
            let mut would_update: u64 = 0;
            let mut updated: u64 = 0;
            let mut skipped_current_key: u64 = 0;

            loop {
                let rows: Vec<VesComplianceProofRow> = sqlx::query_as(
                    r#"
                    SELECT
                        proof_id,
                        event_id,
                        tenant_id,
                        store_id,
                        proof_type,
                        proof_version,
                        policy_id,
                        policy_params,
                        policy_hash,
                        proof,
                        proof_hash
                    FROM ves_compliance_proofs
                    WHERE ($1::uuid IS NULL OR tenant_id = $1)
                      AND ($2::uuid IS NULL OR store_id = $2)
                      AND ($3::uuid IS NULL OR proof_id > $3)
                    ORDER BY proof_id ASC
                    LIMIT $4
                    "#,
                )
                .bind(tenant_id)
                .bind(store_id)
                .bind(last_proof_id)
                .bind(batch_size as i64)
                .fetch_all(&pool)
                .await?;

                if rows.is_empty() {
                    break;
                }

                let mut tx = if dry_run {
                    None
                } else {
                    Some(pool.begin().await?)
                };

                for row in rows {
                    scanned += 1;
                    last_proof_id = Some(row.proof_id);

                    if let Some(limit) = limit {
                        if scanned > limit {
                            break;
                        }
                    }

                    let policy_hash = bytes32("policy_hash", &row.policy_hash)?;
                    let recomputed_policy_hash =
                        compute_ves_compliance_policy_hash(&row.policy_id, &row.policy_params);
                    if recomputed_policy_hash != policy_hash {
                        anyhow::bail!(
                            "policy_hash mismatch for proof_id={} (event_id={})",
                            row.proof_id,
                            row.event_id
                        );
                    }

                    let proof_hash = bytes32("proof_hash", &row.proof_hash)?;
                    let aad = compute_ves_compliance_proof_at_rest_aad(
                        &row.tenant_id,
                        &row.store_id,
                        &row.event_id,
                        &row.proof_id,
                        &policy_hash,
                        &row.proof_type,
                        row.proof_version as u32,
                        &proof_hash,
                    );

                    let is_encrypted = is_payload_at_rest_encrypted(&row.proof);

                    if is_encrypted && !force {
                        if payload_encryption
                            .decrypt_payload_with_current_key(&row.tenant_id, &aad, &row.proof)
                            .await
                            .is_ok()
                        {
                            skipped_current_key += 1;
                            continue;
                        }
                    }

                    let plaintext = if is_encrypted {
                        payload_encryption
                            .decrypt_payload(&row.tenant_id, &aad, &row.proof)
                            .await?
                    } else {
                        row.proof
                    };

                    let recomputed = compute_ves_compliance_proof_hash(&plaintext);
                    if recomputed != proof_hash {
                        anyhow::bail!(
                            "proof_hash mismatch for proof_id={} (event_id={})",
                            row.proof_id,
                            row.event_id
                        );
                    }

                    let new_ciphertext = payload_encryption
                        .encrypt_payload(&row.tenant_id, &aad, &plaintext)
                        .await?;

                    would_update += 1;
                    if let Some(tx) = tx.as_mut() {
                        sqlx::query(
                            "UPDATE ves_compliance_proofs SET proof = $1 WHERE proof_id = $2",
                        )
                        .bind(new_ciphertext)
                        .bind(row.proof_id)
                        .execute(&mut **tx)
                        .await?;
                        updated += 1;
                    }
                }

                if let Some(limit) = limit {
                    if scanned >= limit {
                        break;
                    }
                }

                if let Some(tx) = tx {
                    tx.commit().await?;
                }
            }

            if dry_run {
                println!(
                    "ok: scanned={scanned} would_update={would_update} skipped_current_key={skipped_current_key} (dry run)"
                );
            } else {
                println!(
                    "ok: scanned={scanned} updated={updated} skipped_current_key={skipped_current_key}"
                );
            }

            Ok(())
        }
        "backfill-ves-state-roots" => {
            let mut database_url: Option<String> = None;
            let mut tenant_id: Option<Uuid> = None;
            let mut store_id: Option<Uuid> = None;
            let mut dry_run = false;
            let mut force = false;

            while let Some(arg) = args.pop_front() {
                match arg.as_str() {
                    "--database-url" => {
                        database_url =
                            Some(args.pop_front().ok_or_else(|| {
                                anyhow::anyhow!("missing value for --database-url")
                            })?);
                    }
                    "--tenant-id" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --tenant-id"))?;
                        tenant_id = Some(Uuid::parse_str(&raw)?);
                    }
                    "--store-id" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --store-id"))?;
                        store_id = Some(Uuid::parse_str(&raw)?);
                    }
                    "--dry-run" => dry_run = true,
                    "--force" => force = true,
                    "-h" | "--help" => {
                        print_help();
                        return Ok(());
                    }
                    other => anyhow::bail!("unexpected argument: {other}"),
                }
            }

            if store_id.is_some() && tenant_id.is_none() {
                anyhow::bail!("--store-id requires --tenant-id");
            }

            let database_url = require_database_url(database_url)?;
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&database_url)
                .await?;
            stateset_sequencer::migrations::run_postgres(&pool).await?;

            let streams: Vec<(Uuid, Uuid)> = match (tenant_id, store_id) {
                (Some(t), Some(s)) => vec![(t, s)],
                (Some(t), None) => {
                    sqlx::query_as(
                        r#"
                        SELECT DISTINCT tenant_id, store_id
                        FROM ves_commitments
                        WHERE tenant_id = $1
                        ORDER BY store_id ASC
                        "#,
                    )
                    .bind(t)
                    .fetch_all(&pool)
                    .await?
                }
                (None, None) => {
                    sqlx::query_as(
                        r#"
                        SELECT DISTINCT tenant_id, store_id
                        FROM ves_commitments
                        ORDER BY tenant_id ASC, store_id ASC
                        "#,
                    )
                    .fetch_all(&pool)
                    .await?
                }
                (None, Some(_)) => unreachable!("checked above"),
            };

            let mut total_streams: u64 = 0;
            let mut total_scanned: u64 = 0;
            let mut total_updated: u64 = 0;
            let mut total_would_update: u64 = 0;

            for (tenant_id, store_id) in streams {
                total_streams += 1;
                let mut tx = pool.begin().await?;
                sqlx::query("SELECT pg_advisory_xact_lock($1)")
                    .bind(stream_lock_key(&tenant_id, &store_id))
                    .execute(&mut *tx)
                    .await?;

                let rows: Vec<VesCommitmentRow> = sqlx::query_as(
                    r#"
                    SELECT
                        batch_id,
                        sequence_start,
                        sequence_end,
                        leaf_count,
                        merkle_root,
                        prev_state_root,
                        new_state_root,
                        chain_tx_hash
                    FROM ves_commitments
                    WHERE tenant_id = $1 AND store_id = $2
                    ORDER BY sequence_start ASC
                    "#,
                )
                .bind(tenant_id)
                .bind(store_id)
                .fetch_all(&mut *tx)
                .await?;

                if rows.is_empty() {
                    tx.commit().await?;
                    continue;
                }

                let last_anchored_idx = rows
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| r.chain_tx_hash.is_some())
                    .map(|(i, _)| i)
                    .last();

                let (mut idx, mut prev_end, mut current_prev_root) = if force {
                    (0usize, None, [0u8; 32])
                } else if let Some(i) = last_anchored_idx {
                    let end: u64 = rows[i]
                        .sequence_end
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("invalid sequence_end"))?;
                    let new_root = bytes32("new_state_root", &rows[i].new_state_root)?;
                    (i + 1, Some(end), new_root)
                } else {
                    (0usize, None, [0u8; 32])
                };

                let mut scanned: u64 = 0;
                let mut updated: u64 = 0;
                let mut would_update: u64 = 0;

                while idx < rows.len() {
                    let row = &rows[idx];
                    idx += 1;
                    scanned += 1;

                    let start: u64 = row
                        .sequence_start
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("invalid sequence_start"))?;
                    let end: u64 = row
                        .sequence_end
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("invalid sequence_end"))?;

                    if let Some(prev_end) = prev_end {
                        let expected_start = prev_end
                            .checked_add(1)
                            .ok_or_else(|| anyhow::anyhow!("commitment sequence overflow"))?;
                        if start != expected_start {
                            anyhow::bail!(
                                "non-contiguous VES commitments for {tenant_id}/{store_id}: expected start {expected_start}, found {start}"
                            );
                        }
                    }

                    let leaf_count: u32 = row
                        .leaf_count
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("invalid leaf_count"))?;

                    let expected_leaf_count: u32 = (end
                        .checked_sub(start)
                        .and_then(|d| d.checked_add(1))
                        .ok_or_else(|| anyhow::anyhow!("invalid sequence range"))?)
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("leaf_count overflow"))?;
                    if leaf_count != expected_leaf_count {
                        anyhow::bail!(
                            "invalid leaf_count for {tenant_id}/{store_id} batch {}: expected {expected_leaf_count}, found {leaf_count}",
                            row.batch_id
                        );
                    }

                    let merkle_root = bytes32("merkle_root", &row.merkle_root)?;

                    let expected_prev = current_prev_root;
                    let expected_new = compute_ves_state_root(
                        &tenant_id,
                        &store_id,
                        &expected_prev,
                        &merkle_root,
                        start,
                        end,
                        leaf_count,
                    );

                    let stored_prev = bytes32("prev_state_root", &row.prev_state_root)?;
                    let stored_new = bytes32("new_state_root", &row.new_state_root)?;

                    if stored_prev != expected_prev || stored_new != expected_new {
                        would_update += 1;
                        if !dry_run {
                            sqlx::query(
                                r#"
                                UPDATE ves_commitments
                                SET prev_state_root = $1,
                                    new_state_root = $2
                                WHERE batch_id = $3
                                "#,
                            )
                            .bind(&expected_prev[..])
                            .bind(&expected_new[..])
                            .bind(row.batch_id)
                            .execute(&mut *tx)
                            .await?;
                            updated += 1;
                        }
                    }

                    current_prev_root = expected_new;
                    prev_end = Some(end);
                }

                if dry_run {
                    println!(
                        "ok: stream={tenant_id}/{store_id} scanned={scanned} would_update={would_update} (dry run)"
                    );
                } else {
                    println!(
                        "ok: stream={tenant_id}/{store_id} scanned={scanned} updated={updated}"
                    );
                }

                total_scanned += scanned;
                total_updated += updated;
                total_would_update += would_update;

                tx.commit().await?;
            }

            if dry_run {
                println!(
                    "ok: streams={total_streams} scanned={total_scanned} would_update={total_would_update} (dry run)"
                );
            } else {
                println!(
                    "ok: streams={total_streams} scanned={total_scanned} updated={total_updated}"
                );
            }

            Ok(())
        }
        "ves-commit-and-anchor" => {
            let mut database_url: Option<String> = None;
            let mut tenant_id: Option<Uuid> = None;
            let mut store_id: Option<Uuid> = None;
            let mut sequence_start: Option<u64> = None;
            let mut sequence_end: Option<u64> = None;
            let mut max_events: u64 = 1024;

            while let Some(arg) = args.pop_front() {
                match arg.as_str() {
                    "--database-url" => {
                        database_url =
                            Some(args.pop_front().ok_or_else(|| {
                                anyhow::anyhow!("missing value for --database-url")
                            })?);
                    }
                    "--tenant-id" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --tenant-id"))?;
                        tenant_id = Some(Uuid::parse_str(&raw)?);
                    }
                    "--store-id" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --store-id"))?;
                        store_id = Some(Uuid::parse_str(&raw)?);
                    }
                    "--sequence-start" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --sequence-start"))?;
                        sequence_start = Some(raw.parse()?);
                    }
                    "--sequence-end" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --sequence-end"))?;
                        sequence_end = Some(raw.parse()?);
                    }
                    "--max-events" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --max-events"))?;
                        max_events = raw.parse()?;
                    }
                    "-h" | "--help" => {
                        print_help();
                        return Ok(());
                    }
                    other => anyhow::bail!("unexpected argument: {other}"),
                }
            }

            let tenant_id = tenant_id.ok_or_else(|| anyhow::anyhow!("--tenant-id is required"))?;
            let store_id = store_id.ok_or_else(|| anyhow::anyhow!("--store-id is required"))?;

            if sequence_start.is_some() ^ sequence_end.is_some() {
                anyhow::bail!("--sequence-start and --sequence-end must be provided together");
            }

            let database_url = require_database_url(database_url)?;
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&database_url)
                .await?;
            stateset_sequencer::migrations::run_postgres(&pool).await?;

            let anchor_config = AnchorConfig::from_env()
                .ok_or_else(|| anyhow::anyhow!("anchor service not configured in env"))?;
            let anchor_service = AnchorService::new(anchor_config);

            let engine = stateset_sequencer::infra::PgVesCommitmentEngine::new(pool.clone());

            let (start, end) = if let (Some(start), Some(end)) = (sequence_start, sequence_end) {
                (start, end)
            } else {
                let head = head_sequence(&pool, &tenant_id, &store_id).await?;
                if head == 0 {
                    anyhow::bail!("no events to commit (head_sequence=0)");
                }

                let last_end = engine
                    .last_sequence_end(
                        &TenantId::from_uuid(tenant_id),
                        &StoreId::from_uuid(store_id),
                    )
                    .await?;
                let start = last_end.map(|v| v.saturating_add(1)).unwrap_or(1);
                if start > head {
                    anyhow::bail!("no new events to commit (head_sequence={head})");
                }
                let max_events = max_events.max(1);
                let end = start
                    .checked_add(max_events.saturating_sub(1))
                    .unwrap_or(u64::MAX)
                    .min(head);
                (start, end)
            };

            let commitment = engine
                .create_and_store_commitment(
                    &TenantId::from_uuid(tenant_id),
                    &StoreId::from_uuid(store_id),
                    (start, end),
                )
                .await?;

            if commitment.is_anchored() {
                println!(
                    "ok: already anchored batch_id={} chain_tx_hash={}",
                    commitment.batch_id,
                    commitment
                        .chain_tx_hash
                        .map(hex::encode)
                        .unwrap_or_default()
                );
                return Ok(());
            }

            let (tx_hash, chain_block_number) =
                anchor_service.anchor_ves_commitment(&commitment).await?;

            engine
                .update_chain_tx(
                    commitment.batch_id,
                    anchor_service.chain_id() as u32,
                    tx_hash,
                    chain_block_number,
                )
                .await?;

            println!(
                "ok: anchored batch_id={} tx_hash={} block={}",
                commitment.batch_id,
                hex::encode(tx_hash),
                chain_block_number
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            );
            Ok(())
        }
        other => {
            eprintln!("unknown command: {other}\n");
            print_help();
            anyhow::bail!("unknown command: {other}");
        }
    }
}
