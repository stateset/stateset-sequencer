use std::collections::VecDeque;

use chrono;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use stateset_sequencer::anchor::{AnchorConfig, AnchorService};
use stateset_sequencer::crypto::{
    compute_stream_id, compute_ves_compliance_policy_hash,
    compute_ves_compliance_proof_at_rest_aad, compute_ves_compliance_proof_hash,
    compute_ves_state_root, compute_ves_validity_proof_at_rest_aad,
    compute_ves_validity_proof_hash, is_payload_at_rest_encrypted, ComplianceProofAadParams,
    Hash256,
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
  migrate                         Run database migrations
  verify-proof                    Verify an inclusion proof
  export-events                   Export events to JSON/NDJSON file
  rotate-keys                     Rotate agent signing keys
  list-agent-keys                 List agent keys for a tenant
  reencrypt-events                Re-encrypt event payloads with new key
  reencrypt-ves-validity-proofs   Re-encrypt validity proofs
  reencrypt-ves-compliance-proofs Re-encrypt compliance proofs
  backfill-ves-state-roots        Backfill VES state roots
  ves-commit-and-anchor           Create and anchor a VES commitment

COMMON OPTIONS:
  --database-url <postgres_url>    (defaults to env DATABASE_URL)

verify-proof OPTIONS:
  --leaf-hash <hex>               (required) Hex-encoded leaf hash
  --merkle-root <hex>             (required) Hex-encoded Merkle root
  --proof-path <hex,hex,...>      (required) Comma-separated hex proof hashes
  --leaf-index <n>                (required) Leaf index in the tree

export-events OPTIONS:
  --tenant-id <uuid>              (required)
  --store-id <uuid>               (required)
  --from <n>                      (optional) Starting sequence number
  --to <n>                        (optional) Ending sequence number
  --output <path>                 (optional) Output file path (default: stdout)
  --format <json|ndjson>          (default: ndjson)

rotate-keys OPTIONS:
  --tenant-id <uuid>              (required)
  --agent-id <uuid>               (required)
  --new-key-id <n>                (required) New key ID
  --public-key <hex>              (required) New Ed25519 public key (hex)
  --revoke-old                    (optional) Revoke all previous keys

list-agent-keys OPTIONS:
  --tenant-id <uuid>              (required)
  --agent-id <uuid>               (optional) Filter by agent

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

                    if is_encrypted && !force
                        && payload_encryption
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

                    if is_encrypted && !force
                        && payload_encryption
                            .decrypt_payload_with_current_key(&row.tenant_id, &aad, &row.proof)
                            .await
                            .is_ok()
                        {
                            skipped_current_key += 1;
                            continue;
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
                    let aad = compute_ves_compliance_proof_at_rest_aad(&ComplianceProofAadParams {
                        tenant_id: &row.tenant_id,
                        store_id: &row.store_id,
                        event_id: &row.event_id,
                        proof_id: &row.proof_id,
                        policy_hash: &policy_hash,
                        proof_type: &row.proof_type,
                        proof_version: row.proof_version as u32,
                        proof_hash: &proof_hash,
                    });

                    let is_encrypted = is_payload_at_rest_encrypted(&row.proof);

                    if is_encrypted && !force
                        && payload_encryption
                            .decrypt_payload_with_current_key(&row.tenant_id, &aad, &row.proof)
                            .await
                            .is_ok()
                        {
                            skipped_current_key += 1;
                            continue;
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
                    .next_back();

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
        "verify-proof" => {
            let mut leaf_hash: Option<String> = None;
            let mut merkle_root: Option<String> = None;
            let mut proof_path: Option<String> = None;
            let mut leaf_index: Option<usize> = None;

            while let Some(arg) = args.pop_front() {
                match arg.as_str() {
                    "--leaf-hash" => {
                        leaf_hash = Some(
                            args.pop_front()
                                .ok_or_else(|| anyhow::anyhow!("missing value for --leaf-hash"))?,
                        );
                    }
                    "--merkle-root" => {
                        merkle_root = Some(
                            args.pop_front()
                                .ok_or_else(|| anyhow::anyhow!("missing value for --merkle-root"))?,
                        );
                    }
                    "--proof-path" => {
                        proof_path = Some(
                            args.pop_front()
                                .ok_or_else(|| anyhow::anyhow!("missing value for --proof-path"))?,
                        );
                    }
                    "--leaf-index" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --leaf-index"))?;
                        leaf_index = Some(raw.parse()?);
                    }
                    "-h" | "--help" => {
                        print_help();
                        return Ok(());
                    }
                    other => anyhow::bail!("unexpected argument: {other}"),
                }
            }

            let leaf_hash = leaf_hash.ok_or_else(|| anyhow::anyhow!("--leaf-hash is required"))?;
            let merkle_root =
                merkle_root.ok_or_else(|| anyhow::anyhow!("--merkle-root is required"))?;
            let proof_path =
                proof_path.ok_or_else(|| anyhow::anyhow!("--proof-path is required"))?;
            let leaf_index =
                leaf_index.ok_or_else(|| anyhow::anyhow!("--leaf-index is required"))?;

            let leaf_bytes = hex::decode(&leaf_hash)
                .map_err(|_| anyhow::anyhow!("invalid hex for --leaf-hash"))?;
            let leaf: Hash256 = leaf_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("--leaf-hash must be 32 bytes"))?;

            let root_bytes = hex::decode(&merkle_root)
                .map_err(|_| anyhow::anyhow!("invalid hex for --merkle-root"))?;
            let root: Hash256 = root_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("--merkle-root must be 32 bytes"))?;

            let proof_hashes: Vec<Hash256> = proof_path
                .split(',')
                .map(|h| {
                    let bytes = hex::decode(h.trim())
                        .map_err(|_| anyhow::anyhow!("invalid hex in proof path: {h}"))?;
                    bytes
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("proof hash must be 32 bytes: {h}"))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;

            // Verify the proof using rs_merkle
            use rs_merkle::{algorithms::Sha256, MerkleProof};

            let proof = MerkleProof::<Sha256>::new(proof_hashes.clone());
            let indices = [leaf_index];
            let leaves = [leaf];

            // Calculate the total tree size from the proof path length
            let tree_depth = proof_hashes.len();
            let total_leaves = 1usize << tree_depth;

            let is_valid = proof.verify(
                root,
                &indices,
                &leaves,
                total_leaves,
            );

            if is_valid {
                println!("ok: proof is VALID");
                println!("  leaf_hash:   {}", hex::encode(leaf));
                println!("  leaf_index:  {}", leaf_index);
                println!("  merkle_root: {}", hex::encode(root));
                println!("  proof_depth: {}", tree_depth);
            } else {
                println!("FAIL: proof is INVALID");
                std::process::exit(1);
            }
            Ok(())
        }
        "export-events" => {
            use std::io::Write;

            let mut database_url: Option<String> = None;
            let mut tenant_id: Option<Uuid> = None;
            let mut store_id: Option<Uuid> = None;
            let mut from_seq: Option<u64> = None;
            let mut to_seq: Option<u64> = None;
            let mut output_path: Option<String> = None;
            let mut format = "ndjson".to_string();

            while let Some(arg) = args.pop_front() {
                match arg.as_str() {
                    "--database-url" => {
                        database_url = Some(
                            args.pop_front()
                                .ok_or_else(|| anyhow::anyhow!("missing value for --database-url"))?,
                        );
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
                    "--from" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --from"))?;
                        from_seq = Some(raw.parse()?);
                    }
                    "--to" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --to"))?;
                        to_seq = Some(raw.parse()?);
                    }
                    "--output" => {
                        output_path = Some(
                            args.pop_front()
                                .ok_or_else(|| anyhow::anyhow!("missing value for --output"))?,
                        );
                    }
                    "--format" => {
                        format = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --format"))?;
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

            if !matches!(format.as_str(), "json" | "ndjson") {
                anyhow::bail!("--format must be 'json' or 'ndjson'");
            }

            let database_url = require_database_url(database_url)?;
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&database_url)
                .await?;

            #[derive(Debug, serde::Serialize, sqlx::FromRow)]
            struct ExportRow {
                event_id: Uuid,
                sequence_number: i64,
                event_type: String,
                entity_type: String,
                entity_id: String,
                payload: serde_json::Value,
                created_at: chrono::DateTime<chrono::Utc>,
            }

            let rows: Vec<ExportRow> = sqlx::query_as(
                r#"
                SELECT
                    event_id,
                    sequence_number,
                    event_type,
                    entity_type,
                    entity_id,
                    payload,
                    created_at
                FROM ves_events
                WHERE tenant_id = $1
                  AND store_id = $2
                  AND ($3::bigint IS NULL OR sequence_number >= $3)
                  AND ($4::bigint IS NULL OR sequence_number <= $4)
                ORDER BY sequence_number ASC
                "#,
            )
            .bind(tenant_id)
            .bind(store_id)
            .bind(from_seq.map(|v| v as i64))
            .bind(to_seq.map(|v| v as i64))
            .fetch_all(&pool)
            .await?;

            let mut output: Box<dyn Write> = match output_path {
                Some(path) => Box::new(std::fs::File::create(&path)?),
                None => Box::new(std::io::stdout()),
            };

            match format.as_str() {
                "json" => {
                    serde_json::to_writer_pretty(&mut output, &rows)?;
                    writeln!(output)?;
                }
                "ndjson" => {
                    for row in &rows {
                        serde_json::to_writer(&mut output, row)?;
                        writeln!(output)?;
                    }
                }
                _ => unreachable!(),
            }

            eprintln!("ok: exported {} events", rows.len());
            Ok(())
        }
        "list-agent-keys" => {
            let mut database_url: Option<String> = None;
            let mut tenant_id: Option<Uuid> = None;
            let mut agent_id: Option<Uuid> = None;

            while let Some(arg) = args.pop_front() {
                match arg.as_str() {
                    "--database-url" => {
                        database_url = Some(
                            args.pop_front()
                                .ok_or_else(|| anyhow::anyhow!("missing value for --database-url"))?,
                        );
                    }
                    "--tenant-id" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --tenant-id"))?;
                        tenant_id = Some(Uuid::parse_str(&raw)?);
                    }
                    "--agent-id" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --agent-id"))?;
                        agent_id = Some(Uuid::parse_str(&raw)?);
                    }
                    "-h" | "--help" => {
                        print_help();
                        return Ok(());
                    }
                    other => anyhow::bail!("unexpected argument: {other}"),
                }
            }

            let tenant_id = tenant_id.ok_or_else(|| anyhow::anyhow!("--tenant-id is required"))?;

            let database_url = require_database_url(database_url)?;
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&database_url)
                .await?;

            #[derive(Debug, sqlx::FromRow)]
            struct KeyRow {
                agent_id: Uuid,
                key_id: i32,
                public_key: Vec<u8>,
                active: bool,
                valid_from: Option<chrono::DateTime<chrono::Utc>>,
                valid_to: Option<chrono::DateTime<chrono::Utc>>,
                created_at: chrono::DateTime<chrono::Utc>,
            }

            let rows: Vec<KeyRow> = sqlx::query_as(
                r#"
                SELECT
                    agent_id,
                    key_id,
                    public_key,
                    active,
                    valid_from,
                    valid_to,
                    created_at
                FROM ves_agent_keys
                WHERE tenant_id = $1
                  AND ($2::uuid IS NULL OR agent_id = $2)
                ORDER BY agent_id ASC, key_id ASC
                "#,
            )
            .bind(tenant_id)
            .bind(agent_id)
            .fetch_all(&pool)
            .await?;

            println!("Agent keys for tenant {}:", tenant_id);
            println!("{:-<100}", "");
            println!(
                "{:<36} {:>6} {:<8} {:<20} {:<20}",
                "agent_id", "key_id", "active", "valid_from", "valid_to"
            );
            println!("{:-<100}", "");

            for row in &rows {
                println!(
                    "{:<36} {:>6} {:<8} {:<20} {:<20}",
                    row.agent_id,
                    row.key_id,
                    if row.active { "yes" } else { "no" },
                    row.valid_from
                        .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    row.valid_to
                        .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                        .unwrap_or_else(|| "-".to_string()),
                );
                println!("  public_key: {}", hex::encode(&row.public_key));
            }

            println!("{:-<100}", "");
            println!("Total: {} keys", rows.len());
            Ok(())
        }
        "rotate-keys" => {
            let mut database_url: Option<String> = None;
            let mut tenant_id: Option<Uuid> = None;
            let mut agent_id: Option<Uuid> = None;
            let mut new_key_id: Option<i32> = None;
            let mut public_key: Option<String> = None;
            let mut revoke_old = false;

            while let Some(arg) = args.pop_front() {
                match arg.as_str() {
                    "--database-url" => {
                        database_url = Some(
                            args.pop_front()
                                .ok_or_else(|| anyhow::anyhow!("missing value for --database-url"))?,
                        );
                    }
                    "--tenant-id" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --tenant-id"))?;
                        tenant_id = Some(Uuid::parse_str(&raw)?);
                    }
                    "--agent-id" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --agent-id"))?;
                        agent_id = Some(Uuid::parse_str(&raw)?);
                    }
                    "--new-key-id" => {
                        let raw = args
                            .pop_front()
                            .ok_or_else(|| anyhow::anyhow!("missing value for --new-key-id"))?;
                        new_key_id = Some(raw.parse()?);
                    }
                    "--public-key" => {
                        public_key = Some(
                            args.pop_front()
                                .ok_or_else(|| anyhow::anyhow!("missing value for --public-key"))?,
                        );
                    }
                    "--revoke-old" => revoke_old = true,
                    "-h" | "--help" => {
                        print_help();
                        return Ok(());
                    }
                    other => anyhow::bail!("unexpected argument: {other}"),
                }
            }

            let tenant_id = tenant_id.ok_or_else(|| anyhow::anyhow!("--tenant-id is required"))?;
            let agent_id = agent_id.ok_or_else(|| anyhow::anyhow!("--agent-id is required"))?;
            let new_key_id = new_key_id.ok_or_else(|| anyhow::anyhow!("--new-key-id is required"))?;
            let public_key = public_key.ok_or_else(|| anyhow::anyhow!("--public-key is required"))?;

            let public_key_bytes = hex::decode(&public_key)
                .map_err(|_| anyhow::anyhow!("invalid hex for --public-key"))?;

            if public_key_bytes.len() != 32 {
                anyhow::bail!("--public-key must be 32 bytes (Ed25519 public key)");
            }

            let database_url = require_database_url(database_url)?;
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&database_url)
                .await?;

            let mut tx = pool.begin().await?;

            if revoke_old {
                let result = sqlx::query(
                    r#"
                    UPDATE ves_agent_keys
                    SET active = false
                    WHERE tenant_id = $1 AND agent_id = $2 AND active = true
                    "#,
                )
                .bind(tenant_id)
                .bind(agent_id)
                .execute(&mut *tx)
                .await?;

                eprintln!("Revoked {} existing keys", result.rows_affected());
            }

            sqlx::query(
                r#"
                INSERT INTO ves_agent_keys (tenant_id, agent_id, key_id, public_key, active, created_at)
                VALUES ($1, $2, $3, $4, true, NOW())
                ON CONFLICT (tenant_id, agent_id, key_id) DO UPDATE
                SET public_key = EXCLUDED.public_key,
                    active = true
                "#,
            )
            .bind(tenant_id)
            .bind(agent_id)
            .bind(new_key_id)
            .bind(&public_key_bytes)
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;

            println!(
                "ok: registered new key for agent {} with key_id {}",
                agent_id, new_key_id
            );
            if revoke_old {
                println!("  (all previous keys have been revoked)");
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
                let end = start.saturating_add(max_events.saturating_sub(1))
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
