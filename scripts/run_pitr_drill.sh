#!/usr/bin/env bash
# Physical backup and named-restore-point WAL replay in owned local containers.
set -euo pipefail
umask 077
cd "$(dirname "${BASH_SOURCE[0]}")/.."

for tool in docker jq sha256sum tar; do
  command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }
done
drill_image="${RECOVERY_POSTGRES_IMAGE:-postgres:16-alpine}"
docker image inspect "$drill_image" >/dev/null
drill_binary="${RECOVERY_TEST_BINARY:-}"
if [[ -z "$drill_binary" ]]; then
  drill_binary="$(cargo test --locked --no-default-features --test recovery_drill_test --no-run --message-format=json |
    jq -r 'select(.reason == "compiler-artifact" and .target.name == "recovery_drill_test" and .executable != null) | .executable')"
fi
[[ -x "$drill_binary" ]] || { echo "Recovery fixture executable not found" >&2; exit 1; }

drill_dir="$(mktemp -d /tmp/sequencer-pitr.XXXXXX)"
drill_id="${drill_dir##*/}"
drill_source="${drill_id}-source"
drill_restore="${drill_id}-restore"
drill_label="stateset.pitr-drill"
cleanup() {
  local container owner
  for container in "$drill_source" "$drill_restore"; do
    owner="$(docker inspect --format "{{ index .Config.Labels \"$drill_label\" }}" "$container" 2>/dev/null || true)"
    if [[ "$owner" == "$drill_id" ]]; then docker rm -fv "$container" >/dev/null; fi
  done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_database() {
  local attempt
  for (( attempt = 0; attempt < 120; attempt++ )); do
    if docker exec "$1" pg_isready -h 127.0.0.1 -U sequencer -d sequencer_review >/dev/null 2>&1 &&
      [[ "$(docker exec "$1" psql -X -At -U sequencer -d sequencer_review -c 'SELECT pg_is_in_recovery()' 2>/dev/null)" == f ]]; then
      return
    fi
    [[ "$(docker inspect --format '{{.State.Running}}' "$1")" == true ]] || break
    sleep 0.5
  done
  docker logs "$1" >&2
  echo "Disposable database did not become ready: $1" >&2
  return 1
}
database_url() {
  local binding port
  binding="$(docker port "$1" 5432/tcp)"
  [[ "$binding" == 127.0.0.1:* ]] || { echo "Database must bind loopback only" >&2; return 1; }
  port="${binding##*:}"
  [[ "$port" =~ ^[0-9]+$ ]] || return 1
  echo "postgres://sequencer:sequencer@127.0.0.1:$port/sequencer_review"
}
fixture() {
  DATABASE_URL="$(database_url "$1")" SEQUENCER_RECOVERY_PHASE="$2" \
    SEQUENCER_RECOVERY_FIXTURE="$drill_dir/acknowledged.json" \
    "$drill_binary" --ignored --exact recovery_fixture --nocapture
}
psql_source() {
  docker exec "$drill_source" psql -X -At -v ON_ERROR_STOP=1 -U sequencer -d sequencer_review -c "$1"
}

echo "PITR drill artifacts: $drill_dir"
docker run --pull=never -d --name "$drill_source" --label "$drill_label=$drill_id" \
  -e POSTGRES_USER=sequencer -e POSTGRES_PASSWORD=sequencer -e POSTGRES_DB=sequencer_review \
  -p 127.0.0.1::5432 "$drill_image" postgres -c wal_level=replica \
  -c archive_mode=on \
  -c "archive_command=mkdir -p /tmp/wal_archive && cp %p /tmp/wal_archive/%f.partial && mv /tmp/wal_archive/%f.partial /tmp/wal_archive/%f" >/dev/null
wait_database "$drill_source"
[[ "$(psql_source "SHOW archive_mode")" == on ]]
[[ "$(psql_source "SHOW full_page_writes")" == on ]]

# Take a physical backup before the acknowledged fixture is written. All 128
# events and their receipts must subsequently arrive through archived WAL.
docker exec "$drill_source" pg_basebackup -h 127.0.0.1 -U sequencer -D /tmp/pitr-base -Ft -X stream
docker cp "$drill_source:/tmp/pitr-base/base.tar" "$drill_dir/base.tar"
docker cp "$drill_source:/tmp/pitr-base/pg_wal.tar" "$drill_dir/pg_wal.tar"
fixture "$drill_source" seed | tee "$drill_dir/seed.log"
fixture "$drill_source" verify | tee "$drill_dir/baseline.log"
restore_lsn="$(psql_source "SELECT pg_create_restore_point('stateset_acknowledged')")"

# Commit a change after the recovery target. The restored head must be 128,
# proving that recovery stopped at the named point rather than at the WAL end.
psql_source "UPDATE ves_sequence_counters SET current_sequence = current_sequence + 1000" >/dev/null
[[ "$(psql_source "SELECT min(current_sequence) FROM ves_sequence_counters")" == 1128 ]]
restore_segment="$(psql_source "SELECT pg_walfile_name('$restore_lsn'::pg_lsn)")"
psql_source "SELECT pg_switch_wal()" >/dev/null
for (( attempt = 0; attempt < 120; attempt++ )); do
  failed_archives="$(psql_source "SELECT failed_count FROM pg_stat_archiver")"
  [[ "$failed_archives" == 0 ]] || { echo "WAL archiver failed" >&2; exit 1; }
  # The archive command publishes this name only after the copy completes.
  if docker exec "$drill_source" test -f "/tmp/wal_archive/$restore_segment"; then break; fi
  sleep 0.5
done
docker exec "$drill_source" test -f "/tmp/wal_archive/$restore_segment" || {
  echo "Restore-point WAL segment was not archived" >&2; exit 1;
}
docker cp "$drill_source:/tmp/wal_archive" "$drill_dir/wal_archive"
# docker cp preserves the local umask; PostgreSQL runs as an unprivileged user
# in the restore container and must be able to read these copied WAL files.
chmod -R a+rX "$drill_dir/wal_archive"

mkdir "$drill_dir/restore_data"
tar -xf "$drill_dir/base.tar" -C "$drill_dir/restore_data"
mkdir -p "$drill_dir/restore_data/pg_wal"
tar -xf "$drill_dir/pg_wal.tar" -C "$drill_dir/restore_data/pg_wal"
touch "$drill_dir/restore_data/recovery.signal"
docker create --name "$drill_restore" --label "$drill_label=$drill_id" \
  -e POSTGRES_USER=sequencer -e POSTGRES_PASSWORD=sequencer -e POSTGRES_DB=sequencer_review \
  -p 127.0.0.1::5432 "$drill_image" postgres \
  -c "restore_command=cp /tmp/wal_archive/%f %p" \
  -c recovery_target_name=stateset_acknowledged \
  -c recovery_target_action=promote >/dev/null
docker cp "$drill_dir/restore_data/." "$drill_restore:/var/lib/postgresql/data/"
docker cp "$drill_dir/wal_archive" "$drill_restore:/tmp/wal_archive"
restore_start="$(date +%s)"
docker start "$drill_restore" >/dev/null
wait_database "$drill_restore"
fixture "$drill_restore" verify | tee "$drill_dir/pitr-verify.log"
fixture "$drill_restore" resume | tee "$drill_dir/pitr-projection-resume.log"
restore_and_validation_seconds=$(( $(date +%s) - restore_start ))

jq -n --arg image "$drill_image" --arg commit "$(git rev-parse HEAD)" \
  --arg binary_sha256 "$(sha256sum "$drill_binary" | cut -d ' ' -f 1)" \
  --arg restore_lsn "$restore_lsn" --argjson restore_and_validation_seconds "$restore_and_validation_seconds" \
  '{status:"passed", invoking_checkout_commit:$commit, fixture_binary_sha256:$binary_sha256,
    postgres_image:$image, restore_point_lsn:$restore_lsn, acknowledged_events:128,
    missing_acknowledged_events:0, post_target_counter_update_excluded:true,
    restore_and_validation_seconds:$restore_and_validation_seconds,
    verified:["physical base backup", "archived WAL replay", "named restore point", "post-target write exclusion",
      "128 event payloads", "agent key", "sequence head", "idempotent replay", "signed receipts",
      "persisted commitment", "all inclusion proofs", "projection catch-up"],
    scope:"local physical backup and archived-WAL PITR; not standby failover, host failure, production RPO or RTO"}' \
  | tee "$drill_dir/result.json"
echo "Passed. Owned containers/volumes will be removed; evidence remains in $drill_dir"
