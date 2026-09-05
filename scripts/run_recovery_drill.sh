#!/usr/bin/env bash
# Crash and logical-backup recovery against owned, disposable containers only.
set -euo pipefail
umask 077
cd "$(dirname "${BASH_SOURCE[0]}")/.."

for tool in docker jq sha256sum rg; do
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

drill_dir="$(mktemp -d /tmp/sequencer-recovery.XXXXXX)"
drill_id="${drill_dir##*/}"
drill_source="${drill_id}-source"
drill_restore="${drill_id}-restore"
drill_label="stateset.recovery-drill"
cleanup() {
  local container owner
  for container in "$drill_source" "$drill_restore"; do
    owner="$(docker inspect --format "{{ index .Config.Labels \"$drill_label\" }}" "$container" 2>/dev/null || true)"
    if [[ "$owner" == "$drill_id" ]]; then
      docker rm -fv "$container" >/dev/null
    fi
  done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start_database() {
  docker run --pull=never -d --name "$1" --label "$drill_label=$drill_id" \
    -e POSTGRES_USER=sequencer -e POSTGRES_PASSWORD=sequencer -e POSTGRES_DB=sequencer_review \
    -p 127.0.0.1::5432 "$drill_image" >/dev/null
}
wait_database() {
  local attempt
  for (( attempt = 0; attempt < 120; attempt++ )); do
    # The image briefly starts a Unix-socket-only bootstrap server. Wait for
    # TCP so we cannot mistake that temporary instance for final readiness.
    if docker exec "$1" pg_isready -h 127.0.0.1 -U sequencer -d sequencer_review >/dev/null 2>&1; then
      return
    fi
    sleep 0.5
  done
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

echo "Recovery drill artifacts: $drill_dir"
start_database "$drill_source"
wait_database "$drill_source"
fixture "$drill_source" seed | tee "$drill_dir/seed.log"
fixture "$drill_source" verify | tee "$drill_dir/baseline.log"

# Leave a deliberately wrong sequence head uncommitted when the database dies.
# Recovery must roll this transaction back while preserving acknowledged writes.
docker exec -e PGAPPNAME=stateset-recovery-uncommitted "$drill_source" \
  psql -v ON_ERROR_STOP=1 -U sequencer -d sequencer_review \
  -c 'BEGIN; UPDATE ves_sequence_counters SET current_sequence = current_sequence + 1000; SELECT pg_sleep(600); ROLLBACK;' \
  >"$drill_dir/uncommitted-transaction.log" 2>&1 &
pending_pid=$!
pending_ready=false
for (( attempt = 0; attempt < 60; attempt++ )); do
  pending_count="$(docker exec "$drill_source" psql -At -U sequencer -d sequencer_review \
    -c "SELECT count(*) FROM pg_stat_activity WHERE application_name = 'stateset-recovery-uncommitted' AND wait_event = 'PgSleep'")"
  if [[ "$pending_count" == "1" ]]; then pending_ready=true; break; fi
  sleep 0.1
done
[[ "$pending_ready" == true ]] || { echo "Uncommitted transaction did not reach fault point" >&2; exit 1; }

# Only the container created and labelled by this invocation can be targeted.
[[ "$(docker inspect --format "{{ index .Config.Labels \"$drill_label\" }}" "$drill_source")" == "$drill_id" ]]
crash_start="$(date +%s)"
docker kill --signal=KILL "$drill_source" >/dev/null
wait "$pending_pid" || true # The deliberate container kill terminates this session.
docker start "$drill_source" >/dev/null
wait_database "$drill_source"
fixture "$drill_source" verify | tee "$drill_dir/crash-recovery.log"
crash_seconds=$(( $(date +%s) - crash_start ))

docker exec "$drill_source" pg_dump -U sequencer -d sequencer_review -Fc -f /tmp/recovery.dump
docker cp "$drill_source:/tmp/recovery.dump" "$drill_dir/backup.dump"
# Preserve the lagging checkpoint in the backup before either database catches up.
fixture "$drill_source" resume | tee "$drill_dir/crash-projection-resume.log"
rg -q '^PROJECTION_RECOVERY_VERIFIED:' "$drill_dir/crash-projection-resume.log"
restore_start="$(date +%s)"
start_database "$drill_restore"
wait_database "$drill_restore"
docker cp "$drill_dir/backup.dump" "$drill_restore:/tmp/recovery.dump"
docker exec "$drill_restore" pg_restore --exit-on-error --no-owner -U sequencer \
  -d sequencer_review /tmp/recovery.dump
fixture "$drill_restore" verify | tee "$drill_dir/backup-restore.log"
restore_seconds=$(( $(date +%s) - restore_start ))
fixture "$drill_restore" resume | tee "$drill_dir/restore-projection-resume.log"
rg -q '^PROJECTION_RECOVERY_VERIFIED:' "$drill_dir/restore-projection-resume.log"

jq -n --arg image "$drill_image" --arg commit "$(git rev-parse HEAD)" \
  --arg binary_sha256 "$(sha256sum "$drill_binary" | cut -d ' ' -f 1)" \
  --argjson crash_seconds "$crash_seconds" --argjson restore_seconds "$restore_seconds" \
  '{status:"passed", invoking_checkout_commit:$commit, source_state:"working-tree",
    fixture_binary_sha256:$binary_sha256, postgres_image:$image,
    acknowledged_events:128, missing_acknowledged_events:0,
    crash_recovery_seconds:$crash_seconds, logical_restore_seconds:$restore_seconds,
    fsync:"on", full_page_writes:"on", synchronous_commit:"on",
    verified:["event payloads", "agent key", "sequence head", "uncommitted counter rollback", "idempotent replay",
      "signed receipts", "persisted commitment", "all inclusion proofs",
      "projection checkpoint and document restore", "projection catch-up 64 to 128", "projection worker restart without duplicate application"],
    scope:"local process crash between projection batches and logical backup; recovery timings exclude projection catch-up; not host failure, PITR, HA failover or production RTO"}' \
  | tee "$drill_dir/result.json"
echo "Passed. Owned containers/volumes will be removed; evidence remains in $drill_dir"
