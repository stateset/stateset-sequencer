#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="${1:-load/sequencer_ingest.js}"
PROFILE="${2:-smoke}"
PROFILE_FILE="load/profiles/${PROFILE}.json"
OUT_DIR="${OUT_DIR:-load/results}"

if ! command -v k6 >/dev/null 2>&1; then
  echo "k6 not found. Install from https://k6.io/docs/get-started/installation/"
  exit 1
fi

if [ ! -f "$SCRIPT_PATH" ]; then
  echo "Load script not found: $SCRIPT_PATH"
  exit 1
fi

if [ ! -f "$PROFILE_FILE" ]; then
  echo "Profile not found: $PROFILE_FILE"
  exit 1
fi

mkdir -p "$OUT_DIR"

timestamp="$(date +%Y%m%d-%H%M%S)"
script_name="$(basename "$SCRIPT_PATH" .js)"
json_out="${OUT_DIR}/${script_name}-${PROFILE}-${timestamp}.json"
summary_out="${OUT_DIR}/${script_name}-${PROFILE}-${timestamp}-summary.json"

echo "Running k6 script: $SCRIPT_PATH"
echo "Profile: $PROFILE_FILE"
echo "Output: $json_out"

k6 run "$SCRIPT_PATH" \
  --tag "profile=${PROFILE}" \
  --tag "script=${script_name}" \
  --out "json=${json_out}" \
  --summary-export "${summary_out}" \
  --opts "${PROFILE_FILE}"

echo "Summary written to ${summary_out}"
