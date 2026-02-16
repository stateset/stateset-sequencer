#!/bin/bash
#
# StateSet VES + STARK Zero-Knowledge Compliance Demo
#
# This is a thin wrapper around `scripts/zk_compliance_demo.mjs`.
#
# Env:
# - SEQUENCER_URL (default http://localhost:8080)
# - SEQUENCER_API_KEY (optional; sent as `Authorization: ApiKey <key>`)
# - STATESET_STARK_DIR (optional; default resolves to ../../stateset-stark)
# - VES_STARK_CLI (optional; path to `ves-stark` binary)
# - TENANT_ID / STORE_ID / AMOUNT / THRESHOLD (optional)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
node "${SCRIPT_DIR}/zk_compliance_demo.mjs"
