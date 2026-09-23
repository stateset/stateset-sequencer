#!/usr/bin/env bash
# Read-only check that deployed UUPS proxies point to the exact compiled
# implementation artifacts used by the local idempotency drills.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
foundry_bin="${FOUNDRY_BIN:-${HOME}/.foundry/bin}"
artifact_dir="${CONTRACT_ARTIFACTS:-../set/contracts/out_ar}"
[[ -x "$foundry_bin/cast" ]] || { echo "Missing cast" >&2; exit 1; }
for name in ANCHOR_RPC_URL SET_REGISTRY_ADDRESS SETTLEMENT_RPC_URL SET_PAYMENT_BATCH_ADDRESS; do
  [[ -n "${!name:-}" ]] || { echo "Missing $name" >&2; exit 1; }
done
slot=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
check_proxy() {
  local rpc="$1" proxy="$2" artifact="$3" impl_word impl actual proxy_code
  jq -e '.deployedBytecode.object | test("^(0x)?[0-9a-fA-F]+$")' "$artifact" >/dev/null
  impl_word="$("$foundry_bin/cast" storage "$proxy" "$slot" --rpc-url "$rpc")"
  impl="0x${impl_word: -40}"
  proxy_code="$("$foundry_bin/cast" code "$proxy" --rpc-url "$rpc")"
  printf '%s' "$proxy_code" | python3 scripts/compare_contract_runtime.py \
    "$artifact_dir/ERC1967Proxy.sol/ERC1967Proxy.json" "$impl"
  actual="$("$foundry_bin/cast" code "$impl" --rpc-url "$rpc")"
  printf '%s' "$actual" | python3 scripts/compare_contract_runtime.py "$artifact" "$impl"
  echo "matched proxy=$proxy implementation=$impl artifact=$artifact"
}
check_proxy "$ANCHOR_RPC_URL" "$SET_REGISTRY_ADDRESS" \
  "$artifact_dir/SetRegistry.sol/SetRegistry.json"
check_proxy "$SETTLEMENT_RPC_URL" "$SET_PAYMENT_BATCH_ADDRESS" \
  "$artifact_dir/SetPaymentBatch.sol/SetPaymentBatch.json"
