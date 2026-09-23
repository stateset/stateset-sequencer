#!/usr/bin/env bash
# Deploy the supplied SetRegistry artifact to an owned loopback Anvil and
# exercise lost-local-record replay through AnchorService.
set -euo pipefail
umask 077
cd "$(dirname "${BASH_SOURCE[0]}")/.."
foundry_bin="${FOUNDRY_BIN:-${HOME}/.foundry/bin}"
artifact_dir="${ANCHOR_CONTRACT_ARTIFACTS:-../set/contracts/out_ar}"
registry_artifact="$artifact_dir/SetRegistry.sol/SetRegistry.json"
proxy_artifact="$artifact_dir/ERC1967Proxy.sol/ERC1967Proxy.json"
for tool in "$foundry_bin/anvil" "$foundry_bin/cast"; do
  [[ -x "$tool" ]] || { echo "Missing Foundry executable: $tool" >&2; exit 1; }
done
for artifact in "$registry_artifact" "$proxy_artifact"; do
  jq -e '.bytecode.object | test("^(0x)?[0-9a-fA-F]+$")' "$artifact" >/dev/null
done
drill_dir="$(mktemp -d /tmp/sequencer-anchor.XXXXXX)"
echo "Anchor drill artifacts: $drill_dir"
sha256sum "$registry_artifact" "$proxy_artifact" >"$drill_dir/contract-artifacts.sha256"
"$foundry_bin/anvil" --host 127.0.0.1 --port 0 --chain-id 31337 \
  --mnemonic 'test test test test test test test test test test test junk' \
  >"$drill_dir/anvil.log" 2>&1 &
node_pid=$!
cleanup() {
  if kill -0 "$node_pid" 2>/dev/null; then kill -TERM "$node_pid"; fi
  wait "$node_pid" 2>/dev/null || true
}
trap cleanup EXIT
port=""
for (( attempt = 0; attempt < 100; attempt++ )); do
  kill -0 "$node_pid" 2>/dev/null || { echo "Owned Anvil node exited" >&2; exit 1; }
  port="$(sed -nE 's/.*Listening on 127\.0\.0\.1:([0-9]+).*/\1/p' "$drill_dir/anvil.log" | head -n 1)"
  [[ "$port" =~ ^[0-9]+$ ]] && break
  sleep 0.1
done
[[ "$port" =~ ^[0-9]+$ ]] || { echo "Owned Anvil node did not start" >&2; exit 1; }
rpc="http://127.0.0.1:$port"
cast_cmd=("$foundry_bin/cast")
[[ "$("${cast_cmd[@]}" chain-id --rpc-url "$rpc")" == 31337 ]]
# Public Anvil account 0. No operator key or external RPC is accepted.
key=ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
owner="$("${cast_cmd[@]}" wallet address --private-key "$key")"
deploy() {
  local artifact="$1" args="${2:-0x}" bytecode
  bytecode="$(jq -r '.bytecode.object' "$artifact")"
  bytecode="0x${bytecode#0x}${args#0x}"
  "${cast_cmd[@]}" send --rpc-url "$rpc" --private-key "$key" --json --create "$bytecode" \
    | jq -er '.contractAddress | select(. != null)'
}
implementation="$(deploy "$registry_artifact")"
initializer="$("${cast_cmd[@]}" calldata 'initialize(address,address)' "$owner" "$owner")"
proxy_args="$("${cast_cmd[@]}" abi-encode 'constructor(address,bytes)' "$implementation" "$initializer")"
registry="$(deploy "$proxy_artifact" "$proxy_args")"
slot=0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
stored_impl="$("${cast_cmd[@]}" storage "$registry" "$slot" --rpc-url "$rpc")"
[[ "0x${stored_impl: -40}" == "${implementation,,}" ]] || {
  echo "Registry proxy points to unexpected implementation" >&2; exit 1;
}
runtime="$("${cast_cmd[@]}" code "$implementation" --rpc-url "$rpc")"
printf '%s' "$runtime" | python3 scripts/compare_contract_runtime.py "$registry_artifact" "$implementation"
ANCHOR_RPC_URL="$rpc" SET_REGISTRY_ADDRESS="$registry" ANCHOR_PRIVATE_KEY="$key" \
  cargo test --locked --no-default-features --test anchor_onchain_test \
    -- --exact anchoring_is_idempotent_across_a_lost_local_record --nocapture \
    | tee "$drill_dir/test.log"
rg -q 'test anchoring_is_idempotent_across_a_lost_local_record ... ok' "$drill_dir/test.log"
jq -n --arg registry "$registry" --arg implementation "$implementation" \
  '{status:"passed", chain_id:31337, registry:$registry, implementation:$implementation,
    verified:["first submission succeeds", "lost-record retry sends no transaction",
      "stored batch remains verifiable"],
    scope:"owned local EVM and supplied artifact; deployed network bytecode checked separately"}' \
  | tee "$drill_dir/result.json"
