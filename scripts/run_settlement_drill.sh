#!/usr/bin/env bash
# Prove funded replay safety on a fresh local EVM. Never accepts a remote RPC.
set -euo pipefail
umask 077
cd "$(dirname "${BASH_SOURCE[0]}")/.."
foundry_bin="${FOUNDRY_BIN:-${HOME}/.foundry/bin}"
drill_artifacts="${SETTLEMENT_CONTRACT_ARTIFACTS:-../set/contracts/out_ar}"
for tool in "$foundry_bin/anvil" "$foundry_bin/cast"; do
  [[ -x "$tool" ]] || { echo "Missing Foundry executable: $tool" >&2; exit 1; }
done
for tool in jq sha256sum; do command -v "$tool" >/dev/null; done
payment_artifact="$drill_artifacts/SetPaymentBatch.sol/SetPaymentBatch.json"
proxy_artifact="$drill_artifacts/ERC1967Proxy.sol/ERC1967Proxy.json"
token_artifact="$drill_artifacts/DeployX402Test.s.sol/MockERC20.json"
for artifact in "$payment_artifact" "$proxy_artifact" "$token_artifact"; do
  jq -e '.bytecode.object | test("^(0x)?[0-9a-fA-F]+$")' "$artifact" >/dev/null
done
drill_binary="${SETTLEMENT_TEST_BINARY:-}"
if [[ -z "$drill_binary" ]]; then
  drill_binary="$(cargo test --locked --no-default-features --test settlement_onchain_test --no-run --message-format=json |
    jq -r 'select(.reason == "compiler-artifact" and .target.name == "settlement_onchain_test" and .executable != null) | .executable')"
fi
[[ -x "$drill_binary" ]] || { echo "Settlement fixture executable not found" >&2; exit 1; }
drill_dir="$(mktemp -d /tmp/sequencer-settlement.XXXXXX)"
echo "Settlement drill artifacts: $drill_dir"
sha256sum "$payment_artifact" "$proxy_artifact" "$token_artifact" >"$drill_dir/contract-artifacts.sha256"
jq '{compiler:.metadata.compiler, compilation_target:.metadata.settings.compilationTarget,
  sources:.metadata.sources}' "$payment_artifact" >"$drill_dir/contract-provenance.json"

# Explicit public development mnemonic. No operator wallet keys or RPC are used.
"$foundry_bin/anvil" --host 127.0.0.1 --port 0 --chain-id 31337 \
  --mnemonic 'test test test test test test test test test test test junk' \
  >"$drill_dir/anvil.log" 2>&1 &
node_pid=$!
printf '%s\n' "$node_pid" >"$drill_dir/node.pid"
cleanup() {
  if kill -0 "$node_pid" 2>/dev/null; then kill -TERM "$node_pid"; fi
  wait "$node_pid" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
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
# Public Anvil account 0 (settler/deployer) and account 2 (payer).
settler_key=ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
payer_key=5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
settler="$("${cast_cmd[@]}" wallet address --private-key "$settler_key")"
payer="$("${cast_cmd[@]}" wallet address --private-key "$payer_key")"
zero=0x0000000000000000000000000000000000000000
deploy() {
  local artifact="$1" args="${2:-0x}" bytecode
  bytecode="$(jq -r '.bytecode.object' "$artifact")"
  bytecode="0x${bytecode#0x}${args#0x}"
  "${cast_cmd[@]}" send --rpc-url "$rpc" --private-key "$settler_key" --json --create "$bytecode" \
    | jq -er '.contractAddress | select(. != null)'
}
token_args="$("${cast_cmd[@]}" abi-encode 'constructor(string,string,uint8)' 'Drill USDC' USDC 6)"
token="$(deploy "$token_artifact" "$token_args")"
implementation="$(deploy "$payment_artifact")"
initializer="$("${cast_cmd[@]}" calldata 'initialize(address,address,address,address,address)' "$settler" "$settler" "$token" "$zero" "$zero")"
proxy_args="$("${cast_cmd[@]}" abi-encode 'constructor(address,bytes)' "$implementation" "$initializer")"
payment="$(deploy "$proxy_artifact" "$proxy_args")"
"${cast_cmd[@]}" send --rpc-url "$rpc" --private-key "$settler_key" "$token" 'mint(address,uint256)' "$payer" 100000000 --json >"$drill_dir/mint.json"
"${cast_cmd[@]}" send --rpc-url "$rpc" --private-key "$payer_key" "$token" 'approve(address,uint256)' "$payment" 100000000 --json >"$drill_dir/approve.json"

SETTLEMENT_RPC_URL="$rpc" SET_PAYMENT_BATCH_ADDRESS="$payment" SETTLER_PRIVATE_KEY="$settler_key" \
  SETTLEMENT_TEST_PAYER_KEY="$payer_key" SETTLEMENT_TEST_TOKEN_ADDRESS="$token" \
  SEQUENCER_LOCAL_SETTLEMENT_DRILL=1 \
  "$drill_binary" --exact funded_settlement_is_replay_safe --nocapture | tee "$drill_dir/test.log"
grep -q '^FUNDED_REPLAY_VERIFIED:' "$drill_dir/test.log"
jq -n --arg payment "$payment" --arg token "$token" \
  --arg bytecode_hash "$(jq -r '.bytecode.object' "$payment_artifact" | sha256sum | cut -d ' ' -f 1)" \
  --arg binary_hash "$(sha256sum "$drill_binary" | cut -d ' ' -f 1)" \
  '{status:"passed", chain_id:31337, payment_contract:$payment, token:$token,
    payment_bytecode_text_sha256:$bytecode_hash, fixture_binary_sha256:$binary_hash,
    verified:["authorized token transfer", "lost-record retry sends no transaction",
      "payer debited once", "payee credited once", "stale duplicate batch reverts on-chain",
      "same intent in new batch transfers nothing"],
    scope:"local EVM and supplied compiled artifacts; not production bytecode or partition fencing"}' \
  | tee "$drill_dir/result.json"
echo "Passed. Owned Anvil node will stop; synthetic evidence remains in $drill_dir"
