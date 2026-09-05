# Funded settlement replay drill

Run `bash scripts/run_settlement_drill.sh` to exercise the actual Rust
`SettlementService` against a freshly deployed local `SetPaymentBatch` proxy
and a mock ERC20. This is separate from the older unauthorized-payment smoke
test: success requires an authorized transfer and balance assertions.

## Prerequisites

- Anvil and Cast in `~/.foundry/bin`, or set `FOUNDRY_BIN` to their directory.
- jq, SHA-256 tooling, and the repository's Rust build dependencies.
- Compiled artifacts from the canonical payment-contract repository. Set
  `SETTLEMENT_CONTRACT_ARTIFACTS` to its output directory (default:
  `../set/contracts/out_ar`). Required relative files:
  `SetPaymentBatch.sol/SetPaymentBatch.json`,
  `ERC1967Proxy.sol/ERC1967Proxy.json`, and
  `DeployX402Test.s.sol/MockERC20.json`.

Build these artifacts using that repository's documented build configuration.
The drill uses the supplied bytecode and records hashes and compiler/source
metadata; it does not establish correspondence with deployed production code.
`SETTLEMENT_TEST_BINARY` may select an already-built `settlement_onchain_test`
executable; otherwise the script performs a locked core-feature build.

## Checks and isolation

The harness creates its own loopback-only Anvil process on an automatically
allocated port, with chain ID 31337 and the **public Anvil development mnemonic**.
It accepts no external RPC URL or operator wallet keys. It deploys the mock
token, implementation, and proxy, funds the test payer, and grants allowance.

The Rust fixture signs a real EIP-712 authorization and checks:

1. Settlement succeeds and reports the payment as settled, not skipped.
2. A fresh service instance recovers the result without any local settlement
   record and without consuming another settler transaction nonce.
3. Payer and payee balances reflect exactly one transfer.
4. Bypassing the service pre-check and forcing a mined duplicate-batch
   transaction results in an on-chain revert, with no balance change.
5. Reusing the paid intent under a new batch ID causes no second transfer.

The script requires the funded-test success marker, so a skipped test cannot
produce a passing report. It stops only its owned Anvil process on exit.
Synthetic transaction receipts, logs, artifact provenance, executable hash,
and JSON results remain in the printed `/tmp/sequencer-settlement.*` directory.
The Anvil log contains public development keys, never production keys.

This demonstrates local destination-enforced duplicate protection for the
tested payment bytecode. It is not a network-partition simulation, anchoring
test, finality/reorganization test, or proof of production deployment settings.
Normal Rust test runs skip the funded fixture unless the harness opt-in is set;
run this script explicitly for release qualification.
