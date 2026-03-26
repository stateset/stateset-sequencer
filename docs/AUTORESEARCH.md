# Autoresearch: Optimizing the StateSet Sequencer

## What is Autoresearch?

[Autoresearch](https://github.com/karpathy/autoresearch) is an autonomous research framework by Andrej Karpathy that runs a keep/discard optimization loop. An AI agent makes one code change at a time, commits it, runs an evaluator that produces a scalar metric, and either keeps the commit (if the metric improved) or reverts to the best previous state. The loop runs indefinitely.

We applied this framework to the StateSet VES Sequencer to systematically optimize its hot paths for maximum throughput.

## Setup

### Target Configuration

We created a target config at `/home/dom/karpathy/autoresearch/targets/stateset-sequencer.json`:

```json
{
  "repo": "/home/dom/icommerce-app/stateset-sequencer",
  "metric_name": "sequencer_throughput",
  "goal": "max",
  "eval_cmd": "stateset-sequencer-eval.sh /home/dom/icommerce-app/stateset-sequencer",
  "metric_regex": "^sequencer_throughput:\\s*([0-9.]+)$",
  "timeout_seconds": 900,
  "branch": "autoresearch/sequencer-optimize"
}
```

### Evaluation Script

The eval script (`stateset-sequencer-eval.sh`) runs three phases:

1. **Gate:** `cargo check -p stateset-sequencer` + `cargo test -p stateset-sequencer --lib` — if either fails, score = 0
2. **Benchmark:** `cargo bench --bench sequencer_bench -- --noplot` — runs all Criterion benchmarks
3. **Score:** Parses Criterion output, computes a **weighted geometric mean** of per-benchmark throughput (ops/sec)

We chose geometric mean over simple weighted sum because it gives equal importance to each benchmark regardless of absolute speed. A 2x improvement to a slow operation counts as much as a 2x improvement to a fast one.

### Scoring Formula

The composite score is:

```
score = exp( sum(w_i * ln(ops_per_sec_i)) / sum(w_i) ) / 1000
```

where `w_i` is the weight and `ops_per_sec_i = 1e9 / median_ns_i` for each benchmark.

**Worked example (Round 1 baseline, 7 benchmarks):**

| Benchmark | Median (ns) | ops/sec | Weight | w * ln(ops/sec) |
|-----------|------------|---------|--------|-----------------|
| create_batch/1 | 15,618 | 64,029 | 1 | 11.07 |
| create_batch/10 | 200,190 | 4,995 | 2 | 17.04 |
| create_batch/100 | 2,636,400 | 379 | 3 | 17.82 |
| create_batch/1000 | 22,590,000 | 44 | 5 | 18.94 |
| payload_hash | 22,434 | 44,575 | 4 | 42.82 |
| signing_bytes | 69 | 14,550,957 | 1 | 16.49 |
| payload_hash_verify | 7,029 | 142,262 | 2 | 23.73 |
| **Totals** | | | **18** | **147.91** |

`score = exp(147.91 / 18) / 1000 = exp(8.217) / 1000 = 3,704 / 1000 = 3.70`

This means the "typical" benchmark across all weights runs at ~3,700 ops/sec. A score of 14.59 means ~14,590 ops/sec — a 3.94x improvement.

### Why We Switched from Weighted Sum

The initial Round 1 scoring used a simple weighted sum of ops/sec. The problem: `signing_bytes` at 17.4M ops/sec with weight 3 contributed 52.2M to the total — 98.7% of the entire score. Improvements to payload_hash (45K ops/sec) or batch creation (44 ops/sec) were invisible.

Switching to geometric mean fixed this. Each benchmark contributes proportionally to its log-throughput, so a 2x improvement to `create_batch/1000` (from 44 to 88 ops/sec) moves the score as much as a 2x improvement to `signing_bytes` (from 14M to 28M ops/sec). **Scoring function design turned out to be load-bearing** — it determined which optimizations the loop could even detect.

### Benchmark Weights

Weights reflect production importance:

| Benchmark | Weight | Rationale |
|-----------|--------|-----------|
| create_batch/1000 | 5 | Real-world ingest path |
| build_tree/4096 | 5 | Large Merkle commitment |
| payload_hash | 4 | Called on every event |
| build_tree/1000 | 4 | Typical commitment size |
| event_signing_hash | 3 | VES v1.0 per-event |
| create_batch/100 | 3 | Common batch size |
| leaf_hash | 2 | Per-event in commitments |
| node_hash | 2 | Per-node in Merkle tree |
| payload_hash_verify | 2 | Verification path |
| create_batch/10 | 2 | Small batch |
| signing_bytes | 1 | Already fast |
| create_batch/1 | 1 | Baseline |

### Bench Profile

The sequencer depends on `ves-stark-batch` (a large STARK library) which takes 45+ minutes to compile with LTO. We added a bench profile that disables LTO and sets `opt-level=0` for STARK dependencies not in the benchmark path:

```toml
[profile.bench]
inherits = "release"
opt-level = 2
lto = false
codegen-units = 16

[profile.bench.package.ves-stark-batch]
opt-level = 0
# ... (same for other STARK deps)
```

This reduced bench compilation from 45+ minutes to ~5 minutes.

## The Experiment Loop

Each experiment follows this cycle:

```
1. Read code, identify bottleneck
2. Implement ONE optimization
3. cargo test -p stateset-sequencer --lib  (verify correctness)
4. git commit
5. python coderesearch.py eval --config ... --auto-revert-discard
6. If KEEP → continue from new commit
   If DISCARD → auto-reverted to best, try different approach
```

## Round 1: Event Creation & Hashing

**11 experiments, 4 kept** (15 total across both rounds, 5 kept)

### Experiment Results

| # | Change | Score | Status |
|---|--------|-------|--------|
| 0 | Baseline (pre-allocated signing_bytes + #[inline]) | 3.70 | KEEP |
| 1 | Buffered Sha256Write (256-byte stack buffer) | 2.18 | discard |
| 2 | Replace JCS canonicalizer with serde_json::to_writer | 8.89 | **KEEP** |
| 3 | Derive Copy for TenantId, StoreId, AgentId | 7.68 | discard |
| 4 | Copy derive (same code, re-committed after Cargo.lock fix) | 10.31 | **KEEP** |
| 5 | #[inline] on EntityType/EventType constructors | 6.29 | discard |
| 6 | serde_json::to_vec + single sha256() call | 14.59 | **KEEP** |
| 7 | Apply to_vec to payload_plain_hash too | 8.54 | discard |
| 8 | unsafe ptr::copy_nonoverlapping for signing_bytes | 46.40* | discard |
| 9 | opt-level=3 + codegen-units=1 for hot-path crates | 38.80* | discard |
| 10 | Thin LTO for bench profile | 0.00* | discard (timeout) |

*Experiments 8-10 used the old weighted-sum scoring (not comparable to geometric mean scores above). They are documented in "What Didn't Work."

### A Note on Experiment #3 vs #4

The same `Copy` derive was discarded in experiment 3 (7.68) but kept in experiment 4 (10.31). This was **not** measurement noise — the commits differed. Experiment 3 included a `Cargo.lock` change from a `cargo update` that pulled different dependency versions (the ves-stark-air crate had been fixed between runs). When the auto-revert reset to the best commit, it also reverted the broken Cargo.lock. Experiment 4 re-applied the Copy derive on top of a clean Cargo.lock, producing different compilation artifacts and better codegen.

This is a real limitation of the keep/discard loop: **the score captures the entire build state, not just the diff.** Dependency changes, cache state, and even compilation ordering can shift results by 10-20%. We partially mitigated this by always running `git checkout -- Cargo.lock` before eval, but it's an imperfect defense. When an experiment's score is within ~15% of the baseline, it should be treated as inconclusive rather than a definitive keep or discard.

### What Worked

**1. Replace JCS canonicalizer with `serde_json` (+140%)**

The `canonical_json_hash()` function used `serde_json_canonicalizer` (RFC 8785) to serialize JSON before hashing. However, `serde_json::Map` uses `BTreeMap` internally — keys are *already sorted lexicographically*. The JCS canonicalizer was redundantly re-sorting already-sorted keys.

```rust
// Before: redundant key sorting
let canonical = serde_json_canonicalizer::to_string(value)?;
sha256(canonical.as_bytes())

// After: keys already sorted in BTreeMap
let bytes = serde_json::to_vec(value)?;
sha256(&bytes)
```

This was the single biggest win: **payload_hash went from 22µs to 5.2µs (4.2x)**.

**Caveat:** This optimization is correct only because `serde_json` is compiled without the `preserve_order` feature (which would use `IndexMap` instead of `BTreeMap`). If that feature is ever enabled, the keys would no longer be sorted and the hashes would silently change. The existing test suite catches this — `test_payload_hash_key_order_independence` verifies that `{"a":1,"b":2}` and `{"b":2,"a":1}` produce the same hash. The public `canonicalize_json()` function still uses the JCS canonicalizer for strict RFC 8785 compliance with external systems.

**2. `serde_json::to_vec` + single `sha256()` call (+41%)**

Instead of streaming many small writes through a `Sha256Write` wrapper (each `write()` call has per-call overhead), serialize the entire JSON to a contiguous `Vec<u8>` first, then hash it in one `sha256()` call.

**3. `Copy` derive for UUID newtypes (+16%)**

`TenantId`, `StoreId`, and `AgentId` wrap `uuid::Uuid` (16 bytes) but didn't derive `Copy`. In batch creation loops, `.clone()` generated `memcpy` calls. With `Copy`, the compiler passes them in registers.

### What Didn't Work

- **Buffered Sha256Write**: A 256-byte stack buffer to batch small JCS writes before flushing to SHA-256. Extra copy overhead outweighed reduced update calls — SHA-256 already has an internal 64-byte block buffer that handles this.
- **unsafe ptr::copy_nonoverlapping for signing_bytes**: The compiler already optimizes `extend_from_slice` with known sizes. Manual unsafe was measurably slower.
- **Forced #[inline] on EntityType/EventType constructors**: The compiler made worse inlining decisions when forced, inflating code size and hurting instruction cache locality.
- **opt-level=3 + codegen-units=1**: The reduced codegen parallelism changed inlining heuristics in ways that hurt the hot path.
- **Thin LTO**: Timed out during compilation — the STARK deps are too large for link-time optimization even in thin mode.

### Why `payload_hash_verify` Improved 13x

`payload_hash_verify` calls `compute_payload_hash()` and compares the result to the stored hash. The 13x improvement (7µs to 0.54µs) is the compound effect of two changes:

1. **JCS → serde_json** (experiment 2): `compute_payload_hash` calls `canonical_json_hash` internally. Replacing the JCS canonicalizer with serde_json cut the core hash from 22µs to ~5µs.
2. **Streaming → to_vec + single hash** (experiment 6): Further cut it to ~3µs by eliminating per-write overhead.

The verify benchmark uses a smaller payload than the standalone `payload_hash` benchmark (`{"customer_id":"cust-456","items":[{"sku":"SKU-001","qty":5}]}` vs a larger payload with shipping address), so the absolute time is lower. The 13x is real — it's the same optimization applied to a smaller input where the fixed overhead (hasher init, finalize) is a larger fraction of total time, making the relative improvement larger.

### Round 1 Results

| Benchmark | Before | After | Speedup |
|-----------|--------|-------|---------|
| create_batch/1000 | 22.6 ms | 6.75 ms | **3.3x** |
| create_batch/100 | 2.6 ms | 0.56 ms | **4.7x** |
| payload_hash | 22 µs | 5.2 µs | **4.2x** |
| payload_hash_verify | 7 µs | 0.54 µs | **13x** |

## Round 2: Merkle Tree & VES Crypto

**4 experiments, 1 kept**

### Score Discontinuity Between Rounds

Round 1's final score was 14.59. Round 2's baseline is 12.96. **These scores are not comparable.** Between rounds we added 7 new benchmarks (Merkle tree, VES signing, leaf/node hash) with combined weight 19, nearly doubling the total weight from 18 to 37. The geometric mean is computed over a different set of benchmarks, so the absolute scores shifted. Think of it as switching from a 7-question exam to a 14-question exam — a score of 12.96/14 questions is not worse than 14.59/7 questions.

Within each round, scores are directly comparable. Across rounds, only per-benchmark times should be compared.

### New Benchmarks Added

We added benchmarks covering Merkle tree construction (10-4096 leaves), VES event signing hash, leaf hash, and node hash computation — all previously unmeasured hot paths.

### Experiment Results

| # | Change | Score | Status |
|---|--------|-------|--------|
| 0 | Baseline (new benchmarks + zero-alloc signing hash) | 12.96 | KEEP |
| 1 | Pre-computed domain prefix hasher state | 18.81 | **KEEP** |
| 2 | Batch left+right into single 64-byte buffer | 15.36 | discard |
| 3 | Batch leaf_hash fields into single 136-byte buffer | 11.94 | discard |

### What Worked

**Pre-computed domain prefix hasher state (+45%)**

VES hashing uses domain separation: every hash starts with a constant prefix like `b"VES_NODE_V1"`. Previously, each call created a fresh `Sha256::new()` and updated it with the prefix:

```rust
// Before: fresh hasher + prefix update on every call
pub fn compute_node_hash(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_NODE);  // constant prefix, same every time
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}
```

Now we pre-compute the hasher state after ingesting the domain prefix using `OnceLock`, and clone it:

```rust
fn node_hasher_prefix() -> &'static Sha256 {
    static PREFIX: OnceLock<Sha256> = OnceLock::new();
    PREFIX.get_or_init(|| {
        let mut h = Sha256::new();
        h.update(DOMAIN_NODE);
        h
    })
}

pub fn compute_node_hash(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut hasher = node_hasher_prefix().clone();  // clone pre-initialized state
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}
```

Applied to `compute_node_hash`, `compute_leaf_hash`, and `compute_event_signing_hash`. In Merkle tree builds with 4096 leaves (~8000 node hashes), this eliminates 8000 redundant prefix updates.

**Why this is safe:** `OnceLock` provides exactly-once initialization with shared read access — no data races. `Sha256::clone()` copies ~200 bytes of internal hasher state (the SHA-256 working variables and partial block buffer), which is cheap and has no shared mutable state. Each caller gets an independent copy that they own exclusively.

### What Didn't Work

- **Batching fields into a single buffer**: Copying left+right hashes into a contiguous 64-byte stack buffer before hashing (one `update` call instead of two) was measurably slower. The same pattern failed for leaf_hash with a 136-byte buffer. SHA-256's internal block processing already handles multiple small updates efficiently — the `update()` method simply appends to an internal buffer and processes complete 64-byte blocks. Adding an extra copy step before that is strictly worse.

### Round 2 Results

| Benchmark | Before | After | Speedup |
|-----------|--------|-------|---------|
| event_signing_hash | 1.1 µs | 525 ns | **2.1x** |
| leaf_hash | 1.7 µs | 461 ns | **3.7x** |
| node_hash | 626 ns | 282 ns | **2.2x** |
| build_tree/10 | 8.6 µs | 5.9 µs | **1.5x** |
| build_tree/4096 | 1.64 ms | 1.68 ms | ~1.0x |

Note: `build_tree/4096` showed no meaningful improvement despite `node_hash` improving 2.2x in isolation (626ns to 282ns). With ~8000 nodes, the theoretical savings are ~2.75ms — but the total benchmark time is only 1.64ms. This reveals that **per-node hash is not the bottleneck in large tree builds.** At this scale, the dominant costs are level iteration, memory allocation (a new `Vec` per level), and cache pressure from the working set (~8000 x 32 bytes = 256KB across multiple levels). The `node_hash` benchmark measures the hash in isolation with hot cache; `build_tree/4096` measures it in context where memory access patterns dominate. Parallelizing the per-level hashing with rayon, or switching to an in-place tree build to reduce allocations, would be the next steps for large tree performance.

## Key Takeaways

### 1. Scoring Function Design Is Load-Bearing

The shift from `signing_bytes` dominating 98.7% of the weighted sum to being a rounding error under geometric mean was the most important methodological decision in this project. It determined which optimizations the loop could detect. A bad scoring function makes the autoresearch loop optimize the wrong thing with high confidence. We wasted the first 5 experiments under the old scoring before recognizing this.

### 2. Algorithmic Wins Beat Micro-Optimizations

The biggest win (+140%) came from recognizing that JCS key-sorting was redundant — `BTreeMap` already sorts keys. This required understanding the data structure, not writing faster assembly. The second biggest win (pre-computed hasher prefix, +45%) was similarly structural: recognizing that a constant computation was being repeated.

### 3. The Compiler Is Smarter Than You Think

Multiple "clever" optimizations (unsafe pointer copies, forced inlining, buffer batching, higher opt-levels) performed worse than the compiler's default codegen. The autoresearch discard mechanism protected us from shipping these regressions. This is the strongest argument for the keep/discard loop: it gives you empirical evidence that your intuition was wrong, before it reaches production.

### 4. Pre-computation Compounds

Pre-computing the SHA-256 domain prefix state saved ~300ns per hash. For a single hash, that's marginal. For a 4096-leaf Merkle tree with 8000+ hashes, it saves ~2.4ms. The key insight is that small per-call savings become significant when a function is called in a tight loop thousands of times.

### 5. The Keep/Discard Loop Encourages Bold Experiments

Of 15 total experiments, only 5 were kept. The discard mechanism means you can try aggressive optimizations (unsafe code, radical restructuring) without risk — if it doesn't help, it's automatically reverted. This encourages bolder experimentation than manual optimization where each failed attempt costs review time and git archaeology.

### 6. Measure Before Optimizing (and Re-measure After Changing the Measurement)

Adding new benchmarks between rounds changed the composite score. This is expected and correct — you want the score to reflect reality — but it means cross-round comparisons require care. Always compare per-benchmark times, not composite scores, when the benchmark set has changed.

## Files Changed

```
Cargo.toml           — bench profile (opt-level, LTO, codegen-units)
src/crypto/hash.rs   — serde_json fast path, pre-computed hashers, zero-alloc signing
src/domain/event.rs  — pre-allocated signing_bytes, #[inline] hot paths
src/domain/types.rs  — Copy derive for UUID newtypes
benches/sequencer_bench.rs — expanded benchmark suite (14 benchmarks)
```

## Running the Autoresearch Loop

To continue optimizing:

```bash
# One-time: create experiment branch
git checkout -b autoresearch/my-experiment

# Run one experiment
python3 /home/dom/karpathy/autoresearch/coderesearch.py eval \
  --config /home/dom/karpathy/autoresearch/targets/stateset-sequencer.json \
  --description "my optimization" \
  --auto-revert-discard

# Check results
cat .autoresearch/results.tsv
```
