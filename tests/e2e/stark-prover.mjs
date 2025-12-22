/**
 * VES-STARK-1 Validity Proofs Module
 * Simulated STARK prover for E2E testing
 */

import crypto from 'crypto';
import { TestCrypto, MerkleTree, uuid } from './test-utils.mjs';

// =============================================================================
// STARK Parameters
// =============================================================================

const STARK_PARAMS = {
  blowupFactor: 8,
  numQueries: 32,
  friFoldFactor: 4,
  hashFunction: 'blake3', // simulated with sha256 for testing
  securityBits: 100
};

// =============================================================================
// Execution Trace Builder
// =============================================================================

export class ExecutionTrace {
  constructor(events) {
    this.events = events;
    this.columns = {
      sequence: [],
      eventHashLow: [],
      eventHashHigh: [],
      sigValid: [],
      merkleValid: [],
      paddingFlag: []
    };
    this.build();
  }

  build() {
    // Add real event rows
    for (const event of this.events) {
      const eventHash = this.computeEventHash(event);
      const hashBuf = Buffer.from(eventHash.replace('0x', ''), 'hex');

      this.columns.sequence.push(BigInt(event.sequenceNumber));
      this.columns.eventHashLow.push(BigInt('0x' + hashBuf.slice(0, 16).toString('hex')));
      this.columns.eventHashHigh.push(BigInt('0x' + hashBuf.slice(16, 32).toString('hex')));
      this.columns.sigValid.push(1n);
      this.columns.merkleValid.push(1n);
      this.columns.paddingFlag.push(0n);
    }

    // Pad to next power of 2
    const targetLength = Math.pow(2, Math.ceil(Math.log2(this.events.length || 1)));
    while (this.columns.sequence.length < targetLength) {
      this.columns.sequence.push(0n);
      this.columns.eventHashLow.push(0n);
      this.columns.eventHashHigh.push(0n);
      this.columns.sigValid.push(0n);
      this.columns.merkleValid.push(0n);
      this.columns.paddingFlag.push(1n);
    }

    this.length = this.columns.sequence.length;
    this.realLength = this.events.length;
  }

  computeEventHash(event) {
    const data = `${event.eventId}:${event.sequenceNumber}:${event.eventType}:${event.entityType}:${event.entityId}:${event.payloadHash}:${event.timestamp}`;
    return TestCrypto.hashHex(data);
  }

  getRow(index) {
    return {
      sequence: this.columns.sequence[index],
      eventHashLow: this.columns.eventHashLow[index],
      eventHashHigh: this.columns.eventHashHigh[index],
      sigValid: this.columns.sigValid[index],
      merkleValid: this.columns.merkleValid[index],
      paddingFlag: this.columns.paddingFlag[index]
    };
  }
}

// =============================================================================
// AIR Constraints
// =============================================================================

export class VesBatchAir {
  constructor(batchSize, prevRoot, newRoot) {
    this.batchSize = batchSize;
    this.prevRoot = prevRoot;
    this.newRoot = newRoot;
    this.constraints = [];
    this.defineConstraints();
  }

  defineConstraints() {
    // Constraint 1: Sequence increment
    // Only applies when both current and next rows are non-padding
    this.constraints.push({
      name: 'sequence_increment',
      degree: 2,
      evaluate: (current, next) => {
        // (1 - current.padding) * (1 - next.padding) * (next.seq - current.seq - 1) = 0
        const currentNotPadding = 1n - current.paddingFlag;
        const nextNotPadding = 1n - next.paddingFlag;
        return currentNotPadding * nextNotPadding * (next.sequence - current.sequence - 1n);
      }
    });

    // Constraint 2: Signature validity
    this.constraints.push({
      name: 'signature_valid',
      degree: 1,
      evaluate: (current) => {
        // (1 - padding_flag) * (sig_valid - 1) = 0
        const notPadding = 1n - current.paddingFlag;
        return notPadding * (current.sigValid - 1n);
      }
    });

    // Constraint 3: Merkle validity
    this.constraints.push({
      name: 'merkle_valid',
      degree: 1,
      evaluate: (current) => {
        // (1 - padding_flag) * (merkle_valid - 1) = 0
        const notPadding = 1n - current.paddingFlag;
        return notPadding * (current.merkleValid - 1n);
      }
    });

    // Constraint 4: Padding flag is binary
    this.constraints.push({
      name: 'padding_binary',
      degree: 2,
      evaluate: (current) => {
        // padding_flag * (padding_flag - 1) = 0
        return current.paddingFlag * (current.paddingFlag - 1n);
      }
    });
  }

  evaluateConstraints(trace, rowIndex) {
    const current = trace.getRow(rowIndex);
    const next = trace.getRow((rowIndex + 1) % trace.length);

    const results = [];
    for (const constraint of this.constraints) {
      const value = constraint.evaluate(current, next);
      results.push({
        name: constraint.name,
        value,
        satisfied: value === 0n
      });
    }
    return results;
  }

  verifyAllConstraints(trace) {
    const violations = [];

    // Check all rows (including padding) - constraints handle padding internally
    for (let i = 0; i < trace.length - 1; i++) {
      const results = this.evaluateConstraints(trace, i);
      for (const result of results) {
        if (!result.satisfied) {
          violations.push({
            row: i,
            constraint: result.name,
            value: result.value.toString()
          });
        }
      }
    }

    return {
      valid: violations.length === 0,
      violations
    };
  }
}

// =============================================================================
// Polynomial Commitment (Simulated)
// =============================================================================

class PolynomialCommitment {
  static commit(data) {
    // Simulated commitment using Merkle tree
    const leaves = data.map(d =>
      TestCrypto.hash(Buffer.from(d.toString(16).padStart(64, '0'), 'hex'))
    );
    const tree = new MerkleTree(leaves.map(l => '0x' + l.toString('hex')));
    return tree.getRoot();
  }

  static openAt(data, index, commitment) {
    const leaves = data.map(d =>
      TestCrypto.hash(Buffer.from(d.toString(16).padStart(64, '0'), 'hex'))
    );
    const tree = new MerkleTree(leaves.map(l => '0x' + l.toString('hex')));

    return {
      value: data[index],
      proof: tree.getProof(index),
      commitment
    };
  }
}

// =============================================================================
// FRI Protocol (Simulated)
// =============================================================================

class FRIProtocol {
  constructor(polynomial, blowupFactor, foldFactor) {
    this.polynomial = polynomial;
    this.blowupFactor = blowupFactor;
    this.foldFactor = foldFactor;
    this.layers = [];
  }

  commit() {
    let currentPoly = this.polynomial;
    let currentSize = currentPoly.length;

    while (currentSize > 32) { // Until we reach constant
      // Commit to current layer
      const commitment = PolynomialCommitment.commit(currentPoly);

      this.layers.push({
        commitment,
        size: currentSize,
        evaluations: currentPoly.slice(0, 8).map(e => e.toString(16)) // Sample
      });

      // Fold (reduce degree)
      currentPoly = this.fold(currentPoly);
      currentSize = currentPoly.length;
    }

    // Final constant
    this.finalPoly = currentPoly[0] || 0n;

    return this.layers.map(l => l.commitment);
  }

  fold(poly) {
    // Simulated folding: reduce by half
    const newPoly = [];
    for (let i = 0; i < poly.length / 2; i++) {
      newPoly.push((poly[i * 2] + poly[i * 2 + 1]) / 2n);
    }
    return newPoly;
  }

  generateQueryResponse(queryIndex) {
    const responses = [];

    for (let i = 0; i < this.layers.length; i++) {
      const layer = this.layers[i];
      const adjustedIndex = queryIndex % layer.size;

      responses.push({
        layerIndex: i,
        queryIndex: adjustedIndex,
        value: layer.evaluations[adjustedIndex % layer.evaluations.length],
        commitment: layer.commitment
      });
    }

    return responses;
  }
}

// =============================================================================
// STARK Prover
// =============================================================================

export class StarkProver {
  constructor(params = STARK_PARAMS) {
    this.params = params;
  }

  /**
   * Generate a STARK proof for a batch of events
   */
  prove(batchInput) {
    const startTime = Date.now();

    // Build execution trace
    const trace = new ExecutionTrace(batchInput.events);

    // Define AIR
    const air = new VesBatchAir(
      batchInput.batchSize,
      batchInput.prevEventsRoot,
      batchInput.newEventsRoot
    );

    // Verify constraints (prover must satisfy all)
    const constraintCheck = air.verifyAllConstraints(trace);
    if (!constraintCheck.valid) {
      throw new Error(`Constraint violations: ${JSON.stringify(constraintCheck.violations)}`);
    }

    // Commit to trace columns
    const traceCommitments = [];
    for (const [name, column] of Object.entries(trace.columns)) {
      const commitment = PolynomialCommitment.commit(column);
      traceCommitments.push(commitment);
    }

    // Compute composition polynomial (simulated)
    const compositionPoly = this.computeCompositionPolynomial(trace, air);
    const compositionCommitment = PolynomialCommitment.commit(compositionPoly);

    // FRI protocol
    const fri = new FRIProtocol(compositionPoly, this.params.blowupFactor, this.params.friFoldFactor);
    const friCommitments = fri.commit();

    // Generate query responses
    const queryResponses = [];
    for (let i = 0; i < this.params.numQueries; i++) {
      const queryIndex = this.generateQueryIndex(i, trace.length * this.params.blowupFactor);

      queryResponses.push({
        index: queryIndex,
        traceValues: Object.values(trace.columns).map(col =>
          Buffer.from(col[queryIndex % col.length].toString(16).padStart(64, '0'), 'hex').toString('base64')
        ),
        authenticationPaths: traceCommitments.map((_, colIdx) => {
          const colData = Object.values(trace.columns)[colIdx];
          const tree = new MerkleTree(colData.map(v =>
            TestCrypto.hashHex(v.toString(16).padStart(64, '0'))
          ));
          return tree.getProof(queryIndex % colData.length).map(p => p.hash);
        }),
        friResponses: fri.generateQueryResponse(queryIndex)
      });
    }

    const provingTime = Date.now() - startTime;

    // Build proof object
    const proof = {
      version: 1,
      proverId: 'ves-stark-test-prover',
      generatedAt: new Date().toISOString(),
      publicInputs: {
        prevEventsRoot: batchInput.prevEventsRoot,
        newEventsRoot: batchInput.newEventsRoot,
        batchSize: batchInput.batchSize,
        sequenceStart: batchInput.sequenceStart,
        sequenceEnd: batchInput.sequenceEnd,
        stateCommitment: this.computeStateCommitment(batchInput),
        tenantId: batchInput.tenantId,
        storeId: batchInput.storeId
      },
      starkProof: {
        traceCommitment: traceCommitments,
        compositionCommitment,
        friLayers: friCommitments.map((commitment, i) => ({
          commitment,
          evaluations: fri.layers[i]?.evaluations || []
        })),
        queryResponses,
        finalPoly: Buffer.from(fri.finalPoly.toString(16).padStart(64, '0'), 'hex').toString('base64')
      },
      auxiliary: {
        blowupFactor: this.params.blowupFactor,
        numQueries: this.params.numQueries,
        friFoldFactor: this.params.friFoldFactor,
        hashFunction: this.params.hashFunction
      },
      metadata: {
        provingTimeMs: provingTime,
        proofSizeBytes: 0, // Calculated below
        traceLength: trace.length,
        constraintCount: air.constraints.length
      }
    };

    // Calculate proof size
    proof.metadata.proofSizeBytes = Buffer.byteLength(JSON.stringify(proof));

    return proof;
  }

  computeCompositionPolynomial(trace, air) {
    // Simulated composition polynomial
    const poly = [];
    for (let i = 0; i < trace.length * this.params.blowupFactor; i++) {
      // Hash of constraint evaluations at this point
      const evalPoint = i / (trace.length * this.params.blowupFactor);
      const hash = TestCrypto.hash(Buffer.from(`comp_${i}_${evalPoint}`));
      poly.push(BigInt('0x' + hash.toString('hex').slice(0, 16)));
    }
    return poly;
  }

  computeStateCommitment(batchInput) {
    const data = Buffer.concat([
      Buffer.from(batchInput.tenantId.replace('0x', ''), 'hex'),
      Buffer.from(batchInput.storeId.replace('0x', ''), 'hex'),
      Buffer.from(batchInput.newEventsRoot.replace('0x', ''), 'hex'),
      Buffer.from(batchInput.sequenceEnd.toString())
    ]);
    return TestCrypto.hashHex(data);
  }

  generateQueryIndex(seed, domainSize) {
    const hash = TestCrypto.hash(Buffer.from(`query_${seed}`));
    return Number(BigInt('0x' + hash.toString('hex').slice(0, 8)) % BigInt(domainSize));
  }
}

// =============================================================================
// STARK Verifier
// =============================================================================

export class StarkVerifier {
  constructor(params = STARK_PARAMS) {
    this.params = params;
  }

  /**
   * Verify a STARK proof
   */
  verify(proof) {
    const startTime = Date.now();
    const errors = [];

    // 1. Validate public inputs
    if (!this.validatePublicInputs(proof.publicInputs)) {
      errors.push('Invalid public inputs');
    }

    // 2. Verify trace commitments exist
    if (!proof.starkProof.traceCommitment || proof.starkProof.traceCommitment.length === 0) {
      errors.push('Missing trace commitments');
    }

    // 3. Verify composition commitment
    if (!proof.starkProof.compositionCommitment) {
      errors.push('Missing composition commitment');
    }

    // 4. Verify FRI layers
    if (!proof.starkProof.friLayers || proof.starkProof.friLayers.length === 0) {
      errors.push('Missing FRI layers');
    }

    // 5. Verify query responses
    if (!proof.starkProof.queryResponses || proof.starkProof.queryResponses.length < this.params.numQueries) {
      errors.push(`Insufficient query responses: ${proof.starkProof.queryResponses?.length || 0}/${this.params.numQueries}`);
    }

    // 6. Verify each query (simulated)
    for (let i = 0; i < (proof.starkProof.queryResponses?.length || 0); i++) {
      const query = proof.starkProof.queryResponses[i];

      // Verify authentication paths
      if (!query.authenticationPaths || query.authenticationPaths.length === 0) {
        errors.push(`Query ${i}: Missing authentication paths`);
      }

      // Verify FRI consistency (simulated)
      if (!query.friResponses || query.friResponses.length === 0) {
        errors.push(`Query ${i}: Missing FRI responses`);
      }
    }

    // 7. Verify final polynomial
    if (!proof.starkProof.finalPoly) {
      errors.push('Missing final polynomial');
    }

    const verificationTime = Date.now() - startTime;

    return {
      valid: errors.length === 0,
      errors,
      verificationTimeMs: verificationTime,
      publicInputs: proof.publicInputs
    };
  }

  validatePublicInputs(inputs) {
    if (!inputs) return false;
    if (typeof inputs.batchSize !== 'number' || inputs.batchSize < 1) return false;
    if (inputs.sequenceEnd < inputs.sequenceStart) return false;
    if (inputs.batchSize !== inputs.sequenceEnd - inputs.sequenceStart + 1) return false;
    if (!inputs.prevEventsRoot?.startsWith('0x')) return false;
    if (!inputs.newEventsRoot?.startsWith('0x')) return false;
    return true;
  }
}

// =============================================================================
// Batch Manager
// =============================================================================

export class BatchManager {
  constructor(eventStore) {
    this.eventStore = eventStore;
    this.prover = new StarkProver();
    this.verifier = new StarkVerifier();
    this.batches = new Map();
  }

  /**
   * Create a batch from events in range
   */
  createBatch(sequenceStart, sequenceEnd) {
    const events = this.eventStore.getEventsInRange(sequenceStart, sequenceEnd);

    if (events.length !== sequenceEnd - sequenceStart + 1) {
      throw new Error(`Event count mismatch: expected ${sequenceEnd - sequenceStart + 1}, got ${events.length}`);
    }

    const batchInput = {
      tenantId: '0x' + this.eventStore.tenantId.replace(/-/g, ''),
      storeId: '0x' + this.eventStore.storeId.replace(/-/g, ''),
      batchSize: events.length,
      sequenceStart,
      sequenceEnd,
      prevEventsRoot: this.eventStore.getRootAt(sequenceStart - 1),
      newEventsRoot: this.eventStore.getRootAt(sequenceEnd),
      events: events.map(e => ({
        eventId: e.eventId,
        sequenceNumber: e.sequenceNumber,
        eventType: e.eventType,
        entityType: e.entityType,
        entityId: e.entityId,
        payloadHash: e.payloadHash,
        timestamp: e.timestamp,
        signature: e.signature
      }))
    };

    return batchInput;
  }

  /**
   * Generate proof for a batch
   */
  proveBatch(batchInput) {
    const proof = this.prover.prove(batchInput);

    const batchId = uuid();
    this.batches.set(batchId, {
      batchId,
      proof,
      createdAt: new Date().toISOString(),
      verified: false
    });

    return { batchId, proof };
  }

  /**
   * Verify a batch proof
   */
  verifyBatch(batchId) {
    const batch = this.batches.get(batchId);
    if (!batch) throw new Error('Batch not found');

    const result = this.verifier.verify(batch.proof);
    batch.verified = result.valid;
    batch.verificationResult = result;

    return result;
  }

  /**
   * Record batch verification in VES
   */
  recordVerification(batchId, chainVerification) {
    const batch = this.batches.get(batchId);
    if (!batch) throw new Error('Batch not found');

    const event = this.eventStore.appendEvent({
      eventType: 'BatchVerified',
      entityType: 'StarkBatch',
      entityId: batchId,
      payload: {
        batchSize: batch.proof.publicInputs.batchSize,
        sequenceStart: batch.proof.publicInputs.sequenceStart,
        sequenceEnd: batch.proof.publicInputs.sequenceEnd,
        eventsRoot: batch.proof.publicInputs.newEventsRoot,
        stateCommitment: batch.proof.publicInputs.stateCommitment,
        proofHash: TestCrypto.hashHex(JSON.stringify(batch.proof.starkProof)),
        chainVerification,
        provingTimeMs: batch.proof.metadata.provingTimeMs,
        proofSizeBytes: batch.proof.metadata.proofSizeBytes
      }
    });

    batch.verificationEventId = event.eventId;
    return event;
  }
}
