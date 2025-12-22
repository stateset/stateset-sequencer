/**
 * VES E2E Test Utilities
 * Shared utilities for integration testing VES-CONTRACT-1, VES-MULTI-1, VES-STARK-1
 */

import crypto from 'crypto';

// =============================================================================
// Cryptographic Utilities
// =============================================================================

/**
 * Simple Ed25519-like operations for testing
 * In production, use @noble/curves/ed25519
 */
export class TestCrypto {
  static generateKeyPair() {
    const privateKey = crypto.randomBytes(32);
    const publicKey = crypto.createHash('sha256').update(privateKey).digest();
    return { privateKey, publicKey };
  }

  static sign(message, privateKey) {
    const hmac = crypto.createHmac('sha512', privateKey);
    hmac.update(Buffer.from(message));
    return hmac.digest().slice(0, 64);
  }

  static verify(message, signature, publicKey) {
    // Simplified verification for testing
    return signature.length === 64;
  }

  static hash(data) {
    return crypto.createHash('sha256').update(data).digest();
  }

  static hashHex(data) {
    return '0x' + this.hash(Buffer.from(data)).toString('hex');
  }
}

// =============================================================================
// Merkle Tree Implementation
// =============================================================================

export class MerkleTree {
  constructor(leaves = []) {
    this.leaves = leaves.map(l =>
      Buffer.isBuffer(l) ? l : Buffer.from(l.replace('0x', ''), 'hex')
    );
    this.layers = [];
    if (this.leaves.length > 0) {
      this.build();
    }
  }

  build() {
    // Pad to power of 2
    const targetSize = Math.pow(2, Math.ceil(Math.log2(this.leaves.length || 1)));
    while (this.leaves.length < targetSize) {
      this.leaves.push(Buffer.alloc(32));
    }

    this.layers = [this.leaves];
    let currentLayer = this.leaves;

    while (currentLayer.length > 1) {
      const nextLayer = [];
      for (let i = 0; i < currentLayer.length; i += 2) {
        const left = currentLayer[i];
        const right = currentLayer[i + 1] || left;
        const combined = Buffer.concat([left, right]);
        nextLayer.push(TestCrypto.hash(combined));
      }
      this.layers.push(nextLayer);
      currentLayer = nextLayer;
    }
  }

  getRoot() {
    if (this.layers.length === 0) return Buffer.alloc(32);
    const root = this.layers[this.layers.length - 1][0];
    return '0x' + root.toString('hex');
  }

  getProof(index) {
    const proof = [];
    let currentIndex = index;

    for (let i = 0; i < this.layers.length - 1; i++) {
      const layer = this.layers[i];
      const isLeft = currentIndex % 2 === 0;
      const siblingIndex = isLeft ? currentIndex + 1 : currentIndex - 1;

      if (siblingIndex < layer.length) {
        proof.push({
          position: isLeft ? 'right' : 'left',
          hash: '0x' + layer[siblingIndex].toString('hex')
        });
      }

      currentIndex = Math.floor(currentIndex / 2);
    }

    return proof;
  }

  static verifyProof(leafHash, proof, root) {
    let current = Buffer.from(leafHash.replace('0x', ''), 'hex');

    for (const step of proof) {
      const sibling = Buffer.from(step.hash.replace('0x', ''), 'hex');
      if (step.position === 'left') {
        current = TestCrypto.hash(Buffer.concat([sibling, current]));
      } else {
        current = TestCrypto.hash(Buffer.concat([current, sibling]));
      }
    }

    return '0x' + current.toString('hex') === root;
  }
}

// =============================================================================
// Event Store (In-Memory VES Sequencer Mock)
// =============================================================================

export class EventStore {
  constructor(tenantId, storeId) {
    this.tenantId = tenantId;
    this.storeId = storeId;
    this.events = [];
    this.merkleTree = null;
    this.agentKeyPair = TestCrypto.generateKeyPair();
  }

  appendEvent(event) {
    const sequenceNumber = this.events.length + 1;
    const eventId = `evt_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;

    // Hash the payload
    const payloadHash = TestCrypto.hashHex(JSON.stringify(event.payload));

    // Create canonical event data for hashing
    const eventData = {
      eventId,
      sequenceNumber,
      eventType: event.eventType,
      entityType: event.entityType,
      entityId: event.entityId,
      payloadHash,
      timestamp: event.timestamp || new Date().toISOString()
    };

    // Sign the event
    const signature = TestCrypto.sign(
      JSON.stringify(eventData),
      this.agentKeyPair.privateKey
    );

    const storedEvent = {
      ...eventData,
      payload: event.payload,
      signature: '0x' + signature.toString('hex'),
      agentPublicKey: '0x' + this.agentKeyPair.publicKey.toString('hex')
    };

    this.events.push(storedEvent);

    // Rebuild Merkle tree
    const eventHashes = this.events.map(e => this.computeEventHash(e));
    this.merkleTree = new MerkleTree(eventHashes);

    return {
      eventId,
      sequenceNumber,
      merkleRoot: this.merkleTree.getRoot(),
      signature: storedEvent.signature
    };
  }

  computeEventHash(event) {
    const data = `${event.eventId}:${event.sequenceNumber}:${event.eventType}:${event.entityType}:${event.entityId}:${event.payloadHash}:${event.timestamp}`;
    return TestCrypto.hashHex(data);
  }

  getEvent(eventId) {
    return this.events.find(e => e.eventId === eventId);
  }

  getEventByEntity(entityType, entityId, eventType) {
    return this.events.find(e =>
      e.entityType === entityType &&
      e.entityId === entityId &&
      e.eventType === eventType
    );
  }

  generateProof(eventId) {
    const index = this.events.findIndex(e => e.eventId === eventId);
    if (index === -1) throw new Error(`Event not found: ${eventId}`);

    const event = this.events[index];
    const eventHash = this.computeEventHash(event);

    return {
      eventHash,
      merkleRoot: this.merkleTree.getRoot(),
      proofPath: this.merkleTree.getProof(index),
      event: {
        eventId: event.eventId,
        eventType: event.eventType,
        entityType: event.entityType,
        entityId: event.entityId,
        payloadHash: event.payloadHash,
        timestamp: event.timestamp
      }
    };
  }

  getEventsInRange(start, end) {
    return this.events.filter(e =>
      e.sequenceNumber >= start && e.sequenceNumber <= end
    );
  }

  getRootAt(sequenceNumber) {
    if (sequenceNumber === 0) {
      return '0x' + '0'.repeat(64);
    }
    const eventsUpTo = this.events.slice(0, sequenceNumber);
    const hashes = eventsUpTo.map(e => this.computeEventHash(e));
    const tree = new MerkleTree(hashes);
    return tree.getRoot();
  }
}

// =============================================================================
// Test Assertions
// =============================================================================

export class Assert {
  static equal(actual, expected, message = '') {
    if (actual !== expected) {
      throw new Error(`Assertion failed${message ? ': ' + message : ''}\n  Expected: ${expected}\n  Actual: ${actual}`);
    }
  }

  static deepEqual(actual, expected, message = '') {
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      throw new Error(`Assertion failed${message ? ': ' + message : ''}\n  Expected: ${JSON.stringify(expected, null, 2)}\n  Actual: ${JSON.stringify(actual, null, 2)}`);
    }
  }

  static ok(value, message = '') {
    if (!value) {
      throw new Error(`Assertion failed${message ? ': ' + message : ''}\n  Expected truthy value, got: ${value}`);
    }
  }

  static throws(fn, expectedError, message = '') {
    let threw = false;
    let error;
    try {
      fn();
    } catch (e) {
      threw = true;
      error = e;
    }
    if (!threw) {
      throw new Error(`Assertion failed${message ? ': ' + message : ''}\n  Expected function to throw`);
    }
    if (expectedError && !error.message.includes(expectedError)) {
      throw new Error(`Assertion failed${message ? ': ' + message : ''}\n  Expected error containing: ${expectedError}\n  Got: ${error.message}`);
    }
  }

  static async rejects(promise, expectedError, message = '') {
    let threw = false;
    let error;
    try {
      await promise;
    } catch (e) {
      threw = true;
      error = e;
    }
    if (!threw) {
      throw new Error(`Assertion failed${message ? ': ' + message : ''}\n  Expected promise to reject`);
    }
    if (expectedError && !error.message.includes(expectedError)) {
      throw new Error(`Assertion failed${message ? ': ' + message : ''}\n  Expected error containing: ${expectedError}\n  Got: ${error.message}`);
    }
  }
}

// =============================================================================
// Test Runner
// =============================================================================

export class TestRunner {
  constructor(name) {
    this.name = name;
    this.tests = [];
    this.passed = 0;
    this.failed = 0;
    this.skipped = 0;
  }

  test(name, fn) {
    this.tests.push({ name, fn, skip: false });
  }

  skip(name, fn) {
    this.tests.push({ name, fn, skip: true });
  }

  async run() {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`  ${this.name}`);
    console.log(`${'='.repeat(60)}\n`);

    const startTime = Date.now();

    for (const test of this.tests) {
      if (test.skip) {
        console.log(`  ○ SKIP: ${test.name}`);
        this.skipped++;
        continue;
      }

      try {
        await test.fn();
        console.log(`  ✓ PASS: ${test.name}`);
        this.passed++;
      } catch (error) {
        console.log(`  ✗ FAIL: ${test.name}`);
        console.log(`    ${error.message.split('\n').join('\n    ')}`);
        this.failed++;
      }
    }

    const duration = Date.now() - startTime;
    console.log(`\n${'-'.repeat(60)}`);
    console.log(`  Results: ${this.passed} passed, ${this.failed} failed, ${this.skipped} skipped`);
    console.log(`  Duration: ${duration}ms`);
    console.log(`${'-'.repeat(60)}\n`);

    return this.failed === 0;
  }
}

// =============================================================================
// UUID Generator
// =============================================================================

export function uuid() {
  return crypto.randomUUID();
}

export function uuidHex() {
  return '0x' + crypto.randomUUID().replace(/-/g, '');
}

// =============================================================================
// Formatting Utilities
// =============================================================================

export function formatAmount(amount, decimals = 6) {
  const num = BigInt(amount);
  const divisor = BigInt(10 ** decimals);
  const whole = num / divisor;
  const fraction = (num % divisor).toString().padStart(decimals, '0');
  return `${whole}.${fraction}`;
}

export function toBaseUnits(amount, decimals = 6) {
  const [whole, fraction = ''] = amount.toString().split('.');
  const paddedFraction = fraction.padEnd(decimals, '0').slice(0, decimals);
  return BigInt(whole + paddedFraction).toString();
}
