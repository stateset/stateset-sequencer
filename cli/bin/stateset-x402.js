#!/usr/bin/env node

/**
 * x402 Payment CLI for StateSet Sequencer
 *
 * Commands:
 *   pay      - Create and submit a payment intent
 *   status   - Check payment status
 *   receipt  - Get payment receipt with proof
 *   list     - List payment intents
 *   batch    - Create a payment batch
 *   keygen   - Generate a new Ed25519 keypair
 *
 * Environment variables:
 *   X402_PRIVATE_KEY  - Ed25519 private key (hex, required for pay)
 *   X402_API_URL      - Sequencer API URL (default: http://localhost:8080)
 *   X402_TENANT_ID    - Tenant UUID
 *   X402_STORE_ID     - Store UUID
 *   X402_AGENT_ID     - Agent UUID
 */

import { X402Client, loadPrivateKey, generateKeypair } from '../src/x402/client.js';
import { bytesToHex } from '@noble/hashes/utils';

const VERSION = '1.0.0';

// Parse command line arguments
const args = process.argv.slice(2);
const command = args[0];

// Parse flags
function parseFlags(args) {
  const flags = {};
  const positional = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const nextArg = args[i + 1];
      if (nextArg && !nextArg.startsWith('--')) {
        flags[key] = nextArg;
        i++;
      } else {
        flags[key] = true;
      }
    } else if (!arg.startsWith('-')) {
      positional.push(arg);
    }
  }

  return { flags, positional };
}

// Get client configuration from environment
function getClientConfig(flags) {
  return {
    baseUrl: flags.url || process.env.X402_API_URL || 'http://localhost:8080',
    tenantId: flags.tenant || process.env.X402_TENANT_ID,
    storeId: flags.store || process.env.X402_STORE_ID,
    agentId: flags.agent || process.env.X402_AGENT_ID,
    keyId: parseInt(flags['key-id'] || '1', 10),
  };
}

// Format amount for display
function formatAmount(amount, asset = 'usdc') {
  const decimals = asset === 'dai' ? 18 : 6;
  const value = Number(amount) / Math.pow(10, decimals);
  return value.toLocaleString('en-US', {
    minimumFractionDigits: 2,
    maximumFractionDigits: decimals,
  });
}

// Commands
async function cmdPay(flags, positional) {
  const config = getClientConfig(flags);

  if (!config.tenantId || !config.storeId || !config.agentId) {
    console.error('Error: Missing required configuration');
    console.error('Set X402_TENANT_ID, X402_STORE_ID, and X402_AGENT_ID environment variables');
    console.error('Or use --tenant, --store, and --agent flags');
    process.exit(1);
  }

  if (!flags.to) {
    console.error('Error: --to <address> is required');
    process.exit(1);
  }

  if (!flags.amount) {
    console.error('Error: --amount <amount> is required');
    process.exit(1);
  }

  let privateKey;
  try {
    privateKey = loadPrivateKey();
  } catch (e) {
    console.error('Error: X402_PRIVATE_KEY environment variable not set');
    console.error('Generate a keypair with: stateset-x402 keygen');
    process.exit(1);
  }

  const client = new X402Client({
    ...config,
    privateKey,
  });

  const asset = flags.asset || 'usdc';
  const network = flags.network || 'set_chain';
  const description = positional.slice(1).join(' ') || flags.description;

  console.log(`\nSubmitting x402 payment...`);
  console.log(`  To: ${flags.to}`);
  console.log(`  Amount: ${formatAmount(flags.amount, asset)} ${asset.toUpperCase()}`);
  console.log(`  Network: ${network}`);
  if (description) console.log(`  Description: ${description}`);
  console.log();

  try {
    const result = await client.submitPayment({
      payee: flags.to,
      amount: BigInt(flags.amount),
      asset,
      network,
      description,
      resourceUri: flags.resource,
      idempotencyKey: flags.idempotency,
      validitySeconds: parseInt(flags.validity || '3600', 10),
    });

    console.log('Payment submitted successfully!');
    console.log();
    console.log(`  Intent ID: ${result.intent_id}`);
    console.log(`  Status: ${result.status}`);
    if (result.sequence_number) {
      console.log(`  Sequence Number: ${result.sequence_number}`);
    }
    if (result.sequenced_at) {
      console.log(`  Sequenced At: ${result.sequenced_at}`);
    }
    console.log();
  } catch (e) {
    console.error(`Error: ${e.message}`);
    process.exit(1);
  }
}

async function cmdStatus(flags, positional) {
  const intentId = positional[1] || flags.id;

  if (!intentId) {
    console.error('Error: Intent ID required');
    console.error('Usage: stateset-x402 status <intent_id>');
    process.exit(1);
  }

  const config = getClientConfig(flags);
  const client = new X402Client(config);

  try {
    const result = await client.getStatus(intentId);

    console.log(`\nPayment Status for ${intentId}:`);
    console.log();
    console.log(`  Status: ${result.status}`);
    if (result.sequence_number) {
      console.log(`  Sequence Number: ${result.sequence_number}`);
    }
    if (result.sequenced_at) {
      console.log(`  Sequenced At: ${result.sequenced_at}`);
    }
    if (result.batch_id) {
      console.log(`  Batch ID: ${result.batch_id}`);
    }
    console.log();
  } catch (e) {
    console.error(`Error: ${e.message}`);
    process.exit(1);
  }
}

async function cmdReceipt(flags, positional) {
  const intentId = positional[1] || flags.id;

  if (!intentId) {
    console.error('Error: Intent ID required');
    console.error('Usage: stateset-x402 receipt <intent_id>');
    process.exit(1);
  }

  const config = getClientConfig(flags);
  const client = new X402Client(config);

  try {
    const result = await client.getReceipt(intentId);
    const receipt = result.receipt;

    console.log(`\nPayment Receipt for ${intentId}:`);
    console.log();
    console.log(`  Receipt ID: ${receipt.receipt_id}`);
    console.log(`  Sequence Number: ${receipt.sequence_number}`);
    console.log(`  Batch ID: ${receipt.batch_id}`);
    console.log(`  Merkle Root: ${receipt.merkle_root}`);
    console.log();
    console.log(`  Payer: ${receipt.payer_address}`);
    console.log(`  Payee: ${receipt.payee_address}`);
    console.log(`  Amount: ${formatAmount(receipt.amount, receipt.asset)} ${receipt.asset.toUpperCase()}`);
    console.log(`  Network: ${receipt.network}`);
    if (receipt.tx_hash) {
      console.log(`  TX Hash: ${receipt.tx_hash}`);
      console.log(`  Block: ${receipt.block_number}`);
    }
    console.log();

    if (flags.json) {
      console.log(JSON.stringify(result, null, 2));
    }
  } catch (e) {
    console.error(`Error: ${e.message}`);
    process.exit(1);
  }
}

async function cmdList(flags) {
  const config = getClientConfig(flags);

  if (!config.tenantId || !config.storeId) {
    console.error('Error: Tenant ID and Store ID required');
    console.error('Set X402_TENANT_ID and X402_STORE_ID environment variables');
    process.exit(1);
  }

  const client = new X402Client(config);

  try {
    const filter = {
      status: flags.status,
      payerAddress: flags.payer,
      payeeAddress: flags.payee,
      limit: parseInt(flags.limit || '20', 10),
      offset: parseInt(flags.offset || '0', 10),
    };

    const results = await client.listPayments(filter);

    console.log(`\nPayment Intents:`);
    console.log();

    if (results.length === 0) {
      console.log('  No payment intents found.');
    } else {
      for (const intent of results) {
        console.log(`  ${intent.intent_id}`);
        console.log(`    Status: ${intent.status}`);
        console.log(`    Amount: ${formatAmount(intent.amount, intent.asset)} ${intent.asset.toUpperCase()}`);
        console.log(`    Payee: ${intent.payee_address}`);
        if (intent.sequence_number) {
          console.log(`    Sequence: ${intent.sequence_number}`);
        }
        console.log();
      }
    }

    if (flags.json) {
      console.log(JSON.stringify(results, null, 2));
    }
  } catch (e) {
    console.error(`Error: ${e.message}`);
    process.exit(1);
  }
}

async function cmdBatch(flags) {
  const config = getClientConfig(flags);

  if (!config.tenantId || !config.storeId) {
    console.error('Error: Tenant ID and Store ID required');
    console.error('Set X402_TENANT_ID and X402_STORE_ID environment variables');
    process.exit(1);
  }

  const client = new X402Client(config);

  try {
    const result = await client.createBatch({
      network: flags.network || 'set_chain',
      maxSize: parseInt(flags['max-size'] || '100', 10),
    });

    console.log(`\nBatch Created:`);
    console.log();
    console.log(`  Batch ID: ${result.batch_id}`);
    console.log(`  Status: ${result.status}`);
    console.log(`  Payment Count: ${result.payment_count}`);
    console.log(`  Sequence Range: ${result.sequence_range[0]} - ${result.sequence_range[1]}`);
    if (result.merkle_root) {
      console.log(`  Merkle Root: ${result.merkle_root}`);
    }
    console.log();
  } catch (e) {
    console.error(`Error: ${e.message}`);
    process.exit(1);
  }
}

async function cmdKeygen() {
  const { privateKey, publicKey } = await generateKeypair();

  console.log(`\nGenerated Ed25519 Keypair:`);
  console.log();
  console.log(`  Private Key: 0x${bytesToHex(privateKey)}`);
  console.log(`  Public Key:  0x${bytesToHex(publicKey)}`);
  console.log();
  console.log(`  Set environment variable:`);
  console.log(`  export X402_PRIVATE_KEY=0x${bytesToHex(privateKey)}`);
  console.log();
}

function printHelp() {
  console.log(`
StateSet x402 Payment CLI v${VERSION}

Usage: stateset-x402 <command> [options]

Commands:
  pay         Create and submit a payment intent
  status      Check payment status
  receipt     Get payment receipt with proof
  list        List payment intents
  batch       Create a payment batch
  keygen      Generate a new Ed25519 keypair
  help        Show this help message

Pay Options:
  --to <address>        Payee wallet address (required)
  --amount <amount>     Payment amount in smallest unit (required)
  --asset <asset>       Asset type: usdc, usdt, ssusd, dai (default: usdc)
  --network <network>   Network: set_chain, base, ethereum (default: set_chain)
  --description <desc>  Payment description
  --resource <uri>      Resource URI being paid for
  --validity <seconds>  Validity period in seconds (default: 3600)
  --idempotency <key>   Idempotency key

Status/Receipt Options:
  <intent_id>           Payment intent UUID

List Options:
  --status <status>     Filter by status: pending, sequenced, batched, settled
  --payer <address>     Filter by payer address
  --payee <address>     Filter by payee address
  --limit <n>           Max results (default: 20)
  --offset <n>          Offset for pagination

Batch Options:
  --network <network>   Network (default: set_chain)
  --max-size <n>        Max batch size (default: 100)

Global Options:
  --url <url>           API URL (default: $X402_API_URL or http://localhost:8080)
  --tenant <uuid>       Tenant ID (default: $X402_TENANT_ID)
  --store <uuid>        Store ID (default: $X402_STORE_ID)
  --agent <uuid>        Agent ID (default: $X402_AGENT_ID)
  --key-id <n>          Agent key ID (default: 1)
  --json                Output as JSON

Environment Variables:
  X402_PRIVATE_KEY      Ed25519 private key (hex, required for pay)
  X402_API_URL          Sequencer API URL
  X402_TENANT_ID        Tenant UUID
  X402_STORE_ID         Store UUID
  X402_AGENT_ID         Agent UUID

Examples:
  # Generate a keypair
  stateset-x402 keygen

  # Submit a payment
  stateset-x402 pay --to 0x742d35Cc6634C0532925a3b844Bc9e7595f12345 --amount 1000000 "Payment for API access"

  # Check status
  stateset-x402 status 550e8400-e29b-41d4-a716-446655440000

  # List payments
  stateset-x402 list --status sequenced --limit 10
`);
}

// Main
async function main() {
  const { flags, positional } = parseFlags(args);

  switch (command) {
    case 'pay':
      await cmdPay(flags, positional);
      break;
    case 'status':
      await cmdStatus(flags, positional);
      break;
    case 'receipt':
      await cmdReceipt(flags, positional);
      break;
    case 'list':
      await cmdList(flags);
      break;
    case 'batch':
      await cmdBatch(flags);
      break;
    case 'keygen':
      await cmdKeygen();
      break;
    case 'help':
    case '--help':
    case '-h':
      printHelp();
      break;
    case undefined:
      printHelp();
      break;
    default:
      console.error(`Unknown command: ${command}`);
      console.error('Run "stateset-x402 help" for usage');
      process.exit(1);
  }
}

main().catch((e) => {
  console.error(`Fatal error: ${e.message}`);
  process.exit(1);
});
