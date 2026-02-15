# bolt12-ts

[![npm version](https://img.shields.io/npm/v/bolt12-ts)](https://www.npmjs.com/package/bolt12-ts)
[![CI](https://github.com/nova-carnivore/bolt12-ts/actions/workflows/ci.yml/badge.svg)](https://github.com/nova-carnivore/bolt12-ts/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3+-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20%2B-green.svg)](https://nodejs.org/)

Modern TypeScript implementation of BOLT 12 Lightning Network offer/invoice encoder/decoder with a minimal dependency tree.

## Why bolt12-ts?

BOLT 12 introduces **Offers**, a next-generation payment protocol for Lightning that enables reusable payment codes, invoice requests, and privacy-preserving blinded paths. This library provides a complete, spec-compliant implementation in TypeScript that:

- ✅ **Minimal dependencies** — Only depends on `@noble/curves` and `@noble/hashes` (audited, zero transitive deps)
- ✅ **Full BOLT 12 compliance** — Offers, Invoice Requests, Invoices, and Invoice Errors
- ✅ **BIP-340 Schnorr signatures** — Sign and verify with Merkle tree construction
- ✅ **Modern TypeScript** — Full type safety and excellent IDE support
- ✅ **ESM + CJS** — Works with both module systems
- ✅ **Universal runtime** — Works in Node.js, Bun, Deno, and browsers (no polyfills needed)
- ✅ **Well tested** — Comprehensive test suite with 70+ tests

## Installation

```bash
npm install bolt12-ts
```

## Runtime Compatibility

| Runtime | Status | Notes |
|---------|--------|-------|
| **Node.js** 20+ | ✅ Tested in CI | Full support |
| **Bun** 1.x | ✅ Tested in CI | Full support |
| **Deno** 2.x | ✅ Tested in CI | Use `--unstable-sloppy-imports` for `.js` extensions |
| **Browsers** (Chromium, Firefox, WebKit) | ✅ Tested in CI | Playwright tests against real browser engines |

No polyfills required — uses `@noble/curves` for Schnorr signatures, `@noble/hashes` for SHA-256, and `TextEncoder`/`TextDecoder` which are all universal.

## Quick Start

```typescript
import {
  encodeOffer,
  encodeInvoiceRequest,
  encodeInvoice,
  decodeBolt12,
  verifyBolt12Signature,
  Bech32mPrefix,
} from 'bolt12-ts';

// Decode any BOLT 12 string
const decoded = decodeBolt12('lno1pqps7sjqpgt...');
console.log(decoded.prefix); // 'lno', 'lnr', or 'lni'

// Encode an offer
const offer = encodeOffer({
  issuerId: myPublicKey,
  description: 'Buy a coffee',
  amountMsat: 100000n,
});
// → "lno1pq..."
```

## API

### `decodeBolt12(str: string): AnyDecodedBolt12`

Decodes any BOLT 12 string (offer, invoice request, or invoice).

```typescript
const decoded = decodeBolt12('lno1pqps7sjqpgt...');

switch (decoded.prefix) {
  case 'lno':
    console.log('Offer:', decoded.description);
    break;
  case 'lnr':
    console.log('Invoice Request from:', decoded.payerId);
    break;
  case 'lni':
    console.log('Invoice for:', decoded.amountMsat, 'msat');
    break;
}
```

### `encodeOffer(options: OfferEncodeOptions): string`

Creates a BOLT 12 offer. Offers are **not signed** per the spec.

```typescript
const offer = encodeOffer({
  issuerId: myPublicKey,          // 33-byte compressed public key
  description: 'Buy a coffee',
  amountMsat: 100000n,            // 100 sats
  issuer: 'CoffeeShop',
});
// → "lno1pq..."
```

With optional fields:

```typescript
const offer = encodeOffer({
  issuerId: myPublicKey,
  description: 'Premium Widget',
  amountMsat: 50000n,
  currency: 'USD',                // ISO 4217
  chains: [bitcoinChainHash],     // Omit for bitcoin-only
  absoluteExpiry: 1800000000n,    // Unix timestamp
  quantityMax: 100n,              // Max items per invoice
  issuer: 'WidgetCorp',
  paths: [blindedPath],           // Blinded paths for privacy
  features: featureBytes,
});
```

### `encodeInvoiceRequest(options: InvoiceRequestEncodeOptions): string`

Creates and signs a BOLT 12 invoice request.

```typescript
const invreq = encodeInvoiceRequest({
  invreqMetadata: crypto.getRandomValues(new Uint8Array(32)),
  payerId: myPublicKey,           // 33-byte compressed
  payerPrivateKey: myPrivateKey,  // 32-byte secret key

  // Mirror offer fields
  offerDescription: 'Buy a coffee',
  offerIssuerId: merchantPubkey,
  offerAmountMsat: 100000n,

  // Optional payer fields
  amountMsat: 150000n,            // Tip included
  payerNote: 'Extra hot please!',
  quantity: 2n,
  invreqBip353Name: { name: 'alice', domain: 'example.com' },
});
// → "lnr1pq..."
```

### `encodeInvoice(options: InvoiceEncodeOptions): string`

Creates and signs a BOLT 12 invoice.

```typescript
import { sha256 } from '@noble/hashes/sha256';

const preimage = crypto.getRandomValues(new Uint8Array(32));
const paymentHash = sha256(preimage);

const invoice = encodeInvoice({
  nodeId: myNodePubkey,           // 33-byte compressed
  nodePrivateKey: myNodePrivkey,  // 32-byte secret key
  createdAt: BigInt(Math.floor(Date.now() / 1000)),
  paymentHash,                    // 32-byte SHA256
  amountMsat: 100000n,
  invoicePaths: [blindedPath],    // At least one blinded path
  blindedPayInfo: [payInfo],      // Matching pay info per path

  // Optional
  relativeExpiry: 3600,           // Seconds (default: 7200)
  offerDescription: 'Buy a coffee',
  offerIssuerId: myNodePubkey,
});
// → "lni1pq..."
```

### `verifyBolt12Signature(tlvs, signature, publicKey, prefix): boolean`

Verifies a BIP-340 Schnorr signature on a BOLT 12 message.

```typescript
const decoded = decodeBolt12(invoiceRequestString);

if (decoded.prefix === 'lnr') {
  const isValid = verifyBolt12Signature(
    decoded.tlvs,
    decoded.signature,
    decoded.payerId,              // 33-byte or 32-byte x-only pubkey
    Bech32mPrefix.InvoiceRequest,
  );
  console.log('Signature valid:', isValid);
}
```

### `encodeInvoiceError(options) / decodeInvoiceError(bytes)`

Invoice errors are sent via onion messages to indicate problems with an invoice request or invoice. They use raw TLV encoding (not bech32).

```typescript
import { encodeInvoiceError, decodeInvoiceError, encodeTu64 } from 'bolt12-ts';

// Simple error message
const errorBytes = encodeInvoiceError({
  error: 'Unknown offer',
});

// Error pointing to a specific field
const fieldError = encodeInvoiceError({
  error: 'Amount too low',
  erroneousField: 82n,  // invreq_amount TLV type
});

// Error with a suggested correction
const suggestedError = encodeInvoiceError({
  error: 'Amount must be at least 100000 msat',
  erroneousField: 82n,
  suggestedValue: encodeTu64(100000n),
});

// Decoding an invoice error received via onion message
const decoded = decodeInvoiceError(rawErrorBytes);
console.log('Error:', decoded.error);
```

## Supported TLV Fields

### Offers (`lno`)

| TLV Type | Field | Description |
|----------|-------|-------------|
| 2 | `offer_chains` | Chain hashes (bitcoin by default) |
| 4 | `offer_metadata` | Arbitrary issuer metadata |
| 6 | `offer_currency` | ISO 4217 currency code |
| 8 | `offer_amount` | Amount in millisatoshis |
| 10 | `offer_description` | Short UTF-8 description |
| 12 | `offer_features` | Feature bits |
| 14 | `offer_absolute_expiry` | Expiry as seconds from epoch |
| 16 | `offer_paths` | Blinded paths to issuer |
| 18 | `offer_issuer` | Human-readable issuer name |
| 20 | `offer_quantity_max` | Max quantity per invoice |
| 22 | `offer_issuer_id` | Issuer public key |

### Invoice Requests (`lnr`)

| TLV Type | Field | Description |
|----------|-------|-------------|
| 0 | `invreq_metadata` | Unique random metadata (required) |
| 80 | `invreq_chain` | Chain hash |
| 82 | `invreq_amount` | Amount in millisatoshis |
| 84 | `invreq_features` | Feature bits |
| 86 | `invreq_quantity` | Quantity requested |
| 88 | `invreq_payer_id` | Payer public key (required) |
| 89 | `invreq_payer_note` | Payer note |
| 90 | `invreq_paths` | Payer's blinded paths |
| 91 | `invreq_bip_353_name` | BIP-353 human-readable name |
| 240 | `signature` | BIP-340 Schnorr signature (required) |

### Invoices (`lni`)

| TLV Type | Field | Description |
|----------|-------|-------------|
| 160 | `invoice_paths` | Blinded paths for payment (required) |
| 162 | `invoice_blindedpay` | Blinded pay info per path (required) |
| 164 | `invoice_created_at` | Creation timestamp (required) |
| 166 | `invoice_relative_expiry` | Seconds from creation |
| 168 | `invoice_payment_hash` | SHA256 payment hash (required) |
| 170 | `invoice_amount` | Amount in millisatoshis |
| 172 | `invoice_fallbacks` | On-chain fallback addresses |
| 174 | `invoice_features` | Feature bits |
| 176 | `invoice_node_id` | Node public key (required) |
| 240 | `signature` | BIP-340 Schnorr signature (required) |

### Invoice Errors

| TLV Type | Field | Description |
|----------|-------|-------------|
| 1 | `erroneous_field` | TLV type that caused the error |
| 3 | `suggested_value` | Suggested replacement value |
| 5 | `error` | Human-readable error message (required) |

## Examples

### Working with Blinded Paths

```typescript
import type { BlindedPath, BlindedPayInfo } from 'bolt12-ts';

const blindedPath: BlindedPath = {
  blindingPubkey: blindingKey,    // 33-byte compressed public key
  hops: [
    {
      nodeId: intermediateNode,   // 33-byte compressed
      tlvPayload: encryptedData,  // Encrypted routing data
    },
    {
      nodeId: finalNode,
      tlvPayload: finalData,
    },
  ],
};

const payInfo: BlindedPayInfo = {
  feeBaseMsat: 1000,
  feeProportionalMillionths: 100,
  cltvExpiryDelta: 144,
  htlcMinimumMsat: 1000n,
  htlcMaximumMsat: 1_000_000_000n,
  features: new Uint8Array(0),
};
```

### End-to-End Payment Flow

```typescript
import { encodeOffer, encodeInvoiceRequest, encodeInvoice, decodeBolt12 } from 'bolt12-ts';

// 1. Merchant creates an offer
const offer = encodeOffer({
  issuerId: merchantPubkey,
  description: 'Buy a coffee',
  amountMsat: 100000n,
});

// 2. Customer creates an invoice request
const invreq = encodeInvoiceRequest({
  invreqMetadata: crypto.getRandomValues(new Uint8Array(32)),
  payerId: customerPubkey,
  payerPrivateKey: customerPrivkey,
  offerDescription: 'Buy a coffee',
  offerIssuerId: merchantPubkey,
  offerAmountMsat: 100000n,
});

// 3. Merchant creates an invoice
const invoice = encodeInvoice({
  nodeId: merchantPubkey,
  nodePrivateKey: merchantPrivkey,
  createdAt: BigInt(Math.floor(Date.now() / 1000)),
  paymentHash: sha256(preimage),
  amountMsat: 100000n,
  invoicePaths: [blindedPath],
  blindedPayInfo: [payInfo],
});
```

## Testing

```bash
# Run all tests
npm test

# Run specific test suite
npx tsx --test test/bolt12.test.ts
npx tsx --test test/invoice-error.test.ts

# Type check
npm run typecheck

# Lint
npm run lint

# Format
npm run format
```

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests with coverage
npm test -- --experimental-test-coverage

# Format code
npm run format
```

## Specification

This library implements [BOLT #12: Offer Protocol](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md).

### Implemented

All four BOLT 12 message types are fully supported:

- **Offers** (`lno`) — All TLV fields (types 2–22)
- **Invoice Requests** (`lnr`) — All TLV fields (types 0, 2–22, 80–91, 240)
- **Invoices** (`lni`) — All TLV fields (types 0–22, 80–91, 160–176, 240)
- **Invoice Errors** — All TLV fields (types 1, 3, 5)

### Signature & Merkle Tree

- BIP-340 Schnorr signatures for invoice requests and invoices
- Full Merkle tree construction with `LnLeaf`/`LnNonce`/`LnBranch` tagged hashes
- Signature verification with both 32-byte x-only and 33-byte compressed public keys

### Intentionally Omitted

Features from the spec's "possible future extensions" section:

| Feature | Reason |
|---------|--------|
| Offer recurrence | Removed from spec |
| `invreq_refund_for` | Removed from spec |
| Delivery info | Future extension |
| Shopping lists | Future extension |
| Streaming invoices | Future extension |

### Protocol-Level Features (Out of Scope)

- **Onion message routing** — Separate protocol concern (BOLT 4)
- **Payment execution** — Handled by Lightning node implementations
- **Blinded path construction** — Requires onion routing primitives; this library encodes/decodes existing paths
- **Currency conversion** — Application-specific

## Security

### Minimal Dependency Tree

This library has two production dependencies, both from the audited [@noble](https://paulmillr.com/noble/) family by Paul Miller:

- [`@noble/curves`](https://github.com/paulmillr/noble-curves) — BIP-340 Schnorr signatures
- [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) — SHA-256 hashing

Both have zero transitive dependencies, are audited, and work across all runtimes. A minimal dependency tree reduces the attack surface.

### Reporting Vulnerabilities

If you discover a security vulnerability, please [open a GitHub issue](https://github.com/nova-carnivore/bolt12-ts/issues).

## License

MIT © Nova Carnivore

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass: `npm test`
5. Format code: `npm run format`
6. Submit a pull request

## Acknowledgments

- [BOLT 12 specification](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md) authors
- [@noble/curves](https://github.com/paulmillr/noble-curves) and [@noble/hashes](https://github.com/paulmillr/noble-hashes) by Paul Miller

## See Also

- [bolt11-ts](https://github.com/nova-carnivore/bolt11-ts) — BOLT 11 invoice encoder/decoder (companion library)
- [BOLT Specifications](https://github.com/lightning/bolts)
- [Lightning Network](https://lightning.network/)
- [BIP-340: Schnorr Signatures](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [BIP-173: Bech32](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki)
