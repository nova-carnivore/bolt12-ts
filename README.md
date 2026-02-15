# bolt12-ts

[![CI](https://github.com/nova-carnivore/bolt12-ts/actions/workflows/ci.yml/badge.svg)](https://github.com/nova-carnivore/bolt12-ts/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/bolt12-ts.svg)](https://www.npmjs.com/package/bolt12-ts)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org/)

Modern TypeScript BOLT 12 Lightning Network offer/invoice encoder/decoder with zero vulnerable dependencies.

Supports encoding and decoding of BOLT 12 **Offers** (`lno`), **Invoice Requests** (`lnr`), and **Invoices** (`lni`) with full BIP-340 Schnorr signature support and Merkle tree construction.

## Features

- **Full BOLT 12 compliance** — Offers, Invoice Requests, and Invoices
- **BIP-340 Schnorr signatures** — Sign and verify with Merkle tree construction
- **BIP-353 support** — Human-readable name parsing for invoice requests
- **Bech32 encoding** — Spec-compliant (no checksum, per BOLT 12)
- **Blinded paths** — Full encode/decode support
- **Zero vulnerable dependencies** — Uses only `@noble/curves` and `@noble/hashes`
- **Cross-platform** — Node.js 20+, Bun, Deno, browsers
- **TypeScript strict mode** — Full type safety with comprehensive JSDoc

## Installation

```bash
npm install bolt12-ts
```

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
```

## Usage

### Decoding any BOLT 12 string

```typescript
import { decodeBolt12 } from 'bolt12-ts';

// Works with offers, invoice requests, and invoices
const decoded = decodeBolt12('lno1pqps7sjqpgtyzm3qv4uxzmtsd3...');

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

### Encoding an Offer

Offers are the starting point for BOLT 12 payments. They are **not signed** per the spec.

```typescript
import { encodeOffer } from 'bolt12-ts';

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

### Encoding an Invoice Request

Invoice requests are created by the payer in response to an offer. They are **automatically signed** using the payer's private key.

```typescript
import { encodeInvoiceRequest } from 'bolt12-ts';

const invreq = encodeInvoiceRequest({
  // Required fields
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

### Encoding an Invoice

Invoices are created by the merchant in response to an invoice request. They are **automatically signed** using the node's private key.

```typescript
import { encodeInvoice } from 'bolt12-ts';
import { sha256 } from '@noble/hashes/sha256';

const preimage = crypto.getRandomValues(new Uint8Array(32));
const paymentHash = sha256(preimage);

const invoice = encodeInvoice({
  // Required fields
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

  // Mirror invoice request fields
  invreqMetadata: requestMetadata,
  invreqPayerId: payerPubkey,
});
// → "lni1pq..."
```

### Verifying Signatures

```typescript
import { decodeBolt12, verifyBolt12Signature, Bech32mPrefix } from 'bolt12-ts';

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

### Invoice Errors

Invoice errors are sent via onion messages to indicate problems with an `invoice_request` or `invoice`. They use raw TLV encoding (not bech32).

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
if (decoded.erroneousField !== undefined) {
  console.log('Problem field TLV type:', decoded.erroneousField);
}
if (decoded.suggestedValue) {
  console.log('Suggested value:', decoded.suggestedValue);
}
```

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

## API Reference

### Decoding

| Function | Description |
|----------|-------------|
| `decodeBolt12(str)` | Decode any BOLT 12 string (offer/invreq/invoice) |
| `decodeInvoiceError(bytes)` | Decode a raw TLV invoice error |

### Encoding

| Function | Description |
|----------|-------------|
| `encodeOffer(options)` | Encode a BOLT 12 offer (unsigned) |
| `encodeInvoiceRequest(options)` | Encode and sign a BOLT 12 invoice request |
| `encodeInvoice(options)` | Encode and sign a BOLT 12 invoice |
| `encodeInvoiceError(options)` | Encode an invoice error as raw TLV bytes |
| `encodeBolt12({ hrp, tlvs })` | Low-level: encode raw TLVs with HRP |

### Signatures

| Function | Description |
|----------|-------------|
| `signBolt12(tlvs, privateKey, prefix)` | Sign TLVs using BIP-340 Schnorr |
| `verifyBolt12Signature(tlvs, sig, pubkey, prefix)` | Verify a BOLT 12 signature |
| `computeMerkleRoot(tlvs)` | Compute the Merkle root of TLV entries |
| `taggedHash(tag, msg)` | BIP-340 tagged hash: H(tag, msg) |
| `signatureTag(prefix, fieldName?)` | Get the signature tag string |

### Types

```typescript
// Decoded types
type AnyDecodedBolt12 = DecodedOffer | DecodedInvoiceRequest | DecodedInvoice;

// Encoding option types
type OfferEncodeOptions = { issuerId?, description?, amountMsat?, ... };
type InvoiceRequestEncodeOptions = { invreqMetadata, payerId, payerPrivateKey, ... };
type InvoiceEncodeOptions = { nodeId, nodePrivateKey, createdAt, paymentHash, ... };

// Data types
type BlindedPath = { blindingPubkey, hops: OnionMessageHop[] };
type BlindedPayInfo = { feeBaseMsat, feeProportionalMillionths, cltvExpiryDelta, ... };
type TlvEntry = { type: bigint, length: bigint, value: Uint8Array };

// Prefixes
enum Bech32mPrefix { Offer = 'lno', InvoiceRequest = 'lnr', Invoice = 'lni' }
```

### Low-level Utilities

| Function | Description |
|----------|-------------|
| `bolt12Encode(hrp, data)` | Bech32 encode without checksum (BOLT 12) |
| `bolt12Decode(str)` | Bech32 decode without checksum (BOLT 12) |
| `bech32mEncode(hrp, data)` | Bech32m encode with checksum |
| `bech32mDecode(str)` | Bech32m decode with checksum |
| `convertBits(data, in, out, pad)` | Convert between bit widths |
| `encodeTlvStream(tlvs)` | Encode TLV array to bytes |
| `decodeTlvStream(bytes)` | Decode bytes to TLV array |
| `hexToBytes(hex)` / `bytesToHex(bytes)` | Hex conversion |

## Spec Compliance

This library implements [BOLT 12](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md) with the following features:

| Feature | Status |
|---------|--------|
| Offer encoding/decoding | ✅ Stable |
| Invoice Request encoding/decoding | ✅ Stable |
| Invoice encoding/decoding | ✅ Stable |
| Invoice Error encoding/decoding | ✅ Stable |
| BIP-340 Schnorr signatures | ✅ Stable |
| Merkle tree signature verification | ✅ Stable |
| Blinded paths | ✅ Stable |
| Blinded pay info | ✅ Stable |
| BIP-353 name parsing | ✅ Stable |
| Bech32 encoding (no checksum) | ✅ Stable |
| `+` concatenation support | ✅ Stable |
| Fallback addresses | ✅ Stable |

## Spec Coverage

### Implemented

All four BOLT 12 message types are fully supported:

- **Offers** (`lno`) — All TLV fields (types 2–22): chains, metadata, currency, amount, description, features, absolute expiry, paths, issuer, quantity_max, issuer_id
- **Invoice Requests** (`lnr`) — All TLV fields (types 0, 2–22, 80–91, 240): All offer fields mirrored, plus invreq_metadata, chain, amount, features, quantity, payer_id, payer_note, paths, bip_353_name, signature
- **Invoices** (`lni`) — All TLV fields (types 0–22, 80–91, 160–176, 240): All offer and invreq fields mirrored, plus invoice_paths, blindedpay, created_at, relative_expiry, payment_hash, amount, fallbacks, features, node_id, signature
- **Invoice Errors** — All TLV fields (types 1, 3, 5): erroneous_field, suggested_value, error

### Signature & Merkle Tree

- BIP-340 Schnorr signatures for invoice requests and invoices
- Full Merkle tree construction with LnLeaf/LnNonce/LnBranch tagged hashes
- Signature verification with both 32-byte x-only and 33-byte compressed public keys

### Intentionally Omitted

The following features are mentioned in the BOLT 12 spec's "possible future extensions" section but are **not yet part of the finalized spec** and are therefore not implemented:

| Feature | Reason |
|---------|--------|
| Offer recurrence | Removed from spec (listed as "re-add recurrence" in future extensions) |
| `invreq_refund_for` | Removed from spec (listed as "re-add" in future extensions) |
| `invoice_replace` | Removed from spec (listed as "re-add" in future extensions) |
| Delivery info in offers | Listed as possible future extension (#1) |
| Offer updates | Listed as possible future extension (#2) |
| Shopping lists (multi-offer) | Listed as possible future extension (#4) |
| Streaming invoices | Listed as possible future extension (#8) |
| Raw invoices (no invreq) | Spec says "may define in future"; we don't generate them but can decode them |

### Protocol-Level Features (Out of Scope)

These features are part of the Lightning protocol layer, not the BOLT 12 encoding layer:

- **Onion message routing** — BOLT 12 messages are transported via onion messages (BOLT 4), which is a separate protocol concern
- **Payment execution** — Actually sending/receiving payments is handled by the Lightning node implementation
- **Blinded path construction** — Creating new blinded paths requires onion routing primitives; this library encodes/decodes existing paths
- **Currency conversion** — Converting `offer_currency` amounts to msat is application-specific

## Platform Support

| Platform | Status |
|----------|--------|
| Node.js 20+ | ✅ Tested (20, 22, 24) |
| Bun | ✅ Tested |
| Deno | ✅ Compatible |
| Browsers (via bundler) | ✅ Compatible |

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test                    # Node.js
npm run test:bun            # Bun

# Build
npm run build

# Type check
npm run typecheck

# Lint & format
npm run lint
npm run format
```

## License

MIT

## Related

- [bolt11-ts](https://github.com/nicovalji/bolt11-ts) — BOLT 11 invoice encoder/decoder
- [@noble/curves](https://github.com/paulmillr/noble-curves) — Elliptic curve cryptography
- [@noble/hashes](https://github.com/paulmillr/noble-hashes) — Hash functions
- [BOLT 12 Spec](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md) — Full specification
