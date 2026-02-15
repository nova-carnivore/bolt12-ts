import assert from 'node:assert';
import { describe, it } from 'node:test';
import {
  encodeBolt12,
  encodeOffer,
  encodeInvoiceRequest,
  encodeInvoice,
  encodeBlindedPaths,
  encodeBlindedPayInfoArray,
} from '../src/encode';
import { encodeTlvStream } from '../src/tlv';
import { decodeBolt12 } from '../src/decode';
import { signBolt12, verifyBolt12Signature, computeMerkleRoot, taggedHash } from '../src/signature';
import { bolt12Encode, bolt12Decode, convertBits } from '../src/bech32m';
import {
  Bech32mPrefix,
  TlvEntry,
  DecodedOffer,
  DecodedInvoiceRequest,
  DecodedInvoice,
  BlindedPath,
  BlindedPayInfo,
} from '../src/types';
import { hexToBytes, bytesToHex, utf8ToBytes, numberToBytesBE } from '../src/utils';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

// ── Test key pairs ─────────────────────────────────────────────

// Deterministic test keys
const issuerPrivkey = hexToBytes('e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734');
const issuerPubkey = secp256k1.getPublicKey(issuerPrivkey, true);
const payerPrivkey = hexToBytes('d7e0c73e08845e3be0bdb48b5dc7a5fc5e3e81ec4a9ae64df9214a9851f6e800');
const payerPubkey = secp256k1.getPublicKey(payerPrivkey, true);

// ── Helper ─────────────────────────────────────────────────────

function randomBytes(n: number): Uint8Array {
  // Deterministic pseudo-random for reproducible tests
  const buf = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    buf[i] = ((i * 137 + 43) % 256);
  }
  return buf;
}

// ── Offer Tests ────────────────────────────────────────────────

describe('Offer Encoding/Decoding', () => {
  it('should encode and decode a minimal offer', () => {
    const encoded = encodeOffer({
      issuerId: issuerPubkey,
      description: 'Test offer',
    });

    assert.ok(encoded.startsWith('lno1'));

    const decoded = decodeBolt12(encoded) as DecodedOffer;
    assert.strictEqual(decoded.prefix, Bech32mPrefix.Offer);
    assert.strictEqual(decoded.description, 'Test offer');
    assert.deepStrictEqual(decoded.issuerId, issuerPubkey);
  });

  it('should encode and decode offer with amount', () => {
    const encoded = encodeOffer({
      issuerId: issuerPubkey,
      description: 'Coffee',
      amountMsat: BigInt(100000),
    });

    const decoded = decodeBolt12(encoded) as DecodedOffer;
    assert.strictEqual(decoded.amountMsat, BigInt(100000));
    assert.strictEqual(decoded.description, 'Coffee');
  });

  it('should encode and decode offer with currency', () => {
    const encoded = encodeOffer({
      issuerId: issuerPubkey,
      description: 'Widget',
      amountMsat: BigInt(500),
      currency: 'USD',
    });

    const decoded = decodeBolt12(encoded) as DecodedOffer;
    assert.strictEqual(decoded.currency, 'USD');
    assert.strictEqual(decoded.amountMsat, BigInt(500));
  });

  it('should encode and decode offer with all optional fields', () => {
    const chains = [hexToBytes('6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000')];
    const metadata = randomBytes(32);
    const blindingPubkey = issuerPubkey;
    const nodeId = payerPubkey;
    const tlvPayload = randomBytes(16);
    const paths: BlindedPath[] = [{
      blindingPubkey,
      hops: [{ nodeId, tlvPayload }],
    }];

    const encoded = encodeOffer({
      issuerId: issuerPubkey,
      description: 'Full offer',
      amountMsat: BigInt(50000),
      currency: 'btc',
      chains,
      metadata,
      absoluteExpiry: BigInt(1700000000),
      paths,
      issuer: 'TestMerchant',
      quantityMax: BigInt(100),
      features: new Uint8Array([0x01]),
    });

    const decoded = decodeBolt12(encoded) as DecodedOffer;
    assert.strictEqual(decoded.prefix, Bech32mPrefix.Offer);
    assert.strictEqual(decoded.description, 'Full offer');
    assert.strictEqual(decoded.amountMsat, BigInt(50000));
    assert.strictEqual(decoded.currency, 'btc');
    assert.ok(decoded.chains);
    assert.strictEqual(decoded.chains!.length, 1);
    assert.deepStrictEqual(decoded.metadata, metadata);
    assert.strictEqual(decoded.absoluteExpiry, BigInt(1700000000));
    assert.strictEqual(decoded.issuer, 'TestMerchant');
    assert.strictEqual(decoded.quantityMax, BigInt(100));
    assert.deepStrictEqual(decoded.features, new Uint8Array([0x01]));
    assert.ok(decoded.paths);
    assert.strictEqual(decoded.paths!.length, 1);
    assert.deepStrictEqual(decoded.paths![0].blindingPubkey, blindingPubkey);
    assert.strictEqual(decoded.paths![0].hops.length, 1);
    assert.deepStrictEqual(decoded.paths![0].hops[0].nodeId, nodeId);
    assert.deepStrictEqual(decoded.paths![0].hops[0].tlvPayload, tlvPayload);
  });

  it('should reject offer with amount but no description', () => {
    assert.throws(
      () => encodeOffer({ issuerId: issuerPubkey, amountMsat: BigInt(1000) }),
      /Offer with amount must have a description/,
    );
  });

  it('should reject offer with currency but no amount', () => {
    assert.throws(
      () => encodeOffer({ issuerId: issuerPubkey, currency: 'USD', description: 'test' }),
      /Offer with currency must have an amount/,
    );
  });

  it('should reject offer without issuerId or paths', () => {
    assert.throws(
      () => encodeOffer({ description: 'no issuer' }),
      /Offer must have either issuerId or paths/,
    );
  });

  it('should handle offer with paths but no issuerId', () => {
    const paths: BlindedPath[] = [{
      blindingPubkey: issuerPubkey,
      hops: [{ nodeId: payerPubkey, tlvPayload: randomBytes(8) }],
    }];

    const encoded = encodeOffer({ paths, description: 'path-only offer' });
    const decoded = decodeBolt12(encoded) as DecodedOffer;
    assert.strictEqual(decoded.description, 'path-only offer');
    assert.ok(decoded.paths);
    assert.strictEqual(decoded.paths!.length, 1);
    assert.strictEqual(decoded.issuerId, undefined);
  });
});

// ── Invoice Request Tests ──────────────────────────────────────

describe('Invoice Request Encoding/Decoding', () => {
  it('should encode and decode a basic invoice request', () => {
    const metadata = randomBytes(32);

    const encoded = encodeInvoiceRequest({
      invreqMetadata: metadata,
      payerId: payerPubkey,
      payerPrivateKey: payerPrivkey,
      offerDescription: 'Test offer',
      offerIssuerId: issuerPubkey,
    });

    assert.ok(encoded.startsWith('lnr1'));

    const decoded = decodeBolt12(encoded) as DecodedInvoiceRequest;
    assert.strictEqual(decoded.prefix, Bech32mPrefix.InvoiceRequest);
    assert.deepStrictEqual(decoded.invreqMetadata, metadata);
    assert.deepStrictEqual(decoded.payerId, payerPubkey);
    assert.strictEqual(decoded.offerDescription, 'Test offer');
    assert.deepStrictEqual(decoded.offerIssuerId, issuerPubkey);
    assert.strictEqual(decoded.signature.length, 64);
  });

  it('should encode and decode invoice request with amount and note', () => {
    const metadata = randomBytes(32);

    const encoded = encodeInvoiceRequest({
      invreqMetadata: metadata,
      payerId: payerPubkey,
      payerPrivateKey: payerPrivkey,
      amountMsat: BigInt(250000),
      payerNote: 'For 2 coffees please',
      offerDescription: 'Coffee shop',
      offerIssuerId: issuerPubkey,
      offerAmountMsat: BigInt(100000),
    });

    const decoded = decodeBolt12(encoded) as DecodedInvoiceRequest;
    assert.strictEqual(decoded.amountMsat, BigInt(250000));
    assert.strictEqual(decoded.payerNote, 'For 2 coffees please');
    assert.strictEqual(decoded.offerAmountMsat, BigInt(100000));
  });

  it('should encode and decode invoice request with BIP-353 name', () => {
    const metadata = randomBytes(32);

    const encoded = encodeInvoiceRequest({
      invreqMetadata: metadata,
      payerId: payerPubkey,
      payerPrivateKey: payerPrivkey,
      offerDescription: 'Donation',
      offerIssuerId: issuerPubkey,
      invreqBip353Name: { name: 'satoshi', domain: 'bitcoin.org' },
    });

    const decoded = decodeBolt12(encoded) as DecodedInvoiceRequest;
    assert.ok(decoded.invreqBip353Name);
    assert.strictEqual(decoded.invreqBip353Name!.name, 'satoshi');
    assert.strictEqual(decoded.invreqBip353Name!.domain, 'bitcoin.org');
  });

  it('should encode and decode invoice request with quantity', () => {
    const metadata = randomBytes(32);

    const encoded = encodeInvoiceRequest({
      invreqMetadata: metadata,
      payerId: payerPubkey,
      payerPrivateKey: payerPrivkey,
      offerDescription: 'Widget',
      offerIssuerId: issuerPubkey,
      offerQuantityMax: BigInt(10),
      quantity: BigInt(3),
    });

    const decoded = decodeBolt12(encoded) as DecodedInvoiceRequest;
    assert.strictEqual(decoded.quantity, BigInt(3));
    assert.strictEqual(decoded.offerQuantityMax, BigInt(10));
  });

  it('should produce valid signatures that can be verified', () => {
    const metadata = randomBytes(32);

    const encoded = encodeInvoiceRequest({
      invreqMetadata: metadata,
      payerId: payerPubkey,
      payerPrivateKey: payerPrivkey,
      offerDescription: 'Sig test',
      offerIssuerId: issuerPubkey,
    });

    const decoded = decodeBolt12(encoded) as DecodedInvoiceRequest;

    // Verify the signature
    const isValid = verifyBolt12Signature(
      decoded.tlvs,
      decoded.signature,
      decoded.payerId,
      Bech32mPrefix.InvoiceRequest,
    );
    assert.ok(isValid, 'Signature should be valid');
  });
});

// ── Invoice Tests ──────────────────────────────────────────────

describe('Invoice Encoding/Decoding', () => {
  const paymentHash = sha256(utf8ToBytes('test_preimage'));

  const blindedPath: BlindedPath = {
    blindingPubkey: issuerPubkey,
    hops: [{
      nodeId: payerPubkey,
      tlvPayload: randomBytes(16),
    }],
  };

  const payInfo: BlindedPayInfo = {
    feeBaseMsat: 1000,
    feeProportionalMillionths: 100,
    cltvExpiryDelta: 144,
    htlcMinimumMsat: BigInt(1000),
    htlcMaximumMsat: BigInt(1000000000),
    features: new Uint8Array(0),
  };

  it('should encode and decode a basic invoice', () => {
    const encoded = encodeInvoice({
      nodeId: issuerPubkey,
      nodePrivateKey: issuerPrivkey,
      createdAt: BigInt(1700000000),
      paymentHash,
      amountMsat: BigInt(100000),
      invoicePaths: [blindedPath],
      blindedPayInfo: [payInfo],
      offerDescription: 'Invoice test',
      offerIssuerId: issuerPubkey,
    });

    assert.ok(encoded.startsWith('lni1'));

    const decoded = decodeBolt12(encoded) as DecodedInvoice;
    assert.strictEqual(decoded.prefix, Bech32mPrefix.Invoice);
    assert.strictEqual(decoded.createdAt, BigInt(1700000000));
    assert.deepStrictEqual(decoded.paymentHash, paymentHash);
    assert.strictEqual(decoded.amountMsat, BigInt(100000));
    assert.deepStrictEqual(decoded.nodeId, issuerPubkey);
    assert.strictEqual(decoded.signature.length, 64);
    assert.strictEqual(decoded.invoicePaths.length, 1);
    assert.strictEqual(decoded.blindedPayInfo.length, 1);
  });

  it('should encode and decode invoice with relative expiry', () => {
    const encoded = encodeInvoice({
      nodeId: issuerPubkey,
      nodePrivateKey: issuerPrivkey,
      createdAt: BigInt(1700000000),
      paymentHash,
      amountMsat: BigInt(50000),
      invoicePaths: [blindedPath],
      blindedPayInfo: [payInfo],
      relativeExpiry: 3600,
    });

    const decoded = decodeBolt12(encoded) as DecodedInvoice;
    assert.strictEqual(decoded.relativeExpiry, 3600);
  });

  it('should encode and decode invoice with mirrored request fields', () => {
    const invreqMetadata = randomBytes(32);

    const encoded = encodeInvoice({
      nodeId: issuerPubkey,
      nodePrivateKey: issuerPrivkey,
      createdAt: BigInt(1700000000),
      paymentHash,
      amountMsat: BigInt(200000),
      invoicePaths: [blindedPath],
      blindedPayInfo: [payInfo],
      invreqMetadata,
      invreqPayerId: payerPubkey,
      invreqPayerNote: 'Thanks!',
      offerDescription: 'Coffee',
      offerIssuerId: issuerPubkey,
      offerAmountMsat: BigInt(100000),
    });

    const decoded = decodeBolt12(encoded) as DecodedInvoice;
    assert.deepStrictEqual(decoded.invreqMetadata, invreqMetadata);
    assert.deepStrictEqual(decoded.invreqPayerId, payerPubkey);
    assert.strictEqual(decoded.invreqPayerNote, 'Thanks!');
    assert.strictEqual(decoded.offerDescription, 'Coffee');
    assert.strictEqual(decoded.offerAmountMsat, BigInt(100000));
  });

  it('should encode and decode invoice with blinded pay info correctly', () => {
    const payInfoFull: BlindedPayInfo = {
      feeBaseMsat: 5000,
      feeProportionalMillionths: 250,
      cltvExpiryDelta: 288,
      htlcMinimumMsat: BigInt(2000),
      htlcMaximumMsat: BigInt(5000000000),
      features: new Uint8Array([0x02, 0x00]),
    };

    const encoded = encodeInvoice({
      nodeId: issuerPubkey,
      nodePrivateKey: issuerPrivkey,
      createdAt: BigInt(1700000000),
      paymentHash,
      amountMsat: BigInt(100000),
      invoicePaths: [blindedPath],
      blindedPayInfo: [payInfoFull],
    });

    const decoded = decodeBolt12(encoded) as DecodedInvoice;
    const decodedPayInfo = decoded.blindedPayInfo[0];
    assert.strictEqual(decodedPayInfo.feeBaseMsat, 5000);
    assert.strictEqual(decodedPayInfo.feeProportionalMillionths, 250);
    assert.strictEqual(decodedPayInfo.cltvExpiryDelta, 288);
    assert.strictEqual(decodedPayInfo.htlcMinimumMsat, BigInt(2000));
    assert.strictEqual(decodedPayInfo.htlcMaximumMsat, BigInt(5000000000));
    assert.deepStrictEqual(decodedPayInfo.features, new Uint8Array([0x02, 0x00]));
  });

  it('should produce valid signatures', () => {
    const encoded = encodeInvoice({
      nodeId: issuerPubkey,
      nodePrivateKey: issuerPrivkey,
      createdAt: BigInt(1700000000),
      paymentHash,
      amountMsat: BigInt(100000),
      invoicePaths: [blindedPath],
      blindedPayInfo: [payInfo],
    });

    const decoded = decodeBolt12(encoded) as DecodedInvoice;

    const isValid = verifyBolt12Signature(
      decoded.tlvs,
      decoded.signature,
      decoded.nodeId,
      Bech32mPrefix.Invoice,
    );
    assert.ok(isValid, 'Invoice signature should be valid');
  });

  it('should reject invoice with mismatched paths and payinfo counts', () => {
    assert.throws(
      () => encodeInvoice({
        nodeId: issuerPubkey,
        nodePrivateKey: issuerPrivkey,
        createdAt: BigInt(1700000000),
        paymentHash,
        amountMsat: BigInt(100000),
        invoicePaths: [blindedPath, blindedPath],
        blindedPayInfo: [payInfo],
      }),
      /Number of invoice_paths and blinded_payinfo must match/,
    );
  });
});

// ── Signature Tests ────────────────────────────────────────────

describe('Signature Verification', () => {
  it('should verify a valid invoice request signature', () => {
    const metadata = randomBytes(32);

    const encoded = encodeInvoiceRequest({
      invreqMetadata: metadata,
      payerId: payerPubkey,
      payerPrivateKey: payerPrivkey,
      offerDescription: 'Verify test',
      offerIssuerId: issuerPubkey,
    });

    const decoded = decodeBolt12(encoded) as DecodedInvoiceRequest;
    const valid = verifyBolt12Signature(
      decoded.tlvs,
      decoded.signature,
      decoded.payerId,
      Bech32mPrefix.InvoiceRequest,
    );
    assert.ok(valid);
  });

  it('should reject signature with wrong key', () => {
    const metadata = randomBytes(32);

    const encoded = encodeInvoiceRequest({
      invreqMetadata: metadata,
      payerId: payerPubkey,
      payerPrivateKey: payerPrivkey,
      offerDescription: 'Wrong key test',
      offerIssuerId: issuerPubkey,
    });

    const decoded = decodeBolt12(encoded) as DecodedInvoiceRequest;

    // Use the issuer's pubkey instead of payer's — should fail
    const valid = verifyBolt12Signature(
      decoded.tlvs,
      decoded.signature,
      issuerPubkey,
      Bech32mPrefix.InvoiceRequest,
    );
    assert.strictEqual(valid, false);
  });

  it('should reject corrupted signature', () => {
    const metadata = randomBytes(32);

    const encoded = encodeInvoiceRequest({
      invreqMetadata: metadata,
      payerId: payerPubkey,
      payerPrivateKey: payerPrivkey,
      offerDescription: 'Corrupt sig test',
      offerIssuerId: issuerPubkey,
    });

    const decoded = decodeBolt12(encoded) as DecodedInvoiceRequest;

    // Corrupt one byte of the signature
    const corruptedSig = new Uint8Array(decoded.signature);
    corruptedSig[0] ^= 0xff;

    const valid = verifyBolt12Signature(
      decoded.tlvs,
      corruptedSig,
      decoded.payerId,
      Bech32mPrefix.InvoiceRequest,
    );
    assert.strictEqual(valid, false);
  });

  it('should throw on invalid signature length', () => {
    assert.throws(
      () => verifyBolt12Signature(
        [],
        new Uint8Array(63), // Wrong length
        issuerPubkey,
        Bech32mPrefix.Invoice,
      ),
      /Invalid signature length/,
    );
  });

  it('should throw on invalid public key length', () => {
    assert.throws(
      () => verifyBolt12Signature(
        [],
        new Uint8Array(64),
        new Uint8Array(31), // Wrong length
        Bech32mPrefix.Invoice,
      ),
      /Invalid public key length/,
    );
  });

  it('should handle 32-byte x-only public key for verification', () => {
    const metadata = randomBytes(32);

    const encoded = encodeInvoiceRequest({
      invreqMetadata: metadata,
      payerId: payerPubkey,
      payerPrivateKey: payerPrivkey,
      offerDescription: 'X-only test',
      offerIssuerId: issuerPubkey,
    });

    const decoded = decodeBolt12(encoded) as DecodedInvoiceRequest;

    // Use x-only (32-byte) version of the public key
    const xOnlyPubkey = payerPubkey.subarray(1);
    const valid = verifyBolt12Signature(
      decoded.tlvs,
      decoded.signature,
      xOnlyPubkey,
      Bech32mPrefix.InvoiceRequest,
    );
    assert.ok(valid);
  });
});

// ── Merkle Tree Tests ──────────────────────────────────────────

describe('Merkle Tree', () => {
  it('should compute merkle root for a single TLV', () => {
    const tlvs: TlvEntry[] = [
      { type: BigInt(10), length: BigInt(5), value: utf8ToBytes('hello') },
    ];
    const root = computeMerkleRoot(tlvs);
    assert.strictEqual(root.length, 32);
  });

  it('should compute merkle root for multiple TLVs', () => {
    const tlvs: TlvEntry[] = [
      { type: BigInt(0), length: BigInt(4), value: randomBytes(4) },
      { type: BigInt(10), length: BigInt(5), value: utf8ToBytes('hello') },
      { type: BigInt(22), length: BigInt(33), value: issuerPubkey },
    ];
    const root = computeMerkleRoot(tlvs);
    assert.strictEqual(root.length, 32);
  });

  it('should produce consistent results', () => {
    const tlvs: TlvEntry[] = [
      { type: BigInt(10), length: BigInt(4), value: utf8ToBytes('test') },
    ];
    const root1 = computeMerkleRoot(tlvs);
    const root2 = computeMerkleRoot(tlvs);
    assert.deepStrictEqual(root1, root2);
  });

  it('should produce different results for different TLVs', () => {
    const tlvs1: TlvEntry[] = [
      { type: BigInt(10), length: BigInt(4), value: utf8ToBytes('aaaa') },
    ];
    const tlvs2: TlvEntry[] = [
      { type: BigInt(10), length: BigInt(4), value: utf8ToBytes('bbbb') },
    ];
    const root1 = computeMerkleRoot(tlvs1);
    const root2 = computeMerkleRoot(tlvs2);
    assert.notDeepStrictEqual(root1, root2);
  });
});

// ── BOLT 12 bech32 format tests ────────────────────────────────

describe('BOLT 12 Bech32 (no checksum)', () => {
  it('should encode and decode without checksum', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const encoded = bolt12Encode('lno', data);
    assert.ok(encoded.startsWith('lno1'));

    const decoded = bolt12Decode(encoded);
    assert.strictEqual(decoded.hrp, 'lno');
    assert.deepStrictEqual(decoded.data, data);
  });

  it('should handle + concatenation', () => {
    const data = new Uint8Array([1, 2, 3, 4]);
    const encoded = bolt12Encode('lno', data);

    // Split with +
    const mid = Math.floor(encoded.length / 2);
    const withPlus = encoded.slice(0, mid) + '+' + encoded.slice(mid);

    const decoded = bolt12Decode(withPlus);
    assert.strictEqual(decoded.hrp, 'lno');
    assert.deepStrictEqual(decoded.data, data);
  });

  it('should handle + with whitespace', () => {
    const data = new Uint8Array([1, 2, 3, 4]);
    const encoded = bolt12Encode('lno', data);

    const mid = Math.floor(encoded.length / 2);
    const withPlusWs = encoded.slice(0, mid) + '+\n  ' + encoded.slice(mid);

    const decoded = bolt12Decode(withPlusWs);
    assert.strictEqual(decoded.hrp, 'lno');
    assert.deepStrictEqual(decoded.data, data);
  });

  it('should reject mixed case', () => {
    assert.throws(
      () => bolt12Decode('Lno1pq'),
      /Mixed case/,
    );
  });

  it('should handle uppercase', () => {
    const data = new Uint8Array([1, 2, 3, 4]);
    const encoded = bolt12Encode('lno', data).toUpperCase();
    const decoded = bolt12Decode(encoded);
    assert.strictEqual(decoded.hrp, 'lno');
    assert.deepStrictEqual(decoded.data, data);
  });

  it('should reject unknown HRP in decodeBolt12', () => {
    const data = new Uint8Array([1, 2, 3, 4]);
    const encoded = bolt12Encode('unk', data);
    assert.throws(
      () => decodeBolt12(encoded),
      /Unknown BOLT 12 HRP/,
    );
  });
});

// ── BIP-353 Tests ──────────────────────────────────────────────

describe('BIP-353 Name Parsing', () => {
  it('should roundtrip BIP-353 names in invoice requests', () => {
    const metadata = randomBytes(32);

    const encoded = encodeInvoiceRequest({
      invreqMetadata: metadata,
      payerId: payerPubkey,
      payerPrivateKey: payerPrivkey,
      offerDescription: 'BIP-353 test',
      offerIssuerId: issuerPubkey,
      invreqBip353Name: { name: 'alice', domain: 'example.com' },
    });

    const decoded = decodeBolt12(encoded) as DecodedInvoiceRequest;
    assert.ok(decoded.invreqBip353Name);
    assert.strictEqual(decoded.invreqBip353Name!.name, 'alice');
    assert.strictEqual(decoded.invreqBip353Name!.domain, 'example.com');
  });

  it('should accept valid BIP-353 characters', () => {
    const metadata = randomBytes(32);

    const encoded = encodeInvoiceRequest({
      invreqMetadata: metadata,
      payerId: payerPubkey,
      payerPrivateKey: payerPrivkey,
      offerDescription: 'BIP-353 chars',
      offerIssuerId: issuerPubkey,
      invreqBip353Name: { name: 'my-user_name.123', domain: 'sub.domain-test.com' },
    });

    const decoded = decodeBolt12(encoded) as DecodedInvoiceRequest;
    assert.strictEqual(decoded.invreqBip353Name!.name, 'my-user_name.123');
    assert.strictEqual(decoded.invreqBip353Name!.domain, 'sub.domain-test.com');
  });
});

// ── Error Handling Tests ───────────────────────────────────────

describe('Error Handling', () => {
  it('should throw on empty string', () => {
    assert.throws(
      () => decodeBolt12(''),
      /Failed to decode bolt12 string/,
    );
  });

  it('should throw on garbage input', () => {
    assert.throws(
      () => decodeBolt12('not-a-bolt12-string'),
      /Failed to decode bolt12 string/,
    );
  });

  it('should throw on too-short invoice request (missing metadata)', () => {
    // Build TLVs that would be a valid invreq but missing invreq_metadata
    const tlvs: TlvEntry[] = [
      { type: BigInt(88), length: BigInt(33), value: payerPubkey },
      { type: BigInt(240), length: BigInt(64), value: new Uint8Array(64) },
    ];
    const tlvBytes = encodeTlvStream(tlvs);
    const fiveBitWords = convertBits(tlvBytes, 8, 5, true);
    const encoded = bolt12Encode('lnr', fiveBitWords);
    assert.throws(
      () => decodeBolt12(encoded),
      /Invoice request must have invreq_metadata/,
    );
  });
});

// ── Tagged Hash Tests ──────────────────────────────────────────

describe('Tagged Hash', () => {
  it('should produce 32-byte output', () => {
    const hash = taggedHash('test', utf8ToBytes('hello'));
    assert.strictEqual(hash.length, 32);
  });

  it('should be deterministic', () => {
    const h1 = taggedHash('tag', utf8ToBytes('msg'));
    const h2 = taggedHash('tag', utf8ToBytes('msg'));
    assert.deepStrictEqual(h1, h2);
  });

  it('should differ for different tags', () => {
    const h1 = taggedHash('tag1', utf8ToBytes('msg'));
    const h2 = taggedHash('tag2', utf8ToBytes('msg'));
    assert.notDeepStrictEqual(h1, h2);
  });

  it('should differ for different messages', () => {
    const h1 = taggedHash('tag', utf8ToBytes('msg1'));
    const h2 = taggedHash('tag', utf8ToBytes('msg2'));
    assert.notDeepStrictEqual(h1, h2);
  });
});

// ── Multiple Blinded Paths ─────────────────────────────────────

describe('Multiple Blinded Paths', () => {
  it('should handle multiple paths with multiple hops', () => {
    const path1: BlindedPath = {
      blindingPubkey: issuerPubkey,
      hops: [
        { nodeId: payerPubkey, tlvPayload: randomBytes(8) },
        { nodeId: issuerPubkey, tlvPayload: randomBytes(16) },
      ],
    };
    const path2: BlindedPath = {
      blindingPubkey: payerPubkey,
      hops: [
        { nodeId: issuerPubkey, tlvPayload: randomBytes(12) },
      ],
    };

    const encoded = encodeOffer({
      issuerId: issuerPubkey,
      description: 'Multi-path offer',
      paths: [path1, path2],
    });

    const decoded = decodeBolt12(encoded) as DecodedOffer;
    assert.ok(decoded.paths);
    assert.strictEqual(decoded.paths!.length, 2);
    assert.strictEqual(decoded.paths![0].hops.length, 2);
    assert.strictEqual(decoded.paths![1].hops.length, 1);
  });
});

// ── End-to-end Flow Tests ──────────────────────────────────────

describe('End-to-End Payment Flow', () => {
  it('should support full offer → invoice_request → invoice flow', () => {
    // Step 1: Merchant creates an offer
    const offerStr = encodeOffer({
      issuerId: issuerPubkey,
      description: 'Buy a coffee',
      amountMsat: BigInt(100000),
      issuer: 'CoffeeShop',
    });

    const offer = decodeBolt12(offerStr) as DecodedOffer;
    assert.strictEqual(offer.description, 'Buy a coffee');

    // Step 2: Payer creates invoice request (mirroring offer fields)
    const invreqStr = encodeInvoiceRequest({
      invreqMetadata: randomBytes(32),
      payerId: payerPubkey,
      payerPrivateKey: payerPrivkey,
      offerDescription: offer.description!,
      offerIssuerId: offer.issuerId!,
      offerAmountMsat: offer.amountMsat,
      offerIssuer: offer.issuer,
    });

    const invreq = decodeBolt12(invreqStr) as DecodedInvoiceRequest;
    assert.strictEqual(invreq.offerDescription, 'Buy a coffee');

    // Verify invoice request signature
    const invreqSigValid = verifyBolt12Signature(
      invreq.tlvs,
      invreq.signature,
      invreq.payerId,
      Bech32mPrefix.InvoiceRequest,
    );
    assert.ok(invreqSigValid, 'Invoice request signature should be valid');

    // Step 3: Merchant creates invoice
    const paymentHash = sha256(randomBytes(32));
    const blindedPath: BlindedPath = {
      blindingPubkey: issuerPubkey,
      hops: [{ nodeId: issuerPubkey, tlvPayload: randomBytes(32) }],
    };
    const payInfo: BlindedPayInfo = {
      feeBaseMsat: 1000,
      feeProportionalMillionths: 100,
      cltvExpiryDelta: 144,
      htlcMinimumMsat: BigInt(1000),
      htlcMaximumMsat: BigInt(1000000000),
      features: new Uint8Array(0),
    };

    const invoiceStr = encodeInvoice({
      nodeId: issuerPubkey,
      nodePrivateKey: issuerPrivkey,
      createdAt: BigInt(Math.floor(Date.now() / 1000)),
      paymentHash,
      amountMsat: offer.amountMsat!,
      invoicePaths: [blindedPath],
      blindedPayInfo: [payInfo],
      invreqMetadata: invreq.invreqMetadata,
      invreqPayerId: invreq.payerId,
      offerDescription: offer.description!,
      offerIssuerId: offer.issuerId!,
      offerAmountMsat: offer.amountMsat,
      offerIssuer: offer.issuer,
    });

    const invoice = decodeBolt12(invoiceStr) as DecodedInvoice;
    assert.strictEqual(invoice.prefix, Bech32mPrefix.Invoice);
    assert.strictEqual(invoice.amountMsat, BigInt(100000));

    // Verify invoice signature
    const invoiceSigValid = verifyBolt12Signature(
      invoice.tlvs,
      invoice.signature,
      invoice.nodeId,
      Bech32mPrefix.Invoice,
    );
    assert.ok(invoiceSigValid, 'Invoice signature should be valid');
  });
});
