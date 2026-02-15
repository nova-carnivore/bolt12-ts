// test/index.test.ts — Verify all public exports are available

import assert from 'node:assert';
import { describe, it } from 'node:test';
import {
  // Decoding
  decodeBolt12,
  // Encoding
  encodeBolt12,
  encodeOffer,
  encodeInvoiceRequest,
  encodeInvoice,
  encodeBlindedPaths,
  encodeBlindedPayInfoArray,
  // Signatures
  signBolt12,
  verifyBolt12Signature,
  computeMerkleRoot,
  signatureTag,
  taggedHash,
  // Types
  Bech32mPrefix,
  // Low-level utils
  hexToBytes,
  bytesToHex,
  utf8ToBytes,
  bytesToUtf8,
  concatBytes,
  numberToBytesBE,
  bytesToNumberBE,
  tu64ToBytes,
  bytesToTu64,
  bolt12Encode,
  bolt12Decode,
  bech32mEncode,
  bech32mDecode,
  convertBits,
  encodeTlvStream,
  decodeTlvStream,
  encodeTu64,
  decodeTu64,
  encodeBigSize,
  decodeBigSize,
} from '../src/index';

describe('Public API Exports', () => {
  it('should export all decoding functions', () => {
    assert.strictEqual(typeof decodeBolt12, 'function');
  });

  it('should export all encoding functions', () => {
    assert.strictEqual(typeof encodeBolt12, 'function');
    assert.strictEqual(typeof encodeOffer, 'function');
    assert.strictEqual(typeof encodeInvoiceRequest, 'function');
    assert.strictEqual(typeof encodeInvoice, 'function');
    assert.strictEqual(typeof encodeBlindedPaths, 'function');
    assert.strictEqual(typeof encodeBlindedPayInfoArray, 'function');
  });

  it('should export all signature functions', () => {
    assert.strictEqual(typeof signBolt12, 'function');
    assert.strictEqual(typeof verifyBolt12Signature, 'function');
    assert.strictEqual(typeof computeMerkleRoot, 'function');
    assert.strictEqual(typeof signatureTag, 'function');
    assert.strictEqual(typeof taggedHash, 'function');
  });

  it('should export Bech32mPrefix enum', () => {
    assert.strictEqual(Bech32mPrefix.Offer, 'lno');
    assert.strictEqual(Bech32mPrefix.InvoiceRequest, 'lnr');
    assert.strictEqual(Bech32mPrefix.Invoice, 'lni');
  });

  it('should export all utility functions', () => {
    assert.strictEqual(typeof hexToBytes, 'function');
    assert.strictEqual(typeof bytesToHex, 'function');
    assert.strictEqual(typeof utf8ToBytes, 'function');
    assert.strictEqual(typeof bytesToUtf8, 'function');
    assert.strictEqual(typeof concatBytes, 'function');
    assert.strictEqual(typeof numberToBytesBE, 'function');
    assert.strictEqual(typeof bytesToNumberBE, 'function');
    assert.strictEqual(typeof tu64ToBytes, 'function');
    assert.strictEqual(typeof bytesToTu64, 'function');
  });

  it('should export bech32 functions', () => {
    assert.strictEqual(typeof bolt12Encode, 'function');
    assert.strictEqual(typeof bolt12Decode, 'function');
    assert.strictEqual(typeof bech32mEncode, 'function');
    assert.strictEqual(typeof bech32mDecode, 'function');
    assert.strictEqual(typeof convertBits, 'function');
  });

  it('should export TLV functions', () => {
    assert.strictEqual(typeof encodeTlvStream, 'function');
    assert.strictEqual(typeof decodeTlvStream, 'function');
    assert.strictEqual(typeof encodeTu64, 'function');
    assert.strictEqual(typeof decodeTu64, 'function');
    assert.strictEqual(typeof encodeBigSize, 'function');
    assert.strictEqual(typeof decodeBigSize, 'function');
  });
});
