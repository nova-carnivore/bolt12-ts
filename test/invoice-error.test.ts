import assert from 'node:assert';
import { describe, it } from 'node:test';
import { encodeInvoiceError } from '../src/encode';
import { decodeInvoiceError } from '../src/decode';
import { encodeTu64, decodeTu64, encodeTlvStream } from '../src/tlv';
import { utf8ToBytes, bytesToHex } from '../src/utils';
import type { InvoiceError, TlvEntry } from '../src/types';

// ── Invoice Error Encoding/Decoding Tests ──────────────────────

describe('Invoice Error Encoding/Decoding', () => {
  it('should encode and decode a minimal invoice error (error message only)', () => {
    const errorBytes = encodeInvoiceError({
      error: 'Unknown offer',
    });

    assert.ok(errorBytes instanceof Uint8Array);
    assert.ok(errorBytes.length > 0);

    const decoded = decodeInvoiceError(errorBytes);
    assert.strictEqual(decoded.error, 'Unknown offer');
    assert.strictEqual(decoded.erroneousField, undefined);
    assert.strictEqual(decoded.suggestedValue, undefined);
  });

  it('should encode and decode invoice error with erroneous_field', () => {
    const errorBytes = encodeInvoiceError({
      error: 'Invalid amount',
      erroneousField: BigInt(82), // invreq_amount
    });

    const decoded = decodeInvoiceError(errorBytes);
    assert.strictEqual(decoded.error, 'Invalid amount');
    assert.strictEqual(decoded.erroneousField, BigInt(82));
    assert.strictEqual(decoded.suggestedValue, undefined);
  });

  it('should encode and decode invoice error with all fields', () => {
    const suggestedAmount = encodeTu64(BigInt(100000));

    const errorBytes = encodeInvoiceError({
      error: 'Amount too low',
      erroneousField: BigInt(82), // invreq_amount
      suggestedValue: suggestedAmount,
    });

    const decoded = decodeInvoiceError(errorBytes);
    assert.strictEqual(decoded.error, 'Amount too low');
    assert.strictEqual(decoded.erroneousField, BigInt(82));
    assert.ok(decoded.suggestedValue);
    // The suggested value should decode back to the original amount
    assert.strictEqual(bytesToHex(decoded.suggestedValue!), bytesToHex(suggestedAmount));
  });

  it('should handle large erroneous_field values', () => {
    const errorBytes = encodeInvoiceError({
      error: 'Unknown field',
      erroneousField: BigInt(1000000000), // Experimental range
    });

    const decoded = decodeInvoiceError(errorBytes);
    assert.strictEqual(decoded.erroneousField, BigInt(1000000000));
  });

  it('should handle zero erroneous_field', () => {
    const errorBytes = encodeInvoiceError({
      error: 'Bad metadata',
      erroneousField: BigInt(0), // invreq_metadata
    });

    const decoded = decodeInvoiceError(errorBytes);
    assert.strictEqual(decoded.erroneousField, BigInt(0));
  });

  it('should handle long error messages', () => {
    const longMessage = 'A'.repeat(1000);
    const errorBytes = encodeInvoiceError({
      error: longMessage,
    });

    const decoded = decodeInvoiceError(errorBytes);
    assert.strictEqual(decoded.error, longMessage);
  });

  it('should handle unicode error messages', () => {
    const unicodeMsg = 'Error: amount ≤ minimum (₿0.001)';
    const errorBytes = encodeInvoiceError({
      error: unicodeMsg,
    });

    const decoded = decodeInvoiceError(errorBytes);
    assert.strictEqual(decoded.error, unicodeMsg);
  });

  it('should handle large suggested_value', () => {
    const largeValue = new Uint8Array(256);
    for (let i = 0; i < 256; i++) largeValue[i] = i & 0xff;

    const errorBytes = encodeInvoiceError({
      error: 'Try this instead',
      erroneousField: BigInt(16), // offer_paths
      suggestedValue: largeValue,
    });

    const decoded = decodeInvoiceError(errorBytes);
    assert.deepStrictEqual(decoded.suggestedValue, largeValue);
  });

  it('should preserve TLV entries in decoded result', () => {
    const errorBytes = encodeInvoiceError({
      error: 'Test',
      erroneousField: BigInt(10),
    });

    const decoded = decodeInvoiceError(errorBytes);
    assert.ok(decoded.tlvs);
    assert.ok(decoded.tlvs.length >= 2); // At least erroneous_field and error
  });

  it('should produce TLVs in ascending order', () => {
    const errorBytes = encodeInvoiceError({
      error: 'Ordered test',
      erroneousField: BigInt(82),
      suggestedValue: new Uint8Array([0x01]),
    });

    const decoded = decodeInvoiceError(errorBytes);
    // Verify TLV types are in ascending order
    for (let i = 1; i < decoded.tlvs.length; i++) {
      assert.ok(
        decoded.tlvs[i].type > decoded.tlvs[i - 1].type,
        `TLV types should be ascending: ${decoded.tlvs[i - 1].type} should be < ${decoded.tlvs[i].type}`,
      );
    }
  });
});

// ── Invoice Error Validation Tests ─────────────────────────────

describe('Invoice Error Validation', () => {
  it('should reject encoding with empty error message', () => {
    assert.throws(
      () => encodeInvoiceError({ error: '' }),
      /Invoice error must have an error message/,
    );
  });

  it('should reject encoding with suggested_value but no erroneous_field', () => {
    assert.throws(
      () => encodeInvoiceError({
        error: 'Bad field',
        suggestedValue: new Uint8Array([0x01]),
      }),
      /Invoice error with suggested_value must also set erroneous_field/,
    );
  });

  it('should reject decoding with missing error message', () => {
    // Manually build TLV with only erroneous_field (type 1), no error (type 5)
    const tlvBytes = encodeTlvStream([
      { type: BigInt(1), length: BigInt(1), value: new Uint8Array([82]) },
    ]);

    assert.throws(
      () => decodeInvoiceError(tlvBytes),
      /Invoice error must have an error message/,
    );
  });

  it('should reject decoding with suggested_value but no erroneous_field', () => {
    // Manually build TLV with suggested_value (type 3) and error (type 5), but no erroneous_field (type 1)
    const errorText = utf8ToBytes('test');
    const tlvBytes = encodeTlvStream([
      { type: BigInt(3), length: BigInt(1), value: new Uint8Array([0x01]) },
      { type: BigInt(5), length: BigInt(errorText.length), value: errorText },
    ]);

    assert.throws(
      () => decodeInvoiceError(tlvBytes),
      /Invoice error has suggested_value without erroneous_field/,
    );
  });

  it('should reject decoding of empty bytes', () => {
    // Empty TLV stream has no error field
    assert.throws(
      () => decodeInvoiceError(new Uint8Array(0)),
      /Invoice error must have an error message/,
    );
  });
});

// ── Invoice Error Roundtrip Tests ──────────────────────────────

describe('Invoice Error Roundtrips', () => {
  it('should roundtrip error for each common BOLT 12 field', () => {
    const fields = [
      { type: BigInt(2), name: 'offer_chains' },
      { type: BigInt(8), name: 'offer_amount' },
      { type: BigInt(10), name: 'offer_description' },
      { type: BigInt(80), name: 'invreq_chain' },
      { type: BigInt(82), name: 'invreq_amount' },
      { type: BigInt(86), name: 'invreq_quantity' },
      { type: BigInt(88), name: 'invreq_payer_id' },
      { type: BigInt(160), name: 'invoice_paths' },
      { type: BigInt(168), name: 'invoice_payment_hash' },
      { type: BigInt(170), name: 'invoice_amount' },
    ];

    for (const field of fields) {
      const errorBytes = encodeInvoiceError({
        error: `Problem with ${field.name}`,
        erroneousField: field.type,
      });

      const decoded = decodeInvoiceError(errorBytes);
      assert.strictEqual(decoded.error, `Problem with ${field.name}`);
      assert.strictEqual(decoded.erroneousField, field.type);
    }
  });

  it('should roundtrip with suggested amount value', () => {
    const suggestedAmount = encodeTu64(BigInt(250000));

    const errorBytes = encodeInvoiceError({
      error: 'Amount mismatch: expected 250000 msat',
      erroneousField: BigInt(170), // invoice_amount
      suggestedValue: suggestedAmount,
    });

    const decoded = decodeInvoiceError(errorBytes);
    assert.strictEqual(decoded.error, 'Amount mismatch: expected 250000 msat');
    assert.strictEqual(decoded.erroneousField, BigInt(170));
    // Verify the suggested value can be decoded back to the amount
    const decodedAmount = decodeTu64(decoded.suggestedValue!);
    assert.strictEqual(decodedAmount, BigInt(250000));
  });
});
