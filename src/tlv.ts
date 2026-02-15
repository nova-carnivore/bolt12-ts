// src/tlv.ts
//
// TLV (Type-Length-Value) encoding and decoding for BOLT 12.
// Per BOLT 1, types and lengths use BigSize encoding.
// Values use tu64 (truncated unsigned 64-bit) encoding.

import { TlvEntry } from './types';
import { tu64ToBytes, bytesToTu64, concatBytes } from './utils';

/**
 * Encodes a single number as a tu64 byte array.
 * tu64 is a variable-length unsigned 64-bit integer encoding
 * that uses the minimum number of bytes.
 *
 * @param value - The number to encode.
 * @returns The tu64 encoded bytes.
 */
export function encodeTu64(value: bigint): Uint8Array {
  return tu64ToBytes(value);
}

/**
 * Decodes a tu64 byte array into a bigint.
 *
 * @param bytes - The tu64 encoded bytes.
 * @returns The decoded number.
 */
export function decodeTu64(bytes: Uint8Array): bigint {
  return bytesToTu64(bytes);
}

// ── BigSize encoding/decoding (per BOLT 1) ─────────────────────

/**
 * Encodes a number as BigSize (used for TLV type and length fields).
 *
 * BigSize encoding:
 * - 0x00-0xFC: 1 byte
 * - 0xFD-0xFFFF: 0xFD followed by 2-byte big-endian u16
 * - 0x10000-0xFFFFFFFF: 0xFE followed by 4-byte big-endian u32
 * - 0x100000000-0xFFFFFFFFFFFFFFFF: 0xFF followed by 8-byte big-endian u64
 *
 * @param value - The number to encode as BigSize.
 * @returns The BigSize encoded bytes.
 */
export function encodeBigSize(value: bigint): Uint8Array {
  if (value < BigInt(0)) {
    throw new Error('BigSize cannot be negative');
  }
  if (value <= BigInt(0xfc)) {
    return new Uint8Array([Number(value)]);
  }
  if (value <= BigInt(0xffff)) {
    const buf = new Uint8Array(3);
    buf[0] = 0xfd;
    buf[1] = Number((value >> BigInt(8)) & BigInt(0xff));
    buf[2] = Number(value & BigInt(0xff));
    return buf;
  }
  if (value <= BigInt(0xffffffff)) {
    const buf = new Uint8Array(5);
    buf[0] = 0xfe;
    buf[1] = Number((value >> BigInt(24)) & BigInt(0xff));
    buf[2] = Number((value >> BigInt(16)) & BigInt(0xff));
    buf[3] = Number((value >> BigInt(8)) & BigInt(0xff));
    buf[4] = Number(value & BigInt(0xff));
    return buf;
  }
  const buf = new Uint8Array(9);
  buf[0] = 0xff;
  for (let i = 8; i >= 1; i--) {
    buf[i] = Number(value & BigInt(0xff));
    value >>= BigInt(8);
  }
  return buf;
}

/**
 * Decodes a BigSize value from a byte array at a given offset.
 *
 * @param bytes - The byte array.
 * @param offset - The starting offset.
 * @returns Tuple of [decoded value, new offset after the BigSize].
 */
export function decodeBigSize(bytes: Uint8Array, offset: number): [bigint, number] {
  if (offset >= bytes.length) {
    throw new Error('Invalid TLV: unexpected end of stream');
  }

  const first = bytes[offset];

  if (first <= 0xfc) {
    return [BigInt(first), offset + 1];
  }

  if (first === 0xfd) {
    if (offset + 3 > bytes.length) {
      throw new Error('Invalid BigSize: truncated u16');
    }
    const val = BigInt((bytes[offset + 1] << 8) | bytes[offset + 2]);
    if (val < BigInt(0xfd)) {
      throw new Error('Invalid BigSize: non-minimal encoding');
    }
    return [val, offset + 3];
  }

  if (first === 0xfe) {
    if (offset + 5 > bytes.length) {
      throw new Error('Invalid BigSize: truncated u32');
    }
    const val = BigInt(
      (bytes[offset + 1] << 24) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 8) |
      bytes[offset + 4],
    ) & BigInt(0xffffffff); // Ensure unsigned
    if (val < BigInt(0x10000)) {
      throw new Error('Invalid BigSize: non-minimal encoding');
    }
    return [val, offset + 5];
  }

  // first === 0xff
  if (offset + 9 > bytes.length) {
    throw new Error('Invalid BigSize: truncated u64');
  }
  let val = BigInt(0);
  for (let i = 1; i <= 8; i++) {
    val = (val << BigInt(8)) | BigInt(bytes[offset + i]);
  }
  if (val < BigInt(0x100000000)) {
    throw new Error('Invalid BigSize: non-minimal encoding');
  }
  return [val, offset + 9];
}

/**
 * Encodes an array of TLV entries into a single byte array.
 * Types and lengths use BigSize encoding (per BOLT 1).
 *
 * @param tlvStream - An array of TLV entries.
 * @returns The encoded TLV stream.
 */
export function encodeTlvStream(tlvStream: TlvEntry[]): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const tlv of tlvStream) {
    parts.push(encodeBigSize(tlv.type));
    parts.push(encodeBigSize(BigInt(tlv.value.length)));
    parts.push(tlv.value);
  }
  return concatBytes(...parts);
}

/**
 * Decodes a byte array into an array of TLV entries.
 * Types and lengths use BigSize encoding (per BOLT 1).
 *
 * @param tlvStreamBytes - The byte array containing the TLV stream.
 * @returns An array of decoded TLV entries.
 * @throws If the stream is malformed.
 */
export function decodeTlvStream(tlvStreamBytes: Uint8Array): TlvEntry[] {
  const tlvEntries: TlvEntry[] = [];
  let offset = 0;

  while (offset < tlvStreamBytes.length) {
    // Decode type
    const [type, afterType] = decodeBigSize(tlvStreamBytes, offset);
    offset = afterType;

    // Decode length
    const [length, afterLength] = decodeBigSize(tlvStreamBytes, offset);
    offset = afterLength;

    // Read value
    const len = Number(length);
    if (offset + len > tlvStreamBytes.length) {
      throw new Error('Invalid TLV: truncated value');
    }
    const value = tlvStreamBytes.subarray(offset, offset + len);
    offset += len;

    tlvEntries.push({ type, length, value });
  }

  return tlvEntries;
}
