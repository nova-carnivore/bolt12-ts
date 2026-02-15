// src/utils.ts
//
// Utility functions for byte/string/number conversions.

import { concatBytes as nobleConcatBytes } from '@noble/hashes/utils';

/**
 * Converts a hex string to a Uint8Array.
 *
 * @param hex - The hex string (must have even length).
 * @returns The byte array.
 * @throws If the input is not a valid hex string.
 */
export const hexToBytes = (hex: string): Uint8Array => {
  if (typeof hex !== 'string') {
    throw new Error('Expected string for hexToBytes');
  }
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string length: ' + hex.length);
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
};

/**
 * Converts a Uint8Array to a lowercase hex string.
 *
 * @param bytes - The byte array.
 * @returns The hex string.
 * @throws If the input is not a Uint8Array.
 */
export const bytesToHex = (bytes: Uint8Array): string => {
  if (!(bytes instanceof Uint8Array)) {
    throw new Error('Expected Uint8Array for bytesToHex');
  }
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
};

/**
 * Encodes a string as UTF-8 bytes.
 */
export const utf8ToBytes = (str: string): Uint8Array => new TextEncoder().encode(str);

/**
 * Decodes UTF-8 bytes to a string.
 */
export const bytesToUtf8 = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

/**
 * Concatenates multiple Uint8Arrays into a single Uint8Array.
 */
export const concatBytes = (...arrs: Uint8Array[]): Uint8Array => nobleConcatBytes(...arrs);

/**
 * Converts a number or bigint to a big-endian byte array of a specified length.
 *
 * @param value - The number or bigint to convert.
 * @param length - The desired byte length.
 * @returns The big-endian byte array.
 * @throws If the value is too large for the specified length.
 */
export const numberToBytesBE = (value: number | bigint, length: number): Uint8Array => {
  const buf = new Uint8Array(length);
  let num = typeof value === 'bigint' ? value : BigInt(value);
  for (let i = length - 1; i >= 0; i--) {
    buf[i] = Number(num & BigInt(0xff));
    num >>= BigInt(8);
  }
  if (num > BigInt(0)) {
    throw new Error('numberToBytesBE: value too large for length');
  }
  return buf;
};

/**
 * Converts a big-endian byte array to a number.
 * Only safe for values that fit in a JavaScript number (up to ~2^53).
 *
 * @param bytes - The big-endian byte array.
 * @returns The number value.
 */
export const bytesToNumberBE = (bytes: Uint8Array): number => {
  let num = 0;
  for (let i = 0; i < bytes.length; i++) {
    num = (num << 8) | bytes[i];
  }
  return num >>> 0; // Ensure unsigned
};

/**
 * Encodes a bigint as a tu64 (truncated unsigned 64-bit integer).
 * Uses minimal encoding: strips leading zero bytes.
 *
 * @param value - The value to encode (0 to 2^64-1).
 * @returns The minimally-encoded byte array.
 * @throws If the value is negative or exceeds 64 bits.
 */
export const tu64ToBytes = (value: bigint): Uint8Array => {
  if (value < BigInt(0)) {
    throw new Error('tu64 cannot be negative');
  }
  if (value > BigInt('18446744073709551615')) {
    throw new Error('tu64 value too large');
  }
  if (value === BigInt(0)) {
    return new Uint8Array(0);
  }

  let hex = value.toString(16);
  if (hex.length % 2 !== 0) {
    hex = '0' + hex;
  }
  return hexToBytes(hex);
};

/**
 * Decodes a tu64 byte array into a bigint.
 *
 * @param bytes - The tu64 encoded bytes (0-8 bytes).
 * @returns The decoded value.
 * @throws If the byte array is too long.
 */
export const bytesToTu64 = (bytes: Uint8Array): bigint => {
  if (bytes.length > 8) {
    throw new Error('bytesToTu64: byte array too long for a 64-bit integer');
  }
  let num = BigInt(0);
  for (const byte of bytes) {
    num = (num << BigInt(8)) | BigInt(byte);
  }
  return num;
};
