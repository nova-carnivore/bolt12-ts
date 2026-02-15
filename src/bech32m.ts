// src/bech32m.ts
//
// BOLT 12 uses bech32-style encoding WITHOUT a checksum.
// Per the spec: "There is no checksum, unlike bech32m."
// We also support bech32m (with checksum) for legacy/testing purposes.

import { concatBytes } from '@noble/hashes/utils';

/** Characters used in bech32 encoding. */
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

/** Generator for the bech32m checksum. */
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d42cd37, 0x2a1462b3];

/**
 * Converts words between different bit widths (e.g. 5-bit to 8-bit or vice versa).
 *
 * @param data - The words to convert.
 * @param inBits - The number of bits per input word.
 * @param outBits - The number of bits per output word.
 * @param pad - Whether to pad the output with zeroes.
 * @returns The converted words.
 * @throws If the input has excess or non-zero padding.
 */
export function convertBits(
  data: Uint8Array,
  inBits: number,
  outBits: number,
  pad: boolean,
): Uint8Array {
  let value = 0;
  let bits = 0;
  const result: number[] = [];
  const maxv = (1 << outBits) - 1;

  for (let i = 0; i < data.length; ++i) {
    value = (value << inBits) | data[i];
    bits += inBits;
    while (bits >= outBits) {
      bits -= outBits;
      result.push((value >>> bits) & maxv);
    }
  }

  if (pad) {
    if (bits > 0) {
      result.push((value << (outBits - bits)) & maxv);
    }
  } else {
    if (bits >= inBits) throw new Error('Excess padding');
    if ((value << (outBits - bits)) & maxv) throw new Error('Non-zero padding');
  }

  return new Uint8Array(result);
}

// ── bech32m helpers (with checksum) ──────────────────────────────

function bech32Polymod(values: Uint8Array): number {
  let chk = 1;
  for (let i = 0; i < values.length; ++i) {
    const b = chk >> 25;
    chk = (chk & 0x1ffffff) << 5;
    chk ^= values[i];
    for (let j = 0; j < 5; ++j) {
      if (((b >> j) & 1) !== 0) {
        chk ^= GENERATOR[j];
      }
    }
  }
  return chk;
}

function hrpExpand(hrp: string): Uint8Array {
  const buf = new Uint8Array(hrp.length * 2 + 1);
  for (let i = 0; i < hrp.length; ++i) {
    buf[i] = hrp.charCodeAt(i) >>> 5;
    buf[i + hrp.length + 1] = hrp.charCodeAt(i) & 0x1f;
  }
  buf[hrp.length] = 0;
  return buf;
}

function verifyChecksum(hrp: string, data: Uint8Array): boolean {
  return bech32Polymod(concatBytes(hrpExpand(hrp), data)) === 1;
}

function createChecksum(hrp: string, data: Uint8Array): Uint8Array {
  const values = concatBytes(hrpExpand(hrp), data, new Uint8Array(6).fill(0));
  const poly = bech32Polymod(values) ^ 1;
  const checksum = new Uint8Array(6);
  for (let i = 0; i < 6; ++i) {
    checksum[i] = (poly >>> (5 * (5 - i))) & 0x1f;
  }
  return checksum;
}

/**
 * Encodes data to a bech32m string (WITH checksum).
 *
 * @param hrp - The human-readable part.
 * @param data - The data to encode (5-bit words).
 * @returns The bech32m encoded string.
 */
export function bech32mEncode(hrp: string, data: Uint8Array): string {
  const combined = concatBytes(data, createChecksum(hrp, data));
  let result = hrp + '1';
  for (let i = 0; i < combined.length; ++i) {
    result += CHARSET[combined[i]];
  }
  return result;
}

/**
 * Decodes a bech32m string (WITH checksum).
 *
 * @param bechString - The bech32m encoded string.
 * @returns The decoded human-readable part and data (5-bit words).
 * @throws If the string has mixed case, invalid format, or bad checksum.
 */
export function bech32mDecode(bechString: string): {
  hrp: string;
  data: Uint8Array;
} {
  const lower = bechString.toLowerCase();
  const upper = bechString.toUpperCase();

  if (bechString !== lower && bechString !== upper) {
    throw new Error('Mixed case string ' + bechString);
  }

  const pos = lower.lastIndexOf('1');
  if (pos < 1 || pos + 7 > lower.length) {
    throw new Error('Invalid bech32m string format');
  }

  const hrp = lower.substring(0, pos);
  const data = new Uint8Array(lower.length - pos - 1);
  for (let i = 0; i < data.length; ++i) {
    const char = lower.charCodeAt(pos + 1 + i);
    const charIndex = CHARSET.indexOf(String.fromCharCode(char));
    if (charIndex === -1) {
      throw new Error('Invalid character in bech32m string: ' + char);
    }
    data[i] = charIndex;
  }

  if (!verifyChecksum(hrp, data)) {
    throw new Error('Invalid bech32m checksum');
  }

  return { hrp, data: data.slice(0, -6) };
}

// ── BOLT 12 bech32 (NO checksum, per spec) ──────────────────────

/**
 * Encodes data to a BOLT 12 bech32 string (WITHOUT checksum).
 * Per BOLT 12 spec: "There is no checksum, unlike bech32m."
 *
 * @param hrp - The human-readable part (e.g. "lno", "lnr", "lni").
 * @param data - The data to encode (5-bit words).
 * @returns The encoded bolt12 string.
 */
export function bolt12Encode(hrp: string, data: Uint8Array): string {
  let result = hrp + '1';
  for (let i = 0; i < data.length; ++i) {
    result += CHARSET[data[i]];
  }
  return result;
}

/**
 * Decodes a BOLT 12 bech32 string (WITHOUT checksum).
 * Handles `+` concatenation and whitespace as per BOLT 12 spec.
 *
 * @param bechString - The bolt12 encoded string.
 * @returns The decoded human-readable part and data (5-bit words).
 * @throws If the string has mixed case, invalid format, or invalid characters.
 */
export function bolt12Decode(bechString: string): {
  hrp: string;
  data: Uint8Array;
} {
  // Strip `+` followed by optional whitespace (per BOLT 12 spec)
  const cleaned = bechString.replace(/\+\s*/g, '');

  const lower = cleaned.toLowerCase();
  const upper = cleaned.toUpperCase();

  if (cleaned !== lower && cleaned !== upper) {
    throw new Error('Mixed case in bolt12 string');
  }

  const pos = lower.indexOf('1');
  if (pos < 1) {
    throw new Error('Invalid bolt12 string format: missing separator');
  }

  const hrp = lower.substring(0, pos);
  const dataStr = lower.substring(pos + 1);

  if (dataStr.length === 0) {
    throw new Error('Invalid bolt12 string format: empty data');
  }

  const data = new Uint8Array(dataStr.length);
  for (let i = 0; i < dataStr.length; ++i) {
    const charIndex = CHARSET.indexOf(dataStr[i]);
    if (charIndex === -1) {
      throw new Error(`Invalid character in bolt12 string: '${dataStr[i]}'`);
    }
    data[i] = charIndex;
  }

  return { hrp, data };
}
