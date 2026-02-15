// src/index.ts
//
// bolt12-ts — Modern TypeScript BOLT 12 Lightning Network encoder/decoder
//
// Zero vulnerable dependencies. Uses @noble/curves and @noble/hashes for all cryptography.

// ── Decoding ───────────────────────────────────────────────────
export { decodeBolt12, decodeInvoiceError } from './decode.js';

// ── Encoding ───────────────────────────────────────────────────
export {
  encodeBolt12,
  encodeOffer,
  encodeInvoiceRequest,
  encodeInvoice,
  encodeInvoiceError,
  encodeBlindedPaths,
  encodeBlindedPayInfoArray,
} from './encode.js';
export type {
  OfferEncodeOptions,
  InvoiceRequestEncodeOptions,
  InvoiceEncodeOptions,
  InvoiceErrorEncodeOptions,
} from './encode.js';

// ── Signatures ─────────────────────────────────────────────────
export {
  signBolt12,
  verifyBolt12Signature,
  computeMerkleRoot,
  signatureTag,
  taggedHash,
} from './signature.js';

// ── Types ──────────────────────────────────────────────────────
export { Bech32mPrefix } from './types.js';
export type {
  TlvEntry,
  DecodedTlvStream,
  BaseBolt12,
  DecodedOffer,
  DecodedInvoiceRequest,
  DecodedInvoice,
  InvoiceError,
  BlindedPath,
  OnionMessageHop,
  BlindedPayInfo,
  FallbackAddress,
  MerkleLeaf,
  MerkleTree,
  AnyDecodedBolt12,
} from './types.js';

// ── Low-level utilities ────────────────────────────────────────
export {
  hexToBytes,
  bytesToHex,
  utf8ToBytes,
  bytesToUtf8,
  concatBytes,
  numberToBytesBE,
  bytesToNumberBE,
  tu64ToBytes,
  bytesToTu64,
} from './utils.js';

export {
  bolt12Encode,
  bolt12Decode,
  bech32mEncode,
  bech32mDecode,
  convertBits,
} from './bech32m.js';

export {
  encodeTlvStream,
  decodeTlvStream,
  encodeTu64,
  decodeTu64,
  encodeBigSize,
  decodeBigSize,
} from './tlv.js';
