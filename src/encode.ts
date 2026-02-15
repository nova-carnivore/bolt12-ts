// src/encode.ts
//
// Encodes BOLT 12 offers (lno), invoice requests (lnr), and invoices (lni)
// into their bech32-encoded string representation (without checksum, per spec).

import { bolt12Encode, convertBits } from './bech32m';
import { TlvEntry, Bech32mPrefix, BlindedPath, BlindedPayInfo, FallbackAddress } from './types';
import { encodeTlvStream, encodeTu64 } from './tlv';
import { utf8ToBytes, concatBytes, numberToBytesBE } from './utils';
import { signBolt12 } from './signature';

// ── Low-level encoder ──────────────────────────────────────────

interface EncodeOptions {
  hrp: Bech32mPrefix;
  tlvs: TlvEntry[];
}

/**
 * Encodes a BOLT 12 object into its bech32 string representation (no checksum).
 *
 * @param options - The encoding options including HRP and TLV entries.
 * @returns The encoded BOLT 12 string.
 */
export function encodeBolt12({ hrp, tlvs }: EncodeOptions): string {
  const tlvStreamBytes = encodeTlvStream(tlvs);
  const fiveBitWords = convertBits(tlvStreamBytes, 8, 5, true);
  return bolt12Encode(hrp, fiveBitWords);
}

// ── Blinded path encoding ──────────────────────────────────────

/**
 * Encodes blinded paths into their binary representation.
 * Format per path: 33-byte blinding_pubkey, 1-byte num_hops,
 * then per hop: 33-byte node_id, u16 encrypted_data_len, encrypted_data.
 *
 * @param paths - The blinded paths to encode.
 * @returns The encoded bytes.
 */
export function encodeBlindedPaths(paths: BlindedPath[]): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const path of paths) {
    parts.push(path.blindingPubkey);
    parts.push(new Uint8Array([path.hops.length])); // u8 num_hops
    for (const hop of path.hops) {
      parts.push(hop.nodeId);
      parts.push(numberToBytesBE(hop.tlvPayload.length, 2)); // u16 len
      parts.push(hop.tlvPayload);
    }
  }
  return concatBytes(...parts);
}

/**
 * Encodes blinded pay info entries into their binary representation.
 * Format per entry: u32 fee_base_msat, u32 fee_proportional_millionths,
 * u16 cltv_expiry_delta, u64 htlc_minimum_msat, u64 htlc_maximum_msat,
 * u16 flen, flen*byte features.
 *
 * @param payInfos - The blinded pay info entries.
 * @returns The encoded bytes.
 */
export function encodeBlindedPayInfoArray(payInfos: BlindedPayInfo[]): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const info of payInfos) {
    parts.push(numberToBytesBE(info.feeBaseMsat, 4));
    parts.push(numberToBytesBE(info.feeProportionalMillionths, 4));
    parts.push(numberToBytesBE(info.cltvExpiryDelta, 2));
    parts.push(numberToBytesBE(info.htlcMinimumMsat, 8));
    parts.push(numberToBytesBE(info.htlcMaximumMsat, 8));
    parts.push(numberToBytesBE(info.features.length, 2));
    if (info.features.length > 0) {
      parts.push(info.features);
    }
  }
  return concatBytes(...parts);
}

/**
 * Encodes fallback addresses into their binary representation.
 */
export function encodeFallbackAddresses(fallbacks: FallbackAddress[]): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const fb of fallbacks) {
    parts.push(new Uint8Array([fb.version]));
    parts.push(numberToBytesBE(fb.address.length, 2));
    parts.push(fb.address);
  }
  return concatBytes(...parts);
}

// ── TLV builder helper ─────────────────────────────────────────

function tlv(type: number, value: Uint8Array): TlvEntry {
  return {
    type: BigInt(type),
    length: BigInt(value.length),
    value,
  };
}

// ── Offer encoding ─────────────────────────────────────────────

/**
 * Options for encoding a BOLT 12 Offer.
 */
export interface OfferEncodeOptions {
  /** Public key of the offer issuer (TLV 22). Required unless paths are provided. */
  issuerId?: Uint8Array;
  /** Human-readable description of what is being offered (TLV 10). */
  description?: string;
  /** Amount in millisatoshis (TLV 8). */
  amountMsat?: bigint;
  /** ISO 4217 currency code (TLV 6). Requires amountMsat. */
  currency?: string;
  /** Chain hashes this offer is valid for (TLV 2). Omit for bitcoin-only. */
  chains?: Uint8Array[];
  /** Arbitrary metadata for the issuer's use (TLV 4). */
  metadata?: Uint8Array;
  /** Expiry as seconds from epoch (TLV 14). */
  absoluteExpiry?: bigint;
  /** Blinded paths to reach the issuer (TLV 16). */
  paths?: BlindedPath[];
  /** Human-readable issuer name (TLV 18). */
  issuer?: string;
  /** Maximum quantity per invoice (TLV 20). 0 = unlimited. */
  quantityMax?: bigint;
  /** Feature bits (TLV 12). */
  features?: Uint8Array;
}

/**
 * Encodes a BOLT 12 Offer (lno1...).
 *
 * Note: Offers are NOT signed per the BOLT 12 spec.
 *
 * @param options - The offer fields to encode.
 * @returns The encoded offer string.
 * @throws If required fields are missing.
 *
 * @example
 * ```ts
 * const offer = encodeOffer({
 *   issuerId: myPublicKey,
 *   description: 'Buy a coffee',
 *   amountMsat: 100000n,
 * });
 * ```
 */
export function encodeOffer(options: OfferEncodeOptions): string {
  // Validation
  if (!options.issuerId && (!options.paths || options.paths.length === 0)) {
    throw new Error('Offer must have either issuerId or paths');
  }
  if (options.amountMsat && !options.description) {
    throw new Error('Offer with amount must have a description');
  }
  if (options.currency && !options.amountMsat) {
    throw new Error('Offer with currency must have an amount');
  }

  const tlvs: TlvEntry[] = [];

  if (options.chains) {
    tlvs.push(tlv(2, concatBytes(...options.chains)));
  }
  if (options.metadata) {
    tlvs.push(tlv(4, options.metadata));
  }
  if (options.currency) {
    tlvs.push(tlv(6, utf8ToBytes(options.currency)));
  }
  if (options.amountMsat !== undefined) {
    tlvs.push(tlv(8, encodeTu64(options.amountMsat)));
  }
  if (options.description) {
    tlvs.push(tlv(10, utf8ToBytes(options.description)));
  }
  if (options.features) {
    tlvs.push(tlv(12, options.features));
  }
  if (options.absoluteExpiry !== undefined) {
    tlvs.push(tlv(14, encodeTu64(options.absoluteExpiry)));
  }
  if (options.paths) {
    tlvs.push(tlv(16, encodeBlindedPaths(options.paths)));
  }
  if (options.issuer) {
    tlvs.push(tlv(18, utf8ToBytes(options.issuer)));
  }
  if (options.quantityMax !== undefined) {
    tlvs.push(tlv(20, encodeTu64(options.quantityMax)));
  }
  if (options.issuerId) {
    tlvs.push(tlv(22, options.issuerId));
  }

  // Sort TLVs by type (ascending) before encoding
  tlvs.sort((a, b) => Number(a.type - b.type));

  return encodeBolt12({ hrp: Bech32mPrefix.Offer, tlvs });
}

// ── Invoice Request encoding ───────────────────────────────────

/**
 * Options for encoding a BOLT 12 Invoice Request.
 */
export interface InvoiceRequestEncodeOptions {
  /** Unique random metadata (TLV 0). Required. */
  invreqMetadata: Uint8Array;
  /** Payer's public key (TLV 88). Required. 33-byte compressed. */
  payerId: Uint8Array;
  /** Payer's private key for signing. Required. 32 bytes. */
  payerPrivateKey: Uint8Array;
  /** Amount in millisatoshis (TLV 82). */
  amountMsat?: bigint;
  /** Quantity requested (TLV 86). */
  quantity?: bigint;
  /** Payer note (TLV 89). */
  payerNote?: string;
  /** Payer's blinded paths (TLV 90). */
  invreqPaths?: BlindedPath[];
  /** Chain hash (TLV 80). */
  invreqChain?: Uint8Array;
  /** Features (TLV 84). */
  invreqFeatures?: Uint8Array;
  /** BIP-353 name (TLV 91). */
  invreqBip353Name?: { name: string; domain: string };

  // Mirrored offer fields (copied from the offer being responded to)
  /** Offer chains (TLV 2). */
  offerChains?: Uint8Array[];
  /** Offer metadata (TLV 4). */
  offerMetadata?: Uint8Array;
  /** Offer currency (TLV 6). */
  offerCurrency?: string;
  /** Offer amount (TLV 8). */
  offerAmountMsat?: bigint;
  /** Offer description (TLV 10). */
  offerDescription?: string;
  /** Offer features (TLV 12). */
  offerFeatures?: Uint8Array;
  /** Offer absolute expiry (TLV 14). */
  offerAbsoluteExpiry?: bigint;
  /** Offer paths (TLV 16). */
  offerPaths?: BlindedPath[];
  /** Offer issuer (TLV 18). */
  offerIssuer?: string;
  /** Offer quantity max (TLV 20). */
  offerQuantityMax?: bigint;
  /** Offer issuer id (TLV 22). */
  offerIssuerId?: Uint8Array;
}

/**
 * Encodes a BOLT 12 Invoice Request (lnr1...).
 *
 * The invoice request is automatically signed using the payer's private key
 * via BIP-340 Schnorr with the BOLT 12 Merkle tree construction.
 *
 * @param options - The invoice request fields to encode.
 * @returns The encoded invoice request string.
 * @throws If required fields are missing.
 *
 * @example
 * ```ts
 * const invreq = encodeInvoiceRequest({
 *   invreqMetadata: crypto.getRandomValues(new Uint8Array(32)),
 *   payerId: myPublicKey,
 *   payerPrivateKey: myPrivateKey,
 *   offerDescription: 'Buy a coffee',
 *   offerIssuerId: merchantPubkey,
 *   amountMsat: 100000n,
 * });
 * ```
 */
export function encodeInvoiceRequest(options: InvoiceRequestEncodeOptions): string {
  if (!options.invreqMetadata || options.invreqMetadata.length === 0) {
    throw new Error('Invoice request must have invreq_metadata');
  }
  if (!options.payerId || options.payerId.length !== 33) {
    throw new Error('Invoice request must have a valid payerId (33-byte compressed public key)');
  }
  if (!options.payerPrivateKey || options.payerPrivateKey.length !== 32) {
    throw new Error('Invoice request must have a valid payerPrivateKey (32 bytes)');
  }

  const tlvs: TlvEntry[] = [];

  // invreq_metadata (TLV 0) - must be first numerically
  tlvs.push(tlv(0, options.invreqMetadata));

  // Mirrored offer fields
  if (options.offerChains) {
    tlvs.push(tlv(2, concatBytes(...options.offerChains)));
  }
  if (options.offerMetadata) {
    tlvs.push(tlv(4, options.offerMetadata));
  }
  if (options.offerCurrency) {
    tlvs.push(tlv(6, utf8ToBytes(options.offerCurrency)));
  }
  if (options.offerAmountMsat !== undefined) {
    tlvs.push(tlv(8, encodeTu64(options.offerAmountMsat)));
  }
  if (options.offerDescription) {
    tlvs.push(tlv(10, utf8ToBytes(options.offerDescription)));
  }
  if (options.offerFeatures) {
    tlvs.push(tlv(12, options.offerFeatures));
  }
  if (options.offerAbsoluteExpiry !== undefined) {
    tlvs.push(tlv(14, encodeTu64(options.offerAbsoluteExpiry)));
  }
  if (options.offerPaths) {
    tlvs.push(tlv(16, encodeBlindedPaths(options.offerPaths)));
  }
  if (options.offerIssuer) {
    tlvs.push(tlv(18, utf8ToBytes(options.offerIssuer)));
  }
  if (options.offerQuantityMax !== undefined) {
    tlvs.push(tlv(20, encodeTu64(options.offerQuantityMax)));
  }
  if (options.offerIssuerId) {
    tlvs.push(tlv(22, options.offerIssuerId));
  }

  // Invoice request specific fields
  if (options.invreqChain) {
    tlvs.push(tlv(80, options.invreqChain));
  }
  if (options.amountMsat !== undefined) {
    tlvs.push(tlv(82, encodeTu64(options.amountMsat)));
  }
  if (options.invreqFeatures) {
    tlvs.push(tlv(84, options.invreqFeatures));
  }
  if (options.quantity !== undefined) {
    tlvs.push(tlv(86, encodeTu64(options.quantity)));
  }
  tlvs.push(tlv(88, options.payerId));
  if (options.payerNote) {
    tlvs.push(tlv(89, utf8ToBytes(options.payerNote)));
  }
  if (options.invreqPaths) {
    tlvs.push(tlv(90, encodeBlindedPaths(options.invreqPaths)));
  }
  if (options.invreqBip353Name) {
    tlvs.push(tlv(91, encodeBip353Name(options.invreqBip353Name)));
  }

  // Sort TLVs by type
  tlvs.sort((a, b) => Number(a.type - b.type));

  // Sign with the payer's private key
  const signature = signBolt12(tlvs, options.payerPrivateKey, Bech32mPrefix.InvoiceRequest);
  tlvs.push(tlv(240, signature));

  // Re-sort after adding signature
  tlvs.sort((a, b) => Number(a.type - b.type));

  return encodeBolt12({ hrp: Bech32mPrefix.InvoiceRequest, tlvs });
}

// ── Invoice encoding ───────────────────────────────────────────

/**
 * Options for encoding a BOLT 12 Invoice.
 */
export interface InvoiceEncodeOptions {
  /** Node's private key for signing. Required. 32 bytes. */
  nodePrivateKey: Uint8Array;
  /** Node's public key (TLV 176). Required. 33-byte compressed. */
  nodeId: Uint8Array;
  /** Invoice creation timestamp as seconds from epoch (TLV 164). Required. */
  createdAt: bigint;
  /** Payment hash (TLV 168). Required. 32-byte SHA256. */
  paymentHash: Uint8Array;
  /** Invoice amount in millisatoshis (TLV 170). Required. */
  amountMsat: bigint;
  /** Blinded paths for payment (TLV 160). Required. */
  invoicePaths: BlindedPath[];
  /** Blinded pay info for each path (TLV 162). Required. Must match invoicePaths count. */
  blindedPayInfo: BlindedPayInfo[];
  /** Relative expiry in seconds from creation (TLV 166). Default: 7200. */
  relativeExpiry?: number;
  /** Invoice features (TLV 174). */
  invoiceFeatures?: Uint8Array;
  /** Fallback on-chain addresses (TLV 172). */
  fallbacks?: FallbackAddress[];

  // Mirrored invoice request fields
  /** invreq_metadata (TLV 0). */
  invreqMetadata?: Uint8Array;
  /** invreq_chain (TLV 80). */
  invreqChain?: Uint8Array;
  /** invreq_amount (TLV 82). */
  invreqAmountMsat?: bigint;
  /** invreq_features (TLV 84). */
  invreqFeatures?: Uint8Array;
  /** invreq_quantity (TLV 86). */
  invreqQuantity?: bigint;
  /** invreq_payer_id (TLV 88). */
  invreqPayerId?: Uint8Array;
  /** invreq_payer_note (TLV 89). */
  invreqPayerNote?: string;
  /** invreq_paths (TLV 90). */
  invreqPaths?: BlindedPath[];
  /** invreq_bip_353_name (TLV 91). */
  invreqBip353Name?: { name: string; domain: string };

  // Mirrored offer fields
  /** offer_chains (TLV 2). */
  offerChains?: Uint8Array[];
  /** offer_metadata (TLV 4). */
  offerMetadata?: Uint8Array;
  /** offer_currency (TLV 6). */
  offerCurrency?: string;
  /** offer_amount (TLV 8). */
  offerAmountMsat?: bigint;
  /** offer_description (TLV 10). */
  offerDescription?: string;
  /** offer_features (TLV 12). */
  offerFeatures?: Uint8Array;
  /** offer_absolute_expiry (TLV 14). */
  offerAbsoluteExpiry?: bigint;
  /** offer_paths (TLV 16). */
  offerPaths?: BlindedPath[];
  /** offer_issuer (TLV 18). */
  offerIssuer?: string;
  /** offer_quantity_max (TLV 20). */
  offerQuantityMax?: bigint;
  /** offer_issuer_id (TLV 22). */
  offerIssuerId?: Uint8Array;
}

/**
 * Encodes a BOLT 12 Invoice (lni1...).
 *
 * The invoice is automatically signed using the node's private key
 * via BIP-340 Schnorr with the BOLT 12 Merkle tree construction.
 *
 * @param options - The invoice fields to encode.
 * @returns The encoded invoice string.
 * @throws If required fields are missing or paths/payinfo counts don't match.
 *
 * @example
 * ```ts
 * const invoice = encodeInvoice({
 *   nodeId: myNodePubkey,
 *   nodePrivateKey: myNodePrivkey,
 *   createdAt: BigInt(Math.floor(Date.now() / 1000)),
 *   paymentHash: hash,
 *   amountMsat: 100000n,
 *   invoicePaths: [blindedPath],
 *   blindedPayInfo: [payInfo],
 * });
 * ```
 */
export function encodeInvoice(options: InvoiceEncodeOptions): string {
  // Validation
  if (!options.nodePrivateKey || options.nodePrivateKey.length !== 32) {
    throw new Error('Invoice must have a valid nodePrivateKey (32 bytes)');
  }
  if (!options.nodeId || options.nodeId.length !== 33) {
    throw new Error('Invoice must have a valid nodeId (33-byte compressed public key)');
  }
  if (!options.paymentHash || options.paymentHash.length !== 32) {
    throw new Error('Invoice must have a valid paymentHash (32 bytes)');
  }
  if (!options.invoicePaths || options.invoicePaths.length === 0) {
    throw new Error('Invoice must have at least one invoice path');
  }
  if (!options.blindedPayInfo || options.blindedPayInfo.length === 0) {
    throw new Error('Invoice must have at least one blinded pay info entry');
  }
  if (options.invoicePaths.length !== options.blindedPayInfo.length) {
    throw new Error('Number of invoice_paths and blinded_payinfo must match');
  }

  const tlvs: TlvEntry[] = [];

  // Mirrored invreq fields
  if (options.invreqMetadata) {
    tlvs.push(tlv(0, options.invreqMetadata));
  }

  // Mirrored offer fields
  if (options.offerChains) {
    tlvs.push(tlv(2, concatBytes(...options.offerChains)));
  }
  if (options.offerMetadata) {
    tlvs.push(tlv(4, options.offerMetadata));
  }
  if (options.offerCurrency) {
    tlvs.push(tlv(6, utf8ToBytes(options.offerCurrency)));
  }
  if (options.offerAmountMsat !== undefined) {
    tlvs.push(tlv(8, encodeTu64(options.offerAmountMsat)));
  }
  if (options.offerDescription) {
    tlvs.push(tlv(10, utf8ToBytes(options.offerDescription)));
  }
  if (options.offerFeatures) {
    tlvs.push(tlv(12, options.offerFeatures));
  }
  if (options.offerAbsoluteExpiry !== undefined) {
    tlvs.push(tlv(14, encodeTu64(options.offerAbsoluteExpiry)));
  }
  if (options.offerPaths) {
    tlvs.push(tlv(16, encodeBlindedPaths(options.offerPaths)));
  }
  if (options.offerIssuer) {
    tlvs.push(tlv(18, utf8ToBytes(options.offerIssuer)));
  }
  if (options.offerQuantityMax !== undefined) {
    tlvs.push(tlv(20, encodeTu64(options.offerQuantityMax)));
  }
  if (options.offerIssuerId) {
    tlvs.push(tlv(22, options.offerIssuerId));
  }

  // Invoice request fields
  if (options.invreqChain) {
    tlvs.push(tlv(80, options.invreqChain));
  }
  if (options.invreqAmountMsat !== undefined) {
    tlvs.push(tlv(82, encodeTu64(options.invreqAmountMsat)));
  }
  if (options.invreqFeatures) {
    tlvs.push(tlv(84, options.invreqFeatures));
  }
  if (options.invreqQuantity !== undefined) {
    tlvs.push(tlv(86, encodeTu64(options.invreqQuantity)));
  }
  if (options.invreqPayerId) {
    tlvs.push(tlv(88, options.invreqPayerId));
  }
  if (options.invreqPayerNote) {
    tlvs.push(tlv(89, utf8ToBytes(options.invreqPayerNote)));
  }
  if (options.invreqPaths) {
    tlvs.push(tlv(90, encodeBlindedPaths(options.invreqPaths)));
  }
  if (options.invreqBip353Name) {
    tlvs.push(tlv(91, encodeBip353Name(options.invreqBip353Name)));
  }

  // Invoice-specific fields
  tlvs.push(tlv(160, encodeBlindedPaths(options.invoicePaths)));
  tlvs.push(tlv(162, encodeBlindedPayInfoArray(options.blindedPayInfo)));
  tlvs.push(tlv(164, encodeTu64(options.createdAt)));

  if (options.relativeExpiry !== undefined) {
    tlvs.push(tlv(166, encodeTu64(BigInt(options.relativeExpiry))));
  }
  tlvs.push(tlv(168, options.paymentHash));
  tlvs.push(tlv(170, encodeTu64(options.amountMsat)));

  if (options.fallbacks) {
    tlvs.push(tlv(172, encodeFallbackAddresses(options.fallbacks)));
  }
  if (options.invoiceFeatures) {
    tlvs.push(tlv(174, options.invoiceFeatures));
  }
  tlvs.push(tlv(176, options.nodeId));

  // Sort TLVs by type
  tlvs.sort((a, b) => Number(a.type - b.type));

  // Sign with the node's private key
  const signature = signBolt12(tlvs, options.nodePrivateKey, Bech32mPrefix.Invoice);
  tlvs.push(tlv(240, signature));

  // Re-sort after adding signature
  tlvs.sort((a, b) => Number(a.type - b.type));

  return encodeBolt12({ hrp: Bech32mPrefix.Invoice, tlvs });
}

// ── Invoice Error encoding ─────────────────────────────────────

/**
 * Options for encoding a BOLT 12 Invoice Error.
 */
export interface InvoiceErrorEncodeOptions {
  /** Human-readable error message. Required. */
  error: string;
  /** The TLV field number in the invoice/invoice_request that caused the error. */
  erroneousField?: bigint;
  /** Suggested replacement value for the erroneous field. */
  suggestedValue?: Uint8Array;
}

/**
 * Encodes a BOLT 12 Invoice Error as a raw TLV stream (Uint8Array).
 *
 * Invoice errors are sent via onion messages and are NOT bech32-encoded.
 * They use their own TLV type range (1, 3, 5) per the BOLT 12 spec.
 *
 * Per spec:
 * - TLV type 1: `erroneous_field` (tu64) — which TLV field caused the error
 * - TLV type 3: `suggested_value` (variable bytes) — suggested correction
 * - TLV type 5: `error` (utf8) — human-readable error message
 *
 * @param options - The invoice error fields to encode.
 * @returns The encoded TLV stream as raw bytes.
 * @throws If required fields are missing or constraints are violated.
 *
 * @example
 * ```ts
 * const errorBytes = encodeInvoiceError({
 *   error: 'Unknown offer',
 * });
 *
 * const errorWithField = encodeInvoiceError({
 *   error: 'Amount too low',
 *   erroneousField: 82n, // invreq_amount
 *   suggestedValue: encodeTu64(100000n),
 * });
 * ```
 */
export function encodeInvoiceError(options: InvoiceErrorEncodeOptions): Uint8Array {
  if (!options.error || options.error.length === 0) {
    throw new Error('Invoice error must have an error message');
  }
  if (options.suggestedValue !== undefined && options.erroneousField === undefined) {
    throw new Error('Invoice error with suggested_value must also set erroneous_field');
  }

  const tlvs: TlvEntry[] = [];

  if (options.erroneousField !== undefined) {
    tlvs.push(tlv(1, encodeTu64(options.erroneousField)));
  }
  if (options.suggestedValue !== undefined) {
    tlvs.push(tlv(3, options.suggestedValue));
  }
  tlvs.push(tlv(5, utf8ToBytes(options.error)));

  // Sort TLVs by type (ascending)
  tlvs.sort((a, b) => Number(a.type - b.type));

  return encodeTlvStream(tlvs);
}

// ── BIP-353 name encoding ──────────────────────────────────────

/**
 * Encodes a BIP-353 name into its binary TLV value.
 * Format: u8 name_len, name, u8 domain_len, domain.
 */
function encodeBip353Name(bip353: { name: string; domain: string }): Uint8Array {
  const nameBytes = utf8ToBytes(bip353.name);
  const domainBytes = utf8ToBytes(bip353.domain);

  if (nameBytes.length > 255) {
    throw new Error('BIP-353 name too long (max 255 bytes)');
  }
  if (domainBytes.length > 255) {
    throw new Error('BIP-353 domain too long (max 255 bytes)');
  }

  return concatBytes(
    new Uint8Array([nameBytes.length]),
    nameBytes,
    new Uint8Array([domainBytes.length]),
    domainBytes,
  );
}
