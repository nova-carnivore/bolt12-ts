// src/decode.ts
//
// Decodes BOLT 12 offers (lno), invoice requests (lnr), and invoices (lni)
// from their bech32-encoded string representation.

import { bolt12Decode, convertBits } from './bech32m';
import {
  TlvEntry,
  Bech32mPrefix,
  BaseBolt12,
  DecodedOffer,
  DecodedInvoiceRequest,
  DecodedInvoice,
  InvoiceError,
  BlindedPath,
  OnionMessageHop,
  BlindedPayInfo,
  FallbackAddress,
  AnyDecodedBolt12,
} from './types';
import { decodeTlvStream, decodeTu64 } from './tlv';
import { bytesToUtf8, bytesToNumberBE } from './utils';

/**
 * Decodes a BOLT 12 string (offer, invoice request, or invoice).
 *
 * Handles `+` concatenation and whitespace as per BOLT 12 spec.
 * Uses bech32 encoding without checksum (per spec).
 *
 * @param bolt12String - The bech32-encoded BOLT 12 string.
 * @returns The decoded BOLT 12 object.
 * @throws If the string is malformed or has an unknown prefix.
 *
 * @example
 * ```ts
 * const offer = decodeBolt12('lno1pqps7sjqpgt...');
 * if (offer.prefix === 'lno') {
 *   console.log('Description:', offer.description);
 * }
 * ```
 */
export function decodeBolt12(bolt12String: string): AnyDecodedBolt12 {
  let decodedBech32: { hrp: string; data: Uint8Array };
  try {
    decodedBech32 = bolt12Decode(bolt12String);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(`Failed to decode bolt12 string: ${msg}`);
  }

  const { hrp: decodedHrp, data } = decodedBech32;

  let hrp: Bech32mPrefix;
  switch (decodedHrp) {
    case Bech32mPrefix.Offer:
      hrp = Bech32mPrefix.Offer;
      break;
    case Bech32mPrefix.InvoiceRequest:
      hrp = Bech32mPrefix.InvoiceRequest;
      break;
    case Bech32mPrefix.Invoice:
      hrp = Bech32mPrefix.Invoice;
      break;
    default:
      throw new Error(`Unknown BOLT 12 HRP: ${decodedHrp}`);
  }

  const tlvBytes = convertBits(data, 5, 8, false);
  const tlvEntries = decodeTlvStream(tlvBytes);

  switch (hrp) {
    case Bech32mPrefix.Offer:
      return decodeOffer(tlvEntries);
    case Bech32mPrefix.InvoiceRequest:
      return decodeInvoiceRequest(tlvEntries);
    case Bech32mPrefix.Invoice:
      return decodeInvoice(tlvEntries);
    default:
      throw new Error(`Internal Error: Unhandled Bech32mPrefix ${hrp}`);
  }
}

/**
 * Parses common TLV fields shared across all BOLT 12 message types.
 */
const parseCommonTlvs = (tlvEntries: TlvEntry[]): Partial<BaseBolt12> => {
  const common: Partial<BaseBolt12> = {};
  for (const tlv of tlvEntries) {
    switch (Number(tlv.type)) {
      case 2: { // chains
        const chains: Uint8Array[] = [];
        for (let i = 0; i < tlv.value.length; i += 32) {
          chains.push(tlv.value.subarray(i, i + 32));
        }
        common.chainId = chains[0];
        break;
      }
      case 8: // amount_msat
        common.amountMsat = decodeTu64(tlv.value);
        break;
      case 10: // description
        common.description = bytesToUtf8(tlv.value);
        break;
      case 12: // features
        common.features = tlv.value;
        break;
      case 20: // quantity_max
        common.quantityMax = decodeTu64(tlv.value);
        break;
      case 240: // signature
        common.signature = tlv.value;
        break;
    }
  }
  return common;
};

/**
 * Decodes blinded paths from their TLV value representation.
 *
 * Format per path:
 *   - 33 bytes: blinding_pubkey
 *   - 1 byte: num_hops
 *   - For each hop:
 *     - 33 bytes: node_id
 *     - 2 bytes (u16): encrypted_data_len
 *     - encrypted_data_len bytes: encrypted_data (onion TLV payload)
 */
const decodeBlindedPaths = (bytes: Uint8Array): BlindedPath[] => {
  const paths: BlindedPath[] = [];
  let offset = 0;
  while (offset < bytes.length) {
    // Blinding Pubkey (33 bytes)
    if (offset + 33 > bytes.length) throw new Error('Malformed blinded path: missing blinding_pubkey');
    const blindingPubkey = bytes.subarray(offset, offset + 33);
    offset += 33;

    // num_hops (1 byte per spec for blinded_path)
    if (offset >= bytes.length) throw new Error('Malformed blinded path: missing num_hops');
    const numHops = bytes[offset];
    offset += 1;

    const hops: OnionMessageHop[] = [];
    for (let i = 0; i < numHops; i++) {
      // Node ID (33 bytes)
      if (offset + 33 > bytes.length) throw new Error('Malformed blinded path: missing hop node_id');
      const nodeId = bytes.subarray(offset, offset + 33);
      offset += 33;

      // encrypted_data_len (u16 big-endian)
      if (offset + 2 > bytes.length) throw new Error('Malformed blinded path: missing encrypted_data_len');
      const tlvPayloadLen = (bytes[offset] << 8) | bytes[offset + 1];
      offset += 2;

      // encrypted_data
      if (offset + tlvPayloadLen > bytes.length) throw new Error('Malformed blinded path: truncated encrypted_data');
      const tlvPayload = bytes.subarray(offset, offset + tlvPayloadLen);
      offset += tlvPayloadLen;

      hops.push({ nodeId, tlvPayload });
    }

    paths.push({ blindingPubkey, hops });
  }
  return paths;
};

/**
 * Parses the invreq_bip_353_name TLV (type 91).
 * Format: u8 name_len, name_len*byte name, u8 domain_len, domain_len*byte domain
 */
function parseBip353Name(bytes: Uint8Array): { name: string; domain: string } {
  let offset = 0;

  if (offset >= bytes.length) throw new Error('Malformed invreq_bip_353_name: missing name_len');
  const nameLen = bytes[offset];
  offset += 1;

  if (offset + nameLen > bytes.length) throw new Error('Malformed invreq_bip_353_name: truncated name');
  const name = bytesToUtf8(bytes.subarray(offset, offset + nameLen));
  offset += nameLen;

  if (offset >= bytes.length) throw new Error('Malformed invreq_bip_353_name: missing domain_len');
  const domainLen = bytes[offset];
  offset += 1;

  if (offset + domainLen > bytes.length) throw new Error('Malformed invreq_bip_353_name: truncated domain');
  const domain = bytesToUtf8(bytes.subarray(offset, offset + domainLen));
  offset += domainLen;

  // Validate characters per spec: 0-9, a-z, A-Z, -, _, .
  const validChars = /^[0-9a-zA-Z\-_.]+$/;
  if (!validChars.test(name)) {
    throw new Error(`Invalid BIP-353 name: contains invalid characters: "${name}"`);
  }
  if (!validChars.test(domain)) {
    throw new Error(`Invalid BIP-353 domain: contains invalid characters: "${domain}"`);
  }

  return { name, domain };
}

/**
 * Decodes a BOLT 12 Offer (lno1...).
 *
 * @param tlvEntries - Parsed TLV entries specific to an Offer.
 * @returns The decoded Offer object.
 */
function decodeOffer(tlvEntries: TlvEntry[]): DecodedOffer {
  const offer: DecodedOffer = {
    prefix: Bech32mPrefix.Offer,
    tlvs: tlvEntries,
  };

  Object.assign(offer, parseCommonTlvs(tlvEntries));

  for (const tlv of tlvEntries) {
    switch (Number(tlv.type)) {
      case 2: { // offer_chains
        if (!offer.chains) offer.chains = [];
        for (let i = 0; i < tlv.value.length; i += 32) {
          offer.chains.push(tlv.value.subarray(i, i + 32));
        }
        break;
      }
      case 4: // offer_metadata
        offer.metadata = tlv.value;
        break;
      case 6: // offer_currency
        offer.currency = bytesToUtf8(tlv.value);
        break;
      case 14: // offer_absolute_expiry
        offer.absoluteExpiry = decodeTu64(tlv.value);
        break;
      case 16: // offer_paths
        offer.paths = decodeBlindedPaths(tlv.value);
        break;
      case 18: // offer_issuer
        offer.issuer = bytesToUtf8(tlv.value);
        break;
      case 22: // offer_issuer_id
        offer.issuerId = tlv.value;
        break;
    }
  }

  // Validation per spec
  if (offer.amountMsat && !offer.description) {
    throw new Error('Offer with amount must have a description');
  }
  if (offer.currency && !offer.amountMsat) {
    throw new Error('Offer with currency must have an amount');
  }

  return offer;
}

/**
 * Decodes a BOLT 12 Invoice Request (lnr1...).
 *
 * @param tlvEntries - Parsed TLV entries specific to an Invoice Request.
 * @returns The decoded Invoice Request object.
 */
function decodeInvoiceRequest(tlvEntries: TlvEntry[]): DecodedInvoiceRequest {
  const invReq: DecodedInvoiceRequest = {
    prefix: Bech32mPrefix.InvoiceRequest,
    tlvs: tlvEntries,
    invreqMetadata: new Uint8Array(),
    payerId: new Uint8Array(),
    signature: new Uint8Array(),
  };

  Object.assign(invReq, parseCommonTlvs(tlvEntries));

  for (const tlv of tlvEntries) {
    switch (Number(tlv.type)) {
      case 0: // invreq_metadata
        invReq.invreqMetadata = tlv.value;
        break;
      case 80: // invreq_chain
        if (!invReq.chains) invReq.chains = [];
        invReq.chains.push(tlv.value);
        break;
      case 82: // invreq_amount
        invReq.amountMsat = decodeTu64(tlv.value);
        break;
      case 84: // invreq_features
        invReq.features = tlv.value;
        break;
      case 86: // invreq_quantity
        invReq.quantity = decodeTu64(tlv.value);
        break;
      case 88: // invreq_payer_id
        invReq.payerId = tlv.value;
        break;
      case 89: // invreq_payer_note
        invReq.payerNote = bytesToUtf8(tlv.value);
        break;
      case 90: // invreq_paths
        invReq.invreqPaths = decodeBlindedPaths(tlv.value);
        break;
      case 91: // invreq_bip_353_name
        invReq.invreqBip353Name = parseBip353Name(tlv.value);
        break;
      case 240: // signature
        invReq.signature = tlv.value;
        break;
      // Offer fields mirrored in invoice_request
      case 4: // offer_metadata
        invReq.offerMetadata = tlv.value;
        break;
      case 6: // offer_currency
        invReq.currency = bytesToUtf8(tlv.value);
        break;
      case 8: // offer_amount
        invReq.offerAmountMsat = decodeTu64(tlv.value);
        break;
      case 10: // offer_description
        invReq.offerDescription = bytesToUtf8(tlv.value);
        break;
      case 12: // offer_features
        invReq.offerFeatures = tlv.value;
        break;
      case 14: // offer_absolute_expiry
        invReq.offerAbsoluteExpiry = decodeTu64(tlv.value);
        break;
      case 16: // offer_paths
        invReq.offerPaths = decodeBlindedPaths(tlv.value);
        break;
      case 18: // offer_issuer
        invReq.offerIssuer = bytesToUtf8(tlv.value);
        break;
      case 20: // offer_quantity_max
        invReq.offerQuantityMax = decodeTu64(tlv.value);
        break;
      case 22: // offer_issuer_id
        invReq.offerIssuerId = tlv.value;
        break;
    }
  }

  if (!invReq.invreqMetadata || invReq.invreqMetadata.length === 0) {
    throw new Error('Invoice request must have invreq_metadata');
  }
  if (!invReq.payerId || invReq.payerId.length !== 33) {
    throw new Error('Invoice request must have a valid invreq_payer_id (33 bytes)');
  }
  if (!invReq.signature || invReq.signature.length !== 64) {
    throw new Error('Invoice request must have a valid signature (64 bytes)');
  }

  return invReq;
}

/**
 * Decodes blinded payinfo from its serialized representation.
 * Format: u32 fee_base_msat, u32 fee_proportional_millionths,
 *         u16 cltv_expiry_delta, u64 htlc_minimum_msat,
 *         u64 htlc_maximum_msat, u16 flen, flen*byte features
 */
const decodeBlindedPayInfo = (bytes: Uint8Array): BlindedPayInfo => {
  let offset = 0;

  if (bytes.length < 22) { // 4+4+2+8+8 = 26 minimum (with empty features)
    throw new Error('Malformed blinded_payinfo: too short');
  }

  const feeBaseMsat = bytesToNumberBE(bytes.subarray(offset, offset + 4));
  offset += 4;

  const feeProportionalMillionths = bytesToNumberBE(bytes.subarray(offset, offset + 4));
  offset += 4;

  const cltvExpiryDelta = bytesToNumberBE(bytes.subarray(offset, offset + 2));
  offset += 2;

  // htlc_minimum_msat (u64 = 8 bytes)
  const htlcMinimumMsat = bytesToBigintBE(bytes.subarray(offset, offset + 8));
  offset += 8;

  // htlc_maximum_msat (u64 = 8 bytes)
  const htlcMaximumMsat = bytesToBigintBE(bytes.subarray(offset, offset + 8));
  offset += 8;

  const flen = bytesToNumberBE(bytes.subarray(offset, offset + 2));
  offset += 2;

  const features = bytes.subarray(offset, offset + flen);
  offset += flen;

  return {
    feeBaseMsat,
    feeProportionalMillionths,
    cltvExpiryDelta,
    htlcMinimumMsat,
    htlcMaximumMsat,
    features,
  };
};

/** Reads a big-endian u64 as bigint. */
function bytesToBigintBE(bytes: Uint8Array): bigint {
  let num = BigInt(0);
  for (const byte of bytes) {
    num = (num << BigInt(8)) | BigInt(byte);
  }
  return num;
}

/**
 * Decodes a fallback address.
 * Format: byte version, u16 len, len*byte address
 */
const decodeFallbackAddress = (bytes: Uint8Array): FallbackAddress => {
  let offset = 0;

  const version = bytes[offset];
  offset++;

  const len = bytesToNumberBE(bytes.subarray(offset, offset + 2));
  offset += 2;

  const address = bytes.subarray(offset, offset + len);

  return { version, address };
};

/**
 * Decodes a BOLT 12 Invoice (lni1...).
 *
 * @param tlvEntries - Parsed TLV entries specific to an Invoice.
 * @returns The decoded Invoice object.
 */
function decodeInvoice(tlvEntries: TlvEntry[]): DecodedInvoice {
  const invoice: DecodedInvoice = {
    prefix: Bech32mPrefix.Invoice,
    tlvs: tlvEntries,
    invoicePaths: [],
    blindedPayInfo: [],
    createdAt: BigInt(0),
    paymentHash: new Uint8Array(),
    nodeId: new Uint8Array(),
    signature: new Uint8Array(),
  };

  Object.assign(invoice, parseCommonTlvs(tlvEntries));

  for (const tlv of tlvEntries) {
    switch (Number(tlv.type)) {
      case 160: // invoice_paths
        invoice.invoicePaths = decodeBlindedPaths(tlv.value);
        break;
      case 162: { // invoice_blindedpay
        // Each payinfo is concatenated; parse sequentially
        invoice.blindedPayInfo = parseBlindedPayInfoArray(tlv.value);
        break;
      }
      case 164: // invoice_created_at
        invoice.createdAt = decodeTu64(tlv.value);
        break;
      case 166: // invoice_relative_expiry
        invoice.relativeExpiry = Number(decodeTu64(tlv.value));
        break;
      case 168: // invoice_payment_hash
        invoice.paymentHash = tlv.value;
        break;
      case 170: // invoice_amount
        invoice.amountMsat = decodeTu64(tlv.value);
        break;
      case 172: { // invoice_fallbacks
        invoice.fallbacks = parseFallbackAddresses(tlv.value);
        break;
      }
      case 174: // invoice_features
        invoice.features = tlv.value;
        break;
      case 176: // invoice_node_id
        invoice.nodeId = tlv.value;
        break;
      // Mirrored Invoice Request fields
      case 0: // invreq_metadata
        invoice.invreqMetadata = tlv.value;
        break;
      case 80: // invreq_chain
        invoice.invreqChain = tlv.value;
        break;
      case 82: // invreq_amount
        invoice.invreqAmountMsat = decodeTu64(tlv.value);
        break;
      case 84: // invreq_features
        invoice.invreqFeatures = tlv.value;
        break;
      case 86: // invreq_quantity
        invoice.invreqQuantity = decodeTu64(tlv.value);
        break;
      case 88: // invreq_payer_id
        invoice.invreqPayerId = tlv.value;
        break;
      case 89: // invreq_payer_note
        invoice.invreqPayerNote = bytesToUtf8(tlv.value);
        break;
      case 90: // invreq_paths
        invoice.invreqPaths = decodeBlindedPaths(tlv.value);
        break;
      case 91: // invreq_bip_353_name
        invoice.invreqBip353Name = parseBip353Name(tlv.value);
        break;
      // Mirrored Offer fields
      case 2: { // offer_chains
        if (!invoice.offerChains) invoice.offerChains = [];
        for (let i = 0; i < tlv.value.length; i += 32) {
          invoice.offerChains.push(tlv.value.subarray(i, i + 32));
        }
        break;
      }
      case 4: // offer_metadata
        invoice.offerMetadata = tlv.value;
        break;
      case 6: // offer_currency
        invoice.offerCurrency = bytesToUtf8(tlv.value);
        break;
      case 8: // offer_amount
        invoice.offerAmountMsat = decodeTu64(tlv.value);
        break;
      case 10: // offer_description
        invoice.offerDescription = bytesToUtf8(tlv.value);
        break;
      case 12: // offer_features
        invoice.offerFeatures = tlv.value;
        break;
      case 14: // offer_absolute_expiry
        invoice.offerAbsoluteExpiry = decodeTu64(tlv.value);
        break;
      case 16: // offer_paths
        invoice.offerPaths = decodeBlindedPaths(tlv.value);
        break;
      case 18: // offer_issuer
        invoice.offerIssuer = bytesToUtf8(tlv.value);
        break;
      case 20: // offer_quantity_max
        invoice.offerQuantityMax = decodeTu64(tlv.value);
        break;
      case 22: // offer_issuer_id
        invoice.offerIssuerId = tlv.value;
        break;
    }
  }

  // Validate required fields
  if (!invoice.createdAt) {
    throw new Error('Invoice must have invoice_created_at');
  }
  if (!invoice.paymentHash || invoice.paymentHash.length !== 32) {
    throw new Error('Invoice must have a valid invoice_payment_hash (32 bytes)');
  }
  if (!invoice.nodeId || invoice.nodeId.length !== 33) {
    throw new Error('Invoice must have a valid invoice_node_id (33 bytes)');
  }
  if (!invoice.signature || invoice.signature.length !== 64) {
    throw new Error('Invoice must have a valid signature (64 bytes)');
  }
  if (!invoice.invoicePaths || invoice.invoicePaths.length === 0) {
    throw new Error('Invoice must have invoice_paths');
  }
  if (!invoice.blindedPayInfo || invoice.blindedPayInfo.length === 0) {
    throw new Error('Invoice must have invoice_blindedpay');
  }
  if (invoice.invoicePaths.length !== invoice.blindedPayInfo.length) {
    throw new Error('Number of invoice_paths and blinded_payinfo must match');
  }

  return invoice;
}

/**
 * Parses an array of blinded_payinfo entries from concatenated bytes.
 * Each entry is: u32 + u32 + u16 + u64 + u64 + u16 + flen*byte = 26 + flen bytes
 */
function parseBlindedPayInfoArray(bytes: Uint8Array): BlindedPayInfo[] {
  const result: BlindedPayInfo[] = [];
  let offset = 0;

  while (offset < bytes.length) {
    // Minimum size: 4+4+2+8+8+2 = 28 bytes
    if (offset + 28 > bytes.length) {
      throw new Error('Malformed blinded_payinfo: truncated entry');
    }

    const feeBaseMsat = bytesToNumberBE(bytes.subarray(offset, offset + 4));
    offset += 4;
    const feeProportionalMillionths = bytesToNumberBE(bytes.subarray(offset, offset + 4));
    offset += 4;
    const cltvExpiryDelta = bytesToNumberBE(bytes.subarray(offset, offset + 2));
    offset += 2;
    const htlcMinimumMsat = bytesToBigintBE(bytes.subarray(offset, offset + 8));
    offset += 8;
    const htlcMaximumMsat = bytesToBigintBE(bytes.subarray(offset, offset + 8));
    offset += 8;
    const flen = bytesToNumberBE(bytes.subarray(offset, offset + 2));
    offset += 2;

    if (offset + flen > bytes.length) {
      throw new Error('Malformed blinded_payinfo: truncated features');
    }
    const features = bytes.subarray(offset, offset + flen);
    offset += flen;

    result.push({
      feeBaseMsat,
      feeProportionalMillionths,
      cltvExpiryDelta,
      htlcMinimumMsat,
      htlcMaximumMsat,
      features,
    });
  }

  return result;
}

/**
 * Parses an array of fallback addresses from concatenated bytes.
 */
function parseFallbackAddresses(bytes: Uint8Array): FallbackAddress[] {
  const result: FallbackAddress[] = [];
  let offset = 0;

  while (offset < bytes.length) {
    if (offset + 3 > bytes.length) {
      throw new Error('Malformed fallback address: truncated entry');
    }
    const version = bytes[offset];
    offset++;
    const len = bytesToNumberBE(bytes.subarray(offset, offset + 2));
    offset += 2;
    if (offset + len > bytes.length) {
      throw new Error('Malformed fallback address: truncated address');
    }
    const address = bytes.subarray(offset, offset + len);
    offset += len;

    result.push({ version, address });
  }

  return result;
}

// ── Invoice Error Decoding ─────────────────────────────────────

/**
 * Decodes a BOLT 12 Invoice Error from raw TLV bytes.
 *
 * Invoice errors are received via onion messages and are NOT bech32-encoded.
 * They use their own TLV type range per the BOLT 12 spec:
 * - TLV type 1: `erroneous_field` (tu64) — which TLV field caused the error
 * - TLV type 3: `suggested_value` (variable bytes) — suggested correction
 * - TLV type 5: `error` (utf8) — human-readable error message
 *
 * @param bytes - The raw TLV-encoded invoice error bytes.
 * @returns The decoded InvoiceError object.
 * @throws If the error message is missing or the TLV stream is malformed.
 *
 * @example
 * ```ts
 * const invoiceError = decodeInvoiceError(rawBytes);
 * console.log('Error:', invoiceError.error);
 * if (invoiceError.erroneousField !== undefined) {
 *   console.log('Field:', invoiceError.erroneousField);
 * }
 * ```
 */
export function decodeInvoiceError(bytes: Uint8Array): InvoiceError {
  const tlvEntries = decodeTlvStream(bytes);

  const invoiceError: InvoiceError = {
    error: '',
    tlvs: tlvEntries,
  };

  for (const tlv of tlvEntries) {
    switch (Number(tlv.type)) {
      case 1: // erroneous_field
        invoiceError.erroneousField = decodeTu64(tlv.value);
        break;
      case 3: // suggested_value
        invoiceError.suggestedValue = tlv.value;
        break;
      case 5: // error
        invoiceError.error = bytesToUtf8(tlv.value);
        break;
    }
  }

  if (!invoiceError.error || invoiceError.error.length === 0) {
    throw new Error('Invoice error must have an error message (TLV type 5)');
  }

  // Per spec: suggested_value requires erroneous_field
  if (invoiceError.suggestedValue !== undefined && invoiceError.erroneousField === undefined) {
    throw new Error('Invoice error has suggested_value without erroneous_field');
  }

  return invoiceError;
}
