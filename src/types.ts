// src/types.ts

/**
 * Represents a Type-Length-Value (TLV) entry.
 */
export interface TlvEntry {
  type: bigint; // TLV type, uses bigint to support large type numbers
  length: bigint; // Length of the value in bytes
  value: Uint8Array; // Raw value bytes
}

/**
 * Represents a decoded TLV stream.
 */
export interface DecodedTlvStream {
  [key: string | number]: unknown; // Keys can be numerical TLV types or named fields
}

// Bech32m prefixes for different BOLT12 message types
export enum Bech32mPrefix {
  Offer = "lno",
  InvoiceRequest = "lnr",
  Invoice = "lni",
}

/**
 * The base interface for all decoded BOLT 12 entities.
 */
export interface BaseBolt12 {
  prefix: Bech32mPrefix;
  tlvs: TlvEntry[];
  // Add common fields that all BOLT12 types might share after decoding TLVs
  chainId?: Uint8Array; // offer_chains / invreq_chain etc. (first one in chains)
  description?: string;
  amountMsat?: bigint;
  quantityMax?: bigint;
  features?: Uint8Array;
  signature?: Uint8Array;
}

/**
 * Details for a blinded path hop.
 */
export interface OnionMessageHop {
  nodeId: Uint8Array; // Per BOLT 12, this is next_node_id
  tlvPayload: Uint8Array; // Encrypted data (usually TLV-encoded)
}

/**
 * A blinded path as defined in BOLT 12.
 */
export interface BlindedPath {
  blindingPubkey: Uint8Array; // AKA `path_id` in some contexts
  hops: OnionMessageHop[];
}

/**
 * Represents a decoded BOLT 12 Offer (lno1...).
 * Conforms to `BaseBolt12` and includes offer-specific fields.
 */
export interface DecodedOffer extends BaseBolt12 {
  prefix: Bech32mPrefix.Offer;
  chains?: Uint8Array[]; // Array of chain hashes if multiple are supported
  metadata?: Uint8Array;
  currency?: string; // ISO 4217 currency code
  absoluteExpiry?: bigint; // Seconds from epoch
  paths?: BlindedPath[];
  issuer?: string;
  issuerId?: Uint8Array; // Public key of the issuer
  features?: Uint8Array;
}

/**
 * Represents a decoded BOLT 12 Invoice Request (lnr1...).
 * Conforms to `BaseBolt12` and includes invoice request-specific fields.
 */
export interface DecodedInvoiceRequest extends BaseBolt12 {
  prefix: Bech32mPrefix.InvoiceRequest;
  invreqMetadata: Uint8Array; // Unique to invoice_request
  amountMsat?: bigint; // Amount in millisatoshis if specified by payer
  quantity?: bigint; // Quantity requested by payer
  payerId: Uint8Array; // Public key of the payer
  payerNote?: string;
  invreqPaths?: BlindedPath[]; // Payer's blinded paths
  invreqBip353Name?: { name: string; domain: string };
  // Fields from the offer that are mirrored in the invoice request
  chains?: Uint8Array[];
  offerMetadata?: Uint8Array;
  currency?: string;
  offerAmountMsat?: bigint; // Renamed to avoid collision with invreq_amount_msat
  offerDescription?: string; // Renamed description to offerDescription
  offerFeatures?: Uint8Array;
  offerAbsoluteExpiry?: bigint;
  offerPaths?: BlindedPath[];
  offerIssuer?: string;
  offerQuantityMax?: bigint;
  offerIssuerId?: Uint8Array;
  signature: Uint8Array; // Required for invoice requests
}

/**
 * Represents details for blinded payinfo.
 */
export interface BlindedPayInfo {
  feeBaseMsat: number;
  feeProportionalMillionths: number;
  cltvExpiryDelta: number;
  htlcMinimumMsat: bigint;
  htlcMaximumMsat: bigint;
  features: Uint8Array; // Features for this payinfo
}

/**
 * Represents a decoded BOLT 12 Invoice (lni1...).
 * Conforms to `BaseBolt12` and includes invoice-specific fields.
 */
export interface DecodedInvoice extends BaseBolt12 {
  prefix: Bech32mPrefix.Invoice;
  invoicePaths: BlindedPath[];
  blindedPayInfo: BlindedPayInfo[]; // Array of blinded payinfo
  createdAt: bigint; // Unix timestamp
  relativeExpiry?: number; // Seconds from creation
  paymentHash: Uint8Array; // SHA256 hash of payment_preimage
  nodeId: Uint8Array; // Public key of the invoicing node
  fallbacks?: FallbackAddress[];
  // Mirrored fields from Invoice Request
  invreqMetadata?: Uint8Array;
  invreqChain?: Uint8Array;
  invreqAmountMsat?: bigint;
  invreqFeatures?: Uint8Array;
  invreqQuantity?: bigint;
  invreqPayerId?: Uint8Array;
  invreqPayerNote?: string;
  invreqPaths?: BlindedPath[];
  invreqBip353Name?: { name: string; domain: string };
  // Mirrored fields from Offer (if originated from one)
  offerChains?: Uint8Array[];
  offerMetadata?: Uint8Array;
  offerCurrency?: string;
  offerAmountMsat?: bigint;
  offerDescription?: string;
  offerFeatures?: Uint8Array;
  offerAbsoluteExpiry?: bigint;
  offerPaths?: BlindedPath[];
  offerIssuer?: string;
  offerQuantityMax?: bigint;
  offerIssuerId?: Uint8Array;
  signature: Uint8Array; // Required for invoices
}

/**
 * Represents a fallback address for on-chain payments.
 */
export interface FallbackAddress {
  version: number; // Witness version
  address: Uint8Array; // Raw address bytes
}

/**
 * Merkle Leaf and Branch structures for signature calculation.
 */
export interface MerkleLeaf {
  hash: Uint8Array;
  index: number;
}

export interface MerkleTree {
  root: Uint8Array;
  leaves: MerkleLeaf[];
  branches: Uint8Array[];
}

/**
 * Represents a decoded BOLT 12 Invoice Error.
 *
 * Sent in response to an invoice_request or invoice to indicate an error.
 * Per BOLT 12 spec, this is an informative error message transmitted
 * via onion message `invoice_error` field.
 *
 * Note: Invoice errors are NOT bech32-encoded (they are only sent as raw TLV
 * via onion messages), so they don't have a bech32m prefix.
 */
export interface InvoiceError {
  /** The TLV field number that caused the error (TLV type 1, tu64). Optional. */
  erroneousField?: bigint;
  /** Suggested replacement value for the erroneous field (TLV type 3, variable bytes). Optional. */
  suggestedValue?: Uint8Array;
  /** Human-readable error message (TLV type 5, utf8). Required. */
  error: string;
  /** Raw TLV entries for the invoice error. */
  tlvs: TlvEntry[];
}

// Export a union type for all decodable BOLT 12 types
export type AnyDecodedBolt12 = DecodedOffer | DecodedInvoiceRequest | DecodedInvoice;
