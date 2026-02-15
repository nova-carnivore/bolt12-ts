// src/signature.ts
//
// BOLT 12 signature calculation using BIP-340 Schnorr signatures
// and the Merkle tree construction specified in the BOLT 12 spec.

import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { TlvEntry, Bech32mPrefix } from './types';
import { encodeBigSize } from './tlv';
import { utf8ToBytes, concatBytes } from './utils';

/**
 * Compute a tagged hash as defined in BIP-340/341:
 * H(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
 *
 * @param tag - The tag string.
 * @param msg - The message bytes.
 * @returns The 32-byte tagged hash.
 */
export function taggedHash(tag: string, msg: Uint8Array): Uint8Array {
  const tagHash = sha256(utf8ToBytes(tag));
  return sha256(concatBytes(tagHash, tagHash, msg));
}

/**
 * Serializes a single TLV entry as its on-wire bytes (BigSize type + BigSize length + value).
 * This is used for Merkle tree leaf computation.
 */
function serializeTlv(tlv: TlvEntry): Uint8Array {
  return concatBytes(
    encodeBigSize(tlv.type),
    encodeBigSize(BigInt(tlv.value.length)),
    tlv.value,
  );
}

/**
 * Computes a tagged hash where the tag is already in byte form.
 * H(tagBytes, msg) = SHA256(SHA256(tagBytes) || SHA256(tagBytes) || msg)
 */
function taggedHashRaw(tagBytes: Uint8Array, msg: Uint8Array): Uint8Array {
  const tagHash = sha256(tagBytes);
  return sha256(concatBytes(tagHash, tagHash, msg));
}

/**
 * Computes the Merkle root of a set of TLV entries per BOLT 12 spec.
 *
 * The tree leaves are, in TLV-ascending order for each TLV:
 *   1. H("LnLeaf", tlv) — where tlv is the full serialized TLV entry.
 *   2. H("LnNonce" || first-tlv, tlv-type) — where first-tlv is the serialized
 *      numerically-first TLV entry, and tlv-type is the BigSize-encoded type field.
 *
 * Inner nodes: H("LnBranch", lesser-SHA256 || greater-SHA256)
 * Ordering is lexicographic (lesser first) so proofs are position-independent.
 *
 * If not exactly a power of 2 leaves, the deepest tree is on the lowest-order leaves.
 *
 * @param tlvs - The TLV entries (excluding signature TLVs 240-1000).
 * @returns The 32-byte Merkle root.
 * @throws If no TLV entries are provided.
 */
export function computeMerkleRoot(tlvs: TlvEntry[]): Uint8Array {
  // Sort by type ascending
  const sorted = [...tlvs].sort((a, b) => (a.type < b.type ? -1 : a.type > b.type ? 1 : 0));

  if (sorted.length === 0) {
    throw new Error('Cannot compute Merkle root: no TLV entries');
  }

  // The first TLV (numerically lowest type) serialized in full
  const firstTlvBytes = serializeTlv(sorted[0]);

  // Build leaf pairs: for each TLV, produce (leaf, nonce) pair
  const leaves: Uint8Array[] = [];
  for (const tlv of sorted) {
    const tlvBytes = serializeTlv(tlv);
    const typeBytes = encodeBigSize(tlv.type);

    // H("LnLeaf", tlv)
    const leaf = taggedHash('LnLeaf', tlvBytes);

    // H("LnNonce" || first-tlv, tlv-type)
    // The tag is the concatenation of the string "LnNonce" and the first TLV bytes
    const nonceTagBytes = concatBytes(utf8ToBytes('LnNonce'), firstTlvBytes);
    const nonce = taggedHashRaw(nonceTagBytes, typeBytes);

    leaves.push(leaf);
    leaves.push(nonce);
  }

  return merkleReduce(leaves);
}

/**
 * Helper to compute H("LnBranch", lesser || greater).
 * Ordering is lexicographic to make proofs position-independent.
 */
function branchHash(a: Uint8Array, b: Uint8Array): Uint8Array {
  const cmp = compareBytes(a, b);
  const lesser = cmp <= 0 ? a : b;
  const greater = cmp <= 0 ? b : a;
  return taggedHash('LnBranch', concatBytes(lesser, greater));
}

/**
 * Lexicographic comparison of two byte arrays.
 */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return a.length - b.length;
}

/**
 * Reduces an array of hashes into a single Merkle root.
 *
 * Pairing is done from the start: (0,1), (2,3), ...
 * If odd count, the last element is promoted unpaired to the next level.
 * This puts the deepest tree on the lowest-order (earliest) leaves.
 */
function merkleReduce(hashes: Uint8Array[]): Uint8Array {
  if (hashes.length === 0) {
    throw new Error('Cannot reduce empty hash array');
  }
  if (hashes.length === 1) {
    return hashes[0];
  }

  const next: Uint8Array[] = [];
  let i = 0;
  while (i < hashes.length) {
    if (i + 1 < hashes.length) {
      next.push(branchHash(hashes[i], hashes[i + 1]));
      i += 2;
    } else {
      next.push(hashes[i]);
      i += 1;
    }
  }

  return merkleReduce(next);
}

/**
 * Returns the message name for a given BOLT 12 prefix.
 */
function messageNameForPrefix(prefix: Bech32mPrefix): string {
  switch (prefix) {
    case Bech32mPrefix.Offer:
      return 'offer';
    case Bech32mPrefix.InvoiceRequest:
      return 'invoice_request';
    case Bech32mPrefix.Invoice:
      return 'invoice';
    default:
      throw new Error(`Unknown prefix for signature: ${prefix}`);
  }
}

/**
 * Computes the signature tag for BOLT 12:
 * "lightning" + messagename + fieldname
 *
 * @param prefix - The BOLT 12 message type.
 * @param fieldName - The field name (default: "signature").
 * @returns The tag string.
 */
export function signatureTag(prefix: Bech32mPrefix, fieldName: string = 'signature'): string {
  return 'lightning' + messageNameForPrefix(prefix) + fieldName;
}

/**
 * Signs a BOLT 12 message using BIP-340 Schnorr signatures.
 *
 * Computes the Merkle root of all non-signature TLVs, then signs:
 *   SIG(tag, merkle_root, key)
 * where tag = "lightning" || messagename || "signature"
 *
 * Note: Offers are NOT signed per the spec.
 *
 * @param tlvs - All non-signature TLV entries of the message.
 * @param privateKey - The 32-byte private key.
 * @param prefix - The message type prefix.
 * @returns The 64-byte BIP-340 Schnorr signature.
 */
export function signBolt12(
  tlvs: TlvEntry[],
  privateKey: Uint8Array,
  prefix: Bech32mPrefix,
): Uint8Array {
  // Filter out signature TLVs (types 240-1000)
  const nonSigTlvs = tlvs.filter((t) => Number(t.type) < 240 || Number(t.type) > 1000);

  const merkleRoot = computeMerkleRoot(nonSigTlvs);
  const tag = signatureTag(prefix);
  const msgHash = taggedHash(tag, merkleRoot);

  return schnorr.sign(msgHash, privateKey);
}

/**
 * Verifies a BOLT 12 signature using BIP-340 Schnorr.
 *
 * @param tlvs - All TLV entries of the message (including signature TLV 240).
 * @param signature - The 64-byte Schnorr signature.
 * @param publicKey - The 32-byte x-only public key, or 33-byte compressed (prefix stripped).
 * @param prefix - The message type prefix.
 * @returns True if the signature is valid.
 * @throws If signature or public key have invalid length.
 */
export function verifyBolt12Signature(
  tlvs: TlvEntry[],
  signature: Uint8Array,
  publicKey: Uint8Array,
  prefix: Bech32mPrefix,
): boolean {
  if (signature.length !== 64) {
    throw new Error(`Invalid signature length: expected 64 bytes, got ${signature.length}`);
  }

  let xOnlyPubkey: Uint8Array;
  if (publicKey.length === 33) {
    xOnlyPubkey = publicKey.subarray(1);
  } else if (publicKey.length === 32) {
    xOnlyPubkey = publicKey;
  } else {
    throw new Error(`Invalid public key length: expected 32 or 33 bytes, got ${publicKey.length}`);
  }

  // Filter out signature TLVs (types 240-1000)
  const nonSigTlvs = tlvs.filter((t) => Number(t.type) < 240 || Number(t.type) > 1000);

  const merkleRoot = computeMerkleRoot(nonSigTlvs);
  const tag = signatureTag(prefix);
  const msgHash = taggedHash(tag, merkleRoot);

  return schnorr.verify(signature, msgHash, xOnlyPubkey);
}
