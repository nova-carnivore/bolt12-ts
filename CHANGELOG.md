# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-02-15

### Added

- **Offer encoding/decoding** — Full support for BOLT 12 offers (`lno1...`)
  - All TLV fields: chains, metadata, currency, amount, description, features, absolute expiry, paths, issuer, quantity max, issuer id
  - Blinded path support with multiple hops
- **Invoice Request encoding/decoding** — Full support for invoice requests (`lnr1...`)
  - Automatic BIP-340 Schnorr signing via Merkle tree construction
  - BIP-353 human-readable name parsing (`invreq_bip_353_name`)
  - All mirrored offer fields
- **Invoice encoding/decoding** — Full support for invoices (`lni1...`)
  - Automatic BIP-340 Schnorr signing
  - Blinded pay info (fee, CLTV, HTLC limits)
  - Fallback on-chain addresses
  - All mirrored offer and invoice request fields
- **Signature verification** — `verifyBolt12Signature()` for all signed types
- **Merkle tree** — Spec-compliant construction with `LnLeaf`, `LnNonce`, `LnBranch` tagged hashes
- **Bech32 encoding** — Spec-compliant (no checksum, per BOLT 12)
  - `+` concatenation and whitespace handling
  - Case-insensitive decoding
- **TLV encoding/decoding** — BigSize format per BOLT 1
- **Cross-platform** — Node.js 20+, Bun, Deno, browsers
- **53 comprehensive tests** — Covering all features and edge cases
- **TypeScript strict mode** — Full type safety
- **Zero vulnerable dependencies** — Only `@noble/curves` and `@noble/hashes`
