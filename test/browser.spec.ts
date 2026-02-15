/**
 * Browser runtime tests using Playwright.
 *
 * Bundles the library with esbuild and runs encode/decode
 * in real Chromium, Firefox, and WebKit engines.
 */
import { test, expect } from '@playwright/test';
import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

// Bundle the library for browser before tests run
let bundleCode: string;

test.beforeAll(() => {
  // Build the library first
  execSync('npm run build', { cwd: ROOT, stdio: 'ignore' });

  // Bundle dist/ into a single IIFE for browsers
  execSync(
    'npx esbuild dist/index.js --bundle --format=iife --global-name=bolt12 --platform=browser --outfile=test/browser-bundle.js',
    { cwd: ROOT, stdio: 'ignore' },
  );
  bundleCode = readFileSync(resolve(ROOT, 'test/browser-bundle.js'), 'utf-8');
});

test('encode and decode offer in browser', async ({ page }) => {
  await page.addScriptTag({ content: bundleCode });

  const result = await page.evaluate(() => {
    const { encodeOffer, decodeBolt12 } = (window as any).bolt12;

    // Create a minimal offer with a fake 33-byte pubkey
    const issuerId = new Uint8Array(33);
    issuerId[0] = 0x02;
    for (let i = 1; i < 33; i++) issuerId[i] = i;

    const encoded = encodeOffer({
      issuerId,
      description: 'Browser test coffee',
      amountMsat: BigInt(100000),
    });

    const decoded = decodeBolt12(encoded);
    return {
      startsWithLno: encoded.startsWith('lno1'),
      prefix: decoded.prefix,
      description: decoded.description,
      amountMsat: String(decoded.amountMsat),
    };
  });

  expect(result.startsWithLno).toBe(true);
  expect(result.prefix).toBe('lno');
  expect(result.description).toBe('Browser test coffee');
  expect(result.amountMsat).toBe('100000');
});

test('bech32 encode/decode without checksum in browser', async ({ page }) => {
  await page.addScriptTag({ content: bundleCode });

  const result = await page.evaluate(() => {
    const { bolt12Encode, bolt12Decode } = (window as any).bolt12;

    const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const encoded = bolt12Encode('lno', data);
    const decoded = bolt12Decode(encoded);

    return {
      startsWithLno: encoded.startsWith('lno1'),
      hrp: decoded.hrp,
      dataMatch: JSON.stringify(Array.from(decoded.data)) === JSON.stringify(Array.from(data)),
    };
  });

  expect(result.startsWithLno).toBe(true);
  expect(result.hrp).toBe('lno');
  expect(result.dataMatch).toBe(true);
});

test('TLV encode/decode roundtrip in browser', async ({ page }) => {
  await page.addScriptTag({ content: bundleCode });

  const result = await page.evaluate(() => {
    const { encodeTlvStream, decodeTlvStream, utf8ToBytes, bytesToUtf8 } = (window as any).bolt12;

    const tlvs = [
      { type: BigInt(10), length: BigInt(5), value: utf8ToBytes('hello') },
      { type: BigInt(22), length: BigInt(3), value: utf8ToBytes('abc') },
    ];

    const encoded = encodeTlvStream(tlvs);
    const decoded = decodeTlvStream(encoded);

    return {
      count: decoded.length,
      firstType: String(decoded[0].type),
      firstValue: bytesToUtf8(decoded[0].value),
      secondType: String(decoded[1].type),
      secondValue: bytesToUtf8(decoded[1].value),
    };
  });

  expect(result.count).toBe(2);
  expect(result.firstType).toBe('10');
  expect(result.firstValue).toBe('hello');
  expect(result.secondType).toBe('22');
  expect(result.secondValue).toBe('abc');
});

test('invoice error encode/decode in browser', async ({ page }) => {
  await page.addScriptTag({ content: bundleCode });

  const result = await page.evaluate(() => {
    const { encodeInvoiceError, decodeInvoiceError } = (window as any).bolt12;

    const errorBytes = encodeInvoiceError({
      error: 'Unknown offer',
      erroneousField: BigInt(82),
    });

    const decoded = decodeInvoiceError(errorBytes);

    return {
      error: decoded.error,
      erroneousField: String(decoded.erroneousField),
    };
  });

  expect(result.error).toBe('Unknown offer');
  expect(result.erroneousField).toBe('82');
});
