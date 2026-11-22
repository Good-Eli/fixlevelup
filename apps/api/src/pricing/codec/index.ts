import { Buffer } from 'node:buffer';
import { createHash, timingSafeEqual } from 'node:crypto';
import { calculatePricing, type PricingResult } from '../engine/index.js';
import { boundedPricingText, canonicalPricingJson, parseStrictPricingJson } from './json.js';

export { canonicalPricingJson, parseStrictPricingJson, type PricingJson } from './json.js';

function digest(text: string): Buffer {
  return createHash('sha256').update(text, 'utf8').digest();
}

function encodeResult({ input, lines, breakdown, totalMinor }: PricingResult): string {
  return canonicalPricingJson({ version: 1, input, lines, breakdown, totalMinor });
}

export function sealPricing(input: unknown): { bytes: string; sha256: string } {
  const bytes = encodeResult(calculatePricing(input));
  return { bytes, sha256: digest(bytes).toString('hex') };
}

function invalidSnapshot(): never {
  throw new TypeError('Invalid pricing snapshot');
}

/** The digest must come from trusted storage; replay does not grant approval authority. */
export function verifyPricingSnapshot(bytes: string | Uint8Array, expectedSha256: string): PricingResult {
  if (typeof expectedSha256 !== 'string' || expectedSha256.length !== 64 ||
      /[^0-9a-f]/u.test(expectedSha256)) { invalidSnapshot(); }
  const text = boundedPricingText(bytes);
  // Fatal UTF-8 decoding is byte preserving on valid inputs (including BOMs).
  if (!timingSafeEqual(digest(text), Buffer.from(expectedSha256, 'hex'))) { invalidSnapshot(); }
  const value = parseStrictPricingJson(text);
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== 5 || value['version'] !== 1 ||
      !Object.hasOwn(value, 'input') || !Object.hasOwn(value, 'lines') ||
      !Object.hasOwn(value, 'breakdown') || !Object.hasOwn(value, 'totalMinor')) { invalidSnapshot(); }
  const result = calculatePricing(value['input']);
  // This validates every claimed result field, exact shape, semantic array order
  // and canonical encoding without maintaining a second copy of the engine schema.
  if (encodeResult(result) !== text) { invalidSnapshot(); }
  return result;
}
