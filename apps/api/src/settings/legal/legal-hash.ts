/**
 * Hashing primitives for the P03-03 legal ports.
 *
 * Two different hashes are needed and they must not be confused:
 *
 * - a legal document body is hashed verbatim (`sha256Hex`) and the database
 *   re-computes the same digest on insert, so a stored revision can be proven to
 *   be exactly the text that was reviewed;
 * - a pre-submit session secret is stored only as its SHA-256 hex digest. Anchor
 *   creation receives that digest; evidence operations receive the raw token once
 *   and compare the digest in constant time. The raw token is never persisted,
 *   logged or returned by this module.
 */
import { createHash, timingSafeEqual } from 'node:crypto';

const SHA256_HEX = /^[0-9a-f]{64}$/;

/** Lowercase SHA-256 hex of the UTF-8 bytes of `value`. */
export function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/** Digest the caller stores for a freshly issued raw session token. */
export function hashSessionSecret(rawToken: string): string {
  return sha256Hex(rawToken);
}

/**
 * Constant-time comparison of a presented raw token with a stored digest. A
 * malformed stored digest or an empty token is a non-match, never an exception,
 * so a corrupt row cannot turn into a timing or error oracle.
 */
export function sessionSecretMatches(rawToken: string, storedHash: string): boolean {
  if (!SHA256_HEX.test(storedHash) || rawToken.length === 0) {
    return false;
  }
  const presented = Buffer.from(hashSessionSecret(rawToken), 'hex');
  const stored = Buffer.from(storedHash, 'hex');
  return presented.length === stored.length && timingSafeEqual(presented, stored);
}
