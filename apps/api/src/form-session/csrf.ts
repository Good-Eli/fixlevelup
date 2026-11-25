import { createHmac, timingSafeEqual } from 'node:crypto';
import { F_CSRF_DOMAIN, FormSessionError } from './contract.js';

/**
 * Versioned key of the dedicated `P05_F_MUTATE` CSRF purpose. Rotation replaces
 * `FormCsrfKeyring.current`; a proof minted under another `keyId` (or another
 * secret under the same id) no longer verifies, which is the key-change
 * invalidation required by the protocol.
 */
export interface FormCsrfKey {
  readonly keyId: string;
  readonly secret: Buffer;
}

export interface FormCsrfKeyring {
  readonly current: FormCsrfKey;
}

/**
 * Key id charset. A dot is a field separator of the proof wire format
 * (`${keyId}.${selector}.${expiresAtEpochMs}.${mac}`), so a key id containing a
 * dot could never be verified back: the single grammar of this module must be
 * one-to-one, every acceptable key id issues a proof that verifies and an
 * unacceptable one never reaches issue at all (the service validates the
 * keyring at construction).
 */
export const CSRF_KEY_ID_PATTERN = /^[A-Za-z0-9_-]{1,32}(?![\s\S])/;

/** True when a CSRF key id is usable both for issuing and for verification. */
export function isValidCsrfKeyId(keyId: string): boolean {
  return CSRF_KEY_ID_PATTERN.test(keyId);
}

/** Canonical lowercase UUID text of the form-session selector. */
const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Positive safe epoch-millisecond integer text, no leading zero, no sign. */
const EXPIRY_MS = /^[1-9][0-9]{0,14}$/;

function csrfFailure(): never {
  throw new FormSessionError('CSRF');
}

function unavailable(): never {
  throw new FormSessionError('UNAVAILABLE');
}

/**
 * `P05_F_MUTATE` MAC over key id, selector, F secret and absolute millisecond
 * expiry. Milliseconds are used end to end so `expiresAtEpochMs <= anchor
 * expiresAt` is a plain integer comparison with no second rounding.
 */
function macOf(key: FormCsrfKey, selector: string, sessionSecret: string, expiresAtEpochMs: number): string {
  return createHmac('sha256', key.secret)
    .update(F_CSRF_DOMAIN)
    .update(key.keyId)
    .update('\0')
    .update(selector)
    .update('\0')
    .update(sessionSecret)
    .update('\0')
    .update(String(expiresAtEpochMs))
    .digest('base64url');
}

/**
 * Mints a stateless `P05_F_MUTATE` proof: `${keyId}.${selector}.${expiresAtEpochMs}.${mac}`.
 * It is not an idempotency key: the same tuple reissues the same string, a new
 * expiry yields a new string, and revocation/anchor expiry are checked elsewhere.
 */
export function issueCsrfProof(
  key: FormCsrfKey, selector: string, sessionSecret: string, expiresAtEpochMs: number,
): string {
  if (key.secret.length < 32 || !CSRF_KEY_ID_PATTERN.test(key.keyId)) {
    unavailable();
  }
  if (!CANONICAL_UUID.test(selector) || sessionSecret.length === 0) {
    unavailable();
  }
  if (!Number.isSafeInteger(expiresAtEpochMs) || expiresAtEpochMs <= 0) {
    unavailable();
  }
  const mac = macOf(key, selector, sessionSecret, expiresAtEpochMs);
  return `${key.keyId}.${selector}.${String(expiresAtEpochMs)}.${mac}`;
}

/**
 * Verifies a proof against the current key and the presented selector/secret.
 * Any shape, key id, selector, expiry or MAC mismatch is `CSRF`; the caller must
 * also check anchor liveness, so the optional anchor bound is enforced here as
 * the proof must never outlive the anchor it was issued for.
 */
export function verifyCsrfProof(
  keyring: FormCsrfKeyring,
  selector: string,
  sessionSecret: string,
  proof: string,
  nowEpochMs: number,
  anchorExpiresAtEpochMs?: number,
): { readonly expiresAtEpochMs: number } {
  const parts = proof.split('.');
  if (parts.length !== 4) {
    csrfFailure();
  }
  const proofKeyId = parts[0];
  const proofSelector = parts[1];
  const expiryText = parts[2];
  const suppliedMac = parts[3];
  if (proofKeyId === undefined || proofSelector === undefined
    || expiryText === undefined || suppliedMac === undefined) {
    csrfFailure();
  }
  const key = keyring.current;
  if (proofKeyId !== key.keyId || proofSelector !== selector) {
    csrfFailure();
  }
  if (!EXPIRY_MS.test(expiryText)) {
    csrfFailure();
  }
  const expiresAtEpochMs = Number(expiryText);
  if (!Number.isSafeInteger(expiresAtEpochMs) || expiresAtEpochMs <= nowEpochMs) {
    csrfFailure();
  }
  if (anchorExpiresAtEpochMs !== undefined && expiresAtEpochMs > anchorExpiresAtEpochMs) {
    csrfFailure();
  }
  const wanted = Buffer.from(macOf(key, selector, sessionSecret, expiresAtEpochMs), 'utf8');
  const supplied = Buffer.from(suppliedMac, 'utf8');
  if (supplied.length !== wanted.length || !timingSafeEqual(supplied, wanted)) {
    csrfFailure();
  }
  return { expiresAtEpochMs };
}
