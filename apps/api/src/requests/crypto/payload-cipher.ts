/**
 * AEAD payload cipher for P05-01 (docs/P05-PLAN.md §3).
 *
 * Every payload cell is sealed with its own random 32-byte DEK under
 * AES-256-GCM with a random 96-bit nonce. The DEK itself is wrapped under the
 * versioned KEK as a separate AEAD domain. Domain separation comes purely from
 * distinct AAD strings — wrapping AAD and payload AAD never collide — so a
 * wrapped DEK replayed as payload ciphertext (or the reverse) fails
 * authentication instead of decrypting. There is no double encryption and no
 * implicit key fallback: opening resolves the exact saved keyId, a missing key
 * refuses. Key material, DEKs and plaintext are never logged or exposed in
 * errors.
 */
import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { KeyringError, activeKey, keyById } from './keyring.js';
import type { KeyringConfig } from './keyring.js';

/** Maximum persisted ciphertext size incl. the 16-byte GCM tag (plaintext + tag). */
export const MAX_PLAINTEXT_BYTES = 60000;
/** SQL-aligned minimum: the persisted ciphertext must be at least 16 bytes. */
const MIN_PLAINTEXT_BYTES = 16;

/**
 * Documented per-key rotation bound (docs/P05-PLAN.md §3): a key version MUST
 * be retired before 2^20 = 1048576 seal operations. At that bound the
 * collision probability of the random 96-bit wrap nonce stays below 4e-13
 * under NIST SP 800-38D guidance. sealPayload is stateless — it carries no
 * operation counter — so this bound is an operational contract enforced by
 * the key rotation procedure, not by the cipher itself.
 */
export const MAX_SEALED_PAYLOADS_PER_KEY = 2 ** 20;

const DEK_BYTES = 32;
const NONCE_BYTES = 12;
const AUTH_TAG_BYTES = 16;
const AAD_MIN_CHARS = 8;
const AAD_MAX_CHARS = 128;
const ENVIRONMENT_MAX_CHARS = 24;
const REQUEST_ID_MAX_CHARS = 36;
const SCHEMA_MAX_CHARS = 24;

export type PayloadCipherErrorCode = 'TAMPERED' | 'MISSING_KEY' | 'UNKNOWN_KEY' | 'DOMAIN_MISMATCH' | 'MALFORMED';

export class PayloadCipherError extends Error {
  constructor(readonly code: PayloadCipherErrorCode) {
    super(`Payload cipher error: ${code}`);
    this.name = 'PayloadCipherError';
  }
}

export type PayloadKind = 'CONTACT' | 'ADDRESS' | 'DETAILS';

export interface SealedPayload {
  readonly keyId: string;
  readonly wrappedDek: Buffer;
  readonly nonce: Buffer;
  readonly ciphertext: Buffer;
  readonly authTag: Buffer;
  readonly aadContext: string;
}

/** Unambiguous AAD component encoding: every component is length-prefixed, so
 * unrestricted environment/schema text can never alias another pair through a
 * `/` in its value. */
function aadComponent(value: string): string {
  return `${String(Buffer.byteLength(value, 'utf8'))}:${value}`;
}

/** Payload-domain AAD uses the caller environment verbatim (no truncation). */
function payloadAad(
  environment: string, schema: string, kind: PayloadKind, requestId: string, revision: number,
): string {
  return ['p05/payload/v1', aadComponent(environment), aadComponent(schema), aadComponent(kind),
    aadComponent(requestId), aadComponent(String(revision))].join('/');
}

/** Wrapping-domain AAD string; binds the wrap to the same kind/revision as the
 * payload domain (§3: UUID and immutable revision in both AEAD domains). */
function wrapAad(
  environment: string, schema: string, keyId: string, requestId: string, kind: PayloadKind, revision: number,
): string {
  return ['p05/wrap/v1', aadComponent(environment), aadComponent(schema), 'PAYLOAD_KEK',
    aadComponent(keyId), aadComponent(requestId), aadComponent(kind), aadComponent(String(revision))].join('/');
}

function requireText(value: string, maxChars: number): string {
  if (value.length < 1 || value.length > maxChars) {
    throw new PayloadCipherError('MALFORMED');
  }
  return value;
}

const PAYLOAD_KINDS: ReadonlySet<string> = new Set(['CONTACT', 'ADDRESS', 'DETAILS']);

function requireKind(kind: PayloadKind): PayloadKind {
  // Routed through a widened string so untyped callers' runtime forgeries are
  // still refused by the closed vocabulary.
  const value: string = kind;
  if (!PAYLOAD_KINDS.has(value)) { throw new PayloadCipherError('MALFORMED'); }
  return kind;
}

function requireRevision(revision: number): number {
  if (!Number.isSafeInteger(revision) || revision < 1) {
    throw new PayloadCipherError('MALFORMED');
  }
  return revision;
}

function aeadEncrypt(key: Buffer, nonce: Buffer, plaintext: Buffer, aad: string): { ciphertext: Buffer; authTag: Buffer } {
  const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: AUTH_TAG_BYTES });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { ciphertext, authTag: cipher.getAuthTag() };
}

function aeadDecrypt(key: Buffer, nonce: Buffer, ciphertext: Buffer, authTag: Buffer, aad: string): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: AUTH_TAG_BYTES });
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(authTag);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    // GCM authenticates everything (ciphertext, tag and AAD) before releasing
    // plaintext; a failure here is a domain mismatch or tampering, never a
    // partial plaintext leak.
    throw new PayloadCipherError('TAMPERED');
  }
}

/**
 * Proof-only wrap-domain diagnostic (P05-01 audit round 4): decrypts ONLY the
 * wrapped DEK against a caller-supplied wrap AAD, so a test can assert that
 * the WRAP authentication itself fails when kind/revision are wrong — proving
 * the wrap AAD really carries them (independent of the payload-domain check
 * that would also fail later). Production code must not call this.
 */
export function unwrapDekForProof(ring: KeyringConfig, keyId: string,
  wrappedDek: Buffer, environment: string, schema: string, kind: PayloadKind,
  requestId: string, revision: number): Buffer {
  const key = keyById(ring, 'PAYLOAD_KEK', keyId);
  const wrapAadContext = wrapAad(environment, schema, key.keyId, requestId, kind, revision);
  const dekNonce = wrappedDek.subarray(0, NONCE_BYTES);
  const wrappedCiphertext = wrappedDek.subarray(NONCE_BYTES, NONCE_BYTES + DEK_BYTES);
  const wrappedTag = wrappedDek.subarray(NONCE_BYTES + DEK_BYTES);
  return aeadDecrypt(key.material, dekNonce, wrappedCiphertext, wrappedTag, wrapAadContext);
}

/**
 * Seal one payload cell under the active KEK. The AAD context of the payload
 * domain is returned alongside the sealed fields so the caller can persist it
 * and re-present the exact string on open.
 */
export function sealPayload(input: {
  ring: KeyringConfig;
  environment: string;
  schema: string;
  kind: PayloadKind;
  requestId: string;
  revision: number;
  plaintext: Buffer;
}): SealedPayload {
  // No truncation: distinct environments must produce distinct AAD, so an
  // out-of-bounds environment (> 24 chars) fails closed instead of aliasing.
  const environment = requireText(input.environment, ENVIRONMENT_MAX_CHARS);
  const schema = requireText(input.schema, SCHEMA_MAX_CHARS);
  const kind = requireKind(input.kind);
  const requestId = requireText(input.requestId, REQUEST_ID_MAX_CHARS);
  const revision = requireRevision(input.revision);
  // The stored representation is ciphertext+tag in ONE column: the minimum
  // plaintext therefore aligns with the SQL minimum (16) and the maximum with
  // the SQL maximum (60000) — no representation ever violates the schema.
  if (!Buffer.isBuffer(input.plaintext) || input.plaintext.length < MIN_PLAINTEXT_BYTES
    || input.plaintext.length > MAX_PLAINTEXT_BYTES - AUTH_TAG_BYTES) {
    throw new PayloadCipherError('MALFORMED');
  }
  const aadContext = payloadAad(environment, schema, kind, requestId, revision);
  if (aadContext.length < AAD_MIN_CHARS || aadContext.length > AAD_MAX_CHARS) {
    throw new PayloadCipherError('MALFORMED');
  }
  const key = activeKey(input.ring, 'PAYLOAD_KEK');
  // The wrapped DEK is bound to exactly this (request, kind, revision) cell.
  const wrapAadContext = wrapAad(environment, schema, key.keyId, requestId, kind, revision);
  const dek = randomBytes(DEK_BYTES);
  const dekNonce = randomBytes(NONCE_BYTES);
  const wrapped = aeadEncrypt(key.material, dekNonce, dek, wrapAadContext);
  const payloadNonce = randomBytes(NONCE_BYTES);
  const sealed = aeadEncrypt(dek, payloadNonce, input.plaintext, aadContext);
  // The persisted ciphertext column carries ciphertext+tag together.
  if (sealed.ciphertext.length + sealed.authTag.length > MAX_PLAINTEXT_BYTES) {
    throw new PayloadCipherError('MALFORMED');
  }
  return {
    keyId: key.keyId,
    wrappedDek: Buffer.concat([dekNonce, wrapped.ciphertext, wrapped.authTag]),
    nonce: payloadNonce,
    ciphertext: sealed.ciphertext,
    authTag: sealed.authTag,
    aadContext,
  };
}

/**
 * Open a sealed payload cell. The KEK is resolved by the saved keyId so
 * historical rows survive rotation; a missing key refuses with UNKNOWN_KEY.
 * The wrap and payload AAD strings are reconstructed from the caller's
 * environment/schema/kind/requestId/revision inputs, so any cross-domain or
 * cross-row substitution fails GCM authentication.
 */
export function openPayload(input: {
  ring: KeyringConfig;
  environment: string;
  schema: string;
  kind: PayloadKind;
  requestId: string;
  revision: number;
  sealed: SealedPayload;
}): Buffer {
  // No truncation: distinct environments must produce distinct AAD, so an
  // out-of-bounds environment (> 24 chars) fails closed instead of aliasing.
  const environment = requireText(input.environment, ENVIRONMENT_MAX_CHARS);
  const schema = requireText(input.schema, SCHEMA_MAX_CHARS);
  const kind = requireKind(input.kind);
  const requestId = requireText(input.requestId, REQUEST_ID_MAX_CHARS);
  const revision = requireRevision(input.revision);
  const sealed = input.sealed;
  if (typeof sealed.keyId !== 'string' || sealed.keyId.length < 1) { throw new PayloadCipherError('MALFORMED'); }
  if (!Buffer.isBuffer(sealed.wrappedDek) || !Buffer.isBuffer(sealed.nonce) || !Buffer.isBuffer(sealed.ciphertext)
    || !Buffer.isBuffer(sealed.authTag) || typeof sealed.aadContext !== 'string') {
    throw new PayloadCipherError('MALFORMED');
  }
  if (sealed.wrappedDek.length !== NONCE_BYTES + DEK_BYTES + AUTH_TAG_BYTES
    || sealed.nonce.length !== NONCE_BYTES || sealed.authTag.length !== AUTH_TAG_BYTES
    || sealed.ciphertext.length < 1 || sealed.ciphertext.length > MAX_PLAINTEXT_BYTES - AUTH_TAG_BYTES) {
    throw new PayloadCipherError('MALFORMED');
  }
  const expectedAad = payloadAad(environment, schema, kind, requestId, revision);
  if (sealed.aadContext !== expectedAad) { throw new PayloadCipherError('DOMAIN_MISMATCH'); }
  let key: ReturnType<typeof keyById>;
  try {
    key = keyById(input.ring, 'PAYLOAD_KEK', sealed.keyId);
  } catch (error) {
    if (error instanceof KeyringError && (error.code === 'UNKNOWN_KEY' || error.code === 'MISSING_KEY')) {
      throw new PayloadCipherError(error.code);
    }
    throw error;
  }
  const wrapAadContext = wrapAad(environment, schema, key.keyId, requestId, kind, revision);
  const dekNonce = sealed.wrappedDek.subarray(0, NONCE_BYTES);
  const wrappedCiphertext = sealed.wrappedDek.subarray(NONCE_BYTES, NONCE_BYTES + DEK_BYTES);
  const wrappedTag = sealed.wrappedDek.subarray(NONCE_BYTES + DEK_BYTES);
  const dek = aeadDecrypt(key.material, dekNonce, wrappedCiphertext, wrappedTag, wrapAadContext);
  if (dek.length !== DEK_BYTES) { throw new PayloadCipherError('TAMPERED'); }
  return aeadDecrypt(dek, sealed.nonce, sealed.ciphertext, sealed.authTag, expectedAad);
}

const IDEM_PREFIX = 'p05/idem/v1/';

/**
 * Idempotency HMAC-SHA-256 over the canonical intent with its own versioned
 * key and domain-prefixed namespace. New digests use the active HMAC key and
 * report its keyId; verification resolves the key by the saved keyId.
 */
export function idempotencyHmac(input: {
  ring: KeyringConfig;
  namespace: string;
  canonicalIntent: string;
}): { keyId: string; digest: Buffer } {
  const key = activeKey(input.ring, 'IDEMPOTENCY_HMAC');
  return { keyId: key.keyId, digest: hmacDigest(key.material, input.namespace, input.canonicalIntent) };
}

function hmacDigest(keyMaterial: Buffer, namespace: string, canonicalIntent: string): Buffer {
  return createHmac('sha256', keyMaterial)
    .update(Buffer.from(`${IDEM_PREFIX}${namespace}:${canonicalIntent}`, 'utf8'))
    .digest();
}

/** Constant-time verification against the digest stored on the idempotency row. */
export function verifyIdempotencyHmac(input: {
  ring: KeyringConfig;
  keyId: string;
  namespace: string;
  canonicalIntent: string;
  digest: Buffer;
}): boolean {
  const key = keyById(input.ring, 'IDEMPOTENCY_HMAC', input.keyId);
  if (!Buffer.isBuffer(input.digest) || input.digest.length !== 32) { return false; }
  const expected = hmacDigest(key.material, input.namespace, input.canonicalIntent);
  return input.digest.length === expected.length && timingSafeEqual(input.digest, expected);
}
