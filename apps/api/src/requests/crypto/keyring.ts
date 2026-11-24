/**
 * Versioned keyring for the P05-01 crypto module (docs/P05-PLAN.md §3).
 *
 * Keys live outside the database and Git, one set per environment, and are
 * identified by an immutable `keyId`. New writes always use the active key of
 * a purpose; historical reads resolve the exact saved `keyId`. A missing key
 * refuses the operation — there is no fallback to another key or purpose, and
 * key material is never logged or included in errors.
 */

/** Key purposes are disjoint: a KEK never verifies an HMAC and vice versa. */
export type KeyPurpose = 'PAYLOAD_KEK' | 'IDEMPOTENCY_HMAC';

export interface VersionedKey {
  readonly keyId: string;
  readonly purpose: KeyPurpose;
  readonly material: Buffer;
}

export type KeyringErrorCode = 'MISSING_KEY' | 'UNKNOWN_KEY' | 'INVALID_KEY_MATERIAL' | 'DOMAIN_MISMATCH';

export class KeyringError extends Error {
  constructor(readonly code: KeyringErrorCode) {
    super(`Keyring error: ${code}`);
    this.name = 'KeyringError';
  }
}

export interface KeyringConfig {
  readonly keys: readonly VersionedKey[];
  /** Active key of the PAYLOAD_KEK purpose; new wraps use this key. */
  readonly activeKeyId: string;
  /** Active key of the IDEMPOTENCY_HMAC purpose; new digests use this key. */
  readonly activeHmacKeyId: string;
}

const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{3,63}$/;
const SECRET_HEX_PATTERN = /^[0-9a-f]{64}$/;

interface KeyInput { readonly keyId: string; readonly secretHex: string }

function parseKeys(purpose: KeyPurpose, inputs: readonly KeyInput[]): VersionedKey[] {
  const seen = new Set<string>();
  const keys: VersionedKey[] = [];
  for (const input of inputs) {
    if (typeof input.keyId !== 'string' || !KEY_ID_PATTERN.test(input.keyId)
      || typeof input.secretHex !== 'string' || !SECRET_HEX_PATTERN.test(input.secretHex)) {
      throw new KeyringError('INVALID_KEY_MATERIAL');
    }
    if (seen.has(input.keyId)) { throw new KeyringError('INVALID_KEY_MATERIAL'); }
    seen.add(input.keyId);
    keys.push({ keyId: input.keyId, purpose, material: Buffer.from(input.secretHex, 'hex') });
  }
  return keys;
}

/**
 * Build a keyring from raw configuration. Every secret must be a 64-character
 * lowercase hex string (32 bytes), keyIds must be unique within a purpose,
 * no secret material may appear in more than one key entry across purposes,
 * and both active ids must resolve inside their own purpose list. Partial or
 * ambiguous configuration fails closed.
 */
export function loadKeyring(input: {
  kek: readonly KeyInput[];
  hmac: readonly KeyInput[];
  activeKekId: string;
  activeHmacKeyId: string;
}): KeyringConfig {
  const keys = [
    ...parseKeys('PAYLOAD_KEK', input.kek),
    ...parseKeys('IDEMPOTENCY_HMAC', input.hmac),
  ];
  // Cross-purpose material reuse is forbidden: the same bytes must never
  // appear as a KEK and as an HMAC key (or twice anywhere in the ring).
  const seenMaterials = new Set<string>();
  for (const key of keys) {
    const hex = key.material.toString('hex');
    if (seenMaterials.has(hex)) { throw new KeyringError('INVALID_KEY_MATERIAL'); }
    seenMaterials.add(hex);
  }
  const activeKek = keys.find((key) => key.purpose === 'PAYLOAD_KEK' && key.keyId === input.activeKekId);
  const activeHmac = keys.find((key) => key.purpose === 'IDEMPOTENCY_HMAC' && key.keyId === input.activeHmacKeyId);
  if (activeKek === undefined || activeHmac === undefined) { throw new KeyringError('MISSING_KEY'); }
  return Object.freeze({ keys, activeKeyId: activeKek.keyId, activeHmacKeyId: activeHmac.keyId });
}

/** The key new writes of `purpose` must use. */
export function activeKey(ring: KeyringConfig, purpose: KeyPurpose): VersionedKey {
  const target = purpose === 'PAYLOAD_KEK' ? ring.activeKeyId : ring.activeHmacKeyId;
  const active = ring.keys.find((key) => key.purpose === purpose && key.keyId === target);
  if (active === undefined) { throw new KeyringError('MISSING_KEY'); }
  return active;
}

/**
 * Resolve a historical key by its saved id. A retired or unknown id refuses
 * the read; it never falls back to the active key of the purpose.
 */
export function keyById(ring: KeyringConfig, purpose: KeyPurpose, keyId: string): VersionedKey {
  const key = ring.keys.find((entry) => entry.purpose === purpose && entry.keyId === keyId);
  if (key === undefined) { throw new KeyringError('UNKNOWN_KEY'); }
  return key;
}
