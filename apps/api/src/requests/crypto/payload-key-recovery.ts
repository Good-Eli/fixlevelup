/**
 * Offline managed-wrap backup and rewrap. No database or filesystem discovery
 * is performed here. The read-only issuer must keep all source writers stopped
 * and bind the exact managed slot inventory and backup SHA-256 to the same
 * separately attested database dump. Transfer the KEKs and expected SHA by
 * protected means independently of the archive. A matching SHA is not a
 * signature; an archive and an untrusted SHA grant no restore eligibility.
 *
 * The caller must provision a fresh, offline destination generation for the
 * same environment. Nothing here mutates the source, restores database rows,
 * or grants application access. The caller may activate the destination only
 * after this function and separate database/snapshot checks succeed. On any
 * failure, leave the generation offline: it may contain partial writes and is
 * not a retry target. Never clean up or overwrite final slots as error recovery.
 *
 * The canonical UTF-8 representation is JSON with no extra whitespace:
 * [domain, version, environment, [[cellId, requestId, kind, revision,
 *                                  keyId, lowercaseWrappedDekHex], ...]]
 * Each record is sorted by lowercase cell UUID and carries a managed AEAD wrap,
 * not the payload ciphertext, plaintext, or either KEK.
 */
import { createHash, timingSafeEqual } from 'node:crypto';
import { activeKey } from './keyring.js';
import type { KeyringConfig } from './keyring.js';
import { rewrapPayloadKey } from './payload-cipher.js';
import type { PayloadKeySlotRef, PayloadKeySlots, PayloadKeyWrap } from './payload-key-directory.js';

const DOMAIN = 'p05/payload-key-backup';
const VERSION = 1;
const MAX_REFS = 4096;
const MAX_BACKUP_BYTES = 128 + MAX_REFS * 320;
const WRAP_BYTES = 60;
const KEK_BYTES = 32;
const SHA256_HEX_LENGTH = 64;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PAYLOAD_KINDS: ReadonlySet<string> = new Set(['CONTACT', 'ADDRESS', 'DETAILS']);

type BackupRecord = readonly [
  cellId: string, requestId: string, kind: PayloadKeySlotRef['kind'], revision: number,
  keyId: string, wrappedDekHex: string,
];

function unavailable(): Error {
  const message = 'Payload key recovery unavailable';
  const error = new Error(message);
  error.stack = `Error: ${message}`;
  return error;
}

function isEnvironment(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 1 && value.length <= 24 && !/[^\x20-\x7e]/.test(value);
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && value.length === 36 && UUID.test(value);
}

function isKeyId(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 4 && value.length <= 64
    && /^[A-Za-z0-9]/.test(value) && !/[^A-Za-z0-9._-]/.test(value);
}

function isHex(value: unknown, length: number): value is string {
  return typeof value === 'string' && value.length === length && !/[^0-9a-f]/.test(value);
}

function isBoundedArray(value: unknown): boolean {
  return Array.isArray(value) && value.length <= MAX_REFS;
}

function checkedInventory(refs: readonly PayloadKeySlotRef[], environment: string): PayloadKeySlotRef[] {
  if (!isEnvironment(environment) || !isBoundedArray(refs)) { throw unavailable(); }
  const inventory: PayloadKeySlotRef[] = [];
  const seen = new Set<string>();
  for (const ref of refs) {
    const { environment: refEnvironment, cellId, requestId, kind, revision } = ref;
    if (refEnvironment !== environment || !isUuid(cellId) || !isUuid(requestId) || !PAYLOAD_KINDS.has(kind)
      || !Number.isSafeInteger(revision) || revision < 1 || seen.has(cellId)) {
      throw unavailable();
    }
    seen.add(cellId);
    inventory.push(Object.freeze({ environment, cellId, requestId, kind, revision }));
  }
  return inventory.sort((a, b) => a.cellId < b.cellId ? -1 : a.cellId > b.cellId ? 1 : 0);
}

function checkedWrap(wrap: PayloadKeyWrap): PayloadKeyWrap {
  const { keyId, wrappedDek } = wrap;
  if (!isKeyId(keyId) || !Buffer.isBuffer(wrappedDek) || wrappedDek.length !== WRAP_BYTES) {
    throw unavailable();
  }
  return { keyId, wrappedDek: Buffer.from(wrappedDek) };
}

function record(ref: PayloadKeySlotRef, wrap: PayloadKeyWrap): BackupRecord {
  return [ref.cellId, ref.requestId, ref.kind, ref.revision, wrap.keyId, wrap.wrappedDek.toString('hex')];
}

function encode(environment: string, records: readonly BackupRecord[]): Buffer {
  const bytes = Buffer.from(JSON.stringify([DOMAIN, VERSION, environment, records]), 'utf8');
  if (bytes.length > MAX_BACKUP_BYTES) { throw unavailable(); }
  return bytes;
}

function digest(bytes: Buffer): Buffer {
  return createHash('sha256').update(bytes).digest();
}

function isTuple(value: unknown, length: number): value is readonly unknown[] {
  return Array.isArray(value) && value.length === length;
}

function decode(bytes: Buffer, environment: string, refs: readonly PayloadKeySlotRef[]): PayloadKeyWrap[] {
  const archive: unknown = JSON.parse(bytes.toString('utf8'));
  if (!isTuple(archive, 4)) { throw unavailable(); }
  const [domain, version, archivedEnvironment, rows] = archive;
  if (domain !== DOMAIN || version !== VERSION || archivedEnvironment !== environment
    || !isTuple(rows, refs.length)) {
    throw unavailable();
  }
  const canonical: BackupRecord[] = [];
  const wraps = refs.map((ref, index) => {
    const row = rows[index];
    if (!isTuple(row, 6)) { throw unavailable(); }
    const [cellId, requestId, kind, revision, keyId, hex] = row;
    // Compare exact identities positionally against the sorted inventory; this
    // rejects substitutions, duplicates and any noncanonical archive ordering.
    if (cellId !== ref.cellId || requestId !== ref.requestId || kind !== ref.kind || revision !== ref.revision
      || !isKeyId(keyId) || !isHex(hex, WRAP_BYTES * 2)) {
      throw unavailable();
    }
    canonical.push([ref.cellId, ref.requestId, ref.kind, ref.revision, keyId, hex]);
    return { keyId, wrappedDek: Buffer.from(hex, 'hex') };
  });
  // Comparing canonical bytes rejects extra whitespace, BOM, alternate number
  // forms, escape aliases, and any invalid UTF-8 replaced by the decoder.
  if (!bytes.equals(encode(environment, canonical))) { throw unavailable(); }
  return wraps;
}

function requireFreshKek(previous: KeyringConfig, next: KeyringConfig): string {
  const target = activeKey(next, 'PAYLOAD_KEK');
  if (!isKeyId(target.keyId) || !Buffer.isBuffer(target.material) || target.material.length !== KEK_BYTES) {
    throw unavailable();
  }
  // Refuse rewapping under any historical KEK id or already-used key material,
  // even if that key was not the previous active KEK or present in the dump.
  for (const prior of previous.keys) {
    if (!Buffer.isBuffer(prior.material) || prior.material.length !== KEK_BYTES
      || (prior.purpose === 'PAYLOAD_KEK' && prior.keyId === target.keyId)
      || timingSafeEqual(prior.material, target.material)) {
      throw unavailable();
    }
  }
  return target.keyId;
}

export async function capturePayloadKeyBackup(
  refs: readonly PayloadKeySlotRef[], source: PayloadKeySlots,
): Promise<{ bytes: Buffer; sha256: string }> {
  try {
    const environment = source.environment;
    const exact = checkedInventory(refs, environment);
    const records: BackupRecord[] = [];
    for (const ref of exact) {
      records.push(record(ref, checkedWrap(await source.read(ref))));
    }
    const bytes = encode(environment, records);
    return { bytes, sha256: digest(bytes).toString('hex') };
  } catch {
    throw unavailable();
  }
}

export async function restorePayloadKeyBackup(options: {
  bytes: Uint8Array;
  sha256: string;
  refs: readonly PayloadKeySlotRef[];
  destination: PayloadKeySlots;
  previous: KeyringConfig;
  next: KeyringConfig;
}): Promise<void> {
  try {
    const { bytes: input, sha256, refs, destination, previous, next } = options;
    if (!(input instanceof Uint8Array) || input.byteLength < 1 || input.byteLength > MAX_BACKUP_BYTES
      || !isHex(sha256, SHA256_HEX_LENGTH)) {
      throw unavailable();
    }
    const bytes = Buffer.from(input);
    if (!timingSafeEqual(digest(bytes), Buffer.from(sha256, 'hex'))) { throw unavailable(); }
    const environment = destination.environment;
    const exact = checkedInventory(refs, environment);
    const wraps = decode(bytes, environment, exact);
    const newKeyId = requireFreshKek(previous, next);
    // Pre-authenticate every original managed wrap and stage every new wrap
    // in memory before the first destination side effect. No live source I/O.
    const staged = wraps.map((wrap, index) => {
      const ref = exact[index];
      if (ref === undefined) { throw unavailable(); }
      const rewrapped = checkedWrap(rewrapPayloadKey({ ref, previous, next, wrap, source: 'managed' }));
      if (rewrapped.keyId !== newKeyId) { throw unavailable(); }
      return { ref, rewrapped };
    });
    for (const { ref, rewrapped } of staged) {
      await destination.create(ref, checkedWrap(rewrapped));
      const stored = checkedWrap(await destination.read(ref));
      if (stored.keyId !== rewrapped.keyId || !timingSafeEqual(stored.wrappedDek, rewrapped.wrappedDek)) {
        throw unavailable();
      }
    }
  } catch {
    throw unavailable();
  }
}
