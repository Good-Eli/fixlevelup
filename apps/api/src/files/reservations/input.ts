/**
 * Bounded runtime validation for the file-upload reservation ports.
 *
 * "Internal" is not a licence to trust a shape: every value that could come from
 * a caller is re-narrowed here, unknown keys are rejected, and every string,
 * identifier, quantity and timestamp has a hard bound. Database CHECK/trigger
 * rules remain authoritative for cross-row rules (live anchor, exact GIVEN, quota,
 * immutability); this file only keeps malformed input out of SQL and out of logs.
 *
 * ## The policy is configuration, not request input
 *
 * `policy` is a mandatory closed typed object from trusted reviewed configuration
 * and is validated by the port itself, so a caller cannot "forget" to parse it and
 * cannot invent a default. Any problem with the policy snapshot — absent, not an
 * object, an unknown key, an empty/duplicate/unknown MIME allowlist, a
 * non-positive or unsafe quota, `maxFileBytes > maxOwnerBytes`, a bad version id
 * or source reference, an unparsable expiry — is `NOT_CONFIGURED`, raised before
 * any database access and therefore before any intent/audit/outbox insert.
 *
 * ## Failures never echo submitted values
 *
 * Every refusal is a bare `FileReservationError(<code>)` whose message is the
 * code, so a validation failure cannot leak a token, a source reference or a
 * legal basis into a log or response.
 */
import { FileReservationError } from './contract.js';
import type { FileMimeType, FileOwnerSessionProof } from './contract.js';
import { FILE_MIME_TYPES } from './contract.js';
import { filePolicySha256 } from './hash.js';

/** Hard bounds the schema itself cannot express. */
export const MAX_SOURCE_REF = 500;
export const MAX_TOKEN = 512;
export const MIN_TOKEN = 16;
/**
 * `max_owner_files` and `expected_version` are PostgreSQL `integer` columns, so a
 * JavaScript safe integer is not enough: anything above 2147483647 would be
 * accepted here and then refused by the database as an overflow.
 */
export const MAX_PG_INTEGER = 2_147_483_647;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TOKEN = /^[A-Za-z0-9_-]{16,512}$/;
const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/;

const POLICY_KEYS = [
  'versionId', 'sourceRef', 'allowedMimeTypes', 'maxFileBytes', 'maxOwnerBytes', 'maxOwnerFiles', 'expiresAt',
] as const;
const RESERVE_KEYS = ['session', 'staffId', 'policy', 'declaredMime', 'declaredBytes', 'expiresAt', 'idempotencyKey'] as const;
const READ_KEYS = ['session', 'intentId'] as const;
const CANCEL_KEYS = ['session', 'intentId', 'expectedVersion'] as const;

function invalid(): never {
  throw new FileReservationError('INVALID_INPUT');
}

function notConfigured(): never {
  throw new FileReservationError('NOT_CONFIGURED');
}

/**
 * Narrows one plain input record.
 *
 * Only an ordinary (or null-prototype) object is accepted: a class instance, an
 * array, a `Map`, a function or an object with a custom prototype is refused, so a
 * caller cannot smuggle behaviour through the prototype chain. Every own key —
 * including symbols and non-enumerable keys — must be in the closed allowlist and
 * must be a plain *data* property: an accessor could execute caller code during
 * validation or return a different value on the second read. `Object.keys` alone
 * would miss both, which is why the descriptor walk is the primitive here.
 */
function record(value: unknown, allowed: readonly string[], fail: () => never): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    fail();
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail();
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key === 'symbol' || !allowed.includes(key)) {
      fail();
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      fail();
    }
  }
  return value as Record<string, unknown>;
}

function object(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  return record(value, allowed, invalid);
}

/** A malformed *policy* snapshot is a configuration failure, not a request error. */
function recordWithPolicyFailure(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  return record(value, allowed, notConfigured);
}

/** Closed MIME vocabulary check; no coercion, no case folding, no wildcard. */
export function isFileMimeType(value: string): value is FileMimeType {
  return (FILE_MIME_TYPES as readonly string[]).includes(value);
}

export function mimeValue(value: unknown): FileMimeType {
  if (typeof value !== 'string' || !isFileMimeType(value)) {
    invalid();
  }
  return value;
}

export function uuidValue(value: unknown): string {
  if (typeof value !== 'string' || !UUID.test(value)) {
    invalid();
  }
  return value.toLowerCase();
}

function positiveSafeInteger(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    invalid();
  }
  return value;
}

/** Positive integer that must also fit the PostgreSQL `integer` range. */
function positivePgInteger(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > MAX_PG_INTEGER) {
    invalid();
  }
  return value;
}

/** Intrinsic read: an own `getTime` override on a Date subclass cannot lie. */
function timeOf(date: Date): number {
  return Date.prototype.getTime.call(date);
}

/**
 * Accepts a `Date` or a bounded ISO-8601 string and returns a *fresh* `Date`.
 *
 * A caller-supplied `Date` is a mutable object: the caller (or any library holding
 * the same reference) can call `setTime` on it at any moment, including after this
 * parser has returned. This module awaits between parsing and the policy hash /
 * idempotency hash / INSERT, so a snapshot that still aliased the caller's instance
 * could be hashed at one instant and inserted at another — and a later replay would
 * then disagree with the stored row. The copy is therefore taken synchronously,
 * before the first await, so every downstream read of `expiresAt` is independent of
 * the caller. `Date.prototype.getTime.call` is used so a subclass override cannot
 * substitute a different number during the copy; a string is parsed by the built-in
 * parser into a fresh instance.
 *
 * Date validity and the accepted input shapes are unchanged: `Date` (including a
 * subclass) or the bounded ISO-8601 string, and an invalid instant is still
 * refused by the caller of this helper.
 */
function timestampValue(value: unknown): Date | null {
  const date = value instanceof Date
    ? new Date(timeOf(value))
    : typeof value === 'string' && ISO_TIMESTAMP.test(value)
      ? new Date(value)
      : null;
  if (date === null || Number.isNaN(timeOf(date))) {
    return null;
  }
  return date;
}

function requiredTimestamp(value: unknown): Date {
  const date = timestampValue(value);
  if (date === null) {
    invalid();
  }
  return date;
}

function policyPositiveInteger(record: Record<string, unknown>, key: string): number {
  const value = record[key];
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    notConfigured();
  }
  return value;
}

/** A quota that is also a PostgreSQL `integer` column value. */
function policyPgInteger(record: Record<string, unknown>, key: string): number {
  const value = record[key];
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > MAX_PG_INTEGER) {
    notConfigured();
  }
  return value;
}

/** Raw pre-submit session proof. A trusted-capability proof has no token and is refused. */
export interface ParsedFileSessionProof {
  readonly sessionId: string;
  readonly token: string;
}

export function fileSessionProof(value: unknown): FileOwnerSessionProof {
  const record = object(value, ['sessionId', 'token']);
  const token = record['token'];
  if (typeof token !== 'string' || !TOKEN.test(token)) {
    invalid();
  }
  return { sessionId: uuidValue(record['sessionId']), token };
}

/** Normalised, hashable policy snapshot. */
export interface ParsedFilePolicy {
  readonly versionId: string;
  readonly sourceRef: string;
  readonly allowedMimeTypes: readonly FileMimeType[];
  readonly maxFileBytes: number;
  readonly maxOwnerBytes: number;
  readonly maxOwnerFiles: number;
  readonly expiresAt: Date;
  /** Canonical SHA-256 of the snapshot fields above. */
  readonly sha256: string;
}

/**
 * Validates the trusted policy snapshot. Every refusal is `NOT_CONFIGURED`: the
 * policy is reviewed configuration, so an unusable snapshot is a configuration
 * failure, never something the caller can fix by changing a request value.
 */
export function fileReservationPolicy(value: unknown): ParsedFilePolicy {
  const record = recordWithPolicyFailure(value, POLICY_KEYS);

  const versionId = record['versionId'];
  if (typeof versionId !== 'string' || !UUID.test(versionId)) {
    notConfigured();
  }
  const sourceRef = record['sourceRef'];
  if (typeof sourceRef !== 'string' || sourceRef.length === 0 || sourceRef.length > MAX_SOURCE_REF || !/\S/.test(sourceRef)) {
    notConfigured();
  }

  const rawMimeTypes = record['allowedMimeTypes'];
  if (!Array.isArray(rawMimeTypes) || rawMimeTypes.length === 0 || rawMimeTypes.length > FILE_MIME_TYPES.length) {
    notConfigured();
  }
  const allowedMimeTypes: FileMimeType[] = [];
  for (const entry of rawMimeTypes) {
    if (typeof entry !== 'string' || !isFileMimeType(entry) || allowedMimeTypes.includes(entry)) {
      notConfigured();
    }
    allowedMimeTypes.push(entry);
  }
  // Sorted once so the canonical hash and the stored jsonb snapshot are stable.
  allowedMimeTypes.sort();

  const maxFileBytes = policyPositiveInteger(record, 'maxFileBytes');
  const maxOwnerBytes = policyPositiveInteger(record, 'maxOwnerBytes');
  // `max_owner_files` is a PostgreSQL integer column: cap it at the DB range here so
  // an oversized reviewed value is a configuration failure, not a late 22003.
  const maxOwnerFiles = policyPgInteger(record, 'maxOwnerFiles');
  if (maxFileBytes > maxOwnerBytes) {
    notConfigured();
  }

  const expiresAt = timestampValue(record['expiresAt']);
  if (expiresAt === null) {
    notConfigured();
  }
  // `timestampValue` already returned a private copy, taken synchronously before
  // any await, so this snapshot cannot be changed by the caller afterwards. The
  // hash and the INSERT both read exactly this instance.
  const policyExpiresAt = expiresAt;

  const sha256 = filePolicySha256({
    versionId: versionId.toLowerCase(),
    sourceRef,
    allowedMimeTypes,
    maxFileBytes,
    maxOwnerBytes,
    maxOwnerFiles,
    policyExpiresAt: policyExpiresAt.toISOString(),
  });
  return {
    versionId: versionId.toLowerCase(), sourceRef, allowedMimeTypes, maxFileBytes, maxOwnerBytes, maxOwnerFiles,
    expiresAt: policyExpiresAt, sha256,
  };
}

export interface ParsedReserveFileUpload {
  readonly session: FileOwnerSessionProof;
  readonly policy: ParsedFilePolicy;
  readonly declaredMime: FileMimeType;
  readonly declaredBytes: number;
  readonly expiresAt: Date;
  readonly idempotencyKey: string;
}

/**
 * Parses a reserve request. The staff variant is recognised only in order to be
 * refused `UNSUPPORTED_OWNER`: the check runs before the policy and before any
 * database access, so a staff id from a request body can never become authority
 * even when the rest of the payload is valid or the policy is missing.
 */
export function reserveFileUploadInput(value: unknown): ParsedReserveFileUpload {
  const record = object(value, RESERVE_KEYS);
  if (Object.hasOwn(record, 'staffId')) {
    throw new FileReservationError('UNSUPPORTED_OWNER');
  }
  const session = fileSessionProof(record['session']);
  const policy = fileReservationPolicy(record['policy']);
  const declaredMime = mimeValue(record['declaredMime']);
  if (!policy.allowedMimeTypes.includes(declaredMime)) {
    invalid();
  }
  const declaredBytes = positiveSafeInteger(record['declaredBytes']);
  if (declaredBytes > policy.maxFileBytes) {
    invalid();
  }
  const expiresAt = requiredTimestamp(record['expiresAt']);
  if (timeOf(expiresAt) > timeOf(policy.expiresAt)) {
    invalid();
  }
  // Both dates above are private copies of the caller's values, so the idempotency
  // hash and the INSERT read the same instants the caller submitted even if the
  // caller mutates its own Date objects while the port is waiting on a lock.
  const requestedExpiresAt = expiresAt;
  const idempotencyKey = uuidValue(record['idempotencyKey']);
  return { session, policy, declaredMime, declaredBytes, expiresAt: requestedExpiresAt, idempotencyKey };
}

export interface ParsedReadFileUploadIntent {
  readonly session: FileOwnerSessionProof;
  readonly intentId: string;
}

export function readFileUploadIntentInput(value: unknown): ParsedReadFileUploadIntent {
  const record = object(value, READ_KEYS);
  return { session: fileSessionProof(record['session']), intentId: uuidValue(record['intentId']) };
}

export interface ParsedCancelFileUploadIntent {
  readonly session: FileOwnerSessionProof;
  readonly intentId: string;
  readonly expectedVersion: number;
}

export function cancelFileUploadIntentInput(value: unknown): ParsedCancelFileUploadIntent {
  const record = object(value, CANCEL_KEYS);
  return {
    session: fileSessionProof(record['session']),
    intentId: uuidValue(record['intentId']),
    // `row_version` is a PostgreSQL integer; a safe integer above its range would be
    // a caller bug that can never match a stored version, so it is refused here.
    expectedVersion: positivePgInteger(record['expectedVersion']),
  };
}
