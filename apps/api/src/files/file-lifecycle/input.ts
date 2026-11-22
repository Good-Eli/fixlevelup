import { types } from 'node:util';
import { fileSessionProof, uuidValue } from '../reservations/index.js';
import { uploadOperationalPolicy } from '../upload-coordinator/input.js';
import type { FFile, FileProcessingPolicy, ImageMime, ProcessingContext, RuntimeEpoch } from './contract.js';
import { refuseLifecycle } from './errors.js';
import { isImageMime } from './publication.js';

export const PG_INTEGER_MAX = 2_147_483_647;
export const MAX_PG_BIGINT = 9_223_372_036_854_775_807n;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_BUFFER_BYTES = 67_108_864; // technical ceiling, not a default file policy

export function ownFields<K extends string>(value: unknown, keys: readonly K[]): Record<K, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    refuseLifecycle('INVALID_INPUT');
  }
  const proto: unknown = Object.getPrototypeOf(value);
  if ((proto !== Object.prototype && proto !== null) || Reflect.ownKeys(value).length !== keys.length) {
    refuseLifecycle('INVALID_INPUT');
  }
  const out = Object.create(null) as Record<K, unknown>;
  for (const key of keys) {
    const field = Reflect.getOwnPropertyDescriptor(value, key);
    if (field === undefined || !('value' in field)) {
      refuseLifecycle('INVALID_INPUT');
    }
    out[key] = field.value;
  }
  return out;
}

export function canonicalUuid(value: unknown): string {
  if (typeof value !== 'string' || !UUID.test(value) || uuidValue(value) !== value) {
    refuseLifecycle('INVALID_INPUT');
  }
  return value;
}

export function positive(value: unknown, max: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > max) {
    refuseLifecycle('INVALID_INPUT');
  }
  return value;
}

export function snapshotDate(value: unknown): Date {
  // Intrinsic read safely refuses fake/proxied Date objects and ignores overrides.
  const time = Date.prototype.getTime.call(value);
  const date = new Date(time);
  if (!Number.isFinite(time) || date.getUTCFullYear() < 1 || date.getUTCFullYear() > 9999) {
    refuseLifecycle('INVALID_INPUT');
  }
  return date;
}

export function nativeSignal(value: unknown): AbortSignal {
  if (types.isProxy(value) || !(value instanceof AbortSignal) || Object.getPrototypeOf(value) !== AbortSignal.prototype
    || typeof Reflect.get(AbortSignal.prototype, 'aborted', value) !== 'boolean') {
    refuseLifecycle('INVALID_INPUT');
  }
  return value;
}

export function snapshotEpoch(input: unknown): RuntimeEpoch {
  const { namespace, epoch } = ownFields(input, ['namespace', 'epoch']);
  if (typeof epoch !== 'bigint' || epoch < 1n || epoch > MAX_PG_BIGINT) {
    refuseLifecycle('INVALID_INPUT');
  }
  return Object.freeze({ namespace: canonicalUuid(namespace), epoch });
}

function sessionProof(value: unknown): FFile['session'] {
  const session = ownFields(value, ['sessionId', 'token']);
  canonicalUuid(session.sessionId);
  return Object.freeze(fileSessionProof(session));
}

export function parseFileCommand(input: unknown, withSignal: true): FFile & { readonly signal: AbortSignal };
export function parseFileCommand(input: unknown, withSignal: false): FFile;
export function parseFileCommand(input: unknown, withSignal: boolean): FFile & { readonly signal?: AbortSignal } {
  try {
    if (withSignal) {
      const { session, intentId, signal } = ownFields(input, ['session', 'intentId', 'signal']);
      return Object.freeze({ session: sessionProof(session), intentId: canonicalUuid(intentId), signal: nativeSignal(signal) });
    }
    const { session, intentId } = ownFields(input, ['session', 'intentId']);
    return Object.freeze({ session: sessionProof(session), intentId: canonicalUuid(intentId) });
  } catch {
    refuseLifecycle('INVALID_INPUT');
  }
}

function imageMimes(input: unknown): readonly ImageMime[] {
  if (!Array.isArray(input) || Object.getPrototypeOf(input) !== Array.prototype) {
    refuseLifecycle('INVALID_INPUT');
  }
  const length = positive(Reflect.getOwnPropertyDescriptor(input, 'length')?.value, 3);
  if (Reflect.ownKeys(input).length !== length + 1) {
    refuseLifecycle('INVALID_INPUT');
  }
  const result = new Set<ImageMime>();
  for (let i = 0; i < length; i += 1) {
    const value: unknown = Reflect.getOwnPropertyDescriptor(input, String(i))?.value;
    if (!isImageMime(value) || result.has(value)) {
      refuseLifecycle('INVALID_INPUT');
    }
    result.add(value);
  }
  return Object.freeze([...result].sort());
}

function processingPolicy(input: unknown): FileProcessingPolicy {
  const fields = ownFields(input, ['mode', 'versionId', 'expiresAt', 'allowedMimeTypes', 'maxRawBytes', 'maxOutputBytes',
    'maxWidth', 'maxHeight', 'maxPixels', 'maxChannels', 'leaseMs', 'wallMs', 'maxDefsAgeMs']);
  if (fields.mode !== 'local-synthetic') {
    refuseLifecycle('NOT_CONFIGURED');
  }
  const leaseMs = positive(fields.leaseMs, PG_INTEGER_MAX);
  return Object.freeze({
    mode: fields.mode, versionId: canonicalUuid(fields.versionId), expiresAt: snapshotDate(fields.expiresAt),
    allowedMimeTypes: imageMimes(fields.allowedMimeTypes), maxRawBytes: positive(fields.maxRawBytes, MAX_BUFFER_BYTES),
    maxOutputBytes: positive(fields.maxOutputBytes, MAX_BUFFER_BYTES), maxWidth: positive(fields.maxWidth, PG_INTEGER_MAX),
    maxHeight: positive(fields.maxHeight, PG_INTEGER_MAX), maxPixels: positive(fields.maxPixels, Number.MAX_SAFE_INTEGER),
    maxChannels: positive(fields.maxChannels, 4), leaseMs, wallMs: positive(fields.wallMs, leaseMs - 1),
    maxDefsAgeMs: positive(fields.maxDefsAgeMs, PG_INTEGER_MAX),
  });
}

/** Snapshot all mutable values before the first wait. Ports themselves are trusted wiring, never F input. */
export function snapshotProcessingContext(input: ProcessingContext): ProcessingContext {
  try {
    const fields = ownFields(input, ['pool', 'epoch', 'storage', 'processor', 'uploadPolicy', 'policy']);
    const policy = processingPolicy(fields.policy);
    const uploadPolicy = uploadOperationalPolicy(fields.uploadPolicy);
    const { pool, storage, processor } = fields as unknown as Partial<Pick<ProcessingContext, 'pool' | 'storage' | 'processor'>>;
    if (typeof pool?.connect !== 'function' || typeof storage?.fetchRawBytes !== 'function'
      || typeof storage.prepareSanitizedAttempt !== 'function' || typeof storage.putSanitized !== 'function'
      || typeof storage.verifySanitized !== 'function' || typeof processor?.process !== 'function'
      || typeof processor.isEvidenceCurrent !== 'function' || policy.maxOutputBytes > uploadPolicy.maxPhysicalBytesPerOwner
      || policy.maxRawBytes > uploadPolicy.maxPhysicalBytesPerOwner
      || !policy.allowedMimeTypes.every((mime) => uploadPolicy.allowedMimeTypes.includes(mime))) {
      refuseLifecycle('NOT_CONFIGURED');
    }
    return Object.freeze({ pool, storage, processor, uploadPolicy, policy, epoch: snapshotEpoch(fields.epoch) });
  } catch {
    refuseLifecycle('NOT_CONFIGURED');
  }
}
