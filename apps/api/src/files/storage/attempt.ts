/**
 * One-shot opaque quarantine attempt descriptors.
 *
 * The descriptor is a server-generated object, never a serialized shape: identity
 * lives in a module-wide `WeakSet`, so a plain `{attemptId, objectKey}` object
 * copied out of JSON, a spread copy, a subclass or a structurally equal object is
 * refused. The object is frozen, the key is `quarantine/<uuid>/<uuid>` with no
 * file name and no client value, and a new attempt always gets a new key.
 *
 * Consumption is module-wide on purpose: the same descriptor used through a second
 * adapter instance in this process must still be refused. That is an in-process
 * one-shot guard, *not* durable fencing — after a restart the future B2 coordinator
 * must register a brand-new attempt/key instead of replaying this descriptor.
 *
 * Target binding (MUST1 after ASTRA): the single PUT also binds the descriptor, by
 * object identity, to the immutable canonical storage target it began against —
 * exactly `endpoint` + `bucket` + `region` from the validated config. Credentials
 * are deliberately *not* part of the target: rotating a secret over the same
 * physical target must not invalidate an attempt. The binding and the written
 * receipt target live in module-wide `WeakMap`s, so a verify through a different
 * target is refused *before* any network request, and a second PUT can never
 * switch the target of an attempt that was already spent.
 */
import { randomUUID } from 'node:crypto';
import { privateStorageError } from './errors.js';

declare const SANITIZED_KIND: unique symbol;

/** Existing raw shape, excluding the new sanitized type without requiring any new field. */
export interface QuarantineAttempt {
  readonly [SANITIZED_KIND]?: never;
  readonly attemptId: string;
  readonly objectKey: string;
}

/**
 * The immutable canonical target an attempt is bound to. Only the three storage
 * location primitives belong here; no credential, URL path, query or header.
 */
export interface StorageTarget {
  readonly endpoint: string;
  readonly bucket: string;
  readonly region: string;
}

/** Separate compile-time and process-local namespaces; never accepted by raw PUT/verify. */
export interface SanitizedAttempt {
  readonly [SANITIZED_KIND]: true;
  readonly attemptId: string;
  readonly objectKey: string;
}

const IDENTITIES = new WeakSet<object>();
const SANITIZED_IDENTITIES = new WeakSet<object>();
const CONSUMED = new WeakSet<object>();
/** Descriptor identity -> the target its one PUT began against (module-wide). */
const BOUND = new WeakMap<object, StorageTarget>();
/** Descriptor identity -> the target of the successful bounded PUT (module-wide). */
const WRITTEN = new WeakMap<object, StorageTarget>();

class QuarantineAttemptDescriptor implements QuarantineAttempt {
  readonly attemptId: string;
  readonly objectKey: string;

  constructor() {
    this.attemptId = randomUUID();
    // The first namespace segment *is* the attempt id, so the key is derivable
    // from the descriptor without a second source of truth.
    this.objectKey = `quarantine/${this.attemptId}/${randomUUID()}`;
    Object.freeze(this);
  }
}

/** Creates one fresh descriptor. No IO, no config, no database registration. */
export function prepareQuarantineAttempt(): QuarantineAttempt {
  const descriptor = new QuarantineAttemptDescriptor();
  IDENTITIES.add(descriptor);
  return descriptor;
}

/** Proves the value is one of our live descriptors; otherwise `ATTEMPT_INVALID`. */
export function requireAttempt(value: unknown): QuarantineAttempt {
  if (typeof value !== 'object' || value === null || !IDENTITIES.has(value)) {
    throw privateStorageError('ATTEMPT_INVALID');
  }
  return value as QuarantineAttempt;
}

/**
 * Builds the frozen canonical target copy the adapter keeps for its whole life.
 * Only the three location primitives are read, exactly once, and the copy is
 * immutable, so no later config mutation can retarget a live client.
 */
export function storageTarget(endpoint: string, bucket: string, region: string): StorageTarget {
  return Object.freeze({ endpoint, bucket, region });
}

export function sameTarget(a: StorageTarget, b: StorageTarget): boolean {
  return a.endpoint === b.endpoint && a.bucket === b.bucket && a.region === b.region;
}

/** New B2 descriptor, bound before registration, but still unspent and unwritten. */
export function prepareTargetBoundAttempt(target: StorageTarget): QuarantineAttempt {
  const descriptor = prepareQuarantineAttempt();
  BOUND.set(descriptor, target);
  return descriptor;
}

/** New C descriptor, independently branded and bound before DB registration. */
export function prepareTargetBoundSanitizedAttempt(target: StorageTarget): SanitizedAttempt {
  const attemptId = randomUUID();
  const descriptor = Object.freeze({ attemptId, objectKey: `sanitized/${attemptId}/${randomUUID()}` }) as SanitizedAttempt;
  SANITIZED_IDENTITIES.add(descriptor);
  BOUND.set(descriptor, target);
  return descriptor;
}

/** A raw descriptor, clone or Proxy is not a sanitized attempt. */
export function requireSanitizedAttempt(value: unknown): SanitizedAttempt {
  if (typeof value !== 'object' || value === null || !SANITIZED_IDENTITIES.has(value)) {
    throw privateStorageError('ATTEMPT_INVALID');
  }
  return value as SanitizedAttempt;
}

/**
 * Pre-flight refusal for a PUT, without consuming anything: a spent descriptor is
 * `ATTEMPT_CONSUMED` (checked first, so an already-spent attempt can never be
 * "retargeted"), and a descriptor bound to another target is
 * `ATTEMPT_TARGET_MISMATCH`.
 */
export function assertAttemptWritable(value: object, target: StorageTarget): void {
  if (CONSUMED.has(value)) {
    throw privateStorageError('ATTEMPT_CONSUMED');
  }
  const bound = BOUND.get(value);
  if (bound !== undefined && !sameTarget(bound, target)) {
    throw privateStorageError('ATTEMPT_TARGET_MISMATCH');
  }
}

/**
 * Marks the descriptor's single PUT as started against `target`; a second call is
 * `ATTEMPT_CONSUMED`. Called before the first byte leaves the process.
 */
export function beginAttemptWrite(value: object, target: StorageTarget): void {
  assertAttemptWritable(value, target);
  BOUND.set(value, target);
  CONSUMED.add(value);
}

/** Records the exact target of the successful bounded PUT of this descriptor. */
export function markAttemptWritten(value: object, target: StorageTarget): void {
  WRITTEN.set(value, target);
}

/**
 * Proves a descriptor completed a PUT against *this* target, before any network
 * request: `ATTEMPT_NOT_WRITTEN` when no successful PUT happened, and
 * `ATTEMPT_TARGET_MISMATCH` when the written receipt belongs to another
 * endpoint/bucket/region. The same physical target (even with different
 * credentials) is accepted.
 */
export function requireWrittenTarget(value: object, target: StorageTarget): void {
  const written = WRITTEN.get(value);
  if (written === undefined) {
    throw privateStorageError('ATTEMPT_NOT_WRITTEN');
  }
  if (!sameTarget(written, target)) {
    throw privateStorageError('ATTEMPT_TARGET_MISMATCH');
  }
}
