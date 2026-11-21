/**
 * P03-04B slice B1: typed, value-free failures of the private quarantine adapter.
 *
 * A storage failure must never carry an object key, a URL, a credential, an ETag
 * or raw SDK text: `message` is exactly the code, `reason` is one of the fixed
 * internal constants below. There is no `cause` chain, because a cause is the
 * easiest way to smuggle an SDK error into a log or an HTTP response later.
 *
 * Trust boundary: the class is exported (it is the frozen vocabulary and the type
 * every refusal has), but an error *made by a caller* — including one that copies a
 * legal-looking code — is not this module's failure and is never passed through.
 * Only instances created by the module-private `privateStorageError` factory below
 * are branded in a module-wide `WeakSet`; the public constructor deliberately adds
 * no brand, so a caller cannot brand itself by constructing an instance.
 */

/** Every refusal this internal adapter can produce. */
export const PRIVATE_STORAGE_ERROR_CODES = [
  'INVALID_CONFIG',
  'PRODUCTION_DISABLED',
  'INVALID_INPUT',
  'CLOSED',
  'ATTEMPT_INVALID',
  'ATTEMPT_CONSUMED',
  'ATTEMPT_TARGET_MISMATCH',
  'ATTEMPT_NOT_WRITTEN',
  'CONCURRENCY_LIMIT',
  'ABORTED',
  'WRITE_OUTCOME_UNKNOWN',
  'VERIFY_MISMATCH',
  'READ_FAILED',
] as const;
export type PrivateStorageErrorCode = (typeof PRIVATE_STORAGE_ERROR_CODES)[number];

/**
 * A coarse, value-free cause. Only two of them describe the *caller* (ABORTED,
 * TIMEOUT); the SOURCE_* ones describe a broken upload source, and TRANSPORT is a
 * failure whose actual cause is deliberately not exposed.
 */
export const PRIVATE_STORAGE_FAILURE_REASONS = [
  'ABORTED',
  'TIMEOUT',
  'TRANSPORT',
  'SOURCE_INVALID_CHUNK',
  'SOURCE_CHUNK_TOO_LARGE',
  'SOURCE_TOO_MANY_BYTES',
  'SOURCE_TOO_FEW_BYTES',
  'SOURCE_FAILED',
] as const;
export type PrivateStorageFailureReason = (typeof PRIVATE_STORAGE_FAILURE_REASONS)[number];

/**
 * The one error type of this module. It is deliberately not a subclass of any SDK
 * error and never wraps one.
 */
export class PrivateStorageError extends Error {
  readonly code: PrivateStorageErrorCode;
  readonly reason?: PrivateStorageFailureReason;

  constructor(code: PrivateStorageErrorCode, reason?: PrivateStorageFailureReason) {
    super(code);
    this.name = 'PrivateStorageError';
    this.code = code;
    if (reason !== undefined) {
      this.reason = reason;
    }
  }
}

/**
 * Brand of the errors this module itself created. The brand is applied *after*
 * construction by the factory below, never by the constructor: a caller can call
 * `new PrivateStorageError(...)` with any legal code, and that instance is still
 * untrusted and will not be passed through as an internal failure.
 */
const INTERNAL = new WeakSet<object>();

/** @internal Creates one trusted failure of this module. */
export function privateStorageError(
  code: PrivateStorageErrorCode,
  reason?: PrivateStorageFailureReason,
): PrivateStorageError {
  const error = new PrivateStorageError(code, reason);
  INTERNAL.add(error);
  return error;
}

/** @internal Whether the value is a failure this module itself created. */
export function isInternalStorageError(value: unknown): value is PrivateStorageError {
  return typeof value === 'object' && value !== null && INTERNAL.has(value);
}
