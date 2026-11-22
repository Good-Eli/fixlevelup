/**
 * Internal private quarantine and lifecycle object storage (B1/B2/C).
 *
 * One-shot PUT and independent GET verification are namespace-bound. Registered
 * quarantine probes expose aggregates only; bounded byte reads require a distinct
 * opaque C grant per namespace. This module does not authorize DB transactions,
 * publish READY, delete objects, or serve an HTTP response.
 *
 * Guarantees that matter for a later coordinator:
 *
 * - one descriptor, one PUT per process, module-wide (see `attempt.ts`); a retry is
 *   a brand-new descriptor/key, never a replay of this one;
 * - a failure after the PUT started is `WRITE_OUTCOME_UNKNOWN`, never "not
 *   written", and the adapter never retries, overwrites or deletes that key;
 * - `verifyQuarantined` proves content by reading actual bytes and recomputing
 *   SHA-256; a HEAD, ETag or metadata value is never accepted as content proof;
 * - an attempt is bound, by descriptor identity, to the immutable canonical
 *   endpoint/bucket/region of its PUT; verifying it through a different target is
 *   refused before any network request (see `attempt.ts`);
 * - every failure is a value-free `PrivateStorageError`, and a caller-supplied
 *   error object (however legal-looking) is never rethrown as an internal one.
 */
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { GetObjectCommand, PutObjectCommand, S3ServiceException } from '@aws-sdk/client-s3';
import type { GetObjectCommandOutput, S3Client } from '@aws-sdk/client-s3';
import {
  assertAttemptWritable, beginAttemptWrite, markAttemptWritten, prepareQuarantineAttempt, prepareTargetBoundAttempt,
  prepareTargetBoundSanitizedAttempt, requireAttempt, requireSanitizedAttempt, requireWrittenTarget, sameTarget, storageTarget,
} from './attempt.js';
import type { QuarantineAttempt, SanitizedAttempt, StorageTarget } from './attempt.js';
import { BoundedBodyStream } from './body.js';
import type { BoundedBodyLimits } from './body.js';
import { createS3Client, validateConfig } from './config.js';
import type { PrivateQuarantineStorageConfig, ValidatedStorageConfig } from './config.js';
import { isInternalStorageError, lifecycleStorageError, privateStorageError } from './errors.js';
import type { PrivateStorageError } from './errors.js';
import { requireLifecycleGetGrant } from './lifecycle-proof.js';
import type { RawGetGrant, ReadyGetGrant } from './lifecycle-proof.js';
import { requireRegisteredQuarantineProbe } from './registered-proof.js';
import type { RegisteredQuarantineProbeProof } from './registered-proof.js';
import { bindProbeTransport, ProbeTransport } from './response-limiter.js';

/** Internal storage receipt. Not a public DTO, not a READY marker. */
export interface QuarantineReceipt {
  readonly attemptId: string;
  readonly objectKey: string;
  readonly actualBytes: number;
  readonly sha256: string;
}

/** Bounded upload input. Sizes are mandatory caller policy, never a default here. */
export interface PutQuarantinedInput {
  readonly body: AsyncIterable<Uint8Array>;
  readonly expectedBytes: number;
  readonly maxBytes: number;
  readonly signal: AbortSignal;
}

/** Bounded verification input; `sha256` is the value a previous PUT reported. */
export interface VerifyQuarantinedInput {
  readonly expectedBytes: number;
  readonly sha256: string;
  readonly maxBytes: number;
  readonly signal: AbortSignal;
}

/** The internal adapter surface. Nothing here is wired to a business path in B1. */
export interface PrivateQuarantineStorage {
  prepareQuarantineAttempt(): QuarantineAttempt;
  putQuarantined(attempt: QuarantineAttempt, input: PutQuarantinedInput): Promise<QuarantineReceipt>;
  verifyQuarantined(attempt: QuarantineAttempt, input: VerifyQuarantinedInput): Promise<QuarantineReceipt>;
  close(): Promise<void>;
}

export interface RegisteredQuarantineAttempt {
  readonly attempt: QuarantineAttempt;
  readonly target: StorageTarget;
  readonly maxChunkBytes: number;
}

export interface InspectRegisteredQuarantineInput {
  readonly maxBytes: number;
  readonly signal: AbortSignal;
}

interface ObservedObjectBytes {
  readonly actualBytes: number;
  readonly sha256: string;
}

type ObjectObservation = (ObservedObjectBytes & { readonly observation: 'PRESENT' })
  | { readonly observation: 'NOT_OBSERVED' | 'INDETERMINATE' };

export type RegisteredQuarantineObservation = ObjectObservation & { readonly transportSettled: boolean };

/** Internal storage surface for a trusted durable registry coordinator only. */
export interface RegisteredQuarantineStorage extends PrivateQuarantineStorage {
  prepareRegisteredQuarantineAttempt(): RegisteredQuarantineAttempt;
  inspectRegisteredQuarantineObject(
    proof: RegisteredQuarantineProbeProof, input: InspectRegisteredQuarantineInput,
  ): Promise<RegisteredQuarantineObservation>;
}

export interface RegisteredSanitizedAttempt {
  readonly attempt: SanitizedAttempt;
  readonly target: StorageTarget;
  readonly maxChunkBytes: number;
}

export interface LifecycleGetInput {
  readonly maxBytes: number;
  readonly signal: AbortSignal;
}

export interface ReadyReadStorage {
  fetchReadyBytes(proof: ReadyGetGrant, opts: LifecycleGetInput): Promise<Uint8Array>;
}

export interface LifecycleStorage extends ReadyReadStorage, RegisteredQuarantineStorage {
  fetchRawBytes(proof: RawGetGrant, opts: LifecycleGetInput): Promise<Uint8Array>;
  prepareSanitizedAttempt(): RegisteredSanitizedAttempt;
  putSanitized(attempt: SanitizedAttempt, input: PutQuarantinedInput): Promise<QuarantineReceipt>;
  verifySanitized(attempt: SanitizedAttempt, input: VerifyQuarantinedInput): Promise<QuarantineReceipt>;
}

const SHA256_HEX = /^[0-9a-f]{64}$/;
/** Technical cap on a single accepted SDK payload chunk, in addition to the full-copy budget. */
export const LIFECYCLE_READ_MAX_CHUNK_BYTES = 1_048_576;
/**
 * Technical cleanup bound (not policy): how long `bounded` waits for an aborted SDK
 * request to actually settle, and how long a destroyed response body may take to
 * emit `close`. It exists so cleanup never becomes an unbounded wait.
 */
const CLEANUP_SETTLE_MS = 1_000;

function invalidInput(): never {
  throw privateStorageError('INVALID_INPUT');
}

/** Allowed keys of a `putQuarantined` input; anything else is a refusal. */
const PUT_INPUT_KEYS: ReadonlySet<string> = new Set(['body', 'expectedBytes', 'maxBytes', 'signal']);
/** Allowed keys of a `verifyQuarantined` input; anything else is a refusal. */
const VERIFY_INPUT_KEYS: ReadonlySet<string> = new Set(['expectedBytes', 'sha256', 'maxBytes', 'signal']);
const INSPECT_INPUT_KEYS: ReadonlySet<string> = new Set(['maxBytes', 'signal']);

/**
 * Reads one input object as a closed snapshot of plain data properties.
 *
 * A plain cast would let an accessor or a Proxy return one value for validation and
 * another for use (a secret logged once, validated as another), so only own data
 * descriptors of an exact key set are accepted and copied exactly once. Symbols,
 * inherited/custom prototypes and extra keys are refused.
 *
 * Every reflection step (`Array.isArray`, `Object.getPrototypeOf`, `Reflect.ownKeys`,
 * `Reflect.getOwnPropertyDescriptor`) is caller-visible through a Proxy trap and can
 * throw an arbitrary value — including a caller-made `PrivateStorageError` with a
 * legal code. Nothing that escapes this function is the caller's object: only a
 * fresh fixed `INVALID_INPUT` leaves the guard.
 */
function inputSnapshot(value: unknown, allowed: ReadonlySet<string>): Map<string, unknown> {
  try {
    return readInputSnapshot(value, allowed);
  } catch {
    invalidInput();
  }
}

/** The actual reflection work of `inputSnapshot`; never called unguarded. */
function readInputSnapshot(value: unknown, allowed: ReadonlySet<string>): Map<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    invalidInput();
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    invalidInput();
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== allowed.size) {
    invalidInput();
  }
  const snapshot = new Map<string, unknown>();
  for (const key of keys) {
    if (typeof key !== 'string' || !allowed.has(key)) {
      invalidInput();
    }
    const descriptor = Reflect.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      invalidInput();
    }
    snapshot.set(key, descriptor.value);
  }
  return snapshot;
}

function positiveSize(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    invalidInput();
  }
  return value;
}

function sizes(expectedBytes: unknown, maxBytes: unknown): { expectedBytes: number; maxBytes: number } {
  const expected = positiveSize(expectedBytes);
  const max = positiveSize(maxBytes);
  if (expected > max) {
    invalidInput();
  }
  return { expectedBytes: expected, maxBytes: max };
}

/**
 * Accepts only a real `AbortSignal`. A hand-made object with a throwing `aborted`
 * getter must not be able to turn a refusal into a raw caller error, and a
 * duck-typed object is not a cancellation contract.
 *
 * The brand check is the native `aborted` getter invoked with the *candidate* as
 * receiver (`Reflect.get` on the prototype): the platform getter reads internal
 * slots, so it throws a `TypeError` for any non-signal — including a `Proxy` that
 * fakes `Object.getPrototypeOf` — while returning a real boolean (never throwing)
 * for a genuine, even already-aborted, `AbortSignal`. The `instanceof` check runs
 * inside the same guard because its `getPrototypeOf` lookup is caller-visible too.
 */
function signalOf(snapshot: Map<string, unknown>): AbortSignal {
  const signal: unknown = snapshot.get('signal');
  let aborted: unknown;
  try {
    aborted = Reflect.get(AbortSignal.prototype, 'aborted', signal);
    if (!(signal instanceof AbortSignal)) {
      invalidInput();
    }
  } catch {
    invalidInput();
  }
  if (typeof aborted !== 'boolean') {
    invalidInput();
  }
  return signal;
}

function bodyOf(snapshot: Map<string, unknown>): AsyncIterable<Uint8Array> {
  const body = snapshot.get('body');
  if (typeof body !== 'object' || body === null) {
    invalidInput();
  }
  // Reading the iterator symbol can itself invoke a caller getter or a Proxy trap, so
  // it is wrapped: a throwing source is a typed refusal, never a raw caller error.
  // The factory call (`source[Symbol.asyncIterator]()`) happens later, inside the
  // bounded stream constructor, and is isolated there (`boundedSource`).
  let iterator: unknown;
  try {
    iterator = (body as AsyncIterable<Uint8Array>)[Symbol.asyncIterator];
  } catch {
    invalidInput();
  }
  if (typeof iterator !== 'function') {
    invalidInput();
  }
  return body as AsyncIterable<Uint8Array>;
}

/**
 * Native cancellation reads, never the caller's own properties.
 *
 * `signalOf` already refuses a non-signal and a Proxy, but a *genuine* `AbortSignal`
 * can still carry own `aborted`/`addEventListener` overrides, and those are caller
 * code that can throw. The platform accessors are therefore invoked with the signal
 * as an explicit receiver, which reads the internal state and ignores own shadowing
 * properties. The methods are captured once with their real `this` type, so the
 * receiver is always the signal and never a global or a detached call.
 */
type AbortAddListener = (
  this: AbortSignal,
  type: 'abort',
  listener: () => void,
  options?: { readonly once?: boolean },
) => void;
type AbortRemoveListener = (this: AbortSignal, type: 'abort', listener: () => void) => void;

// The platform methods are intentionally detached and always invoked with an
// explicit `this` (the caller's signal), never with an implicit receiver.
// eslint-disable-next-line @typescript-eslint/unbound-method
const NATIVE_ADD_LISTENER: AbortAddListener = AbortSignal.prototype.addEventListener;
// eslint-disable-next-line @typescript-eslint/unbound-method
const NATIVE_REMOVE_LISTENER: AbortRemoveListener = AbortSignal.prototype.removeEventListener;

function signalAborted(signal: AbortSignal): boolean {
  const aborted: unknown = Reflect.get(AbortSignal.prototype, 'aborted', signal);
  return aborted === true;
}

function onAbort(signal: AbortSignal, listener: () => void): void {
  NATIVE_ADD_LISTENER.call(signal, 'abort', listener, { once: true });
}

function offAbort(signal: AbortSignal, listener: () => void): void {
  NATIVE_REMOVE_LISTENER.call(signal, 'abort', listener);
}

/** Waits for an aborted SDK request to settle, but never without a bound. */
async function settle(run: Promise<unknown>): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      run.then(() => true, () => true),
      new Promise<boolean>((resolve) => { timer = setTimeout(() => { resolve(false); }, CLEANUP_SETTLE_MS); }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/** Records the first source/body failure without exposing it outside the module. */
class FailureSlot {
  #error: PrivateStorageError | null = null;

  record(error: PrivateStorageError): void {
    this.#error ??= error;
  }

  take(): PrivateStorageError | null {
    return this.#error;
  }
}

/**
 * The single way this adapter waits for an SDK call: one whole-operation deadline
 * that also covers a response body *after* its headers, plus the caller signal.
 *
 * The losing race branch is never reported as settled unless it really settled: the
 * internal controller aborts the transport, and the aborted operation is awaited up
 * to `CLEANUP_SETTLE_MS`. If it still has not settled it is handed to `track`, so
 * `close()` keeps waiting for it instead of the adapter pretending no IO remains.
 */
async function bounded<T>(
  run: (signal: AbortSignal, abort: () => void) => Promise<T>,
  deadlineMs: number,
  caller: AbortSignal,
  shutdown: AbortSignal,
  track: (pending: Promise<unknown>) => void,
): Promise<T> {
  if (signalAborted(caller)) {
    throw privateStorageError('ABORTED', 'ABORTED');
  }
  if (signalAborted(shutdown)) {
    throw privateStorageError('CLOSED');
  }
  const controller = new AbortController();
  const relay = (): void => { controller.abort(); };
  onAbort(caller, relay);
  onAbort(shutdown, relay);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const failure = (): PrivateStorageError => {
    if (signalAborted(caller) || signalAborted(shutdown)) {
      return privateStorageError('WRITE_OUTCOME_UNKNOWN', 'ABORTED');
    }
    return privateStorageError('WRITE_OUTCOME_UNKNOWN', 'TIMEOUT');
  };
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(failure());
    }, deadlineMs);
  });
  const stopped = new Promise<never>((_resolve, reject) => {
    controller.signal.addEventListener('abort', () => { reject(failure()); }, { once: true });
  });
  const operation = (async () => run(controller.signal, () => { controller.abort(); }))();
  try {
    return await Promise.race([operation, deadline, stopped]);
  } catch (error: unknown) {
    if (!await settle(operation)) {
      track(operation);
    }
    throw error;
  } finally {
    clearTimeout(timer);
    offAbort(caller, relay);
    offAbort(shutdown, relay);
  }
}

/** Codes a failed PUT may re-emit as a fresh copy: decided by this module's own bounded operation. */
const PASSTHROUGH_CODES: ReadonlySet<string> = new Set(['WRITE_OUTCOME_UNKNOWN', 'ABORTED', 'CLOSED']);

/**
 * Translates an unexpected failure of a started PUT into the typed unknown outcome.
 *
 * Identity is never trusted: `instanceof` is worthless here, because the public error
 * class is exported and a caller can throw a legal-looking instance (with a custom
 * `message`, an extra code or a `cause`) from its own iterator factory. Only a failure
 * this module branded internally is re-emitted, and even then as a *fresh* error
 * rebuilt from the closed code/reason vocabulary — never the caller's object, its
 * message, `cause` or extra properties.
 */
function unknownOutcome(error: unknown): never {
  if (isInternalStorageError(error) && PASSTHROUGH_CODES.has(error.code)) {
    throw privateStorageError(error.code, error.reason);
  }
  throw privateStorageError('WRITE_OUTCOME_UNKNOWN', 'TRANSPORT');
}

/** Destroys an SDK response body; waits (bounded) for `close` only if it had not ended. */
async function destroyBody(body: unknown, ended: boolean): Promise<void> {
  if (typeof body !== 'object' || body === null || typeof (body as { destroy?: unknown }).destroy !== 'function') {
    return;
  }
  const stream = body as { destroy: () => void; destroyed?: boolean; closed?: boolean } & NodeJS.EventEmitter;
  if (stream.destroyed !== true) {
    stream.destroy();
  }
  // A body that ended normally is already closed; only a cut-off body needs the
  // bounded wait for its socket to be released.
  if (ended || stream.closed === true || typeof stream.once !== 'function') {
    return;
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      once(stream, 'close').then(() => undefined, () => undefined),
      new Promise<void>((resolve) => { timer = setTimeout(resolve, CLEANUP_SETTLE_MS); }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/** Reads one SDK response body into bounded chunks, counting bytes and hashing them. */
async function drainBounded(
  stream: AsyncIterable<Uint8Array>,
  maxBytes: number,
  signal: AbortSignal,
  output?: Uint8Array,
): Promise<{ actualBytes: number; sha256: string }> {
  const hash = createHash('sha256');
  let total = 0;
  const iterator = stream[Symbol.asyncIterator]();
  try {
    for (;;) {
      if (signal.aborted) {
        throw privateStorageError('READ_FAILED', 'ABORTED');
      }
      const step = await iterator.next();
      if (step.done === true) {
        break;
      }
      const chunk: unknown = step.value;
      if (!(chunk instanceof Uint8Array)) {
        throw privateStorageError('READ_FAILED', 'TRANSPORT');
      }
      const nextTotal = total + chunk.byteLength;
      if (nextTotal > maxBytes || chunk.byteLength > LIFECYCLE_READ_MAX_CHUNK_BYTES) {
        throw privateStorageError('VERIFY_MISMATCH');
      }
      // Internally owned, exactly-sized buffer, never a view of an SDK chunk.
      output?.set(chunk, total);
      hash.update(chunk);
      total = nextTotal;
    }
  } finally {
    // Close the response body iterator; the caller separately destroys the socket.
    try {
      // Read once behind the guard; the receiver is explicit on call below.
      // eslint-disable-next-line @typescript-eslint/unbound-method
      const close = iterator.return;
      if (typeof close === 'function') {
        const returned = close.call(iterator);
        void Promise.resolve(returned).catch(() => undefined);
      }
    } catch {
      // Ignored: the outcome is already decided by the caller.
    }
  }
  return { actualBytes: total, sha256: hash.digest('hex') };
}

/** Shared B1/B2 payload read; destroy directly because SDK send has already resolved. */
async function drainResponseBody(
  body: unknown, maxBytes: number, signal: AbortSignal, output?: Uint8Array,
): Promise<ObservedObjectBytes> {
  if (typeof body !== 'object' || body === null
    || typeof (body as AsyncIterable<Uint8Array>)[Symbol.asyncIterator] !== 'function') {
    await destroyBody(body, false);
    throw privateStorageError('READ_FAILED', 'TRANSPORT');
  }
  const destroyOnAbort = (): void => {
    const destroy = (body as { destroy?: unknown }).destroy;
    if (typeof destroy === 'function') {
      destroy.call(body);
    }
  };
  signal.addEventListener('abort', destroyOnAbort, { once: true });
  let ended = false;
  try {
    if (signal.aborted) {
      destroyOnAbort();
    }
    const drained = await drainBounded(body as AsyncIterable<Uint8Array>, maxBytes, signal, output);
    ended = true;
    return drained;
  } finally {
    signal.removeEventListener('abort', destroyOnAbort);
    await destroyBody(body, ended);
  }
}

function validObjectResponse(response: GetObjectCommandOutput, maxBytes: number): boolean {
  const length = response.ContentLength;
  return response.$metadata.httpStatusCode === 200
    && response.ContentRange === undefined
    && (length === undefined || (Number.isSafeInteger(length) && length >= 0 && length <= maxBytes));
}

/** Only the SDK send boundary can supply this status; no exception data is returned. */
function notObserved(error: unknown): boolean {
  return error instanceof S3ServiceException && error.$metadata.httpStatusCode === 404;
}

/**
 * Builds the bounded upload stream. Its constructor invokes the caller's iterator
 * factory (`source[Symbol.asyncIterator]()`), which is caller code: it can throw any
 * value, including a caller-made `PrivateStorageError` with a legal-looking code and
 * a custom message. The factory call is therefore isolated here and translated into
 * this module's own fixed post-start failure — the PUT has already begun (the
 * descriptor is consumed and bound), so the only honest outcome is
 * `WRITE_OUTCOME_UNKNOWN` / `SOURCE_FAILED`, never the caller's object.
 */
function boundedSource(
  source: AsyncIterable<Uint8Array>,
  limits: BoundedBodyLimits,
  onFailure: (error: PrivateStorageError) => void,
  transport?: ProbeTransport,
): BoundedBodyStream {
  try {
    return new BoundedBodyStream(source, limits, onFailure,
      transport === undefined ? undefined : (pending) => { transport.track(pending); });
  } catch {
    throw privateStorageError('WRITE_OUTCOME_UNKNOWN', 'SOURCE_FAILED');
  }
}

class S3QuarantineStorage implements LifecycleStorage {
  readonly #config: ValidatedStorageConfig;
  readonly #client: S3Client;
  /**
   * The immutable canonical target this instance talks to: exactly the endpoint,
   * bucket and region of the validated config, copied once and frozen. Credentials
   * are intentionally absent, so rotating a secret over the same physical target
   * never changes an attempt's binding.
   */
  readonly #target: StorageTarget;
  readonly #active = new Set<Promise<unknown>>();
  readonly #inFlight = new Set<Promise<unknown>>();
  readonly #shutdown = new AbortController();
  #closed = false;
  #closing: Promise<void> | null = null;

  constructor(config: ValidatedStorageConfig) {
    this.#config = config;
    this.#target = storageTarget(config.endpoint, config.bucket, config.region);
    this.#client = createS3Client(config);
  }

  prepareQuarantineAttempt(): QuarantineAttempt {
    this.#assertOpen();
    return prepareQuarantineAttempt();
  }

  prepareRegisteredQuarantineAttempt(): RegisteredQuarantineAttempt {
    this.#assertOpen();
    return Object.freeze({
      attempt: prepareTargetBoundAttempt(this.#target),
      target: this.#target,
      maxChunkBytes: this.#config.maxChunkBytes,
    });
  }

  prepareSanitizedAttempt(): RegisteredSanitizedAttempt {
    this.#assertOpen();
    return Object.freeze({
      attempt: prepareTargetBoundSanitizedAttempt(this.#target),
      target: this.#target,
      maxChunkBytes: this.#config.maxChunkBytes,
    });
  }

  async putSanitized(attempt: SanitizedAttempt, input: PutQuarantinedInput): Promise<QuarantineReceipt> {
    return await this.#trackedLifecycle(async (transport) => {
      this.#assertOpen();
      const descriptor = requireSanitizedAttempt(attempt);
      const fields = inputSnapshot(input, PUT_INPUT_KEYS);
      const limits = sizes(fields.get('expectedBytes'), fields.get('maxBytes'));
      const signal = signalOf(fields);
      const body = bodyOf(fields);
      if (signalAborted(signal)) {
        throw privateStorageError('ABORTED', 'ABORTED');
      }
      assertAttemptWritable(descriptor, this.#target);
      this.#assertCapacity();
      return await this.#track(this.#put(descriptor, body, limits, signal, transport));
    });
  }

  async verifySanitized(attempt: SanitizedAttempt, input: VerifyQuarantinedInput): Promise<QuarantineReceipt> {
    return await this.#trackedLifecycle(async (transport) => {
      this.#assertOpen();
      const descriptor = requireSanitizedAttempt(attempt);
      const fields = inputSnapshot(input, VERIFY_INPUT_KEYS);
      const limits = sizes(fields.get('expectedBytes'), fields.get('maxBytes'));
      const expectedSha = fields.get('sha256');
      if (typeof expectedSha !== 'string' || expectedSha.length !== 64 || !SHA256_HEX.test(expectedSha)) {
        invalidInput();
      }
      const signal = signalOf(fields);
      if (signalAborted(signal)) {
        throw privateStorageError('ABORTED', 'ABORTED');
      }
      requireWrittenTarget(descriptor, this.#target);
      this.#assertCapacity();
      const actual = await this.#track(this.#getExact(descriptor.objectKey, limits.expectedBytes, expectedSha, signal, transport));
      return Object.freeze({ attemptId: descriptor.attemptId, objectKey: descriptor.objectKey, ...actual });
    }, true);
  }

  fetchRawBytes(proof: RawGetGrant, opts: LifecycleGetInput): Promise<Uint8Array> {
    return this.#fetchLifecycleBytes(proof, 'RAW', opts);
  }

  fetchReadyBytes(proof: ReadyGetGrant, opts: LifecycleGetInput): Promise<Uint8Array> {
    return this.#fetchLifecycleBytes(proof, 'READY', opts);
  }

  async #fetchLifecycleBytes(
    proof: RawGetGrant | ReadyGetGrant, kind: 'RAW' | 'READY', opts: LifecycleGetInput,
  ): Promise<Uint8Array> {
    return await this.#trackedLifecycle(async (transport) => {
      this.#assertOpen();
      const facts = requireLifecycleGetGrant(proof, kind);
      if (!sameTarget(facts.target, this.#target)) {
        throw privateStorageError('ATTEMPT_TARGET_MISMATCH');
      }
      const fields = inputSnapshot(opts, INSPECT_INPUT_KEYS);
      const { expectedBytes } = sizes(facts.expectedBytes, fields.get('maxBytes'));
      const signal = signalOf(fields);
      if (signalAborted(signal)) {
        throw privateStorageError('ABORTED', 'ABORTED');
      }
      this.#assertCapacity();
      // An independent ArrayBuffer the exact size of the trusted row: no Buffer
      // pool, excess capacity, or second full-sized staging copy on this path.
      const payload = new Uint8Array(expectedBytes);
      await this.#track(this.#getExact(facts.objectKey, expectedBytes, facts.expectedSha256, signal, transport, payload));
      return payload;
    }, true);
  }

  async #trackedLifecycle<T>(run: (transport: ProbeTransport) => Promise<T>, getOnly = false): Promise<T> {
    const transport = new ProbeTransport(getOnly);
    try {
      return await run(transport);
    } catch (error: unknown) {
      if (isInternalStorageError(error)) {
        if (getOnly && error.code === 'WRITE_OUTCOME_UNKNOWN') {
          throw lifecycleStorageError('READ_FAILED', error.reason ?? 'TRANSPORT', transport.settled);
        }
        throw lifecycleStorageError(error.code, error.reason, transport.settled);
      }
      throw lifecycleStorageError(getOnly ? 'READ_FAILED' : 'WRITE_OUTCOME_UNKNOWN', 'TRANSPORT', transport.settled);
    }
  }

  async inspectRegisteredQuarantineObject(
    proof: RegisteredQuarantineProbeProof, input: InspectRegisteredQuarantineInput,
  ): Promise<RegisteredQuarantineObservation> {
    this.#assertOpen();
    const grant = requireRegisteredQuarantineProbe(proof);
    if (!sameTarget(grant.target, this.#target)) {
      throw privateStorageError('ATTEMPT_TARGET_MISMATCH');
    }
    const fields = inputSnapshot(input, INSPECT_INPUT_KEYS);
    const maxBytes = positiveSize(fields.get('maxBytes'));
    const signal = signalOf(fields);
    if (signalAborted(signal)) {
      // No SDK operation was started, hence no local probe debt.
      return Object.freeze({ observation: 'INDETERMINATE', transportSettled: true });
    }
    this.#assertCapacity();
    return await this.#track(this.#inspect(grant.objectKey, maxBytes, signal));
  }

  async putQuarantined(attempt: QuarantineAttempt, input: PutQuarantinedInput): Promise<QuarantineReceipt> {
    this.#assertOpen();
    const descriptor = requireAttempt(attempt);
    const fields = inputSnapshot(input, PUT_INPUT_KEYS);
    const limits = sizes(fields.get('expectedBytes'), fields.get('maxBytes'));
    const signal = signalOf(fields);
    const body = bodyOf(fields);
    if (signalAborted(signal)) {
      throw privateStorageError('ABORTED', 'ABORTED');
    }
    // A spent descriptor can never be retargeted; a descriptor bound to another
    // endpoint/bucket/region is refused before the capacity check and before any IO.
    assertAttemptWritable(descriptor, this.#target);
    this.#assertCapacity();
    return await this.#track(this.#put(descriptor, body, limits, signal));
  }

  async verifyQuarantined(attempt: QuarantineAttempt, input: VerifyQuarantinedInput): Promise<QuarantineReceipt> {
    this.#assertOpen();
    const descriptor = requireAttempt(attempt);
    const fields = inputSnapshot(input, VERIFY_INPUT_KEYS);
    const limits = sizes(fields.get('expectedBytes'), fields.get('maxBytes'));
    const expectedSha = fields.get('sha256');
    if (typeof expectedSha !== 'string' || !SHA256_HEX.test(expectedSha)) {
      invalidInput();
    }
    const signal = signalOf(fields);
    if (signalAborted(signal)) {
      throw privateStorageError('ABORTED', 'ABORTED');
    }
    // Written receipt and target are proven before the capacity check and before any
    // network: a verify through a different endpoint/bucket/region never dials.
    requireWrittenTarget(descriptor, this.#target);
    this.#assertCapacity();
    return await this.#track(this.#verify(descriptor, limits, expectedSha, signal));
  }

  /** Idempotent shutdown: abort in-flight work, then destroy the client, then wait. */
  close(): Promise<void> {
    this.#closed = true;
    this.#closing ??= this.#shutdownNow();
    return this.#closing;
  }

  async #shutdownNow(): Promise<void> {
    const pending = [...this.#active];
    // Abort before destroying: an aborted request destroys its socket, and a
    // destroyed client cannot be asked to cancel an in-flight response body.
    this.#shutdown.abort();
    this.#client.destroy();
    await Promise.allSettled(pending);
    // Transport work that outlived its operation deadline is still tracked here, so
    // shutdown waits for it too rather than leaving detached IO behind.
    await Promise.allSettled([...this.#inFlight]);
  }

  /** Keeps an out-of-deadline transport operation visible to `close()`. */
  #trackInFlight(operation: Promise<unknown>): void {
    this.#inFlight.add(operation);
    const settle = (): void => { this.#inFlight.delete(operation); };
    operation.then(settle, settle);
  }

  #assertOpen(): void {
    if (this.#closed) {
      throw privateStorageError('CLOSED');
    }
  }

  /**
   * Fails fast when the operation budget is exhausted. Transport work that outlived
   * its deadline is still counted: otherwise repeated unknown outcomes could each
   * leak an un-settled request while every new call passed the check.
   */
  #assertCapacity(): void {
    if (this.#active.size + this.#inFlight.size >= this.#config.maxConcurrentOperations) {
      throw privateStorageError('CONCURRENCY_LIMIT');
    }
  }

  /** Tracks one operation so `close()` can wait for it instead of detaching it. */
  #track<T>(operation: Promise<T>): Promise<T> {
    this.#active.add(operation);
    const settle = (): void => { this.#active.delete(operation); };
    operation.then(settle, settle);
    return operation;
  }

  async #put(
    descriptor: QuarantineAttempt | SanitizedAttempt,
    body: AsyncIterable<Uint8Array>,
    limits: { expectedBytes: number; maxBytes: number },
    signal: AbortSignal,
    transport?: ProbeTransport,
  ): Promise<QuarantineReceipt> {
    // Binding + consumption happen before the first byte leaves the process: the
    // attempt is tied to this immutable target, and a second descriptor use (from any
    // adapter in the process) can never overwrite, re-send or retarget it.
    beginAttemptWrite(descriptor, this.#target);
    // The source failure is recorded from the stream callback while the PUT is in
    // flight, and it must also abort that PUT immediately.
    const failure = new FailureSlot();
    try {
      const run = async (operationSignal: AbortSignal, abort: () => void): Promise<ObservedObjectBytes> => {
        const stream = boundedSource(
          body,
          { ...limits, maxChunkBytes: this.#config.maxChunkBytes },
          (error) => {
            failure.record(error);
            // Destroying the source alone would leave the SDK waiting for the
            // declared Content-Length until its own timeout: abort it now.
            abort();
          },
          transport,
        );
        const stopSource = (): void => { stream.destroy(); };
        operationSignal.addEventListener('abort', stopSource, { once: true });
        try {
          if (operationSignal.aborted) {
            throw privateStorageError('WRITE_OUTCOME_UNKNOWN', 'ABORTED');
          }
          await this.#client.send(new PutObjectCommand({
            Bucket: this.#target.bucket,
            Key: descriptor.objectKey,
            Body: stream,
            ContentLength: limits.expectedBytes,
          }), { abortSignal: operationSignal });
        } finally {
          operationSignal.removeEventListener('abort', stopSource);
          stream.destroy();
        }
        // Only a source that fully ended has a byte count and a digest.
        return stream.outcome();
      };
      const outcome = transport === undefined
        ? await bounded(run, this.#config.operationTimeoutMs, signal, this.#shutdown.signal,
          (pending) => { this.#trackInFlight(pending); })
        : await this.#boundedLifecycle(run, signal, transport);
      // The success receipt target is the exact target of this successful PUT; a
      // verify through any other endpoint/bucket/region is refused later, before IO.
      markAttemptWritten(descriptor, this.#target);
      return Object.freeze({
        attemptId: descriptor.attemptId,
        objectKey: descriptor.objectKey,
        actualBytes: outcome.actualBytes,
        sha256: outcome.sha256,
      });
    } catch (error: unknown) {
      const recorded = failure.take();
      if (recorded !== null) {
        // The bounded source generates only fixed SOURCE_* diagnostics. Rebuild
        // so the lifecycle wrapper can preserve the reason without passing an object.
        throw privateStorageError(recorded.code, recorded.reason);
      }
      unknownOutcome(error);
    }
  }

  async #boundedLifecycle<T>(
    run: (signal: AbortSignal, abort: () => void) => Promise<T>, signal: AbortSignal, transport: ProbeTransport,
  ): Promise<T> {
    const result = await bounded(async (operationSignal, abort) => {
      bindProbeTransport(operationSignal, transport);
      try {
        // Defer caller iterator setup until the adapter has registered #active.
        // If a source re-enters close()/another operation, its own slot is visible.
        await Promise.resolve();
        if (operationSignal.aborted) {
          throw privateStorageError('WRITE_OUTCOME_UNKNOWN', 'ABORTED');
        }
        return await run(operationSignal, abort);
      } finally {
        await transport.wait();
      }
    }, this.#config.operationTimeoutMs, signal, this.#shutdown.signal, (pending) => {
      transport.markUncertain();
      this.#trackInFlight(pending);
    });
    if (!transport.settled || !transport.fullResponse) {
      throw privateStorageError(transport.fullObjectOnly ? 'READ_FAILED' : 'WRITE_OUTCOME_UNKNOWN', 'TRANSPORT');
    }
    if (signalAborted(signal) || signalAborted(this.#shutdown.signal)) {
      throw privateStorageError(transport.fullObjectOnly ? 'READ_FAILED' : 'WRITE_OUTCOME_UNKNOWN', 'ABORTED');
    }
    return result;
  }

  async #getExact(
    key: string, expectedBytes: number, expectedSha: string, signal: AbortSignal, transport: ProbeTransport, output?: Uint8Array,
  ): Promise<ObservedObjectBytes> {
    return await this.#boundedLifecycle(async (operationSignal) => {
      const response = await this.#client.send(new GetObjectCommand({
        Bucket: this.#target.bucket,
        Key: key,
      }), { abortSignal: operationSignal });
      if (!validObjectResponse(response, expectedBytes)
        || (response.ContentLength !== undefined && response.ContentLength !== expectedBytes)) {
        await destroyBody(response.Body, false);
        throw privateStorageError('VERIFY_MISMATCH');
      }
      const actual = await drainResponseBody(response.Body, expectedBytes, operationSignal, output);
      if (actual.actualBytes !== expectedBytes || actual.sha256 !== expectedSha) {
        throw privateStorageError('VERIFY_MISMATCH');
      }
      return actual;
    }, signal, transport);
  }

  async #inspect(key: string, maxBytes: number, signal: AbortSignal): Promise<RegisteredQuarantineObservation> {
    const transport = new ProbeTransport();
    let object: ObjectObservation;
    try {
      object = await bounded(async (operationSignal) => {
        bindProbeTransport(operationSignal, transport);
        try {
          return await this.#observeObject(key, maxBytes, operationSignal, transport);
        } finally {
          // Wait on real SDK handler and raw-body cleanup. The outer deadline is
          // still bounded, and will count this task as in-flight if it lingers.
          await transport.wait();
        }
      }, this.#config.operationTimeoutMs, signal, this.#shutdown.signal,
      (pending) => {
        transport.markUncertain();
        this.#trackInFlight(pending);
      });
    } catch {
      object = { observation: 'INDETERMINATE' };
    }
    return Object.freeze({ ...object, transportSettled: transport.settled });
  }

  async #observeObject(
    key: string, maxBytes: number, signal: AbortSignal, transport: ProbeTransport,
  ): Promise<ObjectObservation> {
    let response: GetObjectCommandOutput;
    try {
      response = await this.#client.send(new GetObjectCommand({
        Bucket: this.#target.bucket,
        Key: key,
      }), { abortSignal: signal });
    } catch (error: unknown) {
      if (notObserved(error) && transport.fullResponse) {
        return { observation: 'NOT_OBSERVED' };
      }
      return { observation: 'INDETERMINATE' };
    }
    if (!validObjectResponse(response, maxBytes)) {
      await destroyBody(response.Body, false);
      return { observation: 'INDETERMINATE' };
    }
    const actual = await drainResponseBody(response.Body, maxBytes, signal);
    if (!transport.fullResponse || (response.ContentLength !== undefined && response.ContentLength !== actual.actualBytes)) {
      return { observation: 'INDETERMINATE' };
    }
    return { observation: 'PRESENT', ...actual };
  }

  async #verify(
    descriptor: QuarantineAttempt,
    limits: { expectedBytes: number; maxBytes: number },
    expectedSha: string,
    signal: AbortSignal,
  ): Promise<QuarantineReceipt> {
    try {
      const actual = await bounded(async (operationSignal) => {
        const response = await this.#client.send(new GetObjectCommand({
          Bucket: this.#target.bucket,
          Key: descriptor.objectKey,
        }), { abortSignal: operationSignal });
        // Hashing a matching body is not proof of the whole object: reject range
        // responses just as the operator probe does, before accepting any bytes.
        if (!validObjectResponse(response, limits.maxBytes)) {
          await destroyBody(response.Body, false);
          throw privateStorageError('VERIFY_MISMATCH');
        }
        const drained = await drainResponseBody(response.Body, limits.maxBytes, operationSignal);
        if (response.ContentLength !== undefined && response.ContentLength !== drained.actualBytes) {
          throw privateStorageError('VERIFY_MISMATCH');
        }
        return drained;
      }, this.#config.operationTimeoutMs, signal, this.#shutdown.signal,
      (pending) => { this.#trackInFlight(pending); });
      if (actual.actualBytes !== limits.expectedBytes || actual.sha256 !== expectedSha) {
        throw privateStorageError('VERIFY_MISMATCH');
      }
      return Object.freeze({
        attemptId: descriptor.attemptId,
        objectKey: descriptor.objectKey,
        actualBytes: actual.actualBytes,
        sha256: actual.sha256,
      });
    } catch (error: unknown) {
      // Only a failure this module branded internally is interpreted; anything else —
      // including a caller-made `PrivateStorageError` — becomes a fresh fixed read
      // failure, so no caller code/message/`cause` can escape.
      if (isInternalStorageError(error)) {
        // A write-shaped timeout/abort while only reading is a read failure.
        if (error.code === 'WRITE_OUTCOME_UNKNOWN') {
          throw privateStorageError('READ_FAILED', error.reason ?? 'TRANSPORT');
        }
        throw error;
      }
      throw privateStorageError('READ_FAILED', 'TRANSPORT');
    }
  }
}

/**
 * Creates the adapter. Synchronous and IO-free: it validates and freezes a copy of
 * the config and constructs the SDK client; nothing is dialled until the first
 * `putQuarantined`/`verifyQuarantined`.
 */
export function createPrivateQuarantineStorage(config: PrivateQuarantineStorageConfig): LifecycleStorage {
  return new S3QuarantineStorage(validateConfig(config));
}
