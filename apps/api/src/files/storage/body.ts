/**
 * Bounded upload source: the only path from a caller `AsyncIterable<Uint8Array>`
 * to the S3 request body.
 *
 * Guarantees:
 *
 * - every chunk is copied *before* it is counted, hashed and pushed, so a caller
 *   mutating or reusing its buffer after `next()` cannot change the bytes that are
 *   hashed or sent;
 * - a chunk larger than `maxChunkBytes` and a non-byte chunk are refused, and the
 *   running total may never exceed `expectedBytes`/`maxBytes`, so a hostile or
 *   broken source cannot make the adapter buffer unbounded data;
 * - the stream ends successfully only when exactly `expectedBytes` were sent, so
 *   an undersized source fails instead of producing a short object;
 * - Node backpressure is respected through the Readable high-water mark, which is
 *   set to one maximum chunk: the adapter never holds the whole body in memory.
 *
 * Cancellation contract (documented, not enforceable): the adapter stops pulling,
 * destroys the socket and calls `iterator.return()` when present, but it cannot
 * cancel an arbitrary caller promise. A source that ignores the abort signal and
 * never resolves its own `next()` is caller code; the adapter never awaits such a
 * promise forever and never claims it was cancelled.
 */
import { createHash } from 'node:crypto';
import { Readable } from 'node:stream';
import { PrivateStorageError } from './errors.js';
import type { PrivateStorageFailureReason } from './errors.js';

export interface BoundedBodyLimits {
  readonly expectedBytes: number;
  readonly maxBytes: number;
  readonly maxChunkBytes: number;
}

export interface BoundedBodyOutcome {
  readonly actualBytes: number;
  readonly sha256: string;
}

type FailureSink = (failure: PrivateStorageError) => void;

/**
 * Technical yield interval (not a policy number): after this many pulls the stream
 * hands the event loop one macrotask, so timers and abort listeners can run even if
 * the source resolves every `next()` immediately.
 */
const PULL_YIELD_INTERVAL = 16;

export class BoundedBodyStream extends Readable {
  readonly #limits: BoundedBodyLimits;
  readonly #onFailure: FailureSink;
  readonly #hash = createHash('sha256');
  #iterator: AsyncIterator<Uint8Array> | null;
  #pulling = false;
  #finished = false;
  #bytes = 0;
  #iterations = 0;
  #outcome: BoundedBodyOutcome | null = null;

  constructor(source: AsyncIterable<Uint8Array>, limits: BoundedBodyLimits, onFailure: FailureSink) {
    super({ highWaterMark: limits.maxChunkBytes, objectMode: false });
    this.#limits = limits;
    this.#onFailure = onFailure;
    this.#iterator = source[Symbol.asyncIterator]();
  }

  /** The verified byte count and SHA-256 of the bytes actually sent. */
  outcome(): BoundedBodyOutcome {
    if (this.#outcome === null) {
      throw new PrivateStorageError('WRITE_OUTCOME_UNKNOWN');
    }
    return this.#outcome;
  }

  override _read(): void {
    void this.#pull();
  }

  override _destroy(error: Error | null, callback: (error: Error | null) => void): void {
    this.#release();
    callback(error);
  }

  async #pull(): Promise<void> {
    if (this.#pulling || this.#stopped()) {
      return;
    }
    this.#pulling = true;
    try {
      for (;;) {
        // Cooperative event-loop yield: a source that resolves `next()` immediately
        // (e.g. an endless run of zero-byte chunks) would otherwise starve the
        // operation-deadline timer and the abort signal on the microtask queue.
        if (this.#iterations >= PULL_YIELD_INTERVAL) {
          this.#iterations = 0;
          await new Promise<void>((resolve) => { setImmediate(resolve); });
          if (this.#stopped()) {
            this.#release();
            return;
          }
        }
        this.#iterations += 1;
        const iterator = this.#iterator;
        if (iterator === null) {
          return;
        }
        const step = await iterator.next();
        if (this.#stopped()) {
          this.#release();
          return;
        }
        if (step.done === true) {
          this.#complete();
          return;
        }
        const chunk: unknown = step.value;
        if (!(chunk instanceof Uint8Array)) {
          this.#fail('SOURCE_INVALID_CHUNK');
          return;
        }
        // A zero-byte chunk carries no data; it is skipped and counted towards the
        // yield interval so an endless stream of them cannot block the timer.
        if (chunk.byteLength === 0) {
          continue;
        }
        if (chunk.byteLength > this.#limits.maxChunkBytes) {
          this.#fail('SOURCE_CHUNK_TOO_LARGE');
          return;
        }
        const copy = new Uint8Array(chunk);
        this.#bytes += copy.byteLength;
        if (this.#bytes > this.#limits.expectedBytes || this.#bytes > this.#limits.maxBytes) {
          this.#fail('SOURCE_TOO_MANY_BYTES');
          return;
        }
        this.#hash.update(copy);
        if (!this.push(copy)) {
          return;
        }
      }
    } catch {
      this.#fail('SOURCE_FAILED');
    } finally {
      this.#pulling = false;
    }
  }

  /** Stops pulling as soon as the consumer or the outcome decided the fate. */
  #stopped(): boolean {
    return this.#finished || this.destroyed;
  }

  #complete(): void {
    if (this.#bytes !== this.#limits.expectedBytes) {
      this.#fail('SOURCE_TOO_FEW_BYTES');
      return;
    }
    this.#finished = true;
    this.#release();
    this.#outcome = Object.freeze({ actualBytes: this.#bytes, sha256: this.#hash.digest('hex') });
    this.push(null);
  }

  #fail(reason: PrivateStorageFailureReason): void {
    if (this.#finished || this.destroyed) {
      return;
    }
    this.#finished = true;
    this.destroy();
    this.#onFailure(new PrivateStorageError('WRITE_OUTCOME_UNKNOWN', reason));
  }

  /** Calls the source's `return()` without awaiting an uncooperative iterator. */
  #release(): void {
    const iterator = this.#iterator;
    this.#iterator = null;
    if (iterator === null) {
      return;
    }
    try {
      // Reading `return` is caller code too: it may be a throwing getter. Read it
      // exactly once inside the guard, and preserve the iterator as its receiver.
      // eslint-disable-next-line @typescript-eslint/unbound-method -- captured once; called below with its original receiver
      const cleanup = iterator.return;
      if (typeof cleanup === 'function') {
        const returned = cleanup.call(iterator);
        void Promise.resolve(returned).catch(() => undefined);
      }
    } catch {
      // Optional cleanup cannot suppress EOF, escape _destroy(), or replace an
      // already-decided outcome with caller-controlled data.
    }
  }
}
