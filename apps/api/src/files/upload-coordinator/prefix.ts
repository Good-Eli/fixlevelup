import type { FileMimeType } from '../reservations/index.js';
import { refuse } from './contract.js';
import type { UploadReservedFileCommand } from './contract.js';
import { assertNotAborted, deadline, signalAborted } from './input.js';

interface Signature {
  readonly length: number;
  readonly markers: readonly { readonly offset: number; readonly bytes: Uint8Array }[];
}

const SIGNATURES: Readonly<Record<FileMimeType, Signature>> = {
  'image/jpeg': { length: 3, markers: [{ offset: 0, bytes: Uint8Array.of(0xff, 0xd8, 0xff) }] },
  'image/png': { length: 8, markers: [{ offset: 0, bytes: Uint8Array.of(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a) }] },
  'image/webp': { length: 12, markers: [
    { offset: 0, bytes: Buffer.from('RIFF', 'ascii') }, { offset: 8, bytes: Buffer.from('WEBP', 'ascii') },
  ] },
  'application/pdf': { length: 5, markers: [{ offset: 0, bytes: Buffer.from('%PDF-', 'ascii') }] },
};

interface Source {
  read(signal: AbortSignal): Promise<Uint8Array | null>;
  close(): void;
}

/** Read exactly one cooperative step; an abandoned promise always has a rejection handler. */
async function awaitStep(run: () => Promise<IteratorResult<Uint8Array>>, signal: AbortSignal): Promise<IteratorResult<Uint8Array>> {
  assertNotAborted(signal);
  let stop = (): void => undefined;
  const aborted = new Promise<null>((resolve) => {
    stop = (): void => { resolve(null); };
    AbortSignal.prototype.addEventListener.call(signal, 'abort', stop, { once: true });
  });
  try {
    let step: IteratorResult<Uint8Array> | null;
    try {
      step = await Promise.race([run(), aborted]);
    } catch {
      refuse('SOURCE_FAILED');
    }
    assertNotAborted(signal);
    if (step === null) {
      refuse('ABORTED');
    }
    return step;
  } finally {
    AbortSignal.prototype.removeEventListener.call(signal, 'abort', stop);
  }
}

function openSource(factory: UploadReservedFileCommand['body'], operation: AbortSignal, maxChunk: number, size: number): Source {
  assertNotAborted(operation);
  let iterator: AsyncIterator<Uint8Array> | undefined;
  let next: AsyncIterator<Uint8Array>['next'];
  let closed = false;
  let total = 0;
  const close = (): void => {
    if (closed) {
      return;
    }
    closed = true;
    try {
      // Capture the optional getter once, inside the protected boundary (B1 ASTRA).
      // eslint-disable-next-line @typescript-eslint/unbound-method -- call below binds the original iterator
      const cleanup = iterator?.return;
      if (typeof cleanup === 'function') {
        void Promise.resolve(cleanup.call(iterator)).catch(() => undefined);
      }
    } catch {
      // Optional cleanup cannot suppress success, leak a caller error, or hang us.
    }
  };
  try {
    const iterable = factory(operation);
    iterator = iterable[Symbol.asyncIterator]();
    // eslint-disable-next-line @typescript-eslint/unbound-method -- called later with the original iterator
    next = iterator.next;
    if (typeof next !== 'function') {
      refuse('SOURCE_FAILED');
    }
  } catch {
    // The iterator may already own resources even if reading `next` fails.
    close();
    refuse('SOURCE_FAILED');
  }
  return {
    async read(signal) {
      if (closed) {
        return null;
      }
      const step = await awaitStep(() => next.call(iterator), signal);
      try {
        if (step.done === true) {
          close();
          return null;
        }
        const chunk: unknown = step.value;
        if (!(chunk instanceof Uint8Array)) {
          refuse('SOURCE_FAILED');
        }
        // Read the intrinsic view length before allocating; a subclass cannot spoof a small size.
        const length: unknown = Reflect.get(Object.getPrototypeOf(Uint8Array.prototype) as object, 'byteLength', chunk);
        if (typeof length !== 'number' || length > maxChunk || length > size - total) {
          refuse('SOURCE_FAILED');
        }
        const copy = new Uint8Array(chunk);
        total += copy.byteLength;
        if (copy.byteLength !== length) {
          refuse('SOURCE_FAILED');
        }
        return copy;
      } catch {
        refuse('SOURCE_FAILED');
      }
    },
    close,
  };
}

/** Signature only, not decoding, scanning or a safety decision. */
export async function prepareUploadBody(
  factory: UploadReservedFileCommand['body'], operation: AbortSignal, mime: FileMimeType,
  expectedBytes: number, maxChunk: number, prefixTimeoutMs: number,
): Promise<{ readonly body: AsyncIterable<Uint8Array>; close: () => void }> {
  const signature = SIGNATURES[mime];
  if (expectedBytes < signature.length) {
    refuse('SIGNATURE_MISMATCH');
  }
  const prefix = new Uint8Array(signature.length);
  const prefixDeadline = deadline(operation, prefixTimeoutMs);
  let source: Source | undefined;
  try {
    source = openSource(factory, operation, maxChunk, expectedBytes);
    const opened = source;
    let offset = 0;
    let remainder: Uint8Array | undefined;
    for (let pulls = 0; offset < prefix.length; pulls += 1) {
      if (pulls % 16 === 15) {
        await new Promise<void>((resolve) => { setImmediate(resolve); });
      }
      const chunk = await opened.read(prefixDeadline.signal);
      if (chunk === null) {
        refuse('SIGNATURE_MISMATCH');
      }
      const used = Math.min(chunk.byteLength, prefix.length - offset);
      prefix.set(chunk.subarray(0, used), offset);
      offset += used;
      if (used < chunk.byteLength) {
        remainder = chunk.subarray(used);
      }
    }
    if (!signature.markers.every((marker) => marker.bytes.every((byte, index) => prefix[marker.offset + index] === byte))) {
      refuse('SIGNATURE_MISMATCH');
    }
    const body = (async function* () {
      try {
        // Tiny configured chunk sizes are valid; do not send a combined oversized prefix.
        for (let start = 0; start < prefix.length; start += maxChunk) {
          assertNotAborted(operation);
          yield prefix.subarray(start, start + maxChunk);
        }
        if (remainder !== undefined) {
          assertNotAborted(operation);
          const rest = remainder;
          remainder = undefined;
          yield rest;
        }
        for (;;) {
          const chunk = await opened.read(operation);
          if (chunk === null) {
            break;
          }
          yield chunk;
        }
      } finally {
        opened.close();
      }
    })();
    return { body, close: () => { opened.close(); } };
  } catch (error) {
    source?.close();
    if (signalAborted(prefixDeadline.signal)) {
      refuse('ABORTED');
    }
    throw error;
  } finally {
    prefixDeadline.close();
  }
}
