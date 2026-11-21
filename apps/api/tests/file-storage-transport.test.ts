/**
 * Real loopback transport proofs for the P03-04B **B1** private quarantine adapter.
 *
 * These are not mocks: the adapter dials a real ephemeral `127.0.0.1` HTTP server
 * (the approved `local-synthetic` target), so the assertions cover actual sockets,
 * actual Node HTTP timing and the adapter's own bounded settle. Each fixture is
 * closed at the end of its test; no server outlives the suite.
 *
 * What is proved, and why each case matters:
 *
 * - a connection refused *before* any request was sent is a typed failure, not a
 *   success and not a silent hang;
 * - a server that accepts the connection and never sends response headers settles
 *   within the explicit technical bound (no infinite wait);
 * - a GET response body that starts after headers and then stalls settles too, i.e.
 *   the operation deadline covers a body read after its headers, which
 *   `requestTimeout` alone would not;
 * - a socket destroyed after the request bytes arrived yields
 *   `WRITE_OUTCOME_UNKNOWN` — the object may exist, so the adapter must never claim
 *   "not written" and never retry the old key;
 * - a source that ends short (`too few`) or long (`too many`) bytes, yields a
 *   non-byte chunk, yields an oversized chunk, or throws, is reported as
 *   `WRITE_OUTCOME_UNKNOWN` with the matching internal reason (the PUT had already
 *   started, so no "not written" claim is allowed);
 * - a caller abort during the PUT aborts the stream/socket and settles as
 *   `WRITE_OUTCOME_UNKNOWN`; a source that ignores the signal is not awaited
 *   forever, because the adapter guarantees a bounded settle for the *transport*,
 *   not for caller code;
 * - no socket leaks, no unhandled rejection and no credential/URL/key in any error.
 *
 * Explicit technical parameters only: timeouts and byte ceilings are test values,
 * never business defaults.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import * as storage from '../src/files/storage/index.js';
import {
  LOOPBACK_TIMEOUTS, assertSafeFailure, asyncChunks, bounded, chunked, errorText, loopback, loopbackBehaviour,
  loopbackConfig, loopbackObjectStore, objectPath, oversizedChunkedResponse, refusedEndpoint, settle, sha256Hex,
  sleep, stallingBody, storageCode, syntheticCredentials, syntheticPayload, throwingBody, waitUntil,
  watchUnhandledRejections,
} from './file-storage-fixture.js';
import type { LoopbackFixture, LoopbackHandler, Settled } from './file-storage-fixture.js';

type Adapter = ReturnType<typeof storage.createPrivateQuarantineStorage>;

/** Frozen typed vocabulary (adapter contract, P03-04B B1). */
const UNKNOWN = 'WRITE_OUTCOME_UNKNOWN';
const READ_FAILED = 'READ_FAILED';

function reason(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) {
    return undefined;
  }
  const value: unknown = (error as { reason?: unknown }).reason;
  return typeof value === 'string' ? value : undefined;
}

const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    await cleanup?.();
  }
});

function track<T extends { close(): Promise<void> }>(fixture: T): T {
  cleanups.push(async () => { await fixture.close(); });
  return fixture;
}

function createAdapter(endpoint: string, overrides: Parameters<typeof loopbackConfig>[1] = {}): Adapter {
  const adapter = storage.createPrivateQuarantineStorage(loopbackConfig(endpoint, overrides));
  cleanups.push(async () => { await adapter.close(); });
  return adapter;
}

/** Watchdog for a whole loopback call: the adapter deadline plus a technical margin. */
const WATCHDOG_MS = LOOPBACK_TIMEOUTS.operationTimeoutMs + 3_000;

/**
 * Asserts a typed post-start failure: the code must be `WRITE_OUTCOME_UNKNOWN`
 * (never a "not written" claim), the reason must be one of the frozen constants,
 * and the error must not leak a credential, endpoint or key.
 */
async function expectUnknown(
  action: () => Promise<unknown>,
  fixture: LoopbackFixture,
  config: { accessKeyId: string; secretAccessKey: string },
  expectedReasons: readonly string[],
  objectKey?: string,
): Promise<void> {
  const settled = await settle(action());
  expect(settled.ok).toBe(false);
  if (settled.ok) {
    throw new Error('Expected a typed UNKNOWN outcome, received a success receipt.');
  }
  expect(storageCode(settled.error)).toBe(UNKNOWN);
  expect(expectedReasons).toContain(reason(settled.error));
  assertSafeFailure(
    settled.error,
    [config.accessKeyId, config.secretAccessKey, fixture.endpoint],
    objectKey === undefined ? [] : [objectKey],
  );
}

/** Accepts a PUT with 200 and answers a GET with headers + one byte, then stalls. */
function acceptPutStallGet(request: IncomingMessage, response: ServerResponse): void {
  request.resume();
  request.on('end', () => {
    if ((request.method ?? '') === 'PUT') {
      response.writeHead(200, { ETag: '"synthetic-loopback"', 'Content-Type': 'application/xml' });
      response.end();
      return;
    }
    response.writeHead(200, { 'Content-Length': '64', 'Content-Type': 'application/octet-stream' });
    response.write('x');
    // No end(): the GET body stalls after its headers on purpose.
  });
}

describe('private quarantine storage: loopback transport', () => {
  it('fails closed when the connection is refused before any request is sent', async () => {
    const endpoint = await refusedEndpoint();
    const config = loopbackConfig(endpoint);
    const adapter = createAdapter(endpoint);
    const attempt = adapter.prepareQuarantineAttempt();
    const payload = syntheticPayload(2_048, 'refused');
    const settled = await settle(bounded(adapter.putQuarantined(attempt, {
      body: asyncChunks([payload]),
      expectedBytes: payload.byteLength,
      maxBytes: payload.byteLength,
      signal: new AbortController().signal,
    }), WATCHDOG_MS, 'refused PUT'));
    expect(settled.ok).toBe(false);
    if (settled.ok) {
      return;
    }
    // A refused dial is reported as an UNKNOWN write outcome: the adapter does not
    // pretend it can prove the object was not written.
    expect(storageCode(settled.error)).toBe(UNKNOWN);
    expect(['TRANSPORT', 'TIMEOUT']).toContain(reason(settled.error));
    assertSafeFailure(settled.error, [config.accessKeyId, config.secretAccessKey, endpoint, attempt.objectKey]);
  });

  it('settles when the server accepts the connection but never sends headers', async () => {
    const fixture = track(await loopback(loopbackBehaviour.stallHeaders));
    const config = loopbackConfig(fixture.endpoint);
    const adapter = createAdapter(fixture.endpoint);
    const attempt = adapter.prepareQuarantineAttempt();
    const payload = syntheticPayload(1_024, 'stall-headers');
    const started = performance.now();
    await expectUnknown(
      () => bounded(adapter.putQuarantined(attempt, {
        body: asyncChunks([payload]),
        expectedBytes: payload.byteLength, maxBytes: payload.byteLength,
        signal: new AbortController().signal,
      }), WATCHDOG_MS, 'stall-headers PUT'),
      fixture, config, ['TIMEOUT', 'TRANSPORT'], attempt.objectKey,
    );
    // Bounded: the explicit technical deadline, not an infinite wait.
    expect(performance.now() - started).toBeLessThan(WATCHDOG_MS);
    // The adapter really did dial (this is a real transport test, not a mock).
    expect(fixture.requests.length).toBeGreaterThan(0);
    // Closing the adapter must release the transport instead of leaking a socket.
    await adapter.close();
    await fixture.waitForSocketsClosed(3_000);
    expect(fixture.sockets.size).toBe(0);
  });

  it('settles when a GET response body stalls after its headers', async () => {
    const fixture = track(await loopback(acceptPutStallGet));
    const config = loopbackConfig(fixture.endpoint);
    const adapter = createAdapter(fixture.endpoint);
    const payload = syntheticPayload(4_096, 'stall-body');
    const attempt = adapter.prepareQuarantineAttempt();
    const put = await bounded(adapter.putQuarantined(attempt, {
      body: asyncChunks([payload]),
      expectedBytes: payload.byteLength, maxBytes: payload.byteLength, signal: new AbortController().signal,
    }), WATCHDOG_MS, 'stall-body PUT');
    expect(put.actualBytes).toBe(payload.byteLength);

    // The same descriptor now verifies: the server answers headers, sends one byte
    // and stalls. The operation deadline must cover this body read.
    const started = performance.now();
    const settled = await settle(bounded(adapter.verifyQuarantined(attempt, {
      expectedBytes: payload.byteLength, sha256: put.sha256, maxBytes: payload.byteLength,
      signal: new AbortController().signal,
    }), WATCHDOG_MS, 'stall-body verify'));
    expect(settled.ok).toBe(false);
    if (!settled.ok) {
      // A verify read failure is READ_FAILED (not an UNKNOWN write), bounded.
      expect(storageCode(settled.error)).toBe(READ_FAILED);
      expect(['TIMEOUT', 'TRANSPORT', 'ABORTED']).toContain(reason(settled.error));
      assertSafeFailure(settled.error, [config.accessKeyId, config.secretAccessKey], [fixture.endpoint, attempt.objectKey]);
    }
    expect(performance.now() - started).toBeLessThan(WATCHDOG_MS);
    await adapter.close();
    await fixture.waitForSocketsClosed(3_000);
  });

  it('reports an UNKNOWN outcome when the socket dies after the request bytes were sent', async () => {
    const fixture = track(await loopback(loopbackBehaviour.resetAfterBody));
    const config = loopbackConfig(fixture.endpoint);
    const adapter = createAdapter(fixture.endpoint);
    const attempt = adapter.prepareQuarantineAttempt();
    const payload = syntheticPayload(8 * 1_024, 'reset-after-body');
    await expectUnknown(
      () => bounded(adapter.putQuarantined(attempt, {
        body: asyncChunks(chunked(payload, 1_024)),
        expectedBytes: payload.byteLength, maxBytes: payload.byteLength,
        signal: new AbortController().signal,
      }), WATCHDOG_MS, 'reset-after-body PUT'),
      fixture, config, ['TRANSPORT', 'TIMEOUT'], attempt.objectKey,
    );
    // The request really was delivered before the reset (the server saw the body).
    const request = await fixture.waitForRequest(2_000);
    expect(request.bodyBytes).toBe(payload.byteLength);
    // A descriptor spent on an UNKNOWN outcome can never be replayed: a new attempt
    // with a new key is the only legal retry, and no second request is sent.
    const replay = await settle(adapter.putQuarantined(attempt, {
      body: asyncChunks([payload]),
      expectedBytes: payload.byteLength, maxBytes: payload.byteLength, signal: new AbortController().signal,
    }));
    expect(replay.ok).toBe(false);
    if (!replay.ok) {
      expect(storageCode(replay.error)).toBe('ATTEMPT_CONSUMED');
    }
    expect(fixture.requests).toHaveLength(1);
    await adapter.close();
    await fixture.waitForSocketsClosed(3_000);
  });

  it('reports UNKNOWN with a source reason for too few and too many bytes', async () => {
    const fixture = track(await loopback(loopbackBehaviour.accept));
    const config = loopbackConfig(fixture.endpoint);
    const adapter = createAdapter(fixture.endpoint);
    const payload = syntheticPayload(2_048, 'counts');

    // Too few: the source ends before expectedBytes.
    const fewAttempt = adapter.prepareQuarantineAttempt();
    await expectUnknown(
      () => bounded(adapter.putQuarantined(fewAttempt, {
        body: asyncChunks([new Uint8Array(512)]),
        expectedBytes: payload.byteLength, maxBytes: payload.byteLength,
        signal: new AbortController().signal,
      }), WATCHDOG_MS, 'too-few PUT'),
      fixture, config, ['SOURCE_TOO_FEW_BYTES'], fewAttempt.objectKey,
    );

    // Too many: the source exceeds expectedBytes.
    const manyAttempt = adapter.prepareQuarantineAttempt();
    await expectUnknown(
      () => bounded(adapter.putQuarantined(manyAttempt, {
        body: asyncChunks(chunked(syntheticPayload(4_096, 'counts-over'), 1_024)),
        expectedBytes: payload.byteLength, maxBytes: payload.byteLength,
        signal: new AbortController().signal,
      }), WATCHDOG_MS, 'too-many PUT'),
      fixture, config, ['SOURCE_TOO_MANY_BYTES'], manyAttempt.objectKey,
    );
    await adapter.close();
    await fixture.waitForSocketsClosed(3_000);
  });

  it('reports UNKNOWN with a source reason for a non-byte chunk, an oversized chunk and a throwing source', async () => {
    const fixture = track(await loopback(loopbackBehaviour.accept));
    const config = loopbackConfig(fixture.endpoint, { maxChunkBytes: 1_024 });
    const adapter = createAdapter(fixture.endpoint, { maxChunkBytes: 1_024 });

    const nonByteAttempt = adapter.prepareQuarantineAttempt();
    await expectUnknown(
      () => bounded(adapter.putQuarantined(nonByteAttempt, {
        body: asyncChunks(['not-bytes' as unknown as Uint8Array]),
        expectedBytes: 8, maxBytes: 8, signal: new AbortController().signal,
      }), WATCHDOG_MS, 'non-byte PUT'),
      fixture, config, ['SOURCE_INVALID_CHUNK'], nonByteAttempt.objectKey,
    );

    const oversizedAttempt = adapter.prepareQuarantineAttempt();
    await expectUnknown(
      () => bounded(adapter.putQuarantined(oversizedAttempt, {
        body: asyncChunks([syntheticPayload(4_096, 'oversized')]),
        expectedBytes: 4_096, maxBytes: 4_096, signal: new AbortController().signal,
      }), WATCHDOG_MS, 'oversized-chunk PUT'),
      fixture, config, ['SOURCE_CHUNK_TOO_LARGE'], oversizedAttempt.objectKey,
    );

    const throwingAttempt = adapter.prepareQuarantineAttempt();
    await expectUnknown(
      () => bounded(adapter.putQuarantined(throwingAttempt, {
        body: throwingBody(),
        expectedBytes: 8, maxBytes: 8, signal: new AbortController().signal,
      }), WATCHDOG_MS, 'throwing-source PUT'),
      fixture, config, ['SOURCE_FAILED'], throwingAttempt.objectKey,
    );
    await adapter.close();
    await fixture.waitForSocketsClosed(3_000);
  });

  it('aborts an in-flight PUT on caller signal and settles without a leaked socket', async () => {
    // The server accepts the connection and never answers, so the PUT is genuinely
    // in flight when the caller aborts.
    const fixture = track(await loopback(loopbackBehaviour.stallHeaders));
    const config = loopbackConfig(fixture.endpoint);
    const adapter = createAdapter(fixture.endpoint);
    const attempt = adapter.prepareQuarantineAttempt();
    const controller = new AbortController();
    // A cooperative source: it observes the signal and ends cleanly.
    const payload = syntheticPayload(16 * 1_024, 'abort');
    const body = {
      async *[Symbol.asyncIterator](): AsyncGenerator<Uint8Array> {
        for (const chunk of chunked(payload, 1_024)) {
          if (controller.signal.aborted) {
            return;
          }
          yield chunk;
          await sleep(2);
        }
      },
    };
    const pending = adapter.putQuarantined(attempt, {
      body, expectedBytes: payload.byteLength, maxBytes: payload.byteLength, signal: controller.signal,
    });
    // Let the request reach the server, then abort mid-flight.
    await fixture.waitForRequest(2_000);
    controller.abort();
    const settled = await settle(bounded(pending, WATCHDOG_MS, 'aborted PUT'));
    expect(settled.ok).toBe(false);
    if (!settled.ok) {
      expect(storageCode(settled.error)).toBe(UNKNOWN);
      expect(['ABORTED', 'TRANSPORT', 'TIMEOUT']).toContain(reason(settled.error));
      assertSafeFailure(settled.error, [config.accessKeyId, config.secretAccessKey, fixture.endpoint], [attempt.objectKey]);
    }
    // The abort must close the transport, not leave a detached socket.
    await adapter.close();
    await fixture.waitForSocketsClosed(3_000);
    expect(fixture.sockets.size).toBe(0);
  });

  it('does not starve the deadline on an endless run of zero-byte chunks', async () => {
    // Resource-bound case: an infinite source of empty chunks must not monopolise
    // the microtask queue so the operation-deadline timer can never fire. The
    // source is cooperative in the one way the contract requires (it stops when the
    // signal aborts), and the adapter's own deadline must still settle the call.
    const fixture = track(await loopback(loopbackBehaviour.stallHeaders));
    const config = loopbackConfig(fixture.endpoint);
    const adapter = createAdapter(fixture.endpoint);
    const attempt = adapter.prepareQuarantineAttempt();
    const controller = new AbortController();
    const empty = new Uint8Array(0);
    const body: AsyncIterable<Uint8Array> = {
      [Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
        return {
          next(): Promise<IteratorResult<Uint8Array>> {
            if (controller.signal.aborted) {
              return Promise.resolve({ done: true, value: undefined });
            }
            // Endless empty chunks, each resolved immediately: without a periodic
            // event-loop yield this starves the deadline timer forever.
            return Promise.resolve({ done: false, value: empty });
          },
          return(): Promise<IteratorResult<Uint8Array>> {
            return Promise.resolve({ done: true, value: undefined });
          },
        };
      },
    };
    const started = performance.now();
    const settled = await settle(bounded(adapter.putQuarantined(attempt, {
      body, expectedBytes: 1_024, maxBytes: 1_024, signal: controller.signal,
    }), WATCHDOG_MS, 'empty-chunk starvation PUT'));
    const elapsed = performance.now() - started;
    expect(settled.ok).toBe(false);
    if (!settled.ok) {
      // Never a success receipt for an upload that sent no bytes, and never a raw
      // error: the bounded deadline decides the outcome. Any frozen reason is
      // acceptable, but it must be one of them (never free text).
      expect(storageCode(settled.error)).toBe(UNKNOWN);
      expect([
        'TIMEOUT', 'ABORTED', 'TRANSPORT',
        'SOURCE_INVALID_CHUNK', 'SOURCE_CHUNK_TOO_LARGE', 'SOURCE_TOO_MANY_BYTES',
        'SOURCE_TOO_FEW_BYTES', 'SOURCE_FAILED',
      ]).toContain(reason(settled.error));
      assertSafeFailure(settled.error, [config.accessKeyId, config.secretAccessKey, fixture.endpoint], [attempt.objectKey]);
    }
    // The explicit technical deadline (not an infinite hang) settled it.
    expect(elapsed).toBeLessThan(WATCHDOG_MS);
    // Closing the adapter must leave no socket behind.
    await adapter.close();
    await fixture.waitForSocketsClosed(3_000);
    expect(fixture.sockets.size).toBe(0);
  });

  it('does not wait forever for a source that ignores the abort signal', async () => {
    const fixture = track(await loopback(loopbackBehaviour.stallHeaders));
    const adapter = createAdapter(fixture.endpoint);
    const attempt = adapter.prepareQuarantineAttempt();
    const controller = new AbortController();
    // An uncooperative source: after the first chunk it never resolves its next()
    // again and never observes the signal. The adapter must still settle, because
    // its guarantee is a bounded transport, not caller code.
    const pending = adapter.putQuarantined(attempt, {
      body: stallingBody(new Uint8Array(1_024)),
      expectedBytes: 1_024, maxBytes: 1_024, signal: controller.signal,
    });
    await fixture.waitForRequest(2_000);
    controller.abort();
    const settled = await settle(bounded(pending, WATCHDOG_MS, 'uncooperative PUT'));
    expect(settled.ok).toBe(false);
    if (!settled.ok) {
      expect(storageCode(settled.error)).toBe(UNKNOWN);
    }
    await adapter.close();
    await fixture.waitForSocketsClosed(3_000);
  });

  it('settles source-reason failures well before the operation deadline', async () => {
    // A source error must surface immediately, not wait for operationTimeoutMs: the
    // adapter aborts the in-flight SDK request when the bounded source fails.
    const fixture = track(await loopback(loopbackBehaviour.accept));
    const config = loopbackConfig(fixture.endpoint);
    const adapter = createAdapter(fixture.endpoint);
    const attempt = adapter.prepareQuarantineAttempt();
    const started = performance.now();
    const settled = await settle(adapter.putQuarantined(attempt, {
      body: asyncChunks([new Uint8Array(256)]),
      expectedBytes: 4_096, maxBytes: 4_096, signal: new AbortController().signal,
    }));
    const elapsed = performance.now() - started;
    expect(settled.ok).toBe(false);
    if (!settled.ok) {
      expect(storageCode(settled.error)).toBe(UNKNOWN);
      expect(reason(settled.error)).toBe('SOURCE_TOO_FEW_BYTES');
      assertSafeFailure(settled.error, [config.accessKeyId, config.secretAccessKey], [fixture.endpoint, attempt.objectKey]);
    }
    // Comfortably inside the explicit technical deadline: no hang to the timeout.
    expect(elapsed).toBeLessThan(LOOPBACK_TIMEOUTS.operationTimeoutMs);
    await adapter.close();
    await fixture.waitForSocketsClosed(3_000);
  });

  it('close() aborts an in-flight PUT and closes its socket before fixture cleanup', async () => {
    const fixture = track(await loopback(loopbackBehaviour.stallHeaders));
    const adapter = createAdapter(fixture.endpoint);
    const attempt = adapter.prepareQuarantineAttempt();
    const payload = syntheticPayload(4 * 1_024, 'close-inflight-put');
    // Deliberately NOT wrapped in a Promise.race watchdog: the point of this test
    // is that close() itself settles the adapter, not a test-side timer.
    const pending = settle(adapter.putQuarantined(attempt, {
      body: asyncChunks([payload]),
      expectedBytes: payload.byteLength, maxBytes: payload.byteLength,
      signal: new AbortController().signal,
    }));
    await fixture.waitForRequest(2_000);
    expect(fixture.sockets.size).toBeGreaterThan(0);
    await adapter.close();
    const settled = await pending;
    expect(settled.ok).toBe(false);
    if (!settled.ok) {
      // Shutdown mid-PUT is an UNKNOWN write outcome, never "not written".
      expect(storageCode(settled.error)).toBe(UNKNOWN);
      expect(['ABORTED', 'TRANSPORT', 'TIMEOUT']).toContain(reason(settled.error));
    }
    // The in-flight socket must be gone once close() resolved, before the fixture
    // server is torn down by cleanup.
    await fixture.waitForSocketsClosed(3_000);
    expect(fixture.sockets.size).toBe(0);
    // New operations are refused after close.
    const afterClose = await settle(adapter.putQuarantined(attempt, {
      body: asyncChunks([payload]),
      expectedBytes: payload.byteLength, maxBytes: payload.byteLength,
      signal: new AbortController().signal,
    }));
    expect(afterClose.ok).toBe(false);
    if (!afterClose.ok) {
      expect(storageCode(afterClose.error)).toBe('CLOSED');
    }
  });

  it('close() aborts a stalled GET body read and closes its socket before fixture cleanup', async () => {
    // First put successfully so the descriptor is written, then verify against a
    // server that sends headers + one byte and stalls the body.
    const fixture = track(await loopback(acceptPutStallGet));
    const adapter = createAdapter(fixture.endpoint);
    const payload = syntheticPayload(2_048, 'close-inflight-get');
    const attempt = adapter.prepareQuarantineAttempt();
    const put = await bounded(adapter.putQuarantined(attempt, {
      body: asyncChunks([payload]),
      expectedBytes: payload.byteLength, maxBytes: payload.byteLength, signal: new AbortController().signal,
    }), WATCHDOG_MS, 'close-inflight PUT');
    // Not wrapped in a watchdog: close() must settle the stalled body read itself.
    const pending = settle(adapter.verifyQuarantined(attempt, {
      expectedBytes: payload.byteLength, sha256: put.sha256, maxBytes: payload.byteLength,
      signal: new AbortController().signal,
    }));
    // True barrier: wait until the GET (not the earlier PUT) is observed by the
    // fixture, so close() cannot race the request before it reached the transport.
    const getRequest = await fixture.waitForRequestMatching(
      (request) => request.method === 'GET',
      2_000,
      'GET request',
    );
    expect(getRequest.complete).toBe(true);
    await adapter.close();
    const settled = await pending;
    expect(settled.ok).toBe(false);
    if (!settled.ok) {
      // A GET cut off by shutdown is READ_FAILED, not a write outcome.
      expect(storageCode(settled.error)).toBe(READ_FAILED);
      expect(['ABORTED', 'TIMEOUT', 'TRANSPORT']).toContain(reason(settled.error));
    }
    await fixture.waitForSocketsClosed(3_000);
    expect(fixture.sockets.size).toBe(0);
  });

  it('treats concurrent close() calls as one idempotent shutdown', async () => {
    const fixture = track(await loopback(loopbackBehaviour.stallHeaders));
    const adapter = createAdapter(fixture.endpoint);
    const attempt = adapter.prepareQuarantineAttempt();
    const payload = syntheticPayload(1_024, 'concurrent-close');
    const pending = settle(adapter.putQuarantined(attempt, {
      body: asyncChunks([payload]),
      expectedBytes: payload.byteLength, maxBytes: payload.byteLength,
      signal: new AbortController().signal,
    }));
    await fixture.waitForRequest(2_000);
    // Two concurrent closes must both resolve without a second destroy/throw.
    await Promise.all([adapter.close(), adapter.close()]);
    await pending;
    await fixture.waitForSocketsClosed(3_000);
    expect(fixture.sockets.size).toBe(0);
  });

  it('leaves no unhandled rejection and no secret in errors across a stalled transport', async () => {
    const watch = watchUnhandledRejections();
    try {
      const fixture = track(await loopback(loopbackBehaviour.stallHeaders));
      const config = loopbackConfig(fixture.endpoint);
      const adapter = createAdapter(fixture.endpoint);
      const attempt = adapter.prepareQuarantineAttempt();
      const payload = syntheticPayload(512, 'no-unhandled');
      const settled = await settle(bounded(adapter.putQuarantined(attempt, {
        body: asyncChunks([payload]),
        expectedBytes: payload.byteLength, maxBytes: payload.byteLength,
        signal: new AbortController().signal,
      }), WATCHDOG_MS, 'no-unhandled PUT'));
      expect(settled.ok).toBe(false);
      if (!settled.ok) {
        assertSafeFailure(settled.error, [config.accessKeyId, config.secretAccessKey, fixture.endpoint], [attempt.objectKey]);
      }
      // Give the process a turn to surface a detached rejection, if any.
      await sleep(250);
      expect(watch.rejections).toHaveLength(0);
      await adapter.close();
      await fixture.waitForSocketsClosed(3_000);
    } finally {
      watch.stop();
    }
  });
});

/**
 * MUST1 after ASTRA: an attempt is bound, by descriptor identity, to the exact
 * canonical `endpoint` + `bucket` + `region` of its one PUT. A verify through any
 * other target is refused with the dedicated `ATTEMPT_TARGET_MISMATCH` code *before
 * any network request* — not as a generic read failure or timeout — while the same
 * physical target through another adapter instance (even with rotated credentials)
 * still verifies, and the module-wide one-shot PUT stays consumed.
 *
 * Both loopback servers are real object stores, and the "wrong" target is seeded
 * with the exact bytes at the exact path: if the adapter wrongly dialled it, the GET
 * would succeed with a matching body. The refusal can therefore only come from the
 * pre-network target guard, never from a 404 or an unavailable body.
 */
describe('private quarantine storage: attempt target binding', () => {
  const TARGET_MISMATCH = 'ATTEMPT_TARGET_MISMATCH';

  /** Asserts the exact dedicated mismatch refusal: fixed code, no cause, no marker. */
  function expectTargetMismatch(settled: Settled<unknown>): void {
    expect(settled.ok).toBe(false);
    if (settled.ok) {
      throw new Error('Expected a typed target-mismatch refusal, received a success receipt.');
    }
    expect(storageCode(settled.error)).toBe(TARGET_MISMATCH);
    expect((settled.error as Error).message).toBe(TARGET_MISMATCH);
    expect(reason(settled.error)).toBeUndefined();
    expect('cause' in (settled.error as object)).toBe(false);
    const text = errorText(settled.error);
    expect(text.includes('SYNTHETIC_PRIVATE_MARKER')).toBe(false);
    expect(text.includes('READ_FAILED')).toBe(false);
    expect(text.includes('WRITE_OUTCOME_UNKNOWN')).toBe(false);
  }

  it('refuses another endpoint, bucket or region before any request, and still verifies the same target', async () => {
    const storeA = loopbackObjectStore();
    const storeB = loopbackObjectStore();
    const fixtureA = track(await loopback(storeA.handler, { captureBody: true }));
    const fixtureB = track(await loopback(storeB.handler, { captureBody: true }));
    const configA = loopbackConfig(fixtureA.endpoint);
    const adapterA = createAdapter(fixtureA.endpoint);
    const payload = syntheticPayload(4_096, 'target-binding');
    const attempt = adapterA.prepareQuarantineAttempt();
    const put = await bounded(adapterA.putQuarantined(attempt, {
      body: asyncChunks(chunked(payload, 1_024)),
      expectedBytes: payload.byteLength, maxBytes: payload.byteLength, signal: new AbortController().signal,
    }), WATCHDOG_MS, 'target-binding PUT');
    expect(put.actualBytes).toBe(payload.byteLength);
    expect(put.sha256).toBe(sha256Hex(payload));

    // Positive baseline: the first target saw exactly one PUT and nothing else.
    expect(fixtureA.requests.map((request) => request.method)).toEqual(['PUT']);
    expect(fixtureA.requests[0]?.bodyBytes).toBe(payload.byteLength);
    const storedPath = objectPath(configA.bucket, attempt.objectKey);
    expect(Buffer.compare(storeA.objects.get(storedPath) ?? Buffer.alloc(0), Buffer.from(payload))).toBe(0);

    // The second, genuinely different endpoint WOULD serve the matching body if the
    // adapter wrongly dialled it: seeded exact path/bytes, proven by a raw GET.
    storeB.seed(storedPath, payload);
    const probe = await fetch(`${fixtureB.endpoint}${storedPath}`, {
      method: 'GET', redirect: 'error', signal: AbortSignal.timeout(2_000),
    });
    expect(probe.status).toBe(200);
    expect(sha256Hex(new Uint8Array(await probe.arrayBuffer()))).toBe(put.sha256);
    const requestsA = fixtureA.requests.length;
    const requestsB = fixtureB.requests.length;

    const verify = (adapter: Adapter) => adapter.verifyQuarantined(attempt, {
      expectedBytes: payload.byteLength, sha256: put.sha256, maxBytes: payload.byteLength,
      signal: new AbortController().signal,
    });

    // (a) Different endpoint: dedicated pre-network refusal, zero new requests anywhere.
    const otherEndpoint = createAdapter(fixtureB.endpoint);
    expectTargetMismatch(await settle(verify(otherEndpoint)));
    expect(fixtureB.requests.length).toBe(requestsB);
    expect(fixtureA.requests.length).toBe(requestsA);

    // (b) Same endpoint, different bucket: still zero new requests.
    const otherBucket = createAdapter(fixtureA.endpoint, { bucket: 'synthetic-other-bucket' });
    expectTargetMismatch(await settle(verify(otherBucket)));
    expect(fixtureA.requests.length).toBe(requestsA);

    // (c) Same endpoint and bucket, different region: still zero new requests.
    const otherRegion = createAdapter(fixtureA.endpoint, { region: 'synthetic-other-region' });
    expectTargetMismatch(await settle(verify(otherRegion)));
    expect(fixtureA.requests.length).toBe(requestsA);

    // A PUT through a different target on the already-spent descriptor is consumed,
    // never retargeted, and sends nothing: the module-wide one-shot guard wins.
    const replay = await settle(otherBucket.putQuarantined(attempt, {
      body: asyncChunks([payload]), expectedBytes: payload.byteLength, maxBytes: payload.byteLength,
      signal: new AbortController().signal,
    }));
    expect(replay.ok).toBe(false);
    if (!replay.ok) {
      expect(storageCode(replay.error)).toBe('ATTEMPT_CONSUMED');
    }
    expect(fixtureA.requests.length).toBe(requestsA);
    expect(fixtureB.requests.length).toBe(requestsB);

    // (d) The SAME physical target through a second adapter with rotated credentials
    // is accepted: credentials are not part of the target. The real GET is observed.
    const rotated = syntheticCredentials('rotated-secret');
    const sameTarget = createAdapter(fixtureA.endpoint, {
      accessKeyId: rotated.accessKeyId, secretAccessKey: rotated.secretAccessKey,
    });
    const verified = await bounded(verify(sameTarget), WATCHDOG_MS, 'same-target verify');
    expect(verified.sha256).toBe(put.sha256);
    expect(verified.actualBytes).toBe(payload.byteLength);
    expect(fixtureA.requests.map((request) => request.method)).toEqual(['PUT', 'GET']);
    // The successful verify is a read of the real stored bytes, not a cached receipt.
    expect(storeA.objects.get(storedPath)?.byteLength).toBe(payload.byteLength);
    // One PUT globally consumed: the same descriptor cannot be PUT again by the
    // second adapter either, and no third request appears.
    const secondPut = await settle(sameTarget.putQuarantined(attempt, {
      body: asyncChunks([payload]), expectedBytes: payload.byteLength, maxBytes: payload.byteLength,
      signal: new AbortController().signal,
    }));
    expect(secondPut.ok).toBe(false);
    if (!secondPut.ok) {
      expect(storageCode(secondPut.error)).toBe('ATTEMPT_CONSUMED');
    }
    expect(fixtureA.requests.filter((request) => request.method === 'PUT')).toHaveLength(1);
  });
});

/**
 * MUST2 after ASTRA: the mandatory `maxResponseBodyBytes` cap sits *below* the SDK
 * deserializer, so an oversized service response body is cut before it is collected.
 * Two things must be true at once, and each case below proves one:
 *
 * - the cap is a **response** bound, not a file bound: an object larger than the cap
 *   still uploads and verifies byte-for-byte (positive control);
 * - a chunked body with **no** `Content-Length` is cut early by counting actual
 *   bytes, so a header-only validation cannot pass, the server never writes its
 *   whole planned body, the socket is closed before fixture cleanup, and the caller
 *   gets a typed failure — never a success receipt.
 */
describe('private quarantine storage: bounded service responses', () => {
  /** Chunked-body plan: 256 B writes, no Content-Length, 256 KiB planned in total. */
  const BODY_PLAN = { chunkBytes: 256, totalBytes: 256 * 1_024, intervalMs: 1 } as const;
  /** The cap under test, and the technical margin allowed for in-flight chunks. */
  const CAP_BYTES = 1_024;
  const CHUNK_MARGIN = 16;

  function noContentLength(probe: ReturnType<typeof oversizedChunkedResponse>): void {
    const headers = probe.headers();
    for (const name of Object.keys(headers)) {
      expect(name.toLowerCase()).not.toBe('content-length');
    }
  }

  /** Asserts the server stopped well before its planned body, not after a full send. */
  async function expectEarlyCut(probe: ReturnType<typeof oversizedChunkedResponse>): Promise<void> {
    // The server observes the client's socket close asynchronously: wait for that
    // real event (bounded) instead of sleeping and hoping.
    await waitUntil(() => probe.stopped(), 3_000, 'server to observe the closed socket');
    noContentLength(probe);
    expect(probe.finished()).toBe(false);
    expect(probe.stopped()).toBe(true);
    expect(probe.sentBytes()).toBeGreaterThan(0);
    // Bounded margin: the cap plus a few in-flight chunks, never the whole 256 KiB.
    expect(probe.sentBytes()).toBeLessThanOrEqual(CAP_BYTES + CHUNK_MARGIN * BODY_PLAN.chunkBytes);
    expect(probe.sentBytes()).toBeLessThan(probe.plannedBytes / 8);
  }

  it('caps an oversized PUT success body early and reports no success receipt', async () => {
    const watch = watchUnhandledRejections();
    try {
      const probe = oversizedChunkedResponse({ status: 200, methods: ['PUT'], ...BODY_PLAN });
      const fixture = track(await loopback(probe.handler));
      const config = loopbackConfig(fixture.endpoint, { maxResponseBodyBytes: CAP_BYTES });
      const adapter = createAdapter(fixture.endpoint, { maxResponseBodyBytes: CAP_BYTES });
      const attempt = adapter.prepareQuarantineAttempt();
      const payload = syntheticPayload(512, 'put-success-body-cap');
      const settled = await settle(bounded(adapter.putQuarantined(attempt, {
        body: asyncChunks([payload]),
        expectedBytes: payload.byteLength, maxBytes: payload.byteLength,
        signal: new AbortController().signal,
      }), WATCHDOG_MS, 'oversized PUT success body'));
      // A 200 PUT whose body could not be bounded is a post-start unknown outcome:
      // the object may exist, so no receipt and no "not written" claim.
      expect(settled.ok).toBe(false);
      if (!settled.ok) {
        expect(storageCode(settled.error)).toBe(UNKNOWN);
        expect(reason(settled.error)).toBe('TRANSPORT');
        expect((settled.error as Error).message).toBe(UNKNOWN);
        expect('cause' in (settled.error as object)).toBe(false);
        assertSafeFailure(
          settled.error,
          [config.accessKeyId, config.secretAccessKey, fixture.endpoint],
          [attempt.objectKey],
        );
      }
      await expectEarlyCut(probe);
      // The upload request itself was fully delivered; only the response was cut.
      const request = await fixture.waitForRequest(2_000);
      expect(request.bodyBytes).toBe(payload.byteLength);
      // Sockets are closed before the fixture is torn down, with nothing detached.
      await adapter.close();
      await fixture.waitForSocketsClosed(3_000);
      expect(fixture.sockets.size).toBe(0);
      await sleep(150);
      expect(watch.rejections).toHaveLength(0);
    } finally {
      watch.stop();
    }
  });

  it('keeps an object larger than the cap verifiable, then caps an oversized GET error body', async () => {
    const watch = watchUnhandledRejections();
    try {
      const store = loopbackObjectStore();
      const probe = oversizedChunkedResponse({ status: 500, methods: ['GET'], ...BODY_PLAN });
      let failGet = false;
      const handler: LoopbackHandler = (request, response, record) => {
        if ((request.method ?? '') === 'GET' && failGet) {
          probe.handler(request, response, record);
          return;
        }
        store.handler(request, response, record);
      };
      const fixture = track(await loopback(handler, { captureBody: true }));
      const config = loopbackConfig(fixture.endpoint, { maxResponseBodyBytes: CAP_BYTES });
      const adapter = createAdapter(fixture.endpoint, { maxResponseBodyBytes: CAP_BYTES });
      // Positive control: the payload is 4x the response cap. The cap must not become
      // a hidden file-size limit, so PUT and GET both succeed with exact bytes/hash.
      const payload = syntheticPayload(4 * CAP_BYTES, 'file-larger-than-response-cap');
      const attempt = adapter.prepareQuarantineAttempt();
      const put = await bounded(adapter.putQuarantined(attempt, {
        body: asyncChunks(chunked(payload, 512)),
        expectedBytes: payload.byteLength, maxBytes: payload.byteLength,
        signal: new AbortController().signal,
      }), WATCHDOG_MS, 'large-file PUT');
      expect(put.actualBytes).toBe(payload.byteLength);
      expect(put.sha256).toBe(sha256Hex(payload));
      const verified = await bounded(adapter.verifyQuarantined(attempt, {
        expectedBytes: payload.byteLength, sha256: put.sha256, maxBytes: payload.byteLength,
        signal: new AbortController().signal,
      }), WATCHDOG_MS, 'large-file verify');
      expect(verified.actualBytes).toBe(payload.byteLength);
      expect(verified.sha256).toBe(sha256Hex(payload));
      // The real 200 GET body exceeded the cap and was still delivered in full.
      expect(fixture.requests.map((request) => request.method)).toEqual(['PUT', 'GET']);
      expect(store.objects.get(objectPath(config.bucket, attempt.objectKey))?.byteLength).toBe(payload.byteLength);

      // Now the service answers the same descriptor's GET with a 500 whose chunked
      // error body is far above the cap: a read failure, not a verify result.
      failGet = true;
      const settled = await settle(bounded(adapter.verifyQuarantined(attempt, {
        expectedBytes: payload.byteLength, sha256: put.sha256, maxBytes: payload.byteLength,
        signal: new AbortController().signal,
      }), WATCHDOG_MS, 'oversized GET error body'));
      expect(settled.ok).toBe(false);
      if (!settled.ok) {
        expect(storageCode(settled.error)).toBe(READ_FAILED);
        expect(['TRANSPORT', 'TIMEOUT']).toContain(reason(settled.error));
        expect((settled.error as Error).message).toBe(READ_FAILED);
        expect('cause' in (settled.error as object)).toBe(false);
        assertSafeFailure(
          settled.error,
          [config.accessKeyId, config.secretAccessKey, fixture.endpoint],
          [attempt.objectKey],
        );
      }
      await expectEarlyCut(probe);
      await adapter.close();
      await fixture.waitForSocketsClosed(3_000);
      expect(fixture.sockets.size).toBe(0);
      await sleep(150);
      expect(watch.rejections).toHaveLength(0);
    } finally {
      watch.stop();
    }
  });
});

/**
 * Residual MUST4 after ASTRA: the source's optional `return()` is caller code, and
 * merely *reading* the `return` property can run a caller getter that throws. That
 * read must happen exactly once, inside the module's own guard, after the iterator
 * reference was detached — so it can never suppress a normal EOF, escape `_destroy`
 * as an uncaught exception, or replace an already-decided outcome with a marker.
 *
 * Both cases are real loopback transports with actual sockets: one completes a PUT
 * with an exact success receipt, the other aborts a live PUT after the request and
 * its first body byte were observed.
 */
describe('private quarantine storage: throwing iterator cleanup', () => {
  const RETURN_MARKER = 'SYNTHETIC_RETURN_MARKER';

  /** Collects both detached rejections and escaping exceptions for one test. */
  function watchProcessFaults(): { readonly faults: unknown[]; stop(): void } {
    const faults: unknown[] = [];
    const onRejection = (reason: unknown): void => { faults.push(reason); };
    const onException = (error: unknown): void => { faults.push(error); };
    process.on('unhandledRejection', onRejection);
    process.on('uncaughtException', onException);
    return {
      faults,
      stop(): void {
        process.off('unhandledRejection', onRejection);
        process.off('uncaughtException', onException);
      },
    };
  }

  /** Asserts the fixed safe failure: exact code, no cause, no caller marker. */
  function expectSafeUnknown(error: unknown): void {
    expect(storageCode(error)).toBe(UNKNOWN);
    expect((error as Error).message).toBe(UNKNOWN);
    expect('cause' in (error as object)).toBe(false);
    const text = errorText(error);
    expect(text.includes(RETURN_MARKER)).toBe(false);
  }

  it('completes a PUT normally when reading iterator.return throws, once, after detach', async () => {
    const watch = watchProcessFaults();
    try {
      const store = loopbackObjectStore();
      const fixture = track(await loopback(store.handler, { captureBody: true }));
      const config = loopbackConfig(fixture.endpoint);
      const adapter = createAdapter(fixture.endpoint);
      const payload = syntheticPayload(2_048, 'throwing-return-eof');
      const chunks = chunked(payload, 512);
      let returnReads = 0;
      let index = 0;
      // A fully cooperative iterator that yields exactly `expectedBytes` and then
      // ends, but whose `return` is a getter that throws every time it is read.
      const iterator = {
        next(): Promise<IteratorResult<Uint8Array>> {
          const chunk = chunks[index];
          index += 1;
          return Promise.resolve(chunk === undefined
            ? { done: true, value: undefined }
            : { done: false, value: chunk });
        },
        get return(): never {
          returnReads += 1;
          throw new Error(RETURN_MARKER);
        },
      } as unknown as AsyncIterator<Uint8Array>;
      const body: AsyncIterable<Uint8Array> = { [Symbol.asyncIterator]: () => iterator };

      const attempt = adapter.prepareQuarantineAttempt();
      const started = performance.now();
      const receipt = await bounded(adapter.putQuarantined(attempt, {
        body,
        expectedBytes: payload.byteLength, maxBytes: payload.byteLength,
        signal: new AbortController().signal,
      }), WATCHDOG_MS, 'throwing-return PUT');
      const elapsed = performance.now() - started;
      // Normal EOF: an exact storage receipt, not a masked failure or a hang.
      expect(receipt.actualBytes).toBe(payload.byteLength);
      expect(receipt.sha256).toBe(sha256Hex(payload));
      expect(Object.keys(receipt).sort()).toEqual(['actualBytes', 'attemptId', 'objectKey', 'sha256']);
      expect(elapsed).toBeLessThan(LOOPBACK_TIMEOUTS.operationTimeoutMs);
      // The real bytes arrived: an independent bounded GET re-reads and re-hashes them.
      const verified = await bounded(adapter.verifyQuarantined(attempt, {
        expectedBytes: payload.byteLength, sha256: receipt.sha256, maxBytes: payload.byteLength,
        signal: new AbortController().signal,
      }), WATCHDOG_MS, 'throwing-return verify');
      expect(verified.actualBytes).toBe(payload.byteLength);
      expect(verified.sha256).toBe(sha256Hex(payload));
      expect(store.objects.get(objectPath(config.bucket, attempt.objectKey))?.byteLength).toBe(payload.byteLength);
      // Read exactly once despite the normal `complete()` *and* the later `destroy()`:
      // the iterator reference is detached before the first read.
      expect(returnReads).toBe(1);
      // Nothing escaped as a stream error, an exception or a detached rejection.
      await sleep(150);
      expect(watch.faults).toHaveLength(0);
      await adapter.close();
      await fixture.waitForSocketsClosed(3_000);
      expect(fixture.sockets.size).toBe(0);
    } finally {
      watch.stop();
    }
  });

  it('aborts a live PUT safely when reading iterator.return throws during cleanup', async () => {
    const watch = watchProcessFaults();
    try {
      const store = loopbackObjectStore();
      const fixture = track(await loopback(store.handler, { captureBody: true }));
      const config = loopbackConfig(fixture.endpoint);
      const adapter = createAdapter(fixture.endpoint);
      const firstChunk = syntheticPayload(1_024, 'throwing-return-abort');
      let returnReads = 0;
      let pulled = false;
      // Yields one chunk, then never settles `next()`: the abort, not the source,
      // decides the outcome (a cooperative `next()` could record a source reason and
      // hide the caller-abort path this case is about). `return` is a throwing getter.
      const iterator = {
        next(): Promise<IteratorResult<Uint8Array>> {
          if (!pulled) {
            pulled = true;
            return Promise.resolve({ done: false, value: firstChunk });
          }
          return new Promise<IteratorResult<Uint8Array>>(() => { /* never settles */ });
        },
        get return(): never {
          returnReads += 1;
          throw new Error(RETURN_MARKER);
        },
      } as unknown as AsyncIterator<Uint8Array>;
      const body: AsyncIterable<Uint8Array> = { [Symbol.asyncIterator]: () => iterator };

      const controller = new AbortController();
      const attempt = adapter.prepareQuarantineAttempt();
      const pending = settle(bounded(adapter.putQuarantined(attempt, {
        body,
        expectedBytes: 4_096, maxBytes: 4_096, signal: controller.signal,
      }), WATCHDOG_MS, 'throwing-return abort PUT'));
      // Abort only after the request is genuinely in flight and its first body byte
      // was written: that is the state in which cleanup reads `return`.
      const request = await fixture.waitForRequest(2_000);
      await waitUntil(() => request.bodyBytes > 0, 2_000, 'first request body byte');
      controller.abort();
      const settled = await pending;
      expect(settled.ok).toBe(false);
      if (!settled.ok) {
        expectSafeUnknown(settled.error);
        expect(reason(settled.error)).toBe('ABORTED');
        assertSafeFailure(
          settled.error,
          [config.accessKeyId, config.secretAccessKey, fixture.endpoint],
          [attempt.objectKey],
        );
      }
      // The throwing getter was read once, and its exception never escaped.
      expect(returnReads).toBe(1);
      // The spent descriptor is still one-shot after the aborted attempt.
      const replay = await settle(adapter.putQuarantined(attempt, {
        body: asyncChunks([firstChunk]), expectedBytes: 1_024, maxBytes: 1_024,
        signal: new AbortController().signal,
      }));
      expect(replay.ok).toBe(false);
      if (!replay.ok) {
        expect(storageCode(replay.error)).toBe('ATTEMPT_CONSUMED');
      }
      // Closing the adapter settles the transport and releases the socket before the
      // fixture is torn down; nothing is left detached.
      await adapter.close();
      await fixture.waitForSocketsClosed(3_000);
      expect(fixture.sockets.size).toBe(0);
      await sleep(150);
      expect(watch.faults).toHaveLength(0);
    } finally {
      watch.stop();
    }
  });
});
