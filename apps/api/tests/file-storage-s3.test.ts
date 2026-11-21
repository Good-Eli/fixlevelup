/**
 * Real local Garage proof for the P03-04B **B1** private quarantine adapter.
 *
 * Opt-in only (`FIXLEVELUP_STORAGE_S3_TESTS=1`), so a normal `vitest run` passes
 * with no local S3 service and no credentials. The suite talks to the existing
 * single-node dev Garage (`http://127.0.0.1:3900`, private bucket) with the
 * existing ignored dev credentials and exercises the *actual* adapter: no fake S3,
 * no mock transport, no test-side reimplementation of the byte accounting.
 *
 * What is proved:
 *
 * - a real PUT of a synthetic payload succeeds and the adapter receipt reports the
 *   actual byte count and SHA-256 of the bytes that were sent;
 * - a bounded GET through `verifyQuarantined` re-reads the object from the same
 *   key and independently matches bytes/hash, so HEAD/ETag/metadata are not what
 *   the proof relies on;
 * - a fresh attempt gets a fresh random key and never changes a previous object;
 * - a descriptor is one-shot module-wide: a second adapter instance cannot PUT it
 *   again, and the stored bytes stay the first attempt's bytes (no overwrite);
 * - the bucket stays private: anonymous and wrong-credential access is denied, and
 *   the read-only key cannot PUT;
 * - a mutable caller chunk cannot change what was sent or hashed (the adapter
 *   copies before yielding);
 * - a verify with a wrong expected hash/bytes is a typed `VERIFY_MISMATCH`, not a
 *   success.
 *
 * Deliberate limits: this is B1 only. No DB registration, no `QUARANTINED`/`READY`
 * transition, no HTTP, no scanner, no delete. Every object created here lives under
 * a unique synthetic `quarantine/...` namespace and is intentionally left in place
 * as evidence; nothing existing is read, overwritten or removed, and no bucket
 * grant, policy, container or volume is touched.
 */
import { randomUUID } from 'node:crypto';
import { HeadObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as storage from '../src/files/storage/index.js';
import {
  GARAGE_BUCKET, GARAGE_ENDPOINT, assertSafeFailure, asyncChunks, bounded, chunked, garageConfig,
  loadGarageCredentials, mutableThenMutated, settle, sha256Hex, storageCode, syntheticPayload, wrongCredentials,
} from './file-storage-fixture.js';
import type { StorageTestConfig } from './file-storage-fixture.js';

/** Opt-in: the real-Garage suite never runs in a normal test pass. */
const integration = process.env['FIXLEVELUP_STORAGE_S3_TESTS'] === '1' ? describe : describe.skip;

/** Raw SDK client used only to *inspect* the bucket side effects (never by the adapter). */
function inspector(config: StorageTestConfig): S3Client {
  return new S3Client({
    endpoint: config.endpoint,
    region: config.region,
    forcePathStyle: true,
    maxAttempts: 1,
    credentials: { accessKeyId: config.accessKeyId, secretAccessKey: config.secretAccessKey },
    requestHandler: {
      connectionTimeout: config.connectionTimeoutMs,
      requestTimeout: config.requestTimeoutMs,
      socketTimeout: config.socketTimeoutMs,
      throwOnRequestTimeout: true,
    },
  });
}

async function statusOf(action: () => Promise<unknown>): Promise<number | undefined> {
  try {
    await action();
    return undefined;
  } catch (error: unknown) {
    if (typeof error !== 'object' || error === null || !('$metadata' in error)) {
      return undefined;
    }
    const metadata: unknown = error.$metadata;
    if (typeof metadata !== 'object' || metadata === null || !('httpStatusCode' in metadata)) {
      return undefined;
    }
    const status: unknown = (metadata as { httpStatusCode?: unknown }).httpStatusCode;
    return typeof status === 'number' ? status : undefined;
  }
}

const SIGNAL = new AbortController().signal;
/** Watchdog for a real network call: generous, but bounded. */
const CALL_WATCHDOG_MS = 20_000;

integration('private quarantine storage: real local Garage', () => {
  let config: StorageTestConfig;
  let inspectorClient: S3Client | undefined;
  const adapters: Array<{ close(): Promise<void> }> = [];

  function newAdapter(overrides: Partial<StorageTestConfig> = {}): ReturnType<typeof storage.createPrivateQuarantineStorage> {
    const adapter = storage.createPrivateQuarantineStorage({ ...config, ...overrides });
    adapters.push(adapter);
    return adapter;
  }

  function raw(): S3Client {
    if (inspectorClient === undefined) {
      throw new Error('Garage inspector client is not initialized.');
    }
    return inspectorClient;
  }

  beforeAll(() => {
    try {
      config = garageConfig();
    } catch {
      throw new Error('Local Garage credentials are unavailable; verify infra/dev-s3 configuration.');
    }
    inspectorClient = inspector(config);
  });

  afterAll(async () => {
    await Promise.all(adapters.map(async (adapter) => { await adapter.close(); }));
    inspectorClient?.destroy();
  });

  it('PUTs synthetic bytes and reports the actual byte count and SHA-256', async () => {
    const adapter = newAdapter();
    const payload = syntheticPayload(48 * 1024, 'garage-roundtrip');
    const attempt = adapter.prepareQuarantineAttempt();
    const receipt = await bounded(adapter.putQuarantined(attempt, {
      body: asyncChunks(chunked(payload, 8 * 1024)),
      expectedBytes: payload.byteLength,
      maxBytes: payload.byteLength,
      signal: SIGNAL,
    }), CALL_WATCHDOG_MS, 'Garage PUT');

    expect(receipt.attemptId).toBe(attempt.attemptId);
    expect(receipt.objectKey).toBe(attempt.objectKey);
    expect(receipt.actualBytes).toBe(payload.byteLength);
    expect(receipt.sha256).toBe(sha256Hex(payload));
    // No URL/ETag/credential in the receipt: it is an internal storage receipt.
    expect(Object.keys(receipt).sort()).toEqual(['actualBytes', 'attemptId', 'objectKey', 'sha256']);

    // Independent inspection with the raw client: the object exists, has exactly
    // the payload length, and re-reads to the same bytes/hash.
    const head = await bounded(raw().send(new HeadObjectCommand({
      Bucket: GARAGE_BUCKET, Key: attempt.objectKey,
    })), CALL_WATCHDOG_MS, 'Garage HEAD');
    expect(head.ContentLength).toBe(payload.byteLength);
  });

  it('verifies the stored object by re-reading bounded bytes and hash', async () => {
    const adapter = newAdapter();
    const payload = syntheticPayload(32 * 1024, 'garage-verify');
    const attempt = adapter.prepareQuarantineAttempt();
    const put = await bounded(adapter.putQuarantined(attempt, {
      body: asyncChunks([payload]),
      expectedBytes: payload.byteLength,
      maxBytes: payload.byteLength,
      signal: SIGNAL,
    }), CALL_WATCHDOG_MS, 'Garage PUT for verify');

    const verified = await bounded(adapter.verifyQuarantined(attempt, {
      expectedBytes: put.actualBytes,
      sha256: put.sha256,
      maxBytes: payload.byteLength,
      signal: SIGNAL,
    }), CALL_WATCHDOG_MS, 'Garage verify');

    expect(verified.attemptId).toBe(attempt.attemptId);
    expect(verified.objectKey).toBe(attempt.objectKey);
    expect(verified.actualBytes).toBe(payload.byteLength);
    expect(verified.sha256).toBe(sha256Hex(payload));
    // Verify is read-only: the same descriptor can be verified again.
    const again = await bounded(adapter.verifyQuarantined(attempt, {
      expectedBytes: payload.byteLength, sha256: sha256Hex(payload), maxBytes: payload.byteLength, signal: SIGNAL,
    }), CALL_WATCHDOG_MS, 'Garage re-verify');
    expect(again.sha256).toBe(verified.sha256);
  });

  it('refuses a verify whose expected hash or size does not match the stored bytes', async () => {
    const adapter = newAdapter();
    const payload = syntheticPayload(4 * 1024, 'garage-mismatch');
    const attempt = adapter.prepareQuarantineAttempt();
    await bounded(adapter.putQuarantined(attempt, {
      body: asyncChunks([payload]),
      expectedBytes: payload.byteLength,
      maxBytes: payload.byteLength,
      signal: SIGNAL,
    }), CALL_WATCHDOG_MS, 'Garage PUT for mismatch');

    const wrongHash = await settle(adapter.verifyQuarantined(attempt, {
      expectedBytes: payload.byteLength, sha256: 'b'.repeat(64), maxBytes: payload.byteLength, signal: SIGNAL,
    }));
    expect(wrongHash.ok).toBe(false);
    if (!wrongHash.ok) {
      expect(storageCode(wrongHash.error)).toBe('VERIFY_MISMATCH');
    }
    const wrongBytes = await settle(adapter.verifyQuarantined(attempt, {
      expectedBytes: payload.byteLength + 1, sha256: sha256Hex(payload), maxBytes: payload.byteLength + 8, signal: SIGNAL,
    }));
    expect(wrongBytes.ok).toBe(false);
    if (!wrongBytes.ok) {
      expect(storageCode(wrongBytes.error)).toBe('VERIFY_MISMATCH');
    }
  });

  it('gives every attempt a fresh key and never changes a previous object', async () => {
    const adapter = newAdapter();
    const firstPayload = syntheticPayload(8 * 1024, 'garage-fresh-a');
    const secondPayload = syntheticPayload(16 * 1024, 'garage-fresh-b');

    const firstAttempt = adapter.prepareQuarantineAttempt();
    const first = await bounded(adapter.putQuarantined(firstAttempt, {
      body: asyncChunks([firstPayload]),
      expectedBytes: firstPayload.byteLength, maxBytes: firstPayload.byteLength, signal: SIGNAL,
    }), CALL_WATCHDOG_MS, 'Garage first PUT');

    const secondAttempt = adapter.prepareQuarantineAttempt();
    expect(secondAttempt.objectKey).not.toBe(firstAttempt.objectKey);
    const second = await bounded(adapter.putQuarantined(secondAttempt, {
      body: asyncChunks([secondPayload]),
      expectedBytes: secondPayload.byteLength, maxBytes: secondPayload.byteLength, signal: SIGNAL,
    }), CALL_WATCHDOG_MS, 'Garage second PUT');

    expect(second.objectKey).not.toBe(first.objectKey);
    // The first object is untouched by the second attempt.
    const firstAgain = await bounded(adapter.verifyQuarantined(firstAttempt, {
      expectedBytes: first.actualBytes, sha256: first.sha256, maxBytes: firstPayload.byteLength, signal: SIGNAL,
    }), CALL_WATCHDOG_MS, 'Garage first verify');
    expect(firstAgain.sha256).toBe(sha256Hex(firstPayload));
    const secondAgain = await bounded(adapter.verifyQuarantined(secondAttempt, {
      expectedBytes: second.actualBytes, sha256: second.sha256, maxBytes: secondPayload.byteLength, signal: SIGNAL,
    }), CALL_WATCHDOG_MS, 'Garage second verify');
    expect(secondAgain.sha256).toBe(sha256Hex(secondPayload));
  });

  it('never overwrites a stored key when another adapter instance replays the descriptor', async () => {
    const first = newAdapter();
    const second = newAdapter();
    const payload = syntheticPayload(6 * 1024, 'garage-nooverwrite');
    const attempt = first.prepareQuarantineAttempt();
    const put = await bounded(first.putQuarantined(attempt, {
      body: asyncChunks([payload]),
      expectedBytes: payload.byteLength, maxBytes: payload.byteLength, signal: SIGNAL,
    }), CALL_WATCHDOG_MS, 'Garage PUT for no-overwrite');

    const replay = await settle(second.putQuarantined(attempt, {
      body: asyncChunks([syntheticPayload(1_024, 'replacement')]),
      expectedBytes: 1_024, maxBytes: 1_024, signal: SIGNAL,
    }));
    expect(replay.ok).toBe(false);
    if (!replay.ok) {
      expect(storageCode(replay.error)).toBe('ATTEMPT_CONSUMED');
    }
    // The stored bytes are still the first attempt's bytes, and their hash is unchanged.
    const stored = await bounded(second.verifyQuarantined(attempt, {
      expectedBytes: put.actualBytes, sha256: put.sha256, maxBytes: payload.byteLength, signal: SIGNAL,
    }), CALL_WATCHDOG_MS, 'Garage verify after replay');
    expect(stored.sha256).toBe(sha256Hex(payload));
  });

  it('copies a mutable caller chunk so a later mutation cannot change sent bytes or the hash', async () => {
    const adapter = newAdapter();
    const original = syntheticPayload(16 * 1024, 'garage-mutable');
    const expected = sha256Hex(original);
    const mutable = original.slice();
    const attempt = adapter.prepareQuarantineAttempt();

    const receipt = await bounded(adapter.putQuarantined(attempt, {
      // Mutate the caller buffer *after* it was handed over but before the PUT
      // completes: a non-copying adapter would send/hash the mutated bytes.
      body: mutableThenMutated(mutable),
      expectedBytes: original.byteLength, maxBytes: original.byteLength, signal: SIGNAL,
    }), CALL_WATCHDOG_MS, 'Garage PUT mutable chunk');

    expect(receipt.sha256).toBe(expected);
    const verified = await bounded(adapter.verifyQuarantined(attempt, {
      expectedBytes: original.byteLength, sha256: expected, maxBytes: original.byteLength, signal: SIGNAL,
    }), CALL_WATCHDOG_MS, 'Garage verify mutable chunk');
    expect(verified.sha256).toBe(expected);
  });

  it('keeps the bucket private: anonymous, wrong credentials and read-only PUT are denied', async () => {
    const adapter = newAdapter();
    const payload = syntheticPayload(1_024, 'garage-private');
    const attempt = adapter.prepareQuarantineAttempt();
    const put = await bounded(adapter.putQuarantined(attempt, {
      body: asyncChunks([payload]),
      expectedBytes: payload.byteLength, maxBytes: payload.byteLength, signal: SIGNAL,
    }), CALL_WATCHDOG_MS, 'Garage PUT for privacy');

    // Anonymous PUT to a fresh synthetic key: 403, and nothing is created. This is
    // a plain unsigned HTTP request, i.e. genuinely anonymous (no credential chain).
    const anonymousKey = `quarantine/${randomUUID()}/${randomUUID()}`;
    const anonymousUrl = new URL(GARAGE_ENDPOINT);
    anonymousUrl.pathname = `/${GARAGE_BUCKET}/${anonymousKey}`;
    const anonymous = await fetch(anonymousUrl, {
      method: 'PUT',
      body: Buffer.from([1, 2, 3]),
      redirect: 'error',
      signal: AbortSignal.timeout(config.requestTimeoutMs),
    });
    try {
      expect(anonymous.status).toBe(403);
    } finally {
      // Never parse or print a Garage error body.
      await anonymous.body?.cancel();
    }
    // The anonymous key really does not exist.
    expect(await statusOf(() => raw().send(new HeadObjectCommand({
      Bucket: GARAGE_BUCKET, Key: anonymousKey,
    })))).toBe(404);

    // A private bucket must also deny *reads* of a known uploaded attempt key: a
    // GET/HEAD of the exact object the adapter just wrote must be 403 for an
    // unauthenticated caller, and no object bytes/metadata may be returned. Only the
    // status and the absence of object content are inspected; the URL/key is never
    // printed.
    const uploadedUrl = new URL(GARAGE_ENDPOINT);
    uploadedUrl.pathname = `/${GARAGE_BUCKET}/${attempt.objectKey}`;
    const anonymousGet = await fetch(uploadedUrl, {
      method: 'GET',
      redirect: 'error',
      signal: AbortSignal.timeout(config.requestTimeoutMs),
    });
    // The body is read to completion below, so no separate cancel is needed (a
    // consumed stream cannot be cancelled again).
    expect(anonymousGet.status).toBe(403);
    // The denied response must be the short error document, never the object bytes
    // (no payload prefix, no matching digest). The URL/key is never printed.
    const deniedBytes = new Uint8Array(await anonymousGet.arrayBuffer());
    expect(deniedBytes.byteLength).toBeLessThan(payload.byteLength);
    expect(sha256Hex(deniedBytes)).not.toBe(sha256Hex(payload));
    const prefixLength = Math.min(64, payload.byteLength);
    const payloadPrefix = Buffer.from(payload.subarray(0, prefixLength));
    expect(Buffer.from(deniedBytes).includes(payloadPrefix)).toBe(false);
    const anonymousHead = await fetch(uploadedUrl, {
      method: 'HEAD',
      redirect: 'error',
      signal: AbortSignal.timeout(config.requestTimeoutMs),
    });
    try {
      expect(anonymousHead.status).toBe(403);
      // HEAD must not expose the object's metadata: no ETag, no object content type.
      expect(anonymousHead.headers.get('etag')).toBeNull();
      expect(anonymousHead.headers.get('x-amz-meta-sha256')).toBeNull();
      expect(anonymousHead.headers.get('content-type') ?? '').not.toContain('application/octet-stream');
    } finally {
      await anonymousHead.body?.cancel();
    }

    // Wrong credentials are refused by Garage for the adapter's own target too.
    const wrong = wrongCredentials();
    const badAdapter = newAdapter({ accessKeyId: wrong.accessKeyId, secretAccessKey: wrong.secretAccessKey });
    const badAttempt = badAdapter.prepareQuarantineAttempt();
    const denied = await settle(bounded(badAdapter.putQuarantined(badAttempt, {
      body: asyncChunks([new Uint8Array([1, 2, 3, 4])]),
      expectedBytes: 4, maxBytes: 4, signal: SIGNAL,
    }), CALL_WATCHDOG_MS, 'Garage wrong-credential PUT'));
    expect(denied.ok).toBe(false);
    if (!denied.ok) {
      // A 403 after the PUT started is still an UNKNOWN outcome, never "not written".
      expect(storageCode(denied.error)).toBe('WRITE_OUTCOME_UNKNOWN');
      assertSafeFailure(denied.error, [config.accessKeyId, config.secretAccessKey, config.endpoint, badAttempt.objectKey]);
    }

    // Wrong credentials must also be refused for a *read* of the known object, and
    // the SDK error must be a real 403, not an undefined status.
    const wrongRead = new S3Client({
      endpoint: config.endpoint,
      region: config.region,
      forcePathStyle: true,
      maxAttempts: 1,
      credentials: { accessKeyId: wrong.accessKeyId, secretAccessKey: wrong.secretAccessKey },
      requestHandler: {
        connectionTimeout: config.connectionTimeoutMs,
        requestTimeout: config.requestTimeoutMs,
        socketTimeout: config.socketTimeoutMs,
        throwOnRequestTimeout: true,
      },
    });
    try {
      expect(await statusOf(() => wrongRead.send(new HeadObjectCommand({
        Bucket: GARAGE_BUCKET, Key: attempt.objectKey,
      })))).toBe(403);
    } finally {
      wrongRead.destroy();
    }

    // The read-only key can read but cannot write: a PUT with it is denied.
    const readonly = loadGarageCredentials(true);
    const readonlyAdapter = newAdapter({ accessKeyId: readonly.accessKeyId, secretAccessKey: readonly.secretAccessKey });
    const readonlyAttempt = readonlyAdapter.prepareQuarantineAttempt();
    const readonlyDenied = await settle(bounded(readonlyAdapter.putQuarantined(readonlyAttempt, {
      body: asyncChunks([new Uint8Array([9, 9, 9, 9])]),
      expectedBytes: 4, maxBytes: 4, signal: SIGNAL,
    }), CALL_WATCHDOG_MS, 'Garage read-only PUT'));
    expect(readonlyDenied.ok).toBe(false);
    if (!readonlyDenied.ok) {
      expect(storageCode(readonlyDenied.error)).toBe('WRITE_OUTCOME_UNKNOWN');
      assertSafeFailure(readonlyDenied.error, [readonly.accessKeyId, readonly.secretAccessKey, config.endpoint]);
    }

    // The original object is intact after all denied writes.
    const stored = await bounded(adapter.verifyQuarantined(attempt, {
      expectedBytes: put.actualBytes, sha256: put.sha256, maxBytes: payload.byteLength, signal: SIGNAL,
    }), CALL_WATCHDOG_MS, 'Garage verify after denials');
    expect(stored.sha256).toBe(sha256Hex(payload));
  });
});
