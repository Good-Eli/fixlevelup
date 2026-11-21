/**
 * Unit proofs for the P03-04B **B1** standalone private quarantine storage adapter
 * that need no S3 service and no object bytes: the closed configuration, the
 * absence of implicit IO/default credentials, one-shot descriptor identity,
 * pre-send input limits, closed-adapter behaviour and the safe error envelope.
 *
 * Nothing here is a policy decision. `expectedBytes`/`maxBytes`, timeouts, chunk
 * ceiling and concurrency ceiling are explicit technical test parameters; the
 * adapter is required to refuse a missing value rather than invent one.
 *
 * The only sockets involved are loopback witnesses that must receive **nothing**
 * (a factory or a pre-send refusal must not dial), plus a closed loopback port used
 * to spend a descriptor without reaching any S3 service.
 *
 * The error vocabulary is the adapter's frozen contract (see
 * `apps/api/src/files/storage/errors.ts`); assertions check behaviour plus the
 * typed code, never a raw SDK error or a message string.
 */
import { afterEach, describe, expect, it } from 'vitest';
import * as storage from '../src/files/storage/index.js';
import {
  assertSafeFailure, asyncChunks, errorText, loopback, loopbackConfig, refusedEndpoint, settle, sleep, storageCode,
  syntheticCredentials, syntheticPayload, watchUnhandledRejections,
} from './file-storage-fixture.js';
import type { StorageTestConfig } from './file-storage-fixture.js';

/** Frozen typed refusal vocabulary (adapter contract, P03-04B B1). */
const CODES = {
  invalidConfig: 'INVALID_CONFIG',
  productionDisabled: 'PRODUCTION_DISABLED',
  invalidInput: 'INVALID_INPUT',
  closed: 'CLOSED',
  attemptInvalid: 'ATTEMPT_INVALID',
  attemptConsumed: 'ATTEMPT_CONSUMED',
  attemptTargetMismatch: 'ATTEMPT_TARGET_MISMATCH',
  attemptNotWritten: 'ATTEMPT_NOT_WRITTEN',
  aborted: 'ABORTED',
  writeUnknown: 'WRITE_OUTCOME_UNKNOWN',
} as const;

/** Caller-supplied marker that must never survive into an adapter failure. */
const MARKER = 'SYNTHETIC_PRIVATE_MARKER';

/** Optional internal reason on a typed failure (frozen constants). */
function storageReason(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) {
    return undefined;
  }
  const value: unknown = (error as { reason?: unknown }).reason;
  return typeof value === 'string' ? value : undefined;
}

type Adapter = ReturnType<typeof storage.createPrivateQuarantineStorage>;

const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    await cleanup?.();
  }
});

/** Registers a fixture cleanup that runs even when an assertion fails. */
function using<T extends { close(): Promise<void> }>(fixture: T): T {
  cleanups.push(async () => { await fixture.close(); });
  return fixture;
}

/** Creates an adapter and registers its close; the factory must be synchronous. */
function createAdapter(config: StorageTestConfig): Adapter {
  const adapter = storage.createPrivateQuarantineStorage(config);
  expect(typeof (adapter as { then?: unknown }).then).not.toBe('function');
  cleanups.push(async () => { await adapter.close(); });
  return adapter;
}

/** A body that fails the test if the adapter consumes it before validating input. */
function unconsumedBody(): AsyncIterable<Uint8Array> {
  return {
    [Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
      return {
        next(): Promise<IteratorResult<Uint8Array>> {
          return Promise.reject(new Error('The adapter consumed the body before validating its input.'));
        },
      };
    },
  };
}

const SIGNAL = new AbortController().signal;
const PRE_ABORTED = AbortSignal.abort();

/** Asserts one typed refusal and returns `{code, reason}`. */
async function refusal(action: () => Promise<unknown>): Promise<{ code: string; reason?: string }> {
  const settled = await settle(action());
  expect(settled.ok).toBe(false);
  if (settled.ok) {
    throw new Error('Expected a typed storage refusal, received success.');
  }
  const code = storageCode(settled.error);
  expect(code, `expected a typed refusal, got: ${errorText(settled.error)}`).toBeDefined();
  expect(settled.error).toBeInstanceOf(Error);
  const reason = storageReason(settled.error);
  return reason === undefined ? { code: code ?? '' } : { code: code ?? '', reason };
}

/** Returns the factory refusal code, or `undefined` when the config is accepted. */
function factoryCode(config: unknown): string | undefined {
  try {
    storage.createPrivateQuarantineStorage(config as StorageTestConfig);
    return undefined;
  } catch (error: unknown) {
    return storageCode(error);
  }
}

/** Asserts a synchronous factory refusal and returns its code. */
function factoryRefusal(config: unknown): string {
  const code = factoryCode(config);
  expect(code, 'expected the factory to refuse this configuration').toBeDefined();
  return code ?? '';
}

describe('private quarantine storage: closed configuration', () => {
  it('accepts a valid local-synthetic config first, so the negative cases are meaningful', () => {
    // Positive control: the exact frozen 14-field shape (including the mandatory
    // response-body cap) is usable. Without this, every negative case could "pass"
    // against a factory that refuses everything.
    const adapter = createAdapter(loopbackConfig('http://127.0.0.1:3901'));
    for (const name of ['prepareQuarantineAttempt', 'putQuarantined', 'verifyQuarantined', 'close']) {
      expect(typeof (adapter as unknown as Record<string, unknown>)[name]).toBe('function');
    }
    // Port 3900 is a valid target too: the adapter does not special-case Garage.
    const garagePort = createAdapter(loopbackConfig('http://127.0.0.1:3900'));
    expect(typeof garagePort.close).toBe('function');
  });

  it('refuses a missing or unknown mode instead of defaulting to a usable one', () => {
    const base = loopbackConfig('http://127.0.0.1:3901');
    const invalid: unknown[] = [
      { ...base, mode: undefined },
      { ...base, mode: 'local' },
      { ...base, mode: 'LOCAL-SYNTHETIC' },
      { ...base, mode: 'staging' },
      { ...base, mode: '' },
    ];
    for (const config of invalid) {
      expect(factoryRefusal(config)).toBe(CODES.invalidConfig);
    }
  });

  it('refuses production mode even with an https endpoint: production IO stays disabled', () => {
    const base = loopbackConfig('http://127.0.0.1:3901');
    for (const endpoint of ['https://storage.example.invalid', 'http://127.0.0.1:3901']) {
      expect(factoryRefusal({ ...base, mode: 'production', endpoint, allowedEndpoint: endpoint }))
        .toBe(CODES.productionDisabled);
    }
  });

  it('in local-synthetic mode accepts only literal 127.0.0.1 HTTP with an explicit port', () => {
    const base = loopbackConfig('http://127.0.0.1:3901');
    const rejected = [
      'https://127.0.0.1:3901',
      'http://localhost:3901',
      'http://0.0.0.0:3901',
      'http://[::1]:3901',
      'http://127.0.0.2:3901',
      'http://127.0.0.1',
      'http://127.0.0.1:0',
      'http://127.0.0.1:65536',
      'http://127.0.0.1:3901/bucket',
      'http://127.0.0.1:3901?x=1',
      'http://127.0.0.1:3901#fragment',
      'http://user:secret@127.0.0.1:3901',
      '127.0.0.1:3901',
      '',
    ];
    for (const endpoint of rejected) {
      expect(factoryRefusal({ ...base, endpoint, allowedEndpoint: endpoint })).toBe(CODES.invalidConfig);
    }
  });

  it('requires the dialled endpoint to equal allowedEndpoint exactly, and rejects extra keys', () => {
    const base = loopbackConfig('http://127.0.0.1:3901');
    const mismatches: unknown[] = [
      { ...base, allowedEndpoint: 'http://127.0.0.1:3902' },
      { ...base, allowedEndpoint: 'https://127.0.0.1:3901' },
      { ...base, allowedEndpoint: undefined },
      { ...base, allowedEndpoint: '' },
      { ...base, endpoint: 'http://127.0.0.1:3902', allowedEndpoint: 'http://127.0.0.1:3901' },
      // The config is closed: an extra key from a dead draft is refused, not ignored.
      { ...base, allowLoopbackTestPorts: [3901] },
      { ...base, operationDeadlineMs: 1_000 },
    ];
    for (const config of mismatches) {
      expect(factoryRefusal(config)).toBe(CODES.invalidConfig);
    }
    // A trailing slash is canonicalized, so it matches the same port.
    const slash = createAdapter({ ...base, endpoint: 'http://127.0.0.1:3901/', allowedEndpoint: 'http://127.0.0.1:3901' });
    expect(typeof slash.close).toBe('function');
  });

  it('refuses missing or blank credentials even when the default provider chain is populated', () => {
    const base = loopbackConfig('http://127.0.0.1:3901');
    const fallback = syntheticCredentials('env-fallback');
    const previous = new Map<string, string | undefined>();
    for (const [name, value] of [
      ['AWS_ACCESS_KEY_ID', fallback.accessKeyId],
      ['AWS_SECRET_ACCESS_KEY', fallback.secretAccessKey],
      ['AWS_PROFILE', 'default'],
      ['AWS_ROLE_ARN', 'arn:aws:iam::000000000000:role/synthetic'],
      ['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI', '/v2/credentials/synthetic'],
    ] as const) {
      previous.set(name, process.env[name]);
      process.env[name] = value;
    }
    try {
      const invalid: unknown[] = [
        { ...base, accessKeyId: undefined },
        { ...base, secretAccessKey: undefined },
        { ...base, accessKeyId: '' },
        { ...base, secretAccessKey: '' },
        { ...base, accessKeyId: '   ' },
      ];
      for (const config of invalid) {
        expect(factoryRefusal(config)).toBe(CODES.invalidConfig);
      }
    } finally {
      for (const [name, value] of previous) {
        if (value === undefined) {
          // Restore "unset" without a computed-key delete.
          Reflect.deleteProperty(process.env, name);
        } else {
          process.env[name] = value;
        }
      }
    }
  });

  it('refuses missing, non-integer or out-of-range technical bounds and resource ceilings', () => {
    const base = loopbackConfig('http://127.0.0.1:3901');
    const invalid: unknown[] = [
      { ...base, connectionTimeoutMs: 0 },
      { ...base, requestTimeoutMs: -1 },
      { ...base, socketTimeoutMs: 1.5 },
      { ...base, requestTimeoutMs: Number.NaN },
      { ...base, socketTimeoutMs: Number.POSITIVE_INFINITY },
      { ...base, connectionTimeoutMs: undefined },
      { ...base, requestTimeoutMs: undefined },
      { ...base, socketTimeoutMs: undefined },
      { ...base, region: '' },
      { ...base, bucket: '' },
      // The operation deadline and the resource ceilings are mandatory too: the
      // adapter must not invent a default concurrency, chunk or operation bound.
      { ...base, operationTimeoutMs: undefined },
      { ...base, operationTimeoutMs: 0 },
      { ...base, operationTimeoutMs: -1 },
      { ...base, operationTimeoutMs: 1.5 },
      { ...base, operationTimeoutMs: 3_600_001 },
      { ...base, maxChunkBytes: undefined },
      { ...base, maxChunkBytes: 0 },
      { ...base, maxChunkBytes: -1024 },
      { ...base, maxChunkBytes: 1.5 },
      { ...base, maxChunkBytes: 67_108_865 },
      { ...base, maxConcurrentOperations: undefined },
      { ...base, maxConcurrentOperations: 0 },
      { ...base, maxConcurrentOperations: -1 },
      { ...base, maxConcurrentOperations: 1.5 },
      { ...base, maxConcurrentOperations: 65 },
      { ...base, maxConcurrentOperations: Number.POSITIVE_INFINITY },
      // The response-body cap is a mandatory technical bound too: a missing, zero,
      // negative, fractional or non-finite value must be refused, never defaulted.
      { ...base, maxResponseBodyBytes: undefined },
      { ...base, maxResponseBodyBytes: 0 },
      { ...base, maxResponseBodyBytes: -1 },
      { ...base, maxResponseBodyBytes: 1.5 },
      { ...base, maxResponseBodyBytes: Number.NaN },
      { ...base, maxResponseBodyBytes: Number.POSITIVE_INFINITY },
      { ...base, maxResponseBodyBytes: Number.MAX_SAFE_INTEGER + 2 },
    ];
    for (const config of invalid) {
      expect(factoryRefusal(config)).toBe(CODES.invalidConfig);
    }
  });
});

describe('private quarantine storage: no implicit IO', () => {
  it('creates no network IO and no request when the factory runs', async () => {
    const fixture = using(await loopback(() => { /* must never be called */ }));
    const adapter = createAdapter(loopbackConfig(fixture.endpoint));
    await sleep(150);
    expect(fixture.requests).toHaveLength(0);
    expect(fixture.sockets.size).toBe(0);
    // A prepared attempt is also pure: no IO until put/verify is called.
    const attempt = adapter.prepareQuarantineAttempt();
    expect(typeof attempt.attemptId).toBe('string');
    expect(typeof attempt.objectKey).toBe('string');
    expect(attempt.objectKey).toMatch(/^quarantine\/[0-9a-f-]{36}\/[0-9a-f-]{36}$/);
    await sleep(100);
    expect(fixture.requests).toHaveLength(0);
  });

  it('generates an independent attempt id and key per call, through the adapter or the module function', () => {
    const adapter = createAdapter(loopbackConfig('http://127.0.0.1:3901'));
    const first = adapter.prepareQuarantineAttempt();
    const second = storage.prepareQuarantineAttempt();
    const third = adapter.prepareQuarantineAttempt();
    expect(new Set([first.attemptId, second.attemptId, third.attemptId]).size).toBe(3);
    expect(new Set([first.objectKey, second.objectKey, third.objectKey]).size).toBe(3);
    for (const attempt of [first, second, third]) {
      // The first key segment is the attempt id: one source of truth, no PII.
      expect(attempt.objectKey.startsWith(`quarantine/${attempt.attemptId}/`)).toBe(true);
      // The descriptor is opaque, frozen and never a JSON authority.
      expect(Object.isFrozen(attempt)).toBe(true);
    }
  });

  it('refuses a forged, borrowed or serialized descriptor before any IO', async () => {
    const fixture = using(await loopback(() => { /* must never be called */ }));
    const adapter = createAdapter(loopbackConfig(fixture.endpoint));
    const real = adapter.prepareQuarantineAttempt();
    const forged: unknown[] = [
      { attemptId: real.attemptId, objectKey: real.objectKey },
      { ...real },
      { attemptId: real.attemptId, objectKey: 'synthetic/not-a-quarantine-key' },
      { attemptId: real.attemptId, objectKey: `quarantine/../../${real.attemptId}` },
      { attemptId: 'not-a-uuid', objectKey: real.objectKey },
      { attemptId: real.attemptId },
      JSON.parse(JSON.stringify(real)) as unknown,
      JSON.parse(JSON.stringify({ attemptId: real.attemptId, objectKey: real.objectKey })) as unknown,
      Object.create(null) as unknown,
    ];
    for (const attempt of forged) {
      expect((await refusal(() => adapter.putQuarantined(
        attempt as never,
        { body: unconsumedBody(), expectedBytes: 4, maxBytes: 8, signal: SIGNAL },
      ))).code).toBe(CODES.attemptInvalid);
    }
    expect(fixture.requests).toHaveLength(0);
  });
});

describe('private quarantine storage: pre-send input limits', () => {
  it('refuses unsafe expected/max byte combinations before consuming the body', async () => {
    const fixture = using(await loopback(() => { /* must never be called */ }));
    const adapter = createAdapter(loopbackConfig(fixture.endpoint));
    const invalid = [
      { expectedBytes: 0, maxBytes: 8 },
      { expectedBytes: -1, maxBytes: 8 },
      { expectedBytes: 1.5, maxBytes: 8 },
      { expectedBytes: Number.NaN, maxBytes: 8 },
      { expectedBytes: Number.POSITIVE_INFINITY, maxBytes: 8 },
      { expectedBytes: Number.MAX_SAFE_INTEGER + 2, maxBytes: Number.MAX_SAFE_INTEGER + 2 },
      { expectedBytes: 9, maxBytes: 8 },
      { expectedBytes: 1, maxBytes: 0 },
      { expectedBytes: 1, maxBytes: -8 },
      { expectedBytes: 1, maxBytes: 1.5 },
      { expectedBytes: undefined, maxBytes: 8 },
      { expectedBytes: 1, maxBytes: undefined },
    ];
    for (const input of invalid) {
      const attempt = adapter.prepareQuarantineAttempt();
      expect((await refusal(() => adapter.putQuarantined(
        attempt,
        { body: unconsumedBody(), signal: SIGNAL, ...input } as never,
      ))).code).toBe(CODES.invalidInput);
    }
    // A body without an async iterator is a pre-send input error, not a PUT.
    const attempt = adapter.prepareQuarantineAttempt();
    expect((await refusal(() => adapter.putQuarantined(
      attempt,
      { body: {} as never, expectedBytes: 2, maxBytes: 8, signal: SIGNAL },
    ))).code).toBe(CODES.invalidInput);
    // A missing/invalid signal is a pre-send input error too.
    const noSignal = adapter.prepareQuarantineAttempt();
    expect((await refusal(() => adapter.putQuarantined(
      noSignal,
      { body: unconsumedBody(), expectedBytes: 2, maxBytes: 8, signal: undefined } as never,
    ))).code).toBe(CODES.invalidInput);
    expect(fixture.requests).toHaveLength(0);
  });

  it('refuses an already-aborted signal before starting the PUT', async () => {
    const fixture = using(await loopback(() => { /* must never be called */ }));
    const adapter = createAdapter(loopbackConfig(fixture.endpoint));
    const attempt = adapter.prepareQuarantineAttempt();
    expect((await refusal(() => adapter.putQuarantined(
      attempt,
      { body: unconsumedBody(), expectedBytes: 4, maxBytes: 8, signal: PRE_ABORTED },
    ))).code).toBe(CODES.aborted);
    expect(fixture.requests).toHaveLength(0);
  });

  it('refuses an invalid verify sha256 or byte bound before reading, and verify-before-put', async () => {
    const fixture = using(await loopback(() => { /* must never be called */ }));
    const adapter = createAdapter(loopbackConfig(fixture.endpoint));
    const attempt = adapter.prepareQuarantineAttempt();
    const invalid = [
      { expectedBytes: 4, maxBytes: 8, sha256: 'not-a-digest' },
      { expectedBytes: 4, maxBytes: 8, sha256: 'A'.repeat(64) },
      { expectedBytes: 4, maxBytes: 8, sha256: '' },
      { expectedBytes: 0, maxBytes: 8, sha256: 'a'.repeat(64) },
      { expectedBytes: 9, maxBytes: 8, sha256: 'a'.repeat(64) },
      { expectedBytes: 4, maxBytes: 8, sha256: undefined },
    ];
    for (const input of invalid) {
      expect((await refusal(() => adapter.verifyQuarantined(
        attempt,
        { signal: SIGNAL, ...input } as never,
      ))).code).toBe(CODES.invalidInput);
    }
    // A well-formed verify of a descriptor that never completed a PUT can never be
    // mistaken for a successful storage check.
    expect((await refusal(() => adapter.verifyQuarantined(
      attempt,
      { expectedBytes: 4, maxBytes: 8, sha256: 'a'.repeat(64), signal: SIGNAL },
    ))).code).toBe(CODES.attemptNotWritten);
    // A pre-aborted verify is refused as ABORTED, not as a read failure.
    expect((await refusal(() => adapter.verifyQuarantined(
      attempt,
      { expectedBytes: 4, maxBytes: 8, sha256: 'a'.repeat(64), signal: PRE_ABORTED },
    ))).code).toBe(CODES.aborted);
    expect(fixture.requests).toHaveLength(0);
  });
});

describe('private quarantine storage: closed adapter and one-shot identity', () => {
  it('refuses new operations after close and tolerates a repeated close', async () => {
    const fixture = using(await loopback(() => { /* must never be called */ }));
    const adapter = createAdapter(loopbackConfig(fixture.endpoint));
    const attempt = adapter.prepareQuarantineAttempt();
    await adapter.close();
    expect((await refusal(() => adapter.putQuarantined(
      attempt,
      { body: unconsumedBody(), expectedBytes: 4, maxBytes: 8, signal: SIGNAL },
    ))).code).toBe(CODES.closed);
    expect((await refusal(() => adapter.verifyQuarantined(
      attempt,
      { expectedBytes: 4, maxBytes: 8, sha256: 'a'.repeat(64), signal: SIGNAL },
    ))).code).toBe(CODES.closed);
    // Repeated close must stay safe (no throw, no detached IO).
    await adapter.close();
    expect(fixture.requests).toHaveLength(0);
  });

  it('refuses null/undefined raw inputs with a typed error instead of a TypeError', async () => {
    const fixture = using(await loopback(() => { /* must never be called */ }));
    const adapter = createAdapter(loopbackConfig(fixture.endpoint));
    const attempt = adapter.prepareQuarantineAttempt();
    // A raw null/undefined/garbage input must be a typed refusal, never a
    // TypeError escaping the adapter or a defaulted "empty upload".
    const rawInputs: unknown[] = [null, undefined, 0, '', true, [], [1, 2], new Uint8Array(0)];
    for (const input of rawInputs) {
      const put = await refusal(() => adapter.putQuarantined(attempt, input as never));
      expect([CODES.invalidInput, CODES.attemptInvalid]).toContain(put.code);
      const verify = await refusal(() => adapter.verifyQuarantined(attempt, input as never));
      expect([CODES.invalidInput, CODES.attemptInvalid]).toContain(verify.code);
    }
    // A null attempt is refused the same way, and never consumed.
    for (const rawAttempt of [null, undefined, 0, 'attempt']) {
      const put = await refusal(() => adapter.putQuarantined(
        rawAttempt as never,
        { body: unconsumedBody(), expectedBytes: 4, maxBytes: 8, signal: SIGNAL },
      ));
      expect(put.code).toBe(CODES.attemptInvalid);
    }
    expect(fixture.requests).toHaveLength(0);
  });

  it('refuses prepareQuarantineAttempt on a closed adapter while the module function still works', async () => {
    const adapter = createAdapter(loopbackConfig('http://127.0.0.1:3901'));
    await adapter.close();
    // The adapter method is bound to a dead instance: it must refuse, not hand out
    // a descriptor that could never be used.
    let closedCode: string | undefined;
    try {
      adapter.prepareQuarantineAttempt();
    } catch (error: unknown) {
      closedCode = storageCode(error);
    }
    expect(closedCode).toBe(CODES.closed);
    // The module-level factory has no adapter state and keeps working; it is pure
    // and the descriptor it returns is still a valid one-shot identity.
    const moduleAttempt = storage.prepareQuarantineAttempt();
    expect(Object.isFrozen(moduleAttempt)).toBe(true);
    expect(moduleAttempt.objectKey.startsWith(`quarantine/${moduleAttempt.attemptId}/`)).toBe(true);
  });

  it('refuses a body whose asyncIterator getter throws, without echoing the caller error', async () => {
    const fixture = using(await loopback(() => { /* must never be called */ }));
    const adapter = createAdapter(loopbackConfig(fixture.endpoint));
    const attempt = adapter.prepareQuarantineAttempt();
    // A hostile body: reading `Symbol.asyncIterator` itself throws. The adapter must
    // turn that into its own typed refusal, never surface the caller's raw error.
    const hostileBody = {
      get [Symbol.asyncIterator](): never {
        throw new Error('RAW_CALLER_SECRET_MARKER');
      },
    };
    const settled = await settle(adapter.putQuarantined(
      attempt,
      { body: hostileBody as never, expectedBytes: 4, maxBytes: 8, signal: SIGNAL },
    ));
    expect(settled.ok).toBe(false);
    if (!settled.ok) {
      expect(storageCode(settled.error)).toBe(CODES.invalidInput);
      const text = errorText(settled.error);
      expect(text.includes('RAW_CALLER_SECRET_MARKER')).toBe(false);
      expect((settled.error as Error).message).toBe(CODES.invalidInput);
    }
    expect(fixture.requests).toHaveLength(0);
  });

  it('refuses a second call with CONCURRENCY_LIMIT when the only slot is in flight', async () => {
    // maxConcurrentOperations:1, the first PUT is stalled in flight (server never
    // answers), so a second call must be refused immediately rather than queued.
    const fixture = using(await loopback(() => { /* never respond */ }));
    const config = loopbackConfig(fixture.endpoint, { maxConcurrentOperations: 1 });
    const adapter = createAdapter(config);
    const firstAttempt = adapter.prepareQuarantineAttempt();
    const payload = syntheticPayload(1_024, 'concurrency');
    const pending = settle(adapter.putQuarantined(firstAttempt, {
      body: asyncChunks([payload]),
      expectedBytes: payload.byteLength, maxBytes: payload.byteLength, signal: SIGNAL,
    }));
    // Wait until the first operation is genuinely in flight at the transport.
    await fixture.waitForRequest(2_000);
    const secondAttempt = adapter.prepareQuarantineAttempt();
    expect((await refusal(() => adapter.putQuarantined(secondAttempt, {
      body: unconsumedBody(), expectedBytes: 4, maxBytes: 8, signal: SIGNAL,
    }))).code).toBe('CONCURRENCY_LIMIT');
    // The refused call never reached the transport: only the first request exists.
    expect(fixture.requests).toHaveLength(1);
    // Close aborts the in-flight first operation; it must settle as UNKNOWN.
    await adapter.close();
    const first = await pending;
    expect(first.ok).toBe(false);
    if (!first.ok) {
      expect(storageCode(first.error)).toBe(CODES.writeUnknown);
    }
  });

  it('consumes a descriptor module-wide: another adapter instance cannot reuse it', async () => {
    // A closed port spends the descriptor without reaching any S3 service: the
    // outcome is a typed UNKNOWN and the descriptor stays one-shot for every
    // adapter in the process.
    const endpoint = await refusedEndpoint();
    const first = createAdapter(loopbackConfig(endpoint));
    const second = createAdapter(loopbackConfig(endpoint));
    const attempt = first.prepareQuarantineAttempt();
    const spent = await refusal(() => first.putQuarantined(
      attempt,
      { body: asyncChunks([]), expectedBytes: 1, maxBytes: 8, signal: SIGNAL },
    ));
    expect(spent.code).toBe(CODES.writeUnknown);
    expect((await refusal(() => second.putQuarantined(
      attempt,
      { body: unconsumedBody(), expectedBytes: 4, maxBytes: 8, signal: SIGNAL },
    ))).code).toBe(CODES.attemptConsumed);
    const third = createAdapter(loopbackConfig(endpoint));
    expect((await refusal(() => third.putQuarantined(
      attempt,
      { body: unconsumedBody(), expectedBytes: 4, maxBytes: 8, signal: SIGNAL },
    ))).code).toBe(CODES.attemptConsumed);
  });
});

describe('private quarantine storage: safe error envelope', () => {
  it('never echoes credentials, endpoint, object key or signing markers', async () => {
    const fixture = using(await loopback(() => { /* no IO expected */ }));
    const config = loopbackConfig(fixture.endpoint);
    const adapter = createAdapter(config);
    const attempt = adapter.prepareQuarantineAttempt();
    const secrets = [config.accessKeyId, config.secretAccessKey];
    const forbidden = [fixture.endpoint, attempt.objectKey, attempt.attemptId];

    const cases: Array<() => Promise<unknown>> = [
      () => adapter.putQuarantined(attempt, { body: unconsumedBody(), expectedBytes: 0, maxBytes: 8, signal: SIGNAL }),
      () => adapter.putQuarantined(
        { attemptId: attempt.attemptId, objectKey: 'synthetic/other' },
        { body: unconsumedBody(), expectedBytes: 1, maxBytes: 8, signal: SIGNAL },
      ),
      () => adapter.verifyQuarantined(attempt, { expectedBytes: 1, maxBytes: 8, sha256: 'bad', signal: SIGNAL }),
    ];
    for (const action of cases) {
      const settled = await settle(action());
      expect(settled.ok).toBe(false);
      if (settled.ok) {
        continue;
      }
      assertSafeFailure(settled.error, secrets, forbidden);
      const serialized = JSON.stringify(settled.error);
      for (const value of [...secrets, ...forbidden]) {
        expect(serialized.includes(value)).toBe(false);
      }
      // `message` is exactly the code: no free text can smuggle a value out.
      expect((settled.error as Error).message).toBe(storageCode(settled.error));
    }
    expect(fixture.requests).toHaveLength(0);
  });

  it('keeps the secret out of the adapter object and exposes no delete/list/presign surface', () => {
    const config = loopbackConfig('http://127.0.0.1:3901');
    const adapter = createAdapter(config);
    // Only enumerable own data could ever be serialized; the adapter is a class
    // instance with private fields, so nothing secret is reachable that way.
    const surface = JSON.stringify(adapter) + Object.keys(adapter).join(',');
    expect(surface.includes(config.secretAccessKey)).toBe(false);
    for (const name of [
      'delete', 'deleteObject', 'deleteQuarantined', 'list', 'listQuarantined', 'listObjects',
      'createBucket', 'getSignedUrl', 'presign', 'signedUrl', 'publicUrl', 'head',
    ]) {
      expect(Object.hasOwn(storage, name)).toBe(false);
      expect(Object.hasOwn(adapter as unknown as object, name)).toBe(false);
    }
    for (const name of ['prepareQuarantineAttempt', 'putQuarantined', 'verifyQuarantined', 'close']) {
      expect(typeof (adapter as unknown as Record<string, unknown>)[name]).toBe('function');
    }
  });

  it('leaves no unhandled rejection behind a refused call', async () => {
    const watch = watchUnhandledRejections();
    try {
      const fixture = using(await loopback(() => { /* no IO expected */ }));
      const adapter = createAdapter(loopbackConfig(fixture.endpoint));
      const attempt = adapter.prepareQuarantineAttempt();
      await refusal(() => adapter.putQuarantined(
        attempt,
        { body: unconsumedBody(), expectedBytes: 0, maxBytes: 8, signal: SIGNAL },
      ));
      await sleep(200);
      expect(watch.rejections).toHaveLength(0);
    } finally {
      watch.stop();
    }
  });
});

/**
 * MUST3 after ASTRA: the public module namespace must not publish the config
 * validator or any secret/credential-bearing normalizer, and nothing reachable from
 * a public factory result may serialize a credential. The validated type is a
 * compile-time shape only — a runtime assertion that it does not exist is
 * meaningless, so the proof is the *export surface* plus a credential scan of the
 * serialized public objects.
 */
describe('private quarantine storage: public surface', () => {
  it('publishes no config validator or secret normalizer and serializes no credential', () => {
    const names = Object.keys(storage);
    for (const forbidden of ['validateConfig', 'createS3Client', 'normalizeConfig', 'validatedConfig']) {
      expect(names).not.toContain(forbidden);
    }
    // No export whose *name* implies it hands out or normalizes credentials/secrets.
    expect(names.filter((name) => /secret|credential|passw|accesskey/i.test(name))).toEqual([]);

    const config = loopbackConfig('http://127.0.0.1:3901');
    const adapter = createAdapter(config);
    const attempt = adapter.prepareQuarantineAttempt();
    // Everything a caller can reach and serialize: the module namespace, the factory,
    // the adapter and the descriptor. None may carry the credential values.
    const surfaces = [
      JSON.stringify(names),
      String(storage.createPrivateQuarantineStorage),
      JSON.stringify(adapter),
      Object.keys(adapter).join(','),
      JSON.stringify(attempt),
    ];
    for (const surface of surfaces) {
      expect(surface.includes(config.secretAccessKey)).toBe(false);
      expect(surface.includes(config.accessKeyId)).toBe(false);
    }
    // The factory is still the only construction path: no exported validated type
    // factory and no way to hand it a pre-validated config object.
    expect(typeof storage.createPrivateQuarantineStorage).toBe('function');
  });
});

/**
 * MUST4 after ASTRA: every reflection step on caller input is a Proxy trap, so a
 * trap that throws must become a fixed refusal of *this* module — never the caller's
 * error, message, `cause` or marker. A caller-made `PrivateStorageError` (the class
 * is exported) is likewise untrusted: only the module's own branded failures pass.
 */
describe('private quarantine storage: untrusted caller reflection', () => {
  /** A Proxy over `target` whose single named trap throws the synthetic marker error. */
  function hostileProxy(target: object, trap: 'getPrototypeOf' | 'ownKeys' | 'getOwnPropertyDescriptor'): object {
    const handler: ProxyHandler<object> = {};
    handler[trap] = (): never => { throw new Error(MARKER); };
    return new Proxy(target, handler);
  }

  /** Asserts a fixed refusal: exact code, exact message, no marker, no cause. */
  function expectFixed(error: unknown, code: string): void {
    expect(storageCode(error)).toBe(code);
    expect((error as Error).message).toBe(code);
    expect('cause' in (error as object)).toBe(false);
    expect(errorText(error).includes(MARKER)).toBe(false);
  }

  it('maps config Proxy reflection traps to a fixed INVALID_CONFIG without dialling', async () => {
    const fixture = using(await loopback(() => { /* must never be called */ }));
    const base = loopbackConfig(fixture.endpoint);
    for (const trap of ['getPrototypeOf', 'ownKeys', 'getOwnPropertyDescriptor'] as const) {
      const hostile = hostileProxy({ ...base }, trap);
      expect(factoryRefusal(hostile)).toBe(CODES.invalidConfig);
      try {
        storage.createPrivateQuarantineStorage(hostile as never);
        throw new Error('Expected the factory to refuse the hostile config proxy.');
      } catch (error: unknown) {
        expectFixed(error, CODES.invalidConfig);
      }
    }
    expect(fixture.requests).toHaveLength(0);
  });

  it('maps put/verify input Proxy reflection traps to a fixed INVALID_INPUT before any IO', async () => {
    const fixture = using(await loopback(() => { /* must never be called */ }));
    const adapter = createAdapter(loopbackConfig(fixture.endpoint));
    const attempt = adapter.prepareQuarantineAttempt();
    const putInput = { body: unconsumedBody(), expectedBytes: 4, maxBytes: 8, signal: SIGNAL };
    const verifyInput = { expectedBytes: 4, maxBytes: 8, sha256: 'a'.repeat(64), signal: SIGNAL };
    for (const trap of ['getPrototypeOf', 'ownKeys', 'getOwnPropertyDescriptor'] as const) {
      const putSettled = await settle(adapter.putQuarantined(
        attempt,
        hostileProxy(putInput, trap) as never,
      ));
      expect(putSettled.ok).toBe(false);
      if (!putSettled.ok) {
        expectFixed(putSettled.error, CODES.invalidInput);
      }
      const verifySettled = await settle(adapter.verifyQuarantined(
        attempt,
        hostileProxy(verifyInput, trap) as never,
      ));
      expect(verifySettled.ok).toBe(false);
      if (!verifySettled.ok) {
        expectFixed(verifySettled.error, CODES.invalidInput);
      }
    }
    // The hostile input never reached the transport, and the descriptor is untouched.
    expect(fixture.requests).toHaveLength(0);
    expect(adapter.prepareQuarantineAttempt().attemptId).not.toBe(attempt.attemptId);
  });

  it('maps a caller-thrown PrivateStorageError from the iterator factory to fixed SOURCE_FAILED', async () => {
    const watch = watchUnhandledRejections();
    try {
      const fixture = using(await loopback(() => { /* must never be called */ }));
      const adapter = createAdapter(loopbackConfig(fixture.endpoint));
      const attempt = adapter.prepareQuarantineAttempt();
      // The class is public, so a caller can construct a legal-looking failure with a
      // custom message and even a `cause`. Neither identity nor message is trusted.
      const callerError = new storage.PrivateStorageError(MARKER as never);
      callerError.message = MARKER;
      (callerError as { cause?: unknown }).cause = new Error(MARKER);
      const hostileBody: AsyncIterable<Uint8Array> = {
        [Symbol.asyncIterator](): never { throw callerError; },
      };
      const settled = await settle(adapter.putQuarantined(attempt, {
        body: hostileBody, expectedBytes: 4, maxBytes: 8, signal: SIGNAL,
      }));
      expect(settled.ok).toBe(false);
      if (!settled.ok) {
        // Post-start, so the honest outcome is UNKNOWN with the source reason.
        expect(storageCode(settled.error)).toBe(CODES.writeUnknown);
        expect(storageReason(settled.error)).toBe('SOURCE_FAILED');
        expect((settled.error as Error).message).toBe(CODES.writeUnknown);
        expect(settled.error).not.toBe(callerError);
        expect('cause' in (settled.error as object)).toBe(false);
        expect(errorText(settled.error).includes(MARKER)).toBe(false);
      }
      // No request was ever sent, and the failed call left no detached rejection.
      expect(fixture.requests).toHaveLength(0);
      await sleep(200);
      expect(watch.rejections).toHaveLength(0);
    } finally {
      watch.stop();
    }
  });
});
