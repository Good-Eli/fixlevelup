/**
 * Synthetic fixtures for the P03-04B **B1** standalone private quarantine S3
 * adapter (owner approved B1 only; B2, DB registration, HTTP and READY are out of
 * scope and must not be implied by anything here).
 *
 * This file owns everything the three storage suites share and nothing the adapter
 * owns:
 *
 * - the *test* configuration object. The real-Garage suite reads the existing
 *   ignored local Garage credentials (`infra/dev-s3/.env`); the loopback suite uses
 *   purely synthetic credentials and an ephemeral `127.0.0.1` port. No test value
 *   here is a policy default: sizes, timeouts and chunk sizes are explicit
 *   technical fixture parameters;
 * - an ephemeral loopback HTTP fixture that can accept a request, stall before
 *   response headers, stall a response body after headers, destroy the socket after
 *   N request bytes, and optionally capture the delivered body;
 * - bounded-settle helpers, deterministic synthetic payloads/hashes, typed-error
 *   accessors and the secret/URL leak assertion used by every failure case.
 *
 * Deliberate constraints:
 *
 * - no adapter import: a test must not be able to hide a regression by reusing
 *   adapter internals;
 * - credentials are read only inside the real-Garage suite, only from the ignored
 *   dev env file, and never printed: every error here names the variable, not the
 *   value;
 * - the loopback fixture binds literal `127.0.0.1` only — never DNS, `localhost`,
 *   `::1` or a wildcard — matching the approved `local-synthetic` endpoint rule;
 * - no test deletes an object, changes bucket grants, or touches any key outside
 *   its own unique synthetic namespace. Synthetic objects are intentionally left in
 *   place as evidence; this slice is not allowed to delete.
 */
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Socket } from 'node:net';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '../../..');

/** Fixed non-secret local Garage target (P01-01.10A); never configurable by a test. */
export const GARAGE_ENDPOINT = 'http://127.0.0.1:3900';
export const GARAGE_REGION = 'garage';
export const GARAGE_BUCKET = 'fixlevelup-dev-private';

/**
 * The adapter's closed configuration object, exactly as frozen in
 * docs/P03-04B-STORAGE.md §Конфигурация (ruling A: the doc is authoritative).
 * The fixture keeps its own structural copy so a test cannot pass by importing the
 * adapter's validator; the factory call is the actual contract check.
 */
export interface StorageTestConfig {
  readonly mode: 'production' | 'local-synthetic';
  readonly endpoint: string;
  /** Operator-configured exact allowed target; must equal `endpoint`. */
  readonly allowedEndpoint: string;
  readonly region: string;
  readonly bucket: string;
  readonly accessKeyId: string;
  readonly secretAccessKey: string;
  readonly connectionTimeoutMs: number;
  readonly requestTimeoutMs: number;
  readonly socketTimeoutMs: number;
  /** Whole-operation deadline, including a response body after its headers. */
  readonly operationTimeoutMs: number;
  /** Largest single chunk the adapter accepts from the source iterator. */
  readonly maxChunkBytes: number;
  /** Hard cap on concurrently in-flight adapter operations (no queue). */
  readonly maxConcurrentOperations: number;
  /**
   * Hard cap on a service response body: an error body or an unexpected success
   * body is cut before the SDK deserializer sees it. Mandatory technical bound,
   * never a default; a missing/zero/negative value must be refused.
   */
  readonly maxResponseBodyBytes: number;
}

/**
 * Explicit technical bounds for the local fixtures. They are *not* business
 * defaults: each test that depends on one states it as a technical parameter, and
 * no production policy value (file size, retention, quota) is implied.
 */
export const TECHNICAL_TIMEOUTS = {
  connectionTimeoutMs: 2_000,
  requestTimeoutMs: 5_000,
  socketTimeoutMs: 5_000,
  operationTimeoutMs: 10_000,
  maxChunkBytes: 64 * 1024,
  maxConcurrentOperations: 2,
  maxResponseBodyBytes: 256 * 1024,
} as const;

/** Tight technical bounds for loopback tests, so a stall settles in well under a second. */
export const LOOPBACK_TIMEOUTS = {
  connectionTimeoutMs: 500,
  requestTimeoutMs: 800,
  socketTimeoutMs: 800,
  operationTimeoutMs: 1_500,
  maxChunkBytes: 64 * 1024,
  maxConcurrentOperations: 2,
  maxResponseBodyBytes: 64 * 1024,
} as const;

export interface GarageCredentials {
  readonly accessKeyId: string;
  readonly secretAccessKey: string;
}

/**
 * Reads one credential pair from the existing ignored dev env file. Throws a
 * value-free error so a broken fixture can never echo a secret into the report.
 */
export function loadGarageCredentials(readonly = false): GarageCredentials {
  const source = readFileSync(resolve(root, 'infra/dev-s3/.env'), 'utf8');
  const prefix = readonly ? 'S3_READONLY_' : 'S3_';
  const get = (name: string, pattern: RegExp): string => {
    const match = new RegExp(`^${prefix}${name}=([^\\r\\n]+)$`, 'm').exec(source)?.[1];
    if (match === undefined || !pattern.test(match)) {
      throw new Error(`Missing or invalid local S3 credential: ${prefix}${name}`);
    }
    return match;
  };
  return {
    accessKeyId: get('ACCESS_KEY_ID', /^GK[a-f0-9]{24}$/),
    secretAccessKey: get('SECRET_ACCESS_KEY', /^[a-f0-9]{64}$/),
  };
}

/**
 * Test configuration for the real local Garage: explicit `mode` (the
 * operator-selected local-synthetic boundary, not a default and not a relaxed
 * production allowlist), fixed non-secret target, existing ignored credentials.
 */
export function garageConfig(overrides: Partial<StorageTestConfig> = {}): StorageTestConfig {
  const credentials = loadGarageCredentials();
  return {
    mode: 'local-synthetic',
    endpoint: GARAGE_ENDPOINT,
    allowedEndpoint: GARAGE_ENDPOINT,
    region: GARAGE_REGION,
    bucket: GARAGE_BUCKET,
    accessKeyId: credentials.accessKeyId,
    secretAccessKey: credentials.secretAccessKey,
    ...TECHNICAL_TIMEOUTS,
    ...overrides,
  };
}

/** Deterministic synthetic credentials for loopback fixtures; no disk read, no real secret. */
export function syntheticCredentials(seed = 'p03-04b-synthetic'): GarageCredentials {
  const digest = createHash('sha256').update(seed).digest('hex');
  return { accessKeyId: `GK${digest.slice(0, 24)}`, secretAccessKey: digest };
}

/**
 * Config for an ephemeral loopback fixture: literal 127.0.0.1, synthetic
 * credentials, and `allowedEndpoint` equal to the dialled endpoint (the frozen
 * exact-match rule; there is no port-array allowlist).
 */
export function loopbackConfig(endpoint: string, overrides: Partial<StorageTestConfig> = {}): StorageTestConfig {
  return {
    mode: 'local-synthetic',
    endpoint,
    allowedEndpoint: endpoint,
    region: GARAGE_REGION,
    bucket: GARAGE_BUCKET,
    ...syntheticCredentials(),
    ...LOOPBACK_TIMEOUTS,
    ...overrides,
  };
}

/** A bounded, deterministic payload; the seed makes a mismatch diagnosable. */
export function syntheticPayload(bytes: number, seed = 'p03-04b'): Uint8Array {
  if (!Number.isSafeInteger(bytes) || bytes < 0) {
    throw new Error('Synthetic payload size must be a non-negative safe integer.');
  }
  const payload = new Uint8Array(bytes);
  let block = createHash('sha256').update(seed).digest();
  let offset = 0;
  while (offset < bytes) {
    const take = Math.min(block.byteLength, bytes - offset);
    payload.set(block.subarray(0, take), offset);
    offset += take;
    block = createHash('sha256').update(block).digest();
  }
  return payload;
}

/** Splits a payload into independently delivered chunks. */
export function chunked(payload: Uint8Array, chunkBytes: number): Uint8Array[] {
  if (!Number.isSafeInteger(chunkBytes) || chunkBytes <= 0) {
    throw new Error('Chunk size must be a positive safe integer.');
  }
  const chunks: Uint8Array[] = [];
  for (let offset = 0; offset < payload.byteLength; offset += chunkBytes) {
    chunks.push(payload.slice(offset, Math.min(offset + chunkBytes, payload.byteLength)));
  }
  return chunks;
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

export function sleep(milliseconds: number): Promise<void> {
  return new Promise<void>((resolveSleep) => { setTimeout(resolveSleep, milliseconds); });
}

/**
 * Bounded barrier on an observed side effect (a server noticing the client closed
 * the socket, a request counter moving). Polling with an explicit bound beats a
 * fixed sleep: it is deterministic when the event is fast and still bounded when it
 * never happens.
 */
export async function waitUntil(
  predicate: () => boolean,
  milliseconds: number,
  label = 'condition',
): Promise<void> {
  const deadline = performance.now() + milliseconds;
  while (!predicate()) {
    if (performance.now() > deadline) {
      throw new Error(`Timed out waiting for ${label}.`);
    }
    await sleep(5);
  }
}

/**
 * Test watchdog: every adapter call in these suites is wrapped so a regression
 * cannot hang the runner. An explicit technical bound, not a policy TTL.
 */
export async function bounded<T>(action: Promise<T>, milliseconds: number, label = 'storage operation'): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      action,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => { reject(new Error(`Watchdog expired for ${label}.`)); }, milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

export type Settled<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: unknown };

/** Awaits an action without letting its rejection escape, for typed-refusal asserts. */
export async function settle<T>(action: Promise<T>): Promise<Settled<T>> {
  try {
    return { ok: true, value: await action };
  } catch (error: unknown) {
    return { ok: false, error };
  }
}

/**
 * The typed code of a storage refusal, if the failure carries one. Reading the
 * property is deliberate: a test asserts the *typed* vocabulary, never a raw SDK
 * error or a message string.
 */
export function storageCode(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) {
    return undefined;
  }
  const code: unknown = (error as { code?: unknown }).code;
  return typeof code === 'string' ? code : undefined;
}

/**
 * Renders every diagnosable part of a thrown value without invoking a network or
 * serialisation side effect: name, message, stack and own scalar properties.
 */
export function errorText(error: unknown): string {
  const parts: string[] = [];
  const seen = new Set<unknown>();
  let current: unknown = error;
  for (let depth = 0; depth < 4 && current !== null && current !== undefined && !seen.has(current); depth += 1) {
    seen.add(current);
    if (current instanceof Error) {
      parts.push(current.name, current.message, current.stack ?? '');
      for (const key of Object.getOwnPropertyNames(current)) {
        const value: unknown = (current as unknown as Record<string, unknown>)[key];
        if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
          parts.push(`${key}=${String(value)}`);
        }
      }
      current = (current as { cause?: unknown }).cause;
    } else {
      parts.push(typeof current === 'string' ? current : JSON.stringify(current));
      current = undefined;
    }
  }
  return parts.filter((part) => part !== '').join('\n');
}

/**
 * Fails when a surfaced error text contains a credential, the endpoint, an object
 * key, a signed-URL query or an Authorization header. Storage failures are
 * internal: a raw SDK error, key or URL must never reach a caller or a log.
 */
export function assertSafeFailure(
  error: unknown,
  secrets: readonly string[],
  forbidden: readonly string[] = [],
): void {
  const text = errorText(error);
  if (text === '') {
    throw new Error('Expected a diagnosable storage failure, received an empty error surface.');
  }
  for (const secret of [...secrets, ...forbidden]) {
    if (secret !== '' && text.includes(secret)) {
      throw new Error('Storage failure leaks a credential, endpoint, key or signed URL fragment.');
    }
  }
  for (const marker of ['X-Amz-', 'Authorization', 'AWS4-HMAC', 'presign', 'signedUrl']) {
    if (text.includes(marker)) {
      throw new Error(`Storage failure leaks a request-authentication marker: ${marker}`);
    }
  }
}

/* ------------------------------ loopback HTTP ------------------------------ */

export interface LoopbackRequestRecord {
  readonly method: string;
  readonly url: string;
  bodyBytes: number;
  complete: boolean;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  /** Captured request body bytes, only when the fixture was created with `captureBody`. */
  readonly bodyChunks: Buffer[];
}

export type LoopbackHandler = (
  request: IncomingMessage,
  response: ServerResponse,
  record: LoopbackRequestRecord,
) => void;

export interface LoopbackOptions {
  /** Keep the delivered request body in `record.bodyChunks` (bounded by the test size). */
  readonly captureBody?: boolean;
}

export interface LoopbackFixture {
  /** Literal `http://127.0.0.1:<ephemeral port>`; no DNS, no wildcard. */
  readonly endpoint: string;
  readonly port: number;
  readonly requests: LoopbackRequestRecord[];
  readonly sockets: Set<Socket>;
  /** Resolves once at least one request has arrived, or throws on timeout. */
  waitForRequest(milliseconds: number): Promise<LoopbackRequestRecord>;
  /**
   * True barrier: resolves once a request matching `predicate` has arrived (e.g. the
   * GET of a verify, after the earlier PUT). Prefer this over `sleep` so a test never
   * races the transport it is about to abort.
   */
  waitForRequestMatching(
    predicate: (request: LoopbackRequestRecord) => boolean,
    milliseconds: number,
    label?: string,
  ): Promise<LoopbackRequestRecord>;
  /** Waits until every accepted socket is closed, or throws on timeout. */
  waitForSocketsClosed(milliseconds: number): Promise<void>;
  close(): Promise<void>;
}

/**
 * Ephemeral loopback HTTP fixture. The handler owns the response, so a test can
 * stall before headers, stall the body, answer, or destroy the socket after the
 * request bytes arrived. Request bodies are counted, never printed.
 */
export async function loopback(handler: LoopbackHandler, options: LoopbackOptions = {}): Promise<LoopbackFixture> {
  const sockets = new Set<Socket>();
  const requests: LoopbackRequestRecord[] = [];
  const server = createServer((request, response) => {
    const record: LoopbackRequestRecord = {
      method: request.method ?? '',
      url: request.url ?? '',
      bodyBytes: 0,
      complete: false,
      headers: request.headers,
      bodyChunks: [],
    };
    requests.push(record);
    request.on('data', (chunk: Buffer) => {
      record.bodyBytes += chunk.byteLength;
      if (options.captureBody === true) {
        record.bodyChunks.push(chunk);
      }
    });
    request.on('end', () => { record.complete = true; });
    handler(request, response, record);
  });
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.once('close', () => { sockets.delete(socket); });
  });
  await new Promise<void>((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', rejectListen);
      resolveListen();
    });
  });
  const address = server.address();
  if (address === null || typeof address === 'string') {
    server.close();
    throw new Error('Expected an ephemeral loopback HTTP fixture.');
  }
  const port = address.port;
  return {
    endpoint: `http://127.0.0.1:${String(port)}`,
    port,
    requests,
    sockets,
    async waitForRequest(milliseconds: number): Promise<LoopbackRequestRecord> {
      const deadline = performance.now() + milliseconds;
      for (;;) {
        const first = requests[0];
        if (first !== undefined) {
          return first;
        }
        if (performance.now() > deadline) {
          throw new Error('Loopback fixture received no request within the bound.');
        }
        await sleep(10);
      }
    },
    async waitForRequestMatching(
      predicate: (request: LoopbackRequestRecord) => boolean,
      milliseconds: number,
      label = 'matching request',
    ): Promise<LoopbackRequestRecord> {
      const deadline = performance.now() + milliseconds;
      for (;;) {
        const match = requests.find(predicate);
        if (match !== undefined) {
          return match;
        }
        if (performance.now() > deadline) {
          throw new Error(`Loopback fixture received no ${label} within the bound.`);
        }
        await sleep(5);
      }
    },
    async waitForSocketsClosed(milliseconds: number): Promise<void> {
      const deadline = performance.now() + milliseconds;
      while (sockets.size > 0) {
        if (performance.now() > deadline) {
          throw new Error('Loopback fixture still has open sockets after the bound.');
        }
        await sleep(10);
      }
    },
    async close(): Promise<void> {
      for (const socket of sockets) {
        socket.destroy();
      }
      await new Promise<void>((resolveClose, rejectClose) => {
        server.close((error) => {
          if (error) {
            rejectClose(error);
          } else {
            resolveClose();
          }
        });
      });
    },
  };
}

/**
 * Loopback responses used by the transport suite. Each one is a real socket
 * behaviour, not a mock: the adapter talks HTTP to it exactly as it would to
 * Garage.
 */
export const loopbackBehaviour = {
  /** Accepts the PUT and answers 200 with a synthetic ETag, after draining the body. */
  accept: ((request: IncomingMessage, response: ServerResponse) => {
    request.resume();
    request.on('end', () => {
      response.writeHead(200, { ETag: '"synthetic-loopback"', 'Content-Type': 'application/xml' });
      response.end();
    });
  }) satisfies LoopbackHandler,

  /** Accepts the connection and never sends response headers (requestTimeout case). */
  stallHeaders: (() => { /* Deliberately never respond. */ }) satisfies LoopbackHandler,

  /** Sends headers and one body byte, then stalls the rest (socketTimeout case). */
  stallBody: ((request: IncomingMessage, response: ServerResponse) => {
    request.resume();
    request.on('end', () => {
      response.writeHead(200, { 'Content-Length': '64', 'Content-Type': 'application/octet-stream' });
      response.write('x');
    });
  }) satisfies LoopbackHandler,

  /** Destroys the socket after the request body was fully received. */
  resetAfterBody: ((request: IncomingMessage) => {
    request.resume();
    request.on('end', () => { request.socket.destroy(); });
  }) satisfies LoopbackHandler,
};

/**
 * A stateful loopback *object store*: a real PUT is stored under the request path
 * and a later GET/HEAD of the same path serves exactly those bytes. Two instances
 * of this behaviour are two genuinely different physical targets, and two adapters
 * pointing at the same instance are the same physical target. Create the fixture
 * with `{ captureBody: true }` so the PUT body is available.
 *
 * No object is ever deleted and no grant/bucket metadata is touched.
 */
export interface LoopbackObjectStore {
  readonly handler: LoopbackHandler;
  /** Stored bytes by request path, for direct byte comparison in a test. */
  readonly objects: ReadonlyMap<string, Buffer>;
  /**
   * Pre-seeds an object path with exact bytes, so a *wrong* target would serve a
   * matching body if the adapter wrongly dialled it. That makes a target-mismatch
   * refusal non-vacuous: the refusal can only be the pre-network guard.
   */
  seed(path: string, bytes: Uint8Array): void;
}

export function loopbackObjectStore(): LoopbackObjectStore {
  const objects = new Map<string, Buffer>();
  const handler: LoopbackHandler = (request, response, record) => {
    request.resume();
    request.on('end', () => {
      // Path-style URL without the SDK's query string: the object identity is the
      // path, and the same key must be found for a later GET/HEAD.
      const path = (request.url ?? '').split('?')[0] ?? '';
      const method = request.method ?? '';
      if (method === 'PUT') {
        objects.set(path, Buffer.concat(record.bodyChunks));
        response.writeHead(200, { ETag: '"synthetic-loopback"', 'Content-Type': 'application/xml' });
        response.end();
        return;
      }
      if (method === 'GET' || method === 'HEAD') {
        const stored = objects.get(path);
        if (stored === undefined) {
          response.writeHead(404, { 'Content-Type': 'application/xml' });
          response.end('<Error><Code>NoSuchKey</Code></Error>');
          return;
        }
        response.writeHead(200, {
          'Content-Length': String(stored.byteLength),
          'Content-Type': 'application/octet-stream',
        });
        if (method === 'HEAD') {
          response.end();
        } else {
          response.end(stored);
        }
        return;
      }
      response.writeHead(405, { 'Content-Type': 'application/xml' });
      response.end();
    });
  };
  return { handler, objects, seed(path: string, bytes: Uint8Array): void { objects.set(path, Buffer.from(bytes)); } };
}

export interface OversizedChunkedResponseOptions {
  /** Response status; 500 for an error body, 200 for an unexpected success body. */
  readonly status?: number;
  /** Bytes per incremental write (a technical fixture parameter, not a policy). */
  readonly chunkBytes?: number;
  /** Total body size the server intends to send unless the client cuts it early. */
  readonly totalBytes?: number;
  /** Write cadence, so the body is delivered incrementally, never in one packet. */
  readonly intervalMs?: number;
  /** HTTP methods answered with the oversized body; a PUT request body is drained first. */
  readonly methods?: readonly string[];
  readonly contentType?: string;
}

/**
 * A live probe over a server that answers selected methods with an incrementally
 * written, deliberately huge body **without a `Content-Length` header** (HTTP/1.1
 * chunked framing). It records how many bytes the server actually wrote and whether
 * the client cut the transfer before the planned body was complete, so a test can
 * prove the adapter stopped the response early instead of trusting headers.
 *
 * The write loop is bounded by `totalBytes` (1 MiB by default), so even a regressed
 * adapter cannot make the fixture buffer an unbounded body.
 */
export interface OversizedChunkedResponseProbe {
  readonly handler: LoopbackHandler;
  readonly plannedBytes: number;
  /** Bytes the server has written so far (a lower bound on the wire bytes). */
  sentBytes(): number;
  /** Whether the full planned body was written (a regression for a capped client). */
  finished(): boolean;
  /** Whether the server stopped because the client closed the socket. */
  stopped(): boolean;
  /** The response headers actually sent; must contain no `content-length`. */
  headers(): Readonly<Record<string, string | number | string[]>>;
  status(): number;
}

export function oversizedChunkedResponse(
  options: OversizedChunkedResponseOptions = {},
): OversizedChunkedResponseProbe {
  const status = options.status ?? 500;
  const chunkBytes = options.chunkBytes ?? 256;
  const totalBytes = options.totalBytes ?? 1_048_576;
  const intervalMs = options.intervalMs ?? 1;
  const methods = options.methods ?? ['GET'];
  const contentType = options.contentType ?? 'application/xml';
  let sent = 0;
  let finished = false;
  let stopped = false;
  let headers: Record<string, string | number | string[]> = {};
  const handler: LoopbackHandler = (request, response) => {
    request.resume();
    const method = request.method ?? '';
    const start = (): void => {
      if (!methods.includes(method)) {
        response.writeHead(405, { 'Content-Type': 'application/xml' });
        response.end();
        return;
      }
      // No Content-Length on purpose: the only defence left is counting actual
      // body bytes, so a header-only check cannot pass this case.
      response.writeHead(status, { 'Content-Type': contentType });
      headers = response.getHeaders() as Record<string, string | number | string[]>;
      const block = Buffer.alloc(chunkBytes, 0x78);
      // The interval is created first so the stop path can clear a `const` handle;
      // both the interval callback and the socket listeners only run after this tick.
      const timer = setInterval(() => {
        if (stopped || finished) {
          return;
        }
        const remaining = totalBytes - sent;
        if (remaining <= 0) {
          finished = true;
          stop();
          response.end();
          return;
        }
        const take = Math.min(chunkBytes, remaining);
        sent += take;
        try {
          response.write(take === chunkBytes ? block : block.subarray(0, take));
        } catch {
          stop();
        }
      }, intervalMs);
      function stop(): void {
        if (stopped) {
          return;
        }
        stopped = true;
        clearInterval(timer);
      }
      response.on('close', stop);
      response.on('error', stop);
    };
    if (method === 'PUT') {
      request.on('end', start);
    } else {
      start();
    }
  };
  return {
    handler,
    plannedBytes: totalBytes,
    sentBytes: () => sent,
    finished: () => finished,
    stopped: () => stopped,
    headers: () => headers,
    status: () => status,
  };
}

/** The path-style request URL of one object under a bucket (`forcePathStyle`). */
export function objectPath(bucket: string, objectKey: string): string {
  return `/${bucket}/${objectKey}`;
}

/** A loopback URL whose listener was closed again, i.e. a deterministic
 * connection-refused endpoint: nothing is listening when the adapter dials it.
 */
export async function refusedEndpoint(): Promise<string> {
  const server = createServer();
  await new Promise<void>((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', rejectListen);
      resolveListen();
    });
  });
  const address = server.address();
  if (address === null || typeof address === 'string') {
    server.close();
    throw new Error('Expected an ephemeral loopback port.');
  }
  const port = address.port;
  await new Promise<void>((resolveClose, rejectClose) => {
    server.close((error) => {
      if (error) {
        rejectClose(error);
      } else {
        resolveClose();
      }
    });
  });
  return `http://127.0.0.1:${String(port)}`;
}

/* --------------------------- process-wide guards --------------------------- */

export interface RejectionWatch {
  readonly rejections: unknown[];
  stop(): void;
}

/**
 * Collects unhandled promise rejections for one test. An adapter that detaches a
 * failed operation must never leave an unhandled rejection behind.
 */
export function watchUnhandledRejections(): RejectionWatch {
  const rejections: unknown[] = [];
  const listener = (reason: unknown): void => { rejections.push(reason); };
  process.on('unhandledRejection', listener);
  return {
    rejections,
    stop(): void { process.off('unhandledRejection', listener); },
  };
}

/**
 * Unique synthetic namespace for raw verification objects created directly by a
 * test (never by the adapter). Test objects are intentionally left in place: this
 * slice is not allowed to delete objects or touch existing ones.
 */
export function rawFixtureKey(label: string): string {
  return `synthetic/p03-04b-tests/${randomUUID()}/${label}-${randomUUID()}.bin`;
}

/** Random wrong credentials for the negative Garage cases; never a real key. */
export function wrongCredentials(): GarageCredentials {
  return {
    accessKeyId: `GK${randomBytes(12).toString('hex')}`,
    secretAccessKey: randomBytes(32).toString('hex'),
  };
}

/**
 * Async iterable over pre-computed chunks. Deliberately not an `async function*`:
 * the adapter only requires `AsyncIterable<Uint8Array>`, and a plain iterator keeps
 * the fixture free of an artificial `await`.
 */
export function asyncChunks(chunks: readonly Uint8Array[]): AsyncIterable<Uint8Array> {
  return {
    [Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
      let index = 0;
      return {
        next(): Promise<IteratorResult<Uint8Array>> {
          const chunk = chunks[index];
          index += 1;
          return Promise.resolve(chunk === undefined
            ? { done: true, value: undefined }
            : { done: false, value: chunk });
        },
        return(): Promise<IteratorResult<Uint8Array>> {
          return Promise.resolve({ done: true, value: undefined });
        },
      };
    },
  };
}

/**
 * Yields one caller-owned buffer and then mutates it. A correct adapter copies the
 * chunk before hashing/pushing it, so the mutation must not change what was sent.
 */
export function mutableThenMutated(chunk: Uint8Array): AsyncIterable<Uint8Array> {
  let pulled = false;
  return {
    [Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
      return {
        next(): Promise<IteratorResult<Uint8Array>> {
          if (!pulled) {
            pulled = true;
            return Promise.resolve({ done: false, value: chunk });
          }
          chunk.fill(0);
          return Promise.resolve({ done: true, value: undefined });
        },
      };
    },
  };
}

/** A source that rejects on its first pull (the "source throws" transport case). */
export function throwingBody(): AsyncIterable<Uint8Array> {
  return {
    [Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
      return {
        next(): Promise<IteratorResult<Uint8Array>> {
          return Promise.reject(new Error('synthetic source failure'));
        },
      };
    },
  };
}

/**
 * A source that yields one chunk and then never settles again, ignoring abort:
 * used to prove the adapter does not await uncooperative caller code forever.
 */
export function stallingBody(first: Uint8Array): AsyncIterable<Uint8Array> {
  let pulled = false;
  return {
    [Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
      return {
        next(): Promise<IteratorResult<Uint8Array>> {
          if (!pulled) {
            pulled = true;
            return Promise.resolve({ done: false, value: first });
          }
          return new Promise<IteratorResult<Uint8Array>>(() => { /* never settles */ });
        },
        return(): Promise<IteratorResult<Uint8Array>> {
          return Promise.resolve({ done: true, value: undefined });
        },
      };
    },
  };
}
