/**
 * Closed operator configuration of the private quarantine adapter (B1).
 *
 * Every field is mandatory and validated before any object is constructed, so
 * there is no environment lookup, no default credential chain, no metadata
 * service, no default endpoint, no default timeout and no policy number invented
 * here. The factory copies the primitives it accepts into a frozen object: a
 * caller mutating its own config object afterwards cannot change a live client.
 *
 * Production is deliberately *disabled* in B1. A bare HTTPS endpoint is not
 * enough to open production IO: the approved production address and TLS policy
 * are a separate owner decision, so `mode: 'production'` is refused outright.
 */
import { S3Client } from '@aws-sdk/client-s3';
import { storageTarget } from './attempt.js';
import type { StorageTarget } from './attempt.js';
import { privateStorageError } from './errors.js';
import { installResponseBodyCap } from './response-limiter.js';

/** The only two modes the closed config vocabulary knows. */
export type StorageMode = 'production' | 'local-synthetic';

/** Caller-facing closed configuration. All fields are required. */
export interface PrivateQuarantineStorageConfig {
  readonly mode: StorageMode;
  /** Exact target the adapter may talk to. */
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
  readonly maxChunkBytes: number;
  readonly maxConcurrentOperations: number;
  /**
   * Technical cap on the raw HTTP response body, applied *before* the SDK
   * deserializer collects it. Every caller states it explicitly: there is no
   * default, and it is a resource bound, not a business policy.
   */
  readonly maxResponseBodyBytes: number;
}

/** Validated, frozen copy handed to the adapter and its S3 client. */
export interface ValidatedStorageConfig {
  readonly mode: 'local-synthetic';
  readonly endpoint: string;
  readonly region: string;
  readonly bucket: string;
  readonly accessKeyId: string;
  readonly secretAccessKey: string;
  readonly connectionTimeoutMs: number;
  readonly requestTimeoutMs: number;
  readonly socketTimeoutMs: number;
  readonly operationTimeoutMs: number;
  readonly maxChunkBytes: number;
  readonly maxConcurrentOperations: number;
  readonly maxResponseBodyBytes: number;
}

const CONFIG_KEYS: ReadonlySet<string> = new Set([
  'mode', 'endpoint', 'allowedEndpoint', 'region', 'bucket', 'accessKeyId', 'secretAccessKey',
  'connectionTimeoutMs', 'requestTimeoutMs', 'socketTimeoutMs', 'operationTimeoutMs',
  'maxChunkBytes', 'maxConcurrentOperations', 'maxResponseBodyBytes',
]);

const MAX_TIMEOUT_MS = 3_600_000;
const MAX_CHUNK_BYTES = 67_108_864;
const MAX_CONCURRENT_OPERATIONS = 64;
/**
 * Technical upper bound of the raw response cap, not a policy value: it only stops
 * a caller from declaring an effectively unbounded cap. The actual cap is always
 * the caller's explicit number.
 */
const MAX_RESPONSE_BODY_BYTES = 67_108_864;

/** Literal loopback HTTP only: no DNS, no `localhost`, no IPv6, no wildcard. */
const LOOPBACK_ENDPOINT = /^http:\/\/127\.0\.0\.1:([1-9]\d{0,4})\/?$/;
const REGION = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const BUCKET = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
const CREDENTIAL = /^[A-Za-z0-9._~+/=-]{3,256}$/;

/** Registry tuples must already be canonical; unlike operator config, no slash is normalized. */
export function canonicalRegistryTarget(endpoint: unknown, bucket: unknown, region: unknown): StorageTarget | undefined {
  if (typeof endpoint !== 'string' || endpoint.length > 32 || endpoint !== loopbackEndpointOrUndefined(endpoint)
    || typeof bucket !== 'string' || bucket.length > 63 || !BUCKET.test(bucket)
    || typeof region !== 'string' || region.length > 63 || !REGION.test(region)) {
    return undefined;
  }
  return storageTarget(endpoint, bucket, region);
}

function invalidConfig(): never {
  throw privateStorageError('INVALID_CONFIG');
}

/**
 * Reflection boundary (MUST4). `recordOf` walks a caller object through
 * `Object.getPrototypeOf`/`Reflect.ownKeys`/`Reflect.getOwnPropertyDescriptor`, and
 * a `Proxy` can throw an arbitrary value from any of those traps — including a
 * crafted `PrivateStorageError` with a legal code, a marker string or a `cause`.
 * Nothing from that traversal may escape: every failure here becomes one fresh
 * `INVALID_CONFIG` with no marker and no cause chain.
 */
function recordOf(value: unknown): Record<string, unknown> {
  try {
    return reflectRecordOf(value);
  } catch {
    throw privateStorageError('INVALID_CONFIG');
  }
}

function reflectRecordOf(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    invalidConfig();
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    invalidConfig();
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== CONFIG_KEYS.size) {
    invalidConfig();
  }
  const snapshot: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    if (typeof key !== 'string' || !CONFIG_KEYS.has(key)) {
      invalidConfig();
    }
    const descriptor = Reflect.getOwnPropertyDescriptor(value, key);
    // Only plain writable data properties: an accessor could return a different
    // value on every read (a secret logged once, validated as another).
    if (descriptor === undefined || !('value' in descriptor)) {
      invalidConfig();
    }
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function stringField(record: Record<string, unknown>, key: string, maxLength: number): string {
  const value = record[key];
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) {
    invalidConfig();
  }
  return value;
}

function integerField(record: Record<string, unknown>, key: string, min: number, max: number): number {
  const value = record[key];
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) {
    invalidConfig();
  }
  return value;
}

function patternField(record: Record<string, unknown>, key: string, pattern: RegExp): string {
  const value = stringField(record, key, 512);
  if (!pattern.test(value)) {
    invalidConfig();
  }
  return value;
}

/** Validates one endpoint and returns its canonical `http://127.0.0.1:<port>` form. */
function loopbackEndpoint(value: string): string {
  return loopbackEndpointOrUndefined(value) ?? invalidConfig();
}

function loopbackEndpointOrUndefined(value: string): string | undefined {
  const rawPort = LOOPBACK_ENDPOINT.exec(value)?.[1];
  const port = Number(rawPort);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    return undefined;
  }
  return `http://127.0.0.1:${String(port)}`;
}

/**
 * Validates a caller config without touching the network. Throws
 * `PRODUCTION_DISABLED` for any production attempt and `INVALID_CONFIG` for
 * anything else that is missing, extra, blank, out of range or off-allowlist.
 */
export function validateConfig(input: unknown): ValidatedStorageConfig {
  const record = recordOf(input);
  const mode = record['mode'];
  if (mode === 'production') {
    throw privateStorageError('PRODUCTION_DISABLED');
  }
  if (mode !== 'local-synthetic') {
    invalidConfig();
  }
  const endpoint = loopbackEndpoint(stringField(record, 'endpoint', 512));
  const allowedEndpoint = loopbackEndpoint(stringField(record, 'allowedEndpoint', 512));
  // Exact match after canonicalisation of the one permitted shape: a trailing slash
  // is the only tolerated difference, so `...:3900/` and `...:3900` are the same
  // explicit operator target while any other difference is a refusal.
  if (endpoint !== allowedEndpoint) {
    invalidConfig();
  }
  return Object.freeze({
    mode: 'local-synthetic' as const,
    endpoint,
    region: patternField(record, 'region', REGION),
    bucket: patternField(record, 'bucket', BUCKET),
    accessKeyId: patternField(record, 'accessKeyId', CREDENTIAL),
    secretAccessKey: patternField(record, 'secretAccessKey', CREDENTIAL),
    connectionTimeoutMs: integerField(record, 'connectionTimeoutMs', 1, MAX_TIMEOUT_MS),
    requestTimeoutMs: integerField(record, 'requestTimeoutMs', 1, MAX_TIMEOUT_MS),
    socketTimeoutMs: integerField(record, 'socketTimeoutMs', 1, MAX_TIMEOUT_MS),
    operationTimeoutMs: integerField(record, 'operationTimeoutMs', 1, MAX_TIMEOUT_MS),
    maxChunkBytes: integerField(record, 'maxChunkBytes', 1, MAX_CHUNK_BYTES),
    maxConcurrentOperations: integerField(record, 'maxConcurrentOperations', 1, MAX_CONCURRENT_OPERATIONS),
    maxResponseBodyBytes: integerField(record, 'maxResponseBodyBytes', 1, MAX_RESPONSE_BODY_BYTES),
  });
}

/** Silences SDK logging so no raw request detail can reach a log sink. */
const SILENT_LOGGER = Object.freeze({
  debug: (): void => undefined,
  info: (): void => undefined,
  warn: (): void => undefined,
  error: (): void => undefined,
});

/**
 * Builds the single direct S3 client. Construction performs no IO; the client is
 * pinned to one attempt, path-style addressing, explicit credentials and the
 * operator timeouts, and can only ever talk to the validated endpoint.
 *
 * After construction the SDK has resolved `NodeHttpHandler.create(...)` into
 * `client.config.requestHandler`; the raw response-body cap is installed on that
 * resolved handler (see `response-limiter.ts`), so the cap sits *below* the SDK
 * deserializer and applies to every response body before it is collected.
 */
export function createS3Client(config: ValidatedStorageConfig): S3Client {
  const client = new S3Client({
    endpoint: config.endpoint,
    region: config.region,
    credentials: {
      accessKeyId: config.accessKeyId,
      secretAccessKey: config.secretAccessKey,
    },
    forcePathStyle: true,
    maxAttempts: 1,
    requestChecksumCalculation: 'WHEN_REQUIRED',
    responseChecksumValidation: 'WHEN_REQUIRED',
    logger: SILENT_LOGGER,
    requestHandler: {
      connectionTimeout: config.connectionTimeoutMs,
      requestTimeout: config.requestTimeoutMs,
      socketTimeout: config.socketTimeoutMs,
      throwOnRequestTimeout: true,
    },
  });
  installResponseBodyCap(client, config.maxResponseBodyBytes);
  return client;
}
