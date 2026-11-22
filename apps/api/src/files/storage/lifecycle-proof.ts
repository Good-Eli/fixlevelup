/** Trusted wiring only: neither issuer is re-exported from a feature barrel. */
import type { StorageTarget } from './attempt.js';
import { canonicalRegistryTarget } from './config.js';
import { privateStorageError } from './errors.js';

interface RawGetFacts {
  readonly intentId: string;
  readonly quarantineId: string;
  readonly attemptId: string;
  readonly objectKey: string;
  readonly target: StorageTarget;
  readonly expectedBytes: number;
  readonly expectedSha256: string;
  readonly namespaceId: string;
  readonly runtimeEpoch: bigint;
  readonly accessEpoch: bigint;
  readonly claimId: string;
  readonly claimGeneration: number;
}

interface ReadyGetFacts extends RawGetFacts {
  readonly publicationId: string;
}

declare const GET_KIND: unique symbol;
export interface RawGetGrant {
  readonly [GET_KIND]: 'RAW';
}
export interface ReadyGetGrant {
  readonly [GET_KIND]: 'READY';
}

type StoredGrant = (RawGetFacts & { readonly kind: 'RAW' }) | (ReadyGetFacts & { readonly kind: 'READY' });
const GRANTS = new WeakMap<object, StoredGrant>();
const RAW_KEYS = new Set([
  'intentId', 'quarantineId', 'attemptId', 'objectKey', 'target', 'expectedBytes', 'expectedSha256',
  'namespaceId', 'runtimeEpoch', 'accessEpoch', 'claimId', 'claimGeneration',
]);
const READY_KEYS = new Set([...RAW_KEYS, 'publicationId']);
const TARGET_KEYS = new Set(['endpoint', 'bucket', 'region']);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const MAX_DB_BIGINT = 9_223_372_036_854_775_807n;

function invalidGrant(): never {
  throw privateStorageError('ATTEMPT_INVALID');
}

// Both issuers perform reflection only inside issue's value-free exception boundary.
function dataFields(input: unknown, allowed: ReadonlySet<string>): Map<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    invalidGrant();
  }
  const prototype: unknown = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) {
    invalidGrant();
  }
  const keys = Reflect.ownKeys(input);
  if (keys.length !== allowed.size) {
    invalidGrant();
  }
  const snapshot = new Map<string, unknown>();
  for (const key of keys) {
    if (typeof key !== 'string' || !allowed.has(key)) {
      invalidGrant();
    }
    const descriptor = Reflect.getOwnPropertyDescriptor(input, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      invalidGrant();
    }
    snapshot.set(key, descriptor.value);
  }
  return snapshot;
}

function uuid(value: unknown, format: RegExp = UUID): string {
  if (typeof value !== 'string' || value.length !== 36 || !format.test(value)) {
    invalidGrant();
  }
  return value;
}

function epoch(value: unknown): bigint {
  if (typeof value !== 'bigint' || value < 1n || value > MAX_DB_BIGINT) {
    invalidGrant();
  }
  return value;
}

function issue(kind: StoredGrant['kind'], input: unknown): object {
  try {
    const snapshot = dataFields(input, kind === 'RAW' ? RAW_KEYS : READY_KEYS);
    const attemptId = uuid(snapshot.get('attemptId'), UUID_V4);
    const objectKey = snapshot.get('objectKey');
    const prefix = `${kind === 'RAW' ? 'quarantine' : 'sanitized'}/${attemptId}/`;
    if (typeof objectKey !== 'string' || objectKey.length !== prefix.length + 36 || !objectKey.startsWith(prefix)) {
      invalidGrant();
    }
    uuid(objectKey.slice(prefix.length), UUID_V4);
    const targetFields = dataFields(snapshot.get('target'), TARGET_KEYS);
    const target = canonicalRegistryTarget(targetFields.get('endpoint'), targetFields.get('bucket'), targetFields.get('region'));
    const expectedBytes = snapshot.get('expectedBytes');
    const expectedSha256 = snapshot.get('expectedSha256');
    const claimGeneration = snapshot.get('claimGeneration');
    if (target === undefined || typeof expectedBytes !== 'number' || !Number.isSafeInteger(expectedBytes) || expectedBytes < 1
      || typeof expectedSha256 !== 'string' || expectedSha256.length !== 64 || !SHA256_HEX.test(expectedSha256)
      || typeof claimGeneration !== 'number' || !Number.isInteger(claimGeneration)
      || claimGeneration < 1 || claimGeneration > 2_147_483_647) {
      invalidGrant();
    }
    const facts: RawGetFacts = {
      attemptId, objectKey, target, expectedBytes, expectedSha256, claimGeneration,
      intentId: uuid(snapshot.get('intentId')),
      quarantineId: uuid(snapshot.get('quarantineId')),
      namespaceId: uuid(snapshot.get('namespaceId')),
      runtimeEpoch: epoch(snapshot.get('runtimeEpoch')),
      accessEpoch: epoch(snapshot.get('accessEpoch')),
      claimId: uuid(snapshot.get('claimId')),
    };
    const proof = Object.freeze({});
    GRANTS.set(proof, Object.freeze(kind === 'RAW'
      ? { ...facts, kind }
      : { ...facts, kind, publicationId: uuid(snapshot.get('publicationId')) }));
    return proof;
  } catch {
    // A proxy (including a revoked one) can throw arbitrary data during reflection.
    invalidGrant();
  }
}

/** Mint only after the caller has proved a committed processing claim and exact raw binding. */
export function issueRawGetGrant(input: RawGetFacts): RawGetGrant {
  return issue('RAW', input) as RawGetGrant;
}

/** Mint only after the caller has proved a committed read claim and exact publication tuple. */
export function issueReadyGetGrant(input: ReadyGetFacts): ReadyGetGrant {
  return issue('READY', input) as ReadyGetGrant;
}

/** The brand guards process-local wiring; it does not independently prove authorization. */
export function requireLifecycleGetGrant(value: unknown, kind: StoredGrant['kind']): StoredGrant {
  // Do not reflect on an unbranded value: copies and proxies are refused by identity.
  const facts = typeof value === 'object' && value !== null ? GRANTS.get(value) : undefined;
  if (facts?.kind !== kind) {
    invalidGrant();
  }
  return facts;
}
