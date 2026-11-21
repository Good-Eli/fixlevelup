/**
 * Internal grant issuer for the operator reconciler. Call only with the exact
 * committed registry row and probe claim. This grant is a process-local wiring
 * guard, not evidence of a DB transaction; only the coordinator can prove that.
 * The issuer is deliberately absent from both feature barrels.
 */
import type { StorageTarget } from './attempt.js';
import { canonicalRegistryTarget } from './config.js';
import { privateStorageError } from './errors.js';

interface RegistryProbeFields {
  readonly attemptId: string;
  readonly objectKey: string;
  readonly target: StorageTarget;
  readonly claimId: string;
  readonly claimGeneration: number;
}

declare const REGISTERED_PROOF: unique symbol;
export interface RegisteredQuarantineProbeProof {
  readonly [REGISTERED_PROOF]: true;
}

const PROOFS = new WeakSet<object>();
const PROOF_FIELDS = new WeakMap<object, RegistryProbeFields>();
const PROOF_KEYS = new Set(['attemptId', 'objectKey', 'target', 'claimId', 'claimGeneration']);
const TARGET_KEYS = new Set(['endpoint', 'bucket', 'region']);
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function invalidProof(): never {
  throw privateStorageError('ATTEMPT_INVALID');
}

function dataFields(value: unknown, allowed: ReadonlySet<string>): Map<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    invalidProof();
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    invalidProof();
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== allowed.size) {
    invalidProof();
  }
  const fields = new Map<string, unknown>();
  for (const key of keys) {
    if (typeof key !== 'string' || !allowed.has(key)) {
      invalidProof();
    }
    const descriptor = Reflect.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      invalidProof();
    }
    fields.set(key, descriptor.value);
  }
  return fields;
}

function uuidV4(value: unknown): value is string {
  return typeof value === 'string' && value.length === 36 && UUID_V4.test(value);
}

export function issueRegisteredQuarantineProbe(input: RegistryProbeFields): RegisteredQuarantineProbeProof {
  try {
    const fields = dataFields(input, PROOF_KEYS);
    const attemptId = fields.get('attemptId');
    const objectKey = fields.get('objectKey');
    const claimId = fields.get('claimId');
    const claimGeneration = fields.get('claimGeneration');
    if (!uuidV4(attemptId) || !uuidV4(claimId) || typeof claimGeneration !== 'number'
      || !Number.isInteger(claimGeneration) || claimGeneration < 1 || claimGeneration > 2_147_483_647
      || typeof objectKey !== 'string' || objectKey.length !== 84) {
      invalidProof();
    }
    const namespace = `quarantine/${attemptId}/`;
    if (!objectKey.startsWith(namespace) || !uuidV4(objectKey.slice(namespace.length))) {
      invalidProof();
    }
    const targetFields = dataFields(fields.get('target'), TARGET_KEYS);
    const target = canonicalRegistryTarget(targetFields.get('endpoint'), targetFields.get('bucket'), targetFields.get('region'));
    if (target === undefined) {
      invalidProof();
    }
    const proof = Object.freeze({}) as RegisteredQuarantineProbeProof;
    PROOFS.add(proof);
    PROOF_FIELDS.set(proof, Object.freeze({ attemptId, objectKey, target, claimId, claimGeneration }));
    return proof;
  } catch {
    // Reflection traps (including revoked proxies) can throw arbitrary values.
    invalidProof();
  }
}

/** Never reflect on an unbranded supplied grant, not even to test its shape. */
export function requireRegisteredQuarantineProbe(value: unknown): RegistryProbeFields {
  if (typeof value !== 'object' || value === null || !PROOFS.has(value)) {
    invalidProof();
  }
  return PROOF_FIELDS.get(value) ?? invalidProof();
}
