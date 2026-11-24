/**
 * Signed one-time launch proof (docs/P05-PLAN.md §7, item 1).
 *
 * A short-lived proof token is issued by the external launcher operator and
 * presented by a child process exactly once. The payload is canonical JSON
 * (sorted keys, no whitespace), signed with a detached Ed25519 signature. The
 * signing key never leaves the operator; the application pins only the public
 * key. Errors never echo payload or key material.
 */
import { createHash, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';

export type ConsumerKind = 'API' | 'WORKER' | 'TEST';
export type ProofProfile = 'S0' | 'S1';

/** Exact identity the proof binds to the configured connection endpoint. */
export interface LaunchProofTargetIdentity {
  readonly database: string;
  readonly databaseOid: number;
  readonly runtimeRole: string;
  readonly schema: string;
}

export interface LaunchProofPayload {
  readonly issuerGeneration: number;
  readonly launchNonce: string;
  readonly consumerKind: ConsumerKind;
  readonly instanceId: string;
  readonly channelId: string;
  readonly artifactDigest: string;
  /**
   * Exact configured connection endpoint identity (plan §7 item 1:
   * targetIdentity binds the proof to the same configured endpoint; in the
   * test contour this is the local loopback endpoint string).
   */
  readonly endpoint: string;
  readonly targetIdentity: LaunchProofTargetIdentity;
  readonly profile: ProofProfile;
  readonly historyManifestDigest: string;
  readonly physicalContractDigest: string;
  readonly witness: {
    readonly classId: number;
    readonly objectId: number;
    readonly mode: 'SESSION';
  };
  readonly expiresAt: string;
}

export type ProofErrorCode = 'MALFORMED' | 'BAD_SIGNATURE' | 'EXPIRED';

export class ProofError extends Error {
  readonly code: ProofErrorCode;

  constructor(code: ProofErrorCode, message: string) {
    super(message);
    this.name = 'ProofError';
    this.code = code;
  }
}

/** Deterministic serialization: recursively sorted object keys, no whitespace. */
export function canonicalJson(value: unknown): string {
  return serializeCanonical(value);
}

function serializeCanonical(value: unknown): string {
  if (value === null || typeof value === 'number' || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => serializeCanonical(item)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const entries = Object.keys(record)
      .filter((key) => record[key] !== undefined)
      .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))
      .map((key) => `${JSON.stringify(key)}:${serializeCanonical(record[key])}`);
    return `{${entries.join(',')}}`;
  }
  throw new Error('Unsupported canonical JSON value');
}

/**
 * Signs the canonical payload and returns the proof token
 * `<base64url(payload)>.<base64(signature)>`. The signature is detached
 * Ed25519 over the canonical JSON bytes.
 */
export function signProof(payload: LaunchProofPayload, privateKeyPem: string): string {
  const canonical = canonicalJson(payload);
  const signature = cryptoSign(null, Buffer.from(canonical, 'utf8'), privateKeyPem);
  return `${Buffer.from(canonical, 'utf8').toString('base64url')}.${signature.toString('base64')}`;
}

/** Verifies signature, then payload shape, then expiry against `now`. */
export function verifyProof(token: string, publicKeyPem: string, now: Date): LaunchProofPayload {
  const parts = token.split('.');
  const encodedPayload = parts[0] ?? '';
  const encodedSignature = parts[1] ?? '';
  if (parts.length !== 2 || encodedPayload.length === 0 || encodedSignature.length === 0) {
    throw new ProofError('MALFORMED', 'Malformed launch proof token');
  }
  let canonical: string;
  try {
    canonical = Buffer.from(encodedPayload, 'base64url').toString('utf8');
    JSON.parse(canonical) as unknown;
  } catch {
    throw new ProofError('MALFORMED', 'Malformed launch proof token');
  }
  let signatureValid: boolean;
  try {
    signatureValid = cryptoVerify(null, Buffer.from(canonical, 'utf8'), publicKeyPem, Buffer.from(encodedSignature, 'base64'));
  } catch {
    throw new ProofError('BAD_SIGNATURE', 'Launch proof signature check failed');
  }
  if (!signatureValid) {
    throw new ProofError('BAD_SIGNATURE', 'Launch proof signature check failed');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(canonical) as unknown;
  } catch {
    throw new ProofError('MALFORMED', 'Malformed launch proof token');
  }
  const payload = assertLaunchProofPayload(parsed);
  const expiresAt = Date.parse(payload.expiresAt);
  if (!Number.isFinite(expiresAt) || now.getTime() >= expiresAt) {
    throw new ProofError('EXPIRED', 'Launch proof expired');
  }
  return payload;
}

/** Stable 64-hex digest of the canonical proof payload, used by the registry. */
export function proofDigestOf(payload: LaunchProofPayload): string {
  return createHash('sha256').update(canonicalJson(payload), 'utf8').digest('hex');
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const digestPattern = /^[0-9a-f]{64}$/;
const consumerKinds: readonly ConsumerKind[] = ['API', 'WORKER', 'TEST'];
const profiles: readonly ProofProfile[] = ['S0', 'S1'];

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) { return undefined; }
  return value as Record<string, unknown>;
}

function assertLaunchProofPayload(value: unknown): LaunchProofPayload {
  const malformed = (): ProofError => new ProofError('MALFORMED', 'Malformed launch proof payload');
  const record = asRecord(value);
  if (!record) { throw malformed(); }
  const target = asRecord(record['targetIdentity']);
  const witness = asRecord(record['witness']);
  if (!target || !witness) { throw malformed(); }
  const issuerGeneration = record['issuerGeneration'];
  const databaseOid = target['databaseOid'];
  const witnessClassId = witness['classId'];
  const witnessObjectId = witness['objectId'];
  if (typeof issuerGeneration !== 'number' || !Number.isInteger(issuerGeneration) || issuerGeneration < 0
    || typeof databaseOid !== 'number' || !Number.isInteger(databaseOid) || databaseOid <= 0
    || typeof witnessClassId !== 'number' || !Number.isInteger(witnessClassId)
    || typeof witnessObjectId !== 'number' || !Number.isInteger(witnessObjectId)) {
    throw malformed();
  }
  const launchNonce = record['launchNonce'];
  const instanceId = record['instanceId'];
  const channelId = record['channelId'];
  const consumerKind = record['consumerKind'];
  const artifactDigest = record['artifactDigest'];
  const endpoint = record['endpoint'];
  const historyManifestDigest = record['historyManifestDigest'];
  const physicalContractDigest = record['physicalContractDigest'];
  const profile = record['profile'];
  const expiresAt = record['expiresAt'];
  const database = target['database'];
  const runtimeRole = target['runtimeRole'];
  const schema = target['schema'];
  const mode = witness['mode'];
  if (typeof launchNonce !== 'string' || !uuidPattern.test(launchNonce)
    || typeof instanceId !== 'string' || !uuidPattern.test(instanceId)
    || typeof channelId !== 'string' || !uuidPattern.test(channelId)
    || typeof consumerKind !== 'string' || !consumerKinds.includes(consumerKind as ConsumerKind)
    || typeof artifactDigest !== 'string' || !digestPattern.test(artifactDigest)
    || typeof endpoint !== 'string' || endpoint.length === 0 || endpoint.length > 200
    || typeof historyManifestDigest !== 'string' || !digestPattern.test(historyManifestDigest)
    || typeof physicalContractDigest !== 'string' || !digestPattern.test(physicalContractDigest)
    || typeof profile !== 'string' || !profiles.includes(profile as ProofProfile)
    || typeof expiresAt !== 'string' || !Number.isFinite(Date.parse(expiresAt))
    || typeof database !== 'string' || database.length === 0
    || typeof runtimeRole !== 'string' || runtimeRole.length === 0
    || typeof schema !== 'string' || schema.length === 0
    || mode !== 'SESSION') {
    throw malformed();
  }
  return {
    issuerGeneration,
    launchNonce,
    consumerKind: consumerKind as ConsumerKind,
    instanceId,
    channelId,
    artifactDigest,
    endpoint,
    targetIdentity: { database, databaseOid, runtimeRole, schema },
    profile: profile as ProofProfile,
    historyManifestDigest,
    physicalContractDigest,
    witness: { classId: witnessClassId, objectId: witnessObjectId, mode: 'SESSION' },
    expiresAt,
  };
}
