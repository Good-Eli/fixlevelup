/**
 * Operator-contour admission loading (docs/P05-PLAN.md §7).
 *
 * Production entrypoints (api.ts/worker.ts) load the launch admission from
 * strict environment variables BEFORE any resource is constructed: the signed
 * one-time proof token, the pinned launcher public key (file wins over the
 * literal-`\n` inline value) and the pinned witness holder pid. Every expected
 * fact is pinned from this protected configuration, never taken from the token
 * itself; the verified payload must then match all of them exactly. The loader
 * never connects to a database and never logs values: missing or inconsistent
 * input fails closed as ConfigurationError(['LAUNCH_*']). Tests construct
 * RuntimeAdmission explicitly via the test fixture instead; the
 * migration-credential CLIs (staff-bootstrap/staff-recover) are a separate
 * operator contour and are intentionally not gated here.
 */
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { ConfigurationError } from '../../runtime/config.js';
import type { DatabaseConfig } from '../database/runtime-database.js';
import { AdmissionGate } from './admission.js';
import type { AdmissionBinding, AdmissionExpectedFacts } from './admission.js';
import type { ConsumerKind, LaunchProofPayload, ProofProfile } from './proof.js';
import { proofDigestOf } from './proof.js';
import { WITNESS_KEY } from './witness.js';

export interface RuntimeAdmission {
  readonly gate: AdmissionGate;
  readonly binding: AdmissionBinding;
  /** SHA-256 of the canonical verified proof payload: the registry's exact
   * digest key, derived from the SIGNED token the loader verified — never
   * supplied separately by the environment. */
  readonly proofDigest: string;
  /** The offline-verified proof payload (facts equal to the binding's). */
  readonly payload: LaunchProofPayload;
}

// Identity of the immutable bundle returned only after the signed token and
// trusted expectations have been checked. A structural copy is not a proof.
const verifiedBundles = new WeakSet<RuntimeAdmission>();
export function isVerifiedRuntimeAdmission(value: RuntimeAdmission): boolean {
  return verifiedBundles.has(value);
}

/** Match application configuration against the verified endpoint, role and database. */
export function matchesRuntimeTarget(admission: RuntimeAdmission,
  target: Pick<DatabaseConfig, 'host' | 'port' | 'database' | 'user'>): boolean {
  const binding = admission.binding;
  return binding.database === target.database && binding.role === target.user
    && binding.expected.endpoint === `${target.host}:${String(target.port)}`;
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const digestPattern = /^[0-9a-f]{64}$/;
const consumerKinds: readonly ConsumerKind[] = ['API', 'WORKER', 'TEST'];
const profiles: readonly ProofProfile[] = ['S0', 'S1', 'S2', 'S3'];

/** Deterministic per-instance witness objectId inside the 557001 namespace
 * (positive 31-bit, collision-safe for the isolated contour). */
export function witnessKeyForInstance(instanceId: string): { readonly classId: number; readonly objectId: number } {
  const hash = createHash('sha256').update(`p05/witness/${instanceId}`, 'utf8').digest();
  const objectId = hash.readUInt32BE(0) & 0x7fffffff;
  if (!Number.isInteger(objectId) || objectId <= 0) { return { classId: WITNESS_KEY.classId, objectId: WITNESS_KEY.objectId }; }
  return { classId: WITNESS_KEY.classId, objectId };
}

/**
 * Reads and cross-checks the pinned admission contour. The proof token is
 * verified offline against the pinned key and every pinned fact; the database
 * name/role must also equal the DatabaseConfig the entrypoint will use, so a
 * token minted for another endpoint cannot be replayed here. When
 * `requiredConsumer` is given, the pinned consumer kind must equal it exactly
 * (an API entrypoint only admits an API proof; a worker only a WORKER proof),
 * so a proof minted for one consumer kind cannot start another.
 */
export function loadRuntimeAdmission(env: NodeJS.ProcessEnv, deps: { database: DatabaseConfig;
  requiredConsumer?: 'API' | 'WORKER' | 'TEST' }): RuntimeAdmission {
  const fields: string[] = [];
  const database = env['LAUNCH_DATABASE'] ?? '';
  const databaseOidText = env['LAUNCH_DATABASE_OID'] ?? '';
  const databaseOid = Number(databaseOidText);
  const role = env['LAUNCH_ROLE'] ?? '';
  const schema = env['LAUNCH_SCHEMA'] ?? '';
  const profile = env['LAUNCH_PROFILE'];
  const endpoint = env['LAUNCH_ENDPOINT'] ?? '';
  const issuerGenerationText = env['LAUNCH_ISSUER_GENERATION'] ?? '';
  const issuerGeneration = Number(issuerGenerationText);
  const launchNonce = env['LAUNCH_NONCE'] ?? '';
  const consumerKind = env['LAUNCH_CONSUMER_KIND'];
  const instanceId = env['LAUNCH_INSTANCE_ID'] ?? '';
  const channelId = env['LAUNCH_CHANNEL_ID'] ?? '';
  const artifactDigest = env['LAUNCH_ARTIFACT_DIGEST'] ?? '';
  const historyManifestDigest = env['LAUNCH_HISTORY_MANIFEST_DIGEST'] ?? '';
  const physicalContractDigest = env['LAUNCH_PHYSICAL_CONTRACT_DIGEST'] ?? '';
  const token = env['LAUNCH_PROOF_TOKEN'] ?? '';
  const witnessPidText = env['LAUNCHER_WITNESS_PID'] ?? '';
  const witnessPid = Number(witnessPidText);

  const keyFile = env['LAUNCHER_PUBLIC_KEY_FILE'];
  const keyInline = env['LAUNCHER_PUBLIC_KEY_PEM'] ?? '';
  let publicKeyPem = '';
  if (keyFile !== undefined && keyFile.length > 0) {
    try {
      publicKeyPem = readFileSync(keyFile, 'utf8');
    } catch {
      fields.push('LAUNCHER_PUBLIC_KEY_FILE');
    }
  } else if (keyInline.length > 0) {
    publicKeyPem = keyInline.replaceAll('\\n', '\n');
  } else {
    fields.push('LAUNCHER_PUBLIC_KEY_PEM');
  }
  if (publicKeyPem.length > 0 && !/^-----BEGIN PUBLIC KEY-----[\s\S]+-----END PUBLIC KEY-----/.test(publicKeyPem)) {
    fields.push('LAUNCHER_PUBLIC_KEY_PEM');
  }

  if (database.length === 0 || database !== deps.database.database) { fields.push('LAUNCH_DATABASE'); }
  if (!/^\d+$/.test(databaseOidText) || !Number.isInteger(databaseOid) || databaseOid <= 0) { fields.push('LAUNCH_DATABASE_OID'); }
  if (role.length === 0 || role !== deps.database.user) { fields.push('LAUNCH_ROLE'); }
  if (schema.length === 0) { fields.push('LAUNCH_SCHEMA'); }
  if (typeof profile !== 'string' || !profiles.includes(profile as ProofProfile)) { fields.push('LAUNCH_PROFILE'); }
  // The endpoint fact must name the EXACT configured connection endpoint
  // (host:port), not merely be a non-empty string: a proof minted for another
  // endpoint cannot be pinned here.
  if (endpoint !== `${deps.database.host}:${String(deps.database.port)}`) { fields.push('LAUNCH_ENDPOINT'); }
  if (!/^\d+$/.test(issuerGenerationText) || !Number.isInteger(issuerGeneration) || issuerGeneration < 0) { fields.push('LAUNCH_ISSUER_GENERATION'); }
  if (!uuidPattern.test(launchNonce)) { fields.push('LAUNCH_NONCE'); }
  if (typeof consumerKind !== 'string' || !consumerKinds.includes(consumerKind as ConsumerKind)) { fields.push('LAUNCH_CONSUMER_KIND'); }
  if (deps.requiredConsumer !== undefined && consumerKind !== deps.requiredConsumer) { fields.push('LAUNCH_CONSUMER_KIND'); }
  if (!uuidPattern.test(instanceId)) { fields.push('LAUNCH_INSTANCE_ID'); }
  if (!uuidPattern.test(channelId)) { fields.push('LAUNCH_CHANNEL_ID'); }
  if (!digestPattern.test(artifactDigest)) { fields.push('LAUNCH_ARTIFACT_DIGEST'); }
  if (!digestPattern.test(historyManifestDigest)) { fields.push('LAUNCH_HISTORY_MANIFEST_DIGEST'); }
  if (!digestPattern.test(physicalContractDigest)) { fields.push('LAUNCH_PHYSICAL_CONTRACT_DIGEST'); }
  if (token.length === 0 || token.includes('\n')) { fields.push('LAUNCH_PROOF_TOKEN'); }
  if (!/^\d+$/.test(witnessPidText) || !Number.isInteger(witnessPid) || witnessPid <= 0) { fields.push('LAUNCHER_WITNESS_PID'); }

  if (fields.length) { throw new ConfigurationError(fields); }

  const expected: AdmissionExpectedFacts = {
    endpoint,
    issuerGeneration,
    launchNonce,
    consumerKind: consumerKind as ConsumerKind,
    instanceId,
    channelId,
    artifactDigest,
    historyManifestDigest,
    physicalContractDigest,
  };
  const binding: AdmissionBinding = {
    database,
    databaseOid,
    role,
    schema,
    // Per-instance witness key (plan §7 item 2: the witness is held per
    // launched instance, not cluster-globally): the objectId is derived from
    // the pinned instanceId inside the dedicated 557001 namespace, so
    // independently launched API and worker sessions never contend for one
    // exclusive key for their entire lifetimes. Falls back to the shared
    // constant only when derivation is impossible (validated UUIDs above make
    // this unreachable, kept fail-visible).
    witnessKey: witnessKeyForInstance(instanceId),
    profile: profile as ProofProfile,
    witnessHolderPid: witnessPid,
    expected,
  };
  const gate = new AdmissionGate({ binding, publicKeyPem });
  // Offline full check: signature, expiry, target identity, profile, witness key
  // and every pinned fact. No DB access, no value logging; fail closed.
  let payload: LaunchProofPayload;
  try {
    payload = gate.verifyProofToken(token, new Date());
  } catch {
    throw new ConfigurationError(['LAUNCH_PROOF_TOKEN']);
  }
  // The registry digest is DERIVED from the verified canonical payload — the
  // binding of the one-time consumption to the exact signed token (round-5
  // audit MUST 2: no separately supplied digest can name another row).
  const proofDigest = proofDigestOf(payload);
  Object.freeze(binding.expected);
  Object.freeze(binding.witnessKey);
  Object.freeze(binding);
  Object.freeze(payload.targetIdentity);
  Object.freeze(payload.witness);
  Object.freeze(payload);
  Object.freeze(gate);
  const verified = Object.freeze({ gate, binding, payload, proofDigest });
  verifiedBundles.add(verified);
  return verified;
}
