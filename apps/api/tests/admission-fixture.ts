/**
 * P05-01 test admission fixture.
 *
 * Builds the synthetic launch admission the app path requires: an Ed25519
 * keypair generated in memory, random-but-well-formed expected facts, and —
 * for `admitFixture` — a REAL launcher witness held on a migrator (or any
 * operator) connection to the same disposable database, pinned to the exact
 * holder pid. The point of fixtures is exercising the application path, not
 * the isolation proof (isolation is proven in requests-admission.test.ts).
 *
 * `syntheticAdmission` builds the same typed bundle without any connection:
 * for tests that construct resources with unreachable database configs and
 * therefore must never perform (or admit) DB work.
 */
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Pool } from 'pg';
import type { Client, PoolClient } from 'pg';
import type { WitnessConnection } from '../src/infrastructure/admission/witness.js';
import { AdmissionGate } from '../src/infrastructure/admission/admission.js';
import type { AdmissionBinding } from '../src/infrastructure/admission/admission.js';
import { canonicalJson, signProof } from '../src/infrastructure/admission/proof.js';
import { admitProcess } from '../src/infrastructure/admission/process-admission.js';
import type { ChildHandshake, LauncherChannel, ProcessAuthorization } from '../src/infrastructure/admission/process-admission.js';
import type { ConsumerKind, LaunchProofPayload } from '../src/infrastructure/admission/proof.js';
import type { RuntimeAdmission } from '../src/infrastructure/admission/runtime-admission.js';
import { holdWitness, releaseWitness } from '../src/infrastructure/admission/witness.js';
import { witnessKeyForInstance } from '../src/infrastructure/admission/runtime-admission.js';

const toolingRoot = resolve(import.meta.dirname, '../../..');

function runtimePassword(): string {
  const source = readFileSync(resolve(toolingRoot, 'packages/database-tooling/.env'), 'utf8');
  const password = /^FIXLEVELUP_RUNTIME_PASSWORD=([a-f0-9]{64})$/m.exec(source)?.[1];
  if (!password) { throw new Error('Local runtime credentials are required for the protocol-completing admission fixture'); }
  return password;
}

/**
 * Completes a REAL process admission (round-8 audit: no test issuer of
 * genuine markers exists — admitProcess is the only issuer, in the compiled
 * artifact too). The child side is the PRODUCTION admitProcess: live witness
 * verification on a real connection to the fixture database, handshake, one
 * approval, final live + DB-clock check, ack. The launcher side of the
 * in-memory channel approves exactly once. The physical-profile dep is a
 * test stand-in; the exact classifier is proven in the wiring suite.
 */
async function completeViaProtocol(admission: RuntimeAdmission): Promise<ProcessAuthorization> {
  const listeners: Array<(message: unknown) => void> = [];
  let handshakes = 0;
  const channel: LauncherChannel = {
    send: (message: unknown): boolean => {
      if (message !== null && typeof message === 'object' && (message as Record<string, unknown>)['type'] === 'p05/launch/handshake') {
        handshakes += 1;
        const hs = message as ChildHandshake;
        for (const l of listeners) { l({ type: 'p05/launch/approve', instanceId: hs.instanceId, launchNonce: hs.launchNonce }); }
      }
      return true;
    },
    on: (_: 'message', listener: (message: unknown) => void) => { listeners.push(listener); return channel; },
  };
  const authorization = await admitProcess(admission, {
    database: { host: '127.0.0.1', port: 55432, user: 'fixlevelup_runtime', password: runtimePassword() },
    channel,
    verifyProfile: (): Promise<boolean> => Promise.resolve(true),
    approvalTimeoutMs: 5_000,
  });
  if (handshakes !== 1) { throw new Error('Protocol completion expected exactly one handshake'); }
  return authorization;
}

export interface AdmissionHandle {
  readonly admission: RuntimeAdmission;
  /** The pinned launcher public key of this handle (for LAUNCHER_PUBLIC_KEY_FILE tests). */
  readonly publicKeyPem: string;
  /** Operator-contour env (LAUNCH_*) reproducing this admission via loadRuntimeAdmission. */
  readonly env: NodeJS.ProcessEnv;
  /** Releases the launcher witness (and returns a pool-checked-out client). */
  release(): Promise<void>;
}

/** A handle with a COMPLETED process admission (the application-path bundle). */
export interface AdmittedHandle extends AdmissionHandle {
  /** Issued by the production admitProcess after a real protocol run. */
  readonly authorization: ProcessAuthorization;
}

function randomFacts(consumerKind: ConsumerKind) {
  return {
    endpoint: '127.0.0.1:55432',
    issuerGeneration: 1 + randomBytes(4).readUInt32BE(0) % 1_000_000_000,
    launchNonce: randomUUID(),
    consumerKind,
    instanceId: randomUUID(),
    channelId: randomUUID(),
    artifactDigest: randomBytes(32).toString('hex'),
    historyManifestDigest: randomBytes(32).toString('hex'),
    physicalContractDigest: randomBytes(32).toString('hex'),
  };
}

function buildHandle(binding: AdmissionBinding, publicKeyPem: string, privateKeyPem: string,
  witness: WitnessConnection, releaseClient?: PoolClient): AdmissionHandle {
  const gate = new AdmissionGate({ binding, publicKeyPem });
  const payload: LaunchProofPayload = {
    ...binding.expected,
    targetIdentity: {
      database: binding.database,
      databaseOid: binding.databaseOid,
      runtimeRole: binding.role,
      schema: binding.schema,
    },
    profile: binding.profile,
    witness: { classId: binding.witnessKey.classId, objectId: binding.witnessKey.objectId, mode: 'SESSION' },
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  };
  const token = signProof(payload, privateKeyPem);
  // The registry digest is derived from the canonical verified payload —
  // the same derivation the loader performs (RuntimeAdmission.proofDigest).
  const proofDigest = createHash('sha256').update(canonicalJson(payload), 'utf8').digest('hex');
  const env: NodeJS.ProcessEnv = {
    LAUNCH_PROOF_TOKEN: token,
    LAUNCHER_PUBLIC_KEY_PEM: publicKeyPem.replaceAll('\n', '\\n'),
    LAUNCHER_WITNESS_PID: String(binding.witnessHolderPid),
    LAUNCH_DATABASE: binding.database,
    LAUNCH_DATABASE_OID: String(binding.databaseOid),
    LAUNCH_ROLE: binding.role,
    LAUNCH_SCHEMA: binding.schema,
    LAUNCH_PROFILE: binding.profile,
    LAUNCH_ENDPOINT: payload.endpoint,
    LAUNCH_ISSUER_GENERATION: String(payload.issuerGeneration),
    LAUNCH_NONCE: payload.launchNonce,
    LAUNCH_CONSUMER_KIND: payload.consumerKind,
    LAUNCH_INSTANCE_ID: payload.instanceId,
    LAUNCH_CHANNEL_ID: payload.channelId,
    LAUNCH_ARTIFACT_DIGEST: payload.artifactDigest,
    LAUNCH_HISTORY_MANIFEST_DIGEST: payload.historyManifestDigest,
    LAUNCH_PHYSICAL_CONTRACT_DIGEST: payload.physicalContractDigest,
  };
  const handle: AdmissionHandle = {
    admission: { gate, binding, payload, proofDigest },
    publicKeyPem,
    env,
    async release(): Promise<void> {
      await releaseWitness(witness, binding.witnessKey).catch(() => undefined);
      releaseClient?.release();
    },
  };
  return handle;
}

/**
 * Holds a real launcher witness on `holder` (a pool on, or a client to, the
 * same database the guarded pools will use) and returns the pinned admission
 * plus the matching operator-contour env. `schema` must equal the runtime
 * connections' current_schema() ('public' unless the role search_path is
 * altered).
 */
export async function admitFixture(
  holder: Pool | Client,
  database: string,
  consumerKind: ConsumerKind,
  schema = 'public',
  /** Test override: mint a proof for a profile the database does NOT have
   * (used to prove the exact-profile refusal in both directions). */
  forceProfile?: 'S0' | 'S1',
): Promise<AdmittedHandle> {
  const fromPool = holder instanceof Pool;
  const launcher: PoolClient = fromPool ? await holder.connect() : holder as unknown as PoolClient;
  const facts = await launcher.query<{ db: string; oid: number; pid: number }>(
    `SELECT current_database() AS db,
       (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname = current_database()) AS oid,
       pg_catalog.pg_backend_pid() AS pid`);
  const row = facts.rows[0];
  if (!row || row.db !== database || !Number.isInteger(row.oid) || row.oid <= 0 || !Number.isInteger(row.pid)) {
    if (fromPool) { launcher.release(); }
    throw new Error('Admission fixture could not pin the launcher identity');
  }
  const keyPair = generateKeyPairSync('ed25519');
  const expected = randomFacts(consumerKind);
  // The pinned profile follows the ACTUAL schema of the target database: S1
  // when the 022 request-intake foundation exists, S0 for a pre-P05 chain
  // (e.g. the dev database). The exact-profile verifier refuses a mismatch,
  // so the fixture must state the true profile.
  const profile: 'S0' | 'S1' = forceProfile ?? await launcher.query(
    `SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='foundation' AND c.relname='requests'`).then((r) => (r.rowCount ?? 0) > 0 ? 'S1' : 'S0');
  // Per-instance witness key (§7): derived from the pinned instanceId, so the
  // loader (which derives from the env instanceId) and this fixture agree, and
  // independent launcher sessions never contend for one exclusive key.
  const binding: AdmissionBinding = {
    database,
    databaseOid: row.oid,
    role: 'fixlevelup_runtime',
    schema,
    witnessKey: witnessKeyForInstance(expected.instanceId),
    profile,
    witnessHolderPid: row.pid,
    expected,
  };
  try {
    await holdWitness(launcher, binding.witnessKey);
  } catch (error) {
    if (fromPool) { launcher.release(); }
    throw error;
  }
  const handle = buildHandle(binding,
    keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    launcher, fromPool ? launcher : undefined);
  try {
    return { ...handle, authorization: await completeViaProtocol(handle.admission) };
  } catch (error) {
    await handle.release().catch(() => undefined);
    throw error;
  }
}

/**
 * Same typed bundle with no connection at all: a synthetic database OID and a
 * witness pid that matches no backend, so any real DB work fails closed. For
 * tests constructing resources against unreachable database configurations.
 */
export function syntheticAdmission(consumerKind: ConsumerKind, database = 'fixlevelup_dev', schema = 'public'): AdmissionHandle {
  const keyPair = generateKeyPairSync('ed25519');
  const expected = randomFacts(consumerKind);
  const binding: AdmissionBinding = {
    database,
    databaseOid: 16_384 + randomBytes(2).readUInt16BE(0),
    role: 'fixlevelup_runtime',
    schema,
    witnessKey: witnessKeyForInstance(expected.instanceId),
    profile: 'S1',
    witnessHolderPid: 4_000_000 + randomBytes(3).readUIntBE(0, 3),
    expected,
  };
  // No live witness: release only targets a detached statement executor, so
  // releasing is a harmless no-op for the synthetic bundle.
  const detached: WitnessConnection = { query: () => Promise.reject(new Error('No launcher witness in the synthetic admission')) };
  return buildHandle(binding,
    keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    detached);
}
