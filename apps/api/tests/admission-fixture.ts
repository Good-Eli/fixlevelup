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
import { Client, Pool } from 'pg';
import type { PoolClient } from 'pg';
import type { WitnessConnection } from '../src/infrastructure/admission/witness.js';
import { loadRuntimeAdmission } from '../src/infrastructure/admission/runtime-admission.js';
import type { AdmissionBinding, AdmissionExpectedFacts } from '../src/infrastructure/admission/admission.js';
import { signProof } from '../src/infrastructure/admission/proof.js';
import { admitProcess } from '../src/infrastructure/admission/process-admission.js';
import { launchBindingOf } from '../src/infrastructure/admission/process-admission.js';
import type { ChildHandshake, ProcessAuthorization } from '../src/infrastructure/admission/process-admission.js';
import type { ConsumerKind, LaunchProofPayload } from '../src/infrastructure/admission/proof.js';
import type { RuntimeAdmission } from '../src/infrastructure/admission/runtime-admission.js';
import { holdWitness, releaseWitness } from '../src/infrastructure/admission/witness.js';
import { witnessKeyForInstance } from '../src/infrastructure/admission/runtime-admission.js';
import { issueProof } from '../src/infrastructure/admission/registry.js';
import { loadControlContour } from '../src/infrastructure/admission/control-contour.js';
import { decideLaunch } from '../src/infrastructure/admission/launcher.js';
import type { ExpectedChild, LauncherDeps } from '../src/infrastructure/admission/launcher.js';
import type { DatabaseConfig } from '../src/infrastructure/database/runtime-database.js';
import { authFixtureMigrations, verifyOperatorMigrationHistory } from './auth-db-fixture.js';
import { testLaunchChannel, withTestLaunchChannel } from './admission-transport-fixture.js';
import type { LauncherChannel } from '../src/infrastructure/admission/private-launch-channel.js';

const toolingRoot = resolve(import.meta.dirname, '../../..');

function runtimePassword(): string {
  const password = fixturePassword('FIXLEVELUP_RUNTIME_PASSWORD');
  if (!password) { throw new Error('Local runtime credentials are required for the protocol-completing admission fixture'); }
  return password;
}

function fixturePassword(key: 'FIXLEVELUP_RUNTIME_PASSWORD' | 'FIXLEVELUP_MIGRATOR_PASSWORD'): string | undefined {
  if (process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1') {
    const password = process.env[key];
    return password && /^[a-f0-9]{64}$/.test(password) ? password : undefined;
  }
  const source = readFileSync(resolve(toolingRoot, 'packages/database-tooling/.env'), 'utf8');
  return new RegExp(`^${key}=([a-f0-9]{64})$`, 'm').exec(source)?.[1];
}

const loopback = { host: '127.0.0.1', port: 55432 } as const;

/** Parent-only control spec; the narrow launcher cannot provision its registry. */
export function verifiedControlConfig(database: string): LauncherDeps['control'] {
  const { control } = loadControlContour(process.env);
  const runSuffix = /^fixlevelup_p05_control_([a-f0-9]{12})$/.exec(control.database)?.[1];
  if (process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] !== '1' || control.host !== loopback.host
    || control.port !== loopback.port || control.database === database || !runSuffix
    || control.user !== `fixlevelup_p05_launcher_${runSuffix}` || !/^[a-f0-9]{64}$/.test(control.password)) {
    throw new Error('Invalid isolated launcher control binding');
  }
  return control;
}

export async function openVerifiedControl(control: LauncherDeps['control']): Promise<Client> {
  const cluster = process.env['FIXLEVELUP_CLUSTER_NAME'] ?? '';
  if (!/^fixlevelup_p05s4_lab_[a-z0-9_]{1,40}$/.test(cluster)) { throw new Error('Invalid isolated control cluster'); }
  const client = new Client({ ...control, connectionTimeoutMillis: 3000, statement_timeout: 3000, query_timeout: 4000 });
  client.on('error', () => undefined);
  try {
    await client.connect();
    const { rows } = await client.query<{ valid: boolean }>(`SELECT current_database() = $1 AND current_user = $2
      AND session_user = $2 AND current_setting('cluster_name') = $3
      AND current_setting('server_version_num') = '180007'
      AND NOT has_database_privilege('fixlevelup_runtime',current_database(),'CONNECT')
      AND NOT has_database_privilege('fixlevelup_migrator',current_database(),'CONNECT')
      AND NOT has_schema_privilege(current_user,'launch_control','CREATE')
      AND NOT has_table_privilege(current_user,'launch_control.launch_proofs','DELETE,TRUNCATE,UPDATE')
      AND has_table_privilege(current_user,'launch_control.launch_proofs','SELECT')
      AND has_table_privilege(current_user,'launch_control.launch_proofs','INSERT')
      AND has_column_privilege(current_user,'launch_control.launch_proofs','state','UPDATE')
      AND has_column_privilege(current_user,'launch_control.launch_proofs','consumed_at','UPDATE') AS valid`,
    [control.database, control.user, cluster]);
    if (rows[0]?.valid !== true) { throw new Error('Invalid isolated control permissions'); }
    return client;
  } catch {
    await client.end().catch(() => undefined);
    throw new Error('Unable to attest isolated launch control');
  }
}

function runtimeDatabaseConfig(database: string): DatabaseConfig {
  return { host: '127.0.0.1', port: 55432, database, user: 'fixlevelup_runtime', password: runtimePassword() };
}

interface LauncherIdentity {
  readonly db: string;
  readonly oid: number;
  readonly pid: number;
}

/** Pins the launcher identity facts from the connection that holds the witness. */
async function pinLauncherIdentity(launcher: PoolClient, database: string): Promise<LauncherIdentity> {
  const facts = await launcher.query<LauncherIdentity>(
    `SELECT current_database() AS db,
       (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname = current_database()) AS oid,
       pg_catalog.pg_backend_pid() AS pid`);
  const row = facts.rows[0];
  if (!row || row.db !== database || !Number.isInteger(row.oid) || row.oid <= 0 || !Number.isInteger(row.pid)) {
    throw new Error('Admission fixture could not pin the launcher identity');
  }
  return row;
}

interface PhysicalState {
  /** The schema profile the target database actually is. */
  readonly profile: 'S0' | 'S1' | 'S2' | 'S3';
  /** True when the migration chain has been applied (`foundation.staff` exists). */
  readonly migrated: boolean;
}

/** Detects the ACTUAL physical profile and whether migrations already ran. */
async function detectPhysicalState(launcher: PoolClient): Promise<PhysicalState> {
  const { rows } = await launcher.query<{ has_staff: boolean; has_requests: boolean; has_form_groups: boolean; has_effects: boolean }>(
    `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='foundation' AND c.relname='staff') AS has_staff,
       EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='foundation' AND c.relname='requests') AS has_requests,
       EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='foundation' AND c.relname='form_browser_groups') AS has_form_groups,
       to_regclass('foundation.request_command_receipts') IS NOT NULL AS has_effects`);
  const row = rows[0];
  const profile: 'S0' | 'S1' | 'S2' | 'S3' = row?.has_effects === true ? 'S3'
    : row?.has_form_groups === true ? 'S2' : row?.has_requests === true ? 'S1' : 'S0';
  return { profile, migrated: row?.has_staff === true };
}

/**
 * The exact readiness predicates that define each physical profile in
 * `src/infrastructure/admission/physical-profile.ts` (every profile also
 * requires legacy readiness and the separate P04 catalog gate).
 */
const profileContractPredicates: Record<'S0' | 'S1' | 'S2' | 'S3', readonly string[]> = {
  S0: ['legacy.ready', 'catalog.management.ready', 'preIntakeProfileAbsent', 'formSessionProfileAbsent'],
  S1: ['legacy.ready', 'catalog.management.ready', 'requestIntakeReady', 'formSessionProfileAbsent'],
  S2: ['legacy.ready', 'catalog.management.ready', 'requestIntakeReady', 'formSessionReady'],
  S3: ['legacy.ready', 'catalog.management.ready', 'formSessionReady', 'requestEffectsReady'],
};

/**
 * Deterministic SHA-256 of the physical-profile contract — the same artifact
 * fact the launcher carries in the signed proof. Tests derive it from the
 * profile instead of random bytes, so the proof is reproducible.
 */
export function physicalContractDigestOf(profile: 'S0' | 'S1' | 'S2' | 'S3'): string {
  const predicates = profileContractPredicates[profile];
  return createHash('sha256')
    .update(`p05/physical-contract/v1/${profile}\n${predicates.join('\n')}`, 'utf8')
    .digest('hex');
}

/** Holds the witness and builds the handle; a build failure never leaks the lock. */
async function holdWitnessAndBuildHandle(
  launcher: PoolClient,
  binding: AdmissionBinding,
  fromPool: boolean,
  expiresAt?: Date,
): Promise<AdmissionHandle> {
  await holdWitness(launcher, binding.witnessKey);
  try {
    const keyPair = generateKeyPairSync('ed25519');
    return buildHandle(binding,
      keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      launcher, fromPool ? launcher : undefined, expiresAt);
  } catch (error) {
    await releaseWitness(launcher, binding.witnessKey).catch(() => undefined);
    throw error;
  }
}

/**
 * Completes a REAL process admission (round-8 audit: no test issuer of
 * genuine markers exists — admitProcess is the only issuer, in the compiled
 * artifact too). The child side is the PRODUCTION admitProcess: live witness
 * verification on a real connection to the fixture database, handshake, one
 * approval, final live + DB-clock check, ack. Only the test transport simulates
 * delivery. The release classifier and the signature-verified bundle are used
 * unchanged. This helper does not demonstrate a real parent process or a CAS.
 */
async function completeViaProtocol(handle: AdmissionHandle, runtime: DatabaseConfig): Promise<ProcessAuthorization> {
  // Legacy/local protocol fixture: simulate delivery only; never classify it
  // as durable registry or OS IPC evidence. Runtime DB/profile checks are real.
  let handshakes = 0;
  const wire: ReturnType<typeof testLaunchChannel> = testLaunchChannel((message) => {
    if (!('type' in message)) { return; }
    const facts = launchBindingOf(message as ChildHandshake);
    if (message.type === 'p05/launch/handshake') {
      handshakes += 1;
      wire.deliver({ ...facts, type: 'p05/launch/approve' });
    } else if (message.type === 'p05/launch/active') {
      wire.deliver({ ...facts, type: 'p05/launch/activate' });
    }
  });
  try {
    const authorization = await withTestLaunchChannel(wire.channel, () => admitProcess(handle.admission, {
      database: runtime, approvalTimeoutMs: 5_000,
    }));
    if (handshakes !== 1) { throw new Error('Expected exactly one test handshake'); }
    return authorization;
  } catch (error) { wire.disconnect(); throw error; }
}
interface ChannelPair {
  readonly child: LauncherChannel;
  readonly handshake: Promise<ChildHandshake>;
  readonly ack: Promise<unknown>;
  readonly receipt: Promise<unknown>;
  deliver(message: unknown): void;
}

/**
 * One private child↔launcher channel: both directions flow through the same
 * listener set (the child's own listener is registered by admitProcess, the
 * launcher is driven by `deliver`), and the child's handshake/activation ack
 * are captured for the production decideLaunch.
 */
function channelPair(): ChannelPair {
  let resolveHandshake: (message: ChildHandshake) => void = () => undefined;
  let resolveAck: (message: unknown) => void = () => undefined;
  let resolveReceipt: (message: unknown) => void = () => undefined;
  const handshake = new Promise<ChildHandshake>((resolve) => { resolveHandshake = resolve; });
  const ack = new Promise<unknown>((resolve) => { resolveAck = resolve; });
  const receipt = new Promise<unknown>((resolve) => { resolveReceipt = resolve; });
  const wire = testLaunchChannel((message) => {
    if (!('type' in message)) { return; }
    if (message.type === 'p05/launch/handshake') { resolveHandshake(message as ChildHandshake); }
    if (message.type === 'p05/launch/active') { resolveAck(message); }
    if (message.type === 'p05/launch/activated') { resolveReceipt(message); }
  });
  return { child: wire.channel, handshake, ack, receipt, deliver: (message) => { wire.deliver(message); } };
}
/**
 * Runs the child's production admitProcess against the REAL production
 * decideLaunch: trusted-binding match, live witness gate, one-time
 * ISSUED→CONSUMED CAS on `launch_control.launch_proofs`, DB-clock expiry check,
 * exactly one approval and the activation acknowledgement.
 */
async function runVerifiedLauncherProtocol(
  handle: AdmissionHandle,
  expected: AdmissionExpectedFacts,
  consumerKind: ConsumerKind,
  runtime: DatabaseConfig,
  operator: LauncherDeps['app'],
  control: LauncherDeps['control'],
): Promise<ProcessAuthorization> {
  const { database } = runtime;
  const pair = channelPair();
  const launcherDeps: LauncherDeps = {
    app: operator,
    control,
    witnessKeyOf: witnessKeyForInstance,
    ackTimeoutMs: 5_000,
  };
  const expectedChild: ExpectedChild = {
    instanceId: expected.instanceId,
    launchNonce: expected.launchNonce,
    consumerKind,
    proofDigest: handle.admission.proofDigest,
    issuerGeneration: expected.issuerGeneration,
    witnessHolderPid: handle.admission.binding.witnessHolderPid,
    channelId: expected.channelId,
    database, databaseOid: handle.admission.binding.databaseOid,
    role: handle.admission.binding.role, profile: handle.admission.binding.profile,
  };
  const childOutcome = withTestLaunchChannel(pair.child, () => admitProcess(handle.admission, { database: runtime, approvalTimeoutMs: 5_000 })).then(
    (authorization) => ({ kind: 'admitted' as const, authorization }),
    (error: unknown) => ({ kind: 'refused' as const, error }),
  );
  // A child that refuses before its handshake (e.g. a drifted profile) must not
  // leave the launcher waiting for a handshake that will never arrive.
  const first = await Promise.race([
    pair.handshake.then((handshake) => ({ kind: 'handshake' as const, handshake })),
    childOutcome.then((outcome) => ({ kind: 'child' as const, outcome })),
  ]);
  if (first.kind === 'child') {
    if (first.outcome.kind === 'admitted') { throw new Error('Verified child admitted without a launcher handshake'); }
    throw first.outcome.error;
  }
  const decision = decideLaunch(launcherDeps, expectedChild, first.handshake, process.pid, {
    live: () => true,
    send: (message) => { pair.deliver(message); return Promise.resolve(true); },
    ack: pair.ack,
    receipt: pair.receipt,
  });
  const [outcome, launch] = await Promise.all([childOutcome, decision]);
  if (outcome.kind !== 'admitted') { throw outcome.error; }
  if (!launch.approved) { throw new Error(`Verified launch was refused: ${launch.reason}`); }
  return outcome.authorization;
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

interface FactDigests {
  readonly historyManifestDigest: string;
  readonly physicalContractDigest: string;
}

function randomFacts(consumerKind: ConsumerKind, digests?: FactDigests) {
  return {
    endpoint: '127.0.0.1:55432',
    issuerGeneration: 1 + randomBytes(4).readUInt32BE(0) % 1_000_000_000,
    launchNonce: randomUUID(),
    consumerKind,
    instanceId: randomUUID(),
    channelId: randomUUID(),
    artifactDigest: randomBytes(32).toString('hex'),
    historyManifestDigest: digests?.historyManifestDigest ?? randomBytes(32).toString('hex'),
    physicalContractDigest: digests?.physicalContractDigest ?? randomBytes(32).toString('hex'),
  };
}

function buildHandle(binding: AdmissionBinding, publicKeyPem: string, privateKeyPem: string,
  witness: WitnessConnection, releaseClient?: PoolClient, expiresAt = new Date(Date.now() + 3_600_000)): AdmissionHandle {
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
    expiresAt: expiresAt.toISOString(),
  };
  const token = signProof(payload, privateKeyPem);
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
  // Offline loading verifies the signature and freezes the real identity; it
  // never uses a database password. The live protocol uses its own runtime config.
  const admission = loadRuntimeAdmission(env, { database: { ...loopback, database: binding.database,
    user: 'fixlevelup_runtime', password: '' }, requiredConsumer: binding.expected.consumerKind });
  let released = false;
  const handle: AdmissionHandle = {
    admission,
    publicKeyPem,
    env,
    async release(): Promise<void> {
      if (released) { return; }
      released = true;
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
 *
 * This stage does not issue an application authorization. A requested profile
 * on the wrong schema can be used to test refusal; it cannot grant admission.
 */
export async function holdFixtureWitness(
  holder: Pool | Client,
  database: string,
  consumerKind: ConsumerKind,
  schema = 'public',
  /** Test override: mint a proof for a profile the database does NOT have
   * (used to prove the exact-profile refusal in both directions). */
  forceProfile?: 'S0' | 'S1' | 'S2' | 'S3',
): Promise<AdmissionHandle> {
  const fromPool = holder instanceof Pool;
  const launcher: PoolClient = fromPool ? await holder.connect() : holder as unknown as PoolClient;
  let handle: AdmissionHandle | undefined;
  try {
    const identity = await pinLauncherIdentity(launcher, database);
    const state = await detectPhysicalState(launcher);
    const expected = randomFacts(consumerKind);
    // The pinned profile follows the ACTUAL schema of the target database: S2
    // when the 023 form-session foundation exists, S1 when only the 022
    // request-intake foundation exists, S0 for a pre-P05 chain (e.g. the dev
    // database). The exact-profile verifier refuses a mismatch, so the fixture
    // must state the true profile.
    const profile: 'S0' | 'S1' | 'S2' | 'S3' = forceProfile ?? state.profile;
    // Per-instance witness key (§7): derived from the pinned instanceId, so the
    // loader (which derives from the env instanceId) and this fixture agree, and
    // independent launcher sessions never contend for one exclusive key.
    const binding: AdmissionBinding = {
      database,
      databaseOid: identity.oid,
      role: 'fixlevelup_runtime',
      schema,
      witnessKey: witnessKeyForInstance(expected.instanceId),
      profile,
      witnessHolderPid: identity.pid,
      expected,
    };
    handle = await holdWitnessAndBuildHandle(launcher, binding, fromPool);
    return handle;
  } catch (error) {
    if (handle) { await handle.release().catch(() => undefined); }
    else if (fromPool) { launcher.release(); }
    throw error;
  }
}

/** Test-only app composition using real metadata checks and simulated IPC. */
export async function admitFixture(holder: Pool | Client, database: string, consumerKind: ConsumerKind,
  schema = 'public'): Promise<AdmittedHandle> {
  const handle = await holdFixtureWitness(holder, database, consumerKind, schema);
  try {
    return { ...handle, authorization: await completeViaProtocol(handle, runtimeDatabaseConfig(database)) };
  } catch (error) {
    await handle.release();
    throw error;
  }
}
export interface VerifiedAdmissionOptions {
  /** Force the proof profile (negative drift tests). Default: the actual profile. */
  readonly profile?: 'S0' | 'S1' | 'S2' | 'S3';
  readonly consumerKind?: ConsumerKind;
  /** Expected operator migration manifest (default: the full pinned chain). */
  readonly expectedMigrations?: readonly string[];
  readonly artifactDigest?: string;
}

/**
 * Full two-stage §7 admission against a MIGRATED fixture database — the
 * production contour, not a stand-in:
 *
 *  1. operator preflight: the REAL `foundation._prisma_migrations` history is
 *     verified on the same connection that holds the witness, BEFORE the
 *     witness and BEFORE any registry write (a wrong/extra/missing/incomplete
 *     history is refused with no record);
 *  2. real deterministic `historyManifestDigest` and `physicalContractDigest`
 *     are signed into the proof, and a real one-time row is issued into
 *     `launch_control.launch_proofs` (state ISSUED);
 *  3. the child's production `admitProcess` is answered by the production
 *     `decideLaunch` — live witness gate, single-winner ISSUED→CONSUMED CAS,
 *     DB-clock expiry check, exactly one approval, activation acknowledgement;
 *  4. the resolved `ProcessAuthorization` is the real child-side authorization.
 *
 * The holder is an application migration operator, not a control owner.
 * The separate lab control registry must already be provisioned by its owner;
 * this function uses only the launcher's narrow credential to issue.
 */
export async function issueVerifiedLaunch(
  holder: Pool | Client,
  runtime: DatabaseConfig,
  options: VerifiedAdmissionOptions = {},
): Promise<AdmissionHandle> {
  const { database } = runtime;
  if (!Object.is(runtime.host, loopback.host) || runtime.port !== loopback.port) { throw new Error('Invalid verified runtime endpoint'); }
  const control = verifiedControlConfig(database);
  const fromPool = holder instanceof Pool;
  const launcher: PoolClient = fromPool ? await holder.connect() : holder as unknown as PoolClient;
  const consumerKind = options.consumerKind ?? 'TEST';
  let handle: AdmissionHandle | undefined;
  try {
    // Attest the very application session that reads history and holds witness.
    const cluster = process.env['FIXLEVELUP_CLUSTER_NAME'] ?? '';
    if (!/^fixlevelup_p05s4_lab_[a-z0-9_]{1,40}$/.test(cluster)) { throw new Error('Invalid isolated application cluster'); }
    const { rows } = await launcher.query<{ valid: boolean }>(`SELECT
      current_database() = $1 AND current_user = 'fixlevelup_migrator'
      AND session_user = 'fixlevelup_migrator' AND current_setting('cluster_name') = $2
      AND current_setting('server_version_num') = '180007'
      AND pg_catalog.to_regnamespace('launch_control') IS NULL AS valid`, [database, cluster]);
    if (rows[0]?.valid !== true) { throw new Error('Unable to attest isolated application preflight'); }
    const history = await verifyOperatorMigrationHistory(launcher, options.expectedMigrations ?? authFixtureMigrations);
    if (!history.ok) { throw new Error('Operator preflight history verification failed'); }
    const identity = await pinLauncherIdentity(launcher, database);
    const state = await detectPhysicalState(launcher);
    const profile = options.profile ?? state.profile;
    const expected = {
      ...randomFacts(consumerKind, {
        historyManifestDigest: history.historyManifestDigest,
        physicalContractDigest: physicalContractDigestOf(profile),
      }),
      ...(options.artifactDigest === undefined ? {} : { artifactDigest: options.artifactDigest }),
    };
    if (!/^[a-f0-9]{64}$/.test(expected.artifactDigest)) { throw new Error('Invalid launch artifact digest'); }
    const binding: AdmissionBinding = {
      database,
      databaseOid: identity.oid,
      role: 'fixlevelup_runtime',
      schema: 'public',
      witnessKey: witnessKeyForInstance(expected.instanceId),
      profile,
      witnessHolderPid: identity.pid,
      expected,
    };
    // 2. Real launcher witness and the signed proof for exactly these facts.
    const expiresAt = new Date(Date.now() + 300_000);
    handle = await holdWitnessAndBuildHandle(launcher, binding, fromPool, expiresAt);
    const issuer = await openVerifiedControl(control);
    try {
      await issueProof(issuer, {
        issuerGeneration: expected.issuerGeneration,
        launchNonce: expected.launchNonce,
        proofDigest: handle.admission.proofDigest,
        consumerKind,
        instanceId: expected.instanceId,
        channelId: expected.channelId,
        expiresAt,
      });
    } finally { await issuer.end(); }
    return handle;
  } catch (error) {
    if (handle) { await handle.release().catch(() => undefined); }
    else if (fromPool) { launcher.release(); }
    throw error;
  }
}

export async function admitVerifiedTestInstance(
  holder: Pool | Client,
  database: string,
  options: VerifiedAdmissionOptions = {},
): Promise<AdmittedHandle> {
  const control = verifiedControlConfig(database);
  const runtime = runtimeDatabaseConfig(database);
  const password = fixturePassword('FIXLEVELUP_MIGRATOR_PASSWORD');
  if (!password) { throw new Error('Isolated migrator credentials are required'); }
  const operator = { ...loopback, database, user: 'fixlevelup_migrator', password };
  const handle = await issueVerifiedLaunch(holder, runtime, options);
  try {
    const expected = handle.admission.binding.expected;
    const authorization = await runVerifiedLauncherProtocol(handle, expected, expected.consumerKind, runtime, operator, control);
    return { ...handle, authorization };
  } catch (error) {
    await handle.release();
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
