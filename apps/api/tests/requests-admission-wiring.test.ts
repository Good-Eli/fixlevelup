/**
 * P05-01 slice (g): launch admission wiring of the runtime DB consumers.
 *
 * Unit part (always runs): loadRuntimeAdmission fail-closed semantics — the
 * full operator env yields a verified admission, every missing LAUNCH_* field,
 * a DatabaseConfig/env mismatch, a tampered token and a broken key file all
 * reject as ConfigurationError; the public-key file wins over the inline value.
 * createApi/createWorker refuse to construct DB consumers without admission.
 *
 * Real PostgreSQL part (opt-in like requests-admission.test.ts): a REAL
 * migrator-held launcher witness admits a GuardedPool — query works, the
 * Prisma-driven RuntimeDatabase.ready() is true through the guard (PrismaPg
 * compatibility proof), an already checked-out client keeps working after the
 * witness is released (verify-on-acquire semantics), and every new checkout
 * fails closed as AdmissionRequiredError wrapping the typed code.
 */
import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { createServer } from 'node:net';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { Pool } from 'pg';
import { AdmissionRequiredError, admittedPool } from '../src/infrastructure/admission/pool-guard.js';
import { loadRuntimeAdmission, witnessKeyForInstance } from '../src/infrastructure/admission/runtime-admission.js';
import { admitProcess, validateAuthorization, ProcessAdmissionError } from '../src/infrastructure/admission/process-admission.js';
import { physicalProfileVerifier } from '../src/infrastructure/admission/physical-profile.js';
import { createApi, createWorker } from '../src/bootstrap/factories.js';
import { ConfigurationError, loadConfig } from '../src/runtime/config.js';
import { RuntimeDatabase } from '../src/infrastructure/database/runtime-database.js';
import type { DatabaseConfig } from '../src/infrastructure/database/runtime-database.js';
import { SafeLogger } from '../src/runtime/safe-logger.js';
import { admitFixture, holdFixtureWitness, openVerifiedControl, syntheticAdmission, verifiedControlConfig } from './admission-fixture.js';
import { testLaunchChannel, withTestLaunchChannel } from './admission-transport-fixture.js';
import type { LauncherChannel } from '../src/infrastructure/admission/private-launch-channel.js';
import type { AdmittedHandle } from './admission-fixture.js';
import { createConfigurationFixture } from './configuration-fixture.js';
import type { ConfigurationFixture } from './configuration-fixture.js';

const proof = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1' ? it : it.skip;
// The three launcher-side proofs below issue a proof into the separate control
// database and therefore need the provisioned P05 lab contour (same gate as
// runtime-database.test.ts). Without it they must SKIP, not fail: the control
// credentials are validated before any history is read, so an unlabelled run
// would report a configuration error instead of the proof's own subject.
const labEnabled = process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1';
const labProof = labEnabled ? proof : it.skip;
const root = resolve(import.meta.dirname, '../../..');

function runtimePassword(): string {
  return wiringPassword('FIXLEVELUP_RUNTIME_PASSWORD');
}

function databaseConfig(database: string): DatabaseConfig {
  return { host: '127.0.0.1', port: 55432, database, user: 'fixlevelup_runtime', password: runtimePassword() };
}

function configurationErrorFields(action: () => unknown): readonly string[] {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(ConfigurationError);
    return (error as ConfigurationError).fields;
  }
  throw new Error('Expected ConfigurationError');
}

const launchFields = [
  'LAUNCH_PROOF_TOKEN', 'LAUNCHER_PUBLIC_KEY_PEM', 'LAUNCHER_WITNESS_PID', 'LAUNCH_DATABASE',
  'LAUNCH_DATABASE_OID', 'LAUNCH_ROLE', 'LAUNCH_SCHEMA', 'LAUNCH_PROFILE', 'LAUNCH_ENDPOINT',
  'LAUNCH_ISSUER_GENERATION', 'LAUNCH_NONCE', 'LAUNCH_CONSUMER_KIND', 'LAUNCH_INSTANCE_ID',
  'LAUNCH_CHANNEL_ID', 'LAUNCH_ARTIFACT_DIGEST', 'LAUNCH_HISTORY_MANIFEST_DIGEST', 'LAUNCH_PHYSICAL_CONTRACT_DIGEST',
] as const;

// --- Unit part: the operator-contour loader and the factory guards (no DB). ---

it('loadRuntimeAdmission: full operator env verifies the token and pins the binding', () => {
  const synthetic = syntheticAdmission('API');
  const loaded = loadRuntimeAdmission(synthetic.env, { database: databaseConfig('fixlevelup_dev') });
  const token = synthetic.env['LAUNCH_PROOF_TOKEN'] ?? '';
  const payload = loaded.gate.verifyProofToken(token, new Date());
  expect(payload.consumerKind).toBe('API');
  expect(payload.targetIdentity.database).toBe('fixlevelup_dev');
  expect(loaded.binding.witnessKey.classId).toBe(557001);
  // Per-instance witness key (§7): derived from the pinned instanceId.
  expect(loaded.binding.witnessKey.objectId)
    .toBe(witnessKeyForInstance(String(synthetic.env['LAUNCH_INSTANCE_ID'])).objectId);
});

it('loadRuntimeAdmission: every missing LAUNCH_* field fails closed', () => {
  const synthetic = syntheticAdmission('WORKER');
  const database = databaseConfig('fixlevelup_dev');
  for (const field of launchFields) {
    const partial: NodeJS.ProcessEnv = {};
    for (const [key, value] of Object.entries(synthetic.env)) {
      if (key !== field) { partial[key] = value; }
    }
    const fields = configurationErrorFields(() => loadRuntimeAdmission(partial, { database }));
    expect(fields, field).toContain(field);
  }
});

it('loadRuntimeAdmission: env/config mismatch, tampered token and broken key fail closed', () => {
  const synthetic = syntheticAdmission('API');
  const database = databaseConfig('fixlevelup_dev');
  const mismatched = configurationErrorFields(() =>
    loadRuntimeAdmission(synthetic.env, { database: { ...database, database: 'fixlevelup_other' } }));
  expect(mismatched).toContain('LAUNCH_DATABASE');
  const tampered = configurationErrorFields(() =>
    loadRuntimeAdmission({ ...synthetic.env, LAUNCH_PROOF_TOKEN: `${(synthetic.env['LAUNCH_PROOF_TOKEN'] ?? '').slice(0, -4)}dead` }, { database }));
  expect(tampered).toEqual(['LAUNCH_PROOF_TOKEN']);
  const broken = configurationErrorFields(() =>
    loadRuntimeAdmission({ ...synthetic.env, LAUNCHER_PUBLIC_KEY_PEM: 'not-a-pem' }, { database }));
  expect(broken).toContain('LAUNCHER_PUBLIC_KEY_PEM');

  const keyFile = resolve(tmpdir(), `fixlevelup-launcher-${String(Date.now())}-${Math.random().toString(16).slice(2)}.pem`);
  writeFileSync(keyFile, synthetic.publicKeyPem, 'utf8');
  try {
    // The file wins over the inline value (even an inline one that is invalid).
    const fromFile = loadRuntimeAdmission(
      { ...synthetic.env, LAUNCHER_PUBLIC_KEY_PEM: 'not-a-pem', LAUNCHER_PUBLIC_KEY_FILE: keyFile }, { database });
    expect(() => fromFile.gate.verifyProofToken(synthetic.env['LAUNCH_PROOF_TOKEN'] ?? '', new Date())).not.toThrow();
    const missingFile = configurationErrorFields(() =>
      loadRuntimeAdmission({ ...synthetic.env, LAUNCHER_PUBLIC_KEY_FILE: `${keyFile}.missing` }, { database }));
    expect(missingFile).toContain('LAUNCHER_PUBLIC_KEY_FILE');
  } finally {
    rmSync(keyFile, { force: true });
  }
});

it('createApi and createWorker refuse database consumers without admission', async () => {
  const config = loadConfig({ NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0' });
  const database = databaseConfig('fixlevelup_dev');
  await expect(createApi(config, new SafeLogger('api'), database)).rejects.toMatchObject({
    name: 'ConfigurationError', fields: ['LAUNCH_PROOF_TOKEN'],
  });
  await expect(createWorker(new SafeLogger('worker'), database)).rejects.toMatchObject({
    name: 'ConfigurationError', fields: ['LAUNCH_PROOF_TOKEN'],
  });
});

// --- Real PostgreSQL part: GuardedPool semantics and Prisma compatibility. ---

let fixture: ConfigurationFixture | undefined;
let handle: AdmittedHandle | undefined;

beforeAll(async () => {
  if (process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] !== '1') { return; }
  fixture = await createConfigurationFixture();
}, 240_000);

afterAll(async () => {
  const admitted = handle;
  handle = undefined;
  if (admitted) { await admitted.release(); }
  if (fixture) { await fixture.close(); }
}, 120_000);

proof('wiring: guarded pool admits with the witness, serves Prisma readiness, fails closed after release', { timeout: 120_000 }, async () => {
  const current = requireFixture();
  await current.migrator.query('CREATE TABLE IF NOT EXISTS foundation._prisma_migrations (id text PRIMARY KEY)');
  handle = await admitFixture(current.migrator, current.database, 'TEST');
  const target = databaseConfig(current.database);
  const pool = admittedPool({ authorization: handle.authorization, kind: 'TEST' }, target, { max: 2 });
  // Proxy over a real pg.Pool: Prisma's instanceof check keeps holding.
  expect(pool instanceof Pool).toBe(true);
  const single = await pool.query<{ ok: number }>('SELECT 1 AS ok');
  expect(single.rows[0]?.ok).toBe(1);
  await expect(pool.whenAdmitted()).resolves.toBeUndefined();
  const kept = await pool.connect();
  try {
    // Prisma compatibility: the whole RuntimeDatabase probe runs through the guard.
    const database = new RuntimeDatabase(target, true, handle.authorization, 'TEST');
    try {
      expect(await database.ready()).toBe(true);
    } finally {
      await database.onModuleDestroy();
    }
    // Witness gone: an already checked-out client keeps working (verify-on-acquire).
    await handle.release();
    handle = undefined;
    const still = await kept.query<{ ok: number }>('SELECT 2 AS ok');
    expect(still.rows[0]?.ok).toBe(2);
  } finally {
    kept.release();
  }
  // New checkouts fail closed as the typed AdmissionRequiredError, no driver details.
  const denied = await pool.connect().then(() => 'connected', (error: unknown) =>
    error instanceof AdmissionRequiredError ? `${error.code}/${error.reason ?? 'none'}` : 'other');
  expect(denied).toBe('ADMISSION_REQUIRED/WITNESS_MISSING');
  const deniedQuery = await pool.query('SELECT 1').then(() => 'resolved', (error: unknown) =>
    error instanceof AdmissionRequiredError ? `${error.code}/${error.reason ?? 'none'}` : 'other');
  // D4 permanently revokes this admission after the first proved witness loss.
  expect(deniedQuery).toBe('ADMISSION_REQUIRED/none');
  await pool.end();
});

labProof('process handshake (simulated IPC, real DB): witness-gated one-time CAS, single approval, replay/dead-witness refusals; physical profile gates admission', { timeout: 180_000 }, async () => {
  const current = requireFixture();
  await current.migrator.query('CREATE TABLE IF NOT EXISTS foundation._prisma_migrations (id text PRIMARY KEY)');
  // Resolve the control contour BEFORE taking a witness: a bad control
  // configuration must not leak a held witness into the rest of the file.
  const control = verifiedControlConfig(current.database);
  const admitted = await admitFixture(current.migrator, current.database, 'WORKER');
  const owner = await openVerifiedControl(control).catch(async (error: unknown) => {
    await admitted.release();
    throw error;
  });
  try {
    const loaded = loadRuntimeAdmission(admitted.env, { database: databaseConfig(current.database), requiredConsumer: 'WORKER' });
    // An API-only entrypoint must refuse a WORKER proof (consumer-kind binding).
    expect(() => loadRuntimeAdmission(admitted.env, { database: databaseConfig(current.database), requiredConsumer: 'API' }))
      .toThrow(ConfigurationError);
    const { issueProof, readRegistryState } = await import('../src/infrastructure/admission/registry.js');
    const { decideLaunch } = await import('../src/infrastructure/admission/launcher.js');
    const { witnessKeyForInstance } = await import('../src/infrastructure/admission/runtime-admission.js');
    const instanceId = String(admitted.env['LAUNCH_INSTANCE_ID']);
    const channelId = String(admitted.env['LAUNCH_CHANNEL_ID']);
    const generation = Number(admitted.env['LAUNCH_ISSUER_GENERATION']);
    const nonce = String(admitted.env['LAUNCH_NONCE']);
    const proofDigest = loaded.proofDigest;
    await issueProof(owner, { issuerGeneration: generation, launchNonce: nonce, proofDigest,
      consumerKind: 'WORKER', instanceId, channelId, expiresAt: new Date(Date.now() + 120_000) });
    const launcherDeps = { app: { host: '127.0.0.1', port: 55432, database: current.database,
      user: 'fixlevelup_migrator', password: migratorPassword() }, control,
      witnessKeyOf: witnessKeyForInstance, ackTimeoutMs: 3_000 };
    // In-memory private IPC pair: BOTH directions flow through one listener
    // set (handshake/ack child→launcher, approve/reject launcher→child), the
    // child's handshake is captured for the launcher's decision, and the
    // child's activation ack is captured for the launcher's bounded wait.
    const approvals: string[] = [];
    const rejects: string[] = [];
    interface ChannelPair {
      readonly child: LauncherChannel;
      readonly handshake: Promise<Record<string, unknown>>;
      readonly ack: Promise<unknown>;
      readonly receipt: Promise<unknown>;
      deliver(message: unknown): void;
    }
    const childChannel = (): ChannelPair => {
      let resolveHandshake: (message: Record<string, unknown>) => void = () => undefined;
      let resolveAck: (message: unknown) => void = () => undefined;
      let resolveReceipt: (message: unknown) => void = () => undefined;
      const handshake = new Promise<Record<string, unknown>>((resolve) => { resolveHandshake = resolve; });
      const ack = new Promise<unknown>((resolve) => { resolveAck = resolve; });
      const receipt = new Promise<unknown>((resolve) => { resolveReceipt = resolve; });
      const wire = testLaunchChannel((message) => {
        if (!('type' in message)) { return; }
        if (message.type === 'p05/launch/handshake') { resolveHandshake(message); }
        if (message.type === 'p05/launch/active') { resolveAck(message); }
        if (message.type === 'p05/launch/activated') { resolveReceipt(message); }
      });
      return { child: wire.channel, handshake, ack, receipt, deliver: (message) => { wire.deliver(message); } };
    };
    const runAdmission = (pair: ChannelPair): Promise<string> => withTestLaunchChannel(pair.child,
      () => admitProcess(loaded, { database: databaseConfig(current.database), approvalTimeoutMs: 5_000 }))
      .then(() => 'admitted', (error: unknown) => error instanceof ProcessAdmissionError ? error.kind : 'other');
    const runChild = async (pair: ChannelPair) => {
      const outcome = runAdmission(pair);
      await Promise.race([pair.handshake, outcome.then((state) => { throw new Error(`Child refused before handshake: ${state}`); })]);
      return { outcome };
    };
    // The launcher's OWN trusted expectations for the issued proof (never
    // derived from the child's self-reported handshake).
    const expected = { instanceId, launchNonce: nonce, consumerKind: 'WORKER' as const, proofDigest,
      issuerGeneration: generation, witnessHolderPid: loaded.binding.witnessHolderPid, channelId,
      database: loaded.binding.database, databaseOid: loaded.binding.databaseOid,
      role: loaded.binding.role, profile: loaded.binding.profile };
    const launch = async (pair: ChannelPair, override?: Record<string, unknown>) => {
      const decision = await decideLaunch(launcherDeps, expected, override ?? await pair.handshake, process.pid, {
        live: () => true,
        send: (message) => {
          if (message.type === 'p05/launch/approve') { approvals.push(message.instanceId); }
          pair.deliver(message);
          return Promise.resolve(true);
        },
        ack: pair.ack,
        receipt: pair.receipt,
      });
      if (!decision.approved) {
        rejects.push(expected.instanceId);
        pair.deliver({ ...expected, pid: process.pid, type: 'p05/launch/reject' });
      }
      return decision;
    };

    // 1. A drifted physical profile refuses BEFORE any handshake/consumption.
    await current.migrator.query('ALTER TABLE foundation.requests DISABLE TRIGGER requests_guard');
    try { expect(await runAdmission(childChannel())).toBe('ADMISSION_DENIED'); }
    finally { await current.migrator.query('ALTER TABLE foundation.requests ENABLE TRIGGER requests_guard'); }
    expect((await readRegistryState(owner, generation, nonce))?.state).toBe('ISSUED');

    // 2. The winner: correct profile, launcher decides, single approval, acked.
    const winnerPair = childChannel();
    const winner = await runChild(winnerPair);
    const decision = await launch(winnerPair);
    expect(decision.approved).toBe(true);
    expect((decision as { acked?: boolean }).acked).toBe(true);
    expect(await winner.outcome).toBe('admitted');
    expect(approvals).toEqual([instanceId]);
    expect((await readRegistryState(owner, generation, nonce))?.state).toBe('CONSUMED');

    // 2b. Binding mismatch: a handshake with a DIFFERENT instance/nonce is
    // rejected by the trusted-binding gate with no DB touch at all.
    const forgedPair = childChannel();
    const forged = await runChild(forgedPair);
    const forgedHandshake = { ...await forgedPair.handshake, instanceId: randomUUID() } as Record<string, unknown>;
    const forgedDecision = await launch(forgedPair, forgedHandshake);
    expect(forgedDecision.approved).toBe(false);
    expect((forgedDecision as { reason: string }).reason).toBe('BINDING');
    expect(await forged.outcome).toBe('ADMISSION_DENIED');
    expect(approvals).toEqual([instanceId]);

    // 3. Replay of the same proof: the launcher's CAS loses; no approval.
    const replayPair = childChannel();
    const replay = await runChild(replayPair);
    const replayDecision = await launch(replayPair);
    expect(replayDecision.approved).toBe(false);
    expect(await replay.outcome).toBe('ADMISSION_DENIED');
    expect(approvals).toEqual([instanceId]);

    // 4. Dead witness: a freshly issued second proof — the child itself
    //    refuses at its FIRST live check (witness gone) and never reaches the
    //    handshake; race the outcome against the (never-arriving) handshake.
    const secondNonce = randomUUID();
    await issueProof(owner, { issuerGeneration: generation, launchNonce: secondNonce, proofDigest,
      consumerKind: 'WORKER', instanceId, channelId, expiresAt: new Date(Date.now() + 120_000) });
    await admitted.release();
    const deadPair = childChannel();
    const deadOutcome = runAdmission(deadPair);
    const deadHandshake = await Promise.race([deadPair.handshake, deadOutcome.then((outcome) => outcome)]);
    // The child refused at live verification — the outcome IS the verdict.
    expect(deadHandshake).toBe('ADMISSION_DENIED');
    // The launcher never saw a handshake: the row stays ISSUED, no approvals.
    expect((await readRegistryState(owner, generation, secondNonce))?.state).toBe('ISSUED');
    expect(approvals).toEqual([instanceId]);
    // Rejections were sent only by the launcher (the replay loser + the
    // forged-binding attempt); the dead-witness child never reached it.
    expect(rejects.length).toBe(2);
  } finally {
    await owner.end().catch(() => undefined);
    await admitted.release().catch(() => undefined);
  }
});

proof('authorization identity binding: a marker paired with a DIFFERENT admission authorizes nothing (r7 MUST 1)', { timeout: 60_000 }, async () => {
  const current = requireFixture();
  const first = await admitFixture(current.migrator, current.database, 'TEST');
  const second = await admitFixture(current.migrator, current.database, 'TEST');
  try {
    const a1 = first.authorization;
    const a2 = second.authorization;
    // Even a byte-for-byte structural copy cannot start a handshake: only the
    // immutable object returned by signature verification is eligible.
    let sent = false;
    const channel = testLaunchChannel(() => { sent = true; }).channel;
    await expect(withTestLaunchChannel(channel, () => admitProcess({ ...first.admission }, {
      database: databaseConfig(current.database), approvalTimeoutMs: 100,
    }))).rejects.toMatchObject({ kind: 'ADMISSION_DENIED' });
    expect(sent).toBe(false);
    // The genuine pairing validates.
    expect(() => validateAuthorization(a1)).not.toThrow();
    expect(() => validateAuthorization(a2)).not.toThrow();
    // A marker reused with a DIFFERENT admission (the r7 mix-in attack) is
    // rejected by the boundary — even though both admissions are genuine.
    const mixed = { admission: second.admission, completed: a1.completed };
    expect(() => validateAuthorization(mixed)).toThrow(/not bound to this admission/);
    // A structurally-shaped marker constructed outside the module (compiled
    // JS caller) is rejected: it was never issued for anything.
    const forged = { admission: first.admission, completed: { __p05ProcessAdmissionCompleted: Symbol() } as never };
    expect(() => validateAuthorization(forged)).toThrow(/not bound to this admission/);
    // And the module boundary this exercises is exactly what the factories
    // call (requireAdmission → validateAuthorization).
    await expect(createApi(loadConfig({ NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0' }), new SafeLogger('api'),
      databaseConfig(current.database), undefined, undefined, mixed)).rejects.toThrow(/not bound to this admission/);
  } finally {
    await first.release();
    await second.release();
  }
});

proof('physical profile: the production classifier is exact and positive on a real 023 database (r7 MUST 3)', { timeout: 180_000 }, async () => {
  const current = requireFixture();
  // The fixture chain IS 023 (S2): the real classifier must admit an S2 proof
  // and refuse BOTH earlier profiles against the same physical database.
  const s2 = await admitFixture(current.migrator, current.database, 'TEST');
  expect(s2.admission.binding.profile).toBe('S2');
  // Separately SIGNED S1/S0 proofs (same witness machinery) for the same
  // database — used to prove neither earlier profile admits an S2 database.
  const s1handle = await holdFixtureWitness(current.migrator, current.database, 'TEST', 'public', 'S1');
  const s0handle = await holdFixtureWitness(current.migrator, current.database, 'TEST', 'public', 'S0');
  try {
    const verifier = physicalProfileVerifier(databaseConfig(current.database));
    expect(await verifier(s2.admission)).toBe(true);
    const s1 = loadRuntimeAdmission(s1handle.env, { database: databaseConfig(current.database) });
    expect(s1.binding.profile).toBe('S1');
    expect(await verifier(s1)).toBe(false);
    const s0 = loadRuntimeAdmission(s0handle.env, { database: databaseConfig(current.database) });
    expect(s0.binding.profile).toBe('S0');
    expect(await verifier(s0)).toBe(false);
    // A damaged 022 is NEITHER profile: disable one 022 guard trigger; the S2
    // fingerprint is false (it embeds the 022 fingerprint) AND the positive
    // absence probes are also false (tables still exist), so S2, S1 and S0 are
    // all refused — a later profile never downgrades to an earlier one.
    await current.migrator.query('ALTER TABLE foundation.requests DISABLE TRIGGER requests_guard');
    try {
      expect(await verifier(s2.admission)).toBe(false);
      expect(await verifier(s1)).toBe(false);
      expect(await verifier(s0)).toBe(false);
    } finally {
      await current.migrator.query('ALTER TABLE foundation.requests ENABLE TRIGGER requests_guard');
    }
    // A damaged 023 is NEITHER profile either: disabling one 023 guard trigger
    // breaks the S2 fingerprint while the 023 tables still exist, so S1's
    // positive 023-absence probe stays false — a damaged S2 NEVER rolls back
    // to S1. S0 stays refused for the same reason.
    await current.migrator.query('ALTER TABLE foundation.form_browser_groups DISABLE TRIGGER form_browser_groups_guard');
    try {
      expect(await verifier(s2.admission)).toBe(false);
      expect(await verifier(s1)).toBe(false);
      expect(await verifier(s0)).toBe(false);
    } finally {
      await current.migrator.query('ALTER TABLE foundation.form_browser_groups ENABLE TRIGGER form_browser_groups_guard');
    }
    // Restored: S2 is exact again; S1 and S0 stay refused because the 023
    // tables exist. Exactness in both directions.
    expect(await verifier(s2.admission)).toBe(true);
    expect(await verifier(s1)).toBe(false);
    expect(await verifier(s0)).toBe(false);
  } finally {
    await s2.release();
    await s1handle.release();
    await s0handle.release();
  }
});

labProof('launcher ack deadline: simulated delivery loss after real CAS denies activation', { timeout: 120_000 }, async () => {
  const current = requireFixture();
  await current.migrator.query('CREATE TABLE IF NOT EXISTS foundation._prisma_migrations (id text PRIMARY KEY)');
  // Control contour first: see the process-handshake proof above.
  const control = verifiedControlConfig(current.database);
  const admitted = await admitFixture(current.migrator, current.database, 'WORKER');
  const owner = await openVerifiedControl(control).catch(async (error: unknown) => {
    await admitted.release();
    throw error;
  });
  try {
    const loaded = loadRuntimeAdmission(admitted.env, { database: databaseConfig(current.database), requiredConsumer: 'WORKER' });
    const { issueProof, readRegistryState } = await import('../src/infrastructure/admission/registry.js');
    const { decideLaunch } = await import('../src/infrastructure/admission/launcher.js');
    const instanceId = String(admitted.env['LAUNCH_INSTANCE_ID']);
    const channelId = String(admitted.env['LAUNCH_CHANNEL_ID']);
    const generation = Number(admitted.env['LAUNCH_ISSUER_GENERATION']);
    const nonce = String(admitted.env['LAUNCH_NONCE']);
    const proofDigest = loaded.proofDigest;
    await issueProof(owner, { issuerGeneration: generation, launchNonce: nonce, proofDigest,
      consumerKind: 'WORKER', instanceId, channelId, expiresAt: new Date(Date.now() + 120_000) });
    const launcherDeps = { app: { host: '127.0.0.1', port: 55432, database: current.database,
      user: 'fixlevelup_migrator', password: migratorPassword() },
      control,
      witnessKeyOf: witnessKeyForInstance, ackTimeoutMs: 500 };
    // In-memory child that hands over a VALID handshake but never acks.
    let resolveHandshake: (message: object) => void = () => undefined;
    const pendingHandshake = new Promise<object>((resolve) => { resolveHandshake = resolve; });
    const wire = testLaunchChannel((message) => {
      if ('type' in message && message.type === 'p05/launch/handshake') { resolveHandshake(message); }
    });
    const outcome = withTestLaunchChannel(wire.channel, () => admitProcess(loaded, {
      database: databaseConfig(current.database), approvalTimeoutMs: 5_000,
    })).then(() => 'admitted', (error: unknown) => error instanceof ProcessAdmissionError ? error.kind : 'other');
    const handshake = await Promise.race([pendingHandshake,
      outcome.then((o) => { throw new Error(`child ended before handshake: ${o}`); })]);
    let approvals = 0;
    const decision = await decideLaunch(launcherDeps,
      { instanceId, launchNonce: nonce, consumerKind: 'WORKER', proofDigest,
        issuerGeneration: generation, witnessHolderPid: loaded.binding.witnessHolderPid, channelId,
        database: loaded.binding.database, databaseOid: loaded.binding.databaseOid,
        role: loaded.binding.role, profile: loaded.binding.profile },
      handshake, process.pid, {
        live: () => true,
        send: (message) => { approvals += 1; wire.deliver(message); return Promise.resolve(true); },
        ack: new Promise<never>(() => undefined), // Drop the ACK; never deliver activate.
        receipt: new Promise<never>(() => undefined),
      });
    expect(approvals).toBe(1);
    expect(decision).toEqual({ approved: false, reason: 'NO_ACK' });
    expect((await readRegistryState(owner, generation, nonce))?.state).toBe('CONSUMED');
    expect(await outcome).toBe('ADMISSION_DENIED');
  } finally {
    await owner.end().catch(() => undefined);
    await admitted.release().catch(() => undefined);
  }
});

labProof('launcher DB deadlines: a control endpoint that accepts and never answers refuses quickly (r8 MUST 2)', { timeout: 60_000 }, async () => {
  const current = requireFixture();
  // Control contour first: see the process-handshake proof above.
  const control = verifiedControlConfig(current.database);
  const admitted = await admitFixture(current.migrator, current.database, 'WORKER');
  try {
    const loaded = loadRuntimeAdmission(admitted.env, { database: databaseConfig(current.database), requiredConsumer: 'WORKER' });
    const { issueProof } = await import('../src/infrastructure/admission/registry.js');
    const { decideLaunch } = await import('../src/infrastructure/admission/launcher.js');
    const owner = await openVerifiedControl(control);
    try {
        const instanceId = String(admitted.env['LAUNCH_INSTANCE_ID']);
      const channelId = String(admitted.env['LAUNCH_CHANNEL_ID']);
      const generation = Number(admitted.env['LAUNCH_ISSUER_GENERATION']);
      const nonce = String(admitted.env['LAUNCH_NONCE']);
      await issueProof(owner, { issuerGeneration: generation, launchNonce: nonce, proofDigest: loaded.proofDigest,
        consumerKind: 'WORKER', instanceId, channelId, expiresAt: new Date(Date.now() + 120_000) });
      // A control endpoint that accepts TCP and never answers: the launcher's
      // client-side query_timeout (not the server's) bounds the wait.
      const blackHole = createServer((socket) => { socket.resume(); });
      await new Promise<void>((resolve) => { blackHole.listen(0, '127.0.0.1', () => { resolve(); }); });
      const port = (blackHole.address() as { port: number }).port;
      try {
        const deps = { app: { host: '127.0.0.1', port: 55432, database: current.database,
          user: 'fixlevelup_migrator', password: migratorPassword() },
          control: { ...control, port },
          witnessKeyOf: witnessKeyForInstance, ackTimeoutMs: 500 };
        const expected = { database: loaded.binding.database,
          databaseOid: loaded.binding.databaseOid, role: loaded.binding.role,
          witnessHolderPid: loaded.binding.witnessHolderPid, consumerKind: 'WORKER' as const,
          instanceId, channelId, issuerGeneration: generation, launchNonce: nonce,
          proofDigest: loaded.proofDigest, profile: loaded.binding.profile };
        const handshake = { ...expected, type: 'p05/launch/handshake', pid: process.pid };
        const started = Date.now();
        const decision = await decideLaunch(deps, expected, handshake, process.pid, {
          live: () => true, send: () => Promise.resolve(false), ack: new Promise<never>(() => undefined),
          receipt: new Promise<never>(() => undefined),
        });
        // The stalled control read is bounded: CAS refused, quickly.
        expect(decision.approved).toBe(false);
        expect((decision as { reason: string }).reason).toBe('CAS');
        expect(Date.now() - started).toBeLessThan(20_000);
      } finally {
        blackHole.close();
      }
    } finally { await owner.end(); }
  } finally {
    await admitted.release();
  }
});

function migratorPassword(): string {
  return wiringPassword('FIXLEVELUP_MIGRATOR_PASSWORD');
}

function wiringPassword(key: 'FIXLEVELUP_RUNTIME_PASSWORD' | 'FIXLEVELUP_MIGRATOR_PASSWORD'): string {
  const password = process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1'
    ? process.env[key]
    : new RegExp(`^${key}=([a-f0-9]{64})$`, 'm').exec(readFileSync(resolve(root, 'packages/database-tooling/.env'), 'utf8'))?.[1];
  if (!password || !/^[a-f0-9]{64}$/.test(password)) { throw new Error('Isolated PostgreSQL test credentials are required'); }
  return password;
}

function requireFixture(): ConfigurationFixture {
  if (!fixture) { throw new Error('Isolated fixture is not initialized'); }
  return fixture;
}
