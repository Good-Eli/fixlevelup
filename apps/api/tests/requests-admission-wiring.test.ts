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
import type { LauncherChannel } from '../src/infrastructure/admission/process-admission.js';
import { physicalProfileVerifier } from '../src/infrastructure/admission/physical-profile.js';
import { createApi, createWorker } from '../src/bootstrap/factories.js';
import { ConfigurationError, loadConfig } from '../src/runtime/config.js';
import { RuntimeDatabase } from '../src/infrastructure/database/runtime-database.js';
import type { DatabaseConfig } from '../src/infrastructure/database/runtime-database.js';
import { SafeLogger } from '../src/runtime/safe-logger.js';
import { admitFixture, syntheticAdmission } from './admission-fixture.js';
import type { AdmissionHandle } from './admission-fixture.js';
import { createConfigurationFixture } from './configuration-fixture.js';
import type { ConfigurationFixture } from './configuration-fixture.js';

const proof = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1' ? it : it.skip;
const root = resolve(import.meta.dirname, '../../..');
const connection = { host: '127.0.0.1' as const, port: 55432 };

function runtimePassword(): string {
  const toolingEnv = readFileSync(resolve(root, 'packages/database-tooling/.env'), 'utf8');
  const password = /^FIXLEVELUP_RUNTIME_PASSWORD=([a-f0-9]{64})$/m.exec(toolingEnv)?.[1];
  if (!password) { throw new Error('Local isolated PostgreSQL test credentials are required'); }
  return password;
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
let handle: AdmissionHandle | undefined;

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
  // The operator env contour → loader → gate is the exact production chain.
  const loaded = loadRuntimeAdmission(handle.env, { database: databaseConfig(current.database) });
  const pool = admittedPool({ gate: loaded.gate }, { ...connection, database: current.database,
    user: 'fixlevelup_runtime', password: runtimePassword(), max: 2 });
  // Proxy over a real pg.Pool: Prisma's instanceof check keeps holding.
  expect(pool instanceof Pool).toBe(true);
  const single = await pool.query<{ ok: number }>('SELECT 1 AS ok');
  expect(single.rows[0]?.ok).toBe(1);
  await expect(pool.whenAdmitted()).resolves.toBeUndefined();
  const kept = await pool.connect();
  try {
    // Prisma compatibility: the whole RuntimeDatabase probe runs through the guard.
    const database = new RuntimeDatabase(databaseConfig(current.database), true, handle.admission);
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
  expect(deniedQuery).toBe('ADMISSION_REQUIRED/WITNESS_MISSING');
  await pool.end();
});

proof('process handshake (launcher protocol): witness-gated one-time CAS, single approval, replay/dead-witness refusals; physical profile gates admission', { timeout: 180_000 }, async () => {
  const current = requireFixture();
  await current.migrator.query('CREATE TABLE IF NOT EXISTS foundation._prisma_migrations (id text PRIMARY KEY)');
  const admitted = await admitFixture(current.migrator, current.database, 'WORKER');
  const { Client } = await import('pg');
  const owner = new Client({ ...connection, database: current.database, user: 'fixlevelup_migrator',
    password: migratorPassword() });
  await owner.connect();
  try {
    const loaded = loadRuntimeAdmission(admitted.env, { database: databaseConfig(current.database), requiredConsumer: 'WORKER' });
    // An API-only entrypoint must refuse a WORKER proof (consumer-kind binding).
    expect(() => loadRuntimeAdmission(admitted.env, { database: databaseConfig(current.database), requiredConsumer: 'API' }))
      .toThrow(ConfigurationError);
    const { ensureLaunchRegistry, issueProof, readRegistryState } = await import('../src/infrastructure/admission/registry.js');
    const { decideLaunch } = await import('../src/infrastructure/admission/launcher.js');
    const { witnessKeyForInstance } = await import('../src/infrastructure/admission/runtime-admission.js');
    await ensureLaunchRegistry(owner);
    const instanceId = String(admitted.env['LAUNCH_INSTANCE_ID']);
    const channelId = String(admitted.env['LAUNCH_CHANNEL_ID']);
    const generation = Number(admitted.env['LAUNCH_ISSUER_GENERATION']);
    const nonce = String(admitted.env['LAUNCH_NONCE']);
    const proofDigest = loaded.proofDigest;
    await issueProof(owner, { issuerGeneration: generation, launchNonce: nonce, proofDigest,
      consumerKind: 'WORKER', instanceId, channelId, expiresAt: new Date(Date.now() + 120_000) });
    const control = { host: '127.0.0.1', port: 55432, database: current.database,
      user: 'fixlevelup_migrator', password: migratorPassword() };
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
      readonly ack: Promise<boolean>;
      deliver(message: unknown): void;
    }
    const childChannel = (): ChannelPair => {
      const listeners: Array<(message: unknown) => void> = [];
      let resolveHandshake: (message: Record<string, unknown>) => void = () => undefined;
      let resolveAck: (acked: boolean) => void = () => undefined;
      const handshake = new Promise<Record<string, unknown>>((resolve) => { resolveHandshake = resolve; });
      const ack = new Promise<boolean>((resolve) => { resolveAck = resolve; });
      const pair: ChannelPair = {
        child: {
          send: (message: unknown) => {
            // Child→launcher messages flow to the launcher via the same
            // listeners; handshake and activation ack are also captured.
            for (const l of listeners) { l(message); }
            if (message !== null && typeof message === 'object') {
              const type = (message as Record<string, unknown>)['type'];
              if (type === 'p05/launch/handshake') { resolveHandshake(message as Record<string, unknown>); }
              if (type === 'p05/launch/active') { resolveAck(true); }
            }
            return true;
          },
          on: (_: 'message', listener: (message: unknown) => void) => { listeners.push(listener); return pair.child; },
        },
        handshake,
        ack,
        deliver: (message: unknown) => { for (const l of listeners) { l(message); } },
      };
      return pair;
    };
    let active: ChannelPair | undefined;
    const sendApprove = (iid: string, launchNonce: string): void => {
      approvals.push(iid);
      active?.deliver({ type: 'p05/launch/approve', instanceId: iid, launchNonce });
    };
    const sendReject = (iid: string): void => {
      rejects.push(iid);
      active?.deliver({ type: 'p05/launch/reject', instanceId: iid });
    };
    const falseProfile = (): Promise<boolean> => Promise.resolve(false);
    const trueProfile = (): Promise<boolean> => Promise.resolve(true);
    const depsFor = (channel: LauncherChannel, profileOk = true) => ({ database: databaseConfig(current.database),
      channel, verifyProfile: profileOk ? trueProfile : falseProfile, approvalTimeoutMs: 2_000 });
    const runChild = async (pair: ChannelPair, profileOk = true): Promise<{ outcome: Promise<string>; handshake: Record<string, unknown> }> => {
      active = pair;
      const outcome = admitProcess(loaded, depsFor(pair.child, profileOk)).then(() => 'admitted',
        (error: unknown) => error instanceof ProcessAdmissionError ? error.kind : 'other');
      return { outcome, handshake: await pair.handshake };
    };

    // The launcher's OWN trusted expectations for the issued proof (never
    // derived from the child's self-reported handshake).
    const expected = { instanceId, launchNonce: nonce, consumerKind: 'WORKER' as const, proofDigest,
      issuerGeneration: generation, witnessHolderPid: loaded.binding.witnessHolderPid, channelId };
    // Feed a pair's handshake to the launcher's decideLaunch and await the
    // decision (its bounded ack wait uses the pair's own ack promise).
    const launch = (pair: ChannelPair): Promise<Awaited<ReturnType<typeof decideLaunch>>> =>
      pair.handshake.then((handshake) => decideLaunch(launcherDeps, expected,
        handshake as unknown as Parameters<typeof decideLaunch>[2], sendApprove, sendReject, () => pair.ack));

    // 1. A drifted physical profile refuses BEFORE any handshake/consumption.
    const drifted = await admitProcess(loaded, depsFor(childChannel().child, false)).then(() => 'admitted',
      (error: unknown) => error instanceof ProcessAdmissionError ? error.kind : 'other');
    expect(drifted).toBe('ADMISSION_DENIED');
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
    const forgedDecision = await decideLaunch(launcherDeps, expected,
      forgedHandshake as unknown as Parameters<typeof decideLaunch>[2], sendApprove, sendReject, () => Promise.resolve(true));
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
    active = deadPair;
    const deadOutcome = admitProcess(loaded, depsFor(deadPair.child)).then(() => 'admitted',
      (error: unknown) => error instanceof ProcessAdmissionError ? error.kind : 'other');
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

proof('physical profile: the production classifier is exact and positive on a real 022 database (r7 MUST 3)', { timeout: 120_000 }, async () => {
  const current = requireFixture();
  // The fixture chain IS 022 (S1): the real classifier must admit an S1
  // proof and refuse an S0 proof against the same physical database.
  const s1 = await admitFixture(current.migrator, current.database, 'TEST');
  // A separately SIGNED S0 proof (same witness machinery, S0 profile) for the
  // same database — used to prove S0 never admits an S1 database.
  const s0handle = await admitFixture(current.migrator, current.database, 'TEST', 'public', 'S0');
  try {
    const verifier = physicalProfileVerifier(databaseConfig(current.database));
    expect(await verifier(s1.admission)).toBe(true);
    const s0 = loadRuntimeAdmission(s0handle.env, { database: databaseConfig(current.database) });
    expect(s0.binding.profile).toBe('S0');
    expect(await verifier(s0)).toBe(false);
    // A damaged 022 is NEITHER profile: disable one guard trigger; the S1
    // fingerprint is false AND the positive absence probe is also false
    // (tables still exist), so both S1 and S0 are refused.
    await current.migrator.query('ALTER TABLE foundation.requests DISABLE TRIGGER requests_guard');
    try {
      expect(await verifier(s1.admission)).toBe(false);
      expect(await verifier(s0)).toBe(false);
    } finally {
      await current.migrator.query('ALTER TABLE foundation.requests ENABLE TRIGGER requests_guard');
    }
    // Restored: S1 is exact again; S0 stays refused because the tables exist.
    // Exactness in both directions.
    expect(await verifier(s1.admission)).toBe(true);
    expect(await verifier(s0)).toBe(false);
  } finally {
    await s1.release();
    await s0handle.release();
  }
});

proof('launcher ack deadline: a silent child after approval is a failed launch (r7 MUST 2)', { timeout: 120_000 }, async () => {
  const current = requireFixture();
  await current.migrator.query('CREATE TABLE IF NOT EXISTS foundation._prisma_migrations (id text PRIMARY KEY)');
  const admitted = await admitFixture(current.migrator, current.database, 'WORKER');
  const { Client } = await import('pg');
  const owner = new Client({ ...connection, database: current.database, user: 'fixlevelup_migrator',
    password: migratorPassword() });
  await owner.connect();
  try {
    const loaded = loadRuntimeAdmission(admitted.env, { database: databaseConfig(current.database), requiredConsumer: 'WORKER' });
    const { ensureLaunchRegistry, issueProof, readRegistryState } = await import('../src/infrastructure/admission/registry.js');
    const { decideLaunch } = await import('../src/infrastructure/admission/launcher.js');
    await ensureLaunchRegistry(owner);
    const instanceId = String(admitted.env['LAUNCH_INSTANCE_ID']);
    const channelId = String(admitted.env['LAUNCH_CHANNEL_ID']);
    const generation = Number(admitted.env['LAUNCH_ISSUER_GENERATION']);
    const nonce = String(admitted.env['LAUNCH_NONCE']);
    const proofDigest = loaded.proofDigest;
    await issueProof(owner, { issuerGeneration: generation, launchNonce: nonce, proofDigest,
      consumerKind: 'WORKER', instanceId, channelId, expiresAt: new Date(Date.now() + 120_000) });
    const launcherDeps = { app: { host: '127.0.0.1', port: 55432, database: current.database,
      user: 'fixlevelup_migrator', password: migratorPassword() },
      control: { host: '127.0.0.1', port: 55432, database: current.database,
        user: 'fixlevelup_migrator', password: migratorPassword() },
      witnessKeyOf: witnessKeyForInstance, ackTimeoutMs: 500 };
    // In-memory child that hands over a VALID handshake but never acks.
    const listeners: Array<(message: unknown) => void> = [];
    const child: LauncherChannel = {
      send: () => true,
      on: (_: 'message', listener: (message: unknown) => void) => { listeners.push(listener); return child; },
    };
    const deps = { database: databaseConfig(current.database), channel: child,
      verifyProfile: (): Promise<boolean> => Promise.resolve(true), approvalTimeoutMs: 2_000 };
    const outcome = admitProcess(loaded, deps).then(() => 'admitted',
      (error: unknown) => error instanceof ProcessAdmissionError ? error.kind : 'other');
    const handshake = await Promise.race([
      new Promise<Record<string, unknown>>((resolveHandshake) => {
        const orig = child.send.bind(child);
        child.send = (message: unknown) => {
          if (message !== null && typeof message === 'object' && (message as Record<string, unknown>)['type'] === 'p05/launch/handshake') {
            resolveHandshake(message as Record<string, unknown>);
          }
          return orig(message);
        };
      }),
      outcome.then((o) => { throw new Error(`child ended before handshake: ${o}`); }),
    ]);
    let approvals = 0;
    const decision = await decideLaunch(launcherDeps,
      { instanceId, launchNonce: nonce, consumerKind: 'WORKER' as const, proofDigest,
        issuerGeneration: generation, witnessHolderPid: loaded.binding.witnessHolderPid, channelId },
      handshake as unknown as Parameters<typeof decideLaunch>[2],
      () => { approvals += 1; for (const l of listeners) { l({ type: 'p05/launch/approve', instanceId, launchNonce: nonce }); } },
      () => undefined,
      () => new Promise<boolean>(() => undefined)); // SILENT child: never acks.
    // The approval was sent exactly once, but the launcher's OWN deadline
    // resolved the unacked outcome instead of awaiting forever.
    expect(approvals).toBe(1);
    expect(decision.approved).toBe(true);
    expect((decision as { acked?: boolean }).acked).toBe(false);
    // The proof was durably consumed by the (failed) launch.
    expect((await readRegistryState(owner, generation, nonce))?.state).toBe('CONSUMED');
    expect(await outcome).toBe('admitted'); // the child DID start; the launch is reported unacked
  } finally {
    await owner.end().catch(() => undefined);
    await admitted.release().catch(() => undefined);
  }
});

proof('launcher DB deadlines: a control endpoint that accepts and never answers refuses quickly (r8 MUST 2)', { timeout: 60_000 }, async () => {
  const current = requireFixture();
  const admitted = await admitFixture(current.migrator, current.database, 'WORKER');
  try {
    const loaded = loadRuntimeAdmission(admitted.env, { database: databaseConfig(current.database), requiredConsumer: 'WORKER' });
    const { ensureLaunchRegistry, issueProof } = await import('../src/infrastructure/admission/registry.js');
    const { decideLaunch } = await import('../src/infrastructure/admission/launcher.js');
    const { Client } = await import('pg');
    const owner = new Client({ ...connection, database: current.database, user: 'fixlevelup_migrator', password: migratorPassword() });
    await owner.connect();
    try {
      await ensureLaunchRegistry(owner);
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
          control: { host: '127.0.0.1', port, database: current.database,
            user: 'fixlevelup_migrator', password: migratorPassword() },
          witnessKeyOf: witnessKeyForInstance, ackTimeoutMs: 500 };
        const child: LauncherChannel = {
          send: () => true,
          on: () => child,
        };
        const handshake = { type: 'p05/launch/handshake', pid: process.pid, database: bindingDatabase(loaded),
          databaseOid: loaded.binding.databaseOid, role: loaded.binding.role,
          witnessHolderPid: loaded.binding.witnessHolderPid, consumerKind: 'WORKER',
          instanceId, channelId, issuerGeneration: generation, launchNonce: nonce,
          proofDigest: loaded.proofDigest, profile: 'S1' };
        const started = Date.now();
        const decision = await decideLaunch(deps, { instanceId, launchNonce: nonce, consumerKind: 'WORKER' as const,
          proofDigest: loaded.proofDigest, issuerGeneration: generation,
          witnessHolderPid: loaded.binding.witnessHolderPid, channelId },
          handshake as unknown as Parameters<typeof decideLaunch>[2],
          () => undefined, () => undefined, () => new Promise<boolean>(() => undefined));
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

function bindingDatabase(loaded: ReturnType<typeof loadRuntimeAdmission>): string {
  return loaded.binding.database;
}

function migratorPassword(): string {
  const toolingEnv = readFileSync(resolve(root, 'packages/database-tooling/.env'), 'utf8');
  const password = /^FIXLEVELUP_MIGRATOR_PASSWORD=([a-f0-9]{64})$/m.exec(toolingEnv)?.[1];
  if (!password) { throw new Error('Local isolated PostgreSQL migrator credentials are required'); }
  return password;
}

function requireFixture(): ConfigurationFixture {
  if (!fixture) { throw new Error('Isolated fixture is not initialized'); }
  return fixture;
}
