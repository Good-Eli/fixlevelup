/**
 * P05-01 slice (f): launch proof / one-time admission infrastructure
 * (docs/P05-PLAN.md §7).
 *
 * Real PostgreSQL contour, opt-in via FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS=1,
 * same style as p05-baseline-locks.test.ts: one disposable application
 * database created by `createConfigurationFixture` with the full reviewed
 * migration chain (S1 profile), plus a SEPARATE one-off disposable control
 * database in the same PostgreSQL instance — the plan §7 launcher contour:
 * the launch registry lives in `launch_control` of the control DB, owned and
 * provisioned by a dedicated control owner, with a separate launcher role
 * that has only USAGE on the schema, SELECT/INSERT and UPDATE(state,
 * consumed_at) on launch_proofs — no DELETE, no TRUNCATE, no DDL, and no
 * CONNECT for fixlevelup_runtime.
 *
 * Covered:
 *  - proof sign/verify roundtrip (Ed25519 keypair generated in-test), tampered
 *    token → BAD_SIGNATURE, expired → EXPIRED, malformed token;
 *  - registry (launcher role on the control DB): issue → consume exactly
 *    once, second consume false, CONSUMED immutable (guard rejects direct
 *    UPDATE with 23514, checked by the migrator owner), direct INSERT of a
 *    CONSUMED row rejected (owner), duplicate issue → ALREADY_ISSUED, digest
 *    mismatch → DIGEST_MISMATCH with no state change;
 *  - registry expiry lives in the row: issue stores the future expires_at
 *    (past expiry rejected by the guard with 23514, owner connection), an
 *    expired ISSUED row is not consumable (consume → false, row stays
 *    ISSUED), and expires_at is immutable in a transition UPDATE; the
 *    issue/consume transactions run with synchronous_commit = on (not
 *    introspectable after COMMIT — the working issue→consume path is the
 *    regression assertion);
 *  - isolation: fixlevelup_runtime cannot CONNECT to the control DB, the
 *    launcher cannot DELETE/TRUNCATE/ALTER (42501), the guard function is not
 *    executable by the launcher/PUBLIC, and the application database has no
 *    launch_control schema at all (to_regnamespace IS NULL);
 *  - witness: launcher connection holds the session lock, another connection
 *    sees the exact holder pid (also pid-bound via expectedPid), after release
 *    nothing is visible;
 *  - admission gate: correct database/role/schema + live witness passes, wrong
 *    role → WRONG_ROLE, wrong database → WRONG_DATABASE, wrong schema →
 *    WRONG_SCHEMA, missing witness → WITNESS_MISSING, pid-bound witness passes
 *    with the exact launcher pid and a wrong pid → WITNESS_MISMATCH, proof
 *    token checks;
 *  - concurrent consume: two launcher connections race on one issued nonce,
 *    exactly one winner, final state CONSUMED exactly once.
 */
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { Client, Pool } from 'pg';
import type { PoolClient, QueryResult } from 'pg';
import { AdmissionError, AdmissionGate } from '../src/infrastructure/admission/admission.js';
import type { AdmissionBinding } from '../src/infrastructure/admission/admission.js';
import { canonicalJson, proofDigestOf, signProof, verifyProof } from '../src/infrastructure/admission/proof.js';
import type { LaunchProofPayload, ProofErrorCode } from '../src/infrastructure/admission/proof.js';
import { ProofError } from '../src/infrastructure/admission/proof.js';
import {
  consumeProof, ensureLaunchRegistry, issueProof, readRegistryState, RegistryError,
} from '../src/infrastructure/admission/registry.js';
import type { ControlStatement } from '../src/infrastructure/admission/registry.js';
import { holdWitness, releaseWitness, witnessVisible, WITNESS_KEY } from '../src/infrastructure/admission/witness.js';
import { createConfigurationFixture } from './configuration-fixture.js';
import type { ConfigurationFixture } from './configuration-fixture.js';
import { fixtureCredentials } from './owned-test-database.js';

const proof = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1' ? it : it.skip;

const keyPair = generateKeyPairSync('ed25519');
const privateKeyPem = keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const publicKeyPem = keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();

const root = resolve(import.meta.dirname, '../../..');
const pgConnection = { host: '127.0.0.1' as const, port: 55432 };

async function controlAdminOpener(): Promise<() => Promise<Client>> {
  const labMode = process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1';
  const user = labMode ? 'postgres' : 'fixlevelup_dev';
  const password = labMode ? process.env['FIXLEVELUP_LAB_FIXTURE_ADMIN_PASSWORD']
    : /^POSTGRES_PASSWORD=([a-f0-9]{64})$/m.exec(readFileSync(resolve(root, 'infra/dev-postgres/.env'), 'utf8'))?.[1];
  if (!password || !/^[a-f0-9]{64}$/.test(password)) { throw new Error('Control fixture admin credential is unavailable'); }
  const cluster = process.env['FIXLEVELUP_CLUSTER_NAME'];
  if (labMode) {
    const { loadP05LabTarget } = await import('./p05-lab-target.js');
    const maintenance = await loadP05LabTarget().openMaintenance();
    await maintenance.end();
  }
  return async () => {
    const client = new Client({ ...pgConnection, database: 'postgres', user, password,
      connectionTimeoutMillis: 3000, statement_timeout: 5000, query_timeout: 6000 });
    try {
      await client.connect();
      const { rows } = await client.query<{ valid: boolean }>(`SELECT current_database() = 'postgres'
        AND current_user = $1 AND session_user = $1
        AND EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname=current_user AND rolsuper)
        AND (NOT $2::boolean OR (current_setting('cluster_name') = $3
          AND current_setting('server_version_num') = '180007'
          AND host(inet_server_addr()) = '127.0.0.1' AND inet_server_port() = 55432)) AS valid`,
      [user, labMode, cluster ?? null]);
      if (rows[0]?.valid !== true) { throw new Error('Unexpected control fixture admin identity'); }
      return client;
    } catch {
      await client.end().catch(() => undefined);
      throw new Error('Unable to attest control fixture admin session');
    }
  };
}

interface ControlFixture {
  readonly database: string;
  readonly ownerRole: string;
  readonly launcherRole: string;
  /** Dedicated control-owner pool (NOT the application migrator). */
  readonly owner: Pool;
  /** One-off launcher role pool: USAGE + SELECT/INSERT + UPDATE(state,consumed_at). */
  readonly launcher: Pool;
  close(): Promise<void>;
}

let fixture: ConfigurationFixture | undefined;
let control: ControlFixture | undefined;

beforeAll(async () => {
  if (process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] !== '1') { return; }
  const openAdmin = await controlAdminOpener();
  await (await openAdmin()).end();
  const created = await createConfigurationFixture();
  // A failed beforeAll never reaches afterAll (vitest skips it for the
  // suite), so whatever beforeAll already created must be closed HERE:
  // createControlFixture rolls its own partial provisioning back, and the
  // application database is closed the same way afterAll would.
  fixture = created;
  try {
    control = await createControlFixture(openAdmin);
  } catch (error) {
    fixture = undefined;
    await created.close().catch(() => undefined);
    throw error;
  }
}, 240_000);

afterAll(async () => {
  const created = control;
  control = undefined;
  if (created) { await created.close(); }
  if (fixture) { await fixture.close(); }
}, 120_000);

function requireFixture(): ConfigurationFixture {
  if (!fixture) { throw new Error('Isolated fixture is not initialized'); }
  return fixture;
}

function requireControl(): ControlFixture {
  if (!control) { throw new Error('Control fixture is not initialized'); }
  return control;
}

/**
 * The plan §7 contour: a one-off CONTROL OWNER role, a one-off launcher role
 * and a one-off control database in the same disposable PostgreSQL instance,
 * fully separate from the application database. The control database is owned
 * and provisioned by the dedicated control owner — NOT by the application
 * migrator (§7 excludes application/migrator credentials from the registry
 * contour). CONNECT is granted to the launcher role only; the launcher gets
 * exactly USAGE + SELECT/INSERT + UPDATE(state, consumed_at).
 */
async function createControlFixture(openAdmin: () => Promise<Client>): Promise<ControlFixture> {
  const suffix = randomBytes(12).toString('hex');
  const database = `fixlevelup_p05_control_${suffix}`;
  const ownerRole = `fixlevelup_p05_ctlowner_${suffix}`;
  const launcherRole = `fixlevelup_p05_launcher_${suffix}`;
  // In-memory only: never written anywhere.
  const ownerPassword = randomBytes(32).toString('hex');
  const launcherPassword = randomBytes(32).toString('hex');
  // 12 random bytes as hex (24 chars), same one-off pattern as the fixture DBs.
  if (!/^fixlevelup_p05_control_[a-f0-9]{24}$/.test(database)
    || !/^fixlevelup_p05_launcher_[a-f0-9]{24}$/.test(launcherRole)
    || !/^fixlevelup_p05_ctlowner_[a-f0-9]{24}$/.test(ownerRole)) {
    throw new Error('Control fixture name generation failed');
  }

  // What the admin already created, so a partial provisioning failure can be
  // rolled back without leaking the one-off database or roles.
  let databaseCreated = false;
  let launcherRoleCreated = false;
  let ownerRoleCreated = false;
  const pools: Pool[] = [];

  /**
   * Best-effort mirror of the normal teardown for a PARTIALLY provisioned
   * contour: end whatever pools were already opened, then drop exactly the
   * one-off database and roles that were created — with the same exact-name
   * verification (teardown really connected to `postgres`, each generated
   * name present exactly once) the afterAll teardown uses. Only artifacts
   * flagged as created are verified and dropped. Cleanup failures are
   * swallowed by the caller so the ORIGINAL provisioning error survives.
   */
  const cleanupPartialProvisioning = async (): Promise<void> => {
    await Promise.all(pools.map((pool) => pool.end().catch(() => undefined)));
    const teardown = await openAdmin();
    try {
      const mine = await teardown.query<{ db: string }>('SELECT current_database() AS db');
      const dbRow = databaseCreated ? (await teardown.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM pg_database WHERE datname = $1`, [database])).rows[0] : undefined;
      const roleRow = launcherRoleCreated ? (await teardown.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM pg_roles WHERE rolname = $1`, [launcherRole])).rows[0] : undefined;
      const ownerRow = ownerRoleCreated ? (await teardown.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM pg_roles WHERE rolname = $1`, [ownerRole])).rows[0] : undefined;
      if (mine.rows[0]?.db !== 'postgres'
        || (dbRow !== undefined && dbRow.n !== 1)
        || (roleRow !== undefined && roleRow.n !== 1)
        || (ownerRow !== undefined && ownerRow.n !== 1)) {
        throw new Error(`Refusing control cleanup: db=${database} owner=${ownerRole} role=${launcherRole}`);
      }
      if (databaseCreated) { await teardown.query(`DROP DATABASE "${database}"`); }
      if (launcherRoleCreated) { await teardown.query(`DROP ROLE "${launcherRole}"`); }
      if (ownerRoleCreated) { await teardown.query(`DROP ROLE "${ownerRole}"`); }
    } finally {
      await teardown.end();
    }
  };

  try {
    const admin = await openAdmin();
    try {
      await admin.query(`CREATE ROLE "${ownerRole}" LOGIN PASSWORD '${ownerPassword}'`);
      ownerRoleCreated = true;
      await admin.query(`CREATE ROLE "${launcherRole}" LOGIN PASSWORD '${launcherPassword}'`);
      launcherRoleCreated = true;
      await admin.query(`CREATE DATABASE "${database}" OWNER "${ownerRole}" TEMPLATE template0`);
      databaseCreated = true;
      await admin.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`);
      await admin.query(`GRANT CONNECT ON DATABASE "${database}" TO "${launcherRole}"`);
    } finally {
      await admin.end();
    }

    // Dedicated control owner provisions the registry; the application
    // migrator has no CONNECT here (asserted in the isolation proofs).
    const owner = new Pool({ ...pgConnection, database, user: ownerRole, password: ownerPassword,
      max: 4, connectionTimeoutMillis: 3000, statement_timeout: 12_000 });
    pools.push(owner);
    await ensureLaunchRegistry(owner);
    await owner.query(`GRANT USAGE ON SCHEMA launch_control TO "${launcherRole}"`);
    await owner.query(`GRANT SELECT, INSERT ON launch_control.launch_proofs TO "${launcherRole}"`);
    await owner.query(`GRANT UPDATE (state, consumed_at) ON launch_control.launch_proofs TO "${launcherRole}"`);

    const launcher = new Pool({ ...pgConnection, database, user: launcherRole, password: launcherPassword,
      max: 4, connectionTimeoutMillis: 3000, statement_timeout: 12_000 });
    pools.push(launcher);

    return {
      database,
      ownerRole,
      launcherRole,
      owner,
      launcher,
      async close(): Promise<void> {
        await Promise.all([owner.end(), launcher.end()]);
        const teardown = await openAdmin();
        try {
          // Verify the exact one-off names before dropping anything.
          const mine = await teardown.query<{ db: string }>('SELECT current_database() AS db');
          const dbRow = (await teardown.query<{ n: number }>(
            `SELECT count(*)::int AS n FROM pg_database WHERE datname = $1`, [database])).rows[0];
          const roleRow = (await teardown.query<{ n: number }>(
            `SELECT count(*)::int AS n FROM pg_roles WHERE rolname = $1`, [launcherRole])).rows[0];
          const ownerRow = (await teardown.query<{ n: number }>(
            `SELECT count(*)::int AS n FROM pg_roles WHERE rolname = $1`, [ownerRole])).rows[0];
          if (mine.rows[0]?.db !== 'postgres' || dbRow?.n !== 1 || roleRow?.n !== 1 || ownerRow?.n !== 1) {
            throw new Error(`Refusing control teardown: db=${database} owner=${ownerRole} role=${launcherRole}`);
          }
          await teardown.query(`DROP DATABASE "${database}"`);
          await teardown.query(`DROP ROLE "${launcherRole}"`);
          await teardown.query(`DROP ROLE "${ownerRole}"`);
        } finally {
          await teardown.end();
        }
      },
    };
  } catch (error) {
    // Any failure AFTER the admin created the role(s)/database but BEFORE
    // the fixture object is returned must not leak them: best-effort
    // cleanup, then re-throw the original provisioning error.
    await cleanupPartialProvisioning().catch(() => undefined);
    throw error;
  }
}

function samplePayload(overrides: Partial<LaunchProofPayload> = {}): LaunchProofPayload {
  return {
    issuerGeneration: 3,
    launchNonce: randomUUID(),
    consumerKind: 'TEST',
    instanceId: randomUUID(),
    channelId: randomUUID(),
    artifactDigest: 'a1'.repeat(32),
    endpoint: '127.0.0.1:55432',
    targetIdentity: {
      database: 'admission-fixture-db',
      databaseOid: 12345,
      runtimeRole: 'fixlevelup_runtime',
      schema: 'foundation',
    },
    profile: 'S1',
    historyManifestDigest: 'b2'.repeat(32),
    physicalContractDigest: 'c3'.repeat(32),
    witness: { classId: WITNESS_KEY.classId, objectId: WITNESS_KEY.objectId, mode: 'SESSION' },
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    ...overrides,
  };
}

function beforeExpiry(payload: LaunchProofPayload): Date {
  return new Date(Date.parse(payload.expiresAt) - 1_000);
}

function expectProofError(action: () => unknown, code: ProofErrorCode): void {
  let thrown: unknown;
  try {
    action();
  } catch (error) {
    thrown = error;
  }
  expect(thrown).toBeInstanceOf(ProofError);
  expect((thrown as ProofError).code).toBe(code);
}

function pgErrorCode(error: unknown): string | undefined {
  if (typeof error === 'object' && error !== null && 'code' in error) {
    const code = (error as { readonly code: unknown }).code;
    return typeof code === 'string' ? code : undefined;
  }
  return undefined;
}

async function backendPid(client: PoolClient): Promise<number> {
  const result = await client.query<{ pid: number }>('SELECT pg_backend_pid() AS pid');
  const pid = result.rows[0]?.pid;
  if (typeof pid !== 'number') { throw new Error('Missing backend PID'); }
  return pid;
}

/** Releases a session-scoped witness even if the holder client is gone. */
async function safelyRelease(client: PoolClient): Promise<void> {
  await releaseWitness(client).catch(() => undefined);
  client.release();
}

// --- Pure cryptographic part (no database): always runs. ---

it('proof: canonical JSON is deterministic (sorted keys, no whitespace)', () => {
  const value = { b: 1, a: { d: [3, { z: 1, y: null }], c: true } };
  expect(canonicalJson(value)).toBe('{"a":{"c":true,"d":[3,{"y":null,"z":1}]},"b":1}');
  expect(canonicalJson(value)).toBe(canonicalJson({ a: { c: true, d: [3, { y: null, z: 1 }] }, b: 1 }));
});

it('proof: sign/verify roundtrip returns the exact payload', () => {
  const payload = samplePayload();
  const token = signProof(payload, privateKeyPem);
  expect(token.includes('.')).toBe(true);
  expect(verifyProof(token, publicKeyPem, beforeExpiry(payload))).toEqual(payload);
});

it('proof: tampered payload or signature → BAD_SIGNATURE', () => {
  const payload = samplePayload();
  const token = signProof(payload, privateKeyPem);
  const [encodedPayload, signature] = token.split('.').length === 2
    ? token.split('.') as [string, string]
    : [''];
  expect(signature).toBeDefined();
  const parsed = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8')) as Record<string, unknown>;
  parsed['issuerGeneration'] = payload.issuerGeneration + 1;
  const tamperedPayload = `${Buffer.from(canonicalJson(parsed), 'utf8').toString('base64url')}.${signature ?? ''}`;
  expectProofError(() => verifyProof(tamperedPayload, publicKeyPem, beforeExpiry(payload)), 'BAD_SIGNATURE');

  const tamperedSignature = `${encodedPayload}.${Buffer.from('0000', 'base64').toString('base64')}`;
  expectProofError(() => verifyProof(tamperedSignature, publicKeyPem, beforeExpiry(payload)), 'BAD_SIGNATURE');
});

it('proof: expired token → EXPIRED, garbage token → MALFORMED', () => {
  const payload = samplePayload();
  const token = signProof(payload, privateKeyPem);
  const afterExpiry = new Date(Date.parse(payload.expiresAt) + 1_000);
  expectProofError(() => verifyProof(token, publicKeyPem, afterExpiry), 'EXPIRED');
  expectProofError(() => verifyProof('not-a-proof-token', publicKeyPem, beforeExpiry(payload)), 'MALFORMED');
  expectProofError(() => verifyProof(`${token}.extra`, publicKeyPem, beforeExpiry(payload)), 'MALFORMED');
});

it('proof: wrong shape with a valid signature → MALFORMED (self-signed attack payload)', () => {
  const forged = {
    issuerGeneration: 1,
    launchNonce: randomUUID(),
    consumerKind: 'API',
    instanceId: randomUUID(),
    channelId: randomUUID(),
    artifactDigest: 'aa'.repeat(32),
    targetIdentity: { database: 'x', databaseOid: 'not-a-number', runtimeRole: 'r', schema: 's' },
    profile: 'S1',
    historyManifestDigest: 'bb'.repeat(32),
    physicalContractDigest: 'cc'.repeat(32),
    witness: { classId: 1, objectId: 1, mode: 'SESSION' },
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  };
  const token = signProof(forged as unknown as LaunchProofPayload, privateKeyPem);
  expectProofError(() => verifyProof(token, publicKeyPem, beforeExpiry(forged as unknown as LaunchProofPayload)), 'MALFORMED');
});

// --- Registry contour (real PostgreSQL, launcher role on the control DB). ---

proof('registry: issue then consume succeeds exactly once; CONSUMED is immutable', { timeout: 120_000 }, async () => {
  const client = await requireControl().launcher.connect();
  const owner = await requireControl().owner.connect();
  try {
    const payload = samplePayload({ consumerKind: 'API' });
    const digest = proofDigestOf(payload);
    const input = {
      issuerGeneration: payload.issuerGeneration,
      launchNonce: payload.launchNonce,
      proofDigest: digest,
      consumerKind: payload.consumerKind,
      instanceId: payload.instanceId,
      channelId: payload.channelId,
      expiresAt: new Date(Date.parse(payload.expiresAt)),
    };
    await issueProof(client, input);

    const issued = await readRegistryState(client, payload.issuerGeneration, payload.launchNonce);
    expect(issued?.state).toBe('ISSUED');
    expect(issued?.consumed_at).toBeNull();
    expect(issued?.proof_digest).toBe(digest);
    // The registry row itself carries the future expiry from the issue call.
    expect(issued?.expires_at).toBeInstanceOf(Date);
    expect(issued?.expires_at.getTime()).toBeGreaterThan(Date.now());

    // The consumed row must carry the verified consumer binding (round-5
    // MUST 2): the exact consumer/instance/channel of the issued payload.
    const consumed = await consumeProof(client, {
      issuerGeneration: payload.issuerGeneration,
      launchNonce: payload.launchNonce,
      expectedDigest: digest,
      binding: { consumerKind: payload.consumerKind, instanceId: payload.instanceId, channelId: payload.channelId },
    });
    expect(consumed).toBe(true);

    // Second consume of the same nonce: exactly one winner already committed.
    const again = await consumeProof(client, {
      issuerGeneration: payload.issuerGeneration,
      launchNonce: payload.launchNonce,
      expectedDigest: digest,
      binding: { consumerKind: payload.consumerKind, instanceId: payload.instanceId, channelId: payload.channelId },
    });
    expect(again).toBe(false);

    const final = await readRegistryState(client, payload.issuerGeneration, payload.launchNonce);
    expect(final?.state).toBe('CONSUMED');
    expect(final?.consumed_at).toBeInstanceOf(Date);

    // Guard immutability checks need UPDATE of columns the launcher does not
    // have: run them on the migrator owner connection (guard still rejects).
    let guardCode: string | undefined;
    try {
      await owner.query(`UPDATE launch_control.launch_proofs SET consumed_at = clock_timestamp()
        WHERE issuer_generation = $1 AND launch_nonce = $2`,
      [payload.issuerGeneration, payload.launchNonce]);
    } catch (error) {
      guardCode = pgErrorCode(error);
    }
    expect(guardCode).toBe('23514');

    let resetCode: string | undefined;
    try {
      await owner.query(`UPDATE launch_control.launch_proofs SET state = 'ISSUED', consumed_at = NULL
        WHERE issuer_generation = $1 AND launch_nonce = $2`,
      [payload.issuerGeneration, payload.launchNonce]);
    } catch (error) {
      resetCode = pgErrorCode(error);
    }
    expect(resetCode).toBe('23514');

    const stillConsumed = await readRegistryState(client, payload.issuerGeneration, payload.launchNonce);
    expect(stillConsumed?.state).toBe('CONSUMED');
    expect(stillConsumed?.consumed_at?.getTime()).toBe(final?.consumed_at?.getTime());
  } finally {
    client.release();
    owner.release();
  }
});

proof('registry: direct INSERT of a consumed row is rejected by the guard', { timeout: 60_000 }, async () => {
  const owner = await requireControl().owner.connect();
  try {
    const nonce = randomUUID();
    let guardCode: string | undefined;
    try {
      await owner.query(`INSERT INTO launch_control.launch_proofs
        (issuer_generation, launch_nonce, proof_digest, consumer_kind, instance_id, channel_id, state, expires_at)
        VALUES ($1, $2, $3, 'TEST', $4, $5, 'CONSUMED', clock_timestamp() + interval '5 minutes')`,
      [1, nonce, 'ab'.repeat(32), randomUUID(), randomUUID()]);
    } catch (error) {
      guardCode = pgErrorCode(error);
    }
    expect(guardCode).toBe('23514');
    expect(await readRegistryState(owner, 1, nonce)).toBeUndefined();
  } finally {
    owner.release();
  }
});

proof('registry: duplicate issue → ALREADY_ISSUED', { timeout: 60_000 }, async () => {
  const client = await requireControl().launcher.connect();
  try {
    const payload = samplePayload();
    const input = {
      issuerGeneration: payload.issuerGeneration,
      launchNonce: payload.launchNonce,
      proofDigest: proofDigestOf(payload),
      consumerKind: payload.consumerKind,
      instanceId: payload.instanceId,
      channelId: payload.channelId,
      expiresAt: new Date(Date.parse(payload.expiresAt)),
    };
    await issueProof(client, input);
    await expect(issueProof(client, input)).rejects.toMatchObject({
      name: 'RegistryError', code: 'ALREADY_ISSUED',
    });
    // The row is still the original single ISSUED record.
    const state = await readRegistryState(client, payload.issuerGeneration, payload.launchNonce);
    expect(state?.state).toBe('ISSUED');
    expect(state?.consumed_at).toBeNull();
  } finally {
    client.release();
  }
});

proof('registry: digest mismatch consume → DIGEST_MISMATCH, row stays ISSUED', { timeout: 60_000 }, async () => {
  const client = await requireControl().launcher.connect();
  try {
    const payload = samplePayload();
    const digest = proofDigestOf(payload);
    await issueProof(client, {
      issuerGeneration: payload.issuerGeneration,
      launchNonce: payload.launchNonce,
      proofDigest: digest,
      consumerKind: payload.consumerKind,
      instanceId: payload.instanceId,
      channelId: payload.channelId,
      expiresAt: new Date(Date.parse(payload.expiresAt)),
    });
    const mismatch = await consumeProof(client, {
      issuerGeneration: payload.issuerGeneration,
      launchNonce: payload.launchNonce,
      expectedDigest: 'ff'.repeat(32),
      binding: { consumerKind: payload.consumerKind, instanceId: payload.instanceId, channelId: payload.channelId },
    }).then(() => 'resolved', (error: unknown) => (error instanceof RegistryError ? error.code : 'other'));
    expect(mismatch).toBe('DIGEST_MISMATCH');
    const state = await readRegistryState(client, payload.issuerGeneration, payload.launchNonce);
    expect(state?.state).toBe('ISSUED');
    // The mismatch did not consume the proof: the exact digest still wins.
    const consumed = await consumeProof(client, {
      issuerGeneration: payload.issuerGeneration,
      launchNonce: payload.launchNonce,
      expectedDigest: digest,
      binding: { consumerKind: payload.consumerKind, instanceId: payload.instanceId, channelId: payload.channelId },
    });
    expect(consumed).toBe(true);
  } finally {
    client.release();
  }
});

proof('registry: direct INSERT with a past expires_at is rejected by the guard', { timeout: 60_000 }, async () => {
  const owner = await requireControl().owner.connect();
  try {
    const nonce = randomUUID();
    let guardCode: string | undefined;
    try {
      await owner.query(`INSERT INTO launch_control.launch_proofs
        (issuer_generation, launch_nonce, proof_digest, consumer_kind, instance_id, channel_id, expires_at)
        VALUES ($1, $2, $3, 'TEST', $4, $5, clock_timestamp() - interval '1 second')`,
      [1, nonce, 'ab'.repeat(32), randomUUID(), randomUUID()]);
    } catch (error) {
      guardCode = pgErrorCode(error);
    }
    expect(guardCode).toBe('23514');
    expect(await readRegistryState(owner, 1, nonce)).toBeUndefined();
  } finally {
    owner.release();
  }
});

proof('registry: expiry lives in the row — expired ISSUED proof is not consumable', { timeout: 60_000 }, async () => {
  const client = await requireControl().launcher.connect();
  const owner = await requireControl().owner.connect();
  try {
    const payload = samplePayload();
    const digest = proofDigestOf(payload);
    // Issue with a ~50ms expiry; expires_at is stored in the row and (like
    // every other non-state column) immutable afterwards, so the registry's
    // own clock decides consumability — no caller-supplied deadline.
    await issueProof(client, {
      issuerGeneration: payload.issuerGeneration,
      launchNonce: payload.launchNonce,
      proofDigest: digest,
      consumerKind: payload.consumerKind,
      instanceId: payload.instanceId,
      channelId: payload.channelId,
      expiresAt: new Date(Date.now() + 50),
    });
    await new Promise((resolve) => { setTimeout(resolve, 120); });

    // Expired row: consume returns false and the row simply stays ISSUED.
    // This path also proves the issue/consume transactions still work with
    // SET LOCAL synchronous_commit = on (not introspectable after COMMIT).
    const consumed = await consumeProof(client, {
      issuerGeneration: payload.issuerGeneration,
      launchNonce: payload.launchNonce,
      expectedDigest: digest,
      binding: { consumerKind: payload.consumerKind, instanceId: payload.instanceId, channelId: payload.channelId },
    });
    expect(consumed).toBe(false);
    const expiredState = await readRegistryState(client, payload.issuerGeneration, payload.launchNonce);
    expect(expiredState?.state).toBe('ISSUED');
    expect(expiredState?.consumed_at).toBeNull();
    expect(expiredState?.expires_at.getTime()).toBeLessThanOrEqual(Date.now());

    // Even a well-formed transition UPDATE cannot tamper expires_at (owner
    // connection: the tamper needs UPDATE rights on expires_at).
    let tamperCode: string | undefined;
    try {
      await owner.query(`UPDATE launch_control.launch_proofs
        SET state = 'CONSUMED', consumed_at = clock_timestamp(),
          expires_at = clock_timestamp() + interval '1 hour'
        WHERE issuer_generation = $1 AND launch_nonce = $2`,
      [payload.issuerGeneration, payload.launchNonce]);
    } catch (error) {
      tamperCode = pgErrorCode(error);
    }
    expect(tamperCode).toBe('23514');
    const stillIssued = await readRegistryState(client, payload.issuerGeneration, payload.launchNonce);
    expect(stillIssued?.state).toBe('ISSUED');
    expect(stillIssued?.expires_at.getTime()).toBe(expiredState?.expires_at.getTime());
  } finally {
    client.release();
    owner.release();
  }
});

// --- Control contour isolation proofs (plan §7 launcher rights). ---

proof('control isolation: runtime cannot connect, launcher cannot DELETE/TRUNCATE/ALTER or call the guard, app DB has no launch_control', { timeout: 120_000 }, async () => {
  const ctl = requireControl();
  const launcher = await ctl.launcher.connect();
  try {
    // A live ISSUED row to prove destructive statements actually miss rights.
    const payload = samplePayload({ consumerKind: 'TEST' });
    await issueProof(launcher, {
      issuerGeneration: payload.issuerGeneration,
      launchNonce: payload.launchNonce,
      proofDigest: proofDigestOf(payload),
      consumerKind: payload.consumerKind,
      instanceId: payload.instanceId,
      channelId: payload.channelId,
      expiresAt: new Date(Date.parse(payload.expiresAt)),
    });

    // Launcher DELETE and TRUNCATE: 42501, and the row survives.
    let deleteCode: string | undefined;
    try {
      await launcher.query(`DELETE FROM launch_control.launch_proofs
        WHERE issuer_generation = $1 AND launch_nonce = $2`,
      [payload.issuerGeneration, payload.launchNonce]);
    } catch (error) {
      deleteCode = pgErrorCode(error);
    }
    expect(deleteCode).toBe('42501');
    let truncateCode: string | undefined;
    try {
      await launcher.query('TRUNCATE launch_control.launch_proofs');
    } catch (error) {
      truncateCode = pgErrorCode(error);
    }
    expect(truncateCode).toBe('42501');
    expect(await readRegistryState(launcher, payload.issuerGeneration, payload.launchNonce)).toBeDefined();

    // Launcher DDL: 42501.
    let alterCode: string | undefined;
    try {
      await launcher.query('ALTER TABLE launch_control.launch_proofs ADD COLUMN probe int');
    } catch (error) {
      alterCode = pgErrorCode(error);
    }
    expect(alterCode).toBe('42501');

    // The guard trigger function is not directly executable by the launcher.
    let callCode: string | undefined;
    try {
      await launcher.query('SELECT launch_control.guard_transition()');
    } catch (error) {
      callCode = pgErrorCode(error);
    }
    expect(callCode).toBe('42501');
  } finally {
    launcher.release();
  }

  // fixlevelup_runtime has no CONNECT on the control DB: PostgreSQL 18
  // refuses the session with the exact insufficient_privilege SQLSTATE
  // 42501 (FATAL "permission denied for database", postinit.c
  // CheckMyDatabase; observed live on this contour). A credential problem
  // would instead surface as 28P01, so the exact code pins the privilege
  // denial itself, not merely "connection failed".
  const { runtime: runtimePassword, migrator: migratorPassword } = fixtureCredentials();
  const runtime = new Client({ ...pgConnection, database: ctl.database, user: 'fixlevelup_runtime', password: runtimePassword });
  const refused = await runtime.connect().then(() => 'connected', (error: unknown) => pgErrorCode(error) ?? String(error));
  expect(refused).toBe('42501');
  await runtime.end().catch(() => undefined);

  // The APPLICATION MIGRATOR is equally excluded from the control DB (§7:
  // no application/migrator credentials near the registry contour) — same
  // exact 42501 insufficient_privilege refusal.
  const migrator = new Client({ ...pgConnection, database: ctl.database, user: 'fixlevelup_migrator', password: migratorPassword });
  const migratorRefused = await migrator.connect().then(() => 'connected', (error: unknown) => pgErrorCode(error) ?? String(error));
  expect(migratorRefused).toBe('42501');
  await migrator.end().catch(() => undefined);

  // The application database has no launch_control schema at all.
  const app = await requireFixture().migrator.connect();
  try {
    const schema = await app.query<{ n: string | null }>(`SELECT to_regnamespace('launch_control') AS n`);
    expect(schema.rows[0]?.n).toBeNull();
  } finally {
    app.release();
  }
});

// --- Witness contour (real PostgreSQL). ---

proof('witness: launcher session lock is visible to another connection with the exact pid', { timeout: 60_000 }, async () => {
  const launcher = await requireFixture().migrator.connect();
  const observer = await requireFixture().runtime.connect();
  try {
    await holdWitness(launcher);
    const launcherPid = await backendPid(launcher);
    const visibility = await witnessVisible(observer);
    expect(visibility.visible).toBe(true);
    expect(visibility.pid).toBe(launcherPid);
    // Pid-bound visibility: the exact launcher pid counts, any other does not.
    const exactPid = await witnessVisible(observer, WITNESS_KEY, launcherPid);
    expect(exactPid.visible).toBe(true);
    expect(exactPid.pid).toBe(launcherPid);
    const wrongPid = await witnessVisible(observer, WITNESS_KEY, launcherPid === 1 ? 2 : launcherPid - 1);
    expect(wrongPid.visible).toBe(false);
    expect(wrongPid.pid).toBe(0);
    // The holder itself never counts as a foreign witness.
    const selfVisibility = await witnessVisible(launcher);
    expect(selfVisibility.visible).toBe(false);
    expect(selfVisibility.pid).toBe(0);

    await releaseWitness(launcher);
    const afterRelease = await witnessVisible(observer, WITNESS_KEY, launcherPid);
    expect(afterRelease.visible).toBe(false);
    expect(afterRelease.pid).toBe(0);
  } finally {
    await safelyRelease(launcher);
    observer.release();
  }
});

// --- Admission gate contour (real PostgreSQL, runtime role connection). ---

proof('admission gate: exact database/role/schema plus live witness passes; failures are typed', { timeout: 120_000 }, async () => {
  const runtime = await requireFixture().runtime.connect();
  const launcher = await requireFixture().migrator.connect();
  try {
    await runtime.query('SET search_path TO foundation');
    const facts = await runtime.query<{ db: string; oid: number; role: string; schema: string }>(
      `SELECT current_database() AS db,
         (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname = current_database()) AS oid,
         current_user AS role,
         current_schema() AS schema`);
    const row = facts.rows[0];
    if (!row) { throw new Error('Missing runtime connection facts'); }

    await holdWitness(launcher);
    const launcherPid = await backendPid(launcher);
    const binding: AdmissionBinding = {
      database: row.db,
      databaseOid: row.oid,
      role: row.role,
      schema: row.schema,
      witnessKey: { classId: WITNESS_KEY.classId, objectId: WITNESS_KEY.objectId },
      profile: 'S1',
      witnessHolderPid: launcherPid,
      expected: {
        endpoint: '127.0.0.1:55432',
        issuerGeneration: 3,
        launchNonce: randomUUID(),
        consumerKind: 'TEST',
        instanceId: randomUUID(),
        channelId: randomUUID(),
        artifactDigest: 'a1'.repeat(32),
        historyManifestDigest: 'b2'.repeat(32),
        physicalContractDigest: 'c3'.repeat(32),
      },
    };
    const gate = new AdmissionGate({ binding, publicKeyPem });
    const now = new Date();

    // Correct database + OID + role + schema + live pinned witness: passes.
    await expect(gate.verifyConnection(runtime, now)).resolves.toBeUndefined();

    // Pid-bound gate: the witness must be held by the exact launcher backend
    // (the pid the verified proof binds), not by any other live holder.
    const pidBound = new AdmissionGate({
      binding, publicKeyPem,
    });
    await expect(pidBound.verifyConnection(runtime, now)).resolves.toBeUndefined();
    const wrongPidGate = new AdmissionGate({
      binding: { ...binding, witnessHolderPid: launcherPid === 1 ? 2 : launcherPid - 1 }, publicKeyPem,
    });
    const wrongPid = await wrongPidGate.verifyConnection(runtime, now)
      .then(() => 'resolved', (error: unknown) => (error instanceof AdmissionError ? error.code : 'other'));
    expect(wrongPid).toBe('WITNESS_MISMATCH');

    // Wrong role: the runtime connection is not the migrator the binding pins.
    const migratorGate = new AdmissionGate({
      binding: { ...binding, role: 'fixlevelup_migrator' }, publicKeyPem,
    });
    const wrongRole = await migratorGate.verifyConnection(runtime, now)
      .then(() => 'resolved', (error: unknown) => (error instanceof AdmissionError ? error.code : 'other'));
    expect(wrongRole).toBe('WRONG_ROLE');

    const wrongDatabaseGate = new AdmissionGate({
      binding: { ...binding, database: 'fixlevelup_other_database' }, publicKeyPem,
    });
    const wrongDatabase = await wrongDatabaseGate.verifyConnection(runtime, now)
      .then(() => 'resolved', (error: unknown) => (error instanceof AdmissionError ? error.code : 'other'));
    expect(wrongDatabase).toBe('WRONG_DATABASE');

    const wrongSchemaGate = new AdmissionGate({
      binding: { ...binding, schema: 'public' }, publicKeyPem,
    });
    const wrongSchema = await wrongSchemaGate.verifyConnection(runtime, now)
      .then(() => 'resolved', (error: unknown) => (error instanceof AdmissionError ? error.code : 'other'));
    expect(wrongSchema).toBe('WRONG_SCHEMA');

    // Witness gone: the same binding no longer admits the connection.
    await releaseWitness(launcher);
    const missingWitness = await gate.verifyConnection(runtime, now)
      .then(() => 'resolved', (error: unknown) => (error instanceof AdmissionError ? error.code : 'other'));
    expect(missingWitness).toBe('WITNESS_MISSING');

    // The proof token path: matching payload passes, mismatch/expiry reject.
    const payload = samplePayload({
      targetIdentity: {
        database: row.db, databaseOid: row.oid, runtimeRole: row.role, schema: row.schema,
      },
      issuerGeneration: binding.expected.issuerGeneration,
      launchNonce: binding.expected.launchNonce,
      consumerKind: binding.expected.consumerKind,
      instanceId: binding.expected.instanceId,
      channelId: binding.expected.channelId,
      endpoint: binding.expected.endpoint,
      artifactDigest: binding.expected.artifactDigest,
      historyManifestDigest: binding.expected.historyManifestDigest,
      physicalContractDigest: binding.expected.physicalContractDigest,
    });
    const token = signProof(payload, privateKeyPem);
    expect(gate.verifyProofToken(token, beforeExpiry(payload))).toEqual(payload);
    const otherBinding = new AdmissionGate({
      binding: { ...binding, schema: 'public' }, publicKeyPem,
    });
    expect(() => otherBinding.verifyProofToken(token, beforeExpiry(payload))).toThrow(AdmissionError);
  } finally {
    await runtime.query('RESET ALL').catch(() => undefined);
    await safelyRelease(launcher);
    runtime.release();
  }
});

/** Synchronous proof-token check: typed AdmissionError code or 'resolved'. */
function proofTokenCode(action: () => unknown): string {
  try {
    action();
    return 'resolved';
  } catch (error) {
    return error instanceof AdmissionError ? error.code : 'other';
  }
}

proof('admission gate: proof token expiry and signature map to typed errors', { timeout: 60_000 }, async () => {
  const runtime = await requireFixture().runtime.connect();
  try {
    const facts = await runtime.query<{ db: string; oid: number; role: string; schema: string }>(
      `SELECT current_database() AS db,
         (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname = current_database()) AS oid,
         current_user AS role,
         current_schema() AS schema`);
    const row = facts.rows[0];
    if (!row) { throw new Error('Missing runtime connection facts'); }
    const binding: AdmissionBinding = {
      database: row.db,
      databaseOid: row.oid,
      role: row.role,
      schema: row.schema,
      witnessKey: { classId: WITNESS_KEY.classId, objectId: WITNESS_KEY.objectId },
      profile: 'S1',
      witnessHolderPid: 424242,
      expected: {
        endpoint: '127.0.0.1:55432',
        issuerGeneration: 3,
        launchNonce: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        consumerKind: 'TEST',
        instanceId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        channelId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
        artifactDigest: 'a1'.repeat(32),
        historyManifestDigest: 'b2'.repeat(32),
        physicalContractDigest: 'c3'.repeat(32),
      },
    };
    const gate = new AdmissionGate({ binding, publicKeyPem });
    const payload = samplePayload({
      targetIdentity: {
        database: row.db, databaseOid: row.oid, runtimeRole: row.role, schema: row.schema,
      },
      issuerGeneration: 3,
      launchNonce: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      consumerKind: 'TEST',
      instanceId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      channelId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      endpoint: '127.0.0.1:55432',
      artifactDigest: 'a1'.repeat(32),
      historyManifestDigest: 'b2'.repeat(32),
      physicalContractDigest: 'c3'.repeat(32),
    });
    const expired = proofTokenCode(() => gate.verifyProofToken(signProof(payload, privateKeyPem),
      new Date(Date.parse(payload.expiresAt) + 1_000)));
    expect(expired).toBe('EXPIRED');

    // Signed by a different (unpinned) key: signature check fails closed.
    const stranger = generateKeyPairSync('ed25519');
    const strangerPem = stranger.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const badSignature = proofTokenCode(() => gate.verifyProofToken(signProof(payload, strangerPem), beforeExpiry(payload)));
    expect(badSignature).toBe('BAD_SIGNATURE');

    // Valid signature but a payload bound to another binding: PROOF_MISMATCH.
    const tampered = signProof({ ...payload, profile: 'S0' }, privateKeyPem);
    const mismatch = proofTokenCode(() => gate.verifyProofToken(tampered, beforeExpiry(payload)));
    expect(mismatch).toBe('PROOF_MISMATCH');

    // Each expected fact is mandatory: a signed token differing in exactly
    // one fact is refused as PROOF_MISMATCH (all nine + witness profile).
    const factOverrides: readonly Partial<LaunchProofPayload>[] = [
      { endpoint: '127.0.0.1:65532' },
      { issuerGeneration: 4 },
      { launchNonce: randomUUID() },
      { consumerKind: 'API' },
      { instanceId: randomUUID() },
      { channelId: randomUUID() },
      { artifactDigest: 'ff'.repeat(32) },
      { historyManifestDigest: 'ee'.repeat(32) },
      { physicalContractDigest: 'dd'.repeat(32) },
    ];
    for (const override of factOverrides) {
      const token = signProof({ ...payload, ...override }, privateKeyPem);
      const code = proofTokenCode(() => gate.verifyProofToken(token, beforeExpiry(payload)));
      expect(code, JSON.stringify(override)).toBe('PROOF_MISMATCH');
    }
  } finally {
    runtime.release();
  }
});

// --- Single-winner CAS contour (real PostgreSQL, two racing connections). ---

async function issueCasSample(issuer: PoolClient) {
  const payload = samplePayload({ consumerKind: 'WORKER' });
  const proofDigest = proofDigestOf(payload);
  const { issuerGeneration, launchNonce, consumerKind, instanceId, channelId } = payload;
  const binding = { consumerKind, instanceId, channelId };
  await issueProof(issuer, { issuerGeneration, launchNonce, proofDigest, ...binding,
    expiresAt: new Date(payload.expiresAt) });
  return { issuerGeneration, launchNonce, expectedDigest: proofDigest, binding };
}

proof('concurrent consume: both CAS backends wait, exactly one returns a confirmed win', { timeout: 45_000 }, async () => {
  const { launcher } = requireControl();
  const clients: PoolClient[] = [];
  const acquire = async (): Promise<PoolClient> => {
    const client = await launcher.connect();
    clients.push(client);
    return client;
  };
  let holder: PoolClient | undefined;
  let attempts: Promise<PromiseSettledResult<boolean>[]> | undefined;
  try {
    const observer = await acquire();
    const first = await acquire();
    const second = await acquire();
    const barrier = await acquire();
    holder = barrier;
    const input = await issueCasSample(observer);
    const [firstPid, secondPid, barrierPid] = await Promise.all([backendPid(first), backendPid(second), backendPid(barrier)]);
    await Promise.all([first, second].map((client) => client.query("SET statement_timeout = '12s'")));
    await barrier.query('BEGIN');
    await barrier.query(`SELECT 1 FROM launch_control.launch_proofs
      WHERE issuer_generation = $1 AND launch_nonce = $2 FOR UPDATE`, [input.issuerGeneration, input.launchNonce]);
    attempts = Promise.allSettled([consumeProof(first, input), consumeProof(second, input)]);

    const deadline = performance.now() + 5000;
    let bothQueued = false;
    do {
      const { rows } = await observer.query<{ first: number[]; second: number[] }>(
        'SELECT pg_blocking_pids($1) AS first, pg_blocking_pids($2) AS second', [firstPid, secondPid]);
      const row = rows[0];
      if (!row) { throw new Error('Missing blocker observation'); }
      // One racer may wait behind the other on the tuple lock; both paths
      // must lead to our barrier before it is released.
      bothQueued = (row.first.includes(barrierPid) && (row.second.includes(barrierPid) || row.second.includes(firstPid)))
        || (row.second.includes(barrierPid) && row.first.includes(secondPid));
      if (!bothQueued) { await delay(25); }
    } while (!bothQueued && performance.now() < deadline);
    expect(bothQueued).toBe(true);

    await barrier.query('ROLLBACK');
    holder = undefined;
    const results = await attempts;
    expect(results).toEqual(expect.arrayContaining([
      { status: 'fulfilled', value: true }, { status: 'fulfilled', value: false },
    ]));
    const state = await readRegistryState(observer, input.issuerGeneration, input.launchNonce);
    expect(state?.state).toBe('CONSUMED');
    expect(state?.consumed_at).toBeInstanceOf(Date);
    await expect(consumeProof(observer, input)).resolves.toBe(false);
  } finally {
    if (holder) {
      // Discarding the barrier socket also releases the open transaction.
      clients.splice(clients.indexOf(holder), 1);
      holder.release(true);
    }
    await attempts;
    for (const client of clients) { client.release(true); }
  }
});

for (const durable of [true, false]) {
  proof(`unconfirmed CAS COMMIT denies without retry (${durable ? 'committed' : 'aborted'} backend)`, { timeout: 30_000 }, async () => {
    const { launcher } = requireControl();
    const observer = await launcher.connect();
    try {
      const actor = await launcher.connect();
      try {
        expect(await backendPid(actor)).not.toBe(await backendPid(observer));
        const input = await issueCasSample(observer);
        const statements: string[] = [];
        const resolution = durable ? 'COMMIT' : 'ROLLBACK';
        let observedCommand: string | undefined;
        const query = async (text: string, values?: unknown[]): Promise<QueryResult> => {
          statements.push(text);
          if (text !== 'COMMIT') { return await actor.query(text, values); }
          // Resolve the actual PostgreSQL transaction, then withhold its
          // result from the registry caller at the driver boundary.
          observedCommand = (await actor.query(resolution)).command;
          throw new Error('Injected lost transaction response');
        };
        const uncertain: ControlStatement = { query: query as ControlStatement['query'] };
        await expect(consumeProof(uncertain, input)).rejects.toMatchObject({ code: 'COMMIT_UNKNOWN' });
        expect(observedCommand).toBe(resolution);
        expect(statements).toHaveLength(5);
        expect(statements.at(-1)).toBe('COMMIT');
        expect(statements).not.toContain('ROLLBACK');
        const state = await readRegistryState(observer, input.issuerGeneration, input.launchNonce);
        expect(state?.state).toBe(durable ? 'CONSUMED' : 'ISSUED');
        if (durable) { expect(state?.consumed_at).toBeInstanceOf(Date); }
        else { expect(state?.consumed_at).toBeNull(); }
      } finally { actor.release(true); }
    } finally { observer.release(); }
  });
}
