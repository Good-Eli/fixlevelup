/** P05 §7: separate real history preflight from the runtime physical-schema gate. */
import { randomUUID } from 'node:crypto';
import { Client } from 'pg';
import type { PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';
import { createApi } from '../src/bootstrap/factories.js';
import { verifyPhysicalProfile } from '../src/infrastructure/admission/physical-profile.js';
import { WITNESS_KEY } from '../src/infrastructure/admission/witness.js';
import { loadConfig } from '../src/runtime/config.js';
import { SafeLogger } from '../src/runtime/safe-logger.js';
import { hashPassword } from '../src/staff/password.js';
import { admitVerifiedTestInstance, openVerifiedControl, verifiedControlConfig } from './admission-fixture.js';
import { authFixtureMigrations, verifyOperatorMigrationHistory } from './auth-db-fixture.js';
import { createConfigurationFixture } from './configuration-fixture.js';
import type { ConfigurationFixture } from './configuration-fixture.js';
import { fixtureCredentials } from './owned-test-database.js';

const enabled = process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1'
  && process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1';
const caps = [{profile: 'S0', count: 21}, {profile: 'S1', count: 22},
  {profile: 'S2', count: 23}, {profile: 'S3', count: 24}] as const;
const origin = 'https://127.0.0.1:3100';
const runtimeTarget = (database: string) => ({ host: '127.0.0.1' as const, port: 55432,
  database, user: 'fixlevelup_runtime' as const, password: fixtureCredentials().runtime });

// Never mutate a pre-existing lab DB, even if it would pass operator preflight.
async function assertOwnedTarget(fixture: ConfigurationFixture, holder: PoolClient) {
  if (!enabled || !/^fixlevelup_configuration_test_[a-f0-9]{24}$/.test(fixture.database)) {
    throw new Error('History faults require a freshly owned synthetic configuration fixture');
  }
  const cluster = process.env['FIXLEVELUP_CLUSTER_NAME'] ?? '';
  expect(cluster).toMatch(/^fixlevelup_p05s4_lab_[a-z0-9_]{1,40}$/);
  const { rows } = await holder.query<{ valid: boolean }>(`SELECT current_database()=$1
    AND current_user='fixlevelup_migrator' AND session_user=current_user
    AND current_setting('cluster_name')=$2 AND current_setting('server_version_num')='180007'
    AND host(inet_server_addr())='127.0.0.1' AND inet_server_port()=55432 AND NOT pg_is_in_recovery()
    AND EXISTS (SELECT FROM pg_catalog.pg_database WHERE datname=$1 AND datdba='fixlevelup_migrator'::regrole)
    AND NOT EXISTS (SELECT FROM pg_catalog.pg_database WHERE datname='fixlevelup_dev') AS valid`,
  [fixture.database, cluster]);
  expect(rows).toEqual([{ valid: true }]);
}

type HistoryRow = { id: string; migration_name: string; checksum: string; finished_at: string | null;
  rolled_back_at: string | null; applied_steps_count: number; logs: string | null };

// Server-side JSON keeps timestamps at PG precision through capture/restore.
const historyRows = async (holder: PoolClient) => (await holder.query<{ data: HistoryRow }>(`
  SELECT to_jsonb(h) AS data FROM foundation._prisma_migrations h ORDER BY migration_name,id`)).rows.map(row => row.data);

// Same physical DB/OIDs throughout. Snapshot catalog facts, not stats, tuple counts or filenodes.
async function catalogSnapshot(holder: PoolClient) {
  return (await holder.query<{ digest: string }>(`WITH rels AS (
    SELECT oid,relname,relowner,relkind,relpersistence,relrowsecurity,relforcerowsecurity,relacl
    FROM pg_catalog.pg_class WHERE relnamespace='foundation'::regnamespace
  ), facts(kind,id,shape) AS (
    SELECT 'rel',r.oid::text,to_jsonb(r) FROM rels r
    UNION ALL SELECT 'schema',n.oid::text,to_jsonb(n) FROM pg_catalog.pg_namespace n WHERE n.nspname='foundation'
    UNION ALL SELECT 'column',a.attrelid::text||':'||a.attnum::text,to_jsonb(a)
      FROM pg_catalog.pg_attribute a JOIN rels r ON r.oid=a.attrelid
    UNION ALL SELECT 'default',d.oid::text,to_jsonb(d) FROM pg_catalog.pg_attrdef d JOIN rels r ON r.oid=d.adrelid
    UNION ALL SELECT 'constraint',k.oid::text,to_jsonb(k) FROM pg_catalog.pg_constraint k
      WHERE k.connamespace='foundation'::regnamespace
    UNION ALL SELECT 'index',i.indexrelid::text,to_jsonb(i) FROM pg_catalog.pg_index i JOIN rels r ON r.oid=i.indrelid
    UNION ALL SELECT 'trigger',g.oid::text,to_jsonb(g) FROM pg_catalog.pg_trigger g JOIN rels r ON r.oid=g.tgrelid
    UNION ALL SELECT 'routine',p.oid::text,to_jsonb(p) FROM pg_catalog.pg_proc p WHERE p.pronamespace='foundation'::regnamespace
    UNION ALL SELECT 'policy',p.oid::text,to_jsonb(p) FROM pg_catalog.pg_policy p JOIN rels r ON r.oid=p.polrelid
  ) SELECT encode(sha256(convert_to(jsonb_agg(jsonb_build_array(kind,id,shape)
      ORDER BY kind COLLATE "C",id COLLATE "C")::text,'UTF8')),'hex') AS digest FROM facts`)).rows[0]?.digest;
}

const registryRows = async (control: Client) => (await control.query<{ state: string; consumed_at: Date | null;
  launch_nonce: string; proof_digest: string; consumer_kind: string }>(`SELECT launch_nonce,proof_digest,consumer_kind,state,consumed_at
  FROM launch_control.launch_proofs ORDER BY issuer_generation,launch_nonce`)).rows;

const witnessCount = async (holder: PoolClient) => (await holder.query<{ n: number }>(`SELECT count(*)::int AS n
  FROM pg_catalog.pg_locks WHERE locktype='advisory' AND granted AND classid=$1::int::oid AND objsubid=2
  AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())`, [WITNESS_KEY.classId])).rows[0]?.n;

async function businessSnapshot(holder: PoolClient) {
  return (await holder.query<{ data: unknown }>(`SELECT jsonb_build_object(
    'sessions',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.id),'[]') FROM foundation.web_sessions s),
    'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY o.id),'[]') FROM foundation.outbox_events o),
    'audit',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY a.id),'[]') FROM foundation.audit_logs a),
    'permissions',(SELECT jsonb_agg(to_jsonb(p) ORDER BY p.code) FROM foundation.permissions p)
  ) AS data`)).rows[0]?.data;
}

async function physicalProfileMatches(fixture: ConfigurationFixture, profile: (typeof caps)[number]['profile']) {
  const runtime = await fixture.runtime.connect();
  try { return await verifyPhysicalProfile(runtime, fixture, profile); }
  finally { runtime.release(); }
}

const insertHistory = (holder: PoolClient, row: HistoryRow) => holder.query(`INSERT INTO foundation._prisma_migrations
  SELECT h.* FROM jsonb_populate_record(NULL::foundation._prisma_migrations,$1::jsonb) h`, [JSON.stringify(row)]);

// Mutate only one captured row or add exactly one new record. Each transform is independent.
const faults: readonly { name: string; change: (victim: HistoryRow, other: HistoryRow) => HistoryRow | undefined }[] = [
  {name: 'missing row', change: () => undefined},
  {name: 'extra completed duplicate', change: victim => ({...victim, id: randomUUID()})},
  {name: 'same-count duplicate replaces expected row', change: (victim, other) => ({...other, id: victim.id})},
  {name: 'extra completed unknown name', change: victim => ({...victim, id: randomUUID(), migration_name: '20990101000100_fixture_unknown'})},
  {name: 'same-count unknown name replaces expected row', change: victim => ({...victim, migration_name: '20990101000100_fixture_unknown'})},
  {name: 'wrong checksum only', change: victim => ({...victim,
    checksum: `${victim.checksum[0] === 'a' ? 'b' : 'a'}${victim.checksum.slice(1)}`})},
  {name: 'nonfinished only', change: victim => ({...victim, finished_at: null})},
  {name: 'pending', change: victim => ({...victim, finished_at: null, applied_steps_count: 0})},
  {name: 'failed', change: victim => ({...victim, finished_at: null, applied_steps_count: 0, logs: 'synthetic migration failure'})},
  {name: 'rolled back only', change: victim => ({...victim, rolled_back_at: victim.finished_at})},
  {name: 'wrong applied step count only', change: victim => ({...victim, applied_steps_count: 0})},
];

async function tryApi(fixture: ConfigurationFixture, expectedMigrations: readonly string[], onAuthorized: () => void) {
  const handle = await admitVerifiedTestInstance(fixture.migrator, fixture.database, { consumerKind: 'API', expectedMigrations });
  try {
    onAuthorized();
    const app = await createApi(loadConfig({ NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0' }),
      new SafeLogger('api'), runtimeTarget(fixture.database),
      { origin, csrfSecret: 'c'.repeat(64), throttleSecret: 'd'.repeat(64) }, undefined, handle.authorization);
    return { app, handle };
  } catch (error) { await handle.release(); throw error; }
}

// Negative calls share the actual launch-to-factory continuation with the positive
// control. The spy delegates to the real driver and counts only app-runtime connects.
async function expectRefusal(fixture: ConfigurationFixture, expectedMigrations: readonly string[], reason: string,
  runtimeConnections: number, label: string) {
  const connect = vi.spyOn(Client.prototype, 'connect');
  const authorized = vi.fn();
  try {
    const result = tryApi(fixture, expectedMigrations, authorized).then(async ({ app, handle }) => {
      try { await app.close(); } finally { await handle.release(); }
    });
    await expect(result, label).rejects.toMatchObject({ message: reason });
    expect(authorized, label).not.toHaveBeenCalled();
    expect(connect.mock.contexts.filter(c => c instanceof Client && c.user === 'fixlevelup_runtime'
      && c.database === fixture.database), label).toHaveLength(runtimeConnections);
  } finally { connect.mockRestore(); }
}

describe.runIf(enabled)('P05 §7 migration history integrity', () => {
  it.each(caps)('$profile exact catalog rejects malformed history before issue and accepts restored history',
    {timeout: 180_000}, async ({ profile, count }) => {
      const capBefore = authFixtureMigrations[count];
      const expected = authFixtureMigrations.slice(0, count);
      const fixture = await createConfigurationFixture(capBefore === undefined ? {} : { capBefore });
      try {
        const holder = await fixture.migrator.connect();
        try {
          await assertOwnedTarget(fixture, holder);
          const control = await openVerifiedControl(verifiedControlConfig(fixture.database));
          try {
            const before = await historyRows(holder);
            const physicalBefore = await catalogSnapshot(holder);
            const history = await verifyOperatorMigrationHistory(holder, expected);
            const registryBefore = await registryRows(control);
            const login = `history-${randomUUID()}`;
            const password = `Synthetic-History-${randomUUID()}!`;
            await holder.query('UPDATE foundation.staff_web_credentials SET login=$2,password_hash=$3 WHERE staff_id=$1',
              [fixture.reviewer, login, await hashPassword(password)]);
            const effectsBefore = await businessSnapshot(holder);
            expect(before.map(row => row.migration_name)).toEqual(expected);
            expect(physicalBefore).toMatch(/^[a-f0-9]{64}$/);
            expect(history.ok).toBe(true);
            expect(history.historyManifestDigest).toMatch(/^[a-f0-9]{64}$/);
            expect(await physicalProfileMatches(fixture, profile)).toBe(true);
            await expect(fixture.runtime.query('SELECT migration_name FROM foundation._prisma_migrations'))
              .rejects.toMatchObject({code: '42501'});
            await expect(fixture.runtime.query('SET ROLE fixlevelup_migrator')).rejects.toMatchObject({code: '42501'});
            expect(await witnessCount(holder)).toBe(0);

            const victim = before.at(-1);
            const other = before[0];
            if (!victim || !other || victim.id === other.id) { throw new Error('Expected a complete migration chain'); }
            for (const {name, change} of faults) {
              const changed = change(victim, other);
              const replacing = changed === undefined || changed.id === victim.id;
              // Committed changes, not a local uncommitted view of the history. The
              // verified launcher independently checks out a different connection.
              if (replacing) { expect((await holder.query('DELETE FROM foundation._prisma_migrations WHERE id=$1', [victim.id])).rowCount, name).toBe(1); }
              if (changed) { expect((await insertHistory(holder, changed)).rowCount, name).toBe(1); }
              try {
                const corrupt = await historyRows(holder);
                expect(corrupt, name).not.toEqual(before);
                expect(corrupt.find(row => row.id === (changed?.id ?? victim.id)), name).toEqual(changed);
                expect(corrupt.filter(row => row.id !== (changed?.id ?? victim.id)), name)
                  .toEqual(before.filter(row => !replacing || row.id !== victim.id));
                // Prove causality: the runtime allowlist still accepts the exact profile.
                expect(await physicalProfileMatches(fixture, profile), name).toBe(true);
                expect(await verifyOperatorMigrationHistory(holder, expected), name).toEqual({ok: false, historyManifestDigest: ''});
                await expectRefusal(fixture, expected, 'Operator preflight history verification failed', 0, name);
                expect(await registryRows(control), name).toEqual(registryBefore); // neither ISSUED nor CONSUMED
                expect(await witnessCount(holder), name).toBe(0);
                expect(await businessSnapshot(holder), name).toEqual(effectsBefore);
                expect(await catalogSnapshot(holder), name).toBe(physicalBefore);
                expect(await historyRows(holder), name).toEqual(corrupt); // preflight never repairs/re-applies
              } finally {
                if (changed) { expect((await holder.query('DELETE FROM foundation._prisma_migrations WHERE id=$1', [changed.id])).rowCount, name).toBe(1); }
                if (replacing) { expect((await insertHistory(holder, victim)).rowCount, name).toBe(1); }
              }
              expect(await historyRows(holder), name).toEqual(before);
              expect(await verifyOperatorMigrationHistory(holder, expected), name).toEqual(history);
            }

            // Inverse control: valid history with physical drift reaches the runtime
            // metadata gate. It can issue a fresh row but no handshake can consume it.
            if (profile === 'S3') {
              await holder.query('ALTER TABLE foundation.form_browser_groups DISABLE TRIGGER form_browser_groups_guard');
              try {
                expect(await verifyOperatorMigrationHistory(holder, expected)).toEqual(history);
                expect(await historyRows(holder)).toEqual(before);
                expect(await physicalProfileMatches(fixture, profile)).toBe(false);
                const drifted = await catalogSnapshot(holder);
                expect(drifted).not.toBe(physicalBefore);
                await expectRefusal(fixture, expected, 'ADMISSION_DENIED', 1, 'valid history + disabled S2 guard on S3');
                const old = new Set(registryBefore.map(row => row.launch_nonce));
                expect((await registryRows(control)).filter(row => !old.has(row.launch_nonce)))
                  .toEqual([expect.objectContaining({state: 'ISSUED', consumed_at: null, consumer_kind: 'API'})]);
                expect(await witnessCount(holder)).toBe(0);
                expect(await businessSnapshot(holder)).toEqual(effectsBefore);
                expect(await catalogSnapshot(holder)).toBe(drifted);
              } finally { await holder.query('ALTER TABLE foundation.form_browser_groups ENABLE TRIGGER form_browser_groups_guard'); }
            }

            // Fresh proof after restoring exactly our own fixture fault. Actual
            // approval/completion and readiness are required; auth login writes an
            // observable session. Never reuse the drifted (still ISSUED) proof.
            const beforePositive = await registryRows(control);
            const authorized = vi.fn();
            const { app, handle } = await tryApi(fixture, expected, authorized);
            try {
              expect(authorized).toHaveBeenCalledTimes(1);
              expect(handle.admission.binding.profile).toBe(profile);
              expect(handle.admission.payload.historyManifestDigest).toBe(history.historyManifestDigest);
              expect(await witnessCount(holder)).toBe(1);
              const nonce = handle.admission.binding.expected.launchNonce;
              const after = await registryRows(control);
              const admitted = after.find(row => row.launch_nonce === nonce);
              expect(admitted).toMatchObject({ state: 'CONSUMED', proof_digest: handle.admission.proofDigest });
              expect(admitted?.consumed_at).toBeInstanceOf(Date);
              expect(after.filter(row => row.launch_nonce !== nonce)).toEqual(beforePositive);
              const url = await app.getUrl();
              expect((await fetch(`${url}/health/ready`)).status).toBe(200);
              const freshLogin = await fetch(`${url}/api/v1/auth/login`, { method: 'POST', headers: { origin,
                'content-type': 'application/json', 'x-csrf-token': 'login' }, body: JSON.stringify({login, password}) });
              expect(freshLogin.status).toBe(200);
              expect((await holder.query('SELECT id FROM foundation.web_sessions WHERE staff_id=$1', [fixture.reviewer])).rowCount).toBe(1);
              expect(await catalogSnapshot(holder)).toBe(physicalBefore);
              expect(await historyRows(holder)).toEqual(before);
            } finally { try { await app.close(); } finally { await handle.release(); } }
            expect(await witnessCount(holder)).toBe(0);
          } finally { await control.end(); }
        } finally { holder.release(); }
      } finally { await fixture.close(); }
    });
});
