import { argon2, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Client, Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { bootstrapFirstAdmin } from '../src/staff/bootstrap.js';
import { insertWebStaff, migrateAuthFixture, reassignFixture, spareAdmin } from './auth-db-fixture.js';

// Opt in only on the documented local development PostgreSQL instance. Each run
// creates three empty, randomly named databases; it never writes to dev tables.
// Each database is dropped by this run's own teardown (only names this run
// created and that match the strict disposable-name pattern).
const integration = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1' ? describe : describe.skip;
const root = resolve(import.meta.dirname, '../../..');
const syntheticPassword = 'Synthetic-Password-Canary-2026!';
const login = `bootstrap-${randomBytes(12).toString('hex')}`;

function required<T>(value: T | undefined): T {
  if (value === undefined) { throw new Error('Missing test fixture value'); }
  return value;
}

describe('bootstrap password UTF-8 byte limits', () => {
  it.each([
    { password: 'a'.repeat(15), bytes: 15, valid: false },
    { password: 'a'.repeat(16), bytes: 16, valid: true },
    { password: 'a'.repeat(1024), bytes: 1024, valid: true },
    { password: 'a'.repeat(1025), bytes: 1025, valid: false },
    { password: 'é'.repeat(7) + 'a', bytes: 15, valid: false },
    { password: 'é'.repeat(8), bytes: 16, valid: true },
    { password: 'é'.repeat(512), bytes: 1024, valid: true },
    { password: 'é'.repeat(512) + 'a', bytes: 1025, valid: false },
  ])('validates $bytes UTF-8 bytes (valid: $valid)', async ({ password, bytes, valid }) => {
    expect(Buffer.byteLength(password, 'utf8')).toBe(bytes);
    const connect = vi.fn().mockRejectedValue(new Error('Synthetic connection failure'));
    await expect(bootstrapFirstAdmin({ connect }, { login: 'synthetic-user', password }))
      .rejects.toMatchObject({ code: valid ? 'FAILED' : 'INVALID_INPUT' });
    expect(connect).toHaveBeenCalledTimes(valid ? 1 : 0);
  });
});

describe('compiled bootstrap CLI', () => {
  it('rejects non-TTY input without echoing credentials', () => {
    const result = spawnSync(process.execPath, [resolve(root, 'apps/api/dist/bootstrap/staff-bootstrap.js')], {
      cwd: root, env: { ...process.env, DB_PASSWORD: syntheticPassword }, encoding: 'utf8', input: `${login}\n${syntheticPassword}\n${syntheticPassword}\n`, timeout: 10000,
    });
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(1);
    expect(result.stdout).toBe('');
    expect(result.stderr).toBe('Staff bootstrap failed.\n');
    expect(result.stdout + result.stderr).not.toContain(syntheticPassword);
    expect(result.stdout + result.stderr).not.toContain(login);
  });
});

async function verifyHash(encoded: string, password: string): Promise<boolean> {
  const parts = encoded.split('$');
  expect(parts.slice(0, 4)).toEqual(['', 'argon2id', 'v=19', 'm=19456,t=2,p=1']);
  expect(parts).toHaveLength(6);
  const salt = Buffer.from(required(parts[4]), 'base64');
  const expected = Buffer.from(required(parts[5]), 'base64');
  expect(salt).toHaveLength(16);
  expect(expected).toHaveLength(32);
  const actual = await new Promise<Buffer>((resolveHash, reject) => {
    argon2('argon2id', { message: password, nonce: salt, parallelism: 1, tagLength: 32, memory: 19456, passes: 2 },
      (error, result) => { if (error) { reject(error); } else { resolveHash(result); } });
  });
  return timingSafeEqual(actual, expected);
}

integration('first-admin bootstrap against isolated PostgreSQL databases', () => {
  let admin: Client | undefined;
  const pools: Pool[] = [];
  const fixtures: Client[] = [];
  const runtimePools: Pool[] = [];
  /** Database names created by THIS run (pushed exactly when CREATE succeeded). */
  const createdNames: string[] = [];
  let tornDown = false;

  /** Ownership proof for the teardown drop, consumed exactly once: each pushed name
   * is a CREATE that succeeded in this run AND matches the strict disposable pattern. */
  const takeOwnedDatabases = (): string[] => {
    return createdNames.splice(0).filter((item) => /^fixlevelup_bootstrap_test_[a-f0-9]{24}$/.test(item));
  };

  /** The afterAll teardown, exactly once: this run's pools/clients down first, then
   * the drop of exactly the databases this run created. A second call is a no-op. */
  async function teardown(): Promise<void> {
    if (tornDown) { return; }
    tornDown = true;
    const owned = takeOwnedDatabases();
    try {
      await Promise.all([...pools, ...runtimePools].map((pool) => pool.end()));
      await Promise.all(fixtures.map((fixture) => fixture.end()));
    } finally {
      try {
        for (const name of owned) {
          await admin?.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
        }
      } finally { await admin?.end(); }
    }
  }

  beforeAll(async () => {
    const adminEnv = readFileSync(resolve(root, 'infra/dev-postgres/.env'), 'utf8');
    const runtimeEnv = readFileSync(resolve(root, 'packages/database-tooling/.env'), 'utf8');
    const adminPassword = /^POSTGRES_PASSWORD=([a-f0-9]{64})$/m.exec(adminEnv)?.[1];
    const runtimePassword = /^FIXLEVELUP_RUNTIME_PASSWORD=([a-f0-9]{64})$/m.exec(runtimeEnv)?.[1];
    const migratorPassword = /^FIXLEVELUP_MIGRATOR_PASSWORD=([a-f0-9]{64})$/m.exec(runtimeEnv)?.[1];
    if (!adminPassword || !runtimePassword || !migratorPassword) { throw new Error('Local isolated PostgreSQL test credentials are required'); }
    const connection = { host: '127.0.0.1', port: 55432 };
    admin = new Client({ ...connection, database: 'postgres', user: 'fixlevelup_dev', password: adminPassword });
    await admin.connect();
    try {
      for (let i = 0; i < 3; i++) {
        // The name consists solely of a fixed prefix and cryptographic random hex.
        const name = `fixlevelup_bootstrap_test_${randomBytes(12).toString('hex')}`;
        await admin.query(`CREATE DATABASE "${name}" OWNER fixlevelup_migrator TEMPLATE template0`);
        // CREATE is the reuse guard: an existing name is a hard error, so a successful
        // CREATE proves this run owns the disposable database (the name gates the drop).
        createdNames.push(name);
        await admin.query(`REVOKE ALL ON DATABASE "${name}" FROM PUBLIC`);
        await admin.query(`GRANT CONNECT ON DATABASE "${name}" TO fixlevelup_runtime`);
        const fixture = new Client({ ...connection, database: name, user: 'fixlevelup_migrator', password: migratorPassword });
        fixtures.push(fixture);
        await fixture.connect();
        await migrateAuthFixture(fixture, name);
        pools.push(new Pool({ ...connection, application_name: 'fixture-bootstrap', database: name, user: 'fixlevelup_migrator', password: migratorPassword }));
        runtimePools.push(new Pool({ ...connection, database: name, user: 'fixlevelup_runtime', password: runtimePassword }));
      }
    } catch (error) {
      // Provisioning failed after CREATE: run the same lifecycle cleanup before rethrowing.
      await teardown().catch(() => undefined);
      throw error;
    }
  }, 30000);

  afterAll(teardown);

  it('rolls back staff and credentials when the audit insert fails, without logging secrets', async () => {
    const logs = [vi.spyOn(console, 'log'), vi.spyOn(console, 'warn'), vi.spyOn(console, 'error')];
    // A fixture-local constraint forces a real PostgreSQL error at the last write.
    await required(fixtures[0]).query("ALTER TABLE foundation.audit_logs ADD CONSTRAINT fixture_reject_bootstrap CHECK (operation <> 'STAFF_BOOTSTRAP')");
    try {
      const failure = await bootstrapFirstAdmin(required(pools[0]), { login, password: syntheticPassword }).catch((error: unknown) => error);
      expect(failure).toMatchObject({ code: 'FAILED', message: 'Staff bootstrap failed' });
      expect(JSON.stringify(failure)).not.toContain(syntheticPassword);
      for (const table of ['staff', 'staff_role_assignments', 'staff_web_credentials', 'staff_bootstrap_marker', 'geography_bootstrap_permissions', 'p03_bootstrap_permissions', 'audit_logs']) {
        const result = await required(fixtures[0]).query<{ count: number }>(`SELECT count(*)::int AS count FROM foundation.${table}`);
        expect(result.rows[0]?.count).toBe(0);
      }
      expect(JSON.stringify(logs.flatMap((spy) => spy.mock.calls))).not.toContain(syntheticPassword);
    } finally {
      for (const spy of logs) { spy.mockRestore(); }
      await required(fixtures[0]).query('ALTER TABLE foundation.audit_logs DROP CONSTRAINT fixture_reject_bootstrap');
    }
  });

  it('serializes concurrent first attempts and blocks all later attempts even for an inactive administrator', async () => {
    const attempts = await Promise.allSettled(Array.from({ length: 6 }, (_, i) =>
      bootstrapFirstAdmin(required(pools[0]), { login: `${login}-${String(i)}`, password: syntheticPassword })));
    const successes = attempts.filter((attempt) => attempt.status === 'fulfilled');
    const failures = attempts.filter((attempt) => attempt.status === 'rejected');
    expect(successes).toHaveLength(1);
    expect(failures).toHaveLength(5);
    for (const failure of failures) {
      expect(failure.reason).toMatchObject({ code: 'ALREADY_INITIALIZED' });
    }
    const winner = successes[0];
    if (!winner) { throw new Error('Expected one bootstrap winner'); }
    const staff = await required(fixtures[0]).query('SELECT id, role, employment_state, auth_version FROM foundation.staff');
    expect(staff.rows).toEqual([{ id: winner.value.staffId, role: 'ADMIN', employment_state: 'ACTIVE', auth_version: 0 }]);
    const assignments = await required(fixtures[0]).query<{ role_id: string; code: string }>(
      `SELECT a.role_id,r.code FROM foundation.staff_role_assignments a JOIN foundation.roles r ON r.id=a.role_id
       WHERE a.staff_id=$1 AND a.revoked_at IS NULL AND r.role_type='SYSTEM' AND r.status='ACTIVE'`, [winner.value.staffId]);
    expect(assignments.rows).toHaveLength(1);
    expect(assignments.rows[0]?.code).toBe('ADMIN');
    const audit = await required(fixtures[0]).query("SELECT operation, correlation_id, details FROM foundation.audit_logs WHERE operation='STAFF_BOOTSTRAP'");
    expect(audit.rows).toEqual([{ operation: 'STAFF_BOOTSTRAP', correlation_id: winner.value.correlationId, details: { staffId: winner.value.staffId, roleId: required(assignments.rows[0]).role_id } }]);
    const spare = await spareAdmin(required(fixtures[0]), winner.value.staffId);
    await required(fixtures[0]).query("UPDATE foundation.staff SET employment_state = 'INACTIVE' WHERE id = $1", [winner.value.staffId]);
    await expect(bootstrapFirstAdmin(required(pools[0]), { login: `${login}-later`, password: syntheticPassword }))
      .rejects.toMatchObject({ code: 'ALREADY_INITIALIZED' });
    expect((await required(fixtures[0]).query<{ count: number }>('SELECT count(*)::int AS count FROM foundation.staff')).rows[0]?.count).toBe(2);
    expect((await required(fixtures[0]).query<{ count: number }>('SELECT count(*)::int AS count FROM foundation.staff_web_credentials')).rows[0]?.count).toBe(2);
    expect((await required(fixtures[0]).query<{ operation:string }>('SELECT operation FROM foundation.audit_logs ORDER BY operation')).rows.map(row => row.operation))
      .toEqual(['GEOGRAPHY_BOOTSTRAP_PERMISSIONS','P03_BOOTSTRAP_PERMISSIONS','STAFF_BOOTSTRAP']);
    expect((await required(fixtures[0]).query('SELECT assignment_id FROM foundation.geography_bootstrap_permissions WHERE revoked_at IS NULL')).rowCount).toBe(5);
    const originalAssignment = required((await required(fixtures[0]).query<{ id: string }>(
      'SELECT id FROM foundation.staff_role_assignments WHERE staff_id=$1 AND revoked_at IS NULL', [winner.value.staffId])).rows[0]).id;
    const personal = await required(fixtures[0]).query<{ assignment_id: string; permission_code: string; row_version: number }>(
      'SELECT assignment_id,permission_code,row_version FROM foundation.p03_bootstrap_permissions WHERE revoked_at IS NULL ORDER BY permission_code');
    expect(personal.rows).toEqual([
      'content.manage', 'content.publish', 'content.read', 'legal.manage', 'legal.read',
      'references.callbackinterval.manage', 'references.callbackinterval.read', 'references.cancelreason.manage', 'references.cancelreason.read',
      'references.declinereason.manage', 'references.declinereason.read', 'references.paymentmethod.manage', 'references.paymentmethod.read',
      'references.requestsource.manage', 'references.requestsource.read', 'settings.fullread', 'settings.manage', 'settings.readiness.read',
    ].map(permission_code => ({ assignment_id: originalAssignment, permission_code, row_version: 1 })));
    expect((await required(fixtures[0]).query(`SELECT permission_code FROM foundation.role_permissions
      WHERE permission_code IN (SELECT permission_code FROM foundation.p03_bootstrap_permissions) AND enabled`)).rows).toEqual([]);
    expect((await required(fixtures[0]).query('SELECT id, staff_id FROM foundation.staff_bootstrap_marker')).rows)
      .toEqual([{ id: 1, staff_id: winner.value.staffId }]);
    // The durable marker still blocks replacement after the former admin loses the role.
    await reassignFixture(required(fixtures[0]), winner.value.staffId, 'MANAGER', spare);
    await expect(bootstrapFirstAdmin(required(pools[0]), { login: `${login}-role-changed`, password: syntheticPassword }))
      .rejects.toMatchObject({ code: 'ALREADY_INITIALIZED' });
    expect((await required(fixtures[0]).query<{ count: number }>('SELECT count(*)::int AS count FROM foundation.staff')).rows[0]?.count).toBe(2);
    expect((await required(fixtures[0]).query<{ count: number }>('SELECT count(*)::int AS count FROM foundation.staff_bootstrap_marker')).rows[0]?.count).toBe(1);
  }, 30000);

  it('does not wait on a compatible ROW EXCLUSIVE writer lock when no advisory lock is held', async () => {
    const writer = required(fixtures[0]);
    await writer.query('BEGIN');
    let pending: Promise<unknown> | undefined;
    let deadline: ReturnType<typeof setTimeout> | undefined;
    try {
      await writer.query('LOCK TABLE foundation.staff IN ROW EXCLUSIVE MODE');
      pending = bootstrapFirstAdmin(required(pools[0]), { login: `${login}-compatible-lock`, password: syntheticPassword })
        .then((value): unknown => value, (error: unknown): unknown => error);
      const result = await Promise.race([
        pending,
        new Promise<never>((_, reject) => {
          deadline = setTimeout(() => { reject(new Error('Bootstrap failed to finish before writer released its table lock')); }, 8000);
        }),
      ]);
      expect(result).toMatchObject({ code: 'ALREADY_INITIALIZED' });
    } finally {
      clearTimeout(deadline);
      await writer.query('ROLLBACK');
      await pending;
    }
  }, 30000);

  it('waits for an independent uncommitted admin insertion and rejects after commit', async () => {
    const writer = required(fixtures[2]);
    const observer = required(runtimePools[2]);
    const blocker = required((await writer.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]).pid;
    await writer.query('BEGIN');
    let pending: Promise<unknown> | undefined;
    try {
      const id = await insertWebStaff(writer);
      pending = bootstrapFirstAdmin(required(pools[2]), { login: `${login}-race`, password: syntheticPassword })
        .then((value): unknown => value, (error: unknown): unknown => error);
      // The independent INSERT holds the advisory lock. Observe the specific writer/contender edge.
      const deadline = Date.now() + 10000;
      let waiting = false;
      while (Date.now() < deadline && !waiting) {
        const locks = await observer.query<{ waiting: boolean }>(`SELECT EXISTS (SELECT FROM pg_stat_activity WHERE datname=current_database() AND application_name='fixture-bootstrap'
          AND $1=ANY(pg_blocking_pids(pid))) AS waiting`, [blocker]);
        waiting = locks.rows[0]?.waiting === true;
        if (!waiting) { await new Promise<void>((resolveDelay) => { setTimeout(resolveDelay, 25); }); }
      }
      expect(waiting).toBe(true);
      await writer.query('COMMIT');
      expect(await pending).toMatchObject({ code: 'ALREADY_INITIALIZED' });
      expect((await writer.query('SELECT id FROM foundation.staff')).rows).toEqual([{ id }]);
      expect((await writer.query('SELECT staff_id FROM foundation.staff_web_credentials')).rows).toEqual([{ staff_id: id }]);
      expect((await writer.query('SELECT staff_id FROM foundation.staff_role_assignments')).rows).toEqual([{ staff_id: id }]);
      for (const table of ['staff_bootstrap_marker', 'audit_logs']) {
        expect((await writer.query<{ count: number }>(`SELECT count(*)::int AS count FROM foundation.${table}`)).rows[0]?.count).toBe(0);
      }
    } finally {
      await writer.query('ROLLBACK');
      await pending;
    }
  }, 30000);

  it('stores verifiable Argon2id hashes with independently random salts', async () => {
    await bootstrapFirstAdmin(required(pools[1]), { login: `${login}-second`, password: syntheticPassword });
    const first = required((await required(fixtures[0]).query<{ password_hash: string }>('SELECT c.password_hash FROM foundation.staff_web_credentials c JOIN foundation.staff_bootstrap_marker b ON b.staff_id=c.staff_id')).rows[0]).password_hash;
    const second = required((await required(fixtures[1]).query<{ password_hash: string }>('SELECT c.password_hash FROM foundation.staff_web_credentials c JOIN foundation.staff_bootstrap_marker b ON b.staff_id=c.staff_id')).rows[0]).password_hash;
    expect(first).not.toBe(syntheticPassword);
    expect(first).not.toBe(second);
    expect(first.split('$')[4]).not.toBe(second.split('$')[4]);
    expect(await verifyHash(first, syntheticPassword)).toBe(true);
    expect(await verifyHash(second, syntheticPassword)).toBe(true);
    expect(await verifyHash(first, `${syntheticPassword}-wrong`)).toBe(false);
    const audit = await required(fixtures[1]).query('SELECT row_to_json(a)::text AS data FROM foundation.audit_logs a');
    expect(JSON.stringify(audit.rows)).not.toContain(syntheticPassword);
    expect(JSON.stringify(audit.rows)).not.toContain(second);
  }, 30000);

  it('enforces database checks and limits runtime table privileges', async () => {
    const db = required(fixtures[1]);
    for (const [role, state, version] of [['OWNER', 'ACTIVE', 0], ['ADMIN', 'UNKNOWN', 0], ['ADMIN', 'ACTIVE', -1]] as const) {
      await expect(db.query('INSERT INTO foundation.staff (id, role, employment_state, auth_version) VALUES ($1,$2,$3,$4)',
        [randomUUID(), role, state, version])).rejects.toMatchObject({ code: '23514' });
    }
    // Reuse a valid fixture hash so the credential format CHECK cannot mask the missing staff FK.
    await expect(db.query(`INSERT INTO foundation.staff_web_credentials (staff_id, login, password_hash)
      SELECT $1,$2,c.password_hash FROM foundation.staff_web_credentials c JOIN foundation.staff_bootstrap_marker b ON b.staff_id=c.staff_id`,
      [randomUUID(), 'missing-staff'])).rejects.toMatchObject({ code: '23503', constraint: 'staff_web_credentials_staff_id_fkey' });
    for (const table of ['staff', 'staff_web_credentials', 'staff_bootstrap_marker']) {
      for (const privilege of ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']) {
        const privileges = await db.query<{ allowed: boolean }>("SELECT has_table_privilege('fixlevelup_runtime', $1, $2) AS allowed", [`foundation.${table}`, privilege]);
        expect(privileges.rows[0]?.allowed).toBe(false);
      }
      if (table === 'staff_bootstrap_marker') {
        for (const privilege of ['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']) {
          const acl = await db.query<{ allowed: boolean }>("SELECT has_any_column_privilege('fixlevelup_runtime',$1,$2) AS allowed", [`foundation.${table}`, privilege]);
          expect(acl.rows[0]?.allowed).toBe(false);
        }
        await expect(required(runtimePools[1]).query(`SELECT * FROM foundation.${table}`)).rejects.toMatchObject({ code: '42501' });
      }
    }
    const auditUpdate = await db.query<{ allowed: boolean }>("SELECT has_table_privilege('fixlevelup_runtime', 'foundation.audit_logs', 'UPDATE') AS allowed");
    expect(auditUpdate.rows[0]?.allowed).toBe(false);
    await expect(required(runtimePools[1]).query('DELETE FROM foundation.staff')).rejects.toMatchObject({ code: '42501' });
  });
});
