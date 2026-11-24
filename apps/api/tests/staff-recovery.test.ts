import { spawnSync } from 'node:child_process';
import { argon2, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Client, Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { bootstrapFirstAdmin } from '../src/staff/bootstrap.js';
import { recoverAdmin } from '../src/staff/recovery.js';
import { migrateAuthFixture, reassignFixture, spareAdmin } from './auth-db-fixture.js';

// Identical opt-in and isolation policy to staff-bootstrap.test.ts: only random,
// newly created databases are changed, and this run's teardown drops exactly the
// databases it created (strict disposable-name pattern).
const integration = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1' ? describe : describe.skip;
const root = resolve(import.meta.dirname, '../../..');
const oldPassword = 'Synthetic-Old-Password-Canary-2026!';
const newPassword = 'Synthetic-New-Password-Canary-2026!';
const login = `recovery-${randomBytes(12).toString('hex')}`;

async function verifyHash(encoded: string, password: string): Promise<boolean> {
  const parts = encoded.split('$');
  expect(parts.slice(0, 4)).toEqual(['', 'argon2id', 'v=19', 'm=19456,t=2,p=1']);
  expect(parts).toHaveLength(6);
  const salt = Buffer.from(parts[4] ?? '', 'base64');
  const expected = Buffer.from(parts[5] ?? '', 'base64');
  expect(salt).toHaveLength(16);
  expect(expected).toHaveLength(32);
  const actual = await new Promise<Buffer>((resolveHash, reject) => {
    argon2('argon2id', { message: password, nonce: salt, parallelism: 1, tagLength: 32, memory: 19456, passes: 2 },
      (error, result) => { if (error) { reject(error); } else { resolveHash(result); } });
  });
  return timingSafeEqual(actual, expected);
}

describe('recovery password UTF-8 byte limits', () => {
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
    await expect(recoverAdmin({ connect }, { login: 'synthetic-user', password }))
      .rejects.toMatchObject({ name: 'RecoveryError', message: 'Staff recovery failed' });
    expect(connect).toHaveBeenCalledTimes(valid ? 1 : 0);
  });
});

describe('recovery CLI', () => {
  it('rejects non-TTY input without exposing secrets', () => {
    const result = spawnSync(process.execPath, [resolve(root, 'apps/api/dist/bootstrap/staff-recover.js')], {
      cwd: root, env: { ...process.env, DB_PASSWORD: oldPassword }, input: `${login}\n${newPassword}\n${newPassword}\n`,
      encoding: 'utf8', timeout: 8000,
    });
    if (result.error) { throw result.error; }
    expect(result.status).toBe(1);
    expect(result.stderr).toBe('Staff recovery failed.\n');
    expect(result.stdout).toBe('');
    for (const secret of [oldPassword, newPassword, login]) {
      expect(result.stderr).not.toContain(secret);
    }
  });
});

integration('administrator recovery against isolated PostgreSQL', () => {
  let admin: Client | undefined;
  let fixture: Client;
  let pool: Pool;
  const fixtures: Client[] = [];
  const pools: Pool[] = [];
  let staffId: string;
  let spare: string;
  let dbName: string | undefined;
  let dbCreated = false;
  let tornDown = false;

  /** Ownership proof for the teardown drop, consumed exactly once: this run's CREATE
   * result (flag) AND the strict disposable-name pattern. */
  const takeOwnedDatabase = (): string | undefined => {
    if (!dbCreated) { return undefined; }
    dbCreated = false;
    return dbName !== undefined && /^fixlevelup_recovery_test_[a-f0-9]{24}$/.test(dbName) ? dbName : undefined;
  };

  /** The afterAll teardown, exactly once: this run's pools/clients down first, then
   * the drop of exactly the database this run created. A second call is a no-op. */
  async function teardown(): Promise<void> {
    if (tornDown) { return; }
    tornDown = true;
    const ownedDatabase = takeOwnedDatabase();
    try {
      await Promise.all(pools.map((item) => item.end()));
      await Promise.all(fixtures.map((item) => item.end()));
    } finally {
      try {
        if (ownedDatabase !== undefined) {
          await admin?.query(`DROP DATABASE IF EXISTS "${ownedDatabase}" WITH (FORCE)`);
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
    const name = `fixlevelup_recovery_test_${randomBytes(12).toString('hex')}`;
    try {
      await admin.query(`CREATE DATABASE "${name}" OWNER fixlevelup_migrator TEMPLATE template0`);
      // CREATE is the reuse guard: an existing name is a hard error, so a successful
      // CREATE proves this run owns the disposable database (the flag gates the drop).
      dbName = name;
      dbCreated = true;
      await admin.query(`REVOKE ALL ON DATABASE "${name}" FROM PUBLIC`);
      await admin.query(`GRANT CONNECT ON DATABASE "${name}" TO fixlevelup_migrator, fixlevelup_runtime`);
      fixture = new Client({ ...connection, database: name, user: 'fixlevelup_migrator', password: migratorPassword });
      fixtures.push(fixture);
      await fixture.connect();
      await migrateAuthFixture(fixture, name);
      pool = new Pool({ ...connection, database: name, user: 'fixlevelup_migrator', password: migratorPassword });
      pools.push(pool);
      const runtime = new Pool({ ...connection, database: name, user: 'fixlevelup_runtime', password: runtimePassword });
      pools.push(runtime);
      ({ staffId } = await bootstrapFirstAdmin(pool, { login, password: oldPassword }));
      spare = await spareAdmin(fixture, staffId);
      await expect(runtime.query('SELECT * FROM foundation.staff_bootstrap_marker')).rejects.toMatchObject({ code: '42501' });
      // Valid, active, credentialed ADMIN exists: denial cannot be due to a missing target.
      const before = (await fixture.query('SELECT password_hash FROM foundation.staff_web_credentials WHERE staff_id=$1', [staffId])).rows;
      await expect(recoverAdmin(runtime, { login, password: newPassword })).rejects.toMatchObject({ name: 'RecoveryError', message: 'Staff recovery failed' });
      expect((await fixture.query('SELECT password_hash FROM foundation.staff_web_credentials WHERE staff_id=$1', [staffId])).rows).toEqual(before);
    } catch (error) {
      // Provisioning failed after CREATE: run the same lifecycle cleanup before rethrowing.
      await teardown().catch(() => undefined);
      throw error;
    }
  }, 30000);

  afterAll(teardown);

  it('changes the existing credential and version, audits without secrets, and preserves the bootstrap marker', async () => {
    const logs = [vi.spyOn(console, 'log'), vi.spyOn(console, 'warn'), vi.spyOn(console, 'error')];
    try {
      const before = (await fixture.query<{ password_hash: string }>('SELECT password_hash FROM foundation.staff_web_credentials WHERE staff_id = $1', [staffId])).rows[0]?.password_hash ?? '';
      const marker = (await fixture.query('SELECT id, staff_id FROM foundation.staff_bootstrap_marker')).rows;
      await recoverAdmin(pool, { login, password: newPassword });
      const after = (await fixture.query<{ password_hash: string }>('SELECT password_hash FROM foundation.staff_web_credentials WHERE staff_id = $1', [staffId])).rows[0]?.password_hash ?? '';
      expect(after).not.toBe(before);
      expect(await verifyHash(after, newPassword)).toBe(true);
      expect(await verifyHash(after, oldPassword)).toBe(false);
      expect((await fixture.query('SELECT id, role, employment_state, auth_version FROM foundation.staff WHERE id=$1', [staffId])).rows)
        .toEqual([{ id: staffId, role: 'ADMIN', employment_state: 'ACTIVE', auth_version: 1 }]);
      const audit = (await fixture.query<{ operation: string; correlation_id: string; details: unknown }>('SELECT operation, correlation_id, details FROM foundation.audit_logs WHERE operation = $1', ['STAFF_RECOVERY'])).rows;
      expect(audit).toHaveLength(1);
      expect(audit[0]?.operation).toBe('STAFF_RECOVERY');
      expect(audit[0]?.correlation_id).toMatch(/^[0-9a-f-]{36}$/);
      expect(audit[0]?.details).toEqual({ staffId });
      expect((await fixture.query('SELECT id, staff_id FROM foundation.staff_bootstrap_marker')).rows).toEqual(marker);
      for (const secret of [oldPassword, newPassword, before, after]) {
        expect(JSON.stringify(audit)).not.toContain(secret);
        expect(JSON.stringify(logs.flatMap((spy) => spy.mock.calls))).not.toContain(secret);
      }
    } finally {
      for (const spy of logs) { spy.mockRestore(); }
    }
  }, 30000);

  it('denies missing, inactive, and non-admin accounts without changing state or exposing secrets', async () => {
    const logs = [vi.spyOn(console, 'log'), vi.spyOn(console, 'warn'), vi.spyOn(console, 'error')];
    try {
      const snapshot = async () => ({
        staff: (await fixture.query('SELECT * FROM foundation.staff ORDER BY id')).rows,
        assignments: (await fixture.query('SELECT * FROM foundation.staff_role_assignments ORDER BY id')).rows,
        credentials: (await fixture.query('SELECT * FROM foundation.staff_web_credentials ORDER BY staff_id')).rows,
        audit: (await fixture.query('SELECT * FROM foundation.audit_logs ORDER BY id')).rows,
        marker: (await fixture.query('SELECT * FROM foundation.staff_bootstrap_marker')).rows,
      });
      for (const [role, state, target] of [['ADMIN', 'ACTIVE', `${login}-missing`], ['ADMIN', 'INACTIVE', login], ['MANAGER', 'ACTIVE', login]] as const) {
        if (role === 'MANAGER') { await reassignFixture(fixture, staffId, role, spare); }
        else { await fixture.query('UPDATE foundation.staff SET employment_state=$2 WHERE id=$1', [staffId, state]); }
        const before = await snapshot();
        const failure: unknown = await recoverAdmin(pool, { login: target, password: newPassword }).catch((error: unknown) => error);
        expect(failure).toMatchObject({ name: 'RecoveryError', message: 'Staff recovery failed' });
        expect(String(failure)).not.toContain(newPassword);
        expect(JSON.stringify(failure)).not.toContain(newPassword);
        expect(await snapshot()).toEqual(before);
      }
      expect(JSON.stringify(logs.flatMap((spy) => spy.mock.calls))).not.toContain(newPassword);
    } finally {
      await reassignFixture(fixture, staffId, 'ADMIN', spare);
      for (const spy of logs) { spy.mockRestore(); }
    }
  }, 30000);

  it('rolls back credential and version if the audit write fails', async () => {
    const logs = [vi.spyOn(console, 'log'), vi.spyOn(console, 'warn'), vi.spyOn(console, 'error')];
    await fixture.query("ALTER TABLE foundation.audit_logs ADD CONSTRAINT fixture_reject_recovery CHECK (operation <> 'STAFF_RECOVERY') NOT VALID");
    try {
      const before = (await fixture.query('SELECT s.auth_version, c.password_hash FROM foundation.staff s JOIN foundation.staff_web_credentials c ON c.staff_id = s.id WHERE s.id = $1', [staffId])).rows;
      const audit = (await fixture.query('SELECT * FROM foundation.audit_logs ORDER BY id')).rows;
      const marker = (await fixture.query('SELECT * FROM foundation.staff_bootstrap_marker')).rows;
      const failure: unknown = await recoverAdmin(pool, { login, password: oldPassword }).catch((error: unknown) => error);
      expect(failure).toMatchObject({ name: 'RecoveryError', message: 'Staff recovery failed' });
      expect(String(failure)).not.toContain(oldPassword);
      expect(JSON.stringify(failure)).not.toContain(oldPassword);
      expect((await fixture.query('SELECT s.auth_version, c.password_hash FROM foundation.staff s JOIN foundation.staff_web_credentials c ON c.staff_id = s.id WHERE s.id = $1', [staffId])).rows).toEqual(before);
      expect((await fixture.query('SELECT * FROM foundation.audit_logs ORDER BY id')).rows).toEqual(audit);
      expect((await fixture.query('SELECT * FROM foundation.staff_bootstrap_marker')).rows).toEqual(marker);
      expect(JSON.stringify(logs.flatMap((spy) => spy.mock.calls))).not.toContain(oldPassword);
    } finally {
      await fixture.query('ALTER TABLE foundation.audit_logs DROP CONSTRAINT fixture_reject_recovery');
      for (const spy of logs) { spy.mockRestore(); }
    }
  }, 30000);
});
