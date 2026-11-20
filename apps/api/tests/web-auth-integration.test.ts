import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Client, Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { WebAuthService } from '../src/auth/web-auth.service.js';
import { bootstrapFirstAdmin } from '../src/staff/bootstrap.js';
import { recoverAdmin } from '../src/staff/recovery.js';

// Explicit opt-in only: create a random database, never alter or drop the dev database.
const integration = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1' ? describe : describe.skip;
const root = resolve(import.meta.dirname, '../../..');
const oldPassword = 'Synthetic-Web-Old-Password-2026!';
const newPassword = 'Synthetic-Web-New-Password-2026!';
const recoveredPassword = 'Synthetic-Web-Recovered-Password-2026!';
const login = `web-${randomBytes(12).toString('hex')}`;
const migrations = [
  '20261120000100_technical_audit_outbox',
  '20261120000200_technical_outbox_attempts',
  '20261120000300_technical_outbox_leases',
  '20261120000400_staff_identity',
  '20261120000500_web_auth',
  '20261120000600_authorization',
];
const digest = (token: string) => createHash('sha256').update(token).digest('hex');

integration('web authentication against isolated PostgreSQL', () => {
  let admin: Client | undefined;
  let fixture: Client;
  let migrator: Pool;
  let runtime: Pool;
  const clients: Client[] = [];
  const pools: Pool[] = [];
  let service: WebAuthService;
  let staffId: string;
  let sourceSequence = 0;
  const source = () => `synthetic-source-${String(++sourceSequence)}`;

  beforeAll(async () => {
    const adminEnv = readFileSync(resolve(root, 'infra/dev-postgres/.env'), 'utf8');
    const runtimeEnv = readFileSync(resolve(root, 'packages/database-tooling/.env'), 'utf8');
    const adminPassword = /^POSTGRES_PASSWORD=([a-f0-9]{64})$/m.exec(adminEnv)?.[1];
    const runtimePassword = /^FIXLEVELUP_RUNTIME_PASSWORD=([a-f0-9]{64})$/m.exec(runtimeEnv)?.[1];
    const migratorPassword = /^FIXLEVELUP_MIGRATOR_PASSWORD=([a-f0-9]{64})$/m.exec(runtimeEnv)?.[1];
    if (!adminPassword || !runtimePassword || !migratorPassword) { throw new Error('Local isolated PostgreSQL test credentials are required'); }
    const connection = { host: '127.0.0.1', port: 55432 };
    admin = new Client({ ...connection, database: 'fixlevelup_dev', user: 'fixlevelup_dev', password: adminPassword });
    await admin.connect();
    const database = `fixlevelup_web_auth_test_${randomBytes(12).toString('hex')}`;
    await admin.query(`CREATE DATABASE "${database}" OWNER fixlevelup_migrator TEMPLATE template0`);
    await admin.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`);
    await admin.query(`GRANT CONNECT ON DATABASE "${database}" TO fixlevelup_migrator, fixlevelup_runtime`);
    fixture = new Client({ ...connection, database, user: 'fixlevelup_migrator', password: migratorPassword });
    clients.push(fixture);
    await fixture.connect();
    await fixture.query('CREATE SCHEMA foundation AUTHORIZATION fixlevelup_migrator');
    for (const migration of migrations) {
      await fixture.query(readFileSync(resolve(root, 'prisma/migrations', migration, 'migration.sql'), 'utf8'));
    }
    migrator = new Pool({ ...connection, database, user: 'fixlevelup_migrator', password: migratorPassword });
    runtime = new Pool({ ...connection, database, user: 'fixlevelup_runtime', password: runtimePassword });
    pools.push(migrator, runtime);
    ({ staffId } = await bootstrapFirstAdmin(migrator, { login, password: oldPassword }));
    service = new WebAuthService(runtime, { throttleSecret: randomBytes(32) });
  }, 30000);

  beforeEach(async () => {
    // Tests use independent windows so intentional failures cannot poison later cases.
    await fixture.query('DELETE FROM foundation.web_auth_attempts');
    await fixture.query('DELETE FROM foundation.web_auth_throttles');
  });

  afterAll(async () => {
    await Promise.all(pools.map((pool) => pool.end()));
    await Promise.all(clients.map((client) => client.end()));
    await admin?.end();
  });

  it('uses runtime grants and denies privileged staff writes', async () => {
    await expect(runtime.query('SELECT id FROM foundation.staff WHERE id = $1', [staffId])).resolves.toMatchObject({ rowCount: 1 });
    await expect(runtime.query("UPDATE foundation.staff SET role = 'TECHNICIAN' WHERE id = $1", [staffId])).rejects.toMatchObject({ code: '42501' });
    await expect(runtime.query('SELECT * FROM foundation.staff_bootstrap_marker')).rejects.toMatchObject({ code: '42501' });
  });

  it('accepts active web staff and rejects wrong, missing, inactive, and technician credentials', async () => {
    const credential = await service.login(login, oldPassword, source());
    expect(credential).toMatchObject({ staffId, role: 'ADMIN' });
    expect(await service.authenticate(credential.token)).toMatchObject({ staffId, role: 'ADMIN' });
    for (const [target, password] of [[login, 'Synthetic-Wrong-Password!'], [`${login}-missing`, oldPassword]] as const) {
      await expect(service.login(target, password, source())).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    }
    try {
      await fixture.query("UPDATE foundation.staff SET employment_state = 'INACTIVE' WHERE id = $1", [staffId]);
      await expect(service.login(login, oldPassword, source())).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
      await fixture.query("UPDATE foundation.staff SET employment_state = 'ACTIVE', role = 'TECHNICIAN' WHERE id = $1", [staffId]);
      await expect(service.login(login, oldPassword, source())).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    } finally {
      await fixture.query("UPDATE foundation.staff SET employment_state = 'ACTIVE', role = 'ADMIN' WHERE id = $1", [staffId]);
    }
  }, 30000);

  it('bounds concurrent failures and does not exhaust the limit on successful logins', async () => {
    const origin = source();
    const results = await Promise.allSettled(Array.from({ length: 10 }, () => service.login(login, 'Synthetic-Wrong-Password!', origin)));
    expect(results.filter((result) => result.status === 'rejected' && (result.reason as { code?: string }).code === 'INVALID_CREDENTIALS')).toHaveLength(5);
    expect(results.filter((result) => result.status === 'rejected' && (result.reason as { code?: string }).code === 'RATE_LIMITED')).toHaveLength(5);
    await fixture.query('DELETE FROM foundation.web_auth_attempts');
    await fixture.query('DELETE FROM foundation.web_auth_throttles');
    const successfulOrigin = source();
    for (let i = 0; i < 6; i++) { await service.login(login, oldPassword, successfulOrigin); }
  }, 30000);

  it('keeps recent failures limited past the original window and resets after expiry', async () => {
    const origin = source();
    for (let i = 0; i < 4; i++) {
      await expect(service.login(login, 'Synthetic-Wrong-Password!', origin)).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    }
    // Age each old event independently while preserving its 15-minute lifetime.
    await fixture.query("UPDATE foundation.web_auth_attempts SET reserved_at = reserved_at - interval '14 minutes', completed_at = completed_at - interval '14 minutes', failed_at = failed_at - interval '14 minutes', expires_at = expires_at - interval '14 minutes'");
    await expect(service.login(login, 'Synthetic-Wrong-Password!', origin)).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    await expect(service.login(login, oldPassword, origin)).rejects.toMatchObject({ code: 'RATE_LIMITED' });
    await fixture.query("UPDATE foundation.web_auth_attempts SET reserved_at = reserved_at - interval '2 minutes', completed_at = completed_at - interval '2 minutes', failed_at = failed_at - interval '2 minutes', expires_at = expires_at - interval '2 minutes' WHERE reserved_at < clock_timestamp() - interval '10 minutes'");
    // Four old events expire; the recent fifth still consumes one slot.
    for (let i = 0; i < 4; i++) {
      await expect(service.login(login, 'Synthetic-Wrong-Password!', origin)).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    }
    await expect(service.login(login, oldPassword, origin)).rejects.toMatchObject({ code: 'RATE_LIMITED' });
    await fixture.query("UPDATE foundation.web_auth_attempts SET reserved_at = reserved_at - interval '16 minutes', completed_at = completed_at - interval '16 minutes', failed_at = failed_at - interval '16 minutes', expires_at = expires_at - interval '16 minutes'");
    await expect(service.login(login, oldPassword, origin)).resolves.toMatchObject({ staffId });
  }, 30000);

  it('bounds privileged cleanup and preserves live attempts and sessions', async () => {
    const key = randomBytes(32).toString('hex');
    await fixture.query('INSERT INTO foundation.web_auth_throttles (key_hash) VALUES ($1)', [key]);
    await fixture.query(`INSERT INTO foundation.web_auth_attempts (id, key_hash, reserved_at, expires_at)
      SELECT gen_random_uuid(), $1, clock_timestamp() - interval '2 hours', clock_timestamp() - interval '1 hour'
      FROM generate_series(1, 105)`, [key]);
    const liveId = randomUUID();
    await fixture.query("INSERT INTO foundation.web_auth_attempts (id, key_hash, reserved_at, expires_at) VALUES ($1, $2, clock_timestamp(), clock_timestamp() + interval '15 minutes')", [liveId, key]);
    await expect(runtime.query('DELETE FROM foundation.web_auth_attempts')).rejects.toMatchObject({ code: '42501' });
    const first = await runtime.query<{ count: number }>('SELECT foundation.cleanup_web_auth_attempts() AS count');
    const second = await runtime.query<{ count: number }>('SELECT foundation.cleanup_web_auth_attempts() AS count');
    expect(first.rows[0]?.count).toBe(100);
    expect(second.rows[0]?.count).toBe(5);
    expect((await fixture.query('SELECT id FROM foundation.web_auth_attempts WHERE id = $1', [liveId])).rowCount).toBe(1);
    await fixture.query("INSERT INTO foundation.web_auth_throttles (key_hash) SELECT encode(sha256(gen_random_uuid()::text::bytea), 'hex') FROM generate_series(1, 105)");
    await expect(runtime.query('DELETE FROM foundation.web_auth_throttles')).rejects.toMatchObject({ code: '42501' });
    expect((await runtime.query<{ count: number }>('SELECT foundation.cleanup_web_auth_throttles() AS count')).rows[0]?.count).toBe(100);
    expect((await runtime.query<{ count: number }>('SELECT foundation.cleanup_web_auth_throttles() AS count')).rows[0]?.count).toBe(5);
    expect((await fixture.query('SELECT key_hash FROM foundation.web_auth_throttles WHERE key_hash = $1', [key])).rowCount).toBe(1);
    const session = await service.login(login, oldPassword, source());
    const liveSession = digest(session.token);
    await fixture.query(`INSERT INTO foundation.web_sessions (id, staff_id, token_hash, auth_version, created_at, idle_expires_at, absolute_expires_at)
      SELECT gen_random_uuid(), $1, encode(sha256(gen_random_uuid()::text::bytea), 'hex'), 0,
        clock_timestamp() - interval '40 days', clock_timestamp() - interval '39 days', clock_timestamp() - interval '38 days'
      FROM generate_series(1, 105)`, [staffId]);
    await expect(runtime.query('DELETE FROM foundation.web_sessions')).rejects.toMatchObject({ code: '42501' });
    expect((await runtime.query<{ count: number }>('SELECT foundation.cleanup_web_sessions() AS count')).rows[0]?.count).toBe(100);
    expect((await runtime.query<{ count: number }>('SELECT foundation.cleanup_web_sessions() AS count')).rows[0]?.count).toBe(5);
    expect((await fixture.query('SELECT id FROM foundation.web_sessions WHERE token_hash = $1', [liveSession])).rowCount).toBe(1);
    await expect(service.authenticate(session.token)).resolves.toMatchObject({ staffId });
  }, 30000);

  it('stores only a digest and logout revokes immediately', async () => {
    const { token } = await service.login(login, oldPassword, source());
    const rows = (await fixture.query<{ token_hash: string; revoked_at: Date | null }>('SELECT token_hash, revoked_at FROM foundation.web_sessions WHERE token_hash = $1', [digest(token)])).rows;
    expect(rows).toEqual([{ token_hash: digest(token), revoked_at: null }]);
    expect(JSON.stringify(rows)).not.toContain(token);
    await service.logout(token);
    await expect(service.authenticate(token)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    await expect(service.renew(token)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  });

  it('rejects expired, inactive, technician and version-invalidated sessions', async () => {
    for (const field of ['idle_expires_at', 'absolute_expires_at'] as const) {
      const { token } = await service.login(login, oldPassword, source());
      if (field === 'absolute_expires_at') {
        await fixture.query("UPDATE foundation.web_sessions SET created_at = clock_timestamp() - interval '2 hours', idle_expires_at = clock_timestamp() - interval '1 hour', absolute_expires_at = clock_timestamp() - interval '1 minute' WHERE token_hash = $1", [digest(token)]);
      } else {
        await fixture.query("UPDATE foundation.web_sessions SET created_at = clock_timestamp() - interval '2 hours', idle_expires_at = clock_timestamp() - interval '1 minute' WHERE token_hash = $1", [digest(token)]);
      }
      await expect(service.authenticate(token)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    }
    for (const update of ["employment_state = 'INACTIVE'", "role = 'TECHNICIAN'", 'auth_version = auth_version + 1']) {
      const { token } = await service.login(login, oldPassword, source());
      try {
        await fixture.query(`UPDATE foundation.staff SET ${update} WHERE id = $1`, [staffId]);
        await expect(service.authenticate(token)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
      } finally {
        await fixture.query("UPDATE foundation.staff SET employment_state = 'ACTIVE', role = 'ADMIN' WHERE id = $1", [staffId]);
      }
    }
  }, 30000);

  it('permits exactly one concurrent renewal of a credential', async () => {
    const { token } = await service.login(login, oldPassword, source());
    const results = await Promise.allSettled([service.renew(token), service.renew(token)]);
    const successes = results.filter((result) => result.status === 'fulfilled');
    expect(successes).toHaveLength(1);
    expect(results.filter((result) => result.status === 'rejected' && (result.reason as { code?: string }).code === 'UNAUTHORIZED')).toHaveLength(1);
    await expect(service.authenticate(token)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    const winner = successes[0];
    if (winner?.status !== 'fulfilled') { throw new Error('Missing renewal winner'); }
    expect(winner.value.token).not.toBe(token);
    await expect(service.authenticate(winner.value.token)).resolves.toMatchObject({ staffId });
  });

  it('limits password failures per authenticated staff and source, without charging invalid sessions', async () => {
    const session = await service.login(login, oldPassword, source());
    await fixture.query('DELETE FROM foundation.web_auth_attempts');
    await fixture.query('DELETE FROM foundation.web_auth_throttles');
    await expect(service.changePassword('invalid-token', oldPassword, newPassword, source(), 0)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect((await fixture.query('SELECT key_hash FROM foundation.web_auth_throttles')).rowCount).toBe(0);
    const origin = source();
    const attempts = await Promise.allSettled(Array.from({ length: 10 }, () => service.changePassword(session.token, 'Synthetic-Wrong-Password!', newPassword, origin, session.authVersion)));
    expect(attempts.filter((result) => result.status === 'rejected' && (result.reason as { code?: string }).code === 'INVALID_CREDENTIALS')).toHaveLength(5);
    expect(attempts.filter((result) => result.status === 'rejected' && (result.reason as { code?: string }).code === 'RATE_LIMITED')).toHaveLength(5);
    await expect(service.changePassword(session.token, oldPassword, newPassword, source(), session.authVersion)).rejects.toMatchObject({ code: 'RATE_LIMITED' });
  }, 30000);

  it('shares the identifier failure limit across login and password change', async () => {
    const session = await service.login(login, oldPassword, source());
    const loginOrigin = source();
    const changeOrigin = source();
    for (let i = 0; i < 3; i++) {
      await expect(service.login(login, 'Synthetic-Wrong-Password!', loginOrigin)).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    }
    for (let i = 0; i < 2; i++) {
      await expect(service.changePassword(session.token, 'Synthetic-Wrong-Password!', newPassword, changeOrigin, session.authVersion)).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    }
    await expect(service.login(login, oldPassword, source())).rejects.toMatchObject({ code: 'RATE_LIMITED' });
    await expect(service.changePassword(session.token, oldPassword, newPassword, source(), session.authVersion)).rejects.toMatchObject({ code: 'RATE_LIMITED' });
  }, 30000);

  it('releases successful password reservations and enforces the shared source cap', async () => {
    const session = await service.login(login, oldPassword, source());
    const origin = source();
    let current = oldPassword;
    for (let i = 0; i < 6; i++) {
      const next = i % 2 === 0 ? newPassword : oldPassword;
      await service.changePassword(session.token, current, next, origin, session.authVersion + i);
      current = next;
    }
    const limited = new WebAuthService(runtime, { throttleSecret: randomBytes(32), sourceLimit: 5 });
    const shared = source();
    // Make a second synthetic staff member with the same synthetic password hash.
    const otherId = randomUUID();
    const otherLogin = `${login}-second`;
    await fixture.query("INSERT INTO foundation.staff (id, role, employment_state) VALUES ($1, 'MANAGER', 'ACTIVE')", [otherId]);
    await fixture.query('INSERT INTO foundation.staff_web_credentials (staff_id, login, password_hash) SELECT $1, $2, password_hash FROM foundation.staff_web_credentials WHERE staff_id = $3', [otherId, otherLogin, staffId]);
    const other = await limited.login(otherLogin, oldPassword, source());
    for (let i = 0; i < 3; i++) {
      await expect(limited.changePassword(session.token, 'Synthetic-Wrong-Password!', newPassword, shared, session.authVersion + 6)).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    }
    for (let i = 0; i < 2; i++) {
      await expect(limited.changePassword(other.token, 'Synthetic-Wrong-Password!', newPassword, shared, other.authVersion)).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    }
    await expect(limited.changePassword(other.token, oldPassword, newPassword, shared, other.authVersion)).rejects.toMatchObject({ code: 'RATE_LIMITED' });
  }, 30000);

  it('changes password, preserving current session but invalidating other sessions', async () => {
    const current = await service.login(login, oldPassword, source());
    const other = await service.login(login, oldPassword, source());
    await expect(service.changePassword(current.token, oldPassword, newPassword, source(), current.authVersion + 1)).rejects.toMatchObject({ code: 'STALE' });
    await expect(service.changePassword(current.token, 'Synthetic-Wrong-Password!', newPassword, source(), current.authVersion)).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    const snapshot = async () => (await fixture.query<{ auth_version: number; password_hash: string }>('SELECT s.auth_version, c.password_hash FROM foundation.staff s JOIN foundation.staff_web_credentials c ON c.staff_id = s.id WHERE s.id = $1', [staffId])).rows;
    const before = await snapshot();
    const auditBefore = (await fixture.query('SELECT id FROM foundation.audit_logs WHERE operation = $1', ['STAFF_PASSWORD_CHANGE'])).rowCount;
    await fixture.query("ALTER TABLE foundation.audit_logs ADD CONSTRAINT fixture_reject_password_change CHECK (operation <> 'STAFF_PASSWORD_CHANGE') NOT VALID");
    try {
      await expect(service.changePassword(current.token, oldPassword, newPassword, source(), current.authVersion)).rejects.toMatchObject({ code: 'FAILED' });
      expect(await snapshot()).toEqual(before);
      await expect(service.authenticate(current.token)).resolves.toMatchObject({ staffId });
      await expect(service.authenticate(other.token)).resolves.toMatchObject({ staffId });
    } finally {
      await fixture.query('ALTER TABLE foundation.audit_logs DROP CONSTRAINT fixture_reject_password_change');
    }
    await service.changePassword(current.token, oldPassword, newPassword, source(), current.authVersion);
    const audit = (await fixture.query('SELECT details FROM foundation.audit_logs WHERE operation = $1', ['STAFF_PASSWORD_CHANGE'])).rows;
    expect(audit).toHaveLength((auditBefore ?? 0) + 1);
    expect(audit).toContainEqual({ details: { staffId } });
    expect(JSON.stringify(audit)).not.toContain(newPassword);
    await expect(service.authenticate(current.token)).resolves.toMatchObject({ staffId });
    await expect(service.authenticate(other.token)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    await expect(service.login(login, oldPassword, source())).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    await expect(service.login(login, newPassword, source())).resolves.toMatchObject({ staffId });
  }, 30000);

  it('rolls back recovery when DB audit fails and invalidates a concurrently renewed session after recovery', async () => {
    const session = await service.login(login, newPassword, source());
    const snapshot = async () => (await fixture.query<{ auth_version: number; password_hash: string }>('SELECT s.auth_version, c.password_hash FROM foundation.staff s JOIN foundation.staff_web_credentials c ON c.staff_id = s.id WHERE s.id = $1', [staffId])).rows;
    const before = await snapshot();
    await fixture.query("ALTER TABLE foundation.audit_logs ADD CONSTRAINT fixture_reject_recovery CHECK (operation <> 'STAFF_RECOVERY') NOT VALID");
    try {
      await expect(recoverAdmin(migrator, { login, password: recoveredPassword })).rejects.toMatchObject({ name: 'RecoveryError' });
      expect(await snapshot()).toEqual(before);
      await expect(service.authenticate(session.token)).resolves.toMatchObject({ staffId });
    } finally {
      await fixture.query('ALTER TABLE foundation.audit_logs DROP CONSTRAINT fixture_reject_recovery');
    }
    const [renewal, recovery] = await Promise.allSettled([service.renew(session.token), recoverAdmin(migrator, { login, password: recoveredPassword })]);
    expect(recovery.status).toBe('fulfilled');
    // A renewal winning the lock before recovery remains invalid after it commits.
    await expect(service.login(login, recoveredPassword, source())).resolves.toMatchObject({ staffId });
    await expect(service.authenticate(session.token)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    if (renewal.status === 'fulfilled') {
      await expect(service.authenticate(renewal.value.token)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    } else {
      expect((renewal.reason as unknown)).toMatchObject({ code: 'UNAUTHORIZED' });
    }
  }, 30000);
});
