import 'reflect-metadata';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { Server } from 'node:http';
import { resolve } from 'node:path';
import { ConsoleLogger } from '@nestjs/common';
import { Client, Pool } from 'pg';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { WebAuthConfig } from '../src/auth/web-auth.config.js';
import { createApi } from '../src/bootstrap/factories.js';
import type { DatabaseConfig } from '../src/infrastructure/database/runtime-database.js';
import { loadConfig } from '../src/runtime/config.js';
import { SafeLogger } from '../src/runtime/safe-logger.js';
import { bootstrapFirstAdmin } from '../src/staff/bootstrap.js';
import { hashPassword } from '../src/staff/password.js';

// Real-HTTP staff authorization e2e on the real guard, real SQL and the real staff
// controller. Covers default deny, capability grants, the POST /staff write path with
// audit rows, the mandatory DECISIONS §21 concurrent revoke/write serialization test,
// actor deactivation and response hygiene. Opt-in like web-auth-e2e.test.ts: the suite
// never runs against the dev schema and always builds its own random database.
const integration = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1' ? describe : describe.skip;
const root = resolve(import.meta.dirname, '../../..');
const connection = { host: '127.0.0.1' as const, port: 55432 };
const migrations = [
  '20261120000100_technical_audit_outbox',
  '20261120000200_technical_outbox_attempts',
  '20261120000300_technical_outbox_leases',
  '20261120000400_staff_identity',
  '20261120000500_web_auth',
  '20261120000600_authorization',
];
const origin = 'https://crm.example.test';
const cookieName = '__Host-fixlevelup_session';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const adminPassword = 'Synthetic-E2E-Admin-Password-2026!';
const managerPassword = 'Synthetic-E2E-Manager-Password-2026!';
const adminLogin = `e2e-${randomBytes(12).toString('hex')}`;
const managerLogin = `e2e-${randomBytes(12).toString('hex')}`;

function csrf(body: unknown): string {
  if (typeof body !== 'object' || body === null || !('data' in body) || typeof body.data !== 'object' || body.data === null || !('csrfToken' in body.data) || typeof body.data.csrfToken !== 'string') { throw new Error('Missing CSRF token'); }
  return body.data.csrfToken;
}

function session(headers: Record<string, unknown>): { cookie: string; token: string } {
  const setCookie = headers['set-cookie'];
  if (!Array.isArray(setCookie) || setCookie.length !== 1 || typeof setCookie[0] !== 'string') { throw new Error('Missing session cookie'); }
  const match = new RegExp(`^${cookieName}=([A-Za-z0-9_-]{43}); Path=/; HttpOnly; Secure; SameSite=Strict$`).exec(setCookie[0]);
  if (!match?.[1]) { throw new Error('Invalid session cookie'); }
  return { cookie: `${cookieName}=${match[1]}`, token: match[1] };
}

function itemCount(body: unknown): number {
  if (typeof body !== 'object' || body === null || !('data' in body) || typeof body.data !== 'object' || body.data === null || !('items' in body.data) || !Array.isArray(body.data.items)) { throw new Error('Missing staff list'); }
  return body.data.items.length;
}

interface StaffDto { id: string; role: string; employmentState: string }

/** Validates the list envelope into typed DTOs; no `any` crosses this boundary. */
function staffDtos(body: unknown): StaffDto[] {
  if (typeof body !== 'object' || body === null || !('data' in body) || typeof body.data !== 'object' || body.data === null || !('items' in body.data) || !Array.isArray(body.data.items)) { throw new Error('Missing staff list'); }
  const items: StaffDto[] = [];
  for (const entry of body.data.items) {
    if (typeof entry !== 'object' || entry === null) { throw new Error('Invalid staff list item'); }
    const record = entry as Record<string, unknown>;
    const id = record['id'];
    const role = record['role'];
    const employmentState = record['employmentState'];
    if (typeof id !== 'string' || typeof role !== 'string' || typeof employmentState !== 'string') { throw new Error('Invalid staff list item'); }
    items.push({ id, role, employmentState });
  }
  return items;
}

function createdId(body: unknown): string {
  if (typeof body !== 'object' || body === null || !('data' in body) || typeof body.data !== 'object' || body.data === null || !('id' in body.data) || typeof body.data.id !== 'string') { throw new Error('Missing created staff id'); }
  return body.data.id;
}

function createLoggerSpy() {
  return vi.spyOn(ConsoleLogger.prototype, 'log').mockImplementation(() => undefined);
}

async function waitFor(what: string, check: () => Promise<boolean>, timeoutMs = 4000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!(await check())) {
    if (Date.now() >= deadline) { throw new Error(`Timed out waiting for ${what}`); }
    await new Promise((resolve) => { setTimeout(resolve, 25); });
  }
}

integration('staff authorization real HTTP against isolated PostgreSQL', () => {
  let admin: Client | undefined;
  let fixture: Client | undefined;
  let migrator: Pool | undefined;
  let app: Awaited<ReturnType<typeof createApi>> | undefined;
  let server: Server;
  let logs: ReturnType<typeof createLoggerSpy> | undefined;
  let migratorAccess: { database: string; user: 'fixlevelup_migrator'; password: string } | undefined;
  let adminStaffId: string;
  let managerId: string;
  let managerCookie: string;
  let managerToken: string;
  let managerCsrf: string;
  let createEtag: string;
  const responses: unknown[] = [];
  const cacheControls: string[] = [];
  const collect = (body: unknown): void => { responses.push(body); };

  beforeAll(async () => {
    logs = createLoggerSpy();
    const adminEnv = readFileSync(resolve(root, 'infra/dev-postgres/.env'), 'utf8');
    const runtimeEnv = readFileSync(resolve(root, 'packages/database-tooling/.env'), 'utf8');
    const postgresPassword = /^POSTGRES_PASSWORD=([a-f0-9]{64})$/m.exec(adminEnv)?.[1];
    const runtimePassword = /^FIXLEVELUP_RUNTIME_PASSWORD=([a-f0-9]{64})$/m.exec(runtimeEnv)?.[1];
    const migratorPassword = /^FIXLEVELUP_MIGRATOR_PASSWORD=([a-f0-9]{64})$/m.exec(runtimeEnv)?.[1];
    if (!postgresPassword || !runtimePassword || !migratorPassword) { throw new Error('Local isolated PostgreSQL test credentials are required'); }
    admin = new Client({ ...connection, database: 'fixlevelup_dev', user: 'fixlevelup_dev', password: postgresPassword });
    await admin.connect();
    const database = `fixlevelup_staff_authz_e2e_${randomBytes(12).toString('hex')}`;
    await admin.query(`CREATE DATABASE "${database}" OWNER fixlevelup_migrator TEMPLATE template0`);
    await admin.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`);
    await admin.query(`GRANT CONNECT ON DATABASE "${database}" TO fixlevelup_migrator, fixlevelup_runtime`);
    fixture = new Client({ ...connection, database, user: 'fixlevelup_migrator', password: migratorPassword });
    await fixture.connect();
    await fixture.query('CREATE SCHEMA foundation AUTHORIZATION fixlevelup_migrator');
    for (const migration of migrations) {
      await fixture.query(readFileSync(resolve(root, 'prisma/migrations', migration, 'migration.sql'), 'utf8'));
    }
    await fixture.query('CREATE TABLE foundation._prisma_migrations (id text PRIMARY KEY)');
    migrator = new Pool({ ...connection, database, user: 'fixlevelup_migrator', password: migratorPassword });
    ({ staffId: adminStaffId } = await bootstrapFirstAdmin(migrator, { login: adminLogin, password: adminPassword }));
    // The acting principal: a fixture MANAGER with real web credentials but zero grants.
    managerId = randomUUID();
    await fixture.query('INSERT INTO foundation.staff (id, role, employment_state, auth_version) VALUES ($1, $2, $3, $4)',
      [managerId, 'MANAGER', 'ACTIVE', 0]);
    await fixture.query('INSERT INTO foundation.staff_web_credentials (staff_id, login, password_hash) VALUES ($1, $2, $3)',
      [managerId, managerLogin, await hashPassword(managerPassword)]);
    const dbConfig = { ...connection, database, user: 'fixlevelup_runtime' as const, password: runtimePassword } as DatabaseConfig;
    const webAuth: WebAuthConfig = { origin, csrfSecret: 'a'.repeat(64), throttleSecret: 'b'.repeat(64) };
    app = await createApi(loadConfig({ NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0' }), new SafeLogger('api'), dbConfig, webAuth);
    server = app.getHttpServer() as Server;
    migratorAccess = { database, user: 'fixlevelup_migrator' as const, password: migratorPassword };
    const loggedIn = await request(server).post('/api/v1/auth/login').set('Origin', origin).set('X-CSRF-Token', 'login')
      .send({ login: managerLogin, password: managerPassword }).expect(200);
    collect(loggedIn.body);
    cacheControls.push(loggedIn.headers['cache-control'] ?? '');
    ({ cookie: managerCookie, token: managerToken } = session(loggedIn.headers));
    managerCsrf = csrf(loggedIn.body);
  }, 30000);

  afterAll(async () => {
    try { await app?.close(); }
    finally {
      try { await migrator?.end(); }
      finally {
        try { await fixture?.end(); }
        finally { await admin?.end(); vi.restoreAllMocks(); }
      }
    }
  });

  it('denies a MANAGER session without grants (default deny on the real guard and SQL)', async () => {
    if (!fixture) { throw new Error('Missing isolated fixture'); }
    const db = fixture;
    // Precondition evidence: the manager exists but holds no user_permissions rows.
    const grants = await db.query<{ count: string }>('SELECT count(*) AS count FROM foundation.user_permissions WHERE staff_id = $1', [managerId]);
    expect(Number(grants.rows[0]?.count ?? 0)).toBe(0);
    // The session itself is valid (403, not 401): authentication passed, authorization failed.
    const denied = await request(server).get('/api/v1/staff').set('Origin', origin).set('Cookie', managerCookie).expect(403);
    collect(denied.body);
    cacheControls.push(denied.headers['cache-control'] ?? '');
    expect(denied.body).toMatchObject({ status: 403, code: 'REQUEST_REJECTED' });
  });

  it('unlocks reads with a valid staff.read grant while staff.manage writes stay 403', async () => {
    if (!fixture) { throw new Error('Missing isolated fixture'); }
    const db = fixture;
    await db.query('INSERT INTO foundation.user_permissions (id, staff_id, capability, scope, valid_from, granted_by) VALUES ($1, $2, $3, $4, clock_timestamp(), $5)',
      [randomUUID(), managerId, 'staff.read', 'GLOBAL', adminStaffId]);
    const list = await request(server).get('/api/v1/staff').set('Origin', origin).set('Cookie', managerCookie).expect(200);
    collect(list.body);
    expect(list.headers['cache-control']).toBe('no-store');
    cacheControls.push('no-store');
    expect(itemCount(list.body)).toBe(2);
    // ORDER BY id is unpredictable for random UUIDs, so compare deterministically by role.
    const items = staffDtos(list.body).sort((a, b) => a.role.localeCompare(b.role));
    expect(items).toEqual([
      { id: adminStaffId, role: 'ADMIN', employmentState: 'ACTIVE' },
      { id: managerId, role: 'MANAGER', employmentState: 'ACTIVE' },
    ]);
    expect(list.body).toMatchObject({ data: { pageInfo: { nextCursor: null, hasMore: false } } });
    const found = await request(server).get(`/api/v1/staff/${managerId}`).set('Origin', origin).set('Cookie', managerCookie).expect(200);
    collect(found.body);
    expect(found.headers['cache-control']).toBe('no-store');
    cacheControls.push('no-store');
    expect(found.body).toMatchObject({ data: { id: managerId, role: 'MANAGER', employmentState: 'ACTIVE' } });
    const missing = await request(server).get(`/api/v1/staff/${randomUUID()}`).set('Origin', origin).set('Cookie', managerCookie).expect(404);
    collect(missing.body);
    const malformed = await request(server).get('/api/v1/staff/not-a-uuid').set('Origin', origin).set('Cookie', managerCookie).expect(400);
    collect(malformed.body);
    const write = await request(server).post('/api/v1/staff').set('Origin', origin).set('Cookie', managerCookie)
      .set('X-CSRF-Token', managerCsrf).send({ role: 'TECHNICIAN' }).expect(403);
    collect(write.body);
    const technicians = await db.query<{ count: string }>('SELECT count(*) AS count FROM foundation.staff WHERE role = $1', ['TECHNICIAN']);
    expect(Number(technicians.rows[0]?.count ?? 0)).toBe(0);
  });

  it('creates staff rows with audit entries under staff.manage; a repeat POST creates a second row', async () => {
    if (!fixture) { throw new Error('Missing isolated fixture'); }
    const db = fixture;
    await db.query('INSERT INTO foundation.user_permissions (id, staff_id, capability, scope, valid_from, granted_by) VALUES ($1, $2, $3, $4, clock_timestamp(), $5)',
      [randomUUID(), managerId, 'staff.manage', 'GLOBAL', adminStaffId]);
    const first = await request(server).post('/api/v1/staff').set('Origin', origin).set('Cookie', managerCookie)
      .set('X-CSRF-Token', managerCsrf).send({ role: 'TECHNICIAN' }).expect(201);
    collect(first.body);
    createEtag = first.headers['etag'] ?? '';
    expect(first.headers['cache-control']).toBe('no-store');
    cacheControls.push('no-store');
    const id = createdId(first.body);
    expect(UUID.test(id)).toBe(true);
    expect(first.body).toMatchObject({ data: { role: 'TECHNICIAN', employmentState: 'ACTIVE' } });
    const row = await db.query<{ role: string; employment_state: string; auth_version: number }>(
      'SELECT role, employment_state, auth_version FROM foundation.staff WHERE id = $1', [id]);
    expect(row.rows[0]).toMatchObject({ role: 'TECHNICIAN', employment_state: 'ACTIVE', auth_version: 0 });
    const audit = await db.query<{ details: { by: string; created: string } }>(
      "SELECT details FROM foundation.audit_logs WHERE operation = 'STAFF_CREATED' AND details->>'created' = $1", [id]);
    expect(audit.rowCount).toBe(1);
    expect(audit.rows[0]?.details).toMatchObject({ by: managerId, created: id });
    // No idempotency by lead decision: a repeated identical POST creates a second row.
    const repeat = await request(server).post('/api/v1/staff').set('Origin', origin).set('Cookie', managerCookie)
      .set('X-CSRF-Token', managerCsrf).send({ role: 'TECHNICIAN' }).expect(201);
    collect(repeat.body);
    expect(createdId(repeat.body)).not.toBe(id);
    const technicians = await db.query<{ count: string }>('SELECT count(*) AS count FROM foundation.staff WHERE role = $1', ['TECHNICIAN']);
    expect(Number(technicians.rows[0]?.count ?? 0)).toBe(2);
    const audits = await db.query<{ count: string }>("SELECT count(*) AS count FROM foundation.audit_logs WHERE operation = 'STAFF_CREATED'");
    expect(Number(audits.rows[0]?.count ?? 0)).toBe(2);
  });

  // Mandatory DECISIONS §21 test: the protected write and a concurrent revoke serialize on
  // the same staff row lock. The write transaction is paused on a fixture EXCLUSIVE lock on
  // audit_logs AFTER authorizeForWrite already holds the actor's staff row FOR UPDATE and has
  // inserted the new staff row. The revoke transaction then takes the same staff row FOR
  // UPDATE and demonstrably waits. Releasing the pause commits the write first (201), the
  // revoke commits after it, and the next POST is rejected with 403 and writes nothing.
  it('serializes a concurrent revoke behind the in-flight staff write (DECISIONS §21)', async () => {
    if (!fixture || !migratorAccess) { throw new Error('Missing isolated fixture'); }
    const db = fixture;
    const locker = new Client({ ...connection, ...migratorAccess });
    const revoker = new Client({ ...connection, ...migratorAccess });
    await locker.connect();
    await revoker.connect();
    try {
      await locker.query('BEGIN');
      await locker.query('LOCK TABLE foundation.audit_logs IN EXCLUSIVE MODE');
      let inFlightId = '';
      const creation = new Promise<void>((resolve, reject) => {
        request(server).post('/api/v1/staff').set('Origin', origin).set('Cookie', managerCookie)
          .set('X-CSRF-Token', managerCsrf).send({ role: 'TECHNICIAN' })
          .end((error, response) => {
            if (error || response.status !== 201) { reject(new Error('Expected the in-flight write to commit as 201')); return; }
            collect(response.body);
            inFlightId = createdId(response.body);
            resolve();
          });
      });
      void creation.catch(() => undefined);
      // Wait until the write transaction holds the staff row lock and blocks on the audit insert.
      await waitFor('the write transaction to block on the audit lock', async () => {
        const blocked = await db.query<{ count: number }>(
          `SELECT count(*)::int AS count FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
           WHERE a.datname = current_database() AND a.usename = 'fixlevelup_runtime' AND a.application_name = 'fixlevelup-authz'
             AND l.relation = 'foundation.audit_logs'::regclass AND NOT l.granted`);
        return (blocked.rows[0]?.count ?? 0) > 0;
      });
      // The concurrent revoke: same staff row FOR UPDATE, then the revoke itself. The simple
      // protocol runs BEGIN/SELECT/UPDATE/COMMIT as one in-flight transaction; the SELECT
      // queues behind the write transaction's staff lock and waits.
      const revokerPid = (await revoker.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid ?? 0;
      const revokeDone = revoker.query(`
        BEGIN;
        SELECT id FROM foundation.staff WHERE id = '${managerId}' FOR UPDATE;
        UPDATE foundation.user_permissions SET revoked_at = clock_timestamp()
          WHERE staff_id = '${managerId}' AND capability = 'staff.manage' AND revoked_at IS NULL;
        COMMIT;`);
      void revokeDone.catch(() => undefined);
      await waitFor('the revoke transaction to wait on the staff row lock', async () => {
        const waiting = await db.query<{ count: number }>('SELECT count(*)::int AS count FROM pg_locks WHERE pid = $1 AND NOT granted', [revokerPid]);
        return (waiting.rows[0]?.count ?? 0) > 0;
      });
      // Release the pause: the write commits first, then the revoke takes the staff lock.
      await locker.query('ROLLBACK');
      await creation;
      await revokeDone;
      const grant = await db.query<{ revoked_at: Date | null }>(
        'SELECT revoked_at FROM foundation.user_permissions WHERE staff_id = $1 AND capability = $2', [managerId, 'staff.manage']);
      const revokedAt = grant.rows[0]?.revoked_at;
      const audit = await db.query<{ occurred_at: Date }>(
        "SELECT occurred_at FROM foundation.audit_logs WHERE operation = 'STAFF_CREATED' AND details->>'created' = $1", [inFlightId]);
      const occurredAt = audit.rows[0]?.occurred_at;
      if (!revokedAt || !occurredAt) { throw new Error('Missing revoke or audit evidence'); }
      // Ordering proof on the same server clock: the write was fixed before the revoke.
      expect(revokedAt.getTime()).toBeGreaterThan(occurredAt.getTime());
      const snapshot = async (): Promise<{ staff: number; audit: number }> => {
        const staff = await db.query<{ count: number }>("SELECT count(*)::int AS count FROM foundation.staff WHERE role = 'TECHNICIAN'");
        const rows = await db.query<{ count: number }>("SELECT count(*)::int AS count FROM foundation.audit_logs WHERE operation = 'STAFF_CREATED'");
        return { staff: staff.rows[0]?.count ?? 0, audit: rows.rows[0]?.count ?? 0 };
      };
      expect(await snapshot()).toEqual({ staff: 3, audit: 3 });
      const denied = await request(server).post('/api/v1/staff').set('Origin', origin).set('Cookie', managerCookie)
        .set('X-CSRF-Token', managerCsrf).send({ role: 'TECHNICIAN' }).expect(403);
      collect(denied.body);
      // No write happens after the revoke is fixed: neither a staff row nor an audit row.
      expect(await snapshot()).toEqual({ staff: 3, audit: 3 });
    } finally {
      await locker.query('ROLLBACK').catch(() => undefined);
      await locker.end();
      await revoker.end();
    }
  }, 30000);

  it('turns every staff route into 401 after the actor is deactivated', async () => {
    if (!fixture) { throw new Error('Missing isolated fixture'); }
    const db = fixture;
    // staff.read is still granted here; only the employment state changes.
    const stillActive = await request(server).get('/api/v1/staff').set('Origin', origin).set('Cookie', managerCookie).expect(200);
    collect(stillActive.body);
    await db.query("UPDATE foundation.staff SET employment_state = 'INACTIVE' WHERE id = $1", [managerId]);
    const list = await request(server).get('/api/v1/staff').set('Origin', origin).set('Cookie', managerCookie).expect(401);
    collect(list.body);
    cacheControls.push(list.headers['cache-control'] ?? '');
    const detail = await request(server).get(`/api/v1/staff/${managerId}`).set('Origin', origin).set('Cookie', managerCookie).expect(401);
    collect(detail.body);
    cacheControls.push(detail.headers['cache-control'] ?? '');
    const write = await request(server).post('/api/v1/staff').set('Origin', origin).set('Cookie', managerCookie)
      .set('X-CSRF-Token', managerCsrf).send({ role: 'TECHNICIAN' }).expect(401);
    collect(write.body);
    cacheControls.push(write.headers['cache-control'] ?? '');
  });

  it('keeps the staff-v0 ETag and no-store, and keeps secrets out of bodies and logs', async () => {
    if (!fixture || !logs) { throw new Error('Missing isolated fixture'); }
    const db = fixture;
    expect(createEtag).toBe('"staff-v0"');
    expect(cacheControls.length).toBeGreaterThanOrEqual(8);
    for (const value of cacheControls) { expect(value).toBe('no-store'); }
    const hashes = await db.query<{ password_hash: string }>('SELECT password_hash FROM foundation.staff_web_credentials WHERE staff_id = $1', [managerId]);
    const hash = hashes.rows[0]?.password_hash;
    const serialized = JSON.stringify({ responses, logs: logs.mock.calls });
    for (const secret of [adminLogin, managerLogin, adminPassword, managerPassword, managerToken, hash]) {
      if (secret) { expect(serialized).not.toContain(secret); }
    }
  });
});
