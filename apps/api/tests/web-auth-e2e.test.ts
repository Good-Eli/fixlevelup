import 'reflect-metadata';
import { randomBytes } from 'node:crypto';
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

// Explicit opt-in: preserve the random fixture database, never modify the dev schema.
const integration = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1' ? describe : describe.skip;
const root = resolve(import.meta.dirname, '../../..');
const migrations = [
  '20261120000100_technical_audit_outbox',
  '20261120000200_technical_outbox_attempts',
  '20261120000300_technical_outbox_leases',
  '20261120000400_staff_identity',
  '20261120000500_web_auth',
];
const origin = 'https://crm.example.test';
const cookieName = '__Host-fixlevelup_session';
const oldPassword = 'Synthetic-E2E-Old-Password-2026!';
const newPassword = 'Synthetic-E2E-New-Password-2026!';
const login = `e2e-${randomBytes(12).toString('hex')}`;

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

integration('web auth real HTTP against isolated PostgreSQL', () => {
  let admin: Client | undefined;
  let fixture: Client | undefined;
  let migrator: Pool | undefined;
  let app: Awaited<ReturnType<typeof createApi>> | undefined;
  let server: Server;
  let staffId: string;

  beforeAll(async () => {
    const adminEnv = readFileSync(resolve(root, 'infra/dev-postgres/.env'), 'utf8');
    const runtimeEnv = readFileSync(resolve(root, 'packages/database-tooling/.env'), 'utf8');
    const adminPassword = /^POSTGRES_PASSWORD=([a-f0-9]{64})$/m.exec(adminEnv)?.[1];
    const runtimePassword = /^FIXLEVELUP_RUNTIME_PASSWORD=([a-f0-9]{64})$/m.exec(runtimeEnv)?.[1];
    const migratorPassword = /^FIXLEVELUP_MIGRATOR_PASSWORD=([a-f0-9]{64})$/m.exec(runtimeEnv)?.[1];
    if (!adminPassword || !runtimePassword || !migratorPassword) { throw new Error('Local isolated PostgreSQL test credentials are required'); }
    const connection = { host: '127.0.0.1' as const, port: 55432 };
    admin = new Client({ ...connection, database: 'fixlevelup_dev', user: 'fixlevelup_dev', password: adminPassword });
    await admin.connect();
    const database = `fixlevelup_auth_e2e_test_${randomBytes(12).toString('hex')}`;
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
    ({ staffId } = await bootstrapFirstAdmin(migrator, { login, password: oldPassword }));
    const dbConfig = { ...connection, database, user: 'fixlevelup_runtime' as const, password: runtimePassword } as DatabaseConfig;
    const webAuth: WebAuthConfig = { origin, csrfSecret: 'a'.repeat(64), throttleSecret: 'b'.repeat(64) };
    app = await createApi(loadConfig({ NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0' }), new SafeLogger('api'), dbConfig, webAuth);
    server = app.getHttpServer() as Server;
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

  it('enforces CSRF and rotates credentials through the complete session lifecycle', async () => {
    const logs = vi.spyOn(ConsoleLogger.prototype, 'log').mockImplementation(() => undefined);
    const responses: unknown[] = [];
    const collect = (body: unknown) => { responses.push(body); };
    const ready = await request(server).get('/health/ready').expect(200);
    collect(ready.body);
    const rejectedLogin = await request(server).post('/api/v1/auth/login').set('Origin', origin)
      .send({ login, password: oldPassword }).expect(403);
    collect(rejectedLogin.body);
    const initial = await request(server).post('/api/v1/auth/login').set('Origin', origin).set('X-CSRF-Token', 'login')
      .send({ login, password: oldPassword }).expect(200);
    collect(initial.body);
    expect(initial.headers['cache-control']).toBe('no-store');
    const first = session(initial.headers);
    const firstCsrf = csrf(initial.body);
    const otherLogin = await request(server).post('/api/v1/auth/login').set('Origin', origin).set('X-CSRF-Token', 'login')
      .send({ login, password: oldPassword }).expect(200);
    collect(otherLogin.body);
    const other = session(otherLogin.headers);
    expect(other.token).not.toBe(first.token);
    const me = await request(server).get('/api/v1/auth/me').set('X-Auth-Request', '1').set('Cookie', first.cookie).expect(200);
    collect(me.body);
    expect(me.body).toMatchObject({ data: { staffId, role: 'ADMIN', csrfToken: firstCsrf } });
    const rejectedRenew = await request(server).post('/api/v1/auth/session/renew').set('Origin', origin)
      .set('Cookie', first.cookie).set('X-CSRF-Token', 'wrong').send({}).expect(403);
    collect(rejectedRenew.body);
    const renewed = await request(server).post('/api/v1/auth/session/renew').set('Origin', origin)
      .set('Cookie', first.cookie).set('X-CSRF-Token', firstCsrf).send({}).expect(200);
    collect(renewed.body);
    const current = session(renewed.headers);
    const currentCsrf = csrf(renewed.body);
    expect(current.token).not.toBe(first.token);
    expect(currentCsrf).not.toBe(firstCsrf);
    const replay = await request(server).get('/api/v1/auth/me').set('X-Auth-Request', '1').set('Cookie', first.cookie).expect(401);
    collect(replay.body);
    const rejectedCsrf = await request(server).post('/api/v1/auth/password/change').set('Origin', origin)
      .set('Cookie', current.cookie).set('X-CSRF-Token', firstCsrf).set('If-Match', String(renewed.headers['etag']))
      .send({ currentPassword: oldPassword, newPassword }).expect(403);
    collect(rejectedCsrf.body);
    const missingMatch = await request(server).post('/api/v1/auth/password/change').set('Origin', origin)
      .set('Cookie', current.cookie).set('X-CSRF-Token', currentCsrf).send({ currentPassword: oldPassword, newPassword }).expect(428);
    collect(missingMatch.body);
    const changed = await request(server).post('/api/v1/auth/password/change').set('Origin', origin)
      .set('Cookie', current.cookie).set('X-CSRF-Token', currentCsrf).set('If-Match', String(renewed.headers['etag']))
      .send({ currentPassword: oldPassword, newPassword }).expect(200);
    collect(changed.body);
    expect(changed.body).toMatchObject({ data: { ok: true, authVersion: 1 } });
    expect(changed.headers['etag']).toBe('"auth-v1"');
    const invalidated = await request(server).get('/api/v1/auth/me').set('X-Auth-Request', '1').set('Cookie', other.cookie).expect(401);
    collect(invalidated.body);
    const stillActive = await request(server).get('/api/v1/auth/me').set('X-Auth-Request', '1').set('Cookie', current.cookie).expect(200);
    collect(stillActive.body);
    expect(stillActive.body).toMatchObject({ data: { staffId, authVersion: 1 } });
    const logout = await request(server).post('/api/v1/auth/logout').set('Origin', origin).set('Cookie', current.cookie)
      .set('X-CSRF-Token', currentCsrf).send({}).expect(204);
    collect(logout.body);
    expect(logout.headers['set-cookie']).toEqual([`${cookieName}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`]);
    const loggedOut = await request(server).get('/api/v1/auth/me').set('X-Auth-Request', '1').set('Cookie', current.cookie).expect(401);
    collect(loggedOut.body);
    if (!fixture) { throw new Error('Missing isolated fixture'); }
    const hashes = await fixture.query<{ password_hash: string }>('SELECT password_hash FROM foundation.staff_web_credentials WHERE staff_id = $1', [staffId]);
    const hash = hashes.rows[0]?.password_hash;
    expect(hash).toBeTruthy();
    const serialized = JSON.stringify({ responses, logs: logs.mock.calls });
    for (const secret of [login, oldPassword, newPassword, first.token, other.token, current.token, hash]) {
      if (secret) { expect(serialized).not.toContain(secret); }
    }
  }, 30000);
});
