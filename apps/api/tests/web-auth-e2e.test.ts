import 'reflect-metadata';
import { randomBytes } from 'node:crypto';
import type { Server } from 'node:http';
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
import { migrateAuthFixture } from './auth-db-fixture.js';
import { admitFixture } from './admission-fixture.js';
import type { AdmittedHandle } from './admission-fixture.js';
import { becomeOwner, dropOwnedTestDatabase, fixtureCredentials, maintenanceOpener } from './owned-test-database.js';

// Explicit opt-in: preserve the random fixture database, never modify the dev schema.
const integration = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1' ? describe : describe.skip;
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
  let admission: AdmittedHandle | undefined;
  let app: Awaited<ReturnType<typeof createApi>> | undefined;
  let server: Server;
  let staffId: string;
  let dbName: string | undefined;
  let dbCreated = false;
  let tornDown = false;

  /** Ownership proof for the teardown drop, consumed exactly once: this run's CREATE
   * result (flag) AND the strict disposable-name pattern. */
  const takeOwnedDatabase = (): string | undefined => {
    if (!dbCreated) { return undefined; }
    dbCreated = false;
    return dbName !== undefined && /^fixlevelup_auth_e2e_test_[a-f0-9]{24}$/.test(dbName) ? dbName : undefined;
  };

  /** The afterAll teardown, exactly once: this run's pools/clients down first, then
   * the drop of exactly the database this run created. A second call is a no-op. */
  async function teardown(): Promise<void> {
    if (tornDown) { return; }
    tornDown = true;
    const ownedDatabase = takeOwnedDatabase();
    try { await app?.close(); }
    finally {
      try { await admission?.release(); }
      finally {
        try { await migrator?.end(); }
        finally {
          try { await fixture?.end(); }
          finally {
            try {
              if (ownedDatabase !== undefined && admin !== undefined) {
                await dropOwnedTestDatabase(admin, ownedDatabase);
              }
            } finally { try { await admin?.end(); } finally { vi.restoreAllMocks(); } }
          }
        }
      }
    }
  }

  beforeAll(async () => {
    // Lab mode reads the lab process env and the attested maintenance binding;
    // dev mode reads the local ignored env files. Never the dev database.
    const { migrator: migratorPassword, runtime: runtimePassword } = fixtureCredentials();
    const connection = { host: '127.0.0.1' as const, port: 55432 };
    admin = await maintenanceOpener()();
    const database = `fixlevelup_auth_e2e_test_${randomBytes(12).toString('hex')}`;
    await admin.query(`CREATE DATABASE "${database}" OWNER fixlevelup_migrator TEMPLATE template0`);
    // CREATE is the reuse guard: an existing name is a hard error, so a successful
    // CREATE proves this run owns the disposable database (the flag gates the drop).
    dbName = database;
    dbCreated = true;
    try {
      // GRANT/REVOKE need the owner: in the lab the orchestrator is a NOINHERIT member.
      await becomeOwner(admin);
      await admin.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`);
      await admin.query(`GRANT CONNECT ON DATABASE "${database}" TO fixlevelup_migrator, fixlevelup_runtime`);
      fixture = new Client({ ...connection, database, user: 'fixlevelup_migrator', password: migratorPassword });
      await fixture.connect();
      await migrateAuthFixture(fixture, database);
      await fixture.query('CREATE TABLE foundation._prisma_migrations (id text PRIMARY KEY)');
      migrator = new Pool({ ...connection, database, user: 'fixlevelup_migrator', password: migratorPassword });
      ({ staffId } = await bootstrapFirstAdmin(migrator, { login, password: oldPassword }));
      const dbConfig = { ...connection, database, user: 'fixlevelup_runtime' as const, password: runtimePassword } as DatabaseConfig;
      const webAuth: WebAuthConfig = { origin, csrfSecret: 'a'.repeat(64), throttleSecret: 'b'.repeat(64) };
      // P05-01: the app is admitted through the same launch gate contour — a real
      // migrator-held witness in this fixture DB pins the admission.
      admission = await admitFixture(migrator, database, 'API');
      app = await createApi(loadConfig({ NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0' }), new SafeLogger('api'), dbConfig, webAuth, undefined, admission.authorization);
      server = app.getHttpServer() as Server;
    } catch (error) {
      // Provisioning failed after CREATE: run the same lifecycle cleanup before rethrowing.
      await teardown().catch(() => undefined);
      throw error;
    }
  }, 30000);

  afterAll(teardown);

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
