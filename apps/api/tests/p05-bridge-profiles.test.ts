/**
 * P05 §7 Bridge B compatibility proof: the REAL production API and worker factories
 * against every schema profile (S0/S1/S2/S3), each on its own disposable database
 * inside the isolated lab, plus the explicit P05 role-revoke HTTP contract on the
 * expanded (024) profile.
 *
 * Scope rules for this file:
 *  - it is the only file changed by this task; no fixture or product source is edited;
 *  - every database is created by the reusable configuration fixture (owned lifecycle,
 *    pinned migration history) and capped exactly before the next P05 migration, so the
 *    admission preflight verifies the exact expected manifest through the cap;
 *  - API and WORKER use separate completed `admitVerifiedTestInstance` proofs (distinct
 *    launch facts), not one shared authorization;
 *  - the release composition is exercised through `createApi`/`createWorker` directly,
 *    and the P05/F families must stay 404 on every profile while real P03/P04
 *    reads/writes keep working;
 *  - the S3 case additionally proves, over real HTTP, that the legacy PUT body that
 *    omits an enabled P05 grant is refused (409) with zero effect, and that the explicit
 *    opt-in revocation succeeds with exactly one role-version epoch advance.
 *
 * Nothing here is a static substitute: each assertion runs against a real PostgreSQL
 * 18.7 database and the real factories.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { afterAll, describe, expect, it } from 'vitest';
import { P05_OPERATIONS, P05_PREFIX, P05_ROUTES } from '@fixlevelup/p03-contracts/p05';
import { createApi, createWorker } from '../src/bootstrap/factories.js';
import { hashPassword } from '../src/staff/password.js';
import { OutboxWorker } from '../src/infrastructure/outbox/outbox-worker.js';
import { loadConfig } from '../src/runtime/config.js';
import { SafeLogger } from '../src/runtime/safe-logger.js';
import { authFixtureMigrations } from './auth-db-fixture.js';
import { admitVerifiedTestInstance } from './admission-fixture.js';
import type { AdmittedHandle } from './admission-fixture.js';
import { configurationIntegration, createConfigurationFixture, createSyntheticCity } from './configuration-fixture.js';
import type { ConfigurationFixture } from './configuration-fixture.js';
import { fixtureCredentials } from './owned-test-database.js';

const labIntegration = process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1'
  ? configurationIntegration : describe.skip;
const ORIGIN = 'https://127.0.0.1:3100';
const CSRF_SECRET = 'c'.repeat(64);
const THROTTLE_SECRET = 'd'.repeat(64);
const RUNTIME = { host: '127.0.0.1' as const, port: 55432 as const, user: 'fixlevelup_runtime' as const };

/** The four reviewed schema profiles, each capped exactly before the next P05 migration. */
const PROFILES = [
  { profile: 'S0', capBefore: '20261123000100_request_intake_foundation' },
  { profile: 'S1', capBefore: '20261124000100_form_session_foundation' },
  { profile: 'S2', capBefore: '20261125000100_request_intake_effects' },
  { profile: 'S3', capBefore: undefined },
] as const;

/** Every canonical P05 operation and the S2 form-session family, as real paths. */
const P05_PATHS = P05_OPERATIONS.map((operation) => ({
  method: P05_ROUTES[operation].method,
  path: P05_PREFIX + P05_ROUTES[operation].path.replace(':id', '00000000-0000-4000-8000-0000000000a1'),
}));
const S2_PATHS = [
  { method: 'POST', path: '/api/v1/public/form-session/browser' },
  { method: 'POST', path: '/api/v1/public/form-sessions' },
  { method: 'POST', path: '/api/v1/public/form-session/csrf' },
  { method: 'POST', path: '/api/v1/public/form-session/revoke' },
  { method: 'POST', path: '/api/v1/public/form-session/consents' },
  { method: 'POST', path: '/api/v1/public/coverage/check' },
  { method: 'GET', path: '/api/v1/public/legal-documents/POLICY' },
] as const;

const manifestThrough = (capBefore: string | undefined): readonly string[] => {
  if (capBefore === undefined) { return authFixtureMigrations; }
  const index = authFixtureMigrations.indexOf(capBefore);
  if (index < 0) { throw new Error(`Unknown cap migration ${capBefore}`); }
  return authFixtureMigrations.slice(0, index);
};

const databaseOf = (fixture: ConfigurationFixture) => ({ ...RUNTIME, database: fixture.database,
  password: fixtureCredentials().runtime });

interface HttpReply { readonly status: number; readonly etag: string | undefined;
  readonly data: Record<string, unknown>; readonly setCookie: readonly string[] }

/** One real HTTPS-free loopback client over the compiled-in Nest app. */
function client(app: { getUrl(): Promise<string> }, cookie?: string) {
  let base: string | undefined;
  const send = async (method: string, path: string, options: {
    body?: unknown; csrf?: string; ifMatch?: string; idempotencyKey?: string; extraCookie?: string;
  } = {}): Promise<HttpReply> => {
    base ??= await app.getUrl();
    const headers: Record<string, string> = { origin: ORIGIN };
    if (options.body !== undefined) { headers['content-type'] = 'application/json'; }
    if (options.csrf !== undefined) { headers['x-csrf-token'] = options.csrf; }
    if (options.ifMatch !== undefined) { headers['if-match'] = options.ifMatch; }
    if (options.idempotencyKey !== undefined) { headers['idempotency-key'] = options.idempotencyKey; }
    const jar = [cookie, options.extraCookie].filter((value): value is string => Boolean(value)).join('; ');
    if (jar) { headers['cookie'] = jar; }
    const response = await fetch(base + path, { method, headers,
      ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }) });
    const text = await response.text();
    const parsed: unknown = text ? JSON.parse(text) : {};
    const envelope = parsed as { data?: Record<string, unknown> };
    return { status: response.status, etag: response.headers.get('etag') ?? undefined,
      data: envelope.data ?? {}, setCookie: response.headers.getSetCookie() };
  };
  return { send };
}

/** Gives the fixture's reviewed bootstrap administrator a known login/password and
 * the ordinary P04 catalog pair. Written by the migration owner, never by the app. */
async function prepareStaff(fixture: ConfigurationFixture): Promise<{ login: string; password: string }> {
  const login = `bridge-${randomUUID().slice(0, 8)}`;
  const password = `Synthetic-Bridge-${randomBytes(12).toString('hex')}`;
  await fixture.migrator.query(
    'UPDATE foundation.staff_web_credentials SET login=$2, password_hash=$3 WHERE staff_id=$1',
    [fixture.reviewer, login, await hashPassword(password)]);
  await fixture.migrator.query(`INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
    SELECT r.id,c,'GLOBAL' FROM foundation.roles r CROSS JOIN unnest($1::text[]) c
    WHERE r.role_type='SYSTEM' AND r.code='ADMIN'`, [['catalog.read', 'catalog.manage']]);
  return { login, password };
}

labIntegration('P05 §7 Bridge B on every schema profile (real factories)', () => {
  const created: ConfigurationFixture[] = [];
  const admitted: AdmittedHandle[] = [];
  afterAll(async () => {
    for (const handle of admitted) { await handle.release().catch(() => undefined); }
    for (const fixture of created) { await fixture.close().catch(() => undefined); }
  }, 120_000);

  it.each(PROFILES)('$profile: API and WORKER admit with distinct proofs, P05 stays 404, P03/P04 stay live',
    { timeout: 240_000 }, async ({ profile, capBefore }) => {
      const fixture = await createConfigurationFixture({ ...(capBefore === undefined ? {} : { capBefore }) });
      created.push(fixture);
      const city = await createSyntheticCity(fixture);
      const credentials = await prepareStaff(fixture);
      const database = databaseOf(fixture);
      const manifest = manifestThrough(capBefore);
      // Distinct completed proofs: the API and the WORKER never share an authorization.
      const api = await admitVerifiedTestInstance(fixture.migrator, fixture.database,
        { consumerKind: 'API', expectedMigrations: manifest });
      admitted.push(api);
      const worker = await admitVerifiedTestInstance(fixture.migrator, fixture.database,
        { consumerKind: 'WORKER', expectedMigrations: manifest });
      admitted.push(worker);
      expect(api.authorization.admission.binding.profile).toBe(profile);
      expect(worker.authorization.admission.binding.profile).toBe(profile);
      expect(api.authorization.admission.binding.expected.instanceId)
        .not.toBe(worker.authorization.admission.binding.expected.instanceId);

      const app = await createApi(loadConfig({ NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0' }),
        new SafeLogger('api'), database, { origin: ORIGIN, csrfSecret: CSRF_SECRET, throttleSecret: THROTTLE_SECRET },
        undefined, api.authorization);
      try {
        const anonymous = client(app);
        expect((await anonymous.send('GET', '/health/ready')).status).toBe(200);
        expect((await anonymous.send('GET', '/api/v1/staff/self')).status).toBe(401);
        // Every P05 and S2 route family is absent on every profile.
        for (const route of [...P05_PATHS,
          ...S2_PATHS.map((route) => ({ ...route }))]) {
          const reply = await anonymous.send(route.method, route.path);
          expect({ path: route.path, status: reply.status }).toEqual({ path: route.path, status: 404 });
        }
        const login = await anonymous.send('POST', '/api/v1/auth/login', { body: credentials,
          csrf: 'login' });
        expect(login.status).toBe(200);
        const cookie = login.setCookie[0]?.split(';')[0] ?? '';
        const csrf = typeof login.data['csrfToken'] === 'string' ? login.data['csrfToken'] : '';
        expect(cookie).toMatch(/^__Host-fixlevelup_session=/);
        expect(csrf.length).toBeGreaterThan(20);
        const staff = client(app, cookie);
        // Real P03 read: the trusted city list resolves through the geography port.
        const cities = await staff.send('GET', '/api/v1/settings/service-cities');
        expect(cities.status).toBe(200);
        expect(JSON.stringify(cities.data)).toContain(city.id);
        // Real P03 write: a district inside the synthetic city. The geography runner
        // requires an Idempotency-Key and the exact city If-Match version.
        const cityVersion = (await fixture.migrator.query<{ row_version: number }>(
          'SELECT row_version FROM foundation.service_cities WHERE id=$1', [city.id])).rows[0]?.row_version;
        const district = await staff.send('POST', `/api/v1/settings/service-cities/${city.id}/administrative-districts`,
          { body: { code: `d-${randomUUID().slice(0, 8)}`, name: 'Synthetic bridge district' }, csrf,
            idempotencyKey: randomUUID(), ifMatch: `"geo-v${String(cityVersion)}"` });
        expect(district.status).toBe(201);
        // Real P04 read + write: an ordinary catalog category.
        expect((await staff.send('GET', '/api/v1/catalog/categories')).status).toBe(200);
        const category = await staff.send('POST', '/api/v1/catalog/categories',
          { body: { code: `bridge-${randomUUID().slice(0, 8)}` }, csrf, idempotencyKey: randomUUID() });
        expect(category.status).toBe(201);
        expect(category.data['id']).toBeTruthy();
      } finally { await app.close(); }

      // Real WORKER factory on the same profile: an admitted context with no handlers
      // and an empty outbox claim (the release composition must not lease anything).
      const workerApp = await createWorker(new SafeLogger('worker'), database, worker.authorization);
      try {
        const pending = await fixture.migrator.query(`INSERT INTO foundation.outbox_events(id,event_id,event_type,payload)
          VALUES ($1,$2,'REQUEST_CALLBACK_INTENT','{"synthetic":true}'::jsonb) RETURNING id`, [randomUUID(), randomUUID()]);
        const eventId = (pending.rows[0] as { id: string }).id;
        const row = async () => (await fixture.migrator.query<{ encoded: string }>(
          'SELECT to_jsonb(e)::text AS encoded FROM foundation.outbox_events e WHERE id=$1', [eventId])).rows[0]?.encoded;
        const before = await row();
        await workerApp.get(OutboxWorker).runOnce();
        expect(await row()).toBe(before);
      } finally { await workerApp.close(); }
    });
});

labIntegration('P05 §7 explicit role revoke over real HTTP on the expanded S3 profile', () => {
  let fixture: ConfigurationFixture | undefined;
  let api: AdmittedHandle | undefined;
  afterAll(async () => {
    await api?.release().catch(() => undefined);
    await fixture?.close().catch(() => undefined);
  }, 60_000);

  it('legacy PUT omitting an enabled P05 grant is 409 with zero effect; explicit revoke advances one epoch',
    { timeout: 180_000 }, async () => {
      fixture = await createConfigurationFixture();
      const current = fixture;
      await createSyntheticCity(current);
      const credentials = await prepareStaff(current);
      const database = databaseOf(current);
      api = await admitVerifiedTestInstance(current.migrator, current.database,
        { consumerKind: 'API', expectedMigrations: authFixtureMigrations });
      expect(api.authorization.admission.binding.profile).toBe('S3');
      // Operator-owned synthetic provisioning of a CUSTOM role with the exact P05 pair.
      const roleId = randomUUID();
      const roleCode = `CUSTOM_BRIDGE_${roleId.slice(0, 8).toUpperCase()}`;
      await current.migrator.query('INSERT INTO foundation.roles(id,code,name) VALUES ($1,$2,$3)',
        [roleId, roleCode, 'Bridge revoke role']);
      await current.migrator.query(`INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
        VALUES ($1,'requests.read','CITY'),($1,'requests.review','CITY')`, [roleId]);
      const roleRow = async () => (await current.migrator.query<{ version: number }>(
        'SELECT version FROM foundation.roles WHERE id=$1', [roleId])).rows[0];
      const enabled = async (code: string) => (await current.migrator.query<{ enabled: boolean }>(
        'SELECT enabled FROM foundation.role_permissions WHERE role_id=$1 AND permission_code=$2',
        [roleId, code])).rows[0]?.enabled;

      const app = await createApi(loadConfig({ NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0' }),
        new SafeLogger('api'), database, { origin: ORIGIN, csrfSecret: CSRF_SECRET, throttleSecret: THROTTLE_SECRET },
        undefined, api.authorization);
      try {
        const anonymous = client(app);
        const login = await anonymous.send('POST', '/api/v1/auth/login', { body: credentials, csrf: 'login' });
        expect(login.status).toBe(200);
        const staff = client(app, login.setCookie[0]?.split(';')[0] ?? '');
        const csrf = typeof login.data['csrfToken'] === 'string' ? login.data['csrfToken'] : '';
        const path = `/api/v1/roles/${roleId}/permissions`;
        // 1) Legacy body that omits both enabled P05 grants: refused, nothing written.
        const versionBefore = (await roleRow())?.version;
        const legacy = await staff.send('PUT', path, { body: { permissions: [] }, csrf,
          ifMatch: `"role-v${String(versionBefore)}"` });
        expect(legacy.status).toBe(409);
        expect((await roleRow())?.version).toBe(versionBefore);
        expect(await enabled('requests.read')).toBe(true);
        expect(await enabled('requests.review')).toBe(true);
        // 2) Explicit opt-in revocation of one grant, the other retained by name.
        const revoked = await staff.send('PUT', path, { csrf, ifMatch: `"role-v${String(versionBefore)}"`,
          body: { permissions: [{ code: 'requests.read', scope: 'CITY' }], revokeP05Permissions: ['requests.review'] } });
        expect(revoked.status).toBe(200);
        expect(revoked.data['version']).toBe(Number(versionBefore) + 1);
        expect(await enabled('requests.review')).toBe(false);
        expect(await enabled('requests.read')).toBe(true);
        // 3) A hidden grant was not added: the enabled set is exactly the retained one.
        const enabledCodes = (await current.migrator.query<{ permission_code: string }>(
          'SELECT permission_code FROM foundation.role_permissions WHERE role_id=$1 AND enabled ORDER BY permission_code',
          [roleId])).rows.map((row) => row.permission_code);
        expect(enabledCodes).toEqual(['requests.read']);
        // 4) Stale If-Match on the new epoch is 412 and writes nothing.
        const stale = await staff.send('PUT', path, { csrf, ifMatch: `"role-v${String(versionBefore)}"`,
          body: { permissions: [{ code: 'requests.read', scope: 'CITY' }] } });
        expect(stale.status).toBe(412);
        expect((await roleRow())?.version).toBe(Number(versionBefore) + 1);
      } finally { await app.close(); }
    });
});


labIntegration('P05 S3 database boundary for request capability grants', () => {
  let fixture: ConfigurationFixture | undefined;
  afterAll(async () => { await fixture?.close().catch(() => undefined); }, 60_000);

  it('runtime direct DML cannot issue, reserve, reactivate, widen or delete a request grant',
    { timeout: 120_000 }, async () => {
      fixture = await createConfigurationFixture();
      const current = fixture;
      const roleId = randomUUID();
      await current.migrator.query('INSERT INTO foundation.roles(id,code,name) VALUES ($1,$2,$3)',
        [roleId, `CUSTOM_F01_GRANT_${roleId.slice(0,8).toUpperCase()}`, 'F-01 request grant guard fixture']);
      await current.migrator.query(`INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type,enabled)
        VALUES ($1,'requests.review','CITY',true),($1,'requests.create','CITY',false)`, [roleId]);

      const identity = await current.runtime.query<{ current_user: string; session_user: string;
        insert_columns: boolean; update_enabled: boolean; update_scope: boolean; delete_table: boolean }>(
        `SELECT current_user::text AS current_user,session_user::text AS session_user,
          has_column_privilege(current_user,'foundation.role_permissions','role_id','INSERT')
            AND has_column_privilege(current_user,'foundation.role_permissions','permission_code','INSERT')
            AND has_column_privilege(current_user,'foundation.role_permissions','scope_type','INSERT')
            AND has_column_privilege(current_user,'foundation.role_permissions','enabled','INSERT') AS insert_columns,
          has_column_privilege(current_user,'foundation.role_permissions','enabled','UPDATE') AS update_enabled,
          has_column_privilege(current_user,'foundation.role_permissions','scope_type','UPDATE') AS update_scope,
          has_table_privilege(current_user,'foundation.role_permissions','DELETE') AS delete_table`);
      expect(identity.rows[0]).toEqual({ current_user: 'fixlevelup_runtime', session_user: 'fixlevelup_runtime',
        insert_columns: true, update_enabled: true, update_scope: true, delete_table: false });

      // The INSERT column ACL exists for legacy role editing. The SECURITY INVOKER
      // trigger is the hard boundary that rejects P05 grants, including disabled
      // placeholders that could otherwise poison the unique role/permission key.
      for (const enabled of [true, false]) {
        await expect(current.runtime.query(`INSERT INTO foundation.role_permissions
          (role_id,permission_code,scope_type,enabled) VALUES ($1,'requests.cancel','CITY',$2)`, [roleId, enabled]))
          .rejects.toMatchObject({ code: '42501', message: 'Request grants are not issued by the runtime' });
      }

      // An existing disabled row cannot be activated by an application-side UPDATE.
      await expect(current.runtime.query(`UPDATE foundation.role_permissions SET enabled=true
        WHERE role_id=$1 AND permission_code='requests.create'`, [roleId]))
        .rejects.toMatchObject({ code: '42501', message: 'Request grants are not issued by the runtime' });

      // scope_type is an intentionally granted legacy column, but P05 grant
      // identity is immutable at the row-trigger boundary (CITY cannot be widened).
      await expect(current.runtime.query(`UPDATE foundation.role_permissions SET scope_type='GLOBAL'
        WHERE role_id=$1 AND permission_code='requests.review'`, [roleId]))
        .rejects.toMatchObject({ code: '23514', message: 'Immutable request grant identity' });
      await expect(current.runtime.query(`DELETE FROM foundation.role_permissions
        WHERE role_id=$1 AND permission_code='requests.review'`, [roleId]))
        .rejects.toMatchObject({ code: '42501' });

      const unchanged = (await current.migrator.query<{ permission_code: string; scope_type: string; enabled: boolean }>(
        `SELECT permission_code,scope_type,enabled FROM foundation.role_permissions
          WHERE role_id=$1 AND permission_code=ANY($2::text[]) ORDER BY permission_code`,
        [roleId, ['requests.create','requests.review']])).rows;
      expect(unchanged).toEqual([
        { permission_code: 'requests.create', scope_type: 'CITY', enabled: false },
        { permission_code: 'requests.review', scope_type: 'CITY', enabled: true },
      ]);

      // Narrow, safe operation retained: runtime may revoke but cannot re-enable.
      expect((await current.runtime.query(`UPDATE foundation.role_permissions SET enabled=false
        WHERE role_id=$1 AND permission_code='requests.review'`, [roleId])).rowCount).toBe(1);
      await expect(current.runtime.query(`UPDATE foundation.role_permissions SET enabled=true
        WHERE role_id=$1 AND permission_code='requests.review'`, [roleId]))
        .rejects.toMatchObject({ code: '42501', message: 'Request grants are not issued by the runtime' });
      expect((await current.migrator.query<{ enabled: boolean }>(
        `SELECT enabled FROM foundation.role_permissions WHERE role_id=$1 AND permission_code='requests.review'`,
        [roleId])).rows[0]?.enabled).toBe(false);
    });
});
