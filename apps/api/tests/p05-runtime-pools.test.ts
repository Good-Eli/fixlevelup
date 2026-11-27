import { execFileSync } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client, Pool } from 'pg';
import type { PoolConfig } from 'pg';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { WebAuthResources } from '../src/auth/web-auth.resources.js';
import { TelegramAuthResources } from '../src/auth/telegram-auth.resources.js';
import { AuthorizationResources } from '../src/authz/authorization.resources.js';
import { createApi, createWorker } from '../src/bootstrap/factories.js';
import type { ProcessAuthorization } from '../src/infrastructure/admission/process-admission.js';
import { verifyPhysicalProfile } from '../src/infrastructure/admission/physical-profile.js';
import { RuntimeDatabase } from '../src/infrastructure/database/runtime-database.js';
import type { DatabaseConfig } from '../src/infrastructure/database/runtime-database.js';
import { OutboxStore } from '../src/infrastructure/outbox/outbox-store.js';
import { OutboxWorker } from '../src/infrastructure/outbox/outbox-worker.js';
import { requestEffectsAuditStore } from '../src/requests/intake/coverage.js';
import { loadKeyring } from '../src/requests/crypto/keyring.js';
import { loadConfig } from '../src/runtime/config.js';
import { SafeLogger } from '../src/runtime/safe-logger.js';
import { admitVerifiedTestInstance, issueVerifiedLaunch } from './admission-fixture.js';
import { authFixtureMigrations, verifyOperatorMigrationHistory } from './auth-db-fixture.js';
import { createConfigurationFixture } from './configuration-fixture.js';
import type { ConfigurationFixture } from './configuration-fixture.js';
import { fixtureCredentials } from './owned-test-database.js';
import { startIsolatedIntake } from './p05-composition.js';
import { supportedFixturePolicies } from './p05-request-fixtures.js';
import { createP05RuntimeClone, p05CloneTests, readP05CloneIdentity } from './p05-runtime-clone-fixture.js';

// Instrument, do not emulate, pg.Pool. The subclass uses the real pg client,
// options/checkout and events. No production hook, SQL stub or minted marker.
const trace = vi.hoisted(() => ({ pools: [] as { application: string; driver: Pool }[] }));
vi.mock(import('pg'), async load => {
  const pg = await load();
  class TracedPool extends pg.Pool {
    constructor(options?: PoolConfig) {
      super(options);
      trace.pools.push({ application: options?.application_name ?? '', driver: this });
    }
  }
  return { ...pg, Pool: TracedPool };
});

const live = process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1'
  && process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1';
const origin = 'https://crm.example.test';
const hex = () => randomBytes(32).toString('hex');
const web = { origin, csrfSecret: hex(), throttleSecret: hex() };
const telegram = { botToken: `7000000002:${hex()}` };
const form = { origin, csrfKeyring: { current: { keyId: 'p05-pool-test', secret: randomBytes(32) } }, throttleSecret: randomBytes(32),
  groupTtlMs: 900000, anchorTtlMs: 600000, csrfTtlMs: 300000, throttles: {
    source: { windowSeconds: 600, maxHits: 300 }, global: { windowSeconds: 600, maxHits: 300 }, anchor: { windowSeconds: 600, maxHits: 60 },
  } };
const apiConfig = loadConfig({ NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0' });
const keyring = () => loadKeyring({ activeKekId: 'test-kek-1', activeHmacKeyId: 'test-hmac-1',
  kek: [{ keyId: 'test-kek-1', secretHex: hex() }], hmac: [{ keyId: 'test-hmac-1', secretHex: hex() }] });
const target = (database: string): DatabaseConfig => ({ host: '127.0.0.1', port: 55432, user: 'fixlevelup_runtime', database,
  password: fixtureCredentials().runtime });
const options = (binding: DatabaseConfig, authorization: ProcessAuthorization, tls: { key: Buffer; cert: Buffer }) => ({
  target: binding, authorization, tls, form, staff: web,
  configure: () => ({ ring: keyring(), environment: 'p05-isolated', currentPolicyId: randomUUID(),
    // No app data/key operation belongs to these pool-only probes.
    keySlots: { environment: 'p05-isolated', create: () => Promise.reject(new Error('Not a key operation')),
      read: () => Promise.reject(new Error('Not a key operation')) },
    formSourceEntryId: randomUUID(), supportedPolicies: supportedFixturePolicies() }),
});
function tlsFixture() {
  const dir = mkdtempSync(join(tmpdir(), 'p05-pools-'));
  try {
    const key = join(dir, 'key.pem'), cert = join(dir, 'cert.pem');
    execFileSync('openssl', ['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
      '-keyout',key,'-out',cert], { stdio: 'ignore', timeout: 10_000 });
    return { key: readFileSync(key), cert: readFileSync(cert) };
  } finally { rmSync(dir, { force: true, recursive: true }); }
}

const capCases = [
  { profile:'S0', capBefore:'20261123000100_request_intake_foundation', count:21 },
  { profile:'S1', capBefore:'20261124000100_form_session_foundation', count:22 },
  { profile:'S2', capBefore:'20261125000100_request_intake_effects', count:23 },
  { profile:'S3', capBefore:undefined, count:24 },
] as const;
type TestCap = typeof capCases[number];
const createFixture = (cap: TestCap) => createConfigurationFixture(cap.capBefore ? { capBefore: cap.capBefore } : {});
const token = () => randomBytes(32).toString('base64url');
const caps = [
  ['API', 'Prisma', 'fixlevelup-api-runtime'],
  ['API', 'raw readiness', 'fixlevelup-api-runtime'],
  ['API', 'web auth', 'fixlevelup-web-auth'],
  ['API', 'Telegram auth', 'fixlevelup-telegram-auth'],
  ['API', 'authorization', 'fixlevelup-authz'],
  ['WORKER', 'worker readiness', 'fixlevelup-api-runtime'],
  ['WORKER', 'outbox claim', 'fixlevelup-outbox-runtime'],
  ['TEST', 'T business', 'fixlevelup-intake-isolated'],
  ['TEST', 'T evidence', 'fixlevelup-intake-audit-isolated'],
] as const;
type Consumer = typeof caps[number];

async function consumer(item: Consumer, database: DatabaseConfig, authorization: ProcessAuthorization, tls: { key: Buffer; cert: Buffer }) {
  const name = item[1];
  const start = trace.pools.length;
  let invoke: () => Promise<unknown>;
  let close: () => Promise<void>;
  let healthy: unknown;
  let refused: unknown;
  if (name === 'Prisma' || name === 'raw readiness' || name === 'worker readiness') {
    const resource = new RuntimeDatabase(database, true, authorization, item[0]);
    invoke = () => name === 'raw readiness' ? resource.catalogManagementReady() : resource.ready();
    close = () => resource.onModuleDestroy(); healthy = true; refused = false;
  } else if (name === 'web auth' || name === 'Telegram auth') {
    const resource = name === 'web auth' ? new WebAuthResources(database, web, authorization)
      : new TelegramAuthResources(database, telegram, web.throttleSecret, authorization);
    const source = token();
    invoke = async () => await resource.service.authenticate(source).then(() => 'accepted', (error: unknown) => statusOf(error));
    close = () => resource.onModuleDestroy(); healthy = 'UNAUTHORIZED'; refused = 'FAILED';
  } else if (name === 'authorization') {
    const resource = new AuthorizationResources(database, authorization);
    const proof = { kind: 'staff-web', token: token() } as const;
    invoke = () => resource.service.inspectAccess(proof).then(() => 'accepted', (error: unknown) => statusOf(error));
    close = () => resource.onModuleDestroy(); healthy = 'UNAUTHORIZED'; refused = 500;
  } else if (name === 'outbox claim') {
    const resource = new OutboxStore(database, authorization);
    invoke = () => resource.claim(randomUUID(), ['P05_POOL_PROBE_NO_MATCH'])
      .then(result => result === undefined ? 'NO_MATCH' : 'CLAIMED', (error: unknown) => statusOf(error));
    close = () => resource.close(); healthy = 'NO_MATCH'; refused = 'ADMISSION_REQUIRED';
  } else {
    let audit: ReturnType<typeof requestEffectsAuditStore> | undefined;
    const intake = options(database, authorization, tls);
    const app = await startIsolatedIntake({ ...intake, configure(pool) { audit = requestEffectsAuditStore(pool); return intake.configure(); } });
    close = () => app.app.close();
    if (name === 'T business') {
      invoke = () => app.filePool.query<{ ok: number }>('SELECT 39 AS ok').then(result => result.rows[0]?.ok, (error: unknown) => statusOf(error));
      healthy = 39; refused = 'ADMISSION_REQUIRED';
    } else {
      if (!audit) { await close(); throw new Error('Missing T evidence store'); }
      const port: ReturnType<typeof requestEffectsAuditStore> = audit;
      invoke = () => port.record({ evidenceId: randomUUID(), staffId: randomUUID(), requestId: randomUUID(),
        addressRevisionId: randomUUID(), purpose: 'COVERAGE_REVIEW', correlationId: randomUUID() });
      healthy = 'COMMITTED'; refused = 'UNCONFIRMED';
    }
  }
  const pools = trace.pools.slice(start).filter(entry => entry.application === item[2]);
  const driver = pools[0]?.driver;
  if (pools.length !== 1 || !driver) { await close(); throw new Error(`Missing unique PG pool for ${name}`); }
  return { invoke, close, driver, healthy, refused };
}

function statusOf(error: unknown): unknown {
  if (typeof error !== 'object' || error === null) { return undefined; }
  return 'code' in error ? error.code : 'status' in error ? error.status : undefined;
}
function statements(tap: { mock: { calls: unknown[][]; contexts: unknown[] } }, application: string) {
  const seen: string[] = [];
  for (const [index, args] of tap.mock.calls.entries()) {
    const connection = tap.mock.contexts[index];
    if (!(connection instanceof Client)
      || (connection as Client & { connectionParameters: { application_name?: string } }).connectionParameters.application_name !== application) { continue; }
    const sql = args[0];
    if (typeof sql === 'string') { seen.push(sql); }
    else if (typeof sql === 'object' && sql !== null && 'text' in sql && typeof sql.text === 'string') { seen.push(sql.text); }
  }
  return seen;
}
const gateSql = (sql: string | undefined) => sql?.includes('pg_catalog.pg_locks') && sql.includes('AS dboid');

it.runIf(p05CloneTests)('outbox claim rejects an independent primary with identical S3 identity before business SQL',
  { timeout: 60_000 }, async () => {
    const fixture = await createP05RuntimeClone();
    const clients: Client[] = [];
    const keep = async (pending: Promise<Client>) => {
      const client = await pending;
      clients.push(client);
      return client;
    };
    try {
      const source = await keep(fixture.openSourceRuntime());
      const clone = await keep(fixture.openCloneRuntime());
      const sourceOperator = await keep(fixture.openSourceMigrator());
      const cloneOperator = await keep(fixture.openCloneMigrator());
      // This helper runs issueVerifiedLaunch and the actual admitProcess / decideLaunch CAS.
      const launch = await admitVerifiedTestInstance(sourceOperator, fixture.runtime.database, { consumerKind: 'WORKER' });
      try {
        const { admission } = launch.authorization;
        const { binding } = admission;
        expect(binding.profile).toBe('S3');
        expect(binding.databaseOid).toBe(fixture.oid);
        const identity = { database: binding.database, oid: binding.databaseOid, user: binding.role,
          sessionUser: binding.role, schema: binding.schema, owner: 'fixlevelup_migrator',
          host: '127.0.0.1', version: '180007', primary: true };
        expect(await readP05CloneIdentity(source)).toEqual({ ...identity, port: fixture.runtime.port, cluster: fixture.sourceCluster });
        expect(await readP05CloneIdentity(clone)).toEqual({ ...identity, port: fixture.cloneRuntime.port, cluster: fixture.cloneCluster });
        expect(fixture.cloneCluster).not.toEqual(fixture.sourceCluster);
        for (const operator of [sourceOperator, cloneOperator]) {
          expect(await verifyOperatorMigrationHistory(operator)).toEqual({ ok: true,
            historyManifestDigest: binding.expected.historyManifestDigest });
        }
        // Catalog checks on the actual unprivileged runtime role; no profile stand-in.
        for (const runtime of [source, clone]) {
          expect(await verifyPhysicalProfile(runtime, fixture.runtime, 'S3')).toBe(true);
        }
        await expect(admission.gate.verifyConnection(source, new Date())).resolves.toBeUndefined();

        const eventType = 'P05_INDEPENDENT_CLONE_PROBE', eventId = randomUUID(), owner = randomUUID();
        await cloneOperator.query(`INSERT INTO foundation.outbox_events (id,event_id,event_type,next_attempt_at)
          VALUES ($1,$2,$3,clock_timestamp()-interval '1 minute')`, [randomUUID(), eventId, eventType]);
        const snapshot = async () => (await cloneOperator.query<{ effect: unknown; claimable: boolean }>(`SELECT to_jsonb(e) AS effect,
          next_attempt_at <= clock_timestamp() AND status='PENDING' AND lease_owner IS NULL AS claimable
          FROM foundation.outbox_events e WHERE event_id=$1`, [eventId])).rows;
        const before = await snapshot();
        expect(before).toHaveLength(1);
        expect(before[0]?.claimable).toBe(true);
        expect(before[0]?.effect).toMatchObject({ event_id: eventId, status: 'PENDING',
          lease_owner: null, lease_expires_at: null, lease_generation: 0, attempt_count: 0 });

        const appName = 'fixlevelup-outbox-runtime';
        const marker = trace.pools.length;
        const outbox = new OutboxStore(fixture.runtime, launch.authorization);
        try {
          const entries = trace.pools.slice(marker).filter(entry => entry.application === appName);
          expect(entries).toHaveLength(1);
          const driver = entries[0]?.driver;
          if (!driver) { throw new Error('Missing real outbox pool'); }
          const spy = vi.spyOn(Client.prototype, 'query');
          try {
            await expect(outbox.claim(owner, [eventType])).resolves.toBeUndefined();
            const healthy = statements(spy, appName);
            expect(gateSql(healthy[0])).toBe(true);
            expect(healthy.at(-1)).toContain('UPDATE foundation.outbox_events');
            await expect.poll(() => driver.totalCount, { timeout: 3500, interval: 25 }).toBe(0);

            // Redirect only the real driver's next socket, not the immutable admission
            // or application config. The two primaries share credential and DB identity.
            const original = driver.options.port;
            driver.options.port = fixture.cloneRuntime.port;
            try {
              spy.mockClear();
              await expect(outbox.claim(owner, [eventType])).rejects.toMatchObject({
                code: 'ADMISSION_REQUIRED', reason: 'WITNESS_MISSING',
              });
              const seen = statements(spy, appName);
              expect(seen).toHaveLength(1);
              expect(gateSql(seen[0])).toBe(true);
              const checkout = spy.mock.contexts[0];
              if (!(checkout instanceof Client)) { throw new Error('Missing real clone checkout'); }
              expect({ host: checkout.host, port: checkout.port, database: checkout.database, user: checkout.user })
                .toEqual({ host: fixture.cloneRuntime.host, port: fixture.cloneRuntime.port,
                  database: binding.database, user: binding.role });
              const gateResult: unknown = spy.mock.results[0]?.value;
              await expect(gateResult).resolves.toMatchObject({ rows: [{ db: binding.database, dboid: binding.databaseOid,
                role: binding.role, schema: binding.schema, witness: null }] });
              expect(driver.totalCount).toBe(0); // failed socket evicted
            } finally { driver.options.port = original; }
            spy.mockClear();
            await expect(outbox.claim(owner, [eventType])).rejects.toMatchObject({ code: 'ADMISSION_REQUIRED' });
            expect(statements(spy, appName)).toEqual([]); // no revival after repairing the endpoint
          } finally { spy.mockRestore(); }
          await expect(admission.gate.verifyConnection(source, new Date())).resolves.toBeUndefined();
          expect(await snapshot()).toEqual(before); // no outbox lease or other mutation on the clone
        } finally { await outbox.close(); }
      } finally { await launch.release(); }
    } finally {
      await Promise.all(clients.map(client => client.end()));
    }
  });

describe.runIf(live)('P05 §7 all runtime consumers with independently faulted PG bindings', () => {
  let tls: ReturnType<typeof tlsFixture>;
  beforeAll(() => { tls = tlsFixture(); });

  it('constructs no pool and sends no query before completed admission, including shutdown/timer owners', { timeout: 25_000 }, async () => {
    const f = await createConfigurationFixture();
    try {
      const database = target(f.database);
      const issued = await issueVerifiedLaunch(f.migrator, database, { consumerKind: 'API' });
      try {
        const incomplete = { admission: issued.admission, completed: Object.freeze({}) as ProcessAuthorization['completed'] };
        const marker = trace.pools.length;
        const connect = vi.spyOn(Client.prototype, 'connect');
        const query = vi.spyOn(Client.prototype, 'query');
        const timer = vi.spyOn(globalThis, 'setInterval');
        try {
          await expect(createApi(apiConfig, new SafeLogger('api'), database, web, telegram)).rejects.toThrow();
          await expect(createApi(apiConfig, new SafeLogger('api'), database, web, telegram, incomplete)).rejects.toThrow();
          await expect(createWorker(new SafeLogger('worker'), database)).rejects.toThrow();
          await expect(createWorker(new SafeLogger('worker'), database, incomplete)).rejects.toThrow();
          await expect(startIsolatedIntake(options(database, incomplete, tls))).rejects.toThrow();
          for (const make of [
            () => new RuntimeDatabase(database, true, incomplete), () => new WebAuthResources(database, web, incomplete),
            () => new TelegramAuthResources(database, telegram, web.throttleSecret, incomplete),
            () => new AuthorizationResources(database, incomplete), () => new OutboxStore(database, incomplete),
            () => new OutboxWorker(database, new SafeLogger('worker'), new Map(), incomplete),
          ]) { expect(make).toThrow(); }
          expect(trace.pools).toHaveLength(marker);
          expect(connect).not.toHaveBeenCalled();
          expect(query).not.toHaveBeenCalled();
          expect(timer).not.toHaveBeenCalled();
        } finally { timer.mockRestore(); query.mockRestore(); connect.mockRestore(); }
      } finally { await issued.release(); }
    } finally { await f.close(); }
  });

  for (const cap of capCases) {
    describe(`${cap.profile}: ${String(cap.count)} migrations`, () => {
      let f: ConfigurationFixture;
      let foreign: ConfigurationFixture;
      beforeAll(async () => { f = await createFixture(cap); foreign = await createFixture(cap); }, 30_000);
      afterAll(async () => { try { await foreign.close(); } finally { await f.close(); } });
      for (const subject of caps.filter(item => item[0] !== 'TEST' || cap.profile === 'S3')) {
        for (const fault of ['physical rebind', 'post-admission drift'] as const) {
          it(`${subject[1]} / ${fault}`, { timeout: 25_000 }, async () => {
            const [kind, , appName] = subject;
            const launch = await admitVerifiedTestInstance(f.migrator, f.database, { consumerKind: kind,
              expectedMigrations: authFixtureMigrations.slice(0, cap.count) });
            expect(launch.authorization.admission.binding.profile).toBe(cap.profile);
            try {
              const probe = await consumer(subject, target(f.database), launch.authorization, tls);
              try {
                const spy = vi.spyOn(Client.prototype, 'query');
                try {
                  expect(await probe.invoke()).toEqual(probe.healthy);
                  const positive = statements(spy, appName);
                  expect(gateSql(positive[0])).toBe(true);
                  expect(positive).toContain('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
                  expect(positive.at(-1)).not.toBeUndefined();
                  if (fault === 'physical rebind') {
                    // Wait until the original idle PG socket expires, then redirect
                    // only this named driver's next socket to an exact-profile DB
                    // without this instance's witness. Runtime config is unchanged.
                    await expect.poll(() => probe.driver.totalCount, { timeout: 3500, interval: 25 }).toBe(0);
                    const original = probe.driver.options.database;
                    probe.driver.options.database = foreign.database;
                    try {
                      spy.mockClear();
                      expect(await probe.invoke()).toEqual(probe.refused);
                      const calls = statements(spy, appName);
                      expect(calls).toHaveLength(1);
                      expect(gateSql(calls[0])).toBe(true);
                      expect(spy.mock.contexts.some(candidate => candidate instanceof Client && candidate.database === foreign.database)).toBe(true);
                    } finally { if (original !== undefined) { probe.driver.options.database = original; } }
                  } else {
                    // One reversible ACL drift checked on every supported cap.
                    await f.migrator.query('GRANT SELECT ON foundation._prisma_migrations TO fixlevelup_runtime');
                    try {
                      spy.mockClear();
                      expect(await probe.invoke()).toEqual(probe.refused);
                      const after = statements(spy, appName);
                      expect(gateSql(after[0])).toBe(true);
                      expect(after[1]).toBe('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
                      // Only the metadata probe executes, then finishes read-only.
                      expect(after.slice(2, -1)).toHaveLength(1);
                      expect(after.at(-1)).toBe('ROLLBACK');
                    } finally { await f.migrator.query('REVOKE SELECT ON foundation._prisma_migrations FROM fixlevelup_runtime'); }
                  }
                  spy.mockClear();
                  expect(await probe.invoke()).toEqual(probe.refused);
                  expect(statements(spy, appName)).toEqual([]); // no revival after repair
                } finally { spy.mockRestore(); }
              } finally { await probe.close(); }
            } finally { await launch.release(); }
          });
        }
      }
    });
  }
});
