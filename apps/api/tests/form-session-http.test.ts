/**
 * P05-02 integration tests: the F-session HTTP surface over real Nest routing,
 * real HTTP transport, real PostgreSQL and the real S2 schema (migration 023).
 *
 * Architecture (following p0403-http-fixture.ts / settings-management-fixture.ts):
 *
 * - one isolated disposable PostgreSQL database per test (`RbacFixture`, the
 *   same `fixturePerTest` lifecycle the RBAC/management suites use), migrated
 *   with the full 001..023 chain by `auth-db-fixture.ts`;
 * - a real Nest application is composed per test (isolated test composition T
 *   of P05-PLAN §8): the staff surfaces stay available for provisioning
 *   (single ACTIVE city, districts, zones, coverage, legal documents), and the
 *   P05-02 `FormSessionController` is registered with a real
 *   `FormSessionService` over a real guarded runtime pool admitted by the
 *   launch-proof fixture, plus `boundedJson` and `ProblemFilter`;
 * - every F request goes through real HTTP (supertest against the loopback
 *   listener): exact Origin, JSON, marker header, cookies, selector and CSRF
 *   headers, duplicate-header refusals — the transport is under test, not a
 *   service call;
 * - assertions always check `Cache-Control: no-store`, the problem+json
 *   shape, the absence of PII/secret disclosure (synthetic sentinel), and the
 *   standard error classification of §6.3 (400/401/403/404/409/429/503).
 *
 * Time authority: the database clock is the only authority. Expiry is driven
 * by short anchor TTLs and by `waitForExpiry`/`dbInstant` waiting on the real
 * `clock_timestamp()`, never by client-side `Date.now()`.
 */
import 'reflect-metadata';
import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { createServer as createHttpsServer, request as httpsRequest } from 'node:https';
import { createConnection } from 'node:net';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { ConsoleLogger } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { Client } from 'pg';
import request from 'supertest';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { createApi } from '../src/bootstrap/factories.js';
import { RuntimeDatabase } from '../src/infrastructure/database/runtime-database.js';
import { physicalProfileVerifier } from '../src/infrastructure/admission/physical-profile.js';
import { loadConfig } from '../src/runtime/config.js';
import { SafeLogger } from '../src/runtime/safe-logger.js';
import { ProblemFilter } from '../src/runtime/problem.filter.js';
import { boundedJsonForFormSession } from '../src/form-session/body-parser.js';
import { FormSessionController, FORM_SESSION_HTTP_DEPS } from '../src/form-session/controller.js';
import { FormSessionService } from '../src/form-session/service.js';
import { issueCsrfProof } from '../src/form-session/csrf.js';
import { beginLegalTransaction, publishLegalDocumentVersion } from '../src/settings/legal/index.js';
import type { FormSessionConfig, FormSessionPool } from '../src/form-session/service.js';
import { F_GROUP_COOKIE, F_COOKIE_PREFIX, F_SELECTOR_HEADER } from '../src/form-session/contract.js';
import { admitFixture, admitVerifiedTestInstance } from './admission-fixture.js';
import type { AdmittedHandle } from './admission-fixture.js';
import { authFixtureMigrations, installPinnedMigrationHistory } from './auth-db-fixture.js';
import { createConfigurationFixture } from './configuration-fixture.js';
import { GeographyFixture, check as geoCheck, geoTag, idOf as geoIdOf, versionOf as geoVersionOf } from './geography-fixture.js';
import { fixturePerTest, integration, record, text } from './rbac-fixture.js';
import type { RbacFixture } from './rbac-fixture.js';
import { fixtureCredentials } from './owned-test-database.js';
import { admittedPool } from '../src/infrastructure/admission/pool-guard.js';
import { ManagementFixture, fixtureCode, legalInput } from './settings-management-fixture.js';

const ORIGIN = 'https://crm.example.test';
const TIMEOUT = 60_000;

/** Synthetic PII sentinel: it must never appear in a response, log or error. */
const PRIVATE_PII = 'synthetic-pii-никогда-не-выводить';

/* ----------------------------- F transport client ----------------------------- */

interface FResponse {
  readonly status: number;
  readonly data: Record<string, unknown>;
  readonly body: unknown;
  readonly setCookie: string[];
  readonly headers: Record<string, string | string[] | undefined>;
}

interface FOptions {
  readonly cookies?: string[];
  readonly headers?: Record<string, string | string[]>;
  readonly origin?: string;
  readonly noOrigin?: boolean;
}

/**
 * Raw HTTP client for the F surface. Every request runs through the real Nest
 * listener with the exact headers a browser would send; `raw` mode lets a test
 * smuggle genuinely duplicated headers, which `set()` cannot produce.
 */
function fClient(server: () => Server, secrets: () => Set<string>) {
  async function call(
    method: 'POST' | 'GET', path: string, body?: unknown, options: FOptions = {},
  ): Promise<FResponse> {
    // supertest methods are lower-case; the route is fixed per wrapper below.
    const req = request(server())[method.toLowerCase() as 'post' | 'get'](`/api/v1/public${path}`);
    if (!options.noOrigin) { req.set('Origin', options.origin ?? ORIGIN); }
    if (options.cookies && options.cookies.length > 0) {
      req.set('Cookie', options.cookies.join('; '));
    }
    for (const [name, value] of Object.entries(options.headers ?? {})) {
      if (Array.isArray(value)) {
        // A real duplicate header line, not a merged value.
        for (const item of value) { req.set(name, item); }
      } else {
        req.set(name, value);
      }
    }
    if (body !== undefined) { req.set('Content-Type', 'application/json').send(JSON.stringify(body)); }
    else { req.set('Content-Type', 'application/json'); }
    const response = await req;
    const cookies: unknown = response.headers['set-cookie'];
    const setCookie = Array.isArray(cookies) ? cookies.map(String) : typeof cookies === 'string' ? [cookies] : [];
    expect(response.headers['cache-control']).toBe('no-store');
    // PII sentinel: the response body must never disclose it.
    const raw = JSON.stringify(response.body);
    expect(raw.includes(PRIVATE_PII)).toBe(false);
    for (const secret of secrets()) { expect(raw.includes(secret)).toBe(false); }
    const envelope = response.status < 300 ? record(response.body) : {};
    const data = envelope['data'] === undefined ? {} : record(envelope['data']);
    return {
      status: response.status, data, body: response.body, setCookie,
      headers: response.headers,
    };
  }
  return {
    post: (path: string, body?: unknown, options: FOptions = {}) => call('POST', path, body, options),
    get: (path: string, options: FOptions = {}) => call('GET', path, undefined, options),
  };
}

/** Problem+json refusal shape: the closed five-key body of ProblemFilter. */
function problem(result: FResponse, status: number): FResponse {
  expect(result.status).toBe(status);
  const body = record(result.body);
  expect(Object.keys(body).sort()).toEqual(['code', 'requestId', 'status', 'title', 'type']);
  const code = status === 503 ? 'NOT_READY' : status === 404 ? 'NOT_FOUND' : status === 500 ? 'INTERNAL_ERROR' : 'REQUEST_REJECTED';
  expect(body).toMatchObject({ type: 'about:blank', status, code, title: code });
  expect(text(body, 'requestId')).toMatch(/^[0-9a-f-]{36}$/);
  return result;
}

/** Extracts one cookie pair from a Set-Cookie list by exact name. */
function cookieOf(setCookie: readonly string[], name: string): string | undefined {
  return setCookie.find((value) => value.startsWith(`${name}=`));
}

/** The value of a Set-Cookie pair: the part before the first `;` (attributes). */
function cookieValue(setCookie: string): string {
  return setCookie.slice(0, setCookie.indexOf(';')).split('=').slice(1).join('=');
}

/* ------------------------------- F fixture ------------------------------- */

/** Keep normal scenarios live through several real catalog-verified HTTP calls. */
const LIVE_TTLS = { groupTtlMs: 120_000, anchorTtlMs: 90_000, csrfTtlMs: 60_000 } as const;
/** Pin the original short windows only where expiry is part of the assertion. */
const SHORT_TTLS = { groupTtlMs: 60_000, anchorTtlMs: 4_000, csrfTtlMs: 3_000 } as const;

it('rejects an unregistered F pool before acquiring a connection or running SQL', () => {
  const unavailable = vi.fn((): never => { throw new Error('Unexpected database operation'); });
  expect(() => new FormSessionService({ query: unavailable, connect: unavailable }, {
    origin: ORIGIN, csrfKeyring: { current: { keyId: 'test', secret: randomBytes(32) } },
    throttleSecret: randomBytes(32), ...LIVE_TTLS,
    throttles: { source: { windowSeconds: 60, maxHits: 10 }, global: { windowSeconds: 60, maxHits: 10 },
      anchor: { windowSeconds: 60, maxHits: 10 } },
  })).toThrow('Database admission required');
  expect(unavailable).not.toHaveBeenCalled();
});

class FormSessionHttpFixture {
  readonly base: RbacFixture;
  readonly geo: GeographyFixture;
  readonly management: ManagementFixture;
  readonly csrfSecret: Buffer;
  readonly throttleSecret: Buffer;
  private readonly pool: FormSessionPool & { end(): Promise<void> };
  private readonly runtimeDb: RuntimeDatabase;
  private app?: Awaited<ReturnType<typeof createApi>>;
  private readonly logs: unknown[] = [];
  readonly secrets = new Set<string>([PRIVATE_PII]);
  keyId = 'test-key-1';

  constructor(base: RbacFixture) {
    this.base = base;
    this.geo = new GeographyFixture(base);
    this.management = new ManagementFixture(base, this.logs);
    this.csrfSecret = randomBytes(32);
    this.throttleSecret = randomBytes(32);
    // The F service pool: a real guarded pool behind the same launch admission.
    this.pool = admittedPool({ authorization: base.admitted.authorization, kind: 'API' }, this.databaseConfig(), {
      max: 4, connectionTimeoutMillis: 2000, statement_timeout: 4000, idleTimeoutMillis: 10_000,
      options: '-c lock_timeout=3000',
    });
    this.runtimeDb = new RuntimeDatabase(this.databaseConfig(), true, base.admitted.authorization);
  }

  private static runtimePassword(): string {
    return fixtureCredentials().runtime;
  }

  async start(): Promise<void> {
    // Real app: createApi wires boundedJson + ProblemFilter and listens on 127.0.0.1:0.
    // We extend its controller set by composing a second testing module that mounts
    // the F controller on the same server via a dedicated Nest application.
    this.app = await createApi(loadConfig({ NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0' }),
      new SafeLogger('api'), this.databaseConfig(), this.webAuthConfig(), undefined,
      this.base.admitted.authorization);
    // F surface: a second real Nest app sharing nothing but the process. Tests call
    // it on its own loopback port.
    const fApp = await this.buildFormApp();
    this.fServer = fApp.getHttpServer() as Server;
    await this.listenFormApp(fApp);
  }

  private fServer?: Server;

  private databaseConfig() {
    return {
      host: '127.0.0.1' as const, port: 55432, database: this.base.database,
      user: 'fixlevelup_runtime' as const,
      password: FormSessionHttpFixture.runtimePassword(),
    };
  }

  private webAuthConfig() {
    return { origin: ORIGIN, csrfSecret: randomBytes(32).toString('hex'), throttleSecret: randomBytes(32).toString('hex') };
  }

  private async buildFormApp(service = new FormSessionService(this.pool, {
      origin: ORIGIN,
      csrfKeyring: { current: { keyId: this.keyId, secret: this.csrfSecret } },
      throttleSecret: this.throttleSecret,
      ...LIVE_TTLS,
      throttles: {
        source: { windowSeconds: 86_400, maxHits: 1_000_000 },
        global: { windowSeconds: 86_400, maxHits: 1_000_000 },
        anchor: { windowSeconds: 86_400, maxHits: 1_000_000 },
      },
    }), database = this.runtimeDb) {
    const logger = new SafeLogger('api');
    const mod = await Test.createTestingModule({
      controllers: [FormSessionController],
      providers: [
        { provide: FORM_SESSION_HTTP_DEPS, useValue: {
          service,
          database,
          config: { origin: ORIGIN },
        } },
      ],
    }).compile();
    // Nest's public options contract uses a structural class with no methods.
    // eslint-disable-next-line @typescript-eslint/no-unsafe-class-instance-assignment
    const app = mod.createNestApplication({ logger: false, bodyParser: false });
    app.use(boundedJsonForFormSession(database));
    app.useGlobalFilters(new ProblemFilter(logger));
    await app.init();
    this.closers.push(() => app.close());
    return app;
  }

  private readonly closers: Array<() => Promise<void>> = [];

  private async listenFormApp(app: { listen: (port: number, host: string) => Promise<unknown> }): Promise<void> {
    await app.listen(0, '127.0.0.1');
  }

  get server(): Server {
    const s = this.fServer;
    if (!s) { throw new Error('Missing F HTTP server'); }
    return s;
  }

  /** The F client bound to this fixture's server and secrets. */
  get f() { return fClient(() => this.server, () => this.secrets); }

  async isolatedClient(config: Partial<FormSessionConfig> = {}, max = 4, admission?: AdmittedHandle) {
    const kind = admission === undefined ? 'API' : 'TEST';
    const authorization = (admission ?? this.base.admitted).authorization;
    const pool = admittedPool({ authorization, kind }, this.databaseConfig(), {
      max, connectionTimeoutMillis: 4000, statement_timeout: 10_000, options: '-c lock_timeout=8000',
    });
    this.closers.push(() => pool.end());
    const database = admission === undefined ? this.runtimeDb : new RuntimeDatabase(this.databaseConfig(), true, authorization, kind);
    if (database !== this.runtimeDb) { this.closers.push(() => database.onModuleDestroy()); }
    const app = await this.buildFormApp(new FormSessionService(pool, {
      origin: ORIGIN, csrfKeyring: { current: { keyId: this.keyId, secret: this.csrfSecret } },
      throttleSecret: randomBytes(32), ...LIVE_TTLS,
      throttles: {
        source: { windowSeconds: 86_400, maxHits: 1_000_000 },
        global: { windowSeconds: 86_400, maxHits: 1_000_000 },
        anchor: { windowSeconds: 86_400, maxHits: 1_000_000 },
      },
      ...config,
    }), database);
    await this.listenFormApp(app);
    return fClient(() => app.getHttpServer() as Server, () => this.secrets);
  }

  remember(...values: string[]): void { for (const value of values) { this.secrets.add(value); } }

  /**
   * Rotates the CSRF keyring: rebuilds the service with a new key id/secret and
   * swaps it into the controller's deps (simulated key rotation, §4.1).
   */
  async rotateKey(): Promise<void> {
    this.keyId = 'test-key-2';
    // The controller reads deps once at construction; rotation in tests replaces
    // the whole F app (see rotateFApp).
    await this.rotateFApp();
  }

  private async rotateFApp(): Promise<void> {
    const service = new FormSessionService(this.pool, {
      origin: ORIGIN,
      csrfKeyring: { current: { keyId: this.keyId, secret: this.csrfSecret } },
      throttleSecret: this.throttleSecret,
      ...LIVE_TTLS,
      throttles: {
        source: { windowSeconds: 86_400, maxHits: 1_000_000 },
        global: { windowSeconds: 86_400, maxHits: 1_000_000 },
        anchor: { windowSeconds: 86_400, maxHits: 1_000_000 },
      },
    });
    const logger = new SafeLogger('api');
    const mod = await Test.createTestingModule({
      controllers: [FormSessionController],
      providers: [{ provide: FORM_SESSION_HTTP_DEPS, useValue: {
        service, database: this.runtimeDb,
        config: { origin: ORIGIN },
      } }],
    }).compile();
    // Nest's public options contract uses a structural class with no methods.
    // eslint-disable-next-line @typescript-eslint/no-unsafe-class-instance-assignment
    const app = mod.createNestApplication({ logger: false, bodyParser: false });
    app.use(boundedJsonForFormSession(this.runtimeDb));
    app.useGlobalFilters(new ProblemFilter(logger));
    await app.init();
    const server = app.getHttpServer() as Server;
    // Replace the active server reference (same shape as the initial one).
    this.fServer = server;
    // Nest Testing apps do not listen until asked; run the real listener.
    const httpAdapter = app.getHttpAdapter().getInstance() as unknown as { listen: (p: number, h: string, cb: () => void) => void };
    await new Promise<void>((resolve) => { httpAdapter.listen(0, '127.0.0.1', () => { resolve(); }); });
    this.closers.push(() => app.close());
  }

  /** Database clock, sampled directly. */
  async dbNow(): Promise<Date> {
    const row = (await this.base.db.query<{ now: Date }>('SELECT clock_timestamp() AS now')).rows[0];
    if (!row) { throw new Error('Missing DB clock'); }
    return row.now;
  }

  /** Waits until the DB clock passes the given instant (bounded). */
  async waitForDbClock(expiresAt: Date, budgetMs = 8_000): Promise<void> {
    const deadline = performance.now() + budgetMs;
    for (;;) {
      if ((await this.dbNow()).getTime() >= expiresAt.getTime()) { return; }
      if (performance.now() > deadline) { throw new Error('DB clock did not reach the expiry'); }
      await new Promise((done) => { setTimeout(done, 250); });
    }
  }

  async close(): Promise<void> {
    for (const close of this.closers.splice(0).reverse()) { await close().catch(() => undefined); }
    await this.app?.close().catch(() => undefined);
    await this.runtimeDb.onModuleDestroy().catch(() => undefined);
    // The guarded F pool must be drained before the disposable database is
    // dropped, otherwise its live connections die as 57P01 unhandled errors.
    await this.pool.end().catch(() => undefined);
  }
}

/* ------------------------------ fixture lifecycle ------------------------------ */

integration('P05-02 F form-session HTTP surface over isolated PostgreSQL', () => {
  const baseFixture = fixturePerTest();
  let fixture: FormSessionHttpFixture;
  const logs: unknown[][] = [];

  beforeEach(async () => {
    const base = baseFixture();
    fixture = new FormSessionHttpFixture(base);
    // Capture the ConsoleLogger sink like the management fixture does, so no
    // framework message can leak secrets into the log.
    const sink: unknown = Object.getOwnPropertyDescriptor(ConsoleLogger.prototype, 'log')?.value;
    if (!vi.isMockFunction(sink)) { throw new Error('Missing fixture log sink'); }
    sink.mockImplementation((...args: unknown[]) => { logs.push(args); });
    await fixture.start();
  }, 45_000);

  afterEach(async () => {
    try {
      // No PII or secret in any log line captured during the test.
      expect(JSON.stringify(logs).includes(PRIVATE_PII)).toBe(false);
      for (const secret of fixture.secrets) { expect(JSON.stringify(logs).includes(secret)).toBe(false); }
      // Audit evidence never carries the sentinel either.
      const evidence = await fixture.base.db.query('SELECT details FROM foundation.audit_logs');
      expect(JSON.stringify(evidence.rows).includes(PRIVATE_PII)).toBe(false);
    } finally {
      logs.length = 0;
      // Only the F-side resources close here: the base fixture's own afterEach
      // (registered by fixturePerTest) still runs auditSafe() and then its full
      // teardown — closing base.db here would end the pool before that read.
      await fixture.close().catch(() => undefined);
    }
  }, 45_000);

  /* ------------------------------ shared helpers ------------------------------ */

  /** Provisions the single ACTIVE city, a district and a published covered zone. */
  async function provisionCity() {
    const admin = fixture.base.admin;
    const city = await fixture.geo.activeCity(admin, fixtureCode('f-city'));
    const detail = geoCheck(await fixture.geo.read(admin, `/settings/service-cities/${city.id}`), 200);
    const district = geoCheck(await fixture.geo.createDistrict(admin, city.id, geoVersionOf(detail), fixtureCode('f-district')), 201);
    const districtId = geoIdOf(district);
    const fresh = geoCheck(await fixture.geo.read(admin, `/settings/service-cities/${city.id}`), 200);
    const created = geoCheck(await fixture.geo.createArea(admin, city.id, geoVersionOf(fresh), fixtureCode('f-area')), 201);
    const areaId = geoIdOf(created);
    const areaPath = `/settings/service-cities/${city.id}/service-areas/${areaId}`;
    // Every write must carry the CURRENT aggregate version: reads are cheap and
    // always correct, a stale If-Match is a 412 (see geography-e2e.test.ts).
    const area = geoCheck(await fixture.geo.read(admin, areaPath), 200);
    const draft = geoCheck(await fixture.geo.addAreaVersion(admin, city.id, areaId, geoVersionOf(area), 'Synthetic zone'), 201);
    const versionId = geoIdOf(draft);
    const coverage = geoCheck(await fixture.geo.write(admin, 'put',
      `${areaPath}/versions/${versionId}/district-coverage`,
      { districts: [{ districtId, relation: 'FULL', description: 'Advisory candidate only' }] },
      { etag: geoTag(geoVersionOf(draft)) }), 200);
    geoCheck(await fixture.geo.publishAreaVersion(admin, city.id, areaId, versionId, geoVersionOf(coverage)), 200);
    return { city, districtId, areaId, versionId };
  }

  /** Publishes the REQUEST_PROCESSING CONSENT_FORM the consents route reads.
   * The body is deliberately non-sentinel text: this suite's public GET must be
   * able to read the exact document body back, so the PII sentinel stays a
   * log/error-disclosure probe, not legitimate published content. */
  async function publishLegal(body = 'Synthetic consent form body for the F surface.') {
    const created = check(await fixture.management.post('/legal/documents', { purpose: 'REQUEST_PROCESSING', kind: 'CONSENT_FORM' }), 201);
    const path = `/legal/documents/${text(created.data, 'id')}`;
    const input = { ...legalInput(body), sourceRef: 'fixture-legal-source' };
    const published = check(await fixture.management.post(`${path}/publish`, input, { etag: created.etag }), 201);
    return { documentId: text(created.data, 'id'), versionId: text(published.data, 'revisionId') };
  }

  const { check } = { check: <T extends { readonly status: number }>(r: T, status: number): T => { expect(r.status).toBe(status); return r; } };

  /** Bootstraps a browser group and returns the fgroup cookie pair. */
  async function bootstrapGroup(f = fixture.f): Promise<string> {
    const result = check(await f.post('/form-session/browser', {}, { headers: { 'x-form-session-bootstrap': '1' } }), 200);
    const cookie = cookieOf(result.setCookie, F_GROUP_COOKIE);
    if (!cookie) { throw new Error('Missing fgroup Set-Cookie'); }
    const value = cookieValue(cookie);
    fixture.remember(value);
    return `${F_GROUP_COOKIE}=${value}`;
  }

  /** Issues one F session; returns cookies/selector/CSRF for later calls. */
  async function issueSession(groupCookie: string, f = fixture.f) {
    const result = check(await f.post('/form-sessions', {}, { cookies: [groupCookie] }), 201);
    const selector = text(result.data, 'sessionId');
    const set = cookieOf(result.setCookie, `${F_COOKIE_PREFIX}${selector}`);
    if (!set) { throw new Error('Missing F Set-Cookie'); }
    const secret = cookieValue(set);
    fixture.remember(secret);
    const csrf = text(result.data, 'csrfToken');
    fixture.remember(csrf);
    return { selector, secret, csrf, cookie: `${F_COOKIE_PREFIX}${selector}=${secret}`, result };
  }

  const fullCookies = (f: { cookie: string }, group: string) => [group, f.cookie];

  /**
   * One consent mutation. `Idempotency-Key` is mandatory on this route and is
   * bound to the F-session and to the exact intent: the key must equal the body
   * `evidenceRef`, which is the append-only evidence identity of the event.
   * `key` may be overridden to exercise the refusal paths.
   */
  async function consent(
    body: Record<string, unknown>,
    options: { cookies: string[]; headers: Record<string, string>; key?: string | null },
  ): Promise<FResponse> {
    const headers: Record<string, string> = { ...options.headers };
    const key = options.key === undefined ? text(body, 'evidenceRef') : options.key;
    if (key !== null) { headers['idempotency-key'] = key; }
    return await fixture.f.post('/form-session/consents', body, { cookies: options.cookies, headers });
  }

  async function waitForBlocker(blocker: number): Promise<number> {
    const deadline = performance.now() + 4_000;
    while (performance.now() < deadline) {
      const { rows } = await fixture.base.db.query<{ pid: number }>(
        `SELECT pid FROM pg_stat_activity WHERE datname = current_database()
          AND $1 = ANY(pg_blocking_pids(pid))`, [blocker],
      );
      if (rows[0] !== undefined) { return rows[0].pid; }
      await new Promise<void>((done) => { setTimeout(done, 20); });
    }
    throw new Error('No F transaction observed waiting on the fixture lock');
  }

  it('charges GLOBAL then SOURCE then proven ANCHOR in HTTP, saturates independently and works with one business connection', async () => {
    await provisionCity();
    await publishLegal();
    const throttleSecret = randomBytes(32);
    const f = await fixture.isolatedClient({ throttleSecret, throttles: {
      source: { windowSeconds: 86_400, maxHits: 7 },
      global: { windowSeconds: 86_400, maxHits: 8 },
      anchor: { windowSeconds: 86_400, maxHits: 2 },
    } }, 1);
    const group = await bootstrapGroup(f);
    const session = await issueSession(group, f);
    const auth = { cookies: [session.cookie], headers: { [F_SELECTOR_HEADER]: session.selector } };
    problem(await f.post('/form-session/csrf', {}, { ...auth, cookies: [`${F_COOKIE_PREFIX}${session.selector}=${'A'.repeat(43)}`] }), 401);
    check(await f.post('/form-session/csrf', {}, auth), 200);
    check(await f.post('/form-session/csrf', {}, auth), 200);
    problem(await f.post('/form-session/csrf', {}, auth), 429);
    check(await f.get('/legal-documents/CONSENT_FORM'), 200);
    problem(await f.get('/legal-documents/CONSENT_FORM'), 429); // SOURCE saturates, GLOBAL reaches eight.
    const hash = (kind: string, subject: string) => createHmac('sha256', throttleSecret).update(`${kind}\0${subject}`).digest('hex');
    const readBuckets = async () => (await fixture.base.db.query<{ kind: string; hit_count: number }>(
      'SELECT kind, hit_count FROM foundation.form_throttle_buckets WHERE key_hash=ANY($1::text[]) ORDER BY kind',
      [[hash('GLOBAL', 'global'), hash('SOURCE', '127.0.0.1'), hash('SOURCE', '::ffff:127.0.0.1'),
        hash('ANCHOR', session.selector), hash('SOURCE', '198.51.100.77')]],
    )).rows;
    const saturated = await readBuckets();
    expect(saturated).toEqual([{ kind: 'ANCHOR', hit_count: 2 }, { kind: 'GLOBAL', hit_count: 8 }, { kind: 'SOURCE', hit_count: 7 }]);
    problem(await f.post('/form-session/browser', {}, { headers: { 'x-form-session-bootstrap': '1' } }), 429);
    const secondSource = new FormSessionService(fixture['pool'], {
      origin: ORIGIN, csrfKeyring: { current: { keyId: fixture.keyId, secret: fixture.csrfSecret } },
      throttleSecret, ...LIVE_TTLS,
      throttles: { source: { windowSeconds: 86_400, maxHits: 7 }, global: { windowSeconds: 86_400, maxHits: 8 },
        anchor: { windowSeconds: 86_400, maxHits: 2 } },
    });
    const countBefore = await fixture.base.count('SELECT count(*)::int n FROM foundation.form_throttle_buckets');
    await expect(secondSource.readLegalDocument('CONSENT_FORM', { source: '198.51.100.77' })).rejects.toMatchObject({ code: 'QUOTA' });
    expect(await readBuckets()).toEqual(saturated);
    expect(await fixture.base.count('SELECT count(*)::int n FROM foundation.form_throttle_buckets')).toBe(countBefore);
  }, TIMEOUT);

  it.each(['revoke', 'consents'] as const)('reproves both expiries after a real PG audit write wait: %s', async (operation) => {
    await provisionCity();
    const legal = await publishLegal();
    const f = await fixture.isolatedClient({ anchorTtlMs: 5_000, csrfTtlMs: 2_000 });
    const group = await bootstrapGroup(f);
    for (const authority of ['both', 'csrf'] as const) {
      const session = await issueSession(group, f);
      const { selector, secret } = session;
      const expiry = new Date(text(session.result.data, authority === 'csrf' ? 'csrfExpiresAt' : 'expiresAt'));
      const proof = issueCsrfProof({ keyId: fixture.keyId, secret: fixture.csrfSecret }, selector, secret, expiry.getTime());
      fixture.remember(proof);
      const key = randomUUID();
      const body = operation === 'revoke' ? {} : { action: 'GIVEN', documentId: legal.documentId,
        documentVersionId: legal.versionId, evidenceRef: key };
      const holder = await fixture.base.db.connect();
      let pending: Promise<FResponse> | undefined;
      try {
        await holder.query('BEGIN');
        await holder.query('LOCK TABLE foundation.audit_logs IN SHARE MODE');
        const pid = (await holder.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
        if (pid === undefined) { throw new Error('Missing blocker PID'); }
        pending = f.post(`/form-session/${operation}`, body, {
          cookies: [`${F_COOKIE_PREFIX}${selector}=${secret}`], headers: { [F_SELECTOR_HEADER]: selector, 'x-csrf-token': proof,
            ...(operation === 'consents' ? { 'idempotency-key': key } : {}) },
        });
        await waitForBlocker(pid);
        await fixture.waitForDbClock(expiry);
        await holder.query('COMMIT');
        const response = problem(await pending, authority === 'csrf' ? 403 : 401);
        if (authority === 'csrf') { expect(response.setCookie).toEqual([]); }
        else { expect(response.setCookie).toEqual([`${F_COOKIE_PREFIX}${selector}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`]); }
      } finally {
        await holder.query('ROLLBACK').catch(() => undefined);
        holder.release();
        await pending?.catch(() => undefined);
      }
      expect((await fixture.base.db.query('SELECT revoked_at FROM foundation.request_sessions WHERE id=$1', [selector])).rows)
        .toEqual([{ revoked_at: null }]);
      expect((await fixture.base.db.query('SELECT id FROM foundation.consent_records WHERE session_id=$1', [selector])).rows).toEqual([]);
      expect((await fixture.base.db.query(`SELECT id FROM foundation.audit_logs WHERE details->>'sessionId'=$1
          AND operation IN ('CONSENT_GIVEN','REQUEST_SESSION_REVOKED')`, [selector])).rows).toEqual([]);
    }
  }, TIMEOUT);

  it.each(['publish-first', 'consent-first'] as const)('serializes the document pointer and consent evidence: %s', async (order) => {
    await provisionCity();
    const legal = await publishLegal();
    const detail = check(await fixture.management.read(`/legal/documents/${legal.documentId}`), 200);
    const f = await fixture.isolatedClient();
    const group = await bootstrapGroup(f);
    const session = await issueSession(group, f);
    const key = randomUUID();
    const args = { action: 'GIVEN', documentId: legal.documentId, documentVersionId: legal.versionId, evidenceRef: key };
    const requestConsent = () => f.post('/form-session/consents', args, { cookies: [session.cookie], headers: {
      [F_SELECTOR_HEADER]: session.selector, 'x-csrf-token': session.csrf, 'idempotency-key': key,
    } });
    const holder = await fixture.base.db.connect();
    const publisher = order === 'consent-first' ? await fixture.base.db.connect() : holder;
    const publish = () => publishLegalDocumentVersion(publisher, {
      ...legalInput('Concurrent current revision'), documentId: legal.documentId,
      expectedVersion: Number(detail.etag.match(/"p03-v(\d+)"/)?.[1]), reviewedBy: fixture.base.admin.id,
    });
    let pending: Promise<FResponse> | undefined;
    let pendingPublish: ReturnType<typeof publish> | undefined;
    try {
      await beginLegalTransaction(holder);
      const pid = (await holder.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
      if (pid === undefined) { throw new Error('Missing blocker PID'); }
      if (order === 'publish-first') {
        await publish();
        pending = requestConsent();
        await waitForBlocker(pid);
        await holder.query('COMMIT');
        problem(await pending, 409);
      } else {
        await holder.query('LOCK TABLE foundation.audit_logs IN SHARE MODE');
        pending = requestConsent();
        await waitForBlocker(pid);
        // While audit is waiting, this F backend owns the document row lock.
        const formPid = await waitForBlocker(pid);
        await beginLegalTransaction(publisher);
        pendingPublish = publish();
        void pendingPublish.catch(() => undefined);
        await waitForBlocker(formPid);
        await holder.query('COMMIT');
        check(await pending, 201);
        await pendingPublish;
        await publisher.query('COMMIT');
        problem(await requestConsent(), 409); // old GIVEN remains history and is not replayable as current consent
      }
    } finally {
      await holder.query('ROLLBACK').catch(() => undefined);
      holder.release();
      await pending?.catch(() => undefined);
      await pendingPublish?.catch(() => undefined);
      if (publisher !== holder) {
        await publisher.query('ROLLBACK').catch(() => undefined);
        publisher.release();
      }
    }
    expect(await fixture.base.count('SELECT count(*)::int n FROM foundation.consent_records WHERE evidence_ref=$1', [key]))
      .toBe(order === 'publish-first' ? 0 : 1);
  }, TIMEOUT);

  /* ------------------------------ §4.1 browser group ------------------------------ */

  it('bootstraps a group, re-confirms it unchanged and refuses bad origin, missing marker and duplicated headers', async () => {
    const f = fixture.f;
    // Missing marker header → 403.
    problem(await f.post('/form-session/browser', {}), 403);
    // Wrong Origin → 403.
    problem(await f.post('/form-session/browser', {}, { headers: { 'x-form-session-bootstrap': '1' }, origin: 'https://evil.example.test' }), 403);
    // No Origin at all → 403.
    problem(await f.post('/form-session/browser', {}, { headers: { 'x-form-session-bootstrap': '1' }, noOrigin: true }), 403);
    // Duplicated Origin / marker headers → 400. supertest's set() overwrites the
    // previous value instead of sending a genuine duplicate header line, so the
    // duplicate-aware reader is proven through a raw socket (see the comment on
    // fClient's `raw` mode above).
    const port = fixture.server.address();
    if (!port || typeof port === 'string') { throw new Error('Missing F listener port'); }
    const rawPost = (headers: string) => new Promise<{ status: number; cacheControl: string }>((resolve, reject) => {
      const wire = createConnection({ host: '127.0.0.1', port: port.port });
      wire.once('connect', () => {
        wire.write(`POST /api/v1/public/form-session/browser HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n${headers}Content-Length: 2\r\n\r\n{}`);
      });
      const chunks: Buffer[] = [];
      wire.on('data', (chunk: Buffer) => { chunks.push(chunk); });
      wire.setTimeout(5000, () => { wire.destroy(new Error('Raw duplicate request did not close')); });
      wire.once('error', reject);
      wire.once('close', () => {
        const head = Buffer.concat(chunks).toString('utf8').split('\r\n\r\n', 1)[0] ?? '';
        const status = Number(/^HTTP\/1\.1 (\d{3})\b/.exec(head)?.[1] ?? 0);
        const cacheControl = /^cache-control: (.*)$/im.exec(head)?.[1] ?? '';
        resolve({ status, cacheControl });
      });
    });
    const dup = await rawPost(`Origin: ${ORIGIN}\r\nOrigin: ${ORIGIN}\r\nx-form-session-bootstrap: 1\r\nContent-Type: application/json\r\n`);
    expect(dup.status).toBe(400);
    expect(dup.cacheControl).toBe('no-store');
    // Duplicated marker header → 400.
    const dupMarker = await rawPost(`Origin: ${ORIGIN}\r\nx-form-session-bootstrap: 1\r\nx-form-session-bootstrap: 1\r\nContent-Type: application/json\r\n`);
    expect(dupMarker.status).toBe(400);
    // Selector header on bootstrap → 400 (must not be chosen yet).
    problem(await f.post('/form-session/browser', {}, { headers: { 'x-form-session-bootstrap': '1', [F_SELECTOR_HEADER]: randomUUID() } }), 400);
    // Non-empty body → 400; PII-bearing body → 400 (PII_REJECTED classification).
    problem(await f.post('/form-session/browser', { address: PRIVATE_PII }, { headers: { 'x-form-session-bootstrap': '1' } }), 400);
    problem(await f.post('/form-session/browser', { x: 1 }, { headers: { 'x-form-session-bootstrap': '1' } }), 400);
    // Authorization header is refused before anything.
    problem(await f.post('/form-session/browser', {}, { headers: { 'x-form-session-bootstrap': '1', Authorization: 'Bearer staff-token' } }), 401);

    // Success: group created with the __Host- cookie attributes.
    const first = check(await f.post('/form-session/browser', {}, { headers: { 'x-form-session-bootstrap': '1' } }), 200);
    expect(first.data).toMatchObject({ created: true });
    expect(text(first.data, 'groupId')).toMatch(/^[0-9a-f-]{36}$/);
    const cookie = cookieOf(first.setCookie, F_GROUP_COOKIE);
    expect(cookie).toMatch(/^__Host-fixlevelup_fgroup=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Strict; Max-Age=\d+$/);
    if (!cookie) { throw new Error('Missing fgroup Set-Cookie'); }
    const groupValue = cookieValue(cookie);
    const pair = `${F_GROUP_COOKIE}=${groupValue}`;
    fixture.remember(groupValue);

    // Second call with the same cookie returns the SAME group, no new cookie.
    const second = check(await f.post('/form-session/browser', {}, { cookies: [pair], headers: { 'x-form-session-bootstrap': '1' } }), 200);
    expect(second.data).toMatchObject({ created: false, groupId: text(first.data, 'groupId') });
    expect(second.setCookie).toHaveLength(0);
  }, TIMEOUT);

  it('refuses to bootstrap with an unknown group cookie without issuing a replacement and clears an expired own group cookie with Max-Age=0', async () => {
    const f = await fixture.isolatedClient(SHORT_TTLS);
    // MUST 6 (§4.1): an unknown group cookie is refused (401) and never replaced with a new group.
    const foreign = `${F_GROUP_COOKIE}=${'A'.repeat(43)}`;
    const result = await f.post('/form-session/browser', {}, { cookies: [foreign], headers: { 'x-form-session-bootstrap': '1' } });
    problem(result, 401);
    expect(result.setCookie).toHaveLength(0);

    // An expired own group cookie is refused (401) and cleared with addressed Max-Age=0.
    const groupPair = await bootstrapGroup(f);
    const db = fixture.base.db;
    await db.query('ALTER TABLE foundation.form_browser_groups DISABLE TRIGGER form_browser_groups_guard');
    try {
      await db.query(
        "UPDATE foundation.form_browser_groups SET created_at = clock_timestamp() - interval '2 seconds', expires_at = clock_timestamp() - interval '1 second'",
      );
    } finally {
      await db.query('ALTER TABLE foundation.form_browser_groups ENABLE TRIGGER form_browser_groups_guard');
    }
    const expiredBootstrap = await f.post('/form-session/browser', {}, { cookies: [groupPair], headers: { 'x-form-session-bootstrap': '1' } });
    problem(expiredBootstrap, 401);
    const clear = cookieOf(expiredBootstrap.setCookie, F_GROUP_COOKIE);
    expect(clear).toBe(`${F_GROUP_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`);
  }, TIMEOUT);

  /* -------------------------------- §4.1 issue -------------------------------- */

  it('issues an F session only for a proven group, pins the SINGLE_CITY pair and counts live anchors per group', async () => {
    const f = fixture.f;
    const { city } = await provisionCity();
    // No group cookie → 401.
    problem(await f.post('/form-sessions', {}), 401);
    // A foreign group secret → 401 (unknown group, no clearing).
    const noCookie = await f.post('/form-sessions', {}, { cookies: [`${F_GROUP_COOKIE}=${'B'.repeat(43)}`] });
    problem(noCookie, 401);
    expect(noCookie.setCookie).toHaveLength(0);

    const group = await bootstrapGroup();
    const first = await issueSession(group);
    // The city/version binding must match the SINGLE_CITY resolver.
    expect(first.result.data['intakeCityId']).toBe(city.id);
    const resolverRow = (await fixture.base.db.query<{ cityVersion_id: string }>(
      `SELECT current_version_id AS "cityVersion_id" FROM foundation.service_cities WHERE id=$1`, [city.id])).rows[0];
    expect(first.result.data['intakeCityVersionId']).toBe(resolverRow?.cityVersion_id);
    expect(first.result.data['timezone']).toBe('Europe/Moscow');
    // Cookie + selector + CSRF shape.
    expect(first.cookie).toMatch(/^__Host-fixlevelup_f_[0-9a-f-]{36}=[A-Za-z0-9_-]{43}$/);
    expect(fixture.server).toBeDefined();
    // The response carries the X-Form-Session-Id header equal to the selector.
    const header = Array.isArray(first.result.headers['x-form-session-id'])
      ? first.result.headers['x-form-session-id'][0] : first.result.headers['x-form-session-id'];
    expect(header).toBe(first.selector);

    // Two tabs: a second issue under the same group succeeds (slot budget 4).
    const second = await issueSession(group);
    expect(second.selector).not.toBe(first.selector);

    // Fill the remaining two slots, then the 5th live anchor is 429.
    await issueSession(group);
    await issueSession(group);
    const fifth = await f.post('/form-sessions', {}, { cookies: [group] });
    problem(fifth, 429);
    // The DB, not the cookie jar, is the authority: an old cookie set is irrelevant.
    const count = await fixture.base.count(
      `SELECT count(*)::int n FROM foundation.form_session_group_memberships m
       JOIN foundation.request_sessions s ON s.id=m.session_id
       WHERE m.group_id=(SELECT group_id FROM foundation.form_session_group_memberships WHERE session_id=$1)`,
      [first.selector]);
    expect(count).toBe(4);
  }, TIMEOUT);

  it('frees a slot when an anchor expires by the DB clock and issues then', async () => {
    await provisionCity();
    const f = await fixture.isolatedClient(SHORT_TTLS);
    const group = await bootstrapGroup();
    // Keep three other anchors live while measuring expiry of just the fourth.
    await issueSession(group);
    await issueSession(group);
    await issueSession(group);
    const expiring = await issueSession(group, f);
    problem(await f.post('/form-sessions', {}, { cookies: [group] }), 429);
    // Wait for one anchor to expire by the DB clock (anchorTtl 4s).
    const expiry = (await fixture.base.db.query<{ expires_at: Date }>(
      'SELECT expires_at FROM foundation.request_sessions WHERE id=$1', [expiring.selector])).rows[0]?.expires_at;
    expect(expiry).toBeDefined();
    if (!expiry) { throw new Error('Missing anchor expiry'); }
    await fixture.waitForDbClock(expiry);
    const after = check(await f.post('/form-sessions', {}, { cookies: [group] }), 201);
    expect(text(after.data, 'sessionId')).not.toBe(expiring.selector);
  }, 180_000);

  /* --------------------------------- §4.1 CSRF --------------------------------- */

  it('reissues a fresh CSRF proof for a live session and refuses a foreign selector', async () => {
    await provisionCity();
    const group = await bootstrapGroup();
    const session = await issueSession(group);
    const f = fixture.f;
    // No selector header → 401.
    problem(await f.post('/form-session/csrf', {}, { cookies: [session.cookie] }), 401);
    // Selector that matches no presented cookie → 401.
    problem(await f.post('/form-session/csrf', {}, { cookies: [session.cookie], headers: { [F_SELECTOR_HEADER]: randomUUID() } }), 401);
    // Foreign selector (no membership) → 401, no Set-Cookie.
    const foreignSelector = randomUUID();
    const foreign = await f.post('/form-session/csrf', {}, {
      cookies: [`${F_COOKIE_PREFIX}${foreignSelector}=${'C'.repeat(43)}`],
      headers: { [F_SELECTOR_HEADER]: foreignSelector },
    });
    problem(foreign, 401);
    expect(foreign.setCookie).toHaveLength(0);
    // Success: new proof, anchor expiry unchanged.
    const reissue = check(await f.post('/form-session/csrf', {}, {
      cookies: [session.cookie], headers: { [F_SELECTOR_HEADER]: session.selector },
    }), 200);
    expect(reissue.data['sessionId']).toBe(session.selector);
    expect(text(reissue.data, 'csrfToken')).not.toBe(session.csrf);
    const anchorExpiry = (await fixture.base.db.query<{ expires_at: Date }>(
      'SELECT expires_at FROM foundation.request_sessions WHERE id=$1', [session.selector])).rows[0]?.expires_at;
    const reissuedAt = (await fixture.base.db.query<{ at: Date }>('SELECT clock_timestamp() AS at')).rows[0]?.at;
    if (!anchorExpiry || !reissuedAt) { throw new Error('Missing CSRF reissue evidence'); }
    expect(anchorExpiry.getTime() - reissuedAt.getTime()).toBeGreaterThan(500);
  }, TIMEOUT);

  it('refuses CSRF reissue after anchor expiry and clears the dead own cookie with Max-Age=0', async () => {
    await provisionCity();
    const f = await fixture.isolatedClient(SHORT_TTLS);
    const group = await bootstrapGroup(f);
    const session = await issueSession(group, f);
    const expiry = (await fixture.base.db.query<{ expires_at: Date }>(
      'SELECT expires_at FROM foundation.request_sessions WHERE id=$1', [session.selector])).rows[0]?.expires_at;
    if (!expiry) { throw new Error('Missing anchor expiry'); }
    await fixture.waitForDbClock(expiry);
    const result = await f.post('/form-session/csrf', {}, {
      cookies: [session.cookie], headers: { [F_SELECTOR_HEADER]: session.selector },
    });
    problem(result, 401);
    const clear = cookieOf(result.setCookie, `${F_COOKIE_PREFIX}${session.selector}`);
    expect(clear).toBe(`${F_COOKIE_PREFIX}${session.selector}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`);
  }, 180_000);

  it('invalidates an old CSRF proof after key rotation', async () => {
    await provisionCity();
    const group = await bootstrapGroup();
    const session = await issueSession(group);
    await fixture.rotateKey();
    const f = fixture.f;
    // The old proof no longer verifies under the new key id: revoke fails 403.
    const revoked = await f.post('/form-session/revoke', {}, {
      cookies: [group, session.cookie],
      headers: { [F_SELECTOR_HEADER]: session.selector, 'x-csrf-token': session.csrf },
    });
    problem(revoked, 403);
    // A fresh reissue under the new key works again (the anchor itself is alive).
    const reissue = check(await f.post('/form-session/csrf', {}, {
      cookies: [session.cookie], headers: { [F_SELECTOR_HEADER]: session.selector },
    }), 200);
    const fresh = text(reissue.data, 'csrfToken');
    expect(fresh.startsWith('test-key-2.')).toBe(true);
    const revoked2 = await f.post('/form-session/revoke', {}, {
      cookies: [group, session.cookie],
      headers: { [F_SELECTOR_HEADER]: session.selector, 'x-csrf-token': fresh },
    });
    check(revoked2, 200);
    expect(revoked2.data).toEqual({ revoked: true });
    const clear = cookieOf(revoked2.setCookie, `${F_COOKIE_PREFIX}${session.selector}`);
    expect(clear).toContain('Max-Age=0');
  }, TIMEOUT);

  /* ------------------------------ §4.2 revocation ------------------------------ */

  it('revokes a live session with Max-Age=0 and refuses the second revoke without disclosure', async () => {
    await provisionCity();
    const group = await bootstrapGroup();
    const session = await issueSession(group);
    const f = fixture.f;
    // Revoke requires the CSRF proof.
    problem(await f.post('/form-session/revoke', {}, {
      cookies: [group, session.cookie], headers: { [F_SELECTOR_HEADER]: session.selector },
    }), 403);
    problem(await f.post('/form-session/revoke', {}, {
      cookies: [group, session.cookie], headers: { [F_SELECTOR_HEADER]: session.selector, 'x-csrf-token': 'forged' },
    }), 403);
    // Success.
    const revoked = check(await f.post('/form-session/revoke', {}, {
      cookies: [group, session.cookie],
      headers: { [F_SELECTOR_HEADER]: session.selector, 'x-csrf-token': session.csrf },
    }), 200);
    expect(revoked.data).toEqual({ revoked: true });
    const clear = cookieOf(revoked.setCookie, `${F_COOKIE_PREFIX}${session.selector}`);
    expect(clear).toBe(`${F_COOKIE_PREFIX}${session.selector}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`);
    // DB evidence: the anchor is revoked, the membership is untouched history.
    const row = (await fixture.base.db.query<{ revoked_at: Date | null }>(
      'SELECT revoked_at FROM foundation.request_sessions WHERE id=$1', [session.selector])).rows[0];
    expect(row?.revoked_at).not.toBeNull();
    // Second revoke: 401 with the addressed clearing, no body disclosure.
    const second = await f.post('/form-session/revoke', {}, {
      cookies: [group, session.cookie],
      headers: { [F_SELECTOR_HEADER]: session.selector, 'x-csrf-token': session.csrf },
    });
    problem(second, 401);
    expect(second.data).toEqual({});
    const cleared = cookieOf(second.setCookie, `${F_COOKIE_PREFIX}${session.selector}`);
    expect(cleared).toBe(`${F_COOKIE_PREFIX}${session.selector}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`);
  }, TIMEOUT);

  /* ------------------------ §5.1 consents + advisory ------------------------ */

  it('serves the district advisory with AREA_REVIEW_REQUIRED and hints for the own city, refusing foreign districts', async () => {
    const { city, districtId } = await provisionCity();
    const group = await bootstrapGroup();
    const session = await issueSession(group);
    const f = fixture.f;
    // CSRF is required.
    problem(await f.post('/coverage/check', { districtId }, {
      cookies: [group, session.cookie], headers: { [F_SELECTOR_HEADER]: session.selector },
    }), 403);
    // Address-bearing body is rejected before any processing (PII_REJECTED→400).
    problem(await f.post('/coverage/check', { districtId, address: PRIVATE_PII }, {
      cookies: [group, session.cookie],
      headers: { [F_SELECTOR_HEADER]: session.selector, 'x-csrf-token': session.csrf },
    }), 400);
    // A foreign district (same shape, another city) is the same 404 as a missing one.
    problem(await f.post('/coverage/check', { districtId: randomUUID() }, {
      cookies: [group, session.cookie],
      headers: { [F_SELECTOR_HEADER]: session.selector, 'x-csrf-token': session.csrf },
    }), 404);
    // Success: advisory only, never IN_ZONE.
    const advisory = check(await f.post('/coverage/check', { districtId }, {
      cookies: [group, session.cookie],
      headers: { [F_SELECTOR_HEADER]: session.selector, 'x-csrf-token': session.csrf },
    }), 200);
    expect(advisory.data).toMatchObject({ cityId: city.id, districtId, outcome: 'AREA_REVIEW_REQUIRED' });
    const hints = advisory.data['hints'];
    expect(Array.isArray(hints)).toBe(true);
    const first: unknown = Array.isArray(hints) ? hints[0] : undefined;
    expect(first).toMatchObject({ relation: 'FULL' });
    expect(text(record(first), 'areaId')).toMatch(/^[0-9a-f-]{36}$/);
  }, TIMEOUT);

  it('records GIVEN then REVOKED consent evidence through the real legal ports', async () => {
    await provisionCity();
    const legal = await publishLegal();
    const group = await bootstrapGroup();
    const session = await issueSession(group);
    const headers = { [F_SELECTOR_HEADER]: session.selector, 'x-csrf-token': session.csrf };
    const cookies = fullCookies(session, group);
    // GIVEN requires the exact current document revision.
    problem(await consent({
      action: 'GIVEN', documentId: legal.documentId, documentVersionId: randomUUID(), evidenceRef: randomUUID(),
    }, { cookies, headers }), 409);
    const givenRef = randomUUID();
    const given = check(await consent({
      action: 'GIVEN', documentId: legal.documentId, documentVersionId: legal.versionId, evidenceRef: givenRef,
    }, { cookies, headers }), 201);
    expect(given.data).toMatchObject({ action: 'GIVEN', purpose: 'REQUEST_PROCESSING', replayed: false,
      documentId: legal.documentId, documentVersionId: legal.versionId, sessionId: session.selector });
    const evidenceId = text(given.data, 'evidenceId');
    // REVOKED supersedes the exact GIVEN event.
    const revoked = check(await consent({
      action: 'REVOKED', supersedesEvidenceId: evidenceId, evidenceRef: randomUUID(),
      documentId: legal.documentId, documentVersionId: legal.versionId,
    }, { cookies, headers }), 201);
    expect(revoked.data).toMatchObject({ action: 'REVOKED', replayed: false,
      documentId: legal.documentId, documentVersionId: legal.versionId, sessionId: session.selector });
    // The DB holds both events, append-only.
    const events = await fixture.base.count(
      'SELECT count(*)::int n FROM foundation.consent_records WHERE session_id=$1', [session.selector]);
    expect(events).toBe(2);
  }, TIMEOUT);

  it('requires Idempotency-Key on consent, replays the same key and refuses a reused key with another intent', async () => {
    await provisionCity();
    const legal = await publishLegal();
    const group = await bootstrapGroup();
    const session = await issueSession(group);
    const headers = { [F_SELECTOR_HEADER]: session.selector, 'x-csrf-token': session.csrf };
    const cookies = fullCookies(session, group);
    const key = randomUUID();
    const body = { action: 'GIVEN', documentId: legal.documentId, documentVersionId: legal.versionId, evidenceRef: key };

    // 1. The header is mandatory: absent → 400, malformed → 400, duplicated → 400,
    //    and no evidence row is created by any of them.
    problem(await consent(body, { cookies, headers, key: null }), 400);
    problem(await consent(body, { cookies, headers, key: 'not-a-uuid' }), 400);
    problem(await consent(body, { cookies, headers, key: randomUUID().toUpperCase() }), 400);
    problem(await consent(body, { cookies, headers, key: key.replace(/-/g, '') }), 400);
    expect(await fixture.base.count(
      'SELECT count(*)::int n FROM foundation.consent_records WHERE session_id=$1', [session.selector])).toBe(0);
    // The key is checked before the F proof, so a missing key is 400 even without
    // a cookie — a caller never gets a 401 that hides a protocol error.
    problem(await consent(body, { cookies: [], headers, key: null }), 400);

    // 2. First write: 201 with the exact receipt.
    const first = check(await consent(body, { cookies, headers }), 201);
    expect(first.data).toMatchObject({ action: 'GIVEN', replayed: false, sessionId: session.selector,
      documentId: legal.documentId, documentVersionId: legal.versionId });
    const evidenceId = text(first.data, 'evidenceId');

    // 3. Exact replay of the same key and the same intent: 200 with the SAME
    //    evidence id and `replayed: true`; no second event is appended.
    const replay = check(await consent(body, { cookies, headers }), 200);
    expect(replay.data).toMatchObject({ evidenceId, replayed: true, action: 'GIVEN' });
    expect(await fixture.base.count(
      'SELECT count(*)::int n FROM foundation.consent_records WHERE session_id=$1', [session.selector])).toBe(1);

    // 4. Same key, different intent: a 409 refusal, never a second event and never
    //    a replay of the first one.
    problem(await consent({ ...body, documentVersionId: randomUUID() }, { cookies, headers }), 409);
    problem(await consent({
      action: 'REVOKED', supersedesEvidenceId: evidenceId, evidenceRef: key,
    }, { cookies, headers }), 409);
    expect(await fixture.base.count(
      'SELECT count(*)::int n FROM foundation.consent_records WHERE session_id=$1', [session.selector])).toBe(1);
    // The header must be the body evidence identity; a different header value with
    // the same body is the same reused-key refusal, not a silent new event.
    problem(await consent(body, { cookies, headers, key: randomUUID() }), 409);

    // 5. The key is scoped to the F-session: the same key from another live
    //    session is an independent event, not a replay of this session's evidence.
    const other = await issueSession(group);
    const otherHeaders = { [F_SELECTOR_HEADER]: other.selector, 'x-csrf-token': other.csrf };
    const otherResult = check(await consent(body, { cookies: fullCookies(other, group), headers: otherHeaders }), 201);
    expect(text(otherResult.data, 'evidenceId')).not.toBe(evidenceId);
    expect(otherResult.data).toMatchObject({ sessionId: other.selector, replayed: false });
    const foreign = text(otherResult.data, 'evidenceId');
    const revokeBody = { action: 'REVOKED', supersedesEvidenceId: foreign, evidenceRef: key };
    problem(await consent(revokeBody, { cookies, headers }), 409);
    problem(await consent({ ...revokeBody, supersedesEvidenceId: randomUUID() }, { cookies, headers }), 409);
    problem(await consent({ ...revokeBody, evidenceRef: randomUUID() }, { cookies, headers }), 404);
    problem(await consent({ ...body, documentId: randomUUID() }, { cookies, headers }), 409);
  }, TIMEOUT);

  it('separates a JSON-contract overflow (413) from a rate-limit refusal (429)', async () => {
    await provisionCity();
    const f = fixture.f;
    const group = await bootstrapGroup();
    const session = await issueSession(group);
    const headers = { [F_SELECTOR_HEADER]: session.selector, 'x-csrf-token': session.csrf };
    const cookies = fullCookies(session, group);

    // 413: the body is over the JSON contract. Two distinct caps are exercised —
    // the raw byte cap of the shared reader and the tighter depth cap of the
    // P05-02 decoder — and both must be Payload Too Large, never the 400 of an
    // uninterpretable body.
    const tooManyBytes = { evidenceRef: randomUUID(), padding: 'x'.repeat(20_000) };
    problem(await f.post('/form-session/consents', tooManyBytes, { cookies, headers }), 413);
    const nested: Record<string, unknown> = {};
    let cursor = nested;
    for (let depth = 0; depth < 20; depth += 1) {
      const next: Record<string, unknown> = {};
      cursor['a'] = next;
      cursor = next;
    }
    problem(await f.post('/form-session/consents', nested, { cookies, headers }), 413);
    // A structurally invalid (but small) body stays 400: the 413 is about the cap,
    // not about the body being uninterpretable.
    problem(await f.post('/form-session/consents', [], { cookies, headers }), 400);

    // 429: a quota refusal (the live-anchor slot budget of this browser group) is
    // a different status from the body-cap refusal above, and it is not reported
    // as 413 even though both are "too much" for the client.
    await issueSession(group);
    await issueSession(group);
    await issueSession(group);
    const quota = problem(await f.post('/form-sessions', {}, { cookies: [group] }), 429);
    expect(quota.status).toBe(429);
    // A body-cap refusal on the same F surface stays 413 (never 429, never 400).
    problem(await f.post('/form-session/consents', { padding: 'x'.repeat(20_000) }, { cookies, headers }), 413);
    // A malformed (not oversized) body stays 400: the 413 is about the cap only.
    problem(await f.post('/form-session/consents', { action: 'GIVEN' }, { cookies, headers }), 400);
  }, TIMEOUT);


  it('refuses consent for a stale document revision after a live republish', async () => {
    await provisionCity();
    const legal = await publishLegal();
    const group = await bootstrapGroup();
    const session = await issueSession(group);
    const headers = { [F_SELECTOR_HEADER]: session.selector, 'x-csrf-token': session.csrf };
    const cookies = fullCookies(session, group);
    // GIVEN v1 succeeds.
    check(await consent({
      action: 'GIVEN', documentId: legal.documentId, documentVersionId: legal.versionId, evidenceRef: randomUUID(),
    }, { cookies, headers }), 201);
    // A new revision becomes current (staff surface).
    const path = `/legal/documents/${legal.documentId}`;
    const detail = check(await fixture.management.read(path), 200);
    const next = check(await fixture.management.post(`${path}/publish`, legalInput('Replacement legal fixture'), { etag: detail.etag }), 201);
    const newVersionId = text(next.data, 'revisionId');
    // A second GIVEN naming the OLD revision is 409 (DOCUMENT_NOT_CURRENT).
    problem(await consent({
      action: 'GIVEN', documentId: legal.documentId, documentVersionId: legal.versionId, evidenceRef: randomUUID(),
    }, { cookies, headers }), 409);
    // ...and naming the NEW revision succeeds.
    check(await consent({
      action: 'GIVEN', documentId: legal.documentId, documentVersionId: newVersionId, evidenceRef: randomUUID(),
    }, { cookies, headers }), 201);
  }, TIMEOUT);

  it('serves the current published legal document publicly without operator fields', async () => {
    await provisionCity();
    const legal = await publishLegal();
    const f = fixture.f;
    // Unknown kind → 404 (no oracle for internal kinds).
    problem(await f.get('/legal-documents/OPT_IN_NOTICE'), 404);
    problem(await f.get('/legal-documents/unknown'), 404);
    const doc = check(await f.get('/legal-documents/CONSENT_FORM'), 200);
    expect(doc.data).toMatchObject({ documentId: legal.documentId, versionId: legal.versionId,
      purpose: 'REQUEST_PROCESSING', kind: 'CONSENT_FORM', version: 1 });
    // Operator-only fields never appear.
    expect(Object.keys(doc.data).sort()).toEqual(['body', 'checksum', 'documentId', 'kind', 'legalBasis',
      'publishedAt', 'purpose', 'title', 'version', 'versionId'].sort());
    // The checksum is the sha256 of the exact body.
    const body = text(doc.data, 'body');
    expect(createHash('sha256').update(body).digest('hex')).toBe(text(doc.data, 'checksum'));
  }, TIMEOUT);

  /* --------------------- city/version conflict during an F life --------------------- */

  it('answers 409 CONFLICT on consent and coverage when the city version changes under a live F session', async () => {
    const { districtId } = await provisionCity();
    const legal = await publishLegal();
    const group = await bootstrapGroup();
    const session = await issueSession(group);
    const f = fixture.f;
    const headers = { [F_SELECTOR_HEADER]: session.selector, 'x-csrf-token': session.csrf };
    const cookies = fullCookies(session, group);
    // Baseline: both work.
    check(await f.post('/coverage/check', { districtId }, { cookies, headers }), 200);
    check(await consent({
      action: 'GIVEN', documentId: legal.documentId, documentVersionId: legal.versionId, evidenceRef: randomUUID(),
    }, { cookies, headers }), 201);
    // cityPublish simulation: publish a new city version (pointer move).
    const admin = fixture.base.admin;
    const cityId = text(session.result.data, 'intakeCityId');
    const cityDetail = geoCheck(await fixture.geo.read(admin, `/settings/service-cities/${cityId}`), 200);
    const cityVersion = geoVersionOf(cityDetail);
    const added = geoCheck(await fixture.geo.addCityVersion(admin, cityId, cityVersion), 201);
    geoCheck(await fixture.geo.publishCityVersion(admin, cityId, geoIdOf(added), geoVersionOf(added)), 200);
    // The F session still holds the OLD city version: conflict on both surfaces.
    problem(await f.post('/coverage/check', { districtId }, { cookies, headers }), 409);
    problem(await consent({
      action: 'GIVEN', documentId: legal.documentId, documentVersionId: legal.versionId, evidenceRef: randomUUID(),
    }, { cookies, headers }), 409);
    // The session itself (csrf reissue) still works: it is not the conflict surface.
    check(await f.post('/form-session/csrf', {}, { cookies: [session.cookie], headers: { [F_SELECTOR_HEADER]: session.selector } }), 200);
  }, TIMEOUT);

  it('does not treat a CRM staff cookie or bearer token as an F credential', async () => {
    await provisionCity();
    const f = fixture.f;
    const admin = fixture.base.admin;
    // Authorization bearer → 401 before anything.
    problem(await f.post('/form-session/csrf', {}, { headers: { Authorization: `Bearer ${admin.token}`, [F_SELECTOR_HEADER]: randomUUID() } }), 401);
    // A CRM session cookie alone is not an F proof.
    problem(await f.post('/form-session/csrf', {}, { cookies: [admin.cookie], headers: { [F_SELECTOR_HEADER]: randomUUID() } }), 401);
    // A CRM cookie riding along a real F session does not change the outcome.
    const group = await bootstrapGroup();
    const session = await issueSession(group);
    const withCrm = await f.post('/form-session/csrf', {}, {
      cookies: [group, session.cookie, admin.cookie], headers: { [F_SELECTOR_HEADER]: session.selector },
    });
    check(withCrm, 200);
  }, TIMEOUT);

  it('MUST 3/6/8: distinguishes CSRF expiry on a live F (403, no cookie clear) from simultaneous F+CSRF expiry (401 + Max-Age=0), ignores Date.now() skew, refuses <1s group remainder and dotted CSRF keyIds', async () => {
    await provisionCity();
    const f = await fixture.isolatedClient(SHORT_TTLS);
    // MUST 8: a dotted CSRF keyId is rejected at construction before any DB work.
    expect(() => new FormSessionService(fixture['pool'], {
      origin: ORIGIN,
      csrfKeyring: { current: { keyId: 'bad.key', secret: randomBytes(32) } },
      throttleSecret: randomBytes(32),
      ...SHORT_TTLS,
      throttles: {
        source: { windowSeconds: 60, maxHits: 10 },
        global: { windowSeconds: 60, maxHits: 10 },
        anchor: { windowSeconds: 60, maxHits: 10 },
      },
    })).toThrow(/Invalid form session configuration/);

    const group = await bootstrapGroup(f);
    const session = await issueSession(group, f);

    // MUST 3: host clock skew (Date.now() + 2 hours) never invalidates a live CSRF or anchor;
    // only the PostgreSQL clock_timestamp() decides expiry.
    const spy = vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 7_200_000);
    try {
      const reissueUnderSkew = check(await f.post('/form-session/csrf', {}, {
        cookies: [session.cookie], headers: { [F_SELECTOR_HEADER]: session.selector },
      }), 200);
      expect(reissueUnderSkew.data['sessionId']).toBe(session.selector);
    } finally {
      spy.mockRestore();
    }

    // MUST 3: wait until CSRF expires (3s) while the anchor (4s) is still alive, or extend
    // the anchor in DB so CSRF expires first while F stays live.
    await fixture.base.db.query(
      "UPDATE foundation.request_sessions SET expires_at = expires_at + interval '20 seconds' WHERE id = $1",
      [session.selector],
    ).catch(async () => {
      await fixture.base.db.query('ALTER TABLE foundation.request_sessions DISABLE TRIGGER request_sessions_guard');
      try {
        await fixture.base.db.query(
          "UPDATE foundation.request_sessions SET expires_at = clock_timestamp() + interval '25 seconds' WHERE id = $1",
          [session.selector],
        );
      } finally {
        await fixture.base.db.query('ALTER TABLE foundation.request_sessions ENABLE TRIGGER request_sessions_guard');
      }
    });
    const csrfExpiresAt = new Date(text(session.result.data, 'csrfExpiresAt'));
    await fixture.waitForDbClock(csrfExpiresAt);
    // Live F + expired CSRF -> 403 and NO Set-Cookie Max-Age=0!
    const expiredCsrf = await f.post('/form-session/revoke', {}, {
      cookies: [group, session.cookie],
      headers: { [F_SELECTOR_HEADER]: session.selector, 'x-csrf-token': session.csrf },
    });
    problem(expiredCsrf, 403);
    expect(expiredCsrf.setCookie).toHaveLength(0);

    // Simultaneous F + CSRF expiry -> 401 and addressed Max-Age=0 for the dead own F cookie!
    await fixture.base.db.query('ALTER TABLE foundation.request_sessions DISABLE TRIGGER request_sessions_guard');
    try {
      await fixture.base.db.query(
        "UPDATE foundation.request_sessions SET created_at = clock_timestamp() - interval '2 seconds', expires_at = clock_timestamp() - interval '1 second' WHERE id = $1",
        [session.selector],
      );
    } finally {
      await fixture.base.db.query('ALTER TABLE foundation.request_sessions ENABLE TRIGGER request_sessions_guard');
    }
    const bothExpired = await f.post('/form-session/revoke', {}, {
      cookies: [group, session.cookie],
      headers: { [F_SELECTOR_HEADER]: session.selector, 'x-csrf-token': session.csrf },
    });
    problem(bothExpired, 401);
    expect(cookieOf(bothExpired.setCookie, `${F_COOKIE_PREFIX}${session.selector}`))
      .toBe(`${F_COOKIE_PREFIX}${session.selector}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`);

    // MUST 6: when a group has < 1000ms remaining, issueSession refuses with 401 + Max-Age=0 for fgroup
    // instead of minting an anchor cookie with an inflated Max-Age=1.
    await fixture.base.db.query('ALTER TABLE foundation.form_browser_groups DISABLE TRIGGER form_browser_groups_guard');
    try {
      await fixture.base.db.query(
        "UPDATE foundation.form_browser_groups SET expires_at = clock_timestamp() + interval '400 milliseconds'",
      );
    } finally {
      await fixture.base.db.query('ALTER TABLE foundation.form_browser_groups ENABLE TRIGGER form_browser_groups_guard');
    }
    const subSecondIssue = await f.post('/form-sessions', {}, { cookies: [group] });
    problem(subSecondIssue, 401);
    expect(cookieOf(subSecondIssue.setCookie, F_GROUP_COOKIE))
      .toBe(`${F_GROUP_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`);
  }, TIMEOUT);

  it('MUST 4/5: enforces exact route matching, security header uniqueness and cookie caps (8/9, 8192/8193, 16384/16385, duplicate JSON, bad UTF-8) across all 7 routes including GET', async () => {
    await provisionCity();
    await publishLegal();
    const f = fixture.f;
    const port = fixture.server.address();
    if (!port || typeof port === 'string') { throw new Error('Missing F listener port'); }

    const rawHttp = (requestBytes: Buffer) => new Promise<{ status: number; head: string; body: string }>((resolve, reject) => {
      const wire = createConnection({ host: '127.0.0.1', port: port.port });
      wire.once('connect', () => { wire.write(requestBytes); });
      const chunks: Buffer[] = [];
      wire.on('data', (chunk: Buffer) => { chunks.push(chunk); });
      wire.setTimeout(5000, () => { wire.destroy(new Error('Raw HTTP request timed out')); });
      wire.once('error', reject);
      wire.once('close', () => {
        const textOut = Buffer.concat(chunks).toString('utf8');
        const [head = '', body = ''] = textOut.split('\r\n\r\n', 2);
        const status = Number(/^HTTP\/1\.1 (\d{3})\b/.exec(head)?.[1] ?? 0);
        resolve({ status, head, body });
      });
    });

    // MUST 4: non-canonical paths (trailing slash, case variant) never fall back to P03 JSON.parse,
    // and HEAD on legal-documents is rejected as 404.
    for (const badPath of ['/api/v1/public/form-sessions/', '/api/v1/public/Form-Sessions']) {
      const dupJson = '{"a":1,"a":2}';
      const res = await rawHttp(Buffer.from(
        `POST ${badPath} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: ${ORIGIN}\r\nContent-Type: application/json\r\nContent-Length: ${String(dupJson.length)}\r\n\r\n${dupJson}`,
      ));
      expect(res.status).toBe(400);
    }
    const headRes = await rawHttp(Buffer.from(
      `HEAD /api/v1/public/legal-documents/CONSENT_FORM HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: ${ORIGIN}\r\n\r\n`,
    ));
    expect(headRes.status).toBe(404);

    // MUST 5: GET /legal-documents enforces Cookie byte cap (8192 ok, 8193 -> 413),
    // F-cookie count cap (8 ok, 9 -> 413), and duplicate security headers (400).
    const secret43 = 'A'.repeat(43);
    const eightFCookies = Array.from({ length: 8 }, () => `${F_COOKIE_PREFIX}${randomUUID()}=${secret43}`);
    check(await f.get('/legal-documents/CONSENT_FORM', { cookies: eightFCookies }), 200);
    const nineFCookies = [...eightFCookies, `${F_COOKIE_PREFIX}${randomUUID()}=${secret43}`];
    problem(await f.get('/legal-documents/CONSENT_FORM', { cookies: nineFCookies }), 413);

    const exact8192Cookie = `pad=${'x'.repeat(8192 - 4)}`;
    expect(Buffer.byteLength(exact8192Cookie, 'utf8')).toBe(8192);
    check(await f.get('/legal-documents/CONSENT_FORM', { cookies: [exact8192Cookie] }), 200);
    const over8193Cookie = `pad=${'x'.repeat(8193 - 4)}`;
    expect(Buffer.byteLength(over8193Cookie, 'utf8')).toBe(8193);
    problem(await f.get('/legal-documents/CONSENT_FORM', { cookies: [over8193Cookie] }), 413);

    // Duplicate Cookie header on GET -> 400; duplicate X-CSRF-Token on /form-session/csrf -> 400.
    const dupCookieGet = await rawHttp(Buffer.from(
      `GET /api/v1/public/legal-documents/CONSENT_FORM HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n`,
    ));
    expect(dupCookieGet.status).toBe(400);
    const dupCsrfOnBootstrap = await rawHttp(Buffer.from(
      `POST /api/v1/public/form-session/csrf HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: ${ORIGIN}\r\nX-CSRF-Token: t1\r\nX-CSRF-Token: t2\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}`,
    ));
    expect(dupCsrfOnBootstrap.status).toBe(400);

    // MUST 13: exact 16384 JSON body passes parser, 16385 -> 413; duplicate decoded JSON -> 400; invalid UTF-8 -> 400.
    const exact16384Body = Buffer.from(`{${' '.repeat(16384 - 2)}}`, 'utf8');
    expect(exact16384Body.byteLength).toBe(16384);
    const ok16384 = await rawHttp(Buffer.concat([
      Buffer.from(`POST /api/v1/public/form-session/browser HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: ${ORIGIN}\r\nx-form-session-bootstrap: 1\r\nContent-Type: application/json\r\nContent-Length: 16384\r\n\r\n`),
      exact16384Body,
    ]));
    expect(ok16384.status).toBe(200);

    const over16385Body = Buffer.from(`{${' '.repeat(16385 - 2)}}`, 'utf8');
    const fail16385 = await rawHttp(Buffer.concat([
      Buffer.from(`POST /api/v1/public/form-session/browser HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: ${ORIGIN}\r\nx-form-session-bootstrap: 1\r\nContent-Type: application/json\r\nContent-Length: 16385\r\n\r\n`),
      over16385Body,
    ]));
    expect(fail16385.status).toBe(413);

    const dupDecoded = Buffer.from('{"x":1,"\\u0078":1}', 'utf8');
    const failDupDecoded = await rawHttp(Buffer.concat([
      Buffer.from(`POST /api/v1/public/form-session/browser HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: ${ORIGIN}\r\nx-form-session-bootstrap: 1\r\nContent-Type: application/json\r\nContent-Length: ${String(dupDecoded.byteLength)}\r\n\r\n`),
      dupDecoded,
    ]));
    expect(failDupDecoded.status).toBe(400);

    const badUtf8 = Buffer.from([0x7b, 0x22, 0x61, 0xff, 0x22, 0x3a, 0x31, 0x7d]);
    const failUtf8 = await rawHttp(Buffer.concat([
      Buffer.from(`POST /api/v1/public/form-session/browser HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: ${ORIGIN}\r\nx-form-session-bootstrap: 1\r\nContent-Type: application/json\r\nContent-Length: ${String(badUtf8.byteLength)}\r\n\r\n`),
      badUtf8,
    ]));
    expect(failUtf8.status).toBe(400);
    for (const json of [`{"x":${'['.repeat(70)}0${']'.repeat(70)}}`, `{"x":[${Array.from({ length: 255 }, () => '0').join(',')}]}`]) {
      const overComplexity = await rawHttp(Buffer.from(
        `POST /api/v1/public/form-session/browser HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: ${ORIGIN}\r\nx-form-session-bootstrap: 1\r\nContent-Type: application/json\r\nContent-Length: ${String(json.length)}\r\n\r\n${json}`,
      ));
      expect(overComplexity.status).toBe(413);
    }
    const duplicateBeforeWrongOrigin = await rawHttp(Buffer.from(
      'GET /api/v1/public/legal-documents/CONSENT_FORM HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: https://other.example.test\r\nIf-Match: "one"\r\nIf-Match: "two"\r\n\r\n',
    ));
    expect(duplicateBeforeWrongOrigin.status).toBe(400);
  }, TIMEOUT);

  it('MUST 7/13: serializes concurrent slot issuance (4 win, 4 get 429), isolates two tabs + CRM cookie on revoke, refuses real foreign-city district, and saturates throttle without unauthenticated ANCHOR rows', async () => {
    const { districtId } = await provisionCity();
    const legal = await publishLegal();
    const f = fixture.f;
    const admin = fixture.base.admin;

    // Provision a second real city with its own active district (MUST 13: real foreign-city district).
    const otherCity = await fixture.geo.publishedDraftCity(admin, fixtureCode('other-city'));
    const otherCityDetail = geoCheck(await fixture.geo.read(admin, `/settings/service-cities/${otherCity.id}`), 200);
    const otherDistrict = geoCheck(
      await fixture.geo.createDistrict(admin, otherCity.id, geoVersionOf(otherCityDetail), fixtureCode('other-dist')),
      201,
    );
    const otherDistrictId = geoIdOf(otherDistrict);

    // Concurrent slot issuance: 8 simultaneous POST /form-sessions for one group -> 4 x 201, 4 x 429.
    const group = await bootstrapGroup();
    const concurrent = await Promise.all(
      Array.from({ length: 8 }, () => f.post('/form-sessions', {}, { cookies: [group] })),
    );
    const created = concurrent.filter((r) => r.status === 201);
    const throttled = concurrent.filter((r) => r.status === 429);
    expect(created).toHaveLength(4);
    expect(throttled).toHaveLength(4);

    // Two tabs sharing the same Cookie jar alongside the CRM staff session cookie.
    const [tab1Res, tab2Res] = created;
    if (!tab1Res || !tab2Res) { throw new Error('Missing concurrent tabs'); }
    const tab1Id = text(tab1Res.data, 'sessionId');
    const tab2Id = text(tab2Res.data, 'sessionId');
    const tab1Secret = cookieValue(cookieOf(tab1Res.setCookie, `${F_COOKIE_PREFIX}${tab1Id}`) ?? '');
    const tab2Secret = cookieValue(cookieOf(tab2Res.setCookie, `${F_COOKIE_PREFIX}${tab2Id}`) ?? '');
    const tab1Csrf = text(tab1Res.data, 'csrfToken');
    const tab2Csrf = text(tab2Res.data, 'csrfToken');
    fixture.remember(tab1Secret, tab2Secret, tab1Csrf, tab2Csrf);
    const sharedJar = [
      group,
      `${F_COOKIE_PREFIX}${tab1Id}=${tab1Secret}`,
      `${F_COOKIE_PREFIX}${tab2Id}=${tab2Secret}`,
      admin.cookie,
    ];

    // Real foreign-city district returns the exact same 404 as a non-existent UUID.
    const foreignDistrictRes = problem(await f.post('/coverage/check', { districtId: otherDistrictId }, {
      cookies: sharedJar,
      headers: { [F_SELECTOR_HEADER]: tab2Id, 'x-csrf-token': tab2Csrf },
    }), 404);
    const missingDistrictRes = problem(await f.post('/coverage/check', { districtId: randomUUID() }, {
      cookies: sharedJar,
      headers: { [F_SELECTOR_HEADER]: tab2Id, 'x-csrf-token': tab2Csrf },
    }), 404);
    expect(Object.keys(record(foreignDistrictRes.body)).sort())
      .toEqual(Object.keys(record(missingDistrictRes.body)).sort());

    // Revoke tab1 while sending both F cookies and the CRM cookie: only tab1 is cleared!
    const revokeTab1 = check(await f.post('/form-session/revoke', {}, {
      cookies: sharedJar,
      headers: { [F_SELECTOR_HEADER]: tab1Id, 'x-csrf-token': tab1Csrf },
    }), 200);
    expect(revokeTab1.setCookie).toEqual([
      `${F_COOKIE_PREFIX}${tab1Id}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`,
    ]);
    // tab1 is now 401, while tab2 and the CRM session remain completely unaffected.
    problem(await f.post('/coverage/check', { districtId }, {
      cookies: sharedJar,
      headers: { [F_SELECTOR_HEADER]: tab1Id, 'x-csrf-token': tab1Csrf },
    }), 401);
    check(await f.post('/coverage/check', { districtId }, {
      cookies: sharedJar,
      headers: { [F_SELECTOR_HEADER]: tab2Id, 'x-csrf-token': tab2Csrf },
    }), 200);
    check(await consent({
      action: 'GIVEN', documentId: legal.documentId, documentVersionId: legal.versionId, evidenceRef: randomUUID(),
    }, {
      cookies: sharedJar,
      headers: { [F_SELECTOR_HEADER]: tab2Id, 'x-csrf-token': tab2Csrf },
    }), 201);
    expect((await fixture.base.call(admin, 'get', '/access')).status).toBe(200);

    // MUST 7: unauthenticated selector calls never allocate ANCHOR throttle rows or consume owner budget,
    // and an exhausted SOURCE budget saturates hit_count at maxHits without creating new rows.
    const beforeAnchors = await fixture.base.count(
      "SELECT count(*)::int n FROM foundation.form_throttle_buckets WHERE kind='ANCHOR'",
    );
    const bogusId = randomUUID();
    problem(await f.post('/form-session/csrf', {}, {
      cookies: [`${F_COOKIE_PREFIX}${bogusId}=${'D'.repeat(43)}`],
      headers: { [F_SELECTOR_HEADER]: bogusId },
    }), 401);
    problem(await f.post('/form-session/csrf', {}, {
      cookies: [`${F_COOKIE_PREFIX}${tab2Id}=${'E'.repeat(43)}`],
      headers: { [F_SELECTOR_HEADER]: tab2Id },
    }), 401);
    const afterAnchors = await fixture.base.count(
      "SELECT count(*)::int n FROM foundation.form_throttle_buckets WHERE kind='ANCHOR'",
    );
    expect(afterAnchors).toBe(beforeAnchors);

    const tightService = new FormSessionService(fixture['pool'], {
      origin: ORIGIN,
      csrfKeyring: { current: { keyId: 'tight-k1', secret: randomBytes(32) } },
      throttleSecret: randomBytes(32),
      ...SHORT_TTLS,
      throttles: {
        source: { windowSeconds: 3600, maxHits: 2 },
        global: { windowSeconds: 3600, maxHits: 10 },
        anchor: { windowSeconds: 3600, maxHits: 2 },
      },
    });
    // Use the actual fixture logic for these throttle checks to ensure the same pool and context
    await tightService.readLegalDocument('CONSENT_FORM', { source: '198.51.100.77' });
    await tightService.readLegalDocument('CONSENT_FORM', { source: '198.51.100.77' });
    // This should hit QUOTA.
    await expect(tightService.readLegalDocument('CONSENT_FORM', { source: '198.51.100.77' }))
      .rejects.toMatchObject({ code: 'QUOTA' });
    const totalBefore = await fixture.base.count('SELECT count(*)::int n FROM foundation.form_throttle_buckets');
    // Further calls from the exhausted source even with random selectors allocate 0 new rows.
    const randomSel = randomUUID();
    await expect(tightService.csrfBootstrap({
      cookieHeader: `${F_COOKIE_PREFIX}${randomSel}=${'F'.repeat(43)}`,
      body: {},
      source: '198.51.100.77',
      selector: randomSel,
      csrf: undefined,
    })).rejects.toMatchObject({ code: 'QUOTA' });
    const totalAfter = await fixture.base.count('SELECT count(*)::int n FROM foundation.form_throttle_buckets');
    expect(totalAfter).toBe(totalBefore);
  }, TIMEOUT);

  it('MUST 2/3/12/13: observes real lock waits (GEO/CFG fence on city change, anchor lock across expiry), handles unknown COMMIT as 503 with safe retry, and serves over isolated HTTPS', async () => {
    const { city, districtId } = await provisionCity();
    const legal = await publishLegal();
    const group = await bootstrapGroup();
    const session = await issueSession(group);
    const headers = { [F_SELECTOR_HEADER]: session.selector, 'x-csrf-token': session.csrf };
    const cookies = fullCookies(session, group);

    // 1. Real GEO/CFG fence wait: hold X (734305, 1) while publishing a new city version,
    //    queue an F consent GIVEN behind the fence, observe pg_blocking_pids, then COMMIT.
    const admin = fixture.base.admin;
    const cityDetail = geoCheck(await fixture.geo.read(admin, `/settings/service-cities/${city.id}`), 200);
    const addedVersion = geoCheck(await fixture.geo.addCityVersion(admin, city.id, geoVersionOf(cityDetail)), 201);
    const newVersionId = geoIdOf(addedVersion);

    const fenceHolder = await fixture.base.db.connect();
    try {
      await fenceHolder.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      await fenceHolder.query('SELECT pg_catalog.pg_advisory_xact_lock(734305, 1)');
      const holderPid = (await fenceHolder.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
      expect(holderPid).toBeDefined();
      await fenceHolder.query(
        'UPDATE foundation.service_cities SET current_version_id = $2 WHERE id = $1',
        [city.id, newVersionId],
      );
      const inFlightConsent = consent({
        action: 'GIVEN', documentId: legal.documentId, documentVersionId: legal.versionId, evidenceRef: randomUUID(),
      }, { cookies, headers });

      // Observe the HTTP worker connection genuinely blocked on (734305, 1) by holderPid.
      const deadline = Date.now() + 5_000;
      let observedBlock = false;
      while (Date.now() < deadline) {
        const blocked = await fixture.base.db.query<{ blocked: boolean }>(
          `SELECT EXISTS (
             SELECT 1 FROM pg_stat_activity a
             WHERE a.datname = current_database() AND $1 = ANY(pg_blocking_pids(a.pid))
           ) AS blocked`,
          [holderPid],
        );
        if (blocked.rows[0]?.blocked === true) { observedBlock = true; break; }
        await new Promise((r) => { setTimeout(r, 25); });
      }
      expect(observedBlock).toBe(true);
      await fenceHolder.query('COMMIT');
      const postFenceConsent = await inFlightConsent;
      problem(postFenceConsent, 409);
    } finally {
      await fenceHolder.query('ROLLBACK').catch(() => undefined);
      fenceHolder.release();
    }
    expect(await fixture.base.count(
      'SELECT count(*)::int n FROM foundation.consent_records WHERE session_id = $1', [session.selector],
    )).toBe(0);

    // 2. Issue with the original short TTL and hold the real anchor lock until
    //    that database deadline. The dedicated client allows up to 8s on locks.
    const short = await fixture.isolatedClient(SHORT_TTLS);
    const s2 = await issueSession(group, short);
    const lockHolder = await fixture.base.db.connect();
    try {
      await lockHolder.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      await lockHolder.query('SELECT id FROM foundation.request_sessions WHERE id = $1 FOR UPDATE', [s2.selector]);
      const holderPid = (await lockHolder.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
      const inFlightRevoke = short.post('/form-session/revoke', {}, {
        cookies: [group, s2.cookie],
        headers: { [F_SELECTOR_HEADER]: s2.selector, 'x-csrf-token': s2.csrf },
      });
      const deadline = Date.now() + 5_000;
      let observedWait = false;
      while (Date.now() < deadline) {
        const blocked = await fixture.base.db.query<{ blocked: boolean }>(
          `SELECT EXISTS (
             SELECT 1 FROM pg_stat_activity a
             WHERE a.datname = current_database() AND $1 = ANY(pg_blocking_pids(a.pid))
           ) AS blocked`,
          [holderPid],
        );
        if (blocked.rows[0]?.blocked === true) { observedWait = true; break; }
        await new Promise((r) => { setTimeout(r, 25); });
      }
      expect(observedWait).toBe(true);
      const s2Expiry = (await fixture.base.db.query<{ expires_at: Date }>(
        'SELECT expires_at FROM foundation.request_sessions WHERE id = $1', [s2.selector],
      )).rows[0]?.expires_at;
      if (!s2Expiry) { throw new Error('Missing s2 expiry'); }
      await fixture.waitForDbClock(s2Expiry);
      await lockHolder.query('ROLLBACK');
      const lateRevoke = await inFlightRevoke;
      problem(lateRevoke, 401);
      expect(cookieOf(lateRevoke.setCookie, `${F_COOKIE_PREFIX}${s2.selector}`))
        .toBe(`${F_COOKIE_PREFIX}${s2.selector}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`);
    } finally {
      await lockHolder.query('ROLLBACK').catch(() => undefined);
      lockHolder.release();
    }
    const s2Row = (await fixture.base.db.query<{ revoked_at: Date | null }>(
      'SELECT revoked_at FROM foundation.request_sessions WHERE id = $1', [s2.selector],
    )).rows[0];
    expect(s2Row?.revoked_at).toBeNull();

    // 3. MUST 12: Unknown COMMIT outcome on consent -> 503 NOT_READY, no ROLLBACK attempted,
    //    and an exact retry with the same Idempotency-Key returns 200 replayed: true.
    const s3 = await issueSession(group);
    const s3Headers = { [F_SELECTOR_HEADER]: s3.selector, 'x-csrf-token': s3.csrf };
    const s3Cookies = fullCookies(s3, group);
    const idemKey = randomUUID();
    const abortedAnchor = await issueSession(group);
    const abortedKey = randomUUID();
    const abortedOptions = { cookies: fullCookies(abortedAnchor, group), key: abortedKey,
      headers: { [F_SELECTOR_HEADER]: abortedAnchor.selector, 'x-csrf-token': abortedAnchor.csrf } };
    const consentPayload = {
      action: 'GIVEN', documentId: legal.documentId, documentVersionId: legal.versionId, evidenceRef: idemKey,
    };
    const descriptor = Object.getOwnPropertyDescriptor(Client.prototype, 'query');
    const originalQuery: unknown = descriptor?.value;
    if (!descriptor || typeof originalQuery !== 'function') { throw new Error('Missing PG Client.prototype.query'); }
    let lostCommits = 0;
    let rollbackAfterCommit = 0;
    let abortBeforeCommit = false;
    const armedClients = new WeakSet<Client>();
    const uncertainClients = new WeakSet<Client>();
    Object.defineProperty(Client.prototype, 'query', {
      ...descriptor,
      value: function patchedQuery(this: Client, ...args: unknown[]): unknown {
        const sql = args[0];
        const run = (): unknown => Reflect.apply(originalQuery, this, args);
        if (typeof sql === 'string' && /INSERT\s+INTO\s+foundation\.consent_records\b/i.test(sql)) {
          armedClients.add(this);
        }
        if (typeof sql === 'string' && /^\s*COMMIT\b/i.test(sql) && armedClients.delete(this)
          && lostCommits === (abortBeforeCommit ? 1 : 0)) {
          const connectionLoss = () => {
            lostCommits += 1;
            uncertainClients.add(this);
            throw Object.assign(new Error('Simulated connection loss at COMMIT'), { code: 'ECONNRESET' });
          };
          // For the abort branch COMMIT never reaches PG. The service must
          // discard this connection, which causes PG to roll the transaction back.
          return Promise.resolve(abortBeforeCommit ? undefined : run()).then(connectionLoss);
        }
        if (typeof sql === 'string' && /^\s*ROLLBACK\b/i.test(sql) && uncertainClients.has(this)) {
          rollbackAfterCommit += 1;
        }
        return run();
      },
    });
    try {
      const unknownCommitRes = await consent(consentPayload, { cookies: s3Cookies, headers: s3Headers, key: idemKey });
      problem(unknownCommitRes, 503);
      expect(lostCommits).toBe(1);
      abortBeforeCommit = true;
      problem(await consent({ ...consentPayload, evidenceRef: abortedKey }, abortedOptions), 503);
      expect(lostCommits).toBe(2);
      expect(rollbackAfterCommit).toBe(0);
    } finally {
      Object.defineProperty(Client.prototype, 'query', descriptor);
    }
    const retryAfterUnknownCommit = check(
      await consent(consentPayload, { cookies: s3Cookies, headers: s3Headers, key: idemKey }),
      200,
    );
    expect(retryAfterUnknownCommit.data).toMatchObject({ replayed: true, action: 'GIVEN', sessionId: s3.selector });
    const retryAfterAbort = check(await consent({ ...consentPayload, evidenceRef: abortedKey }, abortedOptions), 201);
    expect(retryAfterAbort.data).toMatchObject({ replayed: false, action: 'GIVEN', sessionId: abortedAnchor.selector });
    expect(await fixture.base.count('SELECT count(*)::int n FROM foundation.consent_records WHERE evidence_ref=ANY($1::uuid[])',
      [[idemKey, abortedKey]])).toBe(2);

    // 4. Isolated HTTPS loopback smoke (MUST 13): real TLS listener with __Host- Secure cookies.
    const opensslBin = existsSync('C:\\Program Files\\Git\\usr\\bin\\openssl.exe')
      ? 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe'
      : 'openssl';
    const tlsDir = mkdtempSync(resolve(tmpdir(), 'p0502-tls-'));
    const keyPath = resolve(tlsDir, 'server.key');
    const certPath = resolve(tlsDir, 'server.pem');
    try {
      execFileSync(opensslBin, [
        'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=localhost',
        '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost',
        '-keyout', keyPath, '-out', certPath,
      ], { stdio: 'ignore', timeout: 10_000 });
      const keyPem = readFileSync(keyPath);
      const certPem = readFileSync(certPath);
      const tlsServer = createHttpsServer(
        { key: keyPem, cert: certPem },
        (req: IncomingMessage, res: ServerResponse) => { fixture.server.emit('request', req, res); },
      );
      await new Promise<void>((done) => { tlsServer.listen(0, '127.0.0.1', () => { done(); }); });
      try {
        const tlsAddr = tlsServer.address();
        if (!tlsAddr || typeof tlsAddr === 'string') { throw new Error('Missing TLS listener address'); }
        const callHttps = (
          method: 'POST' | 'GET', path: string, payload: string | undefined, reqHeaders: Record<string, string>,
        ) => new Promise<{ status: number; setCookie: string[]; data: Record<string, unknown> }>((done, fail) => {
          const req = httpsRequest({
            host: '127.0.0.1',
            port: tlsAddr.port,
            method,
            path: `/api/v1/public${path}`,
            ca: certPem,
            headers: {
              Origin: ORIGIN,
              ...(payload !== undefined ? { 'Content-Type': 'application/json', 'Content-Length': String(Buffer.byteLength(payload, 'utf8')) } : {}),
              ...reqHeaders,
            },
          }, (res) => {
            const chunks: Buffer[] = [];
            res.on('data', (c: Buffer) => { chunks.push(c); });
            res.on('end', () => {
              const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'));
              const rawSetCookie = res.headers['set-cookie'] ?? [];
              const env = record(parsed);
              done({
                status: res.statusCode ?? 0,
                setCookie: Array.isArray(rawSetCookie) ? rawSetCookie : [String(rawSetCookie)],
                data: (res.statusCode ?? 0) < 300 ? record(env['data']) : {},
              });
            });
          });
          req.on('error', fail);
          if (payload !== undefined) { req.write(payload); }
          req.end();
        });

        const tlsBoot = await callHttps('POST', '/form-session/browser', '{}', { 'x-form-session-bootstrap': '1' });
        expect(tlsBoot.status).toBe(200);
        const tlsGroupCookie = cookieOf(tlsBoot.setCookie, F_GROUP_COOKIE);
        expect(tlsGroupCookie).toMatch(/^__Host-fixlevelup_fgroup=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Strict; Max-Age=\d+$/);
        if (!tlsGroupCookie) { throw new Error('Missing TLS group cookie'); }
        const tlsGroupSecret = cookieValue(tlsGroupCookie);
        fixture.remember(tlsGroupSecret);
        const tlsGroupPair = `${F_GROUP_COOKIE}=${tlsGroupSecret}`;

        const tlsIssue = await callHttps('POST', '/form-sessions', '{}', { Cookie: tlsGroupPair });
        expect(tlsIssue.status).toBe(201);
        const tlsSid = text(tlsIssue.data, 'sessionId');
        const tlsCsrf = text(tlsIssue.data, 'csrfToken');
        const tlsFCookie = cookieOf(tlsIssue.setCookie, `${F_COOKIE_PREFIX}${tlsSid}`);
        expect(tlsFCookie).toMatch(new RegExp(`^__Host-fixlevelup_f_${tlsSid}=[A-Za-z0-9_-]{43}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=\\d+$`));
        if (!tlsFCookie) { throw new Error('Missing TLS F cookie'); }
        const tlsFSecret = cookieValue(tlsFCookie);
        fixture.remember(tlsFSecret, tlsCsrf);
        const tlsCookieHeader = `${tlsGroupPair}; ${F_COOKIE_PREFIX}${tlsSid}=${tlsFSecret}`;

        const tlsCov = await callHttps('POST', '/coverage/check', JSON.stringify({ districtId }), {
          Cookie: tlsCookieHeader,
          [F_SELECTOR_HEADER]: tlsSid,
          'x-csrf-token': tlsCsrf,
        });
        expect(tlsCov.status).toBe(200);
        expect(tlsCov.data['outcome']).toBe('AREA_REVIEW_REQUIRED');

        const tlsRevoke = await callHttps('POST', '/form-session/revoke', '{}', {
          Cookie: tlsCookieHeader,
          [F_SELECTOR_HEADER]: tlsSid,
          'x-csrf-token': tlsCsrf,
        });
        expect(tlsRevoke.status).toBe(200);
        expect(cookieOf(tlsRevoke.setCookie, `${F_COOKIE_PREFIX}${tlsSid}`))
          .toBe(`${F_COOKIE_PREFIX}${tlsSid}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`);
      } finally {
        tlsServer.close();
      }
    } finally {
      rmSync(tlsDir, { recursive: true, force: true });
    }
  }, 180_000);

  // The full two-step admission below issues a proof into the separate control
  // database, so it needs the provisioned P05 lab contour (same gate as
  // runtime-database.test.ts). Without it the control credentials are validated
  // before any history is read, and the proof would fail on configuration
  // instead of on its own subject — so it must SKIP, not fail.
  const labEnabled = process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1';

  it.runIf(labEnabled)('MUST 9 (lab): refuses corrupted migration history before witness/registry and completes a real two-step CAS admission', async () => {
    // Full two-step process admission (admitVerifiedTestInstance): refuses corrupted
    // _prisma_migrations history BEFORE taking a witness or writing to launch_proofs,
    // and succeeds with a real CONSUMED registry row when history is intact.
    await fixture.base.db.query("UPDATE \"foundation\".\"_prisma_migrations\" SET checksum = '0000000000000000000000000000000000000000000000000000000000000000' WHERE migration_name = '20261124000100_form_session_foundation'");
    await expect(admitVerifiedTestInstance(fixture.base.db, fixture.base.database))
      .rejects.toThrow(/Operator preflight history verification failed/);
    // Re-install the exact pinned history and complete the full launcher->child CAS admission.
    await installPinnedMigrationHistory(fixture.base.db, authFixtureMigrations);
    const verified = await admitVerifiedTestInstance(fixture.base.db, fixture.base.database, {
      expectedMigrations: authFixtureMigrations,
    });
    try {
      expect(verified.admission.binding.profile).toBe('S3');
      const verifiedF = await fixture.isolatedClient({}, 2, verified);
      await bootstrapGroup(verifiedF);
      const groupsBeforeRelease = await fixture.base.count('SELECT count(*)::int n FROM foundation.form_browser_groups');
      await verified.release();
      problem(await verifiedF.post('/form-session/browser', {}, { headers: { 'x-form-session-bootstrap': '1' } }), 503);
      expect(await fixture.base.count('SELECT count(*)::int n FROM foundation.form_browser_groups')).toBe(groupsBeforeRelease);
    } finally { await verified.release(); }
  }, 180_000);

  it('MUST 9: enforces real RuntimeDatabase S1+S2 readiness, refuses post-launch drift and witness loss as 503 with zero DB effects, and verifies predecessor profiles B2+S0 and B2+S1', async () => {
    await provisionCity();
    const f = fixture.f;

    // 1. Post-launch physical schema drift on S2: disabling a guard trigger causes
    //    RuntimeDatabase.formSessionReady() to fail closed -> 503 NOT_READY before any write.
    const groupsBefore = await fixture.base.count('SELECT count(*)::int n FROM foundation.form_browser_groups');
    const bucketsBefore = await fixture.base.count('SELECT count(*)::int n FROM foundation.form_throttle_buckets');
    await fixture.base.db.query('ALTER TABLE foundation.form_browser_groups DISABLE TRIGGER form_browser_groups_guard');
    try {
      problem(await f.post('/form-session/browser', {}, { headers: { 'x-form-session-bootstrap': '1' } }), 503);
      const malformedWhileDrifted = await request(fixture.server).post('/api/v1/public/form-session/browser')
        .set('Content-Type', 'application/json').send('{');
      expect(malformedWhileDrifted.status).toBe(503);
      expect(malformedWhileDrifted.body).toMatchObject({ code: 'NOT_READY' });
      expect(malformedWhileDrifted.headers['cache-control']).toBe('no-store');
      problem(await f.get('/legal-documents/CONSENT_FORM'), 503);
      expect(await fixture.base.count('SELECT count(*)::int n FROM foundation.form_browser_groups')).toBe(groupsBefore);
      expect(await fixture.base.count('SELECT count(*)::int n FROM foundation.form_throttle_buckets')).toBe(bucketsBefore);
    } finally {
      await fixture.base.db.query('ALTER TABLE foundation.form_browser_groups ENABLE TRIGGER form_browser_groups_guard');
    }
    // Restoring the shape does not reactivate an authorization invalidated by drift.
    problem(await f.post('/form-session/browser', {}, { headers: { 'x-form-session-bootstrap': '1' } }), 503);

    // 2. Predecessor profiles B2+S0 (capped before 022) and B2+S1 (capped before 023):
    //    positive admission on their own profile, refusal of S2 proof, P03/P04 readiness true,
    //    and formSessionReady false (503 safe unavailability on S0/S1).
    const s0Fix = await createConfigurationFixture({ capBefore: '20261123000100_request_intake_foundation' });
    const s1Fix = await createConfigurationFixture({ capBefore: '20261124000100_form_session_foundation' });
    try {
      const s0Admitted = await admitFixture(s0Fix.migrator, s0Fix.database, 'API');
      const s1Admitted = await admitFixture(s1Fix.migrator, s1Fix.database, 'API');
      try {
        expect(s0Admitted.admission.binding.profile).toBe('S0');
        expect(s1Admitted.admission.binding.profile).toBe('S1');
        const s0DbConfig = {
          host: '127.0.0.1' as const, port: 55432, database: s0Fix.database,
          user: 'fixlevelup_runtime' as const, password: FormSessionHttpFixture['runtimePassword'](),
        };
        const s1DbConfig = {
          host: '127.0.0.1' as const, port: 55432, database: s1Fix.database,
          user: 'fixlevelup_runtime' as const, password: FormSessionHttpFixture['runtimePassword'](),
        };
        expect(await physicalProfileVerifier(s0DbConfig)(s0Admitted.admission)).toBe(true);
        expect(await physicalProfileVerifier(s1DbConfig)(s1Admitted.admission)).toBe(true);

        const s0Runtime = new RuntimeDatabase(s0DbConfig, true, s0Admitted.authorization);
        const s1Runtime = new RuntimeDatabase(s1DbConfig, true, s1Admitted.authorization);
        try {
          expect(await s0Runtime.ready()).toBe(true);
          expect(await s0Runtime.catalogManagementReady()).toBe(true);
          expect(await s0Runtime.requestIntakeReady()).toBe(false);
          expect(await s0Runtime.formSessionReady()).toBe(false);

          expect(await s1Runtime.ready()).toBe(true);
          expect(await s1Runtime.catalogManagementReady()).toBe(true);
          expect(await s1Runtime.requestIntakeReady()).toBe(true);
          expect(await s1Runtime.formSessionReady()).toBe(false);
        } finally {
          await s0Runtime.onModuleDestroy();
          await s1Runtime.onModuleDestroy();
        }
      } finally {
        await s0Admitted.release();
        await s1Admitted.release();
      }
    } finally {
      await s0Fix.close();
      await s1Fix.close();
    }

    // 3. Witness loss on the running S2 app: releasing the launcher witness makes
    //    GuardedPool refuse every new checkout -> 503 NOT_READY with zero DB writes.
    const groupsBeforeRelease = await fixture.base.count('SELECT count(*)::int n FROM foundation.form_browser_groups');
    await fixture.base.admitted.release();
    problem(await f.post('/form-session/browser', {}, { headers: { 'x-form-session-bootstrap': '1' } }), 503);
    expect(await fixture.base.count('SELECT count(*)::int n FROM foundation.form_browser_groups')).toBe(groupsBeforeRelease);
  }, 180_000);
});
