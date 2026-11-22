import { createHash, randomUUID } from 'node:crypto';
import { request } from 'node:http';
import type { ClientRequest, OutgoingHttpHeaders } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import { ConsoleLogger } from '@nestjs/common';
import { Client } from 'pg';
import type { PoolClient } from 'pg';
import { beforeEach, expect, vi } from 'vitest';
import { GeographyFixture, check, geoTag, records, text } from './geography-fixture.js';
import { fixturePerTest, record } from './rbac-fixture.js';
import type { RbacFixture, Web } from './rbac-fixture.js';

export const ORIGIN = 'https://crm.example.test';
export const PRIVATE_MARKER = 'synthetic-p03-private-marker-не-выводить';
export const COMPANY_FIELDS = {
  operatorName: 'Synthetic operator', operatorRegistrationId: 'Fixture registration',
  operatorAddress: 'Synthetic operator address', legalReviewRef: 'fixture-legal-review',
  securityPolicyRef: 'fixture-security', retentionPolicyRef: 'fixture-retention', uploadPolicyRef: 'fixture-upload',
};
export const contentInput = (body = PRIVATE_MARKER) => ({ title: 'Synthetic title', body, sourceRef: 'fixture-content-source' });
export const legalInput = (body = PRIVATE_MARKER) => ({ ...contentInput(body), legalBasis: 'Synthetic basis' });
export const p03Tag = (version: number) => `"p03-v${String(version)}"`;
export const fixtureCode = (prefix: string) => `${prefix}-${randomUUID().slice(0, 8)}`;
export const referencePath = (type: string) => `/settings/references/${type}`;
export const idOf = (r: Pick<HttpResult, 'data'>) => text(r.data, 'id');
export type Grant = { code: string; scope: 'GLOBAL' | 'CITY' | 'SELF' };
export const global = (code: string): Grant => ({ code, scope: 'GLOBAL' });
export const city = (code: string): Grant => ({ code, scope: 'CITY' });

export interface HttpResult {
  readonly status: number; readonly data: Record<string, unknown>; readonly body: unknown;
  readonly etag: string; readonly bytes: number; readonly contentType: string;
}
export interface HttpOptions {
  readonly web?: Web | { readonly token: string } | null;
  readonly key?: string | null; readonly etag?: string; readonly origin?: string; readonly csrf?: string;
  readonly headers?: OutgoingHttpHeaders;
  readonly safeBody?: boolean;
}
function isWeb(web: Web | { readonly token: string }): web is Web { return 'cookie' in web; }

export function minimal(r: Pick<HttpResult, 'data' | 'etag'>, revision = false): void {
  expect(Object.keys(r.data).sort()).toEqual(revision ? ['id', 'revisionId', 'revisionVersion', 'version'] : ['id', 'version']);
  expect(text(r.data, 'id')).toMatch(/^[0-9a-f-]{36}$/);
  expect(r.data['version']).toBeGreaterThan(0);
  expect(r.etag).toBe(p03Tag(Number(r.data['version'])));
  if (revision) {
    expect(text(r.data, 'revisionId')).toMatch(/^[0-9a-f-]{36}$/);
    expect(r.data['revisionVersion']).toBeGreaterThan(0);
  }
}

export function problem(r: Pick<HttpResult, 'status' | 'body'>, status: number): void {
  check(r, status);
  if (!('contentType' in r) || !('bytes' in r)) { throw new Error('Expected raw HTTP evidence'); }
  expect(r.contentType).toMatch(/^application\/problem\+json(?:;|$)/);
  expect(Object.keys(record(r.body)).sort()).toEqual(['code', 'requestId', 'status', 'title', 'type']);
  const body = record(r.body);
  const code = status === 500 ? 'INTERNAL_ERROR' : status === 503 ? 'NOT_READY' : status === 404 ? 'NOT_FOUND' : 'REQUEST_REJECTED';
  expect(body).toMatchObject({ type: 'about:blank', status, code, title: code });
  expect(text(body, 'requestId')).toMatch(/^[0-9a-f-]{36}$/);
  expect(r.bytes).toBeLessThan(1024);
}

export class ManagementFixture {
  readonly geo: GeographyFixture;
  private readonly secrets = new Set([PRIVATE_MARKER]);
  constructor(readonly base: RbacFixture, private readonly logs: readonly unknown[]) {
    this.geo = new GeographyFixture(base);
  }
  get admin(): Web { return this.base.admin; }
  remember(...secrets: string[]): void { for (const secret of secrets) { this.secrets.add(secret); } }
  assertClean(value: unknown, includesPayload = true): void {
    const json = JSON.stringify(value);
    expect([...this.secrets].some((secret) => (includesPayload || secret !== PRIVATE_MARKER) && json.includes(secret))).toBe(false);
  }
  async read(path: string, options: HttpOptions = {}): Promise<HttpResult> { return this.http('GET', path, undefined, options); }
  async post(path: string, input: object = {}, options: HttpOptions = {}): Promise<HttpResult> {
    return this.http('POST', path, (req) => req.end(JSON.stringify(input)), options);
  }
  async chunked(method: string, path: string, bytes: Buffer, options: HttpOptions = {}): Promise<HttpResult> {
    return this.http(method, path, async (req) => {
      // First cut can bisect a UTF-8 code point; no Content-Length is sent.
      for (let offset = 0; offset < bytes.length && !req.destroyed; ) {
        const end = Math.min(bytes.length, offset + 2053);
        if (!req.write(bytes.subarray(offset, end))) {
          // Leave the response/close events to settle a rejected request. Chunk sizes
          // are bounded, and flushing yields to the actual TCP peer between batches.
          await delay(1);
        }
        offset = end;
      }
      if (!req.destroyed) { req.end(); }
    }, { ...options, headers: { 'Transfer-Encoding': 'chunked', ...options.headers } });
  }
  async http(method: string, path: string, send?: (req: ClientRequest) => unknown, options: HttpOptions = {}): Promise<HttpResult> {
    const web = options.web === undefined ? this.admin : options.web;
    const headers: OutgoingHttpHeaders = { Origin: options.origin ?? ORIGIN, ...options.headers };
    if (web && isWeb(web)) {
      this.remember(web.token, web.csrf, web.password);
      headers['Cookie'] = web.cookie;
      if (method !== 'GET') { headers['X-CSRF-Token'] = options.csrf ?? web.csrf; }
    } else if (web) {
      this.remember(web.token);
      headers['Authorization'] = `Bearer ${web.token}`;
    }
    if (send) { headers['Content-Type'] ??= 'application/json'; }
    if (method !== 'GET' && options.key !== null) { headers['Idempotency-Key'] = options.key ?? randomUUID(); }
    if (options.etag !== undefined) { headers['If-Match'] = options.etag; }
    const result = await new Promise<HttpResult>((resolve, reject) => {
      const req = request({ host: '127.0.0.1', port: this.base.httpPort, path: `/api/v1${path}`, method, headers, agent: false }, (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => { chunks.push(chunk); });
        response.once('error', reject);
        response.once('end', () => {
          try {
            expect(response.headers['cache-control']).toBe('no-store');
            const raw = Buffer.concat(chunks);
            const body: unknown = JSON.parse(raw.toString('utf8'));
            const status = response.statusCode ?? 0;
            resolve({ status, body, data: status < 300 ? record(record(body)['data']) : {},
              etag: response.headers.etag ?? '', contentType: response.headers['content-type'] ?? '', bytes: raw.length });
          } catch (error) { reject(error instanceof Error ? error : new Error('Malformed fixture response')); }
        });
      });
      const emergency = setTimeout(() => { req.destroy(new Error('Fixture HTTP deadline')); }, 16_000);
      req.once('close', () => { clearTimeout(emergency); });
      req.once('error', reject);
      if (send) { void Promise.resolve(send(req)).catch(reject); } else { req.end(); }
    });
    this.assertClean(result.body, result.status >= 300 || options.safeBody !== false);
    this.assertClean(this.logs);
    return result;
  }
  async addRoleGrants(roleId: string, additions: readonly Grant[], actor = this.admin) {
    const path = `/roles/${roleId}`;
    const detail = check(await this.base.call(actor, 'get', path), 200);
    const old = records(detail.data['permissions']).filter((row) => !additions.some(({ code }) => code === row['code']));
    return this.base.call(actor, 'put', `${path}/permissions`, { permissions: [...old, ...additions] }, detail.etag);
  }
  async assignCity(staffId: string, cityId: string, actor = this.admin) {
    return this.geo.write(actor, 'post', `/settings/service-cities/${cityId}/administrators/${staffId}/assignments`, {},
      { etag: geoTag(await this.geo.staffVersion(staffId)) });
  }
  async shortenSession(web: Web, kind: 'idle' | 'absolute', milliseconds = 1200): Promise<Date> {
    const hash = createHash('sha256').update(web.token).digest('hex');
    const columns = kind === 'absolute'
      ? 'idle_expires_at=expiry.at, absolute_expires_at=expiry.at' : 'idle_expires_at=expiry.at';
    const row = (await this.base.db.query<{ at: Date }>(`UPDATE foundation.web_sessions SET ${columns}
      FROM (SELECT clock_timestamp() + $2::integer * interval '1 millisecond' AS at) expiry WHERE token_hash=$1 RETURNING expiry.at`,
    [hash, milliseconds])).rows[0];
    if (!row) { throw new Error('Missing live fixture session'); }
    return row.at;
  }
  async backend(client: PoolClient): Promise<number> {
    const result = (await client.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0];
    if (!result) { throw new Error('Missing independent PG backend'); }
    return result.pid;
  }
  async waitForLock(blocker: number, table: string, mode: string): Promise<number> {
    const deadline = performance.now() + 3500;
    do {
      const row = (await this.base.db.query<{ pid: number }>(`SELECT l.pid FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid
        WHERE a.datname=current_database() AND a.usename='fixlevelup_runtime' AND NOT l.granted AND l.locktype='relation'
        AND l.relation=to_regclass($2) AND l.mode=$3 AND $1=ANY(pg_blocking_pids(l.pid))`, [blocker, `foundation.${table}`, mode])).rows[0];
      if (row) { return row.pid; }
      await delay(15);
    } while (performance.now() < deadline);
    throw new Error(`Expected real PostgreSQL wait on ${table}/${mode}`);
  }
  async waitForPolicyWait(holder: number): Promise<number> {
    const deadline = performance.now() + 3500;
    do {
      const row = (await this.base.db.query<{ pid: number }>(`WITH key AS (SELECT hashtextextended('fixlevelup:admin-invariant',0) AS k)
        SELECT wait.pid FROM pg_locks wait JOIN pg_locks own USING(database,classid,objid,objsubid) CROSS JOIN key
        WHERE own.pid=$1 AND own.granted AND own.mode='ExclusiveLock' AND NOT wait.granted
          AND own.locktype='advisory' AND wait.locktype='advisory' AND own.objsubid=1
          AND own.classid::bigint=((k>>32)&4294967295) AND own.objid::bigint=(k&4294967295)
          AND own.pid=ANY(pg_blocking_pids(wait.pid))`, [holder])).rows[0];
      if (row) { return row.pid; }
      await delay(15);
    } while (performance.now() < deadline);
    throw new Error('Expected queued policy lock on real PostgreSQL');
  }
  async waitForExpiry(expiresAt: Date): Promise<void> {
    const deadline = performance.now() + 5500;
    do {
      if ((await this.base.db.query<{ expired: boolean }>('SELECT clock_timestamp() >= $1 AS expired', [expiresAt])).rows[0]?.expired) { return; }
      await delay(15);
    } while (performance.now() < deadline);
    throw new Error('Fixture did not observe DB-clock expiry');
  }
  async assertSafeEvidence(): Promise<void> {
    const rows = await this.base.db.query(`SELECT to_jsonb(r) AS v FROM foundation.p03_command_receipts r
      UNION ALL SELECT details FROM foundation.audit_logs UNION ALL SELECT payload FROM foundation.outbox_events`);
    this.assertClean(rows.rows);
    this.assertClean(this.logs);
  }
  private observeReceiptTransaction(beforeRead?: () => Promise<void>, loseAck = false): { fired: () => number; restore: () => void } {
    const descriptor = Object.getOwnPropertyDescriptor(Client.prototype, 'query');
    const original: unknown = descriptor?.value;
    if (!descriptor || typeof original !== 'function') { throw new Error('Missing pg driver query boundary'); }
    const invoke = original;
    const database = this.base.database;
    const seen = new WeakSet<Client>();
    let fired = 0;
    function query(this: Client, ...args: unknown[]): unknown {
      const sql = args[0];
      const run = (): unknown => Reflect.apply(invoke, this, args);
      const origin = this as Client & { database: string; user: string };
      if (origin.database !== database || origin.user !== 'fixlevelup_runtime' || typeof sql !== 'string') { return run(); }
      if (beforeRead && /SELECT\s+request_sha256\b[\s\S]+?FROM\s+foundation\.p03_command_receipts\b/iu.test(sql) && fired === 0) {
        fired += 1;
        return beforeRead().then(run);
      }
      if (loseAck && /INSERT\s+INTO\s+foundation\.p03_command_receipts\b/iu.test(sql)) {
        return Promise.resolve(run()).then((result) => { seen.add(this); return result; });
      }
      if (loseAck && /^\s*COMMIT\s*;?\s*$/iu.test(sql) && seen.delete(this) && fired === 0) {
        return Promise.resolve(run()).then(() => {
          fired += 1;
          throw Object.assign(new Error(PRIVATE_MARKER), { code: 'ECONNRESET' });
        });
      }
      return run();
    }
    Object.defineProperty(Client.prototype, 'query', { ...descriptor, value: query });
    return { fired: () => fired, restore: () => { Object.defineProperty(Client.prototype, 'query', descriptor); } };
  }
  /** Install independent PG lock/fault only after readiness and locked auth; the statement itself still executes in PG. */
  beforeReceiptSelect(run: () => Promise<void>) { return this.observeReceiptTransaction(run); }
  /** Hide only the driver acknowledgement of the successfully executed real COMMIT. */
  loseNextCommitReply() { return this.observeReceiptTransaction(undefined, true); }
}

export function managementPerTest(): () => ManagementFixture {
  const base = fixturePerTest();
  let value: ManagementFixture;
  beforeEach(() => {
    const logs: unknown[] = [];
    // RbacFixture already suppresses ConsoleLogger.log. Keep real SafeLogger as
    // installed by createApi; record only what would have left through this sink.
    const sink: unknown = Object.getOwnPropertyDescriptor(ConsoleLogger.prototype, 'log')?.value;
    if (!vi.isMockFunction(sink)) { throw new Error('Missing fixture log sink'); }
    sink.mockImplementation((...args: unknown[]) => { logs.push(args); });
    value = new ManagementFixture(base(), logs);
  });
  return () => value;
}
