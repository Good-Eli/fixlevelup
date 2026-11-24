import 'reflect-metadata';
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { Server } from 'node:http';
import { resolve } from 'node:path';
import { ConsoleLogger, HttpException } from '@nestjs/common';
import { StaffService } from '../src/staff/staff.service.js';
import { Client, Pool } from 'pg';
import type { PoolClient } from 'pg';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, vi } from 'vitest';
import { createApi } from '../src/bootstrap/factories.js';
import { authFixtureMigrations } from './auth-db-fixture.js';
import { admitFixture } from './admission-fixture.js';
import type { AdmittedHandle } from './admission-fixture.js';
import { loadConfig } from '../src/runtime/config.js';
import { SafeLogger } from '../src/runtime/safe-logger.js';
import { bootstrapFirstAdmin } from '../src/staff/bootstrap.js';
import { hashPassword } from '../src/staff/password.js';

export const integration = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1' ? describe : describe.skip;
const root = resolve(import.meta.dirname, '../../..');
const connection = { host: '127.0.0.1' as const, port: 55432 };
const origin = 'https://crm.example.test';
const random = () => randomBytes(24).toString('hex');
export type Method = 'get' | 'patch' | 'post' | 'put';
export interface Web { id: string; cookie: string; csrf: string; token: string; login: string; password: string }
export interface Result { status: number; data: Record<string, unknown>; body: unknown; etag: string }
export function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) { throw new Error('Expected object'); }
  return value as Record<string, unknown>;
}
export function text(obj: Record<string, unknown>, key: string): string {
  const v = obj[key]; if (typeof v !== 'string') { throw new Error(`Expected string field: ${key}`); } return v;
}
export function items(result: Result): Record<string, unknown>[] {
  const value = result.data['items']; if (!Array.isArray(value)) { throw new Error('Expected items array'); } return value.map(record);
}
export function check(result: Result, status: number): Result { expect(result.status).toBe(status); return result; }
export const grant = (code: string) => ({ code, scope: code.startsWith('staff.self.') ? 'SELF' : 'GLOBAL' });

export class RbacFixture {
  readonly database: string;
  constructor(private readonly options: { readonly p04?: true } = {}) {
    const prefix = options.p04 === true ? 'fixlevelup_configuration_test' : 'fixlevelup_rbac_test';
    this.database = `${prefix}_${randomBytes(12).toString('hex')}`;
  }
  readonly botToken = `7000000002:${random()}`;
  private pool?: Pool;
  private admission?: AdmittedHandle;
  private app?: Awaited<ReturnType<typeof createApi>>;
  private server!: Server;
  admin!: Web;
  private initialized = false;
  /** Set exactly when this run's CREATE DATABASE succeeded (CREATE is the reuse guard). */
  private dbCreated = false;
  private closed = false;
  private adminPassword?: string;
  get ready() { return this.initialized; }
  get httpPort(): number {
    const a = this.server.address(); if (!a || typeof a === 'string' || a.address !== '127.0.0.1') { throw new Error('Missing loopback listener'); }
    return a.port;
  }
  private secrets: string[] = [];
  private logs = vi.spyOn(ConsoleLogger.prototype, 'log').mockImplementation(() => undefined);
  get db(): Pool { if (!this.pool) { throw new Error('Missing isolated fixture'); } return this.pool; }
  async start(): Promise<void> {
    const name = this.options.p04 === true ? /^fixlevelup_configuration_test_[a-f0-9]{24}$/ : /^fixlevelup_rbac_test_[a-f0-9]{24}$/;
    if (process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] !== '1' || !name.test(this.database)) { throw new Error('Refusing non-isolated DB'); }
    const adminEnv = readFileSync(resolve(root, 'infra/dev-postgres/.env'), 'utf8');
    const runtimeEnv = readFileSync(resolve(root, 'packages/database-tooling/.env'), 'utf8');
    const postgresPassword = /^POSTGRES_PASSWORD=([a-f0-9]{64})$/m.exec(adminEnv)?.[1];
    const runtimePassword = /^FIXLEVELUP_RUNTIME_PASSWORD=([a-f0-9]{64})$/m.exec(runtimeEnv)?.[1];
    const migratorPassword = /^FIXLEVELUP_MIGRATOR_PASSWORD=([a-f0-9]{64})$/m.exec(runtimeEnv)?.[1];
    if (!postgresPassword || !runtimePassword || !migratorPassword) { throw new Error('Missing local test credentials'); }
    this.secrets.push(postgresPassword, runtimePassword, migratorPassword, this.botToken);
    this.adminPassword = postgresPassword;
    // No connection to the working dev DB. Maintenance role can only reach these three DDL statements;
    // it is closed before migrations, bootstrap, fixtures or HTTP start. CREATE must succeed (no reuse).
    const maintenance = new Pool({ ...connection, database: 'postgres', user: 'fixlevelup_dev', password: postgresPassword, max: 1 });
    try {
      await maintenance.query(`CREATE DATABASE "${this.database}" OWNER fixlevelup_migrator TEMPLATE template0`);
      this.dbCreated = true;
      await maintenance.query(`REVOKE ALL ON DATABASE "${this.database}" FROM PUBLIC`);
      await maintenance.query(`GRANT CONNECT ON DATABASE "${this.database}" TO fixlevelup_migrator, fixlevelup_runtime`);
    } finally { await maintenance.end(); }
    try {
      this.pool = new Pool({ ...connection, database: this.database, user: 'fixlevelup_migrator', password: migratorPassword });
      const actual = await this.db.query<{ db: string }>('SELECT current_database() AS db');
      if (actual.rows[0]?.db !== this.database) { throw new Error('Fixture DB mismatch'); }
      await this.db.query('CREATE SCHEMA foundation AUTHORIZATION fixlevelup_migrator');
      for (const migration of authFixtureMigrations) { await this.db.query(readFileSync(resolve(root, 'prisma/migrations', migration, 'migration.sql'), 'utf8')); }
      await this.db.query('CREATE TABLE foundation._prisma_migrations (id text PRIMARY KEY)');
      const login = random(); const password = random();
      const { staffId } = await bootstrapFirstAdmin(this.db, { login, password });
      // P05-01: the app is admitted through the same launch gate contour — a real
      // migrator-held witness in this fixture DB pins the admission.
      this.admission = await admitFixture(this.db, this.database, 'API');
      this.app = await createApi(loadConfig({ NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0' }), new SafeLogger('api'),
        { ...connection, database: this.database, user: 'fixlevelup_runtime', password: runtimePassword },
        { origin, csrfSecret: random(), throttleSecret: random() }, { botToken: this.botToken }, this.admission.authorization);
      this.server = this.app.getHttpServer() as Server;
      this.admin = await this.login(staffId, login, password); this.initialized = true;
    } catch (error) {
      // Provisioning failed after CREATE: the same lifecycle cleanup runs before rethrowing.
      await this.close().catch(() => undefined);
      throw error;
    }
  }
  /** No automatic issue at setup, login, startup or recovery. Only a fresh opted-in fixture can call this. */
  async issueP04Synthetic(): Promise<void> {
    if (!this.initialized || this.options.p04 !== true || process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] !== '1'
      || !/^fixlevelup_configuration_test_[a-f0-9]{24}$/.test(this.database)) { throw new Error('Refusing P04 synthetic issuance'); }
    const client = await this.db.connect();
    try {
      const { rows } = await client.query<{ ok: boolean }>(`SELECT current_database()=$1 AND current_user='fixlevelup_migrator'
        AND pg_get_userbyid(datdba)=current_user AS ok FROM pg_database WHERE datname=current_database()`, [this.database]);
      if (rows[0]?.ok !== true) { throw new Error('P04 fixture migrator identity mismatch'); }
      await client.query('SELECT foundation.issue_p04_synthetic_permissions()');
    } finally { client.release(); }
  }
  /**
   * Ownership proof for the teardown drop. Returns this fixture's database name only
   * when BOTH hold: this run's CREATE DATABASE succeeded (the `dbCreated` flag), and the
   * name still matches this fixture's strict disposable-name pattern. Consumes the
   * flag, so a second call (double close) never drops anything.
   */
  private takeCreatedDatabase(): string | undefined {
    if (!this.dbCreated) { return undefined; }
    this.dbCreated = false;
    const pattern = this.options.p04 === true ? /^fixlevelup_configuration_test_[a-f0-9]{24}$/ : /^fixlevelup_rbac_test_[a-f0-9]{24}$/;
    return pattern.test(this.database) ? this.database : undefined;
  }
  async close(): Promise<void> {
    if (this.closed) { return; }
    this.closed = true;
    // Capture the database to drop BEFORE any teardown, so the flag is consumed even
    // when a later teardown step fails (the drop then still runs in the finally).
    const ownedDatabase = this.takeCreatedDatabase();
    try {
      try { await this.app?.close(); } finally { try { await this.admission?.release(); } finally { try { await this.pool?.end(); } finally { this.logs.mockRestore(); } } }
    } finally {
      // Only a database created by THIS run is dropped, after every pool/client of this
      // run was ended. FORCE handles stragglers.
      if (ownedDatabase !== undefined && this.adminPassword !== undefined) {
        const admin = new Client({ ...connection, database: 'postgres', user: 'fixlevelup_dev', password: this.adminPassword });
        try {
          await admin.connect();
          await admin.query(`DROP DATABASE IF EXISTS "${ownedDatabase}" WITH (FORCE)`);
        } finally { await admin.end().catch(() => undefined); }
      }
    }
  }
  private safe(value: unknown): void {
    const json = JSON.stringify(value); expect(this.secrets.some((secret) => json.includes(secret))).toBe(false);
  }
  private async submit(test: request.Test, credentialReply = false): Promise<request.Response> {
    const r = await test;
    expect(r.headers['cache-control']).toBe('no-store');
    if (!credentialReply) { this.safe(r.body); }
    this.safe(this.logs.mock.calls);
    return r;
  }
  async login(id: string, login: string, password: string): Promise<Web> {
    this.secrets.push(login, password);
    const r = await this.submit(request(this.server).post('/api/v1/auth/login').set('Origin', origin).set('X-CSRF-Token', 'login').send({ login, password }), true);
    expect(r.status).toBe(200);
    const cookies: unknown = r.headers['set-cookie'];
    const token = Array.isArray(cookies) && cookies.length === 1 && typeof cookies[0] === 'string'
      ? /^__Host-fixlevelup_session=([A-Za-z0-9_-]{43}); Path=\/; HttpOnly; Secure; SameSite=Strict$/.exec(cookies[0])?.[1] : undefined;
    if (!token) { throw new Error('Invalid session cookie'); }
    const csrf = text(record(record(r.body)['data']), 'csrfToken');
    this.secrets.push(token); this.safe(r.body); this.secrets.push(csrf);
    return { id, login, password, token, csrf, cookie: `__Host-fixlevelup_session=${token}` };
  }
  async rejectedLogin(web: Web): Promise<number> {
    return (await this.submit(request(this.server).post('/api/v1/auth/login').set('Origin', origin).set('X-CSRF-Token', 'login').send({ login: web.login, password: web.password }))).status;
  }
  async credentials(id: string): Promise<{ login: string; password: string }> {
    const login = random(); const password = random(); const hash = await hashPassword(password);
    this.secrets.push(login, password, hash);
    await this.db.query('INSERT INTO foundation.staff_web_credentials (staff_id,login,password_hash) VALUES ($1,$2,$3)', [id, login, hash]);
    return { login, password };
  }
  async webStaff(): Promise<Web> {
    const id = await this.createStaff('MANAGER');
    const { login, password } = await this.credentials(id); return this.login(id, login, password);
  }
  async createStaff(role: 'MANAGER' | 'TECHNICIAN'): Promise<string> {
    return text(check(await this.call(this.admin, 'post', '/staff', { role }), 201).data, 'id');
  }
  async call(web: Web | { token: string }, method: Method, path: string, body?: object, etag?: string, readOrigin?: string): Promise<Result> {
    const req = request(this.server)[method](`/api/v1${path}`);
    if (readOrigin) { req.set('Origin', readOrigin); }
    if ('cookie' in web) { req.set('Cookie', web.cookie).set('Origin', origin); if (method !== 'get') { req.set('X-CSRF-Token', web.csrf); } }
    else { req.set('Authorization', `Bearer ${web.token}`); }
    if (etag !== undefined) { req.set('If-Match', etag); } if (body !== undefined) { req.send(body); }
    const r = await this.submit(req); const raw: unknown = r.body; const envelope = record(raw);
    return { status: r.status, data: r.status < 300 ? record(envelope['data']) : {}, body: raw, etag: r.headers['etag'] ?? '' };
  }
  async tg(id: string) {
    const user = String(BigInt(`0x${randomBytes(5).toString('hex')}`) + 1n);
    const link = randomUUID();
    await this.db.query('INSERT INTO foundation.staff_telegram_links (id,staff_id,telegram_user_id) VALUES ($1,$2,$3)', [link, id, user]);
    return { ...(await this.exchange(user)), link, user };
  }
  async exchange(user: string) {
    const fields = new URLSearchParams({ auth_date: String(Math.floor(Date.now() / 1000)), query_id: random(), user: JSON.stringify({ id: Number(user), first_name: 'Fixture' }) });
    fields.sort(); const payload = Array.from(fields, ([k, v]) => `${k}=${v}`).join('\n');
    fields.set('hash', createHmac('sha256', createHmac('sha256', 'WebAppData').update(this.botToken).digest()).update(payload).digest('hex'));
    const initData = fields.toString(); this.secrets.push(initData);
    const exchange = () => this.submit(request(this.server).post('/api/v1/auth/telegram-miniapp').send({ initData }), true);
    const r = await exchange(); expect(r.status).toBe(200); const token = text(record(record(r.body)['data']), 'sessionToken'); this.secrets.push(token);
    return { token, replay: async () => (await exchange()).status };
  }
  async systemRole(code: string): Promise<string> {
    const result = items(check(await this.call(this.admin, 'get', '/roles'), 200)).find((r) => r['code'] === code);
    if (!result) { throw new Error(`Missing system role ${code}`); } return text(result, 'id');
  }
  createRole() { return this.call(this.admin, 'post', '/roles', { name: `Role ${randomUUID()}`, description: 'Fixture' }); }
  async permset(id: string, codes: string[]) {
    const detail = check(await this.call(this.admin, 'get', `/roles/${id}`), 200);
    return this.call(this.admin, 'put', `/roles/${id}/permissions`, { permissions: codes.map(grant) }, detail.etag);
  }
  assign(target: string, roleId: string, etag = '"staff-v0"') { return this.call(this.admin, 'put', `/staff/${target}/role`, { roleId }, etag); }
  async count(sql: string, params: unknown[] = []): Promise<number> {
    const r = await this.db.query<{ n: number }>(sql, params); const n = r.rows[0]?.n;
    if (typeof n !== 'number') { throw new Error('Missing evidence count'); } return n;
  }
  async auditSafe() { this.safe((await this.db.query('SELECT details FROM foundation.audit_logs')).rows); }
  // Observe the *same* wait edge in two samples separated by wall-clock time. Any unrelated
  // runtime wait (including the audit insert in transaction A) cannot stand in for B waiting on A.
  private async waiter(blocker: number, exclude = 0): Promise<number> {
    const deadline = Date.now() + 3100; let firstSeen = 0; let previousPid = 0;
    do {
      const r = await this.db.query<{ pid: number }>(`SELECT pid FROM pg_stat_activity
        WHERE datname=current_database() AND usename='fixlevelup_runtime' AND pid<>$2 AND $1=ANY(pg_blocking_pids(pid)) ORDER BY pid LIMIT 1`, [blocker, exclude]);
      const pid = r.rows[0]?.pid;
      if (pid && previousPid === pid && Date.now() - firstSeen >= 40) { return pid; }
      if (previousPid !== pid) { previousPid = pid ?? 0; firstSeen = Date.now(); }
      await new Promise((done) => { setTimeout(done, 15); });
    } while (Date.now() < deadline);
    throw new Error('Did not observe two concurrent runtime transactions on the expected PG blocking edge');
  }
  async directSelfDeactivate(actor: Web, version: number): Promise<Result> {
    if (!this.app) { throw new Error('Missing app'); }
    try {
      const d = await this.app.get(StaffService).deactivate({ kind: 'staff-web', token: actor.token }, { kind: 'self', id: actor.id }, version);
      return { status: 200, data: { ...d }, body: null, etag: '' };
    } catch (e) {
      if (!(e instanceof HttpException)) { throw e; }
      return { status: e.getStatus(), data: {}, body: null, etag: '' };
    }
  }
  async race(first: () => Promise<Result>, second: () => Promise<Result>, mode: 'http' | 'both-denied' | 'writers' = 'http'): Promise<[Result, Result]> {
    const bothDenied = mode === 'both-denied';
    const locker: PoolClient = await this.db.connect(); const pending: Promise<Result>[] = [];
    const start = (fn: () => Promise<Result>) => { const p = fn(); void p.catch(() => undefined); pending.push(p); return p; };
    try {
      await locker.query('BEGIN'); const pid = (await locker.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
      if (!pid) { throw new Error('Missing fixture backend PID'); }
      await locker.query(bothDenied ? "SELECT pg_advisory_xact_lock(hashtextextended('fixlevelup:admin-invariant',0))" : 'LOCK TABLE foundation.audit_logs IN EXCLUSIVE MODE');
      const a = start(first); const aPid = await this.waiter(pid);
      const b = start(second); const bPid = await this.waiter(bothDenied ? pid : aPid, aPid);
      expect(aPid).not.toBe(bPid);
      if (mode === 'writers') {
        const locks = await this.count(`WITH key AS (SELECT hashtextextended('fixlevelup:admin-invariant',0) AS k)
          SELECT count(*)::int AS n FROM pg_locks a JOIN pg_locks b USING(database,classid,objid,objsubid)
          CROSS JOIN key WHERE a.pid=$1 AND b.pid=$2 AND a.locktype='advisory' AND b.locktype='advisory'
            AND a.mode='ExclusiveLock' AND b.mode='ExclusiveLock' AND a.granted AND NOT b.granted AND a.objsubid=1
            AND a.classid::bigint=((k>>32)&4294967295) AND a.objid::bigint=(k&4294967295)
            AND a.pid=ANY(pg_blocking_pids(b.pid))`, [aPid,bPid]);
        expect(locks).toBe(1);
      }
      await locker.query('ROLLBACK'); return await Promise.all([a, b]);
    } finally { try { await locker.query('ROLLBACK'); } finally { locker.release(); await Promise.allSettled(pending); } }
  }
}
export function fixturePerTest(): () => RbacFixture {
  let value: RbacFixture;
  beforeEach(async () => { value = new RbacFixture(); await value.start(); }, 30000);
  afterEach(async () => { try { if (value.ready) { await value.auditSafe(); } } finally { await value.close(); } });
  return () => value;
}
