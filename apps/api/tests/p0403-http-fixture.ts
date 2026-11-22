import { ConsoleLogger } from '@nestjs/common';
import { P04_PREFIX, P04_ROUTES } from '@fixlevelup/p03-contracts/p04';
import type { P04Operation } from '@fixlevelup/p03-contracts/p04';
import { Client } from 'pg';
import { afterEach, beforeEach, expect, vi } from 'vitest';
import { check, num, records, text } from './geography-fixture.js';
import { RbacFixture, record } from './rbac-fixture.js';
import { ManagementFixture, fixtureCode } from './settings-management-fixture.js';
import type { HttpResult } from './settings-management-fixture.js';

export const PRIVATE_P04 = 'private-p04-synthetic-не-выводить';
export const p04Tag = (version: number) => `"p04-v${String(version)}"`;
export const id = (r: HttpResult) => text(r.data, 'id');
export const revision = (r: HttpResult) => text(r.data, 'revisionId');
export const page = (r: HttpResult) => records(r.data['items']);

export function p04Path(op: P04Operation, params: Readonly<Record<string, string>> = {}): string {
  return P04_ROUTES[op].path.slice(P04_PREFIX.length).replace(/\{([a-zA-Z]+)\}/gu, (_, key: string) => {
    const value = params[key]; if (!value) { throw new Error(`Missing fixture parameter: ${key}`); }
    return value;
  });
}

export function receipt(result: HttpResult, status: number, withRevision = false): HttpResult {
  check(result, status);
  expect(Object.keys(result.data).sort()).toEqual(withRevision ? ['id', 'revisionId', 'revisionVersion', 'version'] : ['id', 'version']);
  expect(id(result)).toMatch(/^[a-f0-9-]{36}$/u);
  expect(num(result.data, 'version')).toBeGreaterThan(0);
  expect(result.etag).toBe(p04Tag(num(result.data, 'version')));
  if (withRevision) {
    expect(revision(result)).toMatch(/^[a-f0-9-]{36}$/u);
    expect(num(result.data, 'revisionVersion')).toBeGreaterThan(0);
  }
  const envelope = record(result.body);
  expect(Object.keys(envelope).sort()).toEqual(['data', 'meta']);
  expect(text(record(envelope['meta']), 'requestId')).toMatch(/^[a-f0-9-]{36}$/u);
  return result;
}

export class P04HttpFixture extends ManagementFixture {
  async asCatalog() { await this.base.issueP04Synthetic(); }

  async category() {
    const draft = receipt(await this.post('/catalog/categories', { code: fixtureCode('cat') }), 201);
    const published = receipt(await this.post(`/catalog/categories/${id(draft)}/versions`, { title: 'Reviewed category' }, { etag: draft.etag }), 201, true);
    return { id: id(draft), draft, published };
  }

  async part(categoryId?: string) {
    const draft = receipt(await this.post('/catalog/items', { kind: 'PART', code: fixtureCode('part'), unit: 'piece', ...(categoryId ? { categoryId } : {}) }), 201);
    const published = receipt(await this.post(`/catalog/items/${id(draft)}/versions`, {
      kind: 'PART', title: 'Reviewed part', technicianVisible: true, publicVisible: false,
    }, { etag: draft.etag }), 201, true);
    return { id: id(draft), draft, published };
  }

  async cities() {
    const primary = await this.geo.publishedDraftCity(this.admin, fixtureCode('active'));
    check(await this.geo.activateCity(this.admin, primary.id, primary.version), 200);
    const other = await this.geo.publishedDraftCity(this.admin, fixtureCode('draft'));
    return { primary, other };
  }

  async dbInstant(milliseconds = 3_600_000): Promise<string> {
    const row = (await this.base.db.query<{ time: Date }>(`SELECT date_trunc('milliseconds',clock_timestamp())
      + $1::integer * interval '1 millisecond' AS time`, [milliseconds])).rows[0];
    if (!row) { throw new Error('Missing DB time'); }
    return row.time.toISOString();
  }

  async evidence() {
    const { rows } = await this.base.db.query<{ counts: unknown }>(`SELECT jsonb_build_object(
      'entries',(SELECT count(*) FROM foundation.catalog_directory_entries),
      'revisions',(SELECT count(*) FROM foundation.catalog_directory_versions),
      'receipts',(SELECT count(*) FROM foundation.p04_command_receipts),
      'audits',(SELECT count(*) FROM foundation.audit_logs WHERE operation LIKE 'catalog.%'),
      'outbox',(SELECT count(*) FROM foundation.outbox_events WHERE event_type LIKE 'catalog.%')) AS counts`);
    if (!rows[0]) { throw new Error('Missing catalog evidence'); }
    return record(rows[0].counts);
  }

  async readReceipt(key: string) {
    return (await this.base.db.query<{ actor_id: string; operation: string; city_id: string | null; subject_id: string;
      entity_id: string; entity_version: number; revision_id: string | null; revision_version: number | null;
      target_version_id: string | null; request_sha256: string }>(`SELECT actor_id,operation,city_id,subject_id,entity_id,entity_version,
        revision_id,revision_version,target_version_id,request_sha256 FROM foundation.p04_command_receipts WHERE key=$1`, [key])).rows;
  }

  async safeP04Evidence() {
    this.assertClean((await this.base.db.query(`SELECT to_jsonb(p) AS v FROM foundation.p04_command_receipts p
      UNION ALL SELECT details FROM foundation.audit_logs UNION ALL SELECT payload FROM foundation.outbox_events`)).rows);
  }

  /** Install a fault only on this runtime connection at a real receipt statement. */
  observeP04Receipt(mode: { beforeSelect: () => Promise<void> } | { loseCommitAck: true }) {
    const descriptor = Object.getOwnPropertyDescriptor(Client.prototype, 'query');
    const original: unknown = descriptor?.value;
    if (!descriptor || typeof original !== 'function') { throw new Error('Missing PG driver query boundary'); }
    const invoke = original;
    const database = this.base.database;
    let count = 0;
    const seen = new WeakSet<Client>();
    function query(this: Client, ...args: unknown[]): unknown {
      const sql = args[0];
      const run = (): unknown => Reflect.apply(invoke, this, args);
      const actual = this as Client & { database: string; user: string };
      if (actual.database !== database || actual.user !== 'fixlevelup_runtime' || typeof sql !== 'string') { return run(); }
      if ('beforeSelect' in mode && count === 0 && /SELECT\s+request_sha256\b[\s\S]+?FROM\s+foundation\.p04_command_receipts\b/iu.test(sql)) {
        count++;
        return mode.beforeSelect().then(run);
      }
      if ('loseCommitAck' in mode && /INSERT\s+INTO\s+foundation\.p04_command_receipts\b/iu.test(sql)) {
        return Promise.resolve(run()).then(value => { seen.add(this); return value; });
      }
      if ('loseCommitAck' in mode && /^\s*COMMIT\s*;?\s*$/iu.test(sql) && seen.delete(this) && count === 0) {
        return Promise.resolve(run()).then(() => { count++; throw Object.assign(new Error(PRIVATE_P04), { code: 'ECONNRESET' }); });
      }
      return run();
    }
    Object.defineProperty(Client.prototype, 'query', { ...descriptor, value: query });
    return { fired: () => count, restore: () => { Object.defineProperty(Client.prototype, 'query', descriptor); } };
  }
}

export function p04PerTest(): () => P04HttpFixture {
  let base: RbacFixture | undefined;
  let current: P04HttpFixture | undefined;
  beforeEach(async () => {
    base = new RbacFixture({ p04: true });
    await base.start();
    const logs: unknown[] = [];
    const sink: unknown = Object.getOwnPropertyDescriptor(ConsoleLogger.prototype, 'log')?.value;
    if (!vi.isMockFunction(sink)) { throw new Error('Missing fixture log sink'); }
    sink.mockImplementation((...args: unknown[]) => { logs.push(args); });
    current = new P04HttpFixture(base, logs);
    current.remember(PRIVATE_P04, base.admin.token, base.admin.csrf, base.admin.password);
  }, 40_000);
  afterEach(async () => {
    try { if (base?.ready) { await base.auditSafe(); await current?.safeP04Evidence(); } }
    finally { await base?.close(); base = undefined; current = undefined; }
  }, 20_000);
  return () => {
    if (!current) { throw new Error('Missing test-local P04 fixture'); }
    return current;
  };
}
