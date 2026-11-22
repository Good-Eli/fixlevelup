import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { archiveAvito, createAvito, normalizeAvitoPublish, publishAvito } from '../src/catalog-management/avito.js';
import type { CatalogClient, CatalogReceipt } from '../src/catalog/contracts.js';
import { CatalogError, CatalogInternalError } from '../src/catalog/validation.js';
import { configurationIntegration, createConfigurationFixture } from './configuration-fixture.js';
import type { ConfigurationFixture } from './configuration-fixture.js';

const profileBody = { title: 'Synthetic profile', sourceUrl: 'https://www.avito.ru/synthetic/Profile_One', permissionRef: 'fixture:profile' };
const reviewBody = { title: 'Synthetic review', sourceUrl: 'https://avito.ru/synthetic/Review-1', permissionRef: 'fixture:review',
  sourceDate: '2024-02-29', excerpt: 'Самостоятельный синтетический отзыв.', rating: 4 };
const cas = ({ id, version }: CatalogReceipt) => ({ id, expectedVersion: version });
const code = (prefix: string) => `${prefix}-${randomUUID()}`;

function invalid(run: () => unknown, field: string): void {
  expect(run).toThrow(expect.objectContaining({ name: 'CatalogError', code: 'INVALID_INPUT', field }));
}

describe('P04-03 Avito canonical input (no database or network)', () => {
  it('preserves exact safe ASCII URLs and canonicalizes only plain text and optional values', () => {
    const prefix = 'https://avito.ru/';
    const longest = prefix + 'a'.repeat(2048 - prefix.length);
    expect(normalizeAvitoPublish({ ...profileBody, title: '  Пример  ', sourceUrl: longest, permissionRef: '\u00a0 fixture:allowed ' }))
      .toEqual({ title: 'Пример', sourceUrl: longest, permissionRef: 'fixture:allowed', sourceDate: null, excerpt: null, rating: null });
    expect(normalizeAvitoPublish({ ...reviewBody, sourceDate: '0001-01-01', rating: null }))
      .toEqual({ ...reviewBody, sourceDate: '0001-01-01', rating: null });
    const astral = '😀';
    expect(normalizeAvitoPublish({ ...reviewBody, title: astral.repeat(160), excerpt: astral.repeat(1500), permissionRef: astral.repeat(200) }).excerpt)
      .toHaveLength(3000);
    invalid(() => normalizeAvitoPublish({ ...profileBody, sourceUrl: `${longest}a` }), 'sourceUrl');
  });

  it.each([
    'http://avito.ru/a', 'https://Avito.ru/a', 'HTTPS://avito.ru/a', '//avito.ru/a', 'https://avito.ru.evil/a',
    'https://avito.ru:443/a', 'https://name@avito.ru/a', 'https://avito.ru@other.example/a', 'https://avito.ru/a?',
    'https://avito.ru/a#x', 'https://avito.ru/a%2fb', 'https://avito.ru/a%252fb', 'https://avito.ru/a\\b',
    'https://avito.ru/a//b', 'https://avito.ru/a/./b', 'https://avito.ru/a/../b', 'https://avito.ru/a/',
    'https://avito.ru/', 'https://avito.ru/a\n', 'https://avito.ru/a\u2028', ' https://avito.ru/a',
    'https://avito.ru/a ', 'https://avito.ru/я', 'https://avito.ru/a.b',
  ])('rejects non-canonical source URL %j', (sourceUrl) => {
    invalid(() => normalizeAvitoPublish({ ...profileBody, sourceUrl }), 'sourceUrl');
  });

  it('rejects wrong types, markup, invisible controls and unbounded Unicode text', () => {
    for (const [field, max] of [['title', 160], ['permissionRef', 200], ['excerpt', 1500]] as const) {
      for (const value of [' ', '<img>', 'a>b', '\u0000a', 'a\u202e', 'a\ud800', ' a\n', '😀'.repeat(max + 1), true]) {
        invalid(() => normalizeAvitoPublish({ ...reviewBody, [field]: value }), field);
      }
    }
    for (const sourceDate of ['2023-02-29', '1900-02-29', '2000-02-30', '2024-04-31', '0000-01-01', '10000-01-01',
      '2024-2-09', '2024-02-09Z', ' 2024-02-29', '2024-02-29\n', '2024-00-01', '2024-01-00', true]) {
      invalid(() => normalizeAvitoPublish({ ...reviewBody, sourceDate }), 'sourceDate');
    }
    for (const rating of [0, 6, 1.5, '4', false, NaN, Infinity]) {
      invalid(() => normalizeAvitoPublish({ ...reviewBody, rating }), 'rating');
    }
    expect(normalizeAvitoPublish({ ...reviewBody, sourceDate: '2000-02-29', rating: 1 }).rating).toBe(1);
    expect(normalizeAvitoPublish({ ...reviewBody, rating: 5 }).rating).toBe(5);
    invalid(() => normalizeAvitoPublish({ ...reviewBody, kind: 'REVIEW' }), 'input');
    const getter = vi.fn(() => 'fixture:not-invoked');
    invalid(() => normalizeAvitoPublish(Object.defineProperty({ ...reviewBody }, 'permissionRef', { get: getter })), 'input');
    expect(getter).not.toHaveBeenCalled();
  });

  it('validates strict identity, actor and CAS before contacting the client', async () => {
    const query = vi.fn((): never => { throw new Error('Invalid data must not reach PostgreSQL'); });
    const c: CatalogClient = { query };
    const actor = randomUUID();
    const id = randomUUID();
    await expect(createAvito(c, actor, { kind: 'REVIEW', code: 'review', profileId: 'bad' }))
      .rejects.toMatchObject({ code: 'INVALID_INPUT', field: 'profileId' });
    const profileWithParent = { kind: 'PROFILE' as const, code: 'profile', profileId: null };
    await expect(createAvito(c, actor, profileWithParent as unknown as Parameters<typeof createAvito>[2]))
      .rejects.toMatchObject({ code: 'INVALID_INPUT', field: 'profileId' });
    await expect(createAvito(c, 'bad', { kind: 'PROFILE', code: 'profile' }))
      .rejects.toBeInstanceOf(CatalogError);
    await expect(publishAvito(c, actor, { ...profileBody, id, expectedVersion: 0 }))
      .rejects.toMatchObject({ code: 'INVALID_INPUT', field: 'expectedVersion' });
    await expect(archiveAvito(c, actor, { id, expectedVersion: 2_147_483_648 }))
      .rejects.toMatchObject({ code: 'INVALID_INPUT', field: 'expectedVersion' });
    expect(query).not.toHaveBeenCalled();
  });
});

configurationIntegration('P04-03 Avito ports on isolated PostgreSQL', () => {
  let f: ConfigurationFixture | undefined;
  function fixture(): ConfigurationFixture {
    if (!f) { throw new Error('Avito fixture was not initialized'); }
    return f;
  }
  beforeAll(async () => { f = await createConfigurationFixture(); }, 60_000);
  afterAll(async () => { await f?.close(); }, 30_000);

  const run = <T>(operation: (client: CatalogClient, actor: string) => Promise<T>) =>
    fixture().inTransaction(client => operation(client, fixture().reviewer));
  const profile = () => run((c, a) => createAvito(c, a, { kind: 'PROFILE', code: code('profile') }));
  const review = (profileId: string) => run((c, a) => createAvito(c, a, { kind: 'REVIEW', code: code('review'), profileId }));

  async function persisted(id: string) {
    return (await fixture().runtime.query<{ row_version: number; current_version_id: string | null;
      revisions: number; audits: number; events: number }>(`SELECT e.row_version, e.current_version_id,
        (SELECT count(*)::integer FROM foundation.external_review_revisions WHERE entry_id=e.id) AS revisions,
        (SELECT count(*)::integer FROM foundation.audit_logs WHERE details->>'id'=e.id::text) AS audits,
        (SELECT count(*)::integer FROM foundation.outbox_events WHERE payload->>'id'=e.id::text) AS events
      FROM foundation.external_reviews e WHERE e.id=$1`, [id])).rows[0];
  }

  it('pins each immutable review to the original version of its live profile and emits closed evidence', async () => {
    const p = await profile();
    const r = await review(p.id);
    expect(p.version).toBe(1);
    expect(r.version).toBe(1);
    const duplicateCode = code('duplicate');
    await run((c, a) => createAvito(c, a, { kind: 'PROFILE', code: duplicateCode }));
    await expect(run((c, a) => createAvito(c, a, { kind: 'PROFILE', code: duplicateCode })))
      .rejects.toMatchObject({ code: 'CONFLICT', field: 'code' });
    await expect(review(r.id)).rejects.toMatchObject({ code: 'CONFLICT', field: 'profileId' });
    await expect(review(randomUUID())).rejects.toMatchObject({ code: 'NOT_FOUND', field: 'profileId' });
    await expect(run((c, a) => publishAvito(c, a, { ...reviewBody, ...cas(r) })))
      .rejects.toMatchObject({ code: 'CONFLICT', field: 'profileId' });
    await expect(run((c, a) => publishAvito(c, a, { ...reviewBody, ...cas(p) })))
      .rejects.toMatchObject({ code: 'INVALID_INPUT', field: 'sourceDate' });
    const p1 = await run((c, a) => publishAvito(c, a, { ...profileBody, ...cas(p) }));
    await expect(run((c, a) => publishAvito(c, a, { ...profileBody, ...cas(r), sourceDate: reviewBody.sourceDate })))
      .rejects.toMatchObject({ code: 'INVALID_INPUT', field: 'excerpt' });
    const r1 = await run(c => publishAvito(c, fixture().secondReviewer, { ...reviewBody, ...cas(r) }));
    const p2 = await run((c, a) => publishAvito(c, a, { ...profileBody, ...cas(p1), title: 'Reviewed replacement' }));
    const r2 = await run((c, a) => publishAvito(c, a, { ...reviewBody, ...cas(r1), rating: null }));
    expect(r1).toMatchObject({ id: r.id, revisionVersion: 1, version: 2 });
    expect(r2).toMatchObject({ id: r.id, revisionVersion: 2, version: 3 });
    await expect(run((c, a) => publishAvito(c, a, { ...reviewBody, ...cas(r1) })))
      .rejects.toMatchObject({ code: 'STALE_VERSION' });
    expect(await run((c, a) => archiveAvito(c, a, cas(p2)))).toEqual({ id: p.id, version: 4 });
    await expect(run((c, a) => publishAvito(c, a, { ...reviewBody, ...cas(r2) })))
      .rejects.toMatchObject({ code: 'ARCHIVED', field: 'profileId' });
    const { rows: versions } = await fixture().runtime.query(`SELECT id, version, source_date::text AS source_date,
        profile_id, profile_revision_id, rating, excerpt, permission_ref, reviewed_by, published_at IS NOT NULL AS published
      FROM foundation.external_review_revisions WHERE entry_id=$1 ORDER BY version`, [r.id]);
    const common = { source_date: reviewBody.sourceDate, profile_id: p.id, excerpt: reviewBody.excerpt,
      permission_ref: reviewBody.permissionRef, published: true };
    expect(versions).toEqual([
      { ...common, id: r1.revisionId, version: 1, profile_revision_id: p1.revisionId, rating: 4, reviewed_by: fixture().secondReviewer },
      { ...common, id: r2.revisionId, version: 2, profile_revision_id: p2.revisionId, rating: null, reviewed_by: fixture().reviewer },
    ]);
    expect(await run((c, a) => archiveAvito(c, a, cas(r2)))).toEqual({ id: r.id, version: 4 });
    expect(await persisted(r.id)).toEqual({ row_version: 4, current_version_id: r2.revisionId, revisions: 2, audits: 4, events: 4 });
    const { rows: evidence } = await fixture().runtime.query(`SELECT a.operation, a.details, o.payload
      FROM foundation.audit_logs a JOIN foundation.outbox_events o ON (o.event_id, o.event_type)=(a.correlation_id, a.operation)
      WHERE a.details->>'id'=$1 ORDER BY (a.details->>'version')::int`, [r.id]);
    expect(evidence).toEqual(([
      ['create', r, fixture().reviewer], ['publish', r1, fixture().secondReviewer],
      ['publish', r2, fixture().reviewer], ['archive', { id: r.id, version: 4 }, fixture().reviewer],
    ] as const).map(([action, receipt, actorStaffId]) => {
      const payload = { actorStaffId, kind: 'REVIEW', ...receipt };
      return { operation: `content.externalreviews.${action}`, details: payload, payload };
    }));
  }, 20_000);

  it('rolls back pointer, revision and completed audit after outbox failure even if caller commits', async () => {
    const p = await profile();
    const before = await persisted(p.id);
    await fixture().inTransaction(async (c) => {
      const query = ((sql: string, params?: unknown[]) => sql.includes('INSERT INTO foundation.outbox_events')
        ? c.query('SELECT 1/0') // A real SQL failure leaves PostgreSQL needing ROLLBACK TO SAVEPOINT.
        : c.query(sql, params)) as CatalogClient['query'];
      await expect(publishAvito({ query }, fixture().reviewer, { ...profileBody, ...cas(p) }))
        .rejects.toBeInstanceOf(CatalogInternalError);
      expect((await c.query('SELECT 1 AS recovered')).rows).toEqual([{ recovered: 1 }]);
    });
    expect(await persisted(p.id)).toEqual(before);
    expect(await run((c, a) => publishAvito(c, a, { ...profileBody, ...cas(p) })))
      .toMatchObject({ revisionVersion: 1, version: 2 });
  }, 20_000);

  it('waits on the shared catalog fence key and checks profile archive after the wait', async () => {
    const p = await profile();
    const p1 = await run((c, a) => publishAvito(c, a, { ...profileBody, ...cas(p) }));
    const r = await review(p.id);
    const holder = await fixture().runtime.connect();
    try {
      await holder.query('BEGIN');
      await archiveAvito(holder, fixture().reviewer, cas(p1));
      const waiter = await fixture().runtime.connect();
      try {
        await waiter.query('BEGIN');
        await waiter.query("SET LOCAL statement_timeout='8s'");
        const [holderBackend, waiterBackend] = await Promise.all([holder, waiter].map(async c =>
          (await c.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid));
        expect(holderBackend).toBeTypeOf('number');
        expect(waiterBackend).toBeTypeOf('number');
        expect(holderBackend).not.toBe(waiterBackend);
        const pending = publishAvito(waiter, fixture().reviewer, { ...reviewBody, ...cas(r) })
          .then(value => ({ value }), (error: unknown) => ({ error }));
        try {
          let waiting = false;
          const deadline = performance.now() + 4_000;
          while (!waiting && performance.now() < deadline) {
            const { rows } = await fixture().runtime.query<{ waiting: boolean }>(`SELECT EXISTS (
              SELECT 1 FROM pg_locks WHERE pid=$2 AND NOT granted AND locktype='advisory' AND mode='ExclusiveLock'
              AND classid=77304 AND objid=1 AND objsubid=2 AND $1=ANY(pg_blocking_pids($2))) AS waiting`,
            [holderBackend, waiterBackend]);
            waiting = rows[0]?.waiting === true;
            if (!waiting) { await delay(15); }
          }
          expect(waiting).toBe(true);
        } finally {
          await holder.query('COMMIT');
        }
        expect(await pending).toMatchObject({ error: { code: 'ARCHIVED', field: 'profileId' } });
      } finally {
        try { await waiter.query('ROLLBACK'); } finally { waiter.release(); }
      }
    } finally {
      try { await holder.query('ROLLBACK'); } finally { holder.release(); }
    }
    expect(await persisted(r.id)).toEqual({ row_version: 1, current_version_id: null, revisions: 0, audits: 1, events: 1 });
  }, 20_000);
});
