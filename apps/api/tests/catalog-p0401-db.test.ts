import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import type { PoolClient } from 'pg';
import { afterAll, beforeAll, expect, it } from 'vitest';
import {
  archiveDirectory, archiveItem, archiveMapping, CatalogInternalError, closeFixedPrice, createDirectory, createItem,
  createMapping, publishDirectory, publishFixedPrice, publishItem, publishMapping, readCatalogRevision, readFixedPrice,
  readFixedPriceRevision, replaceFixedPrice,
} from '../src/catalog/index.js';
import type {
  CatalogClient, CatalogReceipt, CreateDirectoryInput, ItemKind, PublishFixedPriceInput, PublishItemInput, ReplaceFixedPriceInput,
} from '../src/catalog/index.js';
import { configurationIntegration, createConfigurationFixture, createSyntheticCity } from './configuration-fixture.js';
import type { ConfigurationFixture, SyntheticCity } from './configuration-fixture.js';

const TIMEOUT = 20_000;
const code = (prefix: string) => `${prefix}-${randomUUID()}`;
const cas = ({ id, version }: CatalogReceipt) => ({ id, expectedVersion: version });
const atOffset = (at: string, offset: number) => new Date(Date.parse(at) + offset).toISOString();
const first = <T>(rows: readonly T[]): T => {
  if (rows[0] === undefined) {throw new Error('Expected one fixture row');}
  return rows[0];
};

configurationIntegration('P04-01 catalog ports and price fencing on isolated PostgreSQL', () => {
  let f: ConfigurationFixture | undefined;
  let city: SyntheticCity;
  let otherCity: SyntheticCity;

  function fixture(): ConfigurationFixture {
    if (!f) {throw new Error('Catalog fixture was not initialized');}
    return f;
  }

  beforeAll(async () => {
    f = await createConfigurationFixture();
    city = await createSyntheticCity(f);
    otherCity = await createSyntheticCity(f, { timezone: 'Asia/Yekaterinburg' });
  }, 60_000);
  afterAll(async () => { await f?.close(); }, 30_000);

  const run = <T>(operation: (client: CatalogClient, reviewer: string) => Promise<T>) =>
    fixture().inTransaction(client => operation(client, fixture().reviewer));

  async function dbAt(offsetMs = 0): Promise<string> {
    const { rows } = await fixture().runtime.query<{ at: Date }>(`SELECT
      date_trunc('milliseconds', clock_timestamp()) + $1::integer * interval '1 millisecond' AS at`, [offsetMs]);
    return first(rows).at.toISOString();
  }

  async function until(probe: () => Promise<boolean>, message: string, limit = 6500): Promise<void> {
    const deadline = performance.now() + limit;
    do {
      if (await probe()) {return;}
      await delay(12);
    } while (performance.now() < deadline);
    throw new Error(message);
  }

  async function waitAt(at: string): Promise<void> {
    await until(async () => (await dbAt()) >= at, 'PostgreSQL clock did not reach the price boundary');
  }

  async function directory(input: CreateDirectoryInput) {
    const draft = await run((c, a) => createDirectory(c, a, input));
    expect(draft.version).toBe(1);
    return run((c, a) => publishDirectory(c, a, { ...cas(draft), title: `Reviewed ${input.kind}` }));
  }

  async function sku(kind: ItemKind = 'WORK', categoryId?: string) {
    const assigned = kind === 'WORK' && !categoryId
      ? (await directory({ kind: 'CATEGORY', code: code('cat') })).id : categoryId;
    const unit = kind === 'WORK' ? 'visit' : 'piece';
    const draft = await run((c, a) => kind === 'WORK'
      ? createItem(c, a, { kind, code: code('sku'), unit, categoryId: assigned ?? '' })
      : createItem(c, a, { kind, code: code('sku'), unit, ...(assigned ? { categoryId: assigned } : {}) }));
    const labels = { ...cas(draft), title: `Reviewed ${kind}`, technicianVisible: true, publicVisible: kind !== 'WORK' };
    const input: PublishItemInput = kind === 'WORK' || kind === 'DIAGNOSTICS'
      ? { ...labels, kind, durationMinutes: 25 } : { ...labels, kind };
    const reviewed = await run((c, a) => publishItem(c, a, input));
    expect(draft.version).toBe(1);
    return { draft, reviewed, unit, categoryId: assigned ?? null, input };
  }

  function priceInput(itemId: string, validFrom: string, forCity = city): PublishFixedPriceInput {
    return { cityId: forCity.id, itemId, expectedVersion: 0, validFrom, amountMinor: '3100', currency: 'RUB', sourceRef: 'review://synthetic/price' };
  }

  const target = (itemId: string, forCity = city) => ({ cityId: forCity.id, cityVersionId: forCity.versionId, itemId });
  const fresh = (itemId: string) => run(c => readFixedPrice(c, target(itemId)));

  async function openPrice() {
    const item = await sku();
    const start = await dbAt(900);
    const body = priceInput(item.reviewed.id, start);
    const receipt = await run((c, a) => publishFixedPrice(c, a, body));
    expect(receipt).toMatchObject({ version: 1, revisionVersion: 1 });
    await waitAt(start);
    return { item, receipt, body };
  }

  type OpenPrice = Awaited<ReturnType<typeof openPrice>>;
  function replacement(old: OpenPrice, at: string): ReplaceFixedPriceInput {
    return { cityId: city.id, itemId: old.item.reviewed.id, priceVersionId: old.receipt.revisionId,
      expectedVersion: old.receipt.version, at, amountMinor: '5400', currency: 'RUB', sourceRef: 'review://synthetic/replacement' };
  }

  async function persisted(seriesId: string) {
    const { rows } = await fixture().runtime.query<{
      version: number; revision_ids: string[]; closes: (string | null)[]; amount_minors: string[]; audits: number; events: number;
    }>(`SELECT s.row_version AS version,
        array_agg(v.id ORDER BY v.version) AS revision_ids,
        array_agg(to_char(p.closed_effective_until AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') ORDER BY v.version) AS closes,
        array_agg(v.amount_minor::text ORDER BY v.version) AS amount_minors,
        (SELECT count(*)::integer FROM foundation.audit_logs WHERE details->>'id' = s.id::text) AS audits,
        (SELECT count(*)::integer FROM foundation.outbox_events WHERE payload->>'id' = s.id::text) AS events
      FROM foundation.catalog_price_series s JOIN foundation.catalog_price_versions v ON v.series_id = s.id
      JOIN foundation.catalog_price_periods p ON p.price_version_id = v.id
      WHERE s.id = $1 GROUP BY s.id`, [seriesId]);
    return first(rows);
  }

  async function projectedAt(seriesId: string, at: string): Promise<string[][]> {
    const { rows } = await fixture().runtime.query<{ ids: string[] }>(`SELECT ARRAY(
      SELECT p.price_version_id FROM foundation.catalog_price_periods p WHERE p.series_id = $1
        AND tstzrange(p.valid_from, coalesce(p.closed_effective_until,p.scheduled_until), '[)') @> probe.at
      ORDER BY p.price_version_id) AS ids
      FROM unnest($2::timestamptz[]) WITH ORDINALITY AS probe(at, n) ORDER BY probe.n`,
    [seriesId, [-1, 0, 1].map(delta => atOffset(at, delta))]);
    return rows.map(row => row.ids);
  }

  async function backend(client: PoolClient): Promise<number> {
    return first((await client.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows).pid;
  }

  async function waitForFence(holder: number, waiter: number, waiterMode: 'ShareLock' | 'ExclusiveLock') {
    expect(waiter).not.toBe(holder);
    await until(async () => first((await fixture().runtime.query<{ waiting: boolean }>(`SELECT EXISTS (
      SELECT 1 FROM pg_locks WHERE pid=$2 AND NOT granted AND locktype='advisory'
        AND classid=77304 AND objid=1 AND objsubid=2 AND mode=$3
        AND $1=ANY(pg_blocking_pids($2))) AS waiting`, [holder, waiter, waiterMode])).rows).waiting,
    `Expected distinct PostgreSQL backends to contend on the catalog ${waiterMode}`, 3500);
  }

  async function withConnections<T>(operation: (holder: PoolClient, waiter: PoolClient) => Promise<T>): Promise<T> {
    const h = await fixture().runtime.connect();
    try {
      const w = await fixture().runtime.connect();
      try {
        await h.query('BEGIN ISOLATION LEVEL READ COMMITTED');
        await w.query('BEGIN ISOLATION LEVEL READ COMMITTED');
        await h.query("SET LOCAL statement_timeout = '9s'");
        await w.query("SET LOCAL statement_timeout = '9s'");
        return await operation(h, w);
      } finally {
        // Unblock the second connection first, also on a failed assertion.
        try { await h.query('ROLLBACK'); }
        finally { try { await w.query('ROLLBACK'); } finally { w.release(); } }
      }
    } finally { h.release(); }
  }

  it('publishes every directory/item kind and one same-category fault mapping, then archives terminally', async () => {
    const category = await directory({ kind: 'CATEGORY', code: code('cat') });
    const brand = await directory({ kind: 'BRAND', code: code('brand') });
    const model = await directory({ kind: 'MODEL', code: code('model'), categoryId: category.id, brandId: brand.id });
    const fault = await directory({ kind: 'FAULT', code: code('fault'), categoryId: category.id });
    for (const [kind, revision, categoryId, brandId] of [
      ['CATEGORY', category, null, null], ['BRAND', brand, null, null],
      ['MODEL', model, category.id, brand.id], ['FAULT', fault, category.id, null],
    ] as const) {
      expect(revision).toMatchObject({ version: 2, revisionVersion: 1 });
      expect(await run(c => readCatalogRevision(c, { type: 'directory', id: revision.id, revisionId: revision.revisionId })))
        .toMatchObject({ kind, categoryId, brandId, title: `Reviewed ${kind}`, reviewedBy: fixture().reviewer });
    }
    const work = await sku('WORK', category.id);
    for (const item of [work, await sku('PART'), await sku('MATERIAL'), await sku('TRAVEL'), await sku('DIAGNOSTICS')]) {
      const { id, revisionId } = item.reviewed;
      expect(item.reviewed).toMatchObject({ version: 2, revisionVersion: 1 });
      expect(await run(c => readCatalogRevision(c, { type: 'item', id, revisionId }))).toMatchObject({
        kind: item.input.kind, categoryId: item.categoryId, unit: item.unit, title: item.input.title,
        technicianVisible: true, publicVisible: item.input.publicVisible, durationMinutes: item.input.durationMinutes ?? null,
      });
    }
    const pair = { categoryId: category.id, faultId: fault.id, itemId: work.reviewed.id };
    const mapping = await run((c, a) => createMapping(c, a, pair));
    expect(mapping.version).toBe(1);
    await expect(run((c, a) => createMapping(c, a, pair))).rejects.toMatchObject({ code: 'CONFLICT' });
    const published = await run((c, a) => publishMapping(c, a, cas(mapping)));
    expect(published).toEqual({ id: mapping.id, version: 2 });
    const archived = await run((c, a) => archiveMapping(c, a, cas(published)));
    await expect(run((c, a) => publishMapping(c, a, cas(archived)))).rejects.toMatchObject({ code: 'ARCHIVED' });
    const { rows } = await fixture().runtime.query<{ published_by: string; archived: boolean; row_version: number }>(`SELECT
      published_by, published_at IS NOT NULL AND archived_at IS NOT NULL AS archived, row_version
      FROM foundation.catalog_fault_service_mappings WHERE id=$1`, [mapping.id]);
    expect(rows).toEqual([{ published_by: fixture().reviewer, archived: true, row_version: 3 }]);
    const archivedModel = await run((c, a) => archiveDirectory(c, a, cas(model)));
    await expect(run((c, a) => publishDirectory(c, a, { ...cas(archivedModel), title: 'Forbidden' })))
      .rejects.toMatchObject({ code: 'ARCHIVED' });
    expect(await run(c => readCatalogRevision(c, { type: 'directory', id: model.id, revisionId: model.revisionId })))
      .toMatchObject({ revisionId: model.revisionId, title: 'Reviewed MODEL' });
  }, TIMEOUT);

  it('rejects wrongly typed parents and mappings, and cannot change units of an existing SKU', async () => {
    const category = await directory({ kind: 'CATEGORY', code: code('cat') });
    const wrongCategory = await directory({ kind: 'CATEGORY', code: code('cat') });
    const fault = await directory({ kind: 'FAULT', code: code('fault'), categoryId: category.id });
    const work = await sku('WORK', wrongCategory.id);
    const part = await sku('PART', category.id);
    await expect(run((c, a) => createDirectory(c, a, { kind: 'MODEL', code: code('bad'), categoryId: category.id, brandId: fault.id })))
      .rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(run((c, a) => createMapping(c, a, { categoryId: category.id, faultId: fault.id, itemId: work.reviewed.id })))
      .rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(run((c, a) => createMapping(c, a, { categoryId: category.id, faultId: fault.id, itemId: part.reviewed.id })))
      .rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(run((c, a) => publishItem(c, a, { ...part.input, ...cas(part.reviewed), kind: 'WORK', durationMinutes: 1 })))
      .rejects.toMatchObject({ code: 'CONFLICT', field: 'kind' });
    const attempt = { ...work.input, ...cas(work.reviewed), unit: 'hour' };
    await expect(run((c, a) => publishItem(c, a, attempt))).rejects.toMatchObject({ code: 'INVALID_INPUT', field: 'input' });
    await expect(fixture().migrator.query("UPDATE foundation.catalog_items SET unit='hour' WHERE id=$1", [work.reviewed.id]))
      .rejects.toMatchObject({ code: '23514' });
    expect(await run(c => readCatalogRevision(c, { type: 'item', id: work.reviewed.id, revisionId: work.reviewed.revisionId })))
      .toMatchObject({ unit: 'visit' });
  }, TIMEOUT);

  it('uses explicit zero with basis, exact bigint max, and independent timelines without cross-city fallback', async () => {
    const { reviewed: item } = await sku();
    const start = await dbAt(1800);
    const body = priceInput(item.id, start);
    await expect(fresh(item.id)).rejects.toMatchObject({ code: 'PRICE_NOT_CONFIGURED' });
    for (const amountMinor of ['00', '1.0', '9223372036854775808', '-1']) {
      await expect(run((c, a) => publishFixedPrice(c, a, { ...body, amountMinor })))
        .rejects.toMatchObject({ code: 'INVALID_INPUT', field: 'amountMinor' });
    }
    await expect(run((c, a) => publishFixedPrice(c, a, { ...body, amountMinor: '0' })))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const zero = await run((c, a) => publishFixedPrice(c, a, { ...body, amountMinor: '0', zeroBasis: 'Reviewed synthetic zero' }));
    await expect(run(c => readFixedPrice(c, target(item.id, otherCity)))).rejects.toMatchObject({ code: 'PRICE_NOT_CONFIGURED' });
    const max = await run((c, a) => publishFixedPrice(c, a, { ...body, cityId: otherCity.id, amountMinor: '9223372036854775807' }));
    expect(zero.id).not.toBe(max.id);
    const zeroTarget = { cityId: city.id, itemId: item.id, expectedVersion: zero.version, priceVersionId: zero.revisionId,
      at: atOffset(start, 2000) };
    await expect(run((c, a) => closeFixedPrice(c, a, { ...zeroTarget, cityId: otherCity.id })))
      .rejects.toMatchObject({ code: 'NOT_FOUND', field: 'priceVersionId' });
    expect((await dbAt()) < start).toBe(true);
    await expect(run((c, a) => closeFixedPrice(c, a, zeroTarget))).rejects.toMatchObject({ code: 'CONFLICT', field: 'at' });
    await expect(run(c => readFixedPriceRevision(c, { cityId: otherCity.id, itemId: item.id, priceVersionId: zero.revisionId })))
      .rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(run(c => readFixedPrice(c, { ...target(item.id), cityVersionId: otherCity.versionId })))
      .rejects.toMatchObject({ code: 'CONFLICT', field: 'cityVersionId' });
    await waitAt(start);
    expect((await fresh(item.id)).price).toMatchObject({ cityVersionId: city.versionId, priceVersionId: zero.revisionId,
      amountMinor: '0', zeroBasis: 'Reviewed synthetic zero' });
    expect((await run(c => readFixedPrice(c, target(item.id, otherCity)))).price).toMatchObject({ cityVersionId: otherCity.versionId,
      priceVersionId: max.revisionId, amountMinor: '9223372036854775807', zeroBasis: null });
  }, TIMEOUT);

  it('keeps the reviewed item revision with the same price after rename; archived/hidden sources cannot serve fresh', async () => {
    const old = await openPrice();
    const { id, revisionId } = old.item.reviewed;
    const renamed = await fixture().inTransaction(c => publishItem(c, fixture().secondReviewer, {
      ...old.item.input, ...cas(old.item.reviewed), title: 'Renamed item',
    }));
    const exact = { cityId: city.id, itemId: id, priceVersionId: old.receipt.revisionId };
    const current = await run(c => readFixedPrice(c, { ...target(id), visibility: 'TECHNICIAN' }));
    expect(current).toMatchObject({ title: 'Renamed item', unit: 'visit', itemVersionId: renamed.revisionId,
      price: { priceVersionId: old.receipt.revisionId, itemVersionId: revisionId, amountMinor: '3100', reviewedBy: fixture().reviewer } });
    await expect(run(c => readFixedPrice(c, { ...target(id), visibility: 'PUBLIC' })))
      .rejects.toMatchObject({ code: 'CONFLICT', field: 'visibility' });
    const archived = await run((c, a) => archiveItem(c, a, cas(renamed)));
    await expect(fresh(id)).rejects.toMatchObject({ code: 'ARCHIVED' });
    await expect(run((c, a) => publishItem(c, a, { ...old.item.input, ...cas(archived) })))
      .rejects.toMatchObject({ code: 'ARCHIVED' });
    expect(await run(c => readFixedPriceRevision(c, exact))).toMatchObject({
      priceVersionId: old.receipt.revisionId, itemVersionId: revisionId, reviewedBy: fixture().reviewer });
    expect(await run(c => readCatalogRevision(c, { type: 'item', id, revisionId }))).toMatchObject({ title: 'Reviewed WORK' });
    expect(await run(c => readCatalogRevision(c, { type: 'item', id, revisionId: renamed.revisionId })))
      .toMatchObject({ title: 'Renamed item', reviewedBy: fixture().secondReviewer });
  }, TIMEOUT);

  it('requires explicit caller transactions for mutation and fresh pricing, and RC for fresh pricing', async () => {
    const old = await openPrice();
    const c = await fixture().runtime.connect();
    const value = code('no-autocommit');
    try {
      await expect(createDirectory(c, fixture().reviewer, { kind: 'BRAND', code: value }))
        .rejects.toMatchObject({ code: 'TRANSACTION_REQUIRED' });
      await expect(readFixedPrice(c, target(old.item.reviewed.id))).rejects.toMatchObject({ code: 'TRANSACTION_REQUIRED' });
      await c.query('BEGIN ISOLATION LEVEL REPEATABLE READ');
      await expect(readFixedPrice(c, target(old.item.reviewed.id))).rejects.toMatchObject({ code: 'ISOLATION_REQUIRED' });
    } finally {
      try { await c.query('ROLLBACK'); } finally { c.release(); }
    }
    expect((await fixture().runtime.query('SELECT 1 FROM foundation.catalog_directory_entries WHERE code=$1', [value])).rowCount).toBe(0);
  }, TIMEOUT);

  it('serializes two real replace requests; one wins and persisted projections meet exactly at T', async () => {
    const old = await openPrice();
    const at = await dbAt(3200);
    const req = replacement(old, at);
    const winner = await withConnections(async (h, w) => {
      const holder = await backend(h);
      const waiter = await backend(w);
      const won = await replaceFixedPrice(h, fixture().reviewer, req);
      const queued = replaceFixedPrice(w, fixture().secondReviewer, { ...req, amountMinor: '8200' })
        .then(value => ({ value }), (error: unknown) => ({ error }));
      await waitForFence(holder, waiter, 'ExclusiveLock');
      await h.query('COMMIT');
      expect(await queued).toMatchObject({ error: { code: 'STALE_VERSION' } });
      return won;
    });
    expect(winner).toMatchObject({ id: old.receipt.id, version: 2, revisionVersion: 2 });
    expect(await persisted(winner.id)).toEqual({ version: 2, revision_ids: [old.receipt.revisionId, winner.revisionId],
      closes: [at, null], amount_minors: ['3100', '5400'], audits: 2, events: 2 });
    expect(await projectedAt(winner.id, at)).toEqual([[old.receipt.revisionId], [winner.revisionId], [winner.revisionId]]);
  }, TIMEOUT);

  it('takes the reader clock only after fence release and sees the correct committed version on both sides of T', async () => {
    const old = await openPrice();
    const at = await dbAt(3200);
    const won = await withConnections(async (h, w) => {
      const holder = await backend(h);
      const waiter = await backend(w);
      const newPrice = await replaceFixedPrice(h, fixture().reviewer, replacement(old, at));
      const invokedAt = await dbAt();
      const queued = readFixedPrice(w, target(old.item.reviewed.id)).then(value => ({ value }), (error: unknown) => ({ error }));
      await waitForFence(holder, waiter, 'ShareLock');
      // Ensure the DB clock advances across at least one tick during the observed wait.
      await waitAt(atOffset(invokedAt, 15));
      const releasingAt = await dbAt();
      await h.query('COMMIT');
      const result = await queued;
      if ('error' in result) {throw result.error;}
      expect(result.value.pricingAt >= releasingAt).toBe(true);
      expect(result.value.pricingAt < at).toBe(true);
      expect(result.value.price).toMatchObject({ priceVersionId: old.receipt.revisionId, closedEffectiveUntil: at });
      await w.query('COMMIT');
      return newPrice;
    });
    await waitAt(at);
    const later = await fresh(old.item.reviewed.id);
    expect(later.pricingAt >= at).toBe(true);
    expect(later.price.priceVersionId).toBe(won.revisionId);
  }, TIMEOUT);

  it('after a blocked reader straddles T and the writer rolls back, still reads only the original price', async () => {
    const old = await openPrice();
    const at = await dbAt(2800);
    const before = await persisted(old.receipt.id);
    await withConnections(async (h, w) => {
      const holder = await backend(h);
      const waiter = await backend(w);
      await replaceFixedPrice(h, fixture().reviewer, replacement(old, at));
      const queued = readFixedPrice(w, target(old.item.reviewed.id)).then(value => ({ value }), (error: unknown) => ({ error }));
      await waitForFence(holder, waiter, 'ShareLock');
      await waitAt(at);
      await h.query('ROLLBACK');
      const result = await queued;
      if ('error' in result) {throw result.error;}
      expect(result.value.pricingAt >= at).toBe(true);
      expect(result.value.price).toMatchObject({ priceVersionId: old.receipt.revisionId, closedEffectiveUntil: null });
    });
    expect(await persisted(old.receipt.id)).toEqual(before);
    expect(await projectedAt(old.receipt.id, at)).toEqual(Array.from({ length: 3 }, () => [old.receipt.revisionId]));
  }, TIMEOUT);

  it('rejects COMMIT at the deferred final-clock guard when a successful port call crosses T', async () => {
    const old = await openPrice();
    const at = await dbAt(2200);
    const before = await persisted(old.receipt.id);
    await expect(run(async (c, a) => {
      const tentative = await replaceFixedPrice(c, a, replacement(old, at));
      expect(tentative.version).toBe(2);
      await waitAt(at);
    })).rejects.toMatchObject({ code: '23514', constraint: 'catalog_price_periods_final_clock_guard' });
    expect(await persisted(old.receipt.id)).toEqual(before);
    expect(await projectedAt(old.receipt.id, at)).toEqual(Array.from({ length: 3 }, () => [old.receipt.revisionId]));
  }, TIMEOUT);

  it.each(['audit_logs', 'outbox_events'] as const)('forces complete replace rollback after %s fails, even if caller commits', async table => {
    const old = await openPrice();
    const before = await persisted(old.receipt.id);
    await fixture().migrator.query(`CREATE FUNCTION foundation.catalog_p0401_fail_evidence() RETURNS trigger
      LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
      RAISE EXCEPTION 'synthetic evidence fault' USING ERRCODE='23514'; END $$`);
    try {
      await fixture().migrator.query(`CREATE TRIGGER catalog_p0401_fail_evidence BEFORE INSERT ON foundation.${table}
        FOR EACH ROW EXECUTE FUNCTION foundation.catalog_p0401_fail_evidence()`);
      const at = await dbAt(3500);
      await run(async (c, a) => {
        await expect(replaceFixedPrice(c, a, replacement(old, at))).rejects.toBeInstanceOf(CatalogInternalError);
        // Deliberately swallow the port error; its own savepoint must have undone every change.
      });
      expect(await persisted(old.receipt.id)).toEqual(before);
      expect(await projectedAt(old.receipt.id, at)).toEqual(Array.from({ length: 3 }, () => [old.receipt.revisionId]));
    } finally {
      await fixture().migrator.query(`DROP TRIGGER IF EXISTS catalog_p0401_fail_evidence ON foundation.${table}`);
      await fixture().migrator.query('DROP FUNCTION foundation.catalog_p0401_fail_evidence()');
    }
  }, TIMEOUT);

  it('verifies exact durable state independently after a concealed COMMIT acknowledgement and fences stale retry', async () => {
    const old = await openPrice();
    const at = await dbAt(4000);
    const req = replacement(old, at);
    const ackLost = new Error('Synthetic lost catalog COMMIT acknowledgement');
    await withConnections(async (writer, observer) => {
      expect(await backend(writer)).not.toBe(await backend(observer));
      const won = await replaceFixedPrice(writer, fixture().reviewer, req);
      const concealCommit = async () => {
        await writer.query('COMMIT');
        throw ackLost;
      };
      await expect(concealCommit()).rejects.toBe(ackLost);
      expect(await readFixedPriceRevision(observer, { cityId: city.id, itemId: old.item.reviewed.id, priceVersionId: won.revisionId }))
        .toMatchObject({ priceVersionId: won.revisionId, seriesId: won.id, version: won.revisionVersion,
          cityVersionId: city.versionId, itemVersionId: old.item.reviewed.revisionId, amountMinor: req.amountMinor,
          currency: req.currency, sourceRef: req.sourceRef, validFrom: at, reviewedBy: fixture().reviewer });
      const verified = await persisted(won.id);
      expect(verified).toEqual({ version: 2, revision_ids: [old.receipt.revisionId, won.revisionId], closes: [at, null],
        amount_minors: ['3100', '5400'], audits: 2, events: 2 });
      const { rows } = await observer.query<{ identical: boolean; payload: unknown }>(`SELECT
        a.details=o.payload AS identical, o.payload FROM foundation.audit_logs a JOIN foundation.outbox_events o
          ON o.event_id=a.correlation_id AND o.event_type=a.operation
        WHERE a.operation='catalog.price.replace' AND a.details->>'id'=$1`, [won.id]);
      expect(rows).toHaveLength(1);
      const evidence = first(rows);
      expect(evidence).toMatchObject({ identical: true, payload: { actorStaffId: fixture().reviewer, id: won.id,
        version: 2, revisionId: won.revisionId, revisionVersion: 2, itemId: old.item.reviewed.id, cityId: city.id, kind: 'FIXED_PRICE' } });
      expect(JSON.stringify(evidence.payload)).not.toContain(req.sourceRef);
      expect(evidence.payload).not.toHaveProperty('amountMinor');
      await expect(replaceFixedPrice(observer, fixture().reviewer, req)).rejects.toMatchObject({ code: 'STALE_VERSION' });
      expect(await persisted(won.id)).toEqual(verified);
    });
  }, TIMEOUT);

  it('blocks a direct runtime SQL period writer behind a held fresh-read fence; standalone close leaves a gap', async () => {
    const old = await openPrice();
    const at = await dbAt(3000);
    await withConnections(async (h, w) => {
      const holder = await backend(h);
      const waiter = await backend(w);
      expect((await readFixedPrice(h, target(old.item.reviewed.id))).price.priceVersionId).toBe(old.receipt.revisionId);
      const queued = w.query(`UPDATE foundation.catalog_price_periods SET closed_effective_until=$2 WHERE price_version_id=$1`,
        [old.receipt.revisionId, at]).then(value => ({ value }), (error: unknown) => ({ error }));
      await waitForFence(holder, waiter, 'ExclusiveLock');
      await h.query('COMMIT');
      expect(await queued).toMatchObject({ value: { rowCount: 1 } });
      await w.query('ROLLBACK');
    });
    const cut = await dbAt(1200);
    const close = { cityId: city.id, itemId: old.item.reviewed.id, priceVersionId: old.receipt.revisionId,
      expectedVersion: old.receipt.version, at: cut };
    expect(await run((c, a) => closeFixedPrice(c, a, close))).toMatchObject({ id: old.receipt.id, version: 2 });
    await expect(run((c, a) => closeFixedPrice(c, a, close))).rejects.toMatchObject({ code: 'STALE_VERSION' });
    await expect(run((c, a) => closeFixedPrice(c, a, { ...close, expectedVersion: 2, at: atOffset(cut, 3000) })))
      .rejects.toMatchObject({ code: 'CONFLICT', field: 'at' });
    expect(await projectedAt(old.receipt.id, cut)).toEqual([[old.receipt.revisionId], [], []]);
    await waitAt(cut);
    await expect(fresh(old.item.reviewed.id)).rejects.toMatchObject({ code: 'PRICE_NOT_CONFIGURED' });
  }, TIMEOUT);
});
