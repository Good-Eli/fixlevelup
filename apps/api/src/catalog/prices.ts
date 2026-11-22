import { randomUUID } from 'node:crypto';
import { audit } from './audit.js';
import type {
  CatalogClient, CatalogReceipt, CatalogRevisionReceipt, CloseFixedPriceInput, PublishFixedPriceInput, ReplaceFixedPriceInput,
} from './contracts.js';
import { categoryRef, checkedRevisionId, item, nextVersion, wrote } from './records.js';
import { mutate } from './transaction.js';
import {
  amountMinor, currency, expectedVersion, instant, optionalInstant, optionalText, record, refuse, text, uuid,
} from './validation.js';

const SERIES_KEYS = ['cityId', 'itemId', 'expectedVersion'] as const;
const TARGET_KEYS = [...SERIES_KEYS, 'priceVersionId', 'at'] as const;
const PRICE_KEYS = ['amountMinor', 'currency', 'zeroBasis', 'sourceRef', 'validUntil'] as const;

interface SeriesKey { cityId: string; itemId: string; expectedVersion: number }
interface TargetKey extends SeriesKey { priceVersionId: string; at: string }
interface PriceBody { amountMinor: string; currency: string; zeroBasis: string | null; sourceRef: string; validUntil: string | null }
interface SeriesRow { id: string; row_version: number }

function priceBody(dto: Record<string, unknown>, start: string): PriceBody {
  const amount = amountMinor(dto['amountMinor']);
  const zeroBasis = optionalText(dto['zeroBasis'], 200, 'zeroBasis');
  if ((amount === '0') !== (zeroBasis !== null)) {
    refuse('INVALID_INPUT', 'zeroBasis');
  }
  const validUntil = optionalInstant(dto['validUntil'], 'validUntil');
  if (validUntil !== null && validUntil <= start) {
    refuse('INVALID_INPUT', 'validUntil');
  }
  return { amountMinor: amount, zeroBasis, validUntil, currency: currency(dto['currency']),
    sourceRef: text(dto['sourceRef'], 200, 'sourceRef') };
}

function seriesKey(dto: Record<string, unknown>, initial = false): SeriesKey {
  return { cityId: uuid(dto['cityId'], 'cityId'), itemId: uuid(dto['itemId'], 'itemId'),
    expectedVersion: expectedVersion(dto['expectedVersion'], initial ? 0 : 1) };
}

function targetKey(dto: Record<string, unknown>): TargetKey {
  return { ...seriesKey(dto), priceVersionId: uuid(dto['priceVersionId'], 'priceVersionId'), at: instant(dto['at'], 'at') };
}

async function lockCity(client: CatalogClient, cityId: string): Promise<string> {
  // Do not join the immutable version before waiting: EvalPlanQual can refresh
  // this city row mid-statement. Keep SHARE until the caller ends the tx.
  const { rows } = await client.query<{ current_version_id: string | null }>(`SELECT current_version_id
    FROM foundation.service_cities WHERE id = $1 FOR SHARE`, [cityId]);
  const row = rows[0] ?? refuse('NOT_FOUND', 'cityId');
  return row.current_version_id ?? refuse('CONFLICT', 'cityId');
}

async function reviewedItemVersion(client: CatalogClient, itemId: string): Promise<string> {
  const source = await item(client, itemId, 'itemId');
  const revisionId = checkedRevisionId(source, 'itemId');
  await categoryRef(client, source.category_id, true);
  return revisionId;
}

async function series(client: CatalogClient, key: SeriesKey): Promise<SeriesRow | undefined> {
  const { rows } = await client.query<SeriesRow>(`SELECT id, row_version FROM foundation.catalog_price_series
    WHERE city_id = $1 AND item_id = $2`, [key.cityId, key.itemId]);
  return rows[0];
}

async function advanceSeries(client: CatalogClient, key: SeriesKey, row: SeriesRow): Promise<CatalogReceipt> {
  const expectedNext = nextVersion(row.row_version);
  const { rows } = await client.query<{ row_version: number }>(`UPDATE foundation.catalog_price_series
    SET row_version = $3 WHERE id = $1 AND row_version = $2 RETURNING row_version`,
  [row.id, key.expectedVersion, expectedNext]);
  const updated = rows[0] ?? refuse('STALE_VERSION', 'expectedVersion');
  return { id: row.id, version: updated.row_version };
}

async function createSeries(client: CatalogClient, key: SeriesKey): Promise<CatalogReceipt> {
  const id = randomUUID();
  const { rows } = await client.query<{ row_version: number }>(`INSERT INTO foundation.catalog_price_series
    (id, city_id, item_id) VALUES ($1, $2, $3) ON CONFLICT (city_id, item_id) DO NOTHING RETURNING row_version`,
  [id, key.cityId, key.itemId]);
  const inserted = rows[0] ?? refuse('STALE_VERSION', 'expectedVersion');
  return { id, version: inserted.row_version };
}

async function ensureFutureStart(client: CatalogClient, start: string): Promise<void> {
  const { rows } = await client.query<{ future: boolean }>(`SELECT $1::timestamptz >
    pg_catalog.date_trunc('milliseconds', pg_catalog.clock_timestamp()) AS future`, [start]);
  if (rows[0]?.future !== true) {
    refuse('CONFLICT', 'validFrom');
  }
}

interface NewPrice extends PriceBody {
  cityId: string; cityVersionId: string; itemId: string; itemVersionId: string; validFrom: string; actor: string;
}

async function appendPrice(client: CatalogClient, receipt: CatalogReceipt, price: NewPrice): Promise<CatalogRevisionReceipt> {
  const revisionId = randomUUID();
  const revisionVersion = receipt.version;
  const inserted = await client.query(`INSERT INTO foundation.catalog_price_versions
    (id, series_id, city_id, city_version_id, item_id, item_version_id, version, amount_minor, currency,
     zero_basis, source_ref, reviewed_by, valid_from, valid_until)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8::bigint, $9, $10, $11, $12, $13, $14)`,
  [revisionId, receipt.id, price.cityId, price.cityVersionId, price.itemId, price.itemVersionId, revisionVersion,
    price.amountMinor, price.currency, price.zeroBasis, price.sourceRef, price.actor, price.validFrom, price.validUntil]);
  wrote(inserted.rowCount);
  const period = await client.query(`INSERT INTO foundation.catalog_price_periods
    (price_version_id, series_id, city_id, item_id, valid_from, scheduled_until)
    VALUES ($1, $2, $3, $4, $5, $6)`,
  [revisionId, receipt.id, price.cityId, price.itemId, price.validFrom, price.validUntil]);
  wrote(period.rowCount);
  return { ...receipt, revisionId, revisionVersion };
}

export async function publishFixedPrice(
  client: CatalogClient, reviewedBy: string, input: PublishFixedPriceInput,
): Promise<CatalogRevisionReceipt> {
  const actor = uuid(reviewedBy, 'reviewedBy');
  const dto = record(input, [...SERIES_KEYS, ...PRICE_KEYS, 'validFrom']);
  const key = seriesKey(dto, true);
  const validFrom = instant(dto['validFrom'], 'validFrom');
  const body = priceBody(dto, validFrom);
  return mutate(client, async () => {
    const cityVersionId = await lockCity(client, key.cityId);
    const row = await series(client, key);
    if ((row?.row_version ?? 0) !== key.expectedVersion) {
      refuse('STALE_VERSION', 'expectedVersion');
    }
    const itemVersionId = await reviewedItemVersion(client, key.itemId);
    await ensureFutureStart(client, validFrom);
    const aggregate = row ? await advanceSeries(client, key, row) : await createSeries(client, key);
    const receipt = await appendPrice(client, aggregate, { ...body, ...key, actor, validFrom, cityVersionId, itemVersionId });
    await audit(client, 'catalog.price.publish', actor, 'FIXED_PRICE', receipt, key);
    return receipt;
  });
}

/** Validate exact ownership before CAS, then CAS before any eligibility/clock refusal. */
async function closeTarget(client: CatalogClient, key: TargetKey): Promise<SeriesRow> {
  const { rows } = await client.query<SeriesRow>(`SELECT s.id, s.row_version
    FROM foundation.catalog_price_periods AS p
    JOIN foundation.catalog_price_series AS s ON (s.id, s.city_id, s.item_id) = (p.series_id, p.city_id, p.item_id)
    WHERE p.price_version_id = $1 AND p.city_id = $2 AND p.item_id = $3`,
  [key.priceVersionId, key.cityId, key.itemId]);
  const row = rows[0] ?? refuse('NOT_FOUND', 'priceVersionId');
  if (row.row_version !== key.expectedVersion) {
    refuse('STALE_VERSION', 'expectedVersion');
  }
  return row;
}

async function closePeriod(client: CatalogClient, key: TargetKey): Promise<void> {
  // SQL's trigger re-checks after any row wait; deferred SQL also validates at
  // commit, after audit/outbox and any remaining work in the caller transaction.
  const { rowCount } = await client.query(`WITH clock AS MATERIALIZED (
      SELECT pg_catalog.date_trunc('milliseconds', pg_catalog.clock_timestamp()) AS at
    ) UPDATE foundation.catalog_price_periods AS p SET closed_effective_until = $4::timestamptz
    FROM clock WHERE p.price_version_id = $1 AND p.city_id = $2 AND p.item_id = $3
      AND p.closed_effective_until IS NULL AND p.valid_from <= clock.at AND $4::timestamptz > clock.at
      AND (p.scheduled_until IS NULL OR $4::timestamptz < p.scheduled_until)`,
  [key.priceVersionId, key.cityId, key.itemId, key.at]);
  if (rowCount === 0) {
    refuse('CONFLICT', 'at');
  }
  wrote(rowCount);
}

export async function closeFixedPrice(
  client: CatalogClient, reviewedBy: string, input: CloseFixedPriceInput,
): Promise<CatalogReceipt> {
  const actor = uuid(reviewedBy, 'reviewedBy');
  const key = targetKey(record(input, TARGET_KEYS));
  return mutate(client, async () => {
    await lockCity(client, key.cityId);
    const row = await closeTarget(client, key);
    await closePeriod(client, key);
    const receipt = await advanceSeries(client, key, row);
    await audit(client, 'catalog.price.close', actor, 'FIXED_PRICE', receipt, key);
    return receipt;
  });
}

export async function replaceFixedPrice(
  client: CatalogClient, reviewedBy: string, input: ReplaceFixedPriceInput,
): Promise<CatalogRevisionReceipt> {
  const actor = uuid(reviewedBy, 'reviewedBy');
  const dto = record(input, [...TARGET_KEYS, ...PRICE_KEYS]);
  const key = targetKey(dto);
  const body = priceBody(dto, key.at);
  return mutate(client, async () => {
    const cityVersionId = await lockCity(client, key.cityId);
    const row = await closeTarget(client, key);
    const itemVersionId = await reviewedItemVersion(client, key.itemId);
    await closePeriod(client, key);
    const aggregate = await advanceSeries(client, key, row);
    const receipt = await appendPrice(client, aggregate, {
      ...body, ...key, actor, validFrom: key.at, cityVersionId, itemVersionId,
    });
    await audit(client, 'catalog.price.replace', actor, 'FIXED_PRICE', receipt, key);
    return receipt;
  });
}
