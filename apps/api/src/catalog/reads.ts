import { PRICE_VISIBILITIES } from './contracts.js';
import type {
  CatalogClient, DirectoryRevision, FixedPrice, FixedPriceRevision, ItemRevision,
  ReadCatalogRevisionInput, ReadFixedPriceInput, ReadFixedPriceRevisionInput,
} from './contracts.js';
import { fenceRead, read, READ_TX_SETTING } from './transaction.js';
import { CatalogInternalError, choice, record, refuse, uuid } from './validation.js';

/** All apparent interpolation is composed of private, static SQL expressions. */
const utc = (column: string): string =>
  `pg_catalog.to_char(${column} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')`;

const PRICE_FIELDS = `
  'seriesId', v.series_id, 'priceVersionId', v.id, 'cityId', v.city_id, 'cityVersionId', v.city_version_id,
  'itemId', v.item_id, 'itemVersionId', v.item_version_id, 'version', v.version,
  'amountMinor', v.amount_minor::text, 'currency', v.currency, 'zeroBasis', v.zero_basis, 'sourceRef', v.source_ref,
  'reviewedBy', v.reviewed_by, 'publishedAt', ${utc('v.published_at')},
  'validFrom', ${utc('v.valid_from')}, 'validUntil', ${utc('v.valid_until')}`;

/** The snapshot is acquired strictly after the first statement's shared fence wait. */
const CURRENT_PRICE_SQL = `WITH tx AS MATERIALIZED (
    SELECT pg_catalog.current_setting('${READ_TX_SETTING}', true) = $5 AS caller_tx,
      pg_catalog.current_setting('transaction_isolation') = 'read committed' AS read_committed
  ), clock AS MATERIALIZED (
    SELECT pg_catalog.date_trunc('milliseconds', pg_catalog.clock_timestamp()) AS pricing_at
    FROM tx WHERE caller_tx IS TRUE AND read_committed
  ), sources AS MATERIALIZED (
    SELECT clock.pricing_at, c.id AS city_id, cv.id AS city_version_id, i.id AS item_id, i.unit,
      iv.id AS item_version_id, iv.title, iv.description, iv.duration_minutes,
      iv.technician_visible, iv.public_visible,
      CASE
        WHEN c.id IS NULL THEN 'CITY_NOT_FOUND'
        WHEN cv.id IS NULL OR c.lifecycle <> 'ACTIVE' THEN 'CITY_CONFLICT'
        WHEN i.id IS NULL THEN 'ITEM_NOT_FOUND'
        WHEN i.archived_at IS NOT NULL THEN 'ITEM_ARCHIVED'
        WHEN iv.id IS NULL THEN 'ITEM_CONFLICT'
        WHEN i.category_id IS NOT NULL AND cat.archived_at IS NOT NULL THEN 'CATEGORY_ARCHIVED'
        WHEN i.category_id IS NOT NULL AND (cat.id IS NULL OR cat.current_version_id IS NULL) THEN 'CATEGORY_CONFLICT'
        WHEN ($4::text = 'TECHNICIAN' AND NOT iv.technician_visible)
          OR ($4::text = 'PUBLIC' AND NOT iv.public_visible) THEN 'VISIBILITY_CONFLICT'
        ELSE 'OK'
      END AS status
    FROM clock
    LEFT JOIN foundation.service_cities AS c ON c.id = $1
    LEFT JOIN foundation.service_city_versions AS cv ON (cv.city_id, cv.id) = (c.id, c.current_version_id) AND cv.id = $2
    LEFT JOIN foundation.catalog_items AS i ON i.id = $3
    LEFT JOIN foundation.catalog_item_versions AS iv ON (iv.item_id, iv.id) = (i.id, i.current_version_id)
    LEFT JOIN foundation.catalog_directory_entries AS cat ON cat.id = i.category_id AND cat.kind = 'CATEGORY'
  ), effective_price AS (
    SELECT pg_catalog.jsonb_build_object(${PRICE_FIELDS}, 'closedEffectiveUntil', ${utc('p.closed_effective_until')}) AS price
    FROM sources AS s
    JOIN foundation.catalog_price_periods AS p ON (p.city_id, p.item_id) = (s.city_id, s.item_id)
    JOIN foundation.catalog_price_versions AS v
      ON (v.id, v.series_id, v.city_id, v.item_id) = (p.price_version_id, p.series_id, p.city_id, p.item_id)
    WHERE s.status = 'OK' AND p.valid_from <= s.pricing_at
      AND (coalesce(p.closed_effective_until, p.scheduled_until) IS NULL
        OR s.pricing_at < coalesce(p.closed_effective_until, p.scheduled_until))
  )
  SELECT CASE WHEN tx.caller_tx IS NOT TRUE THEN 'TRANSACTION_REQUIRED'
      WHEN NOT tx.read_committed THEN 'ISOLATION_REQUIRED' ELSE s.status END AS status,
    CASE WHEN p.price IS NOT NULL THEN pg_catalog.jsonb_build_object(
      'pricingAt', ${utc('s.pricing_at')}, 'cityId', s.city_id, 'cityVersionId', s.city_version_id,
      'itemId', s.item_id, 'itemVersionId', s.item_version_id, 'unit', s.unit, 'title', s.title,
      'description', s.description, 'durationMinutes', s.duration_minutes,
      'technicianVisible', s.technician_visible, 'publicVisible', s.public_visible, 'price', p.price
    ) END AS result
  FROM tx LEFT JOIN sources AS s ON true LEFT JOIN effective_price AS p ON true`;

/** Resolve a fresh current-city source; this is not a business readiness check. */
export async function readFixedPrice(client: CatalogClient, input: ReadFixedPriceInput): Promise<FixedPrice> {
  const dto = record(input, ['cityId', 'cityVersionId', 'itemId', 'visibility']);
  const cityId = uuid(dto['cityId'], 'cityId');
  const cityVersionId = uuid(dto['cityVersionId'], 'cityVersionId');
  const itemId = uuid(dto['itemId'], 'itemId');
  const visibility = dto['visibility'] === undefined ? null : choice(dto['visibility'], PRICE_VISIBILITIES, 'visibility');
  return read(async () => {
    const marker = await fenceRead(client);
    const { rows } = await client.query<{ status: string; result: FixedPrice | null }>(CURRENT_PRICE_SQL,
      [cityId, cityVersionId, itemId, visibility, marker]);
    const row = rows[0];
    if (!row || rows.length !== 1) {
      throw new CatalogInternalError();
    }
    switch (row.status) {
      case 'TRANSACTION_REQUIRED': return refuse('TRANSACTION_REQUIRED');
      case 'ISOLATION_REQUIRED': return refuse('ISOLATION_REQUIRED');
      case 'CITY_NOT_FOUND': return refuse('NOT_FOUND', 'cityId');
      case 'CITY_CONFLICT': return refuse('CONFLICT', 'cityVersionId');
      case 'ITEM_NOT_FOUND': return refuse('NOT_FOUND', 'itemId');
      case 'ITEM_ARCHIVED': return refuse('ARCHIVED', 'itemId');
      case 'ITEM_CONFLICT': return refuse('CONFLICT', 'itemId');
      case 'CATEGORY_ARCHIVED': return refuse('ARCHIVED', 'categoryId');
      case 'CATEGORY_CONFLICT': return refuse('CONFLICT', 'categoryId');
      case 'VISIBILITY_CONFLICT': return refuse('CONFLICT', 'visibility');
      case 'OK': return row.result ?? refuse('PRICE_NOT_CONFIGURED');
      default: throw new CatalogInternalError();
    }
  });
}

/** Exact history deliberately does not consult current eligibility or the mutable period. */
export async function readFixedPriceRevision(client: CatalogClient, input: ReadFixedPriceRevisionInput): Promise<FixedPriceRevision> {
  const dto = record(input, ['cityId', 'itemId', 'priceVersionId']);
  const cityId = uuid(dto['cityId'], 'cityId');
  const itemId = uuid(dto['itemId'], 'itemId');
  const priceVersionId = uuid(dto['priceVersionId'], 'priceVersionId');
  return read(async () => {
    const { rows } = await client.query<{ result: FixedPriceRevision }>(`SELECT pg_catalog.jsonb_build_object(${PRICE_FIELDS}) AS result
      FROM foundation.catalog_price_versions AS v WHERE v.city_id = $1 AND v.item_id = $2 AND v.id = $3`,
    [cityId, itemId, priceVersionId]);
    return rows[0]?.result ?? refuse('NOT_FOUND', 'priceVersionId');
  });
}

const REVISION_FIELDS = `'revisionId', v.id, 'version', v.version, 'title', v.title, 'description', v.description,
  'reviewedBy', v.reviewed_by, 'publishedAt', ${utc('v.published_at')}`;

const DIRECTORY_REVISION = `SELECT pg_catalog.jsonb_build_object(
    ${REVISION_FIELDS}, 'type', 'directory', 'id', e.id, 'kind', e.kind, 'code', e.code,
    'categoryId', e.category_id, 'brandId', e.brand_id) AS result
  FROM foundation.catalog_directory_versions AS v
  JOIN foundation.catalog_directory_entries AS e ON e.id = v.entry_id WHERE v.entry_id = $1 AND v.id = $2`;
const ITEM_REVISION = `SELECT pg_catalog.jsonb_build_object(
    ${REVISION_FIELDS}, 'type', 'item', 'id', i.id, 'kind', i.kind, 'code', i.code, 'categoryId', i.category_id, 'unit', i.unit,
    'durationMinutes', v.duration_minutes, 'technicianVisible', v.technician_visible, 'publicVisible', v.public_visible) AS result
  FROM foundation.catalog_item_versions AS v
  JOIN foundation.catalog_items AS i ON i.id = v.item_id WHERE v.item_id = $1 AND v.id = $2`;

/** Read one exact owned immutable revision, with immutable identity fields only. */
export async function readCatalogRevision(client: CatalogClient, input: ReadCatalogRevisionInput): Promise<DirectoryRevision | ItemRevision> {
  const dto = record(input, ['type', 'id', 'revisionId']);
  const type = choice(dto['type'], ['directory', 'item'], 'type');
  const id = uuid(dto['id'], 'id');
  const revisionId = uuid(dto['revisionId'], 'revisionId');
  return read(async () => {
    const { rows } = await client.query<{ result: DirectoryRevision | ItemRevision }>(
      type === 'directory' ? DIRECTORY_REVISION : ITEM_REVISION, [id, revisionId]);
    return rows[0]?.result ?? refuse('NOT_FOUND', 'revisionId');
  });
}
