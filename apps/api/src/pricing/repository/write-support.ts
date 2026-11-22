import { randomUUID } from 'node:crypto';
import type { CatalogClient, CatalogReceipt, CatalogRevisionReceipt } from '../../catalog/contracts.js';
import { nextVersion, wrote } from '../../catalog/records.js';
import { mutate } from '../../catalog/transaction.js';
import { CatalogInternalError, expectedVersion, instant, optionalInstant, refuse, text, uuid } from '../../catalog/validation.js';

export interface ScheduleKey {
  readonly cityId: string;
  readonly expectedVersion: number;
}
export interface ScheduleBody {
  readonly validFrom: string;
  readonly validUntil?: string | null;
  readonly sourceRef: string;
}
export interface CloseTarget { readonly versionId: string; readonly at: string }
export const CLOCK = "pg_catalog.date_trunc('milliseconds', pg_catalog.clock_timestamp(), 'UTC')";

// These identifiers are private constants, never constructed from a request or a database value.
const families = Object.freeze({
  rule: { series: 'price_rule_series', versions: 'price_rule_versions', periods: 'price_rule_periods', owner: 'rule_id' },
  policy: { series: 'pricing_policy_series', versions: 'pricing_policy_versions', periods: 'pricing_policy_periods', owner: null },
  estimate: { series: 'public_price_estimate_series', versions: 'public_price_estimates', periods: 'public_price_estimate_periods', owner: 'id' },
} as const);
export type Family = keyof typeof families;
export type Operation = 'rule.create' | 'rule.archive' | 'estimate.create' | 'estimate.archive' | `${Family}.${'publish' | 'replace' | 'close'}`;
export const SCHEDULE_KEYS = ['cityId', 'expectedVersion'] as const;
export const BODY_KEYS = ['validUntil', 'sourceRef'] as const;
export const CLOSE_KEYS = ['versionId', 'at'] as const;

export function scheduleKey(dto: Record<string, unknown>, initial: boolean): ScheduleKey {
  return { cityId: uuid(dto['cityId'], 'cityId'), expectedVersion: expectedVersion(dto['expectedVersion'], initial ? 0 : 1) };
}
export function closeKey(dto: Record<string, unknown>): CloseTarget {
  return { versionId: uuid(dto['versionId'], 'versionId'), at: instant(dto['at'], 'at') };
}
export function scheduleBody(dto: Record<string, unknown>, start = instant(dto['validFrom'], 'validFrom')) {
  const validUntil = optionalInstant(dto['validUntil'], 'validUntil');
  if (validUntil !== null && validUntil <= start) {refuse('INVALID_INPUT', 'validUntil');}
  return { validFrom: start, validUntil, sourceRef: text(dto['sourceRef'], 200, 'sourceRef') };
}
export type Schedule = ReturnType<typeof scheduleBody>;

export async function lockCity(client: CatalogClient, cityId: string): Promise<string> {
  const { rows } = await client.query<{ current_version_id: string | null }>(
    'SELECT current_version_id FROM foundation.service_cities WHERE id=$1 FOR SHARE', [cityId]);
  const row = rows[0] ?? refuse('NOT_FOUND', 'cityId');
  return row.current_version_id ?? refuse('CONFLICT', 'cityId');
}

interface Series { id: string; row_version: number; archived: boolean }
async function findSeries(client: CatalogClient, family: Family, cityId: string, owner: string | null): Promise<Series | undefined> {
  const { series, owner: column } = families[family];
  if ((owner === null) !== (column === null)) {throw new CatalogInternalError();}
  const { rows } = await client.query<Series>(`SELECT id,row_version,${family === 'estimate' ? 'archived_at IS NOT NULL' : 'false'} AS archived
    FROM foundation.${series} WHERE city_id=$1${column === null ? '' : ` AND ${column}=$2`}`, column === null ? [cityId] : [cityId, owner]);
  if (rows.length > 1) {throw new CatalogInternalError();}
  return rows[0];
}

async function advance(client: CatalogClient, family: Family, key: ScheduleKey, series: Series | undefined, owner: string | null): Promise<CatalogReceipt> {
  const table = families[family].series;
  if ((series?.row_version ?? 0) !== key.expectedVersion) {refuse('STALE_VERSION', 'expectedVersion');}
  if (series) {
    if (series.archived) {refuse('ARCHIVED', 'estimateId');}
    const { rows } = await client.query<{ row_version: number }>(`UPDATE foundation.${table} SET row_version=$3
      WHERE id=$1 AND row_version=$2 RETURNING row_version`, [series.id, key.expectedVersion, nextVersion(series.row_version)]);
    return { id: series.id, version: (rows[0] ?? refuse('STALE_VERSION', 'expectedVersion')).row_version };
  }
  if (family === 'estimate') {refuse('NOT_FOUND', 'estimateId');}
  const id = randomUUID();
  const { rowCount } = family === 'policy'
    ? await client.query(`INSERT INTO foundation.pricing_policy_series (id,city_id) VALUES($1,$2)`, [id, key.cityId])
    : await client.query(`INSERT INTO foundation.price_rule_series (id,city_id,rule_id) VALUES($1,$2,$3)`, [id, key.cityId, owner]);
  wrote(rowCount);
  return { id, version: 1 };
}

export async function pricingAudit(client: CatalogClient, op: Operation, actor: string, receipt: CatalogReceipt | CatalogRevisionReceipt,
  target: { cityId?: string; ruleId?: string; estimateId?: string; previousRevisionId?: string } = {}): Promise<void> {
  // Rebuild from typed identity scalars; neither business contents nor driver errors leave this function.
  const id = randomUUID();
  const details = JSON.stringify({ actorStaffId: actor, id: receipt.id, version: receipt.version,
    ...('revisionId' in receipt ? {revisionId: receipt.revisionId, revisionVersion: receipt.revisionVersion} : {}),
    ...(target.cityId === undefined ? {} : {cityId: target.cityId}), ...(target.ruleId === undefined ? {} : {ruleId: target.ruleId}),
    ...(target.estimateId === undefined ? {} : {estimateId: target.estimateId}),
    ...(target.previousRevisionId === undefined ? {} : {previousRevisionId: target.previousRevisionId}) });
  try {
    wrote((await client.query(`INSERT INTO foundation.audit_logs(id,operation,correlation_id,details) VALUES($1,$2,$3,$4::jsonb)`,
      [randomUUID(), `pricing.${op}`, id, details])).rowCount);
    wrote((await client.query(`INSERT INTO foundation.outbox_events(id,event_id,event_type,payload) VALUES($1,$2,$3,$4::jsonb)`,
      [randomUUID(), id, `pricing.${op}`, details])).rowCount);
  } catch {throw new CatalogInternalError();}
}

function temporalFault(error: unknown, table: string): never {
  if (error instanceof Error && 'code' in error && 'constraint' in error) {
    if (error.code === '23P01' && error.constraint === `${table}_no_overlap`) {refuse('CONFLICT', 'period');}
    if (error.code === '23514' && error.constraint === `${table}_future_start_guard`) {refuse('CONFLICT', 'validFrom');}
    if (error.code === '23514' && error.constraint === `${table}_close_guard`) {refuse('CONFLICT', 'at');}
  }
  throw error;
}

async function closeRow(client: CatalogClient, family: Family, key: ScheduleKey, series: Series, end: CloseTarget): Promise<void> {
  const { periods } = families[family];
  try {
    const { rowCount } = await client.query(`WITH clock AS MATERIALIZED (SELECT ${CLOCK} AS now)
      UPDATE foundation.${periods} AS p SET closed_effective_until=$4::timestamptz FROM clock
      WHERE p.version_id=$1 AND p.series_id=$2 AND p.city_id=$3 AND p.closed_effective_until IS NULL
        AND p.valid_from <= clock.now AND clock.now < $4::timestamptz
        AND (p.scheduled_until IS NULL OR $4::timestamptz < p.scheduled_until)`, [end.versionId, series.id, key.cityId, end.at]);
    if (rowCount === 0) {refuse('CONFLICT', 'at');}
    wrote(rowCount);
  } catch (error) {temporalFault(error, periods);}
}

export interface NewVersion {
  readonly id: string;
  readonly seriesId: string;
  readonly version: number;
  readonly cityVersionId: string;
}
export async function writeSchedule(
  client: CatalogClient, actor: string, family: Family, owner: string | null, key: ScheduleKey,
  end: CloseTarget | null, replacement: { schedule: Schedule; insert: (v: NewVersion) => Promise<void> } | null,
  checkPublish: () => Promise<void>,
): Promise<CatalogReceipt | CatalogRevisionReceipt> {
  return mutate(client, async () => {
    const { periods } = families[family];
    const cityVersionId = await lockCity(client, key.cityId);
    const series = await findSeries(client, family, key.cityId, owner);
    const target = { cityId: key.cityId, ...(family === 'rule' && owner ? {ruleId: owner} : {}),
      ...(family === 'estimate' && owner ? {estimateId: owner} : {}), ...(end ? {previousRevisionId: end.versionId} : {}) };
    if (end) {
      if (!series) {refuse('NOT_FOUND', 'versionId');}
      const { rowCount } = await client.query(`SELECT 1 FROM foundation.${periods}
        WHERE version_id=$1 AND series_id=$2 AND city_id=$3`, [end.versionId, series.id, key.cityId]);
      if (rowCount !== 1) {refuse('NOT_FOUND', 'versionId');}
    }
    if (!series && family === 'estimate') {refuse('NOT_FOUND', 'estimateId');}
    if ((series?.row_version ?? 0) !== key.expectedVersion) {refuse('STALE_VERSION', 'expectedVersion');}
    if (series?.archived) {refuse('ARCHIVED', 'estimateId');}
    if (replacement) {
      await checkPublish();
      const { rows } = await client.query<{ future: boolean }>(`SELECT $1::timestamptz > ${CLOCK} AS future`, [replacement.schedule.validFrom]);
      if (rows[0]?.future !== true) {refuse('CONFLICT', 'validFrom');}
    }
    if (end && series) {await closeRow(client, family, key, series, end);}
    const updated = await advance(client, family, key, series, owner);
    if (!replacement) {
      await pricingAudit(client, `${family}.close`, actor, updated, target);
      return updated;
    }
    const id = randomUUID();
    await replacement.insert({ id, seriesId: updated.id, version: updated.version, cityVersionId });
    try {
      wrote((await client.query(`INSERT INTO foundation.${periods}
        (version_id,series_id,city_id,valid_from,scheduled_until) VALUES($1,$2,$3,$4,$5)`,
      [id, updated.id, key.cityId, replacement.schedule.validFrom, replacement.schedule.validUntil])).rowCount);
    } catch (error) {temporalFault(error, periods);}
    const receipt = { ...updated, revisionId: id, revisionVersion: updated.version };
    await pricingAudit(client, `${family}.${end ? 'replace' : 'publish'}`, actor, receipt, target);
    return receipt;
  });
}

export function revision(receipt: CatalogReceipt | CatalogRevisionReceipt): CatalogRevisionReceipt {
  if (!('revisionId' in receipt)) {throw new CatalogInternalError();}
  return receipt;
}
