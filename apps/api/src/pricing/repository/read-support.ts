import { types } from 'node:util';
import type { CatalogClient, PriceVisibility } from '../../catalog/contracts.js';
import { fenceRead, READ_TX_SETTING } from '../../catalog/transaction.js';
import { CatalogError, CatalogInternalError } from '../../catalog/validation.js';
import { PricingError } from '../engine/index.js';
import type { PricingAdjustment, PricingEvidence } from '../engine/index.js';

export interface ReadPricingInput {
  readonly calculationId: string;
  readonly cityId: string;
  readonly cityVersionId: string;
  readonly tariffAt: string;
  readonly express: boolean;
  readonly selections: readonly PricingSelection[];
  readonly adjustments: readonly PricingAdjustment[];
  readonly evidence: readonly PricingEvidence[];
  readonly visibility?: PriceVisibility;
}

export interface PricingSelection {
  readonly lineId: string;
  readonly itemId: string;
  readonly unit: string;
  readonly quantity: string;
}

export interface ReadEffectiveEstimatesInput {
  readonly cityId: string;
  readonly cityVersionId: string;
  readonly categoryId: string;
}

export interface EffectiveEstimate {
  readonly id: string;
  readonly cityId: string;
  /** Immutable city version reviewed with the estimate. */
  readonly cityVersionId: string;
  readonly seriesId: string;
  readonly version: number;
  readonly categoryId: string;
  readonly code: string;
  readonly title: string;
  readonly currency: string;
  readonly minMinor: string;
  readonly maxMinor: string;
  readonly conditions: string | null;
  readonly disclaimer: string;
  readonly sourceRef: string;
  readonly reviewedBy: string;
  readonly publishedAt: string;
  readonly validFrom: string;
  readonly validUntil: string | null;
  readonly effectiveUntil: string | null;
}

export const MAX_RULES = 64;
export const MAX_ESTIMATES = 64;
const MAX_SELECTIONS = 128;
const MAX_MANUAL_RECORDS = 32;
const CITY_KEYS = ['cityId', 'cityVersionId'] as const;
const EVIDENCE_IDS = ['id', 'calculationId', 'adjustmentId', 'cityId', 'policyVersionId', 'ruleVersionId', 'actorId'] as const;

export function invalid(field: string): never {
  throw new PricingError('INVALID_INPUT', field);
}

function dataField(row: object, key: string, field: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(row, key);
  if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
    return invalid(field);
  }
  return descriptor.value;
}

function record(value: unknown, keys: readonly string[], field: string): Map<string, unknown> {
  if (typeof value !== 'object' || value === null || types.isProxy(value)) {
    return invalid(field);
  }
  const proto: unknown = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    return invalid(field);
  }
  const own = Reflect.ownKeys(value);
  if (own.length > keys.length) {
    return invalid(field);
  }
  const copy = new Map<string, unknown>();
  for (const key of own) {
    if (typeof key !== 'string' || !keys.includes(key)) {
      return invalid(field);
    }
    copy.set(key, dataField(value, key, field));
  }
  return copy;
}

function list<T>(value: unknown, min: number, max: number, field: string, parse: (element: unknown) => T): T[] {
  if (types.isProxy(value) || !Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    return invalid(field);
  }
  const length: unknown = Object.getOwnPropertyDescriptor(value, 'length')?.value;
  if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < min || length > max
      || Reflect.ownKeys(value).length !== length + 1) {
    return invalid(field);
  }
  const copy: T[] = [];
  for (let i = 0; i < length; i++) {
    copy.push(parse(dataField(value, String(i), field)));
  }
  return copy;
}

function uuid(value: unknown, field: string, canonical = false): string {
  if (typeof value !== 'string' || value.length !== 36
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(value)) {
    return invalid(field);
  }
  const lowered = value.toLowerCase();
  return canonical && lowered !== value ? invalid(field) : lowered;
}

function city(row: ReadonlyMap<string, unknown>) {
  return { cityId: uuid(row.get('cityId'), 'cityId'), cityVersionId: uuid(row.get('cityVersionId'), 'cityVersionId') };
}

function choice<T extends string>(value: unknown, options: readonly T[], field: string): T {
  return options.find((option) => value === option) ?? invalid(field);
}

function text(value: unknown, max: number, field: string, allowEmpty = false): string {
  if (typeof value !== 'string' || value.length > max * 2 || (!allowEmpty && !value.trim())
      || /[\p{Cc}\p{Cf}\p{Cs}]/u.test(value) || Array.from(value).length > max) {
    return invalid(field);
  }
  return value;
}

function slug(value: unknown, min: number, max: number, field: string): string {
  if (typeof value !== 'string' || value.length < min || value.length > max
      || !/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?![\s\S])/u.test(value)) {
    return invalid(field);
  }
  return value;
}

function instant(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length !== 24 || value.startsWith('0000')
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) {
    return invalid(field);
  }
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value ? value : invalid(field);
}

function minor(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length > 19 || !/^(?:0|[1-9][0-9]*)(?![\s\S])/u.test(value)
      || BigInt(value) > 9223372036854775807n) {
    return invalid(field);
  }
  return value;
}

function currency(value: unknown): string {
  return typeof value === 'string' && value.length === 3 && /^[A-Z]{3}$/u.test(value) ? value : invalid('currency');
}

function selection(value: unknown): PricingSelection {
  const r = record(value, ['lineId', 'itemId', 'unit', 'quantity'], 'selection');
  const quantity = r.get('quantity');
  if (typeof quantity !== 'string' || quantity.length > 19 || quantity === '0'
      || !/^(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{0,5}[1-9])?(?![\s\S])/u.test(quantity)) {
    return invalid('quantity');
  }
  return { lineId: uuid(r.get('lineId'), 'lineId'), itemId: uuid(r.get('itemId'), 'itemId'),
    unit: slug(r.get('unit'), 1, 24, 'unit'), quantity };
}

function adjustment(value: unknown): PricingAdjustment {
  const r = record(value, ['id', 'ruleId', 'reason'], 'adjustment');
  return { id: uuid(r.get('id'), 'adjustmentId'), ruleId: uuid(r.get('ruleId'), 'ruleId'), reason: text(r.get('reason'), 200, 'reason') };
}

function evidenceRecord(value: unknown): PricingEvidence {
  const r = record(value, [...EVIDENCE_IDS, 'currency', 'baseMinor', 'appliedMinor', 'decision', 'reason'], 'evidence');
  const id = (key: (typeof EVIDENCE_IDS)[number]) => uuid(r.get(key), 'evidence', true);
  return { id: id('id'), calculationId: id('calculationId'), adjustmentId: id('adjustmentId'), cityId: id('cityId'),
    policyVersionId: id('policyVersionId'), ruleVersionId: id('ruleVersionId'), actorId: id('actorId'),
    currency: currency(r.get('currency')), baseMinor: minor(r.get('baseMinor'), 'baseMinor'),
    appliedMinor: minor(r.get('appliedMinor'), 'appliedMinor'), reason: text(r.get('reason'), 200, 'reason'),
    decision: choice(r.get('decision'), ['WITHIN_LIMIT', 'OVER_LIMIT_APPROVED'], 'decision') };
}

/** Bounded copies contain only owned primitive values before the first await. */
export function pricingRequest(value: unknown) {
  const r = record(value, [...CITY_KEYS, 'calculationId', 'tariffAt', 'express', 'selections', 'adjustments', 'evidence', 'visibility'], 'input');
  const express = r.get('express');
  if (typeof express !== 'boolean') {
    return invalid('express');
  }
  const selections = list(r.get('selections'), 1, MAX_SELECTIONS, 'selections', selection);
  if (new Set(selections.map(({ lineId }) => lineId)).size !== selections.length) {
    return invalid('lineId');
  }
  const visibility = r.get('visibility');
  return { ...city(r), calculationId: uuid(r.get('calculationId'), 'calculationId'), express,
    tariffAt: instant(r.get('tariffAt'), 'tariffAt'), selections,
    adjustments: list(r.get('adjustments'), 0, MAX_MANUAL_RECORDS, 'adjustments', adjustment),
    evidence: list(r.get('evidence'), 0, MAX_MANUAL_RECORDS, 'evidence', evidenceRecord),
    visibility: visibility === undefined ? null : choice(visibility, ['TECHNICIAN', 'PUBLIC'], 'visibility') };
}

export function estimateRequest(value: unknown): ReadEffectiveEstimatesInput {
  const r = record(value, [...CITY_KEYS, 'categoryId'], 'input');
  return { ...city(r), categoryId: uuid(r.get('categoryId'), 'categoryId') };
}

export function estimateResult(value: unknown, input: ReadEffectiveEstimatesInput, pricingAt: string): EffectiveEstimate {
  const r = record(value, ['id', 'cityId', 'cityVersionId', 'seriesId', 'version', 'categoryId', 'code', 'title', 'currency',
    'minMinor', 'maxMinor', 'conditions', 'disclaimer', 'sourceRef', 'reviewedBy', 'publishedAt', 'validFrom', 'validUntil', 'effectiveUntil'], 'estimate');
  const { cityId, cityVersionId } = city(r);
  const categoryId = uuid(r.get('categoryId'), 'categoryId');
  const version = r.get('version');
  if (cityId !== input.cityId || categoryId !== input.categoryId || typeof version !== 'number'
      || !Number.isInteger(version) || version < 1 || version > 2147483647) {
    return invalid('estimate');
  }
  const minMinor = minor(r.get('minMinor'), 'minMinor');
  const maxMinor = minor(r.get('maxMinor'), 'maxMinor');
  const validFrom = instant(r.get('validFrom'), 'validFrom');
  const validUntil = r.get('validUntil') === null ? null : instant(r.get('validUntil'), 'validUntil');
  const effectiveUntil = r.get('effectiveUntil') === null ? null : instant(r.get('effectiveUntil'), 'effectiveUntil');
  if (BigInt(minMinor) > BigInt(maxMinor) || pricingAt < validFrom || (effectiveUntil !== null && effectiveUntil <= pricingAt)
      || (validUntil !== null && (effectiveUntil === null || effectiveUntil > validUntil))) {
    return invalid('estimate');
  }
  const conditions = r.get('conditions');
  return Object.freeze({ id: uuid(r.get('id'), 'estimateId'), seriesId: uuid(r.get('seriesId'), 'seriesId'),
    version, cityId, cityVersionId, categoryId, code: slug(r.get('code'), 2, 64, 'code'),
    title: text(r.get('title'), 160, 'title'), currency: currency(r.get('currency')), minMinor, maxMinor,
    conditions: conditions === null ? null : text(conditions, 1000, 'conditions', true),
    disclaimer: text(r.get('disclaimer'), 500, 'disclaimer'), sourceRef: text(r.get('sourceRef'), 200, 'sourceRef'),
    reviewedBy: uuid(r.get('reviewedBy'), 'reviewedBy'), publishedAt: instant(r.get('publishedAt'), 'publishedAt'),
    validFrom, validUntil, effectiveUntil });
}

// Private SQL expressions only. The fixed function expression matches the GiST
// exclusion keys (city[, item/series], range); do not replace with a time scan.
export const effectiveEnd = (period: string): string => `coalesce(${period}.closed_effective_until,${period}.scheduled_until)`;
export const containsAt = (period: string, time: string): string =>
  `pg_catalog.tstzrange(${period}.valid_from,${effectiveEnd(period)},'[)') @> ${time}`;
const wallAt = (timestamp: string, format: string): string => `pg_catalog.to_char(${timestamp}, '${format}')`;
const WALL = 'YYYY-MM-DD"T"HH24:MI:SS.MS';
export const wall = (timestamp: string): string => wallAt(timestamp, WALL);
export const utc = (timestamp: string): string => wallAt(`${timestamp} AT TIME ZONE 'UTC'`, `${WALL}"Z"`);

/** Both readers bind marker, exact city ID and exact current city version as $1–3. */
export const SNAPSHOT_CTES = `tx AS MATERIALIZED (
  SELECT pg_catalog.current_setting('${READ_TX_SETTING}', true) = $1 AS caller_tx,
    pg_catalog.current_setting('transaction_isolation') = 'read committed' AS read_committed
), clock AS MATERIALIZED (
  SELECT pg_catalog.date_trunc('milliseconds',pg_catalog.clock_timestamp(),'UTC') AS pricing_at
  FROM tx WHERE caller_tx IS TRUE AND read_committed
), city AS MATERIALIZED (
  SELECT c.id AS city_id, cv.id AS city_version_id, cv.timezone, clock.pricing_at
  FROM clock JOIN foundation.service_cities AS c ON c.id=$2 AND c.lifecycle='ACTIVE'
  JOIN foundation.service_city_versions AS cv ON (cv.city_id,cv.id)=(c.id,c.current_version_id) AND cv.id=$3
)`;
export const SNAPSHOT_STATUS = `CASE WHEN tx.caller_tx IS NOT TRUE THEN 'TRANSACTION_REQUIRED'
  WHEN NOT tx.read_committed THEN 'ISOLATION_REQUIRED' WHEN city.city_id IS NULL THEN 'CITY_CONFLICT' ELSE 'OK' END`;

export async function queryAfterFence<Row extends { status: string }>(
  client: CatalogClient, sql: string, args: readonly (string | boolean | null)[],
): Promise<Row> {
  const marker = await fenceRead(client);
  let rows: Row[];
  try {
    ({ rows } = await client.query<Row>(sql, [marker, ...args]));
  } catch {
    throw new CatalogInternalError();
  }
  const row = rows[0];
  if (!row || rows.length !== 1) {
    throw new CatalogInternalError();
  }
  switch (row.status) {
    case 'TRANSACTION_REQUIRED': throw new CatalogError('TRANSACTION_REQUIRED');
    case 'ISOLATION_REQUIRED': throw new CatalogError('ISOLATION_REQUIRED');
    case 'CITY_CONFLICT': return invalid('cityVersionId');
    case 'OK': return row;
    default: throw new CatalogInternalError();
  }
}
