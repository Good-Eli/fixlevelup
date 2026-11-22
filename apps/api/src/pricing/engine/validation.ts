import { types } from 'node:util';
import { PricingError } from './contracts.js';
import type {
  PricingAdjustment, PricingCompatibility, PricingContext, PricingErrorCode, PricingEvidence,
  PricingFixedPrice, PricingInput, PricingItem, PricingPolicy, PricingPriority, PricingRule,
} from './contracts.js';

export const BIGINT_MAX = 9223372036854775807n;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const TIMEZONE = /^[A-Za-z][A-Za-z0-9_+-]*(?:\/[A-Za-z0-9_+-]+)+$/u;
const UTC_INSTANT = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const SOURCE = ['id', 'cityId', 'cityVersionId', 'validFrom', 'effectiveUntil'] as const;
const ITEM_KINDS = ['TRAVEL', 'DIAGNOSTICS', 'WORK', 'MATERIAL', 'PART'] as const;
const RULE_KINDS = ['EVENING', 'NIGHT', 'EXPRESS', 'SURCHARGE', 'DISCOUNT'] as const;
const RULE_BASES = ['WORKS', 'WORKS_AND_PARTS', 'ORDER_BASE'] as const;

export function fail(code: PricingErrorCode, field?: string): never {
  throw new PricingError(code, field);
}

function invalid(field: string): never {
  return fail('INVALID_INPUT', field);
}

export function unauthorized(field: string): never {
  return fail('ADJUSTMENT_NOT_AUTHORIZED', field);
}

// All record fields must be own enumerable data fields. In particular, neither
// an accessor nor an inherited property can make up a missing required field.
function record(value: unknown, keys: readonly string[], field: string): Record<string, unknown> {
  const descriptors = plainDescriptors(value, keys.length, field);
  const copy: Record<string, unknown> = {};
  if (descriptors.size !== keys.length) { invalid(field); }
  for (const key of keys) {
    if (!descriptors.has(key)) { invalid(field); }
    copy[key] = descriptors.get(key);
  }
  return copy;
}

function plainDescriptors(value: unknown, max: number, field: string): Map<string, unknown> {
  if (typeof value !== 'object' || value === null || types.isProxy(value)) { return invalid(field); }
  const proto: unknown = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) { return invalid(field); }
  const keys = Reflect.ownKeys(value);
  if (keys.length > max) { return invalid(field); }
  const result = new Map<string, unknown>();
  for (const key of keys) {
    if (typeof key !== 'string') { return invalid(field); }
    result.set(key, dataValue(value, key, field));
  }
  return result;
}

function dataValue(value: object, key: string, field: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) { return invalid(field); }
  return descriptor.value;
}

function list(value: unknown, min: number, max: number, field: string): unknown[] {
  if (types.isProxy(value) || !Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) { return invalid(field); }
  const descriptor = Object.getOwnPropertyDescriptor(value, 'length');
  const length = integer(descriptor?.value, min, max, field);
  if (Reflect.ownKeys(value).length !== length + 1) { return invalid(field); }
  const copy: unknown[] = [];
  for (let i = 0; i < length; i++) { copy.push(dataValue(value, String(i), field)); }
  return copy;
}

// All sorted keys are validated ASCII; no locale dependence or sorting to
// decide between candidate rules of equal priority.
export function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function distinct(values: readonly string[], code: PricingErrorCode, field: string): void {
  if (new Set(values).size !== values.length) { fail(code, field); }
}

export function pairKey(first: string, second: string): string {
  return first < second ? `${first}/${second}` : `${second}/${first}`;
}

function id(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length !== 36 || !UUID.test(value)) { return invalid(field); }
  return value.toLowerCase();
}

// Evidence is compared literally against normalized IDs, not case-folded or
// remapped to make an otherwise non-matching trusted claim pass.
function evidenceId(value: unknown, field: string): string {
  if (typeof value !== 'string' || id(value, field) !== value) { return invalid(field); }
  return value;
}

function text(value: unknown, max: number, field: string): string {
  if (typeof value !== 'string' || value.length > max * 2 || !value.trim()
      || /[\p{Cc}\p{Cf}\p{Cs}]/u.test(value) || Array.from(value).length > max) { return invalid(field); }
  return value;
}

function unit(value: unknown): string {
  if (typeof value !== 'string' || value.length > 24 || !/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?![\s\S])/u.test(value)) {
    return invalid('unit');
  }
  return value;
}

function currency(value: unknown): string {
  if (typeof value !== 'string' || value.length !== 3 || !/^[A-Z]{3}$/u.test(value)) { return invalid('currency'); }
  return value;
}

function integer(value: unknown, min: number, max: number, field: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || Object.is(value, -0) || value < min || value > max) {
    return invalid(field);
  }
  return value;
}

function flag(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') { return invalid(field); }
  return value;
}

function choice<T extends string>(value: unknown, allowed: readonly T[], field: string): T {
  return allowed.find((option) => value === option) ?? invalid(field);
}

function minor(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length > 19 || !/^(?:0|[1-9][0-9]*)(?![\s\S])/u.test(value)
      || BigInt(value) > BIGINT_MAX) { return invalid(field); }
  return value;
}

function optionalMinor(value: unknown, field: string): string | null {
  return value === null ? null : minor(value, field);
}

function instant(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length !== 24 || value.startsWith('0000') || !UTC_INSTANT.test(value)) {
    return invalid(field);
  }
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) { return invalid(field); }
  return value;
}

function context(value: unknown): PricingContext {
  const r = record(value, ['calculationId', 'cityId', 'cityVersionId', 'timezone', 'pricingAt', 'tariffAt', 'localAt', 'utcOffsetSeconds', 'express'], 'context');
  const { timezone, localAt } = r;
  if (typeof timezone !== 'string' || timezone.length > 64 || /[^A-Za-z0-9_+/-]/u.test(timezone)
      || (timezone !== 'UTC' && (!TIMEZONE.test(timezone) || /^(?:posix|right|SystemV)\//u.test(timezone)))) {
    return invalid('timezone');
  }
  const tariffAt = instant(r['tariffAt'], 'tariffAt');
  const utcOffsetSeconds = integer(r['utcOffsetSeconds'], -64800, 64800, 'utcOffsetSeconds');
  const wall = new Date(Date.parse(tariffAt) + utcOffsetSeconds * 1000).toISOString();
  // Arithmetic only. The trusted city source, not engine tzdata, owns the offset.
  if (wall.length !== 24 || wall.startsWith('0000') || localAt !== wall.slice(0, -1)) { return invalid('localAt'); }
  return Object.freeze({
    calculationId: id(r['calculationId'], 'calculationId'), cityId: id(r['cityId'], 'cityId'),
    cityVersionId: id(r['cityVersionId'], 'cityVersionId'), timezone, pricingAt: instant(r['pricingAt'], 'pricingAt'),
    tariffAt, localAt, utcOffsetSeconds, express: flag(r['express'], 'express'),
  });
}

function source(r: Record<string, unknown>, ctx: PricingContext, field: string) {
  const cityId = id(r['cityId'], field);
  if (cityId !== ctx.cityId) { invalid(field); }
  const validFrom = instant(r['validFrom'], 'validFrom');
  const effectiveUntil = r['effectiveUntil'] === null ? null : instant(r['effectiveUntil'], 'effectiveUntil');
  if (effectiveUntil !== null && validFrom >= effectiveUntil) { invalid(field); }
  if (ctx.pricingAt < validFrom || (effectiveUntil !== null && ctx.pricingAt >= effectiveUntil)) {
    fail(field === 'policy' ? 'PRICING_NOT_CONFIGURED' : field === 'price' ? 'PRICE_NOT_CONFIGURED' : 'INVALID_INPUT', field);
  }
  return { id: id(r['id'], field), cityId, cityVersionId: id(r['cityVersionId'], field), validFrom, effectiveUntil };
}

function policy(value: unknown, ctx: PricingContext): PricingPolicy {
  if (value === null) { fail('PRICING_NOT_CONFIGURED', 'policy'); }
  const r = record(value, [...SOURCE, 'currency', 'taxDisplay', 'roundingMode', 'units', 'maxManualDeltaMinor', 'priorities', 'compatibilities'], 'policy');
  const units = plainDescriptors(r['units'], 32, 'units');
  if (units.size === 0) { invalid('units'); }
  const scales = Object.fromEntries([...units.keys()].sort(compare).map((key) => [unit(key), integer(units.get(key), 0, 6, 'units')]));
  const priorities = list(r['priorities'], 0, 64, 'priorities').map((p): PricingPriority => {
    const row = record(p, ['ruleId', 'priority'], 'priority');
    return Object.freeze({ ruleId: id(row['ruleId'], 'priority'), priority: integer(row['priority'], 0, 1000000, 'priority') });
  }).sort((a, b) => compare(a.ruleId, b.ruleId));
  distinct(priorities.map((p) => p.ruleId), 'PRICING_CONFIGURATION_AMBIGUOUS', 'priorities');
  const compatibilities = list(r['compatibilities'], 0, 128, 'compatibilities').map((p): PricingCompatibility => {
    const row = record(p, ['leftRuleId', 'rightRuleId'], 'compatibility');
    const left = id(row['leftRuleId'], 'compatibility');
    const right = id(row['rightRuleId'], 'compatibility');
    if (left === right) { invalid('compatibility'); }
    return Object.freeze({ leftRuleId: left < right ? left : right, rightRuleId: left < right ? right : left });
  }).sort((a, b) => compare(a.leftRuleId, b.leftRuleId) || compare(a.rightRuleId, b.rightRuleId));
  distinct(compatibilities.map((p) => pairKey(p.leftRuleId, p.rightRuleId)), 'INVALID_INPUT', 'compatibilities');
  return Object.freeze({
    ...source(r, ctx, 'policy'), currency: currency(r['currency']), taxDisplay: text(r['taxDisplay'], 200, 'taxDisplay'),
    roundingMode: choice(r['roundingMode'], ['HALF_UP', 'DOWN'], 'roundingMode'), units: Object.freeze(scales),
    maxManualDeltaMinor: minor(r['maxManualDeltaMinor'], 'maxManualDeltaMinor'),
    priorities: Object.freeze(priorities), compatibilities: Object.freeze(compatibilities),
  });
}

function fixedPrice(value: unknown, ctx: PricingContext, p: PricingPolicy, itemId: string): PricingFixedPrice {
  if (value === null) { fail('PRICE_NOT_CONFIGURED', 'price'); }
  const r = record(value, [...SOURCE, 'itemId', 'itemVersionId', 'amountMinor', 'currency', 'zeroBasis'], 'price');
  const amountMinor = minor(r['amountMinor'], 'amountMinor');
  const zeroBasis = r['zeroBasis'] === null ? null : text(r['zeroBasis'], 200, 'zeroBasis');
  const code = currency(r['currency']);
  if ((amountMinor === '0') !== (zeroBasis !== null)) { invalid('zeroBasis'); }
  if (id(r['itemId'], 'priceItemId') !== itemId || code !== p.currency) { invalid('price'); }
  return Object.freeze({ ...source(r, ctx, 'price'), itemId,
    itemVersionId: id(r['itemVersionId'], 'priceItemVersionId'), amountMinor, currency: code, zeroBasis });
}

function item(value: unknown, ctx: PricingContext, p: PricingPolicy): PricingItem {
  const r = record(value, ['lineId', 'itemId', 'itemVersionId', 'kind', 'categoryId', 'unit', 'title', 'quantity', 'price'], 'item');
  const u = unit(r['unit']);
  const scale = Object.hasOwn(p.units, u) ? p.units[u] : undefined;
  const quantity = r['quantity'];
  if (scale === undefined || typeof quantity !== 'string' || quantity.length > 19 || quantity === '0'
      || !/^(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{0,5}[1-9])?(?![\s\S])/u.test(quantity)
      || (quantity.includes('.') && quantity.length - quantity.indexOf('.') - 1 > scale)) { invalid('quantity'); }
  const kind = choice(r['kind'], ITEM_KINDS, 'itemKind');
  const categoryId = r['categoryId'] === null ? null : id(r['categoryId'], 'categoryId');
  if (kind === 'WORK' && categoryId === null) { invalid('categoryId'); }
  const itemId = id(r['itemId'], 'itemId');
  return Object.freeze({
    lineId: id(r['lineId'], 'lineId'), itemId, itemVersionId: id(r['itemVersionId'], 'itemVersionId'),
    kind, categoryId, unit: u, title: text(r['title'], 160, 'itemTitle'), quantity, price: fixedPrice(r['price'], ctx, p, itemId),
  });
}

function windowFields(r: Record<string, unknown>, temporal: boolean) {
  if (!temporal) {
    if (r['startMinute'] !== null || r['endMinute'] !== null || r['wrapsMidnight'] !== null) { invalid('window'); }
    return { startMinute: null, endMinute: null, wrapsMidnight: null };
  }
  const startMinute = integer(r['startMinute'], 0, 1439, 'startMinute');
  const endMinute = integer(r['endMinute'], 0, 1439, 'endMinute');
  const wrapsMidnight = flag(r['wrapsMidnight'], 'wrapsMidnight');
  if (startMinute === endMinute || wrapsMidnight !== (startMinute > endMinute)) { invalid('window'); }
  return { startMinute, endMinute, wrapsMidnight };
}

function rule(value: unknown, ctx: PricingContext, p: PricingPolicy): PricingRule {
  const r = record(value, [...SOURCE, 'ruleId', 'kind', 'title', 'currency', 'method', 'base', 'fixedMinor', 'rateBps', 'minBase', 'maxBase', 'minDelta', 'maxDelta', 'startMinute', 'endMinute', 'wrapsMidnight', 'categoryIds'], 'rule');
  const code = currency(r['currency']);
  if (code !== p.currency) { invalid('ruleCurrency'); }
  const kind = choice(r['kind'], RULE_KINDS, 'ruleKind');
  const method = choice(r['method'], ['FIXED', 'RATE'], 'method');
  const fixedMinor = optionalMinor(r['fixedMinor'], 'fixedMinor');
  const rateBps = r['rateBps'] === null ? null : integer(r['rateBps'], 1, 10000, 'rateBps');
  if (method === 'FIXED' ? fixedMinor === null || rateBps !== null : rateBps === null || fixedMinor !== null) { invalid('method'); }
  const minBase = optionalMinor(r['minBase'], 'minBase');
  const maxBase = optionalMinor(r['maxBase'], 'maxBase');
  const minDelta = optionalMinor(r['minDelta'], 'minDelta');
  const maxDelta = optionalMinor(r['maxDelta'], 'maxDelta');
  if ((minBase !== null && maxBase !== null && BigInt(minBase) > BigInt(maxBase))
      || (minDelta !== null && maxDelta !== null && BigInt(minDelta) > BigInt(maxDelta))) { invalid('ruleBounds'); }
  const categoryIds = list(r['categoryIds'], 0, 32, 'categoryIds').map((v) => id(v, 'categoryId')).sort(compare);
  distinct(categoryIds, 'INVALID_INPUT', 'categoryIds');
  return Object.freeze({
    ...source(r, ctx, 'rule'), ruleId: id(r['ruleId'], 'ruleId'), kind, title: text(r['title'], 160, 'ruleTitle'), currency: code, method,
    base: choice(r['base'], RULE_BASES, 'ruleBase'), fixedMinor, rateBps, minBase, maxBase, minDelta, maxDelta,
    ...windowFields(r, kind === 'EVENING' || kind === 'NIGHT'), categoryIds: Object.freeze(categoryIds),
  });
}

function adjustment(value: unknown): PricingAdjustment {
  const r = record(value, ['id', 'ruleId', 'reason'], 'adjustment');
  return Object.freeze({ id: id(r['id'], 'adjustmentId'), ruleId: id(r['ruleId'], 'ruleId'), reason: text(r['reason'], 200, 'reason') });
}

function evidence(value: unknown): PricingEvidence {
  const r = record(value, ['id', 'calculationId', 'adjustmentId', 'cityId', 'policyVersionId', 'ruleVersionId', 'currency', 'baseMinor', 'appliedMinor', 'decision', 'actorId', 'reason'], 'evidence');
  return Object.freeze({
    id: evidenceId(r['id'], 'evidenceId'), calculationId: evidenceId(r['calculationId'], 'calculationId'),
    adjustmentId: evidenceId(r['adjustmentId'], 'adjustmentId'), cityId: evidenceId(r['cityId'], 'cityId'),
    policyVersionId: evidenceId(r['policyVersionId'], 'policyVersionId'), ruleVersionId: evidenceId(r['ruleVersionId'], 'ruleVersionId'),
    currency: currency(r['currency']), baseMinor: minor(r['baseMinor'], 'baseMinor'), appliedMinor: minor(r['appliedMinor'], 'appliedMinor'),
    decision: choice(r['decision'], ['WITHIN_LIMIT', 'OVER_LIMIT_APPROVED'], 'decision'), actorId: evidenceId(r['actorId'], 'actorId'),
    reason: text(r['reason'], 200, 'reason'),
  });
}

function validateItemSources(items: readonly PricingItem[]): void {
  const byItem = new Map<string, PricingItem>();
  const priceOwners = new Map<string, string>();
  const revisionOwners = new Map<string, string>();
  function owned(map: Map<string, string>, revision: string, owner: string) {
    const known = map.get(revision);
    if (known !== undefined && known !== owner) { invalid('itemSource'); }
    map.set(revision, owner);
  }
  // Repeated SKU selections are allowed; their one-statement sources must agree.
  for (const row of items) {
    owned(priceOwners, row.price.id, row.itemId);
    owned(revisionOwners, row.itemVersionId, row.itemId);
    owned(revisionOwners, row.price.itemVersionId, row.itemId);
    const previous = byItem.get(row.itemId);
    if (previous !== undefined) {
      const a = previous.price;
      const b = row.price;
      if (a.id !== b.id) { fail('PRICING_CONFIGURATION_AMBIGUOUS', 'price'); }
      if (previous.itemVersionId !== row.itemVersionId || previous.kind !== row.kind || previous.title !== row.title
          || previous.categoryId !== row.categoryId || previous.unit !== row.unit || a.cityVersionId !== b.cityVersionId
          || a.itemVersionId !== b.itemVersionId || a.amountMinor !== b.amountMinor || a.zeroBasis !== b.zeroBasis
          || a.validFrom !== b.validFrom || a.effectiveUntil !== b.effectiveUntil) { invalid('itemSource'); }
    } else {
      byItem.set(row.itemId, row);
    }
  }
}

export function normalizePricingInput(value: unknown): PricingInput {
  const r = record(value, ['context', 'policy', 'items', 'rules', 'adjustments', 'evidence'], 'input');
  const ctx = context(r['context']);
  const p = policy(r['policy'], ctx);
  const rules = list(r['rules'], 0, 64, 'rules').map((v) => rule(v, ctx, p)).sort((a, b) => compare(a.ruleId, b.ruleId));
  distinct(rules.map((v) => v.ruleId), 'PRICING_CONFIGURATION_AMBIGUOUS', 'ruleId');
  distinct(rules.map((v) => v.id), 'PRICING_CONFIGURATION_AMBIGUOUS', 'ruleVersionId');
  const items = list(r['items'], 1, 128, 'items').map((v) => item(v, ctx, p)).sort((a, b) => compare(a.lineId, b.lineId));
  distinct(items.map((v) => v.lineId), 'INVALID_INPUT', 'lineId');
  validateItemSources(items);
  const adjustments = list(r['adjustments'], 0, 32, 'adjustments').map(adjustment).sort((a, b) => compare(a.id, b.id));
  const records = list(r['evidence'], 0, 32, 'evidence').map(evidence).sort((a, b) => compare(a.id, b.id));
  distinct(adjustments.map((v) => v.id), 'ADJUSTMENT_NOT_AUTHORIZED', 'adjustmentId');
  distinct(adjustments.map((v) => v.ruleId), 'ADJUSTMENT_NOT_AUTHORIZED', 'manualRuleId');
  distinct(records.map((v) => v.id), 'ADJUSTMENT_NOT_AUTHORIZED', 'evidenceId');
  distinct(records.map((v) => v.adjustmentId), 'ADJUSTMENT_NOT_AUTHORIZED', 'evidenceAdjustmentId');
  return Object.freeze({ context: ctx, policy: p, items: Object.freeze(items), rules: Object.freeze(rules),
    adjustments: Object.freeze(adjustments), evidence: Object.freeze(records) });
}
