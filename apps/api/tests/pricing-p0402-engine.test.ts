import { describe, expect, it } from 'vitest';
import { calculatePricing, normalizePricingInput, PricingError } from '../src/pricing/engine/index.js';
import type {
  PricingContext, PricingErrorCode, PricingEvidence, PricingInput, PricingItem, PricingItemKind, PricingPolicy, PricingRule, PricingRuleKind,
} from '../src/pricing/engine/index.js';

const uuid = (n: number) => `11000000-0000-0000-0000-${n.toString(16).padStart(12, '0')}`;
const CITY = uuid(1);
const CURRENT_CITY = uuid(2);
const OLD_CITY = uuid(3);
const CAT = uuid(4);
const OTHER_CAT = uuid(5);
const RUB = 'RUB';
const MAX = '9223372036854775807';
const WHEN = '2026-11-22T12:00:00.000Z';
const SOURCE = { cityId: CITY, cityVersionId: OLD_CITY, validFrom: WHEN, effectiveUntil: null };
const CONTEXT: PricingContext = {
  calculationId: uuid(6), cityId: CITY, cityVersionId: CURRENT_CITY, timezone: 'Europe/Moscow', pricingAt: WHEN,
  tariffAt: '2026-11-22T19:30:27.123Z', localAt: '2026-11-22T23:30:27.123', utcOffsetSeconds: 14400, express: true,
};
const POLICY: PricingPolicy = {
  ...SOURCE, id: uuid(7), currency: RUB, taxDisplay: 'Synthetic (tax not calculated)', roundingMode: 'HALF_UP',
  units: { hour: 6, piece: 0 }, maxManualDeltaMinor: '8', priorities: [], compatibilities: [],
};

function item(n: number, kind: PricingItemKind, amount: string, quantity = '1', categoryId: string | null = kind === 'WORK' ? CAT : null): PricingItem {
  return {
    lineId: uuid(n), itemId: uuid(100 + n), itemVersionId: uuid(200 + n), categoryId, kind,
    title: `Current title ${n.toString()}`, unit: quantity.includes('.') ? 'hour' : 'piece', quantity,
    price: { ...SOURCE, id: uuid(300 + n), itemId: uuid(100 + n), itemVersionId: uuid(400 + n), amountMinor: amount,
      currency: RUB, zeroBasis: amount === '0' ? 'Explicit no charge' : null },
  };
}

function rule(n: number, kind: PricingRuleKind, fields: Partial<PricingRule> = {}): PricingRule {
  const window = kind === 'EVENING' ? { startMinute: 1080, endMinute: 1439, wrapsMidnight: false }
    : kind === 'NIGHT' ? { startMinute: 1320, endMinute: 360, wrapsMidnight: true }
      : { startMinute: null, endMinute: null, wrapsMidnight: null };
  return {
    ...SOURCE, ...window, id: uuid(n + 600), ruleId: uuid(n + 500), currency: RUB, kind, title: `Rule ${n.toString()}`, method: 'FIXED', base: 'WORKS',
    fixedMinor: '10', rateBps: null, minBase: null, maxBase: null, minDelta: null, maxDelta: null, categoryIds: [], ...fields,
  };
}

function fixture(fields: Partial<PricingInput> = {}): PricingInput {
  return { context: CONTEXT, policy: POLICY, items: [item(10, 'WORK', '101')], rules: [], adjustments: [], evidence: [], ...fields };
}

function withPriorities(rules: readonly PricingRule[]): PricingPolicy {
  return { ...POLICY, priorities: rules.map((r, i) => ({ ruleId: r.ruleId, priority: i })) };
}

function manual(r: PricingRule, baseMinor: string, appliedMinor: string, policy = POLICY, id = 800) {
  const adjustment = { id: uuid(id), ruleId: r.ruleId, reason: 'Trusted synthetic review' };
  const evidence: PricingEvidence = {
    id: uuid(id + 100), calculationId: CONTEXT.calculationId, adjustmentId: adjustment.id, cityId: CITY,
    policyVersionId: policy.id, ruleVersionId: r.id, currency: RUB, baseMinor, appliedMinor, actorId: uuid(8),
    reason: adjustment.reason, decision: BigInt(appliedMinor) > BigInt(policy.maxManualDeltaMinor) ? 'OVER_LIMIT_APPROVED' : 'WITHIN_LIMIT',
  };
  return { adjustment, evidence };
}

function denied(input: unknown, code: PricingErrorCode = 'INVALID_INPUT') {
  expect(() => calculatePricing(input)).toThrow(expect.objectContaining({ code }));
  expect(() => calculatePricing(input)).toThrow(PricingError);
}

function golden(): PricingInput {
  const rules = [rule(0, 'EVENING'), rule(1, 'NIGHT', { method: 'RATE', fixedMinor: null, rateBps: 1000, minBase: '137', maxBase: '137', minDelta: '16' }),
    rule(2, 'EXPRESS', { base: 'WORKS_AND_PARTS', fixedMinor: '30', maxDelta: '25' }),
    rule(3, 'SURCHARGE', { maxDelta: '8' }),
    rule(4, 'DISCOUNT', { method: 'RATE', fixedMinor: null, rateBps: 500, base: 'ORDER_BASE', categoryIds: [OTHER_CAT, CAT], maxDelta: '30' })];
  const [evening, night, express, surcharge, discount] = rules as [PricingRule, PricingRule, PricingRule, PricingRule, PricingRule];
  const applied = [night, express, surcharge, discount];
  const policy = { ...withPriorities([evening, night, express]), compatibilities: applied.flatMap((left, i) =>
    applied.slice(i + 1).map((right) => ({ leftRuleId: left.ruleId, rightRuleId: right.ruleId }))) };
  const extra = manual(surcharge, '137', '8', policy);
  const reduction = manual(discount, '724', '30', policy, 801);
  return fixture({ policy, rules, items: [item(10, 'TRAVEL', '250'), item(11, 'DIAGNOSTICS', '125'), item(12, 'WORK', '101', '1.25'),
    item(13, 'MATERIAL', '21', '0.5'), item(14, 'PART', '299', '2', CAT)],
  adjustments: [extra.adjustment, reduction.adjustment], evidence: [extra.evidence, reduction.evidence] });
}

function shuffle<T>(values: readonly T[], seed: number): T[] {
  const copy = [...values];
  for (let i = copy.length - 1; i > 0; i--) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const j = seed % (i + 1);
    const a = copy[i];
    const b = copy[j];
    if (a === undefined || b === undefined) { throw new Error('fixture contains a hole'); }
    copy[i] = b;
    copy[j] = a;
  }
  return copy;
}

function only<T>(values: readonly T[]): T {
  if (values[0] === undefined) { throw new Error('empty fixture'); }
  return values[0];
}

describe('P04-02 pricing engine (pure, without PostgreSQL)', () => {
  it('matches the eight-component golden vector and traces price and rule provenance separately', () => {
    const result = calculatePricing(golden());
    expect(result.totalMinor).toBe('1129');
    expect(result.breakdown).toEqual({ travel: '250', diagnostics: '125', works: '137', parts: '598', timeSurcharge: '16',
      expressSurcharge: '25', approvedSurcharges: '8', approvedDiscounts: '30' });
    expect(result.lines[2]).toMatchObject({ source: 'ITEM', ordinal: 3, key: `item:${uuid(12)}`, itemVersionId: uuid(212),
      priceVersionId: uuid(312), priceReviewedItemVersionId: uuid(412), unitPriceMinor: '101', zeroBasis: null,
      rawNumerator: '12625', denominator: '100', roundedMinor: '126', appliedMinor: '126' });
    expect(result.lines[5]).toMatchObject({ source: 'RULE', ordinal: 6, key: `rule:${uuid(501)}`, ruleVersionId: uuid(601),
      baseMinor: '137', matchingLineIds: [uuid(12), uuid(13)], rawNumerator: '137000', denominator: '10000',
      roundedMinor: '14', cappedMinor: '16', appliedMinor: '16', evidenceId: null });
    expect(result.lines[8]).toMatchObject({ source: 'RULE', baseMinor: '724', matchingLineIds: [uuid(12), uuid(14)],
      roundedMinor: '36', cappedMinor: '30', evidenceId: uuid(901), adjustmentId: uuid(801), reason: 'Trusted synthetic review' });
  });

  it('normalizes inputs without aliasing, deeply freezes the output and preserves exact replay under permutations', () => {
    const value = golden();
    const frozen = calculatePricing(value);
    expect(normalizePricingInput(frozen.input)).toStrictEqual(frozen.input);
    expect(frozen.input).not.toBe(value);
    expect(frozen.input.items[0]?.price).not.toBe(value.items[0]?.price);
    function assertFrozen(node: unknown) {
      if (node !== null && typeof node === 'object') {
        expect(Object.isFrozen(node)).toBe(true);
        for (const child of Object.values(node) as unknown[]) { assertFrozen(child); }
      }
    }
    assertFrozen(frozen);
    for (let seed = 1; seed <= 32; seed++) {
      const shuffled = calculatePricing({ ...value, items: shuffle(value.items, seed),
        rules: shuffle(value.rules, seed + 1).map((r) => ({ ...r, categoryIds: shuffle(r.categoryIds, seed) })),
        adjustments: shuffle(value.adjustments, seed + 2), evidence: shuffle(value.evidence, seed + 3),
        policy: { ...value.policy, units: { piece: 0, hour: 6 }, priorities: shuffle(value.policy.priorities, seed + 4),
          compatibilities: shuffle(value.policy.compatibilities, seed + 5).map((p) => ({ leftRuleId: p.rightRuleId, rightRuleId: p.leftRuleId })) },
      });
      expect(shuffled).toStrictEqual(frozen);
      expect(JSON.stringify(shuffled)).toBe(JSON.stringify(frozen));
    }
    Reflect.set(value.context, 'timezone', 'Pacific/Apia');
    try { expect(frozen.input.context.timezone).toBe('Europe/Moscow'); }
    finally { Reflect.set(value.context, 'timezone', 'Europe/Moscow'); }
  });

  it('uses exact rational HALF_UP and DOWN, with base from rounded lines, across generated vectors', () => {
    for (const roundingMode of ['HALF_UP', 'DOWN'] as const) {
      const express = rule(1, 'EXPRESS', { method: 'RATE', fixedMinor: null, rateBps: 2550 });
      const policy = { ...withPriorities([express]), roundingMode };
      for (let n = 1; n <= 128; n++) {
        const unitMinor = (n * 37) % 2000;
        const q = (n * 17) % 99 + 1;
        const quantity = `0.${q.toString().padStart(2, '0').replace(/0$/u, '')}`;
        const result = calculatePricing(fixture({ policy, rules: [express], items: [item(10, 'WORK', unitMinor.toString(), quantity)] }));
        // Small-integer oracle: integer biases and divisors are exactly representable here.
        const expectedWorks = Math.floor((unitMinor * q + (roundingMode === 'HALF_UP' ? 50 : 0)) / 100);
        const expectedExpress = Math.floor((expectedWorks * 2550 + (roundingMode === 'HALF_UP' ? 5000 : 0)) / 10000);
        expect(result.breakdown.works).toBe(expectedWorks.toString());
        expect(result.breakdown.expressSurcharge).toBe(expectedExpress.toString());
        expect(result.totalMinor).toBe((expectedWorks + expectedExpress).toString());
      }
    }
  });

  it('accepts maximum money and exact large fractional products; enforces individual stored bounds', () => {
    const exact = calculatePricing(fixture({ items: [item(10, 'WORK', MAX, '0.5')] }));
    expect(exact.totalMinor).toBe('4611686018427387904');
    expect(exact.lines[0]).toMatchObject({ rawNumerator: '46116860184273879035', denominator: '10' });
    expect(calculatePricing(fixture({ items: [item(10, 'WORK', '1', '999999999999.999999')] })).totalMinor).toBe('1000000000000');
    denied(fixture({ items: [item(10, 'WORK', MAX, '1.000001')] }), 'OVERFLOW'); // line
    denied(fixture({ items: [item(10, 'WORK', MAX), item(11, 'MATERIAL', '1')] }), 'OVERFLOW'); // component
    denied(fixture({ items: [item(10, 'WORK', MAX), item(11, 'PART', '1')] }), 'OVERFLOW'); // total
    const r = rule(1, 'DISCOUNT', { method: 'RATE', fixedMinor: null, rateBps: 10000 });
    const adjustment = manual(r, MAX, MAX);
    const inputs = { rules: [r], adjustments: [adjustment.adjustment], evidence: [adjustment.evidence] };
    const balance = calculatePricing(fixture({ ...inputs, items: [item(10, 'WORK', MAX), item(11, 'PART', '1')] }));
    expect(balance.totalMinor).toBe('1');
    expect(balance.lines[2]).toMatchObject({ rawNumerator: `${MAX}0000`, denominator: '10000', baseMinor: MAX, appliedMinor: MAX });
    denied(fixture({ ...inputs, rules: [{ ...r, base: 'ORDER_BASE' }], items: [item(10, 'WORK', MAX), item(11, 'PART', '1')] }), 'OVERFLOW'); // rule base
    denied(fixture({ rules: [{ ...r, rateBps: 10001 }] }));
    denied(fixture({ items: [item(10, 'WORK', '9223372036854775808')] }));
  });

  it('filters a capped non-applicable rule before checking the stored base for overflow', () => {
    const discount = rule(1, 'DISCOUNT', { method: 'RATE', fixedMinor: null, rateBps: 10000 });
    const approved = manual(discount, MAX, MAX);
    const express = rule(2, 'EXPRESS', { base: 'ORDER_BASE', maxBase: '100' });
    const input = fixture({ policy: withPriorities([express]), rules: [discount, express],
      items: [item(10, 'WORK', MAX), item(11, 'PART', '1')], adjustments: [approved.adjustment], evidence: [approved.evidence] });
    const actual = calculatePricing(input);
    expect(actual.totalMinor).toBe('1');
    expect(actual.breakdown.expressSurcharge).toBe('0');
    expect(actual.lines).toHaveLength(3);
    expect(actual.lines.some(line => line.source === 'RULE' && line.ruleId === express.ruleId)).toBe(false);
    denied({ ...input, rules: [discount, { ...express, maxBase: null }] }, 'OVERFLOW');
  });

  it('checks local window boundaries, DST repeat/gap and provided historical seconds with no timezone lookup', () => {
    const night = rule(1, 'NIGHT', { startMinute: 60, endMinute: 120, wrapsMidnight: false });
    const run = (tariffAt: string, localAt: string, utcOffsetSeconds: number) => calculatePricing(fixture({
      context: { ...CONTEXT, timezone: 'America/New_York', tariffAt, localAt, utcOffsetSeconds }, rules: [night], policy: withPriorities([night]),
    })).breakdown.timeSurcharge;
    expect(run('2026-11-01T05:00:00.000Z', '2026-11-01T01:00:00.000', -14400)).toBe('10');
    expect(run('2026-11-01T06:00:00.000Z', '2026-11-01T01:00:00.000', -18000)).toBe('10');
    expect(run('2026-11-01T07:00:00.000Z', '2026-11-01T02:00:00.000', -18000)).toBe('0');
    expect(run('2026-03-08T06:59:59.999Z', '2026-03-08T01:59:59.999', -18000)).toBe('10');
    expect(run('2026-03-08T07:00:00.000Z', '2026-03-08T03:00:00.000', -14400)).toBe('0');
    expect(run('1900-01-01T05:56:02.123Z', '1900-01-01T01:00:00.123', -17762)).toBe('10');
    expect(() => run('2026-11-01T05:00:00.000Z', '2026-11-01T01:00:00.001', -14400)).toThrow(PricingError);
    const wrap = rule(2, 'NIGHT');
    for (const [utc, local, expected] of [['20:00', '00:00', '10'], ['01:59', '05:59', '10'], ['02:00', '06:00', '0']] as const) {
      const date = utc === '20:00' ? '2026-11-22' : '2026-11-23';
      expect(calculatePricing(fixture({ rules: [wrap], policy: withPriorities([wrap]), context: { ...CONTEXT,
        tariffAt: `${date}T${utc}:00.000Z`, localAt: `2026-11-23T${local}:00.000` } })).breakdown.timeSurcharge).toBe(expected);
    }
  });

  it('requires explicit highest priority in each group and explicit permission for the winning pair', () => {
    const night = rule(0, 'NIGHT', { fixedMinor: '4' });
    const evening = rule(2, 'EVENING', { fixedMinor: '7' });
    const express = rule(1, 'EXPRESS', { fixedMinor: '9' });
    denied(fixture({ rules: [night] }), 'PRICING_CONFIGURATION_AMBIGUOUS');
    denied(fixture({ rules: [night, evening], policy: { ...POLICY, priorities: [night, evening].map((r) => ({ ruleId: r.ruleId, priority: 5 })) } }), 'PRICING_CONFIGURATION_AMBIGUOUS');
    expect(calculatePricing(fixture({ rules: [night, evening], policy: withPriorities([night, evening]) })).breakdown.timeSurcharge).toBe('7');
    denied(fixture({ rules: [night, evening, express], policy: { ...withPriorities([night, evening, express]),
      compatibilities: [{ leftRuleId: night.ruleId, rightRuleId: express.ruleId }] } }), 'PRICING_CONFIGURATION_AMBIGUOUS');
    expect(calculatePricing(fixture({ rules: [night, express], context: { ...CONTEXT, express: false }, policy: withPriorities([night]) })).totalMinor).toBe('105');
    denied(fixture({ rules: [night, { ...night, id: uuid(700) }] }), 'PRICING_CONFIGURATION_AMBIGUOUS');
    denied(fixture({ rules: [night, { ...night, ruleId: uuid(700) }] }), 'PRICING_CONFIGURATION_AMBIGUOUS');
  });

  it('validates every candidate before filtering and does not activate empty fixed bases or scoped nulls', () => {
    const express = rule(1, 'EXPRESS');
    const inactive = { ...CONTEXT, express: false };
    for (const broken of [{ ...express, title: '\t' }, { ...express, cityId: uuid(999) }, { ...express, currency: 'USD' },
      { ...express, fixedMinor: null }, { ...express, minBase: '2', maxBase: '1' }, { ...express, minDelta: '8', maxDelta: '7' },
      { ...express, categoryIds: [CAT, CAT] }, { ...express, wrapsMidnight: false }, { ...express, effectiveUntil: WHEN }]) {
      denied(fixture({ context: inactive, rules: [broken] }));
    }
    expect(calculatePricing(fixture({ rules: [express], items: [item(10, 'PART', '100')] })).totalMinor).toBe('100');
    expect(calculatePricing(fixture({ rules: [{ ...express, base: 'ORDER_BASE', categoryIds: [CAT] }], items: [item(10, 'TRAVEL', '100')] })).totalMinor).toBe('100');
    expect(calculatePricing(fixture({ rules: [express], policy: withPriorities([express]), items: [item(10, 'WORK', '0')] })).totalMinor).toBe('10');
    expect(calculatePricing(fixture({ rules: [{ ...express, maxBase: '100' }] })).totalMinor).toBe('101');
    denied(fixture({ rules: Array.from({ length: 65 }, (_, n) => rule(n, 'EXPRESS')), context: inactive }));
  });

  it('requires exact data fields, fixed price provenance, explicit zero basis and valid intervals', () => {
    const value = fixture();
    const row = only(value.items);
    const free = calculatePricing(fixture({ items: [item(10, 'WORK', '0')] }));
    expect(free.lines[0]).toMatchObject({ appliedMinor: '0', zeroBasis: 'Explicit no charge' });
    denied({ ...value, policy: null }, 'PRICING_NOT_CONFIGURED');
    denied({ ...value, items: [{ ...row, price: null }] }, 'PRICE_NOT_CONFIGURED');
    denied({ ...value, unexpected: true });
    denied({ ...value, evidence: undefined });
    denied({ ...value, items: [{ ...row, price: { ...row.price, validFrom: '2026-11-22T11:00:00.000Z', effectiveUntil: WHEN } }] }, 'PRICE_NOT_CONFIGURED');
    for (const wrong of [{ ...row.price, amountMinor: '0' }, { ...row.price, zeroBasis: 'claims free' }, { ...row.price, currency: 'USD' },
      { ...row.price, cityId: uuid(999) }, { ...row.price, itemId: uuid(999) }, { ...row.price, appliedMinor: '101' }]) {
      denied({ ...value, items: [{ ...row, price: wrong }] });
    }
    denied(fixture({ items: [row, { ...row, lineId: uuid(99), price: { ...row.price, id: uuid(999) } }] }), 'PRICING_CONFIGURATION_AMBIGUOUS');
    denied(fixture({ items: [row, { ...row, lineId: uuid(99), unit: 'hour' }] }));
    expect(calculatePricing(fixture({ items: [row, { ...row, lineId: uuid(99) }] })).totalMinor).toBe('202');
    denied(fixture({ items: Array.from({ length: 129 }, (_, n) => ({ ...row, lineId: uuid(1000 + n) })) }));
    let touched = false;
    const access = Object.defineProperty({ ...row }, 'title', { enumerable: true, get() { touched = true; return 'forged'; } });
    denied({ ...value, items: [access] });
    const traps = { getPrototypeOf() { touched = true; throw new Error('trapped'); } };
    denied(new Proxy(value, traps));
    denied({ ...value, items: new Proxy(value.items, traps) });
    expect(touched).toBe(false);
    const sparse: PricingItem[] = [];
    sparse.length = 1;
    denied({ ...value, items: sparse });
    const nullProto: unknown = Object.assign(Object.create(null) as object, value);
    expect(calculatePricing(nullProto).totalMinor).toBe('101');
  });

  it('rejects noncanonical quantity/unit/date/offset and refuses missing policy fields (no defaults)', () => {
    const row = only(fixture().items);
    for (const quantity of [0, '0', '01', '1.0', '0.010', '1e3', '-1', '+1', '1\n', ' 1', '1.0000001', '1000000000000', '１', '1.5']) {
      denied({ ...fixture(), items: [{ ...row, quantity }] });
    }
    denied({ ...fixture(), items: [{ ...row, unit: 'unknown' }] });
    denied({ ...fixture(), policy: { ...POLICY, units: {} } });
    denied({ ...fixture(), policy: { ...POLICY, units: { piece: 7 } } });
    denied({ ...fixture(), policy: { ...POLICY, units: { 'piece\n': 0 } } });
    denied({ ...fixture(), policy: { ...POLICY, roundingMode: undefined } });
    for (const context of [{ ...CONTEXT, pricingAt: '2026-02-30T12:00:00.000Z' }, { ...CONTEXT, pricingAt: WHEN.slice(0, -1) },
      { ...CONTEXT, tariffAt: '2026-11-22T24:00:00.000Z' }, { ...CONTEXT, utcOffsetSeconds: 64801 },
      { ...CONTEXT, utcOffsetSeconds: -0 }, { ...CONTEXT, timezone: '+03:00' }, { ...CONTEXT, timezone: 'posix/Europe/Moscow' },
      { ...CONTEXT, timezone: 'Europe/Moscow\n' }, { ...CONTEXT, express: undefined }]) { denied({ ...fixture(), context }); }
  });

  it('binds manual evidence to exact context, currency, base, capped magnitude, direction and reason', () => {
    const r = rule(1, 'SURCHARGE', { minDelta: '11', maxDelta: '12' });
    const { adjustment, evidence } = manual(r, '101', '11');
    const value = fixture({ rules: [r], adjustments: [adjustment], evidence: [evidence] });
    expect(calculatePricing(value).totalMinor).toBe('112');
    expect(calculatePricing(fixture({ rules: [r] })).totalMinor).toBe('101');
    for (const patch of [{ calculationId: uuid(999) }, { adjustmentId: uuid(999) }, { cityId: uuid(999) }, { policyVersionId: uuid(999) },
      { ruleVersionId: uuid(999) }, { currency: 'EUR' }, { baseMinor: '100' }, { appliedMinor: '10' }, { reason: ` ${adjustment.reason}` },
      { decision: 'WITHIN_LIMIT' }] as const) { denied({ ...value, evidence: [{ ...evidence, ...patch }] }, 'ADJUSTMENT_NOT_AUTHORIZED'); }
    for (const broken of [{ ...evidence, actorId: null }, { ...evidence, reason: ' ' }, { ...evidence, extra: 1 }]) {
      denied({ ...value, evidence: [broken] });
    }
    denied({ ...value, evidence: [] }, 'ADJUSTMENT_NOT_AUTHORIZED');
    denied({ ...value, adjustments: [] }, 'ADJUSTMENT_NOT_AUTHORIZED');
    denied({ ...value, adjustments: [adjustment, { ...adjustment, id: uuid(999) }] }, 'ADJUSTMENT_NOT_AUTHORIZED');
    denied({ ...value, adjustments: [adjustment, adjustment] }, 'ADJUSTMENT_NOT_AUTHORIZED');
    denied({ ...value, evidence: [evidence, { ...evidence, adjustmentId: uuid(999) }] }, 'ADJUSTMENT_NOT_AUTHORIZED');
    denied({ ...value, rules: [{ ...r, categoryIds: [OTHER_CAT] }] }, 'ADJUSTMENT_NOT_AUTHORIZED');
    denied({ ...value, rules: [{ ...r, kind: 'EXPRESS' }], policy: withPriorities([r]) }, 'ADJUSTMENT_NOT_AUTHORIZED');
    denied({ ...value, policy: { ...POLICY, maxManualDeltaMinor: '11' } }, 'ADJUSTMENT_NOT_AUTHORIZED');
    expect(calculatePricing({ ...value, policy: { ...POLICY, maxManualDeltaMinor: '11' },
      evidence: [{ ...evidence, decision: 'WITHIN_LIMIT' }] }).totalMinor).toBe('112');
  });

  it('enforces every pair including manual rules, leaves no extra evidence, and rejects negative totals', () => {
    const value = golden();
    for (const pair of value.policy.compatibilities) {
      denied({ ...value, policy: { ...value.policy, compatibilities: value.policy.compatibilities.filter((p) => p !== pair) } },
        pair.leftRuleId === uuid(501) && pair.rightRuleId === uuid(502) ? 'PRICING_CONFIGURATION_AMBIGUOUS' : 'ADJUSTMENT_NOT_AUTHORIZED');
    }
    const r = rule(1, 'DISCOUNT', { fixedMinor: '102' });
    const { adjustment, evidence } = manual(r, '101', '102');
    denied(fixture({ rules: [r], adjustments: [adjustment], evidence: [evidence] }), 'NEGATIVE_TOTAL');
  });
});
