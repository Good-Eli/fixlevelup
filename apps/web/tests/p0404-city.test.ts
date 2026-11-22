import { describe, expect, it } from 'vitest';
import {
  body, closeAt, estimateFields, fixedFields, isClosable, minor, periodStatus, policyFields, ruleFields, sameRevision, schedule, utc,
  type TemporalRevision,
} from '../app/crm/access/p04/city-wires';

function input(values: Record<string, string>) {
  const form = new FormData();
  for (const [name, value] of Object.entries(values)) { form.append(name, value); }
  return form;
}
const t1 = '2030-01-01T00:00:00.000Z';
const t2 = '2030-02-01T00:00:00.000Z';
const t3 = '2030-03-01T00:00:00.000Z';
const t4 = '2030-04-01T00:00:00.000Z';
const ids = ['11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222'];
const labels = ids.map((id, i) => ({ id, code: `rule-${String(i)}` }));
const first = ids[0] ?? '';
const second = ids[1] ?? '';
const scheduleFields = { validFrom: t3, validUntil: t4, sourceRef: 'CRM test' };

describe('P04-04 city editor request boundaries', () => {
  it('keeps exact INT64 minor amounts and distinguishes missing from configured zero', () => {
    expect(minor('9223372036854775807', true)).toBe('9223372036854775807');
    expect(minor('9007199254740993', true)).toBe('9007199254740993');
    expect(minor('')).toBeNull();
    expect(minor('0')).toBe('0');
    for (const bad of ['9223372036854775808', '00', '1.0', '-1', ' 1', '1e1']) { expect(() => minor(bad, true)).toThrow(); }
    expect(() => fixedFields(input({ currency: 'RUB', amountMinor: '0' }))).toThrow();
    const zero = fixedFields(input({ currency: 'RUB', amountMinor: '0', zeroBasis: 'free diagnosis' }));
    expect(body('fixedPublish', { ...zero, ...scheduleFields }).amountMinor).toBe('0');
    const high = fixedFields(input({ currency: 'RUB', amountMinor: '9223372036854775807' }));
    expect(body('fixedPublish', { ...high, ...scheduleFields }).zeroBasis).toBeNull();
  });
  it('requires exact UTC millisecond strings and ordered validity', () => {
    expect(utc(t3, true)).toBe(t3);
    for (const bad of ['2030-03-01T00:00:00Z', '2030-03-01T00:00:00.000+00:00', '2030-02-30T00:00:00.000Z', ` ${t3}`, '0000-01-01T00:00:00.000Z']) {
      expect(() => utc(bad, true)).toThrow();
    }
    expect(() => schedule(input({ ...scheduleFields, validUntil: t2 }), 'validFrom')).toThrow();
  });
  it('keeps the public estimate amount pair separate and compares exactly', () => {
    const common = { title: 'Repair', currency: 'RUB', disclaimer: 'Estimate only' };
    expect(() => estimateFields(input({ ...common, minMinor: '9007199254740993', maxMinor: '9007199254740992' }))).toThrow();
    const fields = estimateFields(input({ ...common, minMinor: '9007199254740992', maxMinor: '9007199254740993' }));
    expect(body('estimatePublish', { ...fields, ...scheduleFields })).toMatchObject({ minMinor: '9007199254740992', maxMinor: '9007199254740993' });
  });
  it('validates rule method, window, optional limits, and cities’ current category labels', () => {
    const common = { title: 'Late', base: 'WORKS', currency: 'RUB', method: 'RATE', rateBps: '125', categoryIds: first,
      startMinute: '22:30', endMinute: '05:00', wrapsMidnight: 'yes' };
    const rule = ruleFields(input(common), 'NIGHT', labels);
    expect(body('ruleVersionPublish', { ...rule, ...scheduleFields })).toMatchObject({ method: 'RATE', fixedMinor: null,
      rateBps: 125, startMinute: 1350, endMinute: 300, wrapsMidnight: true, categoryIds: [first] });
    for (const kind of ['EXPRESS', 'SURCHARGE', 'DISCOUNT'] as const) {
      const fixed = ruleFields(input({ title: 'Flat', base: 'ORDER_BASE', currency: 'RUB', method: 'FIXED', fixedMinor: '9223372036854775807' }), kind, labels);
      expect(body('ruleVersionReplace', { ...fixed, validUntil: t4, at: t3, sourceRef: 'source' })).toMatchObject({ kind, method: 'FIXED', fixedMinor: '9223372036854775807' });
    }
    expect(() => ruleFields(input({ ...common, categoryIds: 'unlisted' }), 'EVENING', labels)).toThrow();
    expect(() => ruleFields(input({ ...common, wrapsMidnight: 'no' }), 'NIGHT', labels)).toThrow();
    expect(() => ruleFields(input({ ...common, minDelta: '9007199254740993', maxDelta: '9007199254740992' }), 'EVENING', labels)).toThrow();
  });
  it('builds bounded typed policy rows and rejects reversed duplicate compatibility pairs', () => {
    const values = { currency: 'RUB', taxDisplay: 'Tax included', roundingMode: 'HALF_UP', maxManualDeltaMinor: '9223372036854775807',
      'unit-0': 'piece', 'scale-0': '0', 'priority-rule-0': first, 'priority-0': '50', 'left-rule-0': first, 'right-rule-0': second };
    const rows = { units: 1, priorities: 1, compatibilities: 1 };
    const policy = policyFields(input(values), rows, labels);
    expect(body('policyPublish', { ...policy, ...scheduleFields })).toMatchObject({ units: { piece: 0 }, priorities: [{ ruleId: first, priority: 50 }],
      compatibilities: [{ leftRuleId: first, rightRuleId: second }], maxManualDeltaMinor: '9223372036854775807' });
    expect(() => policyFields(input({ ...values, 'left-rule-1': second, 'right-rule-1': first }), { ...rows, compatibilities: 2 }, labels)).toThrow();
    expect(() => policyFields(input(values), { ...rows, units: 33 }, labels)).toThrow();
  });
  it('detects list/detail period or city revision variance and blocks scheduled/closed targets', () => {
    const current: TemporalRevision = { id: first, seriesId: first, cityId: first, cityVersionId: second,
      version: 2, publishedAt: t1, validFrom: t1, validUntil: t4, effectiveUntil: t4 };
    expect(sameRevision(current, { ...current })).toBe(true);
    expect(sameRevision(current, { ...current, cityVersionId: first })).toBe(false);
    const cut = { ...current, effectiveUntil: t3 };
    expect(sameRevision(current, cut)).toBe(false);
    expect(periodStatus(cut, t2)).toContain('закрытия');
    expect(isClosable(cut, t2)).toBe(false);
    expect(isClosable({ ...current, validFrom: t3 }, t2)).toBe(false);
    expect(closeAt(current, t3, t2)).toBe(t3);
    expect(() => closeAt(current, t4, t2)).toThrow();
  });
});
