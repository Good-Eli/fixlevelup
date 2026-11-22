import { describe, expect, it } from 'vitest';
import { amountMinor, instant, record, slug } from '../src/catalog/validation.js';

describe('P04-01 exact input primitives', () => {
  it('preserves the full PostgreSQL bigint wire range without renormalizing numbers', () => {
    for (const accepted of ['0', '1', '9007199254740993', '9223372036854775807']) {
      expect(amountMinor(accepted)).toBe(accepted);
    }
    for (const rejected of [undefined, null, 0, 1n, '9223372036854775808', '00', '+1', '-0', '1.0', '1e3', '1\n', ' 1', '１']) {
      expect(() => amountMinor(rejected)).toThrow('INVALID_INPUT: amountMinor');
    }
  });

  it('requires actual UTC milliseconds, not a date which JavaScript silently rolls over', () => {
    const good = '2028-02-29T12:13:14.059Z';
    expect(instant(good, 'at')).toBe(good);
    for (const bad of ['2027-02-29T12:13:14.059Z', '2028-02-29T24:00:00.000Z', '2028-02-29T12:13:14.059001Z',
      '2028-02-29T12:13:14.059+00:00', '0000-02-29T12:13:14.059Z', 'infinity', new Date(good)]) {
      expect(() => instant(bad, 'at')).toThrow('INVALID_INPUT: at');
    }
  });

  it('separates a canonical slug from unsafe spellings and copies only approved own data', () => {
    expect(slug('kit-piece', 1, 24, 'unit')).toBe('kit-piece');
    for (const bad of ['Kit-piece', 'kit--piece', 'kit-piece\n', 'kit piece', '']) {
      expect(() => slug(bad, 1, 24, 'unit')).toThrow('INVALID_INPUT: unit');
    }
    const original = { unit: 'piece' };
    const copy = record(original, ['unit']);
    original.unit = 'kit';
    expect(copy['unit']).toBe('piece');
    let invoked = false;
    const getter = { get unit() { invoked = true; return 'piece'; } };
    expect(() => record(getter, ['unit'])).toThrow('INVALID_INPUT: input');
    expect(() => record({ unit: 'piece', hidden: 'unexpected' }, ['unit'])).toThrow('INVALID_INPUT: input');
    expect(invoked).toBe(false);
  });
});
