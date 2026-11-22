import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  canonicalPricingJson,
  parseStrictPricingJson,
  sealPricing,
  verifyPricingSnapshot,
} from '../src/pricing/codec/index.js';

function sha256(bytes: string | Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

const id = (value: number): string => `00000000-0000-4000-8000-${String(value).padStart(12, '0')}`;
const validFrom = '2025-01-01T00:00:00.000Z';
const at = '2026-11-22T23:30:00.000Z';

function fixture() {
  return {
    context: {
      calculationId: id(1), cityId: id(2), cityVersionId: id(3), timezone: 'Europe/Moscow',
      pricingAt: at, tariffAt: at, localAt: '2026-11-23T01:30:00.000', utcOffsetSeconds: 7200, express: false,
    },
    policy: {
      id: id(4), cityId: id(2), cityVersionId: id(3), currency: 'RUB', taxDisplay: 'Synthetic',
      roundingMode: 'HALF_UP', units: { piece: 0 }, maxManualDeltaMinor: '500',
      priorities: [], compatibilities: [], validFrom, effectiveUntil: null,
    },
    items: [{
      lineId: id(5), itemId: id(6), itemVersionId: id(7), kind: 'WORK', categoryId: id(8),
      unit: 'piece', title: 'Synthetic work', quantity: '2',
      price: {
        id: id(9), cityId: id(2), cityVersionId: id(10), itemId: id(6), itemVersionId: id(11),
        amountMinor: '125', currency: 'RUB', zeroBasis: null, validFrom, effectiveUntil: null,
      },
    }],
    rules: [], adjustments: [], evidence: [],
  };
}

describe('P04-02 strict pricing JSON', () => {
  it('rejects duplicate decoded members, with independent namespaces per object', () => {
    for (const bytes of [
      '{"a":1,"a":2}', '{"outer":[{"a":1,"\\u0061":2}]}',
      '{"😀":1,"\\uD83D\\uDE00":2}', '{"__proto__":0,"__pr\\u006fto__":1}',
    ]) { expect(() => parseStrictPricingJson(bytes)).toThrow('Invalid pricing JSON'); }
    const parsed = parseStrictPricingJson('{"__proto__":{"a":1},"other":{"a":2}}');
    expect(Object.getPrototypeOf(parsed)).toBeNull();
    expect(canonicalPricingJson(parsed)).toBe('{"__proto__":{"a":1},"other":{"a":2}}');
  });

  it('accepts only safe integer tokens, and distinguishes unbounded amounts as strings', () => {
    for (const token of ['-0', '+1', '01', '1.0', '1E0', '1e+4', 'NaN', 'Infinity', '9007199254740992',
      '-9007199254740992', '9'.repeat(100_000)]) {
      expect(() => parseStrictPricingJson(token)).toThrow('Invalid pricing JSON');
    }
    expect(parseStrictPricingJson('[-9007199254740991,0,9007199254740991,"9223372036854775807","1.125"]'))
      .toEqual([-9007199254740991, 0, 9007199254740991, '9223372036854775807', '1.125']);
    for (const malformed of ['[1,]', '{"a":1,}', 'null false', '{"a":}', '\vtrue', '"\\z"', '"\n"']) {
      expect(() => parseStrictPricingJson(malformed)).toThrow('Invalid pricing JSON');
    }
  });

  it('rejects invalid UTF-8, a BOM, and raw or escaped unpaired surrogates', () => {
    for (const bytes of [
      Uint8Array.of(0x22, 0xc0, 0xaf, 0x22), Uint8Array.of(0x22, 0xed, 0xa0, 0x80, 0x22),
      Uint8Array.of(0xef, 0xbb, 0xbf, 0x31), '"\ud800"', '"\\ud800"', '"\\udfff"',
      '{"\\ud800":0}',
    ]) { expect(() => parseStrictPricingJson(bytes)).toThrow('Invalid pricing JSON'); }
    expect(parseStrictPricingJson(new TextEncoder().encode('"😀"'))).toBe('😀');
  });

  it('bounds bytes, depth and nodes in both directions', () => {
    expect(() => parseStrictPricingJson(`"${'é'.repeat(1024 * 1024)}"`)).toThrow('Invalid pricing JSON');
    expect(() => parseStrictPricingJson(new Uint8Array(2 * 1024 * 1024 + 1))).toThrow('Invalid pricing JSON');
    expect(() => parseStrictPricingJson(`${'['.repeat(64)}null${']'.repeat(64)}`)).toThrow('Invalid pricing JSON');
    expect(() => parseStrictPricingJson(`[${'0,'.repeat(99_999)}0]`)).toThrow('Invalid pricing JSON');
    expect(() => canonicalPricingJson('é'.repeat(1024 * 1024))).toThrow('Invalid pricing JSON');
    const cycle: unknown[] = [];
    cycle.push(cycle);
    expect(() => canonicalPricingJson(cycle)).toThrow('Invalid pricing JSON');
    expect(() => canonicalPricingJson(Array.from({ length: 100_000 }, () => null))).toThrow('Invalid pricing JSON');
  });

  it('sorts only object keys, does not invoke getters, hooks or proxy traps, and refuses loss', () => {
    expect(canonicalPricingJson({ 2: 2, 10: 10, z: ['b', 'a'], a: { y: 1, x: 2 } }))
      .toBe('{"10":10,"2":2,"a":{"x":2,"y":1},"z":["b","a"]}');
    let calls = 0;
    const getter = { get value() { calls += 1; return 1; } };
    const proxy = new Proxy({}, { ownKeys() { calls += 1; return []; } });
    const hook = { toJSON() { calls += 1; return 1; } };
    const arrayGetter = Object.defineProperty([0], '0', { get() { calls += 1; return 1; } });
    for (const value of [getter, proxy, hook, arrayGetter, { value: undefined }, { [Symbol()]: 1 },
      Object.defineProperty({}, 'private', { value: 1 }), new Date(0), new Array(1),
      Object.assign([1], { extra: true }), 1n, NaN, 0.5, -0, '\ud800',
    ]) { expect(() => canonicalPricingJson(value)).toThrow('Invalid pricing JSON'); }
    expect(calls).toBe(0);
  });
});

describe('P04-02 sealed replay with the real engine', () => {
  it('replays saved amounts and wall offset independently of changed prices, timezone and source', () => {
    const input = fixture();
    const sealed = sealPricing(input);
    expect(sealed.sha256).toMatch(/^[0-9a-f]{64}$/u);
    expect(sealed.sha256).toBe(sha256(sealed.bytes));
    const { units, ...otherPolicy } = input.policy;
    expect(sealPricing({ ...input, policy: { units, ...otherPolicy } })).toEqual(sealed);
    const price = input.items[0]?.price;
    if (!price) { throw new Error('Missing fixture price'); }
    price.amountMinor = '800';
    input.context.timezone = 'UTC';
    input.context.localAt = '2026-11-22T23:30:00.000';
    input.context.utcOffsetSeconds = 0;
    expect(sealPricing(input).sha256).not.toBe(sealed.sha256);
    const replayed = verifyPricingSnapshot(new TextEncoder().encode(sealed.bytes), sealed.sha256);
    expect(replayed.totalMinor).toBe('250');
    expect(replayed.input.context.localAt).toBe('2026-11-23T01:30:00.000');
    expect(replayed.input.context.utcOffsetSeconds).toBe(7200);
    expect(Object.isFrozen(replayed.input.items[0]?.price)).toBe(true);
    expect(sealPricing(replayed.input)).toEqual(sealed);
  });

  it('keeps engine-normalized array order and rejects a reordered trace despite a new digest', () => {
    const input = fixture();
    const first = input.items[0];
    if (!first) { throw new Error('Missing fixture line'); }
    input.items.unshift({ ...first, lineId: id(15), quantity: '1' });
    const { bytes, sha256: expected } = sealPricing(input);
    const replayed = verifyPricingSnapshot(bytes, expected);
    expect(replayed.input.items.map(({ lineId }) => lineId)).toEqual([id(5), id(15)]);
    expect(replayed.totalMinor).toBe('375');
    const forged = canonicalPricingJson({ version: 1, ...replayed, lines: [...replayed.lines].reverse() });
    expect(forged).not.toBe(bytes);
    expect(() => verifyPricingSnapshot(forged, sha256(forged))).toThrow('Invalid pricing snapshot');
  });

  it('fails closed on mutation, malformed digest, loss, invalid encoding and duplicate keys', () => {
    const { bytes, sha256: expected } = sealPricing(fixture());
    expect(() => verifyPricingSnapshot(bytes.replace('Synthetic work', 'Altered work'), expected)).toThrow();
    expect(() => verifyPricingSnapshot(bytes.slice(0, -1), expected)).toThrow();
    for (const bad of [expected.toUpperCase(), `${expected}\n`, expected.slice(1), 'z'.repeat(64)]) {
      expect(() => verifyPricingSnapshot(bytes, bad)).toThrow();
    }
    const invalidUtf8 = Uint8Array.of(0x22, 0xff, 0x22);
    expect(() => verifyPricingSnapshot(invalidUtf8, sha256(invalidUtf8))).toThrow();
    const duplicate = bytes.replace('"currency":"RUB"', '"currency":"RUB","curre\\u006ecy":"RUB"');
    expect(duplicate).not.toBe(bytes);
    expect(() => verifyPricingSnapshot(duplicate, sha256(duplicate))).toThrow('Invalid pricing JSON');
  });

  it('rejects noncanonical encoding, unknown fields and forged internally inconsistent results with their own digest', () => {
    const { bytes } = sealPricing(fixture());
    for (const forged of [
      ` ${bytes}`, bytes.replace('Synthetic work', '\\u0053ynthetic work'),
      bytes.replace(/,"version":1\}$/u, '}').replace(/^\{/u, '{"version":1,'),
      bytes.replace('"version":1', '"version":2'), bytes.replace('"version":1', '"other":1'),
      bytes.replace('"quantity":"2"', '"quantity":2'),
      bytes.replace('"amountMinor":"125"', '"amountMinor":125'),
      bytes.replace('"totalMinor":"250"', '"totalMinor":"251"'),
      bytes.replace('"works":"250"', '"works":"251"'),
      bytes.replace('"appliedMinor":"250"', '"appliedMinor":"251"'),
      bytes.replace('"taxDisplay":"Synthetic"', '"taxDisplay":"Synthetic","unknown":0'),
    ]) {
      expect(forged).not.toBe(bytes);
      expect(() => verifyPricingSnapshot(forged, sha256(forged))).toThrow();
    }
  });
});
