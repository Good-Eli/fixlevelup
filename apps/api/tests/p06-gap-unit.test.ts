/**
 * P06 gap unit proofs for pure P06 logic: registry filters/cursor scope, search
 * contract, dashboard link/DTO, ephemeral snapshots, idempotency HMAC and the
 * managed payload cipher. No database, no network, no Nest wiring.
 * KNOWN GAP: none found. Brief-vs-code notes, both fail-closed and already
 * asserted by existing suites: verifyIdempotencyHmac refuses an unknown keyId
 * by throwing KeyringError('UNKNOWN_KEY') (not false; requests-crypto.test.ts
 * asserts it); parseSearch's >1024-byte branch is unreachable because the
 * 256-char cap allows at most 768 UTF-8 bytes (1025-byte queries are still
 * refused via the length check, so the contract is not weakened).
 */
import type { PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';
import { P05_CHANNEL_PROVIDERS, P05_CONTACT_MODES, P05_STATUSES, P05_URGENCIES } from '@fixlevelup/p03-contracts/p05';
import { isRegistryInstant, parseRegistryQuery, type RegistryQuery } from '../src/requests/registry/filters.js';
import { readRegistryEvidence, readVisibleRegistry, type RegistryItem, type RegistryRow } from '../src/requests/registry/store.js';
import type { SingleCityContext } from '../src/settings/geography/city-context.js';
import { normalizeSearchName, parseSearch, SEARCH_BODY_BYTES } from '../src/requests/search/contract.js';
import { DASHBOARD_CAPACITY, DASHBOARD_PAGE_SIZE, DASHBOARD_VERSION, parseDashboardLink, READY_METRICS,
  UNAVAILABLE_METRICS, type ReadyMetric } from '../src/requests/dashboard/contract.js';
import { DashboardSnapshots, dashboardDto, dashboardPage, type DashboardSnapshot,
  type DashboardSubject } from '../src/requests/dashboard/snapshots.js';
import type { DashboardMaterial } from '../src/requests/dashboard/store.js';
import { KeyringError, loadKeyring } from '../src/requests/crypto/keyring.js';
import { MANAGED_PAYLOAD_KEY_MARKER, PayloadCipherError, idempotencyHmac, openManagedPayload,
  sealManagedPayload, verifyIdempotencyHmac, type PayloadCipherErrorCode } from '../src/requests/crypto/payload-cipher.js';
import type { PayloadKeySlotRef, PayloadKeySlots } from '../src/requests/crypto/payload-key-directory.js';
import { COMMENT_KEY_ENVIRONMENT, readInternalComments } from '../src/requests/card/comments.js';
import { RequestFailure } from '../src/requests/intake/errors.js';

const id = (value: number) => `00000000-0000-4000-8000-${String(value).padStart(12, '0')}`;
const CITY = { cityId: id(1), cityVersionId: id(2), timezone: 'Europe/Moscow' } as const;
const OTHER_ID = id(99), CATEGORY = id(10), DISTRICT = id(11), SOURCE = id(12);
const FROM = '2026-11-01T00:00:00.000000Z', TO = '2026-12-01T00:00:00.000000Z';
const parse = (query: string) => parseRegistryQuery(new URLSearchParams(query));
const failureCode = (run: () => unknown): string => {
  try { run(); } catch (error) { return (error as { readonly code?: string }).code ?? 'NO_CODE'; }
  throw new Error('expected a refusal');
};
const clientOf = (query: ReturnType<typeof vi.fn>): PoolClient => ({ query } as unknown as PoolClient);
const itemAt = (index: number): RegistryItem => ({ id: `request-${String(index)}`, publicNumber: String(1000 - index),
  createdAt: `2026-11-17T00:00:00.${String(index).padStart(6, '0')}Z`, type: 'CALLBACK', status: 'NEW', version: 1 });
const rowOf = (value: RegistryItem): RegistryRow => ({ ...value, evidenceId: null, procedureRevision: null, validUntil: null });
const EMPTY_QUERY = { from: null, to: null, status: null, urgency: null, categoryId: null, districtId: null,
  sourceId: null, contactMode: null, provider: null, limit: 30, cursor: null } as const;

describe('P06 registry filters', () => {
  it('accepts every P05 vocabulary value, limit boundaries and maps a full query exactly', () => {
    for (const status of P05_STATUSES) { expect(parse(`status=${status}`).status).toBe(status); }
    for (const urgency of P05_URGENCIES) { expect(parse(`urgency=${urgency}`).urgency).toBe(urgency); }
    for (const contactMode of P05_CONTACT_MODES) { expect(parse(`contactMode=${contactMode}`).contactMode).toBe(contactMode); }
    for (const provider of P05_CHANNEL_PROVIDERS) { expect(parse(`provider=${provider}`).provider).toBe(provider); }
    expect([parse('').limit, parse('limit=1').limit, parse('limit=99').limit, parse('limit=100').limit]).toEqual([30, 1, 99, 100]);
    expect(parse(`from=${FROM}&to=${TO}&status=NEW&urgency=URGENT&categoryId=${CATEGORY}&districtId=${DISTRICT}`
      + `&sourceId=${SOURCE}&contactMode=CHANNEL&provider=MAX&limit=100`)).toEqual({
      from: FROM, to: TO, status: 'NEW', urgency: 'URGENT', categoryId: CATEGORY, districtId: DISTRICT,
      sourceId: SOURCE, contactMode: 'CHANNEL', provider: 'MAX', limit: 100, cursor: null,
    });
  });
  it.each([
    `cityId=${CITY.cityId}`, 'limit=5&limit=5', 'status=NEW&status=NEW', 'status=unsupported', 'urgency=urgent',
    'contactMode=channel', 'provider=TGX', 'categoryId=invalid', 'districtId=not-a-uuid',
    'sourceId=00000000-0000-4000-8000-00000000000A', 'categoryId=00000000000040008000000000000001',
    'limit=0', 'limit=101', 'limit=01', 'limit=1e2',
    'from=2026-11-17T00:00:00.1Z', 'from=2026-11-17T00:00:00.12Z', 'from=2026-11-17T00:00:00.1234Z',
    'from=2026-11-17T00:00:00Z', 'from=2026-11-17T00:00:00.123456%2B03:00', 'from=0000-01-01T00:00:00.000000Z',
    'from=2026-02-30T00:00:00.000000Z', 'from=2026-11-17T24:00:00.000000Z', 'from=2026-11-17 00:00:00.000000Z',
    'from=2026-11-17T00:00:00.123456z', 'to=2026-02-30T00:00:00.000000Z',
  ])('rejects invalid registry query %s', (query) => {
    expect(failureCode(() => parse(query))).toBe('INVALID_REQUEST');
  });
  it('normalizes three-digit milliseconds, retains six-digit bounds and rejects bad intervals', () => {
    expect(parse('from=2026-11-17T00:00:00.123Z&to=2026-11-17T00:00:00.123001Z')).toEqual({
      ...EMPTY_QUERY, from: '2026-11-17T00:00:00.123000Z', to: '2026-11-17T00:00:00.123001Z' });
    expect(parse(`from=${FROM}&to=${TO}`)).toEqual({ ...EMPTY_QUERY, from: FROM, to: TO });
    expect(parse('from=2026-11-17T00:00:00.000000Z&to=2026-11-17T00:00:00.000001Z')).toEqual({
      ...EMPTY_QUERY, from: '2026-11-17T00:00:00.000000Z', to: '2026-11-17T00:00:00.000001Z' });
    expect(failureCode(() => parse('from=2026-11-17T00:00:00.000001Z&to=2026-11-17T00:00:00.000000Z'))).toBe('INVALID_REQUEST');
    expect(failureCode(() => parse('from=2026-11-17T00:00:00.000000Z&to=2026-11-17T00:00:00.000000Z'))).toBe('INVALID_REQUEST');
  });
  it.each([
    ['2026-11-17T00:00:00.123456Z', true], ['2026-11-17T23:59:59.999999Z', true], ['2024-02-29T00:00:00.000000Z', true],
    ['2026-11-17T00:00:00.123Z', false], ['2026-11-17T00:00:00Z', false], ['2026-11-17T00:00:00.1234567Z', false],
    ['2026-11-17T00:00:00.123456+03:00', false], ['2026-11-17 00:00:00.123456Z', false], ['0000-01-01T00:00:00.000000Z', false],
    ['2026-02-30T00:00:00.000000Z', false], ['2026-11-17T24:00:00.000000Z', false], ['2026-11-17T00:00:00.123456z', false],
  ])('isRegistryInstant(%s) is %s', (value, expected) => {
    expect(isRegistryInstant(value)).toBe(expected);
  });
});

describe('P06 registry cursor', () => {
  const first = itemAt(1), second = itemAt(2);
  const baseQuery = `from=${FROM}&to=${TO}&status=NEW&urgency=URGENT&categoryId=${CATEGORY}`
    + `&districtId=${DISTRICT}&sourceId=${SOURCE}&contactMode=PHONE&provider=TG&limit=1`;
  const bound = [CITY.cityId, FROM, TO, 'NEW', CATEGORY, DISTRICT, 'URGENT', 'PHONE', SOURCE, 'TG', 30];
  it('binds the cursor to city, city version and every filter value, but accepts it unchanged', async () => {
    const query = vi.fn().mockResolvedValue({ rows: [rowOf(first), rowOf(second)] });
    const client = clientOf(query), base = parse(baseQuery);
    const page = await readVisibleRegistry(client, CITY, base, undefined);
    expect(page.items).toEqual([first]);
    expect(query).toHaveBeenNthCalledWith(1, expect.stringContaining('WHERE request.city_id = $1'), bound);
    const cursor = page.nextCursor ?? '';
    const continued = await readVisibleRegistry(client, CITY, { ...base, cursor }, undefined);
    expect(continued.items).toEqual([first]);
    expect(query).toHaveBeenNthCalledWith(2,
      expect.stringContaining('(request.created_at, request.public_number) < ($11::timestamptz, $12::bigint)'),
      [...bound.slice(0, 10), first.createdAt, first.publicNumber, 30]);
    const mutations: readonly [string, { readonly city?: Partial<SingleCityContext>; readonly filters?: Partial<RegistryQuery> }][] = [
      ['cityId', { city: { cityId: OTHER_ID } }], ['cityVersionId', { city: { cityVersionId: OTHER_ID } }],
      ['from', { filters: { from: '2026-10-01T00:00:00.000000Z' } }], ['to', { filters: { to: '2026-12-02T00:00:00.000000Z' } }],
      ['status', { filters: { status: 'CANCELLED' } }], ['urgency', { filters: { urgency: 'FLEXIBLE' } }],
      ['categoryId', { filters: { categoryId: OTHER_ID } }], ['districtId', { filters: { districtId: OTHER_ID } }],
      ['sourceId', { filters: { sourceId: OTHER_ID } }], ['contactMode', { filters: { contactMode: 'CHANNEL' } }],
      ['provider', { filters: { provider: 'VK' } }],
    ];
    for (const [label, mutation] of mutations) {
      await expect(readVisibleRegistry(client, { ...CITY, ...mutation.city }, { ...base, ...mutation.filters, cursor }, undefined), label)
        .rejects.toThrow('INVALID_REQUEST');
    }
    expect(query).toHaveBeenCalledTimes(2);
  });
  it('rejects malformed cursors and accepts the int64 boundary position', async () => {
    const query = vi.fn().mockResolvedValue({ rows: [rowOf(first), rowOf(second)] });
    const client = clientOf(query), base = parse('limit=1');
    const page = await readVisibleRegistry(client, CITY, base, undefined);
    const scope = (page.nextCursor ?? '').split('~')[2] ?? '';
    const malformed = [
      'invalid', `${first.createdAt}~${first.publicNumber}`, `${first.createdAt}~${first.publicNumber}~${scope}~extra`,
      `${first.createdAt}~${first.publicNumber}~${'0'.repeat(64)}`, `${first.createdAt}~0~${scope}`,
      `${first.createdAt}~01~${scope}`, `${first.createdAt}~9223372036854775808~${scope}`,
      `${first.createdAt}~9999999999999999999~${scope}`, `${first.createdAt}~12345678901234567890~${scope}`,
      `2026-11-17T00:00:00.123Z~${first.publicNumber}~${scope}`,
    ];
    for (const value of malformed) {
      await expect(readVisibleRegistry(client, CITY, { ...base, cursor: value }, undefined), value).rejects.toThrow('INVALID_REQUEST');
    }
    expect(query).toHaveBeenCalledTimes(1);
    const maxCursor = `${first.createdAt}~9223372036854775807~${scope}`;
    await expect(readVisibleRegistry(client, CITY, { ...base, cursor: maxCursor }, undefined)).resolves.toBeDefined();
    await expect(readVisibleRegistry(client, CITY, { ...base, limit: 2, cursor: maxCursor }, undefined)).resolves.toBeDefined();
    expect(query).toHaveBeenCalledTimes(3);
  });
  it('returns 100 items plus a cursor for 101 visible rows and no cursor for exactly 100', async () => {
    const items = Array.from({ length: 101 }, (_, index) => itemAt(index));
    const withOverflow = vi.fn().mockResolvedValueOnce({ rows: items.map(rowOf) });
    const page = await readVisibleRegistry(clientOf(withOverflow), CITY, parse('limit=100'), undefined);
    expect(page.items).toEqual(items.slice(0, 100));
    const [createdAt, publicNumber] = (page.nextCursor ?? '').split('~');
    expect([createdAt, publicNumber]).toEqual([items[99]?.createdAt, items[99]?.publicNumber]);
    expect(withOverflow).toHaveBeenCalledTimes(1);
    expect(withOverflow).toHaveBeenCalledWith(expect.stringContaining('LIMIT $2'), [CITY.cityId, 101]);
    const exact = vi.fn().mockResolvedValueOnce({ rows: items.slice(0, 100).map(rowOf) });
    const lastPage = await readVisibleRegistry(clientOf(exact), CITY, parse('limit=100'), undefined);
    expect([lastPage.items, lastPage.nextCursor]).toEqual([items.slice(0, 100), null]);
    expect(exact).toHaveBeenCalledTimes(1);
  });
  it('skips hidden evidence rows and derives the cursor only from visible rows', async () => {
    const validUntil = new Date('2026-11-18T00:00:00.000Z');
    const rowAt = (index: number): RegistryRow => ({
      ...itemAt(index), evidenceId: `evidence-${String(index)}`, procedureRevision: 'rev-1', validUntil });
    const query = vi.fn().mockResolvedValueOnce({ rows: Array.from({ length: 30 }, (_, index) => rowAt(index)) });
    const isCurrent = (value: { id: string }) => Number(value.id.replace('evidence-', '')) % 2 === 0;
    const page = await readVisibleRegistry(clientOf(query), CITY, parse('limit=2'), isCurrent);
    expect(page.items).toEqual([itemAt(0), itemAt(2)]);
    // The visible overflow row that proves the next page is verified before the
    // limit break, so its evidence is collected too (as p06-registry.test.ts asserts).
    expect(page.manualEvidence).toEqual([
      { id: 'evidence-0', procedureRevision: 'rev-1', validUntil },
      { id: 'evidence-2', procedureRevision: 'rev-1', validUntil },
      { id: 'evidence-4', procedureRevision: 'rev-1', validUntil },
    ]);
    const [createdAt, publicNumber] = (page.nextCursor ?? '').split('~');
    expect([createdAt, publicNumber]).toEqual([itemAt(2).createdAt, itemAt(2).publicNumber]);
    expect(query).toHaveBeenCalledTimes(1);
  });
  it('rescans a full batch of hidden rows with the correct continuation parameters', async () => {
    const createdAt = '2026-11-17T00:00:00.123456Z';
    const validUntil = new Date('2026-11-18T00:00:00.000Z');
    const hiddenRow = (publicNumber: string): RegistryRow => ({ id: `request-${publicNumber}`, publicNumber, createdAt,
      type: 'CALLBACK', status: 'NEW', version: 1, evidenceId: `evidence-${publicNumber}`, procedureRevision: 'rev-1', validUntil });
    const query = vi.fn()
      .mockResolvedValueOnce({ rows: Array.from({ length: 30 }, (_, index) => hiddenRow(String(35 - index))) })
      .mockResolvedValueOnce({ rows: ['5', '4', '3', '2', '1'].map(hiddenRow) });
    const isCurrent = (value: { id: string }) => value.id === 'evidence-4' || value.id === 'evidence-2';
    const page = await readVisibleRegistry(clientOf(query), CITY, parse('limit=1'), isCurrent);
    expect(page.items).toEqual([{ id: 'request-4', publicNumber: '4', createdAt, type: 'CALLBACK', status: 'NEW', version: 1 }]);
    expect(page.manualEvidence.map((value) => value.id)).toEqual(['evidence-4', 'evidence-2']);
    const [cursorCreatedAt, cursorPublicNumber] = (page.nextCursor ?? '').split('~');
    expect([cursorCreatedAt, cursorPublicNumber]).toEqual([createdAt, '4']);
    expect(query).toHaveBeenCalledTimes(2);
    expect(query).toHaveBeenNthCalledWith(2,
      expect.stringContaining('(request.created_at, request.public_number) < ($2::timestamptz, $3::bigint)'),
      [CITY.cityId, createdAt, '6', 30]);
  });
  it('bounds the candidate scan and refuses instead of serving a partial page', async () => {
    const createdAt = '2026-11-17T00:00:00.123456Z';
    const validUntil = new Date('2026-11-18T00:00:00.000Z');
    let serial = 100000;
    const hidden = (): RegistryRow => {
      serial -= 1;
      const publicNumber = String(serial);
      return { id: 'request-' + publicNumber, publicNumber, createdAt, type: 'CALLBACK', status: 'NEW', version: 1,
        evidenceId: 'evidence-' + publicNumber, procedureRevision: 'rev-1', validUntil };
    };
    const batchSizes: number[] = [];
    const query = vi.fn((_sql: string, parameters: readonly unknown[]) => {
      const size = Number(parameters.at(-1));
      batchSizes.push(size);
      return Promise.resolve({ rows: Array.from({ length: size }, () => hidden()) });
    });
    // Every candidate is hidden: the page can never be proven, so the read refuses.
    await expect(readVisibleRegistry(clientOf(query), CITY, parse('limit=1'), () => false)).rejects.toThrow('NOT_READY');
    expect(batchSizes).toEqual([30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 3]);
    expect(batchSizes.reduce((total, size) => total + size, 0)).toBe(513);
  });
  it('returns a complete page even when the candidate budget is exhausted later', async () => {
    const createdAt = '2026-11-17T00:00:00.123456Z';
    let serial = 200000;
    const visible = (): RegistryRow => {
      serial -= 1;
      const publicNumber = String(serial);
      return { id: 'request-' + publicNumber, publicNumber, createdAt, type: 'CALLBACK', status: 'NEW', version: 1,
        evidenceId: null, procedureRevision: null, validUntil: null };
    };
    const query = vi.fn((_sql: string, parameters: readonly unknown[]) => {
      const size = Number(parameters.at(-1));
      return Promise.resolve({ rows: Array.from({ length: size }, () => visible()) });
    });
    const page = await readVisibleRegistry(clientOf(query), CITY, parse('limit=100'), undefined);
    expect(page.items).toHaveLength(100);
    expect(page.nextCursor).not.toBeNull();
    expect(query).toHaveBeenCalledTimes(1);
  });
  it('stops on a short batch below the candidate budget without refusing', async () => {
    const createdAt = '2026-11-17T00:00:00.123456Z';
    const validUntil = new Date('2026-11-18T00:00:00.000Z');
    let serial = 300000;
    const hidden = (): RegistryRow => {
      serial -= 1;
      const publicNumber = String(serial);
      return { id: 'request-' + publicNumber, publicNumber, createdAt, type: 'CALLBACK', status: 'NEW', version: 1,
        evidenceId: 'evidence-' + publicNumber, procedureRevision: 'rev-1', validUntil };
    };
    const batchSizes: number[] = [];
    const query = vi.fn((_sql: string, parameters: readonly unknown[]) => {
      const size = Number(parameters.at(-1));
      batchSizes.push(size);
      const returned = batchSizes.length < 3 ? size : 1;
      return Promise.resolve({ rows: Array.from({ length: returned }, () => hidden()) });
    });
    await expect(readVisibleRegistry(clientOf(query), CITY, parse('limit=1'), () => false))
      .resolves.toEqual({ items: [], manualEvidence: [], nextCursor: null });
    expect(batchSizes).toEqual([30, 30, 30]);
  });  it('readRegistryEvidence refuses partial evidence and returns the exact basis', () => {
    const validUntil = new Date('2026-11-18T00:00:00.000Z');
    expect(readRegistryEvidence({ evidenceId: null, procedureRevision: null, validUntil: null })).toBeNull();
    expect(failureCode(() => readRegistryEvidence({ evidenceId: 'e', procedureRevision: null, validUntil }))).toBe('NOT_READY');
    expect(failureCode(() => readRegistryEvidence({ evidenceId: 'e', procedureRevision: 'rev', validUntil: null }))).toBe('NOT_READY');
    expect(readRegistryEvidence({ evidenceId: 'e', procedureRevision: 'rev', validUntil })).toEqual({ id: 'e', procedureRevision: 'rev', validUntil });
  });
});

const bodyOf = (value: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(value));
const search = (value: unknown) => parseSearch(bodyOf(value));
const rawSearch = (text: string) => parseSearch(new TextEncoder().encode(text));

describe('P06 search contract', () => {
  it('normalizes names to NFC, single ASCII spaces, trimmed lowercase', () => {
    expect(normalizeSearchName('  Иванов   Иван  ')).toBe('иванов иван');
    expect(normalizeSearchName('cafe\u0301')).toBe('caf\u00e9');
    expect(normalizeSearchName('Анна\u00a0\u00a0Петрова')).toBe('анна петрова');
    expect(normalizeSearchName('\u2003Ёлка\u3000')).toBe('ёлка');
    expect(normalizeSearchName('Елена')).toBe('елена');
    expect(normalizeSearchName('Ёлена')).toBe('ёлена');
    expect(normalizeSearchName('Ёлена')).not.toBe(normalizeSearchName('Елена'));
    const normalized = normalizeSearchName('  МАРИЯ   Петровна ');
    expect(normalizeSearchName(normalized)).toBe(normalized);
  });
  it('accepts number, name and phone forms with exact normalized values', () => {
    expect(search({ kind: 'number', query: '0' })).toEqual({ kind: 'number', value: '0' });
    expect(search({ kind: 'number', query: ' 42 ' })).toEqual({ kind: 'number', value: '42' });
    expect(search({ kind: 'number', query: '9223372036854775807' })).toEqual({ kind: 'number', value: '9223372036854775807' });
    expect(search({ kind: 'name', query: '  Иван   Петров ' })).toEqual({ kind: 'name', value: 'иван петров' });
    expect(search({ kind: 'phone', query: '+7 (999) 123-45-67' })).toEqual({ kind: 'phone', value: '+79991234567' });
    expect(search({ kind: 'phone', query: '+7.999.123.45.67' })).toEqual({ kind: 'phone', value: '+79991234567' });
    expect(search({ kind: 'phone', query: '+7\u00a0999\u00a0123\u00a045\u00a067' })).toEqual({ kind: 'phone', value: '+79991234567' });
    expect(search({ kind: 'phone', query: ' +7 999 123 45 67 ' })).toEqual({ kind: 'phone', value: '+79991234567' });
    expect(search({ kind: 'phone', query: '+1234567890' })).toEqual({ kind: 'phone', value: '+1234567890' });
    expect(search({ kind: 'phone', query: '+123456789012345' })).toEqual({ kind: 'phone', value: '+123456789012345' });
  });
  it.each([
    ['leading zero number', { kind: 'number', query: '0123' }], ['zero-padded number', { kind: 'number', query: '00' }],
    ['negative number', { kind: 'number', query: '-1' }], ['exponent number', { kind: 'number', query: '1e3' }],
    ['hex number', { kind: 'number', query: '0x10' }], ['int64 overflow', { kind: 'number', query: '9223372036854775808' }],
    ['20-digit number', { kind: 'number', query: '12345678901234567890' }],
    ['phone without plus', { kind: 'phone', query: '89991234567' }], ['phone with double plus', { kind: 'phone', query: '++79991234567' }],
    ['phone leading zero', { kind: 'phone', query: '+0 999 123 45 67' }], ['phone too short', { kind: 'phone', query: '+123456789' }],
    ['phone too long', { kind: 'phone', query: '+1234567890123456' }], ['empty name', { kind: 'name', query: '   ' }],
    ['nbsp-only name', { kind: 'name', query: '\u00a0\u00a0' }], ['nul control', { kind: 'name', query: 'a\u0000b' }],
    ['bell control', { kind: 'name', query: 'a\u0007b' }], ['del control', { kind: 'name', query: 'a\u007fb' }],
    ['lone surrogate', { kind: 'name', query: 'a\ud800b' }], ['unknown kind', { kind: 'email', query: 'x' }],
    ['extra key', { kind: 'name', query: 'x', extra: 1 }], ['missing key', { kind: 'name' }],
    ['wrong key name', { kind: 'name', value: 'x' }],
  ])('rejects invalid search body: %s', (_label, value) => {
    expect(failureCode(() => search(value))).toBe('INVALID_REQUEST');
  });
  it('rejects oversized, empty, malformed and non-object bodies', () => {
    expect(failureCode(() => search({ kind: 'name', query: 'a'.repeat(257) }))).toBe('INVALID_REQUEST');
    expect(failureCode(() => search({ kind: 'name', query: 'a'.repeat(1025) }))).toBe('INVALID_REQUEST');
    const oversized = bodyOf({ kind: 'name', query: 'a'.repeat(SEARCH_BODY_BYTES) });
    expect(oversized).toHaveLength(SEARCH_BODY_BYTES + 26);
    expect(failureCode(() => parseSearch(oversized))).toBe('INVALID_REQUEST');
    expect(failureCode(() => parseSearch(new Uint8Array(0)))).toBe('INVALID_REQUEST');
    expect(failureCode(() => parseSearch(new Uint8Array([0x7b, 0xff, 0x7d])))).toBe('INVALID_REQUEST');
    for (const text of ['null', '[]', '"x"', '42', 'true', '{', '']) { expect(failureCode(() => rawSearch(text))).toBe('INVALID_REQUEST'); }
    expect(failureCode(() => rawSearch('{"kind":"name","kind":"name","query":"x"}'))).toBe('INVALID_REQUEST');
  });
});

const SNAPSHOT = '018f0000-0000-4000-8000-0000000000aa';
const link = (query: string) => parseDashboardLink(new URLSearchParams(query));

describe('P06 dashboard contract', () => {
  it('returns null without dashboard keys and parses a valid page-aligned link', () => {
    expect([link(''), link('other=1')]).toEqual([null, null]);
    expect([DASHBOARD_PAGE_SIZE, DASHBOARD_CAPACITY]).toEqual([30, 2000]);
    expect(link(`snapshot=${SNAPSHOT}&metric=callbackRequired&offset=0`)).toEqual({ snapshot: SNAPSHOT, metric: 'callbackRequired', offset: 0 });
    expect(link(`snapshot=${SNAPSHOT}&metric=createdToday&offset=30`)).toEqual({ snapshot: SNAPSHOT, metric: 'createdToday', offset: 30 });
    expect(link(`snapshot=${SNAPSHOT}&metric=newRequests&offset=1980`)).toEqual({ snapshot: SNAPSHOT, metric: 'newRequests', offset: 1980 });
    expect(link(`snapshot=${SNAPSHOT}&metric=newRequests`)).toEqual({ snapshot: SNAPSHOT, metric: 'newRequests', offset: 0 });
  });
  it.each([
    'metric=newRequests&offset=0', `snapshot=${SNAPSHOT}&offset=0`,
    `snapshot=${SNAPSHOT}&metric=newRequests&offset=1`, `snapshot=${SNAPSHOT}&metric=newRequests&offset=31`,
    `snapshot=${SNAPSHOT}&metric=newRequests&offset=-0`, `snapshot=${SNAPSHOT}&metric=newRequests&offset=2000`,
    `snapshot=${SNAPSHOT}&metric=newRequests&offset=1e2`, `snapshot=${SNAPSHOT}&metric=newRequests&offset=`,
    `snapshot=${SNAPSHOT}&metric=newRequests&offset=0&offset=0`,
    `snapshot=${SNAPSHOT}&snapshot=${SNAPSHOT}&metric=newRequests&offset=0`,
    `snapshot=${SNAPSHOT}&metric=newRequests&offset=0&foo=1`,
    'snapshot=00000000-0000-3000-8000-0000000000aa&metric=newRequests&offset=0',
    'snapshot=00000000-0000-4000-c000-0000000000aa&metric=newRequests&offset=0',
    'snapshot=not-a-uuid&metric=newRequests&offset=0', `snapshot=${SNAPSHOT}&metric=unassigned&offset=0`,
  ])('rejects invalid dashboard link %s', (query) => {
    expect(failureCode(() => link(query))).toBe('INVALID_REQUEST');
  });
});

const subject: DashboardSubject = { ...CITY, staffId: 'staff-1', sessionId: 'session-1' };
const material = (queues: Partial<Record<ReadyMetric, RegistryItem[]>> = {}): DashboardMaterial => ({
  asOf: '2026-11-17T09:00:00.000000Z',
  localDay: { from: '2026-11-16T21:00:00.000000Z', to: '2026-11-17T21:00:00.000000Z' },
  queues: { newRequests: [], createdToday: [], callbackRequired: [], awaitingChannel: [], readyForAssignment: [], ...queues },
  evidence: [],
});
const snapshotOf = (snapshotId: string, expiresAt: number): DashboardSnapshot => ({ id: snapshotId, subject, material: material(), expiresAt });

describe('P06 dashboard snapshots', () => {
  it('issues a 90-second snapshot bound to the exact subject', () => {
    let now = 1000;
    const store = new DashboardSnapshots(() => now);
    const snapshot = store.issue(subject, material());
    expect(snapshot.expiresAt).toBe(91000);
    store.remember(snapshot);
    expect(store.find(snapshot.id, subject)).toBe(snapshot);
    for (const other of [
      { ...subject, staffId: 'staff-2' }, { ...subject, sessionId: 'session-2' }, { ...subject, cityId: OTHER_ID },
      { ...subject, cityVersionId: OTHER_ID }, { ...subject, timezone: 'UTC' },
    ]) { expect(store.find(snapshot.id, other)).toBeUndefined(); }
    expect(store.find('unknown', subject)).toBeUndefined();
    now = 90999;
    expect(store.find(snapshot.id, subject)).toBe(snapshot);
    now = 91000;
    expect(store.find(snapshot.id, subject)).toBeUndefined();
  });
  it('evicts the oldest live snapshot at capacity 24', () => {
    const store = new DashboardSnapshots(() => 0);
    const kept = new Map<string, DashboardSnapshot>();
    for (let index = 0; index < 24; index += 1) {
      const snapshot = snapshotOf(`s-${String(index)}`, 1000);
      kept.set(snapshot.id, snapshot);
      store.remember(snapshot);
    }
    expect(store.find('s-0', subject)).toBe(kept.get('s-0'));
    const extra = snapshotOf('s-24', 1000);
    store.remember(extra);
    expect([store.find('s-0', subject), store.find('s-1', subject), store.find('s-24', subject)])
      .toEqual([undefined, kept.get('s-1'), extra]);
    const next = snapshotOf('s-25', 1000);
    store.remember(next);
    expect([store.find('s-1', subject), store.find('s-2', subject), store.find('s-25', subject)])
      .toEqual([undefined, kept.get('s-2'), next]);
  });
  it('purges expired snapshots before the capacity eviction', () => {
    const now = 90012;
    const store = new DashboardSnapshots(() => now);
    const kept = new Map<string, DashboardSnapshot>();
    // Insert newest-expiring first: the oldest Map entry is still live while 13
    // earlier-expiring entries are already expired.
    for (let index = 23; index >= 0; index -= 1) {
      const snapshot = snapshotOf(`s-${String(index)}`, 90000 + index);
      kept.set(snapshot.id, snapshot);
      store.remember(snapshot);
    }
    expect(store.find('s-23', subject)).toBe(kept.get('s-23'));
    store.remember(snapshotOf('fresh', 200000));
    expect(store.find('s-23', subject)).toBe(kept.get('s-23'));
    expect(store.find('s-13', subject)).toBe(kept.get('s-13'));
    expect(store.find('s-12', subject)).toBeUndefined();
    expect(store.find('fresh', subject)).toBeDefined();
  });
  it('renders the exact dashboard DTO with ready and unavailable metrics', () => {
    const store = new DashboardSnapshots(() => 0);
    const source = material({
      newRequests: [itemAt(1), itemAt(2)], createdToday: [itemAt(3)],
      callbackRequired: [itemAt(4), itemAt(5), itemAt(6)], readyForAssignment: [itemAt(7)],
    });
    const snapshot = store.issue(subject, source);
    const dto = dashboardDto(snapshot);
    const ready = (metric: ReadyMetric, count: number, basis: string, appliedFilters: unknown) => ({
      state: 'ready', count, basis, appliedFilters, href: `/crm/requests?snapshot=${snapshot.id}&metric=${metric}` });
    expect(dto).toEqual({
      snapshotId: snapshot.id, asOf: source.asOf, definitionsVersion: DASHBOARD_VERSION, cityId: CITY.cityId,
      cityVersionId: CITY.cityVersionId, timezone: CITY.timezone, localDay: source.localDay,
      metrics: {
        newRequests: ready('newRequests', 2, 'queue_status', { statuses: ['NEW'] }),
        createdToday: ready('createdToday', 1, 'city_creation_day', source.localDay),
        callbackRequired: ready('callbackRequired', 3, 'phone_authority', {
          statuses: ['CALLBACK_REQUIRED'], contactMode: 'PHONE', phonePermission: 'active_current_revision', processing: 'current' }),
        awaitingChannel: ready('awaitingChannel', 0, 'queue_status', { statuses: ['WAITING_TELEGRAM_LINK', 'WAITING_CHANNEL_LINK'] }),
        readyForAssignment: ready('readyForAssignment', 1, 'queue_status', { statuses: ['WAITING_ASSIGNMENT'] }),
        unassigned: { state: 'not_ready' }, unconfirmedAssignments: { state: 'not_ready' }, visitsToday: { state: 'not_ready' },
        diagnosisOrApproval: { state: 'not_ready' }, pendingReports: { state: 'not_ready' },
        overdueOrProblem: { state: 'not_ready' }, freeTechnicians: { state: 'not_ready' },
      },
    });
    expect(Object.keys(dto.metrics)).toEqual([...Object.keys(READY_METRICS), ...UNAVAILABLE_METRICS]);
  });
  it('paginates queues by page size and resets on refresh', () => {
    const store = new DashboardSnapshots(() => 0);
    const queue = Array.from({ length: 65 }, (_, index) => itemAt(index));
    const snapshot = store.issue(subject, material({ newRequests: queue }));
    const page = (offset: number, refreshed = false) => dashboardPage(snapshot, { snapshot: snapshot.id, metric: 'newRequests', offset }, refreshed);
    const firstPage = page(0);
    expect([firstPage.items, firstPage.nextOffset, firstPage.refreshed, firstPage.metric, firstPage.snapshot.snapshotId])
      .toEqual([queue.slice(0, 30), 30, false, 'newRequests', snapshot.id]);
    expect([page(30).items, page(30).nextOffset]).toEqual([queue.slice(30, 60), 60]);
    expect([page(60).items, page(60).nextOffset]).toEqual([queue.slice(60), null]);
    expect([page(1980).items, page(1980).nextOffset]).toEqual([[], null]);
    const refreshed = page(60, true);
    expect([refreshed.items, refreshed.nextOffset, refreshed.refreshed]).toEqual([queue.slice(0, 30), 30, true]);
  });
});

const RING = loadKeyring({ kek: [{ keyId: 'kek-unit-1', secretHex: 'a1'.repeat(32) }],
  hmac: [{ keyId: 'hmac-unit-1', secretHex: 'b2'.repeat(32) }], activeKekId: 'kek-unit-1', activeHmacKeyId: 'hmac-unit-1' });
const OTHER_RING = loadKeyring({ kek: [{ keyId: 'kek-unit-2', secretHex: 'c3'.repeat(32) }],
  hmac: [{ keyId: 'hmac-unit-2', secretHex: 'd4'.repeat(32) }], activeKekId: 'kek-unit-2', activeHmacKeyId: 'hmac-unit-2' });
const REF: PayloadKeySlotRef = { environment: 'p05-unit', cellId: '018f0000-0000-4000-8000-0000000000aa',
  requestId: '018f0000-0000-7000-8000-000000000001', kind: 'DETAILS', revision: 1 };
const flip = (value: Buffer): Buffer => { const copy = Buffer.from(value); copy.writeUInt8(copy.readUInt8(0) ^ 0xff, 0); return copy; };
const cipherCode = (run: () => unknown): PayloadCipherErrorCode => {
  try { run(); } catch (error) { if (error instanceof PayloadCipherError) { return error.code; } throw error; }
  throw new Error('expected PayloadCipherError');
};
const keyringCode = (run: () => unknown): string => {
  try { run(); } catch (error) { return error instanceof KeyringError ? error.code : 'NOT_KEYRING'; }
  throw new Error('expected KeyringError');
};

describe('P06 crypto idempotency and managed payload', () => {
  it('derives a deterministic idempotency HMAC per key, namespace and intent', () => {
    const first = idempotencyHmac({ ring: RING, namespace: 'STAFF:1', canonicalIntent: '{"cmd":"submit"}' });
    const second = idempotencyHmac({ ring: RING, namespace: 'STAFF:1', canonicalIntent: '{"cmd":"submit"}' });
    expect(first.keyId).toBe('hmac-unit-1');
    expect(first.digest).toHaveLength(32);
    expect(first.digest.equals(second.digest)).toBe(true);
    expect(idempotencyHmac({ ring: RING, namespace: 'STAFF:2', canonicalIntent: '{"cmd":"submit"}' }).digest.equals(first.digest)).toBe(false);
    expect(idempotencyHmac({ ring: RING, namespace: 'STAFF:1', canonicalIntent: '{"cmd":"repair"}' }).digest.equals(first.digest)).toBe(false);
    const other = idempotencyHmac({ ring: OTHER_RING, namespace: 'STAFF:1', canonicalIntent: '{"cmd":"submit"}' });
    expect([other.keyId, other.digest.equals(first.digest)]).toEqual(['hmac-unit-2', false]);
  });
  it('verifies by saved keyId and refuses tampered, mis-scoped and wrong-length digests', () => {
    const { keyId, digest } = idempotencyHmac({ ring: RING, namespace: 'STAFF:1', canonicalIntent: 'x' });
    const verify = (input: { namespace?: string; canonicalIntent?: string; digest?: Buffer }) => verifyIdempotencyHmac({
      ring: RING, keyId, namespace: input.namespace ?? 'STAFF:1', canonicalIntent: input.canonicalIntent ?? 'x', digest: input.digest ?? digest });
    expect([verify({}), verify({ digest: flip(digest) }), verify({ namespace: 'STAFF:2' }), verify({ canonicalIntent: 'y' }),
      verify({ digest: digest.subarray(0, 31) })]).toEqual([true, false, false, false, false]);
    // Unknown keyId fails closed by throwing, never by silently returning false.
    expect(keyringCode(() => verifyIdempotencyHmac({ ring: RING, keyId: 'hmac-unknown-1', namespace: 'STAFF:1', canonicalIntent: 'x', digest })))
      .toBe('UNKNOWN_KEY');
  });
  it('seals, opens and binds a managed DETAILS payload without exposing plaintext', () => {
    const plaintext = Buffer.from('{"details":"unit"}');
    const sealed = sealManagedPayload(REF, RING, plaintext);
    expect(sealed.keyId).toBe('kek-unit-1');
    expect(sealed.ciphertext).toHaveLength(plaintext.length);
    expect(sealed.ciphertext.includes(plaintext)).toBe(false);
    expect(MANAGED_PAYLOAD_KEY_MARKER).toBe('p05-managed-slot-v1');
    expect(openManagedPayload(REF, RING, sealed, sealed).equals(plaintext)).toBe(true);
    const cases: readonly [string, PayloadCipherErrorCode, () => Buffer][] = [
      ['revision', 'DOMAIN_MISMATCH', () => openManagedPayload({ ...REF, revision: 2 }, RING, sealed, sealed)],
      ['requestId', 'DOMAIN_MISMATCH', () => openManagedPayload({ ...REF, requestId: '018f0000-0000-7000-8000-000000000002' }, RING, sealed, sealed)],
      ['kind', 'DOMAIN_MISMATCH', () => openManagedPayload({ ...REF, kind: 'ADDRESS' }, RING, sealed, sealed)],
      ['environment', 'DOMAIN_MISMATCH', () => openManagedPayload({ ...REF, environment: 'other' }, RING, sealed, sealed)],
      ['cellId', 'TAMPERED', () => openManagedPayload({ ...REF, cellId: '018f0000-0000-4000-8000-0000000000bb' }, RING, sealed, sealed)],
      ['authTag', 'TAMPERED', () => openManagedPayload(REF, RING, { ...sealed, authTag: flip(sealed.authTag) }, sealed)],
      ['ciphertext', 'TAMPERED', () => openManagedPayload(REF, RING, { ...sealed, ciphertext: flip(sealed.ciphertext) }, sealed)],
    ];
    for (const [label, expected, run] of cases) { expect(cipherCode(run), label).toBe(expected); }
  });

  it('preserves the P05 authorization refusal from the final pre-decrypt recheck', async () => {
    const read = vi.fn(() => Promise.resolve({ keyId:'kek-unit-1',wrappedDek:Buffer.alloc(60) }));
    const slots: PayloadKeySlots = {
      environment:COMMENT_KEY_ENVIRONMENT,
      create:() => Promise.resolve(),
      read,
    };
    const comment = { id:id(30),version:1,nonce:Buffer.alloc(12),ciphertext:Buffer.alloc(16),
      authTag:Buffer.alloc(16),aadContext:'unit',createdAt:'2026-11-28T00:00:00.000000Z' };
    const client = { query:vi.fn(() => Promise.resolve({rows:[comment]})) };
    const staff = { client } as unknown as Parameters<typeof readInternalComments>[0];
    const request = { id:id(31) } as unknown as Parameters<typeof readInternalComments>[1];
    const refusal = new RequestFailure('FORBIDDEN');
    await expect(readInternalComments(staff,request,{ring:RING,keySlots:slots},() => Promise.reject(refusal)))
      .rejects.toBe(refusal);
    expect(read).toHaveBeenCalledOnce();
  });
});
