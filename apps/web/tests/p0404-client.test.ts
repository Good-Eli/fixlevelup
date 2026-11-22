import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, type Identity } from '../app/crm/access/api';
import { p04Transport, prepareP04Command, readP04, sendPreparedP04 } from '../app/crm/access/p04/client';
import { p04Tabs } from '../app/crm/access/p04/workspace';
import { FormError, SessionChanged } from '../app/crm/access/p0305-client';

const actor: Identity = { staffId: '11111111-1111-4111-8111-111111111111', csrf: 'x'.repeat(43), authVersion: 3 };
const category = '22222222-2222-4222-8222-222222222222';
const revision = '33333333-3333-4333-8333-333333333333';
const city = '44444444-4444-4444-8444-444444444444';
const other = '55555555-5555-4555-8555-555555555555';
const signal = () => new AbortController().signal;
const meta = { requestId: actor.staffId };
const receipt = { id: category, version: 3, revisionId: revision, revisionVersion: 2 };
const edit = () => ({ params: { id: category }, body: { title: 'Synthetic report' }, expectedVersion: 2 });
const reply = (data: unknown, status: number, tag?: string) => Response.json({ data, meta }, { status,
  headers: { 'cache-control': 'no-store', ...(tag === undefined ? {} : { etag: tag }) } });
const failure = (status: number, data: unknown = { type: 'about:blank', status, title: 'EXPECTED', code: 'EXPECTED', requestId: revision }) =>
  Response.json(data, { status, headers: { 'cache-control': 'no-store', 'content-type': 'application/problem+json' } });
function mock(...responses: Response[]) {
  const fetch = vi.fn<typeof globalThis.fetch>();
  for (const response of responses) { fetch.mockResolvedValueOnce(response); }
  vi.stubGlobal('fetch', fetch);
  return fetch;
}
afterEach(() => { vi.unstubAllGlobals(); });

describe('P04 CRM exact generated transport', () => {
  it('creates one frozen generated request, never sends until explicit call, and retains the exact wire after uncertainty', async () => {
    const fetch = mock(failure(503), reply(receipt, 200, '"p04-v3"'));
    const input = edit();
    const command = await prepareP04Command('categoryPublish', input, actor);
    input.body.title = 'Changed draft must not escape'; input.expectedVersion = 99; input.params.id = other;
    expect(fetch).not.toHaveBeenCalled();
    await expect(sendPreparedP04(signal(), actor, command)).rejects.toMatchObject({ status: 503 });
    expect(fetch).toHaveBeenCalledTimes(1);
    const call = fetch.mock.calls[0];
    await sendPreparedP04(signal(), actor, command);
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(call?.[0]).toBe(`/api/v1/catalog/categories/${category}/versions`);
    expect(call?.[1]).toMatchObject({ body: '{"title":"Synthetic report"}', credentials: 'same-origin', mode: 'same-origin', cache: 'no-store', redirect: 'error', method: 'POST' });
    const headers = new Headers(call?.[1]?.headers);
    expect(headers.get('if-match')).toBe('"p04-v2"');
    expect(headers.get('idempotency-key')).toMatch(/^[a-f0-9-]{36}$/u);
    expect(headers.get('x-csrf-token') === actor.csrf).toBe(true);
    const second = fetch.mock.calls[1];
    expect([second?.[0], second?.[1]?.headers, second?.[1]?.body]).toEqual([call?.[0], call?.[1]?.headers, call?.[1]?.body]);
  });

  it('rejects bad operation inputs, canceled work and another cookie/session before network I/O', async () => {
    const fetch = mock();
    for (const input of [{ ...edit(), expectedVersion: 0 }, { ...edit(), body: { title: 'Test', extra: 'bad' } },
      { ...edit(), params: { id: 'https://example.test' } }]) {
      await expect(prepareP04Command('categoryPublish', input, actor)).rejects.toBeInstanceOf(FormError);
    }
    const command = await prepareP04Command('categoryPublish', edit(), actor);
    for (const next of [{ ...actor, csrf: 'y'.repeat(43) }, { ...actor, staffId: other }, { ...actor, authVersion: 4 }]) {
      await expect(sendPreparedP04(signal(), next, command)).rejects.toBeInstanceOf(SessionChanged);
    }
    const aborted = new AbortController(); aborted.abort();
    await expect(sendPreparedP04(aborted.signal, actor, command)).rejects.toThrow();
    await expect(p04Transport(signal())({ operation: 'cityList', method: 'GET', path: '//example.test/api/v1/pricing/cities', headers: {} })).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('does not treat an unverified problem, wrong target, wrong version/ETag, or oversize body as a valid receipt', async () => {
    mock(failure(412, { title: 'Synthetic non-contract proxy page' }), reply({ ...receipt, id: other }, 201, '"p04-v3"'),
      reply({ ...receipt, version: 4 }, 200, '"p04-v4"'), reply(receipt, 201, '"p03-v3"'),
      new Response(' '.repeat(4097), { status: 201, headers: { 'cache-control': 'no-store', 'content-type': 'application/json' } }),
      failure(412));
    for (let index = 0; index < 5; index++) {
      const command = await prepareP04Command('categoryPublish', edit(), actor);
      await expect(sendPreparedP04(signal(), actor, command)).rejects.not.toHaveProperty('status');
    }
    const command = await prepareP04Command('categoryPublish', edit(), actor);
    await expect(sendPreparedP04(signal(), actor, command)).rejects.toMatchObject({ status: 412 });
  });

  it.each(['fixedClose','fixedReplace','ruleVersionClose','policyClose'] as const)('binds %s receipts locally to the reviewed stream, including replay', async op => {
    const at = '2030-01-01T00:00:00.000Z';
    const extra = op === 'fixedReplace' ? { revisionId: other, revisionVersion: 2 } : {};
    const fetch = mock(reply({ id: other, version: 2, ...extra }, 200, '"p04-v2"'),
      reply({ id: category, version: 2, ...extra }, 200, '"p04-v2"'));
    const params = { cityId: city, versionId: revision };
    const common = { expectedVersion: 1, receiptSeriesId: category };
    const command = op === 'fixedClose' ? await prepareP04Command(op, { ...common, params: { ...params, itemId: other }, body: { at } }, actor)
      : op === 'fixedReplace' ? await prepareP04Command(op, { ...common, params: { ...params, itemId: other },
        body: { at, amountMinor: '1', sourceRef: 'Synthetic proof', currency: 'RUB' } }, actor)
      : op === 'ruleVersionClose' ? await prepareP04Command(op, { ...common, params: { ...params, ruleId: other }, body: { at } }, actor)
      : await prepareP04Command(op, { ...common, params, body: { at } }, actor);
    await expect(sendPreparedP04(signal(), actor, command)).rejects.toThrow('Invalid staff receipt');
    expect(fetch).toHaveBeenCalledTimes(1);
    await expect(sendPreparedP04(signal(), actor, command)).resolves.toBeUndefined();
    expect(fetch).toHaveBeenCalledTimes(2);
    const [first, second] = fetch.mock.calls;
    expect([first?.[0], first?.[1]?.headers, first?.[1]?.body]).toEqual([second?.[0], second?.[1]?.headers, second?.[1]?.body]);
    expect(JSON.stringify(first?.[1]?.headers)).not.toContain(category);
    expect(first?.[1]?.body).not.toContain('receiptSeriesId');
    expect(first?.[0]).not.toContain(category);
  });

  it.each([
    'fixedPublish', 'fixedReplace', 'ruleVersionPublish', 'ruleVersionReplace',
    'policyPublish', 'policyReplace', 'estimatePublish', 'estimateReplace',
  ] as const)('rejects impossible %s revision receipts on both initial response and replay', async op => {
    const at = '2030-01-01T00:00:00.000Z';
    const dates = { sourceRef: 'Synthetic proof', currency: 'RUB' };
    const price = { ...dates, amountMinor: '1' };
    const rule = { ...dates, kind: 'EXPRESS' as const, method: 'FIXED' as const, fixedMinor: '1',
      title: 'Synthetic rule', base: 'WORKS' as const, categoryIds: [] };
    const policy = { ...dates, units: { piece: 0 }, maxManualDeltaMinor: '0', roundingMode: 'HALF_UP' as const,
      taxDisplay: 'Synthetic policy', priorities: [], compatibilities: [] };
    const estimate = { ...dates, minMinor: '0', maxMinor: '1', title: 'Synthetic range', disclaimer: 'Not a price' };
    const cityParams = { cityId: city };
    const fixedParams = { ...cityParams, itemId: other };
    const ruleParams = { ...cityParams, ruleId: other };
    const estimateParams = { ...cityParams, estimateId: category };
    const common = { expectedVersion: 2, receiptSeriesId: category };
    const replaces = op.endsWith('Replace');
    const made = { id: category, version: 3, revisionId: other, revisionVersion: 3 };
    const fetch = mock(reply({ ...made, revisionVersion: 1 }, 201, '"p04-v3"'),
      reply(replaces ? { ...made, revisionId: revision } : { ...made, revisionVersion: 2 }, 200, '"p04-v3"'),
      reply(made, 200, '"p04-v3"'));
    const prepare = {
      fixedPublish: () => prepareP04Command('fixedPublish', { ...common, params: fixedParams, body: { ...price, validFrom: at } }, actor),
      fixedReplace: () => prepareP04Command('fixedReplace', { ...common, params: { ...fixedParams, versionId: revision }, body: { ...price, at } }, actor),
      ruleVersionPublish: () => prepareP04Command('ruleVersionPublish', { ...common, params: ruleParams, body: { ...rule, validFrom: at } }, actor),
      ruleVersionReplace: () => prepareP04Command('ruleVersionReplace', { ...common, params: { ...ruleParams, versionId: revision }, body: { ...rule, at } }, actor),
      policyPublish: () => prepareP04Command('policyPublish', { ...common, params: cityParams, body: { ...policy, validFrom: at } }, actor),
      policyReplace: () => prepareP04Command('policyReplace', { ...common, params: { ...cityParams, versionId: revision }, body: { ...policy, at } }, actor),
      estimatePublish: () => prepareP04Command('estimatePublish', { expectedVersion: 2, params: estimateParams, body: { ...estimate, validFrom: at } }, actor),
      estimateReplace: () => prepareP04Command('estimateReplace', { expectedVersion: 2, params: { ...estimateParams, versionId: revision }, body: { ...estimate, at } }, actor),
    };
    const command = await prepare[op]();
    await expect(sendPreparedP04(signal(), actor, command)).rejects.toThrow('Invalid staff receipt');
    expect(fetch).toHaveBeenCalledTimes(1);
    await expect(sendPreparedP04(signal(), actor, command)).rejects.toThrow('Invalid staff receipt');
    expect(fetch).toHaveBeenCalledTimes(2);
    await expect(sendPreparedP04(signal(), actor, command)).resolves.toBeUndefined();
    expect(fetch).toHaveBeenCalledTimes(3);
    const calls = fetch.mock.calls.map(([url, init]) => [url, init?.headers, init?.body]);
    expect(calls[1]).toEqual(calls[0]); expect(calls[2]).toEqual(calls[0]);
  });

  it('does not allow an existing stream publication to omit its expected receipt identity', async () => {
    const fetch = mock();
    const input = { params: { cityId: city, itemId: other }, body: { validFrom: '2030-01-01T00:00:00.000Z',
      amountMinor: '1', sourceRef: 'Synthetic proof', currency: 'RUB' }, expectedVersion: 1, receiptSeriesId: null };
    await expect(prepareP04Command('fixedPublish', input, actor)).rejects.toBeInstanceOf(FormError);
    await expect(prepareP04Command('fixedPublish', { ...input, expectedVersion: 0, receiptSeriesId: category }, actor)).rejects.toBeInstanceOf(FormError);
    await expect(prepareP04Command('fixedPublish', { ...input, expectedVersion: 0 }, actor)).resolves.toHaveProperty('family', 'P04');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('binds exact/history reads to requested immutable parents and rejects extra fields or private cache drift', async () => {
    const summary = { id: revision, title: 'Synthetic title', version: 1, publishedAt: '2026-11-22T10:15:00.000Z', entryId: category };
    const version = { ...summary, description: null };
    mock(reply({ ...version, entryId: other }, 200), reply({ ...version, id: other }, 200), reply({ ...version, internal: 'not projected' }, 200),
      reply({ version: 2, items: [summary, summary], pageInfo: { nextCursor: null } }, 200),
      Response.json({ data: version, meta }), reply(version, 200));
    const exact = () => readP04(signal(), 'categoryVersion', { params: { id: category, versionId: revision } });
    for (let index = 0; index < 3; index++) { await expect(exact()).rejects.toThrow(); }
    await expect(readP04(signal(), 'categoryVersions', { params: { id: category } })).rejects.toThrow('Duplicate');
    await expect(exact()).rejects.toThrow('not private');
    await expect(exact()).resolves.toEqual(version);
  });

  it('decodes only bounded own-city hints with actual scoped pricing read capability', async () => {
    const base = { staffId: actor.staffId, role: { id: actor.staffId, type: 'SYSTEM', code: 'ADMIN' }, permissions: ['pricing.read'] };
    const mixed = { ...base, p04Permissions: [{ code: 'pricing.read', scope: 'GLOBAL' }, { code: 'pricing.manage', scope: 'CITY' }] };
    mock(reply(base, 200), reply({ ...mixed, p04PricingWriteCityIds: [city] }, 200),
      reply({ ...mixed, p04PricingWriteCityIds: [city, city] }, 200), reply({ ...base, p04PricingWriteCityIds: [city] }, 200),
      reply({ ...mixed, p04PricingWriteCityIds: Array.from({ length: 129 }, () => city) }, 200));
    const access = api(signal()).access;
    expect(p04Tabs(await access())).toEqual([]);
    const view = await access();
    expect(view.p04PricingWriteCityIds).toEqual([city]);
    expect(p04Tabs(view).map(entry => entry.id)).toEqual(['pricing']);
    for (let index = 0; index < 3; index++) { await expect(access()).rejects.toThrow(); }
  });
});
