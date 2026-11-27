/**
 * KNOWN GAP: readRegistryItem delegates id/publicNumber/type/status/version to
 * decodeP05StaffRequestData before its own RegistryError checks, so malformed
 * staff-request fields escape as P05DecodeError, not the documented
 * RegistryError. Production code is untouched; the tests assert the real P05
 * contract error for those branches.
 *
 * NOTE: P05 endpoints answer with a bare `{data}` envelope; the P03/P04
 * `{data, meta}` fixture shape is rejected, so these fixtures send `{data}`.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { P05DecodeError } from '@fixlevelup/p03-contracts/p05';
import {
  RegistryError, RequestCardError, RequestPanelHttpError,
  addRequestComment, readRegistry, readRegistryOptions, readRequestCard, readRequestComments,
  readRequestContactDetails, readRequestEvents, searchRegistry,
} from '../app/crm/requests/client';
import { DashboardError, readDashboard, readSnapshot } from '../app/crm/dashboard/client';
import { readyMetrics, snapshotHref, unavailableMetrics, type ReadyMetric } from '../app/crm/dashboard/metrics';

const uuid = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const REQUEST_ID = uuid(1);
const OTHER_ID = uuid(2);
const SNAPSHOT_ID = uuid(3);
const OLD_SNAPSHOT_ID = uuid(4);
const CITY_ID = uuid(5);
const CITY_VERSION_ID = uuid(6);
const COMMENT_ID = uuid(7);
const ETAG = `"p05-r1-${'a'.repeat(64)}"`;
const CSRF = 'c'.repeat(43);
const COMMENT_CSRF = 'k'.repeat(43);
const CREATED_AT = '2026-11-27T10:00:00.123456Z';
const AS_OF = '2026-11-27T12:00:00.000000Z';
const DAY_FROM = '2026-11-27T00:00:00.000000Z';
const DAY_TO = '2026-11-28T00:00:00.000000Z';

const signal = () => new AbortController().signal;
const reply = (data: unknown, status = 200) => Response.json({ data }, { status });
function mock(...responses: Response[]) {
  const fetch = vi.fn<typeof globalThis.fetch>();
  for (const response of responses) { fetch.mockResolvedValueOnce(response); }
  vi.stubGlobal('fetch', fetch);
  return fetch;
}
afterEach(() => { vi.unstubAllGlobals(); });

type RegistryItem = { id: string; publicNumber: string; type: string; status: string; version: number; createdAt: string };
const registryItem = (overrides: Partial<RegistryItem> = {}): RegistryItem => ({
  id: REQUEST_ID, publicNumber: '1001', type: 'REPAIR', status: 'NEW', version: 1, createdAt: CREATED_AT, ...overrides,
});

describe('P06 registry decoders', () => {
  it('decodes a valid registry page', async () => {
    const fetch = mock(reply({ items: [registryItem()], nextCursor: null }));
    const page = await readRegistry(new URLSearchParams({ status: 'NEW' }), signal());
    expect(page).toEqual({ items: [registryItem()], nextCursor: null });
    expect(fetch.mock.calls[0]?.[0]).toBe('/api/v1/requests?status=NEW');
  });

  it('rejects malformed registry pages with RegistryError', async () => {
    const pages: unknown[] = [
      { items: {}, nextCursor: null },
      { items: Array.from({ length: 101 }, () => registryItem()), nextCursor: null },
      { items: [], nextCursor: 1 },
      { items: [], nextCursor: '' },
      { items: [], nextCursor: 'x'.repeat(257) },
      { items: [{ ...registryItem(), extra: true }], nextCursor: null },
      { items: [{ id: REQUEST_ID, publicNumber: '1001', type: 'REPAIR', status: 'NEW', version: 1 }], nextCursor: null },
      { items: [registryItem({ createdAt: '2026-11-27T10:00:00.123Z' })], nextCursor: null },
    ];
    mock(...pages.map(page => reply(page)));
    await Promise.all(pages.map(() => expect(readRegistry(new URLSearchParams(), signal())).rejects.toBeInstanceOf(RegistryError)));
  });

  it('surfaces P05 contract errors for malformed staff request fields (KNOWN GAP)', async () => {
    const items = [
      registryItem({ status: 'UNKNOWN' }),
      registryItem({ type: 'OTHER' }),
      registryItem({ version: 0 }),
      registryItem({ version: 1.5 }),
      registryItem({ publicNumber: '0123' }),
      registryItem({ id: 'not-a-uuid' }),
    ];
    mock(...items.map(item => reply({ items: [item], nextCursor: null })));
    await Promise.all(items.map(() => expect(readRegistry(new URLSearchParams(), signal())).rejects.toBeInstanceOf(P05DecodeError)));
  });

  it.each([
    [401, 'Войдите в CRM, чтобы открыть реестр.'],
    [403, 'Реестр недоступен для этой учётной записи.'],
    [404, 'Реестр недоступен для этой учётной записи.'],
    [400, 'Проверьте фильтры или начните просмотр с первой страницы.'],
    [500, 'Реестр временно недоступен.'],
  ] as const)('maps registry HTTP %i to its exact message', async (status, message) => {
    mock(new Response(null, { status }));
    const error: unknown = await readRegistry(new URLSearchParams(), signal()).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(RegistryError);
    expect((error as Error).message).toBe(message);
  });
});

describe('P06 registry search decoder', () => {
  it('posts an exact registry search and decodes the bounded result', async () => {
    const fetch = mock(reply({ items: [registryItem()], truncated: false }));
    const result = await searchRegistry('phone', '+7 999', signal());
    expect(result).toEqual({ items: [registryItem()], truncated: false });
    const call = fetch.mock.calls[0];
    expect(call?.[0]).toBe('/api/v1/requests/search');
    expect(typeof call?.[0] === 'string' && call[0].includes('?')).toBe(false);
    expect(call?.[1]).toMatchObject({
      method: 'POST', body: '{"kind":"phone","query":"+7 999"}',
      cache: 'no-store', credentials: 'same-origin', mode: 'same-origin', redirect: 'error',
    });
    const headers = new Headers(call?.[1]?.headers);
    expect(headers.get('accept')).toBe('application/json');
    expect(headers.get('content-type')).toBe('application/json');
    expect(headers.get('x-auth-request')).toBe('1');
  });

  it.each([
    [400, 'Проверьте поисковый запрос.'],
    [422, 'Проверьте поисковый запрос.'],
    [401, 'Поиск недоступен.'],
    [403, 'Поиск недоступен.'],
    [404, 'Поиск недоступен.'],
    [429, 'Слишком много запросов. Повторите поиск позже.'],
    [500, 'Поиск временно недоступен.'],
  ] as const)('maps search HTTP %i to its exact message', async (status, message) => {
    mock(reply(null, status));
    const error: unknown = await searchRegistry('name', 'x', signal()).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(RegistryError);
    expect((error as Error).message).toBe(message);
  });

  it('rejects a non-JSON search response and out-of-contract result shapes', async () => {
    const responses = [
      new Response('{}', { status: 200, headers: { 'content-type': 'text/plain' } }),
      reply({ items: Array.from({ length: 51 }, () => registryItem()), truncated: false }),
      reply({ items: [], truncated: 'no' }),
      reply({ items: [{ ...registryItem(), extra: true }], truncated: false }),
    ];
    mock(...responses);
    await Promise.all(responses.map(() => expect(searchRegistry('number', '1001', signal())).rejects.toBeInstanceOf(RegistryError)));
  });
});

describe('P06 registry options decoder', () => {
  const optionsPayload = () => ({
    categories: [{ id: uuid(10), name: 'Ремонт' }],
    districts: [{ id: uuid(11), name: 'Центральный' }],
    sources: [{ id: uuid(12), name: 'Сайт' }],
    unavailable: { technician: 'not_ready', payment: 'not_ready', alert: 'not_ready' },
  });

  it('accepts a valid registry options payload', async () => {
    mock(reply(optionsPayload()));
    await expect(readRegistryOptions(signal())).resolves.toEqual({
      categories: [{ id: uuid(10), name: 'Ремонт' }],
      districts: [{ id: uuid(11), name: 'Центральный' }],
      sources: [{ id: uuid(12), name: 'Сайт' }],
    });
  });

  it('rejects unavailable sections that are not exactly not_ready and bad choices', async () => {
    const payloads = [
      { ...optionsPayload(), unavailable: { technician: 'ready', payment: 'not_ready', alert: 'not_ready' } },
      { ...optionsPayload(), unavailable: { technician: 'NOT_READY', payment: 'not_ready', alert: 'not_ready' } },
      { ...optionsPayload(), categories: [{ id: 'not-a-uuid', name: 'X' }] },
      { ...optionsPayload(), districts: [{ id: uuid(11), name: '   ' }] },
    ];
    mock(...payloads.map(payload => reply(payload)));
    await Promise.all(payloads.map(() => expect(readRegistryOptions(signal())).rejects.toBeInstanceOf(RegistryError)));
  });
});

const notReadySections = {
  appointments: 'not_ready', quotes: 'not_ready', reports: 'not_ready', payments: 'not_ready', messages: 'not_ready', attachments: 'not_ready',
} as const;
const sections = (comments: string = 'available', contactDetails: string = 'available') => ({ ...notReadySections, comments, contactDetails });

type FullCard = {
  id: string; publicNumber: string; type: string; status: string; version: number; createdAt: string; contactMode: unknown;
  provider: unknown; facts: Record<string, unknown>; canStartReview: boolean; unavailable: Record<string, unknown>;
};
const fullCard = (overrides: Partial<FullCard> = {}): FullCard => ({
  id: REQUEST_ID, publicNumber: '1001', type: 'REPAIR', status: 'NEW', version: 3,
  createdAt: CREATED_AT, contactMode: 'PHONE', provider: 'TG',
  facts: { source: null, category: null, district: null, urgency: 'URGENT', coverage: 'IN_ZONE' },
  canStartReview: true, unavailable: sections(), ...overrides,
});
const cardReply = (data: unknown, headers: Record<string, string> = {}) => Response.json({ data }, { headers });
async function readFullCard() {
  const card = await readRequestCard(REQUEST_ID, signal());
  if (card.kind !== 'full') { throw new Error('Expected a full card representation'); }
  return card;
}

describe('P06 request card decoder', () => {
  it('decodes the restricted card representation', async () => {
    mock(cardReply({ version: 7 }));
    await expect(readRequestCard(REQUEST_ID, signal())).resolves.toEqual({ kind: 'restricted', version: 7 });
  });

  it('decodes a full card with the exact projection and command proofs', async () => {
    mock(cardReply(fullCard(), { 'x-command-etag': ETAG, 'x-command-csrf': CSRF, 'x-comment-csrf': COMMENT_CSRF }));
    const card = await readFullCard();
    expect(Object.keys(card).sort()).toEqual([
      'addComment', 'canStartReview', 'commentsAvailable', 'contactDetailsAvailable', 'contactMode',
      'createdAt', 'facts', 'id', 'kind', 'provider', 'publicNumber', 'startReview', 'status', 'type', 'version',
    ].sort());
    expect(card).toEqual({
      kind: 'full', id: REQUEST_ID, publicNumber: '1001', type: 'REPAIR', status: 'NEW', version: 3,
      createdAt: CREATED_AT, contactMode: 'PHONE', provider: 'TG',
      facts: { source: null, category: null, district: null, urgency: 'URGENT', coverage: 'IN_ZONE' },
      canStartReview: true, startReview: { etag: ETAG, csrf: CSRF },
      commentsAvailable: true, contactDetailsAvailable: true,
      addComment: { etag: ETAG, csrf: COMMENT_CSRF },
    });
  });

  it('gates startReview and addComment proofs on headers and section state', async () => {
    mock(
      cardReply(fullCard({ canStartReview: false }), { 'x-command-etag': ETAG, 'x-command-csrf': CSRF, 'x-comment-csrf': COMMENT_CSRF }),
      cardReply(fullCard(), { 'x-command-etag': 'not-an-etag', 'x-command-csrf': CSRF, 'x-comment-csrf': COMMENT_CSRF }),
      cardReply(fullCard(), { 'x-command-etag': ETAG, 'x-command-csrf': 'short', 'x-comment-csrf': COMMENT_CSRF }),
      cardReply(fullCard({ unavailable: sections('not_ready', 'not_ready') }), { 'x-command-etag': ETAG, 'x-command-csrf': CSRF }),
      cardReply(fullCard(), { 'x-command-etag': ETAG, 'x-command-csrf': CSRF, 'x-comment-csrf': 'bad' }),
    );
    const withoutStartReview = await readFullCard();
    expect(withoutStartReview.startReview).toBeNull();
    expect(withoutStartReview.addComment).toEqual({ etag: ETAG, csrf: COMMENT_CSRF });
    const badEtag = await readFullCard();
    expect(badEtag.startReview).toBeNull();
    expect(badEtag.addComment).toBeNull();
    const shortCsrf = await readFullCard();
    expect(shortCsrf.startReview).toBeNull();
    expect(shortCsrf.addComment).toEqual({ etag: ETAG, csrf: COMMENT_CSRF });
    const unavailableSections = await readFullCard();
    expect(unavailableSections.startReview).toEqual({ etag: ETAG, csrf: CSRF });
    expect(unavailableSections.commentsAvailable).toBe(false);
    expect(unavailableSections.contactDetailsAvailable).toBe(false);
    expect(unavailableSections.addComment).toBeNull();
    const badCommentCsrf = await readFullCard();
    expect(badCommentCsrf.startReview).toEqual({ etag: ETAG, csrf: CSRF });
    expect(badCommentCsrf.addComment).toBeNull();
  });

  it('rejects wrong id echo, timestamps, enums, sections and facts', async () => {
    const cards = [
      fullCard({ id: OTHER_ID }),
      fullCard({ createdAt: '2026-11-27T10:00:00Z' }),
      fullCard({ contactMode: 'EMAIL' }),
      fullCard({ provider: 'WA' }),
      fullCard({ unavailable: { ...sections(), appointments: 'pending' } }),
      fullCard({ unavailable: { ...sections(), messages: 'available' } }),
      fullCard({ facts: { source: null, category: null, district: null, urgency: 'SOON', coverage: 'IN_ZONE' } }),
      fullCard({ facts: { source: null, category: null, district: null, urgency: 'URGENT', coverage: 'MAYBE' } }),
    ];
    mock(...cards.map(card => cardReply(card)));
    await Promise.all(cards.map(() => expect(readRequestCard(REQUEST_ID, signal())).rejects.toBeInstanceOf(RequestCardError)));
  });
});

type Comment = { id: string; version: number; createdAt: string; text: string };
const comment = (overrides: Partial<Comment> = {}): Comment => ({
  id: COMMENT_ID, version: 2, createdAt: CREATED_AT, text: 'Synthetic comment', ...overrides,
});

describe('P06 request comments decoders', () => {
  it('decodes bounded request comments', async () => {
    mock(reply({ items: [comment()] }));
    await expect(readRequestComments(REQUEST_ID, signal())).resolves.toEqual([comment()]);
  });

  it('rejects empty/oversized comment text and too many comments', async () => {
    const payloads = [
      { items: [comment({ text: '' })] },
      { items: [comment({ text: '   ' })] },
      { items: [comment({ text: 'x'.repeat(4001) })] },
      { items: Array.from({ length: 51 }, () => comment()) },
    ];
    mock(...payloads.map(payload => reply(payload)));
    await Promise.all(payloads.map(() => expect(readRequestComments(REQUEST_ID, signal())).rejects.toBeInstanceOf(RequestCardError)));
  });

  it('posts a comment with proof headers and accepts 200/201 receipts', async () => {
    const receipt = { id: COMMENT_ID, version: 3, createdAt: CREATED_AT };
    const fetch = mock(reply(receipt, 201), reply(receipt, 200));
    await expect(addRequestComment(REQUEST_ID, { etag: ETAG, csrf: CSRF }, 'idem-1', 'Synthetic comment', signal()))
      .resolves.toEqual(receipt);
    const call = fetch.mock.calls[0];
    expect(call?.[0]).toBe(`/api/v1/requests/${REQUEST_ID}/comments`);
    expect(call?.[1]).toMatchObject({
      method: 'POST', body: '{"text":"Synthetic comment"}',
      cache: 'no-store', credentials: 'same-origin', mode: 'same-origin', redirect: 'error',
    });
    const headers = new Headers(call?.[1]?.headers);
    expect(headers.get('accept')).toBe('application/json');
    expect(headers.get('content-type')).toBe('application/json');
    expect(headers.get('x-csrf-token')).toBe(CSRF);
    expect(headers.get('if-match')).toBe(ETAG);
    expect(headers.get('idempotency-key')).toBe('idem-1');
    await expect(addRequestComment(REQUEST_ID, { etag: ETAG, csrf: CSRF }, 'idem-2', 'Synthetic comment', signal()))
      .resolves.toEqual(receipt);
  });

  it.each([412, 409, 503] as const)('throws RequestPanelHttpError %i for a refused comment', async status => {
    mock(reply(null, status));
    const error: unknown = await addRequestComment(REQUEST_ID, { etag: ETAG, csrf: CSRF }, 'idem-3', 'Synthetic comment', signal())
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(RequestPanelHttpError);
    expect(error).toMatchObject({ status });
  });
});

describe('P06 request contact details decoder', () => {
  it('accepts no-call and phone contact details', async () => {
    const fetch = mock(reply({ name: 'Иван', phone: null }), reply({ name: 'Иван', phone: '+7 999 000-00-00' }));
    await expect(readRequestContactDetails(REQUEST_ID, signal())).resolves.toEqual({ name: 'Иван', phone: null });
    await expect(readRequestContactDetails(REQUEST_ID, signal())).resolves.toEqual({ name: 'Иван', phone: '+7 999 000-00-00' });
    expect(new Headers(fetch.mock.calls[0]?.[1]?.headers).get('x-auth-request')).toBe('1');
  });

  it('rejects empty names, non-string phones and extra keys', async () => {
    const payloads = [
      { name: '', phone: null },
      { name: '   ', phone: null },
      { name: 'Иван', phone: 123 },
      { name: 'Иван', phone: null, extra: true },
    ];
    mock(...payloads.map(payload => reply(payload)));
    await Promise.all(payloads.map(() => expect(readRequestContactDetails(REQUEST_ID, signal())).rejects.toBeInstanceOf(RequestCardError)));
  });
});

const eventCases = [
  ['CreateCallback', 'Создана заявка на обратный звонок'],
  ['CreateRepair', 'Создана заявка на ремонт'],
  ['StartReview', 'Начата проверка менеджером'],
  ['ConvertCallback', 'Заявка переведена в ремонт'],
  ['ChangeDetails', 'Изменены данные заявки'],
  ['RecordCoverageAssessment', 'Записана оценка зоны обслуживания'],
  ['ChangeContact', 'Изменён способ связи'],
  ['ReadyForDispatch', 'Заявка готова к назначению'],
  ['ChooseCallback', 'Выбран обратный звонок'],
  ['WithdrawPhonePermission', 'Отозвано разрешение на звонки'],
  ['CancelRequest', 'Заявка отменена'],
] as const;
const event = (command: string, version: number) => ({ version, command, actorKind: version % 2 === 1 ? 'F' : 'STAFF', createdAt: CREATED_AT });

describe('P06 request events decoder', () => {
  it('maps every request event command to its exact Russian label', async () => {
    mock(reply({ items: eventCases.map(([command], index) => event(command, index + 1)) }));
    const events = await readRequestEvents(REQUEST_ID, signal());
    expect(events).toEqual(eventCases.map(([, label], index) => ({
      version: index + 1, label, actorKind: (index + 1) % 2 === 1 ? 'F' : 'STAFF', createdAt: CREATED_AT,
    })));
  });

  it('rejects unknown commands, bad actor kinds and more than 100 events', async () => {
    const payloads = [
      { items: [event('Unknown', 1)] },
      { items: [{ ...event('CreateRepair', 1), actorKind: 'SYSTEM' }] },
      { items: Array.from({ length: 101 }, (_, index) => event('CreateRepair', index + 1)) },
    ];
    mock(...payloads.map(payload => reply(payload)));
    await Promise.all(payloads.map(() => expect(readRequestEvents(REQUEST_ID, signal())).rejects.toBeInstanceOf(RequestCardError)));
  });
});

const statusesByMetric: Record<string, readonly string[]> = {
  newRequests: ['NEW'], callbackRequired: ['CALLBACK_REQUIRED'],
  awaitingChannel: ['WAITING_TELEGRAM_LINK', 'WAITING_CHANNEL_LINK'], readyForAssignment: ['WAITING_ASSIGNMENT'],
};
const appliedFilters = (key: string): Record<string, unknown> => key === 'createdToday'
  ? { from: DAY_FROM, to: DAY_TO }
  : key === 'callbackRequired'
    ? { statuses: statusesByMetric[key], contactMode: 'PHONE', phonePermission: 'active_current_revision', processing: 'current' }
    : { statuses: statusesByMetric[key] };
const ready = (key: ReadyMetric, count = 5): Record<string, unknown> => ({ state: 'ready', count, basis: readyMetrics[key].basis, appliedFilters: appliedFilters(key), href: snapshotHref(SNAPSHOT_ID, key) });
const validMetrics = (): Record<string, unknown> => ({
  newRequests: ready('newRequests'), createdToday: ready('createdToday'), callbackRequired: ready('callbackRequired'),
  awaitingChannel: ready('awaitingChannel'), readyForAssignment: ready('readyForAssignment'),
  ...Object.fromEntries(Object.keys(unavailableMetrics).map(key => [key, { state: 'not_ready' }])),
});
const dashboard = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  snapshotId: SNAPSHOT_ID, asOf: AS_OF, definitionsVersion: 'p06-v1',
  cityId: CITY_ID, cityVersionId: CITY_VERSION_ID, timezone: 'Europe/Moscow',
  localDay: { from: DAY_FROM, to: DAY_TO }, metrics: validMetrics(), ...overrides,
});
const withMetric = (key: string, value: Record<string, unknown>) => dashboard({ metrics: { ...validMetrics(), [key]: value } });

describe('P06 dashboard decoder', () => {
  it('accepts a valid dashboard payload and returns localAsOf with ready metrics', async () => {
    mock(reply(dashboard()));
    const data = await readDashboard(signal());
    const localAsOf = new Intl.DateTimeFormat('ru', { dateStyle: 'medium', timeStyle: 'medium', timeZone: 'Europe/Moscow' })
      .format(new Date(AS_OF));
    expect(data.localAsOf).toBe(localAsOf);
    expect(Object.keys(data).sort()).toEqual(['asOf', 'definitionsVersion', 'localAsOf', 'metrics', 'snapshotId', 'timezone']);
    expect(data).toEqual({
      snapshotId: SNAPSHOT_ID, asOf: AS_OF, definitionsVersion: 'p06-v1', timezone: 'Europe/Moscow', localAsOf,
      metrics: Object.fromEntries((Object.keys(readyMetrics) as ReadyMetric[]).map(key =>
        [key, { count: 5, href: snapshotHref(SNAPSHOT_ID, key) }])),
    });
  });

  it('rejects contract drift in versions, metrics, filters, days and time zones', async () => {
    const payloads = [
      dashboard({ definitionsVersion: 'p06-v2' }),
      dashboard({ metrics: { ...validMetrics(), extra: { state: 'not_ready' } } }),
      withMetric('newRequests', { ...ready('newRequests'), state: 'not_ready' }),
      withMetric('unassigned', { state: 'ready' }),
      withMetric('newRequests', { ...ready('newRequests'), count: 2001 }),
      withMetric('newRequests', { ...ready('newRequests'), count: -1 }),
      withMetric('newRequests', { ...ready('newRequests'), count: 1.5 }),
      withMetric('newRequests', { ...ready('newRequests'), href: '/wrong' }),
      withMetric('callbackRequired', { ...ready('callbackRequired'), appliedFilters: { statuses: ['CALLBACK_REQUIRED'] } }),
      withMetric('createdToday', { ...ready('createdToday'), appliedFilters: { from: DAY_TO, to: DAY_FROM } }),
      dashboard({ localDay: { from: DAY_TO, to: DAY_FROM } }),
      dashboard({ timezone: 'posix/UTC' }),
      dashboard({ timezone: 'Europe/Moscow/Extra' }),
    ];
    mock(...payloads.map(payload => reply(payload)));
    await Promise.all(payloads.map(() => expect(readDashboard(signal())).rejects.toBeInstanceOf(DashboardError)));
  });
});

const row = (index: number) => ({
  id: uuid(1000 + index), publicNumber: String(1000 + index), type: 'REPAIR', status: 'NEW', version: 1, createdAt: CREATED_AT,
});
const snapshotReply = (snapshot: Record<string, unknown>, items: unknown[], nextOffset: number | null, refreshed: boolean) =>
  reply({ snapshot, metric: 'newRequests', items, nextOffset, refreshed });

describe('P06 snapshot decoder', () => {
  it('accepts a normal second page with the exact remaining rows', async () => {
    const snapshot = withMetric('newRequests', { ...ready('newRequests', 45) });
    const items = Array.from({ length: 15 }, (_, index) => row(200 + index));
    const fetch = mock(snapshotReply(snapshot, items, null, false));
    const page = await readSnapshot({ snapshot: SNAPSHOT_ID, metric: 'newRequests', offset: 30 }, signal());
    expect(page.offset).toBe(30);
    expect(page.nextOffset).toBeNull();
    expect(page.refreshed).toBe(false);
    expect(page.snapshot.snapshotId).toBe(SNAPSHOT_ID);
    expect(page.items).toHaveLength(15);
    expect(page.items[0]).toEqual(row(200));
    expect(fetch.mock.calls[0]?.[0]).toBe(`/api/v1/requests?snapshot=${SNAPSHOT_ID}&metric=newRequests&offset=30`);
  });

  it('forces offset zero for a refreshed snapshot', async () => {
    const snapshot = withMetric('newRequests', { ...ready('newRequests', 2) });
    mock(snapshotReply(snapshot, [row(1), row(2)], null, true));
    const page = await readSnapshot({ snapshot: OLD_SNAPSHOT_ID, metric: 'newRequests', offset: 30 }, signal());
    expect(page.offset).toBe(0);
    expect(page.refreshed).toBe(true);
    expect(page.snapshot.snapshotId).toBe(SNAPSHOT_ID);
    expect(page.items).toHaveLength(2);
  });

  it('rejects refreshed inconsistency, page size/offset drift and duplicate rows', async () => {
    const count45 = withMetric('newRequests', { ...ready('newRequests', 45) });
    const count2 = withMetric('newRequests', { ...ready('newRequests', 2) });
    const cases: { query: { snapshot: string; metric: ReadyMetric; offset: number }; payload: Response }[] = [
      { query: { snapshot: SNAPSHOT_ID, metric: 'newRequests', offset: 0 },
        payload: snapshotReply(count45, Array.from({ length: 30 }, (_, index) => row(index)), 30, true) },
      { query: { snapshot: OLD_SNAPSHOT_ID, metric: 'newRequests', offset: 0 },
        payload: snapshotReply(count2, [row(1), row(2)], null, false) },
      { query: { snapshot: SNAPSHOT_ID, metric: 'newRequests', offset: 30 },
        payload: snapshotReply(count45, Array.from({ length: 14 }, (_, index) => row(index)), null, false) },
      { query: { snapshot: SNAPSHOT_ID, metric: 'newRequests', offset: 0 },
        payload: snapshotReply(count45, Array.from({ length: 30 }, (_, index) => row(index)), null, false) },
      { query: { snapshot: OLD_SNAPSHOT_ID, metric: 'newRequests', offset: 0 },
        payload: snapshotReply(count2, [row(1), row(1)], null, true) },
    ];
    mock(...cases.map(entry => entry.payload));
    for (const entry of cases) {
      await expect(readSnapshot(entry.query, signal())).rejects.toBeInstanceOf(DashboardError);
    }
  });
});
