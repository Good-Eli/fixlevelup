import { decodeP05Response, decodeP05StaffRequestData, parseP05Etag, P05_RESPONSE_BYTES } from '@fixlevelup/p03-contracts/p05';
import { boundedResponseText } from '../access/p0305-client';

export class RegistryError extends Error {}
export class RequestCardError extends Error {}

const requestUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const csrfToken = /^[A-Za-z0-9_-]{43}$/;

function object(value: unknown, keys: readonly string[], error: Error = new RegistryError('Некорректный ответ реестра.')): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) {
    throw error;
  }
  return value as Record<string, unknown>;
}

function item(value: unknown) {
  const { createdAt, ...fields } = object(value, ['id', 'publicNumber', 'type', 'status', 'version', 'createdAt']);
  const request = decodeP05StaffRequestData(fields);
  if (!('id' in request) || typeof createdAt !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/.test(createdAt)
    || !Number.isFinite(Date.parse(createdAt))) {
    throw new RegistryError('Некорректная запись реестра.');
  }
  return { ...request, createdAt };
}

function request(path: string, signal: AbortSignal, authRequest = false) {
  const headers = new Headers({ Accept: 'application/json' });
  if (authRequest) { headers.set('X-Auth-Request', '1'); }
  return fetch(path, {
    signal, cache: 'no-store', credentials: 'same-origin', mode: 'same-origin', redirect: 'error',
    headers,
  });
}

async function readData(path: string, signal: AbortSignal) {
  const response = await request(path, signal);
  if (response.status === 401) { throw new RegistryError('Войдите в CRM, чтобы открыть реестр.'); }
  if (response.status === 403 || response.status === 404) { throw new RegistryError('Реестр недоступен для этой учётной записи.'); }
  if (response.status === 400) { throw new RegistryError('Проверьте фильтры или начните просмотр с первой страницы.'); }
  if (!response.ok) { throw new RegistryError('Реестр временно недоступен.'); }
  const payload: unknown = await response.json();
  return object(payload, ['data'])['data'];
}

export async function readRegistry(query: URLSearchParams, signal: AbortSignal) {
  const { items, nextCursor } = object(await readData(`/api/v1/requests?${query.toString()}`, signal), ['items', 'nextCursor']);
  if (!Array.isArray(items) || items.length > 100 || (nextCursor !== null && (typeof nextCursor !== 'string'
    || nextCursor.length === 0 || nextCursor.length > 256))) {
    throw new RegistryError('Некорректная страница реестра.');
  }
  return { items: items.map(item), nextCursor };
}

export type RegistrySearchKind = 'number' | 'name' | 'phone';

export async function searchRegistry(kind: RegistrySearchKind, query: string, signal: AbortSignal) {
  const lifetime = AbortSignal.any([signal, AbortSignal.timeout(18_000)]);
  const response = await fetch('/api/v1/requests/search', {
    method: 'POST', body: JSON.stringify({ kind, query }), signal: lifetime,
    cache: 'no-store', credentials: 'same-origin', mode: 'same-origin', redirect: 'error',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-Auth-Request': '1' },
  });
  if (!response.ok) {
    void response.body?.cancel().catch(() => undefined);
    switch (response.status) {
      case 400:
      case 422: throw new RegistryError('Проверьте поисковый запрос.');
      case 401:
      case 403:
      case 404: throw new RegistryError('Поиск недоступен.');
      case 429: throw new RegistryError('Слишком много запросов. Повторите поиск позже.');
      default: throw new RegistryError('Поиск временно недоступен.');
    }
  }
  if (response.headers.get('Content-Type')?.split(';', 1)[0]?.trim().toLowerCase() !== 'application/json') {
    void response.body?.cancel().catch(() => undefined);
    throw new RegistryError('Некорректный ответ поиска.');
  }
  const payload: unknown = JSON.parse(await boundedResponseText(response, P05_RESPONSE_BYTES.json, true));
  lifetime.throwIfAborted();
  const { items, truncated } = object(object(payload, ['data'])['data'], ['items', 'truncated']);
  if (!Array.isArray(items) || items.length > 50 || typeof truncated !== 'boolean') {
    throw new RegistryError('Некорректный ответ поиска.');
  }
  return { items: items.map(item), truncated };
}

function choices(value: unknown) {
  if (!Array.isArray(value)) { throw new RegistryError('Некорректный справочник реестра.'); }
  return value.map(option => {
    const { id, name } = object(option, ['id', 'name']);
    if (typeof id !== 'string' || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(id)
      || typeof name !== 'string' || !name.trim()) {
      throw new RegistryError('Некорректный справочник реестра.');
    }
    return { id, name };
  });
}

export async function readRegistryOptions(signal: AbortSignal) {
  const { categories, districts, sources, unavailable } = object(await readData('/api/v1/requests/filters', signal),
    ['categories', 'districts', 'sources', 'unavailable']);
  const status = object(unavailable, ['technician', 'payment', 'alert']);
  if (Object.values(status).some(value => value !== 'not_ready')) { throw new RegistryError('Некорректный справочник реестра.'); }
  return { categories: choices(categories), districts: choices(districts), sources: choices(sources) };
}

export const unavailableSections = {
  appointments: 'Визиты', quotes: 'Сметы', reports: 'Отчёты', payments: 'Оплата', messages: 'Переписка',
  attachments: 'Вложения', comments: 'Внутренние комментарии', contactDetails: 'Контактные данные',
};

const eventLabels = {
  CreateCallback: 'Создана заявка на обратный звонок',
  CreateRepair: 'Создана заявка на ремонт',
  StartReview: 'Начата проверка менеджером',
  ConvertCallback: 'Заявка переведена в ремонт',
  ChangeDetails: 'Изменены данные заявки',
  RecordCoverageAssessment: 'Записана оценка зоны обслуживания',
  ChangeContact: 'Изменён способ связи',
  ReadyForDispatch: 'Заявка готова к назначению',
  ChooseCallback: 'Выбран обратный звонок',
  WithdrawPhonePermission: 'Отозвано разрешение на звонки',
  CancelRequest: 'Заявка отменена',
};

function cardObject(value: unknown, keys: readonly string[]) {
  return object(value, keys, new RequestCardError('Некорректный ответ CRM.'));
}

function cardTimestamp(value: unknown): value is string {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}(?:\d{3})?Z$/.test(value)
    && Number.isFinite(Date.parse(value));
}

function requestPath(id: string, resource: string) {
  if (!requestUuid.test(id)) {
    throw new RequestCardError('Заявка недоступна.');
  }
  return `/api/v1/requests/${id}/${resource}`;
}

async function readCardData(id: string, resource: 'card' | 'events', signal: AbortSignal) {
  const response = await request(requestPath(id, resource), signal, resource === 'card');
  if (response.status === 401) { throw new RequestCardError('Войдите в CRM, чтобы открыть заявку.'); }
  if (response.status === 403 || response.status === 404) { throw new RequestCardError('Заявка недоступна.'); }
  if (!response.ok) { throw new RequestCardError('Не удалось загрузить данные заявки.'); }
  const payload: unknown = await response.json();
  return { data: cardObject(payload, ['data'])['data'], headers: response.headers };
}

function readCardFacts(value: unknown) {
  const { source, category, district, urgency, coverage } = cardObject(value, ['source','category','district','urgency','coverage']);
  if ((source !== null && typeof source !== 'string') || (category !== null && typeof category !== 'string')
    || (district !== null && typeof district !== 'string')
    || (urgency !== null && urgency !== 'FLEXIBLE' && urgency !== 'WITHIN_DAY' && urgency !== 'URGENT')
    || (coverage !== null && coverage !== 'IN_ZONE' && coverage !== 'OUTSIDE' && coverage !== 'REVIEW' && coverage !== 'EXCEPTION')) {
    throw new RequestCardError('Некорректные сведения о заявке.');
  }
  return { source, category, district, urgency, coverage } as const;
}

export async function readRequestCard(id: string, signal: AbortSignal) {
  const { data, headers } = await readCardData(id, 'card', signal);
  if (data && typeof data === 'object' && Object.hasOwn(data, 'version') && Object.keys(data).length === 1) {
    const { version } = decodeP05StaffRequestData(data);
    return { kind: 'restricted' as const, version };
  }

  const { createdAt, contactMode, provider, facts, canStartReview, unavailable, ...fields } = cardObject(data,
    ['id', 'publicNumber', 'type', 'status', 'version', 'createdAt', 'contactMode', 'provider', 'facts', 'canStartReview', 'unavailable']);
  const card = decodeP05StaffRequestData(fields);
  const sections = cardObject(unavailable, Object.keys(unavailableSections));
  if (!('id' in card) || card.id !== id || !cardTimestamp(createdAt) || typeof canStartReview !== 'boolean'
    || (contactMode !== null && contactMode !== 'PHONE' && contactMode !== 'CHANNEL')
    || (provider !== null && provider !== 'TG' && provider !== 'VK' && provider !== 'MAX')
    || Object.entries(sections).some(([key, value]) => value !== 'not_ready'
      && (value !== 'available' || (key !== 'comments' && key !== 'contactDetails')))) {
    throw new RequestCardError('Некорректный ответ карточки заявки.');
  }
  const etag = headers.get('X-Command-ETag');
  const csrf = headers.get('X-Command-CSRF');
  const commentCsrf = headers.get('X-Comment-CSRF');
  const commandEtag = etag !== null && parseP05Etag(etag) !== null ? etag : null;
  const startReview = canStartReview && commandEtag && csrf && csrfToken.test(csrf) ? { etag: commandEtag, csrf } : null;
  const commentsAvailable = sections['comments'] === 'available';
  const contactDetailsAvailable = sections['contactDetails'] === 'available';
  const addComment = commentsAvailable && commandEtag && commentCsrf && csrfToken.test(commentCsrf)
    ? { etag: commandEtag, csrf: commentCsrf } : null;
  return { kind: 'full', ...card, createdAt, contactMode, provider, facts: readCardFacts(facts), canStartReview, startReview,
    commentsAvailable, contactDetailsAvailable, addComment } as const;
}

type FullCard = Extract<Awaited<ReturnType<typeof readRequestCard>>, { kind: 'full' }>;
export type CommentProof = NonNullable<FullCard['addComment']>;

export class RequestPanelHttpError extends Error {
  constructor(readonly status: number) { super('Не удалось выполнить операцию с заявкой.'); }
}

const panelTimeout = 18_000;

async function panelData(response: Response, limit: number) {
  if (!response.ok) {
    void response.body?.cancel().catch(() => undefined);
    throw new RequestPanelHttpError(response.status);
  }
  if (response.headers.get('Content-Type')?.split(';', 1)[0]?.trim().toLowerCase() !== 'application/json') {
    void response.body?.cancel().catch(() => undefined);
    throw new RequestCardError('Некорректный ответ CRM.');
  }
  const payload: unknown = JSON.parse(await boundedResponseText(response, limit, true));
  return cardObject(payload, ['data'])['data'];
}

function commentIdentity(id: unknown, version: unknown, createdAt: unknown) {
  if (typeof id !== 'string' || !requestUuid.test(id) || !cardTimestamp(createdAt)) {
    throw new RequestCardError('Некорректный ответ CRM.');
  }
  return { id, version: decodeP05StaffRequestData({ version }).version, createdAt };
}

export async function readRequestComments(id: string, signal: AbortSignal) {
  const lifetime = AbortSignal.any([signal, AbortSignal.timeout(panelTimeout)]);
  const response = await request(requestPath(id, 'comments'), lifetime);
  const { items } = cardObject(await panelData(response, 512 * 1024), ['items']);
  lifetime.throwIfAborted();
  if (!Array.isArray(items) || items.length > 50) {
    throw new RequestCardError('Некорректный ответ CRM.');
  }
  return items.map((item: unknown) => {
    const { id, version, createdAt, text } = cardObject(item, ['id', 'version', 'createdAt', 'text']);
    if (typeof text !== 'string' || !text.trim() || text.length > 4000) {
      throw new RequestCardError('Некорректный ответ CRM.');
    }
    return { ...commentIdentity(id, version, createdAt), text };
  });
}

export async function addRequestComment(id: string, proof: CommentProof, key: string, text: string, signal: AbortSignal) {
  const lifetime = AbortSignal.any([signal, AbortSignal.timeout(panelTimeout)]);
  const response = await fetch(requestPath(id, 'comments'), {
    method: 'POST', body: JSON.stringify({ text }), signal: lifetime,
    cache: 'no-store', credentials: 'same-origin', mode: 'same-origin', redirect: 'error',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json',
      'X-CSRF-Token': proof.csrf, 'If-Match': proof.etag, 'Idempotency-Key': key },
  });
  const data = await panelData(response, P05_RESPONSE_BYTES.json);
  lifetime.throwIfAborted();
  if (response.status !== 200 && response.status !== 201) {
    throw new RequestCardError('Некорректный ответ CRM.');
  }
  const receipt = cardObject(data, ['id', 'version', 'createdAt']);
  return commentIdentity(receipt['id'], receipt['version'], receipt['createdAt']);
}

export async function readRequestContactDetails(id: string, signal: AbortSignal) {
  const lifetime = AbortSignal.any([signal, AbortSignal.timeout(panelTimeout)]);
  const response = await request(requestPath(id, 'contact-details'), lifetime, true);
  const { name, phone } = cardObject(await panelData(response, P05_RESPONSE_BYTES.json), ['name', 'phone']);
  lifetime.throwIfAborted();
  if (typeof name !== 'string' || !name.trim() || (phone !== null && (typeof phone !== 'string' || !phone.trim()))) {
    throw new RequestCardError('Некорректный ответ CRM.');
  }
  return { name, phone };
}

export async function startRequestReview(
  card: FullCard, proof: NonNullable<FullCard['startReview']>, key: string, signal: AbortSignal,
) {
  const lifetime = AbortSignal.any([signal, AbortSignal.timeout(18_000)]);
  const response = await fetch(`/api/v1/requests/${encodeURIComponent(card.id)}/commands/start-review`, {
    method: 'POST', body: '{}', signal: lifetime,
    cache: 'no-store', credentials: 'same-origin', mode: 'same-origin', redirect: 'error',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json',
      'X-CSRF-Token': proof.csrf, 'If-Match': proof.etag, 'Idempotency-Key': key },
  });
  const media = response.headers.get('Content-Type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (media !== (response.ok ? 'application/json' : 'application/problem+json')) {
    void response.body?.cancel().catch(() => undefined);
    throw new RequestCardError('Некорректный ответ CRM.');
  }
  const text = await boundedResponseText(response, response.ok ? P05_RESPONSE_BYTES.json : P05_RESPONSE_BYTES.problem, true);
  const receipt = decodeP05Response('startReview', response.status, new TextEncoder().encode(text));
  lifetime.throwIfAborted();
  if (receipt.id !== card.id || receipt.publicNumber !== card.publicNumber || receipt.version !== card.version + 1
    || receipt.status !== 'MANAGER_REVIEW') {
    throw new RequestCardError('Некорректный ответ CRM.');
  }
}

export async function readRequestEvents(id: string, signal: AbortSignal) {
  const { data } = await readCardData(id, 'events', signal);
  const { items } = cardObject(data, ['items']);
  if (!Array.isArray(items) || items.length > 100) { throw new RequestCardError('Некорректный ответ истории заявки.'); }
  return items.map((item: unknown) => {
    const { version, command, actorKind, createdAt } = cardObject(item, ['version', 'command', 'actorKind', 'createdAt']);
    if (typeof command !== 'string' || !Object.hasOwn(eventLabels, command) || (actorKind !== 'F' && actorKind !== 'STAFF')
      || !cardTimestamp(createdAt)) {
      throw new RequestCardError('Некорректная запись истории заявки.');
    }
    return {
      version: decodeP05StaffRequestData({ version }).version,
      label: eventLabels[command as keyof typeof eventLabels], actorKind, createdAt,
    };
  });
}
