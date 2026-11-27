import { decodeP05StaffRequestData } from '@fixlevelup/p03-contracts/p05';

export class RegistryError extends Error {}

function object(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) {
    throw new RegistryError('Некорректный ответ реестра.');
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

async function readData(path: string, signal: AbortSignal) {
  const response = await fetch(path, {
    signal, cache: 'no-store', credentials: 'same-origin', mode: 'same-origin', redirect: 'error',
    headers: { Accept: 'application/json' },
  });
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
