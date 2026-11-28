import { boundedResponseText } from '../access/p0305-client';
import { readRegistryItem, request } from '../requests/client';
import {
  isSnapshotOffset, readyKeys, readyMetrics, snapshotCapacity, snapshotHref, snapshotPageSize, snapshotUuid, unavailableMetrics, uuid,
} from './metrics';
import type { ReadyMetric, SnapshotQuery } from './metrics';

export class DashboardError extends Error {}

function invalidResponse(): never {
  throw new DashboardError('Некорректный ответ дашборда.');
}

function object(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) {
    invalidResponse();
  }
  return value as Record<string, unknown>;
}

function timestamp(value: unknown): string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/.test(value)) {
    invalidResponse();
  }
  const date = new Date(value);
  if (!Number.isFinite(date.valueOf()) || date.toISOString().slice(0, -1) !== value.slice(0, -4)) {
    invalidResponse();
  }
  return value;
}

function timezoneFormat(value: unknown) {
  if (typeof value !== 'string' || value.length > 64 || (value !== 'UTC'
    && (!/^[A-Za-z][A-Za-z0-9_+-]*(\/[A-Za-z0-9_+-]+)+$/.test(value) || /^(posix|right|SystemV)\//.test(value)))) {
    invalidResponse();
  }
  try {
    return new Intl.DateTimeFormat('ru', { dateStyle: 'medium', timeStyle: 'medium', timeZone: value });
  } catch {
    invalidResponse();
  }
}

type Metric = { count: number; href: string };

const metricStatuses = {
  newRequests: ['NEW'],
  callbackRequired: ['CALLBACK_REQUIRED'],
  awaitingChannel: ['WAITING_TELEGRAM_LINK', 'WAITING_CHANNEL_LINK'],
  readyForAssignment: ['WAITING_ASSIGNMENT'],
} as const;

function validateAppliedFilters(key: ReadyMetric, value: unknown, dayFrom: string, dayTo: string) {
  if (key === 'createdToday') {
    const { from, to } = object(value, ['from', 'to']);
    if (from !== dayFrom || to !== dayTo) { invalidResponse(); }
    return;
  }

  const { statuses, contactMode, phonePermission, processing } = object(value, key === 'callbackRequired'
    ? ['statuses', 'contactMode', 'phonePermission', 'processing'] : ['statuses']);
  const expected = metricStatuses[key];
  if (!Array.isArray(statuses) || statuses.length !== expected.length || expected.some((status, i) => statuses[i] !== status)
    || (key === 'callbackRequired' && (contactMode !== 'PHONE' || phonePermission !== 'active_current_revision'
      || processing !== 'current'))) {
    invalidResponse();
  }
}

function readDashboardData(value: unknown) {
  const { snapshotId, asOf, definitionsVersion, cityId, cityVersionId, timezone, localDay, metrics } = object(value,
    ['snapshotId', 'asOf', 'definitionsVersion', 'cityId', 'cityVersionId', 'timezone', 'localDay', 'metrics']);
  if (typeof snapshotId !== 'string' || !snapshotUuid.test(snapshotId) || definitionsVersion !== 'p06-v1'
    || typeof cityId !== 'string' || !uuid.test(cityId) || typeof cityVersionId !== 'string' || !uuid.test(cityVersionId)
    || typeof timezone !== 'string') {
    invalidResponse();
  }
  const at = timestamp(asOf);
  const formatter = timezoneFormat(timezone);
  const { from, to } = object(localDay, ['from', 'to']);
  const dayFrom = timestamp(from);
  const dayTo = timestamp(to);
  if (dayFrom >= dayTo) { invalidResponse(); }

  const unavailableKeys = Object.keys(unavailableMetrics);
  const entries = object(metrics, [...readyKeys, ...unavailableKeys]);
  for (const key of unavailableKeys) {
    if (object(entries[key], ['state'])['state'] !== 'not_ready') { invalidResponse(); }
  }
  const available = {} as Record<ReadyMetric, Metric>;
  for (const key of readyKeys) {
    const { state, count, basis, appliedFilters, href } = object(entries[key], ['state', 'count', 'basis', 'appliedFilters', 'href']);
    if (state !== 'ready' || typeof count !== 'number' || !Number.isInteger(count) || count < 0 || count > snapshotCapacity
      || basis !== readyMetrics[key].basis || href !== snapshotHref(snapshotId, key)) {
      invalidResponse();
    }
    validateAppliedFilters(key, appliedFilters, dayFrom, dayTo);
    available[key] = { count, href };
  }
  return { snapshotId, asOf: at, definitionsVersion, timezone, localAsOf: formatter.format(new Date(at)), metrics: available };
}

async function readData(path: string, signal: AbortSignal) {
  const lifetime = AbortSignal.any([signal, AbortSignal.timeout(18_000)]);
  const response = await request(path, lifetime);
  if (!response.ok) {
    void response.body?.cancel().catch(() => undefined);
    if (response.status === 401) { throw new DashboardError('Войдите в CRM, чтобы открыть дашборд.'); }
    if (response.status === 403 || response.status === 404) { throw new DashboardError('Дашборд недоступен для этой учётной записи.'); }
    if (response.status === 400) { throw new DashboardError('Ссылка на список заявок недействительна.'); }
    throw new DashboardError('Не удалось загрузить данные дашборда.');
  }
  if (response.headers.get('Content-Type')?.split(';', 1)[0]?.trim().toLowerCase() !== 'application/json') {
    void response.body?.cancel().catch(() => undefined);
    invalidResponse();
  }
  const payload: unknown = JSON.parse(await boundedResponseText(response, 64 * 1024, true));
  lifetime.throwIfAborted();
  return object(payload, ['data'])['data'];
}

export async function readDashboard(signal: AbortSignal) {
  return readDashboardData(await readData('/api/v1/crm/dashboard', signal));
}

export async function readSnapshot(query: SnapshotQuery, signal: AbortSignal) {
  const params = new URLSearchParams({ snapshot: query.snapshot, metric: query.metric });
  if (query.offset > 0) { params.set('offset', String(query.offset)); }
  const { snapshot, metric, items, nextOffset, refreshed } = object(await readData(`/api/v1/requests?${params}`, signal),
    ['snapshot', 'metric', 'items', 'nextOffset', 'refreshed']);
  const context = readDashboardData(snapshot);
  if (metric !== query.metric || typeof refreshed !== 'boolean' || refreshed === (context.snapshotId === query.snapshot)
    || !Array.isArray(items) || items.length > snapshotPageSize || (nextOffset !== null && !isSnapshotOffset(nextOffset))) {
    invalidResponse();
  }
  const offset = refreshed ? 0 : query.offset;
  const remaining = context.metrics[query.metric].count - offset;
  if (items.length !== Math.min(snapshotPageSize, Math.max(0, remaining))
    || nextOffset !== (remaining > snapshotPageSize ? offset + snapshotPageSize : null)) {
    invalidResponse();
  }
  const rows = items.map(readRegistryItem);
  if (new Set(rows.map(row => row.id)).size !== rows.length) { invalidResponse(); }
  return { snapshot: context, items: rows, offset, nextOffset, refreshed };
}
