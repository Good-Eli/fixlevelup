import { decodeP03Envelope, isP03Version, P03_BODY_BYTES, P03_RESPONSE_BYTES } from '@fixlevelup/p03-contracts';
import { api, ApiError, type Identity } from './api';

export type Decoder<T> = (value: unknown) => T | null;
export type VersionFamily = 'p03' | 'geo';
export type Method = 'POST' | 'PATCH' | 'PUT';
export const BODY_BYTES = { standard: P03_BODY_BYTES.default, content: P03_BODY_BYTES.contentPublish, legal: P03_BODY_BYTES.legalPublish, coverage: P03_BODY_BYTES.geographyCoverage } as const;
export const RESPONSE_BYTES = { standard: P03_RESPONSE_BYTES.list, content: P03_RESPONSE_BYTES.contentExact, legal: P03_RESPONSE_BYTES.legalExact } as const;
export type PayloadLimit = keyof typeof BODY_BYTES;
export const jsonBytes = (text: string) => new TextEncoder().encode(text).length;

export class FormError extends Error {}
export class SessionChanged extends Error {}

/** Path fragments are built from closed route prefixes and validated IDs. Free text stays in JSON. */
function relative(path: string) {
  const segments = path.split('?')[0]?.split('/') ?? [];
  if (!/^[a-z0-9_./-]+(?:\?[^#\s\\]*)?$/i.test(path) || segments.some(s => !s || s === '.' || s === '..')) { throw new FormError('Недопустимый путь операции.'); }
  return `/api/v1/${path}`;
}
export function query(path: string, options: Record<string, string | number | boolean | undefined>) {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(options)) { if (v !== undefined) { params.set(k, String(v)); } }
  const search = params.toString();
  return search ? `${path}?${search}` : path;
}
export function sameSession(a: Identity, b: Identity) {
  // The existing web CSRF proof is derived from the HttpOnly session token, not merely the staff ID.
  return a.staffId === b.staffId && a.csrf === b.csrf && a.authVersion === b.authVersion;
}
export async function proveSession(signal: AbortSignal, expected: Identity) {
  const live = await api(signal).me();
  signal.throwIfAborted();
  if (!sameSession(live, expected)) { throw new SessionChanged(); }
  return live;
}
export async function guardedRead<T>(signal: AbortSignal, expected: Identity, read: (signal: AbortSignal) => Promise<T>) {
  await proveSession(signal, expected);
  const data = await read(signal);
  await proveSession(signal, expected);
  signal.throwIfAborted();
  return data;
}

export interface CommandSpec {
  path: string;
  read: Decoder<unknown>;
  version?: number | undefined;
  family?: VersionFamily;
  allowZeroVersion?: boolean;
  method?: Method;
  limit?: PayloadLimit;
}
export interface PreparedCommand {
  readonly path: string;
  readonly method: Method;
  readonly idempotencyKey: string;
  readonly ifMatch: string | undefined;
  readonly body: string;
  readonly read: Decoder<unknown>;
  readonly actor: Identity;
}
export function prepareCommand(spec: CommandSpec, payload: object, actor: Identity): PreparedCommand {
  const { path, read, method = 'POST', family = 'p03', version, limit = 'standard' } = spec;
  relative(path);
  if (version !== undefined && !isP03Version(version, family === 'geo' && spec.allowZeroVersion === true)) { throw new FormError('Нужна актуальная версия записи.'); }
  const body = JSON.stringify(payload);
  if (jsonBytes(body) > BODY_BYTES[limit]) { throw new FormError(`Размер JSON превышает допустимые ${String(BODY_BYTES[limit] / 1024)} КиБ (UTF-8).`); }
  const ifMatch = version === undefined ? undefined : `"${family}-v${String(version)}"`;
  return Object.freeze({ path, method, idempotencyKey: crypto.randomUUID(), ifMatch, body, read, actor: Object.freeze({ ...actor }) });
}
export function isUncertain(e: unknown) {
  return !(e instanceof ApiError) || e.status >= 500;
}

export async function boundedJson(response: Response, limit: number): Promise<unknown> {
  const reported = response.headers.get('content-length');
  const reader = response.body?.getReader();
  if (!reader) { throw new Error('Missing response'); }
  try {
    if (reported !== null && Number(reported) > limit) { throw new Error('Invalid response size'); }
    let size = 0;
    let text = '';
    const utf8 = new TextDecoder('utf-8', { fatal: true });
    for (;;) {
      const part = await reader.read();
      if (part.done) { break; }
      size += part.value.length;
      if (size > limit) { throw new Error('Invalid response size'); }
      text += utf8.decode(part.value, { stream: true });
    }
    text += utf8.decode();
    return JSON.parse(text) as unknown;
  } finally { void reader.cancel().catch(() => undefined); }
}

async function request<T>(path: string, read: Decoder<T>, signal: AbortSignal, limit: number, write?: PreparedCommand): Promise<T> {
  signal.throwIfAborted();
  const headers = new Headers({ Accept: 'application/json', 'X-Auth-Request': '1' });
  if (write) {
    headers.set('Content-Type', 'application/json');
    headers.set('X-CSRF-Token', write.actor.csrf);
    headers.set('Idempotency-Key', write.idempotencyKey);
    if (write.ifMatch !== undefined) { headers.set('If-Match', write.ifMatch); }
  }
  const response = await fetch(relative(path), { signal, credentials: 'same-origin', mode: 'same-origin', cache: 'no-store', redirect: 'error',
    headers, method: write?.method ?? 'GET', ...(write ? { body: write.body } : {}) });
  signal.throwIfAborted();
  if (!response.ok) { void response.body?.cancel().catch(() => undefined); throw new ApiError(response.status); }
  const envelope = await boundedJson(response, limit);
  signal.throwIfAborted();
  const decoded = decodeP03Envelope(envelope, read);
  if (!decoded) { throw new Error('Invalid response envelope'); }
  return decoded.data;
}

export function p03Read<T>(signal: AbortSignal, path: string, read: Decoder<T>, limit = RESPONSE_BYTES.standard) {
  return request(path, read, signal, limit);
}
export function sendCommand(signal: AbortSignal, live: Identity, command: PreparedCommand) {
  if (!sameSession(command.actor, live)) { throw new SessionChanged(); }
  return request(command.path, command.read, signal, RESPONSE_BYTES.standard, command);
}
