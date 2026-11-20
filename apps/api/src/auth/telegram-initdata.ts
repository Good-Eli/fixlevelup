import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

/** Raw Telegram Mini App initData verification (P02-05), node:crypto only.
 * The structure is cross-checked against the official Mini Apps documentation example
 * (public sample bot token/hash published by Telegram for this exact algorithm, see
 * the pinned test vector in telegram-initdata.test.ts):
 * data-check-string = every parameter except `hash`, sorted alphabetically, as
 * decoded `key=value` lines joined with `\n`;
 * secret = HMAC_SHA256 with key 'WebAppData' over the bot token (raw bytes);
 * expected = HMAC_SHA256(secret, data-check-string) as lowercase hex;
 * timing-safe comparison with the `hash` parameter.
 * The Ed25519 third-party-signature path is intentionally not implemented; a
 * `signature` parameter, when present, only participates in the data-check-string.
 * `initDataUnsafe` is never trusted; only this verified raw form is.
 */

export type TelegramInitDataErrorCode = 'INVALID_INPUT' | 'INVALID_SIGNATURE' | 'EXPIRED' | 'FUTURE_DATE';

export class TelegramInitDataError extends Error {
  constructor(readonly code: TelegramInitDataErrorCode) {
    super('Telegram init data verification failed');
    this.name = 'TelegramInitDataError';
  }
}

export interface TelegramInitDataVerifyOptions {
  /** Deterministic clock injection for tests; defaults to the wall clock. */
  readonly now?: Date;
  /** Owner-approved exchange freshness window: 24 hours after auth_date. */
  readonly maxAgeSeconds?: number;
  /** Owner-approved future skew tolerance: 60 seconds. */
  readonly futureSkewSeconds?: number;
}

export interface VerifiedInitData {
  /** Telegram user id as a decimal string; never a JavaScript number (BIGINT-safe). */
  readonly telegramUserId: string;
  readonly authDate: Date;
  /** sha256(data-check-string) hex: the replay digest stored with the session. */
  readonly digest: string;
}

/** Reordered raw initData strings produce the same canonical digest; the same
 * data-check-string always yields one stable digest value.
 */
export const MAX_INIT_DATA_CHARS = 4096;

const MAX_PARAMETERS = 32;
const MAX_KEY_CHARS = 64;
const MAX_VALUE_CHARS = 2048;
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const AUTH_DATE_PATTERN = /^(0|[1-9][0-9]{0,9})$/;
const DEFAULT_MAX_AGE_SECONDS = 86400;
const DEFAULT_FUTURE_SKEW_SECONDS = 60;

interface Parameter { readonly key: string; readonly value: string }

function decode(value: string): string {
  try { return decodeURIComponent(value); }
  catch { throw new TelegramInitDataError('INVALID_INPUT'); }
}

/** Manual x-www-form-adjacent parsing: Telegram percent-encodes initData values
 * (encodeURIComponent style), and duplicate keys are a forgery, so silently
 * collapsing them like URLSearchParams would is rejected instead.
 */
function parseParameters(rawInitData: string): Parameter[] {
  const parameters: Parameter[] = [];
  const seen = new Set<string>();
  for (const part of rawInitData.split('&')) {
    const separator = part.indexOf('=');
    if (separator < 1) { throw new TelegramInitDataError('INVALID_INPUT'); }
    const key = decode(part.slice(0, separator));
    const value = decode(part.slice(separator + 1));
    if (key.length < 1 || key.length > MAX_KEY_CHARS || value.length > MAX_VALUE_CHARS) {
      throw new TelegramInitDataError('INVALID_INPUT');
    }
    if (seen.has(key)) { throw new TelegramInitDataError('INVALID_INPUT'); }
    seen.add(key);
    parameters.push({ key, value });
  }
  if (parameters.length > MAX_PARAMETERS) { throw new TelegramInitDataError('INVALID_INPUT'); }
  return parameters;
}

export function verifyInitData(
  rawInitData: string,
  botToken: string,
  options?: TelegramInitDataVerifyOptions,
): VerifiedInitData {
  if (typeof rawInitData !== 'string' || rawInitData.length < 1 || rawInitData.length > MAX_INIT_DATA_CHARS
    || typeof botToken !== 'string' || botToken.length < 1) { throw new TelegramInitDataError('INVALID_INPUT'); }
  const parameters = parseParameters(rawInitData);
  let hash: string | undefined;
  for (const parameter of parameters) {
    if (parameter.key === 'hash') { hash = parameter.value; }
  }
  if (hash === undefined || !HASH_PATTERN.test(hash)) { throw new TelegramInitDataError('INVALID_INPUT'); }
  const dataCheckString = parameters.filter((parameter) => parameter.key !== 'hash')
    .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
    .map((parameter) => `${parameter.key}=${parameter.value}`)
    .join('\n');
  const secret = createHmac('sha256', 'WebAppData').update(botToken).digest();
  const expected = createHmac('sha256', secret).update(dataCheckString).digest('hex');
  const supplied = Buffer.from(hash, 'utf8');
  const computed = Buffer.from(expected, 'utf8');
  if (supplied.length !== computed.length || !timingSafeEqual(supplied, computed)) {
    throw new TelegramInitDataError('INVALID_SIGNATURE');
  }
  const authDateText = parameters.find((parameter) => parameter.key === 'auth_date')?.value;
  if (authDateText === undefined || !AUTH_DATE_PATTERN.test(authDateText)) { throw new TelegramInitDataError('INVALID_INPUT'); }
  const authDateSeconds = Number(authDateText);
  const authDateMs = authDateSeconds * 1000;
  const nowMs = (options?.now ?? new Date()).getTime();
  const maxAgeSeconds = options?.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS;
  const futureSkewSeconds = options?.futureSkewSeconds ?? DEFAULT_FUTURE_SKEW_SECONDS;
  if (nowMs - authDateMs > maxAgeSeconds * 1000) { throw new TelegramInitDataError('EXPIRED'); }
  if (authDateMs - nowMs > futureSkewSeconds * 1000) { throw new TelegramInitDataError('FUTURE_DATE'); }
  const userText = parameters.find((parameter) => parameter.key === 'user')?.value;
  if (userText === undefined) { throw new TelegramInitDataError('INVALID_INPUT'); }
  let user: unknown;
  try { user = JSON.parse(userText); }
  catch { throw new TelegramInitDataError('INVALID_INPUT'); }
  if (user === null || typeof user !== 'object' || Array.isArray(user)) { throw new TelegramInitDataError('INVALID_INPUT'); }
  const id = (user as Record<string, unknown>)['id'];
  if (typeof id !== 'number' || !Number.isSafeInteger(id) || id <= 0) { throw new TelegramInitDataError('INVALID_INPUT'); }
  return {
    telegramUserId: String(id),
    authDate: new Date(authDateMs),
    digest: createHash('sha256').update(dataCheckString).digest('hex'),
  };
}
