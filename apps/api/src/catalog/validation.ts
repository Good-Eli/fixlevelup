export type CatalogErrorCode =
  | 'INVALID_INPUT' | 'NOT_FOUND' | 'STALE_VERSION' | 'ARCHIVED' | 'CONFLICT'
  | 'PRICE_NOT_CONFIGURED' | 'TRANSACTION_REQUIRED' | 'ISOLATION_REQUIRED';

/** Only constant field labels, never submitted keys/values or driver messages. */
export class CatalogError extends Error {
  constructor(readonly code: CatalogErrorCode, readonly field?: string) {
    super(field === undefined ? code : `${code}: ${field}`);
    this.name = 'CatalogError';
  }
}

/** Unexpected DB, consistency or evidence failure. Do not classify as a domain refusal. */
export class CatalogInternalError extends Error {
  constructor() {
    super('Catalog operation failed internally');
    this.name = 'CatalogInternalError';
  }
}

export function refuse(code: CatalogErrorCode, field?: string): never {
  throw new CatalogError(code, field);
}

export function record(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (typeof value !== 'object' || value === null) {
    return refuse('INVALID_INPUT', 'input');
  }
  const proto: unknown = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    return refuse('INVALID_INPUT', 'input');
  }
  const output: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !keys.includes(key)) {
      return refuse('INVALID_INPUT', 'input');
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !('value' in descriptor)) {
      return refuse('INVALID_INPUT', 'input');
    }
    output[key] = descriptor.value;
  }
  return output;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function isUuid(value: unknown): value is string {
  return typeof value === 'string' && value.length === 36 && UUID.test(value);
}

export function uuid(value: unknown, field: string): string {
  if (!isUuid(value)) {
    return refuse('INVALID_INPUT', field);
  }
  return value.toLowerCase();
}

export function optionalUuid(value: unknown, field: string): string | null {
  return value === undefined || value === null ? null : uuid(value, field);
}

export function choice<T extends string>(value: unknown, options: readonly T[], field: string): T {
  const match = options.find((option) => option === value);
  return match ?? refuse('INVALID_INPUT', field);
}

export function integer(value: unknown, min: number, max: number, field: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
    return refuse('INVALID_INPUT', field);
  }
  return value;
}

export const MAX_VERSION = 2_147_483_647;
export function expectedVersion(value: unknown, min = 1): number {
  return integer(value, min, MAX_VERSION, 'expectedVersion');
}

export function flag(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') {
    return refuse('INVALID_INPUT', field);
  }
  return value;
}

export function slug(value: unknown, min: number, max: number, field: string): string {
  if (typeof value !== 'string' || value.length < min || value.length > max
      || !/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u.test(value) || /[^a-z0-9-]/u.test(value)) {
    return refuse('INVALID_INPUT', field);
  }
  return value;
}

export function text(value: unknown, max: number, field: string, min = 1): string {
  if (typeof value !== 'string' || /[\p{Cc}\p{Cf}\p{Cs}]/u.test(value)) {
    return refuse('INVALID_INPUT', field);
  }
  const normalized = value.trim();
  const length = Array.from(normalized).length;
  if (length < min || length > max) {
    return refuse('INVALID_INPUT', field);
  }
  return normalized;
}

export function optionalText(value: unknown, max: number, field: string, min = 1): string | null {
  return value === undefined || value === null ? null : text(value, max, field, min);
}

export function instant(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length !== 24 || value.startsWith('0000')
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) {
    return refuse('INVALID_INPUT', field);
  }
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    return refuse('INVALID_INPUT', field);
  }
  return value;
}

export function optionalInstant(value: unknown, field: string): string | null {
  return value === undefined || value === null ? null : instant(value, field);
}

export function amountMinor(value: unknown): string {
  if (typeof value !== 'string' || value.length > 19 || !/^(?:0|[1-9][0-9]*)$/u.test(value)
      || /[^0-9]/u.test(value) || BigInt(value) > 9223372036854775807n) {
    return refuse('INVALID_INPUT', 'amountMinor');
  }
  return value;
}

export function currency(value: unknown): string {
  if (typeof value !== 'string' || value.length !== 3 || !/^[A-Z]{3}$/u.test(value)) {
    return refuse('INVALID_INPUT', 'currency');
  }
  return value;
}
