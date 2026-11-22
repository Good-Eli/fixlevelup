import { types } from 'node:util';
import { refuseLifecycle as refuse } from '../file-lifecycle/errors.js';

/** Closed own-data records: read only descriptors, never invoke a caller getter. */
export function accessRecord<K extends string>(value: unknown, keys: readonly K[]): Record<K, unknown> {
  if (typeof value !== 'object' || value === null || types.isProxy(value) || Array.isArray(value)) {
    refuse('INVALID_INPUT');
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  if ((prototype !== Object.prototype && prototype !== null) || Reflect.ownKeys(value).length !== keys.length) {
    refuse('INVALID_INPUT');
  }
  const result = Object.create(null) as Record<K, unknown>;
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor)) {
      refuse('INVALID_INPUT');
    }
    const field: unknown = descriptor.value;
    result[key] = field;
  }
  return result;
}

export function positiveInteger(value: unknown, max: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > max) {
    refuse('INVALID_INPUT');
  }
  return value;
}
