import { types } from 'node:util';
import type { Pool } from 'pg';
import type { LedgerScope } from '../file-ledger/contract.js';
import type { RuntimeEpoch } from '../file-lifecycle/contract.js';
import type { RestoreGateReceipt } from '../file-restore/contract.js';
import { readRestoreDeleteScope } from '../file-restore/rescrub.js';
import { isPrivacyError, refusePrivacy } from './contract.js';
import type { PrivacyContext, RetentionPolicy } from './contract.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_BIGINT = 9_223_372_036_854_775_807n;
export const MAX_TARGETS = 8;
const getAborted = Reflect.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted')?.['get'] as ((this: unknown) => boolean) | undefined;

export function snapshotRecord(value: unknown, keys: readonly string[]): Readonly<Record<string, unknown>> {
  try {
    if (typeof value !== 'object' || value === null || types.isProxy(value)) { return refusePrivacy('INVALID_INPUT'); }
    const proto: unknown = Object.getPrototypeOf(value);
    if (proto !== null && proto !== Object.prototype) { return refusePrivacy('INVALID_INPUT'); }
    const names = Reflect.ownKeys(value);
    if (names.length !== keys.length || names.some((name) => typeof name !== 'string' || !keys.includes(name))) {
      return refusePrivacy('INVALID_INPUT');
    }
    const copy: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const key of keys) {
      const field = Reflect.getOwnPropertyDescriptor(value, key);
      if (field === undefined || !Object.hasOwn(field, 'value')) { return refusePrivacy('INVALID_INPUT'); }
      copy[key] = field.value;
    }
    return Object.freeze(copy);
  } catch {
    return refusePrivacy('INVALID_INPUT');
  }
}

export function snapshotTargets(value: unknown): readonly unknown[] {
  try {
    if (types.isProxy(value) || !Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) { return refusePrivacy('INVALID_INPUT'); }
    const length = positive(Object.getOwnPropertyDescriptor(value, 'length')?.value, MAX_TARGETS);
    if (Reflect.ownKeys(value).length !== length + 1) { return refusePrivacy('INVALID_INPUT'); }
    return Array.from({ length }, (_, i): unknown => {
      const field = Reflect.getOwnPropertyDescriptor(value, String(i));
      if (field === undefined || !Object.hasOwn(field, 'value') || types.isProxy(field.value)) { return refusePrivacy('INVALID_INPUT'); }
      return field.value;
    });
  } catch {
    return refusePrivacy('INVALID_INPUT');
  }
}

export function uuid(value: unknown): string {
  return typeof value === 'string' && UUID.test(value) ? value : refusePrivacy('INVALID_INPUT');
}
export function epochNumber(value: unknown): bigint {
  return typeof value === 'bigint' && value > 0n && value <= MAX_BIGINT ? value : refusePrivacy('INVALID_INPUT');
}
export function positive(value: unknown, max: number): number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1 && value <= max ? value : refusePrivacy('INVALID_INPUT');
}

function policySnapshot(value: unknown): RetentionPolicy {
  const p = snapshotRecord(value, ['mode','versionId','expiresAt','rawBoundMs','readyMs','quarantinedMs','orphanMs','maxBatch','maxItemsPerIntent','claimMs']);
  if (p['mode'] !== 'local-synthetic') { return refusePrivacy('NOT_CONFIGURED'); }
  let expiresAt: number;
  try {
    expiresAt = Date.prototype.getTime.call(p['expiresAt']);
  } catch {
    return refusePrivacy('INVALID_INPUT');
  }
  // Resource ceilings only; none is an injected business duration or a default.
  const maxAgeMs = 31_536_000_000 * 100;
  if (!Number.isFinite(expiresAt) || expiresAt <= 0 || expiresAt > 253_402_300_799_999) { return refusePrivacy('INVALID_INPUT'); }
  return Object.freeze({ mode: 'local-synthetic', versionId: uuid(p['versionId']), expiresAt: new Date(expiresAt),
    rawBoundMs: positive(p['rawBoundMs'], maxAgeMs), readyMs: positive(p['readyMs'], maxAgeMs),
    quarantinedMs: positive(p['quarantinedMs'], maxAgeMs), orphanMs: positive(p['orphanMs'], maxAgeMs),
    maxBatch: positive(p['maxBatch'], 64), maxItemsPerIntent: positive(p['maxItemsPerIntent'], 1024), claimMs: positive(p['claimMs'], 3_600_000) });
}

export function runtimeSnapshot(value: unknown): RuntimeEpoch {
  const r = snapshotRecord(value, ['namespace','epoch']);
  return Object.freeze({ namespace: uuid(r['namespace']), epoch: epochNumber(r['epoch']) });
}
export function scopeSnapshot(value: unknown, epoch: RuntimeEpoch): LedgerScope {
  const s = snapshotRecord(value, ['namespace','incarnation','writerEpoch']);
  if (s['namespace'] !== epoch.namespace || s['writerEpoch'] !== epoch.epoch) { return refusePrivacy('NOT_CONFIGURED'); }
  return Object.freeze({ namespace: epoch.namespace, incarnation: uuid(s['incarnation']), writerEpoch: epoch.epoch });
}
export function contextSnapshot(value: unknown, extra: readonly string[], allowRestore = false): PrivacyContext & {
  readonly fields: Readonly<Record<string, unknown>>; readonly database?: string;
} {
  const keys = ['pool','epoch','policy', ...extra];
  const includesRestore = allowRestore && typeof value === 'object' && value !== null && !types.isProxy(value) && Object.hasOwn(value, 'restore');
  const fields = snapshotRecord(value, includesRestore ? [...keys, 'restore'] : keys);
  if (typeof fields['pool'] !== 'object' || fields['pool'] === null) { return refusePrivacy('NOT_CONFIGURED'); }
  const ctx = { fields, pool: fields['pool'] as Pool, epoch: runtimeSnapshot(fields['epoch']), policy: policySnapshot(fields['policy']) };
  if (!allowRestore) { return ctx; }
  if (ctx.epoch.epoch === 1n && !includesRestore) { return ctx; }
  try {
    const restored = readRestoreDeleteScope(fields['restore'] as RestoreGateReceipt);
    if (restored.epoch.namespace !== ctx.epoch.namespace || restored.epoch.epoch !== ctx.epoch.epoch) { return refusePrivacy('NOT_CONFIGURED'); }
    return { ...ctx, database: restored.database };
  } catch {
    return refusePrivacy('NOT_CONFIGURED');
  }
}

export function nativeSignal(value: unknown): AbortSignal {
  try {
    if (typeof value !== 'object' || value === null || types.isProxy(value) || Object.getPrototypeOf(value) !== AbortSignal.prototype ||
        Reflect.ownKeys(value).some((key) => typeof key === 'string')) {
      return refusePrivacy('INVALID_INPUT');
    }
    if (typeof getAborted?.call(value) !== 'boolean') { return refusePrivacy('INVALID_INPUT'); }
    return value as AbortSignal;
  } catch {
    return refusePrivacy('INVALID_INPUT');
  }
}
export function isAborted(signal: AbortSignal): boolean { return getAborted?.call(signal) !== false; }
export function checkSignal(signal: AbortSignal): void { if (isAborted(signal)) { refusePrivacy('ABORTED'); } }
export function safeFailure(error: unknown): never {
  if (isPrivacyError(error)) { throw error; }
  return refusePrivacy('CONFLICT');
}
