import { fileSessionProof, isFileMimeType, uuidValue } from '../reservations/index.js';
import type { FileMimeType } from '../reservations/index.js';
import { refuse } from './contract.js';
import type { UploadOperationalPolicy, UploadReconcileCommand, UploadReservedFileCommand } from './contract.js';

const POLICY_KEYS = [
  'mode', 'maxAttemptsPerOwner', 'maxPhysicalBytesPerOwner', 'maxLiveOperationsPerOwner',
  'leaseMs', 'prefixTimeoutMs', 'maxSourceChunkBytes', 'allowedMimeTypes',
] as const;

function snapshot<K extends string>(value: unknown, keys: readonly K[]): Record<K, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    refuse('INVALID_INPUT');
  }
  const proto: unknown = Object.getPrototypeOf(value);
  if ((proto !== Object.prototype && proto !== null) || Reflect.ownKeys(value).length !== keys.length) {
    refuse('INVALID_INPUT');
  }
  const out = Object.create(null) as Record<K, unknown>;
  for (const key of keys) {
    const field = Reflect.getOwnPropertyDescriptor(value, key);
    if (field === undefined || !('value' in field)) {
      refuse('INVALID_INPUT');
    }
    out[key] = field.value;
  }
  return out;
}

function positive(value: unknown, max: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > max) {
    refuse('INVALID_INPUT');
  }
  return value;
}

function mimeSubset(value: unknown): readonly FileMimeType[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    refuse('INVALID_INPUT');
  }
  const len = positive(Reflect.getOwnPropertyDescriptor(value, 'length')?.value, 4);
  if (Reflect.ownKeys(value).length !== len + 1) {
    refuse('INVALID_INPUT');
  }
  const out = new Set<FileMimeType>();
  for (let i = 0; i < len; i += 1) {
    const descriptor = Reflect.getOwnPropertyDescriptor(value, String(i));
    const mime: unknown = descriptor?.value;
    if (typeof mime !== 'string' || !isFileMimeType(mime) || out.has(mime)) {
      refuse('INVALID_INPUT');
    }
    out.add(mime);
  }
  return Object.freeze([...out]);
}

export function uploadOperationalPolicy(input: unknown): UploadOperationalPolicy {
  try {
    const fields = snapshot(input, POLICY_KEYS);
    const leaseMs = positive(fields.leaseMs, 3_600_000);
    const prefixTimeoutMs = positive(fields.prefixTimeoutMs, leaseMs - 1);
    if (fields.mode !== 'local-synthetic') {
      refuse('NOT_CONFIGURED');
    }
    return Object.freeze({
      mode: fields.mode, leaseMs, prefixTimeoutMs,
      maxAttemptsPerOwner: positive(fields.maxAttemptsPerOwner, 2_147_483_647),
      maxPhysicalBytesPerOwner: positive(fields.maxPhysicalBytesPerOwner, Number.MAX_SAFE_INTEGER),
      maxLiveOperationsPerOwner: positive(fields.maxLiveOperationsPerOwner, 2_147_483_647),
      maxSourceChunkBytes: positive(fields.maxSourceChunkBytes, 67_108_864),
      allowedMimeTypes: mimeSubset(fields.allowedMimeTypes),
    });
  } catch {
    refuse('NOT_CONFIGURED');
  }
}

export function signalAborted(signal: AbortSignal): boolean {
  const aborted: unknown = Reflect.get(AbortSignal.prototype, 'aborted', signal);
  return aborted === true;
}

function nativeSignal(value: unknown): AbortSignal {
  if (!(value instanceof AbortSignal) || typeof Reflect.get(AbortSignal.prototype, 'aborted', value) !== 'boolean') {
    refuse('INVALID_INPUT');
  }
  return value;
}

export function uploadCommand(input: unknown): UploadReservedFileCommand {
  try {
    const { session, intentId, idempotencyKey, body, signal } = snapshot(
      input, ['session', 'intentId', 'idempotencyKey', 'body', 'signal'],
    );
    const raw = snapshot(session, ['sessionId', 'token']);
    if (typeof body !== 'function') {
      refuse('INVALID_INPUT');
    }
    const proof = fileSessionProof(raw);
    return Object.freeze({
      session: Object.freeze({ sessionId: proof.sessionId, token: proof.token }), intentId: uuidValue(intentId),
      idempotencyKey: uuidValue(idempotencyKey), body: body as UploadReservedFileCommand['body'],
      signal: nativeSignal(signal),
    });
  } catch {
    refuse('INVALID_INPUT');
  }
}

export function reconcileCommand(input: unknown): UploadReconcileCommand {
  try {
    const { limit, signal } = snapshot(input, ['limit', 'signal']);
    return { limit: positive(limit, 100), signal: nativeSignal(signal) };
  } catch {
    refuse('INVALID_INPUT');
  }
}

/** Private signal: native calls ignore own-property overrides on the incoming signal. */
export function deadline(caller: AbortSignal, ms: number): { signal: AbortSignal; close: () => void } {
  const controller = new AbortController();
  const abort = (): void => { controller.abort(); };
  // Native dependent-signal propagation cannot be suppressed by a pre-existing
  // caller listener invoking stopImmediatePropagation() on the abort event.
  const signal = AbortSignal.any([controller.signal, caller]);
  const timer = setTimeout(abort, ms);
  return {
    signal,
    close: () => {
      clearTimeout(timer);
      abort();
    },
  };
}

export function assertNotAborted(signal: AbortSignal): void {
  if (signalAborted(signal)) {
    refuse('ABORTED');
  }
}
