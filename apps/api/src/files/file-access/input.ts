import { types } from 'node:util';
import type { Pool } from 'pg';
import type { AccessContext, FFile, FileAccessPolicy, ReadyReadStorage, RuntimeEpoch } from '../file-lifecycle/contract.js';
import { refuseLifecycle } from '../file-lifecycle/errors.js';
import { canonicalUuid, nativeSignal, snapshotDate, snapshotEpoch } from '../file-lifecycle/input.js';
import { fileSessionProof } from '../reservations/index.js';
import { MAX_PG_INT, readBudgetConfig } from './budget.js';
import { accessRecord, positiveInteger } from './input-shape.js';

const POLICY_KEYS = [
  'mode', 'expiresAt', 'maxAccessAgeMs', 'maxChunkBytes', 'maxBufferedBytes', 'maxActiveStreams', 'ticketMs',
] as const;

export interface ReadContext {
  readonly pool: AccessContext['pool'];
  readonly epoch: RuntimeEpoch;
  readonly fetchReadyBytes: ReadyReadStorage['fetchReadyBytes'];
  readonly policy: Omit<FileAccessPolicy, 'expiresAt'> & { readonly expiresAt: string };
  readonly budget: AccessContext['budget'];
  readonly maxLiveOperationsPerOwner: number;
}

/** Synchronous snapshot, including the Date value and adapter method identity. */
export function readContext(input: AccessContext): ReadContext {
  try {
    const { pool: poolInput, epoch, storage: storageInput, policy, budget: budgetInput } = accessRecord(
      input, ['pool', 'epoch', 'storage', 'policy', 'budget'],
    );
    const pool = poolInput as Pool;
    const storage = storageInput as ReadyReadStorage;
    const budget = budgetInput as AccessContext['budget'];
    accessRecord(epoch, ['namespace', 'epoch']);
    const runtime = snapshotEpoch(epoch);
    const configured = readBudgetConfig(budget, runtime.namespace);
    const fields = accessRecord(policy, POLICY_KEYS);
    if (fields.mode !== 'local-synthetic') {
      refuseLifecycle('NOT_CONFIGURED');
    }
    const expiresAt = snapshotDate(fields.expiresAt).toISOString();
    const maxBufferedBytes = positiveInteger(fields.maxBufferedBytes, Number.MAX_SAFE_INTEGER);
    const maxChunkBytes = positiveInteger(fields.maxChunkBytes, maxBufferedBytes);
    const fetchReadyBytes = storage.fetchReadyBytes.bind(storage);
    if (typeof pool.connect !== 'function') {
      refuseLifecycle('NOT_CONFIGURED');
    }
    return {
      pool,
      epoch: runtime,
      budget, maxLiveOperationsPerOwner: configured.maxLiveOperationsPerOwner,
      fetchReadyBytes,
      policy: {
        mode: 'local-synthetic', expiresAt, maxBufferedBytes, maxChunkBytes,
        maxAccessAgeMs: positiveInteger(fields.maxAccessAgeMs, MAX_PG_INT),
        maxActiveStreams: positiveInteger(fields.maxActiveStreams, MAX_PG_INT),
        ticketMs: positiveInteger(fields.ticketMs, MAX_PG_INT),
      },
    };
  } catch {
    refuseLifecycle('NOT_CONFIGURED');
  }
}

export function readCommand(input: unknown): FFile;
export function readCommand(input: unknown, opening: true): FFile & { readonly signal: AbortSignal };
export function readCommand(input: unknown, opening?: true): FFile & { readonly signal?: AbortSignal } {
  try {
    const fields = accessRecord(input, opening === true ? ['session', 'intentId', 'signal'] : ['session', 'intentId']);
    const session = accessRecord(fields.session, ['sessionId', 'token']);
    canonicalUuid(session.sessionId);
    const proof = fileSessionProof(session);
    const result: FFile = { session: { sessionId: proof.sessionId, token: proof.token }, intentId: canonicalUuid(fields.intentId) };
    if (opening !== true) {
      return result;
    }
    if (types.isProxy(fields.signal)) {
      refuseLifecycle('INVALID_INPUT');
    }
    // Native propagation is not an event callback on the caller's signal.
    return { ...result, signal: AbortSignal.any([nativeSignal(fields.signal)]) };
  } catch {
    refuseLifecycle('INVALID_INPUT');
  }
}
