import cluster from 'node:cluster';
import { isMainThread } from 'node:worker_threads';
import { refuseLifecycle as refuse } from '../file-lifecycle/errors.js';
import { accessRecord, positiveInteger } from './input-shape.js';
import { uuidValue } from '../reservations/index.js';
import { LIFECYCLE_READ_MAX_CHUNK_BYTES } from '../storage/adapter.js';

const budgetBrand: unique symbol = Symbol('FileReadBudget');
export type FileReadBudget = { readonly [budgetBrand]: true };

/** Trusted startup config, not part of the F command surface. No automatic initialization. */
export interface FileReadBudgetConfig {
  readonly mode: 'local-synthetic';
  readonly namespace: string;
  /** Operator attests this runtime has exactly one serving process (no cluster/process replicas). */
  readonly singleProcess: true;
  readonly maxBufferedBytes: number;
  readonly maxActiveStreams: number;
  /** Same live-operation cap used by this runtime's B/C upload policy. */
  readonly maxLiveOperationsPerOwner: number;
}

interface BudgetState {
  readonly handle: FileReadBudget;
  readonly config: FileReadBudgetConfig;
  bytes: number;
  streams: number;
}

const BUDGET_KEYS = [
  'mode', 'namespace', 'singleProcess', 'maxBufferedBytes', 'maxActiveStreams', 'maxLiveOperationsPerOwner',
] as const;
let singleton: BudgetState | undefined;

export const MAX_PG_INT = 2_147_483_647;

/**
 * The only reader manager in this server process; no per-context/namespace sharding,
 * no reset on expiry or epoch change. Cluster/worker-thread wiring is refused. This is
 * not a cross-process mutex: distributed/multi-process serving is unsupported.
 */
export function createFileReadBudget(input: FileReadBudgetConfig): FileReadBudget {
  const config = budgetConfig(input);
  if (singleton !== undefined) {
    const current = singleton.config;
    if (current.namespace !== config.namespace || current.maxBufferedBytes !== config.maxBufferedBytes
      || current.maxActiveStreams !== config.maxActiveStreams
      || current.maxLiveOperationsPerOwner !== config.maxLiveOperationsPerOwner) {
      refuse('NOT_CONFIGURED');
    }
    return singleton.handle;
  }
  const handle = Object.freeze(Object.create(null) as FileReadBudget);
  singleton = { handle, config, bytes: 0, streams: 0 };
  return handle;
}

function budgetConfig(input: unknown): FileReadBudgetConfig {
  try {
    const fields = accessRecord(input, BUDGET_KEYS);
    if (!isMainThread || cluster.isWorker || fields.mode !== 'local-synthetic' || fields.singleProcess !== true) {
      refuse('NOT_CONFIGURED');
    }
    return Object.freeze({
      mode: 'local-synthetic', singleProcess: true, namespace: uuidValue(fields.namespace),
      maxBufferedBytes: positiveInteger(fields.maxBufferedBytes, Number.MAX_SAFE_INTEGER),
      maxActiveStreams: positiveInteger(fields.maxActiveStreams, MAX_PG_INT),
      maxLiveOperationsPerOwner: positiveInteger(fields.maxLiveOperationsPerOwner, MAX_PG_INT),
    });
  } catch {
    refuse('NOT_CONFIGURED');
  }
}

function manager(handle: unknown, namespace: string): BudgetState {
  const state = singleton;
  if (state === undefined || state.handle !== handle || state.config.namespace !== namespace) {
    refuse('NOT_CONFIGURED');
  }
  return state;
}

export function readBudgetConfig(handle: unknown, namespace: string): FileReadBudgetConfig {
  return manager(handle, namespace).config;
}

export interface ReadReservation { readonly release: () => void }

/** Reserve overlapped staging+private copy, transport chunk and standalone output before GET. */
export function reserveRead(
  handle: FileReadBudget, namespace: string, servedBytes: number, limits: {
    readonly maxChunkBytes: number; readonly maxBufferedBytes: number; readonly maxActiveStreams: number;
  },
): ReadReservation {
  const state = manager(handle, namespace);
  const peak = 2 * servedBytes + LIFECYCLE_READ_MAX_CHUNK_BYTES + Math.min(limits.maxChunkBytes, servedBytes);
  const available = Math.min(limits.maxBufferedBytes, state.config.maxBufferedBytes) - state.bytes;
  if (!Number.isSafeInteger(peak) || peak > available
    || state.streams >= Math.min(limits.maxActiveStreams, state.config.maxActiveStreams)) {
    refuse('ACCESS_LIMIT');
  }
  state.bytes += peak;
  state.streams += 1;
  let held = true;
  return {
    release: () => {
      if (held) {
        held = false;
        state.bytes -= peak;
        state.streams -= 1;
      }
    },
  };
}
