import type { RuntimeEpoch } from './contract.js';
import { refuseLifecycle } from './errors.js';

/**
 * The synthetic new-write profile belongs only to the original epoch. A restore
 * opens a strictly later epoch with authority over its copied-object inventory,
 * not over future raw or sanitized objects. Keep those later epochs read/delete
 * only, including an explicitly bootstrapped ACTIVE epoch greater than one.
 *
 * Call only with the authoritative epoch returned by an existing runtime lock.
 * Undefined preserves B's legacy fixture with no runtime row; C requires a row.
 */
export function requireOriginalWriteEpoch(epoch: RuntimeEpoch | undefined): void {
  if (epoch !== undefined && epoch.epoch !== 1n) {
    refuseLifecycle('NOT_CONFIGURED');
  }
}
