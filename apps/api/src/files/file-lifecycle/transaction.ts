import type { Pool, PoolClient } from 'pg';
import { assertCallerTransaction, beginLegalTransaction } from '../../settings/legal/index.js';
import { isLifecycleError, refuseLifecycle } from './errors.js';

const uncertainCommits = new WeakSet<object>();

export function isLifecycleCommitUnknown(value: unknown): boolean {
  return typeof value === 'object' && value !== null && uncertainCommits.has(value);
}

export async function withLifecycleTransaction<T>(pool: Pool, run: (client: PoolClient) => Promise<T>,
  beforeCommit?: (result: T) => void,
): Promise<T> {
  let client: PoolClient;
  try {
    client = await pool.connect();
  } catch {
    refuseLifecycle('CONFLICT');
  }
  let discard = true;
  try {
    await beginLegalTransaction(client);
    await assertCallerTransaction(client);
    const result = await run(client);
    beforeCommit?.(result);
    try {
      if ((await client.query('COMMIT')).command !== 'COMMIT') {
        refuseLifecycle('CONFLICT');
      }
    } catch {
      const error = new Error('COMMIT_ACKNOWLEDGEMENT_UNKNOWN');
      uncertainCommits.add(error);
      throw error;
    }
    discard = false;
    return result;
  } catch (error) {
    if (isLifecycleCommitUnknown(error)) {
      // Do not send any other query over an ambiguously committed connection.
      throw error;
    }
    try {
      await client.query('ROLLBACK');
      discard = false;
    } catch {
      // A broken connection is never returned to the pool.
    }
    if (isLifecycleError(error)) {
      throw error;
    }
    return refuseLifecycle('CONFLICT');
  } finally {
    try {
      client.release(discard);
    } catch {
      // Pool bookkeeping is not a receipt or an error surface.
    }
  }
}
