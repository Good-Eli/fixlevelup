import type { Pool, PoolClient } from 'pg';
import { assertCallerTransaction, beginLegalTransaction } from '../../settings/legal/index.js';
import { isUploadError, refuse } from './contract.js';

/** Uncertain acknowledgement only; no database error properties are kept. */
export class CommitUncertain extends Error {}

export async function inUploadTransaction<T>(pool: Pool, run: (client: PoolClient) => Promise<T>): Promise<T> {
  let client: PoolClient;
  try {
    client = await pool.connect();
  } catch {
    refuse('CONFLICT');
  }
  let discard = true;
  try {
    await beginLegalTransaction(client);
    await assertCallerTransaction(client);
    const result = await run(client);
    try {
      const committed = await client.query('COMMIT');
      if (committed.command !== 'COMMIT') {
        throw new CommitUncertain();
      }
    } catch {
      throw new CommitUncertain();
    }
    discard = false;
    return result;
  } catch (error) {
    if (error instanceof CommitUncertain) {
      // Never send another statement or return this connection to the pool.
      throw error;
    }
    try {
      await client.query('ROLLBACK');
      discard = false;
    } catch {
      // Broken backend: discard on release and keep the sanitized refusal.
    }
    if (isUploadError(error)) {
      throw error;
    }
    refuse('CONFLICT');
  } finally {
    client.release(discard);
  }
}
