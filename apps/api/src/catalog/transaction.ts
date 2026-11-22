import { randomUUID } from 'node:crypto';
import type { CatalogClient } from './contracts.js';
import { CatalogError, CatalogInternalError } from './validation.js';

export const READ_TX_SETTING = 'fixlevelup.catalog_read_tx';

function sqlError(error: unknown): { code?: unknown; constraint?: unknown } {
  return typeof error === 'object' && error !== null ? error : {};
}

/** Only explicit domain constraints are mapped; never expose driver messages. */
function mutationError(error: unknown): CatalogError | CatalogInternalError {
  if (error instanceof CatalogError || error instanceof CatalogInternalError) {
    return error;
  }
  const { code, constraint } = sqlError(error);
  if (code === '23P01' && constraint === 'catalog_price_periods_no_overlap') {
    return new CatalogError('CONFLICT', 'period');
  }
  if (code === '23514') {
    if (constraint === 'catalog_price_periods_future_start_guard') {
      return new CatalogError('CONFLICT', 'validFrom');
    }
    if (constraint === 'catalog_price_periods_close_guard') {
      return new CatalogError('CONFLICT', 'at');
    }
    if (constraint === 'catalog_price_periods_final_clock_guard') {
      return new CatalogError('CONFLICT', 'period');
    }
  }
  return new CatalogInternalError();
}

/**
 * SAVEPOINT proves that this backend is in a caller-owned transaction. A domain
 * error in JS does not abort PostgreSQL on its own: roll back the whole port,
 * including any evidence and writes, before returning any error to the caller.
 * Successful operations retain the exclusive catalog fence until caller COMMIT.
 */
export async function mutate<T>(client: CatalogClient, run: () => Promise<T>): Promise<T> {
  const point = `catalog_${randomUUID().replaceAll('-', '')}`;
  try {
    await client.query(`SAVEPOINT ${point}`);
  } catch (error) {
    if (sqlError(error).code === '25P01') {
      throw new CatalogError('TRANSACTION_REQUIRED');
    }
    throw new CatalogInternalError();
  }
  try {
    const { rows } = await client.query<{ read_committed: boolean }>(`SELECT
      pg_catalog.pg_advisory_xact_lock(77304, 1),
      pg_catalog.current_setting('transaction_isolation') = 'read committed' AS read_committed`);
    if (rows[0]?.read_committed !== true) {
      throw new CatalogError('ISOLATION_REQUIRED');
    }
    const result = await run();
    await client.query(`RELEASE SAVEPOINT ${point}`);
    return result;
  } catch (error) {
    try {
      await client.query(`ROLLBACK TO SAVEPOINT ${point}`);
      await client.query(`RELEASE SAVEPOINT ${point}`);
    } catch {
      // Do not claim a clean domain refusal if the transaction could not recover.
      throw new CatalogInternalError();
    }
    throw mutationError(error);
  }
}

/** Must be the first read statement and distinct from the pricing snapshot. */
export async function fenceRead(client: CatalogClient): Promise<string> {
  const marker = randomUUID();
  try {
    await client.query(`SELECT pg_catalog.pg_advisory_xact_lock_shared(77304, 1),
      pg_catalog.set_config('${READ_TX_SETTING}', $1, true)`, [marker]);
  } catch {
    throw new CatalogInternalError();
  }
  return marker;
}

export async function read<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    if (error instanceof CatalogError || error instanceof CatalogInternalError) {
      throw error;
    }
    throw new CatalogInternalError();
  }
}
