/**
 * Caller-transaction guard for every configuration write and every locking read.
 *
 * The configuration ports never open their own transaction: the caller owns
 * BEGIN/COMMIT so the domain write, its audit row and its outbox event commit or
 * roll back together. That contract is only real if the caller actually opened a
 * transaction. A `PoolClient` used in autocommit executes each statement in its own
 * implicit transaction, which would:
 *
 * - release every `FOR UPDATE` row lock immediately, so the CAS pointer move and
 *   the version insert could interleave with another writer;
 * - commit the revision row before the audit/outbox rows, leaving a published
 *   revision without its evidence (or an audit row describing rolled-back work).
 *
 * So before any write (and before any locking read) the port proves that *this*
 * backend is inside a multi-statement transaction. The probe is a
 * transaction-local custom setting: `set_config(name, value, is_local => true)` in
 * autocommit is discarded when that single statement's transaction ends, so a
 * second statement cannot read it back. Inside an explicit transaction the value
 * survives between statements.
 *
 * The marker value is random per process, so a stale value left by an unrelated
 * connection cannot satisfy the probe. This is a correctness guard against
 * accidental autocommit, not an authentication mechanism.
 *
 * Why not the shared company advisory lock for every write: references and content
 * do not touch the company aggregate, so serializing all of them on that one key
 * would create false contention and an unnecessary lock-order coupling with
 * geography. Only the company settings publisher needs that lock.
 */
import { randomBytes } from 'node:crypto';
import { ConfigurationError } from './configuration-errors.js';
import type { ConfigurationClient } from './configuration-port.js';

/** Dotted name is required for a custom PostgreSQL setting. */
export const CONFIGURATION_TX_SETTING = 'fixlevelup.configuration_tx';

const MARKER = randomBytes(16).toString('hex');

/** One statement text, exported so a proof can assert the transaction-local form. */
export const CONFIGURATION_TX_SET_SQL = `SELECT set_config('${CONFIGURATION_TX_SETTING}',$1,true)`;

export const CONFIGURATION_TX_PROBE_SQL = `SELECT current_setting('${CONFIGURATION_TX_SETTING}',true) AS marker`;

/**
 * Throws `TRANSACTION_REQUIRED` when the caller is not inside an explicit
 * transaction. Call it as the first statement of a write, before any row lock or
 * INSERT.
 */
export async function assertCallerTransaction(client: ConfigurationClient): Promise<void> {
  await client.query(CONFIGURATION_TX_SET_SQL, [MARKER]);
  const probe = await client.query<{ marker: string | null }>(CONFIGURATION_TX_PROBE_SQL);
  if (probe.rows[0]?.marker !== MARKER) {
    throw new ConfigurationError('TRANSACTION_REQUIRED', 'client');
  }
}
