/**
 * Caller-transaction and isolation guard for every legal write and every locking
 * read.
 *
 * The legal ports do not open their own transaction: the caller owns
 * BEGIN/COMMIT so that domain writes, audit and outbox commit or roll back
 * together. That contract is only real if the caller actually opened a
 * transaction. A `PoolClient` used in autocommit executes each statement in its
 * own implicit transaction, which would:
 *
 * - release every `FOR UPDATE` row lock immediately, destroying the mandated
 *   session → document serialization;
 * - commit the document revision before the CAS pointer move, leaving a
 *   half-published revision;
 * - commit the consent event before its audit/outbox row.
 *
 * ## Why the isolation level is part of the guard
 *
 * A consent decision is only correct against the *latest committed* evidence. The
 * database guard locks the anchor and the document, but it does not rewrite the
 * anchor row when a consent is revoked, so a transaction that pinned an older
 * snapshot (REPEATABLE READ / SERIALIZABLE) can still see a `GIVEN` event as
 * active after another transaction committed its `REVOKED` event. That stale
 * answer would be reported as `GRANTED`, which is exactly the fail-open the port
 * must never produce.
 *
 * Therefore the guard establishes `READ COMMITTED` explicitly, before its first
 * data read/change, and verifies the *actual* level from the server instead of
 * relying on a PostgreSQL/ORM default:
 *
 * 1. `SET TRANSACTION ISOLATION LEVEL READ COMMITTED` is the first statement. It
 *    succeeds when no snapshot exists yet (including a transaction started with
 *    `BEGIN ISOLATION LEVEL REPEATABLE READ` and a session whose
 *    `default_transaction_isolation` is stronger) and is a harmless no-op in an
 *    already-READ-COMMITTED transaction, even after earlier statements. If the
 *    transaction already acquired a snapshot under a stronger level, PostgreSQL
 *    refuses it with SQLSTATE 25001; that is translated to a typed refusal and the
 *    call fails closed instead of deciding on the stale snapshot.
 * 2. `current_setting('transaction_isolation')` proves the level that is actually
 *    in force; anything but `read committed` is refused.
 * 3. The transaction-local marker proves that *this* backend is inside a
 *    multi-statement transaction: `set_config(name, value, is_local => true)` in
 *    autocommit is discarded when that single statement's transaction ends, so a
 *    second statement cannot read it back. Inside an explicit transaction the
 *    value survives between statements.
 *
 * The marker value is random per process, so a stale value left by an unrelated
 * connection cannot satisfy the probe. This is a correctness guard against
 * accidental autocommit and a stale snapshot, not an authentication mechanism: a
 * caller that deliberately wants to defeat it can simply not use these ports.
 *
 * The guard never rolls back, restarts or upgrades a transaction on the caller's
 * behalf: a failed guard is a caller bug that must be retried in a fresh
 * transaction opened with `beginLegalTransaction`.
 */
import { randomBytes } from 'node:crypto';
import { LegalPortError } from './legal-contract.js';
import type { LegalSqlClient } from './legal-contract.js';
import { guard } from './legal-errors.js';

/** Dotted name is required for a custom PostgreSQL setting. */
export const LEGAL_TX_SETTING = 'fixlevelup.legal_tx';

const MARKER = randomBytes(16).toString('hex');

/** The isolation the ports require, and the only level a decision may run under. */
export const LEGAL_REQUIRED_ISOLATION = 'read committed';

/**
 * Explicit transaction start for callers of these ports. `BEGIN ISOLATION LEVEL
 * READ COMMITTED` overrides a stronger session default, so a caller cannot inherit
 * an unsafe level by accident.
 */
export const LEGAL_BEGIN_SQL = 'BEGIN ISOLATION LEVEL READ COMMITTED';

/**
 * Idempotent isolation assertion, executed as the first statement of every guarded
 * port call. In a transaction without a snapshot it sets READ COMMITTED; in an
 * already-READ-COMMITTED transaction it is a no-op (same level is allowed even
 * after earlier statements); in a transaction that already pinned a stronger
 * snapshot PostgreSQL raises 25001, which fails the call closed.
 */
export const LEGAL_ISOLATION_SQL = 'SET TRANSACTION ISOLATION LEVEL READ COMMITTED';

/** Reads the level actually in force; never assumed from a default. */
export const LEGAL_ISOLATION_PROBE_SQL = "SELECT current_setting('transaction_isolation') AS isolation";

/** One statement text, exported so a test can assert the exact transaction-local form. */
export const LEGAL_TX_SET_SQL = `SELECT set_config('${LEGAL_TX_SETTING}',$1,true)`;

export const LEGAL_TX_PROBE_SQL = `SELECT current_setting('${LEGAL_TX_SETTING}',true) AS marker`;

/**
 * Opens the caller's transaction with the required isolation. Use this instead of a
 * bare `BEGIN`: it makes READ COMMITTED explicit at the only point where PostgreSQL
 * still allows it to be chosen, before the first data read/change.
 */
export async function beginLegalTransaction(client: LegalSqlClient): Promise<void> {
  await client.query(LEGAL_BEGIN_SQL);
}

/**
 * Throws `LegalPortError('CONFLICT')` when the caller's transaction cannot be
 * proved to be an explicit READ COMMITTED transaction.
 *
 * The code is deliberately the same retryable/concurrency code: the call is a
 * programming error at the integration point (no transaction, a stale snapshot, or
 * an aborted transaction), and no caller-visible detail is needed by an internal
 * port. It is never translated into a consent answer, so it can never be reported
 * as `GRANTED`.
 */
export async function assertCallerTransaction(client: LegalSqlClient): Promise<void> {
  // 1. Explicit isolation, before any data read/change. `guard` maps 25001.
  await guard(() => client.query(LEGAL_ISOLATION_SQL));
  // 2. Verify the level that is actually in force, never a presumed default.
  const isolation = await guard(() => client.query<{ isolation: string }>(LEGAL_ISOLATION_PROBE_SQL));
  if (isolation.rows[0]?.isolation !== LEGAL_REQUIRED_ISOLATION) {
    throw new LegalPortError('CONFLICT');
  }
  // 3. Prove that this backend is inside a multi-statement transaction.
  await client.query(LEGAL_TX_SET_SQL, [MARKER]);
  const probe = await client.query<{ marker: string | null }>(LEGAL_TX_PROBE_SQL);
  if (probe.rows[0]?.marker !== MARKER) {
    throw new LegalPortError('CONFLICT');
  }
}
