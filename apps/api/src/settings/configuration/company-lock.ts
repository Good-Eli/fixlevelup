/**
 * Shared company-configuration advisory lock.
 *
 * `foundation.business_settings_versions` is the single company-wide aggregate
 * shared by P03-03's settings publisher and P03-02's geography primary pointer.
 * Two writers touch it:
 *
 * - the settings publisher appends a full policy revision (company scope only:
 *   launch mode and primary city are carried forward, never switched);
 * - the geography commands append a revision that carries the company policy
 *   columns forward when the primary city changes.
 *
 * Both take this one transaction-scoped advisory lock so the `max(version)+1`
 * sequence cannot collide and neither writer can carry forward a half-published
 * row. The lock key is fixed: `pg_advisory_xact_lock(734305, 1)`.
 *
 * ## Lock order (deadlock avoidance)
 *
 * The lock MUST be acquired before the writer touches a city row, and before it
 * inserts the row whose FK to `service_cities` is checked. PostgreSQL takes a
 * shared row lock on the referenced city for the FK check, so a publisher that
 * locked a city first and then waited for the company lock would invert the
 * geography order (city `FOR UPDATE` -> company lock) and can deadlock:
 *
 *   geography:  city FOR UPDATE -> company lock
 *   publisher:  company lock -> city FK check
 *
 * `acquireCompanySettingsLock` therefore also refuses to run outside an explicit
 * caller transaction: a transaction-scoped advisory lock taken in an implicit
 * single-statement transaction is already released, which would silently give the
 * caller no serialization at all. The check is a second statement that re-reads
 * the lock on *this* backend, so it proves the caller's transaction is still open
 * and cannot be satisfied by another session's lock.
 */
import { ConfigurationError } from './configuration-errors.js';
import type { ConfigurationClient } from './configuration-port.js';
import { mapDatabaseError } from './configuration-rows.js';

/** Advisory-lock key of the company configuration aggregate: (734305, 1). */
export const COMPANY_SETTINGS_LOCK_KEY = Object.freeze({ classId: 734305, objectId: 1 } as const);

/**
 * One SQL statement text, exported so a proof can assert the exact key. The key is
 * written literally (not interpolated) so the statement is a fixed, greppable
 * constant that cannot drift from `COMPANY_SETTINGS_LOCK_KEY` silently: a unit test
 * compares the two.
 */
export const COMPANY_SETTINGS_LOCK_SQL = 'SELECT pg_advisory_xact_lock(734305, 1)';

/**
 * Re-reads the advisory lock this backend holds inside its current transaction.
 *
 * `pg_advisory_xact_lock(int, int)` is recorded in `pg_locks` as
 * `classid = key1`, `objid = key2`, `objsubid = 2` (the two-key form). The
 * one-bigint form uses `objsubid = 1`, so checking `objsubid = 1` here would never
 * see this lock. `pid = pg_backend_pid()` keeps another session's lock from
 * satisfying the probe: only the caller's own transaction can prove itself open.
 */
export const COMPANY_SETTINGS_LOCK_HELD_SQL = `SELECT EXISTS (
  SELECT 1 FROM pg_locks
  WHERE locktype='advisory' AND granted AND pid=pg_backend_pid()
    AND classid=$1::int::oid AND objid=$2::int::oid AND objsubid=2
) AS held`;

/**
 * Takes the shared company lock inside the caller's transaction.
 *
 * Call it as the first statement of the write, before any city read/lock and
 * before the INSERT whose FK is checked against `service_cities`.
 */
export async function acquireCompanySettingsLock(client: ConfigurationClient): Promise<void> {
  // A lock_timeout (55P03) or statement cancel (57014) while waiting for the lock
  // is a retryable concurrency conflict, not an unhandled driver error.
  await client.query(COMPANY_SETTINGS_LOCK_SQL).catch(mapDatabaseError);
  const held = await client.query<{ held: boolean }>(COMPANY_SETTINGS_LOCK_HELD_SQL,
    [COMPANY_SETTINGS_LOCK_KEY.classId, COMPANY_SETTINGS_LOCK_KEY.objectId]);
  if (held.rows[0]?.held !== true) {
    throw new ConfigurationError('TRANSACTION_REQUIRED', 'client');
  }
}
