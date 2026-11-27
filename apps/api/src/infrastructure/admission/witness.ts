/**
 * Live launcher witness (docs/P05-PLAN.md §7, item 2).
 *
 * The external launcher holds a session-scoped advisory lock on a dedicated
 * key for the whole lifetime of an admitted instance. Runtime connections
 * verify the granted lock in pg_locks; the witness is only ever held by the
 * launcher's own connection, never by application pools. The key uses its own
 * namespace — distinct from the GEO/CFG fence (734305,1) and the catalog fence
 * (77304,1).
 */
import type { PoolClient } from 'pg';

/** Minimal pg-like statement executor: any Client or checked-out PoolClient. */
export interface WitnessConnection {
  query: PoolClient['query'];
}

/** Dedicated witness namespace; NOT the GEO/CFG (734305,1) or catalog (77304,1) key. */
export const WITNESS_KEY = { classId: 557001, objectId: 1 } as const;

export interface WitnessKey {
  readonly classId: number;
  readonly objectId: number;
}

/** Session-scoped advisory lock; the caller keeps the connection open (launcher-owned). */
export async function holdWitness(client: WitnessConnection, key: WitnessKey = WITNESS_KEY): Promise<void> {
  await client.query('SELECT pg_catalog.pg_advisory_lock($1::int, $2::int)',
    [key.classId, key.objectId]);
}

/** Releases the session-scoped witness lock held by this connection. */
export async function releaseWitness(client: WitnessConnection, key: WitnessKey = WITNESS_KEY): Promise<void> {
  await client.query('SELECT pg_catalog.pg_advisory_unlock($1::int, $2::int)',
    [key.classId, key.objectId]);
}

export interface WitnessVisibility {
  readonly visible: boolean;
  readonly pid: number;
}

/**
 * Checks pg_locks for a granted session advisory lock (objsubid=2) on the
 * exact key, in the current database, held by a pid different from this
 * connection's (the launcher's). When `expectedPid` is given, only that exact
 * holder pid counts as the witness (pid binding to the launcher identity from
 * the verified proof). Returns the holder pid, or 0 when no such grant is
 * visible.
 */
export async function witnessVisible(
  client: WitnessConnection,
  key: WitnessKey = WITNESS_KEY,
  expectedPid?: number,
): Promise<WitnessVisibility> {
  const result = await client.query<{ pid: number }>(
    `SELECT l.pid AS pid
     FROM pg_catalog.pg_locks l
     WHERE l.locktype = 'advisory' AND l.granted AND l.mode = 'ExclusiveLock'
       AND l.classid = $1::int::oid AND l.objid = $2::int::oid AND l.objsubid = 2
       AND l.database = (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname = current_database())
       AND l.pid <> pg_catalog.pg_backend_pid()
       AND ($3::int IS NULL OR l.pid = $3::int)
     ORDER BY l.pid
     LIMIT 1`,
    [key.classId, key.objectId, expectedPid ?? null]);
  const holder = result.rows[0]?.pid;
  return { visible: typeof holder === 'number', pid: typeof holder === 'number' ? holder : 0 };
}
