import type { PoolClient } from 'pg';

/** One DB-wide order for P02's single company. Acquire before *any* actor, link,
 * session or target row lock. READ COMMITTED: the permission/count queries in
 * subsequent statements see the winner's commit after waiting for this lock. */
export async function lockAccessPolicy(client: PoolClient, mode: 'read' | 'write'): Promise<void> {
  await client.query(mode === 'write'
    ? "SELECT pg_advisory_xact_lock(hashtextextended('fixlevelup:admin-invariant', 0))"
    : "SELECT pg_advisory_xact_lock_shared(hashtextextended('fixlevelup:admin-invariant', 0))");
}
