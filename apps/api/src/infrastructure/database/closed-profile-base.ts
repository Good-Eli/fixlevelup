import type { Client } from 'pg';
import { LegacyReadinessProbes } from './legacy-readiness.js';

/** Closed restore targets cannot grant runtime CONNECT just to check their shape.
 * Use the same predicates, on the pinned observer, measuring the runtime role's
 * rights, not the rights of the observer. The caller owns the transaction. */
export async function verifyClosedBase(client: Pick<Client, 'query'>): Promise<boolean> {
  try {
    const { rows } = await client.query<{ database: string; primary: boolean; role: string }>(
      'SELECT current_database() AS database, NOT pg_catalog.pg_is_in_recovery() AS primary, current_user AS role',
    );
    const target = rows[0];
    if (target?.primary !== true || target.role !== 'fixlevelup_migrator') { return false; }
    const probes = new LegacyReadinessProbes(client, target.database, true, 'fixlevelup_migrator');
    return await probes.ready() && await probes.catalogManagementReady();
  } catch { return false; }
}
