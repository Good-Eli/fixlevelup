import type { Client } from 'pg';
import type { LedgerScope } from '../file-ledger/contract.js';
import type { RestoreLimits } from './contract.js';
import { refuseRestore } from './contract.js';
import { readAuthorityInventory } from './inventory.js';
import { readP05TargetDrainState, type P05TargetDrainState, type RestoreSchemaProfile } from './p05-inventory.js';

/** Read one authoritative observation on the preheld, read-only source observer.
 * datallowconn=false stops new writers regardless of role; checking every other
 * backend and prepared transaction excludes writers already inside the barrier.
 * In this synthetic contour the operator must keep the barrier installed until
 * target completion; a privileged external DBA changing it is out of model. */
export async function observeFencedSource(client: Client, expected: {
  readonly database: string; readonly databaseOid: number; readonly scope: LedgerScope;
  readonly profile: RestoreSchemaProfile; readonly backendPid?: number;
  readonly challenge: string; readonly manifestSha256: string;
}, limits: RestoreLimits): Promise<P05TargetDrainState & {
  readonly backendPid: number; readonly nonce: string; readonly manifestSha256: string; readonly inventorySha256: string;
}> {
  if (!Number.isSafeInteger(expected.databaseOid) || expected.databaseOid < 1 || expected.databaseOid > 0xffff_ffff) {
    return refuseRestore('RESTORE_AUTHORITY');
  }
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    try {
      const result = await client.query<{ pid: number; valid: boolean }>(`SELECT pg_backend_pid() AS pid,
        NOT pg_is_in_recovery() AND current_database()=$1 AND d.oid=$2::oid AND NOT d.datallowconn
        AND current_user='fixlevelup_migrator' AND session_user=current_user
        AND current_setting('default_transaction_read_only')='on'
        AND current_setting('transaction_read_only')='on'
        AND NOT has_database_privilege('fixlevelup_runtime',d.oid,'CONNECT')
        AND NOT EXISTS (SELECT FROM pg_stat_activity a WHERE a.datid=d.oid AND a.pid<>pg_backend_pid())
        AND NOT EXISTS (SELECT FROM pg_prepared_xacts p WHERE p.database=d.datname)
        AND EXISTS (SELECT FROM foundation.file_runtime_epochs e WHERE e.singleton AND e.mode='FENCED'
          AND e.namespace_id=$3::uuid AND e.epoch=$4::bigint) AS valid
        FROM pg_database d WHERE d.datname=current_database()`,
      [expected.database, expected.databaseOid, expected.scope.namespace, expected.scope.writerEpoch.toString()]);
      const fence = result.rows[0];
      if (fence?.valid !== true || !Number.isSafeInteger(fence.pid)
        || (expected.backendPid !== undefined && expected.backendPid !== fence.pid)) {
        return refuseRestore('RESTORE_AUTHORITY');
      }
      const drain = await readP05TargetDrainState(client, expected.profile);
      const inventorySha256 = await readAuthorityInventory(client, limits);
      return Object.freeze({ ...drain, backendPid: fence.pid, nonce: expected.challenge,
        manifestSha256: expected.manifestSha256, inventorySha256 });
    } finally {
      await client.query('ROLLBACK');
    }
  } catch {
    return refuseRestore('RESTORE_AUTHORITY');
  }
}
