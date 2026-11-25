import type { Client } from 'pg';
import type { LedgerScope } from '../file-ledger/contract.js';
import type { ClusterFact, RestoreLimits } from './contract.js';
import { refuseRestore } from './contract.js';
import { readAuthorityInventory } from './inventory.js';
import { readP05RestoreDrainState, type CarriedRestorePolicy, type P05TargetDrainState, type RestoreSchemaProfile } from './p05-inventory.js';

export interface FencedSourceObservation extends P05TargetDrainState {
  readonly backendPid: number;
  readonly nonce: string;
  readonly manifestSha256: string;
  readonly inventorySha256: string;
  /** Set only after the independently read policy matched the signed manifest. */
  readonly policySha256?: string;
  /** Physical identity of the source primary, read in the same observation. */
  readonly cluster: ClusterFact;
}

/** One SQL expression set: the barrier facts, the P05 drain fact and the cluster
 * identity are read in ONE read-only snapshot, so no caller can mix a drain fact
 * from one primary with a cluster fact from another. */
const FENCE_SQL = `SELECT pg_backend_pid() AS pid,
  (SELECT system_identifier::text FROM pg_control_system()) AS system_identifier,
  current_setting('server_version_num') AS server_version_num,
  pg_postmaster_start_time()::text AS postmaster_start,
  NOT pg_is_in_recovery() AND current_database()=$1 AND d.oid=$2::oid AND NOT d.datallowconn
  AND current_user='fixlevelup_migrator' AND session_user=current_user
  AND current_setting('default_transaction_read_only')='on'
  AND current_setting('transaction_read_only')='on'
  AND NOT has_database_privilege('fixlevelup_runtime',d.oid,'CONNECT')
  AND NOT EXISTS (SELECT FROM pg_stat_activity a WHERE a.datid=d.oid AND a.pid<>pg_backend_pid())
  AND NOT EXISTS (SELECT FROM pg_prepared_xacts p WHERE p.database=d.datname)
  AND EXISTS (SELECT FROM foundation.file_runtime_epochs e WHERE e.singleton AND e.mode='FENCED'
    AND e.namespace_id=$3::uuid AND e.epoch=$4::bigint) AS valid
  FROM pg_database d WHERE d.datname=current_database()`;

/** Reads the physical cluster identity of the current primary. Exported so a
 * trusted operator bridge signs exactly the fact the core will observe, instead of
 * re-deriving it from configuration; a caller that cannot read it fails closed. */
export async function readClusterFact(client: Pick<Client, 'query'>): Promise<ClusterFact> {
  try {
    const { rows: [row] } = await client.query<{ system_identifier: string; server_version_num: string;
      postmaster_start: string }>(`SELECT (SELECT system_identifier::text FROM pg_control_system()) AS system_identifier,
        current_setting('server_version_num') AS server_version_num,
        pg_postmaster_start_time()::text AS postmaster_start`);
    if (!row || typeof row.system_identifier !== 'string' || !/^[1-9][0-9]{0,19}$/.test(row.system_identifier)
      || typeof row.server_version_num !== 'string' || !/^[1-9][0-9]{5}$/.test(row.server_version_num)
      || typeof row.postmaster_start !== 'string' || row.postmaster_start.length < 10) {
      return refuseRestore('RESTORE_AUTHORITY');
    }
    return Object.freeze({ systemIdentifier: row.system_identifier, serverVersionNum: row.server_version_num,
      postmasterStart: row.postmaster_start });
  } catch {
    return refuseRestore('RESTORE_AUTHORITY');
  }
}

/** Read one authoritative observation on the preheld, read-only source observer.
 * datallowconn=false stops new writers regardless of role; checking every other
 * backend and prepared transaction excludes writers already inside the barrier.
 * In this synthetic contour the operator must keep the barrier installed until
 * target completion; a privileged external DBA changing it is out of model. */
export async function observeFencedSource(client: Client, expected: {
  readonly database: string; readonly databaseOid: number; readonly scope: LedgerScope;
  readonly profile: RestoreSchemaProfile; readonly backendPid?: number;
  readonly challenge: string; readonly manifestSha256: string;
}, limits: RestoreLimits, carried?: CarriedRestorePolicy): Promise<FencedSourceObservation> {
  if (!Number.isSafeInteger(expected.databaseOid) || expected.databaseOid < 1 || expected.databaseOid > 0xffff_ffff) {
    return refuseRestore('RESTORE_AUTHORITY');
  }
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    try {
      const result = await client.query<{ pid: number; valid: boolean; system_identifier: string | null;
        server_version_num: string | null; postmaster_start: string | null }>(FENCE_SQL,
      [expected.database, expected.databaseOid, expected.scope.namespace, expected.scope.writerEpoch.toString()]);
      const fence = result.rows[0];
      if (fence?.valid !== true || !Number.isSafeInteger(fence.pid)
        || (expected.backendPid !== undefined && expected.backendPid !== fence.pid)
        || typeof fence.system_identifier !== 'string' || !/^[1-9][0-9]{0,19}$/.test(fence.system_identifier)
        || typeof fence.server_version_num !== 'string' || !/^[1-9][0-9]{5}$/.test(fence.server_version_num)
        || typeof fence.postmaster_start !== 'string' || fence.postmaster_start.length < 10) {
        return refuseRestore('RESTORE_AUTHORITY');
      }
      const cluster: ClusterFact = Object.freeze({ systemIdentifier: fence.system_identifier,
        serverVersionNum: fence.server_version_num, postmasterStart: fence.postmaster_start });
      const drain = await readP05RestoreDrainState(client, expected.profile, carried);
      const inventorySha256 = await readAuthorityInventory(client, limits);
      return Object.freeze({ ...drain, backendPid: fence.pid, nonce: expected.challenge,
        manifestSha256: expected.manifestSha256, inventorySha256, cluster,
        ...(carried === undefined ? {} : { policySha256: carried.sha256 }) });
    } finally {
      await client.query('ROLLBACK');
    }
  } catch {
    return refuseRestore('RESTORE_AUTHORITY');
  }
}
