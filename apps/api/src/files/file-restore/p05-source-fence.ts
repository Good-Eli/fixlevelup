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
    AND e.namespace_id=$3::uuid AND e.epoch=$4::bigint) AS valid,
  NOT pg_is_in_recovery() AS is_primary,
  current_database()=$1 AS database_matches,
  d.oid=$2::oid AS database_oid_matches,
  NOT d.datallowconn AS database_connections_disabled,
  current_user='fixlevelup_migrator' AND session_user=current_user AS migrator_identity,
  current_setting('default_transaction_read_only')='on' AS default_read_only,
  current_setting('transaction_read_only')='on' AS transaction_read_only,
  NOT has_database_privilege('fixlevelup_runtime',d.oid,'CONNECT') AS runtime_connect_revoked,
  NOT EXISTS (SELECT FROM pg_stat_activity a WHERE a.datid=d.oid AND a.pid<>pg_backend_pid()) AS no_other_backends,
  COALESCE((SELECT array_agg(DISTINCT a.backend_type ORDER BY a.backend_type)
    FROM pg_stat_activity a WHERE a.datid=d.oid AND a.pid<>pg_backend_pid()), ARRAY[]::text[]) AS other_backend_types,
  COALESCE((SELECT array_agg(DISTINCT a.usename::text ORDER BY a.usename::text)
    FROM pg_stat_activity a WHERE a.datid=d.oid AND a.pid<>pg_backend_pid()), ARRAY[]::text[]) AS other_backend_users,
  (SELECT count(*)::int FROM pg_stat_activity a WHERE a.datid=d.oid AND a.pid<>pg_backend_pid()) AS other_backend_count,
  NOT EXISTS (SELECT FROM pg_prepared_xacts p WHERE p.database=d.datname) AS no_prepared_xacts,
  EXISTS (SELECT FROM foundation.file_runtime_epochs e WHERE e.singleton AND e.mode='FENCED'
    AND e.namespace_id=$3::uuid AND e.epoch=$4::bigint) AS matching_fenced_epoch
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
const SOURCE_FENCE_BACKEND_DRAIN_TIMEOUT_MS = 1_500;
const SOURCE_FENCE_BACKEND_DRAIN_POLL_MS = 25;

export async function observeFencedSource(client: Client, expected: {
  readonly database: string; readonly databaseOid: number; readonly scope: LedgerScope;
  readonly profile: RestoreSchemaProfile; readonly backendPid?: number;
  readonly challenge: string; readonly manifestSha256: string;
}, limits: RestoreLimits, carried?: CarriedRestorePolicy): Promise<FencedSourceObservation> {
  if (!Number.isSafeInteger(expected.databaseOid) || expected.databaseOid < 1 || expected.databaseOid > 0xffff_ffff) {
    return refuseRestore('RESTORE_AUTHORITY');
  }
  const deadline = Date.now() + SOURCE_FENCE_BACKEND_DRAIN_TIMEOUT_MS;
  let loggedBackendWait = false;
  let lastBackendCount = 0;
  let lastBackendUsers: string[] = [];
  for (;;) {
    let retryForBackendDrain = false;
    let stage = 'begin-read-only-transaction';
    try {
      await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      try {
        stage = 'read-fence-facts';
        const result = await client.query<{ pid: number; valid: boolean; system_identifier: string | null;
          server_version_num: string | null; postmaster_start: string | null; is_primary: boolean;
          database_matches: boolean; database_oid_matches: boolean; database_connections_disabled: boolean;
          migrator_identity: boolean; default_read_only: boolean; transaction_read_only: boolean;
          runtime_connect_revoked: boolean; no_other_backends: boolean; other_backend_types: string[];
          other_backend_users: string[]; other_backend_count: number; no_prepared_xacts: boolean;
          matching_fenced_epoch: boolean }>(FENCE_SQL,
        [expected.database, expected.databaseOid, expected.scope.namespace, expected.scope.writerEpoch.toString()]);
        const fence = result.rows[0];
        const clusterIdentityPresent = typeof fence?.system_identifier === 'string'
          && /^[1-9][0-9]{0,19}$/.test(fence.system_identifier)
          && typeof fence.server_version_num === 'string' && /^[1-9][0-9]{5}$/.test(fence.server_version_num)
          && typeof fence.postmaster_start === 'string' && fence.postmaster_start.length >= 10;
        const backendPidMatches = fence !== undefined && Number.isSafeInteger(fence.pid)
          && (expected.backendPid === undefined || expected.backendPid === fence.pid);
        const onlyBackendDrainPending = fence !== undefined && fence.valid === false
          && fence.is_primary === true && fence.database_matches === true && fence.database_oid_matches === true
          && fence.database_connections_disabled === true && fence.migrator_identity === true
          && fence.default_read_only === true && fence.transaction_read_only === true
          && fence.runtime_connect_revoked === true && fence.no_other_backends === false
          && Number.isSafeInteger(fence.other_backend_count) && fence.other_backend_count > 0
          && fence.no_prepared_xacts === true && fence.matching_fenced_epoch === true
          && backendPidMatches && clusterIdentityPresent;
        if (fence?.valid !== true || !backendPidMatches || !clusterIdentityPresent) {
          if (onlyBackendDrainPending) {
            retryForBackendDrain = true;
            lastBackendCount = fence.other_backend_count;
            lastBackendUsers = fence.other_backend_users;
            if (!loggedBackendWait && process.env['FIXLEVELUP_FILE_RESTORE_TESTS'] === '1'
              && process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1') {
              loggedBackendWait = true;
              process.stderr.write('[p05-source-fence-diagnostic] '
                + JSON.stringify({ event: 'source-fence-waiting-for-backend-drain', facts: {
                  otherBackendCount: fence.other_backend_count, otherBackendUsers: fence.other_backend_users,
                } }) + String.fromCharCode(10));
            }
          } else {
            if (process.env['FIXLEVELUP_FILE_RESTORE_TESTS'] === '1'
              && process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1') {
              const facts = fence === undefined ? { rowPresent: false } : {
                rowPresent: true, isPrimary: fence.is_primary, databaseMatches: fence.database_matches,
                databaseOidMatches: fence.database_oid_matches, databaseConnectionsDisabled: fence.database_connections_disabled,
                migratorIdentity: fence.migrator_identity, defaultReadOnly: fence.default_read_only,
                transactionReadOnly: fence.transaction_read_only, runtimeConnectRevoked: fence.runtime_connect_revoked,
                noOtherBackends: fence.no_other_backends, otherBackendCount: fence.other_backend_count,
                otherBackendTypes: fence.other_backend_types, otherBackendUsers: fence.other_backend_users,
                noPreparedXacts: fence.no_prepared_xacts, matchingFencedEpoch: fence.matching_fenced_epoch,
                backendPidMatches, clusterIdentityPresent,
              };
              process.stderr.write('[p05-source-fence-diagnostic] '
                + JSON.stringify({ event: 'source-fence-refused', facts }) + String.fromCharCode(10));
            }
            return refuseRestore('RESTORE_AUTHORITY');
          }
        } else {
          const systemIdentifier = fence.system_identifier;
          const serverVersionNum = fence.server_version_num;
          const postmasterStart = fence.postmaster_start;
          if (typeof systemIdentifier !== 'string' || typeof serverVersionNum !== 'string'
            || typeof postmasterStart !== 'string') { return refuseRestore('RESTORE_AUTHORITY'); }
          const cluster: ClusterFact = Object.freeze({ systemIdentifier, serverVersionNum, postmasterStart });
          stage = 'read-p05-drain-state';
          const drain = await readP05RestoreDrainState(client, expected.profile, carried);
          stage = 'read-authority-inventory';
          const inventorySha256 = await readAuthorityInventory(client, limits);
          return Object.freeze({ ...drain, backendPid: fence.pid, nonce: expected.challenge,
            manifestSha256: expected.manifestSha256, inventorySha256, cluster,
            ...(carried === undefined ? {} : { policySha256: carried.sha256 }) });
        }
      } finally {
        await client.query('ROLLBACK');
      }
    } catch (error) {
      if (process.env['FIXLEVELUP_FILE_RESTORE_TESTS'] === '1'
        && process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1') {
        const value = error !== null && typeof error === 'object'
          ? error as { readonly name?: unknown; readonly code?: unknown } : undefined;
        const name = typeof value?.name === 'string' && /^[A-Za-z][A-Za-z0-9]{0,39}$/.test(value.name)
          ? value.name : 'UnknownError';
        const code = typeof value?.code === 'string' && /^[A-Z0-9_]{1,48}$/.test(value.code)
          ? value.code : undefined;
        process.stderr.write('[p05-source-fence-diagnostic] '
          + JSON.stringify({ event: 'source-observation-error', stage, name, ...(code === undefined ? {} : { code }) })
          + String.fromCharCode(10));
      }
      return refuseRestore('RESTORE_AUTHORITY');
    }
    if (!retryForBackendDrain) { return refuseRestore('RESTORE_AUTHORITY'); }
    if (Date.now() >= deadline) {
      if (process.env['FIXLEVELUP_FILE_RESTORE_TESTS'] === '1'
        && process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1') {
        process.stderr.write('[p05-source-fence-diagnostic] '
          + JSON.stringify({ event: 'source-fence-backend-drain-timeout', facts: {
            timeoutMs: SOURCE_FENCE_BACKEND_DRAIN_TIMEOUT_MS,
            otherBackendCount: lastBackendCount, otherBackendUsers: lastBackendUsers,
          } }) + String.fromCharCode(10));
      }
      return refuseRestore('RESTORE_AUTHORITY');
    }
    await new Promise<void>((resolveDelay) => { setTimeout(resolveDelay, SOURCE_FENCE_BACKEND_DRAIN_POLL_MS); });
  }
}
