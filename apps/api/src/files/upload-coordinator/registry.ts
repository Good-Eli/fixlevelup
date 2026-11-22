import { randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import { uuidValue } from '../reservations/index.js';
import {
  BINDINGS, INTENTS, checkFileAuthorization, lockLegacyFileAuthorization, lockLegacyRuntime, lockLegacyTechnicalFile,
} from '../file-lifecycle/authorization.js';
import type { FileAuthorization } from '../file-lifecycle/authorization.js';
import { checkOwnerWriteBudget, ownerBudget, RAW_ATTEMPTS } from '../file-lifecycle/budget.js';
import type { RuntimeEpoch } from '../file-lifecycle/contract.js';
import { isLifecycleError } from '../file-lifecycle/errors.js';
import { requireOriginalWriteEpoch } from '../file-lifecycle/write-epoch.js';
import type { FileMimeType } from '../reservations/index.js';
import type { QuarantineAttempt, StorageTarget } from '../storage/index.js';
import { refuse } from './contract.js';
import type {
  AttemptState, UploadOperationalPolicy, UploadQuarantineReceipt, UploadReservedFileCommand, VerifiedContent,
} from './contract.js';
import { assertNotAborted } from './input.js';

export const ATTEMPTS = RAW_ATTEMPTS;
export const SHA256 = /^[0-9a-f]{64}$/;
export const ATTEMPT_COLUMNS = `id,intent_id,owner_request_session_id,idempotency_key,generation,upload_lease_id,
  upload_lease_expires_at::text,object_key,storage_endpoint,storage_bucket,storage_region,charged_bytes,state`;

export interface AttemptRow {
  readonly id: string;
  readonly intent_id: string;
  readonly owner_request_session_id: string;
  readonly idempotency_key: string;
  readonly generation: number;
  readonly upload_lease_id: string;
  readonly upload_lease_expires_at: string;
  readonly object_key: string;
  readonly storage_endpoint: string;
  readonly storage_bucket: string;
  readonly storage_region: string;
  readonly charged_bytes: string;
  readonly state: AttemptState;
}

type Authorization = FileAuthorization<RuntimeEpoch | undefined>;
export interface UploadGrant {
  readonly row: AttemptRow;
  readonly intentVersion: number;
  readonly epoch: RuntimeEpoch | null;
  readonly mime: FileMimeType;
  readonly bytes: number;
}

type AuditStatusByEvent = {
  REGISTERED: 'REGISTERED'; DISPATCHED: 'IN_FLIGHT'; OUTCOME: 'FAILED_NOBYTES' | 'UNKNOWN' | 'VERIFIED';
  QUARANTINED: 'QUARANTINED'; OBSERVED: 'PRESENT' | 'NOT_OBSERVED' | 'INDETERMINATE';
};
const AUDIT_STATUS: Readonly<Record<keyof AuditStatusByEvent, readonly string[]>> = {
  REGISTERED: ['REGISTERED'], DISPATCHED: ['IN_FLIGHT'], OUTCOME: ['FAILED_NOBYTES', 'UNKNOWN', 'VERIFIED'],
  QUARANTINED: ['QUARANTINED'], OBSERVED: ['PRESENT', 'NOT_OBSERVED', 'INDETERMINATE'],
};

export async function audit<K extends keyof AuditStatusByEvent>(
  client: PoolClient, event: K, row: Pick<AttemptRow, 'intent_id' | 'id' | 'generation'>, status: AuditStatusByEvent[K],
): Promise<void> {
  if (!AUDIT_STATUS[event].includes(status) || !Number.isInteger(row.generation)
    || row.generation < 1 || row.generation > 2_147_483_647) {
    refuse('CONFLICT');
  }
  const payload = JSON.stringify({ intentId: uuidValue(row.intent_id), attemptId: uuidValue(row.id), generation: row.generation, status });
  const eventId = randomUUID();
  const operation = event === 'QUARANTINED' ? 'FILE_UPLOAD_QUARANTINED' : `FILE_UPLOAD_ATTEMPT_${event}`;
  await client.query('INSERT INTO foundation.audit_logs (id,operation,correlation_id,details) VALUES ($1,$2,$3,$4::jsonb)',
    [randomUUID(), operation, eventId, payload]);
  await client.query('INSERT INTO foundation.outbox_events (id,event_id,event_type,payload) VALUES ($1,$2,$3,$4::jsonb)',
    [randomUUID(), eventId, operation, payload]);
}

async function asUpload<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    if (isLifecycleError(error)) {
      switch (error.code) {
        case 'NOT_READY': case 'UNSUPPORTED_FORMAT': case 'PROCESSING_ACTIVE': case 'PROCESSING_DENIED':
        case 'STALE_CLAIM': case 'TICKET_CLOSED': case 'ACCESS_LIMIT': return refuse('CONFLICT');
        default: return refuse(error.code);
      }
    }
    refuse('CONFLICT');
  }
}

export async function lockUploadRuntime(client: PoolClient, prior?: RuntimeEpoch | null): Promise<RuntimeEpoch | undefined> {
  return await asUpload(() => lockLegacyRuntime(client, prior));
}

async function lockAuthorizedIntent(client: PoolClient, command: UploadReservedFileCommand,
  epoch?: RuntimeEpoch | null,
): Promise<Authorization> {
  return await asUpload(async () => {
    const auth = await lockLegacyFileAuthorization(client, command, epoch);
    // A restored runtime is copy-only: its delete inventory cannot cover new keys.
    requireOriginalWriteEpoch(auth.runtime);
    return auth;
  });
}

async function checkAuthorization(client: PoolClient, auth: Authorization, policy: UploadOperationalPolicy): Promise<FileMimeType> {
  return (await asUpload(() => checkFileAuthorization(client, auth, { logicalQuota: true, allowedMimeTypes: policy.allowedMimeTypes }))).mime;
}

export async function hasProbeCapacity(client: PoolClient, owner: string, policy: UploadOperationalPolicy): Promise<boolean> {
  return (await asUpload(() => ownerBudget(client, owner))).slots < BigInt(policy.maxLiveOperationsPerOwner);
}

async function checkBudget(client: PoolClient, owner: string, policy: UploadOperationalPolicy, addBytes?: string): Promise<void> {
  await asUpload(() => checkOwnerWriteBudget(client, owner, policy,
    addBytes === undefined ? {} : { bytes: BigInt(addBytes), slots: 1n }));
}

export async function lockAttempt(client: PoolClient, intent: string, id: string): Promise<AttemptRow | undefined> {
  const { rows: [row] } = await client.query<AttemptRow>(`SELECT ${ATTEMPT_COLUMNS} FROM ${ATTEMPTS}
    WHERE intent_id=$1 AND id=$2 FOR UPDATE`, [intent, id]);
  return row;
}

function sameAttempt(left: AttemptRow, right: AttemptRow): boolean {
  return left.id === right.id && left.intent_id === right.intent_id && left.owner_request_session_id === right.owner_request_session_id
    && left.idempotency_key === right.idempotency_key && left.generation === right.generation
    && left.upload_lease_id === right.upload_lease_id && left.upload_lease_expires_at === right.upload_lease_expires_at
    && left.object_key === right.object_key && left.storage_endpoint === right.storage_endpoint
    && left.storage_bucket === right.storage_bucket && left.storage_region === right.storage_region
    && left.charged_bytes === right.charged_bytes;
}

export async function retireExpired(client: PoolClient, row: AttemptRow): Promise<'FAILED_NOBYTES' | 'UNKNOWN' | undefined> {
  if (row.state !== 'REGISTERED' && row.state !== 'IN_FLIGHT') {
    return undefined;
  }
  const state = row.state === 'REGISTERED' ? 'FAILED_NOBYTES' : 'UNKNOWN';
  const { rowCount } = await client.query(`UPDATE ${ATTEMPTS} SET state=$2 WHERE id=$1 AND state=$3
    AND upload_lease_expires_at <= clock_timestamp()`, [row.id, state, row.state]);
  if (rowCount !== 1) {
    return undefined;
  }
  await audit(client, 'OUTCOME', row, state);
  return state;
}

interface Binding { readonly id: string; readonly attempt_id: string }
async function authorizedBinding(client: PoolClient, auth: Authorization, policy: UploadOperationalPolicy,
  signal: AbortSignal,
): Promise<Binding | undefined> {
  const { rows: [row] } = await client.query<Binding>(`SELECT id,attempt_id FROM ${BINDINGS} WHERE intent_id=$1`, [auth.intent.id]);
  // Even this SELECT can wait on a relation lock. Recheck the clock while the
  // authority rows are still locked, before exposing presence or a receipt.
  await checkAuthorization(client, auth, policy);
  assertNotAborted(signal);
  return row;
}

function receipt(intentId: string, quarantineId: string, replayed: boolean): UploadQuarantineReceipt {
  return Object.freeze({ intentId, quarantineId, state: 'QUARANTINED', replayed });
}

export type Registration = { readonly kind: 'new'; readonly grant: UploadGrant }
  | { readonly kind: 'existing'; readonly receipt: UploadQuarantineReceipt };

export async function registerUploadAttempt(client: PoolClient, command: UploadReservedFileCommand,
  policy: UploadOperationalPolicy, descriptor: QuarantineAttempt, target: StorageTarget,
): Promise<Registration> {
  const auth = await lockAuthorizedIntent(client, command);
  // Owner lock serializes idempotency lookup. Only lock attempts of the requested
  // intent; a reused key for another intent is a conflict, not a reason to lock it.
  const { rows: [prior] } = await client.query<AttemptRow>(`SELECT ${ATTEMPT_COLUMNS} FROM ${ATTEMPTS}
    WHERE owner_request_session_id=$1 AND idempotency_key=$2`, [auth.owner, command.idempotencyKey]);
  const { rows: locked } = await client.query<AttemptRow>(`SELECT ${ATTEMPT_COLUMNS} FROM ${ATTEMPTS}
    WHERE intent_id=$1 AND (id=$2 OR state IN ('REGISTERED','IN_FLIGHT')) ORDER BY id FOR UPDATE`,
  [auth.intent.id, prior?.id ?? null]);
  const previous = prior?.intent_id === auth.intent.id ? locked.find((row) => row.id === prior.id) : prior;
  const active = locked.find((row) => row.state === 'REGISTERED' || row.state === 'IN_FLIGHT');
  const mime = await checkAuthorization(client, auth, policy);
  assertNotAborted(command.signal);
  if (previous !== undefined && previous.intent_id !== auth.intent.id) {
    refuse('IDEMPOTENCY_CONFLICT');
  }
  const binding = await authorizedBinding(client, auth, policy, command.signal);
  if (binding !== undefined) {
    if (binding.attempt_id !== previous?.id) {
      refuse('ALREADY_QUARANTINED');
    }
    return { kind: 'existing', receipt: receipt(auth.intent.id, binding.id, true) };
  }
  if (previous !== undefined) {
    if (previous.state === 'UNKNOWN' || previous.state === 'IN_FLIGHT') {
      refuse('WRITE_OUTCOME_UNKNOWN');
    }
    refuse(previous.state === 'REGISTERED' ? 'ATTEMPT_ACTIVE' : 'ATTEMPT_FAILED');
  }
  if (active !== undefined && await retireExpired(client, active) === undefined) {
    refuse('ATTEMPT_ACTIVE');
  }
  await checkBudget(client, auth.owner, policy, auth.intent.declared_bytes);
  const { rows: [row] } = await client.query<AttemptRow>(`WITH t AS MATERIALIZED (SELECT clock_timestamp() AS now)
    INSERT INTO ${ATTEMPTS} (id,intent_id,owner_request_session_id,idempotency_key,generation,upload_lease_id,
      upload_lease_expires_at,object_key,storage_endpoint,storage_bucket,storage_region,charged_bytes)
    SELECT $1,i.id,s.id,$2,(SELECT coalesce(max(a.generation),0)+1 FROM ${ATTEMPTS} a WHERE a.intent_id=i.id),$3,
      least(t.now + $4::integer * interval '1 millisecond',i.expires_at,i.policy_expires_at,s.expires_at),
      $5,$6,$7,$8,i.declared_bytes FROM ${INTENTS} i JOIN foundation.request_sessions s ON s.id=i.owner_request_session_id CROSS JOIN t
    WHERE i.id=$9 AND s.id=$10 AND least(i.expires_at,i.policy_expires_at,s.expires_at) > t.now
    RETURNING ${ATTEMPT_COLUMNS}`,
  [descriptor.attemptId, command.idempotencyKey, randomUUID(), policy.leaseMs,
    descriptor.objectKey, target.endpoint, target.bucket, target.region, auth.intent.id, auth.owner]);
  if (row === undefined) {
    refuse('STALE_ATTEMPT');
  }
  await audit(client, 'REGISTERED', row, 'REGISTERED');
  await checkBudget(client, auth.owner, policy);
  await checkAuthorization(client, auth, policy);
  assertNotAborted(command.signal);
  return { kind: 'new', grant: { row, intentVersion: auth.intent.row_version, epoch: auth.runtime ?? null, mime, bytes: Number(row.charged_bytes) } };
}

async function requireGrant(client: PoolClient, command: UploadReservedFileCommand, policy: UploadOperationalPolicy,
  grant: UploadGrant, state: 'REGISTERED' | 'IN_FLIGHT',
): Promise<{ row: AttemptRow; auth: Authorization }> {
  const auth = await lockAuthorizedIntent(client, command, grant.epoch);
  const row = await lockAttempt(client, auth.intent.id, grant.row.id);
  await checkAuthorization(client, auth, policy);
  if (row === undefined || !sameAttempt(row, grant.row) || row.state !== state || auth.intent.row_version !== grant.intentVersion) {
    refuse('STALE_ATTEMPT');
  }
  await checkBudget(client, auth.owner, policy);
  const { rows: [gate] } = await client.query<{ live: boolean }>(`WITH t AS MATERIALIZED (SELECT clock_timestamp() AS now)
    SELECT (least(i.expires_at,i.policy_expires_at,s.expires_at,a.upload_lease_expires_at) > t.now
      AND NOT EXISTS (SELECT 1 FROM ${ATTEMPTS} newer WHERE newer.intent_id=i.id AND newer.generation>a.generation)
      AND NOT EXISTS (SELECT 1 FROM ${BINDINGS} b WHERE b.intent_id=i.id)) AS live
    FROM ${ATTEMPTS} a JOIN ${INTENTS} i ON i.id=a.intent_id
    JOIN foundation.request_sessions s ON s.id=i.owner_request_session_id CROSS JOIN t WHERE a.id=$1`, [row.id]);
  if (gate?.live !== true) {
    refuse('STALE_ATTEMPT');
  }
  assertNotAborted(command.signal);
  return { row, auth };
}

export async function verifyRegistration(client: PoolClient, command: UploadReservedFileCommand,
  policy: UploadOperationalPolicy, grant: UploadGrant,
): Promise<void> {
  await requireGrant(client, command, policy, grant, 'REGISTERED');
}

/** Project the exact DB lease onto a conservative process-monotonic initiation deadline. */
export async function leaseDeadline(client: PoolClient, id: string, type: 'upload' | 'probe'): Promise<number> {
  const sampleStarted = performance.now();
  const column = type === 'upload' ? 'upload_lease_expires_at' : 'probe_lease_expires_at';
  const { rows: [row] } = await client.query<{ remaining_ms: number }>(`SELECT
    greatest(0,floor(extract(epoch FROM (${column} - clock_timestamp())) * 1000))::integer AS remaining_ms
    FROM ${ATTEMPTS} WHERE id=$1`, [id]);
  if (row === undefined || row.remaining_ms <= 0) {
    refuse('STALE_ATTEMPT');
  }
  return sampleStarted + row.remaining_ms;
}

export async function authorizeUploadDispatch(client: PoolClient, command: UploadReservedFileCommand,
  policy: UploadOperationalPolicy, grant: UploadGrant,
): Promise<void> {
  const { row, auth } = await requireGrant(client, command, policy, grant, 'REGISTERED');
  const { rowCount } = await client.query(`UPDATE ${ATTEMPTS} SET state='IN_FLIGHT' WHERE id=$1
    AND state='REGISTERED' AND generation=$2 AND upload_lease_id=$3 AND upload_lease_expires_at > clock_timestamp()`,
  [row.id, row.generation, row.upload_lease_id]);
  if (rowCount !== 1) {
    refuse('STALE_ATTEMPT');
  }
  await audit(client, 'DISPATCHED', row, 'IN_FLIGHT');
  await checkAuthorization(client, auth, policy);
  await leaseDeadline(client, row.id, 'upload');
  assertNotAborted(command.signal);
}

async function markVerified(client: PoolClient, row: AttemptRow, verified: VerifiedContent): Promise<boolean> {
  if (verified.actualBytes !== Number(row.charged_bytes) || !SHA256.test(verified.sha256)) {
    refuse('CONFLICT');
  }
  const { rowCount } = await client.query(`UPDATE ${ATTEMPTS} SET state='VERIFIED',verified_bytes=$2,verified_sha256=$3
    WHERE id=$1 AND state='IN_FLIGHT' AND generation=$4 AND upload_lease_id=$5 AND upload_lease_expires_at > clock_timestamp()`,
  [row.id, verified.actualBytes, verified.sha256, row.generation, row.upload_lease_id]);
  return rowCount === 1;
}

export async function finalizeUploadAttempt(client: PoolClient, command: UploadReservedFileCommand,
  policy: UploadOperationalPolicy, grant: UploadGrant, verified: VerifiedContent,
): Promise<UploadQuarantineReceipt> {
  const { row, auth } = await requireGrant(client, command, policy, grant, 'IN_FLIGHT');
  if (!await markVerified(client, row, verified)) {
    refuse('STALE_ATTEMPT');
  }
  const id = randomUUID();
  await client.query(`INSERT INTO ${BINDINGS} (id,intent_id,attempt_id,actual_bytes,sha256) VALUES ($1,$2,$3,$4,$5)`,
    [id, row.intent_id, row.id, verified.actualBytes, verified.sha256]);
  await audit(client, 'QUARANTINED', row, 'QUARANTINED');
  // A dependent insert can wait; do not rely on the JS timer alone at commit.
  await checkAuthorization(client, auth, policy);
  await leaseDeadline(client, row.id, 'upload');
  assertNotAborted(command.signal);
  return receipt(row.intent_id, id, false);
}

export async function verifyFinalCommit(client: PoolClient, command: UploadReservedFileCommand,
  policy: UploadOperationalPolicy, grant: UploadGrant,
): Promise<UploadQuarantineReceipt> {
  const auth = await lockAuthorizedIntent(client, command, grant.epoch);
  const row = await lockAttempt(client, auth.intent.id, grant.row.id);
  await checkAuthorization(client, auth, policy);
  assertNotAborted(command.signal);
  const binding = await authorizedBinding(client, auth, policy, command.signal);
  if (row === undefined || row.state !== 'VERIFIED' || !sameAttempt(row, grant.row) || binding?.attempt_id !== row.id) {
    refuse('WRITE_OUTCOME_UNKNOWN');
  }
  return receipt(row.intent_id, binding.id, true);
}

/** Technical accounting only: immutable DB lookup, then the same forward lock order. */
export async function lockTechnicalAttempt(client: PoolClient, trusted: Pick<AttemptRow, 'id' | 'intent_id'>,
  options: { readonly epoch?: RuntimeEpoch | null; readonly requireOpen?: boolean } = {},
): Promise<AttemptRow | undefined> {
  const locks = await asUpload(() => lockLegacyTechnicalFile(client, trusted.intent_id, options.epoch));
  if (locks === undefined) {
    return undefined;
  }
  if (options.requireOpen === true && locks.control !== undefined && locks.control.access_epoch !== '1') {
    return undefined;
  }
  return await lockAttempt(client, trusted.intent_id, trusted.id);
}

export async function recordAttemptOutcome(client: PoolClient, grant: UploadGrant,
  phase: 'PRE_DISPATCH' | 'AFTER_DISPATCH', verified?: VerifiedContent,
): Promise<void> {
  const row = await lockTechnicalAttempt(client, grant.row, { epoch: grant.epoch });
  if (row === undefined || !sameAttempt(row, grant.row)) {
    return;
  }
  if (phase === 'PRE_DISPATCH' && row.state === 'REGISTERED') {
    await client.query(`UPDATE ${ATTEMPTS} SET state='FAILED_NOBYTES' WHERE id=$1 AND state='REGISTERED'`, [row.id]);
    await audit(client, 'OUTCOME', row, 'FAILED_NOBYTES');
  } else if (phase === 'AFTER_DISPATCH' && row.state === 'IN_FLIGHT') {
    if (verified !== undefined && await markVerified(client, row, verified)) {
      await audit(client, 'OUTCOME', row, 'VERIFIED');
      return;
    }
    const { rowCount } = await client.query(`UPDATE ${ATTEMPTS} SET state='UNKNOWN' WHERE id=$1
      AND state='IN_FLIGHT' AND upload_lease_expires_at > clock_timestamp()`, [row.id]);
    if (rowCount === 1) {
      await audit(client, 'OUTCOME', row, 'UNKNOWN');
    }
  }
}
