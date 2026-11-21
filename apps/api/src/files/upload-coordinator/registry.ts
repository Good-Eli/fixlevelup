import { randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import { currentPurposeConsent, requireLiveAnchor } from '../../settings/legal/index.js';
import type { CurrentConsent } from '../../settings/legal/index.js';
import { FileReservationError, isFileMimeType, mapLegalPortError, uuidValue } from '../reservations/index.js';
import type { FileMimeType } from '../reservations/index.js';
import type { QuarantineAttempt, StorageTarget } from '../storage/index.js';
import { refuse } from './contract.js';
import type {
  AttemptState, UploadOperationalPolicy, UploadQuarantineReceipt, UploadReservedFileCommand, VerifiedContent,
} from './contract.js';
import { assertNotAborted } from './input.js';

export const ATTEMPTS = 'foundation.file_upload_attempts';
export const INTENTS = 'foundation.file_upload_intents';
const BINDINGS = 'foundation.file_quarantine_objects';
const PURPOSE = 'REQUEST_PROCESSING';
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

interface Intent {
  readonly id: string;
  readonly state: string;
  readonly row_version: number;
  readonly consent_record_id: string;
  readonly consent_document_version_id: string;
  readonly consent_purpose: string;
  readonly declared_mime: string;
  readonly declared_bytes: string;
  readonly max_file_bytes: string;
  readonly allowed: boolean;
}

interface Authorization { readonly intent: Intent; readonly owner: string; readonly consent: CurrentConsent }
export interface UploadGrant {
  readonly row: AttemptRow;
  readonly intentVersion: number;
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

async function legal<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    try {
      mapLegalPortError(error);
    } catch (mapped) {
      if (mapped instanceof FileReservationError) {
        refuse(mapped.code);
      }
      refuse('CONFLICT');
    }
  }
}

function needConsent(consent: CurrentConsent): void {
  if (consent.granted) {
    return;
  }
  switch (consent.reason) {
    case 'SESSION_EXPIRED': return refuse('SESSION_EXPIRED');
    case 'SESSION_REVOKED': return refuse('SESSION_REVOKED');
    case 'DOCUMENT_NOT_PUBLISHED': return refuse('CONSENT_NOT_PUBLISHED');
    case 'DOCUMENT_NOT_CURRENT': return refuse('CONSENT_NOT_CURRENT');
    case 'REVOKED': return refuse('CONSENT_REVOKED');
    case 'NOT_GIVEN': return refuse('CONSENT_NOT_GIVEN');
    case 'GRANTED': return refuse('CONFLICT');
  }
}

async function lockAuthorizedIntent(client: PoolClient, command: UploadReservedFileCommand): Promise<Authorization> {
  const anchor = await legal(() => requireLiveAnchor(client, command.session));
  const consent = await legal(() => currentPurposeConsent(client, { session: command.session, purpose: PURPOSE }));
  const { rows: [intent] } = await client.query<Intent>(`SELECT id,state,row_version,consent_record_id,
    consent_document_version_id,consent_purpose,declared_mime,declared_bytes,max_file_bytes,
    allowed_mime_types ? declared_mime::text AS allowed FROM ${INTENTS}
    WHERE id=$1 AND owner_request_session_id=$2 FOR UPDATE`, [command.intentId, anchor.id]);
  if (intent === undefined) {
    refuse('NOT_FOUND');
  }
  return { intent, owner: anchor.id, consent };
}

/** Recheck using one exact database instant after all waits; no JS timestamp truncation. */
async function checkAuthorization(client: PoolClient, auth: Authorization, policy: UploadOperationalPolicy): Promise<FileMimeType> {
  const { intent, owner, consent } = auth;
  const { rows: [proof] } = await client.query<{
    session_live: boolean; session_revoked: boolean; intent_live: boolean; policy_live: boolean; within_quota: boolean;
  }>(`WITH t AS MATERIALIZED (SELECT clock_timestamp() AS now)
    SELECT s.expires_at > t.now AS session_live, s.revoked_at IS NOT NULL AS session_revoked,
      i.expires_at > t.now AS intent_live, i.policy_expires_at > t.now AS policy_live,
      (q.num <= i.max_owner_files AND q.bytes <= i.max_owner_bytes) AS within_quota
    FROM ${INTENTS} i JOIN foundation.request_sessions s ON s.id=i.owner_request_session_id CROSS JOIN t
    CROSS JOIN LATERAL (SELECT count(*) AS num,coalesce(sum(declared_bytes),0) AS bytes FROM ${INTENTS}
      WHERE owner_request_session_id=s.id AND state='RESERVED' AND expires_at > t.now) q
    WHERE i.id=$1 AND s.id=$2`, [intent.id, owner]);
  if (proof === undefined) {
    refuse('CONFLICT');
  }
  if (proof.session_revoked) {
    refuse('SESSION_REVOKED');
  }
  if (!proof.session_live) {
    refuse('SESSION_EXPIRED');
  }
  if (intent.state !== 'RESERVED') {
    refuse('INTENT_CANCELLED');
  }
  if (!proof.policy_live) {
    refuse('NOT_CONFIGURED');
  }
  if (!proof.intent_live) {
    refuse('INTENT_EXPIRED');
  }
  needConsent(consent);
  // The locked legal document has not moved since currentPurposeConsent. An old
  // GIVEN never borrows authorization from a later GIVEN even on the same form.
  if (intent.consent_purpose !== PURPOSE || consent.evidenceId !== intent.consent_record_id
    || consent.documentVersionId !== intent.consent_document_version_id) {
    refuse('CONSENT_NOT_CURRENT');
  }
  if (!proof.within_quota) {
    refuse('QUOTA_EXCEEDED');
  }
  if (!intent.allowed || !isFileMimeType(intent.declared_mime) || !policy.allowedMimeTypes.includes(intent.declared_mime)
    || BigInt(intent.declared_bytes) > BigInt(intent.max_file_bytes)) {
    refuse('NOT_CONFIGURED');
  }
  return intent.declared_mime;
}

async function ownerBudget(client: PoolClient, owner: string): Promise<{ attempts: bigint; bytes: bigint; slots: bigint }> {
  const { rows: [row] } = await client.query<{ attempts: string; bytes: string; slots: string }>(`SELECT
    count(*)::text AS attempts,coalesce(sum(charged_bytes) FILTER (WHERE state <> 'FAILED_NOBYTES'),0)::text AS bytes,
    (count(*) FILTER (WHERE state IN ('REGISTERED','IN_FLIGHT','UNKNOWN'))
      + coalesce(sum(probe_held_slots::numeric),0))::text AS slots FROM ${ATTEMPTS} WHERE owner_request_session_id=$1`, [owner]);
  if (row === undefined) {
    refuse('CONFLICT');
  }
  return { attempts: BigInt(row.attempts), bytes: BigInt(row.bytes), slots: BigInt(row.slots) };
}

export async function hasProbeCapacity(client: PoolClient, owner: string, policy: UploadOperationalPolicy): Promise<boolean> {
  return (await ownerBudget(client, owner)).slots < BigInt(policy.maxLiveOperationsPerOwner);
}

async function checkBudget(client: PoolClient, owner: string, policy: UploadOperationalPolicy, addBytes?: string): Promise<void> {
  const { attempts, bytes, slots } = await ownerBudget(client, owner);
  const newAttempt = addBytes === undefined ? 0n : 1n;
  if (attempts + newAttempt > BigInt(policy.maxAttemptsPerOwner)) {
    refuse('ATTEMPT_BUDGET_EXCEEDED');
  }
  if (bytes + BigInt(addBytes ?? '0') > BigInt(policy.maxPhysicalBytesPerOwner)) {
    refuse('PHYSICAL_BUDGET_EXCEEDED');
  }
  if (slots + newAttempt > BigInt(policy.maxLiveOperationsPerOwner)) {
    refuse('LIVE_OPERATION_LIMIT');
  }
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
  const previous = prior?.intent_id === auth.intent.id ? await lockAttempt(client, auth.intent.id, prior.id) : prior;
  const { rows: [active] } = await client.query<AttemptRow>(`SELECT ${ATTEMPT_COLUMNS} FROM ${ATTEMPTS}
    WHERE intent_id=$1 AND state IN ('REGISTERED','IN_FLIGHT') FOR UPDATE`, [auth.intent.id]);
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
  return { kind: 'new', grant: { row, intentVersion: auth.intent.row_version, mime, bytes: Number(row.charged_bytes) } };
}

async function requireGrant(client: PoolClient, command: UploadReservedFileCommand, policy: UploadOperationalPolicy,
  grant: UploadGrant, state: 'REGISTERED' | 'IN_FLIGHT',
): Promise<{ row: AttemptRow; auth: Authorization }> {
  const auth = await lockAuthorizedIntent(client, command);
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
  const auth = await lockAuthorizedIntent(client, command);
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
export async function lockTechnicalAttempt(client: PoolClient, trusted: Pick<AttemptRow, 'id' | 'intent_id'>): Promise<AttemptRow | undefined> {
  const { rows: [link] } = await client.query<{ owner: string; document_id: string }>(`SELECT
    i.owner_request_session_id AS owner,c.document_id FROM ${INTENTS} i JOIN foundation.consent_records c ON c.id=i.consent_record_id
    WHERE i.id=$1`, [trusted.intent_id]);
  if (link === undefined) {
    return undefined;
  }
  await client.query('SELECT id FROM foundation.request_sessions WHERE id=$1 FOR UPDATE', [link.owner]);
  await client.query('SELECT id FROM foundation.legal_documents WHERE id=$1 FOR UPDATE', [link.document_id]);
  await client.query(`SELECT id FROM ${INTENTS} WHERE id=$1 AND owner_request_session_id=$2 FOR UPDATE`, [trusted.intent_id, link.owner]);
  return await lockAttempt(client, trusted.intent_id, trusted.id);
}

export async function recordAttemptOutcome(client: PoolClient, grant: UploadGrant,
  phase: 'PRE_DISPATCH' | 'AFTER_DISPATCH', verified?: VerifiedContent,
): Promise<void> {
  const row = await lockTechnicalAttempt(client, grant.row);
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
