import { randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import { signalAborted } from '../upload-coordinator/input.js';
import { auditLifecycle } from './audit.js';
import {
  BINDINGS, CONTROLS, INTENTS, checkFileAuthorization, lockFileAuthorization, lockOrCreateControl, lockTechnicalFile,
} from './authorization.js';
import type { FileAuthorization, PrivacyControl } from './authorization.js';
import { RAW_ATTEMPTS, SANITIZED_ATTEMPTS, checkOwnerWriteBudget } from './budget.js';
import type { ContentDigest, FFile, ImageMime, ProcessingContext, ProcessQuarantineReceipt } from './contract.js';
import { refuseLifecycle } from './errors.js';
import { PG_INTEGER_MAX } from './input.js';
import { PUBLICATIONS, SHA256, isImageMime, selectPublication } from './publication.js';
import type { Publication } from './publication.js';
import type { Clean, PreparedSanitized } from './processing-evidence.js';
import { assertCurrentEvidence } from './processing-evidence.js';
import { requireOriginalWriteEpoch } from './write-epoch.js';

export type ProcessCommand = FFile & { readonly signal: AbortSignal };
interface Raw {
  readonly id: string;
  readonly attempt_id: string;
  readonly actual_bytes: string;
  readonly sha256: string;
  readonly object_key: string;
  readonly storage_endpoint: string;
  readonly storage_bucket: string;
  readonly storage_region: string;
}
export interface ProcessingClaim {
  readonly id: string;
  readonly generation: number;
  readonly expiresAt: string;
  readonly until: number;
  readonly accessEpoch: string;
  readonly intentId: string;
  readonly raw: Raw;
  readonly digest: ContentDigest;
  readonly mime: ImageMime;
}
export interface SanitizedRow {
  readonly id: string;
  readonly intent_id: string;
  readonly quarantine_id: string;
  readonly owner_request_session_id: string;
  readonly lease_id: string;
  readonly lease_expires_at: string;
  readonly generation: number;
  readonly object_key: string;
  readonly storage_endpoint: string;
  readonly storage_bucket: string;
  readonly storage_region: string;
  readonly mime: ImageMime;
  readonly charged_bytes: string;
  readonly expected_sha256: string;
  readonly state: string;
}
const SANITIZED_COLUMNS = `id,intent_id,quarantine_id,owner_request_session_id,lease_id,lease_expires_at::text,generation,
  object_key,storage_endpoint,storage_bucket,storage_region,mime,charged_bytes::text,expected_sha256,state`;

type Admission = { readonly kind: 'existing'; readonly receipt: ProcessQuarantineReceipt }
  | { readonly kind: 'claimed'; readonly claim: ProcessingClaim };

function toProcessReceipt(intentId: string): ProcessQuarantineReceipt {
  return Object.freeze({ intentId, completed: true });
}

async function selectRaw(client: PoolClient, auth: FileAuthorization): Promise<Raw | undefined> {
  const { rows: [row] } = await client.query<Raw>(`SELECT q.id,q.attempt_id,q.actual_bytes::text,q.sha256,
    a.object_key,a.storage_endpoint,a.storage_bucket,a.storage_region FROM ${BINDINGS} q
    JOIN ${RAW_ATTEMPTS} a ON a.intent_id=q.intent_id AND a.id=q.attempt_id
    WHERE q.intent_id=$1 AND a.owner_request_session_id=$2 AND a.state='VERIFIED'
      AND a.verified_bytes=q.actual_bytes AND a.verified_sha256=q.sha256`, [auth.intent.id, auth.owner]);
  return row;
}

function sameRaw(left: Raw | undefined, right: Raw): boolean {
  return left !== undefined && left.id === right.id && left.attempt_id === right.attempt_id
    && left.actual_bytes === right.actual_bytes && left.sha256 === right.sha256 && left.object_key === right.object_key
    && left.storage_endpoint === right.storage_endpoint && left.storage_bucket === right.storage_bucket
    && left.storage_region === right.storage_region;
}

function sameClaim(control: PrivacyControl | undefined, claim: ProcessingClaim): boolean {
  return control !== undefined && control.processing_generation === claim.generation && control.processing_lease_id === claim.id
    && control.processing_expires_at === claim.expiresAt;
}

async function lockSanitized(client: PoolClient, claim: ProcessingClaim, attemptId: string): Promise<SanitizedRow | undefined> {
  const { rows: [row] } = await client.query<SanitizedRow>(`SELECT ${SANITIZED_COLUMNS} FROM ${SANITIZED_ATTEMPTS}
    WHERE intent_id=$1 AND id=$2 AND generation=$3 AND lease_id=$4 FOR UPDATE`,
  [claim.intentId, attemptId, claim.generation, claim.id]);
  return row;
}

function sameSanitized(row: SanitizedRow | undefined, expected: SanitizedRow): row is SanitizedRow {
  return row !== undefined && row.id === expected.id && row.intent_id === expected.intent_id && row.quarantine_id === expected.quarantine_id
    && row.owner_request_session_id === expected.owner_request_session_id && row.lease_id === expected.lease_id
    && row.lease_expires_at === expected.lease_expires_at && row.generation === expected.generation
    && row.object_key === expected.object_key && row.storage_endpoint === expected.storage_endpoint
    && row.storage_bucket === expected.storage_bucket && row.storage_region === expected.storage_region
    && row.mime === expected.mime && row.charged_bytes === expected.charged_bytes && row.expected_sha256 === expected.expected_sha256;
}

export function checkLocalLifetime(command: ProcessCommand, wallUntil: number, claim?: ProcessingClaim): void {
  if (signalAborted(command.signal)) {
    refuseLifecycle('ABORTED');
  }
  if (performance.now() >= Math.min(wallUntil, claim?.until ?? Infinity)) {
    refuseLifecycle('STALE_CLAIM');
  }
}

async function currentAuthority(client: PoolClient, auth: FileAuthorization, ctx: ProcessingContext,
  command: ProcessCommand, wallUntil: number, claim?: ProcessingClaim,
): Promise<{ readonly mime: ImageMime; readonly dbNow: string }> {
  // Budget queries/checkpoints run first. The latest authoritative clock sample
  // must be *after* any audit/row/table wait, not a clock captured before it.
  const proof = await checkFileAuthorization(client, auth, { logicalQuota: true, allowedMimeTypes: ctx.uploadPolicy.allowedMimeTypes,
    policyExpiresAt: ctx.policy.expiresAt, ...(claim === undefined ? {} : { leaseExpiresAt: claim.expiresAt }) });
  if (!isImageMime(proof.mime) || !ctx.policy.allowedMimeTypes.includes(proof.mime)) {
    refuseLifecycle('UNSUPPORTED_FORMAT');
  }
  checkLocalLifetime(command, wallUntil, claim);
  return { mime: proof.mime, dbNow: proof.dbNow };
}

export async function admitProcessing(client: PoolClient, ctx: ProcessingContext, command: ProcessCommand,
  wallUntil: number,
): Promise<Admission> {
  const auth = await lockFileAuthorization(client, command, ctx.epoch);
  requireOriginalWriteEpoch(auth.runtime);
  const publication = await selectPublication(client, command.intentId);
  const raw = await selectRaw(client, auth);
  const { mime } = await currentAuthority(client, auth, ctx, command, wallUntil);
  if (publication !== undefined && raw !== undefined && samePublicationRaw(publication, raw, mime)) {
    return { kind: 'existing', receipt: toProcessReceipt(auth.intent.id) };
  }
  if (publication !== undefined) {
    refuseLifecycle('CONFLICT');
  }
  if (raw === undefined) {
    refuseLifecycle('NOT_READY');
  }
  const bytes = Number(raw.actual_bytes);
  if (!Number.isSafeInteger(bytes) || bytes < 1 || !SHA256.test(raw.sha256)) {
    refuseLifecycle('CONFLICT');
  }
  if (bytes > ctx.policy.maxRawBytes) {
    refuseLifecycle('PROCESSING_DENIED');
  }
  const control = await lockOrCreateControl(client, auth.intent.id, auth.control);
  if (control.processing_lease_id !== null || control.processing_generation >= PG_INTEGER_MAX) {
    refuseLifecycle('PROCESSING_ACTIVE');
  }
  // No successful result can register fewer than one byte / one attempt.
  // Check that lower bound before raw/worker IO; registration charges the exact output.
  await checkOwnerWriteBudget(client, auth.owner, ctx.uploadPolicy, { bytes: 1n, slots: 1n });
  const id = randomUUID();
  const sampled = performance.now();
  const { rows: [lease] } = await client.query<{ generation: number; expires_at: string; remaining_ms: number }>(`WITH
    t AS MATERIALIZED (SELECT clock_timestamp() AS now),
    due AS (SELECT least(t.now + $3::integer * interval '1 millisecond',i.expires_at,i.policy_expires_at,s.expires_at,$4::timestamptz) AS expires_at,t.now
      FROM ${INTENTS} i JOIN foundation.request_sessions s ON s.id=i.owner_request_session_id CROSS JOIN t WHERE i.id=$1)
    UPDATE ${CONTROLS} c SET processing_generation=c.processing_generation+1,processing_lease_id=$2,processing_expires_at=due.expires_at
    FROM due WHERE c.intent_id=$1 AND c.processing_lease_id IS NULL AND c.processing_generation=$5 AND due.expires_at > due.now
    RETURNING c.processing_generation AS generation,c.processing_expires_at::text AS expires_at,
      floor(extract(epoch FROM (due.expires_at-due.now)) * 1000)::integer AS remaining_ms`,
  [auth.intent.id, id, ctx.policy.leaseMs, ctx.policy.expiresAt, control.processing_generation]);
  if (lease === undefined || lease.remaining_ms < 1) {
    refuseLifecycle('STALE_CLAIM');
  }
  const claim: ProcessingClaim = {
    id, generation: lease.generation, expiresAt: lease.expires_at, until: sampled + lease.remaining_ms,
    accessEpoch: control.access_epoch, intentId: auth.intent.id, raw, digest: Object.freeze({ bytes, sha256: raw.sha256 }), mime,
  };
  await auditLifecycle(client, 'PROCESS_CLAIM', auth.intent.id, id);
  await currentAuthority(client, auth, ctx, command, wallUntil, claim);
  return { kind: 'claimed', claim };
}

async function authorizeStage(client: PoolClient, ctx: ProcessingContext, command: ProcessCommand, claim: ProcessingClaim,
  wallUntil: number, expected?: SanitizedRow, state?: 'REGISTERED' | 'IN_FLIGHT',
): Promise<FileAuthorization> {
  const auth = await lockFileAuthorization(client, command, ctx.epoch);
  requireOriginalWriteEpoch(auth.runtime);
  const raw = await selectRaw(client, auth);
  const row = expected === undefined ? undefined : await lockSanitized(client, claim, expected.id);
  await checkOwnerWriteBudget(client, auth.owner, ctx.uploadPolicy);
  const { mime } = await currentAuthority(client, auth, ctx, command, wallUntil, claim);
  if (mime !== claim.mime || !sameRaw(raw, claim.raw) || !sameClaim(auth.control, claim) || auth.control?.access_epoch !== claim.accessEpoch
    || (expected !== undefined && (!sameSanitized(row, expected) || row.state !== state))) {
    refuseLifecycle('STALE_CLAIM');
  }
  return auth;
}

export async function authorizeWorker(client: PoolClient, ctx: ProcessingContext, command: ProcessCommand, claim: ProcessingClaim,
  wallUntil: number,
): Promise<void> {
  await authorizeStage(client, ctx, command, claim, wallUntil);
}

export async function registerSanitized(client: PoolClient, ctx: ProcessingContext, command: ProcessCommand, claim: ProcessingClaim,
  prepared: PreparedSanitized, clean: Clean, wallUntil: number,
): Promise<SanitizedRow> {
  const auth = await authorizeStage(client, ctx, command, claim, wallUntil);
  await checkOwnerWriteBudget(client, auth.owner, ctx.uploadPolicy, { bytes: BigInt(clean.served.bytes) });
  assertCurrentEvidence(ctx, clean, (await currentAuthority(client, auth, ctx, command, wallUntil, claim)).dbNow);
  const { rows: [row] } = await client.query<SanitizedRow>(`INSERT INTO ${SANITIZED_ATTEMPTS}
    (id,intent_id,owner_request_session_id,quarantine_id,generation,lease_id,lease_expires_at,object_key,storage_endpoint,
      storage_bucket,storage_region,mime,charged_bytes,expected_sha256) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
    RETURNING ${SANITIZED_COLUMNS}`, [prepared.id, auth.intent.id, auth.owner, claim.raw.id, claim.generation, claim.id,
    claim.expiresAt, prepared.key, prepared.target.endpoint, prepared.target.bucket, prepared.target.region,
    clean.mime, clean.served.bytes, clean.served.sha256]);
  if (row === undefined) {
    refuseLifecycle('CONFLICT');
  }
  await auditLifecycle(client, 'SANITIZED_REGISTER', auth.intent.id, row.id);
  assertCurrentEvidence(ctx, clean, (await currentAuthority(client, auth, ctx, command, wallUntil, claim)).dbNow);
  return row;
}

export async function dispatchSanitized(client: PoolClient, ctx: ProcessingContext, command: ProcessCommand, claim: ProcessingClaim,
  row: SanitizedRow, clean: Clean, wallUntil: number,
): Promise<void> {
  const auth = await authorizeStage(client, ctx, command, claim, wallUntil, row, 'REGISTERED');
  const { rowCount } = await client.query(`UPDATE ${SANITIZED_ATTEMPTS} SET state='IN_FLIGHT' WHERE id=$1 AND state='REGISTERED'
    AND lease_id=$2 AND generation=$3 AND lease_expires_at>clock_timestamp()`, [row.id, claim.id, claim.generation]);
  if (rowCount !== 1) {
    refuseLifecycle('STALE_CLAIM');
  }
  await auditLifecycle(client, 'SANITIZED_DISPATCH', auth.intent.id, row.id);
  assertCurrentEvidence(ctx, clean, (await currentAuthority(client, auth, ctx, command, wallUntil, claim)).dbNow);
}

export async function authorizeVerify(client: PoolClient, ctx: ProcessingContext, command: ProcessCommand, claim: ProcessingClaim,
  row: SanitizedRow, clean: Clean, wallUntil: number,
): Promise<void> {
  const auth = await authorizeStage(client, ctx, command, claim, wallUntil, row, 'IN_FLIGHT');
  assertCurrentEvidence(ctx, clean, (await currentAuthority(client, auth, ctx, command, wallUntil, claim)).dbNow);
}

export async function publishVerified(client: PoolClient, ctx: ProcessingContext, command: ProcessCommand, claim: ProcessingClaim,
  row: SanitizedRow, clean: Clean, wallUntil: number, publicationId: string,
): Promise<{ readonly receipt: ProcessQuarantineReceipt; readonly dbNow: string }> {
  const auth = await authorizeStage(client, ctx, command, claim, wallUntil, row, 'IN_FLIGHT');
  const { rowCount } = await client.query(`UPDATE ${SANITIZED_ATTEMPTS} SET state='VERIFIED',verified_bytes=$2,verified_sha256=$3
    WHERE id=$1 AND state='IN_FLIGHT' AND lease_id=$4 AND generation=$5 AND lease_expires_at>clock_timestamp()`,
  [row.id, clean.served.bytes, clean.served.sha256, claim.id, claim.generation]);
  if (rowCount !== 1) {
    refuseLifecycle('STALE_CLAIM');
  }
  await client.query(`INSERT INTO ${PUBLICATIONS} (id,intent_id,quarantine_id,raw_bytes,raw_sha256,sanitized_attempt_id,mime,
    served_bytes,served_sha256,processing_policy_id,processing_policy_sha256,engine_version,engine_image_sha256,defs_sha256,defs_built_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, [publicationId, auth.intent.id, claim.raw.id,
    claim.digest.bytes, claim.digest.sha256, row.id, clean.mime, clean.served.bytes, clean.served.sha256, ctx.policy.versionId,
    clean.policySha256, clean.engineVersion, clean.engineImageSha256, clean.defsSha256, clean.defsBuiltAt]);
  await auditLifecycle(client, 'PUBLISH', auth.intent.id, publicationId);
  // Both storage and worker were already proven locally settled; release in this
  // same commit so command completion never waits on an unauthenticated cleanup.
  await releaseProcessing(client, claim);
  const { dbNow } = await currentAuthority(client, auth, ctx, command, wallUntil, claim);
  return { dbNow, receipt: toProcessReceipt(auth.intent.id) };
}

function samePublicationRaw(publication: Publication, raw: Raw, mime: ImageMime): boolean {
  return publication.quarantine_id === raw.id && publication.raw_bytes === raw.actual_bytes
    && publication.raw_sha256 === raw.sha256 && publication.mime === mime;
}

export async function replayFinalPublication(client: PoolClient, ctx: ProcessingContext, command: ProcessCommand, claim: ProcessingClaim,
  row: SanitizedRow, publicationId: string, wallUntil: number,
): Promise<ProcessQuarantineReceipt> {
  const auth = await lockFileAuthorization(client, command, ctx.epoch);
  requireOriginalWriteEpoch(auth.runtime);
  const raw = await selectRaw(client, auth);
  const publication = await selectPublication(client, auth.intent.id);
  const { mime } = await currentAuthority(client, auth, ctx, command, wallUntil);
  if (!sameRaw(raw, claim.raw) || publication === undefined || publication.id !== publicationId
    || !samePublicationRaw(publication, claim.raw, mime) || publication.sanitized_attempt_id !== row.id
    || publication.served_bytes !== row.charged_bytes || publication.served_sha256 !== row.expected_sha256
    || publication.object_key !== row.object_key || publication.storage_endpoint !== row.storage_endpoint
    || publication.storage_bucket !== row.storage_bucket || publication.storage_region !== row.storage_region) {
    refuseLifecycle('WRITE_OUTCOME_UNKNOWN');
  }
  return toProcessReceipt(auth.intent.id);
}

/** Audit retirement and exact claim release atomically. Never infer settlement from expiry. */
export async function settleProcessing(client: PoolClient, ctx: ProcessingContext, claim: ProcessingClaim,
  attemptId: string | undefined, locallySettled: boolean,
): Promise<void> {
  const locks = await lockTechnicalFile(client, claim.intentId, ctx.epoch);
  if (!sameClaim(locks?.control, claim)) {
    return;
  }
  if (attemptId !== undefined) {
    const row = await lockSanitized(client, claim, attemptId);
    if (row?.state === 'REGISTERED' || row?.state === 'IN_FLIGHT') {
      const next = row.state === 'REGISTERED' ? 'FAILED_NOBYTES' : 'UNKNOWN';
      const { rowCount } = await client.query(`UPDATE ${SANITIZED_ATTEMPTS} SET state=$2
        WHERE id=$1 AND generation=$3 AND lease_id=$4 AND state=$5`, [row.id, next, claim.generation, claim.id, row.state]);
      if (rowCount !== 1) {
        refuseLifecycle('STALE_CLAIM');
      }
      await auditLifecycle(client, next === 'UNKNOWN' ? 'SANITIZED_UNKNOWN' : 'SANITIZED_FAILED_NOBYTES', claim.intentId, row.id);
    }
  }
  if (locallySettled) {
    await releaseProcessing(client, claim);
  }
}

async function releaseProcessing(client: PoolClient, claim: ProcessingClaim): Promise<void> {
  const { rowCount } = await client.query(`UPDATE ${CONTROLS} SET processing_lease_id=NULL,processing_expires_at=NULL
    WHERE intent_id=$1 AND processing_generation=$2 AND processing_lease_id=$3`, [claim.intentId, claim.generation, claim.id]);
  if (rowCount !== 1) {
    refuseLifecycle('STALE_CLAIM');
  }
  await auditLifecycle(client, 'PROCESS_RELEASE', claim.intentId, claim.id);
}
