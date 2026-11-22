/**
 * P03-04 slice A: internal, F-owned file-upload reservation ports.
 *
 * Three operations exist and nothing else:
 *
 * - `reserveFileUpload` — reserves future upload capacity for one F-owned request
 *   session under a mandatory reviewed policy snapshot and the session's *current*
 *   `REQUEST_PROCESSING` GIVEN consent. It writes one immutable intent row plus one
 *   audit/outbox pair in the caller's transaction. It does not upload bytes, create
 *   a file row, return an object key or mark anything READY.
 * - `readFileUploadIntent` — the same proof/basis/liveness guards, returning only a
 *   safe projection (no token, no secret hash, no legal text, no object credential).
 * - `cancelFileUploadIntent` — a one-way CAS from RESERVED to CANCELLED. It needs no
 *   new consent (a person may withdraw a reservation after withdrawing consent) and
 *   no still-live policy or reservation expiry: authorization is the live owner
 *   proof plus the CAS version. It preserves history and releases the pending
 *   quota because the quota only counts live RESERVED rows.
 *
 * ## Mandated order (one order only, no reverse file → session lock)
 *
 * `assertCallerTransaction` (explicit READ COMMITTED) → runtime singleton `FOR
 * SHARE` when present → `request_sessions FOR UPDATE` + raw token proof →
 * `legal_documents FOR UPDATE` through `currentPurposeConsent` → the owner's
 * existing intent row → privacy control (`FOR UPDATE`) for a read/replay → a
 * fresh database-clock re-check of the anchor, the policy expiry
 * and the intent expiry after the last wait → exact current GIVEN basis → quota
 * sum/count → INSERT/receipt + audit + outbox.
 *
 * The session row lock serializes every reservation of one owner and every consent
 * revoke of that anchor, so the pending quota is counted under a stable view and no
 * separate quota mutex exists. Cancel also takes the session row first and then the
 * intent row, which keeps the same order and cannot deadlock with reserve.
 *
 * ## What the guards refuse
 *
 * - a missing/incomplete policy: `NOT_CONFIGURED`, before any database write;
 * - a staff owner: `UNSUPPORTED_OWNER`, before any database access at all;
 * - a foreign/missing session or intent: one `NOT_FOUND` (no existence oracle);
 * - a dead anchor, a stale document, a revoked or absent GIVEN, or a GIVEN that is
 *   not the exact basis stored on the intent: `SESSION_*` / `CONSENT_*`;
 * - a replay with a different payload under the same owner/key:
 *   `IDEMPOTENCY_CONFLICT`; a cancelled/expired intent is never revived;
 * - a quota that the new pending reservation would exceed: `QUOTA_EXCEEDED`.
 *
 * The database guard of migration 014 re-checks liveness, current consent, expiry
 * and quota independently of this module, and it is authoritative; a caller that
 * bypasses these ports cannot write a reservation that the guard refuses.
 */
import { randomUUID } from 'node:crypto';
import { assertAnchorLiveAfterLock, assertCallerTransaction, currentPurposeConsent, requireLiveAnchor } from '../../settings/legal/index.js';
import type { CurrentConsent } from '../../settings/legal/index.js';
import { FileReservationError } from './contract.js';
import type {
  FileIntentState, FileReservationSqlClient, FileUploadCancellation, FileUploadIntentView, FileUploadReservation,
} from './contract.js';
import { FILE_RESERVATION_PURPOSE } from './contract.js';
import { writeFileIntentAudit } from './audit.js';
import { guardFile, legalCall } from './errors.js';
import { fileIntentBodySha256 } from './hash.js';
import { isFileMimeType } from './input.js';
import type { ParsedFilePolicy, ParsedReserveFileUpload } from './input.js';
import {
  cancelFileUploadIntentInput, readFileUploadIntentInput, reserveFileUploadInput,
} from './input.js';

/** Selected columns of `foundation.file_upload_intents` this module reads/writes. */
const INTENT_COLUMN_NAMES = [
  'id', 'consent_record_id', 'consent_document_version_id', 'consent_purpose', 'policy_version_id',
  'policy_source_ref', 'policy_sha256', 'policy_expires_at', 'declared_mime', 'declared_bytes', 'expires_at',
  'created_at', 'idempotency_key', 'body_sha256', 'state', 'cancelled_at', 'row_version',
] as const;
const INTENT_COLUMNS = INTENT_COLUMN_NAMES.join(',');
const JOINED_INTENT_COLUMNS = INTENT_COLUMN_NAMES.map((column) => `i.${column}`).join(',');

interface FileIntentRow {
  readonly id: string;
  readonly consent_record_id: string | null;
  readonly consent_document_version_id: string | null;
  readonly consent_purpose: string | null;
  readonly policy_version_id: string;
  readonly policy_source_ref: string;
  readonly policy_sha256: string;
  readonly policy_expires_at: Date | null;
  readonly declared_mime: string;
  readonly declared_bytes: string | number;
  readonly expires_at: Date;
  readonly created_at: Date;
  readonly idempotency_key: string;
  readonly body_sha256: string;
  readonly state: string;
  readonly cancelled_at: Date | null;
  readonly row_version: number;
}

/** Exact current GIVEN consent basis an intent is bound to. */
interface ConsentBasis {
  readonly evidenceId: string;
  readonly documentVersionId: string;
}

interface MetadataRuntime {
  readonly namespace_id: string;
  readonly epoch: string;
  readonly mode: string;
}

/** Runtime first: an exclusive restore/fence transition waits for this transaction. */
async function lockMetadataRuntime(client: FileReservationSqlClient): Promise<void> {
  const { rows: [runtime] } = await guardFile(() => client.query<MetadataRuntime>(
    `SELECT namespace_id,epoch::text,mode FROM foundation.file_runtime_epochs WHERE singleton FOR SHARE`,
  ));
  // No row is the historical non-restored A/B-only case on the current schema.
  // Missing tables are not compatibility: driver errors still fail closed.
  if (runtime !== undefined && (runtime.mode !== 'ACTIVE'
    || typeof runtime.namespace_id !== 'string' || runtime.namespace_id.length === 0
    || typeof runtime.epoch !== 'string' || !/^[1-9]\d*$/.test(runtime.epoch))) {
    conflict();
  }
}

/** Intent lock precedes its control lock, matching C/D's irreversible decision. */
async function requireOpenMetadata(client: FileReservationSqlClient, intentId: string): Promise<void> {
  const { rows: [control] } = await guardFile(() => client.query<{ access_epoch: string; delete_state: string }>(
    `SELECT access_epoch::text,delete_state FROM foundation.file_privacy_controls WHERE intent_id=$1 FOR UPDATE`,
    [intentId],
  ));
  // Lazy absence is an unfrozen intent. Any decision epoch/state denies even a
  // replay's state/dedupe answer; a hold by itself does not grant or revoke access.
  if (control !== undefined && (control.access_epoch !== '1' || control.delete_state !== 'OPEN')) {
    conflict();
  }
}

function conflict(): never {
  throw new FileReservationError('CONFLICT');
}

function safeInteger(value: string | number): number {
  const numeric = typeof value === 'string' ? Number(value) : value;
  if (!Number.isSafeInteger(numeric) || numeric < 0) {
    conflict();
  }
  return numeric;
}

function intentState(value: string): FileIntentState {
  if (value === 'RESERVED' || value === 'CANCELLED') {
    return value;
  }
  conflict();
}

function policyExpiry(row: FileIntentRow): Date {
  if (row.policy_expires_at === null) {
    conflict();
  }
  return row.policy_expires_at;
}

/** Safe projection: identifiers, versions, sizes, MIME, state and timestamps only. */
function intentView(row: FileIntentRow): FileUploadIntentView {
  const declaredMime = row.declared_mime;
  if (!isFileMimeType(declaredMime)) {
    conflict();
  }
  if (row.consent_record_id === null || row.consent_document_version_id === null) {
    conflict();
  }
  if (row.consent_purpose !== FILE_RESERVATION_PURPOSE) {
    conflict();
  }
  return {
    intentId: row.id,
    state: intentState(row.state),
    rowVersion: row.row_version,
    declaredMime,
    declaredBytes: safeInteger(row.declared_bytes),
    expiresAt: row.expires_at.toISOString(),
    createdAt: row.created_at.toISOString(),
    policyVersionId: row.policy_version_id,
    policySourceRef: row.policy_source_ref,
    policySha256: row.policy_sha256,
    consentEvidenceId: row.consent_record_id,
    consentDocumentVersionId: row.consent_document_version_id,
    consentPurpose: FILE_RESERVATION_PURPOSE,
    cancelledAt: row.cancelled_at === null ? null : row.cancelled_at.toISOString(),
  };
}

/**
 * Minimal cancel receipt.
 *
 * Cancel deliberately bypasses the read guard (a withdrawal needs no new consent
 * and no still-live policy or reservation expiry), so it must not hand back the
 * read projection: the metadata a denied `readFileUploadIntent` refuses at that
 * very moment would otherwise leak through the cancel door. Only the intent
 * identity, its terminal state, the CAS version and the database-stamped
 * cancellation instant are returned — the exact same keys for the first cancel and
 * for a replay, with only `replayed` differing.
 */
function cancellationReceipt(row: FileIntentRow, replayed: boolean): FileUploadCancellation {
  if (row.state !== 'CANCELLED' || row.cancelled_at === null) {
    conflict();
  }
  return {
    intentId: row.id,
    state: 'CANCELLED',
    rowVersion: safeInteger(row.row_version),
    cancelledAt: row.cancelled_at.toISOString(),
    replayed,
  };
}

/** Fresh database clock, sampled after the last lock of the current path. */
async function dbClock(client: FileReservationSqlClient): Promise<Date> {
  const result = await guardFile(() => client.query<{ db_now: Date }>('SELECT clock_timestamp() AS db_now'));
  const now = result.rows[0]?.db_now;
  if (!(now instanceof Date)) {
    conflict();
  }
  return now;
}

/** Locks one intent that belongs to this anchor. Missing *or* foreign is `NOT_FOUND`. */
async function lockOwnedIntent(
  client: FileReservationSqlClient, sessionId: string, intentId: string,
): Promise<FileIntentRow> {
  const result = await guardFile(() => client.query<FileIntentRow>(
    `SELECT ${JOINED_INTENT_COLUMNS} FROM foundation.file_upload_intents i
     WHERE i.id=$1 AND i.owner_request_session_id=$2 FOR UPDATE OF i`,
    [intentId, sessionId],
  ));
  const row = result.rows[0];
  if (!row) {
    throw new FileReservationError('NOT_FOUND');
  }
  return row;
}

/** Locks the owner's intent for an idempotency key, if one exists. */
async function lockIntentByIdempotency(
  client: FileReservationSqlClient, sessionId: string, idempotencyKey: string,
): Promise<FileIntentRow | null> {
  const result = await guardFile(() => client.query<FileIntentRow>(
    `SELECT ${JOINED_INTENT_COLUMNS} FROM foundation.file_upload_intents i
     WHERE i.owner_request_session_id=$1 AND i.idempotency_key=$2 FOR UPDATE OF i`,
    [sessionId, idempotencyKey],
  ));
  return result.rows[0] ?? null;
}

/**
 * Requires the exact current GIVEN basis. A typed `CurrentConsent` refusal is
 * translated to a precise reservation code; a granted consent without an evidence
 * id/version is impossible by construction and fails closed as `CONFLICT`.
 */
function consentBasis(consent: CurrentConsent): ConsentBasis {
  if (consent.granted) {
    if (consent.evidenceId === null || consent.documentVersionId === null) {
      conflict();
    }
    return { evidenceId: consent.evidenceId, documentVersionId: consent.documentVersionId };
  }
  switch (consent.reason) {
    case 'SESSION_EXPIRED':
      throw new FileReservationError('SESSION_EXPIRED');
    case 'SESSION_REVOKED':
      throw new FileReservationError('SESSION_REVOKED');
    case 'DOCUMENT_NOT_PUBLISHED':
      throw new FileReservationError('CONSENT_NOT_PUBLISHED');
    case 'DOCUMENT_NOT_CURRENT':
      throw new FileReservationError('CONSENT_NOT_CURRENT');
    case 'REVOKED':
      throw new FileReservationError('CONSENT_REVOKED');
    case 'NOT_GIVEN':
      throw new FileReservationError('CONSENT_NOT_GIVEN');
    case 'GRANTED':
      conflict();
  }
}

/**
 * The intent is bound to exactly one GIVEN event and document revision. A new
 * GIVEN after a revoke is a different basis, so an old intent is never re-bound to
 * it and never revived.
 */
function assertCurrentBasis(row: FileIntentRow, basis: ConsentBasis): void {
  if (row.consent_record_id !== basis.evidenceId || row.consent_document_version_id !== basis.documentVersionId) {
    throw new FileReservationError('CONSENT_NOT_CURRENT');
  }
}

/** Same policy version id with a different canonical hash contradicts the stored snapshot. */
async function assertPolicyVersionStable(
  client: FileReservationSqlClient, sessionId: string, policy: ParsedFilePolicy,
): Promise<void> {
  const result = await guardFile(() => client.query(
    `SELECT 1 FROM foundation.file_upload_intents
     WHERE owner_request_session_id=$1 AND policy_version_id=$2 AND policy_sha256<>$3 LIMIT 1`,
    [sessionId, policy.versionId, policy.sha256],
  ));
  if (result.rows.length > 0) {
    throw new FileReservationError('POLICY_VERSION_CONFLICT');
  }
}

/**
 * Counts the owner's live pending reservations and compares them with the policy
 * snapshot. Only `state='RESERVED' AND expires_at > clock_timestamp()` rows count,
 * so cancelled and expired intents release their quota, and an identical replay
 * never consumes a second slot. The session row lock held by the caller serializes
 * this with every other reservation of the same owner.
 */
async function assertOwnerQuota(
  client: FileReservationSqlClient, sessionId: string, declaredBytes: number, policy: ParsedFilePolicy,
): Promise<void> {
  const result = await guardFile(() => client.query<{ active_count: number; active_bytes: string }>(
    `SELECT count(*)::int AS active_count, COALESCE(sum(declared_bytes),0)::text AS active_bytes
     FROM foundation.file_upload_intents
     WHERE owner_request_session_id=$1 AND state='RESERVED' AND expires_at > clock_timestamp()`,
    [sessionId],
  ));
  const row = result.rows[0];
  if (!row) {
    conflict();
  }
  if (row.active_count + 1 > policy.maxOwnerFiles) {
    throw new FileReservationError('QUOTA_EXCEEDED');
  }
  // bigint arithmetic in JS: never trust a float sum for the byte ceiling.
  if (BigInt(row.active_bytes) + BigInt(declaredBytes) > BigInt(policy.maxOwnerBytes)) {
    throw new FileReservationError('QUOTA_EXCEEDED');
  }
}

/** Inserts one immutable intent. State, row_version and created_at are database-owned. */
async function insertIntent(
  client: FileReservationSqlClient, sessionId: string, parsed: ParsedReserveFileUpload, basis: ConsentBasis,
  bodySha256: string,
): Promise<FileIntentRow> {
  const result = await guardFile(() => client.query<FileIntentRow>(
    `INSERT INTO foundation.file_upload_intents
       (id,owner_request_session_id,consent_record_id,consent_document_version_id,consent_purpose,
        policy_version_id,policy_source_ref,policy_sha256,allowed_mime_types,max_file_bytes,max_owner_bytes,max_owner_files,
        policy_expires_at,declared_mime,declared_bytes,expires_at,idempotency_key,body_sha256)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13,$14,$15,$16,$17,$18)
     RETURNING ${INTENT_COLUMNS}`,
    [
      randomUUID(), sessionId, basis.evidenceId, basis.documentVersionId, FILE_RESERVATION_PURPOSE,
      parsed.policy.versionId, parsed.policy.sourceRef, parsed.policy.sha256,
      JSON.stringify(parsed.policy.allowedMimeTypes), parsed.policy.maxFileBytes, parsed.policy.maxOwnerBytes,
      parsed.policy.maxOwnerFiles, parsed.policy.expiresAt, parsed.declaredMime, parsed.declaredBytes,
      parsed.expiresAt, parsed.idempotencyKey, bodySha256,
    ],
  ));
  const row = result.rows[0];
  if (!row) {
    conflict();
  }
  return row;
}

/** Canonical idempotency payload of one reserve request, including the exact basis. */
function bodySha256(parsed: ParsedReserveFileUpload, basis: ConsentBasis): string {
  return fileIntentBodySha256({
    consentDocumentVersionId: basis.documentVersionId,
    consentEvidenceId: basis.evidenceId,
    consentPurpose: FILE_RESERVATION_PURPOSE,
    declaredBytes: parsed.declaredBytes,
    declaredMime: parsed.declaredMime,
    expiresAt: parsed.expiresAt.toISOString(),
    idempotencyKey: parsed.idempotencyKey,
    policySha256: parsed.policy.sha256,
    policyVersionId: parsed.policy.versionId,
  });
}

/**
 * Idempotent replay: only the exact same owner/key/payload may return the stored
 * intent, and only after the current proof and the *exact stored* basis were
 * re-checked. A changed payload is a conflict; a cancelled or expired intent is
 * reported as dead and never revived. A replay writes no second audit/outbox pair.
 */
function replayReservation(
  row: FileIntentRow, parsed: ParsedReserveFileUpload, basis: ConsentBasis, expectedBodySha256: string, now: Date,
): FileUploadReservation {
  if (row.state === 'CANCELLED') {
    throw new FileReservationError('INTENT_CANCELLED');
  }
  if (row.state !== 'RESERVED') {
    conflict();
  }
  if (policyExpiry(row).getTime() <= now.getTime()) {
    throw new FileReservationError('NOT_CONFIGURED');
  }
  if (row.expires_at.getTime() <= now.getTime()) {
    throw new FileReservationError('INTENT_EXPIRED');
  }
  assertCurrentBasis(row, basis);
  if (row.body_sha256 !== expectedBodySha256) {
    throw new FileReservationError('IDEMPOTENCY_CONFLICT');
  }
  if (row.policy_version_id !== parsed.policy.versionId || row.policy_sha256 !== parsed.policy.sha256) {
    throw new FileReservationError('IDEMPOTENCY_CONFLICT');
  }
  return { ...intentView(row), replayed: true };
}

/**
 * Reserves one future upload slot for an F-owned session.
 *
 * The caller owns the transaction (open it with `beginFileReservationTransaction`
 * or the legal `beginLegalTransaction`) and commits so that the intent, its audit
 * row and its outbox row are one atomic unit.
 */
export async function reserveFileUpload(
  client: FileReservationSqlClient, input: unknown,
): Promise<FileUploadReservation> {
  const parsed = reserveFileUploadInput(input);
  // The guard is the first statement of the call: explicit READ COMMITTED, no
  // inherited stronger snapshot, and a proven multi-statement transaction.
  await legalCall(() => assertCallerTransaction(client));
  await lockMetadataRuntime(client);
  const anchor = await legalCall(() => requireLiveAnchor(client, parsed.session));
  // Lock order: runtime, anchor, then document. The consent answer is the exact current
  // GIVEN of REQUEST_PROCESSING for this anchor.
  const consent = await legalCall(() => currentPurposeConsent(client, {
    session: parsed.session, purpose: FILE_RESERVATION_PURPOSE,
  }));
  const basis = consentBasis(consent);
  const expectedBodySha256 = bodySha256(parsed, basis);
  // Replay lookup under the anchor lock: a concurrent duplicate of this owner
  // waits on the session row and then sees the committed intent.
  const existing = await lockIntentByIdempotency(client, anchor.id, parsed.idempotencyKey);
  if (existing !== null) {
    await requireOpenMetadata(client, existing.id);
  }
  // Last wait (including an existing privacy control) is over: re-prove liveness.
  const now = await dbClock(client);
  await legalCall(() => assertAnchorLiveAfterLock(client, anchor));
  if (parsed.policy.expiresAt.getTime() <= now.getTime()) {
    throw new FileReservationError('NOT_CONFIGURED');
  }
  if (existing !== null) {
    return replayReservation(existing, parsed, basis, expectedBodySha256, now);
  }
  // A reservation may not outlive its proof: the session expiry is the ceiling.
  if (parsed.expiresAt.getTime() > anchor.expires_at.getTime()) {
    throw new FileReservationError('INVALID_INPUT');
  }
  if (parsed.expiresAt.getTime() <= now.getTime()) {
    throw new FileReservationError('INVALID_INPUT');
  }
  await assertPolicyVersionStable(client, anchor.id, parsed.policy);
  await assertOwnerQuota(client, anchor.id, parsed.declaredBytes, parsed.policy);
  const row = await insertIntent(client, anchor.id, parsed, basis, expectedBodySha256);
  await writeFileIntentAudit(client, 'FILE_UPLOAD_INTENT_RESERVED', {
    intentId: row.id,
    sessionId: anchor.id,
    policyVersionId: parsed.policy.versionId,
    declaredMime: parsed.declaredMime,
    declaredBytes: parsed.declaredBytes,
    purpose: FILE_RESERVATION_PURPOSE,
    consentEvidenceId: basis.evidenceId,
    state: 'RESERVED',
    rowVersion: row.row_version,
  });
  return { ...intentView(row), replayed: false };
}

/**
 * Reads one own reservation under the same proof/basis/liveness guards.
 *
 * A wrong token, a missing intent and somebody else's intent all return one
 * `NOT_FOUND`: the read must not become an existence oracle. The returned
 * projection contains no token, no secret hash, no idempotency hash, no legal text
 * and no object credential.
 */
export async function readFileUploadIntent(
  client: FileReservationSqlClient, input: unknown,
): Promise<FileUploadIntentView> {
  const parsed = readFileUploadIntentInput(input);
  await legalCall(() => assertCallerTransaction(client));
  await lockMetadataRuntime(client);
  const anchor = await legalCall(() => requireLiveAnchor(client, parsed.session));
  const consent = await legalCall(() => currentPurposeConsent(client, {
    session: parsed.session, purpose: FILE_RESERVATION_PURPOSE,
  }));
  const basis = consentBasis(consent);
  const row = await lockOwnedIntent(client, anchor.id, parsed.intentId);
  await requireOpenMetadata(client, row.id);
  const now = await dbClock(client);
  await legalCall(() => assertAnchorLiveAfterLock(client, anchor));
  if (policyExpiry(row).getTime() <= now.getTime()) {
    throw new FileReservationError('NOT_CONFIGURED');
  }
  if (row.expires_at.getTime() <= now.getTime()) {
    throw new FileReservationError('INTENT_EXPIRED');
  }
  // The stored basis must still be the exact current GIVEN: a stale document or a
  // revoke followed by a new GIVEN must deny the read.
  assertCurrentBasis(row, basis);
  return intentView(row);
}

/**
 * Cancels one own reservation with a one-way CAS.
 *
 * Authorization is the live owner proof only: withdrawing a reservation is a pure
 * withdrawal, so it needs no new consent and no still-valid policy or reservation
 * expiry. Cancelling a *historical* reservation after its intent expiry (or after
 * the policy snapshot expired) is legitimate and is deliberately allowed — the
 * pending quota was already released by the expiry, and the call only records the
 * withdrawal. The transition is RESERVED → CANCELLED only, stamped by the database
 * (cancelled_at, row_version); this module sets only `state`. A stale
 * `expectedVersion` is `STALE_VERSION`; an already cancelled intent is reported
 * with `replayed: true` only when the caller presents the current version,
 * otherwise it is stale. The receipt is the minimal `FileUploadCancellation`
 * (identity, terminal state, version, database-stamped `cancelledAt`, replay flag):
 * since the call intentionally skips the read guard, it must not return the read
 * projection that `readFileUploadIntent` would refuse at that moment. Nothing is
 * deleted and no access to a file is granted.
 */
export async function cancelFileUploadIntent(
  client: FileReservationSqlClient, input: unknown,
): Promise<FileUploadCancellation> {
  const parsed = cancelFileUploadIntentInput(input);
  await legalCall(() => assertCallerTransaction(client));
  // Session lock first: the same order as reserve, so quota/cancel cannot deadlock.
  const anchor = await legalCall(() => requireLiveAnchor(client, parsed.session));
  const row = await lockOwnedIntent(client, anchor.id, parsed.intentId);
  // The intent row lock can wait; re-prove the live owner on the database clock
  // after the last wait. Expiry/consent/policy are *not* re-checked here: cancel is
  // a withdrawal, not a consumption.
  await legalCall(() => assertAnchorLiveAfterLock(client, anchor));
  if (row.state === 'CANCELLED') {
    if (row.row_version === parsed.expectedVersion) {
      return cancellationReceipt(row, true);
    }
    throw new FileReservationError('STALE_VERSION');
  }
  if (row.state !== 'RESERVED') {
    conflict();
  }
  if (row.row_version !== parsed.expectedVersion) {
    throw new FileReservationError('STALE_VERSION');
  }
  const updated = await guardFile(() => client.query<FileIntentRow>(
    `UPDATE foundation.file_upload_intents SET state='CANCELLED'
     WHERE id=$1 AND owner_request_session_id=$2 AND state='RESERVED' AND row_version=$3
     RETURNING ${INTENT_COLUMNS}`,
    [parsed.intentId, anchor.id, parsed.expectedVersion],
  ));
  const cancelled = updated.rows[0];
  if (!cancelled) {
    // The row is locked FOR UPDATE, so this can only be a version predicate miss.
    throw new FileReservationError('STALE_VERSION');
  }
  const consentEvidenceId = cancelled.consent_record_id;
  if (consentEvidenceId === null) {
    conflict();
  }
  await writeFileIntentAudit(client, 'FILE_UPLOAD_INTENT_CANCELLED', {
    intentId: cancelled.id,
    sessionId: anchor.id,
    policyVersionId: cancelled.policy_version_id,
    declaredMime: cancelled.declared_mime,
    declaredBytes: safeInteger(cancelled.declared_bytes),
    purpose: FILE_RESERVATION_PURPOSE,
    consentEvidenceId,
    state: 'CANCELLED',
    rowVersion: cancelled.row_version,
  });
  return cancellationReceipt(cancelled, false);
}
