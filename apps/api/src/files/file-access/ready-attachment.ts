/**
 * P05 §5.2 — narrow in-transaction READY attachment admission.
 *
 * This module is the only P05 application port that turns already-published P03
 * files into `foundation.request_files` rows. It is deliberately *not* a public
 * upload/read/download surface: it accepts an F owner session proof plus a bounded
 * list of publication UUIDs, runs inside the caller's submit transaction on the
 * caller's `PoolClient`, and returns safe `{fileId, mime, bytes}` views plus one
 * internal commit deadline shared by the set. It never
 * returns an object key, a storage endpoint/bucket/region, a stream ticket, a
 * signed URL or a read claim, and it never reads or writes bytes.
 *
 * ## Two-call prefix
 *
 * The caller owns the P05 transaction and the single mandated lock order
 * (`runtime → anchor → legal → request target → request row → intent → control →
 * publication evidence`). Because a later `FOR SHARE` on the runtime row could wait
 * behind a queued exclusive epoch flip, the runtime proof is a separate first step:
 *
 * 1. `lockAttachmentRuntime(client, ctx)` — must be called **before** the F anchor;
 *    it takes the existing P03 runtime `FOR SHARE` and returns an opaque token.
 * 2. after the caller has locked the anchor/legal parents, inserted its request
 *    aggregate, submit edge and command event, and (optionally) forced its own
 *    deferred checks, `admitReadyAttachments(client, token, input)` runs the
 *    attachment part on the same client. It re-proves the runtime, anchor, exact
 *    current GIVEN basis, request/submit-edge binding and every file window with
 *    plain post-wait reads — never a second runtime lock and never an extra legal
 *    parent lock that would invert the prefix.
 *
 * The port never opens a nested transaction and never commits: `request_files`
 * rows, the caller's command event and receipt stay one atomic unit.
 *
 * ## What is re-proved (nothing is taken on trust)
 *
 * - runtime is `ACTIVE` at exactly the locked namespace/epoch (P03 return guard);
 * - the anchor secret matches its stored digest, the anchor is live on the database
 *   clock and is not revoked;
 * - the supplied consent evidence is the exact `REQUEST_PROCESSING` `GIVEN` of that
 *   anchor, is not superseded, and still names the document's current revision;
 * - the request is an F `REPAIR` of the anchor's own city/version and the committed
 *   `request_session_submits` edge binds exactly this session, request and consent;
 * - every requested publication is the exact `READY` publication (`fileId =
 *   file_publications.id`) of a `VERIFIED` sanitized attempt, owned by this anchor;
 * - each intent is `RESERVED`, its privacy control is `OPEN` at access epoch 1 (a
 *   missing control is created lazily through the existing port), the publication
 *   evidence is re-read under the intent lock, and the existing
 *   `checkFileAuthorization`/access-window proofs pass;
 * - no file/intent is already linked to any request, and the complete list fits the
 *   configured attachment count/byte budget;
 * - after the insert and the forced deferred constraints, the same window proof is
 *   repeated for every attached file on a fresh database clock.
 *
 * Any missing/foreign/stale/drifted fact is a typed refusal with zero side effects;
 * a schema that is not exactly the reviewed S3 interlock is `NOT_CONFIGURED`, never
 * a legacy fallback.
 */
import type { PoolClient } from 'pg';
import { assertCallerTransaction, sessionSecretMatches } from '../../settings/legal/index.js';
import type { CurrentConsent } from '../../settings/legal/index.js';
import {
  checkFileAuthorization, lockAttachmentFileAuthorization, lockRuntime, probeAttachmentInterlock,
  verifyAttachmentRuntime,
} from '../file-lifecycle/authorization.js';
import type { AttachmentRuntimeLock } from '../file-lifecycle/authorization.js';
import type { FFile, ImageMime, RuntimeEpoch } from '../file-lifecycle/contract.js';
import { isLifecycleError, refuseLifecycle } from '../file-lifecycle/errors.js';
import { canonicalUuid, ownFields, positive, snapshotDate, snapshotEpoch } from '../file-lifecycle/input.js';
import { selectPublication } from '../file-lifecycle/publication.js';
import { FileReservationError, fileSessionProof, mapLegalPortError, uuidValue } from '../reservations/index.js';
import type { FileOwnerSessionProof } from '../reservations/index.js';
import { proveReadyWindow } from './registry.js';
import type { ReadyWindowPolicy } from './registry.js';

const REQUEST_FILES = 'foundation.request_files';
const SESSIONS = 'foundation.request_sessions';
const CONSENTS = 'foundation.consent_records';
const REQUESTS = 'foundation.requests';
const SUBMITS = 'foundation.request_session_submits';
const PUBLICATIONS = 'foundation.file_publications';
const INTENTS = 'foundation.file_upload_intents';
const PURPOSE = 'REQUEST_PROCESSING';

/** Closed image vocabulary: PDF/video/animation never become a READY attachment. */
const ATTACHMENT_MIMES: readonly ImageMime[] = Object.freeze(['image/jpeg', 'image/png', 'image/webp']);
/** Technical ceilings only; the configured policy supplies the real budgets. */
const MAX_ATTACHMENTS = 16;
const MAX_ATTACHMENT_BYTES = 67_108_864;
const MAX_ACCESS_AGE_MS = 2_147_483_647;

export interface ReadyAttachmentPolicy {
  readonly mode: 'local-synthetic';
  /** Access-policy expiry; the attachment must stay inside the original READY window. */
  readonly expiresAt: Date;
  readonly maxAccessAgeMs: number;
  readonly maxFiles: number;
  readonly maxBytes: number;
}

export interface ReadyAttachmentContext {
  readonly epoch: RuntimeEpoch;
  readonly policy: ReadyAttachmentPolicy;
}

/** The only projection this port returns: no storage capability of any kind. */
export interface ReadyAttachment {
  readonly fileId: string;
  readonly mime: ImageMime;
  readonly bytes: number;
}

/** Opaque proof that `lockAttachmentRuntime` ran first in this transaction. */
export interface ReadyAttachmentRuntime {
  readonly ready: true;
}

interface LockedAttachmentRuntime {
  readonly runtime: RuntimeEpoch;
  readonly policy: ReadyAttachmentPolicy;
  /** The exact `PoolClient` the runtime lock was taken on. */
  readonly client: object;
}

const lockedRuntimes = new WeakMap<object, LockedAttachmentRuntime>();

interface AttachmentCommand {
  readonly requestId: string;
  readonly session: FileOwnerSessionProof;
  readonly consentEvidenceId: string;
  readonly consentDocumentVersionId: string;
  readonly fileIds: readonly string[];
}

interface AnchorFacts {
  readonly id: string;
  readonly secret_hash: string;
  readonly intake_city_id: string;
  readonly intake_city_version_id: string;
  readonly revoked: boolean;
  readonly live: boolean;
}

interface ConsentFacts {
  readonly evidence_id: string;
  readonly document_id: string;
  readonly document_version_id: string;
  readonly occurred_at: string;
  readonly unrevoked: boolean;
  readonly current: boolean;
  readonly published: boolean;
}

interface RequestFacts {
  readonly id: string;
  readonly type: string;
  readonly city_id: string;
  readonly intake_city_version_id: string;
  readonly edge_session_id: string | null;
  readonly edge_consent_id: string | null;
  readonly edge_document_version_id: string | null;
  readonly edge_command: string | null;
}

interface PublicationFacts {
  readonly id: string;
  readonly intent_id: string;
  readonly mime: string;
  readonly served_bytes: string;
}

function attachmentPolicy(value: unknown): ReadyAttachmentPolicy {
  try {
    const fields = ownFields(value, ['mode', 'expiresAt', 'maxAccessAgeMs', 'maxFiles', 'maxBytes']);
    if (fields['mode'] !== 'local-synthetic') {
      refuseLifecycle('NOT_CONFIGURED');
    }
    return Object.freeze({
      mode: 'local-synthetic',
      expiresAt: snapshotDate(fields['expiresAt']),
      maxAccessAgeMs: positive(fields['maxAccessAgeMs'], MAX_ACCESS_AGE_MS),
      maxFiles: positive(fields['maxFiles'], MAX_ATTACHMENTS),
      maxBytes: positive(fields['maxBytes'], MAX_ATTACHMENT_BYTES),
    });
  } catch {
    return refuseLifecycle('NOT_CONFIGURED');
  }
}

function attachmentContext(value: unknown): { epoch: RuntimeEpoch; policy: ReadyAttachmentPolicy } {
  try {
    const fields = ownFields(value, ['epoch', 'policy']);
    return Object.freeze({ epoch: snapshotEpoch(fields['epoch']), policy: attachmentPolicy(fields['policy']) });
  } catch {
    return refuseLifecycle('NOT_CONFIGURED');
  }
}

function readLockedRuntime(token: unknown, client: PoolClient): LockedAttachmentRuntime {
  const locked = typeof token === 'object' && token !== null ? lockedRuntimes.get(token) : undefined;
  if (locked === undefined) {
    refuseLifecycle('NOT_CONFIGURED');
  }
  // The proof is bound to the exact client that took the `FOR SHARE` row lock: a
  // token replayed on another pooled connection would otherwise let the admission
  // run in a transaction that never locked the runtime before its anchor.
  if (locked.client !== client) {
    refuseLifecycle('NOT_CONFIGURED');
  }
  return locked;
}

/** Consume the proof: one admission attempt per runtime lock, in this transaction. */
function consumeLockedRuntime(token: object): void {
  lockedRuntimes.delete(token);
}

function uuidList(value: unknown, maxFiles: number): readonly string[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    return refuseLifecycle('INVALID_INPUT');
  }
  const length = Reflect.getOwnPropertyDescriptor(value, 'length')?.value;
  if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < 1 || length > maxFiles) {
    return refuseLifecycle('INVALID_INPUT');
  }
  if (Reflect.ownKeys(value).length !== length + 1) {
    return refuseLifecycle('INVALID_INPUT');
  }
  const seen = new Set<string>();
  const result: string[] = [];
  for (let index = 0; index < length; index += 1) {
    const field = Reflect.getOwnPropertyDescriptor(value, String(index));
    if (field === undefined || !Object.hasOwn(field, 'value')) {
      return refuseLifecycle('INVALID_INPUT');
    }
    const id = uuidValue(field.value);
    if (seen.has(id)) {
      return refuseLifecycle('INVALID_INPUT');
    }
    seen.add(id);
    result.push(id);
  }
  return Object.freeze(result);
}

function attachmentCommand(value: unknown, maxFiles: number): AttachmentCommand {
  try {
    const fields = ownFields(value, ['requestId', 'session', 'consentEvidenceId', 'consentDocumentVersionId', 'fileIds']);
    return Object.freeze({
      requestId: canonicalUuid(fields['requestId']),
      session: Object.freeze(fileSessionProof(fields['session'])),
      consentEvidenceId: uuidValue(fields['consentEvidenceId']),
      consentDocumentVersionId: uuidValue(fields['consentDocumentVersionId']),
      fileIds: uuidList(fields['fileIds'], maxFiles),
    });
  } catch (error) {
    if (isLifecycleError(error)) {
      throw error;
    }
    return refuseLifecycle('INVALID_INPUT');
  }
}

async function legal<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    if (isLifecycleError(error)) {
      throw error;
    }
    try {
      mapLegalPortError(error);
    } catch (mapped) {
      refuseLifecycle(mapped instanceof FileReservationError ? mapped.code : 'CONFLICT');
    }
    return refuseLifecycle('CONFLICT');
  }
}

/** Step 1: runtime `FOR SHARE` before the F anchor. Must be called first. */
export async function lockAttachmentRuntime(client: PoolClient, input: unknown): Promise<ReadyAttachmentRuntime> {
  const ctx = attachmentContext(input);
  await legal(() => assertCallerTransaction(client));
  // The existing P03 ACTIVE/epoch return guard, taken before the F anchor.
  const runtime = await lockRuntime(client, ctx.epoch);
  const token = Object.freeze({ ready: true as const });
  lockedRuntimes.set(token, Object.freeze({ runtime, policy: ctx.policy, client }));
  return token;
}

async function verifyAnchor(client: PoolClient, session: FileOwnerSessionProof): Promise<AnchorFacts> {
  const { rows: [row] } = await client.query<AnchorFacts>(`SELECT id,secret_hash,intake_city_id,intake_city_version_id,
    revoked_at IS NOT NULL AS revoked, expires_at > clock_timestamp() AS live
    FROM ${SESSIONS} WHERE id=$1`, [session.sessionId]);
  // A wrong token and a missing anchor are the same refusal: no existence oracle.
  if (row === undefined || !sessionSecretMatches(session.token, row.secret_hash)) {
    refuseLifecycle('NOT_FOUND');
  }
  if (row.revoked) {
    refuseLifecycle('SESSION_REVOKED');
  }
  if (!row.live) {
    refuseLifecycle('SESSION_EXPIRED');
  }
  return row;
}

async function verifyConsent(client: PoolClient, anchor: AnchorFacts, command: AttachmentCommand): Promise<CurrentConsent> {
  const { rows: [row] } = await client.query<ConsentFacts>(`SELECT c.id AS evidence_id,c.document_id,
    c.document_version_id,c.occurred_at::text AS occurred_at,
    NOT EXISTS (SELECT 1 FROM ${CONSENTS} r WHERE r.supersedes_id=c.id) AS unrevoked,
    d.current_version_id IS NOT DISTINCT FROM c.document_version_id AS current,
    d.current_version_id IS NOT NULL AS published
    FROM ${CONSENTS} c JOIN foundation.legal_documents d ON d.id=c.document_id
    WHERE c.id=$1 AND c.session_id=$2 AND c.purpose=$3 AND c.action='GIVEN'`,
  [command.consentEvidenceId, anchor.id, PURPOSE]);
  if (row === undefined) {
    refuseLifecycle('NOT_FOUND');
  }
  if (row.document_version_id !== command.consentDocumentVersionId) {
    refuseLifecycle('CONSENT_NOT_CURRENT');
  }
  if (!row.unrevoked) {
    refuseLifecycle('CONSENT_REVOKED');
  }
  if (!row.published) {
    refuseLifecycle('CONSENT_NOT_PUBLISHED');
  }
  if (!row.current) {
    refuseLifecycle('CONSENT_NOT_CURRENT');
  }
  return Object.freeze({
    granted: true, reason: 'GRANTED', documentId: row.document_id, documentVersionId: row.document_version_id,
    evidenceId: row.evidence_id, occurredAt: row.occurred_at,
  });
}

/** The committed submit edge is the authoritative binding, not a body field. */
async function verifyRequest(client: PoolClient, anchor: AnchorFacts, command: AttachmentCommand): Promise<void> {
  const { rows: [row] } = await client.query<RequestFacts>(`SELECT r.id,r.type,r.city_id,r.intake_city_version_id,
    e.session_id AS edge_session_id,e.consent_id AS edge_consent_id,
    e.document_version_id AS edge_document_version_id,e.submit_command AS edge_command
    FROM ${REQUESTS} r LEFT JOIN ${SUBMITS} e ON e.request_id=r.id WHERE r.id=$1`, [command.requestId]);
  if (row === undefined) {
    refuseLifecycle('NOT_FOUND');
  }
  // Fresh attach is F repair only; a callback request or another city/version is
  // not this anchor's attachment target.
  if (row.type !== 'REPAIR' || row.city_id !== anchor.intake_city_id
    || row.intake_city_version_id !== anchor.intake_city_version_id) {
    refuseLifecycle('NOT_FOUND');
  }
  if (row.edge_session_id !== anchor.id || row.edge_command !== 'CreateRepair'
    || row.edge_consent_id !== command.consentEvidenceId
    || row.edge_document_version_id !== command.consentDocumentVersionId) {
    refuseLifecycle('CONFLICT');
  }
}

interface ResolvedAttachment {
  readonly fileId: string;
  readonly intentId: string;
  readonly mime: ImageMime;
  readonly bytes: number;
}

function imageMime(value: string): ImageMime {
  return (ATTACHMENT_MIMES as readonly string[]).includes(value)
    ? value as ImageMime
    : refuseLifecycle('NOT_READY');
}

function safeBytes(value: string): number {
  const bytes = Number(value);
  return Number.isSafeInteger(bytes) && bytes >= 1 ? bytes : refuseLifecycle('NOT_READY');
}

/**
 * Non-locking resolution of the requested publications. Only a `READY` publication
 * whose intent is owned by this anchor can become an attachment; the immutable
 * publication evidence is re-read again under the intent lock below.
 */
async function resolveAttachments(client: PoolClient, anchor: AnchorFacts, command: AttachmentCommand,
  policy: ReadyAttachmentPolicy,
): Promise<readonly ResolvedAttachment[]> {
  const { rows } = await client.query<PublicationFacts>(`SELECT p.id,p.intent_id,p.mime,p.served_bytes::text
    FROM ${PUBLICATIONS} p JOIN ${INTENTS} i ON i.id=p.intent_id
    WHERE p.id = ANY($1::uuid[]) AND i.owner_request_session_id=$2`, [command.fileIds, anchor.id]);
  const byFile = new Map<string, ResolvedAttachment>();
  for (const row of rows) {
    const mime = imageMime(row.mime);
    const bytes = safeBytes(row.served_bytes);
    byFile.set(row.id, Object.freeze({ fileId: row.id, intentId: row.intent_id, mime, bytes }));
  }
  if (byFile.size !== command.fileIds.length) {
    refuseLifecycle('NOT_FOUND');
  }
  const resolved = command.fileIds.map((fileId) => byFile.get(fileId) ?? refuseLifecycle('NOT_FOUND'));
  let total = 0;
  for (const attachment of resolved) {
    total += attachment.bytes;
    if (!Number.isSafeInteger(total)) {
      refuseLifecycle('QUOTA_EXCEEDED');
    }
  }
  if (resolved.length > policy.maxFiles || total > policy.maxBytes) {
    refuseLifecycle('QUOTA_EXCEEDED');
  }
  return Object.freeze(resolved);
}

function quoteIdentifier(name: string): string {
  return `"${name.replaceAll('"', '""')}"`;
}

/**
 * Force only the `request_files` deferred constraints before the final window
 * proof, so the S3 interlock is proven inside this transaction even if a future
 * migration makes one of its FKs deferrable. Discovered from the catalog, never a
 * hardcoded constraint name list.
 */
async function forceAttachmentConstraints(client: PoolClient): Promise<void> {
  const { rows } = await client.query<{ conname: string }>(`SELECT conname FROM pg_constraint
    WHERE conrelid='${REQUEST_FILES}'::regclass AND condeferrable AND contype IN ('c','f','p','u')`);
  const names = rows.map((row) => row.conname).filter((name) => name.startsWith('request_files_'));
  if (names.length === 0) {
    return;
  }
  await client.query(`SET CONSTRAINTS ${names.map(quoteIdentifier).join(',')} IMMEDIATE`);
}

/**
 * Step 2: attachment admission on the caller's already-open submit transaction.
 *
 * Preconditions (enforced, not assumed): `lockAttachmentRuntime` ran first on this
 * client; the caller holds the request row and has inserted the request aggregate,
 * submit edge and command event. The port inserts the `request_files` rows, forces
 * the interlock constraints and re-proves every file window on a fresh database
 * clock; the caller then performs its own final F/CSRF clock check and commits.
 */
export async function admitReadyAttachments(client: PoolClient, runtime: ReadyAttachmentRuntime,
  input: unknown,
): Promise<{ readonly attachments: readonly ReadyAttachment[]; readonly expiresAtMs: number }> {
  const locked = readLockedRuntime(runtime, client);
  // Single use: a second admission attempt in the same transaction must take a new
  // runtime lock instead of replaying a proof that already authorized one insert.
  consumeLockedRuntime(runtime);
  const command = attachmentCommand(input, locked.policy.maxFiles);
  try {
    await legal(() => assertCallerTransaction(client));
    // The runtime row was locked before the anchor; re-prove it with a plain read.
    const runtimeLock: AttachmentRuntimeLock = Object.freeze({ runtime: locked.runtime });
    await verifyAttachmentRuntime(client, runtimeLock);
    const mode = await probeAttachmentInterlock(client);
    if (mode !== 'S3') {
      // Pre-S3 and drifted profiles have no reviewed interlock; never fall back.
      refuseLifecycle('NOT_CONFIGURED');
    }
    const anchor = await verifyAnchor(client, command.session);
    const consent = await verifyConsent(client, anchor, command);
    await verifyRequest(client, anchor, command);
    const attachments = await resolveAttachments(client, anchor, command, locked.policy);
    const windowPolicy: ReadyWindowPolicy = Object.freeze({
      expiresAt: locked.policy.expiresAt.toISOString(), maxAccessAgeMs: locked.policy.maxAccessAgeMs,
    });
    // Fixed order: intents by UUID, and for each intent its control and only then
    // the publication evidence/attempts.
    const ordered = [...attachments].sort((left, right) => left.intentId < right.intentId ? -1 : left.intentId > right.intentId ? 1 : 0);
    const proofs: Awaited<ReturnType<typeof lockAttachmentFileAuthorization>>[] = [];
    for (const attachment of ordered) {
      const file: FFile = { session: command.session, intentId: attachment.intentId };
      const auth = await lockAttachmentFileAuthorization(client, file, locked.runtime, consent);
      const publication = await selectPublication(client, attachment.intentId);
      if (publication === undefined || publication.id !== attachment.fileId
        || publication.mime !== attachment.mime || publication.served_bytes !== String(attachment.bytes)) {
        refuseLifecycle('NOT_READY');
      }
      await checkFileAuthorization(client, auth, { allowedMimeTypes: ATTACHMENT_MIMES });
      await proveReadyWindow(client, auth, windowPolicy, publication);
      proofs.push(auth);
    }
    // No file/intent may belong to another request (or already to this one): a
    // repeated admission is not a silent replay.
    const intentIds = ordered.map((attachment) => attachment.intentId);
    const { rows: links } = await client.query(`SELECT rf.intent_id FROM ${REQUEST_FILES} rf
      WHERE rf.request_id=$1 OR rf.file_id = ANY($2::uuid[]) OR rf.intent_id = ANY($3::uuid[]) LIMIT 1`,
    [command.requestId, command.fileIds, intentIds]);
    if (links.length > 0) {
      refuseLifecycle('CONFLICT');
    }
    const { rowCount } = await client.query(`INSERT INTO ${REQUEST_FILES}
      (request_id,owner_session_id,intent_id,file_id)
      SELECT $1,$2,x.intent_id,x.file_id
      FROM jsonb_to_recordset($3::jsonb) AS x(intent_id uuid,file_id uuid)`,
    [command.requestId, anchor.id, JSON.stringify(ordered.map((attachment) => ({
      intent_id: attachment.intentId, file_id: attachment.fileId,
    })))]);
    if (rowCount !== ordered.length) {
      refuseLifecycle('CONFLICT');
    }
    await forceAttachmentConstraints(client);
    // Fresh database clock for every attached file after the last write/constraint
    // wait; the exact READY window and the current legal basis must still hold.
    let expiresAtMs = Infinity;
    for (const proof of proofs) {
      const publication = await selectPublication(client, proof.intent.id);
      if (publication === undefined) {
        refuseLifecycle('NOT_READY');
      }
      await checkFileAuthorization(client, proof, { allowedMimeTypes: ATTACHMENT_MIMES });
      expiresAtMs = Math.min(expiresAtMs, await proveReadyWindow(client, proof, windowPolicy, publication));
    }
    if (!Number.isSafeInteger(expiresAtMs)) { return refuseLifecycle('NOT_READY'); }
    const byFile = new Map(ordered.map((attachment) => [attachment.fileId, attachment]));
    const views = command.fileIds.map((fileId) => {
      const attachment = byFile.get(fileId) ?? refuseLifecycle('CONFLICT');
      return Object.freeze({ fileId: attachment.fileId, mime: attachment.mime, bytes: attachment.bytes });
    });
    // The submit transaction still has offer and F checks to make. Check the
    // earliest of ALL READY windows against its final DB clock, not timestamps
    // sampled one by one during this function's earlier awaits.
    return Object.freeze({ attachments: Object.freeze(views), expiresAtMs });
  } catch (error) {
    if (isLifecycleError(error)) {
      throw error;
    }
    return refuseLifecycle('CONFLICT');
  }
}
