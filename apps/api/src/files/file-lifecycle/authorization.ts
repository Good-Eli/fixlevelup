import type { PoolClient } from 'pg';
import { preS3Absent, probeP05Layer } from '../../infrastructure/database/p05-profile-catalog.js';
import { currentPurposeConsent, requireLiveAnchor } from '../../settings/legal/index.js';
import type { CurrentConsent } from '../../settings/legal/index.js';
import { FileReservationError, isFileMimeType, mapLegalPortError } from '../reservations/index.js';
import type { FileMimeType } from '../reservations/index.js';
import type { FFile, RuntimeEpoch } from './contract.js';
import { refuseLifecycle } from './errors.js';

export const INTENTS = 'foundation.file_upload_intents';
export const CONTROLS = 'foundation.file_privacy_controls';
export const RUNTIMES = 'foundation.file_runtime_epochs';
export const BINDINGS = 'foundation.file_quarantine_objects';
const PURPOSE = 'REQUEST_PROCESSING';
export const DB_CLOCK_ISO = `to_char(t.now AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
export const CONTROL_COLUMNS = `intent_id,row_version::text,access_epoch::text,processing_generation,processing_lease_id,
  processing_expires_at::text,read_generation,read_lease_id,read_expires_at::text`;

export interface PrivacyControl {
  readonly intent_id: string;
  readonly row_version: string;
  readonly access_epoch: string;
  readonly processing_generation: number;
  readonly processing_lease_id: string | null;
  readonly processing_expires_at: string | null;
  readonly read_generation: number;
  readonly read_lease_id: string | null;
  readonly read_expires_at: string | null;
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
interface FileLocks<E> {
  readonly runtime: E;
  readonly owner: string;
  readonly control: PrivacyControl | undefined;
}
export interface FileAuthorization<E = RuntimeEpoch> extends FileLocks<E> {
  readonly intent: Intent;
  readonly consent: CurrentConsent;
}

async function readRuntime(client: PoolClient): Promise<(RuntimeEpoch & { readonly mode: string }) | undefined> {
  const { rows: [row] } = await client.query<{ namespace_id: string; epoch: string; mode: string }>(
    `SELECT namespace_id,epoch::text,mode FROM ${RUNTIMES} WHERE singleton FOR SHARE`,
  );
  return row === undefined ? undefined : { namespace: row.namespace_id, epoch: BigInt(row.epoch), mode: row.mode };
}

/** B has no runtime proof only on a never-restored, no-runtime fixture. Bind every active B continuation to its first row. */
export async function lockLegacyRuntime(client: PoolClient, prior?: RuntimeEpoch | null): Promise<RuntimeEpoch | undefined> {
  const runtime = await readRuntime(client);
  if (runtime === undefined) {
    if (prior !== undefined && prior !== null) {
      refuseLifecycle('NOT_CONFIGURED');
    }
    return undefined;
  }
  if (runtime.mode !== 'ACTIVE' || prior === null || (prior !== undefined &&
    (prior.namespace !== runtime.namespace || prior.epoch !== runtime.epoch))) {
    refuseLifecycle('NOT_CONFIGURED');
  }
  return { namespace: runtime.namespace, epoch: runtime.epoch };
}

export async function lockRuntime(client: PoolClient, epoch: RuntimeEpoch): Promise<RuntimeEpoch> {
  const runtime = await lockLegacyRuntime(client, epoch);
  if (runtime === undefined) {
    refuseLifecycle('NOT_CONFIGURED');
  }
  return runtime;
}

/** Epoch matching still mandatory for cleanup after local settlement; never opens the epoch or issues bytes. */
async function lockTechnicalRuntime(client: PoolClient, epoch: RuntimeEpoch): Promise<RuntimeEpoch> {
  const runtime = await readRuntime(client);
  if (runtime === undefined || runtime.namespace !== epoch.namespace || runtime.epoch !== epoch.epoch) {
    refuseLifecycle('NOT_CONFIGURED');
  }
  return { namespace: runtime.namespace, epoch: runtime.epoch };
}

async function lockControl(client: PoolClient, intentId: string): Promise<PrivacyControl | undefined> {
  const { rows: [row] } = await client.query<PrivacyControl>(
    `SELECT ${CONTROL_COLUMNS} FROM ${CONTROLS} WHERE intent_id=$1 FOR UPDATE`, [intentId],
  );
  return row;
}

export async function lockOrCreateControl(client: PoolClient, intentId: string, control: PrivacyControl | undefined): Promise<PrivacyControl> {
  if (control !== undefined) {
    return control;
  }
  const { rows: [row] } = await client.query<PrivacyControl>(
    `INSERT INTO ${CONTROLS} (intent_id) VALUES ($1) RETURNING ${CONTROL_COLUMNS}`, [intentId],
  );
  if (row === undefined) {
    refuseLifecycle('CONFLICT');
  }
  return row;
}

/** Stable 016/017 fence: only an irreversible delete decision raises access_epoch. */
export function requireOpenPrivacy(control: PrivacyControl | undefined): void {
  if (control !== undefined && control.access_epoch !== '1') {
    refuseLifecycle('NOT_FOUND');
  }
}

async function legal<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    try {
      mapLegalPortError(error);
    } catch (mapped) {
      if (mapped instanceof FileReservationError) {
        refuseLifecycle(mapped.code);
      }
      refuseLifecycle('CONFLICT');
    }
  }
}

async function lockAuthorized<E>(client: PoolClient, command: FFile, runtime: E): Promise<FileAuthorization<E>> {
  const anchor = await legal(() => requireLiveAnchor(client, command.session));
  const consent = await legal(() => currentPurposeConsent(client, { session: command.session, purpose: PURPOSE }));
  const { rows: [intent] } = await client.query<Intent>(`SELECT id,state,row_version,consent_record_id,
    consent_document_version_id,consent_purpose,declared_mime,declared_bytes::text,max_file_bytes::text,
    allowed_mime_types ? declared_mime::text AS allowed FROM ${INTENTS}
    WHERE id=$1 AND owner_request_session_id=$2 FOR UPDATE`, [command.intentId, anchor.id]);
  if (intent === undefined) {
    refuseLifecycle('NOT_FOUND');
  }
  const control = await lockControl(client, intent.id);
  requireOpenPrivacy(control);
  return { intent, owner: anchor.id, consent, runtime, control };
}

export async function lockFileAuthorization(client: PoolClient, command: FFile, epoch: RuntimeEpoch): Promise<FileAuthorization> {
  return await lockAuthorized(client, command, await lockRuntime(client, epoch));
}

export async function lockLegacyFileAuthorization(client: PoolClient, command: FFile,
  epoch?: RuntimeEpoch | null,
): Promise<FileAuthorization<RuntimeEpoch | undefined>> {
  return await lockAuthorized(client, command, await lockLegacyRuntime(client, epoch));
}

function needConsent(consent: CurrentConsent): void {
  if (consent.granted) {
    return;
  }
  switch (consent.reason) {
    case 'SESSION_EXPIRED': return refuseLifecycle('SESSION_EXPIRED');
    case 'SESSION_REVOKED': return refuseLifecycle('SESSION_REVOKED');
    case 'DOCUMENT_NOT_PUBLISHED': return refuseLifecycle('CONSENT_NOT_PUBLISHED');
    case 'DOCUMENT_NOT_CURRENT': return refuseLifecycle('CONSENT_NOT_CURRENT');
    case 'REVOKED': return refuseLifecycle('CONSENT_REVOKED');
    case 'NOT_GIVEN': return refuseLifecycle('CONSENT_NOT_GIVEN');
    case 'GRANTED': return refuseLifecycle('CONFLICT');
  }
}

/** No cached clock and no use of JS time for SQL expiry; call after the last lock/audit/binding wait. */
export async function checkFileAuthorization<E>(client: PoolClient, auth: FileAuthorization<E>,
  opts?: { readonly logicalQuota?: boolean; readonly allowedMimeTypes?: readonly FileMimeType[];
    readonly policyExpiresAt?: Date; readonly leaseExpiresAt?: string },
): Promise<{ readonly mime: FileMimeType; readonly dbNow: string }> {
  const { intent, owner, consent } = auth;
  const { rows: [proof] } = await client.query<{
    session_live: boolean; session_revoked: boolean; intent_live: boolean; policy_live: boolean; within_quota: boolean;
    extra_policy_live: boolean; lease_live: boolean; db_now: string;
  }>(`WITH t AS MATERIALIZED (SELECT clock_timestamp() AS now)
    SELECT s.expires_at > t.now AS session_live, s.revoked_at IS NOT NULL AS session_revoked,
      i.expires_at > t.now AS intent_live, i.policy_expires_at > t.now AS policy_live,${DB_CLOCK_ISO} AS db_now,
      coalesce($4::timestamptz > t.now,true) AS extra_policy_live,
      coalesce($5::timestamptz > t.now,true) AS lease_live,
      CASE WHEN $3::boolean THEN (SELECT count(*) <= i.max_owner_files AND coalesce(sum(q.declared_bytes),0) <= i.max_owner_bytes
        FROM ${INTENTS} q WHERE q.owner_request_session_id=s.id AND q.state='RESERVED' AND q.expires_at > t.now)
      ELSE true END AS within_quota
    FROM ${INTENTS} i JOIN foundation.request_sessions s ON s.id=i.owner_request_session_id CROSS JOIN t
    WHERE i.id=$1 AND s.id=$2`, [intent.id, owner, opts?.logicalQuota === true, opts?.policyExpiresAt ?? null, opts?.leaseExpiresAt ?? null]);
  if (proof === undefined) {
    refuseLifecycle('CONFLICT');
  }
  if (proof.session_revoked) {
    refuseLifecycle('SESSION_REVOKED');
  }
  if (!proof.session_live) {
    refuseLifecycle('SESSION_EXPIRED');
  }
  if (intent.state !== 'RESERVED') {
    refuseLifecycle('INTENT_CANCELLED');
  }
  if (!proof.policy_live || !proof.extra_policy_live) {
    refuseLifecycle('NOT_CONFIGURED');
  }
  if (!proof.intent_live) {
    refuseLifecycle('INTENT_EXPIRED');
  }
  needConsent(consent);
  // The legal document is locked. A later GIVEN never substitutes for the exact original one.
  if (intent.consent_purpose !== PURPOSE || consent.evidenceId !== intent.consent_record_id
    || consent.documentVersionId !== intent.consent_document_version_id) {
    refuseLifecycle('CONSENT_NOT_CURRENT');
  }
  if (!proof.within_quota) {
    refuseLifecycle('QUOTA_EXCEEDED');
  }
  if (!intent.allowed || !isFileMimeType(intent.declared_mime)
    || (opts?.allowedMimeTypes !== undefined && !opts.allowedMimeTypes.includes(intent.declared_mime))
    || BigInt(intent.declared_bytes) > BigInt(intent.max_file_bytes)) {
    refuseLifecycle('NOT_CONFIGURED');
  }
  if (!proof.lease_live) {
    refuseLifecycle('STALE_CLAIM');
  }
  return { mime: intent.declared_mime, dbNow: proof.db_now };
}

async function lockTechnical<E>(client: PoolClient, intentId: string, runtime: E): Promise<FileLocks<E> | undefined> {
  const { rows: [link] } = await client.query<{ owner: string; document_id: string }>(`SELECT
    i.owner_request_session_id AS owner,c.document_id FROM ${INTENTS} i JOIN foundation.consent_records c ON c.id=i.consent_record_id
    WHERE i.id=$1`, [intentId]);
  if (link === undefined) {
    return undefined;
  }
  await client.query('SELECT id FROM foundation.request_sessions WHERE id=$1 FOR UPDATE', [link.owner]);
  await client.query('SELECT id FROM foundation.legal_documents WHERE id=$1 FOR UPDATE', [link.document_id]);
  await client.query(`SELECT id FROM ${INTENTS} WHERE id=$1 AND owner_request_session_id=$2 FOR UPDATE`, [intentId, link.owner]);
  const control = await lockControl(client, intentId);
  return { owner: link.owner, runtime, control };
}

export async function lockTechnicalFile(client: PoolClient, intentId: string, epoch: RuntimeEpoch): Promise<FileLocks<RuntimeEpoch> | undefined> {
  return await lockTechnical(client, intentId, await lockTechnicalRuntime(client, epoch));
}

export async function lockLegacyTechnicalFile(client: PoolClient, intentId: string,
  epoch?: RuntimeEpoch | null,
): Promise<FileLocks<RuntimeEpoch | undefined> | undefined> {
  return await lockTechnical(client, intentId, await lockLegacyRuntime(client, epoch));
}

/* ------------------------------------------------------------------------- */
/* P05 §5.2: in-transaction READY attachment prefix and S3 retention interlock */
/* ------------------------------------------------------------------------- */

/** Exact runtime proof taken once, before the F anchor, for a P05 attach path. */
export interface AttachmentRuntimeLock {
  readonly runtime: RuntimeEpoch;
}

/**
 * Post-wait re-proof of the attachment runtime: a plain read, never a second lock.
 *
 * The caller still holds the `FOR SHARE` row lock taken by the first call
 * (`lockAttachmentRuntime` in `file-access/ready-attachment.ts`, which reuses the
 * existing P03 `lockRuntime` return guard), so a plain read cannot wait behind a
 * queued epoch flip; it only proves that this transaction is still looking at the
 * exact runtime it locked before the anchor.
 */
export async function verifyAttachmentRuntime(client: PoolClient, locked: AttachmentRuntimeLock): Promise<void> {
  const { rows: [row] } = await client.query<{ namespace_id: string; epoch: string; mode: string }>(
    `SELECT namespace_id,epoch::text,mode FROM ${RUNTIMES} WHERE singleton`,
  );
  if (row === undefined || row.mode !== 'ACTIVE' || row.namespace_id !== locked.runtime.namespace
    || row.epoch !== locked.runtime.epoch.toString()) {
    refuseLifecycle('NOT_CONFIGURED');
  }
}

/** Control row with the deletion state needed by the S3 attach interlock. */
export interface AttachmentControl extends PrivacyControl {
  readonly delete_state: string;
}

async function lockAttachmentControlRow(client: PoolClient, intentId: string): Promise<AttachmentControl | undefined> {
  const { rows: [row] } = await client.query<AttachmentControl>(
    `SELECT ${CONTROL_COLUMNS},delete_state FROM ${CONTROLS} WHERE intent_id=$1 FOR UPDATE`, [intentId],
  );
  return row;
}

/**
 * The attach path requires the control to exist and to be `OPEN` with the original
 * access epoch 1. A missing control is *not* frozen and the existing lazy port
 * creates it (the S3 FK then binds every attachment to that exact OPEN row).
 */
function requireOpenAttachmentControl(control: AttachmentControl): AttachmentControl {
  if (control.delete_state !== 'OPEN' || control.access_epoch !== '1') {
    refuseLifecycle('NOT_FOUND');
  }
  return control;
}

/**
 * Intent → control locks for one attached file, taken after the caller's request
 * row lock and in the fixed `intent → control` order. Deliberately no runtime lock
 * and no legal-parent lock: the caller already holds that prefix, and the supplied
 * consent is the post-wait-verified exact current GIVEN of this anchor.
 *
 * The lazy control insert reuses the existing P03 port shape (`INSERT (intent_id)`),
 * but returns `delete_state` as well so the attachment can require `OPEN` instead of
 * inferring it from the access epoch alone.
 */
export async function lockAttachmentFileAuthorization(client: PoolClient, command: FFile,
  runtime: RuntimeEpoch, consent: CurrentConsent,
): Promise<FileAuthorization> {
  const { rows: [intent] } = await client.query<Intent>(`SELECT id,state,row_version,consent_record_id,
    consent_document_version_id,consent_purpose,declared_mime,declared_bytes::text,max_file_bytes::text,
    allowed_mime_types ? declared_mime::text AS allowed FROM ${INTENTS}
    WHERE id=$1 AND owner_request_session_id=$2 FOR UPDATE`, [command.intentId, command.session.sessionId]);
  if (intent === undefined) {
    refuseLifecycle('NOT_FOUND');
  }
  const existing = await lockAttachmentControlRow(client, intent.id);
  let control: AttachmentControl;
  if (existing === undefined) {
    const { rows: [created] } = await client.query<AttachmentControl>(
      `INSERT INTO ${CONTROLS} (intent_id) VALUES ($1) RETURNING ${CONTROL_COLUMNS},delete_state`, [intent.id],
    );
    if (created === undefined) {
      refuseLifecycle('CONFLICT');
    }
    control = created;
  } else {
    control = existing;
  }
  requireOpenAttachmentControl(control);
  return { intent, owner: command.session.sessionId, consent, runtime, control };
}

/** Catalog facts of the `foundation.request_files` relation and its S3 siblings. */
export interface AttachmentInterlockFacts {
  readonly present: unknown;
  readonly columns: unknown;
  readonly constraints: unknown;
  readonly s3_relations: unknown;
  readonly s3_indexes: unknown;
}

/**
 * `S3` — the reviewed attach/retention interlock relation exists exactly as the
 * migration provisions it; `PRE_S3` — the relation and every S3-only artifact are
 * absent, so the legacy P03 retention path is the honest one; `DRIFTED` — anything
 * else (an intermediate schema, a missing FK/CHECK/UNIQUE, a deferrable interlock or
 * a same-prefixed artifact). `DRIFTED` is never a fallback: callers fail closed.
 */
export type AttachmentInterlock = 'S3' | 'PRE_S3' | 'DRIFTED';

const ATTACHMENT_COLUMNS = [
  'file_id:uuid:NN:NODEFAULT',
  'intent_id:uuid:NN:NODEFAULT',
  'open_state:character varying(24):NN:DEFAULT',
  'owner_session_id:uuid:NN:NODEFAULT',
  'request_id:uuid:NN:NODEFAULT',
] as const;

const ATTACHMENT_CONSTRAINTS = [
  'c:open_state=OPEN',
  'f:intent_id,file_id->file_publications:intent_id,id:BLOCK',
  'f:intent_id,open_state->file_privacy_controls:intent_id,delete_state:BLOCK',
  'f:intent_id,owner_session_id->file_upload_intents:id,owner_request_session_id:BLOCK',
  'f:request_id,owner_session_id->request_session_submits:request_id,session_id:BLOCK',
  'p:request_id,file_id',
  'u:file_id',
  'u:intent_id',
] as const;

/**
 * Only the interlock-relevant S3 artifacts: the link relation, its submit-edge FK
 * target, and the two exact unique targets the interlock FKs need. Names come from
 * the reviewed S3 migration; anything else in the S3 layer is not this probe's
 * business, so a later S3 addition cannot silently flip the classification.
 */
const S3_RELATIONS = ['request_session_submits', 'request_files'] as const;

const S3_INDEXES = ['file_privacy_controls_intent_open_key', 'file_publications_intent_file_key'] as const;

const ATTACHMENT_INTERLOCK_SQL = `WITH target AS (SELECT to_regclass('foundation.request_files') AS oid),
  relations(name) AS (VALUES ${S3_RELATIONS.map((name) => `('${name}')`).join(',')}),
  indexes(name) AS (VALUES ${S3_INDEXES.map((name) => `('${name}')`).join(',')})
  SELECT t.oid IS NOT NULL AS present,
    coalesce((SELECT jsonb_agg(jsonb_build_array(a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,
        CASE WHEN a.atthasdef THEN pg_get_expr(d.adbin,d.adrelid) END) ORDER BY a.attname)
      FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
      WHERE a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped),'[]'::jsonb) AS columns,
    coalesce((SELECT jsonb_agg(jsonb_build_object('type',k.contype,'deferrable',k.condeferrable,
        'validated',k.convalidated,
        'cols',(SELECT jsonb_agg(x.attname ORDER BY u.ord) FROM unnest(k.conkey) WITH ORDINALITY AS u(attnum,ord)
          JOIN pg_attribute x ON x.attrelid=k.conrelid AND x.attnum=u.attnum),
        'ref',CASE WHEN k.confrelid<>0 THEN k.confrelid::regclass::text END,
        'ref_cols',(SELECT jsonb_agg(x.attname ORDER BY u.ord) FROM unnest(k.confkey) WITH ORDINALITY AS u(attnum,ord)
          JOIN pg_attribute x ON x.attrelid=k.confrelid AND x.attnum=u.attnum),
        'upd',k.confupdtype,'del',k.confdeltype,'def',pg_get_constraintdef(k.oid)) ORDER BY k.contype,k.conname)
      FROM pg_constraint k WHERE k.conrelid=t.oid),'[]'::jsonb) AS constraints,
    coalesce((SELECT jsonb_agg(r.name ORDER BY r.name) FROM relations r
      WHERE to_regclass('foundation.'||r.name) IS NOT NULL),'[]'::jsonb) AS s3_relations,
    coalesce((SELECT jsonb_agg(i.name ORDER BY i.name) FROM indexes i
      WHERE to_regclass('foundation.'||i.name) IS NOT NULL),'[]'::jsonb) AS s3_indexes
  FROM target t`;

function asArray(value: unknown): readonly unknown[] | undefined {
  return Array.isArray(value) ? value : undefined;
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function asStringList(value: unknown): string[] | undefined {
  const list = asArray(value);
  if (list === undefined || list.some((item) => typeof item !== 'string')) {
    return undefined;
  }
  return list as string[];
}

/**
 * A CHECK that constrains exactly `open_state` to the literal `OPEN`.
 *
 * The accepted normal form is the one PostgreSQL 18 produces for the reviewed
 * `CHECK (open_state='OPEN')` column constraint:
 * `CHECK (((open_state)::text = 'OPEN'::text))`. Everything else — in particular a
 * weakened `CHECK (open_state='OPEN' OR TRUE)` or any additional conjunction /
 * disjunction / negation — is `DRIFTED`, never "close enough".
 */
function canonicalCheck(def: string): string | undefined {
  let flat = def.toLowerCase().replace(/\s+/gu, '');
  if (!flat.startsWith('check')) {
    return undefined;
  }
  flat = flat.slice('check'.length)
    // Reviewed casts of the varchar column to text (the comparison coercion).
    .replaceAll('::text', '')
    .replaceAll('::character varying', '')
    .replaceAll('::character(24)', '')
    .replaceAll('"', '')
    .replaceAll('(', '')
    .replaceAll(')', '');
  // The exact reviewed predicate, with nothing added: no OR/AND/NOT/TRUE tokens,
  // no other column, no second literal.
  if (flat !== "open_state='open'") {
    return undefined;
  }
  return 'c:open_state=OPEN';
}

/** NO ACTION and RESTRICT both block a control-state change; cascades never do. */
function blockingAction(code: string): boolean {
  return code === 'a' || code === 'r';
}

function canonicalColumn(value: unknown): string | undefined {
  const row = asArray(value);
  if (row === undefined || row.length !== 4) {
    return undefined;
  }
  const name = asString(row[0]);
  const type = asString(row[1]);
  const notNull = row[2];
  const definition = row[3];
  if (name === undefined || type === undefined || typeof notNull !== 'boolean'
    || (definition !== null && definition !== undefined && typeof definition !== 'string')) {
    return undefined;
  }
  if (name === 'open_state' && (typeof definition !== 'string' || !definition.toLowerCase().includes("'open'"))) {
    return undefined;
  }
  return `${name}:${type}:${notNull ? 'NN' : 'NULL'}:${typeof definition === 'string' ? 'DEFAULT' : 'NODEFAULT'}`;
}

/** `regclass::text` may drop the schema prefix when the caller's search_path has it. */
function normalizeRelation(value: string | undefined): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  return value.startsWith('foundation.') ? value.slice('foundation.'.length) : value;
}

function canonicalConstraint(value: unknown): string | undefined {
  if (typeof value !== 'object' || value === null) {
    return undefined;
  }
  const row = value as Record<string, unknown>;
  const type = asString(row['type']);
  const cols = asStringList(row['cols']);
  if (type === undefined || cols === undefined || row['deferrable'] !== false || row['validated'] !== true) {
    return undefined;
  }
  if (type === 'p' || type === 'u') {
    return `${type}:${cols.join(',')}`;
  }
  if (type === 'c') {
    const def = asString(row['def']);
    return def === undefined ? undefined : canonicalCheck(def);
  }
  if (type === 'f') {
    const ref = normalizeRelation(asString(row['ref']));
    const refCols = asStringList(row['ref_cols']);
    const upd = asString(row['upd']);
    const del = asString(row['del']);
    if (ref === undefined || refCols === undefined || upd === undefined || del === undefined
      || !blockingAction(upd) || !blockingAction(del)) {
      return undefined;
    }
    return `f:${cols.join(',')}->${ref}:${refCols.join(',')}:BLOCK`;
  }
  return undefined;
}

function sameSet(left: readonly string[], right: readonly string[]): boolean {
  const sortedLeft = [...left].sort();
  const sortedRight = [...right].sort();
  return sortedLeft.length === sortedRight.length
    && sortedLeft.every((value, index) => value === sortedRight[index]);
}

/**
 * Pure classification of the catalog facts. Exported so the exact S3/PRE_S3/DRIFTED
 * boundary can be tested without a database: every unknown, extra or missing fact
 * is `DRIFTED`, never a permissive default.
 */
export function classifyAttachmentInterlock(facts: AttachmentInterlockFacts | undefined): AttachmentInterlock {
  if (facts === undefined) {
    return 'DRIFTED';
  }
  const present = facts.present;
  const relations = asStringList(facts.s3_relations);
  const indexes = asStringList(facts.s3_indexes);
  if (typeof present !== 'boolean' || relations === undefined || indexes === undefined) {
    return 'DRIFTED';
  }
  if (!present) {
    return relations.length === 0 && indexes.length === 0 ? 'PRE_S3' : 'DRIFTED';
  }
  const rawColumns = asArray(facts.columns);
  const rawConstraints = asArray(facts.constraints);
  if (rawColumns === undefined || rawConstraints === undefined) {
    return 'DRIFTED';
  }
  // PostgreSQL 18 records NOT NULL as `pg_constraint` rows of type 'n' in addition
  // to the column flag. NOT NULL is already pinned by the column facts above (and by
  // the reviewed S3 fingerprint for the whole layer), so those rows are not part of
  // the interlock set: counting them as "8 constraints" would wrongly refuse a
  // correct 024 schema. Every other constraint type stays exact.
  const reviewed = rawConstraints.filter((constraint) => {
    const row = constraint as Record<string, unknown> | null;
    return row?.['type'] !== 'n';
  });
  const columns = rawColumns.map(canonicalColumn);
  const constraints = reviewed.map(canonicalConstraint);
  if (columns.some((column) => column === undefined) || constraints.some((constraint) => constraint === undefined)) {
    return 'DRIFTED';
  }
  if (!sameSet(columns as string[], ATTACHMENT_COLUMNS)
    || !sameSet(constraints as string[], ATTACHMENT_CONSTRAINTS)) {
    return 'DRIFTED';
  }
  return 'S3';
}

/**
 * Explicit existence/interlock test for the retention decision and the attach path.
 *
 * Order matters:
 * 1. a cheap `to_regclass` presence read decides the branch without ever catching a
 *    "relation does not exist" error;
 * 2. when the relation is present, one `AccessShare` read freezes its definition for
 *    the rest of the transaction (a concurrent `ALTER`/`DROP TABLE request_files`
 *    needs `AccessExclusive` and now waits), so the verdict cannot be invalidated
 *    between the check and the `INSERT`;
 * 3. `PRE_S3` requires the *whole* reviewed pre-S3 absence predicate (shared
 *    `preS3Absent`: no S3 table, index, function or permission code anywhere), not
 *    just a missing `request_files`;
 * 4. `S3` additionally requires the exact reviewed S3 fingerprint
 *    (`probeP05Layer('S3')`), the same instrument launch admission uses, so a
 *    hand-written "looks close" schema is refused.
 *
 * `DRIFTED` is never a fallback: callers fail closed.
 */
export async function probeAttachmentInterlock(client: Pick<PoolClient, 'query'>): Promise<AttachmentInterlock> {
  const { rows: [presence] } = await client.query<{ present: boolean }>(
    `SELECT to_regclass('foundation.request_files') IS NOT NULL AS present`,
  );
  if (presence?.present !== true) {
    return await preS3Absent(client) ? 'PRE_S3' : 'DRIFTED';
  }
  // Freeze the reviewed relation for the rest of this transaction (parse-time lock,
  // no rows read): a later DDL on request_files must wait for this transaction.
  await client.query('SELECT 1 FROM foundation.request_files WHERE false');
  const { rows: [row] } = await client.query<AttachmentInterlockFacts>(ATTACHMENT_INTERLOCK_SQL);
  if (classifyAttachmentInterlock(row) !== 'S3') {
    return 'DRIFTED';
  }
  return await probeP05Layer(client, 'S3') ? 'S3' : 'DRIFTED';
}
