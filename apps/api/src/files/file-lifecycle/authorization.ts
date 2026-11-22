import type { PoolClient } from 'pg';
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
