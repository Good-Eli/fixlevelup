/**
 * Late no-file callback for the restore-refusal proof (task-20).
 *
 * The fixture commits a real P05 aggregate through the production intake store/effect
 * ports, not through the HTTP service. The exact S3 inventory counts the immutable
 * policy package that the requests FK requires; a committed callback cannot have
 * an empty policy table. Keep the non-P05 reference and the P05 policy separate so
 * clean, policy-only, and policy-plus-callback checkpoints cannot be confused:
 *
 *  - `seedLateCallbackReference` provisions the non-P05 reference before either dump;
 *  - `seedLateCallbackPolicy` provisions the pinned package before the application dump;
 *  - `commitNoFileCallback` writes one complete `CreateCallback` aggregate through
 *    the production `store`/`effects` helpers, on the caller's transaction, as
 *    whatever role that transaction runs under (the fixture's runtime role).
 *
 * It deliberately does NOT reimplement the aggregate with raw SQL: the row set is
 * produced by `createRequestRow`, `writeContact`, `writePreference`,
 * `insertStaffEvidence`, `writeEffect` and `writePhone`, so the deferred 024
 * completeness guards validate the same write path the service uses. No file or
 * attachment row is written, so the callback is a "no-file" intake.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import type { P05ManualCallbackRequest } from '@fixlevelup/p03-contracts/p05';
import type { KeyringConfig } from '../src/requests/crypto/keyring.js';
import type { PayloadKeySlots } from '../src/requests/crypto/payload-key-directory.js';
import { lockStaffCommandKey, writeEffect } from '../src/requests/intake/effects.js';
import {
  createRequestRow, insertStaffEvidence, writeContact, writePhone, writePreference,
} from '../src/requests/intake/store.js';
import {
  REQUEST_POLICY_METADATA_SHA256, REQUEST_POLICY_REVISION, REQUEST_WORKFLOW_VERSION, attestDisposableFixture,
} from './p05-request-fixtures.js';

/** Unified GEO/CFG writer fence (022 `geo_cfg_fence_guard`). */
const GEO_CFG_FENCE = 'SELECT pg_catalog.pg_advisory_xact_lock(734305,1)';
const HOUR_MS = 3_600_000;

interface LateCallbackReference {
  readonly sourceEntryId: string;
  readonly sourceVersionId: string;
}

export interface LateCallbackBasis extends LateCallbackReference {
  readonly policyId: string;
}

export interface LateCallbackAggregate {
  readonly requestId: string;
  readonly eventId: string;
  readonly contactRevisionId: string;
  readonly phonePermissionId: string;
  readonly manualEvidenceId: string;
  readonly phoneEvidenceId: string;
  /** The role that actually wrote the rows — must be the narrow runtime identity. */
  readonly writerRole: string;
}

/** Published non-P05 prerequisite, unchanged across both physical dumps. */
export async function seedLateCallbackReference(migrator: Pool,
  options: { readonly reviewerId: string }): Promise<LateCallbackReference> {
  const sourceEntryId = randomUUID();
  const sourceVersionId = randomUUID();
  const client = await migrator.connect();
  try {
    // Hard lab admission on this very connection: the reviewed cluster name, the
    // exact PostgreSQL 18.7, loopback 55432, the disposable database name and the
    // migration-owner identity are all re-checked before a single row is written.
    // A non-lab or non-disposable target is refused here, not by convention.
    await attestDisposableFixture(client, 'WRITE');
    await client.query('BEGIN');
    await client.query(GEO_CFG_FENCE);
    await client.query(`INSERT INTO foundation.reference_entries (id,type,scope,code)
      VALUES ($1,'REQUEST_SOURCE','COMPANY',$2)`,
    [sourceEntryId, `late-source-${randomBytes(4).toString('hex')}`]);
    await client.query(`INSERT INTO foundation.reference_entry_versions
      (id,entry_id,type,version,label,valid_from,valid_until,source_ref,reviewed_by)
      VALUES ($1,$2,'REQUEST_SOURCE',1,'Synthetic late restore source',clock_timestamp(),NULL,'synthetic:late',$3)`,
    [sourceVersionId, sourceEntryId, options.reviewerId]);
    await client.query('UPDATE foundation.reference_entries SET current_version_id=$2 WHERE id=$1',
      [sourceEntryId, sourceVersionId]);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
  return Object.freeze({ sourceEntryId, sourceVersionId });
}

/** Required by both the intake service and the physical requests FKs. */
export const lateRestorePolicyPin = Object.freeze({ workflowVersion: REQUEST_WORKFLOW_VERSION,
  policyRevision: REQUEST_POLICY_REVISION, metadataSha256: REQUEST_POLICY_METADATA_SHA256 });

/** Stable full policy tuple for the two independent sources, including 6-digit created_at. */
export async function seedLateCallbackPolicy(migrator: Pool, reference: LateCallbackReference): Promise<LateCallbackBasis> {
  const policyId = 'a0e37ed8-ca00-45e1-91ee-abb8eb146a69';
  const client = await migrator.connect();
  try {
    await attestDisposableFixture(client, 'WRITE');
    const { rows: [policy] } = await client.query<{ metadata_sha256: string }>(`INSERT INTO foundation.request_policy_packages
      (id,workflow_version,policy_revision,metadata_sha256,metadata,created_at)
      VALUES ($1,$2,$3,encode(sha256(convert_to($4::jsonb::text,'UTF8')),'hex'),$4::jsonb,$5::timestamptz)
      RETURNING metadata_sha256`, [policyId, lateRestorePolicyPin.workflowVersion, lateRestorePolicyPin.policyRevision,
      JSON.stringify({ purpose: 'REQUEST_CONFIRMATION', source: 'synthetic-fixture', revision: 1 }), '2026-01-01T00:00:00.123456Z']);
    if (policy?.metadata_sha256 !== lateRestorePolicyPin.metadataSha256) {
      throw new Error('Reviewed policy package digest does not match the pinned constant');
    }
    return Object.freeze({ policyId, ...reference });
  } finally { client.release(); }
}

/**
 * Commits one complete PHONE-mode `CreateCallback` aggregate with no file rows on
 * the caller's transaction. The caller owns BEGIN/COMMIT, so the aggregate lands in
 * exactly one durable transaction; the reviewed deferred guards are forced to run
 * here via `SET CONSTRAINTS ALL IMMEDIATE`.
 */
export async function commitNoFileCallback(client: PoolClient, options: {
  readonly ring: KeyringConfig;
  readonly keySlots: PayloadKeySlots;
  readonly environment: string;
  readonly basis: LateCallbackBasis;
  readonly staffId: string;
  readonly cityId: string;
  readonly cityVersionId: string;
  readonly timezone?: string;
  readonly key?: string;
}): Promise<LateCallbackAggregate> {
  const requestId = randomUUID();
  const customerId = randomUUID();
  const contactRevisionId = randomUUID();
  const preferenceRevisionId = randomUUID();
  const manualEvidenceId = randomUUID();
  const phoneEvidenceId = randomUUID();
  const phonePermissionId = randomUUID();
  const eventId = randomUUID();
  const key = options.key ?? randomUUID();
  const contact = { name: 'Synthetic late callback', phone: '+15550100003' };
  const body: P05ManualCallbackRequest = {
    type: 'CALLBACK',
    sourceEntryId: options.basis.sourceEntryId,
    evidenceId: manualEvidenceId,
    contact: { mode: 'PHONE', phonePermission: true, name: contact.name, phone: contact.phone, phoneEvidenceId },
  };
  const actor = { kind: 'STAFF' as const, id: options.staffId };
  const validUntil = new Date(Date.now() + HOUR_MS);

  // Hard lab admission for the RUNTIME write path as well: same reviewed cluster,
  // exact 18.7, loopback 55432, disposable database, and `current_user` must be the
  // narrow runtime role (the `'READ'` flag is what admits a non-migrator identity).
  await attestDisposableFixture(client, 'READ');
  const writerRole = (await client.query<{ role: string }>('SELECT current_user AS role')).rows[0]?.role;
  if (writerRole !== 'fixlevelup_runtime') { throw new Error('Late restore fixture requires the exact runtime role'); }
  await client.query('SET LOCAL synchronous_commit=on');
  await lockStaffCommandKey(client, actor, 'CreateManualRequest', key);
  const row = await createRequestRow(client, { id: requestId, customerId, cityId: options.cityId,
    cityVersionId: options.cityVersionId, policyId: options.basis.policyId, type: 'CALLBACK',
    status: 'CALLBACK_REQUIRED',
    revisions: { contact: contactRevisionId, address: null, appliance: null, preference: preferenceRevisionId,
      assessment: null } });
  await writeContact(client, { ring: options.ring, keySlots: options.keySlots, environment: options.environment }, row.id, contactRevisionId, 1,
    'PHONE', contact);
  await writePreference(client, row.id, preferenceRevisionId, 1, 'PHONE', options.timezone ?? 'Europe/Moscow');
  await client.query(`INSERT INTO foundation.request_intake_provenance
    (request_id,source_entry_id,source_version_id,callback_entry_id,callback_version_id)
    VALUES ($1,$2,$3,NULL,NULL)`, [row.id, options.basis.sourceEntryId, options.basis.sourceVersionId]);
  await insertStaffEvidence(client, row.id, options.staffId, 'MANUAL_INTAKE',
    { id: manualEvidenceId, procedureRevision: 'p05-manual-intake-v1', validUntil });
  await insertStaffEvidence(client, row.id, options.staffId, 'PHONE_GIVE',
    { id: phoneEvidenceId, procedureRevision: 'p05-phone-give-v1', validUntil });
  const receipt = await writeEffect(client, options.ring, row,
    { actor, command: 'CreateCallback', key, target: null, match: null, body }, eventId, randomUUID());
  await writePhone(client, row, eventId, 'GIVEN', phonePermissionId, phoneEvidenceId);
  // The reviewed deferred completeness triggers run before the caller's COMMIT.
  await client.query('SET CONSTRAINTS ALL IMMEDIATE');
  return Object.freeze({ requestId: receipt.requestId, eventId: receipt.eventId, contactRevisionId,
    phonePermissionId, manualEvidenceId, phoneEvidenceId, writerRole });
}
