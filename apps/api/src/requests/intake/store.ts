import { randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import type { P05Address, P05Appliance, P05Fault, P05FContact, P05PreferredVisit, P05Urgency } from '@fixlevelup/p03-contracts/p05';
import { canonicalJson } from '../../infrastructure/admission/proof.js';
import type { DispatchBranch, RequestStatus, RequestType } from '../workflow/registry.js';
import type { PayloadKind } from '../crypto/payload-cipher.js';
import { MANAGED_PAYLOAD_KEY_MARKER, sealManagedPayload } from '../crypto/payload-cipher.js';
import type { PayloadKeySlots } from '../crypto/payload-key-directory.js';
import type { KeyringConfig } from '../crypto/keyring.js';
import type { StaffEvidence, StaffEvidencePurpose } from './basis.js';
import { deny } from './errors.js';

export interface RequestRow {
  readonly id: string; readonly public_number: string; readonly type: RequestType; readonly status: RequestStatus;
  readonly row_version: number; readonly customer_id: string; readonly city_id: string;
  readonly intake_city_version_id: string; readonly intake_policy_revision_id: string; readonly workflow_package_id: string;
  readonly current_contact_revision_id: string | null; readonly current_address_revision_id: string | null;
  readonly current_appliance_revision_id: string | null; readonly current_preference_revision_id: string | null;
  readonly current_assessment_id: string | null;
}
const COLS = `id,public_number::text,type,status,row_version,customer_id,city_id,intake_city_version_id,
  intake_policy_revision_id,workflow_package_id,current_contact_revision_id,current_address_revision_id,
  current_appliance_revision_id,current_preference_revision_id,current_assessment_id`;
export async function requestRow(client: PoolClient, id: string, lock: boolean): Promise<RequestRow | undefined> {
  return (await client.query<RequestRow>(`SELECT ${COLS} FROM foundation.requests WHERE id=$1${lock ? ' FOR UPDATE' : ''}`, [id])).rows[0];
}
export interface Revisions {
  readonly contact: string | null; readonly address: string | null; readonly appliance: string | null; readonly preference: string | null;
  readonly assessment: string | null;
}
export interface Snapshots { readonly ring: KeyringConfig; readonly environment: string; readonly keySlots: PayloadKeySlots }

async function insertPayload(client: PoolClient, config: Snapshots, id: string, kind: PayloadKind, revision: number, value: unknown) {
  const ref = { environment: config.environment, requestId: id, cellId: randomUUID(), kind, revision };
  // The legacy columns carry only a format marker and zero bytes, never a copy
  // of the external wrap. Publish the durable slot before a row can commit.
  // A rolled back/unknown SQL outcome can leave an orphan: do not delete or
  // recycle it here; a committed row may own it. Offline inventory uses PG IDs.
  const plaintext = Buffer.from(canonicalJson(value).padEnd(16, ' '), 'utf8');
  const sealed = (() => {
    try { return sealManagedPayload(ref, config.ring, plaintext); }
    finally { plaintext.fill(0); }
  })();
  await config.keySlots.create(ref, { keyId: sealed.keyId, wrappedDek: sealed.wrappedDek });
  await client.query(`INSERT INTO foundation.request_payload_cells
    (id,request_id,kind,revision,key_id,wrapped_dek,nonce,ciphertext,auth_tag,aad_context)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, [ref.cellId, id, kind, revision, MANAGED_PAYLOAD_KEY_MARKER,
    Buffer.alloc(0), sealed.nonce, sealed.ciphertext, sealed.authTag, sealed.aadContext]);
  return ref.cellId;
}

export async function createRequestRow(client: PoolClient, input: { id: string; customerId: string; cityId: string; cityVersionId: string;
  policyId: string; type: RequestType; status: RequestStatus; revisions: Revisions }): Promise<RequestRow> {
  await client.query('INSERT INTO foundation.customers(id) VALUES ($1)', [input.customerId]);
  const { contact, address, appliance, preference } = input.revisions;
  const { rows: [row] } = await client.query<RequestRow>(`INSERT INTO foundation.requests
    (id,customer_id,city_id,intake_city_version_id,workflow_package_id,intake_policy_revision_id,type,status,
      current_contact_revision_id,current_address_revision_id,current_appliance_revision_id,current_preference_revision_id)
    VALUES ($1,$2,$3,$4,$5,$5,$6,$7,$8,$9,$10,$11) RETURNING ${COLS}`,
  [input.id,input.customerId,input.cityId,input.cityVersionId,input.policyId,input.type,input.status,contact,address,appliance,preference]);
  return row ?? deny('NOT_READY');
}

export async function updateRequestRow(client: PoolClient, prior: RequestRow, status: RequestStatus, type: RequestType, next: Revisions): Promise<RequestRow> {
  const { rows: [row] } = await client.query<RequestRow>(`UPDATE foundation.requests SET type=$3,status=$4,
    current_contact_revision_id=$5,current_address_revision_id=$6,current_appliance_revision_id=$7,
    current_preference_revision_id=$8,current_assessment_id=$9 WHERE id=$1 AND row_version=$2 RETURNING ${COLS}`,
  [prior.id,prior.row_version,type,status,next.contact,next.address,next.appliance,next.preference,next.assessment]);
  return row ?? deny('PRECONDITION_FAILED');
}

export async function writeContact(client: PoolClient, cfg: Snapshots, requestId: string, id: string, version: number,
  mode: DispatchBranch, contact: P05FContact, comment?: string): Promise<void> {
  const cell = await insertPayload(client,cfg,requestId,'CONTACT',version,{ name: contact.name, phone: contact.phone, ...(comment === undefined ? {} : { comment }) });
  await client.query(`INSERT INTO foundation.request_contact_revisions(id,request_id,revision,mode,payload_cell_id)
    VALUES ($1,$2,$3,$4,$5)`, [id,requestId,version,mode,cell]);
}

export async function readContactMode(client: PoolClient, row: RequestRow): Promise<DispatchBranch> {
  const { rows: [contact] } = await client.query<{ mode: DispatchBranch }>(`SELECT mode FROM foundation.request_contact_revisions
    WHERE request_id=$1 AND id=$2`, [row.id,row.current_contact_revision_id]);
  return contact?.mode ?? deny('NOT_READY');
}

export async function writeAddress(client: PoolClient, cfg: Snapshots, row: Pick<RequestRow,'id'|'city_id'>,
  id: string, version: number, address: P05Address): Promise<void> {
  let districtVersion: number | null = null;
  if (address.districtId !== undefined) {
    const { rows: [district] } = await client.query<{ row_version: number }>(`SELECT row_version
      FROM foundation.administrative_districts WHERE id=$1 AND city_id=$2 AND archived_at IS NULL`, [address.districtId,row.city_id]);
    if (!district) { return deny('NOT_FOUND'); }
    districtVersion = district.row_version;
  }
  const cell = await insertPayload(client,cfg,row.id,'ADDRESS',version,address);
  await client.query(`INSERT INTO foundation.request_address_revisions(id,request_id,revision,district_id,district_row_version,payload_cell_id)
    VALUES ($1,$2,$3,$4,$5,$6)`, [id,row.id,version,address.districtId ?? null,districtVersion,cell]);
}

interface CatalogFacts { id: string; kind: string; category_id: string | null; brand_id: string | null; version: string }
async function catalogSource(client: PoolClient, id: string, kind: string): Promise<CatalogFacts> {
  const { rows: [row] } = await client.query<CatalogFacts>(`SELECT e.id,e.kind,e.category_id,e.brand_id,v.id AS version
    FROM foundation.catalog_directory_entries e JOIN foundation.catalog_directory_versions v
      ON (v.entry_id,v.id)=(e.id,e.current_version_id) WHERE e.id=$1 AND e.kind=$2 AND e.archived_at IS NULL`, [id,kind]);
  return row ?? deny('CONFLICT');
}

export async function writeAppliance(client: PoolClient, cfg: Snapshots, requestId: string, id: string, version: number,
  appliance: P05Appliance, fault: P05Fault): Promise<void> {
  const category = await catalogSource(client,appliance.categoryId,'CATEGORY');
  const model = appliance.modelId === undefined ? undefined : await catalogSource(client,appliance.modelId,'MODEL');
  if (model && (model.category_id !== category.id || (appliance.brandId && appliance.brandId !== model.brand_id))) {
    return deny('UNPROCESSABLE');
  }
  const brandId = appliance.brandId ?? model?.brand_id ?? undefined;
  const brand = brandId === undefined ? undefined : await catalogSource(client,brandId,'BRAND');
  const versions: CatalogFacts[] = [];
  for (const faultId of fault.faultIds) {
    const source = await catalogSource(client,faultId,'FAULT');
    if (source.category_id !== category.id) { return deny('UNPROCESSABLE'); }
    versions.push(source);
  }
  const personal = { modelText: appliance.modelText, approximateAge: appliance.approximateAge,
    otherDescription: fault.otherDescription, description: fault.description, errorCode: fault.errorCode };
  const cell = await insertPayload(client,cfg,requestId,'DETAILS',version,personal);
  await client.query(`INSERT INTO foundation.request_appliance_revisions
    (id,request_id,revision,category_id,category_version_id,model_id,model_version_id,payload_cell_id)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, [id,requestId,version,category.id,category.version,model?.id ?? null,model?.version ?? null,cell]);
  // Brand when no model is selected is optional, but never arbitrary or unreviewed.
  if (brand) {
    await client.query(`INSERT INTO foundation.request_appliance_brands(appliance_revision_id,request_id,brand_id,brand_version_id)
      VALUES ($1,$2,$3,$4)`, [id,requestId,brand.id,brand.version]);
  }
  for (const option of versions) {
    await client.query(`INSERT INTO foundation.request_faults(id,request_id,appliance_revision_id,fault_id,fault_version_id,category_id)
      VALUES ($1,$2,$3,$4,$5,$6)`, [randomUUID(),requestId,id,option.id,option.version,category.id]);
  }
  if (fault.otherDescription !== undefined) {
    await client.query(`INSERT INTO foundation.request_faults(id,request_id,appliance_revision_id,is_other,category_id)
      VALUES ($1,$2,$3,true,$4)`, [randomUUID(),requestId,id,category.id]);
  }
}

export async function writePreference(client: PoolClient, requestId: string, id: string, version: number, mode: DispatchBranch,
  timezone: string, urgency?: P05Urgency, visit?: P05PreferredVisit): Promise<void> {
  const windows = visit === undefined ? [] : [{ from: visit.from, to: visit.to, timezone }];
  await client.query(`INSERT INTO foundation.request_preference_revisions(id,request_id,revision,urgency,preferred_windows,contact_mode)
    VALUES ($1,$2,$3,$4,$5::jsonb,$6)`, [id,requestId,version,urgency ?? null,JSON.stringify(windows),mode]);
}

export async function modeOf(client: PoolClient, row: RequestRow): Promise<DispatchBranch> {
  const { rows: [pref] } = await client.query<{ contact_mode: DispatchBranch }>(`SELECT contact_mode FROM foundation.request_preference_revisions
    WHERE request_id=$1 AND id=$2`, [row.id,row.current_preference_revision_id]);
  return pref?.contact_mode ?? deny('NOT_READY');
}

export async function clonePhonePreference(client: PoolClient, row: RequestRow, id: string): Promise<void> {
  const result = await client.query(`INSERT INTO foundation.request_preference_revisions
    (id,request_id,revision,urgency,preferred_windows,contact_mode)
    SELECT $3,request_id,$4,urgency,preferred_windows,'PHONE' FROM foundation.request_preference_revisions
    WHERE request_id=$1 AND id=$2`, [row.id,row.current_preference_revision_id,id,row.row_version+1]);
  if (result.rowCount !== 1) { deny('NOT_READY'); }
}

export async function insertStaffEvidence(client: PoolClient, requestId: string, actor: string, purpose: StaffEvidencePurpose,
  evidence: StaffEvidence): Promise<void> {
  const result = await client.query(`INSERT INTO foundation.request_staff_evidence (id,request_id,staff_id,purpose,procedure_revision,valid_until)
    VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (id) DO NOTHING`,
  [evidence.id,requestId,actor,purpose,evidence.procedureRevision,evidence.validUntil]);
  if (result.rowCount !== 1) { deny('FORBIDDEN'); }
}

export async function activePhone(client: PoolClient, row: RequestRow): Promise<string | undefined> {
  const { rows: [grant] } = await client.query<{ id: string }>(`SELECT x.id FROM foundation.phone_permission_events x
    WHERE x.request_id=$1 AND x.contact_revision_id=$2 AND x.action='GIVEN' AND x.purpose='REQUEST_SERVICE_CALL'
      AND NOT EXISTS (SELECT FROM foundation.phone_permission_events y WHERE y.supersedes_given_id=x.id)`,
  [row.id,row.current_contact_revision_id]);
  return grant?.id;
}

export async function writePhone(client: PoolClient, row: RequestRow, eventId: string,
  action: 'GIVEN' | 'REVOKED', id: string, staffEvidenceId?: string, supersedes?: string): Promise<void> {
  await client.query(`INSERT INTO foundation.phone_permission_events
    (id,request_id,contact_revision_id,action,supersedes_given_id,event_id,staff_evidence_id)
    VALUES ($1,$2,$3,$4,$5,$6,$7)`, [id,row.id,row.current_contact_revision_id,action,supersedes ?? null,eventId,staffEvidenceId ?? null]);
}
