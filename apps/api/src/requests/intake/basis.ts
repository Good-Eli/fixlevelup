import type { PoolClient } from 'pg';
import type { P05ChannelSelection } from '@fixlevelup/p03-contracts/p05';
import type { SingleCityContext } from '../../settings/geography/city-context.js';
import { readSingleCityContext } from '../../settings/geography/city-context.js';
import { resolveReferenceForUse } from '../../settings/configuration/references.js';
import { deny } from './errors.js';

export async function dbClock(client: PoolClient): Promise<Date> {
  const { rows: [row] } = await client.query<{ now: Date }>('SELECT clock_timestamp() AS now');
  if (!row || !Number.isFinite(row.now.getTime())) { return deny('NOT_READY'); }
  return row.now;
}

export async function geoFence(client: PoolClient): Promise<void> {
  await client.query('SELECT pg_catalog.pg_advisory_xact_lock_shared(734305,1)');
}

export async function currentCity(client: PoolClient): Promise<SingleCityContext> {
  try { return await readSingleCityContext(client); }
  catch { return deny('NOT_READY'); }
}

export interface ConsentBinding { readonly id: string; readonly document_id: string; readonly document_version_id: string }
export interface SessionSubmit extends ConsentBinding {
  readonly session_id: string;
  readonly request_id: string;
  readonly event_id: string;
  readonly submit_command: 'CreateCallback' | 'CreateRepair';
}

export async function submitEdge(client: PoolClient, id: { sessionId: string } | { requestId: string }): Promise<SessionSubmit | undefined> {
  const session = 'sessionId' in id;
  return (await client.query<SessionSubmit>(`SELECT session_id,request_id,event_id,submit_command,consent_id AS id,document_id,document_version_id
    FROM foundation.request_session_submits WHERE ${session ? 'session_id' : 'request_id'}=$1`,
  [session ? id.sessionId : id.requestId])).rows[0];
}

/** Request commands call after the F anchor lock and before locking the request.
 * The city registry takes a shared lock on the canonical document. */
export async function lockConsent(client: PoolClient, prior?: ConsentBinding, mode: 'shared' | 'exclusive' = 'exclusive'): Promise<string | undefined> {
  const { rows: [row] } = await client.query<{ id: string }>(`SELECT id FROM foundation.legal_documents
    WHERE purpose='REQUEST_PROCESSING' AND kind='CONSENT_FORM' AND ($1::uuid IS NULL OR id=$1) FOR ${mode === 'shared' ? 'SHARE' : 'UPDATE'}`,
  [prior?.document_id ?? null]);
  return row?.id;
}

export async function readConsent(client: PoolClient, target: { sessionId: string; documentId: string;
  evidenceId: string; documentVersionId: string }): Promise<(ConsentBinding & { current: boolean; granted: boolean }) | undefined> {
  return (await client.query<ConsentBinding & { current: boolean; granted: boolean }>(`SELECT c.id,c.document_id,c.document_version_id,
    coalesce(d.current_version_id=c.document_version_id,false) AS current,
    NOT EXISTS(SELECT FROM foundation.consent_records revoke WHERE revoke.supersedes_id=c.id) AS granted
    FROM foundation.consent_records c JOIN foundation.legal_documents d ON d.id=c.document_id
    WHERE c.session_id=$1 AND c.document_id=$2 AND c.id=$3 AND c.document_version_id=$4
      AND c.purpose='REQUEST_PROCESSING' AND c.action='GIVEN' AND c.source='FORM'
      AND d.purpose='REQUEST_PROCESSING' AND d.kind='CONSENT_FORM'`,
  [target.sessionId, target.documentId, target.evidenceId, target.documentVersionId])).rows[0];
}

export async function boundConsent(client: PoolClient, edge: SessionSubmit) {
  return await readConsent(client, { sessionId: edge.session_id, documentId: edge.document_id,
    evidenceId: edge.id, documentVersionId: edge.document_version_id });
}

export async function activeReference(client: PoolClient, type: 'REQUEST_SOURCE' | 'CALLBACK_INTERVAL' | 'CANCEL_REASON',
  id: string, city?: SingleCityContext) {
  try {
    const facts = await resolveReferenceForUse(client, { entryId: id, type, ...(city ? { intakeCityVersionId: city.cityVersionId } : {}) });
    if (city && (facts.scope !== 'CITY' || facts.cityId !== city.cityId || facts.timezoneCityVersionId !== city.cityVersionId)) {
      return deny('CONFLICT');
    }
    if (!city && facts.scope !== 'COMPANY') { return deny('CONFLICT'); }
    return facts;
  } catch { return deny('CONFLICT'); }
}

export interface OfferBasis {
  readonly provider: P05ChannelSelection['provider'];
  readonly catalogVersionId: string;
  readonly optionVersionId: string;
  readonly purpose: 'REQUEST_CONFIRMATION';
  readonly basisId: string;
  readonly validUntil: Date;
}
/** Only composition T supplies this port. Writers and this read share the
 * source's transaction fence, acquired separately from the authoritative read. */
export interface RequestOffers {
  lock(client: PoolClient): Promise<void>;
  validateNewOffer(client: PoolClient, choice: P05ChannelSelection): Promise<OfferBasis>;
}

export async function confirmOffer(client: PoolClient, port: RequestOffers | undefined, choice: P05ChannelSelection): Promise<OfferBasis> {
  if (!port) { return deny('CHANNEL_NOT_READY'); }
  const basis = await port.validateNewOffer(client, choice);
  if (basis.provider !== choice.provider || basis.catalogVersionId !== choice.catalogVersionId
    || basis.optionVersionId !== choice.optionVersionId || !Object.is(basis.purpose,choice.purpose)) { return deny('CHANNEL_OPTIONS_CHANGED'); }
  await checkOfferClock(client, basis);
  return Object.freeze({ ...basis, validUntil: new Date(basis.validUntil) });
}

export async function checkOfferClock(client: PoolClient, basis: OfferBasis): Promise<void> {
  if (!(basis.validUntil instanceof Date) || !Number.isFinite(basis.validUntil.getTime())
    || basis.validUntil.getTime() <= (await dbClock(client)).getTime()) { return deny('CHANNEL_NOT_READY'); }
}

export type StaffEvidencePurpose = 'MANUAL_INTAKE' | 'PHONE_GIVE' | 'CONTACT_CHANGE' | 'PHONE_WITHDRAW';
export interface StaffEvidence {
  readonly id: string;
  readonly procedureRevision: string;
  readonly validUntil: Date;
}
/** This is a trusted reviewed-procedure port; no setting or Web payload provides
 * a default implementation. The fixture issuer must bind every element of input. */
export interface StaffEvidencePort {
  verify(client: PoolClient, input: { readonly id: string; readonly purpose: StaffEvidencePurpose;
    readonly staffId: string; readonly target: string; readonly canonicalIntent: string }): Promise<StaffEvidence | undefined>;
  isCurrent(client: PoolClient, evidence: StaffEvidence): Promise<boolean>;
  /** Open a registry view once per transaction. The synchronous predicate must
   * agree with isCurrent through the final decision, either under the issuer's
   * transaction fence or by reading authoritative in-process synthetic state. */
  openRegistry?(client: PoolClient): Promise<(evidence: StaffEvidence) => boolean>;
}
export async function confirmEvidence(client: PoolClient, port: StaffEvidencePort | undefined,
  input: Parameters<StaffEvidencePort['verify']>[1]): Promise<StaffEvidence> {
  const evidence = await port?.verify(client, Object.freeze({ ...input }));
  if (!evidence || evidence.id !== input.id || !await staffEvidenceLive(client, port, evidence)) { return deny('FORBIDDEN'); }
  return Object.freeze({ ...evidence, validUntil: new Date(evidence.validUntil) });
}

export async function staffEvidenceLive(client: PoolClient, port: StaffEvidencePort | undefined, evidence: StaffEvidence): Promise<boolean> {
  return !!port && evidence.validUntil instanceof Date && Number.isFinite(evidence.validUntil.getTime())
    && await port.isCurrent(client, evidence) && evidence.validUntil.getTime() > (await dbClock(client)).getTime();
}
