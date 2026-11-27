import { randomBytes, randomUUID } from 'node:crypto';
import type { PoolClient } from 'pg';
import {
  decodeP05Body, p05DecodeStatus, P05DecodeError, P05_IF_MATCH_OPERATIONS, parseP05Etag,
} from '@fixlevelup/p03-contracts/p05';
import type { P05BodyOperation, P05Bodies, P05CallbackRequest, P05ManualRequest, P05RepairRequest, P05ChannelSelection, P05FContact } from '@fixlevelup/p03-contracts/p05';
import type { P05AuthorizationApi, P05Context, SessionProof } from '../../authz/authorization.service.js';
import { AuthorizationError, P05CommitUnknown } from '../../authz/authorization.service.js';
import type { P05Capability } from '../../authz/capability.js';
import { requireRequestEffectsPool } from '../../infrastructure/admission/pool-guard.js';
import { WebAuthError, WebAuthService } from '../../auth/web-auth.service.js';
import type { GuardedPool } from '../../infrastructure/admission/pool-guard.js';
import { canonicalJson } from '../../infrastructure/admission/proof.js';
import type { FormSessionSelectorInput, FormSessionService } from '../../form-session/service.js';
import { FormSessionError } from '../../form-session/contract.js';
import { beginLegalTransaction, lockRequestSession } from '../../settings/legal/index.js';
import type { SingleCityContext } from '../../settings/geography/city-context.js';
import { fenceRead } from '../../catalog/transaction.js';
import { admitReadyAttachments, lockAttachmentRuntime } from '../../files/file-access/ready-attachment.js';
import type { ReadyAttachmentContext, ReadyAttachmentRuntime } from '../../files/file-access/ready-attachment.js';
import { isLifecycleError } from '../../files/file-lifecycle/errors.js';
import { decide, policyPairKey, SUPPORTED_WORKFLOW_VERSIONS } from '../workflow/registry.js';
import type { CommandName, DispatchBranch, RequestStatus } from '../workflow/registry.js';
import { deny, RequestFailure } from './errors.js';
import type { RequestFailureCode } from './errors.js';
import { activeReference, boundConsent, confirmEvidence, confirmOffer, currentCity, geoFence,
  lockConsent, staffEvidenceLive, submitEdge } from './basis.js';
import { readRegistrySearch, readVisibleRegistry } from '../registry/store.js';
import { readRegistryOptions } from '../registry/options.js';
import type { RegistryQuery } from '../registry/filters.js';
import { readCard, readTimeline } from '../card/store.js';
import { authorizeComments, commentGrant, COMMENT_KEY_ENVIRONMENT, readInternalComments, writeInternalComment } from '../card/comments.js';
import type { CommentConfig } from '../card/comments.js';
import { hasContactGrant, readContactDetails, readStoredContact } from '../card/contacts.js';
import type { ContactAudit } from '../card/contacts.js';
import { parseSearch } from '../search/contract.js';
import type { ContactSearchIndex } from '../search/index.js';
import { captureDashboard, dashboardRowsCurrent } from '../dashboard/store.js';
import { dashboardDto, dashboardPage } from '../dashboard/snapshots.js';
import type { DashboardSnapshot, DashboardSnapshots, DashboardSubject } from '../dashboard/snapshots.js';
import type { DashboardLink } from '../dashboard/contract.js';
import type { ConsentBinding, OfferBasis, RequestOffers, SessionSubmit, StaffEvidence, StaffEvidencePort } from './basis.js';
import { activePhone, clonePhonePreference, createRequestRow, insertStaffEvidence, modeOf, readContactMode,
  requestRow, updateRequestRow, writeAddress, writeAppliance, writeContact, writePhone, writePreference } from './store.js';
import type { RequestRow, Revisions, Snapshots } from './store.js';
import { checkedReceipt, findEvent, findManualEvent, lockStaffCommandKey, replayReceipt, requestRepresentation, writeEffect } from './effects.js';
import type { Actor, CommandIdentity, EffectReceipt } from './effects.js';

export type FProof = Omit<FormSessionSelectorInput, 'body'>;
export type FSubmit = 'createCallback' | 'createRepair';
export type FCommand = 'chooseCallback' | 'withdrawPhonePermission' | 'cancelRequestF';
export type StaffCommand = 'startReview' | 'convertCallback' | 'changeDetails' | 'recordCoverage' | 'changeContact'
  | 'readyForDispatch' | 'withdrawPhoneStaff' | 'cancelRequestStaff';
export interface WriteInput { readonly key: string; readonly ifMatch?: string; readonly bytes: Uint8Array }
export interface WriteResult { readonly receipt: EffectReceipt; readonly replayed: boolean }
export interface CoverageEffect {
  assess(context: { client: PoolClient; actor: P05Context; request: RequestRow; body: P05Bodies['recordCoverage'];
    eventId: string; recheck: () => Promise<Date> }): Promise<{ id: string; expiresAt: Date }>;
  eligible(client: PoolClient, request: RequestRow): Promise<boolean>;
}
export interface RequestIntakeConfig extends Snapshots {
  readonly currentPolicyId: string;
  /** Independently provisioned expected metadata digest per exact workflow/policy pair. */
  readonly supportedPolicies: ReadonlyMap<string,string>;
  readonly formSourceEntryId: string;
  readonly staffEvidence?: StaffEvidencePort;
  readonly offers?: RequestOffers;
  readonly attachments?: ReadyAttachmentContext;
  readonly coverage?: CoverageEffect;
  readonly comments?: CommentConfig;
  readonly contactAudit?: ContactAudit;
  readonly search?: ContactSearchIndex;
  readonly dashboard?: DashboardSnapshots;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const CLOSING = new Set<CommandName>(['WithdrawPhonePermission','CancelRequest']);
const F_COMMANDS: Readonly<Record<FCommand,CommandName>> = Object.freeze({ chooseCallback: 'ChooseCallback',
  withdrawPhonePermission: 'WithdrawPhonePermission', cancelRequestF: 'CancelRequest' });
const STAFF_COMMANDS: Readonly<Record<StaffCommand, readonly [CommandName,P05Capability]>> = Object.freeze({
  startReview: ['StartReview','requests.review'], convertCallback: ['ConvertCallback','requests.review'],
  changeDetails: ['ChangeDetails','requests.review'], recordCoverage: ['RecordCoverageAssessment','requests.coverage.assess'],
  changeContact: ['ChangeContact','requests.contact.manage'], readyForDispatch: ['ReadyForDispatch','requests.ready'],
  withdrawPhoneStaff: ['WithdrawPhonePermission','requests.contact.manage'], cancelRequestStaff: ['CancelRequest','requests.cancel'],
});

function readBody<O extends P05BodyOperation>(operation: O, bytes: Uint8Array): P05Bodies[O] {
  try { return decodeP05Body(operation,bytes); }
  catch (error) {
    if (error instanceof P05DecodeError) {
      const { status } = p05DecodeStatus(error);
      return deny(status === 413 ? 'BODY_TOO_LARGE' : status === 422 ? 'UNPROCESSABLE' : 'INVALID_REQUEST');
    }
    throw error;
  }
}
function requireHeaders(op: P05BodyOperation, input: WriteInput) {
  if (!UUID.test(input.key)) { deny('INVALID_REQUEST'); }
  const needV = (P05_IF_MATCH_OPERATIONS as readonly P05BodyOperation[]).includes(op);
  if (input.ifMatch === undefined) {
    if (needV) { deny('PRECONDITION_REQUIRED'); }
  } else if (!needV || parseP05Etag(input.ifMatch) === null) { deny('INVALID_REQUEST'); }
}

async function activeGiven(client: PoolClient, selector: string, doc: string | undefined): Promise<ConsentBinding> {
  if (!doc) { return deny('CONSENT_REQUIRED'); }
  const { rows } = await client.query<ConsentBinding>(`SELECT c.id,c.document_id,c.document_version_id
    FROM foundation.consent_records c JOIN foundation.legal_documents d ON d.id=c.document_id
    WHERE c.session_id=$1 AND c.document_id=$2 AND c.document_version_id=d.current_version_id
      AND c.action='GIVEN' AND c.purpose='REQUEST_PROCESSING' AND c.source='FORM'
      AND NOT EXISTS(SELECT FROM foundation.consent_records r WHERE r.supersedes_id=c.id) LIMIT 2`, [selector,doc]);
  return rows.length === 1 && rows[0] ? rows[0] : deny('CONSENT_REQUIRED');
}

interface Basis {
  readonly historical: boolean; readonly current: boolean;
  readonly recheck: () => Promise<boolean>;
  readonly historicalLive: () => Promise<boolean>;
  /** Null denotes a legal basis without a time limit, not absent manual evidence. */
  readonly expiresAtMs: number | null;
  readonly manualEvidence?: StaffEvidence;
}
type Authorization = { readonly form?: { selector: string; secret: string }; readonly staff?: P05Context;
  readonly recheck: () => Promise<Date> };
type Decision<T> = (clock: Date) => T;
type Deadline = readonly [expiresAtMs: number, refusal: RequestFailureCode];

function atDecision<T>(deadlines: readonly Deadline[], outcome: () => T): Decision<T> {
  return (clock) => {
    const now = clock.getTime();
    if (!Number.isFinite(now)) { return deny('NOT_READY'); }
    for (const [expiresAtMs, refusal] of deadlines) {
      if (!Number.isSafeInteger(expiresAtMs)) { return deny('NOT_READY'); }
      if (expiresAtMs <= now) { return deny(refusal); }
    }
    return outcome();
  };
}
const basisDeadline = (basis: Basis): readonly Deadline[] =>
  basis.expiresAtMs === null ? [] : [[basis.expiresAtMs,'CONSENT_REQUIRED']];
const decidePrepared = <T>(fn: Decision<T>, clock: Date): T => fn(clock);

/** Isolated P05 application only. There is no HTTP, issuer, secret reader or
 * provider integration in this module. A checked-out connection must belong to
 * an admitted S3 process; no raw environment switch constructs a runtime here. */
export class RequestIntake {
  private readonly config: RequestIntakeConfig;
  private readonly staffAuth: WebAuthService;
  constructor(private readonly pool: GuardedPool, private readonly form: FormSessionService,
    private readonly staff: P05AuthorizationApi, config: RequestIntakeConfig) {
    requireRequestEffectsPool(pool);
    if (config.keySlots.environment !== config.environment
      || !UUID.test(config.currentPolicyId) || !UUID.test(config.formSourceEntryId) || !config.supportedPolicies.size) {
      throw new Error('Invalid request intake configuration');
    }
    if ([...config.supportedPolicies.values()].some(digest => !/^[0-9a-f]{64}$/.test(digest))) {
      throw new Error('Invalid request policy metadata pins');
    }
    this.config = Object.freeze({ ...config, supportedPolicies: new Map(config.supportedPolicies) });
    // P05 uses this service only for authenticate(); the independent throttle key is
    // intentionally ephemeral and is never reused as a CSRF or encryption secret.
    this.staffAuth = new WebAuthService(this.pool, { throttleSecret: randomBytes(32) });
  }

  /** Match the regular CRM guard at the isolated P05 HTTP boundary. This performs
   * the standard sliding-idle authentication in its own short transaction; the
   * subsequent P05 authorization transaction independently rechecks the same proof. */
  async authenticateStaff(token: string): Promise<void> {
    try {
      await this.staffAuth.authenticate(token);
    } catch (error) {
      if (error instanceof WebAuthError) {
        throw new AuthorizationError(error.code === 'UNAUTHORIZED' ? 'UNAUTHORIZED' : 'FAILED');
      }
      throw error;
    }
  }

  private async transaction<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect().catch(() => deny('NOT_READY'));
    let commit = false;
    let discard = false;
    try {
      await beginLegalTransaction(client);
      await client.query('SET LOCAL synchronous_commit=on');
      const result = await fn(client);
      commit = true;
      if ((await client.query('COMMIT')).command !== 'COMMIT') { return deny('NOT_READY'); }
      return result;
    } catch (error) {
      if (commit) { discard = true; return deny('NOT_READY'); }
      try { await client.query('ROLLBACK'); } catch { discard = true; }
      if (error instanceof RequestFailure || error instanceof FormSessionError) { throw error; }
      // Driver exceptions (including connection/busy failures) may carry a query
      // and bindings. Do not send them, retry, or reinterpret as a fresh command.
      if (isLifecycleError(error)) {
        if (error.code === 'NOT_FOUND') { return deny('NOT_FOUND'); }
        if (error.code === 'NOT_CONFIGURED' || error.code === 'WRITE_OUTCOME_UNKNOWN') { return deny('NOT_READY'); }
        return deny('CONFLICT');
      }
      return deny('NOT_READY');
    } finally { client.release(discard); }
  }

  private async ruleVersion(client: PoolClient, id: string): Promise<string | null> {
    const { rows: [row] } = await client.query<{ workflow_version: string; policy_revision: string; metadata_sha256: string; digest_ok: boolean }>(`
      SELECT workflow_version,policy_revision,metadata_sha256,metadata_sha256=encode(sha256(convert_to(metadata::text,'UTF8')),'hex') AS digest_ok
      FROM foundation.request_policy_packages WHERE id=$1`, [id]);
    if (!row?.digest_ok || !SUPPORTED_WORKFLOW_VERSIONS.includes(row.workflow_version)
      || this.config.supportedPolicies.get(policyPairKey(row.workflow_version,row.policy_revision)) !== row.metadata_sha256) {
      return null;
    }
    return row.workflow_version;
  }

  private async rules(client: PoolClient, id: string): Promise<string> {
    return await this.ruleVersion(client,id) ?? deny('REQUEST_RULES_UNAVAILABLE');
  }

  private async manualBasis(client: PoolClient, row: RequestRow): Promise<Basis> {
    const { rows: [source] } = await client.query<{ id: string; procedure_revision: string; valid_until: Date }>(`
      SELECT id,procedure_revision,valid_until FROM foundation.request_staff_evidence
      WHERE request_id=$1 AND purpose='MANUAL_INTAKE'`, [row.id]);
    const evidence = source && { id:source.id,procedureRevision:source.procedure_revision,validUntil:source.valid_until };
    const check = async () => evidence !== undefined && await staffEvidenceLive(client,this.config.staffEvidence,evidence);
    const allowed = await check();
    return { historical: allowed, current: allowed, recheck: check, historicalLive: check,
      expiresAtMs: source?.valid_until.getTime() ?? null, ...(evidence ? {manualEvidence:evidence} : {}) };
  }

  private async formBasis(client: PoolClient, edge: SessionSubmit): Promise<Basis> {
    const consent = await boundConsent(client,edge);
    if (!consent) { return deny('NOT_READY'); }
    return { historical: consent.granted, current: consent.granted && consent.current, expiresAtMs:null,
      historicalLive: async () => (await boundConsent(client,edge))?.granted === true,
      recheck: async () => { const live = await boundConsent(client,edge); return live?.granted === true && live.current; } };
  }

  private async noPartialForm(client: PoolClient, selector: string): Promise<void> {
    // A missing submit edge is not sufficient evidence of no committed effect.
    const partial = await client.query(`SELECT e.id FROM foundation.request_events e WHERE e.actor_session_id=$1
      AND e.command IN ('CreateCallback','CreateRepair') LIMIT 1`, [selector]);
    if (partial.rowCount !== 0) { deny('NOT_READY'); }
  }

  private async knownFormSubmit(client: PoolClient, edge: SessionSubmit, row: RequestRow) {
    const receipt = await checkedReceipt(client,row,edge.event_id);
    if (receipt.command !== edge.submit_command || receipt.principal !== `F:${edge.session_id}` || receipt.version !== 1) {
      return deny('NOT_READY');
    }
    return receipt;
  }

  async submitForm(operation: FSubmit, proof: FProof, input: WriteInput): Promise<WriteResult> {
    requireHeaders(operation,input);
    const prepared = await this.form.prepareRequestProof(proof,true);
    const actor: Actor = { kind: 'F', id: prepared.selector };
    const command = operation === 'createCallback' ? 'CreateCallback' : 'CreateRepair';
    return await this.transaction(async (client) => {
      await this.config.search?.lock(client);
      if (operation === 'createRepair') { await fenceRead(client); }
      await geoFence(client);
      if (operation === 'createRepair') { await this.config.offers?.lock(client); }
      let files: ReadyAttachmentRuntime | undefined;
      if (operation === 'createRepair' && this.config.attachments) {
        try { files = await lockAttachmentRuntime(client,this.config.attachments); }
        catch (error) { if (!isLifecycleError(error) || error.code !== 'NOT_CONFIGURED') { throw error; } }
      }
      const { anchor, recheck } = await prepared.lock(client);
      const edge = await submitEdge(client,{sessionId:anchor.id});
      const doc = await lockConsent(client,edge);
      if (edge) {
        if (!doc || !(await this.formBasis(client,edge)).historical) { await recheck(); return deny('CONSENT_REQUIRED'); }
        const row = await requestRow(client,edge.request_id,true);
        if (!row) { return deny('NOT_READY'); }
        const receipt = await this.knownFormSubmit(client,edge,row);
        await recheck();
        if (receipt.command !== command || receipt.key !== input.key) { return deny('FORM_ALREADY_SUBMITTED'); }
        const body = readBody(operation,input.bytes);
        const result = replayReceipt(this.config.ring,{ actor,command,key:input.key,target:null, match:null,body },receipt);
        await recheck();
        return { receipt: result,replayed: true };
      }
      // No address/contact decode before the live anchor and current exact
      // processing authority have been established independently of that body.
      const consent = await activeGiven(client,anchor.id,doc);
      await recheck();
      await this.noPartialForm(client,anchor.id);
      const body = readBody(operation,input.bytes);
      if (body.consent.evidenceId !== consent.id || body.consent.documentVersionId !== consent.document_version_id) { return deny('CONSENT_REQUIRED'); }
      const city = await currentCity(client);
      if (city.cityId !== anchor.intake_city_id || city.cityVersionId !== anchor.intake_city_version_id) { return deny('CITY_CONTEXT_STALE'); }
      const finish = await this.create(client,{ actor,command,key:input.key,target:null,match:null,body },body,city,
        { form:{ selector:anchor.id,secret:prepared.secret }, recheck },consent,files);
      return finish(await recheck());
    });
  }

  async submitStaff(proof: SessionProof, input: WriteInput): Promise<WriteResult> {
    requireHeaders('createManualRequest',input);
    return await this.staffCall(() => this.staff.withP05(proof,['requests.create'],async (staff) => {
      const { client } = staff;
      await this.config.search?.lock(client);
      await fenceRead(client);
      await geoFence(client);
      const actor: Actor = { kind:'STAFF',id:staff.staffId };
      const identity = { actor,key:input.key,target:null,match:null };
      const decode = () => {
        const body = readBody('createManualRequest',input.bytes);
        const command = body.type === 'CALLBACK' ? 'CreateCallback' : 'CreateRepair';
        const cmd: CommandIdentity = { ...identity,command,body };
        return { body,cmd };
      };
      // An immutable hint determines which target must be authorized before
      // decoding PII. It grants no authority and is read again under the key.
      // Fresh-only channel prerequisites never gate historical replay.
      const hint = await findManualEvent(client,identity);
      let fresh: ReturnType<typeof decode> & { city: SingleCityContext } | undefined;
      if (!hint) {
        const city = await currentCity(client);
        await staff.authorizeCity(city.cityId);
        fresh = { ...decode(),city };
        if (fresh.body.type === 'REPAIR' && fresh.body.contact.mode === 'CHANNEL') { await this.config.offers?.lock(client); }
      }
      // The manual route shares one namespace across callback and repair.
      await lockStaffCommandKey(client,actor,'CreateManualRequest',input.key);
      const event = await findManualEvent(client,identity);
      if (hint && hint.id !== event?.id) { return deny('NOT_READY'); }
      if (event) {
        const target = await this.staffTarget(staff,event.request_id);
        if (target.edge) { return deny('NOT_READY'); }
        const { row,basis } = await this.lockedStaffTarget(staff,target);
        if (!basis.historical) { return deny('CONSENT_REQUIRED'); }
        const receipt = await checkedReceipt(client,row,event.id);
        if (!await basis.historicalLive()) { return deny('CONSENT_REQUIRED'); }
        await staff.recheck();
        const { cmd } = fresh ?? decode();
        return atDecision(basisDeadline(basis), () => {
          if (receipt.command !== cmd.command) { return deny('IDEMPOTENCY_KEY_REUSED'); }
          return { receipt:replayReceipt(this.config.ring,cmd,receipt),replayed:true };
        });
      }
      if (!fresh) { return deny('NOT_READY'); }
      return await this.create(client,fresh.cmd,fresh.body,fresh.city,{ staff, recheck:staff.recheck });
    },decidePrepared));
  }

  private async create(client: PoolClient, cmd: CommandIdentity, body: P05CallbackRequest | P05RepairRequest | P05ManualRequest,
    city: SingleCityContext, authorization: Authorization, consent?: ConsentBinding, files?: ReadyAttachmentRuntime): Promise<Decision<WriteResult>> {
    const staffBody = 'type' in body ? body : undefined;
    const repair = 'address' in body ? body : undefined;
    const callback = repair ? undefined : body as P05CallbackRequest | Extract<P05ManualRequest,{type:'CALLBACK'}>;
    const staff = authorization.staff;
    const form = authorization.form;
    const { staffEvidence } = this.config;
    const workflow = await this.rules(client,this.config.currentPolicyId);
    const selection: P05ChannelSelection | undefined = 'channelSelection' in body ? body.channelSelection
      : staffBody?.contact.mode === 'CHANNEL' ? staffBody.contact.channelSelection : undefined;
    const mode: DispatchBranch = selection ? 'MESSENGER' : 'PHONE';
    const result = decide({ workflowVersion: workflow, command:cmd.command, actor:staff ? 'S' : 'F',status:null,type:null,branch:mode });
    if (result.decision !== 'EXECUTABLE') { return deny('CONFLICT'); }
    const offer = selection ? await confirmOffer(client,this.config.offers,selection) : undefined;
    const status: RequestStatus = offer ? offer.provider === 'TG' ? 'WAITING_TELEGRAM_LINK' : 'WAITING_CHANNEL_LINK'
      : repair ? 'NEW' : 'CALLBACK_REQUIRED';
    const source = await activeReference(client,'REQUEST_SOURCE',staffBody?.sourceEntryId ?? this.config.formSourceEntryId);
    const interval = callback?.callbackIntervalId ? await activeReference(client,'CALLBACK_INTERVAL',callback.callbackIntervalId,city) : null;
    const staffEvidenceTarget = canonicalJson({ cityId:city.cityId, cityVersionId:city.cityVersionId, sourceVersionId:source.versionId,
      operation:cmd.command,key:cmd.key });
    let manual: StaffEvidence | undefined;
    let phone: StaffEvidence | undefined;
    if (staff && staffBody) {
      manual = await confirmEvidence(client,staffEvidence,{ id:staffBody.evidenceId,staffId:staff.staffId,
        purpose:'MANUAL_INTAKE',target:staffEvidenceTarget,canonicalIntent:canonicalJson(body) });
      if (staffBody.contact.mode === 'PHONE') {
        phone = await confirmEvidence(client,staffEvidence,{ id:staffBody.contact.phoneEvidenceId,staffId:staff.staffId,
          purpose:'PHONE_GIVE',target:staffEvidenceTarget,canonicalIntent:canonicalJson(body) });
      }
    } else if (!form || !consent) { return deny('FORBIDDEN'); }
    const ids = { contact:randomUUID(), preference:randomUUID(), address:repair ? randomUUID() : null,
      appliance:repair ? randomUUID() : null, assessment:null };
    const row = await createRequestRow(client,{ id:randomUUID(),customerId:randomUUID(),cityId:city.cityId,
      cityVersionId:city.cityVersionId,policyId:this.config.currentPolicyId,type:repair ? 'REPAIR' : 'CALLBACK',status,revisions:ids });
    await writeContact(client,this.config,row.id,ids.contact,1,mode,body.contact,callback?.comment);
    if (repair && ids.address && ids.appliance) {
      await writeAddress(client,this.config,row,ids.address,1,repair.address);
      await writeAppliance(client,this.config,row.id,ids.appliance,1,repair.appliance,repair.fault);
    }
    await writePreference(client,row.id,ids.preference,1,mode,city.timezone,repair?.urgency,repair?.preferredVisit);
    await client.query(`INSERT INTO foundation.request_intake_provenance
      (request_id,source_entry_id,source_version_id,callback_entry_id,callback_version_id) VALUES ($1,$2,$3,$4,$5)`,
    [row.id,source.entryId,source.versionId,interval?.entryId ?? null,interval?.versionId ?? null]);
    if (manual && staff) { await insertStaffEvidence(client,row.id,staff.staffId,'MANUAL_INTAKE',manual); }
    if (phone && staff) { await insertStaffEvidence(client,row.id,staff.staffId,'PHONE_GIVE',phone); }
    if (offer) { await this.storeOffer(client,row.id,offer); }
    const event = randomUUID();
    const receipt = await writeEffect(client,this.config.ring,row,cmd,event,randomUUID());
    if (mode === 'PHONE') { await writePhone(client,row,event,'GIVEN',randomUUID(),phone?.id); }
    if (form && consent) {
      await client.query(`INSERT INTO foundation.request_session_submits
        (session_id,request_id,customer_id,intake_city_id,intake_city_version_id,consent_id,document_id,document_version_id,event_id,submit_command)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, [form.selector,row.id,row.customer_id,row.city_id,row.intake_city_version_id,
        consent.id,consent.document_id,consent.document_version_id,event,cmd.command]);
    }
    await this.config.search?.setContact(client,row,body.contact,mode === 'PHONE');
    await client.query('SET CONSTRAINTS ALL IMMEDIATE');
    const deadlines: Deadline[] = [];
    const fileIds = 'attachments' in body ? body.attachments : undefined;
    if (fileIds?.length) {
      if (!files || !form || !consent) { return deny('NOT_READY'); }
      const attached = await admitReadyAttachments(client,files,{ requestId:row.id,session:{sessionId:form.selector,token:form.secret},
        consentEvidenceId:consent.id,consentDocumentVersionId:consent.document_version_id,fileIds });
      deadlines.push([attached.expiresAtMs,'CONFLICT']);
    }
    if (offer) { deadlines.push([offer.validUntil.getTime(),'CHANNEL_NOT_READY']); }
    for (const evidence of [manual,phone]) {
      if (evidence) {
        if (!await staffEvidenceLive(client,staffEvidence,evidence)) { return deny('FORBIDDEN'); }
        deadlines.push([evidence.validUntil.getTime(),'FORBIDDEN']);
      }
    }
    for (const reference of [source,interval]) {
      if (reference && reference.validUntil !== null) { deadlines.push([Date.parse(reference.validUntil),'CONFLICT']); }
    }
    // All mutable facts remain under their fences. Expiry is decided at the
    // caller's last F proof or final staff-proof SQL sample, after all awaits.
    return atDecision(deadlines, () => ({ receipt,replayed:false }));
  }

  private async storeOffer(client: PoolClient, id: string, offer: OfferBasis): Promise<void> {
    await client.query(`INSERT INTO foundation.request_channel_choices
      (request_id,provider,catalog_version_id,option_version_id,readiness_basis_id) VALUES ($1,$2,$3,$4,$5)`,
    [id,offer.provider,offer.catalogVersionId,offer.optionVersionId,offer.basisId]);
  }

  private async staffCall<T>(run: () => Promise<T>): Promise<T> {
    try { return await run(); }
    catch (error) { if (error instanceof P05CommitUnknown) { return deny('NOT_READY'); } throw error; }
  }

  private async staffTarget(staff: P05Context, id: string) {
    const row = await requestRow(staff.client,id,false);
    if (!row) { return deny('NOT_FOUND'); }
    await staff.authorizeCity(row.city_id);
    const edge = await submitEdge(staff.client,{ requestId:id });
    return { row,edge };
  }

  private async lockStaffBasis(client: PoolClient, targets: readonly Awaited<ReturnType<RequestIntake['staffTarget']>>[]) {
    const edges = targets.flatMap(({ edge }) => edge ? [edge] : []);
    for (const id of [...new Set(edges.map(e => e.session_id))].sort()) {
      if (!await lockRequestSession(client,id)) { return deny('NOT_READY'); }
    }
    const docs = new Map(edges.map(e => [e.document_id,e]));
    for (const id of [...docs.keys()].sort()) {
      if (!await lockConsent(client,docs.get(id))) { return deny('NOT_READY'); }
    }
  }

  private async lockedStaffTarget(staff: P05Context, target: Awaited<ReturnType<RequestIntake['staffTarget']>>) {
    const { client } = staff;
    const row = await requestRow(client,target.row.id,true);
    if (!row || row.city_id !== target.row.city_id) { return deny('NOT_FOUND'); }
    const linked = target.edge;
    if (linked) { await this.knownFormSubmit(client,linked,row); }
    const basis = linked ? await this.formBasis(client,linked) : await this.manualBasis(client,row);
    await staff.recheck();
    return { row,basis };
  }

  private async scopedStaffRequest(staff: P05Context, id: string) {
    const target = await this.staffTarget(staff,id);
    await this.lockStaffBasis(staff.client,[target]);
    return await this.lockedStaffTarget(staff,target);
  }

  async readStaff(proof: SessionProof, id: string) {
    return await this.staffCall(() => this.staff.withP05(proof,['requests.read'],async (staff) => {
      const { row,basis } = await this.scopedStaffRequest(staff,id);
      const available = await basis.historicalLive();
      return (clock: Date) => requestRepresentation('STAFF',row,available
        && (basis.expiresAtMs === null || clock.getTime() < basis.expiresAtMs));
    },decidePrepared));
  }

  private async readCrmTarget<T, R>(proof: SessionProof, id: string,
    project: (staff: P05Context, row: RequestRow, basis: Basis) => Promise<T>, restricted: (row: RequestRow) => R) {
    return await this.staffCall(() => this.staff.withP05(proof, ['requests.read'], async staff => {
      const { row,basis } = await this.scopedStaffRequest(staff,id);
      if (!basis.historical) { return () => restricted(row); }
      const stillCurrent = await this.crmBasisAtDecision(staff,basis);
      const data = await project(staff,row,basis);
      const available = await basis.historicalLive();
      return (clock: Date) => available && (basis.expiresAtMs === null || clock.getTime() < basis.expiresAtMs)
        && stillCurrent()
        ? data : restricted(row);
    },decidePrepared));
  }

  private async crmBasisAtDecision(staff: P05Context, basis: Basis): Promise<() => boolean> {
    const evidence = basis.manualEvidence;
    if (!evidence) { return () => true; }
    const isCurrent = await this.config.staffEvidence?.openRegistry?.(staff.client);
    if (!isCurrent) { return deny('NOT_READY'); }
    return () => isCurrent(evidence);
  }

  async readStaffCard(proof: SessionProof, id: string) {
    return await this.readCrmTarget(proof, id, async (staff,row,basis) => {
      const { branch, ...card } = await readCard(staff.client,row);
      let canStartReview = false;
      if (basis.current && branch !== null && (row.status === 'NEW' || row.status === 'CALLBACK_REQUIRED')
        && await staff.hasCityGrant('requests.review',row.city_id)) {
        const workflowVersion = await this.ruleVersion(staff.client,row.workflow_package_id);
        canStartReview = workflowVersion !== null && decide({ workflowVersion, command:'StartReview',
          actor:'S',status:row.status,type:row.type,branch }).decision === 'EXECUTABLE';
      }
      const comments = this.config.comments?.keySlots.environment === COMMENT_KEY_ENVIRONMENT ? await commentGrant(staff,row) : undefined;
      const contacts = this.config.contactAudit && basis.current && await hasContactGrant(staff,row.city_id);
      const unavailable = { ...card.unavailable,comments:comments?.canRead ? 'available' : 'not_ready',
        contactDetails:contacts ? 'available' : 'not_ready' };
      return { data:{ ...card,canStartReview,unavailable },commandEtag:requestRepresentation('STAFF',row,true).etag,
        canAddComment:basis.current && comments?.canWrite === true };
    }, row => ({ data:{ version:row.row_version },commandEtag:null,canAddComment:false }));
  }

  async readStaffTimeline(proof: SessionProof, id: string) {
    return await this.readCrmTarget(proof,id,(staff,row) => readTimeline(staff.client,row),() => ({ items:[] }));
  }

  async readStaffComments(proof: SessionProof, id: string) {
    const config = this.config.comments;
    return await this.readCrmTarget(proof,id,async (staff,row,basis) => {
      if (!config || config.keySlots.environment !== COMMENT_KEY_ENVIRONMENT) { return deny('NOT_READY'); }
      await authorizeComments(staff,row,false);
      const isCurrent = await this.crmBasisAtDecision(staff,basis);
      const beforeOpen = async () => {
        if (!await basis.recheck()) { return deny('CONSENT_REQUIRED'); }
        const clock = await staff.recheck();
        if ((basis.expiresAtMs !== null && basis.expiresAtMs <= clock.getTime()) || !isCurrent()) {
          return deny('CONSENT_REQUIRED');
        }
      };
      return await readInternalComments(staff,row,config,beforeOpen);
    },() => ({ items:[] }));
  }

  async readStaffContact(proof: SessionProof, id: string) {
    const audit = this.config.contactAudit;
    return await this.readCrmTarget(proof,id,async (staff,row,basis) => {
      if (!audit) { return deny('NOT_READY'); }
      if (!await hasContactGrant(staff,row.city_id)) { return deny('FORBIDDEN'); }
      const recheck = async () => {
        if (!await basis.recheck()) { return deny('CONSENT_REQUIRED'); }
        const clock = await staff.recheck();
        atDecision(basisDeadline(basis),() => undefined)(clock);
      };
      await recheck();
      const contact = await readContactDetails(staff,row,this.config,audit,recheck);
      await recheck();
      return contact;
    },() => deny('CONSENT_REQUIRED'));
  }

  async addStaffComment(proof: SessionProof, id: string, input: WriteInput) {
    const config = this.config.comments;
    return await this.staffCall(() => this.staff.withP05(proof, ['requests.read'], async staff => {
      const { row,basis } = await this.scopedStaffRequest(staff,id);
      if (!config || config.keySlots.environment !== COMMENT_KEY_ENVIRONMENT) { return deny('NOT_READY'); }
      await authorizeComments(staff,row,true);
      if (!basis.current) { return deny('CONSENT_REQUIRED'); }
      const stillCurrent = await this.crmBasisAtDecision(staff,basis);
      const result = await writeInternalComment(staff,row,config,input,requestRepresentation('STAFF',row,true).etag,proof.token);
      if (!await basis.recheck()) { return deny('CONSENT_REQUIRED'); }
      return atDecision(basisDeadline(basis),() => stillCurrent() ? result : deny('CONSENT_REQUIRED'));
    },decidePrepared,'write'));
  }

  async readStaffRegistry(proof: SessionProof, query: RegistryQuery) {
    return await this.staffCall(() => this.staff.withP05(proof, ['requests.read'], async (staff) => {
      await geoFence(staff.client);
      const city = await currentCity(staff.client);
      await staff.authorizeCity(city.cityId);
      // Consent withdrawal takes this same document lock before writing the revocation.
      if (!await lockConsent(staff.client, undefined, 'shared')) { return deny('NOT_READY'); }
      const evidencePort = this.config.staffEvidence;
      if (evidencePort && !evidencePort.openRegistry) { return deny('NOT_READY'); }
      const isCurrent = await evidencePort?.openRegistry?.(staff.client);
      return { ...await readVisibleRegistry(staff.client, city, query, isCurrent), isCurrent };
    }, ({ items, nextCursor, manualEvidence, isCurrent }, clock) => {
      if (manualEvidence.some(evidence => !(evidence.validUntil.getTime() > clock.getTime()) || !isCurrent?.(evidence))) {
        return deny('NOT_READY');
      }
      return { items, nextCursor };
    }));
  }

  async readStaffRegistryOptions(proof: SessionProof) {
    return await this.staffCall(() => this.staff.withP05(proof, ['requests.read'], async (staff) => {
      await geoFence(staff.client);
      const city = await currentCity(staff.client);
      await staff.authorizeCity(city.cityId);
      return await readRegistryOptions(staff.client, city.cityId);
    }));
  }

  async searchStaffRegistry(proof: SessionProof, bytes: Uint8Array) {
    return await this.staffCall(() => this.staff.withP05(proof, ['requests.read'], async staff => {
      const search = this.config.search;
      if (!search) { return deny('NOT_READY'); }
      await search.lock(staff.client);
      await geoFence(staff.client);
      const city = await currentCity(staff.client);
      await staff.authorizeCity(city.cityId);
      const query = parseSearch(bytes);
      if (query.kind !== 'number' && !await hasContactGrant(staff,city.cityId)) { return deny('FORBIDDEN'); }
      if (query.kind !== 'number') { await search.assertCurrent(staff.client); }
      await search.admit(staff.staffId,city.cityId,query.kind);
      if (!await lockConsent(staff.client,undefined,'shared')) { return deny('NOT_READY'); }
      const port = this.config.staffEvidence;
      if (port && !port.openRegistry) { return deny('NOT_READY'); }
      const isCurrent = await port?.openRegistry?.(staff.client);
      const match = query.kind === 'number' ? { kind:query.kind,key:query.value } as const
        : { kind:query.kind,key:search.token(query.kind,city.cityId,query.value) };
      return { ...await readRegistrySearch(staff.client,city.cityId,match,isCurrent),isCurrent };
    }, ({ items,truncated,manualEvidence,isCurrent }, clock) => {
      if (manualEvidence.some(evidence => !(evidence.validUntil.getTime() > clock.getTime()) || !isCurrent?.(evidence))) {
        return deny('NOT_READY');
      }
      return { items,truncated };
    }));
  }

  async readStaffDashboard(proof: SessionProof) {
    return dashboardDto((await this.dashboardSnapshot(proof)).snapshot);
  }

  async readStaffDashboardPage(proof: SessionProof, link: DashboardLink) {
    const { snapshot,reused } = await this.dashboardSnapshot(proof,link);
    return dashboardPage(snapshot,link,!reused);
  }

  private async dashboardSnapshot(proof: SessionProof, link?: DashboardLink) {
    const cache = this.config.dashboard;
    if (!cache) { return deny('NOT_READY'); }
    const run = async (tryReuse: boolean) => await this.staffCall(() => this.staff.withP05(proof,['requests.read'],async staff => {
      await geoFence(staff.client);
      const city = await currentCity(staff.client);
      await staff.authorizeCity(city.cityId);
      if (!await lockConsent(staff.client,undefined,'shared')) { return deny('NOT_READY'); }
      const port = this.config.staffEvidence;
      if (port && !port.openRegistry) { return deny('NOT_READY'); }
      const isCurrent = await port?.openRegistry?.(staff.client);
      const subject: DashboardSubject = { ...city,staffId:staff.staffId,sessionId:staff.sessionId };
      const basisCurrent = (snapshot: DashboardSnapshot, clock: Date) => snapshot.material.evidence.every(evidence =>
        evidence.validUntil.getTime() > clock.getTime() && isCurrent?.(evidence) === true);
      const usable = (snapshot: DashboardSnapshot, clock: Date) => cache.live(snapshot)
        && Date.parse(snapshot.material.localDay.to) > clock.getTime() && basisCurrent(snapshot,clock);
      const previous = tryReuse && link ? cache.find(link.snapshot,subject) : undefined;
      if (previous && await dashboardRowsCurrent(staff.client,city.cityId,previous.material)
        && usable(previous,await staff.recheck())) {
        return (clock:Date) => usable(previous,clock) ? { snapshot:previous,reused:true } : null;
      }
      const snapshot = cache.issue(subject,await captureDashboard(staff.client,city,isCurrent));
      return (clock:Date) => usable(snapshot,clock) ? { snapshot,reused:false } : null;
    },decidePrepared));
    const selected = await run(true) ?? await run(false);
    if (!selected) { return deny('NOT_READY'); }
    if (!selected.reused) { cache.remember(selected.snapshot); }
    return selected;
  }

  async readForm(proof: FProof) {
    const prepared = await this.form.prepareRequestProof(proof,false);
    return await this.transaction(async (client) => {
      const { anchor,recheck } = await prepared.lock(client);
      const edge = await submitEdge(client,{ sessionId:anchor.id });
      if (!edge) { await this.noPartialForm(client,anchor.id); await recheck(); return deny('NOT_FOUND'); }
      if (!await lockConsent(client,edge)) { return deny('NOT_READY'); }
      const row = await requestRow(client,edge.request_id,true);
      if (!row) { return deny('NOT_READY'); }
      await this.knownFormSubmit(client,edge,row);
      const basis = await this.formBasis(client,edge);
      await recheck();
      return requestRepresentation('F',row,basis.historical);
    });
  }

  async commandForm(operation: FCommand, proof: FProof, input: WriteInput): Promise<WriteResult> {
    requireHeaders(operation,input);
    const prepared = await this.form.prepareRequestProof(proof,true);
    return await this.transaction(async (client) => {
      if (operation !== 'cancelRequestF') { await this.config.search?.lock(client); }
      await geoFence(client);
      const { anchor,recheck } = await prepared.lock(client);
      const edge = await submitEdge(client,{ sessionId:anchor.id });
      if (!edge) { await this.noPartialForm(client,anchor.id); await recheck(); return deny('NOT_FOUND'); }
      if (!await lockConsent(client,edge)) { return deny('NOT_READY'); }
      const row = await requestRow(client,edge.request_id,true);
      if (!row) { return deny('NOT_READY'); }
      const basis = await this.formBasis(client,edge);
      if (!basis.historical && !CLOSING.has(F_COMMANDS[operation])) { await recheck(); return deny('CONSENT_REQUIRED'); }
      await this.knownFormSubmit(client,edge,row);
      await recheck();
      const body = readBody(operation,input.bytes);
      const cmd: CommandIdentity = { actor:{kind:'F',id:anchor.id},command:F_COMMANDS[operation],key:input.key,
        target:row.id,match:input.ifMatch ?? null,body };
      const finish = await this.mutate(client,row,basis,cmd,body,{ form:{selector:anchor.id,secret:prepared.secret},recheck });
      return finish(await recheck());
    });
  }

  async commandStaff(operation: StaffCommand, proof: SessionProof, id: string, input: WriteInput): Promise<WriteResult> {
    requireHeaders(operation,input);
    const [command,code] = STAFF_COMMANDS[operation];
    return await this.staffCall(() => this.staff.withP05(proof,[code],async (staff) => {
      if (operation === 'changeContact' || operation === 'withdrawPhoneStaff') { await this.config.search?.lock(staff.client); }
      if (operation === 'convertCallback' || operation === 'changeDetails') { await fenceRead(staff.client); }
      await geoFence(staff.client);
      const identity = { actor:{kind:'STAFF' as const,id:staff.staffId},command,key:input.key,target:id,match:input.ifMatch ?? null };
      const { client } = staff;
      const target = await this.staffTarget(staff,id);
      // This hint is a non-authoritative immutable lookup before we take any
      // anchors. If it changes while waiting for the key, fail closed rather
      // than extend the lock set backwards or disclose a prior effect.
      const hint = await findEvent(client,identity);
      const previous = hint && hint.request_id !== id ? await this.staffTarget(staff,hint.request_id) : undefined;
      await this.lockStaffBasis(client,previous ? [target,previous] : [target]);
      await lockStaffCommandKey(client,identity.actor,command,input.key);
      const prior = await findEvent(client,identity);
      if (prior && prior.request_id !== id && (!previous || previous.row.id !== prior.request_id)) { return deny('NOT_READY'); }
      const targets = new Map<string,Awaited<ReturnType<RequestIntake['lockedStaffTarget']>>>();
      for (const item of (previous ? [target,previous] : [target]).sort((left,right) => left.row.id < right.row.id ? -1 : 1)) {
        targets.set(item.row.id,await this.lockedStaffTarget(staff,item));
      }
      const own = targets.get(id);
      if (!own) { return deny('NOT_READY'); }
      const { row,basis } = own;
      const closing = CLOSING.has(command);
      if (!closing && !await basis.historicalLive()) { return deny('CONSENT_REQUIRED'); }
      if (prior && prior.request_id !== id) {
        const other = targets.get(prior.request_id);
        if (!other) { return deny('NOT_READY'); }
        if (!closing && !await other.basis.historicalLive()) { return deny('CONSENT_REQUIRED'); }
        await checkedReceipt(client,other.row,prior.id);
        const deadlines = closing ? [] : [...basisDeadline(basis),...basisDeadline(other.basis)];
        return atDecision<WriteResult>(deadlines, () => deny('IDEMPOTENCY_KEY_REUSED'));
      }
      const body = readBody(operation,input.bytes);
      return await this.mutate(client,row,basis,{ ...identity,body },body,{ staff,recheck:staff.recheck });
    },decidePrepared));
  }

  private async mutate(client: PoolClient, row: RequestRow, basis: Basis, cmd: CommandIdentity,
    body: P05Bodies[FCommand|StaffCommand], auth: Authorization): Promise<Decision<WriteResult>> {
    const closing = CLOSING.has(cmd.command);
    const prior = await findEvent(client,cmd);
    if (prior) {
      // Cross-target staff reuse was resolved under the ordered lock set.
      if (prior.request_id !== row.id) { return deny('NOT_READY'); }
      const persisted = await checkedReceipt(client,row,prior.id);
      if (!closing && !await basis.historicalLive()) { return deny('CONSENT_REQUIRED'); }
      return atDecision(closing ? [] : basisDeadline(basis), () => ({
        receipt:replayReceipt(this.config.ring,cmd,persisted),replayed:true,
      }));
    }
    if (!closing && !basis.current) { await auth.recheck(); return deny('CONSENT_REQUIRED'); }
    const workflow = await this.rules(client,row.intake_policy_revision_id);
    const fullAtStart = await basis.historicalLive();
    if (cmd.match !== requestRepresentation(cmd.actor.kind,row,fullAtStart).etag) { await auth.recheck(); return deny('PRECONDITION_FAILED'); }
    const mode = await modeOf(client,row);
    const decision = decide({ workflowVersion:workflow, command:cmd.command,actor:cmd.actor.kind === 'F' ? 'F' : 'S',
      status:row.status,type:row.type,branch:mode });
    if (decision.decision === 'AWAIT_DEPENDENCY') { return deny('DEPENDENCY_UNAVAILABLE'); }
    if (decision.decision !== 'EXECUTABLE') { return deny('CONFLICT'); }
    const effectId = randomUUID();
    const nextVersion = row.row_version + 1;
    const staff = auth.staff;
    let revisions: Revisions = { contact:row.current_contact_revision_id,address:row.current_address_revision_id,
      appliance:row.current_appliance_revision_id,preference:row.current_preference_revision_id,assessment:row.current_assessment_id };
    let extra: Record<string,string> = {};
    let permission: { action:'GIVEN'|'REVOKED'; id:string; evidenceId?:string; supersedes?:string } | undefined;
    let finalEvidence: StaffEvidence | undefined;
    let changedContact: P05FContact | undefined;
    let assessmentDeadline: number | undefined;
    let expires: string | null = null;
    switch (cmd.command) {
      case 'StartReview': break;
      case 'ConvertCallback': {
        const patch = body as P05Bodies['convertCallback'];
        const city = await currentCity(client);
        if (city.cityId !== row.city_id) { return deny('CITY_CONTEXT_STALE'); }
        const address = randomUUID(), appliance = randomUUID(), preference = randomUUID();
        await writeAddress(client,this.config,row,address,nextVersion,patch.address);
        await writeAppliance(client,this.config,row.id,appliance,nextVersion,patch.appliance,patch.fault);
        await writePreference(client,row.id,preference,nextVersion,mode,city.timezone,patch.urgency,patch.preferredVisit);
        revisions = { ...revisions,address,appliance,preference,assessment:null };
        break;
      }
      case 'ChangeDetails': {
        const patch = body as P05Bodies['changeDetails'];
        const city = await currentCity(client);
        if (city.cityId !== row.city_id) { return deny('CITY_CONTEXT_STALE'); }
        if (patch.section === 'ADDRESS') {
          const address = randomUUID();
          await writeAddress(client,this.config,row,address,nextVersion,patch.address);
          revisions = { ...revisions,address,assessment:null };
        } else if (patch.section === 'APPLIANCE') {
          const appliance = randomUUID();
          await writeAppliance(client,this.config,row.id,appliance,nextVersion,patch.appliance,patch.fault);
          revisions = { ...revisions,appliance };
        } else {
          const preference = randomUUID();
          await writePreference(client,row.id,preference,nextVersion,mode,city.timezone,patch.urgency,patch.preferredVisit);
          revisions = { ...revisions,preference };
        }
        break;
      }
      case 'RecordCoverageAssessment': {
        if (!staff || !this.config.coverage) { return deny('DEPENDENCY_UNAVAILABLE'); }
        const assessment = await this.config.coverage.assess({ client,actor:staff,request:row,body:body as P05Bodies['recordCoverage'],
          eventId:effectId,recheck:async () => {
             if (!await basis.recheck()) { deny('CONSENT_REQUIRED'); }
             const clock = await auth.recheck();
             atDecision(basisDeadline(basis), () => undefined)(clock);
             return clock;
           } });
        revisions = { ...revisions,assessment:assessment.id };
        assessmentDeadline = assessment.expiresAt.getTime();
        if (!Number.isFinite(assessmentDeadline)) { return deny('FORBIDDEN'); }
        break;
      }
      case 'ChangeContact': {
        if (!staff) { return deny('FORBIDDEN'); }
        const patch = body as P05Bodies['changeContact'];
        finalEvidence = await this.consumeStaffEvidence(staff,row,'CONTACT_CHANGE',patch.evidenceId,cmd);
        const contact = randomUUID();
        await writeContact(client,this.config,row.id,contact,nextVersion,await readContactMode(client,row),patch.contact);
        changedContact = patch.contact;
        revisions = { ...revisions,contact };
        break;
      }
      case 'ChooseCallback': {
        if (!auth.form || mode !== 'MESSENGER' || await activePhone(client,row)) { return deny('CONFLICT'); }
        const preference = randomUUID();
        await clonePhonePreference(client,row,preference);
        revisions = { ...revisions,preference };
        permission = { action:'GIVEN',id:randomUUID() };
        break;
      }
      case 'WithdrawPhonePermission': {
        const given = await activePhone(client,row);
        if (!given) { return deny('CONFLICT'); }
        if (staff) {
          finalEvidence = await this.consumeStaffEvidence(staff,row,'PHONE_WITHDRAW',(body as P05Bodies['withdrawPhoneStaff']).evidenceId,cmd,given);
        }
        permission = { action:'REVOKED',id:randomUUID(),supersedes:given,...(finalEvidence ? { evidenceId:finalEvidence.id } : {}) };
        break;
      }
      case 'ReadyForDispatch': {
        if (!await activePhone(client,row)) { return deny('CONFLICT'); }
        if (!this.config.coverage || !await this.config.coverage.eligible(client,row)) { return deny('COVERAGE_ASSESSMENT_STALE'); }
        break;
      }
      case 'CancelRequest': {
        const reason = await activeReference(client,'CANCEL_REASON',(body as P05Bodies['cancelRequestStaff']).reasonEntryId);
        extra = { reasonEntryId:reason.entryId,reasonVersionId:reason.versionId };
        expires = reason.validUntil;
        break;
      }
      default: return deny('CONFLICT');
    }
    const changed = await updateRequestRow(client,row,decision.target ?? row.status,decision.resultingType ?? row.type,revisions);
    const receipt = await writeEffect(client,this.config.ring,changed,cmd,effectId,randomUUID(),extra);
    if (permission) { await writePhone(client,changed,effectId,permission.action,permission.id,permission.evidenceId,permission.supersedes); }
    const search = this.config.search;
    if (search && changedContact) {
      await search.setContact(client,changed,changedContact,false);
    } else if (search && permission?.action === 'GIVEN') {
      await search.assertCurrent(client);
      await search.setContact(client,changed,await readStoredContact(client,changed,this.config),true);
    } else if (search && permission?.action === 'REVOKED') {
      await search.removePhone(client,changed);
    }
    await client.query('SET CONSTRAINTS ALL IMMEDIATE');
    if (!closing && !await basis.recheck()) { return deny('CONSENT_REQUIRED'); }
    if (finalEvidence && !await staffEvidenceLive(client,this.config.staffEvidence,finalEvidence)) { return deny('FORBIDDEN'); }
    const deadlines: Deadline[] = closing ? [] : [...basisDeadline(basis)];
    if (finalEvidence) { deadlines.push([finalEvidence.validUntil.getTime(),'FORBIDDEN']); }
    if (expires !== null) { deadlines.push([Date.parse(expires),'CONFLICT']); }
    if (assessmentDeadline !== undefined) { deadlines.push([assessmentDeadline,'FORBIDDEN']); }
    const available = closing ? await basis.historicalLive() : true;
    return (clock) => {
      const full = available && (basis.expiresAtMs === null || clock.getTime() < basis.expiresAtMs);
      if (closing && full !== fullAtStart) { return deny('PRECONDITION_FAILED'); }
      return atDecision(deadlines, () => ({ receipt,replayed:false }))(clock);
    };
  }

  private async consumeStaffEvidence(staff: P05Context, row: RequestRow, purpose:'CONTACT_CHANGE'|'PHONE_WITHDRAW', id:string,
    cmd: CommandIdentity, permit?: string) {
    const evidence = await confirmEvidence(staff.client,this.config.staffEvidence,{ id,purpose,staffId:staff.staffId,
      target:canonicalJson({ requestId:row.id,contactRevisionId:row.current_contact_revision_id,permit:permit ?? null,
        version:row.row_version,ifMatch:cmd.match }),canonicalIntent:canonicalJson(cmd.body) });
    await insertStaffEvidence(staff.client,row.id,staff.staffId,purpose,evidence);
    return evidence;
  }

  /** Read-only reference predicate for both future admission points. This is
   * NOT an enqueue/execution grant: future callers must hold the corresponding
   * transaction through admission. There is no consumer in P05. */
  async inspectPhoneEligibility(proof: SessionProof, id: string, expectedVersion: number, expectedPermit: string): Promise<boolean> {
    return await this.staffCall(() => this.staff.withP05(proof,['requests.ready'],async (staff) => {
      await geoFence(staff.client);
      const { row,basis } = await this.scopedStaffRequest(staff,id);
      if (!basis.current || row.row_version !== expectedVersion || row.status !== 'WAITING_ASSIGNMENT'
        || await modeOf(staff.client,row) !== 'PHONE' || await activePhone(staff.client,row) !== expectedPermit
        || !this.config.coverage) { return () => false; }
      const eligible = await this.config.coverage.eligible(staff.client,row) && await basis.recheck();
      return (clock: Date) => eligible && (basis.expiresAtMs === null || clock.getTime() < basis.expiresAtMs);
    },decidePrepared));
  }
}

