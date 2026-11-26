import { createHmac, randomUUID } from 'node:crypto';
import type { IncomingHttpHeaders } from 'node:http';
import { decodeP05ManualRequest } from '@fixlevelup/p03-contracts/p05';
import { expect } from 'vitest';
import { canonicalJson } from '../src/infrastructure/admission/proof.js';
import type { StaffEvidence, StaffEvidencePort } from '../src/requests/intake/basis.js';
import type { CoverageReviewEvidence } from '../src/requests/intake/coverage.js';
import { changedPointers, closingCommands, expectedMutation, formCommands, futureStates, noP05CommandRoutes,
  staffCommands, witnesses } from './p05-http-matrix-oracle.js';
import type { FormCommand, MatrixActor, MatrixCommand, Mutation, Preparation, Provider, Recipe, StaffCommand, Witness } from './p05-http-matrix-oracle.js';
import { withHttpMatrixActors } from './p05-http-matrix-actors.js';
import type { StaffProof } from './p05-http-matrix-actors.js';
import type { OfferFixtureIds } from './p05-offer-fixture.js';
import type { RequestFixtures } from './p05-request-fixtures.js';
import { record, text } from './rbac-fixture.js';
import type { RbacFixture } from './rbac-fixture.js';

interface Reply {
  status: number; bytes: string; headers: IncomingHttpHeaders; data(): Record<string, unknown>;
}
interface Form { sid: string; csrf: string; cookie: string }
interface Snapshot {
  row: { row_version:number; public_number:string; current_contact_revision_id:string|null;
    current_address_revision_id:string|null; current_appliance_revision_id:string|null;
    current_preference_revision_id:string|null; current_assessment_id:string|null };
  history: readonly { kind:string; value:Record<string,unknown> }[];
}
type EvidenceBinding=Parameters<StaffEvidencePort['verify']>[1];
interface Ports {
  lab: RbacFixture; fixture: RequestFixtures; staffCsrf: string; offerIds: Readonly<Record<Provider,OfferFixtureIds>>;
  /** Bounded phases of one normative inventory. Vitest's per-case cap would
   * otherwise truncate the walk. Each witness slice runs exactly the cells of
   * its six witnesses; the union over all phases is the full inventory. */
  phase: 'witnesses-0' | 'witnesses-1' | 'witnesses-2' | 'roles' | 'denials'
    | 'city-admin-0' | 'city-admin-1' | 'city-admin-2' | 'city-manager-0' | 'city-manager-1' | 'city-manager-2' | 'city-custom-0' | 'city-custom-1' | 'city-custom-2';
  contact: { readonly name:string; readonly phone:string }; address: { readonly street:string; readonly building:string };
  send: (method:'GET'|'POST', path:string, body?:unknown, headers?:Record<string,string>) => Promise<Reply>;
  issue(): Promise<Form>;
  given(form:Form): Promise<string>;
  capture(id:string): Promise<Snapshot>;
  progress(phase:string,checks:number): void;
  setStaff(proof:StaffEvidence & EvidenceBinding): void;
  setReview(proof:CoverageReviewEvidence): void;
}
interface Target { id:string; path:string; form:Form|undefined }
interface Principal { kind:MatrixActor; id:string }
const fPath='/public/request-session';
const fView=['publicNumber','status','version'];
const staffView=['id','publicNumber','type','status','version'];
const staffReceipt=['id','publicNumber','status','version'];
const byStaff=Object.keys(staffCommands) as StaffCommand[];
const byForm=Object.keys(formCommands) as FormCommand[];

type Inspector = (kind:string) => Record<string,unknown>;
function appendOnly(before:Snapshot['history'],after:Snapshot['history'],expected:readonly string[],label:string):Inspector {
  const old=new Set(before.map(canonicalJson));
  const current=new Set(after.map(canonicalJson));
  expect([...old].every(item=>current.has(item)),label).toBe(true);
  const added=after.filter(item=>!old.has(canonicalJson(item)));
  expect(added.map(item=>item.kind).sort(),label).toEqual([...expected].sort());
  return kind=>{
    const row=added.find(item=>item.kind === kind);
    if (!row) { throw new Error(`Missing ${kind}: ${label}`); }
    return row.value;
  };
}
function currentPermit(s:Snapshot): string|null {
  const phone=s.history.filter(x=>x.kind === 'phone').map(x=>x.value);
  const current=phone.filter(p=>p['contact_revision_id'] === s.row.current_contact_revision_id && p['action']==='GIVEN'
    && !phone.some(other=>other['supersedes_given_id']===p['id']));
  expect(current.length).toBeLessThanOrEqual(1);
  return current[0] ? text(current[0],'id') : null;
}

/** HTTP requests only for effects and state creation. The owner-side ports are
 * passive snapshots, fenced RBAC provisioning, and approved synthetic evidence. */
export async function proveHttpMatrix(p:Ports): Promise<number> {
  const {lab,fixture,send,contact}=p;
  const detail={address:{...p.address,districtId:fixture.districtId},appliance:{categoryId:fixture.categoryId},fault:{faultIds:[fixture.faultId]}};
  const cancel={reasonEntryId:fixture.cancelReasonEntryId};
  const phoneContact=()=>({...contact,mode:'PHONE',phonePermission:true,phoneEvidenceId:randomUUID()});
  const { rows:[source] }=await lab.db.query<{version:string}>(`SELECT current_version_id AS version FROM foundation.reference_entries WHERE id=$1`,[fixture.formSourceEntryId]);
  if (!source) { throw new Error('Missing synthetic intake source'); }
  const sourceVersion=source.version;
  const headers=(actor:StaffProof|Form,key?:string,etag?:string) => ({Cookie:actor.cookie,
    ...('sid' in actor ? {'X-Form-Session-Id':actor.sid} : {}),
    ...(key ? {'Idempotency-Key':key,'X-CSRF-Token':'sid' in actor ? actor.csrf
      : createHmac('sha256',p.staffCsrf).update('web-auth-csrf\0').update(actor.token).digest('base64url')} : {}),
    ...(etag ? {'If-Match':etag} : {}),
  });
  function wire(r:Reply,status:number,label:string):void {
    expect(r.status,`${label}: ${r.status < 400 ? 'success' : r.bytes}`).toBe(status);
    expect(r.headers['cache-control'],label).toMatch(/^no-store/);
    const message=JSON.stringify([r.bytes,r.headers]);
    for (const sentinel of [contact.name,contact.phone,p.address.street,'F matrix secret']) { expect(message.includes(sentinel),label).toBe(false); }
  }
  function closed(r:Reply,status:number,keys:readonly string[],label:string):Reply {
    wire(r,status,label);
    expect(Object.keys(record(JSON.parse(r.bytes) as unknown)),label).toEqual(['data']);
    expect(Object.keys(r.data()).sort(),label).toEqual([...keys].sort());
    return r;
  }
  function deny(r:Reply,status:number,code:string,label:string):void {
    wire(r,status,label);
    const {requestId,...problem}=record(JSON.parse(r.bytes) as unknown);
    expect(requestId,label).toEqual(expect.any(String));
    expect(problem,label).toEqual({type:'about:blank',title:code,status,code});
    expect(r.headers.etag,label).toBeUndefined();
  }
  function mint(id:string,purpose:EvidenceBinding['purpose'],staffId:string,target:string,body:unknown) {
    p.setStaff({id,purpose,staffId,target,canonicalIntent:canonicalJson(body),procedureRevision:'fixture-v1',
      validUntil:new Date(Date.now()+(purpose==='MANUAL_INTAKE' ? 900000 : 300000))});
  }
  const view=async (target:Target,actor:StaffProof|Form,label:string) => {
    const form='sid' in actor;
    const reply=closed(await send('GET',form ? fPath : target.path,undefined,headers(actor)),200,form ? fView : staffView,label);
    expect(reply.headers.etag,label).toMatch(/^"p05-r1-[a-f0-9]{64}"$/);
    return { data:reply.data(), etag:reply.headers.etag ?? '' };
  };
  function verifyCommon(added:Inspector,id:string,status:string,version:number,key:string,
    name:string,principal:Principal,label:string,extra:Record<string,string>={}) {
    const event=added('event'), receipt=added('receipt'), audit=added('audit'), outbox=added('outbox');
    const info={requestId:id,status,version,...extra};
    expect(event,label).toMatchObject({request_id:id,command:name,operation:name,principal:`${principal.kind}:${principal.id}`,
      idempotency_key:key,actor_type:principal.kind,actor_staff_id:principal.kind==='STAFF' ? principal.id : null,
      actor_session_id:principal.kind==='F' ? principal.id : null,resulting_version:version});
    expect(event['details'],label).toEqual(info);
    expect(receipt,label).toMatchObject({event_id:event['id'],request_id:id,version,command:name,
      resulting_status:status,correlation_id:event['correlation_id'],audit_id:audit['id'],outbox_id:outbox['id']});
    expect(audit,label).toMatchObject({operation:name,correlation_id:event['correlation_id']});
    expect(audit['details'],label).toEqual({...info,actorId:principal.id,actorKind:principal.kind});
    expect(outbox,label).toMatchObject({event_id:event['id'],status:'PENDING',lease_owner:null,
      event_type:name==='CreateCallback' ? 'REQUEST_CALLBACK_INTENT' : name==='ReadyForDispatch'
        ? 'REQUEST_READY_FOR_ASSIGNMENT' : 'REQUEST_EFFECT_RECORDED'});
    expect(outbox['payload'],label).toEqual({requestId:id,version});
    return event;
  }
  const cancelVersion=text((await lab.db.query<{version:string}>(`SELECT current_version_id AS version FROM foundation.reference_entries WHERE id=$1`,
    [fixture.cancelReasonEntryId])).rows[0] ?? {},'version');
  const inventory=async () => (await lab.db.query<Record<string,unknown>>(`SELECT
    (SELECT count(*) FROM foundation.customers) customers,(SELECT count(*) FROM foundation.requests) requests,
    (SELECT count(*) FROM foundation.request_events) events,(SELECT count(*) FROM foundation.request_command_receipts) receipts,
    (SELECT count(*) FROM foundation.request_staff_evidence) staff_evidence,(SELECT count(*) FROM foundation.request_session_submits) submits,
    (SELECT count(*) FROM foundation.request_payload_cells) cells,(SELECT count(*) FROM foundation.phone_permission_events) permissions,
    (SELECT count(*) FROM foundation.request_address_review_attempts) address_reviews,
    (SELECT count(*) FROM foundation.audit_logs) audit,(SELECT count(*) FROM foundation.outbox_events) outbox`)).rows[0];

  const create=async (recipe:Recipe,actor:StaffProof|'F'):Promise<Target> => {
    const form=actor==='F' ? await p.issue() : undefined;
    const principal:Principal=actor==='F' && form ? {kind:'F',id:form.sid} : {kind:'STAFF',id:actor==='F' ? '' : actor.id};
    const key=randomUUID();
    const name=recipe==='callback' ? 'CreateCallback' : 'CreateRepair';
    const type=recipe==='callback' ? 'CALLBACK' : 'REPAIR';
    const selection=recipe!=='callback' && recipe!=='manual-phone' ? p.offerIds[recipe] : undefined;
    const status=recipe==='callback' ? 'CALLBACK_REQUIRED' : recipe==='manual-phone' ? 'NEW'
      : recipe==='TG' ? 'WAITING_TELEGRAM_LINK' : 'WAITING_CHANNEL_LINK';
    const person=form ?? actor;
    if (person==='F') { throw new Error('No form session'); }
    let path='/requests', body:unknown;
    if (form) {
      if (recipe==='manual-phone') { throw new Error('No PHONE repair creation through F'); }
      path=recipe==='callback' ? '/public/callback-requests' : '/public/repair-requests';
      const consent={evidenceId:await p.given(form),documentVersionId:fixture.consentDocumentVersionId,accepted:true};
      body=recipe==='callback' ? {contact,consent,phonePermission:true,callbackIntervalId:fixture.callbackIntervalEntryId}
        : {...detail,contact,consent,channelSelection:selection};
    } else {
      const input=decodeP05ManualRequest({type,sourceEntryId:fixture.formSourceEntryId,evidenceId:randomUUID(),
        contact:selection ? {...contact,mode:'CHANNEL',channelSelection:selection} : phoneContact(),
        ...(type==='REPAIR' ? detail : {})});
      const binding=canonicalJson({cityId:fixture.cityId,cityVersionId:fixture.cityVersionId,sourceVersionId:sourceVersion,operation:name,key});
      mint(input.evidenceId,'MANUAL_INTAKE',principal.id,binding,input);
      if (input.contact.mode==='PHONE') { mint(input.contact.phoneEvidenceId,'PHONE_GIVE',principal.id,binding,input); }
      body=input;
    }
    const label=`create/${principal.kind}/${recipe}`;
    const keys=form ? fView : staffReceipt;
    const apply=() => send('POST',path,body,headers(person,key));
    const snapshot=await inventory();
    const first=closed(await apply(),201,keys,label);
    expect(first.headers.etag,label).toBeUndefined();
    const id=text(form ? (await lab.db.query<{id:string}>(`SELECT id FROM foundation.requests WHERE public_number=$1`,
      [first.data()['publicNumber']])).rows[0] ?? {} : first.data(),'id');
    const target={id,path:`/requests/${id}`,form};
    const created=await p.capture(id);
    expect(created.row,label).toMatchObject({id,type,status,row_version:1,city_id:fixture.cityId,intake_city_version_id:fixture.cityVersionId});
    const extra=['customer','intake','contact','preference','payload',...(type==='REPAIR' ? ['address','appliance','fault','payload','payload'] : []),
      ...(selection ? ['channel'] : ['phone']),...(form ? ['submit'] : selection ? ['staffEvidence'] : ['staffEvidence','staffEvidence'])];
    const added=appendOnly([],created.history,['event','receipt','audit','outbox',...extra],label);
    const event=verifyCommon(added,id,status,1,key,name,principal,label);
    if (form) { expect(added('submit'),label).toMatchObject({session_id:form.sid,request_id:id,event_id:event['id']}); }
    if (selection) { expect(added('channel'),label).toMatchObject({provider:selection.provider,catalog_version_id:selection.catalogVersionId,
      option_version_id:selection.optionVersionId}); }
    expect(currentPermit(created)!==null,label).toBe(!selection);
    expect(first.data(),label).toEqual({...(form ? {} : {id}),publicNumber:created.row.public_number,status,version:1});
    expect(closed(await apply(),200,keys,`${label}/replay`).bytes,label).toBe(first.bytes);
    expect(await p.capture(id),label).toEqual(created);
    const after=await inventory();
    expect(after,label).toMatchObject({requests:String(Number(snapshot?.['requests'])+1),customers:String(Number(snapshot?.['customers'])+1),
      events:String(Number(snapshot?.['events'])+1),receipts:String(Number(snapshot?.['receipts'])+1)});
    return target;
  };

  function commandInput(target:Target,s:Snapshot,cmd:MatrixCommand,actor:Principal,etag:string):unknown {
    switch (cmd) {
      case 'ConvertCallback': return detail;
      case 'ChangeDetails': return {section:'PREFERENCE',urgency:'URGENT'};
      case 'RecordCoverageAssessment': {
        const evidenceId=randomUUID();
        if (s.row.current_address_revision_id) { p.setReview({evidenceId,issuer:'T',purpose:'COVERAGE_REVIEW',staffId:actor.id,
          requestId:target.id,addressRevisionId:s.row.current_address_revision_id,candidate:detail.address,expiresAt:new Date(Date.now()+300000)}); }
        return {evidenceId,outcome:'IN_ZONE',areaId:fixture.areaId};
      }
      case 'ChangeContact':
      case 'WithdrawPhonePermission': {
        if (actor.kind==='F') { return {action:'REVOKED'}; }
        const evidenceId=randomUUID();
        const body=cmd==='ChangeContact' ? {evidenceId,contact:{...contact,name:'F matrix secret replacement'}} : {evidenceId};
        mint(evidenceId,cmd==='ChangeContact' ? 'CONTACT_CHANGE' : 'PHONE_WITHDRAW',actor.id,
          canonicalJson({requestId:target.id,contactRevisionId:s.row.current_contact_revision_id,
            permit:cmd==='ChangeContact' ? null : currentPermit(s),version:s.row.row_version,ifMatch:etag}),body);
        return body;
      }
      case 'CancelRequest': return cancel;
      case 'ChooseCallback': return {phonePermission:true};
      default: return {};
    }
  }
  function prepared(target:Target,s:Snapshot,cmd:MatrixCommand,actor:StaffProof|Form,etag:string) {
    const principal:Principal='sid' in actor ? {kind:'F',id:actor.sid} : {kind:'STAFF',id:actor.id};
    const url=principal.kind==='F' ? `${fPath}/${formCommands[cmd as FormCommand]}` : `${target.path}/commands/${staffCommands[cmd as StaffCommand]}`;
    const key=randomUUID(), body=commandInput(target,s,cmd,principal,etag);
    return {principal,url,key,body,apply:() => send('POST',url,body,headers(actor,key,etag))};
  }
  async function applyMutation(target:Target,before:Snapshot,cmd:MatrixCommand,actor:StaffProof|Form,etag:string,decision:Mutation,label:string) {
    const {principal,key,apply}=prepared(target,before,cmd,actor,etag);
    const keys=closingCommands.has(cmd) ? ['applied','version'] : principal.kind==='F' ? fView : staffReceipt;
    const reply=closed(await apply(),200,keys,label);
    expect(reply.headers.etag,label).toBeUndefined();
    const after=await p.capture(target.id);
    const version=before.row.row_version+1;
    const patch:Record<string,unknown>={...before.row,row_version:version,type:decision.type,status:decision.status};
    for (const pointer of decision.pointers) {
      const field=changedPointers[pointer];
      expect(after.row[field],label).toEqual(expect.any(String));
      expect(after.row[field],label).not.toBe(before.row[field]);
      patch[field]=after.row[field];
    }
    expect(after.row,label).toEqual(patch);
    const added=appendOnly(before.history,after.history,['event','receipt','audit','outbox',...decision.extraRows],label);
    const event=verifyCommon(added,target.id,decision.status,version,key,cmd,principal,label,cmd==='CancelRequest'
      ? {...cancel,reasonVersionId:cancelVersion} : {});
    for (const pointer of decision.pointers) {
      expect(added(pointer),label).toMatchObject({id:after.row[changedPointers[pointer]],request_id:target.id});
    }
    if (cmd==='RecordCoverageAssessment') { expect(added('assessment'),label).toMatchObject({event_id:event['id'],outcome:'IN_ZONE',area_id:fixture.areaId,
      staff_id:principal.id,address_revision_id:before.row.current_address_revision_id,attempt_correlation_id:added('addressReview')['correlation_id']}); }
    if (cmd==='WithdrawPhonePermission' || cmd==='ChooseCallback') { expect(added('phone'),label).toMatchObject({
      request_id:target.id,contact_revision_id:before.row.current_contact_revision_id,
      action:cmd==='ChooseCallback' ? 'GIVEN' : 'REVOKED',supersedes_given_id:cmd==='ChooseCallback' ? null : currentPermit(before),
    }); }
    if (cmd==='ChangeContact' || cmd==='WithdrawPhonePermission') { expect(currentPermit(after),label).toBeNull(); }
    const expected=closingCommands.has(cmd) ? {applied:true,version}
      : {...(principal.kind==='F' ? {} : {id:target.id}),publicNumber:before.row.public_number,status:decision.status,version};
    expect(reply.data(),label).toEqual(expected);
    expect(closed(await apply(),200,keys,`${label}/exact replay`).bytes,label).toBe(reply.bytes);
    expect(await p.capture(target.id),`${label}/replay snapshot`).toEqual(after);
    return {after,apply};
  }

  const prep: Readonly<Record<Preparation,MatrixCommand>>={review:'StartReview',convert:'ConvertCallback',assess:'RecordCoverageAssessment',
    ready:'ReadyForDispatch',choose:'ChooseCallback',cancel:'CancelRequest','change-contact':'ChangeContact'};
  const build=async (w:Witness,admin:StaffProof) => {
    const target=await create(w.recipe,w.origin==='F' ? 'F' : admin);
    for (const step of w.via) {
      const cmd=prep[step];
      const actor=(step==='choose' || step==='cancel') && target.form ? target.form : admin;
      const tag=(await view(target,actor,`prepare ${w.label}`)).etag;
      const before=await p.capture(target.id);
      const request=prepared(target,before,cmd,actor,tag);
      closed(await request.apply(),200,closingCommands.has(cmd) ? ['applied','version'] : 'sid' in actor ? fView : staffReceipt,`prepare ${w.label}/${step}`);
    }
    const initial=await p.capture(target.id);
    expect(initial.row,`lawful witness ${w.label}`).toMatchObject({type:w.type,status:w.status});
    expect(currentPermit(initial)!==null,`live PHONE ${w.label}`).toBe(w.phone);
    if (w.coverage) { expect(initial.row.current_assessment_id,w.label).toEqual(expect.any(String)); }
    return {target,initial};
  };

  return await withHttpMatrixActors(lab,fixture.cityId,async actors=>{
    p.progress('actors-ready',0);
    // First walk the actual state/command cross-product under GLOBAL authority
    // and own F. Stable negatives share one subject; every mutating cell gets
    // a fresh subject, never an SQL rewind or an invented fixture state.
    let observed=0;
    const slice=/^witnesses-([0-2])$/.exec(p.phase)?.[1];
    if (slice!==undefined) {
      // The oracle fixes exactly 18 witnesses; a slice is the stable 6-witness window.
      expect(witnesses).toHaveLength(18);
      const window=witnesses.slice(Number(slice)*6,Number(slice)*6+6);
      for (const w of window) {
        const {target,initial}=await build(w,actors.global);
        const staffTag=(await view(target,actors.global,w.label)).etag;
        const formTag=target.form ? (await view(target,target.form,w.label)).etag : undefined;
        const denialInventory=await inventory();
        const positives: {kind:MatrixActor; cmd:MatrixCommand; decision:Mutation; label:string}[]=[];
        for (const actor of [actors.global,...(target.form ? [target.form] : [])]) {
          const kind='sid' in actor ? 'F' : 'STAFF';
          for (const cmd of kind==='F' ? byForm : byStaff) {
            const label=`GLOBAL/own F/${w.label}/${kind}/${cmd}`;
            const decision=expectedMutation(w,kind,cmd);
            if ('http' in decision) {
              const stamp=kind==='F' ? formTag ?? '' : staffTag;
              deny(await prepared(target,initial,cmd,actor,stamp).apply(),decision.http,decision.code,label);
            } else { positives.push({kind,cmd,decision,label}); }
            observed++;
          }
        }
        expect(await inventory(),`denials have no business/audit/outbox side effects for ${w.label}`).toEqual(denialInventory);
        expect(await p.capture(target.id),`denials preserve ${w.label}`).toEqual(initial);
        for (const [index,{kind,cmd,decision,label}] of positives.entries()) {
          const fresh=index===0 ? {target,initial} : await build(w,actors.global);
          const owner=kind==='F' ? fresh.target.form : actors.global;
          if (!owner) { throw new Error(`No original form: ${label}`); }
          const etag=index===0 ? kind==='F' ? formTag ?? '' : staffTag : (await view(fresh.target,owner,label)).etag;
          await applyMutation(fresh.target,fresh.initial,cmd,owner,etag,decision,label);
        }
        p.progress('workflow-witness-complete',observed);
      }
      // Per-window cell count from the oracle itself: F-originated witnesses add
      // their three form commands to the eight staff commands.
      expect(observed).toBe(window.reduce((sum,w)=>sum+8+(w.origin==='F' ? 3 : 0),0));
      expect(await lab.count(`SELECT count(*)::int n FROM foundation.requests WHERE status=ANY($1::text[])`,[futureStates])).toBe(0);
      return observed;
    }
    const cityPhase=/^city-(admin|manager|custom)-([0-2])$/.exec(p.phase);
    if (cityPhase) {
      const role=cityPhase[1];
      const slice=Number(cityPhase[2]);
      const actor=role==='admin' ? actors.cityAdmin : role==='manager' ? actors.manager : actors.custom;
      // A SYSTEM ADMIN's grants are role-wide. Convert the reviewed ADMIN rows
      // to CITY for this entire phase; build and mutating requests are issued by
      // that same assigned CITY admin, so no unassigned GLOBAL principal is
      // accidentally used to create the witness or its replay targets.
      if (role==='admin') { await actors.setAdminScope('CITY'); }
      const builder=role==='admin' ? actors.cityAdmin : actors.global;
      const window=witnesses.slice(slice*6,slice*6+6);
      expect(window).toHaveLength(6);
      for (const w of window) {
        const {target,initial}=await build(w,builder);
        const labelPrefix=`${role.toUpperCase()} CITY/${w.label}`;
        const cityTag=(await view(target,actor,`${labelPrefix}/GET`)).etag;
        const denialInventory=await inventory();
        // All state-inapplicable commands are executed on the same untouched
        // target under the real CITY principal. Each refusal must preserve its
        // request snapshot and every durable/audit/outbox inventory counter.
        for (const cmd of byStaff) {
          const decision=expectedMutation(w,'STAFF',cmd);
          if (!('http' in decision)) { continue; }
          const label=`${labelPrefix}/${cmd}/expected-${decision.code}`;
          const request=prepared(target,initial,cmd,actor,cityTag);
          deny(await request.apply(),decision.http,decision.code,label);
          observed++;
        }
        expect(await inventory(),`${labelPrefix}/refusals have no effects`).toEqual(denialInventory);
        expect(await p.capture(target.id),`${labelPrefix}/refusals preserve state`).toEqual(initial);

        // Every executable cell gets a fresh lawful witness. This avoids SQL
        // rewinds and prevents one successful command from changing the state
        // tested by the next command. The independent oracle decides the exact
        // success effect; the actual HTTP request is authenticated as this CITY role.
        for (const cmd of byStaff) {
          const decision=expectedMutation(w,'STAFF',cmd);
          if ('http' in decision) { continue; }
          const fresh=await build(w,builder);
          const label=`${labelPrefix}/${cmd}/allowed`;
          const etag=(await view(fresh.target,actor,label)).etag;
          await applyMutation(fresh.target,fresh.initial,cmd,actor,etag,decision,label);
          observed++;
        }
        p.progress(`${role}-city-witness-complete`,observed);
      }
      expect(observed).toBe(window.length*byStaff.length);
      return observed;
    }

    if (p.phase==='roles') {
      // Repeat each operation and distinct create shape under the three other
      // authorized grant shapes. The state axis above is independent of RBAC;
      // permission denials below use the real command DTO on an authorized target.
      for (const [scope,actor] of [['ADMIN GLOBAL',actors.global],['ADMIN CITY',actors.cityAdmin],
        ['MANAGER CITY',actors.manager],['CUSTOM CITY',actors.custom]] as const) {
        if (scope==='ADMIN CITY') { await actors.setAdminScope('CITY'); }
        for (const recipe of ['callback','manual-phone','TG','VK','MAX'] as const) { await create(recipe,actor); }
        if (scope!=='ADMIN GLOBAL') {
          const permitProofs = [
            ['manual NEW','StartReview'],['form CALLBACK_REQUIRED','ConvertCallback'],['form REPAIR in review, assessed','ChangeDetails'],
            ['form REPAIR in review, no assessment','RecordCoverageAssessment'],['form CALLBACK in review','ChangeContact'],
            ['manual REPAIR in review, assessed','ReadyForDispatch'],['manual CANCELLED','WithdrawPhonePermission'],
            ['manual WAITING_ASSIGNMENT','CancelRequest'],
          ] as const;
          for (const [name,cmd] of permitProofs) {
            const w=witnesses.find(item=>item.label===name);
            if (!w) { throw new Error(`Missing witness ${name}`); }
            const {target,initial}=await build(w,actors.cityAdmin);
            const decision=expectedMutation(w,'STAFF',cmd);
            if ('http' in decision) { throw new Error(`Non-executable role witness ${name}/${cmd}`); }
            const label=`${scope}/${name}/${cmd}`;
            await applyMutation(target,initial,cmd,actor,(await view(target,actor,label)).etag,decision,label);
          }
        }
        observed+=scope==='ADMIN GLOBAL' ? 5 : 13; // Five create combinations; eight extra existing-request operations for CITY roles.
        p.progress('staff-role-group-complete',observed);
      }
      for (const recipe of ['callback','TG','VK','MAX'] as const) { await create(recipe,'F'); }
      observed+=4;
      p.progress('create-forms-complete',observed);
      return observed;
    }

    const t=await create('callback','F');
    if (!t.form) { throw new Error('Missing original form'); }
    // Same precondition the unsplit walk had after its role phase: SYSTEM ADMIN
    // holds CITY-scoped grants, so an admin without this city's assignment must
    // not see the target. Stated explicitly; not inherited from another case.
    await actors.setAdminScope('CITY');
    const freshForm=await p.issue();
    const missing=`/requests/${randomUUID()}`;
    const snapshot=await p.capture(t.id);
    const {etag}=await view(t,actors.cityAdmin,'scope control');
    const otherTag=(await view(t,t.form,'original F')).etag;
    const baseline=await inventory();
    p.progress('scope-and-proof-denials-start',observed);
    const attemptAs=async (command:StaffCommand,proof:Record<string,string>,status:number,code:string,label:string) => {
      const body=commandInput(t,snapshot,command,{kind:'STAFF',id:actors.cityAdmin.id},etag);
      deny(await send('POST',`${t.path}/commands/${staffCommands[command]}`,body,proof),status,code,label);
    };
    for (const [name,actor] of [['MANAGER wrong CITY',actors.wrong],['CUSTOM no CITY',actors.noCity],
      ['ADMIN CITY without target assignment',actors.global]] as const) {
      for (const path of [t.path,missing]) {
        deny(await send('GET',path,undefined,{...headers(actor),'If-None-Match':etag}),404,'NOT_FOUND',name);
        for (const cmd of byStaff) {
          deny(await send('POST',`${path}/commands/${staffCommands[cmd]}`,commandInput(t,snapshot,cmd,{kind:'STAFF',id:actor.id},etag),
            headers(actor,randomUUID(),etag)),404,'NOT_FOUND',`${name}/${cmd}`);
        }
      }
      deny(await send('POST','/requests',{type:'CALLBACK',contact},headers(actor,randomUUID())),404,'NOT_FOUND',`${name}/create`);
    }
    await actors.setAdminScope('MIXED');
    expect((await view(t,actors.global,'GLOBAL read only at this city')).etag).toBe(etag);
    for (const cmd of byStaff) { await attemptAs(cmd,headers(actors.global,randomUUID(),etag),404,'NOT_FOUND',`GLOBAL read plus CITY action/${cmd}`); }
    await actors.setAdminScope('CITY');
    expect((await view(t,actors.reader,'read only at matching city')).etag).toBe(etag);
    deny(await send('GET',t.path,undefined,headers(actors.actionOnly)),403,'FORBIDDEN','action-only GET');
    for (const actor of [actors.reader,actors.actionOnly]) {
      for (const cmd of byStaff) { await attemptAs(cmd,headers(actor,randomUUID(),etag),403,'FORBIDDEN',`independent read/action/${cmd}`); }
      deny(await send('POST','/requests',{type:'CALLBACK',contact},headers(actor,randomUUID())),403,'FORBIDDEN','independent read/action create');
    }
    const techCookie={id:'',token:actors.technicianToken,cookie:`__Host-fixlevelup_session=${actors.technicianToken}`};
    for (const [label,proof] of [['guest',{}],['technician TG bearer',{Authorization:`Bearer ${actors.technicianToken}`}],
      ['technician TG cookie',headers(techCookie)],['F cookie',{Cookie:t.form.cookie}]] as const) {
      const tokenProof=label==='technician TG cookie' ? headers(techCookie,randomUUID(),etag)
        : {...proof,'Idempotency-Key':randomUUID(),'If-Match':etag};
      deny(await send('GET',t.path,undefined,{...proof,'If-None-Match':etag}),401,'UNAUTHORIZED',label);
      for (const cmd of byStaff) { await attemptAs(cmd,tokenProof,401,'UNAUTHORIZED',`${label}/${cmd}`); }
      const createProof: Record<string,string>={...tokenProof};
      delete createProof['If-Match'];
      deny(await send('POST','/requests',{type:'CALLBACK',contact},createProof),401,'UNAUTHORIZED',`${label}/create`);
    }
    deny(await send('GET',fPath,undefined,{...headers(freshForm),'If-None-Match':otherTag}),404,'NOT_FOUND','unsubmitted F');
    deny(await send('GET',fPath,undefined,{...headers(actors.cityAdmin),'If-None-Match':otherTag}),401,'UNAUTHORIZED','staff is not F');
    for (const cmd of byForm) {
      const body=commandInput(t,snapshot,cmd,{kind:'F',id:t.form.sid},otherTag);
      const path=`${fPath}/${formCommands[cmd]}`;
      deny(await send('POST',path,body,headers(freshForm,randomUUID(),otherTag)),404,'NOT_FOUND',`unsubmitted F/${cmd}`);
      deny(await send('POST',path,body,headers(actors.cityAdmin,randomUUID(),otherTag)),401,'UNAUTHORIZED',`staff is not F/${cmd}`);
    }
    for (const cmd of noP05CommandRoutes) {
      deny(await send('POST',`${t.path}/commands/${cmd}`,{},headers(actors.cityAdmin,randomUUID(),etag)),404,'NOT_FOUND',`unmapped ${cmd}`);
    }
    // Three sets of (2 targets × (GET + 8 writes) + create), 8 mixed-scope
    // writes, 1 GET + 18 exact-code writes, 4 × (GET + 8 writes + create),
    // two F proof variants × (GET + 3 writes), and unmapped route probes.
    observed+=3*19+8+19+4*10+8+noP05CommandRoutes.length;
    expect(await inventory(),'authorization denials preserve domain, audit and outbox counts').toEqual(baseline);
    expect(await p.capture(t.id),'authorization denials preserve immutable history and current pointers').toEqual(snapshot);
    const w=witnesses.find(item=>item.label==='form CALLBACK_REQUIRED');
    if (!w) { throw new Error('Missing replay source'); }
    const decision=expectedMutation(w,'STAFF','StartReview');
    if ('http' in decision) { throw new Error('Missing executable replay control'); }
    const success=await applyMutation(t,snapshot,'StartReview',actors.cityAdmin,etag,decision,'same-city control');
    await actors.revokeCity(actors.cityAdmin);
    deny(await success.apply(),404,'NOT_FOUND','same receipt after CITY revocation');
    expect(await p.capture(t.id)).toEqual(success.after);
    p.progress('scope-and-proof-denials-complete',observed+2);
    return observed+2;
  });
}
