import { execFileSync } from 'node:child_process';
import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { request } from 'node:https';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { Client } from 'pg';
import supertest from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { decodeP05ManualRequest } from '@fixlevelup/p03-contracts/p05';
import { P05_CAPABILITIES } from '../src/authz/capability.js';
import { lockAccessPolicy } from '../src/authz/rbac-lock.js';
import { hashPassword } from '../src/staff/password.js';
import { acquireCompanySettingsLock } from '../src/settings/configuration/company-lock.js';
import { canonicalJson } from '../src/infrastructure/admission/proof.js';
import { loadKeyring } from '../src/requests/crypto/keyring.js';
import type { KeyringConfig } from '../src/requests/crypto/keyring.js';
import { checkedReceipt, writeEffect } from '../src/requests/intake/effects.js';
import { clonePhonePreference, requestRow, updateRequestRow, writeContact, writePhone, writePreference } from '../src/requests/intake/store.js';
import { requestEffectsHistoryComplete } from '../src/infrastructure/database/request-phone-history.js';
import type { RequestOffers, StaffEvidence, StaffEvidencePort } from '../src/requests/intake/basis.js';
import { coverageEffects } from '../src/requests/intake/coverage-effects.js';
import type { CoverageReviewEvidence } from '../src/requests/intake/coverage.js';
import { fixtureCredentials } from './owned-test-database.js';
import { RbacFixture, record, text } from './rbac-fixture.js';
import { policyPairKey } from '../src/requests/workflow/registry.js';
import { REQUEST_POLICY_METADATA_SHA256, seedPolicyPackage, seedRequestFixtures, supportedFixturePolicies } from './p05-request-fixtures.js';
import type { PolicyPackage, RequestFixtures } from './p05-request-fixtures.js';
import { RequestOfferFixture } from './p05-offer-fixture.js';
import { startIsolatedIntake } from './p05-composition.js';
import { provePartialWire } from './p05-partial-wire-proof.js';
import { proveHttpMatrix } from './p05-http-matrix-proof.js';
import { noP05CommandRoutes, witnesses } from './p05-http-matrix-oracle.js';
import { createSyntheticKeySlots } from './p05-key-slot-fixture.js';

const origin = 'https://crm.example.test';
const enabled = process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1'
  && process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1';
const contact = Object.freeze({ name:'Synthetic intake sentinel',phone:'+15550100001' });
const address = Object.freeze({ street:'Synthetic comparison sentinel',building:'12' });
const pub = '/public';

interface Reply {
  readonly status: number;
  readonly bytes: string;
  readonly headers: import('node:http').IncomingHttpHeaders;
  data(): Record<string,unknown>;
}
interface BrowserForm { readonly sid: string; readonly csrf: string; readonly cookie: string }

describe.runIf(enabled)('P05 isolated T, real HTTPS and PostgreSQL S3', () => {
  let base: RbacFixture | undefined;
  let fixture: RequestFixtures;
  let testApp: Awaited<ReturnType<typeof startIsolatedIntake>> | undefined;
  let cert: Buffer;
  let port: number;
  let offers: RequestOfferFixture;
  let historical: PolicyPackage;
  let keyring: KeyringConfig;
  let managed: Awaited<ReturnType<typeof createSyntheticKeySlots>> | undefined;
  let launchWithPolicy: (id: string, pins?: ReadonlyMap<string,string>, anchorTtlMs?: number,
    matrixOffers?: RequestOffers) => ReturnType<typeof startIsolatedIntake>;
  const historicalDigest = '3799c7e532579641d010675a229541c998f4d02bf85c3156fe167f79d33631cf';
  const evidence = new Map<string, NonNullable<Awaited<ReturnType<StaffEvidencePort['verify']>>> & Parameters<StaffEvidencePort['verify']>[1]>();
  const review = new Map<string,CoverageReviewEvidence>();
  const evidenceClockHooks = new Map<string,(client: import('pg').PoolClient, proof: StaffEvidence) => Promise<void>>();
  const evidencePort: StaffEvidencePort = {
    async verify(_client, expected) {
      await Promise.resolve();
      const verified = evidence.get(expected.id);
      return verified?.purpose === expected.purpose && verified.staffId === expected.staffId && verified.target === expected.target
        && verified.canonicalIntent === expected.canonicalIntent ? verified : undefined;
    },
    async isCurrent(client, proof) {
      await evidenceClockHooks.get(proof.id)?.(client,proof);
      return evidence.get(proof.id)?.procedureRevision === proof.procedureRevision;
    },
  };
  function db() { if (!base) { throw new Error('Missing fixture'); } return base; }

  beforeAll(async () => {
    const lab = new RbacFixture({p04:true});
    base = lab;
    await lab.start();
    fixture = await seedRequestFixtures(lab,{ reviewerId:lab.admin.id });
    historical = await seedPolicyPackage(lab,{ workflowVersion:fixture.workflowVersion });
    expect(fixture.policyMetadataSha256).toBe(REQUEST_POLICY_METADATA_SHA256);
    expect(historical.metadataSha256).toBe(historicalDigest);
    offers = await RequestOfferFixture.attach(lab,{provider:'TG'});
    await lab.db.query(`INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
      SELECT r.id,c,'GLOBAL' FROM foundation.roles r CROSS JOIN unnest($1::text[]) c WHERE r.role_type='SYSTEM' AND r.code='ADMIN'`, [P05_CAPABILITIES]);
    const dir = mkdtempSync(resolve(tmpdir(),'p05-intake-tls-'));
    let key: Buffer;
    try {
      const pem = resolve(dir,'server.pem');
      const privateKey = resolve(dir,'server.key');
      const openssl = existsSync('C:\\Program Files\\Git\\usr\\bin\\openssl.exe') ? 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe' : 'openssl';
      execFileSync(openssl,['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
        '-addext','subjectAltName=IP:127.0.0.1,DNS:localhost','-keyout',privateKey,'-out',pem],{stdio:'ignore',timeout:10000});
      cert = readFileSync(pem);
      key = readFileSync(privateKey);
    } finally { rmSync(dir,{recursive:true,force:true}); }
    keyring = loadKeyring({ activeKekId:'test-kek-1',activeHmacKeyId:'test-hmac-1',
      kek:[{keyId:'test-kek-1',secretHex:randomBytes(32).toString('hex')}],
      hmac:[{keyId:'test-hmac-1',secretHex:randomBytes(32).toString('hex')}] });
    const keys=await createSyntheticKeySlots('p05-isolated');
    managed=keys;
    const supportedPolicies = new Map(supportedFixturePolicies());
    supportedPolicies.set(policyPairKey(historical.workflowVersion,historical.policyRevision),historicalDigest);
    const csrf = randomBytes(32).toString('hex');
    // Every T instance uses the same exact admitted database and staff proof;
    // package and short-TTL settings are explicit synthetic inputs.
    launchWithPolicy = async (id, pins = supportedPolicies, anchorTtlMs = 600000, matrixOffers) => {
      const settings = { ring:keyring,keySlots:keys.slots,environment:'p05-isolated',currentPolicyId:id,
        supportedPolicies:pins,formSourceEntryId:fixture.formSourceEntryId };
      const matrix = matrixOffers !== undefined;
      return await startIsolatedIntake({ target:{ host:'127.0.0.1',port:55432,database:lab.database,user:'fixlevelup_runtime',password:fixtureCredentials().runtime },
        authorization:lab.admitted.authorization,tls:{key,cert},staff:{origin,csrfSecret:csrf},
        form:{ origin,csrfKeyring:{current:{keyId:'csrf-t1',secret:randomBytes(32)}},throttleSecret:randomBytes(32),
          groupTtlMs:matrix ? 1800000 : 900000,anchorTtlMs,csrfTtlMs:matrix ? anchorTtlMs : Math.min(300000,anchorTtlMs),
          throttles:{ source:{windowSeconds:600,maxHits:matrix ? 3000 : 300},global:{windowSeconds:600,maxHits:matrix ? 3000 : 300},
            anchor:{windowSeconds:600,maxHits:60} } },
        configure:audit=>({...settings,offers:matrixOffers ?? offers,staffEvidence:evidencePort,coverage:coverageEffects(settings,audit,{
          async verify(input) { return await Promise.resolve(review.get(input.evidenceId)); },
        },64)}),
      });
    };
    testApp = await launchWithPolicy(fixture.policyId);
    port = portOf(testApp);
    staffCsrf = csrf;
  },90000);

  let staffCsrf: string;
  afterAll(async () => {
    try { await testApp?.app.close(); }
    finally { try { await managed?.close(); } finally { await base?.close(); } }
  },20000);

  function portOf(instance: Awaited<ReturnType<typeof startIsolatedIntake>>): number {
    const server = instance.app.getHttpServer() as import('node:https').Server;
    const bind = server.address();
    if (!bind || typeof bind === 'string' || bind.address !== '127.0.0.1') { throw new Error('Missing isolated TLS server'); }
    return bind.port;
  }

  function https(method: 'GET'|'POST',path: string,payload?: unknown,headers: Record<string,string> = {}, targetPort = port): Promise<Reply> {
    return new Promise((ok,fail) => {
      const body = payload === undefined ? undefined : JSON.stringify(payload);
      const req = request({ method,host:'127.0.0.1',port:targetPort,path:`/api/v1${path}`,ca:cert,agent:false,
        headers:{ Origin:origin,...(body === undefined ? {} : {'Content-Type':'application/json','Content-Length':String(Buffer.byteLength(body))}),...headers },
      },res=>{
        const chunks: Buffer[]=[];
        res.on('data',(chunk: Buffer)=>chunks.push(chunk));
        res.once('error',fail);
        res.once('end',()=>{
          const bytes=Buffer.concat(chunks).toString('utf8');
          ok({status:res.statusCode ?? 0,bytes,headers:res.headers,data:()=>record(record(JSON.parse(bytes) as unknown)['data'])});
        });
      });
      req.setTimeout(15000,()=>req.destroy(new Error('Isolated HTTPS deadline')));
      req.once('error',fail);
      req.end(body);
    });
  }
  function accepted(reply: Reply,status: number) {
    expect(reply.status,reply.status >= 400 ? reply.bytes : 'status').toBe(status);
    expect(reply.headers['cache-control']).toMatch(/^no-store/);
    expect(reply.bytes).not.toContain('sentinel');
    expect(reply.bytes).not.toContain(contact.phone);
    return reply;
  }
  const failure = (reply: Reply,status:number,code:string) => {
    accepted(reply,status);
    expect(record(JSON.parse(reply.bytes) as unknown)['code']).toBe(code);
  };
  function browser(reply: Reply): string {
    const first = reply.headers['set-cookie']?.[0];
    expect(first).toMatch(/; Path=\/; Secure; HttpOnly; SameSite=Strict;/);
    if (first === undefined) { throw new Error('Missing isolated cookie'); }
    return first.split(';')[0] ?? '';
  }
  function tag(reply: Reply): string {
    const value = reply.headers.etag;
    if (typeof value !== 'string') { throw new Error('Missing strong ETag'); }
    expect(value).toMatch(/^"p05-r1-[a-f0-9]{64}"$/);
    return value;
  }
  async function issue(targetPort = port): Promise<BrowserForm> {
    const group = browser(accepted(await https('POST',`${pub}/form-session/browser`,{},{'X-Form-Session-Bootstrap':'1'},targetPort),200));
    const created = accepted(await https('POST',`${pub}/form-sessions`,{},{Cookie:group},targetPort),201);
    return { sid:text(created.data(),'sessionId'),csrf:text(created.data(),'csrfToken'),cookie:browser(created) };
  }
  const proof = (form: BrowserForm) => ({Cookie:form.cookie,'X-Form-Session-Id':form.sid});
  const mutate = (form: BrowserForm,key=randomUUID(),ifMatch?:string) => ({...proof(form),'X-CSRF-Token':form.csrf,'Idempotency-Key':key,
    ...(ifMatch === undefined ? {} : {'If-Match':ifMatch})});
  async function given(form: BrowserForm,targetPort = port): Promise<string> {
    const key=randomUUID();
    return text(accepted(await https('POST',`${pub}/form-session/consents`,{action:'GIVEN',documentId:fixture.consentDocumentId,
      documentVersionId:fixture.consentDocumentVersionId,evidenceRef:key},mutate(form,key),targetPort),201).data(),'evidenceId');
  }
  const staff = () => ({Cookie:db().admin.cookie});
  function staffMutation(key=randomUUID(),ifMatch?:string) {
    const csrfToken=createHmac('sha256',staffCsrf).update('web-auth-csrf\0').update(db().admin.token).digest('base64url');
    return {...staff(),'X-CSRF-Token':csrfToken,'Idempotency-Key':key,...(ifMatch === undefined ? {} : {'If-Match':ifMatch})};
  }

  function mintEvidence(id: string, purpose: Parameters<StaffEvidencePort['verify']>[1]['purpose'], target: string, body: unknown) {
    evidence.set(id,{id,purpose,staffId:db().admin.id,target,canonicalIntent:canonicalJson(body),procedureRevision:'fixture-v1',
      validUntil:new Date(Date.now()+300000)});
  }

  async function manualPrepared() {
    const source=(await db().db.query<{version:string}>('SELECT current_version_id AS version FROM foundation.reference_entries WHERE id=$1',[fixture.formSourceEntryId])).rows[0];
    if (!source) { throw new Error('Missing synthetic source'); }
    const key=randomUUID();
    const body=decodeP05ManualRequest({type:'REPAIR',sourceEntryId:fixture.formSourceEntryId,evidenceId:randomUUID(),contact:{...contact,
      mode:'PHONE',phonePermission:true,phoneEvidenceId:randomUUID()},address,appliance:{categoryId:fixture.categoryId},fault:{faultIds:[fixture.faultId]}});
    if (body.type !== 'REPAIR' || body.contact.mode !== 'PHONE') { throw new Error('Wrong test DTO'); }
    const target=canonicalJson({cityId:fixture.cityId,cityVersionId:fixture.cityVersionId,sourceVersionId:source.version,operation:'CreateRepair',key});
    const phoneEvidenceId=body.contact.phoneEvidenceId;
    return { body,key,phoneEvidenceId, authorize: () => {
      mintEvidence(body.evidenceId,'MANUAL_INTAKE',target,body);
      mintEvidence(phoneEvidenceId,'PHONE_GIVE',target,body);
    } };
  }

  function closed(reply: Reply, status: number, keys: readonly string[]) {
    const result=accepted(reply,status);
    expect(Object.keys(record(JSON.parse(result.bytes) as unknown))).toEqual(['data']);
    expect(Object.keys(result.data()).sort()).toEqual([...keys].sort());
    for (const sample of [contact.name,contact.phone,address.street,'F matrix secret']) {
      expect(JSON.stringify([result.bytes,result.headers])).not.toContain(sample);
    }
    if (status !== 200 || result.headers['cache-control'] !== 'no-store, no-transform') {
      expect(result.headers.etag).toBeUndefined();
    }
    return result;
  }
  function closedFailure(reply: Reply,status: number,code: string) {
    failure(reply,status,code);
    expect(reply.headers.etag).toBeUndefined();
    const {requestId,...body}=record(JSON.parse(reply.bytes) as unknown);
    expect(requestId).toEqual(expect.any(String));
    expect(body).toEqual({type:'about:blank',title:code,status,code});
    const wire=JSON.stringify([reply.bytes,reply.headers]);
    for (const sample of [contact.name,contact.phone,address.street,'F matrix secret']) {
      expect(wire.includes(sample)).toBe(false);
    }
  }
  const staffViewKeys=['id','publicNumber','type','status','version'];
  const staffReceiptKeys=['id','publicNumber','status','version'];
  const fReceiptKeys=['publicNumber','status','version'];

  async function prepareCallback(targetPort = port) {
    const form=await issue(targetPort);
    const evidenceId=await given(form,targetPort);
    const key=randomUUID();
    const body={contact,consent:{evidenceId,documentVersionId:fixture.consentDocumentVersionId,accepted:true},
      phonePermission:true,callbackIntervalId:fixture.callbackIntervalEntryId,comment:'F matrix secret callback'};
    return {form,evidenceId,key,body,send: (sendKey=key) => https('POST',`${pub}/callback-requests`,body,mutate(form,sendKey),targetPort)};
  }

  async function captureRequest(id: string, matrix = false) {
    const client=await db().db.connect();
    try {
      const row=await requestRow(client,id,false);
      if (!row) { throw new Error('Missing synthetic request'); }
      // Owner-side passive observations; never alter the business schema, roles or rows.
      const history=await client.query<{kind:string; value:Record<string,unknown>}>(`SELECT 'contact' AS kind,to_jsonb(x) AS value FROM foundation.request_contact_revisions x WHERE request_id=$1
        UNION ALL SELECT 'address',to_jsonb(x) FROM foundation.request_address_revisions x WHERE request_id=$1
        UNION ALL SELECT 'appliance',to_jsonb(x) FROM foundation.request_appliance_revisions x WHERE request_id=$1
        UNION ALL SELECT 'preference',to_jsonb(x) FROM foundation.request_preference_revisions x WHERE request_id=$1
        UNION ALL SELECT 'assessment',to_jsonb(x) FROM foundation.request_coverage_assessments x WHERE request_id=$1
        UNION ALL SELECT 'fault',to_jsonb(x) FROM foundation.request_faults x WHERE request_id=$1
        UNION ALL SELECT 'payload',to_jsonb(x) FROM foundation.request_payload_cells x WHERE request_id=$1
        UNION ALL SELECT 'phone',to_jsonb(x) FROM foundation.phone_permission_events x WHERE request_id=$1
        UNION ALL SELECT 'staffEvidence',to_jsonb(x) FROM foundation.request_staff_evidence x WHERE request_id=$1
        UNION ALL SELECT 'submit',to_jsonb(x) FROM foundation.request_session_submits x WHERE request_id=$1
        UNION ALL SELECT 'event',to_jsonb(x) FROM foundation.request_events x WHERE request_id=$1
        UNION ALL SELECT 'receipt',to_jsonb(x) FROM foundation.request_command_receipts x WHERE request_id=$1
        UNION ALL SELECT 'audit',to_jsonb(x) FROM foundation.audit_logs x WHERE details->>'requestId'=$1::uuid::text
        UNION ALL SELECT 'outbox',to_jsonb(x) FROM foundation.outbox_events x WHERE payload->>'requestId'=$1::uuid::text
        ${matrix ? `UNION ALL SELECT 'customer',to_jsonb(c) FROM foundation.customers c JOIN foundation.requests r ON r.customer_id=c.id WHERE r.id=$1
          UNION ALL SELECT 'intake',to_jsonb(x) FROM foundation.request_intake_provenance x WHERE request_id=$1
          UNION ALL SELECT 'channel',to_jsonb(x) FROM foundation.request_channel_choices x WHERE request_id=$1
          UNION ALL SELECT 'file',to_jsonb(x) FROM foundation.request_files x WHERE request_id=$1
          UNION ALL SELECT 'brand',to_jsonb(x) FROM foundation.request_appliance_brands x WHERE request_id=$1
          UNION ALL SELECT 'addressReview',to_jsonb(x) FROM foundation.request_address_review_attempts x WHERE request_id=$1` : ''}
        ORDER BY kind,value`,[id]);
      return {row,history:history.rows};
    } finally { client.release(); }
  }
  type CapturedRequest=Awaited<ReturnType<typeof captureRequest>>;
  function addedHistory(before: CapturedRequest, after: CapturedRequest, expectedKinds: readonly string[]) {
    for (const row of before.history) { expect(after.history).toContainEqual(row); }
    const added=after.history.filter((item) => !before.history.some((old) => old.kind === item.kind
      && canonicalJson(old.value) === canonicalJson(item.value)));
    expect(added.map(({kind})=>kind).sort()).toEqual([...expectedKinds,'event','receipt','audit','outbox'].sort());
    return (kind: string) => {
      const row=added.find(item=>item.kind === kind);
      if (!row) { throw new Error(`Missing appended ${kind}`); }
      return row.value;
    };
  }
  function staffEffect(before: CapturedRequest,after: CapturedRequest,key: string,command: string,
    patch: Partial<CapturedRequest['row']>, kinds: readonly string[],actorId=db().admin.id) {
    const row=after.row;
    expect(row).toEqual({...before.row,row_version:before.row.row_version+1,...patch});
    const added=addedHistory(before,after,kinds);
    const event=added('event');
    const receipt=added('receipt');
    const audit=added('audit');
    const outbox=added('outbox');
    const info={requestId:row.id,status:row.status,version:row.row_version};
    expect(event).toMatchObject({request_id:row.id,resulting_version:row.row_version,command,operation:command,idempotency_key:key,
      actor_type:'STAFF',actor_staff_id:actorId,actor_session_id:null,details:info});
    expect(receipt).toMatchObject({event_id:event['id'],request_id:row.id,version:row.row_version,resulting_status:row.status,
      correlation_id:event['correlation_id'],command,audit_id:audit['id'],outbox_id:outbox['id']});
    expect(audit).toMatchObject({operation:command,correlation_id:event['correlation_id'],details:{...info,actorId,actorKind:'STAFF'}});
    expect(outbox).toMatchObject({event_id:event['id'],event_type:command === 'ReadyForDispatch' ? 'REQUEST_READY_FOR_ASSIGNMENT' : 'REQUEST_EFFECT_RECORDED',
      payload:{requestId:row.id,version:row.row_version},status:'PENDING',lease_owner:null});
    expect(JSON.stringify([event,receipt,audit,outbox])).not.toMatch(/F matrix secret|Synthetic .*sentinel|15550100001/);
    return added;
  }

  async function readyCandidate() {
    const manual=await manualPrepared();
    manual.authorize();
    const created=accepted(await https('POST','/requests',manual.body,staffMutation(manual.key)),201);
    const id=text(created.data(),'id');
    const path=`/requests/${id}`;
    const initial=accepted(await https('GET',path,undefined,staff()),200);
    accepted(await https('POST',`${path}/commands/start-review`,{},staffMutation(undefined,tag(initial))),200);
    const working=accepted(await https('GET',path,undefined,staff()),200);
    const {rows:[snapshot]}=await db().db.query<{ address_id:string; contact_id:string; permit_id:string }>(`SELECT
      r.current_address_revision_id AS address_id,r.current_contact_revision_id AS contact_id,p.id AS permit_id
      FROM foundation.requests r JOIN foundation.phone_permission_events p ON p.request_id=r.id AND p.action='GIVEN'
      WHERE r.id=$1`,[id]);
    if (!snapshot) { throw new Error('Missing synthetic review target'); }
    const evidenceId=randomUUID();
    review.set(evidenceId,{evidenceId,issuer:'T',purpose:'COVERAGE_REVIEW',staffId:db().admin.id,requestId:id,
      addressRevisionId:snapshot.address_id,candidate:address,expiresAt:new Date(Date.now()+90000)});
    accepted(await https('POST',`${path}/commands/record-coverage`,{evidenceId,outcome:'IN_ZONE',areaId:fixture.areaId},staffMutation(undefined,tag(working))),200);
    const latest=accepted(await https('GET',path,undefined,staff()),200);
    return { id,path,snapshot,latest };
  }

  async function waitForRequestLock(holder: number, waiting: number): Promise<void> {
    const until=performance.now()+3500;
    do {
      // pg_stat_activity.wait_event_type is hidden from the fixture owner for
      // another role's sessions. Wait edges from pg_locks/pg_blocking_pids
      // are visible and the recursive root is this test's exact backend.
      const n=await db().count(`WITH RECURSIVE pending AS (
        SELECT $1::int AS pid UNION SELECT a.pid FROM (SELECT DISTINCT pid FROM pg_locks WHERE NOT granted AND pid IS NOT NULL) a
        JOIN pending p ON p.pid=ANY(pg_blocking_pids(a.pid))
      ) SELECT count(*)::int AS n FROM pending WHERE pid<>$1`,[holder]);
      if (n>=waiting) { return; }
      await delay(20);
    } while (performance.now()<until);
    throw new Error('Expected two observed PostgreSQL lock contenders');
  }

  it('callback is consent-bound, single effect and exact replay; revoke changes both GET validators without changing row_version', async () => {
    const f=await issue();
    const cb=`${pub}/callback-requests`;
    const fGet=`${pub}/request-session`;
    const key=randomUUID();
    const evidenceIdBeforeConsent: string = randomUUID();
    const body = {contact,consent:{evidenceId:evidenceIdBeforeConsent,documentVersionId:fixture.consentDocumentVersionId,accepted:true},
      phonePermission:true,callbackIntervalId:fixture.callbackIntervalEntryId,comment:'Synthetic comment sentinel'};
    failure(await https('POST',cb,body,mutate(f,key)),409,'CONSENT_REQUIRED');
    const evidenceId=await given(f);
    body.consent.evidenceId=evidenceId;
    const [a,b]=await Promise.all([https('POST',cb,body,mutate(f,key)),https('POST',cb,body,mutate(f,key))]);
    expect([a.status,b.status].sort()).toEqual([200,201]);
    expect(a.data()).toEqual(b.data());
    expect(a.headers.etag).toBeUndefined();
    const requestId=text((await db().db.query<{id:string}>(`SELECT id FROM foundation.requests WHERE public_number=$1`,[a.data()['publicNumber']])).rows[0] ?? {},'id');
    const sGet=`/requests/${requestId}`;
    expect(await db().count(`SELECT count(*)::int n FROM foundation.outbox_events WHERE event_type='REQUEST_CALLBACK_INTENT' AND payload->>'requestId'=$1`,[requestId])).toBe(1);
    failure(await https('POST',cb,body,mutate(f)),409,'FORM_ALREADY_SUBMITTED');
    failure(await https('POST',cb,{...body,comment:'Other synthetic input'},mutate(f,key)),409,'IDEMPOTENCY_KEY_REUSED');
    const ownGet=accepted(await https('GET',fGet,undefined,proof(f)),200);
    const repeat=accepted(await https('GET',fGet,undefined,proof(f)),200);
    const staffGet=accepted(await https('GET',sGet,undefined,staff()),200);
    expect(ownGet.bytes).toBe(repeat.bytes);
    expect(ownGet.headers['x-request-id']).not.toBe(repeat.headers['x-request-id']);
    expect(tag(ownGet)).toBe(tag(repeat));
    expect(tag(ownGet)).not.toBe(tag(staffGet));
    expect(accepted(await https('GET',fGet,undefined,{...proof(f),'If-None-Match':tag(ownGet)}),304).bytes).toBe('');
    const withdrawalKey=randomUUID();
    accepted(await https('POST',`${pub}/form-session/consents`,{action:'REVOKED',evidenceRef:withdrawalKey,
      supersedesEvidenceId:evidenceId},mutate(f,withdrawalKey)),201);
    failure(await https('POST',cb,body,mutate(f,key)),409,'CONSENT_REQUIRED');
    failure(await https('POST',cb,body,mutate(f)),409,'CONSENT_REQUIRED');
    const restricted=accepted(await https('GET',fGet,undefined,{...proof(f),'If-None-Match':tag(ownGet)}),200);
    const staffRestricted=accepted(await https('GET',sGet,undefined,{...staff(),'If-None-Match':tag(staffGet)}),200);
    expect(restricted.data()).toEqual({version:1});
    expect(staffRestricted.data()).toEqual({version:1});
    expect(tag(restricted)).not.toBe(tag(ownGet));
    expect(tag(staffRestricted)).not.toBe(tag(staffGet));
    // Reject the old FULL staff validator while row_version is still exactly 1.
    // A different version would not prove that the representation changed.
    const staleStaffKey=randomUUID();
    failure(await https('POST',`${sGet}/commands/cancel`,{reasonEntryId:fixture.cancelReasonEntryId},staffMutation(staleStaffKey,tag(staffGet))),412,'VERSION_MISMATCH');
    expect(await db().count('SELECT count(*)::int n FROM foundation.request_events WHERE idempotency_key=$1',[staleStaffKey])).toBe(0);
    expect(accepted(await https('GET',sGet,undefined,staff()),200).bytes).toBe(staffRestricted.bytes);
    failure(await https('POST',`${pub}/request-session/phone-permissions`,{action:'REVOKED'},mutate(f,undefined,tag(ownGet))),412,'VERSION_MISMATCH');
    const withdraw=accepted(await https('POST',`${pub}/request-session/phone-permissions`,{action:'REVOKED'},mutate(f,undefined,tag(restricted))),200);
    expect(withdraw.data()).toEqual({applied:true,version:2});
    failure(await https('POST',`${sGet}/commands/cancel`,{reasonEntryId:fixture.cancelReasonEntryId},staffMutation(undefined,tag(staffGet))),412,'VERSION_MISMATCH');
    const latest=accepted(await https('GET',sGet,undefined,staff()),200);
    expect(accepted(await https('POST',`${sGet}/commands/cancel`,{reasonEntryId:fixture.cancelReasonEntryId},staffMutation(undefined,tag(latest))),200).data()).toEqual({applied:true,version:3});
    const regain=randomUUID();
    failure(await https('POST',`${pub}/form-session/consents`,{action:'GIVEN',documentId:fixture.consentDocumentId,
      documentVersionId:fixture.consentDocumentVersionId,evidenceRef:regain},mutate(f,regain)),409,'CONFLICT');
    accepted(await https('POST',`${pub}/form-session/revoke`,{},mutate(f)),400); // idempotency belongs only to named request commands
    accepted(await https('POST',`${pub}/form-session/revoke`,{},{...proof(f),'X-CSRF-Token':f.csrf}),200);
    const dead=accepted(await https('GET',fGet,undefined,proof(f)),401);
    expect(dead.headers['set-cookie']?.[0]?.startsWith(`__Host-fixlevelup_f_${f.sid}=;`)).toBe(true);
  },45000);

  it('accepts other-only repair, persists the exact no-call offer and requires explicit PHONE fallback', async () => {
    const f=await issue();
    const evidenceId=await given(f);
    const repair=`${pub}/repair-requests`;
    const body={contact,address:{...address,districtId:fixture.districtId},appliance:{categoryId:fixture.categoryId},
      fault:{otherDescription:'Synthetic other symptom sentinel'},
      consent:{evidenceId,documentVersionId:fixture.consentDocumentVersionId,accepted:true},channelSelection:offers.ids};
    const key=randomUUID();
    failure(await https('POST',repair,{...body,fault:{}},mutate(f,key)),422,'SEMANTIC');
    expect(await db().count('SELECT count(*)::int n FROM foundation.request_events WHERE idempotency_key=$1',[key])).toBe(0);
    const created=accepted(await https('POST',repair,body,mutate(f,key)),201);
    expect(created.data()['status']).toBe('WAITING_TELEGRAM_LINK');
    const fault=await db().db.query(`SELECT f.is_other,f.fault_id,f.fault_version_id FROM foundation.request_faults f
      JOIN foundation.requests q ON q.id=f.request_id AND q.current_appliance_revision_id=f.appliance_revision_id
      WHERE q.public_number=$1`,[created.data()['publicNumber']]);
    expect(fault.rows).toEqual([{is_other:true,fault_id:null,fault_version_id:null}]);
    await offers.setOfferEnabled(false);
    const exact=accepted(await https('POST',repair,body,mutate(f,key)),200);
    expect(exact.bytes).toBe(created.bytes);
    const other=await issue();
    failure(await https('POST',repair,{...body,consent:{...body.consent,evidenceId:await given(other)}},mutate(other)),409,'CHANNEL_OFFER_DISABLED');
    const get=accepted(await https('GET',`${pub}/request-session`,undefined,proof(f)),200);
    const follow=`${pub}/request-session/contact-mode`;
    failure(await https('POST',follow,{phonePermission:false},mutate(f,undefined,tag(get))),422,'SEMANTIC');
    const id=text((await db().db.query<{id:string}>(
      'SELECT id FROM foundation.requests WHERE public_number=$1',[created.data()['publicNumber']])).rows[0] ?? {},'id');
    const instance=testApp;
    if (!instance) { throw new Error('Missing isolated HTTPS composition'); }
    const switchBody={phonePermission:true};
    const etag=tag(get);

    // Negative storage-contract proof: unfinished units exist only in an isolated
    // runtime transaction, never in committed history. No triggers are bypassed.
    // Check both read predicates before forcing the exact deferred refusal.
    for (const shape of ['missing-preference','different-anchor','changed-preference','changed-contact','unbound-cancel'] as const) {
      const deniedKey=randomUUID();
      const client=await instance.filePool.connect();
      try {
        await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
        const prior=await requestRow(client,id,true);
        if (!prior || prior.row_version !== 1) { throw new Error('Missing waiting synthetic request'); }
        expect(await requestEffectsHistoryComplete(client)).toBe(true);
        const cancel=shape === 'unbound-cancel';
        let preference=prior.current_preference_revision_id;
        if (!cancel && shape !== 'missing-preference') {
          preference=randomUUID();
          if (shape === 'changed-preference') {
            await writePreference(client,id,preference,2,'PHONE','Europe/Moscow','URGENT');
          } else { await clonePhonePreference(client,prior,preference); }
        }
        let contactRevision=prior.current_contact_revision_id;
        if (shape === 'changed-contact') {
          contactRevision=randomUUID();
          if (!managed) { throw new Error('Missing synthetic key slots'); }
          await writeContact(client,{ring:keyring,keySlots:managed.slots,environment:'p05-isolated'},id,contactRevision,2,'MESSENGER',contact);
        }
        const next=await updateRequestRow(client,prior,cancel ? 'CANCELLED' : 'CALLBACK_REQUIRED','REPAIR',{
          contact:contactRevision,address:prior.current_address_revision_id,
          appliance:prior.current_appliance_revision_id,preference,assessment:prior.current_assessment_id,
        });
        const eventId=randomUUID();
        await writeEffect(client,keyring,next,{actor:{kind:'F',id:shape === 'different-anchor' || cancel ? other.sid : f.sid},
          command:cancel ? 'CancelRequest' : 'ChooseCallback',key:deniedKey,target:id,match:etag,
          body:cancel ? {reasonEntryId:fixture.cancelReasonEntryId} : switchBody},eventId,randomUUID());
        if (!cancel) { await writePhone(client,next,eventId,'GIVEN',randomUUID()); }
        expect(await requestEffectsHistoryComplete(client),shape).toBe(false);
        await expect(checkedReceipt(client,next,eventId)).rejects.toMatchObject({code:'NOT_READY'});
        await expect(client.query('SET CONSTRAINTS ALL IMMEDIATE')).rejects.toMatchObject({
          code:'23514',message:cancel ? 'Incomplete form submit for a follow-up command' : 'Incomplete callback switch',
        });
      } finally {
        try { await client.query('ROLLBACK'); } finally { client.release(); }
      }
      expect(await db().count('SELECT count(*)::int n FROM foundation.request_events WHERE idempotency_key=$1',[deniedKey])).toBe(0);
    }
    expect((await https('GET',`${pub}/request-session`,undefined,proof(f))).bytes).toBe(get.bytes);
    const switchHeaders=mutate(f,randomUUID(),etag);
    const chosen=accepted(await https('POST',follow,switchBody,switchHeaders),200);
    expect(chosen.data()).toEqual({...created.data(),status:'CALLBACK_REQUIRED',version:2});
    expect(accepted(await https('POST',follow,switchBody,switchHeaders),200).bytes).toBe(chosen.bytes);
    const exactSwitch=await db().db.query(`SELECT q.type,q.row_version,pr.revision,pr.contact_mode,
      e.actor_session_id,p.contact_revision_id=q.current_contact_revision_id AS contact_bound
      FROM foundation.requests q JOIN foundation.request_preference_revisions pr ON pr.id=q.current_preference_revision_id
      JOIN foundation.request_events e ON e.request_id=q.id AND e.resulting_version=q.row_version
      JOIN foundation.phone_permission_events p ON p.event_id=e.id AND p.action='GIVEN'
      WHERE q.id=$1`,[id]);
    expect(exactSwitch.rows).toEqual([{type:'REPAIR',row_version:2,revision:2,contact_mode:'PHONE',
      actor_session_id:f.sid,contact_bound:true}]);

    // Later valid preference and contact changes cannot make the immutable
    // switch incomplete or copy its permission to a new contact.
    const path=`/requests/${id}`;
    const staffView=async () => tag(accepted(await https('GET',path,undefined,staff()),200));
    accepted(await https('POST',`${path}/commands/start-review`,{},staffMutation(undefined,await staffView())),200);
    const changed=accepted(await https('POST',`${path}/commands/change-details`,{section:'PREFERENCE',urgency:'URGENT'},
      staffMutation(undefined,await staffView())),200);
    expect(changed.data()['version']).toBe(4);
    const contactId=text((await db().db.query<{id:string}>(
      'SELECT current_contact_revision_id AS id FROM foundation.requests WHERE id=$1',[id])).rows[0] ?? {},'id');
    const newContact={evidenceId:randomUUID(),contact:{...contact,name:'Synthetic replacement sentinel'}};
    const contactTag=await staffView();
    mintEvidence(newContact.evidenceId,'CONTACT_CHANGE',canonicalJson({requestId:id,contactRevisionId:contactId,
      permit:null,version:4,ifMatch:contactTag}),newContact);
    expect(accepted(await https('POST',`${path}/commands/change-contact`,newContact,
      staffMutation(undefined,contactTag)),200).data()['version']).toBe(5);
    const { rows:[current] }=await db().db.query<{ contact_id:string; inherited:boolean }>(`SELECT
      q.current_contact_revision_id AS contact_id,EXISTS (SELECT FROM foundation.phone_permission_events p
        WHERE p.request_id=q.id AND p.contact_revision_id=q.current_contact_revision_id AND p.action='GIVEN') AS inherited
      FROM foundation.requests q WHERE q.id=$1`,[id]);
    expect(current?.contact_id).not.toBe(contactId);
    expect(current?.inherited).toBe(false);
    expect(accepted(await https('POST',follow,switchBody,switchHeaders),200).bytes).toBe(chosen.bytes);
  },75000);

  it('manual repair requires separate staff evidence and confirms a purpose-bound comparison before READY', async () => {
    const source=(await db().db.query<{version:string}>('SELECT current_version_id AS version FROM foundation.reference_entries WHERE id=$1',[fixture.formSourceEntryId])).rows[0];
    if (!source) { throw new Error('Missing synthetic source'); }
    const key=randomUUID();
    const body=decodeP05ManualRequest({type:'REPAIR',sourceEntryId:fixture.formSourceEntryId,evidenceId:randomUUID(),contact:{...contact,
      mode:'PHONE',phonePermission:true,phoneEvidenceId:randomUUID()},address,appliance:{categoryId:fixture.categoryId},fault:{faultIds:[fixture.faultId]}});
    if (body.type !== 'REPAIR' || body.contact.mode !== 'PHONE') { throw new Error('Wrong test DTO'); }
    failure(await https('POST','/requests',body,staffMutation(key)),403,'FORBIDDEN');
    const target=canonicalJson({cityId:fixture.cityId,cityVersionId:fixture.cityVersionId,sourceVersionId:source.version,operation:'CreateRepair',key});
    for (const [id,purpose] of [[body.evidenceId,'MANUAL_INTAKE'],[body.contact.phoneEvidenceId,'PHONE_GIVE']] as const) {
      evidence.set(id,{id,purpose,staffId:db().admin.id,target,canonicalIntent:canonicalJson(body),procedureRevision:'fixture-v1',validUntil:new Date(Date.now()+300000)});
    }
    const created=accepted(await https('POST','/requests',body,staffMutation(key)),201);
    const id=text(created.data(),'id');
    const path=`/requests/${id}`;
    expect(accepted(await https('POST','/requests',body,staffMutation(key)),200).bytes).toEqual(created.bytes);
    // The manual wire operation shares one namespace across both business branches.
    const callback=decodeP05ManualRequest({type:'CALLBACK',sourceEntryId:fixture.formSourceEntryId,evidenceId:randomUUID(),
      contact:{...contact,mode:'PHONE',phonePermission:true,phoneEvidenceId:randomUUID()}});
    if (callback.type !== 'CALLBACK') { throw new Error('Wrong callback test DTO'); }
    const callbackTarget=canonicalJson({cityId:fixture.cityId,cityVersionId:fixture.cityVersionId,
      sourceVersionId:source.version,operation:'CreateCallback',key});
    mintEvidence(callback.evidenceId,'MANUAL_INTAKE',callbackTarget,callback);
    mintEvidence(callback.contact.phoneEvidenceId,'PHONE_GIVE',callbackTarget,callback);
    failure(await https('POST','/requests',callback,staffMutation(key)),409,'IDEMPOTENCY_KEY_REUSED');
    expect(await db().count('SELECT count(*)::int n FROM foundation.request_events WHERE idempotency_key=$1',[key])).toBe(1);
    const init=accepted(await https('GET',path,undefined,staff()),200);
    failure(await https('POST',`${path}/commands/start-review`,{},staffMutation()),428,'PRECONDITION_REQUIRED');
    const reviewStarted=accepted(await https('POST',`${path}/commands/start-review`,{},staffMutation(undefined,tag(init))),200);
    expect(reviewStarted.data()['status']).toBe('MANAGER_REVIEW');
    const working=accepted(await https('GET',path,undefined,staff()),200);
    const snapshot=(await db().db.query<{id:string}>('SELECT current_address_revision_id AS id FROM foundation.requests WHERE id=$1',[id])).rows[0];
    if (!snapshot) { throw new Error('Missing address snapshot'); }
    const coverage=`${path}/commands/record-coverage`;
    const noProof={evidenceId:randomUUID(),outcome:'IN_ZONE',areaId:fixture.areaId};
    failure(await https('POST',coverage,noProof,staffMutation(undefined,tag(working))),403,'FORBIDDEN');
    expect(await db().count('SELECT count(*)::int n FROM foundation.request_address_review_attempts WHERE request_id=$1',[id])).toBe(0);
    const mint=(candidate:unknown) => {
      const evidenceId=randomUUID();
      review.set(evidenceId,{evidenceId,issuer:'T',purpose:'COVERAGE_REVIEW',staffId:db().admin.id,requestId:id,
        addressRevisionId:snapshot.id,candidate,expiresAt:new Date(Date.now()+60000)});
      return {...noProof,evidenceId};
    };
    failure(await https('POST',coverage,mint({...address,building:'13'}),staffMutation(undefined,tag(working))),403,'FORBIDDEN');
    expect(await db().count('SELECT count(*)::int n FROM foundation.request_address_review_attempts WHERE request_id=$1',[id])).toBe(1);
    expect(await db().count('SELECT count(*)::int n FROM foundation.request_coverage_assessments WHERE request_id=$1',[id])).toBe(0);
    accepted(await https('POST',coverage,mint(address),staffMutation(undefined,tag(working))),200);
    const reviewed=accepted(await https('GET',path,undefined,staff()),200);
    const ready=accepted(await https('POST',`${path}/commands/ready-for-dispatch`,{},staffMutation(undefined,tag(reviewed))),200);
    expect(ready.data()['status']).toBe('WAITING_ASSIGNMENT');
    expect(await db().count(`SELECT count(*)::int n FROM foundation.outbox_events WHERE payload->>'requestId'=$1
      AND event_type='REQUEST_READY_FOR_ASSIGNMENT' AND status='PENDING' AND lease_owner IS NULL`,[id])).toBe(1);
  },45000);

  it('uses the saved policy pin across a current-package change and refuses a self-consistent but unpinned digest', async () => {
    const manual = await manualPrepared();
    manual.authorize();
    const writer = await launchWithPolicy(historical.id);
    let id: string;
    try {
      const acceptedInHistory = accepted(await https('POST','/requests',manual.body,staffMutation(manual.key),portOf(writer)),201);
      id = text(acceptedInHistory.data(),'id');
    } finally { await writer.app.close(); }
    const path = `/requests/${id}`;
    const etag = tag(accepted(await https('GET',path,undefined,staff()),200));
    const key = randomUUID();
    const wrongPins = new Map(supportedFixturePolicies());
    wrongPins.set(policyPairKey(historical.workflowVersion,historical.policyRevision),REQUEST_POLICY_METADATA_SHA256);
    const wrong = await launchWithPolicy(fixture.policyId,wrongPins);
    try {
      failure(await https('POST',`${path}/commands/start-review`,{},staffMutation(key,etag),portOf(wrong)),503,'REQUEST_RULES_UNAVAILABLE');
    } finally { await wrong.app.close(); }
    expect(await db().count('SELECT count(*)::int n FROM foundation.request_events WHERE idempotency_key=$1',[key])).toBe(0);
    expect(tag(accepted(await https('GET',path,undefined,staff()),200))).toBe(etag);
    const started = accepted(await https('POST',`${path}/commands/start-review`,{},staffMutation(key,etag)),200);
    expect(started.data()).toMatchObject({status:'MANAGER_REVIEW',version:2});
    expect((await db().db.query(`SELECT intake_policy_revision_id,workflow_package_id,row_version
      FROM foundation.requests WHERE id=$1`,[id])).rows).toEqual([{
      intake_policy_revision_id:historical.id,workflow_package_id:historical.id,row_version:2,
    }]);
  },35000);

  it('rolls back the entire manual intake when the first evidence expires while the second is rechecked', async () => {
    const manual=await manualPrepared();
    manual.authorize();
    const proof=evidence.get(manual.body.evidenceId);
    if (!proof) { throw new Error('Missing synthetic manual evidence'); }
    const { rows:[clock] }=await db().db.query<{ deadline:Date }>("SELECT clock_timestamp()+interval '4 seconds' AS deadline");
    if (!clock) { throw new Error('Missing PostgreSQL clock'); }
    evidence.set(proof.id,{...proof,validUntil:clock.deadline});
    let phoneProofs=0;
    let crossedDeadline=false;
    evidenceClockHooks.set(manual.phoneEvidenceId,async (client) => {
      if (++phoneProofs !== 2) { return; }
      // The second PHONE proof follows the final MANUAL proof, after the writes.
      // Wait to the exact first deadline using the same isolated database clock.
      await client.query(`SELECT pg_sleep(least(4.5,greatest(0,extract(epoch FROM
        ($1::timestamptz-clock_timestamp()))+0.025)))`,[clock.deadline]);
      const { rows:[gate] }=await client.query<{ expired:boolean }>(
        'SELECT clock_timestamp()>=$1::timestamptz AS expired',[clock.deadline]);
      crossedDeadline=gate?.expired === true;
    });
    try {
      failure(await https('POST','/requests',manual.body,staffMutation(manual.key)),403,'FORBIDDEN');
      expect(phoneProofs).toBe(2);
      expect(crossedDeadline).toBe(true);
      expect(await db().count('SELECT count(*)::int n FROM foundation.request_events WHERE idempotency_key=$1',[manual.key])).toBe(0);
      expect(await db().count('SELECT count(*)::int n FROM foundation.request_staff_evidence WHERE id=ANY($1::uuid[])',
        [[proof.id,manual.phoneEvidenceId]])).toBe(0);
    } finally { evidenceClockHooks.delete(manual.phoneEvidenceId); }
    // The denied key and evidence were not consumed; a fresh valid proof can win.
    manual.authorize();
    const created=accepted(await https('POST','/requests',manual.body,staffMutation(manual.key)),201);
    expect(accepted(await https('POST','/requests',manual.body,staffMutation(manual.key)),200).bytes).toBe(created.bytes);
  },25000);

  it.each(['withdraw-first','ready-first'] as const)('serializes PHONE withdrawal and READY on the same PostgreSQL row: %s', async (order) => {
    const {id,path,snapshot,latest}=await readyCandidate();
    const staffProof={kind:'staff-web' as const,token:db().admin.token};
    const readyPath=`${path}/commands/ready-for-dispatch`;
    const withdrawPath=`${path}/commands/withdraw-phone`;
    const makeWithdrawal=(view: Reply) => {
      const etag=tag(view);
      const body={evidenceId:randomUUID()};
      const key=randomUUID();
      mintEvidence(body.evidenceId,'PHONE_WITHDRAW',canonicalJson({requestId:id,contactRevisionId:snapshot.contact_id,
        permit:snapshot.permit_id,version:view.data()['version'],ifMatch:etag}),body);
      return () => https('POST',withdrawPath,body,staffMutation(key,etag));
    };
    const ready=() => https('POST',readyPath,{},staffMutation(undefined,tag(latest)));
    const withdraw=makeWithdrawal(latest);
    const hold=await db().db.connect();
    let first: Promise<Reply> | undefined;
    let second: Promise<Reply> | undefined;
    let withdrawalReply: Reply | undefined;
    let repeatWithdrawal=withdraw;
    try {
      await hold.query('BEGIN');
      const handle=(await hold.query<{pid:number}>('SELECT pg_backend_pid() AS pid')).rows[0];
      if (!handle) { throw new Error('Missing lock observer identity'); }
      await hold.query('SELECT id FROM foundation.requests WHERE id=$1 FOR UPDATE',[id]);
      first=(order === 'ready-first' ? ready : withdraw)();
      await waitForRequestLock(handle.pid,1);
      second=(order === 'ready-first' ? withdraw : ready)();
      await waitForRequestLock(handle.pid,2);
      await hold.query('ROLLBACK');
      const [winner,loser]=await Promise.all([first,second]);
      accepted(winner,200);
      failure(loser,412,'VERSION_MISMATCH');
      if (order === 'withdraw-first') { withdrawalReply=winner; }
    } finally {
      await hold.query('ROLLBACK').catch(() => undefined);
      hold.release();
      await Promise.allSettled([first,second]);
    }
    let current=accepted(await https('GET',path,undefined,staff()),200);
    const effectCount = () => db().count(`SELECT count(*)::int n FROM foundation.outbox_events
      WHERE payload->>'requestId'=$1 AND event_type='REQUEST_READY_FOR_ASSIGNMENT' AND lease_owner IS NULL`,[id]);
    const version=current.data()['version'];
    if (typeof version !== 'number' || !testApp) { throw new Error('Missing committed version'); }
    if (order === 'ready-first') {
      expect(current.data()['status']).toBe('WAITING_ASSIGNMENT');
      expect(await effectCount()).toBe(1);
      expect(await testApp.service.inspectPhoneEligibility(staffProof,id,version,snapshot.permit_id)).toBe(true);
      repeatWithdrawal=makeWithdrawal(current);
      withdrawalReply=closed(await repeatWithdrawal(),200,['applied','version']);
      expect(withdrawalReply.data()).toEqual({applied:true,version:version+1});
      current=accepted(await https('GET',path,undefined,staff()),200);
      expect(current.data()['status']).toBe('WAITING_ASSIGNMENT');
      expect(await effectCount()).toBe(1);
    } else {
      expect(current.data()['status']).toBe('MANAGER_REVIEW');
      failure(await https('POST',readyPath,{},staffMutation(undefined,tag(current))),409,'CONFLICT');
      expect(await effectCount()).toBe(0);
    }
    expect(await testApp.service.inspectPhoneEligibility(staffProof,id,version,snapshot.permit_id)).toBe(false);
    expect(await testApp.service.inspectPhoneEligibility(staffProof,id,Number(current.data()['version']),snapshot.permit_id)).toBe(false);
    const settled=await captureRequest(id);
    expect(withdrawalReply?.data()).toEqual({applied:true,version:current.data()['version']});
    expect(closed(await repeatWithdrawal(),200,['applied','version']).bytes).toBe(withdrawalReply?.bytes);
    closedFailure(await makeWithdrawal(latest)(),412,'VERSION_MISMATCH');
    closedFailure(await makeWithdrawal(current)(),409,'CONFLICT');
    expect(await captureRequest(id)).toEqual(settled);
    expect(await db().count(`SELECT count(*)::int n FROM foundation.phone_permission_events WHERE supersedes_given_id=$1 AND action='REVOKED'`,[snapshot.permit_id])).toBe(1);
  },45000);

  it('F core: ConvertCallback and section/contact effects', async () => {
    const view=async (path:string) => closed(await https('GET',path,undefined,staff()),200,staffViewKeys);
    const call=(path:string,command:string,body:unknown,etag:string,key=randomUUID()) =>
      https('POST',`${path}/commands/${command}`,body,staffMutation(key,etag));
    const details={address:{...address,districtId:fixture.districtId},appliance:{categoryId:fixture.categoryId},
      fault:{faultIds:[fixture.faultId],description:'F matrix secret appliance'}};
    const paths=[];
    for (const from of ['CALLBACK_REQUIRED','MANAGER_REVIEW'] as const) {
      const seed=await prepareCallback();
      const created=closed(await seed.send(),201,fReceiptKeys);
      const id=text((await db().db.query<{id:string}>('SELECT id FROM foundation.requests WHERE public_number=$1',
        [created.data()['publicNumber']])).rows[0] ?? {},'id');
      const path=`/requests/${id}`;
      if (from === 'MANAGER_REVIEW') {
        closed(await call(path,'start-review',{},tag(await view(path))),200,staffReceiptKeys);
      }
      const source=await view(path);
      const before=await captureRequest(id);
      expect(source.data()).toEqual({id,publicNumber:created.data()['publicNumber'],type:'CALLBACK',status:from,version:before.row.row_version});
      expect([before.row.current_address_revision_id,before.row.current_appliance_revision_id,before.row.current_assessment_id]).toEqual([null,null,null]);
      // A valid ADDRESS is written before the missing category is discovered; it too must roll back.
      const key=randomUUID();
      closedFailure(await call(path,'convert-callback',{...details,appliance:{categoryId:randomUUID()}},tag(source),key),409,'CONFLICT');
      closedFailure(await call(path,'change-details',{section:'ADDRESS',address:details.address},tag(source)),409,'CONFLICT');
      expect(await captureRequest(id)).toEqual(before);
      if (paths[0]) {
        closedFailure(await call(path,'convert-callback',details,tag(paths[0].source)),412,'VERSION_MISMATCH');
        closedFailure(await call(path,'convert-callback',details,tag(source),paths[0].key),409,'IDEMPOTENCY_KEY_REUSED');
        expect(await captureRequest(id)).toEqual(before);
        expect(await captureRequest(paths[0].id)).toEqual(paths[0].converted);
      }
      const receipt=closed(await call(path,'convert-callback',details,tag(source),key),200,staffReceiptKeys);
      const converted=await captureRequest(id);
      const r=converted.row;
      expect(receipt.data()).toEqual({id,publicNumber:r.public_number,status:'MANAGER_REVIEW',version:r.row_version});
      expect(r.current_preference_revision_id).not.toBe(before.row.current_preference_revision_id);
      for (const field of [r.current_address_revision_id,r.current_appliance_revision_id,r.current_preference_revision_id]) {
        expect(field).toEqual(expect.any(String));
      }
      const added=staffEffect(before,converted,key,'ConvertCallback',{type:'REPAIR',status:'MANAGER_REVIEW',
        current_address_revision_id:r.current_address_revision_id,current_appliance_revision_id:r.current_appliance_revision_id,
        current_preference_revision_id:r.current_preference_revision_id},['address','appliance','preference','fault','payload','payload']);
      expect(added('address')).toMatchObject({id:r.current_address_revision_id,revision:r.row_version,district_id:fixture.districtId});
      expect(added('appliance')).toMatchObject({id:r.current_appliance_revision_id,revision:r.row_version,category_id:fixture.categoryId});
      expect(added('preference')).toMatchObject({id:r.current_preference_revision_id,revision:r.row_version,contact_mode:'PHONE'});
      expect(added('fault')).toMatchObject({appliance_revision_id:r.current_appliance_revision_id,fault_id:fixture.faultId,is_other:false});
      closedFailure(await call(path,'convert-callback',details,tag(await view(path))),409,'CONFLICT');
      expect(closed(await call(path,'convert-callback',details,tag(source),key),200,staffReceiptKeys).bytes).toBe(receipt.bytes);
      expect(await captureRequest(id)).toEqual(converted);
      paths.push({id,path,source,key,receipt,converted});
    }
    const [a,b]=paths;
    if (!a || !b) { throw new Error('Missing two converted requests'); }
    const addressId=a.converted.row.current_address_revision_id;
    if (!addressId) { throw new Error('Missing conversion address'); }
    const assessment=randomUUID();
    review.set(assessment,{evidenceId:assessment,issuer:'T',purpose:'COVERAGE_REVIEW',staffId:db().admin.id,requestId:a.id,
      addressRevisionId:addressId,candidate:details.address,expiresAt:new Date(Date.now()+90000)});
    closed(await call(a.path,'record-coverage',{evidenceId:assessment,outcome:'IN_ZONE',areaId:fixture.areaId},tag(await view(a.path))),200,staffReceiptKeys);
    let before=await captureRequest(a.id);
    expect(before.row.current_assessment_id).toEqual(expect.any(String));
    const other=await captureRequest(b.id);
    const sections=[
      {section:'APPLIANCE',body:{section:'APPLIANCE',appliance:details.appliance,fault:{otherDescription:'F matrix secret replacement'}},
        pointer:'current_appliance_revision_id',kinds:['appliance','fault','payload']},
      {section:'PREFERENCE',body:{section:'PREFERENCE',urgency:'URGENT'},pointer:'current_preference_revision_id',kinds:['preference']},
      {section:'ADDRESS',body:{section:'ADDRESS',address:{...details.address,building:'32'}},
        pointer:'current_address_revision_id',kinds:['address','payload']},
    ] as const;
    for (const {section,body,pointer,kinds} of sections) {
      const source=tag(await view(a.path));
      const otherTag=tag(await view(b.path));
      const key=randomUUID();
      closedFailure(await call(a.path,'change-details',{...body,contact},source,key),400,'MALFORMED');
      if (section === 'ADDRESS') {
        closedFailure(await call(a.path,'change-details',{section,address:{...details.address,districtId:randomUUID()}},source,key),404,'NOT_FOUND');
      }
      closedFailure(await call(a.path,'change-details',body,otherTag,key),412,'VERSION_MISMATCH');
      expect(await captureRequest(a.id)).toEqual(before);
      const receipt=closed(await call(a.path,'change-details',body,source,key),200,staffReceiptKeys);
      const after=await captureRequest(a.id);
      const r=after.row;
      expect(r[pointer]).toEqual(expect.any(String));
      expect(r[pointer]).not.toBe(before.row[pointer]);
      const added=staffEffect(before,after,key,'ChangeDetails',{[pointer]:r[pointer],
        ...(section === 'ADDRESS' ? {current_assessment_id:null} : {})},kinds);
      expect(added(section.toLowerCase())).toMatchObject({id:r[pointer],revision:r.row_version});
      if (section === 'APPLIANCE') { expect(added('fault')).toMatchObject({appliance_revision_id:r[pointer],is_other:true,fault_id:null}); }
      if (section === 'PREFERENCE') { expect(added('preference')).toMatchObject({urgency:'URGENT',contact_mode:'PHONE'}); }
      expect(closed(await call(a.path,'change-details',body,source,key),200,staffReceiptKeys).bytes).toBe(receipt.bytes);
      closedFailure(await call(b.path,'change-details',body,otherTag,key),409,'IDEMPOTENCY_KEY_REUSED');
      expect(await captureRequest(a.id)).toEqual(after);
      expect(await captureRequest(b.id)).toEqual(other);
      before=after;
    }
    const source=tag(await view(a.path));
    const otherTag=tag(await view(b.path));
    const key=randomUUID();
    const body={evidenceId:randomUUID(),contact:{...contact,name:'F matrix secret new contact'}};
    const evidenceTarget=canonicalJson({requestId:a.id,contactRevisionId:before.row.current_contact_revision_id,
      permit:null,version:before.row.row_version,ifMatch:source});
    mintEvidence(body.evidenceId,'CONTACT_CHANGE',evidenceTarget,body);
    closedFailure(await call(b.path,'change-contact',body,otherTag,key),403,'FORBIDDEN'); // valid declaration on wrong target
    closedFailure(await call(a.path,'change-contact',{...body,contact:{...body.contact,phonePermission:true}},source,key),400,'MALFORMED');
    let evidenceChecks=0;
    // Force the trusted declaration to disappear only after the contact/effect writes.
    evidenceClockHooks.set(body.evidenceId,async () => {
      if (++evidenceChecks === 2) { evidence.delete(body.evidenceId); }
      await Promise.resolve();
    });
    try {
      closedFailure(await call(a.path,'change-contact',body,source,key),403,'FORBIDDEN');
      expect(evidenceChecks).toBe(2);
      expect(await captureRequest(a.id)).toEqual(before);
      expect(await captureRequest(b.id)).toEqual(other);
    } finally { evidenceClockHooks.delete(body.evidenceId); }
    mintEvidence(body.evidenceId,'CONTACT_CHANGE',evidenceTarget,body);
    const receipt=closed(await call(a.path,'change-contact',body,source,key),200,staffReceiptKeys);
    const after=await captureRequest(a.id);
    const currentContact=after.row.current_contact_revision_id;
    expect(currentContact).toEqual(expect.any(String));
    expect(currentContact).not.toBe(before.row.current_contact_revision_id);
    const added=staffEffect(before,after,key,'ChangeContact',{current_contact_revision_id:currentContact},['contact','payload','staffEvidence']);
    expect(added('contact')).toMatchObject({id:currentContact,mode:'PHONE',revision:after.row.row_version});
    expect(added('staffEvidence')).toMatchObject({id:body.evidenceId,request_id:a.id,purpose:'CONTACT_CHANGE',staff_id:db().admin.id});
    expect(closed(await call(a.path,'change-contact',body,source,key),200,staffReceiptKeys).bytes).toBe(receipt.bytes);
    closedFailure(await call(b.path,'change-contact',body,otherTag,key),409,'IDEMPOTENCY_KEY_REUSED');
    expect(await captureRequest(a.id)).toEqual(after);
    expect(await captureRequest(b.id)).toEqual(other);
  },90000);

  it('conceals a fresh manual target before decoding an unauthorized CITY actor’s body', async () => {
    const manager = await db().webStaff();
    const provision = await db().db.connect();
    try {
      await provision.query('BEGIN');
      await lockAccessPolicy(provision,'write');
      await provision.query(`INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
        SELECT r.id,p,'CITY' FROM foundation.roles r CROSS JOIN unnest($1::text[]) p
        WHERE r.role_type='SYSTEM' AND r.code='MANAGER'`, [['requests.read','requests.create']]);
      await provision.query('COMMIT');
    } catch (error) {
      await provision.query('ROLLBACK');
      throw error;
    } finally { provision.release(); }
    const mutateAsManager = (key: string) => ({ Cookie:manager.cookie, 'Idempotency-Key':key,
      'X-CSRF-Token':createHmac('sha256',staffCsrf).update('web-auth-csrf\0').update(manager.token).digest('base64url') });
    const manual = await manualPrepared();
    const other = randomUUID();
    failure(await https('POST','/requests',manual.body,mutateAsManager(manual.key)),404,'NOT_FOUND');
    // If the decoder ran first, this malformed object would reveal a 400/422.
    failure(await https('POST','/requests',{ type:'REPAIR', contact },mutateAsManager(other)),404,'NOT_FOUND');
    expect(await db().count('SELECT count(*)::int n FROM foundation.request_events WHERE idempotency_key=ANY($1::uuid[])',
      [[manual.key,other]])).toBe(0);
  },45000);

  it('F matrix: exact staff read/action and CITY boundaries', async () => {
    const lab=db();
    const policy=async (apply:(client:import('pg').PoolClient)=>Promise<void>) => {
      const client=await lab.db.connect();
      try {
        await client.query('BEGIN');
        await lockAccessPolicy(client,'write');
        await apply(client);
        await client.query('COMMIT');
      } finally { try { await client.query('ROLLBACK'); } finally { client.release(); } }
    };
    const makeStaff=async (channel:'MANAGER'|'ADMIN',roleId:string) => {
      const id=randomUUID();
      const login=randomBytes(24).toString('hex');
      const password=randomBytes(24).toString('hex');
      const passwordHash=await hashPassword(password);
      await policy(async client => {
        await client.query(`INSERT INTO foundation.staff (id,role,employment_state,auth_version) VALUES ($1,$2,'ACTIVE',0)`,[id,channel]);
        await client.query('INSERT INTO foundation.staff_web_credentials(staff_id,login,password_hash) VALUES ($1,$2,$3)',[id,login,passwordHash]);
        await client.query('INSERT INTO foundation.staff_role_assignments (id,staff_id,role_id) VALUES ($1,$2,$3)',[randomUUID(),id,roleId]);
      });
      return await lab.login(id,login,password);
    };
    const updateAdmin=async (mode:'GLOBAL'|'CITY'|'MIXED') => {
      await policy(async client => {
        // Reprovision only this fixture's ADMIN rows under RBAC X. The grant guard
        // correctly disallows changing an existing request grant's identity.
        const old=await client.query('DELETE FROM foundation.role_permissions WHERE role_id=$1 AND permission_code=ANY($2::text[])',
          [adminRole,P05_CAPABILITIES]);
        expect(old.rowCount).toBe(P05_CAPABILITIES.length);
        const seeded=await client.query(`INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
          SELECT $1,c,CASE WHEN $2='MIXED' THEN CASE WHEN c='requests.read' THEN 'GLOBAL' ELSE 'CITY' END ELSE $2 END
          FROM unnest($3::text[]) c`,[adminRole,mode,P05_CAPABILITIES]);
        expect(seeded.rowCount).toBe(P05_CAPABILITIES.length);
      });
    };
    const assignCity=async (staffId:string,cityId:string) => {
      const id=randomUUID();
      await policy(async client => { await client.query(`INSERT INTO foundation.staff_admin_city_assignments(id,staff_id,city_id,granted_by)
        VALUES ($1,$2,$3,$4)`,[id,staffId,cityId,lab.admin.id]); });
      return id;
    };
    const revokeCity=async (id:string) => {
      await policy(async client => { await client.query(`UPDATE foundation.staff_admin_city_assignments
        SET revoked_at=clock_timestamp(),revoked_by=$2 WHERE id=$1`,[id,lab.admin.id]); });
    };
    const managerRole=await lab.systemRole('MANAGER');
    const adminRole=await lab.systemRole('ADMIN');
    const otherCity=randomUUID();
    const roles=[randomUUID(),randomUUID(),randomUUID()];
    const [full,readOnly,actionOnly]=roles;
    if (!full || !readOnly || !actionOnly) { throw new Error('Missing matrix roles'); }
    await policy(async client => {
      // A second administrative CITY assignment is real; a DRAFT city leaves SINGLE_CITY intake unchanged.
      await acquireCompanySettingsLock(client);
      await client.query('INSERT INTO foundation.service_cities(id,code) VALUES ($1,$2)',[otherCity,`p05-other-${otherCity.slice(0,8)}`]);
      await client.query(`INSERT INTO foundation.role_permissions (role_id,permission_code,scope_type)
        SELECT $1,c,'CITY' FROM unnest($2::text[]) c ON CONFLICT (role_id,permission_code) DO NOTHING`,[managerRole,P05_CAPABILITIES]);
      for (const [roleId,codes] of [[full,P05_CAPABILITIES],[readOnly,['requests.read']],
        [actionOnly,P05_CAPABILITIES.filter(code=>code !== 'requests.read')]] as const) {
        await client.query('INSERT INTO foundation.roles (id,code,name) VALUES ($1,$2,$3)',[roleId,`CUSTOM_F_${roleId.slice(0,8).toUpperCase()}`,'Synthetic P05 HTTP role']);
        await client.query(`INSERT INTO foundation.role_permissions (role_id,permission_code,scope_type)
          SELECT $1,c,'CITY' FROM unnest($2::text[]) c`,[roleId,codes]);
      }
    });
    const administrator=await makeStaff('ADMIN',adminRole);
    const manager=await makeStaff('MANAGER',managerRole);
    const custom=await makeStaff('MANAGER',full);
    const reader=await makeStaff('MANAGER',readOnly);
    const actorOnly=await makeStaff('MANAGER',actionOnly);
    await assignCity(reader.id,fixture.cityId);
    await assignCity(actorOnly.id,fixture.cityId);
    // Provision authentic persisted TG-channel sessions with the same hashed-token
    // shape as the issuer. The denial under test starts at the P05 HTTPS boundary.
    const mintTelegram=async (staffId:string,userId:number) => {
      const token=randomBytes(32).toString('base64url');
      const link=randomUUID();
      await policy(async client => {
        await client.query(`INSERT INTO foundation.staff_telegram_links(id,staff_id,telegram_user_id) VALUES ($1,$2,$3)`,[link,staffId,userId]);
        const issued=await client.query(`INSERT INTO foundation.web_sessions(id,staff_id,token_hash,auth_version,created_at,
          idle_expires_at,absolute_expires_at,channel,initdata_digest,initdata_exchanged_at,telegram_link_id)
          SELECT $1,s.id,$2,s.auth_version,clock_timestamp(),clock_timestamp()+interval '10 minutes',clock_timestamp()+interval '1 hour',
          'STAFF_TELEGRAM',$3,clock_timestamp(),$4 FROM foundation.staff s WHERE s.id=$5`,
        [randomUUID(),createHash('sha256').update(token).digest('hex'),randomBytes(32).toString('hex'),link,staffId]);
        expect(issued.rowCount).toBe(1);
      });
      return token;
    };
    const tech=await mintTelegram(await lab.createStaff('TECHNICIAN'),700950001);
    const managerTg=await mintTelegram(manager.id,700950002);
    const mutant=(actor:{cookie:string;token:string},key:string,etag?:string) => ({Cookie:actor.cookie,'Idempotency-Key':key,
      'X-CSRF-Token':createHmac('sha256',staffCsrf).update('web-auth-csrf\0').update(actor.token).digest('base64url'),
      ...(etag === undefined ? {} : {'If-Match':etag})});
    const seed=async () => {
      const f=await prepareCallback();
      const reply=closed(await f.send(),201,fReceiptKeys);
      const id=text((await lab.db.query<{id:string}>('SELECT id FROM foundation.requests WHERE public_number=$1',[reply.data()['publicNumber']])).rows[0] ?? {},'id');
      return {id,path:`/requests/${id}`,f};
    };
    const target=await seed();
    const missing=`/requests/${randomUUID()}`;
    const get=(path:string,headers:Record<string,string>) => https('GET',path,undefined,headers);
    const view=closed(await get(target.path,staff()),200,staffViewKeys);
    const etag=tag(view);
    const initial=await captureRequest(target.id);
    const ops=[['start-review',{}],['convert-callback',{}],['change-details',{}],['record-coverage',{}],['change-contact',{}],
      ['ready-for-dispatch',{}],['withdraw-phone',{}],['cancel',{}]] as const;
    const deniedProofs: Record<string,string>[]=[{},{Cookie:target.f.form.cookie},{Authorization:`Bearer ${tech}`},
      {Authorization:`Bearer ${managerTg}`},{Cookie:`__Host-fixlevelup_session=${tech}`},{Cookie:`__Host-fixlevelup_session=${managerTg}`}];
    for (const [i,headers] of deniedProofs.entries()) {
      closedFailure(await get(target.path,{...headers,'If-None-Match':etag}),401,'UNAUTHORIZED');
      const writeHeaders=i >= 4 ? mutant({cookie:headers['Cookie'] ?? '',token:i === 4 ? tech : managerTg},randomUUID(),etag)
        : {...headers,'If-Match':etag,'Idempotency-Key':randomUUID()};
      closedFailure(await https('POST',`${target.path}/commands/start-review`,{},writeHeaders),401,'UNAUTHORIZED');
    }
    closedFailure(await get(target.path,{...proof(target.f.form),'If-None-Match':etag}),400,'MALFORMED');
    const denied=new Map([[reader,200],[actorOnly,403]]);
    for (const [actor,readStatus] of denied) {
      const result=await get(target.path,{Cookie:actor.cookie});
      if (readStatus === 200) { expect(closed(result,200,staffViewKeys).bytes).toBe(view.bytes); }
      else { closedFailure(result,403,'FORBIDDEN'); }
      for (const [op,body] of ops) {
        closedFailure(await https('POST',`${target.path}/commands/${op}`,body,mutant(actor,randomUUID(),etag)),403,'FORBIDDEN');
      }
      closedFailure(await https('POST','/requests',{contact},mutant(actor,randomUUID())),403,'FORBIDDEN');
    }
    expect(await captureRequest(target.id)).toEqual(initial);
    for (const actor of [manager,custom]) {
      const wrong=await assignCity(actor.id,otherCity);
      const headers={Cookie:actor.cookie,'If-None-Match':etag};
      const conceal=async () => {
        for (const path of [target.path,missing]) {
          closedFailure(await get(path,headers),404,'NOT_FOUND');
          closedFailure(await https('POST',`${path}/commands/start-review`,{},mutant(actor,randomUUID(),etag)),404,'NOT_FOUND');
        }
        closedFailure(await https('POST','/requests',{contact},mutant(actor,randomUUID())),404,'NOT_FOUND');
      };
      await conceal(); // A different CITY is not a permission for the target.
      await revokeCity(wrong);
      await conceal(); // No active CITY is not a GLOBAL fallback.
      const matching=await assignCity(actor.id,fixture.cityId);
      const own=await seed();
      const read=closed(await get(own.path,{Cookie:actor.cookie}),200,staffViewKeys);
      expect(closed(await get(target.path,{Cookie:actor.cookie}),200,staffViewKeys).bytes).toBe(view.bytes);
      const before=await captureRequest(own.id);
      const key=randomUUID();
      const apply=() => https('POST',`${own.path}/commands/start-review`,{},mutant(actor,key,tag(read)));
      closed(await apply(),200,staffReceiptKeys);
      const after=await captureRequest(own.id);
      staffEffect(before,after,key,'StartReview',{status:'MANAGER_REVIEW'},[],actor.id);
      await revokeCity(matching);
      closedFailure(await apply(),404,'NOT_FOUND'); // Existing receipt is not a grant.
      expect(await captureRequest(own.id)).toEqual(after);
    }
    try {
      expect(closed(await get(target.path,{Cookie:administrator.cookie}),200,staffViewKeys).bytes).toBe(view.bytes);
      await updateAdmin('MIXED'); // GLOBAL read cannot confer the missing CITY-scoped action.
      expect(closed(await get(target.path,{Cookie:administrator.cookie}),200,staffViewKeys).bytes).toBe(view.bytes);
      const key=randomUUID();
      const apply=() => https('POST',`${target.path}/commands/start-review`,{},mutant(administrator,key,etag));
      closedFailure(await apply(),404,'NOT_FOUND');
      await updateAdmin('CITY');
      closedFailure(await get(target.path,{Cookie:administrator.cookie,'If-None-Match':etag}),404,'NOT_FOUND');
      const matching=await assignCity(administrator.id,fixture.cityId);
      expect(closed(await get(target.path,{Cookie:administrator.cookie}),200,staffViewKeys).bytes).toBe(view.bytes);
      closed(await apply(),200,staffReceiptKeys);
      const after=await captureRequest(target.id);
      staffEffect(initial,after,key,'StartReview',{status:'MANAGER_REVIEW'},[],administrator.id);
      await revokeCity(matching);
      closedFailure(await apply(),404,'NOT_FOUND');
      expect(await captureRequest(target.id)).toEqual(after);
    } finally { await updateAdmin('GLOBAL'); }
  },90000);

  // One normative inventory, five bounded HTTPS cases: Vitest's per-case cap
  // would truncate a single walk. Each witness slice asserts its own oracle-derived
  // count inside the proof; the expected totals below must sum to the whole matrix.
  const sliceCells=(index:number) => witnesses.slice(index*6,index*6+6).reduce((sum,w)=>sum+8+(w.origin==='F' ? 3 : 0),0);
  const phases=[
    ['witnesses-0','F normative HTTPS matrix: lawful states 1/3',sliceCells(0),300000],
    ['witnesses-1','F normative HTTPS matrix: lawful states 2/3',sliceCells(1),300000],
    ['witnesses-2','F normative HTTPS matrix: lawful states 3/3',sliceCells(2),300000],
    ['roles','F normative HTTPS matrix: exact roles and create shapes',5+13+13+13+4,300000],
    ['denials','F normative HTTPS matrix: scope, proof and unmapped-route denials',3*19+8+19+4*10+8+noP05CommandRoutes.length+2,300000],
    ['city-admin-0','CITY-RBAC × state × command: SYSTEM ADMIN CITY states 1/3',6*8,900000],
    ['city-admin-1','CITY-RBAC × state × command: SYSTEM ADMIN CITY states 2/3',6*8,900000],
    ['city-admin-2','CITY-RBAC × state × command: SYSTEM ADMIN CITY states 3/3',6*8,900000],
    ['city-manager-0','CITY-RBAC × state × command: SYSTEM MANAGER CITY states 1/3',6*8,900000],
    ['city-manager-1','CITY-RBAC × state × command: SYSTEM MANAGER CITY states 2/3',6*8,900000],
    ['city-manager-2','CITY-RBAC × state × command: SYSTEM MANAGER CITY states 3/3',6*8,900000],
    ['city-custom-0','CITY-RBAC × state × command: CUSTOM CITY states 1/3',6*8,900000],
    ['city-custom-1','CITY-RBAC × state × command: CUSTOM CITY states 2/3',6*8,900000],
    ['city-custom-2','CITY-RBAC × state × command: CUSTOM CITY states 3/3',6*8,900000],
  ] as const;
  it('F normative HTTPS matrix inventory: phases cover every oracle cell exactly once', () => {
    expect(witnesses).toHaveLength(18);
    const cityPhases=phases.filter(([phase])=>phase.startsWith('city-'));
    expect(cityPhases.map(([phase])=>phase)).toEqual([
      'city-admin-0','city-admin-1','city-admin-2',
      'city-manager-0','city-manager-1','city-manager-2',
      'city-custom-0','city-custom-1','city-custom-2',
    ]);
    expect(cityPhases.reduce((sum,[, ,cells])=>sum+cells,0)).toBe(432);
    expect(new Set(cityPhases.map(([phase])=>phase)).size).toBe(9);
    expect(sliceCells(0)+sliceCells(1)+sliceCells(2)).toBe(18*8+9*3);
  });
  for (const [phase,name,expected,budget] of phases) {
    it(name, async () => {
      const began=performance.now();
      const progress=(label:string,checks:number) => {
        process.stdout.write(`[P05 HTTPS matrix/${phase}] ${label} checks=${String(checks)} elapsedMs=${String(Math.round(performance.now()-began))}\n`);
      };
      const requireTime=() => {
        if (performance.now()-began >= budget-25000) { throw new Error('P05 HTTPS matrix work deadline reached'); }
      };
      progress('setup',0);
      // Each phase owns three separate provider schemas inside the same
      // disposable test database. The database is the lifecycle boundary:
      // schemas are never dropped while other phases/clients may still use them.
      // Reusing the fixed mxtg/mxvk/mxmax names made the second phase collide
      // with the first even though each RequestOfferFixture instance is new.
      const phaseTag=phase.replace(/[^a-z0-9]/gi,'').toLowerCase();
      if (!/^[a-z0-9]{1,12}$/.test(phaseTag)) { throw new Error('Invalid P05 matrix phase schema tag'); }
      const tg=await RequestOfferFixture.attach(db(),{provider:'TG',schema:`p05_offer_fixture_${phaseTag}tg`});
      const vk=await RequestOfferFixture.attach(db(),{provider:'VK',schema:`p05_offer_fixture_${phaseTag}vk`});
      const max=await RequestOfferFixture.attach(db(),{provider:'MAX',schema:`p05_offer_fixture_${phaseTag}max`});
      // Each provider uses the fixture's real same-connection admission. They
      // share the same PG offer fence; the preliminary lock is provider-independent.
      const byProvider={TG:tg,VK:vk,MAX:max};
      const matrix=await launchWithPolicy(fixture.policyId,undefined,900000,{
        lock: client=>tg.lock(client),validateNewOffer:(client,choice)=>byProvider[choice.provider].validateNewOffer(client,choice),
      });
      try {
        const matrixPort=portOf(matrix);
        const executed=await proveHttpMatrix({lab:db(),fixture,staffCsrf,phase,offerIds:{TG:tg.ids,VK:vk.ids,MAX:max.ids},contact,address,
          send:(method,path,body,headers)=>{requireTime(); return https(method,path,body,headers,matrixPort);},
          issue:()=>{requireTime(); return issue(matrixPort);},given:form=>{requireTime(); return given(form,matrixPort);},
          capture:id=>captureRequest(id,true),progress,
          setStaff:proof=>{evidence.set(proof.id,proof);},setReview:proof=>{review.set(proof.evidenceId,proof);},
        });
        // The declared inventory is asserted per case, so no cell can silently vanish.
        expect(executed,`${phase} normative cells`).toBe(expected);
      } finally { await matrix.app.close(); }
    },budget);
  }

  it('F privacy: exact live authority and evidence gate the address SELECT behind a committed audit', async () => {
    const lab=db();
    const manual=await manualPrepared();
    manual.authorize();
    const created=closed(await https('POST','/requests',manual.body,staffMutation(manual.key)),201,staffReceiptKeys);
    const id=text(created.data(),'id');
    const path=`/requests/${id}`;
    const currentTag=async () => tag(closed(await https('GET',path,undefined,staff()),200,staffViewKeys));
    closed(await https('POST',`${path}/commands/start-review`,{},staffMutation(undefined,await currentTag())),200,staffReceiptKeys);
    const oldAddress=(await captureRequest(id)).row.current_address_revision_id;
    // Preserve the candidate while replacing its revision: an old, genuine
    // revision of this same request is not sufficient evidence for comparison.
    closed(await https('POST',`${path}/commands/change-details`,{section:'ADDRESS',address},
      staffMutation(undefined,await currentTag())),200,staffReceiptKeys);
    const etag=await currentTag();
    const before=await captureRequest(id);
    expect(before.row).toMatchObject({type:'REPAIR',status:'MANAGER_REVIEW',current_assessment_id:null});
    const addressId=before.row.current_address_revision_id;
    if (!oldAddress || !addressId || oldAddress === addressId) { throw new Error('Missing distinct address revisions'); }
    const current=before.history.find(({kind,value})=>kind === 'address' && value['id'] === addressId);
    const cellId=text(current?.value ?? {},'payload_cell_id');
    const staffId=lab.admin.id;
    const expiresAt=(await lab.db.query<{deadline:Date}>("SELECT clock_timestamp()+interval '5 minutes' AS deadline")).rows[0]?.deadline;
    if (!expiresAt) { throw new Error('Missing PostgreSQL evidence deadline'); }
    const exact={issuer:'T',purpose:'COVERAGE_REVIEW',staffId,requestId:id,addressRevisionId:addressId,candidate:address,expiresAt} as const;
    const attempts=async () => (await lab.db.query<Record<string,unknown>>(
      'SELECT * FROM foundation.request_address_review_attempts WHERE request_id=$1',[id])).rows;
    expect(await attempts()).toEqual([]);

    const original=Object.getOwnPropertyDescriptor(Client.prototype,'query')?.value as Client['query'] | undefined;
    if (!original) { throw new Error('Missing real PG query method'); }
    const compare=async (patch: Partial<CoverageReviewEvidence>, headers: Record<string,string>) => {
      const evidenceId=randomUUID();
      review.set(evidenceId,{...exact,...patch,evidenceId});
      const trace: string[]=[];
      const reads: {params: unknown; committed: Record<string,unknown>[]; rowCount: unknown; kind: unknown;
        hasCiphertext: boolean; separate: boolean}[]=[];
      const auditBackends=new WeakSet<Client>();
      // Only the two admitted runtime pools in this DB, during this single HTTPS
      // command. Owner snapshots and the independent visibility check do not enter
      // the trace. The driver still executes every observed statement unchanged.
      Client.prototype.query=function(this:Client,...args:unknown[]) {
        const delegate=():unknown => Reflect.apply(original,this,args);
        const application=(this as Client & {connectionParameters:{application_name?:string}}).connectionParameters.application_name;
        if (this.database !== lab.database || this.user !== 'fixlevelup_runtime'
          || (application !== 'fixlevelup-intake-isolated' && application !== 'fixlevelup-intake-audit-isolated')) { return delegate(); }
        const [input,values]=args;
        const config=typeof input === 'object' && input !== null ? record(input) : {};
        const sql=typeof input === 'string' ? input : config['text'];
        if (typeof sql !== 'string') { return delegate(); }
        const normalized=sql.trim().replace(/\s+/g,' ');
        if (/^INSERT INTO foundation\.request_address_review_attempts\s*\(/i.test(normalized)) {
          auditBackends.add(this);
          trace.push('audit INSERT');
        }
        if (auditBackends.has(this) && normalized === 'COMMIT') {
          return Promise.resolve(delegate()).then((result:unknown) => {
            trace.push(`audit ${text(record(result),'command')}`);
            return result;
          });
        }
        // A readiness/catalog query naming the relation does not read a cell.
        if (/\b(?:FROM|JOIN)\s+foundation\.request_payload_cells\b/i.test(normalized)) {
          trace.push('custody SELECT');
          return (async () => {
            // A separate owner connection sees the exact row before sending
            // the SELECT to PG, not merely before returning its result.
            const committed=await attempts();
            const result:unknown=await delegate();
            const rowset=record(result);
            const rows:unknown=rowset['rows'];
            const cell=Array.isArray(rows) && rows.length === 1 ? record(rows[0]) : {};
            const ciphertext=cell['ciphertext'];
            reads.push({params:values ?? config['values'],committed,rowCount:rowset['rowCount'],kind:cell['kind'],
              hasCiphertext:Buffer.isBuffer(ciphertext) && ciphertext.length > 0,
              separate:application === 'fixlevelup-intake-isolated' && !auditBackends.has(this)});
            return result;
          })();
        }
        return delegate();
      } as typeof original;
      try {
        const reply=await https('POST',`${path}/commands/record-coverage`,{evidenceId,outcome:'IN_ZONE',areaId:fixture.areaId},headers);
        return {reply,evidenceId,trace,reads};
      } finally { Client.prototype.query=original; review.delete(evidenceId); }
    };
    const denyCompare=async (name:string,status:number,code:string,patch:Partial<CoverageReviewEvidence>={},headers=staffMutation(undefined,etag)) => {
      const {reply,trace,reads}=await compare(patch,headers);
      expect({trace,reads},name).toEqual({trace:[],reads:[]});
      closedFailure(reply,status,code);
      expect(await attempts(),name).toEqual([]);
      expect(await captureRequest(id),name).toEqual(before);
    };
    for (const [name,patch] of [['wrong actor',{staffId:randomUUID()}],['wrong request',{requestId:randomUUID()}],
      ['old address revision',{addressRevisionId:oldAddress}],['expired evidence',{expiresAt:new Date(0)}]] as const) {
      await denyCompare(name,403,'FORBIDDEN',patch);
    }

    const access=async (sql:string,params:string[]) => {
      const client=await lab.db.connect();
      try {
        await client.query('BEGIN');
        await lockAccessPolicy(client,'write');
        expect((await client.query(sql,params)).rowCount).toBe(1);
        await client.query('COMMIT');
      } finally { try { await client.query('ROLLBACK'); } finally { client.release(); } }
    };
    const role=await lab.systemRole('ADMIN');
    await access("DELETE FROM foundation.role_permissions WHERE role_id=$1 AND permission_code=$2 AND scope_type='GLOBAL'",[role,'requests.coverage.assess']);
    try {
      expect(await currentTag()).toBe(etag); // Still has scoped read, but no compare capability.
      await denyCompare('no compare capability',403,'FORBIDDEN');
    } finally {
      await access("INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type) VALUES ($1,$2,'GLOBAL')",[role,'requests.coverage.assess']);
    }

    const secondary=await lab.login(staffId,lab.admin.login,lab.admin.password);
    const secondaryHeaders={...staffMutation(undefined,etag),Cookie:secondary.cookie,
      'X-CSRF-Token':createHmac('sha256',staffCsrf).update('web-auth-csrf\0').update(secondary.token).digest('base64url')};
    expect(tag(closed(await https('GET',path,undefined,{Cookie:secondary.cookie}),200,staffViewKeys))).toBe(etag);
    // Logout has no JSON envelope. Exercise the real fixture HTTP route directly.
    await supertest(`http://127.0.0.1:${String(lab.httpPort)}`).post('/api/v1/auth/logout')
      .set('Origin',origin).set('Cookie',secondary.cookie).set('X-CSRF-Token',secondary.csrf).send({}).expect(204);
    await denyCompare('revoked staff web session',401,'UNAUTHORIZED',{},secondaryHeaders);

    const key=randomUUID();
    const {reply,evidenceId,trace,reads}=await compare({},staffMutation(key,etag));
    expect(trace).toEqual(['audit INSERT','audit COMMIT','custody SELECT']);
    expect(reads).toHaveLength(1);
    const [read]=reads;
    if (!read) { throw new Error('Missing real custody read'); }
    expect(read.separate).toBe(true);
    expect(read.params).toEqual([id,cellId]);
    expect(read.rowCount).toBe(1);
    expect(read.kind).toBe('ADDRESS');
    expect(read.hasCiphertext).toBe(true);
    const attempt=read.committed[0] ?? {};
    expect(text(attempt,'correlation_id')).toMatch(/^[0-9a-f-]{36}$/);
    expect(attempt['occurred_at']).toBeInstanceOf(Date);
    expect(read.committed).toEqual([{evidence_id:evidenceId,staff_id:staffId,request_id:id,address_revision_id:addressId,
      purpose:'COVERAGE_REVIEW',correlation_id:attempt['correlation_id'],occurred_at:attempt['occurred_at']}]);
    expect(await attempts()).toEqual(read.committed);
    expect(closed(reply,200,staffReceiptKeys).data()).toEqual({id,publicNumber:created.data()['publicNumber'],status:'MANAGER_REVIEW',version:before.row.row_version+1});
    const after=await captureRequest(id);
    const assessmentId=after.row.current_assessment_id;
    expect(assessmentId).toEqual(expect.any(String));
    const added=staffEffect(before,after,key,'RecordCoverageAssessment',{current_assessment_id:assessmentId},['assessment']);
    expect(added('assessment')).toMatchObject({id:assessmentId,request_id:id,address_revision_id:addressId,staff_id:staffId,
      attempt_correlation_id:read.committed[0]?.['correlation_id'],outcome:'IN_ZONE',area_id:fixture.areaId});
  },60000);

  it('F lifecycle: consent revoke wins or loses to fresh submit and exact replay', async () => {
    for (const mode of ['fresh','replay'] as const) {
      for (const order of ['revoke-first','submit-first'] as const) {
        const seed=await prepareCallback();
        const prior=mode === 'replay' ? closed(await seed.send(),201,fReceiptKeys) : undefined;
        const {rows:[edge]}=await db().db.query<{request_id:string}>(`SELECT request_id FROM foundation.request_session_submits WHERE session_id=$1`,[seed.form.sid]);
        const before=edge ? await captureRequest(edge.request_id) : undefined;
        const revocationKey=randomUUID();
        const revoke=() => https('POST',`${pub}/form-session/consents`,{action:'REVOKED',supersedesEvidenceId:seed.evidenceId,
          evidenceRef:revocationKey},mutate(seed.form,revocationKey));
        const hold=await db().db.connect();
        let first:Promise<Reply>|undefined;
        let second:Promise<Reply>|undefined;
        try {
          await hold.query('BEGIN');
          const {rows:[holder]}=await hold.query<{pid:number}>('SELECT pg_backend_pid() AS pid');
          if (!holder) { throw new Error('Missing anchor lock barrier'); }
          await hold.query('SELECT id FROM foundation.request_sessions WHERE id=$1 FOR UPDATE',[seed.form.sid]);
          first=order === 'revoke-first' ? revoke() : seed.send();
          void first.catch(() => undefined);
          await waitForRequestLock(holder.pid,1);
          second=order === 'revoke-first' ? seed.send() : revoke();
          void second.catch(() => undefined);
          await waitForRequestLock(holder.pid,2);
          await hold.query('ROLLBACK');
          const [a,b]=await Promise.all([first,second]);
          const [withdrawal,submit]=order === 'revoke-first' ? [a,b] : [b,a];
          expect(accepted(withdrawal,201).data()).toMatchObject({action:'REVOKED',sessionId:seed.form.sid,purpose:'REQUEST_PROCESSING'});
          if (order === 'revoke-first') { closedFailure(submit,409,'CONSENT_REQUIRED'); }
          else if (prior) { expect(closed(submit,200,fReceiptKeys).bytes).toBe(prior.bytes); }
          else { closed(submit,201,fReceiptKeys); }
        } finally {
          await hold.query('ROLLBACK').catch(() => undefined);
          hold.release();
          await Promise.allSettled([first,second]);
        }
        const expectedEffects=mode === 'fresh' && order === 'revoke-first' ? 0 : 1;
        expect(await db().count(`SELECT count(*)::int n FROM foundation.request_session_submits WHERE session_id=$1`,[seed.form.sid])).toBe(expectedEffects);
        expect(await db().count(`SELECT count(*)::int n FROM foundation.request_events WHERE actor_session_id=$1 AND operation='CreateCallback'`,[seed.form.sid])).toBe(expectedEffects);
        expect(await db().count(`SELECT count(*)::int n FROM foundation.consent_records WHERE session_id=$1 AND action='REVOKED' AND supersedes_id=$2`,
          [seed.form.sid,seed.evidenceId])).toBe(1);
        closedFailure(await seed.send(),409,'CONSENT_REQUIRED');
        const result=await https('GET',`${pub}/request-session`,undefined,proof(seed.form));
        if (expectedEffects === 0) { closedFailure(result,404,'NOT_FOUND'); }
        else { expect(closed(result,200,['version']).data()).toEqual({version:1}); }
        if (edge) { expect(await captureRequest(edge.request_id)).toEqual(before); }
      }
    }
  },75000);

  it('F lifecycle: post-submit authority, PHONE duplicate and real anchor TTL', async () => {
    // Keep enough live budget for the guarded HTTPS requests before deliberately waiting for expiry.
    const instance=await launchWithPolicy(fixture.policyId,undefined,25000);
    try {
      const targetPort=portOf(instance);
      const call=(method:'GET'|'POST',path:string,body:unknown,headers:Record<string,string>) => https(method,`${pub}${path}`,body,headers,targetPort);
      const seed=await prepareCallback(targetPort);
      const {form}=seed;
      const created=closed(await seed.send(),201,fReceiptKeys);
      const {rows:[edge]}=await db().db.query<{request_id:string; expires_at:Date}>(`SELECT e.request_id,s.expires_at
        FROM foundation.request_session_submits e JOIN foundation.request_sessions s ON s.id=e.session_id WHERE e.session_id=$1`,[form.sid]);
      if (!edge) { throw new Error('Missing live linked F anchor'); }
      const initial=await captureRequest(edge.request_id);
      const own=closed(await call('GET','/request-session',undefined,proof(form)),200,fReceiptKeys);
      expect(own.data()).toEqual(created.data());
      const foreign=await issue(targetPort);
      const fGet='/request-session';
      closedFailure(await call('GET',fGet,undefined,{...proof(foreign),'If-None-Match':tag(own)}),404,'NOT_FOUND');
      closedFailure(await call('GET',fGet,undefined,{...proof(form),Cookie:foreign.cookie,'If-None-Match':tag(own)}),401,'UNAUTHORIZED');
      closedFailure(await call('POST','/callback-requests',seed.body,mutate(foreign,seed.key)),409,'CONSENT_REQUIRED');
      const newConsentKey=randomUUID();
      const give={action:'GIVEN',documentId:fixture.consentDocumentId,documentVersionId:fixture.consentDocumentVersionId,evidenceRef:newConsentKey};
      closedFailure(await call('POST','/form-session/consents',give,mutate(form,newConsentKey)),409,'CONFLICT');
      closedFailure(await seed.send(randomUUID()),409,'FORM_ALREADY_SUBMITTED');
      closedFailure(await call('POST','/repair-requests',{},mutate(form,seed.key)),409,'FORM_ALREADY_SUBMITTED');
      closedFailure(await call('POST','/request-session/contact-mode',{phonePermission:true},mutate(form,undefined,tag(own))),409,'CONFLICT');
      const refreshed=accepted(await call('POST','/form-session/csrf',{},proof(form)),200);
      expect(Object.keys(refreshed.data()).sort()).toEqual(['csrfExpiresAt','csrfToken','expiresAt','sessionId']);
      expect(refreshed.data()).toMatchObject({sessionId:form.sid,expiresAt:edge.expires_at.toISOString()});
      expect(refreshed.headers.etag).toBeUndefined();
      const currentProof={...form,csrf:text(refreshed.data(),'csrfToken')};
      // Advisory lookup is district-only, not a continuation or address validation.
      const advisoryAuth={...proof(currentProof),'X-CSRF-Token':currentProof.csrf};
      const advisory=accepted(await call('POST','/coverage/check',{districtId:fixture.districtId},advisoryAuth),200);
      expect(Object.keys(advisory.data()).sort()).toEqual(['cityId','cityVersionId','districtId','hints','outcome']);
      closedFailure(await call('POST','/coverage/check',{districtId:fixture.districtId,address},advisoryAuth),400,'MALFORMED');
      expect(await captureRequest(edge.request_id)).toEqual(initial);
      // The same F key replays history; new keys do not reapply on no active permission.
      const phonePath='/request-session/phone-permissions';
      const phoneBody={action:'REVOKED'};
      const phoneHeaders=mutate(currentProof,randomUUID(),tag(own));
      const withdraw=closed(await call('POST',phonePath,phoneBody,phoneHeaders),200,['applied','version']);
      expect(withdraw.data()).toEqual({applied:true,version:2});
      const afterPhone=await captureRequest(edge.request_id);
      const phoneAdded=addedHistory(initial,afterPhone,['phone']);
      const givenPhone=initial.history.find(({kind,value})=>kind === 'phone' && value['action'] === 'GIVEN');
      if (!givenPhone) { throw new Error('Missing exact PHONE allow'); }
      expect(phoneAdded('phone')).toMatchObject({action:'REVOKED',supersedes_given_id:givenPhone.value['id'],
        contact_revision_id:initial.row.current_contact_revision_id,event_id:phoneAdded('event')['id']});
      expect(afterPhone.row).toEqual({...initial.row,row_version:2});
      expect(closed(await call('POST',phonePath,phoneBody,phoneHeaders),200,['applied','version']).bytes).toBe(withdraw.bytes);
      closedFailure(await call('POST',phonePath,phoneBody,mutate(currentProof,undefined,tag(own))),412,'VERSION_MISMATCH');
      const afterWithdraw=closed(await call('GET',fGet,undefined,proof(form)),200,fReceiptKeys);
      closedFailure(await call('POST',phonePath,phoneBody,mutate(currentProof,undefined,tag(afterWithdraw))),409,'CONFLICT');
      expect(await captureRequest(edge.request_id)).toEqual(afterPhone);
      const cancelPath='/request-session/cancel';
      const cancelBody={reasonEntryId:fixture.cancelReasonEntryId};
      const cancelHeaders=mutate(currentProof,randomUUID(),tag(afterWithdraw));
      const cancelled=closed(await call('POST',cancelPath,cancelBody,cancelHeaders),200,['applied','version']);
      expect(cancelled.data()).toEqual({applied:true,version:3});
      const afterCancel=await captureRequest(edge.request_id);
      addedHistory(afterPhone,afterCancel,[]);
      expect(afterCancel.row).toEqual({...afterPhone.row,row_version:3,status:'CANCELLED'});
      await db().db.query(`SELECT pg_sleep(greatest(0,extract(epoch FROM ($1::timestamptz-clock_timestamp())))+0.025)`,[edge.expires_at]);
      expect(await db().count('SELECT count(*)::int n FROM foundation.request_sessions WHERE id=$1 AND expires_at <= clock_timestamp() AND revoked_at IS NULL',[form.sid])).toBe(1);
      for (const send of [() => call('GET',fGet,undefined,proof(form)),() => seed.send(),
        () => call('POST',phonePath,phoneBody,phoneHeaders),() => call('POST',cancelPath,cancelBody,cancelHeaders),
        () => call('POST','/form-session/csrf',{},proof(form))]) {
        const dead=await send();
        closedFailure(dead,401,'UNAUTHORIZED');
        expect(dead.headers['set-cookie']?.[0]).toContain(`__Host-fixlevelup_f_${form.sid}=;`);
      }
      expect(await captureRequest(edge.request_id)).toEqual(afterCancel);
    } finally { await instance.app.close(); }
  },55000);

  it('F partial: unreadable receipt fails closed over HTTPS without schema drift', async () => {
    const seed=await prepareCallback();
    const created=closed(await seed.send(),201,fReceiptKeys);
    const {rows:[target]}=await db().db.query<{id:string; event_id:string}>(`SELECT request_id AS id,event_id
      FROM foundation.request_session_submits WHERE session_id=$1`,[seed.form.sid]);
    if (!target) { throw new Error('Missing committed submit edge'); }
    const path=`/requests/${target.id}`;
    const fPath=`${pub}/request-session`;
    const fRead=closed(await https('GET',fPath,undefined,proof(seed.form)),200,fReceiptKeys);
    const staffRead=closed(await https('GET',path,undefined,staff()),200,staffViewKeys);
    const before=await captureRequest(target.id);
    const commandKey=randomUUID();
    const staffCommand=()=>https('POST',`${path}/commands/start-review`,{},staffMutation(commandKey,tag(staffRead)));
    const original=Object.getOwnPropertyDescriptor(Client.prototype,'query')?.value as Client['query'] | undefined;
    if (!original) { throw new Error('Missing test PG query method'); }
    let reads=0;
    // Trusted, test-local result fault after a real admitted connection and real SELECT.
    // Do not delete the receipt, change any ACL/DDL, skip readiness, or inject a write.
    Client.prototype.query=function(this:Client,...args:unknown[]) {
      const [sql,params]=args;
      const result:unknown=Reflect.apply(original,this,args);
      if (typeof sql !== 'string' || !sql.includes('SELECT r.event_id,r.request_id,r.version,r.resulting_status AS status')
        || !Array.isArray(params) || params[0] !== target.event_id || params[1] !== target.id) { return result; }
      return Promise.resolve(result).then((value:unknown) => {
        const rowset=record(value);
        expect(rowset['rowCount']).toBe(1); // persisted effect is demonstrably present, not a fresh request
        reads++;
        return {...rowset,rows:[],rowCount:0};
      });
    } as typeof original;
    try {
      for (const send of [() => seed.send(),() => seed.send(randomUUID()),
        () => https('GET',fPath,undefined,{...proof(seed.form),'If-None-Match':tag(fRead)}),
        () => https('GET',path,undefined,{...staff(),'If-None-Match':tag(staffRead)}),staffCommand]) {
        closedFailure(await send(),503,'NOT_READY');
      }
      expect(reads).toBe(5);
      expect(await captureRequest(target.id)).toEqual(before);
    } finally { Client.prototype.query=original; }
    expect(closed(await seed.send(),200,fReceiptKeys).bytes).toBe(created.bytes);
    expect(await captureRequest(target.id)).toEqual(before);
    closed(await staffCommand(),200,staffReceiptKeys);
    staffEffect(before,await captureRequest(target.id),commandKey,'StartReview',{status:'MANAGER_REVIEW'},[]);
  },60000);

  it('F partial: missing edge and invalid audit or outbox each refuse over HTTPS', async () => {
    const seed=await prepareCallback();
    const created=closed(await seed.send(),201,fReceiptKeys);
    const {rows:[edge]}=await db().db.query<{request_id:string;event_id:string}>(`SELECT request_id,event_id
      FROM foundation.request_session_submits WHERE session_id=$1`,[seed.form.sid]);
    if (!edge) { throw new Error('Missing committed callback edge'); }
    const target={sessionId:seed.form.sid,requestId:edge.request_id,eventId:edge.event_id};
    const fPath=`${pub}/request-session`;
    const staffPath=`/requests/${target.requestId}`;
    const fView=closed(await https('GET',fPath,undefined,proof(seed.form)),200,fReceiptKeys);
    const staffView=closed(await https('GET',staffPath,undefined,staff()),200,staffViewKeys);
    const replay=()=>seed.send();
    const fresh=()=>seed.send(randomUUID());
    const fRead=()=>https('GET',fPath,undefined,{...proof(seed.form),'If-None-Match':tag(fView)});
    const staffRead=()=>https('GET',staffPath,undefined,{...staff(),'If-None-Match':tag(staffView)});
    const staffWrite=()=>https('POST',`${staffPath}/commands/start-review`,{},staffMutation(undefined,tag(staffView)));
    const closePhone=()=>https('POST',`${fPath}/phone-permissions`,{action:'REVOKED'},mutate(seed.form,undefined,tag(fView)));
    await provePartialWire({target,
      sends:{submitEdge:[replay,fresh,fRead,closePhone],good_audit:[replay,fRead,staffRead,staffWrite],good_outbox:[replay,fRead,staffRead,staffWrite]},
      assertClosed503:reply=>{ closedFailure(reply,503,'NOT_READY'); },
      snapshot:({requestId})=>captureRequest(requestId),
      async assertRecovered() {
        expect(closed(await replay(),200,fReceiptKeys).bytes).toBe(created.bytes);
        expect(accepted(await fRead(),304).bytes).toBe('');
        expect(accepted(await staffRead(),304).bytes).toBe('');
      },
    });
  },90000);
});
