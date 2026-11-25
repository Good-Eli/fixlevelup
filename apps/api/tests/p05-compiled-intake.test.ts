import { execFileSync } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { freshGarageBucket } from '../../../infra/file-restore/resources.mjs';
import { lockAccessPolicy } from '../src/authz/rbac-lock.js';
import { createConfigurationFixture } from './configuration-fixture.js';
import { TECHNICAL_TIMEOUTS } from './file-storage-fixture.js';
import { RequestOfferFixture } from './p05-offer-fixture.js';
import type { NativeBusinessInput } from './p05-native-business.js';
import { seedRequestFixtures, supportedFixturePolicies } from './p05-request-fixtures.js';
import type { RequestFixtures } from './p05-request-fixtures.js';
import { startLauncher } from './launcher-harness.js';
import { fixtureCredentials } from './owned-test-database.js';

const root = resolve(import.meta.dirname, '../../..');
const enabled = process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1'
  && process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1';

/** Executed by native Node from a fresh tsc output, not transformed by Vitest.
 * Only F paths run here; the larger HTTPS suite covers staff and the offer port.
 * Synthetic TLS keys are read from this run's scratch files, never IPC/env/argv. */
function childSource(paths: { build: string; ssl: string }, settings: RequestFixtures, keys: readonly string[]) {
  const url = (file: string) => JSON.stringify(pathToFileURL(resolve(paths.build, file)).href);
  const fixture = JSON.stringify({ policyId: settings.policyId, workflowVersion: settings.workflowVersion,
    policyRevision: settings.policyRevision, source: settings.formSourceEntryId, doc: settings.consentDocumentId,
    version: settings.consentDocumentVersionId });
  return `
    import assert from 'node:assert/strict';
    import {readFileSync} from 'node:fs';
    import {createRequire} from 'node:module';
    import {randomBytes, randomUUID} from 'node:crypto';
    import {request} from 'node:https';
    import {startIsolatedIntake} from ${url('tests/p05-composition.js')};
    import {createSyntheticKeySlots} from ${url('tests/p05-key-slot-fixture.js')};
    import {loadRuntimeAdmission} from ${url('src/infrastructure/admission/runtime-admission.js')};
    import {admitProcess} from ${url('src/infrastructure/admission/process-admission.js')};
    import {loadKeyring} from ${url('src/requests/crypto/keyring.js')};
    const {Client} = createRequire(${JSON.stringify(pathToFileURL(resolve(root,'apps/api/package.json')).href)})('pg');
    assert(!Object.keys(process.env).some(k => /^(?:FIXLEVELUP_(?:LAB_ORCHESTRATOR|MIGRATOR)|LAUNCH_CONTROL_|POSTGRES_)/.test(k)));
    const target = {host:'127.0.0.1',port:55432,database:process.env.DB_NAME,user:'fixlevelup_runtime',password:process.env.DB_PASSWORD};
    const admission = loadRuntimeAdmission(process.env,{database:target,requiredConsumer:'TEST'});
    const authorization = await admitProcess(admission,{database:target,approvalTimeoutMs:10000});
    const {policyId,source,doc,version} = ${fixture};
    const keys = ${JSON.stringify(keys)};
    const origin = 'https://intake-compiled.example.test';
    const secret = () => randomBytes(32).toString('hex');
    const ring = loadKeyring({activeKekId:'compiled-kek-1',activeHmacKeyId:'compiled-hmac-1',
      kek:[{keyId:'compiled-kek-1',secretHex:secret()}],hmac:[{keyId:'compiled-hmac-1',secretHex:secret()}]});
    const cert = readFileSync(${JSON.stringify(resolve(paths.ssl,'t-cert.pem'))});
    const key = readFileSync(${JSON.stringify(resolve(paths.ssl,'t-key.pem'))});
    const managed = await createSyntheticKeySlots('compiled-t');
    const {app} = await startIsolatedIntake({ target,authorization,tls:{cert,key},staff:{origin,csrfSecret:secret()},
      form:{origin,csrfKeyring:{current:{keyId:'compiled-csrf',secret:randomBytes(32)}},throttleSecret:randomBytes(32),
        groupTtlMs:900000,anchorTtlMs:600000,csrfTtlMs:300000,
        throttles:{source:{windowSeconds:600,maxHits:50},global:{windowSeconds:600,maxHits:50},anchor:{windowSeconds:600,maxHits:20}}},
      configure:() => ({ring,environment:'compiled-t',keySlots:managed.slots,currentPolicyId:policyId,formSourceEntryId:source,
        supportedPolicies:new Map(${JSON.stringify([...supportedFixturePolicies()])})}) })
       .catch(async error => { await managed.close(); throw error; });
    const armed = new WeakSet(), uncertain = new WeakSet();
    const original = Client.prototype.query;
    let mode, injected = 0, rollbacks = 0;
    Client.prototype.query = function(...args) {
      const sql = args[0];
      if (typeof sql === 'string' && mode && sql.includes('INSERT INTO foundation.request_command_receipts')) { armed.add(this); }
      if (sql === 'COMMIT' && armed.delete(this)) {
        const requested = mode;
        mode = undefined;
        injected += 1;
        uncertain.add(this);
        const result = requested === 'commit' ? Reflect.apply(original,this,args) : undefined;
        return Promise.resolve(result).then(() => { throw Object.assign(new Error('Synthetic ACK loss'),{code:'ECONNRESET'}); });
      }
      if (sql === 'ROLLBACK' && uncertain.has(this)) { rollbacks += 1; }
      return Reflect.apply(original,this,args);
    };
    const port = app.getHttpServer().address().port;
    function call(path, body, headers={}) {
      return new Promise((success,fail) => {
        const entity = JSON.stringify(body);
        const req = request({ host:'127.0.0.1',port,path:'/api/v1/public'+path,method:'POST',agent:false,ca:cert,
          headers:{ origin,'content-type':'application/json','content-length':Buffer.byteLength(entity),...headers } }, res => {
          const chunks=[];
          res.on('data',c=>chunks.push(c));
          res.once('error',fail);
          res.once('end',()=>{
            const bytes=Buffer.concat(chunks).toString('utf8');
            try { success({status:res.statusCode,cookie:res.headers['set-cookie']?.[0]?.split(';')[0],bytes,json:JSON.parse(bytes)}); }
            catch (error) { fail(error); }
          });
        });
        req.setTimeout(15000,()=>req.destroy(new Error('Isolated request deadline')));
        req.once('error',fail);
        req.end(entity);
      });
    }
    try {
      for (const [i,branch] of ['commit','abort'].entries()) {
        const group=await call('/form-session/browser',{}, {'x-form-session-bootstrap':'1'});
        assert.equal(group.status,200);
        const anchor=await call('/form-sessions',{},{cookie:group.cookie});
        assert.equal(anchor.status,201);
        const auth={cookie:anchor.cookie,'x-form-session-id':anchor.json.data.sessionId,'x-csrf-token':anchor.json.data.csrfToken};
        const consentKey=randomUUID();
        const consent=await call('/form-session/consents',{ action:'GIVEN',documentId:doc,documentVersionId:version,evidenceRef:consentKey },
          {...auth,'idempotency-key':consentKey});
        assert.equal(consent.status,201);
        const body={contact:{name:'Compiled synthetic marker',phone:'+15550100009'},phonePermission:true,
          consent:{evidenceId:consent.json.data.evidenceId,documentVersionId:version,accepted:true}};
        const headers={...auth,'idempotency-key':keys[i]};
        mode=branch;
        const ambiguous=await call('/callback-requests',body,headers);
        assert.equal(ambiguous.status,503);
        assert.equal(ambiguous.json.code,'NOT_READY');
        assert(!ambiguous.bytes.includes('Compiled synthetic marker'));
        const resolved=await call('/callback-requests',body,headers);
        assert.equal(resolved.status,branch==='commit'?200:201);
        const replay=await call('/callback-requests',body,headers);
        assert.equal(replay.status,200);
        assert.equal(replay.bytes,resolved.bytes);
        assert.equal(replay.json.data.version,1);
      }
      assert.equal(injected,2);
      assert.equal(rollbacks,0);
      console.log('COMPILED_T_OK');
    } finally { Client.prototype.query=original; try { await app.close(); } finally { await managed.close(); } }
  `;
}

it.runIf(enabled)('compiled T OS child verifies real admit/HTTPS and both uncertain submit outcomes without a duplicate', async () => {
  const api = resolve(root,'apps/api');
  const parent = resolve(api,'build');
  mkdirSync(parent,{recursive:true});
  const build = mkdtempSync(resolve(parent,'p05-t-'));
  const ssl = mkdtempSync(resolve(tmpdir(),'p05-compiled-tls-'));
  let fixture: Awaited<ReturnType<typeof createConfigurationFixture>> | undefined;
  let launch: Awaited<ReturnType<typeof startLauncher>> | undefined;
  try {
    const compiler=resolve(root,'node_modules/typescript/bin/tsc');
    execFileSync(process.execPath,[compiler,'-p',resolve(api,'tsconfig.p05-test-build.json'),'--outDir',build],{cwd:root,timeout:90000,stdio:'pipe'});
    execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
      '-addext','subjectAltName=IP:127.0.0.1,DNS:localhost','-keyout',resolve(ssl,'t-key.pem'),'-out',resolve(ssl,'t-cert.pem')],
    {timeout:10000,stdio:'ignore'});
    expect(readFileSync(resolve(build,'tests/p05-composition.js'),'utf8')).toContain('startIsolatedIntake');
    fixture=await createConfigurationFixture();
    const settings=await seedRequestFixtures({db:fixture.migrator},{reviewerId:fixture.reviewer});
    const {runtime,migrator}=fixtureCredentials();
    const target={host:'127.0.0.1' as const,port:55432,database:fixture.database};
    launch=await startLauncher('TEST',{runtime:{...target,user:'fixlevelup_runtime',password:runtime},
      operator:{...target,user:'fixlevelup_migrator',password:migrator},isolatedArtifactRoot:build,
      artifactPaths:[resolve(build,'tests/p05-composition.js'),resolve(build,'src/requests/intake/service.js')]});
    const keys=[randomUUID(),randomUUID()];
    const outcome=await launch.launch({env:{NODE_ENV:'test'},timeoutMs:60000,source:childSource({build,ssl},settings,keys)});
    expect(outcome.acked).toBe(true);
    expect(outcome.exitCode,outcome.stderr).toBe(0);
    expect(outcome.stdout).toContain('COMPILED_T_OK');
    expect(outcome.stderr).toBe('');
    const { rows }=await fixture.migrator.query<{ complete: boolean }>(`SELECT count(*)=2
      AND count(DISTINCT e.request_id)=2 AND count(DISTINCT e.idempotency_key)=2 AS complete
      FROM foundation.request_events e JOIN foundation.request_command_receipts r ON r.event_id=e.id
      JOIN foundation.request_session_submits s ON s.event_id=e.id JOIN foundation.audit_logs a ON a.id=r.audit_id
      JOIN foundation.outbox_events o ON o.id=r.outbox_id WHERE e.idempotency_key=ANY($1::uuid[])
        AND e.resulting_version=1 AND o.event_id=e.id AND o.event_type='REQUEST_CALLBACK_INTENT'`,[keys]);
    expect(rows).toEqual([{complete:true}]);
  } finally {
    try { await launch?.close(); } finally { await fixture?.close(); }
    if (realpathSync(build)===build && /^p05-t-[A-Za-z0-9]+$/.test(relative(parent,build))) {
      rmSync(build,{recursive:true,force:true});
    }
    if (realpathSync(ssl)===ssl && /^p05-compiled-tls-[A-Za-z0-9]+$/.test(relative(tmpdir(),ssl))) {
      rmSync(ssl,{recursive:true,force:true});
    }
  }
},120000);

const engines = enabled && process.env['FIXLEVELUP_FILE_PROCESSING_TESTS'] === '1'
  && process.env['FIXLEVELUP_STORAGE_S3_TESTS'] === '1' && process.env['FIXLEVELUP_FILE_RESTORE_TESTS'] === '1';

it.runIf(engines)('compiled T admits manual and no-call repair with real READY, exact replay and no PHONE inheritance', async () => {
  const ticket = process.env['FIXLEVELUP_LAB_ENGINE_TICKET'];
  const descriptor = process.env['FIXLEVELUP_FILE_PROCESSING_FIXTURE'];
  if (!ticket || !/^[a-f0-9]{32}$/u.test(ticket) || descriptor !== '/p05lab-engine-fixture.json') {
    throw new Error('A reviewed, isolated engine ticket is required');
  }
  const api = resolve(root, 'apps/api');
  const parent = resolve(api, 'build');
  mkdirSync(parent, { recursive: true });
  const build = mkdtempSync(resolve(parent, 'p05-t-'));
  const ssl = mkdtempSync(resolve(tmpdir(), 'p05-compiled-tls-'));
  let fixture: Awaited<ReturnType<typeof createConfigurationFixture>> | undefined;
  let launch: Awaited<ReturnType<typeof startLauncher>> | undefined;
  try {
    const compiler = resolve(root, 'node_modules/typescript/bin/tsc');
    execFileSync(process.execPath, [compiler, '-p', resolve(api, 'tsconfig.p05-test-build.json'), '--outDir', build],
      { cwd: root, timeout: 90_000, stdio: 'inherit' });
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost', '-keyout', resolve(ssl, 't-key.pem'), '-out', resolve(ssl, 't-cert.pem')],
    { timeout: 10_000, stdio: 'ignore' });
    fixture = await createConfigurationFixture();
    const { migrator, reviewer, database } = fixture;
    const settings = await seedRequestFixtures({ db: migrator }, { reviewerId: reviewer });
    const offer = await RequestOfferFixture.attach({ db: migrator }, { provider: 'TG' });
    const namespace = randomUUID();
    const bucket = freshGarageBucket(namespace);
    const token = randomBytes(32).toString('base64url');
    const staged = await migrator.connect();
    try {
      await staged.query('BEGIN');
      await lockAccessPolicy(staged, 'write');
      await staged.query(`INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
        SELECT r.id,c,'GLOBAL' FROM foundation.roles r CROSS JOIN unnest($1::text[]) c
        WHERE r.role_type='SYSTEM' AND r.code='ADMIN'`, [['requests.read','requests.create']]);
      expect((await staged.query(`INSERT INTO foundation.web_sessions(id,staff_id,token_hash,auth_version,idle_expires_at,absolute_expires_at,channel)
        SELECT $1,id,$3,auth_version,clock_timestamp()+interval '10 minutes',clock_timestamp()+interval '20 minutes','CRM'
        FROM foundation.staff WHERE id=$2`, [randomUUID(), reviewer, createHash('sha256').update(token).digest('hex')])).rowCount).toBe(1);
      await staged.query(`INSERT INTO foundation.file_runtime_epochs (singleton,namespace_id,epoch,mode) VALUES (true,$1,1,'ACTIVE')`, [namespace]);
      await staged.query('COMMIT');
    } finally { try { await staged.query('ROLLBACK'); } finally { staged.release(); } }
    const source = (await migrator.query<{ id: string }>('SELECT current_version_id AS id FROM foundation.reference_entries WHERE id=$1',
      [settings.formSourceEntryId])).rows[0];
    if (!source) { throw new Error('Missing pinned reference fixture'); }
    const input: NativeBusinessInput = { settings, actor: { id: reviewer, token }, sourceVersionId: source.id,
      offer: { schema: offer.schema, ids: offer.ids }, keys: [randomUUID(), randomUUID()],
      file: { namespace, ticket, descriptor, bridge: pathToFileURL(resolve(root, 'infra/file-processing/p05-lab-engine-client.mjs')).href,
        target: { mode: 'local-synthetic', ...bucket.target, ...bucket.rw, allowedEndpoint: bucket.target.endpoint, ...TECHNICAL_TIMEOUTS } } };
    // As with the ephemeral TLS key: do not embed temporary credentials in argv or logs.
    const inputFile = resolve(ssl, 'native-business.json');
    writeFileSync(inputFile, JSON.stringify(input), { flag: 'wx', mode: 0o600 });
    const creds = fixtureCredentials();
    const target = { host: '127.0.0.1' as const, port: 55432, database };
    const native = resolve(build, 'tests/p05-native-business.js');
    const fileUrl = (path: string) => JSON.stringify(pathToFileURL(resolve(build, path)).href);
    launch = await startLauncher('TEST', { runtime: { ...target, user: 'fixlevelup_runtime', password: creds.runtime },
      operator: { ...target, user: 'fixlevelup_migrator', password: creds.migrator }, isolatedArtifactRoot: build,
      artifactPaths: [native, resolve(build, 'tests/p05-composition.js'), resolve(build, 'tests/p05-native-ready.js')] });
    const outcome = await launch.launch({ env: { NODE_ENV: 'test' }, timeoutMs: 150_000, source: `
      import assert from 'node:assert/strict';
      import {readFileSync} from 'node:fs';
      import {runNativeBusiness} from ${fileUrl('tests/p05-native-business.js')};
      import {loadRuntimeAdmission} from ${fileUrl('src/infrastructure/admission/runtime-admission.js')};
      import {admitProcess} from ${fileUrl('src/infrastructure/admission/process-admission.js')};
      assert(!Object.keys(process.env).some(k=>/^(?:FIXLEVELUP_(?:LAB_ORCHESTRATOR|MIGRATOR)|LAUNCH_CONTROL_|POSTGRES_)/.test(k)));
      const database={host:'127.0.0.1',port:55432,database:process.env.DB_NAME,user:'fixlevelup_runtime',password:process.env.DB_PASSWORD};
      const loaded=loadRuntimeAdmission(process.env,{database,requiredConsumer:'TEST'});
      const authorization=await admitProcess(loaded,{database,approvalTimeoutMs:10000});
      const input=JSON.parse(readFileSync(${JSON.stringify(inputFile)},'utf8'));
      await runNativeBusiness(input,database,authorization,{key:readFileSync(${JSON.stringify(resolve(ssl, 't-key.pem'))}),
        cert:readFileSync(${JSON.stringify(resolve(ssl, 't-cert.pem'))})});
    ` });
    expect(outcome.acked).toBe(true);
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(outcome.stderr).toBe('');
    expect(outcome.stdout).toContain('COMPILED_T_MANUAL_NO_CALL_READY_OK');
    const { rows } = await migrator.query<{ manual: boolean; no_call: boolean }>(`SELECT
      count(*) FILTER (WHERE e.idempotency_key=$1 AND e.actor_type='STAFF' AND e.actor_staff_id=$3
        AND r.resulting_status='NEW' AND c.request_id IS NULL AND f.request_id IS NULL AND s.request_id IS NULL
        AND (SELECT count(*) FROM foundation.phone_permission_events p WHERE p.request_id=e.request_id AND p.action='GIVEN')=1
        AND (SELECT count(*) FROM foundation.request_staff_evidence pr WHERE pr.request_id=e.request_id)=2)=1 AS manual,
      count(*) FILTER (WHERE e.idempotency_key=$2 AND e.actor_type='F' AND e.actor_session_id=s.session_id
        AND r.resulting_status='WAITING_TELEGRAM_LINK' AND c.provider='TG' AND c.catalog_version_id=$4 AND c.option_version_id=$5
        AND f.owner_session_id=s.session_id AND f.open_state='OPEN' AND b.id=f.file_id AND b.served_bytes>0
        AND dc.delete_state='OPEN' AND raw.verified_sha256=b.raw_sha256 AND clean.verified_sha256=b.served_sha256
        AND NOT EXISTS(SELECT FROM foundation.phone_permission_events p WHERE p.request_id=e.request_id))=1 AS no_call
      FROM foundation.request_events e JOIN foundation.request_command_receipts r ON r.event_id=e.id
      JOIN foundation.audit_logs a ON a.id=r.audit_id JOIN foundation.outbox_events o ON o.id=r.outbox_id AND o.event_id=e.id
      LEFT JOIN foundation.request_channel_choices c ON c.request_id=e.request_id
      LEFT JOIN foundation.request_session_submits s ON s.event_id=e.id
      LEFT JOIN foundation.request_files f ON f.request_id=e.request_id
      LEFT JOIN foundation.file_publications b ON b.id=f.file_id
      LEFT JOIN foundation.file_privacy_controls dc ON dc.intent_id=f.intent_id
      LEFT JOIN foundation.file_quarantine_objects q ON q.id=b.quarantine_id
      LEFT JOIN foundation.file_upload_attempts raw ON raw.id=q.attempt_id AND raw.state='VERIFIED'
      LEFT JOIN foundation.file_sanitized_attempts clean ON clean.id=b.sanitized_attempt_id AND clean.state='VERIFIED'
      WHERE e.command='CreateRepair' AND e.resulting_version=1 AND e.idempotency_key IN ($1,$2)`,
    [...input.keys, reviewer, offer.ids.catalogVersionId, offer.ids.optionVersionId]);
    expect(rows).toEqual([{ manual: true, no_call: true }]);
  } finally {
    try { await launch?.close(); } finally { await fixture?.close(); }
    if (realpathSync(build) === build && /^p05-t-[A-Za-z0-9]+$/u.test(relative(parent, build))) { rmSync(build, { recursive: true, force: true }); }
    if (realpathSync(ssl) === ssl && /^p05-compiled-tls-[A-Za-z0-9]+$/u.test(relative(tmpdir(), ssl))) { rmSync(ssl, { recursive: true, force: true }); }
  }
}, 180_000);
