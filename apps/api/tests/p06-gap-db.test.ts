/**
 * P06 gap proof (isolated T): direct SQL authority and DB-enforced invariants.
 *
 * Every statement here is executed as `fixlevelup_runtime` (the production
 * runtime role) with no Nest service in the path. The question it answers is:
 * which P06 invariants does PostgreSQL itself enforce (grants, SECURITY DEFINER
 * boundary, triggers, deferred recheck), and which ones can only be enforced by
 * the application transaction?
 *
 * The follow-up audit moved the internal-comment write behind
 * `p06_crm.insert_internal_comment(...)` and revoked direct DML on
 * `p06_crm.comments`. This suite proves that boundary and the failure modes
 * around it, including the deferred basis recheck at COMMIT.
 *
 * Opt-in: FIXLEVELUP_P06_GAP_PROOF=1 + the standard isolated lab flags and
 * FIXLEVELUP_P06_COMMENT_PROOF=1 (the comment overlay is required).
 */
import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { request as httpsRequest } from 'node:https';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { Client } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { decodeP05ManualRequest } from '@fixlevelup/p03-contracts/p05';
import { P05_CAPABILITIES } from '../src/authz/capability.js';
import { lockAccessPolicy } from '../src/authz/rbac-lock.js';
import { canonicalJson } from '../src/infrastructure/admission/proof.js';
import { loadKeyring } from '../src/requests/crypto/keyring.js';
import type { KeyringConfig } from '../src/requests/crypto/keyring.js';
import { createContactAudit } from '../src/requests/card/contacts.js';
import { COMMENT_KEY_ENVIRONMENT } from '../src/requests/card/comments.js';
import { fixtureCredentials } from './owned-test-database.js';
import { RbacFixture, record, text } from './rbac-fixture.js';
import { seedPolicyPackage, seedRequestFixtures, supportedFixturePolicies } from './p05-request-fixtures.js';
import type { RequestFixtures } from './p05-request-fixtures.js';
import { RequestOfferFixture } from './p05-offer-fixture.js';
import { startIsolatedIntake } from './p05-composition.js';
import { createSyntheticKeySlots } from './p05-key-slot-fixture.js';
import { installCommentFixture } from './p06-comment-fixture.js';
import { installSearchFixture } from './p06-search-fixture.js';
import { withHttpMatrixActors } from './p05-http-matrix-actors.js';
import type { StaffEvidence, StaffEvidencePort } from '../src/requests/intake/basis.js';

const origin = 'https://crm.example.test';
const enabled = process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1'
  && process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1'
  && process.env['FIXLEVELUP_P06_GAP_PROOF'] === '1'
  && process.env['FIXLEVELUP_P06_COMMENT_PROOF'] === '1'
  && process.env['FIXLEVELUP_P06_SEARCH_PROOF'] === '1';
const contact = Object.freeze({ name: 'Synthetic gap sentinel', phone: '+15550130001' });
const address = Object.freeze({ street: 'Synthetic gap street', building: '7' });
const commentAudit = 'P06_ADD_INTERNAL_COMMENT';
const functionSignature = 'p06_crm.insert_internal_comment(uuid,uuid,uuid,uuid,text,integer,uuid,text,bytea,bytea,bytea,bytea,text,uuid)';

interface Reply {
  readonly status: number;
  readonly bytes: string;
  readonly headers: import('node:http').IncomingHttpHeaders;
  data(): Record<string, unknown>;
}

describe.runIf(enabled)('P06 gap: runtime SQL grants and DB-enforced comment boundary', () => {
  let base: RbacFixture | undefined;
  let fixture: RequestFixtures;
  let app: Awaited<ReturnType<typeof startIsolatedIntake>> | undefined;
  let cert: Buffer;
  let staffTlsKey: Buffer;
  let port = 0;
  let offers: RequestOfferFixture;
  let keyring: KeyringConfig;
  let managed: Awaited<ReturnType<typeof createSyntheticKeySlots>> | undefined;
  let managedComments: Awaited<ReturnType<typeof createSyntheticKeySlots>> | undefined;
  let sessionId = '';
  let staffCsrf = '';
  const evidence = new Map<string, StaffEvidence & Parameters<StaffEvidencePort['verify']>[1]>();

  function db() {
    if (!base) { throw new Error('Missing fixture'); }
    return base;
  }

  beforeAll(async () => {
    const lab = new RbacFixture({ p04: true });
    base = lab;
    await lab.start();
    fixture = await seedRequestFixtures(lab, { reviewerId: lab.admin.id });
    await seedPolicyPackage(lab, { workflowVersion: fixture.workflowVersion });
    offers = await RequestOfferFixture.attach(lab, { provider: 'TG' });
    await lab.db.query(`INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
      SELECT r.id,c,'GLOBAL' FROM foundation.roles r CROSS JOIN unnest($1::text[]) c WHERE r.role_type='SYSTEM' AND r.code='ADMIN'`,
    [P05_CAPABILITIES]);
    const dir = mkdtempSync(resolve(tmpdir(), 'p06-gap-db-tls-'));
    try {
      const pem = resolve(dir, 'server.pem');
      const privateKey = resolve(dir, 'server.key');
      const openssl = existsSync('C:\\Program Files\\Git\\usr\\bin\\openssl.exe')
        ? 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe' : 'openssl';
      execFileSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
        '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost', '-keyout', privateKey, '-out', pem], { stdio: 'ignore', timeout: 10000 });
      cert = readFileSync(pem);
      staffTlsKey = readFileSync(privateKey);
    } finally { rmSync(dir, { recursive: true, force: true }); }
    keyring = loadKeyring({ activeKekId: 'test-kek-1', activeHmacKeyId: 'test-hmac-1',
      kek: [{ keyId: 'test-kek-1', secretHex: randomBytes(32).toString('hex') }],
      hmac: [{ keyId: 'test-hmac-1', secretHex: randomBytes(32).toString('hex') }] });
    managed = await createSyntheticKeySlots('p05-isolated');
    managedComments = await createSyntheticKeySlots(COMMENT_KEY_ENVIRONMENT);
    await installCommentFixture(lab);
    await installSearchFixture(lab);
    const csrf = randomBytes(32).toString('hex');
    staffCsrf = csrf;
    const policies = new Map(supportedFixturePolicies());
    const settings = { ring: keyring, keySlots: managed.slots, environment: 'p05-isolated',
      currentPolicyId: fixture.policyId, supportedPolicies: policies, formSourceEntryId: fixture.formSourceEntryId };
    const evidencePort: StaffEvidencePort = {
      async verify(_client, expected) {
        await Promise.resolve();
        const verified = evidence.get(expected.id);
        return verified?.purpose === expected.purpose && verified.staffId === expected.staffId
          && verified.target === expected.target && verified.canonicalIntent === expected.canonicalIntent ? verified : undefined;
      },
      async isCurrent(client, proof) {
        await client.query('SELECT 1');
        return evidence.get(proof.id)?.procedureRevision === proof.procedureRevision;
      },
      async openRegistry(client) {
        await client.query('SELECT 1');
        return proof => evidence.get(proof.id)?.procedureRevision === proof.procedureRevision;
      },
    };
    app = await startIsolatedIntake({
      target: { host: '127.0.0.1', port: 55432, database: lab.database, user: 'fixlevelup_runtime', password: fixtureCredentials().runtime },
      authorization: lab.admitted.authorization,
      tls: { key: staffTlsKey, cert },
      staff: { origin, csrfSecret: csrf },
      form: { origin, csrfKeyring: { current: { keyId: 'csrf-t1', secret: randomBytes(32) } }, throttleSecret: randomBytes(32),
        groupTtlMs: 900000, anchorTtlMs: 600000, csrfTtlMs: 300000,
        throttles: { source: { windowSeconds: 600, maxHits: 300 }, global: { windowSeconds: 600, maxHits: 300 },
          anchor: { windowSeconds: 600, maxHits: 60 } } },
      configure: audit => ({ ...settings, offers, staffEvidence: evidencePort,
        comments: { ring: keyring, keySlots: managedComments?.slots },
        contactAudit: createContactAudit(audit) } as never),
    });
    const server = app.app.getHttpServer() as import('node:https').Server;
    const bind = server.address();
    if (!bind || typeof bind === 'string' || bind.address !== '127.0.0.1') { throw new Error('Missing isolated TLS server'); }
    port = bind.port;
    const tokenHash = createHash('sha256').update(lab.admin.token).digest('hex');
    const { rows: [session] } = await lab.db.query<{ id: string }>(
      'SELECT id FROM foundation.web_sessions WHERE token_hash=$1', [tokenHash]);
    if (!session) { throw new Error('Missing synthetic CRM session'); }
    sessionId = session.id;
  }, 120000);

  afterAll(async () => {
    try { await app?.app.close(); } finally {
      try { await managed?.close(); } finally {
        try { await managedComments?.close(); } finally { await base?.close(); }
      }
    }
  }, 20000);

  function https(method: 'GET' | 'POST', path: string, payload?: unknown,
    headers: Record<string, string> = {}): Promise<Reply> {
    return new Promise((ok, fail) => {
      const body = payload === undefined ? undefined : JSON.stringify(payload);
      const req = httpsRequest({ method, host: '127.0.0.1', port, path: `/api/v1${path}`, ca: cert, agent: false,
        headers: { Origin: origin, ...(body === undefined ? {} : { 'Content-Type': 'application/json',
          'Content-Length': String(Buffer.byteLength(body)) }), ...headers } }, res => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.once('error', fail);
        res.once('end', () => {
          const bytes = Buffer.concat(chunks).toString('utf8');
          ok({ status: res.statusCode ?? 0, bytes, headers: res.headers,
            data: () => record(record(JSON.parse(bytes) as unknown)['data']) });
        });
      });
      req.setTimeout(20000, () => req.destroy(new Error('Isolated HTTPS deadline')));
      req.once('error', fail);
      req.end(body);
    });
  }

  async function manualPrepared(ttlMs = 600000) {
    const source = (await db().db.query<{ version: string }>(
      'SELECT current_version_id AS version FROM foundation.reference_entries WHERE id=$1',
      [fixture.formSourceEntryId])).rows[0];
    if (!source) { throw new Error('Missing synthetic source'); }
    const key = randomUUID();
    const body = decodeP05ManualRequest({ type: 'REPAIR', sourceEntryId: fixture.formSourceEntryId,
      evidenceId: randomUUID(), contact: { ...contact, mode: 'PHONE', phonePermission: true, phoneEvidenceId: randomUUID() },
      address: { ...address, districtId: fixture.districtId }, appliance: { categoryId: fixture.categoryId },
      fault: { faultIds: [fixture.faultId] } });
    if (body.type !== 'REPAIR' || body.contact.mode !== 'PHONE') { throw new Error('Wrong test DTO'); }
    const target = canonicalJson({ cityId: fixture.cityId, cityVersionId: fixture.cityVersionId,
      sourceVersionId: source.version, operation: 'CreateRepair', key });
    const phoneEvidenceId = body.contact.phoneEvidenceId;
    return { body, key, authorize: () => {
      for (const id of [body.evidenceId, phoneEvidenceId]) {
        evidence.set(id, { id, purpose: id === body.evidenceId ? 'MANUAL_INTAKE' : 'PHONE_GIVE',
          staffId: db().admin.id, target, canonicalIntent: canonicalJson(body), procedureRevision: 'fixture-v1',
          validUntil: new Date(Date.now() + ttlMs) });
      }
    } };
  }

  async function createManualRequest(ttlMs = 600000): Promise<{ id: string; version: number }> {
    const prepared = await manualPrepared(ttlMs);
    prepared.authorize();
    const csrf = createHmac('sha256', staffCsrf).update('web-auth-csrf\0').update(db().admin.token).digest('base64url');
    const reply = await https('POST', '/requests', prepared.body,
      { Cookie: db().admin.cookie, 'X-CSRF-Token': csrf, 'Idempotency-Key': prepared.key });
    expect(reply.status, reply.bytes).toBe(201);
    const id = text(reply.data(), 'id');
    const { rows: [row] } = await db().db.query<{ version: number }>(
      'SELECT row_version AS version FROM foundation.requests WHERE id=$1', [id]);
    if (!row) { throw new Error('Missing created request'); }
    return { id, version: row.version };
  }
  async function grantComment(staffId: string, cityId: string, write: boolean): Promise<void> {
    const client = await db().db.connect();
    try {
      await client.query('BEGIN');
      await lockAccessPolicy(client, 'write');
      await client.query(`INSERT INTO p06_crm.comment_grants(staff_id,city_id,can_read,can_write)
        VALUES ($1,$2,true,$3) ON CONFLICT (staff_id,city_id) DO UPDATE SET can_read=true,can_write=excluded.can_write`,
      [staffId, cityId, write]);
      await client.query('COMMIT');
    } finally {
      try { await client.query('ROLLBACK'); } finally { client.release(); }
    }
  }

  async function runtime(): Promise<Client> {
    const client = new Client({ host: '127.0.0.1', port: 55432, database: db().database,
      user: 'fixlevelup_runtime', password: fixtureCredentials().runtime, application_name: 'p06-gap-direct' });
    await client.connect();
    return client;
  }

  const commentRows = (requestId: string) => db().count(
    'SELECT count(*)::int AS n FROM p06_crm.comments WHERE request_id=$1', [requestId]);
  const auditRows = (commentId: string) => db().count(
    'SELECT count(*)::int AS n FROM foundation.audit_logs WHERE operation=$1 AND correlation_id=$2',
    [commentAudit, commentId]);

  interface CommentInput {
    readonly requestId: string;
    readonly version: number;
    readonly id?: string;
    readonly authorId?: string;
    readonly authSessionId?: string;
    readonly token?: string;
    readonly idempotencyKey?: string;
    readonly auditId?: string;
  }

  function functionParameters(input: CommentInput): unknown[] {
    return [input.id ?? randomUUID(), input.requestId, input.authorId ?? db().admin.id,
      input.authSessionId ?? sessionId, input.token ?? db().admin.token, input.version,
      input.idempotencyKey ?? randomUUID(), 'test-hmac-1', randomBytes(32), randomBytes(12), randomBytes(48),
      randomBytes(16), 'p06-gap-direct', input.auditId ?? randomUUID()];
  }

  /** Runs the DB writer and reports the SQLSTATE of the statement or of COMMIT. */
  async function write(client: Client, parameters: unknown[], commit = true) {
    await client.query('BEGIN');
    let statement: string | undefined;
    let commitCode: string | undefined;
    try {
      await client.query(`SELECT * FROM p06_crm.insert_internal_comment(${parameters.map((_, index) => `$${String(index + 1)}`).join(',')})`,
        parameters);
      if (commit) {
        try { await client.query('COMMIT'); }
        catch (error) {
          commitCode = (error as { code?: string }).code;
          await client.query('ROLLBACK').catch(() => undefined);
        }
      } else { await client.query('ROLLBACK'); }
    } catch (error) {
      statement = (error as { code?: string }).code;
      await client.query('ROLLBACK').catch(() => undefined);
    }
    return { statement, commitCode };
  }

  it('grants the runtime role no direct DML on the comment overlay', async () => {
    const client = await runtime();
    try {
      await expect(client.query('SELECT id FROM p06_crm.comments LIMIT 0')).resolves.toBeDefined();
      await expect(client.query('SELECT staff_id FROM p06_crm.comment_grants LIMIT 0')).resolves.toBeDefined();
      await expect(client.query('SELECT request_id FROM p06_crm.contact_search LIMIT 0')).resolves.toBeDefined();
      await expect(client.query(`SELECT proname FROM pg_proc WHERE oid='${functionSignature}'::regprocedure`))
        .resolves.toBeDefined();
      const denied = [
        ['INSERT comments', `INSERT INTO p06_crm.comments(id,request_id,author_id,auth_session_id,auth_token_hash,
          request_version,idempotency_key,idem_key_id,fingerprint,nonce,ciphertext,auth_tag,aad_context,audit_id)
          VALUES (gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),repeat('a',64),1,gen_random_uuid(),
          'k',decode(repeat('00',32),'hex'),decode(repeat('00',12),'hex'),decode(repeat('00',48),'hex'),
          decode(repeat('00',16),'hex'),'a',gen_random_uuid())`],
        ['UPDATE comments', 'UPDATE p06_crm.comments SET aad_context=aad_context WHERE false'],
        ['DELETE comments', 'DELETE FROM p06_crm.comments WHERE false'],
        ['TRUNCATE comments', 'TRUNCATE p06_crm.comments'],
        ['UPDATE audit', 'UPDATE foundation.audit_logs SET operation=operation WHERE false'],
        ['DELETE audit', 'DELETE FROM foundation.audit_logs WHERE false'],
        ['TRUNCATE audit', 'TRUNCATE foundation.audit_logs'],
        ['INSERT comment_grants', `INSERT INTO p06_crm.comment_grants(staff_id,city_id,can_read,can_write)
          VALUES (gen_random_uuid(),gen_random_uuid(),true,true)`],
        ['INSERT contact_grants', `INSERT INTO p06_crm.contact_grants(staff_id,city_id,capability)
          VALUES (gen_random_uuid(),gen_random_uuid(),'customer.pii.read')`],
        ['INSERT search_generation', `INSERT INTO p06_crm.search_generation(singleton,generation,key_check)
          VALUES (true,gen_random_uuid(),decode(repeat('00',32),'hex'))`],
        ['UPDATE contact_search name_token', 'UPDATE p06_crm.contact_search SET name_token=name_token WHERE false'],
      ] as const;
      for (const [label, sql] of denied) {
        await expect(client.query(sql), label).rejects.toMatchObject({ code: '42501' });
      }
      // UPDATE(phone_token) is the single column-level write on the derived index.
      await expect(client.query('UPDATE p06_crm.contact_search SET phone_token=phone_token WHERE false'))
        .resolves.toBeDefined();
    } finally { await client.end(); }
  }, 60000);

  it('refuses a direct comment INSERT even with a matching audit row', async () => {
    const created = await createManualRequest();
    await grantComment(db().admin.id, fixture.cityId, true);
    const client = await runtime();
    try {
      const commentId = randomUUID();
      const auditId = randomUUID();
      await client.query('BEGIN');
      await client.query(`INSERT INTO foundation.audit_logs(id,operation,correlation_id,details)
        VALUES ($1,$2,$3,$4::jsonb)`, [auditId, commentAudit, commentId, JSON.stringify({ requestId: created.id,
        commentId, actorId: db().admin.id, sessionId, version: created.version })]);
      await expect(client.query(`INSERT INTO p06_crm.comments(id,request_id,author_id,auth_session_id,auth_token_hash,
        request_version,idempotency_key,idem_key_id,fingerprint,nonce,ciphertext,auth_tag,aad_context,audit_id)
        VALUES ($1,$2,$3,$4,$5,$6,$7,'test-hmac-1',$8,$9,$10,$11,'p06-gap-direct',$12)`,
      [commentId, created.id, db().admin.id, sessionId,
        createHash('sha256').update(db().admin.token).digest('hex'), created.version, randomUUID(),
        randomBytes(32), randomBytes(12), randomBytes(48), randomBytes(16), auditId]))
        .rejects.toMatchObject({ code: '42501' });
      await client.query('ROLLBACK');
      expect(await commentRows(created.id)).toBe(0);
      expect(await auditRows(commentId)).toBe(0);
    } finally { await client.end(); }
  }, 60000);

  it('admits exactly one comment and one audit row through the DB writer', async () => {
    const created = await createManualRequest();
    await grantComment(db().admin.id, fixture.cityId, true);
    const client = await runtime();
    try {
      const id = randomUUID();
      const result = await write(client, functionParameters({ requestId: created.id, version: created.version, id }));
      expect(result).toEqual({ statement: undefined, commitCode: undefined });
      expect(await commentRows(created.id)).toBe(1);
      expect(await auditRows(id)).toBe(1);
      // The bearer itself is never stored; only its SHA-256 is.
      const { rows: [row] } = await db().db.query<{ hash: string; token: string }>(`SELECT auth_token_hash AS hash,
        encode(ciphertext,'hex') AS token FROM p06_crm.comments WHERE id=$1`, [id]);
      expect(row?.hash).toBe(createHash('sha256').update(db().admin.token).digest('hex'));
      expect(row?.hash).not.toBe(db().admin.token);
      expect(JSON.stringify(row)).not.toContain(db().admin.token);
      // The audit row is bound to the exact comment/request/session.
      expect(await db().count(`SELECT count(*)::int AS n FROM foundation.audit_logs WHERE id IN
        (SELECT audit_id FROM p06_crm.comments WHERE id=$1) AND correlation_id=$1
        AND details->>'requestId'=$2 AND details->>'sessionId'=$3`, [id, created.id, sessionId])).toBe(1);
    } finally { await client.end(); }
  }, 60000);

  it('refuses the DB writer without a live CRM bearer, read authority or comment grant', async () => {
    const created = await createManualRequest();
    await grantComment(db().admin.id, fixture.cityId, true);
    const client = await runtime();
    try {
      const cases: readonly [string, CommentInput, string][] = [
        ['unknown bearer', { requestId: created.id, version: created.version, token: randomBytes(32).toString('base64url').slice(0, 43) }, '42501'],
        ['short bearer', { requestId: created.id, version: created.version, token: 'too-short' }, '42501'],
        ['foreign session id', { requestId: created.id, version: created.version, authSessionId: randomUUID() }, '42501'],
        ['inactive staff', { requestId: created.id, version: created.version, authorId: randomUUID() }, '42501'],
        ['stale request version', { requestId: created.id, version: created.version + 3 }, '23514'],
        ['unknown request', { requestId: randomUUID(), version: created.version }, '23514'],
      ];
      for (const [label, input, code] of cases) {
        const result = await write(client, functionParameters(input));
        expect({ label, ...result }).toEqual({ label, statement: code, commitCode: undefined });
      }
      expect(await commentRows(created.id)).toBe(0);
      expect(await db().count(`SELECT count(*)::int AS n FROM foundation.audit_logs
        WHERE operation=$1 AND details->>'requestId'=$2`, [commentAudit, created.id])).toBe(0);

      // A revoked web session stops the writer even with the right bearer.
      const tokenHash = createHash('sha256').update(db().admin.token).digest('hex');
      await db().db.query('UPDATE foundation.web_sessions SET revoked_at=clock_timestamp() WHERE token_hash=$1', [tokenHash]);
      try {
        expect((await write(client, functionParameters({ requestId: created.id, version: created.version }))).statement).toBe('42501');
      } finally {
        await db().db.query('UPDATE foundation.web_sessions SET revoked_at=NULL WHERE token_hash=$1', [tokenHash]);
      }
      // Without the comment grant the binding trigger refuses the row.
      await db().db.query('DELETE FROM p06_crm.comment_grants WHERE staff_id=$1 AND city_id=$2', [db().admin.id, fixture.cityId]);
      expect((await write(client, functionParameters({ requestId: created.id, version: created.version }))).statement).toBe('23514');
      expect(await commentRows(created.id)).toBe(0);

      // Without requests.read the writer refuses too, even with a comment grant.
      await grantComment(db().admin.id, fixture.cityId, true);
      await withHttpMatrixActors(db(), fixture.cityId, async actors => {
        await grantComment(actors.actionOnly.id, fixture.cityId, true);
        const input: CommentInput = { requestId: created.id, version: created.version, authorId: actors.actionOnly.id };
        // The action-only actor has no live CRM bearer here, so the session check
        // fires first; the read-authority predicate is asserted separately below.
        expect((await write(client, functionParameters(input))).statement).toBe('42501');
      });
    } finally { await client.end(); }
  }, 90000);

  it('refuses the DB writer when the processing basis is withdrawn or has expired', async () => {
    const created = await createManualRequest();
    await grantComment(db().admin.id, fixture.cityId, true);
    const client = await runtime();
    try {
      const allowed = await write(client, functionParameters({ requestId: created.id, version: created.version }), false);
      expect(allowed).toEqual({ statement: undefined, commitCode: undefined });
      // The manual basis is immutable history: use a short-lived basis instead.
      const expiring = await createManualRequest(3500);
      expect((await write(client, functionParameters({ requestId: expiring.id, version: expiring.version }), false)))
        .toEqual({ statement: undefined, commitCode: undefined });
      await new Promise(done => setTimeout(done, 4500));
      const expired = await write(client, functionParameters({ requestId: expiring.id, version: expiring.version }));
      expect(expired.statement).toBe('23514');
      expect(await commentRows(expiring.id)).toBe(0);

      // Form consent: valid, then withdrawn.
      const form = await issue();
      const consentId = await given(form);
      const channel = await https('POST', '/public/repair-requests', {
        contact, address, appliance: { categoryId: fixture.categoryId }, fault: { faultIds: [fixture.faultId] },
        channelSelection: offers.ids, consent: { evidenceId: consentId, documentVersionId: fixture.consentDocumentVersionId, accepted: true },
      }, mutate(form));
      expect(channel.status, channel.bytes).toBe(201);
      const { rows: [linked] } = await db().db.query<{ id: string; version: number }>(
        'SELECT id,row_version AS version FROM foundation.requests WHERE public_number=$1', [channel.data()['publicNumber']]);
      if (!linked) { throw new Error('Missing form request'); }
      expect((await write(client, functionParameters({ requestId: linked.id, version: linked.version }), false)))
        .toEqual({ statement: undefined, commitCode: undefined });
      const withdrawalKey = randomUUID();
      expect((await https('POST', '/public/form-session/consents', {
        action: 'REVOKED', evidenceRef: withdrawalKey, supersedesEvidenceId: consentId,
      }, mutate(form, withdrawalKey))).status).toBe(201);
      expect((await write(client, functionParameters({ requestId: linked.id, version: linked.version }))).statement).toBe('23514');
      expect(await commentRows(linked.id)).toBe(0);
    } finally { await client.end(); }
  }, 120000);

  it('re-runs the basis check at COMMIT and rolls the whole insert back', async () => {
    // Manual basis with a short life: the INSERT is valid, the COMMIT is not.
    const created = await createManualRequest(4000);
    await grantComment(db().admin.id, fixture.cityId, true);
    const client = await runtime();
    try {
      const id = randomUUID();
      await client.query('BEGIN');
      await client.query(`SELECT * FROM p06_crm.insert_internal_comment($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
        functionParameters({ requestId: created.id, version: created.version, id }));
      // The row is visible inside the transaction but not committed yet.
      const { rows: [inside] } = await client.query<{ n: number }>(
        'SELECT count(*)::int AS n FROM p06_crm.comments WHERE request_id=$1', [created.id]);
      expect(inside?.n).toBe(1);
      await new Promise(done => setTimeout(done, 5000));
      await expect(client.query('COMMIT')).rejects.toMatchObject({ code: '23514' });
      await client.query('ROLLBACK').catch(() => undefined);
      expect(await commentRows(created.id)).toBe(0);
      expect(await auditRows(id)).toBe(0);
    } finally { await client.end(); }
  }, 90000);

  it('keeps the audit and the comment atomic when the audit insert fails', async () => {
    const created = await createManualRequest();
    await grantComment(db().admin.id, fixture.cityId, true);
    const client = await runtime();
    try {
      await db().db.query(`ALTER TABLE foundation.audit_logs ADD CONSTRAINT p06_gap_comment_audit_failure
        CHECK (operation <> '${commentAudit}') NOT VALID`);
      try {
        const refused = await write(client, functionParameters({ requestId: created.id, version: created.version }));
        expect(refused.statement).toBe('23514');
        expect(await commentRows(created.id)).toBe(0);
      } finally {
        await db().db.query('ALTER TABLE foundation.audit_logs DROP CONSTRAINT p06_gap_comment_audit_failure');
      }
      const recovered = await write(client, functionParameters({ requestId: created.id, version: created.version }));
      expect(recovered).toEqual({ statement: undefined, commitCode: undefined });
      expect(await commentRows(created.id)).toBe(1);
    } finally { await client.end(); }
  }, 60000);

  it('fails the read path closed when the external key slot is missing', async () => {
    const created = await createManualRequest();
    await grantComment(db().admin.id, fixture.cityId, true);
    const client = await runtime();
    let commentId: string | undefined;
    try {
      commentId = randomUUID();
      // The database cannot see the filesystem slot: this is the residual risk R1.
      const result = await write(client, functionParameters({ requestId: created.id, version: created.version, id: commentId }));
      expect(result).toEqual({ statement: undefined, commitCode: undefined });
      expect(await commentRows(created.id)).toBe(1);
    } finally { await client.end(); }
    try {
      const listed = await https('GET', `/requests/${created.id}/comments`, undefined, { Cookie: db().admin.cookie });
      expect(listed.status).toBe(503);
      expect(record(JSON.parse(listed.bytes) as unknown)['code']).toBe('NOT_READY');
      expect(listed.bytes).not.toContain('p06-gap-direct');
    } finally {
      await db().db.query('DELETE FROM p06_crm.comments WHERE request_id=$1', [created.id]);
    }
    expect(commentId).toBeTypeOf('string');
  }, 60000);

  async function issue(): Promise<{ sid: string; csrf: string; cookie: string }> {
    const group = cookieOf(await https('POST', '/public/form-session/browser', {}, { 'X-Form-Session-Bootstrap': '1' }));
    const created = await https('POST', '/public/form-sessions', {}, { Cookie: group });
    expect(created.status).toBe(201);
    return { sid: text(created.data(), 'sessionId'), csrf: text(created.data(), 'csrfToken'), cookie: cookieOf(created) };
  }
  function cookieOf(reply: Reply): string {
    const first = reply.headers['set-cookie']?.[0];
    if (first === undefined) { throw new Error('Missing isolated cookie'); }
    return first.split(';')[0] ?? '';
  }
  type Form = { sid: string; csrf: string; cookie: string };
  const proof = (form: Form) => ({ Cookie: form.cookie, 'X-Form-Session-Id': form.sid });
  const mutate = (form: Form, key = randomUUID()) => ({ ...proof(form), 'X-CSRF-Token': form.csrf, 'Idempotency-Key': key });
  async function given(form: Form): Promise<string> {
    const key = randomUUID();
    const reply = await https('POST', '/public/form-session/consents', {
      action: 'GIVEN', documentId: fixture.consentDocumentId, documentVersionId: fixture.consentDocumentVersionId, evidenceRef: key,
    }, mutate(form, key));
    expect(reply.status).toBe(201);
    return text(reply.data(), 'evidenceId');
  }
});
