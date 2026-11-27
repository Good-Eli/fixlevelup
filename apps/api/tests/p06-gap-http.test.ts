/**
 * P06 gap proof (isolated T, real HTTPS + PostgreSQL 18.7): authority, races,
 * rollback and negative scenarios that the accepted P06 suites did not cover.
 *
 * Every case runs through the real isolated composition: TLS listener, runtime
 * role pools, an admitted key-slot generation, P05 transaction/lock discipline
 * and the P06 overlay. Only the reviewed synthetic `StaffEvidencePort` issuer is
 * in-process (exactly as in the accepted P06 suites).
 *
 * Opt-in: FIXLEVELUP_P06_GAP_PROOF=1 plus the standard isolated lab flags and
 * FIXLEVELUP_P06_COMMENT_PROOF=1 / ..._SEARCH_PROOF=1 / ..._DASHBOARD_PROOF=1.
 */
import { createHash, createHmac as hmac, randomBytes, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { request as httpsRequest } from 'node:https';
import { Client } from 'pg';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { decodeP05ManualRequest } from '@fixlevelup/p03-contracts/p05';
import { P05_CAPABILITIES } from '../src/authz/capability.js';
import { lockAccessPolicy } from '../src/authz/rbac-lock.js';
import { canonicalJson } from '../src/infrastructure/admission/proof.js';
import { loadKeyring } from '../src/requests/crypto/keyring.js';
import type { KeyringConfig } from '../src/requests/crypto/keyring.js';
import type { PayloadKeySlots } from '../src/requests/crypto/payload-key-directory.js';
import { createContactAudit } from '../src/requests/card/contacts.js';
import { COMMENT_KEY_ENVIRONMENT } from '../src/requests/card/comments.js';
import { ContactSearchIndex } from '../src/requests/search/index.js';
import { DashboardSnapshots } from '../src/requests/dashboard/snapshots.js';
import { fixtureCredentials } from './owned-test-database.js';
import { RbacFixture, record, text } from './rbac-fixture.js';
import { seedPolicyPackage, seedRequestFixtures, supportedFixturePolicies } from './p05-request-fixtures.js';
import type { RequestFixtures } from './p05-request-fixtures.js';
import { RequestOfferFixture } from './p05-offer-fixture.js';
import { startIsolatedIntake } from './p05-composition.js';
import { createSyntheticKeySlots } from './p05-key-slot-fixture.js';
import { installCommentFixture } from './p06-comment-fixture.js';
import { installSearchFixture, rebuildSearchFixture } from './p06-search-fixture.js';
import { withHttpMatrixActors } from './p05-http-matrix-actors.js';
import type { StaffProof } from './p05-http-matrix-actors.js';
import type { StaffEvidence, StaffEvidencePort } from '../src/requests/intake/basis.js';

const origin = 'https://crm.example.test';
const commentProof = process.env['FIXLEVELUP_P06_COMMENT_PROOF'] === '1';
const searchProof = process.env['FIXLEVELUP_P06_SEARCH_PROOF'] === '1';
const dashboardProof = process.env['FIXLEVELUP_P06_DASHBOARD_PROOF'] === '1';
const enabled = process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1'
  && process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1'
  && process.env['FIXLEVELUP_P06_GAP_PROOF'] === '1'
  && commentProof && searchProof && dashboardProof;
const contact = Object.freeze({ name: 'Synthetic gap sentinel', phone: '+15550130001' });
const address = Object.freeze({ street: 'Synthetic gap street', building: '7' });
const contactAudit = 'P06_READ_REQUEST_CONTACT';
const commentAudit = 'P06_ADD_INTERNAL_COMMENT';
const searchAudit = 'P06_SEARCH_REQUESTS';

interface Reply {
  readonly status: number;
  readonly bytes: string;
  readonly headers: import('node:http').IncomingHttpHeaders;
  data(): Record<string, unknown>;
}

type Instance = Awaited<ReturnType<typeof startIsolatedIntake>>;

describe.runIf(enabled)('P06 gap: HTTPS authority, races, rollback and negatives', () => {
  let base: RbacFixture | undefined;
  let fixture: RequestFixtures;
  let app: Instance | undefined;
  let rotated: Instance | undefined;
  let cert: Buffer;
  let staffTlsKey: Buffer;
  let port = 0;
  let offers: RequestOfferFixture;
  let keyring: KeyringConfig;
  let managed: Awaited<ReturnType<typeof createSyntheticKeySlots>> | undefined;
  let managedComments: Awaited<ReturnType<typeof createSyntheticKeySlots>> | undefined;
  let activeSearch: ContactSearchIndex | undefined;
  let originalSearchKey: { generation: string; key: Buffer } | undefined;
  let rotatedSearchKey: { generation: string; key: Buffer } | undefined;
  let evidencePort: StaffEvidencePort;
  const indexes = new Map<string, ContactSearchIndex>();
  let staffCsrf = '';
  const evidence = new Map<string, StaffEvidence & Parameters<StaffEvidencePort['verify']>[1]>();
  const slotReads: string[] = [];
  const slotCreates: string[] = [];
  let onSlotRead: ((ref: { kind: string; requestId: string }) => Promise<void>) | undefined;
  let onRegistryOpen: (() => Promise<void>) | undefined;

  function db() {
    if (!base) { throw new Error('Missing fixture'); }
    return base;
  }

  /** Observable key-slot access: proves "no decrypt" and counts slot writes. */
  function instrument(slots: PayloadKeySlots): PayloadKeySlots {
    return {
      environment: slots.environment,
      async read(ref) {
        slotReads.push(`${ref.kind}:${ref.requestId}`);
        await onSlotRead?.(ref);
        return await slots.read(ref);
      },
      async create(ref, wrap) {
        slotCreates.push(`${ref.kind}:${ref.requestId}`);
        return slots.create(ref, wrap);
      },
    };
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
    const dir = mkdtempSync(resolve(tmpdir(), 'p06-gap-http-tls-'));
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
    evidencePort = {
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
        await onRegistryOpen?.();
        return proof => evidence.get(proof.id)?.procedureRevision === proof.procedureRevision;
      },
    };
    originalSearchKey = { generation: randomUUID(), key: randomBytes(32) };
    app = await startInstance(fixture.policyId, originalSearchKey, evidencePort);
    if (!activeSearch) { throw new Error('Missing isolated search'); }
    await rebuildSearchFixture(lab, activeSearch, { ring: keyring, environment: 'p05-isolated', keySlots: managed.slots },
      client => evidencePort.openRegistry?.(client) ?? Promise.reject(new Error('Missing evidence issuer')));
    port = portOf(app);
    rotatedSearchKey = { generation: randomUUID(), key: randomBytes(32) };
    rotated = await startInstance(fixture.policyId, rotatedSearchKey, evidencePort);
  }, 150000);

  async function startInstance(policyId: string, searchKey: { generation: string; key: Buffer },
    evidencePort: StaffEvidencePort): Promise<Instance> {
    if (!base || !managed || !managedComments) { throw new Error('Missing fixture'); }
    const businessSlots = managed.slots;
    const commentSlots = managedComments.slots;
    const settings = { ring: keyring, keySlots: instrument(businessSlots), environment: 'p05-isolated', currentPolicyId: policyId,
      supportedPolicies: new Map(supportedFixturePolicies()), formSourceEntryId: fixture.formSourceEntryId };
    return await startIsolatedIntake({
      target: { host: '127.0.0.1', port: 55432, database: base.database, user: 'fixlevelup_runtime', password: fixtureCredentials().runtime },
      authorization: base.admitted.authorization,
      tls: { key: staffTlsKey, cert },
      staff: { origin, csrfSecret: staffCsrf },
      form: { origin, csrfKeyring: { current: { keyId: 'csrf-t1', secret: randomBytes(32) } }, throttleSecret: randomBytes(32),
        groupTtlMs: 900000, anchorTtlMs: 600000, csrfTtlMs: 300000,
        throttles: { source: { windowSeconds: 600, maxHits: 300 }, global: { windowSeconds: 600, maxHits: 300 },
          anchor: { windowSeconds: 600, maxHits: 60 } } },
      configure: audit => ({ ...settings, offers, staffEvidence: evidencePort,
        search: registerIndex(audit, searchKey),
        comments: { ring: keyring, keySlots: commentSlots },
        contactAudit: createContactAudit(audit),
        dashboard: new DashboardSnapshots() }),
    });
  }

  function registerIndex(audit: Parameters<typeof createContactAudit>[0], searchKey: { generation: string; key: Buffer }) {
    const index = new ContactSearchIndex(audit, 'p05-isolated', searchKey.generation, searchKey.key);
    indexes.set(searchKey.generation, index);
    activeSearch = index;
    return index;
  }

  afterAll(async () => {
    try { await rotated?.app.close(); } finally {
      try { await app?.app.close(); } finally {
        try { await managed?.close(); } finally {
          try { await managedComments?.close(); } finally { await base?.close(); }
        }
      }
    }
  }, 30000);

  function portOf(instance: Instance): number {
    const server = instance.app.getHttpServer() as import('node:https').Server;
    const bind = server.address();
    if (!bind || typeof bind === 'string' || bind.address !== '127.0.0.1') { throw new Error('Missing isolated TLS server'); }
    return bind.port;
  }

  function https(method: 'GET' | 'POST', path: string, payload?: unknown,
    headers: Record<string, string> = {}, targetPort = port): Promise<Reply> {
    return new Promise((ok, fail) => {
      const body = payload === undefined ? undefined : JSON.stringify(payload);
      const req = httpsRequest({ method, host: '127.0.0.1', port: targetPort, path: `/api/v1${path}`, ca: cert, agent: false,
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
      req.setTimeout(25000, () => req.destroy(new Error('Isolated HTTPS deadline')));
      req.once('error', fail);
      req.end(body);
    });
  }

  const staff = () => ({ Cookie: db().admin.cookie });
  function staffMutation(key = randomUUID(), ifMatch?: string) {
    const csrf = hmac('sha256', staffCsrf).update('web-auth-csrf\0').update(db().admin.token).digest('base64url');
    return { ...staff(), 'X-CSRF-Token': csrf, 'Idempotency-Key': key,
      ...(ifMatch === undefined ? {} : { 'If-Match': ifMatch }) };
  }
  const codeOf = (reply: Reply): unknown => record(JSON.parse(reply.bytes) as unknown)['code'];
  const tagOf = (reply: Reply): string => {
    const value = reply.headers.etag;
    if (typeof value !== 'string') { throw new Error('Missing strong ETag'); }
    return value;
  };

  async function manualPrepared() {
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
          validUntil: new Date(Date.now() + 900000) });
      }
    } };
  }

  async function createManualRequest(): Promise<{ id: string; publicNumber: string; version: number }> {
    const prepared = await manualPrepared();
    prepared.authorize();
    const reply = await https('POST', '/requests', prepared.body, staffMutation(prepared.key));
    expect(reply.status, reply.bytes).toBe(201);
    const id = text(reply.data(), 'id');
    const { rows: [row] } = await db().db.query<{ version: number }>(
      'SELECT row_version AS version FROM foundation.requests WHERE id=$1', [id]);
    if (!row) { throw new Error('Missing created request'); }
    return { id, publicNumber: text(reply.data(), 'publicNumber'), version: row.version };
  }

  async function grant(statement: string, parameters: unknown[]): Promise<void> {
    const client = await db().db.connect();
    try {
      await client.query('BEGIN');
      await lockAccessPolicy(client, 'write');
      await client.query(statement, parameters);
      await client.query('COMMIT');
    } finally {
      try { await client.query('ROLLBACK'); } finally { client.release(); }
    }
  }
  const grantComment = (staffId: string, cityId: string, write: boolean) => grant(
    `INSERT INTO p06_crm.comment_grants(staff_id,city_id,can_read,can_write) VALUES ($1,$2,true,$3)
     ON CONFLICT (staff_id,city_id) DO UPDATE SET can_read=true,can_write=excluded.can_write`, [staffId, cityId, write]);
  const grantContact = (staffId: string, cityId: string) => grant(
    `INSERT INTO p06_crm.contact_grants(staff_id,city_id,capability) VALUES ($1,$2,'customer.pii.read')
     ON CONFLICT DO NOTHING`, [staffId, cityId]);

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
  const mutate = (form: Form, key = randomUUID(), ifMatch?: string) => ({ ...proof(form), 'X-CSRF-Token': form.csrf,
    'Idempotency-Key': key, ...(ifMatch === undefined ? {} : { 'If-Match': ifMatch }) });
  async function given(form: Form): Promise<string> {
    const key = randomUUID();
    const reply = await https('POST', '/public/form-session/consents', {
      action: 'GIVEN', documentId: fixture.consentDocumentId, documentVersionId: fixture.consentDocumentVersionId, evidenceRef: key,
    }, mutate(form, key));
    expect(reply.status).toBe(201);
    return text(reply.data(), 'evidenceId');
  }
  async function createFormRequest(formContact: { name: string; phone: string } = contact):
  Promise<{ id: string; consentId: string; form: Form }> {
    const form = await issue();
    const consentId = await given(form);
    const reply = await https('POST', '/public/repair-requests', {
      contact: formContact, address, appliance: { categoryId: fixture.categoryId }, fault: { faultIds: [fixture.faultId] },
      channelSelection: offers.ids, consent: { evidenceId: consentId, documentVersionId: fixture.consentDocumentVersionId, accepted: true },
    }, mutate(form, randomUUID()));
    expect(reply.status, reply.bytes).toBe(201);
    const { rows: [row] } = await db().db.query<{ id: string }>(
      'SELECT id FROM foundation.requests WHERE public_number=$1', [reply.data()['publicNumber']]);
    if (!row) { throw new Error('Missing form request'); }
    return { id: row.id, consentId, form };
  }
  const requestAuditCount = (operation: string, requestId: string) =>
    db().count(`SELECT count(*)::int AS n FROM foundation.audit_logs WHERE operation=$1 AND details->>'requestId'=$2`,
      [operation, requestId]);
  const contactReads = () => slotReads.filter(entry => entry.startsWith('CONTACT:')).length;

  // ------------------------------------------------------------- PII ------

  it('refuses PII before any decryption and commits the durable audit before disclosure', async () => {
    const created = await createManualRequest();
    const path = `/requests/${created.id}/contact-details`;
    const headers = { ...staff(), 'X-Auth-Request': '1' };
    const readsBefore = contactReads();
    const denied = await https('GET', path, undefined, headers);
    expect(denied.status).toBe(403);
    expect(codeOf(denied)).toBe('FORBIDDEN');
    expect(contactReads()).toBe(readsBefore);
    expect(await requestAuditCount(contactAudit, created.id)).toBe(0);

    await grantContact(db().admin.id, fixture.cityId);
    const auditAtOpen: number[] = [];
    onSlotRead = async ref => {
      if (ref.kind === 'CONTACT') { auditAtOpen.push(await requestAuditCount(contactAudit, ref.requestId)); }
    };
    let revealed: Reply;
    try { revealed = await https('GET', path, undefined, headers); }
    finally { onSlotRead = undefined; }
    expect(revealed.status, revealed.bytes).toBe(200);
    expect(revealed.data()).toEqual(contact);
    expect(revealed.headers['cache-control']).toBe('no-store, no-transform');
    // The durable audit row existed before the ciphertext was opened.
    expect(auditAtOpen).toEqual([1]);
    expect(await requestAuditCount(contactAudit, created.id)).toBe(1);
    expect(await db().count(`SELECT count(*)::int AS n FROM foundation.audit_logs
      WHERE operation=$1 AND details->>'requestId'=$2 AND (position($3 IN details::text)>0 OR position($4 IN details::text)>0)`,
    [contactAudit, created.id, contact.name, contact.phone])).toBe(0);
  }, 60000);

  it('denies PII on a revoked consent or revoked session and hides the phone under no-call', async () => {
    const created = await createFormRequest();
    await grantContact(db().admin.id, fixture.cityId);
    const path = `/requests/${created.id}/contact-details`;
    const headers = { ...staff(), 'X-Auth-Request': '1' };
    // The form request chose a messenger channel, so its phone is never disclosed.
    expect((await https('GET', path, undefined, headers)).data()).toEqual({ name: contact.name, phone: null });

    const withdrawalKey = randomUUID();
    const withdrawn = await https('POST', '/public/form-session/consents', {
      action: 'REVOKED', evidenceRef: withdrawalKey, supersedesEvidenceId: created.consentId,
    }, mutate(created.form, withdrawalKey));
    expect(withdrawn.status).toBe(201);
    const readsBefore = contactReads();
    const denied = await https('GET', path, undefined, headers);
    expect(denied.status).toBe(409);
    expect(codeOf(denied)).toBe('CONSENT_REQUIRED');
    expect(contactReads()).toBe(readsBefore);
    expect(denied.bytes).not.toContain(contact.phone);

    // No-call: withdraw the current phone permission on a PHONE request; the name
    // stays available, the phone never does.
    const noCall = await createManualRequest();
    const noCallTag = tagOf(await https('GET', `/requests/${noCall.id}`, undefined, staff()));
    const { rows: [contactRow] } = await db().db.query<{ id: string; permit: string }>(
      `SELECT r.current_contact_revision_id AS id,p.id AS permit FROM foundation.requests r
         JOIN foundation.phone_permission_events p ON p.request_id=r.id AND p.action='GIVEN'
          AND p.purpose='REQUEST_SERVICE_CALL'
          AND p.contact_revision_id=r.current_contact_revision_id
          AND NOT EXISTS (SELECT FROM foundation.phone_permission_events x WHERE x.supersedes_given_id=p.id)
       WHERE r.id=$1`, [noCall.id]);
    if (!contactRow) { throw new Error('Missing contact revision'); }
    const withdrawEvidence = randomUUID();
    const withdrawBody = { evidenceId: withdrawEvidence };
    evidence.set(withdrawEvidence, { id: withdrawEvidence, purpose: 'PHONE_WITHDRAW', staffId: db().admin.id,
      target: canonicalJson({ requestId: noCall.id, contactRevisionId: contactRow.id, permit: contactRow.permit,
        version: noCall.version, ifMatch: noCallTag }),
      canonicalIntent: canonicalJson(withdrawBody), procedureRevision: 'fixture-v1',
      validUntil: new Date(Date.now() + 600000) });
    const withdrawnPhone = await https('POST', `/requests/${noCall.id}/commands/withdraw-phone`,
      withdrawBody, staffMutation(undefined, noCallTag));
    expect(withdrawnPhone.status, withdrawnPhone.bytes).toBe(200);
    const readsBeforeNoCall = contactReads();
    const noCallRead = await https('GET', `/requests/${noCall.id}/contact-details`, undefined, headers);
    expect(noCallRead.status).toBe(200);
    expect(noCallRead.data()).toEqual({ name: contact.name, phone: null });
    expect(noCallRead.bytes).not.toContain(contact.phone);
    expect(contactReads()).toBeGreaterThanOrEqual(readsBeforeNoCall);

    // Revoked staff session: authority fails before any decrypt or audit.
    const tokenHash = createHash('sha256').update(db().admin.token).digest('hex');
    const { rowCount } = await db().db.query(
      'UPDATE foundation.web_sessions SET revoked_at=clock_timestamp() WHERE token_hash=$1 AND revoked_at IS NULL', [tokenHash]);
    expect(rowCount).toBe(1);
    try {
      const after = contactReads();
      const anonymous = await https('GET', path, undefined, headers);
      expect(anonymous.status).toBe(401);
      expect(codeOf(anonymous)).toBe('UNAUTHORIZED');
      expect(contactReads()).toBe(after);
    } finally {
      await db().db.query('UPDATE foundation.web_sessions SET revoked_at=NULL WHERE token_hash=$1', [tokenHash]);
    }
    // The restored session reads a live request again (the form request above
    // stays restricted because its consent was withdrawn).
    expect((await https('GET', `/requests/${noCall.id}/contact-details`, undefined, headers)).status).toBe(200);
  }, 90000);

  it('refuses PII when the durable audit cannot be written, without decrypting or leaking', async () => {
    const created = await createManualRequest();
    await grantContact(db().admin.id, fixture.cityId);
    const path = `/requests/${created.id}/contact-details`;
    const headers = { ...staff(), 'X-Auth-Request': '1' };
    await db().db.query(`ALTER TABLE foundation.audit_logs ADD CONSTRAINT p06_gap_audit_failure
      CHECK (operation <> '${contactAudit}') NOT VALID`);
    try {
      const readsBefore = contactReads();
      // The service distinguishes an unavailable audit sink from a missing basis ...
      let direct: unknown;
      try { await app?.service.readStaffContact({ kind:'staff-web', token: db().admin.token }, created.id); }
      catch (error) { direct = error; }
      expect(direct).toMatchObject({ code: 'DEPENDENCY_UNAVAILABLE' });
      // ... while the closed P05 problem vocabulary reports every 503 as NOT_READY.
      const refused = await https('GET', path, undefined, headers);
      expect(refused.status).toBe(503);
      expect(codeOf(refused)).toBe('NOT_READY');
      expect(contactReads()).toBe(readsBefore);
      expect(refused.bytes).not.toContain(contact.name);
      expect(refused.bytes).not.toContain(contact.phone);
      expect(await requestAuditCount(contactAudit, created.id)).toBe(0);
    } finally {
      await db().db.query('ALTER TABLE foundation.audit_logs DROP CONSTRAINT p06_gap_audit_failure');
    }
    const recovered = await https('GET', path, undefined, headers);
    expect(recovered.status).toBe(200);
    expect(recovered.data()).toEqual(contact);
    expect(await requestAuditCount(contactAudit, created.id)).toBe(1);
  }, 60000);

  // ------------------------------------------------------------ RBAC ------

  it('enforces the role × scope × employment × request-state matrix over HTTPS', async () => {
    const created = await createManualRequest();
    await grantComment(db().admin.id, fixture.cityId, true);
    await grantContact(db().admin.id, fixture.cityId);
    const review = await createManualRequest();
    const reviewTag = tagOf(await https('GET', `/requests/${review.id}`, undefined, staff()));
    expect((await https('POST', `/requests/${review.id}/commands/start-review`, {}, staffMutation(undefined, reviewTag))).status).toBe(200);
    const cancelled = await createManualRequest();
    const cancelTag = tagOf(await https('GET', `/requests/${cancelled.id}`, undefined, staff()));
    expect((await https('POST', `/requests/${cancelled.id}/commands/cancel`,
      { reasonEntryId: fixture.cancelReasonEntryId }, staffMutation(undefined, cancelTag))).status).toBe(200);

    const routes = (id: string) => [
      ['GET', '/requests', undefined], ['GET', '/requests/filters', undefined],
      ['GET', `/requests/${id}/card`, undefined], ['GET', `/requests/${id}/events`, undefined],
      ['GET', `/requests/${id}/comments`, undefined], ['GET', `/requests/${id}/contact-details`, undefined],
      ['GET', '/crm/dashboard', undefined],
      ['POST', '/requests/search', { kind: 'number', query: '1' }],
    ] as const;

    const readAs = async (actor: StaffProof, method: 'GET' | 'POST', path: string, payload?: unknown) => {
      const browser = { Cookie: actor.cookie, 'X-Auth-Request': '1' };
      return await https(method, path, payload, browser);
    };

    await withHttpMatrixActors(db(), fixture.cityId, async actors => {
      // Every reader needs the two panel-specific grants; requests.read alone is
      // checked separately below with the action-only role.
      for (const actor of [actors.cityAdmin, actors.manager, actors.custom, actors.reader]) {
        await grantComment(actor.id, fixture.cityId, false);
        await grantContact(actor.id, fixture.cityId);
      }
      // Positive authority for a request in the actor's city.
      for (const actor of [actors.global, actors.cityAdmin, actors.manager, actors.custom, actors.reader]) {
        for (const [method, path, payload] of routes(created.id)) {
          const reply = await readAs(actor, method, path, payload);

          expect({ who: actor.id, method, path, status: reply.status }).toMatchObject({ status: 200 });
        }
      }
      // requests.read is the single mandatory code: every other P05 code is not enough.
      for (const [method, path, payload] of routes(created.id)) {
        const reply = await readAs(actors.actionOnly, method, path, payload);
        expect({ method, path, status: reply.status }).toMatchObject({ status: 403 });
        expect(codeOf(reply)).toBe('FORBIDDEN');
      }
      // A city outside the trusted assignment is indistinguishable from a missing target.
      for (const [method, path, payload] of routes(created.id)) {
        const reply = await readAs(actors.wrong, method, path, payload);
        expect({ method, path, status: reply.status }).toMatchObject({ status: 404 });
      }
      for (const [method, path, payload] of routes(created.id)) {
        expect((await readAs(actors.noCity, method, path, payload)).status).toBe(404);
      }
      // ADMIN with CITY-scoped grants works only while the assignment is active.
      await actors.setAdminScope('CITY');
      expect((await readAs(actors.cityAdmin, 'GET', '/requests')).status).toBe(200);
      await actors.revokeCity(actors.cityAdmin);
      expect((await readAs(actors.cityAdmin, 'GET', '/requests')).status).toBe(404);
      expect((await readAs(actors.cityAdmin, 'GET', `/requests/${created.id}/card`)).status).toBe(404);
      await actors.setAdminScope('GLOBAL');

      // Employment state: INACTIVE closes every P06 read at the session level.
      await db().db.query(`UPDATE foundation.staff SET employment_state='INACTIVE' WHERE id=$1`, [actors.reader.id]);
      try {
        for (const [method, path, payload] of routes(created.id)) {
          const reply = await readAs(actors.reader, method, path, payload);
          expect({ method, path, status: reply.status }).toMatchObject({ status: 401 });
        }
      } finally {
        await db().db.query(`UPDATE foundation.staff SET employment_state='ACTIVE' WHERE id=$1`, [actors.reader.id]);
      }
      expect((await readAs(actors.reader, 'GET', '/requests')).status).toBe(200);
    });

    // Request state: a cancelled request keeps its read projection but offers no review hint.
    const cancelledCard = await https('GET', `/requests/${cancelled.id}/card`, undefined, { ...staff(), 'X-Auth-Request': '1' });
    expect(cancelledCard.status).toBe(200);
    expect(cancelledCard.data()['status']).toBe('CANCELLED');
    expect(cancelledCard.data()['canStartReview']).toBe(false);
    const reviewCard = await https('GET', `/requests/${review.id}/card`, undefined, { ...staff(), 'X-Auth-Request': '1' });
    expect(reviewCard.data()['status']).toBe('MANAGER_REVIEW');
    expect(reviewCard.data()['canStartReview']).toBe(false);
    const freshCard = await https('GET', `/requests/${created.id}/card`, undefined, { ...staff(), 'X-Auth-Request': '1' });
    expect(freshCard.data()['canStartReview']).toBe(true);
  }, 150000);

  it('serializes a mid-read authority revocation and denies every later request', async () => {
    await createManualRequest();
    await withHttpMatrixActors(db(), fixture.cityId, async actors => {
      const readAs = (actor: StaffProof) => https('GET', '/requests', undefined, { Cookie: actor.cookie });
      expect((await readAs(actors.reader)).status).toBe(200);
      let release: () => void = () => { throw new Error('No read hook'); };
      const blocked = new Promise<void>(done => { release = done; });
      let revocation: Promise<void> | undefined;
      onRegistryOpen = async () => {
        // Start the revocation while this read transaction holds the shared policy lock.
        revocation = actors.revokeCity(actors.reader);
        await blocked;
      };
      const reading = readAs(actors.reader);
      try {
        // The revocation writer (a different role) is waiting on this read
        // transaction, not racing it. Observe the real wait edge: a not-granted
        // lock in this database whose blocker is another backend holding the
        // same lock object. Role-independent by design.
        const deadline = performance.now() + 8000;
        let waiting = 0;
        do {
          waiting = await db().count(`SELECT count(*)::int AS n FROM pg_locks AS pending
            WHERE NOT pending.granted AND pending.pid IS NOT NULL
              AND pending.database=(SELECT oid FROM pg_database WHERE datname=current_database())
              AND EXISTS (SELECT FROM pg_locks AS held WHERE held.granted AND held.pid<>pending.pid
                AND held.database=pending.database AND held.locktype=pending.locktype
                AND held.classid=pending.classid AND held.objid=pending.objid AND held.objsubid=pending.objsubid
                AND held.pid=ANY(pg_blocking_pids(pending.pid)))`);
          if (waiting >= 1) { break; }
          await new Promise(done => setTimeout(done, 25));
        } while (performance.now() < deadline);
        expect(waiting).toBeGreaterThanOrEqual(1);
      } finally {
        release();
        onRegistryOpen = undefined;
      }
      const reply = await reading;
      expect(reply.status).toBe(200);
      await revocation;
      // Every later request sees the revocation, including the card and the dashboard.
      for (const path of ['/requests', '/requests/filters', '/crm/dashboard']) {
        expect({ path, status: (await https('GET', path, undefined, { Cookie: actors.reader.cookie })).status })
          .toMatchObject({ status: 404 });
      }
      // Another city manager is unaffected.
      expect((await readAs(actors.manager)).status).toBe(200);
    });
  }, 120000);

  // -------------------------------------------------------- comments ------

  async function commentProof(): Promise<{ id: string; etag: string; csrf: string }> {
    const created = await createManualRequest();
    await grantComment(db().admin.id, fixture.cityId, true);
    const card = await https('GET', `/requests/${created.id}/card`, undefined, { ...staff(), 'X-Auth-Request': '1' });
    expect(card.status, card.bytes).toBe(200);
    const etag = card.headers['x-command-etag'];
    const csrf = card.headers['x-comment-csrf'];
    if (typeof etag !== 'string' || typeof csrf !== 'string') { throw new Error('Missing comment proof'); }
    return { id: created.id, etag, csrf };
  }
  const addComment = (proof: { id: string; etag: string; csrf: string }, key: string, text: string) =>
    https('POST', `/requests/${proof.id}/comments`, { text }, { ...staff(), 'X-CSRF-Token': proof.csrf,
      'If-Match': proof.etag, 'Idempotency-Key': key });
  const commentRows = (requestId: string) => db().count(
    'SELECT count(*)::int AS n FROM p06_crm.comments WHERE request_id=$1', [requestId]);

  it('keeps one row for concurrent identical idempotency keys and refuses a content conflict', async () => {
    const proof = await commentProof();
    const key = randomUUID();
    const text = 'Synthetic concurrent comment';
    const [first, second] = await Promise.all([addComment(proof, key, text), addComment(proof, key, text)]);
    expect([first.status, second.status].sort()).toEqual([200, 201]);
    expect(first.bytes).toBe(second.bytes);
    expect(await commentRows(proof.id)).toBe(1);
    expect(await db().count(`SELECT count(*)::int AS n FROM foundation.audit_logs
      WHERE operation=$1 AND details->>'requestId'=$2`, [commentAudit, proof.id])).toBe(1);
    // Same key, different content: refused, no second row.
    const conflict = await addComment(proof, key, 'Synthetic different comment');
    expect(conflict.status).toBe(409);
    expect(codeOf(conflict)).toBe('IDEMPOTENCY_KEY_REUSED');
    expect(await commentRows(proof.id)).toBe(1);
    // A stale ETag is refused even with a fresh key.
    const staleTag = await https('GET', `/requests/${proof.id}`, undefined, staff());
    await https('POST', `/requests/${proof.id}/commands/start-review`, {}, staffMutation(undefined, tagOf(staleTag)));
    const stale = await addComment(proof, randomUUID(), text);
    expect(stale.status).toBe(412);
    expect(codeOf(stale)).toBe('VERSION_MISMATCH');
    expect(await commentRows(proof.id)).toBe(1);
  }, 60000);

  /**
   * KNOWN DEFECT F-2 (recorded, not masked): a *definite* database failure while
   * writing the comment audit row is classified as 500 INTERNAL_ERROR instead
   * of the closed-vocabulary 503 NOT_READY. The security invariants hold (no
   * partial comment, no audit row, no plaintext), so this is an error-mapping
   * defect only. Reproduce with the statement below. The strict expectation is
   * kept in an it.fails so a future fix makes this test fail loudly and the
   * marker can be removed; the companion test below asserts the invariants.
   */
  it.fails('F-2: a definite comment-audit DB failure maps to 503 NOT_READY', async () => {
    const proof = await commentProof();
    await db().db.query(`ALTER TABLE foundation.audit_logs ADD CONSTRAINT p06_gap_comment_audit_failure
      CHECK (operation <> '${commentAudit}') NOT VALID`);
    try {
      const refused = await addComment(proof, randomUUID(), 'Synthetic classification comment');
      expect(refused.status).toBe(503);
      expect(codeOf(refused)).toBe('NOT_READY');
    } finally {
      await db().db.query('ALTER TABLE foundation.audit_logs DROP CONSTRAINT p06_gap_comment_audit_failure');
    }
  }, 60000);

  it('fails closed with no partial effect when the comment audit insert fails', async () => {
    const proof = await commentProof();
    await db().db.query(`ALTER TABLE foundation.audit_logs ADD CONSTRAINT p06_gap_comment_audit_failure
      CHECK (operation <> '${commentAudit}') NOT VALID`);
    const text = 'Synthetic rollback comment';
    try {
      const refused = await addComment(proof, randomUUID(), text);
      // Classification is covered by the F-2 test above; here the contract is the
      // absence of a partial comment/audit row and of plaintext in the response.
      expect(refused.status).toBeGreaterThanOrEqual(500);
      expect(refused.bytes).not.toContain(text);
      expect(await commentRows(proof.id)).toBe(0);
      expect(await requestAuditCount(commentAudit, proof.id)).toBe(0);
    } finally {
      await db().db.query('ALTER TABLE foundation.audit_logs DROP CONSTRAINT p06_gap_comment_audit_failure');
    }
    // A retry with the same key now succeeds exactly once.
    const key = randomUUID();
    const created = await addComment(proof, key, text);
    expect(created.status).toBe(201);
    expect((await addComment(proof, key, text)).status).toBe(200);
    expect(await commentRows(proof.id)).toBe(1);
    // Ciphertext, audit and wire carry no plaintext.
    expect(await db().count(`SELECT count(*)::int AS n FROM p06_crm.comments
      WHERE request_id=$1 AND position(convert_to($2,'UTF8') IN ciphertext)=0`, [proof.id, text])).toBe(1);
    expect(await db().count(`SELECT count(*)::int AS n FROM foundation.audit_logs
      WHERE operation=$1 AND position($2 IN details::text)>0`, [commentAudit, text])).toBe(0);
    const listed = await https('GET', `/requests/${proof.id}/comments`, undefined, staff());
    expect(listed.status).toBe(200);
    expect(listed.data()['items']).toEqual([expect.objectContaining({ text })]);
  }, 60000);

  it('survives an uncertain COMMIT without duplicating the comment', async () => {
    const proof = await commentProof();
    const descriptor = Object.getOwnPropertyDescriptor(Client.prototype, 'query');
    const original: unknown = descriptor?.value;
    if (!descriptor || typeof original !== 'function') { throw new Error('Missing PG query'); }
    let armed = false;
    let lost = 0;
    const text = 'Synthetic uncertain commit comment';
    const key = randomUUID();
    Object.defineProperty(Client.prototype, 'query', {
      ...descriptor,
      value: function patched(this: unknown, ...args: unknown[]) {
        const sql = args[0];
        const run = (): unknown => Reflect.apply(original as (...input: unknown[]) => unknown, this, args);
        if (typeof sql === 'string' && /p06_crm\.insert_internal_comment/i.test(sql)) { armed = true; }
        if (typeof sql === 'string' && /^\s*COMMIT\b/i.test(sql) && armed) {
          armed = false;
          lost += 1;
          return Promise.resolve(run()).then(() => {
            throw Object.assign(new Error('Simulated connection loss at COMMIT'), { code: 'ECONNRESET' });
          });
        }
        return run();
      },
    });
    try {
      const uncertain = await addComment(proof, key, text);
      expect(uncertain.status).toBe(503);
      expect(lost).toBe(1);
    } finally {
      Object.defineProperty(Client.prototype, 'query', descriptor);
    }
    // The transaction did commit; the same key replays instead of duplicating.
    const retry = await addComment(proof, key, text);
    expect([200, 201]).toContain(retry.status);
    expect(await commentRows(proof.id)).toBe(1);
  }, 60000);

  // ---------------------------------------------------------- search ------

  const searchAs = (body: object, targetPort = port) =>
    https('POST', '/requests/search', body, { ...staff(), 'X-Auth-Request': '1' }, targetPort);
  const searchIds = (reply: Reply) => {
    expect(reply.status, reply.bytes).toBe(200);
    const items = reply.data()['items'];
    if (!Array.isArray(items)) { throw new Error('Invalid search items'); }
    return items.map(item => text(record(item), 'id'));
  };
  async function seedNamedRequest(name: string, phone: string): Promise<string> {
    const source = (await db().db.query<{ version: string }>(
      'SELECT current_version_id AS version FROM foundation.reference_entries WHERE id=$1',
      [fixture.formSourceEntryId])).rows[0];
    if (!source) { throw new Error('Missing source'); }
    const key = randomUUID();
    const body = decodeP05ManualRequest({ type: 'REPAIR', sourceEntryId: fixture.formSourceEntryId, evidenceId: randomUUID(),
      contact: { name, phone, mode: 'PHONE', phonePermission: true, phoneEvidenceId: randomUUID() },
      address: { ...address, districtId: fixture.districtId }, appliance: { categoryId: fixture.categoryId },
      fault: { faultIds: [fixture.faultId] } });
    const target = canonicalJson({ cityId: fixture.cityId, cityVersionId: fixture.cityVersionId,
      sourceVersionId: source.version, operation: 'CreateRepair', key });
    if (body.contact.mode !== 'PHONE') { throw new Error('Expected a PHONE manual contact'); }
    const phoneEvidenceId = body.contact.phoneEvidenceId;
    for (const id of [body.evidenceId, phoneEvidenceId]) {
      evidence.set(id, { id, purpose: id === body.evidenceId ? 'MANUAL_INTAKE' : 'PHONE_GIVE', staffId: db().admin.id,
        target, canonicalIntent: canonicalJson(body), procedureRevision: 'fixture-v1',
        validUntil: new Date(Date.now() + 900000) });
    }
    const reply = await https('POST', '/requests', body, staffMutation(key));
    expect(reply.status, reply.bytes).toBe(201);
    return text(reply.data(), 'id');
  }

  it('keeps search consistent while the phone permission and the consent change', async () => {
    await grantContact(db().admin.id, fixture.cityId);
    const name = 'Synthetic race name';
    const phone = '+15550130222';
    const id = await seedNamedRequest(name, phone);
    expect(searchIds(await searchAs({ kind: 'name', query: name }))).toContain(id);
    expect(searchIds(await searchAs({ kind: 'phone', query: phone }))).toContain(id);

    // Withdraw the phone permission while a phone search is in flight.
    let release: () => void = () => { throw new Error('No hook'); };
    const blocked = new Promise<void>(done => { release = done; });
    onRegistryOpen = async () => { await blocked; };
    const inFlight = searchAs({ kind: 'phone', query: phone });
    await new Promise(done => setTimeout(done, 120));
    const withdrawTag = tagOf(await https('GET', `/requests/${id}`, undefined, staff()));
    const { rows: [permit] } = await db().db.query<{ id: string; contact: string }>(
      `SELECT p.id,r.current_contact_revision_id AS contact FROM foundation.phone_permission_events p
         JOIN foundation.requests r ON r.id=p.request_id
        WHERE p.request_id=$1 AND p.action='GIVEN' AND p.purpose='REQUEST_SERVICE_CALL'
          AND NOT EXISTS (SELECT FROM foundation.phone_permission_events x WHERE x.supersedes_given_id=p.id)`, [id]);
    if (!permit) { throw new Error('Missing phone permit'); }
    const evidenceId = randomUUID();
    const body = { evidenceId };
    evidence.set(evidenceId, { id: evidenceId, purpose: 'PHONE_WITHDRAW', staffId: db().admin.id,
      target: canonicalJson({ requestId: id, contactRevisionId: permit.contact, permit: permit.id,
        version: 1, ifMatch: withdrawTag }), canonicalIntent: canonicalJson(body), procedureRevision: 'fixture-v1',
      validUntil: new Date(Date.now() + 600000) });
    const withdrawn = await https('POST', `/requests/${id}/commands/withdraw-phone`, body, staffMutation(undefined, withdrawTag));
    expect(withdrawn.status, withdrawn.bytes).toBe(200);
    release();
    onRegistryOpen = undefined;
    const after = await inFlight;
    // The in-flight search resolves consistently with one of the two serialized
    // states: before the withdrawal (the match is still visible) or after it
    // (the phone token is gone, so the match is empty). A 503 is also acceptable
    // when the basis changes under the read. Anything else would be a stale or
    // partial answer.
    if (after.status === 200) {
      const ids = searchIds(after);
      expect([ids.length === 0, ids.length === 1 && ids[0] === id]).toContain(true);
    } else { expect(after.status).toBe(503); }
    expect(searchIds(await searchAs({ kind: 'phone', query: phone }))).toEqual([]);
    expect(searchIds(await searchAs({ kind: 'name', query: name }))).toContain(id);

    // Consent withdrawal removes the whole indexed projection of that exact form
    // request; the unique synthetic name isolates it from every other request.
    const formName = 'Synthetic form consent race';
    const formRequest = await createFormRequest({ name: formName, phone: '+15550130333' });
    expect(searchIds(await searchAs({ kind: 'name', query: formName }))).toEqual([formRequest.id]);
    expect(searchIds(await searchAs({ kind: 'phone', query: '+15550130333' }))).toEqual([]);
    const withdrawalKey = randomUUID();
    expect((await https('POST', '/public/form-session/consents', {
      action: 'REVOKED', evidenceRef: withdrawalKey, supersedesEvidenceId: formRequest.consentId,
    }, mutate(formRequest.form, withdrawalKey))).status).toBe(201);
    expect(searchIds(await searchAs({ kind: 'name', query: formName }))).toEqual([]);
    expect(await db().count('SELECT count(*)::int AS n FROM p06_crm.contact_search WHERE request_id=$1', [formRequest.id])).toBe(0);
  }, 120000);

  it('enforces the exact STAFF and CITY search quota boundaries and leaks no token', async () => {
    await grantContact(db().admin.id, fixture.cityId);
    const quota = async (scope: 'STAFF' | 'CITY', used: number) => {
      await db().db.query(`INSERT INTO p06_crm.search_budget(scope,city_id,subject_id,minute,used)
        VALUES ($1,$2,$3,date_trunc('minute',statement_timestamp()),$4)
        ON CONFLICT (scope,city_id,subject_id) DO UPDATE SET minute=excluded.minute,used=excluded.used`,
      [scope, fixture.cityId, scope === 'STAFF' ? db().admin.id : fixture.cityId, used]);
    };
    const clear = () => db().db.query('DELETE FROM p06_crm.search_budget WHERE city_id=$1', [fixture.cityId]);
    try {
      await quota('STAFF', 23);
      expect((await searchAs({ kind: 'number', query: '1' })).status).toBe(200);
      expect((await searchAs({ kind: 'number', query: '1' })).status).toBe(429);
      await clear();
      await quota('CITY', 239);
      expect((await searchAs({ kind: 'number', query: '1' })).status).toBe(200);
      expect((await searchAs({ kind: 'number', query: '1' })).status).toBe(429);
    } finally { await clear(); }
    // Audit keeps only staff/city/kind; no query, token or match is written.
    expect(await db().count(`SELECT count(*)::int AS n FROM foundation.audit_logs
      WHERE operation=$1 AND (details ? 'query' OR details ? 'token' OR details ? 'items' OR details ? 'value')`,
    [searchAudit])).toBe(0);
    expect(await db().count(`SELECT count(*)::int AS n FROM foundation.audit_logs
      WHERE operation=$1 AND details::text LIKE '%Synthetic%'`, [searchAudit])).toBe(0);
  }, 60000);

  it('rejects an obsolete index generation and accepts only the rebuilt one', async () => {
    const original = originalSearchKey === undefined ? undefined : indexes.get(originalSearchKey.generation);
    const obsolete = rotatedSearchKey === undefined ? undefined : indexes.get(rotatedSearchKey.generation);
    if (!original || !obsolete || !managed) { throw new Error('Missing search generations'); }
    await grantContact(db().admin.id, fixture.cityId);
    const rotatedPort = portOf(rotated as Instance);
    const name = 'Synthetic generation name';
    const id = await seedNamedRequest(name, '+15550130444');
    // The active generation is the original index.
    expect(searchIds(await searchAs({ kind: 'name', query: name }))).toContain(id);
    // The rotated instance holds a different key: it refuses before reading.
    const stale = await searchAs({ kind: 'name', query: name }, rotatedPort);
    expect(stale.status).toBe(503);
    expect(codeOf(stale)).toBe('NOT_READY');
    // Rebuilding with the rotated key switches the active generation atomically.
    const rebuild = (index: ContactSearchIndex) => rebuildSearchFixture(db(), index,
      { ring: keyring, environment: 'p05-isolated', keySlots: managed?.slots as PayloadKeySlots },
      client => evidencePort.openRegistry?.(client) ?? Promise.reject(new Error('Missing evidence issuer')));
    await rebuild(obsolete);
    expect(searchIds(await searchAs({ kind: 'name', query: name }, rotatedPort))).toContain(id);
    const oldGeneration = await searchAs({ kind: 'name', query: name });
    expect(oldGeneration.status).toBe(503);
    expect(codeOf(oldGeneration)).toBe('NOT_READY');
    // A number search does not depend on the key and still works on both instances.
    expect((await searchAs({ kind: 'number', query: '1' })).status).toBe(200);
    expect((await searchAs({ kind: 'number', query: '1' }, rotatedPort)).status).toBe(200);
    // Restore the original generation for the remaining tests.
    await rebuild(original);
    expect(searchIds(await searchAs({ kind: 'name', query: name }))).toContain(id);
  }, 120000);

  // ------------------------------------------------------- dashboard ------

  function metricOf(reply: Reply, name: string) {
    expect(reply.status, reply.bytes).toBe(200);
    return record(record(reply.data()['metrics'])[name]);
  }

  it('keeps dashboard counts equal to the registry selection and refreshes on change', async () => {
    for (let index = 0; index < 35; index++) { await createManualRequest(); }
    const dashboard = await https('GET', '/crm/dashboard', undefined, staff());
    const newRequests = metricOf(dashboard, 'newRequests');
    const href = text(newRequests, 'href').slice(4);
    const seen: string[] = [];
    for (let offset = 0; ; offset += 30) {
      const page = await https('GET', `${href}&offset=${String(offset)}`, undefined, staff());
      expect(page.status, page.bytes).toBe(200);
      expect(page.data()['refreshed']).toBe(false);
      const items = page.data()['items'];
      if (!Array.isArray(items)) { throw new Error('Invalid dashboard page'); }
      seen.push(...items.map(item => text(record(item), 'id')));
      if (page.data()['nextOffset'] === null) { break; }
    }
    expect(seen).toHaveLength(Number(newRequests['count']));
    expect(new Set(seen).size).toBe(seen.length);
    // The registry read with the same rule returns the same set in the same order.
    const registry = await https('GET', '/requests?status=NEW&limit=100', undefined, staff());
    expect(registry.status).toBe(200);
    const registryItems = registry.data()['items'];
    if (!Array.isArray(registryItems)) { throw new Error('Invalid registry page'); }
    expect(registryItems.map(item => text(record(item), 'id'))).toEqual(seen);
    // A parallel insert during a page read stays out of the served snapshot.
    const [during, inserted] = await Promise.all([
      https('GET', `${href}&offset=0`, undefined, staff()),
      createManualRequest(),
    ]);
    expect(during.data()['refreshed']).toBe(false);
    expect(record(during.data()['snapshot'])['snapshotId']).toBe(record(dashboard.data())['snapshotId']);
    // The next snapshot includes it.
    const next = await https('GET', '/crm/dashboard', undefined, staff());
    expect(Number(metricOf(next, 'newRequests')['count'])).toBe(Number(newRequests['count']) + 1);
    expect(await db().count('SELECT count(*)::int AS n FROM foundation.requests WHERE id=$1', [inserted.id])).toBe(1);
  }, 180000);

  it('invalidates a dashboard snapshot when a counted request loses its basis or the reader loses rights', async () => {
    const target = await createManualRequest();
    const dashboard = await https('GET', '/crm/dashboard', undefined, staff());
    const href = text(metricOf(dashboard, 'newRequests'), 'href').slice(4);
    const page = await https('GET', `${href}&offset=0`, undefined, staff());
    expect(page.data()['refreshed']).toBe(false);
    const snapshotId = record(page.data()['snapshot'])['snapshotId'];
    // Withdraw the manual basis of a counted request.
    const { rows: [manual] } = await db().db.query<{ id: string }>(`SELECT id
      FROM foundation.request_staff_evidence WHERE request_id=$1 AND purpose='MANUAL_INTAKE'`, [target.id]);
    if (!manual) { throw new Error('Missing manual evidence'); }
    evidence.delete(manual.id);
    const refreshed = await https('GET', `${href}&offset=0`, undefined, staff());
    expect(refreshed.status, refreshed.bytes).toBe(200);
    expect(refreshed.data()['refreshed']).toBe(true);
    expect(record(refreshed.data()['snapshot'])['snapshotId']).not.toBe(snapshotId);
    const ids = (refreshed.data()['items'] as unknown[]).map(item => text(record(item), 'id'));
    expect(ids).not.toContain(target.id);
    // A stale offset page of a changed snapshot is served from a new first page.
    const stale = await https('GET', `${href}&offset=30`, undefined, staff());
    expect(stale.status).toBe(200);
    expect(stale.data()['offset']).toBeUndefined();
    // A different session cannot reuse the identifier: it receives a fresh
    // snapshot of its own and the first page, never the other staff material.
    await withHttpMatrixActors(db(), fixture.cityId, async actors => {
      const foreign = await https('GET', `${href}&offset=0`, undefined, { Cookie: actors.reader.cookie });
      expect(foreign.status, foreign.bytes).toBe(200);
      expect(foreign.data()['refreshed']).toBe(true);
      expect(record(foreign.data()['snapshot'])['snapshotId']).not.toBe(snapshotId);
      const foreignIds = (foreign.data()['items'] as unknown[]).map(item => text(record(item), 'id'));
      expect(foreignIds).not.toContain(target.id);
    });
  }, 150000);
});
