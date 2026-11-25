import assert from 'node:assert/strict';
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { request } from 'node:https';
import type { IncomingHttpHeaders } from 'node:http';
import type { Server } from 'node:https';
import { decodeP05ManualRequest } from '@fixlevelup/p03-contracts/p05';
import { canonicalJson } from '../src/infrastructure/admission/proof.js';
import type { ProcessAuthorization } from '../src/infrastructure/admission/process-admission.js';
import type { DatabaseConfig } from '../src/infrastructure/database/runtime-database.js';
import type { PrivateQuarantineStorageConfig } from '../src/files/storage/config.js';
import type { StaffEvidencePort } from '../src/requests/intake/basis.js';
import { loadKeyring } from '../src/requests/crypto/keyring.js';
import { startIsolatedIntake } from './p05-composition.js';
import { createSyntheticKeySlots } from './p05-key-slot-fixture.js';
import { RequestOfferFixture } from './p05-offer-fixture.js';
import type { OfferFixtureIds } from './p05-offer-fixture.js';
import { supportedFixturePolicies } from './p05-request-fixtures.js';
import type { RequestFixtures } from './p05-request-fixtures.js';
import { nativeReady } from './p05-native-ready.js';

export interface NativeBusinessInput {
  settings: RequestFixtures;
  actor: { id: string; token: string };
  sourceVersionId: string;
  offer: { schema: string; ids: OfferFixtureIds };
  file: { namespace: string; target: PrivateQuarantineStorageConfig; bridge: string; descriptor: string; ticket: string };
  keys: readonly [manual: string, noCall: string];
}

type Reply = { status: number; bytes: string; headers: IncomingHttpHeaders; json: { data?: Record<string, unknown>; code?: string } };
const origin = 'https://intake-compiled.example.test';
const contact = { name: 'Native closed DTO sentinel', phone: '+15550100009' };
const address = { street: 'Native private street sentinel', building: '13' };
const secret = () => randomBytes(32).toString('hex');
const cookie = (reply: Reply): string => {
  const value = reply.headers['set-cookie']?.[0]?.split(';')[0];
  assert(value);
  return value;
};
function receipt(reply: Reply, status: number, keys: readonly string[]) {
  assert.equal(reply.status, status, `Unexpected response status; safe code: ${reply.json.code ?? 'none'}`);
  assert.equal(reply.headers['cache-control'], 'no-store');
  assert.equal(reply.headers.etag, undefined);
  assert(!reply.bytes.includes('sentinel') && !reply.bytes.includes(contact.phone));
  assert.deepEqual(Object.keys(reply.json), ['data']);
  assert(reply.json.data);
  assert.deepEqual(Object.keys(reply.json.data).sort(), [...keys].sort());
  return reply.json.data;
}

/** Independently launched after private IPC admission, with a single PNG ticket.
 * The native module imports the same application and fixture offer read port; the
 * external operator supplies only scenario facts, no migration/control login. */
export async function runNativeBusiness(input: NativeBusinessInput, target: DatabaseConfig,
  authorization: ProcessAuthorization, tls: { cert: Buffer; key: Buffer }) {
  const { settings, actor, offer, file, keys } = input;
  assert.equal(process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'], '1');
  assert(/^[a-f0-9]{32}$/u.test(file.ticket));
  process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] = '1';
  process.env['FIXLEVELUP_STORAGE_S3_TESTS'] = '1';
  process.env['FIXLEVELUP_FILE_PROCESSING_TESTS'] = '1';
  process.env['FIXLEVELUP_LAB_ENGINE_TICKET'] = file.ticket;
  const epoch = { namespace: file.namespace, epoch: 1n };
  const csrfSecret = secret();
  const ring = loadKeyring({ activeKekId: 'compiled-kek-1', activeHmacKeyId: 'compiled-hmac-1',
    kek: [{ keyId: 'compiled-kek-1', secretHex: secret() }], hmac: [{ keyId: 'compiled-hmac-1', secretHex: secret() }] });
  const normalized = decodeP05ManualRequest({ type: 'REPAIR', sourceEntryId: settings.formSourceEntryId, evidenceId: randomUUID(),
    contact: { ...contact, mode: 'PHONE', phonePermission: true, phoneEvidenceId: randomUUID() }, address,
    appliance: { categoryId: settings.categoryId }, fault: { faultIds: [settings.faultId] } });
  assert(normalized.type === 'REPAIR' && normalized.contact.mode === 'PHONE');
  const manualIds = { MANUAL_INTAKE: normalized.evidenceId, PHONE_GIVE: normalized.contact.phoneEvidenceId };
  const binding = canonicalJson({ cityId: settings.cityId, cityVersionId: settings.cityVersionId,
    sourceVersionId: input.sourceVersionId, operation: 'CreateRepair', key: keys[0] });
  const validUntil = new Date(Date.now() + 300_000);
  const staffEvidence: StaffEvidencePort = {
    async verify(_client, expected) {
      await Promise.resolve();
      if ((expected.purpose !== 'MANUAL_INTAKE' && expected.purpose !== 'PHONE_GIVE') || expected.id !== manualIds[expected.purpose]
        || expected.staffId !== actor.id || expected.canonicalIntent !== canonicalJson(normalized) || expected.target !== binding) { return undefined; }
      return { id: expected.id, procedureRevision: 'native-t-test-v1', validUntil };
    },
    isCurrent(_client, evidence) {
      return Promise.resolve(Object.values(manualIds).includes(evidence.id)
        && evidence.procedureRevision === 'native-t-test-v1' && evidence.validUntil.getTime() === validUntil.getTime());
    },
  };
  const keyGeneration = await createSyntheticKeySlots('compiled-t');
  const { app, filePool } = await startIsolatedIntake({ target, authorization, tls, staff: { origin, csrfSecret },
    form: { origin, csrfKeyring: { current: { keyId: 'compiled-csrf', secret: randomBytes(32) } }, throttleSecret: randomBytes(32),
      groupTtlMs: 900000, anchorTtlMs: 600000, csrfTtlMs: 300000,
      throttles: { source: { windowSeconds: 600, maxHits: 50 }, global: { windowSeconds: 600, maxHits: 50 }, anchor: { windowSeconds: 600, maxHits: 20 } } },
    configure: audit => ({ ring, environment: 'compiled-t', keySlots: keyGeneration.slots, currentPolicyId: settings.policyId,
      formSourceEntryId: settings.formSourceEntryId, supportedPolicies: supportedFixturePolicies(), staffEvidence,
      offers: RequestOfferFixture.readOnly(target.database, offer.schema, offer.ids, audit),
      attachments: { epoch, policy: { mode: 'local-synthetic', expiresAt: validUntil, maxAccessAgeMs: 300_000, maxFiles: 8, maxBytes: 512_000 } } }),
  }).catch(async (error: unknown) => { await keyGeneration.close(); throw error; });
  try {
    const bind = (app.getHttpServer() as Server).address();
    assert(bind && typeof bind !== 'string' && bind.address === '127.0.0.1');
    const post = (path: string, body: unknown, headers: Record<string, string> = {}) => new Promise<Reply>((ok, fail) => {
      const bytes = JSON.stringify(body);
      const req = request({ host: '127.0.0.1', port: bind.port, path: `/api/v1${path}`, method: 'POST', ca: tls.cert, agent: false,
        headers: { origin, 'content-type': 'application/json', 'content-length': Buffer.byteLength(bytes), ...headers } }, res => {
        const parts: Buffer[] = [];
        res.on('data', (data: Buffer) => { parts.push(data); });
        res.once('error', fail);
        res.once('end', () => {
          try {
            const body = Buffer.concat(parts).toString('utf8');
            ok({ status: res.statusCode ?? 0, bytes: body, headers: res.headers, json: JSON.parse(body) as Reply['json'] });
          } catch (error) { fail(error instanceof Error ? error : new Error('Invalid native test HTTP response', { cause: error })); }
        });
      });
      req.once('error', fail);
      req.setTimeout(15_000, () => { req.destroy(new Error('Native HTTPS deadline')); });
      req.end(bytes);
    });
    const staffHeaders = { cookie: `__Host-fixlevelup_session=${actor.token}`, 'idempotency-key': keys[0],
      'x-csrf-token': createHmac('sha256', csrfSecret).update('web-auth-csrf\0').update(actor.token).digest('base64url') };
    const manual = await post('/requests', normalized, staffHeaders);
    assert.equal(receipt(manual, 201, ['id', 'publicNumber', 'status', 'version'])['status'], 'NEW');
    const manualReplay = await post('/requests', normalized, staffHeaders);
    receipt(manualReplay, 200, ['id', 'publicNumber', 'status', 'version']);
    assert.equal(manualReplay.bytes, manual.bytes);

    const boot = await post('/public/form-session/browser', {}, { 'x-form-session-bootstrap': '1' });
    assert.equal(boot.status, 200);
    const issued = await post('/public/form-sessions', {}, { cookie: cookie(boot) });
    assert.equal(issued.status, 201);
    const sid = issued.json.data?.['sessionId'], csrf = issued.json.data?.['csrfToken'];
    assert(typeof sid === 'string' && typeof csrf === 'string');
    const proof = { cookie: cookie(issued), 'x-form-session-id': sid, 'x-csrf-token': csrf };
    const key = randomUUID();
    const consent = await post('/public/form-session/consents', { action: 'GIVEN', documentId: settings.consentDocumentId,
      documentVersionId: settings.consentDocumentVersionId, evidenceRef: key }, { ...proof, 'idempotency-key': key });
    assert.equal(consent.status, 201);
    const raw = proof.cookie.slice(`__Host-fixlevelup_f_${sid}=`.length);
    const ready = await nativeReady(filePool, epoch, { sessionId: sid, token: raw }, file.target, file.bridge, file.descriptor);
    const repair = { contact, address, appliance: { categoryId: settings.categoryId }, fault: { faultIds: [settings.faultId] },
      consent: { evidenceId: consent.json.data?.['evidenceId'], documentVersionId: settings.consentDocumentVersionId, accepted: true },
      channelSelection: offer.ids, attachments: [ready] };
    const header = { ...proof, 'idempotency-key': keys[1] };
    const refusal = await post('/public/repair-requests', { ...repair, attachments: [randomUUID()] }, header);
    assert.equal(refusal.status, 404);
    assert.equal(refusal.json.code, 'NOT_FOUND');
    assert(!refusal.bytes.includes('sentinel'));
    const result = await post('/public/repair-requests', repair, header);
    assert.equal(receipt(result, 201, ['publicNumber', 'status', 'version'])['status'], 'WAITING_TELEGRAM_LINK');
    const replay = await post('/public/repair-requests', repair, header);
    receipt(replay, 200, ['publicNumber', 'status', 'version']);
    assert.equal(replay.bytes, result.bytes);
    console.log('COMPILED_T_MANUAL_NO_CALL_READY_OK');
  } finally { try { await app.close(); } finally { await keyGeneration.close(); } }
}
