/**
 * P05 §5.2 real-HTTP attachment suite (task-13, strengthened by task-15).
 *
 * One new file only. No simulated READY: every attachment here is a genuine
 * Garage object produced by the real B upload and the real pinned ClamAV/Sharp
 * pipeline, and the request is created by the real F HTTP surface.
 *
 * Covered:
 *  1. real `POST /public/repair-requests` with `attachments` creates the request,
 *     the submit edge and the exact `foundation.request_files` rows;
 *  2. exact replay of the same idempotency key returns the same bytes and does not
 *     duplicate the links;
 *  3. BOTH retention orders as REAL PostgreSQL interleavings: the intent row is held
 *     `FOR UPDATE` in a separate backend, the attach and the real `planRetention`
 *     queue behind it in either order, and the wait edges are observed through
 *     `pg_locks`/`pg_blocking_pids` before the holder commits. Attach-first → the
 *     sweep defers; delete-first → the attach is refused;
 *  4. delete-first pins the EXACT named constraint (`23503` /
 *     `request_files_intent_id_open_state_fkey`) on a legitimately committed
 *     no-attachment request of the same anchor — not "some FK", not a random id;
 *  5. a complete parent-side deletion transition reaches the same restrictive FK;
 *     the rejected runtime write leaves no decision or graph;
 *  6. active reconcile and terminal drain run on that same file and ledger scope.
 *     The real broker cannot delete the attached file; in the opposite order both
 *     exact objects settle and no later attach wins. A read-only Garage observer
 *     checks full lengths and digests or exact absence.
 *
 * Gating: only the isolated pg-lab contour with Garage (`s3test`/`engine`).
 *
 * IMPORTANT — the reviewed engine bridge (`infra/file-processing/p05-lab-engine-host.mjs`)
 * accepts exactly ONE synthetic image per ticket (three operations: raw-scan,
 * decode, output-scan). Each test below therefore creates exactly one real READY
 * file, and the suite is executed as TWO invocations, one per test:
 *
 *   node infra/p05-lab/lab.mjs engine --privacy --ledger --s3 --restore -- apps/api/tests/p05-attachment-http.test.ts -t "creates the real request"
 *   node infra/p05-lab/lab.mjs engine --privacy --ledger --s3 --restore -- apps/api/tests/p05-attachment-http.test.ts -t "refuses the HTTP create"
 *
 * Running both tests in one invocation would ask the single-use bridge for a second
 * file and be refused; that is a property of the reviewed bridge, not of the
 * attachment port.
 */
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { request } from 'node:https';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { DeleteObjectCommand, GetObjectCommand, NoSuchKey, S3Client } from '@aws-sdk/client-s3';
import sharp from 'sharp';
import type { PoolClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { freshGarageBucket } from '../../../infra/file-restore/resources.mjs';
import { closeReadyStream, createFileReadBudget, openReadyStream, readReadyChunk, readReadyMetadata } from '../src/files/file-access/index.js';
import { beginLegalTransaction } from '../src/settings/legal/index.js';
import { createPrivateQuarantineStorage } from '../src/files/storage/index.js';
import { processQuarantine } from '../src/files/file-lifecycle/index.js';
import { createLocalFileProcessor } from '../src/files/file-processing/processor.js';
import type { DefinitionEpoch, FileProcessingLauncher } from '../src/files/file-processing/processor.js';
import { createSyntheticDeleteBroker, drainFencedFileDecisions, makeFilePrivacyGrant, planRetention,
  reconcileFileDeletion, revokeDeleteBroker } from '../src/files/file-privacy/index.js';
import type { RetentionPolicy } from '../src/files/file-privacy/contract.js';
import { loadKeyring } from '../src/requests/crypto/keyring.js';
import { accessPolicy, processingContext, provision, signal } from './file-lifecycle-fixture.js';
import { auditPairs, control, items, openPrivacyLedger } from './file-privacy-fixture.js';
import type { FileReservationsFixture } from './file-reservations-fixture.js';
import { TECHNICAL_TIMEOUTS } from './file-storage-fixture.js';
import { RbacFixture, record, text } from './rbac-fixture.js';
import { RequestOfferFixture } from './p05-offer-fixture.js';
import { seedRequestFixtures, supportedFixturePolicies } from './p05-request-fixtures.js';
import type { RequestFixtures } from './p05-request-fixtures.js';
import { startIsolatedIntake } from './p05-composition.js';
import { createSyntheticKeySlots } from './p05-key-slot-fixture.js';

const origin = 'https://crm.example.test';
const pub = '/public';
const enabled = process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1'
  && process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1'
  && process.env['FIXLEVELUP_STORAGE_S3_TESTS'] === '1'
  && process.env['FIXLEVELUP_FILE_PRIVACY_TESTS'] === '1'
  && process.env['FIXLEVELUP_ISOLATED_FILE_LEDGER_TESTS'] === '1'
  && process.env['FIXLEVELUP_FILE_PROCESSING_TESTS'] === '1';

// An engine invocation is an explicit request to execute this suite, not a reason
// to let describe.runIf silently turn missing opt-ins into a successful skipped file.
if (process.env['FIXLEVELUP_FILE_PROCESSING_TESTS'] === '1' && !enabled) {
  throw new Error('P05 attachment HTTP suite requires the isolated PG, privacy, Garage, ledger and engine opt-ins');
}

interface Reply {
  readonly status: number;
  readonly bytes: string;
  readonly headers: import('node:http').IncomingHttpHeaders;
  data(): Record<string, unknown>;
}
interface BrowserForm { readonly sid: string; readonly csrf: string; readonly cookie: string }

const sha256 = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');

/** Real bytes for the real engine: the reviewed 9x5 synthetic image. */
async function engineFixtureImage(): Promise<Buffer> {
  return await sharp({ create: { width: 9, height: 5, channels: 3, background: '#f03412' } })
    .withMetadata({ orientation: 6 })
    .withExifMerge({
      IFD3: { GPSLatitudeRef: 'N', GPSLatitude: '1/1 2/1 3/1', GPSLongitudeRef: 'E', GPSLongitude: '4/1 5/1 6/1' },
      IFD0: { Artist: 'SYNTHETIC_PRIVACY_MARKER' },
    })
    .png()
    .toBuffer();
}

interface EngineModule {
  createFileProcessingTestLauncher(config: unknown): Promise<{
    launcher: FileProcessingLauncher; epoch: DefinitionEpoch;
  }>;
}

/**
 * The reviewed bridge is single-use per ticket (one image, three operations). A
 * second acquisition in the same process can never succeed, so it reports that
 * explicitly instead of surfacing as an opaque PROCESSING_DENIED: the caller skips
 * with a note telling the operator to run that test in its own invocation.
 */
let bridgeConsumed = false;

async function pinnedEngine() {
  if (bridgeConsumed) { return undefined; }
  const path = process.env['FIXLEVELUP_FILE_PROCESSING_FIXTURE'];
  if (path === undefined) { throw new Error('Real engine contour requires FIXLEVELUP_FILE_PROCESSING_FIXTURE'); }
  const config: unknown = JSON.parse(readFileSync(resolve(path), 'utf8'));
  const module = await import(new URL('../../../infra/file-processing/p05-lab-engine-client.mjs', import.meta.url).href) as EngineModule;
  const created = await module.createFileProcessingTestLauncher(config);
  bridgeConsumed = true;
  return created;
}

describe.runIf(enabled)('P05 real HTTP attachments and both retention orders', () => {
  let base: RbacFixture | undefined;
  let fixture: RequestFixtures;
  let testApp: Awaited<ReturnType<typeof startIsolatedIntake>> | undefined;
  let keyGeneration: Awaited<ReturnType<typeof createSyntheticKeySlots>> | undefined;
  let offers: RequestOfferFixture;
  let cert: Buffer;
  let port = 0;
  let files: FileReservationsFixture;
  let ledger: Awaited<ReturnType<typeof openPrivacyLedger>>;
  let closeLedger: (() => Promise<unknown>) | undefined;
  let bucket: ReturnType<typeof freshGarageBucket>;
  let epoch: { namespace: string; epoch: bigint };

  function db() { if (!base) { throw new Error('Missing fixture'); } return base; }
  function app() { if (!testApp) { throw new Error('Missing composition'); } return testApp; }

  /** Real P03 fixture over the T-owned guarded pool; no second runtime pool. */
  function fileFixture(): FileReservationsFixture {
    return files;
  }

  function https(method: 'GET' | 'POST', path: string, payload?: unknown,
    headers: Record<string, string> = {}): Promise<Reply> {
    return new Promise((ok, fail) => {
      const body = payload === undefined ? undefined : JSON.stringify(payload);
      const req = request({ method, host: '127.0.0.1', port, path: `/api/v1${path}`, ca: cert, agent: false,
        headers: { Origin: origin,
          ...(body === undefined ? {} : { 'Content-Type': 'application/json', 'Content-Length': String(Buffer.byteLength(body)) }),
          ...headers } }, res => {
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

  function accepted(reply: Reply, status: number): Reply {
    expect(reply.status, reply.status >= 400 ? reply.bytes : 'status').toBe(status);
    return reply;
  }

  function browser(reply: Reply): string {
    const first = reply.headers['set-cookie']?.[0];
    if (first === undefined) { throw new Error('Missing isolated cookie'); }
    return first.split(';')[0] ?? '';
  }

  async function issue(): Promise<BrowserForm> {
    const group = browser(accepted(await https('POST', `${pub}/form-session/browser`, {}, { 'X-Form-Session-Bootstrap': '1' }), 200));
    const created = accepted(await https('POST', `${pub}/form-sessions`, {}, { Cookie: group }), 201);
    return { sid: text(created.data(), 'sessionId'), csrf: text(created.data(), 'csrfToken'), cookie: browser(created) };
  }
  const proofOf = (form: BrowserForm) => ({ Cookie: form.cookie, 'X-Form-Session-Id': form.sid });
  const mutate = (form: BrowserForm, key: string = randomUUID()) =>
    ({ ...proofOf(form), 'X-CSRF-Token': form.csrf, 'Idempotency-Key': key });

  async function given(form: BrowserForm): Promise<string> {
    const key = randomUUID();
    const reply = accepted(await https('POST', `${pub}/form-session/consents`,
      { action: 'GIVEN', documentId: fixture.consentDocumentId,
        documentVersionId: fixture.consentDocumentVersionId, evidenceRef: key }, mutate(form, key)), 201);
    return text(reply.data(), 'evidenceId');
  }

  /**
   * The raw F secret is exactly the proof-cookie value: the anchor row stores only
   * `hashSessionSecret(raw)`, so the cookie is the only place the raw token exists.
   */
  function rawToken(form: BrowserForm): string {
    const name = `__Host-fixlevelup_f_${form.sid}=`;
    if (!form.cookie.startsWith(name)) { throw new Error('Unexpected proof cookie'); }
    return form.cookie.slice(name.length);
  }

  /**
   * Real READY file for one F anchor: real upload + real scan/decode + publication.
   * Returns `undefined` only when this process already spent the single-use engine
   * ticket; the caller then skips instead of failing with an opaque refusal.
   */
  async function readyFile(anchor: {
    sessionId: string; token: string; evidenceId: string; documentId: string; documentVersionId: string;
  }, bytes: Buffer) {
    const engine = await pinnedEngine();
    if (engine === undefined) { return undefined; }
    const storage = createPrivateQuarantineStorage({ mode: 'local-synthetic', ...bucket.target, ...bucket.rw,
      allowedEndpoint: bucket.target.endpoint, ...TECHNICAL_TIMEOUTS });
    try {
      const reserved = await provision(fileFixture(), storage, bytes, { anchor });
      const processor = createLocalFileProcessor({
        scan: async (raw, definition, abort) => await engine.launcher.scan(raw, definition, abort),
        decode: engine.launcher.decode.bind(engine.launcher),
      }, { epoch: engine.epoch, maxRawBytes: 64_000, maxOutputBytes: 64_000, maxJobs: 1, maxWallMs: 90_000 });
      const receipt = await processQuarantine(processingContext(fileFixture(), storage, processor, { epoch }),
        { ...reserved.file, signal: signal() });
      expect(receipt).toStrictEqual({ intentId: reserved.file.intentId, completed: true });
      const publication = (await fileFixture().migrator.query<{ id: string }>(
        `SELECT id FROM foundation.file_publications WHERE intent_id=$1`, [reserved.file.intentId])).rows[0];
      if (publication === undefined) { throw new Error('Missing real publication'); }
      return { ...reserved, storage, publicationFileId: publication.id };
    } catch (error) {
      await storage.close().catch(() => undefined);
      throw error;
    }
  }

  function repairBody(evidenceId: string, attachments?: readonly string[]) {
    return {
      contact: { name: 'Synthetic attachment sentinel', phone: '+15550100002' },
      consent: { evidenceId, documentVersionId: fixture.consentDocumentVersionId, accepted: true },
      channelSelection: offers.ids, address: { street: 'Synthetic attachment street', building: '12' },
      appliance: { categoryId: fixture.categoryId }, fault: { faultIds: [fixture.faultId] },
      urgency: 'WITHIN_DAY',
      ...(attachments === undefined ? {} : { attachments }),
    };
  }

  function retentionPolicy(): RetentionPolicy {
    return { mode: 'local-synthetic', versionId: randomUUID(),
      expiresAt: new Date(Date.now() + 120_000), rawBoundMs: 1, readyMs: 1, quarantinedMs: 1, orphanMs: 1,
      maxBatch: 32, maxItemsPerIntent: 8, claimMs: 10_000 };
  }

  /** Real retention plan over the same runtime pool, no mocked SQL. */
  async function plan() {
    return await planRetention({
      pool: fileFixture().runtime,
      epoch,
      policy: retentionPolicy(),
      grant: operator('RETENTION'), scope: ledger.scope,
    }, signal());
  }

  function operator(role: 'RETENTION' | 'DELETE' | 'SOURCE_DRAIN') {
    return makeFilePrivacyGrant({ mode: 'local-synthetic', namespace: epoch.namespace, role, actorId: db().admin.id });
  }

  beforeAll(async () => {
    ledger = await openPrivacyLedger();
    closeLedger = ledger.close;
    epoch = { namespace: ledger.scope.namespace, epoch: ledger.scope.writerEpoch };
    bucket = freshGarageBucket(epoch.namespace);
    const lab = new RbacFixture({ p04: true });
    base = lab;
    await lab.start();
    fixture = await seedRequestFixtures(lab, { reviewerId: lab.admin.id });
    offers = await RequestOfferFixture.attach(lab, { provider: 'TG' });
    // The reviewed runtime epoch for the attachment port.
    await lab.db.query(`INSERT INTO foundation.file_runtime_epochs (singleton,namespace_id,epoch,mode)
      VALUES (true,$1,$2,'ACTIVE')`, [epoch.namespace, epoch.epoch.toString()]);
    const dir = mkdtempSync(resolve(tmpdir(), 'p05-attach-tls-'));
    let key: Buffer;
    try {
      const pem = resolve(dir, 'server.pem');
      const privateKey = resolve(dir, 'server.key');
      const openssl = existsSync('C:\\Program Files\\Git\\usr\\bin\\openssl.exe')
        ? 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe' : 'openssl';
      execFileSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
        '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost', '-keyout', privateKey, '-out', pem],
      { stdio: 'ignore', timeout: 10000 });
      cert = readFileSync(pem);
      key = readFileSync(privateKey);
    } finally { rmSync(dir, { recursive: true, force: true }); }
    const keyring = loadKeyring({ activeKekId: 'test-kek-1', activeHmacKeyId: 'test-hmac-1',
      kek: [{ keyId: 'test-kek-1', secretHex: randomBytes(32).toString('hex') }],
      hmac: [{ keyId: 'test-hmac-1', secretHex: randomBytes(32).toString('hex') }] });
    keyGeneration = await createSyntheticKeySlots('p05-isolated');
    const settings = { ring: keyring, environment: 'p05-isolated', keySlots: keyGeneration.slots, currentPolicyId: fixture.policyId,
      supportedPolicies: supportedFixturePolicies(),
      formSourceEntryId: fixture.formSourceEntryId };
    const csrf = randomBytes(32).toString('hex');
    testApp = await startIsolatedIntake({
      target: { host: '127.0.0.1', port: 55432, database: lab.database, user: 'fixlevelup_runtime',
        password: process.env['FIXLEVELUP_RUNTIME_PASSWORD'] ?? '' },
      authorization: lab.admitted.authorization,
      tls: { key, cert },
      staff: { origin, csrfSecret: csrf },
      form: { origin, csrfKeyring: { current: { keyId: 'csrf-t1', secret: randomBytes(32) } },
        throttleSecret: randomBytes(32), groupTtlMs: 900000, anchorTtlMs: 600000, csrfTtlMs: 300000,
        throttles: { source: { windowSeconds: 600, maxHits: 300 }, global: { windowSeconds: 600, maxHits: 300 },
          anchor: { windowSeconds: 600, maxHits: 60 } } },
      configure: () => ({ ...settings, offers,
        attachments: { epoch, policy: { mode: 'local-synthetic' as const,
          expiresAt: new Date(Date.now() + 300_000), maxAccessAgeMs: 300_000, maxFiles: 16, maxBytes: 67_108_864 } } }),
    });
    const server = testApp.app.getHttpServer() as import('node:https').Server;
    const bind = server.address();
    if (!bind || typeof bind === 'string' || bind.address !== '127.0.0.1') { throw new Error('Missing isolated TLS server'); }
    port = bind.port;
    // The real P03 fixture over the composition's own guarded pool: one runtime
    // authority for the whole suite, no second pool and no separate anchor source.
    files = {
      database: lab.database,
      migrator: lab.db,
      runtime: app().filePool,
      reviewer: lab.admin.id,
      city: { cityId: fixture.cityId, cityVersionId: fixture.cityVersionId },
      async inTransaction<T>(run: (client: PoolClient) => Promise<T>): Promise<T> {
        const client = await app().filePool.connect();
        try {
          await beginLegalTransaction(client);
          const result = await run(client);
          await client.query('COMMIT');
          return result;
        } catch (error) {
          await client.query('ROLLBACK').catch(() => undefined);
          throw error;
        } finally { client.release(); }
      },
      async drainPools() { /* the composition owns filePool; app.close() drains it */ },
      async close() { /* owned by the composition */ },
    };
  }, 180_000);

  afterAll(async () => {
    try { await testApp?.app.close(); }
    finally { try { await keyGeneration?.close(); } finally { try { await base?.close(); } finally { await closeLedger?.(); } } }
  }, 30000);
  /**
   * Real PostgreSQL wait edge: the backend pids currently blocked, directly or
   * transitively, by `holder`. `pg_locks` + `pg_blocking_pids` are used instead of
   * `pg_stat_activity.wait_event_type`, which is not visible for another role's
   * sessions in this contour.
   */
  async function blockedBehind(holder: number): Promise<number[]> {
    const { rows } = await db().db.query<{ pid: number }>(`WITH RECURSIVE pending AS (
      SELECT $1::int AS pid
      UNION
      SELECT a.pid FROM (SELECT DISTINCT pid FROM pg_locks WHERE NOT granted AND pid IS NOT NULL) a
        JOIN pending p ON p.pid = ANY(pg_blocking_pids(a.pid))
    ) SELECT pid FROM pending WHERE pid <> $1`, [holder]);
    return rows.map((row) => row.pid);
  }

  async function waitForBlocked(holder: number, expected: number): Promise<number[]> {
    const until = performance.now() + 8_000;
    do {
      const pids = await blockedBehind(holder);
      if (pids.length >= expected) { return pids; }
      await delay(20);
    } while (performance.now() < until);
    throw new Error(`Expected ${String(expected)} observed lock contender(s) behind ${String(holder)}`);
  }

  /** Holds the intent row `FOR UPDATE` — the first row lock both paths take. */
  async function withHeldIntent<T>(intentId: string,
    run: (held: { readonly pid: number; release(): Promise<void> }) => Promise<T>): Promise<T> {
    const holder = await db().db.connect();
    const state = { released: false };
    try {
      await holder.query('BEGIN');
      await holder.query('SELECT id FROM foundation.file_upload_intents WHERE id=$1 FOR UPDATE', [intentId]);
      const { rows: [backend] } = await holder.query<{ pid: number }>('SELECT pg_backend_pid() AS pid');
      if (backend === undefined) { throw new Error('Missing holder backend pid'); }
      return await run({ pid: backend.pid, async release() {
        if (!state.released) { state.released = true; await holder.query('COMMIT'); }
      } });
    } finally {
      if (!state.released) { await holder.query('ROLLBACK').catch(() => undefined); }
      holder.release();
    }
  }

  /**
   * Attach queues FIRST, the real retention sweep queues SECOND, both behind one
   * genuine `FOR UPDATE` hold on the intent row. When the hold is released the
   * attach wins the lock queue, so the sweep must defer — not delete.
   */
  async function attachFirst(intentId: string, body: unknown, form: BrowserForm, key: string) {
    let attach: Promise<Reply> | undefined;
    let retention: Promise<Awaited<ReturnType<typeof plan>>> | undefined;
    try {
      return await withHeldIntent(intentId, async (held) => {
        const queuedAttach = https('POST', `${pub}/repair-requests`, body, mutate(form, key));
        attach = queuedAttach;
        await waitForBlocked(held.pid, 1);
        const queuedRetention = plan();
        retention = queuedRetention;
        try {
          await waitForBlocked(held.pid, 2);
        } finally { await held.release(); }
        const reply = accepted(await queuedAttach, 201);
        const planned = await queuedRetention;
        return { reply, planned };
      });
    } catch (error) {
      await attach?.catch(() => undefined);
      await retention?.catch(() => undefined);
      throw error;
    }
  }

  /**
   * Retention queues FIRST, the attach queues SECOND, same real `FOR UPDATE` hold.
   * The sweep wins, freezes the control, and the attach must then be refused.
   */
  async function deleteFirst(intentId: string, body: unknown, form: BrowserForm) {
    let attach: Promise<Reply> | undefined;
    let retention: Promise<Awaited<ReturnType<typeof plan>>> | undefined;
    try {
      return await withHeldIntent(intentId, async (held) => {
        const queuedRetention = plan();
        retention = queuedRetention;
        await waitForBlocked(held.pid, 1);
        const queuedAttach = https('POST', `${pub}/repair-requests`, body, mutate(form));
        attach = queuedAttach;
        try {
          await waitForBlocked(held.pid, 2);
        } finally { await held.release(); }
        const planned = await queuedRetention;
        const reply = await queuedAttach;
        return { planned, reply };
      });
    } catch (error) {
      await attach?.catch(() => undefined);
      await retention?.catch(() => undefined);
      throw error;
    }
  }

  /** The exact FK identity a refused write produced, or `undefined` when it passed. */
  async function fkFailure(statement: () => Promise<unknown>):
  Promise<{ code: string | undefined; constraint: string | undefined } | undefined> {
    return await statement().then(() => undefined, (error: unknown) => {
      const failure = error as { code?: string; constraint?: string };
      return { code: failure.code, constraint: failure.constraint };
    });
  }

  function deletion() {
    const broker = createSyntheticDeleteBroker({ mode: 'local-synthetic', namespace: epoch.namespace, epoch: epoch.epoch,
      targets: [{ mode: 'local-synthetic', ...bucket.target, ...bucket.rw, allowedEndpoint: bucket.target.endpoint,
        ...TECHNICAL_TIMEOUTS }] });
    const context = { pool: fileFixture().runtime, epoch, policy: retentionPolicy(),
      scope: ledger.scope, ledger: ledger.ledger, verifier: ledger.verifier };
    return {
      reconcile: () => reconcileFileDeletion({ ...context, grant: operator('DELETE'), broker }, signal()),
      drain: async () => {
        const flipped = await db().db.query(`UPDATE foundation.file_runtime_epochs SET mode='FENCED'
          WHERE singleton AND mode='ACTIVE' AND namespace_id=$1 AND epoch=$2`, [epoch.namespace, epoch.epoch.toString()]);
        expect(flipped.rowCount).toBe(1);
        return await drainFencedFileDecisions({ ...context, grant: operator('SOURCE_DRAIN') }, signal());
      },
      close: () => revokeDeleteBroker(broker),
    };
  }

  function s3(): S3Client {
    return new S3Client({ endpoint: bucket.target.endpoint, region: bucket.target.region,
      forcePathStyle: true, maxAttempts: 1, credentials: bucket.ro });
  }

  async function exactObjects(intentId: string) {
    const { rows } = await db().db.query<{ kind: 'RAW' | 'SANITIZED'; attempt: string; key: string; sha: string; bytes: string }>(`
      SELECT 'RAW' AS kind,id AS attempt,object_key AS key,verified_sha256 AS sha,verified_bytes::text AS bytes
      FROM foundation.file_upload_attempts WHERE intent_id=$1 AND state='VERIFIED'
      UNION ALL
      SELECT 'SANITIZED',a.id,a.object_key,p.served_sha256,p.served_bytes::text
      FROM foundation.file_publications p JOIN foundation.file_sanitized_attempts a ON a.id=p.sanitized_attempt_id
      WHERE p.intent_id=$1 AND a.state='VERIFIED' ORDER BY kind`, [intentId]);
    const [raw, served] = rows;
    if (rows.length !== 2 || raw?.kind !== 'RAW' || served?.kind !== 'SANITIZED') { throw new Error('Missing exact file objects'); }
    return [raw, served] as const;
  }

  /** Real bounded GET: the digest is computed over the bytes actually read. */
  async function objectDigest(client: S3Client, key: string, expectedBytes: string): Promise<string> {
    const bytes = Number(expectedBytes);
    // Read exactly one small fixture object, not a prefix that could match a
    // longer object. Content-Range also proves the full stored object length.
    expect(Number.isSafeInteger(bytes) && bytes > 0 && bytes <= 65_536).toBe(true);
    const last = String(bytes - 1);
    const object = await client.send(new GetObjectCommand(
      { Bucket: bucket.target.bucket, Key: key, Range: `bytes=0-${last}` }), { abortSignal: AbortSignal.timeout(5_000) });
    expect(object.ContentLength).toBe(bytes);
    expect(object.ContentRange).toBe(`bytes 0-${last}/${String(bytes)}`);
    const body = await object.Body?.transformToByteArray();
    if (body === undefined) { throw new Error('Empty object body'); }
    expect(body.byteLength).toBe(bytes);
    return sha256(body);
  }

  const idle = { examined: 0, advanced: 0, deferred: 0 };
  const advanced = { examined: 1, advanced: 1, deferred: 0 };

  async function verifyReadyBytes(ready: NonNullable<Awaited<ReturnType<typeof readyFile>>>, served: { sha: string; bytes: string }) {
    // Reserve the reviewed transport chunk in addition to the two staged copies.
    const policy = accessPolicy({ maxBufferedBytes: 2_200_000, maxChunkBytes: 4_096 });
    const budget = createFileReadBudget({ mode: 'local-synthetic', namespace: epoch.namespace, singleProcess: true,
      maxBufferedBytes: policy.maxBufferedBytes, maxActiveStreams: policy.maxActiveStreams, maxLiveOperationsPerOwner: 4 });
    const access = { pool: fileFixture().runtime, epoch, storage: ready.storage, policy, budget };
    const bytes = Number(served.bytes);
    expect(await readReadyMetadata(access, ready.file)).toEqual({ fileId: ready.publicationFileId, state: 'READY', mime: 'image/png', bytes });
    const ticket = await openReadyStream(access, { ...ready.file, signal: AbortSignal.timeout(12_000) });
    try {
      const chunks: Uint8Array[] = [];
      let length = 0;
      for (;;) {
        const part = await readReadyChunk(ticket);
        if (part.kind === 'EOF') { break; }
        length += part.bytes.length;
        expect(length).toBeLessThanOrEqual(bytes);
        expect(part.bytes.length).toBeGreaterThan(0);
        chunks.push(part.bytes);
      }
      expect(length).toBe(bytes);
      expect(sha256(Buffer.concat(chunks))).toBe(served.sha);
    } finally { await closeReadyStream(ticket); }
  }

  function actualDeletes(spy: ReturnType<typeof spyOnS3>) {
    return spy.mock.calls.flatMap(([cmd]) => cmd instanceof DeleteObjectCommand
      ? [{ bucket: cmd.input.Bucket, key: cmd.input.Key }] : []);
  }
  const spyOnS3 = () => vi.spyOn(S3Client.prototype, 'send');

  it('creates the real request with a real READY attachment and preserves every digest', async () => {
    const form = await issue();
    const evidenceId = await given(form);
    const anchor = { sessionId: form.sid, token: rawToken(form), evidenceId,
      documentId: fixture.consentDocumentId, documentVersionId: fixture.consentDocumentVersionId };
    // The reviewed engine bridge is deliberately single-file (one raw-scan/decode/
    // output-scan triple per ticket), so this suite produces exactly one real READY
    // file per run. That file is the attachment under test.
    const ready = await readyFile(anchor, await engineFixtureImage());
    if (ready === undefined) { throw new Error('The one-ticket engine bridge was already consumed in this invocation'); }
    const key = randomUUID();
    const body = repairBody(evidenceId, [ready.publicationFileId]);
    try {
      const { reply: created, planned } = await attachFirst(ready.file.intentId, body, form, key);
      // The attach won the queue; the concurrent sweep observed the link and deferred.
      expect(planned.advanced).toBe(0);

      const publicNumber = text(created.data(), 'publicNumber');
      // Exact replay: same bytes, no duplicate links, no second effect.
      const replay = accepted(await https('POST', `${pub}/repair-requests`, body, mutate(form, key)), 200);
      expect(replay.bytes).toBe(created.bytes);

      const { rows: [request] } = await db().db.query<{ id: string }>(
        'SELECT id FROM foundation.requests WHERE public_number=$1', [publicNumber]);
      if (request === undefined) { throw new Error('Missing created request'); }
      const requestId = request.id;

      const links = await db().db.query<{ file_id: string; intent_id: string; open_state: string;
        owner_session_id: string }>(`SELECT file_id,intent_id,open_state,owner_session_id
        FROM foundation.request_files WHERE request_id=$1 ORDER BY file_id`, [requestId]);
      expect(links.rows.map((row) => row.intent_id)).toEqual([ready.file.intentId]);
      expect(links.rows.map((row) => row.file_id)).toEqual([ready.publicationFileId]);
      for (const row of links.rows) {
        expect(row.open_state).toBe('OPEN');
        expect(row.owner_session_id).toBe(form.sid);
      }

      const intent = ready.file.intentId;
      const exact = await exactObjects(intent);
      const [raw, served] = exact;
      expect(raw.sha).toBe(ready.binding.sha256);
      await verifyReadyBytes(ready, served);
      const before = await control(fileFixture(), intent);
      expect(before).toMatchObject({ delete_state: 'OPEN', access_epoch: '1' });
      expect(await items(fileFixture(), intent)).toEqual([]);
      const priorAudit = await auditPairs(fileFixture(), intent);
      const head = await ledger.floor.read(epoch.namespace);
      expect(head.seq).toBe(0n);
      const work = deletion();
      const sends = spyOnS3();
      const objects = s3();
      try {
        // An old-style runtime operation ignores the link. Supply every field
        // the production DELETE_DECIDED transition requires; assert the FK itself.
        const oldWriter = await fileFixture().runtime.connect();
        try {
          await oldWriter.query('BEGIN');
          expect(await fkFailure(() => oldWriter.query(`UPDATE foundation.file_privacy_controls
            SET delete_state='PENDING_LEDGER',delete_event_id=$2,delete_policy_id=$3,delete_graph_sha256=$4
            WHERE intent_id=$1 AND access_epoch=1 AND NOT hold_active AND delete_state='OPEN'`,
          [intent, randomUUID(), randomUUID(), 'b'.repeat(64)])))
            .toEqual({ code: '23001', constraint: 'request_files_intent_id_open_state_fkey' });
        } finally { try { await oldWriter.query('ROLLBACK'); } finally { oldWriter.release(); } }
        expect(await plan()).toEqual(idle);
        expect(await work.reconcile()).toEqual(idle);
        expect(await work.drain()).toEqual(idle);
        await expect(work.reconcile()).rejects.toMatchObject({ code: 'NOT_CONFIGURED' });
        expect(actualDeletes(sends)).toEqual([]);
        expect(await ledger.events()).toEqual([]);
        expect(await ledger.floor.read(epoch.namespace)).toEqual(head);
        expect(await auditPairs(fileFixture(), intent)).toEqual(priorAudit);
        expect(await control(fileFixture(), intent)).toEqual(before);
        expect(await items(fileFixture(), intent)).toEqual([]);
        expect((await db().db.query('SELECT 1 FROM foundation.request_files WHERE request_id=$1 AND file_id=$2 AND intent_id=$3',
          [requestId, ready.publicationFileId, intent])).rowCount).toBe(1);
        for (const expected of exact) { expect(await objectDigest(objects, expected.key, expected.bytes)).toBe(expected.sha); }
      } finally { sends.mockRestore(); objects.destroy(); await work.close(); }
    } finally {
      await ready.storage.close().catch(() => undefined);
    }
  }, 240_000);

  it('refuses the HTTP create once the real retention decision moved the control', async () => {
    const form = await issue();
    const evidenceId = await given(form);
    const anchor = { sessionId: form.sid, token: rawToken(form), evidenceId,
      documentId: fixture.consentDocumentId, documentVersionId: fixture.consentDocumentVersionId };
    const ready = await readyFile(anchor, await engineFixtureImage());
    if (ready === undefined) { throw new Error('The one-ticket engine bridge was already consumed in this invocation'); }
    try {
      const intent = ready.file.intentId;
      const exact = await exactObjects(intent);
      const body = repairBody(evidenceId, [ready.publicationFileId]);
      const { planned, reply } = await deleteFirst(intent, body, form);
      expect(planned).toEqual(advanced);
      const frozen = await control(fileFixture(), intent);
      expect(frozen).toMatchObject({ delete_state: 'PENDING_LEDGER', access_epoch: '2' });
      const subjectCount = async () => (await db().db.query<{ n: number, submits: number }>(`SELECT
        (SELECT count(*)::int FROM foundation.request_files WHERE file_id=$1) AS n,
        (SELECT count(*)::int FROM foundation.request_session_submits WHERE session_id=$2) AS submits`,
      [ready.publicationFileId, form.sid])).rows[0];
      expect(reply.status).toBe(404);
      expect(reply.bytes).not.toContain(ready.publicationFileId);
      expect(await subjectCount()).toEqual({ n: 0, submits: 0 });

      const work = deletion();
      const objects = s3();
      const sends = spyOnS3();
      try {
        for (const object of exact) { expect(await objectDigest(objects, object.key, object.bytes)).toBe(object.sha); }
        expect(await ledger.events()).toEqual([]);
        expect(await work.reconcile()).toEqual(advanced);
        expect(await work.reconcile()).toEqual(advanced);
        expect(await work.reconcile()).toEqual(idle);
        expect(actualDeletes(sends)).toHaveLength(2);
        expect(actualDeletes(sends)).toEqual(expect.arrayContaining(exact.map(({ key }) => ({ bucket: bucket.target.bucket, key }))));
        expect(await ledger.events()).toEqual([expect.objectContaining({ intent_id: intent, event_id: frozen.delete_event_id })]);
        expect((await ledger.floor.read(epoch.namespace)).seq).toBe(1n);
        expect(await control(fileFixture(), intent)).toMatchObject({ delete_state: 'CONFIRMED_ABSENT', access_epoch: '2' });
        const settled = await items(fileFixture(), intent);
        expect(settled).toHaveLength(exact.length);
        for (const [i, { attempt, kind, key }] of exact.entries()) {
          expect(settled[i]).toMatchObject({ event_id: frozen.delete_event_id, attempt_id: attempt, attempt_kind: kind,
            object_key: key, state: 'CONFIRMED_ABSENT', write_proof: 'VERIFIED_SETTLED', claim_generation: 1 });
        }
        for (const { key } of exact) {
          const absent: unknown = await objects.send(new GetObjectCommand({ Bucket: bucket.target.bucket, Key: key }),
            { abortSignal: AbortSignal.timeout(5_000) }).catch((error: unknown) => error);
          expect(absent).toBeInstanceOf(NoSuchKey);
          expect(absent).toMatchObject({ $metadata: { httpStatusCode: 404 } });
        }
        const afterBroker = await https('POST', `${pub}/repair-requests`, body, mutate(form));
        expect(afterBroker.status).toBe(404);
        expect(afterBroker.bytes).not.toContain(ready.publicationFileId);
        expect(await subjectCount()).toEqual({ n: 0, submits: 0 });
      } finally { sends.mockRestore(); objects.destroy(); await work.close(); }

      // A legitimate, committed no-attachment request of the SAME anchor: the
      // defensive INSERT below references a real request and a real submit edge, so
      // the only possible violation is the reviewed attachment interlock.
      const plain = accepted(await https('POST', `${pub}/repair-requests`,
        repairBody(evidenceId), mutate(form)), 201);
      const { rows: [realRequest] } = await db().db.query<{ id: string }>(
        'SELECT id FROM foundation.requests WHERE public_number=$1', [text(plain.data(), 'publicNumber')]);
      if (realRequest === undefined) { throw new Error('Missing committed no-attachment request'); }

      const client = await db().db.connect();
      try {
        await client.query('BEGIN');
        const refused = await fkFailure(() => client.query(`INSERT INTO foundation.request_files
          (request_id,owner_session_id,intent_id,file_id) VALUES ($1,$2,$3,$4)`,
        [realRequest.id, form.sid, ready.file.intentId, ready.publicationFileId]));
        // Exact constraint identity: not "some FK", and not a random request id.
        expect(refused).toEqual({ code: '23503', constraint: 'request_files_intent_id_open_state_fkey' });
        await client.query('ROLLBACK');
      } finally { client.release(); }
    } finally { await ready.storage.close().catch(() => undefined); }
  }, 240_000);
});



