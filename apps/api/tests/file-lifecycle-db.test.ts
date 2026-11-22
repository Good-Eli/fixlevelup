import { randomUUID } from 'node:crypto';
import sharp from 'sharp';
import { afterAll, afterEach, beforeAll, expect, it } from 'vitest';
import { createFileReadBudget, readReadyMetadata } from '../src/files/file-access/index.js';
import { processQuarantine } from '../src/files/file-lifecycle/index.js';
import type { FileProcessingPolicy, LocalFileProcessor } from '../src/files/file-lifecycle/contract.js';
import { createLocalFileProcessor } from '../src/files/file-processing/processor.js';
import { definitionEngineImage } from '../src/files/file-processing/protocol.js';
import type { ChildResult } from '../src/files/file-processing/processor.js';
import { cancelFileUploadIntent } from '../src/files/reservations/index.js';
import { recordConsentGiven, revokeRequestSession } from '../src/settings/legal/index.js';
import { proof, publishNextConsentForm, revokeConsent } from './file-reservations-fixture.js';
import type { FileReservationsFixture } from './file-reservations-fixture.js';
import { assertRefusal, attempts, bindings, gate, pid, poolWithCommitHook, waitForBlockingPid, waitForDbExpiry } from './file-upload-fixture.js';
import { settle, sha256Hex } from './file-storage-fixture.js';
import {
  accessPolicy, assertNoReady, assertProcessReceipt, closeFixture, control, epoch, expectRefusal, expiresIn, faultEvidence,
  lifecycleIntegration, maxLiveOperationsPerOwner, png, processingContext, processingPolicy, provision, publications,
  sanitized, seedReadFixture, signal, startLifecycleDb, uploadPolicy, wireStore, withQueryHook,
} from './file-lifecycle-fixture.js';

const broken = new Error('synthetic-private-pg-source-diagnostic');
const blockedProcessor: LocalFileProcessor = {
  process: () => Promise.resolve({ kind: 'INDETERMINATE', reason: 'SCAN_FAILED' }), isEvidenceCurrent: () => false,
};
const bytesOnly = (output: Uint8Array): ChildResult => ({
  reaped: true, exitCode: 0, signal: null, stdinComplete: true, stdoutEof: true, stderrEof: true,
  stdout: output, stderr: new Uint8Array(),
});

lifecycleIntegration('C coordinator with isolated PostgreSQL and controlled S3 wire', () => {
  let db: FileReservationsFixture;
  let wire: Awaited<ReturnType<typeof wireStore>>;
  beforeAll(async () => { db = await startLifecycleDb(); }, 40_000);
  afterEach(async () => { await closeFixture(wire); });
  afterAll(async () => { await closeFixture(db); });

  it('no configuration, wrong epoch, and non-live epoch cannot reach GET or worker', async () => {
    wire = await wireStore();
    const { file } = await provision(db, wire.storage);
    const baseline = wire.socket.requests.length;
    let calls = 0;
    const ctx = processingContext(db, wire.storage, { ...blockedProcessor, process: () => {
      calls++;
      return Promise.resolve({ kind: 'INDETERMINATE', reason: 'SCAN_FAILED' });
    } });
    await expectRefusal(processQuarantine({ ...ctx, policy: undefined as unknown as FileProcessingPolicy }, { ...file, signal: signal() }), 'NOT_CONFIGURED');
    await expectRefusal(processQuarantine({ ...ctx, processor: {} as LocalFileProcessor }, { ...file, signal: signal() }), 'NOT_CONFIGURED');
    await expectRefusal(processQuarantine({ ...ctx, epoch: { ...ctx.epoch, epoch: ctx.epoch.epoch + 1n } }, { ...file, signal: signal() }), ['NOT_CONFIGURED', 'STALE_CLAIM']);
    expect(wire.socket.requests).toHaveLength(baseline);
    expect(calls).toBe(0);
    await assertNoReady(db, file.intentId);
  });

  it.each(['raw hit', 'second scan unavailable'] as const)('%s suppresses sanitized PUT and READY', async (scenario) => {
    wire = await wireStore();
    const { file } = await provision(db, wire.storage);
    const seen: string[] = [];
    let decoded = 0;
    const processor = createLocalFileProcessor({
      scan: (input) => {
        seen.push(sha256Hex(input));
        if (scenario === 'raw hit') {return Promise.resolve({ ...bytesOnly(Buffer.from('stdin: Synthetic.Fixture FOUND\n')), exitCode: 1 });}
        if (seen.length === 2) { return Promise.resolve({ ...bytesOnly(new Uint8Array()), exitCode: 2 }); }
        return Promise.resolve(bytesOnly(Buffer.from('stdin: OK\n')));
      },
      decode: () => { decoded++; return Promise.resolve(bytesOnly(png)); },
    }, {
      epoch: { engineVersion: '1.4.7', engineImageSha256: definitionEngineImage,
        defsSha256: 'a'.repeat(64), defsBuiltAt: new Date(Date.now() - 1_000).toISOString() },
      maxRawBytes: 64_000, maxOutputBytes: 64_000, maxJobs: 1, maxWallMs: 90_000,
    });
    await expectRefusal(processQuarantine(processingContext(db, wire.storage, processor), { ...file, signal: signal() }), 'PROCESSING_DENIED');
    expect(seen).toEqual(Array.from({ length: scenario === 'raw hit' ? 1 : 2 }, () => sha256Hex(png)));
    expect(decoded).toBe(scenario === 'raw hit' ? 0 : 1);
    expect(wire.sanitizedPuts()).toEqual([]);
    await assertNoReady(db, file.intentId);
  });

  it('does not trust a worker result whose output bytes disagree with its purported digest', async () => {
    wire = await wireStore();
    const { file } = await provision(db, wire.storage);
    const processor: LocalFileProcessor = {
      process: ({ raw }) => Promise.resolve({ ...faultEvidence(png, raw), served: { bytes: png.length, sha256: '0'.repeat(64) } }),
      isEvidenceCurrent: () => true,
    };
    await expectRefusal(processQuarantine(processingContext(db, wire.storage, processor), { ...file, signal: signal() }), 'PROCESSING_DENIED');
    expect(await sanitized(db, file.intentId)).toEqual([]);
    expect(wire.sanitizedPuts()).toEqual([]);
    await assertNoReady(db, file.intentId);
  });

  it.each(['revoke', 'new GIVEN', 'new document', 'cancel', 'session revoked', 'session expiry', 'intent expiry', 'policy expiry'] as const)(
    'rejects %s committed while the worker is held outside PG', async (scenario) => {
      const inWorker = gate();
      const resumeWorker = gate();
      wire = await wireStore();
      const shortExpiry = expiresIn(1_800);
      const fixture = await provision(db, wire.storage, png, scenario === 'intent expiry' ? { intentExpiry: shortExpiry }
        : scenario === 'session expiry' ? { sessionExpiry: shortExpiry, intentExpiry: shortExpiry } : {});
      const { anchor, file, intent } = fixture;
      const processor: LocalFileProcessor = {
        process: async ({ raw }) => { inWorker.open(); await resumeWorker.wait(); return faultEvidence(png, raw); },
        isEvidenceCurrent: () => true,
      };
      const ctx = processingContext(db, wire.storage, processor);
      const pending = settle(processQuarantine(scenario === 'policy expiry' ? { ...ctx, policy: { ...ctx.policy, expiresAt: shortExpiry } } : ctx,
        { ...file, signal: signal() }));
      const codes = {
        revoke: ['CONSENT_REVOKED'], 'new GIVEN': ['CONSENT_NOT_CURRENT'], 'new document': ['CONSENT_NOT_CURRENT', 'CONSENT_STALE'],
        cancel: ['INTENT_CANCELLED'], 'session revoked': ['SESSION_REVOKED'], 'session expiry': ['SESSION_EXPIRED', 'ABORTED'],
        'intent expiry': ['INTENT_EXPIRED', 'ABORTED'],
        'policy expiry': ['NOT_CONFIGURED', 'STALE_CLAIM', 'ABORTED'],
      }[scenario];
      try {
        await inWorker.wait();
        expect(db.runtime.idleCount).toBe(db.runtime.totalCount);
        if (scenario === 'revoke' || scenario === 'new GIVEN') {
          await revokeConsent(db, anchor, anchor.evidenceId);
          if (scenario === 'new GIVEN') {
            const given = await db.inTransaction((client) => recordConsentGiven(client, {
              session: proof(anchor), purpose: 'REQUEST_PROCESSING', documentVersionId: anchor.documentVersionId,
              accepted: true, evidenceRef: randomUUID(),
            }));
            expect(given.evidenceId).not.toBe(anchor.evidenceId);
          }
        } else if (scenario === 'new document') {
          const doc = (await db.migrator.query<{ row_version: number }>('SELECT row_version FROM foundation.legal_documents WHERE id=$1', [anchor.documentId])).rows[0];
          if (doc === undefined) {throw new Error('missing fixture document');}
          await publishNextConsentForm(db, doc.row_version);
        } else if (scenario === 'cancel') {
          await db.inTransaction((client) => cancelFileUploadIntent(client, { ...file, expectedVersion: intent.rowVersion }));
        } else if (scenario === 'session revoked') {
          await db.inTransaction((client) => revokeRequestSession(client, proof(anchor)));
        } else {
          await waitForDbExpiry(db, shortExpiry);
        }
        resumeWorker.open();
        const outcome = await pending;
        assertRefusal(outcome.ok ? undefined : outcome.error, codes, [anchor.token]);
        expect(wire.sanitizedPuts()).toEqual([]);
        await assertNoReady(db, file.intentId);
        expect(await bindings(db, file.intentId)).toEqual([fixture.binding]);
      } finally { resumeWorker.open(); await pending; }
    }, 12_000,
  );

  it.each(['register', 'dispatch'] as const)('does not PUT after lost %s acknowledgement', async (stage) => {
    wire = await wireStore();
    const { file } = await provision(db, wire.storage);
    const pool = poolWithCommitHook(db.runtime, async (n, _client, commit) => {
      const result = await commit();
      if (n === (stage === 'register' ? 3 : 4)) {throw broken;}
      return result;
    });
    const processor: LocalFileProcessor = { process: ({ raw }) => Promise.resolve(faultEvidence(png, raw)), isEvidenceCurrent: () => true };
    const ctx = processingContext(db, wire.storage, processor, { pool, uploadPolicy: uploadPolicy({ maxAttemptsPerOwner: 2 }) });
    await expectRefusal(processQuarantine(ctx, { ...file, signal: signal() }), ['WRITE_OUTCOME_UNKNOWN', 'CONFLICT']);
    const [row] = await sanitized(db, file.intentId);
    expect(row?.state).toMatch(stage === 'register' ? /^(REGISTERED|FAILED_NOBYTES)$/u : /^(IN_FLIGHT|UNKNOWN)$/u);
    expect(wire.sanitizedPuts()).toEqual([]);
    await assertNoReady(db, file.intentId);
    await expectRefusal(processQuarantine({ ...ctx, pool: db.runtime }, { ...file, signal: signal() }),
      'ATTEMPT_BUDGET_EXCEEDED');
    expect(await sanitized(db, file.intentId)).toEqual([row]);
  });

  it('commits register and dispatch before first PUT; revoked definitions after verification retain combined physical debt', async () => {
    const pausedRegister = gate(); const register = gate(); const pausedDispatch = gate(); const dispatch = gate();
    const processor = createLocalFileProcessor({
      // Fault scheduling only: the real-engine publication is a separate Garage test.
      scan: () => Promise.resolve(bytesOnly(Buffer.from('stdin: OK\n'))),
      decode: () => Promise.resolve(bytesOnly(png)),
    }, {
      epoch: { engineVersion: '1.4.7', engineImageSha256: definitionEngineImage,
        defsSha256: 'a'.repeat(64), defsBuiltAt: new Date(Date.now() - 1_000).toISOString() },
      maxRawBytes: png.length, maxOutputBytes: png.length, maxJobs: 1, maxWallMs: 90_000,
    });
    wire = await wireStore((path, method) => path.includes('/sanitized/') && method === 'GET' ? (req, res, record) => {
      // The socket serves the full object; independently revoke the trusted wrapper's epoch.
      res.once('finish', () => { processor.revokeDefinitions(); });
      wire.store.handler(req, res, record);
    } : undefined);
    const { file, binding } = await provision(db, wire.storage);
    const ctx = processingContext(db, wire.storage, processor,
      { pool: poolWithCommitHook(db.runtime, async (n, _client, commit) => {
      if (n === 3) { pausedRegister.open(); await register.wait(); }
      if (n === 4) { pausedDispatch.open(); await dispatch.wait(); }
      return commit();
    }), uploadPolicy: uploadPolicy({ maxPhysicalBytesPerOwner: 2 * png.length }) });
    const boundedContext = { ...ctx, policy: { ...ctx.policy, maxRawBytes: png.length, maxOutputBytes: png.length } };
    const action = settle(processQuarantine(boundedContext, { ...file, signal: signal() }));
    try {
      await pausedRegister.wait();
      expect(await sanitized(db, file.intentId)).toEqual([]);
      expect(wire.sanitizedPuts()).toEqual([]);
      register.open();
      await pausedDispatch.wait();
      expect((await sanitized(db, file.intentId))[0]?.state).toBe('REGISTERED');
      expect(wire.sanitizedPuts()).toEqual([]);
      dispatch.open();
      const outcome = await action;
      assertRefusal(outcome.ok ? undefined : outcome.error, ['PROCESSING_DENIED', 'WRITE_OUTCOME_UNKNOWN']);
      expect(wire.sanitizedPuts()).toHaveLength(1);
      expect(wire.sanitizedGets()).toHaveLength(1);
      expect(await bindings(db, file.intentId)).toEqual([binding]);
      expect((await attempts(db, file.intentId))[0]?.charged_bytes).toBe(String(png.length));
      expect(await sanitized(db, file.intentId)).toMatchObject([{ charged_bytes: String(png.length), state: 'UNKNOWN' }]);
      await assertNoReady(db, file.intentId);
      const valid = { ...boundedContext, pool: db.runtime, processor: { ...ctx.processor, isEvidenceCurrent: () => true } };
      await expectRefusal(processQuarantine(valid, { ...file, signal: signal() }), 'PHYSICAL_BUDGET_EXCEEDED');
      expect(wire.sanitizedPuts()).toHaveLength(1);
    } finally { register.open(); dispatch.open(); await action; }
  }, 15_000);

  it('expired occupied processing claim cannot be replaced until the local holder actually settles', async () => {
    wire = await wireStore();
    const { file } = await provision(db, wire.storage);
    const entered = gate(); const finish = gate();
    const ctx = processingContext(db, wire.storage, {
      ...blockedProcessor, process: async () => { entered.open(); await finish.wait(); return { kind: 'INDETERMINATE', reason: 'SCAN_FAILED' }; },
    });
    const short = { ...ctx, policy: { ...ctx.policy, leaseMs: 1_400, wallMs: 1_100 } };
    const working = settle(processQuarantine(short, { ...file, signal: signal() }));
    try {
      await entered.wait();
      const lease = await control(db, file.intentId);
      if (lease === undefined || lease.processing_expires_at === null) {throw new Error('No working lease');}
      await waitForDbExpiry(db, lease.processing_expires_at);
      await expectRefusal(processQuarantine(ctx, { ...file, signal: signal() }), 'PROCESSING_ACTIVE');
      expect(await control(db, file.intentId)).toEqual(lease);
      finish.open();
      const failure = await working;
      expect(failure.ok).toBe(false);
      expect((await control(db, file.intentId))?.processing_lease_id).toBeNull();
      await expectRefusal(processQuarantine({ ...ctx, processor: blockedProcessor }, { ...file, signal: signal() }), 'PROCESSING_DENIED');
      expect((await control(db, file.intentId))?.processing_generation).toBe(lease.processing_generation + 1);
      expect(wire.sanitizedPuts()).toEqual([]);
    } finally { finish.open(); await working; }
  }, 12_000);

  it('unsettled child failure conservatively keeps the processing claim occupied', async () => {
    wire = await wireStore();
    const { file } = await provision(db, wire.storage);
    const ctx = processingContext(db, wire.storage, { ...blockedProcessor, process: () => Promise.reject(broken) });
    await expectRefusal(processQuarantine(ctx, { ...file, signal: signal() }), 'PROCESSING_DENIED');
    const held = await control(db, file.intentId);
    expect(held?.processing_lease_id).toMatch(/^[0-9a-f-]{36}$/u);
    await expectRefusal(processQuarantine({ ...ctx, processor: blockedProcessor }, { ...file, signal: signal() }), 'PROCESSING_ACTIVE');
    expect(await control(db, file.intentId)).toEqual(held);
    expect(wire.sanitizedPuts()).toEqual([]);
    await assertNoReady(db, file.intentId);
  });

  it('processing replay actually blocks at the publication SELECT and denies after policy expiry', async () => {
    wire = await wireStore();
    const { file, pub } = await seedReadFixture(db, wire);
    const dbLocker = await db.migrator.connect();
    const arriving = gate();
    const deadline = expiresIn(1_500);
    let waitingPid = -1;
    let replay: ReturnType<typeof settle> | undefined;
    try {
      await dbLocker.query('BEGIN');
      await dbLocker.query('LOCK TABLE foundation.file_publications IN ACCESS EXCLUSIVE MODE');
      const blocker = await pid(dbLocker);
      const pool = withQueryHook(db.runtime, (sql) => /SELECT[\s\S]+file_publications/iu.test(sql), async (_sql, client, query) => {
        waitingPid = await pid(client); arriving.open(); return query();
      });
      const ctx = processingContext(db, wire.storage, blockedProcessor, { pool });
      replay = settle(processQuarantine({ ...ctx, policy: { ...ctx.policy, expiresAt: deadline } }, { ...file, signal: signal() }));
      await arriving.wait();
      await waitForBlockingPid(db, blocker, waitingPid);
      await waitForDbExpiry(db, deadline);
      await dbLocker.query('COMMIT');
      const outcome = await replay;
      assertRefusal(outcome.ok ? undefined : outcome.error, 'NOT_CONFIGURED');
      const actual = await processQuarantine({ ...ctx, pool: db.runtime }, { ...file, signal: signal() });
      assertProcessReceipt(actual, file.intentId);
      expect((await publications(db, file.intentId))[0]?.id).toBe(pub);
      expect(wire.sanitizedPuts()).toEqual([]);
      expect(wire.sanitizedGets()).toEqual([]);
    } finally { await dbLocker.query('ROLLBACK'); dbLocker.release(); await replay; }
  }, 12_000);

  it.each(['policy expiry', 'publication age'] as const)(
    'ordinary process replay cannot reveal publication metadata after access %s', async (window) => {
      wire = await wireStore();
      const { file, pub } = await seedReadFixture(db, wire);
      const maxBufferedBytes = 2_200_000;
      const access = { pool: db.runtime, storage: wire.storage, epoch, policy: accessPolicy({ maxBufferedBytes }),
        budget: createFileReadBudget({ mode: 'local-synthetic', namespace: epoch.namespace, singleProcess: true,
          maxBufferedBytes, maxActiveStreams: 2, maxLiveOperationsPerOwner }) };
      expect(await readReadyMetadata(access, file)).toStrictEqual({ fileId: pub, state: 'READY', mime: 'image/png', bytes: png.length });
      const policy = window === 'policy expiry' ? { ...access.policy, expiresAt: expiresIn(-1_000) }
        : { ...access.policy, maxAccessAgeMs: 10 };
      await waitForDbExpiry(db, expiresIn(30));
      await expectRefusal(readReadyMetadata({ ...access, policy }, file), window === 'policy expiry' ? 'NOT_CONFIGURED' : 'NOT_READY');
      const requests = wire.socket.requests.length;
      const ctx = processingContext(db, wire.storage, blockedProcessor);
      assertProcessReceipt(await processQuarantine(ctx, { ...file, signal: signal() }), file.intentId);
      expect(wire.socket.requests).toHaveLength(requests);
      expect((await publications(db, file.intentId)).map(({ id }) => id)).toStrictEqual([pub]);
    },
  );

  it.each(['jpeg', 'png', 'webp', 'png missing IDAT'] as const)(
    'trusted host rejects untrusted decoder %s output before second scanner, PUT or READY', async (variant) => {
      wire = await wireStore();
      const incomplete = variant === 'png missing IDAT';
      const format = incomplete ? 'png' : variant;
      const mime = `image/${format}` as const;
      const image = (width: number) => sharp({ create: { width, height: 1, channels: 3, background: '#507090' } }).toFormat(format).toBuffer();
      const raw = await image(4);
      const output = incomplete ? Buffer.concat([raw.subarray(0, 33), raw.subarray(-12)]) : await image(9);
      if (!incomplete) {
        expect(await sharp(output).metadata()).toMatchObject({ format, width: 9, height: 1 });
        expect((await sharp(output).raw().toBuffer()).length).toBe(27);
      }
      const { file } = await provision(db, wire.storage, raw, { mime });
      const scanned: string[] = [];
      let decodeCalls = 0;
      const processor = createLocalFileProcessor({
        scan: (bytes) => { scanned.push(sha256Hex(bytes)); return Promise.resolve(bytesOnly(Buffer.from('stdin: OK\n'))); },
        decode: () => { decodeCalls++; return Promise.resolve(bytesOnly(output)); },
      }, {
        epoch: { engineVersion: '1.4.7', engineImageSha256: definitionEngineImage,
          defsSha256: 'a'.repeat(64), defsBuiltAt: new Date(Date.now() - 1_000).toISOString() },
        maxRawBytes: 64_000, maxOutputBytes: 64_000, maxJobs: 1, maxWallMs: 90_000,
      });
      const ctx = processingContext(db, wire.storage, processor, {
        policy: processingPolicy({ allowedMimeTypes: [mime], maxWidth: 8 }), uploadPolicy: uploadPolicy({ allowedMimeTypes: [mime] }),
      });
      await expectRefusal(processQuarantine(ctx, { ...file, signal: signal() }), 'PROCESSING_DENIED');
      expect(scanned).toStrictEqual([sha256Hex(raw)]);
      expect(decodeCalls).toBe(1);
      expect(wire.sanitizedPuts()).toEqual([]);
      expect(await sanitized(db, file.intentId)).toEqual([]);
      await assertNoReady(db, file.intentId);
    },
  );

  it('rolls back publication and VERIFIED row when final outbox insert fails', async () => {
    wire = await wireStore();
    const { file, binding } = await provision(db, wire.storage);
    const dbFault = withQueryHook(db.runtime, (sql) => /INSERT INTO foundation\.outbox_events/iu.test(sql), async (_sql, client, query) => {
      // Only fail the real publication outbox INSERT, after publication INSERT and audit.
      const matching = await client.query<{ found: boolean }>(`SELECT EXISTS (SELECT 1 FROM foundation.file_publications WHERE intent_id=$1) AS found`, [file.intentId]);
      if (matching.rows[0]?.found === true) {await client.query('SELECT 1/0');}
      return query();
    });
    const ctx = processingContext(db, wire.storage, { process: ({ raw }) => Promise.resolve(faultEvidence(png, raw)), isEvidenceCurrent: () => true }, { pool: dbFault });
    await expectRefusal(processQuarantine(ctx, { ...file, signal: signal() }), 'CONFLICT');
    expect(wire.sanitizedPuts()).toHaveLength(1);
    expect(wire.sanitizedGets()).toHaveLength(1);
    await assertNoReady(db, file.intentId);
    expect(await bindings(db, file.intentId)).toEqual([binding]);
    expect(await sanitized(db, file.intentId)).toMatchObject([{ charged_bytes: String(png.length), state: 'UNKNOWN' }]);
    expect((await db.migrator.query(`SELECT 1 FROM foundation.audit_logs
      WHERE details->>'intentId'=$1 AND operation='FILE_PUBLISHED'`, [file.intentId])).rowCount).toBe(0);
    expect((await db.migrator.query(`SELECT 1 FROM foundation.outbox_events
      WHERE payload->>'intentId'=$1 AND event_type='FILE_PUBLISHED'`, [file.intentId])).rowCount).toBe(0);
  });
});
