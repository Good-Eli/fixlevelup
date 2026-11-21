import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { cancelFileUploadIntent } from '../src/files/reservations/index.js';
import { recordConsentGiven } from '../src/settings/legal/index.js';
import { uploadReservedFile } from '../src/files/upload-coordinator/index.js';
import { reconcileUploadAttempts } from '../src/files/upload-coordinator/reconcile.js';
import { fileReservationsIntegration, newConsentedAnchor, proof, publishNextConsentForm, revokeConsent } from './file-reservations-fixture.js';
import type { FileReservationsFixture } from './file-reservations-fixture.js';
import { asyncChunks, bounded, loopbackObjectStore, settle, sha256Hex } from './file-storage-fixture.js';
import {
  FAILURE_MARKER, PNG, assertRefusal, assertUploadEventPairs, attempts, bindings, command, expectRefusal, gate, pid, policy,
  poolWithCommitHook, reserve, startUploadDb, until, uploadEvents, waitForBlockingPid, waitForDbExpiry, wire,
} from './file-upload-fixture.js';

fileReservationsIntegration('B2 coordinator with real PostgreSQL and controlled loopback S3', () => {
  let db: FileReservationsFixture;
  let dispose: (() => Promise<void>) | undefined;
  beforeAll(async () => { db = await startUploadDb(); dispose = () => db.close(); }, 180_000);
  afterAll(async () => { await dispose?.(); });

  it('commits registration before factory/first next, and dispatch before PUT, outside any checked-out DB client', async () => {
    const { anchor, intent } = await reserve(db, { exactLogicalQuota: true });
    const store = loopbackObjectStore();
    const transport = await wire(store.handler);
    const reads: string[] = [];
    const observeFirstByte = async (): Promise<void> => {
      const [row] = await attempts(db, intent.intentId);
      reads.push(row?.state ?? 'missing');
      expect(row?.dispatched_at).toBeNull();
      expect(db.runtime.idleCount).toBe(db.runtime.totalCount);
    };
    let factoryCalled = false;
    let wireSawDispatch = false;
    try {
      const putQuarantined: typeof transport.storage.putQuarantined = async (...args) => {
        const [row] = await attempts(db, intent.intentId);
        wireSawDispatch = row?.state === 'IN_FLIGHT' && row.dispatched_at instanceof Date;
        expect(db.runtime.idleCount).toBe(db.runtime.totalCount);
        return transport.storage.putQuarantined(...args);
      };
      const probeStorage = new Proxy(transport.storage, {
        get(target, key): unknown {
          if (key === 'putQuarantined') { return putQuarantined; }
          const value: unknown = Reflect.get(target, key, target);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
      const enteredCommit = gate();
      const finishCommit = gate();
      const primary = poolWithCommitHook(db.runtime, async (ordinal, client, commit) => {
        if (ordinal === 1) {
          expect((await client.query<{ isolation: string }>("SELECT current_setting('transaction_isolation') AS isolation")).rows[0]?.isolation)
            .toBe('read committed');
          enteredCommit.open();
          await finishCommit.wait();
        }
        return commit();
      });
      const run = settle(uploadReservedFile(primary, probeStorage, policy(), command(anchor, intent.intentId, {
        body: () => {
          factoryCalled = true;
          const factoryObservation = observeFirstByte();
          return (async function* () {
            await factoryObservation;
            await observeFirstByte();
            yield PNG;
          })();
        },
      })));
      try {
        await enteredCommit.wait();
        expect(await attempts(db, intent.intentId)).toEqual([]);
        expect(factoryCalled).toBe(false);
        expect(transport.socket.requests).toHaveLength(0);
      } finally {
        finishCommit.open();
      }
      expect(await run).toMatchObject({ ok: true, value: { state: 'QUARANTINED', replayed: false } });
      expect(reads).toEqual(['REGISTERED', 'REGISTERED']);
      expect(wireSawDispatch).toBe(true);
      expect(transport.socket.requests.map(({ method }) => method)).toEqual(['PUT', 'GET']);
      await assertUploadEventPairs(db, intent.intentId);
    } finally { await transport.close(); }
  });

  it.each([
    { stage: 1, lostAfterCommit: false, expectedPuts: 0 },
    { stage: 1, lostAfterCommit: true, expectedPuts: 1 },
    { stage: 2, lostAfterCommit: false, expectedPuts: 0 },
    { stage: 2, lostAfterCommit: true, expectedPuts: 0 },
    { stage: 3, lostAfterCommit: false, expectedPuts: 1 },
    { stage: 3, lostAfterCommit: true, expectedPuts: 1 },
  ])('loses COMMIT reply: stage $stage, server applied = $lostAfterCommit', async ({ stage, lostAfterCommit, expectedPuts }) => {
    const { anchor, intent } = await reserve(db);
    const transport = await wire(loopbackObjectStore().handler);
    const observed: number[] = [];
    let bodyCalls = 0;
    let lost = false;
    let affectedPid: number | undefined;
    let beganWithFreshBackend = false;
    const primary = poolWithCommitHook(db.runtime, async (ordinal, client, commit) => {
      if (ordinal !== stage) { return commit(); }
      affectedPid = await pid(client);
      if (lostAfterCommit) { await commit(); }
      // Lost before commit is modeled by a server-side rollback and a lost reply,
      // not a fake storage error nor an invented success/rollback state.
      else { await client.query('ROLLBACK'); }
      lost = true;
      throw Object.assign(new Error(FAILURE_MARKER), { code: 'ECONNRESET' });
    }, (client) => { const backend = client as typeof client & { processID: number }; observed.push(backend.processID); });
    const byKey = command(anchor, intent.intentId, { body: () => {
      bodyCalls += 1;
      beganWithFreshBackend = !lost || observed.length >= 2 && observed[1] !== affectedPid;
      return asyncChunks([PNG]);
    } });
    try {
      const result = await settle(uploadReservedFile(primary, transport.storage, policy(), byKey));
      expect(lost).toBe(true);
      if (!lostAfterCommit || stage === 2) {
        expect(result.ok).toBe(false);
        if (!result.ok) {
          assertRefusal(result.error, stage === 1 ? 'STALE_ATTEMPT' : 'WRITE_OUTCOME_UNKNOWN');
        }
        expect(await bindings(db, intent.intentId)).toEqual([]);
        if (stage === 1) {
          expect(bodyCalls).toBe(0);
          expect(await attempts(db, intent.intentId)).toEqual([]);
          expect(await uploadEvents(db, intent.intentId)).toEqual([]);
        } else {
          const rows = await attempts(db, intent.intentId);
          expect(rows).toHaveLength(1);
          const operations = (await uploadEvents(db, intent.intentId)).map(({ operation }) => operation);
          expect(operations).toContain('FILE_UPLOAD_ATTEMPT_REGISTERED');
          expect(operations).not.toContain('FILE_UPLOAD_QUARANTINED');
          if (stage === 2 && !lostAfterCommit) {
            expect(rows[0]).toMatchObject({ state: 'FAILED_NOBYTES', dispatched_at: null });
            expect(operations).not.toContain('FILE_UPLOAD_ATTEMPT_DISPATCHED');
          } else {
            expect(rows[0]?.dispatched_at).toBeInstanceOf(Date);
            expect(rows[0]?.charged_bytes).toBe(String(PNG.length));
            expect(operations).toContain('FILE_UPLOAD_ATTEMPT_DISPATCHED');
            if (stage === 3) {
              expect(rows[0]?.state).toMatch(/^(?:VERIFIED|UNKNOWN)$/u);
              await expectRefusal(uploadReservedFile(db.runtime, transport.storage,
                policy({ maxPhysicalBytesPerOwner: PNG.length }), command(anchor, intent.intentId)), 'PHYSICAL_BUDGET_EXCEEDED');
            }
          }
          const beforeReplay = await uploadEvents(db, intent.intentId);
          await expectRefusal(uploadReservedFile(db.runtime, transport.storage, policy(), byKey),
            rows[0]?.state === 'FAILED_NOBYTES' || rows[0]?.state === 'VERIFIED' ? 'ATTEMPT_FAILED' : 'WRITE_OUTCOME_UNKNOWN');
          expect(await uploadEvents(db, intent.intentId)).toEqual(beforeReplay);
          expect(bodyCalls).toBe(1);
        }
      } else {
        expect(result).toMatchObject({ ok: true, value: { state: 'QUARANTINED' } });
        expect(bodyCalls).toBe(1);
        expect(beganWithFreshBackend).toBe(true);
        const before = await uploadEvents(db, intent.intentId);
        const replay = await uploadReservedFile(db.runtime, transport.storage, policy(), byKey);
        expect(replay).toMatchObject({ state: 'QUARANTINED', replayed: true });
        expect(await uploadEvents(db, intent.intentId)).toEqual(before);
        expect(before.filter(({ operation }) => operation === 'FILE_UPLOAD_QUARANTINED')).toHaveLength(1);
        expect(bodyCalls).toBe(1);
        expect(await bindings(db, intent.intentId)).toHaveLength(1);
        expect(await attempts(db, intent.intentId)).toHaveLength(1);
      }
      expect(transport.socket.requests.filter(({ method }) => method === 'PUT')).toHaveLength(expectedPuts);
      await assertUploadEventPairs(db, intent.intentId);
    } finally { await transport.close(); }
  });

  it.each([206, 200])('rejects HTTP %i range verification despite exact returned bytes and digest', async (status) => {
    const { anchor, intent } = await reserve(db);
    const store = loopbackObjectStore();
    const transport = await wire((req, res, record) => {
      if (record.method === 'PUT') { store.handler(req, res, record); return; }
      req.resume();
      res.writeHead(status, {
        'Content-Length': String(PNG.length), 'Content-Range': `bytes 0-${String(PNG.length - 1)}/${String(PNG.length * 2)}`,
        'Connection': 'close',
      });
      res.end(PNG);
    });
    try {
      const byKey = command(anchor, intent.intentId);
      await expectRefusal(uploadReservedFile(db.runtime, transport.storage, policy(), byKey), 'WRITE_OUTCOME_UNKNOWN');
      expect([...store.objects.values()]).toEqual([PNG]);
      expect(await bindings(db, intent.intentId)).toEqual([]);
      expect(await attempts(db, intent.intentId)).toMatchObject([{ state: 'UNKNOWN',
        charged_bytes: String(PNG.length), verified_bytes: null, verified_sha256: null }]);
      const events = await uploadEvents(db, intent.intentId);
      expect(events.map(({ operation }) => operation)).not.toContain('FILE_UPLOAD_QUARANTINED');
      await expectRefusal(uploadReservedFile(db.runtime, transport.storage, policy(), byKey), 'WRITE_OUTCOME_UNKNOWN');
      await expectRefusal(uploadReservedFile(db.runtime, transport.storage,
        policy({ maxPhysicalBytesPerOwner: PNG.length }), command(anchor, intent.intentId)), 'PHYSICAL_BUDGET_EXCEEDED');
      expect(await uploadEvents(db, intent.intentId)).toEqual(events);
      expect(transport.socket.requests.map(({ method }) => method)).toEqual(['PUT', 'GET']);
      await transport.socket.waitForSocketsClosed(1_500);
      await assertUploadEventPairs(db, intent.intentId);
    } finally { await transport.close(); }
  });

  it.each(['ordinary replay', 'lost finalize COMMIT'] as const)('refuses expired %s after an actual binding read lock wait', async (route) => {
    const { anchor, intent } = await reserve(db, { ttlMs: 2_750 });
    const transport = await wire(loopbackObjectStore().handler);
    const blocker = await db.migrator.connect();
    const lockBinding = async (): Promise<void> => {
      await blocker.query('BEGIN');
      await blocker.query('LOCK TABLE foundation.file_quarantine_objects IN ACCESS EXCLUSIVE MODE');
    };
    let bodyCalls = 0;
    const byKey = command(anchor, intent.intentId, { body: () => { bodyCalls += 1; return asyncChunks([PNG]); } });
    const p = policy();
    let action: Promise<void> | undefined;
    try {
      const blockingPid = await pid(blocker);
      let expectedBinding: Awaited<ReturnType<typeof bindings>> = [];
      let expectedEvents: Awaited<ReturnType<typeof uploadEvents>> = [];
      if (route === 'ordinary replay') {
        await uploadReservedFile(db.runtime, transport.storage, p, byKey);
        expectedBinding = await bindings(db, intent.intentId);
        expectedEvents = await uploadEvents(db, intent.intentId);
        await lockBinding();
      }
      const primary = poolWithCommitHook(db.runtime, async (ordinal, _client, commit) => {
        const value = await commit();
        if (route === 'lost finalize COMMIT' && ordinal === 3) {
          expectedBinding = await bindings(db, intent.intentId);
          expectedEvents = await uploadEvents(db, intent.intentId);
          await lockBinding();
          throw Object.assign(new Error(FAILURE_MARKER), { code: 'ECONNRESET' });
        }
        return value;
      });
      action = expectRefusal(uploadReservedFile(primary, transport.storage, p, byKey), 'INTENT_EXPIRED');
      void action.catch(() => undefined);
      await until(async () => (await db.migrator.query<{ waiting: boolean }>(
        `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='relation' AND NOT granted
         AND relation='foundation.file_quarantine_objects'::regclass AND mode='AccessShareLock'
         AND $1=ANY(pg_blocking_pids(pid))) AS waiting`, [blockingPid],
      )).rows[0]?.waiting === true, 'binding read blocked by independent backend');
      expect(expectedBinding).toHaveLength(1);
      await waitForDbExpiry(db, intent.expiresAt);
      await blocker.query('COMMIT');
      await action;
      expect(bodyCalls).toBe(1);
      expect(transport.socket.requests.map(({ method }) => method)).toEqual(['PUT', 'GET']);
      expect(await bindings(db, intent.intentId)).toEqual(expectedBinding);
      expect(await uploadEvents(db, intent.intentId)).toEqual(expectedEvents);
      expect(expectedEvents.filter(({ operation }) => operation === 'FILE_UPLOAD_QUARANTINED')).toHaveLength(1);
      await assertUploadEventPairs(db, intent.intentId);
    } finally {
      await blocker.query('ROLLBACK').catch(() => undefined);
      blocker.release();
      await Promise.allSettled([action]);
      await transport.close();
    }
  }, 15_000);

  it.each([
    { operation: 'FILE_UPLOAD_ATTEMPT_DISPATCHED', expectedMethods: [] },
    { operation: 'FILE_UPLOAD_QUARANTINED', expectedMethods: ['PUT', 'GET'] },
  ])('rolls back $operation when the outbox fails after its audit INSERT', async ({ operation, expectedMethods }) => {
    const { anchor, intent } = await reserve(db);
    const transport = await wire(loopbackObjectStore().handler);
    const trigger = 'test_b2_reject_upload_outbox';
    const dispatch = expectedMethods.length === 0;
    const byKey = command(anchor, intent.intentId);
    try {
      // Test-only DDL in the isolated DB. The failure fires only when the audit
      // insert is already visible to this same writer transaction, and only for
      // this intent/operation. The production runtime needs no new grant.
      await db.migrator.query(`CREATE FUNCTION foundation.${trigger}() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
        BEGIN
          IF NEW.event_type=TG_ARGV[0] AND NEW.payload->>'intentId'=TG_ARGV[1] AND EXISTS (
            SELECT 1 FROM foundation.audit_logs
              WHERE operation=NEW.event_type AND details=NEW.payload AND correlation_id=NEW.event_id
          ) THEN
            RAISE EXCEPTION '${FAILURE_MARKER}' USING ERRCODE='23514';
          END IF;
          RETURN NEW;
        END $$`);
      await db.migrator.query(`CREATE TRIGGER ${trigger} BEFORE INSERT ON foundation.outbox_events
        FOR EACH ROW EXECUTE FUNCTION foundation.${trigger}('${operation}','${intent.intentId}')`);
      await expectRefusal(uploadReservedFile(db.runtime, transport.storage, policy(), byKey), 'CONFLICT');
      expect(await bindings(db, intent.intentId)).toEqual([]);
      const rows = await attempts(db, intent.intentId);
      expect(rows).toHaveLength(1);
      if (dispatch) {
        expect(rows[0]).toMatchObject({ state: 'FAILED_NOBYTES', dispatched_at: null, verified_sha256: null });
      } else {
        expect(rows[0]?.dispatched_at).toBeInstanceOf(Date);
        expect(rows[0]?.charged_bytes).toBe(String(PNG.length));
        expect(rows[0]?.state).toMatch(/^(?:UNKNOWN|VERIFIED)$/u);
        await expectRefusal(uploadReservedFile(db.runtime, transport.storage,
          policy({ maxPhysicalBytesPerOwner: PNG.length }), command(anchor, intent.intentId)), 'PHYSICAL_BUDGET_EXCEEDED');
      }
      const events = await uploadEvents(db, intent.intentId);
      expect(events.map(({ operation: event }) => event)).toEqual(dispatch
        ? ['FILE_UPLOAD_ATTEMPT_REGISTERED', 'FILE_UPLOAD_ATTEMPT_OUTCOME']
        : ['FILE_UPLOAD_ATTEMPT_REGISTERED', 'FILE_UPLOAD_ATTEMPT_DISPATCHED', 'FILE_UPLOAD_ATTEMPT_OUTCOME']);
      await expectRefusal(uploadReservedFile(db.runtime, transport.storage, policy(), byKey),
        rows[0]?.state === 'UNKNOWN' ? 'WRITE_OUTCOME_UNKNOWN' : 'ATTEMPT_FAILED');
      expect(await uploadEvents(db, intent.intentId)).toEqual(events);
      expect(transport.socket.requests.map(({ method }) => method)).toEqual(expectedMethods);
      await assertUploadEventPairs(db, intent.intentId);
    } finally {
      try {
        await db.migrator.query(`DROP TRIGGER IF EXISTS ${trigger} ON foundation.outbox_events`);
        await db.migrator.query(`DROP FUNCTION IF EXISTS foundation.${trigger}()`);
      } finally { await transport.close(); }
    }
  });

  it.each([
    { overrides: { maxLiveOperationsPerOwner: 1 }, code: 'LIVE_OPERATION_LIMIT' },
    { overrides: { maxPhysicalBytesPerOwner: PNG.byteLength }, code: 'PHYSICAL_BUDGET_EXCEEDED' },
    { overrides: { maxAttemptsPerOwner: 1 }, code: 'ATTEMPT_BUDGET_EXCEEDED' },
  ])('serializes two distinct intents for the same owner at last capacity: $code', async ({ overrides, code }) => {
    const { anchor, intent: first } = await reserve(db);
    const { intent: second } = await reserve(db, { anchor });
    const transport = await wire(loopbackObjectStore().handler);
    const acquired = gate();
    const release = gate();
    const secondCheckedOut = gate();
    const bodyRelease = gate();
    let blockingPid = 0;
    let waitingPid = 0;
    const p = policy(overrides);
    const firstPool = poolWithCommitHook(db.runtime, async (ordinal, client, commit) => {
      if (ordinal === 1) {
        blockingPid = await pid(client);
        acquired.open();
        await release.wait();
      }
      return commit();
    });
    const secondPool = poolWithCommitHook(db.runtime, (_ordinal, _client, commit) => commit(), (client) => {
      waitingPid = (client as typeof client & { processID: number }).processID;
      secondCheckedOut.open();
    });
    const winner = settle(uploadReservedFile(firstPool, transport.storage, p, command(anchor, first.intentId, {
      body: () => (async function* () { await bodyRelease.wait(); yield PNG; })(),
    })));
    let loser: Promise<void> | undefined;
    try {
      await acquired.wait();
      loser = expectRefusal(uploadReservedFile(secondPool, transport.storage, p, command(anchor, second.intentId)), code);
      // Attach immediately while the observer waits for the actual lock edge.
      void loser.catch(() => undefined);
      await secondCheckedOut.wait();
      expect(blockingPid).not.toBe(waitingPid);
      await waitForBlockingPid(db, blockingPid, waitingPid);
      expect(await attempts(db, first.intentId)).toEqual([]);
      expect(await attempts(db, second.intentId)).toEqual([]);
      release.open();
      await loser;
      expect(transport.socket.requests).toHaveLength(0);
      bodyRelease.open();
      expect(await winner).toMatchObject({ ok: true, value: { state: 'QUARANTINED' } });
      expect(await attempts(db, second.intentId)).toEqual([]);
      expect(transport.socket.requests.filter(({ method }) => method === 'PUT')).toHaveLength(1);
    } finally {
      release.open();
      bodyRelease.open();
      await Promise.allSettled([winner, loser]);
      await transport.close();
    }
  });

  it.each(['revoked', 're-given', 'republished', 'cancelled', 'expired'] as const)(
    'requires the original authorization again after PUT/GET: %s', async (transition) => {
      const anchor = await newConsentedAnchor(db);
      const { intent } = await reserve(db, { anchor, ttlMs: transition === 'expired' ? 2_500 : 40_000 });
      const store = loopbackObjectStore();
      const entered = gate();
      const finish = gate();
      const transport = await wire((req, res, record) => {
        if (record.method === 'GET') {
          entered.open();
          req.resume();
          void finish.wait().then(() => {
            const bytes = store.objects.get(record.url.split('?')[0] ?? '');
            if (bytes === undefined) { res.writeHead(404); res.end(); return; }
            res.writeHead(200, { 'Content-Length': String(bytes.length) });
            res.end(bytes);
          }, () => { res.destroy(); });
        } else { store.handler(req, res, record); }
      });
      const byKey = command(anchor, intent.intentId);
      const action = uploadReservedFile(db.runtime, transport.storage, policy(), byKey);
      const codes = {
        revoked: ['CONSENT_REVOKED'], 're-given': ['CONSENT_NOT_CURRENT'], republished: ['CONSENT_NOT_CURRENT', 'CONSENT_STALE'],
        cancelled: ['INTENT_CANCELLED', 'CONFLICT'], expired: ['INTENT_EXPIRED', 'STALE_ATTEMPT', 'WRITE_OUTCOME_UNKNOWN'],
      }[transition];
      const refused = expectRefusal(action, codes, [anchor.token]);
      void refused.catch(() => undefined);
      try {
        await entered.wait();
        const [during] = await attempts(db, intent.intentId);
        expect(during?.state).toBe('IN_FLIGHT');
        expect(store.objects.size).toBe(1);
        expect(db.runtime.idleCount).toBe(db.runtime.totalCount);
        if (transition === 'revoked' || transition === 're-given') {
          await revokeConsent(db, anchor, anchor.evidenceId);
          if (transition === 're-given') {
            const given = await db.inTransaction((client) => recordConsentGiven(client, {
              session: proof(anchor), purpose: 'REQUEST_PROCESSING', documentVersionId: anchor.documentVersionId,
              accepted: true, evidenceRef: randomUUID(),
            }));
            expect(given.evidenceId).not.toBe(anchor.evidenceId);
          }
        } else if (transition === 'republished') {
          const current = await db.migrator.query<{ row_version: number }>(
            'SELECT row_version FROM foundation.legal_documents WHERE id=$1', [anchor.documentId]);
          const version = current.rows[0]?.row_version;
          if (version === undefined) { throw new Error('No fixture document'); }
          await publishNextConsentForm(db, version);
        } else if (transition === 'cancelled') {
          await db.inTransaction((client) => cancelFileUploadIntent(client, {
            session: proof(anchor), intentId: intent.intentId, expectedVersion: intent.rowVersion,
          }));
        } else {
          await waitForDbExpiry(db, intent.expiresAt);
        }
        finish.open();
        await refused;
        expect(await bindings(db, intent.intentId)).toEqual([]);
        expect((await uploadEvents(db, intent.intentId)).some(({ operation }) => operation === 'FILE_UPLOAD_QUARANTINED')).toBe(false);
        expect((await attempts(db, intent.intentId))[0]?.charged_bytes).toBe(String(PNG.byteLength));
        await assertUploadEventPairs(db, intent.intentId);
        if (transition !== 'expired') {
          // Storage success is still a private technical fact, not a metadata grant.
          expect((await attempts(db, intent.intentId))[0]?.state).toMatch(/^(?:VERIFIED|UNKNOWN)$/u);
          await expectRefusal(uploadReservedFile(db.runtime, transport.storage, policy(), byKey), codes, [anchor.token]);
        }
        expect(transport.socket.requests.map(({ method }) => method)).toEqual(['PUT', 'GET']);
      } finally {
        finish.open();
        await Promise.allSettled([refused]);
        await transport.close();
      }
    }, 15_000,
  );

  it('rejects wrong F proof/foreign owner and pre-dispatch signature, overflow, cleanup and prefix timeout with zero PUT', async () => {
    const { anchor, intent } = await reserve(db);
    const foreign = await newConsentedAnchor(db);
    const transport = await wire(loopbackObjectStore().handler);
    let cleanupReads = 0;
    const badSource = (): AsyncIterable<Uint8Array> => ({
      [Symbol.asyncIterator]() {
        return {
          next: () => Promise.resolve({ done: false, value: Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8) }),
          get return(): never { cleanupReads += 1; throw new Error(FAILURE_MARKER); },
        };
      },
    });
    const noBytes = () => { throw new Error(FAILURE_MARKER); };
    try {
      const original = command(anchor, intent.intentId, { body: noBytes });
      await expectRefusal(uploadReservedFile(db.runtime, transport.storage, policy(), originalWithWrongToken()), 'NOT_FOUND');
      await expectRefusal(uploadReservedFile(db.runtime, transport.storage, policy(), command(foreign, intent.intentId, { body: noBytes })), 'NOT_FOUND');
      expect(await attempts(db, intent.intentId)).toEqual([]);
      const invalid = [
        { body: badSource, code: 'SIGNATURE_MISMATCH' },
        { body: () => asyncChunks([PNG.subarray(0, 2)]), code: 'SIGNATURE_MISMATCH' },
        { body: () => asyncChunks([Buffer.concat([PNG, PNG])]), code: 'SOURCE_FAILED' },
        { body: noBytes, code: 'SOURCE_FAILED' },
        { body: () => ({ [Symbol.asyncIterator]() {
          return { next: () => Promise.resolve({ done: false as const, value: new Uint8Array() }) };
        } }), code: 'ABORTED' },
      ];
      for (const { body, code } of invalid) {
        await expectRefusal(uploadReservedFile(db.runtime, transport.storage, policy({ prefixTimeoutMs: 80 }), command(anchor, intent.intentId, { body })), code);
      }
      const rows = await attempts(db, intent.intentId);
      expect(rows).toHaveLength(invalid.length);
      expect(rows.every((row) => row.state === 'FAILED_NOBYTES' && row.dispatched_at === null)).toBe(true);
      expect(cleanupReads).toBe(1);
      expect(await bindings(db, intent.intentId)).toEqual([]);
      expect(transport.socket.requests).toHaveLength(0);
      await assertUploadEventPairs(db, intent.intentId);

      function originalWithWrongToken() {
        return { ...original, session: { ...original.session, token: `${original.session.token}wrong` } };
      }
    } finally { await transport.close(); }
  });

  it('caller abort reaches active wire GET despite an earlier stopImmediatePropagation listener', async () => {
    const { anchor, intent } = await reserve(db);
    const store = loopbackObjectStore();
    const firstByte = gate();
    const responseClosed = gate();
    const abort = new AbortController();
    abort.signal.addEventListener('abort', (event) => { event.stopImmediatePropagation(); }, { once: true });
    const transport = await wire((req, res, record) => {
      if (record.method !== 'GET') { store.handler(req, res, record); return; }
      req.resume();
      res.once('close', () => { responseClosed.open(); });
      res.writeHead(200, { 'Content-Length': String(PNG.byteLength) });
      res.write(PNG.subarray(0, 1), () => { firstByte.open(); });
      // Server will not finish the response; only client abort can close this
      // socket inside the shorter test bound than the configured transport TTL.
    });
    const action = settle(uploadReservedFile(db.runtime, transport.storage, policy(), command(anchor, intent.intentId, { signal: abort.signal })));
    try {
      await firstByte.wait();
      expect(store.objects.size).toBe(1);
      expect((await attempts(db, intent.intentId))[0]?.state).toBe('IN_FLIGHT');
      abort.abort(new Error(FAILURE_MARKER));
      await bounded(responseClosed.wait(), 1_500, 'caller abort closed active GET');
      const result = await bounded(action, 2_000, 'caller-aborted upload');
      expect(result.ok).toBe(false);
      if (!result.ok) { assertRefusal(result.error, 'WRITE_OUTCOME_UNKNOWN'); }
      expect(await bindings(db, intent.intentId)).toEqual([]);
      expect((await attempts(db, intent.intentId))[0]).toMatchObject({ state: 'UNKNOWN', charged_bytes: String(PNG.byteLength) });
      expect(transport.socket.requests.map(({ method }) => method)).toEqual(['PUT', 'GET']);
    } finally {
      abort.abort();
      await transport.close();
      await action;
    }
  });

  it('closes the acquired iterator exactly once when reading its next getter throws', async () => {
    const { anchor, intent } = await reserve(db);
    const transport = await wire(loopbackObjectStore().handler);
    let cleanup = 0;
    const body = (): AsyncIterable<Uint8Array> => ({
      [Symbol.asyncIterator]() {
        return {
          get next(): never { throw new Error(FAILURE_MARKER); },
          return() { cleanup += 1; return Promise.resolve({ done: true as const, value: undefined }); },
        };
      },
    });
    try {
      await expectRefusal(uploadReservedFile(db.runtime, transport.storage, policy(), command(anchor, intent.intentId, { body })), 'SOURCE_FAILED');
      expect(cleanup).toBe(1);
      expect((await attempts(db, intent.intentId))[0]).toMatchObject({ state: 'FAILED_NOBYTES', dispatched_at: null });
      expect(await bindings(db, intent.intentId)).toEqual([]);
      expect(transport.socket.requests).toHaveLength(0);
    } finally { await transport.close(); }
  });

  it('post-wait DB clock disallows an intent that expired behind the owner lock', async () => {
    const { anchor, intent } = await reserve(db, { ttlMs: 2_000 });
    const owner = await db.runtime.connect();
    const transport = await wire(loopbackObjectStore().handler);
    const checked = gate();
    let waiter = 0;
    let refused: Promise<void> | undefined;
    try {
      await owner.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      const ownerPid = await pid(owner);
      await owner.query('SELECT id FROM foundation.request_sessions WHERE id=$1 FOR UPDATE', [anchor.sessionId]);
      const primary = poolWithCommitHook(db.runtime, (_ordinal, _client, commit) => commit(), (client) => {
        waiter = (client as typeof client & { processID: number }).processID;
        checked.open();
      });
      refused = expectRefusal(uploadReservedFile(primary, transport.storage, policy(), command(anchor, intent.intentId)), 'INTENT_EXPIRED');
      void refused.catch(() => undefined);
      await checked.wait();
      await waitForBlockingPid(db, ownerPid, waiter);
      await waitForDbExpiry(db, intent.expiresAt);
      await owner.query('COMMIT');
      await refused;
      expect(await attempts(db, intent.intentId)).toEqual([]);
      expect(transport.socket.requests).toHaveLength(0);
    } finally {
      await owner.query('ROLLBACK').catch(() => undefined);
      owner.release();
      await Promise.allSettled([refused]);
      await transport.close();
    }
  });

  it('fences a stale probe completion after new generation, retaining only stale debt', async () => {
    const { anchor, intent } = await reserve(db);
    const store = loopbackObjectStore();
    const firstProbeEntered = gate();
    const firstReceiptParked = gate();
    const releaseReceipt = gate();
    let getCalls = 0;
    const transport = await wire((req, res, record) => {
      if (record.method === 'PUT') {
        req.resume();
        req.on('end', () => {
          store.seed(record.url.split('?')[0] ?? '', Buffer.concat(record.bodyChunks));
          req.socket.destroy(); // committed to the fixture store, but no PUT acknowledgement
        });
        return;
      }
      getCalls += 1;
      if (getCalls !== 1) { store.handler(req, res, record); return; }
      req.resume();
      res.writeHead(200, { 'Content-Length': String(PNG.length) });
      res.write(PNG.subarray(0, 1), () => { firstProbeEntered.open(); });
    });
    const oldInspect: typeof transport.storage.inspectRegisteredQuarantineObject = async (...args) => {
      const observed = await transport.storage.inspectRegisteredQuarantineObject(...args);
      firstReceiptParked.open();
      await releaseReceipt.wait();
      return observed;
    };
    const oldWorker = new Proxy(transport.storage, { get(target, property): unknown {
      if (property === 'inspectRegisteredQuarantineObject') { return oldInspect; }
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    } });
    const restarted = transport.newAdapter();
    const p = policy({ leaseMs: 800, prefixTimeoutMs: 300 });
    const signal = new AbortController().signal;
    let oldSweep: ReturnType<typeof reconcileUploadAttempts> | undefined;
    try {
      await expectRefusal(uploadReservedFile(db.runtime, transport.storage, p, command(anchor, intent.intentId)), 'WRITE_OUTCOME_UNKNOWN');
      expect(store.objects.size).toBe(1);
      oldSweep = reconcileUploadAttempts(db.runtime, oldWorker, p, { limit: 5, signal });
      void oldSweep.catch(() => undefined);
      await firstProbeEntered.wait();
      const [claimed] = await attempts(db, intent.intentId);
      expect(claimed).toMatchObject({ probe_generation: 1, probe_held_slots: 1 });
      if (claimed?.probe_lease_expires_at === null || claimed?.probe_lease_expires_at === undefined) { throw new Error('No probe lease'); }
      await waitForDbExpiry(db, claimed.probe_lease_expires_at);
      await firstReceiptParked.wait();
      expect(await reconcileUploadAttempts(db.runtime, restarted, p, { limit: 5, signal })).toMatchObject({ present: 1 });
      const [newer] = await attempts(db, intent.intentId);
      expect(newer).toMatchObject({ state: 'UNKNOWN', probe_generation: 2, probe_held_slots: 1,
        observation: 'PRESENT', observed_sha256: sha256Hex(PNG), charged_bytes: String(PNG.length) });
      releaseReceipt.open();
      expect(await oldSweep).toMatchObject({ skipped: 1, indeterminate: 0 });
      expect((await attempts(db, intent.intentId))[0]).toEqual(newer);
      expect(await bindings(db, intent.intentId)).toEqual([]);
      expect(transport.socket.requests.map(({ method }) => method)).toEqual(['PUT', 'GET', 'GET']);
      await assertUploadEventPairs(db, intent.intentId);
    } finally {
      releaseReceipt.open();
      await Promise.allSettled([oldSweep]);
      await restarted.close();
      await transport.close();
    }
  }, 15_000);

  it('rolls back an observation if the probe lease expires while audit is blocked', async () => {
    const { anchor, intent } = await reserve(db);
    const store = loopbackObjectStore();
    const getEntered = gate();
    const releaseGet = gate();
    const transport = await wire((req, res, record) => {
      req.resume();
      if (record.method === 'PUT') {
        req.on('end', () => {
          store.seed(record.url.split('?')[0] ?? '', Buffer.concat(record.bodyChunks));
          req.socket.destroy();
        });
        return;
      }
      getEntered.open();
      void releaseGet.wait().then(() => {
        res.writeHead(200, { 'Content-Length': String(PNG.length) }); res.end(PNG);
      }, () => { res.destroy(); });
    });
    const blocker = await db.migrator.connect();
    const p = policy({ leaseMs: 1_500, prefixTimeoutMs: 500 });
    let sweep: ReturnType<typeof reconcileUploadAttempts> | undefined;
    try {
      await expectRefusal(uploadReservedFile(db.runtime, transport.storage, p, command(anchor, intent.intentId)), 'WRITE_OUTCOME_UNKNOWN');
      sweep = reconcileUploadAttempts(db.runtime, transport.storage, p, { limit: 5, signal: new AbortController().signal });
      void sweep.catch(() => undefined);
      await getEntered.wait();
      const [claimed] = await attempts(db, intent.intentId);
      if (!claimed?.probe_lease_expires_at) { throw new Error('No probe lease'); }
      await blocker.query('BEGIN');
      const blockingPid = await pid(blocker);
      await blocker.query('LOCK TABLE foundation.audit_logs IN SHARE MODE');
      releaseGet.open();
      await until(async () => (await db.migrator.query<{ waiting: boolean }>(
        `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='relation' AND NOT granted
         AND relation='foundation.audit_logs'::regclass AND $1=ANY(pg_blocking_pids(pid))) AS waiting`, [blockingPid],
      )).rows[0]?.waiting === true, 'probe audit INSERT blocked');
      await waitForDbExpiry(db, claimed.probe_lease_expires_at);
      await blocker.query('COMMIT');
      expect(await sweep).toMatchObject({ present: 0, skipped: 1 });
      const [after] = await attempts(db, intent.intentId);
      expect(after).toEqual(claimed);
      expect(after).toMatchObject({ observation: null, probe_held_slots: 1, charged_bytes: String(PNG.length) });
      expect((await uploadEvents(db, intent.intentId)).some(({ operation }) => operation === 'FILE_UPLOAD_ATTEMPT_OBSERVED')).toBe(false);
      expect(await bindings(db, intent.intentId)).toEqual([]);
      expect(transport.socket.requests.map(({ method }) => method)).toEqual(['PUT', 'GET']);
    } finally {
      releaseGet.open();
      await blocker.query('ROLLBACK').catch(() => undefined);
      blocker.release();
      await Promise.allSettled([sweep]);
      await transport.close();
    }
  }, 15_000);

  it('new worker observes GET-only 404 then a late old PUT without dropping its charge or replacing the retry binding', async () => {
    const { anchor, intent } = await reserve(db);
    const { intent: tooMuch } = await reserve(db, { anchor });
    const store = loopbackObjectStore();
    const firstBodyOnWire = gate();
    const releaseLateWrite = gate();
    const lateWriteDone = gate();
    const oldPayload = Buffer.from(PNG);
    oldPayload[11] = 0x61;
    let puts = 0;
    const transport = await wire((req, res, record) => {
      if (record.method !== 'PUT' || ++puts !== 1) {
        store.handler(req, res, record);
        return;
      }
      req.on('end', () => {
        firstBodyOnWire.open();
        void releaseLateWrite.wait().then(() => {
          store.seed(record.url.split('?')[0] ?? '', Buffer.concat(record.bodyChunks));
          if (!res.destroyed) { res.writeHead(200); res.end(); }
          lateWriteDone.open();
        }, () => { res.destroy(); });
      });
    });
    const restarted = transport.newAdapter();
    const controller = new AbortController();
    const p = policy({ leaseMs: 1_600, prefixTimeoutMs: 500, maxPhysicalBytesPerOwner: 2 * PNG.byteLength });
    const old = settle(uploadReservedFile(db.runtime, transport.storage, p, command(anchor, intent.intentId, {
      signal: controller.signal, body: () => asyncChunks([oldPayload]),
    })));
    try {
      await firstBodyOnWire.wait();
      const [prior] = await attempts(db, intent.intentId);
      if (prior === undefined) { throw new Error('Missing old attempt'); }
      expect(prior.state).toBe('IN_FLIGHT');
      await waitForDbExpiry(db, prior.upload_lease_expires_at);
      const signal = new AbortController().signal;
      await reconcileUploadAttempts(db.runtime, restarted, p, { limit: 5, signal });
      expect(transport.socket.requests.map(({ method }) => method)).toEqual(['PUT', 'GET']);
      const [absent] = await attempts(db, intent.intentId);
      expect(absent).toMatchObject({ state: 'UNKNOWN', observation: 'NOT_OBSERVED', observed_bytes: null, charged_bytes: String(PNG.byteLength) });
      expect(await bindings(db, intent.intentId)).toEqual([]);
      const success = await uploadReservedFile(db.runtime, restarted, p, command(anchor, intent.intentId));
      expect(success.state).toBe('QUARANTINED');
      await expectRefusal(uploadReservedFile(db.runtime, restarted, p, command(anchor, tooMuch.intentId)), 'PHYSICAL_BUDGET_EXCEEDED');
      const [oldRow, winningRow] = await attempts(db, intent.intentId);
      expect(winningRow?.generation).toBe(2);
      expect(oldRow?.object_key === winningRow?.object_key).toBe(false);
      releaseLateWrite.open();
      await lateWriteDone.wait();
      expect((await old).ok).toBe(false);
      await reconcileUploadAttempts(db.runtime, restarted, p, { limit: 5, signal });
      await until(async () => (await attempts(db, intent.intentId))[0]?.observation === 'PRESENT', 'late object observation');
      expect((await attempts(db, intent.intentId))[0]).toMatchObject({
        state: 'UNKNOWN', observation: 'PRESENT', observed_bytes: String(PNG.byteLength),
        observed_sha256: sha256Hex(oldPayload), verified_sha256: null, charged_bytes: String(PNG.byteLength),
      });
      expect(await bindings(db, intent.intentId)).toEqual([{
        id: success.quarantineId, attempt_id: winningRow?.id, actual_bytes: String(PNG.byteLength), sha256: sha256Hex(PNG),
      }]);
      const paths = transport.socket.requests.map(({ method, url }) => [method, url.split('?')[0]]);
      expect(paths.map(([method]) => method)).toEqual(['PUT', 'GET', 'PUT', 'GET', 'GET']);
      const [firstPath, absencePath, retryPath, retryProofPath, observedPath] = paths.map(([, path]) => path);
      expect(absencePath === firstPath && observedPath === firstPath && retryProofPath === retryPath && retryPath !== firstPath).toBe(true);
      expect(store.objects.size).toBe(2);
      await assertUploadEventPairs(db, intent.intentId);
    } finally {
      controller.abort();
      releaseLateWrite.open();
      await old;
      await restarted.close();
      await transport.close();
    }
  }, 20_000);
});
