import { expect, it } from 'vitest';
import { executeCommittedDelete } from '../src/files/file-privacy/broker.js';
import type { CommittedDeleteGrant } from '../src/files/file-privacy/contract.js';
import { planRetention, reconcileFileDeletion } from '../src/files/file-privacy/index.js';
import { uploadReservedFile } from '../src/files/upload-coordinator/index.js';
import { reconcileUploadAttempts } from '../src/files/upload-coordinator/reconcile.js';
import {
  aggregate, auditPairs, control, dbTime, garageTarget, items, orphanRaw, privacyDb, privacyFixture, privacyGarage, privacyWire,
  rawFixture, refusal, retentionPolicy, revokeDeleteBroker, seedSanitized, signal,
} from './file-privacy-fixture.js';
import { withQueryHook } from './file-lifecycle-fixture.js';
import { attempts, bindings, gate, pid, PNG, policy, waitForBlockingPid, waitForDbExpiry } from './file-upload-fixture.js';
import { settle, sha256Hex } from './file-storage-fixture.js';

privacyDb('D: controlled real wire with separate PG ledger/floor', () => {
  it('denies counterfeit tokens and wrong exact target, then rejects fresh-signed ledger rollback with zero DELETE', async () => {
    const fx = await privacyFixture();
    const source = await privacyWire(fx.scope.namespace, 'source');
    const wrong = await privacyWire(fx.scope.namespace, 'wrong');
    const sourceBroker = fx.broker(source.config);
    const wrongBroker = fx.broker(wrong.config);
    try {
      const { raw, intent } = await rawFixture(fx.db, source.storage);
      wrong.seed(raw.object_key, PNG);
      const p = await retentionPolicy(fx.db);
      const counterfeit = Object.freeze({ target: wrong.config.bucket, objectKey: raw.object_key, claimGeneration: 1 }) as unknown as CommittedDeleteGrant;
      await refusal(executeCommittedDelete(wrongBroker, counterfeit, signal()), 'NOT_CONFIGURED', [raw.object_key]);
      const noIo = source.socket.requests.length;
      await planRetention(fx.plan(p), signal());
      // Ordinary reconciliation with a genuine wrong-target broker appends/pins but cannot claim.
      aggregate(await reconcileFileDeletion(fx.delete(p, wrongBroker), signal()));
      expect(wrong.socket.requests).toHaveLength(0);
      expect(source.socket.requests).toHaveLength(noIo);
      expect((await fx.floor.read(fx.scope.namespace)).seq).toBe(1n);
      const decision = await control(fx.db, intent.intentId);
      expect(decision.delete_state).toBe('LEDGERED');
      const snapshot = await items(fx.db, intent.intentId);
      expect(snapshot).toEqual([expect.objectContaining({ claim_generation: 0, state: 'AUTHORIZED' })]);
      await refusal(reconcileFileDeletion({ ...fx.delete(p, sourceBroker), verifier: fx.rollbackVerifier() }, signal()), 'CONFLICT', [raw.object_key]);
      expect(await control(fx.db, intent.intentId)).toEqual(decision);
      expect(await items(fx.db, intent.intentId)).toEqual(snapshot);
      expect(source.socket.requests).toHaveLength(noIo);
      expect(wrong.socket.requests).toHaveLength(0);
      expect(source.objects.has(source.path(raw.object_key))).toBe(true);
      // The same work is legitimate with a fresh anchored current head.
      aggregate(await reconcileFileDeletion(fx.delete(p, sourceBroker), signal()));
      expect(source.deletes()).toHaveLength(1);
      expect((await control(fx.db, intent.intentId)).delete_state).toBe('CONFIRMED_ABSENT');
    } finally { await revokeDeleteBroker(sourceBroker); await revokeDeleteBroker(wrongBroker); await source.close(); await wrong.close(); await fx.close(); }
  }, 30_000);

  it('does not let an older same-epoch unsupported target starve an eligible LEDGERED job at maxBatch 1', async () => {
    const fx = await privacyFixture();
    const unsupported = await privacyWire(fx.scope.namespace, 'starved');
    const approved = await privacyWire(fx.scope.namespace, 'eligible');
    const neutral = await privacyWire(fx.scope.namespace, 'ledger-only');
    const stampOnly = fx.broker(neutral.config);
    const exact = fx.broker(approved.config);
    try {
      const p = await retentionPolicy(fx.db, { maxBatch: 1 });
      const old = await rawFixture(fx.db, unsupported.storage);
      expect((await planRetention(fx.plan(p), signal())).advanced).toBe(1);
      await reconcileFileDeletion(fx.delete(p, stampOnly), signal());
      const next = await rawFixture(fx.db, approved.storage);
      expect((await planRetention(fx.plan(p), signal())).advanced).toBe(1);
      await reconcileFileDeletion(fx.delete(p, stampOnly), signal());
      const oldState = await control(fx.db, old.intent.intentId);
      const nextState = await control(fx.db, next.intent.intentId);
      for (const state of [oldState, nextState]) {
        expect(state).toMatchObject({ delete_writer_epoch: '1', delete_state: 'LEDGERED' });
      }
      expect(oldState.delete_at?.getTime()).toBeLessThan(nextState.delete_at?.getTime() ?? 0);
      const oldItems = await items(fx.db, old.intent.intentId);
      expect(oldItems).toEqual([expect.objectContaining({ claim_generation: 0, state: 'AUTHORIZED', attempt_id: old.raw.id })]);
      expect(await items(fx.db, next.intent.intentId)).toEqual([expect.objectContaining({ claim_generation: 0, state: 'AUTHORIZED', attempt_id: next.raw.id })]);
      const oldRequests = unsupported.socket.requests.length;
      const nextRequests = approved.socket.requests.length;
      expect(unsupported.deletes()).toHaveLength(0);
      expect(approved.deletes()).toHaveLength(0);
      expect(neutral.socket.requests).toHaveLength(0);
      expect((await fx.floor.read(fx.scope.namespace)).seq).toBe(2n);
      expect(unsupported.objects.get(unsupported.path(old.raw.object_key))?.equals(PNG)).toBe(true);
      expect(approved.objects.get(approved.path(next.raw.object_key))?.equals(PNG)).toBe(true);

      expect(await reconcileFileDeletion(fx.delete(p, exact), signal())).toEqual({ examined: 1, advanced: 1, deferred: 0 });
      expect(approved.socket.requests.slice(nextRequests).map(({ method, url }) => [method, url.split('?')[0]])).toEqual([
        ['DELETE', approved.path(next.raw.object_key)], ['GET', approved.path(next.raw.object_key)],
      ]);
      expect(approved.objects.has(approved.path(next.raw.object_key))).toBe(false);
      expect(await control(fx.db, next.intent.intentId)).toMatchObject({ delete_state: 'CONFIRMED_ABSENT', delete_event_id: nextState.delete_event_id });
      expect(unsupported.socket.requests).toHaveLength(oldRequests);
      expect(neutral.socket.requests).toHaveLength(0);
      expect(unsupported.objects.get(unsupported.path(old.raw.object_key))?.equals(PNG)).toBe(true);
      expect(await control(fx.db, old.intent.intentId)).toEqual(oldState);
      expect(await items(fx.db, old.intent.intentId)).toEqual(oldItems);
      expect((await fx.events()).map(({ event_id }) => event_id)).toEqual([oldState.delete_event_id, nextState.delete_event_id]);
    } finally {
      await revokeDeleteBroker(stampOnly); await revokeDeleteBroker(exact);
      await unsupported.close(); await approved.close(); await neutral.close(); await fx.close();
    }
  }, 30_000);

  it('does not treat 204+404 as settlement for UNKNOWN, including a late PUT after the first DELETE', async () => {
    const fx = await privacyFixture();
    const putAccepted = gate();
    let pendingPut: (() => void) | undefined;
    let laterProbeFails = false;
    const wire = await privacyWire(fx.scope.namespace, 'late', (record) => {
      if (record.method === 'PUT') {
        return (req) => {
          req.resume();
          req.once('end', () => {
            const path = record.url.split('?')[0] ?? '';
            const bytes = Buffer.concat(record.bodyChunks);
            // Server owns the accepted request bytes even after the client times out/resets.
            pendingPut = () => { wire.objects.set(path, bytes); };
            putAccepted.open();
            req.socket.destroy();
          });
        };
      }
      if (laterProbeFails && record.method === 'GET') {
        return (req) => { req.resume(); req.once('end', () => req.socket.destroy()); };
      }
      return undefined;
    });
    const broker = fx.broker(wire.config);
    try {
      const { intent, raw, upload } = await orphanRaw(fx.db, wire);
      await putAccepted.wait();
      laterProbeFails = true;
      await reconcileUploadAttempts(fx.db.runtime, wire.storage, policy(), { limit: 1, signal: signal() });
      laterProbeFails = false;
      const [debt] = await attempts(fx.db, intent.intentId);
      expect(debt).toMatchObject({ state: 'UNKNOWN', charged_bytes: String(PNG.length), probe_held_slots: 1 });
      const p = await retentionPolicy(fx.db);
      await planRetention(fx.plan(p), signal());
      await reconcileFileDeletion(fx.delete(p, broker), signal());
      expect(wire.deletes()).toHaveLength(1);
      expect(await items(fx.db, intent.intentId)).toEqual([expect.objectContaining({ write_proof: 'UNKNOWN', state: 'VERIFY_PENDING', verified_at: null })]);
      expect((await control(fx.db, intent.intentId)).delete_state).toBe('VERIFY_PENDING');
      expect(wire.objects.has(wire.path(raw.object_key))).toBe(false);
      if (pendingPut === undefined) { throw new Error('No accepted delayed PUT to deliver'); }
      pendingPut();
      expect(wire.objects.get(wire.path(raw.object_key))?.equals(PNG)).toBe(true);
      const requestsBefore = wire.socket.requests.length;
      await refusal(uploadReservedFile(fx.db.runtime, wire.storage, policy(), upload), ['CONFLICT','NOT_FOUND']);
      expect(wire.socket.requests).toHaveLength(requestsBefore);
      aggregate(await reconcileFileDeletion(fx.delete(p, broker), signal()));
      expect(wire.deletes().map(({ url }) => url.split('?')[0])).toEqual([wire.path(raw.object_key), wire.path(raw.object_key)]);
      expect(wire.socket.requests.filter(({ method }) => method === 'PUT')).toHaveLength(1);
      expect(wire.objects.has(wire.path(raw.object_key))).toBe(false);
      expect(await items(fx.db, intent.intentId)).toEqual([expect.objectContaining({ write_proof: 'UNKNOWN', state: 'VERIFY_PENDING', claim_generation: 2, verified_at: null })]);
      expect((await control(fx.db, intent.intentId)).delete_state).toBe('VERIFY_PENDING');
      expect((await attempts(fx.db, intent.intentId))[0]).toEqual(debt);
      expect(await bindings(fx.db, intent.intentId)).toEqual([]);
      expect((await fx.db.migrator.query('SELECT 1 FROM foundation.file_publications WHERE intent_id=$1', [intent.intentId])).rowCount).toBe(0);
      expect(await fx.events()).toHaveLength(1);
    } finally { await revokeDeleteBroker(broker); await wire.close(); await fx.close(); }
  }, 30_000);

  it('duplicate claimer cannot send before expiry; stale completion cannot checkpoint a new generation', async () => {
    const fx = await privacyFixture();
    let gettingAfterClaim = false;
    let firstObservation = false;
    const beforeCheckpoint = gate();
    const resumeOld = gate();
    const wire = await privacyWire(fx.scope.namespace, 'claims', (record) => {
      if (!gettingAfterClaim || record.method !== 'GET') { return undefined; }
      if (!firstObservation) {
        firstObservation = true;
        return (req, res) => {
          req.resume(); req.once('end', () => res.writeHead(404, { 'Content-Type': 'application/xml' }).end('<Error><Code>NoSuchKey</Code></Error>'));
        };
      }
      return (req, res) => { req.resume(); req.once('end', () => res.writeHead(403, { 'Content-Type': 'application/xml' }).end('<Error><Code>AccessDenied</Code></Error>')); };
    });
    const broker1 = fx.broker(wire.config);
    const broker2 = fx.broker(wire.config);
    let action: Promise<unknown> | undefined;
    try {
      const { intent, raw } = await rawFixture(fx.db, wire.storage);
      const p = await retentionPolicy(fx.db, { claimMs: 1_500 });
      await planRetention(fx.plan(p), signal());
      const pausedPool = withQueryHook(fx.db.runtime, (sql) => firstObservation && /^BEGIN/iu.test(sql.trim()), async (_sql, _client, query) => {
        beforeCheckpoint.open();
        await resumeOld.wait();
        return query();
      });
      gettingAfterClaim = true;
      action = settle(reconcileFileDeletion({ ...fx.delete(p, broker1), pool: pausedPool }, signal()));
      await beforeCheckpoint.wait();
      const [old] = await items(fx.db, intent.intentId);
      if (old?.claim_expires_at === undefined || old.claim_expires_at === null) { throw new Error('Missing real old claim'); }
      expect(old).toMatchObject({ claim_generation: 1, state: 'DELETE_ATTEMPTED' });
      await reconcileFileDeletion(fx.delete(p, broker2), signal());
      expect(wire.deletes()).toHaveLength(1);
      expect(await items(fx.db, intent.intentId)).toEqual([old]);
      await waitForDbExpiry(fx.db, old.claim_expires_at);
      await reconcileFileDeletion(fx.delete(p, broker2), signal());
      const replacement = await items(fx.db, intent.intentId);
      expect(replacement).toEqual([expect.objectContaining({ claim_generation: 2, state: 'VERIFY_PENDING', verified_at: null })]);
      expect(wire.deletes().map(({ url }) => url.split('?')[0])).toEqual([wire.path(raw.object_key), wire.path(raw.object_key)]);
      resumeOld.open();
      expect(await action).toMatchObject({ ok: true });
      expect(await items(fx.db, intent.intentId)).toEqual(replacement);
      expect((await control(fx.db, intent.intentId)).delete_state).toBe('VERIFY_PENDING');
      expect((await auditPairs(fx.db, intent.intentId)).map(({ payload }) => payload['phase'])).not.toContain('DELETE_ITEM_ABSENT');
    } finally { resumeOld.open(); await action; await revokeDeleteBroker(broker1); await revokeDeleteBroker(broker2); await wire.close(); await fx.close(); }
  }, 30_000);
  it('rolls back item, group and audit when the claim expires while the aggregate update waits', async () => {
    const fx = await privacyFixture();
    const afterDelete = gate();
    const send404 = gate();
    const beforeGroup = gate();
    let blockObservation = false;
    let waitingPid = 0;
    const wire = await privacyWire(fx.scope.namespace, 'aggregate-wait', (record) => {
      if (!blockObservation || record.method !== 'GET') { return undefined; }
      return (request, response) => {
        request.resume();
        request.once('end', () => {
          afterDelete.open();
          void send404.wait().then(() => {
            // The body is already drained; emit the actual fixture store result now.
            const path = record.url.split('?')[0] ?? '';
            if (wire.objects.has(path) || typeof record.headers['authorization'] !== 'string') {
              response.writeHead(403).end();
            } else {
              response.writeHead(404, { 'Content-Type': 'application/xml' }).end('<Error><Code>NoSuchKey</Code></Error>');
            }
          }, () => response.destroy());
        });
      };
    });
    const broker = fx.broker(wire.config);
    const blocker = await fx.db.migrator.connect();
    let action: Promise<unknown> | undefined;
    try {
      const { intent, raw } = await rawFixture(fx.db, wire.storage);
      const p = await retentionPolicy(fx.db, { claimMs: 3_000 });
      await planRetention(fx.plan(p), signal());
      const watched = withQueryHook(fx.db.runtime,
        (sql) => /UPDATE\s+foundation\.file_privacy_controls\s+c\s+SET\s+delete_state='CONFIRMED_ABSENT'/iu.test(sql),
        async (_sql, client, query) => {
          waitingPid = await pid(client);
          beforeGroup.open();
          return query();
        });
      blockObservation = true;
      const reconciled = reconcileFileDeletion({ ...fx.delete(p, broker), pool: watched }, signal());
      action = settle(reconciled);
      await afterDelete.wait();
      const [claim] = await items(fx.db, intent.intentId);
      if (claim?.claim_expires_at === undefined || claim.claim_expires_at === null) { throw new Error('Missing durable fixture claim'); }
      expect(wire.deletes()).toHaveLength(1);
      expect(wire.objects.has(wire.path(raw.object_key))).toBe(false);
      expect(claim.state).toBe('DELETE_ATTEMPTED');
      const parent = await control(fx.db, intent.intentId);
      const history = await auditPairs(fx.db, intent.intentId);
      await blocker.query('BEGIN');
      await blocker.query('LOCK TABLE foundation.file_privacy_controls IN SHARE MODE');
      send404.open();
      await beforeGroup.wait();
      await waitForBlockingPid(fx.db, await pid(blocker), waitingPid);
      expect((await dbTime(fx.db, 0)).getTime()).toBeLessThan(claim.claim_expires_at.getTime());
      await waitForDbExpiry(fx.db, claim.claim_expires_at);
      expect((await dbTime(fx.db, 0)).getTime()).toBeLessThan(p.expiresAt.getTime());
      await blocker.query('COMMIT');
      await refusal(reconciled, 'CONFLICT', [raw.object_key]);
      expect(await items(fx.db, intent.intentId)).toEqual([claim]);
      expect(await control(fx.db, intent.intentId)).toEqual(parent);
      expect(await auditPairs(fx.db, intent.intentId)).toEqual(history);
    } finally {
      send404.open();
      await blocker.query('ROLLBACK'); blocker.release();
      await action;
      await revokeDeleteBroker(broker); await wire.close(); await fx.close();
    }
  }, 30_000);
});

privacyGarage('D: isolated Garage bucket with actual ledger and independent floor', () => {
  it('proves verified RAW/SANITIZED and never-dispatched keys absent, keeping history and enforcing read-only IAM', async () => {
    const fx = await privacyFixture();
    const garage = garageTarget(fx.scope.namespace);
    const broker = fx.broker(garage.config);
    try {
      const fixture = await rawFixture(fx.db, garage.storage);
      const { raw, intent } = fixture;
      const san = await seedSanitized(fx.db, fixture, garage.config, { publish: true, dispatched: true });
      const never = await seedSanitized(fx.db, fixture, garage.config, { publish: false, dispatched: false });
      for (const key of [raw.object_key, san.objectKey, never.objectKey]) { garage.allow(key); }
      await garage.putSanitizedFixture(san.objectKey);
      expect(await garage.readOnlyDeleteStatus(raw.object_key)).toBe(403);
      for (const key of [raw.object_key, san.objectKey]) { expect(await garage.observe(key)).toEqual({ http: 200, digest: sha256Hex(PNG) }); }
      expect(await garage.observe(never.objectKey)).toEqual({ http: 404, code: 'NoSuchKey' });
      const p = await retentionPolicy(fx.db);
      await planRetention(fx.plan(p), signal());
      const pending = await control(fx.db, intent.intentId);
      expect(pending).toMatchObject({ delete_state: 'PENDING_LEDGER', ledger_seq: null });
      expect(await fx.events()).toEqual([]);
      expect(await garage.observe(raw.object_key)).toMatchObject({ http: 200 });
      for (let i = 0; i < 3; i++) {
        aggregate(await reconcileFileDeletion(fx.delete(p, broker), signal()));
      }
      for (const key of [raw.object_key, san.objectKey, never.objectKey]) { expect(await garage.observe(key)).toEqual({ http: 404, code: 'NoSuchKey' }); }
      const [ledger] = await fx.events();
      expect(ledger).toMatchObject({ event_id: pending.delete_event_id, intent_id: intent.intentId, seq: '1' });
      expect((await fx.floor.read(fx.scope.namespace))).toMatchObject({ seq: 1n, hash: ledger?.sha256, incarnation: fx.scope.incarnation });
      expect(await control(fx.db, intent.intentId)).toMatchObject({ delete_state: 'CONFIRMED_ABSENT', access_epoch: '2', ledger_seq: '1', ledger_hash: ledger?.sha256 });
      const graph = await items(fx.db, intent.intentId);
      expect(graph).toHaveLength(3);
      expect(graph.every((item) => item.state === 'CONFIRMED_ABSENT' && item.claim_generation === 1 && item.verified_at !== null)).toBe(true);
      expect(graph.map(({ write_proof }) => write_proof).sort()).toEqual(['NEVER_DISPATCHED','VERIFIED_SETTLED','VERIFIED_SETTLED']);
      expect((await attempts(fx.db, intent.intentId))[0]?.charged_bytes).toBe(String(PNG.length));
      expect(await bindings(fx.db, intent.intentId)).toHaveLength(1);
      expect((await fx.db.migrator.query('SELECT 1 FROM foundation.file_publications WHERE intent_id=$1', [intent.intentId])).rowCount).toBe(1);
      const repeated = await reconcileFileDeletion(fx.delete(p, broker), signal());
      expect(repeated).toEqual({ examined: 0, advanced: 0, deferred: 0 });
      expect(await fx.events()).toHaveLength(1);
      expect(await items(fx.db, intent.intentId)).toEqual(graph);
      expect(await auditPairs(fx.db, intent.intentId)).toHaveLength(8);
    } finally { await revokeDeleteBroker(broker); await garage.close(); await fx.close(); }
  }, 30_000);
});
