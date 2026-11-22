import { randomUUID } from 'node:crypto';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { closeReadyStream, createFileReadBudget, openReadyStream, readReadyChunk, readReadyMetadata } from '../src/files/file-access/index.js';
import type { AccessContext } from '../src/files/file-lifecycle/contract.js';
import {
  changeFileHold, makeHoldGrant, planRetention, reconcileFileDeletion,
} from '../src/files/file-privacy/index.js';
import type { HoldGrant } from '../src/files/file-privacy/contract.js';
import { cancelFileUploadIntent, readFileUploadIntent, reserveFileUpload } from '../src/files/reservations/index.js';
import type { ReserveFileUploadInput } from '../src/files/reservations/contract.js';
import { reconcileUploadAttempts } from '../src/files/upload-coordinator/reconcile.js';
import { uploadReservedFile } from '../src/files/upload-coordinator/index.js';
import {
  aggregate, auditPairs, control, dbTime, items, observeBackend, orphanRaw, privacyDb, privacyFixture, privacyWire,
  rawFixture, refusal, rejectOutbox, retentionPolicy, revokeDeleteBroker, seedSanitized, signal,
} from './file-privacy-fixture.js';
import { withQueryHook } from './file-lifecycle-fixture.js';
import { newConsentedAnchor, proof } from './file-reservations-fixture.js';
import { attempts, bindings, command, FAILURE_MARKER, gate, pid, PNG, policy, poolWithCommitHook, reserve, waitForBlockingPid, waitForDbExpiry } from './file-upload-fixture.js';
import { settle } from './file-storage-fixture.js';

privacyDb('D: real PostgreSQL source, ledger and independent floor', () => {
  let fx: Awaited<ReturnType<typeof privacyFixture>>;
  let wire: Awaited<ReturnType<typeof privacyWire>>;
  let cleanup: (() => Promise<void>) | undefined;
  beforeEach(async () => {
    fx = await privacyFixture();
    cleanup = () => fx.close();
    wire = await privacyWire(fx.scope.namespace);
    cleanup = async () => { try { await wire.close(); } finally { await fx.close(); } };
  }, 30_000);
  afterEach(async () => { try { await cleanup?.(); } finally { cleanup = undefined; } });

  it.each(['tombstone', 'runtime fence'] as const)('A metadata and exact reservation replay close after %s', async (boundary) => {
    const owner = await newConsentedAnchor(fx.db);
    const foreign = await newConsentedAnchor(fx.db);
    const reservation: ReserveFileUploadInput = {
      session: proof(owner), idempotencyKey: randomUUID(), declaredMime: 'image/png', declaredBytes: PNG.length,
      expiresAt: await dbTime(fx.db, 90_000), policy: {
        versionId: randomUUID(), sourceRef: 'synthetic://cross-slice', allowedMimeTypes: ['image/png'],
        maxFileBytes: PNG.length, maxOwnerBytes: 1_000, maxOwnerFiles: 8, expiresAt: await dbTime(fx.db, 120_000),
      },
    };
    const reserveExactly = () => fx.db.inTransaction((client) => reserveFileUpload(client, reservation));
    const original = await reserveExactly();
    const request = { session: reservation.session, intentId: original.intentId };
    const read = () => fx.db.inTransaction((client) => readFileUploadIntent(client, request));
    await expect(read()).resolves.toMatchObject({ intentId: original.intentId, state: 'RESERVED' });
    await expect(reserveExactly()).resolves.toMatchObject({ intentId: original.intentId, replayed: true });
    await refusal(fx.db.inTransaction((client) => readFileUploadIntent(client, { ...request, session: proof(foreign) })), 'NOT_FOUND');
    await refusal(fx.db.inTransaction((client) => readFileUploadIntent(client, { ...request, session: { ...request.session, token: foreign.token } })), 'NOT_FOUND');
    if (boundary === 'tombstone') {
      await uploadReservedFile(fx.db.runtime, wire.storage, policy(), command(owner, original.intentId));
      expect((await planRetention(fx.plan(await retentionPolicy(fx.db)), signal())).advanced).toBe(1);
      expect(await control(fx.db, original.intentId)).toMatchObject({ delete_state: 'PENDING_LEDGER', access_epoch: '2' });
      await refusal(fx.db.inTransaction((client) => readFileUploadIntent(client, { ...request, session: proof(foreign) })), 'NOT_FOUND');
    } else {
      // This test owns a new fixture DB: FENCED is irreversible and never reset.
      const fenced = await fx.db.migrator.query(`UPDATE foundation.file_runtime_epochs SET mode='FENCED'
        WHERE singleton AND namespace_id=$1 AND epoch=1 AND mode='ACTIVE'`, [fx.scope.namespace]);
      expect(fenced.rowCount).toBe(1);
    }
    const persistent = async () => {
      const id = original.intentId;
      const rows = (await fx.db.migrator.query(`SELECT to_jsonb(i) AS snapshot FROM foundation.file_upload_intents i WHERE id=$1`, [id])).rows;
      const audit = (await fx.db.migrator.query(`SELECT id FROM foundation.audit_logs WHERE details->>'intentId'=$1 ORDER BY id`, [id])).rows;
      const outbox = (await fx.db.migrator.query(`SELECT id FROM foundation.outbox_events WHERE payload->>'intentId'=$1 ORDER BY id`, [id])).rows;
      return { rows, audit, outbox };
    };
    const before = await persistent();
    await refusal(read(), 'CONFLICT', [owner.token]);
    await refusal(reserveExactly(), 'CONFLICT', [owner.token]);
    expect(await persistent()).toEqual(before);
    if (boundary === 'tombstone') {
      const cancelled = await fx.db.inTransaction((client) => cancelFileUploadIntent(client, { ...request, expectedVersion: original.rowVersion }));
      expect(Object.keys(cancelled).sort()).toEqual(['cancelledAt', 'intentId', 'replayed', 'rowVersion', 'state']);
      expect(cancelled).toMatchObject({ state: 'CANCELLED', intentId: original.intentId, replayed: false });
      await refusal(read(), 'CONFLICT', [owner.token]);
    }
  });

  it.each(['D freeze', 'C occupancy'] as const)('B probe limit=1 skips an older ineligible owner after %s', async (reason) => {
    const brokenPut = await privacyWire(fx.scope.namespace, 'b-fairness', (record) => record.method === 'PUT'
      ? (request) => { request.resume(); request.once('end', () => request.socket.destroy()); } : undefined);
    try {
      const older = await orphanRaw(fx.db, brokenPut);
      if (reason === 'D freeze') {
        expect((await planRetention(fx.plan(await retentionPolicy(fx.db)), signal())).advanced).toBe(1);
        expect(await control(fx.db, older.intent.intentId)).toMatchObject({ delete_state: 'PENDING_LEDGER', access_epoch: '2' });
      } else {
        // Seed only the real C occupancy fact, not a scan or a READY publication.
        await fx.db.migrator.query(`INSERT INTO foundation.file_privacy_controls (intent_id) VALUES ($1) ON CONFLICT DO NOTHING`, [older.intent.intentId]);
        const occupied = await fx.db.migrator.query(`UPDATE foundation.file_privacy_controls SET read_generation=read_generation+1,
          read_lease_id=$2,read_expires_at=clock_timestamp()+interval '120 seconds' WHERE intent_id=$1 AND read_lease_id IS NULL`,
        [older.intent.intentId, randomUUID()]);
        expect(occupied.rowCount).toBe(1);
      }
      const newer = await orphanRaw(fx.db, brokenPut);
      const before = await attempts(fx.db, older.intent.intentId);
      const [young] = await attempts(fx.db, newer.intent.intentId);
      expect(older.anchor.sessionId).not.toBe(newer.anchor.sessionId);
      expect(before).toEqual([expect.objectContaining({ state: 'UNKNOWN', probe_generation: 0, charged_bytes: String(PNG.length) })]);
      expect(young).toMatchObject({ state: 'UNKNOWN', probe_generation: 0, charged_bytes: String(PNG.length) });
      const uploaded = brokenPut.socket.requests.length;
      expect(uploaded).toBe(2);
      await reconcileUploadAttempts(fx.db.runtime, brokenPut.storage, policy({ maxLiveOperationsPerOwner: 2 }), { limit: 1, signal: signal() });
      expect(brokenPut.socket.requests.slice(uploaded).map(({ method, url }) => [method, url.split('?')[0]])).toEqual([
        ['GET', brokenPut.path(newer.raw.object_key)],
      ]);
      expect(await attempts(fx.db, older.intent.intentId)).toEqual(before);
      expect(await attempts(fx.db, newer.intent.intentId)).toEqual([expect.objectContaining({
        id: newer.raw.id, state: 'UNKNOWN', observation: 'NOT_OBSERVED', probe_generation: 1, charged_bytes: String(PNG.length),
      })]);
    } finally { await brokenPut.close(); }
  });

  it('defaults off and rejects counterfeit operator UUIDs without decision, ledger, or network', async () => {
    const { intent } = await rawFixture(fx.db, wire.storage);
    const broker = fx.broker(wire.config);
    const disabled = { ...await retentionPolicy(fx.db), mode: 'production' } as unknown as Awaited<ReturnType<typeof retentionPolicy>>;
    try {
      await refusal(planRetention({ ...fx.plan(disabled), policy: undefined } as never, signal()), 'INVALID_INPUT');
      await refusal(planRetention(fx.plan(disabled), signal()), 'NOT_CONFIGURED');
      await refusal(reconcileFileDeletion(fx.delete(disabled, broker), signal()), 'NOT_CONFIGURED');
      for (const malformed of [await retentionPolicy(fx.db, { orphanMs: 0 }), await retentionPolicy(fx.db, { readyMs: 1.5 })]) {
        await refusal(planRetention(fx.plan(malformed), signal()), 'INVALID_INPUT');
      }
      await refusal(changeFileHold(fx.hold(await retentionPolicy(fx.db)), Object.freeze({ intentId: intent.intentId,
        actorId: fx.actorId, expectedRowVersion: 1n, action: 'PLACE', reason: 'LEGAL_HOLD', grantId: randomUUID() }) as unknown as HoldGrant), 'NOT_CONFIGURED');
      expect(await items(fx.db, intent.intentId)).toEqual([]);
      expect(await fx.events()).toEqual([]);
      expect(wire.deletes()).toHaveLength(0);
    } finally { await revokeDeleteBroker(broker); }
  });

  it.each(['hold', 'decision'] as const)('linearizes %s first across two observed PostgreSQL backends', async (winner) => {
    const { intent } = await rawFixture(fx.db, wire.storage);
    const p = await retentionPolicy(fx.db);
    const hold = makeHoldGrant(fx.holdOperator, { intentId: intent.intentId, expectedRowVersion: 1n, action: 'PLACE', reason: 'LEGAL_HOLD' });
    const commitEntered = gate();
    const release = gate();
    let firstPid = 0;
    const firstPool = poolWithCommitHook(fx.db.runtime, async (_ordinal, client, commit) => {
      const row = (await client.query<{ hold_active: boolean; delete_state: string }>(`SELECT hold_active,delete_state
        FROM foundation.file_privacy_controls WHERE intent_id=$1`, [intent.intentId])).rows[0];
      if (firstPid === 0 && (winner === 'hold' ? row?.hold_active === true : row?.delete_state === 'PENDING_LEDGER')) {
        firstPid = await pid(client);
        commitEntered.open();
        await release.wait();
      }
      return commit();
    });
    const waiting = observeBackend(fx.db.runtime);
    const winnerRun = settle<unknown>(winner === 'hold' ? changeFileHold(fx.hold(p, firstPool), hold) : planRetention(fx.plan(p, firstPool), signal()));
    let loser: Promise<unknown> | undefined;
    try {
      await commitEntered.wait();
      const loserRun = winner === 'hold' ? planRetention(fx.plan(p, waiting.pool), signal()) : changeFileHold(fx.hold(p, waiting.pool), hold);
      loser = settle<unknown>(loserRun);
      const waitingPid = await waiting.pid();
      expect(waitingPid).not.toBe(firstPid);
      await waitForBlockingPid(fx.db, firstPid, waitingPid);
      expect(wire.deletes()).toHaveLength(0);
      release.open();
      expect((await winnerRun).ok).toBe(true);
      if (winner === 'hold') {
        await loserRun;
        expect(await control(fx.db, intent.intentId)).toMatchObject({ hold_active: true, hold_actor_id: fx.actorId,
          hold_reason: 'LEGAL_HOLD', row_version: '2', access_epoch: '1', delete_state: 'OPEN', delete_event_id: null });
        expect(await items(fx.db, intent.intentId)).toEqual([]);
        const stale = makeHoldGrant(fx.holdOperator, { intentId: intent.intentId, expectedRowVersion: 1n, action: 'RELEASE' });
        await refusal(changeFileHold(fx.hold(p), stale), 'STALE_VERSION');
        const valid = makeHoldGrant(fx.holdOperator, { intentId: intent.intentId, expectedRowVersion: 2n, action: 'RELEASE' });
        await expect(changeFileHold(fx.hold(p), valid)).resolves.toEqual({ applied: true, rowVersion: 3n });
        expect(await control(fx.db, intent.intentId)).toMatchObject({ hold_active: false, hold_actor_id: null, hold_reason: null, hold_at: null, access_epoch: '1' });
        await planRetention(fx.plan(p), signal());
      } else {
        await refusal(loserRun, 'TOO_LATE');
      }
      const decided = await control(fx.db, intent.intentId);
      expect(decided).toMatchObject({ delete_state: 'PENDING_LEDGER', hold_active: false, access_epoch: '2', delete_policy_id: p.versionId,
        delete_writer_epoch: '1', ledger_seq: null, ledger_hash: null });
      expect(decided.delete_graph_sha256).toMatch(/^[a-f0-9]{64}$/u);
      expect(await items(fx.db, intent.intentId)).toHaveLength(1);
      expect(await fx.events()).toEqual([]);
      expect(wire.deletes()).toHaveLength(0);
      expect(await auditPairs(fx.db, intent.intentId)).toHaveLength(winner === 'hold' ? 3 : 1);
    } finally { release.open(); await winnerRun; await loser; }
  }, 20_000);

  it.each(['session','outbox'] as const)('rechecks policy expiration after an observed %s lock wait', async (blockedOn) => {
    const { intent, anchor } = await rawFixture(fx.db, wire.storage);
    const blocker = await fx.db.migrator.connect();
    let action: Promise<unknown> | undefined;
    try {
      await blocker.query('BEGIN');
      await (blockedOn === 'session'
        ? blocker.query('SELECT id FROM foundation.request_sessions WHERE id=$1 FOR UPDATE', [anchor.sessionId])
        : blocker.query('LOCK foundation.outbox_events IN ACCESS EXCLUSIVE MODE'));
      const atOutbox = gate();
      let outboxPid = 0;
      const watching = observeBackend(fx.db.runtime);
      const audited = new WeakSet<object>();
      const watched = blockedOn === 'session' ? watching.pool : withQueryHook(fx.db.runtime,
        (sql) => /INSERT\s+INTO\s+foundation\.(audit_logs|outbox_events)/iu.test(sql), async (sql, client, query) => {
          if (sql.includes('audit_logs')) {
            const result = await query();
            audited.add(client);
            return result;
          }
          expect(audited.has(client)).toBe(true);
          outboxPid = await pid(client);
          atOutbox.open();
          return query();
        });
      const p = await retentionPolicy(fx.db, { expiresAt: await dbTime(fx.db, 2_000) });
      const planning = planRetention(fx.plan(p, watched), signal());
      action = settle(planning);
      if (blockedOn === 'outbox') { await atOutbox.wait(); }
      await waitForBlockingPid(fx.db, await pid(blocker), blockedOn === 'outbox' ? outboxPid : await watching.pid());
      await waitForDbExpiry(fx.db, p.expiresAt);
      await blocker.query('COMMIT');
      // Some planner ports defer an expired candidate; others fail closed at the operation boundary.
      const outcome = await settle(planning);
      if (outcome.ok) { expect(outcome.value.advanced).toBe(0); }
      else { await refusal(planning, 'NOT_CONFIGURED'); }
      expect(await items(fx.db, intent.intentId)).toEqual([]);
      expect(await auditPairs(fx.db, intent.intentId)).toEqual([]);
      expect(await fx.events()).toEqual([]);
      expect(wire.deletes()).toHaveLength(0);
    } finally { await blocker.query('ROLLBACK'); blocker.release(); await action; }
  }, 15_000);

  it.each(['hold', 'decision'] as const)('rolls back %s and graph if same-transaction outbox refuses after audit', async (operation) => {
    const fixture = await rawFixture(fx.db, wire.storage);
    const { intent } = fixture;
    await seedSanitized(fx.db, fixture, wire.config, { publish: false, dispatched: false });
    const before = await control(fx.db, intent.intentId);
    await rejectOutbox(fx.db, intent.intentId);
    const p = await retentionPolicy(fx.db);
    const action = operation === 'hold' ? changeFileHold(fx.hold(p), makeHoldGrant(fx.holdOperator, {
      intentId: intent.intentId, expectedRowVersion: BigInt(before.row_version), action: 'PLACE', reason: 'OPERATOR_REVIEW',
    })) : planRetention(fx.plan(p), signal());
    await refusal(action, 'CONFLICT', [fixture.raw.object_key]);
    expect(await control(fx.db, intent.intentId)).toEqual(before);
    expect(await items(fx.db, intent.intentId)).toEqual([]);
    expect(await auditPairs(fx.db, intent.intentId)).toEqual([]);
    expect(await fx.events()).toEqual([]);
    expect(wire.deletes()).toHaveLength(0);
  });

  it.each([false, true])('primary decision COMMIT reply lost (persisted=%s): resumes only after fresh durable proof', async (committed) => {
    const { intent, raw } = await rawFixture(fx.db, wire.storage);
    const p = await retentionPolicy(fx.db);
    const broker = fx.broker(wire.config);
    let triggered = false;
    const lossy = poolWithCommitHook(fx.db.runtime, async (_ordinal, client, commit) => {
      const row = (await client.query<{ pending: boolean }>(`SELECT delete_state='PENDING_LEDGER' AS pending
        FROM foundation.file_privacy_controls WHERE intent_id=$1`, [intent.intentId])).rows[0];
      if (!triggered && row?.pending === true) {
        triggered = true;
        if (committed) { await commit(); } else { await client.query('ROLLBACK'); }
        throw new Error(FAILURE_MARKER);
      }
      return commit();
    });
    try {
      await refusal(planRetention(fx.plan(p, lossy), signal()), 'CONFLICT', [raw.object_key]);
      expect(triggered).toBe(true);
      const [persisted] = await items(fx.db, intent.intentId);
      expect(persisted !== undefined).toBe(committed);
      expect(wire.deletes()).toHaveLength(0);
      expect(await fx.events()).toEqual([]);
      if (!committed) {
        await reconcileFileDeletion(fx.delete(p, broker), signal());
        expect(wire.deletes()).toHaveLength(0);
        expect(await fx.events()).toEqual([]);
        await planRetention(fx.plan(p), signal());
      }
      const expectedId = (await control(fx.db, intent.intentId)).delete_event_id;
      aggregate(await reconcileFileDeletion(fx.delete(p, broker), signal()));
      expect(wire.deletes()).toHaveLength(1);
      expect(await fx.events()).toEqual([expect.objectContaining({ event_id: expectedId, seq: '1' })]);
      expect(await control(fx.db, intent.intentId)).toMatchObject({ delete_event_id: expectedId, ledger_seq: '1' });
    } finally { await revokeDeleteBroker(broker); }
  });

  it('source decision and real ledger COMMIT precede wire; lost append reply retries exact event after lock-free wait', async () => {
    const { intent, raw } = await rawFixture(fx.db, wire.storage);
    const p = await retentionPolicy(fx.db);
    const broker = fx.broker(wire.config);
    const entered = gate();
    const reply = gate();
    const lossyLedger = { ...fx.ledger, async append(graph: Parameters<typeof fx.ledger.append>[0]) {
      // Autocommit append already committed to the separate PG; lose only its reply.
      await fx.ledger.append(graph);
      entered.open();
      await reply.wait();
      throw new Error(FAILURE_MARKER);
    } };
    let action: Promise<unknown> | undefined;
    try {
      await planRetention(fx.plan(p), signal());
      const pending = await control(fx.db, intent.intentId);
      expect(pending.delete_state).toBe('PENDING_LEDGER');
      expect(await fx.events()).toEqual([]);
      expect(wire.deletes()).toHaveLength(0);
      const run = reconcileFileDeletion({ ...fx.delete(p, broker), ledger: lossyLedger }, signal());
      action = settle(run);
      await entered.wait();
      expect(await fx.events()).toEqual([expect.objectContaining({ event_id: pending.delete_event_id, seq: '1' })]);
      expect(await control(fx.db, intent.intentId)).toEqual(pending);
      expect(wire.deletes()).toHaveLength(0);
      expect(fx.db.runtime.idleCount).toBe(fx.db.runtime.totalCount);
      const lock = await fx.db.migrator.connect();
      try {
        await lock.query('BEGIN');
        await lock.query('SELECT id FROM foundation.file_upload_intents WHERE id=$1 FOR UPDATE NOWAIT', [intent.intentId]);
        await lock.query('SELECT intent_id FROM foundation.file_privacy_controls WHERE intent_id=$1 FOR UPDATE NOWAIT', [intent.intentId]);
      } finally { await lock.query('ROLLBACK'); lock.release(); }
      reply.open();
      const outcome = await settle(run);
      if (!outcome.ok) { await refusal(run, 'CONFLICT', [raw.object_key]); }
      expect(wire.deletes()).toHaveLength(0);
      expect(await control(fx.db, intent.intentId)).toEqual(pending);
      aggregate(await reconcileFileDeletion(fx.delete(p, broker), signal()));
      expect((await fx.events()).map(({ event_id }) => event_id)).toEqual([pending.delete_event_id]);
      expect((await fx.floor.read(fx.scope.namespace)).seq).toBe(1n);
      expect(wire.deletes()).toHaveLength(1);
      expect(wire.objects.has(wire.path(raw.object_key))).toBe(false);
    } finally { reply.open(); await action; await revokeDeleteBroker(broker); }
  }, 20_000);

  it('waits for the authentic external floor CAS before its first DELETE', async () => {
    const { intent, raw } = await rawFixture(fx.db, wire.storage);
    const quarantineWindow = await retentionPolicy(fx.db, { quarantinedMs: 3_600_000 });
    expect((await planRetention(fx.plan(quarantineWindow), signal())).advanced).toBe(0);
    expect(await items(fx.db, intent.intentId)).toEqual([]);
    const p = await retentionPolicy(fx.db);
    await planRetention(fx.plan(p), signal());
    const broker = fx.broker(wire.config);
    const entered = gate();
    const resume = gate();
    const verifier = fx.withFloor({ read: (namespace) => fx.floor.read(namespace), async compareAndPin(expected, next) {
      entered.open();
      await resume.wait();
      return fx.floor.compareAndPin(expected, next);
    } });
    const action = settle(reconcileFileDeletion({ ...fx.delete(p, broker), verifier }, signal()));
    try {
      await entered.wait();
      const [event] = await fx.events();
      expect(event).toMatchObject({ intent_id: intent.intentId, seq: '1' });
      expect((await control(fx.db, intent.intentId)).delete_state).toBe('PENDING_LEDGER');
      expect((await fx.floor.read(fx.scope.namespace)).seq).toBe(0n);
      expect(fx.db.runtime.idleCount).toBe(fx.db.runtime.totalCount);
      expect(wire.deletes()).toHaveLength(0);
      expect(wire.objects.has(wire.path(raw.object_key))).toBe(true);
      resume.open();
      expect(await action).toMatchObject({ ok: true });
      expect((await fx.floor.read(fx.scope.namespace))).toMatchObject({ seq: 1n, hash: event?.sha256 });
      expect(wire.deletes()).toHaveLength(1);
      expect((await control(fx.db, intent.intentId)).delete_state).toBe('CONFIRMED_ABSENT');
    } finally { resume.open(); await action; await revokeDeleteBroker(broker); }
  });

  it('uses all class anchors and either freezes the full cross-target graph or nothing, stopping B/C access', async () => {
    const orphanWire = await privacyWire(fx.scope.namespace, 'orphan', (record) => record.method === 'PUT'
      ? (req) => { req.resume(); req.once('end', () => { req.socket.destroy(); }); } : undefined);
    const sanWire = await privacyWire(fx.scope.namespace, 'san');
    try {
      const reservation = await reserve(fx.db);
      const orphan = await orphanRaw(fx.db, orphanWire, reservation);
      const upload = command(reservation.anchor, reservation.intent.intentId);
      await uploadReservedFile(fx.db.runtime, wire.storage, policy(), upload);
      const intentId = reservation.intent.intentId;
      const raw = (await attempts(fx.db, intentId)).find((row) => row.state === 'VERIFIED');
      if (raw === undefined) { throw new Error('Missing second real RAW attempt'); }
      const fixture = { ...reservation, upload, raw };
      const san = await seedSanitized(fx.db, fixture, sanWire.config, { publish: true, dispatched: true });
      const failed = await seedSanitized(fx.db, fixture, sanWire.config, { publish: false, dispatched: false });
      const graph = [raw.object_key, orphan.raw.object_key, san.objectKey, failed.objectKey].sort();
      expect(new Set(graph).size).toBe(4);
      for (const override of [{ rawBoundMs: 3_600_000 }, { readyMs: 3_600_000 }, { orphanMs: 3_600_000 }, { maxItemsPerIntent: 3 }]) {
        const pending = await planRetention(fx.plan(await retentionPolicy(fx.db, override)), signal());
        expect(pending.advanced).toBe(0);
        expect(await items(fx.db, intentId)).toEqual([]);
        expect(await control(fx.db, intentId)).toMatchObject({ access_epoch: '1', delete_state: 'OPEN' });
      }
      sanWire.seed(san.objectKey, PNG);
      const budget = createFileReadBudget({ mode: 'local-synthetic', namespace: fx.epoch.namespace, singleProcess: true,
        maxBufferedBytes: 2_000_000, maxActiveStreams: 1, maxLiveOperationsPerOwner: 4 });
      const access: AccessContext = { pool: fx.db.runtime, epoch: fx.epoch, storage: sanWire.storage,
        policy: { mode: 'local-synthetic', expiresAt: await dbTime(fx.db, 60_000), maxAccessAgeMs: 60_000,
          maxChunkBytes: 4, maxBufferedBytes: 2_000_000, maxActiveStreams: 1, ticketMs: 10_000 }, budget };
      const file = { session: proof(reservation.anchor), intentId };
      // Metadata and stream use actual C ports; fixture publication intentionally is not scanner evidence.
      await expect(readReadyMetadata(access, file)).resolves.toMatchObject({ state: 'READY' });
      const ticket = await openReadyStream(access, { ...file, signal: signal() });
      try {
        await expect(readReadyChunk(ticket)).resolves.toMatchObject({ kind: 'CHUNK', bytes: Uint8Array.from(PNG.subarray(0, 4)) });
        aggregate(await planRetention(fx.plan(await retentionPolicy(fx.db)), signal()));
        const rows = await items(fx.db, intentId);
        expect(rows.map(({ object_key }) => object_key).sort()).toEqual(graph);
        expect(rows.map(({ attempt_kind, attempt_id, target_bucket, write_proof }) => [attempt_kind, attempt_id, target_bucket, write_proof])).toEqual(expect.arrayContaining([
          ['RAW', raw.id, wire.config.bucket, 'VERIFIED_SETTLED'], ['RAW', orphan.raw.id, orphanWire.config.bucket, 'UNKNOWN'],
          ['SANITIZED', san.attempt, sanWire.config.bucket, 'VERIFIED_SETTLED'], ['SANITIZED', failed.attempt, sanWire.config.bucket, 'NEVER_DISPATCHED'],
        ]));
        const count = wire.socket.requests.length + sanWire.socket.requests.length + orphanWire.socket.requests.length;
        await refusal(readReadyMetadata(access, file), ['NOT_READY', 'NOT_FOUND', 'CONFLICT']);
        await refusal(uploadReservedFile(fx.db.runtime, wire.storage, policy(), upload), ['CONFLICT', 'NOT_FOUND']);
        expect(wire.socket.requests.length + sanWire.socket.requests.length + orphanWire.socket.requests.length).toBe(count);
        expect(await bindings(fx.db, intentId)).toHaveLength(1);
        await refusal(readReadyChunk(ticket), ['NOT_READY', 'TICKET_CLOSED', 'STALE_CLAIM', 'NOT_FOUND']);
      } finally { await closeReadyStream(ticket); }
    } finally { await orphanWire.close(); await sanWire.close(); }
  }, 20_000);
});
