import { afterAll, afterEach, beforeAll, expect, it } from 'vitest';
import { closeReadyStream, createFileReadBudget, openReadyStream, readReadyChunk, readReadyMetadata } from '../src/files/file-access/index.js';
import type { AccessContext } from '../src/files/file-lifecycle/contract.js';
import { recordConsentGiven } from '../src/settings/legal/index.js';
import { proof, revokeConsent } from './file-reservations-fixture.js';
import type { FileReservationsFixture } from './file-reservations-fixture.js';
import { assertRefusal, gate, poolWithCommitHook, pid, waitForBlockingPid, waitForDbExpiry } from './file-upload-fixture.js';
import { settle } from './file-storage-fixture.js';
import { randomUUID } from 'node:crypto';
import {
  accessPolicy, closeFixture, control, epoch, expectRefusal, expiresIn, lifecycleIntegration, maxLiveOperationsPerOwner, png,
  seedReadFixture, signal, startLifecycleDb, wireStore, withQueryHook,
} from './file-lifecycle-fixture.js';

lifecycleIntegration('C protected access with real PostgreSQL claims and bounded S3 wire', () => {
  let db: FileReservationsFixture;
  let wire: Awaited<ReturnType<typeof wireStore>>;
  const budgetConfig = { mode: 'local-synthetic', namespace: epoch.namespace, singleProcess: true,
    maxBufferedBytes: 2_200_000, maxActiveStreams: 2, maxLiveOperationsPerOwner } as const;
  let budget: AccessContext['budget'];
  const tickets: Awaited<ReturnType<typeof openReadyStream>>[] = [];
  beforeAll(async () => { db = await startLifecycleDb(); budget = createFileReadBudget(budgetConfig); }, 40_000);
  afterEach(async () => {
    await Promise.all(tickets.splice(0).map(async (ticket) => { await closeReadyStream(ticket); }));
    await closeFixture(wire);
  });
  afterAll(async () => { await closeFixture(db); });
  const context = (patch: Partial<AccessContext> = {}): AccessContext => ({
    pool: db.runtime, epoch, storage: wire.storage, budget,
    policy: accessPolicy({ maxBufferedBytes: budgetConfig.maxBufferedBytes }), ...patch,
  });
  const open = async (ctx: AccessContext, cmd: Parameters<typeof openReadyStream>[1]) => {
    const ticket = await openReadyStream(ctx, cmd); tickets.push(ticket); return ticket;
  };

  it('opaque ticket copies fail; each delivered chunk owns exactly its bytes and mutating one cannot alter future data', async () => {
    wire = await wireStore();
    const { file, pub, key, output } = await seedReadFixture(db, wire);
    const ctx = context();
    expect(await readReadyMetadata(ctx, file)).toEqual({ fileId: pub, state: 'READY', mime: 'image/png', bytes: output.length });
    expect(wire.sanitizedGets()).toHaveLength(0);
    const ticket = await open(ctx, { ...file, signal: signal() });
    expect(Reflect.ownKeys(ticket)).toEqual([]);
    for (const forged of [{}, { ...ticket }, JSON.parse(JSON.stringify(ticket)) as unknown, new Proxy(ticket, {})]) {
      await expectRefusal(readReadyChunk(forged as typeof ticket), 'TICKET_CLOSED');
    }
    const buffers: ArrayBufferLike[] = [];
    let cursor = 0;
    for (;;) {
      const result = await readReadyChunk(ticket);
      if (result.kind === 'EOF') {break;}
      expect(Buffer.isBuffer(result.bytes)).toBe(false);
      expect(result.bytes.byteOffset).toBe(0);
      expect(result.bytes.buffer.byteLength).toBe(result.bytes.byteLength);
      expect(buffers).not.toContain(result.bytes.buffer);
      buffers.push(result.bytes.buffer);
      const original = output.subarray(cursor, cursor + result.bytes.length);
      expect(Buffer.from(new Uint8Array(result.bytes.buffer))).toEqual(original);
      cursor += result.bytes.byteLength;
      result.bytes.fill(255);
    }
    expect(cursor).toBe(output.length);
    expect(buffers.length).toBeGreaterThan(3);
    expect(wire.sanitizedGets()).toHaveLength(1);
    expect(wire.store.objects.get(`/${wire.config.bucket}/${key}`)).toEqual(output);
  });

  it.each(['same-length tamper', 'partial status', 'malformed full response'] as const)(
    'full GET refuses %s before creating a ticket or exposing any byte', async (scenario) => {
      wire = await wireStore((path, method) => path.includes('/sanitized/') && method === 'GET' ? (req, res) => {
        req.resume();
        const copy = Buffer.from(png);
        if (scenario === 'same-length tamper') {copy[copy.length - 1] = 0;}
        res.writeHead(scenario === 'partial status' ? 206 : 200, {
          'Content-Length': String(copy.length),
          ...(scenario === 'same-length tamper' ? {} : { 'Content-Range': `bytes 0-${String(copy.length - 1)}/${String(copy.length)}` }),
        });
        res.end(copy);
      } : undefined);
      const { file } = await seedReadFixture(db, wire);
      await expectRefusal(openReadyStream(context(), { ...file, signal: signal() }), ['NOT_READY', 'CONFLICT', 'WRITE_OUTCOME_UNKNOWN']);
      expect(wire.sanitizedGets()).toHaveLength(1);
    },
  );

  it('revocation after one admitted chunk stops later chunks and metadata; new GIVEN does not replace original basis', async () => {
    wire = await wireStore();
    const { anchor, file } = await seedReadFixture(db, wire);
    const ctx = context();
    const ticket = await open(ctx, { ...file, signal: signal() });
    const admitted = gate(); const release = gate();
    // Authorization reaches COMMIT on a real PG connection. A second pull must not race the first.
    const heldContext = context({ pool: poolWithCommitHook(db.runtime, async (n, _client, commit) => {
      const result = await commit();
      if (n === 2) { admitted.open(); await release.wait(); }
      return result;
    }) });
    await closeReadyStream(ticket);
    const heldTicket = await open(heldContext, { ...file, signal: signal() });
    const pull = settle(readReadyChunk(heldTicket));
    try {
      await admitted.wait();
      await expectRefusal(readReadyChunk(heldTicket), 'TICKET_CLOSED');
      await revokeConsent(db, anchor, anchor.evidenceId);
      const accepted = await db.inTransaction((client) => recordConsentGiven(client, {
        session: proof(anchor), purpose: 'REQUEST_PROCESSING', documentVersionId: anchor.documentVersionId,
        accepted: true, evidenceRef: randomUUID(),
      }));
      expect(accepted.evidenceId).not.toBe(anchor.evidenceId);
      await expectRefusal(readReadyMetadata(ctx, file), 'CONSENT_NOT_CURRENT', [anchor.token]);
      release.open();
      const chunk = await pull;
      expect(chunk).toMatchObject({ ok: true, value: { kind: 'CHUNK', bytes: new Uint8Array(png.subarray(0, 17)) } });
      await expectRefusal(readReadyChunk(heldTicket), 'CONSENT_NOT_CURRENT', [anchor.token]);
    } finally { release.open(); await pull; }
  });

  it('does not reclaim an expired occupied read; only exact old cleanup permits new generation', async () => {
    wire = await wireStore();
    const { file } = await seedReadFixture(db, wire);
    const ctx = context({ policy: accessPolicy({ maxBufferedBytes: budgetConfig.maxBufferedBytes, ticketMs: 700 }) });
    const old = await open(ctx, { ...file, signal: signal() });
    const leased = await control(db, file.intentId);
    if (leased === undefined || leased.read_expires_at === null) {throw new Error('Expected an occupied read claim');}
    await waitForDbExpiry(db, leased.read_expires_at);
    await expectRefusal(openReadyStream(context(), { ...file, signal: signal() }), 'ACCESS_LIMIT');
    expect(wire.sanitizedGets()).toHaveLength(1);
    expect(await control(db, file.intentId)).toEqual(leased);
    await closeReadyStream(old);
    const fresh = await open(context(), { ...file, signal: signal() });
    const next = await control(db, file.intentId);
    expect(next?.read_generation).toBe(leased.read_generation + 1);
    expect(next?.read_lease_id).not.toBe(leased.read_lease_id);
    await expectRefusal(readReadyChunk(old), 'TICKET_CLOSED');
    await closeReadyStream(old);
    expect(await control(db, file.intentId)).toEqual(next);
    expect(await readReadyChunk(fresh)).toMatchObject({ kind: 'CHUNK' });
  });

  it.each(['stream count', 'peak RAM'] as const)('global %s covers opening and live streams across contexts and publications', async (reason) => {
    const got = gate(); const letGetFinish = gate();
    let stall = '';
    wire = await wireStore((path, method) => method === 'GET' && path === stall ? (req, res) => {
      req.resume();
      got.open();
      void letGetFinish.wait().then(() => {
        const stored = wire.store.objects.get(path);
        if (stored === undefined) { res.writeHead(404).end(); return; }
        res.writeHead(200, { 'Content-Length': String(stored.length) }).end(stored);
      }, () => { res.destroy(); });
    } : undefined);
    const a = await seedReadFixture(db, wire); const b = await seedReadFixture(db, wire);
    stall = `/${wire.config.bucket}/${a.key}`;
    const caps = reason === 'stream count' ? { maxActiveStreams: 1 } : { maxBufferedBytes: 1_500_000 };
    const policy = accessPolicy({ maxBufferedBytes: budgetConfig.maxBufferedBytes, ...caps });
    // Separate context and adapter object, same single configured process handle.
    const actual = wire.storage;
    const ctx = context({ policy });
    const other = context({ policy: { ...policy }, budget: createFileReadBudget({ ...budgetConfig }),
      storage: { fetchReadyBytes: actual.fetchReadyBytes.bind(actual) } });
    const opened = settle(open(ctx, { ...a.file, signal: signal() }));
    try {
      await got.wait();
      await expectRefusal(openReadyStream(other, { ...b.file, signal: signal() }), 'ACCESS_LIMIT');
      expect(wire.sanitizedGets()).toHaveLength(1);
      letGetFinish.open();
      const result = await opened;
      if (!result.ok) {throw result.error;}
      await expectRefusal(openReadyStream(other, { ...b.file, signal: signal() }), 'ACCESS_LIMIT');
      await closeReadyStream(result.value);
      const after = await open(other, { ...b.file, signal: signal() });
      expect(await readReadyChunk(after)).toMatchObject({ kind: 'CHUNK' });
      expect(wire.sanitizedGets()).toHaveLength(2);
    } finally { letGetFinish.open(); await opened; }
  }, 15_000);

  it('publication SELECT actually waits on another backend and metadata rechecks DB clock afterwards', async () => {
    wire = await wireStore();
    const { file } = await seedReadFixture(db, wire);
    const locker = await db.migrator.connect();
    const waiterReady = gate();
    const deadline = expiresIn(1_500);
    let waitingPid = -1;
    let read: ReturnType<typeof settle> | undefined;
    try {
      await locker.query('BEGIN');
      // Even a plain SELECT blocks on this independent DDL-strength lock; no
      // fake query result and no behavioral dependence on its row-lock clause.
      await locker.query('LOCK TABLE foundation.file_publications IN ACCESS EXCLUSIVE MODE');
      const blocker = await pid(locker);
      const pool = withQueryHook(db.runtime, (sql) => /SELECT[\s\S]+file_publications/iu.test(sql), async (_sql, client, query) => {
        waitingPid = await pid(client); waiterReady.open(); return query();
      });
      read = settle(readReadyMetadata(context({ pool, policy: accessPolicy({ expiresAt: deadline, maxBufferedBytes: budgetConfig.maxBufferedBytes }) }), file));
      await waiterReady.wait();
      await waitForBlockingPid(db, blocker, waitingPid);
      await waitForDbExpiry(db, deadline);
      await locker.query('COMMIT');
      const outcome = await read;
      assertRefusal(outcome.ok ? undefined : outcome.error, ['NOT_CONFIGURED', 'NOT_READY', 'STALE_CLAIM']);
      expect(wire.sanitizedGets()).toHaveLength(0);
    } finally { await locker.query('ROLLBACK'); locker.release(); await read; }
  }, 12_000);

  it('native abort cannot be hidden by a caller listener stopping propagation', async () => {
    wire = await wireStore();
    const { file } = await seedReadFixture(db, wire);
    const abort = new AbortController();
    abort.signal.addEventListener('abort', (event) => { event.stopImmediatePropagation(); });
    const ticket = await open(context(), { ...file, signal: abort.signal });
    abort.abort(new Error('fixture-private-abort-reason'));
    await expectRefusal(readReadyChunk(ticket), ['ABORTED', 'TICKET_CLOSED'], ['fixture-private-abort-reason']);
    await closeReadyStream(ticket);
    expect((await control(db, file.intentId))?.read_lease_id).toBeNull();
  });

  it('unclassified GET rejection retains both durable occupancy and process peak capacity', async () => {
    // This deliberately leaves unresolved debt: keep the case last in this process.
    wire = await wireStore();
    const a = await seedReadFixture(db, wire); const b = await seedReadFixture(db, wire);
    const entered = gate(); const finish = gate(); const abort = new AbortController();
    const policy = accessPolicy({ maxBufferedBytes: 1_500_000, ticketMs: 600 });
    const ctx = context({ policy, storage: { fetchReadyBytes: async () => {
      entered.open(); await finish.wait(); throw new Error('fixture-private-uncertain-get');
    } } });
    const opening = settle(openReadyStream(ctx, { ...a.file, signal: abort.signal }));
    try {
      await entered.wait();
      const occupied = await control(db, a.file.intentId);
      if (occupied === undefined || occupied.read_expires_at === null) {throw new Error('Missing occupied read lease');}
      abort.abort();
      await waitForDbExpiry(db, occupied.read_expires_at);
      await expectRefusal(openReadyStream(context({ policy }), { ...b.file, signal: signal() }), 'ACCESS_LIMIT');
      finish.open();
      const outcome = await opening;
      assertRefusal(outcome.ok ? undefined : outcome.error, ['ABORTED', 'STALE_CLAIM', 'NOT_READY']);
      expect(await control(db, a.file.intentId)).toEqual(occupied);
      await expectRefusal(openReadyStream(context({ policy }), { ...b.file, signal: signal() }), 'ACCESS_LIMIT');
      expect(wire.sanitizedGets()).toEqual([]);
    } finally { finish.open(); await opening; }
  }, 12_000);
});
