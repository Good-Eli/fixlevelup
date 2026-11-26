import { generateKeyPairSync, randomBytes, randomUUID, verify } from 'node:crypto';
import { parseEnv } from 'node:util';
import { readFileSync } from 'node:fs';
import { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { encodeGraph, headMessage } from '../src/files/file-ledger/codec.js';
import { bootstrapFileLedgerNamespace, createFileLedgerVerifier, createPgFileLedger, createPgFloorStore, ledgerGraphSha256,
  readLedgerMembership, type FileLedger, type LedgerFloor, type LedgerGraph, type LedgerHead, type LedgerScope } from '../src/files/file-ledger/index.js';

const limits = { maxItems: 8, maxProofEvents: 32 };
const credentials = { publicKey: generateKeyPairSync('ed25519').publicKey };
const scopeOf = ({ namespace, incarnation, writerEpoch }: LedgerScope): LedgerScope => ({ namespace, incarnation, writerEpoch });
const headOf = ({ namespace, incarnation, writerEpoch, seq, hash }: LedgerHead): LedgerHead => ({ namespace, incarnation, writerEpoch, seq, hash });
function graph(scope: LedgerScope): LedgerGraph {
  const raw = randomUUID(), sanitized = randomUUID();
  const target = { endpoint: 'http://127.0.0.1:3900', bucket: 'synthetic-ledger-proof', region: 'garage' };
  return { ...scopeOf(scope), eventId: randomUUID(), intentId: randomUUID(), accessEpoch: 2n, items: [
    { kind: 'SANITIZED', attemptId: sanitized, target, objectKey: `sanitized/${sanitized}/${randomUUID()}`, writeProof: 'UNKNOWN' },
    { kind: 'RAW', attemptId: raw, target, objectKey: `quarantine/${raw}/${randomUUID()}`, writeProof: 'VERIFIED_SETTLED' },
  ] };
}
const denied = { code: 'LEDGER_DENIED' };

describe('closed v1 file-ledger graph codec', () => {
  it('canonicalizes typed graph order and rejects unsafe or malformed input without caller diagnostics', () => {
    const input = graph({ namespace: randomUUID(), incarnation: randomUUID(), writerEpoch: 1n });
    const digest = ledgerGraphSha256(input, 2);
    expect(digest).toMatch(/^[0-9a-f]{64}$/);
    expect(ledgerGraphSha256({ ...input, items: [...input.items].reverse() }, 2)).toBe(digest);
    const reason = { code: 'INVALID_LEDGER_INPUT', message: 'INVALID_LEDGER_INPUT' };
    expect(() => ledgerGraphSha256(input, 1)).toThrow(expect.objectContaining(reason));
    expect(() => ledgerGraphSha256({ ...input, accessEpoch: 9_223_372_036_854_775_808n }, 2)).toThrow(expect.objectContaining(reason));
    const first = input.items[0];
    if (!first) { throw new Error('SYNTHETIC_LEDGER_ITEM_MISSING'); }
    expect(() => ledgerGraphSha256({ ...input, items: [first, first] }, 2)).toThrow(expect.objectContaining(reason));
    expect(() => ledgerGraphSha256({ ...input, items: [{ ...first, objectKey: `sanitized/${randomUUID()}/${randomUUID()}` }] }, 2)).toThrow(expect.objectContaining(reason));
    expect(() => ledgerGraphSha256({ ...input, items: [{ ...first, target: { ...first.target, endpoint: `${first.target.endpoint}/` } }] }, 2)).toThrow(expect.objectContaining(reason));
    expect(() => ledgerGraphSha256(new Proxy(input, { ownKeys() { throw new Error('untrusted-reflection-marker'); } }), 2)).toThrow(expect.objectContaining(reason));
    expect(() => ledgerGraphSha256({ ...input, get intentId(): string { throw new Error('untrusted-getter-marker'); } }, 2)).toThrow(expect.objectContaining(reason));
    const revoked = Proxy.revocable(input.items, {}); revoked.revoke();
    expect(() => ledgerGraphSha256({ ...input, items: revoked.proxy }, 2)).toThrow(expect.objectContaining(reason));
  });
});

describe.skipIf(process.env['FIXLEVELUP_ISOLATED_FILE_LEDGER_TESTS'] !== '1')('isolated real PostgreSQL file ledger + independent floor', () => {
  const databases = { ledger: 'fixlevelup_file_ledger', floor: 'fixlevelup_file_floor' };
  const pools: Pool[] = [];
  const backgroundPoolErrors: string[] = [];
  /** Disposable database names created by THIS run on the docker test containers:
   * pushed exactly when the run's CREATE DATABASE succeeded (CREATE is the reuse
   * guard, so a successful CREATE proves this run owns that database). */
  const createdLedgerDbs: string[] = [];
  const createdFloorDbs: string[] = [];
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  let env: ReturnType<typeof parseEnv>;
  let writer: Pool, signer: Pool, operator: Pool, floorAdmin: Pool, ledgerAdmin: Pool, floorOperator: Pool, floorVerifier: Pool;
  let ledger: FileLedger;
  const pool = (kind: keyof typeof databases, role: string, database = databases[kind]) => {
    const user = `file_${kind}_${role}`;
    const password = env[`${user.toUpperCase()}_PASSWORD`];
    if (!password || !/^[0-9a-f]{64}$/.test(password)) {throw new Error('INVALID_SYNTHETIC_LEDGER_CREDENTIAL_CONFIG');}
    const p = new Pool({ user, password, database, host: '127.0.0.1', port: kind === 'ledger' ? 55433 : 55434, max: 4,
      connectionTimeoutMillis: 5_000, statement_timeout: 10_000 });
    // Idle-client socket errors must be observed and asserted during teardown,
    // never escape Vitest as process-level unhandled errors.
    p.on('error', (error) => {
      backgroundPoolErrors.push(typeof error.code === 'string' ? error.code : 'PG_POOL_ERROR');
    });
    pools.push(p);
    return p;
  };
  const makeLedger = (a: Pool, b: Pool, ops?: Pool) => createPgFileLedger(a, {
    mode: 'local-synthetic', privateKey, signerPool: b, limits, ...(ops ? { operatorPool: ops } : {}),
  });
  const bootstrap = () => bootstrapFileLedgerNamespace({ mode: 'local-synthetic', signerPublicKey: publicKey,
    ledgerOperatorPool: operator, floorOperatorPool: floorOperator, initialEpoch: 1n });
  const verifier = (source = ledger, store = createPgFloorStore(floorVerifier)) => createFileLedgerVerifier({ ledger: source,
    signerPublicKey: publicKey, floor: store, limits });
  const branch = async (anchor: LedgerFloor): Promise<FileLedger> => {
    // Fresh DB and exact genesis backup row, copied directly from the ledger.
    // No source rows/DBs/volumes (including the floor) are modified.
    const db = `file_ledger_proof_${randomBytes(12).toString('hex')}`;
    const row = (await ledgerAdmin.query<{ namespace_id: string; incarnation_id: string; seq: string; chain_sha256: string; writer_epoch: string }>(`
      SELECT namespace_id,incarnation_id,seq::text,chain_sha256,writer_epoch::text FROM file_ledger.namespace_heads WHERE namespace_id=$1`,
    [anchor.namespace])).rows[0];
    if (!row) { throw new Error('SYNTHETIC_LEDGER_SNAPSHOT_MISSING'); }
    expect(row).toMatchObject({ seq: '0', chain_sha256: anchor.hash });
    await ledgerAdmin.query(`CREATE DATABASE ${db}`);
    // A successful CREATE proves this run owns the disposable database; the name is
    // tracked so this run's teardown can drop exactly it.
    createdLedgerDbs.push(db);
    const restoredAdmin = pool('ledger', 'admin', db);
    const sql = readFileSync(new URL('../../../infra/file-ledger/ledger.sql', import.meta.url), 'utf8');
    await restoredAdmin.query(sql.slice(sql.indexOf('REVOKE ALL ON SCHEMA public')));
    await restoredAdmin.query(readFileSync(new URL('../../../infra/file-ledger/ledger-writers.sql', import.meta.url), 'utf8'));
    await restoredAdmin.query('INSERT INTO file_ledger.namespace_heads VALUES ($1,$2,$3,$4,$5)',
      [row.namespace_id, row.incarnation_id, row.seq, row.chain_sha256, row.writer_epoch]);
    const binding = (await ledgerAdmin.query<{ writer_role_oid: number }>(`SELECT writer_role_oid FROM file_ledger.namespace_writers
      WHERE namespace_id=$1 AND writer_epoch=$2`, [anchor.namespace, anchor.writerEpoch.toString()])).rows[0];
    if (!binding) { throw new Error('SYNTHETIC_LEDGER_WRITER_SNAPSHOT_MISSING'); }
    await restoredAdmin.query('INSERT INTO file_ledger.namespace_writers VALUES ($1,$2,$3)',
      [row.namespace_id, row.writer_epoch, binding.writer_role_oid]);
    return makeLedger(pool('ledger', 'writer', db), pool('ledger', 'signer', db), pool('ledger', 'operator', db));
  };
  /** Drops exactly the disposable databases this run created on the docker test
   * containers, from the matching admin pool and only after every pool of this run
   * was ended. Ownership is re-proven by the strict disposable-name pattern. */
  const dropCreatedDatabases = async (): Promise<void> => {
    for (const db of createdLedgerDbs.splice(0)) {
      if (!/^file_ledger_proof_[a-f0-9]{24}$/.test(db)) { throw new Error('SYNTHETIC_LEDGER_REFUSING_NON_FIXTURE_DROP'); }
      const active = await ledgerAdmin.query<{ pid: number }>(
        'SELECT pid FROM pg_stat_activity WHERE datname=$1', [db]);
      if (active.rowCount !== 0) { throw new Error('SYNTHETIC_LEDGER_DISPOSABLE_DATABASE_HAS_OPEN_SESSIONS'); }
      await ledgerAdmin.query(`DROP DATABASE IF EXISTS "${db}"`);
    }
    for (const db of createdFloorDbs.splice(0)) {
      if (!/^file_floor_proof_[a-f0-9]{24}$/.test(db)) { throw new Error('SYNTHETIC_LEDGER_REFUSING_NON_FIXTURE_DROP'); }
      const active = await floorAdmin.query<{ pid: number }>(
        'SELECT pid FROM pg_stat_activity WHERE datname=$1', [db]);
      if (active.rowCount !== 0) { throw new Error('SYNTHETIC_LEDGER_DISPOSABLE_DATABASE_HAS_OPEN_SESSIONS'); }
      await floorAdmin.query(`DROP DATABASE IF EXISTS "${db}"`);
    }
  };
  beforeAll(() => {
    env = parseEnv(readFileSync(new URL('../../../infra/file-ledger/.env', import.meta.url), 'utf8'));
    writer = pool('ledger', 'writer'); signer = pool('ledger', 'signer'); operator = pool('ledger', 'operator');
    floorVerifier = pool('floor', 'verifier'); floorOperator = pool('floor', 'operator');
    floorAdmin = pool('floor', 'admin'); ledgerAdmin = pool('ledger', 'admin');
    ledger = makeLedger(writer, signer, operator);
  });
  afterAll(async () => {
    // Close every non-admin pool completely before touching its disposable DB.
    // If any pool fails to close, do not force-drop its DB: that would SIGTERM
    // live clients and turn a cleanup defect into Vitest unhandled 57P01 errors.
    const droppers = [ledgerAdmin, floorAdmin];
    try {
      const closing = await Promise.allSettled(pools
        .filter((p) => p !== ledgerAdmin && p !== floorAdmin).map((p) => p.end()));
      if (closing.some((result) => result.status === 'rejected')) {
        throw new Error('SYNTHETIC_LEDGER_POOL_CLOSE_FAILED');
      }
      if (backgroundPoolErrors.length > 0) {
        throw new Error('SYNTHETIC_LEDGER_BACKGROUND_CONNECTION_ERROR');
      }
      await dropCreatedDatabases();
    } finally {
      const closingDroppers = await Promise.allSettled(droppers.map((p) => p.end()));
      if (closingDroppers.some((result) => result.status === 'rejected')) {
        throw new Error('SYNTHETIC_LEDGER_ADMIN_POOL_CLOSE_FAILED');
      }
    }
  });

  it('serializes two real writers under head lock, rolls back head+event and idempotently replays exact payload only', async () => {
    const genesis = await bootstrap(), scope = scopeOf(genesis);
    const a = await writer.connect(), b = await writer.connect();
    const first = graph(scope), second = graph(scope);
    const request = (event: LedgerGraph) => {
      // Exercise the exact SQL boundary in a deliberately uncommitted tx.
      return [event.namespace, event.incarnation, event.writerEpoch.toString(), event.eventId, event.intentId, event.accessEpoch.toString(),
        encodeGraph(event, limits.maxItems).payload];
    };
    const append = 'SELECT seq::text, sha256 FROM file_ledger.append($1,$2,$3,$4,$5,$6,$7)';
    let pending: Promise<unknown> | undefined;
    try {
      await a.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      await a.query('SET LOCAL synchronous_commit=off');
      const result = await a.query<{ seq: string }>(append, request(first));
      expect(result.rows[0]?.seq).toBe('1');
      expect((await a.query<{ synchronous_commit: string }>('SHOW synchronous_commit')).rows[0]?.synchronous_commit).toBe('on');
      const { rows: [ap] } = await a.query<{ pid: number }>('SELECT pg_backend_pid() AS pid');
      const { rows: [bp] } = await b.query<{ pid: number }>('SELECT pg_backend_pid() AS pid');
      if (!ap || !bp) { throw new Error('SYNTHETIC_LEDGER_WRITER_PIDS_MISSING'); }
      pending = b.query(append, request(second));
      void pending.catch(() => undefined);
      await vi.waitFor(async () => {
        const observed = await ledgerAdmin.query<{ blocked: boolean }>('SELECT $1 = ANY(pg_blocking_pids($2)) AS blocked', [ap.pid, bp.pid]);
        expect(observed.rows[0]?.blocked).toBe(true);
      });
      const during = await ledger.getHead(scope, randomBytes(32).toString('hex'));
      expect(during.seq).toBe(0n);
      await a.query('ROLLBACK');
      await expect(pending).resolves.toMatchObject({ rows: [{ seq: '1' }] });
    } finally {
      await a.query('ROLLBACK');
      await pending?.catch(() => undefined);
      a.release(); b.release();
    }
    const writes = await Promise.all([ledger.append(first), ledger.append(first), ledger.append(second)]);
    expect(writes.map((event) => event.seq)).toEqual([2n, 2n, 1n]);
    expect(writes[0]).toEqual(writes[1]);
    await expect(ledger.append({ ...first, accessEpoch: 3n })).rejects.toMatchObject({ code: 'LEDGER_CONFLICT' });
    await expect(writer.query(append, [...request(graph(scope)).slice(0, 6), Buffer.from('{}')])).rejects.toMatchObject({ code: 'FL002' });
    const events = await ledger.getEvents(scope, 0n, 2n);
    expect(events.map((event) => [event.seq, event.graph.eventId])).toEqual([[1n, second.eventId], [2n, first.eventId]]);
    const member = await verifier().verifyMembership(first, 2n);
    expect(readLedgerMembership(member)).toMatchObject({ ...writes[0], graphSha256: ledgerGraphSha256(first, 8), eventId: first.eventId });
    expect(() => readLedgerMembership(JSON.parse(JSON.stringify(member)))).toThrow('LEDGER_DENIED');
    expect(await createPgFloorStore(floorVerifier).read(scope.namespace)).toMatchObject(writes[0]);
  });

  it('rejects privileged role drift, preserves history and makes floor CAS monotonic/durable', async () => {
    const base = await bootstrap(), scope = scopeOf(base), event = graph(scope);
    await ledger.append(event);
    for (const [p, sql] of [
      [writer, 'UPDATE file_ledger.namespace_heads SET seq=99'], [writer, 'DELETE FROM file_ledger.events'],
      [writer, 'SELECT * FROM file_ledger.events'], [writer, 'TRUNCATE file_ledger.events'],
      [signer, 'SELECT file_ledger.append(NULL,NULL,NULL,NULL,NULL,NULL,NULL)'],
      [writer, 'SELECT file_ledger.initialize(NULL,NULL,NULL,NULL)'],
      [writer, 'SELECT file_ledger.append_unbound(NULL,NULL,NULL,NULL,NULL,NULL,NULL)'],
      [operator, 'SELECT file_ledger.fence_writer_unbound(NULL,NULL,NULL,NULL)'],
      [operator, 'INSERT INTO file_ledger.namespace_writers VALUES (NULL,NULL,NULL)'],
      [floorVerifier, 'SELECT file_floor.initialize(1,NULL)'],
      [floorOperator, 'SELECT file_floor.pin(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)'],
      [floorVerifier, 'UPDATE file_floor.current_heads SET seq=0'],
    ] as const) {await expect(p.query(sql)).rejects.toMatchObject({ code: '42501' });}
    const checkOwner = async (admin: Pool, role: string, commands: string[]) => {
      const client = await admin.connect();
      try {
        await client.query(`SET ROLE ${role}`);
        for (const sql of commands) {await expect(client.query(sql)).rejects.toMatchObject({ code: 'FL002' });}
      } finally { await client.query('RESET ROLE'); client.release(); }
    };
    await checkOwner(ledgerAdmin, 'file_ledger_owner', ['UPDATE file_ledger.events SET payload=payload',
      'DELETE FROM file_ledger.events WHERE false', 'TRUNCATE file_ledger.events']);
    await checkOwner(floorAdmin, 'file_floor_owner', ['DELETE FROM file_floor.current_heads WHERE false', 'TRUNCATE file_floor.current_heads']);
    const store = createPgFloorStore(floorVerifier);
    const read = await store.read(base.namespace);
    expect(read).toEqual(base);
    // Simulate a CAS race using a genuinely committed competing verifier.
    let first = true;
    const racing = createFileLedgerVerifier({ ledger, signerPublicKey: publicKey, limits, floor: {
      read: (ns) => store.read(ns),
      async compareAndPin(expected, next) {
        if (first) { first = false; await verifier().verifyMembership(event, 1n); }
        return store.compareAndPin(expected, next);
      },
    } });
    await expect(racing.verifyMembership(event, 1n)).resolves.toBeDefined();
    const after = await store.read(base.namespace);
    expect(after.seq).toBe(1n);
    await expect(store.compareAndPin(after, base)).rejects.toMatchObject(denied);
    await expect(store.compareAndPin(after, { ...after, hash: base.hash })).rejects.toMatchObject(denied);
  });

  it('rejects an independently cloned old ledger under valid fresh signatures and a same-height fork', async () => {
    const base = await bootstrap(), scope = scopeOf(base), event = graph(scope);
    const restored = await branch(base);
    const live = await ledger.append(event);
    await verifier().verifyMembership(event, live.seq);
    const nonce = randomBytes(32).toString('hex');
    const old = await restored.getHead(scope, nonce);
    expect(old.seq).toBe(0n);
    expect(verify(null, headMessage(old, nonce), publicKey, Buffer.from(old.signature, 'hex'))).toBe(true);
    await expect(verifier(restored).verifyLineage(scope, headOf(base))).rejects.toMatchObject(denied);
    const fork = await restored.append(graph(scope));
    expect(fork.seq).toBe(live.seq);
    expect(fork.hash).not.toBe(live.hash);
    const forkNonce = randomBytes(32).toString('hex'), forkHead = await restored.getHead(scope, forkNonce);
    expect(verify(null, headMessage(forkHead, forkNonce), publicKey, Buffer.from(forkHead.signature, 'hex'))).toBe(true);
    await expect(verifier(restored).verifyLineage(scope, headOf(base))).rejects.toMatchObject(denied);
    await restored.append(graph(scope));
    await expect(verifier(restored).verifyLineage(scope, headOf(base))).rejects.toMatchObject(denied);
    await expect(verifier(restored).verifyLineage(scope, { ...headOf(base), ...live })).rejects.toMatchObject(denied);
    expect(await createPgFloorStore(floorVerifier).read(base.namespace)).toMatchObject(live);
  });

  it('denies a missing floor after verifier restart, replayed nonce, wrong key, or lost durable pin ack', async () => {
    const genesis = await bootstrap(), scope = scopeOf(genesis), event = graph(scope), store = createPgFloorStore(floorVerifier);
    const position = await ledger.append(event);
    const db = `file_floor_proof_${randomBytes(12).toString('hex')}`;
    await floorAdmin.query(`CREATE DATABASE ${db}`);
    // A successful CREATE proves this run owns the disposable database; the name is
    // tracked so this run's teardown can drop exactly it.
    createdFloorDbs.push(db);
    const floorSql = readFileSync(new URL('../../../infra/file-ledger/floor.sql', import.meta.url), 'utf8');
    // The cluster-wide roles already exist; install only schema+ACL in this empty DB.
    await pool('floor', 'admin', db).query(floorSql.slice(floorSql.indexOf('REVOKE ALL ON SCHEMA public')));
    const empty = createPgFloorStore(pool('floor', 'verifier', db));
    await expect(verifier(ledger, empty).verifyMembership(event, position.seq)).rejects.toMatchObject(denied);
    await expect(empty.read(genesis.namespace)).rejects.toMatchObject(denied);
    const fresh = await bootstrapFileLedgerNamespace({ mode: 'local-synthetic', signerPublicKey: publicKey,
      ledgerOperatorPool: operator, floorOperatorPool: pool('floor', 'operator', db), initialEpoch: 1n });
    expect(fresh.namespace).not.toBe(genesis.namespace);
    await expect(empty.read(genesis.namespace)).rejects.toMatchObject(denied);
    const stale = await ledger.getHead(scope, randomBytes(32).toString('hex'));
    await expect(verifier({ ...ledger, getHead: () => Promise.resolve(stale) }).verifyMembership(event, position.seq)).rejects.toMatchObject(denied);
    const wrongKey = createFileLedgerVerifier({ ledger, signerPublicKey: credentials.publicKey, floor: store, limits });
    await expect(wrongKey.verifyMembership(event, position.seq)).rejects.toMatchObject(denied);
    const lostAck = createFileLedgerVerifier({ ledger, signerPublicKey: publicKey, limits, floor: {
      read: (ns) => store.read(ns),
      async compareAndPin(expected, next) { await store.compareAndPin(expected, next); throw new Error('pin ack lost'); },
    } });
    await expect(lostAck.verifyMembership(event, position.seq)).rejects.toMatchObject(denied);
    expect(await store.read(scope.namespace)).toMatchObject(position);
    await expect(verifier().verifyMembership(event, position.seq)).resolves.toBeDefined();
  });

  it('fences old writers and proves old events only under the newly active epoch', async () => {
    const base = await bootstrap(), scope = scopeOf(base), event = graph(scope);
    const restored = await branch(base);
    const position = await ledger.append(event);
    await restored.append(event);
    await verifier().verifyMembership(event, position.seq);
    const nextRole = 'file_ledger_writer_next';
    const oldPool = pool('ledger', 'writer');
    const independentOld = makeLedger(oldPool, signer);
    const nextWriter = makeLedger(pool('ledger', 'writer_next'), signer);
    await expect(nextWriter.append(graph(scope))).rejects.toMatchObject(denied);
    const oldClient = await oldPool.connect();
    const oldBackend = () => oldClient.query<{ pid: number }>('SELECT pg_backend_pid() AS pid');
    const nextEvent = graph({ ...scope, writerEpoch: 2n });
    let next: LedgerHead;
    try {
      const warmed = (await oldBackend()).rows[0];
      expect(warmed?.pid).toBeGreaterThan(0);
      next = await ledger.fenceLedgerWriter(scope, 2n, nextRole);
      await expect(oldClient.query('SELECT * FROM file_ledger.append($1,$2,$3,$4,$5,$6,$7)',
        [scope.namespace, scope.incarnation, '2', nextEvent.eventId, nextEvent.intentId, nextEvent.accessEpoch.toString(),
          encodeGraph(nextEvent, limits.maxItems).payload])).rejects.toMatchObject({ code: 'FL002' });
      expect((await oldBackend()).rows[0]).toEqual(warmed);
    } finally { oldClient.release(); }
    await expect(independentOld.append(graph(scope))).rejects.toMatchObject(denied);
    await expect(independentOld.append(event)).rejects.toMatchObject(denied);
    await expect(ledger.fenceLedgerWriter(scope, 3n, nextRole)).rejects.toMatchObject(denied);
    await expect(ledger.fenceLedgerWriter(scopeOf(next), 3n, nextRole)).rejects.toMatchObject(denied);
    await expect(operator.query('SELECT file_ledger.fence_writer($1,$2,$3,$4,$5)',
      [scope.namespace, scope.incarnation, '2', '3', 'file_ledger_writer'])).rejects.toMatchObject({ code: 'FL002' });
    await expect(independentOld.append(nextEvent)).rejects.toMatchObject(denied);
    const unrelated = await bootstrap();
    await expect(nextWriter.append(graph(scopeOf(unrelated)))).rejects.toMatchObject(denied);
    await expect(verifier().verifyMembership(event, position.seq)).rejects.toMatchObject(denied);
    const result = await verifier().verifyLineage(scopeOf(next), headOf(base));
    expect(result.head).toEqual(next);
    expect(result.events).toHaveLength(1);
    expect(await createPgFloorStore(floorVerifier).read(base.namespace)).toMatchObject(next);
    const oldNonce = randomBytes(32).toString('hex'), old = await restored.getHead(scope, oldNonce);
    expect(old).toMatchObject({ ...position, writerEpoch: 1n });
    expect(verify(null, headMessage(old, oldNonce), publicKey, Buffer.from(old.signature, 'hex'))).toBe(true);
    await expect(verifier(restored).verifyLineage(scope, headOf(base))).rejects.toMatchObject(denied);
    await expect(verifier().verifyLineage(scopeOf(next), { ...next, writerEpoch: 1n })).resolves.toMatchObject({ head: next, events: [] });
    const fact = readLedgerMembership(await verifier().verifyMembership(event, position.seq, scopeOf(next)));
    expect(fact.writerEpoch).toBe(1n);
    expect(fact.head.writerEpoch).toBe(2n);
    const nextPosition = await nextWriter.append(nextEvent);
    expect(nextPosition.seq).toBe(position.seq + 1n);
    await expect(independentOld.append(nextEvent)).rejects.toMatchObject(denied);
    await expect(verifier(nextWriter).verifyMembership(nextEvent, nextPosition.seq)).resolves.toBeDefined();
  });
});