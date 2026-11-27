import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Client } from 'pg';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { DatabaseConfig } from '../src/infrastructure/database/runtime-database.js';
import { OutboxStore } from '../src/infrastructure/outbox/outbox-store.js';
import type { OutboxLease } from '../src/infrastructure/outbox/outbox-store.js';
import { OutboxWorker } from '../src/infrastructure/outbox/outbox-worker.js';
import { SafeLogger } from '../src/runtime/safe-logger.js';
import { admitFixture } from './admission-fixture.js';
import { authFixtureMigrations, installPinnedMigrationHistory } from './auth-db-fixture.js';
import { loadP05LabTarget } from './p05-lab-target.js';
import { pinFreshFileDatabase } from './owned-test-database.js';

const lab = () => process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1' ? loadP05LabTarget() : undefined;
import type { AdmittedHandle } from './admission-fixture.js';

const root = resolve(import.meta.dirname, '../../..');
const databaseName = `fixlevelup_p019a_worker_${randomBytes(6).toString('hex')}`;
const clients: Client[] = [];
const stores: OutboxStore[] = [];
const workers: OutboxWorker[] = [];
let admission: AdmittedHandle;
let config: DatabaseConfig;
let migrator: Client;
let runtime: Client;
let contender: Client;
let first: OutboxStore;
let second: OutboxStore;

interface EventFixture {
  id: string;
  eventId: string;
  eventType: string;
  payload: { commandId: string; synthetic: true };
}

interface EventRow {
  id: string;
  event_id: string;
  event_type: string;
  status: 'PENDING' | 'EXPANDED' | 'FAILED';
  payload: unknown;
  attempt_count: number;
  lease_owner: string | null;
  lease_generation: string;
  lease_expires_at: Date | null;
  next_attempt_at: Date;
  last_error_code: 'HANDLER_FAILED' | 'ATTEMPTS_EXHAUSTED' | null;
}

function credential(source: string, key: string): string {
  const value = new RegExp(`^${key}=([a-f0-9]{64})$`, 'm').exec(source)?.[1];
  if (!value) { throw new Error('Local credentials required for isolated outbox integration tests'); }
  return value;
}

async function connect(user: string, password: string, database = databaseName): Promise<Client> {
  const client = new Client({ host: '127.0.0.1', port: 55432, database, user, password,
    connectionTimeoutMillis: 3000, statement_timeout: 3000, query_timeout: 4000,
    application_name: 'fixlevelup-p019a-outbox-test' });
  clients.push(client);
  await client.connect();
  return client;
}

function eventType(): string { return `test.${randomBytes(12).toString('hex')}`; }

async function seed(type: string, ageSeconds = 0): Promise<EventFixture> {
  const fixture: EventFixture = { id: randomUUID(), eventId: randomUUID(), eventType: type,
    payload: { commandId: randomUUID(), synthetic: true } };
  await runtime.query(`INSERT INTO foundation.outbox_events
    (id, event_id, event_type, payload, created_at)
    VALUES ($1, $2, $3, $4::jsonb, clock_timestamp() - $5::integer * INTERVAL '1 second')`,
  [fixture.id, fixture.eventId, fixture.eventType, JSON.stringify(fixture.payload), ageSeconds]);
  return fixture;
}

async function row(id: string): Promise<EventRow> {
  const result = await migrator.query<EventRow>('SELECT * FROM foundation.outbox_events WHERE id=$1', [id]);
  const found = result.rows[0];
  if (!found) { throw new Error('Missing synthetic outbox fixture'); }
  return found;
}

function leased(value: OutboxLease | undefined): OutboxLease {
  expect(value).toBeDefined();
  if (!value) { throw new Error('Expected synthetic event lease'); }
  return value;
}

async function expire(id: string): Promise<void> {
  await migrator.query(`UPDATE foundation.outbox_events
    SET lease_expires_at=clock_timestamp() - INTERVAL '1 second' WHERE id=$1`, [id]);
}

async function due(id: string): Promise<void> {
  await migrator.query(`UPDATE foundation.outbox_events
    SET next_attempt_at=clock_timestamp() - INTERVAL '1 second' WHERE id=$1`, [id]);
}

async function databaseNow(): Promise<Date> {
  const result = await migrator.query<{ now: Date }>('SELECT clock_timestamp() AS now');
  const now = result.rows[0]?.now;
  if (!now) { throw new Error('Missing database clock'); }
  return now;
}

function expectReleased(event: EventRow): void {
  expect(event.lease_owner).toBeNull();
  expect(event.lease_expires_at).toBeNull();
}

// Test-only command/effect table: no production business entity or handler is introduced.
async function syntheticCommand(client: Client, commandId: string, eventId: string, fail = false): Promise<boolean> {
  await client.query('BEGIN');
  try {
    const inserted = await client.query(`INSERT INTO outbox_test.command_effects(command_id)
      VALUES ($1) ON CONFLICT (command_id) DO NOTHING RETURNING command_id`, [commandId]);
    if (inserted.rowCount === 0) {
      await client.query('COMMIT');
      return false;
    }
    await client.query(`INSERT INTO foundation.audit_logs(id, operation, correlation_id, details)
      VALUES ($1, 'synthetic.command', $2, '{"synthetic":true}')`, [randomUUID(), commandId]);
    await client.query(`INSERT INTO foundation.outbox_events(id, event_id, event_type, payload)
      VALUES ($1, $2, 'test.synthetic.command', jsonb_build_object('commandId', $3::text))`,
    [randomUUID(), eventId, commandId]);
    if (fail) {
      // A real constraint failure after all three writes must roll the entire transaction back.
      await client.query('INSERT INTO outbox_test.command_effects(command_id) VALUES ($1)', [commandId]);
    }
    await client.query('COMMIT');
    return true;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  }
}

async function commandCounts(commandId: string): Promise<{ effects: number; audits: number; events: number }> {
  const result = await migrator.query<{ effects: number; audits: number; events: number }>(`SELECT
    (SELECT count(*)::integer FROM outbox_test.command_effects WHERE command_id=$1) AS effects,
    (SELECT count(*)::integer FROM foundation.audit_logs WHERE correlation_id=$1) AS audits,
    (SELECT count(*)::integer FROM foundation.outbox_events WHERE payload->>'commandId'=$1::text) AS events`, [commandId]);
  const counts = result.rows[0];
  if (!counts) { throw new Error('Missing synthetic transaction counts'); }
  return counts;
}

describe.runIf(process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1')('real PostgreSQL outbox leases (P01-01.9A)', () => {
  // Set exactly when this run's CREATE DATABASE succeeded (below): the flag plus the
  // strict disposable-name pattern gate the teardown drop to this run's own database.
  let dbCreated = false;

  /** Drops exactly the disposable database this run created, from the maintenance
  * connection, after this run's clients/pools were ended. FORCE handles stragglers. */
  async function dropFixtureDatabase(): Promise<void> {
    if (!dbCreated) { return; }
    if (!/^fixlevelup_p019a_worker_[a-f0-9]{12}$/.test(databaseName)) {
      throw new Error('Refusing to drop a non-fixture database');
    }
    dbCreated = false;
    const target = lab();
    const admin = target ? await target.openMaintenance() : new Client({ host: '127.0.0.1', port: 55432, database: 'postgres', user: 'fixlevelup_dev',
      password: credential(readFileSync(resolve(root, 'infra/dev-postgres/.env'), 'utf8'), 'POSTGRES_PASSWORD'),
      connectionTimeoutMillis: 3000, statement_timeout: 3000, query_timeout: 4000 });
    try {
      if (target) {
        await admin.query('SET ROLE fixlevelup_migrator');
        const dispose = await pinFreshFileDatabase(admin, databaseName);
        await dispose(admin);
      } else {
        await admin.connect();
        await admin.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
      }
    } finally {
      await admin.end().catch(() => undefined);
    }
  }

  beforeAll(async () => {
    // Read ignored credentials only in memory. Never log configs, passwords, URLs or env contents.
    const target = lab();
    const toolingEnv = target ? '' : readFileSync(resolve(root, 'packages/database-tooling/.env'), 'utf8');
    const migratorPassword = target?.migrator.password ?? credential(toolingEnv, 'FIXLEVELUP_MIGRATOR_PASSWORD');
    const runtimePassword = target?.runtime.password ?? credential(toolingEnv, 'FIXLEVELUP_RUNTIME_PASSWORD');
    const admin = target ? await target.openMaintenance() : await connect('fixlevelup_dev',
      credential(readFileSync(resolve(root, 'infra/dev-postgres/.env'), 'utf8'), 'POSTGRES_PASSWORD'), 'postgres');
    if (target) { clients.push(admin); }
    // The name is generated above from a fixed prefix and twelve hexadecimal characters.
    await admin.query(`CREATE DATABASE "${databaseName}" OWNER fixlevelup_migrator TEMPLATE template0`);
    // CREATE is the reuse guard: an existing name is a hard error, so a successful
    // CREATE proves this run owns the disposable database (the flag gates the drop).
    dbCreated = true;
    try {
      if (target) { await admin.query('SET ROLE fixlevelup_migrator'); }
      await admin.query(`REVOKE ALL ON DATABASE "${databaseName}" FROM PUBLIC`);
      await admin.query(`GRANT CONNECT ON DATABASE "${databaseName}" TO fixlevelup_migrator, fixlevelup_runtime`);
      migrator = await connect('fixlevelup_migrator', migratorPassword);
      await migrator.query('REVOKE CREATE ON SCHEMA public FROM PUBLIC');
      // A business worker is admitted only on a complete, reviewed profile.
      for (const migration of authFixtureMigrations) {
        await migrator.query(readFileSync(resolve(root, 'prisma/migrations', migration, 'migration.sql'), 'utf8'));
      }
      await installPinnedMigrationHistory(migrator);
      await migrator.query(`CREATE SCHEMA outbox_test;
        REVOKE ALL ON SCHEMA outbox_test FROM PUBLIC;
        GRANT USAGE ON SCHEMA outbox_test TO fixlevelup_runtime;
        CREATE TABLE outbox_test.command_effects(command_id uuid PRIMARY KEY);
        GRANT SELECT, INSERT ON outbox_test.command_effects TO fixlevelup_runtime`);
      runtime = await connect('fixlevelup_runtime', runtimePassword);
      contender = await connect('fixlevelup_runtime', runtimePassword);
      config = { host: '127.0.0.1', port: 55432, database: databaseName,
        user: 'fixlevelup_runtime', password: runtimePassword };
      // P05-01: the stores/workers are admitted through the launch gate — a real
      // migrator-held witness in this isolated DB pins the admission.
      admission = await admitFixture(migrator, databaseName, 'WORKER');
      first = new OutboxStore(config, admission.authorization);
      stores.push(first);
      second = new OutboxStore(config, admission.authorization);
      stores.push(second);
    } catch (error) {
      // Provisioning failed after CREATE: run the same lifecycle cleanup before rethrowing.
      await Promise.allSettled([
        ...stores.map(async (store) => { await store.close(); }),
        ...clients.map(async (client) => { await client.end(); }),
      ]);
      await dropFixtureDatabase().catch(() => undefined);
      throw error;
    }
  }, 30_000);

  afterAll(async () => {
    // The isolated database created above is dropped by this run's own teardown
    // (exactly that name, after every resource of this run was closed); the
    // development database is never dropped or truncated.
    const stopped = await Promise.allSettled(workers.map(async (worker) => { await worker.onModuleDestroy(); }));
    const closed = await Promise.allSettled(stores.map(async (store) => { await store.close(); }));
    const released = await Promise.allSettled([admission.release()]);
    const ended = await Promise.allSettled(clients.map(async (client) => { await client.end(); }));
    let dropError: Error | undefined;
    try { await dropFixtureDatabase(); } catch (error) {
      dropError = error instanceof Error ? error : new Error(String(error));
    }
    for (const result of [...stopped, ...closed, ...released, ...ended]) {
      if (result.status === 'rejected') { throw new Error('Failed to close an isolated outbox test resource'); }
    }
    if (dropError !== undefined) { throw dropError; }
  });

  it('gives one event to exactly one of two concurrent owners and completes only once', async () => {
    const type = eventType();
    const fixture = await seed(type);
    const owners = [randomUUID(), randomUUID()] as const;
    const before = await databaseNow();
    const claims = await Promise.all([first.claim(owners[0], [type]), second.claim(owners[1], [type])]);
    expect(claims.filter((claim) => claim !== undefined)).toHaveLength(1);
    const winner = leased(claims[0] ?? claims[1]);
    expect(winner).toEqual({ ...fixture, owner: claims[0] ? owners[0] : owners[1], generation: 1n, attemptCount: 1 });
    const active = await row(fixture.id);
    expect(active.status).toBe('PENDING');
    expect(active.attempt_count).toBe(1);
    expect(active.lease_owner).toBe(winner.owner);
    expect(active.lease_generation).toBe('1');
    expect(active.last_error_code).toBeNull();
    const expiry = await migrator.query<{ bounded: boolean }>(`SELECT lease_expires_at >= $2::timestamptz + INTERVAL '30 seconds'
      AND lease_expires_at <= clock_timestamp() + INTERVAL '30 seconds' AS bounded
      FROM foundation.outbox_events WHERE id=$1`, [fixture.id, before]);
    expect(expiry.rows[0]?.bounded).toBe(true);
    expect(await second.claim(randomUUID(), [type])).toBeUndefined();
    expect(await first.complete(winner)).toBe(true);
    const completed = await row(fixture.id);
    expect(completed.status).toBe('EXPANDED');
    expect(completed.attempt_count).toBe(1);
    expectReleased(completed);
    expect(await second.complete(winner)).toBe(false);
    expect(await first.retry(winner)).toBe(false);
    expect(await first.claim(randomUUID(), [type])).toBeUndefined();
    expect(await row(fixture.id)).toEqual(completed);
  });

  it('skips a row held by another runtime transaction and claims the next available row', async () => {
    const type = eventType();
    const locked = await seed(type, 120);
    const available = await seed(type, 60);
    await runtime.query('BEGIN');
    try {
      await runtime.query('SELECT id FROM foundation.outbox_events WHERE id=$1 FOR UPDATE', [locked.id]);
      const before = await databaseNow();
      const claim = leased(await second.claim(randomUUID(), [type], 45_000));
      expect(claim.id).toBe(available.id);
      expect(claim.attemptCount).toBe(1);
      const expiry = await migrator.query<{ bounded: boolean }>(`SELECT
        lease_expires_at >= $2::timestamptz + INTERVAL '45 seconds'
        AND lease_expires_at <= clock_timestamp() + INTERVAL '45 seconds' AS bounded
        FROM foundation.outbox_events WHERE id=$1`, [available.id, before]);
      expect(expiry.rows[0]?.bounded).toBe(true);
      expect((await row(locked.id)).attempt_count).toBe(0);
      expect(await first.complete(claim)).toBe(true);
    } finally { await runtime.query('ROLLBACK'); }
    const next = leased(await first.claim(randomUUID(), [type]));
    expect(next.id).toBe(locked.id);
    expect(await first.complete(next)).toBe(true);
  });

  it.each(['complete', 'retry'] as const)('%s refuses a lease that expires while waiting for a real row lock', async (operation) => {
    const type = eventType();
    const fixture = await seed(type);
    const claim = leased(await first.claim(randomUUID(), [type]));
    await migrator.query(`UPDATE foundation.outbox_events
      SET lease_expires_at=clock_timestamp() + INTERVAL '500 milliseconds' WHERE id=$1`, [fixture.id]);
    const before = await row(fixture.id);
    await runtime.query('BEGIN');
    let pending: Promise<boolean> | undefined;
    try {
      await runtime.query('SELECT id FROM foundation.outbox_events WHERE id=$1 FOR UPDATE', [fixture.id]);
      const holder = await runtime.query<{ pid: number }>('SELECT pg_backend_pid() AS pid');
      const holderPid = holder.rows[0]?.pid;
      if (!holderPid) { throw new Error('Missing lock-holder backend PID'); }
      pending = first[operation](claim);
      // Observe the real store query under the same runtime role, which can inspect its own sessions.
      // Attach a rejection handler immediately; the assertion below still awaits the original result.
      void pending.catch(() => undefined);
      const deadline = Date.now() + 350;
      let waitingBeforeExpiry = false;
      do {
        const observed = await contender.query<{ waiting: boolean; live: boolean }>(`SELECT
          EXISTS(SELECT 1 FROM pg_stat_activity
            WHERE datname=current_database() AND application_name='fixlevelup-outbox-runtime'
              AND wait_event_type='Lock' AND $2::integer=ANY(pg_blocking_pids(pid))) AS waiting,
          lease_expires_at>clock_timestamp() AS live
          FROM foundation.outbox_events WHERE id=$1`, [fixture.id, holderPid]);
        const activity = observed.rows[0];
        if (activity?.waiting && activity.live) { waitingBeforeExpiry = true; break; }
        await new Promise<void>((resolve) => { setTimeout(resolve, 10); });
      } while (Date.now() < deadline);
      expect(waitingBeforeExpiry).toBe(true);
      // This single short database wait advances past expiry without exceeding the store's 1s lock timeout.
      await migrator.query('SELECT pg_sleep(0.55)');
      await runtime.query('COMMIT');
      expect(await pending).toBe(false);
      expect(await row(fixture.id)).toEqual(before);
    } finally {
      await runtime.query('ROLLBACK');
      if (pending) { await Promise.allSettled([pending]); }
    }
  });

  it('refuses expired completion/retry before takeover, then fences old owners and generations', async () => {
    const type = eventType();
    const fixture = await seed(type);
    const original = leased(await first.claim(randomUUID(), [type]));
    await expire(fixture.id);
    const expired = await row(fixture.id);
    expect(await first.complete(original)).toBe(false);
    expect(await first.retry(original)).toBe(false);
    expect(await row(fixture.id)).toEqual(expired);
    const current = leased(await second.claim(randomUUID(), [type]));
    expect(current).toEqual({ ...fixture, owner: current.owner, generation: 2n, attemptCount: 2 });
    expect(current.owner).not.toBe(original.owner);
    const active = await row(fixture.id);
    for (const invalid of [
      original,
      { ...current, owner: original.owner },
      { ...current, generation: original.generation },
      { ...current, id: randomUUID() },
    ]) {
      expect(await first.complete(invalid)).toBe(false);
      expect(await first.retry(invalid)).toBe(false);
      expect(await row(fixture.id)).toEqual(active);
    }
    expect(await second.complete(current)).toBe(true);
    const completed = await row(fixture.id);
    expect(completed.status).toBe('EXPANDED');
    expect(completed.attempt_count).toBe(2);
    expect(completed.lease_generation).toBe('2');
    expectReleased(completed);
  });

  it('increments the fence even when the same owner reclaims its expired lease', async () => {
    const type = eventType();
    const fixture = await seed(type);
    const owner = randomUUID();
    const old = leased(await first.claim(owner, [type]));
    await expire(fixture.id);
    const current = leased(await second.claim(owner, [type]));
    expect(current.generation).toBe(old.generation + 1n);
    expect(current.attemptCount).toBe(2);
    expect(await first.complete(old)).toBe(false);
    expect(await first.retry(old)).toBe(false);
    expect(await second.complete(current)).toBe(true);
  });

  it('schedules database-time exponential retries at 1s/2s and fails at the third attempt', async () => {
    const type = eventType();
    const fixture = await seed(type);
    for (let attempt = 1; attempt <= 3; attempt++) {
      const claim = leased(await first.claim(randomUUID(), [type]));
      expect(claim.attemptCount).toBe(attempt);
      expect(claim.generation).toBe(BigInt(attempt));
      const before = await databaseNow();
      expect(await first.retry(claim)).toBe(true);
      const retried = await row(fixture.id);
      expect(retried.attempt_count).toBe(attempt);
      expectReleased(retried);
      if (attempt < 3) {
        expect(retried.status).toBe('PENDING');
        expect(retried.last_error_code).toBe('HANDLER_FAILED');
        const delayMs = 1000 * 2 ** (attempt - 1);
        const schedule = await migrator.query<{ bounded: boolean }>(`SELECT
          next_attempt_at >= $2::timestamptz + $3::integer * INTERVAL '1 millisecond'
          AND next_attempt_at <= clock_timestamp() + $3::integer * INTERVAL '1 millisecond' AS bounded
          FROM foundation.outbox_events WHERE id=$1`, [fixture.id, before, delayMs]);
        expect(schedule.rows[0]?.bounded).toBe(true);
        expect(await second.claim(randomUUID(), [type])).toBeUndefined();
        expect(await row(fixture.id)).toEqual(retried);
        await due(fixture.id);
      } else {
        expect(retried.status).toBe('FAILED');
        expect(retried.last_error_code).toBe('ATTEMPTS_EXHAUSTED');
        await due(fixture.id);
        const terminal = await row(fixture.id);
        expect(await second.claim(randomUUID(), [type])).toBeUndefined();
        expect(await first.retry(claim)).toBe(false);
        expect(await first.complete(claim)).toBe(false);
        expect(await row(fixture.id)).toEqual(terminal);
      }
    }
  });

  it('recovers a crashed final attempt to terminal FAILED on a later claim call', async () => {
    const type = eventType();
    const fixture = await seed(type);
    let last: OutboxLease | undefined;
    for (let attempt = 1; attempt <= 3; attempt++) {
      last = leased(await first.claim(randomUUID(), [type]));
      expect(last.attemptCount).toBe(attempt);
      expect(last.generation).toBe(BigInt(attempt));
      const live = await row(fixture.id);
      expect(live.status).toBe('PENDING');
      expect(await second.claim(randomUUID(), [type])).toBeUndefined();
      expect(await row(fixture.id)).toEqual(live);
      await expire(fixture.id);
    }
    expect(await second.claim(randomUUID(), [type])).toBeUndefined();
    const terminal = await row(fixture.id);
    expect(terminal.status).toBe('FAILED');
    expect(terminal.attempt_count).toBe(3);
    expect(terminal.lease_generation).toBe('3');
    expect(terminal.last_error_code).toBe('ATTEMPTS_EXHAUSTED');
    expectReleased(terminal);
    expect(await first.complete(leased(last))).toBe(false);
    expect(await first.retry(leased(last))).toBe(false);
    expect(await first.claim(randomUUID(), [type])).toBeUndefined();
    expect(await row(fixture.id)).toEqual(terminal);
  });

  it('leaves not-due, unsupported and already terminal events unchanged', async () => {
    const supported = eventType();
    const unsupported = await seed(eventType());
    const notDue = await seed(supported);
    const expanded = await seed(supported);
    const failed = await seed(supported);
    await migrator.query(`UPDATE foundation.outbox_events SET next_attempt_at=clock_timestamp() + INTERVAL '1 day' WHERE id=$1`, [notDue.id]);
    await migrator.query("UPDATE foundation.outbox_events SET status='EXPANDED' WHERE id=$1", [expanded.id]);
    await migrator.query("UPDATE foundation.outbox_events SET status='FAILED', last_error_code='ATTEMPTS_EXHAUSTED' WHERE id=$1", [failed.id]);
    const fixtures = [unsupported, notDue, expanded, failed];
    const before: EventRow[] = [];
    for (const fixture of fixtures) { before.push(await row(fixture.id)); }
    expect(await first.claim(randomUUID(), [supported])).toBeUndefined();
    const after: EventRow[] = [];
    for (const fixture of fixtures) { after.push(await row(fixture.id)); }
    expect(after).toEqual(before);
  });

  it('does not mutate any rows when the handler event-type list is empty', async () => {
    const type = eventType();
    const fresh = await seed(type);
    const expiredFinal = await seed(type);
    await migrator.query(`UPDATE foundation.outbox_events SET attempt_count=3, lease_generation=3,
      lease_owner=$2, lease_expires_at=clock_timestamp() - INTERVAL '1 second' WHERE id=$1`, [expiredFinal.id, randomUUID()]);
    const before = await migrator.query<EventRow>('SELECT * FROM foundation.outbox_events ORDER BY id');
    const noHandlers: readonly string[] = [];
    expect(await first.claim(randomUUID(), noHandlers)).toBeUndefined();
    const after = await migrator.query<EventRow>('SELECT * FROM foundation.outbox_events ORDER BY id');
    expect(after.rows).toEqual(before.rows);
    expect((await row(fresh.id)).attempt_count).toBe(0);
    expect((await row(expiredFinal.id)).status).toBe('PENDING');
  });

  it('runs the production worker with no handlers without claiming or changing events and clears its timer', async () => {
    const fixture = await seed(eventType());
    const before = await row(fixture.id);
    const allBefore = await migrator.query<EventRow>('SELECT * FROM foundation.outbox_events ORDER BY id');
    const logger = new SafeLogger('worker');
    const log = vi.spyOn(logger, 'event').mockImplementation(() => undefined);
    const scheduled = vi.spyOn(globalThis, 'setTimeout');
    const cleared = vi.spyOn(globalThis, 'clearTimeout');
    const close = vi.spyOn(OutboxStore.prototype, 'close');
    const worker = new OutboxWorker(config, logger, new Map(), admission.authorization);
    workers.push(worker);
    try {
      await worker.runOnce();
      // Capture before further SQL adds driver timeouts: this is the worker's scheduled poll.
      expect(scheduled.mock.calls.at(-1)?.[1]).toBe(1000);
      const timer = scheduled.mock.results.at(-1)?.value as ReturnType<typeof setTimeout> | undefined;
      expect(timer).toBeDefined();
      expect(await row(fixture.id)).toEqual(before);
      const allAfter = await migrator.query<EventRow>('SELECT * FROM foundation.outbox_events ORDER BY id');
      expect(allAfter.rows).toEqual(allBefore.rows);
      expect(log).not.toHaveBeenCalledWith('outbox_unavailable');
      await worker.onModuleDestroy();
      expect(cleared).toHaveBeenCalledWith(timer);
      expect(close).toHaveBeenCalledTimes(1);
      await worker.runOnce();
      expect(await row(fixture.id)).toEqual(before);
    } finally {
      await worker.onModuleDestroy();
      close.mockRestore();
      cleared.mockRestore();
      scheduled.mockRestore();
      log.mockRestore();
    }
  });

  it.each(['metadata', 'lease migration'] as const)('requires real database readiness (%s) before invoking an injected handler', async (missing) => {
    const type = eventType();
    const fixture = await seed(type);
    const before = await row(fixture.id);
    const handler = vi.fn<(lease: OutboxLease, signal: AbortSignal) => Promise<void>>(() => Promise.resolve());
    const logger = new SafeLogger('worker');
    const log = vi.spyOn(logger, 'event').mockImplementation(() => undefined);
    const testLaunch = await admitFixture(migrator, databaseName, 'WORKER');
    const worker = new OutboxWorker(config, logger, new Map([[type, handler]]), testLaunch.authorization);
    workers.push(worker);
    const hide = missing === 'metadata'
      ? 'ALTER TABLE foundation._prisma_migrations RENAME TO _prisma_migrations_test_hidden'
      : 'ALTER TABLE foundation.outbox_events RENAME COLUMN lease_generation TO lease_generation_test_hidden';
    const restore = missing === 'metadata'
      ? 'ALTER TABLE foundation._prisma_migrations_test_hidden RENAME TO _prisma_migrations'
      : 'ALTER TABLE foundation.outbox_events RENAME COLUMN lease_generation_test_hidden TO lease_generation';
    await migrator.query(hide);
    try {
      await worker.runOnce();
      expect(handler).not.toHaveBeenCalled();
      expect(log).toHaveBeenCalledWith('outbox_unavailable');
      if (missing === 'metadata') { expect(await row(fixture.id)).toEqual(before); }
    } finally {
      await worker.onModuleDestroy();
      await migrator.query(restore);
      await testLaunch.release();
      log.mockRestore();
    }
    expect(await row(fixture.id)).toEqual(before);
  });

  it('expands an event only after its injected test handler succeeds', async () => {
    const type = eventType();
    const fixture = await seed(type);
    const handler = vi.fn<(lease: OutboxLease, signal: AbortSignal) => Promise<void>>(() => Promise.resolve());
    const worker = new OutboxWorker(config, new SafeLogger('worker'), new Map([[type, handler]]), admission.authorization);
    workers.push(worker);
    try {
      await worker.runOnce();
      expect(handler).toHaveBeenCalledTimes(1);
      const args = handler.mock.calls[0];
      expect(args?.[0]).toMatchObject({ ...fixture, generation: 1n, attemptCount: 1 });
      expect(args?.[1]).toBeInstanceOf(AbortSignal);
      expect(args?.[1].aborted).toBe(false);
      const completed = await row(fixture.id);
      expect(completed.status).toBe('EXPANDED');
      expectReleased(completed);
      await worker.runOnce();
      expect(handler).toHaveBeenCalledTimes(1);
    } finally { await worker.onModuleDestroy(); }
  });

  it('stores only HANDLER_FAILED for a thrown test-handler error and does not print its canary', async () => {
    const type = eventType();
    const fixture = await seed(type);
    const canary = `synthetic-handler-error-${randomUUID()}`;
    const handler = vi.fn((): Promise<void> => Promise.reject(new Error(canary)));
    const output = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const errors = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const worker = new OutboxWorker(config, new SafeLogger('worker'), new Map([[type, handler]]), admission.authorization);
    workers.push(worker);
    try {
      await worker.runOnce();
      expect(handler).toHaveBeenCalledTimes(1);
      const retried = await row(fixture.id);
      expect(retried.status).toBe('PENDING');
      expect(retried.attempt_count).toBe(1);
      expect(retried.last_error_code).toBe('HANDLER_FAILED');
      expectReleased(retried);
      expect(JSON.stringify(retried)).not.toContain(canary);
      expect(JSON.stringify([...output.mock.calls, ...errors.mock.calls])).not.toContain(canary);
    } finally {
      await worker.onModuleDestroy();
      errors.mockRestore();
      output.mockRestore();
    }
  });

  it('aborts and waits for an active handler at shutdown, preserving its lease for later recovery', async () => {
    const type = eventType();
    const fixture = await seed(type);
    let enter: (() => void) | undefined;
    const entered = new Promise<void>((resolve) => { enter = resolve; });
    let observedSignal: AbortSignal | undefined;
    let handlerFinished = false;
    const handler = vi.fn(async (lease: OutboxLease, signal: AbortSignal): Promise<void> => {
      expect(lease.id).toBe(fixture.id);
      observedSignal = signal;
      enter?.();
      await new Promise<void>((resolve) => {
        if (signal.aborted) { resolve(); }
        else { signal.addEventListener('abort', () => { resolve(); }, { once: true }); }
      });
      handlerFinished = true;
    });
    const close = vi.spyOn(OutboxStore.prototype, 'close');
    const worker = new OutboxWorker(config, new SafeLogger('worker'), new Map([[type, handler]]), admission.authorization);
    workers.push(worker);
    const pending = worker.runOnce();
    try {
      // If readiness fails, runOnce resolves instead; fail promptly without waiting forever for entry.
      await Promise.race([entered, pending]);
      expect(handler).toHaveBeenCalledTimes(1);
      expect(observedSignal?.aborted).toBe(false);
      const active = await row(fixture.id);
      expect(active.status).toBe('PENDING');
      expect(active.attempt_count).toBe(1);
      expect(active.lease_owner).not.toBeNull();
      await worker.onModuleDestroy();
      await pending;
      expect(observedSignal?.aborted).toBe(true);
      expect(handlerFinished).toBe(true);
      expect(close).toHaveBeenCalledTimes(1);
      expect(await row(fixture.id)).toEqual(active);
      await worker.runOnce();
      expect(handler).toHaveBeenCalledTimes(1);
      expect(await row(fixture.id)).toEqual(active);
      await expire(fixture.id);
      const recovered = leased(await second.claim(randomUUID(), [type]));
      expect(recovered.attemptCount).toBe(2);
      expect(recovered.generation).toBe(2n);
      expect(recovered.owner).not.toBe(active.lease_owner);
      expect(await second.complete(recovered)).toBe(true);
    } finally {
      await worker.onModuleDestroy();
      close.mockRestore();
    }
  });

  it('commits exactly one synthetic effect, audit and outbox event for concurrent duplicate commands', async () => {
    const commandId = randomUUID();
    const results = await Promise.all([
      syntheticCommand(runtime, commandId, randomUUID()),
      syntheticCommand(contender, commandId, randomUUID()),
    ]);
    expect(results.sort()).toEqual([false, true]);
    expect(await commandCounts(commandId)).toEqual({ effects: 1, audits: 1, events: 1 });
    expect(await syntheticCommand(runtime, commandId, randomUUID())).toBe(false);
    expect(await commandCounts(commandId)).toEqual({ effects: 1, audits: 1, events: 1 });
  });

  it('rolls back synthetic effect, audit and outbox together and permits a clean retry', async () => {
    const commandId = randomUUID();
    const eventId = randomUUID();
    await expect(syntheticCommand(runtime, commandId, eventId, true)).rejects.toMatchObject({ code: '23505' });
    expect(await commandCounts(commandId)).toEqual({ effects: 0, audits: 0, events: 0 });
    expect(await syntheticCommand(runtime, commandId, eventId)).toBe(true);
    expect(await commandCounts(commandId)).toEqual({ effects: 1, audits: 1, events: 1 });
  });
});
