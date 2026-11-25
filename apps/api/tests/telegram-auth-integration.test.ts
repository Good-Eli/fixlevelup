import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Client, Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { verifyInitData } from '../src/auth/telegram-initdata.js';
import { TelegramAuthError, TelegramAuthService } from '../src/auth/telegram-auth.service.js';
import { becomeOwner, dropOwnedTestDatabase, fixtureCredentials, maintenanceOpener } from './owned-test-database.js';

// Explicit opt-in only: create a random database, never alter or drop the dev database.
const integration = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1' ? describe : describe.skip;
const root = resolve(import.meta.dirname, '../../..');
const botToken = `7000000001:${'A'.repeat(43)}`;
const migrations = [
  '20261120000100_technical_audit_outbox',
  '20261120000200_technical_outbox_attempts',
  '20261120000300_technical_outbox_leases',
  '20261120000400_staff_identity',
  '20261120000500_web_auth',
  '20261120000600_authorization',
  '20261120000700_staff_telegram_auth',
];
const digestOf = (token: string) => createHash('sha256').update(token).digest('hex');
const connection = { host: '127.0.0.1', port: 55432 };
const telegramUserId = '279058397';
// auth_date has one-second resolution, so two calls in the same second would otherwise
// produce an identical digest and turn an intended "new exchange" into a grace replay.
// A per-call query_id keeps every call a distinct digest; tests that need a stable digest
// for replay capture one raw string and reuse it.
let initDataSequence = 0;
const signedInitData = (userId: number = 279058397): string => {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const user = JSON.stringify({ id: userId, first_name: 'Synthetic', username: 'synthetic_master' });
  const queryId = `AAH${String(++initDataSequence).padStart(6, '0')}`;
  const pairs: [string, string][] = [['user', user], ['auth_date', String(nowSeconds)], ['query_id', queryId]];
  const dcs = pairs.slice().sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([k, v]) => `${k}=${v}`).join('\n');
  const hash = createHmac('sha256', createHmac('sha256', 'WebAppData').update(botToken).digest()).update(dcs).digest('hex');
  const all: [string, string][] = [...pairs, ['hash', hash]];
  return all.map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
};

async function waitFor(what: string, check: () => Promise<boolean>, timeoutMs = 4000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!(await check())) {
    if (Date.now() >= deadline) { throw new Error(`Timed out waiting for ${what}`); }
    await new Promise((resolve) => { setTimeout(resolve, 25); });
  }
}

integration('telegram staff authentication against isolated PostgreSQL', () => {
  let admin: Client | undefined;
  let fixture: Client;
  let runtime: Pool;
  const clients: Client[] = [];
  const pools: Pool[] = [];
  let service: TelegramAuthService;
  let staffId: string;
  let migratorAccess: { database: string; user: 'fixlevelup_migrator'; password: string } | undefined;
  let sourceSequence = 0;
  const source = () => `synthetic-source-${String(++sourceSequence)}`;
  let dbName: string | undefined;
  let dbCreated = false;
  let tornDown = false;

  /** Ownership proof for the teardown drop, consumed exactly once: this run's CREATE
   * result (flag) AND the strict disposable-name pattern. */
  const takeOwnedDatabase = (): string | undefined => {
    if (!dbCreated) { return undefined; }
    dbCreated = false;
    return dbName !== undefined && /^fixlevelup_tg_auth_test_[a-f0-9]{24}$/.test(dbName) ? dbName : undefined;
  };

  /** The afterAll teardown, exactly once: this run's pools/clients down first, then
   * the drop of exactly the database this run created. A second call is a no-op. */
  async function teardown(): Promise<void> {
    if (tornDown) { return; }
    tornDown = true;
    const ownedDatabase = takeOwnedDatabase();
    try {
      await Promise.all(pools.map((pool) => pool.end()));
      await Promise.all(clients.map((client) => client.end()));
    } finally {
      try {
        if (ownedDatabase !== undefined && admin !== undefined) {
          await dropOwnedTestDatabase(admin, ownedDatabase);
        }
      } finally {
        await admin?.end();
      }
    }
  }

  beforeAll(async () => {
    // Lab mode reads the lab process env and the attested maintenance binding;
    // dev mode reads the local ignored env files. Never the dev database.
    const { migrator: migratorPassword, runtime: runtimePassword } = fixtureCredentials();
    admin = await maintenanceOpener()();
    const database = `fixlevelup_tg_auth_test_${randomBytes(12).toString('hex')}`;
    migratorAccess = { database, user: 'fixlevelup_migrator', password: migratorPassword };
    try {
      await admin.query(`CREATE DATABASE "${database}" OWNER fixlevelup_migrator TEMPLATE template0`);
      // CREATE is the reuse guard: an existing name is a hard error, so a successful
      // CREATE proves this run owns the disposable database (the flag gates the drop).
      dbName = database;
      dbCreated = true;
      // GRANT/REVOKE need the owner: in the lab the orchestrator is a NOINHERIT member.
      await becomeOwner(admin);
      await admin.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`);
      await admin.query(`GRANT CONNECT ON DATABASE "${database}" TO fixlevelup_migrator, fixlevelup_runtime`);
      fixture = new Client({ ...connection, database, user: 'fixlevelup_migrator', password: migratorPassword });
      clients.push(fixture);
      await fixture.connect();
      await fixture.query('CREATE SCHEMA foundation AUTHORIZATION fixlevelup_migrator');
      for (const migration of migrations) {
        await fixture.query(readFileSync(resolve(root, 'prisma/migrations', migration, 'migration.sql'), 'utf8'));
      }
      runtime = new Pool({ ...connection, database, user: 'fixlevelup_runtime', password: runtimePassword });
      pools.push(runtime);
      // Synthetic staff rows: the link INSERT flow is outside P02-05 (migration grants
      // only SELECT/UPDATE on links to the runtime role).
      staffId = randomUUID();
      await fixture.query("INSERT INTO foundation.staff (id, role, employment_state, auth_version) VALUES ($1, 'TECHNICIAN', 'ACTIVE', 0)", [staffId]);
      await fixture.query('INSERT INTO foundation.staff_telegram_links (id, staff_id, telegram_user_id) VALUES ($1, $2, $3::bigint)', [randomUUID(), staffId, telegramUserId]);
      service = new TelegramAuthService(runtime, { botToken, throttleSecret: randomBytes(32) });
    } catch (error) {
      // Provisioning failed after CREATE: run the same lifecycle cleanup before rethrowing.
      await teardown().catch(() => undefined);
      throw error;
    }
  }, 30000);

  beforeEach(async () => {
    await fixture.query('DELETE FROM foundation.web_sessions');
    await fixture.query('DELETE FROM foundation.web_auth_attempts');
    await fixture.query('DELETE FROM foundation.web_auth_throttles');
  });

  afterAll(teardown);

  it('exchanges valid initData for a TECHNICIAN session stored with the digest', async () => {
    const credential = await service.exchange(signedInitData(), source());
    expect(credential).toMatchObject({ staffId, role: 'TECHNICIAN', authVersion: 0, telegramUserId });
    const row = await fixture.query<{ channel: string; initdata_digest: string }>(
      'SELECT channel, initdata_digest FROM foundation.web_sessions WHERE token_hash = $1', [digestOf(credential.token)]);
    expect(row.rows[0]).toMatchObject({ channel: 'STAFF_TELEGRAM' });
    const identity = await service.authenticate(credential.token);
    expect(identity).toMatchObject({ staffId, role: 'TECHNICIAN', telegramUserId });
  }, 30000);

  it('replays the same initData within grace: same session row, rotated token, absolute TTL unchanged', async () => {
    // One raw string for every call: signedInitData() embeds auth_date with one-second
    // resolution, so calling it repeatedly can straddle a second boundary and produce a
    // different digest — that would make this a second exchange instead of a grace replay.
    const raw = signedInitData();
    const first = await service.exchange(raw, source());
    const second = await service.exchange(raw, source());
    expect(second.staffId).toBe(first.staffId);
    expect(second.token).not.toBe(first.token);
    const rows = await fixture.query<{ token_hash: string }>(
      'SELECT token_hash FROM foundation.web_sessions WHERE initdata_digest = $1',
      [verifyInitData(raw, botToken).digest]);
    expect(rows.rowCount).toBe(1);
    expect(rows.rows[0]?.token_hash).toBe(digestOf(second.token));
    expect(second.absoluteExpiresAt).toEqual(first.absoluteExpiresAt);
    await expect(service.authenticate(first.token)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect(await service.authenticate(second.token)).toMatchObject({ staffId });
  }, 30000);

  it('denies replay after the 60-second grace window', async () => {
    const raw = signedInitData();
    const first = await service.exchange(raw, source());
    await fixture.query("UPDATE foundation.web_sessions SET initdata_exchanged_at = initdata_exchanged_at - interval '61 seconds', created_at = created_at - interval '61 seconds' WHERE token_hash = $1", [digestOf(first.token)]);
    await expect(service.exchange(raw, source())).rejects.toMatchObject({ code: 'REPLAY' });
  }, 30000);

  it('denies replay of a revoked digest even within grace', async () => {
    const raw = signedInitData();
    const first = await service.exchange(raw, source());
    await fixture.query('UPDATE foundation.web_sessions SET revoked_at = clock_timestamp() WHERE token_hash = $1', [digestOf(first.token)]);
    await expect(service.exchange(raw, source())).rejects.toMatchObject({ code: 'REPLAY' });
  }, 30000);

  it('serializes simultaneous exchanges of one digest into one session with two rotated tokens', async () => {
    const raw = signedInitData();
    const results = await Promise.allSettled([service.exchange(raw, source()), service.exchange(raw, source())]);
    const fulfilled = results.filter((result) => result.status === 'fulfilled').map((result) => (result as PromiseFulfilledResult<{ token: string }>).value);
    expect(fulfilled).toHaveLength(2);
    const rows = await fixture.query<{ token_hash: string }>(
      'SELECT token_hash FROM foundation.web_sessions WHERE initdata_digest = $1',
      [verifyInitData(raw, botToken).digest]);
    expect(rows.rowCount).toBe(1);
    const stored = rows.rows[0];
    const winner = fulfilled.at(-1);
    if (!stored || !winner) { throw new Error('expected one stored session and a winner'); }
    expect(stored.token_hash).toBe(digestOf(winner.token));
  }, 30000);

  it('rejects unknown, unlinked, inactive and non-technician identities', async () => {
    // Unknown Telegram user: never auto-registered.
    const unknownUser = JSON.stringify({ id: 900000001 });
    const nowSeconds = Math.floor(Date.now() / 1000);
    const signUnknown = (): string => {
      const dcs = `auth_date=${String(nowSeconds)}\nuser=${unknownUser}`;
      const hash = createHmac('sha256', createHmac('sha256', 'WebAppData').update(botToken).digest()).update(dcs).digest('hex');
      return `user=${encodeURIComponent(unknownUser)}&auth_date=${String(nowSeconds)}&hash=${hash}`;
    };
    await expect(service.exchange(signUnknown(), source())).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    // Revoked link.
    await fixture.query('UPDATE foundation.staff_telegram_links SET revoked_at = clock_timestamp() WHERE staff_id = $1', [staffId]);
    try {
      await expect(service.exchange(signedInitData(), source())).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    } finally {
      await fixture.query('UPDATE foundation.staff_telegram_links SET revoked_at = NULL WHERE staff_id = $1', [staffId]);
    }
    // Inactive staff.
    try {
      await fixture.query("UPDATE foundation.staff SET employment_state = 'INACTIVE' WHERE id = $1", [staffId]);
      await expect(service.exchange(signedInitData(), source())).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    } finally {
      await fixture.query("UPDATE foundation.staff SET employment_state = 'ACTIVE' WHERE id = $1", [staffId]);
    }
    // Non-technician role: a linked manager must not get a Mini App session.
    try {
      await fixture.query("UPDATE foundation.staff SET role = 'MANAGER' WHERE id = $1", [staffId]);
      await expect(service.exchange(signedInitData(), source())).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    } finally {
      await fixture.query("UPDATE foundation.staff SET role = 'TECHNICIAN' WHERE id = $1", [staffId]);
    }
  }, 30000);

  it('rejects forged and expired initData before any database access', async () => {
    const invalid = 'user=x&auth_date=1&hash=not-hex';
    await expect(service.exchange(invalid, source())).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const stale = (() => {
      const oldSeconds = Math.floor(Date.now() / 1000) - 86401;
      const user = JSON.stringify({ id: Number(telegramUserId) });
      const dcs = `auth_date=${String(oldSeconds)}\nuser=${user}`;
      const hash = createHmac('sha256', createHmac('sha256', 'WebAppData').update(botToken).digest()).update(dcs).digest('hex');
      return `user=${encodeURIComponent(user)}&auth_date=${String(oldSeconds)}&hash=${hash}`;
    })();
    await expect(service.exchange(stale, source())).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    const rows = await fixture.query<{ count: number }>('SELECT count(*)::int AS count FROM foundation.web_sessions');
    expect(rows.rows[0]?.count).toBe(0);
    const attempts = await fixture.query<{ count: number }>('SELECT count(*)::int AS count FROM foundation.web_auth_attempts');
    expect(attempts.rows[0]?.count).toBe(0);
  }, 30000);

  it('bounds repeated failed exchanges by telegram-user throttle buckets', async () => {
    // Unknown Telegram users fail after the throttle reservation, consuming buckets.
    const fixedSource = source();
    for (let i = 0; i < 5; i++) {
      await expect(service.exchange(signedInitData(900000001), fixedSource)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    }
    await expect(service.exchange(signedInitData(900000001), fixedSource)).rejects.toMatchObject({ code: 'RATE_LIMITED' });
    // A different user from the same source is unaffected until the source limit.
    await expect(service.exchange(signedInitData(), fixedSource)).resolves.toMatchObject({ staffId });
  }, 30000);

  it('expires idle and absolute TTLs, rejects revoked sessions and unknown tokens', async () => {
    const credential = await service.exchange(signedInitData(), source());
    await fixture.query(
      "UPDATE foundation.web_sessions SET created_at = clock_timestamp() - interval '3 hours', idle_expires_at = clock_timestamp() - interval '2 hours', absolute_expires_at = clock_timestamp() - interval '1 hour' WHERE token_hash = $1",
      [digestOf(credential.token)]);
    await expect(service.authenticate(credential.token)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    await expect(service.authenticate('x'.repeat(43))).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    const fresh = await service.exchange(signedInitData(), source());
    await fixture.query(
      "UPDATE foundation.web_sessions SET created_at = clock_timestamp() - interval '25 hours', idle_expires_at = clock_timestamp() - interval '24 hours', absolute_expires_at = clock_timestamp() - interval '23 hours' WHERE token_hash = $1",
      [digestOf(fresh.token)]);
    await expect(service.authenticate(fresh.token)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    const active = await service.exchange(signedInitData(), source());
    await fixture.query('UPDATE foundation.web_sessions SET revoked_at = clock_timestamp() WHERE token_hash = $1', [digestOf(active.token)]);
    await expect(service.authenticate(active.token)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  }, 30000);

  it('keeps a web CRM session untouched by the telegram channel checks', async () => {
    const webToken = 'w'.repeat(43);
    await fixture.query(
      `INSERT INTO foundation.web_sessions (id, staff_id, token_hash, auth_version, created_at, idle_expires_at, absolute_expires_at)
       VALUES ($1, $2, $3, 0, clock_timestamp(), clock_timestamp() + interval '30 minutes', clock_timestamp() + interval '12 hours')`,
      [randomUUID(), staffId, digestOf(webToken)]);
    // The Telegram boundary never authenticates a CRM cookie session token.
    await expect(service.authenticate(webToken)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  }, 30000);

  it('rejects construction with unsafe options', () => {
    expect(() => new TelegramAuthService(runtime, { botToken: 'short', throttleSecret: randomBytes(32) })).toThrow(TelegramAuthError);
    expect(() => new TelegramAuthService(runtime, { botToken, throttleSecret: 'tiny' })).toThrow(TelegramAuthError);
    expect(() => new TelegramAuthService(runtime, { botToken, throttleSecret: randomBytes(32), sourceLimit: 1 })).toThrow(TelegramAuthError);
  }, 30000);

  // P02-05 hotfix regression: a session is pinned to the exact staff_telegram_links row
  // (telegram_link_id). Re-binding the staff member to another Telegram identity must kill
  // the old session and must not let the grace window resurrect it; only the new link
  // carries a working session, and revoking that link kills it the same way.
  it('pins the session to its exact link: re-bind kills the old session and only the new link works', async () => {
    const rebindStaffId = randomUUID();
    const linkA = randomUUID();
    const linkB = randomUUID();
    const userA = 700000101;
    const userB = 700000102;
    await fixture.query("INSERT INTO foundation.staff (id, role, employment_state, auth_version) VALUES ($1, 'TECHNICIAN', 'ACTIVE', 0)", [rebindStaffId]);
    await fixture.query('INSERT INTO foundation.staff_telegram_links (id, staff_id, telegram_user_id) VALUES ($1, $2, $3::bigint)', [linkA, rebindStaffId, userA]);
    // Session A on link A.
    const rawA = signedInitData(userA);
    const sessionA = await service.exchange(rawA, source());
    expect(sessionA).toMatchObject({ staffId: rebindStaffId, telegramUserId: String(userA) });
    expect(await service.authenticate(sessionA.token)).toMatchObject({ staffId: rebindStaffId });
    // Re-bind in one transaction: the partial unique active-per-staff index requires the
    // revoke of A and the insert of B to commit together.
    await fixture.query('BEGIN');
    await fixture.query('UPDATE foundation.staff_telegram_links SET revoked_at = clock_timestamp() WHERE id = $1', [linkA]);
    await fixture.query('INSERT INTO foundation.staff_telegram_links (id, staff_id, telegram_user_id) VALUES ($1, $2, $3::bigint)', [linkB, rebindStaffId, userB]);
    await fixture.query('COMMIT');
    // The staff member still has an active link, but the old session stays pinned to the
    // revoked link A: the active link B must not silently carry it.
    const active = await fixture.query<{ count: number }>(
      'SELECT count(*)::int AS count FROM foundation.staff_telegram_links WHERE staff_id = $1 AND revoked_at IS NULL', [rebindStaffId]);
    expect(active.rows[0]?.count).toBe(1);
    const storedA = await fixture.query<{ revoked_at: Date | null; telegram_link_id: string }>(
      'SELECT revoked_at, telegram_link_id FROM foundation.web_sessions WHERE initdata_digest = $1',
      [verifyInitData(rawA, botToken).digest]);
    expect(storedA.rowCount).toBe(1);
    expect(storedA.rows[0]?.revoked_at).toBeNull();
    expect(storedA.rows[0]?.telegram_link_id).toBe(linkA);
    await expect(service.authenticate(sessionA.token)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    // Replaying the old initData inside the grace window must not mint a session either.
    await expect(service.exchange(rawA, source())).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    const digestRows = await fixture.query<{ count: number }>(
      'SELECT count(*)::int AS count FROM foundation.web_sessions WHERE initdata_digest = $1', [verifyInitData(rawA, botToken).digest]);
    expect(digestRows.rows[0]?.count).toBe(1);
    const staffSessions = await fixture.query<{ count: number }>(
      'SELECT count(*)::int AS count FROM foundation.web_sessions WHERE staff_id = $1', [rebindStaffId]);
    expect(staffSessions.rows[0]?.count).toBe(1);
    // Fresh initData B exchanges into a new session pinned to link B and keeps working
    // while B is active.
    const sessionB = await service.exchange(signedInitData(userB), source());
    expect(sessionB).toMatchObject({ staffId: rebindStaffId, telegramUserId: String(userB) });
    const storedB = await fixture.query<{ telegram_link_id: string }>(
      'SELECT telegram_link_id FROM foundation.web_sessions WHERE token_hash = $1', [digestOf(sessionB.token)]);
    expect(storedB.rows[0]?.telegram_link_id).toBe(linkB);
    expect(await service.authenticate(sessionB.token)).toMatchObject({ staffId: rebindStaffId, telegramUserId: String(userB) });
    expect(await service.authenticate(sessionB.token)).toMatchObject({ staffId: rebindStaffId, telegramUserId: String(userB) });
    // Revoking link B kills session B exactly like revoking A killed session A.
    await fixture.query('UPDATE foundation.staff_telegram_links SET revoked_at = clock_timestamp() WHERE id = $1', [linkB]);
    await expect(service.authenticate(sessionB.token)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  }, 30000);

  // P02-05 hotfix regression (concurrency, real PostgreSQL): the in-flight exchange holds
  // the staff row lock and the link row lock (taken in staff->link order), so a parallel
  // rebind revoke (same staff->link order) queues behind it and lands only after the
  // exchange commits; the freshly committed session then dies with its revoked link. No
  // deadlock is possible: the exchange waits only on the fixture gate (released first),
  // the revoke waits only on the exchange's staff lock, and the bare link UPDATE waits
  // only on the exchange's link lock.
  it('serializes a concurrent link revoke behind the in-flight exchange holding staff and link locks', async () => {
    if (!migratorAccess) { throw new Error('Local isolated PostgreSQL test credentials are required'); }
    const concurrentStaffId = randomUUID();
    const linkId = randomUUID();
    await fixture.query("INSERT INTO foundation.staff (id, role, employment_state, auth_version) VALUES ($1, 'TECHNICIAN', 'ACTIVE', 0)", [concurrentStaffId]);
    await fixture.query('INSERT INTO foundation.staff_telegram_links (id, staff_id, telegram_user_id) VALUES ($1, $2, $3::bigint)', [linkId, concurrentStaffId, 700000103]);
    const gate = new Client({ ...connection, ...migratorAccess });
    const revoker = new Client({ ...connection, ...migratorAccess });
    const linkUpdater = new Client({ ...connection, ...migratorAccess });
    await gate.connect();
    await revoker.connect();
    await linkUpdater.connect();
    try {
      // Park the exchange on the session INSERT: by then it already holds the staff row
      // lock and the link row lock.
      await gate.query('BEGIN');
      await gate.query('LOCK TABLE foundation.web_sessions IN EXCLUSIVE MODE');
      const exchanged = service.exchange(signedInitData(700000103), source());
      void exchanged.catch(() => undefined);
      await waitFor('the exchange to block on the session insert after taking the staff and link locks', async () => {
        const blocked = await fixture.query<{ count: number }>(
          `SELECT count(*)::int AS count FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
           WHERE a.datname = current_database() AND a.usename = 'fixlevelup_runtime'
             AND l.relation = 'foundation.web_sessions'::regclass AND NOT l.granted`);
        return (blocked.rows[0]?.count ?? 0) > 0;
      });
      // The concurrent rebind revoke: staff row first, then the link row — the same
      // staff->link order the exchange uses. It queues on the staff lock and waits.
      const revokerPid = (await revoker.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid ?? 0;
      const revoked = revoker.query(`
        BEGIN;
        SELECT id FROM foundation.staff WHERE id = '${concurrentStaffId}' FOR UPDATE;
        UPDATE foundation.staff_telegram_links SET revoked_at = clock_timestamp() WHERE id = '${linkId}' AND revoked_at IS NULL;
        COMMIT;`);
      void revoked.catch(() => undefined);
      await waitFor('the revoke transaction to wait on the staff row lock held by the exchange', async () => {
        const waiting = await fixture.query<{ count: number }>(
          'SELECT count(*)::int AS count FROM pg_locks WHERE pid = $1 AND NOT granted', [revokerPid]);
        return (waiting.rows[0]?.count ?? 0) > 0;
      });
      // A bare link-row UPDATE (no staff lock) queues as well: the link row itself is
      // locked by the exchange, not just the staff row.
      const updaterPid = (await linkUpdater.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid ?? 0;
      const touched = linkUpdater.query(
        `UPDATE foundation.staff_telegram_links SET username = username WHERE id = '${linkId}'`);
      void touched.catch(() => undefined);
      await waitFor('the bare link update to wait on the link row lock held by the exchange', async () => {
        const waiting = await fixture.query<{ count: number }>(
          'SELECT count(*)::int AS count FROM pg_locks WHERE pid = $1 AND NOT granted', [updaterPid]);
        return (waiting.rows[0]?.count ?? 0) > 0;
      });
      // Release the gate: the exchange commits first, then the waiting updates land after
      // it. All three complete without a deadlock (40P01) because the lock order is
      // staff->link everywhere and the gate is released first.
      await gate.query('ROLLBACK');
      const credential = await exchanged;
      await touched;
      await revoked;
      const pinned = await fixture.query<{ telegram_link_id: string }>(
        'SELECT telegram_link_id FROM foundation.web_sessions WHERE token_hash = $1', [digestOf(credential.token)]);
      expect(pinned.rowCount).toBe(1);
      expect(pinned.rows[0]?.telegram_link_id).toBe(linkId);
      const link = await fixture.query<{ revoked_at: Date | null }>(
        'SELECT revoked_at FROM foundation.staff_telegram_links WHERE id = $1', [linkId]);
      expect(link.rows[0]?.revoked_at).not.toBeNull();
      // The committed revoke kills the just-created session on the next authenticate.
      await expect(service.authenticate(credential.token)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    } finally {
      await gate.query('ROLLBACK').catch(() => undefined);
      await gate.end();
      await revoker.end();
      await linkUpdater.end();
    }
  }, 30000);

  // P02-05 hotfix 2 (recheck under lock): a revoke landing between the exchange's
  // initial link lookup and the FOR UPDATE recheck must fail closed — no session row,
  // no credential. The exchange parks on the link lock itself (staff lock already held),
  // the revoke lands while it waits, and the recheck (same id, same staff, same telegram
  // id, still active) refuses to proceed.
  it('refuses the exchange when the link is revoked between the initial lookup and the lock recheck', async () => {
    if (!migratorAccess) { throw new Error('Local isolated PostgreSQL test credentials are required'); }
    const lateStaffId = randomUUID();
    const lateLinkId = randomUUID();
    await fixture.query("INSERT INTO foundation.staff (id, role, employment_state, auth_version) VALUES ($1, 'TECHNICIAN', 'ACTIVE', 0)", [lateStaffId]);
    await fixture.query('INSERT INTO foundation.staff_telegram_links (id, staff_id, telegram_user_id) VALUES ($1, $2, $3::bigint)', [lateLinkId, lateStaffId, 700000104]);
    const staffLocker = new Client({ ...connection, ...migratorAccess });
    const revoker = new Client({ ...connection, ...migratorAccess });
    await staffLocker.connect();
    await revoker.connect();
    try {
      // Hold the staff row lock so the exchange reaches it, takes it, and then hits
      // the link lock held by the revoker's open transaction.
      await staffLocker.query('BEGIN');
      await staffLocker.query("SELECT id FROM foundation.staff WHERE id = $1 FOR UPDATE", [lateStaffId]);
      // Start the exchange: it queues on the staff lock before touching the link.
      const exchanged = service.exchange(signedInitData(700000104), source());
      void exchanged.catch(() => undefined);
      await waitFor('the exchange to wait on the staff row lock', async () => {
        const waiting = await fixture.query<{ count: number }>(
          `SELECT count(*)::int AS count FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
           WHERE a.datname = current_database() AND a.usename = 'fixlevelup_runtime' AND NOT l.granted`);
        return (waiting.rows[0]?.count ?? 0) > 0;
      });
      // Lock the link and revoke it in a transaction that commits while the exchange
      // is still in flight (it either waits on this lock or re-reads the revoked row).
      await revoker.query('BEGIN');
      await revoker.query('SELECT id FROM foundation.staff_telegram_links WHERE id = $1 FOR UPDATE', [lateLinkId]);
      await revoker.query('UPDATE foundation.staff_telegram_links SET revoked_at = clock_timestamp() WHERE id = $1', [lateLinkId]);
      await staffLocker.query('ROLLBACK');
      await revoker.query('COMMIT');
      // The recheck under the lock (or the fresh read of the committed revocation)
      // refuses the exchange: no credential, no session row.
      await expect(exchanged).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
      const sessions = await fixture.query<{ count: number }>(
        "SELECT count(*)::int AS count FROM foundation.web_sessions WHERE staff_id = $1 AND channel = 'STAFF_TELEGRAM'", [lateStaffId]);
      expect(sessions.rows[0]?.count).toBe(0);
    } finally {
      await staffLocker.query('ROLLBACK').catch(() => undefined);
      await revoker.query('ROLLBACK').catch(() => undefined);
      await staffLocker.end();
      await revoker.end();
    }
  }, 30000);

  // P02-05 hotfix 3 (grace must not extend TTLs): a grace replay rotates the token only;
  // idle and absolute expiry stay byte-identical, the new token works, the old one dies.
  it('rotates the token on a grace replay without extending either TTL', async () => {
    if (!migratorAccess) { throw new Error('Local isolated PostgreSQL test credentials are required'); }
    const graceStaffId = randomUUID();
    const graceLinkId = randomUUID();
    await fixture.query("INSERT INTO foundation.staff (id, role, employment_state, auth_version) VALUES ($1, 'TECHNICIAN', 'ACTIVE', 0)", [graceStaffId]);
    await fixture.query('INSERT INTO foundation.staff_telegram_links (id, staff_id, telegram_user_id) VALUES ($1, $2, $3::bigint)', [graceLinkId, graceStaffId, 700000105]);
    const raw = signedInitData(700000105);
    const first = await service.exchange(raw, source());
    const before = await fixture.query<{ idle_expires_at: Date; absolute_expires_at: Date }>(
      'SELECT idle_expires_at, absolute_expires_at FROM foundation.web_sessions WHERE token_hash = $1', [digestOf(first.token)]);
    const initialTtls = before.rows[0];
    if (!initialTtls) { throw new Error('Missing grace session row'); }
    // Small clock shift to prove a changed value would be caught: sleep 20ms so a
    // recomputed idle window would differ if the implementation ever refreshed it.
    await new Promise((resolve) => { setTimeout(resolve, 20); });
    const second = await service.exchange(raw, source());
    expect(second.token).not.toBe(first.token);
    expect(second.staffId).toBe(first.staffId);
    const after = await fixture.query<{ idle_expires_at: Date; absolute_expires_at: Date; telegram_link_id: string }>(
      'SELECT idle_expires_at, absolute_expires_at, telegram_link_id FROM foundation.web_sessions WHERE token_hash = $1', [digestOf(second.token)]);
    const replayedRow = after.rows[0];
    if (!replayedRow) { throw new Error('Missing rotated session row'); }
    expect(replayedRow.telegram_link_id).toBe(graceLinkId);
    expect(replayedRow.idle_expires_at).toEqual(initialTtls.idle_expires_at);
    expect(replayedRow.absolute_expires_at).toEqual(initialTtls.absolute_expires_at);
    const rows = await fixture.query<{ count: number }>(
      "SELECT count(*)::int AS count FROM foundation.web_sessions WHERE staff_id = $1 AND channel = 'STAFF_TELEGRAM' AND initdata_digest = $2",
      [graceStaffId, verifyInitData(raw, botToken).digest]);
    expect(rows.rows[0]?.count).toBe(1);
    await expect(service.authenticate(second.token)).resolves.toMatchObject({ staffId: graceStaffId });
    await expect(service.authenticate(first.token)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  }, 30000);
});
