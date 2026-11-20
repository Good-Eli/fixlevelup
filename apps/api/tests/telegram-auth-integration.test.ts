import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Client, Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { verifyInitData } from '../src/auth/telegram-initdata.js';
import { TelegramAuthError, TelegramAuthService } from '../src/auth/telegram-auth.service.js';

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
const telegramUserId = '279058397';
const signedInitData = (userId: number = 279058397): string => {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const user = JSON.stringify({ id: userId, first_name: 'Synthetic', username: 'synthetic_master' });
  const pairs: [string, string][] = [['user', user], ['auth_date', String(nowSeconds)]];
  const dcs = pairs.slice().sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([k, v]) => `${k}=${v}`).join('\n');
  const hash = createHmac('sha256', createHmac('sha256', 'WebAppData').update(botToken).digest()).update(dcs).digest('hex');
  const all: [string, string][] = [...pairs, ['hash', hash]];
  return all.map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
};

integration('telegram staff authentication against isolated PostgreSQL', () => {
  let admin: Client | undefined;
  let fixture: Client;
  let runtime: Pool;
  const clients: Client[] = [];
  const pools: Pool[] = [];
  let service: TelegramAuthService;
  let staffId: string;
  let sourceSequence = 0;
  const source = () => `synthetic-source-${String(++sourceSequence)}`;

  beforeAll(async () => {
    const adminEnv = readFileSync(resolve(root, 'infra/dev-postgres/.env'), 'utf8');
    const runtimeEnv = readFileSync(resolve(root, 'packages/database-tooling/.env'), 'utf8');
    const adminPassword = /^POSTGRES_PASSWORD=([a-f0-9]{64})$/m.exec(adminEnv)?.[1];
    const runtimePassword = /^FIXLEVELUP_RUNTIME_PASSWORD=([a-f0-9]{64})$/m.exec(runtimeEnv)?.[1];
    const migratorPassword = /^FIXLEVELUP_MIGRATOR_PASSWORD=([a-f0-9]{64})$/m.exec(runtimeEnv)?.[1];
    if (!adminPassword || !runtimePassword || !migratorPassword) { throw new Error('Local isolated PostgreSQL test credentials are required'); }
    const connection = { host: '127.0.0.1', port: 55432 };
    admin = new Client({ ...connection, database: 'fixlevelup_dev', user: 'fixlevelup_dev', password: adminPassword });
    await admin.connect();
    const database = `fixlevelup_tg_auth_test_${randomBytes(12).toString('hex')}`;
    await admin.query(`CREATE DATABASE "${database}" OWNER fixlevelup_migrator TEMPLATE template0`);
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
  }, 30000);

  beforeEach(async () => {
    await fixture.query('DELETE FROM foundation.web_sessions');
    await fixture.query('DELETE FROM foundation.web_auth_attempts');
    await fixture.query('DELETE FROM foundation.web_auth_throttles');
  });

  afterAll(async () => {
    await Promise.all(pools.map((pool) => pool.end()));
    await Promise.all(clients.map((client) => client.end()));
    await admin?.end();
  });

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
    const first = await service.exchange(signedInitData(), source());
    const second = await service.exchange(signedInitData(), source());
    expect(second.staffId).toBe(first.staffId);
    expect(second.token).not.toBe(first.token);
    const rows = await fixture.query<{ token_hash: string }>(
      'SELECT token_hash FROM foundation.web_sessions WHERE initdata_digest = $1',
      [verifyInitData(signedInitData(), botToken).digest]);
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
});
