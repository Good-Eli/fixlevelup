import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { MAX_INIT_DATA_CHARS, verifyInitData } from './telegram-initdata.js';
import { TelegramInitDataError } from './telegram-initdata.js';
import type { VerifiedInitData } from './telegram-initdata.js';

/** Staff Telegram Mini App authentication (P02-05) over foundation.web_sessions
 * rows with channel 'STAFF_TELEGRAM' (migration 20261120000700) and
 * foundation.staff_telegram_links. Owner-approved policy (DECISIONS §21):
 * TECHNICIAN-only, 2h idle / 24h absolute TTL, single initData exchange with a
 * 60-second grace window; within grace a repeat returns the same session with a
 * rotated token, after grace (or after revocation) the digest is denied.
 * Concurrency: pg_advisory_xact_lock over the initData digest serializes
 * simultaneous exchanges of the same initData; the staff row is locked before
 * the session row, matching the P02-03 lock order.
 */
export type TelegramAuthErrorCode = 'UNAUTHORIZED' | 'REPLAY' | 'RATE_LIMITED' | 'INVALID_INPUT' | 'FAILED';

export class TelegramAuthError extends Error {
  constructor(readonly code: TelegramAuthErrorCode) {
    super('Telegram staff authentication failed');
    this.name = 'TelegramAuthError';
  }
}

export interface TelegramSessionIdentity {
  readonly staffId: string;
  readonly role: 'TECHNICIAN';
  readonly authVersion: number;
  /** Decimal string of the Telegram user id (BIGINT end to end). */
  readonly telegramUserId: string;
  readonly idleExpiresAt: Date;
  readonly absoluteExpiresAt: Date;
}

export interface TelegramSessionCredential extends TelegramSessionIdentity { readonly token: string }

export interface TelegramAuthOptions {
  readonly botToken: string;
  /** Reuses WEB_AUTH_THROTTLE_SECRET (owner decision); separate dimensions keep
   * telegram-user and source buckets independent of web login buckets.
   */
  readonly throttleSecret: string | Buffer;
  readonly sourceLimit?: number;
}

interface StaffRow { id: string; role: 'TECHNICIAN'; auth_version: number }
interface SessionRow { id: string; staff_id: string; auth_version: number; idle_expires_at: Date; absolute_expires_at: Date }
interface PriorRow { id: string; staff_id: string; telegram_link_id: string; revoked_at: Date | null }
interface LinkRow { id: string; staff_id: string; telegram_user_id: string }

const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const BOT_TOKEN = /^[0-9]+:[A-Za-z0-9_-]{30,}$/;
const TELEGRAM_USER_ATTEMPT_LIMIT = 5;
const DEFAULT_SOURCE_LIMIT = 50;
const hashToken = (token: string): string => createHash('sha256').update(token).digest('hex');
const newToken = (): string => randomBytes(32).toString('base64url');
interface Reservation { key: string; id: string }
type ExchangeOutcome = { ok: true; credential: TelegramSessionCredential } | { ok: false; code: TelegramAuthErrorCode };

/** Core only: callers must provide a trusted socket-derived source, never a forwarded header. */
export class TelegramAuthService {
  private readonly secret: Buffer;
  private readonly sourceLimit: number;
  private readonly botToken: string;

  constructor(private readonly pool: Pick<Pool, 'connect'>, options: TelegramAuthOptions) {
    this.secret = Buffer.from(options.throttleSecret);
    this.sourceLimit = options.sourceLimit ?? DEFAULT_SOURCE_LIMIT;
    this.botToken = options.botToken;
    if (!BOT_TOKEN.test(this.botToken) || this.secret.length < 32
      || !Number.isInteger(this.sourceLimit) || this.sourceLimit < 5 || this.sourceLimit > 10000) {
      throw new TelegramAuthError('FAILED');
    }
  }

  private key(dimension: string, value: string): string {
    return createHmac('sha256', this.secret).update(dimension).update('\0').update(value).digest('hex');
  }

  private async transaction<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
    let client: PoolClient | undefined;
    let inTransaction = false;
    let discard = false;
    try {
      client = await this.pool.connect();
      await client.query('BEGIN');
      inTransaction = true;
      const result = await fn(client);
      await client.query('COMMIT');
      inTransaction = false;
      return result;
    } catch (error) {
      if (client && inTransaction) { try { await client.query('ROLLBACK'); } catch { discard = true; } }
      if (error instanceof TelegramAuthError) { throw error; }
      throw new TelegramAuthError('FAILED');
    } finally { client?.release(discard); }
  }

  /** Each in-flight exchange attempt consumes a slot. Crashes fail closed until
   * the 15-minute expiry. Reuses the web auth throttle tables with dedicated
   * HMAC dimensions ('telegram-user' 5/15m, 'source' 50/15m, owner decision).
   */
  private async reserve(telegramUserId: string, source: string): Promise<readonly Reservation[]> {
    const entries = [
      { key: this.key('telegram-user', telegramUserId), limit: TELEGRAM_USER_ATTEMPT_LIMIT },
      { key: this.key('source', source), limit: this.sourceLimit },
    ].sort((a, b) => a.key.localeCompare(b.key));
    return this.transaction(async (client) => {
      const reservations: Reservation[] = [];
      for (const entry of entries) {
        await client.query('INSERT INTO foundation.web_auth_throttles (key_hash) VALUES ($1) ON CONFLICT (key_hash) DO NOTHING', [entry.key]);
        const lock = await client.query('SELECT key_hash FROM foundation.web_auth_throttles WHERE key_hash = $1 FOR UPDATE', [entry.key]);
        if (lock.rowCount !== 1) { throw new TelegramAuthError('FAILED'); }
        const count = await client.query<{ count: string }>(`SELECT count(*) AS count FROM foundation.web_auth_attempts
          WHERE key_hash = $1 AND expires_at > clock_timestamp() AND (completed_at IS NULL OR failed_at IS NOT NULL)`, [entry.key]);
        if (Number(count.rows[0]?.count ?? entry.limit) >= entry.limit) { throw new TelegramAuthError('RATE_LIMITED'); }
        const id = randomUUID();
        await client.query(`INSERT INTO foundation.web_auth_attempts (id, key_hash, reserved_at, expires_at)
          VALUES ($1, $2, clock_timestamp(), clock_timestamp() + interval '15 minutes')`, [id, entry.key]);
        reservations.push({ id, key: entry.key });
      }
      return reservations;
    });
  }

  private async finish(client: PoolClient, reservations: readonly Reservation[], failed: boolean): Promise<void> {
    for (const reservation of reservations) {
      const locked = await client.query('SELECT key_hash FROM foundation.web_auth_throttles WHERE key_hash = $1 FOR UPDATE', [reservation.key]);
      if (locked.rowCount !== 1) { throw new TelegramAuthError('FAILED'); }
      const result = await client.query(`WITH stamp AS MATERIALIZED (SELECT clock_timestamp() AS now)
        UPDATE foundation.web_auth_attempts SET completed_at = stamp.now, failed_at = CASE WHEN $3 THEN stamp.now ELSE NULL END,
            expires_at = CASE WHEN $3 THEN stamp.now + interval '15 minutes' ELSE expires_at END
        FROM stamp WHERE id = $1 AND key_hash = $2 AND completed_at IS NULL AND expires_at > stamp.now`,
      [reservation.id, reservation.key, failed]);
      if (result.rowCount !== 1) { throw new TelegramAuthError('FAILED'); }
    }
  }

  private async lockedStaff(client: PoolClient, staffId: string): Promise<StaffRow | undefined> {
    const result = await client.query<StaffRow>(
      `SELECT s.id, s.role, s.auth_version FROM foundation.staff s
       WHERE s.id = $1 AND s.employment_state = 'ACTIVE' AND s.role = 'TECHNICIAN' FOR UPDATE`, [staffId]);
    return result.rows[0];
  }

  async exchange(rawInitData: string, source: string): Promise<TelegramSessionCredential> {
    if (typeof rawInitData !== 'string' || rawInitData.length < 1 || rawInitData.length > MAX_INIT_DATA_CHARS
      || typeof source !== 'string' || source.length < 1 || source.length > 256) { throw new TelegramAuthError('INVALID_INPUT'); }
    let verified: VerifiedInitData;
    try { verified = verifyInitData(rawInitData, this.botToken); }
    catch (error) {
      if (error instanceof TelegramInitDataError) {
        throw new TelegramAuthError(error.code === 'INVALID_INPUT' ? 'INVALID_INPUT' : 'UNAUTHORIZED');
      }
      throw error;
    }
    // Verified signature first (no DB access), so only verified identities occupy throttle buckets.
    const reservations = await this.reserve(verified.telegramUserId, source);
    const token = newToken();
    const outcome = await this.transaction(async (client): Promise<ExchangeOutcome> => {
      // Serialize simultaneous exchanges of the same initData across all instances.
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [verified.digest]);
      const prior = await client.query<PriorRow>(
        `SELECT ws.id, ws.staff_id, ws.telegram_link_id, ws.revoked_at FROM foundation.web_sessions ws
         WHERE ws.initdata_digest = $1 AND ws.channel = 'STAFF_TELEGRAM'
         ORDER BY ws.created_at DESC LIMIT 1`, [verified.digest]);
      const priorRow = prior.rows[0];
      if (priorRow) {
        if (priorRow.revoked_at !== null) { await this.finish(client, reservations, true); return { ok: false, code: 'REPLAY' }; }
        const staff = await this.lockedStaff(client, priorRow.staff_id);
        if (!staff) { await this.finish(client, reservations, true); return { ok: false, code: 'UNAUTHORIZED' }; }
        // The exact link used at the original exchange must still be active and bound to
        // the same Telegram identity: a re-bind (revoke A + link B) must not resurrect
        // an old session through the grace window.
        const priorLink = await client.query(
          `SELECT 1 FROM foundation.staff_telegram_links l
           WHERE l.id = $1 AND l.staff_id = $2 AND l.telegram_user_id = $3::bigint AND l.revoked_at IS NULL
           FOR UPDATE OF l`, [priorRow.telegram_link_id, priorRow.staff_id, verified.telegramUserId]);
        if (priorLink.rowCount !== 1) { await this.finish(client, reservations, true); return { ok: false, code: 'UNAUTHORIZED' }; }
        // Grace window: same session, rotated token, idle refreshed, absolute TTL unchanged.
        const rotated = await client.query<SessionRow>(
          `UPDATE foundation.web_sessions SET token_hash = $1,
             idle_expires_at = LEAST(absolute_expires_at, clock_timestamp() + interval '2 hours')
           WHERE id = $2 AND initdata_digest = $3 AND channel = 'STAFF_TELEGRAM' AND revoked_at IS NULL
             AND initdata_exchanged_at + interval '60 seconds' >= clock_timestamp()
           RETURNING id, staff_id, auth_version, idle_expires_at, absolute_expires_at`,
          [hashToken(token), priorRow.id, verified.digest]);
        const row = rotated.rows[0];
        if (!row) { await this.finish(client, reservations, true); return { ok: false, code: 'REPLAY' }; }
        await this.finish(client, reservations, false);
        return {
          ok: true,
          credential: {
            staffId: row.staff_id, role: staff.role, authVersion: row.auth_version,
            telegramUserId: verified.telegramUserId, idleExpiresAt: row.idle_expires_at,
            absoluteExpiresAt: row.absolute_expires_at, token,
          },
        };
      }
      // New exchange: only a pre-existing active staff Telegram link authorizes a session;
      // unknown Telegram users are never registered automatically. The link row is
      // locked (after staff) so a concurrent revoke of this exact link serializes
      // against the exchange; the link id is pinned immutably into the session.
      const link = await client.query<LinkRow>(
        `SELECT l.id, l.staff_id, l.telegram_user_id::text AS telegram_user_id
         FROM foundation.staff_telegram_links l
         WHERE l.telegram_user_id = $1::bigint AND l.revoked_at IS NULL`,
        [verified.telegramUserId]);
      const linked = link.rows[0];
      if (!linked) { await this.finish(client, reservations, true); return { ok: false, code: 'UNAUTHORIZED' }; }
      const staff = await this.lockedStaff(client, linked.staff_id);
      if (!staff) { await this.finish(client, reservations, true); return { ok: false, code: 'UNAUTHORIZED' }; }
      await client.query('SELECT 1 FROM foundation.staff_telegram_links WHERE id = $1 FOR UPDATE', [linked.id]);
      const inserted = await client.query<SessionRow>(
        `INSERT INTO foundation.web_sessions (id, staff_id, token_hash, auth_version, created_at,
           idle_expires_at, absolute_expires_at, channel, initdata_digest, initdata_exchanged_at, telegram_link_id)
         VALUES ($1, $2, $3, $4, clock_timestamp(), clock_timestamp() + interval '2 hours',
           clock_timestamp() + interval '24 hours', 'STAFF_TELEGRAM', $5, clock_timestamp(), $6)
         RETURNING id, staff_id, auth_version, idle_expires_at, absolute_expires_at`,
        [randomUUID(), staff.id, hashToken(token), staff.auth_version, verified.digest, linked.id]);
      const row = inserted.rows[0];
      if (!row) { throw new TelegramAuthError('FAILED'); }
      await this.finish(client, reservations, false);
      return {
        ok: true,
        credential: {
          staffId: row.staff_id, role: staff.role, authVersion: row.auth_version,
          telegramUserId: verified.telegramUserId, idleExpiresAt: row.idle_expires_at,
          absoluteExpiresAt: row.absolute_expires_at, token,
        },
      };
    });
    if (!outcome.ok) { throw new TelegramAuthError(outcome.code); }
    return outcome.credential;
  }

  /** Bearer-style token check: the session's pinned link (same id, same staff, same
   * Telegram identity, still active), staff state and auth_version are re-verified on
   * every use; idle TTL slides within the unchanged absolute TTL; revoked sessions fail.
   */
  async authenticate(token: string): Promise<TelegramSessionIdentity> {
    if (typeof token !== 'string' || !TOKEN.test(token)) { throw new TelegramAuthError('UNAUTHORIZED'); }
    const digest = hashToken(token);
    return this.transaction(async (client) => {
      const candidate = await client.query<{ staff_id: string }>(
        "SELECT staff_id FROM foundation.web_sessions WHERE token_hash = $1 AND channel = 'STAFF_TELEGRAM'", [digest]);
      const staffId = candidate.rows[0]?.staff_id;
      if (!staffId) { throw new TelegramAuthError('UNAUTHORIZED'); }
      const staff = await client.query<{ id: string }>(
        "SELECT id FROM foundation.staff WHERE id = $1 AND employment_state = 'ACTIVE' AND role = 'TECHNICIAN' FOR UPDATE", [staffId]);
      if (!staff.rows[0]) { throw new TelegramAuthError('UNAUTHORIZED'); }
      const result = await client.query<SessionRow & { telegram_user_id: string }>(
        `SELECT ws.id, ws.staff_id, ws.auth_version, ws.idle_expires_at, ws.absolute_expires_at, l.telegram_user_id
         FROM foundation.web_sessions ws
         JOIN foundation.staff s ON s.id = ws.staff_id
         JOIN foundation.staff_telegram_links l ON l.id = ws.telegram_link_id AND l.staff_id = ws.staff_id
           AND l.telegram_user_id::text = (
             SELECT l2.telegram_user_id::text FROM foundation.staff_telegram_links l2
             WHERE l2.id = ws.telegram_link_id AND l2.staff_id = ws.staff_id AND l2.revoked_at IS NULL)
         WHERE ws.token_hash = $1 AND ws.staff_id = $2 AND ws.channel = 'STAFF_TELEGRAM' AND ws.revoked_at IS NULL
           AND ws.idle_expires_at > clock_timestamp() AND ws.absolute_expires_at > clock_timestamp()
           AND ws.auth_version = s.auth_version AND s.employment_state = 'ACTIVE' AND s.role = 'TECHNICIAN'
         FOR UPDATE OF ws`, [digest, staffId]);
      const session = result.rows[0];
      if (!session) { throw new TelegramAuthError('UNAUTHORIZED'); }
      const updated = await client.query<SessionRow>(
        `UPDATE foundation.web_sessions SET idle_expires_at = LEAST(absolute_expires_at, clock_timestamp() + interval '2 hours')
         WHERE id = $1 AND token_hash = $2 AND revoked_at IS NULL
           AND idle_expires_at > clock_timestamp() AND absolute_expires_at > clock_timestamp()
         RETURNING id, staff_id, auth_version, idle_expires_at, absolute_expires_at`, [session.id, digest]);
      const row = updated.rows[0];
      if (!row) { throw new TelegramAuthError('UNAUTHORIZED'); }
      return {
        staffId: row.staff_id, role: 'TECHNICIAN', authVersion: row.auth_version,
        telegramUserId: session.telegram_user_id, idleExpiresAt: row.idle_expires_at,
        absoluteExpiresAt: row.absolute_expires_at,
      };
    });
  }
}
