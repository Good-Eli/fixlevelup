import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { DUMMY_PASSWORD_HASH, hashPassword, isValidPassword, verifyPassword } from '../staff/password.js';

export type WebRole = 'ADMIN' | 'MANAGER';
export interface SessionIdentity {
  readonly staffId: string;
  readonly role: WebRole;
  readonly authVersion: number;
  readonly idleExpiresAt: Date;
  readonly absoluteExpiresAt: Date;
}
export interface SessionCredential extends SessionIdentity { readonly token: string }
export type WebAuthErrorCode = 'INVALID_CREDENTIALS' | 'UNAUTHORIZED' | 'RATE_LIMITED' | 'INVALID_INPUT' | 'STALE' | 'FAILED';
export class WebAuthError extends Error {
  constructor(readonly code: WebAuthErrorCode) { super('Web authentication failed'); this.name = 'WebAuthError'; }
}
export interface WebAuthOptions {
  /** Independent high-entropy secret, stable across all API instances and restarts. */
  readonly throttleSecret: string | Buffer;
  readonly sourceLimit?: number;
}
interface StaffRow { id: string; role: WebRole; auth_version: number; password_hash: string }
interface SessionRow { id: string; staff_id: string; role: WebRole; auth_version: number; idle_expires_at: Date; absolute_expires_at: Date }
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const LOGIN = /^[A-Za-z0-9][A-Za-z0-9._@+-]{0,254}$/;
const hashToken = (token: string): string => createHash('sha256').update(token).digest('hex');
const newToken = (): string => randomBytes(32).toString('base64url');
const identity = (row: SessionRow): SessionIdentity => ({ staffId: row.staff_id, role: row.role, authVersion: row.auth_version,
  idleExpiresAt: row.idle_expires_at, absoluteExpiresAt: row.absolute_expires_at });
interface Reservation { key: string; id: string }

/** Core only: callers must provide a trusted socket-derived source, never a forwarded header. */
export class WebAuthService {
  private readonly secret: Buffer;
  private readonly sourceLimit: number;
  constructor(private readonly pool: Pick<Pool, 'connect'>, options: WebAuthOptions) {
    this.secret = Buffer.from(options.throttleSecret);
    this.sourceLimit = options.sourceLimit ?? 50;
    if (this.secret.length < 32 || !Number.isInteger(this.sourceLimit) || this.sourceLimit < 5 || this.sourceLimit > 10000) {
      throw new WebAuthError('FAILED');
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
      if (error instanceof WebAuthError) { throw error; }
      throw new WebAuthError('FAILED');
    } finally { client?.release(discard); }
  }

  /** Each in-flight attempt consumes a slot. Crashes fail closed until its 15-minute expiry. */
  private async reserve(identifier: string, source: string): Promise<readonly Reservation[]> {
    const entries = [
      { key: this.key('identifier', identifier), limit: 5 },
      { key: this.key('source', source), limit: this.sourceLimit },
    ].sort((a, b) => a.key.localeCompare(b.key));
    return this.transaction(async (client) => {
      const reservations: Reservation[] = [];
      for (const entry of entries) {
        await client.query('INSERT INTO foundation.web_auth_throttles (key_hash) VALUES ($1) ON CONFLICT (key_hash) DO NOTHING', [entry.key]);
        const lock = await client.query('SELECT key_hash FROM foundation.web_auth_throttles WHERE key_hash = $1 FOR UPDATE', [entry.key]);
        if (lock.rowCount !== 1) { throw new WebAuthError('FAILED'); }
        const count = await client.query<{ count: string }>(`SELECT count(*) AS count FROM foundation.web_auth_attempts
          WHERE key_hash = $1 AND expires_at > clock_timestamp() AND (completed_at IS NULL OR failed_at IS NOT NULL)`, [entry.key]);
        if (Number(count.rows[0]?.count ?? entry.limit) >= entry.limit) { throw new WebAuthError('RATE_LIMITED'); }
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
      if (locked.rowCount !== 1) { throw new WebAuthError('FAILED'); }
      const result = await client.query(`WITH stamp AS MATERIALIZED (SELECT clock_timestamp() AS now)
        UPDATE foundation.web_auth_attempts SET completed_at = stamp.now, failed_at = CASE WHEN $3 THEN stamp.now ELSE NULL END,
            expires_at = CASE WHEN $3 THEN stamp.now + interval '15 minutes' ELSE expires_at END
        FROM stamp WHERE id = $1 AND key_hash = $2 AND completed_at IS NULL AND expires_at > stamp.now`,
      [reservation.id, reservation.key, failed]);
      if (result.rowCount !== 1) { throw new WebAuthError('FAILED'); }
    }
  }

  async login(login: string, password: string, source: string): Promise<SessionCredential> {
    if (typeof login !== 'string' || login.length > 255 || typeof password !== 'string' || Buffer.byteLength(password) > 1024
      || typeof source !== 'string' || source.length < 1 || source.length > 256) { throw new WebAuthError('INVALID_CREDENTIALS'); }
    const reservations = await this.reserve(login, source);
    const found = await this.transaction(async (client) => client.query<StaffRow>(
      `SELECT s.id, s.role, s.auth_version, c.password_hash FROM foundation.staff s
       JOIN foundation.staff_web_credentials c ON c.staff_id = s.id WHERE c.login = $1`, [login]));
    const row = found.rows[0];
    let verified: boolean;
    try { verified = await verifyPassword(password, row?.password_hash ?? DUMMY_PASSWORD_HASH); }
    catch { throw new WebAuthError('FAILED'); }
    if (!row || !verified || !LOGIN.test(login)) {
      await this.transaction(async (client) => this.finish(client, reservations, true));
      throw new WebAuthError('INVALID_CREDENTIALS');
    }
    const token = newToken();
    const authenticated = await this.transaction(async (client) => {
      const current = await client.query<StaffRow>(
        `SELECT s.id, s.role, s.auth_version, c.password_hash FROM foundation.staff s
         JOIN foundation.staff_web_credentials c ON c.staff_id = s.id
         WHERE s.id = $1 AND s.employment_state = 'ACTIVE' AND s.role IN ('ADMIN', 'MANAGER') FOR UPDATE OF s, c`, [row.id]);
      const staff = current.rows[0];
      if (!staff || staff.password_hash !== row.password_hash || staff.auth_version !== row.auth_version) {
        await this.finish(client, reservations, true);
        return null;
      }
      const inserted = await client.query<SessionRow>(
        `INSERT INTO foundation.web_sessions (id, staff_id, token_hash, auth_version, created_at, idle_expires_at, absolute_expires_at)
         VALUES ($1, $2, $3, $4, clock_timestamp(), clock_timestamp() + interval '30 minutes', clock_timestamp() + interval '12 hours')
         RETURNING id, staff_id, idle_expires_at, absolute_expires_at`, [randomUUID(), staff.id, hashToken(token), staff.auth_version]);
      const session = inserted.rows[0];
      if (!session) { throw new WebAuthError('FAILED'); }
      await this.finish(client, reservations, false);
      return { ...identity({ ...session, role: staff.role, auth_version: staff.auth_version }), token };
    });
    if (!authenticated) { throw new WebAuthError('INVALID_CREDENTIALS'); }
    return authenticated;
  }

  /** Lock staff before session, matching recovery/password change lock order. */
  private async lockedSession(client: PoolClient, token: string): Promise<SessionRow> {
    if (typeof token !== 'string' || !TOKEN.test(token)) { throw new WebAuthError('UNAUTHORIZED'); }
    const digest = hashToken(token);
    const candidate = await client.query<{ staff_id: string }>("SELECT staff_id FROM foundation.web_sessions WHERE token_hash = $1 AND channel = 'CRM'", [digest]);
    const staffId = candidate.rows[0]?.staff_id;
    if (!staffId) { throw new WebAuthError('UNAUTHORIZED'); }
    const staff = await client.query<{ id: string }>("SELECT id FROM foundation.staff WHERE id = $1 AND employment_state = 'ACTIVE' AND role IN ('ADMIN', 'MANAGER') FOR UPDATE", [staffId]);
    if (!staff.rows[0]) { throw new WebAuthError('UNAUTHORIZED'); }
    const result = await client.query<SessionRow>(
      `SELECT ws.id, ws.staff_id, s.role, s.auth_version, ws.idle_expires_at, ws.absolute_expires_at
       FROM foundation.web_sessions ws JOIN foundation.staff s ON s.id = ws.staff_id
       WHERE ws.token_hash = $1 AND ws.staff_id = $2 AND ws.channel = 'CRM' AND ws.revoked_at IS NULL
         AND ws.idle_expires_at > clock_timestamp() AND ws.absolute_expires_at > clock_timestamp()
         AND ws.auth_version = s.auth_version AND s.employment_state = 'ACTIVE' AND s.role IN ('ADMIN', 'MANAGER')
       FOR UPDATE OF ws`, [digest, staffId]);
    const session = result.rows[0];
    if (!session) { throw new WebAuthError('UNAUTHORIZED'); }
    return session;
  }

  async authenticate(token: string): Promise<SessionIdentity> {
    return this.transaction(async (client) => {
      const session = await this.lockedSession(client, token);
      const result = await client.query<SessionRow>(
        `UPDATE foundation.web_sessions SET idle_expires_at = LEAST(absolute_expires_at, clock_timestamp() + interval '30 minutes')
         WHERE id = $1 AND token_hash = $2 AND revoked_at IS NULL AND idle_expires_at > clock_timestamp() AND absolute_expires_at > clock_timestamp()
         RETURNING id, staff_id, idle_expires_at, absolute_expires_at`, [session.id, hashToken(token)]);
      const updated = result.rows[0];
      if (!updated) { throw new WebAuthError('UNAUTHORIZED'); }
      return identity({ ...updated, role: session.role, auth_version: session.auth_version });
    });
  }

  async renew(token: string): Promise<SessionCredential> {
    const replacement = newToken();
    return this.transaction(async (client) => {
      const session = await this.lockedSession(client, token);
      const result = await client.query<SessionRow>(
        `UPDATE foundation.web_sessions SET token_hash = $1, idle_expires_at = LEAST(absolute_expires_at, clock_timestamp() + interval '30 minutes')
         WHERE id = $2 AND token_hash = $3 AND revoked_at IS NULL AND idle_expires_at > clock_timestamp() AND absolute_expires_at > clock_timestamp()
         RETURNING id, staff_id, idle_expires_at, absolute_expires_at`, [hashToken(replacement), session.id, hashToken(token)]);
      const updated = result.rows[0];
      if (!updated) { throw new WebAuthError('UNAUTHORIZED'); }
      return { ...identity({ ...updated, role: session.role, auth_version: session.auth_version }), token: replacement };
    });
  }

  async logout(token: string): Promise<void> {
    await this.transaction(async (client) => {
      const session = await this.lockedSession(client, token);
      const result = await client.query('UPDATE foundation.web_sessions SET revoked_at = clock_timestamp() WHERE id = $1 AND token_hash = $2 AND revoked_at IS NULL AND idle_expires_at > clock_timestamp() AND absolute_expires_at > clock_timestamp()', [session.id, hashToken(token)]);
      if (result.rowCount !== 1) { throw new WebAuthError('UNAUTHORIZED'); }
    });
  }

  async changePassword(token: string, currentPassword: string, newPassword: string, source: string, expectedVersion: number): Promise<number> {
    if (!isValidPassword(newPassword) || typeof currentPassword !== 'string' || Buffer.byteLength(currentPassword) > 1024
      || typeof source !== 'string' || source.length < 1 || source.length > 256
      || !Number.isSafeInteger(expectedVersion) || expectedVersion < 0) { throw new WebAuthError('INVALID_INPUT'); }
    // Read and verify outside locks; recheck exact hash and session under locks before update.
    const snapshot = await this.transaction(async (client) => {
      const session = await this.lockedSession(client, token);
      if (session.auth_version !== expectedVersion) { throw new WebAuthError('STALE'); }
      const result = await client.query<{ password_hash: string; login: string }>('SELECT password_hash, login FROM foundation.staff_web_credentials WHERE staff_id = $1', [session.staff_id]);
      if (!result.rows[0]) { throw new WebAuthError('UNAUTHORIZED'); }
      return { passwordHash: result.rows[0].password_hash, login: result.rows[0].login };
    });
    const reservations = await this.reserve(snapshot.login, source);
    let valid: boolean;
    let replacement: string;
    try { valid = await verifyPassword(currentPassword, snapshot.passwordHash); replacement = valid ? await hashPassword(newPassword) : ''; }
    catch { throw new WebAuthError('FAILED'); }
    if (!valid) {
      await this.transaction(async (client) => this.finish(client, reservations, true));
      throw new WebAuthError('INVALID_CREDENTIALS');
    }
    return this.transaction(async (client) => {
      const session = await this.lockedSession(client, token);
      if (session.auth_version !== expectedVersion) { throw new WebAuthError('STALE'); }
      const credential = await client.query('UPDATE foundation.staff_web_credentials SET password_hash = $1 WHERE staff_id = $2 AND password_hash = $3', [replacement, session.staff_id, snapshot.passwordHash]);
      if (credential.rowCount !== 1) { throw new WebAuthError('UNAUTHORIZED'); }
      const staff = await client.query<{ auth_version: number }>('UPDATE foundation.staff SET auth_version = auth_version + 1 WHERE id = $1 RETURNING auth_version', [session.staff_id]);
      const version = staff.rows[0]?.auth_version;
      if (version === undefined) { throw new WebAuthError('FAILED'); }
      const updated = await client.query("UPDATE foundation.web_sessions SET auth_version = $1, idle_expires_at = LEAST(absolute_expires_at, clock_timestamp() + interval '30 minutes') WHERE id = $2 AND token_hash = $3 AND revoked_at IS NULL AND idle_expires_at > clock_timestamp() AND absolute_expires_at > clock_timestamp()", [version, session.id, hashToken(token)]);
      if (updated.rowCount !== 1) { throw new WebAuthError('UNAUTHORIZED'); }
      await client.query('INSERT INTO foundation.audit_logs (id, operation, correlation_id, details) VALUES ($1, $2, $3, $4::jsonb)',
        [randomUUID(), 'STAFF_PASSWORD_CHANGE', randomUUID(), JSON.stringify({ staffId: session.staff_id })]);
      await this.finish(client, reservations, false);
      return version;
    });
  }
}
