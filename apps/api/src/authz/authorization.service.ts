import { createHash } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { HttpException, InternalServerErrorException } from '@nestjs/common';
import type { Principal } from './principal.js';
import type { StaffWebPrincipal } from './principal.js';
import type { Capability, Scope } from './capability.js';
import { isCapability } from './capability.js';

export type AuthorizationErrorCode = 'UNAUTHORIZED' | 'FORBIDDEN' | 'FAILED';
export class AuthorizationError extends Error {
  constructor(readonly code: AuthorizationErrorCode) { super('Authorization failed'); this.name = 'AuthorizationError'; }
}

export interface StaffWriteContext {
  readonly client: PoolClient;
  readonly principal: StaffWebPrincipal;
}

/** DI-facing API of AuthorizationService, mirroring the WebAuthServiceApi pattern. */
export interface AuthorizationServiceApi {
  authorize(principal: Principal, capability: Capability, scope: Scope): Promise<void>;
  read<T>(fn: (client: PoolClient) => Promise<T>): Promise<T>;
  authorizeForWrite<T>(token: string, capability: Capability, scope: Scope, write: (context: StaffWriteContext) => Promise<T>): Promise<T>;
}

const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const hashToken = (token: string): string => createHash('sha256').update(token).digest('hex');

interface StaffRow { id: string; role: 'ADMIN' | 'MANAGER'; auth_version: number }

/**
 * Default-deny capability check. Grants come only from foundation.user_permissions;
 * no role gets implicit rights. authorize() verifies permissions for reads in a plain
 * READ COMMITTED transaction (the guard has just re-authenticated the session through
 * WebAuthService.authenticate). authorizeForWrite() re-verifies session, staff state and
 * permissions under the P02-03 lock order — staff row FOR UPDATE first, then the session
 * row FOR UPDATE, then the permissions read — and runs the caller's write on the same
 * client so revoke, deactivation and write serialize on the common authorization state.
 */
export class AuthorizationService implements AuthorizationServiceApi {
  constructor(private readonly pool: Pick<Pool, 'connect'>) {}

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
      // Safe, already-mapped errors propagate; raw driver errors never escape this boundary.
      if (error instanceof AuthorizationError || error instanceof HttpException) { throw error; }
      throw new InternalServerErrorException();
    } finally { client?.release(discard); }
  }

  private async permitted(client: PoolClient, staffId: string, capability: Capability, scope: Scope): Promise<boolean> {
    if (!isCapability(capability)) { return false; }
    const result = await client.query(
      `SELECT 1 FROM foundation.user_permissions
       WHERE staff_id = $1 AND capability = $2 AND scope = $3 AND revoked_at IS NULL
         AND valid_from <= clock_timestamp() AND (valid_until IS NULL OR valid_until > clock_timestamp())`,
      [staffId, capability, scope.kind]);
    return result.rowCount === 1;
  }

  /** Throws FORBIDDEN when the principal lacks the capability in scope. Default deny.
   * Read path: no locks, plain READ COMMITTED; the guard has just re-verified the session.
   */
  async authorize(principal: Principal, capability: Capability, scope: Scope): Promise<void> {
    await this.transaction(async (client) => {
      if (!await this.permitted(client, principal.staffId, capability, scope)) { throw new AuthorizationError('FORBIDDEN'); }
    });
  }

  /** Plain read transaction without locks for staff data queries after the guard's checks. */
  async read<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
    return this.transaction(fn);
  }

  /** Lock staff before session, matching the WebAuthService recovery/password-change order. */
  private async lockedPrincipal(client: PoolClient, token: string): Promise<StaffWebPrincipal> {
    if (typeof token !== 'string' || !TOKEN.test(token)) { throw new AuthorizationError('UNAUTHORIZED'); }
    const digest = hashToken(token);
    const candidate = await client.query<{ staff_id: string }>('SELECT staff_id FROM foundation.web_sessions WHERE token_hash = $1', [digest]);
    const staffId = candidate.rows[0]?.staff_id;
    if (!staffId) { throw new AuthorizationError('UNAUTHORIZED'); }
    const staff = await client.query<{ id: string }>("SELECT id FROM foundation.staff WHERE id = $1 AND employment_state = 'ACTIVE' AND role IN ('ADMIN', 'MANAGER') FOR UPDATE", [staffId]);
    if (!staff.rows[0]) { throw new AuthorizationError('UNAUTHORIZED'); }
    const result = await client.query<StaffRow>(
      `SELECT s.id, s.role, s.auth_version FROM foundation.web_sessions ws
       JOIN foundation.staff s ON s.id = ws.staff_id
       WHERE ws.token_hash = $1 AND ws.staff_id = $2 AND ws.revoked_at IS NULL
         AND ws.idle_expires_at > clock_timestamp() AND ws.absolute_expires_at > clock_timestamp()
         AND ws.auth_version = s.auth_version AND s.employment_state = 'ACTIVE' AND s.role IN ('ADMIN', 'MANAGER')
       FOR UPDATE OF ws`, [digest, staffId]);
    const locked = result.rows[0];
    if (!locked) { throw new AuthorizationError('UNAUTHORIZED'); }
    return { kind: 'staff-web', staffId: locked.id, role: locked.role, authVersion: locked.auth_version };
  }

  /** Rechecks the session and permissions under locks, then runs the write in the same transaction. */
  async authorizeForWrite<T>(token: string, capability: Capability, scope: Scope, write: (context: StaffWriteContext) => Promise<T>): Promise<T> {
    return this.transaction(async (client) => {
      const principal = await this.lockedPrincipal(client, token);
      if (!await this.permitted(client, principal.staffId, capability, scope)) { throw new AuthorizationError('FORBIDDEN'); }
      return write({ client, principal });
    });
  }
}
