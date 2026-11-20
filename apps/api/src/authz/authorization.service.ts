import { createHash } from 'node:crypto';
import { ConflictException, HttpException, InternalServerErrorException } from '@nestjs/common';
import type { Pool, PoolClient } from 'pg';
import type { Principal } from './principal.js';
import type { Capability, Scope } from './capability.js';
import { isCapability, PERMISSION_CONTRACT, PROTECTED_CAPABILITIES, scopeMatches } from './capability.js';
import { lockAccessPolicy } from './rbac-lock.js';

export type AuthorizationErrorCode = 'UNAUTHORIZED' | 'FORBIDDEN' | 'FAILED';
export class AuthorizationError extends Error {
  constructor(readonly code: AuthorizationErrorCode) { super('Authorization failed'); this.name = 'AuthorizationError'; }
}
export interface SessionProof { readonly token: string; readonly kind: Principal['kind'] }
export interface EffectiveRole { readonly id: string; readonly code: string; readonly type: 'SYSTEM' | 'CUSTOM' }
export interface AccessView { readonly staffId: string; readonly role: EffectiveRole; readonly permissions: readonly Capability[] }
export interface StaffWriteContext extends AccessView { readonly client: PoolClient; readonly principal: Principal }
type Command<T> = (ctx: StaffWriteContext) => Promise<T>;
export interface AuthorizationServiceApi {
  authorize(principal: Principal, capability: Capability, scope: Scope): Promise<void>;
  inspectAccess(proof: SessionProof): Promise<AccessView>;
  authorizeForRead<T>(proof: SessionProof, capability: Capability, scope: Scope, read: Command<T>): Promise<T>;
  authorizeForWrite<T>(proof: SessionProof, capability: Capability, scope: Scope, write: Command<T>): Promise<T>;
}

const TOKEN = /^[A-Za-z0-9_-]{43}$/;
interface IdentityRow { id: string; role: string; auth_version: number }
interface PolicyRow {
  id: string; code: string; role_type: string; permission_code: string | null;
  scope_type: string | null; protected: boolean | null;
}
export function isSystemAdmin(role: EffectiveRole): boolean { return role.type === 'SYSTEM' && role.code === 'ADMIN'; }
function requirePermission(view: AccessView, capability: Capability, scope: Scope): void {
  if (!scopeMatches(capability, scope, view.staffId) || !view.permissions.includes(capability)) {
    throw new AuthorizationError('FORBIDDEN');
  }
}

/** No permission cache, plain unchecked read callback or channel-derived grants. A guard preflight
 * is not authority for a later read/write: every protected projection and command takes
 * the policy lock, verifies the specific session and reads the role on its own transaction. */
export class AuthorizationService implements AuthorizationServiceApi {
  constructor(private readonly pool: Pick<Pool, 'connect'>) {}

  private async transaction<T>(mode: 'read' | 'write', fn: (client: PoolClient) => Promise<T>): Promise<T> {
    let client: PoolClient | undefined;
    let inTransaction = false;
    let discard = false;
    try {
      client = await this.pool.connect();
      await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      inTransaction = true;
      await lockAccessPolicy(client, mode);
      const result = await fn(client);
      await client.query('COMMIT');
      inTransaction = false;
      return result;
    } catch (error) {
      if (client && inTransaction) { try { await client.query('ROLLBACK'); } catch { discard = true; } }
      if (error instanceof AuthorizationError || error instanceof HttpException) { throw error; }
      if (error && typeof error === 'object' && 'code' in error &&
        ['40001', '40P01', '55P03', '23505'].some((code) => code === error.code)) { throw new ConflictException(); }
      throw new InternalServerErrorException();
    } finally { client?.release(discard); }
  }

  private async policy(client: PoolClient, principal: Principal): Promise<AccessView> {
    const result = await client.query<PolicyRow>(
      `SELECT r.id, r.code, r.role_type, p.code AS permission_code, rp.scope_type, p.protected
       FROM foundation.staff s
       JOIN foundation.staff_role_assignments a ON a.staff_id=s.id AND a.revoked_at IS NULL
       JOIN foundation.roles r ON r.id=a.role_id AND r.status='ACTIVE'
       LEFT JOIN foundation.role_permissions rp ON rp.role_id=r.id AND rp.enabled
       LEFT JOIN foundation.permissions p ON p.code=rp.permission_code AND p.active
       WHERE s.id=$1 AND s.auth_version=$2 AND s.employment_state='ACTIVE' AND s.role=$3
       ORDER BY p.code`, [principal.staffId, principal.authVersion, principal.role]);
    const first = result.rows[0];
    if (!first) {
      // A guard authentication can precede a concurrent deactivation/role change.
      // A stale identity is 401; a live identity with no valid assignment is 403.
      const live = await client.query("SELECT 1 FROM foundation.staff WHERE id=$1 AND role=$2 AND auth_version=$3 AND employment_state='ACTIVE'",
        [principal.staffId, principal.role, principal.authVersion]);
      throw new AuthorizationError(live.rowCount === 1 ? 'FORBIDDEN' : 'UNAUTHORIZED');
    }
    if ((first.role_type !== 'SYSTEM' && first.role_type !== 'CUSTOM')
        || (first.role_type === 'SYSTEM' && first.code !== principal.role)) { throw new AuthorizationError('FORBIDDEN'); }
    const role: EffectiveRole = { id: first.id, code: first.code, type: first.role_type };
    const permissions: Capability[] = [];
    for (const row of result.rows) {
      if (row.id !== role.id) { throw new AuthorizationError('FAILED'); }
      const code = row.permission_code;
      if (!isCapability(code)) { continue; } // unknown, disabled or missing catalog entry: deny
      const protectedCode = PROTECTED_CAPABILITIES.includes(code);
      if (row.scope_type !== PERMISSION_CONTRACT[code] || row.protected !== protectedCode
        || (protectedCode && !isSystemAdmin(role))) { continue; }
      permissions.push(code);
    }
    return { staffId: principal.staffId, role, permissions };
  }

  /** Deliberately obtain the staff lock before the channel link and session locks,
   * matching credential rotation/recovery and TG exchange. Revalidate token after waiting. */
  private async lockedPrincipal(client: PoolClient, proof: SessionProof): Promise<Principal> {
    if (!TOKEN.test(proof.token)) {
      throw new AuthorizationError('UNAUTHORIZED');
    }
    const channel = proof.kind === 'staff-web' ? 'CRM' : 'STAFF_TELEGRAM';
    const hash = createHash('sha256').update(proof.token).digest('hex');
    const lookup = await client.query<{ staff_id: string; telegram_link_id: string | null }>(
      'SELECT staff_id, telegram_link_id FROM foundation.web_sessions WHERE token_hash=$1 AND channel=$2', [hash, channel]);
    const candidate = lookup.rows[0];
    if (!candidate) { throw new AuthorizationError('UNAUTHORIZED'); }
    const staff = (await client.query<IdentityRow>(
      "SELECT id, role, auth_version FROM foundation.staff WHERE id=$1 AND employment_state='ACTIVE' FOR SHARE", [candidate.staff_id])).rows[0];
    if (!staff) { throw new AuthorizationError('UNAUTHORIZED'); }
    let principal: Principal;
    if (proof.kind === 'staff-web' && (staff.role === 'ADMIN' || staff.role === 'MANAGER') && candidate.telegram_link_id === null) {
      principal = { kind: proof.kind, staffId: staff.id, role: staff.role, authVersion: staff.auth_version };
    } else if (proof.kind === 'staff-telegram' && staff.role === 'TECHNICIAN' && candidate.telegram_link_id) {
      const link = (await client.query<{ telegram_user_id: string }>(
        `SELECT telegram_user_id::text FROM foundation.staff_telegram_links
         WHERE id=$1 AND staff_id=$2 AND revoked_at IS NULL FOR SHARE`, [candidate.telegram_link_id, staff.id])).rows[0];
      if (!link) { throw new AuthorizationError('UNAUTHORIZED'); }
      principal = { kind: proof.kind, staffId: staff.id, role: staff.role, authVersion: staff.auth_version, telegramUserId: link.telegram_user_id };
    } else { throw new AuthorizationError('UNAUTHORIZED'); }
    const session = await client.query(
      `SELECT id FROM foundation.web_sessions WHERE token_hash=$1 AND channel=$2 AND staff_id=$3 AND auth_version=$4
       AND telegram_link_id IS NOT DISTINCT FROM $5::uuid AND revoked_at IS NULL
       AND idle_expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp() FOR SHARE`,
      [hash, channel, staff.id, staff.auth_version, candidate.telegram_link_id]);
    if (session.rowCount !== 1) { throw new AuthorizationError('UNAUTHORIZED'); }
    return principal;
  }

  async authorize(principal: Principal, capability: Capability, scope: Scope): Promise<void> {
    await this.transaction('read', async (client) => { requirePermission(await this.policy(client, principal), capability, scope); });
  }
  async inspectAccess(proof: SessionProof): Promise<AccessView> {
    return this.transaction('read', async (client) => this.policy(client, await this.lockedPrincipal(client, proof)));
  }
  private async execute<T>(mode: 'read' | 'write', proof: SessionProof, capability: Capability, scope: Scope, operation: Command<T>): Promise<T> {
    return this.transaction(mode, async (client) => {
      const principal = await this.lockedPrincipal(client, proof);
      const view = await this.policy(client, principal);
      requirePermission(view, capability, scope);
      return operation({ ...view, client, principal });
    });
  }
  authorizeForRead<T>(proof: SessionProof, capability: Capability, scope: Scope, read: Command<T>): Promise<T> {
    return this.execute('read', proof, capability, scope, read);
  }
  authorizeForWrite<T>(proof: SessionProof, capability: Capability, scope: Scope, write: Command<T>): Promise<T> {
    return this.execute('write', proof, capability, scope, write);
  }
}
