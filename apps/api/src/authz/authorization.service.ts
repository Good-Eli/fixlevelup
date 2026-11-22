import { createHash } from 'node:crypto';
import {
  BadRequestException, ConflictException, HttpException, InternalServerErrorException, NotFoundException,
} from '@nestjs/common';
import type { Pool, PoolClient } from 'pg';
import { P03_REFERENCE_TYPES } from '@fixlevelup/p03-contracts';
import type { P03Target } from '@fixlevelup/p03-contracts';
import type { Principal, StaffWebPrincipal } from './principal.js';
import type { Capability, GeoCapability, GeoGrant, P03Capability, P03Grant, Scope } from './capability.js';
import {
  GEO_CAPABILITIES, GEO_SCOPE_CONTRACT, isCapability, isGeoCapability, isP03Capability, PERMISSION_CONTRACT,
  PROTECTED_CAPABILITIES, scopeMatches,
} from './capability.js';
import { activeAdminCityIds, effectiveP03Grants } from './p03-grants.js';
import { lockAccessPolicy } from './rbac-lock.js';
import type { GeoAction, GeoContext, GeographyAuthorizationApi } from '../settings/geography/geo-contract.js';

export type { P03Target } from '@fixlevelup/p03-contracts';

export type AuthorizationErrorCode = 'UNAUTHORIZED' | 'FORBIDDEN' | 'FAILED';
export class AuthorizationError extends Error {
  constructor(readonly code: AuthorizationErrorCode) { super('Authorization failed'); this.name = 'AuthorizationError'; }
}
/** P03 writes only: the last authorization check passed, but COMMIT was not acknowledged.
 * Callers may reauthorize a receipt read, never retry the mutation. No raw error is kept. */
export class P03CommitUnknown extends Error {
  constructor() { super('P03 commit acknowledgement unknown'); this.name = 'P03CommitUnknown'; }
}

function definiteCommitRejection(error: unknown): boolean {
  if (!error || typeof error !== 'object' || !('severity' in error) || error.severity !== 'ERROR'
    || !('code' in error) || typeof error.code !== 'string') { return false; }
  return /^[A-Z0-9]{5}$/.test(error.code) && !error.code.startsWith('08') && error.code !== '40003';
}
export interface SessionProof { readonly token: string; readonly kind: Principal['kind'] }
export interface EffectiveRole { readonly id: string; readonly code: string; readonly type: 'SYSTEM' | 'CUSTOM' }
/** Session projection for the UI and command callbacks. Missing domain grants in legacy
 * callers/test doubles are treated as no grants, never authority. */
export interface AccessView {
  readonly staffId: string; readonly role: EffectiveRole; readonly permissions: readonly Capability[];
  readonly geoPermissions?: readonly GeoGrant[];
  readonly p03Permissions?: readonly P03Grant[];
}
export interface StaffWriteContext extends AccessView { readonly client: PoolClient; readonly principal: Principal }
type Command<T> = (ctx: StaffWriteContext) => Promise<T>;
export interface AuthorizationServiceApi {
  authorize(principal: Principal, capability: Capability, scope: Scope): Promise<void>;
  inspectAccess(proof: SessionProof): Promise<AccessView>;
  authorizeForRead<T>(proof: SessionProof, capability: Capability, scope: Scope, read: Command<T>): Promise<T>;
  authorizeForWrite<T>(proof: SessionProof, capability: Capability, scope: Scope, write: Command<T>): Promise<T>;
}

export interface P03PolicyContext extends StaffWriteContext {
  readonly principal: StaffWebPrincipal;
  readonly p03Permissions: readonly P03Grant[];
  readonly geoPermissions: readonly GeoGrant[];
}
export interface P03Context extends P03PolicyContext {
  readonly target: P03Target;
  /** null means all required grants are GLOBAL, not authority over a different target. */
  readonly cityIds: readonly string[] | null;
}
type P03TargetResolver = (ctx: P03PolicyContext) => Promise<P03Target>;
export type P03DiscoveryDomain = 'content' | 'callback_interval';
export interface P03AuthorizationApi {
  withP03<T>(proof: SessionProof, mode: 'read' | 'write', required: readonly P03Capability[], target: P03Target | P03TargetResolver,
    callback: (ctx: P03Context) => Promise<T>): Promise<T>;
  withP03Discovery<T>(proof: SessionProof, domain: P03DiscoveryDomain,
    callback: (ctx: P03PolicyContext, cityIds: readonly string[] | null) => Promise<T>): Promise<T>;
}

const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const GEO_ACTIONS: readonly GeoAction[] = Object.freeze([
  ...GEO_CAPABILITIES, 'geography.admin.assign', 'geography.self.read', 'geography.bootstrap.revoke',
]);
/** A manager may write geography only with the independent matching read grant too. */
const WRITE_READ_PAIR: Readonly<Partial<Record<GeoAction, GeoCapability>>> = Object.freeze({
  'geography.manage': 'geography.read', 'staff.geography.manage': 'staff.geography.read',
});
function isGeoAction(value: unknown): value is GeoAction {
  return typeof value === 'string' && (GEO_ACTIONS as readonly string[]).includes(value);
}
interface IdentityRow { id: string; role: string; auth_version: number }
interface LockedProof {
  readonly principal: Principal;
  readonly sessionId: string;
  readonly tokenHash: string;
  readonly channel: 'CRM' | 'STAFF_TELEGRAM';
  readonly linkId: string | null;
}
interface PolicyRow {
  id: string; code: string; role_type: string; permission_code: string | null;
  scope_type: string | null; protected: boolean | null;
}
interface GeoGrantRow { code: string; scope: string; source: string }
export function isSystemAdmin(role: EffectiveRole): boolean { return role.type === 'SYSTEM' && role.code === 'ADMIN'; }
function requirePermission(view: AccessView, capability: Capability, scope: Scope): void {
  if (!scopeMatches(capability, scope, view.staffId) || !view.permissions.includes(capability)) {
    throw new AuthorizationError('FORBIDDEN');
  }
}
/** A stored geography grant is authority only when the scope is one the contract allows,
 * the row is not protected (protection would make it mandatory on every ADMIN), GLOBAL is
 * held by a SYSTEM ADMIN alone, and publish is held by a SYSTEM ADMIN alone. The bootstrap
 * exception is likewise never authority for a non-administrator role. A drifted row is
 * ignored rather than rejected, matching the "unknown grant is no grant" rule. */
function effectiveGeoGrant(code: unknown, scope: unknown, role: EffectiveRole, source: string): GeoGrant | null {
  if (!isGeoCapability(code) || !(GEO_SCOPE_CONTRACT[code] as readonly string[]).includes(scope as string)) { return null; }
  const stored = scope as 'GLOBAL' | 'CITY';
  const admin = isSystemAdmin(role);
  // The technician channel role never holds geography, matching the migration 012 grant guard.
  if (role.type === 'SYSTEM' && role.code === 'TECHNICIAN') { return null; }
  if (stored === 'GLOBAL' && !admin) { return null; }
  if (code === 'geography.publish' && !admin) { return null; }
  if (source === 'BOOTSTRAP' && !admin) { return null; }
  return { code, scope: stored };
}

/** No permission cache, plain unchecked read callback or channel-derived grants. A guard preflight
 * is not authority for a later read/write: every protected projection and command takes
 * the policy lock, verifies the specific session and reads the role on its own transaction. */
export class AuthorizationService implements AuthorizationServiceApi, GeographyAuthorizationApi, P03AuthorizationApi {
  constructor(private readonly pool: Pick<Pool, 'connect'>) {}

  private async transaction<T>(mode: 'read' | 'write', fn: (client: PoolClient) => Promise<T>, recoverP03Receipt = false): Promise<T> {
    let client: PoolClient | undefined;
    let inTransaction = false;
    let discard = false;
    try {
      client = await this.pool.connect();
      await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      inTransaction = true;
      await lockAccessPolicy(client, mode);
      const result = await fn(client);
      if (recoverP03Receipt) {
        try {
          const acknowledgement = await client.query('COMMIT');
          if (acknowledgement.command !== 'COMMIT') { throw new InternalServerErrorException(); }
        } catch (error) {
          if (error instanceof InternalServerErrorException || definiteCommitRejection(error)) { throw error; }
          // A broken/uncertain connection cannot be reused, even for rollback.
          // Only the caller's receipt-only path may open a new transaction.
          discard = true;
          inTransaction = false;
          throw new P03CommitUnknown();
        }
      } else {
        await client.query('COMMIT');
      }
      inTransaction = false;
      return result;
    } catch (error) {
      if (client && inTransaction) { try { await client.query('ROLLBACK'); } catch { discard = true; } }
      if (error instanceof AuthorizationError || error instanceof HttpException || (discard && error instanceof P03CommitUnknown)) { throw error; }
      if (error && typeof error === 'object' && 'code' in error &&
        ['40001', '40P01', '55P03', '23505'].some((code) => code === error.code)) { throw new ConflictException(); }
      throw new InternalServerErrorException();
    } finally { client?.release(discard); }
  }

  private async policy(client: PoolClient, principal: Principal): Promise<AccessView & { geoPermissions: readonly GeoGrant[] }> {
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
    return { staffId: principal.staffId, role, permissions, geoPermissions: await this.geoGrants(client, principal.staffId, role) };
  }

  /** Geography grants on the same locked snapshot. Role grants come from the live role;
   * the bootstrap exception is resolved ONLY from the trusted assignment table and only
   * for the caller's *current* assignment, so an explicit revocation, a reassignment or a
   * redeploy cannot resurrect it, and no other administrator inherits it. */
  private async geoGrants(client: PoolClient, staffId: string, role: EffectiveRole): Promise<readonly GeoGrant[]> {
    const result = await client.query<GeoGrantRow>(
      `WITH current_assignment AS (
         SELECT a.id, a.role_id FROM foundation.staff_role_assignments a
         WHERE a.staff_id=$1 AND a.revoked_at IS NULL
       ), granted AS (
         SELECT rp.permission_code AS code, rp.scope_type AS scope, 'ROLE' AS source
         FROM current_assignment ca
         JOIN foundation.role_permissions rp ON rp.role_id=ca.role_id AND rp.enabled
         JOIN foundation.permissions p ON p.code=rp.permission_code AND p.active AND NOT p.protected
         WHERE rp.permission_code=ANY($2::text[])
         UNION ALL
         SELECT b.permission_code, 'GLOBAL', 'BOOTSTRAP'
         FROM foundation.geography_bootstrap_permissions b
         JOIN current_assignment ca ON ca.id=b.assignment_id
         JOIN foundation.permissions p ON p.code=b.permission_code AND p.active AND NOT p.protected
         WHERE b.revoked_at IS NULL AND b.permission_code=ANY($2::text[])
       )
       SELECT code, scope, source FROM granted ORDER BY code, source`,
      [staffId, GEO_CAPABILITIES]);
    const byCode = new Map<GeoCapability, GeoGrant>();
    for (const row of result.rows) {
      const grant = effectiveGeoGrant(row.code, row.scope, role, row.source);
      if (!grant) { continue; }
      const current = byCode.get(grant.code);
      // An explicit GLOBAL grant wins over a narrower CITY grant for the same code.
      if (!current || (current.scope === 'CITY' && grant.scope === 'GLOBAL')) { byCode.set(grant.code, grant); }
    }
    return Object.freeze([...byCode.values()]);
  }

  /** Deliberately obtain the staff lock before the channel link and session locks,
   * matching credential rotation/recovery and TG exchange. Revalidate token after waiting. */
  private async lockedPrincipal(client: PoolClient, proof: SessionProof): Promise<LockedProof> {
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
    const session = await client.query<{ id: string }>(
      `SELECT id FROM foundation.web_sessions WHERE token_hash=$1 AND channel=$2 AND staff_id=$3 AND auth_version=$4
       AND telegram_link_id IS NOT DISTINCT FROM $5::uuid AND revoked_at IS NULL
       AND idle_expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp() FOR SHARE`,
      [hash, channel, staff.id, staff.auth_version, candidate.telegram_link_id]);
    const current = session.rows[0];
    if (session.rowCount !== 1 || !current) { throw new AuthorizationError('UNAUTHORIZED'); }
    return { principal, sessionId: current.id, tokenHash: hash, channel, linkId: candidate.telegram_link_id };
  }

  /** The held row/policy locks protect the identity and grants, but time still moves while
   * a data, audit or receipt statement waits. This is the last statement before COMMIT.
   * SELF deactivation may itself make the actor INACTIVE at exactly the next epoch; the
   * original locked token must still be live, and no other actor transition can pass. */
  private async assertProofCurrent(client: PoolClient, locked: LockedProof, selfDeactivation: boolean): Promise<void> {
    const { principal, sessionId, tokenHash, channel, linkId } = locked;
    const result = await client.query(
      `SELECT s.id FROM foundation.web_sessions ws
       JOIN foundation.staff s ON s.id=ws.staff_id AND s.role=$7
       WHERE ws.id=$1 AND ws.token_hash=$2 AND ws.channel=$3 AND ws.staff_id=$4 AND ws.auth_version=$5
       AND ws.telegram_link_id IS NOT DISTINCT FROM $6::uuid AND ws.revoked_at IS NULL
       AND ((s.employment_state='ACTIVE' AND s.auth_version=$5)
         OR ($8 AND s.employment_state='INACTIVE' AND s.auth_version=$5::bigint+1))
       AND (ws.telegram_link_id IS NULL OR EXISTS (SELECT 1 FROM foundation.staff_telegram_links l
         WHERE l.id=ws.telegram_link_id AND l.staff_id=s.id AND l.revoked_at IS NULL))
       AND ws.idle_expires_at>clock_timestamp() AND ws.absolute_expires_at>clock_timestamp()`,
      [sessionId, tokenHash, channel, principal.staffId, principal.authVersion, linkId, principal.role, selfDeactivation]);
    if (result.rowCount !== 1) { throw new AuthorizationError('UNAUTHORIZED'); }
  }

  private async withProof<T>(mode: 'read' | 'write', proof: SessionProof, callback: (client: PoolClient, principal: Principal) => Promise<T>,
    selfDeactivation = false, recoverP03Receipt = false): Promise<T> {
    return this.transaction(mode, async (client) => {
      const locked = await this.lockedPrincipal(client, proof);
      const result = await callback(client, locked.principal);
      await this.assertProofCurrent(client, locked, selfDeactivation);
      return result;
    }, recoverP03Receipt);
  }

  async authorize(principal: Principal, capability: Capability, scope: Scope): Promise<void> {
    await this.transaction('read', async (client) => { requirePermission(await this.policy(client, principal), capability, scope); });
  }
  async inspectAccess(proof: SessionProof): Promise<AccessView> {
    return this.withProof('read', proof, async (client, principal) => {
      const view = await this.policy(client, principal);
      return { ...view, p03Permissions: await effectiveP03Grants(client, principal, view.role) };
    });
  }
  private async execute<T>(mode: 'read' | 'write', proof: SessionProof, capability: Capability, scope: Scope, operation: Command<T>): Promise<T> {
    return this.withProof(mode, proof, async (client, principal) => {
      const view = await this.policy(client, principal);
      requirePermission(view, capability, scope);
      const p03Permissions = await effectiveP03Grants(client, principal, view.role);
      return operation({ ...view, p03Permissions, client, principal });
    }, mode === 'write' && capability === 'staff.self.deactivate' && scope.kind === 'SELF');
  }
  authorizeForRead<T>(proof: SessionProof, capability: Capability, scope: Scope, read: Command<T>): Promise<T> {
    return this.execute('read', proof, capability, scope, read);
  }
  authorizeForWrite<T>(proof: SessionProof, capability: Capability, scope: Scope, write: Command<T>): Promise<T> {
    return this.execute('write', proof, capability, scope, write);
  }

  private async p03Policy(client: PoolClient, principal: Principal): Promise<P03PolicyContext> {
    if (principal.kind !== 'staff-web') { throw new AuthorizationError('FORBIDDEN'); }
    const view = await this.policy(client, principal);
    const p03Permissions = await effectiveP03Grants(client, principal, view.role);
    return { ...view, p03Permissions, client, principal };
  }

  /** All required capabilities cover the same target. The optional resolver is trusted
   * server code, and exists only to resolve a stored identity's actual scope, not to read
   * its body or replay receipts before that scope has been authorized. */
  async withP03<T>(proof: SessionProof, mode: 'read' | 'write', required: readonly P03Capability[], inputTarget: P03Target | P03TargetResolver,
    callback: (ctx: P03Context) => Promise<T>): Promise<T> {
    const codes = [...required];
    if (codes.some((code) => !isP03Capability(code))) { throw new BadRequestException(); }
    const resolver = typeof inputTarget === 'function' ? inputTarget : null;
    const explicitTarget = typeof inputTarget === 'function' ? null : this.p03Target(inputTarget);
    return this.withProof(mode, proof, async (client, principal) => {
      const ctx = await this.p03Policy(client, principal);
      if (!codes.length) {
        // The only grant-less path is own bootstrap-source inspection. Its query must
        // still restrict every source to a code the caller currently holds at GLOBAL.
        if (mode !== 'read' || explicitTarget?.scope !== 'COMPANY' || !isSystemAdmin(ctx.role)
          || !ctx.permissions.includes('roles.permissions.manage')) { throw new AuthorizationError('FORBIDDEN'); }
      }
      const applicable = codes.map((code) => ctx.p03Permissions.find((grant) => grant.code === code));
      if (applicable.some((grant) => !grant)) { throw new AuthorizationError('FORBIDDEN'); }
      const target = resolver ? this.p03Target(await resolver(Object.freeze(ctx))) : explicitTarget;
      if (!target) { throw new BadRequestException(); }
      const cityLimited = applicable.some((grant) => grant?.scope === 'CITY');
      if (target.scope === 'COMPANY') {
        // If a stored identity resolved to a scope outside the caller's grant, don't
        // distinguish it from a missing identifier; explicit COMPANY requests are 403.
        if (cityLimited) {
          if (resolver) { throw new NotFoundException(); }
          throw new AuthorizationError('FORBIDDEN');
        }
        return callback({ ...ctx, target, cityIds: null });
      }
      const cityIds = cityLimited ? await activeAdminCityIds(client, principal.staffId) : null;
      if (cityIds !== null && !cityIds.includes(target.cityId)) { throw new NotFoundException(); }
      if ((await client.query('SELECT id FROM foundation.service_cities WHERE id=$1', [target.cityId])).rowCount !== 1) {
        throw new NotFoundException();
      }
      return callback({ ...ctx, target, cityIds });
    }, false, mode === 'write');
  }

  private p03Target(value: unknown): P03Target {
    if (value && typeof value === 'object' && 'scope' in value) {
      if (value.scope === 'COMPANY' && (!('cityId' in value) || value.cityId === undefined)) { return Object.freeze({ scope: 'COMPANY' }); }
      if (value.scope === 'CITY' && 'cityId' in value && typeof value.cityId === 'string' && UUID.test(value.cityId)) {
        return Object.freeze({ scope: 'CITY', cityId: value.cityId.toLowerCase() });
      }
    }
    throw new BadRequestException();
  }

  /** Separate narrow operation for the two domain city pickers; this never confers
   * geography authority or allows an unscoped content/callback data query. */
  async withP03Discovery<T>(proof: SessionProof, domain: P03DiscoveryDomain,
    callback: (ctx: P03PolicyContext, cityIds: readonly string[] | null) => Promise<T>): Promise<T> {
    const codes = { content: 'content.read', callback_interval: P03_REFERENCE_TYPES.callback_interval.read } as const;
    if (!Object.hasOwn(codes, domain)) { throw new BadRequestException(); }
    const code = codes[domain];
    return this.withProof('read', proof, async (client, principal) => {
      const ctx = await this.p03Policy(client, principal);
      const grant = ctx.p03Permissions.find((item) => item.code === code);
      if (!grant) { throw new AuthorizationError('FORBIDDEN'); }
      return callback(ctx, grant.scope === 'GLOBAL' ? null : await activeAdminCityIds(client, principal.staffId));
    });
  }

  /** Single central authority for every geography route and command. The raw session
   * proof is verified on this transaction only, after the policy lock and before any
   * command reads or writes. There is no `@RequireCapability` preflight for geography:
   * the callback receives the trusted city scope and must use it in its own SQL. */
  async withGeography<T>(proof: SessionProof, mode: 'read' | 'write', action: GeoAction, cityId: string | null,
    command: (ctx: GeoContext) => Promise<T>): Promise<T> {
    if (!isGeoAction(action)) { throw new BadRequestException(); }
    if (cityId !== null && !UUID.test(cityId)) { throw new BadRequestException(); }
    const target = cityId === null ? null : cityId.toLowerCase();
    return this.withProof(mode, proof, async (client, principal) => {
      const view = await this.policy(client, principal);
      const grants = view.geoPermissions;
      if (action === 'geography.self.read') {
        // SELF summary is a verified Telegram master reading only its own row. A CRM
        // session and every other channel can never reach it; TG can never become admin.
        if (principal.kind !== 'staff-telegram' || target !== null) { throw new AuthorizationError('FORBIDDEN'); }
        if (!view.permissions.includes('staff.self.read')) { throw new AuthorizationError('FORBIDDEN'); }
        return command({ ...view, client, principal, cityIds: [] });
      }
      if (principal.kind === 'staff-telegram') { throw new AuthorizationError('FORBIDDEN'); }
      const admin = isSystemAdmin(view.role);
      if (action === 'geography.admin.assign') {
        // Delegating administrative cities is never a manager operation, cannot be
        // self-derived from staff.geography.*, and needs a GLOBAL geography.manage grant.
        // The target city is a nested path id, so it may be present; the callback proves
        // that the city exists and that the target is not the caller itself.
        if (!admin || !view.permissions.includes('staff.role.assign')
          || !grants.some((g) => g.code === 'geography.manage' && g.scope === 'GLOBAL')) {
          throw new AuthorizationError('FORBIDDEN');
        }
        const p03Permissions = await effectiveP03Grants(client, principal, view.role);
        return command({ ...view, p03Permissions, client, principal, cityIds: null });
      }
      if (action === 'geography.bootstrap.revoke') {
        // Technical action, not a catalog permission: revoking one bootstrap exception is
        // available only to the live CRM SYSTEM ADMIN that manages role permissions, and
        // only as a global operation. The callback still proves the target assignment and
        // that the actor holds the specific GLOBAL code; after a handover/demotion the
        // exception is already ineffective, so this only records the explicit removal.
        if (mode !== 'write' || !admin || !view.permissions.includes('roles.permissions.manage')
          || target !== null) {
          throw new AuthorizationError('FORBIDDEN');
        }
        return command({ ...view, client, principal, cityIds: null });
      }
      const grant = grants.find((g) => g.code === action);
      if (!grant) { throw new AuthorizationError('FORBIDDEN'); }
      const unrestricted = admin && grant.scope === 'GLOBAL';
      const cityIds = unrestricted ? null : await activeAdminCityIds(client, principal.staffId);
      if (target !== null) {
        // A city outside the trusted assignment is indistinguishable from a missing one.
        if (cityIds !== null && !cityIds.includes(target)) { throw new NotFoundException(); }
      } else if (mode === 'write' && cityIds !== null) {
        // A global command may only run for an unrestricted SYSTEM ADMIN; a list read
        // with cityId=null is authorized above and filtered by cityIds in the callback.
        throw new AuthorizationError('FORBIDDEN');
      }
      if (mode === 'write' && !admin) {
        // The matrix is explicit: a manager writes geography only with the independent
        // matching read grant, in a city from the trusted assignment checked above.
        const paired = WRITE_READ_PAIR[action];
        if (paired && !grants.some((g) => g.code === paired)) { throw new AuthorizationError('FORBIDDEN'); }
      }
      return command({ ...view, client, principal, cityIds });
    });
  }
}
