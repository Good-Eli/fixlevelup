import { createHash } from 'node:crypto';
import {
  BadRequestException, ConflictException, HttpException, InternalServerErrorException, NotFoundException,
} from '@nestjs/common';
import type { Pool, PoolClient } from 'pg';
import { P03_REFERENCE_TYPES } from '@fixlevelup/p03-contracts';
import type { P03Target } from '@fixlevelup/p03-contracts';
import type { Principal, StaffWebPrincipal } from './principal.js';
import type { Capability, GeoCapability, GeoGrant, P03Capability, P03Grant, P05Capability, P05Grant, Scope } from './capability.js';
import {
  GEO_CAPABILITIES, GEO_SCOPE_CONTRACT, isCapability, isGeoCapability, isP03Capability, isP05Capability, PERMISSION_CONTRACT,
  PROTECTED_CAPABILITIES, scopeMatches,
} from './capability.js';
import { activeAdminCityIds, effectiveP03Grants } from './p03-grants.js';
import { effectiveP04Grants } from './p04-grants.js';
import { effectiveP05Grants } from './p05-grants.js';
import type { P04Capability, P04Grant, P04Target } from './p04-grants.js';
import { lockAccessPolicy } from './rbac-lock.js';
import type { GeoAction, GeoContext, GeographyAuthorizationApi } from '../settings/geography/geo-contract.js';

export type { P03Target } from '@fixlevelup/p03-contracts';
export type { P04Capability, P04Target } from './p04-grants.js';

export type AuthorizationErrorCode = 'UNAUTHORIZED' | 'FORBIDDEN' | 'FAILED';
export class AuthorizationError extends Error {
  constructor(readonly code: AuthorizationErrorCode) { super('Authorization failed'); this.name = 'AuthorizationError'; }
}
/** Receipt-backed P03/P04 writes only: COMMIT was not acknowledged. Never retry the
 * mutation automatically. No raw error is kept; P03's existing receipt path is unchanged. */
export class P03CommitUnknown extends Error {
  constructor() { super('P03 commit acknowledgement unknown'); this.name = 'P03CommitUnknown'; }
}
/** P05 domain commands use the same shared policy lock and their own receipt code, so a
 * caller cannot confuse a P03/P04 uncertain commit with a P05 one. Never auto-retry. */
export class P05CommitUnknown extends Error {
  readonly code = 'P05_COMMIT_UNKNOWN';
  constructor() { super('P05 commit acknowledgement unknown'); this.name = 'P05CommitUnknown'; }
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
  readonly p04Permissions?: readonly P04Grant[];
  readonly p05Permissions?: readonly P05Grant[];
  /** Own active P04 CITY assignments for UI affordances; never used as authorization. */
  readonly p04PricingWriteCityIds?: readonly string[];
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

export interface P04Context {
  readonly client: PoolClient;
  readonly staffId: string;
  readonly target: P04Target;
  /** Null means all required grants are GLOBAL; a CITY query must still bind its target. */
  readonly cityIds: readonly string[] | null;
  recheck(target?: P04Target): Promise<void>;
}
export interface P04AuthorizationApi {
  withP04<T>(proof: SessionProof, mode: 'read' | 'write', required: readonly P04Capability[], target: P04Target,
    callback: (ctx: P04Context) => Promise<T>): Promise<T>;
}

/** Narrow P05 staff port. The callback resolves the persisted target under its own
 * request/GEO locks and then names the target's city, so a wrong city and a missing
 * target are indistinguishable (404); a missing command grant is a 403 decided from the
 * locked policy, never from the body. Every command additionally requires
 * `requests.read` on the same target. P05 domain writes take the *shared* RBAC lock:
 * they never block each other and cannot invert against a policy writer, while a
 * revocation still wins for every later command. */
export interface P05Context {
  readonly client: PoolClient;
  readonly staffId: string;
  /** Exact locked web session row, for receipts that bind a staff actor. */
  readonly sessionId: string;
  readonly role: EffectiveRole;
  /** Null means every required grant is GLOBAL (exact SYSTEM ADMIN). */
  readonly cityIds: readonly string[] | null;
  readonly authorizeCity: (cityId: string) => Promise<void>;
  readonly recheck: () => Promise<Date>;
}
export interface P05AuthorizationApi {
  withP05<T>(proof: SessionProof, required: readonly P05Capability[], callback: (ctx: P05Context) => Promise<T>): Promise<T>;
  withP05<Prepared, Result>(proof: SessionProof, required: readonly P05Capability[],
    prepare: (ctx: P05Context) => Promise<Prepared>, decide: (prepared: Prepared, clock: Date) => Result): Promise<Result>;
}

const P04_COMPANY_ACTIONS: readonly (readonly P04Capability[])[] = [
  ['catalog.read'], ['catalog.read', 'catalog.manage'], ['pricing.rules.read'], ['pricing.rules.read', 'pricing.rules.manage'],
  ['content.externalreviews.read'], ['content.externalreviews.read', 'content.externalreviews.manage'],
  ['content.externalreviews.read', 'content.externalreviews.manage', 'content.externalreviews.publish'],
];
const P04_FINAL_CLOCK_GUARDS = new Set([
  'catalog_price_periods_final_clock_guard', 'price_rule_periods_final_clock_guard',
  'pricing_policy_periods_final_clock_guard', 'public_price_estimate_periods_final_clock_guard',
]);
type ReceiptCommitMode = false | 'P03' | 'P04' | 'P05';

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
  scope_type: string | null; protected: boolean | null; p04_present?: boolean;
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
export class AuthorizationService implements AuthorizationServiceApi, GeographyAuthorizationApi, P03AuthorizationApi, P04AuthorizationApi, P05AuthorizationApi {
  constructor(private readonly pool: Pick<Pool, 'connect'>) {}

  private async transaction<T>(mode: 'read' | 'write', fn: (client: PoolClient) => Promise<T>, receiptCommitMode: ReceiptCommitMode = false): Promise<T> {
    let client: PoolClient | undefined;
    let inTransaction = false;
    let discard = false;
    try {
      client = await this.pool.connect();
      await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      inTransaction = true;
      await lockAccessPolicy(client, mode);
      if (receiptCommitMode === 'P05') { await client.query('SET LOCAL synchronous_commit=on'); }
      const result = await fn(client);
      if (receiptCommitMode) {
        try {
          const acknowledgement = await client.query('COMMIT');
          if (acknowledgement.command !== 'COMMIT') {
            if (receiptCommitMode === 'P05') { throw new P05CommitUnknown(); }
            throw new InternalServerErrorException();
          }
        } catch (error) {
          if (receiptCommitMode === 'P04' && definiteCommitRejection(error) && error && typeof error === 'object'
            && 'code' in error && error.code === '23514' && 'constraint' in error
            && typeof error.constraint === 'string' && P04_FINAL_CLOCK_GUARDS.has(error.constraint)) {
            throw new ConflictException();
          }
          if (error instanceof InternalServerErrorException || definiteCommitRejection(error)) { throw error; }
          // A broken/uncertain connection cannot be reused, even for rollback.
          // Only the caller's receipt-only path may open a new transaction.
          discard = true;
          inTransaction = false;
          throw receiptCommitMode === 'P05' ? new P05CommitUnknown() : new P03CommitUnknown();
        }
      } else {
        await client.query('COMMIT');
      }
      inTransaction = false;
      return result;
    } catch (error) {
      if (client && inTransaction) { try { await client.query('ROLLBACK'); } catch { discard = true; } }
      if (error instanceof AuthorizationError || error instanceof HttpException
        || (discard && (error instanceof P03CommitUnknown || error instanceof P05CommitUnknown))) { throw error; }
      if (error && typeof error === 'object' && 'code' in error &&
        ['40001', '40P01', '55P03', '23505'].some((code) => code === error.code)) { throw new ConflictException(); }
      throw new InternalServerErrorException();
    } finally { client?.release(discard); }
  }

  private async policy(client: PoolClient, principal: Principal, includeP04 = false): Promise<AccessView & { geoPermissions: readonly GeoGrant[] }> {
    // Legacy projections keep their statement sequence: detect 021 via pg_catalog in
    // the existing lookup, and never reference the new source relation on 018–020.
    const p04Marker = includeP04 && principal.kind === 'staff-web'
      ? ", to_regclass('foundation.p04_bootstrap_permissions') IS NOT NULL AS p04_present" : '';
    const result = await client.query<PolicyRow>(
      `SELECT r.id, r.code, r.role_type, p.code AS permission_code, rp.scope_type, p.protected${p04Marker}
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
    const geoPermissions = await this.geoGrants(client, principal.staffId, role);
    const p04Permissions = includeP04 && first.p04_present === true ? await effectiveP04Grants(client, principal, role) : [];
    return { staffId: principal.staffId, role, permissions, geoPermissions,
      ...(p04Permissions.length ? { p04Permissions } : {}) };
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
  private async assertProofCurrent(client: PoolClient, locked: LockedProof, selfDeactivation: boolean,
    sampleDecisionClock = false): Promise<Date | undefined> {
    const { principal, sessionId, tokenHash, channel, linkId } = locked;
    const clock = sampleDecisionClock ? 'sample.db_now' : 'clock_timestamp()';
    const result = await client.query<{ db_now?: Date }>(
      `SELECT s.id${sampleDecisionClock ? ',sample.db_now' : ''} FROM foundation.web_sessions ws
       JOIN foundation.staff s ON s.id=ws.staff_id AND s.role=$7
       ${sampleDecisionClock ? 'CROSS JOIN (SELECT clock_timestamp() AS db_now) sample' : ''}
       WHERE ws.id=$1 AND ws.token_hash=$2 AND ws.channel=$3 AND ws.staff_id=$4 AND ws.auth_version=$5
       AND ws.telegram_link_id IS NOT DISTINCT FROM $6::uuid AND ws.revoked_at IS NULL
       AND ((s.employment_state='ACTIVE' AND s.auth_version=$5)
         OR ($8 AND s.employment_state='INACTIVE' AND s.auth_version=$5::bigint+1))
       AND (ws.telegram_link_id IS NULL OR EXISTS (SELECT 1 FROM foundation.staff_telegram_links l
         WHERE l.id=ws.telegram_link_id AND l.staff_id=s.id AND l.revoked_at IS NULL))
       AND ws.idle_expires_at>${clock} AND ws.absolute_expires_at>${clock}`,
      [sessionId, tokenHash, channel, principal.staffId, principal.authVersion, linkId, principal.role, selfDeactivation]);
    if (result.rowCount !== 1) { throw new AuthorizationError('UNAUTHORIZED'); }
    const now = result.rows[0]?.db_now;
    if (sampleDecisionClock && (!(now instanceof Date) || !Number.isFinite(now.getTime()))) {
      throw new AuthorizationError('FAILED');
    }
    return now;
  }

  private async withProof<T>(mode: 'read' | 'write', proof: SessionProof, callback: (client: PoolClient, principal: Principal) => Promise<T>,
    selfDeactivation = false, receiptCommitMode: ReceiptCommitMode = false): Promise<T> {
    return this.transaction(mode, async (client) => {
      const locked = await this.lockedPrincipal(client, proof);
      const result = await callback(client, locked.principal);
      await this.assertProofCurrent(client, locked, selfDeactivation);
      return result;
    }, receiptCommitMode);
  }

  async authorize(principal: Principal, capability: Capability, scope: Scope): Promise<void> {
    await this.transaction('read', async (client) => { requirePermission(await this.policy(client, principal), capability, scope); });
  }
  async inspectAccess(proof: SessionProof): Promise<AccessView> {
    return this.withProof('read', proof, async (client, principal) => {
      const view = await this.policy(client, principal, true);
      const p03Permissions = await effectiveP03Grants(client, principal, view.role);
      const pricingRead = view.p04Permissions?.find(grant => grant.code === 'pricing.read');
      const pricingManage = view.p04Permissions?.find(grant => grant.code === 'pricing.manage');
      if (pricingRead === undefined || (pricingRead.scope !== 'CITY' && pricingManage?.scope !== 'CITY')) {
        return { ...view, p03Permissions };
      }
      // The UI observes revocation even when the web session epoch and role
      // stay the same. In mixed scope, cityList proves only read. Expose just
      // the caller's active assignments, with a fail-closed bound.
      const { rows } = await client.query<{ city_id: string }>(`SELECT a.city_id
        FROM foundation.staff_admin_city_assignments a JOIN foundation.service_cities c ON c.id=a.city_id
        WHERE a.staff_id=$1 AND a.revoked_at IS NULL AND c.lifecycle='ACTIVE' AND c.current_version_id IS NOT NULL
        ORDER BY a.city_id LIMIT 129`, [principal.staffId]);
      return { ...view, p03Permissions, p04PricingWriteCityIds: rows.length > 128 ? [] : rows.map(row => row.city_id) };
    });
  }
  private async execute<T>(mode: 'read' | 'write', proof: SessionProof, capability: Capability, scope: Scope, operation: Command<T>): Promise<T> {
    return this.withProof(mode, proof, async (client, principal) => {
      const view = await this.policy(client, principal, mode === 'write' &&
        (capability === 'roles.permissions.manage' || capability === 'staff.role.assign' || capability === 'staff.create'));
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
    }, false, mode === 'write' && 'P03');
  }

  /** P04 uses the same RC policy lock and live session proof as P03. The callback
   * rechecks actual stored targets after its own fence/receipt waits; all such targets
   * then remain part of the last proof even on a thrown conflict or other late error. */
  async withP04<T>(proof: SessionProof, mode: 'read' | 'write', required: readonly P04Capability[], inputTarget: P04Target,
    callback: (ctx: P04Context) => Promise<T>): Promise<T> {
    const codes = [...required];
    const target = this.p04Target(inputTarget);
    const matches = (expected: readonly P04Capability[]): boolean =>
      codes.length === expected.length && expected.every((code) => codes.includes(code));
    const validate = (current: P04Target): void => {
      if (current.scope === 'COMPANY') {
        if (P04_COMPANY_ACTIONS.some((action) => (mode === 'read') === (action.length === 1) && matches(action))) { return; }
      } else if (mode === 'read' ? matches(['pricing.read']) : current.scope === 'CITY' && matches(['pricing.read', 'pricing.manage'])) {
        return;
      }
      throw new BadRequestException();
    };
    validate(target);
    return this.transaction(mode, async (client) => {
      const locked = await this.lockedPrincipal(client, proof);
      const { principal } = locked;
      if (principal.kind !== 'staff-web') { throw new AuthorizationError('FORBIDDEN'); }
      const authorizeTargets = async (targets: readonly P04Target[]): Promise<readonly string[] | null> => {
        await this.assertProofCurrent(client, locked, false);
        const view = await this.policy(client, principal, true);
        const grants = codes.map((code) => view.p04Permissions?.find((grant) => grant.code === code));
        if (grants.some((grant) => !grant)) { throw new AuthorizationError('FORBIDDEN'); }
        const cityIds = grants.some((grant) => grant?.scope === 'CITY') ? await activeAdminCityIds(client, principal.staffId) : null;
        for (const current of targets) {
          if (current.scope === 'COMPANY' && cityIds !== null) { throw new AuthorizationError('FORBIDDEN'); }
          if (current.scope === 'CITY' && ((cityIds !== null && !cityIds.includes(current.cityId)) ||
            (await client.query('SELECT id FROM foundation.service_cities WHERE id=$1', [current.cityId])).rowCount !== 1)) {
            throw new NotFoundException();
          }
        }
        // Keep the time-sensitive session predicate the last statement in the proof.
        await this.assertProofCurrent(client, locked, false);
        return cityIds;
      };
      const cityIds = await authorizeTargets([target]);
      const checked = new Map([[JSON.stringify(target), target]]);
      const recheck = async (otherTarget = target): Promise<void> => {
        const current = this.p04Target(otherTarget);
        // Receipt targets can change the city, but cannot convert a scoped command
        // into a company or discovery operation (or vice versa).
        if (current.scope !== target.scope) { throw new NotFoundException(); }
        checked.set(JSON.stringify(current), current);
        await authorizeTargets([...checked.values()]);
      };
      await client.query('SAVEPOINT p04_authorized_callback');
      let result: T;
      try {
        result = await callback(Object.freeze({ client, staffId: principal.staffId, target, cityIds, recheck }));
      } catch (error) {
        // A raw SQL failure can abort the transaction; restore the pre-callback state
        // first so we can do the live, locked proof before exposing its status.
        await client.query('ROLLBACK TO SAVEPOINT p04_authorized_callback');
        await authorizeTargets([...checked.values()]);
        throw error;
      }
      await authorizeTargets([...checked.values()]);
      return result;
    }, mode === 'write' && 'P04');
  }

  /** P05 staff commands. The policy lock is deliberately the *shared* one, exactly as
   * P04 uses it for its domain writes: P05 domain writers are serialized by their own
   * request/anchor/geography locks, a shared policy lock cannot invert against a
   * role/revocation writer, and a revocation still wins before every later command
   * because its exclusive lock waits for running commands and is visible to the next
   * one. `required` is the exact command set; `requests.read` is added here so no caller
   * can forget it, and the union is never widened to another target. The callback
   * resolves the persisted target under its own locks and calls `authorizeCity`, which
   * turns a wrong city and a missing target into the same 404 and a missing command
   * grant into a 403 only *after* that target exists. The proof is re-read after the
   * callback, before COMMIT; a domain write gets its own unknown-COMMIT signal. */
  async withP05<T>(proof: SessionProof, required: readonly P05Capability[], callback: (ctx: P05Context) => Promise<T>): Promise<T>;
  async withP05<Prepared, Result>(proof: SessionProof, required: readonly P05Capability[],
    prepare: (ctx: P05Context) => Promise<Prepared>, decide: (prepared: Prepared, clock: Date) => Result): Promise<Result>;
  async withP05<Prepared, Result = Prepared>(proof: SessionProof, required: readonly P05Capability[],
    callback: (ctx: P05Context) => Promise<Prepared>, decide?: (prepared: Prepared, clock: Date) => Result): Promise<Prepared | Result> {
    const codes = [...required];
    if (!codes.length || codes.some((code) => !isP05Capability(code))) { throw new BadRequestException(); }
    const needed = Object.freeze([...new Set<P05Capability>(['requests.read', ...codes])]);
    const write = codes.some((code) => code !== 'requests.read');
    return this.transaction('read', async (client) => {
      const locked = await this.lockedPrincipal(client, proof);
      const { principal } = locked;
      if (principal.kind !== 'staff-web') { throw new AuthorizationError('FORBIDDEN'); }
      const authorizeTargets = async (targets: readonly string[], sampleDecisionClock = false) => {
        const view = await this.policy(client, principal);
        const p05Permissions = await effectiveP05Grants(client, principal, view.role);
        const grants = needed.map((code) => p05Permissions.find((grant) => grant.code === code));
        if (grants.some((grant) => !grant)) { throw new AuthorizationError('FORBIDDEN'); }
        const cityIds = grants.some((grant) => grant?.scope === 'CITY') ? await activeAdminCityIds(client, principal.staffId) : null;
        for (const cityId of targets) {
          // A city outside the trusted assignment is indistinguishable from a missing one.
          if (cityIds !== null && !cityIds.includes(cityId)) { throw new NotFoundException(); }
          if ((await client.query('SELECT id FROM foundation.service_cities WHERE id=$1', [cityId])).rowCount !== 1) {
            throw new NotFoundException();
          }
        }
        // Keep the time-sensitive session predicate the last statement in the proof.
        const clock = await this.assertProofCurrent(client, locked, false, sampleDecisionClock);
        return { cityIds, role: view.role, clock };
      };
      const checked: string[] = [];
      const authorizeCity = async (cityId: string): Promise<void> => {
        if (typeof cityId !== 'string' || !UUID.test(cityId)) { throw new BadRequestException(); }
        const city = cityId.toLowerCase();
        checked.push(city);
        await authorizeTargets([city]);
      };
      const recheck = async (): Promise<Date> => {
        const { clock } = await authorizeTargets([...checked], true);
        if (!clock) { throw new AuthorizationError('FAILED'); }
        return clock;
      };
      const initial = await authorizeTargets([]);
      const result = await callback(Object.freeze({ client, staffId: principal.staffId, sessionId: locked.sessionId,
        role: initial.role, cityIds: initial.cityIds, authorizeCity, recheck }));
      // A command that never named its target has no authority over any row: fail closed
      // before COMMIT rather than after an effect.
      if (!checked.length) { throw new InternalServerErrorException(); }
      const { clock } = await authorizeTargets([...checked], decide !== undefined);
      // No IO after this common SQL clock. The isolated domain can choose a
      // restricted representation or roll back a write whose basis has expired.
      if (decide) {
        if (!clock) { throw new AuthorizationError('FAILED'); }
        return decide(result, clock);
      }
      return result;
    }, write && 'P05');
  }

  private p04Target(value: unknown): P04Target {
    if (value && typeof value === 'object' && 'scope' in value) {
      if (value.scope === 'CITY' && Object.keys(value).length === 2
        && 'cityId' in value && typeof value.cityId === 'string' && UUID.test(value.cityId)) {
        return Object.freeze({ scope: 'CITY', cityId: value.cityId.toLowerCase() });
      }
      if ((value.scope === 'COMPANY' || value.scope === 'DISCOVERY') && Object.keys(value).length === 1) {
        return Object.freeze({ scope: value.scope });
      }
    }
    throw new BadRequestException();
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
      const view = await this.policy(client, principal, action === 'geography.admin.assign' && mode === 'write');
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
