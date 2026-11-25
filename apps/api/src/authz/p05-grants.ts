import { ForbiddenException } from '@nestjs/common';
import type { PoolClient } from 'pg';
import type { AccessView, EffectiveRole } from './authorization.service.js';
import { isP05Capability, P05_CAPABILITIES, P05_MODULE, P05_SCOPE_CONTRACT } from './capability.js';
import type { P05Capability, P05Grant, P05Scope } from './capability.js';
import type { Principal } from './principal.js';

type RoleIdentity = Pick<EffectiveRole, 'type' | 'code'>;
const EMPTY: readonly P05Grant[] = Object.freeze([]);

/** Stored scopes a P05 code may legally carry on a target role. The exact SYSTEM
 * ADMIN role may store CITY or GLOBAL; SYSTEM MANAGER and CUSTOM web roles may store
 * CITY only; the technician channel (and every other role) may store none. A CUSTOM
 * role shared with Telegram is masked at grant-projection time, not by name. */
export function p05GrantableScopes(code: P05Capability, role: RoleIdentity): readonly P05Scope[] {
  const scopes: readonly P05Scope[] = P05_SCOPE_CONTRACT[code];
  if (role.type === 'SYSTEM' && role.code === 'ADMIN') { return scopes; }
  if (role.type === 'CUSTOM' || role.code === 'MANAGER') { return scopes.filter((scope) => scope === 'CITY'); }
  return [];
}

/** The only live delegation authority: exact SYSTEM ADMIN with role management and the
 * exact GLOBAL P05 grant. The ordinary release composition never issues or expands P05
 * through the role editor; this predicate exists for the fail-closed checks and for
 * future operator-owned synthetic provisioning, not to open a new runtime source. */
export function holdsGlobalP05(actor: AccessView, code: P05Capability): boolean {
  return actor.role.type === 'SYSTEM' && actor.role.code === 'ADMIN'
    && actor.permissions.includes('roles.permissions.manage')
    && (actor.p05Permissions ?? []).some((grant) => grant.code === code && grant.scope === 'GLOBAL');
}

interface GrantRow { code: string; scope: P05Scope }

/** Effective P05 grants on the already locked RBAC/policy snapshot. The source rows are
 * the ordinary `foundation.permissions` catalog (migration 024 provisions them) and the
 * current assignment's enabled `role_permissions`. A row is authority only when the
 * catalog entry is the exact active ordinary code in the fixed `requests` module and
 * the stored scope is allowed for the live role. A drifted, protected, inactive or
 * foreign-module row is ignored rather than repaired, and an absent catalog (any
 * pre-024 profile) simply yields no grants. No P05 source relation is referenced here,
 * so legacy profiles never query an absent table. */
export async function effectiveP05Grants(client: PoolClient, principal: Principal,
  role: EffectiveRole): Promise<readonly P05Grant[]> {
  if (principal.kind !== 'staff-web' || (role.type === 'CUSTOM' && principal.role !== 'MANAGER')) { return EMPTY; }
  const result = await client.query<GrantRow>(
    `WITH current_assignment AS (
       SELECT id,role_id FROM foundation.staff_role_assignments
       WHERE staff_id=$1 AND role_id=$2 AND revoked_at IS NULL
     )
     SELECT rp.permission_code AS code,rp.scope_type AS scope
     FROM current_assignment ca
     JOIN foundation.role_permissions rp ON rp.role_id=ca.role_id AND rp.enabled
     JOIN foundation.permissions p ON p.code=rp.permission_code
     WHERE rp.permission_code=ANY($3::text[]) AND p.active AND NOT p.protected AND p.module=$4
     ORDER BY rp.permission_code`,
    [principal.staffId, role.id, P05_CAPABILITIES, P05_MODULE]);
  const byCode = new Map<P05Capability, P05Grant>();
  for (const { code, scope } of result.rows) {
    if (!isP05Capability(code) || !p05GrantableScopes(code, role).includes(scope)) { continue; }
    byCode.set(code, Object.freeze({ code, scope }));
  }
  return Object.freeze([...byCode.values()]);
}

/** Called under the RBAC write lock, only on the path that adds a *new* administrative
 * city to an existing staff member. A live CITY-scoped P05 grant widens with every new
 * admin-city assignment, so the ordinary release composition refuses that indirect
 * expansion before the INSERT; an operator-owned synthetic provisioning path grants the
 * new city explicitly instead. GLOBAL P05 grants are not widened by an assignment. */
export async function requireNoP05CityExpansion(ctx: { readonly client: PoolClient }, targetStaffId: string): Promise<void> {
  const result = await ctx.client.query(
    `SELECT 1 FROM foundation.staff s
     JOIN foundation.staff_role_assignments a ON a.staff_id=s.id AND a.revoked_at IS NULL
     JOIN foundation.roles r ON r.id=a.role_id AND r.status='ACTIVE'
     JOIN foundation.role_permissions rp ON rp.role_id=r.id AND rp.enabled AND rp.scope_type='CITY'
     JOIN foundation.permissions p ON p.code=rp.permission_code AND p.active AND NOT p.protected AND p.module=$2
     WHERE s.id=$1 AND p.code=ANY($3::text[]) LIMIT 1`,
    [targetStaffId, P05_MODULE, P05_CAPABILITIES]);
  if (result.rowCount !== 0) { throw new ForbiddenException(); }
}
