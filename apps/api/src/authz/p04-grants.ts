import { ForbiddenException } from '@nestjs/common';
import type { PoolClient } from 'pg';
import type { AccessView, EffectiveRole, StaffWriteContext } from './authorization.service.js';
import { isP04Capability, P04_CAPABILITIES, P04_SCOPE_CONTRACT } from './capability.js';
import type { P04Capability, P04Grant, P04Scope } from './capability.js';
import type { Principal } from './principal.js';

export { isP04Capability } from './capability.js';
export type { P04Capability, P04Grant } from './capability.js';
export type P04Target = { readonly scope: 'COMPANY' } | { readonly scope: 'CITY'; readonly cityId: string }
  | { readonly scope: 'DISCOVERY' };

type RoleIdentity = Pick<EffectiveRole, 'type' | 'code'>;
const EMPTY: readonly P04Grant[] = Object.freeze([]);

/** Shared CUSTOM roles may also be assigned to Telegram; that channel gets no P04 grant. */
export function p04GrantableScopes(code: P04Capability, role: RoleIdentity): readonly P04Scope[] {
  const scopes: readonly P04Scope[] = P04_SCOPE_CONTRACT[code];
  if (role.type === 'SYSTEM' && role.code === 'ADMIN') { return scopes; }
  if (role.type === 'CUSTOM' || role.code === 'MANAGER') {
    return scopes.filter((scope) => scope === 'CITY');
  }
  return [];
}

/** The only live delegation authority: SYSTEM ADMIN with role management and exact GLOBAL. */
export function holdsGlobalP04(actor: AccessView, code: P04Capability): boolean {
  return actor.role.type === 'SYSTEM' && actor.role.code === 'ADMIN'
    && actor.permissions.includes('roles.permissions.manage')
    && (actor.p04Permissions ?? []).some((grant) => grant.code === code && grant.scope === 'GLOBAL');
}

interface GrantRow { code: string; scope: P04Scope; source: string }

/** Called under the RBAC policy lock, after proving the web identity and current role.
 * Source relation SQL is never used by a legacy projection without a P04 catalog marker. */
export async function effectiveP04Grants(client: PoolClient, principal: Principal, role: EffectiveRole): Promise<readonly P04Grant[]> {
  if (principal.kind !== 'staff-web' || (role.type === 'CUSTOM' && principal.role !== 'MANAGER')) { return EMPTY; }
  const result = await client.query<GrantRow>(
    `WITH current_assignment AS (
       SELECT id,role_id FROM foundation.staff_role_assignments
       WHERE staff_id=$1 AND role_id=$2 AND revoked_at IS NULL
     ), granted AS (
       SELECT rp.permission_code AS code,rp.scope_type AS scope,'ROLE' AS source
       FROM current_assignment ca JOIN foundation.role_permissions rp ON rp.role_id=ca.role_id AND rp.enabled
       WHERE rp.permission_code=ANY($3::text[])
       UNION ALL
       SELECT b.permission_code,'GLOBAL','BOOTSTRAP'
       FROM current_assignment ca JOIN foundation.p04_bootstrap_permissions b ON b.assignment_id=ca.id
       WHERE b.revoked_at IS NULL AND b.permission_code=ANY($3::text[])
     )
     SELECT g.code,g.scope,g.source FROM granted g JOIN foundation.permissions p ON p.code=g.code
     WHERE p.active AND NOT p.protected AND p.module=split_part(p.code,'.',1)
     ORDER BY g.code,g.source`, [principal.staffId, role.id, P04_CAPABILITIES]);
  const byCode = new Map<P04Capability, P04Grant>();
  for (const { code, scope, source } of result.rows) {
    if (!isP04Capability(code) || !p04GrantableScopes(code, role).includes(scope)) { continue; }
    if (source !== 'ROLE' && (source !== 'BOOTSTRAP' || scope !== 'GLOBAL' || role.type !== 'SYSTEM' || role.code !== 'ADMIN')) { continue; }
    if (!byCode.has(code) || scope === 'GLOBAL') { byCode.set(code, Object.freeze({ code, scope })); }
  }
  return Object.freeze([...byCode.values()]);
}

/** Reads only the pending target's active web assignment under the policy+staff locks.
 * The caller invokes this only after finding a P04 CITY grant in the legacy scan, so
 * pre-021 geography never references the new relation. A target's existing same-code
 * GLOBAL founder source already covers the new city, so there is no expansion there. */
export async function requireP04CityExpansion(ctx: StaffWriteContext, targetStaffId: string,
  grants: readonly { code: P04Capability; role: RoleIdentity }[]): Promise<void> {
  const missing = grants.filter(({ code, role }) => p04GrantableScopes(code, role).includes('CITY') && !holdsGlobalP04(ctx, code));
  if (!missing.length) { return; }
  if (missing.some(({ role }) => role.type !== 'SYSTEM' || role.code !== 'ADMIN')) { throw new ForbiddenException(); }
  const result = await ctx.client.query<{ permission_code: string }>(
    `SELECT b.permission_code FROM foundation.staff_role_assignments a
     JOIN foundation.p04_bootstrap_permissions b ON b.assignment_id=a.id AND b.revoked_at IS NULL
     WHERE a.staff_id=$1 AND a.revoked_at IS NULL AND b.permission_code=ANY($2::text[])`,
    [targetStaffId, missing.map(({ code }) => code)]);
  if (missing.some(({ code }) => !result.rows.some(({ permission_code }) => permission_code === code))) {
    throw new ForbiddenException();
  }
}
