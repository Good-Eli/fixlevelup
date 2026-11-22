import { ForbiddenException } from '@nestjs/common';
import type { PoolClient } from 'pg';
import type { AccessView, EffectiveRole, StaffWriteContext } from './authorization.service.js';
import {
  isP03Capability, P03_CAPABILITIES, P03_CAPABILITY_METADATA,
} from './capability.js';
import type { P03Capability, P03Grant, P03Scope } from './capability.js';
import type { Principal } from './principal.js';

type RoleIdentity = Pick<EffectiveRole, 'type' | 'code'>;
const EMPTY: readonly P03Grant[] = Object.freeze([]);

/** Stored scope is independent of a CUSTOM assignee's channel: a shared role can be
 * assigned to web or Telegram staff, but the effective-grant projection masks Telegram. */
export function p03GrantableScopes(code: P03Capability, role: RoleIdentity): readonly P03Scope[] {
  const meta = P03_CAPABILITY_METADATA[code];
  if (role.type === 'CUSTOM' || role.code === 'MANAGER') {
    if (meta.systemAdminOnly) { return []; }
    return meta.globalSystemAdminOnly ? meta.scopes.filter((scope) => scope === 'CITY') : meta.scopes;
  }
  if (role.code === 'ADMIN') { return meta.scopes; }
  return [];
}

export function holdsGlobalP03(actor: AccessView, code: P03Capability): boolean {
  return (actor.p03Permissions ?? []).some((grant) => grant.code === code && grant.scope === 'GLOBAL');
}

interface GrantRow { code: string; scope: P03Scope; source: string }

/** Read from the current assignment only. Source rows can only be issued by the trusted
 * bootstrap function; the runtime role has no access to the original bootstrap marker. */
export async function effectiveP03Grants(client: PoolClient, principal: Principal, role: EffectiveRole): Promise<readonly P03Grant[]> {
  if (principal.kind !== 'staff-web') { return EMPTY; }
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
       FROM current_assignment ca JOIN foundation.p03_bootstrap_permissions b ON b.assignment_id=ca.id
       WHERE b.revoked_at IS NULL AND b.permission_code=ANY($3::text[])
     )
     SELECT g.code,g.scope,g.source FROM granted g JOIN foundation.permissions p ON p.code=g.code
     WHERE p.active AND NOT p.protected AND p.module=split_part(p.code,'.',1)
     ORDER BY g.code,g.source`, [principal.staffId, role.id, P03_CAPABILITIES]);
  const byCode = new Map<P03Capability, P03Grant>();
  for (const { code, scope, source } of result.rows) {
    if (!isP03Capability(code) || !p03GrantableScopes(code, role).includes(scope)) { continue; }
    if (source !== 'ROLE' && (source !== 'BOOTSTRAP' || scope !== 'GLOBAL' || role.type !== 'SYSTEM' || role.code !== 'ADMIN')) { continue; }
    if (!byCode.has(code) || scope === 'GLOBAL') { byCode.set(code, Object.freeze({ code, scope })); }
  }
  return Object.freeze([...byCode.values()]);
}

/** Live administrative assignments only; a projection must independently check its own grant. */
export async function activeAdminCityIds(client: PoolClient, staffId: string): Promise<readonly string[]> {
  const result = await client.query<{ city_id: string }>(
    `SELECT city_id FROM foundation.staff_admin_city_assignments
     WHERE staff_id=$1 AND revoked_at IS NULL ORDER BY city_id`, [staffId]);
  return Object.freeze(result.rows.map((row) => row.city_id));
}

/** Caller holds the policy write lock and target staff lock, and calls this only for a new
 * administrative city, not replays or revocations. There is no personal CITY source. */
export async function requireP03CityExpansion(ctx: StaffWriteContext, targetStaffId: string): Promise<void> {
  const result = await ctx.client.query<{ code: string; role_type: EffectiveRole['type']; role_code: string }>(
    `SELECT p.code,r.role_type,r.code AS role_code
     FROM foundation.staff s
     JOIN foundation.staff_role_assignments a ON a.staff_id=s.id AND a.revoked_at IS NULL
     JOIN foundation.roles r ON r.id=a.role_id AND r.status='ACTIVE'
     JOIN foundation.role_permissions rp ON rp.role_id=r.id AND rp.enabled AND rp.scope_type='CITY'
     JOIN foundation.permissions p ON p.code=rp.permission_code AND p.active AND NOT p.protected
       AND p.module=split_part(p.code,'.',1)
     WHERE s.id=$1 AND s.employment_state='ACTIVE' AND s.role IN ('ADMIN','MANAGER')
       AND (r.role_type='CUSTOM' OR (r.role_type='SYSTEM' AND r.code=s.role))
       AND p.code=ANY($2::text[])
       AND NOT (r.role_type='SYSTEM' AND r.code='ADMIN' AND EXISTS (
         SELECT 1 FROM foundation.p03_bootstrap_permissions b
         WHERE b.assignment_id=a.id AND b.permission_code=p.code AND b.revoked_at IS NULL
       ))`, [targetStaffId, P03_CAPABILITIES]);
  for (const { code, role_type, role_code } of result.rows) {
    if (isP03Capability(code) && p03GrantableScopes(code, { type: role_type, code: role_code }).includes('CITY')
      && !holdsGlobalP03(ctx, code)) { throw new ForbiddenException(); }
  }
}
