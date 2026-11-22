import { randomUUID } from 'node:crypto';
import { ConflictException, ForbiddenException, HttpException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import type { PoolClient } from 'pg';
import { AUTHORIZATION_SERVICE } from '../authz/authorization.resources.js';
import { AuthorizationError, isSystemAdmin } from '../authz/authorization.service.js';
import type { AuthorizationServiceApi, EffectiveRole, SessionProof, StaffWriteContext } from '../authz/authorization.service.js';
import {
  GLOBAL_SCOPE, isCapability, isGeoCapability, isP03Capability, P03_CAPABILITIES, P03_CAPABILITY_METADATA, PROTECTED_CAPABILITIES,
} from '../authz/capability.js';
import { holdsGlobalP03, p03GrantableScopes } from '../authz/p03-grants.js';
import { checkTarget, nextChannelMarker, staffReadFilter, staffTargetFilter } from './staff-policy.js';
import type { ChannelMarker, StaffTarget } from './staff-policy.js';

type InitialRole = 'MANAGER' | 'TECHNICIAN';
interface StaffRow {
  id: string; role: string; role_id: string; role_name: string; role_type: EffectiveRole['type']; channel_marker: ChannelMarker;
  employment_state: 'ACTIVE' | 'INACTIVE'; display_name: string | null; auth_version: number; profile_version: number;
}
export interface StaffDto {
  id: string; role: string; roleId: string; roleName: string; employmentState: StaffRow['employment_state']; displayName: string | null; version: number;
}
const projection = `SELECT s.id, r.code AS role, r.id AS role_id, r.name AS role_name, r.role_type, s.role AS channel_marker,
  s.employment_state, s.display_name, s.auth_version, s.profile_version
  FROM foundation.staff s
  JOIN foundation.staff_role_assignments a ON a.staff_id=s.id AND a.revoked_at IS NULL
  JOIN foundation.roles r ON r.id=a.role_id`;
const dto = (s: StaffRow): StaffDto => ({ id: s.id, role: s.role, roleId: s.role_id, roleName: s.role_name,
  employmentState: s.employment_state, displayName: s.display_name, version: s.auth_version + s.profile_version });
const scope = (t: StaffTarget) => t.kind === 'self' ? { kind: 'SELF' as const, ownerId: t.id } : GLOBAL_SCOPE;

/** SQL ownership / target filtering happens in the transaction that rechecked both
 * authorization and the channel session. Ineligible and nonexistent targets are indistinguishable. */
async function loadTarget(ctx: StaffWriteContext, target: StaffTarget, write: boolean): Promise<StaffRow> {
  checkTarget(ctx.principal.staffId, target, write);
  if (!write && target.kind === 'general' && target.id.toLowerCase() === ctx.staffId.toLowerCase() && !ctx.permissions.includes('staff.self.read')) { throw new NotFoundException(); }
  const visible = target.kind === 'self' ? 's.id=$2' : staffTargetFilter(ctx.role);
  const result = await ctx.client.query<StaffRow>(`${projection} WHERE s.id=$1 AND ${visible}${write ? ' FOR UPDATE OF s' : ''}`,
    target.kind === 'self' ? [target.id, ctx.principal.staffId] : [target.id]);
  if (!result.rows[0]) { throw new NotFoundException(); }
  return result.rows[0];
}
export type StaffMutationDto = StaffDto | Pick<StaffDto, 'id' | 'version'>;
async function acknowledgement(ctx: StaffWriteContext, target: StaffTarget, version: number): Promise<StaffMutationDto> {
  if (!ctx.permissions.includes(target.kind === 'self' ? 'staff.self.read' : 'staff.read')) { return { id: target.id, version }; }
  return dto(await loadTarget(ctx, target, false));
}
function requireEditable(row: StaffRow, expected: number): void {
  if (row.employment_state !== 'ACTIVE') { throw new ConflictException(); }
  if (row.auth_version + row.profile_version !== expected) { throw new HttpException('Precondition Failed', 412); }
}
function requireAssignmentAuthority(ctx: StaffWriteContext): void {
  if (!isSystemAdmin(ctx.role) || !ctx.permissions.includes('staff.role.assign')) { throw new ForbiddenException(); }
}
/** Even an administrator may only delegate general grants they presently hold. SELF
 * grants bind to the new subject's own resources and do not expand delegated authority.
 * Geography and P03 require same-code GLOBAL. P03 checks every enabled stored role
 * grant, including drifted catalog rows and shared CUSTOM roles assigned to TG staff. */
async function requireDelegable(ctx: StaffWriteContext, roleId: string): Promise<void> {
  const rows = (await ctx.client.query<{
    code: string; scope: string; role_type: EffectiveRole['type']; role_code: string;
    active: boolean | null; protected: boolean | null; module: string | null;
  }>(
    `SELECT rp.permission_code AS code, rp.scope_type AS scope, r.role_type, r.code AS role_code, p.active, p.protected, p.module
     FROM foundation.role_permissions rp
     LEFT JOIN foundation.permissions p ON p.code=rp.permission_code
     JOIN foundation.roles r ON r.id=rp.role_id
     WHERE rp.role_id=$1 AND rp.enabled
       AND (rp.permission_code=ANY($2::text[]) OR (p.active
         AND NOT (p.code IN ('staff.self.read','staff.self.update','staff.self.deactivate')
           AND rp.scope_type='SELF' AND NOT p.protected)))`, [roleId, P03_CAPABILITIES])).rows;
  const globalGeo = new Set((ctx.geoPermissions ?? []).filter((g) => g.scope === 'GLOBAL').map((g) => g.code));
  for (const row of rows) {
    if (isP03Capability(row.code)) {
      if (row.active !== true || row.protected !== false || row.module !== P03_CAPABILITY_METADATA[row.code].module
        || (row.scope !== 'CITY' && row.scope !== 'GLOBAL')
        || !p03GrantableScopes(row.code, { type: row.role_type, code: row.role_code }).includes(row.scope)
        || !holdsGlobalP03(ctx, row.code)) { throw new ForbiddenException(); }
      continue;
    }
    if (isCapability(row.code)) {
      if (!ctx.permissions.includes(row.code)) { throw new ForbiddenException(); }
      continue;
    }
    if (!isGeoCapability(row.code) || !globalGeo.has(row.code)) { throw new ForbiddenException(); }
    const targetAdmin = row.role_type === 'SYSTEM' && row.role_code === 'ADMIN';
    if (row.scope !== 'CITY' && !targetAdmin) { throw new ForbiddenException(); }
    if (row.code === 'geography.publish' && !targetAdmin) { throw new ForbiddenException(); }
  }
}
async function otherUsableAdmin(client: PoolClient, target: StaffRow): Promise<void> {
  if (target.role_type !== 'SYSTEM' || target.role !== 'ADMIN') { return; }
  // Counting mere staff rows would allow an uncredentialed, Telegram-only or
  // otherwise unusable replacement to strand the administrative surface.
  const result = await client.query(`SELECT 1 FROM foundation.staff s
    JOIN foundation.staff_web_credentials c ON c.staff_id=s.id
    JOIN foundation.staff_role_assignments a ON a.staff_id=s.id AND a.revoked_at IS NULL
    JOIN foundation.roles r ON r.id=a.role_id AND r.role_type='SYSTEM' AND r.code='ADMIN' AND r.status='ACTIVE'
    WHERE s.id<>$1 AND s.role='ADMIN' AND s.employment_state='ACTIVE' AND NOT EXISTS (
      SELECT 1 FROM unnest($2::text[]) AS required(code) WHERE NOT EXISTS (
        SELECT 1 FROM foundation.role_permissions rp JOIN foundation.permissions p ON p.code=rp.permission_code
        WHERE rp.role_id=r.id AND rp.permission_code=required.code AND rp.enabled AND rp.scope_type='GLOBAL' AND p.protected AND p.active)) LIMIT 1`,
  [target.id, PROTECTED_CAPABILITIES]);
  if (result.rowCount !== 1) { throw new ConflictException(); }
}
async function record(client: PoolClient, action: string, details: Record<string, string | number | null>): Promise<void> {
  await client.query('INSERT INTO foundation.audit_logs (id,operation,correlation_id,details) VALUES ($1,$2,$3,$4::jsonb)',
    [randomUUID(), action, randomUUID(), JSON.stringify(details)]);
}
async function addAssignment(client: PoolClient, id: string, roleId: string, by: string): Promise<void> {
  await client.query('INSERT INTO foundation.staff_role_assignments (id,staff_id,role_id,assigned_by) VALUES ($1,$2,$3,$4)', [randomUUID(), id, roleId, by]);
}

@Injectable()
export class StaffService {
  constructor(@Inject(AUTHORIZATION_SERVICE) private readonly auth: AuthorizationServiceApi) {}

  list(proof: SessionProof): Promise<StaffDto[]> {
    return this.auth.authorizeForRead(proof, 'staff.read', GLOBAL_SCOPE, async (ctx) =>
      (await ctx.client.query<StaffRow>(`${projection} WHERE ${staffReadFilter(ctx.role, '$2', '$1')} ORDER BY s.id`,
        [ctx.staffId, ctx.permissions.includes('staff.self.read')])).rows.map(dto));
  }
  get(proof: SessionProof, target: StaffTarget): Promise<StaffDto> {
    return this.auth.authorizeForRead(proof, target.kind === 'self' ? 'staff.self.read' : 'staff.read', scope(target),
      async (ctx) => dto(await loadTarget(ctx, target, false)));
  }
  create(proof: SessionProof, role: InitialRole, name: string | null): Promise<StaffMutationDto> {
    return this.auth.authorizeForWrite(proof, 'staff.create', GLOBAL_SCOPE, async (ctx) => {
      if (!['TECHNICIAN', 'MANAGER'].includes(role)) { throw new ForbiddenException(); }
      if (role !== 'TECHNICIAN') { requireAssignmentAuthority(ctx); }
      const assigned = (await ctx.client.query<{ id: string }>(
        "SELECT id FROM foundation.roles WHERE code=$1 AND role_type='SYSTEM' AND status='ACTIVE'", [role])).rows[0];
      if (!assigned) { throw new ConflictException(); }
      await requireDelegable(ctx, assigned.id);
      const id = randomUUID();
      await ctx.client.query(`INSERT INTO foundation.staff (id,role,employment_state,auth_version,display_name)
        VALUES ($1,$2,'ACTIVE',0,$3)`, [id, role, name]);
      await addAssignment(ctx.client, id, assigned.id, ctx.staffId);
      await record(ctx.client, 'STAFF_CREATED', { by: ctx.staffId, created: id });
      await record(ctx.client, 'STAFF_ROLE_ASSIGNED', { by: ctx.staffId, target: id, oldRoleId: null, newRoleId: assigned.id });
      return acknowledgement(ctx, { kind: 'general', id }, 0);
    });
  }
  update(proof: SessionProof, target: StaffTarget, expected: number, name: string): Promise<StaffMutationDto> {
    return this.auth.authorizeForWrite(proof, target.kind === 'self' ? 'staff.self.update' : 'staff.update', scope(target), async (ctx) => {
      const row = await loadTarget(ctx, target, true);
      requireEditable(row, expected);
      // A write-only grantee must not learn the previous name by comparing ETags
      // after a guessed no-op. Each accepted profile edit advances the profile version.
      await ctx.client.query('UPDATE foundation.staff SET display_name=$2, profile_version=profile_version+1 WHERE id=$1', [row.id, name]);
      await record(ctx.client, 'STAFF_PROFILE_UPDATED', { by: ctx.staffId, target: row.id, field: 'display_name', previousVersion: expected, version: expected + 1 });
      return acknowledgement(ctx, target, expected + 1);
    });
  }
  deactivate(proof: SessionProof, target: StaffTarget, expected: number): Promise<StaffMutationDto> {
    return this.auth.authorizeForWrite(proof, target.kind === 'self' ? 'staff.self.deactivate' : 'staff.deactivate', scope(target), async (ctx) => {
      const row = await loadTarget(ctx, target, true);
      requireEditable(row, expected);
      await otherUsableAdmin(ctx.client, row);
      // Preserve P02-06 audit and history; stale auth_version rejects both channels.
      await ctx.client.query("UPDATE foundation.staff SET employment_state='INACTIVE', auth_version=auth_version+1 WHERE id=$1", [row.id]);
      await record(ctx.client, 'STAFF_DEACTIVATED', { by: ctx.staffId, target: row.id });
      return acknowledgement(ctx, target, expected + 1);
    });
  }
  assign(proof: SessionProof, id: string, expected: number, roleId: string): Promise<StaffMutationDto> {
    const target: StaffTarget = { kind: 'general', id };
    return this.auth.authorizeForWrite(proof, 'staff.role.assign', GLOBAL_SCOPE, async (ctx) => {
      requireAssignmentAuthority(ctx);
      const row = await loadTarget(ctx, target, true);
      requireEditable(row, expected);
      const next = (await ctx.client.query<EffectiveRole & { status: string }>(
        'SELECT id,code,role_type AS type,status FROM foundation.roles WHERE id=$1', [roleId])).rows[0];
      if (!next) { throw new NotFoundException(); }
      if (next.status !== 'ACTIVE' || next.id === row.role_id) { throw new ConflictException(); }
      await otherUsableAdmin(ctx.client, row);
      await requireDelegable(ctx, roleId);
      const marker = nextChannelMarker(row.channel_marker, next);
      if (isSystemAdmin(next) && (await ctx.client.query('SELECT 1 FROM foundation.staff_web_credentials WHERE staff_id=$1', [row.id])).rowCount !== 1) {
        throw new ConflictException();
      }
      // The replacement's assigned_at DEFAULT uses this same statement_timestamp(),
      // so even a transaction queued for a long time has contiguous history intervals.
      const changed = await ctx.client.query(`WITH closed AS (
          UPDATE foundation.staff_role_assignments SET revoked_by=$3,revoked_at=statement_timestamp()
          WHERE staff_id=$1 AND role_id=$2 AND revoked_at IS NULL RETURNING staff_id)
        INSERT INTO foundation.staff_role_assignments (id,staff_id,role_id,assigned_by)
        SELECT $4,staff_id,$5,$3 FROM closed`, [row.id, row.role_id, ctx.staffId, randomUUID(), roleId]);
      if (changed.rowCount !== 1) { throw new AuthorizationError('FAILED'); }
      await ctx.client.query('UPDATE foundation.staff SET role=$2,auth_version=auth_version+1 WHERE id=$1', [row.id, marker]);
      await record(ctx.client, 'STAFF_ROLE_ASSIGNED', { by: ctx.staffId, target: row.id, oldRoleId: row.role_id, newRoleId: roleId });
      return acknowledgement(ctx, target, expected + 1);
    });
  }
}
