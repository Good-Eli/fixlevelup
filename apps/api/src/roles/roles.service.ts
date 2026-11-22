import { randomUUID } from 'node:crypto';
import { ConflictException, ForbiddenException, HttpException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import type { PoolClient } from 'pg';
import { AUTHORIZATION_SERVICE } from '../authz/authorization.resources.js';
import { isSystemAdmin } from '../authz/authorization.service.js';
import type { AuthorizationServiceApi, SessionProof, StaffWriteContext } from '../authz/authorization.service.js';
import { GLOBAL_SCOPE, isCapability, isP03Capability, isPermissionCode, P03_CAPABILITY_METADATA, PERMISSION_CONTRACT, PROTECTED_CAPABILITIES } from '../authz/capability.js';
import type { Capability, GrantScope } from '../authz/capability.js';
import { staffReadFilter } from '../staff/staff-policy.js';
import type { StaffDto } from '../staff/staff.service.js';
import { catalogEntry, checkReplacement, grantableScopes } from './role-policy.js';
import type { MetadataPatch, PermissionDto, RoleGrant } from './role-policy.js';

interface RoleRecord {
  id: string; code: string; name: string; description: string; type: 'SYSTEM' | 'CUSTOM'; status: 'ACTIVE' | 'ARCHIVED';
  version: number; updatedAt: Date; updatedBy: string | null;
}
export interface RoleDto extends RoleRecord { assignedCount: number | null; activeAssignedCount: number | null; permissions: RoleGrant[] }
interface StoredGrant { code: string; scope: string; module: string; active: boolean; protected: boolean | null }
interface Projection extends Omit<RoleDto, 'permissions'> { grants: StoredGrant[] }
type RoleReceipt = Pick<RoleDto, 'id' | 'version'>;
export type RoleResult = RoleDto | RoleReceipt;
const columns = `r.id,r.code,r.name,r.description,r.role_type AS type,r.status,r.version,r.updated_at AS "updatedAt"`;

async function catalog(client: PoolClient): Promise<PermissionDto[]> {
  const result = await client.query<{ code: string; module: string; description: string; protected: boolean }>(
    'SELECT code,module,description,protected FROM foundation.permissions WHERE active ORDER BY module,code');
  return result.rows.map(catalogEntry).filter((p) => p !== null);
}

/** All scalar counts use the same filter as the member endpoint. NULL means the caller is
 * not entitled to staff data, not that the role is unused. The archive invariant uses its
 * own unrestricted EXISTS test, never a filtered response count. */
async function projected(ctx: StaffWriteContext, id: string | null): Promise<RoleDto[]> {
  const result = await ctx.client.query<Projection>(`WITH visible AS (
    SELECT s.id,a.role_id,s.employment_state FROM foundation.staff s
    JOIN foundation.staff_role_assignments a ON a.staff_id=s.id AND a.revoked_at IS NULL
    JOIN foundation.roles r ON r.id=a.role_id
    WHERE $2 AND ${staffReadFilter(ctx.role, '$3', '$4')}
  ), counts AS (
    SELECT role_id,count(*)::int AS total,(count(*) FILTER (WHERE employment_state='ACTIVE'))::int AS active
    FROM visible GROUP BY role_id
  ) SELECT ${columns}, editor.id AS "updatedBy", CASE WHEN $2 THEN COALESCE(counts.total,0) END AS "assignedCount",
    CASE WHEN $2 THEN COALESCE(counts.active,0) END AS "activeAssignedCount",
    COALESCE((SELECT jsonb_agg(jsonb_build_object('code',p.code,'scope',rp.scope_type,'module',p.module,'active',p.active,'protected',p.protected) ORDER BY p.code)
      FROM foundation.role_permissions rp JOIN foundation.permissions p ON p.code=rp.permission_code
      WHERE rp.role_id=r.id AND rp.enabled),'[]'::jsonb) AS grants
    FROM foundation.roles r LEFT JOIN counts ON counts.role_id=r.id LEFT JOIN visible editor ON editor.id=r.updated_by
    WHERE ($1::uuid IS NULL OR r.id=$1) ORDER BY r.code`,
  [id, ctx.permissions.includes('staff.read'), ctx.permissions.includes('staff.self.read'), ctx.staffId]);
  return result.rows.map(({ grants, ...role }) => {
    const permissions: RoleGrant[] = [];
    for (const g of grants) {
      if (!g.active) { continue; }
      if (isCapability(g.code)) {
        if (PERMISSION_CONTRACT[g.code] === g.scope && PROTECTED_CAPABILITIES.includes(g.code) === g.protected
          && (!g.protected || isSystemAdmin(role))) { permissions.push({ code: g.code, scope: PERMISSION_CONTRACT[g.code] }); }
        continue;
      }
      // Display only the scopes this role is allowed to store. A P03 catalog collision or
      // protected-domain drift must not become a delegable (or visible) grant.
      if (!isPermissionCode(g.code)) { continue; }
      if (isP03Capability(g.code) && (g.protected !== false || g.module !== P03_CAPABILITY_METADATA[g.code].module)) { continue; }
      const scope = g.scope as GrantScope;
      if (!grantableScopes(g.code, role).includes(scope)) { continue; }
      permissions.push({ code: g.code, scope });
    }
    return { ...role, permissions };
  });
}
async function detail(ctx: StaffWriteContext, id: string): Promise<RoleDto> {
  const [role] = await projected(ctx, id);
  if (!role) { throw new NotFoundException(); }
  return role;
}
async function result(ctx: StaffWriteContext, id: string, version: number): Promise<RoleResult> {
  return ctx.permissions.includes('roles.read') ? detail(ctx, id) : { id, version };
}
async function writable(ctx: StaffWriteContext, id: string, version: number, customOnly: boolean): Promise<RoleRecord> {
  if (!isSystemAdmin(ctx.role)) { throw new ForbiddenException(); }
  const current = (await ctx.client.query<RoleRecord>(`SELECT ${columns},r.updated_by AS "updatedBy" FROM foundation.roles r WHERE id=$1 FOR UPDATE`, [id])).rows[0];
  if (!current) { throw new NotFoundException(); }
  if (current.version !== version) { throw new HttpException('Precondition Failed', 412); }
  if (current.status !== 'ACTIVE' || (customOnly && current.type !== 'CUSTOM')) { throw new ConflictException(); }
  return current;
}
async function audit(ctx: StaffWriteContext, operation: string, objectId: string, oldValue: unknown, newValue: unknown): Promise<void> {
  await ctx.client.query('INSERT INTO foundation.audit_logs(id,operation,correlation_id,details) VALUES ($1,$2,$3,$4::jsonb)',
    [randomUUID(), operation, randomUUID(), JSON.stringify({ by: ctx.staffId, target: objectId, old: oldValue, new: newValue })]);
}
// Free-form metadata can contain secrets pasted by mistake. Record which fields changed,
// not raw user text (or a dictionary-attackable hash). Other diff fields are server enums/ids.
function metadataDiff(before: MetadataPatch | null, after: Required<MetadataPatch>) {
  return { nameChanged: before?.name !== after.name, descriptionChanged: before?.description !== after.description };
}

@Injectable()
export class RolesService {
  constructor(@Inject(AUTHORIZATION_SERVICE) private readonly auth: AuthorizationServiceApi) {}

  list(session: SessionProof): Promise<RoleDto[]> {
    return this.auth.authorizeForRead(session, 'roles.read', GLOBAL_SCOPE, (ctx) => projected(ctx, null));
  }
  get(session: SessionProof, id: string): Promise<RoleDto> {
    return this.auth.authorizeForRead(session, 'roles.read', GLOBAL_SCOPE, (ctx) => detail(ctx, id));
  }
  permissions(session: SessionProof): Promise<PermissionDto[]> {
    return this.auth.authorizeForRead(session, 'roles.read', GLOBAL_SCOPE, ({ client }) => catalog(client));
  }
  members(session: SessionProof, id: string): Promise<StaffDto[]> {
    return this.auth.authorizeForRead(session, 'roles.read', GLOBAL_SCOPE, async (ctx) => {
      if (!ctx.permissions.includes('staff.read')) { throw new ForbiddenException(); }
      if ((await ctx.client.query('SELECT id FROM foundation.roles WHERE id=$1', [id])).rowCount !== 1) { throw new NotFoundException(); }
      return (await ctx.client.query<StaffDto>(`SELECT s.id,r.code AS role,r.id AS "roleId",r.name AS "roleName",s.employment_state AS "employmentState",
        s.display_name AS "displayName",s.auth_version::float8+s.profile_version AS version
        FROM foundation.roles r JOIN foundation.staff_role_assignments a ON a.role_id=r.id AND a.revoked_at IS NULL
        JOIN foundation.staff s ON s.id=a.staff_id WHERE r.id=$1 AND ${staffReadFilter(ctx.role, '$2', '$3')} ORDER BY s.id`,
      [id, ctx.permissions.includes('staff.self.read'), ctx.staffId])).rows;
    });
  }

  create(session: SessionProof, meta: Required<MetadataPatch>): Promise<RoleResult> {
    return this.auth.authorizeForWrite(session, 'roles.create', GLOBAL_SCOPE, async (ctx) => {
      if (!isSystemAdmin(ctx.role)) { throw new ForbiddenException(); }
      const id = randomUUID();
      const code = `CUSTOM_${id.replaceAll('-', '').toUpperCase()}`;
      const insert = await ctx.client.query<RoleReceipt>(`INSERT INTO foundation.roles(id,code,name,description,created_by,updated_by)
        VALUES ($1,$2,$3,$4,$5,$5) RETURNING id,version`, [id, code, meta.name, meta.description, ctx.staffId]);
      const row = insert.rows[0];
      if (!row) { throw new ConflictException(); }
      await audit(ctx, 'ROLE_CREATED', id, null, { code, type: 'CUSTOM', status: 'ACTIVE', version: row.version, ...metadataDiff(null, meta) });
      return result(ctx, id, row.version);
    });
  }
  patch(session: SessionProof, id: string, version: number, patch: MetadataPatch): Promise<RoleResult> {
    return this.auth.authorizeForWrite(session, 'roles.update', GLOBAL_SCOPE, async (ctx) => {
      const old = await writable(ctx, id, version, true);
      const next = { name: patch.name ?? old.name, description: patch.description ?? old.description };
      const changes = metadataDiff(old, next);
      // Also advance on matching input: a write-only caller must not learn metadata via ETag comparisons.
      await ctx.client.query(`UPDATE foundation.roles SET name=$2,description=$3,version=version+1,updated_at=clock_timestamp(),updated_by=$4 WHERE id=$1`,
        [id, next.name, next.description, ctx.staffId]);
      await audit(ctx, 'ROLE_UPDATED', id, { version }, { version: version + 1, ...changes });
      return result(ctx, id, version + 1);
    });
  }
  archive(session: SessionProof, id: string, version: number): Promise<RoleResult> {
    return this.auth.authorizeForWrite(session, 'roles.archive', GLOBAL_SCOPE, async (ctx) => {
      await writable(ctx, id, version, true);
      const inUse = await ctx.client.query(`SELECT 1 FROM foundation.staff_role_assignments a JOIN foundation.staff s ON s.id=a.staff_id
        WHERE a.role_id=$1 AND a.revoked_at IS NULL AND s.employment_state='ACTIVE' LIMIT 1`, [id]);
      if (inUse.rowCount !== 0) { throw new ConflictException(); }
      await ctx.client.query("UPDATE foundation.roles SET status='ARCHIVED',version=version+1,updated_at=clock_timestamp(),updated_by=$2 WHERE id=$1", [id, ctx.staffId]);
      await audit(ctx, 'ROLE_ARCHIVED', id, { status: 'ACTIVE', version }, { status: 'ARCHIVED', version: version + 1 });
      return result(ctx, id, version + 1);
    });
  }
  replacePermissions(session: SessionProof, id: string, version: number, desired: RoleGrant[]): Promise<RoleResult> {
    return this.auth.authorizeForWrite(session, 'roles.permissions.manage', GLOBAL_SCOPE, async (ctx) => {
      const target = await writable(ctx, id, version, false);
      const available = await catalog(ctx.client);
      const before = await ctx.client.query<{ code: string; scope: string }>(
        'SELECT permission_code AS code,scope_type AS scope FROM foundation.role_permissions WHERE role_id=$1 AND enabled ORDER BY permission_code', [id]);
      const current: RoleGrant[] = [];
      for (const g of before.rows) {
        // Do not echo or silently re-enable unsupported/disabled grants from a drifted DB.
        const p = available.find((item) => item.code === g.code && item.scopes.includes(g.scope as GrantScope));
        if (!p || !grantableScopes(p.code, target).includes(g.scope as GrantScope)) { throw new ConflictException(); }
        current.push({ code: p.code, scope: g.scope as GrantScope });
      }
      checkReplacement(ctx, target, available, current, desired);
      // Compare code+scope: a geography grant may change CITY<->GLOBAL, which is a real change.
      const removed = current.filter((g) => !desired.some((n) => n.code === g.code && n.scope === g.scope));
      const added = desired.filter((g) => !current.some((o) => o.code === g.code && o.scope === g.scope));
      // Matching sets receive the same version/audit treatment as changed sets.
      if (removed.length) {
        await ctx.client.query('UPDATE foundation.role_permissions SET enabled=false WHERE role_id=$1 AND enabled AND permission_code=ANY($2::text[])', [id, removed.map((g) => g.code)]);
      }
      if (added.length) {
        await ctx.client.query(`INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type,enabled)
          SELECT $1,g.code,g.scope,true FROM unnest($2::text[],$3::text[]) AS g(code,scope)
          ON CONFLICT(role_id,permission_code) DO UPDATE SET enabled=EXCLUDED.enabled,scope_type=EXCLUDED.scope_type`,
        [id, added.map((g) => g.code), added.map((g) => g.scope)]);
      }
      await ctx.client.query('UPDATE foundation.roles SET version=version+1,updated_at=clock_timestamp(),updated_by=$2 WHERE id=$1', [id, ctx.staffId]);
      await audit(ctx, 'ROLE_PERMISSIONS_CHANGED', id, { version, removed }, { version: version + 1, added });
      // Geography grants are not staff capabilities: ctx.permissions stays the staff set.
      const permissions: readonly Capability[] = id === ctx.role.id ? desired.map((g) => g.code).filter(isCapability) : ctx.permissions;
      return result({ ...ctx, permissions }, id, version + 1);
    });
  }
}
