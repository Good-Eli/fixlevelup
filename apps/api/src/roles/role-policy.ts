import { BadRequestException, ForbiddenException } from '@nestjs/common';
import {
  GEO_SCOPE_CONTRACT, isCapability, isGeoCapability, isPermissionCode, PERMISSION_CONTRACT,
  PERMISSION_CODES, PROTECTED_CAPABILITIES,
} from '../authz/capability.js';
import type { GeoCapability, GrantScope, PermissionCode } from '../authz/capability.js';
import { isSystemAdmin } from '../authz/authorization.service.js';
import type { AccessView, EffectiveRole } from '../authz/authorization.service.js';

export interface RoleGrant { code: PermissionCode; scope: GrantScope }
export interface PermissionDto extends RoleGrant {
  description: string; module: string; protected: boolean;
  /** Every scope this code may legally carry. `scope` above is kept for existing clients
   * and always equals the first entry: a fixed staff scope or CITY for geography. */
  scopes: readonly GrantScope[];
}
export interface MetadataPatch { name?: string; description?: string }

function fields(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
    || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
    || Object.keys(value).some((key) => !allowed.includes(key))) { throw new BadRequestException(); }
  return value as Record<string, unknown>;
}
function text(value: unknown, limit: number, required: boolean): string {
  if (typeof value !== 'string' || /[\p{Cc}\p{Cf}\p{Cs}]/u.test(value)) { throw new BadRequestException(); }
  const normalized = value.trim();
  // PostgreSQL varchar(n) limits Unicode code points, not UTF-16 units or graphemes.
  if (Array.from(normalized).length > limit || (required && !normalized)) { throw new BadRequestException(); }
  return normalized;
}
export function metadataPatch(body: unknown): MetadataPatch {
  const obj = fields(body, ['name', 'description']);
  if (!Object.keys(obj).length) { throw new BadRequestException(); }
  const patch: MetadataPatch = {};
  if (Object.hasOwn(obj, 'name')) { patch.name = text(obj['name'], 80, true); }
  if (Object.hasOwn(obj, 'description')) { patch.description = text(obj['description'], 500, false); }
  return patch;
}
export function createMetadata(body: unknown): Required<MetadataPatch> {
  const { name, description } = metadataPatch(body);
  if (name === undefined || description === undefined) { throw new BadRequestException(); }
  return { name, description };
}
export function emptyBody(body: unknown): void { fields(body, []); }

/** Scopes a role may legally store for one code. The staff dictionary keeps its fixed
 * scope. Geography is CITY on an ordinary role, GLOBAL only on the SYSTEM ADMIN role, and
 * `geography.publish` never belongs to a non-administrator or to the technician channel
 * role at all (migration 012 enforces the same rule in the database). */
export function grantableScopes(code: PermissionCode, target: Pick<EffectiveRole, 'type' | 'code'>): readonly GrantScope[] {
  if (isCapability(code)) { return [PERMISSION_CONTRACT[code]]; }
  if (target.type === 'SYSTEM' && target.code === 'TECHNICIAN') { return []; }
  const admin = isSystemAdmin({ id: '', type: target.type, code: target.code });
  if (code === 'geography.publish' && !admin) { return []; }
  return GEO_SCOPE_CONTRACT[code].filter((scope) => scope === 'CITY' || admin);
}

export function replacement(body: unknown): RoleGrant[] {
  const obj = fields(body, ['permissions']);
  const input = obj['permissions'];
  if (!Object.hasOwn(obj, 'permissions') || !Array.isArray(input) || input.length > PERMISSION_CODES.length) { throw new BadRequestException(); }
  const seen = new Set<PermissionCode>();
  return input.map((item: unknown): RoleGrant => {
    const entry = fields(item, ['code', 'scope']);
    const code = entry['code'];
    if (!Object.hasOwn(entry, 'code') || !Object.hasOwn(entry, 'scope') || !isPermissionCode(code) || seen.has(code)) { throw new BadRequestException(); }
    const scope = entry['scope'];
    // Parsing accepts every contract scope; the target-role and actor rules are applied
    // against the locked snapshot in checkReplacement.
    if (typeof scope !== 'string' || !grantableScopes(code, { type: 'SYSTEM', code: 'ADMIN' }).includes(scope as GrantScope)) { throw new BadRequestException(); }
    seen.add(code);
    return { code, scope: scope as GrantScope };
  });
}

/** A database catalog entry alone is not an implemented server contract. Geography rows
 * are never protected: protection would make the grant mandatory on every ADMIN, while
 * the owner's rule is an explicit individual grant only. */
export function catalogEntry(row: { code: string; description: string; module: string; protected: boolean }): PermissionDto | null {
  if (isCapability(row.code)) {
    if (row.protected !== PROTECTED_CAPABILITIES.includes(row.code)) { return null; }
    const scope = PERMISSION_CONTRACT[row.code];
    return { code: row.code, module: row.module, description: row.description, protected: row.protected, scope, scopes: [scope] };
  }
  if (!isGeoCapability(row.code) || row.protected) { return null; }
  const scopes = GEO_SCOPE_CONTRACT[row.code];
  return { code: row.code, module: row.module, description: row.description, protected: false, scope: 'CITY', scopes };
}

/** The actor may delegate a geography code only at the scope it holds itself. */
function holdsGlobalGeo(actor: AccessView, code: GeoCapability): boolean {
  return (actor.geoPermissions ?? []).some((grant) => grant.code === code && grant.scope === 'GLOBAL');
}

/** Called on the locked policy snapshot, before making any permission write. The list is
 * authoritative: we neither silently preserve omitted ADMIN grants nor synthesize grants. */
export function checkReplacement(actor: AccessView, target: EffectiveRole, catalog: readonly PermissionDto[], current: readonly RoleGrant[], desired: readonly RoleGrant[]): void {
  if (!isSystemAdmin(actor.role)) { throw new ForbiddenException(); }
  const targetAdmin = isSystemAdmin(target);
  if (targetAdmin && PROTECTED_CAPABILITIES.some((code) => !desired.some((g) => g.code === code))) { throw new ForbiddenException(); }
  for (const grant of desired) {
    const item = catalog.find(({ code }) => code === grant.code);
    if (!item || !grantableScopes(grant.code, target).includes(grant.scope)) { throw new BadRequestException(); }
    // Keeping an existing grant is not delegation, but a blind writer must not
    // distinguish "already enabled" from "not enabled" via a 200/403 response.
    const mayRetain = actor.role.id !== target.id && actor.permissions.includes('roles.read')
      && current.some((g) => g.code === grant.code && g.scope === grant.scope);
    if (isCapability(grant.code)) {
      if ((item.protected && !targetAdmin) || (!actor.permissions.includes(grant.code) && !mayRetain)) { throw new ForbiddenException(); }
      continue;
    }
    // Geography: an administrator may hand out only codes it holds at GLOBAL, and a
    // non-administrator target can never receive GLOBAL or publish.
    if (!holdsGlobalGeo(actor, grant.code) && !mayRetain) { throw new ForbiddenException(); }
  }
}
