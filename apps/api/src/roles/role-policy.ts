import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { isCapability, PERMISSION_CONTRACT, PROTECTED_CAPABILITIES, STAFF_CAPABILITIES } from '../authz/capability.js';
import type { Capability } from '../authz/capability.js';
import { isSystemAdmin } from '../authz/authorization.service.js';
import type { AccessView, EffectiveRole } from '../authz/authorization.service.js';

export interface RoleGrant { code: Capability; scope: 'GLOBAL' | 'SELF' }
export interface PermissionDto extends RoleGrant { description: string; module: string; protected: boolean }
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

export function replacement(body: unknown): RoleGrant[] {
  const obj = fields(body, ['permissions']);
  const input = obj['permissions'];
  if (!Object.hasOwn(obj, 'permissions') || !Array.isArray(input) || input.length > STAFF_CAPABILITIES.length) { throw new BadRequestException(); }
  const seen = new Set<Capability>();
  return input.map((item: unknown): RoleGrant => {
    const entry = fields(item, ['code', 'scope']);
    const code = entry['code'];
    if (!Object.hasOwn(entry, 'code') || !Object.hasOwn(entry, 'scope') || !isCapability(code)
      || entry['scope'] !== PERMISSION_CONTRACT[code] || seen.has(code)) { throw new BadRequestException(); }
    seen.add(code);
    return { code, scope: PERMISSION_CONTRACT[code] };
  });
}

/** A database catalog entry alone is not an implemented server contract. */
export function catalogEntry(row: { code: string; description: string; module: string; protected: boolean }): PermissionDto | null {
  if (!isCapability(row.code) || row.protected !== PROTECTED_CAPABILITIES.includes(row.code)) { return null; }
  return { code: row.code, module: row.module, description: row.description, protected: row.protected, scope: PERMISSION_CONTRACT[row.code] };
}

/** Called on the locked policy snapshot, before making any permission write. The list is
 * authoritative: we neither silently preserve omitted ADMIN grants nor synthesize grants. */
export function checkReplacement(actor: AccessView, target: EffectiveRole, catalog: readonly PermissionDto[], current: readonly RoleGrant[], desired: readonly RoleGrant[]): void {
  if (!isSystemAdmin(actor.role)) { throw new ForbiddenException(); }
  if (isSystemAdmin(target) && PROTECTED_CAPABILITIES.some((code) => !desired.some((g) => g.code === code))) { throw new ForbiddenException(); }
  for (const grant of desired) {
    const item = catalog.find(({ code }) => code === grant.code);
    if (!item || item.scope !== grant.scope) { throw new BadRequestException(); }
    const held = actor.permissions.includes(grant.code);
    // Keeping an existing grant is not delegation, but a blind writer must not
    // distinguish "already enabled" from "not enabled" via a 200/403 response.
    const mayRetain = actor.role.id !== target.id && actor.permissions.includes('roles.read')
      && current.some((g) => g.code === grant.code && g.scope === grant.scope);
    if ((item.protected && !isSystemAdmin(target)) || (!held && !mayRetain)) { throw new ForbiddenException(); }
  }
}
