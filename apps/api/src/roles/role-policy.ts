import { BadRequestException, ConflictException, ForbiddenException } from '@nestjs/common';
import {
  GEO_SCOPE_CONTRACT, isCapability, isGeoCapability, isP03Capability, isP04Capability, isP05Capability, isPermissionCode,
  P03_CAPABILITY_METADATA, P04_SCOPE_CONTRACT, P05_CAPABILITIES, P05_MODULE, P05_SCOPE_CONTRACT, p04Module, PERMISSION_CONTRACT,
  PERMISSION_CODES, PROTECTED_CAPABILITIES,
} from '../authz/capability.js';
import type { GeoCapability, GrantScope, P05Capability, PermissionCode } from '../authz/capability.js';
import { isSystemAdmin } from '../authz/authorization.service.js';
import type { AccessView, EffectiveRole } from '../authz/authorization.service.js';
import { holdsGlobalP03, p03GrantableScopes } from '../authz/p03-grants.js';
import { holdsGlobalP04, p04GrantableScopes } from '../authz/p04-grants.js';
import { p05GrantableScopes } from '../authz/p05-grants.js';

export interface RoleGrant { code: PermissionCode; scope: GrantScope }
export interface PermissionDto extends RoleGrant {
  description: string; module: string; protected: boolean;
  /** Every scope this code may legally carry. `scope` above is kept for existing clients
   * and always equals the first contract entry. */
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
  if (isP03Capability(code)) { return p03GrantableScopes(code, target); }
  if (isP04Capability(code)) { return p04GrantableScopes(code, target); }
  if (isP05Capability(code)) { return p05GrantableScopes(code, target); }
  if (target.type === 'SYSTEM' && target.code === 'TECHNICIAN') { return []; }
  const admin = isSystemAdmin({ id: '', type: target.type, code: target.code });
  if (code === 'geography.publish' && !admin) { return []; }
  return GEO_SCOPE_CONTRACT[code].filter((scope) => scope === 'CITY' || admin);
}

export function replacement(body: unknown): RoleGrant[] {
  return [...permissionReplacement(body).grants];
}

export interface PermissionReplacement { readonly grants: readonly RoleGrant[]; readonly revokeP05: readonly P05Capability[] }

/** The legacy body is `{permissions:[...]}` and keeps its exact meaning. P05 grants are
 * never issued or expanded through this wire; the only additive field is an explicit
 * revocation list, because a pre-P05 client cannot express a revoke and must not have
 * one inferred from an omission. */
export function permissionReplacement(body: unknown): PermissionReplacement {
  const obj = fields(body, ['permissions', 'revokeP05Permissions']);
  const input = obj['permissions'];
  if (!Object.hasOwn(obj, 'permissions') || !Array.isArray(input) || input.length > PERMISSION_CODES.length) { throw new BadRequestException(); }
  const seen = new Set<PermissionCode>();
  const grants = input.map((item: unknown): RoleGrant => {
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
  const raw = obj['revokeP05Permissions'];
  if (raw === undefined) { return { grants, revokeP05: [] }; }
  if (!Array.isArray(raw) || raw.length > P05_CAPABILITIES.length) { throw new BadRequestException(); }
  const revokeP05: P05Capability[] = [];
  for (const item of raw) {
    if (!isP05Capability(item) || revokeP05.includes(item)) { throw new BadRequestException(); }
    revokeP05.push(item);
  }
  return { grants, revokeP05 };
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
  if (isP03Capability(row.code)) {
    const meta = P03_CAPABILITY_METADATA[row.code];
    const [scope] = meta.scopes;
    if (row.protected || row.module !== meta.module || scope === undefined) { return null; }
    return { ...row, code: row.code, scope, scopes: meta.scopes };
  }
  if (isP04Capability(row.code)) {
    if (row.protected || row.module !== p04Module(row.code)) { return null; }
    const scopes = P04_SCOPE_CONTRACT[row.code];
    return { ...row, code: row.code, scope: scopes[0], scopes };
  }
  if (isP05Capability(row.code)) {
    // The whole P05 contract lives in the exact `requests` module and is never protected.
    if (row.protected || row.module !== P05_MODULE) { return null; }
    const scopes = P05_SCOPE_CONTRACT[row.code];
    return { ...row, code: row.code, scope: scopes[0], scopes };
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
export function checkReplacement(actor: AccessView, target: EffectiveRole, catalog: readonly PermissionDto[],
  current: readonly RoleGrant[], desired: readonly RoleGrant[], revokeP05: readonly P05Capability[] = []): void {
  if (!isSystemAdmin(actor.role)) { throw new ForbiddenException(); }
  const targetAdmin = isSystemAdmin(target);
  if (targetAdmin && PROTECTED_CAPABILITIES.some((code) => !desired.some((g) => g.code === code))) { throw new ForbiddenException(); }
  // P05 is a closed, operator-provisioned surface. The ordinary release composition
  // never issues or expands it through this writer:
  //  - a desired pair must be exactly an already enabled pair (retention, not delegation);
  //  - an enabled grant omitted from the legacy body is refused as an incomplete
  //    authority set instead of being silently preserved or silently revoked;
  //  - a revocation must be explicit and name a currently enabled P05 grant.
  const p05Current = current.filter((grant): grant is RoleGrant & { code: P05Capability } => isP05Capability(grant.code));
  const p05Desired = desired.filter((grant): grant is RoleGrant & { code: P05Capability } => isP05Capability(grant.code));
  const revoked = new Set<P05Capability>(revokeP05);
  for (const code of revoked) {
    if (!p05Current.some((grant) => grant.code === code)) { throw new ConflictException(); }
    if (p05Desired.some((grant) => grant.code === code)) { throw new BadRequestException(); }
  }
  for (const grant of p05Current) {
    if (revoked.has(grant.code)) { continue; }
    if (!p05Desired.some((next) => next.code === grant.code && next.scope === grant.scope)) { throw new ConflictException(); }
  }
  for (const grant of p05Desired) {
    if (!p05Current.some((existing) => existing.code === grant.code && existing.scope === grant.scope)) {
      throw new ForbiddenException();
    }
  }
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
    if (isP05Capability(grant.code)) {
      // Only retention reached this point; it never confers a new P05 right on the actor.
      continue;
    }
    // Domain grants are delegable only when the actor independently owns that exact
    // code at GLOBAL (or retains the exact visible grant on another role).
    if (isP04Capability(grant.code)) {
      if (!actor.permissions.includes('roles.permissions.manage') || (!holdsGlobalP04(actor, grant.code) && !mayRetain)) {
        throw new ForbiddenException();
      }
      continue;
    }
    const holdsGlobal = isP03Capability(grant.code) ? holdsGlobalP03(actor, grant.code) : holdsGlobalGeo(actor, grant.code);
    if (!holdsGlobal && !mayRetain) { throw new ForbiddenException(); }
  }
}
