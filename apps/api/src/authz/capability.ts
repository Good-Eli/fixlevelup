import { isP03Capability, P03_CAPABILITIES } from '@fixlevelup/p03-contracts';
import type { P03Capability } from '@fixlevelup/p03-contracts';

export { isP03Capability, P03_CAPABILITIES, P03_CAPABILITY_METADATA, P03_SCOPE_CONTRACT } from '@fixlevelup/p03-contracts';
export type { P03Capability, P03Grant, P03Scope } from '@fixlevelup/p03-contracts';

/** Known operation contracts, not grants. A new entry does not authorize anyone:
 * the DB catalog, scope and an enabled permission on the current role must also match. */
export const PERMISSION_CONTRACT = {
  'staff.self.read': 'SELF', 'staff.self.update': 'SELF', 'staff.self.deactivate': 'SELF',
  'staff.read': 'GLOBAL', 'staff.create': 'GLOBAL', 'staff.update': 'GLOBAL', 'staff.deactivate': 'GLOBAL',
  'roles.read': 'GLOBAL', 'roles.create': 'GLOBAL', 'roles.update': 'GLOBAL', 'roles.archive': 'GLOBAL',
  'roles.permissions.manage': 'GLOBAL', 'staff.role.assign': 'GLOBAL',
} as const;
export type Capability = keyof typeof PERMISSION_CONTRACT;
export const STAFF_CAPABILITIES = Object.freeze(Object.keys(PERMISSION_CONTRACT) as Capability[]);
export const PROTECTED_CAPABILITIES: readonly Capability[] = Object.freeze([
  'roles.create', 'roles.update', 'roles.archive', 'roles.permissions.manage', 'staff.role.assign',
]);
export type Scope = { readonly kind: 'GLOBAL' } | { readonly kind: 'SELF'; readonly ownerId: string };
export const GLOBAL_SCOPE = Object.freeze({ kind: 'GLOBAL' } as const);
export function isCapability(value: unknown): value is Capability {
  return typeof value === 'string' && Object.hasOwn(PERMISSION_CONTRACT, value);
}
export function staffScope(capability: Capability, ownerId: string): Scope {
  return PERMISSION_CONTRACT[capability] === 'SELF' ? { kind: 'SELF', ownerId } : GLOBAL_SCOPE;
}
export function scopeMatches(capability: Capability, scope: Scope, staffId: string): boolean {
  return isCapability(capability) && scope.kind === PERMISSION_CONTRACT[capability]
    && (scope.kind === 'GLOBAL' || (!!staffId && scope.ownerId === staffId));
}
export const CAPABILITY_METADATA = Symbol('fixlevelup:require-capability');

/** Grant scopes a stored role permission may carry. CITY is only meaningful for the
 * geography and P03 contracts; staff operations keep exactly one supported scope. */
export type GrantScope = 'GLOBAL' | 'SELF' | 'CITY';

/** Geography operation codes are a separate contract from the staff dictionary above:
 * one code can be granted either for the caller's assigned cities (CITY) or without a
 * geographic border (GLOBAL). The scope is not fixed per code because only a SYSTEM
 * ADMIN may ever hold GLOBAL, while every other role may only hold CITY. The five codes
 * are deliberately never `protected`: protection makes a grant mandatory on ADMIN and
 * would silently give geography to every administrator instead of an explicit grant.
 * `geography.publish` is additionally restricted to SYSTEM ADMIN by the authorization
 * service and the role editor, whatever its stored scope. A catalog row or a string in
 * a request never becomes authority: the enabled role grant, the live role type and the
 * caller's current assignment are checked on every request.
 */
export const GEO_SCOPE_CONTRACT = {
  'geography.read': ['CITY', 'GLOBAL'],
  'geography.manage': ['CITY', 'GLOBAL'],
  'geography.publish': ['CITY', 'GLOBAL'],
  'staff.geography.read': ['CITY', 'GLOBAL'],
  'staff.geography.manage': ['CITY', 'GLOBAL'],
} as const satisfies Record<string, readonly GrantScope[]>;
export type GeoCapability = keyof typeof GEO_SCOPE_CONTRACT;
export const GEO_CAPABILITIES = Object.freeze(Object.keys(GEO_SCOPE_CONTRACT) as GeoCapability[]);
/** One explicitly granted geography operation and the geographic border it carries. */
export interface GeoGrant { readonly code: GeoCapability; readonly scope: 'GLOBAL' | 'CITY' }
export const P04_SCOPE_CONTRACT = {
  'catalog.read': ['GLOBAL'], 'catalog.manage': ['GLOBAL'],
  'pricing.rules.read': ['GLOBAL'], 'pricing.rules.manage': ['GLOBAL'],
  'pricing.read': ['CITY', 'GLOBAL'], 'pricing.manage': ['CITY', 'GLOBAL'],
  'content.externalreviews.read': ['GLOBAL'], 'content.externalreviews.manage': ['GLOBAL'],
  'content.externalreviews.publish': ['GLOBAL'],
} as const satisfies Record<string, readonly GrantScope[]>;
export type P04Capability = keyof typeof P04_SCOPE_CONTRACT;
export type P04Scope = 'CITY' | 'GLOBAL';
export interface P04Grant { readonly code: P04Capability; readonly scope: P04Scope }
export const P04_CAPABILITIES = Object.freeze(Object.keys(P04_SCOPE_CONTRACT) as P04Capability[]);
export function isP04Capability(value: unknown): value is P04Capability {
  return typeof value === 'string' && Object.hasOwn(P04_SCOPE_CONTRACT, value);
}
export function p04Module(code: P04Capability): string { return code.slice(0, code.indexOf('.')); }

/** P05 request processing is a separate domain contract from the staff dictionary.
 * Every code is an ordinary (never protected) catalog entry in the fixed `requests`
 * module, and its stored scope is CITY or GLOBAL. GLOBAL is authority only for the
 * exact SYSTEM ADMIN role; SYSTEM MANAGER and CUSTOM web roles may store CITY only,
 * and the technician channel holds no P05 grant at all. A catalog row, a request body
 * or a role name never becomes authority: the enabled grant, live role and current
 * admin-city assignment are checked on every command by the P05 authorization port.
 * These are the seven exact codes of the closed P05 surface; adding a code here does
 * not provision it in a database (migration 024 does, operator-owned). */
export const P05_SCOPE_CONTRACT = {
  'requests.read': ['CITY', 'GLOBAL'],
  'requests.create': ['CITY', 'GLOBAL'],
  'requests.review': ['CITY', 'GLOBAL'],
  'requests.coverage.assess': ['CITY', 'GLOBAL'],
  'requests.contact.manage': ['CITY', 'GLOBAL'],
  'requests.ready': ['CITY', 'GLOBAL'],
  'requests.cancel': ['CITY', 'GLOBAL'],
} as const satisfies Record<string, readonly GrantScope[]>;
export type P05Capability = keyof typeof P05_SCOPE_CONTRACT;
export type P05Scope = 'CITY' | 'GLOBAL';
export interface P05Grant { readonly code: P05Capability; readonly scope: P05Scope }
export const P05_CAPABILITIES = Object.freeze(Object.keys(P05_SCOPE_CONTRACT) as P05Capability[]);
export const P05_MODULE = 'requests' as const;
export function isP05Capability(value: unknown): value is P05Capability {
  return typeof value === 'string' && Object.hasOwn(P05_SCOPE_CONTRACT, value);
}
export type PermissionCode = Capability | GeoCapability | P03Capability | P04Capability | P05Capability;
export const PERMISSION_CODES: readonly PermissionCode[] = Object.freeze([
  ...STAFF_CAPABILITIES, ...GEO_CAPABILITIES, ...P03_CAPABILITIES, ...P04_CAPABILITIES, ...P05_CAPABILITIES,
]);
export function isGeoCapability(value: unknown): value is GeoCapability {
  return typeof value === 'string' && Object.hasOwn(GEO_SCOPE_CONTRACT, value);
}
export function isPermissionCode(value: unknown): value is PermissionCode {
  return isCapability(value) || isGeoCapability(value) || isP03Capability(value) || isP04Capability(value)
    || isP05Capability(value);
}
export function isGrantScope(value: unknown): value is GrantScope {
  return value === 'GLOBAL' || value === 'SELF' || value === 'CITY';
}
