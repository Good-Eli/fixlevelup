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
