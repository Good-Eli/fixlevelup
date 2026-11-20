/** Fixed capability vocabulary for P02-04 (owner-approved enum). Unknown capability is always
 * denied; grants live in foundation.user_permissions and nothing is implicit for any role.
 */
export const STAFF_CAPABILITIES = ['staff.read', 'staff.manage'] as const;
export type Capability = (typeof STAFF_CAPABILITIES)[number];

/** P02-04 has GLOBAL only; concrete CITY grants wait for P03 (DECISIONS §21). */
export interface Scope {
  readonly kind: 'GLOBAL';
}
export const GLOBAL_SCOPE: Scope = { kind: 'GLOBAL' };

export function isCapability(value: unknown): value is Capability {
  return value === 'staff.read' || value === 'staff.manage';
}

/** Metadata key for @RequireCapability; read by StaffWebAuthGuard through Reflector. */
export const CAPABILITY_METADATA = Symbol('fixlevelup:require-capability');
