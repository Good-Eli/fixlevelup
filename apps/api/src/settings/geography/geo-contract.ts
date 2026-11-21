import type { SessionProof, StaffWriteContext } from '../../authz/authorization.service.js';

export type GeoAction = 'geography.read' | 'geography.manage' | 'geography.publish'
  | 'staff.geography.read' | 'staff.geography.manage' | 'geography.admin.assign' | 'geography.self.read' | 'geography.bootstrap.revoke';

/** A null list means an authorized GLOBAL operation. For SELF the subject is always ctx.staffId. */
export interface GeoContext extends StaffWriteContext { readonly cityIds: readonly string[] | null }
export interface GeographyAuthorizationApi {
  withGeography<T>(proof: SessionProof, mode: 'read' | 'write', action: GeoAction, cityId: string | null,
    command: (ctx: GeoContext) => Promise<T>): Promise<T>;
}
export interface GeoTarget {
  cityId?: string; areaId?: string; districtId?: string; versionId?: string; staffId?: string; grantId?: string; permissionCode?: string;
}
export interface GeoReceipt { id: string; version: number }
export interface GeoCommand {
  action: GeoAction;
  write: boolean;
  scoped: 'global' | 'city' | 'list' | 'self';
  /** Recheck object visibility, subtype and ownership even on idempotent replay. */
  check(ctx: GeoContext, target: GeoTarget): Promise<void>;
  /** Called on the same transaction after check; every write returns a minimal GeoReceipt. */
  run(ctx: GeoContext, target: GeoTarget, body: unknown, expected: number | null): Promise<unknown>;
}
