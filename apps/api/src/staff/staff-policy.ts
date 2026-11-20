import { BadRequestException, ForbiddenException } from '@nestjs/common';
import { isSystemAdmin } from '../authz/authorization.service.js';
import type { EffectiveRole } from '../authz/authorization.service.js';

/** This role is from the live RBAC assignment, never from a channel marker or request. */
export const hasAdministrativeRole = isSystemAdmin;
export function staffTargetFilter(actorRole: EffectiveRole): string {
  return isSystemAdmin(actorRole) ? 'TRUE' : "(r.role_type='SYSTEM' AND r.code='TECHNICIAN')";
}

/** Shared roster/count filter: placeholders are query-owned, never request fields. */
export function staffReadFilter(actorRole: EffectiveRole, selfPermissionParam: `$${number}`, staffIdParam: `$${number}`): string {
  return `(${staffTargetFilter(actorRole)} AND (${selfPermissionParam}::boolean OR s.id<>${staffIdParam}::uuid))`;
}

/** General mutations can never substitute for SELF, even for a system ADMIN. */
export type StaffTarget = { kind: 'general' | 'self'; id: string };
export function checkTarget(actorId: string, target: StaffTarget, write: boolean): void {
  const same = actorId.toLowerCase() === target.id.toLowerCase();
  if ((target.kind === 'self' && !same) || (target.kind === 'general' && write && same)) {
    throw new ForbiddenException();
  }
}

export function displayName(value: unknown): string {
  if (typeof value !== 'string' || /[\p{Cc}\p{Cf}\p{Cs}]/u.test(value)) { throw new BadRequestException(); }
  const name = value.trim();
  if (!/^.{1,80}$/su.test(name)) { throw new BadRequestException(); }
  return name;
}

/** Preserve Telegram vs web eligibility when assigning CUSTOM; do not leave an
 * obsolete ADMIN marker on demotion. System roles retain their established channel. */
export type ChannelMarker = 'ADMIN' | 'MANAGER' | 'TECHNICIAN';
export function nextChannelMarker(current: ChannelMarker, role: EffectiveRole): ChannelMarker {
  if (role.type === 'CUSTOM') { return current === 'TECHNICIAN' ? 'TECHNICIAN' : 'MANAGER'; }
  if (role.code === 'ADMIN' || role.code === 'MANAGER' || role.code === 'TECHNICIAN') { return role.code; }
  throw new ForbiddenException();
}
