import { BadRequestException, ConflictException, ForbiddenException, HttpException, NotFoundException } from '@nestjs/common';
import { isGeoCapability } from '../../authz/capability.js';
import type { GeoCommand } from './geo-contract.js';

/** An explicit removal is permanent for this original assignment. No personal grant creation route exists. */
export const revokeBootstrap: GeoCommand = {
  action: 'geography.bootstrap.revoke', scoped: 'global', write: true,
  async check(ctx, target) {
    if (!isGeoCapability(target.permissionCode) || !target.staffId) { throw new BadRequestException(); }
    if (!ctx.geoPermissions?.some(g => g.code === target.permissionCode && g.scope === 'GLOBAL')) { throw new ForbiddenException(); }
    const result = await ctx.client.query(`SELECT 1 FROM foundation.geography_bootstrap_permissions b
      JOIN foundation.staff_role_assignments a ON a.id=b.assignment_id WHERE a.staff_id=$1 AND b.permission_code=$2`, [target.staffId,target.permissionCode]);
    if (!result.rowCount) { throw new NotFoundException(); }
  },
  async run(ctx, target, body, expected) {
    if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length) { throw new BadRequestException(); }
    const rev = await ctx.client.query<{version:number}>(`UPDATE foundation.staff SET profile_version=profile_version+1
      WHERE id=$1 AND auth_version::bigint+profile_version=$2 RETURNING (auth_version::float8+profile_version) AS version`, [target.staffId,expected]);
    const row = rev.rows[0]; if (!row) { throw new HttpException('Precondition Failed',412); }
    const changed = await ctx.client.query(`UPDATE foundation.geography_bootstrap_permissions b SET revoked_at=statement_timestamp()
      FROM foundation.staff_role_assignments a WHERE a.id=b.assignment_id AND a.staff_id=$1 AND b.permission_code=$2 AND b.revoked_at IS NULL`, [target.staffId,target.permissionCode]);
    if (changed.rowCount !== 1) { throw new ConflictException(); }
    return {id:target.staffId,version:row.version};
  },
};
