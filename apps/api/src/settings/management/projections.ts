import { ForbiddenException, HttpException } from '@nestjs/common';
import { P03_COMPANY_FIELDS } from '@fixlevelup/p03-contracts';
import type {
  P03BootstrapGrant, P03Capability, P03CityPickerItem, P03CityStatus, P03CityVersionPickerItem, P03Page, P03Readiness,
  P03ReadinessCity, P03ReadinessSection, P03Receipt, P03VersionedPage,
} from '@fixlevelup/p03-contracts';
import type { PoolClient } from 'pg';
import { isSystemAdmin } from '../../authz/authorization.service.js';
import type { P03PolicyContext } from '../../authz/authorization.service.js';
import { activeAdminCityIds } from '../../authz/p03-grants.js';
import { COMPANY_SETTINGS_COLUMNS } from '../configuration/index.js';
import { found } from './catalog-reads.js';
import type { Keyset } from './page.js';

export function requireBootstrapAuthority(ctx: P03PolicyContext): void {
  if (!isSystemAdmin(ctx.role) || !ctx.permissions.includes('roles.permissions.manage')) { throw new ForbiddenException(); }
}
interface BootstrapRow { assignment_id: string; staff_id: string; permission_code: P03Capability; row_version: number }
const source = (r: BootstrapRow): P03BootstrapGrant => ({ assignmentId: r.assignment_id, staffId: r.staff_id, code: r.permission_code, version: r.row_version });
export async function bootstrapList(ctx: P03PolicyContext, page: Keyset<string>): Promise<P03Page<P03BootstrapGrant>> {
  requireBootstrapAuthority(ctx);
  const codes = ctx.p03Permissions.filter(g => g.scope === 'GLOBAL').map(g => g.code);
  const { rows } = await ctx.client.query<BootstrapRow>(`SELECT b.assignment_id,a.staff_id,b.permission_code,b.row_version
    FROM foundation.p03_bootstrap_permissions b JOIN foundation.staff_role_assignments a ON a.id=b.assignment_id
    WHERE b.revoked_at IS NULL AND a.revoked_at IS NULL AND b.permission_code=ANY($1::text[])
      AND ($2::text IS NULL OR (b.permission_code COLLATE "C",b.assignment_id)>($2::text,$3::uuid))
    ORDER BY b.permission_code COLLATE "C",b.assignment_id LIMIT $4`, [codes, page.key, page.id, page.count]);
  return page.page(rows, source, r => [r.permission_code, r.assignment_id]);
}
export async function bootstrapIdentity(ctx: P03PolicyContext, staffId: string, code: P03Capability): Promise<P03BootstrapGrant> {
  requireBootstrapAuthority(ctx);
  const { rows } = await ctx.client.query<BootstrapRow>(`SELECT b.assignment_id,a.staff_id,b.permission_code,b.row_version
    FROM foundation.p03_bootstrap_permissions b JOIN foundation.staff_role_assignments a ON a.id=b.assignment_id
    WHERE a.staff_id=$1 AND b.permission_code=$2`, [staffId, code]);
  return source(found(rows[0]));
}
export async function bootstrapRevoke(ctx: P03PolicyContext, target: P03BootstrapGrant, expected: number): Promise<P03Receipt> {
  if (target.version !== expected) { throw new HttpException('Precondition Failed', 412); }
  if (target.version !== 1) { throw new HttpException('Conflict', 409); }
  const rows = await ctx.client.query<{ row_version: number }>(`UPDATE foundation.p03_bootstrap_permissions
    SET revoked_at=clock_timestamp(),revoked_by=$3 WHERE assignment_id=$1 AND permission_code=$2 AND row_version=$4 AND revoked_at IS NULL
    RETURNING row_version`, [target.assignmentId, target.code, ctx.staffId, expected]);
  const changed = rows.rows[0];
  if (!changed) { throw new HttpException('Precondition Failed', 412); }
  return { id: target.assignmentId, version: changed.row_version };
}

interface CityRow { id: string; code: string; lifecycle: P03CityStatus; row_version: number; current_version_id: string | null }
export async function cityPicker(client: PoolClient, cityIds: readonly string[] | null, page: Keyset<string>): Promise<P03Page<P03CityPickerItem>> {
  const { rows } = await client.query<CityRow>(`SELECT id,code,lifecycle,row_version,current_version_id FROM foundation.service_cities
    WHERE ($1::uuid[] IS NULL OR id=ANY($1::uuid[]))
      AND ($2::text IS NULL OR (code COLLATE "C",id)>($2::text,$3::uuid)) ORDER BY code COLLATE "C",id LIMIT $4`,
  [cityIds, page.key, page.id, page.count]);
  return page.page(rows, r => ({ id: r.id, code: r.code, status: r.lifecycle, version: r.row_version, currentVersionId: r.current_version_id }), r => [r.code, r.id]);
}
export async function cityVersionPicker(client: PoolClient, cityId: string, page: Keyset<number>): Promise<P03VersionedPage<P03CityVersionPickerItem>> {
  const parent = found((await client.query<{ row_version: number }>('SELECT row_version FROM foundation.service_cities WHERE id=$1', [cityId])).rows[0]);
  const { rows } = await client.query<{ id: string; version: number; timezone: string; published: boolean }>(`
    SELECT id,version,timezone,(published_at IS NOT NULL) AS published FROM foundation.service_city_versions WHERE city_id=$1
      AND ($2::int IS NULL OR (version,id)<($2,$3::uuid)) ORDER BY version DESC,id DESC LIMIT $4`, [cityId, page.key, page.id, page.count]);
  return { version: parent.row_version, ...page.page(rows, r => ({ id: r.id, sequence: r.version, timezone: r.timezone, published: r.published }), r => [r.version, r.id]) };
}

const companyBooleans = P03_COMPANY_FIELDS.map(field => `(${COMPANY_SETTINGS_COLUMNS[field]} ~ '[^[:space:]]') AS "${field}"`).join(',');
export async function readiness(ctx: P03PolicyContext, page: Keyset<string>): Promise<P03Readiness> {
  const { client } = ctx;
  const { rows: [company] } = await client.query<Record<typeof P03_COMPANY_FIELDS[number], boolean | null>>(`
    SELECT ${companyBooleans} FROM foundation.business_settings_versions ORDER BY version DESC LIMIT 1`);
  const missing = P03_COMPANY_FIELDS.filter(field => company?.[field] !== true);
  const { rows: [legal] } = await client.query<{ configured: boolean }>(`
    SELECT EXISTS(SELECT 1 FROM foundation.legal_documents WHERE purpose='REQUEST_PROCESSING'
      AND kind='CONSENT_FORM' AND current_version_id IS NOT NULL) AS configured`);
  const sections: P03ReadinessSection[] = [
    { section: 'COMPANY_SETTINGS', status: missing.length ? 'MISSING' : 'CONFIGURED', missing: company ? missing : ['COMPANY_VERSION_MISSING', ...missing] },
    { section: 'REQUEST_PROCESSING', status: legal?.configured ? 'CONFIGURED' : 'MISSING', missing: legal?.configured ? [] : ['REQUEST_PROCESSING_FORM_MISSING'] },
    { section: 'P04', status: 'NOT_IMPLEMENTED', missing: [] }, { section: 'P05', status: 'NOT_IMPLEMENTED', missing: [] },
    { section: 'P09', status: 'NOT_IMPLEMENTED', missing: [] }, { section: 'PROVIDERS', status: 'NOT_ASSESSED', missing: [] },
    { section: 'PRODUCTION', status: 'NOT_ASSESSED', missing: [] },
  ];
  const geo = ctx.geoPermissions.filter(g => g.code === 'geography.read');
  if (!geo.length) { return { sections, items: [], pageInfo: { hasMore: false, nextCursor: null } }; }
  const cityIds = geo.some(g => g.scope === 'GLOBAL') ? null : await activeAdminCityIds(client, ctx.staffId);
  const { rows } = await client.query<Pick<CityRow, 'id' | 'code' | 'lifecycle'> & { name: string | null }>(`
    SELECT c.id,c.code,c.lifecycle,v.display_name AS name FROM foundation.service_cities c
    LEFT JOIN foundation.service_city_versions v ON v.city_id=c.id AND v.id=c.current_version_id
    WHERE ($1::uuid[] IS NULL OR c.id=ANY($1::uuid[]))
      AND ($2::text IS NULL OR (c.code COLLATE "C",c.id)>($2::text,$3::uuid)) ORDER BY c.code COLLATE "C",c.id LIMIT $4`,
  [cityIds, page.key, page.id, page.count]);
  return { sections, ...page.page(rows, (r): P03ReadinessCity => {
    const cityMissing: P03ReadinessCity['missing'][number][] = [];
    if (r.name === null) { cityMissing.push('CITY_VERSION_MISSING'); }
    if (r.lifecycle !== 'ACTIVE') { cityMissing.push('CITY_INACTIVE'); }
    return { id: r.id, name: r.name, status: cityMissing.length ? 'MISSING' : 'CONFIGURED', missing: cityMissing };
  }, r => [r.code, r.id]) };
}
