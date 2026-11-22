import { ConflictException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import type { Capability, GeoCapability, Scope } from '../src/authz/capability.js';
import {
  GEO_CAPABILITIES, GEO_SCOPE_CONTRACT, GLOBAL_SCOPE, isCapability, isGeoCapability, isPermissionCode,
  isP04Capability, P03_CAPABILITIES, P04_CAPABILITIES, PERMISSION_CONTRACT, PERMISSION_CODES,
  PROTECTED_CAPABILITIES, scopeMatches, STAFF_CAPABILITIES, staffScope,
} from '../src/authz/capability.js';
import { AuthorizationError, AuthorizationService, isSystemAdmin, P03CommitUnknown } from '../src/authz/authorization.service.js';
import type { AccessView, SessionProof } from '../src/authz/authorization.service.js';
import { catalogEntry, checkReplacement } from '../src/roles/role-policy.js';
import type { RoleGrant } from '../src/roles/role-policy.js';

describe('server permission contracts are not grants', () => {
  it('keeps thirteen staff, five geography, eighteen P03 and nine disjoint P04 codes', () => {
    expect(new Set(STAFF_CAPABILITIES).size).toBe(13);
    expect(GEO_CAPABILITIES).toEqual(['geography.read', 'geography.manage', 'geography.publish',
      'staff.geography.read', 'staff.geography.manage']);
    expect(P03_CAPABILITIES).toHaveLength(18);
    expect(new Set(PERMISSION_CODES).size).toBe(45);
    expect(P04_CAPABILITIES).toEqual(['catalog.read', 'catalog.manage', 'pricing.rules.read', 'pricing.rules.manage',
      'pricing.read', 'pricing.manage', 'content.externalreviews.read', 'content.externalreviews.manage', 'content.externalreviews.publish']);
    expect(P04_CAPABILITIES.every((code) => isPermissionCode(code) && isP04Capability(code)
      && !isCapability(code) && !isGeoCapability(code) && !(P03_CAPABILITIES as readonly string[]).includes(code))).toBe(true);
    expect(P03_CAPABILITIES.every((code) => !isCapability(code) && !isGeoCapability(code))).toBe(true);
    for (const input of [null, [], {}, 'staff.manage', 'jobs.create', '__proto__', 'constructor', 'roles.READ',
      'geography', 'geography.write', 'geography.self.read', 'geography.admin.assign', 'geography.bootstrap.revoke']) {
      expect(isPermissionCode(input)).toBe(false);
    }
    expect(isGeoCapability('geography.publish')).toBe(true);
    expect(isCapability('geography.publish')).toBe(false);
    expect(PROTECTED_CAPABILITIES).toHaveLength(5);
    expect(PROTECTED_CAPABILITIES.every(c => isCapability(c) && PERMISSION_CONTRACT[c] === 'GLOBAL')).toBe(true);
    // Geography codes are never protected: protection would make them mandatory on every
    // ADMIN and would grant them to all administrators instead of one explicit exception.
    expect(PROTECTED_CAPABILITIES.some(c => (GEO_CAPABILITIES as readonly string[]).includes(c))).toBe(false);
    expect(isSystemAdmin({ id: 'role', code: 'ADMIN', type: 'CUSTOM' })).toBe(false);
  });
  it.each(STAFF_CAPABILITIES)('requires the supported scope and checks SELF ownership for %s', capability => {
    const own = { kind: 'SELF', ownerId: 'caller' } as const;
    expect(scopeMatches(capability, staffScope(capability, 'caller'), 'caller')).toBe(true);
    expect(scopeMatches(capability, own, 'another')).toBe(false);
    expect(scopeMatches(capability, GLOBAL_SCOPE, 'caller')).toBe(!capability.startsWith('staff.self.'));
    expect(scopeMatches(capability, { kind: 'CITY', cityId: 'untrusted' } as unknown as Scope, 'caller')).toBe(false);
    expect(scopeMatches('staff.manage' as Capability, GLOBAL_SCOPE, 'caller')).toBe(false);
  });
  it('never treats an abstract CITY scope or a request city as staff authority', () => {
    for (const code of GEO_CAPABILITIES) {
      expect(GEO_SCOPE_CONTRACT[code]).toEqual(['CITY', 'GLOBAL']);
      // scopeMatches only knows GLOBAL/SELF staff scopes; a legacy CITY value matches nothing.
      expect(scopeMatches(code as unknown as Capability, { kind: 'CITY', cityId: 'x' } as unknown as Scope, 'caller')).toBe(false);
      expect(scopeMatches(code as unknown as Capability, GLOBAL_SCOPE, 'caller')).toBe(false);
    }
    expect(isSystemAdmin({ id: 'role', code: 'ADMIN', type: 'SYSTEM' })).toBe(true);
    expect(isSystemAdmin({ id: 'role', code: 'MANAGER', type: 'SYSTEM' })).toBe(false);
  });
});

/** Scripted driver: each SQL statement is matched to the first response whose fragment it
 * contains, so the same transaction shape can be replayed by several calls. An unmatched
 * statement fails loudly, which proves no unexpected query ran. */
interface Response { contains: string; rows?: unknown[]; rowCount?: number | (() => number) }
function pool(responses: Response[], failCommit?: Error) {
  const statements: { sql: string; params?: unknown[] }[] = [];
  const releases: boolean[] = [];
  const client = {
    query: (sql: string, params?: unknown[]) => {
      if (sql === 'COMMIT' && failCommit) { return Promise.reject(failCommit); }
      if (sql.startsWith('BEGIN') || sql === 'COMMIT' || sql === 'ROLLBACK' || sql.includes('pg_advisory_xact_lock')
        || sql.includes('SAVEPOINT p04_authorized_callback')) {
        return Promise.resolve({ command: sql, rowCount: 0, rows: [] });
      }
      const response: Response | undefined = responses.find(candidate => sql.includes(candidate.contains))
        ?? (sql.includes('foundation.p03_bootstrap_permissions') ? { contains: 'foundation.p03_bootstrap_permissions', rows: [] } : undefined);
      if (!response) { throw new Error(`Unexpected query: ${sql}`); }
      statements.push(params ? { sql, params } : { sql });
      const rows = response.rows ?? [];
      return Promise.resolve({ rowCount: typeof response.rowCount === 'function' ? response.rowCount() : response.rowCount ?? rows.length, rows });
    },
    release: (discard: boolean) => { releases.push(discard); },
  } as unknown as Parameters<Parameters<Pick<import('pg').Pool, 'connect'>['connect']>[0]>[0];
  const connect = () => Promise.resolve(client);
  return { service: new AuthorizationService({ connect } as unknown as Pick<import('pg').Pool, 'connect'>), statements, releases };
}

const staffId = '00000000-0000-4000-8000-000000000005';
const cityA = '00000000-0000-4000-8000-0000000000c1';
const cityB = '00000000-0000-4000-8000-0000000000c2';
const web: SessionProof = { kind: 'staff-web', token: 'A'.repeat(43) };
const telegram: SessionProof = { kind: 'staff-telegram', token: 'B'.repeat(43) };

const adminRole = { id: 'role-admin', code: 'ADMIN', role_type: 'SYSTEM' } as const;
const managerRole = { id: 'role-manager', code: 'MANAGER', role_type: 'SYSTEM' } as const;
const technicianRole = { id: 'role-tech', code: 'TECHNICIAN', role_type: 'SYSTEM' } as const;

function policyRows(role: { id: string; code: string; role_type: string }, grants: { code: string; scope: string; protected?: boolean }[] = []) {
  const rows = grants.map(g => ({ ...role, permission_code: g.code, scope_type: g.scope, protected: g.protected ?? false }));
  // The projection always returns at least the role row so a valid assignment is recognized.
  return rows.length ? rows : [{ ...role, permission_code: null, scope_type: null, protected: null }];
}
function geoRows(grants: { code: string; scope: string }[]) {
  return grants.map(grant => ({ ...grant, source: 'ROLE' }));
}
function webIdentity(role: 'ADMIN' | 'MANAGER') {
  return [
    { contains: 'FROM foundation.web_sessions WHERE token_hash=$1 AND channel=$2', rows: [{ staff_id: staffId, telegram_link_id: null }] },
    { contains: 'FROM foundation.staff WHERE id=$1', rows: [{ id: staffId, role, auth_version: 0 }] },
    { contains: 'SELECT id FROM foundation.web_sessions', rows: [{ id: 'session' }] },
    freshClock,
  ];
}
function telegramIdentity() {
  return [
    { contains: 'FROM foundation.web_sessions WHERE token_hash=$1 AND channel=$2', rows: [{ staff_id: staffId, telegram_link_id: 'link' }] },
    { contains: 'FROM foundation.staff WHERE id=$1', rows: [{ id: staffId, role: 'TECHNICIAN', auth_version: 0 }] },
    { contains: 'FROM foundation.staff_telegram_links', rows: [{ telegram_user_id: '7000000001' }] },
    { contains: 'SELECT id FROM foundation.web_sessions', rows: [{ id: 'session' }] },
    freshClock,
  ];
}
const freshClock = { contains: 'FROM foundation.web_sessions ws', rowCount: 1 };
const bootstrapEmpty = { contains: 'geography_bootstrap_permissions', rows: [] };
const cityScopeRows = (...ids: string[]) => ({ contains: 'staff_admin_city_assignments', rows: ids.map(city_id => ({ city_id })) });

describe('withGeography is the single authority for geography', () => {
  it('binds city scope to the trusted assignment and denies a foreign city with 404', async () => {
    const fx = pool([...webIdentity('MANAGER'),
      { contains: 'FROM foundation.staff s', rows: policyRows(managerRole,
        [{ code: 'geography.read', scope: 'CITY' }, { code: 'geography.manage', scope: 'CITY' }]) },
      { contains: 'geography_bootstrap_permissions', rows: geoRows([{ code: 'geography.read', scope: 'CITY' }, { code: 'geography.manage', scope: 'CITY' }]) },
      cityScopeRows(cityA)]);
    const seen: (readonly string[] | null)[] = [];
    await expect(fx.service.withGeography(web, 'write', 'geography.manage', cityA, (ctx) => { seen.push(ctx.cityIds); return Promise.resolve('ok'); }))
      .resolves.toBe('ok');
    expect(seen).toEqual([[cityA]]);
    // The scope query is bound to the caller, never to a request value, and ignores revoked rows.
    const scope = fx.statements.find(s => s.sql.includes('staff_admin_city_assignments'));
    expect(scope?.params).toEqual([staffId]);
    expect(scope?.sql).toContain('revoked_at IS NULL');
    // A city outside the trusted assignment is a 404, indistinguishable from a missing city.
    await expect(fx.service.withGeography(web, 'write', 'geography.manage', cityB, () => Promise.resolve('no')))
      .rejects.toMatchObject({ status: 404 });
  });
  it('denies a manager write without the independent read grant and a write without a city', async () => {
    const withoutRead = pool([...webIdentity('MANAGER'),
      { contains: 'FROM foundation.staff s', rows: policyRows(managerRole, [{ code: 'geography.manage', scope: 'CITY' }]) },
      { contains: 'geography_bootstrap_permissions', rows: geoRows([{ code: 'geography.manage', scope: 'CITY' }]) },
      cityScopeRows(cityA)]);
    await expect(withoutRead.service.withGeography(web, 'write', 'geography.manage', cityA, () => Promise.resolve('no')))
      .rejects.toMatchObject({ code: 'FORBIDDEN' });
    const listWrite = pool([...webIdentity('MANAGER'),
      { contains: 'FROM foundation.staff s', rows: policyRows(managerRole,
        [{ code: 'geography.read', scope: 'CITY' }, { code: 'geography.manage', scope: 'CITY' }]) },
      { contains: 'geography_bootstrap_permissions', rows: geoRows([{ code: 'geography.read', scope: 'CITY' }, { code: 'geography.manage', scope: 'CITY' }]) },
      cityScopeRows(cityA)]);
    // cityId=null never means "skip the scope" for a write: it needs an unrestricted admin.
    await expect(listWrite.service.withGeography(web, 'write', 'geography.manage', null, () => Promise.resolve('no')))
      .rejects.toMatchObject({ code: 'FORBIDDEN' });
    // A scoped list read is allowed and the callback filters by the trusted ids.
    await expect(listWrite.service.withGeography(web, 'read', 'geography.read', null, (ctx) => Promise.resolve(ctx.cityIds)))
      .resolves.toEqual([cityA]);
    const noGrant = pool([...webIdentity('MANAGER'),
      { contains: 'FROM foundation.staff s', rows: policyRows(managerRole) }, bootstrapEmpty]);
    await expect(noGrant.service.withGeography(web, 'read', 'geography.read', cityA, () => Promise.resolve('no')))
      .rejects.toMatchObject({ code: 'FORBIDDEN' });
  });
  it('allows an unrestricted SYSTEM ADMIN global command and rejects GLOBAL geography for a manager', async () => {
    const admin = pool([...webIdentity('ADMIN'),
      { contains: 'FROM foundation.staff s', rows: policyRows(adminRole, [
        { code: 'geography.read', scope: 'GLOBAL' }, { code: 'geography.manage', scope: 'GLOBAL' },
        { code: 'geography.publish', scope: 'GLOBAL' }, { code: 'staff.role.assign', scope: 'GLOBAL', protected: true },
      ]) },
      { contains: 'geography_bootstrap_permissions', rows: geoRows([
        { code: 'geography.read', scope: 'GLOBAL' }, { code: 'geography.manage', scope: 'GLOBAL' },
        { code: 'geography.publish', scope: 'GLOBAL' },
      ]) }]);
    const seen: (readonly string[] | null)[] = [];
    await expect(admin.service.withGeography(web, 'write', 'geography.publish', null, (ctx) => { seen.push(ctx.cityIds); return Promise.resolve('ok'); }))
      .resolves.toBe('ok');
    expect(seen).toEqual([null]);
    // A drifted GLOBAL grant on a manager role is ignored, not honoured.
    const drifted = pool([...webIdentity('MANAGER'),
      { contains: 'FROM foundation.staff s', rows: policyRows(managerRole, [{ code: 'geography.read', scope: 'GLOBAL' }]) },
      { contains: 'geography_bootstrap_permissions', rows: geoRows([{ code: 'geography.read', scope: 'GLOBAL' }]) },
      cityScopeRows()]);
    await expect(drifted.service.withGeography(web, 'read', 'geography.read', cityA, () => Promise.resolve('no')))
      .rejects.toMatchObject({ code: 'FORBIDDEN' });
  });
  it('grants the five bootstrap codes only through the current assignment of a SYSTEM ADMIN', async () => {
    const bootstrap = GEO_CAPABILITIES.map(code => ({ code, scope: 'GLOBAL', source: 'BOOTSTRAP' }));
    const founder = pool([...webIdentity('ADMIN'),
      { contains: 'FROM foundation.staff s', rows: policyRows(adminRole) },
      { contains: 'geography_bootstrap_permissions', rows: bootstrap }]);
    await expect(founder.service.withGeography(web, 'write', 'geography.publish', null, () => Promise.resolve('ok'))).resolves.toBe('ok');
    // The exception is resolved from the trusted table, bound to the *current* assignment.
    const query = founder.statements.find(s => s.sql.includes('geography_bootstrap_permissions'));
    expect(query?.params).toEqual([staffId, GEO_CAPABILITIES]);
    expect(query?.sql).toContain('revoked_at IS NULL');
    expect(query?.sql).toContain('ca.id=b.assignment_id');
    expect(query?.sql).not.toContain('INSERT');
    // A different administrator without individual rows gets no geography automatically.
    const other = pool([...webIdentity('ADMIN'),
      { contains: 'FROM foundation.staff s', rows: policyRows(adminRole) }, bootstrapEmpty]);
    await expect(other.service.withGeography(web, 'read', 'geography.read', null, () => Promise.resolve('no')))
      .rejects.toMatchObject({ code: 'FORBIDDEN' });
    // The same individual exception is never authority for a non-administrator role.
    const demoted = pool([...webIdentity('MANAGER'),
      { contains: 'FROM foundation.staff s', rows: policyRows(managerRole) },
      { contains: 'geography_bootstrap_permissions', rows: bootstrap }]);
    await expect(demoted.service.withGeography(web, 'read', 'geography.read', null, () => Promise.resolve('no')))
      .rejects.toMatchObject({ code: 'FORBIDDEN' });
  });
  it('requires admin, staff.role.assign and GLOBAL geography.manage for administrative city assignment', async () => {
    const admin = pool([...webIdentity('ADMIN'),
      { contains: 'FROM foundation.staff s', rows: policyRows(adminRole, [
        { code: 'geography.manage', scope: 'GLOBAL' }, { code: 'staff.role.assign', scope: 'GLOBAL', protected: true },
      ]) },
      { contains: 'geography_bootstrap_permissions', rows: geoRows([{ code: 'geography.manage', scope: 'GLOBAL' }]) }]);
    // A nested target city is a real path id, so cityId may be present; the callback still
    // receives the unrestricted scope and proves the target itself.
    await expect(admin.service.withGeography(web, 'write', 'geography.admin.assign', cityA, (ctx) => Promise.resolve(ctx.cityIds)))
      .resolves.toBeNull();
    const manager = pool([...webIdentity('MANAGER'),
      { contains: 'FROM foundation.staff s', rows: policyRows(managerRole, [
        { code: 'geography.manage', scope: 'CITY' }, { code: 'staff.role.assign', scope: 'GLOBAL', protected: true },
        { code: 'staff.geography.manage', scope: 'CITY' },
      ]) },
      { contains: 'geography_bootstrap_permissions', rows: geoRows([
        { code: 'geography.manage', scope: 'CITY' }, { code: 'staff.geography.manage', scope: 'CITY' },
      ]) },
      cityScopeRows(cityA)]);
    await expect(manager.service.withGeography(web, 'write', 'geography.admin.assign', cityA, () => Promise.resolve('no')))
      .rejects.toMatchObject({ code: 'FORBIDDEN' });
  });
  it('revokes one bootstrap exception only as a live CRM administrator with role-permission management', async () => {
    const actor = pool([...webIdentity('ADMIN'),
      { contains: 'FROM foundation.staff s', rows: policyRows(adminRole, [
        { code: 'roles.permissions.manage', scope: 'GLOBAL', protected: true },
      ]) },
      { contains: 'geography_bootstrap_permissions', rows: geoRows([{ code: 'geography.manage', scope: 'GLOBAL' }]) }]);
    await expect(actor.service.withGeography(web, 'write', 'geography.bootstrap.revoke', null, (ctx) => Promise.resolve(ctx.cityIds)))
      .resolves.toBeNull();
    await expect(actor.service.withGeography(web, 'read', 'geography.bootstrap.revoke', null, () => Promise.resolve('no')))
      .rejects.toMatchObject({ code: 'FORBIDDEN' });
    const withoutManage = pool([...webIdentity('ADMIN'),
      { contains: 'FROM foundation.staff s', rows: policyRows(adminRole) }, bootstrapEmpty]);
    await expect(withoutManage.service.withGeography(web, 'write', 'geography.bootstrap.revoke', null, () => Promise.resolve('no')))
      .rejects.toMatchObject({ code: 'FORBIDDEN' });
    const tg = pool([...telegramIdentity(),
      { contains: 'FROM foundation.staff s', rows: policyRows(technicianRole, [{ code: 'staff.self.read', scope: 'SELF' }]) },
      bootstrapEmpty]);
    await expect(tg.service.withGeography(telegram, 'write', 'geography.bootstrap.revoke', null, () => Promise.resolve('no')))
      .rejects.toMatchObject({ code: 'FORBIDDEN' });
  });
  it('lets only a verified Telegram master read the SELF summary and never makes it general', async () => {
    const self = pool([...telegramIdentity(),
      { contains: 'FROM foundation.staff s', rows: policyRows(technicianRole, [{ code: 'staff.self.read', scope: 'SELF' }]) },
      bootstrapEmpty]);
    const seen: (readonly string[] | null)[] = [];
    await expect(self.service.withGeography(telegram, 'read', 'geography.self.read', null, (ctx) => {
      seen.push(ctx.cityIds); expect(ctx.principal.kind).toBe('staff-telegram'); expect(ctx.staffId).toBe(staffId); return Promise.resolve('ok');
    })).resolves.toBe('ok');
    expect(seen).toEqual([[]]);
    // A CRM session can never reach the SELF summary, and a city target is not a SELF read.
    const crm = pool([...webIdentity('ADMIN'),
      { contains: 'FROM foundation.staff s', rows: policyRows(adminRole) }, bootstrapEmpty]);
    await expect(crm.service.withGeography(web, 'read', 'geography.self.read', null, () => Promise.resolve('no')))
      .rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(self.service.withGeography(telegram, 'read', 'geography.self.read', cityA, () => Promise.resolve('no')))
      .rejects.toMatchObject({ code: 'FORBIDDEN' });
    // A master can never escalate the SELF channel into an administrative geography action.
    await expect(self.service.withGeography(telegram, 'read', 'geography.read', null, () => Promise.resolve('no')))
      .rejects.toMatchObject({ code: 'FORBIDDEN' });
    await expect(self.service.withGeography(telegram, 'read', 'geography.admin.assign', null, () => Promise.resolve('no')))
      .rejects.toMatchObject({ code: 'FORBIDDEN' });
  });
  it('rejects a malformed action or city id before opening a transaction', async () => {
    const fx = pool([]);
    await expect(fx.service.withGeography(web, 'read', 'geography.everything' as unknown as GeoCapability, null, () => Promise.resolve('no')))
      .rejects.toThrow();
    await expect(fx.service.withGeography(web, 'read', 'geography.read', 'not-a-uuid', () => Promise.resolve('no')))
      .rejects.toThrow();
    expect(fx.statements).toHaveLength(0);
  });
  it('maps a stale session to UNAUTHORIZED before any policy or city read', async () => {
    const stale = pool([{ contains: 'FROM foundation.web_sessions WHERE token_hash=$1 AND channel=$2', rows: [] }]);
    await expect(stale.service.withGeography(web, 'read', 'geography.read', null, () => Promise.resolve('no')))
      .rejects.toBeInstanceOf(AuthorizationError);
    expect(stale.statements).toHaveLength(1);
  });
});

describe('inspectAccess projects individual geography grants for the UI', () => {
  it('returns the five founder codes as GLOBAL and nothing for another administrator', async () => {
    const founder = pool([...webIdentity('ADMIN'),
      { contains: 'FROM foundation.staff s', rows: policyRows(adminRole, [{ code: 'staff.read', scope: 'GLOBAL' }]) },
      { contains: 'geography_bootstrap_permissions', rows: GEO_CAPABILITIES.map(code => ({ code, scope: 'GLOBAL', source: 'BOOTSTRAP' })) }]);
    const view = await founder.service.inspectAccess(web);
    expect(view.permissions).toEqual(['staff.read']);
    expect(view.geoPermissions).toHaveLength(5);
    expect(view.geoPermissions?.every(grant => grant.scope === 'GLOBAL')).toBe(true);
    const other = pool([...webIdentity('ADMIN'),
      { contains: 'FROM foundation.staff s', rows: policyRows(adminRole) }, bootstrapEmpty]);
    await expect(other.service.inspectAccess(web)).resolves.toMatchObject({ geoPermissions: [] });
  });
  it('ignores a drifted GLOBAL, publish or technician-channel geography row instead of echoing it', async () => {
    const manager = pool([...webIdentity('MANAGER'),
      { contains: 'FROM foundation.staff s', rows: policyRows(managerRole) },
      { contains: 'geography_bootstrap_permissions', rows: [
        { code: 'geography.read', scope: 'GLOBAL', source: 'ROLE' },
        { code: 'geography.publish', scope: 'CITY', source: 'ROLE' },
        { code: 'geography.manage', scope: 'CITY', source: 'ROLE' },
        { code: 'unknown.code', scope: 'CITY', source: 'ROLE' },
      ] }]);
    const managerView = await manager.service.inspectAccess(web);
    expect(managerView.geoPermissions).toEqual([{ code: 'geography.manage', scope: 'CITY' }]);
    // The technician channel role never receives geography, matching migration 012's guard.
    const technician = pool([...telegramIdentity(),
      { contains: 'FROM foundation.staff s', rows: policyRows(technicianRole, [{ code: 'staff.self.read', scope: 'SELF' }]) },
      { contains: 'geography_bootstrap_permissions', rows: [{ code: 'geography.read', scope: 'CITY', source: 'ROLE' }] }]);
    await expect(technician.service.inspectAccess(telegram)).resolves.toMatchObject({ geoPermissions: [] });
  });
  it('lets an explicit GLOBAL role grant win over a narrower CITY grant for the same code', async () => {
    const fx = pool([...webIdentity('ADMIN'),
      { contains: 'FROM foundation.staff s', rows: policyRows(adminRole) },
      { contains: 'geography_bootstrap_permissions', rows: [
        { code: 'geography.read', scope: 'CITY', source: 'ROLE' },
        { code: 'geography.read', scope: 'GLOBAL', source: 'BOOTSTRAP' },
      ] }]);
    const view = await fx.service.inspectAccess(web);
    expect(view.geoPermissions).toEqual([{ code: 'geography.read', scope: 'GLOBAL' }]);
  });
});

const customRole = { id: 'role-custom', code: 'CUSTOM_1', role_type: 'CUSTOM' } as const;
const p04Rows = (role: typeof adminRole | typeof managerRole | typeof customRole) => ({
  contains: 'FROM foundation.staff s', rows: policyRows(role).map(row => ({ ...row, p04_present: true })),
});
const p04Grants = (...rows: { code: string; scope: string; source: string }[]) => ({
  contains: 'foundation.p04_bootstrap_permissions b', rows,
});
const pricingRead = { code: 'pricing.read', scope: 'CITY', source: 'ROLE' };
const pricingManage = { code: 'pricing.manage', scope: 'CITY', source: 'ROLE' };

describe('P04-03 locked authorization, independent from P03', () => {
  it('authorizes exact CITY read/write intersections and allows only pricing discovery', async () => {
    const fx = pool([...webIdentity('MANAGER'), p04Rows(customRole), bootstrapEmpty,
      p04Grants(pricingRead, pricingManage), cityScopeRows(cityA), { contains: 'SELECT id FROM foundation.service_cities', rowCount: 1 }]);
    const target = { scope: 'CITY', cityId: cityA } as const;
    const discovery = { scope: 'DISCOVERY' } as const;
    await expect(fx.service.withP04(web, 'write', ['pricing.read', 'pricing.manage'], target, async (ctx) => {
      expect(ctx.staffId).toBe(staffId);
      expect(ctx.target).toEqual(target);
      await ctx.recheck();
      return ctx.cityIds;
    })).resolves.toEqual([cityA]);
    await expect(fx.service.withP04(web, 'write', ['pricing.read', 'pricing.manage'], target, async ctx => {
      await ctx.recheck({ scope: 'CITY', cityId: cityB });
      throw new ConflictException();
    })).rejects.toMatchObject({ status: 404 });
    await expect(fx.service.withP04(web, 'read', ['pricing.read'], discovery, ctx => Promise.resolve(ctx.cityIds))).resolves.toEqual([cityA]);
    await expect(fx.service.withP04(web, 'read', ['pricing.manage'], discovery, () => Promise.resolve('no'))).rejects.toMatchObject({ status: 400 });
    const readOnly = pool([...webIdentity('MANAGER'), p04Rows(managerRole), bootstrapEmpty, p04Grants(pricingRead), cityScopeRows(cityA)]);
    await expect(readOnly.service.withP04(web, 'write', ['pricing.read', 'pricing.manage'], target, () => Promise.resolve('no')))
      .rejects.toMatchObject({ code: 'FORBIDDEN' });
  });

  it('masks malformed, Telegram and legacy projections', async () => {
    const company = { scope: 'COMPANY' } as const;
    const unsupported = p04Grants({ ...pricingRead, scope: 'GLOBAL' }, { code: 'catalog.read', scope: 'GLOBAL', source: 'ROLE' },
      { ...pricingManage, source: 'BOOTSTRAP' });
    const manager = pool([...webIdentity('MANAGER'), p04Rows(managerRole), bootstrapEmpty, unsupported]);
    expect(await manager.service.inspectAccess(web)).not.toHaveProperty('p04Permissions');
    await expect(manager.service.withP04(web, 'read', ['catalog.read'], company, () => Promise.resolve('no'))).rejects.toMatchObject({ code: 'FORBIDDEN' });
    const tg = pool([...telegramIdentity(), p04Rows(customRole), bootstrapEmpty, p04Grants(pricingRead)]);
    expect(await tg.service.inspectAccess(telegram)).not.toHaveProperty('p04Permissions');
    await expect(tg.service.withP04(telegram, 'read', ['catalog.read'], company, () => Promise.resolve('no'))).rejects.toMatchObject({ code: 'FORBIDDEN' });
    const fakeAdminMarker = pool([...webIdentity('ADMIN'), p04Rows(customRole), bootstrapEmpty, p04Grants(pricingRead)]);
    expect(await fakeAdminMarker.service.inspectAccess(web)).not.toHaveProperty('p04Permissions');
    const legacy = pool([...webIdentity('ADMIN'), { contains: 'FROM foundation.staff s', rows: policyRows(adminRole) }, bootstrapEmpty]);
    expect(await legacy.service.inspectAccess(web)).not.toHaveProperty('p04Permissions');
    expect(legacy.statements.some(({ sql }) => sql.includes('JOIN foundation.p04_bootstrap_permissions'))).toBe(false);
  });

  it('discards an unknown COMMIT session and safely maps only named final-clock guards to conflict', async () => {
    const responses = [...webIdentity('ADMIN'), p04Rows(adminRole), bootstrapEmpty,
      p04Grants({ ...pricingRead, scope: 'GLOBAL' }, { ...pricingManage, scope: 'GLOBAL' }),
      { contains: 'SELECT id FROM foundation.service_cities', rowCount: 1 }];
    const unknown = pool(responses, new Error('Connection lost'));
    const known = pool(responses, Object.assign(new Error('late clock check'), {
      severity: 'ERROR', code: '23514', constraint: 'catalog_price_periods_final_clock_guard',
    }));
    const internal = pool(responses, Object.assign(new Error('other invariant'), {
      severity: 'ERROR', code: '23514', constraint: 'proof_evidence_guard',
    }));
    const run = ({ service }: ReturnType<typeof pool>) => service.withP04(web, 'write', ['pricing.read', 'pricing.manage'],
      { scope: 'CITY', cityId: cityA }, () => Promise.resolve('receipt'));
    await expect(run(unknown)).rejects.toBeInstanceOf(P03CommitUnknown);
    expect(unknown.releases).toEqual([true]);
    await expect(run(known)).rejects.toMatchObject({ status: 409 });
    expect(known.releases).toEqual([false]);
    await expect(run(internal)).rejects.toMatchObject({ status: 500 });
  });

  it('distinguishes exact visible retention from delegation and requires same-code GLOBAL', () => {
    const actor: AccessView = { staffId, role: { id: 'admin', type: 'SYSTEM', code: 'ADMIN' },
      permissions: ['roles.permissions.manage', 'roles.read'] };
    const target = { id: 'manager', type: 'SYSTEM', code: 'MANAGER' } as const;
    const row = catalogEntry({ code: 'pricing.read', module: 'pricing', description: 'Read', protected: false });
    if (!row) { throw new Error('Expected known P04 catalog entry'); }
    const grant: RoleGrant[] = [{ code: 'pricing.read', scope: 'CITY' }];
    expect(() => { checkReplacement(actor, target, [row], grant, grant); }).not.toThrow();
    expect(() => { checkReplacement({ ...actor, permissions: ['roles.permissions.manage'] }, target, [row], grant, grant); }).toThrow();
    expect(() => { checkReplacement(actor, target, [row], [], grant); }).toThrow();
    expect(() => { checkReplacement({ ...actor, p04Permissions: [{ code: 'pricing.manage', scope: 'GLOBAL' }] }, target, [row], [], grant); }).toThrow();
    expect(() => { checkReplacement({ ...actor, p04Permissions: [{ code: 'pricing.read', scope: 'CITY' }] }, target, [row], [], grant); }).toThrow();
    expect(() => { checkReplacement({ ...actor, p04Permissions: [{ code: 'pricing.read', scope: 'GLOBAL' }] }, target, [row], [], grant); }).not.toThrow();
  });

  it('checks live proof after a late error and retains a checked receipt city through final proof', async () => {
    let live = true, cityStillExists = true;
    const fx = pool([{ ...freshClock, rowCount: () => live ? 1 : 0 }, ...webIdentity('ADMIN'), p04Rows(adminRole), bootstrapEmpty,
      p04Grants({ ...pricingRead, scope: 'GLOBAL', source: 'BOOTSTRAP' }, { ...pricingManage, scope: 'GLOBAL', source: 'BOOTSTRAP' }),
      { contains: 'SELECT id FROM foundation.service_cities', rowCount: () => cityStillExists ? 1 : 0 }]);
    const target = { scope: 'CITY', cityId: cityA } as const;
    await expect(fx.service.withP04(web, 'write', ['pricing.read', 'pricing.manage'], target, async ctx => {
      expect(ctx.cityIds).toBeNull();
      await ctx.recheck({ scope: 'CITY', cityId: cityB });
      live = false;
      throw new ConflictException();
    })).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    live = true;
    const before = fx.statements.filter(({ params }) => params?.[0] === cityB).length;
    await expect(fx.service.withP04(web, 'write', ['pricing.read', 'pricing.manage'], target, async ctx => {
      await ctx.recheck({ scope: 'CITY', cityId: cityB });
      return 'ok';
    })).resolves.toBe('ok');
    expect(fx.statements.filter(({ params }) => params?.[0] === cityB)).toHaveLength(before + 2);
    await expect(fx.service.withP04(web, 'write', ['pricing.read', 'pricing.manage'], target, async ctx => {
      await ctx.recheck({ scope: 'CITY', cityId: cityB });
      cityStillExists = false;
      return 'no';
    })).rejects.toMatchObject({ status: 404 });
  });
});
