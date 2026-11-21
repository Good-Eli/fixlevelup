import { randomUUID } from 'node:crypto';
import { expect, it } from 'vitest';
import { fixturePerTest, integration } from './rbac-fixture.js';
import type { Web } from './rbac-fixture.js';
import {
  BOOTSTRAP_GEO_PERMISSIONS, GeographyFixture, check, geoTag, idOf, itemsOf, num, records, text, versionOf,
} from './geography-fixture.js';

/** Independent end-to-end proof of the approved P03-02 delegation matrix on real HTTP
 * against an isolated PostgreSQL database. Every authority decision is made by the
 * server under test; the test only sends requests and inspects persisted state, so a
 * regression in the policy cannot be masked by a test-side reimplementation of it. */

const HOURS = Array.from({ length: 7 }, () => [[540, 1080]]);
function status(result: { readonly status: number }, expected: number): void { expect(result.status).toBe(expected); }
function code(prefix: string): string { return `${prefix}-${randomUUID().slice(0, 8)}`; }
function geoPermissionsOf(access: { readonly data: Record<string, unknown> }): { code: string; scope: string }[] {
  return records(access.data['geoPermissions']).map((row) => ({ code: text(row, 'code'), scope: text(row, 'scope') }));
}
async function roleGrants(f: GeographyFixture, admin: Web, roleId: string) {
  const detail = check(await f.read(admin, `/roles/${roleId}`), 200);
  return {
    etag: detail.etag,
    grants: records(detail.data['permissions']).map((row) => ({ code: text(row, 'code'), scope: text(row, 'scope') })),
  };
}
async function addGeoToRole(f: GeographyFixture, admin: Web, roleId: string,
  extra: readonly { readonly code: string; readonly scope: string }[]) {
  const { etag, grants } = await roleGrants(f, admin, roleId);
  check(await f.write(admin, 'put', `/roles/${roleId}/permissions`, { permissions: [...grants, ...extra] }, { etag }), 200);
}

integration('P03-02 geography delegation, scope, revocation and concurrency over real HTTP + PostgreSQL', () => {
  // Registered once at describe level: fixturePerTest installs the per-test isolated
  // database lifecycle hooks, which must exist before any `it` callback runs.
  const fixture = fixturePerTest();
  const open = (): GeographyFixture => new GeographyFixture(fixture());

  it('grants the five bootstrap geography rights only to the original first administrator and never reissues them', async () => {
    const f = open(); const admin = f.remember(f.base.admin);
    // The approved exception is materialised by the real bootstrap path, bound to the
    // administrator's original SYSTEM ADMIN assignment.
    const access = check(await f.read(admin, '/access'), 200);
    expect(geoPermissionsOf(access)).toEqual(BOOTSTRAP_GEO_PERMISSIONS.map((item) => ({ code: item, scope: 'GLOBAL' })));
    const assignment = await f.currentAssignment(admin.id);
    expect(await f.bootstrapRows()).toEqual(BOOTSTRAP_GEO_PERMISSIONS.map((item) => ({ assignmentId: assignment, code: item, revoked: false })));
    // The exception is never written on the shared ADMIN role, so it cannot leak to a
    // second administrator created later.
    const adminRole = await f.base.systemRole('ADMIN');
    expect(await f.count(`SELECT count(*)::int n FROM foundation.role_permissions
      WHERE role_id=$1 AND permission_code LIKE 'geography.%'`, [adminRole])).toBe(0);
    const later = await f.base.createStaff('MANAGER');
    const credential = await f.base.credentials(later);
    status(await f.base.assign(later, adminRole), 200);
    const second = f.remember(await f.base.login(later, credential.login, credential.password));
    expect(geoPermissionsOf(check(await f.read(second, '/access'), 200))).toEqual([]);
    check(await f.read(second, '/settings/service-cities'), 403);
    expect((await f.bootstrapRows()).every((row) => row.assignmentId === assignment)).toBe(true);
    // An explicit revocation is permanent: a new session, a fresh ETag and the role
    // editor cannot restore the removed right.
    const staffVersion = await f.staffVersion(admin.id);
    const revoked = check(await f.write(admin, 'post',
      `/settings/geography/bootstrap/${admin.id}/staff.geography.read/revoke`, {}, { etag: geoTag(staffVersion) }), 200);
    expect(revoked.data).toEqual({ id: admin.id, version: staffVersion + 1 });
    expect((await f.bootstrapRows()).filter((row) => row.code === 'staff.geography.read'))
      .toEqual([{ assignmentId: assignment, code: 'staff.geography.read', revoked: true }]);
    const relogin = f.remember(await f.base.login(admin.id, admin.login, admin.password));
    expect(geoPermissionsOf(check(await f.read(relogin, '/access'), 200)))
      .toEqual(BOOTSTRAP_GEO_PERMISSIONS.filter((item) => item !== 'staff.geography.read').map((item) => ({ code: item, scope: 'GLOBAL' })));
    check(await f.write(relogin, 'post', `/settings/geography/bootstrap/${admin.id}/staff.geography.read/revoke`, {},
      { etag: geoTag(staffVersion + 1) }), 403);
    const { etag, grants } = await roleGrants(f, relogin, adminRole);
    check(await f.write(relogin, 'put', `/roles/${adminRole}/permissions`,
      { permissions: [...grants, { code: 'staff.geography.read', scope: 'GLOBAL' }] }, { etag }), 403);
    expect((await f.bootstrapRows()).filter((row) => row.revoked)).toHaveLength(1);
  }, 60000);

  it('delegates catalog editing only in assigned cities and keeps publish and administration with the administrator', async () => {
    const f = open(); const admin = f.remember(f.base.admin);
    const cityA = await f.activeCity(admin, code('city-a'));
    const cityB = await f.publishedDraftCity(admin, code('city-b'));
    const manager = f.remember(await f.base.webStaff());
    const managerRole = await f.base.systemRole('MANAGER');
    // Administrative territory is a protected administrator command, not a role grant.
    const assigned = check(await f.write(admin, 'post',
      `/settings/service-cities/${cityA.id}/administrators/${manager.id}/assignments`, {},
      { etag: geoTag(await f.staffVersion(manager.id)) }), 201);
    expect(assigned.data).toMatchObject({ version: 1 });
    expect(await f.count(`SELECT count(*)::int n FROM foundation.staff_admin_city_assignments
      WHERE staff_id=$1 AND city_id=$2 AND granted_by=$3 AND revoked_at IS NULL`, [manager.id, cityA.id, admin.id])).toBe(1);
    // The manager receives geography only through an explicit CITY-scoped role grant.
    await addGeoToRole(f, admin, managerRole,
      [{ code: 'geography.read', scope: 'CITY' }, { code: 'geography.manage', scope: 'CITY' }]);
    const list = check(await f.read(manager, '/settings/service-cities'), 200);
    expect(itemsOf(list).map((row) => text(row, 'id'))).toEqual([cityA.id]);
    const district = check(await f.createDistrict(manager, cityA.id,
      versionOf(check(await f.read(manager, `/settings/service-cities/${cityA.id}`), 200)), code('district')), 201);
    const districtId = idOf(district);
    const districts = check(await f.read(manager, `/settings/service-cities/${cityA.id}/administrative-districts`), 200);
    expect(itemsOf(districts).map((row) => text(row, 'id'))).toContain(districtId);
    const area = check(await f.createArea(manager, cityA.id, num(districts.data, 'version'), code('area')), 201);
    const areaId = idOf(area);
    expect(versionOf(area)).toBe(1);
    const draft = check(await f.addAreaVersion(manager, cityA.id, areaId, versionOf(area), 'Synthetic zone'), 201);
    const versionId = idOf(draft);
    const coverage = check(await f.write(manager, 'put',
      `/settings/service-cities/${cityA.id}/service-areas/${areaId}/versions/${versionId}/district-coverage`,
      { districts: [{ districtId, relation: 'FULL', description: 'Advisory candidate only' }] },
      { etag: geoTag(versionOf(draft)) }), 200);
    expect(versionOf(coverage)).toBe(versionOf(draft) + 1);
    expect(await f.count('SELECT count(*)::int n FROM foundation.service_area_district_coverage WHERE area_version_id=$1',
      [versionId])).toBe(1);
    // Publishing stays a separate administrator operation, and city preparation and
    // administrative delegation are never manager rights.
    check(await f.write(manager, 'post',
      `/settings/service-cities/${cityA.id}/service-areas/${areaId}/versions/${versionId}/publish`, {},
      { etag: geoTag(versionOf(coverage)) }), 403);
    check(await f.write(manager, 'post', `/settings/service-cities/${cityA.id}/versions`, {
      displayName: 'Manager city version', addressDisplay: null, timezone: 'Europe/Moscow',
      publicContact: '+70000000000', officeHours: HOURS,
    }, { etag: geoTag(versionOf(check(await f.read(manager, `/settings/service-cities/${cityA.id}`), 200))) }), 403);
    check(await f.write(manager, 'post',
      `/settings/service-cities/${cityA.id}/administrators/${manager.id}/assignments`, {},
      { etag: geoTag(await f.staffVersion(manager.id)) }), 403);
    check(await f.createCity(manager, code('city-c')), 403);
    // A manager cannot revoke its own territory nor hand a city to another manager,
    // even while holding the geography write grants.
    const ownAssignment = text((await f.base.db.query<{ id: string }>(
      'SELECT id FROM foundation.staff_admin_city_assignments WHERE staff_id=$1 AND revoked_at IS NULL', [manager.id])).rows[0] ?? {}, 'id');
    check(await f.write(manager, 'post',
      `/settings/service-cities/${cityA.id}/administrators/${manager.id}/assignments/${ownAssignment}/revoke`, {},
      { etag: geoTag(await f.staffVersion(manager.id)) }), 403);
    const otherManager = f.remember(await f.base.webStaff());
    check(await f.write(manager, 'post',
      `/settings/service-cities/${cityA.id}/administrators/${otherManager.id}/assignments`, {},
      { etag: geoTag(await f.staffVersion(otherManager.id)) }), 403);
    expect(await f.count('SELECT count(*)::int n FROM foundation.staff_admin_city_assignments WHERE staff_id=$1',
      [otherManager.id])).toBe(0);
    // A city outside the trusted assignment is indistinguishable from a missing one.
    check(await f.read(manager, `/settings/service-cities/${cityB.id}`), 404);
    check(await f.read(manager, `/settings/service-cities/${cityB.id}/administrative-districts`), 404);
    check(await f.createDistrict(manager, cityB.id, 1, code('district')), 404);
    // The write capability alone is not authority: without the independent read grant
    // the same accepted write is refused, while the territory itself is unchanged.
    const withoutRead = (await roleGrants(f, admin, managerRole)).grants
      .filter((grant) => !grant.code.startsWith('geography.'))
      .concat([{ code: 'geography.manage', scope: 'CITY' }]);
    const current = await roleGrants(f, admin, managerRole);
    check(await f.write(admin, 'put', `/roles/${managerRole}/permissions`, { permissions: withoutRead }, { etag: current.etag }), 200);
    check(await f.createDistrict(manager, cityA.id, 1, code('district')), 403);
    expect(await f.count('SELECT count(*)::int n FROM foundation.administrative_districts WHERE city_id=$1', [cityA.id])).toBe(1);
    expect(await f.count(`SELECT count(*)::int n FROM foundation.staff_admin_city_assignments
      WHERE staff_id=$1 AND city_id=$2 AND revoked_at IS NULL`, [manager.id, cityA.id])).toBe(1);
  }, 60000);

  it('cannot replace the current zone by publishing a second draft with a stale area version', async () => {
    const f = open(); const admin = f.remember(f.base.admin);
    const city = await f.activeCity(admin, code('publish'));
    const area = check(await f.createArea(admin,city.id,city.version,code('zone')),201);
    const base = `/settings/service-cities/${city.id}/service-areas/${idOf(area)}`;
    const a = check(await f.addAreaVersion(admin,city.id,idOf(area),versionOf(area),'First draft'),201);
    const beforeB = versionOf(check(await f.read(admin,base),200));
    const b = check(await f.addAreaVersion(admin,city.id,idOf(area),beforeB,'Second draft'),201);
    const expectedAreaVersion = versionOf(check(await f.read(admin,base),200));
    const publish = (draft: typeof a) => f.write(admin,'post',`${base}/versions/${idOf(draft)}/publish`, {expectedAreaVersion}, {etag:geoTag(versionOf(draft))});
    const results = await Promise.all([publish(a), publish(b)]);
    expect(results.map(r => r.status).sort()).toEqual([200, 412]);
    const winner = results[0].status === 200 ? idOf(a) : idOf(b);
    expect(check(await f.read(admin,base),200).data['currentVersionId']).toBe(winner);
    expect(await f.count('SELECT count(*)::int n FROM foundation.service_area_versions WHERE area_id=$1 AND published_at IS NOT NULL',[idOf(area)])).toBe(1);
    check(await f.read(admin,`/catalog/service-areas/${idOf(area)}?cityId=${city.id}`),200);
    check(await f.read(admin,`/catalog/service-areas/${idOf(area)}`),400);
  }, 60000);

  it('shows a technician only its own active territory through the Telegram channel and never resurrects a revoked admission', async () => {
    const f = open(); const admin = f.remember(f.base.admin);
    const city = await f.activeCity(admin, code('city-t'));
    const technician = await f.base.createStaff('TECHNICIAN');
    const tg = await f.base.tg(technician);
    const otherTg = await f.base.tg(await f.base.createStaff('TECHNICIAN'));
    const area = check(await f.createArea(admin, city.id,
      versionOf(check(await f.read(admin, `/settings/service-cities/${city.id}`), 200)), code('area')), 201);
    const areaId = idOf(area);
    const draft = check(await f.addAreaVersion(admin, city.id, areaId, versionOf(area), 'Published zone'), 201);
    check(await f.publishAreaVersion(admin, city.id, areaId, idOf(draft), versionOf(draft)), 200);
    // A dated city admission, then a zone admission contained in it.
    const membershipKey = randomUUID();
    const anchor = Date.now();
    const day = (offset: number) => new Date(anchor + offset * 86_400_000).toISOString();
    const membershipBody = { validFrom: day(-10), validTo: day(30) };
    const membershipTag = geoTag(await f.staffVersion(technician));
    const membership = check(await f.write(admin, 'post',
      `/settings/service-cities/${city.id}/technicians/${technician}/city-memberships`,
      membershipBody, { etag: membershipTag, key: membershipKey }), 201);
    const membershipId = idOf(membership);
    const zone = check(await f.write(admin, 'post',
      `/settings/service-cities/${city.id}/technicians/${technician}/service-area-grants`,
      { areaId, validFrom: day(-5), validTo: day(10) },
      { etag: geoTag(versionOf(membership)) }), 201);
    // The real Telegram bearer sees exactly its own active rows; other channels and
    // other technicians do not.
    const territory = check(await f.tgRead(tg.token, '/telegram/technicians/self/territory'), 200);
    const cities = itemsOf(territory);
    expect(cities.map((row) => text(row, 'cityId'))).toEqual([city.id]);
    expect(records(cities[0]?.['zones']).map((row) => text(row, 'areaId'))).toEqual([areaId]);
    expect(itemsOf(check(await f.tgRead(otherTg.token, '/telegram/technicians/self/territory'), 200))).toEqual([]);
    check(await f.read(admin, '/telegram/technicians/self/territory'), 401);
    check(await f.tgWrite(tg.token, 'post',
      `/settings/service-cities/${city.id}/administrators/${technician}/assignments`, {}), 401);
    // A grant id that belongs to another technician or another city is indistinguishable
    // from a missing one, and the foreign row stays untouched.
    const stranger = await f.base.createStaff('TECHNICIAN');
    const strangerMembership = check(await f.write(admin, 'post',
      `/settings/service-cities/${city.id}/technicians/${stranger}/city-memberships`,
      membershipBody, { etag: geoTag(await f.staffVersion(stranger)) }), 201);
    check(await f.write(admin, 'post',
      `/settings/service-cities/${city.id}/technicians/${technician}/city-memberships/${idOf(strangerMembership)}/revoke`, {},
      { etag: geoTag(versionOf(zone)) }), 404);
    const otherCity = await f.publishedDraftCity(admin, code('city-x'));
    check(await f.write(admin, 'post',
      `/settings/service-cities/${otherCity.id}/technicians/${technician}/city-memberships/${membershipId}/revoke`, {},
      { etag: geoTag(versionOf(zone)) }), 404);
    check(await f.write(admin, 'post',
      `/settings/service-cities/${city.id}/technicians/${stranger}/service-area-grants/${idOf(zone)}/revoke`, {},
      { etag: geoTag(await f.staffVersion(stranger)) }), 404);
    expect(await f.count('SELECT count(*)::int n FROM foundation.technician_city_memberships WHERE technician_id=$1 AND revoked_at IS NULL',
      [stranger])).toBe(1);
    expect(await f.count('SELECT count(*)::int n FROM foundation.technician_city_memberships WHERE id=$1 AND revoked_at IS NULL',
      [membershipId])).toBe(1);
    // Revoking the city admission also revokes the contained zone admission; history stays.
    const revoked = check(await f.write(admin, 'post',
      `/settings/service-cities/${city.id}/technicians/${technician}/city-memberships/${membershipId}/revoke`, {},
      { etag: geoTag(versionOf(zone)) }), 200);
    expect(revoked.data).toEqual({ id: membershipId, version: versionOf(zone) + 1 });
    expect(await f.count('SELECT count(*)::int n FROM foundation.technician_city_memberships WHERE technician_id=$1 AND revoked_at IS NULL',
      [technician])).toBe(0);
    expect(await f.count('SELECT count(*)::int n FROM foundation.technician_service_areas WHERE technician_id=$1 AND revoked_at IS NULL',
      [technician])).toBe(0);
    expect(await f.count('SELECT count(*)::int n FROM foundation.technician_city_memberships WHERE id=$1', [membershipId])).toBe(1);
    expect(itemsOf(check(await f.tgRead(tg.token, '/telegram/technicians/self/territory'), 200))).toEqual([]);
    // Replaying the exact accepted command (same key, body and validator) may return the
    // stored receipt, but it cannot reissue the admission: no live row appears and the
    // master summary stays empty.
    const replay = check(await f.write(admin, 'post',
      `/settings/service-cities/${city.id}/technicians/${technician}/city-memberships`,
      membershipBody, { etag: membershipTag, key: membershipKey }), 200);
    expect(replay.data).toMatchObject({ id: membershipId });
    expect(await f.count('SELECT count(*)::int n FROM foundation.technician_city_memberships WHERE technician_id=$1 AND revoked_at IS NULL',
      [technician])).toBe(0);
    expect(itemsOf(check(await f.tgRead(tg.token, '/telegram/technicians/self/territory'), 200))).toEqual([]);
  }, 60000);

  it('serializes stale updates, a revoked assignment and a concurrent write, and rolls the whole command back on audit failure', async () => {
    const f = open(); const admin = f.remember(f.base.admin);
    const city = await f.activeCity(admin, code('city-r'));
    const manager = f.remember(await f.base.webStaff());
    const managerRole = await f.base.systemRole('MANAGER');
    check(await f.write(admin, 'post',
      `/settings/service-cities/${city.id}/administrators/${manager.id}/assignments`, {},
      { etag: geoTag(await f.staffVersion(manager.id)) }), 201);
    await addGeoToRole(f, admin, managerRole,
      [{ code: 'geography.read', scope: 'CITY' }, { code: 'geography.manage', scope: 'CITY' }]);
    const district = check(await f.createDistrict(manager, city.id,
      versionOf(check(await f.read(manager, `/settings/service-cities/${city.id}`), 200)), code('district')), 201);
    const districtId = idOf(district);
    const staleTag = geoTag(versionOf(district));
    // Two writers holding the same ETag: exactly one wins, the loser is 412, and the
    // stored name is the winner's.
    const [first, second] = await f.base.race(
      () => f.write(manager, 'patch', `/settings/service-cities/${city.id}/administrative-districts/${districtId}`,
        { name: 'First writer' }, { etag: staleTag }),
      () => f.write(manager, 'patch', `/settings/service-cities/${city.id}/administrative-districts/${districtId}`,
        { name: 'Second writer' }, { etag: staleTag }),
    );
    expect([first.status, second.status].sort()).toEqual([200, 412]);
    const winner = first.status === 200 ? 'First writer' : 'Second writer';
    const stored = await f.base.db.query<{ name: string; row_version: number }>(
      'SELECT name, row_version FROM foundation.administrative_districts WHERE id=$1', [districtId]);
    expect(stored.rows[0]).toEqual({ name: winner, row_version: 2 });
    // Idempotency: the same key and canonical body replay the same receipt without a
    // second row; a different body under the same key is a conflict.
    const key = randomUUID();
    const body = { code: code('district'), name: 'Idempotent district' };
    const cityVersion = versionOf(check(await f.read(manager, `/settings/service-cities/${city.id}`), 200));
    const created = check(await f.write(manager, 'post', `/settings/service-cities/${city.id}/administrative-districts`,
      body, { etag: geoTag(cityVersion), key }), 201);
    const replayed = check(await f.write(manager, 'post', `/settings/service-cities/${city.id}/administrative-districts`,
      body, { etag: geoTag(cityVersion), key }), 200);
    expect(replayed.data).toEqual(created.data);
    // The replayed response is a successful read-back of the stored receipt, not a second
    // 201: the aggregate token is the one the original command produced.
    expect(replayed.etag).toBe(created.etag);
    check(await f.write(manager, 'post', `/settings/service-cities/${city.id}/administrative-districts`,
      { ...body, name: 'Different body' }, { etag: geoTag(cityVersion + 1), key }), 409);
    expect(await f.count('SELECT count(*)::int n FROM foundation.administrative_districts WHERE id=$1', [idOf(created)])).toBe(1);
    // Revoking the manager's city assignment denies a replay of an already accepted write
    // under the same Idempotency-Key: no entity and no audit row is produced.
    const acceptedKey = randomUUID();
    const acceptedBody = { code: code('district'), name: 'Before revoke' };
    const accepted = check(await f.write(manager, 'post', `/settings/service-cities/${city.id}/administrative-districts`,
      acceptedBody, { etag: geoTag(cityVersion + 1), key: acceptedKey }), 201);
    const acceptedId = idOf(accepted);
    const auditForAccepted = () => f.count(
      `SELECT count(*)::int n FROM foundation.audit_logs WHERE operation='GEOGRAPHY_CHANGED' AND details->>'entityId'=$1`, [acceptedId]);
    expect(await auditForAccepted()).toBe(1);
    const assignmentId = text((await f.base.db.query<{ id: string }>(
      'SELECT id FROM foundation.staff_admin_city_assignments WHERE staff_id=$1 AND revoked_at IS NULL', [manager.id])).rows[0] ?? {}, 'id');
    check(await f.write(admin, 'post',
      `/settings/service-cities/${city.id}/administrators/${manager.id}/assignments/${assignmentId}/revoke`, {},
      { etag: geoTag(await f.staffVersion(manager.id)) }), 200);
    const denied = check(await f.write(manager, 'post', `/settings/service-cities/${city.id}/administrative-districts`,
      acceptedBody, { etag: geoTag(cityVersion + 2), key: acceptedKey }), 404);
    expect(JSON.stringify(denied.body).includes('Before revoke')).toBe(false);
    expect(await f.count('SELECT count(*)::int n FROM foundation.administrative_districts WHERE id=$1', [acceptedId])).toBe(1);
    expect(await auditForAccepted()).toBe(1);
    expect(await f.count(`SELECT count(*)::int n FROM foundation.staff_admin_city_assignments
      WHERE id=$1 AND revoked_at IS NOT NULL`, [assignmentId])).toBe(1);
    // An audit write failure rolls the entire command back, including its receipt, so the
    // same command succeeds after the fault is removed.
    await f.base.db.query(`ALTER TABLE foundation.audit_logs ADD CONSTRAINT fixture_inject_geo_audit_failure
      CHECK (operation <> 'GEOGRAPHY_CHANGED') NOT VALID`);
    const failureKey = randomUUID();
    const failedBody = { code: code('district'), name: 'Rolled back' };
    try {
      const failed = check(await f.write(admin, 'post', `/settings/service-cities/${city.id}/administrative-districts`,
        failedBody, { etag: geoTag(versionOf(check(await f.read(admin, `/settings/service-cities/${city.id}`), 200))), key: failureKey }), 500);
      // A persistence failure of the audit/outbox/receipt part is a server failure, never a
      // domain conflict: the client learns nothing about the injected constraint.
      expect(failed.body).toMatchObject({ code: 'INTERNAL_ERROR' });
      expect(JSON.stringify(failed.body).includes('fixture_inject')).toBe(false);
      expect(await f.count('SELECT count(*)::int n FROM foundation.geography_command_receipts WHERE key=$1', [failureKey])).toBe(0);
      expect(await f.count("SELECT count(*)::int n FROM foundation.administrative_districts WHERE name='Rolled back'")).toBe(0);
    } finally {
      await f.base.db.query('ALTER TABLE foundation.audit_logs DROP CONSTRAINT fixture_inject_geo_audit_failure');
    }
    const retried = check(await f.write(admin, 'post', `/settings/service-cities/${city.id}/administrative-districts`,
      failedBody, { etag: geoTag(versionOf(check(await f.read(admin, `/settings/service-cities/${city.id}`), 200))), key: failureKey }), 201);
    expect(await f.count('SELECT count(*)::int n FROM foundation.administrative_districts WHERE id=$1', [idOf(retried)])).toBe(1);
    // Concurrent assignment revocation against a running write: whichever order the race
    // takes, the result is consistent and leaves no orphan district or audit row.
    for (const order of ['revoke-first', 'write-first'] as const) {
      const target = await f.base.webStaff();
      check(await f.write(admin, 'post',
        `/settings/service-cities/${city.id}/administrators/${target.id}/assignments`, {},
        { etag: geoTag(await f.staffVersion(target.id)) }), 201);
      const grantId = text((await f.base.db.query<{ id: string }>(
        'SELECT id FROM foundation.staff_admin_city_assignments WHERE staff_id=$1 AND revoked_at IS NULL', [target.id])).rows[0] ?? {}, 'id');
      const targetVersion = await f.staffVersion(target.id);
      const cityTag = geoTag(versionOf(check(await f.read(target, `/settings/service-cities/${city.id}`), 200)));
      const name = `Race ${order}`;
      const revoke = () => f.write(admin, 'post',
        `/settings/service-cities/${city.id}/administrators/${target.id}/assignments/${grantId}/revoke`, {},
        { etag: geoTag(targetVersion) });
      const write = () => f.write(target, 'post', `/settings/service-cities/${city.id}/administrative-districts`,
        { code: code('district'), name }, { etag: cityTag });
      const [a, b] = order === 'revoke-first' ? await f.base.race(revoke, write) : await f.base.race(write, revoke);
      if (order === 'revoke-first') { check(a, 200); check(b, 404); }
      else { check(a, 201); check(b, 200); }
      expect(await f.count('SELECT count(*)::int n FROM foundation.administrative_districts WHERE city_id=$1 AND name=$2',
        [city.id, name])).toBe(order === 'write-first' ? 1 : 0);
      expect(await f.count(`SELECT count(*)::int n FROM foundation.staff_admin_city_assignments
        WHERE id=$1 AND revoked_at IS NOT NULL`, [grantId])).toBe(1);
    }
  }, 90000);
});
