import { expect, it } from 'vitest';
import { check, text } from './geography-fixture.js';
import { p04PerTest, p04Path, page } from './p0403-http-fixture.js';
import { integration } from './rbac-fixture.js';
import { city, global, problem } from './settings-management-fixture.js';

integration('P04-04 scoped CRM access projection (isolated PostgreSQL)', () => {
  const fixture = p04PerTest();

  it('projects only the signed-in actor’s active assigned cities; no extra authority, grants or scope on revocation', async () => {
    const f = fixture();
    const field = 'p04PricingWriteCityIds';
    const access = async (web = f.admin) => check(await f.read('/access', { web }), 200).data;
    problem(await f.read('/access', { web: null }), 401);
    expect(await access()).not.toHaveProperty(field);
    await f.asCatalog();
    const { primary, other } = await f.cities();
    const ordinary = await f.base.webStaff();
    const delegate = await f.base.webStaff();
    const adminRole = await f.base.systemRole('ADMIN');
    check(await f.base.assign(delegate.id, adminRole), 200);
    check(await f.addRoleGrants(adminRole, [global('pricing.read'), city('pricing.manage')]), 200);
    check(await f.addRoleGrants(await f.base.systemRole('MANAGER'), [city('pricing.read')]), 200);
    const scopedAdmin = await f.base.login(delegate.id, delegate.login, delegate.password);
    expect((await access(scopedAdmin))[field]).toEqual([]);
    expect((await access(ordinary))[field]).toEqual([]);
    const assignment = check(await f.assignCity(delegate.id, primary.id), 201);
    check(await f.assignCity(ordinary.id, primary.id), 201);
    check(await f.assignCity(delegate.id, other.id), 409); // P03 refuses assignments to an inactive city.
    expect((await access(scopedAdmin))[field]).toEqual([primary.id]);
    expect((await access(ordinary))[field]).toEqual([primary.id]);
    expect(await access()).not.toHaveProperty(field); // founder’s effective write grant is GLOBAL
    expect(page(check(await f.read(p04Path('cityList'), { web: scopedAdmin }), 200))).toEqual([expect.objectContaining({ id: primary.id })]);
    await f.base.db.query(`UPDATE foundation.staff_admin_city_assignments SET revoked_at=clock_timestamp(),revoked_by=$2 WHERE id=$1`,
      [text(assignment.data, 'id'), f.admin.id]);
    expect((await access(scopedAdmin))[field]).toEqual([]);
    const path = p04Path('policyPublish', { cityId: primary.id });
    problem(await f.post(path, { validFrom: await f.dbInstant(), sourceRef: 'Synthetic proof', currency: 'RUB', taxDisplay: 'Synthetic',
      roundingMode: 'HALF_UP', units: { piece: 0 }, maxManualDeltaMinor: '0', priorities: [], compatibilities: [] },
    { web: scopedAdmin, etag: '"p04-v0"' }), 404);
  }, 30_000);
});
