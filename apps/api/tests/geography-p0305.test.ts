import { expect, it } from 'vitest';
import type { PoolClient } from 'pg';
import { GeographyFixture, check, geoTag, idOf, itemsOf, text, versionOf } from './geography-fixture.js';
import type { GeoResult } from './geography-fixture.js';
import { fixturePerTest, integration, record } from './rbac-fixture.js';

const base = '/settings/service-cities';

/** Wraps guarded GEO/CFG basis DML (migration 022) in one transaction that holds
 * the unified writer fence before its first statement, on one pinned pool client. */
async function fencedDml<T>(f: GeographyFixture, run: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await f.base.db.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(734305,1)');
    const result = await run(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}
const pageIds = (result: GeoResult) => itemsOf(result).map(row => text(row, 'id'));
function more(result: GeoResult): string {
  const pageInfo = record(result.data['pageInfo']);
  expect(pageInfo['hasMore']).toBe(true);
  return encodeURIComponent(text(pageInfo, 'nextCursor'));
}
const finalPage = { hasMore: false, nextCursor: null };

integration('P03-05 geography pagination and full coverage over closed HTTP + isolated PostgreSQL', () => {
  const fixture = fixturePerTest();
  const open = () => new GeographyFixture(fixture());

  it('pages trusted catalog results, rejects cross-filter/parent cursors and keeps aggregate ETags', async () => {
    const f = open(), admin = f.base.admin;
    const city = await f.activeCity(admin, 'visible-city');
    const hidden = await f.publishedDraftCity(admin, 'hidden-city');
    const manager = await f.base.webStaff();
    check(await f.write(admin, 'post', `${base}/${city.id}/administrators/${manager.id}/assignments`, {},
      { etag: geoTag(await f.staffVersion(manager.id)) }), 201);
    const role = await f.base.systemRole('MANAGER');
    check(await f.replaceRolePermissions(admin, role, [{ code: 'geography.read', scope: 'CITY' }]), 200);
    const visible = check(await f.read(manager, `${base}?limit=1`), 200);
    expect(pageIds(visible)).toEqual([city.id]);
    expect(visible.data['pageInfo']).toEqual(finalPage);
    const all = check(await f.read(admin, `${base}?limit=1`), 200);
    expect(pageIds(all)).toEqual([hidden.id]);
    check(await f.read(manager, `${base}?limit=1&cursor=${more(all)}`), 400);
    const rest = check(await f.read(admin, `${base}?limit=1&cursor=${more(all)}`), 200);
    expect(pageIds(rest)).toEqual([city.id]);
    expect(rest.data['pageInfo']).toEqual(finalPage);
    for (const query of ['limit=0', 'limit=201', 'limit=1&%6cimit=1', 'cursor=%FF', 'cursor=eA', 'offset=1']) {
      check(await f.read(admin, `${base}?${query}`), 400);
    }

    const cityVersion = check(await f.addCityVersion(admin, city.id, city.version), 201);
    const first = check(await f.read(admin, `${base}/${city.id}/versions?limit=1`), 200);
    expect(pageIds(first)).toEqual([idOf(cityVersion)]);
    expect(first.etag).toBe(geoTag(versionOf(cityVersion)));
    const versionsNext = `?limit=1&cursor=${more(first)}`;
    const oldest = check(await f.read(admin, `${base}/${city.id}/versions${versionsNext}`), 200);
    expect(pageIds(oldest)).toEqual([city.versionId]);
    expect(oldest.etag).toBe(first.etag);
    expect(oldest.data['pageInfo']).toEqual(finalPage);
    check(await f.read(admin, `${base}/${hidden.id}/versions${versionsNext}`), 400);
    check(await f.read(manager, `${base}/${hidden.id}/versions${versionsNext}`), 404);

    // More than 200 authorized rows, and an earlier archived row that must not
    // consume the first slot or count as continuation when filtered out.
    const districts = `${base}/${city.id}/administrative-districts`;
    await fencedDml(f, (client) => client.query(`INSERT INTO foundation.administrative_districts(id,city_id,code,name,archived_at)
      SELECT gen_random_uuid(),$1,'district-'||lpad(i::text,3,'0'),'Synthetic district',
        CASE WHEN i=0 THEN statement_timestamp() END FROM generate_series(0,202) i`, [city.id]));
    const defaultPage = check(await f.read(manager, `${districts}?includeArchived=false`), 200);
    expect(itemsOf(defaultPage)).toHaveLength(50);
    expect(defaultPage.etag).toBe(first.etag);
    const districtsPage = check(await f.read(manager, `${districts}?limit=200&includeArchived=false`), 200);
    const firstItems = itemsOf(districtsPage);
    expect(firstItems).toHaveLength(200);
    expect(firstItems[0]?.['code']).toBe('district-001');
    const tailQuery = `limit=200&cursor=${more(districtsPage)}`;
    check(await f.read(manager, `${districts}?${tailQuery}&includeArchived=true`), 400);
    const districtTail = check(await f.read(manager, `${districts}?${tailQuery}&includeArchived=false`), 200);
    expect(itemsOf(districtTail).map(row => row['code'])).toEqual(['district-201', 'district-202']);
    expect(districtTail.data['pageInfo']).toEqual(finalPage);
    expect(districtTail.etag).toBe(first.etag);
  }, 60_000);

  it('refuses a valid-length 200-item history whose escaped JSON exceeds 512 KiB', async () => {
    const f = open(), admin = f.base.admin;
    const city = await f.activeCity(admin, 'byte-budget-city');
    const area = check(await f.createArea(admin, city.id, city.version, 'byte-budget-area'), 201);
    const path = `${base}/${city.id}/service-areas/${idOf(area)}/versions`;
    // 2,000 permitted characters per field, but U+0001 expands to six JSON bytes.
    const escaped = '\u0001'.repeat(2_000);
    await fencedDml(f, (client) => client.query(`INSERT INTO foundation.service_area_versions
      (id,city_id,area_id,version,name,coverage_description,address_criteria,created_by)
      SELECT gen_random_uuid(),$1,$2,i,'Synthetic escaped history',$3,$3,$4 FROM generate_series(1,200) i`,
    [city.id, idOf(area), escaped, admin.id]));
    const small = check(await f.read(admin, `${path}?limit=1`), 200);
    expect(small.etag).toBe(area.etag);
    expect(itemsOf(small)[0]?.['coverageDescription']).toBe(escaped);
    const refused = check(await f.read(admin, `${path}?limit=200`), 500);
    expect(refused.payload).toBeUndefined();
    expect(JSON.stringify(refused.body)).not.toContain('Synthetic escaped history');
  }, 60_000);

  it('keeps the complete 200-row draft separate from the district picker and refuses over-limit history instead of truncating', async () => {
    const f = open(), admin = f.base.admin;
    const city = await f.activeCity(admin, 'coverage-city');
    const cityPath = `${base}/${city.id}`;
    const records = await fencedDml(f, (client) => client.query<{ id: string; code: string }>(`INSERT INTO foundation.administrative_districts(id,city_id,code,name)
      SELECT gen_random_uuid(),$1,'district-'||lpad(i::text,3,'0'),'Synthetic district'
      FROM generate_series(1,201) i RETURNING id,code`, [city.id]));
    const [first, ...remaining] = records.rows.sort((a, b) => a.code.localeCompare(b.code));
    const archived = remaining.find(row => row.code === 'district-200');
    const overflow = remaining.find(row => row.code === 'district-201');
    if (!first || !archived || !overflow) { throw new Error('Incomplete isolated coverage fixture'); }
    const area = check(await f.createArea(admin, city.id, city.version, 'area-a'), 201);
    const areaId = idOf(area);
    const draft = check(await f.addAreaVersion(admin, city.id, areaId, versionOf(area), 'Coverage draft'), 201);
    const rev = idOf(draft);
    const path = `${cityPath}/service-areas/${areaId}/versions/${rev}/district-coverage`;
    const districts = [first, ...remaining.filter(row => row.id !== overflow.id)]
      .map(({ id }) => ({ districtId: id, relation: 'FULL', description: 'Original synthetic coverage' }));
    const mapped = check(await f.write(admin, 'put', path, { districts }, { etag: draft.etag }), 200);
    const districtPath = `${cityPath}/administrative-districts/${archived.id}`;
    const district = check(await f.read(admin, districtPath), 200);
    check(await f.write(admin, 'post', `${districtPath}/archive`, {}, { etag: district.etag }), 200);
    const picker = check(await f.read(admin, `${cityPath}/administrative-districts?limit=1&includeArchived=false`), 200);
    expect(pageIds(picker)).toEqual([first.id]);
    more(picker);
    const full = check(await f.read(admin, path), 200);
    expect(full.data['pageInfo']).toBeUndefined();
    expect(full.etag).toBe(mapped.etag);
    expect(itemsOf(full)).toHaveLength(200);
    expect(itemsOf(full)).toEqual(expect.arrayContaining(districts));
    check(await f.read(admin, `${path}?limit=1`), 400);

    const retained = itemsOf(full).map(row => row['districtId'] === first.id ? { ...row, description: 'Edited visible row' } : row);
    const changed = check(await f.write(admin, 'put', path, { districts: retained }, { etag: full.etag }), 200);
    const after = check(await f.read(admin, path), 200);
    expect(itemsOf(after)).toEqual(retained);
    expect(after.etag).toBe(changed.etag);
    const editedArchived = retained.map(row => row['districtId'] === archived.id ? { ...row, relation: 'PARTIAL' } : row);
    check(await f.write(admin, 'put', path, { districts: editedArchived }, { etag: after.etag }), 409);
    check(await f.publishAreaVersion(admin, city.id, areaId, rev, versionOf(after)), 409);

    const explicitRemoval = retained.filter(row => row['districtId'] !== archived.id);
    check(await f.write(admin, 'put', path, { districts: explicitRemoval }, { etag: after.etag }), 200);
    const afterRemoval = check(await f.read(admin, path), 200);
    expect(itemsOf(afterRemoval)).toEqual(explicitRemoval);
    check(await f.write(admin, 'put', path, { districts: retained }, { etag: afterRemoval.etag }), 409);

    // Older privileged SQL imports were not upper-bounded by the schema. Model an
    // oversized draft in this isolated DB; the API must refuse the entire response.
    await fencedDml(f, (client) => client.query(`INSERT INTO foundation.service_area_district_coverage(city_id,area_version_id,district_id,relation)
      VALUES ($1,$2,$3,'FULL'),($1,$2,$4,'FULL')`, [city.id, rev, archived.id, overflow.id]));
    const refused = check(await f.read(admin, path), 500);
    expect(refused.payload).toBeUndefined();
    expect(JSON.stringify(refused.body)).not.toContain(archived.id);
  }, 60_000);

  it('keeps genuinely fresh staff at version zero until their first territory write', async () => {
    const f = open(), admin = f.base.admin;
    const city = await f.activeCity(admin, 'fresh-territory-city');
    const techId = await f.base.createStaff('TECHNICIAN');
    const manager = await f.base.webStaff();
    expect(await f.staffVersion(techId)).toBe(0);
    expect(await f.staffVersion(manager.id)).toBe(0);
    const cityPath = `${base}/${city.id}`;
    const picker = check(await f.read(admin, `${cityPath}/technicians`), 200);
    expect(picker.data).toEqual({ items: [{ id: techId, displayName: null, version: 0 }], pageInfo: finalPage });
    const memberships = `${cityPath}/technicians/${techId}/city-memberships`;
    const zones = `${cityPath}/technicians/${techId}/service-area-grants`;
    const assignments = `${cityPath}/administrators/${manager.id}/assignments`;
    const empty = { items: [], version: 0, pageInfo: finalPage };
    for (const path of [memberships, zones, assignments]) {
      const history = check(await f.read(admin, path), 200);
      expect(history.data).toEqual(empty);
      expect(history.etag).toBe('"geo-v0"');
    }

    const admitted = check(await f.write(admin, 'post', memberships, { validFrom: '2025-01-01T00:00:00Z' },
      { etag: '"geo-v0"' }), 201);
    const assigned = check(await f.write(admin, 'post', assignments, {}, { etag: '"geo-v0"' }), 201);
    for (const [path, receipt, staffId] of [[memberships, admitted, techId], [assignments, assigned, manager.id]] as const) {
      expect(versionOf(receipt)).toBe(1);
      expect(receipt.etag).toBe('"geo-v1"');
      expect(await f.staffVersion(staffId)).toBe(1);
      const history = check(await f.read(admin, path), 200);
      expect(versionOf(history)).toBe(1);
      expect(history.etag).toBe(receipt.etag);
      expect(pageIds(history)).toEqual([idOf(receipt)]);
    }
  }, 60_000);

  it('uses independent staff geography capability and the same technician visibility on every page', async () => {
    const f = open(), admin = f.base.admin;
    const city = await f.activeCity(admin, 'picker-city');
    const foreign = await f.publishedDraftCity(admin, 'foreign-city');
    const manager = await f.base.webStaff();
    const assigned = `${base}/${city.id}/administrators/${manager.id}/assignments`;
    const assignment = check(await f.write(admin, 'post', assigned, {}, { etag: geoTag(await f.staffVersion(manager.id)) }), 201);
    const role = await f.base.systemRole('MANAGER');
    check(await f.replaceRolePermissions(admin, role, [{ code: 'geography.read', scope: 'CITY' }]), 200);
    const picker = `${base}/${city.id}/technicians`;
    check(await f.read(manager, picker), 403);
    check(await f.replaceRolePermissions(admin, role, [{ code: 'staff.geography.read', scope: 'CITY' }]), 200);
    const technicians = await Promise.all(Array.from({ length: 3 }, () => f.base.createStaff('TECHNICIAN')));
    // Lower hidden UUID makes the test fail if filtering is applied after LIMIT.
    technicians.sort();
    const [hidden, visible, related] = technicians;
    if (!hidden || !visible || !related) { throw new Error('Incomplete isolated picker fixture'); }
    const custom = idOf(check(await f.write(admin, 'post', '/roles', { name: 'Synthetic worker', description: 'Fixture' }), 201));
    expect((await f.base.assign(related, custom)).status).toBe(200);
    const interval = { validFrom: '2025-01-01T00:00:00Z', validTo: '2026-01-01T00:00:00Z' };
    for (const technician of [related, visible]) {
      check(await f.write(admin, 'post', `${picker}/${technician}/city-memberships`, interval,
        { etag: geoTag(await f.staffVersion(technician)) }), 201);
    }
    check(await f.read(manager, `${base}/${foreign.id}/technicians`), 404);
    check(await f.read(manager, base), 403);
    const first = check(await f.read(manager, `${picker}?limit=1`), 200);
    expect(itemsOf(first)).toEqual([{ id: visible, displayName: null, version: await f.staffVersion(visible) }]);
    const cursor = more(first);
    const next = check(await f.read(manager, `${picker}?limit=1&cursor=${cursor}`), 200);
    expect(itemsOf(next)).toEqual([{ id: related, displayName: null, version: await f.staffVersion(related) }]);
    expect(next.data['pageInfo']).toEqual(finalPage);
    check(await f.read(manager, `${picker}/${hidden}/city-memberships`), 404);
    const periods = `${picker}/${related}/city-memberships`;
    check(await f.write(admin, 'post', periods, { validFrom: '2026-01-01T00:00:00Z' },
      { etag: geoTag(await f.staffVersion(related)) }), 201);
    const m1 = check(await f.read(manager, `${periods}?limit=1`), 200);
    expect(itemsOf(m1)[0]?.['validFrom']).toBe('2025-01-01T00:00:00.000Z');
    const m2 = check(await f.read(manager, `${periods}?limit=1&cursor=${more(m1)}`), 200);
    expect(itemsOf(m2)[0]?.['validFrom']).toBe('2026-01-01T00:00:00.000Z');
    expect(m2.etag).toBe(m1.etag);
    expect(m2.data['pageInfo']).toEqual(finalPage);
    check(await f.read(manager, `${picker}/${visible}/city-memberships?cursor=${more(m1)}`), 400);
    const listing = check(await f.read(admin, `${assigned}?limit=1`), 200);
    expect(listing.data['pageInfo']).toEqual(finalPage);
    expect(pageIds(listing)).toEqual([idOf(assignment)]);
    check(await f.write(admin, 'post', `${assigned}/${idOf(assignment)}/revoke`, {}, { etag: listing.etag }), 200);
    check(await f.read(manager, `${picker}?cursor=${cursor}`), 404);
  }, 60_000);
});
