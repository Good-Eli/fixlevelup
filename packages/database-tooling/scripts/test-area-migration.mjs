import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { connection, credentials } from './migration-local.mjs';
import { proveCityReadGrants } from './test-city-migration.mjs';

// Keep this inventory independent of the DDL: a dropped or weakened guard must fail CI.
export const areaChecks = [
  'administrative_districts_code_check', 'administrative_districts_name_check', 'administrative_districts_row_version_check',
  'service_areas_code_check', 'service_areas_row_version_check',
  'service_area_versions_version_check', 'service_area_versions_row_version_check', 'service_area_versions_name_check',
  'service_area_versions_coverage_description_check', 'service_area_versions_address_criteria_check',
  'service_area_versions_publication_pair_check',
  'service_area_district_coverage_relation_check', 'service_area_district_coverage_description_check',
];

const areaTables = ['administrative_districts', 'service_areas', 'service_area_versions', 'service_area_district_coverage'];
const guardFunctions = ['service_areas_guard_pointer', 'administrative_districts_guard_update',
  'service_area_versions_guard_change', 'service_area_district_coverage_guard_change', 'service_area_history_reject_truncate'];

async function denied(query, sqlState, label) {
  await assert.rejects(query, (error) => error.code === sqlState, `Expected SQLSTATE ${sqlState}${label ? `: ${label}` : ''}`);
}
// 55P03 lock_not_available proves a statement really waits for the held revision row lock.
async function blocked(query, label) {
  await assert.rejects(query, (error) => error.code === '55P03', `Expected a held row lock to block${label ? `: ${label}` : ''}`);
}

// 011 grants the application role nothing at all, not even SELECT: the audited read
// and write path is a later reviewed sub-step and no capability is implied here.
export async function proveAreaRuntimeGrants(runtime) {
  for (const table of areaTables) {
    const target = `foundation.${table}`;
    const broad = await runtime.query(`SELECT has_table_privilege(current_user,$1,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') AS table_any,
      has_any_column_privilege(current_user,$1,'SELECT,INSERT,UPDATE,REFERENCES') AS column_any`, [target]);
    assert.equal(broad.rows[0].table_any, false, `Runtime table privilege on ${table}`);
    assert.equal(broad.rows[0].column_any, false, `Runtime column privilege on ${table}`);
    const columns = await runtime.query(`SELECT attname FROM pg_attribute WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped
      AND has_column_privilege(current_user,attrelid,attnum,'SELECT,INSERT,UPDATE,REFERENCES')`, [target]);
    assert.equal(columns.rowCount, 0, `Runtime per-column privilege on ${table}`);
    await denied(runtime.query(`SELECT * FROM ${target}`), '42501');
    await denied(runtime.query(`INSERT INTO ${target} DEFAULT VALUES`), '42501');
    await denied(runtime.query(`DELETE FROM ${target}`), '42501');
    await denied(runtime.query(`TRUNCATE ${target}`), '42501');
  }
  for (const [table, assignment] of [['administrative_districts', 'name=name'], ['service_areas', 'code=code'],
    ['service_area_versions', 'name=name'], ['service_area_district_coverage', 'relation=relation']]) {
    await denied(runtime.query(`UPDATE foundation.${table} SET ${assignment}`), '42501');
  }
  const { rows } = await runtime.query(`SELECT p.proname FROM pg_proc p
    WHERE p.pronamespace='foundation'::regnamespace AND p.proname=ANY($1::text[])
      AND pg_get_userbyid(p.proowner)='fixlevelup_migrator' AND NOT p.prosecdef
      AND 'search_path=pg_catalog'=ANY(p.proconfig)
      AND NOT has_function_privilege(current_user,p.oid,'EXECUTE')
      AND NOT EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl
        WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE')`, [guardFunctions]);
  assert.deepEqual(rows.map((row) => row.proname).sort(), [...guardFunctions].sort());
  console.log('P03-02 runtime: no table/column grant, no DML/TRUNCATE and no guard EXECUTE on area geography: PASS');
}

// Runs on the populated 010 database from the city proof: 011 is applied to real
// synthetic city history, then exercised with two cities, districts, zones and M:N
// coverage. No test DDL in the working application database.
export async function proveAreaUpgrade(db, deploy) {
  const { rows: [identity] } = await db.query('SELECT current_database() AS db, current_user AS role');
  assert.match(identity.db, /^fixlevelup_p017a_upgrade_[a-f0-9]{12}$/);
  assert.equal(identity.role, 'fixlevelup_migrator');
  const cityTables = ['service_cities', 'service_city_versions', 'business_settings_versions'];
  const citySnapshot = async () => {
    const rows = [];
    for (const table of cityTables) { rows.push((await db.query(`SELECT * FROM foundation.${table} ORDER BY id`)).rows); }
    return rows;
  };
  const citiesBefore = await citySnapshot();
  for (const table of areaTables) {
    assert.equal((await db.query(`SELECT to_regclass('foundation.${table}') AS ref`)).rows[0].ref, null, '011 applied before its proof');
  }
  deploy();
  // The zero-privilege proof is anchored at exactly 011 on this isolated database:
  // a later activation migration may grant the audited write path, so the fresh
  // latest database is not a valid place to assert 011 granted nothing.
  const runtime = connection('fixlevelup_runtime', credentials().fixlevelup_runtime, identity.db);
  await runtime.connect();
  try {
    // 011 must not widen the nine 010 resolver columns either.
    await proveCityReadGrants(runtime);
    await proveAreaRuntimeGrants(runtime);
  } finally { await runtime.end(); }
  assert.deepEqual(await citySnapshot(), citiesBefore, '011 changed the populated 010 fixture');
  for (const table of areaTables) {
    assert.equal((await db.query(`SELECT FROM foundation.${table}`)).rowCount, 0, `Unexpected seed in ${table}`);
  }
  const { rows: cities } = await db.query('SELECT id,code FROM foundation.service_cities ORDER BY code');
  assert.equal(cities.length, 2, 'Expected the two synthetic 010 cities');
  assert.deepEqual(cities.map((city) => city.code), ['test-east', 'test-west']);
  const [east, west] = cities;
  const staff = (await db.query("SELECT id FROM foundation.staff WHERE role='ADMIN' ORDER BY id LIMIT 1")).rows[0]?.id;
  assert.ok(staff, 'Expected a synthetic reviewed staff member');

  const insertDistrict = (id, cityId, code, name) => db.query(
    'INSERT INTO foundation.administrative_districts(id,city_id,code,name) VALUES($1,$2,$3,$4)', [id, cityId, code, name]);
  const insertArea = (id, cityId, code) => db.query(
    'INSERT INTO foundation.service_areas(id,city_id,code) VALUES($1,$2,$3)', [id, cityId, code]);
  const insertVersion = (id, cityId, areaId, version, name, extra = {}) => db.query(`INSERT INTO foundation.service_area_versions
    (id,city_id,area_id,version,name,coverage_description,address_criteria,created_by)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
    [id, cityId, areaId, version, name, extra.coverage ?? null, extra.criteria ?? null, extra.createdBy ?? staff]);
  const publishOn = (client, id, by = staff) => client.query(
    'UPDATE foundation.service_area_versions SET published_at=CURRENT_TIMESTAMP,published_by=$2 WHERE id=$1 RETURNING row_version', [id, by]);
  const coverOn = (client, cityId, versionId, districtId, relation, description = null) => client.query(
    `INSERT INTO foundation.service_area_district_coverage(city_id,area_version_id,district_id,relation,description)
    VALUES($1,$2,$3,$4,$5)`, [cityId, versionId, districtId, relation, description]);
  const setPointer = (areaId, versionId, expectedVersion) => db.query(
    'UPDATE foundation.service_areas SET current_version_id=$2 WHERE id=$1 AND row_version=$3 RETURNING row_version',
    [areaId, versionId, expectedVersion]);
  const rowVersion = async (table, id) => (await db.query(`SELECT row_version FROM foundation.${table} WHERE id=$1`, [id])).rows[0]?.row_version;
  const count = async (table) => (await db.query(`SELECT count(*)::int AS n FROM foundation.${table}`)).rows[0].n;

  // Districts: optional real reference data, city-scoped identity and code.
  const north = randomUUID(), south = randomUUID(), extra = randomUUID(), westNorth = randomUUID();
  await insertDistrict(north, east.id, 'north', 'Synthetic north');
  await insertDistrict(south, east.id, 'south', 'Synthetic south');
  await insertDistrict(extra, east.id, 'extra', 'Synthetic extra');
  await insertDistrict(westNorth, west.id, 'north', 'Synthetic west north');
  await denied(insertDistrict(randomUUID(), east.id, 'north', 'Duplicate code'), '23505');
  await denied(insertDistrict(randomUUID(), east.id, 'Bad', 'Uppercase code'), '23514');
  await denied(insertDistrict(randomUUID(), east.id, 'x', 'Too short code'), '23514');
  await denied(insertDistrict(randomUUID(), east.id, 'blank-name', ' \t'), '23514');
  await denied(insertDistrict(randomUUID(), randomUUID(), 'orphan', 'Unknown city'), '23503');
  await denied(db.query('UPDATE foundation.administrative_districts SET city_id=$2 WHERE id=$1', [north, west.id]), '23514');
  await denied(db.query('UPDATE foundation.administrative_districts SET code=$2 WHERE id=$1', [north, 'changed']), '23514');
  assert.equal((await db.query('UPDATE foundation.administrative_districts SET name=$2 WHERE id=$1', [north, 'Synthetic north renamed'])).rowCount, 1);
  assert.equal(await rowVersion('administrative_districts', north), 2, 'District row_version must be database-owned');

  // Areas: stable city-scoped identity; the pointer is the published revision.
  const central = randomUUID(), outer = randomUUID(), westCentral = randomUUID();
  await insertArea(central, east.id, 'central');
  await insertArea(outer, east.id, 'outer');
  await insertArea(westCentral, west.id, 'central');
  await denied(insertArea(randomUUID(), east.id, 'central'), '23505');
  await denied(insertArea(randomUUID(), east.id, 'Bad'), '23514');
  await denied(insertArea(randomUUID(), randomUUID(), 'orphan'), '23503');
  await denied(db.query('UPDATE foundation.service_areas SET code=$2 WHERE id=$1', [central, 'renamed']), '23514');
  await denied(db.query('UPDATE foundation.service_areas SET city_id=$2 WHERE id=$1', [central, west.id]), '23514');

  // Revisions are born as drafts; identity is stable and the database owns row_version.
  const v1 = randomUUID(), v2 = randomUUID(), vOuter = randomUUID(), vWest = randomUUID();
  await insertVersion(v1, east.id, central, 1, 'Central v1', { coverage: 'North and south', criteria: 'Manual street list' });
  await denied(insertVersion(randomUUID(), east.id, central, 1, 'Duplicate v1'), '23505');
  await denied(insertVersion(randomUUID(), east.id, central, 0, 'Zero version'), '23514');
  await denied(insertVersion(randomUUID(), east.id, central, 3, '   '), '23514');
  await denied(insertVersion(randomUUID(), east.id, central, 3, 'Blank coverage', { coverage: ' \n' }), '23514');
  await denied(insertVersion(randomUUID(), east.id, central, 3, 'Blank criteria', { criteria: '\t' }), '23514');
  await denied(insertVersion(randomUUID(), west.id, central, 1, 'Foreign city area'), '23503');
  await denied(insertVersion(randomUUID(), east.id, randomUUID(), 1, 'Unknown area'), '23503');
  await denied(insertVersion(randomUUID(), east.id, central, 3, 'Unknown author', { createdBy: randomUUID() }), '23503');
  await denied(db.query(`INSERT INTO foundation.service_area_versions(id,city_id,area_id,version,name,created_by,published_at,published_by)
    VALUES($1,$2,$3,4,'Published at insert',$4,CURRENT_TIMESTAMP,$4)`, [randomUUID(), east.id, central, staff]), '23514');
  await denied(db.query('UPDATE foundation.service_area_versions SET version=9 WHERE id=$1', [v1]), '23514');
  await denied(db.query('UPDATE foundation.service_area_versions SET area_id=$2 WHERE id=$1', [v1, outer]), '23514');
  await denied(db.query('UPDATE foundation.service_area_versions SET created_by=$2 WHERE id=$1', [v1, randomUUID()]), '23514');
  assert.equal((await db.query('UPDATE foundation.service_area_versions SET row_version=99 WHERE id=$1 RETURNING row_version', [v1])).rows[0].row_version, 2,
    'Caller must not control version row_version');

  // A draft may not become current.
  await denied(setPointer(central, v1, 1), '23514');

  // Draft coverage: M:N FULL/PARTIAL inside the same city; each child edit bumps the
  // draft revision so a stale draft token is detectable.
  const draftBeforeCoverage = await rowVersion('service_area_versions', v1);
  await coverOn(db, east.id, v1, north, 'FULL', 'Whole north');
  await coverOn(db, east.id, v1, south, 'PARTIAL', 'South edge');
  assert.equal(await rowVersion('service_area_versions', v1), draftBeforeCoverage + 2, 'Coverage edit must bump the draft revision');
  await denied(coverOn(db, east.id, v1, extra, 'MAYBE'), '23514');
  await denied(coverOn(db, east.id, v1, extra, 'FULL', '  '), '23514');
  await denied(coverOn(db, east.id, v1, north, 'FULL'), '23505');
  await denied(coverOn(db, west.id, v1, westNorth, 'FULL'), '23503');
  await denied(coverOn(db, east.id, v1, westNorth, 'FULL'), '23503');
  await denied(coverOn(db, east.id, randomUUID(), north, 'FULL'), '23503');
  await denied(db.query(`UPDATE foundation.service_area_district_coverage SET district_id=$3
    WHERE area_version_id=$1 AND district_id=$2`, [v1, north, extra]), '23514');
  assert.equal((await db.query(`UPDATE foundation.service_area_district_coverage SET relation='PARTIAL',description='Reviewed edge'
    WHERE area_version_id=$1 AND district_id=$2`, [v1, north])).rowCount, 1, 'Draft coverage content must stay editable');
  assert.equal(await rowVersion('service_area_versions', v1), draftBeforeCoverage + 3, 'Coverage content edit must bump the draft revision');

  // Publication is a state transition, never a content edit.
  await denied(db.query(`UPDATE foundation.service_area_versions SET published_at=CURRENT_TIMESTAMP,published_by=$2,name='Changed'
    WHERE id=$1`, [v1, staff]), '23514');
  await denied(db.query('UPDATE foundation.service_area_versions SET published_at=CURRENT_TIMESTAMP WHERE id=$1', [v1]), '23514');
  assert.equal((await publishOn(db, v1)).rowCount, 1, 'Publication failed');
  await denied(db.query('UPDATE foundation.service_area_versions SET name=$2 WHERE id=$1', [v1, 'Rewrite history']), '23514');
  await denied(db.query('DELETE FROM foundation.service_area_versions WHERE id=$1', [v1]), '23514');
  await denied(coverOn(db, east.id, v1, extra, 'FULL'), '23514');
  await denied(db.query(`UPDATE foundation.service_area_district_coverage SET relation='FULL' WHERE area_version_id=$1`, [v1]), '23514');
  await denied(db.query('DELETE FROM foundation.service_area_district_coverage WHERE area_version_id=$1', [v1]), '23514');

  // The pointer accepts only a published revision of this very city and area.
  await denied(setPointer(central, v2, 1), '23503'); // not created yet
  assert.deepEqual((await setPointer(central, v1, 1)).rows, [{ row_version: 2 }]);
  await denied(db.query('UPDATE foundation.service_areas SET current_version_id=$2,code=$3 WHERE id=$1', [central, v1, 'renamed']), '23514');

  // Second zone in the same city covers the same district: M:N overlap is legal.
  await insertVersion(vOuter, east.id, outer, 1, 'Outer v1', { coverage: 'Overlaps central on north' });
  await coverOn(db, east.id, vOuter, north, 'PARTIAL', 'Overlapping advisory candidate');
  await publishOn(db, vOuter);
  assert.deepEqual((await setPointer(outer, vOuter, 1)).rows, [{ row_version: 2 }]);
  // Foreign city zone is a normal published revision of its own city.
  await insertVersion(vWest, west.id, westCentral, 1, 'West central v1');
  await coverOn(db, west.id, vWest, westNorth, 'FULL', 'Whole west north');
  await publishOn(db, vWest);
  assert.deepEqual((await setPointer(westCentral, vWest, 1)).rows, [{ row_version: 2 }]);

  // Two versions of one zone move the pointer without rewriting history.
  await insertVersion(v2, east.id, central, 2, 'Central v2', { coverage: 'North, south and extra' });
  await denied(setPointer(central, v2, 2), '23514'); // draft
  await denied(setPointer(central, vWest, 2), '23503'); // other city
  await denied(setPointer(central, vOuter, 2), '23503'); // other area
  await denied(setPointer(central, randomUUID(), 2), '23503'); // nonexistent
  const historyBefore = {
    version: (await db.query('SELECT * FROM foundation.service_area_versions WHERE id=$1', [v1])).rows,
    coverage: (await db.query(`SELECT city_id,area_version_id,district_id,relation,description
      FROM foundation.service_area_district_coverage WHERE area_version_id=$1 ORDER BY district_id`, [v1])).rows,
  };
  assert.equal((await db.query('UPDATE foundation.service_area_versions SET name=$2 WHERE id=$1', [v2, 'Central v2 edited'])).rowCount, 1);
  await coverOn(db, east.id, v2, south, 'FULL', 'Whole south');
  await publishOn(db, v2);
  assert.equal((await setPointer(central, v2, 1)).rowCount, 0, 'Stale pointer token advanced the area');
  assert.deepEqual((await setPointer(central, v2, 2)).rows, [{ row_version: 3 }]);
  assert.deepEqual({
    version: (await db.query('SELECT * FROM foundation.service_area_versions WHERE id=$1', [v1])).rows,
    coverage: (await db.query(`SELECT city_id,area_version_id,district_id,relation,description
      FROM foundation.service_area_district_coverage WHERE area_version_id=$1 ORDER BY district_id`, [v1])).rows,
  }, historyBefore, 'Re-publication rewrote the previous version or its coverage');
  // Late changes after re-publication are refused as well.
  await denied(coverOn(db, east.id, v2, extra, 'FULL'), '23514');
  await denied(db.query(`UPDATE foundation.service_area_district_coverage SET description='late' WHERE area_version_id=$1`, [v2]), '23514');
  await denied(db.query('DELETE FROM foundation.service_area_district_coverage WHERE area_version_id=$1', [v2]), '23514');
  await denied(db.query('UPDATE foundation.service_area_versions SET name=$2 WHERE id=$1', [v2, 'late rewrite']), '23514');
  await denied(db.query('DELETE FROM foundation.service_area_versions WHERE id=$1', [v2]), '23514');

  // TRUNCATE bypasses row triggers, so both history tables refuse it at statement level.
  // The pointer FK requires the whole area graph in one statement; the trigger still fires.
  await db.query('BEGIN');
  try {
    await denied(db.query(`TRUNCATE foundation.administrative_districts, foundation.service_areas,
      foundation.service_area_versions, foundation.service_area_district_coverage`), '23514');
  } finally { await db.query('ROLLBACK'); }
  await db.query('BEGIN');
  try {
    await denied(db.query('TRUNCATE foundation.service_area_district_coverage'), '23514');
  } finally { await db.query('ROLLBACK'); }

  // Archive is an UPDATE, not a delete: referenced history and coverage stay intact.
  assert.equal((await db.query('UPDATE foundation.administrative_districts SET archived_at=CURRENT_TIMESTAMP WHERE id=$1', [extra])).rowCount, 1);
  assert.equal((await db.query('UPDATE foundation.service_areas SET archived_at=CURRENT_TIMESTAMP WHERE id=$1', [outer])).rowCount, 1);
  assert.equal(await count('service_area_versions'), 4);

  const areaSnapshot = async () => {
    const rows = [];
    for (const table of areaTables) { rows.push((await db.query(`SELECT * FROM foundation.${table} ORDER BY 1,2,3`)).rows); }
    return rows;
  };
  const beforeReplay = await areaSnapshot();
  const historyBeforeReplay = await db.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name');
  assert.equal(historyBeforeReplay.rows.at(-1)?.migration_name, '20261121000200_service_areas');
  deploy();
  assert.deepEqual((await db.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name')).rows,
    historyBeforeReplay.rows, '011 replay changed migration history');
  assert.deepEqual(await areaSnapshot(), beforeReplay, '011 replay changed area geography');

  // Concurrency: publication and a pending child change serialize on the revision row.
  // Both orders are proven with independent connections and a bounded lock wait, no sleeps.
  const password = credentials().fixlevelup_migrator;
  const first = connection('fixlevelup_migrator', password, identity.db);
  const second = connection('fixlevelup_migrator', password, identity.db);
  await first.connect();
  await second.connect();
  try {
    // Publication holds the revision row; a child insert waits and is refused after commit.
    const publishedArea = randomUUID(), publishedVersion = randomUUID();
    await insertArea(publishedArea, east.id, 'concurrent-published');
    await insertVersion(publishedVersion, east.id, publishedArea, 1, 'Concurrent published');
    await first.query('BEGIN');
    assert.equal((await publishOn(first, publishedVersion)).rowCount, 1);
    await second.query('BEGIN');
    await second.query("SET LOCAL lock_timeout='300ms'");
    await blocked(coverOn(second, east.id, publishedVersion, north, 'FULL'), 'coverage insert vs publication');
    await second.query('ROLLBACK');
    await first.query('COMMIT');
    await denied(coverOn(second, east.id, publishedVersion, north, 'FULL'), '23514');
    assert.equal((await db.query('SELECT published_at IS NOT NULL AS published FROM foundation.service_area_versions WHERE id=$1', [publishedVersion])).rows[0].published, true);

    // A child edit first holds the revision row and bumps it; the publisher's stale
    // token then matches zero rows instead of publishing over a changed mapping.
    const draftArea = randomUUID(), draftVersion = randomUUID();
    await insertArea(draftArea, east.id, 'concurrent-draft');
    await insertVersion(draftVersion, east.id, draftArea, 1, 'Concurrent draft');
    await first.query('BEGIN');
    assert.equal((await coverOn(first, east.id, draftVersion, south, 'FULL')).rowCount, 1);
    const pendingDraftVersion = (await first.query('SELECT row_version FROM foundation.service_area_versions WHERE id=$1', [draftVersion])).rows[0]?.row_version;
    assert.equal(pendingDraftVersion, 2, 'Pending coverage edit must bump the draft revision');
    await second.query('BEGIN');
    await second.query("SET LOCAL lock_timeout='300ms'");
    await blocked(second.query(`UPDATE foundation.service_area_versions SET published_at=CURRENT_TIMESTAMP,published_by=$2
      WHERE id=$1 AND row_version=1`, [draftVersion, staff]), 'publication vs pending coverage edit');
    await second.query('ROLLBACK');
    await first.query('COMMIT');
    assert.equal((await second.query(`UPDATE foundation.service_area_versions SET published_at=CURRENT_TIMESTAMP,published_by=$2
      WHERE id=$1 AND row_version=1`, [draftVersion, staff])).rowCount, 0, 'Stale draft token published over a child edit');
    assert.equal((await publishOn(second, draftVersion)).rowCount, 1, 'Publication after the child edit must succeed');
    await denied(coverOn(second, east.id, draftVersion, north, 'PARTIAL'), '23514');
    console.log('011 concurrent publication vs pending district coverage: blocked, serialized, late child change denied: PASS');
  } finally {
    for (const client of [first, second]) {
      await client.query('ROLLBACK').catch(() => undefined);
      await client.end().catch(() => undefined);
    }
  }
  assert.equal(await count('service_area_versions'), 6);
  console.log('010 → service areas: populated cities preserved, same-city districts/zones/coverage, draft edit, publish/pointer, frozen history, replay: PASS');
}
