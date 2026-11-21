import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

// Keep this inventory independent of the DDL: a dropped or unvalidated guard must fail CI.
export const cityChecks = [
  'service_cities_lifecycle_check', 'service_cities_code_check', 'service_cities_row_version_check',
  'service_cities_active_pointer_check', 'service_city_versions_version_check',
  'service_city_versions_display_name_check', 'service_city_versions_address_display_check',
  'service_city_versions_public_contact_check', 'service_city_versions_office_hours_check',
  'business_settings_versions_version_check', 'business_settings_versions_launch_mode_check',
];

const readable = {
  service_cities: ['id', 'lifecycle', 'current_version_id'],
  service_city_versions: ['id', 'city_id', 'timezone'],
  business_settings_versions: ['version', 'launch_mode', 'primary_city_id'],
};

async function denied(query, sqlState) {
  await assert.rejects(query, (err) => err.code === sqlState, `Expected SQLSTATE ${sqlState}`);
}

export async function proveCityReadGrants(runtime) {
  for (const [table, columns] of Object.entries(readable)) {
    const target = `foundation.${table}`;
    const grants = await runtime.query(`SELECT attname, has_column_privilege(current_user,attrelid,attnum,'SELECT') AS readable,
      has_column_privilege(current_user,attrelid,attnum,'INSERT,UPDATE,REFERENCES,SELECT WITH GRANT OPTION') AS elevated
      FROM pg_attribute WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped`, [target]);
    assert.deepEqual(grants.rows.filter(r => r.readable).map(r => r.attname).sort(), [...columns].sort());
    assert(grants.rows.every(r => !r.elevated));
    const broad = await runtime.query(`SELECT has_table_privilege(current_user,$1,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') AS elevated`, [target]);
    assert.equal(broad.rows[0].elevated, false);
    await runtime.query(`SELECT ${columns.join(',')} FROM ${target} LIMIT 1`);
    await denied(runtime.query(`SELECT * FROM ${target}`), '42501');
    await denied(runtime.query(`INSERT INTO ${target} DEFAULT VALUES`), '42501');
  }
  const helpers = ['city_office_hours_is_valid', 'city_timezone_is_valid', 'city_versions_validate',
    'city_settings_reject_revision_change', 'city_guard_update'];
  const { rows } = await runtime.query(`SELECT p.proname FROM pg_proc p
    WHERE p.pronamespace='foundation'::regnamespace AND p.proname=ANY($1::text[])
      AND pg_get_userbyid(p.proowner)='fixlevelup_migrator' AND NOT p.prosecdef
      AND 'search_path=pg_catalog'=ANY(p.proconfig)
      AND NOT has_function_privilege(current_user,p.oid,'EXECUTE')`, [helpers]);
  assert.deepEqual(rows.map(row => row.proname).sort(), [...helpers].sort());
  console.log('P03 runtime: nine resolver columns; no DML, delegation or direct validator/trigger functions: PASS');
}

// Run on the already-populated 009 DB from the RBAC cutover proof. No test DDL or data in the working application database.
export async function proveCityUpgrade(db, deploy) {
  const { rows: [identity] } = await db.query('SELECT current_database() AS db, current_user AS role');
  assert.match(identity.db, /^fixlevelup_p017a_upgrade_[a-f0-9]{12}$/);
  assert.equal(identity.role, 'fixlevelup_migrator');
  const baseline = () => db.query(`SELECT s.id,s.role,s.employment_state,s.auth_version,a.id AS assignment,a.role_id
    FROM foundation.staff s JOIN foundation.staff_role_assignments a ON a.staff_id=s.id ORDER BY s.id,a.id`);
  const { rows: before } = await baseline();
  const reviewer = before.find(row => row.role === 'ADMIN')?.id;
  assert.ok(reviewer, 'Expected a populated P02 fixture');
  assert.equal((await db.query("SELECT to_regclass('foundation.service_cities') AS ref")).rows[0].ref, null);
  deploy();
  assert.deepEqual((await baseline()).rows, before);
  for (const table of Object.keys(readable)) {
    assert.equal((await db.query(`SELECT FROM foundation.${table}`)).rowCount, 0, `Unexpected seed in ${table}`);
  }

  const city = randomUUID(), other = randomUUID(), first = randomUUID(), second = randomUUID(), foreign = randomUUID();
  const hours = [ [[0, 60], [60, 1440]], [], [], [], [], [], [] ];
  const insertVersion = (id, cityId, version, name, zone, officeHours = hours, contact = 'synthetic.example.test') => db.query(`
    INSERT INTO foundation.service_city_versions(id,city_id,version,display_name,timezone,office_hours,public_contact,reviewed_by)
    VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8)`, [id,cityId,version,name,zone,JSON.stringify(officeHours),contact,reviewer]);
  const launch = (version, mode, primary) => db.query(`INSERT INTO foundation.business_settings_versions
    (id,version,launch_mode,primary_city_id,reviewed_by) VALUES($1,$2,$3,$4,$5)`, [randomUUID(),version,mode,primary,reviewer]);
  const update = (id, versionId, expectedVersion) => db.query(`UPDATE foundation.service_cities SET current_version_id=$2,lifecycle='ACTIVE'
    WHERE id=$1 AND row_version=$3 RETURNING row_version`, [id,versionId,expectedVersion]);
  const oldVersion = () => db.query('SELECT * FROM foundation.service_city_versions WHERE id=$1', [first]);
  await db.query("INSERT INTO foundation.service_cities(id,code) VALUES ($1,'test-east'),($2,'test-west')", [city, other]);
  await denied(db.query("UPDATE foundation.service_cities SET lifecycle='ACTIVE' WHERE id=$1", [city]), '23514');
  await denied(db.query("UPDATE foundation.service_cities SET code='changed' WHERE id=$1", [city]), '23514');
  await insertVersion(first,city,1,'Synthetic A','Etc/GMT-3');
  await insertVersion(foreign,other,1,'Synthetic B','Asia/Tokyo');
  await denied(insertVersion(randomUUID(),city,1,'Duplicate','UTC'), '23505');
  await denied(insertVersion(randomUUID(),randomUUID(),1,'Unknown city','UTC'), '23503');
  await denied(insertVersion(randomUUID(),city,2,'\t','UTC'), '23514');
  await denied(insertVersion(randomUUID(),city,2,'Empty contact','UTC',hours,' \n'), '23514');
  for (const timezone of ['Not/AZone', '+03:00', 'MSK', 'posix/Europe/Moscow']) {
    await denied(insertVersion(randomUUID(),city,2,'Bad timezone',timezone), '23514');
  }
  for (const invalid of [ {}, [], [null, ...hours.slice(1)], [[[0,'60']], ...hours.slice(1)],
    [[[0,10.5]], ...hours.slice(1)], [[[60,60]], ...hours.slice(1)], [[[1,1441]], ...hours.slice(1)],
    [[[30,90],[70,120]], ...hours.slice(1)], [[[100,120],[0,60]], ...hours.slice(1)] ]) {
    await denied(insertVersion(randomUUID(),city,2,'Bad hours','UTC',invalid), '23514');
  }
  await denied(update(city,foreign,1), '23503');
  assert.deepEqual((await update(city,first,1)).rows, [{row_version:2}]);
  assert.equal((await update(city,first,1)).rowCount, 0, 'Stale city version advanced');
  await launch(1,'SINGLE_CITY',city);
  await denied(launch(2,'SINGLE_CITY',randomUUID()), '23503');
  await denied(launch(2,'UNKNOWN',city), '23514');
  await denied(launch(1,'SINGLE_CITY',other), '23505');
  const original = (await oldVersion()).rows;
  await insertVersion(second,city,2,'Renamed synthetic A','Etc/UTC');
  assert.deepEqual((await update(city,second,2)).rows, [{row_version:3}]);
  assert.equal((await update(other,foreign,1)).rowCount, 1, 'Schema must permit a second ACTIVE without ALTER');
  assert.equal((await db.query("SELECT FROM foundation.service_cities WHERE lifecycle='ACTIVE'")).rowCount, 2);
  assert.deepEqual((await oldVersion()).rows, original, 'Publishing a newer version rewrote history');
  for (const table of ['service_city_versions', 'business_settings_versions']) {
    await denied(db.query(`UPDATE foundation.${table} SET version=version`), '23514');
    await denied(db.query(`DELETE FROM foundation.${table}`), '23514');
  }
  // The FK cycle requires all related tables in the TRUNCATE. Roll back even if a guard regresses.
  await db.query('BEGIN');
  try {
    await denied(db.query('TRUNCATE foundation.service_cities, foundation.service_city_versions, foundation.business_settings_versions'), '23514');
  } finally { await db.query('ROLLBACK'); }
  deploy();
  assert.deepEqual((await oldVersion()).rows, original, 'Deploy replay changed city history');
  assert.deepEqual((await baseline()).rows, before);
  console.log('009 → city foundation: P02 data preserved, no seed, two cities, same-city FK, append-only revisions, timezone/hours, replay: PASS');
}
