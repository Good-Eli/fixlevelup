import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { syntheticVerifier } from './test-rbac-migration.mjs';

// 012 CHECK inventory, kept independent of the DDL: a dropped, renamed or unvalidated
// guard must fail CI. role_permissions_scope_check is deliberately absent: 012 replaces
// the 009 constraint in place under the same name, so it is not a new check of 012.
export const geoAccessChecks = [
  'geography_bootstrap_permissions_code_check',
  'staff_admin_city_assignments_actor_check', 'staff_admin_city_assignments_revoke_check',
  'staff_admin_city_assignments_period_check',
  'technician_city_memberships_interval_check', 'technician_city_memberships_revoke_check',
  'technician_city_memberships_actor_check',
  'technician_service_areas_interval_check', 'technician_service_areas_revoke_check',
  'technician_service_areas_actor_check',
  'geography_command_receipts_operation_check', 'geography_command_receipts_body_hash_check',
  'geography_command_receipts_entity_version_check',
];

const bootstrapCodes = ['geography.manage', 'geography.publish', 'geography.read',
  'staff.geography.manage', 'staff.geography.read'];
const newTables = ['geography_bootstrap_permissions', 'staff_admin_city_assignments',
  'technician_city_memberships', 'technician_service_areas', 'geography_command_receipts'];
const geographyFunctions = ['geography_guard_role_grant', 'geography_bootstrap_guard',
  'issue_first_geo_permissions', 'geography_admin_assignment_guard', 'geography_membership_guard',
  'geography_zone_guard', 'geography_membership_zone_consistency', 'geography_receipts_immutable',
  'geography_reject_truncate'];
// The 011 guards must stay unreachable as well: 012 adds no new callable surface.
const areaGuardFunctions = ['service_areas_guard_pointer', 'administrative_districts_guard_update',
  'service_area_versions_guard_change', 'service_area_district_coverage_guard_change',
  'service_area_history_reject_truncate'];
const validators = ['city_office_hours_is_valid', 'city_timezone_is_valid'];
// The 012 delta must not disturb the 010/011 history it is applied on top of.
const preservedTables = ['service_cities', 'service_city_versions', 'business_settings_versions',
  'administrative_districts', 'service_areas', 'service_area_versions', 'service_area_district_coverage'];
const sortKeys = {
  geography_bootstrap_permissions: 'assignment_id,permission_code',
  staff_admin_city_assignments: 'id', technician_city_memberships: 'id',
  technician_service_areas: 'id', geography_command_receipts: 'actor_id,operation,key',
};

async function denied(query, sqlState, label) {
  await assert.rejects(query, (error) => error.code === sqlState, `Expected SQLSTATE ${sqlState}${label ? `: ${label}` : ''}`);
}
// Several expected failures inside one transaction need a savepoint each: without one the
// first error aborts the transaction and every later statement would report 25P02 instead
// of the guard's own SQLSTATE.
async function deniedInTransaction(client, sql, sqlState, label) {
  await client.query('SAVEPOINT proof');
  try {
    await denied(client.query(sql), sqlState, label);
  } finally {
    await client.query('ROLLBACK TO SAVEPOINT proof');
    await client.query('RELEASE SAVEPOINT proof');
  }
}
const snapshotOf = async (db, tables) => {
  const rows = [];
  for (const table of tables) {
    rows.push((await db.query(`SELECT * FROM foundation.${table} ORDER BY ${sortKeys[table] ?? '1,2,3'}`)).rows);
  }
  return rows;
};

// Exact runtime ACL of 012 on the final fresh database: approved columns only, no
// table-level privilege, no DELETE of grant history (draft coverage deletion is the one
// exception), no DDL/role privilege and no callable guard.
export async function proveGeoAccessGrants(runtime) {
  const acl = {
    geography_bootstrap_permissions: {
      select: ['assignment_id', 'permission_code', 'revoked_at'], insert: [], update: ['revoked_at'], delete: false },
    staff_admin_city_assignments: {
      select: ['id', 'staff_id', 'city_id', 'granted_by', 'granted_at', 'revoked_at', 'revoked_by'],
      insert: ['id', 'staff_id', 'city_id', 'granted_by'], update: ['revoked_at', 'revoked_by'], delete: false },
    technician_city_memberships: {
      select: ['id', 'technician_id', 'city_id', 'valid_from', 'valid_to', 'approved_by', 'revoked_at', 'revoked_by'],
      insert: ['id', 'technician_id', 'city_id', 'valid_from', 'valid_to', 'approved_by'],
      update: ['revoked_at', 'revoked_by'], delete: false },
    technician_service_areas: {
      select: ['id', 'technician_id', 'city_id', 'service_area_id', 'membership_id', 'valid_from', 'valid_to',
        'approved_by', 'revoked_at', 'revoked_by'],
      insert: ['id', 'technician_id', 'city_id', 'service_area_id', 'membership_id', 'valid_from', 'valid_to', 'approved_by'],
      update: ['revoked_at', 'revoked_by'], delete: false },
    geography_command_receipts: {
      select: ['actor_id', 'operation', 'key', 'body_hash', 'entity_id', 'entity_version'],
      insert: ['actor_id', 'operation', 'key', 'body_hash', 'entity_id', 'entity_version'], update: [], delete: false },
    service_cities: {
      select: ['id', 'code', 'lifecycle', 'row_version', 'current_version_id'],
      insert: ['id', 'code'], update: ['lifecycle', 'current_version_id'], delete: false },
    service_city_versions: {
      select: ['id', 'city_id', 'version', 'display_name', 'address_display', 'timezone', 'public_contact',
        'office_hours', 'reviewed_by', 'published_at'],
      insert: ['id', 'city_id', 'version', 'display_name', 'address_display', 'timezone', 'public_contact',
        'office_hours', 'reviewed_by'], update: [], delete: false },
    business_settings_versions: {
      select: ['id', 'version', 'launch_mode', 'primary_city_id', 'reviewed_by', 'published_at'],
      insert: ['id', 'version', 'launch_mode', 'primary_city_id', 'reviewed_by'], update: [], delete: false },
    administrative_districts: {
      select: ['id', 'city_id', 'code', 'name', 'archived_at', 'row_version'],
      insert: ['id', 'city_id', 'code', 'name'], update: ['name', 'archived_at'], delete: false },
    service_areas: {
      select: ['id', 'city_id', 'code', 'current_version_id', 'archived_at', 'row_version'],
      insert: ['id', 'city_id', 'code'], update: ['current_version_id', 'archived_at'], delete: false },
    service_area_versions: {
      select: ['id', 'city_id', 'area_id', 'version', 'name', 'coverage_description', 'address_criteria',
        'created_by', 'published_at', 'published_by', 'row_version'],
      insert: ['id', 'city_id', 'area_id', 'version', 'name', 'coverage_description', 'address_criteria', 'created_by'],
      update: ['name', 'coverage_description', 'address_criteria', 'published_at', 'published_by', 'row_version'],
      delete: false },
    service_area_district_coverage: {
      select: ['city_id', 'area_version_id', 'district_id', 'relation', 'description'],
      insert: ['city_id', 'area_version_id', 'district_id', 'relation', 'description'],
      update: ['relation', 'description'], delete: true },
    // 012's single deliberate widening of the 009 RBAC ACL: the role editor writes the
    // geography scope explicitly. Everything else about a role grant stays read-only.
    role_permissions: {
      select: ['role_id', 'permission_code', 'scope_type', 'enabled'],
      insert: ['role_id', 'permission_code', 'scope_type', 'enabled'],
      update: ['enabled', 'scope_type'], delete: false },
  };
  for (const [table, spec] of Object.entries(acl)) {
    const target = `foundation.${table}`;
    const columns = await runtime.query(`SELECT attname,
      has_column_privilege(current_user,attrelid,attnum,'SELECT') AS readable,
      has_column_privilege(current_user,attrelid,attnum,'INSERT') AS insertable,
      has_column_privilege(current_user,attrelid,attnum,'UPDATE') AS updatable,
      has_column_privilege(current_user,attrelid,attnum,'REFERENCES') AS referencable,
      has_column_privilege(current_user,attrelid,attnum,'SELECT WITH GRANT OPTION') AS grantable
      FROM pg_attribute WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped`, [target]);
    const pick = (flag) => columns.rows.filter((column) => column[flag]).map((column) => column.attname).sort();
    assert.deepEqual(pick('readable'), [...spec.select].sort(), `Runtime SELECT columns on ${table}`);
    assert.deepEqual(pick('insertable'), [...spec.insert].sort(), `Runtime INSERT columns on ${table}`);
    assert.deepEqual(pick('updatable'), [...spec.update].sort(), `Runtime UPDATE columns on ${table}`);
    assert.equal(pick('referencable').length, 0, `Runtime REFERENCES on ${table}`);
    assert.equal(pick('grantable').length, 0, `Runtime grant option on ${table}`);
    const broad = await runtime.query(`SELECT has_table_privilege(current_user,$1,
      'SELECT,INSERT,UPDATE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') AS elevated,
      has_table_privilege(current_user,$1,'DELETE') AS deletable`, [target]);
    assert.equal(broad.rows[0].elevated, false, `Runtime table-level privilege on ${table}`);
    // Draft coverage deletion is the only DELETE granted: the 011 guard still refuses it
    // once the parent revision is published.
    assert.equal(broad.rows[0].deletable, spec.delete, `Runtime DELETE privilege on ${table}`);
  }
  // Exactly the two 010 validators are callable; every 011/012 guard stays owner-only and
  // the founder issue function is migrator-only.
  const executable = await runtime.query(`SELECT p.proname,
    has_function_privilege(current_user,p.oid,'EXECUTE') AS allowed,
    has_function_privilege('fixlevelup_migrator',p.oid,'EXECUTE') AS migrator_allowed,
    pg_get_userbyid(p.proowner) AS owner, p.prosecdef, p.proconfig,
    EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl
      WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE') AS public_execute
    FROM pg_proc p WHERE p.pronamespace='foundation'::regnamespace AND p.proname=ANY($1::text[])`,
  [[...validators, ...geographyFunctions, ...areaGuardFunctions]]);
  assert.equal(executable.rowCount, validators.length + geographyFunctions.length + areaGuardFunctions.length);
  assert.deepEqual(executable.rows.filter((row) => row.allowed).map((row) => row.proname).sort(), [...validators].sort(),
    'Runtime must execute exactly the two 010 validators');
  assert.equal(executable.rows.filter((row) => row.public_execute).length, 0, 'PUBLIC EXECUTE on a geography function');
  assert(executable.rows.every((row) => row.owner === 'fixlevelup_migrator' && row.prosecdef === false
    && row.proconfig?.includes('search_path=pg_catalog')), 'Geography function ownership/security mismatch');
  const issue = executable.rows.find((row) => row.proname === 'issue_first_geo_permissions');
  assert.equal(issue.allowed, false, 'Runtime must not execute the founder issue function');
  assert.equal(issue.migrator_allowed, true, 'The founder issue function is migrator-only');
  // No DDL and no role/identity escalation.
  const hygiene = await runtime.query(`SELECT current_user AS role,
    (SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit)
       FROM pg_roles WHERE rolname=current_user) AS safe_role,
    (SELECT count(*)::int FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user)) AS memberships,
    has_database_privilege(current_user,current_database(),'CREATE,TEMP') AS db_ddl,
    has_schema_privilege(current_user,'foundation','CREATE') AS schema_ddl,
    has_schema_privilege(current_user,'public','CREATE') AS public_ddl`);
  assert.deepEqual(hygiene.rows[0], { role: 'fixlevelup_runtime', safe_role: true, memberships: 0,
    db_ddl: false, schema_ddl: false, public_ddl: false });
  // The runtime really cannot write the founder exception or delete grant history.
  for (const sql of [
    `INSERT INTO foundation.geography_bootstrap_permissions(assignment_id,permission_code) VALUES(gen_random_uuid(),'geography.read')`,
    'DELETE FROM foundation.geography_bootstrap_permissions',
    'DELETE FROM foundation.technician_city_memberships',
    'DELETE FROM foundation.technician_service_areas',
    'DELETE FROM foundation.staff_admin_city_assignments',
    'DELETE FROM foundation.geography_command_receipts',
    'UPDATE foundation.geography_command_receipts SET operation=operation',
    'UPDATE foundation.staff_admin_city_assignments SET granted_at=granted_at',
    'TRUNCATE foundation.geography_bootstrap_permissions',
    'ALTER TABLE foundation.staff_admin_city_assignments ADD COLUMN forbidden integer',
    'CREATE TABLE foundation.forbidden_geo(id integer)',
    'DELETE FROM foundation.role_permissions',
  ]) { await denied(runtime.query(sql), '42501', sql); }
  // The scope_type widening is real but stays non-escalating: the 012 scope CHECK still
  // refuses a legacy code or a SELF geography scope written through it.
  await denied(runtime.query(`UPDATE foundation.role_permissions SET scope_type='CITY'
    WHERE permission_code='staff.read'`), '23514', 'legacy code widened through scope_type');
  await denied(runtime.query(`UPDATE foundation.role_permissions SET scope_type='GLOBAL'
    WHERE permission_code='staff.self.read'`), '23514', 'self code widened through scope_type');
  // The runtime holds 009's INSERT on role_permissions, so it really can write a valid
  // MANAGER/CITY geography grant (that is the protected RBAC API); the guard and the
  // scope CHECK are what keep the write non-escalating. Prove it from the runtime role.
  await runtime.query('BEGIN');
  try {
    const { rows: [manager] } = await runtime.query("SELECT id FROM foundation.roles WHERE code='MANAGER'");
    const { rows: [technician] } = await runtime.query("SELECT id FROM foundation.roles WHERE code='TECHNICIAN'");
    await runtime.query(`INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
      VALUES($1,'geography.read','CITY')`, [manager.id]);
    await deniedInTransaction(runtime, `INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
      VALUES('${manager.id}','geography.read','GLOBAL')`, '23514', 'runtime GLOBAL geography on a manager role');
    await deniedInTransaction(runtime, `INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
      VALUES('${manager.id}','geography.publish','CITY')`, '23514', 'runtime publish on a manager role');
    await deniedInTransaction(runtime, `INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
      VALUES('${technician.id}','geography.read','CITY')`, '23514', 'runtime geography on the technician role');
  } finally { await runtime.query('ROLLBACK'); }
  // Approved reads work with the exact granted columns.
  await runtime.query('SELECT assignment_id,permission_code,revoked_at FROM foundation.geography_bootstrap_permissions LIMIT 1');
  await runtime.query(`SELECT id,technician_id,city_id,valid_from,valid_to,approved_by,revoked_at,revoked_by
    FROM foundation.technician_city_memberships LIMIT 1`);
  await runtime.query('SELECT actor_id,operation,key,body_hash,entity_id,entity_version FROM foundation.geography_command_receipts LIMIT 1');
  await runtime.query('SELECT id,city_id,code,current_version_id,archived_at,row_version FROM foundation.service_areas LIMIT 1');
  await runtime.query('SELECT id,city_id,area_id,version,name,coverage_description,address_criteria,created_by,published_at,published_by,row_version FROM foundation.service_area_versions LIMIT 1');
  console.log('012 runtime: approved column ACL only, no DELETE of grant history (draft coverage only), '
    + 'two validators executable, founder issue function migrator-only, no DDL/role escalation: PASS');
}

// Runs on the populated 011 database from the area proof: 012 is applied to real synthetic
// city/district/zone history, then exercised. No test DDL in a working application
// database, no seed of real people, cities or grants.
export async function proveGeoAccessUpgrade(db, deploy) {
  const { rows: [identity] } = await db.query('SELECT current_database() AS db, current_user AS role');
  assert.match(identity.db, /^fixlevelup_p017a_upgrade_[a-f0-9]{12}$/);
  assert.equal(identity.role, 'fixlevelup_migrator');
  for (const table of newTables) {
    assert.equal((await db.query(`SELECT to_regclass('foundation.${table}') AS ref`)).rows[0].ref, null,
      '012 applied before its proof');
  }
  const before = await snapshotOf(db, preservedTables);
  const historyBefore = await db.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name');
  assert.equal(historyBefore.rows.at(-1)?.migration_name, '20261121000200_service_areas');

  // ---- Collision refusal is atomic. ----
  // A pre-existing geography catalog row can only come from drift or an unapproved seed,
  // and 012 deliberately aborts instead of reusing it. Execute the real migration SQL in a
  // transaction on the capped 011 database: the DO block must refuse with one fixed,
  // value-free error and the rollback must leave 011 completely intact.
  const migrationSql = readFileSync(
    new URL('../../../prisma/migrations/20261121000300_geography_access/migration.sql', import.meta.url), 'utf8');
  await db.query('BEGIN');
  try {
    await db.query(`INSERT INTO foundation.permissions(code,module,description) VALUES('geography.read','geography','collision probe')`);
    await assert.rejects(db.query(migrationSql), (error) => error.code === '23514'
      && error.message === 'Geography catalog must be empty before migration 012',
    '012 must refuse a pre-existing geography catalog row');
  } finally { await db.query('ROLLBACK').catch(() => undefined); }
  for (const table of newTables) {
    assert.equal((await db.query(`SELECT to_regclass('foundation.${table}') AS ref`)).rows[0].ref, null,
      `Rejected 012 left ${table} behind`);
  }
  assert.equal((await db.query(`SELECT count(*)::int AS n FROM foundation.permissions
    WHERE code LIKE 'geography.%' OR code LIKE 'staff.geography.%'`)).rows[0].n, 0,
  'Rejected 012 kept its colliding catalog row');
  assert.deepEqual(await snapshotOf(db, preservedTables), before, 'Rejected 012 changed populated 011 geography');
  assert.deepEqual((await db.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name')).rows,
    historyBefore.rows, 'Rejected 012 changed migration history');
  // The scope CHECK was not swapped either: the 009 rule still applies on the capped DB.
  await db.query('BEGIN');
  try {
    await deniedInTransaction(db, `INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
      SELECT r.id,'staff.read','CITY' FROM foundation.roles r WHERE r.code='MANAGER'`, '23514',
    '009 scope CHECK must still be in force after a rejected 012');
  } finally { await db.query('ROLLBACK'); }

  deploy();
  const historyAfter = await db.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name');
  assert.equal(historyAfter.rows.at(-1)?.migration_name, '20261121000300_geography_access');
  assert.equal(historyAfter.rows.at(-1)?.finished_at instanceof Date, true);
  assert.deepEqual(await snapshotOf(db, preservedTables), before, '012 changed populated 010/011 geography');

  // ---- Founder-only bootstrap exception: exactly five codes on one assignment. ----
  const bootstrap = await db.query(`SELECT g.assignment_id,g.permission_code,g.revoked_at,
      a.staff_id,a.revoked_at AS assignment_revoked,
      s.role,s.employment_state,r.code AS role_code,r.role_type,b.staff_id AS marker_staff,
      EXISTS (SELECT FROM foundation.staff_web_credentials c WHERE c.staff_id=s.id) AS has_web,
      (SELECT count(*)::int FROM foundation.staff_role_assignments other
        WHERE other.staff_id=a.staff_id AND other.id <> a.id) AS other_assignments
    FROM foundation.geography_bootstrap_permissions g
    JOIN foundation.staff_role_assignments a ON a.id=g.assignment_id
    JOIN foundation.staff s ON s.id=a.staff_id
    JOIN foundation.roles r ON r.id=a.role_id
    LEFT JOIN foundation.staff_bootstrap_marker b ON b.staff_id=s.id
    ORDER BY g.permission_code`);
  assert.equal(bootstrap.rowCount, 5, 'Bootstrap exception must issue exactly five rows');
  assert.deepEqual(bootstrap.rows.map((row) => row.permission_code), bootstrapCodes);
  // The guard binds the exception to the staff's ONLY assignment ever, so a demotion and
  // re-promotion (which adds a second assignment) can never qualify again.
  assert(bootstrap.rows.every((row) => row.revoked_at === null && row.assignment_revoked === null
    && row.marker_staff !== null && row.role === 'ADMIN' && row.employment_state === 'ACTIVE'
    && row.role_code === 'ADMIN' && row.role_type === 'SYSTEM' && row.has_web && row.other_assignments === 0),
  'Bootstrap rows must belong only to the original verified bootstrap ADMIN assignment');
  assert.equal(new Set(bootstrap.rows.map((row) => row.assignment_id)).size, 1);
  const founderAssignment = bootstrap.rows[0].assignment_id;
  const founderStaff = bootstrap.rows[0].staff_id;
  assert.equal((await db.query("SELECT count(*)::int AS n FROM foundation.audit_logs WHERE operation='GEOGRAPHY_BOOTSTRAP_PERMISSIONS'")).rows[0].n,
    1, 'Bootstrap issue must be audited exactly once');
  // The five codes exist but stay ordinary (never protected): protection would make them
  // mandatory on every ADMIN, which the owner explicitly rejected.
  const catalog = await db.query(`SELECT code,protected,active,module FROM foundation.permissions
    WHERE code=ANY($1::text[]) ORDER BY code`, [bootstrapCodes]);
  assert.equal(catalog.rowCount, 5);
  assert(catalog.rows.every((row) => row.protected === false && row.active === true && row.module === 'geography'));
  // No role receives any geography code from this migration: no automatic grant at all.
  assert.equal((await db.query(`SELECT FROM foundation.role_permissions
    WHERE permission_code LIKE 'geography.%' OR permission_code LIKE 'staff.geography.%'`)).rowCount, 0,
  '012 must not grant geography to any role');

  // ---- Fixture ids from the populated 010/011 history. ----
  const cities = (await db.query('SELECT id,code FROM foundation.service_cities ORDER BY code')).rows;
  const [east, west] = cities;
  const staff = (await db.query(`SELECT s.id,s.role,s.employment_state,
      EXISTS (SELECT FROM foundation.staff_web_credentials c WHERE c.staff_id=s.id) AS has_web,
      (SELECT r.code FROM foundation.staff_role_assignments a JOIN foundation.roles r ON r.id=a.role_id
        WHERE a.staff_id=s.id AND a.revoked_at IS NULL) AS role_code
    FROM foundation.staff s ORDER BY s.id`)).rows;
  const admin = staff.find((row) => row.role_code === 'ADMIN');
  const technician = staff.find((row) => row.role_code === 'TECHNICIAN');
  assert.ok(east && west && admin && technician, 'Expected the populated 011 fixture');
  // The only SYSTEM ADMIN after the 009 cutover is the verified bootstrap principal.
  assert.equal(admin.id, founderStaff, 'Expected exactly one ADMIN: the verified bootstrap principal');
  const areas = (await db.query('SELECT id,city_id,code FROM foundation.service_areas ORDER BY code')).rows;
  const eastArea = areas.find((area) => area.city_id === east.id);
  const westArea = areas.find((area) => area.city_id === west.id);
  assert.ok(eastArea && westArea, 'Expected the two synthetic city zones from the 011 proof');
  const roles = Object.fromEntries((await db.query('SELECT id,code FROM foundation.roles')).rows.map((row) => [row.code, row.id]));
  // An administrative territory needs a real admin actor and a non-technician web target,
  // so create one synthetic web MANAGER as the target (isolated test database only).
  const webManager = randomUUID();
  await db.query('BEGIN');
  try {
    await db.query("INSERT INTO foundation.staff(id,role,employment_state,auth_version) VALUES($1,'MANAGER','ACTIVE',1)", [webManager]);
    await db.query('INSERT INTO foundation.staff_web_credentials(staff_id,login,password_hash) VALUES($1,$2,$3)',
      [webManager, 'synthetic-web-manager', await syntheticVerifier()]);
    await db.query('INSERT INTO foundation.staff_role_assignments(id,staff_id,role_id,assigned_by) VALUES($1,$2,$3,$4)',
      [randomUUID(), webManager, roles.MANAGER, admin.id]);
    await db.query('COMMIT');
  } catch (error) { await db.query('ROLLBACK').catch(() => undefined); throw error; }

  // ---- Role grant guard: geography never reaches the technician role, GLOBAL and
  // publish stay ADMIN-only, and the widened scope CHECK stays narrow. ----
  await denied(db.query(`INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
    VALUES($1,'geography.read','CITY')`, [roles.TECHNICIAN]), '23514', 'geography on the technician role');
  await denied(db.query(`INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
    VALUES($1,'geography.read','GLOBAL')`, [roles.MANAGER]), '23514', 'GLOBAL geography on a manager role');
  await denied(db.query(`INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
    VALUES($1,'geography.publish','CITY')`, [roles.MANAGER]), '23514', 'publish on a manager role');
  await denied(db.query(`INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
    VALUES($1,'geography.read','SELF')`, [roles.MANAGER]), '23514', 'SELF geography scope');
  await denied(db.query(`INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
    VALUES($1,'staff.read','CITY')`, [roles.MANAGER]), '23514', 'legacy code widened to CITY');
  await denied(db.query(`INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
    VALUES($1,'staff.self.read','GLOBAL')`, [roles.MANAGER]), '23514', 'self code widened to GLOBAL');
  // A delegated CITY grant is legal, and it still cannot be escalated to GLOBAL in place.
  await db.query(`INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
    VALUES($1,'geography.read','CITY')`, [roles.MANAGER]);
  await denied(db.query(`UPDATE foundation.role_permissions SET scope_type='GLOBAL'
    WHERE role_id=$1 AND permission_code='geography.read'`, [roles.MANAGER]), '23514', 'geography scope escalation');
  // Disabling a geography grant is a removal, not an escalation, and must stay possible.
  assert.equal((await db.query(`UPDATE foundation.role_permissions SET enabled=false
    WHERE role_id=$1 AND permission_code='geography.read'`, [roles.MANAGER])).rowCount, 1,
  'Disabling a geography grant must be allowed');
  await db.query(`DELETE FROM foundation.role_permissions WHERE role_id=$1 AND permission_code='geography.read'`,
    [roles.MANAGER]);

  // ---- Administrative city assignment: territory for an active web staff member. ----
  const assignmentId = randomUUID();
  await denied(db.query(`INSERT INTO foundation.staff_admin_city_assignments(id,staff_id,city_id,granted_by)
    VALUES($1,$2,$3,$4)`, [randomUUID(), technician.id, east.id, admin.id]), '23514',
  'administrative territory on a technician');
  await denied(db.query(`INSERT INTO foundation.staff_admin_city_assignments(id,staff_id,city_id,granted_by)
    VALUES($1,$2,$3,$2)`, [randomUUID(), admin.id, east.id]), '23514', 'self-granted territory');
  await denied(db.query(`INSERT INTO foundation.staff_admin_city_assignments(id,staff_id,city_id,granted_by)
    VALUES($1,$2,$3,$4)`, [randomUUID(), webManager, randomUUID(), admin.id]), '23503',
  'territory in an unknown city');
  // Only an ACTIVE SYSTEM ADMIN may write the stored actor: a MANAGER cannot grant a
  // territory even when the application guard is bypassed.
  await denied(db.query(`INSERT INTO foundation.staff_admin_city_assignments(id,staff_id,city_id,granted_by)
    VALUES($1,$2,$3,$4)`, [randomUUID(), webManager, east.id, webManager]), '23514',
  'manager acting as administrative grantor');
  await db.query(`INSERT INTO foundation.staff_admin_city_assignments(id,staff_id,city_id,granted_by)
    VALUES($1,$2,$3,$4)`, [assignmentId, webManager, east.id, admin.id]);
  assert.equal((await db.query('SELECT granted_at FROM foundation.staff_admin_city_assignments WHERE id=$1', [assignmentId])).rows[0]
    .granted_at instanceof Date, true, 'granted_at must be database-stamped');
  await denied(db.query(`INSERT INTO foundation.staff_admin_city_assignments(id,staff_id,city_id,granted_by)
    VALUES($1,$2,$3,$4)`, [randomUUID(), webManager, east.id, admin.id]), '23505', 'duplicate live territory');
  await denied(db.query('DELETE FROM foundation.staff_admin_city_assignments WHERE id=$1', [assignmentId]), '23514');
  await denied(db.query('UPDATE foundation.staff_admin_city_assignments SET city_id=$2 WHERE id=$1',
    [assignmentId, west.id]), '23514');
  // The revocation actor is held to the same SYSTEM ADMIN rule, and the revoker may not be
  // omitted: a NULL revoker or a MANAGER revoker is refused before the pair CHECK applies.
  await denied(db.query(`UPDATE foundation.staff_admin_city_assignments
    SET revoked_at=CURRENT_TIMESTAMP,revoked_by=$2 WHERE id=$1`, [assignmentId, webManager]), '23514',
  'manager acting as administrative revoker');
  await denied(db.query(`UPDATE foundation.staff_admin_city_assignments
    SET revoked_at=CURRENT_TIMESTAMP,revoked_by=NULL WHERE id=$1`, [assignmentId]), '23514',
  'administrative revocation without a revoker');
  assert.equal((await db.query(`UPDATE foundation.staff_admin_city_assignments
    SET revoked_at=CURRENT_TIMESTAMP,revoked_by=$2 WHERE id=$1`, [assignmentId, admin.id])).rowCount, 1);
  await denied(db.query(`UPDATE foundation.staff_admin_city_assignments SET revoked_at=CURRENT_TIMESTAMP
    WHERE id=$1`, [assignmentId]), '23514', 'second revocation');
  await denied(db.query(`UPDATE foundation.staff_admin_city_assignments SET revoked_at=NULL,revoked_by=NULL
    WHERE id=$1`, [assignmentId]), '23514', 'un-revocation');

  // ---- Technician city admission: dates, overlap, actor and history. ----
  // One fixed instant for every adjoining interval: per-statement CURRENT_TIMESTAMP would
  // differ by milliseconds and turn a deliberately touching period into an overlap.
  const base = new Date();
  const at = (days) => new Date(base.getTime() + days * 86400000);
  const membership = randomUUID();
  const insertCityAdmission = (id, technicianId, cityId, from, to, approvedBy) => db.query(
    `INSERT INTO foundation.technician_city_memberships
      (id,technician_id,city_id,valid_from,valid_to,approved_by) VALUES($1,$2,$3,$4,$5,$6)`,
    [id, technicianId, cityId, from, to, approvedBy]);
  await insertCityAdmission(membership, technician.id, east.id, base, at(30), admin.id);
  await denied(insertCityAdmission(randomUUID(), technician.id, east.id, base, at(30), admin.id),
    '23P01', 'overlapping live city admission');
  // Expired and exactly adjacent periods are legal: a closed admission never blocks a new
  // one, and a period that ends exactly where the next starts is not an overlap.
  await insertCityAdmission(randomUUID(), technician.id, east.id, at(-60), at(-30), admin.id);
  await insertCityAdmission(randomUUID(), technician.id, east.id, at(-30), base, admin.id);
  // At most one open-ended live admission per technician+city: the overlap guard refuses
  // the second one before the declarative partial unique index is even reached.
  await insertCityAdmission(randomUUID(), technician.id, east.id, at(400), null, admin.id);
  await denied(insertCityAdmission(randomUUID(), technician.id, east.id, at(800), null, admin.id),
    '23P01', 'second open-ended city admission');
  await denied(insertCityAdmission(randomUUID(), technician.id, west.id, base, base, admin.id),
    '23514', 'empty city admission period');
  await denied(db.query(`INSERT INTO foundation.technician_city_memberships
    (id,technician_id,city_id,valid_from,valid_to,approved_by) VALUES($1,$2,$3,$4,$5,$2)`,
  [randomUUID(), technician.id, west.id, base, at(1)]), '23514', 'self-approved city admission');
  await denied(insertCityAdmission(randomUUID(), admin.id, east.id, base, at(1), webManager),
    '23514', 'city admission for a non-technician');
  await denied(insertCityAdmission(randomUUID(), technician.id, east.id, base, at(1), randomUUID()),
    '23514', 'unknown approver');

  // ---- Technician zone admission: same-city composite FKs and period containment. ----
  const westMembership = randomUUID();
  await insertCityAdmission(westMembership, technician.id, west.id, base, at(30), admin.id);
  const zone = randomUUID();
  const insertZone = (id, technicianId, cityId, areaId, membershipId, from, to) => db.query(
    `INSERT INTO foundation.technician_service_areas
      (id,technician_id,city_id,service_area_id,membership_id,valid_from,valid_to,approved_by)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, [id, technicianId, cityId, areaId, membershipId, from, to, admin.id]);
  await insertZone(zone, technician.id, east.id, eastArea.id, membership, base, at(10));
  await denied(insertZone(randomUUID(), technician.id, east.id, eastArea.id, membership, at(1), at(2)),
    '23P01', 'overlapping live zone admission');
  // A different area of another city: the overlap guard is per area, so the city-scoped
  // composite FK is what refuses this one.
  await denied(insertZone(randomUUID(), technician.id, east.id, westArea.id, membership, at(1), at(2)),
    '23503', 'foreign-city area on a city admission');
  await denied(insertZone(randomUUID(), technician.id, east.id, eastArea.id, westMembership, at(1), at(2)),
    '23503', 'zone admission bound to another city membership');
  await denied(insertZone(randomUUID(), technician.id, east.id, eastArea.id, randomUUID(), at(1), at(2)),
    '23503', 'unknown membership');
  await denied(insertZone(randomUUID(), technician.id, east.id, eastArea.id, membership, at(-1), at(5)),
    '23514', 'zone admission starting before its city admission');
  await denied(insertZone(randomUUID(), technician.id, east.id, eastArea.id, membership, at(1), at(60)),
    '23514', 'zone admission outliving its city admission');
  await denied(db.query('UPDATE foundation.technician_service_areas SET valid_from=$2 WHERE id=$1',
    [zone, at(-2)]), '23514');
  await denied(db.query('DELETE FROM foundation.technician_service_areas WHERE id=$1', [zone]), '23514');
  await denied(db.query('DELETE FROM foundation.technician_city_memberships WHERE id=$1', [membership]), '23514');

  // Revocation order: an active zone cannot survive its revoked city admission, even when
  // the two statements are separate inside one transaction (deferred consistency).
  await db.query('BEGIN');
  try {
    await db.query('UPDATE foundation.technician_city_memberships SET revoked_at=CURRENT_TIMESTAMP,revoked_by=$2 WHERE id=$1',
      [membership, admin.id]);
    await assert.rejects(db.query('COMMIT'), (error) => error.code === '23514',
      'Revoked city admission kept an active zone admission');
  } finally { await db.query('ROLLBACK').catch(() => undefined); }
  // The supported order revokes the zone first, then the city admission.
  assert.equal((await db.query('UPDATE foundation.technician_service_areas SET revoked_at=CURRENT_TIMESTAMP,revoked_by=$2 WHERE id=$1',
    [zone, admin.id])).rowCount, 1);
  assert.equal((await db.query('UPDATE foundation.technician_city_memberships SET revoked_at=CURRENT_TIMESTAMP,revoked_by=$2 WHERE id=$1',
    [membership, admin.id])).rowCount, 1);
  await denied(db.query('UPDATE foundation.technician_city_memberships SET revoked_at=CURRENT_TIMESTAMP WHERE id=$1',
    [membership]), '23514', 'second city admission revocation');

  // ---- Idempotency receipts: minimal, append-only, validated. ----
  const receipt = [admin.id, 'AreaCreate', randomUUID()];
  await db.query(`INSERT INTO foundation.geography_command_receipts(actor_id,operation,key,body_hash,entity_id,entity_version)
    VALUES($1,$2,$3,$4,$5,1)`, [...receipt, 'a'.repeat(64), randomUUID()]);
  await denied(db.query(`INSERT INTO foundation.geography_command_receipts(actor_id,operation,key,body_hash,entity_id,entity_version)
    VALUES($1,$2,$3,$4,$5,1)`, [...receipt, 'a'.repeat(64), randomUUID()]), '23505', 'duplicate receipt key');
  await denied(db.query(`INSERT INTO foundation.geography_command_receipts(actor_id,operation,key,body_hash,entity_id,entity_version)
    VALUES($1,'bad operation',$2,$3,$4,1)`, [admin.id, randomUUID(), 'a'.repeat(64), randomUUID()]), '23514');
  await denied(db.query(`INSERT INTO foundation.geography_command_receipts(actor_id,operation,key,body_hash,entity_id,entity_version)
    VALUES($1,$2,$3,'NOTAHASH',$4,1)`, [admin.id, 'AreaCreate', randomUUID(), randomUUID()]), '23514');
  await denied(db.query(`INSERT INTO foundation.geography_command_receipts(actor_id,operation,key,body_hash,entity_id,entity_version)
    VALUES($1,$2,$3,$4,$5,-1)`, [admin.id, 'AreaCreate', randomUUID(), 'a'.repeat(64), randomUUID()]), '23514');
  await denied(db.query('UPDATE foundation.geography_command_receipts SET entity_version=2'), '23514');
  await denied(db.query('DELETE FROM foundation.geography_command_receipts'), '23514');
  await db.query('BEGIN');
  try {
    await deniedInTransaction(db, 'TRUNCATE foundation.geography_command_receipts', '23514');
    await deniedInTransaction(db, 'TRUNCATE foundation.geography_bootstrap_permissions', '23514');
    await deniedInTransaction(db, 'TRUNCATE foundation.staff_admin_city_assignments', '23514');
    await deniedInTransaction(db, 'TRUNCATE foundation.technician_city_memberships, foundation.technician_service_areas', '23514');
  } finally { await db.query('ROLLBACK'); }

  // ---- The founder exception is bounded: a later ADMIN never inherits it. ----
  const laterAdmin = randomUUID(), laterAssignment = randomUUID();
  await db.query('BEGIN');
  try {
    await db.query("INSERT INTO foundation.staff(id,role,employment_state,auth_version) VALUES($1,'ADMIN','ACTIVE',1)", [laterAdmin]);
    await db.query('INSERT INTO foundation.staff_web_credentials(staff_id,login,password_hash) VALUES($1,$2,$3)',
      [laterAdmin, 'synthetic-later-admin', await syntheticVerifier()]);
    await db.query('INSERT INTO foundation.staff_role_assignments(id,staff_id,role_id,assigned_by) VALUES($1,$2,$3,$4)',
      [laterAssignment, laterAdmin, roles.ADMIN, admin.id]);
    await db.query('COMMIT');
  } catch (error) { await db.query('ROLLBACK').catch(() => undefined); throw error; }
  assert.equal((await db.query('SELECT count(*)::int AS n FROM foundation.geography_bootstrap_permissions WHERE assignment_id=$1',
    [laterAssignment])).rows[0].n, 0, 'A later ADMIN must not inherit the founder exception');
  await db.query('SELECT foundation.issue_first_geo_permissions()');
  assert.equal((await db.query('SELECT count(*)::int AS n FROM foundation.geography_bootstrap_permissions')).rows[0].n, 5,
    'The issue function must not extend the exception to another administrator');
  await denied(db.query(`INSERT INTO foundation.geography_bootstrap_permissions(assignment_id,permission_code)
    VALUES($1,'geography.read')`, [laterAssignment]), '23514', 'bootstrap row for a later ADMIN');
  await denied(db.query(`INSERT INTO foundation.geography_bootstrap_permissions(assignment_id,permission_code)
    VALUES($1,'geography.read')`, [randomUUID()]), '23514', 'bootstrap row for an unknown assignment');

  // ---- Revocation is one-way; a role cycle never resurrects or re-issues it. ----
  assert.equal((await db.query(`UPDATE foundation.geography_bootstrap_permissions SET revoked_at=CURRENT_TIMESTAMP
    WHERE assignment_id=$1 AND permission_code='geography.manage'`, [founderAssignment])).rowCount, 1);
  await denied(db.query(`UPDATE foundation.geography_bootstrap_permissions SET revoked_at=NULL
    WHERE assignment_id=$1 AND permission_code='geography.manage'`, [founderAssignment]), '23514', 'un-revocation');
  await denied(db.query('DELETE FROM foundation.geography_bootstrap_permissions WHERE assignment_id=$1', [founderAssignment]), '23514');
  // Demote and re-promote the founder: the new assignment is an additional assignment, so
  // the exception can never be re-issued to it (and the old rows stay bound to the old one).
  const cycledAssignment = randomUUID();
  await db.query('BEGIN');
  try {
    await db.query('UPDATE foundation.staff_role_assignments SET revoked_at=CURRENT_TIMESTAMP,revoked_by=$2 WHERE id=$1',
      [founderAssignment, laterAdmin]);
    await db.query('INSERT INTO foundation.staff_role_assignments(id,staff_id,role_id,assigned_by) VALUES($1,$2,$3,$4)',
      [cycledAssignment, founderStaff, roles.ADMIN, laterAdmin]);
    await db.query('COMMIT');
  } catch (error) { await db.query('ROLLBACK').catch(() => undefined); throw error; }
  await db.query('SELECT foundation.issue_first_geo_permissions()');
  const afterCycle = await db.query(`SELECT assignment_id,permission_code,revoked_at
    FROM foundation.geography_bootstrap_permissions ORDER BY assignment_id,permission_code`);
  assert.equal(afterCycle.rowCount, 5, 'A role cycle must not issue a second bootstrap set');
  assert(afterCycle.rows.every((row) => row.assignment_id === founderAssignment),
    'Bootstrap rows must stay bound to the original assignment');
  assert.equal(afterCycle.rows.filter((row) => row.revoked_at !== null).length, 1);
  assert.equal((await db.query('SELECT count(*)::int AS n FROM foundation.geography_bootstrap_permissions WHERE assignment_id=$1',
    [cycledAssignment])).rows[0].n, 0, 'A re-promoted founder must not receive a new bootstrap set');
  // The exception is inert after the cycle: it hangs off a revoked assignment, so the
  // authorization layer (which resolves only the current assignment) cannot see it.
  assert.equal((await db.query(`SELECT count(*)::int AS n FROM foundation.geography_bootstrap_permissions g
    JOIN foundation.staff_role_assignments a ON a.id=g.assignment_id
    WHERE a.revoked_at IS NULL AND g.revoked_at IS NULL`)).rows[0].n, 0,
  'A revoked assignment must leave no effective bootstrap grant');

  // ---- Replay: no new rows, no resurrection, no changed history or data. ----
  const newTableSnapshot = await snapshotOf(db, newTables);
  const auditCount = (await db.query("SELECT count(*)::int AS n FROM foundation.audit_logs WHERE operation='GEOGRAPHY_BOOTSTRAP_PERMISSIONS'")).rows[0].n;
  const historyBeforeReplay = await db.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name');
  deploy();
  assert.deepEqual((await db.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name')).rows,
    historyBeforeReplay.rows, '012 replay changed migration history');
  assert.deepEqual(await snapshotOf(db, newTables), newTableSnapshot, '012 replay changed geography access data');
  assert.deepEqual(await snapshotOf(db, preservedTables), before, '012 replay changed the populated geography');
  assert.equal((await db.query("SELECT count(*)::int AS n FROM foundation.audit_logs WHERE operation='GEOGRAPHY_BOOTSTRAP_PERMISSIONS'")).rows[0].n,
    auditCount, '012 replay re-issued the bootstrap exception');
  assert.notEqual((await db.query(`SELECT revoked_at FROM foundation.geography_bootstrap_permissions
    WHERE assignment_id=$1 AND permission_code='geography.manage'`, [founderAssignment])).rows[0]?.revoked_at, null,
  'Replay resurrected a revoked bootstrap grant');
  console.log('011 → geography access: five founder-only bootstrap codes on the original verified ADMIN assignment, '
    + 'no role grant, no later-ADMIN inheritance, one-way revocation across role cycle and replay: PASS');
  console.log('012 same-city admission FKs, dated periods, overlap/actor/history guards, receipts, deferred revoke consistency: PASS');
}
