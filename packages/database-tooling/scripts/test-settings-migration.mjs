import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { connection, credentials } from './migration-local.mjs';

// 013 CHECK inventory, deliberately independent of the DDL text: a dropped, renamed or
// unvalidated guard must fail this proof. Every name below is expected to exist as a
// validated `contype='c'` constraint on the final database.
export const settingsChecks = [
  'business_settings_versions_operator_name_check',
  'business_settings_versions_operator_registration_id_check',
  'business_settings_versions_operator_address_check',
  'business_settings_versions_legal_review_ref_check',
  'business_settings_versions_security_policy_ref_check',
  'business_settings_versions_retention_policy_ref_check',
  'business_settings_versions_upload_policy_ref_check',
  'reference_entries_type_check', 'reference_entries_scope_check', 'reference_entries_scope_city_check',
  'reference_entries_code_check', 'reference_entries_row_version_check',
  'reference_entry_versions_version_check', 'reference_entry_versions_type_check',
  'reference_entry_versions_type_fields_check', 'reference_entry_versions_interval_check',
  'reference_entry_versions_label_check', 'reference_entry_versions_source_check',
  'reference_entry_versions_window_check',
  'content_blocks_kind_check', 'content_blocks_scope_check', 'content_blocks_scope_city_check',
  'content_blocks_code_check', 'content_blocks_row_version_check', 'content_blocks_fallback_scope_check',
  'content_block_revisions_version_check', 'content_block_revisions_text_check',
  'legal_documents_purpose_check', 'legal_documents_kind_check', 'legal_documents_row_version_check',
  'legal_document_versions_purpose_check', 'legal_document_versions_kind_check',
  'legal_document_versions_version_check', 'legal_document_versions_checksum_check',
  'legal_document_versions_text_check',
  'request_sessions_secret_hash_check', 'request_sessions_expiry_check',
  'consent_records_purpose_check', 'consent_records_action_check', 'consent_records_source_check',
  'consent_records_given_supersedes_check', 'consent_records_legal_basis_check',
];

const settingsTables = ['reference_entries', 'reference_entry_versions', 'content_blocks',
  'content_block_revisions', 'legal_documents', 'legal_document_versions', 'request_sessions',
  'consent_records'];
// Every 013 trigger, mapped to its trigger function. All functions are SECURITY INVOKER
// with a fixed search_path and no runtime EXECUTE, so a trigger is the only way they run.
const settingsTriggers = [
  ['reference_entries', 'reference_entries_guard', 'reference_entries_guard'],
  ['reference_entries', 'reference_entries_reject_truncate', 'settings_history_reject_truncate'],
  ['reference_entry_versions', 'reference_entry_versions_pointer_guard', 'reference_entry_versions_pointer_guard'],
  ['reference_entry_versions', 'reference_entry_versions_immutable', 'reference_entry_versions_immutable'],
  ['reference_entry_versions', 'reference_entry_versions_reject_truncate', 'settings_history_reject_truncate'],
  ['content_blocks', 'content_blocks_guard', 'content_blocks_guard'],
  ['content_blocks', 'content_blocks_reject_truncate', 'settings_history_reject_truncate'],
  ['content_block_revisions', 'content_block_revisions_pointer_guard', 'content_block_revisions_pointer_guard'],
  ['content_block_revisions', 'content_block_revisions_immutable', 'content_block_revisions_immutable'],
  ['content_block_revisions', 'content_block_revisions_reject_truncate', 'settings_history_reject_truncate'],
  ['legal_documents', 'legal_documents_guard', 'legal_documents_guard'],
  ['legal_documents', 'legal_documents_reject_truncate', 'settings_history_reject_truncate'],
  ['legal_document_versions', 'legal_document_versions_pointer_guard', 'legal_document_versions_pointer_guard'],
  ['legal_document_versions', 'legal_document_versions_immutable', 'legal_document_versions_immutable'],
  ['legal_document_versions', 'legal_document_versions_reject_truncate', 'settings_history_reject_truncate'],
  ['request_sessions', 'request_sessions_guard', 'request_sessions_guard'],
  ['request_sessions', 'request_sessions_reject_truncate', 'settings_history_reject_truncate'],
  ['consent_records', 'consent_records_guard', 'consent_records_guard'],
  ['consent_records', 'consent_records_reject_truncate', 'settings_history_reject_truncate'],
];
const settingsFunctions = ['reference_entries_guard', 'reference_entry_versions_pointer_guard',
  'reference_entry_versions_immutable', 'content_blocks_guard', 'content_block_revisions_pointer_guard',
  'content_block_revisions_immutable', 'legal_documents_guard', 'legal_document_versions_pointer_guard',
  'legal_document_versions_immutable', 'request_sessions_guard', 'consent_records_guard',
  'settings_history_reject_truncate'];
// The P05-01 (022) unified GEO/CFG fence triggers on the two reference basis
// tables of the 013 list: expected by exact name, function and enabled state.
const settingsFenceTriggers = [
  ['reference_entries', 'reference_entries_geo_cfg_fence', 'geo_cfg_fence_guard'],
  ['reference_entry_versions', 'reference_entry_versions_geo_cfg_fence', 'geo_cfg_fence_guard'],
];
// The 012 delta must survive 013 untouched.
const preservedTables = ['service_cities', 'service_city_versions', 'business_settings_versions',
  'administrative_districts', 'service_areas', 'service_area_versions', 'service_area_district_coverage',
  'staff_admin_city_assignments', 'technician_city_memberships', 'technician_service_areas',
  'geography_bootstrap_permissions', 'geography_command_receipts'];

async function denied(query, sqlState, label) {
  await assert.rejects(query, (error) => error.code === sqlState, `Expected SQLSTATE ${sqlState}${label ? `: ${label}` : ''}`);
}
async function deniedInTransaction(client, sql, sqlState, label) {
  await client.query('SAVEPOINT proof');
  try {
    await denied(client.query(sql), sqlState, label);
  } finally {
    await client.query('ROLLBACK TO SAVEPOINT proof');
    await client.query('RELEASE SAVEPOINT proof');
  }
}
const sha256 = (text) => createHash('sha256').update(text, 'utf8').digest('hex');
// 013 adds columns to business_settings_versions, so a preservation snapshot must pin
// the pre-013 column list instead of using SELECT * before and after the upgrade.
const columnsOf = async (db, tables) => {
  const map = {};
  for (const table of tables) {
    map[table] = (await db.query(`SELECT attname FROM pg_attribute
      WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped ORDER BY attnum`,
    [`foundation.${table}`])).rows.map((row) => row.attname);
  }
  return map;
};
const snapshotOf = async (db, tables, columns) => {
  const rows = [];
  for (const table of tables) {
    const list = columns?.[table]?.map((column) => `"${column}"`).join(', ') ?? '*';
    rows.push((await db.query(`SELECT ${list} FROM foundation.${table} ORDER BY 1`)).rows);
  }
  return rows;
};

// Exact runtime ACL of 013 on the final fresh database, plus the previous grants that
// 013 must not widen or narrow. A missing, extra or table-level privilege fails here.
export async function proveSettingsGrants(runtime, options = {}) {
  // On a database capped at exactly 013 the P05-01 fence triggers do not exist
  // yet; only the final full-chain proof expects them.
  const fenceTriggers = options.expectFenceTriggers === true ? settingsFenceTriggers : [];
  const acl = {
    business_settings_versions: {
      select: ['id', 'version', 'launch_mode', 'primary_city_id', 'reviewed_by', 'published_at',
        'operator_name', 'operator_registration_id', 'operator_address', 'legal_review_ref',
        'security_policy_ref', 'retention_policy_ref', 'upload_policy_ref'],
      insert: ['id', 'version', 'launch_mode', 'primary_city_id', 'reviewed_by',
        'operator_name', 'operator_registration_id', 'operator_address', 'legal_review_ref',
        'security_policy_ref', 'retention_policy_ref', 'upload_policy_ref'],
      update: [], delete: false },
    reference_entries: {
      select: ['id', 'type', 'scope', 'city_id', 'code', 'row_version', 'current_version_id', 'archived_at'],
      insert: ['id', 'type', 'scope', 'city_id', 'code'], update: ['current_version_id', 'archived_at'], delete: false },
    reference_entry_versions: {
      select: ['id', 'entry_id', 'type', 'city_id', 'version', 'label', 'valid_from', 'valid_until', 'source_ref',
        'reviewed_by', 'published_at', 'city_version_id', 'start_minute', 'end_minute'],
      insert: ['id', 'entry_id', 'type', 'city_id', 'version', 'label', 'valid_from', 'valid_until', 'source_ref',
        'reviewed_by', 'city_version_id', 'start_minute', 'end_minute'],
      update: [], delete: false },
    content_blocks: {
      select: ['id', 'code', 'kind', 'scope', 'city_id', 'allow_company_fallback', 'row_version',
        'current_revision_id', 'archived_at'],
      insert: ['id', 'code', 'kind', 'scope', 'city_id', 'allow_company_fallback'],
      update: ['current_revision_id', 'archived_at'], delete: false },
    content_block_revisions: {
      select: ['id', 'block_id', 'version', 'title', 'body', 'source_ref', 'reviewed_by', 'published_at'],
      insert: ['id', 'block_id', 'version', 'title', 'body', 'source_ref', 'reviewed_by'], update: [], delete: false },
    legal_documents: {
      select: ['id', 'purpose', 'kind', 'row_version', 'current_version_id'],
      insert: ['id', 'purpose', 'kind'], update: ['current_version_id'], delete: false },
    legal_document_versions: {
      select: ['id', 'document_id', 'purpose', 'kind', 'version', 'title', 'body', 'checksum', 'legal_basis',
        'source_ref', 'reviewed_by', 'published_at'],
      insert: ['id', 'document_id', 'purpose', 'kind', 'version', 'title', 'body', 'checksum', 'legal_basis',
        'source_ref', 'reviewed_by'],
      update: [], delete: false },
    request_sessions: {
      select: ['id', 'secret_hash', 'intake_city_id', 'intake_city_version_id', 'created_at', 'expires_at', 'revoked_at'],
      insert: ['id', 'secret_hash', 'intake_city_id', 'intake_city_version_id', 'expires_at'],
      update: ['revoked_at'], delete: false },
    consent_records: {
      select: ['id', 'session_id', 'document_id', 'document_version_id', 'purpose', 'action', 'legal_basis',
        'source', 'evidence_ref', 'occurred_at', 'supersedes_id'],
      insert: ['id', 'session_id', 'document_id', 'document_version_id', 'purpose', 'action', 'legal_basis',
        'source', 'evidence_ref', 'supersedes_id'],
      update: [], delete: false },
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
    assert.equal(broad.rows[0].deletable, spec.delete, `Runtime DELETE privilege on ${table}`);
    // No PUBLIC privilege on any new table.
    const publicAcl = await runtime.query(`SELECT count(*)::int AS n FROM pg_class c
      CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) acl
      WHERE c.oid=$1::regclass AND acl.grantee=0`, [target]);
    assert.equal(publicAcl.rows[0].n, 0, `PUBLIC privilege on ${table}`);
  }
  // 013 adds no callable surface: no function is executable by the runtime or PUBLIC.
  const executable = await runtime.query(`SELECT p.proname,
    has_function_privilege(current_user,p.oid,'EXECUTE') AS allowed,
    has_function_privilege('fixlevelup_migrator',p.oid,'EXECUTE') AS migrator_allowed,
    pg_get_userbyid(p.proowner) AS owner, p.prosecdef, p.proconfig,
    EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl
      WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE') AS public_execute
    FROM pg_proc p WHERE p.pronamespace='foundation'::regnamespace AND p.proname=ANY($1::text[])`,
  [settingsFunctions]);
  assert.equal(executable.rowCount, settingsFunctions.length, '013 guard functions missing');
  assert.equal(executable.rows.filter((row) => row.allowed).length, 0, 'Runtime must not execute a 013 guard');
  assert.equal(executable.rows.filter((row) => row.public_execute).length, 0, 'PUBLIC EXECUTE on a 013 guard');
  assert(executable.rows.every((row) => row.owner === 'fixlevelup_migrator' && row.prosecdef === false
    && row.proconfig?.includes('search_path=pg_catalog')), '013 guard ownership/security mismatch');
  // Every expected 013 trigger exists, is enabled, and is bound to its own function. A
  // disabled trigger would silently drop an immutability or pointer guard.
  // P05-01 (022) additionally installs the two unified GEO/CFG fence triggers on
  // the reference basis tables of this list; they are expected by exact name and
  // bound function, never by a loose count.
  const triggers = await runtime.query(`SELECT c.relname AS table, g.tgname AS name, g.tgenabled IN ('O','A') AS enabled,
      p.proname AS fn
    FROM pg_trigger g JOIN pg_class c ON c.oid=g.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_proc p ON p.oid=g.tgfoid
    WHERE n.nspname='foundation' AND c.relname=ANY($1::text[]) AND NOT g.tgisinternal
    ORDER BY c.relname, g.tgname`, [settingsTables]);
  assert.equal(triggers.rowCount, settingsTriggers.length + fenceTriggers.length, '013 trigger count mismatch');
  for (const [table, trigger, fn] of settingsTriggers) {
    const found = triggers.rows.find((row) => row.table === table && row.name === trigger);
    assert.ok(found, `Missing 013 trigger ${table}.${trigger}`);
    assert.equal(found.enabled, true, `Disabled 013 trigger ${table}.${trigger}`);
    assert.equal(found.fn, fn, `013 trigger ${table}.${trigger} bound to the wrong function`);
  }
  for (const [table, trigger, fn] of fenceTriggers) {
    const found = triggers.rows.find((row) => row.table === table && row.name === trigger);
    assert.ok(found, `Missing S1 fence trigger ${table}.${trigger}`);
    assert.equal(found.enabled, true, `Disabled S1 fence trigger ${table}.${trigger}`);
    assert.equal(found.fn, fn, `S1 fence trigger ${table}.${trigger} bound to the wrong function`);
  }
  // Exactly the two 010 validators remain callable: 013 neither adds nor removes EXECUTE.
  const validators = await runtime.query(`SELECT p.proname FROM pg_proc p
    WHERE p.pronamespace='foundation'::regnamespace AND p.proname=ANY($1::text[])
      AND has_function_privilege(current_user,p.oid,'EXECUTE')`, [['city_office_hours_is_valid', 'city_timezone_is_valid']]);
  assert.deepEqual(validators.rows.map((row) => row.proname).sort(),
    ['city_office_hours_is_valid', 'city_timezone_is_valid'], '013 changed the callable validator set');
  // Previous 012 grants stay intact (spot check the widened role grant and draft delete).
  const preserved = await runtime.query(`SELECT
    has_column_privilege(current_user,'foundation.role_permissions','scope_type','UPDATE') AS scope_write,
    has_column_privilege(current_user,'foundation.service_area_district_coverage','relation','UPDATE') AS draft_write,
    has_table_privilege(current_user,'foundation.service_area_district_coverage','DELETE') AS draft_delete,
    has_table_privilege(current_user,'foundation.service_cities','UPDATE') AS city_broad,
    has_column_privilege(current_user,'foundation.service_cities','current_version_id','UPDATE') AS city_pointer`);
  assert.deepEqual(preserved.rows[0], { scope_write: true, draft_write: true, draft_delete: true,
    city_broad: false, city_pointer: true }, '013 changed the 010/011/012 runtime grants');
  console.log('013 runtime: exact column ACL on settings/legal tables, append-only history without '
    + 'UPDATE/DELETE/TRUNCATE, no PUBLIC access, no callable guard, 010-012 grants preserved: PASS');
}

// The runtime really cannot mutate history, and cannot reach the guards directly.
export async function proveSettingsRuntimeDenials(runtime) {
  const history = ['reference_entry_versions', 'content_block_revisions', 'legal_document_versions', 'consent_records'];
  const statements = [
    ...history.flatMap((table) => [`UPDATE foundation.${table} SET id=id`, `DELETE FROM foundation.${table}`,
      `TRUNCATE foundation.${table}`]),
    ...settingsTables.filter((table) => !history.includes(table)).flatMap((table) => [`DELETE FROM foundation.${table}`,
      `TRUNCATE foundation.${table}`]),
    // Session identity/expiry is stable; only revoked_at may move.
    'UPDATE foundation.request_sessions SET secret_hash=secret_hash',
    'UPDATE foundation.request_sessions SET expires_at=expires_at',
    'UPDATE foundation.request_sessions SET created_at=created_at',
    'UPDATE foundation.request_sessions SET intake_city_id=intake_city_id',
    // Database-owned stamps are not insertable: the runtime can neither backdate an anchor
    // nor forge an event time (occurred_at is also overwritten by the consent guard).
    "INSERT INTO foundation.request_sessions(id,secret_hash,intake_city_id,intake_city_version_id,created_at,expires_at) VALUES(gen_random_uuid(),repeat('a',64),gen_random_uuid(),gen_random_uuid(),CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+INTERVAL '1 hour')",
    "INSERT INTO foundation.consent_records(id,session_id,document_id,document_version_id,purpose,action,legal_basis,source,evidence_ref,occurred_at) VALUES(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),'REQUEST_PROCESSING','GIVEN','X','FORM',gen_random_uuid(),CURRENT_TIMESTAMP)",
    "INSERT INTO foundation.reference_entry_versions(id,entry_id,type,version,label,valid_from,source_ref,reviewed_by,published_at) VALUES(gen_random_uuid(),gen_random_uuid(),'PAYMENT_METHOD',1,'x',CURRENT_TIMESTAMP,'x',gen_random_uuid(),CURRENT_TIMESTAMP)",
    "INSERT INTO foundation.content_block_revisions(id,block_id,version,title,body,source_ref,reviewed_by,published_at) VALUES(gen_random_uuid(),gen_random_uuid(),1,'t','b','s',gen_random_uuid(),CURRENT_TIMESTAMP)",
    // Identity columns of the stable tables are not writable at all.
    'UPDATE foundation.reference_entries SET type=type',
    'UPDATE foundation.reference_entries SET code=code',
    'UPDATE foundation.content_blocks SET code=code',
    'UPDATE foundation.legal_documents SET purpose=purpose',
    'UPDATE foundation.legal_documents SET kind=kind',
    // No DDL and no function call.
    'ALTER TABLE foundation.consent_records ADD COLUMN forbidden integer',
    'CREATE TABLE foundation.forbidden_settings(id integer)',
    ...settingsFunctions.map((name) => `SELECT foundation.${name}()`),
  ];
  for (const sql of statements) { await denied(runtime.query(sql), '42501', sql); }
  const hygiene = await runtime.query(`SELECT current_user AS role,
    has_schema_privilege(current_user,'foundation','CREATE') AS schema_ddl,
    has_database_privilege(current_user,current_database(),'CREATE,TEMP') AS db_ddl`);
  assert.deepEqual(hygiene.rows[0], { role: 'fixlevelup_runtime', schema_ddl: false, db_ddl: false });
  console.log(`013 runtime denials (${statements.length}): no UPDATE/DELETE/TRUNCATE on history, `
    + 'no DDL, no callable guard: PASS');
}

// Runs on the populated 012 database from the geography proof: 013 is applied to real
// synthetic city/settings/geography history, then every invariant is exercised with
// explicit expected SQLSTATEs. No test DDL in a working application database.
export async function proveSettingsUpgrade(db, deploy, diff) {
  const { rows: [identity] } = await db.query('SELECT current_database() AS db, current_user AS role');
  assert.match(identity.db, /^fixlevelup_p017a_upgrade_[a-f0-9]{12}$/);
  assert.equal(identity.role, 'fixlevelup_migrator');
  for (const table of settingsTables) {
    assert.equal((await db.query(`SELECT to_regclass('foundation.${table}') AS ref`)).rows[0].ref, null,
      '013 applied before its proof');
  }
  assert.equal((await db.query(`SELECT count(*)::int AS n FROM pg_attribute
    WHERE attrelid='foundation.business_settings_versions'::regclass AND attname='operator_name'`)).rows[0].n, 0,
  '013 provenance column applied before its proof');
  const preservedColumns = await columnsOf(db, preservedTables);
  const before = await snapshotOf(db, preservedTables, preservedColumns);
  const historyBefore = await db.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name');
  assert.equal(historyBefore.rows.at(-1)?.migration_name, '20261121000300_geography_access');

  deploy();
  const historyAfter = await db.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name');
  assert.equal(historyAfter.rows.at(-1)?.migration_name, '20261121000400_settings_legal_references');
  assert.equal(historyAfter.rows.at(-1)?.finished_at instanceof Date, true);
  assert.deepEqual(await snapshotOf(db, preservedTables, preservedColumns), before, '013 changed populated 010-012 data');
  for (const table of settingsTables) {
    assert.equal((await db.query(`SELECT FROM foundation.${table}`)).rowCount, 0, `Unexpected seed in ${table}`);
  }
  // Existing reviewed revisions keep meaning "unknown" for the new provenance columns.
  assert.equal((await db.query(`SELECT count(*)::int AS n FROM foundation.business_settings_versions
    WHERE operator_name IS NOT NULL OR operator_registration_id IS NOT NULL OR operator_address IS NOT NULL
      OR legal_review_ref IS NOT NULL OR security_policy_ref IS NOT NULL OR retention_policy_ref IS NOT NULL
      OR upload_policy_ref IS NOT NULL`)).rows[0].n, 0, '013 backfilled provenance it cannot know');
  const cities = (await db.query('SELECT id,code FROM foundation.service_cities ORDER BY code')).rows;
  const [east, west] = cities;
  assert.ok(east && west, 'Expected the populated 012 fixture cities');
  const cityVersions = (await db.query('SELECT id,city_id,version FROM foundation.service_city_versions ORDER BY city_id,version')).rows;
  const eastVersion = cityVersions.find((row) => row.city_id === east.id);
  const westVersion = cityVersions.find((row) => row.city_id === west.id);
  assert.ok(eastVersion && westVersion, 'Expected the populated 012 city versions');
  const staff = (await db.query("SELECT id FROM foundation.staff WHERE role='ADMIN' ORDER BY id LIMIT 1")).rows[0]?.id;
  assert.ok(staff, 'Expected a synthetic reviewed staff member');

  // ---- Company settings provenance: additive, nullable, bounded, still immutable. ----
  const settings = (await db.query(`SELECT * FROM foundation.business_settings_versions ORDER BY version DESC LIMIT 1`)).rows[0];
  assert.ok(settings, 'Expected a reviewed company settings revision');
  const provenance = {
    operator_name: 'Synthetic Operator LLC', operator_registration_id: 'SYNTH-0001',
    operator_address: 'Synthetic address 1', legal_review_ref: 'review://synthetic/legal',
    security_policy_ref: 'policy://synthetic/security', retention_policy_ref: 'policy://synthetic/retention',
    upload_policy_ref: 'policy://synthetic/upload',
  };
  await db.query(`INSERT INTO foundation.business_settings_versions
    (id,version,launch_mode,primary_city_id,reviewed_by,operator_name,operator_registration_id,operator_address,
     legal_review_ref,security_policy_ref,retention_policy_ref,upload_policy_ref)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
  [randomUUID(), settings.version + 1, settings.launch_mode, settings.primary_city_id, staff, provenance.operator_name,
    provenance.operator_registration_id, provenance.operator_address, provenance.legal_review_ref,
    provenance.security_policy_ref, provenance.retention_policy_ref, provenance.upload_policy_ref]);
  const stored = (await db.query(`SELECT operator_name,operator_registration_id,operator_address,legal_review_ref,
    security_policy_ref,retention_policy_ref,upload_policy_ref FROM foundation.business_settings_versions
    WHERE version=$1`, [settings.version + 1])).rows[0];
  assert.deepEqual(stored, provenance, 'Company provenance not stored verbatim');
  // Unknown is expressed as NULL, never as blank text.
  for (const field of Object.keys(provenance)) {
    await denied(db.query(`INSERT INTO foundation.business_settings_versions
      (id,version,launch_mode,primary_city_id,reviewed_by,${field}) VALUES($1,$2,$3,$4,$5,$6)`,
    [randomUUID(), settings.version + 2, settings.launch_mode, settings.primary_city_id, staff, ' \t']), '23514', field);
  }
  await denied(db.query(`INSERT INTO foundation.business_settings_versions
    (id,version,launch_mode,primary_city_id,reviewed_by,operator_name) VALUES($1,$2,$3,$4,$5,$6)`,
  [randomUUID(), settings.version + 2, settings.launch_mode, settings.primary_city_id, staff, 'x'.repeat(201)]), '23514');
  await denied(db.query('UPDATE foundation.business_settings_versions SET operator_name=operator_name'), '23514');
  await denied(db.query('DELETE FROM foundation.business_settings_versions'), '23514');

  // ---- Reference entries: typed scope, stable identity, DB-owned row_version. ----
  const paymentEntry = randomUUID(), callbackEntry = randomUUID(), archiveEntry = randomUUID();
  await db.query(`INSERT INTO foundation.reference_entries(id,type,scope,city_id,code)
    VALUES($1,'PAYMENT_METHOD','COMPANY',NULL,'CARD'),($2,'CALLBACK_INTERVAL','CITY',$3,'DAY'),
      ($4,'CANCEL_REASON','COMPANY',NULL,'ARCHIVE')`,
  [paymentEntry, callbackEntry, east.id, archiveEntry]);
  await denied(db.query(`INSERT INTO foundation.reference_entries(id,type,scope,city_id,code)
    VALUES($1,'UNKNOWN','COMPANY',NULL,'X')`, [randomUUID()]), '23514', 'reference type vocabulary');
  await denied(db.query(`INSERT INTO foundation.reference_entries(id,type,scope,city_id,code)
    VALUES($1,'PAYMENT_METHOD','GLOBAL',NULL,'X')`, [randomUUID()]), '23514', 'reference scope vocabulary');
  await denied(db.query(`INSERT INTO foundation.reference_entries(id,type,scope,city_id,code)
    VALUES($1,'CALLBACK_INTERVAL','COMPANY',NULL,'X')`, [randomUUID()]), '23514', 'callback interval must be CITY');
  await denied(db.query(`INSERT INTO foundation.reference_entries(id,type,scope,city_id,code)
    VALUES($1,'PAYMENT_METHOD','CITY',$2,'X')`, [randomUUID(), east.id]), '23514', 'company type must be COMPANY');
  await denied(db.query(`INSERT INTO foundation.reference_entries(id,type,scope,city_id,code)
    VALUES($1,'CALLBACK_INTERVAL','CITY',NULL,'X')`, [randomUUID()]), '23514', 'city type needs a city');
  await denied(db.query(`INSERT INTO foundation.reference_entries(id,type,scope,city_id,code)
    VALUES($1,'PAYMENT_METHOD','COMPANY',NULL,'1BAD')`, [randomUUID()]), '23514', 'reference code format');
  await denied(db.query(`INSERT INTO foundation.reference_entries(id,type,scope,city_id,code)
    VALUES($1,'CALLBACK_INTERVAL','CITY',$2,'X')`, [randomUUID(), randomUUID()]), '23503', 'unknown city FK');
  await denied(db.query(`INSERT INTO foundation.reference_entries(id,type,scope,city_id,code)
    VALUES($1,'PAYMENT_METHOD','COMPANY',NULL,'CARD')`, [randomUUID()]), '23505', 'duplicate company code');
  await denied(db.query(`INSERT INTO foundation.reference_entries(id,type,scope,city_id,code,row_version)
    VALUES($1,'CANCEL_REASON','COMPANY',NULL,'CARD',0)`, [randomUUID()]), '23514', 'row_version lower bound');
  // Same code in another type or another city is a different identity.
  await db.query(`INSERT INTO foundation.reference_entries(id,type,scope,city_id,code)
    VALUES($1,'CANCEL_REASON','COMPANY',NULL,'CARD'),($2,'CALLBACK_INTERVAL','CITY',$3,'DAY')`,
  [randomUUID(), randomUUID(), west.id]);
  await denied(db.query(`INSERT INTO foundation.reference_entries(id,type,scope,city_id,code)
    VALUES($1,'CALLBACK_INTERVAL','CITY',$2,'DAY')`, [randomUUID(), east.id]), '23505', 'duplicate city code');
  // Identity is stable and row_version is owned by the database.
  await denied(db.query(`UPDATE foundation.reference_entries SET type='PAYMENT_METHOD' WHERE id=$1`, [callbackEntry]), '23514');
  await denied(db.query(`UPDATE foundation.reference_entries SET code='OTHER' WHERE id=$1`, [paymentEntry]), '23514');
  await denied(db.query(`UPDATE foundation.reference_entries SET city_id=$2 WHERE id=$1`, [callbackEntry, west.id]), '23514');
  // The database owns row_version: a caller-supplied value is overwritten, never honoured.
  const paymentRowVersion = (await db.query('SELECT row_version FROM foundation.reference_entries WHERE id=$1', [paymentEntry])).rows[0].row_version;
  assert.deepEqual((await db.query('UPDATE foundation.reference_entries SET row_version=1 WHERE id=$1 RETURNING row_version',
    [paymentEntry])).rows, [{ row_version: paymentRowVersion + 1 }], 'caller row_version must be overwritten by OLD+1');

  // ---- Reference versions: composite type FK, callback window, immutability. ----
  const insertVersion = (id, entryId, type, cityId, version, extra = {}) => db.query(`INSERT INTO foundation.reference_entry_versions
    (id,entry_id,type,city_id,version,label,valid_from,valid_until,source_ref,reviewed_by,city_version_id,start_minute,end_minute)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
  [id, entryId, type, cityId, version, extra.label ?? 'Synthetic label', extra.from ?? new Date(),
    extra.until ?? null, extra.source ?? 'review://synthetic/reference', staff, extra.cityVersionId ?? null,
    extra.start ?? null, extra.end ?? null]);
  const companyVersion = randomUUID(), callbackVersion = randomUUID(), archiveVersion = randomUUID();
  await insertVersion(companyVersion, paymentEntry, 'PAYMENT_METHOD', null, 1);
  await insertVersion(callbackVersion, callbackEntry, 'CALLBACK_INTERVAL', east.id, 1,
    { cityVersionId: eastVersion.id, start: 540, end: 1080 });
  // The archived-entry probes need a real revision to point at *before* the archive.
  await insertVersion(archiveVersion, archiveEntry, 'CANCEL_REASON', null, 1);
  // Wrong type for an existing entry is refused by the composite FK.
  await denied(insertVersion(randomUUID(), paymentEntry, 'CANCEL_REASON', null, 2), '23503', 'version type must match entry');
  await denied(insertVersion(randomUUID(), randomUUID(), 'PAYMENT_METHOD', null, 1), '23503', 'version needs an entry');
  await denied(insertVersion(randomUUID(), paymentEntry, 'PAYMENT_METHOD', null, 1), '23505', 'duplicate entry version');
  await denied(insertVersion(randomUUID(), paymentEntry, 'PAYMENT_METHOD', null, 0), '23514', 'version lower bound');
  for (const extra of [{ label: ' \n' }, { source: '  ' }]) {
    await denied(insertVersion(randomUUID(), paymentEntry, 'PAYMENT_METHOD', null, 2, extra), '23514');
  }
  await denied(insertVersion(randomUUID(), paymentEntry, 'PAYMENT_METHOD', null, 2,
    { from: new Date(), until: new Date() }), '23514', 'empty validity window');
  // Callback interval fields: all four present, 0 <= start < end <= 1440.
  for (const extra of [{ cityVersionId: eastVersion.id, start: -1, end: 60 },
    { cityVersionId: eastVersion.id, start: 60, end: 60 },
    { cityVersionId: eastVersion.id, start: 120, end: 60 },
    { cityVersionId: eastVersion.id, start: 0, end: 1441 },
    { cityVersionId: eastVersion.id, start: 0 },
    { cityVersionId: eastVersion.id, end: 60 }]) {
    await denied(insertVersion(randomUUID(), callbackEntry, 'CALLBACK_INTERVAL', east.id, 2, extra), '23514',
      `callback interval ${JSON.stringify(extra)}`);
  }
  // Non-callback types must not carry any city/interval field.
  await denied(insertVersion(randomUUID(), paymentEntry, 'PAYMENT_METHOD', east.id, 2,
    { start: 0, end: 60 }), '23514', 'company version with interval');
  await denied(insertVersion(randomUUID(), paymentEntry, 'PAYMENT_METHOD', null, 2,
    { cityVersionId: eastVersion.id }), '23514', 'company version with city version');
  // Same-city provenance FK and the same-city pointer guard.
  await denied(insertVersion(randomUUID(), callbackEntry, 'CALLBACK_INTERVAL', east.id, 2,
    { cityVersionId: westVersion.id, start: 0, end: 60 }), '23503', 'callback city version of another city');
  await denied(insertVersion(randomUUID(), callbackEntry, 'CALLBACK_INTERVAL', west.id, 2,
    { cityVersionId: westVersion.id, start: 0, end: 60 }), '23503', 'callback version city of another city');
  // Archiving is one-way and closes the "archive, unarchive, append" bypass: the stamp
  // can never be cleared or rewritten, an archived entry takes no new version and its
  // pointer cannot actually move (a no-op pointer write is still allowed).
  const entryRowVersion = (await db.query('SELECT row_version FROM foundation.reference_entries WHERE id=$1', [archiveEntry])).rows[0].row_version;
  assert.deepEqual((await db.query('UPDATE foundation.reference_entries SET archived_at=CURRENT_TIMESTAMP WHERE id=$1 RETURNING row_version',
    [archiveEntry])).rows, [{ row_version: entryRowVersion + 1 }], 'DB must own reference row_version');
  await denied(db.query('UPDATE foundation.reference_entries SET archived_at=NULL WHERE id=$1', [archiveEntry]),
    '23514', 'cleared archive stamp');
  await denied(db.query("UPDATE foundation.reference_entries SET archived_at=CURRENT_TIMESTAMP-INTERVAL '1 day' WHERE id=$1",
    [archiveEntry]), '23514', 'rewritten archive stamp');
  await denied(insertVersion(randomUUID(), archiveEntry, 'CANCEL_REASON', null, 2), '23514',
    'archived entry received a new version');
  await denied(db.query('UPDATE foundation.reference_entries SET current_version_id=$2 WHERE id=$1',
    [archiveEntry, archiveVersion]), '23514', 'archived entry moved its pointer');
  assert.equal((await db.query('UPDATE foundation.reference_entries SET current_version_id=current_version_id WHERE id=$1',
    [archiveEntry])).rowCount, 1, 'a no-op pointer write on an archived entry stays allowed');
  await denied(db.query('DELETE FROM foundation.reference_entries'), '23514');
  // TRUNCATE is refused by the statement trigger; CASCADE is needed to reach it because the
  // table participates in a circular FK.
  await denied(db.query('TRUNCATE foundation.reference_entries CASCADE'), '23514');
  // Pointer must name a version of this entry and type (composite FK).
  assert.equal((await db.query('UPDATE foundation.reference_entries SET current_version_id=$2 WHERE id=$1',
    [paymentEntry, companyVersion])).rowCount, 1);
  await denied(db.query('UPDATE foundation.reference_entries SET current_version_id=$2 WHERE id=$1',
    [paymentEntry, callbackVersion]), '23503', 'pointer to another entry');
  await denied(db.query('UPDATE foundation.reference_entries SET current_version_id=$2 WHERE id=$1',
    [paymentEntry, randomUUID()]), '23503', 'pointer to an unknown version');
  // Immutable revisions, including TRUNCATE.
  await denied(db.query(`UPDATE foundation.reference_entry_versions SET label='changed' WHERE id=$1`, [companyVersion]), '23514');
  await denied(db.query('DELETE FROM foundation.reference_entry_versions WHERE id=$1', [companyVersion]), '23514');
  await db.query('BEGIN');
  try { await deniedInTransaction(db, 'TRUNCATE foundation.reference_entry_versions CASCADE', '23514'); }
  finally { await db.query('ROLLBACK'); }
  // Historical snapshot keeps the exact reviewed label after the pointer moved on.
  assert.equal((await db.query('SELECT label FROM foundation.reference_entry_versions WHERE id=$1',
    [companyVersion])).rows[0].label, 'Synthetic label');

  // ---- Content blocks and revisions. ----
  const faqBlock = randomUUID(), cityFact = randomUUID();
  await db.query(`INSERT INTO foundation.content_blocks(id,code,kind,scope,city_id,allow_company_fallback)
    VALUES($1,'main_faq','FAQ','COMPANY',NULL,true),($2,'zone_fact','FACT','CITY',$3,false)`,
  [faqBlock, cityFact, east.id]);
  await denied(db.query(`INSERT INTO foundation.content_blocks(id,code,kind,scope,city_id)
    VALUES($1,'bad_kind','CONTACT','COMPANY',NULL)`, [randomUUID()]), '23514', 'content kind vocabulary');
  await denied(db.query(`INSERT INTO foundation.content_blocks(id,code,kind,scope,city_id)
    VALUES($1,'bad_scope','FAQ','GLOBAL',NULL)`, [randomUUID()]), '23514', 'content scope vocabulary');
  await denied(db.query(`INSERT INTO foundation.content_blocks(id,code,kind,scope,city_id)
    VALUES($1,'bad_pair','FAQ','COMPANY',$2)`, [randomUUID(), east.id]), '23514', 'company block with a city');
  await denied(db.query(`INSERT INTO foundation.content_blocks(id,code,kind,scope,city_id)
    VALUES($1,'bad_pair','FAQ','CITY',NULL)`, [randomUUID()]), '23514', 'city block without a city');
  await denied(db.query(`INSERT INTO foundation.content_blocks(id,code,kind,scope,city_id,allow_company_fallback)
    VALUES($1,'bad_fallback','FAQ','CITY',$2,true)`, [randomUUID(), east.id]), '23514', 'fallback on a city block');
  await denied(db.query(`INSERT INTO foundation.content_blocks(id,code,kind,scope,city_id)
    VALUES($1,'main_faq','FAQ','COMPANY',NULL)`, [randomUUID()]), '23505', 'duplicate company content code');
  await denied(db.query(`INSERT INTO foundation.content_blocks(id,code,kind,scope,city_id)
    VALUES($1,'zone_fact','FACT','CITY',$2)`, [randomUUID(), east.id]), '23505', 'duplicate city content code');
  await db.query(`INSERT INTO foundation.content_blocks(id,code,kind,scope,city_id) VALUES($1,'zone_fact','FACT','CITY',$2)`,
    [randomUUID(), west.id]);
  const faqRevision = randomUUID(), factRevision = randomUUID();
  const insertRevision = (id, blockId, version, extra = {}) => db.query(`INSERT INTO foundation.content_block_revisions
    (id,block_id,version,title,body,source_ref,reviewed_by) VALUES($1,$2,$3,$4,$5,$6,$7)`,
  [id, blockId, version, extra.title ?? 'Synthetic title', extra.body ?? 'Synthetic body',
    extra.source ?? 'review://synthetic/content', staff]);
  await insertRevision(faqRevision, faqBlock, 1);
  await insertRevision(factRevision, cityFact, 1);
  await denied(insertRevision(randomUUID(), faqBlock, 1), '23505', 'duplicate block revision');
  await denied(insertRevision(randomUUID(), faqBlock, 0), '23514', 'revision lower bound');
  for (const extra of [{ title: ' ' }, { body: '\t' }, { source: ' ' }]) {
    await denied(insertRevision(randomUUID(), faqBlock, 2, extra), '23514', 'blank revision text');
  }
  await denied(insertRevision(randomUUID(), randomUUID(), 1), '23503', 'revision needs a block');
  assert.equal((await db.query('UPDATE foundation.content_blocks SET current_revision_id=$2 WHERE id=$1',
    [faqBlock, faqRevision])).rowCount, 1);
  await denied(db.query('UPDATE foundation.content_blocks SET current_revision_id=$2 WHERE id=$1',
    [faqBlock, factRevision]), '23503', 'pointer to another block revision');
  await denied(db.query(`UPDATE foundation.content_blocks SET kind='SEO' WHERE id=$1`, [faqBlock]), '23514');
  await denied(db.query(`UPDATE foundation.content_blocks SET code='changed' WHERE id=$1`, [faqBlock]), '23514');
  const contentRowVersion = (await db.query('SELECT row_version FROM foundation.content_blocks WHERE id=$1', [faqBlock])).rows[0].row_version;
  assert.deepEqual((await db.query('UPDATE foundation.content_blocks SET archived_at=CURRENT_TIMESTAMP WHERE id=$1 RETURNING row_version',
    [faqBlock])).rows, [{ row_version: contentRowVersion + 1 }], 'DB must own content row_version');
  // Content archiving is one-way too, before any pointer rule applies.
  await denied(db.query('UPDATE foundation.content_blocks SET archived_at=NULL WHERE id=$1', [faqBlock]),
    '23514', 'cleared content archive stamp');
  await denied(db.query("UPDATE foundation.content_blocks SET archived_at=CURRENT_TIMESTAMP-INTERVAL '1 day' WHERE id=$1",
    [faqBlock]), '23514', 'rewritten content archive stamp');
  await denied(insertRevision(randomUUID(), faqBlock, 2), '23514', 'archived block received a revision');
  await denied(db.query(`UPDATE foundation.content_blocks SET current_revision_id=NULL WHERE id=$1`, [faqBlock]), '23514',
    'archived block moved its pointer');
  await denied(db.query(`UPDATE foundation.content_block_revisions SET title='changed' WHERE id=$1`, [faqRevision]), '23514');
  await denied(db.query('DELETE FROM foundation.content_block_revisions'), '23514');
  await denied(db.query('DELETE FROM foundation.content_blocks'), '23514');
  await db.query('BEGIN');
  try {
    await deniedInTransaction(db, 'TRUNCATE foundation.content_block_revisions CASCADE', '23514');
    await deniedInTransaction(db, 'TRUNCATE foundation.content_blocks CASCADE', '23514');
  } finally { await db.query('ROLLBACK'); }

  // ---- Legal documents: purpose+kind identity, DB-verified checksum, immutable text. ----
  const consentDoc = randomUUID(), policyDoc = randomUUID();
  await db.query(`INSERT INTO foundation.legal_documents(id,purpose,kind)
    VALUES($1,'REQUEST_PROCESSING','CONSENT_FORM'),($2,'REQUEST_PROCESSING','POLICY')`,
  [consentDoc, policyDoc]);
  await denied(db.query(`INSERT INTO foundation.legal_documents(id,purpose,kind)
    VALUES($1,'SERVICE','POLICY')`, [randomUUID()]), '23514', 'legal purpose vocabulary');
  await denied(db.query(`INSERT INTO foundation.legal_documents(id,purpose,kind)
    VALUES($1,'REQUEST_PROCESSING','TERMS')`, [randomUUID()]), '23514', 'legal kind vocabulary');
  await denied(db.query(`INSERT INTO foundation.legal_documents(id,purpose,kind)
    VALUES($1,'REQUEST_PROCESSING','CONSENT_FORM')`, [randomUUID()]), '23505', 'duplicate purpose+kind');
  await db.query(`INSERT INTO foundation.legal_documents(id,purpose,kind)
    VALUES($1,'ADDRESS_COVERAGE','CONSENT_FORM')`, [randomUUID()]);
  const insertLegalVersion = (id, documentId, purpose, kind, version, body, extra = {}) => db.query(`INSERT INTO foundation.legal_document_versions
    (id,document_id,purpose,kind,version,title,body,checksum,legal_basis,source_ref,reviewed_by)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
  [id, documentId, purpose, kind, version, extra.title ?? 'Synthetic legal title', body,
    extra.checksum ?? sha256(body), extra.basis ?? 'SYNTHETIC_LEGAL_BASIS',
    extra.source ?? 'review://synthetic/legal', staff]);
  const consentV1 = randomUUID(), consentV2 = randomUUID(), policyV1 = randomUUID();
  const bodyV1 = 'Synthetic consent text v1';
  const bodyV2 = 'Synthetic consent text v2';
  await insertLegalVersion(consentV1, consentDoc, 'REQUEST_PROCESSING', 'CONSENT_FORM', 1, bodyV1);
  await insertLegalVersion(consentV2, consentDoc, 'REQUEST_PROCESSING', 'CONSENT_FORM', 2, bodyV2);
  await insertLegalVersion(policyV1, policyDoc, 'REQUEST_PROCESSING', 'POLICY', 1, 'Synthetic policy text');
  // The database itself verifies the SHA-256 of the exact UTF-8 body.
  await denied(insertLegalVersion(randomUUID(), consentDoc, 'REQUEST_PROCESSING', 'CONSENT_FORM', 3, bodyV2,
    { checksum: 'a'.repeat(64) }), '23514', 'wrong checksum');
  await denied(insertLegalVersion(randomUUID(), consentDoc, 'REQUEST_PROCESSING', 'CONSENT_FORM', 3, bodyV2,
    { checksum: sha256(bodyV2).toUpperCase() }), '23514', 'checksum case');
  await denied(insertLegalVersion(randomUUID(), consentDoc, 'REQUEST_PROCESSING', 'CONSENT_FORM', 3, bodyV2,
    { checksum: sha256(`${bodyV2} `) }), '23514', 'checksum of another body');
  // Purpose/kind of a version must match its document.
  await denied(insertLegalVersion(randomUUID(), consentDoc, 'MARKETING', 'CONSENT_FORM', 3, bodyV2), '23503',
    'version purpose mismatch');
  await denied(insertLegalVersion(randomUUID(), consentDoc, 'REQUEST_PROCESSING', 'POLICY', 3, bodyV2), '23503',
    'version kind mismatch');
  await denied(insertLegalVersion(randomUUID(), randomUUID(), 'REQUEST_PROCESSING', 'CONSENT_FORM', 1, bodyV1), '23503');
  await denied(insertLegalVersion(randomUUID(), consentDoc, 'REQUEST_PROCESSING', 'CONSENT_FORM', 1, bodyV1), '23505');
  await denied(insertLegalVersion(randomUUID(), consentDoc, 'REQUEST_PROCESSING', 'CONSENT_FORM', 0, bodyV1), '23514');
  for (const extra of [{ title: ' ' }, { basis: '\t' }, { source: ' ' }]) {
    await denied(insertLegalVersion(randomUUID(), consentDoc, 'REQUEST_PROCESSING', 'CONSENT_FORM', 4, bodyV2, extra), '23514');
  }
  await denied(insertLegalVersion(randomUUID(), consentDoc, 'REQUEST_PROCESSING', 'CONSENT_FORM', 4, ' '), '23514',
    'blank legal body');
  assert.equal((await db.query('UPDATE foundation.legal_documents SET current_version_id=$2 WHERE id=$1',
    [consentDoc, consentV2])).rowCount, 1);
  await denied(db.query('UPDATE foundation.legal_documents SET current_version_id=$2 WHERE id=$1',
    [consentDoc, policyV1]), '23503', 'pointer to another document version');
  await denied(db.query(`UPDATE foundation.legal_documents SET purpose='MARKETING' WHERE id=$1`, [consentDoc]), '23514');
  await denied(db.query(`UPDATE foundation.legal_document_versions SET body='changed' WHERE id=$1`, [consentV1]), '23514');
  await denied(db.query('DELETE FROM foundation.legal_document_versions'), '23514');
  await denied(db.query('DELETE FROM foundation.legal_documents'), '23514');
  await db.query('BEGIN');
  try { await deniedInTransaction(db, 'TRUNCATE foundation.legal_document_versions CASCADE', '23514'); }
  finally { await db.query('ROLLBACK'); }

  // ---- Request anchors: minimal, same-city, one-way revoke. ----
  // created_at is forced to the database clock by the guard, so a caller-supplied value is
  // ignored and an already-expired anchor cannot be created at all. The only way to reach
  // the "expired anchor" branch is a short-lived live anchor that really expires.
  const session = randomUUID(), revokedSession = randomUUID(), expiringSession = randomUUID();
  const insertSession = (id, cityId, cityVersionId, extra = {}) => db.query(`INSERT INTO foundation.request_sessions
    (id,secret_hash,intake_city_id,intake_city_version_id,expires_at)
    VALUES($1,$2,$3,$4,clock_timestamp()+$5::interval)`,
  [id, extra.hash ?? sha256(randomUUID()), cityId, cityVersionId, extra.lifetime ?? '1 day']);
  await insertSession(session, east.id, eastVersion.id);
  await insertSession(revokedSession, east.id, eastVersion.id);
  // A short-lived live anchor: created_at is database-stamped, so an anchor that is
  // already expired cannot even be inserted; the expired branch needs a real expiry.
  await insertSession(expiringSession, east.id, eastVersion.id, { lifetime: '250 milliseconds' });
  const stampedSession = (await db.query('SELECT created_at,revoked_at FROM foundation.request_sessions WHERE id=$1', [session])).rows[0];
  assert.ok(Math.abs(Date.now() - stampedSession.created_at.getTime()) < 60000,
    'created_at must be the database clock, not the caller value');
  assert.equal(stampedSession.revoked_at, null, 'a new anchor must be live');
  await denied(insertSession(randomUUID(), east.id, eastVersion.id, { hash: 'not-a-hash' }), '23514', 'secret hash format');
  // An anchor can never be created already expired: expires_at must follow the DB stamp.
  await denied(insertSession(randomUUID(), east.id, eastVersion.id,
    { lifetime: '-2 minutes' }), '23514', 'expiry must follow database-stamped creation');
  // A secret hash is one anchor's identity: a second anchor with the same hash is refused.
  const reusedHash = sha256('reused');
  await insertSession(randomUUID(), east.id, eastVersion.id, { hash: reusedHash });
  await denied(insertSession(randomUUID(), east.id, eastVersion.id, { hash: reusedHash }), '23505',
    'duplicate secret hash');
  await denied(insertSession(randomUUID(), east.id, westVersion.id), '23503', 'anchor version of another city');
  await denied(insertSession(randomUUID(), randomUUID(), eastVersion.id), '23503', 'anchor in an unknown city');
  await denied(db.query('UPDATE foundation.request_sessions SET expires_at=CURRENT_TIMESTAMP+INTERVAL \'1 day\' WHERE id=$1',
    [session]), '23514', 'anchor expiry is stable');
  await denied(db.query('UPDATE foundation.request_sessions SET secret_hash=$2 WHERE id=$1', [session, sha256('x')]), '23514');
  await denied(db.query('UPDATE foundation.request_sessions SET created_at=created_at WHERE id=$1', [session]), '23514');
  assert.equal((await db.query('UPDATE foundation.request_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE id=$1 RETURNING revoked_at',
    [revokedSession])).rows[0].revoked_at instanceof Date, true, 'revoke must be database-stamped');
  await denied(db.query('UPDATE foundation.request_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE id=$1', [revokedSession]),
    '23514', 'second revoke');
  await denied(db.query('UPDATE foundation.request_sessions SET revoked_at=NULL WHERE id=$1', [revokedSession]),
    '23514', 'un-revoke');
  await denied(db.query('DELETE FROM foundation.request_sessions'), '23514');
  await db.query('BEGIN');
  try { await deniedInTransaction(db, 'TRUNCATE foundation.request_sessions CASCADE', '23514'); }
  finally { await db.query('ROLLBACK'); }

  // ---- Consent evidence: purposes separate, stale text refused, revoke/replay exact. ----
  const marketingDoc = randomUUID();
  await db.query(`INSERT INTO foundation.legal_documents(id,purpose,kind) VALUES($1,'MARKETING','CONSENT_FORM')`,
    [marketingDoc]);
  const marketingV1 = randomUUID();
  await insertLegalVersion(marketingV1, marketingDoc, 'MARKETING', 'CONSENT_FORM', 1, 'Synthetic marketing text');
  await db.query('UPDATE foundation.legal_documents SET current_version_id=$2 WHERE id=$1', [marketingDoc, marketingV1]);
  const insertConsent = (extra = {}) => db.query(`INSERT INTO foundation.consent_records
    (id,session_id,document_id,document_version_id,purpose,action,legal_basis,source,evidence_ref,occurred_at,supersedes_id)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
  [extra.id ?? randomUUID(), extra.session ?? session, extra.document ?? consentDoc,
    extra.version ?? consentV2, extra.purpose ?? 'REQUEST_PROCESSING', extra.action ?? 'GIVEN',
    extra.basis ?? 'SYNTHETIC_LEGAL_BASIS', extra.source ?? 'FORM', extra.evidence ?? randomUUID(),
    extra.occurredAt ?? new Date('2000-01-01T00:00:00Z'), extra.supersedes ?? null]);
  const given = randomUUID();
  await insertConsent({ id: given, evidence: randomUUID() });
  const givenRow = (await db.query('SELECT occurred_at,purpose,action,source FROM foundation.consent_records WHERE id=$1',
    [given])).rows[0];
  assert.equal(givenRow.action, 'GIVEN');
  assert.equal(givenRow.source, 'FORM');
  assert.ok(Date.now() - givenRow.occurred_at.getTime() < 60000, 'occurred_at must be the database clock, not the caller value');
  // Stale text: the current pointer is v2, so a GIVEN of v1 is refused, not silently accepted.
  await denied(insertConsent({ version: consentV1, evidence: randomUUID() }), '23514', 'stale GIVEN text');
  await denied(insertConsent({ basis: 'OTHER_BASIS', evidence: randomUUID() }), '23514', 'forged legal basis');
  // A REVOKED event without a target is refused by the guard (it looks the GIVEN up before
  // the CHECK is reached), and a GIVEN must never carry supersedes.
  await denied(insertConsent({ action: 'REVOKED', evidence: randomUUID() }), '23503',
    'REVOKED without a referenced GIVEN event');
  // GIVEN must not carry supersedes. This is a CHECK, so the probe needs an anchor with no
  // active GIVEN (otherwise the guard's duplicate rule fires first with 23505).
  const schemaSession = randomUUID();
  await insertSession(schemaSession, east.id, eastVersion.id);
  await denied(insertConsent({ session: schemaSession, action: 'GIVEN', supersedes: given,
    evidence: randomUUID() }), '23514', 'GIVEN must not supersede');
  await denied(insertConsent({ session: schemaSession, action: 'UNKNOWN', supersedes: given,
    evidence: randomUUID() }), '23514', 'consent action vocabulary');
  await denied(insertConsent({ session: schemaSession, source: 'API', evidence: randomUUID() }), '23514',
    'consent source vocabulary');
  await denied(insertConsent({ session: schemaSession, purpose: 'SERVICE', evidence: randomUUID() }), '23503',
    'unknown purpose cannot name a document version');
  await denied(insertConsent({ session: schemaSession, basis: ' ', evidence: randomUUID() }), '23514',
    'blank legal basis');
  // Purpose separation: a MARKETING document version cannot be used for REQUEST_PROCESSING.
  await denied(insertConsent({ document: marketingDoc, version: marketingV1, evidence: randomUUID() }), '23503',
    'cross-purpose document version');
  await denied(insertConsent({ document: policyDoc, version: policyV1, evidence: randomUUID() }), '23514',
    'consent on a POLICY document');
  // Purpose separation is proven on its own anchor: a MARKETING consent is a different
  // purpose and never counts as a REQUEST_PROCESSING consent for the same session.
  const marketingSession = randomUUID();
  await insertSession(marketingSession, east.id, eastVersion.id);
  const marketingGiven = randomUUID(), marketingEvidence = randomUUID();
  await insertConsent({ id: marketingGiven, session: marketingSession, document: marketingDoc,
    version: marketingV1, purpose: 'MARKETING', evidence: marketingEvidence });
  const activeGivens = async (sessionId) => (await db.query(`SELECT purpose, count(*)::int AS n
    FROM foundation.consent_records c
    WHERE c.session_id=$1 AND c.action='GIVEN'
      AND NOT EXISTS (SELECT FROM foundation.consent_records r WHERE r.supersedes_id=c.id)
    GROUP BY purpose ORDER BY purpose`, [sessionId])).rows;
  assert.deepEqual(await activeGivens(marketingSession), [{ purpose: 'MARKETING', n: 1 }],
    'A MARKETING consent must not create a REQUEST_PROCESSING consent');
  // Evidence replay is refused even across purposes of the same anchor, and the refused
  // attempt leaves no row behind (the guard passes first: no active GIVEN of that purpose).
  await denied(insertConsent({ session: marketingSession, evidence: marketingEvidence }), '23505',
    'replayed evidence reference across purposes');
  assert.deepEqual(await activeGivens(marketingSession), [{ purpose: 'MARKETING', n: 1 }],
    'A refused replay must not add a consent row');
  // One active GIVEN per session+purpose+document version.
  await denied(insertConsent({ evidence: randomUUID() }), '23505', 'duplicate active GIVEN');
  // Anchor liveness: revoked and expired anchors are refused for both actions.
  await denied(insertConsent({ session: revokedSession, evidence: randomUUID() }), '23514', 'revoked anchor');
  // Wait for the short-lived anchor to really expire, then both actions are refused.
  await new Promise((resolve) => { setTimeout(resolve, 400); });
  await denied(insertConsent({ session: expiringSession, evidence: randomUUID() }), '23514', 'expired anchor');
  await denied(insertConsent({ session: randomUUID(), evidence: randomUUID() }), '23503', 'unknown anchor');
  // REVOKED names the exact GIVEN and only that event; a replay cannot resurrect it.
  const revoke = randomUUID();
  await insertConsent({ id: revoke, action: 'REVOKED', supersedes: given, evidence: randomUUID() });
  assert.equal((await db.query('SELECT count(*)::int AS n FROM foundation.consent_records WHERE action=\'REVOKED\' AND supersedes_id=$1',
    [given])).rows[0].n, 1);
  await denied(insertConsent({ action: 'REVOKED', supersedes: given, evidence: randomUUID() }), '23505',
    'second revoke of the same GIVEN');
  await denied(insertConsent({ action: 'REVOKED', supersedes: revoke, evidence: randomUUID() }), '23514',
    'REVOKED of a REVOKED event');
  await denied(insertConsent({ action: 'REVOKED', supersedes: randomUUID(), evidence: randomUUID() }), '23503',
    'REVOKED of an unknown event');
  await denied(insertConsent({ action: 'REVOKED', supersedes: given, session: revokedSession, evidence: randomUUID() }),
    '23514', 'REVOKED of another session GIVEN');
  await denied(insertConsent({ action: 'REVOKED', supersedes: given, document: marketingDoc,
    version: marketingV1, purpose: 'MARKETING', evidence: randomUUID() }), '23514', 'REVOKED of another document GIVEN');
  // A replay of the original GIVEN after revocation is still refused: no resurrection, no stale text.
  await denied(insertConsent({ id: given, evidence: randomUUID() }), '23505', 'primary key replay');
  await denied(insertConsent({ version: consentV1, evidence: randomUUID() }), '23514', 'stale text after revoke');
  // A genuine re-GIVEN of the *same* current version is a new event, not a resurrection:
  // the revoked event stays revoked and history keeps both GIVENs plus the REVOKED.
  const reGiven = randomUUID();
  await insertConsent({ id: reGiven, evidence: randomUUID() });
  const cycle = (await db.query(`SELECT id,action,supersedes_id FROM foundation.consent_records
    WHERE session_id=$1 AND purpose='REQUEST_PROCESSING' AND document_id=$2 ORDER BY occurred_at,id`,
  [session, consentDoc])).rows;
  assert.deepEqual(cycle.map((row) => row.action), ['GIVEN', 'REVOKED', 'GIVEN'], 'GIVEN→REVOKED→GIVEN history');
  assert.equal(cycle[0].id, given);
  assert.equal(cycle[1].supersedes_id, given);
  assert.equal(cycle[2].supersedes_id, null);
  assert.equal(cycle[2].id, reGiven);
  // The revoked event is untouched: the new GIVEN does not clear supersedes_id or rewrite history.
  assert.equal((await db.query('SELECT count(*)::int AS n FROM foundation.consent_records WHERE id=$1 AND action=\'REVOKED\' AND supersedes_id=$2',
    [revoke, given])).rows[0].n, 1, 're-GIVEN must not modify the old revoke event');
  // Exactly one active GIVEN remains for this session/purpose/document.
  assert.equal((await db.query(`SELECT count(*)::int AS n FROM foundation.consent_records c
    WHERE c.session_id=$1 AND c.purpose='REQUEST_PROCESSING' AND c.document_id=$2 AND c.action='GIVEN'
      AND NOT EXISTS (SELECT FROM foundation.consent_records r WHERE r.supersedes_id=c.id)`,
  [session, consentDoc])).rows[0].n, 1, 're-GIVEN must leave exactly one active GIVEN');
  // Marketing consent on the same anchor never satisfies request processing: the anchor's
  // only active consent is the re-GIVEN REQUEST_PROCESSING one, and the MARKETING purpose
  // stays separate.
  assert.deepEqual((await db.query(`SELECT purpose FROM foundation.consent_records c
    WHERE c.session_id=$1 AND c.action='GIVEN'
      AND NOT EXISTS (SELECT FROM foundation.consent_records r WHERE r.supersedes_id=c.id)
    ORDER BY purpose`, [session])).rows.map((row) => row.purpose), ['REQUEST_PROCESSING'],
  'A MARKETING consent must never be counted as a REQUEST_PROCESSING consent');
  // Append-only events, including TRUNCATE.
  await denied(db.query(`UPDATE foundation.consent_records SET action='GIVEN' WHERE id=$1`, [given]), '23514');
  await denied(db.query('DELETE FROM foundation.consent_records WHERE id=$1', [given]), '23514');
  await db.query('BEGIN');
  try { await deniedInTransaction(db, 'TRUNCATE foundation.consent_records', '23514'); }
  finally { await db.query('ROLLBACK'); }

  // ---- Acceptance-time expiry: the guard re-checks the anchor AFTER the document lock. ----
  // A waiting consent insert must not be accepted on a liveness proof taken before the
  // wait: hold the document row lock, let the anchor expire, then release the lock. The
  // blocked INSERT must fail with 23514 instead of storing a stale acceptance.
  {
    // Reuse the ADDRESS_COVERAGE consent form created above (purpose+kind is unique) and
    // append a fresh current version for this race probe.
    const raceDoc = (await db.query(`SELECT id FROM foundation.legal_documents
      WHERE purpose='ADDRESS_COVERAGE' AND kind='CONSENT_FORM'`)).rows[0].id;
    const raceVersion = randomUUID();
    await insertLegalVersion(raceVersion, raceDoc, 'ADDRESS_COVERAGE', 'CONSENT_FORM', 1,
      'Synthetic acceptance-time text');
    await db.query('UPDATE foundation.legal_documents SET current_version_id=$2 WHERE id=$1', [raceDoc, raceVersion]);
    const raceSession = randomUUID();
    // Short trusted expiry: the anchor is live at statement start and dead after the wait.
    await insertSession(raceSession, east.id, eastVersion.id, { lifetime: '1500 milliseconds' });
    const blocker = connection('fixlevelup_migrator', credentials().fixlevelup_migrator, identity.db);
    await blocker.connect();
    try {
      await blocker.query('BEGIN');
      await blocker.query('SELECT 1 FROM foundation.legal_documents WHERE id=$1 FOR UPDATE', [raceDoc]);
      const blocked = assert.rejects(db.query(`INSERT INTO foundation.consent_records
        (id,session_id,document_id,document_version_id,purpose,action,legal_basis,source,evidence_ref)
        VALUES($1,$2,$3,$4,'ADDRESS_COVERAGE','GIVEN','SYNTHETIC_LEGAL_BASIS','FORM',$5)`,
      [randomUUID(), raceSession, raceDoc, raceVersion, randomUUID()]),
      { code: '23514', message: 'Consent record anchor expired before the event was accepted' });
      // The INSERT can finish before COMMIT's response; observe rejection now and assert below.
      void blocked.catch(() => undefined);
      // Let the anchor expire while the insert waits on the document lock, then release it.
      await new Promise((resolve) => { setTimeout(resolve, 1800); });
      await blocker.query('COMMIT');
      await blocked;
    } finally { await blocker.query('ROLLBACK').catch(() => undefined); await blocker.end(); }
    assert.equal((await db.query('SELECT count(*)::int AS n FROM foundation.consent_records WHERE session_id=$1',
      [raceSession])).rows[0].n, 0, 'the expired-at-acceptance consent must not be stored');
    // Positive control: the same flow without a blocker accepts the event and stamps the
    // database acceptance time, not the caller value.
    const liveSession = randomUUID();
    await insertSession(liveSession, east.id, eastVersion.id);
    const acceptedId = randomUUID();
    await db.query(`INSERT INTO foundation.consent_records
      (id,session_id,document_id,document_version_id,purpose,action,legal_basis,source,evidence_ref,occurred_at)
      VALUES($1,$2,$3,$4,'ADDRESS_COVERAGE','GIVEN','SYNTHETIC_LEGAL_BASIS','FORM',$5,$6)`,
    [acceptedId, liveSession, raceDoc, raceVersion, randomUUID(), new Date('2000-01-01T00:00:00Z')]);
    const accepted = (await db.query('SELECT occurred_at FROM foundation.consent_records WHERE id=$1', [acceptedId])).rows[0];
    assert.ok(Math.abs(Date.now() - accepted.occurred_at.getTime()) < 60000,
      'occurred_at must be the database acceptance clock, not the caller value');
  }

  // ---- Replay: no new rows, no changed history, no drift. ----
  const afterProof = await snapshotOf(db, settingsTables);
  // The proof appends its own reviewed settings revision, so the pre-013 rows are compared
  // by id: a replay must not touch them even though the table legitimately grew.
  const settingsIds = (await db.query('SELECT id FROM foundation.business_settings_versions ORDER BY id')).rows.map((row) => row.id);
  const settingsRowsById = () => db.query(`SELECT id,version,launch_mode,primary_city_id,reviewed_by,published_at
    FROM foundation.business_settings_versions WHERE id=ANY($1::uuid[]) ORDER BY id`, [settingsIds]);
  const preservedReplayTables = preservedTables.filter((table) => table !== 'business_settings_versions');
  const preservedReplayColumns = Object.fromEntries(Object.entries(preservedColumns)
    .filter(([table]) => table !== 'business_settings_versions'));
  const preservedReplayBefore = await snapshotOf(db, preservedReplayTables, preservedReplayColumns);
  const settingsBeforeReplay = await settingsRowsById();
  const historyBeforeReplay = await db.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name');
  deploy();
  assert.deepEqual((await db.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name')).rows,
    historyBeforeReplay.rows, '013 replay changed migration history');
  assert.deepEqual(await snapshotOf(db, settingsTables), afterProof, '013 replay changed settings/legal data');
  assert.deepEqual(await snapshotOf(db, preservedReplayTables, preservedReplayColumns), preservedReplayBefore,
    '013 replay changed populated 010-012 data');
  assert.deepEqual((await settingsRowsById()).rows, settingsBeforeReplay.rows,
    '013 replay changed the pre-existing reviewed settings revisions');
  diff(0);
  await db.query('ALTER TABLE foundation.consent_records ADD COLUMN p0303_drift_probe integer');
  diff(2);
  await db.query('ALTER TABLE foundation.consent_records DROP COLUMN p0303_drift_probe');
  diff(0);
  // The runtime ACL of this upgraded database matches the final-fresh proof.
  const runtime = connection('fixlevelup_runtime', credentials().fixlevelup_runtime, identity.db);
  await runtime.connect();
  try {
    await proveSettingsGrants(runtime);
    await proveSettingsRuntimeDenials(runtime);
  } finally { await runtime.end(); }
  console.log('012 → settings/legal references: additive provenance, no seed, typed references, immutable '
    + 'snapshots, same-city callback window, checksum, anchor/consent rules, replay and drift: PASS');
}
