import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { connection, credentials } from './migration-local.mjs';
import { proveSettingsGrants } from './test-settings-migration.mjs';

// 014 CHECK inventory, deliberately independent of the DDL text: a dropped, renamed or
// unvalidated guard must fail this proof. Every name below is expected to exist as a
// validated `contype='c'` constraint on the final database. It is a hard list, not a
// count, so a renamed CHECK is a failure even when the total stays 17.
export const fileReservationChecks = [
  'file_upload_intents_owner_xor_check',
  'file_upload_intents_owner_basis_check',
  'file_upload_intents_state_check',
  'file_upload_intents_state_stamp_check',
  'file_upload_intents_row_version_check',
  'file_upload_intents_policy_sha256_check',
  'file_upload_intents_body_sha256_check',
  'file_upload_intents_policy_source_ref_check',
  'file_upload_intents_mime_allowlist_check',
  'file_upload_intents_declared_mime_check',
  'file_upload_intents_declared_mime_allowed_check',
  'file_upload_intents_size_check',
  'file_upload_intents_safe_integer_check',
  'file_upload_intents_max_owner_files_check',
  'file_upload_intents_expiry_check',
  'file_upload_intents_policy_expiry_check',
  'file_upload_intents_expires_policy_check',
];

const reservationTable = 'file_upload_intents';
// 014 is additive on the existing chain: every one of these tables must keep its exact
// rows and its exact column/constraint inventory. No column, constraint or grant of an
// existing table changes; the only delta on an existing table is one index on
// consent_records, which carries no ACL.
const preservedTables = ['service_cities', 'service_city_versions', 'business_settings_versions',
  'administrative_districts', 'service_areas', 'service_area_versions', 'service_area_district_coverage',
  'staff_admin_city_assignments', 'technician_city_memberships', 'technician_service_areas',
  'geography_bootstrap_permissions', 'geography_command_receipts',
  'reference_entries', 'reference_entry_versions', 'content_blocks', 'content_block_revisions',
  'legal_documents', 'legal_document_versions', 'request_sessions', 'consent_records',
  'staff', 'roles', 'permissions', 'role_permissions', 'staff_role_assignments', 'audit_logs', 'outbox_events'];
const reservationFunctions = ['file_upload_intents_guard', 'file_upload_intents_reject_truncate'];
const reservationTriggers = [
  ['file_upload_intents', 'file_upload_intents_guard', 'file_upload_intents_guard'],
  ['file_upload_intents', 'file_upload_intents_reject_truncate', 'file_upload_intents_reject_truncate'],
];

const sha256 = (text) => createHash('sha256').update(text, 'utf8').digest('hex');
const hex = () => createHash('sha256').update(randomUUID(), 'utf8').digest('hex');

async function denied(query, sqlState, constraint, label) {
  await assert.rejects(query, (error) => error.code === sqlState && (constraint === undefined || error.constraint === constraint),
    (error) => `Expected SQLSTATE ${sqlState}${constraint ? ` (${constraint})` : ''}${label ? `: ${label}` : ''} `
      + `but got ${String(error.code)}${error.constraint ? ` (${String(error.constraint)})` : ''}: ${String(error.message)}`);
}
// A few probes can be refused by either of two equivalent named guards (for example a
// declared MIME outside the closed vocabulary also falls outside the policy allowlist).
// The proof still demands one of the exact expected names, never just any 23514.
async function deniedAny(query, sqlState, constraints, label) {
  await assert.rejects(query, (error) => error.code === sqlState && constraints.includes(error.constraint),
    (error) => `Expected SQLSTATE ${sqlState} (${constraints.join('|')})${label ? `: ${label}` : ''} `
      + `but got ${String(error.code)}${error.constraint ? ` (${String(error.constraint)})` : ''}: ${String(error.message)}`);
}
// Several expected failures inside one transaction need a savepoint each: without one the
// first error aborts the transaction and every later statement would report 25P02.
async function deniedInTransaction(client, sql, values, sqlState, constraint, label) {
  await client.query('SAVEPOINT proof');
  try {
    await denied(client.query(sql, values), sqlState, constraint, label);
  } finally {
    await client.query('ROLLBACK TO SAVEPOINT proof');
    await client.query('RELEASE SAVEPOINT proof');
  }
}
const snapshotOf = async (db, tables) => {
  const rows = [];
  for (const table of tables) {
    rows.push((await db.query(`SELECT * FROM foundation.${table} ORDER BY 1`)).rows);
  }
  return rows;
};
// The exact column and constraint inventory of every existing table, so "014 changed no
// existing column/constraint" is proven from the catalog instead of from the DDL text.
const inventoryOf = async (db) => {
  const columns = (await db.query(`SELECT c.relname AS table, a.attname AS column, format_type(a.atttypid,a.atttypmod) AS type,
      a.attnotnull AS not_null
    FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='foundation' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
    ORDER BY c.relname, a.attnum`)).rows;
  const constraints = (await db.query(`SELECT c.relname AS table, k.conname AS name, k.contype AS kind,
      k.convalidated AS validated, pg_get_constraintdef(k.oid) AS definition
    FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='foundation' ORDER BY c.relname, k.conname`)).rows;
  return { columns, constraints };
};
const tablesOf = (inventory) => [...new Set(inventory.columns.map((row) => row.table))].sort();

// ---------------------------------------------------------------- insert fixtures ----
// Every value is an explicit synthetic fixture. There is no default policy, TTL or quota
// anywhere: the numbers below are test data, not production configuration.
const OWNER_INSERT = `INSERT INTO foundation.file_upload_intents
  (id,owner_request_session_id,owner_staff_id,consent_record_id,consent_document_version_id,consent_purpose,
   policy_version_id,policy_source_ref,policy_sha256,allowed_mime_types,max_file_bytes,max_owner_bytes,max_owner_files,
   policy_expires_at,declared_mime,declared_bytes,expires_at,idempotency_key,body_sha256,state,cancelled_at,row_version,created_at)
  VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`;
// The runtime holds exactly these 18 INSERT columns; created_at/state/cancelled_at/
// row_version are database-owned and owner_staff_id is not insertable by the runtime.
const RUNTIME_INSERT = `INSERT INTO foundation.file_upload_intents
  (id,owner_request_session_id,consent_record_id,consent_document_version_id,consent_purpose,policy_version_id,
   policy_source_ref,policy_sha256,allowed_mime_types,max_file_bytes,max_owner_bytes,max_owner_files,
   policy_expires_at,declared_mime,declared_bytes,expires_at,idempotency_key,body_sha256)
  VALUES ($1,$2,$3,$4,'REQUEST_PROCESSING',$5,$6,$7,$8::jsonb,$9,$10,$11,$12,$13,$14,$15,$16,$17)`;

function intentValues(overrides = {}) {
  const now = Date.now();
  return {
    id: randomUUID(), ownerSession: null, ownerStaff: null, consentRecord: null, consentVersion: null,
    consentPurpose: null, policyVersionId: randomUUID(), policySourceRef: 'synthetic://upload-policy/p0304a',
    policySha256: 'a'.repeat(64), allowedMime: ['image/jpeg'], maxFileBytes: 400, maxOwnerBytes: 1000,
    maxOwnerFiles: 3, policyExpiresAt: new Date(now + 3_600_000), declaredMime: 'image/jpeg', declaredBytes: 100,
    expiresAt: new Date(now + 600_000), idempotencyKey: randomUUID(), bodySha256: 'b'.repeat(64),
    state: null, cancelledAt: null, rowVersion: null, createdAt: new Date(),
    ...overrides,
  };
}
const ownerParams = (value) => [value.id, value.ownerSession, value.ownerStaff, value.consentRecord,
  value.consentVersion, value.consentPurpose, value.policyVersionId, value.policySourceRef, value.policySha256,
  JSON.stringify(value.allowedMime), value.maxFileBytes, value.maxOwnerBytes, value.maxOwnerFiles,
  value.policyExpiresAt, value.declaredMime, value.declaredBytes, value.expiresAt, value.idempotencyKey,
  value.bodySha256, value.state, value.cancelledAt, value.rowVersion, value.createdAt];

const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

async function newSession(db, city, expiresInMs = 3_600_000) {
  const id = randomUUID();
  await db.query(`INSERT INTO foundation.request_sessions(id,secret_hash,intake_city_id,intake_city_version_id,expires_at)
    VALUES($1,$2,$3,$4,$5)`, [id, hex(), city.cityId, city.cityVersionId, new Date(Date.now() + expiresInMs)]);
  return id;
}
async function newGiven(db, sessionId, document) {
  const id = randomUUID();
  await db.query(`INSERT INTO foundation.consent_records
    (id,session_id,document_id,document_version_id,purpose,action,legal_basis,source,evidence_ref)
    VALUES($1,$2,$3,$4,'REQUEST_PROCESSING','GIVEN',$5,'FORM',$6)`,
  [id, sessionId, document.documentId, document.versionId, document.basis, randomUUID()]);
  return id;
}
async function revokeGiven(db, sessionId, document, givenId) {
  await db.query(`INSERT INTO foundation.consent_records
    (id,session_id,document_id,document_version_id,purpose,action,legal_basis,source,evidence_ref,supersedes_id)
    VALUES($1,$2,$3,$4,'REQUEST_PROCESSING','REVOKED',$5,'FORM',$6,$7)`,
  [randomUUID(), sessionId, document.documentId, document.versionId, document.basis, randomUUID(), givenId]);
}
async function currentConsentForm(db) {
  const row = (await db.query(`SELECT d.id AS document_id,d.current_version_id AS version_id,v.version,v.legal_basis
    FROM foundation.legal_documents d
    JOIN foundation.legal_document_versions v ON v.id=d.current_version_id
    WHERE d.purpose='REQUEST_PROCESSING' AND d.kind='CONSENT_FORM'`)).rows[0];
  assert.ok(row, 'Expected the reviewed synthetic REQUEST_PROCESSING consent form from the 013 proof');
  return { documentId: row.document_id, versionId: row.version_id, version: row.version, basis: row.legal_basis };
}

// ------------------------------------------------------------- runtime fixtures ----
// Resolves the synthetic reviewed city and current REQUEST_PROCESSING consent form the
// runtime ACL proof needs. Both already exist on the populated 013 database.
export async function currentFileReservationFixtures(db) {
  const city = (await db.query(`SELECT c.id AS city_id,c.current_version_id AS version_id
    FROM foundation.service_cities c WHERE c.current_version_id IS NOT NULL ORDER BY c.code LIMIT 1`)).rows[0];
  assert.ok(city, 'Expected a reviewed synthetic city from the previous proofs');
  const document = (await db.query(`SELECT d.id AS document_id,d.current_version_id AS version_id,v.legal_basis
    FROM foundation.legal_documents d JOIN foundation.legal_document_versions v ON v.id=d.current_version_id
    WHERE d.purpose='REQUEST_PROCESSING' AND d.kind='CONSENT_FORM'`)).rows[0];
  assert.ok(document, 'Expected the reviewed synthetic REQUEST_PROCESSING consent form');
  return { cityId: city.city_id, cityVersionId: city.version_id,
    documentId: document.document_id, versionId: document.version_id, legalBasis: document.legal_basis };
}

// Creates one synthetic city/version and one synthetic consent form/version on the fresh
// database, so the runtime ACL proof has real reviewed parents to reference. Written by
// the migration owner (never by the runtime under test).
export async function seedFileReservationFixtures(db, reviewer) {
  const cityId = randomUUID(), cityVersionId = randomUUID();
  const hours = JSON.stringify(Array.from({ length: 7 }, () => [[540, 1080]]));
  await db.query("INSERT INTO foundation.service_cities(id,code,lifecycle) VALUES($1,$2,'DRAFT')",
    [cityId, `files-${cityId.slice(0, 8)}`]);
  await db.query(`INSERT INTO foundation.service_city_versions
    (id,city_id,version,display_name,timezone,public_contact,office_hours,reviewed_by)
    VALUES($1,$2,1,'Synthetic reservation city','Europe/Moscow','+70000000000',$3::jsonb,$4)`,
  [cityVersionId, cityId, hours, reviewer]);
  await db.query('UPDATE foundation.service_cities SET current_version_id=$2 WHERE id=$1', [cityId, cityVersionId]);
  const documentId = randomUUID(), versionId = randomUUID();
  const body = `Synthetic p0304a runtime consent ${randomUUID()}`;
  await db.query("INSERT INTO foundation.legal_documents(id,purpose,kind) VALUES($1,'REQUEST_PROCESSING','CONSENT_FORM')",
    [documentId]);
  await db.query(`INSERT INTO foundation.legal_document_versions
    (id,document_id,purpose,kind,version,title,body,checksum,legal_basis,source_ref,reviewed_by)
    VALUES($1,$2,'REQUEST_PROCESSING','CONSENT_FORM',1,'Synthetic runtime consent',$3,$4,'Synthetic p0304a basis','synthetic://p0304a/runtime',$5)`,
  [versionId, documentId, body, sha256(body), reviewer]);
  await db.query('UPDATE foundation.legal_documents SET current_version_id=$2 WHERE id=$1', [documentId, versionId]);
  return { cityId, cityVersionId, documentId, versionId, legalBasis: 'Synthetic p0304a basis' };
}

// ------------------------------------------------------------- runtime ACL proof ----
// Exact runtime ACL of 014 on the final fresh database. A missing, extra or table-level
// privilege fails here, and proveSettingsGrants re-proves that 013's ACL (including
// consent_records) is byte-for-byte unchanged: the new unique index carries no ACL.
export async function proveFileReservationsGrants(runtime, fixtures) {
  const acl = {
    [reservationTable]: {
      select: ['id', 'owner_request_session_id', 'owner_staff_id', 'consent_record_id', 'consent_document_version_id',
        'consent_purpose', 'policy_version_id', 'policy_source_ref', 'policy_sha256', 'allowed_mime_types',
        'max_file_bytes', 'max_owner_bytes', 'max_owner_files', 'policy_expires_at', 'declared_mime', 'declared_bytes',
        'expires_at', 'created_at', 'idempotency_key', 'body_sha256', 'state', 'cancelled_at', 'row_version'],
      insert: ['id', 'owner_request_session_id', 'consent_record_id', 'consent_document_version_id', 'consent_purpose',
        'policy_version_id', 'policy_source_ref', 'policy_sha256', 'allowed_mime_types', 'max_file_bytes',
        'max_owner_bytes', 'max_owner_files', 'policy_expires_at', 'declared_mime', 'declared_bytes', 'expires_at',
        'idempotency_key', 'body_sha256'],
      update: ['state'], delete: false,
    },
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
    const publicAcl = await runtime.query(`SELECT count(*)::int AS n FROM pg_class c
      CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) acl
      WHERE c.oid=$1::regclass AND acl.grantee=0`, [target]);
    assert.equal(publicAcl.rows[0].n, 0, `PUBLIC privilege on ${table}`);
    const publicColumnAcl = await runtime.query(`SELECT count(*)::int AS n FROM pg_attribute a
      CROSS JOIN LATERAL aclexplode(a.attacl) acl
      WHERE a.attrelid=$1::regclass AND a.attnum>0 AND NOT a.attisdropped AND acl.grantee=0`, [target]);
    assert.equal(publicColumnAcl.rows[0].n, 0, `PUBLIC column privilege on ${table}`);
  }
  // 014 adds no callable surface: both guards are SECURITY INVOKER, migrator-owned, fixed
  // search_path and unreachable by the runtime or PUBLIC.
  const executable = await runtime.query(`SELECT p.proname, pg_get_userbyid(p.proowner) AS owner, p.prosecdef, p.proconfig,
      has_function_privilege(current_user,p.oid,'EXECUTE') AS allowed,
      EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl
        WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE') AS public_execute
    FROM pg_proc p WHERE p.pronamespace='foundation'::regnamespace AND p.proname=ANY($1::text[])`,
  [reservationFunctions]);
  assert.equal(executable.rowCount, reservationFunctions.length, '014 guard functions missing');
  assert.equal(executable.rows.filter((row) => row.allowed).length, 0, 'Runtime must not execute a 014 guard');
  assert.equal(executable.rows.filter((row) => row.public_execute).length, 0, 'PUBLIC EXECUTE on a 014 guard');
  assert(executable.rows.every((row) => row.owner === 'fixlevelup_migrator' && row.prosecdef === false
    && row.proconfig?.includes('search_path=pg_catalog')), '014 guard ownership/security mismatch');
  // Every expected trigger exists, is enabled and is bound to its own function.
  const triggers = await runtime.query(`SELECT c.relname AS table, g.tgname AS name, g.tgenabled IN ('O','A') AS enabled,
      p.proname AS fn
    FROM pg_trigger g JOIN pg_class c ON c.oid=g.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_proc p ON p.oid=g.tgfoid
    WHERE n.nspname='foundation' AND c.relname=$1 AND NOT g.tgisinternal
    ORDER BY g.tgname`, [reservationTable]);
  assert.equal(triggers.rowCount, reservationTriggers.length, '014 trigger count mismatch');
  for (const [table, trigger, fn] of reservationTriggers) {
    const found = triggers.rows.find((row) => row.table === table && row.name === trigger);
    assert.ok(found, `Missing 014 trigger ${table}.${trigger}`);
    assert.equal(found.enabled, true, `Disabled 014 trigger ${table}.${trigger}`);
    assert.equal(found.fn, fn, `014 trigger ${table}.${trigger} bound to the wrong function`);
  }
  // Exact index shape: the consent-basis FK target includes `id` (so the legitimate
  // GIVEN→REVOKED→GIVEN cycle cannot collide) and the two partial owner+key indexes.
  const indexes = await runtime.query(`SELECT i.relname AS name, x.indisunique AS unique, x.indisvalid AS valid,
      pg_get_indexdef(x.indexrelid) AS definition
    FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid JOIN pg_class t ON t.oid=x.indrelid
    JOIN pg_namespace n ON n.oid=t.relnamespace
    WHERE n.nspname='foundation' AND t.relname=ANY($1::text[]) ORDER BY i.relname`,
  [[reservationTable, 'consent_records']]);
  const findIndex = (name) => indexes.rows.find((row) => row.name === name);
  const basis = findIndex('consent_records_intent_basis_key');
  assert.ok(basis?.unique && basis.valid && basis.definition.includes('(id, session_id, document_version_id, purpose)'),
    '014 consent-basis unique index mismatch');
  const sessionKey = findIndex('file_upload_intents_session_idempotency_key');
  assert.ok(sessionKey?.unique && sessionKey.valid
    && sessionKey.definition.includes('(owner_request_session_id, idempotency_key)')
    && sessionKey.definition.includes('WHERE (owner_request_session_id IS NOT NULL)'),
  '014 session idempotency index mismatch');
  const staffKey = findIndex('file_upload_intents_staff_idempotency_key');
  assert.ok(staffKey?.unique && staffKey.valid
    && staffKey.definition.includes('(owner_staff_id, idempotency_key)')
    && staffKey.definition.includes('WHERE (owner_staff_id IS NOT NULL)'),
  '014 staff idempotency index mismatch');
  const pending = findIndex('file_upload_intents_session_pending_idx');
  assert.ok(pending?.valid && !pending.unique
    && pending.definition.includes('(owner_request_session_id, state, expires_at)'),
  '014 pending-quota index mismatch');

  // ---- The runtime really can reserve and cancel with exactly its granted columns. ----
  const sessionId = randomUUID();
  const givenId = randomUUID();
  const intentId = randomUUID();
  await runtime.query('BEGIN');
  try {
    await runtime.query(`INSERT INTO foundation.request_sessions(id,secret_hash,intake_city_id,intake_city_version_id,expires_at)
      VALUES($1,$2,$3,$4,CURRENT_TIMESTAMP+INTERVAL '1 hour')`,
    [sessionId, hex(), fixtures.cityId, fixtures.cityVersionId]);
    await runtime.query(`INSERT INTO foundation.consent_records
      (id,session_id,document_id,document_version_id,purpose,action,legal_basis,source,evidence_ref)
      VALUES($1,$2,$3,$4,'REQUEST_PROCESSING','GIVEN',$5,'FORM',$6)`,
    [givenId, sessionId, fixtures.documentId, fixtures.versionId, fixtures.legalBasis, randomUUID()]);
    await runtime.query(RUNTIME_INSERT, [intentId, sessionId, givenId, fixtures.versionId, randomUUID(),
      'synthetic://upload-policy/runtime', 'c'.repeat(64), JSON.stringify(['image/jpeg']), 400, 1000, 2,
      new Date(Date.now() + 3_600_000), 'image/jpeg', 120, new Date(Date.now() + 600_000), randomUUID(), 'd'.repeat(64)]);
    const stored = (await runtime.query(`SELECT state,row_version,cancelled_at,created_at,declared_bytes,consent_purpose
      FROM foundation.file_upload_intents WHERE id=$1`, [intentId])).rows[0];
    assert.equal(stored?.state, 'RESERVED');
    assert.equal(stored?.row_version, 1);
    assert.equal(stored?.cancelled_at, null);
    assert.equal(stored?.consent_purpose, 'REQUEST_PROCESSING');
    assert.ok(stored?.created_at instanceof Date, 'created_at must be database-stamped');
    const cancelled = (await runtime.query(`UPDATE foundation.file_upload_intents SET state='CANCELLED'
      WHERE id=$1 AND state='RESERVED' AND row_version=1 RETURNING state,row_version,cancelled_at`, [intentId])).rows[0];
    assert.equal(cancelled?.state, 'CANCELLED');
    assert.equal(cancelled?.row_version, 2, 'row_version must be database-owned OLD+1');
    assert.ok(cancelled?.cancelled_at instanceof Date, 'cancelled_at must be database-stamped');
    await runtime.query('COMMIT');
  } catch (error) { await runtime.query('ROLLBACK').catch(() => undefined); throw error; }

  // ---- The runtime cannot widen its own write surface. ----
  const denials = [
    `INSERT INTO foundation.file_upload_intents(id,owner_staff_id) VALUES(gen_random_uuid(),gen_random_uuid())`,
    `INSERT INTO foundation.file_upload_intents(id,created_at) VALUES(gen_random_uuid(),CURRENT_TIMESTAMP)`,
    `INSERT INTO foundation.file_upload_intents(id,state) VALUES(gen_random_uuid(),'RESERVED')`,
    `INSERT INTO foundation.file_upload_intents(id,cancelled_at) VALUES(gen_random_uuid(),CURRENT_TIMESTAMP)`,
    `INSERT INTO foundation.file_upload_intents(id,row_version) VALUES(gen_random_uuid(),1)`,
    `UPDATE foundation.file_upload_intents SET declared_bytes=declared_bytes`,
    `UPDATE foundation.file_upload_intents SET row_version=row_version`,
    `UPDATE foundation.file_upload_intents SET owner_request_session_id=owner_request_session_id`,
    `UPDATE foundation.file_upload_intents SET created_at=created_at`,
    'DELETE FROM foundation.file_upload_intents',
    'TRUNCATE foundation.file_upload_intents',
    'ALTER TABLE foundation.file_upload_intents ADD COLUMN forbidden integer',
    'CREATE TABLE foundation.forbidden_files(id integer)',
    'SELECT * FROM foundation._prisma_migrations',
    'SELECT foundation.file_upload_intents_guard()',
    'SELECT foundation.file_upload_intents_reject_truncate()',
  ];
  for (const sql of denials) { await denied(runtime.query(sql), '42501', undefined, sql); }
  // 013's exact ACL, including consent_records, must be untouched by 014.
  await proveSettingsGrants(runtime);
  console.log('014 runtime: exact column ACL, cancel-only UPDATE, no DELETE/TRUNCATE/DDL, '
    + 'no callable guard, 013 ACL unchanged: PASS');
}

// ------------------------------------------------------ populated 013 → 014 proof ----
// Runs on the populated 013 database from the settings proof: 014 is applied to real
// synthetic city/settings/legal/consent history, then every invariant is exercised with
// explicit expected SQLSTATEs. No test DDL in a working application database.
export async function proveFileReservationsUpgrade(db, deploy, diff) {
  const { rows: [identity] } = await db.query('SELECT current_database() AS db, current_user AS role');
  assert.match(identity.db, /^fixlevelup_p017a_upgrade_[a-f0-9]{12}$/);
  assert.equal(identity.role, 'fixlevelup_migrator');
  // 014 must not be applied before its own proof, and the capped chain must really end at 013.
  assert.equal((await db.query(`SELECT to_regclass('foundation.${reservationTable}') AS ref`)).rows[0].ref, null,
    '014 applied before its proof');
  assert.equal((await db.query("SELECT to_regclass('foundation.consent_records_intent_basis_key') AS ref")).rows[0].ref, null,
    '014 consent index applied before its proof');
  assert.equal((await db.query("SELECT count(*)::int AS n FROM pg_proc p WHERE p.pronamespace='foundation'::regnamespace AND p.proname=ANY($1::text[])",
    [reservationFunctions])).rows[0].n, 0, '014 guard functions applied before their proof');
  const historyBefore = await db.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name');
  assert.equal(historyBefore.rows.at(-1)?.migration_name, '20261121000400_settings_legal_references');

  const inventoryBefore = await inventoryOf(db);
  const tablesBefore = tablesOf(inventoryBefore);
  const preservedColumnsBefore = await db.query(`SELECT c.relname AS table, a.attname AS column, format_type(a.atttypid,a.atttypmod) AS type,
      a.attnotnull AS not_null
    FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='foundation' AND c.relkind='r' AND c.relname=ANY($1::text[]) AND a.attnum>0 AND NOT a.attisdropped
    ORDER BY c.relname, a.attnum`, [preservedTables]);
  const before = await snapshotOf(db, preservedTables);
  const consentConstraintsBefore = (await db.query(`SELECT k.conname AS name, k.contype AS kind, k.convalidated AS validated,
      pg_get_constraintdef(k.oid) AS definition
    FROM pg_constraint k WHERE k.conrelid='foundation.consent_records'::regclass ORDER BY k.conname`)).rows;

  deploy();
  const historyAfter = await db.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name');
  assert.equal(historyAfter.rows.at(-1)?.migration_name, '20261121000500_file_upload_reservations');
  assert.equal(historyAfter.rows.at(-1)?.finished_at instanceof Date, true);
  assert.equal(historyAfter.rowCount, historyBefore.rowCount + 1, '014 must add exactly one history row');
  assert.deepEqual(historyAfter.rows.slice(0, -1), historyBefore.rows, '014 changed the existing migration history');
  // No backfill, no seed, no real value.
  assert.equal((await db.query(`SELECT count(*)::int AS n FROM foundation.${reservationTable}`)).rows[0].n, 0,
    '014 seeded a reservation intent');
  assert.deepEqual(await snapshotOf(db, preservedTables), before, '014 changed populated 013 data');
  // No existing column or constraint changed anywhere; only the one new index on
  // consent_records was added, and it carries no ACL.
  const inventoryAfter = await inventoryOf(db);
  assert.deepEqual(tablesOf(inventoryAfter), [...tablesBefore, reservationTable].sort(),
    '014 added or removed an unexpected table');
  assert.deepEqual(inventoryAfter.columns.filter((row) => row.table !== reservationTable),
    inventoryBefore.columns, '014 changed an existing column');
  assert.deepEqual(inventoryAfter.constraints.filter((row) => row.table !== reservationTable),
    inventoryBefore.constraints, '014 changed an existing constraint');
  assert.deepEqual((await db.query(`SELECT c.relname AS table, a.attname AS column, format_type(a.atttypid,a.atttypmod) AS type,
      a.attnotnull AS not_null
    FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='foundation' AND c.relkind='r' AND c.relname=ANY($1::text[]) AND a.attnum>0 AND NOT a.attisdropped
    ORDER BY c.relname, a.attnum`, [preservedTables])).rows, preservedColumnsBefore.rows,
  '014 changed the preserved 013 column list');
  assert.deepEqual((await db.query(`SELECT k.conname AS name, k.contype AS kind, k.convalidated AS validated,
      pg_get_constraintdef(k.oid) AS definition
    FROM pg_constraint k WHERE k.conrelid='foundation.consent_records'::regclass ORDER BY k.conname`)).rows,
  consentConstraintsBefore, '014 changed the 013 consent_records constraints');
  const basisIndex = (await db.query(`SELECT x.indisunique AS unique, x.indisvalid AS valid,
      pg_get_indexdef(x.indexrelid) AS definition
    FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid
    WHERE i.oid='foundation.consent_records_intent_basis_key'::regclass`)).rows[0];
  assert.ok(basisIndex?.unique && basisIndex.valid
    && basisIndex.definition.includes('(id, session_id, document_version_id, purpose)'),
  '014 consent-basis index missing or wrong');

  // ---- Fixture ids from the populated 013 history. ----
  const cityRow = (await db.query(`SELECT c.id AS city_id,cv.id AS version_id FROM foundation.service_cities c
    JOIN foundation.service_city_versions cv ON cv.id=c.current_version_id ORDER BY c.code LIMIT 1`)).rows[0];
  assert.ok(cityRow, 'Expected the populated 013 fixture city');
  // newSession() takes the {cityId,cityVersionId} shape used by the runtime fixtures.
  const city = { cityId: cityRow.city_id, cityVersionId: cityRow.version_id };
  const staff = (await db.query("SELECT id FROM foundation.staff WHERE role='ADMIN' ORDER BY id LIMIT 1")).rows[0]?.id;
  assert.ok(staff, 'Expected a synthetic reviewed staff member');
  let document = await currentConsentForm(db);
  const given = async (sessionId) => newGiven(db, sessionId, document);
  const insertIntent = (overrides) => db.query(OWNER_INSERT, ownerParams(intentValues(overrides)));
  const deniedIntent = (overrides, sqlState, constraint, label) => denied(insertIntent(overrides), sqlState, constraint, label);

  // ---- A valid F-owned reservation: database-owned stamps, RESERVED only. ----
  const session = await newSession(db, city);
  const evidence = await given(session);
  const valid = intentValues({ ownerSession: session, consentRecord: evidence, consentVersion: document.versionId,
    consentPurpose: 'REQUEST_PROCESSING' });
  await db.query(OWNER_INSERT, ownerParams(valid));
  const stored = (await db.query(`SELECT state,row_version,cancelled_at,created_at,declared_bytes,declared_mime,
      consent_purpose,policy_source_ref FROM foundation.${reservationTable} WHERE id=$1`, [valid.id])).rows[0];
  assert.equal(stored?.state, 'RESERVED');
  assert.equal(stored?.row_version, 1);
  assert.equal(stored?.cancelled_at, null);
  assert.equal(stored?.declared_bytes, '100');
  assert.equal(stored?.declared_mime, 'image/jpeg');
  assert.equal(stored?.consent_purpose, 'REQUEST_PROCESSING');
  assert.ok(stored?.created_at instanceof Date && Math.abs(Date.now() - stored.created_at.getTime()) < 60000,
    'created_at must be the database clock');

  // ---- A direct INSERT inside a non-READ-COMMITTED transaction is refused. ----
  const raceSession = await newSession(db, city);
  const raceEvidence = await given(raceSession);
  await db.query('BEGIN ISOLATION LEVEL REPEATABLE READ');
  try {
    await deniedIntent({ ownerSession: raceSession, consentRecord: raceEvidence, consentVersion: document.versionId,
      consentPurpose: 'REQUEST_PROCESSING' }, '25001', 'file_upload_intents_isolation',
    'direct INSERT under REPEATABLE READ');
  } finally { await db.query('ROLLBACK'); }
  assert.equal((await db.query(`SELECT count(*)::int AS n FROM foundation.${reservationTable} WHERE owner_request_session_id=$1`,
    [raceSession])).rows[0].n, 0, 'the refused REPEATABLE READ insert must not leave a row');

  // ---- Owner XOR and consent basis. ----
  // A row with no owner violates both the XOR and the basis CHECK; PostgreSQL reports
  // whichever it evaluates first, so either exact name is accepted (never a bare 23514).
  await deniedAny(insertIntent({}), '23514',
    ['file_upload_intents_owner_xor_check', 'file_upload_intents_owner_basis_check'], 'no owner');
  await deniedIntent({ ownerSession: session, ownerStaff: staff, consentRecord: evidence,
    consentVersion: document.versionId, consentPurpose: 'REQUEST_PROCESSING' },
  '23514', 'file_upload_intents_owner_xor_check', 'both owners');
  await deniedIntent({ ownerSession: session }, '23514', 'file_upload_intents_consent',
    'F-owned without a consent basis');
  await deniedIntent({ ownerSession: session, consentRecord: randomUUID(), consentVersion: document.versionId,
    consentPurpose: 'REQUEST_PROCESSING' }, '23503', 'file_upload_intents_consent_basis_fkey',
  'unknown consent evidence');
  await deniedIntent({ ownerSession: randomUUID(), consentRecord: evidence, consentVersion: document.versionId,
    consentPurpose: 'REQUEST_PROCESSING' }, '23503', 'file_upload_intents_owner_request_session_id_fkey',
  'unknown owner session');
  // Wrong-owner basis: another session's real GIVEN cannot authorize this owner. The
  // tuple mismatch is a reference violation (23503), not a policy/consent rule.
  const foreignSession = await newSession(db, city);
  const foreignEvidence = await given(foreignSession);
  await deniedIntent({ ownerSession: session, consentRecord: foreignEvidence, consentVersion: document.versionId,
    consentPurpose: 'REQUEST_PROCESSING' }, '23503', 'file_upload_intents_consent_basis_fkey',
  'consent evidence of another session');
  // A purpose outside the evidence tuple is the same reference mismatch.
  await deniedIntent({ ownerSession: session, consentRecord: evidence, consentVersion: document.versionId,
    consentPurpose: 'MARKETING' }, '23503', 'file_upload_intents_consent_basis_fkey', 'foreign consent purpose');

  // ---- Dead anchor: revoked and expired (database clock). ----
  const revokedSession = await newSession(db, city);
  const revokedEvidence = await given(revokedSession);
  await db.query('UPDATE foundation.request_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE id=$1', [revokedSession]);
  await deniedIntent({ ownerSession: revokedSession, consentRecord: revokedEvidence,
    consentVersion: document.versionId, consentPurpose: 'REQUEST_PROCESSING' }, '23514', 'file_upload_intents_session',
  'revoked anchor');
  const expiringSession = await newSession(db, city, 3_000);
  const expiringEvidence = await given(expiringSession);
  await sleep(3_600);
  await deniedIntent({ ownerSession: expiringSession, consentRecord: expiringEvidence,
    consentVersion: document.versionId, consentPurpose: 'REQUEST_PROCESSING' }, '23514', 'file_upload_intents_session',
  'expired anchor');

  // ---- Revoked GIVEN basis is refused; a re-GIVEN never revives the old evidence. ----
  const revokedBasisSession = await newSession(db, city);
  const revokedBasis = await given(revokedBasisSession);
  await revokeGiven(db, revokedBasisSession, document, revokedBasis);
  await deniedIntent({ ownerSession: revokedBasisSession, consentRecord: revokedBasis,
    consentVersion: document.versionId, consentPurpose: 'REQUEST_PROCESSING' }, '23514', 'file_upload_intents_consent',
  'revoked GIVEN basis');
  const reGiven = await given(revokedBasisSession);
  await deniedIntent({ ownerSession: revokedBasisSession, consentRecord: revokedBasis,
    consentVersion: document.versionId, consentPurpose: 'REQUEST_PROCESSING' }, '23514', 'file_upload_intents_consent',
  'revoked basis after a new GIVEN');
  const reGivenIntent = intentValues({ ownerSession: revokedBasisSession, consentRecord: reGiven,
    consentVersion: document.versionId, consentPurpose: 'REQUEST_PROCESSING' });
  await db.query(OWNER_INSERT, ownerParams(reGivenIntent));

  // ---- Stale document version: publishing a new current revision invalidates the old basis. ----
  const staleSession = await newSession(db, city);
  const staleEvidence = await given(staleSession);
  const nextBody = `Synthetic p0304a consent text v${document.version + 1} ${randomUUID()}`;
  const nextVersion = randomUUID();
  await db.query(`INSERT INTO foundation.legal_document_versions
    (id,document_id,purpose,kind,version,title,body,checksum,legal_basis,source_ref,reviewed_by)
    VALUES($1,$2,'REQUEST_PROCESSING','CONSENT_FORM',$3,'Synthetic consent revision',$4,$5,'Synthetic p0304a basis','synthetic://p0304a/consent',$6)`,
  [nextVersion, document.documentId, document.version + 1, nextBody, sha256(nextBody), staff]);
  await db.query('UPDATE foundation.legal_documents SET current_version_id=$2 WHERE id=$1', [document.documentId, nextVersion]);
  await deniedIntent({ ownerSession: staleSession, consentRecord: staleEvidence,
    consentVersion: document.versionId, consentPurpose: 'REQUEST_PROCESSING' }, '23514', 'file_upload_intents_consent',
  'stale consent document version');
  document = { documentId: document.documentId, versionId: nextVersion, version: document.version + 1,
    basis: 'Synthetic p0304a basis' };

  // ---- Policy snapshot, expiry and size guards (all before/inside the same guard). ----
  const policySession = await newSession(db, city);
  const policyEvidence = await given(policySession);
  const policyBasis = { ownerSession: policySession, consentRecord: policyEvidence,
    consentVersion: document.versionId, consentPurpose: 'REQUEST_PROCESSING' };
  await deniedIntent({ ...policyBasis, policyExpiresAt: new Date(Date.now() - 1000) },
    '23514', 'file_upload_intents_policy', 'expired policy snapshot');
  await deniedIntent({ ...policyBasis, expiresAt: new Date(Date.now() - 1000) },
    '23514', 'file_upload_intents_expiry', 'intent already expired');
  await deniedIntent({ ...policyBasis, expiresAt: new Date(Date.now() + 7_200_000) },
    '23514', 'file_upload_intents_policy', 'intent outlives its policy');
  await deniedIntent({ ...policyBasis, expiresAt: new Date(Date.now() + 4_000_000), policyExpiresAt: new Date(Date.now() + 3_600_000) },
    '23514', 'file_upload_intents_policy', 'intent outlives its policy ceiling');
  // A reservation may not outlive its session anchor (anchor is one hour, ask for two).
  await deniedIntent({ ...policyBasis, expiresAt: new Date(Date.now() + 2 * 3_600_000),
    policyExpiresAt: new Date(Date.now() + 3 * 3_600_000) }, '23514', 'file_upload_intents_policy',
  'intent outlives its request session anchor');
  await deniedAny(insertIntent({ ...policyBasis, declaredMime: 'image/gif' }), '23514',
    ['file_upload_intents_declared_mime_check', 'file_upload_intents_declared_mime_allowed_check'],
    'MIME outside the closed vocabulary');
  await deniedIntent({ ...policyBasis, allowedMime: ['application/pdf'] },
    '23514', 'file_upload_intents_declared_mime_allowed_check', 'declared MIME outside the policy allowlist');
  await deniedIntent({ ...policyBasis, allowedMime: ['image/jpeg', 'image/jpeg'] },
    '23514', 'file_upload_intents_policy', 'duplicated allowlist entry');
  await deniedIntent({ ...policyBasis, allowedMime: [1] },
    '23514', 'file_upload_intents_policy', 'non-string allowlist entry');
  await deniedAny(insertIntent({ ...policyBasis, allowedMime: [] }), '23514',
    ['file_upload_intents_mime_allowlist_check', 'file_upload_intents_declared_mime_allowed_check'],
    'empty allowlist');
  await deniedIntent({ ...policyBasis, declaredBytes: 0 }, '23514', 'file_upload_intents_size_check', 'zero bytes');
  await deniedIntent({ ...policyBasis, declaredBytes: 500 }, '23514', 'file_upload_intents_size_check',
    'file bytes above the per-file ceiling');
  await deniedIntent({ ...policyBasis, maxFileBytes: 900, maxOwnerBytes: 500 },
    '23514', 'file_upload_intents_size_check', 'per-file ceiling above the owner ceiling');
  await deniedIntent({ ...policyBasis, maxOwnerBytes: '9007199254740992' },
    '23514', 'file_upload_intents_safe_integer_check', 'quota above the safe-integer ceiling');
  // A zero file quota is refused by the quota guard before the CHECK is even reached.
  await deniedAny(insertIntent({ ...policyBasis, maxOwnerFiles: 0 }), '23514',
    ['file_upload_intents_quota', 'file_upload_intents_max_owner_files_check'], 'zero file quota');
  await deniedIntent({ ...policyBasis, policySha256: 'NOTAHASH' },
    '23514', 'file_upload_intents_policy_sha256_check', 'malformed policy hash');
  await deniedIntent({ ...policyBasis, bodySha256: 'NOTAHASH' },
    '23514', 'file_upload_intents_body_sha256_check', 'malformed body hash');
  await deniedIntent({ ...policyBasis, policySourceRef: ' \t' },
    '23514', 'file_upload_intents_policy_source_ref_check', 'blank policy source reference');
  // A caller cannot fabricate a READY row or a backdated/hand-versioned row: the guard
  // overwrites every database-owned stamp instead of trusting the caller.
  const fabricated = intentValues({ ...policyBasis, state: 'READY', cancelledAt: new Date(),
    rowVersion: 7, createdAt: new Date('2000-01-01T00:00:00Z') });
  await db.query(OWNER_INSERT, ownerParams(fabricated));
  const forced = (await db.query(`SELECT state,cancelled_at,row_version,created_at FROM foundation.${reservationTable}
    WHERE id=$1`, [fabricated.id])).rows[0];
  assert.equal(forced?.state, 'RESERVED', 'a caller-supplied state must be overwritten');
  assert.equal(forced?.cancelled_at, null, 'a caller-supplied cancel stamp must be discarded');
  assert.equal(forced?.row_version, 1, 'a caller-supplied row_version must be discarded');
  assert.ok(Math.abs(Date.now() - forced.created_at.getTime()) < 60000, 'a caller-supplied created_at must be discarded');

  // ---- Quota: file count, bytes, and release by expiry/cancel. ----
  const countSession = await newSession(db, city);
  const countEvidence = await given(countSession);
  const countBasis = { ownerSession: countSession, consentRecord: countEvidence,
    consentVersion: document.versionId, consentPurpose: 'REQUEST_PROCESSING', maxOwnerFiles: 1 };
  await db.query(OWNER_INSERT, ownerParams(intentValues(countBasis)));
  await deniedIntent({ ...countBasis, idempotencyKey: randomUUID(), declaredBytes: 50 },
    '23514', 'file_upload_intents_quota', 'file quota exceeded');
  const bytesSession = await newSession(db, city);
  const bytesEvidence = await given(bytesSession);
  const bytesBasis = { ownerSession: bytesSession, consentRecord: bytesEvidence,
    consentVersion: document.versionId, consentPurpose: 'REQUEST_PROCESSING',
    maxFileBytes: 200, maxOwnerBytes: 250, maxOwnerFiles: 5 };
  await db.query(OWNER_INSERT, ownerParams(intentValues({ ...bytesBasis, declaredBytes: 100 })));
  await db.query(OWNER_INSERT, ownerParams(intentValues({ ...bytesBasis, declaredBytes: 100, idempotencyKey: randomUUID() })));
  await deniedIntent({ ...bytesBasis, declaredBytes: 100, idempotencyKey: randomUUID() },
    '23514', 'file_upload_intents_quota', 'byte quota exceeded');
  // Pending quota only counts live RESERVED rows: an expired reservation frees its slot.
  const expiringQuotaSession = await newSession(db, city);
  const expiringQuotaEvidence = await given(expiringQuotaSession);
  const expiringQuotaBasis = { ownerSession: expiringQuotaSession, consentRecord: expiringQuotaEvidence,
    consentVersion: document.versionId, consentPurpose: 'REQUEST_PROCESSING', maxOwnerFiles: 1 };
  await db.query(OWNER_INSERT, ownerParams(intentValues({ ...expiringQuotaBasis, expiresAt: new Date(Date.now() + 1_500) })));
  await sleep(2_000);
  await db.query(OWNER_INSERT, ownerParams(intentValues({ ...expiringQuotaBasis, idempotencyKey: randomUUID() })));
  // A cancelled reservation releases its quota, and cancel is database-stamped one-way.
  const cancelSession = await newSession(db, city);
  const cancelEvidence = await given(cancelSession);
  const cancelBasis = { ownerSession: cancelSession, consentRecord: cancelEvidence,
    consentVersion: document.versionId, consentPurpose: 'REQUEST_PROCESSING', maxOwnerFiles: 1 };
  const cancelIntent = intentValues(cancelBasis);
  await db.query(OWNER_INSERT, ownerParams(cancelIntent));
  const cancelled = (await db.query(`UPDATE foundation.${reservationTable} SET state='CANCELLED',row_version=99
    WHERE id=$1 AND state='RESERVED' RETURNING state,row_version,cancelled_at`, [cancelIntent.id])).rows[0];
  assert.equal(cancelled?.state, 'CANCELLED');
  assert.equal(cancelled?.row_version, 2, 'cancel must stamp OLD+1 and ignore a caller row_version');
  assert.ok(cancelled?.cancelled_at instanceof Date, 'cancel must be database-stamped');
  await db.query(OWNER_INSERT, ownerParams(intentValues({ ...cancelBasis, idempotencyKey: randomUUID() })));
  // Concurrent guard: two backends try the last slot; the second waits on the session row
  // lock and is refused after the first commits.
  const raceOwner = await newSession(db, city);
  const raceOwnerEvidence = await given(raceOwner);
  const raceBasis = { ownerSession: raceOwner, consentRecord: raceOwnerEvidence,
    consentVersion: document.versionId, consentPurpose: 'REQUEST_PROCESSING', maxOwnerFiles: 1 };
  const first = connection('fixlevelup_migrator', credentials().fixlevelup_migrator, identity.db);
  const second = connection('fixlevelup_migrator', credentials().fixlevelup_migrator, identity.db);
  await first.connect();
  await second.connect();
  try {
    await first.query('BEGIN');
    await first.query(OWNER_INSERT, ownerParams(intentValues(raceBasis)));
    await second.query('BEGIN');
    const pending = second.query(OWNER_INSERT, ownerParams(intentValues({ ...raceBasis, idempotencyKey: randomUUID() })))
      .then(() => 'committed', (error) => error.code);
    await sleep(500);
    await first.query('COMMIT');
    assert.equal(await pending, '23514', 'the second concurrent reservation must be refused by the quota guard');
    await second.query('ROLLBACK');
  } finally {
    await first.query('ROLLBACK').catch(() => undefined);
    await second.query('ROLLBACK').catch(() => undefined);
    await first.end();
    await second.end();
  }
  assert.equal((await db.query(`SELECT count(*)::int AS n FROM foundation.${reservationTable} WHERE owner_request_session_id=$1`,
    [raceOwner])).rows[0].n, 1, 'exactly one concurrent reservation must be committed');

  // ---- One-way cancel, immutable fields, no DELETE/TRUNCATE. ----
  await denied(db.query(`UPDATE foundation.${reservationTable} SET state='READY' WHERE id=$1`, [valid.id]),
    '23514', 'file_upload_intents_state_transition', 'READY is not a 014 state');
  await denied(db.query(`UPDATE foundation.${reservationTable} SET state='CANCELLED',declared_bytes=999 WHERE id=$1`, [valid.id]),
    '23514', 'file_upload_intents_immutable', 'declared bytes are immutable');
  await denied(db.query(`UPDATE foundation.${reservationTable} SET state='CANCELLED',created_at=CURRENT_TIMESTAMP WHERE id=$1`, [valid.id]),
    '23514', 'file_upload_intents_immutable', 'created_at is immutable');
  await denied(db.query(`UPDATE foundation.${reservationTable} SET state='CANCELLED',consent_record_id=$2 WHERE id=$1`,
    [valid.id, reGiven]), '23514', 'file_upload_intents_immutable', 'consent basis is immutable');
  await db.query(`UPDATE foundation.${reservationTable} SET state='CANCELLED' WHERE id=$1`, [valid.id]);
  await denied(db.query(`UPDATE foundation.${reservationTable} SET state='CANCELLED' WHERE id=$1`, [valid.id]),
    '23514', 'file_upload_intents_state_transition', 'second cancel');
  await denied(db.query(`UPDATE foundation.${reservationTable} SET state='RESERVED' WHERE id=$1`, [valid.id]),
    '23514', 'file_upload_intents_state_transition', 'un-cancel');
  await denied(db.query(`DELETE FROM foundation.${reservationTable} WHERE id=$1`, [valid.id]),
    '23514', 'file_upload_intents_history', 'DELETE of a reservation intent');
  await db.query('BEGIN');
  try { await deniedInTransaction(db, `TRUNCATE foundation.${reservationTable}`, [], '23514', undefined, 'TRUNCATE'); }
  finally { await db.query('ROLLBACK'); }

  // ---- Idempotency uniqueness and the staff-owner shape. ----
  const keySession = await newSession(db, city);
  const keyEvidence = await given(keySession);
  const keyBasis = { ownerSession: keySession, consentRecord: keyEvidence,
    consentVersion: document.versionId, consentPurpose: 'REQUEST_PROCESSING' };
  const keyIntent = intentValues(keyBasis);
  await db.query(OWNER_INSERT, ownerParams(keyIntent));
  await denied(insertIntent({ ...keyBasis, idempotencyKey: keyIntent.idempotencyKey }),
    '23505', 'file_upload_intents_session_idempotency_key', 'duplicate owner+idempotency key');
  // The staff variant exists as schema shape only: the runtime cannot insert owner_staff_id
  // (proven in the ACL proof), and a staff row carries no request consent basis.
  const staffIntent = intentValues({ ownerStaff: staff, maxOwnerFiles: 1 });
  await db.query(OWNER_INSERT, ownerParams(staffIntent));
  await denied(insertIntent({ ownerStaff: staff, idempotencyKey: staffIntent.idempotencyKey }),
    '23505', 'file_upload_intents_staff_idempotency_key', 'duplicate staff idempotency key');
  await deniedIntent({ ownerStaff: randomUUID() }, '23503', 'file_upload_intents_owner_staff_id_fkey', 'unknown staff owner');
  await denied(insertIntent({ ownerStaff: staff, consentRecord: evidence, consentVersion: document.versionId,
    consentPurpose: 'REQUEST_PROCESSING' }), '23514', 'file_upload_intents_consent',
  'staff intent with a request consent basis');

  // ---- Replay and drift: no new rows, no changed history, no drift. ----
  const intentsAfterProof = (await db.query(`SELECT * FROM foundation.${reservationTable} ORDER BY id`)).rows;
  const preservedAfterProof = await snapshotOf(db, preservedTables);
  const historyBeforeReplay = await db.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name');
  deploy();
  assert.deepEqual((await db.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name')).rows,
    historyBeforeReplay.rows, '014 replay changed migration history');
  assert.deepEqual((await db.query(`SELECT * FROM foundation.${reservationTable} ORDER BY id`)).rows, intentsAfterProof,
    '014 replay changed reservation intents');
  assert.deepEqual(await snapshotOf(db, preservedTables), preservedAfterProof, '014 replay changed populated 013 data');
  diff(0);
  await db.query(`ALTER TABLE foundation.${reservationTable} ADD COLUMN p0304a_drift_probe integer`);
  diff(2);
  await db.query(`ALTER TABLE foundation.${reservationTable} DROP COLUMN p0304a_drift_probe`);
  diff(0);
  // Runtime ACL and denials on the upgraded database, then 013's exact ACL again.
  const runtime = connection('fixlevelup_runtime', credentials().fixlevelup_runtime, identity.db);
  await runtime.connect();
  try {
    // proveFileReservationsGrants also re-proves 013's exact ACL on this upgraded DB.
    await proveFileReservationsGrants(runtime, await currentFileReservationFixtures(db));
  } finally { await runtime.end(); }
  console.log('013 → 014 file upload reservations: additive consent-basis index, no seed, immutable '
    + 'owner/basis/policy snapshot, READ COMMITTED guard, live anchor/exact GIVEN/quota, one-way cancel, '
    + 'replay and drift: PASS');
  console.log('014 guard denials: isolation 25001, session/consent/policy/expiry/quota/immutable/state/history 23514, '
    + 'FK 23503, idempotency 23505: PASS');
}
