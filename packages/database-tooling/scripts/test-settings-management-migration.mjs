import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { connection } from './migration-local.mjs';
import { syntheticVerifier } from './test-rbac-migration.mjs';

// Independent of SQL/discovery and of the shared wire implementation.
const migration = '20261122000400_settings_management';
const receipts = 'foundation.p03_command_receipts';
const sources = 'foundation.p03_bootstrap_permissions';
export const settingsManagementCodes = [
  'settings.fullread', 'settings.manage', 'settings.readiness.read',
  'references.callbackinterval.read', 'references.callbackinterval.manage', 'references.paymentmethod.read', 'references.paymentmethod.manage',
  'references.cancelreason.read', 'references.cancelreason.manage', 'references.declinereason.read', 'references.declinereason.manage',
  'references.requestsource.read', 'references.requestsource.manage', 'content.read', 'content.manage', 'content.publish', 'legal.read', 'legal.manage',
].sort();
const codes = settingsManagementCodes;
const operations = ['companyPublish', 'referenceCreate', 'referencePublish', 'referenceArchive', 'contentCreate', 'contentPublish',
  'contentArchive', 'legalCreate', 'legalPublish', 'bootstrapRevoke'];
const publish = ['referencePublish', 'contentPublish', 'legalPublish'];
const receiptInputs = ['actor_id', 'operation', 'key', 'request_sha256', 'entity_id', 'entity_version', 'revision_id', 'revision_version'];
const sourceInputs = ['assignment_id', 'permission_code'];
const functions = ['issue_first_p03_permissions', 'p03_bootstrap_guard', 'p03_guard_role_grant', 'p03_history_immutable', 'p03_original_bootstrap_assignment'];
export const settingsManagementChecks = [
  'p03_bootstrap_permissions_code_check', 'p03_bootstrap_permissions_revoke_check', 'p03_bootstrap_permissions_row_version_check',
  'p03_command_receipts_operation_check', 'p03_command_receipts_request_sha256_check', 'p03_command_receipts_entity_version_check', 'p03_command_receipts_revision_check',
];
const rows = async (db, sql, args) => (await db.query(sql, args)).rows;
const one = async (db, sql, args) => (await rows(db, sql, args))[0];
const history = (db) => rows(db, 'SELECT * FROM foundation._prisma_migrations ORDER BY migration_name');
const rejects = (query, code, constraint) => assert.rejects(query, { code, ...(constraint ? { constraint } : {}) });
const issue = (db) => db.query('SELECT foundation.issue_first_p03_permissions()');
const sourceRows = (db) => rows(db, `SELECT * FROM ${sources} ORDER BY assignment_id,permission_code COLLATE "C"`);
const audit = (db) => rows(db, "SELECT details FROM foundation.audit_logs WHERE operation='P03_BOOTSTRAP_PERMISSIONS' ORDER BY id");
const geo = (db) => rows(db, 'SELECT * FROM foundation.geography_bootstrap_permissions ORDER BY assignment_id,permission_code');
const noRoleGrants = async (db) => assert.deepEqual(await rows(db,
  'SELECT * FROM foundation.role_permissions WHERE permission_code=ANY($1::text[])', [codes]), [], '018 must not populate shared role grants');
const quote = (value) => `"${value.replaceAll('"', '""')}"`;

async function isolated(db, role, kind = '(?:fresh|upgrade)') {
  const identity = await one(db, 'SELECT current_database() AS db,current_user AS role');
  assert.match(identity.db, new RegExp(`^fixlevelup_p017a_${kind}_[a-f0-9]{12}$`));
  assert.equal(identity.role, role);
  return identity.db;
}
async function foundationTables(db) {
  return (await rows(db, `SELECT relname FROM pg_class WHERE relnamespace='foundation'::regnamespace
    AND relkind='r' AND relname<>'_prisma_migrations' ORDER BY relname`)).map(({ relname }) => relname);
}
async function snapshot(db, tables, permittedAdds = false) {
  const result = {};
  for (const table of tables) {
    const [where, args] = permittedAdds && table === 'permissions' ? ['WHERE NOT (code=ANY($1::text[]))', [codes]]
      : permittedAdds && table === 'audit_logs' ? ["WHERE operation <> 'P03_BOOTSTRAP_PERMISSIONS'", []] : ['', []];
    result[table] = await rows(db, `SELECT to_jsonb(r)::text AS value FROM foundation.${quote(table)} r ${where} ORDER BY (to_jsonb(r)::text) COLLATE "C"`, args);
  }
  return result;
}
// Pin raw privilege identities, not just whether runtime still happens to have the same effective access.
async function aclSnapshot(db) {
  return {
    relations: await rows(db, `SELECT c.relname AS name,c.relkind,c.relowner,c.relacl::text FROM pg_class c
      WHERE c.relnamespace='foundation'::regnamespace AND c.relkind IN ('r','S','v','m','p') ORDER BY c.relname`),
    columns: await rows(db, `SELECT c.relname AS name,a.attname,a.attacl::text FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
      WHERE c.relnamespace='foundation'::regnamespace AND c.relkind IN ('r','S','v','m','p') AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum`),
    routines: await rows(db, `SELECT p.proname AS name,pg_get_function_identity_arguments(p.oid) AS args,p.proowner,p.proacl::text
      FROM pg_proc p WHERE p.pronamespace='foundation'::regnamespace ORDER BY p.proname,args`),
    scope: await rows(db, `SELECT 'database' AS kind,datdba AS owner,datacl::text AS acl FROM pg_database WHERE datname=current_database()
      UNION ALL SELECT nspname,nspowner,nspacl::text FROM pg_namespace WHERE nspname IN ('foundation','public') ORDER BY kind`),
  };
}
async function preservedAcl(db, before) {
  const after = await aclSnapshot(db);
  for (const [key, expected] of Object.entries(before)) {
    const present = after[key].filter((entry) => !['p03_command_receipts', 'p03_bootstrap_permissions', ...functions].includes(entry.name));
    assert.deepEqual(present, expected, `018 changed prior ${key} ACLs`);
  }
}
async function catalog(db) {
  assert.deepEqual(await rows(db, `SELECT code,module,description ~ '[А-Яа-я]' AS localized,protected,active FROM foundation.permissions
    WHERE code=ANY($1::text[]) ORDER BY code COLLATE "C"`, [codes]), codes.map((code) => ({
    code, module: code.split('.')[0], localized: true, protected: false, active: true,
  })), 'exact catalog addition');
  await noRoleGrants(db);
}

async function addStaff(db, role, label, assignedBy = null, marker = false) {
  const id = randomUUID(), assignment = randomUUID();
  const verifier = await syntheticVerifier();
  await db.query('BEGIN');
  try {
    await db.query("INSERT INTO foundation.staff(id,role,employment_state) VALUES($1,$2,'ACTIVE')", [id, role]);
    await db.query('INSERT INTO foundation.staff_web_credentials(staff_id,login,password_hash) VALUES($1,$2,$3)', [id, label, verifier]);
    await db.query(`INSERT INTO foundation.staff_role_assignments(id,staff_id,role_id,assigned_by)
      SELECT $1,$2,id,$3 FROM foundation.roles WHERE role_type='SYSTEM' AND code=$4`, [assignment, id, assignedBy, role]);
    if (marker) { await db.query('INSERT INTO foundation.staff_bootstrap_marker(id,staff_id) VALUES(1,$1)', [id]); }
    await db.query('COMMIT');
  } catch (error) { await db.query('ROLLBACK'); throw error; }
  return { id, assignment };
}
export async function prepareSettingsManagementFounder(db) {
  await isolated(db, 'fixlevelup_migrator', 'upgrade');
  const founder = await addStaff(db, 'ADMIN', 'p03-founder', null, true);
  await addStaff(db, 'ADMIN', 'p03-next-admin', founder.id);
  await db.query('SELECT foundation.issue_first_geo_permissions()');
  const prior = await geo(db);
  assert.equal(prior.length, 5);
  assert.ok(prior.every(({ assignment_id }) => assignment_id === founder.assignment));
  return founder;
}

export async function proveSettingsManagementCollision(db) {
  await isolated(db, 'fixlevelup_migrator', 'upgrade');
  // Put the last vocabulary member in the old catalog: no upsert/adoption, no other 018 effects.
  await db.query(`INSERT INTO foundation.permissions(code,module,description,protected,active)
    VALUES('legal.manage','legal','synthetic collision',false,false)`);
  const tables = await foundationTables(db);
  const before = await snapshot(db, tables), acl = await aclSnapshot(db), migrations = await history(db);
  const roleScope = () => one(db, `SELECT pg_get_constraintdef(oid) AS definition FROM pg_constraint
    WHERE conrelid='foundation.role_permissions'::regclass AND conname='role_permissions_scope_check'`);
  const beforeScope = await roleScope();
  const sql = readFileSync(new URL(`../../../prisma/migrations/${migration}/migration.sql`, import.meta.url), 'utf8');
  try { await rejects(db.query(sql), '23514'); } finally { await db.query('ROLLBACK'); }
  assert.equal(migrations.length, 17);
  assert.deepEqual(await history(db), migrations);
  assert.deepEqual(await roleScope(), beforeScope);
  assert.deepEqual(await foundationTables(db), tables);
  assert.deepEqual(await snapshot(db, tables), before);
  assert.deepEqual(await aclSnapshot(db), acl);
  console.log('018 collision: disabled pre-existing code rejects atomically (23514): PASS');
}

export async function proveSettingsManagementUpgrade(db, deploy, historyDiff, schemaDiff, migrations, founder, populated = false) {
  await isolated(db, 'fixlevelup_migrator', 'upgrade');
  const old = await history(db), tables = await foundationTables(db), before = await snapshot(db, tables), grants = await aclSnapshot(db);
  assert.deepEqual(old.map(({ migration_name }) => migration_name), migrations.slice(0, 17));
  if (populated) {
    for (const table of ['file_privacy_controls', 'file_publications', 'file_sanitized_attempts', 'service_cities', 'geography_bootstrap_permissions',
      'consent_records', 'content_blocks', 'reference_entries', 'legal_documents', 'staff_web_credentials', 'role_permissions', 'audit_logs']) {
      assert.ok(before[table].length > 0, `populated 017 fixture: ${table}`);
    }
  }
  deploy();
  const after = await history(db);
  assert.deepEqual(after.slice(0, 17), old);
  assert.deepEqual(after.map(({ migration_name }) => migration_name), migrations);
  assert.ok(after.every(({ finished_at }) => finished_at instanceof Date));
  assert.deepEqual(await foundationTables(db), [...tables, 'p03_bootstrap_permissions', 'p03_command_receipts'].sort());
  assert.deepEqual(await snapshot(db, tables, true), before, '018 touched older rows');
  await preservedAcl(db, grants);
  await catalog(db);
  assert.deepEqual(await rows(db, `SELECT * FROM ${receipts}`), []);
  assert.deepEqual(await sourceRows(db), founder ? codes.map((permission_code) => ({
    assignment_id: founder.assignment, permission_code, row_version: 1, revoked_at: null, revoked_by: null,
  })) : [], 'only the original verified founder has a personal source');
  assert.deepEqual(await audit(db), founder ? [{ details: {
    actor: 'SYSTEM_MIGRATION_018', assignmentId: founder.assignment, permissions: codes,
  } }] : []);
  const fullTables = await foundationTables(db), replay = await snapshot(db, fullTables);
  deploy();
  assert.deepEqual(await history(db), after);
  assert.deepEqual(await snapshot(db, fullTables), replay);
  await preservedAcl(db, grants);
  if (historyDiff && schemaDiff) {
    historyDiff(0); schemaDiff(0);
    await db.query(`ALTER TABLE ${receipts} ADD COLUMN p018_drift_probe integer`);
    try { historyDiff(2); schemaDiff(2); } finally { await db.query(`ALTER TABLE ${receipts} DROP COLUMN p018_drift_probe`); }
    historyDiff(0); schemaDiff(0);
  }
  console.log(`018 upgrade/replay (${tables.length} prior tables, ${Object.values(before).reduce((n, records) => n + records.length, 0)} prior rows): ${founder ? 'exact founder issuance' : 'no eligible founder, full drift detection/restoration'}, old ACLs/data preserved: PASS`);
}

async function proveAcl(runtime) {
  const expected = [
    [receipts, [
      ['actor_id', 'uuid', true, -1, null], ['operation', 'varchar', true, 68, null], ['key', 'uuid', true, -1, null],
      ['request_sha256', 'varchar', true, 68, null], ['entity_id', 'uuid', true, -1, null], ['entity_version', 'int4', true, -1, null],
      ['revision_id', 'uuid', false, -1, null], ['revision_version', 'int4', false, -1, null], ['created_at', 'timestamptz', true, 6, 'clock_timestamp()'],
    ], receiptInputs, receiptInputs, []],
    [sources, [
      ['assignment_id', 'uuid', true, -1, null], ['permission_code', 'varchar', true, 68, null], ['row_version', 'int4', true, -1, '1'],
      ['revoked_at', 'timestamptz', false, 6, null], ['revoked_by', 'uuid', false, -1, null],
    ], [...sourceInputs, 'row_version', 'revoked_at'], [], ['revoked_at', 'revoked_by']],
  ];
  for (const [table, columns, read, insert, update] of expected) {
    assert.deepEqual(await rows(runtime, `SELECT a.attname AS name,t.typname AS type,a.attnotnull AS required,a.atttypmod AS mod,
        pg_get_expr(d.adbin,d.adrelid) AS default_value,
        has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT') AS r,
        has_column_privilege(current_user,a.attrelid,a.attnum,'INSERT') AS i,
        has_column_privilege(current_user,a.attrelid,a.attnum,'UPDATE') AS u,
        has_column_privilege(current_user,a.attrelid,a.attnum,'REFERENCES,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION') AS extra,
        EXISTS(SELECT FROM aclexplode(a.attacl) acl WHERE acl.grantee=0) AS public_acl
      FROM pg_attribute a JOIN pg_type t ON t.oid=a.atttypid LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
      WHERE a.attrelid=$1::regclass AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum`, [table]),
    columns.map(([name,type,required,mod,default_value]) => ({ name,type,required,mod,default_value,
      r: read.includes(name), i: insert.includes(name), u: update.includes(name), extra: false, public_acl: false })), table);
    assert.deepEqual(await one(runtime, `SELECT pg_get_userbyid(c.relowner) AS owner,c.relkind,c.relrowsecurity AS rls,
      has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') AS broad,
      EXISTS(SELECT FROM aclexplode(c.relacl) acl WHERE acl.grantee=0) AS public_acl FROM pg_class c WHERE c.oid=$1::regclass`, [table]),
    { owner: 'fixlevelup_migrator', relkind: 'r', rls: false, broad: false, public_acl: false });
  }
  assert.deepEqual(await rows(runtime, `SELECT p.proname AS name,p.pronargs,p.prokind,p.proretset,p.prosecdef,p.proconfig,
    pg_get_userbyid(p.proowner) AS owner,has_function_privilege(current_user,p.oid,'EXECUTE') AS runtime_exec,
    (SELECT array_agg(pg_get_userbyid(acl.grantee)::text ORDER BY acl.grantee) FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl
      WHERE acl.privilege_type='EXECUTE') AS executors
    FROM pg_proc p WHERE p.pronamespace='foundation'::regnamespace AND p.proname=ANY($1::text[]) ORDER BY p.proname`, [functions]),
  functions.map((name) => ({ name, pronargs: 0, prokind: 'f', proretset: false, prosecdef: false, proconfig: ['search_path=pg_catalog'],
    owner: 'fixlevelup_migrator', runtime_exec: false, executors: ['fixlevelup_migrator'] })));
  assert.deepEqual(await rows(runtime, `SELECT conname,k.contype,k.convalidated,k.condeferrable,k.confupdtype,k.confdeltype,
    pg_get_constraintdef(k.oid) AS definition FROM pg_constraint k WHERE k.conrelid IN ($1::regclass,$2::regclass) AND k.contype IN ('p','f') ORDER BY conname`, [receipts,sources]), [
    ['p03_bootstrap_permissions_assignment_id_fkey', 'f', 'FOREIGN KEY (assignment_id) REFERENCES foundation.staff_role_assignments(id) ON UPDATE RESTRICT ON DELETE RESTRICT'],
    ['p03_bootstrap_permissions_permission_code_fkey', 'f', 'FOREIGN KEY (permission_code) REFERENCES foundation.permissions(code) ON UPDATE RESTRICT ON DELETE RESTRICT'],
    ['p03_bootstrap_permissions_pkey', 'p', 'PRIMARY KEY (assignment_id, permission_code)'],
    ['p03_bootstrap_permissions_revoked_by_fkey', 'f', 'FOREIGN KEY (revoked_by) REFERENCES foundation.staff(id) ON UPDATE RESTRICT ON DELETE RESTRICT'],
    ['p03_command_receipts_actor_id_fkey', 'f', 'FOREIGN KEY (actor_id) REFERENCES foundation.staff(id) ON UPDATE RESTRICT ON DELETE RESTRICT'],
    ['p03_command_receipts_pkey', 'p', 'PRIMARY KEY (actor_id, operation, key)'],
  ].map(([conname,contype,definition]) => ({ conname,contype,convalidated:true,condeferrable:false,
    confupdtype:contype === 'f' ? 'r' : ' ',confdeltype:contype === 'f' ? 'r' : ' ',definition })));
}

// A prohibited destructive statement must not actually remove fixtures even if the guard fails.
async function denyWithoutRemoving(client, sql, code) {
  await client.query('BEGIN');
  try { await rejects(client.query(sql), code); } finally { await client.query('ROLLBACK'); }
}
const validHash = 'b'.repeat(64);
async function proveReceipts(owner, runtime, founder, other) {
  const key = randomUUID(), entity = randomUUID(), rev = randomUUID();
  const insert = (op, revision, seq, { actor = founder.id, id = entity, hash = validHash, version = 1, k = key } = {}) => runtime.query(
    `INSERT INTO ${receipts} (${receiptInputs.join(',')}) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, [actor,op,k,hash,id,version,revision,seq]);
  await runtime.query('BEGIN');
  try {
    const before = await one(runtime, 'SELECT transaction_timestamp()::text AS started');
    await runtime.query('SELECT pg_sleep(0.015)');
    for (const op of operations) {
      const revisioned = publish.includes(op);
      assert.equal((await insert(op, revisioned ? rev : null, revisioned ? 3 : null)).rowCount, 1);
    }
    assert.equal((await insert('companyPublish',null,null,{ actor: other.id })).rowCount, 1, 'actor is part of key');
    const after = await one(runtime, 'SELECT clock_timestamp()::text AS ended');
    await runtime.query('COMMIT');
    assert.deepEqual(await one(owner, `SELECT count(*)::int AS count,bool_and(created_at>$1 AND created_at<=$2) AS stamped FROM ${receipts}`, [before.started, after.ended]), { count: 11, stamped: true });
  } catch (error) { await runtime.query('ROLLBACK'); throw error; }
  for (const op of operations) {
    const revisioned = publish.includes(op);
    for (const [revision, seq] of (revisioned ? [[null,null],[rev,null],[null,1],[rev,0],[rev,-1]] : [[rev,1],[rev,null],[null,1]])) {
      await rejects(insert(op,revision,seq,{ k: randomUUID() }), '23514', 'p03_command_receipts_revision_check');
    }
  }
  await rejects(insert('companyPublish',null,null), '23505', 'p03_command_receipts_pkey');
  for (const op of ['CompanyPublish','contentUpdate','bootstrapIssue','']) {
    await rejects(insert(op,null,null), '23514', 'p03_command_receipts_operation_check');
  }
  for (const hash of ['A'.repeat(64), 'g'.repeat(64), 'a'.repeat(63), 'a'.repeat(65), null]) {
    const sqlstate = hash === null ? '23502' : hash.length === 65 ? '22001' : '23514';
    await rejects(insert('companyPublish',null,null,{ hash, k: randomUUID() }), sqlstate);
  }
  for (const version of [0, -1, 2147483648, null, '1.5']) {
    await rejects(insert('companyPublish',null,null,{ version, k: randomUUID() }), version === null ? '23502'
      : version === '1.5' ? '22P02' : version === 2147483648 ? '22003' : '23514');
  }
  await rejects(insert('companyPublish',null,null,{ actor: randomUUID() }), '23503', 'p03_command_receipts_actor_id_fkey');
  await rejects(insert('companyPublish',null,null,{ id: 'not-uuid' }), '22P02');
  await rejects(runtime.query(`SELECT created_at FROM ${receipts}`), '42501');
  await rejects(runtime.query(`INSERT INTO ${receipts}(created_at) VALUES(clock_timestamp())`), '42501');
  for (const [client, status] of [[runtime,'42501'], [owner, '23514']]) {
    for (const sql of [`UPDATE ${receipts} SET entity_version=2`, `DELETE FROM ${receipts}`, `TRUNCATE ${receipts}`, `DELETE FROM ${sources}`, `TRUNCATE ${sources}`]) {
      await denyWithoutRemoving(client, sql, status);
    }
  }
  for (const table of [receipts,sources]) { await denyWithoutRemoving(runtime, `DROP TABLE ${table}`, '42501'); }
  await rejects(runtime.query(`INSERT INTO ${sources}(assignment_id,permission_code) VALUES($1,'settings.manage')`, [founder.assignment]), '42501');
  await rejects(runtime.query(`SELECT revoked_by FROM ${sources}`), '42501');
  await rejects(runtime.query(`UPDATE ${sources} SET row_version=row_version`), '42501');
  for (const name of functions) { await rejects(runtime.query(`SELECT foundation.${name}()`), '42501'); }
  await rejects(owner.query('SELECT foundation.issue_first_p03_permissions($1::uuid)', [founder.assignment]), '42883');
}

async function proveMatrix(owner, runtime) {
  const roles = Object.fromEntries((await rows(owner, 'SELECT code,id FROM foundation.roles')).map(({ code,id }) => [code,id]));
  roles.CUSTOM = randomUUID();
  await runtime.query("INSERT INTO foundation.roles(id,code,name) VALUES($1,'CUSTOM_P03_PROOF','Synthetic P03 proof')", [roles.CUSTOM]);
  const grant = (target, code, scope, enabled = true) => runtime.query(`INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type,enabled)
    VALUES($1,$2,$3,$4) ON CONFLICT(role_id,permission_code) DO UPDATE SET scope_type=EXCLUDED.scope_type,enabled=EXCLUDED.enabled`, [roles[target], code, scope, enabled]);
  const city = new Set(['references.callbackinterval.read','references.callbackinterval.manage','content.read','content.manage','content.publish']);
  const adminOnly = new Set(['settings.fullread','settings.manage','legal.read','legal.manage']);
  // Savepoints independently test every role/code/scope and leave no stored grant after this proof.
  await runtime.query('BEGIN');
  try {
    for (const role of ['ADMIN','MANAGER','CUSTOM','TECHNICIAN']) {
      for (const code of codes) {
        for (const scope of ['CITY','GLOBAL','SELF']) {
          const allowed = role !== 'TECHNICIAN' && (city.has(code) ? scope === 'CITY' || role === 'ADMIN' && scope === 'GLOBAL'
            : scope === 'GLOBAL' && (!adminOnly.has(code) || role === 'ADMIN'));
          await runtime.query('SAVEPOINT p03_grant');
          try {
            if (allowed) { assert.equal((await grant(role,code,scope)).rowCount, 1); }
            else { await rejects(grant(role,code,scope), '23514'); }
          } finally { await runtime.query('ROLLBACK TO SAVEPOINT p03_grant'); await runtime.query('RELEASE SAVEPOINT p03_grant'); }
        }
      }
    }
    for (const [role,code,scope,allowed] of [
      ['CUSTOM','staff.read','CITY',false], ['CUSTOM','staff.read','GLOBAL',true],
      ['TECHNICIAN','staff.self.read','SELF',true], ['TECHNICIAN','staff.self.read','GLOBAL',false],
      ['MANAGER','geography.read','CITY',true], ['MANAGER','geography.read','GLOBAL',false],
      ['MANAGER','geography.publish','CITY',false], ['ADMIN','geography.publish','GLOBAL',true],
    ]) {
      await runtime.query('SAVEPOINT p03_grant');
      try { if (allowed) { await grant(role,code,scope); } else { await rejects(grant(role,code,scope), '23514'); } }
      finally { await runtime.query('ROLLBACK TO SAVEPOINT p03_grant'); await runtime.query('RELEASE SAVEPOINT p03_grant'); }
    }
    // Simulate drift locally; the guard must reject a later enabled grant and permit disabling it.
    await runtime.query('SAVEPOINT p03_grant');
    await grant('TECHNICIAN','content.read','CITY',false);
    await rejects(grant('TECHNICIAN','content.read','CITY',true), '23514');
    await runtime.query('ROLLBACK TO SAVEPOINT p03_grant');
    await runtime.query('RELEASE SAVEPOINT p03_grant');
  } finally { await runtime.query('ROLLBACK'); }
  await noRoleGrants(owner);
}

async function proofRevoke(owner, runtime, founder, other, manager) {
  const code = 'settings.manage';
  const revoke = (actor, version = 1) => runtime.query(`UPDATE ${sources} SET revoked_at='2000-01-01',revoked_by=$2
    WHERE assignment_id=$1 AND permission_code=$3 AND row_version=$4 RETURNING row_version,revoked_at`, [founder.assignment,actor,code,version]);
  await rejects(revoke(manager.id), '23514');
  await rejects(revoke(randomUUID()), '23514');
  assert.equal((await revoke(other.id, 2)).rowCount, 0, 'CAS uses original version');
  // Hold the actual RBAC lock in another backend. Check the wait edge, then compare
  // the persisted clock against a DB timestamp before releasing the waiter.
  const waiter = await one(runtime, 'SELECT pg_backend_pid() AS pid');
  await owner.query('BEGIN');
  await owner.query("SELECT pg_advisory_xact_lock(hashtextextended('fixlevelup:admin-invariant',0))");
  const pending = revoke(other.id).then((result) => ({ result }), (error) => ({ error }));
  let lower;
  try {
    let blocked = false;
    for (let i = 0; i < 60 && !blocked; i += 1) {
      const observed = await one(owner, 'SELECT pg_backend_pid()=ANY(pg_blocking_pids($1)) AS blocked,clock_timestamp()::text AS t', [waiter.pid]);
      blocked = observed.blocked;
      lower = observed.t;
      if (!blocked) { await owner.query('SELECT pg_sleep(0.01)'); }
    }
    assert.ok(blocked, 'negative proof needs a real RBAC wait edge');
    await owner.query('COMMIT');
  } finally { await owner.query('ROLLBACK'); await pending; }
  const { result,error } = await pending;
  if (error) { throw error; }
  assert.equal(result.rowCount, 1);
  assert.deepEqual(await one(owner, `SELECT row_version,revoked_by,revoked_at>$2 AND revoked_at<=clock_timestamp() AS fresh
    FROM ${sources} WHERE assignment_id=$1 AND permission_code=$3`, [founder.assignment,lower,code]), { row_version: 2, revoked_by: other.id, fresh: true });
  assert.equal((await revoke(other.id)).rowCount, 0);
  await rejects(revoke(other.id,2), '23514');
  await rejects(owner.query(`UPDATE ${sources} SET revoked_at=NULL,revoked_by=NULL,row_version=1 WHERE permission_code=$1`, [code]), '23514');
  const revoked = await sourceRows(owner), issuanceAudit = await audit(owner);
  await issue(owner);
  assert.deepEqual(await sourceRows(owner), revoked);
  assert.deepEqual(await audit(owner), issuanceAudit);
  // A role cycle, password credential recovery update, and subsequent issuer retry
  // do not rebind or resurrect the personal source. Actual auth flows have their own tests.
  await owner.query('BEGIN');
  try {
    await owner.query(`UPDATE foundation.staff_role_assignments SET revoked_at=clock_timestamp(),revoked_by=$2 WHERE id=$1`, [founder.assignment,other.id]);
    await owner.query(`INSERT INTO foundation.staff_role_assignments(id,staff_id,role_id,assigned_by)
      SELECT gen_random_uuid(),$1,id,$2 FROM foundation.roles WHERE code='ADMIN'`, [founder.id,other.id]);
    await owner.query('UPDATE foundation.staff_web_credentials SET password_hash=$2 WHERE staff_id=$1', [founder.id, await syntheticVerifier()]);
    await issue(owner);
    await owner.query('COMMIT');
  } catch (error) { await owner.query('ROLLBACK'); throw error; }
  assert.deepEqual(await sourceRows(owner), revoked);
  assert.deepEqual(await audit(owner), issuanceAudit);
  assert.deepEqual(await rows(owner, `SELECT 1 FROM ${sources} p JOIN foundation.staff_role_assignments a ON a.id=p.assignment_id
    WHERE a.revoked_at IS NULL AND p.revoked_at IS NULL`), []);
}

export async function proveSettingsManagementRuntime(owner, password, founder) {
  const db = await isolated(owner, 'fixlevelup_migrator');
  const isFresh = founder === undefined;
  const oldGeo = await geo(owner);
  await catalog(owner);
  const other = await addStaff(owner, 'ADMIN', 'p03-ordinary-admin', founder?.id);
  if (isFresh) {
    await issue(owner);
    assert.deepEqual(await sourceRows(owner), [], 'no marker means no fallback to a valid admin');
    assert.deepEqual(await audit(owner), []);
    founder = await addStaff(owner, 'ADMIN', 'p03-fresh-founder', null, true);
    await issue(owner);
  }
  assert.deepEqual(await sourceRows(owner), codes.map((permission_code) => ({
    assignment_id: founder.assignment, permission_code, row_version: 1, revoked_at: null, revoked_by: null,
  })));
  await rejects(owner.query(`INSERT INTO ${sources}(assignment_id,permission_code) VALUES($1,'content.read')`, [other.assignment]), '23514');
  const manager = await addStaff(owner,'MANAGER','p03-revocation-manager',founder.id);
  const runtime = connection('fixlevelup_runtime', password, db);
  await runtime.connect();
  try {
    await isolated(runtime,'fixlevelup_runtime');
    await proveAcl(runtime);
    await proveReceipts(owner, runtime, founder, other);
    await proveMatrix(owner, runtime);
    await proofRevoke(owner, runtime, founder, other, manager);
  } finally { await runtime.end(); }
  assert.deepEqual(await geo(owner), oldGeo, 'P03 issuer/revocation must not change 012 sources');
  console.log(`018 ${isFresh ? 'fresh' : 'upgrade'} runtime: exact ACL/PK/FK, 216 role×code×scope combinations, receipt closure/immutability, no broad issuer, observed-wait DB revocation and no re-issue: PASS`);
}
