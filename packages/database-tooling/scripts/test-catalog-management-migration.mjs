import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { setTimeout as delay } from 'node:timers/promises';
import { baseTables, migrationHistory, snapshot } from './test-catalog-fixed-prices-migration.mjs';
import { syntheticVerifier } from './test-rbac-migration.mjs';

const migration = '20261122000700_catalog_management';
const pricingSha = 'faccb0d44f3526c43e0131340446b2a12671435f11877fa24786ff52a56bee09';
const sql = name => {
  assert.match(name, /^\d{14}_[a-z_]+$/);
  return readFileSync(new URL(`../../../prisma/migrations/${name}/migration.sql`, import.meta.url), 'utf8');
};
const checks = (table, keys) => keys.map(key => `${table}_${key}_check`);
export const catalogManagementChecks = [
  ...checks('p04_bootstrap_permissions', ['code', 'revoke', 'row_version']),
  ...checks('p04_command_receipts', ['operation', 'request_sha256', 'entity_version', 'city', 'subject', 'target_version', 'revision']),
  ...checks('external_reviews', ['code', 'profile_kind', 'profile', 'row_version', 'archive']),
  ...checks('external_review_revisions', ['version', 'profile_kind', 'title', 'source_url', 'source_date', 'excerpt', 'rating', 'permission_ref', 'kind_fields', 'published_at']),
];
export const catalogManagementCodes = [
  'catalog.manage', 'catalog.read', 'content.externalreviews.manage', 'content.externalreviews.publish', 'content.externalreviews.read',
  'pricing.manage', 'pricing.read', 'pricing.rules.manage', 'pricing.rules.read',
];
const cityCodes = ['pricing.manage', 'pricing.read'];
const receipts = 'p04_command_receipts';
const personal = 'p04_bootstrap_permissions';
const entries = 'external_reviews';
const revisions = 'external_review_revisions';
const receiptColumns = 'actor_id operation key request_sha256 city_id subject_id target_version_id entity_id entity_version revision_id revision_version';
const tables = {
  [personal]: ['assignment_id permission_code row_version revoked_at', '', ''],
  [receipts]: [receiptColumns, receiptColumns, ''],
  [entries]: ['*', 'id code kind profile_id', 'current_version_id archived_at'],
  [revisions]: ['*', 'id entry_id kind version title source_url source_date excerpt rating permission_ref profile_id profile_revision_id reviewed_by', ''],
};
const issuer = 'issue_p04_synthetic_permissions';
const functions = [issuer, 'p04_guard_role_grant', 'p04_bootstrap_guard', 'external_reviews_guard_identity',
  'external_review_revisions_guard_basis', 'external_review_revisions_guard_chain'];
const issueSql = `SELECT foundation.${issuer}()`;
const rows = async (db, text, values) => (await db.query(text, values)).rows;
const one = async (db, text, values) => (await rows(db, text, values))[0];
const deny = (query, code, constraint) => assert.rejects(query, { code, ...(constraint ? { constraint } : {}) });
async function isolated(db, role, pattern) {
  const identity = await one(db, 'SELECT current_user AS role,current_database() AS name');
  assert.equal(identity.role, role);
  assert.match(identity.name, pattern);
  return identity.name;
}
const upgradeDb = /^fixlevelup_p017a_upgrade_[a-f0-9]{12}$/;
const freshDb = /^fixlevelup_p017a_fresh_[a-f0-9]{12}$/;
const allowedFixture = /^fixlevelup_(?:configuration_test|p04_browser_test)_[a-f0-9]{24}$/;
async function transaction(db, fn, begin = 'BEGIN ISOLATION LEVEL READ COMMITTED') {
  await db.query(begin);
  try { const result = await fn(); await db.query('COMMIT'); return result; }
  catch (error) { await db.query('ROLLBACK'); throw error; }
}
const insert = (db, table, values) => db.query(`INSERT INTO foundation.${table}(${Object.keys(values).join(',')})
  VALUES(${Object.keys(values).map((_, i) => `$${i + 1}`).join(',')})`, Object.values(values));
async function noGrants(db) {
  assert.deepEqual(await rows(db, 'SELECT * FROM foundation.role_permissions WHERE permission_code=ANY($1::text[])', [catalogManagementCodes]), []);
  assert.deepEqual(await rows(db, `SELECT * FROM foundation.${personal}`), []);
}
async function inert(db) {
  assert.deepEqual(await rows(db, `SELECT code,module,description ~ '[А-Яа-я]' AS localized,protected,active
    FROM foundation.permissions WHERE code=ANY($1::text[]) ORDER BY code COLLATE "C"`, [catalogManagementCodes]),
  catalogManagementCodes.map(code => ({ code, module: code.split('.')[0], localized: true, protected: false, active: true })));
  await noGrants(db);
  for (const table of [receipts, entries, revisions]) {
    assert.deepEqual(await rows(db, `SELECT FROM foundation.${table} LIMIT 1`), []);
  }
}

export async function proveCatalogManagementCollision(db) {
  await isolated(db, 'fixlevelup_migrator', upgradeDb);
  const permission = 'pricing.rules.manage';
  await insert(db, 'permissions', { code: permission, module: 'pricing', description: 'Isolated disabled collision', protected: false, active: false });
  try {
    const names = await baseTables(db), before = await snapshot(db, names), history = await migrationHistory(db);
    assert.equal(history.at(-1)?.checksum, pricingSha);
    try { await deny(db.query(sql(migration)), '23514'); } finally { await db.query('ROLLBACK'); }
    assert.deepEqual(await baseTables(db), names);
    assert.deepEqual(await snapshot(db, names), before);
    assert.deepEqual(await migrationHistory(db), history);
  } finally {
    const removed = await db.query('DELETE FROM foundation.permissions WHERE code=$1 AND active=false AND protected=false', [permission]);
    assert.equal(removed.rowCount, 1, 'Must remove exactly our isolated collision before success proof');
  }
  console.log('021 disabled pre-existing code collision fails closed and leaves exact 020 state: PASS');
}

function preservePrevious(before, after, names) {
  const permissionIndex = names.indexOf('permissions');
  const roleIndex = after.definition.findIndex(x => x.relname === 'role_permissions');
  const role = after.definition[roleIndex];
  const oldRole = before.definition[roleIndex];
  const oldCheck = oldRole.constraints.find(([label]) => label === 'role_permissions_scope_check');
  const newCheck = role.constraints.find(([label]) => label === 'role_permissions_scope_check');
  assert.equal(newCheck[1], true);
  const oldCodes = [...oldCheck[2].matchAll(/'([^']+)'/g)].map(m => m[1]);
  const retained = [...newCheck[2].matchAll(/'([^']+)'/g)].map(m => m[1]);
  assert.deepEqual(retained.filter(token => !cityCodes.includes(token)), oldCodes);
  assert.deepEqual(retained.filter(token => cityCodes.includes(token)).sort(), cityCodes);
  // Compare the entire old expression after removing only the known two allowlist values, not by excluding the CHECK.
  const withoutNew = newCheck[2].replace(/,\s*'pricing\.(?:read|manage)'::(?:character varying|text)/g, '');
  assert.equal(withoutNew, oldCheck[2]);
  const addedTrigger = role.triggers.filter(([name]) => name === 'p04_guard_role_grant');
  assert.equal(addedTrigger.length, 1);
  assert.equal(addedTrigger[0][1], 'O');
  assert.match(addedTrigger[0][2], /BEFORE INSERT OR UPDATE ON foundation\.role_permissions FOR EACH ROW EXECUTE FUNCTION foundation\.p04_guard_role_grant\(\)/);
  const added = new Set(catalogManagementCodes);
  const data = after.data.map((tableRows, i) => i === permissionIndex
    ? tableRows.filter(({ value }) => !added.has(JSON.parse(value).code)) : tableRows);
  const definition = after.definition.map((row, i) => i === roleIndex ? { ...row,
    constraints: role.constraints.map(check => check === newCheck ? oldCheck : check),
    triggers: role.triggers.filter(([name]) => name !== 'p04_guard_role_grant'),
  } : row);
  assert.deepEqual({ ...after, data, definition }, before, 'Unexpected SQL/data/ACL change outside precise P04 additions');
}

export async function proveCatalogManagementUpgrade(db, expected, deploy, diff) {
  await isolated(db, 'fixlevelup_migrator', upgradeDb);
  const oldHistory = await migrationHistory(db), previous = await baseTables(db);
  assert.deepEqual(oldHistory.map(row => row.migration_name), expected.slice(0, -1));
  assert.equal(oldHistory.at(-1)?.checksum, pricingSha, 'Accepted 020 changed');
  const before = await snapshot(db, previous);
  for (const table of ['price_rule_versions','price_rule_periods','price_rule_scopes','pricing_policy_versions','pricing_policy_periods',
    'price_rule_priorities','price_rule_compatibilities','public_price_estimates','public_price_estimate_periods']) {
    assert.ok(before.data[previous.indexOf(table)]?.length, `Missing populated 020 source: ${table}`);
  }
  deploy();
  const history = await migrationHistory(db), tablesAfter = await baseTables(db);
  assert.deepEqual(history.map(row => row.migration_name), expected);
  assert.deepEqual(history.slice(0, -1), oldHistory);
  assert.ok(history.at(-1)?.finished_at instanceof Date);
  assert.deepEqual(tablesAfter, [...previous, ...Object.keys(tables)].sort());
  preservePrevious(before, await snapshot(db, previous), previous);
  await inert(db);
  const published = await snapshot(db, tablesAfter);
  deploy();
  assert.deepEqual(await migrationHistory(db), history);
  assert.deepEqual(await snapshot(db, tablesAfter), published);
  diff(0);
  await db.query(`ALTER TABLE foundation.${receipts} ADD COLUMN p021_drift_probe integer`);
  try { diff(2); } finally { await db.query(`ALTER TABLE foundation.${receipts} DROP COLUMN p021_drift_probe`); }
  diff(0);
  console.log('021 populated 020 upgrade: original checksum, pricing data/FKs/ACL, exact RBAC delta, replay, Prisma/SQL drift: PASS');
}

async function acl(owner, db) {
  for (const [table, [read, insertable, update]] of Object.entries(tables)) {
    const name = `foundation.${table}`;
    const observed = await rows(db, `SELECT a.attname AS name,
      has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT') AS r,
      has_column_privilege(current_user,a.attrelid,a.attnum,'INSERT') AS i,
      has_column_privilege(current_user,a.attrelid,a.attnum,'UPDATE') AS u,
      has_column_privilege(current_user,a.attrelid,a.attnum,'REFERENCES,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION') AS elevated,
      EXISTS(SELECT FROM aclexplode(a.attacl) x WHERE x.grantee<>to_regrole('fixlevelup_runtime')::oid) AS other
      FROM pg_attribute a WHERE a.attrelid=$1::regclass AND a.attnum>0 AND NOT a.attisdropped`, [name]);
    const columns = s => s.split(' ').filter(Boolean).sort();
    const allowed = k => observed.filter(x => x[k]).map(x => x.name).sort();
    assert.ok(observed.length && observed.every(x => !x.elevated && !x.other));
    assert.deepEqual(allowed('r'), read === '*' ? observed.map(x => x.name).sort() : columns(read), `SELECT ${table}`);
    assert.deepEqual(allowed('i'), columns(insertable), `INSERT ${table}`);
    assert.deepEqual(allowed('u'), columns(update), `UPDATE ${table}`);
    assert.deepEqual(await one(db, `SELECT pg_get_userbyid(relowner) AS owner,
      has_table_privilege(current_user,oid,'SELECT') AS r,
      has_table_privilege(current_user,oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN,SELECT WITH GRANT OPTION') AS elevated,
      EXISTS(SELECT FROM aclexplode(relacl) x WHERE x.grantee NOT IN (relowner,to_regrole('fixlevelup_runtime')::oid)) AS other
      FROM pg_class WHERE oid=$1::regclass`, [name]), { owner: 'fixlevelup_migrator', r: read === '*', elevated: false, other: false });
    const key = observed.find(x => !x.u).name;
    await deny(db.query(`UPDATE ${name} SET ${key}=${key} WHERE false`), '42501');
    await deny(db.query(`DELETE FROM ${name} WHERE false`), '42501');
    await deny(db.query(`TRUNCATE ${name}`), '42501');
    await deny(owner.query(`DELETE FROM ${name} WHERE false`), '23514');
  }
  const routineAcl = await rows(db, `SELECT proname,pg_get_userbyid(proowner) AS owner,prosecdef,proconfig,
    has_function_privilege(current_user,oid,'EXECUTE') AS r,
    EXISTS(SELECT FROM aclexplode(coalesce(proacl,acldefault('f',proowner))) a WHERE a.grantee<>proowner) AS other
    FROM pg_proc WHERE pronamespace='foundation'::regnamespace AND proname=ANY($1::text[]) ORDER BY proname COLLATE "C"`, [functions]);
  assert.deepEqual(routineAcl, [...functions].sort().map(proname => ({ proname, owner: 'fixlevelup_migrator', prosecdef: false,
    proconfig: ['search_path=pg_catalog'], r: false, other: false })));
  assert.deepEqual(await one(db, `SELECT enum_range(NULL::foundation.external_review_kind)::text AS kinds,
    has_type_privilege(current_user,t.oid,'USAGE') AS usable,
    EXISTS(SELECT FROM aclexplode(t.typacl) a WHERE a.grantee NOT IN (t.typowner,to_regrole('fixlevelup_runtime')::oid)) AS other
    FROM pg_type t WHERE t.oid='foundation.external_review_kind'::regtype`), { kinds: '{PROFILE,REVIEW}', usable: true, other: false });
  const exact = [
    [entries, 'external_reviews_write_fence', 'catalog_lock_write', 22, false],
    [revisions, 'external_review_revisions_write_fence', 'catalog_lock_write', 6, false],
    [revisions, 'external_review_revisions_chain_guard', 'external_review_revisions_guard_chain', 5, true],
    [personal, 'p04_bootstrap_write', 'rbac_lock_write', 22, false],
    ['role_permissions', 'p04_guard_role_grant', 'p04_guard_role_grant', 23, false],
  ].sort((a, b) => a[1] < b[1] ? -1 : 1);
  assert.deepEqual(await rows(db, `SELECT c.relname AS name,t.tgname,p.proname,t.tgtype::int AS type,t.tgdeferrable,
    t.tginitdeferred,t.tgenabled,t.tgqual IS NULL AS unconditional,t.tgnargs AS args FROM pg_trigger t
    JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_proc p ON p.oid=t.tgfoid
    WHERE c.relnamespace='foundation'::regnamespace AND p.pronamespace='foundation'::regnamespace
      AND t.tgname=ANY($1::text[]) AND NOT t.tgisinternal ORDER BY t.tgname COLLATE "C"`, [exact.map(x => x[1])]),
  exact.map(([name,tgname,proname,type,tgdeferrable]) => ({ name,tgname,proname,type,tgdeferrable,tginitdeferred:tgdeferrable,
    tgenabled:'O',unconditional:true,args:0 })));
  const fks = [
    [personal, 'assignment_id', 'staff_role_assignments', 'id'], [personal, 'permission_code', 'permissions', 'code'],
    [personal, 'revoked_by', 'staff', 'id'], [receipts, 'actor_id', 'staff', 'id'], [receipts, 'city_id', 'service_cities', 'id'],
    [entries, 'profile_id profile_kind', entries, 'id kind'], [entries, 'id kind current_version_id', revisions, 'entry_id kind id'],
    [revisions, 'entry_id kind', entries, 'id kind'], [revisions, 'profile_id profile_kind profile_revision_id', revisions, 'entry_id kind id'],
    [revisions, 'reviewed_by', 'staff', 'id'],
  ].map(([name, source, target, ref]) => [name, source, target, ref].join('|')).sort();
  const actualFks = await rows(db, `SELECT c.relname AS name, r.relname AS target, k.convalidated AND NOT k.condeferrable
      AND k.confupdtype='r' AND k.confdeltype='r' AND r.relnamespace=c.relnamespace AS restrictive,
      (SELECT string_agg(a.attname,' ' ORDER BY n) FROM unnest(k.conkey) WITH ORDINALITY AS keys(attnum,n)
        JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=keys.attnum) AS source,
      (SELECT string_agg(a.attname,' ' ORDER BY n) FROM unnest(k.confkey) WITH ORDINALITY AS keys(attnum,n)
        JOIN pg_attribute a ON a.attrelid=r.oid AND a.attnum=keys.attnum) AS ref
    FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_class r ON r.oid=k.confrelid
    WHERE k.contype='f' AND c.relnamespace='foundation'::regnamespace AND c.relname=ANY($1::text[])`, [Object.keys(tables)]);
  assert.ok(actualFks.every(fk => fk.restrictive));
  assert.deepEqual(actualFks.map(({ name, source, target, ref }) => [name, source, target, ref].join('|')).sort(), fks);
  const receiptOps = await one(db, `SELECT pg_get_constraintdef(oid) AS shape FROM pg_constraint
    WHERE conname='p04_command_receipts_operation_check' AND conrelid='foundation.p04_command_receipts'::regclass AND convalidated`);
  assert.deepEqual([...receiptOps.shape.matchAll(/'([^']+)'/g)].map(m => m[1]).sort(), [...operations].sort());
  await deny(db.query(issueSql), '42501');
  await deny(owner.query(issueSql), '42501'); // fresh p017a name is deliberately ineligible, never query dev
  await deny(owner.query(`INSERT INTO foundation.${personal}(assignment_id,permission_code) VALUES($1,'catalog.read')`, [randomUUID()]), '42501');
  await deny(db.query(`ALTER TABLE foundation.${revisions} ADD COLUMN forbidden integer`), '42501');
  await deny(db.query('CREATE TABLE foundation.p021_forbidden(x integer)'), '42501');
}

async function matrix(owner, db) {
  const roles = Object.fromEntries((await rows(owner, "SELECT code,id FROM foundation.roles WHERE role_type='SYSTEM'")).map(r => [r.code,r.id]));
  const custom = randomUUID(), archived = randomUUID();
  for (const [id,code] of [[custom,'P04_PROOF_CURRENT'],[archived,'P04_PROOF_ARCHIVED']]) {
    await insert(owner,'roles',{id,code,name:'Synthetic role'});
  }
  await owner.query("UPDATE foundation.roles SET status='ARCHIVED' WHERE id=$1", [archived]);
  let allowed = 0, refused = 0;
  const grant = (client, role, code, scope) => insert(client,'role_permissions', { role_id: role, permission_code: code, scope_type: scope, enabled:true });
  for (const code of catalogManagementCodes) {
    for (const [role, id] of Object.entries({ ...roles, CUSTOM: custom, ARCHIVED: archived })) {
      for (const scope of ['GLOBAL','CITY','SELF']) {
        const permitted = (role === 'ADMIN' && scope === 'GLOBAL') || (cityCodes.includes(code) && scope === 'CITY'
          && ['ADMIN','MANAGER','CUSTOM'].includes(role));
        // Each bit runs with the actual SQL runtime and leaves no role grant behind.
        await db.query('BEGIN');
        try {
          if (permitted) { assert.equal((await grant(db,id,code,scope)).rowCount,1); allowed++; }
          else { await deny(grant(db,id,code,scope),'23514'); refused++; }
        } finally { await db.query('ROLLBACK'); }
      }
    }
  }
  for (const [patch, restore] of [["module='wrong'", "module='catalog'"], ['active=false','active=true']]) {
    await owner.query(`UPDATE foundation.permissions SET ${patch} WHERE code='catalog.read'`);
    try { await deny(grant(db,roles.ADMIN,'catalog.read','GLOBAL'),'23514'); refused++; }
    finally { await owner.query(`UPDATE foundation.permissions SET ${restore} WHERE code='catalog.read'`); }
  }
  await noGrants(owner);
  return [allowed,refused];
}

const entities = ['category','brand','model','fault','item'];
const cityVersions = ['fixed','ruleVersion','policy'];
const operations = [
  ...entities.flatMap(entity => ['Create','Publish','Archive'].map(action => entity + action)),
  'mappingCreate','mappingPublish','mappingArchive','ruleCreate','ruleArchive',
  ...cityVersions.flatMap(entity => ['Publish','Close','Replace'].map(action => entity + action)),
  'estimateCreate','estimateArchive','estimatePublish','estimateClose','estimateReplace','avitoCreate','avitoPublish','avitoArchive',
];

async function proveReceipts(owner, db, reviewer, city) {
  const sample = operation => {
    const entity = randomUUID();
    const hasCity = /^(fixed|ruleVersion|policy|estimate)/.test(operation);
    const revision = operation !== 'mappingPublish' && /(?:Publish|Replace)$/.test(operation);
    return { actor_id:reviewer, operation, key:randomUUID(), request_sha256:'a'.repeat(64),
      city_id:hasCity ? city : null, subject_id:operation.startsWith('policy') ? city : operation.endsWith('Create') ? entity : randomUUID(),
      target_version_id:/(?:Close|Replace)$/.test(operation) ? randomUUID() : null, entity_id:entity, entity_version:1,
      revision_id:revision ? randomUUID() : null, revision_version:revision ? 1 : null };
  };
  for (const operation of operations) {
    assert.equal((await insert(db,receipts,sample(operation))).rowCount,1);
  }
  const baseline = sample('fixedReplace');
  for (const [operation, patch, suffix] of [
    ['notACommand',{},'operation'], ['categoryList',{},'operation'],
    ['fixedReplace',{request_sha256:'A'.repeat(64)},'request_sha256'], ['fixedReplace',{entity_version:0},'entity_version'],
    ['fixedReplace',{city_id:null},'city'], ['categoryCreate',{city_id:city},'city'],
    ['policyPublish',{subject_id:randomUUID()},'subject'], ['estimateCreate',{subject_id:randomUUID()},'subject'],
    ['fixedReplace',{target_version_id:null},'target_version'], ['fixedPublish',{target_version_id:randomUUID()},'target_version'],
    ['fixedReplace',{revision_id:null},'revision'], ['fixedReplace',{revision_version:0},'revision'],
    ['mappingPublish',{revision_id:randomUUID(),revision_version:1},'revision'],
  ]) {
    await deny(insert(db,receipts,{ ...sample(operation), ...patch }),'23514',`${receipts}_${suffix}_check`);
  }
  await deny(insert(db,receipts,{...baseline,subject_id:null}), '23502');
  await deny(insert(db,receipts,{...baseline,actor_id:randomUUID()}), '23503', `${receipts}_actor_id_fkey`);
  await deny(insert(db,receipts,{...baseline,city_id:randomUUID()}), '23503', `${receipts}_city_id_fkey`);
  await insert(db,receipts,baseline);
  await deny(insert(db,receipts,baseline), '23505', `${receipts}_pkey`);
  await deny(db.query(`SELECT created_at FROM foundation.${receipts}`), '42501');
  await deny(owner.query(`UPDATE foundation.${receipts} SET entity_version=2 WHERE key=$1`, [baseline.key]), '23514');
  assert.deepEqual(await one(db, `SELECT ${receiptColumns.replaceAll(' ', ',')} FROM foundation.${receipts}
    WHERE actor_id=$1 AND operation=$2 AND key=$3`, [reviewer,baseline.operation,baseline.key]), baseline);
  assert.equal((await one(owner, `SELECT count(*)::int AS n FROM foundation.${receipts} WHERE isfinite(created_at)`)).n, operations.length+1);
}

async function proveAvito(owner, db, reviewer) {
  const profile = randomUUID(), another = randomUUID(), review = randomUUID(), abandoned = randomUUID(), p1 = randomUUID(), p2 = randomUUID(), other = randomUUID(), rv = randomUUID();
  const create = (id,code,kind,profile_id = null) => insert(db,entries,{id,code,kind,profile_id});
  const publish = (entry,id) => db.query(`UPDATE foundation.${entries} SET current_version_id=$2 WHERE id=$1`,[entry,id]);
  const version = (entry,id,kind,number,patch = {}) => insert(db,revisions,{id, entry_id:entry,kind,version:number,
    title:'Reviewed synthetic text',source_url:'https://www.avito.ru/synthetic/profile',permission_ref:'synthetic reference',reviewed_by:reviewer,...patch});
  const reviewFields = { profile_id:profile, profile_revision_id:p1, source_date:'2026-11-20', excerpt:'Synthetic plain text', rating:5 };
  // One real SQL writer waits on the same shared fence as pricing readers.
  await owner.query('BEGIN');
  let pending;
  try {
    await owner.query('SELECT pg_advisory_xact_lock_shared(77304,1)');
    const waiter = await one(db,'SELECT pg_backend_pid() AS pid');
    pending = create(profile,'synthetic-profile','PROFILE').then(result => ({result}), error => ({error}));
    const deadline = performance.now()+3500;
    let observed = false;
    do {
      const row = await one(owner,`SELECT EXISTS(SELECT FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted
        AND classid=77304 AND objid=1 AND objsubid=2 AND mode='ExclusiveLock' AND pg_backend_pid()=ANY(pg_blocking_pids($1))) AS waiting`,[waiter.pid]);
      if (row.waiting) { observed = true; break; }
      await delay(12);
    } while (performance.now()<deadline);
    assert.ok(observed);
  } finally { await owner.query('ROLLBACK'); await pending; }
  const outcome = await pending;
  if (outcome.error) { throw outcome.error; }
  assert.equal(outcome.result.rowCount,1);
  await create(another,'other-profile','PROFILE');
  await deny(create(randomUUID(),'wrong-code','REVIEW'), '23514');
  await deny(create(randomUUID(),'what-parent','PROFILE',profile), '23514', 'external_reviews_profile_check');
  await deny(create(randomUUID(),'Uppercase','PROFILE'), '23514', 'external_reviews_code_check');
  await deny(transaction(db,() => version(profile,p1,'PROFILE',1)), '23514'); // draft cannot leave unattached revision
  await deny(version(profile,p1,'PROFILE',2), '23514'); // only next reviewed sequence
  for (const source_url of ['https://avito.ru:443/path','https://avito.ru/../path','https://avito.ru/path?x=1','https://avito.ru/path#x',
    'https://avito.ru/path%2Fchild','https://avito.ru/','http://avito.ru/path','https://avito.ru.attacker.test/path','https://user@avito.ru/path','https://avito.ru/path\\child']) {
    await deny(version(profile,p1,'PROFILE',1,{source_url}),'23514','external_review_revisions_source_url_check');
  }
  await deny(version(profile,p1,'PROFILE',1,{title:'<b>synthetic</b>'}),'23514','external_review_revisions_title_check');
  await deny(version(profile,p1,'PROFILE',1,{permission_ref:'\u200b'}),'23514','external_review_revisions_permission_ref_check');
  await deny(version(profile,p1,'PROFILE',1,{rating:5}),'23514','external_review_revisions_kind_fields_check');
  await transaction(db,async () => { await version(profile,p1,'PROFILE',1); await publish(profile,p1); });
  await transaction(db,async () => { await version(another,other,'PROFILE',1); await publish(another,other); });
  await create(review,'synthetic-review','REVIEW',profile);
  await create(abandoned,'synthetic-abandoned','REVIEW',profile);
  await deny(create(randomUUID(),'wrong-kind-parent','REVIEW',review),'23514');
  await deny(publish(profile,other),'23503');
  await deny(version(review,rv,'REVIEW',1,{ ...reviewFields, profile_id:another,profile_revision_id:other }), '23514');
  for (const [patch, suffix] of [[{ rating:6 },'rating'],[{excerpt:'<p>x</p>'},'excerpt'],[{source_date:'10000-01-01'},'source_date'],
    [{excerpt:null},'kind_fields']]) {
    await deny(version(review,rv,'REVIEW',1,{...reviewFields,...patch}),'23514',`external_review_revisions_${suffix}_check`);
  }
  await transaction(db,async () => { await version(review,rv,'REVIEW',1,reviewFields); await publish(review,rv); });
  await transaction(db,async () => { await version(profile,p2,'PROFILE',2,{source_url:'https://avito.ru/synthetic/Profile2'}); await publish(profile,p2); });
  await deny(version(review,randomUUID(),'REVIEW',2,reviewFields),'23514'); // historical basis no longer current
  await db.query(`UPDATE foundation.${entries} SET archived_at=clock_timestamp() WHERE id=$1`,[profile]);
  await deny(create(randomUUID(),'archived-profile-parent','REVIEW',profile),'23514');
  await deny(version(abandoned,randomUUID(),'REVIEW',1,{...reviewFields,profile_revision_id:p2}),'23514');
  await deny(owner.query(`UPDATE foundation.${revisions} SET title='Rewrite forbidden' WHERE id=$1`,[rv]),'23514');
  await deny(owner.query(`UPDATE foundation.${entries} SET archived_at=NULL WHERE id=$1`,[profile]),'23514');
  assert.deepEqual(await rows(db,`SELECT r.version,r.profile_revision_id,r.rating,r.reviewed_by,p.current_version_id AS current_profile
    FROM foundation.${revisions} r JOIN foundation.${entries} p ON p.id=r.profile_id
    WHERE r.entry_id=$1 AND r.id=$2 AND p.archived_at IS NOT NULL`,[review,rv]),
  [{version:1,profile_revision_id:p1,rating:5,reviewed_by:reviewer,current_profile:p2}]);
}

export async function proveCatalogManagementFresh(owner, db, reviewer, { cityA }) {
  const name = await isolated(owner,'fixlevelup_migrator',freshDb);
  assert.equal(await isolated(db,'fixlevelup_runtime',freshDb),name);
  await inert(owner);
  await acl(owner,db);
  const [allowed, refused] = await matrix(owner,db);
  await proveReceipts(owner,db,reviewer,cityA);
  await proveAvito(owner,db,reviewer);
  console.log(`021 fresh: ${catalogManagementChecks.length} independent CHECK names, 4 exact ACLs, 9 inert codes, ${allowed}/${refused} admitted/refused grant cases, ${operations.length} receipt operations and Avito real fence/history: PASS`);
}

async function addStaff(db, { role, login, marker = false, assignedBy = null }) {
  const id = randomUUID(), assignment = randomUUID(), verifier = await syntheticVerifier();
  await transaction(db,async () => {
    await insert(db,'staff',{id,role,employment_state:'ACTIVE'});
    await insert(db,'staff_web_credentials',{staff_id:id,login,password_hash:verifier});
    const result = await db.query(`INSERT INTO foundation.staff_role_assignments(id,staff_id,role_id,assigned_by)
      SELECT $1,$2,r.id,$3 FROM foundation.roles r WHERE r.role_type='SYSTEM' AND r.code=$4`,[assignment,id,assignedBy,role]);
    assert.equal(result.rowCount,1);
    if (marker) { await insert(db,'staff_bootstrap_marker',{id:1,staff_id:id}); }
  });
  return { id, assignment };
}

// Use exactly the two fixture namespaces accepted by the SQL guard; never enlarge the shared deployment allowlist.
export async function proveCatalogManagementIssuer(admin, passwords, migrations) {
  // The issuer proof is anchored at exactly the 021 capped chain; a later
  // slice appends migrations, so the pinned count here refers to the 021
  // prefix of the chain, not to the live repository length.
  assert.equal(migrations.length >= 21 ? migrations[20] : migrations.at(-1), migration);
  assert.equal(migrations.indexOf(migration), 20);
  assert.deepEqual(await one(admin, 'SELECT current_database() AS db,current_user AS role,current_setting(\'server_version_num\') AS pg'),
    {db:'fixlevelup_dev',role:'fixlevelup_dev',pg:'180007'}); // only database provisioning uses the admin connection; all migration/data SQL runs in isolated DBs
  const requireApi = createRequire(new URL('../../../apps/api/package.json',import.meta.url));
  const { Client } = requireApi('pg');
  for (const prefix of ['configuration_test','p04_browser_test']) {
    const name = `fixlevelup_${prefix}_${randomBytes(12).toString('hex')}`;
    assert.match(name,allowedFixture);
    assert.deepEqual(await rows(admin,'SELECT datname FROM pg_database WHERE datname=$1',[name]),[]);
    await admin.query(`CREATE DATABASE "${name}" OWNER fixlevelup_migrator TEMPLATE template0`);
    await admin.query(`REVOKE ALL ON DATABASE "${name}" FROM PUBLIC; GRANT CONNECT ON DATABASE "${name}" TO fixlevelup_migrator,fixlevelup_runtime`);
    const connect = role => {
      assert.match(passwords[role] ?? '',/^[a-f0-9]{64}$/);
      return new Client({host:'127.0.0.1',port:55432,database:name,user:role,password:passwords[role],connectionTimeoutMillis:5000,statement_timeout:10000});
    };
    const owner = connect('fixlevelup_migrator'), db = connect('fixlevelup_runtime');
    try {
      await owner.connect();
      assert.equal(await isolated(owner,'fixlevelup_migrator',allowedFixture),name);
      // The issuer proof deploys the EXACT capped 021 chain into its fixture
      // databases: a later slice's migrations must never silently enter this
      // proof's schema profile.
      for (const step of migrations.slice(0, migrations.indexOf(migration) + 1)) { await owner.query(sql(step)); }
      await db.connect();
      assert.equal(await isolated(db,'fixlevelup_runtime',allowedFixture),name);
      await inert(owner);
      const ordinary = await addStaff(owner,{role:'ADMIN',login:'p04-proof-ordinary'});
      await owner.query(issueSql); // normal SYSTEM ADMIN is not enough
      await noGrants(owner);
      const founder = await addStaff(owner,{role:'ADMIN',login:'p04-proof-founder',marker:true});
      await deny(transaction(owner,() => owner.query(issueSql),'BEGIN ISOLATION LEVEL REPEATABLE READ'),'40001');
      await deny(db.query(issueSql),'42501');
      await deny(db.query(`INSERT INTO foundation.${personal}(assignment_id,permission_code) VALUES($1,'catalog.read')`,[founder.assignment]),'42501');
      await deny(owner.query(`INSERT INTO foundation.${personal}(assignment_id,permission_code) VALUES($1,'catalog.read')`,[ordinary.assignment]),'23514');
      await owner.query(issueSql);
      const sources = () => rows(owner,`SELECT * FROM foundation.${personal} ORDER BY permission_code COLLATE "C"`);
      const issued = await sources();
      assert.deepEqual(issued,catalogManagementCodes.map(permission_code => ({assignment_id:founder.assignment,permission_code,row_version:1,revoked_at:null,revoked_by:null})));
      await owner.query(issueSql);
      assert.deepEqual(await sources(),issued);
      const revoke = (client, actor, code = 'catalog.read') => client.query(`UPDATE foundation.${personal}
        SET revoked_at='2001-01-01'::timestamptz, revoked_by=$2 WHERE assignment_id=$1 AND permission_code=$3`,[founder.assignment,actor,code]);
      if (prefix === 'configuration_test') {
        const manager = await addStaff(owner,{role:'MANAGER',login:'p04-proof-manager',assignedBy:ordinary.id});
        await deny(revoke(db,ordinary.id),'42501');
        await deny(revoke(owner,manager.id),'23514');
        assert.equal((await revoke(owner,ordinary.id)).rowCount,1);
        await deny(revoke(owner,ordinary.id),'23514');
        await deny(owner.query(`UPDATE foundation.${personal} SET revoked_at=NULL,revoked_by=NULL WHERE permission_code='catalog.read'`),'23514');
        assert.deepEqual(await one(owner,`SELECT row_version,revoked_by,revoked_at>clock_timestamp()-interval '15 seconds'
          AND revoked_at<=clock_timestamp() AS fresh FROM foundation.${personal} WHERE permission_code='catalog.read'`),
        {row_version:2,revoked_by:ordinary.id,fresh:true});
        const revoked = await sources();
        await owner.query(issueSql);
        assert.deepEqual(await sources(),revoked);
        await transaction(owner,async () => {
          await owner.query('UPDATE foundation.staff_role_assignments SET revoked_at=clock_timestamp(),revoked_by=$2 WHERE id=$1',[founder.assignment,ordinary.id]);
          await owner.query(`INSERT INTO foundation.staff_role_assignments(id,staff_id,role_id,assigned_by)
            SELECT $1,$2,id,$3 FROM foundation.roles WHERE role_type='SYSTEM' AND code='ADMIN'`,[randomUUID(),founder.id,ordinary.id]);
        });
        await owner.query(issueSql);
        assert.deepEqual(await sources(),revoked);
        assert.deepEqual(await rows(owner,`SELECT p.assignment_id FROM foundation.${personal} p JOIN foundation.staff_role_assignments a ON a.id=p.assignment_id
          WHERE a.revoked_at IS NULL AND p.revoked_at IS NULL`),[]);
      }
      assert.deepEqual(await rows(owner,'SELECT * FROM foundation.role_permissions WHERE permission_code=ANY($1::text[])',[catalogManagementCodes]),[]);
    } finally { await Promise.all([owner.end(),db.end()]); }
  }
  console.log('021 issuer/revoke: two exact isolated names, runtime and non-eligible denials, initial assignment only, no reissue after revoke/reassignment: PASS');
}
