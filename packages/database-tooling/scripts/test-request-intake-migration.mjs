import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
/** P05-01 (022) migration proof: request intake foundation (schema profile S1).
 *
 * Proves on disposable isolated PostgreSQL databases:
 *  - the fresh 001–022 chain applies cleanly;
 *  - the populated 021 → 022 upgrade adds exactly the P05 tables, keeps the
 *    previous state byte-identical and replays idempotently;
 *  - the runtime column/table grants match the reviewed allowlist exactly;
 *  - the unified GEO/CFG fence rejects an unfenced basis write when another
 *    session holds X or S on (734305,1) — writer-first and reader-first —
 *    and also refuses a session that never took the fence at all (strict
 *    guard: no implicit acquisition), while a fenced write proceeds;
 *  - the request aggregate guards: DELETE refused, identity/immutability
 *    columns refused, status/pointer updates advance row_version, and a
 *    request with its first contact revision is created at row_version 1 in
 *    one transaction through the deferred pointer FK;
 *  - typed history uniqueness and the request_faults category/revision guard.
 */
export const requestIntakeMigration = '20261123000100_request_intake_foundation';

const p05Tables = [
  'request_policy_packages', 'customers', 'requests', 'request_payload_cells',
  'request_contact_revisions', 'request_address_revisions', 'request_appliance_revisions',
  'request_faults', 'request_preference_revisions', 'request_events',
];
const rows = async (db, text, values) => (await db.query(text, values)).rows;
const one = async (db, text, values) => (await rows(db, text, values))[0];
const deny = (query, code, constraint) => assert.rejects(query, { code, ...(constraint ? { constraint } : {}) });
const checks = (table, keys) => keys.map(key => `${table}_${key}_check`);
export const requestIntakeChecks = [
  ...checks('request_policy_packages', ['workflow_version', 'policy_revision', 'metadata_sha256']),
  ...checks('requests', ['type', 'status', 'row_version']),
  ...checks('request_payload_cells', ['kind', 'revision', 'key_id', 'nonce', 'tag', 'ciphertext', 'aad']),
  ...checks('request_contact_revisions', ['revision', 'mode']),
  ...checks('request_address_revisions', ['revision', 'district_pair']),
  ...checks('request_appliance_revisions', ['revision', 'category_kind', 'model_kind', 'model_pair']),
  ...checks('request_faults', ['fault_kind', 'category_kind', 'other_choice']),
  ...checks('request_preference_revisions', ['revision', 'urgency', 'windows']),
  ...checks('request_events', ['actor_type', 'resulting_version', 'command']),
];

async function transaction(db, fn) {
  await db.query('BEGIN ISOLATION LEVEL READ COMMITTED');
  try { const result = await fn(); await db.query('COMMIT'); return result; }
  catch (error) { await db.query('ROLLBACK'); throw error; }
}
const insert = (db, table, values) => db.query(`INSERT INTO foundation.${table}(${Object.keys(values).join(',')})
  VALUES(${Object.keys(values).map((_, i) => `$${i + 1}`).join(',')})`, Object.values(values));

/** Runtime grant allowlist: [table, readable, insertable, updatable]. */
const grantTables = {
  request_policy_packages: ['id workflow_version policy_revision metadata_sha256 metadata created_at', '', ''],
  customers: ['id created_at', 'id', ''],
  requests: ['id public_number type status row_version customer_id city_id intake_city_version_id workflow_package_id intake_policy_revision_id current_contact_revision_id current_address_revision_id current_appliance_revision_id current_preference_revision_id created_at updated_at is_waiting_link',
    'id type status customer_id city_id intake_city_version_id workflow_package_id intake_policy_revision_id current_contact_revision_id current_address_revision_id current_appliance_revision_id current_preference_revision_id',
    'status current_contact_revision_id current_address_revision_id current_appliance_revision_id current_preference_revision_id row_version updated_at'],
  request_payload_cells: ['id request_id kind revision key_id created_at',
    'id request_id kind revision key_id wrapped_dek nonce ciphertext auth_tag aad_context', ''],
  request_contact_revisions: ['id request_id revision mode payload_cell_id created_at', 'id request_id revision mode payload_cell_id', ''],
  request_address_revisions: ['id request_id revision district_id district_row_version payload_cell_id created_at', 'id request_id revision district_id district_row_version payload_cell_id', ''],
  request_appliance_revisions: ['id request_id revision category_id category_kind category_version_id model_id model_kind model_version_id payload_cell_id created_at',
    'id request_id revision category_id category_kind category_version_id model_id model_kind model_version_id payload_cell_id', ''],
  request_faults: ['id request_id appliance_revision_id is_other fault_id fault_kind fault_version_id category_id category_kind',
    'id request_id appliance_revision_id is_other fault_id fault_kind fault_version_id category_id category_kind', ''],
  request_preference_revisions: ['id request_id revision urgency preferred_windows created_at', 'id request_id revision urgency preferred_windows', ''],
  request_events: ['id request_id command principal operation idempotency_key actor_type actor_session_id actor_staff_id resulting_version correlation_id details created_at',
    'id request_id command principal operation idempotency_key actor_type actor_session_id actor_staff_id resulting_version correlation_id details', ''],
};

async function proveGrants(owner, db) {
  for (const [table, [read, insertable, update]] of Object.entries(grantTables)) {
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
    assert.ok(observed.length && observed.every(x => !x.elevated && !x.other), `${table} elevated/foreign ACL`);
    assert.deepEqual(allowed('r'), read === '*' ? observed.map(x => x.name).sort() : columns(read), `SELECT ${table}`);
    assert.deepEqual(allowed('i'), columns(insertable), `INSERT ${table}`);
    assert.deepEqual(allowed('u'), columns(update), `UPDATE ${table}`);
    assert.deepEqual(await one(db, `SELECT pg_get_userbyid(relowner) AS owner,
      has_table_privilege(current_user,oid,'SELECT') AS r,
      has_table_privilege(current_user,oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN,SELECT WITH GRANT OPTION') AS elevated,
      EXISTS(SELECT FROM aclexplode(relacl) x WHERE x.grantee NOT IN (relowner,to_regrole('fixlevelup_runtime')::oid)) AS other
      FROM pg_class WHERE oid=$1::regclass`, [name]), { owner: 'fixlevelup_migrator', r: read === '*', elevated: false, other: false });
    await deny(db.query(`DELETE FROM ${name} WHERE false`), '42501');
    await deny(db.query(`TRUNCATE ${name}`), '42501');
  }
  // History functions stay unreachable for the runtime role.
  const routineAcl = await rows(db, `SELECT proname,pg_get_userbyid(proowner) AS owner,prosecdef,proconfig,
    has_function_privilege(current_user,oid,'EXECUTE') AS r,
    EXISTS(SELECT FROM aclexplode(coalesce(proacl,acldefault('f',proowner))) a WHERE a.grantee<>proowner) AS other
    FROM pg_proc WHERE pronamespace='foundation'::regnamespace AND proname=ANY($1::text[]) ORDER BY proname COLLATE "C"`,
    [['geo_cfg_fence_guard', 'requests_guard', 'request_faults_category_guard', 'request_appliance_revisions_guard_basis', 'request_address_revisions_guard_city', 'request_history_payload_guard']]);
  assert.deepEqual(routineAcl, [
    { proname: 'geo_cfg_fence_guard', owner: 'fixlevelup_migrator', prosecdef: false, proconfig: ['search_path=pg_catalog'], r: false, other: false },
    { proname: 'request_address_revisions_guard_city', owner: 'fixlevelup_migrator', prosecdef: false, proconfig: ['search_path=pg_catalog'], r: false, other: false },
    { proname: 'request_appliance_revisions_guard_basis', owner: 'fixlevelup_migrator', prosecdef: false, proconfig: ['search_path=pg_catalog'], r: false, other: false },
    { proname: 'request_faults_category_guard', owner: 'fixlevelup_migrator', prosecdef: false, proconfig: ['search_path=pg_catalog'], r: false, other: false },
    { proname: 'request_history_payload_guard', owner: 'fixlevelup_migrator', prosecdef: false, proconfig: ['search_path=pg_catalog'], r: false, other: false },
    { proname: 'requests_guard', owner: 'fixlevelup_migrator', prosecdef: false, proconfig: ['search_path=pg_catalog'], r: false, other: false },
  ]);
  // Every P05 history trigger is enabled and statement-level where designed.
  const triggers = await rows(db, `SELECT c.relname AS table,t.tgname,p.proname,t.tgtype::int AS type
    FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_proc p ON p.oid=t.tgfoid
    WHERE c.relnamespace='foundation'::regnamespace AND c.relname=ANY($1::text[]) AND NOT t.tgisinternal
    ORDER BY t.tgname COLLATE "C"`, [p05Tables]);
  const historyTables = p05Tables.filter(t => t !== 'requests');
  const byName = Object.fromEntries(triggers.map(t => [t.tgname, t]));
  for (const name of [...historyTables.map(t => `${t}_immutable`), 'requests_guard']) {
    assert.ok(byName[name], `missing trigger ${name}`);
  }
  const fenceTriggers = await rows(db, `SELECT c.relname AS table,t.tgname
    FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
    WHERE t.tgfoid='foundation.geo_cfg_fence_guard()'::regprocedure AND NOT t.tgisinternal
    ORDER BY c.relname COLLATE "C"`);
  assert.deepEqual(fenceTriggers.map(t => t.table).sort(), [
    'administrative_districts', 'business_settings_versions', 'reference_entries', 'reference_entry_versions',
    'service_area_district_coverage', 'service_area_versions', 'service_areas', 'service_cities', 'service_city_versions',
  ]);
}

/** The fence requires a pre-taken transaction-scoped lock: a session that never
 * called the fence port is refused even with zero contention; a conflicting
 * holder (X or S) refuses everyone else; a fenced write passes. */
async function proveFence(adminPoolLike, connect) {
  // 1. Strict refusal for an unfenced solo writer (owner privileges, no lock).
  let soloRefused = false;
  try { await adminPoolLike.query('UPDATE foundation.service_cities SET row_version=row_version WHERE false'); }
  catch (error) { assert.equal(error.code, '42501', `fence solo: expected 42501, got ${error.code}`); soloRefused = true; }
  assert.ok(soloRefused, 'fence solo: unfenced write unexpectedly allowed');
  console.log('022 unified fence refuses a session that never took the fence (strict, uncontended): PASS');
  // 2. Conflicting holders.
  for (const [mode, lock] of [['writer-first', 'SELECT pg_advisory_xact_lock(734305,1)'],
    ['reader-first', 'SELECT pg_advisory_xact_lock_shared(734305,1)']]) {
    const blocker = connect();
    try {
      await blocker.connect();
      await blocker.query('BEGIN');
      await blocker.query(lock);
      let refused = false;
      try { await adminPoolLike.query('UPDATE foundation.service_cities SET row_version=row_version WHERE false'); }
      catch (error) { assert.equal(error.code, '42501', `fence ${mode}: expected 42501, got ${error.code}`); refused = true; }
      assert.ok(refused, `fence ${mode}: unfenced write unexpectedly allowed`);
      await blocker.query('ROLLBACK');
      console.log(`022 unified fence rejects an unfenced basis write (${mode}): PASS`);
    } finally { await blocker.end(); }
  }
  // 3. A fenced write in the same transaction passes the fence itself (owner
  // connection: the runtime role has no UPDATE on the guarded basis at all).
  await transaction(adminPoolLike, async () => {
    await adminPoolLike.query('SELECT pg_advisory_xact_lock(734305,1)');
    await adminPoolLike.query('UPDATE foundation.service_cities SET row_version=row_version WHERE false');
  });
  console.log('022 fenced basis write passes the fence: PASS');
}

/** Request aggregate + typed history guards on a seeded minimal graph. */
async function proveRequestGuards(owner) {
  // All guarded-basis seeding runs under the fence inside one transaction.
  const seed = await transaction(owner, async () => {
    await owner.query('SELECT pg_advisory_xact_lock(734305,1)');
    const staff = (await rows(owner, 'SELECT id FROM foundation.staff LIMIT 1'))[0]?.id;
    assert.ok(staff, 'seed staff missing');
    const cityId = (await rows(owner, `INSERT INTO foundation.service_cities (id,code)
      VALUES (gen_random_uuid(),$1) RETURNING id`, [`p05-${randomUUID().slice(0, 8)}`]))[0].id;
    const versionId = (await rows(owner, `INSERT INTO foundation.service_city_versions
      (id,city_id,version,display_name,timezone,public_contact,office_hours,reviewed_by)
      VALUES (gen_random_uuid(),$1,1,'P05 proof','Europe/Moscow','p05@example.test','[[],[],[],[],[],[],[]]'::jsonb,$2) RETURNING id`,
      [cityId, staff]))[0].id;
    await owner.query('UPDATE foundation.service_cities SET current_version_id=$2,lifecycle=$3 WHERE id=$1',
      [cityId, versionId, 'ACTIVE']);
    // A district of the SAME city for address-provenance proofs.
    const districtId = (await rows(owner, `INSERT INTO foundation.administrative_districts (id,city_id,code,name)
      VALUES (gen_random_uuid(),$1,$2,'P05 district') RETURNING id,row_version`,
      [cityId, `d${randomUUID().slice(0, 8)}`]))[0];
    // A district of ANOTHER city: the same-city guard must refuse it.
    const otherCityId = (await rows(owner, `INSERT INTO foundation.service_cities (id,code)
      VALUES (gen_random_uuid(),$1) RETURNING id`, [`p06-${randomUUID().slice(0, 8)}`]))[0].id;
    const foreignDistrict = (await rows(owner, `INSERT INTO foundation.administrative_districts (id,city_id,code,name)
      VALUES (gen_random_uuid(),$1,$2,'Foreign district') RETURNING id,row_version`,
      [otherCityId, `f${randomUUID().slice(0, 8)}`]))[0];
    // A published catalog category/brand/model/fault for appliance + fault proofs
    // (019 semantics: a MODEL needs both category and brand parents).
    const categoryId = (await rows(owner, `INSERT INTO foundation.catalog_directory_entries (id,kind,code)
      VALUES (gen_random_uuid(),'CATEGORY',$1) RETURNING id`, [`c${randomUUID().slice(0, 8)}`]))[0].id;
    const categoryVersionId = (await rows(owner, `INSERT INTO foundation.catalog_directory_versions
      (id,entry_id,version,title,reviewed_by) VALUES (gen_random_uuid(),$1,1,'P05 category',$2) RETURNING id`,
      [categoryId, staff]))[0].id;
    await owner.query('UPDATE foundation.catalog_directory_entries SET current_version_id=$2 WHERE id=$1',
      [categoryId, categoryVersionId]);
    const brandId = (await rows(owner, `INSERT INTO foundation.catalog_directory_entries (id,kind,code)
      VALUES (gen_random_uuid(),'BRAND',$1) RETURNING id`, [`b${randomUUID().slice(0, 8)}`]))[0].id;
    const brandVersionId = (await rows(owner, `INSERT INTO foundation.catalog_directory_versions
      (id,entry_id,version,title,reviewed_by) VALUES (gen_random_uuid(),$1,1,'P05 brand',$2) RETURNING id`,
      [brandId, staff]))[0].id;
    await owner.query('UPDATE foundation.catalog_directory_entries SET current_version_id=$2 WHERE id=$1',
      [brandId, brandVersionId]);
    const modelId = (await rows(owner, `INSERT INTO foundation.catalog_directory_entries (id,kind,code,category_id,brand_id)
      VALUES (gen_random_uuid(),'MODEL',$1,$2,$3) RETURNING id`,
      [`m${randomUUID().slice(0, 8)}`, categoryId, brandId]))[0].id;
    const modelVersionId = (await rows(owner, `INSERT INTO foundation.catalog_directory_versions
      (id,entry_id,version,title,reviewed_by) VALUES (gen_random_uuid(),$1,1,'P05 model',$2) RETURNING id`,
      [modelId, staff]))[0].id;
    await owner.query('UPDATE foundation.catalog_directory_entries SET current_version_id=$2 WHERE id=$1',
      [modelId, modelVersionId]);
    const faultId = (await rows(owner, `INSERT INTO foundation.catalog_directory_entries (id,kind,code,category_id)
      VALUES (gen_random_uuid(),'FAULT',$1,$2) RETURNING id`,
      [`flt${randomUUID().slice(0, 8)}`, categoryId]))[0].id;
    const faultVersionId = (await rows(owner, `INSERT INTO foundation.catalog_directory_versions
      (id,entry_id,version,title,reviewed_by) VALUES (gen_random_uuid(),$1,1,'P05 fault',$2) RETURNING id`,
      [faultId, staff]))[0].id;
    await owner.query('UPDATE foundation.catalog_directory_entries SET current_version_id=$2 WHERE id=$1',
      [faultId, faultVersionId]);
    const pkgId = (await rows(owner, `INSERT INTO foundation.request_policy_packages
      (id,workflow_version,policy_revision,metadata_sha256) VALUES (gen_random_uuid(),'wf-r2-p05-v1',$1,$2)
      ON CONFLICT (workflow_version) DO NOTHING RETURNING id`,
      [`p05-policy-${randomUUID().slice(0, 8)}`, 'a'.repeat(64)]))[0]?.id
      ?? (await rows(owner, `SELECT id FROM foundation.request_policy_packages WHERE workflow_version='wf-r2-p05-v1'`))[0].id;
    const customerId = (await rows(owner, 'INSERT INTO foundation.customers (id) VALUES (gen_random_uuid()) RETURNING id'))[0].id;
    return { staff, cityId, versionId, districtId, foreignDistrict, categoryId, categoryVersionId,
      modelId, modelVersionId, faultId, faultVersionId, pkgId, customerId };
  });

  // v1 creation: request + payload + contact history + current pointer in ONE
  // transaction through the deferred pointer FK — row_version stays 1.
  const created = await transaction(owner, async () => {
    const contactId = randomUUID();
    const cellId = randomUUID();
    const requestId = (await rows(owner, `INSERT INTO foundation.requests
      (id,type,status,customer_id,city_id,intake_city_version_id,workflow_package_id,intake_policy_revision_id,current_contact_revision_id)
      VALUES (gen_random_uuid(),'CALLBACK','CALLBACK_REQUIRED',$1,$2,$3,$4,$4,$5) RETURNING id,row_version`,
      [seed.customerId, seed.cityId, seed.versionId, seed.pkgId, contactId]))[0];
    await insert(owner, 'request_payload_cells', {
      id: cellId, request_id: requestId.id, kind: 'CONTACT', revision: 1, key_id: 'k-test-0001',
      wrapped_dek: Buffer.alloc(44), nonce: Buffer.alloc(12), ciphertext: Buffer.alloc(64),
      auth_tag: Buffer.alloc(16), aad_context: 'p05/payload/v1/proof',
    });
    await insert(owner, 'request_contact_revisions', {
      id: contactId, request_id: requestId.id, revision: 1, mode: 'PHONE', payload_cell_id: cellId,
    });
    return requestId;
  });
  assert.equal(created.row_version, 1, 'creation with a pointer must stay at row_version 1');
  const requestId = created.id;
  console.log('022 request created with its first contact revision at row_version 1 (deferred pointer FK): PASS');

  await deny(owner.query('DELETE FROM foundation.requests'), '23514');
  await deny(owner.query('UPDATE foundation.requests SET public_number=public_number+1'), '23514');
  await deny(owner.query(`UPDATE foundation.requests SET intake_policy_revision_id=(SELECT id FROM foundation.request_policy_packages WHERE workflow_version<>'wf-r2-p05-v1' LIMIT 1)`), '23514');
  const advanced = await rows(owner, "UPDATE foundation.requests SET status='MANAGER_REVIEW' WHERE id=$1 RETURNING row_version",
    [requestId]);
  assert.equal(advanced[0].row_version, 2, 'row_version must advance on status change');

  // Payload provenance: a cell of ANOTHER request cannot back a history row.
  const otherCreated = await transaction(owner, async () => {
    const id = (await rows(owner, `INSERT INTO foundation.requests
      (id,type,status,customer_id,city_id,intake_city_version_id,workflow_package_id,intake_policy_revision_id)
      VALUES (gen_random_uuid(),'CALLBACK','NEW',$1,$2,$3,$4,$4) RETURNING id`,
      [seed.customerId, seed.cityId, seed.versionId, seed.pkgId]))[0].id;
    return id;
  });
  const foreignCell = (await rows(owner, `INSERT INTO foundation.request_payload_cells
    (id,request_id,kind,revision,key_id,wrapped_dek,nonce,ciphertext,auth_tag,aad_context)
    VALUES (gen_random_uuid(),$1,'CONTACT',1,'k-test-0001',$2,$3,$4,$5,'p05/payload/v1/proof') RETURNING id`,
    [otherCreated, Buffer.alloc(44), Buffer.alloc(12), Buffer.alloc(64), Buffer.alloc(16)]))[0].id;
  await deny(insert(owner, 'request_contact_revisions',
    { id: randomUUID(), request_id: requestId, revision: 2, mode: 'PHONE', payload_cell_id: foreignCell }), '23503');

  // Write-time payload provenance: a same-request cell of the WRONG KIND (at
  // the SAME revision, so only the kind differs) or WRONG REVISION cannot back
  // a history row (commit-time refusal, not just a later decrypt failure).
  const wrongKindCell = (await rows(owner, `INSERT INTO foundation.request_payload_cells
    (id,request_id,kind,revision,key_id,wrapped_dek,nonce,ciphertext,auth_tag,aad_context)
    VALUES (gen_random_uuid(),$1,'ADDRESS',3,'k-test-0001',$2,$3,$4,$5,'p05/payload/v1/proof') RETURNING id`,
    [requestId, Buffer.alloc(44), Buffer.alloc(12), Buffer.alloc(64), Buffer.alloc(16)]))[0].id;
  await deny(transaction(owner, async () => {
    await insert(owner, 'request_contact_revisions',
      { id: randomUUID(), request_id: requestId, revision: 3, mode: 'PHONE', payload_cell_id: wrongKindCell });
  }).catch(async error => { await owner.query('ROLLBACK').catch(() => undefined); throw error; }), '23514');
  const wrongRevisionCell = (await rows(owner, `INSERT INTO foundation.request_payload_cells
    (id,request_id,kind,revision,key_id,wrapped_dek,nonce,ciphertext,auth_tag,aad_context)
    VALUES (gen_random_uuid(),$1,'CONTACT',2,'k-test-0001',$2,$3,$4,$5,'p05/payload/v1/proof') RETURNING id`,
    [requestId, Buffer.alloc(44), Buffer.alloc(12), Buffer.alloc(64), Buffer.alloc(16)]))[0].id;
  await deny(transaction(owner, async () => {
    await insert(owner, 'request_contact_revisions',
      { id: randomUUID(), request_id: requestId, revision: 4, mode: 'PHONE', payload_cell_id: wrongRevisionCell });
  }).catch(async error => { await owner.query('ROLLBACK').catch(() => undefined); throw error; }), '23514');
  console.log('022 history payload guard: wrong-kind and wrong-revision cells refused at commit: PASS');

  // Address provenance: the district must belong to the request's city AND be
  // recorded at its current row_version (deferred guard); later district
  // evolution (rename bumps row_version) must NOT block existing writers.
  const addressCell = (await rows(owner, `INSERT INTO foundation.request_payload_cells
    (id,request_id,kind,revision,key_id,wrapped_dek,nonce,ciphertext,auth_tag,aad_context)
    VALUES (gen_random_uuid(),$1,'ADDRESS',1,'k-test-0001',$2,$3,$4,$5,'p05/payload/v1/proof') RETURNING id`,
    [requestId, Buffer.alloc(44), Buffer.alloc(12), Buffer.alloc(64), Buffer.alloc(16)]))[0].id;
  await transaction(owner, async () => {
    await insert(owner, 'request_address_revisions', {
      id: randomUUID(), request_id: requestId, revision: 1,
      district_id: seed.districtId.id, district_row_version: seed.districtId.row_version, payload_cell_id: addressCell,
    });
  });
  console.log('022 address revision with a same-city district at its current revision accepted: PASS');
  await deny(transaction(owner, async () => {
    await insert(owner, 'request_address_revisions', {
      id: randomUUID(), request_id: requestId, revision: 2,
      district_id: seed.foreignDistrict.id, district_row_version: seed.foreignDistrict.row_version,
      payload_cell_id: addressCell,
    });
  }).catch(async error => { await owner.query('ROLLBACK').catch(() => undefined); throw error; }), '23514');
  console.log('022 address revision with a foreign-city district refused: PASS');
  // Partial district pair (id without row_version) is refused by the CHECK.
  await transaction(owner, async () => {
    await deny(insert(owner, 'request_address_revisions', {
      id: randomUUID(), request_id: requestId, revision: 3,
      district_id: seed.districtId.id, district_row_version: null, payload_cell_id: addressCell,
    }), '23514');
  });
  console.log('022 address revision with a partial district pair refused: PASS');
  // A stale recorded row_version (not the district's current one) is refused.
  await deny(transaction(owner, async () => {
    await insert(owner, 'request_address_revisions', {
      id: randomUUID(), request_id: requestId, revision: 4,
      district_id: seed.districtId.id, district_row_version: seed.districtId.row_version + 1,
      payload_cell_id: addressCell,
    });
  }).catch(async error => { await owner.query('ROLLBACK').catch(() => undefined); throw error; }), '23514');
  console.log('022 address revision with a non-current district revision refused: PASS');
  // Historical address must not block district evolution: rename the district
  // (the 011 guard bumps row_version) under the fence — it must succeed.
  await transaction(owner, async () => {
    await owner.query('SELECT pg_advisory_xact_lock(734305,1)');
    await owner.query('UPDATE foundation.administrative_districts SET name=$2 WHERE id=$1',
      [seed.districtId.id, 'Renamed P05 district']);
  });
  const afterRename = (await rows(owner, 'SELECT row_version FROM foundation.administrative_districts WHERE id=$1',
    [seed.districtId.id]))[0];
  assert.ok(afterRename.row_version > seed.districtId.row_version, 'district rename must bump row_version');
  console.log('022 district rename after a stored historical address succeeds (no writer blocking): PASS');

  // Appliance provenance: exact live published category/model revisions; a
  // version of ANOTHER category is refused by the deferred guard (the catalog
  // chain guard makes non-current revisions impossible to store at all, so a
  // wrong-category current revision is the reachable stale/mismatch case).
  const applianceCell = (await rows(owner, `INSERT INTO foundation.request_payload_cells
    (id,request_id,kind,revision,key_id,wrapped_dek,nonce,ciphertext,auth_tag,aad_context)
    VALUES (gen_random_uuid(),$1,'DETAILS',1,'k-test-0001',$2,$3,$4,$5,'p05/payload/v1/proof') RETURNING id`,
    [requestId, Buffer.alloc(44), Buffer.alloc(12), Buffer.alloc(64), Buffer.alloc(16)]))[0].id;
  const applianceOk = randomUUID();
  await transaction(owner, async () => {
    await insert(owner, 'request_appliance_revisions', {
      id: applianceOk, request_id: requestId, revision: 1, category_id: seed.categoryId,
      category_kind: 'CATEGORY', category_version_id: seed.categoryVersionId,
      model_id: seed.modelId, model_kind: 'MODEL', model_version_id: seed.modelVersionId,
      payload_cell_id: applianceCell,
    });
  });
  console.log('022 appliance revision with live published category+model accepted: PASS');
  // A second category+brand+model set for the negative cases.
  const otherCategory = await transaction(owner, async () => {
    const categoryId = (await rows(owner, `INSERT INTO foundation.catalog_directory_entries (id,kind,code)
      VALUES (gen_random_uuid(),'CATEGORY',$1) RETURNING id`, [`x${randomUUID().slice(0, 8)}`]))[0].id;
    const versionId = (await rows(owner, `INSERT INTO foundation.catalog_directory_versions
      (id,entry_id,version,title,reviewed_by) VALUES (gen_random_uuid(),$1,1,'P05 other',$2) RETURNING id`,
      [categoryId, seed.staff]))[0].id;
    await owner.query('UPDATE foundation.catalog_directory_entries SET current_version_id=$2 WHERE id=$1',
      [categoryId, versionId]);
    const brandId = (await rows(owner, `INSERT INTO foundation.catalog_directory_entries (id,kind,code)
      VALUES (gen_random_uuid(),'BRAND',$1) RETURNING id`, [`w${randomUUID().slice(0, 8)}`]))[0].id;
    const brandVersionId = (await rows(owner, `INSERT INTO foundation.catalog_directory_versions
      (id,entry_id,version,title,reviewed_by) VALUES (gen_random_uuid(),$1,1,'P05 other brand',$2) RETURNING id`,
      [brandId, seed.staff]))[0].id;
    await owner.query('UPDATE foundation.catalog_directory_entries SET current_version_id=$2 WHERE id=$1',
      [brandId, brandVersionId]);
    const modelId = (await rows(owner, `INSERT INTO foundation.catalog_directory_entries (id,kind,code,category_id,brand_id)
      VALUES (gen_random_uuid(),'MODEL',$1,$2,$3) RETURNING id`,
      [`y${randomUUID().slice(0, 8)}`, categoryId, brandId]))[0].id;
    const modelVersionId = (await rows(owner, `INSERT INTO foundation.catalog_directory_versions
      (id,entry_id,version,title,reviewed_by) VALUES (gen_random_uuid(),$1,1,'P05 other model',$2) RETURNING id`,
      [modelId, seed.staff]))[0].id;
    await owner.query('UPDATE foundation.catalog_directory_entries SET current_version_id=$2 WHERE id=$1',
      [modelId, modelVersionId]);
    return { categoryId, versionId, modelId, modelVersionId };
  });
  await deny(transaction(owner, async () => {
    await insert(owner, 'request_appliance_revisions', {
      id: randomUUID(), request_id: requestId, revision: 2, category_id: seed.categoryId,
      category_kind: 'CATEGORY', category_version_id: seed.categoryVersionId,
      model_id: otherCategory.modelId, model_kind: 'MODEL', model_version_id: otherCategory.modelVersionId,
      payload_cell_id: applianceCell,
    });
  }).catch(async error => { await owner.query('ROLLBACK').catch(() => undefined); throw error; }), '23514');
  console.log('022 appliance revision with a model of another category refused: PASS');
  // Partial model pair (id without its version) is refused by the CHECK.
  await transaction(owner, async () => {
    await deny(insert(owner, 'request_appliance_revisions', {
      id: randomUUID(), request_id: requestId, revision: 3, category_id: seed.categoryId,
      category_kind: 'CATEGORY', category_version_id: seed.categoryVersionId,
      model_id: seed.modelId, model_kind: 'MODEL', model_version_id: null, payload_cell_id: applianceCell,
    }), '23514');
  });
  console.log('022 appliance revision with a partial model pair refused: PASS');

  // Faults: a published same-category fault is admitted; the "other" choice
  // carries no fault id/version; a wrong-category fault is refused by the
  // category-match guard.
  await transaction(owner, async () => {
    await insert(owner, 'request_faults', {
      id: randomUUID(), request_id: requestId, appliance_revision_id: applianceOk, is_other: false,
      fault_id: seed.faultId, fault_kind: 'FAULT', fault_version_id: seed.faultVersionId,
      category_id: seed.categoryId, category_kind: 'CATEGORY',
    });
    await insert(owner, 'request_faults', {
      id: randomUUID(), request_id: requestId, appliance_revision_id: applianceOk, is_other: true,
      fault_id: null, fault_kind: 'FAULT', fault_version_id: null,
      category_id: seed.categoryId, category_kind: 'CATEGORY',
    });
  });
  console.log('022 request_faults: published same-category fault + explicit other choice admitted: PASS');
  const otherCategoryFault = await transaction(owner, async () => {
    const faultId = (await rows(owner, `INSERT INTO foundation.catalog_directory_entries (id,kind,code,category_id)
      VALUES (gen_random_uuid(),'FAULT',$1,$2) RETURNING id`,
      [`z${randomUUID().slice(0, 8)}`, otherCategory.categoryId]))[0].id;
    const versionId = (await rows(owner, `INSERT INTO foundation.catalog_directory_versions
      (id,entry_id,version,title,reviewed_by) VALUES (gen_random_uuid(),$1,1,'P05 foreign fault',$2) RETURNING id`,
      [faultId, seed.staff]))[0].id;
    await owner.query('UPDATE foundation.catalog_directory_entries SET current_version_id=$2 WHERE id=$1',
      [faultId, versionId]);
    return { faultId, versionId };
  });
  await deny(transaction(owner, async () => {
    await insert(owner, 'request_faults', {
      id: randomUUID(), request_id: requestId, appliance_revision_id: applianceOk, is_other: false,
      fault_id: otherCategoryFault.faultId, fault_kind: 'FAULT', fault_version_id: otherCategoryFault.versionId,
      category_id: otherCategory.categoryId, category_kind: 'CATEGORY',
    });
  }).catch(async error => { await owner.query('ROLLBACK').catch(() => undefined); throw error; }), '23514');
  console.log('022 request_faults: wrong-category fault refused by the category-match guard: PASS');
}

/** Full 022 proof entry point used by the orchestrator on the upgrade DB. */
export async function proveRequestIntakeUpgrade(owner, db, connect) {
  // Inert start: the S1 foundation carries no seeded rows of its own.
  for (const table of ['customers', 'requests', 'request_events', 'request_policy_packages']) {
    assert.deepEqual(await rows(owner, `SELECT * FROM foundation.${table}`), [], `${table} must start empty`);
  }
  await proveGrants(owner, db);
  await proveFence(owner, connect);
  await proveRequestGuards(owner);
  console.log('022 populated upgrade: inert start, exact grants, fence, guards: PASS');
}
