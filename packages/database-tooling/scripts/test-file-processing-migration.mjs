import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { currentFileReservationFixtures } from './test-file-reservations-migration.mjs';

const migration = '20261122000200_file_processing_access';
// Deliberately independent of migration discovery and PostgreSQL's observed inventory.
export const fileProcessingChecks = [
  'file_runtime_epochs_singleton_check', 'file_runtime_epochs_namespace_check', 'file_runtime_epochs_epoch_check',
  'file_runtime_epochs_mode_check', 'file_runtime_epochs_opened_check',
  'file_privacy_controls_versions_check', 'file_privacy_controls_processing_check', 'file_privacy_controls_read_check',
  'file_sanitized_attempts_generation_check', 'file_sanitized_attempts_charge_check', 'file_sanitized_attempts_digest_check',
  'file_sanitized_attempts_lease_check', 'file_sanitized_attempts_key_check', 'file_sanitized_attempts_endpoint_check',
  'file_sanitized_attempts_storage_names_check', 'file_sanitized_attempts_mime_check', 'file_sanitized_attempts_state_check',
  'file_sanitized_attempts_dispatch_check', 'file_sanitized_attempts_verified_check',
  'file_publications_mime_check', 'file_publications_bytes_check', 'file_publications_digest_check',
  'file_publications_engine_version_check', 'file_publications_timestamps_check',
];
const names = ['file_runtime_epochs', 'file_privacy_controls', 'file_sanitized_attempts', 'file_publications'];
const [epochs, controls, attempts, publications] = names.map((name) => `foundation.${name}`);
const oldFiles = ['file_upload_intents', 'file_upload_attempts', 'file_quarantine_objects'];
const guards = ['file_runtime_epochs_guard', 'file_privacy_controls_guard', 'file_sanitized_attempts_guard',
  'file_publications_guard', 'file_processing_history_reject_removal'];
const leaseColumns = ['processing', 'read'].flatMap((kind) => [`${kind}_generation`, `${kind}_lease_id`, `${kind}_expires_at`]);
const attemptInput = ['id', 'intent_id', 'owner_request_session_id', 'quarantine_id', 'generation', 'lease_id',
  'lease_expires_at', 'object_key', 'storage_endpoint', 'storage_bucket', 'storage_region', 'mime', 'charged_bytes', 'expected_sha256'];
const attemptUpdate = ['state', 'verified_bytes', 'verified_sha256'];
const publicationInput = ['id', 'intent_id', 'quarantine_id', 'raw_bytes', 'raw_sha256', 'sanitized_attempt_id',
  'mime', 'served_bytes', 'served_sha256', 'processing_policy_id', 'processing_policy_sha256', 'engine_version',
  'engine_image_sha256', 'defs_sha256', 'defs_built_at'];
const acl = [
  [epochs, ['singleton', 'namespace_id', 'epoch', 'mode', 'opened_at'], [], ['singleton']],
  [controls, ['intent_id', 'row_version', 'access_epoch', ...leaseColumns], ['intent_id'], leaseColumns],
  [attempts, [...attemptInput, ...attemptUpdate, 'created_at', 'dispatched_at'], attemptInput, attemptUpdate],
  [publications, [...publicationInput, 'published_at'], publicationInput, []],
];
const rows = async (db, sql, values) => (await db.query(sql, values)).rows;
const one = async (db, sql, values) => (await rows(db, sql, values))[0];
const history = (db) => rows(db, 'SELECT * FROM foundation._prisma_migrations ORDER BY migration_name');
const rejects = (query, code, constraint) => assert.rejects(query, { code, ...(constraint ? { constraint } : {}) });
const digest = () => createHash('sha256').update(randomUUID()).digest('hex');

export async function proveFileProcessingGrants(runtime) {
  const identity = await one(runtime, 'SELECT current_database() AS db,current_user AS role');
  assert.match(identity.db, /^fixlevelup_p017a_(?:fresh|upgrade)_[a-f0-9]{12}$/);
  assert.equal(identity.role, 'fixlevelup_runtime');
  for (const [table, read, insert, update] of acl) {
    const columns = await rows(runtime, `SELECT attname,
      has_column_privilege(current_user,attrelid,attnum,'SELECT') AS readable,
      has_column_privilege(current_user,attrelid,attnum,'INSERT') AS insertable,
      has_column_privilege(current_user,attrelid,attnum,'UPDATE') AS writable,
      has_column_privilege(current_user,attrelid,attnum,
        'REFERENCES,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION') AS elevated,
      EXISTS(SELECT 1 FROM aclexplode(attacl) a WHERE a.grantee=0) AS public_acl
      FROM pg_attribute WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped`, [table]);
    assert.deepEqual(columns.map(({ attname }) => attname).sort(), [...read].sort(), `${table} columns`);
    for (const column of columns) {
      assert.deepEqual([column.readable, column.insertable, column.writable, column.elevated, column.public_acl],
        [true, insert.includes(column.attname), update.includes(column.attname), false, false], `${table}.${column.attname} ACL`);
    }
    assert.deepEqual(await one(runtime, `SELECT pg_get_userbyid(c.relowner) AS owner, c.relrowsecurity AS rls,
      has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') AS elevated,
      EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee=0) AS public_acl
      FROM pg_class c WHERE c.oid=$1::regclass`, [table]),
    { owner: 'fixlevelup_migrator', rls: false, elevated: false, public_acl: false }, `${table} table ACL`);
    await rejects(runtime.query(`DELETE FROM ${table}`), '42501');
    await rejects(runtime.query(`TRUNCATE ${table}`), '42501');
  }
  for (const sql of [`INSERT INTO ${epochs}(singleton) VALUES(true)`, `UPDATE ${epochs} SET epoch=epoch`,
    `UPDATE ${controls} SET row_version=row_version`, `UPDATE ${controls} SET access_epoch=access_epoch`,
    `INSERT INTO ${controls}(intent_id,row_version) VALUES(gen_random_uuid(),1)`,
    `UPDATE ${attempts} SET expected_sha256=expected_sha256`, `UPDATE ${attempts} SET dispatched_at=dispatched_at`,
    `INSERT INTO ${attempts}(id,created_at) VALUES(gen_random_uuid(),clock_timestamp())`,
    `UPDATE ${publications} SET served_sha256=served_sha256`,
    `INSERT INTO ${publications}(id,published_at) VALUES(gen_random_uuid(),clock_timestamp())`]) {
    await rejects(runtime.query(sql), '42501');
  }
  assert.deepEqual(await rows(runtime, `SELECT p.proname AS name,pg_get_userbyid(p.proowner) AS owner,
    p.prosecdef AS definer,p.proconfig AS config,has_function_privilege(current_user,p.oid,'EXECUTE') AS callable,
    EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0) AS public_acl
    FROM pg_proc p WHERE p.pronamespace='foundation'::regnamespace AND p.proname=ANY($1::text[]) ORDER BY p.proname`, [guards]),
  [...guards].sort().map((name) => ({ name, owner: 'fixlevelup_migrator', definer: false, config: ['search_path=pg_catalog'],
    callable: false, public_acl: false })));
  for (const name of guards) { await rejects(runtime.query(`SELECT foundation.${name}()`), '42501'); }
  console.log('016 runtime: exact column privileges, no table/PUBLIC/guard EXECUTE/removal grants: PASS');
}

// Ordinary populated 015 rows, built using its actual guards and an existing reviewed synthetic city/form.
async function seedRaw(db, fixture) {
  const owner = randomUUID(), consent = randomUUID(), intent = randomUUID(), attempt = randomUUID(), raw = randomUUID();
  const rawSha = digest();
  await db.query(`INSERT INTO foundation.request_sessions(id,secret_hash,intake_city_id,intake_city_version_id,expires_at)
    VALUES($1,$2,$3,$4,clock_timestamp()+interval '30 minutes')`, [owner, digest(), fixture.cityId, fixture.cityVersionId]);
  await db.query(`INSERT INTO foundation.consent_records
    (id,session_id,document_id,document_version_id,purpose,action,legal_basis,source,evidence_ref)
    VALUES($1,$2,$3,$4,'REQUEST_PROCESSING','GIVEN',$5,'FORM',$6)`,
  [consent, owner, fixture.documentId, fixture.versionId, fixture.legalBasis, randomUUID()]);
  await db.query(`INSERT INTO foundation.file_upload_intents
    (id,owner_request_session_id,consent_record_id,consent_document_version_id,consent_purpose,policy_version_id,
     policy_source_ref,policy_sha256,allowed_mime_types,max_file_bytes,max_owner_bytes,max_owner_files,
     policy_expires_at,declared_mime,declared_bytes,expires_at,idempotency_key,body_sha256)
    VALUES($1,$2,$3,$4,'REQUEST_PROCESSING',$5,'synthetic://p0304c/upgrade',$6,'["image/jpeg"]',
     200,1000,5,clock_timestamp()+interval '20 minutes','image/jpeg',100,clock_timestamp()+interval '10 minutes',$7,$8)`,
  [intent, owner, consent, fixture.versionId, randomUUID(), digest(), randomUUID(), digest()]);
  await db.query(`INSERT INTO foundation.file_upload_attempts
    (id,intent_id,owner_request_session_id,idempotency_key,generation,upload_lease_id,upload_lease_expires_at,
     object_key,storage_endpoint,storage_bucket,storage_region,charged_bytes)
    VALUES($1,$2,$3,$4,1,$5,clock_timestamp()+interval '1 minute',$6,'http://127.0.0.1:3900','synthetic-files','local',100)`,
  [attempt, intent, owner, randomUUID(), randomUUID(), `quarantine/${attempt}/${randomUUID()}`]);
  await db.query("UPDATE foundation.file_upload_attempts SET state='IN_FLIGHT' WHERE id=$1", [attempt]);
  await db.query("UPDATE foundation.file_upload_attempts SET state='VERIFIED',verified_bytes=100,verified_sha256=$2 WHERE id=$1", [attempt, rawSha]);
  await db.query(`INSERT INTO foundation.file_quarantine_objects(id,intent_id,attempt_id,actual_bytes,sha256)
    VALUES($1,$2,$3,100,$4)`, [raw, intent, attempt, rawSha]);
  return { owner, intent, raw, rawSha };
}

const foundationTables = async (db) => (await rows(db, `SELECT relname FROM pg_class
  WHERE relnamespace='foundation'::regnamespace AND relkind='r' AND relname<>'_prisma_migrations' ORDER BY relname`)).map(({ relname }) => relname);
async function snapshot(db, tables) {
  const result = {};
  for (const table of tables) {
    result[table] = await rows(db, `SELECT to_jsonb(t)::text AS data FROM foundation."${table.replaceAll('"', '""')}" t ORDER BY 1`);
  }
  return result;
}
const indexes = (db, tableNames) => rows(db, `SELECT c.relname AS table_name,ic.relname AS name,i.indisunique AS unique,
  i.indisvalid AS valid,pg_get_indexdef(i.indexrelid) AS definition
  FROM pg_class c JOIN pg_index i ON i.indrelid=c.oid JOIN pg_class ic ON ic.oid=i.indexrelid
  WHERE c.relnamespace='foundation'::regnamespace AND c.relname=ANY($1::text[]) ORDER BY c.relname,ic.relname`, [tableNames]);
async function oldCatalog(db) {
  return {
    columnsAndAcl: await rows(db, `SELECT c.relname,c.relacl,c.relowner,c.relrowsecurity,
      a.attname,a.attnotnull,a.attacl,format_type(a.atttypid,a.atttypmod) AS type,pg_get_expr(d.adbin,d.adrelid) AS default_expr
      FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
      WHERE c.relnamespace='foundation'::regnamespace AND c.relname=ANY($1::text[]) AND a.attnum>0 AND NOT a.attisdropped
      ORDER BY c.relname,a.attnum`, [oldFiles]),
    constraints: await rows(db, `SELECT c.relname,k.conname,k.convalidated,pg_get_constraintdef(k.oid) AS definition
      FROM pg_class c JOIN pg_constraint k ON k.conrelid=c.oid
      WHERE c.relnamespace='foundation'::regnamespace AND c.relname=ANY($1::text[]) ORDER BY c.relname,k.conname`, [oldFiles]),
    triggers: await rows(db, `SELECT c.relname,g.tgname,g.tgenabled,pg_get_triggerdef(g.oid) AS definition
      FROM pg_class c JOIN pg_trigger g ON g.tgrelid=c.oid
      WHERE c.relnamespace='foundation'::regnamespace AND c.relname=ANY($1::text[]) AND NOT g.tgisinternal
      ORDER BY c.relname,g.tgname`, [oldFiles]),
    indexes: await indexes(db, oldFiles),
  };
}

const change = (db, table, id, set, params = []) => db.query(`UPDATE ${table} SET ${set} WHERE id=$1`, [id, ...params]);
const claim = (db, intent, kind, lease, duration = '1 minute', step = 1) => one(db, `UPDATE ${controls} SET
  ${kind}_generation=${kind}_generation+$2,${kind}_lease_id=$3,${kind}_expires_at=clock_timestamp()+$4::interval
  WHERE intent_id=$1 RETURNING row_version,${kind}_generation AS generation,${kind}_expires_at::text AS expires`, [intent, step, lease, duration]);
const release = (db, intent, kind, lease, generation) => db.query(`UPDATE ${controls} SET ${kind}_lease_id=NULL,${kind}_expires_at=NULL
  WHERE intent_id=$1 AND ${kind}_lease_id=$2 AND ${kind}_generation=$3`, [intent, lease, generation]);
function register(db, parent, lease, options = {}) {
  const { id = randomUUID(), generation = lease.generation, leaseId = lease.id, expires = lease.expires,
    key = `sanitized/${id}/${randomUUID()}`, mime = 'image/jpeg', charged = 80, sha = digest() } = options;
  return one(db, `INSERT INTO ${attempts} (${attemptInput.join(',')})
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,'http://127.0.0.1:3900','synthetic-files','local',$9,$10,$11)
    RETURNING id,state,created_at,dispatched_at,verified_bytes,verified_sha256,expected_sha256,length(object_key) AS key_length`,
  [id, parent.intent, parent.owner, parent.raw, generation, leaseId, expires, key, mime, charged, sha]);
}
const dispatch = (db, id) => change(db, attempts, id, "state='IN_FLIGHT'");
const verify = (db, attempt, bytes = 80, sha = attempt.expected_sha256) => change(db, attempts, attempt.id,
  "state='VERIFIED',verified_bytes=$2,verified_sha256=$3", [bytes, sha]);
function publish(db, parent, attempt, options = {}) {
  const { rawBytes = 100, rawSha = parent.rawSha, mime = 'image/jpeg', servedBytes = 80,
    servedSha = attempt.expected_sha256 } = options;
  return one(db, `INSERT INTO ${publications} (${publicationInput.join(',')})
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'1.4.7',$12,$13,clock_timestamp()-interval '1 minute')
    RETURNING published_at,raw_bytes,raw_sha256,mime,served_bytes,served_sha256`,
  [randomUUID(), parent.intent, parent.raw, rawBytes, rawSha, attempt.id, mime, servedBytes, servedSha, randomUUID(), digest(), digest(), digest()]);
}

async function proveKeys(db, before, after) {
  const newOldIndexes = [
    ['file_upload_intents', 'file_upload_intents_file_owner_key', '(id, owner_request_session_id)'],
    ['file_quarantine_objects', 'file_quarantine_objects_intent_object_key', '(intent_id, id)'],
    ['file_quarantine_objects', 'file_quarantine_objects_raw_tuple_key', '(intent_id, id, actual_bytes, sha256)'],
  ];
  for (const [table_name, name, tuple] of newOldIndexes) {
    const found = after.indexes.find((idx) => idx.name === name);
    assert.ok(found?.table_name === table_name && found.unique && found.valid && found.definition.endsWith(tuple), `${name}: old FK target index`);
  }
  assert.deepEqual({ ...after, indexes: after.indexes.filter((idx) => !newOldIndexes.some((entry) => entry[1] === idx.name)) },
    before, '016 changed prior A/B file columns, ACLs, constraints, triggers or indexes');
  const expectedFks = [
    ['file_privacy_controls_intent_id_fkey', 'file_privacy_controls', '(intent_id)', 'file_upload_intents(id)'],
    ['file_sanitized_attempts_intent_owner_fkey', 'file_sanitized_attempts', '(intent_id, owner_request_session_id)', 'file_upload_intents(id, owner_request_session_id)'],
    ['file_sanitized_attempts_quarantine_fkey', 'file_sanitized_attempts', '(intent_id, quarantine_id)', 'file_quarantine_objects(intent_id, id)'],
    ['file_publications_raw_tuple_fkey', 'file_publications', '(intent_id, quarantine_id, raw_bytes, raw_sha256)',
      'file_quarantine_objects(intent_id, id, actual_bytes, sha256)'],
    ['file_publications_served_tuple_fkey', 'file_publications', '(intent_id, quarantine_id, sanitized_attempt_id, mime, served_bytes, served_sha256)',
      'file_sanitized_attempts(intent_id, quarantine_id, id, mime, verified_bytes, verified_sha256)'],
  ];
  const fks = await rows(db, `SELECT k.conname,c.relname,k.convalidated,k.condeferrable,pg_get_constraintdef(k.oid) AS definition
    FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
    WHERE k.connamespace='foundation'::regnamespace AND c.relname=ANY($1::text[]) AND k.contype='f'`, [names]);
  assert.deepEqual(fks.map((fk) => fk.conname).sort(), expectedFks.map(([name]) => name).sort());
  for (const [conname, relname, source, target] of expectedFks) {
    const fk = fks.find((row) => row.conname === conname);
    assert.equal(fk.relname, relname);
    assert.equal(fk.convalidated, true);
    assert.equal(fk.condeferrable, false);
    assert.equal(fk.definition.replace('REFERENCES foundation.', 'REFERENCES '),
      `FOREIGN KEY ${source} REFERENCES ${target} ON UPDATE RESTRICT ON DELETE RESTRICT`, conname);
  }
  const registry = await indexes(db, ['file_sanitized_attempts']);
  const budget = registry.find((idx) => idx.name === 'file_sanitized_attempts_owner_budget_idx');
  assert.ok(budget?.valid && !budget.unique && budget.definition.endsWith('(owner_request_session_id, state)'));
  const active = registry.find((idx) => idx.name === 'file_sanitized_attempts_active_intent_key');
  assert.ok(active?.valid && active.unique && active.definition.includes('(intent_id) WHERE'));
  assert.deepEqual([...active.definition.matchAll(/'([A-Z_]+)'/g)].map((match) => match[1]).sort(), ['IN_FLIGHT', 'REGISTERED']);
}

async function proveControls(owner, runtime, parent) {
  const namespace = randomUUID();
  const setEpoch = (set) => owner.query(`UPDATE ${epochs} SET ${set} WHERE singleton`);
  const epochChange = (set) => rejects(setEpoch(set), '23514', 'file_runtime_epochs_transition');
  const initEpoch = (mode, singleton = true) => one(owner, `INSERT INTO ${epochs}(singleton,namespace_id,epoch,mode,opened_at)
    VALUES($1,$2,1,$3,'2000-01-01') RETURNING mode,opened_at`, [singleton, namespace, mode]);
  await rejects(initEpoch('FENCED'), '23514', 'file_runtime_epochs_initial_mode');
  await rejects(initEpoch('ACTIVE', false), '23514', 'file_runtime_epochs_singleton_check');
  await rejects(owner.query(`INSERT INTO ${controls}(intent_id,row_version) VALUES($1,2)`, [parent.intent]),
    '23514', 'file_privacy_controls_initial_state');
  const init = await one(runtime, `INSERT INTO ${controls}(intent_id) VALUES($1) RETURNING *`, [parent.intent]);
  assert.deepEqual(init, { intent_id: parent.intent, row_version: '1', access_epoch: '1', processing_generation: 0,
    processing_lease_id: null, processing_expires_at: null, read_generation: 0, read_lease_id: null, read_expires_at: null });
  const acquire = (kind, lease, duration, step) => claim(runtime, parent.intent, kind, lease, duration, step);
  const deniedClaim = (kind, lease, duration, step) => rejects(acquire(kind, lease, duration, step), '23514', `file_privacy_controls_${kind}_claim`);
  const inactive = () => rejects(acquire('processing', randomUUID()), '23514', 'file_privacy_controls_active_runtime');
  await inactive();
  assert.deepEqual(await initEpoch('RESTORE_CLOSED'), { mode: 'RESTORE_CLOSED', opened_at: null });
  // This executes a real row lock under the actual runtime login, with only the lock-column UPDATE grant.
  await runtime.query('BEGIN');
  try {
    assert.deepEqual(await one(runtime, `SELECT namespace_id,epoch,mode FROM ${epochs} WHERE singleton FOR SHARE`),
      { namespace_id: namespace, epoch: '1', mode: 'RESTORE_CLOSED' });
  } finally { await runtime.query('ROLLBACK'); }
  await rejects(runtime.query(`UPDATE ${epochs} SET singleton=singleton WHERE singleton`), '42501');
  assert.deepEqual(await one(owner, `SELECT singleton,namespace_id,epoch,mode,opened_at FROM ${epochs}`),
    { singleton: true, namespace_id: namespace, epoch: '1', mode: 'RESTORE_CLOSED', opened_at: null });
  await inactive();
  await rejects(initEpoch('ACTIVE'), '23505', 'file_runtime_epochs_pkey');
  await epochChange("mode='ACTIVE'");
  await epochChange("mode='FENCED',epoch=2");
  await rejects(setEpoch("mode='ACTIVE',epoch=2,namespace_id=gen_random_uuid()"), '23514', 'file_runtime_epochs_immutable');
  await setEpoch("mode='ACTIVE',epoch=2");
  assert.deepEqual(await one(runtime, `SELECT epoch,mode,opened_at>'2000-01-01'::timestamptz AS db_stamp FROM ${epochs}`),
    { epoch: '2', mode: 'ACTIVE', db_stamp: true });
  await epochChange("mode='FENCED',epoch=3");
  await rejects(owner.query(`UPDATE ${controls} SET access_epoch=2 WHERE intent_id=$1`, [parent.intent]),
    '23514', 'file_privacy_controls_immutable');
  await rejects(runtime.query(`UPDATE ${controls} SET processing_generation=1,processing_lease_id=gen_random_uuid(),
    processing_expires_at=clock_timestamp()+interval '1 minute',read_generation=1,read_lease_id=gen_random_uuid(),
    read_expires_at=clock_timestamp()+interval '1 minute' WHERE intent_id=$1`, [parent.intent]),
  '23514', 'file_privacy_controls_claim_transition');
  for (const kind of ['processing', 'read']) {
    await deniedClaim(kind, randomUUID(), '-1 second');
    await deniedClaim(kind, randomUUID(), '1 minute', 2);
    await rejects(runtime.query(`UPDATE ${controls} SET ${kind}_generation=1,${kind}_lease_id=gen_random_uuid(),
      ${kind}_expires_at='infinity' WHERE intent_id=$1`, [parent.intent]), '23514', `file_privacy_controls_${kind}_claim`);
  }
  // Hold two occupied slots until PostgreSQL's clock passes both expiries; neither expires into NULL.
  for (const [index, kind] of ['processing', 'read'].entries()) {
    const id = randomUUID();
    const { row_version, generation } = await acquire(kind, id, '2 seconds');
    assert.deepEqual([row_version, generation], [String(2 + index), 1]);
    await deniedClaim(kind, id, '1 minute', 0); // no renewal
  }
  await runtime.query(`SELECT pg_sleep_until(greatest(processing_expires_at,read_expires_at)+interval '10 milliseconds')
    FROM ${controls} WHERE intent_id=$1`, [parent.intent]);
  const old = await one(runtime, `SELECT processing_lease_id,read_lease_id FROM ${controls} WHERE intent_id=$1`, [parent.intent]);
  const live = {};
  for (const [index, kind] of ['processing', 'read'].entries()) {
    await deniedClaim(kind, randomUUID());
    await rejects(runtime.query(`UPDATE ${controls} SET ${kind}_lease_id=NULL,${kind}_expires_at=NULL,${kind}_generation=2
      WHERE intent_id=$1`, [parent.intent]), '23514', `file_privacy_controls_${kind}_release`);
    assert.equal((await release(runtime, parent.intent, kind, randomUUID(), 1)).rowCount, 0);
    // A synthetic settled holder: SQL restricts shape, but does not attest to I/O settlement.
    assert.equal((await release(runtime, parent.intent, kind, old[`${kind}_lease_id`], 1)).rowCount, 1);
    const id = randomUUID();
    const next = await acquire(kind, id);
    assert.deepEqual([next.row_version, next.generation], [String(5 + 2 * index), 2]);
    assert.equal((await release(runtime, parent.intent, kind, old[`${kind}_lease_id`], 1)).rowCount, 0);
    live[kind] = { ...next, id };
  }
  return live;
}

async function proveEvidence(owner, runtime, parent, foreign, live) {
  const lease = live.processing;
  const badAttempt = (query, suffix) => rejects(query, '23514', `file_sanitized_attempts_${suffix}`);
  for (const [input, suffix] of [
    [{ generation: lease.generation + 1 }, 'live_claim'], [{ leaseId: randomUUID() }, 'live_claim'],
    [{ expires: '2000-01-01' }, 'live_claim'], [{ key: `rawupload/${randomUUID()}/${randomUUID()}` }, 'key_check'],
    [{ key: `sanitized/${randomUUID()}/${randomUUID()}` }, 'key_check'], [{ charged: 0 }, 'charge_check'],
    [{ charged: '9007199254740992' }, 'charge_check'], [{ sha: 'A'.repeat(64) }, 'digest_check'],
    [{ mime: 'application/pdf' }, 'mime_check'],
  ]) { await badAttempt(register(runtime, parent, lease, input), suffix); }
  await rejects(register(runtime, { ...parent, owner: foreign.owner }, lease), '23503', 'file_sanitized_attempts_intent_owner_fkey');
  await rejects(register(runtime, { ...parent, raw: foreign.raw }, lease), '23503', 'file_sanitized_attempts_quarantine_fkey');
  const first = await register(runtime, parent, lease);
  assert.deepEqual(first, { id: first.id, state: 'REGISTERED', created_at: first.created_at, dispatched_at: null,
    verified_bytes: null, verified_sha256: null, expected_sha256: first.expected_sha256, key_length: 83 });
  assert.ok(first.created_at instanceof Date);
  const badPublication = (data = parent, proof = first, opts) => rejects(publish(runtime, data, proof, opts),
    '23514', 'file_publications_live_verified_claim');
  await badPublication();
  await badAttempt(verify(runtime, first), 'state_transition');
  await badAttempt(change(owner, attempts, first.id, "state='IN_FLIGHT',expected_sha256='" + digest() + "'"), 'immutable');
  await dispatch(runtime, first.id);
  assert.equal((await one(runtime, `SELECT dispatched_at>=created_at AND dispatched_at<lease_expires_at AS db_stamp
    FROM ${attempts} WHERE id=$1`, [first.id])).db_stamp, true);
  await badPublication();
  await badAttempt(change(runtime, attempts, first.id, "state='FAILED_NOBYTES'"), 'state_transition');
  await badAttempt(verify(runtime, first, 79), 'verified_check');
  await badAttempt(verify(runtime, first, 80, digest()), 'verified_check');
  await badAttempt(verify(runtime, first, 80, null), 'verified_check');
  await verify(runtime, first);
  await badAttempt(change(runtime, attempts, first.id, "state='UNKNOWN'"), 'state_transition');
  for (const input of [{ rawBytes: 101 }, { rawSha: digest() }, { mime: 'image/png' }, { servedBytes: 81 }, { servedSha: digest() }]) {
    await badPublication(parent, first, input);
  }
  await badPublication(foreign);
  assert.equal((await runtime.query(`SELECT id FROM ${publications}`)).rowCount, 0);
  // Synthetic evidence exercises DB linkage; it does not prove worker cleanliness, bytes or remote settlement.
  const row = await publish(runtime, parent, first);
  assert.ok(row.published_at instanceof Date);
  assert.deepEqual(row, { published_at: row.published_at, raw_bytes: '100', raw_sha256: parent.rawSha,
    mime: 'image/jpeg', served_bytes: '80', served_sha256: first.expected_sha256 });
  await rejects(publish(runtime, parent, first), '23505'); // one immutable publication for this exact parent and attempt
  await rejects(owner.query(`UPDATE ${publications} SET served_sha256=served_sha256`), '23514', 'file_publications_immutable');
  assert.equal((await release(runtime, parent.intent, 'processing', lease.id, lease.generation)).rowCount, 1);
  assert.equal((await release(runtime, parent.intent, 'read', live.read.id, live.read.generation)).rowCount, 1);
  await badPublication();

  await runtime.query(`INSERT INTO ${controls}(intent_id) VALUES($1)`, [foreign.intent]);
  const id = randomUUID();
  const expiring = { ...await claim(runtime, foreign.intent, 'processing', id, '2 seconds'), id };
  const existing = await register(runtime, foreign, expiring);
  await runtime.query(`SELECT pg_sleep_until(lease_expires_at+interval '10 milliseconds') FROM ${attempts} WHERE id=$1`, [existing.id]);
  await badAttempt(dispatch(runtime, existing.id), 'live_claim');
  await badAttempt(register(runtime, foreign, expiring), 'live_claim');
  assert.equal((await release(runtime, foreign.intent, 'processing', id, expiring.generation)).rowCount, 1);
  const nextId = randomUUID();
  const next = { ...await claim(runtime, foreign.intent, 'processing', nextId), id: nextId };
  await rejects(register(runtime, foreign, next), '23505', 'file_sanitized_attempts_active_intent_key');
  await change(runtime, attempts, existing.id, "state='FAILED_NOBYTES'");
  const pending = await register(runtime, foreign, next);
  await dispatch(runtime, pending.id);
  await owner.query(`UPDATE ${epochs} SET mode='FENCED' WHERE singleton`);
  await badAttempt(verify(runtime, pending), 'live_claim');
  await badAttempt(register(runtime, foreign, next), 'live_claim');
  await change(runtime, attempts, pending.id, "state='UNKNOWN'");
  await badAttempt(dispatch(runtime, pending.id), 'state_transition');
  await rejects(owner.query(`UPDATE ${epochs} SET mode='ACTIVE',epoch=epoch+1`), '23514', 'file_runtime_epochs_transition');
  await badPublication();
  for (const table of [epochs, controls, attempts, publications]) {
    await rejects(owner.query(`DELETE FROM ${table}`), '23514', 'file_processing_history_immutable');
  }
  await rejects(owner.query(`TRUNCATE ${[epochs, controls, attempts, publications].join(',')}`), '23514', 'file_processing_history_immutable');
}

export async function proveFileProcessingUpgrade(owner, runtime, deploy, diff, schemaDiff) {
  const identity = await one(owner, 'SELECT current_database() AS db,current_user AS role');
  assert.match(identity.db, /^fixlevelup_p017a_upgrade_[a-f0-9]{12}$/);
  assert.equal(identity.role, 'fixlevelup_migrator');
  assert.equal((await one(runtime, 'SELECT current_database() AS db')).db, identity.db);
  const before = await history(owner);
  assert.equal(before.length, 15);
  assert.equal(before.at(-1).migration_name, '20261122000100_file_upload_attempts');
  const fixture = await currentFileReservationFixtures(owner);
  const parent = await seedRaw(owner, fixture);
  const foreign = await seedRaw(owner, fixture);
  const oldTables = await foundationTables(owner);
  const oldRows = await snapshot(owner, oldTables);
  const oldStructure = await oldCatalog(owner);
  deploy();
  const applied = await history(owner);
  assert.equal(applied.length, 16);
  assert.equal(applied.at(-1).migration_name, migration);
  assert.ok(applied.at(-1).finished_at instanceof Date);
  assert.deepEqual(applied.slice(0, 15), before);
  const allTables = [...oldTables, ...names].sort();
  assert.deepEqual(await foundationTables(owner), allTables, '016 table inventory');
  assert.deepEqual(await snapshot(owner, oldTables), oldRows, '016 modified populated 015 data');
  assert.deepEqual(await snapshot(owner, names), Object.fromEntries(names.map((name) => [name, []])), '016 must not seed or backfill');
  const checks = await rows(owner, `SELECT k.conname,k.convalidated FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
    WHERE k.connamespace='foundation'::regnamespace AND c.relname=ANY($1::text[]) AND k.contype='c' ORDER BY k.conname`, [names]);
  assert.deepEqual(checks, [...fileProcessingChecks].sort().map((conname) => ({ conname, convalidated: true })));
  await proveKeys(owner, oldStructure, await oldCatalog(owner));
  await proveFileProcessingGrants(runtime);
  await proveEvidence(owner, runtime, parent, foreign, await proveControls(owner, runtime, parent));
  const populated = await snapshot(owner, allTables);
  deploy();
  assert.deepEqual(await history(owner), applied, '016 replay modified migration history');
  assert.deepEqual(await snapshot(owner, allTables), populated, '016 replay modified populated rows');
  diff(0);
  await owner.query(`ALTER TABLE ${publications} ADD COLUMN p017a_drift_probe integer`);
  try { diff(2); } finally { await owner.query(`ALTER TABLE ${publications} DROP COLUMN p017a_drift_probe`); }
  diff(0);
  schemaDiff();
  console.log('016 populated upgrade: old rows/catalog, exact FKs, epoch/claim/attempt/publication guards, replay and restored drift: PASS');
}
