import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { currentFileReservationFixtures } from './test-file-reservations-migration.mjs';

// Independent inventory: dropping, renaming, or leaving any guard NOT VALID fails.
export const fileUploadChecks = [
  'file_upload_attempts_generation_check', 'file_upload_attempts_charge_check',
  'file_upload_attempts_upload_lease_check', 'file_upload_attempts_key_check',
  'file_upload_attempts_endpoint_check', 'file_upload_attempts_storage_names_check',
  'file_upload_attempts_state_check', 'file_upload_attempts_dispatch_check',
  'file_upload_attempts_verified_check', 'file_upload_attempts_probe_check',
  'file_upload_attempts_observation_check',
];
const attempts = 'foundation.file_upload_attempts';
const bindings = 'foundation.file_quarantine_objects';
const migration = '20261122000100_file_upload_attempts';
const parentIndex = 'file_upload_intents_attempt_basis_key';
const hash = 'a'.repeat(64);
const digest = () => createHash('sha256').update(randomUUID()).digest('hex');
const attemptInsert = ['id', 'intent_id', 'owner_request_session_id', 'idempotency_key', 'generation',
  'upload_lease_id', 'upload_lease_expires_at', 'object_key', 'storage_endpoint', 'storage_bucket', 'storage_region', 'charged_bytes'];
const attemptUpdate = ['state', 'verified_bytes', 'verified_sha256', 'probe_generation', 'probe_held_slots',
  'probe_lease_id', 'probe_lease_expires_at', 'observation', 'observed_bytes', 'observed_sha256'];
const bindingInsert = ['id', 'intent_id', 'attempt_id', 'actual_bytes', 'sha256'];
const guards = ['file_upload_attempts_guard', 'file_quarantine_objects_guard', 'file_upload_history_reject_removal'];

const rows = async (db, sql, values) => (await db.query(sql, values)).rows;
const one = async (db, sql, values) => (await rows(db, sql, values))[0];
const history = (db) => rows(db, 'SELECT * FROM foundation._prisma_migrations ORDER BY migration_name');
async function rejects(query, code, constraint) {
  await assert.rejects(query, { code, ...(constraint ? { constraint } : {}) });
}

// The proof uses ordinary synthetic 014 rows rather than bypassing constraints or
// importing ports. Staff, city and current legal form/version come from existing proofs.
async function reserve(db, fixtures, count = 1) {
  const owner = randomUUID(), evidence = randomUUID();
  await db.query(`INSERT INTO foundation.request_sessions(id,secret_hash,intake_city_id,intake_city_version_id,expires_at)
    VALUES($1,$2,$3,$4,clock_timestamp()+interval '30 minutes')`,
  [owner, digest(), fixtures.cityId, fixtures.cityVersionId]);
  await db.query(`INSERT INTO foundation.consent_records
    (id,session_id,document_id,document_version_id,purpose,action,legal_basis,source,evidence_ref)
    VALUES($1,$2,$3,$4,'REQUEST_PROCESSING','GIVEN',$5,'FORM',$6)`,
  [evidence, owner, fixtures.documentId, fixtures.versionId, fixtures.legalBasis, randomUUID()]);
  const result = [];
  for (let i = 0; i < count; i += 1) {
    const intent = randomUUID();
    await db.query(`INSERT INTO foundation.file_upload_intents
      (id,owner_request_session_id,consent_record_id,consent_document_version_id,consent_purpose,policy_version_id,
       policy_source_ref,policy_sha256,allowed_mime_types,max_file_bytes,max_owner_bytes,max_owner_files,
       policy_expires_at,declared_mime,declared_bytes,expires_at,idempotency_key,body_sha256)
      VALUES($1,$2,$3,$4,'REQUEST_PROCESSING',$5,'synthetic://upload-policy/p0304b2',$6,'["image/jpeg"]',
        200,1000,5,clock_timestamp()+interval '20 minutes','image/jpeg',100,clock_timestamp()+interval '10 minutes',$7,$8)`,
    [intent, owner, evidence, fixtures.versionId, randomUUID(), digest(), randomUUID(), digest()]);
    result.push({ intent, owner });
  }
  return result;
}

function register(db, parent, options = {}) {
  const { id = randomUUID(), key = randomUUID(), generation = 1, lifetime = '1 minute',
    objectKey = `quarantine/${id}/${randomUUID()}`, endpoint = 'http://127.0.0.1:3900',
    bucket = 'synthetic-files', region = 'local', charge = 100, extra = '' } = options;
  const [column, expression] = extra.split('=');
  return one(db, `INSERT INTO ${attempts} (${attemptInsert.join(',')}${extra ? `,${column}` : ''})
    VALUES($1,$2,$3,$4,$5,$6,clock_timestamp()+$7::interval,$8,$9,$10,$11,$12${extra ? `,${expression}` : ''})
    RETURNING id,object_key,state,created_at,dispatched_at,verified_bytes,verified_sha256,probe_generation,probe_held_slots,
      probe_lease_id,probe_lease_expires_at,observed_at,observation,observed_bytes,observed_sha256`,
  [id, parent.intent, parent.owner, key, generation, randomUUID(), lifetime, objectKey, endpoint, bucket, region, charge]);
}
const update = (db, id, set, values = []) => db.query(`UPDATE ${attempts} SET ${set} WHERE id=$1`, [id, ...values]);
const dispatch = (db, id) => update(db, id, "state='IN_FLIGHT'");
const verify = (db, id, charge = 100, sha = hash) => update(db, id,
  "state='VERIFIED',verified_bytes=$2,verified_sha256=$3", [charge, sha]);
const quarantine = (db, parent, attempt, actual = 100, sha = hash) => one(db, `INSERT INTO ${bindings}
  (id,intent_id,attempt_id,actual_bytes,sha256) VALUES($1,$2,$3,$4,$5) RETURNING id,created_at`,
[randomUUID(), parent.intent, attempt, actual, sha]);
const claim = (db, id, lease, lifetime = '1 minute') => update(db, id,
  `probe_generation=probe_generation+1,probe_held_slots=probe_held_slots+1,probe_lease_id=$2,
   probe_lease_expires_at=clock_timestamp()+$3::interval`, [lease, lifetime]);
const finish = (db, id, observation, actual = null, sha = null) => update(db, id,
  `probe_held_slots=probe_held_slots-1,probe_lease_id=NULL,probe_lease_expires_at=NULL,
   observation=$2,observed_bytes=$3,observed_sha256=$4`, [observation, actual, sha]);

export async function proveFileUploadGrants(db, fixtures) {
  assert.match((await one(db, 'SELECT current_database() AS db')).db, /^fixlevelup_p017a_fresh_[a-f0-9]{12}$/);
  for (const [table, select, insert, write] of [
    [attempts, [...attemptInsert, ...attemptUpdate, 'created_at', 'dispatched_at', 'observed_at'], attemptInsert, attemptUpdate],
    [bindings, [...bindingInsert, 'created_at'], bindingInsert, []],
  ]) {
    const columns = await rows(db, `SELECT attname,
      has_column_privilege(current_user,attrelid,attnum,'SELECT') AS can_read,
      has_column_privilege(current_user,attrelid,attnum,'INSERT') AS can_insert,
      has_column_privilege(current_user,attrelid,attnum,'UPDATE') AS can_update,
      has_column_privilege(current_user,attrelid,attnum,
        'REFERENCES,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION') AS elevated,
      EXISTS(SELECT 1 FROM aclexplode(attacl) acl WHERE acl.grantee=0) AS public_acl
      FROM pg_attribute WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped`, [table]);
    assert.deepEqual(columns.map((column) => column.attname).sort(), [...select].sort(), `${table}: column inventory`);
    for (const column of columns) {
      assert.deepEqual([column.can_read, column.can_insert, column.can_update, column.elevated, column.public_acl],
        [true, insert.includes(column.attname), write.includes(column.attname), false, false], `${table}.${column.attname}: ACL`);
    }
    assert.deepEqual(await one(db, `SELECT
      has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') AS elevated,
      EXISTS(SELECT 1 FROM aclexplode(c.relacl) acl WHERE acl.grantee=0) AS public_acl,
      c.relrowsecurity AS rls, pg_get_userbyid(c.relowner) AS owner
      FROM pg_class c WHERE c.oid=$1::regclass`, [table]),
    { elevated: false, public_acl: false, rls: false, owner: 'fixlevelup_migrator' }, `${table}: table security`);
    for (const sql of [`DELETE FROM ${table}`, `TRUNCATE ${table}`, `UPDATE ${table} SET id=id`,
      `INSERT INTO ${table}(id,created_at) VALUES(gen_random_uuid(),clock_timestamp())`]) {
      await rejects(db.query(sql), '42501');
    }
  }
  const functions = await rows(db, `SELECT p.proname AS name,pg_get_userbyid(p.proowner) AS owner,
    p.prosecdef AS definer,p.proconfig AS config,has_function_privilege(current_user,p.oid,'EXECUTE') AS callable,
    EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.grantee=0) AS public_acl
    FROM pg_proc p WHERE p.pronamespace='foundation'::regnamespace AND p.proname=ANY($1::text[]) ORDER BY p.proname`, [guards]);
  assert.deepEqual(functions, [...guards].sort().map((name) => ({ name, owner: 'fixlevelup_migrator', definer: false,
    config: ['search_path=pg_catalog'], callable: false, public_acl: false })));
  for (const name of guards) { await rejects(db.query(`SELECT foundation.${name}()`), '42501'); }
  for (const sql of [`UPDATE ${attempts} SET object_key=object_key`, `UPDATE ${attempts} SET dispatched_at=dispatched_at`,
    `UPDATE ${attempts} SET observed_at=observed_at`, `UPDATE ${bindings} SET sha256=sha256`]) {
    await rejects(db.query(sql), '42501');
  }

  // This demonstrates actual column-level permissions, not just the ACL inspection.
  // The digest and bytes are synthetic inputs: SQL proves linkage, not S3 or raw F proof.
  const [parent, probeParent] = await reserve(db, fixtures, 2);
  const stored = await register(db, parent);
  assert.deepEqual(stored, { id: stored.id, object_key: stored.object_key, state: 'REGISTERED',
    created_at: stored.created_at, dispatched_at: null, verified_bytes: null, verified_sha256: null,
    probe_generation: 0, probe_held_slots: 0, probe_lease_id: null, probe_lease_expires_at: null,
    observed_at: null, observation: null, observed_bytes: null, observed_sha256: null });
  assert.ok(stored.created_at instanceof Date);
  await dispatch(db, stored.id);
  await verify(db, stored.id);
  assert.ok((await quarantine(db, parent, stored.id)).created_at instanceof Date);
  const probe = await register(db, probeParent);
  await dispatch(db, probe.id);
  await update(db, probe.id, "state='UNKNOWN'");
  await claim(db, probe.id, randomUUID());
  await finish(db, probe.id, 'NOT_OBSERVED');
  assert.deepEqual(await one(db, `SELECT state,probe_held_slots,observation,charged_bytes FROM ${attempts} WHERE id=$1`, [probe.id]),
    { state: 'UNKNOWN', probe_held_slots: 0, observation: 'NOT_OBSERVED', charged_bytes: '100' });
  console.log('015 runtime: exact new column ACL, no callable guards/PUBLIC/removal, verified binding and UNKNOWN probe: PASS');
}

async function snapshotRows(db, tables) {
  const result = {};
  for (const { name } of tables) {
    // The identifier source is pg_catalog; quote even though current names are ASCII.
    result[name] = (await rows(db, `SELECT to_jsonb(t)::text AS data FROM foundation."${name.replaceAll('"', '""')}" t ORDER BY 1`));
  }
  return result;
}

async function catalog(db, names) {
  const table = 'c.relname=ANY($1::text[]) AND c.relnamespace=\'foundation\'::regnamespace';
  return {
    tables: await rows(db, `SELECT c.relname, c.relacl, c.relowner, c.relrowsecurity, c.relforcerowsecurity
      FROM pg_class c WHERE ${table} ORDER BY c.relname`, [names]),
    columns: await rows(db, `SELECT c.relname,a.attname,format_type(a.atttypid,a.atttypmod) AS type,a.attnotnull,a.attacl,
        pg_get_expr(d.adbin,d.adrelid) AS default_expr
      FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
      WHERE ${table} AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum`, [names]),
    constraints: await rows(db, `SELECT c.relname,k.conname,k.convalidated,pg_get_constraintdef(k.oid) AS definition
      FROM pg_class c JOIN pg_constraint k ON k.conrelid=c.oid WHERE ${table} ORDER BY c.relname,k.conname`, [names]),
    indexes: await rows(db, `SELECT c.relname,idx.relname AS name,i.indisunique AS unique,i.indisvalid AS valid,
        pg_get_indexdef(i.indexrelid) AS definition
      FROM pg_class c JOIN pg_index i ON i.indrelid=c.oid JOIN pg_class idx ON idx.oid=i.indexrelid
      WHERE ${table} ORDER BY c.relname,idx.relname`, [names]),
    triggers: await rows(db, `SELECT c.relname,g.tgname,g.tgenabled,pg_get_triggerdef(g.oid) AS definition
      FROM pg_class c JOIN pg_trigger g ON g.tgrelid=c.oid
      WHERE ${table} AND NOT g.tgisinternal ORDER BY c.relname,g.tgname`, [names]),
  };
}
const foundationTables = (db) => rows(db, `SELECT relname AS name FROM pg_class
  WHERE relnamespace='foundation'::regnamespace AND relkind='r' AND relname<>'_prisma_migrations' ORDER BY relname`);

async function proveOwnerGuards(db, parents, foreign) {
  const [parent, sibling, probeParent, expiringParent] = parents;
  const attemptGuard = (query, name) => rejects(query, '23514', `file_upload_attempts_${name}`);
  for (const [options, name] of [
    [{ generation: 0 }, 'generation_check'], [{ charge: 0 }, 'charge_check'],
    [{ charge: '9007199254740992' }, 'charge_check'], [{ lifetime: '-1 second' }, 'upload_lease_check'],
    [{ objectKey: `quarantine/${randomUUID()}/${randomUUID()}` }, 'key_check'],
    [{ id: '1'.repeat(8) + '-1111-4111-8111-111111111111', objectKey: 'quarantine/11111111-1111-4111-8111-111111111111/11111111-1111-1111-8111-111111111111' }, 'key_check'],
    [{ endpoint: 'http://127.0.0.1:0655' }, 'endpoint_check'], [{ endpoint: 'http://127.0.0.1:65536' }, 'endpoint_check'],
    [{ endpoint: 'http://127.0.0.1:3900/' }, 'endpoint_check'], [{ bucket: 'BadBucket' }, 'storage_names_check'],
    [{ region: '-bad' }, 'storage_names_check'], [{ extra: "state='IN_FLIGHT'" }, 'initial_state'],
    [{ extra: 'probe_held_slots=1' }, 'initial_state'],
  ]) { await attemptGuard(register(db, parent, options), name); }
  for (const forgedParent of [{ ...parent, owner: foreign.owner }, { ...parent, intent: randomUUID() }]) {
    await rejects(register(db, forgedParent), '23503', 'file_upload_attempts_intent_basis_fkey');
  }
  await rejects(register(db, parent, { charge: 101 }), '23503', 'file_upload_attempts_intent_basis_fkey');

  const key = randomUUID();
  const first = await register(db, parent, { key, extra: "created_at='2000-01-01T00:00:00Z'" });
  assert.ok(first.created_at.getUTCFullYear() > 2000, 'attempt creation stamp is DB-owned');
  await rejects(register(db, sibling, { key }), '23505', 'file_upload_attempts_owner_idempotency_key');
  const otherOwner = await register(db, foreign, { key });
  assert.equal(otherOwner.state, 'REGISTERED', 'same key is independently scoped to another owner');
  await rejects(register(db, parent, { generation: 2 }), '23505', 'file_upload_attempts_active_intent_key');
  await rejects(quarantine(db, parent, first.id), '23503', 'file_quarantine_objects_verified_attempt_fkey');
  for (const changed of ['id=gen_random_uuid()', 'intent_id=gen_random_uuid()', 'owner_request_session_id=gen_random_uuid()',
    'generation=generation+1', 'idempotency_key=gen_random_uuid()', 'upload_lease_id=gen_random_uuid()',
    "upload_lease_expires_at=upload_lease_expires_at+interval '1 second'", "object_key='quarantine/'||id::text||'/'||gen_random_uuid()::text",
    "storage_endpoint='http://127.0.0.1:3901'", "storage_bucket='other-bucket'", "storage_region='other'", 'charged_bytes=101',
    "created_at='2000-01-01'", 'dispatched_at=clock_timestamp()', 'observed_at=clock_timestamp()']) {
    await attemptGuard(update(db, first.id, `state='IN_FLIGHT',${changed}`), 'immutable');
  }
  await attemptGuard(verify(db, first.id), 'state_transition');
  await attemptGuard(claim(db, first.id, randomUUID()), 'probe_transition');
  await update(db, first.id, "state='FAILED_NOBYTES'");
  await attemptGuard(dispatch(db, first.id), 'state_transition');
  await rejects(register(db, parent), '23505', 'file_upload_attempts_intent_generation_key');
  const live = await register(db, parent, { generation: 2 });
  assert.notEqual(live.object_key, first.object_key);
  await dispatch(db, live.id);
  assert.equal((await one(db, `SELECT dispatched_at>=created_at AND dispatched_at<upload_lease_expires_at AS valid
    FROM ${attempts} WHERE id=$1`, [live.id])).valid, true);
  await rejects(register(db, parent, { generation: 3 }), '23505', 'file_upload_attempts_active_intent_key');
  await attemptGuard(update(db, live.id, "state='FAILED_NOBYTES'"), 'state_transition');
  await attemptGuard(verify(db, live.id, 99), 'verified_check');
  await attemptGuard(verify(db, live.id, 100, 'A'.repeat(64)), 'verified_check');
  await verify(db, live.id);
  await attemptGuard(update(db, live.id, "state='UNKNOWN'"), 'state_transition');
  for (const [target, bytes, sha] of [[sibling, 100, hash], [parent, 99, hash], [parent, 100, 'b'.repeat(64)]]) {
    await rejects(quarantine(db, target, live.id, bytes, sha), '23503', 'file_quarantine_objects_verified_attempt_fkey');
  }
  const binding = await quarantine(db, parent, live.id);
  assert.ok(binding.created_at instanceof Date);
  const secondVerified = await register(db, parent, { generation: 3 });
  await dispatch(db, secondVerified.id);
  await verify(db, secondVerified.id);
  await rejects(quarantine(db, parent, secondVerified.id), '23505', 'file_quarantine_objects_intent_id_key');
  await rejects(db.query(`UPDATE ${bindings} SET sha256=$2 WHERE id=$1`, [binding.id, digest()]),
    '23514', 'file_quarantine_objects_immutable');
  for (const sql of [`DELETE FROM ${attempts}`, `DELETE FROM ${bindings}`, `TRUNCATE ${bindings}`, `TRUNCATE ${attempts},${bindings}`]) {
    await rejects(db.query(sql), '23514', 'file_upload_history_immutable');
  }

  // Build distinct expiration paths under one old transaction timestamp. The update
  // decisions must use the fresh database clock, not the transaction-start instant.
  await db.query('BEGIN');
  try {
    const expiredRegistration = await register(db, expiringParent, { lifetime: '2 seconds' });
    const expiredDispatch = await register(db, probeParent, { lifetime: '2 seconds' });
    await dispatch(db, expiredDispatch.id);
    await db.query(`SELECT pg_sleep_until(max(upload_lease_expires_at)+interval '10 milliseconds')
      FROM ${attempts} WHERE id=ANY($1::uuid[])`, [[expiredRegistration.id, expiredDispatch.id]]);
    for (const test of [() => dispatch(db, expiredRegistration.id), () => verify(db, expiredDispatch.id)]) {
      await db.query('SAVEPOINT live_lease_proof');
      await attemptGuard(test(), 'live_lease');
      await db.query('ROLLBACK TO SAVEPOINT live_lease_proof');
      await db.query('RELEASE SAVEPOINT live_lease_proof');
    }
    await db.query('COMMIT');
    // An expired active marker still excludes replacement, until explicitly retired.
    await rejects(register(db, expiringParent, { generation: 2 }), '23505', 'file_upload_attempts_active_intent_key');
    await update(db, expiredRegistration.id, "state='FAILED_NOBYTES'");
    assert.equal((await register(db, expiringParent, { generation: 2 })).state, 'REGISTERED');
    await update(db, expiredDispatch.id, "state='UNKNOWN'");
    await attemptGuard(dispatch(db, expiredDispatch.id), 'state_transition');
    await attemptGuard(verify(db, expiredDispatch.id), 'state_transition');
    await attemptGuard(finish(db, expiredDispatch.id, 'NOT_OBSERVED'), 'probe_finish');
    const oldClaim = randomUUID(), replacement = randomUUID();
    await claim(db, expiredDispatch.id, oldClaim, '1500 milliseconds');
    await attemptGuard(claim(db, expiredDispatch.id, replacement), 'probe_claim');
    await db.query(`SELECT pg_sleep_until(probe_lease_expires_at+interval '10 milliseconds') FROM ${attempts} WHERE id=$1`,
      [expiredDispatch.id]);
    await attemptGuard(finish(db, expiredDispatch.id, 'NOT_OBSERVED'), 'probe_finish');
    await claim(db, expiredDispatch.id, replacement);
    const stale = await db.query(`UPDATE ${attempts} SET probe_lease_id=NULL,probe_lease_expires_at=NULL,
      observation='NOT_OBSERVED' WHERE id=$1 AND probe_lease_id=$2 AND probe_generation=1`, [expiredDispatch.id, oldClaim]);
    assert.equal(stale.rowCount, 0, 'the stale coordinator CAS no longer matches');
    await attemptGuard(finish(db, expiredDispatch.id, 'PRESENT', 101, hash), 'observation_check');
    await attemptGuard(finish(db, expiredDispatch.id, 'NOT_OBSERVED', 100, hash), 'observation_check');
    await finish(db, expiredDispatch.id, 'PRESENT', 100, hash);
    const unknown = await one(db, `SELECT state,charged_bytes,probe_generation,probe_held_slots,probe_lease_id,
      observed_at,observation,observed_bytes,observed_sha256,verified_sha256 FROM ${attempts} WHERE id=$1`, [expiredDispatch.id]);
    assert.ok(unknown.observed_at instanceof Date);
    assert.deepEqual(unknown, { state: 'UNKNOWN', charged_bytes: '100', probe_generation: 2, probe_held_slots: 1,
      probe_lease_id: null, observed_at: unknown.observed_at, observation: 'PRESENT', observed_bytes: '100',
      observed_sha256: hash, verified_sha256: null });
    await rejects(quarantine(db, probeParent, expiredDispatch.id), '23503', 'file_quarantine_objects_verified_attempt_fkey');
  } finally { await db.query('ROLLBACK'); }
}

export async function proveFileUploadUpgrade(db, deploy, diff, schemaDiff) {
  const identity = await one(db, 'SELECT current_database() AS db,current_user AS role');
  assert.match(identity.db, /^fixlevelup_p017a_upgrade_[a-f0-9]{12}$/);
  assert.equal(identity.role, 'fixlevelup_migrator');
  const beforeHistory = await history(db);
  assert.equal(beforeHistory.length, 14);
  assert.equal(beforeHistory.at(-1).migration_name, '20261121000500_file_upload_reservations');
  const fixtures = await currentFileReservationFixtures(db);
  const parents = await reserve(db, fixtures, 4);
  const [foreign] = await reserve(db, fixtures);
  const beforeTables = await foundationTables(db);
  const names = beforeTables.map(({ name }) => name);
  const beforeRows = await snapshotRows(db, beforeTables);
  const beforeCatalog = await catalog(db, names);
  deploy();
  const afterHistory = await history(db);
  assert.equal(afterHistory.length, 15);
  assert.equal(afterHistory.at(-1).migration_name, migration);
  assert.ok(afterHistory.at(-1).finished_at instanceof Date);
  assert.deepEqual(afterHistory.slice(0, 14), beforeHistory);
  const afterTables = await foundationTables(db);
  const additions = [bindings, attempts].map((table) => table.split('.')[1]);
  assert.deepEqual(afterTables.map(({ name }) => name), [...names, ...additions].sort());
  assert.deepEqual(await snapshotRows(db, beforeTables), beforeRows, '015 changed populated 014 rows');
  const afterCatalog = await catalog(db, names);
  const added = afterCatalog.indexes.find((index) => index.name === parentIndex);
  assert.ok(added?.unique && added.valid && added.relname === 'file_upload_intents'
    && added.definition.endsWith('(id, owner_request_session_id, declared_bytes)'), '015 immutable parent tuple index');
  assert.deepEqual({ ...afterCatalog, indexes: afterCatalog.indexes.filter((index) => index.name !== parentIndex) },
    beforeCatalog, '015 changed preexisting columns, constraints, ACL, triggers or indexes');
  const registry = await catalog(db, additions);
  assert.equal(registry.constraints.filter((key) => key.definition.startsWith('FOREIGN KEY')).length, 2);
  for (const [name, tuple] of [
    ['file_upload_attempts_intent_basis_fkey', '(intent_id, owner_request_session_id, charged_bytes)'],
    ['file_quarantine_objects_verified_attempt_fkey', '(intent_id, attempt_id, actual_bytes, sha256)'],
  ]) {
    const fk = registry.constraints.find((key) => key.conname === name);
    assert.ok(fk?.convalidated && fk.definition.startsWith(`FOREIGN KEY ${tuple}`)
      && fk.definition.endsWith('ON UPDATE RESTRICT ON DELETE RESTRICT'), `${name}: restrictive FK`);
  }
  for (const [name, unique, shape, predicate] of [
    ['file_upload_attempts_owner_budget_idx', false, '(owner_request_session_id, state)'],
    ['file_upload_attempts_active_intent_key', true, '(intent_id)', "'REGISTERED'"],
    ['file_upload_attempts_retirement_idx', false, '(upload_lease_expires_at, id)', "'IN_FLIGHT'"],
    ['file_upload_attempts_probe_idx', false, '(storage_endpoint, storage_bucket, storage_region, observed_at NULLS FIRST, id)', "'UNKNOWN'"],
    ['file_quarantine_objects_attempt_id_key', true, '(attempt_id)'],
  ]) {
    const index = registry.indexes.find((entry) => entry.name === name);
    assert.ok(index?.valid && index.unique === unique && index.definition.includes(shape)
      && (!predicate || (index.definition.includes('WHERE') && index.definition.includes(predicate))), `${name}: index shape`);
  }
  assert.deepEqual(await snapshotRows(db, additions.map((name) => ({ name }))),
    { file_upload_attempts: [], file_quarantine_objects: [] }, '015 must not seed/backfill');
  await proveOwnerGuards(db, parents, foreign);
  const beforeReplay = await snapshotRows(db, afterTables);
  deploy();
  assert.deepEqual(await history(db), afterHistory, '015 replay modified history');
  assert.deepEqual(await snapshotRows(db, afterTables), beforeReplay, '015 replay modified populated rows');
  diff(0);
  // Roll back the probe, even if diff does not detect drift. Prisma must see it via a
  // different connection, so use committed reversible DDL on this isolated test DB.
  await db.query(`ALTER TABLE ${bindings} ADD COLUMN p017a_drift_probe integer`);
  try { diff(2); } finally { await db.query(`ALTER TABLE ${bindings} DROP COLUMN p017a_drift_probe`); }
  diff(0);
  schemaDiff();
  console.log('015 populated upgrade: 014 rows/catalog preserved, lifecycle/FK/clock/fencing/removal guards, replay and drift: PASS');
}
