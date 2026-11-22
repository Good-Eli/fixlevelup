import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { connection } from './migration-local.mjs';

export const filePrivacyChecks = [
  'file_privacy_controls_hold_check', 'file_privacy_controls_delete_state_check',
  'file_privacy_controls_delete_shape_check', 'file_privacy_controls_ledger_check',
  'file_delete_items_kind_check', 'file_delete_items_proof_check', 'file_delete_items_state_check', 'file_delete_items_claim_check',
];
const migration = '20261122000300_file_privacy_deletion';
const controls = 'foundation.file_privacy_controls';
const items = 'foundation.file_delete_items';
const epochs = 'foundation.file_runtime_epochs';
const newControlColumns = ['hold_active', 'hold_actor_id', 'hold_reason', 'hold_at', 'delete_state', 'delete_event_id',
  'delete_at', 'delete_policy_id', 'ledger_seq', 'ledger_hash', 'delete_graph_sha256', 'delete_writer_epoch'];
const cClaims = ['processing', 'read'].flatMap((kind) => [`${kind}_generation`, `${kind}_lease_id`, `${kind}_expires_at`]);
const itemInput = ['event_id', 'attempt_kind', 'attempt_id', 'intent_id', 'target_endpoint', 'target_bucket', 'target_region', 'object_key', 'write_proof'];
const itemUpdate = ['state', 'claim_generation', 'claim_id', 'claim_expires_at'];
const guards = ['file_privacy_controls_guard', 'file_delete_items_guard', 'file_processing_history_reject_removal',
  'file_delete_graph_guard', 'file_write_freeze_guard'];
const rows = async (db, sql, values) => (await db.query(sql, values)).rows;
const one = async (db, sql, values) => (await rows(db, sql, values))[0];
const history = (db) => rows(db, 'SELECT * FROM foundation._prisma_migrations ORDER BY migration_name');
const rejects = (query, code, constraint) => assert.rejects(query, { code, ...(constraint ? { constraint } : {}) });
const hash = 'a'.repeat(64);
const emptyD = { hold_active: false, hold_actor_id: null, hold_reason: null, hold_at: null, delete_state: 'OPEN',
  delete_event_id: null, delete_at: null, delete_policy_id: null, ledger_seq: null, ledger_hash: null,
  delete_graph_sha256: null, delete_writer_epoch: null };

async function snapshot(db, tables, exclude = []) {
  const result = {};
  for (const table of tables) {
    result[table] = await rows(db, `SELECT (to_jsonb(t)-$1::text[])::text AS data
      FROM foundation."${table.replaceAll('"', '""')}" t ORDER BY 1`, [table === 'file_privacy_controls' ? exclude : []]);
  }
  return result;
}
const foundationTables = async (db) => (await rows(db, `SELECT relname FROM pg_class
  WHERE relnamespace='foundation'::regnamespace AND relkind='r' AND relname<>'_prisma_migrations' ORDER BY relname`)).map(({ relname }) => relname);

export async function proveFilePrivacyUpgrade(owner, deploy, diff, schemaDiff) {
  const identity = await one(owner, 'SELECT current_database() AS db,current_user AS role');
  assert.match(identity.db, /^fixlevelup_p017a_upgrade_[a-f0-9]{12}$/);
  assert.equal(identity.role, 'fixlevelup_migrator');
  const before = await history(owner);
  assert.equal(before.length, 16);
  assert.equal(before.at(-1).migration_name, '20261122000200_file_processing_access');
  const priorTables = await foundationTables(owner);
  const old = await snapshot(owner, priorTables);
  assert.ok(old.file_privacy_controls.length > 0 && old.file_publications.length > 0 && old.file_sanitized_attempts.length > 0);
  deploy();
  const after = await history(owner);
  assert.equal(after.length, 17);
  assert.equal(after.at(-1).migration_name, migration);
  assert.ok(after.at(-1).finished_at instanceof Date);
  assert.deepEqual(after.slice(0, 16), before);
  const tables = [...priorTables, 'file_delete_items'].sort();
  assert.deepEqual(await foundationTables(owner), tables);
  assert.deepEqual(await snapshot(owner, priorTables, newControlColumns), old, '017 changed prior data or stamps');
  assert.deepEqual(await rows(owner, `SELECT ${newControlColumns.join(',')} FROM ${controls}`),
    old.file_privacy_controls.map(() => emptyD), '016 controls upgrade to OPEN and unheld, no invented decision');
  assert.deepEqual(await rows(owner, `SELECT * FROM ${items}`), [], '017 must not invent a deletion graph');
  const itemFk = await rows(owner, `SELECT conname,convalidated,condeferrable,pg_get_constraintdef(oid) AS definition
    FROM pg_constraint WHERE conrelid=$1::regclass AND contype='f'`, [items]);
  assert.equal(itemFk.length, 1);
  assert.deepEqual({ ...itemFk[0], definition: itemFk[0].definition.replace('REFERENCES foundation.', 'REFERENCES ') }, {
    conname: 'file_delete_items_control_fkey', convalidated: true, condeferrable: false,
    definition: 'FOREIGN KEY (intent_id, event_id) REFERENCES file_privacy_controls(intent_id, delete_event_id) ON UPDATE RESTRICT ON DELETE RESTRICT',
  });
  const keys = await rows(owner, `SELECT idx.relname AS name, i.indisvalid AS valid, i.indisunique AS unique,
    pg_get_indexdef(i.indexrelid) AS definition FROM pg_index i JOIN pg_class idx ON idx.oid=i.indexrelid
    WHERE i.indrelid IN ($1::regclass,$2::regclass)`, [controls, items]);
  for (const [name, tuple] of [
    ['file_privacy_controls_delete_event_id_key', '(delete_event_id)'],
    ['file_privacy_controls_intent_event_key', '(intent_id, delete_event_id)'],
    ['file_delete_items_pkey', '(event_id, attempt_kind, attempt_id)'],
    ['file_delete_items_event_target_key', '(event_id, target_endpoint, target_bucket, target_region, object_key)'],
  ]) {
    const key = keys.find((item) => item.name === name);
    assert.ok(key?.valid && key.unique && key.definition.endsWith(tuple), name);
  }
  const populated = await snapshot(owner, tables);
  deploy();
  assert.deepEqual(await history(owner), after, '017 replay modified history');
  assert.deepEqual(await snapshot(owner, tables), populated, '017 replay modified existing data');
  diff(0);
  await owner.query(`ALTER TABLE ${items} ADD COLUMN p017a_drift_probe integer`);
  try { diff(2); } finally { await owner.query(`ALTER TABLE ${items} DROP COLUMN p017a_drift_probe`); }
  diff(0);
  schemaDiff();
  console.log('017 populated upgrade: C016 data/stamps, OPEN defaults, exact restrictive event FK, replay and restored drift: PASS');
}

async function proveGrants(runtime) {
  const specs = [
    [controls, ['intent_id', 'row_version', 'access_epoch', ...cClaims, ...newControlColumns], ['intent_id'],
      [...cClaims, 'hold_active', 'hold_actor_id', 'hold_reason', 'delete_state', 'delete_event_id',
        'delete_policy_id', 'ledger_seq', 'ledger_hash', 'delete_graph_sha256']],
    [items, [...itemInput, ...itemUpdate, 'verified_at'], itemInput, itemUpdate],
  ];
  for (const [table, read, insert, update] of specs) {
    const columns = await rows(runtime, `SELECT attname,
      has_column_privilege(current_user,attrelid,attnum,'SELECT') AS readable,
      has_column_privilege(current_user,attrelid,attnum,'INSERT') AS insertable,
      has_column_privilege(current_user,attrelid,attnum,'UPDATE') AS writable,
      has_column_privilege(current_user,attrelid,attnum,'REFERENCES,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION,SELECT WITH GRANT OPTION') AS elevated,
      EXISTS(SELECT 1 FROM aclexplode(attacl) a WHERE a.grantee=0) AS public_acl
      FROM pg_attribute WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped`, [table]);
    assert.deepEqual(columns.map(({ attname }) => attname).sort(), [...read].sort());
    for (const column of columns) {
      assert.deepEqual([column.readable, column.insertable, column.writable, column.elevated, column.public_acl],
        [true, insert.includes(column.attname), update.includes(column.attname), false, false], `${table}.${column.attname}`);
    }
    assert.deepEqual(await one(runtime, `SELECT pg_get_userbyid(c.relowner) AS owner, c.relrowsecurity AS rls,
      has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') AS elevated,
      EXISTS(SELECT 1 FROM aclexplode(c.relacl) a WHERE a.grantee=0) AS public_acl
      FROM pg_class c WHERE c.oid=$1::regclass`, [table]),
    { owner: 'fixlevelup_migrator', rls: false, elevated: false, public_acl: false });
    await rejects(runtime.query(`DELETE FROM ${table}`), '42501');
    await rejects(runtime.query(`TRUNCATE ${table}`), '42501');
  }
  for (const sql of [`UPDATE ${controls} SET access_epoch=access_epoch`, `UPDATE ${controls} SET hold_at=hold_at`,
    `UPDATE ${controls} SET delete_at=delete_at`, `UPDATE ${controls} SET delete_writer_epoch=delete_writer_epoch`,
    `UPDATE ${items} SET write_proof=write_proof`,
    `UPDATE ${items} SET object_key=object_key`, `UPDATE ${items} SET verified_at=verified_at`]) {
    await rejects(runtime.query(sql), '42501');
  }
  const functions = await rows(runtime, `SELECT p.proname AS name,pg_get_userbyid(p.proowner) AS owner,
    p.prosecdef AS definer,p.proconfig AS config,has_function_privilege(current_user,p.oid,'EXECUTE') AS callable,
    EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0) AS public_acl
    FROM pg_proc p WHERE p.pronamespace='foundation'::regnamespace AND p.proname=ANY($1::text[]) ORDER BY p.proname`, [guards]);
  assert.deepEqual(functions, [...guards].sort().map((name) => ({ name, owner: 'fixlevelup_migrator', definer: false,
    config: ['search_path=pg_catalog'], callable: false, public_acl: false })));
  for (const guard of guards) { await rejects(runtime.query(`SELECT foundation.${guard}()`), '42501'); }
}

const controlFor = (db, intent) => one(db, `SELECT * FROM ${controls} WHERE intent_id=$1`, [intent]);
const updateControl = (db, intent, set, args = []) => db.query(`UPDATE ${controls} SET ${set} WHERE intent_id=$1`, [intent, ...args]);
const decision = (db, intent, event, version) => db.query(`UPDATE ${controls} SET
  delete_state='PENDING_LEDGER',delete_event_id=$2,delete_policy_id=$3,delete_graph_sha256=$4
  WHERE intent_id=$1 AND row_version=$5 AND delete_state='OPEN'`, [intent, event, randomUUID(), hash, version]);
const appendItem = (db, event, raw, proof, extra = {}) => one(db, `INSERT INTO ${items} (${itemInput.join(',')})
  VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING state,claim_generation,claim_id,claim_expires_at,verified_at`,
[event, extra.kind ?? 'RAW', raw.id, raw.intent_id, extra.endpoint ?? raw.storage_endpoint,
  extra.bucket ?? raw.storage_bucket, extra.region ?? raw.storage_region, extra.key ?? raw.object_key, proof]);
const claimItem = (db, event, id, lifetime = '1 minute', step = 1) => one(db, `UPDATE ${items} SET state='DELETE_ATTEMPTED',
  claim_generation=claim_generation+$2,claim_id=$3,claim_expires_at=clock_timestamp()+$4::interval WHERE event_id=$1
  RETURNING claim_generation,claim_id`, [event, step, id, lifetime]);
const settle = (db, event, id, gen, state) => db.query(`UPDATE ${items} SET state=$4,claim_id=NULL,claim_expires_at=NULL
  WHERE event_id=$1 AND claim_id=$2 AND claim_generation=$3 RETURNING state,verified_at`, [event, id, gen, state]);

export async function proveFilePrivacyRuntime(runtime, ownerPassword, database) {
  const identity = await one(runtime, 'SELECT current_database() AS db,current_user AS role');
  assert.match(identity.db, /^fixlevelup_p017a_fresh_[a-f0-9]{12}$/);
  assert.equal(identity.role, 'fixlevelup_runtime');
  assert.equal(identity.db, database);
  await proveGrants(runtime);
  const owner = connection('fixlevelup_migrator', ownerPassword, database);
  await owner.connect();
  try {
    const writerEpoch = '2147483650';
    await owner.query(`INSERT INTO ${epochs}(singleton,namespace_id,epoch,mode) VALUES(true,$1,$2,'ACTIVE')`, [randomUUID(), writerEpoch]);
    const selected = (state) => one(runtime, `SELECT id,intent_id,storage_endpoint,storage_bucket,storage_region,object_key
      FROM foundation.file_upload_attempts WHERE state=$1 ORDER BY id LIMIT 1`, [state]);
    const verified = await selected('VERIFIED');
    const unknown = await selected('UNKNOWN');
    assert.ok(verified && unknown && verified.intent_id !== unknown.intent_id, '015 proof supplies settled and UNKNOWN raw fixtures');
    const { intent_id: intent } = verified;
    const event = randomUUID(), actor = randomUUID();
    await runtime.query(`INSERT INTO ${controls}(intent_id) VALUES($1)`, [intent]);
    const original = await controlFor(runtime, intent);
    assert.deepEqual(newControlColumns.map((column) => original[column]), newControlColumns.map((column) => emptyD[column]));
    assert.deepEqual([original.access_epoch, original.row_version], ['1', '1']);
    await rejects(updateControl(runtime, intent, 'hold_active=true'), '23514');
    await updateControl(runtime, intent, "hold_active=true,hold_actor_id=$2,hold_reason='LEGAL_HOLD'", [actor]);
    const held = await controlFor(runtime, intent);
    assert.deepEqual([held.hold_active, held.hold_actor_id, held.hold_reason, held.access_epoch, held.row_version],
      [true, actor, 'LEGAL_HOLD', '1', '2']);
    assert.ok(held.hold_at instanceof Date);
    assert.equal((await decision(runtime, intent, event, original.row_version)).rowCount, 0, 'stale row version CAS');
    await rejects(decision(runtime, intent, event, held.row_version), '23514');
    await rejects(appendItem(runtime, event, verified, 'VERIFIED_SETTLED'), '23514');
    await updateControl(runtime, intent, 'hold_active=false,hold_actor_id=NULL,hold_reason=NULL');
    const released = await controlFor(runtime, intent);
    assert.deepEqual([released.hold_at, released.access_epoch, released.row_version], [null, '1', '3']);
    const read = randomUUID();
    await updateControl(runtime, intent, "read_generation=1,read_lease_id=$2,read_expires_at=clock_timestamp()+interval '1 minute'", [read]);
    await rejects(decision(runtime, intent, event, '4'), '23514', 'file_delete_graph_complete');
    assert.equal((await controlFor(runtime, intent)).delete_state, 'OPEN', 'failed graph rolls back freeze');
    await runtime.query('BEGIN');
    assert.equal((await decision(runtime, intent, event, '4')).rowCount, 1);
    assert.deepEqual(await appendItem(runtime, event, verified, 'VERIFIED_SETTLED'),
      { state: 'AUTHORIZED', claim_generation: 0, claim_id: null, claim_expires_at: null, verified_at: null });
    await runtime.query('COMMIT');
    const frozen = await controlFor(runtime, intent);
    assert.deepEqual([frozen.delete_state, frozen.delete_event_id, frozen.access_epoch, frozen.row_version, frozen.ledger_seq, frozen.delete_writer_epoch],
      ['PENDING_LEDGER', event, '2', '5', null, writerEpoch]);
    await rejects(updateControl(owner, intent, 'delete_writer_epoch=delete_writer_epoch+1'), '23514', 'file_privacy_controls_immutable');
    assert.ok(frozen.delete_at instanceof Date);
    await rejects(updateControl(runtime, intent, "hold_active=true,hold_actor_id=$2,hold_reason='LEGAL_HOLD'", [actor]), '23514');
    await rejects(updateControl(runtime, intent, "delete_state='OPEN',delete_event_id=NULL,delete_policy_id=NULL,delete_graph_sha256=NULL"), '23514');
    await updateControl(runtime, intent, 'read_lease_id=NULL,read_expires_at=NULL');
    for (const kind of ['read', 'processing']) {
      await rejects(updateControl(runtime, intent, `${kind}_generation=${kind}_generation+1,${kind}_lease_id=gen_random_uuid(),
        ${kind}_expires_at=clock_timestamp()+interval '1 minute'`), '23514');
    }
    for (const wrong of [{ kind: 'SANITIZED' }, { endpoint: 'http://127.0.0.1:3901' }, { bucket: 'other-bucket' },
      { region: 'other' }, { key: `quarantine/${verified.id}/${randomUUID()}` }]) {
      await rejects(appendItem(runtime, event, verified, 'VERIFIED_SETTLED', wrong), '23514');
    }
    await rejects(appendItem(runtime, event, verified, 'NEVER_DISPATCHED'), '23514');
    await rejects(appendItem(runtime, event, { ...verified, id: unknown.id }, 'VERIFIED_SETTLED'), '23514');
    await rejects(claimItem(runtime, event, randomUUID()), '23514', 'file_delete_items_parent_phase');
    const ledger = (parent) => updateControl(runtime, parent, "delete_state='LEDGERED',ledger_seq=2147483648,ledger_hash=$2", [hash]);
    const verifyPending = (parent) => updateControl(runtime, parent, "delete_state='VERIFY_PENDING'");
    const complete = (parent) => updateControl(runtime, parent, "delete_state='CONFIRMED_ABSENT'");
    await ledger(intent);
    await rejects(appendItem(runtime, event, verified, 'VERIFIED_SETTLED'), '23514');
    await rejects(updateControl(runtime, intent, 'ledger_seq=ledger_seq+1'), '23514');
    await verifyPending(intent);
    await rejects(complete(intent), '23514');
    const oldClaim = randomUUID();
    await rejects(claimItem(runtime, event, oldClaim, '1 minute', 2), '23514');
    assert.deepEqual(await claimItem(runtime, event, oldClaim, '2 seconds'), { claim_generation: 1, claim_id: oldClaim });
    const renewed = randomUUID();
    await rejects(claimItem(runtime, event, renewed), '23514');
    await runtime.query(`SELECT pg_sleep_until(claim_expires_at+interval '10 milliseconds') FROM ${items} WHERE event_id=$1`, [event]);
    await rejects(settle(runtime, event, oldClaim, 1, 'CONFIRMED_ABSENT'), '23514');
    assert.deepEqual(await claimItem(runtime, event, renewed), { claim_generation: 2, claim_id: renewed });
    assert.equal((await settle(runtime, event, oldClaim, 1, 'CONFIRMED_ABSENT')).rowCount, 0);
    const settled = (await settle(runtime, event, renewed, 2, 'CONFIRMED_ABSENT')).rows[0];
    assert.equal(settled.state, 'CONFIRMED_ABSENT');
    assert.ok(settled.verified_at instanceof Date);
    await complete(intent);
    const done = await controlFor(runtime, intent);
    assert.deepEqual([done.delete_state, done.access_epoch, done.ledger_seq, done.ledger_hash], ['CONFIRMED_ABSENT', '2', '2147483648', hash]);
    await rejects(claimItem(runtime, event, randomUUID()), '23514');
    await rejects(verifyPending(intent), '23514');

    const unknownEvent = randomUUID(), unknownClaim = randomUUID();
    await runtime.query(`INSERT INTO ${controls}(intent_id) VALUES($1)`, [unknown.intent_id]);
    await runtime.query('BEGIN');
    await decision(runtime, unknown.intent_id, unknownEvent, '1');
    await appendItem(runtime, unknownEvent, unknown, 'UNKNOWN');
    await runtime.query('COMMIT');
    await ledger(unknown.intent_id);
    await verifyPending(unknown.intent_id);
    await claimItem(runtime, unknownEvent, unknownClaim);
    await rejects(settle(runtime, unknownEvent, unknownClaim, 1, 'CONFIRMED_ABSENT'), '23514');
    assert.deepEqual((await settle(runtime, unknownEvent, unknownClaim, 1, 'VERIFY_PENDING')).rows,
      [{ state: 'VERIFY_PENDING', verified_at: null }]);
    await rejects(complete(unknown.intent_id), '23514');
    await rejects(owner.query(`UPDATE ${items} SET target_region='different' WHERE event_id=$1`, [unknownEvent]), '23514');
    await rejects(owner.query(`DELETE FROM ${items}`), '23514', 'file_processing_history_immutable');
    await rejects(owner.query(`TRUNCATE ${items}`), '23514', 'file_processing_history_immutable');
  } finally { await owner.end(); }
  // SQL evidence is only structural: no claim that an external ledger committed or that storage returned an authenticated 404.
  console.log('017 runtime: control/item ACL, hold/version/epoch freeze, exact graph tuples, fenced claims, UNKNOWN retention and immutable history: PASS');
}
