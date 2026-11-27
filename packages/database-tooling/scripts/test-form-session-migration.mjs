import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';

/** P05-02 (023, schema profile S2) migration proof: form session foundation.
 *
 * Proves on the disposable isolated PostgreSQL databases of the migration
 * orchestrator:
 *  - `form_browser_groups` are immutable history: UPDATE and DELETE are
 *    refused with SQLSTATE 23514 by the guard trigger, `created_at` is always
 *    pinned to the database clock (even on an owner INSERT that supplies a
 *    caller value), and TRUNCATE is refused;
 *  - `form_session_group_memberships` are immutable history: the INSERT guard
 *    requires an existing browser group, an existing live (unrevoked and
 *    unexpired) `request_sessions` anchor, and an anchor expiry that does not
 *    exceed its group expiry; UPDATE, DELETE and TRUNCATE are refused;
 *  - `form_throttle_buckets` are bounded window counters: `hit_count` never
 *    decreases (same value and +1 are allowed), the identity/window columns
 *    are immutable, DELETE and TRUNCATE are refused, and every CHECK bound
 *    (kind vocabulary, key hash format, window seconds, hit count) plus the
 *    unique (kind,key_hash,window_started_at) window key are proven;
 *  - the exact column grants for `fixlevelup_runtime` on all three tables:
 *    a missing, extra or elevated privilege fails the proof, every grant
 *    appears exactly once per column (a single REVOKE/GRANT cycle, never a
 *    duplicated ACL entry), no PUBLIC access exists, the four guard functions
 *    are not callable, and every runtime attempt to UPDATE a forbidden
 *    column, DELETE a row or TRUNCATE a table is refused.
 */
export const formSessionMigration = '20261124000100_form_session_foundation';

// 023 CHECK inventory, deliberately independent of the DDL text: a dropped,
// renamed or unvalidated guard must fail this proof.
export const formSessionChecks = [
  'form_browser_groups_secret_hash_check',
  'form_browser_groups_expiry_check',
  'form_throttle_buckets_kind_check',
  'form_throttle_buckets_key_hash_check',
  'form_throttle_buckets_window_seconds_check',
  'form_throttle_buckets_hit_count_check',
];

const formSessionTables = ['form_browser_groups', 'form_session_group_memberships', 'form_throttle_buckets'];
// Every 023 trigger, mapped to its trigger function. All functions are
// SECURITY INVOKER with a fixed search_path and no runtime EXECUTE, so a
// trigger is the only way they run.
const formSessionTriggers = [
  ['form_browser_groups', 'form_browser_groups_guard', 'form_browser_groups_guard'],
  ['form_browser_groups', 'form_browser_groups_reject_truncate', 'form_history_reject_truncate'],
  ['form_session_group_memberships', 'form_session_group_memberships_guard', 'form_session_group_memberships_guard'],
  ['form_session_group_memberships', 'form_session_group_memberships_reject_truncate', 'form_history_reject_truncate'],
  ['form_throttle_buckets', 'form_throttle_buckets_guard', 'form_throttle_buckets_guard'],
  ['form_throttle_buckets', 'form_throttle_buckets_reject_truncate', 'form_history_reject_truncate'],
];
const formSessionFunctions = ['form_browser_groups_guard', 'form_session_group_memberships_guard',
  'form_throttle_buckets_guard', 'form_history_reject_truncate'];
const sha256 = (text) => createHash('sha256').update(text, 'utf8').digest('hex');

async function denied(query, sqlState, label) {
  await assert.rejects(query, (error) => error.code === sqlState, `Expected SQLSTATE ${sqlState}${label ? `: ${label}` : ''}`);
}

// Exact runtime ACL of 023: SELECT/INSERT/UPDATE column allowlists per table.
// A missing, extra or elevated column privilege fails the proof.
const formSessionAcl = {
  form_browser_groups: {
    select: ['id', 'secret_hash', 'created_at', 'expires_at'],
    insert: ['id', 'secret_hash', 'expires_at'],
    update: [],
  },
  form_session_group_memberships: {
    select: ['session_id', 'group_id', 'created_at'],
    insert: ['session_id', 'group_id'],
    update: [],
  },
  form_throttle_buckets: {
    select: ['id', 'kind', 'key_hash', 'window_started_at', 'window_seconds', 'hit_count'],
    insert: ['id', 'kind', 'key_hash', 'window_started_at', 'window_seconds', 'hit_count'],
    update: ['hit_count'],
  },
};

/** Exact runtime grants, single ACL entry per granted column, no PUBLIC, no
 * callable guard, exact trigger inventory, and real denial statements. */
export async function proveFormSessionGrants(runtime) {
  for (const [table, spec] of Object.entries(formSessionAcl)) {
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
      'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') AS elevated`, [target]);
    assert.equal(broad.rows[0].elevated, false, `Runtime table-level privilege on ${table}`);
    // No PUBLIC privilege and exactly one ACL item per granted column for the
    // runtime role (the single REVOKE/GRANT cycle of 023; a duplicated
    // re-grant would materialise a second item here). aclexplode reports one
    // row per privilege, so items are counted on the raw array instead.
    const entries = await runtime.query(`SELECT a.attname AS name,
      cardinality(a.attacl) AS items,
      (SELECT count(*)::int FROM aclexplode(a.attacl) x WHERE x.grantee<>to_regrole('fixlevelup_runtime')::oid) AS foreign_grants
      FROM pg_attribute a WHERE a.attrelid=$1::regclass AND a.attnum>0 AND NOT a.attisdropped`, [target]);
    const grantedColumns = new Set([...spec.select, ...spec.insert, ...spec.update]);
    for (const column of entries.rows) {
      if (grantedColumns.has(column.name)) {
        assert.equal(column.foreign_grants, 0, `Foreign ACL entry on ${table}.${column.name}`);
        assert.equal(column.items, 1, `Runtime must hold exactly one ACL item on ${table}.${column.name}`);
      } else {
        assert.equal(column.items, null, `Unexpected ACL item on ${table}.${column.name}`);
      }
    }
    const publicAcl = await runtime.query(`SELECT count(*)::int AS n FROM pg_class c
      CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) acl
      WHERE c.oid=$1::regclass AND acl.grantee=0`, [target]);
    assert.equal(publicAcl.rows[0].n, 0, `PUBLIC privilege on ${table}`);
  }
  // The four guard functions exist with the reviewed ownership/security shape
  // and are executable by neither the runtime nor PUBLIC.
  const functions = await runtime.query(`SELECT p.proname,
    has_function_privilege(current_user,p.oid,'EXECUTE') AS allowed,
    pg_get_userbyid(p.proowner) AS owner, p.prosecdef, p.proconfig,
    EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl
      WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE') AS public_execute
    FROM pg_proc p WHERE p.pronamespace='foundation'::regnamespace AND p.proname=ANY($1::text[])
    ORDER BY p.proname`, [formSessionFunctions]);
  assert.equal(functions.rowCount, formSessionFunctions.length, '023 guard functions missing');
  assert.equal(functions.rows.filter((row) => row.allowed).length, 0, 'Runtime must not execute a 023 guard');
  assert.equal(functions.rows.filter((row) => row.public_execute).length, 0, 'PUBLIC EXECUTE on a 023 guard');
  assert(functions.rows.every((row) => row.owner === 'fixlevelup_migrator' && row.prosecdef === false
    && row.proconfig?.includes('search_path=pg_catalog')), '023 guard ownership/security mismatch');
  // Every expected 023 trigger exists, is enabled, and is bound to its own
  // function; no extra trigger exists on the three tables.
  const triggers = await runtime.query(`SELECT c.relname AS table, g.tgname AS name, g.tgenabled IN ('O','A') AS enabled,
      p.proname AS fn
    FROM pg_trigger g JOIN pg_class c ON c.oid=g.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
    JOIN pg_proc p ON p.oid=g.tgfoid
    WHERE n.nspname='foundation' AND c.relname=ANY($1::text[]) AND NOT g.tgisinternal
    ORDER BY c.relname, g.tgname`, [formSessionTables]);
  assert.equal(triggers.rowCount, formSessionTriggers.length, '023 trigger count mismatch');
  for (const [table, trigger, fn] of formSessionTriggers) {
    const found = triggers.rows.find((row) => row.table === table && row.name === trigger);
    assert.ok(found, `Missing 023 trigger ${table}.${trigger}`);
    assert.equal(found.enabled, true, `Disabled 023 trigger ${table}.${trigger}`);
    assert.equal(found.fn, fn, `023 trigger ${table}.${trigger} bound to the wrong function`);
  }
  // Runtime really cannot mutate the forbidden surface: no UPDATE of a
  // non-granted column, no INSERT of a database-owned stamp, no DELETE, no
  // TRUNCATE, no DDL and no callable guard.
  const statements = [
    'UPDATE foundation.form_browser_groups SET secret_hash=secret_hash',
    'UPDATE foundation.form_browser_groups SET expires_at=expires_at',
    'UPDATE foundation.form_browser_groups SET created_at=created_at',
    "INSERT INTO foundation.form_browser_groups(id,secret_hash,created_at,expires_at) VALUES(gen_random_uuid(),repeat('a',64),CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+INTERVAL '1 hour')",
    'DELETE FROM foundation.form_browser_groups',
    'TRUNCATE foundation.form_browser_groups',
    'UPDATE foundation.form_session_group_memberships SET group_id=group_id',
    'UPDATE foundation.form_session_group_memberships SET created_at=created_at',
    "INSERT INTO foundation.form_session_group_memberships(session_id,group_id,created_at) VALUES(gen_random_uuid(),gen_random_uuid(),CURRENT_TIMESTAMP)",
    'DELETE FROM foundation.form_session_group_memberships',
    'TRUNCATE foundation.form_session_group_memberships',
    'UPDATE foundation.form_throttle_buckets SET kind=kind',
    'UPDATE foundation.form_throttle_buckets SET key_hash=key_hash',
    'UPDATE foundation.form_throttle_buckets SET window_started_at=window_started_at',
    'UPDATE foundation.form_throttle_buckets SET window_seconds=window_seconds',
    'UPDATE foundation.form_throttle_buckets SET id=id WHERE false',
    'DELETE FROM foundation.form_throttle_buckets',
    'TRUNCATE foundation.form_throttle_buckets',
    'ALTER TABLE foundation.form_browser_groups ADD COLUMN forbidden integer',
    ...formSessionFunctions.map((name) => `SELECT foundation.${name}()`),
  ];
  for (const sql of statements) { await denied(runtime.query(sql), '42501', sql); }
  // Positive surface: the runtime appends a group and counts a bucket up.
  const groupHash = sha256(randomUUID());
  await runtime.query(`INSERT INTO foundation.form_browser_groups(id,secret_hash,expires_at)
    VALUES($1,$2,clock_timestamp()+INTERVAL '2 hours')`, [randomUUID(), groupHash]);
  const stamped = (await runtime.query(`SELECT created_at FROM foundation.form_browser_groups WHERE secret_hash=$1`,
    [groupHash])).rows[0];
  assert.ok(stamped && Date.now() - stamped.created_at.getTime() < 60000,
    'runtime group created_at must be the database clock');
  const bucketId = randomUUID();
  await runtime.query(`INSERT INTO foundation.form_throttle_buckets
    (id,kind,key_hash,window_started_at,window_seconds,hit_count)
    VALUES($1,'SOURCE',$2,clock_timestamp(),60,1)`, [bucketId, sha256(randomUUID())]);
  assert.deepEqual((await runtime.query(
    'UPDATE foundation.form_throttle_buckets SET hit_count=hit_count+1 WHERE id=$1 RETURNING hit_count',
    [bucketId])).rows, [{ hit_count: 2 }], 'runtime throttle count-up failed');
  console.log('023 runtime grants: exact column ACL (single entry per granted column), no table-level or '
    + 'PUBLIC privilege, no callable guard, exact triggers, forbidden writes denied: PASS');
}

/** Guard proofs on the populated upgrade database, run as the migration
 * owner; the optional runtime connection proves the positive write surface. */
export async function proveFormSessionUpgrade(owner, runtime) {
  // Inert start: the S2 foundation carries no seeded rows of its own.
  for (const table of formSessionTables) {
    assert.equal((await owner.query(`SELECT FROM foundation.${table}`)).rowCount, 0,
      `Unexpected seed in ${table}`);
  }
  // The populated chain carries reviewed cities; the anchor fixtures need one.
  const cities = (await owner.query('SELECT id FROM foundation.service_cities ORDER BY code LIMIT 1')).rows;
  const east = cities[0];
  assert.ok(east, 'Expected the populated city fixture');
  const eastVersion = (await owner.query(
    'SELECT id FROM foundation.service_city_versions WHERE city_id=$1 ORDER BY version LIMIT 1',
    [east.id])).rows[0];
  assert.ok(eastVersion, 'Expected the populated city version fixture');
  const insertSession = (id, extra = {}) => owner.query(`INSERT INTO foundation.request_sessions
    (id,secret_hash,intake_city_id,intake_city_version_id,expires_at)
    VALUES($1,$2,$3,$4,clock_timestamp()+$5::interval)`,
  [id, extra.hash ?? sha256(randomUUID()), east.id, eastVersion.id, extra.lifetime ?? '1 day']);

  // ---- Browser groups: DB-stamped creation, bounded, immutable. ----
  const groupHash = sha256(randomUUID());
  const groupId = randomUUID();
  // 2 days: the 1-day anchors issued below must never exceed the group expiry.
  await owner.query(`INSERT INTO foundation.form_browser_groups(id,secret_hash,expires_at)
    VALUES($1,$2,clock_timestamp()+INTERVAL '2 days')`, [groupId, groupHash]);
  const group = (await owner.query('SELECT created_at,expires_at FROM foundation.form_browser_groups WHERE id=$1',
    [groupId])).rows[0];
  assert.ok(Date.now() - group.created_at.getTime() < 60000, 'group created_at must be the database clock');
  // A caller-supplied created_at is discarded even on an owner INSERT.
  const backdated = randomUUID();
  await owner.query(`INSERT INTO foundation.form_browser_groups(id,secret_hash,created_at,expires_at)
    VALUES($1,$2,$3,clock_timestamp()+INTERVAL '1 hour')`,
  [backdated, sha256(randomUUID()), new Date('2000-01-01T00:00:00Z')]);
  const stamped = (await owner.query('SELECT created_at FROM foundation.form_browser_groups WHERE id=$1',
    [backdated])).rows[0];
  assert.ok(Date.now() - stamped.created_at.getTime() < 60000, 'owner-supplied created_at must be overwritten');
  await denied(owner.query(`INSERT INTO foundation.form_browser_groups(id,secret_hash,expires_at)
    VALUES($1,'not-a-hash',clock_timestamp()+INTERVAL '1 hour')`, [randomUUID()]), '23514', 'group hash format');
  await denied(owner.query(`INSERT INTO foundation.form_browser_groups(id,secret_hash,expires_at)
    VALUES($1,$2,clock_timestamp()-INTERVAL '1 minute')`, [randomUUID(), sha256(randomUUID())]),
  '23514', 'group must expire after its DB-stamped creation');
  await denied(owner.query(`INSERT INTO foundation.form_browser_groups(id,secret_hash,expires_at)
    VALUES($1,$2,clock_timestamp()+INTERVAL '1 hour')`, [randomUUID(), groupHash]), '23505', 'duplicate group hash');
  // Immutability: UPDATE, DELETE and TRUNCATE are refused by the guard.
  await denied(owner.query('UPDATE foundation.form_browser_groups SET expires_at=expires_at'), '23514');
  await denied(owner.query('UPDATE foundation.form_browser_groups SET secret_hash=secret_hash WHERE id=$1',
    [groupId]), '23514');
  await denied(owner.query('DELETE FROM foundation.form_browser_groups'), '23514');
  // CASCADE is needed to reach the trigger because memberships reference groups.
  await denied(owner.query('TRUNCATE foundation.form_browser_groups CASCADE'), '23514');

  // ---- Memberships: guard on INSERT, immutable history. ----
  const session = randomUUID();
  await insertSession(session);
  await owner.query('INSERT INTO foundation.form_session_group_memberships(session_id,group_id) VALUES($1,$2)',
    [session, groupId]);
  const membership = (await owner.query('SELECT created_at FROM foundation.form_session_group_memberships WHERE session_id=$1',
    [session])).rows[0];
  assert.ok(Date.now() - membership.created_at.getTime() < 60000, 'membership created_at must be the database clock');
  // Guard: an existing browser group is required (checked before the FK).
  await denied(owner.query('INSERT INTO foundation.form_session_group_memberships(session_id,group_id) VALUES($1,$2)',
    [randomUUID(), randomUUID()]), '23514', 'membership needs an existing browser group');
  // Guard: an existing request session anchor is required.
  await denied(owner.query('INSERT INTO foundation.form_session_group_memberships(session_id,group_id) VALUES($1,$2)',
    [randomUUID(), groupId]), '23514', 'membership needs an existing request session');
  // Guard: the anchor must be live — a revoked anchor is refused.
  const revokedSession = randomUUID();
  await insertSession(revokedSession);
  await owner.query('UPDATE foundation.request_sessions SET revoked_at=clock_timestamp() WHERE id=$1',
    [revokedSession]);
  await denied(owner.query('INSERT INTO foundation.form_session_group_memberships(session_id,group_id) VALUES($1,$2)',
    [revokedSession, groupId]), '23514', 'membership needs a live request session');
  // Guard: the anchor must be live — an expired anchor is refused. The anchor
  // cannot be created already expired (013 pins created_at to the DB clock),
  // so the branch needs a short-lived anchor that really expires.
  const expiringSession = randomUUID();
  await insertSession(expiringSession, { lifetime: '250 milliseconds' });
  await new Promise((resolve) => { setTimeout(resolve, 400); });
  await denied(owner.query('INSERT INTO foundation.form_session_group_memberships(session_id,group_id) VALUES($1,$2)',
    [expiringSession, groupId]), '23514', 'membership needs an unexpired request session');
  // Guard: the anchor expiry may never exceed its browser group expiry.
  const shortGroup = randomUUID();
  await owner.query(`INSERT INTO foundation.form_browser_groups(id,secret_hash,expires_at)
    VALUES($1,$2,clock_timestamp()+INTERVAL '10 minutes')`, [shortGroup, sha256(randomUUID())]);
  const longSession = randomUUID();
  await insertSession(longSession, { lifetime: '1 day' });
  await denied(owner.query('INSERT INTO foundation.form_session_group_memberships(session_id,group_id) VALUES($1,$2)',
    [longSession, shortGroup]), '23514', 'anchor expiry exceeds its browser group');
  // Immutability: UPDATE, DELETE and TRUNCATE are refused by the guard.
  await denied(owner.query('UPDATE foundation.form_session_group_memberships SET group_id=group_id'), '23514');
  await denied(owner.query('UPDATE foundation.form_session_group_memberships SET session_id=session_id WHERE session_id=$1',
    [session]), '23514');
  await denied(owner.query('DELETE FROM foundation.form_session_group_memberships'), '23514');
  await denied(owner.query('TRUNCATE foundation.form_session_group_memberships'), '23514');

  // ---- Throttle buckets: bounded counters, monotone hit_count. ----
  const bucketId = randomUUID(), bucketHash = sha256(randomUUID());
  await owner.query(`INSERT INTO foundation.form_throttle_buckets
    (id,kind,key_hash,window_started_at,window_seconds,hit_count)
    VALUES($1,'SOURCE',$2,clock_timestamp(),60,1)`, [bucketId, bucketHash]);
  // hit_count grows and may stay; it never decreases.
  assert.deepEqual((await owner.query(
    'UPDATE foundation.form_throttle_buckets SET hit_count=hit_count+1 WHERE id=$1 RETURNING hit_count',
    [bucketId])).rows, [{ hit_count: 2 }], 'throttle count-up failed');
  assert.deepEqual((await owner.query(
    'UPDATE foundation.form_throttle_buckets SET hit_count=hit_count WHERE id=$1 RETURNING hit_count',
    [bucketId])).rows, [{ hit_count: 2 }], 'same hit_count must stay allowed');
  await denied(owner.query('UPDATE foundation.form_throttle_buckets SET hit_count=hit_count-1 WHERE id=$1',
    [bucketId]), '23514', 'hit count cannot decrease');
  await denied(owner.query('UPDATE foundation.form_throttle_buckets SET hit_count=1 WHERE id=$1',
    [bucketId]), '23514', 'hit count reset refused');
  // Identity and window are immutable; a real change is refused.
  await denied(owner.query("UPDATE foundation.form_throttle_buckets SET kind='GLOBAL' WHERE id=$1",
    [bucketId]), '23514', 'kind is immutable');
  await denied(owner.query('UPDATE foundation.form_throttle_buckets SET key_hash=$2 WHERE id=$1',
    [bucketId, sha256(randomUUID())]), '23514', 'key hash is immutable');
  await denied(owner.query('UPDATE foundation.form_throttle_buckets SET window_started_at=clock_timestamp() WHERE id=$1',
    [bucketId]), '23514', 'window start is immutable');
  await denied(owner.query('UPDATE foundation.form_throttle_buckets SET window_seconds=window_seconds+60 WHERE id=$1',
    [bucketId]), '23514', 'window length is immutable');
  await denied(owner.query('UPDATE foundation.form_throttle_buckets SET id=$2 WHERE id=$1',
    [bucketId, randomUUID()]), '23514', 'bucket id is immutable');
  await denied(owner.query('DELETE FROM foundation.form_throttle_buckets'), '23514');
  await denied(owner.query('TRUNCATE foundation.form_throttle_buckets'), '23514');
  // CHECK bounds and the unique window key.
  const validHash = sha256(randomUUID());
  const insertBucket = (kind, keyHash, windowSeconds, hitCount, windowStartedAt) => owner.query(
    `INSERT INTO foundation.form_throttle_buckets(id,kind,key_hash,window_started_at,window_seconds,hit_count)
     VALUES($1,$2,$3,$4,$5,$6)`,
  [randomUUID(), kind, keyHash, windowStartedAt ?? new Date(), windowSeconds, hitCount]);
  await denied(insertBucket('SOURCE', 'not-a-hash', 60, 1), '23514', 'bucket hash format');
  await denied(insertBucket('SESSION', validHash, 60, 1), '23514', 'kind vocabulary');
  await denied(insertBucket('SOURCE', validHash, 0, 1), '23514', 'window lower bound');
  await denied(insertBucket('SOURCE', validHash, 86401, 1), '23514', 'window upper bound');
  await denied(insertBucket('SOURCE', validHash, 60, 0), '23514', 'hit count lower bound');
  await denied(insertBucket('SOURCE', validHash, 60, 1000001), '23514', 'hit count upper bound');
  // The unique window key: a second row of the same (kind,key_hash,window)
  // triple is refused. The stored window stamp has microsecond precision, so
  // the duplicate reuses the exact stored value by id reference, not a JS Date.
  await denied(owner.query(`INSERT INTO foundation.form_throttle_buckets
    (id,kind,key_hash,window_started_at,window_seconds,hit_count)
    SELECT $1,'SOURCE',key_hash,window_started_at,window_seconds,1
    FROM foundation.form_throttle_buckets WHERE id=$2`,
  [randomUUID(), bucketId]), '23505', 'duplicate window row');

  // ---- Positive runtime surface on the populated database. ----
  if (runtime) {
    const runtimeGroup = randomUUID();
    // The group must outlive the anchor by a real margin: both expiries are
    // taken at different statement instants, so equal intervals would race.
    await runtime.query(`INSERT INTO foundation.form_browser_groups(id,secret_hash,expires_at)
      VALUES($1,$2,clock_timestamp()+INTERVAL '4 hours')`, [runtimeGroup, sha256(randomUUID())]);
    const runtimeSession = randomUUID();
    await runtime.query(`INSERT INTO foundation.request_sessions
      (id,secret_hash,intake_city_id,intake_city_version_id,expires_at)
      VALUES($1,$2,$3,$4,clock_timestamp()+INTERVAL '2 hours')`,
    [runtimeSession, sha256(randomUUID()), east.id, eastVersion.id]);
    await runtime.query('INSERT INTO foundation.form_session_group_memberships(session_id,group_id) VALUES($1,$2)',
      [runtimeSession, runtimeGroup]);
    const runtimeBucket = randomUUID();
    await runtime.query(`INSERT INTO foundation.form_throttle_buckets
      (id,kind,key_hash,window_started_at,window_seconds,hit_count)
      VALUES($1,'ANCHOR',$2,clock_timestamp(),60,1)`, [runtimeBucket, sha256(randomUUID())]);
    assert.deepEqual((await runtime.query(
      'UPDATE foundation.form_throttle_buckets SET hit_count=hit_count+1 WHERE id=$1 RETURNING hit_count',
      [runtimeBucket])).rows, [{ hit_count: 2 }], 'runtime throttle count-up failed');
    await denied(runtime.query('UPDATE foundation.form_throttle_buckets SET kind=kind'), '42501');
    await denied(runtime.query('UPDATE foundation.form_browser_groups SET expires_at=expires_at'), '42501');
    await denied(runtime.query('DELETE FROM foundation.form_session_group_memberships'), '42501');
    await denied(runtime.query('TRUNCATE foundation.form_throttle_buckets'), '42501');
  }
  console.log('023 populated upgrade: inert start, immutable groups/memberships/buckets, INSERT guards '
    + '(group, live anchor, expiry bound), monotone counters, TRUNCATE refusal, runtime writes: PASS');
}
