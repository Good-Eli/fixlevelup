import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { baseTables, migrationHistory, snapshot } from './test-catalog-fixed-prices-migration.mjs';

// Expected SQL-only constraints from the contract; a missing migration CHECK must fail this inventory.
const common = ['version', 'source_ref', 'valid_from', 'valid_until'];
const interval = ['valid_from', 'scheduled_until', 'closed_until'];
const names = (table, suffixes) => suffixes.map(suffix => `${table}_${suffix}_check`);
export const pricingChecks = [
  ...names('price_rules', ['code', 'kind', 'row_version', 'archive']),
  ...names('price_rule_series', ['row_version']),
  ...names('price_rule_versions', [...common, 'title', 'method', 'base', 'currency', 'base_bounds', 'delta_bounds', 'window', 'scope_count']),
  ...names('price_rule_scopes', ['category_kind']),
  ...names('pricing_policy_series', ['row_version']),
  ...names('pricing_policy_versions', [...common, 'currency', 'tax_display', 'rounding_mode', 'units', 'max_manual_delta', 'priority_count', 'compatibility_count']),
  ...names('price_rule_priorities', ['priority']),
  ...names('price_rule_compatibilities', ['order']),
  ...names('public_price_estimate_series', ['category_kind', 'code', 'row_version', 'archive']),
  ...names('public_price_estimates', [...common, 'title', 'currency', 'range', 'conditions', 'disclaimer']),
  ...['price_rule_periods', 'pricing_policy_periods', 'public_price_estimate_periods'].flatMap(table => names(table, interval)),
];
const versionInput = 'id series_id city_id city_version_id version source_ref reviewed_by valid_from valid_until';
const periodInput = 'version_id series_id city_id valid_from scheduled_until';
const tables = {
  price_rules: ['id code kind', 'archived_at'],
  price_rule_series: ['id city_id rule_id', 'row_version'],
  price_rule_versions: [`${versionInput} rule_id kind title method base currency fixed_minor rate_bps min_base max_base min_delta max_delta start_minute end_minute wraps_midnight scope_count`, ''],
  price_rule_scopes: ['rule_version_id category_id', ''],
  pricing_policy_series: ['id city_id', 'row_version'],
  pricing_policy_versions: [`${versionInput} currency tax_display rounding_mode units max_manual_delta_minor priority_count compatibility_count`, ''],
  price_rule_priorities: ['policy_version_id rule_id priority', ''],
  price_rule_compatibilities: ['policy_version_id left_rule_id right_rule_id', ''],
  public_price_estimate_series: ['id city_id category_id code', 'row_version archived_at'],
  public_price_estimates: [`${versionInput} title currency min_minor max_minor conditions disclaimer`, ''],
  price_rule_periods: [periodInput, 'closed_effective_until'],
  pricing_policy_periods: [periodInput, 'closed_effective_until'],
  public_price_estimate_periods: [periodInput, 'closed_effective_until'],
};
const unitsValidator = 'pricing_policy_units_valid';
const routines = ['pricing_guard_identity', 'pricing_guard_series', 'pricing_guard_publish_basis', 'pricing_guard_child_basis',
  'pricing_guard_child_counts', 'pricing_guard_period', 'pricing_guard_final_clock', unitsValidator];
const triples = [
  ['price_rule_series', 'price_rule_versions', 'price_rule_periods'],
  ['pricing_policy_series', 'pricing_policy_versions', 'pricing_policy_periods'],
  ['public_price_estimate_series', 'public_price_estimates', 'public_price_estimate_periods'],
];
const deferredChildren = ['price_rule_versions_counts_guard', 'price_rule_scopes_count_guard', 'pricing_policy_versions_counts_guard',
  'price_rule_priorities_count_guard', 'price_rule_compatibilities_count_guard'];
const catalogSha = '277e308346bd578e5b4910046bee91699c4f0c96cab40be17a51e57062f778b0';
const rows = async (db, sql, values) => (await db.query(sql, values)).rows;
const one = async (db, sql, values) => (await rows(db, sql, values))[0];
const deny = (request, code, constraint) => assert.rejects(request, { code, ...(constraint ? { constraint } : {}) });
async function isolated(db, role, kind) {
  const where = await one(db, 'SELECT current_database() AS db,current_user AS role');
  assert.equal(where.role, role);
  assert.match(where.db, new RegExp(`^fixlevelup_p017a_${kind}_[a-f0-9]{12}$`));
  return where.db;
}
async function transact(db, run, begin = 'BEGIN ISOLATION LEVEL READ COMMITTED') {
  await db.query(begin);
  try { const result = await run(); await db.query('COMMIT'); return result; }
  catch (error) { await db.query('ROLLBACK'); throw error; }
}
async function noSeed(db) {
  for (const table of Object.keys(tables)) {
    assert.equal((await db.query(`SELECT FROM foundation.${table} LIMIT 1`)).rowCount, 0, `Unexpected 020 seed: ${table}`);
  }
}

export async function provePricingMigrationUpgrade(owner, migrations, deploy, diff) {
  await isolated(owner, 'fixlevelup_migrator', 'upgrade');
  const history = await migrationHistory(owner), previous = await baseTables(owner);
  assert.deepEqual(history.map(row => row.migration_name), migrations.slice(0, -1));
  assert.equal(history.at(-1)?.checksum, catalogSha, 'Accepted 019 changed');
  const before = await snapshot(owner, previous);
  for (const table of ['catalog_directory_entries', 'catalog_directory_versions', 'catalog_items', 'catalog_item_versions',
    'catalog_price_series', 'catalog_price_versions', 'catalog_price_periods']) {
    assert.ok(before.data[previous.indexOf(table)]?.length, `Expected populated 019 ${table}`);
  }
  deploy();
  const deployed = await migrationHistory(owner);
  assert.deepEqual(deployed.slice(0, -1), history);
  assert.deepEqual(deployed.map(row => row.migration_name), migrations);
  assert.ok(deployed.at(-1)?.finished_at instanceof Date);
  const allTables = await baseTables(owner);
  assert.deepEqual(allTables, [...previous, ...Object.keys(tables)].sort());
  assert.deepEqual(await snapshot(owner, previous), before, '020 changed prior data, catalog definitions or ACL');
  await noSeed(owner);
  const after = await snapshot(owner, allTables);
  deploy();
  assert.deepEqual(await migrationHistory(owner), deployed);
  assert.deepEqual(await snapshot(owner, allTables), after);
  diff(0);
  await owner.query('ALTER TABLE foundation.pricing_policy_versions ADD COLUMN p020_drift_probe integer');
  try { diff(2); }
  finally { await owner.query('ALTER TABLE foundation.pricing_policy_versions DROP COLUMN p020_drift_probe'); }
  diff(0);
  console.log('020 populated 019 upgrade: pinned 019 checksum, exact older data/FK/ACL, no seed, replay and SQL/Prisma drift detection/restoration: PASS');
}

async function proveAcl(owner, db) {
  for (const [table, [inserts, updates]] of Object.entries(tables)) {
    const name = `foundation.${table}`;
    const columns = await rows(db, `SELECT attname,
      has_column_privilege(current_user,attrelid,attnum,'SELECT') AS r,
      has_column_privilege(current_user,attrelid,attnum,'INSERT') AS i,
      has_column_privilege(current_user,attrelid,attnum,'UPDATE') AS u,
      has_column_privilege(current_user,attrelid,attnum,'REFERENCES,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION') AS extra,
      EXISTS (SELECT FROM aclexplode(attacl) AS acl WHERE acl.grantee<>to_regrole('fixlevelup_runtime')::oid) AS other
      FROM pg_attribute WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped`, [name]);
    const words = value => value.split(' ').filter(Boolean).sort();
    const allowed = key => columns.filter(row => row[key]).map(row => row.attname).sort();
    assert.ok(columns.length && columns.every(row => row.r && !row.extra && !row.other), `SELECT and column ACL: ${table}`);
    assert.deepEqual(allowed('i'), words(inserts), `INSERT ACL: ${table}`);
    assert.deepEqual(allowed('u'), words(updates), `UPDATE ACL: ${table}`);
    assert.deepEqual(await one(db, `SELECT pg_get_userbyid(relowner) AS owner,
      has_table_privilege(current_user,oid,'SELECT') AS r,
      has_table_privilege(current_user,oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN,SELECT WITH GRANT OPTION') AS extra,
      EXISTS (SELECT FROM aclexplode(relacl) acl WHERE acl.grantee NOT IN (relowner,to_regrole('fixlevelup_runtime')::oid)) AS other
      FROM pg_class WHERE oid=$1::regclass`, [name]), { owner: 'fixlevelup_migrator', r: true, extra: false, other: false });
    const key = inserts.split(' ')[0];
    await deny(db.query(`UPDATE ${name} SET ${key}=${key} WHERE false`), '42501');
    await deny(db.query(`DELETE FROM ${name} WHERE false`), '42501');
    await deny(db.query(`TRUNCATE ${name}`), '42501');
    await deny(owner.query(`DELETE FROM ${name} WHERE false`), '23514');
    if (!updates) { await deny(owner.query(`UPDATE ${name} SET ${key}=${key} WHERE false`), '23514'); }
  }
  await deny(db.query('ALTER TABLE foundation.pricing_policy_versions ADD COLUMN forbidden integer'), '42501');
  await deny(db.query('CREATE TABLE foundation.p020_forbidden(id integer)'), '42501');
  const fn = await rows(db, `SELECT proname,pg_get_userbyid(proowner) AS owner,prosecdef,provolatile,proisstrict,proconfig,
    has_function_privilege(current_user,oid,'EXECUTE') AS runtime,
    has_function_privilege(current_user,oid,'EXECUTE WITH GRANT OPTION') AS elevate,
    EXISTS (SELECT FROM aclexplode(coalesce(proacl,acldefault('f',proowner))) acl
      WHERE acl.grantee NOT IN (proowner,to_regrole('fixlevelup_runtime')::oid)) AS other
    FROM pg_proc WHERE pronamespace='foundation'::regnamespace AND proname=ANY($1::text[]) ORDER BY proname COLLATE "C"`, [routines]);
  assert.deepEqual(fn, [...routines].sort().map(proname => ({ proname, owner: 'fixlevelup_migrator', prosecdef: false,
    provolatile: proname === unitsValidator ? 'i' : 'v', proisstrict: proname === unitsValidator,
    proconfig: ['search_path=pg_catalog'], runtime: proname === unitsValidator, elevate: false, other: false })));
  const fences = await rows(db, `SELECT c.relname AS name,t.tgname AS trigger,t.tgtype::int AS type,t.tgenabled AS enabled,
    t.tgqual IS NULL AS unconditional,t.tgnargs AS args
    FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='foundation'::regnamespace
      AND c.relname=ANY($1::text[]) AND t.tgfoid='foundation.catalog_lock_write()'::regprocedure
    ORDER BY c.relname COLLATE "C"`, [Object.keys(tables)]);
  assert.deepEqual(fences, Object.keys(tables).sort().map(name => ({ name, trigger: `${name}_write_fence`,
    type: tables[name][1] ? 22 : 6, enabled: 'O', unconditional: true, args: 0 })));
  const deferred = await rows(db, `SELECT tgname AS name FROM pg_trigger
    WHERE tgname=ANY($1::text[]) AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND NOT tgisinternal
      AND ((tgtype=5 AND tgfoid='foundation.pricing_guard_child_counts()'::regprocedure)
        OR (tgtype=21 AND tgfoid='foundation.pricing_guard_final_clock()'::regprocedure))
    ORDER BY tgname COLLATE "C"`, [[...deferredChildren, ...triples.map(([, , period]) => `${period}_final_clock_guard`)]]);
  assert.deepEqual(deferred.map(({ name }) => name), [...deferredChildren, ...triples.map(([, , period]) => `${period}_final_clock_guard`)].sort());
  for (const [, version, period] of triples) {
    const fk = await rows(db, `SELECT conname,condeferrable,condeferred,convalidated FROM pg_constraint
      WHERE conname=ANY($1::text[]) AND connamespace='foundation'::regnamespace AND contype='f' ORDER BY conname COLLATE "C"`,
    [[`${version}_period_fkey`, `${period}_version_fkey`]]);
    assert.deepEqual(fk, [
      { conname: `${version}_period_fkey`, condeferrable: true, condeferred: true, convalidated: true },
      { conname: `${period}_version_fkey`, condeferrable: false, condeferred: false, convalidated: true },
    ].sort((a, b) => a.conname < b.conname ? -1 : 1));
    const exclusion = await one(db, `SELECT pg_get_constraintdef(oid) AS definition FROM pg_constraint
      WHERE conname=$1 AND conrelid=$2::regclass AND contype='x' AND convalidated`, [`${period}_no_overlap`, `foundation.${period}`]);
    assert.match(exclusion?.definition ?? '', /EXCLUDE USING gist \(city_id(?: foundation\.gist_uuid_ops)? WITH =, series_id(?: foundation\.gist_uuid_ops)? WITH =, tstzrange\(valid_from, COALESCE\(closed_effective_until, scheduled_until\), '\[\)'::text\) WITH &&\)/i);
  }
}

async function proveFence(owner, db) {
  const holder = await one(owner, 'SELECT pg_backend_pid() AS pid');
  const waiter = await one(db, 'SELECT pg_backend_pid() AS pid');
  assert.notEqual(holder.pid, waiter.pid);
  await db.query("SET statement_timeout='7s'");
  await owner.query('BEGIN');
  let pending;
  try {
    await owner.query('SELECT pg_advisory_xact_lock_shared(77304,1)');
    pending = db.query("INSERT INTO foundation.price_rules(id,code,kind) VALUES($1,'p020-fence','EXPRESS')", [randomUUID()])
      .then(result => ({ result }), error => ({ error }));
    const deadline = performance.now() + 4000;
    let observed = false;
    do {
      const wait = await one(owner, `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid=$2 AND NOT granted
        AND locktype='advisory' AND mode='ExclusiveLock' AND classid=77304 AND objid=1 AND objsubid=2
        AND $1=ANY(pg_blocking_pids($2))) AS observed`, [holder.pid, waiter.pid]);
      if (wait.observed) { observed = true; break; }
      await delay(12);
    } while (performance.now() < deadline);
    assert.ok(observed, 'Expected observed SQL writer blocked by 019/P04 shared catalog fence');
  } finally {
    await owner.query('ROLLBACK');
    // Drain the waiter before issuing another statement, without masking the observed-wait assertion.
    await pending;
    await db.query('RESET statement_timeout');
  }
  const outcome = await pending;
  assert.ok(outcome, 'Expected the SQL writer to run after release');
  if (outcome.error) { throw outcome.error; }
  assert.equal(outcome.result.rowCount, 1);
  await deny(transact(db, () => db.query("INSERT INTO foundation.price_rules(id,code,kind) VALUES($1,'p020-rr','EXPRESS')", [randomUUID()]),
    'BEGIN ISOLATION LEVEL REPEATABLE READ'), '40001');
}

// Reuse the reviewed synthetic city/category installed by the 019 proof. All pricing writes below use the runtime role.
async function proveSql(db, reviewer, { cityA, cityB, cityAV, cityBV, category }) {
  const evening = randomUUID(), express = randomUUID(), night = randomUUID(), otherCategory = randomUUID(), brand = randomUUID();
  const categoryRevision = randomUUID();
  await transact(db, async () => {
    await db.query(`INSERT INTO foundation.catalog_directory_entries(id,kind,code)
      VALUES($1,'CATEGORY','p020-extra-category'),($2,'BRAND','p020-not-a-category')`, [otherCategory, brand]);
    await db.query(`INSERT INTO foundation.catalog_directory_versions(id,entry_id,version,title,reviewed_by)
      VALUES($1,$2,1,'Synthetic second category',$3)`, [categoryRevision, otherCategory, reviewer]);
    await db.query('UPDATE foundation.catalog_directory_entries SET current_version_id=$2 WHERE id=$1', [otherCategory, categoryRevision]);
    await db.query(`INSERT INTO foundation.price_rules(id,code,kind)
      VALUES($1,'p020-evening','EVENING'),($2,'p020-express','EXPRESS'),($3,'p020-night','NIGHT')`, [evening, express, night]);
  });
  const { start, end, adjacentEnd, micros } = await one(db, `SELECT t AS start,t+interval '1 hour' AS "end",t+interval '2 hours' AS "adjacentEnd",
    to_char((t AT TIME ZONE 'UTC') + interval '1 microsecond','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS micros
    FROM (SELECT date_trunc('milliseconds',clock_timestamp())+interval '1 hour' AS t) s`);
  const ruleFields = { rule_id: evening, kind: 'EVENING', title: 'Reviewed evening', method: 'FIXED', base: 'WORKS', currency: 'RUB',
    fixed_minor: '9223372036854775807', rate_bps: null, min_base: null, max_base: null, min_delta: null, max_delta: null,
    start_minute: 1080, end_minute: 10, wraps_midnight: true, scope_count: 0 };
  const policyFields = { currency: 'RUB', tax_display: 'Synthetic display', rounding_mode: 'HALF_UP', units: { piece: 0, 'hour-short': 6 },
    max_manual_delta_minor: '9223372036854775807', priority_count: 0, compatibility_count: 0 };
  const estimateFields = { title: 'Reviewed estimate', currency: 'RUB', min_minor: '0', max_minor: '9223372036854775807',
    conditions: null, disclaimer: 'Synthetic estimate only' };
  const insert = (table, fields) => db.query(`INSERT INTO foundation.${table}(${Object.keys(fields).join(',')})
    VALUES(${Object.keys(fields).map((_, index) => `$${index + 1}`).join(',')})`, Object.values(fields));
  const series = (table, city, extra = {}) => insert(table, { id: randomUUID(), city_id: city, ...extra });
  const version = (table, fields, more = {}) => insert(table, { source_ref: 'synthetic review', reviewed_by: reviewer,
    valid_from: start, valid_until: end, version: 1, ...fields, ...more });
  const period = (table, fields, more = {}) => insert(table, { version_id: fields.id, series_id: fields.series_id, city_id: fields.city_id,
    valid_from: start, scheduled_until: end, ...more });
  const scope = (rule, categoryId) => insert('price_rule_scopes', { rule_version_id: rule, category_id: categoryId });
  const priority = (pol, rule, value) => insert('price_rule_priorities', { policy_version_id: pol, rule_id: rule, priority: value });
  const pairs = (...ids) => ids.sort();
  const compatibility = (pol, [left, right]) => insert('price_rule_compatibilities', { policy_version_id: pol, left_rule_id: left, right_rule_id: right });
  let negative = 0;
  const rejected = async (request, code, constraint) => { await deny(request, code, constraint); negative++; };

  for (const [seriesTable, versionTable, periodTable, versionFields, seriesFields] of [
    [...triples[0], ruleFields, { rule_id: evening }],
    [...triples[1], policyFields, {}],
    [...triples[2], estimateFields, { category_id: category, code: 'p020-proof-range' }],
  ]) {
    const a = { id: randomUUID(), series_id: randomUUID(), city_id: cityA, city_version_id: cityAV };
    const b = { id: randomUUID(), series_id: randomUUID(), city_id: cityB, city_version_id: cityBV };
    await series(seriesTable, cityA, { id: a.series_id, ...seriesFields });
    await series(seriesTable, cityB, { id: b.series_id, ...seriesFields });
    const staged = (fields, override) => version(versionTable, { ...versionFields, ...fields }, override);
    await rejected(transact(db, () => staged(a)), '23503', `${versionTable}_period_fkey`); // deferred orphan at COMMIT
    await rejected(transact(db, () => staged(a, { city_version_id: cityBV })), '23503', `${versionTable}_city_basis_guard`);
    await rejected(transact(db, () => staged(a, { series_id: b.series_id })), '23503', `${versionTable}_series_fkey`);
    await rejected(transact(db, () => staged(a, { valid_from: micros })), '23514', `${versionTable}_valid_from_check`);
    await rejected(transact(db, async () => {
      await staged(a);
      await period(periodTable, a, { city_id: cityB, series_id: b.series_id });
    }), '23514', `${periodTable}_projection_guard`);
    await rejected(transact(db, async () => {
      await staged(a);
      await period(periodTable, a, { scheduled_until: null });
    }), '23514', `${periodTable}_projection_guard`);
    await rejected(transact(db, async () => {
      await staged(a);
      await period(periodTable, a, { closed_effective_until: new Date(start.getTime() + 1000) });
    }), '42501'); // cannot supply the closure column to INSERT
    await transact(db, async () => { await staged(a); await period(periodTable, a); await staged(b); await period(periodTable, b); });
    await rejected(transact(db, async () => {
      const competing = { ...a, id: randomUUID() };
      await db.query(`UPDATE foundation.${seriesTable} SET row_version=2 WHERE id=$1`, [a.series_id]);
      await staged(competing, { version: 2 });
      await period(periodTable, competing);
    }), '23P01', `${periodTable}_no_overlap`);
    await rejected(db.query(`UPDATE foundation.${periodTable} SET closed_effective_until=$2 WHERE version_id=$1`,
      [a.id, new Date(start.getTime() + 1000)]), '23514', `${periodTable}_close_guard`);
    const adjacent = { ...a, id: randomUUID() };
    await transact(db, async () => {
      await db.query(`UPDATE foundation.${seriesTable} SET row_version=2 WHERE id=$1`, [a.series_id]);
      await staged(adjacent, { version: 2, valid_from: end, valid_until: adjacentEnd });
      await period(periodTable, adjacent, { valid_from: end, scheduled_until: adjacentEnd });
    });
    assert.deepEqual(await rows(db, `SELECT ARRAY(SELECT version_id FROM foundation.${periodTable}
        WHERE series_id=$1 AND tstzrange(valid_from,coalesce(closed_effective_until,scheduled_until),'[)') @> probe.at) AS ids
      FROM unnest($2::timestamptz[]) WITH ORDINALITY AS probe(at,n) ORDER BY n`,
    [a.series_id, [-1, 0, 1].map(delta => new Date(end.getTime() + delta))]), [{ ids: [a.id] }, { ids: [adjacent.id] }, { ids: [adjacent.id] }]);
  }

  const expressSeries = randomUUID();
  await series('price_rule_series', cityA, { id: expressSeries, rule_id: express });
  const expressVersion = { ...ruleFields, id: randomUUID(), series_id: expressSeries, city_id: cityA, city_version_id: cityAV,
    rule_id: express, kind: 'EXPRESS', method: 'RATE', fixed_minor: null, rate_bps: 10000, start_minute: null, end_minute: null, wraps_midnight: null };
  for (const [overrides, suffix] of [
    [{ method: 'FIXED', fixed_minor: null, rate_bps: null }, 'method'],
    [{ method: 'FIXED', fixed_minor: '-1', rate_bps: null }, 'method'],
    [{ method: 'FIXED', fixed_minor: '1', rate_bps: 1 }, 'method'],
    [{ rate_bps: null }, 'method'], [{ rate_bps: 0 }, 'method'], [{ rate_bps: 10001 }, 'method'],
    [{ currency: 'rub' }, 'currency'], [{ min_base: '8', max_base: '7' }, 'base_bounds'], [{ max_delta: '-1' }, 'delta_bounds'],
    [{ start_minute: 5, end_minute: 10, wraps_midnight: false }, 'window'], [{ scope_count: 33 }, 'scope_count'],
  ]) {
    await rejected(version('price_rule_versions', expressVersion, overrides), '23514', `price_rule_versions_${suffix}_check`);
  }
  const nightSeries = randomUUID();
  await series('price_rule_series', cityA, { id: nightSeries, rule_id: night });
  const nightVersion = { ...ruleFields, id: randomUUID(), series_id: nightSeries, city_id: cityA, city_version_id: cityAV, rule_id: night, kind: 'NIGHT' };
  for (const overrides of [{ start_minute: null }, { end_minute: 1440 }, { end_minute: 1080 }, { wraps_midnight: false }]) {
    await rejected(version('price_rule_versions', nightVersion, overrides), '23514', 'price_rule_versions_window_check');
  }
  const scoped = { ...expressVersion, scope_count: 1 };
  await rejected(transact(db, async () => { await version('price_rule_versions', scoped); await period('price_rule_periods', scoped); }),
    '23514', 'price_rule_scopes_count_guard');
  await rejected(transact(db, async () => { await version('price_rule_versions', scoped); await scope(scoped.id, brand); }),
    '23503', 'price_rule_scopes_category_fkey');
  await transact(db, async () => { await version('price_rule_versions', scoped); await scope(scoped.id, category); await period('price_rule_periods', scoped); });
  await rejected(scope(scoped.id, otherCategory), '23514', 'price_rule_scopes_count_guard');
  assert.deepEqual(await rows(db, 'SELECT category_id FROM foundation.price_rule_scopes WHERE rule_version_id=$1', [scoped.id]), [{ category_id: category }]);

  const policySeries = await one(db, 'SELECT id FROM foundation.pricing_policy_series WHERE city_id=$1', [cityA]);
  const policy = { ...policyFields, id: randomUUID(), series_id: policySeries.id, city_id: cityA, city_version_id: cityAV };
  const tooManyUnits = Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`sku-${i}`, 0]));
  for (const units of [{}, '[]', { piece: '1' }, { piece: 7 }, { piece: -1 }, { piece: 1.5 }, { 'Upper-X': 1 }, { ['x'.repeat(25)]: 1 }, tooManyUnits]) {
    await rejected(version('pricing_policy_versions', policy, { version: 3, units }), '23514', 'pricing_policy_versions_units_check');
  }
  const dated = { version: 3, valid_from: adjacentEnd, valid_until: null };
  const newPolicyPeriod = () => period('pricing_policy_periods', policy, { valid_from: adjacentEnd, scheduled_until: null });
  const savePolicy = (priorityCount, compatibilityCount) => version('pricing_policy_versions', policy,
    { ...dated, priority_count: priorityCount, compatibility_count: compatibilityCount });
  await rejected(transact(db, async () => { await savePolicy(1, 0); await newPolicyPeriod(); }), '23514', 'price_rule_priorities_count_guard');
  await rejected(transact(db, async () => { await savePolicy(0, 1); await newPolicyPeriod(); }), '23514', 'price_rule_compatibilities_count_guard');
  await rejected(transact(db, async () => { await savePolicy(1, 0); await priority(policy.id, express, 1000001); }),
    '23514', 'price_rule_priorities_priority_check');
  await rejected(transact(db, async () => { await savePolicy(0, 1); await compatibility(policy.id, pairs(evening, express).reverse()); }),
    '23514', 'price_rule_compatibilities_order_check');
  await transact(db, async () => {
    await db.query('UPDATE foundation.pricing_policy_series SET row_version=3 WHERE id=$1', [policySeries.id]);
    await savePolicy(1, 1); await priority(policy.id, express, 1000000);
    await compatibility(policy.id, pairs(evening, express)); await newPolicyPeriod();
  });
  await rejected(priority(policy.id, night, 1), '23514', 'price_rule_priorities_count_guard');
  await rejected(compatibility(policy.id, pairs(night, express)), '23514', 'price_rule_compatibilities_count_guard');
  assert.deepEqual(await rows(db, `SELECT v.units, v.max_manual_delta_minor AS cap,
      (SELECT count(*)::int FROM foundation.price_rule_priorities WHERE policy_version_id=v.id) AS priorities,
      (SELECT count(*)::int FROM foundation.price_rule_compatibilities WHERE policy_version_id=v.id) AS compatibilities
    FROM foundation.pricing_policy_versions v WHERE v.id=$1`, [policy.id]),
  [{ units: policyFields.units, cap: '9223372036854775807', priorities: 1, compatibilities: 1 }]);

  await rejected(series('public_price_estimate_series', cityA, { category_id: brand, code: 'p020-false-category' }),
    '23503', 'public_price_estimate_series_category_fkey');
  const estimate = await one(db, 'SELECT id FROM foundation.public_price_estimate_series WHERE city_id=$1', [cityA]);
  await rejected(version('public_price_estimates', { ...estimateFields, id: randomUUID(), series_id: estimate.id,
    city_id: cityA, city_version_id: cityAV, version: 3 }, { min_minor: '42', max_minor: '41' }),
  '23514', 'public_price_estimates_range_check');
  assert.deepEqual(await rows(db, `SELECT DISTINCT min_minor,max_minor FROM foundation.public_price_estimates`),
    [{ min_minor: '0', max_minor: '9223372036854775807' }]);
  return negative;
}

export async function provePricingFresh(owner, db, reviewer, fixtures, kind = 'fresh') {
  const database = await isolated(owner, 'fixlevelup_migrator', kind);
  assert.equal(await isolated(db, 'fixlevelup_runtime', kind), database);
  await noSeed(owner);
  await proveAcl(owner, db);
  await proveFence(owner, db);
  const negative = await proveSql(db, reviewer, fixtures);
  console.log(`020 fresh: ${pricingChecks.length} independent CHECK names, ${Object.keys(tables).length} exact ACL/fence sets, real advisory wait, ${negative} direct SQL data refusals: PASS`);
}
