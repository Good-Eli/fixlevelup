import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

// Independent expected names; discovering CHECKs from the SQL would miss a removed guard.
const checks = (table, suffixes) => suffixes.map(suffix => `catalog_${table}_${suffix}_check`);
export const catalogFixedPriceChecks = [
  ...checks('directory_entries', ['kind', 'code', 'category_kind', 'brand_kind', 'parents', 'row_version', 'archive']),
  ...checks('directory_versions', ['version', 'title', 'description']),
  ...checks('items', ['kind', 'code', 'unit', 'category_kind', 'category_required', 'row_version', 'archive']),
  ...checks('item_versions', ['version', 'title', 'description', 'duration']),
  ...checks('fault_service_mappings', ['fault_kind', 'item_kind', 'row_version', 'publication', 'archive']),
  ...checks('price_series', ['row_version']),
  ...checks('price_versions', ['version', 'amount', 'currency', 'zero_basis', 'source_ref', 'valid_from', 'valid_until']),
  ...checks('price_periods', ['valid_from', 'scheduled_until', 'closed_until']),
];
const tables = {
  catalog_directory_entries: ['id kind code category_id brand_id', 'current_version_id archived_at'],
  catalog_directory_versions: ['id entry_id version title description reviewed_by', ''],
  catalog_items: ['id kind code category_id unit', 'current_version_id archived_at'],
  catalog_item_versions: ['id item_id kind version title description duration_minutes technician_visible public_visible reviewed_by', ''],
  catalog_fault_service_mappings: ['id category_id fault_id item_id', 'published_at published_by archived_at'],
  catalog_price_series: ['id city_id item_id', 'row_version'],
  catalog_price_versions: ['id series_id city_id city_version_id item_id item_version_id version amount_minor currency zero_basis source_ref reviewed_by valid_from valid_until', ''],
  catalog_price_periods: ['price_version_id series_id city_id item_id valid_from scheduled_until', 'closed_effective_until'],
};
const functions = ['catalog_lock_write', 'catalog_reject_history_change', 'catalog_guard_identity', 'catalog_guard_revision_chain',
  'catalog_guard_mapping', 'catalog_guard_price_series', 'catalog_guard_price_basis', 'catalog_guard_price_period', 'catalog_guard_price_final_clock'];
const rows = async (db, sql, params) => (await db.query(sql, params)).rows;
const one = async (db, sql, params) => (await rows(db, sql, params))[0];
const not = (sql, code, constraint) => assert.rejects(sql, { code, ...(constraint ? { constraint } : {}) });
const quote = s => `"${s.replaceAll('"', '""')}"`;
const history = db => rows(db, 'SELECT * FROM foundation._prisma_migrations ORDER BY migration_name COLLATE "C"');
const identity = async (db, role, kind) => {
  const context = await one(db, 'SELECT current_database() AS db, current_user AS role');
  assert.equal(context.role, role);
  assert.match(context.db, new RegExp(`^fixlevelup_p017a_${kind}_[a-f0-9]{12}$`));
};
async function baseTables(db) {
  return (await rows(db, `SELECT c.relname AS name FROM pg_class c
    WHERE c.relnamespace='foundation'::regnamespace AND c.relkind='r' AND c.relname<>'_prisma_migrations'
    ORDER BY c.relname COLLATE "C"`)).map(row => row.name);
}
async function snapshot(db, previous) {
  const data = [];
  for (const table of previous) {
    data.push(await rows(db, `SELECT to_jsonb(r)::text AS value FROM foundation.${quote(table)} r ORDER BY (to_jsonb(r)::text) COLLATE "C"`));
  }
  const definition = await rows(db, `SELECT c.relname, c.relowner,c.relacl::text,
    (SELECT jsonb_agg(jsonb_build_array(a.attname,a.atttypid,a.attnotnull,a.atttypmod,a.attacl::text) ORDER BY a.attnum)
      FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped) AS columns,
    (SELECT jsonb_agg(jsonb_build_array(k.conname,k.convalidated,pg_get_constraintdef(k.oid)) ORDER BY k.conname)
      FROM pg_constraint k WHERE k.conrelid=c.oid) AS constraints,
    (SELECT jsonb_agg(jsonb_build_array(g.tgname,g.tgenabled,pg_get_triggerdef(g.oid)) ORDER BY g.tgname)
      FROM pg_trigger g WHERE g.tgrelid=c.oid AND NOT g.tgisinternal) AS triggers
    FROM pg_class c WHERE c.relnamespace='foundation'::regnamespace AND c.relname=ANY($1::text[])
    ORDER BY c.relname COLLATE "C"`, [previous]);
  const grants = await rows(db, `SELECT nspname, nspowner,nspacl::text FROM pg_namespace
    WHERE nspname IN ('foundation','public') ORDER BY nspname COLLATE "C"`);
  return { data, definition, grants };
}

export async function proveCatalogMigrationUpgrade(db, migration, previousCount, deploy) {
  await identity(db, 'fixlevelup_migrator', 'upgrade');
  const oldHistory = await history(db), previous = await baseTables(db);
  assert.equal(oldHistory.length, previousCount);
  assert.ok(previous.includes('p03_command_receipts') && previous.includes('p03_bootstrap_permissions'));
  const old = await snapshot(db, previous);
  for (const name of ['audit_logs', 'service_cities', 'service_city_versions', 'reference_entries', 'staff']) {
    assert.ok(old.data[previous.indexOf(name)]?.length, `Missing populated 018 proof table: ${name}`);
  }
  deploy();
  const applied = await history(db), expected = [...previous, ...Object.keys(tables)].sort();
  assert.equal(applied.length, previousCount + 1);
  assert.deepEqual(applied.slice(0, previousCount), oldHistory);
  assert.equal(applied.at(-1)?.migration_name, migration);
  assert.ok(applied.at(-1)?.finished_at instanceof Date);
  assert.deepEqual(await baseTables(db), expected);
  assert.deepEqual(await snapshot(db, previous), old);
  for (const name of Object.keys(tables)) {
    assert.equal((await db.query(`SELECT FROM foundation.${name} LIMIT 1`)).rowCount, 0, `Unexpected data seed: ${name}`);
  }
  deploy();
  assert.deepEqual(await history(db), applied);
  assert.deepEqual(await snapshot(db, previous), old);
  assert.deepEqual(await baseTables(db), expected);
  console.log('019 populated 018 upgrade: exact old data/catalog/ACL and migration stamps, no seed, replay unchanged: PASS');
}

export async function proveCatalogMigrationAcl(db) {
  await identity(db, 'fixlevelup_runtime', 'fresh');
  for (const [table, [inserts, updates]] of Object.entries(tables)) {
    const name = `foundation.${table}`;
    const acl = await rows(db, `SELECT a.attname,
      has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT') AS readable,
      has_column_privilege(current_user,a.attrelid,a.attnum,'INSERT') AS insertable,
      has_column_privilege(current_user,a.attrelid,a.attnum,'UPDATE') AS writable,
      has_column_privilege(current_user,a.attrelid,a.attnum,'REFERENCES,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION') AS elevated,
      EXISTS (SELECT FROM aclexplode(a.attacl) p WHERE p.grantee=0) AS public
      FROM pg_attribute a WHERE a.attrelid=$1::regclass AND a.attnum>0 AND NOT a.attisdropped`, [name]);
    assert.ok(acl.length && acl.every(a => a.readable && !a.elevated && !a.public), `ACL projections: ${table}`);
    const by = p => acl.filter(a => a[p]).map(a => a.attname).sort();
    const columns = s => s.split(' ').filter(Boolean).sort();
    assert.deepEqual(by('insertable'), columns(inserts), `INSERT: ${table}`);
    assert.deepEqual(by('writable'), columns(updates), `UPDATE: ${table}`);
    const limits = await one(db, `SELECT pg_get_userbyid(c.relowner) AS owner,
      has_table_privilege(current_user,c.oid,'SELECT') AS readable,
      has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN,SELECT WITH GRANT OPTION') AS elevated,
      EXISTS (SELECT FROM aclexplode(c.relacl) p WHERE p.grantee=0) AS public
      FROM pg_class c WHERE c.oid=$1::regclass`, [name]);
    assert.deepEqual(limits, { owner: 'fixlevelup_migrator', readable: true, elevated: false, public: false });
    await not(db.query(`DELETE FROM ${name} WHERE false`), '42501');
    await not(db.query(`TRUNCATE ${name}`), '42501');
  }
  const routines = await rows(db, `SELECT p.proname, p.prosecdef, p.proconfig,
    has_function_privilege(current_user,p.oid,'EXECUTE') AS callable,
    EXISTS (SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0) AS public
    FROM pg_proc p WHERE p.pronamespace='foundation'::regnamespace AND p.proname=ANY($1::text[])
    ORDER BY p.proname COLLATE "C"`, [functions]);
  assert.deepEqual(routines, [...functions].sort().map(proname => ({
    proname, prosecdef: false, proconfig: ['search_path=pg_catalog'], callable: false, public: false,
  })));
  const fences = await rows(db, `SELECT c.relname AS name,t.tgtype::int AS type,t.tgenabled AS enabled
    FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_proc p ON p.oid=t.tgfoid
    WHERE c.relnamespace='foundation'::regnamespace AND p.proname='catalog_lock_write' ORDER BY c.relname COLLATE "C"`);
  assert.deepEqual(fences, Object.entries(tables).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([name, [, update]]) => ({ name, type: update ? 22 : 6, enabled: 'O' })));
  const exclusion = await one(db, `SELECT convalidated, contype, pg_get_constraintdef(oid) AS definition
    FROM pg_constraint WHERE conrelid='foundation.catalog_price_periods'::regclass AND conname='catalog_price_periods_no_overlap'`);
  assert.equal(exclusion?.convalidated, true);
  assert.equal(exclusion?.contype, 'x');
  assert.match(exclusion.definition, /EXCLUDE USING gist \(city_id(?: foundation\.gist_uuid_ops)? WITH =, item_id(?: foundation\.gist_uuid_ops)? WITH =, tstzrange\(valid_from, COALESCE\(closed_effective_until, scheduled_until\), '\[\)'::text\) WITH &&\)/i);
  const fks = await rows(db, `SELECT conname, condeferrable, condeferred, convalidated
    FROM pg_constraint WHERE conname IN ('catalog_price_versions_period_fkey','catalog_price_periods_version_fkey') ORDER BY conname COLLATE "C"`);
  assert.deepEqual(fks, [
    { conname: 'catalog_price_periods_version_fkey', condeferrable: false, condeferred: false, convalidated: true },
    { conname: 'catalog_price_versions_period_fkey', condeferrable: true, condeferred: true, convalidated: true },
  ]);
  const pinned = await one(db, `SELECT extversion,nspname FROM pg_extension x JOIN pg_namespace n ON n.oid=x.extnamespace WHERE extname='btree_gist'`);
  assert.deepEqual(pinned, { extversion: '1.8', nspname: 'foundation' });
  console.log('019 fresh runtime: 8 exact ACL/fence sets, sealed routines, validated EXCLUDE and reverse FK, extension pin: PASS');
}

async function transaction(db, run) {
  await db.query('BEGIN');
  try { await run(); await db.query('COMMIT'); }
  catch (e) { await db.query('ROLLBACK'); throw e; }
}

// Direct SQL invariants are separate from TS tests and use the real runtime role.
export async function proveCatalogMigrationRejections(owner, db, reviewer) {
  await identity(owner, 'fixlevelup_migrator', 'fresh');
  await identity(db, 'fixlevelup_runtime', 'fresh');
  const cityA = randomUUID(), cityB = randomUUID(), cityAV = randomUUID(), cityBV = randomUUID();
  for (const [id, version, code] of [[cityA, cityAV, 'p04-proof-a'], [cityB, cityBV, 'p04-proof-b']]) {
    await owner.query('INSERT INTO foundation.service_cities(id,code) VALUES($1,$2)', [id,code]);
    await owner.query(`INSERT INTO foundation.service_city_versions(id,city_id,version,display_name,timezone,public_contact,office_hours,reviewed_by)
      VALUES($1,$2,1,'Synthetic city','UTC','office@example.test',$3::jsonb,$4)`, [version,id,JSON.stringify(Array.from({ length: 7 }, () => [])),reviewer]);
    await owner.query(`UPDATE foundation.service_cities SET current_version_id=$2,lifecycle='ACTIVE' WHERE id=$1`, [id,version]);
  }
  const category = randomUUID(), categoryVersion = randomUUID(), part = randomUUID(), partVersion = randomUUID();
  await transaction(db, async () => {
    await db.query(`INSERT INTO foundation.catalog_directory_entries(id,kind,code) VALUES($1,'CATEGORY','p04-proof-category')`, [category]);
    await db.query(`INSERT INTO foundation.catalog_directory_versions(id,entry_id,version,title,reviewed_by)
      VALUES($1,$2,1,'Synthetic category',$3)`, [categoryVersion,category,reviewer]);
    await db.query(`UPDATE foundation.catalog_directory_entries SET current_version_id=$2 WHERE id=$1`, [category,categoryVersion]);
    await db.query(`INSERT INTO foundation.catalog_items(id,kind,code,category_id,unit) VALUES($1,'PART','p04-proof-part',$2,'piece')`, [part,category]);
    await db.query(`INSERT INTO foundation.catalog_item_versions(id,item_id,kind,version,title,technician_visible,public_visible,reviewed_by)
      VALUES($1,$2,'PART',1,'Synthetic part',true,false,$3)`, [partVersion,part,reviewer]);
    await db.query('UPDATE foundation.catalog_items SET current_version_id=$2 WHERE id=$1', [part,partVersion]);
  });
  await not(db.query(`INSERT INTO foundation.catalog_item_versions(id,item_id,kind,version,title,duration_minutes,
    technician_visible,public_visible,reviewed_by) VALUES($1,$2,'PART',2,'Invalid',20,true,false,$3)`,
  [randomUUID(),part,reviewer]), '23514', 'catalog_item_versions_duration_check');
  await not(db.query(`INSERT INTO foundation.catalog_directory_entries(id,kind,code,category_id,brand_id)
    VALUES($1,'MODEL','p04-proof-false-brand',$2,$2)`, [randomUUID(),category]), '23503', 'catalog_directory_entries_brand_fkey');
  await not(db.query('UPDATE foundation.catalog_items SET unit=$1 WHERE id=$2', ['pack',part]), '42501');
  await not(owner.query('UPDATE foundation.catalog_items SET unit=$1 WHERE id=$2', ['pack',part]), '23514');
  await not(owner.query('UPDATE foundation.catalog_item_versions SET title=$1 WHERE id=$2', ['Immutable',partVersion]), '23514');

  const seriesA = randomUUID(), seriesB = randomUUID(), priceA = randomUUID(), priceB = randomUUID();
  const { start, end, micros } = await one(db, `SELECT t AS start, t+interval '1 hour' AS "end",
    to_char((t AT TIME ZONE 'UTC') + interval '1 microsecond','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS micros
    FROM (SELECT date_trunc('milliseconds',clock_timestamp())+interval '1 hour' AS t) d`);
  const series = (id, city) => db.query('INSERT INTO foundation.catalog_price_series(id,city_id,item_id) VALUES($1,$2,$3)', [id,city,part]);
  const price = (id, s, city, cityVersion, version = 1, time = start) => db.query(`INSERT INTO foundation.catalog_price_versions(
    id,series_id,city_id,city_version_id,item_id,item_version_id,version,amount_minor,currency,source_ref,reviewed_by,valid_from,valid_until)
    VALUES($1,$2,$3,$4,$5,$6,$7,9223372036854775807,'RUB','synthetic-review',$8,$9,$10)`,
  [id,s,city,cityVersion,part,partVersion,version,reviewer,time,end]);
  const period = (id, s, city, startAt = start) => db.query(`INSERT INTO foundation.catalog_price_periods(
    price_version_id,series_id,city_id,item_id,valid_from,scheduled_until) VALUES($1,$2,$3,$4,$5,$6)`, [id,s,city,part,startAt,end]);
  await not(transaction(db, async () => { await series(seriesA,cityA); await price(priceA,seriesA,cityA,cityAV); }),
    '23503', 'catalog_price_versions_period_fkey');
  assert.equal((await one(db,'SELECT count(*)::int AS n FROM foundation.catalog_price_series')).n, 0);
  await not(transaction(db, async () => { await series(seriesA,cityA); await price(priceA,seriesA,cityA,cityBV); }), '23503');
  await not(transaction(db, async () => { await series(seriesA,cityA); await price(priceA,seriesA,cityA,cityAV,1,micros); }),
    '23514', 'catalog_price_versions_valid_from_check');
  await not(transaction(db, async () => { await series(seriesA,cityA); await price(priceA,seriesA,cityA,cityAV); await period(priceA,seriesA,cityB); }),
    '23514', 'catalog_price_periods_projection_guard');
  await transaction(db, async () => {
    await series(seriesA,cityA); await price(priceA,seriesA,cityA,cityAV); await period(priceA,seriesA,cityA);
    await series(seriesB,cityB); await price(priceB,seriesB,cityB,cityBV); await period(priceB,seriesB,cityB);
  });
  await not(transaction(db, async () => {
    const colliding = randomUUID();
    await db.query('UPDATE foundation.catalog_price_series SET row_version=2 WHERE id=$1', [seriesA]);
    await price(colliding,seriesA,cityA,cityAV,2);
    await period(colliding,seriesA,cityA);
  }), '23P01', 'catalog_price_periods_no_overlap');
  await not(db.query('UPDATE foundation.catalog_price_periods SET closed_effective_until=$2 WHERE price_version_id=$1',
    [priceA,new Date(start.getTime() + 1000)]), '23514', 'catalog_price_periods_close_guard');
  assert.deepEqual(await rows(db, `SELECT v.amount_minor::text AS amount, s.row_version, p.closed_effective_until AS closed
    FROM foundation.catalog_price_versions v JOIN foundation.catalog_price_periods p ON p.price_version_id=v.id
    JOIN foundation.catalog_price_series s ON s.id=v.series_id`), [
    { amount: '9223372036854775807', row_version: 1, closed: null },
    { amount: '9223372036854775807', row_version: 1, closed: null },
  ]);
  console.log('019 real SQL negatives: kinds and immutable unit, missing/mismatched projections, cross-city basis, micros, scheduled close and overlap; overlapping different cities and BIGINT max preserved: PASS');
}
