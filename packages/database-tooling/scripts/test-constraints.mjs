import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { admin, credentials, connection } from './migration-local.mjs';

function assert(condition, label) { if (!condition) { throw new Error(label); } }
let negativeCount = 0;
async function rejects(client, sql, expected) {
  try { await client.query(sql); }
  catch (error) { assert(error.code === expected, `Expected ${expected}, got ${error.code}; constraint=${error.constraint ?? 'unknown'}; synthetic SQL=${sql}`); negativeCount++; return; }
  throw new Error(`Expected ${expected}, statement was accepted`);
}
const bootstrap = await admin();
const password = credentials();
const database = `fixlevelup_p017b_proof_${randomBytes(6).toString('hex')}`;
let migration, runtime, contender;
try {
  assert((await bootstrap.query('SELECT 1 FROM pg_database WHERE datname=$1', [database])).rowCount === 0, 'Existing test DB');
  await bootstrap.query(`CREATE DATABASE "${database}" OWNER fixlevelup_migrator`);
  const localPassword = readFileSync(new URL('../../../infra/dev-postgres/.env', import.meta.url), 'utf8').match(/^POSTGRES_PASSWORD=([a-f0-9]{64})$/m)?.[1];
  const extensionAdmin = connection('fixlevelup_dev', localPassword, database);
  await extensionAdmin.connect();
  try { await extensionAdmin.query('CREATE EXTENSION btree_gist'); }
  finally { await extensionAdmin.end(); }
  migration = connection('fixlevelup_migrator', password.fixlevelup_migrator, database);
  await migration.connect();
  await migration.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`);
  await migration.query(`GRANT CONNECT ON DATABASE "${database}" TO fixlevelup_runtime`);
  const sql = readFileSync(new URL('../proofs/constraints.sql', import.meta.url), 'utf8').replace('CREATE EXTENSION btree_gist;', '');
  await migration.query(sql);
  runtime = connection('fixlevelup_runtime', password.fixlevelup_runtime, database);
  contender = connection('fixlevelup_runtime', password.fixlevelup_runtime, database);
  await runtime.connect(); await contender.connect();
  await runtime.query("SET TIME ZONE 'UTC'");
  await contender.query("SET TIME ZONE 'UTC'");
  console.log(`Synthetic proof database: ${database}`);
  await runtime.query(`
    INSERT INTO proof.city VALUES(1,'SYNTHETIC_CITY_A'),(2,'SYNTHETIC_CITY_B');
    INSERT INTO proof.city_version VALUES(1,1,'SYNTHETIC_CITY_A','Etc/GMT-3'),(2,1,'SYNTHETIC_CITY_B','Etc/GMT-7');
    INSERT INTO proof.zone_version VALUES(1,11,1,'SYNTHETIC_ZONE_A'),(2,22,1,'SYNTHETIC_ZONE_B');
    INSERT INTO proof.district VALUES(1,111),(2,222);
    INSERT INTO proof.coverage VALUES(1,11,1,111,'PARTIAL');
    INSERT INTO proof.request VALUES(101,1,1),(102,2,1);
    INSERT INTO proof.address_snapshot VALUES(201,101,1,1,'SYNTHETIC_CITY_A','Etc/GMT-3',11,1,'SYNTHETIC_ZONE_A'),
      (202,102,2,1,'SYNTHETIC_CITY_B','Etc/GMT-7',22,1,'SYNTHETIC_ZONE_B');
    INSERT INTO proof.plan VALUES(301,101,1,201,'2026-01-01T07:00Z','2026-01-01T08:00Z',true);
    INSERT INTO proof.file VALUES(401),(402);
    INSERT INTO proof.report(id,request_id) VALUES(501,101),(502,102);
    INSERT INTO proof.quote VALUES(601,101),(602,102),(603,101);
    UPDATE proof.report SET quote_id=601 WHERE id=501;
    UPDATE proof.report SET quote_id=602 WHERE id=502;
    INSERT INTO proof.quote_line VALUES(701,101,601,100,1),(702,102,602,200,1),(704,101,603,150,1);
    INSERT INTO proof.report_file VALUES(101,501,401);
    INSERT INTO proof.report_line VALUES(501,101,601,701);
    INSERT INTO proof.price VALUES(801,1,1,'[2026-01-01,2026-02-01)',100),(802,2,1,'[2026-01-01,2026-02-01)',200),
      (803,1,1,'[2026-02-01,2026-03-01)',150);
    INSERT INTO proof.accepted_price_snapshot VALUES(901,101,1,801,100);
    INSERT INTO proof.membership VALUES(1001,1),(1001,2);
    INSERT INTO proof.zone_grant VALUES(1001,1,11,1),(1001,2,22,1);
  `);
  // Callback is city-bound even without an address; another city requires no ALTER.
  assert((await runtime.query('SELECT count(*)::int AS count FROM proof.request')).rows[0].count === 2, 'Second city proof');
  await runtime.query('INSERT INTO proof.request VALUES(103,1,1)');
  assert((await runtime.query('SELECT count(*)::int AS count FROM proof.address_snapshot WHERE request_id=103')).rows[0].count === 0, 'Callback forced address');
  await rejects(runtime, 'INSERT INTO proof.request VALUES(104,NULL,1)', '23502');
  await rejects(runtime, 'INSERT INTO proof.request VALUES(104,2,999)', '23503');
  await rejects(runtime, "INSERT INTO proof.coverage VALUES(1,11,1,222,'FULL')", '23503');
  await rejects(runtime, "INSERT INTO proof.address_snapshot VALUES(203,101,2,1,'X','Etc/UTC',22,1,'X')", '23503');
  await rejects(runtime, "INSERT INTO proof.plan VALUES(302,101,2,202,'2026-01-01T07:00Z','2026-01-01T08:00Z',false)", '23503');
  await rejects(runtime, "INSERT INTO proof.plan VALUES(302,101,1,201,'2026-01-01T08:00Z','2026-01-01T07:00Z',false)", '23514');
  await rejects(runtime, "INSERT INTO proof.plan VALUES(302,101,1,201,'2026-01-02T07:00Z','2026-01-02T08:00Z',true)", '23505');
  await rejects(runtime, 'INSERT INTO proof.report_file VALUES(102,501,402)', '23503');
  await rejects(runtime, 'INSERT INTO proof.report_file VALUES(102,502,999)', '23503');
  await rejects(runtime, 'INSERT INTO proof.report_line VALUES(501,101,602,702)', '23503');
  await rejects(runtime, 'INSERT INTO proof.report_line VALUES(501,101,603,704)', '23503');
  await rejects(runtime, 'INSERT INTO proof.quote_line VALUES(703,101,601,-1,1)', '23514');
  await rejects(runtime, 'INSERT INTO proof.quote_line VALUES(703,101,601,1,0)', '23514');
  await rejects(runtime, "INSERT INTO proof.price VALUES(804,1,1,'[2026-01-15,2026-02-15)',100)", '23P01');
  await rejects(runtime, "INSERT INTO proof.price VALUES(804,1,1,'empty',100)", '23514');
  await rejects(runtime, "INSERT INTO proof.price VALUES(804,1,1,'[2026-03-01,2026-04-01)',-1)", '23514');
  await rejects(runtime, 'INSERT INTO proof.accepted_price_snapshot VALUES(902,101,1,802,200)', '23503');
  await rejects(runtime, 'INSERT INTO proof.zone_grant VALUES(1002,1,11,1)', '23503');
  await rejects(runtime, 'INSERT INTO proof.zone_grant VALUES(1001,1,22,1)', '23503');
  await rejects(runtime, "UPDATE proof.address_snapshot SET timezone='Etc/UTC' WHERE id=201", '42501');
  await rejects(runtime, 'DELETE FROM proof.address_snapshot WHERE id=201', '42501');
  await rejects(runtime, "UPDATE proof.city_version SET name='CHANGED' WHERE city_id=1", '42501');
  await rejects(runtime, "UPDATE proof.zone_version SET label='CHANGED' WHERE city_id=1", '42501');
  await rejects(runtime, 'DELETE FROM proof.zone_version WHERE city_id=1', '42501');
  await rejects(runtime, 'UPDATE proof.accepted_price_snapshot SET amount_minor=999 WHERE id=901', '42501');
  await rejects(runtime, 'UPDATE proof.request SET city_id=2,city_version=1 WHERE id=103', '42501');
  await runtime.query("UPDATE proof.city SET name='SYNTHETIC_CITY_A_RENAMED' WHERE id=1; INSERT INTO proof.city_version VALUES(1,2,'SYNTHETIC_CITY_A_RENAMED','Etc/GMT-3'); INSERT INTO proof.zone_version VALUES(1,11,2,'SYNTHETIC_ZONE_A_REZONED'); UPDATE proof.price SET amount_minor=999 WHERE id=801");
  const history = (await runtime.query('SELECT city_name,timezone,zone_label,(SELECT amount_minor::text FROM proof.accepted_price_snapshot WHERE id=901) AS accepted FROM proof.address_snapshot WHERE id=201')).rows[0];
  assert(history.city_name === 'SYNTHETIC_CITY_A' && history.timezone === 'Etc/GMT-3' && history.zone_label === 'SYNTHETIC_ZONE_A' && history.accepted === '100', 'Historical snapshot changed');
  const offsets = (await runtime.query("SELECT ('2026-01-01 10:00'::timestamp AT TIME ZONE timezone) AS utc FROM proof.city_version WHERE version=1 ORDER BY city_id")).rows;
  assert(offsets[0].utc.toISOString() === '2026-01-01T07:00:00.000Z' && offsets[1].utc.toISOString() === '2026-01-01T03:00:00.000Z', 'City timezone snapshot proof');
  console.log(`FK/CHECK/partial UNIQUE/EXCLUDE and immutable history: PASS; ${String(negativeCount)} negative SQLSTATE assertions.`);
  // A technician has a SINGLE global resource key, irrespective of city membership.
  await runtime.query('BEGIN'); await contender.query('BEGIN');
  await runtime.query('SELECT pg_advisory_xact_lock(1001::bigint)');
  assert((await contender.query('SELECT pg_try_advisory_xact_lock(1001::bigint) AS locked')).rows[0].locked === false, 'Same tech lock split by city');
  assert((await contender.query('SELECT pg_try_advisory_xact_lock(1002::bigint) AS locked')).rows[0].locked === true, 'Different technician unexpectedly blocked');
  await runtime.query('COMMIT');
  assert((await contender.query('SELECT pg_try_advisory_xact_lock(1001::bigint) AS locked')).rows[0].locked === true, 'Global lock not released on commit');
  await contender.query('ROLLBACK');
  console.log('Global technician transaction advisory-lock cross-city proof: PASS.');
  console.log('P01-01.7B synthetic SQL proofs: PASS; no domain migrations/dev schema changes. Test DB retained.');
} catch (error) { console.error(`Constraint proof failed: ${error.message}`); process.exitCode = 1; }
finally {
  for (const client of [runtime, contender, migration, bootstrap]) {
    if (client) { try { await client.query('ROLLBACK'); } catch { /* best effort transaction cleanup */ } await client.end(); }
  }
}
