/**
 * Disposable single-purpose database for a measurement (task-1 lab).
 *
 * Creates exactly ONE new database `fixlevelup_p05_<purpose>lab_<hex>` owned by
 * `fixlevelup_migrator`, applies the reviewed migration chain prefix and installs
 * the pinned `_prisma_migrations` history, then prints its OID. An existing name
 * is a hard error (CREATE is the reuse guard), so it can never "upgrade" a
 * database that already exists — in particular never the 023 gateway database.
 *
 * `--drop <oid>` removes exactly that database after the measurement, and only
 * after re-proving that the name still carries the same OID and the disposable
 * prefix. No other database, role or object is touched.
 */
import { createHash, randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';

const apiRequire = createRequire(new URL('../../apps/api/package.json', import.meta.url));
const { Client } = apiRequire('pg');

const MIGRATION_ROOT = resolve(import.meta.dirname, '../../prisma/migrations');
const DISPOSABLE = /^fixlevelup_p05_[a-z0-9_]{1,48}$/;
const WORKING_DATABASE = 'fixlevelup_dev';
const HEX64 = /^[a-f0-9]{64}$/;

function secret(name) {
  const value = process.env[name] ?? '';
  if (!HEX64.test(value)) { throw new Error(`Lab credential unavailable: ${name}`); }
  return value;
}
function migrationChecksum(name) {
  const sql = readFileSync(resolve(MIGRATION_ROOT, name, 'migration.sql'), 'utf8').replaceAll('\r\n', '\n');
  return createHash('sha256').update(sql, 'utf8').digest('hex');
}
async function scalar(client, sql, values = []) { return (await client.query(sql, values)).rows[0]; }

function chain() {
  return readdirSync(MIGRATION_ROOT, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && /^\d{14}_/.test(entry.name))
    .map((entry) => entry.name).sort();
}

async function admin() {
  const client = new Client({ host: '127.0.0.1', port: 55432, database: 'postgres', user: 'postgres',
    password: secret('FIXLEVELUP_LAB_FIXTURE_ADMIN_PASSWORD'), connectionTimeoutMillis: 5000,
    statement_timeout: 120_000, application_name: 'p05lab-makedb' });
  await client.connect();
  return client;
}

async function create() {
  const database = process.env['FIXLEVELUP_LAB_DATABASE'] ?? '';
  const limit = Number(process.env['FIXLEVELUP_LAB_MIGRATION_LIMIT'] ?? '');
  const migratorPassword = secret('FIXLEVELUP_MIGRATOR_PASSWORD');
  if (!DISPOSABLE.test(database) || database === WORKING_DATABASE) { throw new Error('Invalid disposable database'); }
  const all = chain();
  if (!Number.isInteger(limit) || limit < 1 || limit > all.length) { throw new Error('Invalid migration limit'); }
  const applied = all.slice(0, limit);

  const control = await admin();
  try {
    if ((await scalar(control, 'SELECT 1 AS present FROM pg_database WHERE datname=$1', [database]))?.present === 1) {
      throw new Error('Disposable database already exists; refusing to reuse it');
    }
    await control.query(`CREATE DATABASE "${database}" OWNER "fixlevelup_migrator" TEMPLATE template0`);
    await control.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`);
    await control.query(`GRANT CONNECT ON DATABASE "${database}" TO "fixlevelup_migrator", "fixlevelup_runtime"`);
  } finally { await control.end(); }

  const client = new Client({ host: '127.0.0.1', port: 55432, database, user: 'fixlevelup_migrator',
    password: migratorPassword, connectionTimeoutMillis: 5000, statement_timeout: 180_000,
    application_name: 'p05lab-makedb' });
  await client.connect();
  try {
    const identity = await scalar(client, `SELECT current_database() AS db, current_user AS role,
      pg_get_userbyid(datdba) AS owner FROM pg_database WHERE datname=current_database()`);
    if (identity?.db !== database || identity.role !== 'fixlevelup_migrator' || identity.owner !== 'fixlevelup_migrator') {
      throw new Error('Disposable database identity mismatch');
    }
    for (const name of applied) {
      await client.query(readFileSync(resolve(MIGRATION_ROOT, name, 'migration.sql'), 'utf8'));
    }
    await client.query(`CREATE TABLE IF NOT EXISTS foundation._prisma_migrations (
      id text PRIMARY KEY, checksum varchar(64) NOT NULL, finished_at timestamptz,
      migration_name varchar(255) NOT NULL, logs text, rolled_back_at timestamptz,
      started_at timestamptz NOT NULL DEFAULT clock_timestamp(), applied_steps_count integer NOT NULL DEFAULT 1)`);
    await client.query('DELETE FROM foundation._prisma_migrations');
    for (const name of applied) {
      await client.query(`INSERT INTO foundation._prisma_migrations
        (id, checksum, finished_at, migration_name, rolled_back_at, applied_steps_count)
        VALUES ($1, $2, clock_timestamp(), $3, NULL, 1)`, [randomBytes(16).toString('hex'), migrationChecksum(name), name]);
    }
  } finally { await client.end(); }

  const oidClient = await admin();
  try {
    const oid = (await scalar(oidClient, 'SELECT oid::text AS oid FROM pg_database WHERE datname=$1', [database]))?.oid;
    process.stdout.write(`${JSON.stringify({ ok: true, database, oid, migrations: applied.length,
      lastMigration: applied.at(-1) })}\n`);
  } finally { await oidClient.end(); }
}

async function drop() {
  const oid = process.argv[3] ?? '';
  const client = await admin();
  try {
    const row = await scalar(client, `SELECT oid::text AS oid, datname FROM pg_database WHERE oid=$1::oid`, [oid]);
    if (!row || !DISPOSABLE.test(row.datname) || row.datname === WORKING_DATABASE || String(row.oid) !== oid) {
      throw new Error('Refusing to drop: not this run\'s disposable database');
    }
    await client.query(`ALTER DATABASE "${row.datname}" ALLOW_CONNECTIONS false`);
    await client.query(`DROP DATABASE "${row.datname}"`);
    process.stdout.write(`${JSON.stringify({ ok: true, dropped: row.datname })}\n`);
  } finally { await client.end(); }
}

/**
 * `empty` mode: create ONE new EMPTY database owned by `fixlevelup_migrator`
 * (no migrations, no history). Used as a Prisma shadow database: Prisma replays
 * migration files into it and only needs the database to exist and be owned by
 * the connecting role — no CREATEDB privilege is required from that role.
 */
async function createEmpty() {
  const database = process.env['FIXLEVELUP_LAB_DATABASE'] ?? '';
  if (!DISPOSABLE.test(database) || database === WORKING_DATABASE) { throw new Error('Invalid disposable database'); }
  const control = await admin();
  let oid;
  try {
    if ((await scalar(control, 'SELECT 1 AS present FROM pg_database WHERE datname=$1', [database]))?.present === 1) {
      throw new Error('Disposable database already exists; refusing to reuse it');
    }
    await control.query(`CREATE DATABASE "${database}" OWNER "fixlevelup_migrator" TEMPLATE template0`);
    await control.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`);
    await control.query(`GRANT CONNECT ON DATABASE "${database}" TO "fixlevelup_migrator", "fixlevelup_runtime"`);
    oid = (await scalar(control, 'SELECT oid::text AS oid FROM pg_database WHERE datname=$1', [database]))?.oid;
  } finally { await control.end(); }
  process.stdout.write(`${JSON.stringify({ ok: true, database, oid, migrations: 0, lastMigration: null })}\n`);
}

if (process.argv[2] === 'drop') { await drop(); }
else if (process.argv[2] === 'empty') { await createEmpty(); }
else { await create(); }
