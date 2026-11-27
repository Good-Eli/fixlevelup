/**
 * P05 lab attestation (task-1) — read-only check of an already-provisioned lab.
 *
 * Prints the same one-line JSON summary as `provision.mjs`, but only after
 * proving every expected object exists in the expected shape. It never creates,
 * alters or drops anything, so `lab.mjs up` can safely call it on an existing
 * lab and skip provisioning.
 */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';

const apiRequire = createRequire(new URL('../../apps/api/package.json', import.meta.url));
const { Client } = apiRequire('pg');

const HEX64 = /^[a-f0-9]{64}$/;
const MIGRATION_ROOT = resolve(import.meta.dirname, '../../prisma/migrations');
const WORKING_DATABASE = 'fixlevelup_dev';

function secret(name) {
  const value = process.env[name] ?? '';
  if (!HEX64.test(value)) { throw new Error(`Lab credential unavailable: ${name}`); }
  return value;
}
function migrationChecksum(name) {
  const sql = readFileSync(resolve(MIGRATION_ROOT, name, 'migration.sql'), 'utf8').replaceAll('\r\n', '\n');
  return createHash('sha256').update(sql, 'utf8').digest('hex');
}
function manifestDigest(entries) {
  return createHash('sha256').update(entries.map((entry) => `${entry.name}:${entry.checksum}`).join('\n'), 'utf8').digest('hex');
}
async function scalar(client, sql, values = []) {
  const { rows } = await client.query(sql, values);
  return rows[0];
}

async function main() {
  const passwords = {
    admin: secret('FIXLEVELUP_LAB_FIXTURE_ADMIN_PASSWORD'),
    migrator: secret('FIXLEVELUP_MIGRATOR_PASSWORD'),
  };
  const database = process.env['FIXLEVELUP_LAB_DATABASE'] ?? '';
  const controlDatabase = process.env['FIXLEVELUP_LAB_CONTROL_DATABASE'] ?? '';
  const launcherRole = process.env['FIXLEVELUP_LAB_CONTROL_ROLE'] ?? '';
  const limit = Number(process.env['FIXLEVELUP_LAB_MIGRATION_LIMIT'] ?? '');
  if (!/^fixlevelup_p05_[a-z0-9_]{1,48}$/.test(database) || database === WORKING_DATABASE) {
    throw new Error('Invalid lab application database');
  }
  if (!Number.isInteger(limit) || limit < 1) { throw new Error('Invalid migration limit'); }

  const admin = new Client({ host: '127.0.0.1', port: 55432, database: 'postgres', user: 'postgres',
    password: passwords.admin, connectionTimeoutMillis: 5000, statement_timeout: 30_000,
    application_name: 'p05lab-attest' });
  await admin.connect();
  try {
    const cluster = process.env['FIXLEVELUP_CLUSTER_NAME'] ?? '';
    const identity = await scalar(admin, `SELECT current_setting('server_version_num')::int AS version,
      current_setting('cluster_name') AS cluster, coalesce(host(inet_server_addr()),'') AS address,
      coalesce(inet_server_port(),0) AS port,
      EXISTS(SELECT FROM pg_database WHERE datname=$1) AS has_working_database`, [WORKING_DATABASE]);
    if (identity?.version !== 180007 || identity.cluster !== cluster
      || identity.address !== '127.0.0.1' || identity.port !== 55432 || identity.has_working_database !== false) {
      throw new Error('Lab cluster identity mismatch');
    }
    const roles = await admin.query(`SELECT rolname FROM pg_roles WHERE rolname = ANY($1::text[]) ORDER BY rolname`,
      [['fixlevelup_lab_orchestrator', 'fixlevelup_migrator', 'fixlevelup_runtime']]);
    if (roles.rowCount !== 3) { throw new Error('Lab roles missing'); }
    const databaseRow = await scalar(admin, `SELECT oid::text AS oid, pg_get_userbyid(datdba) AS owner
      FROM pg_database WHERE datname=$1`, [database]);
    if (databaseRow?.owner !== 'fixlevelup_migrator') { throw new Error('Lab application database owner mismatch'); }
    const controlRow = await scalar(admin, 'SELECT 1 AS present FROM pg_database WHERE datname=$1', [controlDatabase]);
    if (controlRow?.present !== 1) { throw new Error('Lab control database missing'); }
    const launcher = await scalar(admin, 'SELECT 1 AS present FROM pg_roles WHERE rolname=$1', [launcherRole]);
    if (launcher?.present !== 1) { throw new Error('Lab launcher role missing'); }
  } finally { await admin.end(); }

  const app = new Client({ host: '127.0.0.1', port: 55432, database, user: 'fixlevelup_migrator',
    password: passwords.migrator, connectionTimeoutMillis: 5000, statement_timeout: 60_000,
    application_name: 'p05lab-attest' });
  await app.connect();
  let migrations;
  try {
    const chain = readdirSync(MIGRATION_ROOT, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && /^\d{14}_/.test(entry.name))
      .map((entry) => entry.name).sort().slice(0, limit);
    const rows = (await app.query('SELECT migration_name, checksum, finished_at, rolled_back_at, applied_steps_count FROM foundation._prisma_migrations ORDER BY migration_name')).rows;
    if (rows.length !== chain.length) { throw new Error('Lab migration history length mismatch'); }
    const entries = [];
    for (const [index, name] of chain.entries()) {
      const row = rows[index];
      if (row?.migration_name !== name || !(row.finished_at instanceof Date)
        || row.rolled_back_at !== null || row.applied_steps_count !== 1) {
        throw new Error('Lab migration history shape mismatch');
      }
      const checksum = migrationChecksum(name);
      if (row.checksum !== checksum) { throw new Error('Lab migration checksum mismatch'); }
      entries.push({ name, checksum });
    }
    migrations = { applied: chain.length, lastMigration: chain.at(-1), historyManifestDigest: manifestDigest(entries) };
  } finally { await app.end(); }

  const control = new Client({ host: '127.0.0.1', port: 55432, database: controlDatabase, user: 'postgres',
    password: passwords.admin, connectionTimeoutMillis: 5000, statement_timeout: 30_000,
    application_name: 'p05lab-attest' });
  await control.connect();
  try {
    const registry = await scalar(control, `SELECT to_regclass('launch_control.launch_proofs') IS NOT NULL AS present`);
    if (registry?.present !== true) { throw new Error('Lab launch registry missing'); }
  } finally { await control.end(); }

  const admin2 = new Client({ host: '127.0.0.1', port: 55432, database: 'postgres', user: 'postgres',
    password: passwords.admin, connectionTimeoutMillis: 5000, application_name: 'p05lab-attest' });
  await admin2.connect();
  try {
    const databases = await admin2.query('SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY datname');
    const summary = { ok: true, cluster: process.env['FIXLEVELUP_CLUSTER_NAME'], database,
      databaseOid: String((await scalar(admin2, 'SELECT oid::text AS oid FROM pg_database WHERE datname=$1', [database])).oid),
      migrations: migrations.applied, lastMigration: migrations.lastMigration,
      historyManifestDigest: migrations.historyManifestDigest, controlDatabase, launcherRole,
      databases: databases.rows.map((row) => row.datname) };
    process.stdout.write(`${JSON.stringify(summary)}\n`);
  } finally { await admin2.end(); }
}

await main();
