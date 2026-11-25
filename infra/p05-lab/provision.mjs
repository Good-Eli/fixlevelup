/**
 * P05 lab provisioning (task-1) — runs INSIDE the private lab runner container,
 * never on the host and never against the working cluster.
 *
 * The PostgreSQL container and this runner share one private network namespace
 * (`--network none` on PostgreSQL, `--network container:<pg>` on the runner), so
 * the only reachable endpoint is loopback `127.0.0.1:55432` inside that
 * namespace. `fixlevelup_dev` does not exist there and is refused explicitly.
 *
 * Provisioned state (all synthetic, all discarded with the container):
 *  - roles `fixlevelup_migrator`, `fixlevelup_runtime` (exact names 022/023 DDL
 *    requires) and the scoped `fixlevelup_lab_orchestrator` (LOGIN, CREATEDB,
 *    NOINHERIT, MEMBER of the migrator, no superuser — the identity
 *    `apps/api/tests/p05-lab-target.ts` attests);
 *  - one application database owned by the migrator with the reviewed migration
 *    chain applied from `/workspace/prisma/migrations` and a pinned
 *    `foundation._prisma_migrations` history whose checksums are the exact
 *    SHA-256 of the LF-normalized migration scripts (same manifest the test
 *    fixture builds in `apps/api/tests/auth-db-fixture.ts`);
 *  - one disposable control database with the launcher-only registry contour
 *    (`ensureLaunchRegistry` from the frozen tree) and a narrow launcher role
 *    that can only SELECT/INSERT and UPDATE(state, consumed_at).
 *
 * Everything is idempotence-hostile on purpose: an existing role or database is
 * a hard error, so a re-run can never "repair" or mutate a previous lab.
 *
 * No credential is printed. The result on stdout is one JSON line.
 */
import { createHash, randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';

// `pg` is an api-package dependency (not hoisted to the workspace root): resolve
// it exactly as the tests do, from `apps/api/package.json`.
const apiRequire = createRequire(new URL('../../apps/api/package.json', import.meta.url));
const { Client } = apiRequire('pg');
import { writeContainerEnv } from './containerenv.mjs';

const HEX64 = /^[a-f0-9]{64}$/;
const CONTROL_DATABASE = /^fixlevelup_p05_control_[a-f0-9]{12}$/;
const LAUNCHER_ROLE = /^fixlevelup_p05_launcher_[a-f0-9]{12}$/;
const APP_DATABASE = /^fixlevelup_p05_[a-z0-9_]{1,48}$/;
const CLUSTER = /^fixlevelup_p05s4_lab_[a-z0-9_]{1,40}$/;
const WORKING_DATABASE = 'fixlevelup_dev';
const PG_SERVER_VERSION_NUM = 180007;
const MIGRATION_ROOT = resolve(import.meta.dirname, '../../prisma/migrations');

function secret(name) {
  const value = process.env[name] ?? '';
  if (!HEX64.test(value)) { throw new Error(`Lab credential unavailable: ${name}`); }
  return value;
}

function required(name, pattern, label) {
  const value = process.env[name] ?? '';
  if (!pattern.test(value)) { throw new Error(`Invalid lab ${label}`); }
  return value;
}

/** Exact SHA-256 of the migration script with newline form normalized. */
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

/** Server-side proof that this is the private lab cluster and nothing else. */
async function attestCluster(admin) {
  const cluster = required('FIXLEVELUP_CLUSTER_NAME', CLUSTER, 'cluster name');
  const row = await scalar(admin, `SELECT
    current_setting('server_version_num')::int AS version,
    current_setting('cluster_name') AS cluster,
    coalesce(host(inet_server_addr()),'') AS address,
    coalesce(inet_server_port(),0) AS port,
    EXISTS(SELECT FROM pg_database WHERE datname=$1) AS has_working_database`, [WORKING_DATABASE]);
  if (row?.version !== PG_SERVER_VERSION_NUM) { throw new Error('Lab cluster must be PostgreSQL 18.7'); }
  if (row.cluster !== cluster) { throw new Error('Lab cluster marker mismatch'); }
  if (row.address !== '127.0.0.1' || row.port !== 55432) { throw new Error('Lab cluster must be loopback 127.0.0.1:55432'); }
  if (row.has_working_database !== false) { throw new Error('Working database must not exist in the lab cluster'); }
  return cluster;
}

async function createRoles(admin, passwords) {
  const existing = await admin.query(`SELECT rolname FROM pg_roles WHERE rolname = ANY($1::text[])`,
    [['fixlevelup_migrator', 'fixlevelup_runtime', 'fixlevelup_lab_orchestrator']]);
  if (existing.rowCount !== 0) { throw new Error('Lab roles already exist; refusing to reuse the cluster'); }
  await admin.query(`CREATE ROLE "fixlevelup_migrator" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD '${passwords.migrator}'`);
  await admin.query(`CREATE ROLE "fixlevelup_runtime" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD '${passwords.runtime}'`);
  await admin.query(`CREATE ROLE "fixlevelup_lab_orchestrator" LOGIN NOSUPERUSER CREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD '${passwords.orchestrator}'`);
  // The orchestrator owns nothing but may assume the owner role for the
  // GRANT/REVOKE/DROP block the fixtures perform (`SET ROLE fixlevelup_migrator`).
  await admin.query('GRANT "fixlevelup_migrator" TO "fixlevelup_lab_orchestrator"');
}

async function createApplicationDatabase(admin, database) {
  const existing = await admin.query('SELECT 1 FROM pg_database WHERE datname=$1', [database]);
  if (existing.rowCount !== 0) { throw new Error('Lab application database already exists; refusing to reuse it'); }
  await admin.query(`CREATE DATABASE "${database}" OWNER "fixlevelup_migrator" TEMPLATE template0`);
  await admin.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`);
  await admin.query(`GRANT CONNECT ON DATABASE "${database}" TO "fixlevelup_migrator", "fixlevelup_runtime"`);
}

/**
 * Applies exactly `limit` reviewed migrations (the frozen chain prefix) and
 * installs the pinned history. `limit` is an explicit count so the same script
 * can provision a separate 024 test database later without ever re-applying
 * anything to an existing one.
 */
async function applyMigrations(database, passwords, limit) {
  const chain = readdirSync(MIGRATION_ROOT, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && /^\d{14}_/.test(entry.name))
    .map((entry) => entry.name)
    .sort();
  if (!Number.isInteger(limit) || limit < 1 || limit > chain.length) {
    throw new Error(`Invalid migration limit ${String(limit)} (chain has ${String(chain.length)})`);
  }
  const applied = chain.slice(0, limit);
  const client = new Client({ host: '127.0.0.1', port: 55432, database, user: 'fixlevelup_migrator',
    password: passwords.migrator, connectionTimeoutMillis: 5000, statement_timeout: 120_000,
    application_name: 'p05lab-provision' });
  await client.connect();
  try {
    const identity = await scalar(client, `SELECT current_database() AS db, current_user AS role,
      pg_get_userbyid(datdba) AS owner FROM pg_database WHERE datname=current_database()`);
    if (identity?.db !== database || identity.role !== 'fixlevelup_migrator' || identity.owner !== 'fixlevelup_migrator') {
      throw new Error('Lab application database identity mismatch');
    }
    for (const name of applied) {
      await client.query(readFileSync(resolve(MIGRATION_ROOT, name, 'migration.sql'), 'utf8'));
    }
    // The REAL Prisma history shape, exactly as the fixture installs it.
    await client.query(`CREATE TABLE IF NOT EXISTS foundation._prisma_migrations (
      id text PRIMARY KEY,
      checksum varchar(64) NOT NULL,
      finished_at timestamptz,
      migration_name varchar(255) NOT NULL,
      logs text,
      rolled_back_at timestamptz,
      started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
      applied_steps_count integer NOT NULL DEFAULT 1
    )`);
    const entries = applied.map((name) => ({ name, checksum: migrationChecksum(name) }));
    await client.query('DELETE FROM foundation._prisma_migrations');
    for (const entry of entries) {
      await client.query(`INSERT INTO foundation._prisma_migrations
        (id, checksum, finished_at, migration_name, rolled_back_at, applied_steps_count)
        VALUES ($1, $2, clock_timestamp(), $3, NULL, 1)`, [randomBytes(16).toString('hex'), entry.checksum, entry.name]);
    }
    return { applied: applied.length, lastMigration: applied.at(-1), historyManifestDigest: manifestDigest(entries) };
  } finally { await client.end(); }
}

/**
 * Separate disposable control contour (§7): its own database, its own launcher
 * role, the reviewed registry from the frozen tree, and no CONNECT for the
 * application roles. The test contracts assert exactly these privileges.
 */
async function createControlContour(admin, controlDatabase, launcherRole, launcherPassword, passwords) {
  const existingDb = await admin.query('SELECT 1 FROM pg_database WHERE datname=$1', [controlDatabase]);
  const existingRole = await admin.query('SELECT 1 FROM pg_roles WHERE rolname=$1', [launcherRole]);
  if (existingDb.rowCount !== 0 || existingRole.rowCount !== 0) {
    throw new Error('Lab control contour already exists; refusing to reuse it');
  }
  await admin.query(`CREATE ROLE "${launcherRole}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD '${launcherPassword}'`);
  await admin.query(`CREATE DATABASE "${controlDatabase}" OWNER "postgres" TEMPLATE template0`);
  await admin.query(`REVOKE ALL ON DATABASE "${controlDatabase}" FROM PUBLIC`);
  await admin.query(`GRANT CONNECT ON DATABASE "${controlDatabase}" TO "${launcherRole}"`);

  const control = new Client({ host: '127.0.0.1', port: 55432, database: controlDatabase, user: 'postgres',
    password: passwords.admin, connectionTimeoutMillis: 5000, statement_timeout: 60_000,
    application_name: 'p05lab-provision' });
  await control.connect();
  try {
    // The exact reviewed registry DDL, not a copy of it.
    const { ensureLaunchRegistry } = await import(resolve(import.meta.dirname,
      '../../apps/api/src/infrastructure/admission/registry.ts'));
    await ensureLaunchRegistry(control);
    await control.query(`GRANT USAGE ON SCHEMA launch_control TO "${launcherRole}"`);
    await control.query(`GRANT SELECT, INSERT ON launch_control.launch_proofs TO "${launcherRole}"`);
    await control.query(`GRANT UPDATE (state, consumed_at) ON launch_control.launch_proofs TO "${launcherRole}"`);
    const shape = await scalar(control, `SELECT
      has_schema_privilege($1,'launch_control','CREATE') AS launcher_creates,
      has_table_privilege($1,'launch_control.launch_proofs','DELETE') AS launcher_deletes,
      has_database_privilege('fixlevelup_runtime',$2,'CONNECT') AS runtime_connects,
      has_database_privilege('fixlevelup_migrator',$2,'CONNECT') AS migrator_connects`,
    [launcherRole, controlDatabase]);
    if (shape?.launcher_creates !== false || shape.launcher_deletes !== false
      || shape.runtime_connects !== false || shape.migrator_connects !== false) {
      throw new Error('Lab control contour privileges are not narrow');
    }
    // The launcher identity must really work through its own credential.
    const probe = new Client({ host: '127.0.0.1', port: 55432, database: controlDatabase, user: launcherRole,
      password: launcherPassword, connectionTimeoutMillis: 5000, statement_timeout: 5000,
      application_name: 'p05lab-provision' });
    await probe.connect();
    try {
      const granted = await scalar(probe, `SELECT (current_user = $1
        AND current_database() = $2
        AND has_table_privilege(current_user,'launch_control.launch_proofs','SELECT')
        AND has_table_privilege(current_user,'launch_control.launch_proofs','INSERT')
        AND has_column_privilege(current_user,'launch_control.launch_proofs','state','UPDATE')
        AND has_column_privilege(current_user,'launch_control.launch_proofs','consumed_at','UPDATE')
        AND NOT has_schema_privilege(current_user,'launch_control','CREATE')) AS valid`,
      [launcherRole, controlDatabase]);
      if (granted?.valid !== true) { throw new Error('Lab launcher role cannot use the registry as reviewed'); }
    } finally { await probe.end(); }
  } finally { await control.end(); }
}

/**
 * Container-local synthetic `.env` files — see `containerenv.mjs` for the full
 * rationale and the explicit limitation of this lab-only workaround.
 */

async function main() {
  const passwords = {
    admin: secret('FIXLEVELUP_LAB_FIXTURE_ADMIN_PASSWORD'),
    orchestrator: secret('FIXLEVELUP_LAB_ORCHESTRATOR_PASSWORD'),
    migrator: secret('FIXLEVELUP_MIGRATOR_PASSWORD'),
    runtime: secret('FIXLEVELUP_RUNTIME_PASSWORD'),
  };
  const database = required('FIXLEVELUP_LAB_DATABASE', APP_DATABASE, 'application database');
  if (database === WORKING_DATABASE) { throw new Error('Refusing the working database'); }
  const controlDatabase = required('FIXLEVELUP_LAB_CONTROL_DATABASE', CONTROL_DATABASE, 'control database');
  const launcherRole = required('FIXLEVELUP_LAB_CONTROL_ROLE', LAUNCHER_ROLE, 'launcher role');
  const launcherPassword = secret('FIXLEVELUP_LAB_CONTROL_PASSWORD');
  const limit = Number(process.env['FIXLEVELUP_LAB_MIGRATION_LIMIT'] ?? '');
  if (!Number.isInteger(limit) || limit < 1) { throw new Error('Invalid FIXLEVELUP_LAB_MIGRATION_LIMIT'); }

  const admin = new Client({ host: '127.0.0.1', port: 55432, database: 'postgres', user: 'postgres',
    password: passwords.admin, connectionTimeoutMillis: 5000, statement_timeout: 120_000,
    application_name: 'p05lab-provision' });
  await admin.connect();
  let summary;
  try {
    const cluster = await attestCluster(admin);
    await createRoles(admin, passwords);
    await createApplicationDatabase(admin, database);
    const migrations = await applyMigrations(database, passwords, limit);
    await createControlContour(admin, controlDatabase, launcherRole, launcherPassword, passwords);
    // Explicit lab-only workaround for the one unguarded test-side `.env` reader.
    writeContainerEnv();
    const oid = (await scalar(admin, 'SELECT oid::text AS oid FROM pg_database WHERE datname=$1', [database]))?.oid;
    const databases = await admin.query(`SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY datname`);
    summary = {
      ok: true,
      cluster,
      database,
      databaseOid: oid,
      migrations: migrations.applied,
      lastMigration: migrations.lastMigration,
      historyManifestDigest: migrations.historyManifestDigest,
      controlDatabase,
      launcherRole,
      databases: databases.rows.map((row) => row.datname),
    };
  } finally { await admin.end(); }
  process.stdout.write(`${JSON.stringify(summary)}\n`);
}

await main();
