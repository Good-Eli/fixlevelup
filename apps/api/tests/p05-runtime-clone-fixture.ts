import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Client } from 'pg';
import { authFixtureMigrations, installPinnedMigrationHistory } from './auth-db-fixture.js';
import { loadP05LabTarget } from './p05-lab-target.js';

const s3Database = /^fixlevelup_p05_s3tlab_[a-f0-9]{12}$/;
const clonePort = 55435;
const migratorRole = 'fixlevelup_migrator';
const runtimeRole = 'fixlevelup_runtime';
const migrationRoot = resolve(import.meta.dirname, '../../../prisma/migrations');

export const p05CloneTests = process.env['FIXLEVELUP_P05_CLONE_TESTS'] === '1'
  && process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1'
  && process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1';

async function open(options: { host: string; port: number; database: string; user: string; password: string }) {
  const client = new Client({ ...options, application_name: 'fixlevelup-p05-clone-fixture',
    connectionTimeoutMillis: 3000, statement_timeout: 20_000 });
  try { await client.connect(); return client; }
  catch { await client.end(); throw new Error('Unable to connect isolated P05 clone fixture'); }
}

interface ServerIdentity {
  readonly database: string;
  readonly user: string;
  readonly sessionUser: string;
  readonly schema: string;
  readonly oid: number;
  readonly cluster: string;
  readonly port: number;
  readonly host: string;
  readonly version: string;
  readonly primary: boolean;
  readonly owner: string;
}

export async function readP05CloneIdentity(client: Client) {
  return (await client.query<ServerIdentity>(`SELECT current_database() AS database, current_user AS user,
    session_user AS "sessionUser", current_schema() AS schema, d.oid AS oid, pg_get_userbyid(d.datdba) AS owner,
    current_setting('cluster_name') AS cluster, inet_server_port() AS port, host(inet_server_addr()) AS host,
    current_setting('server_version_num') AS version, NOT pg_is_in_recovery() AS primary
    FROM pg_catalog.pg_database d WHERE d.datname=current_database()`)).rows[0];
}

function verifyIdentity(row: ServerIdentity | undefined, config: { database: string; user: string; port: number }, cluster: string) {
  if (!row || row.host !== '127.0.0.1' || row.port !== config.port || row.cluster !== cluster
    || row.version !== '180007' || !row.primary || row.database !== config.database
    || row.user !== config.user || row.sessionUser !== config.user || row.schema !== 'public') {
    throw new Error('Isolated P05 clone fixture identity mismatch');
  }
  return row;
}

/** Only the separately provisioned virgin clone primary receives fixture writes. */
export async function createP05RuntimeClone() {
  if (!p05CloneTests) { throw new Error('P05 clone fixture requires explicit synthetic opt-in'); }
  const lab = loadP05LabTarget();
  const { runtime, migrator, oid } = lab;
  const { database } = runtime;
  const runId = process.env['FIXLEVELUP_SESSION_RUN_ID'] ?? '';
  const sourceCluster = `fixlevelup_p05s4_lab_${runId}`;
  const cloneCluster = `fixlevelup_p05clone_${runId}`;
  const password = process.env['FIXLEVELUP_LAB_FIXTURE_ADMIN_PASSWORD'] ?? '';
  if (!s3Database.test(database) || process.env['FIXLEVELUP_CLUSTER_NAME'] !== sourceCluster
    || !/^[a-f0-9]{64}$/.test(password) || authFixtureMigrations.length !== 24 || oid < 16384) {
    throw new Error('Invalid source/clone fixture binding');
  }

  const labMaintenance = await lab.openMaintenance();
  await labMaintenance.end();
  const source = await open(runtime);
  try {
    if (verifyIdentity(await readP05CloneIdentity(source), runtime, sourceCluster).oid !== oid) {
      throw new Error('Isolated P05 clone source OID mismatch');
    }
  } finally { await source.end(); }

  const maintenance = { host: '127.0.0.1', port: clonePort, database: 'postgres', user: 'postgres', password };
  const admin = await open(maintenance);
  try {
    verifyIdentity(await readP05CloneIdentity(admin), maintenance, cloneCluster);
    const { rows } = await admin.query<{ fresh: boolean }>(`SELECT
      NOT EXISTS (SELECT FROM pg_catalog.pg_database WHERE datname NOT IN ('postgres','template0','template1') OR oid=$1::oid)
      AND NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE NOT starts_with(rolname, 'pg_') AND rolname<>'postgres')
      AS fresh`, [oid]);
    if (rows[0]?.fresh !== true) { throw new Error('Clone primary is not pristine; refusing reuse'); }
    // loadP05LabTarget validates both passwords as 64 hex characters; never log them.
    for (const [role, secret] of [[migratorRole, migrator.password], [runtimeRole, runtime.password]] as const) {
      await admin.query(`CREATE ROLE "${role}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
        NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD '${secret}'`);
    }
    await admin.query(`CREATE DATABASE "${database}" OWNER "${migratorRole}" TEMPLATE template0 OID ${String(oid)}`);
    await admin.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`);
    await admin.query(`GRANT CONNECT ON DATABASE "${database}" TO "${migratorRole}", "${runtimeRole}"`);
  } finally { await admin.end(); }

  const cloneRuntime = Object.freeze({ ...runtime, port: clonePort });
  const cloneMigrator = Object.freeze({ ...migrator, port: clonePort });
  const operator = await open(cloneMigrator);
  try {
    const identity = verifyIdentity(await readP05CloneIdentity(operator), cloneMigrator, cloneCluster);
    if (identity.oid !== oid || identity.owner !== migratorRole) { throw new Error('Clone database owner/OID mismatch'); }
    for (const migration of authFixtureMigrations) {
      await operator.query(readFileSync(resolve(migrationRoot, migration, 'migration.sql'), 'utf8'));
    }
    await installPinnedMigrationHistory(operator);
  } finally { await operator.end(); }

  // No SQL teardown: the parent test runner owns the disposable clone container.
  return { runtime, cloneRuntime, sourceCluster, cloneCluster, oid,
    openSourceRuntime: () => open(runtime), openSourceMigrator: () => open(migrator),
    openCloneRuntime: () => open(cloneRuntime), openCloneMigrator: () => open(cloneMigrator) };
}
