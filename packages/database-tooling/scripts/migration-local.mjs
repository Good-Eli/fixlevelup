import { createRequire } from 'node:module';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

export const root = fileURLToPath(new URL('../../../', import.meta.url));
const apiRequire = createRequire(new URL('../../../apps/api/package.json', import.meta.url));
const cliRequire = createRequire(new URL('../package.json', import.meta.url));
const { Client } = apiRequire('pg');
const rolesPath = new URL('../.env', import.meta.url);
const names = ['fixlevelup_migrator', 'fixlevelup_runtime'];

/* ---------------------------------------------------------------------------
 * P05-02 S4 opt-in lab orchestrator.
 *
 * Default (dev) behaviour is unchanged: this module is the only path that may
 * touch `fixlevelup_dev`, and every guard below is inert unless the single
 * opt-in flag is set. Under the flag the orchestrator becomes a SEPARATE scoped
 * identity: role `fixlevelup_lab_orchestrator` on control DB `postgres`, only
 * historical disposable `fixlevelup_p017a_{fresh,upgrade,shadow}_*` targets
 * (never `fixlevelup_dev`), dedicated credentials from `../.env.synthetic`, and
 * a server-side cluster binding (loopback, exact PostgreSQL 18.7, cluster_name
 * + session-run application_name markers, safe non-superuser role flags). Role
 * names `fixlevelup_migrator` / `fixlevelup_runtime` stay verbatim: 022/023 DDL
 * hard-requires them.
 * ------------------------------------------------------------------------- */

/** Fixed loopback endpoint; never configurable, never another host. */
export const HOST = '127.0.0.1';
export const PORT = 55432;
/** Exact PostgreSQL 18.7 `server_version_num`: equality, not a lower bound. */
export const PG_SERVER_VERSION_NUM = 180007;
/** The single shared physical-profile module (Node 24 runs its erasable TS). */
const PROFILE_MODULE = '../../../apps/api/src/infrastructure/database/p05-profile-catalog.ts';

const DEV_DATABASE = 'fixlevelup_dev';
const DEV_ADMIN_ROLE = 'fixlevelup_dev';
const DEV_DATABASE_ALLOWLIST = /^(?:fixlevelup_p017a_(?:fresh|upgrade|shadow)_[a-f0-9]{12}|fixlevelup_p017b_proof_[a-f0-9]{12}|fixlevelup_p019a_worker_[a-f0-9]{12})$/;

const SYNTHETIC_FLAG = 'FIXLEVELUP_SYNTHETIC_ORCHESTRATOR';
const SYNTHETIC_ENV_PATH = new URL('../.env.synthetic', import.meta.url);
const LAB_ROLE = 'fixlevelup_lab_orchestrator';
const LAB_CONTROL_DATABASE = 'postgres';
const LAB_MARKER_PREFIX = 'fixlevelup-p05s4-';
/**
 * Historical DISPOSABLE database names. The ten sibling migration proofs hard-
 * code exactly this shape for their identity guards, so the lab orchestrator
 * must keep it too: the names are a disposable-test convention, not the working
 * database. `fixlevelup_dev` itself is still refused outright (see below).
 */
const DISPOSABLE_DATABASE = /^fixlevelup_p017a_(?:fresh|upgrade|shadow)_[a-f0-9]{12}$/;
const DISPOSABLE_SHADOW = /^fixlevelup_p017a_shadow_[a-f0-9]{12}$/;
const LAB_PASSWORDS = {
  [LAB_ROLE]: 'FIXLEVELUP_LAB_ORCHESTRATOR_PASSWORD',
  fixlevelup_migrator: 'FIXLEVELUP_MIGRATOR_PASSWORD',
  fixlevelup_runtime: 'FIXLEVELUP_RUNTIME_PASSWORD',
};
let labFile;

/** Process env wins over the dedicated lab env file; the file is read once. */
function labEnv() {
  labFile ??= existsSync(SYNTHETIC_ENV_PATH) ? readFileSync(SYNTHETIC_ENV_PATH, 'utf8') : '';
  const fromFile = Object.fromEntries(labFile.split(/\r?\n/)
    .map((line) => /^([A-Z0-9_]+)=(.*)$/.exec(line.trim()))
    .filter((match) => match !== null)
    .map((match) => [match[1], match[2]]));
  return { ...fromFile, ...process.env };
}

/** True only under the explicit opt-in flag; every other value keeps dev mode. */
export function syntheticMode() {
  return labEnv()[SYNTHETIC_FLAG] === '1';
}

/** Exact cluster name; a marker, never a name-based allowlist. */
function clusterName() {
  const name = labEnv()['FIXLEVELUP_CLUSTER_NAME'] ?? '';
  if (!/^[a-z0-9][a-z0-9_-]{2,47}$/.test(name)) {
    throw new Error('FIXLEVELUP_CLUSTER_NAME must be 3-48 chars of [a-z0-9_-]');
  }
  return name;
}

/** Exact session-run marker. A missing or imprecise run id fails the run. */
function sessionRunMarker() {
  const runId = labEnv()['FIXLEVELUP_SESSION_RUN_ID'] ?? '';
  if (!/^[a-f0-9]{12}$/.test(runId)) {
    throw new Error('FIXLEVELUP_SESSION_RUN_ID must be exactly 12 lowercase hex characters');
  }
  return `${LAB_MARKER_PREFIX}${runId}`;
}

function labPassword(role) {
  const value = labEnv()[LAB_PASSWORDS[role]] ?? '';
  if (!/^[a-f0-9]{64}$/.test(value)) { throw new Error(`Lab credential unavailable for ${role}`); }
  return value;
}

export function credentials(create = false) {
  if (syntheticMode()) {
    // Lab runs never create or rotate credentials and never read the dev `.env`.
    if (create) { throw new Error('Lab orchestrator never creates credentials'); }
    return Object.fromEntries(names.map((name) => [name, labPassword(name)]));
  }
  if (!existsSync(rolesPath)) {
    if (!create) { throw new Error('Local role credentials unavailable; run db:roles first'); }
    writeFileSync(rolesPath, names.map((name) => `${name.toUpperCase()}_PASSWORD=${randomBytes(32).toString('hex')}`).join('\n') + '\n', { flag: 'wx' });
  }
  const source = readFileSync(rolesPath, 'utf8');
  return Object.fromEntries(names.map((name) => {
    const value = new RegExp(`^${name.toUpperCase()}_PASSWORD=([a-f0-9]{64})$`, 'm').exec(source)?.[1];
    if (!value) { throw new Error('Invalid local role credentials'); }
    return [name, value];
  }));
}

export function validateDatabase(database) {
  if (syntheticMode()) {
    // The working database is refused outright, in both directions: the lab
    // orchestrator may only touch generated disposable test names.
    if (database === DEV_DATABASE) { throw new Error('Lab orchestrator refused the working database'); }
    if (!DISPOSABLE_DATABASE.test(database)) {
      throw new Error('Lab orchestrator target outside the disposable allowlist');
    }
    return;
  }
  if (database !== DEV_DATABASE && !DEV_DATABASE_ALLOWLIST.test(database)) {
    throw new Error('Database target outside P01-01.7A allowlist');
  }
}

export function connection(user, password, database) {
  validateDatabase(database);
  const allowedUsers = syntheticMode() ? [LAB_ROLE, ...names] : [DEV_ADMIN_ROLE, ...names];
  if (!allowedUsers.includes(user)) { throw new Error('Unknown technical role'); }
  if (!/^[a-f0-9]{64}$/.test(password)) { throw new Error('Invalid local credential'); }
  return new Client({ host: HOST, port: PORT, user, password, database,
    connectionTimeoutMillis: 5000, statement_timeout: 10000,
    application_name: syntheticMode() ? sessionRunMarker() : 'fixlevelup-p017a' });
}

/**
 * Test database names. Both modes emit the historical disposable shape
 * `fixlevelup_p017a_<purpose>_<12hex>`: the ten sibling migration proofs hard-
 * code that exact pattern in their identity guards, so it must not change. The
 * working database `fixlevelup_dev` is never produced here and is refused by
 * `validateDatabase` in lab mode.
 */
export function testDatabaseName(purpose, suffix) {
  if (!/^[a-f0-9]{12}$/.test(suffix)) { throw new Error('Invalid test database suffix'); }
  if (!['fresh', 'upgrade', 'shadow'].includes(purpose)) { throw new Error('Invalid test database purpose'); }
  return `fixlevelup_p017a_${purpose}_${suffix}`;
}

/**
 * Expected identity of the admin/maintenance connection for the current mode.
 * Dev: the local `fixlevelup_dev` superuser on its own database. Lab: the scoped
 * `fixlevelup_lab_orchestrator` on the `postgres` control database. Callers that
 * assert the admin identity (the 021 issuer proof) parametrize with this instead
 * of hardcoding the dev pair, so the same assertion stays exact in both modes.
 */
export function adminIdentity() {
  return syntheticMode()
    ? Object.freeze({ db: LAB_CONTROL_DATABASE, role: LAB_ROLE, pg: String(PG_SERVER_VERSION_NUM) })
    : Object.freeze({ db: DEV_DATABASE, role: DEV_ADMIN_ROLE, pg: String(PG_SERVER_VERSION_NUM) });
}

/**
 * Server-side proof that this connection is the scoped lab orchestrator on the
 * exact reviewed cluster. Every condition is an exact equality: identity, PG
 * 18.7, loopback endpoint (host part of `inet_server_addr()`, PG18 renders the
 * mask otherwise), cluster marker, session-run marker, no foreign sessions,
 * and safe non-superuser role flags plus the migrator membership that
 * `CREATE DATABASE ... OWNER fixlevelup_migrator` requires.
 */
async function assertLabCluster(client) {
  const marker = sessionRunMarker();
  const expectedCluster = clusterName();
  const { rows } = await client.query(`SELECT current_database() AS db, current_user AS role,
    current_setting('server_version_num')::int AS version,
    current_setting('cluster_name') AS cluster,
    current_setting('application_name') AS marker,
    coalesce(host(inet_server_addr()),'') AS address,
    coalesce(inet_server_port(),0) AS port,
    (SELECT rolsuper OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit
       FROM pg_roles WHERE rolname=current_user) AS unsafe_role,
    (SELECT rolcreatedb FROM pg_roles WHERE rolname=current_user) AS can_create_db,
    pg_has_role(current_user,'fixlevelup_migrator','MEMBER') AS migrator_member`);
  const row = rows[0];
  if (row?.db !== LAB_CONTROL_DATABASE || row.role !== LAB_ROLE) {
    throw new Error('Unexpected lab PostgreSQL identity');
  }
  if (row.version !== PG_SERVER_VERSION_NUM) {
    throw new Error('Lab cluster must be PostgreSQL 18.7 (server_version_num 180007)');
  }
  if (row.cluster !== expectedCluster) { throw new Error(`Cluster marker mismatch: expected ${expectedCluster}`); }
  if (row.marker !== marker) { throw new Error('Session-run cluster marker mismatch'); }
  // Exact equality on the host part, never a suffix/prefix match.
  if (row.address !== HOST) { throw new Error(`Lab cluster must be loopback ${HOST}:${PORT}`); }
  if (row.port !== PORT) { throw new Error(`Lab cluster must be loopback ${HOST}:${PORT}`); }
  if (row.unsafe_role !== false) { throw new Error('Lab orchestrator must not be a privileged role'); }
  if (row.can_create_db !== true) { throw new Error('Lab orchestrator must have CREATEDB'); }
  if (row.migrator_member !== true) { throw new Error('Lab orchestrator must be a MEMBER of fixlevelup_migrator'); }
  // The disposable cluster lives in a private netns, so only this run's marker
  // family may be present; any foreign session means a shared/reused cluster.
  const foreign = await client.query(`SELECT count(*)::int AS n FROM pg_stat_activity
    WHERE datname IS NOT NULL AND pid <> pg_backend_pid() AND application_name NOT LIKE $1`,
  [`${LAB_MARKER_PREFIX}%`]);
  if ((foreign.rows[0]?.n ?? -1) !== 0) {
    throw new Error('Cluster carries foreign sessions; refusing the lab run');
  }
}

async function labAdmin() {
  const client = new Client({ host: HOST, port: PORT, user: LAB_ROLE, password: labPassword(LAB_ROLE),
    database: LAB_CONTROL_DATABASE, connectionTimeoutMillis: 5000, statement_timeout: 10000,
    application_name: sessionRunMarker() });
  await client.connect();
  try { await assertLabCluster(client); } catch (error) { await client.end(); throw error; }
  return client;
}

async function devAdmin() {
  const source = readFileSync(new URL('../../../infra/dev-postgres/.env', import.meta.url), 'utf8');
  const password = /^POSTGRES_PASSWORD=([a-f0-9]{64})$/m.exec(source)?.[1];
  if (!password) { throw new Error('Local admin credential unavailable'); }
  const client = connection(DEV_ADMIN_ROLE, password, DEV_DATABASE);
  await client.connect();
  const result = await client.query('SELECT current_database() AS db, current_user AS role, current_setting(\'server_version_num\')::int AS version');
  if (result.rows[0].db !== DEV_DATABASE || result.rows[0].role !== DEV_ADMIN_ROLE
    || result.rows[0].version !== PG_SERVER_VERSION_NUM) {
    await client.end(); throw new Error('Unexpected local PostgreSQL identity');
  }
  return client;
}

export async function admin() {
  return syntheticMode() ? labAdmin() : devAdmin();
}

export async function prepareDatabase(client, database, create) {
  validateDatabase(database);
  if (syntheticMode()) {
    // The orchestrator creates the database, but every privilege statement on it
    // runs as the owning migrator: the orchestrator is a NOINHERIT member of the
    // owner role, so it must not be assumed to hold owner rights itself.
    if (!create) {
      const owner = connection('fixlevelup_migrator', credentials().fixlevelup_migrator, database);
      await owner.connect();
      try { await owner.query(`REVOKE CREATE, TEMPORARY ON DATABASE "${database}" FROM PUBLIC`); }
      finally { await owner.end(); }
      return;
    }
    if ((await client.query('SELECT 1 FROM pg_database WHERE datname=$1', [database])).rowCount) {
      throw new Error('Refusing existing test database');
    }
    await client.query(`CREATE DATABASE "${database}" OWNER fixlevelup_migrator`);
    // The database must really be owned by the migrator: a mis-created target
    // would silently invalidate every later ownership/ACL proof.
    const created = await client.query('SELECT pg_get_userbyid(datdba) AS owner FROM pg_database WHERE datname=$1', [database]);
    if (created.rows[0]?.owner !== 'fixlevelup_migrator') {
      throw new Error('Unexpected database owner after CREATE');
    }
    const bootstrap = connection('fixlevelup_migrator', credentials().fixlevelup_migrator, database);
    await bootstrap.connect();
    try {
      await bootstrap.query('CREATE SCHEMA IF NOT EXISTS foundation AUTHORIZATION fixlevelup_migrator');
      const owner = await bootstrap.query("SELECT pg_get_userbyid(nspowner) AS owner FROM pg_namespace WHERE nspname='foundation'");
      if (owner.rows[0]?.owner !== 'fixlevelup_migrator') { throw new Error('Unexpected foundation schema owner'); }
      await bootstrap.query('REVOKE ALL ON SCHEMA foundation FROM PUBLIC');
      await bootstrap.query('REVOKE CREATE ON SCHEMA public FROM PUBLIC');
      await bootstrap.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`);
      await bootstrap.query(`GRANT CONNECT ON DATABASE "${database}" TO fixlevelup_runtime`);
      await bootstrap.query(`GRANT CREATE ON DATABASE "${database}" TO fixlevelup_migrator`);
    } finally { await bootstrap.end(); }
    return;
  }
  if (create) {
    if ((await client.query('SELECT 1 FROM pg_database WHERE datname=$1', [database])).rowCount) {
      throw new Error('Refusing existing test database');
    }
    await client.query(`CREATE DATABASE "${database}" OWNER fixlevelup_migrator`);
  }
  const bootstrap = create ? connection('fixlevelup_migrator', credentials().fixlevelup_migrator, database) : client;
  if (create) { await bootstrap.connect(); }
  try {
    await bootstrap.query('CREATE SCHEMA IF NOT EXISTS foundation AUTHORIZATION fixlevelup_migrator');
    const owner = await bootstrap.query("SELECT pg_get_userbyid(nspowner) AS owner FROM pg_namespace WHERE nspname='foundation'");
    if (owner.rows[0]?.owner !== 'fixlevelup_migrator') { throw new Error('Unexpected foundation schema owner'); }
    await bootstrap.query('REVOKE ALL ON SCHEMA foundation FROM PUBLIC');
    await bootstrap.query('REVOKE CREATE ON SCHEMA public FROM PUBLIC');
    if (create) { await bootstrap.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`); }
  } finally { if (create) { await bootstrap.end(); } }
  await client.query(`GRANT CONNECT ON DATABASE "${database}" TO fixlevelup_migrator, fixlevelup_runtime`);
  await client.query(`GRANT CREATE ON DATABASE "${database}" TO fixlevelup_migrator`);
  if (!create) { await client.query(`REVOKE CREATE, TEMPORARY ON DATABASE "${database}" FROM PUBLIC`); }
}

export function runPrisma(args, database, shadow, history) {
  validateDatabase(database);
  if (shadow) {
    validateDatabase(shadow);
    // Both modes require an exact disposable shadow name; only the shape differs
    // in nothing — the historical pattern is the single accepted one.
    const safeShadow = syntheticMode() ? DISPOSABLE_SHADOW.test(shadow) : shadow.startsWith('fixlevelup_p017a_shadow_');
    if (shadow === database || !safeShadow) { throw new Error('Unsafe shadow target'); }
  }
  const password = credentials().fixlevelup_migrator;
  const appName = syntheticMode() ? `&application_name=${encodeURIComponent(sessionRunMarker())}` : '';
  const url = (db) => `postgresql://fixlevelup_migrator:${password}@${HOST}:${PORT}/${db}?schema=foundation${appName}`;
  const env = { ...process.env, CHECKPOINT_DISABLE: '1', PRISMA_HIDE_UPDATE_MESSAGE: '1',
    FIXLEVELUP_MIGRATION_URL: url(database) };
  for (const key of ['DEBUG', 'RUST_LOG', 'PRISMA_SCHEMA_ENGINE_BINARY', 'PRISMA_ENGINES_MIRROR']) { delete env[key]; }
  delete env['FIXLEVELUP_MIGRATIONS_DIR'];
  if (history) {
    const allowed = fileURLToPath(new URL('../../../node_modules/.cache/p017a-', import.meta.url));
    if (!history.startsWith(allowed)) { throw new Error('Unsafe test migration directory'); }
    env['FIXLEVELUP_MIGRATIONS_DIR'] = history;
  }
  delete env['FIXLEVELUP_SHADOW_URL'];
  if (shadow) { env['FIXLEVELUP_SHADOW_URL'] = url(shadow); }
  const result = spawnSync(process.execPath, [cliRequire.resolve('prisma/build/index.js'), ...args, '--config', 'prisma.config.ts'], {
    cwd: fileURLToPath(new URL('../', import.meta.url)), env, encoding: 'utf8', timeout: 90000,
  });
  if (result.error) { throw new Error('Prisma migration command failed to execute'); }
  return { status: result.status, output: (result.stdout + result.stderr).replaceAll(password, '[REDACTED]') };
}

/**
 * Physical-profile regression, lab mode only.
 *
 * Runs the SINGLE shared module that runtime readiness and the §5.3 restore gate
 * use — `probeP05Catalog` from
 * `apps/api/src/infrastructure/database/p05-profile-catalog.ts`, executed by
 * Node 24's type stripping — through a REAL runtime-role client against the
 * migrated database. There is no hash parsing, no spawned verifier and no
 * override: the boolean the runtime would compute is the boolean asserted here.
 * Outside the lab opt-in this function is never called, so dev behaviour and its
 * dependencies are unchanged.
 *
 * `S3` is accepted because the reviewed 024 SQL is in the tree: a fresh 001…024
 * database is an S3 database, while the historical S1/S2 pins stay untouched and
 * are still asserted at their exact earlier caps.
 */
export async function assertReviewedProfile(database, profile) {
  if (!syntheticMode() || !['S1','S2','S3'].includes(profile)) { throw new Error('Invalid lab profile assertion'); }
  validateDatabase(database);
  const client = connection('fixlevelup_runtime', credentials().fixlevelup_runtime, database);
  await client.connect();
  try {
    let probeP05Catalog;
    try {
      ({ probeP05Catalog } = await import(new URL(PROFILE_MODULE, import.meta.url).href));
    } catch (error) {
      throw new Error(`Shared physical-profile module unavailable (${PROFILE_MODULE})`, { cause: error });
    }
    if (typeof probeP05Catalog !== 'function') {
      throw new Error(`Shared physical-profile module does not export probeP05Catalog (${PROFILE_MODULE})`);
    }
    if (await probeP05Catalog(client, profile) !== true) {
      throw new Error(`${profile} does not match the reviewed runtime/restore profile`);
    }
    return { checked: true, profile };
  } finally { await client.end(); }
}
