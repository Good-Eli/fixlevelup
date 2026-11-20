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

export function credentials(create = false) {
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
  if (database !== 'fixlevelup_dev' && !/^fixlevelup_p017a_(?:fresh|upgrade|shadow)_[a-f0-9]{12}$/.test(database)
    && !/^fixlevelup_p017b_proof_[a-f0-9]{12}$/.test(database)
    && !/^fixlevelup_p019a_worker_[a-f0-9]{12}$/.test(database)) {
    throw new Error('Database target outside P01-01.7A allowlist');
  }
}
export function connection(user, password, database) {
  validateDatabase(database);
  if (!['fixlevelup_dev', ...names].includes(user)) { throw new Error('Unknown technical role'); }
  if (!/^[a-f0-9]{64}$/.test(password)) { throw new Error('Invalid local credential'); }
  return new Client({ host: '127.0.0.1', port: 55432, user, password, database,
    connectionTimeoutMillis: 5000, statement_timeout: 10000, application_name: 'fixlevelup-p017a' });
}
export async function admin() {
  const source = readFileSync(new URL('../../../infra/dev-postgres/.env', import.meta.url), 'utf8');
  const password = /^POSTGRES_PASSWORD=([a-f0-9]{64})$/m.exec(source)?.[1];
  if (!password) { throw new Error('Local admin credential unavailable'); }
  const client = connection('fixlevelup_dev', password, 'fixlevelup_dev');
  await client.connect();
  const result = await client.query('SELECT current_database() AS db, current_user AS role, current_setting(\'server_version_num\')::int AS version');
  if (result.rows[0].db !== 'fixlevelup_dev' || result.rows[0].role !== 'fixlevelup_dev' || result.rows[0].version !== 180007) {
    await client.end(); throw new Error('Unexpected local PostgreSQL identity');
  }
  return client;
}
export async function prepareDatabase(client, database, create) {
  validateDatabase(database);
  if (create) {
    const exists = await client.query('SELECT 1 FROM pg_database WHERE datname=$1', [database]);
    if (exists.rowCount) { throw new Error('Refusing existing test database'); }
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
  // Bootstrap admin grants the two explicit roles; no inherited privileges.
  await client.query(`GRANT CONNECT ON DATABASE "${database}" TO fixlevelup_migrator, fixlevelup_runtime`);
  // Migration DDL may create its schema; runtime must never get DB CREATE.
  await client.query(`GRANT CREATE ON DATABASE "${database}" TO fixlevelup_migrator`);
  if (!create) { await client.query(`REVOKE CREATE, TEMPORARY ON DATABASE "${database}" FROM PUBLIC`); }
}

export function runPrisma(args, database, shadow, history) {
  validateDatabase(database);
  if (shadow) {
    validateDatabase(shadow);
    if (shadow === database || !shadow.startsWith('fixlevelup_p017a_shadow_')) { throw new Error('Unsafe shadow target'); }
  }
  const password = credentials().fixlevelup_migrator;
  const url = (db) => `postgresql://fixlevelup_migrator:${password}@127.0.0.1:55432/${db}?schema=foundation`;
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
  const output = (result.stdout + result.stderr).replaceAll(password, '[REDACTED]');
  return { status: result.status, output };
}
