import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

// This entry point belongs exclusively to the fresh, isolated /workspace image.
// The parent provisions Garage grants and shares the isolated service namespace;
// no host connection, Docker command, RPC credential or service teardown is used.
const root = fileURLToPath(new URL('../../', import.meta.url));
const postgresEnv = new URL('../dev-postgres/.env', import.meta.url);
const storageEnv = new URL('../dev-s3/.env', import.meta.url);
const rolesEnv = new URL('../../packages/database-tooling/.env', import.meta.url);
const evidence = new URL('../../node_modules/.cache/linux-integration/', import.meta.url);
const marker = 'fixlevelup-p01-01-5-persistence';
const steps = [];
let stage = 'runtime preflight';
let lockSha256;
let canWriteEvidence = false;
let admin;

function assert(condition) {
  if (!condition) { throw new Error('Isolated Linux integration condition failed'); }
}
function hashLock() {
  return createHash('sha256').update(readFileSync(new URL('../../pnpm-lock.yaml', import.meta.url))).digest('hex');
}
function absent(path) {
  try { lstatSync(path); }
  catch (error) {
    if (error.code === 'ENOENT') { return; }
    // Filesystem errors may include local paths; keep only the safe stage label.
    // eslint-disable-next-line preserve-caught-error
    throw new Error('Unable to check bootstrap path');
  }
  throw new Error('Refusing existing bootstrap path');
}
function secret(name, pattern) {
  const value = process.env[name];
  assert(typeof value === 'string' && pattern.test(value));
  return value;
}
async function step(name, action) {
  stage = name;
  console.log(`Linux integration: ${name}`);
  try {
    await action();
    steps.push({ name, status: 0, signal: null });
  } catch {
    steps.push({ name, status: 1, signal: null });
    throw new Error('Integration step failed');
  }
}
function run(name, args) {
  stage = name;
  console.log(`Linux integration: ${name}`);
  let result;
  try {
    // Nine serial CITY slices may consume 135 minutes in the full proof.
    result = spawnSync('corepack', ['pnpm', ...args], {
      cwd: root, stdio: 'inherit', timeout: 9_600_000,
      // Do not detach children: the enclosing Docker lifecycle owns the process tree.
      killSignal: 'SIGKILL',
    });
  } catch {
    steps.push({ name, status: null, signal: null, error: 'spawn failed' });
    throw new Error('Integration command failed to start');
  }
  const commandStep = { name, status: result.status, signal: result.signal,
    ...(result.error ? { error: result.error.code === 'ETIMEDOUT' ? 'timeout' : 'spawn failed' } : {}) };
  steps.push(commandStep);
  if (result.error || result.status !== 0 || result.signal) {
    steps.push({ name: `${name}: command outcome`, status: 1, signal: result.signal, error: 'command did not complete successfully' });
    throw new Error('Integration command failed');
  }
  try { assert(hashLock() === lockSha256); }
  catch {
    steps.push({ name: `${name}: lockfile invariant`, status: 1, signal: null, error: 'lockfile hash verification failed' });
    throw new Error('Integration lockfile invariant failed');
  }
}
async function identity(client, timeout = 3000) {
  const result = await client.query({
    text: "SELECT current_database() AS db, current_user AS role, current_setting('server_version_num')::int AS version",
    query_timeout: timeout,
  });
  assert(result.rows[0]?.db === 'fixlevelup_dev'
    && result.rows[0].role === 'fixlevelup_dev' && result.rows[0].version === 180007);
}
async function waitPostgres(Client, password) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const client = new Client({
      host: '127.0.0.1', port: 55432, database: 'fixlevelup_dev', user: 'fixlevelup_dev', password,
      connectionTimeoutMillis: Math.max(1, Math.min(1000, deadline - Date.now())),
      statement_timeout: 1000, query_timeout: 1000, application_name: 'fixlevelup-linux-integration',
    });
    // Suppress asynchronous socket/driver errors as well as rejected API calls.
    client.on('error', () => {});
    try {
      await client.connect();
      assert(Date.now() < deadline);
      await identity(client, Math.max(1, Math.min(1000, deadline - Date.now())));
      assert(Date.now() <= deadline);
      return client;
    } catch {
      try { await client.end(); } catch { /* Never print raw driver errors. */ }
    }
    if (Date.now() < deadline) { await delay(Math.min(250, deadline - Date.now())); }
  }
  throw new Error('Isolated PostgreSQL readiness deadline exceeded');
}
function writeEvidence(overallStatus, failedStage) {
  mkdirSync(evidence, { recursive: true });
  writeFileSync(new URL('result.json', evidence), JSON.stringify({
    node: process.version, platform: process.platform, lockSha256, steps, overallStatus, failedStage,
    fullVitestClaim: 'see actual logs',
    limitations: ['not remote CI', 'no Linux backup/restore', 'no actual services OS signal proof'],
  }, null, 2) + '\n', { mode: 0o600 });
}

try {
  await step('runtime preflight', async () => {
    assert(process.platform === 'linux' && process.arch === 'x64' && process.version === 'v24.22.3');
    assert(realpathSync(root) === '/workspace' && realpathSync(process.cwd()) === '/workspace');
    // lstat also rejects dangling symlinks. Source directories come from the fresh image.
    for (const path of [postgresEnv, storageEnv, rolesEnv]) { absent(path); }
    lockSha256 = hashLock();
    canWriteEvidence = true;
  });

  // Deps and generated Prisma output are prepared by the image build. Validate
  // the frozen offline install without --force or any lifecycle scripts.
  run('offline frozen install', ['install', '--frozen-lockfile', '--offline', '--ignore-scripts', '--strict-peer-dependencies']);

  let password;
  await step('isolated credential bootstrap', async () => {
    password = secret('POSTGRES_PASSWORD', /^[a-f0-9]{64}$/);
    const values = [
      ['S3_ACCESS_KEY_ID', /^GK[a-f0-9]{24}$/],
      ['S3_SECRET_ACCESS_KEY', /^[a-f0-9]{64}$/],
      ['S3_READONLY_ACCESS_KEY_ID', /^GK[a-f0-9]{24}$/],
      ['S3_READONLY_SECRET_ACCESS_KEY', /^[a-f0-9]{64}$/],
    ].map(([name, pattern]) => [name, secret(name, pattern)]);
    assert(values[0][1] !== values[2][1] && values[1][1] !== values[3][1]);
    for (const path of [postgresEnv, storageEnv, rolesEnv]) { absent(path); }
    writeFileSync(postgresEnv, `POSTGRES_PASSWORD=${password}\n`, { flag: 'wx', mode: 0o600 });
    writeFileSync(storageEnv, values.map(([name, value]) => `${name}=${value}`).join('\n') + '\n', { flag: 'wx', mode: 0o600 });
    // db:roles alone generates packages/database-tooling/.env in this image.
  });

  await step('PostgreSQL 18.7 identity and fresh database', async () => {
    const apiRequire = createRequire(new URL('../../apps/api/package.json', import.meta.url));
    const { Client } = apiRequire('pg');
    admin = await waitPostgres(Client, password);
    const schemas = await admin.query("SELECT 1 FROM pg_namespace WHERE nspname IN ('foundation','p01_technical')");
    const roles = await admin.query("SELECT 1 FROM pg_roles WHERE rolname IN ('fixlevelup_migrator','fixlevelup_runtime')");
    const databases = await admin.query("SELECT 1 FROM pg_database WHERE NOT datistemplate AND datname NOT IN ('postgres','fixlevelup_dev')");
    const relations = await admin.query("SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f','S')");
    assert(schemas.rowCount === 0 && roles.rowCount === 0 && databases.rowCount === 0 && relations.rowCount === 0);
  });

  await step('synthetic persistence marker bootstrap', async () => {
    await admin.query('BEGIN');
    try {
      await admin.query('CREATE SCHEMA p01_technical');
      await admin.query('CREATE TABLE p01_technical.persistence_probe (id integer PRIMARY KEY CHECK (id=1), marker text NOT NULL)');
      await admin.query('INSERT INTO p01_technical.persistence_probe(id,marker) VALUES(1,$1)', [marker]);
      await admin.query('COMMIT');
    } catch {
      try { await admin.query('ROLLBACK'); } catch { /* Safe cleanup only. */ }
      throw new Error('Synthetic marker bootstrap failed');
    }
  });

  run('db:roles', ['run', 'db:roles']);
  run('db:deploy', ['run', 'db:deploy']);
  run('db:test-migrations', ['run', 'db:test-migrations']);
  run('db:test-constraints', ['run', 'db:test-constraints']);

  await step('S3 bucket credentials preflight', async () => {
    const { loadStorageConfig, makeClient } = await import('../../packages/storage-tooling/scripts/local.mjs');
    const storageRequire = createRequire(new URL('../../packages/storage-tooling/package.json', import.meta.url));
    const { HeadBucketCommand } = storageRequire('@aws-sdk/client-s3');
    for (const readonly of [false, true]) {
      const config = loadStorageConfig(readonly);
      const client = makeClient(config);
      try {
        const response = await client.send(new HeadBucketCommand({ Bucket: config.bucket }), { abortSignal: AbortSignal.timeout(5000) });
        assert(response.$metadata.httpStatusCode === 200);
      } finally { client.destroy(); }
    }
  });

  run('full pnpm check', ['run', 'check']);
  run('db:runtime-check', ['run', 'db:runtime-check']);
  run('db:check', ['run', 'db:check']);

  await step('isolated database final invariants', async () => {
    await identity(admin);
    const counts = await admin.query('SELECT (SELECT count(*)::int FROM foundation.audit_logs) AS audit, (SELECT count(*)::int FROM foundation.outbox_events) AS outbox');
    const probe = await admin.query('SELECT id,marker FROM p01_technical.persistence_probe');
    const busy = await admin.query("SELECT count(*)::int AS count FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid() AND state IS DISTINCT FROM 'idle'");
    assert(counts.rows[0].audit === 0 && counts.rows[0].outbox === 0);
    assert(probe.rowCount === 1 && probe.rows[0].id === 1 && probe.rows[0].marker === marker);
    assert(busy.rows[0].count === 0);
    assert(hashLock() === lockSha256);
    console.log('Isolated dev audit/outbox counts: 0/0; exact persistence marker: 1; other busy PG clients: 0.');
  });
  await step('PostgreSQL admin disconnect', async () => { await admin.end(); admin = undefined; });
  stage = 'redacted result write';
  writeEvidence('passed', null);
  console.log('Isolated Linux PG/S3 integration: PASS; full Vitest results are in actual logs.');
} catch {
  const failedStage = stage;
  console.error(`Isolated Linux integration failed at ${failedStage}; details suppressed.`);
  process.exitCode = 1;
  if (admin) {
    try { await admin.end(); } catch { /* Suppress credentials and driver diagnostics. */ }
  }
  if (canWriteEvidence) {
    try { writeEvidence('failed', failedStage); }
    catch { console.error('Redacted integration result could not be written; details suppressed.'); }
  }
}
