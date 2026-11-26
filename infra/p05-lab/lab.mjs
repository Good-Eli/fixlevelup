/**
 * P05 lab orchestrator (task-1) — host-side, PowerShell-free, no third-party deps.
 *
 * Everything here is additive test/lab plumbing: it never touches the working
 * dev PostgreSQL (host port 55432), never stops or queries foreign containers,
 * never switches branches and never commits. It creates exactly two containers
 * labelled `dsh.owner=pg-lab`, both inside a private network namespace.
 *
 *   node infra/p05-lab/lab.mjs freeze          # export the frozen gateway tree
 *   node infra/p05-lab/lab.mjs build           # build the runner image from it
 *   node infra/p05-lab/lab.mjs up [--fresh]    # start PG + runner, provision
 *   node infra/p05-lab/lab.mjs run <files...>  # focused vitest run (exit code passed through)
 *   node infra/p05-lab/lab.mjs exec <cmd...>   # arbitrary command inside the runner
 *   node infra/p05-lab/lab.mjs psql            # interactive-ish psql probe
 *   node infra/p05-lab/lab.mjs status
 *   node infra/p05-lab/lab.mjs down            # stop+rm ONLY this run's containers
 *
 * FROZEN SOURCE POLICY (owner/lead decision): the gateway image is built from
 * `git archive` of the gateway commit plus an explicit overlay of reviewed
 * P05-02 files only. Unfinished 024 SQL, bridge edits and any other working-tree
 * change can therefore never enter the gateway image. The overlay list and every
 * file digest are recorded next to the staging tree.
 */
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { GATEWAY_COMMIT, gatewayFiles, sha256 } from './snapshot.mjs';

const root = resolve(import.meta.dirname, '../..');
const cacheRoot = resolve(root, 'node_modules/.cache/p05-lab');
/**
 * Independent lab instance name. Every instance gets its OWN PostgreSQL + runner
 * containers, its own state and env files, while shared caches (images, frozen
 * tree, locks) stay global. This is how a suite with an exclusive-cluster guard
 * (e.g. the migration orchestrator's `assertLabCluster`, which refuses any
 * foreign session) gets a private cluster instead of fighting the shared one.
 */
const INSTANCE = process.env['FIXLEVELUP_LAB_INSTANCE'] ?? 'default';
const instanceRoot = resolve(cacheRoot, 'instances', INSTANCE);
const statePath = resolve(instanceRoot, 'state.json');

const PG_IMAGE = 'postgres:18.7-bookworm@sha256:1757c628698dd1ca67ff7a5fc386bfd91040afc62a45484c346c788b0cbe5402';
const RUNNER_IMAGE = 'fixlevelup-p05-lab:local';
const S3_IMAGE = 'fixlevelup-p05-lab:s3';
const PG_VERSION_NUM = 180007;

function fail(message) {
  process.stderr.write(`p05-lab: ${message}\n`);
  process.exit(1);
}
function run(command, args, options = {}) {
  const result = spawnSync(command, args, { cwd: root, encoding: 'utf8', stdio: options.stdio ?? 'pipe', ...options });
  if (result.error) { throw result.error; }
  return result;
}
function docker(args, options = {}) {
  const result = run('docker', args, options);
  if (result.status !== 0 && options.allowFailure !== true) {
    throw new Error(`docker ${args[0]} failed (exit ${String(result.status)}): ${String(result.stderr).trim()}`);
  }
  return result;
}
function hex(bytes = 32) { return randomBytes(bytes).toString('hex'); }

/* ---------------------------------- lock ---------------------------------- */

/**
 * Cross-agent mutex for the staging/build phases.
 *
 * Several agents share this working directory, and the S3 snapshot directory is
 * derived from the tree digest: two concurrent `s3test`/`s3image` calls would
 * both `rm -rf`/`mkdir` the SAME staging path and one would die with EPERM on
 * Windows. The lock is an exclusive file (`open` with 'wx'); a stale lock older
 * than 15 minutes is broken, so a crashed run cannot wedge the lab.
 *
 * The lock covers ONLY snapshot + image resolution/build. Actual test runs do
 * not need it: they use their own disposable database and an ephemeral `--rm`
 * container.
 */
const LOCK_TIMEOUT_MS = 30 * 60_000;
const LOCK_STALE_MS = 15 * 60_000;

function sleepSync(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }

function withLock(name, action) {
  mkdirSync(cacheRoot, { recursive: true });
  const path = resolve(cacheRoot, `${name}.lock`);
  const started = Date.now();
  for (;;) {
    try {
      writeFileSync(path, `${String(process.pid)} ${new Date().toISOString()}\n`, { flag: 'wx' });
      break;
    } catch (error) {
      if (error?.code !== 'EEXIST') { throw error; }
      const age = existsSync(path) ? Date.now() - statSync(path).mtimeMs : 0;
      if (age > LOCK_STALE_MS) { rmSync(path, { force: true }); continue; }
      if (Date.now() - started > LOCK_TIMEOUT_MS) {
        throw new Error(`Timed out waiting for the ${name} lab lock (${path}); another agent is building`,
          { cause: error });
      }
      sleepSync(2_000);
    }
  }
  try {
    return action();
  } finally {
    rmSync(path, { force: true });
  }
}

/** `rm -rf` that tolerates the transient Windows EPERM/EBUSY on a busy directory. */
function removeTree(path) {
  for (let attempt = 0; attempt < 10; attempt += 1) {
    try {
      rmSync(path, { recursive: true, force: true });
      return;
    } catch (error) {
      if (attempt === 9) { throw error; }
      sleepSync(250 * (attempt + 1));
    }
  }
}

/* ------------------------------- frozen tree ------------------------------- */

function freezeTree() {
  const derived = gatewayFiles(root);
  const fileHashes = Object.fromEntries([...derived].map(([path, text]) => [path, sha256(text)]));
  const treeId = `${GATEWAY_COMMIT.slice(0, 12)}-${sha256(JSON.stringify(fileHashes)).slice(0, 12)}`;
  const staging = resolve(cacheRoot, `frozen-${treeId}`);
  removeTree(staging);
  mkdirSync(staging, { recursive: true });

  // `git archive` of the frozen commit: tracked files only, no .git, no local data.
  // Written to a file (not captured on stdout) so the tree size is irrelevant.
  const archivePath = resolve(cacheRoot, `frozen-${treeId}.tar`);
  const archive = run('git', ['archive', '--format=tar', `--output=${archivePath}`, GATEWAY_COMMIT]);
  if (archive.status !== 0) { throw new Error('git archive of the gateway commit failed'); }
  const extract = run('tar', ['-xf', archivePath, '-C', staging]);
  rmSync(archivePath, { force: true });
  if (extract.status !== 0) { throw new Error(`tar extract failed: ${String(extract.stderr)}`); }

  // Gateway overlay: the two reviewed test files verbatim plus the DERIVED
  // 023-only snapshot of the product catalog (never the live working copy, which
  // carries in-progress S3 wiring). See infra/p05-lab/snapshot.mjs.
  for (const [path, text] of derived) {
    const destination = resolve(staging, path);
    mkdirSync(resolve(destination, '..'), { recursive: true });
    writeFileSync(destination, text);
  }
  // The lab harness itself (this directory) is part of the image so the runner
  // can provision itself; it contains no product code and no credentials.
  const labFiles = ['Dockerfile', 'Dockerfile.s3', 'provision.mjs', 'attest.mjs', 'makedb.mjs',
    'containerenv.mjs', 'snapshot.mjs', 'README.md', 'lab.mjs'];
  mkdirSync(resolve(staging, 'infra/p05-lab'), { recursive: true });
  for (const name of labFiles) {
    const source = resolve(root, 'infra/p05-lab', name);
    if (existsSync(source)) { writeFileSync(resolve(staging, 'infra/p05-lab', name), readFileSync(source)); }
  }

  const manifest = {
    gatewayCommit: GATEWAY_COMMIT,
    treeId,
    // path -> sha256 of the exact bytes written into the image
    overlay: fileHashes,
    // The frozen chain must be exactly the gateway chain (001..023): a 024 SQL
    // directory present in the working tree is NOT part of this image.
    migrationChain: readdirSync(resolve(staging, 'prisma/migrations'), { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && /^\d{14}_/.test(entry.name))
      .map((entry) => entry.name)
      .sort(),
  };
  if (manifest.migrationChain.at(-1) !== '20261124000100_form_session_foundation') {
    throw new Error('Gateway frozen chain must end at 023 form_session_foundation');
  }
  writeFileSync(resolve(staging, 'p05-lab-frozen.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(resolve(cacheRoot, 'frozen.json'), `${JSON.stringify({ staging, ...manifest }, null, 2)}\n`);
  return { staging, manifest };
}

function frozenState() {
  const path = resolve(cacheRoot, 'frozen.json');
  if (!existsSync(path)) { throw new Error('No frozen tree; run `node infra/p05-lab/lab.mjs freeze`'); }
  return JSON.parse(readFileSync(path, 'utf8'));
}

function buildImage({ fresh = false } = {}) {
  // The frozen tree staging directory is shared state too (same digest across
  // agents), so freeze+build are serialized with the same convention.
  return withLock('gateway-build', () => {
  const frozen = fresh ? (() => { const { staging, manifest } = freezeTree(); return { staging, ...manifest }; })() : frozenState();
  const digest = sha256(`${frozen.treeId}:${PG_VERSION_NUM}`);
  const tag = `${RUNNER_IMAGE}`;
  process.stdout.write(`p05-lab: building ${tag} from frozen tree ${frozen.treeId}\n`);
  const result = docker(['build', '--pull=false', '-f', 'infra/p05-lab/Dockerfile', '-t', tag, frozen.staging],
    { stdio: 'inherit', allowFailure: true });
  if (result.status !== 0) { throw new Error(`image build failed (exit ${String(result.status)})`); }
  const imageId = docker(['image', 'inspect', '--format', '{{.Id}}', tag]).stdout.trim();
  const record = { ...frozen, imageId, imageDigest: digest, builtAt: new Date().toISOString() };
  writeFileSync(resolve(cacheRoot, 'frozen.json'), `${JSON.stringify(record, null, 2)}\n`);
  process.stdout.write(`p05-lab: image ${imageId}\n`);
  return record;
  });
}

/* --------------------------------- state ---------------------------------- */

function loadState() {
  // Legacy layout migration: before independent instances existed, the shared
  // lab state lived at `<cacheRoot>/state.json` with its env under
  // `<cacheRoot>/<runId>/`. Moving it into `instances/default/` keeps a running
  // lab addressable after the layout change (no container is touched).
  const legacyState = resolve(cacheRoot, 'state.json');
  if (!existsSync(statePath) && INSTANCE === 'default' && existsSync(legacyState)) {
    const legacy = JSON.parse(readFileSync(legacyState, 'utf8'));
    mkdirSync(instanceRoot, { recursive: true });
    if (legacy.runId !== undefined && existsSync(resolve(cacheRoot, legacy.runId))) {
      rmSync(resolve(instanceRoot, legacy.runId), { recursive: true, force: true });
      renameSync(resolve(cacheRoot, legacy.runId), resolve(instanceRoot, legacy.runId));
    }
    legacy.envFile = resolve(instanceRoot, legacy.runId, 'env');
    writeFileSync(statePath, `${JSON.stringify(legacy, null, 2)}\n`, { mode: 0o600 });
    process.stdout.write('p05-lab: migrated legacy lab state into instances/default\n');
  }
  return existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf8')) : undefined;
}
function saveState(state) { writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 }); }

function containerState(name) {
  const result = docker(['inspect', '--format', '{{.State.Status}}', name], { allowFailure: true });
  return result.status === 0 ? result.stdout.trim() : 'missing';
}
function requireState() {
  const state = loadState();
  if (state === undefined) { fail('no lab state; run `node infra/p05-lab/lab.mjs up`'); }
  return state;
}

/* ------------------------------- credentials ------------------------------ */

/**
 * Synthetic lab credentials, generated in memory and persisted ONLY under the
 * gitignored `node_modules/.cache/p05-lab/<runId>/` with mode 0600. They are
 * never printed, never committed and never used outside the lab containers.
 */
function writeLabEnv(state, overrides = {}) {
  const envDir = resolve(instanceRoot, state.runId);
  mkdirSync(envDir, { recursive: true });
  const values = { ...state.env, ...overrides };
  const body = Object.entries(values)
    .filter(([, value]) => value !== undefined && value !== '')
    .map(([key, value]) => `${key}=${String(value)}`)
    .join('\n');
  const path = resolve(envDir, 'env');
  writeFileSync(path, `${body}\n`, { mode: 0o600 });
  state.envFile = path;
  saveState(state);
  return path;
}

/* -------------------------------- cluster --------------------------------- */

function startPostgres(state) {
  const name = `p05lab-pg-${state.runId}`;
  if (containerState(name) !== 'missing') { return name; }
  // Only the initial superuser password file is mounted (read-only, 0600); the
  // full synthetic env file is NOT exposed to the PostgreSQL container.
  const initDir = resolve(instanceRoot, state.runId, 'pg-init');
  mkdirSync(initDir, { recursive: true });
  writeFileSync(resolve(initDir, 'pg-init-password'),
    `${state.env.FIXLEVELUP_LAB_FIXTURE_ADMIN_PASSWORD}\n`, { mode: 0o600 });
  docker(['run', '--detach', '--name', name,
    '--label', 'dsh.owner=pg-lab', '--label', 'dsh.task=task-1',
    '--label', 'dsh.purpose=p05-lab-pg', '--label', 'dsh.ephemeral=true',
    '--network', 'none',
    '--tmpfs', '/var/lib/postgresql:rw,size=2g',
    '--env', 'POSTGRES_DB=postgres',
    '--env', 'POSTGRES_USER=postgres',
    '--env', 'POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256',
    '--env', 'POSTGRES_PASSWORD_FILE=/run/p05lab/pg-init-password',
    '--mount', `type=bind,source=${initDir},target=/run/p05lab,readonly`,
    PG_IMAGE,
    'postgres', '-c', 'listen_addresses=127.0.0.1', '-c', 'port=55432',
    '-c', `cluster_name=${state.env.FIXLEVELUP_CLUSTER_NAME}`,
    '-c', 'fsync=on', '-c', 'synchronous_commit=on', '-c', 'full_page_writes=on',
    '-c', 'log_connections=off', '-c', 'log_statement=none']);
  return name;
}

function waitForPostgres(state, name) {
  const deadline = Date.now() + 90_000;
  for (;;) {
    const ready = docker(['exec', name, 'pg_isready', '-h', '127.0.0.1', '-p', '55432', '-U', 'postgres'],
      { allowFailure: true });
    if (ready.status === 0) { break; }
    if (Date.now() > deadline) { throw new Error('lab PostgreSQL readiness deadline exceeded'); }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
  }
  // Exact identity: PG 18.7 and the unique cluster marker, inside the namespace.
  const probe = docker(['exec', '-e', 'PGPASSWORD=' + state.env.FIXLEVELUP_LAB_FIXTURE_ADMIN_PASSWORD,
    name, 'psql', '-h', '127.0.0.1', '-p', '55432', '-U', 'postgres', '-d', 'postgres', '-X', '-A', '-t',
    '-c', "SELECT current_setting('server_version_num') || '|' || current_setting('cluster_name')"]);
  const [version, cluster] = probe.stdout.trim().split('|');
  if (version !== String(PG_VERSION_NUM) || cluster !== state.env.FIXLEVELUP_CLUSTER_NAME) {
    throw new Error('lab PostgreSQL identity mismatch');
  }
  return probe.stdout.trim();
}

function startRunner(state, pgName) {
  const name = `p05lab-runner-${state.runId}`;
  if (containerState(name) !== 'missing') { return name; }
  const initDir = resolve(instanceRoot, state.runId, 'pg-init');
  docker(['run', '--detach', '--name', name,
    '--label', 'dsh.owner=pg-lab', '--label', 'dsh.task=task-1',
    '--label', 'dsh.purpose=p05-lab-runner', '--label', 'dsh.ephemeral=true',
    '--network', `container:${pgName}`,
    '--mount', `type=bind,source=${initDir},target=/run/p05lab,readonly`,
    state.runnerImage ?? RUNNER_IMAGE]);
  return name;
}

/** Runs a command inside the runner with the synthetic env, never in argv. */
function runnerExec(state, args, options = {}) {
  const result = run('docker', ['exec', '--env-file', state.envFile, '-w', options.workdir ?? '/workspace',
    state.runner, ...args], { stdio: options.stdio ?? 'inherit', env: process.env });
  return result;
}

/** Same, but captures stdout so a JSON summary line can be parsed. */
function runnerCapture(state, args) {
  return run('docker', ['exec', '--env-file', state.envFile, '-w', '/workspace', state.runner, ...args],
    { stdio: 'pipe', env: process.env });
}

/* ---------------------------------- up ------------------------------------ */

function up({ fresh = false, image = 'gateway' } = {}) {
  mkdirSync(instanceRoot, { recursive: true });
  const existing = loadState();
  if (existing !== undefined && containerState(`p05lab-pg-${existing.runId}`) !== 'missing' && fresh !== true) {
    process.stdout.write(`p05-lab[${INSTANCE}]: already up (runId ${existing.runId})\n`);
    return existing;
  }
  if (fresh === true && existing !== undefined) { down({ quiet: true }); }

  // `--image s3` starts the runner from the CURRENT-TREE image (024 chain) so an
  // exclusive-cluster consumer such as the migration orchestrator runs against
  // the tree under test; the default stays the frozen 023 gateway image.
  const runnerImage = image === 's3' ? S3_IMAGE : RUNNER_IMAGE;
  const inspect = docker(['image', 'inspect', '--format', '{{.Id}}', runnerImage], { allowFailure: true });
  if (inspect.status !== 0) {
    throw new Error(`missing ${runnerImage}; run \`node infra/p05-lab/lab.mjs ${image === 's3' ? 's3image' : 'build'}\``);
  }

  const runId = hex(6);
  const suffix = hex(6);
  const migrationLimit = process.env['FIXLEVELUP_LAB_MIGRATION_LIMIT'] ?? (image === 's3' ? '24' : '23');
  const appDatabase = process.env['FIXLEVELUP_LAB_DATABASE'] ?? (image === 's3' ? 'fixlevelup_p05_s3lab' : 'fixlevelup_p05_s2lab');
  const env = {
    FIXLEVELUP_SYNTHETIC_ORCHESTRATOR: '1',
    FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS: '1',
    FIXLEVELUP_FILE_RESTORE_TESTS: '1',
    FIXLEVELUP_SESSION_RUN_ID: runId,
    FIXLEVELUP_CLUSTER_NAME: `fixlevelup_p05s4_lab_${runId}`,
    FIXLEVELUP_LAB_DATABASE: appDatabase,
    FIXLEVELUP_LAB_ORCHESTRATOR_ROLE: 'fixlevelup_lab_orchestrator',
    FIXLEVELUP_LAB_ORCHESTRATOR_PASSWORD: hex(),
    FIXLEVELUP_LAB_FIXTURE_ADMIN_PASSWORD: hex(),
    FIXLEVELUP_MIGRATOR_PASSWORD: hex(),
    FIXLEVELUP_RUNTIME_PASSWORD: hex(),
    FIXLEVELUP_LAB_CONTROL_DATABASE: `fixlevelup_p05_control_${suffix}`,
    FIXLEVELUP_LAB_CONTROL_ROLE: `fixlevelup_p05_launcher_${suffix}`,
    FIXLEVELUP_LAB_CONTROL_PASSWORD: hex(),
    FIXLEVELUP_LAB_MIGRATION_LIMIT: String(migrationLimit),
    LAUNCH_CONTROL_HOST: '127.0.0.1',
    LAUNCH_CONTROL_PORT: '55432',
    LAUNCH_CONTROL_DATABASE: `fixlevelup_p05_control_${suffix}`,
    LAUNCH_CONTROL_USER: `fixlevelup_p05_launcher_${suffix}`,
    LAUNCH_CONTROL_PASSWORD: '',
    LAUNCH_APPROVAL_TIMEOUT_MS: '10000',
  };
  env.LAUNCH_CONTROL_PASSWORD = env.FIXLEVELUP_LAB_CONTROL_PASSWORD;
  const state = { instance: INSTANCE, runId, suffix, env, runnerImage, createdAt: new Date().toISOString() };
  writeLabEnv(state);

  const pgName = startPostgres(state);
  state.pg = pgName;
  saveState(state);
  const identity = waitForPostgres(state, pgName);
  const runnerName = startRunner(state, pgName);
  state.runner = runnerName;
  saveState(state);

  process.stdout.write(`p05-lab: pg ${pgName} (${identity}), runner ${runnerName}\n`);
  // Idempotent: attest an already-provisioned cluster first; only a cluster that
  // fails attestation (i.e. a fresh empty one) is provisioned.
  let summary;
  const attest = runnerCapture(state, ['node', 'infra/p05-lab/attest.mjs']);
  if (attest.status === 0) {
    summary = JSON.parse(attest.stdout.trim().split('\n').at(-1));
    process.stdout.write('p05-lab: existing provisioning attested, nothing created\n');
  } else {
    process.stdout.write('p05-lab: provisioning synthetic cluster (roles, 001..' + String(migrationLimit) + ', control DB)\n');
    const provision = runnerCapture(state, ['node', 'infra/p05-lab/provision.mjs']);
    if (provision.status !== 0) {
      process.stderr.write(String(provision.stderr));
      throw new Error(`lab provisioning failed (exit ${String(provision.status)})`);
    }
    summary = JSON.parse(provision.stdout.trim().split('\n').at(-1));
  }
  state.summary = summary;
  state.env.FIXLEVELUP_LAB_DATABASE_OID = String(summary.databaseOid);
  writeLabEnv(state);
  saveState(state);
  process.stdout.write(`p05-lab: ready — db ${summary.database} (oid ${String(summary.databaseOid)}), `
    + `${String(summary.migrations)} migrations, last ${summary.lastMigration}, control ${summary.controlDatabase}\n`);
  return state;
}

/* ---------------------------- S3 (024) measurement ------------------------ */

/**
 * Separate capability for the S3/024 work: measures fingerprints of the REVIEWED
 * 024 SQL against the CURRENT working tree's measurement functions, in a brand
 * new disposable database. It never touches the 023 gateway database, never
 * upgrades it, and never claims a build PASS (the measurement entry is compiled
 * on its own import graph, so unrelated WIP type errors cannot block it).
 */
function s3measure() {
  const state = requireState();
  const live = resolve(cacheRoot, 's3-live');
  rmSync(live, { recursive: true, force: true });
  mkdirSync(resolve(live, 'apps/api'), { recursive: true });
  mkdirSync(resolve(live, 'infra/p05-lab/s3'), { recursive: true });
  // Source-only copies: no .env, no node_modules, no dist, no local data.
  copyTree(resolve(root, 'apps/api/src'), resolve(live, 'apps/api/src'));
  copyFile(resolve(root, 'apps/api/package.json'), resolve(live, 'apps/api/package.json'));
  copyFile(resolve(root, 'infra/p05-lab/s3/measure.ts'), resolve(live, 'infra/p05-lab/s3/measure.ts'));
  copyFile(resolve(root, 'infra/p05-lab/s3/tsconfig.json'), resolve(live, 'infra/p05-lab/s3/tsconfig.json'));
  copyFile(resolve(root, 'infra/p05-lab/makedb.mjs'), resolve(live, 'infra/p05-lab/makedb.mjs'));
  // The reviewed migration chain is applied by `makedb.mjs`; copy it as source.
  copyTree(resolve(root, 'prisma/migrations'), resolve(live, 'prisma/migrations'));
  // ESM marker for the staged tree; the measurement entry uses top-level await.
  writeFileSync(resolve(live, 'package.json'), `${JSON.stringify({ name: 'p05lab-s3-measure', private: true, type: 'module' }, null, 2)}\n`);

  const suffix = hex(6);
  const database = `fixlevelup_p05_s3lab_${suffix}`;
  const workspace = '/tmp/p05lab-s3';
  docker(['exec', state.runner, 'rm', '-rf', workspace], { allowFailure: true });
  docker(['exec', state.runner, 'mkdir', '-p', workspace]);
  // `<src>/.` copies the CONTENTS of the staging directory (not the directory
  // itself), so the paths inside the container match the tsconfig rootDir.
  docker(['cp', `${live}${sep}.`, `${state.runner}:${workspace}`]);
  // Compile ONLY the measurement entry and its import graph. The output goes
  // under `apps/api/` so Node's ESM resolution walks up into the api package's
  // node_modules (pg, @fixlevelup/p03-contracts); the workspace root provides
  // typescript and @types/node. Symlinks only; nothing is installed.
  const outDir = `${workspace}/apps/api/p05lab-dist`;
  const prepared = docker(['exec', state.runner, 'sh', '-lc',
    `ln -sfn /workspace/node_modules ${workspace}/node_modules && `
    + `ln -sfn /workspace/apps/api/node_modules ${workspace}/apps/api/node_modules && `
    + `node /workspace/node_modules/typescript/bin/tsc -p ${workspace}/infra/p05-lab/s3/tsconfig.json --outDir ${outDir}`],
  { allowFailure: true });
  if (prepared.status !== 0) {
    process.stderr.write(prepared.stdout ?? '');
    process.stderr.write(prepared.stderr ?? '');
    fail(`S3 measurement compilation failed (exit ${String(prepared.status)})`);
  }
  const created = run('docker', ['exec', '--env-file', state.envFile,
    '-e', `FIXLEVELUP_LAB_DATABASE=${database}`, '-e', 'FIXLEVELUP_LAB_MIGRATION_LIMIT=24',
    '-w', workspace, state.runner, 'node', 'infra/p05-lab/makedb.mjs']);
  if (created.status !== 0) {
    process.stderr.write(String(created.stderr));
    fail(`024 test database provisioning failed (exit ${String(created.status)})`);
  }
  const db = JSON.parse(created.stdout.trim().split('\n').at(-1));
  process.stdout.write(`p05-lab: 024 measurement database ${db.database} (oid ${String(db.oid)}, `
    + `${String(db.migrations)} migrations, last ${db.lastMigration})\n`);
  let measured;
  try {
    measured = run('docker', ['exec', '--env-file', state.envFile,
      '-e', `FIXLEVELUP_LAB_DATABASE=${database}`,
      '-w', workspace, state.runner, 'node', `${outDir}/infra/p05-lab/s3/measure.js`]);
  } finally {
    // Drop exactly this run's disposable 024 database, addressed by its own OID.
    const dropped = run('docker', ['exec', '--env-file', state.envFile, '-w', workspace, state.runner,
      'node', 'infra/p05-lab/makedb.mjs', 'drop', String(db.oid)]);
    process.stdout.write(`p05-lab: ${dropped.status === 0 ? 'dropped' : 'DROP FAILED'} ${db.database}\n`);
  }
  if (measured.status !== 0) {
    process.stderr.write(String(measured.stderr));
    fail(`S3 measurement failed (exit ${String(measured.status)})`);
  }
  process.stdout.write(`${measured.stdout.trim()}\n`);
}

function copyFile(from, to) { writeFileSync(to, readFileSync(from)); }
function copyTree(from, to) {
  mkdirSync(to, { recursive: true });
  for (const entry of readdirSync(from, { withFileTypes: true })) {
    const source = resolve(from, entry.name);
    const destination = resolve(to, entry.name);
    if (entry.isDirectory()) { mkdirSync(destination, { recursive: true }); copyTree(source, destination); }
    else if (entry.isFile()) { copyFile(source, destination); }
  }
}

/* --------------------------- S3 (024) test snapshot ----------------------- */

/**
 * Files never allowed into an S3 test snapshot: local credentials, dumps,
 * generated artifacts and local QA material. `git ls-files --others
 * --exclude-standard` already drops gitignored paths; this is the explicit
 * second gate so a future `.gitignore` mistake cannot leak a secret into an
 * image.
 */
const SNAPSHOT_EXCLUDE = [
  // Real secrets only. Tracked SAMPLES stay in the snapshot (`.env.example`,
  // `.env.sample`, `.env.template`) — they carry placeholders, and the reviewed
  // lab fixtures read some of them. Every other `.env*` variant is excluded.
  /(^|\/)\.env(\.(?!example$|sample$|template$)[^/]+)?$/,
  /(^|\/)node_modules\//,
  /(^|\/)(dist|\.next|coverage|test-results|backups|uploads|secrets|private|local-data)\//,
  /\.(pem|key|p12|pfx|dump|backup|sql\.gz|tsbuildinfo|log)$/,
];

function snapshotPaths() {
  const list = (args) => {
    const out = execFileSync('git', args, { cwd: root, encoding: 'buffer', maxBuffer: 64 * 1024 * 1024 });
    return out.toString('utf8').split('\0').filter((entry) => entry.length > 0);
  };
  const tracked = list(['ls-files', '-z']);
  const untracked = list(['ls-files', '-z', '--others', '--exclude-standard']);
  const all = [...new Set([...tracked, ...untracked])].sort();
  return all.filter((path) => !SNAPSHOT_EXCLUDE.some((pattern) => pattern.test(path)));
}

/**
 * Materializes the current-tree snapshot and returns its digest + path count.
 *
 * Each file is read EXACTLY ONCE: the same bytes that are hashed are the bytes
 * written into the staging tree, so a concurrent edit between hashing and
 * copying cannot make the recorded digest describe different content than the
 * image is built from. The full 64-hex snapshot digest is recorded (the 16-hex
 * `treeId` is only the staging directory name).
 */
function s3Snapshot() {
  const paths = snapshotPaths();
  const digest = createHash('sha256');
  const contents = [];
  for (const path of paths) {
    const bytes = readFileSync(resolve(root, path));
    digest.update(`${path}\0${String(bytes.byteLength)}\0`).update(bytes);
    contents.push({ path, bytes });
  }
  const snapshotSha256 = digest.digest('hex');
  const treeId = snapshotSha256.slice(0, 16);
  const staging = resolve(cacheRoot, `s3-snapshot-${treeId}`);
  removeTree(staging);
  mkdirSync(staging, { recursive: true });
  const written = createHash('sha256');
  for (const { path, bytes } of contents) {
    const destination = resolve(staging, path);
    mkdirSync(resolve(destination, '..'), { recursive: true });
    writeFileSync(destination, bytes);
    // Verify the destination, not the in-memory input a second time.
    const stagedBytes = readFileSync(destination);
    written.update(`${path}\0${String(stagedBytes.byteLength)}\0`).update(stagedBytes);
  }
  if (written.digest('hex') !== snapshotSha256) {
    throw new Error('S3 snapshot digest does not match the bytes written to staging');
  }
  const manifest = { treeId, snapshotSha256, files: paths.length, generatedAt: new Date().toISOString() };
  writeFileSync(resolve(cacheRoot, 's3-snapshot.json'), `${JSON.stringify({ staging, ...manifest }, null, 2)}\n`);
  // Prune older staging trees: only the current tree can be used by a run, and
  // each one is a full copy of the working tree. Strictly limited to our own
  // `s3-snapshot-*` directories under the lab cache.
  for (const entry of readdirSync(cacheRoot, { withFileTypes: true })) {
    if (!entry.isDirectory() || !/^s3-snapshot-[a-f0-9]{16}$/.test(entry.name) || entry.name === `s3-snapshot-${treeId}`) {
      continue;
    }
    removeTree(resolve(cacheRoot, entry.name));
  }
  return { staging, manifest };
}

function s3Image({ rebuild = false } = {}) {
  const recordPath = resolve(cacheRoot, 's3-snapshot.json');
  // Snapshot + image resolution/build are the ONLY phases that mutate shared
  // state (`s3-snapshot-<treeId>` and the image tag). Several agents run against
  // this lab, so these phases are serialized with a lock file; two agents
  // computing the same treeId would otherwise race on rm/mkdir (Windows EPERM).
  return withLock('s3-build', () => {
  // The previous record MUST be read inside the lock: reading it before the lock
  // means another agent could rewrite it in between, and the reuse decision would
  // be based on a stale `imageId`.
  const previous = existsSync(recordPath) ? JSON.parse(readFileSync(recordPath, 'utf8')) : undefined;
  const current = s3Snapshot();
  const existing = docker(['image', 'inspect', '--format', '{{.Id}}', S3_IMAGE], { allowFailure: true });
  const existingId = existing.status === 0 ? existing.stdout.trim() : undefined;
  // Reuse requires BOTH the same tree AND that the tag still points at exactly the
  // image the previous run built: a tag that merely exists may have been
  // retagged by another agent, which would silently change what gets tested.
  if (!rebuild && previous?.imageId !== undefined && existingId === previous.imageId
    && previous.snapshotSha256 === current.manifest.snapshotSha256) {
    const reuse = { ...previous, staging: current.staging, snapshotSha256: current.manifest.snapshotSha256,
      generatedAt: current.manifest.generatedAt };
    writeFileSync(recordPath, `${JSON.stringify(reuse, null, 2)}\n`);
    return reuse;
  }
  process.stdout.write(`p05-lab: building ${S3_IMAGE} from current tree ${current.manifest.treeId} `
    + `(${String(current.manifest.files)} files)\n`);
  const result = docker(['build', '--pull=false', '-f', 'infra/p05-lab/Dockerfile.s3', '-t', S3_IMAGE, current.staging],
    { stdio: 'inherit', allowFailure: true });
  if (result.status !== 0) { throw new Error(`S3 image build failed (exit ${String(result.status)})`); }
  const imageId = docker(['image', 'inspect', '--format', '{{.Id}}', S3_IMAGE]).stdout.trim();
  const record = { staging: current.staging, ...current.manifest, imageId };
  writeFileSync(recordPath, `${JSON.stringify(record, null, 2)}\n`);
  process.stdout.write(`p05-lab: ${S3_IMAGE} ${imageId}\n`);
  return record;
  });
}

/* ---------------------- optional run inputs (--old-binary etc.) ----------- */

/**
 * `--old-binary` support: export a reviewed HISTORICAL commit with
 * `git archive` (read-only, no worktree switch, no branch change, the live `.git`
 * is never mounted) into this lab's own ignored cache directory, then mount the
 * exact tarball read-only and hand the test both the path and the full SHA-256 of
 * the bytes it will read. The archive is created once per commit and reused.
 */
const OLD_BINARY_COMMIT = '7a60d4c5a84adeb2f6cbec6a0eb1b8723e104a62';

function oldBinaryArchive() {
  const name = `old-binary-${OLD_BINARY_COMMIT.slice(0, 12)}.tar`;
  const path = resolve(cacheRoot, name);
  if (!existsSync(path)) {
    process.stdout.write(`p05-lab: exporting ${OLD_BINARY_COMMIT.slice(0, 12)} via git archive\n`);
    const result = run('git', ['archive', '--format=tar', `--output=${path}`, OLD_BINARY_COMMIT], { allowFailure: true });
    if (result.status !== 0) { throw new Error(`git archive ${OLD_BINARY_COMMIT} failed (exit ${String(result.status)})`); }
  }
  const sha256Hex = createHash('sha256').update(readFileSync(path)).digest('hex');
  const bytes = statSync(path).size;
  process.stdout.write(`p05-lab: old-binary archive ${name} (${String(bytes)} bytes, sha256 ${sha256Hex})\n`);
  return { path, sha256: sha256Hex };
}

/**
 * Opt-in test flags a run may need, expressed as explicit command flags so the
 * caller never has to hand-write env. Each one only ENABLES a reviewed suite that
 * is skipped by default; none of them relaxes a production path. A flag whose
 * supporting service is not actually up is refused here, before the run starts,
 * rather than turning into a confusing in-test skip or failure.
 */
const OPT_IN_FLAGS = [
  ['--s3', ['FIXLEVELUP_STORAGE_S3_TESTS=1'], 'garage'],
  ['--privacy', ['FIXLEVELUP_FILE_PRIVACY_TESTS=1', 'FIXLEVELUP_FILE_PROCESSING_TESTS=1'], 'garage'],
  ['--ledger', ['FIXLEVELUP_ISOLATED_FILE_LEDGER_TESTS=1'], 'ledger'],
  ['--restore', ['FIXLEVELUP_FILE_RESTORE_TESTS=1', 'FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS=1'], 'ledger'],
];

function optInEnv(state, flags) {
  const wanted = OPT_IN_FLAGS.filter(([flag]) => flags.includes(flag));
  const needsGarage = wanted.some(([, , needs]) => needs === 'garage');
  const needsLedger = wanted.some(([, , needs]) => needs === 'ledger');
  if (needsGarage && containerState(garageName(state)) === 'missing') {
    fail('--s3/--privacy need the isolated Garage; run `node infra/p05-lab/lab.mjs garage up` first');
  }
  if (needsLedger) {
    for (const name of [ledgerName(state), floorName(state)]) {
      if (containerState(name) === 'missing') {
        fail('--ledger/--restore need the isolated ledger+floor; run `node infra/p05-lab/lab.mjs ledger up` first');
      }
    }
  }
  return wanted.flatMap(([, env]) => env);
}

/** Extra docker args + env for `--old-binary` (read-only mount, exact digest). */
function oldBinaryMount(flags) {
  if (!flags.includes('--old-binary')) { return { args: [], env: [] }; }
  const archive = oldBinaryArchive();
  return {
    args: ['--mount', `type=bind,source=${archive.path},target=/p05-old-binary.tar,readonly`],
    env: ['FIXLEVELUP_P05_OLD_ARCHIVE=/p05-old-binary.tar',
      `FIXLEVELUP_P05_OLD_ARCHIVE_SHA256=${archive.sha256}`],
  };
}

/**
 * `s3test` — run an arbitrary verification command against a fresh disposable
 * 024 database in the private lab namespace, using the current-tree snapshot.
 *
 * Everything after `--` is the command, verbatim (so a migration script or an
 * old check needs no new flag here). Default: `corepack pnpm exec vitest run`.
 * The command runs with `FIXLEVELUP_LAB_DATABASE` and `..._OID` pointing at the
 * freshly created 024 database; that database is dropped (by its own OID) after
 * the command, whatever its exit code, and the helper container is `--rm`.
 */
function s3test(argv) {
  const state = requireState();
  const separator = argv.indexOf('--');
  const flags = separator === -1 ? argv : argv.slice(0, separator);
  const passthrough = separator === -1 ? [] : argv.slice(separator + 1);
  const image = s3Image({ rebuild: flags.includes('--rebuild') });
  const database = `fixlevelup_p05_s3tlab_${hex(6)}`;
  const pgName = state.pg;
  if (containerState(pgName) === 'missing') { fail('lab PostgreSQL is not running; run `up` first'); }
  // Default operation: `corepack pnpm exec vitest run` with everything after `--`
  // passed through verbatim. `--cmd` (before OR after the separator) instead
  // treats the passthrough as a full command line, e.g.
  //   s3test --cmd -- sh -lc 'node infra/p05-lab/makedb.mjs ...'
  const cmdMode = flags.includes('--cmd') || passthrough[0] === '--cmd';
  const args = passthrough[0] === '--cmd' ? passthrough.slice(1) : passthrough;
  const runCommand = cmdMode ? args : ['corepack', 'pnpm', 'exec', 'vitest', 'run', ...args];
  // Resolve the optional historical archive ONCE (creates it if absent).
  const oldBinary = oldBinaryMount(flags);
  if (runCommand.length === 0) { fail('s3test requires a command after --cmd'); }
  process.stdout.write(`p05-lab: s3test db ${database} (snapshot ${image.treeId}, image ${image.imageId})\n`);
  // One ephemeral container: create DB -> write the lab-only synthetic env ->
  // run the command -> drop the DB by its own OID. `--rm` leaves nothing behind.
  const script = [
    'set -u',
    'node infra/p05-lab/makedb.mjs > /tmp/p05lab-db.json || { echo "p05-lab: 024 database provisioning failed"; exit 90; }',
    'oid=$(node -e \'process.stdout.write(JSON.parse(require("node:fs").readFileSync("/tmp/p05lab-db.json","utf8")).oid)\')',
    'export FIXLEVELUP_LAB_DATABASE_OID="$oid"',
    'node infra/p05-lab/containerenv.mjs',
    '"$@"',
    'rc=$?',
    'node infra/p05-lab/makedb.mjs drop "$oid" || echo "p05-lab: DROP FAILED (addressed by oid)"',
    'exit "$rc"',
  ].join('\n');
  const result = run('docker', ['run', '--rm', '--network', `container:${pgName}`,
    '--env-file', state.envFile,
    '-e', `FIXLEVELUP_LAB_DATABASE=${database}`,
    '-e', 'FIXLEVELUP_LAB_MIGRATION_LIMIT=24',
    // Opt-in suites (`--s3`, `--privacy`, `--ledger`, `--restore`) are enabled by
    // explicit flags; each reviewed fixture still requires its own env gate.
    ...optInEnv(state, flags).flatMap((entry) => ['-e', entry]),
    ...oldBinary.args,
    ...oldBinary.env.flatMap((entry) => ['-e', entry]),
    '-w', '/workspace', image.imageId, 'sh', '-lc', script, 'p05lab', ...runCommand],
  { stdio: 'inherit' });
  process.exit(result.status ?? 1);
}

/**
 * `s3run` — run an arbitrary shell command in an ephemeral container inside the
 * private lab namespace, on the current-tree S3 image, WITHOUT creating or
 * dropping anything automatically. The caller owns its own disposable databases
 * (`makedb.mjs` / `makedb.mjs empty` / `makedb.mjs drop <oid>`).
 *
 * Usage: node infra/p05-lab/lab.mjs s3run [--rebuild] -- sh -lc '<script>'
 */
function s3run(argv) {
  const state = requireState();
  const separator = argv.indexOf('--');
  const flags = separator === -1 ? argv : argv.slice(0, separator);
  const command = separator === -1 ? [] : argv.slice(separator + 1);
  if (command.length === 0) { fail('s3run requires a command after --'); }
  const image = s3Image({ rebuild: flags.includes('--rebuild') });
  if (containerState(state.pg) === 'missing') { fail('lab PostgreSQL is not running; run `up` first'); }
  process.stdout.write(`p05-lab: s3run (snapshot ${image.treeId}, image ${image.imageId})\n`);
  const result = run('docker', ['run', '--rm', '--network', `container:${state.pg}`,
    '--env-file', state.envFile, '-w', '/workspace', image.imageId, ...command], { stdio: 'inherit' });
  process.exit(result.status ?? 1);
}

/* ------------------------- isolated Garage (S3) in netns ------------------ */

/**
 * Real Garage in the SAME private network namespace as the lab PostgreSQL.
 *
 * Owner-approved (25.11.2026): reviewed `dxflrs/garage:v2.5.0` image, reviewed
 * `infra/dev-s3/garage.toml` mounted read-only, data on tmpfs (no volumes, no
 * host ports, no dev container, no dev volume, no external credentials). The
 * container joins `--network container:<pg>`, so Garage listens on loopback
 * 3900/3901 inside the namespace and the runner reaches it as
 * `http://127.0.0.1:3900` — the exact endpoint the reviewed storage config
 * pins. Nothing is published to the host.
 */
const GARAGE_IMAGE = 'dxflrs/garage:v2.5.0@sha256:677e5b758e4425a325b811c425c026bf35a4bf42f7ddbaa773de3f4fd779a5a5';
const GARAGE_BUCKET = 'fixlevelup-dev-private';

function garageName(state) { return `p05lab-garage-${state.runId}`; }

function startGarage(state) {
  const name = garageName(state);
  if (containerState(name) !== 'missing') { return name; }
  if (containerState(state.pg) === 'missing') { fail('lab PostgreSQL is not running; run `up` first'); }
  if (state.env.GARAGE_RPC_SECRET === undefined) {
    state.env.GARAGE_RPC_SECRET = hex();
    writeLabEnv(state);
  }
  docker(['run', '--detach', '--name', name,
    '--label', 'dsh.owner=pg-lab', '--label', 'dsh.task=task-1',
    '--label', 'dsh.purpose=p05-lab-garage', '--label', 'dsh.ephemeral=true',
    '--network', `container:${state.pg}`,
    '--tmpfs', '/var/lib/garage:rw,size=512m',
    '--mount', `type=bind,source=${resolve(root, 'infra/dev-s3/garage.toml')},target=/etc/garage.toml,readonly`,
    '--env', `GARAGE_RPC_SECRET=${state.env.GARAGE_RPC_SECRET}`,
    '--env', 'GARAGE_LOG_FORMAT=json', '--env', 'RUST_LOG=error', '--env', 'NO_COLOR=1',
    GARAGE_IMAGE, '/garage', 'server', '--single-node']);
  // Wait for the admin API (loopback inside the namespace).
  const deadline = Date.now() + 60_000;
  for (;;) {
    const probe = docker(['exec', name, '/garage', '-c', '/etc/garage.toml', 'status'], { allowFailure: true });
    if (probe.status === 0) { break; }
    if (Date.now() > deadline) { throw new Error('lab Garage readiness deadline exceeded'); }
    sleepSync(500);
  }
  return name;
}

function garageCli(state, args) {
  const result = docker(['exec', garageName(state), '/garage', '-c', '/etc/garage.toml', ...args], { allowFailure: true });
  if (result.status !== 0) {
    throw new Error(`lab Garage command failed: ${args.slice(0, 2).join(' ')} (exit ${String(result.status)})`);
  }
  return result.stdout;
}

/**
 * One-time bootstrap: single-node layout, the reviewed bucket name, and two
 * fresh synthetic keys (RW + RO) with the exact grant shapes the reviewed
 * storage tests assert. Keys are generated here, never copied from dev.
 */
function bootstrapGarage(state) {
  const name = garageName(state);
  if (state.env.LAB_S3_ACCESS_KEY_ID !== undefined) { return; }
  // `--single-node` already assigns and applies a valid single-node layout at
  // startup (version 1, dc1, 512 MiB), so no layout mutation is needed here:
  // touching it would stage a redundant change and can fail on a version race.
  // Only the reviewed bucket name and two fresh synthetic keys are provisioned.
  garageCli(state, ['bucket', 'create', GARAGE_BUCKET]);
  const rw = { id: `GK${hex(12)}`, secret: hex() };
  const ro = { id: `GK${hex(12)}`, secret: hex() };
  garageCli(state, ['key', 'import', '--yes', '-n', 'p05lab-rw', rw.id, rw.secret]);
  garageCli(state, ['key', 'import', '--yes', '-n', 'p05lab-ro', ro.id, ro.secret]);
  garageCli(state, ['bucket', 'allow', '--read', '--write', '--key', rw.id, GARAGE_BUCKET]);
  garageCli(state, ['bucket', 'allow', '--read', '--key', ro.id, GARAGE_BUCKET]);
  state.env.LAB_S3_ACCESS_KEY_ID = rw.id;
  state.env.LAB_S3_SECRET_ACCESS_KEY = rw.secret;
  state.env.LAB_S3_READONLY_ACCESS_KEY_ID = ro.id;
  state.env.LAB_S3_READONLY_SECRET_ACCESS_KEY = ro.secret;
  // The reviewed file-restore lab branch pins the RPC node line and needs the
  // run's RPC secret in its client config; both are per-run, so they travel in
  // the env file and are written into the ephemeral container at start.
  const nodeLine = garageCli(state, ['node', 'id', '-q']).trim();
  if (!/^[0-9a-f]{64}@127\.0\.0\.1:3901$/.test(nodeLine)) { throw new Error('lab Garage node id unavailable'); }
  state.env.LAB_GARAGE_NODE = nodeLine;
  state.env.LAB_GARAGE_RPC_SECRET = state.env.GARAGE_RPC_SECRET;
  writeLabEnv(state);
  process.stdout.write(`p05-lab: garage ${name} bucket ${GARAGE_BUCKET} bootstrapped (synthetic keys, not printed)\n`);
}

function garageUp() {
  const state = requireState();
  const name = startGarage(state);
  bootstrapGarage(state);
  // Always refresh the per-run RPC node line + secret in the env file, even when
  // the bucket/keys were already bootstrapped earlier in this run.
  const nodeLine = garageCli(state, ['node', 'id', '-q']).trim();
  if (!/^[0-9a-f]{64}@127\.0\.0\.1:3901$/.test(nodeLine)) { throw new Error('lab Garage node id unavailable'); }
  state.env.LAB_GARAGE_NODE = nodeLine;
  state.env.LAB_GARAGE_RPC_SECRET = state.env.GARAGE_RPC_SECRET;
  writeLabEnv(state);
  process.stdout.write(`p05-lab: garage ${name} ready at http://127.0.0.1:3900 (loopback inside the lab namespace only)\n`);
  return state;
}

function garageDown() {
  const state = requireState();
  const name = garageName(state);
  if (containerState(name) === 'missing') { process.stdout.write('p05-lab: no lab garage\n'); return; }
  docker(['stop', '--time', '20', name], { allowFailure: true });
  docker(['rm', name], { allowFailure: true });
  delete state.env.LAB_S3_ACCESS_KEY_ID;
  delete state.env.LAB_S3_SECRET_ACCESS_KEY;
  delete state.env.LAB_S3_READONLY_ACCESS_KEY_ID;
  delete state.env.LAB_S3_READONLY_SECRET_ACCESS_KEY;
  writeLabEnv(state);
  process.stdout.write(`p05-lab: removed ${name}\n`);
}

/* --------------------- reviewed engine host bridge (C tests) -------------- */

/**
 * The reviewed engine bridge splits the real pinned launcher from the test
 * process: `infra/file-processing/p05-lab-engine-host.mjs` runs ON THE HOST
 * (the only place with the Docker API), and
 * `infra/file-processing/p05-lab-engine-client.mjs` runs inside the disposable
 * test container. They exchange only one-use-ticketed JSON files through a
 * shared directory; the runner never gets a Docker socket, the controller never
 * gets DB credentials, and the launcher itself starts each engine container
 * with `--network none`, `--read-only`, `--cap-drop ALL`, non-root uid.
 *
 * `lab.mjs engine -- <vitest args>` wires that path up: fresh ticket, host
 * controller as a child process, the exchange directory mounted into the
 * container at the reviewed absolute path, and the exact four opt-in flags.
 */
const ENGINE_EXCHANGE_PARENT = resolve(root, 'node_modules/.cache/p05-engine-jobs');
const ENGINE_DESCRIPTOR = resolve(process.env['FIXLEVELUP_LAB_ENGINE_DESCRIPTOR']
  ?? resolve(root, 'node_modules/.cache/p0304cde/engines-20261121T2315155122Z/worker-fixture-backport-v1.json'));

function engineFixtureFile() {
  if (!existsSync(ENGINE_DESCRIPTOR)) { throw new Error('Reviewed engine descriptor is missing'); }
  const bytes = readFileSync(ENGINE_DESCRIPTOR);
  const descriptor = JSON.parse(bytes.toString('utf8'));
  const path = resolve(cacheRoot, 'engine-fixture.json');
  writeFileSync(path, `${JSON.stringify(descriptor, null, 2)}\n`, { mode: 0o600 });
  return { path, descriptorSha256: createHash('sha256').update(bytes).digest('hex') };
}

async function engineRun(argv) {
  const state = requireState();
  const separator = argv.indexOf('--');
  const flags = separator === -1 ? argv : argv.slice(0, separator);
  const args = separator === -1 ? [] : argv.slice(separator + 1);
  if (args.length === 0) { fail('engine requires vitest arguments after --'); }
  if (containerState(state.pg) === 'missing') { fail('lab PostgreSQL is not running; run `up` first'); }
  if (containerState(garageName(state)) === 'missing') {
    fail('the reviewed engine path needs the isolated Garage; run `node infra/p05-lab/lab.mjs garage up`');
  }
  const image = s3Image({ rebuild: flags.includes('--rebuild') });
  const ticket = hex(16);
  // The reviewed host controller OWNS ticket-directory creation: it requires
  // `FIXLEVELUP_LAB_ENGINE_EXCHANGE` to be the PARENT (`.../p05-engine-jobs`,
  // basename-checked) and then does `mkdir(join(owner, ticket))` itself, which
  // fails on EEXIST. So: pass the parent, never pre-create the ticket dir.
  // Only this ticket's own directory is cleaned up afterwards; the shared parent
  // (and any other agent's ticket) is never touched.
  const exchange = ENGINE_EXCHANGE_PARENT;
  // The host controller owns the one-use ticket directory, but its validated
  // parent must exist before its realpath check. Create only this shared cache
  // parent; never pre-create or clean another ticket's directory.
  mkdirSync(exchange, { recursive: true, mode: 0o700 });
  const fixture = engineFixtureFile();
  const database = `fixlevelup_p05_s3tlab_${hex(6)}`;
  // Same opt-in contract as `s3test`: flags are validated against the lab's
  // running services BEFORE the controller or any container starts.
  const optIn = optInEnv(state, flags);
  const oldBinary = oldBinaryMount(flags);
  process.stdout.write(`p05-lab: engine ticket ${ticket} (image ${image.imageId})\n`);
  return await startEngineController(state, { ticket, exchange, fixture: fixture.path, descriptorSha256: fixture.descriptorSha256,
    database, image, args, optIn, oldBinary });
}

async function startEngineController(state, { ticket, exchange, fixture, descriptorSha256, database, image, args, optIn, oldBinary }) {
  const controller = spawn('node', ['infra/file-processing/p05-lab-engine-host.mjs'], {
    cwd: root,
    env: { ...process.env, FIXLEVELUP_LAB_ENGINE_TICKET: ticket, FIXLEVELUP_LAB_ENGINE_EXCHANGE: exchange,
      FIXLEVELUP_LAB_ENGINE_DESCRIPTOR: ENGINE_DESCRIPTOR, FIXLEVELUP_LAB_ENGINE_DESCRIPTOR_SHA256: descriptorSha256 },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  const created = new Set();
  controller.stdout.on('data', (chunk) => {
    stdout += chunk.toString('utf8');
    for (const match of chunk.toString('utf8').matchAll(/ENGINE_CONTAINER (fixlevelup-p0304cde-[a-z-]+-[0-9a-f-]{36})/g)) {
      created.add(match[1]);
    }
  });
  // Never swallow the controller's diagnostics: a refusal inside the reviewed
  // host script must be visible instead of surfacing as a bare deadline.
  controller.stderr.on('data', (chunk) => { process.stderr.write(chunk); });
  // Wait for ENGINE_READY (the controller publishes ready.json first). This wait
  // MUST be asynchronous: `stdout` is filled by a stream callback, so a blocking
  // sync sleep would keep the event loop busy forever and the loop could never
  // observe readiness.
  const deadline = Date.now() + 60_000;
  while (!stdout.includes('ENGINE_READY')) {
    if (controller.exitCode !== null) { throw new Error(`engine controller exited early (${String(controller.exitCode)})`); }
    if (Date.now() > deadline) { controller.kill(); throw new Error('engine controller readiness deadline exceeded'); }
    await delay(250);
  }
  process.stdout.write('p05-lab: engine controller ready\n');
  const script = [
    'set -u',
    'node infra/p05-lab/makedb.mjs > /tmp/p05lab-db.json || { echo "p05-lab: 024 database provisioning failed"; exit 90; }',
    'oid=$(node -e \'process.stdout.write(JSON.parse(require("node:fs").readFileSync("/tmp/p05lab-db.json","utf8")).oid)\')',
    'export FIXLEVELUP_LAB_DATABASE_OID="$oid"',
    'node infra/p05-lab/containerenv.mjs',
    '"$@"',
    'rc=$?',
    'node infra/p05-lab/makedb.mjs drop "$oid" || echo "p05-lab: DROP FAILED (addressed by oid)"',
    'exit "$rc"',
  ].join('\n');
  let result;
  try {
    result = run('docker', ['run', '--rm', '--network', `container:${state.pg}`,
      '--mount', `type=bind,source=${ENGINE_EXCHANGE_PARENT},target=/p0305/node_modules/.cache/p05-engine-jobs`,
      '--env-file', state.envFile,
      '-e', `FIXLEVELUP_LAB_DATABASE=${database}`,
      '-e', 'FIXLEVELUP_LAB_MIGRATION_LIMIT=24',
      '-e', `FIXLEVELUP_LAB_ENGINE_TICKET=${ticket}`,
      '-e', `FIXLEVELUP_FILE_PROCESSING_FIXTURE=/p05lab-engine-fixture.json`,
      '-e', 'FIXLEVELUP_FILE_PROCESSING_TESTS=1',
      '-e', 'FIXLEVELUP_STORAGE_S3_TESTS=1',
      '-e', 'FIXLEVELUP_FILE_RESTORE_TESTS=1',
      ...optIn.flatMap((entry) => ['-e', entry]),
      ...oldBinary.args,
      ...oldBinary.env.flatMap((entry) => ['-e', entry]),
      '--mount', `type=bind,source=${fixture},target=/p05lab-engine-fixture.json,readonly`,
      '-w', '/workspace', image.imageId, 'sh', '-lc', script, 'p05lab',
      'corepack', 'pnpm', 'exec', 'vitest', 'run', ...args], { stdio: 'inherit' });
  } finally {
    // `run(...)` above is a SYNCHRONOUS spawn, so the controller's stdout 'data'
    // callbacks cannot run while it is in flight: the buffered chunks are only
    // delivered once the event loop resumes. Wait one turn BEFORE reaping,
    // otherwise `created` is empty, the wrapper reports "reaped: 0" and exited
    // engine containers are left behind. Kill the controller after the flush so
    // no diagnostic output is lost.
    await delay(400);
    for (const match of stdout.matchAll(/ENGINE_CONTAINER (fixlevelup-p0304cde-[a-z-]+-[0-9a-f-]{36})/g)) {
      created.add(match[1]);
    }
    controller.kill();
    for (const name of created) {
      if (containerState(name) !== 'missing') { docker(['rm', '--force', name], { allowFailure: true }); }
    }
    removeTree(resolve(exchange, ticket));
    process.stdout.write(`p05-lab: engine containers reaped: ${String(created.size)}\n`);
  }
  process.exit(result.status ?? 1);
}

/* ---------------- isolated file ledger + trust floor (P03-04 D) ------------ */

/**
 * Fresh, reviewed ledger and floor PostgreSQL instances in the SAME private
 * network namespace as the lab PostgreSQL (owner decision 25.11.2026):
 * `postgres:18.7-bookworm` at the reviewed digest, tmpfs data (no volumes, in
 * particular NOT the historical `fixlevelup-test-file-ledger-data` /
 * `fixlevelup-test-file-floor-data` volumes), no host ports, and the reviewed
 * `infra/file-ledger/*.sql` applied byte-for-byte with `\getenv` secrets.
 *
 * Ports 55433 (ledger) and 55434 (floor) are loopback-only inside the namespace,
 * exactly the endpoints the reviewed fixtures pin; the runner sees them without
 * any published port.
 */
const LEDGER_SQL = ['ledger.sql', 'writer-roles.sql', 'ledger-writers.sql'];
const FLOOR_SQL = ['floor.sql'];
const LEDGER_DB = 'fixlevelup_file_ledger';
const FLOOR_DB = 'fixlevelup_file_floor';
const LEDGER_KEYS = ['FILE_LEDGER_ADMIN_PASSWORD', 'FILE_LEDGER_WRITER_PASSWORD',
  'FILE_LEDGER_WRITER_NEXT_PASSWORD', 'FILE_LEDGER_SIGNER_PASSWORD', 'FILE_LEDGER_OPERATOR_PASSWORD',
  'FILE_FLOOR_ADMIN_PASSWORD', 'FILE_FLOOR_VERIFIER_PASSWORD', 'FILE_FLOOR_OPERATOR_PASSWORD'];

function ledgerName(state) { return `p05lab-ledger-${state.runId}`; }
function floorName(state) { return `p05lab-floor-${state.runId}`; }

function startLedgerService(state, { name, database, adminRole, port, sql, label, adminKey }) {
  if (containerState(name) !== 'missing') { return name; }
  if (containerState(state.pg) === 'missing') { fail('lab PostgreSQL is not running; run `up` first'); }
  const sqlDir = resolve(root, 'infra/file-ledger');
  const adminPassword = state.env[adminKey];
  if (!/^[a-f0-9]{64}$/.test(adminPassword ?? '')) { throw new Error(`Missing ${adminKey}`); }
  docker(['run', '--detach', '--name', name,
    '--label', 'dsh.owner=pg-lab', '--label', 'dsh.task=task-1',
    `--label`, `dsh.purpose=p05-lab-${label}`, '--label', 'dsh.ephemeral=true',
    '--network', `container:${state.pg}`,
    '--tmpfs', '/var/lib/postgresql:rw,size=512m',
    '--env', `POSTGRES_DB=${database}`, '--env', `POSTGRES_USER=${adminRole}`,
    '--env', `POSTGRES_PASSWORD=${adminPassword}`,
    '--env', 'POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256',
    '--mount', `type=bind,source=${sqlDir},target=/p05lab-sql,readonly`,
    PG_IMAGE,
    'postgres', '-c', 'listen_addresses=127.0.0.1', '-c', `port=${String(port)}`,
    '-c', 'fsync=on', '-c', 'synchronous_commit=on', '-c', 'full_page_writes=on']);
  const deadline = Date.now() + 90_000;
  for (;;) {
    const ready = docker(['exec', name, 'pg_isready', '-h', '127.0.0.1', '-p', String(port), '-U', adminRole],
      { allowFailure: true });
    if (ready.status === 0) { break; }
    if (Date.now() > deadline) { throw new Error(`lab ${label} readiness deadline exceeded`); }
    sleepSync(500);
  }
  // Apply the reviewed SQL exactly as the reviewed compose does at init time.
  // `PGPASSWORD` is required: the container is scram-auth, so psql cannot use
  // peer auth; the reviewed scripts read the remaining secrets via `\getenv`.
  const secretEnv = ['-e', `PGPASSWORD=${adminPassword}`,
    ...LEDGER_KEYS.flatMap((key) => ['-e', `${key}=${state.env[`LAB_${key}`] ?? ''}`])];
  for (const file of sql) {
    const applied = docker(['exec', ...secretEnv, name, 'psql', '-h', '127.0.0.1', '-p', String(port),
      '-U', adminRole, '-d', database, '-X', '-v', 'ON_ERROR_STOP=1', '-f', `/p05lab-sql/${file}`],
    { allowFailure: true });
    if (applied.status !== 0) {
      process.stderr.write(`${String(applied.stderr ?? '')}\n`);
      throw new Error(`lab ${label} init script failed: ${file} (exit ${String(applied.status)})`);
    }
  }
  return name;
}

function ledgerUp() {
  const state = requireState();
  for (const key of LEDGER_KEYS) {
    if (!/^[a-f0-9]{64}$/.test(state.env[`LAB_${key}`] ?? '')) { state.env[`LAB_${key}`] = hex(); }
  }
  writeLabEnv(state);
  const ledger = startLedgerService(state, { name: ledgerName(state), database: LEDGER_DB,
    adminRole: 'file_ledger_admin', port: 55433, sql: LEDGER_SQL, label: 'ledger',
    adminKey: 'LAB_FILE_LEDGER_ADMIN_PASSWORD' });
  const floor = startLedgerService(state, { name: floorName(state), database: FLOOR_DB,
    adminRole: 'file_floor_admin', port: 55434, sql: FLOOR_SQL, label: 'floor',
    adminKey: 'LAB_FILE_FLOOR_ADMIN_PASSWORD' });
  process.stdout.write(`p05-lab: ${ledger} (127.0.0.1:55433/${LEDGER_DB}) and `
    + `${floor} (127.0.0.1:55434/${FLOOR_DB}) ready inside the lab namespace\n`);
}

function ledgerDown() {
  const state = requireState();
  for (const name of [ledgerName(state), floorName(state)]) {
    if (containerState(name) === 'missing') { continue; }
    docker(['stop', '--time', '20', name], { allowFailure: true });
    docker(['rm', name], { allowFailure: true });
    process.stdout.write(`p05-lab: removed ${name}\n`);
  }
}

function ledgerStatus() {
  const state = requireState();
  for (const name of [ledgerName(state), floorName(state)]) {
    process.stdout.write(`${name}\t${containerState(name)}\n`);
  }
}

/* -------------------------------- commands -------------------------------- */

function down({ quiet = false } = {}) {
  const state = loadState();
  if (state === undefined) {
    if (quiet !== true) { process.stdout.write('p05-lab: nothing to stop\n'); }
    return;
  }
  for (const name of [state.runner, ledgerName(state), floorName(state), garageName(state), state.pg].filter(Boolean)) {
    if (containerState(name) === 'missing') { continue; }
    docker(['stop', '--time', '20', name], { allowFailure: true });
    docker(['rm', name], { allowFailure: true });
    if (quiet !== true) { process.stdout.write(`p05-lab: removed ${name}\n`); }
  }
  rmSync(statePath, { force: true });
  if (quiet !== true) { process.stdout.write('p05-lab: stopped (volumes untouched; there are none)\n'); }
}

function status() {
  const state = loadState();
  if (state === undefined) { process.stdout.write('p05-lab: no lab\n'); return; }
  const lines = [state.pg, state.runner].filter(Boolean).map((name) => `${name}\t${containerState(name)}`);
  process.stdout.write(`${lines.join('\n')}\n`);
  if (state.summary !== undefined) {
    process.stdout.write(`db=${state.summary.database} oid=${String(state.summary.databaseOid)} `
      + `migrations=${String(state.summary.migrations)} last=${state.summary.lastMigration} `
      + `control=${state.summary.controlDatabase}\n`);
  }
}

function focusedRun(files) {
  if (files.length === 0) { fail('run requires at least one test file'); }
  const state = requireState();
  const result = runnerExec(state, ['sh', '-lc',
    `corepack pnpm vitest run --reporter=verbose ${files.map((file) => JSON.stringify(file)).join(' ')}`]);
  process.exit(result.status ?? 1);
}

async function main(argv) {
  const [command, ...rest] = argv;
  switch (command) {
    case 'freeze': {
      const frozen = freezeTree();
      process.stdout.write(`p05-lab: frozen tree ${frozen.staging} (${frozen.manifest.treeId})\n`);
      return;
    }
    case 'build': {
      buildImage({ fresh: rest.includes('--fresh') });
      return;
    }
    case 'up': {
      up({ fresh: rest.includes('--fresh'), image: rest.includes('--image=s3') ? 's3' : 'gateway' });
      return;
    }
    case 'down': { down(); return; }
    case 'status': { status(); return; }
    case 's3measure': { s3measure(); return; }
    case 's3test': { s3test(rest); return; }
    case 's3run': { s3run(rest); return; }
    case 'ledger': {
      const action = rest[0];
      if (action === 'up') { ledgerUp(); return; }
      if (action === 'down') { ledgerDown(); return; }
      if (action === 'status') { ledgerStatus(); return; }
      fail('ledger requires up|down|status');
      return;
    }
    case 'garage': {
      const action = rest[0];
      if (action === 'up') { garageUp(); return; }
      if (action === 'down') { garageDown(); return; }
      if (action === 'status') {
        const state = requireState();
        process.stdout.write(`${garageName(state)}\t${containerState(garageName(state))}\n`);
        return;
      }
      fail('garage requires up|down|status');
      return;
    }
    case 'engine': { await engineRun(rest); return; }
    case 's3image': { s3Image({ rebuild: rest.includes('--rebuild') }); return; }
    case 'provision': {
      // Re-runs attestation/provisioning on an already-started lab.
      const state = requireState();
      const attest = runnerCapture(state, ['node', 'infra/p05-lab/attest.mjs']);
      if (attest.status === 0) {
        process.stdout.write('p05-lab: existing provisioning attested, nothing created\n');
      } else {
        const result = runnerExec(state, ['node', 'infra/p05-lab/provision.mjs']);
        if (result.status !== 0) { fail(`lab provisioning failed (exit ${String(result.status)})`); }
      }
      const summary = JSON.parse(runnerCapture(state, ['node', 'infra/p05-lab/attest.mjs']).stdout.trim().split('\n').at(-1));
      state.summary = summary;
      state.env.FIXLEVELUP_LAB_DATABASE_OID = String(summary.databaseOid);
      writeLabEnv(state);
      saveState(state);
      process.stdout.write(`p05-lab: ready — db ${summary.database} (oid ${String(summary.databaseOid)}), `
        + `${String(summary.migrations)} migrations, last ${summary.lastMigration}, control ${summary.controlDatabase}\n`);
      return;
    }
    case 'run': { focusedRun(rest); return; }
    case 'exec': {
      const state = requireState();
      const result = runnerExec(state, rest);
      process.exit(result.status ?? 1);
      return;
    }
    case 'psql': {
      const state = requireState();
      const result = runnerExec(state, ['sh', '-lc',
        'PGPASSWORD="$FIXLEVELUP_LAB_FIXTURE_ADMIN_PASSWORD" psql -h 127.0.0.1 -p 55432 -U postgres -d postgres -X']);
      process.exit(result.status ?? 1);
      return;
    }
    default:
      fail(`unknown command ${String(command)}; see infra/p05-lab/README.md`);
  }
}

await main(process.argv.slice(2));
