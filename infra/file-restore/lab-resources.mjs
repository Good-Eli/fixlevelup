import { createHash, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { resolve, sep } from 'node:path';

/** P05-02 S4: hermetic lab branch for the file-restore fixtures.
 *
 * This module is the ONLY place that knows how to reach a real, non-Docker
 * restore contour. It is inert unless the lab opt-in flag is set, and it fails
 * closed on anything it cannot prove:
 *
 *  - fixed absolute tool paths `/opt/p05-lab/bin/{pg_dump,pg_restore,psql,garage}`
 *    with the shared library directory `/opt/p05-lab/lib` on LD_LIBRARY_PATH;
 *  - only the pinned Garage client config (RPC secret file) and expected
 *    loopback node are passed to its CLI; no PostgreSQL or admin credentials;
 *  - every PostgreSQL tool invocation goes to host loopback 55432 as `-U postgres`
 *    with the secret from `FIXLEVELUP_LAB_FIXTURE_ADMIN_PASSWORD` and the exact
 *    session-run `application_name`, so a wrong cluster/role/version is refused;
 *  - the cluster is attested (cluster_name, exact PostgreSQL 18.7, loopback
 *    endpoint, run marker) once per process BEFORE any operation, using the real
 *    `psql` binary, and every tool version is checked to be 18.7;
 *  - only the exact reviewed control/source/destination database names and the
 *    reviewed bucket shapes are accepted.
 *
 * No Docker socket, no `docker cp`, no dev `.env` read, no invented digests: the
 * archive bytes are produced and consumed at their own validated local paths.
 */

export const LAB_BIN = '/opt/p05-lab/bin';
export const LAB_LIB = '/opt/p05-lab/lib';
export const LAB_GARAGE_CONFIG = '/opt/p05-lab/garage-client.toml';
const LAB_GARAGE_NODE = '/opt/p05-lab/garage-node.txt';
export const LAB_HOST = '127.0.0.1';
export const LAB_PORT = 55432;
export const LAB_SERVER_VERSION = '18.7';
export const LAB_SERVER_VERSION_NUM = '180007';

const SYNTHETIC_FLAG = 'FIXLEVELUP_SYNTHETIC_ORCHESTRATOR';
const ADMIN_PASSWORD_ENV = 'FIXLEVELUP_LAB_FIXTURE_ADMIN_PASSWORD';
const CLUSTER_ENV = 'FIXLEVELUP_CLUSTER_NAME';
const RUN_ID_ENV = 'FIXLEVELUP_SESSION_RUN_ID';
const CLUSTER = /^fixlevelup_p05s4_lab_[a-z0-9_]{1,40}$/;
const RUN_ID = /^[a-f0-9]{12}$/;
const HEX64 = /^[a-f0-9]{64}$/;
const CONTROL_DATABASE = 'postgres';
const SOURCE_DATABASE = /^fixlevelup_legal_test_[a-f0-9]{24}$/;
const DESTINATION_DATABASE = /^fixlevelup_file_restore_[a-f0-9]{24}$/;
const BUCKET = /^fixlevelup-restore-[a-f0-9]{24}$/;
const NAMESPACED_BUCKET = /^p0304-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const TABLE = /^[a-z][a-z_]+$/;

function stop(stage) { throw new Error(`Synthetic lab restore failed: ${stage}`); }

/** True only under the explicit lab opt-in. */
export function labMode() {
  return process.env[SYNTHETIC_FLAG] === '1';
}

function runId() {
  const value = process.env[RUN_ID_ENV] ?? '';
  if (!RUN_ID.test(value)) { stop('session-run-id'); }
  return value;
}

/** Exact session-run marker used as `application_name` for every tool call. */
export function labApplicationName() {
  return `fixlevelup-p05s4-${runId()}`;
}

function clusterName() {
  const value = process.env[CLUSTER_ENV] ?? '';
  if (!CLUSTER.test(value)) { stop('cluster-name'); }
  return value;
}

function adminPassword() {
  const value = process.env[ADMIN_PASSWORD_ENV] ?? '';
  if (!HEX64.test(value)) { stop('admin-credential'); }
  return value;
}

function tool(name) {
  const path = `${LAB_BIN}/${name}`;
  if (!existsSync(path)) { stop(`tool-missing:${name}`); }
  const status = statSync(path);
  if (!status.isFile() || status.size < 1) { stop(`tool-invalid:${name}`); }
  return path;
}

/** Environment for a tool call: pinned libs, admin secret, run marker, loopback. */
function toolEnv(extra = {}) {
  return {
    LANG: 'C.UTF-8',
    LD_LIBRARY_PATH: LAB_LIB,
    PGPASSWORD: adminPassword(),
    PGHOST: LAB_HOST,
    PGPORT: String(LAB_PORT),
    PGUSER: 'postgres',
    PGDATABASE: CONTROL_DATABASE,
    PGAPPNAME: labApplicationName(),
    PGCONNECT_TIMEOUT: '5',
    PGTZ: 'UTC',
    ...extra,
  };
}

function run(stage, executable, argv, { maxBuffer = 2_097_152, env = toolEnv() } = {}) {
  const result = spawnSync(executable, argv, {
    env, timeout: 45_000, maxBuffer, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error || result.status !== 0 || !Buffer.isBuffer(result.stdout)) { stop(stage); }
  return result.stdout;
}

const versions = new Set();
/** Every PostgreSQL tool must be exactly 18.7 — the same generation as the server. */
function requireToolVersion(name) {
  if (versions.has(name)) { return; }
  const output = run(`tool-version:${name}`, tool(name), ['--version']).toString();
  const match = /(\d+)\.(\d+)/.exec(output);
  if (match === null || `${match[1]}.${match[2]}` !== LAB_SERVER_VERSION) { stop(`tool-version:${name}`); }
  versions.add(name);
}

/** Garage is a separate product: the dev branch pins image tag v2.5.0, so the
 * lab binary must be the same 2.5 generation (never the PostgreSQL version). */
const GARAGE_VERSION = '2.5';
function requireGarageVersion() {
  if (versions.has('garage')) { return; }
  const output = run('tool-version:garage', tool('garage'), ['--version'],
    { env: { LANG: 'C.UTF-8', LD_LIBRARY_PATH: LAB_LIB } }).toString();
  const match = /(\d+)\.(\d+)/.exec(output);
  if (match === null || `${match[1]}.${match[2]}` !== GARAGE_VERSION) { stop('tool-version:garage'); }
  versions.add('garage');
}

/** SHA-256 of a pinned tool/config file; exposed for the run report only. */
function digest(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

let attested = false;
/**
 * Attests the lab cluster ONCE per process with the real `psql`: exact
 * cluster_name, exact PostgreSQL 18.7, loopback endpoint and the session-run
 * marker. Any deviation refuses every later operation.
 */
export function attestLabCluster() {
  if (attested) { return; }
  // Validate the whole binding BEFORE any process is spawned, so a
  // misconfigured run is reported precisely and never starts a tool.
  const expectedCluster = clusterName();
  const expectedApplication = labApplicationName();
  adminPassword();
  requireToolVersion('psql');
  const query = `SELECT current_database()='postgres' AND current_user='postgres' AND session_user=current_user
    AND NOT EXISTS (SELECT FROM pg_database WHERE datname='fixlevelup_dev')
    AND current_setting('cluster_name') = '${expectedCluster}'
    AND current_setting('server_version_num') = '${LAB_SERVER_VERSION_NUM}'
    AND host(inet_server_addr()) = '${LAB_HOST}'
    AND inet_server_port() = ${LAB_PORT}
    AND current_setting('application_name') = '${expectedApplication}'`;
  const output = run('cluster-attestation', tool('psql'),
    ['-X', '-A', '-t', '--no-password', '-d', CONTROL_DATABASE, '-c', query]).toString().trim();
  if (output !== 't') { stop('cluster-attestation'); }
  attested = true;
}

/** Reviewed tool/config digests, recorded by the lead; no local pin is invented. */
export function labToolEvidence() {
  attestLabCluster();
  return Object.freeze({
    applicationName: labApplicationName(),
    cluster: clusterName(),
    garageConfig: LAB_GARAGE_CONFIG,
    digests: Object.freeze({
      pg_dump: digest(tool('pg_dump')),
      pg_restore: digest(tool('pg_restore')),
      psql: digest(tool('psql')),
      garage: digest(tool('garage')),
      'garage-client.toml': digest(LAB_GARAGE_CONFIG),
      'garage-node.txt': digest(LAB_GARAGE_NODE),
    }),
  });
}

/** Lab maintenance/scoped credentials. Never reads a dev `.env` file. */
export function labDbOptions(database, role) {
  // Cheap allowlist/credential validation first: a wrong target is refused
  // before the cluster attestation spawns any tool.
  if (role === 'maintenance') {
    if (database !== CONTROL_DATABASE) { stop('database-allowlist'); }
    const password = adminPassword();
    attestLabCluster();
    return { host: LAB_HOST, port: LAB_PORT, database: CONTROL_DATABASE, user: 'postgres', password,
      application_name: labApplicationName(), connectionTimeoutMillis: 5_000, statement_timeout: 15_000 };
  }
  if ((role !== 'migrator' && role !== 'runtime')
    || (!SOURCE_DATABASE.test(database) && !DESTINATION_DATABASE.test(database))) { stop('database-allowlist'); }
  const password = process.env[`FIXLEVELUP_${role.toUpperCase()}_PASSWORD`] ?? '';
  if (!HEX64.test(password)) { stop(`${role}-credential`); }
  attestLabCluster();
  return { host: LAB_HOST, port: LAB_PORT, database, user: `fixlevelup_${role}`, password,
    application_name: labApplicationName(), connectionTimeoutMillis: 5_000, statement_timeout: 15_000 };
}

export function labGarageCli(stage, ...args) {
  if (!labMode() || process.env.FIXLEVELUP_STORAGE_S3_TESTS !== '1') { stop('garage-opt-in'); }
  attestLabCluster();
  requireGarageVersion();
  const pinned = readFileSync(LAB_GARAGE_NODE, 'utf8').trimEnd();
  if (!/^[0-9a-f]{64}@127\.0\.0\.1:3901$/.test(pinned)) { stop('garage-node'); }
  return run(stage, tool('garage'), ['-c', LAB_GARAGE_CONFIG, '-h', pinned, ...args],
    { env: { LANG: 'C.UTF-8', LD_LIBRARY_PATH: LAB_LIB } }).toString();
}

/** Same bucket/credential proof as the dev branch, through the real Garage CLI. */
export function labGarageBucket(namespace) {
  if (namespace !== undefined && !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(namespace)) {
    stop('bucket-namespace');
  }
  const bucket = namespace === undefined ? `fixlevelup-restore-${randomBytes(12).toString('hex')}` : `p0304-${namespace}`;
  if (namespace === undefined ? !BUCKET.test(bucket) : !NAMESPACED_BUCKET.test(bucket)) { stop('bucket-name'); }
  if (labGarageCli('list-new-bucket', 'bucket', 'list').includes(bucket)) { stop('bucket-reuse'); }
  labGarageCli('new-bucket', 'bucket', 'create', bucket);
  const creds = (rw) => {
    const accessKeyId = `GK${randomBytes(12).toString('hex')}`;
    const secretAccessKey = randomBytes(32).toString('hex');
    labGarageCli('new-key', 'key', 'import', '--yes', '-n', `${bucket}-${rw ? 'rw' : 'ro'}`, accessKeyId, secretAccessKey);
    labGarageCli('new-bucket-grant', 'bucket', 'allow', '--read', ...(rw ? ['--write'] : []), '--key', accessKeyId, bucket);
    const info = JSON.parse(labGarageCli('key-check', 'json-api', 'GetKeyInfo', JSON.stringify({ id: accessKeyId, showSecretKey: false })));
    const grant = info.buckets?.[0];
    if (info.permissions?.createBucket !== false || info.buckets?.length !== 1 || !grant?.globalAliases?.includes(bucket)
      || grant.permissions.read !== true || grant.permissions.write !== rw || grant.permissions.owner !== false) { stop('bucket-grant'); }
    return { accessKeyId, secretAccessKey };
  };
  const target = { endpoint: `http://${LAB_HOST}:3900`, bucket, region: 'garage' };
  return { target, rw: creds(true), ro: creds(false) };
}

/** Every path a lab archive may touch must live inside the run's own directory. */
function insideDirectory(file, directory) {
  const realFile = realpathSync(file);
  const realDirectory = realpathSync(directory);
  if (realFile !== realDirectory && !realFile.startsWith(realDirectory + sep)) { stop('archive-path'); }
  return realFile;
}

function hash(path, maximum) {
  const status = statSync(path);
  if (!status.isFile() || status.size < 1 || status.size > maximum) { stop('artifact-bound'); }
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

/**
 * Lab archive pipeline: real `pg_dump`/`pg_restore` against loopback 55432 as
 * `postgres`, with the archive bytes kept at their own validated local paths
 * (no `docker cp`, no container copy, no fabricated digest). The TOC used for
 * the data restore is produced from the SAME validated local dump file.
 */
export function labNewArchives(source, destination, overlayTables, maxDumpBytes, directory) {
  // Allowlist first: a wrong source/destination or bound is refused before any
  // attestation process starts.
  if (!SOURCE_DATABASE.test(source) || !DESTINATION_DATABASE.test(destination)) { stop('archive-allowlist'); }
  if (!Number.isInteger(maxDumpBytes) || maxDumpBytes < 1 || maxDumpBytes > 268_435_456) { stop('archive-allowlist'); }
  if (!Array.isArray(overlayTables) || overlayTables.length > 24
    || overlayTables.some((table) => !TABLE.test(table))
    || new Set(overlayTables).size !== overlayTables.length) { stop('archive-allowlist'); }
  attestLabCluster();
  for (const name of ['pg_dump', 'pg_restore']) { requireToolVersion(name); }
  const base = resolve(directory, 'database.dump');
  const overlay = resolve(directory, 'authority.dump');
  const tocPath = resolve(directory, 'old-data.toc');

  const saveDump = (stage, path, flags) => {
    const data = run(stage, tool('pg_dump'),
      ['--format=custom', '--no-password', `--dbname=${source}`, ...flags],
      { maxBuffer: maxDumpBytes, env: toolEnv({ PGDATABASE: source }) });
    writeFileSync(path, data, { flag: 'wx', mode: 0o600 });
    return hash(path, maxDumpBytes);
  };
  return {
    directory,
    dump: () => saveDump('backup-dump', base, ['--exclude-table-data=foundation.file_runtime_epochs']),
    overlay: () => saveDump('authority-dump', overlay,
      ['--data-only', '--strict-names', ...overlayTables.map((table) => `--table=foundation.${table}`)]),
    manifest(value) { writeFileSync(resolve(directory, 'snapshot.json'), JSON.stringify(value), { flag: 'wx', mode: 0o600 }); },
    evidence(value) { writeFileSync(resolve(directory, 'evidence.json'), JSON.stringify(value), { flag: 'wx', mode: 0o600 }); },
    artifact(item, bytes) {
      if (!/^(quarantine|sanitized)\/[a-f0-9-]{36}\/[a-f0-9-]{36}$/.test(item.key)
        || item.key.split('/')[1] !== item.attemptId) { stop('artifact-id'); }
      writeFileSync(resolve(directory, `${item.kind}-${item.attemptId}.bin`), bytes, { flag: 'wx', mode: 0o600 });
    },
    object(item, maximum) {
      const file = resolve(directory, `${item.kind}-${item.attemptId}.bin`);
      const status = statSync(file);
      if (!status.isFile() || status.size !== item.bytes || status.size > maximum) { stop('object-bound'); }
      return readFileSync(file);
    },
    restore(expectedDump, expectedOverlay, createClosedDb, installClosedEpoch) {
      if (hash(base, maxDumpBytes) !== expectedDump || hash(overlay, maxDumpBytes) !== expectedOverlay) { stop('archive-digest'); }
      return (async () => {
        // Same contract as the dev branch: freshness is proven only by a
        // successful CREATE DATABASE of this run's exact random destination.
        await createClosedDb();
        insideDirectory(base, directory);
        insideDirectory(overlay, directory);
        const toc = run('archive-toc', tool('pg_restore'), ['--list', base],
          { maxBuffer: 8_388_608, env: toolEnv() }).toString();
        const removed = new Set();
        const filtered = toc.split('\n').map((line) => {
          const match = /^\d+; \d+ \d+ TABLE DATA foundation ([a-z_]+) \S+\r?$/.exec(line)?.[1];
          if (match === undefined || !overlayTables.includes(match)) { return line; }
          if (removed.has(match)) { stop('duplicate-overlay-table'); }
          removed.add(match);
          return `; ${line}`;
        }).join('\n');
        if (removed.size !== overlayTables.length || /TABLE DATA foundation file_runtime_epochs /.test(toc)) {
          stop('archive-toc-coverage');
        }
        writeFileSync(tocPath, filtered, { flag: 'wx', mode: 0o600 });
        const restore = (stage, ...args) => run(stage, tool('pg_restore'),
          ['--no-password', '--exit-on-error', '--single-transaction', `--dbname=${destination}`, ...args],
          { env: toolEnv({ PGDATABASE: destination }) });
        restore('pre-data', '--section=pre-data', base);
        restore('old-data', '--section=data', `--use-list=${tocPath}`, base);
        restore('overlay-data', '--data-only', overlay);
        restore('post-data-and-guards', '--section=post-data', base);
        await installClosedEpoch();
      })();
    },
    toolEvidence: labToolEvidence,
  };
}
