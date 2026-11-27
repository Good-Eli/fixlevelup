import { randomBytes, createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { labDbOptions, labGarageBucket, labMode, labNewArchives } from './lab-resources.mjs';
export { labGarageCli } from './lab-resources.mjs';
export { restoreReviewedExpressions } from './reviewed-expressions.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const PG = 'fixlevelup-dev-postgres';
const GARAGE = 'fixlevelup-dev-s3';
const SRC = /^fixlevelup_legal_test_[a-f0-9]{24}$/;
const DST = /^fixlevelup_file_restore_[a-f0-9]{24}$/;
const bucketPattern = /^fixlevelup-restore-[a-f0-9]{24}$/;
const TABLE = /^[a-z][a-z_]+$/;
const KEY = /^(quarantine|sanitized)\/[a-f0-9-]{36}\/[a-f0-9-]{36}$/;
function stop(stage) { throw new Error(`Synthetic restore failed: ${stage}`); }
function opts() {
  if (process.env['FIXLEVELUP_FILE_RESTORE_TESTS'] !== '1' || process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] !== '1'
    || process.env['FIXLEVELUP_STORAGE_S3_TESTS'] !== '1') {stop('opt-in');}
}
function docker(stage, argv, { maxBuffer = 2_097_152 } = {}) {
  const r = spawnSync('docker', argv, { timeout: 45_000, maxBuffer, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  if (r.error || r.status !== 0 || !Buffer.isBuffer(r.stdout)) {stop(stage);}
  return r.stdout;
}
function requireImage(container, prefix) {
  const value = docker('container-check', ['inspect', '-f', '{{.State.Running}} {{.Config.Image}}', container]).toString().trim();
  if (!value.startsWith(`true ${prefix}`)) {stop('container-pin');}
}
function secret(file, name) {
  const text = readFileSync(join(root, file), 'utf8');
  const m = new RegExp(`^${name}=([a-f0-9]{64})\\r?$`, 'm').exec(text);
  if (!m?.[1]) {stop('credentials');}
  return m[1];
}
export function restoreDbOptions(database, role) {
  opts();
  // Lab branch: attested cluster, scoped lab credentials from the lab process
  // env only (never a dev `.env`), fixed loopback endpoint.
  if (labMode()) {return labDbOptions(database, role);}
  if (role === 'maintenance' && database === 'postgres') {return { host: '127.0.0.1', port: 55432, database,
    user: 'fixlevelup_dev', password: secret('infra/dev-postgres/.env', 'POSTGRES_PASSWORD') };}
  if ((!SRC.test(database) && !DST.test(database)) || (role !== 'migrator' && role !== 'runtime')) {stop('database-allowlist');}
  return { host: '127.0.0.1', port: 55432, database, user: `fixlevelup_${role}`,
    password: secret('packages/database-tooling/.env', `FIXLEVELUP_${role.toUpperCase()}_PASSWORD`),
    connectionTimeoutMillis: 5_000, statement_timeout: 15_000 };
}
export function freshGarageBucket(namespace) {
  opts();
  // Lab branch: real Garage CLI at the pinned path/config, no Docker socket.
  if (labMode()) {return labGarageBucket(namespace);}
  if (namespace !== undefined && !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(namespace)) {stop('bucket-namespace');}
  requireImage(GARAGE, 'dxflrs/garage:v2.5.0@sha256:677e5b758e4425a325b811c425c026bf35a4bf42f7ddbaa773de3f4fd779a5a5');
  const bucket = namespace === undefined ? `fixlevelup-restore-${randomBytes(12).toString('hex')}` : `p0304-${namespace}`;
  const cli = (stage, ...args) => docker(stage, ['exec', GARAGE, '/garage', ...args]).toString();
  if ((namespace === undefined && !bucketPattern.test(bucket)) || cli('list-new-bucket', 'bucket', 'list').includes(bucket)) {stop('bucket-reuse');}
  cli('new-bucket', 'bucket', 'create', bucket);
  const creds = (rw) => {
    const accessKeyId = `GK${randomBytes(12).toString('hex')}`;
    const secretAccessKey = randomBytes(32).toString('hex');
    cli('new-key', 'key', 'import', '--yes', '-n', `${bucket}-${rw ? 'rw' : 'ro'}`, accessKeyId, secretAccessKey);
    cli('new-bucket-grant', 'bucket', 'allow', '--read', ...(rw ? ['--write'] : []), '--key', accessKeyId, bucket);
    const info = JSON.parse(cli('key-check', 'json-api', 'GetKeyInfo', JSON.stringify({ id: accessKeyId, showSecretKey: false })));
    const grant = info.buckets?.[0];
    if (info.permissions?.createBucket !== false || info.buckets?.length !== 1 || !grant?.globalAliases?.includes(bucket)
      || grant.permissions.read !== true || grant.permissions.write !== rw || grant.permissions.owner !== false) {stop('bucket-grant');}
    return { accessKeyId, secretAccessKey };
  };
  const target = { endpoint: 'http://127.0.0.1:3900', bucket, region: 'garage' };
  return { target, rw: creds(true), ro: creds(false) };
}

function hash(file, maximum) {
  const s = statSync(file);
  if (!s.isFile() || s.size < 1 || s.size > maximum) {stop('artifact-bound');}
  return createHash('sha256').update(readFileSync(file)).digest('hex');
}
function shellPg(stage, tool, argv, maxBuffer) {
  return docker(stage, ['exec', PG, tool, '--username=fixlevelup_dev', ...argv], { maxBuffer });
}
export function newArchives(source, destination, overlayTables, maxDumpBytes) {
  opts();
  if (!SRC.test(source) || !DST.test(destination) || !Number.isInteger(maxDumpBytes) || maxDumpBytes < 1
    || maxDumpBytes > 268_435_456 || !Array.isArray(overlayTables) || overlayTables.length > 24
    || overlayTables.some(t => !TABLE.test(t)) || new Set(overlayTables).size !== overlayTables.length) {stop('archive-allowlist');}
  // Lab branch: real pg_dump/pg_restore/psql at the pinned paths against loopback
  // 55432. The exclusive temp directory is created here so every archive path is
  // owned by this run; there is no Docker copy and no container-side path.
  if (labMode()) {
    const work = join(root, 'backups');
    mkdirSync(work, { recursive: true });
    const labDirectory = mkdtempSync(join(work, 'p0304-file-restore-'));
    return labNewArchives(source, destination, overlayTables, maxDumpBytes, labDirectory);
  }
  requireImage(PG, 'postgres:18.7-bookworm@sha256:1757c628698dd1ca67ff7a5fc386bfd91040afc62a45484c346c788b0cbe5402');
  const work = join(root, 'backups');
  mkdirSync(work, { recursive: true });
  const directory = mkdtempSync(join(work, 'p0304-file-restore-'));
  const base = join(directory, 'database.dump');
  const overlay = join(directory, 'authority.dump');
  const tocPath = join(directory, 'old-data.toc');
  const temp = `/tmp/${destination}`;
  const baseOptions = ['--format=custom', '--no-password', `--dbname=${source}`];
  const fileFor = (item) => {
    if (!KEY.test(item.key) || item.key.split('/')[1] !== item.attemptId) {stop('artifact-id');}
    return join(directory, `${item.kind}-${item.attemptId}.bin`);
  };
  function saveDump(stage, path, flags) {
    const data = shellPg(stage, 'pg_dump', [...baseOptions, ...flags], maxDumpBytes);
    writeFileSync(path, data, { flag: 'wx', mode: 0o600 });
    return hash(path, maxDumpBytes);
  }
  return {
    directory,
    dump: () => saveDump('backup-dump', base, ['--exclude-table-data=foundation.file_runtime_epochs']),
    overlay: () => saveDump('authority-dump', overlay,
      ['--data-only', '--strict-names', ...overlayTables.map(t => `--table=foundation.${t}`)]),
    manifest(value) { writeFileSync(join(directory, 'snapshot.json'), JSON.stringify(value), { flag: 'wx', mode: 0o600 }); },
    evidence(value) { writeFileSync(join(directory, 'evidence.json'), JSON.stringify(value), { flag: 'wx', mode: 0o600 }); },
    artifact(item, bytes) { writeFileSync(fileFor(item), bytes, { flag: 'wx', mode: 0o600 }); },
    object(item, maximum) {
      const file = fileFor(item);
      const status = statSync(file);
      if (!status.isFile() || status.size !== item.bytes || status.size > maximum) {stop('object-bound');}
      return readFileSync(file);
    },
    restore(expectedDump, expectedOverlay, createClosedDb, installClosedEpoch) {
      if (hash(base, maxDumpBytes) !== expectedDump || hash(overlay, maxDumpBytes) !== expectedOverlay) {stop('archive-digest');}
      return (async () => {
        // CREATE TABLE is not used as a freshness signal. Only a successful CREATE DATABASE of a random exact name qualifies.
        await createClosedDb();
        const cp = (stage, from, to) => docker(stage, ['cp', from, `${PG}:${to}`]);
        cp('copy-old-archive', base, `${temp}.dump`);
        cp('copy-authority-archive', overlay, `${temp}.overlay.dump`);
        const verifyCopy = (name, expected) => {
          if (docker('container-archive-digest', ['exec', PG, 'sha256sum', name]).toString().split(' ')[0] !== expected) {stop('container-archive-digest');}
        };
        verifyCopy(`${temp}.dump`, expectedDump);
        verifyCopy(`${temp}.overlay.dump`, expectedOverlay);
        const toc = shellPg('archive-toc', 'pg_restore', ['--list', `${temp}.dump`]).toString();
        const removed = new Set();
        const filtered = toc.split('\n').map(line => {
          const match = /^\d+; \d+ \d+ TABLE DATA foundation ([a-z_]+) \S+\r?$/.exec(line)?.[1];
          if (match === undefined || !overlayTables.includes(match)) {return line;}
          if (removed.has(match)) {stop('duplicate-overlay-table');}
          removed.add(match);
          return `; ${line}`;
        }).join('\n');
        if (removed.size !== overlayTables.length || /TABLE DATA foundation file_runtime_epochs /.test(toc)) {stop('archive-toc-coverage');}
        writeFileSync(tocPath, filtered, { flag: 'wx', mode: 0o600 });
        cp('copy-toc', tocPath, `${temp}.toc`);
        const restore = (stage, ...args) => shellPg(stage, 'pg_restore',
          ['--no-password', '--exit-on-error', '--single-transaction', `--dbname=${destination}`, ...args]);
        restore('pre-data', '--section=pre-data', `${temp}.dump`);
        restore('old-data', '--section=data', `--use-list=${temp}.toc`, `${temp}.dump`);
        restore('overlay-data', '--data-only', `${temp}.overlay.dump`);
        restore('post-data-and-guards', '--section=post-data', `${temp}.dump`);
        await installClosedEpoch();
      })();
    },
  };
}