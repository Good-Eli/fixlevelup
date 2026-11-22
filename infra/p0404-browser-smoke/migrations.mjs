import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFile, readdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { host, pgPort } from './isolation.mjs';

// Public SHA-256 checksums pin the full Prisma 001–021 chain. They are not
// credentials and live in a standard checksum manifest, separate from code.
async function pinnedMigrations() {
  const manifest = await readFile(new URL('./SHA256SUMS', import.meta.url), 'utf8');
  const lines = manifest.replaceAll('\r\n', '\n').split('\n');
  if (lines.pop() !== '' || lines.length !== 21) { throw new Error('Invalid pinned migration manifest'); }
  return lines.map(line => {
    const match = /^([a-f0-9]{64}) {2}(\d{14}_[a-z0-9_]+)\/migration\.sql$/u.exec(line);
    if (!match || match[0] !== line) { throw new Error('Invalid pinned migration entry'); }
    return [match[2], match[1]];
  });
}
const migrationRoot = new URL('../../prisma/migrations/', import.meta.url);
const tooling = new URL('../../packages/database-tooling/', import.meta.url);
const requirePrisma = createRequire(new URL('package.json', tooling));

export async function deploy(migrator, database, password) {
  const pins = await pinnedMigrations();
  const dirs = (await readdir(migrationRoot, { withFileTypes: true })).filter(entry => entry.isDirectory()).map(entry => entry.name).sort();
  if (dirs.join() !== pins.map(([name]) => name).join()) { throw new Error('Unexpected pinned migration directory chain'); }
  const deployedDigests = [];
  for (const [name, checksum] of pins) {
    const sql = await readFile(new URL(`${name}/migration.sql`, migrationRoot), 'utf8');
    if (createHash('sha256').update(sql.replaceAll('\r\n', '\n')).digest('hex') !== checksum) {
      throw new Error('Unexpected pinned migration digest');
    }
    deployedDigests.push(createHash('sha256').update(sql).digest('hex'));
  }
  const result = spawnSync(process.execPath, [requirePrisma.resolve('prisma/build/index.js'), 'migrate', 'deploy', '--config', 'prisma.config.ts'], {
    cwd: tooling, stdio: 'ignore', timeout: 60_000,
    env: { PATH: process.env['PATH'], HOME: process.env['HOME'], NODE_ENV: 'production', CHECKPOINT_DISABLE: '1', PRISMA_HIDE_UPDATE_MESSAGE: '1',
      FIXLEVELUP_MIGRATION_URL: `postgresql://fixlevelup_migrator:${password}@${host}:${pgPort}/${database}?schema=foundation` },
  });
  if (result.status !== 0) { throw new Error('Prisma migrate deploy failed in disposable namespace'); }
  const history = await migrator.query(`SELECT migration_name,finished_at IS NOT NULL AND rolled_back_at IS NULL AS applied,
    checksum FROM foundation._prisma_migrations ORDER BY migration_name`);
  if (history.rows.length !== pins.length || history.rows.some((row, index) => !row.applied || row.migration_name !== pins[index][0]
    || ![deployedDigests[index], pins[index][1]].includes(row.checksum))) { throw new Error('Unexpected deployed migration history'); }
}
