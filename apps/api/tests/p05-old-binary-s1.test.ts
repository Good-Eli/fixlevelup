/**
 * P05 plan §7 rollback floor: “прежний 7a60d4c + S1 не допускается”.
 *
 * Compile the detached old catalog entry and its import graph using the old API
 * tsconfig and the current repo's installed dependencies (including built
 * p03-contracts). pnpm links API-only dependencies at the workspace package,
 * not the root; link just those packages by absolute real path in the checkout
 * (junctions on Windows). No install, source patch, or Prisma stub is needed:
 * this graph does not import the generated client and the writer uses pg only.
 * The incremental tsc cache lives inside the ignored worktree. A pre-existing
 * clean checkout at the exact revision may be reused, but is never removed.
 *
 * This deliberately exercises the command boundary, not HTTP or authentication.
 * Both versions receive the same synthetic, already-authorized GeoContext on a
 * real runtime-role PoolClient. GeoRunner only inserts durable receipts, audit
 * and outbox rows after run resolves; the failing statement cannot reach that
 * boundary. No application mock, synthetic DML substitute, or migration bypass
 * is used for the negative command.
 */
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Client } from 'pg';
import type { PoolClient } from 'pg';
import { afterAll, beforeAll, expect, it, vi } from 'vitest';
import { catalogCommands } from '../src/settings/geography/catalog-commands.js';
import type { GeoCommand, GeoContext } from '../src/settings/geography/geo-contract.js';
import { configurationIntegration, createConfigurationFixture, createSyntheticCity } from './configuration-fixture.js';
import type { ConfigurationFixture } from './configuration-fixture.js';

const root = resolve(import.meta.dirname, '../../..');
const oldRevision = '7a60d4c5a84adeb2f6cbec6a0eb1b8723e104a62';
const oldTree = resolve(root, 'node_modules/.cache/p05-oldbin');
const oldApi = resolve(oldTree, 'apps/api');
const oldDependencies = ['@nestjs/common', '@fixlevelup/p03-contracts', 'pg', '@types/pg'];
const lockSql = 'SELECT pg_advisory_xact_lock(734305,1)';
const coverageDelete = /DELETE FROM foundation\.service_area_district_coverage\b/;
const guardMessage = 'GEO/CFG basis writes require the unified writer fence';

function git(args: string[], cwd = root): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8', timeout: 60_000 }).trim();
}

function assertOldCheckout(): void {
  if (!lstatSync(resolve(oldTree, '.git')).isFile()
    || realpathSync(git(['rev-parse', '--show-toplevel'], oldTree)) !== realpathSync(oldTree)
    || git(['rev-parse', 'HEAD'], oldTree) !== oldRevision) {
    throw new Error(`Expected the ${oldRevision} linked worktree at ${oldTree}`);
  }
}

function buildOldCatalog(): string {
  assertOldCheckout();
  if (git(['status', '--porcelain', '--untracked-files=no'], oldTree) !== '') {
    throw new Error('Refusing a modified old writer checkout');
  }
  for (const dep of oldDependencies) {
    const dependency = realpathSync(resolve(root, 'apps/api/node_modules', dep));
    const link = resolve(oldApi, 'node_modules', dep);
    mkdirSync(dirname(link), { recursive: true });
    if (!existsSync(link)) {
      symlinkSync(dependency, link, process.platform === 'win32' ? 'junction' : 'dir');
    }
    if (!lstatSync(link).isSymbolicLink() || realpathSync(link) !== dependency) {
      throw new Error(`Unexpected old dependency link: ${link}`);
    }
  }

  const config = resolve(oldApi, 'tsconfig.p05-oldbin.json');
  const tsc = [resolve(root, 'node_modules/typescript/bin/tsc'), '-p', config];
  const project = {
    extends: './tsconfig.build.json',
    compilerOptions: {
      outDir: './.p05-oldbin', incremental: true, noEmitOnError: true,
      tsBuildInfoFile: './.p05-oldbin/catalog.tsbuildinfo',
    },
    files: ['./src/settings/geography/catalog-commands.ts'],
    include: [],
  };
  writeFileSync(config, JSON.stringify(project));
  // Being under node_modules makes tsc classify imported worktree files as
  // external. Discover the local import graph and promote it to explicit roots
  // so tsc emits the dependencies as well as the catalog entry.
  const graph = execFileSync(process.execPath, [...tsc, '--listFilesOnly'], {
    cwd: oldTree, timeout: 60_000, encoding: 'utf8',
  });
  const files = graph.trim().split(/\r?\n/).map(path => relative(oldApi, path))
    .filter(path => /^src[/\\].*\.ts$/.test(path) && !isAbsolute(path));
  writeFileSync(config, JSON.stringify({ ...project, files }));
  execFileSync(process.execPath, tsc, { cwd: oldTree, timeout: 60_000, stdio: 'inherit' });
  return resolve(oldApi, '.p05-oldbin/settings/geography/catalog-commands.js');
}

async function importOldCoverage(compiled: string): Promise<Pick<GeoCommand, 'run'>> {
  const source = readFileSync(compiled, 'utf8');
  expect(source).toMatch(coverageDelete);
  expect(source).not.toMatch(/geo_cfg_fence|pg_advisory_xact_lock\(\s*734305\s*,\s*1\s*\)/);
  // Older city-primary operations already call the company lock, but the old
  // common wrapper must not fence every write (unlike the current module).
  expect(source).toMatch(/run: async \(ctx, target, body, expected\) => \{\s*const result = await spec\.run/);
  const url = pathToFileURL(compiled).href;
  const module: unknown = await import(/* @vite-ignore */ url);
  if (typeof module !== 'object' || module === null || !('catalogCommands' in module)) {
    throw new Error(`Missing old command registry at ${url}`);
  }
  const registry = module.catalogCommands;
  if (typeof registry !== 'object' || registry === null || !('areaCoverage' in registry)) {
    throw new Error(`Missing old areaCoverage at ${url}`);
  }
  const coverage = registry.areaCoverage;
  if (typeof coverage !== 'object' || coverage === null || !('run' in coverage) || typeof coverage.run !== 'function') {
    throw new Error(`Missing old areaCoverage.run at ${url}`);
  }
  return coverage as Pick<GeoCommand, 'run'>;
}

async function dropFixture(fixture: ConfigurationFixture): Promise<void> {
  await fixture.close();
  // The shared fixture's close() both ends its pools and drops the database it
  // created; this belt-and-braces drop is idempotent for the exact same name
  // (strict disposable pattern + IF EXISTS) in case close() did not reach it.
  const { database } = fixture;
  const { password } = fixture.migrator.options;
  if (!/^fixlevelup_configuration_test_[a-f0-9]{24}$/.test(database) || typeof password !== 'string') {
    throw new Error('Refusing to drop a non-fixture database');
  }
  const maintenance = new Client({ ...fixture.migrator.options, password, database: 'postgres' });
  await maintenance.connect();
  try {
    await maintenance.query(`DROP DATABASE IF EXISTS "${database}" WITH (FORCE)`);
  } finally {
    await maintenance.end();
  }
}

async function seedTarget(fixture: ConfigurationFixture) {
  const { id: cityId } = await createSyntheticCity(fixture);
  const districtId = randomUUID();
  const areaId = randomUUID();
  const versionId = randomUUID();
  const seed = await fixture.migrator.connect();
  try {
    await seed.query('BEGIN');
    await seed.query(lockSql);
    await seed.query(`INSERT INTO foundation.administrative_districts (id,city_id,code,name)
      VALUES ($1,$2,'rollback-district','Synthetic district')`, [districtId, cityId]);
    await seed.query(`INSERT INTO foundation.service_areas (id,city_id,code)
      VALUES ($1,$2,'rollback-area')`, [areaId, cityId]);
    await seed.query(`INSERT INTO foundation.service_area_versions (id,city_id,area_id,version,name,created_by)
      VALUES ($1,$2,$3,1,'Synthetic draft',$4)`, [versionId, cityId, areaId, fixture.reviewer]);
    await seed.query('COMMIT');
  } finally {
    await seed.query('ROLLBACK').finally(() => { seed.release(); });
  }
  return { target: { cityId, areaId, versionId }, districtId };
}

async function snapshot(fixture: ConfigurationFixture, versionId: string) {
  const result = await fixture.migrator.query<{
    row_version: number; draft: unknown; area: unknown; coverage: number;
    receipts: number; audit: number; outbox: number; geography_audit: number; geography_outbox: number;
  }>(`SELECT v.row_version, to_jsonb(v) AS draft, to_jsonb(a) AS area,
    (SELECT count(*)::int FROM foundation.service_area_district_coverage) AS coverage,
    (SELECT count(*)::int FROM foundation.geography_command_receipts) AS receipts,
    (SELECT count(*)::int FROM foundation.audit_logs) AS audit,
    (SELECT count(*)::int FROM foundation.outbox_events) AS outbox,
    (SELECT count(*)::int FROM foundation.audit_logs WHERE operation='GEOGRAPHY_CHANGED') AS geography_audit,
    (SELECT count(*)::int FROM foundation.outbox_events WHERE event_type='GEOGRAPHY_CHANGED') AS geography_outbox
    FROM foundation.service_area_versions v JOIN foundation.service_areas a ON a.id=v.area_id
    WHERE v.id=$1`, [versionId]);
  const row = result.rows[0];
  if (!row) { throw new Error('Missing synthetic command target'); }
  return row;
}

configurationIntegration('P05 §7 rollback floor: old binary against S1', () => {
  let createdOldTree = false;
  let fixture: ConfigurationFixture | undefined;
  let oldCoverage: Pick<GeoCommand, 'run'>;

  beforeAll(async () => {
    if (!existsSync(oldTree)) {
      git(['worktree', 'add', '--detach', oldTree, oldRevision]);
      createdOldTree = true;
    }
    oldCoverage = await importOldCoverage(buildOldCatalog());
    fixture = await createConfigurationFixture(); // Full 001–022 chain, no capBefore.
  }, 120_000);

  afterAll(async () => {
    try {
      if (fixture) { await dropFixture(fixture); }
    } finally {
      if (createdOldTree) {
        assertOldCheckout();
        // Do not give recursive removal access to the current packages through
        // Windows junctions; unlink only the four links created by this suite.
        for (const dep of oldDependencies) {
          const link = resolve(oldApi, 'node_modules', dep);
          if (existsSync(link) && lstatSync(link).isSymbolicLink()) { unlinkSync(link); }
        }
        git(['worktree', 'remove', '--force', oldTree]);
      }
    }
  }, 120_000);

  it('refuses the 7a60d4c areaCoverage before row mutation and accepts the fenced current command', { timeout: 60_000 }, async () => {
    if (!fixture) { throw new Error('Missing isolated S1 fixture'); }
    const f = fixture;
    const { target, districtId } = await seedTarget(f);
    const before = await snapshot(f, target.versionId);
    expect(before).toMatchObject({ coverage: 0, receipts: 0, geography_audit: 0, geography_outbox: 0 });

    // Prove the source of the failure is the active S1 BEFORE STATEMENT trigger,
    // rather than a row guard, an ACL failure, or an application error.
    const guard = await f.migrator.query<{ definition: string }>(`SELECT pg_get_triggerdef(oid) AS definition
      FROM pg_trigger WHERE tgrelid='foundation.service_area_district_coverage'::regclass
        AND tgname='service_area_district_coverage_geo_cfg_fence' AND tgenabled='O'`);
    expect(guard.rows[0]?.definition).toMatch(/BEFORE .*DELETE.* FOR EACH STATEMENT EXECUTE FUNCTION foundation\.geo_cfg_fence_guard\(\)/);

    const role = await f.migrator.query<{ id: string }>(`SELECT id FROM foundation.roles
      WHERE role_type='SYSTEM' AND code='ADMIN' AND status='ACTIVE'`);
    const roleId = role.rows[0]?.id;
    if (!roleId) { throw new Error('Missing fixture ADMIN role'); }
    const context = (client: PoolClient): GeoContext => ({
      client, staffId: f.reviewer, cityIds: null,
      principal: { kind: 'staff-web', staffId: f.reviewer, role: 'ADMIN', authVersion: 1 },
      role: { id: roleId, code: 'ADMIN', type: 'SYSTEM' },
      permissions: [], geoPermissions: [{ code: 'geography.manage', scope: 'GLOBAL' }],
    });
    const body = { districts: [{ districtId, relation: 'FULL' }] };

    const unfenced = await f.runtime.connect();
    try {
      await unfenced.query('BEGIN');
      // Observe the real queries without replacing pg execution. The 42501
      // must happen on the first DML, the coverage DELETE, even on an empty set.
      const trace = vi.spyOn(unfenced, 'query');
      try {
        const error: unknown = await oldCoverage.run(context(unfenced), target, body, before.row_version)
          .catch((failure: unknown) => failure);
        expect(error).toHaveProperty('code', '42501');
        expect(error).toHaveProperty('message', expect.stringContaining(guardMessage));
        expect(error).toHaveProperty('where', expect.stringContaining('foundation.geo_cfg_fence_guard()'));
        const statements = trace.mock.calls.map(([sql]) => sql);
        expect(statements.join('\n')).not.toMatch(/pg_advisory_xact_lock\b/);
        expect(statements.filter(sql => typeof sql === 'string' && /^\s*(DELETE|INSERT|UPDATE)\b/.test(sql)))
          .toEqual([expect.stringMatching(coverageDelete)]);
        expect(statements.at(-1)).toMatch(coverageDelete);
      } finally {
        trace.mockRestore();
      }
      await expect(unfenced.query('SELECT 1')).rejects.toMatchObject({ code: '25P02' });
    } finally {
      await unfenced.query('ROLLBACK').finally(() => { unfenced.release(); });
    }
    // Global counts in this disposable DB also catch unexpected receipts/audit/
    // outbox rows regardless of payload, while allowing the bootstrap's audit.
    expect(await snapshot(f, target.versionId)).toEqual(before);

    const fenced = await f.runtime.connect();
    try {
      await fenced.query('BEGIN');
      await fenced.query(lockSql);
      await expect(catalogCommands.areaCoverage.run(context(fenced), target, body, before.row_version))
        .resolves.toEqual({ id: target.versionId, version: before.row_version + 1 });
      await fenced.query('COMMIT');
    } finally {
      await fenced.query('ROLLBACK').finally(() => { fenced.release(); });
    }
    const written = await f.migrator.query(`SELECT city_id, area_version_id, district_id, relation, description
      FROM foundation.service_area_district_coverage`);
    expect(written.rowCount).toBe(1);
    expect(written.rows).toEqual([{
      city_id: target.cityId, area_version_id: target.versionId, district_id: districtId, relation: 'FULL', description: null,
    }]);
    expect((await snapshot(f, target.versionId)).row_version).toBe(before.row_version + 1);
  });
});
