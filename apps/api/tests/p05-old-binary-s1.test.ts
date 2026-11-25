/**
 * P05 plan §7 rollback floor: the exact old 7a60d4c catalog writer is usable
 * on 021 and cannot reach the same write on any expanded schema S1/S2/S3.
 *
 * The isolated launcher supplies a read-only `git archive` from the frozen
 * commit, verified against the exact archive digest before extraction. No
 * live Git directory, branch switch, old worktree, dependency install or
 * Prisma stub is needed. The command uses the real current pg driver and
 * compiled old source; it does not claim a whole old API/worker launch.
 * Each profile is migrated to a separate disposable database.
 *
 * This deliberately exercises the command boundary, not HTTP or authentication.
 * Both versions receive the same synthetic, already-authorized GeoContext on a
 * real runtime-role PoolClient. GeoRunner only inserts durable receipts, audit
 * and outbox rows after run resolves; the failing statement cannot reach that
 * boundary. No application mock, synthetic DML substitute, or migration bypass
 * is used for the negative command.
 */
import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { PoolClient } from 'pg';
import { afterAll, beforeAll, expect, it, vi } from 'vitest';
import { catalogCommands } from '../src/settings/geography/catalog-commands.js';
import type { GeoCommand, GeoContext } from '../src/settings/geography/geo-contract.js';
import { configurationIntegration, createConfigurationFixture, createSyntheticCity } from './configuration-fixture.js';
import type { ConfigurationFixture } from './configuration-fixture.js';

const root = resolve(import.meta.dirname, '../../..');
const oldRevision = '7a60d4c5a84adeb2f6cbec6a0eb1b8723e104a62';
const archivePath = process.env['FIXLEVELUP_P05_OLD_ARCHIVE'];
const archiveDigest = 'fdce94115f6b1af090e74b27104fa64805eb5288e9682c83fa78a75ade1cb3c7';
const archiveEnabled = process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1' && archivePath !== undefined;
const predecessorIntegration = archiveEnabled ? configurationIntegration : configurationIntegration.skip;
const oldDependencies = ['@nestjs/common', '@fixlevelup/p03-contracts', 'pg', '@types/pg'];
const lockSql = 'SELECT pg_advisory_xact_lock(734305,1)';
const coverageDelete = /DELETE FROM foundation\.service_area_district_coverage\b/;
const guardMessage = 'GEO/CFG basis writes require the unified writer fence';

function buildOldCatalog(oldTree: string): string {
  if (!archivePath || process.env['FIXLEVELUP_P05_OLD_ARCHIVE_SHA256'] !== archiveDigest
    || !lstatSync(archivePath).isFile() || createHash('sha256').update(readFileSync(archivePath)).digest('hex') !== archiveDigest) {
    throw new Error(`Historical writer archive does not match the pinned Git input ${oldRevision}`);
  }
  execFileSync('tar', ['-xf', archivePath, '-C', oldTree], { timeout: 30_000, stdio: 'inherit' });
  const oldApi = resolve(oldTree, 'apps/api');
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

/** Absent/present objects that pin the schema profile of a fixture. */
async function profileObjects(fixture: ConfigurationFixture): Promise<{
  requestSessions: string | null; formBrowserGroups: string | null; formThrottleBuckets: string | null;
}> {
  const result = await fixture.migrator.query<{
    request_sessions: string | null; form_browser_groups: string | null; form_throttle_buckets: string | null;
  }>(`SELECT to_regclass('foundation.request_sessions')::text AS request_sessions,
    to_regclass('foundation.form_browser_groups')::text AS form_browser_groups,
    to_regclass('foundation.form_throttle_buckets')::text AS form_throttle_buckets`);
  const row = result.rows[0];
  if (!row) { throw new Error('Missing schema profile row'); }
  return {
    requestSessions: row.request_sessions,
    formBrowserGroups: row.form_browser_groups,
    formThrottleBuckets: row.form_throttle_buckets,
  };
}

/**
 * One complete rollback-floor proof on a fixture of the given schema profile:
 * the old `7a60d4c` writer is refused on its first DML with 42501 by the active
 * BEFORE STATEMENT fence trigger and leaves zero receipts/audit/outbox rows,
 * while the current fenced writer commits exactly one coverage row.
 */
async function proveRollbackFloor(
  fixture: ConfigurationFixture,
  oldCoverage: Pick<GeoCommand, 'run'>,
  beforeExpansion = false,
): Promise<void> {
  const f = fixture;
  const { target, districtId } = await seedTarget(f);
  const before = await snapshot(f, target.versionId);
  expect(before).toMatchObject({ coverage: 0, receipts: 0, geography_audit: 0, geography_outbox: 0 });

  // Prove the source of the failure is the active S1 BEFORE STATEMENT trigger,
  // rather than a row guard, an ACL failure, or an application error.
  const guard = await f.migrator.query<{ definition: string }>(`SELECT pg_get_triggerdef(oid) AS definition
    FROM pg_trigger WHERE tgrelid='foundation.service_area_district_coverage'::regclass
      AND tgname='service_area_district_coverage_geo_cfg_fence' AND tgenabled='O'`);
  if (beforeExpansion) { expect(guard.rowCount).toBe(0); }
  else { expect(guard.rows[0]?.definition).toMatch(/BEFORE .*DELETE.* FOR EACH STATEMENT EXECUTE FUNCTION foundation\.geo_cfg_fence_guard\(\)/); }

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

  if (beforeExpansion) {
    const actor = await f.runtime.connect();
    try {
      await actor.query('BEGIN');
      await expect(oldCoverage.run(context(actor), target, body, before.row_version))
        .resolves.toEqual({ id: target.versionId, version: before.row_version + 1 });
      await actor.query('COMMIT');
    } finally { actor.release(true); }
    expect(await snapshot(f, target.versionId)).toMatchObject({ coverage: 1, row_version: before.row_version + 1 });
    expect((await f.migrator.query('SELECT district_id,relation FROM foundation.service_area_district_coverage WHERE area_version_id=$1',
      [target.versionId])).rows).toEqual([{ district_id: districtId, relation: 'FULL' }]);
    return;
  }
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
}

predecessorIntegration('P05 §7 rollback floor: old binary against S0–S3', () => {
  let oldTree: string | undefined;
  let s1: ConfigurationFixture | undefined;
  let s2: ConfigurationFixture | undefined;
  let oldCoverage: Pick<GeoCommand, 'run'>;

  beforeAll(async () => {
    const cache = resolve(root, 'node_modules/.cache');
    mkdirSync(cache, { recursive: true });
    oldTree = mkdtempSync(resolve(cache, 'p05-oldwriter-'));
    oldCoverage = await importOldCoverage(buildOldCatalog(oldTree));
    // Two independent disposable databases, one per reviewed profile:
    //  - S1: capped before 023, the exact 022 request-intake profile;
    //  - S2: the full 001…023 chain, the current reviewed profile.
    s1 = await createConfigurationFixture({ capBefore: '20261124000100_form_session_foundation' });
    s2 = await createConfigurationFixture({ capBefore: '20261125000100_request_intake_effects' });
  }, 300_000);

  afterAll(async () => {
    try {
      if (s1) { await dropFixture(s1); }
      if (s2) { await dropFixture(s2); }
    } finally {
      const cache = resolve(root, 'node_modules/.cache');
      if (oldTree && /^p05-oldwriter-[A-Za-z0-9]+$/.test(relative(cache, oldTree)) && realpathSync(oldTree) === oldTree) {
        // Unlink only the dependency links created by this run, then remove
        // the exact owned scratch directory. An input archive is never removed.
        for (const dep of oldDependencies) {
          const link = resolve(oldTree, 'apps/api/node_modules', dep);
          if (existsSync(link) && lstatSync(link).isSymbolicLink()) { unlinkSync(link); }
        }
        rmSync(oldTree, { recursive: true, force: true });
      }
    }
  }, 300_000);

  it('S0 (exact 021): the compiled old writer commits the same coverage change', { timeout: 120_000 }, async () => {
    const legacy = await createConfigurationFixture({ capBefore: '20261123000100_request_intake_foundation' });
    try { await proveRollbackFloor(legacy, oldCoverage, true); }
    finally { await legacy.close(); }
  });

  it('S1 (capped before 023): refuses the 7a60d4c areaCoverage before row mutation and accepts the fenced current command', { timeout: 120_000 }, async () => {
    if (!s1) { throw new Error('Missing isolated S1 fixture'); }
    // Profile compatibility: the capped chain really is the 022 profile — the
    // 022 anchor exists and none of the 023 objects does.
    expect(await profileObjects(s1)).toEqual({
      requestSessions: 'foundation.request_sessions', formBrowserGroups: null, formThrottleBuckets: null,
    });
    await proveRollbackFloor(s1, oldCoverage);
  });

  it('S2 (full 001…023): refuses the same old writer and accepts the fenced current command on the 023 profile', { timeout: 120_000 }, async () => {
    if (!s2) { throw new Error('Missing isolated S2 fixture'); }
    // Profile compatibility: the full chain really is the 023 profile, so the
    // fence proof below runs against the current reviewed schema, not a copy of
    // the capped one.
    expect(await profileObjects(s2)).toEqual({
      requestSessions: 'foundation.request_sessions',
      formBrowserGroups: 'foundation.form_browser_groups',
      formThrottleBuckets: 'foundation.form_throttle_buckets',
    });
    await proveRollbackFloor(s2, oldCoverage);
  });

  it('S3 (024): refuses the old coverage writer and preserves the current bridge writer', { timeout: 120_000 }, async () => {
    const expanded = await createConfigurationFixture();
    try {
      const { rows: [objects] } = await expanded.migrator.query<{ link: string }>(
        `SELECT to_regclass('foundation.request_files')::text AS link`);
      expect(objects?.link).toBe('foundation.request_files');
      await proveRollbackFloor(expanded, oldCoverage);
    } finally { await expanded.close(); }
  });
});
