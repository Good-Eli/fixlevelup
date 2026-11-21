import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Client, Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { CityContextError, readSingleCityContext, SINGLE_CITY_CONTEXT_SQL } from '../src/settings/geography/city-context.js';
import type { CityContextReader } from '../src/settings/geography/city-context.js';
import { bootstrapFirstAdmin } from '../src/staff/bootstrap.js';
import { migrateAuthFixture } from './auth-db-fixture.js';

const incomplete = { code: 'CONFIGURATION_INCOMPLETE' };

function fakeReader(rows: readonly Record<string, unknown>[], seen: string[] = []): CityContextReader {
  return { query: (sql: string) => { seen.push(sql); return Promise.resolve({ rows }); } };
}

describe('single city context read port', () => {
  it('returns only the trusted identity and asks the database once', async () => {
    const seen: string[] = [];
    const result = await readSingleCityContext(fakeReader([
      { cityId: 'city', cityVersionId: 'version', timezone: 'Etc/UTC', extra: 'must-not-leak' },
    ], seen));
    expect(result).toEqual({ cityId: 'city', cityVersionId: 'version', timezone: 'Etc/UTC' });
    expect(Object.keys(result)).toEqual(['cityId', 'cityVersionId', 'timezone']);
    expect(seen).toEqual([SINGLE_CITY_CONTEXT_SQL]);
  });

  it('refuses an absent, ambiguous or incomplete configuration', async () => {
    const cases: readonly (readonly Record<string, unknown>[])[] = [
      [],
      [{ cityId: 'a', cityVersionId: 'b', timezone: 'Etc/UTC' }, { cityId: 'c', cityVersionId: 'd', timezone: 'Asia/Tokyo' }],
      [{ cityId: 'a', cityVersionId: 'b' }],
      [{ cityId: '', cityVersionId: 'b', timezone: 'Etc/UTC' }],
      [{ cityId: 'a', cityVersionId: 42, timezone: 'Etc/UTC' }],
    ];
    for (const rows of cases) {
      await expect(readSingleCityContext(fakeReader(rows))).rejects.toMatchObject(incomplete);
      await expect(readSingleCityContext(fakeReader(rows))).rejects.toBeInstanceOf(CityContextError);
    }
  });

  it('propagates a real database failure instead of reporting an incomplete configuration', async () => {
    const outage = new Error('connection terminated unexpectedly');
    const failure = await readSingleCityContext({ query: () => Promise.reject(outage) }).catch((error: unknown) => error);
    expect(failure).toBe(outage);
    expect(failure).not.toBeInstanceOf(CityContextError);
  });
});

// Explicit opt-in only: creates a random isolated database and never touches the dev database.
const integration = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1' ? describe : describe.skip;
const root = resolve(import.meta.dirname, '../../..');
const connection = { host: '127.0.0.1' as const, port: 55432 };

integration('single city context against isolated PostgreSQL', () => {
  const pools: Pool[] = [];
  let migrator: Pool;
  let runtime: Pool;
  let reviewer: string;

  beforeAll(async () => {
    const adminEnv = readFileSync(resolve(root, 'infra/dev-postgres/.env'), 'utf8');
    const toolingEnv = readFileSync(resolve(root, 'packages/database-tooling/.env'), 'utf8');
    const adminPassword = /^POSTGRES_PASSWORD=([a-f0-9]{64})$/m.exec(adminEnv)?.[1];
    const migratorPassword = /^FIXLEVELUP_MIGRATOR_PASSWORD=([a-f0-9]{64})$/m.exec(toolingEnv)?.[1];
    const runtimePassword = /^FIXLEVELUP_RUNTIME_PASSWORD=([a-f0-9]{64})$/m.exec(toolingEnv)?.[1];
    if (!adminPassword || !migratorPassword || !runtimePassword) { throw new Error('Local isolated PostgreSQL test credentials are required'); }
    // Same isolated fixture contract as the existing auth integration suites: a fresh
    // random database owned by the migrator, never the dev database.
    const database = `fixlevelup_auth_e2e_test_${randomBytes(12).toString('hex')}`;
    const admin = new Client({ ...connection, database: 'postgres', user: 'fixlevelup_dev', password: adminPassword });
    await admin.connect();
    try {
      await admin.query(`CREATE DATABASE "${database}" OWNER fixlevelup_migrator TEMPLATE template0`);
      await admin.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`);
      await admin.query(`GRANT CONNECT ON DATABASE "${database}" TO fixlevelup_migrator, fixlevelup_runtime`);
    } finally { await admin.end(); }
    const fixture = new Client({ ...connection, database, user: 'fixlevelup_migrator', password: migratorPassword });
    await fixture.connect();
    try { await migrateAuthFixture(fixture, database); } finally { await fixture.end(); }
    migrator = new Pool({ ...connection, database, user: 'fixlevelup_migrator', password: migratorPassword, max: 1 });
    pools.push(migrator);
    runtime = new Pool({ ...connection, database, user: 'fixlevelup_runtime', password: runtimePassword, max: 1 });
    pools.push(runtime);
    reviewer = (await bootstrapFirstAdmin(migrator, { login: `geo-${randomBytes(12).toString('hex')}`,
      password: `Synthetic-Geo-${randomBytes(12).toString('hex')}!` })).staffId;
  }, 30000);

  afterAll(async () => { await Promise.all(pools.map(pool => pool.end())); });

  // Synthetic setup is written by the migrator; the port under test always reads through
  // the real runtime role, exactly as application code will.
  const read = () => readSingleCityContext(runtime);
  const city = (zone: string) => ({ id: randomUUID(), zone });
  let settingsVersion = 0;

  async function addCity(target: { id: string; zone: string }, lifecycle: 'DRAFT' | 'ACTIVE' | 'INACTIVE') {
    await migrator.query('INSERT INTO foundation.service_cities (id, code) VALUES ($1, $2)',
      [target.id, `test-${target.id.slice(0, 8)}`]);
    const versionId = await addVersion(target, 1);
    await migrator.query('UPDATE foundation.service_cities SET current_version_id = $2, lifecycle = $3 WHERE id = $1',
      [target.id, versionId, lifecycle]);
    return versionId;
  }

  async function addVersion(target: { id: string; zone: string }, version: number) {
    const versionId = randomUUID();
    await migrator.query(`INSERT INTO foundation.service_city_versions
      (id, city_id, version, display_name, timezone, public_contact, office_hours, reviewed_by)
      VALUES ($1, $2, $3, 'Synthetic city', $4, 'office@example.test', $5::jsonb, $6)`,
    [versionId, target.id, version, target.zone, JSON.stringify(Array.from({ length: 7 }, () => [])), reviewer]);
    return versionId;
  }

  async function publishSettings(launchMode: string, primaryCityId: string) {
    settingsVersion += 1;
    await migrator.query(`INSERT INTO foundation.business_settings_versions
      (id, version, launch_mode, primary_city_id, reviewed_by) VALUES ($1, $2, $3, $4, $5)`,
    [randomUUID(), settingsVersion, launchMode, primaryCityId, reviewer]);
  }

  const setLifecycle = (id: string, lifecycle: string) =>
    migrator.query('UPDATE foundation.service_cities SET lifecycle = $2 WHERE id = $1', [id, lifecycle]);
  const setCurrentVersion = (id: string, versionId: string) =>
    migrator.query('UPDATE foundation.service_cities SET current_version_id = $2 WHERE id = $1', [id, versionId]);

  it('resolves exactly one ACTIVE SINGLE_CITY primary and follows committed revisions', async () => {
    // No published revision yet.
    await expect(read()).rejects.toMatchObject(incomplete);

    // A published revision whose primary city is still DRAFT is not a configuration.
    const east = city('Etc/UTC');
    const eastVersion = await addCity(east, 'DRAFT');
    await publishSettings('SINGLE_CITY', east.id);
    await expect(read()).rejects.toMatchObject(incomplete);

    // DRAFT -> ACTIVE makes the single primary city resolvable.
    await setLifecycle(east.id, 'ACTIVE');
    await expect(read()).resolves.toEqual({ cityId: east.id, cityVersionId: eastVersion, timezone: 'Etc/UTC' });

    // A second ACTIVE city is ambiguous: the resolver refuses instead of picking one.
    const west = city('Asia/Tokyo');
    await addCity(west, 'ACTIVE');
    await expect(read()).rejects.toMatchObject(incomplete);
    await setLifecycle(west.id, 'INACTIVE');
    await expect(read()).resolves.toMatchObject({ cityId: east.id });

    // An unsupported launch mode is incomplete even with a valid ACTIVE primary.
    await publishSettings('MULTI_CITY', east.id);
    await expect(read()).rejects.toMatchObject(incomplete);

    // A newer SINGLE_CITY revision naming an INACTIVE city does not fall back to revision 1.
    await publishSettings('SINGLE_CITY', west.id);
    await expect(read()).rejects.toMatchObject(incomplete);

    // Switching the single ACTIVE city and the revision together resolves the new city.
    await setLifecycle(east.id, 'INACTIVE');
    await setLifecycle(west.id, 'ACTIVE');
    await expect(read()).resolves.toMatchObject({ cityId: west.id, timezone: 'Asia/Tokyo' });

    // A new immutable version of the same city becomes current with its own timezone.
    const tokyoVersion = await addVersion({ id: west.id, zone: 'Asia/Tokyo' }, 2);
    await setCurrentVersion(west.id, tokyoVersion);
    await expect(read()).resolves.toEqual({ cityId: west.id, cityVersionId: tokyoVersion, timezone: 'Asia/Tokyo' });
  }, 30000);

  it('cannot rewrite reviewed city versions, even with the catalog commands enabled', async () => {
    // The exact read-only grants of 010 are independently proved before the 012 activation step.
    await expect(runtime.query("UPDATE foundation.service_city_versions SET timezone='UTC'"))
      .rejects.toMatchObject({ code: '42501' });
    await expect(runtime.query('DELETE FROM foundation.business_settings_versions'))
      .rejects.toMatchObject({ code: '42501' });
  }, 30000);
});
