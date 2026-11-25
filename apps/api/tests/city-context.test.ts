import { randomBytes, randomUUID } from 'node:crypto';
import { Client, Pool } from 'pg';
import type { PoolClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { CityContextError, readSingleCityContext, SINGLE_CITY_CONTEXT_SQL } from '../src/settings/geography/city-context.js';
import type { CityContextReader } from '../src/settings/geography/city-context.js';
import { bootstrapFirstAdmin } from '../src/staff/bootstrap.js';
import { migrateAuthFixture } from './auth-db-fixture.js';
import { becomeOwner, dropOwnedTestDatabase, fixtureCredentials, maintenanceOpener } from './owned-test-database.js';

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
const connection = { host: '127.0.0.1' as const, port: 55432 };

integration('single city context against isolated PostgreSQL', () => {
  const pools: Pool[] = [];
  let migrator: Pool;
  let runtime: Pool;
  let reviewer: string;
  let maintenance: Client | undefined;
  let dbName: string | undefined;
  let dbCreated = false;
  let tornDown = false;

  /** Ownership proof for the teardown drop, consumed exactly once: this run's CREATE
   * result (flag) AND the strict disposable-name pattern. */
  const takeOwnedDatabase = (): string | undefined => {
    if (!dbCreated) { return undefined; }
    dbCreated = false;
    return dbName !== undefined && /^fixlevelup_auth_e2e_test_[a-f0-9]{24}$/.test(dbName) ? dbName : undefined;
  };

  /** The afterAll teardown, exactly once: this run's pools down first, then the drop
   * of exactly the database this run created. A second call is a no-op. */
  async function teardown(): Promise<void> {
    if (tornDown) { return; }
    tornDown = true;
    const ownedDatabase = takeOwnedDatabase();
    try { await Promise.all(pools.map((pool) => pool.end())); }
    finally {
      try {
        if (ownedDatabase !== undefined && maintenance !== undefined) {
          await dropOwnedTestDatabase(maintenance, ownedDatabase);
        }
      } finally { await maintenance?.end().catch(() => undefined); }
    }
  }

  beforeAll(async () => {
    // Lab mode reads the lab process env and the attested maintenance binding;
    // dev mode reads the local ignored env files. Never the dev database.
    const { migrator: migratorPassword, runtime: runtimePassword } = fixtureCredentials();
    maintenance = await maintenanceOpener()();
    const admin = maintenance;
    // Same isolated fixture contract as the existing auth integration suites: a fresh
    // random database owned by the migrator, never the dev database.
    const database = `fixlevelup_auth_e2e_test_${randomBytes(12).toString('hex')}`;
    try {
      await admin.query(`CREATE DATABASE "${database}" OWNER fixlevelup_migrator TEMPLATE template0`);
      // CREATE is the reuse guard: an existing name is a hard error, so a successful
      // CREATE proves this run owns the disposable database (the flag gates the drop).
      dbName = database;
      dbCreated = true;
      // GRANT/REVOKE need the owner: in the lab the orchestrator is a NOINHERIT member.
      await becomeOwner(admin);
      await admin.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`);
      await admin.query(`GRANT CONNECT ON DATABASE "${database}" TO fixlevelup_migrator, fixlevelup_runtime`);
      const fixture = new Client({ ...connection, database, user: 'fixlevelup_migrator', password: migratorPassword });
      await fixture.connect();
      try { await migrateAuthFixture(fixture, database); } finally { await fixture.end(); }
      migrator = new Pool({ ...connection, database, user: 'fixlevelup_migrator', password: migratorPassword, max: 1 });
      pools.push(migrator);
      runtime = new Pool({ ...connection, database, user: 'fixlevelup_runtime', password: runtimePassword, max: 1 });
      pools.push(runtime);
      reviewer = (await bootstrapFirstAdmin(migrator, { login: `geo-${randomBytes(12).toString('hex')}`,
        password: `Synthetic-Geo-${randomBytes(12).toString('hex')}!` })).staffId;
    } catch (error) {
      // Provisioning failed after CREATE: run the same lifecycle cleanup before rethrowing.
      await teardown().catch(() => undefined);
      throw error;
    }
  }, 30000);

  afterAll(teardown);

  // Synthetic setup is written by the migrator; the port under test always reads through
  // the real runtime role, exactly as application code will.
  const read = () => readSingleCityContext(runtime);
  const city = (zone: string) => ({ id: randomUUID(), zone });
  let settingsVersion = 0;

  /** Wraps guarded-basis fixture DML in one transaction that holds the unified
   * GEO/CFG writer fence before its first statement (migration 022 guard). */
  async function fenced<T>(run: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await migrator.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(734305,1)');
      const result = await run(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async function addCity(target: { id: string; zone: string }, lifecycle: 'DRAFT' | 'ACTIVE' | 'INACTIVE') {
    const versionId = randomUUID();
    // One pinned client owns the whole fenced transaction: the migrator pool has
    // max 1, so a nested fenced call would wait forever for this held client.
    await fenced(async (client) => {
      await client.query('INSERT INTO foundation.service_cities (id, code) VALUES ($1, $2)',
        [target.id, `test-${target.id.slice(0, 8)}`]);
      await client.query(`INSERT INTO foundation.service_city_versions
        (id, city_id, version, display_name, timezone, public_contact, office_hours, reviewed_by)
        VALUES ($1, $2, 1, 'Synthetic city', $3, 'office@example.test', $4::jsonb, $5)`,
      [versionId, target.id, target.zone, JSON.stringify(Array.from({ length: 7 }, () => [])), reviewer]);
      await client.query('UPDATE foundation.service_cities SET current_version_id = $2, lifecycle = $3 WHERE id = $1',
        [target.id, versionId, lifecycle]);
    });
    return versionId;
  }

  async function addVersion(target: { id: string; zone: string }, version: number) {
    const versionId = randomUUID();
    await fenced(async (client) => {
      await client.query(`INSERT INTO foundation.service_city_versions
        (id, city_id, version, display_name, timezone, public_contact, office_hours, reviewed_by)
        VALUES ($1, $2, $3, 'Synthetic city', $4, 'office@example.test', $5::jsonb, $6)`,
      [versionId, target.id, version, target.zone, JSON.stringify(Array.from({ length: 7 }, () => [])), reviewer]);
    });
    return versionId;
  }

  async function publishSettings(launchMode: string, primaryCityId: string) {
    settingsVersion += 1;
    await fenced(async (client) => {
      await client.query(`INSERT INTO foundation.business_settings_versions
        (id, version, launch_mode, primary_city_id, reviewed_by) VALUES ($1, $2, $3, $4, $5)`,
      [randomUUID(), settingsVersion, launchMode, primaryCityId, reviewer]);
    });
  }

  const setLifecycle = (id: string, lifecycle: string) =>
    fenced((client) => client.query('UPDATE foundation.service_cities SET lifecycle = $2 WHERE id = $1', [id, lifecycle]));
  const setCurrentVersion = (id: string, versionId: string) =>
    fenced((client) => client.query('UPDATE foundation.service_cities SET current_version_id = $2 WHERE id = $1', [id, versionId]));

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
