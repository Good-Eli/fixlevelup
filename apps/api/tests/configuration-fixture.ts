/**
 * Shared isolated-PostgreSQL fixture for the P03-03 configuration suites.
 *
 * Same contract as the existing auth/city integration suites: an explicit opt-in
 * (`FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS=1`), a fresh random database owned by
 * the migrator, the real migration chain applied by `migrateAuthFixture`, and all
 * writes of the port under test executed through the real `fixlevelup_runtime`
 * role. Nothing here touches the dev database and no production fake is used.
 * The database lifecycle, credentials and maintenance binding come from
 * `owned-test-database.ts`: dev reads the local ignored env files, synthetic lab
 * mode reads only the lab process env and the attested lab maintenance binding.
 *
 * The fixture also builds the *synthetic* staff/city rows the ports need. Those
 * rows are written by the migration owner exactly as reviewed data would be, never
 * by the port under test, so a port cannot authorize itself.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Client, Pool } from 'pg';
import type { PoolClient } from 'pg';
import { describe } from 'vitest';
import { bootstrapFirstAdmin } from '../src/staff/bootstrap.js';
import { authFixtureMigrations, installPinnedMigrationHistory, migrateAuthFixture } from './auth-db-fixture.js';
import { fixtureCredentials, maintenanceOpener, OwnedTestDatabase } from './owned-test-database.js';

export const configurationIntegration = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1'
  ? describe : describe.skip;

const root = resolve(import.meta.dirname, '../../..');
const migrationRoot = resolve(root, 'prisma/migrations');
const connection = { host: '127.0.0.1' as const, port: 55432 };

export interface ConfigurationFixture {
  readonly database: string;
  readonly migrator: Pool;
  readonly runtime: Pool;
  /** Reviewed staff identity used as reviewer/actor of synthetic rows. */
  readonly reviewer: string;
  /** A second reviewed staff identity, to prove actor/reviewer separation. */
  readonly secondReviewer: string;
  /** Runs `run` inside one explicit runtime transaction, rolling back on failure. */
  inTransaction<T>(run: (client: Client) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

/**
 * Connected maintenance client on the `postgres` database, for lifecycle proofs
 * that must inspect `pg_database`/`pg_stat_activity` around a fixture whose
 * provisioning is expected to fail. Uses the same opener as the fixture itself:
 * dev role on `postgres`, or the attested lab binding in synthetic mode. The
 * caller always closes it.
 */
export async function openConfigurationMaintenanceClient(): Promise<Client> {
  if (process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] !== '1') {
    throw new Error('Configuration fixture requires FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS=1');
  }
  return await maintenanceOpener()();
}

/**
 * Creates one isolated database and applies the migration chain. The
 * `database` name matches the auth-fixture guard pattern so `migrateAuthFixture`
 * accepts it. `capBefore` optionally stops the chain before the named migration
 * (exclusive), reproducing an older schema profile for baseline proofs.
 */
export async function createConfigurationFixture(options: { readonly capBefore?: string } = {}): Promise<ConfigurationFixture> {
  // Explicit opt-in is checked before any database is created, so an accidental
  // call in a normal test run cannot provision anything.
  if (process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] !== '1') {
    throw new Error('Configuration fixture requires FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS=1');
  }
  const { migrator: migratorPassword, runtime: runtimePassword } = fixtureCredentials();
  const capIndex = options.capBefore === undefined ? -1 : authFixtureMigrations.indexOf(options.capBefore);
  if (options.capBefore !== undefined && capIndex < 0) { throw new Error(`Unknown cap migration: ${options.capBefore}`); }
  const chain = capIndex >= 0 ? authFixtureMigrations.slice(0, capIndex) : null;
  const database = `fixlevelup_configuration_test_${randomBytes(12).toString('hex')}`;
  if (!/^fixlevelup_configuration_test_[a-f0-9]{24}$/.test(database)) {
    throw new Error('Refusing non-isolated configuration fixture');
  }
  // Owned lifecycle: CREATE + the REVOKE/GRANT block on `postgres`, then exactly
  // this run's database is dropped on any later failure (owned-test-database.ts).
  const owned = await OwnedTestDatabase.create({
    name: database,
    pattern: /^fixlevelup_configuration_test_[a-f0-9]{24}$/,
    prepare: async (maintenance) => {
      await maintenance.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`);
      await maintenance.query(`GRANT CONNECT ON DATABASE "${database}" TO fixlevelup_migrator, fixlevelup_runtime`);
    },
  });
  let migrator: Pool | undefined;
  let runtime: Pool | undefined;
  const closeOwnResources = async (): Promise<void> => {
    const pools = [migrator, runtime].filter((pool): pool is Pool => pool !== undefined);
    if (pools.length > 0) { await Promise.all(pools.map((pool) => pool.end())); }
  };
  try {
    const fixtureClient = new Client({ ...connection, database, user: 'fixlevelup_migrator', password: migratorPassword });
    try {
      await fixtureClient.connect();
      if (chain) {
        // Same isolation guard as migrateAuthFixture, applied to the capped chain.
        // (The opt-in env was checked by the caller above; here only the disposable
        // name pattern and the actual connection identity are re-proved.)
        if (!/^fixlevelup_(bootstrap|recovery|web_auth|auth_e2e|legal|configuration)_test_[a-f0-9]{24}$/.test(database)
          || (await fixtureClient.query<{ db: string }>('SELECT current_database() AS db')).rows[0]?.db !== database) {
          throw new Error('Refusing non-isolated capped fixture');
        }
        for (const migration of chain) {
          await fixtureClient.query(readFileSync(resolve(migrationRoot, migration, 'migration.sql'), 'utf8'));
        }
        await installPinnedMigrationHistory(fixtureClient, chain);
      } else {
        await migrateAuthFixture(fixtureClient, database);
        await installPinnedMigrationHistory(fixtureClient, authFixtureMigrations);
      }
    } finally {
      await fixtureClient.end().catch(() => undefined);
    }
    const migratorPool = new Pool({ ...connection, database, user: 'fixlevelup_migrator', password: migratorPassword, max: 4 });
    migrator = migratorPool;
    const runtimePool = new Pool({ ...connection, database, user: 'fixlevelup_runtime', password: runtimePassword, max: 4 });
    runtime = runtimePool;
    const reviewer = (await bootstrapFirstAdmin(migratorPool, {
      login: `config-${randomBytes(12).toString('hex')}`,
      password: `Synthetic-Config-${randomBytes(12).toString('hex')}!`,
    })).staffId;
    const secondReviewer = await createSecondStaff(migratorPool);
    return {
      database,
      migrator: migratorPool,
      runtime: runtimePool,
      reviewer,
      secondReviewer,
      async inTransaction<T>(run: (client: Client) => Promise<T>): Promise<T> {
        const client = await runtimePool.connect();
        try {
          await client.query('BEGIN');
          const result = await run(client);
          await client.query('COMMIT');
          return result;
        } catch (error) {
          await client.query('ROLLBACK').catch(() => undefined);
          throw error;
        } finally {
          client.release();
        }
      },
      async close(): Promise<void> {
        // Ends this run's pools first, then drops exactly this run's database.
        await owned.dispose(closeOwnResources);
      },
    };
  } catch (error) {
    // Provisioning failed after CREATE: close this run's pools, drop exactly this
    // run's database, and surface a teardown failure instead of swallowing it.
    throw await owned.failure(error, closeOwnResources);
  }
}

/**
 * A second reviewed staff row, so a test can prove the publisher actor and the
 * revision reviewer are independent identities. The 009 deferred constraint needs
 * a live role and a matching channel by commit, so the staff row and its role
 * assignment are created in one transaction. It is written by the migration owner
 * (synthetic reviewed data), never by a port under test.
 */
async function createSecondStaff(migrator: Pool): Promise<string> {
  const staffId = randomUUID();
  // One connected client owns the whole transaction: a pooled `query` call could
  // otherwise land on another backend between BEGIN and COMMIT.
  const client = await migrator.connect();
  try {
    await client.query('BEGIN');
    await client.query("INSERT INTO foundation.staff (id,role,employment_state) VALUES ($1,'MANAGER','ACTIVE')",
      [staffId]);
    await client.query(`INSERT INTO foundation.staff_role_assignments (id,staff_id,role_id)
      SELECT $1,$2,r.id FROM foundation.roles r WHERE r.role_type='SYSTEM' AND r.code='MANAGER' AND r.status='ACTIVE'`,
    [randomUUID(), staffId]);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
  return staffId;
}

export interface SyntheticCity {
  readonly id: string;
  readonly versionId: string;
  readonly timezone: string;
}

/** Runs guarded-basis fixture DML under the unified writer fence (S1+). The lock
 * and the statements must share one backend, so the pinned client is passed in. */
async function fenced<T>(fixture: ConfigurationFixture, run: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await fixture.migrator.connect();
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

/**
 * Creates a synthetic city with one reviewed version, as the migration owner.
 * `lifecycle` is ACTIVE for a city the resolver would serve.
 */
export async function createSyntheticCity(
  fixture: ConfigurationFixture,
  options: { timezone?: string; lifecycle?: 'DRAFT' | 'ACTIVE' | 'INACTIVE'; version?: number } = {},
): Promise<SyntheticCity> {
  const timezone = options.timezone ?? 'Europe/Moscow';
  const lifecycle = options.lifecycle ?? 'ACTIVE';
  const id = randomUUID();
  const versionId = randomUUID();
  await fenced(fixture, async (client) => {
    await client.query('INSERT INTO foundation.service_cities (id,code) VALUES ($1,$2)',
      [id, `city-${id.slice(0, 8)}`]);
    await client.query(`INSERT INTO foundation.service_city_versions
      (id,city_id,version,display_name,timezone,public_contact,office_hours,reviewed_by)
      VALUES ($1,$2,$3,'Synthetic city',$4,'office@example.test',$5::jsonb,$6)`,
    [versionId, id, options.version ?? 1, timezone, JSON.stringify(Array.from({ length: 7 }, () => [])), fixture.reviewer]);
    await client.query('UPDATE foundation.service_cities SET current_version_id=$2,lifecycle=$3 WHERE id=$1',
      [id, versionId, lifecycle]);
  });
  return { id, versionId, timezone };
}

/** Adds one more reviewed version of an existing synthetic city (same city). */
export async function addSyntheticCityVersion(
  fixture: ConfigurationFixture,
  city: { id: string },
  options: { timezone: string; version: number },
): Promise<string> {
  const versionId = randomUUID();
  await fenced(fixture, async (client) => {
    await client.query(`INSERT INTO foundation.service_city_versions
      (id,city_id,version,display_name,timezone,public_contact,office_hours,reviewed_by)
      VALUES ($1,$2,$3,'Synthetic city',$4,'office@example.test',$5::jsonb,$6)`,
    [versionId, city.id, options.version, options.timezone,
      JSON.stringify(Array.from({ length: 7 }, () => [])), fixture.reviewer]);
  });
  return versionId;
}

/**
 * The first company settings revision is created by geography activation, so a
 * synthetic baseline revision (all policy fields NULL) is written by the migration
 * owner here. The port under test must then publish a complete revision over it.
 */
export async function createSyntheticSettingsBaseline(
  fixture: ConfigurationFixture,
  city: { id: string },
): Promise<{ id: string; version: number }> {
  const id = randomUUID();
  let version: number | undefined;
  await fenced(fixture, async (client) => {
    const result = await client.query<{ version: number }>(
      `INSERT INTO foundation.business_settings_versions (id,version,launch_mode,primary_city_id,reviewed_by)
       SELECT $1,COALESCE(max(version),0)+1,'SINGLE_CITY',$2,$3 FROM foundation.business_settings_versions
       RETURNING version`,
      [id, city.id, fixture.reviewer]);
    version = result.rows[0]?.version;
  });
  if (version === undefined) {
    throw new Error('Missing settings baseline');
  }
  return { id, version };
}

/** Synthetic complete policy input for a publish. */
export function syntheticSettings(overrides: Record<string, string> = {}) {
  return {
    operatorName: 'Synthetic Operator LLC',
    operatorRegistrationId: 'SYNTH-0000001',
    operatorAddress: 'Synthetic street 1, Synthetic city',
    legalReviewRef: 'review://synthetic-legal/1',
    securityPolicyRef: 'policy://synthetic-security/1',
    retentionPolicyRef: 'policy://synthetic-retention/1',
    uploadPolicyRef: 'policy://synthetic-upload/1',
    ...overrides,
  };
}

/**
 * Makes every audit INSERT fail for the duration of one test, so the suite can
 * prove that a failed audit rolls the domain write back. A temporary BEFORE INSERT
 * trigger is created by the migration owner and always dropped again; the runtime
 * role never gains a privilege and no grant is touched.
 */
export async function installFailingAuditTrigger(fixture: ConfigurationFixture): Promise<void> {
  const client = await fixture.migrator.connect();
  try {
    await client.query(`CREATE FUNCTION foundation.configuration_test_fail_audit() RETURNS trigger
      LANGUAGE plpgsql SET search_path=pg_catalog AS $$
      BEGIN RAISE EXCEPTION 'synthetic audit failure' USING ERRCODE='23514'; END $$`);
    await client.query(`CREATE TRIGGER configuration_test_fail_audit BEFORE INSERT ON foundation.audit_logs
      FOR EACH ROW EXECUTE FUNCTION foundation.configuration_test_fail_audit()`);
  } finally {
    client.release();
  }
}

export async function removeFailingAuditTrigger(fixture: ConfigurationFixture): Promise<void> {
  const client = await fixture.migrator.connect();
  try {
    await client.query('DROP TRIGGER IF EXISTS configuration_test_fail_audit ON foundation.audit_logs');
    await client.query('DROP FUNCTION IF EXISTS foundation.configuration_test_fail_audit()');
  } finally {
    client.release();
  }
}
