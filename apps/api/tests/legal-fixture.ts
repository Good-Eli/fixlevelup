/**
 * Isolated PostgreSQL fixture for the P03-03 legal ports.
 *
 * Opt-in only: every test that uses it is skipped unless
 * `FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS=1`, and the fixture refuses any database
 * name that is not a freshly created `fixlevelup_legal_test_<24 random hex>`.
 * The suffix is cryptographically random, so a run can never reuse a previous
 * database: `CREATE DATABASE` failing on an existing name is a hard error, not a
 * silent reuse of stale rows. Nothing here touches the working dev database and
 * nothing deletes a database.
 *
 * The migration chain is the shared `authFixtureMigrations` list, so this fixture
 * follows the real chain (including `013_settings_legal_references`) without a
 * second discovery implementation. Migrations run as the migrator role on the new
 * database; the ports under test run as `fixlevelup_runtime`.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Pool } from 'pg';
import type { PoolClient } from 'pg';
import { describe } from 'vitest';
import { bootstrapFirstAdmin } from '../src/staff/bootstrap.js';
import { beginLegalTransaction } from '../src/settings/legal/legal-tx.js';
import { authFixtureMigrations } from './auth-db-fixture.js';

const root = resolve(import.meta.dirname, '../../..');
const migrationRoot = resolve(root, 'prisma/migrations');
const LEGAL_MIGRATION = '20261121000400_settings_legal_references';
const connection = { host: '127.0.0.1' as const, port: 55432 };

export const legalIntegration = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1'
  ? describe
  : describe.skip;

if (!authFixtureMigrations.includes(LEGAL_MIGRATION)) {
  // Fail loudly instead of silently proving the ports against an older schema.
  throw new Error('Legal fixture requires the 013 settings/legal migration in the shared chain');
}

function secret(env: string, name: string): string {
  const match = new RegExp(`^${name}=([a-f0-9]{64})$`, 'm').exec(env);
  if (!match?.[1]) {
    throw new Error(`Missing local test credential: ${name}`);
  }
  return match[1];
}

export interface LegalFixtureDatabase {
  readonly name: string;
  readonly migrator: Pool;
  readonly runtime: Pool;
  /** The bootstrapped first administrator, used as the reviewed_by FK target. */
  readonly staffId: string;
  close(): Promise<void>;
}

export async function startLegalDatabase(): Promise<LegalFixtureDatabase> {
  if (process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] !== '1') {
    throw new Error('Refusing non-isolated legal fixture');
  }
  const name = `fixlevelup_legal_test_${randomBytes(12).toString('hex')}`;
  if (!/^fixlevelup_legal_test_[a-f0-9]{24}$/.test(name)) {
    throw new Error('Invalid legal fixture database name');
  }
  const postgresEnv = readFileSync(resolve(root, 'infra/dev-postgres/.env'), 'utf8');
  const runtimeEnv = readFileSync(resolve(root, 'packages/database-tooling/.env'), 'utf8');
  const postgresPassword = secret(postgresEnv, 'POSTGRES_PASSWORD');
  const runtimePassword = secret(runtimeEnv, 'FIXLEVELUP_RUNTIME_PASSWORD');
  const migratorPassword = secret(runtimeEnv, 'FIXLEVELUP_MIGRATOR_PASSWORD');

  // The maintenance role can only reach `postgres` and this one CREATE/GRANT block;
  // it is closed before migrations, seeds or port calls start.
  const maintenance = new Pool({ ...connection, database: 'postgres', user: 'fixlevelup_dev', password: postgresPassword, max: 1 });
  // Set exactly when this run's CREATE DATABASE succeeded: CREATE is the reuse
  // guard (an existing name is a hard error), so a successful CREATE proves the
  // database is this run's own disposable artifact.
  let databaseCreated = false;
  try {
    await maintenance.query(`CREATE DATABASE "${name}" OWNER fixlevelup_migrator TEMPLATE template0`);
    databaseCreated = true;
    await maintenance.query(`REVOKE ALL ON DATABASE "${name}" FROM PUBLIC`);
    await maintenance.query(`GRANT CONNECT ON DATABASE "${name}" TO fixlevelup_migrator, fixlevelup_runtime`);
  } finally {
    await maintenance.end();
  }
  const migrator = new Pool({ ...connection, database: name, user: 'fixlevelup_migrator', password: migratorPassword, max: 2 });
  const runtime = new Pool({ ...connection, database: name, user: 'fixlevelup_runtime', password: runtimePassword, max: 4 });
  let closed = false;
  /** Ownership proof for the teardown drop: the `databaseCreated` flag (set exactly
   * when this run's CREATE DATABASE succeeded — CREATE is the reuse guard, an
   * existing name is a hard error) AND the strict disposable-name pattern. Consumes
   * the flag, so a second call never drops anything. */
  const takeCreatedDatabase = (): string | undefined => {
    if (!databaseCreated) { return undefined; }
    databaseCreated = false;
    return /^fixlevelup_legal_test_[a-f0-9]{24}$/.test(name) ? name : undefined;
  };
  /** Ends this run's pools first, then drops exactly the database this run created.
   * Idempotent: the ownership flag is consumed by the first call. */
  const dispose = async (): Promise<void> => {
    if (closed) { return; }
    closed = true;
    const ownedDatabase = takeCreatedDatabase();
    try {
      try { await runtime.end(); } finally { await migrator.end(); }
    } finally {
      if (ownedDatabase !== undefined) {
        const dropper = new Pool({ ...connection, database: 'postgres', user: 'fixlevelup_dev', password: postgresPassword, max: 1 });
        try {
          await dropper.query(`DROP DATABASE IF EXISTS "${ownedDatabase}" WITH (FORCE)`);
        } finally {
          await dropper.end();
        }
      }
    }
  };
  try {
    const actual = await migrator.query<{ db: string }>('SELECT current_database() AS db');
    if (actual.rows[0]?.db !== name) {
      throw new Error('Fixture database mismatch');
    }
    await migrator.query('CREATE SCHEMA foundation AUTHORIZATION fixlevelup_migrator');
    for (const migration of authFixtureMigrations) {
      await migrator.query(readFileSync(resolve(migrationRoot, migration, 'migration.sql'), 'utf8'));
    }
    // The 009 deferred invariants require a live administrator with a web credential
    // before any other staff row can commit, so the fixture uses the real bootstrap
    // path instead of hand-inserting staff. This also issues the 012 founder grants.
    const { staffId } = await bootstrapFirstAdmin(migrator, {
      login: `legal-${randomBytes(6).toString('hex')}`,
      password: randomBytes(24).toString('hex'),
    });
    return {
      name,
      migrator,
      runtime,
      staffId,
      close: async () => {
        await dispose();
      },
    };
  } catch (error) {
    // Provisioning failed after CREATE: the same lifecycle cleanup runs before rethrowing.
    await dispose().catch(() => undefined);
    throw error;
  }
}

/** Runs `run` inside an explicit caller transaction on one runtime client. */
export async function inRuntimeTransaction<T>(pool: Pool, run: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    // The legal ports require an explicit READ COMMITTED transaction; never a bare
    // `BEGIN`, so a stronger session default cannot be inherited.
    await beginLegalTransaction(client);
    try {
      const result = await run(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    }
  } finally {
    client.release();
  }
}

export interface FixtureCity {
  readonly cityId: string;
  readonly cityVersionId: string;
}

/** One city with one published reviewed version, inserted as the migrator under
 * the unified GEO/CFG writer fence on one pinned client. */
export async function seedCity(db: Pool, staffId: string): Promise<FixtureCity> {
  const cityId = randomUUID();
  const cityVersionId = randomUUID();
  const hours = JSON.stringify(Array.from({ length: 7 }, () => [[540, 1080]]));
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(734305,1)');
    await client.query("INSERT INTO foundation.service_cities (id,code,lifecycle) VALUES ($1,$2,'DRAFT')",
      [cityId, `legal-${cityId.slice(0, 8)}`]);
    await client.query(`INSERT INTO foundation.service_city_versions
        (id,city_id,version,display_name,timezone,public_contact,office_hours,reviewed_by)
      VALUES ($1,$2,1,'Legal fixture city','Europe/Moscow','+70000000000',$3::jsonb,$4)`,
    [cityVersionId, cityId, hours, staffId]);
    await client.query('UPDATE foundation.service_cities SET current_version_id=$2 WHERE id=$1', [cityId, cityVersionId]);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
  return { cityId, cityVersionId };
}
