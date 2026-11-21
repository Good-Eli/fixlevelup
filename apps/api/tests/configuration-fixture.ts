/**
 * Shared isolated-PostgreSQL fixture for the P03-03 configuration suites.
 *
 * Same contract as the existing auth/city integration suites: an explicit opt-in
 * (`FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS=1`), a fresh random database owned by
 * the migrator, the real migration chain applied by `migrateAuthFixture`, and all
 * writes of the port under test executed through the real `fixlevelup_runtime`
 * role. Nothing here touches the dev database and no production fake is used.
 *
 * The fixture also builds the *synthetic* staff/city rows the ports need. Those
 * rows are written by the migration owner exactly as reviewed data would be, never
 * by the port under test, so a port cannot authorize itself.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Client, Pool } from 'pg';
import { describe } from 'vitest';
import { bootstrapFirstAdmin } from '../src/staff/bootstrap.js';
import { migrateAuthFixture } from './auth-db-fixture.js';

export const configurationIntegration = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1'
  ? describe : describe.skip;

const root = resolve(import.meta.dirname, '../../..');
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

function credentials(): { admin: string; migrator: string; runtime: string } {
  const adminEnv = readFileSync(resolve(root, 'infra/dev-postgres/.env'), 'utf8');
  const toolingEnv = readFileSync(resolve(root, 'packages/database-tooling/.env'), 'utf8');
  const admin = /^POSTGRES_PASSWORD=([a-f0-9]{64})$/m.exec(adminEnv)?.[1];
  const migrator = /^FIXLEVELUP_MIGRATOR_PASSWORD=([a-f0-9]{64})$/m.exec(toolingEnv)?.[1];
  const runtime = /^FIXLEVELUP_RUNTIME_PASSWORD=([a-f0-9]{64})$/m.exec(toolingEnv)?.[1];
  if (!admin || !migrator || !runtime) {
    throw new Error('Local isolated PostgreSQL test credentials are required');
  }
  return { admin, migrator, runtime };
}

/**
 * Creates one isolated database and applies the whole migration chain. The
 * `database` name matches the auth-fixture guard pattern so `migrateAuthFixture`
 * accepts it.
 */
export async function createConfigurationFixture(): Promise<ConfigurationFixture> {
  // Explicit opt-in is checked before any database is created, so an accidental
  // call in a normal test run cannot provision anything.
  if (process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] !== '1') {
    throw new Error('Configuration fixture requires FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS=1');
  }
  const { admin: adminPassword, migrator: migratorPassword, runtime: runtimePassword } = credentials();
  const database = `fixlevelup_configuration_test_${randomBytes(12).toString('hex')}`;
  const admin = new Client({ ...connection, database: 'postgres', user: 'fixlevelup_dev', password: adminPassword });
  await admin.connect();
  try {
    await admin.query(`CREATE DATABASE "${database}" OWNER fixlevelup_migrator TEMPLATE template0`);
    await admin.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`);
    await admin.query(`GRANT CONNECT ON DATABASE "${database}" TO fixlevelup_migrator, fixlevelup_runtime`);
  } finally {
    await admin.end();
  }
  const fixtureClient = new Client({ ...connection, database, user: 'fixlevelup_migrator', password: migratorPassword });
  await fixtureClient.connect();
  try {
    await migrateAuthFixture(fixtureClient, database);
  } finally {
    await fixtureClient.end();
  }
  const migrator = new Pool({ ...connection, database, user: 'fixlevelup_migrator', password: migratorPassword, max: 4 });
  const runtime = new Pool({ ...connection, database, user: 'fixlevelup_runtime', password: runtimePassword, max: 4 });
  const reviewer = (await bootstrapFirstAdmin(migrator, {
    login: `config-${randomBytes(12).toString('hex')}`,
    password: `Synthetic-Config-${randomBytes(12).toString('hex')}!`,
  })).staffId;
  const secondReviewer = await createSecondStaff(migrator);
  return {
    database,
    migrator,
    runtime,
    reviewer,
    secondReviewer,
    async inTransaction<T>(run: (client: Client) => Promise<T>): Promise<T> {
      const client = await runtime.connect();
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
      await Promise.all([migrator.end(), runtime.end()]);
    },
  };
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
  await fixture.migrator.query('INSERT INTO foundation.service_cities (id,code) VALUES ($1,$2)',
    [id, `city-${id.slice(0, 8)}`]);
  await fixture.migrator.query(`INSERT INTO foundation.service_city_versions
    (id,city_id,version,display_name,timezone,public_contact,office_hours,reviewed_by)
    VALUES ($1,$2,$3,'Synthetic city',$4,'office@example.test',$5::jsonb,$6)`,
  [versionId, id, options.version ?? 1, timezone, JSON.stringify(Array.from({ length: 7 }, () => [])), fixture.reviewer]);
  await fixture.migrator.query('UPDATE foundation.service_cities SET current_version_id=$2,lifecycle=$3 WHERE id=$1',
    [id, versionId, lifecycle]);
  return { id, versionId, timezone };
}

/** Adds one more reviewed version of an existing synthetic city (same city). */
export async function addSyntheticCityVersion(
  fixture: ConfigurationFixture,
  city: { id: string },
  options: { timezone: string; version: number },
): Promise<string> {
  const versionId = randomUUID();
  await fixture.migrator.query(`INSERT INTO foundation.service_city_versions
    (id,city_id,version,display_name,timezone,public_contact,office_hours,reviewed_by)
    VALUES ($1,$2,$3,'Synthetic city',$4,'office@example.test',$5::jsonb,$6)`,
  [versionId, city.id, options.version, options.timezone,
    JSON.stringify(Array.from({ length: 7 }, () => [])), fixture.reviewer]);
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
  const result = await fixture.migrator.query<{ version: number }>(
    `INSERT INTO foundation.business_settings_versions (id,version,launch_mode,primary_city_id,reviewed_by)
     SELECT $1,COALESCE(max(version),0)+1,'SINGLE_CITY',$2,$3 FROM foundation.business_settings_versions
     RETURNING version`,
    [id, city.id, fixture.reviewer]);
  const version = result.rows[0]?.version;
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
