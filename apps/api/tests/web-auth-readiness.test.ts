import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Client } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { RuntimeDatabase } from '../src/infrastructure/database/runtime-database.js';
import { authFixtureMigrations as migrations } from './auth-db-fixture.js';
import { admitFixture } from './admission-fixture.js';
import type { AdmissionHandle } from './admission-fixture.js';

// Explicit opt-in: preserve the random fixture database and never modify the dev schema.
const integration = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1' ? describe : describe.skip;
const root = resolve(import.meta.dirname, '../../..');

integration('web auth readiness against isolated PostgreSQL', () => {
  let admin: Client | undefined;
  let fixture: Client | undefined;
  let admission: AdmissionHandle | undefined;
  let db: RuntimeDatabase | undefined;
  let authReady: () => Promise<boolean>;

  beforeAll(async () => {
    const adminEnv = readFileSync(resolve(root, 'infra/dev-postgres/.env'), 'utf8');
    const runtimeEnv = readFileSync(resolve(root, 'packages/database-tooling/.env'), 'utf8');
    const adminPassword = /^POSTGRES_PASSWORD=([a-f0-9]{64})$/m.exec(adminEnv)?.[1];
    const runtimePassword = /^FIXLEVELUP_RUNTIME_PASSWORD=([a-f0-9]{64})$/m.exec(runtimeEnv)?.[1];
    const migratorPassword = /^FIXLEVELUP_MIGRATOR_PASSWORD=([a-f0-9]{64})$/m.exec(runtimeEnv)?.[1];
    if (!adminPassword || !runtimePassword || !migratorPassword) { throw new Error('Local isolated PostgreSQL test credentials are required'); }
    const connection = { host: '127.0.0.1' as const, port: 55432 };
    admin = new Client({ ...connection, database: 'fixlevelup_dev', user: 'fixlevelup_dev', password: adminPassword });
    await admin.connect();
    const database = `fixlevelup_auth_readiness_test_${randomBytes(12).toString('hex')}`;
    await admin.query(`CREATE DATABASE "${database}" OWNER fixlevelup_migrator TEMPLATE template0`);
    await admin.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`);
    await admin.query(`GRANT CONNECT ON DATABASE "${database}" TO fixlevelup_migrator, fixlevelup_runtime`);
    fixture = new Client({ ...connection, database, user: 'fixlevelup_migrator', password: migratorPassword });
    await fixture.connect();
    await fixture.query('CREATE SCHEMA foundation AUTHORIZATION fixlevelup_migrator');
    for (const migration of migrations) {
      await fixture.query(readFileSync(resolve(root, 'prisma/migrations', migration, 'migration.sql'), 'utf8'));
    }
    await fixture.query('CREATE TABLE foundation._prisma_migrations (id text PRIMARY KEY)');
    // Construct the production Prisma adapter/pool with the isolated DB and actual runtime role.
    // Invoke the auth-specific probe directly: the surrounding probe has its own DB identity checks.
    // P05-01: the pool is admitted through the launch gate (migrator-held witness).
    admission = await admitFixture(fixture, database, 'TEST');
    db = new RuntimeDatabase({ ...connection, database, user: 'fixlevelup_runtime', password: runtimePassword }, true, admission.admission);
    const internal = db as unknown as { authReady: () => Promise<boolean> };
    authReady = () => internal.authReady();
  }, 30000);

  afterAll(async () => {
    try { await db?.onModuleDestroy(); }
    finally { await admission?.release(); }
    await fixture?.end();
    await admin?.end();
  });

  it('accepts the migrated schema with the runtime role', async () => {
    await expect(authReady()).resolves.toBe(true);
    await expect(db?.ready()).resolves.toBe(true);
  });

  it('rejects missing and excessive auth privileges and restores readiness', async () => {
    if (!fixture) { throw new Error('Missing isolated fixture'); }
    for (const [breakGrant, restoreGrant] of [
      ['REVOKE UPDATE (password_hash) ON foundation.staff_web_credentials FROM fixlevelup_runtime', 'GRANT UPDATE (password_hash) ON foundation.staff_web_credentials TO fixlevelup_runtime'],
      ['GRANT UPDATE (id) ON foundation.staff TO fixlevelup_runtime', 'REVOKE UPDATE (id) ON foundation.staff FROM fixlevelup_runtime'],
      ['GRANT SELECT (staff_id) ON foundation.user_permissions TO fixlevelup_runtime', 'REVOKE SELECT (staff_id) ON foundation.user_permissions FROM fixlevelup_runtime'],
      ['GRANT UPDATE (protected) ON foundation.permissions TO fixlevelup_runtime', 'REVOKE UPDATE (protected) ON foundation.permissions FROM fixlevelup_runtime'],
      ['GRANT SELECT ON foundation.roles TO fixlevelup_runtime', 'REVOKE SELECT ON foundation.roles FROM fixlevelup_runtime; GRANT SELECT(id,code,name,description,role_type,status,version,created_by,updated_by,created_at,updated_at) ON foundation.roles TO fixlevelup_runtime'],
      ['REVOKE UPDATE (revoked_by) ON foundation.staff_role_assignments FROM fixlevelup_runtime', 'GRANT UPDATE (revoked_by) ON foundation.staff_role_assignments TO fixlevelup_runtime'],
      ['GRANT MAINTAIN ON foundation.roles TO fixlevelup_runtime', 'REVOKE MAINTAIN ON foundation.roles FROM fixlevelup_runtime'],
      ['GRANT SELECT(code) ON foundation.permissions TO fixlevelup_runtime WITH GRANT OPTION', 'REVOKE GRANT OPTION FOR SELECT(code) ON foundation.permissions FROM fixlevelup_runtime'],
      ['ALTER TABLE foundation.staff DISABLE TRIGGER rbac_staff_current', 'ALTER TABLE foundation.staff ENABLE TRIGGER rbac_staff_current'],
      ['ALTER TABLE foundation.role_permissions DISABLE TRIGGER geography_guard_role_grant', 'ALTER TABLE foundation.role_permissions ENABLE TRIGGER geography_guard_role_grant'],
      ['REVOKE EXECUTE ON FUNCTION foundation.cleanup_web_sessions() FROM fixlevelup_runtime', 'GRANT EXECUTE ON FUNCTION foundation.cleanup_web_sessions() TO fixlevelup_runtime'],
    ] as const) {
      await fixture.query(breakGrant);
      try { await expect(authReady()).resolves.toBe(false); }
      finally { await fixture.query(restoreGrant); }
      await expect(authReady()).resolves.toBe(true);
    }
  });

  it('rejects a missing required constraint', async () => {
    if (!fixture) { throw new Error('Missing isolated fixture'); }
    await fixture.query('ALTER TABLE foundation.staff DROP CONSTRAINT staff_auth_version_check');
    try { await expect(authReady()).resolves.toBe(false); }
    finally { await fixture.query('ALTER TABLE foundation.staff ADD CONSTRAINT staff_auth_version_check CHECK (auth_version >= 0)'); }
    await expect(authReady()).resolves.toBe(true);
  });

  it('fails closed when an auth table is missing', async () => {
    if (!fixture || !db) { throw new Error('Missing isolated fixture'); }
    await fixture.query('ALTER TABLE foundation.web_sessions RENAME TO web_sessions_hidden');
    try {
      // Missing relations can make PostgreSQL throw; ready() converts probe errors to false.
      expect(await authReady().catch(() => false)).toBe(false);
      expect(await db.ready()).toBe(false);
    } finally { await fixture.query('ALTER TABLE foundation.web_sessions_hidden RENAME TO web_sessions'); }
    await expect(authReady()).resolves.toBe(true);
  });
});
