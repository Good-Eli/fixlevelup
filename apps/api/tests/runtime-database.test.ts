import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Server } from 'node:http';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApi } from '../src/bootstrap/factories.js';
import { loadConfig, ConfigurationError } from '../src/runtime/config.js';
import { loadDatabaseConfig, RuntimeDatabase } from '../src/infrastructure/database/runtime-database.js';
import { LegacyReadinessProbes } from '../src/infrastructure/database/legacy-readiness.js';
import { probeP05Layer } from '../src/infrastructure/database/p05-profile-catalog.js';
import type { ProcessAuthorization } from '../src/infrastructure/admission/process-admission.js';
import type { DatabaseConfig } from '../src/infrastructure/database/runtime-database.js';
import { SafeLogger } from '../src/runtime/safe-logger.js';
import { authFixtureMigrations, migrateAuthFixture } from './auth-db-fixture.js';
import { admitFixture, syntheticAdmission } from './admission-fixture.js';
import { loadP05LabTarget } from './p05-lab-target.js';
import { startLauncher } from './launcher-harness.js';

const root = resolve(import.meta.dirname, '../../..');
const labEnabled = process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1';
const lab = labEnabled ? loadP05LabTarget() : undefined;
const loaderFixture: DatabaseConfig = { host: '127.0.0.1', port: 55432, database: 'fixlevelup_dev',
  user: 'fixlevelup_runtime', password: 'a'.repeat(64) };
const database = lab?.runtime ?? loaderFixture;
const password = database.password;
const config = loadConfig({ NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0' });
const isolatedDbTests = labEnabled && process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1';

async function attestLab() {
  if (!lab) { throw new Error('An isolated P05 lab target is required'); }
  await (await lab.openMaintenance()).end();
  return lab;
}

function fixtureAdminPassword(): string {
  const secret = process.env['FIXLEVELUP_LAB_FIXTURE_ADMIN_PASSWORD'] ?? '';
  if (!lab || !/^[a-f0-9]{64}$/.test(secret)) { throw new Error('Isolated P05 fixture admin credential is required'); }
  return secret;
}

/**
 * Drops one disposable database created earlier by THIS test run. Ownership is proven
 * twice: the `created` flag, set exactly when this run's CREATE DATABASE succeeded
 * (CREATE is the reuse guard — an existing name is a hard error), and the strict
 * disposable-name pattern of that fixture. The drop runs from a maintenance connection
 * after the test's own app/pool/client teardown; never touches fixlevelup_dev.
 */
async function dropDisposableDatabase(name: string, created: boolean, pattern: RegExp): Promise<void> {
  if (!created) { return; }
  const adminPassword = fixtureAdminPassword();
  if (!pattern.test(name) || !adminPassword) { throw new Error('Refusing to drop a non-fixture database'); }
  const { Client } = await import('pg');
  const admin = new Client({ host: '127.0.0.1', port: 55432, database: 'postgres', user: 'postgres', password: adminPassword });
  try {
    await admin.connect();
    await admin.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
  } finally {
    await admin.end().catch(() => undefined);
  }
}

describe('API runtime database readiness', () => {
  it('binds readiness values instead of interpolating them into SQL', async () => {
    let sql = '';
    let values: unknown[] = [];
    const client = { query: (text: string, parameters: unknown[]) => {
      sql = text;
      values = parameters;
      return Promise.resolve({ rows: [{ compatible: true, metadata: 'wrong-shape' }] });
    } } as unknown as Pick<import('pg').Client, 'query'>;
    expect(await new LegacyReadinessProbes(client, database.database, true).settingsManagementReady()).toBe(false);
    expect(sql).toContain('ANY($1::text[])');
    expect(sql).not.toContain('settings.fullread');
    expect(values[0]).toContain('settings.fullread');
  });

  it('requires explicit safe runtime DB configuration without echoing secrets', () => {
    const env = { DB_HOST: '127.0.0.1', DB_PORT: '55432', DB_NAME: 'fixlevelup_dev', DB_USER: 'fixlevelup_runtime', DB_PASSWORD: loaderFixture.password };
    expect(loadDatabaseConfig(env)).toEqual(loaderFixture);
    for (const invalid of [{}, { ...env, DB_USER: 'fixlevelup_dev' }, { ...env, DB_PORT: '5433' }, { ...env, DB_NAME: 'immich' }, { ...env, DB_PASSWORD: '' }]) {
      expect(() => loadDatabaseConfig(invalid)).toThrow(ConfigurationError);
    }
  });

  it.runIf(labEnabled)('serves real HTTP readiness under runtime role and shuts down the pool', async () => {
    const { Client } = await import('pg');
    await attestLab();
    // P05-01: a real launcher witness on the dev database pins the admission.
    const holder = new Client(database);
    await holder.connect();
    const admission = await admitFixture(holder, database.database, 'API');
    try {
      const app = await createApi(config, new SafeLogger('api'), database, undefined, undefined, admission.authorization);
      const server = app.getHttpServer() as Server;
      try {
        const responses = await Promise.all(Array.from({ length: 5 }, () => request(server).get('/health/ready')));
        expect(responses.every((response) => response.status === 200)).toBe(true);
        expect(responses[0]?.body).toEqual({ status: 'ok' });
        expect(responses[0]?.headers['cache-control']).toBe('no-store');
        await request(server).get('/health/live').expect(200);
      } finally { await app.close(); }
    } finally { await admission.release(); await holder.end(); }
  });

  it.runIf(labEnabled)('requires fresh admission after observed witness loss, even when the same witness returns', async () => {
    const { Client } = await import('pg');
    await attestLab();
    const holder = new Client(database);
    await holder.connect();
    const initial = await admitFixture(holder, database.database, 'API');
    let fresh: Awaited<ReturnType<typeof admitFixture>> | undefined;
    const old = new RuntimeDatabase(database, false, initial.authorization);
    let recovered: RuntimeDatabase | undefined;
    try {
      expect(await old.ready()).toBe(true);
      const { classId, objectId } = initial.admission.binding.witnessKey;
      expect((await holder.query<{ released: boolean }>('SELECT pg_advisory_unlock($1, $2) AS released', [classId, objectId])).rows[0]?.released).toBe(true);
      expect(await old.ready()).toBe(false);
      await holder.query('SELECT pg_advisory_lock($1, $2)', [classId, objectId]);
      expect(await old.ready()).toBe(false);
      expect(() => new RuntimeDatabase(database, false, initial.authorization)).toThrow();
      fresh = await admitFixture(holder, database.database, 'API');
      recovered = new RuntimeDatabase(database, false, fresh.authorization);
      expect(await recovered.ready()).toBe(true);
    } finally {
      await Promise.all([old.onModuleDestroy(), recovered?.onModuleDestroy()]);
      await fresh?.release();
      await initial.release();
      await holder.end();
    }
  });

  it.runIf(labEnabled)('keeps liveness healthy on invalid password and never exposes driver errors', async () => {
    // A GENUINE process admission (real witness on the dev database, issued by
    // the production admitProcess) for an application whose pool carries an
    // invalid password: every checkout fails closed, nothing is logged, and
    // liveness stays independent of providers.
    const { Client } = await import('pg');
    await attestLab();
    const holder = new Client(database);
    await holder.connect();
    const admitted = await admitFixture(holder, database.database, 'API');
    try {
      const app = await createApi(config, new SafeLogger('api'), { ...database, password: 'synthetic-invalid-password-canary' },
        undefined, undefined, admitted.authorization);
      try {
        const server = app.getHttpServer() as Server;
        const started = Date.now();
        const response = await request(server).get('/health/ready').expect(503);
        expect(Date.now() - started).toBeLessThan(2500);
        expect(JSON.stringify(response.body)).not.toMatch(/synthetic-invalid|password|postgresql|stack/);
        await request(server).get('/health/live').expect(200);
      } finally { await app.close(); }
    } finally { await admitted.release(); await holder.end(); }
  });

  it('does not accept an offline launch proof as runtime authorization', () => {
    const offline = syntheticAdmission('API').admission;
    expect(() => new RuntimeDatabase(database, false, { admission: offline } as ProcessAuthorization)).toThrow();
  });

  it.runIf(labEnabled)('rejects a genuinely incompatible isolated DB without mutating dev schema/grants', async () => {
    await attestLab();
    const apiRequire = createRequire(pathToFileURL(resolve(root, 'apps/api/package.json')));
    // Resolve the already-installed pg entry from this API package, no new dependency.
    const pgModule = await import(pathToFileURL(apiRequire.resolve('pg')).href) as typeof import('pg');
    const adminPassword = fixtureAdminPassword();
    const name = `fixlevelup_p018b_incompatible_${randomBytes(6).toString('hex')}`;
    let fixture: import('pg').Client | undefined;
    let runtime: import('pg').Client | undefined;
    // Set exactly when this run's CREATE DATABASE succeeded (CREATE is the reuse guard).
    let dbCreated = false;
    try {
      const admin = new pgModule.Client({ host: '127.0.0.1', port: 55432, database: 'postgres', user: 'postgres', password: adminPassword });
      await admin.connect();
      try { await admin.query(`CREATE DATABASE "${name}" TEMPLATE template0`);
        dbCreated = true;
        await admin.query(`REVOKE ALL ON DATABASE "${name}" FROM PUBLIC`);
        await admin.query(`GRANT CONNECT ON DATABASE "${name}" TO fixlevelup_runtime`);
      } finally { await admin.end(); }
      fixture = new pgModule.Client({ host: '127.0.0.1', port: 55432, database: name, user: 'postgres', password: adminPassword });
      await fixture.connect();
      for (const migration of ['20261120000100_technical_audit_outbox', '20261120000200_technical_outbox_attempts', '20261120000300_technical_outbox_leases']) {
        await fixture.query(readFileSync(resolve(root, 'prisma/migrations', migration, 'migration.sql'), 'utf8'));
      }
      await fixture.query('CREATE TABLE foundation._prisma_migrations(id text PRIMARY KEY)');
      runtime = new pgModule.Client({ ...database, database: name, options: '-c default_transaction_read_only=on' });
      await runtime.connect();
      const probes = new LegacyReadinessProbes(runtime, name, false);
      const ready = () => probes.ready().catch(() => false);
      expect(await ready()).toBe(true);
      await fixture.query('ALTER TABLE foundation.audit_logs DROP CONSTRAINT audit_logs_operation_check; ALTER TABLE foundation.audit_logs ADD CONSTRAINT audit_logs_operation_check CHECK (true)');
      expect(await ready()).toBe(false);
      await fixture.query('ALTER TABLE foundation.audit_logs DROP CONSTRAINT audit_logs_operation_check; ALTER TABLE foundation.audit_logs ADD CONSTRAINT audit_logs_operation_check CHECK (length(operation)>0)');
      expect(await ready()).toBe(true);
      await fixture.query('REVOKE INSERT ON foundation.audit_logs FROM fixlevelup_runtime');
      expect(await ready()).toBe(false);
      await fixture.query('GRANT INSERT ON foundation.audit_logs TO fixlevelup_runtime');
      expect(await ready()).toBe(true);
      // Each mutation must independently make the complete three-migration schema unready.
      for (const [breakSchema, restoreSchema] of [
        ['ALTER TABLE foundation.outbox_events ALTER COLUMN lease_owner SET NOT NULL', 'ALTER TABLE foundation.outbox_events ALTER COLUMN lease_owner DROP NOT NULL'],
        ['ALTER TABLE foundation.outbox_events ALTER COLUMN lease_expires_at SET NOT NULL', 'ALTER TABLE foundation.outbox_events ALTER COLUMN lease_expires_at DROP NOT NULL'],
        ['ALTER TABLE foundation.outbox_events ALTER COLUMN last_error_code SET NOT NULL', 'ALTER TABLE foundation.outbox_events ALTER COLUMN last_error_code DROP NOT NULL'],
        ['ALTER TABLE foundation.outbox_events ALTER COLUMN lease_generation DROP NOT NULL', 'ALTER TABLE foundation.outbox_events ALTER COLUMN lease_generation SET NOT NULL'],
        ['ALTER TABLE foundation.outbox_events ALTER COLUMN next_attempt_at DROP NOT NULL', 'ALTER TABLE foundation.outbox_events ALTER COLUMN next_attempt_at SET NOT NULL'],
        ['ALTER TABLE foundation.outbox_events ALTER COLUMN lease_generation TYPE integer', 'ALTER TABLE foundation.outbox_events ALTER COLUMN lease_generation TYPE bigint'],
        ['ALTER TABLE foundation.outbox_events ALTER COLUMN lease_expires_at TYPE timestamptz(3)', 'ALTER TABLE foundation.outbox_events ALTER COLUMN lease_expires_at TYPE timestamptz(6)'],
        ['ALTER TABLE foundation.outbox_events ALTER COLUMN next_attempt_at TYPE timestamptz(3)', 'ALTER TABLE foundation.outbox_events ALTER COLUMN next_attempt_at TYPE timestamptz(6)'],
        ['ALTER TABLE foundation.outbox_events ALTER COLUMN last_error_code TYPE varchar(64)',
          "ALTER TABLE foundation.outbox_events ALTER COLUMN last_error_code TYPE varchar(32); ALTER TABLE foundation.outbox_events DROP CONSTRAINT outbox_events_last_error_code_check; ALTER TABLE foundation.outbox_events ADD CONSTRAINT outbox_events_last_error_code_check CHECK (last_error_code IN ('HANDLER_FAILED', 'ATTEMPTS_EXHAUSTED'))"],
        ['GRANT UPDATE ON foundation.outbox_events TO fixlevelup_runtime',
          'REVOKE UPDATE ON foundation.outbox_events FROM fixlevelup_runtime; GRANT UPDATE(status,attempt_count,lease_owner,lease_generation,lease_expires_at,next_attempt_at,last_error_code) ON foundation.outbox_events TO fixlevelup_runtime'],
        ['GRANT UPDATE(payload) ON foundation.outbox_events TO fixlevelup_runtime', 'REVOKE UPDATE(payload) ON foundation.outbox_events FROM fixlevelup_runtime'],
        ['GRANT UPDATE(details) ON foundation.audit_logs TO fixlevelup_runtime', 'REVOKE UPDATE(details) ON foundation.audit_logs FROM fixlevelup_runtime'],
        ['DROP INDEX foundation.outbox_events_due_idx; CREATE INDEX outbox_events_due_idx ON foundation.outbox_events(status,created_at,next_attempt_at,id)',
          'DROP INDEX foundation.outbox_events_due_idx; CREATE INDEX outbox_events_due_idx ON foundation.outbox_events(status,next_attempt_at,created_at,id)'],
      ] as const) {
        await fixture.query(breakSchema);
        expect(await ready()).toBe(false);
        await fixture.query(restoreSchema);
        expect(await ready(), restoreSchema).toBe(true);
      }
      for (const column of ['status', 'attempt_count', 'lease_owner', 'lease_generation', 'lease_expires_at', 'next_attempt_at', 'last_error_code']) {
        await fixture.query(`REVOKE UPDATE(${column}) ON foundation.outbox_events FROM fixlevelup_runtime`);
        expect(await ready()).toBe(false);
        await fixture.query(`GRANT UPDATE(${column}) ON foundation.outbox_events TO fixlevelup_runtime`);
        expect(await ready()).toBe(true);
      }
      for (const [name, definition] of [
        ['outbox_events_lease_generation_check', 'lease_generation >= 0'],
        ['outbox_events_lease_pair_check', '(lease_owner IS NULL) = (lease_expires_at IS NULL)'],
        ['outbox_events_lease_pending_check', "lease_owner IS NULL OR status = 'PENDING'"],
        ['outbox_events_last_error_code_check', "last_error_code IN ('HANDLER_FAILED', 'ATTEMPTS_EXHAUSTED')"],
      ] as const) {
        await fixture.query(`ALTER TABLE foundation.outbox_events DROP CONSTRAINT ${name}; ALTER TABLE foundation.outbox_events ADD CONSTRAINT ${name} CHECK (true)`);
        expect(await ready()).toBe(false);
        await fixture.query(`ALTER TABLE foundation.outbox_events DROP CONSTRAINT ${name}; ALTER TABLE foundation.outbox_events ADD CONSTRAINT ${name} CHECK (${definition})`);
        expect(await ready()).toBe(true);
      }
      await fixture.query('DROP INDEX foundation.outbox_events_queue_idx; CREATE INDEX outbox_events_queue_idx ON foundation.outbox_events(created_at,status)');
      expect(await ready()).toBe(false);
    } finally {
      try { await runtime?.end(); } finally {
        try { await fixture?.end(); } finally {
          await dropDisposableDatabase(name, dbCreated, /^fixlevelup_p018b_incompatible_[a-f0-9]{12}$/);
        }
      }
    }
  });

  it.runIf(isolatedDbTests)('rejects weakened 013 settings/legal guards and grants on an isolated full-migration DB', async () => {
    await attestLab();
    const apiRequire = createRequire(pathToFileURL(resolve(root, 'apps/api/package.json')));
    const pgModule = await import(pathToFileURL(apiRequire.resolve('pg')).href) as typeof import('pg');
    const adminPassword = fixtureAdminPassword();
    const migratorPassword = lab?.migrator.password;
    if (!adminPassword || !migratorPassword) { throw new Error('Local isolated PostgreSQL test credentials are required'); }
    // The fixture isolation guard requires the opt-in flag and an allowlisted name.
    const name = `fixlevelup_legal_test_${randomBytes(12).toString('hex')}`;
    let fixture: import('pg').Client | undefined;
    let runtime: import('pg').Client | undefined;
    // Set exactly when this run's CREATE DATABASE succeeded (CREATE is the reuse guard).
    let dbCreated = false;
    try {
      const admin = new pgModule.Client({ host: '127.0.0.1', port: 55432, database: 'postgres', user: 'postgres', password: adminPassword });
      await admin.connect();
      try {
        await admin.query(`CREATE DATABASE "${name}" OWNER fixlevelup_migrator TEMPLATE template0`);
        dbCreated = true;
        await admin.query(`REVOKE ALL ON DATABASE "${name}" FROM PUBLIC`);
        await admin.query(`GRANT CONNECT ON DATABASE "${name}" TO fixlevelup_migrator, fixlevelup_runtime`);
      } finally { await admin.end(); }
      fixture = new pgModule.Client({ host: '127.0.0.1', port: 55432, database: name, user: 'fixlevelup_migrator', password: migratorPassword });
      await fixture.connect();
      await migrateAuthFixture(fixture, name);
      // The full fixture must include 013; later additive migrations must not make
      // this regression stop checking the still-required settings/legal guards.
      expect(authFixtureMigrations).toContain('20261121000400_settings_legal_references');
      // The runtime must not read migration history, but auth readiness expects the table.
      await fixture.query('CREATE TABLE foundation._prisma_migrations (id text PRIMARY KEY)');
      runtime = new pgModule.Client({ ...database, database: name, options: '-c default_transaction_read_only=on' });
      await runtime.connect();
      const probes = new LegacyReadinessProbes(runtime, name, true);
      const ready = () => probes.ready().catch(() => false);
      expect(await ready()).toBe(true);
      // A weakened named CHECK must be detected even under the same constraint name.
      await fixture.query('ALTER TABLE foundation.consent_records DROP CONSTRAINT consent_records_action_check; ALTER TABLE foundation.consent_records ADD CONSTRAINT consent_records_action_check CHECK (true)');
      expect(await ready()).toBe(false);
      await fixture.query("ALTER TABLE foundation.consent_records DROP CONSTRAINT consent_records_action_check; ALTER TABLE foundation.consent_records ADD CONSTRAINT consent_records_action_check CHECK (action IN ('GIVEN','REVOKED'))");
      expect(await ready()).toBe(true);
      // The checksum guard must really be the SHA-256 of the body, not a format pattern.
      await fixture.query("ALTER TABLE foundation.legal_document_versions DROP CONSTRAINT legal_document_versions_checksum_check; ALTER TABLE foundation.legal_document_versions ADD CONSTRAINT legal_document_versions_checksum_check CHECK (checksum ~ '^[0-9a-f]{64}$')");
      expect(await ready()).toBe(false);
      await fixture.query("ALTER TABLE foundation.legal_document_versions DROP CONSTRAINT legal_document_versions_checksum_check; ALTER TABLE foundation.legal_document_versions ADD CONSTRAINT legal_document_versions_checksum_check CHECK (checksum = encode(sha256(convert_to(body,'UTF8')),'hex'))");
      expect(await ready()).toBe(true);
      // A disabled immutability trigger silently removes the append-only guarantee.
      await fixture.query('ALTER TABLE foundation.legal_document_versions DISABLE TRIGGER legal_document_versions_immutable');
      expect(await ready()).toBe(false);
      await fixture.query('ALTER TABLE foundation.legal_document_versions ENABLE TRIGGER legal_document_versions_immutable');
      expect(await ready()).toBe(true);
      // A missing column grant, an extra table-level grant and a widened history grant fail.
      for (const [breakGrant, restoreGrant] of [
        ['REVOKE SELECT(session_id) ON foundation.consent_records FROM fixlevelup_runtime',
          'GRANT SELECT(session_id) ON foundation.consent_records TO fixlevelup_runtime'],
        ['GRANT UPDATE ON foundation.legal_document_versions TO fixlevelup_runtime',
          'REVOKE UPDATE ON foundation.legal_document_versions FROM fixlevelup_runtime'],
        ['GRANT DELETE ON foundation.consent_records TO fixlevelup_runtime',
          'REVOKE DELETE ON foundation.consent_records FROM fixlevelup_runtime'],
        ['GRANT INSERT(published_at) ON foundation.content_block_revisions TO fixlevelup_runtime',
          'REVOKE INSERT(published_at) ON foundation.content_block_revisions FROM fixlevelup_runtime'],
        ['GRANT EXECUTE ON FUNCTION foundation.consent_records_guard() TO fixlevelup_runtime',
          'REVOKE EXECUTE ON FUNCTION foundation.consent_records_guard() FROM fixlevelup_runtime'],
        ['GRANT SELECT(operator_name) ON foundation.business_settings_versions TO PUBLIC',
          'REVOKE SELECT(operator_name) ON foundation.business_settings_versions FROM PUBLIC'],
      ] as const) {
        await fixture.query(breakGrant);
        expect(await ready()).toBe(false);
        await fixture.query(restoreGrant);
        expect(await ready()).toBe(true);
      }
      // A dropped pointer/unique index and a changed predicate both fail closed.
      await fixture.query('DROP INDEX foundation.consent_records_supersedes_id_key');
      expect(await ready()).toBe(false);
      await fixture.query('CREATE UNIQUE INDEX consent_records_supersedes_id_key ON foundation.consent_records(supersedes_id)');
      expect(await ready()).toBe(true);
      await fixture.query('DROP INDEX foundation.reference_entries_company_code_key; CREATE UNIQUE INDEX reference_entries_company_code_key ON foundation.reference_entries(type, code)');
      expect(await ready()).toBe(false);
    } finally {
      try { await runtime?.end(); } finally {
        try { await fixture?.end(); } finally {
          await dropDisposableDatabase(name, dbCreated, /^fixlevelup_legal_test_[a-f0-9]{24}$/);
        }
      }
    }
  });

  it.runIf(isolatedDbTests)('requires exact 018 guards, catalog and ACL without requiring founder or settings values', async () => {
    const { Client } = await import('pg');
    await attestLab();
    const adminPassword = fixtureAdminPassword();
    const migratorPassword = lab?.migrator.password;
    if (!adminPassword || !migratorPassword) { throw new Error('Local isolated PostgreSQL test credentials are required'); }
    const name = `fixlevelup_legal_test_${randomBytes(12).toString('hex')}`;
    const address = { host: '127.0.0.1', port: 55432 };
    let owner: import('pg').Client | undefined;
    let runtime: import('pg').Client | undefined;
    // Set exactly when this run's CREATE DATABASE succeeded (CREATE is the reuse guard).
    let dbCreated = false;
    try {
      const admin = new Client({ ...address, database: 'postgres', user: 'postgres', password: adminPassword });
      await admin.connect();
      try {
        await admin.query(`CREATE DATABASE "${name}" OWNER fixlevelup_migrator TEMPLATE template0`);
        dbCreated = true;
        await admin.query(`REVOKE ALL ON DATABASE "${name}" FROM PUBLIC`);
        await admin.query(`GRANT CONNECT ON DATABASE "${name}" TO fixlevelup_migrator, fixlevelup_runtime`);
      } finally { await admin.end(); }
      owner = new Client({ ...address, database: name, user: 'fixlevelup_migrator', password: migratorPassword });
      await owner.connect();
      runtime = new Client({ ...database, database: name, options: '-c default_transaction_read_only=on' });
      await runtime.connect();
      const probes = new LegacyReadinessProbes(runtime, name, true);
      const db = { settingsManagementReady: () => probes.settingsManagementReady().catch(() => false),
        ready: () => probes.ready().catch(() => false) };
      expect(await db.settingsManagementReady()).toBe(false);
      expect(await db.ready()).toBe(false);
      await migrateAuthFixture(owner, name);
      await owner.query('CREATE TABLE foundation._prisma_migrations (id text PRIMARY KEY)');
      expect(await owner.query('SELECT 1 FROM foundation.p03_bootstrap_permissions')).toMatchObject({ rowCount: 0 });
      expect(await db.settingsManagementReady()).toBe(true);
      expect(await db.ready()).toBe(true);
      const transactions = [
        'ALTER TABLE foundation.p03_command_receipts RENAME TO broken_receipts',
        'ALTER TABLE foundation.p03_command_receipts ADD COLUMN extra text',
        'ALTER TABLE foundation.p03_command_receipts ALTER COLUMN revision_id SET NOT NULL',
        'ALTER TABLE foundation.p03_command_receipts ALTER COLUMN created_at SET DEFAULT transaction_timestamp()',
        'ALTER TABLE foundation.p03_command_receipts ALTER COLUMN created_at TYPE timestamptz(3)',
        'ALTER TABLE foundation.p03_command_receipts DROP CONSTRAINT p03_command_receipts_revision_check; ALTER TABLE foundation.p03_command_receipts ADD CONSTRAINT p03_command_receipts_revision_check CHECK (true)',
        'ALTER TABLE foundation.role_permissions DROP CONSTRAINT role_permissions_scope_check; ALTER TABLE foundation.role_permissions ADD CONSTRAINT role_permissions_scope_check CHECK (true)',
        'ALTER TABLE foundation.p03_command_receipts DISABLE TRIGGER p03_receipts_immutable',
        'ALTER TABLE foundation.p03_bootstrap_permissions DISABLE TRIGGER p03_bootstrap_write',
        'ALTER TABLE foundation.role_permissions DISABLE TRIGGER p03_guard_role_grant',
        'ALTER FUNCTION foundation.issue_first_p03_permissions() SECURITY DEFINER',
        "CREATE OR REPLACE FUNCTION foundation.issue_first_p03_permissions() RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$ BEGIN RETURN; END $$",
        "CREATE OR REPLACE FUNCTION foundation.p03_bootstrap_guard() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$ BEGIN RETURN NEW; END $$",
        'GRANT EXECUTE ON FUNCTION foundation.issue_first_p03_permissions() TO fixlevelup_runtime',
        'GRANT EXECUTE ON FUNCTION foundation.issue_first_p03_permissions() TO PUBLIC',
        'GRANT SELECT(actor_id) ON foundation.p03_command_receipts TO PUBLIC',
        'GRANT SELECT(created_at) ON foundation.p03_command_receipts TO fixlevelup_runtime',
        'REVOKE SELECT(request_sha256) ON foundation.p03_command_receipts FROM fixlevelup_runtime',
        'GRANT INSERT ON foundation.p03_bootstrap_permissions TO fixlevelup_runtime',
        "UPDATE foundation.permissions SET active=false WHERE code='content.read'",
        "UPDATE foundation.permissions SET description='incompatible' WHERE code='content.read'",
      ];
      // Each mutation commits to its own isolated database before the runtime probe.
      // An exact inverse restores baseline without deleting the retained fixture.
      const reverses = [
        'ALTER TABLE foundation.broken_receipts RENAME TO p03_command_receipts',
        'ALTER TABLE foundation.p03_command_receipts DROP COLUMN extra',
        'ALTER TABLE foundation.p03_command_receipts ALTER COLUMN revision_id DROP NOT NULL',
        'ALTER TABLE foundation.p03_command_receipts ALTER COLUMN created_at SET DEFAULT clock_timestamp()',
        'ALTER TABLE foundation.p03_command_receipts ALTER COLUMN created_at TYPE timestamptz(6)',
        undefined, undefined,
        'ALTER TABLE foundation.p03_command_receipts ENABLE TRIGGER p03_receipts_immutable',
        'ALTER TABLE foundation.p03_bootstrap_permissions ENABLE TRIGGER p03_bootstrap_write',
        'ALTER TABLE foundation.role_permissions ENABLE TRIGGER p03_guard_role_grant',
        'ALTER FUNCTION foundation.issue_first_p03_permissions() SECURITY INVOKER',
        undefined, undefined,
        'REVOKE EXECUTE ON FUNCTION foundation.issue_first_p03_permissions() FROM fixlevelup_runtime',
        'REVOKE EXECUTE ON FUNCTION foundation.issue_first_p03_permissions() FROM PUBLIC',
        'REVOKE SELECT(actor_id) ON foundation.p03_command_receipts FROM PUBLIC',
        'REVOKE SELECT(created_at) ON foundation.p03_command_receipts FROM fixlevelup_runtime',
        'GRANT SELECT(request_sha256) ON foundation.p03_command_receipts TO fixlevelup_runtime',
        'REVOKE INSERT ON foundation.p03_bootstrap_permissions FROM fixlevelup_runtime',
        "UPDATE foundation.permissions SET active=true WHERE code='content.read'",
        undefined,
      ];
      reverses[5] = `ALTER TABLE foundation.p03_command_receipts DROP CONSTRAINT p03_command_receipts_revision_check;
        ALTER TABLE foundation.p03_command_receipts ADD CONSTRAINT p03_command_receipts_revision_check CHECK (
          CASE WHEN operation IN ('referencePublish','contentPublish','legalPublish')
            THEN revision_id IS NOT NULL AND revision_version IS NOT NULL AND revision_version > 0
            ELSE revision_id IS NULL AND revision_version IS NULL END)`;
      reverses[6] = `ALTER TABLE foundation.role_permissions DROP CONSTRAINT role_permissions_scope_check;
        ALTER TABLE foundation.role_permissions ADD CONSTRAINT role_permissions_scope_check CHECK (
          CASE WHEN permission_code LIKE 'staff.self.%' THEN scope_type = 'SELF'
            WHEN permission_code IN ('geography.read','geography.manage','geography.publish','staff.geography.read','staff.geography.manage',
              'references.callbackinterval.read','references.callbackinterval.manage','content.read','content.manage','content.publish')
            THEN scope_type IN ('CITY','GLOBAL') ELSE scope_type = 'GLOBAL' END)`;
      const functions = (await owner.query<{ definition: string }>(`SELECT pg_get_functiondef(oid) AS definition
        FROM pg_proc WHERE pronamespace='foundation'::regnamespace AND proname IN ('issue_first_p03_permissions','p03_bootstrap_guard') ORDER BY proname`)).rows;
      reverses[11] = functions[0]?.definition;
      reverses[12] = functions[1]?.definition;
      const original = (await owner.query<{ literal: string }>("SELECT quote_literal(description) AS literal FROM foundation.permissions WHERE code='content.read'")).rows[0]?.literal;
      if (!original) { throw new Error('Missing baseline fixture metadata'); }
      reverses[20] = `UPDATE foundation.permissions SET description=${original} WHERE code='content.read'`;
      for (const [index, broken] of transactions.entries()) {
        const restore = reverses[index];
        if (!restore) { throw new Error('Missing fixture drift restoration'); }
        await owner.query(broken);
        try { expect(await db.settingsManagementReady(), broken).toBe(false); }
        finally { await owner.query(restore); }
        expect(await db.settingsManagementReady(), restore).toBe(true);
      }
    } finally {
      try { await runtime?.end(); } finally {
        try { await owner?.end(); } finally {
          await dropDisposableDatabase(name, dbCreated, /^fixlevelup_legal_test_[a-f0-9]{24}$/);
        }
      }
    }
  });

  it.runIf(isolatedDbTests)('P05-01 S1 + P05-02 S2 gates: positive on the exact 022/023 profile, negative on every listed drift', async () => {
    const { Client } = await import('pg');
    await attestLab();
    const adminPassword = fixtureAdminPassword();
    const migratorPassword = lab?.migrator.password;
    if (!adminPassword || !migratorPassword) { throw new Error('Local isolated PostgreSQL test credentials are required'); }
    const name = `fixlevelup_legal_test_${randomBytes(12).toString('hex')}`;
    const address = { host: '127.0.0.1', port: 55432 };
    let owner: import('pg').Client | undefined;
    let runtime: import('pg').Client | undefined;
    // Set exactly when this run's CREATE DATABASE succeeded (CREATE is the reuse guard).
    let dbCreated = false;
    try {
      const admin = new Client({ ...address, database: 'postgres', user: 'postgres', password: adminPassword });
      await admin.connect();
      try {
        await admin.query(`CREATE DATABASE "${name}" OWNER fixlevelup_migrator TEMPLATE template0`);
        dbCreated = true;
        await admin.query(`REVOKE ALL ON DATABASE "${name}" FROM PUBLIC`);
        await admin.query(`GRANT CONNECT ON DATABASE "${name}" TO fixlevelup_migrator, fixlevelup_runtime`);
      } finally { await admin.end(); }
      owner = new Client({ ...address, database: name, user: 'fixlevelup_migrator', password: migratorPassword });
      await owner.connect();
      const metadata = new Client({ ...database, database: name, options: '-c default_transaction_read_only=on' });
      runtime = metadata;
      await metadata.connect();
      const layer = (value: 'S1' | 'S2' | 'NO_S2') => probeP05Layer(metadata, value).catch(() => false);
      const db = { requestIntakeReady: () => layer('S1'), formSessionReady: () => layer('S2'),
        formSessionProfileAbsent: () => layer('NO_S2') };
      // Before the chain exists the S1 and S2 gates are closed...
      expect(await db.requestIntakeReady()).toBe(false);
      expect(await db.formSessionReady()).toBe(false);
      // ...and the positive pre-S2 absence probe holds: no 023 object exists.
      expect(await db.formSessionProfileAbsent()).toBe(true);
      // ...and legacy readiness never depends on it (no P05 tables at all yet).
      await migrateAuthFixture(owner, name, '20261125000100_request_intake_effects');
      await owner.query('CREATE TABLE foundation._prisma_migrations (id text PRIMARY KEY)');
      // The S1 gate turns true exactly on the full 022 profile, the S2 gate on
      // the full 023 profile, and the 023-absence probe is now false.
      expect(await db.requestIntakeReady()).toBe(true);
      expect(await db.formSessionReady()).toBe(true);
      expect(await db.formSessionProfileAbsent()).toBe(false);
      const drift = [
        // A disabled fence trigger on a LEGACY basis table must fail the gate.
        'ALTER TABLE foundation.service_cities DISABLE TRIGGER service_cities_geo_cfg_fence',
        // A no-op replacement of the fence guard body must fail the gate.
        "CREATE OR REPLACE FUNCTION foundation.geo_cfg_fence_guard() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$ BEGIN RETURN NULL; END $$",
        // A dropped P05 guard trigger and a weakened CHECK both fail closed.
        'ALTER TABLE foundation.requests DISABLE TRIGGER requests_guard',
        'ALTER TABLE foundation.requests DROP CONSTRAINT requests_status_check; ALTER TABLE foundation.requests ADD CONSTRAINT requests_status_check CHECK (true)',
        // Extra table-level runtime privilege on a P05 table fails closed.
        'GRANT DELETE ON foundation.request_events TO fixlevelup_runtime',
        // A PUBLIC grant on a P05 table fails closed.
        'GRANT SELECT(id) ON foundation.request_policy_packages TO PUBLIC',
        // A fence trigger missing entirely from one of the nine relations.
        'DROP TRIGGER reference_entries_geo_cfg_fence ON foundation.reference_entries',
        // Persistence drift: an unlogged P05 table changes crash durability.
        'ALTER TABLE foundation.request_events SET UNLOGGED',
        // An extra table-level runtime UPDATE privilege on a P05 table (the
        // stored ACL beyond the reviewed column grants) fails closed.
        'GRANT UPDATE ON foundation.request_policy_packages TO fixlevelup_runtime',
        // An extra individual runtime privilege on a FENCE relation where a
        // sibling from the same former any-of group is already granted: 012
        // grants DELETE on the coverage table, so only the per-privilege
        // fence_acl booleans can see the new TRUNCATE.
        'GRANT TRUNCATE ON foundation.service_area_district_coverage TO fixlevelup_runtime',
        // A PUBLIC grant on a FENCE relation (not only on the ten P05
        // tables) fails closed: public_acl covers all 19 relations.
        'GRANT SELECT ON foundation.service_cities TO PUBLIC',
        // A RUNTIME column-only privilege on a FENCE relation where no
        // table-level boolean changes: 012 grants the runtime no UPDATE
        // column at all on service_city_versions (only SELECT/INSERT lists),
        // so only the per-column fence_column_grants shape can see the new
        // UPDATE(display_name) — administrative_districts would not do here
        // because 012 already grants UPDATE(name,archived_at) there.
        'GRANT UPDATE(display_name) ON foundation.service_city_versions TO fixlevelup_runtime',
        // A GRANT OPTION upgrade of a privilege the runtime already holds:
        // 012 grants plain table DELETE on the coverage table, so no
        // per-privilege boolean changes — only the per-privilege grantable
        // variant in fence_acl can see the authority change. The owner can
        // re-grant with grant option because it owns the table.
        'GRANT DELETE ON foundation.service_area_district_coverage TO fixlevelup_runtime WITH GRANT OPTION',
        // A third role gaining COLUMN-level SELECT on the ciphertext must also
        // fail closed (the attacl entry is part of the fingerprint). The admin
        // connection creates the one-off probe role first.
        undefined,
      ];
      const restore = [
        'ALTER TABLE foundation.service_cities ENABLE TRIGGER service_cities_geo_cfg_fence',
        undefined,
        'ALTER TABLE foundation.requests ENABLE TRIGGER requests_guard',
        'ALTER TABLE foundation.requests DROP CONSTRAINT requests_status_check; ALTER TABLE foundation.requests ADD CONSTRAINT requests_status_check CHECK (status COLLATE "C" IN (\'NEW\',\'CALLBACK_REQUIRED\',\'WAITING_TELEGRAM_LINK\',\'WAITING_CHANNEL_LINK\',\'MANAGER_REVIEW\',\'WAITING_ASSIGNMENT\',\'ASSIGNED\',\'TECHNICIAN_ACCEPTED\',\'ON_THE_WAY\',\'ARRIVED\',\'DIAGNOSTICS\',\'WAITING_ESTIMATE_APPROVAL\',\'IN_PROGRESS\',\'WAITING_PARTS\',\'PAUSED\',\'TECHNICIAN_COMPLETED\',\'REVISIT_REQUIRED\',\'CLOSED\',\'CANCELLED\'))',
        'REVOKE DELETE ON foundation.request_events FROM fixlevelup_runtime',
        'REVOKE SELECT(id) ON foundation.request_policy_packages FROM PUBLIC',
        'CREATE TRIGGER reference_entries_geo_cfg_fence BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON foundation.reference_entries FOR EACH STATEMENT EXECUTE FUNCTION foundation.geo_cfg_fence_guard()',
        'ALTER TABLE foundation.request_events SET LOGGED',
        'REVOKE UPDATE ON foundation.request_policy_packages FROM fixlevelup_runtime',
        'REVOKE TRUNCATE ON foundation.service_area_district_coverage FROM fixlevelup_runtime',
        'REVOKE SELECT ON foundation.service_cities FROM PUBLIC',
        'REVOKE UPDATE(display_name) ON foundation.service_city_versions FROM fixlevelup_runtime',
        // REVOKE GRANT OPTION FOR removes only the grant option and keeps
        // the base DELETE privilege, so the hash returns exactly to baseline.
        'REVOKE GRANT OPTION FOR DELETE ON foundation.service_area_district_coverage FROM fixlevelup_runtime',
        undefined,
      ];
      const fenceDef = (await owner.query<{ definition: string }>(`SELECT pg_get_functiondef(oid) AS definition
        FROM pg_proc WHERE pronamespace='foundation'::regnamespace AND proname='geo_cfg_fence_guard'`)).rows[0]?.definition;
      if (!fenceDef) { throw new Error('Missing fence guard definition'); }
      restore[1] = fenceDef;
      // The attacl probe role: created and dropped by the admin connection
      // (the migrator has no CREATEROLE); the drift loop only grants/revokes,
      // and the migrator runs the plain REVOKE from the restore list. The
      // role name is unique per run and NOLOGIN: a plain CREATE ROLE cannot
      // collide with (or silently mask) any pre-existing cluster role, and
      // the teardown drop can only ever touch this run's own role.
      const probeRole = `fixlevelup_s1_probe_${randomBytes(6).toString('hex')}`;
      {
        const admin2 = new Client({ ...address, database: 'postgres', user: 'postgres', password: adminPassword });
        await admin2.connect();
        try { await admin2.query(`CREATE ROLE "${probeRole}" NOLOGIN`); }
        finally { await admin2.end(); }
      }
      drift[drift.length - 1] = `GRANT SELECT(ciphertext) ON foundation.request_payload_cells TO "${probeRole}"`;
      restore[restore.length - 1] = `REVOKE SELECT(ciphertext) ON foundation.request_payload_cells FROM "${probeRole}"`;
      const driftStatements = drift.map((statement): string => {
        if (statement === undefined) { throw new Error('Unresolved S1 drift statement'); }
        return statement;
      });
      const dropProbe = new Client({ ...address, database: 'postgres', user: 'postgres', password: adminPassword });
      await dropProbe.connect();
      try {
        for (const [index, broken] of driftStatements.entries()) {
          const undo = restore[index];
          if (!undo) { throw new Error('Missing S1 drift restoration'); }
          await owner.query(broken);
          try { expect(await db.requestIntakeReady(), broken).toBe(false); }
          finally {
            // Every restore is a plain REVOKE/DDL the migrator is allowed to
            // run, including the attacl one; only the role DROP needs the
            // admin connection, and that happens in the teardown below.
            await owner.query(undo);
          }
          expect(await db.requestIntakeReady(), undo).toBe(true);
        }
      } finally {
        await dropProbe.query(`DROP ROLE IF EXISTS "${probeRole}"`).catch(() => undefined);
        await dropProbe.end();
      }
      // P05-02 (023, S2) gate: positive on the exact 023 profile, negative on
      // every listed S2 drift. Each mutation commits to the disposable database
      // before the runtime probe; an exact inverse restores the baseline.
      const s2Drift = [
        // A disabled 023 guard trigger fails closed (tgenabled is fingerprinted).
        'ALTER TABLE foundation.form_browser_groups DISABLE TRIGGER form_browser_groups_guard',
        // A disabled 023 TRUNCATE guard fails closed too: row triggers never see
        // TRUNCATE, so the statement trigger is part of the physical contract.
        'ALTER TABLE foundation.form_session_group_memberships DISABLE TRIGGER form_session_group_memberships_reject_truncate',
        // A weakened CHECK on the throttle counter fails closed.
        'ALTER TABLE foundation.form_throttle_buckets DROP CONSTRAINT form_throttle_buckets_hit_count_check; '
          + 'ALTER TABLE foundation.form_throttle_buckets ADD CONSTRAINT form_throttle_buckets_hit_count_check CHECK (true)',
        // Extra table-level runtime privilege on a P05-02 table fails closed.
        'GRANT DELETE ON foundation.form_throttle_buckets TO fixlevelup_runtime',
        // An extra column-level runtime privilege fails closed: 023 grants no
        // UPDATE at all on form_browser_groups.
        'GRANT UPDATE(expires_at) ON foundation.form_browser_groups TO fixlevelup_runtime',
        // A PUBLIC grant on a 023 table fails closed.
        'GRANT SELECT(id) ON foundation.form_browser_groups TO PUBLIC',
        // Persistence drift: an unlogged 023 table changes crash durability.
        'ALTER TABLE foundation.form_throttle_buckets SET UNLOGGED',
        // Extra reserved object unrelated to the three reviewed tables.
        'CREATE VIEW foundation.form_browser_groups_extra AS SELECT 1 AS extra',
      ];
      const s2Restore = [
        'ALTER TABLE foundation.form_browser_groups ENABLE TRIGGER form_browser_groups_guard',
        'ALTER TABLE foundation.form_session_group_memberships ENABLE TRIGGER form_session_group_memberships_reject_truncate',
        'ALTER TABLE foundation.form_throttle_buckets DROP CONSTRAINT form_throttle_buckets_hit_count_check; '
          + 'ALTER TABLE foundation.form_throttle_buckets ADD CONSTRAINT form_throttle_buckets_hit_count_check '
          + 'CHECK (hit_count BETWEEN 1 AND 1000000)',
        'REVOKE DELETE ON foundation.form_throttle_buckets FROM fixlevelup_runtime',
        'REVOKE UPDATE(expires_at) ON foundation.form_browser_groups FROM fixlevelup_runtime',
        'REVOKE SELECT(id) ON foundation.form_browser_groups FROM PUBLIC',
        'ALTER TABLE foundation.form_throttle_buckets SET LOGGED',
        'DROP VIEW foundation.form_browser_groups_extra',
      ];
      for (const [index, broken] of s2Drift.entries()) {
        const undo = s2Restore[index];
        if (!undo) { throw new Error('Missing S2 drift restoration'); }
        await owner.query(broken);
        try { expect(await db.formSessionReady(), broken).toBe(false); }
        finally { await owner.query(undo); }
        expect(await db.formSessionReady(), undo).toBe(true);
      }
      // MUST 10 (Astra round 1) negative PG assertions for S2:
      // 1. Disabling the INTERNAL FK enforcement triggers under superuser —
      //    the FK definition itself stays intact, only tgenabled flips, so
      //    ONLY the stable-identity fk_trigger fingerprint can see it.
      {
        const admin2 = new Client({ ...address, database: name, user: 'postgres', password: adminPassword });
        await admin2.connect();
        try {
          // DISABLE TRIGGER ALL on the referencing table disables the internal
          // RI_ConstraintTrigger_* triggers (tgenabled O -> D).
          await admin2.query('ALTER TABLE foundation.form_session_group_memberships DISABLE TRIGGER ALL');
          try { expect(await db.formSessionReady()).toBe(false); }
          finally { await admin2.query('ALTER TABLE foundation.form_session_group_memberships ENABLE TRIGGER ALL'); }
          expect(await db.formSessionReady()).toBe(true);
        } finally { await admin2.end(); }
      }
      // 2. A surplus EXECUTE grant on a 023 guard function to a third
      //    probe role: the runtime's effective EXECUTE stays false, so ONLY
      //    the exact function_acl fingerprint can see the extra grant.
      {
        const probeRole = `fixlevelup_s2_probe_${randomBytes(6).toString('hex')}`;
        const admin2 = new Client({ ...address, database: 'postgres', user: 'postgres', password: adminPassword });
        await admin2.connect();
        try {
          await admin2.query(`CREATE ROLE "${probeRole}" NOLOGIN`);
          try {
            await owner.query(`GRANT EXECUTE ON FUNCTION foundation.form_browser_groups_guard() TO "${probeRole}"`);
            try { expect(await db.formSessionReady()).toBe(false); }
            finally { await owner.query(`REVOKE EXECUTE ON FUNCTION foundation.form_browser_groups_guard() FROM "${probeRole}"`); }
            expect(await db.formSessionReady()).toBe(true);
            // Same for a PUBLIC grant: the stored function ACL moves the hash.
            await owner.query('GRANT EXECUTE ON FUNCTION foundation.form_browser_groups_guard() TO PUBLIC');
            try { expect(await db.formSessionReady()).toBe(false); }
            finally { await owner.query('REVOKE EXECUTE ON FUNCTION foundation.form_browser_groups_guard() FROM PUBLIC'); }
            expect(await db.formSessionReady()).toBe(true);
          } finally { await admin2.query(`DROP ROLE IF EXISTS "${probeRole}"`); }
        } finally { await admin2.end(); }
      }
      // 3. formSessionProfileAbsent on a pre-S2 database: an object of a
      //    DIFFERENT kind under a reserved 023 name (a composite TYPE and a
      //    leftover INDEX — kinds the old relkind filter skipped) makes the
      //    absence probe false, so a half-destroyed S2 never counts as the
      //    pre-023 profile. Uses the S1-capped state of this same database
      //    after dropping nothing: the chain here is full S2, so build the
      //    conflicting objects on scratch relations and drop them again —
      //    but the probe sees ANY object with the reserved name, so a plain
      //    scratch-table index named form_browser_groups suffices.
      {
        expect(await db.formSessionProfileAbsent()).toBe(false);
        // Drop the three 023 tables on this disposable database (the migrator
        // owns them) to reach the pre-S2 state, then plant foreign objects.
        // The suite never re-runs the positive S2 checks after this block.
        await owner.query('DROP TABLE foundation.form_session_group_memberships, foundation.form_browser_groups, foundation.form_throttle_buckets CASCADE');
        expect(await db.formSessionReady()).toBe(false);
        expect(await db.formSessionProfileAbsent()).toBe(false); // functions remain
        await owner.query('DROP FUNCTION foundation.form_browser_groups_guard(), foundation.form_session_group_memberships_guard(), foundation.form_throttle_buckets_guard(), foundation.form_history_reject_truncate()');
        expect(await db.formSessionProfileAbsent()).toBe(true);
        // A composite TYPE under a reserved name: not a table, not a function.
        await owner.query('CREATE TYPE foundation.form_browser_groups AS (x int)');
        try { expect(await db.formSessionProfileAbsent()).toBe(false); }
        finally { await owner.query('DROP TYPE foundation.form_browser_groups'); }
        expect(await db.formSessionProfileAbsent()).toBe(true);
        // An INDEX (relkind 'i') under a reserved name — invisible to the old
        // ('r','p','S','v') relkind filter.
        await owner.query('CREATE TABLE foundation.s2_probe_holder (id int)');
        await owner.query('CREATE INDEX form_throttle_buckets ON foundation.s2_probe_holder (id)');
        try { expect(await db.formSessionProfileAbsent()).toBe(false); }
        finally {
          await owner.query('DROP INDEX foundation.form_throttle_buckets');
          await owner.query('DROP TABLE foundation.s2_probe_holder');
        }
        expect(await db.formSessionProfileAbsent()).toBe(true);
      }
    } finally {
      // Same lifecycle cleanup for the failure path: runtime pool down, client
      // ended, then exactly this run's disposable database dropped.
      try { await runtime?.end(); } finally {
        try { await owner?.end(); } finally {
          await dropDisposableDatabase(name, dbCreated, /^fixlevelup_legal_test_[a-f0-9]{24}$/);
        }
      }
    }
  });

  it.runIf(labEnabled)('closes a used runtime DB pool in the compiled API signal handler without leaking password', async () => {
    // A named lab target loads the compiled API factory via a test entry with a real
    // private IPC channel; this parent acts as the launcher (witness, one-time
    // registry row, production decideLaunch). The child only listens after
    // the single approval + acknowledgement, and shuts its pool down on SIGTERM.
    const target = await attestLab();
    const compiled = (file: string) => pathToFileURL(resolve(root, 'apps/api/dist', file)).href;
    const launcher = await startLauncher('API', { runtime: target.runtime, operator: target.migrator,
      artifactPaths: [resolve(root, 'apps/api/dist/bootstrap/api.js'), resolve(root, 'apps/api/dist/bootstrap/factories.js')] });
    let result;
    try {
      result = await launcher.launch({
        timeoutMs: 20_000,
        env: { NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0', SHUTDOWN_TIMEOUT_MS: '5000',
          DB_HOST: database.host, DB_PORT: String(database.port), DB_NAME: database.database, DB_USER: database.user,
          DB_PASSWORD: password, LAUNCH_APPROVAL_TIMEOUT_MS: '10000' },
        source: `
        import { createApi } from ${JSON.stringify(compiled('bootstrap/factories.js'))};
        import { loadConfig } from ${JSON.stringify(compiled('runtime/config.js'))};
        import { SafeLogger } from ${JSON.stringify(compiled('runtime/safe-logger.js'))};
        import { registerShutdown } from ${JSON.stringify(compiled('runtime/lifecycle.js'))};
        import { loadRuntimeAdmission } from ${JSON.stringify(compiled('infrastructure/admission/runtime-admission.js'))};
        import { admitProcess } from ${JSON.stringify(compiled('infrastructure/admission/process-admission.js'))};
        const database = { host: '127.0.0.1', port: 55432, database: process.env.FIXLEVELUP_LAB_DATABASE,
          user: 'fixlevelup_runtime', password: process.env.DB_PASSWORD };
        const config = loadConfig(process.env);
        const logger = new SafeLogger('api');
        const admission = loadRuntimeAdmission(process.env, { database, requiredConsumer: 'API' });
        const authorization = await admitProcess(admission, { database, approvalTimeoutMs: 10000 });
        const app = await createApi(config, logger, database, undefined, undefined, authorization);
        registerShutdown(app, config, logger);
        logger.event('started');
        const response = await fetch((await app.getUrl()) + '/health/ready');
        await response.arrayBuffer();
        if (response.status !== 200) throw new Error('Runtime pool did not become ready');
        process.emit('SIGTERM');
        `,
      });
    } finally {
      await launcher.close();
    }
    expect(result.status).toBe(0);
    expect(result.approvals).toBe(1);
    expect(result.acked).toBe(true);
    expect(result.decision).toBe('approved:acked');
    expect(result.stdout).toContain('"event":"started"');
    expect(result.stdout).toContain('shutdown_completed');
    expect(result.stdout + result.stderr).not.toContain(password);
  }, 60_000);
});
