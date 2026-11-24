import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createServer } from 'node:net';
import type { Server } from 'node:http';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApi } from '../src/bootstrap/factories.js';
import { loadConfig, ConfigurationError } from '../src/runtime/config.js';
import { loadDatabaseConfig, RuntimeDatabase } from '../src/infrastructure/database/runtime-database.js';
import type { DatabaseConfig } from '../src/infrastructure/database/runtime-database.js';
import { SafeLogger } from '../src/runtime/safe-logger.js';
import { authFixtureMigrations, migrateAuthFixture } from './auth-db-fixture.js';
import { admitFixture, syntheticAdmission } from './admission-fixture.js';
import { startLauncher } from './launcher-harness.js';

const root = resolve(import.meta.dirname, '../../..');
const source = readFileSync(resolve(root, 'packages/database-tooling/.env'), 'utf8');
const password = /^FIXLEVELUP_RUNTIME_PASSWORD=([a-f0-9]{64})$/m.exec(source)?.[1];
if (!password) { throw new Error('Local runtime credentials required for DB integration tests'); }
const database: DatabaseConfig = { host: '127.0.0.1', port: 55432, database: 'fixlevelup_dev', user: 'fixlevelup_runtime', password };
const config = loadConfig({ NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0' });
// The 013 readiness proof needs a disposable full-migration database, so it follows the
// same opt-in as every other isolated integration suite.
const isolatedDbTests = process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1';

/** Credential of the local dev PostgreSQL maintenance role (read in-memory only). */
function devAdminPassword(): string | undefined {
  return /^POSTGRES_PASSWORD=([a-f0-9]{64})$/m.exec(readFileSync(resolve(root, 'infra/dev-postgres/.env'), 'utf8'))?.[1];
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
  const adminPassword = devAdminPassword();
  if (!pattern.test(name) || !adminPassword) { throw new Error('Refusing to drop a non-fixture database'); }
  const { Client } = await import('pg');
  const admin = new Client({ host: '127.0.0.1', port: 55432, database: 'postgres', user: 'fixlevelup_dev', password: adminPassword });
  try {
    await admin.connect();
    await admin.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
  } finally {
    await admin.end().catch(() => undefined);
  }
}

describe('API runtime database readiness', () => {
  it('mocked settings readiness fails closed on missing schema or grants', async () => {
    const db = new RuntimeDatabase(undefined, true);
    const internal = db as unknown as { client: { $queryRaw: (parts: TemplateStringsArray) => Promise<unknown[]> }; settingsReady: () => Promise<boolean> };
    let row: unknown = undefined;
    let sql = '';
    internal.client = { $queryRaw: (parts) => { sql = parts.join(''); return Promise.resolve(row ? [row] : []); } };
    expect(await internal.settingsReady()).toBe(false);
    // A payload without any 013 catalog rows must stay not-ready, never throw.
    row = { columns: [], checks: [], indexes: [], triggers: [], grants: [], broad: [] };
    expect(await internal.settingsReady()).toBe(false);
    // Table names are bound parameters, not SQL text, so assert on stable fragments.
    expect(sql).toContain('public_acl');
    expect(sql).toContain('has_column_privilege');
    expect(sql).toContain('public_execute');
    expect(sql).not.toContain(password);
    row = undefined;
  });

  it('coalesces a bounded management probe and fails closed on missing or incompatible metadata', async () => {
    const authOff = new RuntimeDatabase(undefined, false);
    expect(await authOff.settingsManagementReady()).toBe(false);
    const db = new RuntimeDatabase(undefined, true);
    const internal = db as unknown as { client: { $queryRaw: (parts: TemplateStringsArray) => Promise<unknown[]> } };
    let simulated: object[] = [];
    let probes = 0;
    let sql = '';
    internal.client = { $queryRaw: (parts) => { probes += 1; sql = parts.join(''); return Promise.resolve(simulated); } };
    const pending = db.settingsManagementReady();
    expect(db.settingsManagementReady()).toBe(pending);
    expect(await pending).toBe(false);
    expect(probes).toBe(1);
    simulated = [{ compatible: true, metadata: 'wrong-shape' }];
    expect(await db.settingsManagementReady()).toBe(false);
    simulated = [{ compatible: false, metadata: 'wrong-shape' }];
    expect(await db.settingsManagementReady()).toBe(false);
    internal.client.$queryRaw = () => Promise.reject(new Error('driver error never exposed'));
    expect(await db.settingsManagementReady()).toBe(false);
    expect(sql).toContain('p.prosrc');
    expect(sql).toContain('has_column_privilege');
    expect(sql).toContain('p03_command_receipts');
    expect(sql).not.toContain(password);
  });

  it('mocked auth readiness fails closed on missing schema or privileges', async () => {
    const db = new RuntimeDatabase(undefined, true);
    const internal = db as unknown as { client: { $queryRaw: (parts: TemplateStringsArray) => Promise<{ ready: boolean }[]> }; authReady: () => Promise<boolean> };
    let ready = false;
    let sql = '';
    internal.client = { $queryRaw: (parts) => { sql = parts.join(''); return Promise.resolve([{ ready }]); } };
    expect(await internal.authReady()).toBe(false);
    ready = true;
    expect(await internal.authReady()).toBe(true);
    expect(sql).toContain('expected_columns');
    expect(sql).toContain('required_privileges');
    expect(sql).toContain('expected_constraints');
    expect(sql).toContain('expected_indexes');
    expect(sql).toContain('cleanup_web_auth_throttles');
    expect(sql).not.toContain(password);
  });

  it('requires explicit safe runtime DB configuration without echoing secrets', () => {
    const env = { DB_HOST: '127.0.0.1', DB_PORT: '55432', DB_NAME: 'fixlevelup_dev', DB_USER: 'fixlevelup_runtime', DB_PASSWORD: password };
    expect(loadDatabaseConfig(env)).toEqual(database);
    for (const invalid of [{}, { ...env, DB_USER: 'fixlevelup_dev' }, { ...env, DB_PORT: '5433' }, { ...env, DB_NAME: 'immich' }, { ...env, DB_PASSWORD: '' }]) {
      expect(() => loadDatabaseConfig(invalid)).toThrow(ConfigurationError);
    }
  });

  it('serves real HTTP readiness under runtime role and shuts down the pool', async () => {
    const { Client } = await import('pg');
    // P05-01: a real launcher witness on the dev database pins the admission.
    const holder = new Client({ host: '127.0.0.1', port: 55432, database: 'fixlevelup_dev', user: 'fixlevelup_runtime', password });
    await holder.connect();
    const admission = await admitFixture(holder, 'fixlevelup_dev', 'API');
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

  it('keeps liveness healthy on invalid password and never exposes driver errors', async () => {
    // A GENUINE process admission (real witness on the dev database, issued by
    // the production admitProcess) for an application whose pool carries an
    // invalid password: every checkout fails closed, nothing is logged, and
    // liveness stays independent of providers.
    const { Client } = await import('pg');
    const holder = new Client({ host: '127.0.0.1', port: 55432, database: 'fixlevelup_dev', user: 'fixlevelup_runtime', password });
    await holder.connect();
    const admitted = await admitFixture(holder, 'fixlevelup_dev', 'API');
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

  it('bounds stalled TCP handshake and closes pending sockets without changing Docker', async () => {
    const sockets = new Set<import('node:net').Socket>();
    const stalled = createServer((socket) => {
      sockets.add(socket);
      socket.on('close', () => { sockets.delete(socket); });
      // Consume startup bytes so the fixture observes remote FIN/close, but never reply.
      socket.resume();
    });
    await new Promise<void>((resolve) => { stalled.listen(0, '127.0.0.1', resolve); });
    const address = stalled.address();
    if (!address || typeof address === 'string') { throw new Error('Expected TCP port'); }
    const db = new RuntimeDatabase({ ...database, port: address.port }, false, syntheticAdmission('API').admission);
    try {
      const started = Date.now();
      const first = db.ready();
      const second = db.ready();
      expect(first).toBe(second);
      await db.onModuleDestroy();
      expect(await first).toBe(false);
      // Allow the remote fixture to process the socket close event.
      await new Promise<void>((resolve) => { setTimeout(resolve, 50); });
      expect(sockets.size).toBe(0);
      expect(Date.now() - started).toBeLessThan(2500);
      expect(await db.ready()).toBe(false);
    } finally {
      for (const socket of sockets) { socket.destroy(); }
      await new Promise<void>((resolve) => { stalled.close(() => { resolve(); }); });
    }
  });

  it('rejects a genuinely incompatible isolated DB without mutating dev schema/grants', async () => {
    const apiRequire = createRequire(pathToFileURL(resolve(root, 'apps/api/package.json')));
    // Resolve the already-installed pg entry from this API package, no new dependency.
    const pgModule = await import(pathToFileURL(apiRequire.resolve('pg')).href) as typeof import('pg');
    const adminPassword = /^POSTGRES_PASSWORD=([a-f0-9]{64})$/m.exec(readFileSync(resolve(root, 'infra/dev-postgres/.env'), 'utf8'))?.[1];
    const name = `fixlevelup_p018b_incompatible_${randomBytes(6).toString('hex')}`;
    let fixture: import('pg').Client | undefined;
    let admission: Awaited<ReturnType<typeof admitFixture>> | undefined;
    let app: Awaited<ReturnType<typeof createApi>> | undefined;
    // Set exactly when this run's CREATE DATABASE succeeded (CREATE is the reuse guard).
    let dbCreated = false;
    try {
      const admin = new pgModule.Client({ host: '127.0.0.1', port: 55432, database: 'fixlevelup_dev', user: 'fixlevelup_dev', password: adminPassword });
      await admin.connect();
      try { await admin.query(`CREATE DATABASE "${name}" TEMPLATE template0`);
        dbCreated = true;
        await admin.query(`REVOKE ALL ON DATABASE "${name}" FROM PUBLIC`);
        await admin.query(`GRANT CONNECT ON DATABASE "${name}" TO fixlevelup_runtime`);
      } finally { await admin.end(); }
      fixture = new pgModule.Client({ host: '127.0.0.1', port: 55432, database: name, user: 'fixlevelup_dev', password: adminPassword });
      await fixture.connect();
      // P05-01: the launcher witness lives on the fixture owner connection.
      admission = await admitFixture(fixture, name, 'API');
      app = await createApi(config, new SafeLogger('api'), { ...database, database: name }, undefined, undefined, admission.authorization);
      const server = app.getHttpServer() as Server;
      for (const migration of ['20261120000100_technical_audit_outbox', '20261120000200_technical_outbox_attempts', '20261120000300_technical_outbox_leases']) {
        await fixture.query(readFileSync(resolve(root, 'prisma/migrations', migration, 'migration.sql'), 'utf8'));
      }
      await fixture.query('CREATE TABLE foundation._prisma_migrations(id text PRIMARY KEY)');
      await request(server).get('/health/ready').expect(200);
      await fixture.query('ALTER TABLE foundation.audit_logs DROP CONSTRAINT audit_logs_operation_check; ALTER TABLE foundation.audit_logs ADD CONSTRAINT audit_logs_operation_check CHECK (true)');
      await request(server).get('/health/ready').expect(503);
      await fixture.query('ALTER TABLE foundation.audit_logs DROP CONSTRAINT audit_logs_operation_check; ALTER TABLE foundation.audit_logs ADD CONSTRAINT audit_logs_operation_check CHECK (length(operation)>0)');
      await request(server).get('/health/ready').expect(200);
      await fixture.query('REVOKE INSERT ON foundation.audit_logs FROM fixlevelup_runtime');
      await request(server).get('/health/ready').expect(503);
      await fixture.query('GRANT INSERT ON foundation.audit_logs TO fixlevelup_runtime');
      await request(server).get('/health/ready').expect(200);
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
        await request(server).get('/health/ready').expect(503);
        await fixture.query(restoreSchema);
        const restored = await request(server).get('/health/ready');
        expect(restored.status, restoreSchema).toBe(200);
      }
      for (const column of ['status', 'attempt_count', 'lease_owner', 'lease_generation', 'lease_expires_at', 'next_attempt_at', 'last_error_code']) {
        await fixture.query(`REVOKE UPDATE(${column}) ON foundation.outbox_events FROM fixlevelup_runtime`);
        await request(server).get('/health/ready').expect(503);
        await fixture.query(`GRANT UPDATE(${column}) ON foundation.outbox_events TO fixlevelup_runtime`);
        await request(server).get('/health/ready').expect(200);
      }
      for (const [name, definition] of [
        ['outbox_events_lease_generation_check', 'lease_generation >= 0'],
        ['outbox_events_lease_pair_check', '(lease_owner IS NULL) = (lease_expires_at IS NULL)'],
        ['outbox_events_lease_pending_check', "lease_owner IS NULL OR status = 'PENDING'"],
        ['outbox_events_last_error_code_check', "last_error_code IN ('HANDLER_FAILED', 'ATTEMPTS_EXHAUSTED')"],
      ] as const) {
        await fixture.query(`ALTER TABLE foundation.outbox_events DROP CONSTRAINT ${name}; ALTER TABLE foundation.outbox_events ADD CONSTRAINT ${name} CHECK (true)`);
        await request(server).get('/health/ready').expect(503);
        await fixture.query(`ALTER TABLE foundation.outbox_events DROP CONSTRAINT ${name}; ALTER TABLE foundation.outbox_events ADD CONSTRAINT ${name} CHECK (${definition})`);
        await request(server).get('/health/ready').expect(200);
      }
      await fixture.query('DROP INDEX foundation.outbox_events_queue_idx; CREATE INDEX outbox_events_queue_idx ON foundation.outbox_events(created_at,status)');
      await request(server).get('/health/ready').expect(503);
      await request(server).get('/health/live').expect(200);
    } finally {
      // Same lifecycle cleanup for the failure path: app down, admission released, client
      // ended, then exactly this run's disposable database dropped.
      try { await app?.close(); } finally {
        try { await admission?.release(); } finally {
          try { await fixture?.end(); } finally {
            await dropDisposableDatabase(name, dbCreated, /^fixlevelup_p018b_incompatible_[a-f0-9]{12}$/);
          }
        }
      }
    }
  });

  it.runIf(isolatedDbTests)('rejects weakened 013 settings/legal guards and grants on an isolated full-migration DB', async () => {
    const apiRequire = createRequire(pathToFileURL(resolve(root, 'apps/api/package.json')));
    const pgModule = await import(pathToFileURL(apiRequire.resolve('pg')).href) as typeof import('pg');
    const adminPassword = /^POSTGRES_PASSWORD=([a-f0-9]{64})$/m.exec(readFileSync(resolve(root, 'infra/dev-postgres/.env'), 'utf8'))?.[1];
    const migratorPassword = /^FIXLEVELUP_MIGRATOR_PASSWORD=([a-f0-9]{64})$/m.exec(source)?.[1];
    if (!adminPassword || !migratorPassword) { throw new Error('Local isolated PostgreSQL test credentials are required'); }
    // The fixture isolation guard requires the opt-in flag and an allowlisted name.
    const name = `fixlevelup_legal_test_${randomBytes(12).toString('hex')}`;
    let fixture: import('pg').Client | undefined;
    let admission: Awaited<ReturnType<typeof admitFixture>> | undefined;
    let app: Awaited<ReturnType<typeof createApi>> | undefined;
    // Set exactly when this run's CREATE DATABASE succeeded (CREATE is the reuse guard).
    let dbCreated = false;
    try {
      const admin = new pgModule.Client({ host: '127.0.0.1', port: 55432, database: 'postgres', user: 'fixlevelup_dev', password: adminPassword });
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
      const webAuth = { origin: 'https://127.0.0.1:3100', csrfSecret: 'a'.repeat(64), throttleSecret: 'b'.repeat(64) };
      // P05-01: the launcher witness lives on the migrator fixture connection.
      admission = await admitFixture(fixture, name, 'API');
      app = await createApi(config, new SafeLogger('api'), { ...database, database: name }, webAuth, undefined, admission.authorization);
      const server = app.getHttpServer() as Server;
      await request(server).get('/health/ready').expect(200);
      // A weakened named CHECK must be detected even under the same constraint name.
      await fixture.query('ALTER TABLE foundation.consent_records DROP CONSTRAINT consent_records_action_check; ALTER TABLE foundation.consent_records ADD CONSTRAINT consent_records_action_check CHECK (true)');
      await request(server).get('/health/ready').expect(503);
      await fixture.query("ALTER TABLE foundation.consent_records DROP CONSTRAINT consent_records_action_check; ALTER TABLE foundation.consent_records ADD CONSTRAINT consent_records_action_check CHECK (action IN ('GIVEN','REVOKED'))");
      await request(server).get('/health/ready').expect(200);
      // The checksum guard must really be the SHA-256 of the body, not a format pattern.
      await fixture.query("ALTER TABLE foundation.legal_document_versions DROP CONSTRAINT legal_document_versions_checksum_check; ALTER TABLE foundation.legal_document_versions ADD CONSTRAINT legal_document_versions_checksum_check CHECK (checksum ~ '^[0-9a-f]{64}$')");
      await request(server).get('/health/ready').expect(503);
      await fixture.query("ALTER TABLE foundation.legal_document_versions DROP CONSTRAINT legal_document_versions_checksum_check; ALTER TABLE foundation.legal_document_versions ADD CONSTRAINT legal_document_versions_checksum_check CHECK (checksum = encode(sha256(convert_to(body,'UTF8')),'hex'))");
      await request(server).get('/health/ready').expect(200);
      // A disabled immutability trigger silently removes the append-only guarantee.
      await fixture.query('ALTER TABLE foundation.legal_document_versions DISABLE TRIGGER legal_document_versions_immutable');
      await request(server).get('/health/ready').expect(503);
      await fixture.query('ALTER TABLE foundation.legal_document_versions ENABLE TRIGGER legal_document_versions_immutable');
      await request(server).get('/health/ready').expect(200);
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
        await request(server).get('/health/ready').expect(503);
        await fixture.query(restoreGrant);
        await request(server).get('/health/ready').expect(200);
      }
      // A dropped pointer/unique index and a changed predicate both fail closed.
      await fixture.query('DROP INDEX foundation.consent_records_supersedes_id_key');
      await request(server).get('/health/ready').expect(503);
      await fixture.query('CREATE UNIQUE INDEX consent_records_supersedes_id_key ON foundation.consent_records(supersedes_id)');
      await request(server).get('/health/ready').expect(200);
      await fixture.query('DROP INDEX foundation.reference_entries_company_code_key; CREATE UNIQUE INDEX reference_entries_company_code_key ON foundation.reference_entries(type, code)');
      await request(server).get('/health/ready').expect(503);
      await request(server).get('/health/live').expect(200);
    } finally {
      // Same lifecycle cleanup for the failure path: app down, admission released, client
      // ended, then exactly this run's disposable database dropped.
      try { await app?.close(); } finally {
        try { await admission?.release(); } finally {
          try { await fixture?.end(); } finally {
            await dropDisposableDatabase(name, dbCreated, /^fixlevelup_legal_test_[a-f0-9]{24}$/);
          }
        }
      }
    }
  });

  it.runIf(isolatedDbTests)('requires exact 018 guards, catalog and ACL without requiring founder or settings values', async () => {
    const { Client } = await import('pg');
    const adminPassword = /^POSTGRES_PASSWORD=([a-f0-9]{64})$/m.exec(readFileSync(resolve(root, 'infra/dev-postgres/.env'), 'utf8'))?.[1];
    const migratorPassword = /^FIXLEVELUP_MIGRATOR_PASSWORD=([a-f0-9]{64})$/m.exec(source)?.[1];
    if (!adminPassword || !migratorPassword) { throw new Error('Local isolated PostgreSQL test credentials are required'); }
    const name = `fixlevelup_legal_test_${randomBytes(12).toString('hex')}`;
    const address = { host: '127.0.0.1', port: 55432 };
    let owner: import('pg').Client | undefined;
    let admission: Awaited<ReturnType<typeof admitFixture>> | undefined;
    let db: RuntimeDatabase | undefined;
    // Set exactly when this run's CREATE DATABASE succeeded (CREATE is the reuse guard).
    let dbCreated = false;
    try {
      const admin = new Client({ ...address, database: 'postgres', user: 'fixlevelup_dev', password: adminPassword });
      await admin.connect();
      try {
        await admin.query(`CREATE DATABASE "${name}" OWNER fixlevelup_migrator TEMPLATE template0`);
        dbCreated = true;
        await admin.query(`REVOKE ALL ON DATABASE "${name}" FROM PUBLIC`);
        await admin.query(`GRANT CONNECT ON DATABASE "${name}" TO fixlevelup_migrator, fixlevelup_runtime`);
      } finally { await admin.end(); }
      owner = new Client({ ...address, database: name, user: 'fixlevelup_migrator', password: migratorPassword });
      await owner.connect();
      // P05-01: the launcher witness lives on the migrator owner connection.
      admission = await admitFixture(owner, name, 'TEST');
      db = new RuntimeDatabase({ ...database, database: name }, true, admission.admission);
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
      // Same lifecycle cleanup for the failure path: runtime pool down, admission
      // released, client ended, then exactly this run's disposable database dropped.
      try { await db?.onModuleDestroy(); } finally {
        try { await admission?.release(); } finally {
          try { await owner?.end(); } finally {
            await dropDisposableDatabase(name, dbCreated, /^fixlevelup_legal_test_[a-f0-9]{24}$/);
          }
        }
      }
    }
  });

  it.runIf(isolatedDbTests)('P05-01 S1 gate: positive on the exact 022 profile, negative on every listed drift', async () => {
    const { Client } = await import('pg');
    const adminPassword = /^POSTGRES_PASSWORD=([a-f0-9]{64})$/m.exec(readFileSync(resolve(root, 'infra/dev-postgres/.env'), 'utf8'))?.[1];
    const migratorPassword = /^FIXLEVELUP_MIGRATOR_PASSWORD=([a-f0-9]{64})$/m.exec(source)?.[1];
    if (!adminPassword || !migratorPassword) { throw new Error('Local isolated PostgreSQL test credentials are required'); }
    const name = `fixlevelup_legal_test_${randomBytes(12).toString('hex')}`;
    const address = { host: '127.0.0.1', port: 55432 };
    let owner: import('pg').Client | undefined;
    let db: RuntimeDatabase | undefined;
    // Set exactly when this run's CREATE DATABASE succeeded (CREATE is the reuse guard).
    let dbCreated = false;
    try {
      const admin = new Client({ ...address, database: 'postgres', user: 'fixlevelup_dev', password: adminPassword });
      await admin.connect();
      try {
        await admin.query(`CREATE DATABASE "${name}" OWNER fixlevelup_migrator TEMPLATE template0`);
        dbCreated = true;
        await admin.query(`REVOKE ALL ON DATABASE "${name}" FROM PUBLIC`);
        await admin.query(`GRANT CONNECT ON DATABASE "${name}" TO fixlevelup_migrator, fixlevelup_runtime`);
      } finally { await admin.end(); }
      owner = new Client({ ...address, database: name, user: 'fixlevelup_migrator', password: migratorPassword });
      await owner.connect();
      // P05-01: the launcher witness lives on the migrator owner connection.
      const admission = await admitFixture(owner, name, 'TEST');
      db = new RuntimeDatabase({ ...database, database: name }, true, admission.admission);
      // Before the chain exists the S1 gate is closed...
      expect(await db.requestIntakeReady()).toBe(false);
      // ...and legacy readiness never depends on it (no P05 tables at all yet).
      await migrateAuthFixture(owner, name);
      await owner.query('CREATE TABLE foundation._prisma_migrations (id text PRIMARY KEY)');
      // The S1 gate turns true exactly on the full 022 profile.
      expect(await db.requestIntakeReady()).toBe(true);
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
        const admin2 = new Client({ ...address, database: 'postgres', user: 'fixlevelup_dev', password: adminPassword });
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
      const dropProbe = new Client({ ...address, database: 'postgres', user: 'fixlevelup_dev', password: adminPassword });
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
    } finally {
      // Same lifecycle cleanup for the failure path: runtime pool down, client
      // ended, then exactly this run's disposable database dropped.
      try { await db?.onModuleDestroy(); } finally {
        try { await owner?.end(); } finally {
          await dropDisposableDatabase(name, dbCreated, /^fixlevelup_legal_test_[a-f0-9]{24}$/);
        }
      }
    }
  });

  it('closes a used runtime DB pool in the compiled API signal handler without leaking password', async () => {
    // P05-01 §7 (round 6): the compiled API entrypoint is spawned with the real
    // private IPC channel; this parent acts as the launcher (witness, one-time
    // registry row, production decideLaunch). The child only listens after
    // the single approval + acknowledgement, and shuts its pool down on SIGTERM.
    const launcher = await startLauncher('API');
    let result;
    try {
      result = await launcher.launch({
        timeoutMs: 20_000,
        env: { ...process.env, NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0', SHUTDOWN_TIMEOUT_MS: '5000',
          DB_HOST: database.host, DB_PORT: String(database.port), DB_NAME: database.database, DB_USER: database.user,
          DB_PASSWORD: password, LAUNCH_APPROVAL_TIMEOUT_MS: '10000' },
        source: `
        await import(${JSON.stringify(pathToFileURL(resolve(root, 'apps/api/dist/bootstrap/api.js')).href)});
        setTimeout(()=>{process.emit('SIGTERM');},600);
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
  });
});
