import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createServer } from 'node:net';
import type { Server } from 'node:http';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createApi } from '../src/bootstrap/factories.js';
import { loadConfig, ConfigurationError } from '../src/runtime/config.js';
import { loadDatabaseConfig, RuntimeDatabase } from '../src/infrastructure/database/runtime-database.js';
import type { DatabaseConfig } from '../src/infrastructure/database/runtime-database.js';
import { SafeLogger } from '../src/runtime/safe-logger.js';

const root = resolve(import.meta.dirname, '../../..');
const source = readFileSync(resolve(root, 'packages/database-tooling/.env'), 'utf8');
const password = /^FIXLEVELUP_RUNTIME_PASSWORD=([a-f0-9]{64})$/m.exec(source)?.[1];
if (!password) { throw new Error('Local runtime credentials required for DB integration tests'); }
const database: DatabaseConfig = { host: '127.0.0.1', port: 55432, database: 'fixlevelup_dev', user: 'fixlevelup_runtime', password };
const config = loadConfig({ NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0' });

describe('API runtime database readiness', () => {
  it('requires explicit safe runtime DB configuration without echoing secrets', () => {
    const env = { DB_HOST: '127.0.0.1', DB_PORT: '55432', DB_NAME: 'fixlevelup_dev', DB_USER: 'fixlevelup_runtime', DB_PASSWORD: password };
    expect(loadDatabaseConfig(env)).toEqual(database);
    for (const invalid of [{}, { ...env, DB_USER: 'fixlevelup_dev' }, { ...env, DB_PORT: '5433' }, { ...env, DB_NAME: 'immich' }, { ...env, DB_PASSWORD: '' }]) {
      expect(() => loadDatabaseConfig(invalid)).toThrow(ConfigurationError);
    }
  });

  it('serves real HTTP readiness under runtime role and shuts down the pool', async () => {
    const app = await createApi(config, new SafeLogger('api'), database);
    const server = app.getHttpServer() as Server;
    try {
      const responses = await Promise.all(Array.from({ length: 5 }, () => request(server).get('/health/ready')));
      expect(responses.every((response) => response.status === 200)).toBe(true);
      expect(responses[0]?.body).toEqual({ status: 'ok' });
      expect(responses[0]?.headers['cache-control']).toBe('no-store');
      await request(server).get('/health/live').expect(200);
    } finally { await app.close(); }
  });

  it('keeps liveness healthy on invalid password and never exposes driver errors', async () => {
    const app = await createApi(config, new SafeLogger('api'), { ...database, password: 'synthetic-invalid-password-canary' });
    try {
      const server = app.getHttpServer() as Server;
      const started = Date.now();
      const response = await request(server).get('/health/ready').expect(503);
      expect(Date.now() - started).toBeLessThan(2500);
      expect(JSON.stringify(response.body)).not.toMatch(/synthetic-invalid|password|postgresql|stack/);
      await request(server).get('/health/live').expect(200);
    } finally { await app.close(); }
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
    const db = new RuntimeDatabase({ ...database, port: address.port });
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
    const admin = new pgModule.Client({ host: '127.0.0.1', port: 55432, database: 'fixlevelup_dev', user: 'fixlevelup_dev', password: adminPassword });
    await admin.connect();
    try { await admin.query(`CREATE DATABASE "${name}" TEMPLATE template0`);
      await admin.query(`REVOKE ALL ON DATABASE "${name}" FROM PUBLIC`);
      await admin.query(`GRANT CONNECT ON DATABASE "${name}" TO fixlevelup_runtime`);
    } finally { await admin.end(); }
    const fixture = new pgModule.Client({ host: '127.0.0.1', port: 55432, database: name, user: 'fixlevelup_dev', password: adminPassword });
    await fixture.connect();
    const app = await createApi(config, new SafeLogger('api'), { ...database, database: name });
    const server = app.getHttpServer() as Server;
    try {
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
    } finally { await app.close(); await fixture.end(); }
  });

  it('closes a used runtime DB pool in the compiled API signal handler without leaking password', () => {
    const source = `
      import {createApi} from ${JSON.stringify(pathToFileURL(resolve(root, 'apps/api/dist/bootstrap/factories.js')).href)};
      import {loadConfig} from ${JSON.stringify(pathToFileURL(resolve(root, 'apps/api/dist/runtime/config.js')).href)};
      import {loadDatabaseConfig} from ${JSON.stringify(pathToFileURL(resolve(root, 'apps/api/dist/infrastructure/database/runtime-database.js')).href)};
      import {SafeLogger} from ${JSON.stringify(pathToFileURL(resolve(root, 'apps/api/dist/runtime/safe-logger.js')).href)};
      import {registerShutdown} from ${JSON.stringify(pathToFileURL(resolve(root, 'apps/api/dist/runtime/lifecycle.js')).href)};
      const c=loadConfig(process.env),logger=new SafeLogger('api');
      const app=await createApi(c,logger,loadDatabaseConfig(process.env));registerShutdown(app,c,logger);
      const r=await fetch((await app.getUrl())+'/health/ready');if(r.status!==200)throw new Error('not-ready');
      process.emit('SIGTERM');
    `;
    const result = spawnSync(process.execPath, ['--input-type=module', '--eval', source], {
      cwd: root, encoding: 'utf8', timeout: 10000, env: {
        ...process.env, NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0', SHUTDOWN_TIMEOUT_MS: '5000',
        DB_HOST: database.host, DB_PORT: String(database.port), DB_NAME: database.database, DB_USER: database.user, DB_PASSWORD: password,
      },
    });
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('shutdown_completed');
    expect(result.stdout + result.stderr).not.toContain(password);
  });
});
