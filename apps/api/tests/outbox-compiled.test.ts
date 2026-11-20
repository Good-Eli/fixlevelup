import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';

const root = resolve(import.meta.dirname, '../../..');
const moduleUrl = (path: string): string => pathToFileURL(resolve(root, 'apps/api/dist', path)).href;
const baseEnv: NodeJS.ProcessEnv = {
  ...process.env,
  NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0', SHUTDOWN_TIMEOUT_MS: '5000',
  DB_HOST: '127.0.0.1', DB_PORT: '55432', DB_NAME: 'fixlevelup_dev', DB_USER: 'fixlevelup_runtime',
};

describe('compiled outbox worker lifecycle', () => {
  it('uses the real runtime database and closes worker pools and timers on SIGTERM without exposing credentials', () => {
    const source = readFileSync(resolve(root, 'packages/database-tooling/.env'), 'utf8');
    const password = /^FIXLEVELUP_RUNTIME_PASSWORD=([a-f0-9]{64})$/m.exec(source)?.[1];
    if (!password) { throw new Error('Local runtime credentials required for compiled worker integration test'); }
    const result = spawnSync(process.execPath, ['--input-type=module', '--eval', `
      import {createWorker} from ${JSON.stringify(moduleUrl('bootstrap/factories.js'))};
      import {loadConfig} from ${JSON.stringify(moduleUrl('runtime/config.js'))};
      import {loadDatabaseConfig} from ${JSON.stringify(moduleUrl('infrastructure/database/runtime-database.js'))};
      import {OutboxWorker} from ${JSON.stringify(moduleUrl('infrastructure/outbox/outbox-worker.js'))};
      import {SafeLogger} from ${JSON.stringify(moduleUrl('runtime/safe-logger.js'))};
      import {registerShutdown} from ${JSON.stringify(moduleUrl('runtime/lifecycle.js'))};
      const config=loadConfig(process.env),logger=new SafeLogger('worker');
      const app=await createWorker(logger,loadDatabaseConfig(process.env));
      registerShutdown(app,config,logger);
      await app.get(OutboxWorker).runOnce();
      console.log('compiled-outbox-poll-completed');
      process.emit('SIGTERM');
      process.emit('SIGINT');
    `], {
      cwd: root, encoding: 'utf8', timeout: 12_000,
      env: { ...baseEnv, DB_PASSWORD: password },
    });
    // A leaked heartbeat, poll timer or pool makes spawnSync hit its deadline instead of exiting naturally.
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    expect(result.signal).toBeNull();
    expect(result.stdout).toContain('compiled-outbox-poll-completed');
    expect(result.stdout).not.toContain('outbox_unavailable');
    expect(result.stdout.match(/"event":"shutdown_started"/g)).toHaveLength(1);
    expect(result.stdout).toContain('"event":"shutdown_completed"');
    expect(result.stdout).not.toContain('shutdown_timeout');
    expect(result.stdout).not.toContain('shutdown_failed');
    expect(result.stdout + result.stderr).not.toContain(password);
    expect(result.stderr).toBe('');
  }, 15_000);

  it('rejects missing database configuration in the compiled worker entrypoint without starting a worker', () => {
    const canary = 'synthetic-missing-worker-db-config-canary';
    const result = spawnSync(process.execPath, ['--input-type=module', '--eval', `
      await import(${JSON.stringify(moduleUrl('bootstrap/worker.js'))});
    `], {
      cwd: root, encoding: 'utf8', timeout: 8000,
      env: { ...baseEnv, DB_PASSWORD: '', BOT_TOKEN: canary },
    });
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(1);
    expect(result.stdout).toContain('"event":"startup_failed"');
    expect(result.stdout).not.toContain('"event":"started"');
    expect(result.stdout).not.toContain('"event":"heartbeat"');
    expect(result.stdout + result.stderr).not.toContain(canary);
    expect(result.stderr).toBe('');
  });
});
