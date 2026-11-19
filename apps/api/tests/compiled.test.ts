import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';

const root = resolve(import.meta.dirname, '../../..');
const moduleUrl = (path: string): string => pathToFileURL(resolve(root, 'apps/api/dist', path)).href;
const env = {
  ...process.env,
  NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0', SHUTDOWN_TIMEOUT_MS: '5000',
  NEST_LOG_LEVEL: 'synthetic-secret-canary', BOT_TOKEN: 'synthetic-secret-canary',
};

function run(source: string, overrides: NodeJS.ProcessEnv = {}) {
  const result = spawnSync(process.execPath, ['--input-type=module', '--eval', source], {
    cwd: root, env: { ...env, ...overrides }, encoding: 'utf8', timeout: 8000,
  });
  if (result.error) { throw result.error; }
  return result;
}

describe('compiled Node 24 runtime', () => {
  it('boots compiled ESM with tsc metadata and serves real loopback HTTP', () => {
    const result = run(`
      import {createApi} from ${JSON.stringify(moduleUrl('bootstrap/factories.js'))};
      import {loadConfig} from ${JSON.stringify(moduleUrl('runtime/config.js'))};
      import {SafeLogger} from ${JSON.stringify(moduleUrl('runtime/safe-logger.js'))};
      const app=await createApi(loadConfig(process.env),new SafeLogger('api'));
      try {
        const response=await fetch((await app.getUrl())+'/health/live');
        if(response.status!==200 || (await response.json()).status!=='ok')throw new Error('live failure');
        const ready=await fetch((await app.getUrl())+'/health/ready');
        if(ready.status!==503)throw new Error('ready failure');
        console.log('compiled-http-ok');
      } finally {await app.close();}
    `);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('compiled-http-ok');
    expect(result.stderr).toBe('');
  });

  it.each(['api', 'worker'])('boots the actual %s entrypoint and closes on an internally emitted signal', (role) => {
    // Windows child.kill(SIGTERM) is forceful. This checks the actual compiled
    // handler with an in-process signal simulation; Linux OS-signal proof is deferred.
    const result = run(`
      await import(${JSON.stringify(moduleUrl(`bootstrap/${role}.js`))});
      setTimeout(()=>{process.emit('SIGTERM');process.emit('SIGINT');},100);
    `);
    expect(result.status).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.stdout).toContain('"event":"started"');
    expect(result.stdout.match(/"event":"shutdown_started"/g)).toHaveLength(1);
    expect(result.stdout).toContain('"event":"shutdown_completed"');
    expect(result.stdout).not.toContain('synthetic-secret-canary');
  });

  it.each(['api', 'worker'])('rejects invalid config in the compiled %s entrypoint without secrets', (role) => {
    const result = run(`await import(${JSON.stringify(moduleUrl(`bootstrap/${role}.js`))});`, {
      APP_HOST: 'synthetic-secret-canary', APP_PORT: 'synthetic-secret-canary',
    });
    expect(result.status).toBe(1);
    expect(result.stdout).toContain('"event":"startup_failed"');
    expect(result.stdout).not.toContain('synthetic-secret-canary');
    expect(result.stderr).toBe('');
  });

  it.each(['reject', 'hang'])('bounds shutdown when close() will %s and live handles remain', (behavior) => {
    const result = run(`
      import {registerShutdown} from ${JSON.stringify(moduleUrl('runtime/lifecycle.js'))};
      import {SafeLogger} from ${JSON.stringify(moduleUrl('runtime/safe-logger.js'))};
      setInterval(()=>{},1000);
      const app={close:()=>${behavior === 'reject' ? "Promise.reject(new Error('synthetic-secret-canary'))" : 'new Promise(()=>{})'}};
      registerShutdown(app,{shutdownTimeoutMs:100},new SafeLogger('worker'));
      process.emit('SIGINT');process.emit('SIGTERM');
    `);
    expect(result.status).toBe(1);
    expect(result.stdout.match(/"event":"shutdown_started"/g)).toHaveLength(1);
    expect(result.stdout).toContain('"event":"shutdown_timeout"');
    if (behavior === 'reject') { expect(result.stdout).toContain('"event":"shutdown_failed"'); }
    expect(result.stdout).not.toContain('synthetic-secret-canary');
    expect(result.stderr).toBe('');
  });
});
