import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { startLauncher, moduleUrl, registryState } from './launcher-harness.js';

const root = resolve(import.meta.dirname, '../../..');
const baseEnv: NodeJS.ProcessEnv = {
  ...process.env,
  NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0', SHUTDOWN_TIMEOUT_MS: '5000',
  DB_HOST: '127.0.0.1', DB_PORT: '55432', DB_NAME: 'fixlevelup_dev', DB_USER: 'fixlevelup_runtime',
};
const password = /^FIXLEVELUP_RUNTIME_PASSWORD=([a-f0-9]{64})$/m.exec(readFileSync(resolve(root, 'packages/database-tooling/.env'), 'utf8'))?.[1] ?? '';
if (!password) { throw new Error('Local runtime credentials required for compiled worker integration tests'); }

describe('compiled outbox worker lifecycle', () => {
  it('uses the real runtime database and closes worker pools and timers on SIGTERM without exposing credentials', async () => {
    // P05-01 §7 (round 6): the child is the REAL compiled worker entrypoint,
    // spawned with the private IPC channel. The parent acts as the launcher:
    // holds the per-instance witness, issues the one-time proof row, and
    // answers the child's handshake with the production decideLaunch(). The
    // child only reaches its tick after the single approval + ack.
    const launcher = await startLauncher('WORKER');
    let result;
    try {
      result = await launcher.launch({
        timeoutMs: 20_000,
        env: { ...baseEnv, DB_PASSWORD: password, LAUNCH_APPROVAL_TIMEOUT_MS: '10000' },
        source: `
        await import(${JSON.stringify(moduleUrl('bootstrap/worker.js'))});
        setTimeout(()=>{process.emit('SIGTERM');process.emit('SIGINT');},600);
        `,
      });
    } finally {
      await launcher.close();
    }
    expect(result.status).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.stdout).toContain('"event":"started"');
    expect(result.stdout.match(/"event":"shutdown_started"/g)).toHaveLength(1);
    expect(result.stdout).toContain('"event":"shutdown_completed"');
    // Exactly one approval, the launcher's actual decision was approved AND
    // acknowledged (ack bound to this instance), no credential leak.
    expect(result.approvals).toBe(1);
    expect(result.acked).toBe(true);
    expect(result.decision).toBe('approved:acked');
    expect(result.stdout + result.stderr).not.toContain(password);
  }, 60_000);

  it('a child the launcher does not recognize (BINDING mismatch) never starts the worker', async () => {
    // The launcher's trusted binding is corrupted: the production
    // decideLaunch refuses the GENUINE compiled child at the BINDING gate —
    // before any witness check, CAS or approval.
    const launcher = await startLauncher('WORKER');
    let result;
    try {
      result = await launcher.launch({
        timeoutMs: 20_000, corruptBinding: true,
        env: { ...baseEnv, DB_PASSWORD: password, LAUNCH_APPROVAL_TIMEOUT_MS: '10000' },
        source: `
        await import(${JSON.stringify(moduleUrl('bootstrap/worker.js'))});
        setTimeout(()=>{process.emit('SIGTERM');},600);
        `,
      });
    } finally {
      await launcher.close();
    }
    expect(result.status).toBe(1);
    expect(result.stdout).toContain('"event":"admission_denied"');
    expect(result.stdout).not.toContain('"event":"started"');
    expect(result.stdout).not.toContain('"event":"shutdown_started"');
    expect(result.decision).toBe('rejected:BINDING');
    expect(result.approvals).toBe(0);
    expect(result.rejects).toBe(1);
    expect(result.acked).toBe(false);
    // No DB access before the BINDING gate: the proof row stays ISSUED.
    const state = await registryState(Number(launcher.admission.env['LAUNCH_ISSUER_GENERATION']),
      String(launcher.admission.env['LAUNCH_NONCE']));
    expect(state?.state).toBe('ISSUED');
  }, 60_000);

  it('rejects missing database configuration in the compiled worker entrypoint without starting a worker', () => {
    const result = spawnSync(process.execPath, ['--input-type=module', '--eval', `
      await import(${JSON.stringify(moduleUrl('bootstrap/worker.js'))});
    `], { cwd: root, encoding: 'utf8', timeout: 10_000, env: { ...baseEnv, DB_PASSWORD: '' } });
    expect(result.status).toBe(1);
    expect(result.stdout).toContain('"event":"startup_failed"');
    expect(result.stderr).toBe('');
  });

  it('the compiled artifact contains NO issuer of genuine markers outside admitProcess (r8 MUST 1)', () => {
    // r8 audit: completeForTests was previously exported by the BUILT module.
    // Now the only issuer is admitProcess; the compiled module must not
    // export any other way to mint a ProcessAuthorization.
    const distPath = resolve(root, 'apps/api/dist/infrastructure/admission/process-admission.js');
    expect(existsSync(distPath)).toBe(true);
    const built = readFileSync(distPath, 'utf8');
    expect(built).toContain('admitProcess');
    expect(built).not.toContain('completeForTests');
    expect(built).not.toContain('completeViaProtocol');
    // And no separate issuer module exists in the compiled tree at all.
    expect(existsSync(resolve(root, 'apps/api/dist/infrastructure/admission/test-only-issuer.js'))).toBe(false);
  });

  it('the compiled factory boundary refuses a wrapper-shaped authorization that was never issued (r7 MUST 1)', async () => {
    // A compiled JavaScript caller can build the { admission, completed }
    // shape by hand; the boundary must refuse it because the marker was never
    // issued for this (or any) admission. The offline admission itself is
    // GENUINE (a real signed proof loaded through the production loader), so
    // the refusal is attributable to the forged marker alone.
    const launcher = await startLauncher('WORKER');
    let result;
    try {
      result = await launcher.launch({
        timeoutMs: 15_000,
        env: { ...baseEnv, DB_PASSWORD: password, LAUNCH_APPROVAL_TIMEOUT_MS: '10000' },
        source: `
        import {createWorker} from ${JSON.stringify(moduleUrl('bootstrap/factories.js'))};
        import {SafeLogger} from ${JSON.stringify(moduleUrl('runtime/safe-logger.js'))};
        import {loadRuntimeAdmission} from ${JSON.stringify(moduleUrl('infrastructure/admission/runtime-admission.js'))};
        import {loadDatabaseConfig} from ${JSON.stringify(moduleUrl('infrastructure/database/runtime-database.js'))};
        const database = loadDatabaseConfig(process.env);
        const offline = loadRuntimeAdmission(process.env, { database, requiredConsumer: 'WORKER' });
        const forged = { admission: offline, completed: { __p05ProcessAdmissionCompleted: Symbol() } };
        try {
          await createWorker(new SafeLogger('worker'), database, forged);
          console.log('FACTORY_ACCEPTED');
        } catch (e) {
          console.log('FACTORY_REFUSED:' + String(e && e.message ? e.message : e).slice(0, 80));
        }
        setTimeout(()=>{process.exit(0);},200);
        `,
      });
    } finally {
      await launcher.close();
    }
    expect(result.stderr).toBe('');
    expect(result.stdout).toContain('FACTORY_REFUSED:Invalid process authorization');
    expect(result.stdout).not.toContain('FACTORY_ACCEPTED');
    expect(result.stdout).not.toContain('"event":"started"');
  }, 45_000);
});
