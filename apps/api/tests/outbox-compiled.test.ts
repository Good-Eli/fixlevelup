import { randomUUID } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { startLauncher, moduleUrl, registryState } from './launcher-harness.js';
import { Client } from 'pg';
import { loadP05LabTarget } from './p05-lab-target.js';
import { openVerifiedControl, verifiedControlConfig } from './admission-fixture.js';

const root = resolve(import.meta.dirname, '../../..');
const baseEnv: NodeJS.ProcessEnv = {
  NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0', SHUTDOWN_TIMEOUT_MS: '5000',
  DB_HOST: '127.0.0.1', DB_PORT: '55432', DB_NAME: 'fixlevelup_dev', DB_USER: 'fixlevelup_runtime',
};
const password = process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1' ? loadP05LabTarget().runtime.password : '';

const namedLab = () => loadP05LabTarget();
const assertRuntimeOnlyEnv = `
  if (Object.keys(process.env).some((key) => /^(?:FIXLEVELUP_(?:LAB_ORCHESTRATOR|MIGRATOR)|LAUNCH_CONTROL_|POSTGRES_)/.test(key))) {
    throw new Error('Privileged configuration crossed the child boundary');
  }
`;
async function namedWorkerLauncher() {
  const lab = namedLab();
  await (await lab.openMaintenance()).end();
  return await startLauncher('WORKER', { runtime: lab.runtime, operator: lab.migrator, artifactPaths: artifacts('worker.js') });
}
const artifacts = (entry: string) => [resolve(root, 'apps/api/dist/bootstrap', entry),
  resolve(root, 'apps/api/dist/bootstrap/factories.js')];

it.runIf(process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1')('compiled R admits S2 without publishing F routes or creating F rows', async () => {
  const lab = namedLab();
  await (await lab.openMaintenance()).end();
  const observer = new Client(lab.migrator);
  await observer.connect();
  const snapshot = async () => (await observer.query<{ groups: string; anchors: string; consents: string; requests: string }>(`SELECT
    (SELECT count(*)::text FROM foundation.form_browser_groups) AS groups,
    (SELECT count(*)::text FROM foundation.request_sessions) AS anchors,
    (SELECT count(*)::text FROM foundation.consent_records) AS consents,
    (SELECT count(*)::text FROM foundation.requests) AS requests`)).rows;
  try {
    const before = await snapshot();
    const launcher = await startLauncher('API', { runtime: lab.runtime, operator: lab.migrator,
      artifactPaths: artifacts('api.js') });
    try {
      expect(launcher.admission.admission.binding.profile).toBe('S2');
      const result = await launcher.launch({ timeoutMs: 60_000, env: {
        NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0', SHUTDOWN_TIMEOUT_MS: '5000',
        FIXLEVELUP_LAB_DATABASE: lab.runtime.database, DB_PASSWORD: lab.runtime.password,
        WEB_AUTH_ENABLED: '1', WEB_AUTH_ORIGIN: 'https://127.0.0.1:3100',
        WEB_AUTH_CSRF_SECRET: 'a'.repeat(64), WEB_AUTH_THROTTLE_SECRET: 'b'.repeat(64),
      }, source: `
        import {createApi} from ${JSON.stringify(moduleUrl('bootstrap/factories.js'))};
        import {SafeLogger} from ${JSON.stringify(moduleUrl('runtime/safe-logger.js'))};
        import {loadConfig} from ${JSON.stringify(moduleUrl('runtime/config.js'))};
        import {loadWebAuthConfig} from ${JSON.stringify(moduleUrl('auth/web-auth.config.js'))};
        import {loadRuntimeAdmission} from ${JSON.stringify(moduleUrl('infrastructure/admission/runtime-admission.js'))};
        import {admitProcess} from ${JSON.stringify(moduleUrl('infrastructure/admission/process-admission.js'))};
        ${assertRuntimeOnlyEnv}
        const database = { host: '127.0.0.1', port: 55432, user: 'fixlevelup_runtime',
          database: process.env.FIXLEVELUP_LAB_DATABASE, password: process.env.DB_PASSWORD };
        const admission = loadRuntimeAdmission(process.env, {database, requiredConsumer: 'API'});
        const authorization = await admitProcess(admission, { database, approvalTimeoutMs: 10000 });
        const config = loadConfig(process.env);
        const logger = new SafeLogger('api');
        const app = await createApi(config, logger, database, loadWebAuthConfig(process.env), undefined, authorization);
        const { registerShutdown } = await import(${JSON.stringify(moduleUrl('runtime/lifecycle.js'))});
        registerShutdown(app, config, logger);
        try {
          const base = await app.getUrl();
          const check = async (method, path) => {
            const response = await fetch(base + path, {method});
            await response.arrayBuffer();
            return response.status;
          };
          const ready = await check('GET', '/health/ready');
          const staff = await check('GET', '/api/v1/staff/self');
          const routes = ['form-session/browser', 'form-sessions', 'form-session/csrf', 'form-session/revoke',
            'form-session/consents', 'coverage/check', 'legal-documents/POLICY'];
          const statuses = [];
          for (const route of routes) statuses.push(await check(route.startsWith('legal-documents/') ? 'GET' : 'POST', '/api/v1/public/' + route));
          console.log('R_PROBE:' + JSON.stringify({ready, staff, statuses}));
        } finally { process.emit('SIGTERM'); }
      ` });
      expect(result.status).toBe(0);
      expect(result.acked).toBe(true);
      expect(result.stdout).toContain('"event":"shutdown_completed"');
      expect(result.stdout).toContain('R_PROBE:' + JSON.stringify({ ready: 200, staff: 401, statuses: Array(7).fill(404) }));
      expect(await snapshot()).toEqual(before);
    } finally { await launcher.close(); }
  } finally { await observer.end(); }
}, 90_000);

const namedWorkerStartup = `
  import {createWorker} from ${JSON.stringify(moduleUrl('bootstrap/factories.js'))};
  import {SafeLogger} from ${JSON.stringify(moduleUrl('runtime/safe-logger.js'))};
  import {loadConfig} from ${JSON.stringify(moduleUrl('runtime/config.js'))};
  import {registerShutdown} from ${JSON.stringify(moduleUrl('runtime/lifecycle.js'))};
  import {loadRuntimeAdmission} from ${JSON.stringify(moduleUrl('infrastructure/admission/runtime-admission.js'))};
  import {admitProcess} from ${JSON.stringify(moduleUrl('infrastructure/admission/process-admission.js'))};
  ${assertRuntimeOnlyEnv}
  const logger = new SafeLogger('worker');
  const config = loadConfig(process.env);
  const database = {host: '127.0.0.1', port: 55432, user: 'fixlevelup_runtime',
    database: process.env.FIXLEVELUP_LAB_DATABASE, password: process.env.DB_PASSWORD};
  const admission = loadRuntimeAdmission(process.env, {database, requiredConsumer: 'WORKER'});
  let authorization;
  try {
    authorization = await admitProcess(admission, { database, approvalTimeoutMs: 10000 });
  } catch {
    logger.event('admission_denied');
    process.exit(1);
  }
  const app = await createWorker(logger, database, authorization);
  registerShutdown(app, config, logger);
  logger.event('started');
`;

describe.runIf(process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1')('compiled outbox worker lifecycle', () => {
  it('uses the real runtime database and closes worker pools and timers on SIGTERM without exposing credentials', async () => {
    // This child uses the compiled worker factory on a named lab target,
    // not the dev-only environment loader. The parent owns the real private IPC:
    // holds the per-instance witness, issues the one-time proof row, and
    // answers the child's handshake with the production decideLaunch(). The
    // child only reaches its tick after the single approval + ack.
    const launcher = await namedWorkerLauncher();
    const { binding } = launcher.admission.admission;
    const event = randomUUID();
    const observer = new Client(namedLab().migrator);
    const controlConfig = verifiedControlConfig(binding.database);
    const control = await openVerifiedControl(controlConfig);
    // pg_stat_activity can retain the snapshot of the transaction holding the
    // barrier. Sample the wait from a third, autocommit control connection.
    const monitor = await openVerifiedControl(controlConfig);
    let pending: ReturnType<typeof launcher.launch> | undefined;
    let locked = false;
    let result;
    try {
      await observer.connect();
      await observer.query(`INSERT INTO foundation.outbox_events(id,event_id,event_type,payload) VALUES ($1,$2,'P05_TEST_PENDING',$3::jsonb)`,
        [event, randomUUID(), JSON.stringify({ synthetic: true })]);
      const row = async () => (await observer.query<{ encoded: string }>(
        'SELECT to_jsonb(e)::text AS encoded FROM foundation.outbox_events e WHERE id=$1', [event])).rows[0]?.encoded;
      const original = await row();
      expect(original).toBeDefined();
      const holderPid = (await control.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
      await control.query('BEGIN');
      locked = true;
      await control.query('SELECT 1 FROM launch_control.launch_proofs WHERE issuer_generation=$1 AND launch_nonce=$2 FOR UPDATE',
        [binding.expected.issuerGeneration, binding.expected.launchNonce]);
      let repeated = false;
      pending = launcher.launch({
        repeatFirstHandshake: () => { repeated = true; },
        timeoutMs: 20_000,
        env: { ...baseEnv, FIXLEVELUP_LAB_DATABASE: namedLab().runtime.database, DB_PASSWORD: password, LAUNCH_APPROVAL_TIMEOUT_MS: '10000' },
        source: `
        ${namedWorkerStartup}
        const { OutboxWorker } = await import(${JSON.stringify(moduleUrl('infrastructure/outbox/outbox-worker.js'))});
        await app.get(OutboxWorker).runOnce();
        process.emit('SIGTERM');process.emit('SIGINT');
        `,
      });
      void pending.catch(() => undefined);
      await expect.poll(async () => repeated && (await monitor.query<{ waiting: boolean }>(`SELECT EXISTS(
        SELECT FROM pg_stat_activity WHERE datname=current_database() AND $1::int=ANY(pg_blocking_pids(pid))) AS waiting`, [holderPid])).rows[0]?.waiting,
      { timeout: 7_000, interval: 25 }).toBe(true);
      await control.query('ROLLBACK');
      locked = false;
      result = await pending;
      expect(await row()).toBe(original);
      expect((await registryState(binding.expected.issuerGeneration, binding.expected.launchNonce))?.state).toBe('CONSUMED');
    } finally {
      if (locked) { await control.query('ROLLBACK'); }
      await Promise.allSettled([pending]);
      try { await launcher.close(); } finally { await Promise.all([control.end(), monitor.end(), observer.end()]); }
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
    const launcher = await namedWorkerLauncher();
    let result;
    try {
      result = await launcher.launch({
        timeoutMs: 20_000, corruptBinding: true,
        env: { ...baseEnv, FIXLEVELUP_LAB_DATABASE: namedLab().runtime.database, DB_PASSWORD: password, LAUNCH_APPROVAL_TIMEOUT_MS: '10000' },
        source: `
        ${namedWorkerStartup}
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
    `], { cwd: root, encoding: 'utf8', timeout: 30_000, env: { ...baseEnv, DB_PASSWORD: '' } });
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
    const launcher = await namedWorkerLauncher();
    let result;
    try {
      result = await launcher.launch({
        timeoutMs: 15_000,
        env: { ...baseEnv, FIXLEVELUP_LAB_DATABASE: namedLab().runtime.database, DB_PASSWORD: password, LAUNCH_APPROVAL_TIMEOUT_MS: '10000' },
        source: `
        import {createWorker} from ${JSON.stringify(moduleUrl('bootstrap/factories.js'))};
        import {SafeLogger} from ${JSON.stringify(moduleUrl('runtime/safe-logger.js'))};
        import {loadRuntimeAdmission} from ${JSON.stringify(moduleUrl('infrastructure/admission/runtime-admission.js'))};
        const database = {host: '127.0.0.1', port: 55432, user: 'fixlevelup_runtime',
          database: process.env.FIXLEVELUP_LAB_DATABASE, password: process.env.DB_PASSWORD};
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
