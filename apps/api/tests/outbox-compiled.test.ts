import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { Client, Pool } from 'pg';
import { P05_OPERATIONS, P05_PREFIX, P05_ROUTES } from '@fixlevelup/p03-contracts/p05';
import { bootstrapFirstAdmin } from '../src/staff/bootstrap.js';
import { startLauncher, moduleUrl, registryState } from './launcher-harness.js';
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

/** Every canonical P05 route, in the exact method/path the shared contract defines.
 * A release composition must publish none of them; `:id` is a syntactically valid
 * UUID so the probe reaches the router instead of failing path validation. */
const P05_PROBES = P05_OPERATIONS.map((operation) => ({
  operation,
  method: P05_ROUTES[operation].method,
  path: P05_PREFIX + P05_ROUTES[operation].path.replace(':id', '00000000-0000-4000-8000-0000000000a1'),
}));

/** The S2 form-session family that R must keep refusing after the S3 expansion. */
const S2_PROBES = [
  { method: 'POST', path: '/api/v1/public/form-session/browser' },
  { method: 'POST', path: '/api/v1/public/form-sessions' },
  { method: 'POST', path: '/api/v1/public/form-session/csrf' },
  { method: 'POST', path: '/api/v1/public/form-session/revoke' },
  { method: 'POST', path: '/api/v1/public/form-session/consents' },
  { method: 'POST', path: '/api/v1/public/coverage/check' },
  { method: 'GET', path: '/api/v1/public/legal-documents/POLICY' },
] as const;

/** Zero-effect witness: every P05/F/S2 operational table the release must not touch. */
const P05_TABLES = ['requests', 'request_sessions', 'request_events', 'request_command_receipts',
  'request_staff_evidence', 'request_session_submits', 'phone_permission_events', 'request_files',
  'request_channel_choices', 'request_address_review_attempts', 'request_coverage_assessments',
  'request_intake_provenance', 'form_browser_groups', 'form_session_group_memberships',
  'form_throttle_buckets', 'consent_records'] as const;

async function p05Counts(observer: Client): Promise<string> {
  const columns = P05_TABLES.map((table) => `'${table}',(SELECT count(*)::text FROM foundation.${table})`).join(',');
  return (await observer.query<{ counts: string }>(`SELECT jsonb_build_object(${columns})::text AS counts`)).rows[0]?.counts ?? '';
}

/** Real login in the compiled R: exact Origin, the login CSRF sentinel and JSON body,
 * then the session cookie returned by the real `/auth/login` route. */
const rProbeSource = (login: string, password: string, origin: string) => `
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
    const origin = ${JSON.stringify(origin)};
    const status = async (method, path, headers = {}) => {
      const response = await fetch(base + path, {method, headers});
      await response.arrayBuffer();
      return response.status;
    };
    const ready = await status('GET', '/health/ready');
    const anonymous = await status('GET', '/api/v1/staff/self');
    const s2 = [];
    for (const route of ${JSON.stringify(S2_PROBES)}) {
      s2.push(await status(route.method, route.path, {origin, 'content-type': 'application/json'}));
    }
    const p05 = [];
    for (const route of ${JSON.stringify(P05_PROBES)}) {
      p05.push(await status(route.method, route.path, {origin, 'content-type': 'application/json'}));
    }
    const loginResponse = await fetch(base + '/api/v1/auth/login', {method: 'POST',
      headers: {origin, 'content-type': 'application/json', 'x-csrf-token': 'login'},
      body: JSON.stringify({login: ${JSON.stringify(login)}, password: ${JSON.stringify(password)}})});
    const loginBody = await loginResponse.json();
    const cookie = (loginResponse.headers.getSetCookie?.() ?? [])[0]?.split(';')[0] ?? '';
    const auth = {origin, cookie};
    const staffSelf = await status('GET', '/api/v1/staff/self', auth);
    const cities = await status('GET', '/api/v1/settings/service-cities', auth);
    const catalog = await status('GET', '/api/v1/catalog/categories', auth);
    console.log('R_PROBE:' + JSON.stringify({ready, anonymous, s2, p05, login: loginResponse.status,
      staffSelf, cities, catalog, csrf: typeof loginBody?.data?.csrfToken}));
  } finally { process.emit('SIGTERM'); }
`;

it.runIf(process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1')(
  'compiled R admits S3 and publishes none of the 16 P05 or 7 S2 route families, with zero P05 effects and real auth/P03/P04 reads',
  async () => {
    const lab = namedLab();
    await (await lab.openMaintenance()).end();
    const observer = new Client(lab.migrator);
    await observer.connect();
    const login = `r-probe-${randomUUID().slice(0, 8)}`;
    const password = `Synthetic-R-Probe-${randomBytes(12).toString('hex')}`;
    let launcher: Awaited<ReturnType<typeof startLauncher>> | undefined;
    try {
      // The only staff identity is the fixture's reviewed bootstrap administrator; it is
      // created by the migration owner, never by the composition under test.
      const migratorPool = new Pool(lab.migrator);
      try {
        await bootstrapFirstAdmin(migratorPool, { login, password });
      } finally { await migratorPool.end(); }
      // P04 is ordinary (never protected) authority: provision the exact reviewed grant
      // for the bootstrap ADMIN as the operator, so the positive read has a real grant.
      await observer.query(`INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
        SELECT r.id,'catalog.read','GLOBAL' FROM foundation.roles r
        WHERE r.role_type='SYSTEM' AND r.code='ADMIN'`);
      const before = await p05Counts(observer);
      launcher = await startLauncher('API', { runtime: lab.runtime, operator: lab.migrator,
        artifactPaths: artifacts('api.js') });
      expect(launcher.admission.admission.binding.profile).toBe('S3');
      const result = await launcher.launch({ timeoutMs: 90_000, env: {
        NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: '0', SHUTDOWN_TIMEOUT_MS: '5000',
        FIXLEVELUP_LAB_DATABASE: lab.runtime.database, DB_PASSWORD: lab.runtime.password,
        WEB_AUTH_ENABLED: '1', WEB_AUTH_ORIGIN: 'https://127.0.0.1:3100',
        WEB_AUTH_CSRF_SECRET: 'a'.repeat(64), WEB_AUTH_THROTTLE_SECRET: 'b'.repeat(64),
      }, source: rProbeSource(login, password, 'https://127.0.0.1:3100') });
      expect(result.status).toBe(0);
      expect(result.acked).toBe(true);
      expect(result.stderr).toBe('');
      expect(result.stdout).toContain('"event":"shutdown_completed"');
      expect(result.stdout).not.toContain(password);
      const probeLine = result.stdout.split('\n').find((line) => line.startsWith('R_PROBE:'));
      if (!probeLine) { throw new Error('Missing compiled R probe result'); }
      expect(JSON.parse(probeLine.slice('R_PROBE:'.length))).toEqual({
        ready: 200,
        anonymous: 401,
        s2: S2_PROBES.map(() => 404),
        p05: P05_PROBES.map(() => 404),
        login: 200,
        staffSelf: 200,
        cities: 200,
        catalog: 200,
        csrf: 'string',
      });
      // No P05/F/S2 row was created by any probed route.
      expect(await p05Counts(observer)).toBe(before);
    } finally {
      try { await launcher?.close(); } finally { await observer.end(); }
    }
  }, 120_000);

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

  it('rejects a second real OS worker with the same issued proof while the first waits on the registry', async () => {
    const launcher = await namedWorkerLauncher();
    const { issuerGeneration, launchNonce } = launcher.admission.admission.binding.expected;
    const cfg = verifiedControlConfig(namedLab().runtime.database);
    const lock = await openVerifiedControl(cfg);
    const monitor = await openVerifiedControl(cfg);
    let first: ReturnType<typeof launcher.launch> | undefined;
    let locked = false;
    try {
      const holder = (await lock.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0];
      if (!holder) { throw new Error('Missing registry lock holder'); }
      await lock.query('BEGIN');
      locked = true;
      expect((await lock.query('SELECT 1 FROM launch_control.launch_proofs WHERE issuer_generation=$1 AND launch_nonce=$2 FOR UPDATE',
        [issuerGeneration, launchNonce])).rowCount).toBe(1);
      const options = { timeoutMs: 20000, env: baseEnv, source: `${namedWorkerStartup}
        const {OutboxWorker} = await import(${JSON.stringify(moduleUrl('infrastructure/outbox/outbox-worker.js'))});
        await app.get(OutboxWorker).runOnce();
        console.log('AUTHORIZED_WORKER_TICK');
        process.emit('SIGTERM');` };
      first = launcher.launch(options);
      void first.catch(() => undefined);
      await expect.poll(async () => (await monitor.query<{ blocked: boolean }>(`SELECT EXISTS (
        SELECT FROM pg_locks l WHERE NOT l.granted AND $1::int=ANY(pg_blocking_pids(l.pid))) AS blocked`,[holder.pid])).rows[0]?.blocked,
      { timeout: 4500, interval: 20 }).toBe(true);
      // Both real children receive the same signed payload. This supervisor
      // closes the second private channel before it can reach a second CAS;
      // the separate registry test races two backends at the CAS itself.
      const second = launcher.launch(options);
      void second.catch(() => undefined);
      await lock.query('ROLLBACK');
      locked = false;
      const [accepted, refused] = await Promise.all([first,second]);
      expect(accepted.pid).toBeTypeOf('number');
      expect(refused.pid).toBeTypeOf('number');
      expect(refused.pid).not.toBe(accepted.pid);
      expect(accepted).toMatchObject({ acked: true, approvals: 1, exitCode: 0 });
      expect(accepted.stdout.match(/AUTHORIZED_WORKER_TICK/g)).toHaveLength(1);
      expect(refused).toMatchObject({ acked: false, approvals: 0, decision: 'rejected:CAS' });
      expect(refused.stdout).not.toMatch(/AUTHORIZED_WORKER_TICK|"event":"started"/);
      expect((await registryState(issuerGeneration, launchNonce))?.state).toBe('CONSUMED');
    } finally {
      if (locked) { await lock.query('ROLLBACK'); }
      try { await Promise.allSettled([first]); await launcher.close(); }
      finally { await Promise.all([lock.end(),monitor.end()]); }
    }
  }, 60000);

  it('leaves every pending P05 outbox event unclaimed in the compiled R worker (no consumer, no lease, no status change)', async () => {
    // P05 plan §8: the release composition must have no P05 outbox consumer. A pending
    // P05 event must therefore keep its exact row: no lease owner, no generation bump,
    // no attempt count, no status transition, no external call. The event types are the
    // three the S3 schema itself requires for request receipts.
    const launcher = await namedWorkerLauncher();
    const observer = new Client(namedLab().migrator);
    const events = [
      { type: 'REQUEST_CALLBACK_INTENT', payload: { requestId: randomUUID(), version: 1 } },
      { type: 'REQUEST_READY_FOR_ASSIGNMENT', payload: { requestId: randomUUID(), version: 2 } },
      { type: 'REQUEST_EFFECT_RECORDED', payload: { requestId: randomUUID(), version: 3 } },
    ].map((event) => ({ ...event, id: randomUUID(), eventId: randomUUID() }));
    let result;
    try {
      await observer.connect();
      for (const event of events) {
        await observer.query(`INSERT INTO foundation.outbox_events(id,event_id,event_type,payload)
          VALUES ($1,$2,$3,$4::jsonb)`, [event.id, event.eventId, event.type, JSON.stringify(event.payload)]);
      }
      const rows = async () => (await observer.query<{ encoded: string }>(
        `SELECT to_jsonb(e)::text AS encoded FROM foundation.outbox_events e
         WHERE id=ANY($1::uuid[]) ORDER BY event_type`, [events.map((event) => event.id)])).rows.map((row) => row.encoded);
      const before = await rows();
      expect(before).toHaveLength(3);
      // Sanity: all three start PENDING with no lease at all.
      for (const encoded of before) {
        expect(JSON.parse(encoded)).toMatchObject({ status: 'PENDING', lease_owner: null, attempt_count: 0 });
      }
      result = await launcher.launch({
        timeoutMs: 30_000,
        env: { ...baseEnv, FIXLEVELUP_LAB_DATABASE: namedLab().runtime.database, DB_PASSWORD: password, LAUNCH_APPROVAL_TIMEOUT_MS: '10000' },
        source: `
        ${namedWorkerStartup}
        const { OutboxWorker } = await import(${JSON.stringify(moduleUrl('infrastructure/outbox/outbox-worker.js'))});
        await app.get(OutboxWorker).runOnce();
        // A second tick proves the absence of a delayed/queued handler as well.
        await app.get(OutboxWorker).runOnce();
        console.log('WORKER_TICKS_DONE');
        process.emit('SIGTERM');process.emit('SIGINT');
        `,
      });
      // Byte-identical rows: no lease, no attempt, no status change, no payload rewrite.
      expect(await rows()).toEqual(before);
    } finally {
      try { await launcher.close(); } finally { await observer.end(); }
    }
    expect(result.status).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.stdout).toContain('WORKER_TICKS_DONE');
    expect(result.stdout).toContain('"event":"started"');
    expect(result.stdout).toContain('"event":"shutdown_completed"');
    expect(result.stdout).not.toContain('outbox_lease_lost');
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
