import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { Client } from 'pg';
import { describe, expect, it, vi } from 'vitest';
import { decideLaunch, superviseLaunch } from '../src/infrastructure/admission/launcher.js';
import type { ExpectedChild, LauncherDeps } from '../src/infrastructure/admission/launcher.js';
import type { LauncherMessage } from '../src/infrastructure/admission/process-admission.js';
import { readRegistryState } from '../src/infrastructure/admission/registry.js';
import { witnessKeyForInstance } from '../src/infrastructure/admission/runtime-admission.js';
import { issueVerifiedLaunch, openVerifiedControl, verifiedControlConfig } from './admission-fixture.js';
import type { AdmissionHandle } from './admission-fixture.js';
import { moduleUrl } from './launcher-harness.js';
import { loadP05LabTarget } from './p05-lab-target.js';

const live = process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1'
  && process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1';
const HANDSHAKE = 'p05/launch/handshake';
const ACK = 'p05/launch/active';
const RECEIPT = 'p05/launch/activated';
const APPROVE = 'p05/launch/approve';
const ACTIVATE = 'p05/launch/activate';
const TICK = 'p05/test/tick';
const kindOf = (value: unknown) => typeof value === 'object' && value !== null && 'type' in value ? value.type : undefined;

function frame(child: ChildProcess, type: string) {
  return new Promise<unknown>(resolve => {
    const finish = (message: unknown) => {
      child.off('message', pick);
      child.off('exit', ended);
      resolve(message);
    };
    const ended = () => { finish(undefined); };
    const pick = (message: unknown) => { if (kindOf(message) === type) { finish(message); } };
    child.on('message', pick);
    child.once('exit', ended);
  });
}

async function scope() {
  const lab = loadP05LabTarget();
  await (await lab.openMaintenance()).end();
  const controlConfig = verifiedControlConfig(lab.runtime.database);
  const operator = new Client(lab.migrator);
  const clients = [operator];
  const handles: AdmissionHandle[] = [];
  const children: { child: ChildProcess; closed: Promise<void> }[] = [];
  const close = async () => {
    try {
      for (const { child, closed } of children) {
        if (child.connected) { child.disconnect(); }
        const watchdog = setTimeout(() => { if (child.exitCode === null && child.signalCode === null) { child.kill('SIGKILL'); } }, 3500);
        try { await closed; } finally { clearTimeout(watchdog); }
      }
    } finally {
      try { for (const handle of handles.reverse()) { await handle.release(); } }
      finally { await Promise.all(clients.map(client => client.end())); }
    }
  };
  try {
    await operator.connect();
    const monitor = await openVerifiedControl(controlConfig);
    clients.push(monitor);
    const deps: LauncherDeps = { app: lab.migrator, control: controlConfig, witnessKeyOf: witnessKeyForInstance, ackTimeoutMs: 1600 };
    const holder = new Client(lab.migrator);
    clients.push(holder);
    await holder.connect();
    const handle = await issueVerifiedLaunch(holder, lab.runtime, { consumerKind: 'WORKER' });
    handles.push(handle);
    const { binding, proofDigest } = handle.admission;
    const expected: ExpectedChild = { ...binding.expected, consumerKind: 'WORKER', database: binding.database, databaseOid: binding.databaseOid,
      profile: binding.profile, role: binding.role, proofDigest, witnessHolderPid: binding.witnessHolderPid };
    const eventType = `P05_DELIVERY_${randomUUID()}`;
    const launchArgs = [expected.issuerGeneration, expected.launchNonce] as const;
    const state = () => readRegistryState(monitor, ...launchArgs);
    const event = randomUUID();
    await operator.query('INSERT INTO foundation.outbox_events(id,event_id,event_type,payload) VALUES ($1,$2,$3,$4)',
      [event, randomUUID(), eventType, JSON.stringify({ synthetic: true })]);
    const effect = async () => (await operator.query<{ status: string; generation: string; count: number }>(
      `SELECT status,lease_generation::text AS generation,attempt_count AS count FROM foundation.outbox_events WHERE id=$1`, [event])).rows[0];

    function launch() {
      const child = spawn(process.execPath, ['--input-type=module', '--eval', `
        import {loadRuntimeAdmission} from ${JSON.stringify(moduleUrl('infrastructure/admission/runtime-admission.js'))};
        import {admitProcess} from ${JSON.stringify(moduleUrl('infrastructure/admission/process-admission.js'))};
        import {OutboxWorker} from ${JSON.stringify(moduleUrl('infrastructure/outbox/outbox-worker.js'))};
        import {SafeLogger} from ${JSON.stringify(moduleUrl('runtime/safe-logger.js'))};
        const database={host:'127.0.0.1',port:55432,database:process.env.DB_NAME,user:'fixlevelup_runtime',password:process.env.DB_PASSWORD};
        try {
          const proof=loadRuntimeAdmission(process.env,{database,requiredConsumer:'WORKER'});
          const authorization=await admitProcess(proof,{database,approvalTimeoutMs:10000});
          let calls=0;
          const worker=new OutboxWorker(database,new SafeLogger('worker'),new Map([[${JSON.stringify(eventType)},()=>{ calls++; }]]),authorization);
          process.on('SIGTERM',()=>{void worker.onModuleDestroy().finally(()=>process.exit(0));});
          worker.onApplicationBootstrap();
          await worker.runOnce();
          process.send?.({type:${JSON.stringify(TICK)},calls});
        } catch {process.exit(43);}
      `], { env: { ...handle.env, DB_NAME: lab.runtime.database, DB_PASSWORD: lab.runtime.password },
        stdio: ['ignore', 'pipe', 'pipe', 'ipc'], timeout: 20_000, killSignal: 'SIGKILL' });
      if (!child.stdout || !child.stderr) { throw new Error('Missing owned child pipes'); }
      child.stdout.resume();
      child.stderr.resume();
      // Aggregate ChildProcess.close can be absent after a parent-initiated IPC
      // disconnect. Track each owned resource, as the shipped supervisor does.
      const exited = new Promise<void>((resolve, reject) => {
        child.once('error', reject);
        child.once('exit', () => { resolve(); });
      });
      const disconnected = new Promise<void>(resolve => { child.once('disconnect', resolve); });
      const pipes = [child.stdout, child.stderr].map(pipe => new Promise<void>(resolve => { pipe.once('close', resolve); }));
      const closed = Promise.all([exited, disconnected, ...pipes]).then(() => undefined);
      children.push({ child, closed });
      expect(child.pid).toBeGreaterThan(0);
      return { child, closed };
    }
    return { controlConfig, monitor, expected, deps, launchArgs, state, effect, launch, close };
  } catch (error) { await close(); throw error; }
}

const untouched = { status: 'PENDING', generation: '0', count: 0 };

describe.runIf(live)('P05 native launch delivery and uncertainty', () => {
  it('queues two valid deliveries of the same native handshake on one registry row and starts one worker', { timeout: 35_000 }, async () => {
    const f = await scope();
    const barrier = await openVerifiedControl(f.controlConfig);
    try {
      const blockerPid = (await barrier.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
      expect(blockerPid).toBeGreaterThan(0);
      await barrier.query('BEGIN');
      expect((await barrier.query(`SELECT 1 FROM launch_control.launch_proofs
        WHERE issuer_generation=$1 AND launch_nonce=$2 FOR UPDATE`, [...f.launchArgs])).rowCount).toBe(1);
      const { child } = f.launch();
      if (!child.pid) { throw new Error('Missing native consumer PID'); }
      const sent: { delivery: number; frame: LauncherMessage['type'] }[] = [];
      const tick = frame(child, TICK);
      const ack = frame(child, ACK);
      const receipt = frame(child, RECEIPT);
      const handshake = await frame(child, HANDSHAKE);
      // These deliveries originate from the ONE bound child's actual IPC frame.
      // At the transport edge only, deliver it twice in order to exercise both
      // calls into the real launcher decision (including its own PG connections).
      // This is deliberately not the supervisor's early duplicate-channel check.
      const dispatch = (delivery: number) => decideLaunch(f.deps, f.expected, structuredClone(handshake), child.pid ?? 0, {
        live: () => child.connected, ack, receipt,
        send: message => new Promise<boolean>(resolve => {
          sent.push({ delivery, frame: message.type });
          child.send(message, error => { resolve(!error); });
        }),
      });
      const racing = Promise.all([dispatch(1), dispatch(2)]);
      void racing.catch(() => undefined);
      await expect.poll(async () => (await f.monitor.query<{ contenders: number }>(`WITH RECURSIVE queue(pid) AS (
        SELECT $1::int UNION
        SELECT a.pid FROM pg_stat_activity a JOIN queue q ON q.pid=ANY(pg_blocking_pids(a.pid))
        WHERE a.datname=current_database() AND a.query LIKE 'SELECT state, proof_digest FROM launch_control.launch_proofs%'
        AND a.query LIKE '%FOR UPDATE') SELECT count(*)::int-1 AS contenders FROM queue`, [blockerPid])).rows[0]?.contenders,
      { timeout: 3500, interval: 20 }).toBe(2);
      expect(await f.state()).toMatchObject({ state: 'ISSUED', consumed_at: null });
      expect(sent).toEqual([]);
      expect(await f.effect()).toEqual(untouched);
      await barrier.query('ROLLBACK');
      const decisions = await racing;
      expect(decisions.filter(d => d.approved)).toEqual([{ approved: true, acked: true,
        instanceId: f.expected.instanceId, launchNonce: f.expected.launchNonce }]);
      expect(decisions.filter(d => !d.approved)).toEqual([{ approved: false, reason: 'CAS' }]);
      expect(sent.map(entry => entry.frame)).toEqual([APPROVE, ACTIVATE]);
      expect(new Set(sent.map(entry => entry.delivery)).size).toBe(1);
      const consumed = await f.state();
      expect(consumed).toMatchObject({ state: 'CONSUMED', proof_digest: f.expected.proofDigest });
      expect(consumed?.consumed_at).toBeInstanceOf(Date);
      expect(await tick).toEqual({ type: TICK, calls: 1 });
      expect(await f.effect()).toEqual({ status: 'EXPANDED', generation: '1', count: 1 });
      expect(child.connected).toBe(true); // losing CAS did not close the winner
    } finally { await barrier.end(); await f.close(); }
  });

  it.each([ACK, RECEIPT])('closes the original child when %s is lost; never admits a replacement on that proof',
    { timeout: 35_000 }, async drop => {
      const f = await scope();
      try {
        const { child } = f.launch();
        let dropped = 0;
        // Drop exactly one actual inbound IPC frame at the parent's event edge.
        // Every other message and all native close events pass through unmodified.
        const emit: (event: string | symbol, ...args: unknown[]) => boolean = child.emit.bind(child);
        const fault = vi.spyOn(child, 'emit').mockImplementation((event: string | symbol, ...args: unknown[]) => {
          if (event === 'message' && kindOf(args[0]) === drop) { dropped++; return true; }
          return emit(event, ...args);
        });
        const sent: string[] = [];
        const one = superviseLaunch(f.deps, f.expected, child, { startupTimeoutMs: 12_000, drainTimeoutMs: 2500,
          onSend: msg => { sent.push(msg.type); } });
        try {
          expect(await one.activation).toEqual({ approved: false, reason: 'NO_ACK' });
          await one.closed;
          expect(child.connected).toBe(false);
          expect(dropped).toBe(1);
          expect(sent).toEqual(drop === ACK ? [APPROVE] : [APPROVE, ACTIVATE]);
          const consumed = await f.state();
          expect(consumed?.state).toBe('CONSUMED');
          expect(consumed?.consumed_at).toBeInstanceOf(Date);
          const effect = await f.effect();
          if (drop === ACK) { expect(effect).toEqual(untouched); }
          else { expect(['0', '1']).toContain(effect?.generation); } // an already started effect need not roll back
          const next = f.launch().child;
          const replacement = superviseLaunch(f.deps, f.expected, next, { startupTimeoutMs: 8000, drainTimeoutMs: 2500 });
          expect(await replacement.activation).toEqual({ approved: false, reason: 'CAS' });
          await replacement.closed;
          expect(await f.effect()).toEqual(effect);
        } finally { fault.mockRestore(); await one.stop(); }
      } finally { await f.close(); }
    });

  it.each(['COMMIT', 'ROLLBACK'] as const)('losing confirmation after actual registry %s closes the channel, no approval or retry',
    { timeout: 35_000 }, async completion => {
      const f = await scope();
      try {
        const { child } = f.launch();
        let attempts = 0;
        let observed: string | undefined;
        const driver = Object.getOwnPropertyDescriptor(Client.prototype, 'query')?.value as
          ((this: Client, ...args: unknown[]) => unknown) | undefined;
        if (!driver) { throw new Error('Missing real PG driver'); }
        Client.prototype.query = function (this: Client, ...args: unknown[]): unknown {
          if (this.database !== f.controlConfig.database || this.user !== f.controlConfig.user || args[0] !== 'COMMIT') {
            return Reflect.apply(driver, this, args);
          }
          attempts++;
          const result: unknown = Reflect.apply(driver, this, [completion]);
          return Promise.resolve(result).then((reply: unknown) => {
            if (reply && typeof reply === 'object' && 'command' in reply && typeof reply.command === 'string') { observed = reply.command; }
            throw new Error('Synthetic confirmation lost');
          });
        } as Client['query'];
        const sent: string[] = [];
        const supervisor = superviseLaunch(f.deps, f.expected, child, { startupTimeoutMs: 12_000, drainTimeoutMs: 2500,
          onSend: msg => { sent.push(msg.type); } });
        try {
          expect(await supervisor.activation).toEqual({ approved: false, reason: 'COMMIT_UNKNOWN' });
          await supervisor.closed;
          expect(child.connected).toBe(false);
          expect(attempts).toBe(1);
          expect(observed).toBe(completion);
          expect(sent).toEqual([]);
          expect(await f.state()).toMatchObject({ state: completion === 'COMMIT' ? 'CONSUMED' : 'ISSUED' });
          expect(await f.effect()).toEqual(untouched);
          const replacement = superviseLaunch(f.deps, f.expected, f.launch().child, { startupTimeoutMs: 8000, drainTimeoutMs: 2500 });
          expect(await replacement.activation).toEqual({ approved: false, reason: 'CAS' });
          await replacement.closed;
          expect(attempts).toBe(1);
          expect(await f.effect()).toEqual(untouched);
        } finally { Client.prototype.query = driver as Client['query']; await supervisor.stop(); }
      } finally { await f.close(); }
    });
});
