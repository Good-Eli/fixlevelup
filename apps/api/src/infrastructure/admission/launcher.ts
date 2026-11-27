/** Isolated launcher contour. The child never receives control credentials. */
import { createRequire } from 'node:module';
import type { ChildProcess } from 'node:child_process';
import { consumeProofWithExpiry, RegistryError } from './registry.js';
import { witnessVisible } from './witness.js';
import type { WitnessKey } from './witness.js';
import { launchBindingOf, matchesLaunchBinding } from './process-admission.js';
import type { LaunchBinding, LauncherMessage } from './process-admission.js';

const apiRequire = createRequire(new URL('../../../package.json', import.meta.url));
const { Client } = apiRequire('pg') as typeof import('pg');

/** Provisioned by the launcher, independently of messages from the child. */
export type ExpectedChild = Omit<LaunchBinding, 'pid' | 'consumerKind'> & {
  readonly consumerKind: 'API' | 'WORKER' | 'TEST';
};

type Db = { readonly host: string; readonly port: number; readonly database: string;
  readonly user: string; readonly password: string };

export interface LauncherDeps {
  readonly app: Db;
  readonly control: Db;
  readonly witnessKeyOf: (instanceId: string) => WitnessKey;
  readonly ackTimeoutMs: number;
}

type Refusal = 'BINDING' | 'WITNESS' | 'CAS' | 'COMMIT_UNKNOWN' | 'EXPIRED' | 'NO_ACK' | 'IPC';
export type LaunchDecision =
  | { readonly approved: true; readonly acked: true; readonly instanceId: string; readonly launchNonce: string }
  | { readonly approved: false; readonly reason: Refusal };

function bounded<T>(result: Promise<T>, ms: number, timeout: T): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return Promise.race([result, new Promise<T>((resolve) => { timer = setTimeout(() => { resolve(timeout); }, ms); })])
    .finally(() => { if (timer) { clearTimeout(timer); } });
}

function timeLimit(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0 || value > 2_147_483_647) { throw new Error('Invalid launch deadline'); }
  return value;
}

function pg(db: Db): import('pg').Client {
  const client = new Client({ ...db, connectionTimeoutMillis: 5000, statement_timeout: 5000, query_timeout: 5000 });
  client.on('error', () => { /* Failed operator sessions are closed; don't leak driver details. */ });
  return client;
}

async function checkWitness(deps: LauncherDeps, bound: LaunchBinding, expiry?: Date): Promise<Refusal | undefined> {
  if (deps.app.database !== bound.database) { return 'BINDING'; }
  const app = pg(deps.app);
  try {
    await app.connect();
    const { rows } = await app.query<{ oid: number; db: string }>(`SELECT current_database() AS db,
      (SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()) AS oid`);
    if (rows[0]?.db !== bound.database || rows[0].oid !== bound.databaseOid) { return 'BINDING'; }
    const live = await witnessVisible(app, deps.witnessKeyOf(bound.instanceId), bound.witnessHolderPid);
    if (!live.visible) { return 'WITNESS'; }
    if (expiry) {
      const clock = await app.query<{ db_now: Date }>('SELECT clock_timestamp() AS db_now');
      const now = clock.rows[0]?.db_now;
      if (!(now instanceof Date) || !Number.isFinite(now.getTime()) || now.getTime() >= expiry.getTime()) { return 'EXPIRED'; }
    }
    return undefined;
  } catch { return 'WITNESS'; }
  finally { await app.end().catch(() => undefined); }
}

/** Deterministic transport boundary, also used by in-process protocol fixtures.
 * A real child may only use superviseLaunch below, which owns the actual IPC. */
export interface LaunchTransport {
  readonly live: () => boolean;
  send(message: LauncherMessage): Promise<boolean>;
  readonly ack: Promise<unknown>;
  readonly receipt: Promise<unknown>;
}

/** Decide exactly one handshake. No reread, rollback or reapproval on COMMIT_UNKNOWN. */
export async function decideLaunch(deps: LauncherDeps, expected: ExpectedChild, handshake: unknown,
  bindingPid: number, transport: LaunchTransport): Promise<LaunchDecision> {
  const bound = Object.freeze(launchBindingOf({ ...expected, pid: bindingPid }));
  const reject = (reason: Refusal): LaunchDecision => ({ approved: false, reason });
  if (!Number.isSafeInteger(bindingPid) || bindingPid <= 0
    || typeof handshake !== 'object' || handshake === null || !('type' in handshake)
    || handshake.type !== 'p05/launch/handshake' || !matchesLaunchBinding(handshake, bound)) { return reject('BINDING'); }
  if (!transport.live()) { return reject('IPC'); }
  const before = await checkWitness(deps, bound);
  if (before) { return reject(before); }
  if (!transport.live()) { return reject('IPC'); }
  const control = pg(deps.control);
  let expiry: Date | undefined;
  try {
    await control.connect();
    if (!transport.live()) { return reject('IPC'); }
    expiry = await consumeProofWithExpiry(control, { issuerGeneration: bound.issuerGeneration,
      launchNonce: bound.launchNonce, expectedDigest: bound.proofDigest,
      binding: { consumerKind: bound.consumerKind, instanceId: bound.instanceId, channelId: bound.channelId } });
  } catch (error) {
    return reject(error instanceof RegistryError && error.code === 'COMMIT_UNKNOWN' ? 'COMMIT_UNKNOWN' : 'CAS');
  } finally { await control.end().catch(() => undefined); }
  if (!expiry) { return reject('CAS'); }
  if (!transport.live()) { return reject('IPC'); }
  const after = await checkWitness(deps, bound, expiry);
  if (after) { return reject(after); }
  const timeout = timeLimit(deps.ackTimeoutMs);
  if (!transport.live() || !await bounded(transport.send({ ...bound, type: 'p05/launch/approve' }), timeout, false)) {
    return reject('IPC');
  }
  const ack = await bounded(transport.ack, timeout, undefined);
  if (typeof ack !== 'object' || ack === null || !('type' in ack) || ack.type !== 'p05/launch/active'
    || !matchesLaunchBinding(ack, bound)) { return reject('NO_ACK'); }
  if (!transport.live()) { return reject('IPC'); }
  const final = await checkWitness(deps, bound, expiry);
  if (final) { return reject(final); }
  if (!transport.live() || !await bounded(transport.send({ ...bound, type: 'p05/launch/activate' }), timeout, false)
    || !transport.live()) { return reject('IPC'); }
  const receipt = await bounded(transport.receipt, timeout, undefined);
  if (typeof receipt !== 'object' || receipt === null || !('type' in receipt) || receipt.type !== 'p05/launch/activated'
    || !matchesLaunchBinding(receipt, bound)) { return reject('NO_ACK'); }
  if (!transport.live()) { return reject('IPC'); }
  return { approved: true, acked: true, instanceId: bound.instanceId, launchNonce: bound.launchNonce };
}

export interface LaunchSupervisor {
  /** A failed launch does not settle until that child is proven closed. */
  readonly activation: Promise<LaunchDecision>;
  /** Observed OS exit, IPC disconnect and closure of owned stdio pipes, not a signal-send result. */
  readonly closed: Promise<void>;
  /** Intentional stop is separate from approving a child after ambiguous delivery. */
  stop(): Promise<void>;
}

const usedChildren = new WeakSet<ChildProcess>();
// This isolated operator never opens another OS channel for the same issued
// binding, even if its CAS was not committed. Restart must issue new facts.
const usedBindings = new Set<string>();

/** Own the lifetime of one concrete, privately forked/spawned Node IPC child. */
export function superviseLaunch(deps: LauncherDeps, expected: ExpectedChild, child: ChildProcess,
  options: { readonly startupTimeoutMs: number; readonly drainTimeoutMs: number;
    readonly onSend?: (message: LauncherMessage) => void }): LaunchSupervisor {
  const startupTimeout = timeLimit(options.startupTimeoutMs);
  const grace = timeLimit(options.drainTimeoutMs);
  timeLimit(deps.ackTimeoutMs);
  const pid = child.pid;
  if (!child.connected || !pid || child.exitCode !== null || child.signalCode !== null || usedChildren.has(child)) {
    throw new Error('Fresh private launch channel required');
  }
  usedChildren.add(child);
  const bound = Object.freeze(launchBindingOf({ ...expected, pid }));
  const key = `${String(bound.issuerGeneration)}/${bound.launchNonce}`;
  const wasUsed = usedBindings.has(key);
  usedBindings.add(key);
  let stopping = false;
  let ended = false;
  let inFlight = false;
  let awaitingAck = false;
  let awaitingReceipt = false;
  let settleAck: (message: unknown) => void = () => undefined;
  let settleReceipt: (message: unknown) => void = () => undefined;
  let settleDecision: (decision: LaunchDecision) => void = () => undefined;
  const ack = new Promise<unknown>((resolve) => { settleAck = resolve; });
  const receipt = new Promise<unknown>((resolve) => { settleReceipt = resolve; });
  const decision = new Promise<LaunchDecision>((resolve) => { settleDecision = resolve; });
  // Node on Windows can omit its aggregate 'close' after the parent
  // disconnects IPC. Observe each owned resource directly.
  const exited = new Promise<void>((resolve) => {
    child.once('exit', () => { ended = true; resolve(); });
  });
  const disconnected = new Promise<void>((resolve) => { child.once('disconnect', resolve); });
  const pipes = child.stdio.flatMap((stream) => stream ? [new Promise<void>((resolve) => {
    if (stream.closed) { resolve(); }
    else { stream.once('close', resolve); }
  })] : []);
  const closed = Promise.all([exited, disconnected, ...pipes]).then(() => undefined);
  let drain: Promise<void> | undefined;
  const live = (): boolean => !stopping && !ended && child.connected && child.exitCode === null && child.signalCode === null;
  const stop = (): Promise<void> => {
    if (drain) { return drain; }
    stopping = true;
    settleAck(undefined);
    settleReceipt(undefined);
    settleDecision({ approved: false, reason: 'IPC' });
    drain = bounded(closed.then(() => true), grace, false).then(async (graceful) => {
      if (graceful) { return; }
      // Exiting but with stdio still open is not a positive drain result.
      // Never release/reuse the binding until close has actually arrived.
      if (child.exitCode === null && child.signalCode === null) { child.kill('SIGKILL'); }
      await closed;
    });
    // Schedule the callback after assigning drain: disconnect/error may fire
    // while closing, and all concurrent callers must share the same barrier.
    if (child.connected) {
      try { child.disconnect(); } catch { /* Fall through to bounded forced stop. */ }
    }
    return drain;
  };
  const send = (message: LauncherMessage): Promise<boolean> => {
    if (!live()) { return Promise.resolve(false); }
    if (message.type === 'p05/launch/approve') { awaitingAck = true; }
    if (message.type === 'p05/launch/activate') { awaitingReceipt = true; }
    return new Promise<boolean>((resolve) => {
      try {
        options.onSend?.(message);
        child.send(message, (error) => { resolve(!error); });
      } catch { resolve(false); }
    });
  };
  child.on('message', (message: unknown) => {
    if (!live() || typeof message !== 'object' || message === null || !('type' in message)) { return; }
    if (message.type === 'p05/launch/active') {
      if (awaitingAck && matchesLaunchBinding(message, bound)) { settleAck(message); }
      return;
    }
    if (message.type === 'p05/launch/activated') {
      if (awaitingReceipt && matchesLaunchBinding(message, bound)) { settleReceipt(message); }
      return;
    }
    if (message.type !== 'p05/launch/handshake' || inFlight || wasUsed) { return; }
    inFlight = true; // same-channel duplicates cannot race a second reject against the winner.
    void decideLaunch(deps, { ...bound, consumerKind: expected.consumerKind }, message, pid, { live, send, ack, receipt }).then(settleDecision,
      () => { settleDecision({ approved: false, reason: 'IPC' }); });
  });
  child.on('error', () => { void stop(); });
  child.once('disconnect', () => { void stop(); });
  child.once('exit', () => { void stop(); });
  const startup = wasUsed ? Promise.resolve<LaunchDecision>({ approved: false, reason: 'CAS' })
    : bounded<LaunchDecision>(decision, startupTimeout, { approved: false, reason: 'IPC' });
  const activation = startup.then(async (result) => {
    if (result.approved) { return result; }
    // A definite rejection may be reported to the child before closing. No
    // message or reread can recover an indeterminate or unacked launch.
    if (result.reason === 'BINDING' || result.reason === 'WITNESS' || result.reason === 'EXPIRED') {
      const observed = await bounded(send({ ...bound, type: 'p05/launch/reject' }), Math.min(250, deps.ackTimeoutMs), false);
      if (observed) { await bounded(closed.then(() => true), Math.min(250, grace), false); }
    }
    await stop();
    return result;
  });
  return { activation, closed, stop };
}
