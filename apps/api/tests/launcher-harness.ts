/**
 * Real launcher→child IPC harness for compiled-process tests (P05-01 §7,
 * audit round 6 MUST 5): spawns a compiled child with the Node IPC channel,
 * acts as the LAUNCHER side, and proves the child only starts after the
 * single approval.
 *
 * The parent process is the launcher: it holds the witness, provisions the
 * one-time registry row, and answers the child's handshake with the real
 * decideLaunch() — the same code the production launcher runs. Every
 * decision (approve or reject) passes through it; tests may corrupt the
 * launcher's trusted binding to exercise the BINDING gate on a genuine
 * compiled child.
 */
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Client } from 'pg';
import type { ChildProcess } from 'node:child_process';
import { admitFixture } from './admission-fixture.js';
import type { AdmittedHandle } from './admission-fixture.js';
import { ensureLaunchRegistry, issueProof, readRegistryState } from '../src/infrastructure/admission/registry.js';
import { decideLaunch } from '../src/infrastructure/admission/launcher.js';
import { witnessKeyForInstance } from '../src/infrastructure/admission/runtime-admission.js';
import type { ChildHandshake } from '../src/infrastructure/admission/process-admission.js';

const root = resolve(import.meta.dirname, '../../..');
export const moduleUrl = (path: string): string => pathToFileURL(resolve(root, 'apps/api/dist', path)).href;

export interface LaunchOutcome {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly approvals: number;
  readonly rejects: number;
  /** True only when an activation ack bound to THIS instance was received. */
  readonly acked: boolean;
  readonly exitCode: number | null;
  /** The launcher's actual LaunchDecision for this child. */
  readonly decision: string;
}

export interface LaunchOptions {
  /** Child source (ESM) evaluated with `node --input-type=module --eval`. */
  readonly source: string;
  readonly env: NodeJS.ProcessEnv;
  readonly timeoutMs: number;
  /** Corrupts the launcher's trusted binding: the production decideLaunch
   * must refuse the genuine child at the BINDING gate (no DB access). */
  readonly corruptBinding?: boolean;
}

export interface LauncherHandle {
  readonly admission: AdmittedHandle;
  launch(options: LaunchOptions): Promise<LaunchOutcome>;
  close(): Promise<void>;
}

function migratorPassword(): string {
  const tooling = readFileSync(resolve(root, 'packages/database-tooling/.env'), 'utf8');
  const password = /^FIXLEVELUP_MIGRATOR_PASSWORD=([a-f0-9]{64})$/m.exec(tooling)?.[1];
  if (!password) { throw new Error('Local migrator credentials required for the launcher harness'); }
  return password;
}

/**
 * Starts a real launcher for the dev database: holds the witness (per-instance
 * key), provisions launch_control on the SAME instance (isolated equivalent
 * of the control DB; its separate ownership/role isolation is proven in
 * requests-admission.test.ts), and issues the one-time row for the compiled
 * child's proof.
 */
export async function startLauncher(consumerKind: 'API' | 'WORKER', database = 'fixlevelup_dev'): Promise<LauncherHandle> {
  const password = (() => {
    const source = readFileSync(resolve(root, 'packages/database-tooling/.env'), 'utf8');
    return /^FIXLEVELUP_RUNTIME_PASSWORD=([a-f0-9]{64})$/m.exec(source)?.[1] ?? '';
  })();
  const holder = new Client({ host: '127.0.0.1', port: 55432, database, user: 'fixlevelup_runtime', password });
  await holder.connect();
  const admission = await admitFixture(holder, database, consumerKind);
  const control = new Client({ host: '127.0.0.1', port: 55432, database, user: 'fixlevelup_migrator', password: migratorPassword() });
  await control.connect();
  await ensureLaunchRegistry(control);
  const generation = Number(admission.env['LAUNCH_ISSUER_GENERATION']);
  const nonce = String(admission.env['LAUNCH_NONCE']);
  const instanceId = String(admission.env['LAUNCH_INSTANCE_ID']);
  const channelId = String(admission.env['LAUNCH_CHANNEL_ID']);
  await issueProof(control, { issuerGeneration: generation, launchNonce: nonce, proofDigest: admission.admission.proofDigest,
    consumerKind, instanceId, channelId, expiresAt: new Date(Date.now() + 300_000) });
  const launcherDeps = { app: { host: '127.0.0.1', port: 55432, database, user: 'fixlevelup_migrator', password: migratorPassword() },
    control: { host: '127.0.0.1', port: 55432, database, user: 'fixlevelup_migrator', password: migratorPassword() },
    witnessKeyOf: witnessKeyForInstance, ackTimeoutMs: 5_000 };
  const expected = { instanceId, launchNonce: nonce, consumerKind, proofDigest: admission.admission.proofDigest,
    issuerGeneration: generation, witnessHolderPid: admission.admission.binding.witnessHolderPid, channelId };
  return {
    admission,
    launch: (options) => new Promise<LaunchOutcome>((resolveLaunch) => {
      // The launcher's OWN expectations; a test may corrupt them to prove the
      // trusted-binding gate (BINDING) through the production decideLaunch.
      const trusted = options.corruptBinding === true
        ? { ...expected, launchNonce: randomUUID() }
        : expected;
      const child: ChildProcess = spawn(process.execPath, ['--input-type=module', '--eval', options.source], {
        cwd: root, env: { ...options.env, ...admission.env }, stdio: ['ignore', 'pipe', 'pipe', 'ipc'], timeout: options.timeoutMs,
      });
      let stdout = '';
      let stderr = '';
      let approvals = 0;
      let rejects = 0;
      let acked = false;
      let decision: string | undefined;
      let ackResolver: ((acked: boolean) => void) | undefined;
      // The in-flight launcher decision: on child exit the harness waits for
      // it to settle before reporting, so an ack deadline still pending when
      // the child dies is reported as its real outcome (never 'no-handshake').
      let inFlight: Promise<void> = Promise.resolve();
      child.stdout?.on('data', (chunk: Buffer) => { stdout += chunk.toString('utf8'); });
      child.stderr?.on('data', (chunk: Buffer) => { stderr += chunk.toString('utf8'); });
      child.on('message', (message: unknown) => {
        if (message === null || typeof message !== 'object' || !('type' in message)) { return; }
        const typed = message as Record<string, unknown>;
        if (typed['type'] === 'p05/launch/active') {
          // The activation ack is only counted when bound to THIS instance.
          acked = typed['instanceId'] === expected.instanceId;
          ackResolver?.(acked);
          return;
        }
        if (typed['type'] !== 'p05/launch/handshake') { return; }
        // Every decision goes through the production decideLaunch: the
        // trusted-binding gate, witness gate, CAS, post-COMMIT checks and the
        // launcher's own ack deadline all run for the real compiled child.
        inFlight = decideLaunch(launcherDeps, trusted, message as ChildHandshake,
          (iid, n) => { approvals += 1; child.send({ type: 'p05/launch/approve', instanceId: iid, launchNonce: n }); },
          (iid) => { rejects += 1; child.send({ type: 'p05/launch/reject', instanceId: iid }); },
          () => new Promise<boolean>((resolveAck) => {
            if (acked) { resolveAck(true); return; }
            ackResolver = resolveAck;
          }),
        ).then((d) => { decision = d.approved ? `approved:${d.acked ? 'acked' : 'unacked'}` : `rejected:${d.reason}`; },
          () => { decision = 'launcher-error'; });
      });
      child.on('exit', (code) => {
        void inFlight.then(() => {
          resolveLaunch({ status: code, stdout, stderr, approvals, rejects, acked, exitCode: code,
            decision: decision ?? 'no-handshake' });
        });
      });
      child.on('error', () => { resolveLaunch({ status: null, stdout, stderr, approvals, rejects, acked, exitCode: null,
        decision: decision ?? 'spawn-error' }); });
    }),
    close: async () => {
      await admission.release();
      await control.end().catch(() => undefined);
      await holder.end().catch(() => undefined);
    },
  };
}

/** Exposed for the test's registry-state assertions. */
export async function registryState(generation: number, nonce: string, database = 'fixlevelup_dev') {
  const client = new Client({ host: '127.0.0.1', port: 55432, database, user: 'fixlevelup_migrator', password: migratorPassword() });
  await client.connect();
  try { return await readRegistryState(client, generation, nonce); }
  finally { await client.end().catch(() => undefined); }
}
