/** Compiled-child IPC harness for the attested lab and its external control registry. */
import { spawn } from 'node:child_process';
import { lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Client } from 'pg';
import type { ChildProcess } from 'node:child_process';
import { issueVerifiedLaunch, openVerifiedControl, verifiedControlConfig } from './admission-fixture.js';
import type { AdmissionHandle } from './admission-fixture.js';
import { readRegistryState } from '../src/infrastructure/admission/registry.js';
import type { DatabaseConfig } from '../src/infrastructure/database/runtime-database.js';
import { superviseLaunch } from '../src/infrastructure/admission/launcher.js';
import type { LaunchSupervisor } from '../src/infrastructure/admission/launcher.js';
import { witnessKeyForInstance } from '../src/infrastructure/admission/runtime-admission.js';

const root = resolve(import.meta.dirname, '../../..');
export const moduleUrl = (path: string): string => pathToFileURL(resolve(root, 'apps/api/dist', path)).href;

export interface LaunchOutcome {
  readonly pid: number | undefined;
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
  /** Re-deliver only the genuine frame received on this child’s own channel. */
  readonly repeatFirstHandshake?: () => void;
}

export interface LauncherHandle {
  readonly admission: AdmissionHandle;
  launch(options: LaunchOptions): Promise<LaunchOutcome>;
  close(): Promise<void>;
}

type LauncherTarget = {
  readonly runtime: DatabaseConfig;
  readonly operator: { readonly host: string; readonly port: number; readonly database: string;
    readonly user: string; readonly password: string };
  readonly artifactPaths: readonly string[];
  readonly expectedMigrations?: readonly string[];
  /** Only TEST may pin a separate emitted composition. */
  readonly isolatedArtifactRoot?: string;
};

const CHILD_ENV = ['NODE_ENV', 'APP_HOST', 'APP_PORT', 'SHUTDOWN_TIMEOUT_MS', 'LAUNCH_APPROVAL_TIMEOUT_MS',
  'WEB_AUTH_ENABLED', 'WEB_AUTH_ORIGIN', 'WEB_AUTH_CSRF_SECRET', 'WEB_AUTH_THROTTLE_SECRET'] as const;

function artifactDigestOf(paths: readonly string[], dist: string): string {
  if (paths.length === 0) { throw new Error('No compiled launch artifact was pinned'); }
  if (!lstatSync(dist).isDirectory() || relative(realpathSync(root), realpathSync(dist)) !== relative(root, dist)) {
    throw new Error('Invalid compiled launch artifact root');
  }
  const files: string[] = [];
  function collect(dir: string): void {
    for (const name of readdirSync(dir)) {
      const path = resolve(dir, name);
      const stat = lstatSync(path);
      if (stat.isSymbolicLink()) { throw new Error('Linked compiled launch artifact'); }
      if (stat.isDirectory()) { collect(path); }
      else if (stat.isFile() && /\.(?:js|mjs|cjs|json)$/.test(name)) { files.push(relative(dist, path)); }
    }
  }
  collect(dist);
  for (const path of paths) {
    const entry = relative(dist, path);
    if (!isAbsolute(path) || isAbsolute(entry) || !files.includes(entry)) {
      throw new Error('Launch entry is outside the compiled artifact');
    }
  }
  const digest = createHash('sha256').update('fixlevelup/api-dist/v1\0');
  for (const entry of files.sort()) {
    const name = Buffer.from(entry.split(sep).join('/'), 'utf8');
    const bytes = readFileSync(resolve(dist, entry));
    digest.update(`${String(name.byteLength)}:${String(bytes.byteLength)}:`).update(name).update(bytes);
  }
  return digest.digest('hex');
}

/** Starts an explicitly targeted isolated launch; no dev or control-owner fallback. */
export async function startLauncher(consumerKind: 'API' | 'WORKER' | 'TEST', target: LauncherTarget): Promise<LauncherHandle> {
  const { runtime, operator, isolatedArtifactRoot } = target;
  const { database } = runtime;
  const databasePattern = consumerKind === 'TEST'
    ? /^fixlevelup_configuration_test_[0-9a-f]{24}$/ : /^fixlevelup_p05_[a-z0-9_]{1,48}$/;
  if (!databasePattern.test(database) || database !== operator.database
    || operator.host !== runtime.host || operator.port !== runtime.port || operator.user !== 'fixlevelup_migrator'
    || (consumerKind === 'TEST' ? isolatedArtifactRoot === undefined
      || !/^p05-t-[A-Za-z0-9]+$/.test(relative(resolve(root, 'apps/api/build'), isolatedArtifactRoot))
      : isolatedArtifactRoot !== undefined)) {
    throw new Error('Invalid isolated compiled launcher target');
  }
  const dist = isolatedArtifactRoot ?? resolve(root, 'apps/api/dist');
  const control = verifiedControlConfig(database);
  const paths = [...target.artifactPaths];
  const artifactDigest = artifactDigestOf(paths, dist);
  const holder = new Client({ ...operator, connectionTimeoutMillis: 3000, statement_timeout: 3000, query_timeout: 4000 });
  const admission = await (async () => {
    try {
      await holder.connect();
      return await issueVerifiedLaunch(holder, runtime, { consumerKind, artifactDigest,
        ...(target.expectedMigrations === undefined ? {} : { expectedMigrations: target.expectedMigrations }) });
    } catch (error) {
      await holder.end().catch(() => undefined);
      throw error;
    }
  })();
  const generation = Number(admission.env['LAUNCH_ISSUER_GENERATION']);
  const nonce = String(admission.env['LAUNCH_NONCE']);
  const instanceId = String(admission.env['LAUNCH_INSTANCE_ID']);
  const channelId = String(admission.env['LAUNCH_CHANNEL_ID']);
  const launcherDeps = { app: operator, control, witnessKeyOf: witnessKeyForInstance, ackTimeoutMs: 5_000 };
  const { binding } = admission.admission;
  const expected = { instanceId, launchNonce: nonce, consumerKind, proofDigest: admission.admission.proofDigest,
    issuerGeneration: generation, witnessHolderPid: binding.witnessHolderPid, channelId,
    database, databaseOid: binding.databaseOid, role: binding.role, profile: binding.profile };
  const supervisors = new Set<LaunchSupervisor>();
  return {
    admission,
    launch: (options) => new Promise<LaunchOutcome>((resolveLaunch) => {
      // The launcher's OWN expectations; a test may corrupt them to prove the
      // trusted-binding gate (BINDING) through the production decideLaunch.
      const trusted = options.corruptBinding === true
        ? { ...expected, launchNonce: randomUUID() }
        : expected;
      if (artifactDigestOf(paths, dist) !== artifactDigest) { throw new Error('Pinned launch artifacts changed'); }
      const env: NodeJS.ProcessEnv = {
        ...admission.env, FIXLEVELUP_LAB_DATABASE: database,
        DB_HOST: runtime.host, DB_PORT: String(runtime.port), DB_NAME: database,
        DB_USER: runtime.user, DB_PASSWORD: runtime.password,
      };
      if (consumerKind === 'TEST') {
        const cluster = process.env['FIXLEVELUP_CLUSTER_NAME'];
        if (!cluster || !/^fixlevelup_p05s4_lab_[a-z0-9_]{1,40}$/.test(cluster)) { throw new Error('Invalid test child cluster'); }
        env['FIXLEVELUP_CLUSTER_NAME'] = cluster;
        env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] = '1';
      }
      for (const name of CHILD_ENV) {
        const value = options.env[name];
        if (value !== undefined) { env[name] = value; }
      }
      const child: ChildProcess = spawn(process.execPath, ['--input-type=module', '--eval', options.source], {
        cwd: root, env, stdio: ['ignore', 'pipe', 'pipe', 'ipc'], timeout: options.timeoutMs,
      });
      let stdout = '';
      let stderr = '';
      let approvals = 0;
      let rejects = 0;
      child.stdout?.on('data', (chunk: Buffer) => { stdout += chunk.toString('utf8'); });
      child.stderr?.on('data', (chunk: Buffer) => { stderr += chunk.toString('utf8'); });
      child.on('error', () => undefined); // also handles a synchronous spawn refusal
      const supervised = superviseLaunch(launcherDeps, trusted, child, {
        startupTimeoutMs: options.timeoutMs, drainTimeoutMs: 5_000,
        onSend: ({ type }) => {
          if (type === 'p05/launch/approve') { approvals += 1; }
          if (type === 'p05/launch/reject') { rejects += 1; }
        },
      });
      supervisors.add(supervised);
      if (options.repeatFirstHandshake) {
        let repeated = false;
        child.on('message', (message: unknown) => {
          if (repeated || typeof message !== 'object' || message === null || !('type' in message) || message.type !== 'p05/launch/handshake') { return; }
          repeated = true;
          child.emit('message', message);
          options.repeatFirstHandshake?.();
        });
      }
      void Promise.all([supervised.activation, supervised.closed]).then(([result]) => {
        const code = child.exitCode;
        resolveLaunch({ pid: child.pid, status: code, stdout, stderr, approvals, rejects, acked: result.approved, exitCode: code,
          decision: result.approved ? 'approved:acked' : `rejected:${result.reason}` });
      });
    }),
    close: async () => {
      await Promise.all([...supervisors].map((supervisor) => supervisor.stop()));
      await admission.release();
      await holder.end().catch(() => undefined);
    },
  };
}

/** Exposed for the test's registry-state assertions. */
export async function registryState(generation: number, nonce: string) {
  const client = await openVerifiedControl(verifiedControlConfig(process.env['FIXLEVELUP_LAB_DATABASE'] ?? ''));
  try { return await readRegistryState(client, generation, nonce); }
  finally { await client.end().catch(() => undefined); }
}
