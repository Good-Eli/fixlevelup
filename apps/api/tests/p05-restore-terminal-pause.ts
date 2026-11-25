import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Client, Pool } from 'pg';
import type { ClientConfig } from 'pg';
import { expect } from 'vitest';
import { restoreDbOptions } from '../../../infra/file-restore/resources.mjs';
import type { RestoreContext, SignedSnapshotManifest } from '../src/files/file-restore/contract.js';
import { readAuthorityInventory } from '../src/files/file-restore/inventory.js';
import { readP05SourceState } from '../src/files/file-restore/p05-inventory.js';
import { rescrubFileRestore } from '../src/files/file-restore/rescrub.js';
import { admitVerifiedTestInstance, issueVerifiedLaunch, openVerifiedControl, verifiedControlConfig } from './admission-fixture.js';
import type { AdmissionHandle } from './admission-fixture.js';
import { withQueryHook } from './file-lifecycle-fixture.js';
import { moduleUrl } from './launcher-harness.js';
import { loadP05LabTarget } from './p05-lab-target.js';

const consumers = ['API', 'WORKER', 'TEST'] as const;
type Consumer = typeof consumers[number];
const canEnter = ['fixlevelup_runtime', 'fixlevelup_migrator', 'fixlevelup_lab_orchestrator'] as const;
const runtimeAdmissionUrl = moduleUrl('infrastructure/admission/runtime-admission.js');
const processAdmissionUrl = moduleUrl('infrastructure/admission/process-admission.js');

/** Real cases from the existing lab: API/worker/TEST share runtime, launcher
 * witness/issuer preflight and DDL share migrator, dump/import uses postgres.
 * The orchestrator is a non-inheriting member of the owner and the external
 * launcher has its own narrow control login, never a source role. */
export async function prepareTerminalRestarts(pool: Pool, database: string) {
  if (!/^fixlevelup_legal_test_[a-f0-9]{24}$/u.test(database)
    || process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] !== '1') {
    throw new Error('Terminal restart requires an owned lab restore source');
  }
  for (const url of [runtimeAdmissionUrl, processAdmissionUrl]) {
    if (!existsSync(fileURLToPath(url))) { throw new Error('Terminal restart requires the compiled API release'); }
  }
  const runtime = { ...loadP05LabTarget().runtime, database };
  const proofs = new Map<Consumer, AdmissionHandle>();
  for (const consumerKind of consumers) {
    // Genuine positive, including CAS and SQL/profile admission, before drain.
    // This legacy fixture uses simulated IPC; the restart itself uses OS IPC.
    const handle = await admitVerifiedTestInstance(pool, database, { consumerKind });
    await handle.release(); // close every witness before SOURCE_DRAIN
    proofs.set(consumerKind, handle);
  }
  return { runtime, proofs };
}

type OlderLaunches = Awaited<ReturnType<typeof prepareTerminalRestarts>>;

/** The stock API/worker entrypoints bind fixlevelup_dev. Start the common
 * compiled admission entry with the exact old signed fixture proofs instead.
 * Fail at live admission (not missing config/IPC); never call a factory. */
async function tryRestart(kind: Consumer, old: OlderLaunches): Promise<void> {
  const proof = old.proofs.get(kind);
  if (!proof) { throw new Error('Missing old admitted process proof'); }
  const source = `
    import { loadRuntimeAdmission } from ${JSON.stringify(runtimeAdmissionUrl)};
    import { admitProcess, ProcessAdmissionError } from ${JSON.stringify(processAdmissionUrl)};
    const database = {host:'127.0.0.1',port:55432,database:process.env.DB_NAME,
      user:'fixlevelup_runtime',password:process.env.DB_PASSWORD};
    const admission = loadRuntimeAdmission(process.env,{database,requiredConsumer:${JSON.stringify(kind)}});
    try { await admitProcess(admission,{database,approvalTimeoutMs:3000}); process.exit(2); }
    catch (error) { process.exit(error instanceof ProcessAdmissionError && error.kind==='ADMISSION_DENIED' ? 41 : 3); }
  `;
  const child = spawn(process.execPath, ['--input-type=module', '--eval', source], {
    env: { ...proof.env, DB_NAME: old.runtime.database, DB_PASSWORD: old.runtime.password },
    stdio: ['ignore', 'ignore', 'ignore', 'ipc'], timeout: 8_000,
  });
  const frames: unknown[] = [];
  child.on('message', (message: unknown) => { frames.push(message); });
  expect(child.pid).toBeGreaterThan(0);
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once('error', reject);
    child.once('close', resolve);
  });
  expect(code).toBe(41);
  expect(frames).toEqual([]); // no admission handshake, approval, or activation
}

async function connectionRefused(options: ClientConfig, code: string): Promise<void> {
  const client = new Client({ ...options, connectionTimeoutMillis: 3_000 });
  try { await expect(client.connect()).rejects.toMatchObject({ code }); }
  finally { await client.end(); }
}

async function sourceBarrier(maintenance: Pool, database: string, oid: number) {
  return (await maintenance.query<{
    allow: boolean; public_connect: boolean; roles: boolean[]; sessions: number[]; prepared: number;
  }>(`SELECT d.datallowconn AS allow,
    EXISTS(SELECT FROM aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) acl
      WHERE acl.grantee=0 AND acl.privilege_type='CONNECT') AS public_connect,
    ARRAY(SELECT has_database_privilege(r.role,d.oid,'CONNECT') FROM unnest($3::text[]) r(role)) AS roles,
    ARRAY(SELECT pid FROM pg_stat_activity WHERE datid=d.oid ORDER BY pid) AS sessions,
    (SELECT count(*)::int FROM pg_prepared_xacts WHERE database=d.datname) AS prepared
    FROM pg_database d WHERE d.datname=$1 AND d.oid=$2::oid`, [database, oid, canEnter])).rows[0];
}

/** Pause after the final real source read-only transaction returns ROLLBACK,
 * before the target can run its ACTIVE CAS. A failing test assertion is saved
 * and rethrown outside the restore error mapper, never mistaken for refusal. */
export async function checkTerminalPause(ctx: RestoreContext, manifest: SignedSnapshotManifest, options: {
  readonly maintenance: Pool;
  readonly old: OlderLaunches;
  readonly loseFence: boolean;
  readonly signal: AbortSignal;
}) {
  const { maintenance, old, loseFence, signal } = options;
  const source = ctx.sourceObserver;
  const sourceConfig = restoreDbOptions(ctx.sourceDatabase, 'migrator');
  const targetRuntime = restoreDbOptions(ctx.destinationDatabase, 'runtime');
  const target = new Client({ ...restoreDbOptions(ctx.destinationDatabase, 'migrator'),
    options: '-c default_transaction_read_only=on' });
  const controlSpec = verifiedControlConfig(ctx.sourceDatabase);
  const control = await openVerifiedControl(controlSpec);
  const sourceState = async () => ({
    p05: await readP05SourceState(source, 'S3'), authority: await readAuthorityInventory(source, ctx.limits),
    epochs: (await source.query(`SELECT namespace_id::text,epoch::text,mode FROM foundation.file_runtime_epochs`)).rows,
  });
  const targetState = async () => (await target.query<{ mode: string; epoch: string; connect: boolean }>(`SELECT mode,epoch::text,
    has_database_privilege('fixlevelup_runtime',current_database(),'CONNECT') AS connect
    FROM foundation.file_runtime_epochs WHERE singleton`)).rows;
  const registry = async () => (await control.query<{ issued_total: number; consumed_total: number }>(`SELECT count(*)::int AS issued_total,
    count(*) FILTER (WHERE state='CONSUMED')::int AS consumed_total FROM launch_control.launch_proofs`)).rows;
  const sourcePid = (await source.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]?.pid;
  const healthy = { allow: false, public_connect: false, roles: [false, false, false], sessions: [sourcePid], prepared: 0 };
  const barrier = () => sourceBarrier(maintenance, ctx.sourceDatabase, ctx.sourceDatabaseOid);
  const before = await sourceState();
  const beforeRegistry = await registry();
  expect(sourcePid).toBeGreaterThan(0);
  expect(before.p05.empty).toBe(true);
  expect(await barrier()).toEqual(healthy);

  const cancelled = new AbortController();
  let observations = 0;
  let pauses = 0;
  let cas = 0;
  const pause = { error: undefined as Error | undefined, writerFenceLost: false };
  // Count only the restore core's source observation transactions; the
  // independent probes use other connections (or the unwrapped read-only source).
  const observed = new Proxy(source, { get(backend, key): unknown {
    const member: unknown = Reflect.get(backend, key, backend);
    if (key !== 'query') { return typeof member === 'function' ? member.bind(backend) : member; }
    if (typeof member !== 'function') { throw new Error('Missing source query'); }
    return async (...args: unknown[]) => {
      const result: unknown = await Reflect.apply(member, backend, args);
      if (args[0] !== 'ROLLBACK' || ++observations !== 2) { return result; }
      pauses++;
      try {
        await target.connect();
        expect(await targetState()).toEqual([{ mode: 'RESTORE_CLOSED', epoch: String(ctx.oldScope.writerEpoch), connect: false }]);
        await connectionRefused(targetRuntime, '42501');
        expect(await barrier()).toEqual(healthy);
        // Real source connections under each distinct relevant login, including
        // privileged import and the external no-source launcher login.
        const orchestration = await loadP05LabTarget().openMaintenance();
        try {
          await Promise.all([
            connectionRefused(old.runtime, '55000'), connectionRefused(sourceConfig, '55000'),
            connectionRefused({ ...restoreDbOptions('postgres', 'maintenance'), database: ctx.sourceDatabase }, '55000'),
            connectionRefused({ host: '127.0.0.1', port: 55432, user: 'fixlevelup_lab_orchestrator',
              password: process.env['FIXLEVELUP_LAB_ORCHESTRATOR_PASSWORD'] ?? '', database: ctx.sourceDatabase }, '55000'),
            connectionRefused({ ...controlSpec, database: ctx.sourceDatabase }, '55000'),
            ...consumers.map(kind => tryRestart(kind, old)),
          ]);
        } finally { await orchestration.end(); }
        // Attempt *fresh* launch issuance as well as replay/restart of a consumed
        // proof. The real issuance port cannot acquire its source preflight.
        const issuer = new Pool({ ...sourceConfig, max: 1 });
        try {
          await expect(issueVerifiedLaunch(issuer, old.runtime, { consumerKind: 'API' })).rejects.toMatchObject({ code: '55000' });
        } finally { await issuer.end(); }
        expect(await registry()).toEqual(beforeRegistry);
        expect(await sourceState()).toEqual(before);
        expect(await barrier()).toEqual(healthy);
        if (loseFence) {
          // Trusted controller fault, not a claim to defend against arbitrary DBA
          // changes. Break ACL while leaving datallowconn=false and the read-only
          // observer in place, so even this negative never opens the source.
          await maintenance.query(`GRANT CONNECT ON DATABASE "${ctx.sourceDatabase}" TO fixlevelup_runtime`);
          pause.writerFenceLost = true;
          expect(await barrier()).toEqual({ ...healthy, roles: [true, false, false] });
          cancelled.abort(); // independent observation aborts before the core CAS
        }
      } catch (error) {
        pause.error = error instanceof Error ? error : new Error('Terminal pause probe failed', { cause: error });
        cancelled.abort();
      }
      return result;
    };
  } });
  const targetOperatorPool = withQueryHook(ctx.targetOperatorPool,
    sql => sql.startsWith('UPDATE foundation.file_runtime_epochs SET mode=\'ACTIVE\''),
    (_sql, _client, send) => { cas++; return send(); });
  try {
    const run = rescrubFileRestore({ ...ctx, sourceObserver: observed, targetOperatorPool }, manifest,
      AbortSignal.any([signal, cancelled.signal])).then(receipt => ({ receipt }), (error: unknown) => ({ error }));
    const result = await run;
    if (pause.error !== undefined) { throw pause.error; }
    expect({ observations, pauses }).toEqual({ observations: 2, pauses: 1 });
    if (loseFence) {
      expect(pause.writerFenceLost).toBe(true);
      expect(result).toMatchObject({ error: { code: 'RESTORE_ABORTED' } });
      expect(cas).toBe(0);
      expect(await targetState()).toEqual([{ mode: 'RESTORE_CLOSED', epoch: String(ctx.oldScope.writerEpoch), connect: false }]);
    } else {
      expect(result).toMatchObject({ receipt: { mode: 'ACTIVE', epoch: { epoch: ctx.nextEpoch } } });
      expect(cas).toBe(1);
      expect(await targetState()).toEqual([{ mode: 'ACTIVE', epoch: String(ctx.nextEpoch), connect: false }]);
    }
    await connectionRefused(targetRuntime, '42501');
    expect(await sourceState()).toEqual(before);
    expect(await registry()).toEqual(beforeRegistry);
    return { terminalPause: loseFence ? 'controller-aborted-on-fence-loss' : 'closed-then-active', observations, pauses, cas,
      sourcePreserved: true, targetRuntimeConnect: false, attempts: [...consumers] };
  } finally {
    try {
      if (pause.writerFenceLost) {
        await maintenance.query(`REVOKE CONNECT ON DATABASE "${ctx.sourceDatabase}" FROM fixlevelup_runtime`);
        expect(await barrier()).toEqual(healthy);
      }
    } finally { await Promise.all([target.end(), control.end()]); }
  }
}
