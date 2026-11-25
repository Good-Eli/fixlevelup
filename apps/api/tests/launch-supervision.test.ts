import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { expect, it } from 'vitest';
import { superviseLaunch } from '../src/infrastructure/admission/launcher.js';
import type { ExpectedChild } from '../src/infrastructure/admission/launcher.js';
import { consumeProof, issueProof, readRegistryState } from '../src/infrastructure/admission/registry.js';
import type { ControlStatement } from '../src/infrastructure/admission/registry.js';

function facts(): ExpectedChild {
  return {
    issuerGeneration: 5, launchNonce: randomUUID(), instanceId: randomUUID(), channelId: randomUUID(),
    consumerKind: 'WORKER', proofDigest: 'a'.repeat(64), witnessHolderPid: 3,
    database: 'unused', databaseOid: 4, role: 'fixlevelup_runtime', profile: 'S1',
  };
}

it.each(['throw', 'rollback tag'])('does not roll back or reuse an unconfirmed CAS COMMIT (%s)', async (mode) => {
  const binding = facts();
  const calls: string[] = [];
  const query = (sql: string): Promise<unknown> => {
    calls.push(sql);
    if (sql.startsWith('SELECT')) { return Promise.resolve({ rows: [{ proof_digest: binding.proofDigest }] }); }
    if (sql.startsWith('UPDATE')) { return Promise.resolve({ rowCount: 1, rows: [{ expires_at: new Date(60_000) }] }); }
    if (sql === 'COMMIT') {
      if (mode === 'throw') { return Promise.reject(new Error('Lost transport')); }
      return Promise.resolve({ command: 'ROLLBACK' });
    }
    return Promise.resolve({});
  };
  const client = { query: query as ControlStatement['query'] };
  const input = { issuerGeneration: binding.issuerGeneration, launchNonce: binding.launchNonce,
    expectedDigest: binding.proofDigest, binding };
  await expect(consumeProof(client, input)).rejects.toMatchObject({ code: 'COMMIT_UNKNOWN' });
  expect(calls.at(-1)).toBe('COMMIT');
  expect(calls).toHaveLength(5);
  await expect(consumeProof(client, input)).rejects.toMatchObject({ code: 'COMMIT_UNKNOWN' });
  await expect(readRegistryState(client, binding.issuerGeneration, binding.launchNonce))
    .rejects.toMatchObject({ code: 'COMMIT_UNKNOWN' });
  expect(calls).toHaveLength(5);
});

it('does not publish issuance without a confirmed COMMIT', async () => {
  const binding = facts();
  const calls: string[] = [];
  const query = (sql: string): Promise<unknown> => {
    calls.push(sql);
    return sql === 'COMMIT' ? Promise.reject(new Error('Lost transport')) : Promise.resolve({});
  };
  const client = { query: query as ControlStatement['query'] };
  await expect(issueProof(client, { ...binding, expiresAt: new Date(60_000) }))
    .rejects.toMatchObject({ code: 'COMMIT_UNKNOWN' });
  expect(calls.at(-1)).toBe('COMMIT');
  expect(calls).not.toContain('ROLLBACK');
});

it('drains the private OS child after an uncompleted launch and refuses reuse of its attempt', async () => {
  const expected = facts();
  const db = { host: 'invalid', port: 0, database: 'unused', user: 'unused', password: 'unused' };
  const deps = { app: db, control: db, ackTimeoutMs: 100,
    witnessKeyOf: (): never => { throw new Error('Unexpected database path'); } };
  const createChild = (source = 'setInterval(()=>{}, 1000)') => {
    const child = spawn(process.execPath, ['-e', source], { stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
    child.stdout?.resume();
    child.stderr?.resume();
    return child;
  };
  const first = createChild();
  const firstSupervisor = superviseLaunch(deps, expected, first, { startupTimeoutMs: 150, drainTimeoutMs: 100 });
  try {
    await expect(firstSupervisor.activation).resolves.toEqual({ approved: false, reason: 'IPC' });
    await firstSupervisor.closed;
    expect(first.connected).toBe(false);
    expect(first.signalCode).toBe('SIGKILL');
    expect(first.stdout?.closed && first.stderr?.closed).toBe(true);
  } finally { await firstSupervisor.stop(); }
  const second = createChild();
  const secondSupervisor = superviseLaunch(deps, expected, second, { startupTimeoutMs: 150, drainTimeoutMs: 100 });
  try {
    await expect(secondSupervisor.activation).resolves.toEqual({ approved: false, reason: 'CAS' });
    await secondSupervisor.closed;
    expect(second.connected).toBe(false);
    expect(second.stdout?.closed && second.stderr?.closed).toBe(true);
  } finally { await secondSupervisor.stop(); }
  const graceful = createChild('process.on("disconnect",()=>process.exit(0));setInterval(()=>{},1000)');
  const fresh = { ...expected, launchNonce: randomUUID() };
  const gracefulSupervisor = superviseLaunch(deps, fresh, graceful, { startupTimeoutMs: 600, drainTimeoutMs: 400 });
  try {
    await expect(gracefulSupervisor.activation).resolves.toEqual({ approved: false, reason: 'IPC' });
    expect(graceful.exitCode).toBe(0);
    expect(graceful.connected).toBe(false);
    expect(graceful.stdout?.closed && graceful.stderr?.closed).toBe(true);
  } finally { await gracefulSupervisor.stop(); }
});
