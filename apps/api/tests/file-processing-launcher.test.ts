import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { resolve, sep } from 'node:path';
import { PassThrough, Readable } from 'node:stream';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { FileProcessingPolicy } from '../src/files/file-lifecycle/contract.js';
import { createLocalFileProcessor, type ChildResult, type DefinitionEpoch, type FileProcessingLauncher } from '../src/files/file-processing/processor.js';

const mockedSpawn = vi.hoisted(() => vi.fn<(executable: string, args: string[]) => FakeChild>());
const fakeBytes = Buffer.alloc(513, 0x53);
const fakeNames = ['bytecode.cvd', 'daily.cvd', 'main.cvd'];

vi.mock('node:child_process', () => ({ spawn: mockedSpawn }));
vi.mock('node:fs', () => ({ createReadStream: () => Readable.from([fakeBytes]) }));
vi.mock('node:fs/promises', () => ({
  lstat: () => Promise.resolve({ isFile: () => true, nlink: 1, size: fakeBytes.length }),
  realpath: (path: string) => Promise.resolve(resolve(path)),
  readdir: () => Promise.resolve([...fakeNames]),
}));

// @ts-expect-error The local synthetic infrastructure is native ESM, not an API TS module.
import * as infrastructure from '../../../infra/file-processing/docker-test-launcher.mjs';

const { createFileProcessingTestLauncher, syntheticSnapshotDigest, DECODER_INDEX_SHA, DECODER_PLATFORM_SHA,
  SCANNER_INDEX_SHA, SCANNER_PLATFORM_SHA } = infrastructure as {
  createFileProcessingTestLauncher: (config: unknown) => Promise<{ launcher: FileProcessingLauncher; epoch: DefinitionEpoch }>;
  syntheticSnapshotDigest: (path: string) => Promise<string>;
  DECODER_INDEX_SHA: string; DECODER_PLATFORM_SHA: string; SCANNER_INDEX_SHA: string; SCANNER_PLATFORM_SHA: string;
};
const scannerImageId = `sha256:${'a'.repeat(64)}`;
const decoderImageId = `sha256:${'b'.repeat(64)}`;
const id = '1'.repeat(64);
const unknown = { name: 'UnknownWorkerSettlementError', message: 'Synthetic worker settlement unknown' };
const fixtureRoot = resolve('node_modules', '.cache', 'p0304cde', 'launcher-mock');
const types = ['context', 'image', 'create', 'start', 'inspect', 'kill'] as const;
type Rpc = typeof types[number];
type Reply = { stdout?: string; stderr?: string; code?: number; hangs?: boolean; ignoresLocalKill?: boolean };

class FakeChild extends EventEmitter {
  readonly stdout = new PassThrough();
  readonly stderr = new PassThrough();
  readonly stdin = new PassThrough();
  readonly unref = vi.fn();
  readonly kill = vi.fn((signal: string) => {
    if (!this.reply.ignoresLocalKill) {
      this.stdout.end();
      this.stderr.end();
      queueMicrotask(() => this.emit('close', null, signal));
    }
    return true;
  });

  constructor(private readonly reply: Reply) {
    super();
    this.stdin.resume();
    if (!reply.hangs) {
      // Emit close after the two EOF events, without relying on real wall time.
      let ends = 0;
      const close = () => { if (++ends === 2) { queueMicrotask(() => this.emit('close', reply.code ?? 0, null)); } };
      this.stdout.on('end', close);
      this.stderr.on('end', close);
      queueMicrotask(() => { this.stdout.end(reply.stdout); this.stderr.end(reply.stderr); });
    }
  }
}

let phase: 'preflight' | 'worker';
let commands: [Rpc, FakeChild][];
let scenario: (rpc: Rpc, args: string[]) => Reply | undefined;

function fixtureDescriptor() {
  const h = createHash('sha256');
  const fileDigest = createHash('sha256').update(fakeBytes).digest('hex');
  for (const name of fakeNames) { h.update(`${name}\t${String(fakeBytes.length)}\t${fileDigest}\n`); }
  const limits = { cpuMilli: 1000, memoryMiB: 1200, pids: 32, tmpfsMiB: 32, wallMs: 750 };
  return {
    snapshotDir: fixtureRoot, scannerImageId, decoderImage: decoderImageId,
    epoch: { engineVersion: '1.4.7', engineIndexSha256: SCANNER_INDEX_SHA.slice(7),
      engineImageSha256: SCANNER_PLATFORM_SHA.slice(7), engineConfigSha256: scannerImageId.slice(7),
      decoderIndexSha256: DECODER_INDEX_SHA.slice(7), decoderImageSha256: DECODER_PLATFORM_SHA.slice(7),
      decoderConfigSha256: decoderImageId.slice(7),
      defsSha256: h.digest('hex'), defsBuiltAt: '2026-11-21T06:27:04Z' },
    scanner: { ...limits, dailyRevision: 28190, maxFileBytes: 4096, maxScanBytes: 8192, maxFiles: 64, maxRecursion: 8 },
    decoder: limits,
  };
}

function normal(rpc: Rpc, args: string[]): Reply {
  switch (rpc) {
    case 'context': return { stdout: 'unix:///var/run/docker.sock\n' };
    case 'image': return { stdout: args.at(-1) === scannerImageId
      ? `${scannerImageId} linux/amd64\n` : `${decoderImageId} linux/amd64\n` };
    case 'create': return { stdout: `${id}\n` };
    case 'start': return { stdout: phase === 'preflight' ? 'ClamAV 1.4.7/28190/Sat Nov 21 06:27:04 2026\n' : 'stdin: OK\n' };
    case 'inspect': return { stdout: 'exited 0 false\n' };
    case 'kill': return { stdout: `${id}\n` };
  }
}

async function verified() {
  const fixture = await createFileProcessingTestLauncher(fixtureDescriptor());
  phase = 'worker';
  commands = [];
  return fixture;
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
  vi.stubEnv('DOCKER_HOST', undefined);
  phase = 'preflight';
  commands = [];
  scenario = () => undefined;
  mockedSpawn.mockReset();
  mockedSpawn.mockImplementation((command, args) => {
    expect(command).toBe('docker');
    const rpc = args[0] as Rpc;
    expect(types).toContain(rpc);
    const child = new FakeChild(scenario(rpc, args) ?? normal(rpc, args));
    commands.push([rpc, child]);
    return child;
  });
});

afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });

function operations() { return commands.map(([rpc]) => rpc); }
function readInput() { return Buffer.from('synthetic local fixture'); }

// Attach a rejection handler before advancing each deterministic watchdog clock.
async function rejectedWithin(result: Promise<unknown>, maxMs: number, expected: object) {
  const assertion = expect(result).rejects.toMatchObject(expected);
  await vi.advanceTimersByTimeAsync(maxMs);
  await assertion;
}

describe('bounded Docker synthetic fixture', () => {
  it('refuses an unrelated immutable decoder index before even inspecting Docker', async () => {
    await expect(createFileProcessingTestLauncher({ ...fixtureDescriptor(), decoderImage: `sha256:${'f'.repeat(64)}` })).rejects.toThrow('Synthetic worker unavailable or misconfigured');
    expect(operations()).toEqual([]);
  });

  it('refuses a descriptor with the wrong pinned linux/amd64 manifest before inspecting Docker', async () => {
    const fixture = fixtureDescriptor();
    fixture.epoch.decoderImageSha256 = 'f'.repeat(64);
    await expect(createFileProcessingTestLauncher(fixture)).rejects.toThrow('Synthetic worker unavailable or misconfigured');
    expect(operations()).toEqual([]);
  });

  it('refuses a local image whose config digest differs from the verified Buildx metadata', async () => {
    scenario = (rpc, args) => rpc === 'image' && args.at(-1) === scannerImageId
      ? { stdout: `sha256:${'f'.repeat(64)} linux/amd64\n` } : undefined;
    await expect(createFileProcessingTestLauncher(fixtureDescriptor())).rejects.toThrow('Synthetic worker unavailable or misconfigured');
    expect(operations()).toEqual(['context', 'image']);
  });

  it('bounds an unresponsive metadata RPC even if the local CLI never closes', async () => {
    scenario = (rpc) => rpc === 'context' ? { hangs: true, ignoresLocalKill: true } : undefined;
    await rejectedWithin(createFileProcessingTestLauncher(fixtureDescriptor()), 2750,
      { message: 'Synthetic worker unavailable or misconfigured' });
    expect(operations()).toEqual(['context']);
    expect(commands[0]?.[1].kill).toHaveBeenCalledExactlyOnceWith('SIGKILL');
    expect(commands[0]?.[1].unref).toHaveBeenCalledTimes(1);
  });

  it('bounds ambiguous create from the operation deadline and never starts or asserts reap', async () => {
    const { launcher, epoch } = await verified();
    expect(await syntheticSnapshotDigest(`${fixtureRoot}${sep}`)).toBe(epoch.defsSha256);
    scenario = (rpc) => rpc === 'create' ? { hangs: true, ignoresLocalKill: true } : undefined;
    await rejectedWithin(launcher.scan(readInput(), epoch, new AbortController().signal), 1000, unknown);
    expect(operations()).toEqual(['create']);
    expect(commands[0]?.[1].kill).toHaveBeenCalledExactlyOnceWith('SIGKILL');
  });

  it('does not accept good attached output when every inspect and kill RPC hangs', async () => {
    const { launcher, epoch } = await verified();
    scenario = (rpc) => rpc === 'inspect' || rpc === 'kill' ? { hangs: true, ignoresLocalKill: true } : undefined;
    await rejectedWithin(launcher.scan(readInput(), epoch, new AbortController().signal), 6600, unknown);
    expect(operations()).toEqual(['create', 'start', 'inspect', 'kill', 'inspect']);
    expect(commands[2]?.[1].kill).toHaveBeenCalledTimes(1);
    expect(commands[3]?.[1].kill).toHaveBeenCalledTimes(1);
    expect(commands[4]?.[1].kill).toHaveBeenCalledTimes(1);
  });

  it('observes abort despite another listener and does not confuse a killed CLI with a stopped container', async () => {
    const { launcher, epoch } = await verified();
    const controller = new AbortController();
    controller.signal.addEventListener('abort', (event) => { event.stopImmediatePropagation(); });
    let reachedStart!: () => void;
    const started = new Promise<void>((r) => { reachedStart = r; });
    scenario = (rpc) => {
      if (rpc === 'start') { reachedStart(); return { hangs: true, ignoresLocalKill: true }; }
      if (rpc === 'inspect') { return { stdout: 'created 0 false\n' }; }
      return undefined;
    };
    const result = launcher.scan(readInput(), epoch, controller.signal);
    const assertion = expect(result).rejects.toMatchObject(unknown);
    await started;
    controller.abort();
    await vi.advanceTimersByTimeAsync(250);
    await assertion;
    expect(operations()).toEqual(['create', 'start', 'kill', 'inspect']);
    expect(commands[1]?.[1].kill).toHaveBeenCalledExactlyOnceWith('SIGKILL');
  });

  it('retains the processor slot when the container exited but the attached local CLI never closed', async () => {
    const { launcher, epoch } = await verified();
    scenario = (rpc) => rpc === 'start' ? { hangs: true, ignoresLocalKill: true } :
      rpc === 'inspect' ? { stdout: 'exited 137 false\n' } : undefined;
    const processor = createLocalFileProcessor(launcher, { epoch, maxJobs: 1, maxRawBytes: 4096, maxOutputBytes: 4096, maxWallMs: 3000 });
    const policy: FileProcessingPolicy = { mode: 'local-synthetic', versionId: '4e0eb02c-f486-4181-a1ad-6dd5a7d5a58e',
      expiresAt: new Date('2026-11-24T00:00:00Z'), allowedMimeTypes: ['image/png'], maxRawBytes: 4096, maxOutputBytes: 4096,
      maxWidth: 32, maxHeight: 32, maxPixels: 1024, maxChannels: 4, leaseMs: 5000, wallMs: 3000, maxDefsAgeMs: 172_800_000 };
    const bytes = readInput();
    const input = { mime: 'image/png' as const, bytes, raw: { bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') }, policy };
    const signal = new AbortController().signal;
    await rejectedWithin(processor.process(input, signal), 1000, { message: 'Local file processing did not settle' });
    expect(await processor.process(input, signal)).toEqual({ kind: 'INDETERMINATE', reason: 'BUSY' });
    expect(operations()).toEqual(['create', 'start', 'kill', 'inspect']);
    expect(commands[1]?.[1].unref).toHaveBeenCalledTimes(1);
  });

  it('does not erase an unclosed kill CLI when the following inspection proves container exit', async () => {
    const { launcher, epoch } = await verified();
    scenario = (rpc) => rpc === 'start' ? { hangs: true } : rpc === 'kill' ? { hangs: true, ignoresLocalKill: true } :
      rpc === 'inspect' ? { stdout: 'exited 137 false\n' } : undefined;
    await rejectedWithin(launcher.scan(readInput(), epoch, new AbortController().signal), 3500, unknown);
    expect(operations()).toEqual(['create', 'start', 'kill', 'inspect']);
    expect(commands[2]?.[1].unref).toHaveBeenCalledTimes(1);
  });

  it('returns a fixed failed result once all local CLIs closed and Docker confirms exit', async () => {
    const { launcher, epoch } = await verified();
    scenario = (rpc) => rpc === 'start' ? { hangs: true } :
      rpc === 'inspect' ? { stdout: 'exited 137 false\n' } : undefined;
    const promise = launcher.scan(readInput(), epoch, new AbortController().signal);
    await vi.advanceTimersByTimeAsync(1000);
    const result: ChildResult = await promise;
    expect(result).toEqual({ reaped: true, exitCode: null, signal: null, stdinComplete: false,
      stdoutEof: false, stderrEof: false, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) });
    expect(operations()).toEqual(['create', 'start', 'kill', 'inspect']);
  });
});
