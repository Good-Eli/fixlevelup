// Local synthetic test fixture, not an API/production launcher. No container removal.
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, realpath, readdir } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export const SCANNER_INDEX_SHA = 'sha256:39f936f37a24b0b4658414230bcefa6b52de3a57c42ac88caed0ec6c09317883';
export const SCANNER_PLATFORM_SHA = 'sha256:7c58440c10859ec126d4bba5a5f260cc467395d640c193a5197b1da12073e9f8';
export const DECODER_INDEX_SHA = 'sha256:7162306fb4f11234456de8471a3299267f020f7be64f4720c4c9586ca8ee5f68';
export const DECODER_PLATFORM_SHA = 'sha256:8a0b65bc02e28cab840ea184bc193862ac2806cf02184d6e79df25522d3e23fc';
// Local infrastructure ceilings, not file-processing policy defaults.
const controlRpcMs = 2500;
const cliReapGraceMs = 250;
const cleanupWallMs = 6500;
const cache = fileURLToPath(new URL('../../node_modules/.cache/p0304cde/', import.meta.url));
const entries = ['bytecode.cvd', 'daily.cvd', 'main.cvd'];
const hex256 = /^[0-9a-f]{64}$/u;
const imageIdPattern = /^sha256:[0-9a-f]{64}$/u;

function check(ok) { if (!ok) { throw new Error('Synthetic worker unavailable or misconfigured'); } }
const stopped = () => ({ reaped: true, exitCode: null, signal: null, stdinComplete: false, stdoutEof: false,
  stderrEof: false, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0) });
function integer(value, min, max) { check(Number.isSafeInteger(value) && value >= min && value <= max); return value; }

async function snapshotDigest(dir) {
  const names = (await readdir(dir)).sort();
  check(names.join('\n') === entries.join('\n'));
  const manifest = createHash('sha256');
  for (const file of entries) {
    const path = join(dir, file);
    const stat = await lstat(path);
    check(stat.isFile() && stat.nlink === 1 && stat.size > 512 && stat.size <= 256 * 1024 * 1024);
    const h = createHash('sha256');
    let seen = 0;
    for await (const chunk of createReadStream(path)) {
      seen += chunk.length;
      check(seen <= stat.size);
      h.update(chunk);
    }
    check(seen === stat.size);
    manifest.update(`${file}\t${stat.size}\t${h.digest('hex')}\n`);
  }
  return manifest.digest('hex');
}

const emptyRpc = (rpcTimedOut, cliSettled = false) => ({
  rpcTimedOut, cliSettled, failed: true, stdinComplete: false, stdoutEof: false, stderrEof: false,
  exitCode: null, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0),
});

function docker(args, { frames, maxOutputBytes = 4096, deadlineAt = performance.now() + controlRpcMs, signal } = {}) {
  return new Promise((resolveResult) => {
    if (signal?.aborted || performance.now() >= deadlineAt) { resolveResult(emptyRpc(true)); return; }
    let child;
    try { child = spawn('docker', args, { shell: false, windowsHide: true, stdio: [frames ? 'pipe' : 'ignore', 'pipe', 'pipe'] }); }
    catch { resolveResult(emptyRpc(false)); return; }
    const streams = [child.stdout, child.stderr];
    const chunks = [[], []];
    const count = [0, 0];
    const eof = [false, false];
    let stdinComplete = false;
    let rpcTimedOut = false;
    let failed = false;
    let done = false;
    let grace;
    let timer;
    // A one-input dependent abort signal cannot have its own listener suppressed
    // by another listener on the original abort signal.
    const abort = signal === undefined ? undefined : AbortSignal.any([signal]);
    const finish = (result) => {
      if (done) { return; }
      done = true;
      clearTimeout(timer);
      clearTimeout(grace);
      abort?.removeEventListener('abort', expire);
      resolveResult(result);
    };
    const fail = () => {
      if (failed || done) { return; }
      failed = true;
      // Kill only this Docker CLI process. This is not evidence the container stopped.
      try { child.kill('SIGKILL'); } catch { /* still enforce the bounded grace */ }
      grace = setTimeout(() => {
        finish(emptyRpc(rpcTimedOut));
        child.stdin?.destroy();
        child.stdout?.destroy();
        child.stderr?.destroy();
        child.unref();
      }, cliReapGraceMs);
    };
    function expire() { rpcTimedOut = true; fail(); }
    for (const [i, stream] of streams.entries()) {
      stream.on('data', (chunk) => {
        if (failed || done) { return; }
        count[i] += chunk.length;
        if (count[i] > (i === 0 ? maxOutputBytes : 4096)) { fail(); }
        else { chunks[i].push(chunk); }
      });
      stream.on('end', () => { eof[i] = true; });
      stream.on('error', fail);
    }
    child.on('error', fail);
    child.on('close', (exitCode, childSignal) => {
      if (failed || abort?.aborted || performance.now() >= deadlineAt) {
        finish(emptyRpc(rpcTimedOut || !!abort?.aborted || performance.now() >= deadlineAt, true));
      } else {
        finish({ exitCode, signal: childSignal, failed: false, rpcTimedOut: false, cliSettled: true,
          stdinComplete, stdoutEof: eof[0], stderrEof: eof[1], stdout: Buffer.concat(chunks[0]), stderr: Buffer.concat(chunks[1]) });
      }
    });
    timer = setTimeout(expire, Math.max(0, deadlineAt - performance.now()));
    abort?.addEventListener('abort', expire, { once: true });
    if (abort?.aborted) { expire(); }
    if (frames) {
      child.stdin.on('error', fail);
      child.stdin.on('finish', () => { stdinComplete = true; });
      // Processor-supplied frames are already bounded; honor pipe backpressure.
      let next = 0;
      const write = () => {
        while (!failed && !done && next < frames.length) { if (!child.stdin.write(frames[next++])) { return; } }
        if (!failed && !done && next === frames.length) { child.stdin.end(); }
      };
      child.stdin.on('drain', write);
      try { write(); } catch { fail(); }
    }
  });
}

function good(result) {
  check(result.cliSettled && !result.rpcTimedOut && !result.failed && result.exitCode === 0 && result.signal === null &&
    result.stdoutEof && result.stderrEof && result.stderr.length === 0);
  return result.stdout.toString('utf8');
}

function control(args, { deadlineAt = Infinity, signal } = {}) {
  return docker(args, { deadlineAt: Math.min(deadlineAt, performance.now() + controlRpcMs), signal });
}

class UnknownWorkerSettlementError extends Error {
  constructor() { super('Synthetic worker settlement unknown'); this.name = 'UnknownWorkerSettlementError'; }
}

function limits(config) {
  return Object.freeze({
    cpuMilli: integer(config.cpuMilli, 100, 4000), memoryMiB: integer(config.memoryMiB, 64, 4096),
    pids: integer(config.pids, 8, 128), tmpfsMiB: integer(config.tmpfsMiB, 1, 128),
    wallMs: integer(config.wallMs, 1, 180_000),
  });
}

function configFlags(config) {
  return [
    '--pull', 'never', '--platform', 'linux/amd64', '--user', '65532:65532', '--read-only',
    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--network', 'none', '--no-healthcheck',
    '--log-driver', 'none', '--pids-limit', String(config.pids), '--cpus', String(config.cpuMilli / 1000),
    // Override Docker client's implicit container proxy environment.
    ...['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'FTP_PROXY'].flatMap((key) =>
      ['--env', `${key}=`, '--env', `${key.toLowerCase()}=`]),
    '--memory', `${config.memoryMiB}m`, '--memory-swap', `${config.memoryMiB}m`,
    '--tmpfs', `/tmp:rw,noexec,nosuid,nodev,size=${config.tmpfsMiB}m`,
  ];
}

// Keep every created container. Never treat a stopped client, RPC error,
// or `created` state as proof that a potentially started sandbox was reaped.
async function exitedStatus(id, options, record) {
  const status = record(await control(['inspect', '--format', '{{.State.Status}} {{.State.ExitCode}} {{.State.OOMKilled}}', id], options));
  try { return /^exited (\d{1,3}) (false|true)$/u.exec(good(status).trim()); }
  catch { return null; }
}

async function run(kind, config, command, frames, maxOutputBytes, signal) {
  if (signal.aborted) { return stopped(); }
  const name = `fixlevelup-p0304cde-${kind}-${randomUUID()}`;
  const deadlineAt = performance.now() + config.wallMs;
  const options = { deadlineAt, signal };
  // Reap proof covers both resources: Docker's sandbox and every local CLI
  // started to control it. A later successful inspect cannot erase CLI debt.
  let cliDebt = false;
  const record = (rpc) => {
    cliDebt ||= !rpc.cliSettled;
    return rpc;
  };
  let id;
  const create = record(await control(['create', '--name', name, ...configFlags(config), ...frames ? ['-i'] : [], ...command], options));
  try { id = good(create).trim(); } catch { throw new UnknownWorkerSettlementError(); }
  if (!hex256.test(id)) { throw new UnknownWorkerSettlementError(); }
  // A confirmed create cannot start a process on this fixed, non-restarting profile.
  if (signal.aborted || performance.now() >= deadlineAt) { return stopped(); }

  // Attached start is the worker data plane and may legitimately span the
  // worker wall, unlike a control RPC. It still uses the same bounded CLI reap.
  const result = record(await docker(['start', '-a', ...frames ? ['-i'] : [], id], { ...options, frames, maxOutputBytes }));
  if (!result.failed && !cliDebt && !result.rpcTimedOut && !signal.aborted && performance.now() < deadlineAt) {
    const exited = await exitedStatus(id, options, record);
    if (exited) {
      if (signal.aborted || performance.now() >= deadlineAt || exited[2] !== 'false' || Number(exited[1]) !== result.exitCode) { return stopped(); }
      return { reaped: true, exitCode: result.exitCode, signal: result.signal, stdinComplete: result.stdinComplete,
        stdoutEof: result.stdoutEof, stderrEof: result.stderrEof, stdout: result.stdout, stderr: result.stderr };
    }
  }
  // At most one kill and one confirmation, serially awaited. Cancellation
  // ends normal IO, not this independently bounded attempt to confirm exit.
  const cleanup = { deadlineAt: Math.min(deadlineAt + cleanupWallMs, performance.now() + cleanupWallMs) };
  record(await control(['kill', '--signal', 'KILL', id], cleanup));
  const exited = await exitedStatus(id, cleanup, record);
  if (exited && !cliDebt) { return stopped(); }
  throw new UnknownWorkerSettlementError();
}

export async function createFileProcessingTestLauncher({ snapshotDir, epoch, scannerImageId, decoderImage, scanner, decoder }) {
  check(process.env.DOCKER_HOST === undefined);
  check(imageIdPattern.test(scannerImageId));
  check(decoderImage === undefined || imageIdPattern.test(decoderImage));
  check(epoch?.engineIndexSha256 === SCANNER_INDEX_SHA.slice(7)
    && epoch?.engineImageSha256 === SCANNER_PLATFORM_SHA.slice(7)
    && epoch?.engineConfigSha256 === scannerImageId.slice(7)
    && epoch.engineVersion === '1.4.7' && hex256.test(epoch.defsSha256));
  if (decoderImage !== undefined) {
    check(epoch?.decoderIndexSha256 === DECODER_INDEX_SHA.slice(7)
      && epoch?.decoderImageSha256 === DECODER_PLATFORM_SHA.slice(7)
      && epoch?.decoderConfigSha256 === decoderImage.slice(7));
  }
  check(typeof epoch.defsBuiltAt === 'string' && Number.isFinite(Date.parse(epoch.defsBuiltAt)));
  const context = good(await control(['context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'])).trim();
  check(/^unix:\/\//u.test(context) || /^npipe:\/\/\/\.\/pipe\//u.test(context));
  const scannerIdentity = good(await control(['image', 'inspect', '--format',
    '{{.Id}} {{.Os}}/{{.Architecture}}', scannerImageId])).trim();
  check(scannerIdentity === `${scannerImageId} linux/amd64`);
  if (decoderImage !== undefined) {
    const decoderIdentity = good(await control(['image', 'inspect', '--format',
      '{{.Id}} {{.Os}}/{{.Architecture}}', decoderImage])).trim();
    check(decoderIdentity === `${decoderImage} linux/amd64`);
  }
  const pinned = Object.freeze({ ...epoch });
  const actualCache = await realpath(cache);
  const dir = await realpath(resolve(snapshotDir));
  check(dir.startsWith(actualCache + sep) && !/[\r\n",]/u.test(dir));
  check(await snapshotDigest(dir) === pinned.defsSha256);
  const scanLimits = limits(scanner);
  const decLimits = decoderImage === undefined ? undefined : limits(decoder);
  const tool = ['--mount', `type=bind,source=${dir},target=/defs,readonly`, '--entrypoint', '/usr/bin/clamscan', scannerImageId];
  const maxFile = integer(scanner.maxFileBytes, 1024, Math.min(16 * 1024 * 1024, scanLimits.tmpfsMiB * 1024 * 1024 / 2));
  const maxScan = integer(scanner.maxScanBytes, maxFile, 64 * 1024 * 1024);
  const maxFiles = integer(scanner.maxFiles, 1, 1024);
  const maxRecursion = integer(scanner.maxRecursion, 1, 16);
  const daily = integer(scanner.dailyRevision, 1, 999999);
  const expectedBuild = new Date(pinned.defsBuiltAt).toUTCString();
  // UTC Date's RFC 1123 output and ClamAV's ctime output have different order.
  const [week, day, month, year, time] = expectedBuild.replace(',', '').split(' ');
  const version = `ClamAV 1.4.7/${daily}/${week} ${month} ${day.padStart(2, ' ').replace(/^0/u, ' ')} ${time} ${year}\n`;
  const clock = () => AbortSignal.timeout(scanLimits.wallMs);
  const verified = await run('defs-version', scanLimits, [...tool, '--database=/defs', '--version'], undefined, 4096, clock());
  check(verified.reaped && verified.exitCode === 0 && verified.signal === null && verified.stdoutEof && verified.stderrEof &&
    verified.stderr.length === 0 && verified.stdout.toString('utf8') === version);
  const launcher = Object.freeze({
    async scan(input, suppliedEpoch, signal) {
      check(input.byteLength > 0 && input.byteLength <= maxFile);
      check(suppliedEpoch.engineVersion === pinned.engineVersion && suppliedEpoch.engineImageSha256 === pinned.engineImageSha256 &&
        suppliedEpoch.defsSha256 === pinned.defsSha256 && suppliedEpoch.defsBuiltAt === pinned.defsBuiltAt);
      check(await snapshotDigest(dir) === pinned.defsSha256);
      const result = await run('scan', scanLimits, [
        ...tool, '--database=/defs', '--tempdir=/tmp', '--official-db-only=yes', '--bytecode=yes', '--bytecode-unsigned=no',
        '--disable-cache', '--heuristic-alerts=yes', '--alert-encrypted=yes', '--alert-exceeds-max=yes', '--alert-broken-media=yes',
        `--max-files=${maxFiles}`, `--max-recursion=${maxRecursion}`, `--max-filesize=${maxFile}`, `--max-scansize=${maxScan}`,
        '--max-scantime=0', '--no-summary', '-',
      ], [input], 4096, signal);
      check(await snapshotDigest(dir) === pinned.defsSha256);
      return result;
    },
    async decode(frames, maxOutputBytes, signal) {
      check(decLimits !== undefined);
      integer(maxOutputBytes, 1, 16 * 1024 * 1024);
      check(Array.isArray(frames) && frames.length === 3 && frames.reduce((n, b) => n + b.byteLength, 0) <= maxFile + 4100);
      return run('decode', decLimits, ['--entrypoint', '/usr/local/bin/node', decoderImage, '/worker/decoder-entry.js'], frames, maxOutputBytes, signal);
    },
  });
  return { launcher, epoch: pinned };
}

export async function syntheticSnapshotDigest(dir) { return snapshotDigest(dir); }
