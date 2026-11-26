// Test-only client for a single raw-scan / decode / output-scan sequence. A
// separate operator owns the real pinned launcher. No Docker endpoint or DB
// credential is passed to it. Each private session has a fresh one-use ticket.
import { createHash } from 'node:crypto';
import { link, lstat, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const root = '/p0305/node_modules/.cache/p05-engine-jobs';
const reject = () => { throw new Error('Private test engine did not confirm execution'); };

async function waitFor(path, signal, ms) {
  const end = performance.now() + ms;
  while (!signal.aborted && performance.now() < end) {
    try {
      const s = await lstat(path);
      if (!s.isFile() || s.size < 1 || s.size > 100_000) { reject(); }
      return JSON.parse(await readFile(path, 'utf8'));
    } catch (error) { if (error.code !== 'ENOENT') { throw error; } }
    await delay(50, undefined, { signal });
  }
  return reject();
}

export async function createFileProcessingTestLauncher(descriptor) {
  const ticket = process.env.FIXLEVELUP_LAB_ENGINE_TICKET ?? '';
  if (!/^[a-f0-9]{32}$/u.test(ticket) || process.env.FIXLEVELUP_SYNTHETIC_ORCHESTRATOR !== '1'
      || !['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS','FIXLEVELUP_STORAGE_S3_TESTS','FIXLEVELUP_FILE_PROCESSING_TESTS']
        .every(key => process.env[key] === '1')) { reject(); }
  const dir = join(root, ticket);
  const ready = await waitFor(join(dir,'ready.json'), AbortSignal.timeout(20_000), 20_000);
  const epoch = descriptor.epoch;
  if (ready.ticket !== ticket || !epoch || JSON.stringify(ready.epoch) !== JSON.stringify(epoch)) { reject(); }
  let next = 0;
  const expected = ['raw-scan', 'decode', 'output-scan'];
  async function exchange(op, frames, signal) {
    const n = next++;
    if (signal.aborted || expected[n] !== op || frames.some(b => !(b instanceof Uint8Array))
        || frames.reduce((size,b) => size+b.byteLength,0) > 65_100) { reject(); }
    const request = JSON.stringify({ ticket, op, parts: frames.map(b => Buffer.from(b).toString('base64')) });
    const prefix = join(dir, String(n));
    // The host-side controller runs as the runner UID while this disposable
    // container writes as root. The exchange parent is mode 0700, so 0644 keeps
    // the request private to the two bridge processes while allowing host reads.
    await writeFile(prefix+'.tmp',request,{flag:'wx',mode:0o644});
    // Atomic publish without replacing any previously published request.
    await link(prefix+'.tmp',prefix+'.req');
    const r = await waitFor(prefix+'.res',signal,50_000);
    if (r.ticket !== ticket || r.requestSha256 !== hash(request) || r.reaped !== true
        || ![r.stdinComplete,r.stdoutEof,r.stderrEof].every(b=>typeof b==='boolean')
        || (r.signal !== null && typeof r.signal !== 'string')
        || (r.exitCode !== null && !Number.isInteger(r.exitCode))
        || typeof r.stdout !== 'string' || typeof r.stderr !== 'string') { reject(); }
    return { reaped:r.reaped, exitCode:r.exitCode, signal:r.signal, stdinComplete:r.stdinComplete,
      stdoutEof:r.stdoutEof, stderrEof:r.stderrEof, stdout:Buffer.from(r.stdout,'base64'), stderr:Buffer.from(r.stderr,'base64') };
  }
  return {epoch,launcher:{
    scan: (bytes,pin,signal) => {
      if (pin.defsSha256 !== epoch.defsSha256 || pin.engineImageSha256 !== epoch.engineImageSha256
          || bytes.byteLength > 64_000) { reject(); }
      return exchange(next===0?'raw-scan':'output-scan',[bytes],signal);
    },
    decode: (frame,maximum,signal) => {
      if (frame.length!==3 || maximum!==64_000) { reject(); }
      return exchange('decode',frame,signal);
    },
  }};
}
