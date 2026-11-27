import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { createConnection } from 'node:net';
import { resolve } from 'node:path';
import { performance } from 'node:perf_hooks';

// Run only against the precompiled application in the isolated Linux workspace.
// No dependency installation, compilation, database, shell, or signal simulation.
const root = resolve(import.meta.dirname, '../..');
const evidencePath = '/workspace/node_modules/.cache/linux-proof/posix.json';
const outputLimit = 128 * 1024;
const canary = 'synthetic-secret-canary';
const password = 'synthetic-runtime-password-placeholder';
const children = new Set();
let stage = 'runtime';
let interrupted = false;

function requireCondition(condition) {
  if (!condition) {throw new Error('proof failed');}
}

// Never inherit .env values, NODE_OPTIONS, DEBUG, or real credentials. Node and
// the entrypoint are absolute paths; only the harmless OS lookup paths survive.
function childEnvironment(port) {
  return {
    ...(process.env.PATH === undefined ? {} : { PATH: process.env.PATH }),
    ...(process.env.HOME === undefined ? {} : { HOME: process.env.HOME }),
    NODE_ENV: 'test', APP_HOST: '127.0.0.1', APP_PORT: String(port),
    SHUTDOWN_TIMEOUT_MS: '5000',
    DB_HOST: '127.0.0.1', DB_PORT: '55432', DB_NAME: 'fixlevelup_dev',
    DB_USER: 'fixlevelup_runtime', DB_PASSWORD: password,
    BOT_TOKEN: canary, NEST_LOG_LEVEL: canary,
  };
}

function refusedDatabase() {
  return new Promise((resolveProbe, reject) => {
    const socket = createConnection({ host: '127.0.0.1', port: 55432 });
    let refusal = false;
    let settled = false;
    const timer = setTimeout(() => finish(false), 1500);
    function finish(ok) {
      if (settled) {return;}
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (ok) {resolveProbe();}
      else {reject(new Error('database precondition failed'));}
    }
    socket.once('connect', () => finish(false));
    socket.once('error', (error) => { refusal = error.code === 'ECONNREFUSED'; });
    socket.once('close', () => finish(refusal));
  });
}

function startChild(role, entrypoint, args = []) {
  const child = spawn(process.execPath, [entrypoint, ...args], {
    cwd: root, env: childEnvironment(0), stdio: ['ignore', 'pipe', 'pipe'],
    shell: false,
  });
  const state = {
    child, closed: false, fault: false, result: undefined,
    stdout: '', stderr: '', pendingLine: '', bytes: 0, events: [], waiters: new Set(),
  };
  children.add(state);
  const notify = () => { for (const waiter of state.waiters) {waiter();} };
  state.fail = () => {
    state.fault = true;
    if (!state.closed) {child.kill('SIGKILL');}
    notify();
  };
  function parseLine(line) {
    if (!line.trim()) {return;}
    try {
      const parsed = JSON.parse(line);
      // Nest ConsoleLogger's JSON envelope stores the technical event in message.
      const message = parsed.message ?? parsed;
      requireCondition(message !== null && typeof message === 'object'
        && message.role === role && typeof message.event === 'string');
      state.events.push(message.event);
      if (/failed|timeout/.test(message.event)) {state.fail();}
    } catch { state.fail(); }
  }
  function capture(stream, chunk) {
    state.bytes += chunk.length;
    if (state.bytes > outputLimit) { state.fail(); return; }
    const text = chunk.toString('utf8');
    state[stream] += text;
    if (state[stream].includes(canary) || state[stream].includes(password)) {state.fail();}
    if (stream === 'stdout') {
      state.pendingLine += text;
      let newline;
      while ((newline = state.pendingLine.indexOf('\n')) !== -1) {
        parseLine(state.pendingLine.slice(0, newline));
        state.pendingLine = state.pendingLine.slice(newline + 1);
      }
    }
    notify();
  }
  child.stdout.on('data', (chunk) => capture('stdout', chunk));
  child.stderr.on('data', (chunk) => capture('stderr', chunk));
  child.stdout.on('error', state.fail);
  child.stderr.on('error', state.fail);
  child.once('error', state.fail);
  state.closePromise = new Promise((resolveClose) => {
    child.once('close', (code, signal) => {
      if (state.pendingLine) {parseLine(state.pendingLine);}
      state.closed = true;
      state.result = { code, signal };
      children.delete(state);
      notify();
      resolveClose();
    });
  });
  state.wait = (predicate, timeout) => new Promise((resolveWait, reject) => {
    const timer = setTimeout(() => settle(false), timeout);
    function settle(ok) {
      clearTimeout(timer);
      state.waiters.delete(check);
      if (ok) {resolveWait();}
      else {reject(new Error('child condition failed'));}
    }
    function check() {
      if (state.fault || interrupted) {settle(false);}
      else if (predicate()) {settle(true);}
      else if (state.closed) {settle(false);}
    }
    state.waiters.add(check);
    check();
  });
  return state;
}

async function assertAdmissionRefusal(role) {
  stage = `${role}-admission-refusal`;
  const entrypoint = resolve(root, `apps/api/dist/bootstrap/${role}.js`);
  const state = startChild(role, entrypoint);
  // No LAUNCH_* proof and no IPC channel are intentionally supplied. Production
  // API/worker entrypoints must fail closed instead of starting DB consumers.
  await state.wait(() => state.closed, 3000);
  requireCondition(state.result.code === 1 && state.result.signal === null
    && state.events.length === 1 && state.events[0] === 'admission_missing');
  requireCondition(!state.fault && state.stderr === ''
    && !state.stdout.includes(canary) && !state.stdout.includes(password));
}

async function runCase(role, signal) {
  const prefix = `${role}-${signal}`;
  stage = `${prefix}-startup`;
  requireCondition(!interrupted);
  // Exercise the exact compiled production registerShutdown hook in a small
  // disposable child. This is separate from application admission: the real
  // API/worker entrypoints above are tested to refuse without a signed proof.
  const helper = resolve(root, 'infra/linux-proof/lifecycle-child.mjs');
  const state = startChild(role, helper, [role]);
  await state.wait(() => state.events.includes('started') && !state.closed, 10000);
  stage = `${prefix}-signal`;
  requireCondition(!state.closed && !state.fault && !interrupted);
  const beforeSignal = performance.now();
  requireCondition(state.child.kill(signal));
  await state.wait(() => state.closed, 7500);
  const shutdownMs = Math.ceil(performance.now() - beforeSignal);
  stage = `${prefix}-assertions`;
  if (!(shutdownMs < 8000 && state.result.code === 0 && state.result.signal === null)) {
    // Redacted lifecycle facts only; never print child output, paths, env or credentials.
    console.error(`lifecycle outcome: ${JSON.stringify({ role, signal, shutdownMs,
      exitCode: state.result?.code ?? null, exitSignal: state.result?.signal ?? null,
      events: state.events, fault: state.fault, stderrBytes: Buffer.byteLength(state.stderr) })}`);
    throw new Error('Lifecycle child did not exit cleanly');
  }
  for (const event of ['started', 'shutdown_started', 'shutdown_completed']) {
    requireCondition(state.events.filter((value) => value === event).length === 1);
  }
  requireCondition(state.events.indexOf('started') < state.events.indexOf('shutdown_started')
    && state.events.indexOf('shutdown_started') < state.events.indexOf('shutdown_completed'));
  requireCondition(!state.fault && state.stderr === ''
    && !state.stdout.includes(canary) && !state.stdout.includes(password)
    && !state.events.some((event) => /failed|timeout/.test(event)));
  return { role, signal, exitCode: state.result.code, exitSignal: state.result.signal,
    shutdownMs, started: 1, shutdownStarted: 1, shutdownCompleted: 1,
    outputBytes: state.bytes, stderrBytes: 0, secretCanaryAbsent: true };
}

async function collectChildren() {
  const active = [...children];
  if (!active.length) {return;}
  for (const state of active) {state.child.kill('SIGKILL');}
  let timer;
  try {
    await Promise.race([
      Promise.all(active.map((state) => state.closePromise)),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('cleanup deadline exceeded')), 2000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
    // Even a failed cleanup cannot keep parent-side pipes/timers alive.
    for (const state of active) {
      state.child.stdout.destroy();
      state.child.stderr.destroy();
      state.child.unref();
    }
  }
}

function interrupt() {
  interrupted = true;
  for (const state of children) {state.fail();}
}

let evidence;
let failureStage;
try {
  requireCondition(process.platform === 'linux' && process.arch === 'x64'
    && process.versions.node === '24.22.3');
  process.on('SIGTERM', interrupt);
  process.on('SIGINT', interrupt);
  stage = 'database-refused';
  await refusedDatabase();
  for (const role of ['api', 'worker']) { await assertAdmissionRefusal(role); }
  const cases = [];
  for (const role of ['api', 'worker']) {
    for (const signal of ['SIGTERM', 'SIGINT']) {cases.push(await runCase(role, signal));}
  }
  requireCondition(!interrupted && children.size === 0);
  evidence = { node: process.versions.node, platform: process.platform, arch: process.arch,
    databaseConnectionRefused: true, admissionRefusalWithoutProof: true, cases };
} catch {
  failureStage = interrupted ? 'interrupted' : stage;
} finally {
  try { await collectChildren(); }
  catch { failureStage = 'cleanup'; }
  process.removeListener('SIGTERM', interrupt);
  process.removeListener('SIGINT', interrupt);
}

if (failureStage === undefined) {
  try {
    stage = 'evidence';
    requireCondition(!interrupted);
    await mkdir(resolve(evidencePath, '..'), { recursive: true });
    // This file contains only the bounded safe projection below (role, signal,
    // exit status, timings and boolean assertions). The Docker container runs as
    // root while the host evidence collector runs as the GitHub runner user;
    // 0600 would make the bind-mounted file unreadable to that collector.
    await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o644 });
  } catch { failureStage = stage; }
}
if (failureStage !== undefined) {
  // Do not print exceptions, child output, configuration, paths, or credentials.
  console.error(`Linux POSIX smoke FAIL: ${failureStage}`);
  process.exitCode = 1;
} else {
  console.log('Linux POSIX smoke PASS');
  console.log(JSON.stringify(evidence));
}
