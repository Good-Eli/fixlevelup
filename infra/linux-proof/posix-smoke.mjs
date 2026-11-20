import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { request } from 'node:http';
import { createConnection, createServer } from 'node:net';
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

function freePort() {
  return new Promise((resolvePort, reject) => {
    const server = createServer();
    let settled = false;
    const timer = setTimeout(() => finish(), 1500);
    function finish(port) {
      if (settled) {return;}
      settled = true;
      clearTimeout(timer);
      // No clients can be accepted: close immediately after obtaining the port.
      server.close(() => {
        if (port === undefined) {reject(new Error('port allocation failed'));}
        else {resolvePort(port);}
      });
    }
    server.once('error', () => finish());
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      finish(typeof address === 'object' && address !== null ? address.port : undefined);
    });
  });
}

function startChild(role, port) {
  const child = spawn(process.execPath, [resolve(root, `apps/api/dist/bootstrap/${role}.js`)], {
    cwd: root, env: childEnvironment(port), stdio: ['ignore', 'pipe', 'pipe'],
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

// Use a one-shot HTTP client, not a global fetch pool that can leave keepalive
// handles. Both the response body and the whole request have absolute bounds.
function health(port, path) {
  return new Promise((resolveHealth, reject) => {
    let settled = false;
    let response;
    const req = request({ host: '127.0.0.1', port, path, method: 'GET', agent: false,
      headers: { Connection: 'close' } });
    const timer = setTimeout(() => finish(), 3500);
    function finish(result) {
      if (settled) {return;}
      settled = true;
      clearTimeout(timer);
      response?.destroy();
      req.destroy();
      if (result === undefined) {reject(new Error('health request failed'));}
      else {resolveHealth(result);}
    }
    req.once('error', () => finish());
    req.once('response', (incoming) => {
      response = incoming;
      let body = '';
      let bytes = 0;
      incoming.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes > 16 * 1024) { finish(); return; }
        body += chunk.toString('utf8');
      });
      incoming.once('error', () => finish());
      incoming.once('aborted', () => finish());
      incoming.once('end', () => {
        try { finish({ status: incoming.statusCode, body: JSON.parse(body) }); }
        catch { finish(); }
      });
    });
    req.end();
  });
}

async function runCase(role, signal) {
  const prefix = `${role}-${signal}`;
  stage = `${prefix}-port`;
  // The actual entrypoint does not expose the port chosen by APP_PORT=0. In
  // this isolated container the listen(0)/close/rebind race is acceptable.
  const port = role === 'api' ? await freePort() : 0;
  requireCondition(!interrupted);
  stage = `${prefix}-startup`;
  const state = startChild(role, port);
  await state.wait(() => state.events.includes('started') && !state.closed, 10000);
  const http = {};
  if (role === 'api') {
    stage = `${prefix}-liveness`;
    const live = await health(port, '/health/live');
    requireCondition(live.status === 200 && live.body.status === 'ok');
    http.live = { status: live.status, marker: live.body.status };
    stage = `${prefix}-readiness`;
    const ready = await health(port, '/health/ready');
    requireCondition(ready.status === 503 && ready.body.code === 'NOT_READY'
      && ready.body.status === 503);
    http.ready = { status: ready.status, marker: ready.body.code };
  }
  stage = `${prefix}-signal`;
  requireCondition(!state.closed && !state.fault && !interrupted);
  const beforeSignal = performance.now();
  // This is an OS-delivered POSIX signal to the real compiled entrypoint.
  requireCondition(state.child.kill(signal));
  await state.wait(() => state.closed, 7500);
  const shutdownMs = Math.ceil(performance.now() - beforeSignal);
  stage = `${prefix}-assertions`;
  requireCondition(shutdownMs < 8000 && state.result.code === 0 && state.result.signal === null);
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
    outputBytes: state.bytes, stderrBytes: 0, secretCanaryAbsent: true,
    ...(role === 'api' ? { http } : {}) };
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
  const cases = [];
  for (const role of ['api', 'worker']) {
    for (const signal of ['SIGTERM', 'SIGINT']) {cases.push(await runCase(role, signal));}
  }
  requireCondition(!interrupted && children.size === 0);
  evidence = { node: process.versions.node, platform: process.platform, arch: process.arch,
    databaseConnectionRefused: true, cases };
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
    await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
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
