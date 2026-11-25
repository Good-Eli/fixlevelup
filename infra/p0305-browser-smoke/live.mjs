import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdir, mkdtemp, readFile } from 'node:fs/promises';
import { request } from 'node:http';
import { createServer } from 'node:https';
import { createServer as createHttpServer } from 'node:http';
import { setTimeout as wait } from 'node:timers/promises';
import { database, provision, verifyPublication } from './database.mjs';
import { compileLauncherModules, host, launchGuarded, pgPort, token } from './launch.mjs';

const api = 4174;
const web = 4175;
const tls = 4176;
const origin = `https://${host}:${tls}`;
const run = [];
const approved = new Set(['/api/v1/auth/me', '/api/v1/auth/login', '/api/v1/auth/logout', '/api/v1/access', '/api/v1/permissions', '/api/v1/roles', '/api/v1/staff', '/api/v1/staff/self']);
const legal = /^\/api\/v1\/legal\/documents(?:\/[a-f0-9-]{36}(?:\/(?:publish|versions(?:\/[a-f0-9-]{36})?))?)?$/u;
let unexpected = 0;

const baseEnv = { PATH: process.env['PATH'], HOME: process.env['HOME'], COREPACK_HOME: process.env['COREPACK_HOME'],
  PLAYWRIGHT_BROWSERS_PATH: '/ms-playwright', NODE_ENV: 'production', NEXT_TELEMETRY_DISABLED: '1', CI: '1' };

function start(args, extra = {}) {
  const child = spawn(process.execPath, args, { env: { ...baseEnv, ...extra }, stdio: 'ignore' });
  child.on('error', () => {});
  run.push(child);
  return child;
}
/** Spawns the real compiled entrypoint with the inherited private IPC channel. */
function startAdmitted(extra) {
  const child = spawn(process.execPath, ['apps/api/dist/bootstrap/api.js'],
    { env: { ...baseEnv, ...extra }, stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
  child.on('error', () => {});
  run.push(child);
  return child;
}
async function probe(url, child) {
  for (let attempt = 0; attempt < 60; attempt++) {
    if (child.exitCode !== null || child.signalCode !== null) { break; }
    try {
      const r = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(1000) });
      await r.body?.cancel();
      if (r.ok) { return; }
    } catch { /* Service is not listening yet. */ }
    await wait(500);
  }
  throw new Error('Production application not ready');
}

function proxy(keys) {
  return createServer(keys, (req, res) => {
    const path = new URL(req.url ?? '/', origin).pathname;
    const backend = path.startsWith('/api/v1/');
    if (req.headers.host !== new URL(origin).host || (backend && !approved.has(path) && !legal.test(path))
      || (!backend && path !== '/crm/access' && !path.startsWith('/_next/static/') && path !== '/favicon.ico')) {
      unexpected++;
      res.writeHead(404).end();
      return;
    }
    // The browser's actual Host, Origin, cookies and Set-Cookie are never rewritten.
    const upstream = request({ host, port: backend ? api : web, path: req.url, method: req.method, headers: req.headers }, response => {
      res.writeHead(response.statusCode ?? 502, response.headers);
      response.pipe(res);
    });
    upstream.on('error', () => { if (!res.headersSent) { res.writeHead(502); } res.end(); });
    upstream.setTimeout(12_000, () => upstream.destroy());
    req.on('aborted', () => upstream.destroy());
    res.on('close', () => upstream.destroy());
    req.pipe(upstream);
  });
}

let fixture, ingress, evidence, launch;
let stage = 'namespace guard';
try {
  if (process.platform !== 'linux' || process.version !== 'v24.22.3' || process.env['P0305_ISOLATED_BROWSER'] !== '1') {
    throw new Error('Must invoke isolated container fixture');
  }
  if ((await readFile('/proc/net/dev', 'utf8')).trim().split('\n').slice(2).some(line => !/^\s*lo:/u.test(line))) {
    throw new Error('Fixture network namespace has a non-loopback interface');
  }
  const marker = process.env['P0305_NAMESPACE'];
  if (!/^[a-f0-9]{24}$/u.test(marker ?? '')) { throw new Error('Disposable network identity missing'); }
  stage = 'pinned S0 migrations, synthetic commissioning and disposable control contour';
  fixture = await provision(marker);
  console.log(`P03-05 S0 cap: applied ${String(fixture.migrationReport.applied)} of ${String(fixture.migrationReport.chain)} migrations; excluded ${fixture.migrationReport.excluded.join(', ')}`);
  stage = 'ephemeral TLS';
  await mkdir('node_modules/.cache', { recursive: true, mode: 0o700 });
  const dir = await mkdtemp('node_modules/.cache/p0305-live-');
  const cert = `${dir}/server.pem`, key = `${dir}/server.key`;
  const openssl = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost', '-keyout', key, '-out', cert], { stdio: 'ignore', timeout: 10_000 });
  if (openssl.status !== 0) { throw new Error('Fixture TLS generation failed'); }
  ingress = proxy({ key: await readFile(key), cert: await readFile(cert) });
  ingress.listen(tls, host);
  await once(ingress, 'listening');

  stage = 'guarded launch of the compiled API (one-use proof, launcher witness)';
  const modules = await compileLauncherModules();
  launch = await launchGuarded({
    modules, consumerKind: 'API', appDatabase: fixture.database, appOperator: fixture.operator,
    control: fixture.control.facts, databaseOid: fixture.databaseOid,
    artifact: fixture.artifact, history: fixture.history, physical: fixture.physical,
    startChild: (launchEnv) => startAdmitted({
      ...launchEnv, APP_HOST: host, APP_PORT: String(api), DB_HOST: host, DB_PORT: String(pgPort), DB_NAME: database,
      DB_USER: 'fixlevelup_runtime', DB_PASSWORD: fixture.database.password,
      WEB_AUTH_ENABLED: '1', WEB_AUTH_ORIGIN: origin, WEB_AUTH_CSRF_SECRET: token(), WEB_AUTH_THROTTLE_SECRET: token(),
    }),
  });
  const nest = launch.child;
  await probe(`http://${host}:${api}/health/ready`, nest);
  const consumed = await launch.registryState();
  if (consumed?.state !== 'CONSUMED') { throw new Error('Launch proof was not consumed exactly once'); }

  stage = 'compiled Next readiness';
  const next = start(['apps/web/scripts/next.mjs', 'start', '--hostname', host, '--port', String(web)]);
  await probe(`http://${host}:${web}/crm/access`, next);

  // Private, loopback-only verification channel. Browser never opens it and no API fixtures replace Nest.
  const proofToken = token();
  evidence = createHttpServer({ requestTimeout: 5000 }, async (req, res) => {
    if (req.headers.authorization !== `Bearer ${proofToken}` || req.method !== 'POST' || req.url !== '/proof') {
      res.writeHead(404).end(); return;
    }
    try {
      let bytes = 0;
      const chunks = [];
      for await (const chunk of req) {
        bytes += chunk.length;
        if (bytes > 65536) { throw new Error('Verification input too large'); }
        chunks.push(chunk);
      }
      const result = await verifyPublication(fixture, JSON.parse(Buffer.concat(chunks).toString('utf8')));
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(result));
    } catch { res.writeHead(500).end(); }
  });
  evidence.listen(4177, host);
  await once(evidence, 'listening');

  stage = 'real browser and PostgreSQL assertions';
  const testEnv = { ...process.env, NODE_ENV: 'test', NEXT_TELEMETRY_DISABLED: '1', P0305_LIVE: '1', P0305_PROOF_TOKEN: proofToken,
    P0305_ADMIN_LOGIN: fixture.administrator.login, P0305_ADMIN_PASSWORD: fixture.administrator.password,
    P0305_MANAGER_LOGIN: fixture.manager.login, P0305_MANAGER_PASSWORD: fixture.manager.password,
    P0305_MANAGER_ID: fixture.manager.id };
  delete testEnv['P0305_PG_BOOTSTRAP'];
  const child = spawn('corepack', ['pnpm', '--filter', '@fixlevelup/browser-tooling', 'exec', 'playwright', 'test', '-c', 'playwright.p0305.config.ts'],
    { env: testEnv, stdio: 'inherit' });
  run.push(child);
  const [exit] = await once(child, 'exit');
  if (exit !== 0 || unexpected !== 0) { throw new Error('Live test or unexpected-origin/path assertion failed'); }
  console.log('P03-05 HTTPS browser / isolated PostgreSQL smoke passed; unknown proxy requests: 0');
} catch {
  console.error(`P03-05 smoke failed: ${stage} (private details suppressed)`);
  process.exitCode = 1;
} finally {
  for (const child of run.reverse()) { if (child.exitCode === null && child.signalCode === null) { child.kill(); } }
  for (const server of [evidence, ingress]) {
    if (server) { server.closeAllConnections(); server.close(); }
  }
  await launch?.stop().catch(() => undefined);
  if (fixture) { await fixture.migrator.end().catch(() => undefined); }
}
