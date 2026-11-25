import { fork, spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdir, mkdtemp, readFile } from 'node:fs/promises';
import { request } from 'node:http';
import { createServer } from 'node:https';
import { setTimeout as wait } from 'node:timers/promises';
import { commission } from './commission.mjs';
import { provision } from './database.mjs';
import { observer } from './observer.mjs';
import { apiPort, host, isolated, origin, proofPort, tlsPort, token, webPort } from './isolation.mjs';
import { compileLauncherModules, launchGuarded } from '../p0305-browser-smoke/launch.mjs';
import { P04_ROUTES } from '../../packages/p03-contracts/dist/p04.js';
import { P03_ROUTES } from '../../packages/p03-contracts/dist/index.js';

const env = { PATH: process.env['PATH'], HOME: process.env['HOME'], COREPACK_HOME: process.env['COREPACK_HOME'],
  PLAYWRIGHT_BROWSERS_PATH: '/ms-playwright', NODE_ENV: 'production', NEXT_TELEMETRY_DISABLED: '1', CI: '1' };
const children = [];
let unexpected = 0;
const uuid = '[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}';
const approved = new Set(['/api/v1/auth/me','/api/v1/auth/login','/api/v1/auth/logout','/api/v1/access',
  '/api/v1/permissions','/api/v1/roles','/api/v1/staff','/api/v1/staff/self']);
const pathRules = [...Object.values(P04_ROUTES).map(route => route.path), ...Object.values(P03_ROUTES).map(route => `/api/v1${route}`),
  `/api/v1/settings/service-cities/:cityId`, '/api/v1/settings/service-cities/:cityId/versions',
  '/api/v1/settings/service-cities/:cityId/versions/:versionId/publish',
  '/api/v1/settings/service-cities/:cityId/administrative-districts', '/api/v1/settings/service-cities/:cityId/administrative-districts/:districtId',
  '/api/v1/settings/service-cities/:cityId/administrative-districts/:districtId/archive',
  '/api/v1/settings/service-cities/:cityId/service-areas', '/api/v1/settings/service-cities/:cityId/service-areas/:areaId',
  '/api/v1/settings/service-cities/:cityId/service-areas/:areaId/archive',
  '/api/v1/settings/service-cities/:cityId/service-areas/:areaId/versions',
  '/api/v1/settings/service-cities/:cityId/service-areas/:areaId/versions/:versionId',
  '/api/v1/settings/service-cities/:cityId/service-areas/:areaId/versions/:versionId/publish',
  '/api/v1/settings/service-cities', '/api/v1/roles/:id', '/api/v1/roles/:id/staff', '/api/v1/staff/:id',
].map(route => new RegExp(`^${route.replace(/\{([A-Za-z]+)\}|:([A-Za-z]+)/g, (_, a, b) => {
  const name = a ?? b;
  if (name === 'version') { return '[0-9]{1,10}'; }
  if (name === 'type' || name === 'permissionCode') { return '[a-z._]{1,64}'; }
  return uuid;
})}$`));

function childProcess(child) { children.push(child); child.on('error', () => {}); return child; }
async function awaitApi(child) {
  const result = await Promise.race([once(child, 'message'), once(child, 'exit'), wait(30000, [], { ref: false })]);
  if (result[0]?.ready !== true) { throw new Error('Compiled guarded API not ready'); }
}
async function probeNext(child) {
  for (let attempt = 0; attempt < 60; attempt++) {
    if (child.exitCode !== null || child.signalCode !== null) { break; }
    try {
      const r = await fetch(`http://${host}:${webPort}/crm/access`, { redirect: 'error', signal: AbortSignal.timeout(1000) });
      await r.body?.cancel();
      if (r.ok) { return; }
    } catch { /* not listening yet */ }
    await wait(500);
  }
  throw new Error('Production Next not ready');
}
function proxy(keys) {
  return createServer({ ...keys, requestTimeout: 12000, headersTimeout: 5000 }, (req, res) => {
    const url = new URL(req.url ?? '/', origin);
    const path = url.pathname;
    const backend = path.startsWith('/api/v1/');
    if (req.headers.host !== new URL(origin).host || url.origin !== origin || (backend && !approved.has(path) && !pathRules.some(rule => rule.test(path)))
      || (!backend && path !== '/crm/access' && !path.startsWith('/_next/static/') && path !== '/favicon.ico')) {
      unexpected++;
      res.writeHead(404).end(); return;
    }
    // The browser's real Host, Origin, cookies and Set-Cookie travel unchanged.
    const upstream = request({ host, port: backend ? apiPort : webPort, path: req.url, method: req.method, headers: req.headers }, response => {
      res.writeHead(response.statusCode ?? 502, response.headers); response.pipe(res);
    });
    upstream.on('error', () => { if (!res.headersSent) { res.writeHead(502); } res.end(); });
    upstream.setTimeout(12000, () => upstream.destroy());
    req.on('aborted', () => upstream.destroy());
    res.on('close', () => upstream.destroy());
    req.pipe(upstream);
  });
}

const groups = ['item','price','district','coverage','faq','contact'];
function assertScenario(reports) {
  const complete = reports.filter(r => groups.every(key => r.writes[key]?.exact) && r.deniedReceipts === 0);
  if (complete.length < 2 || JSON.stringify(complete.at(-1)) !== JSON.stringify(complete.at(-2))) {
    throw new Error('Missing exact persisted effects or stable before/after denial evidence');
  }
}

async function listener(server, port) {
  await once(server.listen(port, host), 'listening');
}

async function browser(fixture, proofToken) {
  const child = childProcess(spawn('corepack', ['pnpm','--filter','@fixlevelup/browser-tooling','exec','playwright','test','-c','playwright.p0404.config.ts'], {
    env: { ...env, NODE_ENV: 'test', P0404_LIVE: '1', P0404_PROOF_TOKEN: proofToken,
      P0404_ADMIN_ID: fixture.administrator.id, P0404_ADMIN_LOGIN: fixture.administrator.login, P0404_ADMIN_PASSWORD: fixture.administrator.password,
      P0404_MANAGER_ID: fixture.manager.id, P0404_MANAGER_LOGIN: fixture.manager.login, P0404_MANAGER_PASSWORD: fixture.manager.password,
      P0404_CITY_ID: fixture.cityId, P0404_OUTSIDE_CITY_ID: fixture.outsideCityId }, stdio: ['ignore','pipe','ignore'],
  }));
  let output = '', oversized = false;
  child.stdout.setEncoding('utf8').on('data', chunk => {
    if (output.length + chunk.length > 65536) { oversized = true; child.kill(); } else { output += chunk; }
  });
  const [status] = await once(child, 'close');
  const summary = output.split(/\r?\n/).filter(line => /^P04-04 HTTPS browser: (?:passed|failed|timedOut|skipped|interrupted)(?: \(fixture line (?:unknown|[0-9]{1,5})\))?$/.test(line));
  for (const line of summary) { console.log(line); }
  if (status !== 0 || oversized || summary.length === 0 || summary.some(line => line !== 'P04-04 HTTPS browser: passed') || unexpected !== 0) {
    throw new Error('Browser scenario or ingress confinement failed');
  }
}

let fixture, ingress, evidence, launch;
let stage = 'namespace guard';
try {
  const namespace = await isolated();
  stage = 'pinned S0 cap / first-admin bootstrap / disposable control contour';
  fixture = await provision(namespace);
  console.log(`P04-04 S0 cap: applied ${String(fixture.migrationReport.applied)} of ${String(fixture.migrationReport.chain)} migrations; excluded ${fixture.migrationReport.excluded.join(', ')}`);
  delete process.env['P0404_PG_BOOTSTRAP'];
  stage = 'compiled Nest / P03 and P04 readiness behind a guarded one-use launch';
  const modules = await compileLauncherModules();
  launch = await launchGuarded({
    modules, consumerKind: 'API', appDatabase: fixture.database, appOperator: fixture.operator,
    control: fixture.control.facts, databaseOid: fixture.databaseOid,
    artifact: fixture.artifact, history: fixture.history, physical: fixture.physical,
    startChild: (launchEnv) => childProcess(fork(new URL('./launch-api.mjs', import.meta.url), [],
      { execArgv: [], stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
        env: { ...env, ...launchEnv, P0404_ISOLATED_BROWSER: '1', P0404_NAMESPACE: namespace.marker,
          P0404_RUNTIME_PASSWORD: fixture.runtimePassword } })),
  });
  await awaitApi(launch.child);
  const consumed = await launch.registryState();
  if (consumed?.state !== 'CONSUMED') { throw new Error('Launch proof was not consumed exactly once'); }
  stage = 'authorized staff, role and city commissioning';
  await commission(fixture, label => { stage = `authorized commissioning / ${label}`; });
  const reports = [], proofToken = token();
  stage = 'private Node-only read-back observer';
  evidence = observer(fixture, proofToken, reports);
  await listener(evidence, proofPort);
  if (process.env['P0404_FIXTURE_ONLY'] === '1') {
    stage = 'standalone real command and observer verification';
    await (await import('./self-check.mjs')).selfCheck(fixture, proofToken, label => { stage = `standalone commands / ${label}`; });
    assertScenario(reports);
    console.log('P04-04 fixture: PG 18.7 / pinned S0 cap (21 of 24) / real P03/P04 command and authorization / exact observer PASS (no browser scenario)');
  } else {
    stage = 'production Next and ephemeral HTTPS ingress';
    const next = childProcess(spawn(process.execPath, ['apps/web/scripts/next.mjs','start','--hostname',host,'--port',String(webPort)], { env, stdio: 'ignore' }));
    await probeNext(next);
    await mkdir('node_modules/.cache', { recursive: true, mode: 0o700 });
    const dir = await mkdtemp('node_modules/.cache/p0404-live-');
    const cert = `${dir}/server.pem`, key = `${dir}/server.key`;
    const openssl = spawnSync('openssl', ['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
      '-addext','subjectAltName=IP:127.0.0.1,DNS:localhost','-keyout',key,'-out',cert], { env, stdio: 'ignore', timeout: 10000 });
    if (openssl.status !== 0) { throw new Error('Disposable TLS certificate generation failed'); }
    ingress = proxy({ key: await readFile(key), cert: await readFile(cert) });
    await listener(ingress, tlsPort);
    stage = 'production HTTPS browser scenario / exact and denied PostgreSQL evidence';
    await browser(fixture, proofToken);
    assertScenario(reports);
    console.log('P04-04 browser proof: PG 18.7 / pinned S0 cap (21 of 24) / guarded one-use launch / production Nest + Next / exact item, price, district, coverage, FAQ, contact / denied counts unchanged / unexpected ingress 0');
    console.log(JSON.stringify(reports.filter(r => groups.every(key => r.writes[key]?.exact)).at(-1)));
  }
} catch {
  console.error(`P04-04 smoke failed: ${stage} (private details suppressed)`);
  process.exitCode = 1;
} finally {
  for (const child of children.reverse()) {
    if (child.exitCode === null && child.signalCode === null) { child.kill(); }
  }
  for (const server of [evidence, ingress]) {
    if (server) { server.close(); server.closeAllConnections(); }
  }
  await launch?.stop().catch(() => undefined);
  if (fixture) { await fixture.migrator.end(); }
}
