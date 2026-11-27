import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';

const browserImage = process.argv[2];
if (!browserImage || process.argv.length !== 3 || !/^fixlevelup-(?:p05-browser|browser-proof):[a-z0-9][a-z0-9.-]*$/u.test(browserImage)) {
  throw new Error('Usage: node infra/p05-lab/p06-browser.mjs <local fixlevelup-p05-browser or fixlevelup-browser-proof image tag>');
}

const instance = `p06-browser-${randomBytes(5).toString('hex')}`;
const env = { ...process.env, FIXLEVELUP_LAB_INSTANCE: instance };
delete env.FIXLEVELUP_LAB_DATABASE;
delete env.FIXLEVELUP_LAB_MIGRATION_LIMIT;
const cwd = new URL('../../', import.meta.url);
const statePath = new URL(`node_modules/.cache/p05-lab/instances/${instance}/state.json`, cwd);
const launchBrowser = `
  const { chromium } = require('/workspace/packages/browser-tooling/node_modules/@playwright/test');
  chromium.launchServer({ host: '127.0.0.1', port: 4178, wsPath: '/p06-registry',
    args: ['--no-proxy-server', '--host-resolver-rules=MAP crm.example.test 127.0.0.1'] }).then(() => {
    console.log('P06_BROWSER_READY');
  }).catch(() => { console.error('Chromium launch failed'); process.exitCode = 1; });
`;

function run(command, args, stdio = 'inherit') {
  const result = spawnSync(command, args, { cwd, env, stdio, encoding: 'utf8' });
  if (result.error) { throw result.error; }
  if (result.status !== 0) { throw new Error(`${command} ${args[0]} exited ${String(result.status)}`); }
  return result.stdout?.trim();
}

const lab = (...args) => run(process.execPath, ['infra/p05-lab/lab.mjs', ...args]);
const inspectContainer = (id, template) => run('docker', ['container', 'inspect', '--format', template, id], 'pipe');

function stopBrowser(id) {
  if (inspectContainer(id, '{{index .Config.Labels "dsh.owner"}}') !== instance) {
    throw new Error('Chromium container ownership check failed');
  }
  run('docker', ['stop', id]);
}

let browser;
let ownedLab = false;
try {
  const image = run('docker', ['image', 'inspect', '--format', '{{.Id}}', browserImage], 'pipe');
  if (!/^sha256:[a-f0-9]{64}$/u.test(image ?? '')) { throw new Error('Local Chromium image identity unavailable'); }
  ownedLab = true;
  lab('up', '--image=s3');
  const { pg, runId } = JSON.parse(readFileSync(statePath, 'utf8'));
  if (!/^[a-f0-9]{12}$/u.test(runId ?? '') || pg !== `p05lab-pg-${runId}`
    || inspectContainer(pg, '{{index .Config.Labels "dsh.purpose"}} {{.HostConfig.NetworkMode}}') !== 'p05-lab-pg none') {
    throw new Error('Disposable PostgreSQL namespace unavailable');
  }

  browser = run('docker', ['run', '--pull', 'never', '--rm', '--detach', '--name', instance, '--label', `dsh.owner=${instance}`,
    '--network', `container:${pg}`, '--shm-size', '256m', image, 'node', '-e', launchBrowser], 'pipe');
  if (!/^[a-f0-9]{64}$/u.test(browser ?? '')) { throw new Error('Chromium container identity unavailable'); }
  let ready = false;
  for (let attempt = 0; attempt < 30; attempt++) {
    const logs = run('docker', ['logs', browser], 'pipe');
    if (logs === 'P06_BROWSER_READY') { ready = true; break; }
    await delay(250);
  }
  if (!ready) { throw new Error('Chromium container did not start'); }

  lab('s3run', '--', 'env', 'FIXLEVELUP_P06_BROWSER=1', 'corepack', 'pnpm', 'exec', 'vitest', 'run',
    'apps/api/tests/p05-intake-http.test.ts', '-t', 'P06 browser renders and filters the live CRM registry');
} finally {
  try {
    if (browser) { stopBrowser(browser); }
  } finally {
    if (ownedLab) { lab('down'); }
  }
}
