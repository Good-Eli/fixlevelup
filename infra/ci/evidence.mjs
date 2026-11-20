import { copyFileSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const stepNames = new Set(['offline frozen force reinstall', 'lint', 'typecheck', 'build all three targets', 'service-independent tests', 'API runtime graph isolation', 'real OS SIGTERM/SIGINT API/worker', 'runtime preflight', 'offline frozen install', 'isolated credential bootstrap', 'PostgreSQL 18.7 identity and fresh database', 'synthetic persistence marker bootstrap', 'db:roles', 'db:deploy', 'db:test-migrations', 'db:test-constraints', 'S3 bucket credentials preflight', 'full pnpm check', 'db:runtime-check', 'db:check', 'isolated database final invariants', 'PostgreSQL admin disconnect', 'redacted result write', 'browser lint/typecheck', 'browser typecheck', 'all production builds', 'real browser smoke']);
function safeStep(name) {
  const base = typeof name === 'string' ? name.replace(/: (?:command outcome|lockfile invariant)$/, '') : '';
  if (!stepNames.has(base)) { throw new Error('Unapproved evidence step'); }
  return name;
}
function numeric(value) {
  if (!Number.isFinite(value) || value < 0) { throw new Error('Invalid evidence number'); }
  return value;
}
function exitStatus(value) {
  if (value !== null && (!Number.isInteger(value) || value < 0 || value > 255)) { throw new Error('Invalid evidence exit status'); }
  return value;
}
function enumValue(value, values) {
  if (!values.includes(value)) { throw new Error('Invalid evidence enum'); }
  return value;
}
export function redactJson(name, value) {
  if (name === 'result.json') {
    const result = { redacted: true };
    for (const [key, allowed] of Object.entries({ node: ['24.22.3', 'v24.22.3'], platform: ['linux'], arch: ['x64'], playwright: ['1.65.1'], network: ['none'], status: ['passed', 'failed'], overallStatus: ['passed', 'failed'] })) {
      if (value[key] !== undefined) { result[key] = enumValue(value[key], allowed); }
    }
    if (value.lockSha256 !== undefined) {
      if (!/^[a-f0-9]{64}$/.test(value.lockSha256)) { throw new Error('Invalid evidence hash'); }
      result.lockSha256 = value.lockSha256;
    }
    if (value.failedStage !== undefined) { result.failedStage = value.failedStage === null ? null : safeStep(value.failedStage); }
    if (value.steps !== undefined) { result.steps = value.steps.map(step => typeof step === 'string' ? safeStep(step) : {
      name: safeStep(step.name), status: exitStatus(step.status), signal: enumValue(step.signal, [null, 'SIGTERM', 'SIGKILL', 'SIGINT', 'SIGABRT', 'SIGSEGV', 'SIGBUS', 'SIGHUP', 'SIGQUIT', 'SIGPIPE']),
      ...(step.error ? { error: enumValue(step.error, ['timeout', 'spawn failed', 'command did not complete successfully', 'lockfile hash verification failed']) } : {}),
    }); }
    return result;
  }
  if (name === 'posix.json') {
    return { node: enumValue(value.node, ['24.22.3']), platform: enumValue(value.platform, ['linux']), arch: enumValue(value.arch, ['x64']), databaseConnectionRefused: enumValue(value.databaseConnectionRefused, [true]), cases: value.cases.map(item => ({
      role: enumValue(item.role, ['api', 'worker']), signal: enumValue(item.signal, ['SIGTERM', 'SIGINT']), exitCode: enumValue(item.exitCode, [0]), exitSignal: enumValue(item.exitSignal, [null]),
      ...Object.fromEntries(['shutdownMs', 'started', 'shutdownStarted', 'shutdownCompleted', 'outputBytes', 'stderrBytes'].map(key => [key, numeric(item[key])])),
      secretCanaryAbsent: enumValue(item.secretCanaryAbsent, [true]),
      ...(item.role === 'api' ? { http: { live: { status: enumValue(item.http.live.status, [200]), marker: enumValue(item.http.live.marker, ['ok']) }, ready: { status: enumValue(item.http.ready.status, [503]), marker: enumValue(item.http.ready.marker, ['NOT_READY']) } } } : {}),
    })) };
  }
  if (name === 'browser-smoke.json') {
    const cases = [];
    function visit(suites) {
      for (const suite of suites ?? []) {
        for (const spec of suite.specs ?? []) {
          for (const test of spec.tests ?? []) {
            cases.push({ project: enumValue(test.projectName, ['chromium-desktop', 'chromium-mobile', 'firefox-desktop', 'firefox-mobile', 'webkit-desktop', 'webkit-mobile']), expectedStatus: enumValue(test.expectedStatus, ['passed', 'failed', 'skipped']), status: enumValue(test.status, ['expected', 'unexpected', 'flaky', 'skipped']),
              results: (test.results ?? []).map(result => ({ status: enumValue(result.status, ['passed', 'failed', 'timedOut', 'skipped', 'interrupted']), duration: numeric(result.duration), retry: numeric(result.retry) })) });
          }
        }
        visit(suite.suites);
      }
    }
    visit(value.suites);
    return { redacted: true, stats: Object.fromEntries(['duration', 'expected', 'unexpected', 'flaky', 'skipped'].filter(key => value.stats[key] !== undefined).map(key => [key, numeric(value.stats[key])])), cases };
  }
  throw new Error('Unapproved evidence JSON');
}
export function collectEvidence(sources, destination, { images = false } = {}) {
  let files = 0;
  function walk(source, target) {
    if (!existsSync(source)) { return; }
    if (!lstatSync(source).isDirectory()) { throw new Error('Unsafe evidence directory'); }
    for (const entry of readdirSync(source, { withFileTypes: true })) {
      const from = join(source, entry.name), to = join(target, entry.name);
      if (entry.isSymbolicLink()) { throw new Error('Unsafe evidence symlink'); }
      if (entry.isDirectory()) { walk(from, to); continue; }
      if (!entry.isFile() || lstatSync(from).size > 10 * 1024 * 1024) { continue; }
      if (['result.json', 'posix.json', 'browser-smoke.json'].includes(entry.name)) {
        const projected = redactJson(entry.name, JSON.parse(readFileSync(from, 'utf8')));
        mkdirSync(dirname(to), { recursive: true });
        writeFileSync(to, JSON.stringify(projected, null, 2) + '\n'); files++;
      } else if (images && ['web.png', 'miniapp.png'].includes(entry.name)) {
        if (!readFileSync(from).subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) { throw new Error('Invalid screenshot'); }
        mkdirSync(dirname(to), { recursive: true }); copyFileSync(from, to); files++;
      }
    }
  }
  for (const source of sources) { walk(resolve(source), destination); }
  if (!files) { throw new Error('No redacted evidence found'); }
  return { files, redacted: true };
}
export function writeContext(output) {
  const context = { schemaVersion: 1, redacted: true, commit: process.env.GITHUB_SHA ?? 'local',
    runner: process.env.RUNNER_OS ?? process.platform, runnerImage: process.env.ImageOS ?? 'unknown',
    runnerImageVersion: process.env.ImageVersion ?? 'unknown', arch: process.arch,
    node: process.version, pnpm: process.env.CI_PNPM_VERSION ?? 'unverified' };
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, JSON.stringify(context, null, 2) + '\n');
  return context;
}
export function summarizeJob(title, destination, steps, jobStatus) {
  const outcomes = Object.entries(steps).map(([name, step]) => ({ name, outcome: step.outcome, conclusion: step.conclusion }));
  const facts = [];
  function reports(directory) {
    if (!existsSync(directory)) { return; }
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const file = join(directory, entry.name);
      if (entry.isDirectory()) { reports(file); continue; }
      if (!entry.isFile() || !['browser-smoke.json', 'posix.json', 'dependencies.json', 'secrets.json'].includes(entry.name)) { continue; }
      const report = JSON.parse(readFileSync(file, 'utf8'));
      if (entry.name === 'browser-smoke.json') {
        for (const key of ['expected', 'unexpected', 'flaky', 'skipped']) { facts.push({ check: `browser-${key}`, count: numeric(report.stats[key]) }); }
      } else if (entry.name === 'posix.json') { facts.push({ check: 'real-POSIX-signal-cases', count: numeric(report.cases.length) }); }
      else if (entry.name === 'dependencies.json' && report.audit && report.licenseInventory) {
        for (const key of ['info', 'low', 'moderate', 'high', 'critical']) { facts.push({ check: `audit-${key}`, count: numeric(report.audit.counts[key]) }); }
        facts.push({ check: 'license-identities', count: numeric(report.licenseInventory.metadataEntries) });
        facts.push({ check: 'license-distribution-legal-follow-up', count: numeric(report.licenseInventory.requiresLegalReview.length) });
      } else if (entry.name === 'secrets.json') {
        facts.push({ check: 'secret-findings', count: numeric(report.scans.reduce((sum, scan) => sum + numeric(scan.findings), 0)) });
      }
    }
  }
  reports(destination);
  const result = { schemaVersion: 1, redacted: true, job: title, status: jobStatus,
    steps: outcomes, facts, limitation: 'Remote CI evidence only for this run; no production/image security or full visual/a11y acceptance' };
  mkdirSync(destination, { recursive: true });
  writeFileSync(join(destination, 'execution.json'), JSON.stringify(result, null, 2) + '\n');
  writeContext(join(destination, 'context.json'));
  if (process.env.GITHUB_STEP_SUMMARY) {
    const line = `### ${title}\n\nJob state: **${jobStatus}**. Actual step outcomes:\n\n| Step | Outcome |\n|---|---|\n${outcomes.map(step => `| ${step.name} | ${step.outcome} |`).join('\n')}\n\n${facts.map(fact => `- ${fact.check}: **${fact.count}**`).join('\n')}\n\nCommit: \`${process.env.GITHUB_SHA ?? 'local'}\`. Node: \`${process.version}\`, pnpm: \`${process.env.CI_PNPM_VERSION ?? 'unverified'}\`.\n\nJSON is projected/redacted; raw Compose, inspect, environment, Playwright errors and logs are not artifacts.\n`;
    writeFileSync(process.env.GITHUB_STEP_SUMMARY, line, { flag: 'a' });
  }
  return result;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const [mode, source, destination] = process.argv.slice(2);
    if (mode === 'collect') { collectEvidence(source.split(','), destination, { images: process.env.CI_INCLUDE_SCREENSHOTS === '1' }); }
    else if (mode === 'context') { writeContext(source); }
    else if (mode === 'summary') { summarizeJob(source, destination, JSON.parse(process.env.CI_STEPS ?? '{}'), process.env.CI_JOB_STATUS ?? 'unknown'); }
    else { throw new Error('Unsupported evidence operation'); }
  } catch { console.error('CI evidence operation failed safely.'); process.exitCode = 1; }
}
