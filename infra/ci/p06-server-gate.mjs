/**
 * P06 server Gate (runs INSIDE the isolated lab container).
 *
 * The lab image is a snapshot of the tree under test; the disposable PostgreSQL
 * database is created for this command only. This script is the single place
 * that decides whether the server side of the P06 Gate passed:
 *
 *   1. the accepted P06 scenarios in `p05-intake-http.test.ts` (name-filtered);
 *   2. every dedicated `p06-*.test.ts` suite (registry, gap DB, gap HTTPS);
 *   3. both Vitest JSON reports are checked by `p06-results.mjs`, which refuses
 *      a skipped opt-in suite, a missing required scenario, or a failure.
 *
 * It prints exactly one machine-readable `P06 GATE SUMMARY {...}` line so the CI
 * job can publish a small redacted summary even though the container filesystem
 * is discarded with the run.
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '../..');
const tests = resolve(root, 'apps/api/tests');
// Explicit list: no shell glob expansion here, and a silently missing suite must
// fail the gate instead of shrinking the set.
const dedicated = readdirSync(tests)
  .filter(name => /^p06-.*\.test\.ts$/u.test(name))
  .sort()
  .map(name => `apps/api/tests/${name}`);
const EXPECTED_DEDICATED = 4;
if (dedicated.length !== EXPECTED_DEDICATED) {
  throw new Error(`Expected exactly ${String(EXPECTED_DEDICATED)} dedicated P06 suites, found ${String(dedicated.length)}`);
}

const results = resolve(root, 'node_modules/.cache/ci-artifacts/p06/results');
mkdirSync(results, { recursive: true });

const ACCEPTED_REQUIRED = [
  'P06 registry paginates only visible requests over HTTPS',
  'P06 registry enforces GLOBAL and CITY grants over HTTPS',
  'P06 card and timeline use the request authority and the existing command validator',
  'P06 comments are private, encrypted, versioned and idempotent over HTTPS',
  'P06 contact details require explicit CITY authority and audit, and hide no-call phone',
  'P06 search uses protected exact matches, independent CITY authority and durable quotas',
  'P06 search removes revoked and obsolete tokens and rebuilds a rotated historic index',
  'P06 search limits the retained and locked results across bounded candidate batches',
  'P06 dashboard keeps counts and pages on one authorized snapshot and refreshes expired or changed data',
  'P06 dashboard paginates a large snapshot without N+1 and uses true city-day bounds',
];

const GAP_REQUIRED = [
  'grants the runtime role no direct DML on the comment overlay',
  'refuses a direct comment INSERT even with a matching audit row',
  'admits exactly one comment and one audit row through the DB writer',
  'refuses the DB writer without a live CRM bearer, read authority or comment grant',
  'refuses the DB writer when the processing basis is withdrawn or has expired',
  're-runs the basis check at COMMIT and rolls the whole insert back',
  'keeps the audit and the comment atomic when the audit insert fails',
  'fails the read path closed when the external key slot is missing',
  'refuses PII before any decryption and commits the durable audit before disclosure',
  'denies PII on a revoked consent or revoked session and hides the phone under no-call',
  'refuses PII when the durable audit cannot be written, without decrypting or leaking',
  'enforces the role × scope × employment × request-state matrix over HTTPS',
  'serializes a mid-read authority revocation and denies every later request',
  'keeps one row for concurrent identical idempotency keys and refuses a content conflict',
  'fails closed with no partial effect when the comment audit insert fails',
  'survives an uncertain COMMIT without duplicating the comment',
  'keeps search consistent while the phone permission and the consent change',
  'enforces the exact STAFF and CITY search quota boundaries and leaks no token',
  'rejects an obsolete index generation and accepts only the rebuilt one',
  'keeps dashboard counts equal to the registry selection and refreshes on change',
  'invalidates a dashboard snapshot when a counted request loses its basis or the reader loses rights',
  'bounds the candidate scan and refuses instead of serving a partial page',
  'binds the cursor to city, city version and every filter value, but accepts it unchanged',
  'returns a complete page even when the candidate budget is exhausted later',
  'stops on a short batch below the candidate budget without refusing',
  'derives a deterministic idempotency HMAC per key, namespace and intent',
  'seals, opens and binds a managed DETAILS payload without exposing plaintext',
];

function run(label, command, args) {
  const result = spawnSync(command, args, { cwd: root, stdio: 'inherit' });
  if (result.error) { throw result.error; }
  if (result.status !== 0) { throw new Error(`${label} failed (exit ${String(result.status)})`); }
}

function check(report, minimum, total, skipped, required) {
  const args = [resolve(root, 'infra/ci/p06-results.mjs'), report, String(minimum)];
  if (total !== undefined) { args.push('--total', String(total)); }
  if (skipped !== undefined) { args.push('--skipped', String(skipped)); }
  for (const title of required) { args.push('--require', title); }
  run(`P06 results check ${report}`, process.execPath, args);
}

function count(report) {
  const parsed = JSON.parse(readFileSync(report, 'utf8'));
  const files = (Array.isArray(parsed.testResults) ? parsed.testResults : []).map(file => {
    const assertions = Array.isArray(file.assertionResults) ? file.assertionResults : [];
    return {
      file: file.name.split('/').pop(),
      passed: assertions.filter(assertion => assertion.status === 'passed').length,
      skipped: assertions.filter(assertion => assertion.status === 'pending'
        || assertion.status === 'skipped').length,
      failed: assertions.filter(assertion => assertion.status === 'failed').length,
    };
  });
  const total = key => files.reduce((sum, file) => sum + file[key], 0);
  return { passed: total('passed'), skipped: total('skipped'), failed: total('failed'), files };
}

const accepted = resolve(results, 'p06-accepted.json');
const gap = resolve(results, 'p06-gap.json');
const summary = { gate: 'p06-server', reports: {} };

try {
  run('accepted P06 scenarios', 'corepack', ['pnpm', 'exec', 'vitest', 'run', '--maxWorkers', '1',
    '--testNamePattern', 'P06', '--reporter=json', `--outputFile=${accepted}`,
    'apps/api/tests/p05-intake-http.test.ts']);
  run('dedicated P06 suites', 'corepack', ['pnpm', 'exec', 'vitest', 'run', '--maxWorkers', '1',
    '--reporter=json', `--outputFile=${gap}`, ...dedicated]);
  // Counts are published even when a check below fails, so the job summary always
  // shows what actually ran.
  summary.reports.accepted = count(accepted);
  summary.reports.gap = count(gap);
  // The name filter must keep exactly 11 P06 scenarios out of 42 collected tests:
  // 31 non-P06 tests and the browser proof (which runs in its own Gate stage) are
  // skipped. A changed filter or a lost opt-in flag cannot shrink the set quietly.
  check(accepted, 11, 42, 31, ACCEPTED_REQUIRED);
  check(gap, 100, undefined, 0, GAP_REQUIRED);
  summary.status = 'passed';
  writeFileSync(resolve(results, 'server-summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
  console.log(`P06 GATE SUMMARY ${JSON.stringify(summary)}`);
} catch (error) {
  summary.status = 'failed';
  summary.error = error instanceof Error ? error.message : 'unknown';
  writeFileSync(resolve(results, 'server-summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
  console.log(`P06 GATE SUMMARY ${JSON.stringify(summary)}`);
  process.exitCode = 1;
}
