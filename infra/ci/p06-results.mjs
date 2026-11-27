/**
 * Strict P06 Gate result check (CI, exact SHA).
 *
 * A P06 opt-in suite is enabled by an environment flag, so a missing flag makes
 * it *skip* instead of failing. A green job would then say nothing about P06.
 * This checker turns a Vitest JSON report into a hard gate:
 *
 *   - every test file in the report must have passed;
 *   - the number of passed tests must reach the pinned minimum;
 *   - the number of skipped/todo tests must equal the pinned value exactly
 *     (default 0), so a silently disabled suite is a failure, not a skip;
 *   - every `--require <title>` must be present and passed.
 *
 * Usage:
 *   node infra/ci/p06-results.mjs <report.json> <minPassed>
 *     [--skipped <count>] [--require <exact title>]...
 *
 * Exit code 0 only when every condition holds. Prints one redacted line and, on
 * failure, titles only — never payloads, credentials or absolute paths.
 */
import { readFileSync } from 'node:fs';

const argv = process.argv.slice(2);
const positional = [];
const required = [];
let expectedSkipped = 0;
let expectedTotal;
for (let index = 0; index < argv.length; index += 1) {
  const argument = argv[index];
  if (argument === '--require') {
    const title = argv[index + 1];
    if (title === undefined) { console.error('Missing --require value'); process.exit(2); }
    required.push(title);
    index += 1;
  } else if (argument === '--skipped') {
    const raw = argv[index + 1];
    const parsed = Number(raw);
    if (raw === undefined || !Number.isInteger(parsed) || parsed < 0) {
      console.error('Invalid --skipped value');
      process.exit(2);
    }
    expectedSkipped = parsed;
    index += 1;
  } else if (argument === '--total') {
    const raw = argv[index + 1];
    const parsed = Number(raw);
    if (raw === undefined || !Number.isInteger(parsed) || parsed < 1) {
      console.error('Invalid --total value');
      process.exit(2);
    }
    expectedTotal = parsed;
    index += 1;
  } else if (argument.startsWith('--')) {
    console.error(`Unknown option ${argument}`);
    process.exit(2);
  } else {
    positional.push(argument);
  }
}

const [reportPath, minimumRaw] = positional;
if (reportPath === undefined || minimumRaw === undefined) {
  console.error('Usage: node infra/ci/p06-results.mjs <report.json> <minPassed> [--skipped <n>] [--require <title>]...');
  process.exit(2);
}
const minimum = Number(minimumRaw);
if (!Number.isInteger(minimum) || minimum < 1) {
  console.error('Invalid minimum passed test count');
  process.exit(2);
}

let report;
try {
  report = JSON.parse(readFileSync(reportPath, 'utf8'));
} catch {
  console.error(`P06 GATE FAIL: unreadable Vitest report ${reportPath.split(/[\\/]/u).pop() ?? 'report'}`);
  process.exit(1);
}

const results = Array.isArray(report.testResults) ? report.testResults : [];
const assertions = results.flatMap((file) =>
  (Array.isArray(file.assertionResults) ? file.assertionResults : []).map((assertion) => ({
    title: typeof assertion.title === 'string' ? assertion.title : '',
    fullName: typeof assertion.fullName === 'string' ? assertion.fullName : '',
    status: assertion.status,
    file: typeof file.name === 'string' ? file.name : '',
  })));

const passed = assertions.filter((assertion) => assertion.status === 'passed');
const skipped = assertions.filter((assertion) => assertion.status === 'pending'
  || assertion.status === 'skipped' || assertion.status === 'todo');
const failed = assertions.filter((assertion) => !passed.includes(assertion) && !skipped.includes(assertion));
const failedFiles = results.filter((file) => file.status !== 'passed');
const missing = required.filter((title) =>
  !passed.some((assertion) => assertion.title === title || assertion.fullName === title));

const problems = [];
if (results.length === 0) { problems.push('no test files were executed'); }
if (passed.length < minimum) {
  problems.push(`only ${String(passed.length)} tests passed, minimum is ${String(minimum)}`);
}
if (failed.length > 0) { problems.push(`${String(failed.length)} test(s) not passed`); }
if (failedFiles.length > 0) { problems.push(`${String(failedFiles.length)} file(s) not passed`); }
if (skipped.length !== expectedSkipped) {
  problems.push(`${String(skipped.length)} skipped test(s), expected exactly ${String(expectedSkipped)}`);
}
if (expectedTotal !== undefined && assertions.length !== expectedTotal) {
  problems.push(`${String(assertions.length)} collected test(s), expected exactly ${String(expectedTotal)}`);
}
if (missing.length > 0) { problems.push(`${String(missing.length)} required test(s) missing`); }

if (problems.length > 0) {
  for (const assertion of failed.slice(0, 20)) {
    const file = assertion.file.split(/[\\/]/u).pop() ?? 'unknown';
    console.error(`P06 GATE FAIL ${file}: ${assertion.status} — ${assertion.title}`);
  }
  for (const assertion of skipped.slice(0, 20)) {
    const file = assertion.file.split(/[\\/]/u).pop() ?? 'unknown';
    console.error(`P06 GATE FAIL ${file}: unexpected skip — ${assertion.title}`);
  }
  for (const title of missing.slice(0, 20)) {
    console.error(`P06 GATE FAIL missing required test — ${title}`);
  }
  console.error(`P06 GATE FAIL: ${problems.join('; ')}`);
  process.exit(1);
}

console.log(`P06 GATE PASS: ${String(passed.length)} passed, ${String(skipped.length)} skipped (pinned), `
  + `${String(results.length)} file(s), ${String(required.length)} required title(s) present `
  + `(${reportPath.split(/[\\/]/u).pop() ?? 'report'})`);
