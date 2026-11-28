/**
 * Strict P05 HTTPS matrix partition checker. Pins exact test-file inventory,
 * exact selected titles, status=passed for each selected title and the exact
 * number of intentionally filtered-out tests.
 */
import { readFileSync } from 'node:fs';

const suites = {
  normative: [
    'F normative HTTPS matrix inventory: phases cover every oracle cell exactly once',
    'F normative HTTPS matrix: lawful states 1/3',
    'F normative HTTPS matrix: lawful states 2/3',
    'F normative HTTPS matrix: lawful states 3/3',
    'F normative HTTPS matrix: exact roles and create shapes',
    'F normative HTTPS matrix: scope, proof and unmapped-route denials',
  ],
  'city-admin': [
    'CITY-RBAC × state × command: SYSTEM ADMIN CITY states 1/3',
    'CITY-RBAC × state × command: SYSTEM ADMIN CITY states 2/3',
    'CITY-RBAC × state × command: SYSTEM ADMIN CITY states 3/3',
  ],
  'city-manager': [
    'CITY-RBAC × state × command: SYSTEM MANAGER CITY states 1/3',
    'CITY-RBAC × state × command: SYSTEM MANAGER CITY states 2/3',
    'CITY-RBAC × state × command: SYSTEM MANAGER CITY states 3/3',
  ],
  'city-custom': [
    'CITY-RBAC × state × command: CUSTOM CITY states 1/3',
    'CITY-RBAC × state × command: CUSTOM CITY states 2/3',
    'CITY-RBAC × state × command: CUSTOM CITY states 3/3',
  ],
};

const [reportPath, suite] = process.argv.slice(2);
if (!reportPath || !suite || !Object.hasOwn(suites, suite)) {
  console.error('Usage: node infra/ci/p05-matrix-results.mjs <report.json> <suite>');
  console.error('Known suites: ' + Object.keys(suites).join(', '));
  process.exit(2);
}

let report;
try {
  report = JSON.parse(readFileSync(reportPath, 'utf8'));
} catch {
  console.error('P05 MATRIX GATE FAIL: unreadable report');
  process.exit(1);
}

const files = Array.isArray(report.testResults) ? report.testResults : [];
const problems = [];
if (files.length !== 1) {
  problems.push('expected one test file, received ' + String(files.length));
}

const file = files[0];
const fileName = typeof file?.name === 'string' ? file.name.replaceAll('\\', '/') : '';
if (!fileName.endsWith('/apps/api/tests/p05-intake-http.test.ts')
    && fileName !== 'apps/api/tests/p05-intake-http.test.ts') {
  problems.push('unexpected or missing test file');
}
if (file?.status !== 'passed') {
  problems.push('test file status is ' + String(file?.status || 'missing'));
}

const assertions = Array.isArray(file?.assertionResults) ? file.assertionResults : [];
const expected = suites[suite];
const expectedSet = new Set(expected);
const passed = assertions.filter(item => item.status === 'passed');
const skipped = assertions.filter(item =>
  item.status === 'pending' || item.status === 'skipped' || item.status === 'todo');
const failed = assertions.filter(item => !passed.includes(item) && !skipped.includes(item));

if (assertions.length !== 42) {
  problems.push('collected ' + String(assertions.length) + ' tests; pinned inventory is 42');
}
if (passed.length !== expected.length) {
  problems.push('passed ' + String(passed.length) + ' tests; exact suite requires ' + String(expected.length));
}
if (skipped.length !== 42 - expected.length) {
  problems.push('filtered/skipped ' + String(skipped.length) + ' tests; expected exactly ' + String(42 - expected.length));
}
if (failed.length > 0) {
  problems.push(String(failed.length) + ' test(s) have failed or unknown status');
}

for (const title of expected) {
  const matches = assertions.filter(item => item.title === title);
  if (matches.length !== 1) {
    problems.push('required title occurs ' + String(matches.length) + ' times: ' + title);
  } else if (matches[0].status !== 'passed') {
    problems.push('required title is not passed (' + String(matches[0].status) + '): ' + title);
  }
}
for (const item of passed) {
  if (!expectedSet.has(item.title)) {
    problems.push('unexpected test selected by filter: ' + String(item.title || '<untitled>'));
  }
}
for (const item of skipped) {
  if (expectedSet.has(item.title)) {
    problems.push('required scenario was skipped: ' + String(item.title));
  }
}

if (problems.length > 0) {
  for (const problem of problems) {
    console.error('P05 MATRIX GATE FAIL [' + suite + ']: ' + problem);
  }
  process.exit(1);
}
console.log('P05 MATRIX GATE PASS: ' + suite + '; ' + String(expected.length)
  + ' exact titles passed; ' + String(skipped.length) + ' other cases filtered; inventory 42/42');
