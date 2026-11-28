import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
const script = fileURLToPath(new URL('./p05-matrix-results.mjs', import.meta.url));
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
function makeReport(suite, mutate = () => {}) {
  const selected = suites[suite];
  const assertionResults = Array.from({ length: 42 - selected.length }, (_, i) => ({
    title: 'filtered unrelated case ' + String(i + 1), status: 'pending',
  }));
  for (const title of selected) assertionResults.push({ title, status: 'passed' });
  mutate(assertionResults);
  return { testResults: [{
    name: '/workspace/apps/api/tests/p05-intake-http.test.ts',
    status: 'passed', assertionResults,
  }] };
}
function run(report, suite) {
  const dir = mkdtempSync(join(tmpdir(), 'p05-matrix-results-'));
  const path = join(dir, 'report.json');
  writeFileSync(path, JSON.stringify(report));
  return spawnSync(process.execPath, [script, path, suite], { encoding: 'utf8' });
}
for (const suite of Object.keys(suites)) {
  test('passes exact selected scenario titles for ' + suite, () => {
    const result = run(makeReport(suite), suite);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /P05 MATRIX GATE PASS/u);
  });
}
test('fails a renamed required test even if the pass count stays constant', () => {
  const result = run(makeReport('city-admin', assertions => {
    assertions.find(x => x.status === 'passed').title = 'renamed CITY admin test';
  }), 'city-admin');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /required title occurs 0 times/u);
});
test('fails when an exact selected test is skipped', () => {
  const result = run(makeReport('normative', assertions => {
    assertions.find(x => x.status === 'passed').status = 'pending';
  }), 'normative');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /required title is not passed/u);
});
test('fails when the filter accidentally selects an unrelated test', () => {
  const result = run(makeReport('city-manager', assertions => {
    assertions.find(x => x.status === 'pending').status = 'passed';
  }), 'city-manager');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /passed 4 tests; exact suite requires 3/u);
});
test('fails if a selected title is duplicated or inventory changes', () => {
  const duplicate = run(makeReport('city-custom', assertions => {
    const first = assertions.find(x => x.status === 'passed');
    assertions.push({ ...first });
  }), 'city-custom');
  assert.equal(duplicate.status, 1);
  assert.match(duplicate.stderr, /inventory is 42/u);
  const shrunk = run(makeReport('city-custom', assertions => assertions.pop()), 'city-custom');
  assert.equal(shrunk.status, 1);
  assert.match(shrunk.stderr, /inventory is 42/u);
});
test('rejects unknown suites and unexpected test files', () => {
  const dir = mkdtempSync(join(tmpdir(), 'p05-matrix-results-'));
  const path = join(dir, 'report.json');
  writeFileSync(path, JSON.stringify(makeReport('normative')));
  const unknown = spawnSync(process.execPath, [script, path, 'not-a-suite'], { encoding: 'utf8' });
  assert.equal(unknown.status, 2);
  const wrong = makeReport('normative');
  wrong.testResults[0].name = '/workspace/apps/api/tests/another-file.test.ts';
  assert.equal(run(wrong, 'normative').status, 1);
});
