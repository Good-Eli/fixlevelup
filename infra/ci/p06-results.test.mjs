import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('./p06-results.mjs', import.meta.url));

function report(assertions, fileStatus = 'passed') {
  return {
    testResults: [{
      name: '/workspace/apps/api/tests/p06-gap-unit.test.ts',
      status: fileStatus,
      assertionResults: assertions.map(([title, status]) => ({ title, fullName: `suite > ${title}`, status })),
    }],
  };
}

function run(contents, minimum, extra = []) {
  const directory = mkdtempSync(join(tmpdir(), 'p06-results-'));
  const path = join(directory, 'report.json');
  writeFileSync(path, typeof contents === 'string' ? contents : JSON.stringify(contents));
  return spawnSync(process.execPath, [script, path, String(minimum), ...extra], { encoding: 'utf8' });
}

test('passes only when every test passed and the minimum count is met', () => {
  const result = run(report([['alpha', 'passed'], ['beta', 'passed']]), 2, ['--require', 'alpha', '--require', 'beta']);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /P06 GATE PASS: 2 passed, 0 skipped \(pinned\)/u);
});

test('fails on a skipped test even when every executed test passed', () => {
  const result = run(report([['alpha', 'passed'], ['beta', 'pending']]), 2);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /unexpected skip/u);
  assert.match(result.stderr, /beta/u);
});

test('accepts an exactly pinned number of skips but not one more or one less', () => {
  const pinned = run(report([['alpha', 'passed'], ['beta', 'pending'], ['gamma', 'pending']]), 1, ['--skipped', '2']);
  assert.equal(pinned.status, 0, pinned.stderr);
  const fewer = run(report([['alpha', 'passed'], ['beta', 'pending']]), 1, ['--skipped', '2']);
  assert.equal(fewer.status, 1);
  const more = run(report([['alpha', 'passed'], ['beta', 'pending'], ['gamma', 'pending']]), 1, ['--skipped', '1']);
  assert.equal(more.status, 1);
});

test('fails when fewer tests passed than the pinned minimum', () => {
  const result = run(report([['alpha', 'passed']]), 10);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /minimum is 10/u);
});

test('fails when a required title is absent or not passed', () => {
  const absent = run(report([['alpha', 'passed']]), 1, ['--require', 'gamma']);
  assert.equal(absent.status, 1);
  assert.match(absent.stderr, /missing required test/u);
  const failed = run(report([['gamma', 'failed']]), 1, ['--require', 'gamma']);
  assert.equal(failed.status, 1);
});

test('fails on a failed file, an empty report and an unreadable report', () => {
  const failedFile = run(report([['alpha', 'passed']], 'failed'), 1);
  assert.equal(failedFile.status, 1);
  assert.match(failedFile.stderr, /file\(s\) not passed/u);
  const empty = run({ testResults: [] }, 1);
  assert.equal(empty.status, 1);
  assert.match(empty.stderr, /no test files were executed/u);
  const unreadable = run('{not json', 1);
  assert.equal(unreadable.status, 1);
  assert.match(unreadable.stderr, /unreadable Vitest report/u);
});

test('pins the exact collected total, so a filter cannot silently shrink the set', () => {
  const exact = run(report([['alpha', 'passed'], ['beta', 'pending']]), 1, ['--total', '2', '--skipped', '1']);
  assert.equal(exact.status, 0, exact.stderr);
  const shrunk = run(report([['alpha', 'passed']]), 1, ['--total', '2']);
  assert.equal(shrunk.status, 1);
  assert.match(shrunk.stderr, /1 collected test\(s\), expected exactly 2/u);
  const grown = run(report([['alpha', 'passed'], ['beta', 'passed']]), 2, ['--total', '1']);
  assert.equal(grown.status, 1);
});

test('rejects an invalid minimum or an unknown option', () => {
  const zero = run(report([['alpha', 'passed']]), 0);
  assert.equal(zero.status, 2);
  const unknown = run(report([['alpha', 'passed']]), 1, ['--bogus']);
  assert.equal(unknown.status, 2);
});

test('never echoes assertion payloads, only titles', () => {
  const result = run(report([['secret-looking-title', 'failed']]), 1);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /secret-looking-title/u);
  assert.doesNotMatch(result.stdout, /secret-looking-title/u);
});
