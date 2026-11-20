import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { collectEvidence, redactJson, summarizeJob } from './evidence.mjs';
import { summarizeFindings } from './secrets.mjs';

test('secret scan evidence never retains values, paths or personal Git metadata', () => {
  const summary = summarizeFindings([{ RuleID: 'generic-api-key', Secret: 'not-for-artifacts', Match: 'raw', File: '.env', Author: 'private', Email: 'private', Commit: 'raw', Message: 'raw' }]);
  assert.deepEqual(summary, { findings: 1, rules: { 'generic-api-key': 1 } });
  assert.throws(() => summarizeFindings({}));
  assert.throws(() => summarizeFindings([{ RuleID: 'unsafe\nvalue' }]));
});
test('Playwright report retains numeric outcomes, never errors, config or attachments', () => {
  const value = redactJson('browser-smoke.json', { config: { metadata: 'secret' }, errors: ['private'], stats: { expected: 1, unexpected: 0, skipped: 0, flaky: 0 }, suites: [{ specs: [{ title: 'private source', tests: [{ projectName: 'webkit-mobile', expectedStatus: 'passed', status: 'expected', results: [{ status: 'passed', duration: 10, retry: 0, errors: ['private'], attachments: ['private'], stdout: ['private'] }] }] }] }] });
  assert.equal(JSON.stringify(value).includes('private'), false);
  assert.equal(value.cases[0].project, 'webkit-mobile');
  assert.equal(value.cases[0].results[0].duration, 10);
});
test('proof result drops arbitrary top-level fields and keeps actual failed stage', () => {
  assert.deepEqual(redactJson('result.json', { overallStatus: 'failed', failedStage: 'offline frozen install', lockSha256: 'a'.repeat(64), env: { PASSWORD: 'private' } }), { redacted: true, lockSha256: 'a'.repeat(64), overallStatus: 'failed', failedStage: 'offline frozen install' });
  assert.throws(() => redactJson('result.json', { steps: [{ name: 'full pnpm check', status: 1, signal: null, error: { password: 'private' } }] }));
  assert.throws(() => redactJson('result.json', { failedStage: 'private arbitrary diagnostic' }));
  assert.equal(redactJson('result.json', { steps: [{ name: 'full pnpm check', status: 137, signal: null }] }).steps[0].status, 137);
  assert.throws(() => redactJson('result.json', { steps: [{ name: 'full pnpm check', status: 999, signal: null }] }));
  assert.throws(() => redactJson('raw-inspect.json', {}));
});
test('artifact collector accepts only known JSON and actual technical PNG names', () => {
  const root = mkdtempSync(join(tmpdir(), 'fixlevelup-evidence-test-')), source = join(root, 'raw'), destination = join(root, 'public');
  mkdirSync(source);
  writeFileSync(join(source, 'result.json'), JSON.stringify({ status: 'passed', secret: 'private' }));
  writeFileSync(join(source, '.env'), 'PASSWORD=private');
  writeFileSync(join(source, 'dump.json'), '{}');
  writeFileSync(join(source, 'stdout.log'), 'private');
  assert.deepEqual(collectEvidence([source], destination), { files: 1, redacted: true });
  assert.deepEqual(readdirSync(destination), ['result.json']);
  assert.equal(readFileSync(join(destination, 'result.json'), 'utf8').includes('private'), false);
});
test('summary uses actual step outcomes and never copies outputs or environment', () => {
  const root = mkdtempSync(join(tmpdir(), 'fixlevelup-summary-test-'));
  writeFileSync(join(root, 'secrets.json'), JSON.stringify({ scans: [{ findings: 0 }, { findings: 2 }] }));
  const value = summarizeJob('fixture', root, { proof: { outcome: 'failure', conclusion: 'failure', outputs: { key: 'private' } }, persistence: { outcome: 'skipped', conclusion: 'skipped' } }, 'failure');
  assert.deepEqual(value.facts, [{ check: 'secret-findings', count: 2 }]);
  assert.equal(value.status, 'failure');
  assert.equal(value.steps[0].outcome, 'failure');
  assert.equal(JSON.stringify(value).includes('private'), false);
});
