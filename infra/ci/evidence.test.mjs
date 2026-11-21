import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { collectEvidence, redactJson, summarizeJob } from './evidence.mjs';
import { APPROVED_EXCEPTION, APPROVED_EXCEPTIONS, HISTORY_EXCEPTION, classifyScan, summarizeFindings, validateIgnoreDeclaration, validateSourcePath } from './secrets.mjs';

const DECLARATION = APPROVED_EXCEPTIONS.map(exception => exception.fingerprint).join('\n');
test('secret scan evidence never retains values, paths or personal Git metadata', () => {
  const summary = summarizeFindings([{ RuleID: 'generic-api-key', Secret: 'not-for-artifacts', Match: 'raw', File: '.env', Author: 'private', Email: 'private', Commit: 'raw', Message: 'raw' }]);
  assert.deepEqual(summary, { findings: 1, rules: { 'generic-api-key': 1 } });
  assert.throws(() => summarizeFindings({}));
  assert.throws(() => summarizeFindings([{ RuleID: 'unsafe\nvalue' }]));
});
test('approved exceptions are exactly two immutable fingerprints with blob hashes', () => {
  assert.deepEqual(validateIgnoreDeclaration(`${DECLARATION}\n`), DECLARATION);
  assert.deepEqual(validateIgnoreDeclaration(`${DECLARATION.replace('\n', '\r\n')}\r\n`), DECLARATION);
  assert.deepEqual(APPROVED_EXCEPTIONS.map(exception => exception.fingerprint), [APPROVED_EXCEPTION.fingerprint, HISTORY_EXCEPTION.fingerprint]);
  for (const exception of APPROVED_EXCEPTIONS) {
    assert.equal(`${exception.commit}:${exception.path}:${exception.rule}:${exception.line}`, exception.fingerprint);
    assert.match(exception.commit, /^[a-f0-9]{40}$/);
    assert.match(exception.blobSha256, /^[a-f0-9]{64}$/);
  }
  assert.equal(APPROVED_EXCEPTION.line, 203);
  assert.deepEqual([...APPROVED_EXCEPTION.scopes], ['repository', 'history']);
  // The owner-approved historical false positive is history only, never a tree copy.
  assert.equal(HISTORY_EXCEPTION.commit, '3677960f4ba6cc355ea4338e18cad782932e60b3');
  assert.equal(HISTORY_EXCEPTION.path, 'apps/api/tests/auth-db-fixture.ts');
  assert.equal(HISTORY_EXCEPTION.line, 11);
  assert.equal(HISTORY_EXCEPTION.rule, 'generic-api-key');
  assert.equal(HISTORY_EXCEPTION.blobSha256, 'e590d0786b6ad455cdc2a3475a05ecfe9361769ca24facd096b6774cb5d123fa');
  assert.deepEqual([...HISTORY_EXCEPTION.scopes], ['history']);
  for (const text of ['', '\n', `${APPROVED_EXCEPTION.fingerprint}\n`, `${HISTORY_EXCEPTION.fingerprint}\n`,
    `${DECLARATION}\n${APPROVED_EXCEPTION.fingerprint}\n`, `${DECLARATION}\n${HISTORY_EXCEPTION.fingerprint}\n`,
    `${APPROVED_EXCEPTION.fingerprint}\n${HISTORY_EXCEPTION.fingerprint}\n${APPROVED_EXCEPTION.fingerprint}\n`,
    `${HISTORY_EXCEPTION.fingerprint}\n${APPROVED_EXCEPTION.fingerprint}\n`,
    `${DECLARATION}\n0000000000000000000000000000000000000000:other:generic-api-key:1\n`,
    `${DECLARATION.replace(':11', ':12')}\n`, `${DECLARATION.replace(':203', ':204')}\n`,
    `*${DECLARATION}\n`, `${DECLARATION} # approved\n`, `${DECLARATION}`.replace('generic-api-key', 'generic_api_key') + '\n']) {
    assert.throws(() => validateIgnoreDeclaration(text));
  }
  assert.throws(() => validateIgnoreDeclaration(null));
  assert.throws(() => validateIgnoreDeclaration(DECLARATION, null));
});
test('the repository declares exactly the two approved exceptions', () => {
  assert.equal(validateIgnoreDeclaration(readFileSync(join(import.meta.dirname, '..', '..', '.gitleaksignore'), 'utf8')), DECLARATION);
});
test('only the root declaration is accepted, nested ones fail closed', () => {
  assert.equal(validateSourcePath('.gitleaksignore'), '.gitleaksignore');
  assert.equal(validateSourcePath('apps/api/src/main.ts'), 'apps/api/src/main.ts');
  assert.equal(validateSourcePath('info/Полный diff P02-06.patch'), 'info/Полный diff P02-06.patch');
  assert.equal(validateSourcePath('apps/api/tests/auth-db-fixture.ts'), 'apps/api/tests/auth-db-fixture.ts');
  // `git ls-files -z` always separates with '/', so a literal backslash is a real
  // filename character on Linux: it must never be normalized or silently skipped.
  for (const file of ['info\\Полный diff P02-06.patch', 'docs\\file.txt', 'a\\b']) {
    assert.throws(() => validateSourcePath(file));
  }
  for (const file of ['docs/.gitleaksignore', 'apps/.GitleaksIgnore', 'a/b/.GITLEAKSIGNORE', '', null]) {
    assert.throws(() => validateSourcePath(file));
  }
});
test('only evidenced fingerprints are approved, never a file or rule', () => {
  const root = join(tmpdir(), 'fixlevelup-scan-root');
  const dirFinding = { RuleID: 'generic-api-key', StartLine: 203, File: join(root, APPROVED_EXCEPTION.path) };
  const historyFinding = { RuleID: 'generic-api-key', StartLine: 203, File: APPROVED_EXCEPTION.path, Commit: APPROVED_EXCEPTION.commit };
  const dir = (findings, contentMatches) => classifyScan(findings, { scope: 'repository', root, contentMatches });
  const history = (findings, contentMatches) => classifyScan(findings, { scope: 'history', contentMatches });
  assert.deepEqual(dir([dirFinding], true), { findings: 0, rules: {}, approved: 1, raw: 1 });
  assert.deepEqual(history([historyFinding], { [APPROVED_EXCEPTION.fingerprint]: true }), { findings: 0, rules: {}, approved: 1, raw: 1 });
  // No content evidence means no approval, even for a matching fingerprint.
  assert.deepEqual(dir([dirFinding], false), { findings: 1, rules: { 'generic-api-key': 1 }, approved: 0, raw: 1 });
  assert.deepEqual(history([historyFinding], {}), { findings: 1, rules: { 'generic-api-key': 1 }, approved: 0, raw: 1 });
  // Wrong line, rule, path or commit stay unexpected.
  assert.equal(dir([{ ...dirFinding, StartLine: 204 }], true).findings, 1);
  assert.equal(dir([{ ...dirFinding, RuleID: 'private-key' }], true).findings, 1);
  assert.equal(dir([{ ...dirFinding, File: join(root, 'info', 'other.patch') }], true).findings, 1);
  assert.equal(dir([{ ...dirFinding, File: join(root, '..', 'outside', APPROVED_EXCEPTION.path) }], true).findings, 1);
  assert.equal(history([{ ...historyFinding, Commit: '0'.repeat(40) }], { [APPROVED_EXCEPTION.fingerprint]: true }).findings, 1);
  // A second matching finding is unexpected: one approval per exception per scan.
  assert.deepEqual(dir([dirFinding, dirFinding], true), { findings: 1, rules: { 'generic-api-key': 1 }, approved: 1, raw: 2 });
  // Other findings are never filtered out by the approval.
  assert.deepEqual(dir([dirFinding, { RuleID: 'aws-access-token', StartLine: 1, File: join(root, 'leak.ts') }], true), { findings: 1, rules: { 'aws-access-token': 1 }, approved: 1, raw: 2 });
  assert.throws(() => classifyScan([dirFinding], { scope: 'repository', root }));
  assert.throws(() => classifyScan([dirFinding], { scope: 'repository', contentMatches: true }));
  assert.throws(() => classifyScan([dirFinding], { scope: 'other', contentMatches: true }));
  assert.throws(() => classifyScan({}, { scope: 'history', contentMatches: true }));
  assert.throws(() => classifyScan([{ ...historyFinding, Commit: 'raw' }], { scope: 'history', contentMatches: { [APPROVED_EXCEPTION.fingerprint]: true } }));
  assert.throws(() => classifyScan([{ ...dirFinding, StartLine: 0 }], { scope: 'repository', root, contentMatches: true }));
  // A bare boolean cannot evidence one of several scope-applicable exceptions.
  assert.throws(() => classifyScan([historyFinding], { scope: 'history', contentMatches: true }));
});
test('the historical fixture exception is history only and requires its exact commit', () => {
  const root = join(tmpdir(), 'fixlevelup-history-scan-root');
  const historyFinding = { RuleID: 'generic-api-key', StartLine: 11, File: HISTORY_EXCEPTION.path, Commit: HISTORY_EXCEPTION.commit };
  const history = (findings, contentMatches) => classifyScan(findings, { scope: 'history', contentMatches });
  const dir = (findings, contentMatches) => classifyScan(findings, { scope: 'repository', root, contentMatches });
  assert.deepEqual(history([historyFinding], { [HISTORY_EXCEPTION.fingerprint]: true }), { findings: 0, rules: {}, approved: 1, raw: 1 });
  // A copy in the working tree stays unexpected even with the exact blob hash,
  // because the exception is declared for history only.
  const treeCopy = { RuleID: 'generic-api-key', StartLine: 11, File: join(root, HISTORY_EXCEPTION.path) };
  assert.deepEqual(dir([treeCopy], { [HISTORY_EXCEPTION.fingerprint]: true }), { findings: 1, rules: { 'generic-api-key': 1 }, approved: 0, raw: 1 });
  assert.equal(dir([treeCopy], true).findings, 1);
  // Same line in a different commit, a new history entry, or a duplicated
  // finding is rejected: the approval is bound to one commit and one occurrence.
  assert.equal(history([{ ...historyFinding, Commit: 'a'.repeat(40) }], { [HISTORY_EXCEPTION.fingerprint]: true }).findings, 1);
  assert.deepEqual(history([historyFinding, historyFinding], { [HISTORY_EXCEPTION.fingerprint]: true }), { findings: 1, rules: { 'generic-api-key': 1 }, approved: 1, raw: 2 });
  // Missing, mismatched or borrowed evidence approves nothing.
  assert.equal(history([historyFinding], {}).findings, 1);
  assert.equal(history([historyFinding], { [HISTORY_EXCEPTION.fingerprint]: false }).findings, 1);
  assert.equal(history([historyFinding], { [APPROVED_EXCEPTION.fingerprint]: true }).findings, 1);
  // Evidence for one exception never approves the other's finding.
  const otherHistory = { RuleID: 'generic-api-key', StartLine: 203, File: APPROVED_EXCEPTION.path, Commit: APPROVED_EXCEPTION.commit };
  assert.deepEqual(history([historyFinding, otherHistory], { [HISTORY_EXCEPTION.fingerprint]: true }), { findings: 1, rules: { 'generic-api-key': 1 }, approved: 1, raw: 2 });
  assert.deepEqual(history([historyFinding, otherHistory], { [HISTORY_EXCEPTION.fingerprint]: true, [APPROVED_EXCEPTION.fingerprint]: true }), { findings: 0, rules: {}, approved: 2, raw: 2 });
  // The historical fixture copy at a different path, line or rule stays unexpected.
  assert.equal(history([{ ...historyFinding, File: `sub/${HISTORY_EXCEPTION.path}` }], { [HISTORY_EXCEPTION.fingerprint]: true }).findings, 1);
  assert.equal(history([{ ...historyFinding, StartLine: 12 }], { [HISTORY_EXCEPTION.fingerprint]: true }).findings, 1);
  assert.equal(history([{ ...historyFinding, RuleID: 'private-key' }], { [HISTORY_EXCEPTION.fingerprint]: true }).findings, 1);
  // Invalid exception records are rejected instead of trusted.
  assert.throws(() => classifyScan([historyFinding], { scope: 'history', exceptions: [{ ...HISTORY_EXCEPTION, scopes: ['tree'] }], contentMatches: {} }));
  assert.throws(() => classifyScan([historyFinding], { scope: 'history', exceptions: [], contentMatches: {} }));
  assert.throws(() => classifyScan([historyFinding], { scope: 'history', exceptions: [{ ...HISTORY_EXCEPTION, fingerprint: 'mismatch' }], contentMatches: {} }));
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
