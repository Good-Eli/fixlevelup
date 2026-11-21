import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';

// Gitleaks' default rules are pinned by the checksummed 8.30.1 binary. Never use
// a repository baseline, custom allowlist or ambient GITLEAKS_* override.
// Two owner-approved false positives are declared in .gitleaksignore: both lines
// are migration-name lists, not credentials. Each approval is bound to one
// immutable commit/path/line/rule and to the SHA-256 of that exact blob, so any
// edited, relocated, duplicated or differently-committed content stays an
// unexpected finding. The first applies to the tracked tree and history; the
// second is history only, so a working-tree copy is never concealed even when
// its bytes happen to have the approved hash.
export const APPROVED_EXCEPTION = Object.freeze({
  fingerprint: '5ff927854947a07605677ffe74a0fc5bac607640:info/Полный diff P02-06.patch:generic-api-key:203',
  commit: '5ff927854947a07605677ffe74a0fc5bac607640',
  path: 'info/Полный diff P02-06.patch',
  line: 203,
  rule: 'generic-api-key',
  blobSha256: '3b92bf6129eab412e5d786555986a8afe7e03954795a1c79422792d6f350ae26',
  scopes: Object.freeze(['repository', 'history']),
});
export const HISTORY_EXCEPTION = Object.freeze({
  fingerprint: '3677960f4ba6cc355ea4338e18cad782932e60b3:apps/api/tests/auth-db-fixture.ts:generic-api-key:11',
  commit: '3677960f4ba6cc355ea4338e18cad782932e60b3',
  path: 'apps/api/tests/auth-db-fixture.ts',
  line: 11,
  rule: 'generic-api-key',
  blobSha256: 'e590d0786b6ad455cdc2a3475a05ecfe9361769ca24facd096b6774cb5d123fa',
  scopes: Object.freeze(['history']),
});
export const APPROVED_EXCEPTIONS = Object.freeze([APPROVED_EXCEPTION, HISTORY_EXCEPTION]);
const DECLARATION = APPROVED_EXCEPTIONS.map(exception => exception.fingerprint).join('\n');
const RULE = /^[a-z0-9-]{1,100}$/;
const IGNORE_NAME = '.gitleaksignore';
// Repository-location variables could redirect Git away from the inspected tree.
const GIT_LOCATION = /^GIT_(DIR|WORK_TREE|INDEX_FILE|OBJECT_DIRECTORY|ALTERNATE_OBJECT_DIRECTORIES|COMMON_DIR|NAMESPACE|PREFIX|CEILING_DIRECTORIES)$/i;
function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
export function summarizeFindings(findings) {
  if (!Array.isArray(findings)) { throw new Error('Invalid scanner report'); }
  const counts = {};
  for (const finding of findings) {
    if (typeof finding.RuleID !== 'string' || !RULE.test(finding.RuleID)) { throw new Error('Invalid scanner rule'); }
    counts[finding.RuleID] = (counts[finding.RuleID] ?? 0) + 1;
  }
  // No Match, Secret, author, email, commit message, source line or raw report.
  return { findings: findings.length, rules: counts };
}
function assertFinding(finding, scope) {
  if (!finding || typeof finding !== 'object' || typeof finding.RuleID !== 'string' || !RULE.test(finding.RuleID)
    || !Number.isInteger(finding.StartLine) || finding.StartLine < 1 || typeof finding.File !== 'string' || !finding.File) {
    throw new Error('Invalid scanner finding');
  }
  if (scope === 'history' && (typeof finding.Commit !== 'string' || !/^[a-f0-9]{40,64}$/.test(finding.Commit))) { throw new Error('Invalid scanner finding'); }
}
function relativeTo(root, file) {
  const path = relative(resolve(root), resolve(file));
  return path && !path.startsWith('..') ? path.split(sep).join('/') : null;
}
function validException(exception) {
  return exception !== null && typeof exception === 'object'
    && typeof exception.fingerprint === 'string' && typeof exception.commit === 'string'
    && typeof exception.path === 'string' && typeof exception.rule === 'string'
    && Number.isInteger(exception.line) && typeof exception.blobSha256 === 'string'
    && Array.isArray(exception.scopes) && exception.scopes.length > 0
    && exception.scopes.every(scope => scope === 'repository' || scope === 'history')
    && exception.fingerprint === `${exception.commit}:${exception.path}:${exception.rule}:${exception.line}`;
}
// A finding is approved only with actual content evidence (blob SHA-256 checked
// by the caller), the exact scope-specific fingerprint and at most one approval
// per exception per scan; anything else stays an unexpected finding for the gate.
// `contentMatches` is either one boolean for a single-scope check or a map from
// exception fingerprint to the verified blob evidence for that exception.
export function classifyScan(findings, { scope, root = null, exceptions = APPROVED_EXCEPTIONS, contentMatches } = {}) {
  if (!Array.isArray(findings)) { throw new Error('Invalid scanner report'); }
  if (scope !== 'repository' && scope !== 'history') { throw new Error('Invalid scanner scope'); }
  if (!Array.isArray(exceptions) || exceptions.length === 0 || !exceptions.every(validException)) { throw new Error('Invalid scanner exception'); }
  const scoped = exceptions.filter(exception => exception.scopes.includes(scope));
  const perException = contentMatches !== null && typeof contentMatches === 'object' && !Array.isArray(contentMatches);
  if (perException) {
    for (const value of Object.values(contentMatches)) { if (typeof value !== 'boolean') { throw new Error('Missing scanner content evidence'); } }
  } else if (typeof contentMatches !== 'boolean' || scoped.length !== 1) {
    // A bare boolean cannot name which exception it evidences: only a single
    // scope-applicable exception may rely on it, otherwise evidence must be
    // supplied per exception fingerprint so no copy is approved by association.
    throw new Error('Missing scanner content evidence');
  }
  if (scope === 'repository' && typeof root !== 'string') { throw new Error('Invalid scanner root'); }
  const unexpected = [];
  const approved = new Set();
  for (const finding of findings) {
    assertFinding(finding, scope);
    const path = scope === 'repository' ? relativeTo(root, finding.File) : finding.File;
    const exception = scoped.find(item => item.path === path
      && item.line === finding.StartLine && item.rule === finding.RuleID
      && (scope !== 'history' || item.commit === finding.Commit));
    const evidenced = exception !== undefined && (perException ? contentMatches[exception.fingerprint] === true : contentMatches);
    if (exception !== undefined && evidenced && !approved.has(exception.fingerprint)) { approved.add(exception.fingerprint); } else { unexpected.push(finding); }
  }
  const summary = summarizeFindings(unexpected);
  return { findings: summary.findings, rules: summary.rules, approved: approved.size, raw: findings.length };
}
// Only the single validated root declaration may exist. A nested declaration
// (any case) could hide findings in the directory scan, so it is rejected.
// `git ls-files -z` separates with '/' on every platform, so a backslash is a
// literal filename character (possible on Linux): never rewrite or skip it.
export function validateSourcePath(file) {
  if (typeof file !== 'string' || !file || file.includes('\\')) { throw new Error('Unsafe tracked path'); }
  const name = file.slice(file.lastIndexOf('/') + 1);
  if (name.toLowerCase() === IGNORE_NAME && file !== IGNORE_NAME) { throw new Error('Unexpected nested secret scanner ignore'); }
  return file;
}
export function validateIgnoreDeclaration(text, expected = DECLARATION) {
  if (typeof text !== 'string' || typeof expected !== 'string') { throw new Error('Secret scanner ignore declaration rejected'); }
  const lines = text.split('\n').map(line => line.endsWith('\r') ? line.slice(0, -1) : line).filter(line => line.trim() !== '');
  if (lines.join('\n') !== expected) { throw new Error('Secret scanner ignore declaration rejected'); }
  return expected;
}
export function scanRepository(binary, output) {
  // Resolve a caller-supplied path before any temporary working directory is used.
  const scanner = /[\\/]/.test(binary) ? resolve(binary) : binary;
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.toUpperCase().startsWith('GITLEAKS_') && !GIT_LOCATION.test(key)));
  const root = resolve('.');
  const execute = (command, args, options = {}) => {
    const result = spawnSync(command, args, { env, timeout: 300_000, maxBuffer: 32 * 1024 * 1024, ...options });
    if (result.error || result.signal) { throw new Error('Secret scanner process failed'); }
    return result;
  };
  const run = (command, args, options = {}) => execute(command, args, { encoding: 'utf8', ...options });
  const git = (args) => {
    const result = run('git', args);
    if (result.status !== 0) { throw new Error('Secret scanner Git preflight failed'); }
    return result.stdout.trim();
  };
  if (git(['-C', root, 'rev-parse', '--is-shallow-repository']) !== 'false') { throw new Error('Full available Git history required'); }
  if (run(scanner, ['version']).stdout.trim() !== '8.30.1') { throw new Error('Unexpected secret scanner version'); }
  // The repository declaration must be exactly the approved line: extra, missing
  // or reordered entries are rejected instead of being trusted or ignored.
  const declaration = join(root, IGNORE_NAME);
  if (!existsSync(declaration) || !lstatSync(declaration).isFile()) { throw new Error('Secret scanner ignore declaration rejected'); }
  validateIgnoreDeclaration(readFileSync(declaration, 'utf8'));
  const temp = mkdtempSync(join(tmpdir(), 'fixlevelup-secret-scan-'));
  const snapshot = join(temp, 'tracked');
  mkdirSync(snapshot);
  const config = join(temp, 'rules.toml'), ignore = join(temp, 'empty-ignore');
  writeFileSync(config, '[extend]\nuseDefault = true\n');
  writeFileSync(ignore, '');
  // On a clean CI checkout this is the tracked tree. Locally include new,
  // non-ignored source too; ignored dotenv/data/caches are never traversed.
  const listed = run('git', ['-C', root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard']);
  if (listed.status !== 0) { throw new Error('Unable to enumerate tracked source'); }
  let files = 0;
  for (const file of listed.stdout.split('\0').filter(Boolean)) {
    const path = validateSourcePath(file);
    const source = resolve(root, path), target = resolve(snapshot, path);
    if (!source.startsWith(root + sep) || !target.startsWith(snapshot + sep)) { throw new Error('Unsafe tracked path'); }
    if (!existsSync(source)) { continue; } // Existing local user deletions are not restored.
    if (!lstatSync(source).isFile()) { throw new Error('Non-regular tracked path'); }
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(source, target);
    files++;
  }
  // Isolated mirror: history is scanned without the checkout's .gitleaksignore,
  // which Gitleaks otherwise discovers from the repository root. The original
  // repository is only read, and no ref is created or overwritten: a detached
  // HEAD commit is passed explicitly to the scanner and to the commit count, so
  // an existing refs/keepalive/* in the source can never be clobbered.
  const history = join(temp, 'history.git');
  const head = git(['-C', root, 'rev-parse', '--verify', 'HEAD']);
  if (run('git', ['clone', '--mirror', '--no-hardlinks', '--quiet', root, history]).status !== 0) { throw new Error('Secret scanner Git isolation failed'); }
  if (git(['-C', history, 'rev-parse', '--is-shallow-repository']) !== 'false') { throw new Error('Full available Git history required'); }
  if (execute('git', ['-C', history, 'cat-file', '-e', `${head}^{commit}`]).status !== 0) { throw new Error('Secret scanner Git isolation failed'); }
  const treeCopy = join(snapshot, APPROVED_EXCEPTION.path);
  const treeMatches = existsSync(treeCopy) && lstatSync(treeCopy).isFile() && sha256(readFileSync(treeCopy)) === APPROVED_EXCEPTION.blobSha256;
  const historyEvidence = (exception) => {
    const blob = execute('git', ['-C', history, 'cat-file', 'blob', `${exception.commit}:${exception.path}`]);
    return blob.status === 0 && sha256(blob.stdout) === exception.blobSha256;
  };
  // Evidence is per scan scope: a verified history blob never approves the
  // working tree, and the history-only exception never approves the tree at all.
  const evidence = {
    repository: treeMatches ? { [APPROVED_EXCEPTION.fingerprint]: true } : {},
    history: Object.fromEntries(APPROVED_EXCEPTIONS.filter(exception => historyEvidence(exception)).map(exception => [exception.fingerprint, true])),
  };
  const scans = [];
  for (const [kind, args] of [['repository', ['dir', snapshot]], ['history', ['git', history, `--log-opts=--all --full-history ${head}`]]]) {
    // Every scanner run uses a sterile working directory; raw output stays in memory.
    const result = run(scanner, [...args, '--config', config, '--gitleaks-ignore-path', ignore, '--ignore-gitleaks-allow', '--redact=100', '--no-banner', '--log-level', 'error', '--exit-code', '2', '--report-format', 'json', '--report-path', '-'], { cwd: temp });
    if (![0, 2].includes(result.status)) { throw new Error('Secret scanner failed safely; raw output suppressed'); }
    const findings = JSON.parse(result.stdout);
    if ((result.status === 2) !== (Array.isArray(findings) && findings.length > 0)) { throw new Error('Secret scanner result mismatch'); }
    scans.push({ scope: kind, ...classifyScan(findings, { scope: kind, root: snapshot, contentMatches: evidence[kind] }) });
  }
  const result = { tool: 'gitleaks', version: '8.30.1', redacted: true, sourceFiles: files,
    history: 'all available refs, full history; shallow clones rejected', commits: Number(git(['-C', history, 'rev-list', '--count', '--all', head])),
    exception: { declared: APPROVED_EXCEPTIONS.length, approved: scans.reduce((sum, scan) => sum + scan.approved, 0) },
    scans, status: scans.every(scan => scan.findings === 0) ? 'passed' : 'failed' };
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, JSON.stringify(result, null, 2) + '\n');
  return result;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const result = scanRepository(process.argv[2] ?? 'gitleaks', process.argv[3] ?? 'node_modules/.cache/ci/security/secrets.json');
    console.log(`Repository and available Git history secret scan: ${result.status}; values suppressed.`);
    if (result.status !== 'passed') { process.exitCode = 1; }
  } catch { console.error('Secret scan failed safely; raw output suppressed.'); process.exitCode = 1; }
}
