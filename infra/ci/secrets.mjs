import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';

// Gitleaks' default rules are pinned by the checksummed 8.30.1 binary. Never use
// a repository baseline, custom allowlist or ambient GITLEAKS_* override.
export function summarizeFindings(findings) {
  if (!Array.isArray(findings)) { throw new Error('Invalid scanner report'); }
  const counts = {};
  for (const finding of findings) {
    if (typeof finding.RuleID !== 'string' || !/^[a-z0-9-]{1,100}$/.test(finding.RuleID)) { throw new Error('Invalid scanner rule'); }
    counts[finding.RuleID] = (counts[finding.RuleID] ?? 0) + 1;
  }
  // No Match, Secret, author, email, commit message, source line or raw report.
  return { findings: findings.length, rules: counts };
}
export function scanRepository(binary, output) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.toUpperCase().startsWith('GITLEAKS_')));
  const run = (command, args) => {
    const result = spawnSync(command, args, { env, encoding: 'utf8', timeout: 300_000, maxBuffer: 32 * 1024 * 1024 });
    if (result.error || result.signal) { throw new Error('Secret scanner process failed'); }
    return result;
  };
  const git = (...args) => {
    const result = run('git', args);
    if (result.status !== 0) { throw new Error('Secret scanner Git preflight failed'); }
    return result.stdout.trim();
  };
  if (git('rev-parse', '--is-shallow-repository') !== 'false') { throw new Error('Full available Git history required'); }
  if (run(binary, ['version']).stdout.trim() !== '8.30.1') { throw new Error('Unexpected secret scanner version'); }
  const temp = mkdtempSync(join(tmpdir(), 'fixlevelup-secret-scan-'));
  const snapshot = join(temp, 'tracked');
  mkdirSync(snapshot);
  const config = join(temp, 'rules.toml'), ignore = join(temp, 'empty-ignore');
  writeFileSync(config, '[extend]\nuseDefault = true\n');
  writeFileSync(ignore, '');
  // On a clean CI checkout this is the tracked tree. Locally include new,
  // non-ignored source too; ignored dotenv/data/caches are never traversed.
  const listed = run('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard']);
  if (listed.status !== 0) { throw new Error('Unable to enumerate tracked source'); }
  let files = 0;
  const root = resolve('.');
  for (const file of listed.stdout.split('\0').filter(Boolean)) {
    const source = resolve(root, file), target = resolve(snapshot, file);
    if (!source.startsWith(root + sep) || !target.startsWith(snapshot + sep)) { throw new Error('Unsafe tracked path'); }
    if (!existsSync(source)) { continue; } // Existing local user deletions are not restored.
    if (!lstatSync(source).isFile()) { throw new Error('Non-regular tracked path'); }
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(source, target);
    files++;
  }
  const scans = [];
  for (const [kind, args] of [['repository', ['dir', snapshot]], ['history', ['git', '.', '--log-opts=--all --full-history']]]) {
    // Keep even redacted raw diagnostics in memory, never in the artifact tree.
    const result = run(binary, [...args, '--config', config, '--gitleaks-ignore-path', ignore, '--ignore-gitleaks-allow', '--redact=100', '--no-banner', '--log-level', 'error', '--exit-code', '2', '--report-format', 'json', '--report-path', '-']);
    if (![0, 2].includes(result.status)) { throw new Error('Secret scanner failed safely; raw output suppressed'); }
    const summary = summarizeFindings(JSON.parse(result.stdout));
    if ((result.status === 2) !== (summary.findings > 0)) { throw new Error('Secret scanner result mismatch'); }
    scans.push({ scope: kind, ...summary });
  }
  const result = { tool: 'gitleaks', version: '8.30.1', redacted: true, sourceFiles: files,
    history: 'all available refs, full history; shallow clones rejected', commits: Number(git('rev-list', '--all', '--count')),
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
