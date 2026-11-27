// Produce the exact candidate manifest only after every required CI job succeeds.
// Artifacts live outside the source tree to avoid a self-referential hash.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '../..');
const output = resolve(process.argv[2] ?? 'node_modules/.cache/ci-artifacts/p05-candidate');
function git(args) { return execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim(); }
function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

const needs = JSON.parse(process.env.P05_GATE_NEEDS_JSON ?? '{}');
const jobs = Object.entries(needs).map(([id, value]) => ({ id, result: value.result }));
const failed = jobs.filter(job => job.result !== 'success');
if (!jobs.length || failed.length) {
  throw new Error('Cannot freeze P05 candidate: required CI jobs are not all successful');
}
const sha = git(['rev-parse', 'HEAD']);
const expectedSha = process.env.P05_CANDIDATE_SHA ?? '';
if (!expectedSha || sha !== expectedSha) {
  throw new Error('Checked-out commit differs from the exact candidate SHA');
}
if (git(['status', '--porcelain', '--untracked-files=no']) !== '') {
  throw new Error('Tracked worktree is dirty; refusing candidate freeze');
}
execFileSync('git', ['diff', '--check'], { cwd: root, stdio: 'ignore' });
execFileSync('git', ['diff', '--cached', '--check'], { cwd: root, stdio: 'ignore' });

const tree = git(['rev-parse', 'HEAD^{tree}']);
const rows = git(['ls-files', '--stage', '-z']).split('\0').filter(Boolean);
const files = [];
for (const row of rows) {
  const tab = row.indexOf('\t');
  const meta = row.slice(0, tab).split(' ');
  const path = row.slice(tab + 1);
  const mode = meta[0], blob = meta[1], stage = meta[2];
  if (!mode || !blob || stage !== '0') {
    throw new Error('Unexpected Git index entry during candidate freeze');
  }
  const bytes = execFileSync('git', ['cat-file', 'blob', blob], {
    cwd: root, encoding: 'buffer', maxBuffer: 64 * 1024 * 1024,
  });
  files.push({ path, mode, gitBlob: blob, bytes: bytes.length, sha256: sha256(bytes) });
}
files.sort((a,b) => a.path.localeCompare(b.path));
const canonical = files.map(file => file.path + '\t' + file.mode + '\t' + file.gitBlob + '\t'
  + file.bytes + '\t' + file.sha256 + '\n').join('');
const treeManifestSha256 = sha256(canonical);
const lock = files.find(file => file.path === 'pnpm-lock.yaml');
const runId = process.env.GITHUB_RUN_ID ?? 'unknown';
const manifest = {
  schemaVersion: 1,
  candidate: {
    commitSha: sha, treeSha: tree, lockfileSha256: lock?.sha256 ?? null,
    trackedFiles: files.length, canonicalTreeManifestSha256: treeManifestSha256,
  },
  ci: {
    repository: process.env.GITHUB_REPOSITORY ?? null,
    workflow: process.env.GITHUB_WORKFLOW ?? null,
    runId, runAttempt: process.env.GITHUB_RUN_ATTEMPT ?? null,
    url: process.env.GITHUB_SERVER_URL && process.env.GITHUB_REPOSITORY
      ? process.env.GITHUB_SERVER_URL + '/' + process.env.GITHUB_REPOSITORY + '/actions/runs/' + runId : null,
    jobs,
  },
  files,
};
const manifestBytes = JSON.stringify(manifest, null, 2) + '\n';
const manifestSha256 = sha256(manifestBytes);
const redacted = {
  schemaVersion: 1, candidateSha: sha, treeSha: tree,
  manifestFileSha256: manifestSha256, canonicalTreeManifestSha256: treeManifestSha256,
  runId, requiredJobs: jobs, allRequiredJobsSucceeded: true,
  claims: ['technical validation evidence only', 'no deployment or production migration was performed'],
};

mkdirSync(output, { recursive: true });
writeFileSync(resolve(output, 'candidate-manifest.json'), manifestBytes, { mode: 0o600 });
writeFileSync(resolve(output, 'candidate-manifest.sha256'), manifestSha256 + '  candidate-manifest.json\n', { mode: 0o600 });
writeFileSync(resolve(output, 'candidate-tree.sha256'), treeManifestSha256 + '  canonical-source-tree\n', { mode: 0o600 });
writeFileSync(resolve(output, 'redacted-gate-evidence.json'), JSON.stringify(redacted, null, 2) + '\n', { mode: 0o600 });
process.stdout.write('P05 candidate frozen: ' + sha + '; ' + files.length
  + ' tracked files; manifest SHA-256 ' + manifestSha256 + '\n');
