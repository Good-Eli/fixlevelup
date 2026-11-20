import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  collectGraph, normalizeAudit, normalizeLicense, parseArgs, parseLockPackages,
  parsePackageKey, reviewLicense, runGate, validateRegistryMetadata,
} from './dependencies.mjs';

const lockText = `---
lockfileVersion: '9.0'
importers:
  .:
    packageManagerDependencies:
      pnpm:
        version: 12.21.0
packages:
  pnpm@12.21.0:
    resolution: {integrity: redacted}
---
lockfileVersion: '9.0'
packages:
  direct@1.0.0:
    resolution: {integrity: redacted}
  child@2.0.0:
    resolution: {integrity: redacted}
  skipped@3.0.0:
    resolution: {integrity: redacted}
snapshots:
  direct@1.0.0(peer@1.0.0): {}
`;
const graph = [{
  name: 'workspace', path: 'C:/Users/private/workspace',
  dependencies: {
    direct: { from: 'direct', version: '1.0.0', dependencies: {
      child: { from: 'child', version: '2.0.0' },
      skipped: { from: 'skipped', version: '3.0.0' },
    } },
  },
  devDependencies: { child: { from: 'child', version: '2.0.0' } },
}];
function cleanAudit(total = 4) {
  return {
    advisories: {},
    metadata: {
      vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0 },
      dependencies: 2, devDependencies: 1, optionalDependencies: 1, totalDependencies: total,
    },
  };
}
function fixtures(overrides = {}) {
  return {
    lockText,
    adapters: {
      skipToolchain: true,
      graph,
      licenses: new Map([['direct@1.0.0', 'MIT'], ['child@2.0.0', 'ISC']]),
      registry: async () => 'MIT',
      audit: cleanAudit(),
      ...overrides,
    },
  };
}

test('reads both pnpm 12 lock documents, scoped names and peer snapshots', () => {
  const entries = parseLockPackages(lockText);
  assert.equal(entries.length, 4);
  assert.equal(entries[0].scope, 'package-manager');
  assert.equal(entries[1].scope, 'application');
  assert.deepEqual(parsePackageKey("'@scope/name@1.2.3-beta.1(peer@2.0.0)'"), {
    packageName: '@scope/name', version: '1.2.3-beta.1', lockKey: "'@scope/name@1.2.3-beta.1(peer@2.0.0)'",
  });
  assert.throws(() => parseLockPackages('packages:\n  arbitrary-url:\n'));
  assert.throws(() => parseLockPackages('snapshots:\n  direct@1.0.0: {}\n'));
  assert.throws(() => parseLockPackages(lockText + '\npackages:\n  direct@1.0.0:\n'));
  assert.throws(() => parsePackageKey('https://private.test/name@1.0.0'));
  assert.throws(() => parseLockPackages(lockText.replaceAll("lockfileVersion: '9.0'", "lockfileVersion: '10.0'")));
});

test('records direct AND transitive reachability and excludes validated workspace links', () => {
  const data = collectGraph(graph);
  assert.ok(data.direct.has('child@2.0.0'));
  assert.ok(data.transitive.has('child@2.0.0'));
  assert.equal(data.all.size, 3);
  assert.equal(collectGraph([{ name: 'a', dependencies: { b: { version: 'link:../b' } } }, { name: 'b' }]).all.size, 0);
  assert.throws(() => collectGraph([{ name: 'a', dependencies: { b: { version: 'link:../b' } } }]));
  assert.throws(() => collectGraph([]));
});

test('normalizes legacy package licenses without inventing SPDX changes', () => {
  assert.equal(normalizeLicense([{ type: 'MIT', url: 'https://private.test' }]), 'MIT');
  assert.equal(normalizeLicense('MIT and ISC'), 'MIT and ISC');
  assert.equal(normalizeLicense({ type: 'Apache-2.0' }), 'Apache-2.0');
  assert.equal(normalizeLicense(null), null);
  assert.equal(normalizeLicense([{ type: 'MIT' }, { type: 'ISC' }]), null);
  assert.equal(normalizeLicense([{ type: 'MIT' }, {}]), null);
});

test('registry evidence must have exact name/version and unambiguous license metadata', () => {
  assert.equal(validateRegistryMetadata({ name: 'a', version: '1.0.0', license: 'MIT' }, 'a', '1.0.0'), 'MIT');
  assert.equal(validateRegistryMetadata({ name: 'a', version: '1.0.0', licenses: [{ type: 'ISC' }] }, 'a', '1.0.0'), 'ISC');
  for (const data of [null, {}, { name: 'b', version: '1.0.0', license: 'MIT' }, { name: 'a', version: '1.0.1', license: 'MIT' }, { name: 'a', version: '1.0.0' }, { name: 'a', version: '1.0.0', licenses: [{ type: 'MIT' }, { type: 'ISC' }] }]) {
    assert.throws(() => validateRegistryMetadata(data, 'a', '1.0.0'));
  }
});

test('technical review is not legal approval and nonpermissive exceptions are version scoped', () => {
  assert.equal(reviewLicense('MIT', 'direct', '1.0.0').reviewed, true);
  const scoped = reviewLicense('EPL-2.0', 'elkjs', '0.11.1');
  assert.equal(scoped.reviewed, true);
  assert.equal(scoped.requiresLegalReview, true);
  assert.match(scoped.reviewNote, /not legal or production approval/);
  assert.equal(reviewLicense('EPL-2.0', 'elkjs', '0.11.2').reviewed, false);
  assert.equal(reviewLicense('EPL-2.0', 'different', '0.11.1').reviewed, false);
  for (const license of [null, 'UNKNOWN', 'UNLICENSED', 'GPL-3.0-only', 'MIT OR GPL-3.0-only']) {
    assert.equal(reviewLicense(license, 'direct', '1.0.0').reviewed, false);
  }
});

test('complete inventory includes skipped optional and package-manager packages with exact sources', async () => {
  const requested = [];
  const result = await runGate(fixtures({ registry: async (name, version) => { requested.push(`${name}@${version}`); return 'Apache-2.0'; } }));
  assert.equal(result.status, 'pass');
  assert.equal(result.licenseInventory.lockEntries, 4);
  assert.equal(result.licenseInventory.metadataEntries, 4);
  assert.deepEqual(requested.sort(), ['pnpm@12.21.0', 'skipped@3.0.0']);
  assert.equal(result.licenseInventory.entries.find((entry) => entry.package === 'skipped').source, 'npm-registry-exact-version');
  assert.equal(result.licenseInventory.entries.find((entry) => entry.package === 'pnpm').scope, 'package-manager');
  const child = result.licenseInventory.entries.find((entry) => entry.package === 'child');
  assert.equal(child.direct, true);
  assert.equal(child.transitive, true);
  assert.equal(result.lockSha256, createHash('sha256').update(lockText).digest('hex'));
  assert.doesNotMatch(JSON.stringify(result), /Users|private|workspace|https:|paths|author|repository/);
});

test('fails unknown licenses and registry gaps without leaking raw license or error metadata', async () => {
  const unavailable = await runGate(fixtures({ registry: async () => { throw new Error('C:\\Users\\Secret\\token'); } }));
  assert.equal(unavailable.status, 'fail');
  assert.equal(unavailable.licenseInventory.metadataEntries, 2);
  assert.ok(unavailable.issues.some((issue) => issue.type === 'incomplete-license-inventory'));
  assert.doesNotMatch(JSON.stringify(unavailable), /Secret|token|Users/);
  const unknown = await runGate(fixtures({ registry: async () => 'UNKNOWN' }));
  assert.equal(unknown.status, 'fail');
  assert.ok(unknown.issues.some((issue) => issue.type === 'unreviewed-license'));
  const malicious = await runGate(fixtures({ registry: async () => 'SEE LICENSE IN C:\\Users\\Secret\\LICENSE' }));
  assert.equal(malicious.status, 'fail');
  assert.doesNotMatch(JSON.stringify(malicious), /Users|Secret/);
  assert.equal(malicious.licenseInventory.entries.find((entry) => entry.package === 'skipped').malformedLicenseSha256.length, 64);
});

test('rejects graph/lock/license coverage mismatches and reduced audit coverage', async () => {
  await assert.rejects(runGate(fixtures({ licenses: new Map([['foreign@1.0.0', 'MIT']]) })));
  await assert.rejects(runGate(fixtures({ graph: [{ name: 'workspace', dependencies: { direct: { version: '1.0.0' } } }] })));
  const incompleteAudit = await runGate(fixtures({ audit: cleanAudit(3) }));
  assert.equal(incompleteAudit.status, 'fail');
  assert.ok(incompleteAudit.issues.some((issue) => issue.type === 'incomplete-audit-coverage'));
});

test('fails audit at every severity including info even without advisory details', async () => {
  for (const severity of ['info', 'low', 'moderate', 'high', 'critical']) {
    const audit = cleanAudit();
    audit.metadata.vulnerabilities[severity] = 1;
    const result = await runGate(fixtures({ audit, auditExitStatus: 1 }));
    assert.equal(result.status, 'fail', severity);
    assert.equal(result.audit.counts[severity], 1);
    assert.ok(result.issues.some((issue) => issue.type === 'vulnerabilities'));
  }
});

test('audit parser rejects errors/missing fields and never projects raw advisory payload', () => {
  const audit = cleanAudit();
  audit.advisories = { 123: { paths: ['C:/Users/Secret'], title: 'token=secret' } };
  assert.equal(normalizeAudit(audit, 1).clean, false);
  assert.doesNotMatch(JSON.stringify(normalizeAudit(audit, 1)), /Secret|token/);
  assert.throws(() => normalizeAudit({ error: 'registry unavailable' }, 1));
  assert.throws(() => normalizeAudit({ ...cleanAudit(), error: 'registry unavailable' }));
  assert.throws(() => normalizeAudit(cleanAudit(), 1));
  const missing = cleanAudit();
  delete missing.metadata.vulnerabilities.info;
  assert.throws(() => normalizeAudit(missing));
  const unknown = cleanAudit();
  unknown.metadata.vulnerabilities.futureSeverity = 1;
  assert.throws(() => normalizeAudit(unknown));
  const invalid = cleanAudit();
  invalid.metadata.totalDependencies = NaN;
  assert.throws(() => normalizeAudit(invalid));
});

test('CLI accepts only check/output and rejects duplicates/missing/unknown options', () => {
  assert.deepEqual(parseArgs([]), { check: false, output: null });
  assert.deepEqual(parseArgs(['--output', 'artifact.json', '--check']), { check: true, output: 'artifact.json' });
  for (const args of [['--output'], ['--wat'], ['--check', '--check'], ['--output', 'a', '--output', 'b']]) {assert.throws(() => parseArgs(args));}
  const result = spawnSync(process.execPath, ['infra/ci/dependencies.mjs', '--unknown=C:/Users/Secret'], { encoding: 'utf8' });
  assert.equal(result.status, 2);
  assert.deepEqual(JSON.parse(result.stdout), { schemaVersion: 1, status: 'error', issues: [{ type: 'usage' }] });
  assert.equal(result.stderr, '');
});

test('implementation never requests reduced/suppressed audit modes or dependency installation', () => {
  const source = readFileSync(new URL('./dependencies.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /['"]--(?:ignore|ignore-unfixable|ignore-registry-errors|no-optional|prod|dev|fix)['"]/);
  assert.doesNotMatch(source, /runPnpm\([^\n]*\[['"](?:install|add|update|remove)['"]/);
  assert.match(source, /'audit', '--json', '--audit-level', 'info'/);
});
