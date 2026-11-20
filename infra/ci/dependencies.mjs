#!/usr/bin/env node
/**
 * Dependency gate for the pinned pnpm 12.21.0 workspace.
 *
 * pnpm 12 has the lightest native inventory (`pnpm licenses list --json`),
 * therefore no additional scanner or license package is installed here. The
 * lockfile is the completeness boundary: platform-skipped packages are filled
 * from the public npm metadata endpoint, while installed packages come from
 * pnpm's own metadata. Only package names, versions, license expressions and
 * review state are emitted; paths, users, URLs and subprocess diagnostics are
 * deliberately excluded.
 */

import { writeFile } from 'node:fs/promises';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import process from 'node:process';

const PINNED_PNPM = '12.21.0';
const REGISTRY = 'https://registry.npmjs.org/';
const SCHEMA_VERSION = 1;
const PERMISSIVE = new Set([
  '0BSD', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'BlueOak-1.0.0',
  'ISC', 'MIT', 'Unlicense',
]);
const TECHNICAL_EXCEPTIONS = {
  'MPL-2.0': new Set([
    'lightningcss@1.33.0',
    'lightningcss-android-arm64@1.33.0', 'lightningcss-darwin-arm64@1.33.0',
    'lightningcss-darwin-x64@1.33.0', 'lightningcss-freebsd-x64@1.33.0',
    'lightningcss-linux-arm-gnueabihf@1.33.0', 'lightningcss-linux-arm64-gnu@1.33.0',
    'lightningcss-linux-arm64-musl@1.33.0', 'lightningcss-linux-x64-gnu@1.33.0',
    'lightningcss-linux-x64-musl@1.33.0', 'lightningcss-win32-arm64-msvc@1.33.0',
    'lightningcss-win32-x64-msvc@1.33.0',
  ]),
  'EPL-2.0': new Set(['elkjs@0.11.1']),
  'CC-BY-4.0': new Set(['caniuse-lite@1.0.30001826']),
  'MIT and ISC': new Set(['@visx/vendor@4.0.0-alpha.0']),
  'Apache-2.0 AND LGPL-3.0-or-later': new Set([
    '@img/sharp-win32-x64@0.35.5', '@img/sharp-win32-arm64@0.35.5', '@img/sharp-win32-ia32@0.35.5',
  ]),
  'Apache-2.0 AND LGPL-3.0-or-later AND MIT': new Set(['@img/sharp-wasm32@0.35.5']),
  'LGPL-3.0-or-later': new Set([
    '@img/sharp-libvips-darwin-arm64@1.3.4', '@img/sharp-libvips-darwin-x64@1.3.4',
    '@img/sharp-libvips-linux-arm@1.3.4', '@img/sharp-libvips-linux-arm64@1.3.4',
    '@img/sharp-libvips-linux-ppc64@1.3.4', '@img/sharp-libvips-linux-riscv64@1.3.4',
    '@img/sharp-libvips-linux-s390x@1.3.4', '@img/sharp-libvips-linux-x64@1.3.4',
    '@img/sharp-libvips-linuxmusl-arm64@1.3.4', '@img/sharp-libvips-linuxmusl-x64@1.3.4',
  ]),
};
const LEGAL_OBLIGATIONS = {
  'MPL-2.0': 'Retain notices; disclose source for modified MPL-covered files when distributed.',
  'EPL-2.0': 'Retain notices and satisfy source/notice terms for distributed modifications.',
  'CC-BY-4.0': 'Retain attribution and indicate changes for covered data/content.',
  'LGPL-3.0-or-later': 'Retain notices; provide corresponding source and relinking rights where applicable.',
  'MIT and ISC': 'Retain the MIT and ISC notices in distributions.',
  'Apache-2.0 AND LGPL-3.0-or-later': 'Retain Apache/LGPL notices and satisfy corresponding-source/relinking terms where applicable.',
  'Apache-2.0 AND LGPL-3.0-or-later AND MIT': 'Retain Apache/LGPL/MIT notices and satisfy corresponding-source/relinking terms where applicable.',
};

function fail(message, code = 'invalid') {
  const error = new Error(message);
  error.code = code;
  throw error;
}

function normalizeLicense(value) {
  if (typeof value === 'string' && value.trim()) {return value.trim();}
  if (Array.isArray(value)) {
    const values = value.map((item) => normalizeLicense(item));
    // Legacy one-license arrays are unambiguous. Multiple different entries
    // do not tell us AND vs OR; never invent a permissive expression.
    return values.length && values.every((item) => item && item === values[0]) ? values[0] : null;
  }
  if (value && typeof value === 'object') {
    if (typeof value.type === 'string') {return normalizeLicense(value.type);}
    if (typeof value.name === 'string') {return normalizeLicense(value.name);}
  }
  return null;
}

function packageKey(packageName, version) {
  return `${packageName}@${version}`;
}

function parsePackageKey(rawKey) {
  let key = rawKey.trim().replace(/^['"]|['"]$/g, '');
  const peerIndex = key.indexOf('(');
  if (peerIndex !== -1) {key = key.slice(0, peerIndex);}
  const at = key.lastIndexOf('@');
  if (at <= 0 || at === key.length - 1) {fail(`Malformed lock package key: ${rawKey}`);}
  const packageName = key.slice(0, at);
  const version = key.slice(at + 1);
  if (!/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/.test(packageName)) {fail('Malformed locked package name');}
  if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version)) {fail('Malformed locked package version');}
  return { packageName, version, lockKey: rawKey.trim() };
}

export function parseLockPackages(lockText) {
  // This deliberately narrow reader handles only the existing pnpm 9 lock
  // format's top-level package keys (including pnpm 12 multi-doc tooling lock).
  // It is not a general YAML parser: unfamiliar keys/versions fail closed.
  const entries = [];
  const seen = new Set();
  for (const document of lockText.split(/^---\s*$/m)) {
    if (!document.trim()) { continue; }
    if (!/^lockfileVersion: ['"]9\.0['"]\s*$/m.test(document)) { fail('Unsupported frozen lockfile format'); }
    const scope = /^ {4}packageManagerDependencies:/m.test(document) ? 'package-manager' : 'application';
    let inPackages = false;
    for (const line of document.split(/\r?\n/)) {
      if (line === 'packages:') { inPackages = true; continue; }
      if (inPackages && /^\S/.test(line)) { inPackages = false; }
      if (inPackages && /^ {2}[^ ]/.test(line)) {
        const entry = parsePackageKey(line.slice(2).replace(/:$/, ''));
        const key = packageKey(entry.packageName, entry.version);
        if (seen.has(key)) {fail('Duplicate locked package identity');}
        seen.add(key);
        entries.push({ ...entry, scope });
      }
    }
  }
  if (!entries.length) {fail('No lockfile package entries found');}
  return entries;
}

export function collectGraph(graph) {
  if (!Array.isArray(graph) || graph.length === 0) {fail('Workspace dependency graph is empty');}
  const direct = new Set();
  const transitive = new Set();
  const all = new Set();
  const projects = new Set(graph.map((project) => project.name));
  function visit(node, depth) {
    for (const section of ['dependencies', 'devDependencies', 'optionalDependencies']) {
      for (const [alias, dependency] of Object.entries(node[section] ?? {})) {
        if (typeof dependency?.version !== 'string') {fail('Dependency graph version missing');}
        if (dependency.version.startsWith('link:')) {
          if (!projects.has(dependency.from ?? alias)) {fail('Unknown workspace dependency');}
        } else {
          const { packageName, version } = parsePackageKey(packageKey(dependency.from ?? alias, dependency.version));
          const key = packageKey(packageName, version);
          all.add(key);
          (depth === 0 ? direct : transitive).add(key);
        }
        visit(dependency, depth + 1);
      }
    }
  }
  graph.forEach((project) => visit(project, 0));
  return { direct, transitive, all, projects };
}

function readWorkspaceManifests(root) {
  // Match the existing workspace's apps/* and packages/* patterns. Never scan
  // arbitrary directories, installed dependencies, local data or dotenv files.
  const locations = [resolve(root, 'package.json')];
  for (const directory of ['apps', 'packages']) {
    for (const entry of readdirSync(resolve(root, directory), { withFileTypes: true })) {
      const manifest = resolve(root, directory, entry.name, 'package.json');
      if (entry.isDirectory() && existsSync(manifest)) {locations.push(manifest);}
    }
  }
  return locations.map((location) => JSON.parse(readFileSync(location, 'utf8')));
}

function runPnpm(root, args, { allowNonzero = false } = {}) {
  // On Windows do not invoke a .cmd via a shell. Corepack's JS entry point
  // alongside the pinned Node installation has the same behavior without
  // quoting, shell expansion, command injection or a second package manager.
  const corepack = resolve(dirname(process.execPath), 'node_modules/corepack/dist/corepack.js');
  const command = process.platform === 'win32' ? process.execPath : 'corepack';
  const prefix = process.platform === 'win32' ? [corepack, 'pnpm'] : ['pnpm'];
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (/^(?:pnpm_config_|npm_config_|node_options$)/i.test(key)) {delete env[key];}
  }
  env.COREPACK_ENABLE_NETWORK = '0';
  const result = spawnSync(command, [...prefix, ...args], {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    timeout: 10 * 60 * 1000,
    windowsHide: true,
    env,
  });
  if (result.error || result.signal || result.status === null || (!allowNonzero && result.status !== 0)) {fail('Pinned pnpm command failed', 'tooling');}
  return { stdout: result.stdout, status: result.status };
}

function parseJsonOutput(text, label) {
  try { return JSON.parse(text); } catch { fail(`pnpm ${label} returned malformed JSON`, 'tooling'); }
}

function collectPnpmLicenses(root) {
  const grouped = parseJsonOutput(runPnpm(root, ['licenses', 'list', '-r', '--include-workspace-root', '--json']).stdout, 'licenses');
  const result = new Map();
  for (const [group, packages] of Object.entries(grouped)) {
    if (!Array.isArray(packages)) {fail('pnpm licenses group is malformed', 'tooling');}
    for (const item of packages) {
      if (!item || typeof item.name !== 'string' || !Array.isArray(item.versions)) {fail('pnpm license entry is malformed', 'tooling');}
      for (const version of item.versions) {
        if (typeof version !== 'string') {fail('pnpm license version is malformed', 'tooling');}
        const key = packageKey(item.name, version);
        parsePackageKey(key);
        const license = normalizeLicense(item.license);
        if (license !== normalizeLicense(group) || (result.has(key) && result.get(key) !== license)) {fail('Conflicting pnpm license metadata');}
        if (!Array.isArray(item.paths) || !item.paths.length) {fail('Installed license metadata has no evidence');}
        for (const path of item.paths) {
          // Paths are used privately to verify pnpm metadata, never emitted.
          const manifest = JSON.parse(readFileSync(resolve(path, 'package.json'), 'utf8'));
          if (manifest.name !== item.name || !item.versions.includes(manifest.version)
              || normalizeLicense(manifest.license ?? manifest.licenses) !== license) {fail('Installed license metadata mismatch');}
        }
        result.set(key, license);
      }
    }
  }
  return result;
}

async function registryLicense(packageName, version) {
  const encoded = encodeURIComponent(packageName);
  const response = await fetch(`${REGISTRY}${encoded}/${encodeURIComponent(version)}`, {
    headers: { accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) {fail('Registry metadata unavailable', 'metadata');}
  const text = await response.text();
  if (text.length > 2 * 1024 * 1024) {fail('Registry metadata exceeds size limit', 'metadata');}
  let data;
  try { data = JSON.parse(text); } catch { fail('Registry metadata malformed', 'metadata'); }
  return validateRegistryMetadata(data, packageName, version);
}

export function validateRegistryMetadata(data, packageName, version) {
  const license = normalizeLicense(data?.license ?? data?.licenses);
  if (!license || data.name !== packageName || data.version !== version) { fail('Registry metadata identity or license mismatch', 'metadata'); }
  return license;
}

function reviewLicense(license, packageName, version) {
  if (!license) {return { reviewed: false, technicalStatus: 'unreviewed-unknown', requiresLegalReview: true };}
  if (PERMISSIVE.has(license)) {return { reviewed: true, technicalStatus: 'technical-reviewed-existing-baseline', requiresLegalReview: false };}
  const scoped = TECHNICAL_EXCEPTIONS[license]?.has(packageKey(packageName, version)) === true;
  if (!scoped) {return { reviewed: false, technicalStatus: 'unreviewed-existing-expression', requiresLegalReview: true };}
  return {
    reviewed: true,
    technicalStatus: 'technical-reviewed-existing-baseline',
    requiresLegalReview: true,
    obligations: LEGAL_OBLIGATIONS[license],
    reviewNote: 'Technical inventory only; this is not legal or production approval.',
  };
}

async function buildInventory({ lockText, graph, licenses, registry = registryLicense }) {
  const lockEntries = parseLockPackages(lockText);
  const keys = new Set(lockEntries.map(({ packageName, version }) => packageKey(packageName, version)));
  const issues = [];
  for (const key of [...graph.all, ...licenses.keys()]) {
    if (!keys.has(key)) {fail('Dependency or license identity not present in frozen lockfile');}
  }
  for (const entry of lockEntries) {
    if (entry.scope === 'application' && !graph.all.has(packageKey(entry.packageName, entry.version))) {fail('Locked application package absent from recursive graph');}
  }
  const fetched = new Map();
  const pending = lockEntries.filter(({ packageName, version }) => !licenses.has(packageKey(packageName, version)));
  // Bounded registry concurrency: no new dependencies and no registry bulk
  // payloads containing workspace names, paths or private project metadata.
  await Promise.all(Array.from({ length: Math.min(6, pending.length) }, async () => {
    while (pending.length) {
      const { packageName, version } = pending.shift();
      const key = packageKey(packageName, version);
      try { fetched.set(key, normalizeLicense(await registry(packageName, version))); }
      catch { issues.push({ type: 'registry-metadata-unavailable', package: packageName, version }); }
    }
  }));
  const inventory = lockEntries.map(({ packageName, version, scope }) => {
    const key = packageKey(packageName, version);
    const rawLicense = licenses.get(key) ?? fetched.get(key);
    // Unknown/freeform values cannot carry arbitrary local paths or secret
    // metadata into an artifact. Preserve a digest, not the untrusted string.
    const knownExpression = PERMISSIVE.has(rawLicense) || Object.hasOwn(TECHNICAL_EXCEPTIONS, rawLicense);
    const license = knownExpression ? rawLicense : null;
    const review = reviewLicense(license, packageName, version);
    if (!license) {issues.push({ type: 'missing-or-malformed-license', package: packageName, version });}
    if (!review.reviewed) {issues.push({ type: 'unreviewed-license', package: packageName, version });}
    return {
      package: packageName,
      version,
      scope,
      direct: scope === 'package-manager' ? packageName === 'pnpm' : graph.direct.has(key),
      transitive: scope === 'package-manager' ? packageName !== 'pnpm' : graph.transitive.has(key),
      license,
      ...(rawLicense && !license ? { malformedLicenseSha256: createHash('sha256').update(rawLicense).digest('hex') } : {}),
      source: licenses.has(key) ? 'pnpm-licenses-and-installed-package-manifest' : 'npm-registry-exact-version',
      ...review,
    };
  }).sort((a, b) => packageKey(a.package, a.version).localeCompare(packageKey(b.package, b.version), 'en'));
  return { inventory, issues, lockEntries: lockEntries.length, metadataEntries: inventory.filter((item) => item.license !== null).length };
}

export function normalizeAudit(value, exitStatus = 0) {
  const levels = ['info', 'low', 'moderate', 'high', 'critical'];
  const vulnerabilities = value?.metadata?.vulnerabilities;
  if (!vulnerabilities || value.error || value.errorCode || Array.isArray(vulnerabilities)
      || !value.advisories || typeof value.advisories !== 'object' || Array.isArray(value.advisories)
      || Object.keys(vulnerabilities).some((level) => !levels.includes(level))) {fail('pnpm audit metadata is incomplete', 'tooling');}
  const counts = {};
  for (const level of levels) {
    if (!Number.isSafeInteger(vulnerabilities[level]) || vulnerabilities[level] < 0) {fail('Invalid audit severity count', 'tooling');}
    counts[level] = vulnerabilities[level];
  }
  const total = Object.values(counts).reduce((sum, count) => sum + count, 0);
  const advisoryCount = Object.keys(value.advisories).length;
  const dependencyCounts = {};
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'totalDependencies']) {
    if (!Number.isSafeInteger(value.metadata[field]) || value.metadata[field] < 0) {fail('Invalid audit dependency count', 'tooling');}
    dependencyCounts[field] = value.metadata[field];
  }
  // Nonzero + no findings is a tool/registry failure, never a clean audit.
  if (exitStatus !== 0 && total === 0 && advisoryCount === 0) {fail('pnpm audit failed without a complete result', 'tooling');}
  return { counts, advisoryCount, ...dependencyCounts, clean: total === 0 && advisoryCount === 0 && exitStatus === 0 };
}

function audit(root) {
  const config = parseJsonOutput(runPnpm(root, ['config', 'get', 'auditConfig', '--json']).stdout, 'audit config');
  // Never honor ignored CVEs/GHSAs or registry-error suppression from config.
  if (config !== null && (typeof config !== 'object' || Object.keys(config).length !== 0)) {fail('Audit suppressions/configuration are not permitted', 'tooling');}
  const result = runPnpm(root, [
    'audit', '--json', '--audit-level', 'info', '--prod=false', '--dev=false', '--optional=true',
    '--ignore-registry-errors=false', '--ignore-unfixable=false',
  ], { allowNonzero: true });
  return normalizeAudit(parseJsonOutput(result.stdout, 'audit'), result.status);
}

export async function runGate({ root = resolve(import.meta.dirname, '../..'), lockText = readFileSync(resolve(root, 'pnpm-lock.yaml'), 'utf8'), adapters = {} } = {}) {
  if (!adapters.skipToolchain) {
    const rootManifest = readWorkspaceManifests(root)[0];
    if (rootManifest.packageManager !== `pnpm@${PINNED_PNPM}` || rootManifest.engines?.pnpm !== PINNED_PNPM
        || rootManifest.engines?.node !== process.versions.node
        || runPnpm(root, ['--version']).stdout.trim() !== PINNED_PNPM) {fail('Pinned toolchain mismatch', 'tooling');}
  }
  const graph = collectGraph(adapters.graph ?? parseJsonOutput(runPnpm(root, ['list', '-r', '--include-workspace-root', '--depth', 'Infinity', '--lockfile-only', '--json']).stdout, 'list'));
  const inventoryResult = await buildInventory({ lockText, graph, licenses: adapters.licenses ?? collectPnpmLicenses(root), registry: adapters.registry ?? registryLicense });
  const auditResult = adapters.audit ? normalizeAudit(adapters.audit, adapters.auditExitStatus ?? 0) : audit(root);
  const issues = [...inventoryResult.issues];
  if (inventoryResult.lockEntries !== inventoryResult.metadataEntries) {issues.push({ type: 'incomplete-license-inventory' });}
  if (auditResult.totalDependencies !== inventoryResult.lockEntries) {issues.push({ type: 'incomplete-audit-coverage' });}
  if (!auditResult.clean) {issues.push({ type: 'vulnerabilities', advisoryCount: auditResult.advisoryCount, severityCount: Object.values(auditResult.counts).reduce((sum, count) => sum + count, 0) });}
  return {
    schemaVersion: SCHEMA_VERSION,
    status: issues.length ? 'fail' : 'pass',
    toolchain: { node: process.versions.node, pnpm: PINNED_PNPM },
    lockSha256: createHash('sha256').update(lockText).digest('hex'),
    audit: auditResult,
    licenseInventory: {
      entries: inventoryResult.inventory, lockEntries: inventoryResult.lockEntries, metadataEntries: inventoryResult.metadataEntries,
      requiresLegalReview: inventoryResult.inventory.filter((entry) => entry.requiresLegalReview).map(({ package: packageName, version, license }) => ({ package: packageName, version, license })),
      approval: 'technical-inventory-only-not-legal-or-production-approval',
    },
    issues: issues.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b), 'en')),
  };
}

export function parseArgs(argv) {
  let output = null;
  let check = false;
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--check' && !check) {check = true;}
    else if (argv[index] === '--output' && output === null && argv[index + 1] && !argv[index + 1].startsWith('-')) {output = argv[++index];}
    else {fail('Invalid command-line arguments', 'usage');}
  }
  return { check, output };
}

export async function main(argv = process.argv.slice(2)) {
  let args;
  try { args = parseArgs(argv); }
  catch { process.stdout.write(`${JSON.stringify({ schemaVersion: SCHEMA_VERSION, status: 'error', issues: [{ type: 'usage' }] })}\n`); return 2; }
  let result;
  try { result = await runGate(); }
  catch (error) {
    const type = ['tooling', 'metadata', 'invalid'].includes(error.code) ? error.code : 'gate-error';
    result = { schemaVersion: SCHEMA_VERSION, status: 'error', issues: [{ type }] };
  }
  const json = `${JSON.stringify(result, null, 2)}\n`;
  try {
    if (args.output) {await writeFile(resolve(process.cwd(), args.output), json, { encoding: 'utf8', flag: 'wx' });}
    else {process.stdout.write(json);}
  } catch {
    process.stdout.write(`${JSON.stringify({ schemaVersion: SCHEMA_VERSION, status: 'error', issues: [{ type: 'output-unavailable-or-existing' }] })}\n`);
    return 1;
  }
  return result.status === 'pass' ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {process.exitCode = await main();}

export { normalizeLicense, parsePackageKey, reviewLicense, runPnpm };
