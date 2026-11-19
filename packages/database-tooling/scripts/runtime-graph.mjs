import { createRequire } from 'node:module';
import { readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { resolve } from 'node:path';

const forbidden = (name) => name === 'prisma' || name === 'react' || name === 'react-dom'
  || name.startsWith('@visx/') || name.startsWith('@prisma/studio');

// Inspect manifests without importing/executing dependency code. Missing optional
// packages may be skipped, but unreadable/malformed installed packages must fail.
function resolveManifest(require, name) {
  for (const directory of require.resolve.paths(name) ?? []) {
    const packageDirectory = resolve(directory, name);
    try { statSync(packageDirectory); }
    catch (error) {
      if (error.code === 'ENOENT' || error.code === 'ENOTDIR') { continue; }
      throw error;
    }
    const path = resolve(packageDirectory, 'package.json');
    const manifest = JSON.parse(readFileSync(path, 'utf8'));
    if (manifest.name !== name) { throw new Error(`Runtime package identity mismatch ${name}`); }
    return path;
  }
  return undefined;
}

export function inspectRuntimeGraph(start) {
  const visited = new Set();
  const packages = [];
  function visit(manifestPath) {
    manifestPath = realpathSync(manifestPath);
    if (visited.has(manifestPath)) { return; }
    visited.add(manifestPath);
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    if (forbidden(manifest.name)) { throw new Error(`Forbidden API runtime package: ${manifest.name}`); }
    packages.push({ name: manifest.name, version: manifest.version });
    const require = createRequire(manifestPath);
    const dependencies = { ...manifest.dependencies, ...manifest.optionalDependencies };
    const names = new Set([...Object.keys(dependencies), ...Object.keys(manifest.peerDependencies ?? {})]);
    for (const name of names) {
      const path = resolveManifest(require, name);
      if (!path) {
        if (manifest.optionalDependencies?.[name] || manifest.peerDependenciesMeta?.[name]?.optional) { continue; }
        throw new Error(`Missing required runtime dependency ${name}`);
      }
      visit(path);
    }
  }
  visit(start);
  return packages;
}

export function inspectCompiledImports(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) { inspectCompiledImports(path); continue; }
    if (!entry.name.endsWith('.js')) { continue; }
    const source = readFileSync(path, 'utf8');
    for (const match of source.matchAll(/(?:from\s*|import\s*(?:\(\s*)?|require\s*\()\s*['"]([^'"]+)['"]/g)) {
      const specifier = match[1];
      const name = specifier.startsWith('@') ? specifier.split('/').slice(0, 2).join('/') : specifier.split('/')[0];
      if (forbidden(name)) { throw new Error(`Forbidden compiled import ${name}`); }
    }
  }
}
