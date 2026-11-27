import { spawnSync } from 'node:child_process';
import { lstatSync, readdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const api = fileURLToPath(new URL('../', import.meta.url));
const require = createRequire(import.meta.url);
const prohibited = [
  'form-session', 'requests', 'tests',
  'files/file-access/ready-attachment.js',
  'infrastructure/admission/launcher.js', 'infrastructure/admission/registry.js',
  'infrastructure/admission/control-contour.js',
];

/** tsc never removes files excluded by a new build config. Refuse to certify a
 * mixed output tree rather than deleting an existing directory or packaging T. */
function assertReleaseTree(target) {
  function visit(directory, prefix = '') {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = prefix + entry.name;
      if (entry.isSymbolicLink() || prohibited.includes(path)) {
        throw new Error('API release output is not clean; build in a fresh isolated checkout. Existing files were preserved.');
      }
      if (entry.isDirectory()) { visit(resolve(directory, entry.name), path + '/'); }
      else if (!entry.isFile()) { throw new Error('Unexpected API release output file type'); }
    }
  }
  const info = lstatSync(target, { throwIfNoEntry: false });
  if (info === undefined) { return; }
  if (!info.isDirectory() || info.isSymbolicLink()) { throw new Error('Invalid API release output directory'); }
  visit(target);
}

try {
  const target = resolve(api, 'dist');
  assertReleaseTree(target);
  const result = spawnSync(process.execPath, [require.resolve('typescript/bin/tsc'), '-p', 'tsconfig.build.json'],
    { cwd: api, stdio: 'inherit' });
  if (result.error || result.status !== 0) { process.exitCode = result.status ?? 1; }
  else { assertReleaseTree(target); }
} catch (error) {
  console.error(error instanceof Error ? error.message : 'API release build refused');
  process.exitCode = 1;
}
