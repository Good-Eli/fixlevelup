import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';

const require = createRequire(new URL('../package.json', import.meta.url));
const [command, ...args] = process.argv.slice(2);
if (!['build', 'typegen', 'start'].includes(command)) {
  throw new Error('Unsupported technical Next command');
}
const nextPackage = require.resolve('next/package.json');
const nextRequire = createRequire(nextPackage);
if (process.platform === 'win32' && process.arch === 'x64') {
  // Require the installed native binding before Next can attempt a fallback download.
  nextRequire('@next/swc-win32-x64-msvc');
}
const env = { ...process.env, CI: '1', NEXT_TELEMETRY_DISABLED: '1', NEXT_DISABLE_SWC_WASM: '1' };
delete env['NEXT_TELEMETRY_DEBUG'];
const result = spawnSync(process.execPath, [require.resolve('next/dist/bin/next'), command, ...args], {
  cwd: new URL('../', import.meta.url), env, stdio: 'inherit',
});
if (result.error) { throw result.error; }
process.exitCode = result.status ?? 1;
