import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const require = createRequire(new URL('../package.json', import.meta.url));
const env = { ...process.env, CHECKPOINT_DISABLE: '1', PRISMA_HIDE_UPDATE_MESSAGE: '1' };
const result = spawnSync(process.execPath, [require.resolve('prisma/build/index.js'),
  'generate', '--config', 'prisma.config.ts', '--no-hints'], {
  cwd: fileURLToPath(new URL('../', import.meta.url)), env, stdio: 'inherit',
});
if (result.error) { throw result.error; }
process.exitCode = result.status ?? 1;
