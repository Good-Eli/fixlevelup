import { spawnSync } from 'node:child_process';
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const evidence = '/workspace/node_modules/.cache/linux-proof';
const hash = () => createHash('sha256').update(readFileSync('pnpm-lock.yaml')).digest('hex');
const initial = hash();
const steps = [];
function run(name, args) {
  console.log(`Linux proof: ${name}`);
  // The whole-repository ESLint pass exceeds Node's default heap in the 4 GiB
  // sandbox. Give only the lint child a bounded 3.5 GiB V8 heap; CI allocates 5 GiB.
  const env = name === 'lint'
    ? { ...process.env, NODE_OPTIONS: '--max-old-space-size=3584' }
    : process.env;
  const result = spawnSync('corepack', ['pnpm', ...args], { stdio: 'inherit', timeout: 600_000, env });
  if (result.error || result.status !== 0 || result.signal) { throw new Error(`Linux proof step failed: ${name}`); }
  if (hash() !== initial) { throw new Error('Linux lockfile changed'); }
  steps.push(name);
}
try {
  if (process.platform !== 'linux' || process.arch !== 'x64' || process.version !== 'v24.22.3') { throw new Error('Unexpected Linux runtime'); }
  run('offline frozen force reinstall', ['install','--frozen-lockfile','--offline','--ignore-scripts','--strict-peer-dependencies','--force']);
  run('lint', ['run','lint']);
  run('typecheck', ['run','typecheck']);
  run('build all three targets', ['run','build']);
  // Deliberate allowlist: DB/S3 fixtures require credentials and services, which
  // are intentionally absent. This is not a passing claim for full Linux CI.
  const tests = [
    'packages/tooling/tests/tooling.test.ts',
    'apps/api/tests/compiled.test.ts','apps/api/tests/config.test.ts','apps/api/tests/http.test.ts',
    'apps/api/tests/logger.test.ts','apps/api/tests/worker.test.ts','apps/api/tests/prisma-foundation.test.ts',
    'apps/web/tests/production.test.ts','apps/miniapp/tests/foundation.test.tsx','apps/miniapp/tests/preview.test.ts',
    'packages/storage-tooling/tests/backup-manifest.test.ts','packages/storage-tooling/tests/timeouts.test.ts',
  ];
  run('service-independent tests', ['exec','vitest','run',...tests]);
  run('API runtime graph isolation', ['run','db:runtime-check']);
  const posix = spawnSync(process.execPath,['infra/linux-proof/posix-smoke.mjs'],{stdio:'inherit',timeout:60_000});
  if (posix.error || posix.status !== 0 || posix.signal) { throw new Error('Linux POSIX signal smoke failed'); }
  steps.push('real OS SIGTERM/SIGINT API/worker');
  mkdirSync(evidence,{recursive:true});
  writeFileSync(`${evidence}/result.json`,JSON.stringify({platform:process.platform,arch:process.arch,node:process.version,lockSha256:initial,steps,network:'none',credentials:'synthetic only',limitations:['no Linux DB/S3 integration','no remote CI','no browser/image security scan','local Docker proof only']},null,2)+'\n');
  console.log('Linux reproducibility and OS signal proof: PASS');
} catch (error) {
  console.error(error instanceof Error ? error.message : 'Linux proof failed');
  process.exitCode=1;
}
