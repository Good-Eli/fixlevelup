import { runPrisma } from './migration-local.mjs';

const result = runPrisma(['migrate', 'deploy'], 'fixlevelup_dev');
process.stdout.write(result.output);
process.exitCode = result.status ?? 1;
