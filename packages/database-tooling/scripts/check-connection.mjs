import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = new URL('../../../', import.meta.url);
const text = readFileSync(new URL('infra/dev-postgres/.env', root), 'utf8');
const match = /^POSTGRES_PASSWORD=([a-f0-9]{64})$/m.exec(text);
if (!match) { throw new Error('Local PostgreSQL proof password is unavailable'); }
const result = spawnSync(process.execPath, [fileURLToPath(new URL('apps/api/dist/bootstrap/prisma-proof.js', root))], {
  cwd: fileURLToPath(root), env: { ...process.env, FIXLEVELUP_PROOF_PASSWORD: match[1] }, stdio: 'inherit',
});
if (result.error) { throw result.error; }
process.exitCode = result.status ?? 1;
