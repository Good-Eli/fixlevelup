import { createFoundationClient } from '../infrastructure/database/foundation-client.js';

let client: ReturnType<typeof createFoundationClient> | undefined;
try {
  client = createFoundationClient({
    host: '127.0.0.1', port: 55432, database: 'fixlevelup_dev', user: 'fixlevelup_dev',
    password: process.env['FIXLEVELUP_PROOF_PASSWORD'] ?? '',
  });
  const identity = await client.$queryRaw<{ database: string; user: string; version: string; read_only: string }[]>`
    SELECT current_database() AS database, current_user AS user, current_setting('server_version') AS version, current_setting('transaction_read_only') AS read_only
  `;
  if (identity[0]?.database !== 'fixlevelup_dev' || identity[0].user !== 'fixlevelup_dev'
    || !identity[0].version.startsWith('18.7') || identity[0].read_only !== 'on') {
    throw new Error('Unexpected foundation database identity');
  }
  const probe = await client.$queryRaw<{ id: number; marker: string }[]>`
    SELECT id, marker FROM p01_technical.persistence_probe WHERE id = 1
  `;
  if (probe.length !== 1 || probe[0]?.marker !== 'fixlevelup-p01-01-5-persistence') {
    throw new Error('Unexpected persistence proof');
  }
  process.stdout.write('Prisma ESM/adapter-pg read-only connection: PASS; PostgreSQL18.7; persistence unchanged.\n');
} catch {
  process.stderr.write('Prisma foundation connection: FAIL (details suppressed).\n');
  process.exitCode = 1;
} finally {
  if (client) {
    try { await client.$disconnect(); }
    catch {
      process.stderr.write('Prisma foundation disconnect: FAIL (details suppressed).\n');
      process.exitCode = 1;
    }
  }
}
