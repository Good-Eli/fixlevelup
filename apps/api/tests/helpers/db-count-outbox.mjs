// Counts disposable outbox-worker databases in the dev PostgreSQL instance.
// Read-only. The outbox suite names its DBs fixlevelup_p019a_worker_<12 hex>.
import { readFileSync } from 'node:fs';
import { Client } from 'pg';

const password = /^POSTGRES_PASSWORD=([a-f0-9]{64})$/m.exec(
  readFileSync(new URL('../../../../infra/dev-postgres/.env', import.meta.url), 'utf8'))?.[1];
if (!password) { throw new Error('Missing dev postgres credentials'); }

const client = new Client({ host: '127.0.0.1', port: 55432, database: 'postgres', user: 'fixlevelup_dev', password });
await client.connect();
try {
  const all = (await client.query(
    `SELECT datname FROM pg_database WHERE datname LIKE 'fixlevelup\\_p019a\\_worker\\_%' ESCAPE '\\' ORDER BY datname`)).rows.map((r) => r.datname);
  console.log(`COUNT=${all.length}`);
  for (const name of all) { console.log(`DB=${name}`); }
} finally {
  await client.end();
}
