import { admin, credentials, prepareDatabase } from './migration-local.mjs';

const client = await admin();
try {
  const passwords = credentials(true);
  for (const name of ['fixlevelup_migrator', 'fixlevelup_runtime']) {
    const existing = await client.query('SELECT 1 FROM pg_roles WHERE rolname=$1', [name]);
    if (existing.rowCount) { throw new Error('Technical role already exists; refusing implicit credential changes'); }
  }
  const schema = await client.query("SELECT pg_get_userbyid(nspowner) AS owner FROM pg_namespace WHERE nspname='foundation'");
  if (schema.rowCount) { throw new Error('Foundation schema already exists; refusing bootstrap overwrite'); }
  await client.query('BEGIN');
  try {
    for (const name of ['fixlevelup_migrator', 'fixlevelup_runtime']) {
      await client.query(`CREATE ROLE "${name}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD '${passwords[name]}'`);
    }
    await prepareDatabase(client, 'fixlevelup_dev', false);
    await client.query('COMMIT');
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  console.log('Technical migration/runtime roles created; local secrets suppressed.');
} catch {
  console.error('Role bootstrap failed; details suppressed to protect credentials.');
  process.exitCode = 1;
} finally { await client.end(); }
