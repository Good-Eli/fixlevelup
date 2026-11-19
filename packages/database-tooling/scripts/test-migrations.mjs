import { randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync, cpSync } from 'node:fs';
import { resolve } from 'node:path';
import { admin, credentials, connection, prepareDatabase, runPrisma, root } from './migration-local.mjs';

function assert(condition, label) { if (!condition) { throw new Error(label); } }
function command(args, database, expected = 0, shadow, history) {
  const result = runPrisma(args, database, shadow, history);
  if (result.status !== expected) { process.stdout.write(result.output); throw new Error(`Prisma command expected ${String(expected)}, got ${String(result.status)}`); }
  return result.output;
}
async function denied(client, sql) {
  try { await client.query(sql); }
  catch (error) { assert(error.code === '42501', `Expected insufficient_privilege, got ${error.code}`); return; }
  throw new Error('Runtime privilege unexpectedly allowed');
}
const client = await admin();
const passwords = credentials();
const suffix = randomBytes(6).toString('hex');
const fresh = `fixlevelup_p017a_fresh_${suffix}`;
const upgrade = `fixlevelup_p017a_upgrade_${suffix}`;
const shadow = `fixlevelup_p017a_shadow_${suffix}`;
const history = resolve(root, `node_modules/.cache/p017a-${suffix}/migrations`);
try {
  for (const database of [fresh, upgrade, shadow]) { await prepareDatabase(client, database, true); }
  console.log(`Isolated test databases: ${fresh}, ${upgrade}, ${shadow}`);
  mkdirSync(history, { recursive: true });
  cpSync(resolve(root, 'prisma/migrations/migration_lock.toml'), resolve(history, 'migration_lock.toml'));
  cpSync(resolve(root, 'prisma/migrations/20261120000100_technical_audit_outbox'), resolve(history, '20261120000100_technical_audit_outbox'), { recursive: true });
  command(['migrate', 'deploy'], fresh);
  command(['migrate', 'deploy'], upgrade, 0, undefined, history);
  const upgraded = connection('fixlevelup_runtime', passwords.fixlevelup_runtime, upgrade);
  await upgraded.connect();
  const upgradeId = randomUUID();
  try {
    await upgraded.query('INSERT INTO foundation.outbox_events(id,event_id,event_type) VALUES($1,$2,$3)', [upgradeId, randomUUID(), 'TECHNICAL_UPGRADE']);
  } finally { await upgraded.end(); }
  command(['migrate', 'deploy'], upgrade);
  const reader = connection('fixlevelup_migrator', passwords.fixlevelup_migrator, upgrade);
  await reader.connect();
  try {
    const row = await reader.query('SELECT attempt_count FROM foundation.outbox_events WHERE id=$1', [upgradeId]);
    assert(row.rows[0]?.attempt_count === 0, 'Upgrade lost data/default');
    const before = await reader.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name');
    command(['migrate', 'deploy'], upgrade);
    const after = await reader.query('SELECT migration_name,checksum,finished_at FROM foundation._prisma_migrations ORDER BY migration_name');
    assert(JSON.stringify(before.rows) === JSON.stringify(after.rows) && after.rowCount === 2, 'Replay changed migration history');
  } finally { await reader.end(); }
  console.log('Fresh/upgrade/data preservation/replay: PASS');
  command(['migrate', 'diff', '--from-migrations', '../../prisma/migrations', '--to-config-datasource', '--exit-code'], fresh, 0, shadow);
  command(['migrate', 'diff', '--from-schema', '../../prisma/schema.prisma', '--to-config-datasource', '--exit-code'], fresh);
  const migration = connection('fixlevelup_migrator', passwords.fixlevelup_migrator, fresh);
  await migration.connect();
  try {
    const owner = await migration.query("SELECT pg_get_userbyid(nspowner) AS owner FROM pg_namespace WHERE nspname='foundation'");
    assert(owner.rows[0]?.owner === 'fixlevelup_migrator', 'Schema owner mismatch');
    const checks = await migration.query("SELECT conname FROM pg_constraint WHERE connamespace='foundation'::regnamespace AND contype='c'");
    assert(checks.rowCount === 4, 'Custom CHECK constraints missing');
    await migration.query('ALTER TABLE foundation.audit_logs ADD COLUMN p017a_drift_probe integer');
    command(['migrate', 'diff', '--from-schema', '../../prisma/schema.prisma', '--to-config-datasource', '--exit-code'], fresh, 2);
    await migration.query('ALTER TABLE foundation.audit_logs DROP COLUMN p017a_drift_probe');
    command(['migrate', 'diff', '--from-schema', '../../prisma/schema.prisma', '--to-config-datasource', '--exit-code'], fresh);
  } finally { await migration.end(); }
  console.log('Migration-history diff/schema drift detection/restoration/catalog checks: PASS');
  const runtime = connection('fixlevelup_runtime', passwords.fixlevelup_runtime, fresh);
  await runtime.connect();
  try {
    const role = await runtime.query("SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,rolinherit FROM pg_roles WHERE rolname IN ('fixlevelup_runtime','fixlevelup_migrator')");
    assert(role.rowCount === 2 && role.rows.every((row) => Object.values(row).every((value) => value === false)), 'Unsafe technical role flags');
    const memberships = await runtime.query("SELECT 1 FROM pg_auth_members WHERE member IN (SELECT oid FROM pg_roles WHERE rolname IN ('fixlevelup_runtime','fixlevelup_migrator'))");
    assert(memberships.rowCount === 0, 'Technical role membership');
    const event = randomUUID(), correlation = randomUUID();
    await runtime.query('BEGIN');
    await runtime.query('INSERT INTO foundation.audit_logs(id,operation,correlation_id) VALUES($1,$2,$3)', [event, 'TECHNICAL_COMMIT', correlation]);
    await runtime.query('INSERT INTO foundation.outbox_events(id,event_id,event_type) VALUES($1,$2,$3)', [event, event, 'TECHNICAL_COMMIT']);
    await runtime.query('COMMIT');
    const committed = await runtime.query('SELECT (SELECT count(*)::int FROM foundation.audit_logs WHERE id=$1) AS audit, (SELECT count(*)::int FROM foundation.outbox_events WHERE id=$1) AS outbox', [event]);
    assert(committed.rows[0].audit === 1 && committed.rows[0].outbox === 1, 'Committed pair missing');
    await runtime.query("UPDATE foundation.outbox_events SET status='EXPANDED',attempt_count=1 WHERE id=$1", [event]);
    const rolledBack = randomUUID();
    await runtime.query('BEGIN');
    await runtime.query('INSERT INTO foundation.audit_logs(id,operation,correlation_id) VALUES($1,$2,$3)', [rolledBack, 'TECHNICAL_ROLLBACK', correlation]);
    await runtime.query('INSERT INTO foundation.outbox_events(id,event_id,event_type) VALUES($1,$2,$3)', [rolledBack, rolledBack, 'TECHNICAL_ROLLBACK']);
    await runtime.query('ROLLBACK');
    const counts = await runtime.query('SELECT (SELECT count(*)::int FROM foundation.audit_logs WHERE id=$1) AS audit, (SELECT count(*)::int FROM foundation.outbox_events WHERE id=$1) AS outbox', [rolledBack]);
    assert(counts.rows[0].audit === 0 && counts.rows[0].outbox === 0, 'Rollback not atomic');
    const failed = randomUUID();
    await runtime.query('BEGIN');
    await runtime.query('INSERT INTO foundation.audit_logs(id,operation,correlation_id) VALUES($1,$2,$3)', [failed, 'TECHNICAL_FAILURE', correlation]);
    try {
      await runtime.query("INSERT INTO foundation.outbox_events(id,event_id,event_type,status) VALUES($1,$2,'TECHNICAL_FAILURE','INVALID')", [failed, failed]);
      throw new Error('Invalid outbox status accepted');
    } catch (error) { assert(error.code === '23514', 'Expected status CHECK violation'); }
    await runtime.query('ROLLBACK');
    assert((await runtime.query('SELECT 1 FROM foundation.audit_logs WHERE id=$1', [failed])).rowCount === 0, 'Error rollback retained audit');
    for (const sql of [
      "UPDATE foundation.outbox_events SET attempt_count=-1", "UPDATE foundation.outbox_events SET status='INVALID'",
      "INSERT INTO foundation.audit_logs(id,operation,correlation_id) VALUES(gen_random_uuid(),'',gen_random_uuid())",
      "INSERT INTO foundation.outbox_events(id,event_id,event_type) VALUES(gen_random_uuid(),gen_random_uuid(),'')",
    ]) {
      try { await runtime.query(sql); throw new Error('Invalid CHECK input accepted'); }
      catch (error) { assert(error.code === '23514', 'Expected custom CHECK violation'); }
    }
    for (const sql of [
      "UPDATE foundation.audit_logs SET operation='FORBIDDEN'", 'DELETE FROM foundation.audit_logs',
      'TRUNCATE foundation.audit_logs', 'ALTER TABLE foundation.audit_logs ADD COLUMN forbidden integer',
      'DROP TABLE foundation.audit_logs', 'SELECT * FROM foundation._prisma_migrations',
      'CREATE TABLE foundation.forbidden(id integer)', 'CREATE SCHEMA forbidden', 'CREATE TEMP TABLE forbidden(id integer)',
      'SET ROLE fixlevelup_migrator', "UPDATE foundation.outbox_events SET payload='{}'", 'DELETE FROM foundation.outbox_events',
      "UPDATE foundation.outbox_events SET event_id='00000000-0000-0000-0000-000000000000'", 'CREATE TABLE public.forbidden(id integer)',
    ]) { await denied(runtime, sql); }
    console.log('Runtime committed writes/rollback and 14 privilege denials: PASS');
  } finally { await runtime.end(); }
  console.log('P01-01.7A integration proofs: PASS. Test databases retained; no dev data reset.');
} catch (error) {
  console.error(`Migration proof failed: ${error.message}`);
  process.exitCode = 1;
} finally { await client.end(); }
