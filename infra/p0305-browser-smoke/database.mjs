import { randomBytes, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { setTimeout as wait } from 'node:timers/promises';
import { bootstrapFirstAdmin } from '../../apps/api/dist/staff/bootstrap.js';
import { hashPassword } from '../../apps/api/dist/staff/password.js';

const requireApi = createRequire(new URL('../../apps/api/package.json', import.meta.url));
const { Pool } = requireApi('pg');
const migrationRoot = new URL('../../prisma/migrations/', import.meta.url);
const head = '20261122000400_settings_management';
export const database = 'fixlevelup_dev'; // Required by compiled production API, inside a new network namespace only.
export const token = () => randomBytes(32).toString('hex');

async function connected(pool) {
  for (let attempt = 0; attempt < 40; attempt++) {
    try { await pool.query('SELECT 1'); return; }
    catch { await wait(500); }
  }
  throw new Error('Isolated PostgreSQL not available');
}

export async function provision() {
  // No existing env file, connection string or default driver config is accepted.
  const connection = { host: '127.0.0.1', port: 55432, database, ssl: false,
    connectionTimeoutMillis: 1000, statement_timeout: 30000, max: 1 };
  const adminPassword = process.env['P0305_PG_BOOTSTRAP'];
  if (!/^[a-f0-9]{64}$/.test(adminPassword ?? '')) { throw new Error('Disposable database token missing'); }
  const admin = new Pool({ ...connection, user: 'p0305_postgres', password: adminPassword });
  const passwords = { fixlevelup_migrator: token(), fixlevelup_runtime: token() };
  const marker = process.env['P0305_NAMESPACE'];
  if (!marker || !/^[a-f0-9]{24}$/.test(marker)) { throw new Error('Disposable namespace marker missing'); }
  try {
    await connected(admin);
    const proof = await admin.query(`SELECT current_database()=$1 AND current_user='p0305_postgres'
      AND current_setting('server_version_num')='180007' AND current_setting('cluster_name')=$2
      AND NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='foundation')
      AND NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname IN ('fixlevelup_migrator','fixlevelup_runtime')) AS ok`, [database, `p0305-${marker}`]);
    if (proof.rows[0]?.ok !== true) { throw new Error('Refusing non-disposable or initialized cluster'); }
    for (const [role, password] of Object.entries(passwords)) {
      await admin.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD '${password}'`);
    }
    await admin.query(`ALTER DATABASE ${database} OWNER TO fixlevelup_migrator;
      REVOKE ALL ON DATABASE ${database} FROM PUBLIC;
      GRANT CONNECT ON DATABASE ${database} TO fixlevelup_migrator,fixlevelup_runtime;
      CREATE SCHEMA foundation AUTHORIZATION fixlevelup_migrator;
      REVOKE ALL ON SCHEMA foundation FROM PUBLIC;
      REVOKE CREATE ON SCHEMA public FROM PUBLIC`);
  } finally { await admin.end(); }

  const migrator = new Pool({ ...connection, user: 'fixlevelup_migrator', password: passwords.fixlevelup_migrator });
  const administrator = { login: `p0305-admin-${randomUUID()}`, password: token() };
  const manager = { id: randomUUID(), login: `p0305-manager-${randomUUID()}`, password: token() };
  try {
    const steps = (await readdir(migrationRoot)).filter(name => /^\d{14}_/.test(name)).sort();
    if (steps.length !== 18 || steps.at(-1) !== head) { throw new Error('Unexpected P03 migration chain'); }
    const databaseTooling = new URL('../../packages/database-tooling/', import.meta.url);
    const requirePrisma = createRequire(new URL('package.json', databaseTooling));
    const deployed = spawnSync(process.execPath, [requirePrisma.resolve('prisma/build/index.js'), 'migrate', 'deploy', '--config', 'prisma.config.ts'], {
      cwd: databaseTooling, stdio: 'ignore', timeout: 60_000,
      env: { PATH: process.env['PATH'], HOME: process.env['HOME'], CHECKPOINT_DISABLE: '1', PRISMA_HIDE_UPDATE_MESSAGE: '1',
        FIXLEVELUP_MIGRATION_URL: `postgresql://fixlevelup_migrator:${passwords.fixlevelup_migrator}@127.0.0.1:55432/${database}?schema=foundation` },
    });
    if (deployed.status !== 0) { throw new Error('Production migration deploy failed on isolated cluster'); }
    const history = await migrator.query('SELECT migration_name FROM foundation._prisma_migrations WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL ORDER BY migration_name');
    if (history.rows.map(row => row.migration_name).join() !== steps.join()) { throw new Error('Incomplete isolated migration history'); }
    const { staffId: actor } = await bootstrapFirstAdmin(migrator, administrator);
    const client = await migrator.connect();
    try {
      await client.query('BEGIN');
      await client.query("INSERT INTO foundation.staff (id,role,employment_state) VALUES ($1,'MANAGER','ACTIVE')", [manager.id]);
      await client.query('INSERT INTO foundation.staff_web_credentials (staff_id,login,password_hash) VALUES ($1,$2,$3)', [manager.id, manager.login, await hashPassword(manager.password)]);
      const assignment = await client.query(`INSERT INTO foundation.staff_role_assignments (id,staff_id,role_id,assigned_by)
        SELECT gen_random_uuid(),$1,id,$2 FROM foundation.roles WHERE role_type='SYSTEM' AND code='MANAGER' AND status='ACTIVE'`, [manager.id, actor]);
      if (assignment.rowCount !== 1) { throw new Error('Synthetic manager role missing'); }
      await client.query('COMMIT');
    } catch (error) { await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
    return { administrator, manager, actor, migrator, runtimePassword: passwords.fixlevelup_runtime };
  } catch (error) { await migrator.end(); throw error; }
}

export async function verifyPublication({ migrator, actor }, request) {
  const result = await migrator.query(`SELECT
    (SELECT count(*)::int FROM foundation.legal_document_versions) AS versions,
    (SELECT count(*)::int FROM foundation.p03_command_receipts WHERE operation='legalPublish') AS receipts,
    (SELECT count(*)::int FROM foundation.audit_logs WHERE operation='LEGAL_DOCUMENT_VERSION_PUBLISHED') AS audits,
    (SELECT count(*)::int FROM foundation.outbox_events WHERE event_type='LEGAL_DOCUMENT_VERSION_PUBLISHED') AS events,
    EXISTS (SELECT 1 FROM foundation.legal_documents d JOIN foundation.legal_document_versions v
      ON v.id=d.current_version_id AND v.document_id=d.id
      JOIN foundation.p03_command_receipts r ON r.entity_id=d.id AND r.revision_id=v.id
      JOIN foundation.audit_logs a ON a.operation='LEGAL_DOCUMENT_VERSION_PUBLISHED'
        AND a.details=jsonb_build_object('documentId',d.id,'purpose',d.purpose,'kind',d.kind,
          'versionId',v.id,'sequence',v.version,'reviewedBy',v.reviewed_by)
      JOIN foundation.outbox_events o ON o.event_id=a.correlation_id AND o.event_type=a.operation AND o.payload=a.details
      WHERE d.id=$1 AND v.id=$2 AND d.purpose='REQUEST_PROCESSING' AND d.kind='CONSENT_FORM'
        AND v.reviewed_by=$3 AND r.actor_id=$3 AND r.operation='legalPublish'
        AND r.key=$4 AND r.entity_version=d.row_version AND r.revision_version=v.version
        AND v.title=$5 AND v.body=$6 AND v.source_ref=$7 AND v.legal_basis=$8) AS exact`,
  [request.id, request.revisionId, actor, request.key, request.title, request.body, request.sourceRef, request.legalBasis]);
  return result.rows[0]; // Booleans/counts only, never a body, key, credential or actor identifier.
}
