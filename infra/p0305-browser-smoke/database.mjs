import { randomUUID } from 'node:crypto';
import { setTimeout as wait } from 'node:timers/promises';
import { bootstrapFirstAdmin } from '../../apps/api/dist/staff/bootstrap.js';
import { hashPassword } from '../../apps/api/dist/staff/password.js';
import { Pool, applyCappedMigrations, artifactDigest, compileLauncherModules, createControlContour, host,
  migrationInventory, pgPort, physicalContractDigest, token } from './launch.mjs';

// Required by the compiled production API entrypoint. It is only reachable
// inside the container's own network namespace: no host or preexisting
// fixlevelup_dev is reachable from it.
export const database = 'fixlevelup_dev';

const adminRole = 'p0305_postgres';
function pool(facts) {
  const pool = new Pool({ ...facts, ssl: false, connectionTimeoutMillis: 1000, max: 2,
    statement_timeout: 60_000, query_timeout: 65_000, application_name: 'p0305-fixture' });
  pool.on('error', () => { /* Driver errors never surface with values. */ });
  return pool;
}
async function connected(client) {
  for (let attempt = 0; attempt < 40; attempt++) {
    try { await client.query('SELECT 1'); return; }
    catch { await wait(500); }
  }
  throw new Error('Isolated PostgreSQL not available');
}

/** The disposable cluster must be fresh: exact version, cluster marker, no prior schema/roles. */
async function proveFresh(admin, marker) {
  const proof = await admin.query(`SELECT current_database()=$1 AND current_user=$2
      AND current_setting('server_version_num')='180007' AND current_setting('cluster_name')=$3
      AND current_setting('listen_addresses')='127.0.0.1'
      AND NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='foundation')
      AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relnamespace='public'::regnamespace)
      AND NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname !~ '^pg_' AND rolname<>$2)
      AND NOT EXISTS (SELECT 1 FROM pg_database WHERE datname NOT IN ($1,'postgres','template0','template1'))
      AND (SELECT count(*)::int FROM pg_database)=4 AS ok`,
  [database, adminRole, `p0305-${marker}`]);
  if (proof.rows[0]?.ok !== true) { throw new Error('Refusing non-disposable or initialized cluster'); }
}

export async function provision(marker) {
  // No existing env file, connection string or default driver config is accepted.
  const adminPassword = process.env['P0305_PG_BOOTSTRAP'];
  if (!/^[a-f0-9]{64}$/u.test(adminPassword ?? '')) { throw new Error('Disposable database token missing'); }
  if (!/^[a-f0-9]{24}$/u.test(marker ?? '')) { throw new Error('Disposable namespace marker missing'); }
  const operator = Object.freeze({ host, port: pgPort, user: adminRole, password: adminPassword });
  const admin = pool({ ...operator, database });
  const passwords = { fixlevelup_migrator: token(), fixlevelup_runtime: token() };
  const pinned = await migrationInventory();
  let control;
  try {
    await connected(admin);
    await proveFresh(admin, marker);
    // Identifier/password interpolation is confined to fixed identifiers and generated hex.
    for (const [role, password] of Object.entries(passwords)) {
      await admin.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
        NOBYPASSRLS NOINHERIT PASSWORD '${password}'`);
    }
    await admin.query(`ALTER DATABASE ${database} OWNER TO fixlevelup_migrator;
      REVOKE ALL ON DATABASE ${database} FROM PUBLIC;
      GRANT CONNECT ON DATABASE ${database} TO fixlevelup_migrator,fixlevelup_runtime;
      CREATE SCHEMA foundation AUTHORIZATION fixlevelup_migrator;
      REVOKE ALL ON SCHEMA foundation FROM PUBLIC;
      REVOKE CREATE ON SCHEMA public FROM PUBLIC`);
    // Separate disposable control contour (plan §7): own database, own narrow
    // launcher role, no CONNECT for the application roles.
    control = await createControlContour({ admin, owner: operator, marker, modules: await compileLauncherModules() });
  } finally { await admin.end().catch(() => undefined); }

  const migratorFacts = Object.freeze({ host, port: pgPort, database, user: 'fixlevelup_migrator',
    password: passwords.fixlevelup_migrator });
  const migrator = pool(migratorFacts);
  const administrator = { login: `p0305-admin-${randomUUID()}`, password: token() };
  const manager = { id: randomUUID(), login: `p0305-manager-${randomUUID()}`, password: token() };
  try {
    const migrationClient = await migrator.connect();
    let history;
    try { history = await applyCappedMigrations(migrationClient, pinned); }
    finally { migrationClient.release(); }
    const { staffId: actor } = await bootstrapFirstAdmin(migrator, administrator);
    const client = await migrator.connect();
    try {
      await client.query('BEGIN');
      await client.query("INSERT INTO foundation.staff (id,role,employment_state) VALUES ($1,'MANAGER','ACTIVE')", [manager.id]);
      await client.query('INSERT INTO foundation.staff_web_credentials (staff_id,login,password_hash) VALUES ($1,$2,$3)',
        [manager.id, manager.login, await hashPassword(manager.password)]);
      const assignment = await client.query(`INSERT INTO foundation.staff_role_assignments (id,staff_id,role_id,assigned_by)
        SELECT gen_random_uuid(),$1,id,$2 FROM foundation.roles WHERE role_type='SYSTEM' AND code='MANAGER' AND status='ACTIVE'`,
      [manager.id, actor]);
      if (assignment.rowCount !== 1) { throw new Error('Synthetic manager role missing'); }
      await client.query('COMMIT');
    } catch (error) { await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
    const identity = await migrator.query(`SELECT oid FROM pg_database WHERE datname=current_database()`);
    const databaseOid = identity.rows[0]?.oid;
    if (!Number.isSafeInteger(databaseOid) || databaseOid <= 0) { throw new Error('Application database OID missing'); }
    return Object.freeze({
      administrator, manager, actor, migrator, databaseOid,
      database: Object.freeze({ host, port: pgPort, database, user: 'fixlevelup_runtime',
        password: passwords.fixlevelup_runtime }),
      operator: migratorFacts,
      control,
      artifact: await artifactDigest(),
      physical: await physicalContractDigest(),
      history: history.historyManifestDigest,
      migrationReport: Object.freeze({ applied: history.applied, chain: history.chain, excluded: history.excluded }),
    });
  } catch (error) { await migrator.end().catch(() => undefined); throw error; }
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
