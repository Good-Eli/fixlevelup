import { randomUUID } from 'node:crypto';
import { setTimeout as wait } from 'node:timers/promises';
import { bootstrapFirstAdmin } from '../../apps/api/dist/staff/bootstrap.js';
import { hashPassword } from '../../apps/api/dist/staff/password.js';
import { adminRole, connection, controlIdentity, Pool, token, verifyContour, verifyIdentity } from './isolation.mjs';
import { deploy } from './migrations.mjs';
import { artifactDigest, compileLauncherModules, createControlContour, physicalContractDigest } from '../p0305-browser-smoke/launch.mjs';

const runtimeRole = 'fixlevelup_runtime';
const ownerRole = 'fixlevelup_migrator';
function pool(namespace, role, password, timeoutMs = 12_000) {
  return new Pool({ ...connection(namespace, role, password), max: 1, connectionTimeoutMillis: 1000,
    statement_timeout: timeoutMs, query_timeout: timeoutMs + 1000, idleTimeoutMillis: 1000 });
}
async function waitForPostgres(admin) {
  for (let attempt = 0; attempt < 50; attempt++) {
    try { await admin.query('SELECT 1'); return; }
    catch { await wait(400); }
  }
  throw new Error('Disposable PostgreSQL unavailable');
}

export async function provision(namespace) {
  const adminPassword = process.env['P0404_PG_BOOTSTRAP'];
  if (typeof adminPassword !== 'string' || !/^[a-f0-9]{64}$/u.test(adminPassword)) {
    throw new Error('Disposable database token missing');
  }
  const operator = Object.freeze({ host: '127.0.0.1', port: 55432, user: adminRole, password: adminPassword });
  const admin = pool(namespace, adminRole, adminPassword, 60_000);
  const runtimePassword = token(), migratorPassword = token();
  let control;
  try {
    await waitForPostgres(admin);
    // The cluster must be provably fresh BEFORE anything is created: this is
    // also the only place the "no preexisting databases" invariant is checked.
    await verifyIdentity(admin, namespace, adminRole, 'fresh');
    // Identifier/password interpolation is confined to fixed identifiers and generated hex.
    await admin.query(`CREATE ROLE ${ownerRole} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD '${migratorPassword}';
      CREATE ROLE ${runtimeRole} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD '${runtimePassword}';
      ALTER DATABASE ${namespace.database} OWNER TO ${ownerRole};
      REVOKE ALL ON DATABASE ${namespace.database} FROM PUBLIC;
      GRANT CONNECT ON DATABASE ${namespace.database} TO ${ownerRole},${runtimeRole};
      CREATE SCHEMA foundation AUTHORIZATION ${ownerRole};
      REVOKE ALL ON SCHEMA foundation FROM PUBLIC;
      REVOKE CREATE ON SCHEMA public FROM PUBLIC`);
    // Separate disposable control contour (plan §7): its own database with its
    // own owner and its own narrow launcher role; the application roles get no
    // CONNECT on it. Created by the reviewed registry module, then read back.
    const modules = await compileLauncherModules();
    control = await createControlContour({ admin, owner: operator, marker: namespace.marker, modules });
    await verifyContour(admin, namespace, control, control.facts);
  } finally { await admin.end().catch(() => undefined); }

  const migrator = pool(namespace, ownerRole, migratorPassword);
  migrator.on('error', () => {});
  const administrator = { login: `p0404-admin-${randomUUID()}`, password: token() };
  const manager = { login: `p0404-manager-${randomUUID()}`, password: token() };
  try {
    await verifyIdentity(migrator, namespace, ownerRole, 'migrator');
    const history = await deploy(migrator);
    administrator.id = (await bootstrapFirstAdmin(migrator, administrator)).staffId;
    const client = await migrator.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      await verifyIdentity(client, namespace, ownerRole, 'migrator');
      const prior = await client.query('SELECT count(*)::int AS n FROM foundation.p04_bootstrap_permissions');
      if (prior.rows[0]?.n !== 0) { throw new Error('P04 grants must not be issued by migrations or first-admin bootstrap'); }
      // UI proof only; production deployment/bootstrap never invokes this function.
      await client.query('SELECT foundation.issue_p04_synthetic_permissions()');
      const created = await client.query(`SELECT count(*)::int AS n FROM foundation.p04_bootstrap_permissions p
        JOIN foundation.staff_role_assignments a ON a.id=p.assignment_id
        WHERE a.staff_id=$1 AND a.revoked_at IS NULL AND p.revoked_at IS NULL`, [administrator.id]);
      if (created.rows[0]?.n !== 9) { throw new Error('Expected exactly nine synthetic founder grants'); }
      await client.query('COMMIT');
    } catch (error) { await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
    const identity = await migrator.query('SELECT oid FROM pg_database WHERE datname=current_database()');
    const databaseOid = identity.rows[0]?.oid;
    if (!Number.isSafeInteger(databaseOid) || databaseOid <= 0) { throw new Error('Application database OID missing'); }
    const { database, role } = controlIdentity(namespace.marker);
    if (control.database !== database || control.role !== role) { throw new Error('Control contour mismatch'); }
    // Mutable fixture record: commissioning adds the created city IDs to it.
    // Only the nested connection/contour facts are frozen.
    return {
      administrator, manager, migrator, runtimePassword, databaseOid,
      database: Object.freeze(connection(namespace, runtimeRole, runtimePassword)),
      operator: Object.freeze(connection(namespace, ownerRole, migratorPassword)),
      control,
      artifact: await artifactDigest(),
      physical: await physicalContractDigest(),
      history: history.historyManifestDigest,
      migrationReport: Object.freeze({ applied: history.applied, chain: history.chain, excluded: history.excluded }),
    };
  } catch (error) { await migrator.end(); throw error; }
}

export async function seedManagerCredential(fixture) {
  // Staff himself and both assignments are created via the authenticated API.
  // Only the password hash (no public provisioning endpoint) is a test PG seed.
  await fixture.migrator.query('INSERT INTO foundation.staff_web_credentials (staff_id,login,password_hash) VALUES ($1,$2,$3)',
    [fixture.manager.id, fixture.manager.login, await hashPassword(fixture.manager.password)]);
}
