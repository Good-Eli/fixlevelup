import { randomUUID } from 'node:crypto';
import { setTimeout as wait } from 'node:timers/promises';
import { bootstrapFirstAdmin } from '../../apps/api/dist/staff/bootstrap.js';
import { hashPassword } from '../../apps/api/dist/staff/password.js';
import { connection, Pool, token, verifyIdentity } from './isolation.mjs';
import { deploy } from './migrations.mjs';

const runtimeRole = 'fixlevelup_runtime';
const ownerRole = 'fixlevelup_migrator';
const adminRole = 'p0404_postgres';
function pool(namespace, role, password) {
  return new Pool({ ...connection(namespace, role, password), max: 1, connectionTimeoutMillis: 1000,
    statement_timeout: 12000, query_timeout: 13000, idleTimeoutMillis: 1000 });
}
async function waitForPostgres(admin) {
  for (let attempt = 0; attempt < 50; attempt++) {
    try { await admin.query('SELECT 1'); return; }
    catch { await wait(400); }
  }
  throw new Error('Disposable PostgreSQL unavailable');
}

export async function provision(namespace) {
  const admin = pool(namespace, adminRole, process.env['P0404_PG_BOOTSTRAP']);
  const runtimePassword = token(), migratorPassword = token();
  try {
    await waitForPostgres(admin);
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
  } finally { await admin.end(); }

  const migrator = pool(namespace, ownerRole, migratorPassword);
  migrator.on('error', () => {});
  const administrator = { login: `p0404-admin-${randomUUID()}`, password: token() };
  const manager = { login: `p0404-manager-${randomUUID()}`, password: token() };
  try {
    await verifyIdentity(migrator, namespace, ownerRole, 'migrator');
    await deploy(migrator, namespace.database, migratorPassword);
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
    return { administrator, manager, migrator, runtimePassword };
  } catch (error) { await migrator.end(); throw error; }
}

export async function seedManagerCredential(fixture) {
  // Staff himself and both assignments are created via the authenticated API.
  // Only the password hash (no public provisioning endpoint) is a test PG seed.
  await fixture.migrator.query('INSERT INTO foundation.staff_web_credentials (staff_id,login,password_hash) VALUES ($1,$2,$3)',
    [fixture.manager.id, fixture.manager.login, await hashPassword(fixture.manager.password)]);
}
