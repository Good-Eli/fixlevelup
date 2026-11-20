import { randomUUID } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Client } from 'pg';
import { hashPassword } from '../src/staff/password.js';

const migrationRoot = resolve(import.meta.dirname, '../../../prisma/migrations');
const expectedSteps = ['technical_audit_outbox', 'technical_outbox_attempts', 'technical_outbox_leases',
  'staff_identity', 'web_auth', 'authorization', 'staff_telegram_auth', 'staff_deactivation_grant', 'rbac'];
function discoverMigrations(): readonly string[] {
  const dirs = readdirSync(migrationRoot, { withFileTypes: true })
    .filter(entry => entry.isDirectory() && /^\d{14}_/.test(entry.name)).map(entry => entry.name).sort();
  if (dirs.length !== expectedSteps.length || !expectedSteps.every((step, i) =>
    dirs[i] === `20261120${String(i + 1).padStart(4, '0')}00_${step}`)) {
    throw new Error('Unexpected auth fixture migration chain');
  }
  return Object.freeze(dirs);
}
export const authFixtureMigrations = discoverMigrations();

export async function migrateAuthFixture(db: Client, database: string): Promise<void> {
  if (process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] !== '1'
    || !/^fixlevelup_(bootstrap|recovery|web_auth|auth_e2e)_test_[a-f0-9]{24}$/.test(database)
    || (await db.query<{ db: string }>('SELECT current_database() AS db')).rows[0]?.db !== database) {
    throw new Error('Refusing non-isolated auth fixture');
  }
  for (const migration of authFixtureMigrations) {
    await db.query(readFileSync(resolve(migrationRoot, migration, 'migration.sql'), 'utf8'));
  }
}

export async function inFixtureTransaction<T>(db: Client, run: () => Promise<T>): Promise<T> {
  await db.query('BEGIN');
  try { const result = await run(); await db.query('COMMIT'); return result; }
  catch (error) { await db.query('ROLLBACK'); throw error; }
}

type SystemRole = 'ADMIN' | 'MANAGER' | 'TECHNICIAN';
async function assign(db: Client, staffId: string, role: SystemRole, actor: string | null) {
  const result = await db.query(`INSERT INTO foundation.staff_role_assignments (id,staff_id,role_id,assigned_by)
    SELECT gen_random_uuid(),$1,r.id,$3 FROM foundation.roles r WHERE r.role_type='SYSTEM' AND r.code=$2 AND r.status='ACTIVE'`, [staffId, role, actor]);
  if (result.rowCount !== 1) { throw new Error('Missing system role'); }
}

// Caller owns the transaction, including its commit point in the lock regression.
export async function insertWebStaff(db: Client, role: SystemRole = 'ADMIN', login: string = randomUUID(), password: string = randomUUID(), actor: string | null = null) {
  const id = randomUUID();
  await db.query("INSERT INTO foundation.staff (id,role,employment_state) VALUES ($1,$2,'ACTIVE')", [id, role]);
  await db.query('INSERT INTO foundation.staff_web_credentials (staff_id,login,password_hash) VALUES ($1,$2,$3)', [id, login, await hashPassword(password)]);
  await assign(db, id, role, actor);
  return id;
}

export function spareAdmin(db: Client, actor: string) {
  return inFixtureTransaction(db, () => insertWebStaff(db, 'ADMIN', undefined, undefined, actor));
}

export function reassignFixture(db: Client, staffId: string, role: SystemRole, actor: string) {
  return inFixtureTransaction(db, async () => {
    await db.query("UPDATE foundation.staff SET employment_state='ACTIVE', role=$2 WHERE id=$1", [staffId, role]);
    const revoked = await db.query(`UPDATE foundation.staff_role_assignments SET revoked_at=clock_timestamp(), revoked_by=$2
      WHERE staff_id=$1 AND revoked_at IS NULL`, [staffId, actor]);
    if (revoked.rowCount !== 1) { throw new Error('Missing current assignment'); }
    await assign(db, staffId, role, actor);
  });
}
