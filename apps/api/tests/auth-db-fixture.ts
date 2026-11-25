import { createHash, randomUUID } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Client } from 'pg';
import { hashPassword } from '../src/staff/password.js';

const migrationRoot = resolve(import.meta.dirname, '../../../prisma/migrations');
// The numerical sequence restarts for each migration day. Keep the expected names independent of discovery.
function migrationDay(day: string, steps: readonly string[]): string[] {
  return steps.map((step, index) => `${day}${String(index + 1).padStart(4, '0')}00_${step}`);
}
const expectedSteps = [
  ...migrationDay('20261120', [
    'technical_audit_outbox', 'technical_outbox_attempts', 'technical_outbox_leases',
    'staff_identity', 'web_auth', 'authorization', 'staff_telegram_auth', 'staff_deactivation_grant', 'rbac',
  ]),
  ...migrationDay('20261121', ['city_foundation', 'service_areas', 'geography_access', 'settings_legal_references',
    'file_upload_reservations']),
  '20261122000100_file_upload_attempts',
  '20261122000200_file_processing_access',
  '20261122000300_file_privacy_deletion',
  '20261122000400_settings_management',
  '20261122000500_catalog_fixed_prices',
  '20261122000600_pricing_rules_ranges',
  '20261122000700_catalog_management',
  '20261123000100_request_intake_foundation',
  '20261124000100_form_session_foundation',
  '20261125000100_request_intake_effects',
];
function discoverMigrations(): readonly string[] {
  const dirs = readdirSync(migrationRoot, { withFileTypes: true })
    .filter(entry => entry.isDirectory() && /^\d{14}_/.test(entry.name)).map(entry => entry.name).sort();
  if (dirs.length !== expectedSteps.length || !expectedSteps.every((step, i) => dirs[i] === step)) {
    throw new Error('Unexpected auth fixture migration chain');
  }
  return Object.freeze(dirs);
}
export const authFixtureMigrations = discoverMigrations();

export async function migrateAuthFixture(db: Client, database: string, capBefore?: string): Promise<void> {
  // Isolation guard: only an allowlisted disposable database may be migrated by a fixture.
  if (process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] !== '1'
    || !/^fixlevelup_(bootstrap|recovery|web_auth|auth_e2e|legal|configuration)_test_[a-f0-9]{24}$/.test(database)
    || (await db.query<{ db: string }>('SELECT current_database() AS db')).rows[0]?.db !== database) {
    throw new Error('Refusing non-isolated auth fixture');
  }
  const end = capBefore === undefined ? authFixtureMigrations.length : authFixtureMigrations.indexOf(capBefore);
  if (end < 1) { throw new Error('Unknown auth fixture cap'); }
  for (const migration of authFixtureMigrations.slice(0,end)) {
    await db.query(readFileSync(resolve(migrationRoot, migration, 'migration.sql'), 'utf8'));
  }
}

/** SHA-256 of the migration script with the newline form normalized, so the
 * pinned manifest does not depend on the checkout's CRLF/LF representation. */
function migrationChecksum(migration: string): string {
  const sql = readFileSync(resolve(migrationRoot, migration, 'migration.sql'), 'utf8').replaceAll('\r\n', '\n');
  return createHash('sha256').update(sql, 'utf8').digest('hex');
}

interface ManifestEntry {
  readonly name: string;
  readonly checksum: string;
}

/** Stable SHA-256 of the ordered `name:checksum` manifest. */
function manifestDigest(entries: readonly ManifestEntry[]): string {
  return createHash('sha256')
    .update(entries.map((entry) => `${entry.name}:${entry.checksum}`).join('\n'), 'utf8')
    .digest('hex');
}

/**
 * Writes the REAL Prisma migration history into `foundation._prisma_migrations`
 * (the exact table shape Prisma uses) for the pinned chain, with one completed,
 * non-rolled-back record per migration and the exact SHA-256 of the migration
 * script as the checksum. The table is (re)created and fully repopulated, so
 * the fixture history is exactly the manifest — never an accumulation of runs.
 * The returned digest is the same value `verifyOperatorMigrationHistory`
 * recomputes from the database rows.
 */
export async function installPinnedMigrationHistory(
  db: Pick<Client, 'query'>,
  migrations: readonly string[] = authFixtureMigrations,
): Promise<{ readonly historyManifestDigest: string }> {
  await db.query(`CREATE TABLE IF NOT EXISTS foundation._prisma_migrations (
    id text PRIMARY KEY,
    checksum varchar(64) NOT NULL,
    finished_at timestamptz,
    migration_name varchar(255) NOT NULL,
    logs text,
    rolled_back_at timestamptz,
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    applied_steps_count integer NOT NULL DEFAULT 1
  )`);
  const entries = migrations.map((name) => ({ name, checksum: migrationChecksum(name) }));
  await db.query('DELETE FROM foundation._prisma_migrations');
  for (const entry of entries) {
    await db.query(`INSERT INTO foundation._prisma_migrations
      (id, checksum, finished_at, migration_name, rolled_back_at, applied_steps_count)
      VALUES ($1, $2, clock_timestamp(), $3, NULL, 1)`, [randomUUID(), entry.checksum, entry.name]);
  }
  return { historyManifestDigest: manifestDigest(entries) };
}

interface MigrationHistoryRow {
  readonly migration_name: string;
  readonly checksum: string;
  readonly finished_at: Date | null;
  readonly rolled_back_at: Date | null;
  readonly applied_steps_count: number;
}

/**
 * Operator-contour preflight (docs/P05-PLAN.md §7 item 1): reads the REAL
 * migration history and refuses on any deviation — a missing migration, an
 * extra/unknown row, a NULL `finished_at`, a rolled-back record, an applied
 * steps count other than 1, or a checksum that is not the exact SHA-256 of the
 * pinned migration script. Every failure returns `ok: false` with an empty
 * digest; the digest is only produced for a fully verified history.
 */
export async function verifyOperatorMigrationHistory(
  db: Pick<Client, 'query'>,
  expectedMigrations: readonly string[] = authFixtureMigrations,
): Promise<{ readonly ok: boolean; readonly historyManifestDigest: string }> {
  const failed = { ok: false, historyManifestDigest: '' } as const;
  let rows: readonly MigrationHistoryRow[];
  try {
    const result = await db.query<MigrationHistoryRow>(
      `SELECT migration_name, checksum, finished_at, rolled_back_at, applied_steps_count
         FROM foundation._prisma_migrations
         ORDER BY migration_name ASC`);
    rows = result.rows;
  } catch {
    // An absent/unreadable history table is a failed preflight, never a success.
    return failed;
  }
  if (rows.length !== expectedMigrations.length) { return failed; }
  const entries: ManifestEntry[] = [];
  for (const [index, expected] of expectedMigrations.entries()) {
    const row = rows[index];
    if (row === undefined
      || row.migration_name !== expected
      || !(row.finished_at instanceof Date)
      || row.rolled_back_at !== null
      || row.applied_steps_count !== 1) {
      return failed;
    }
    let checksum: string;
    try { checksum = migrationChecksum(expected); } catch { return failed; }
    if (row.checksum !== checksum) { return failed; }
    entries.push({ name: expected, checksum });
  }
  return { ok: true, historyManifestDigest: manifestDigest(entries) };
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
