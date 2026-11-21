import { argon2, randomBytes, randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { lockAccessPolicy } from '../authz/rbac-lock.js';

export type BootstrapErrorCode = 'INVALID_INPUT' | 'ALREADY_INITIALIZED' | 'FAILED';

export class BootstrapError extends Error {
  constructor(readonly code: BootstrapErrorCode) {
    super('Staff bootstrap failed');
    this.name = 'BootstrapError';
  }
}

export interface BootstrapAdminInput {
  readonly login: string;
  readonly password: string;
  readonly correlationId?: string;
}

export interface BootstrapAdminResult {
  readonly staffId: string;
  readonly correlationId: string;
}

function validInput(input: BootstrapAdminInput | null | undefined): boolean {
  return input !== null && input !== undefined && typeof input.login === 'string' && /^[A-Za-z0-9][A-Za-z0-9._@+-]{0,254}$/.test(input.login)
    && typeof input.password === 'string' && !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(input.password)
    && Buffer.byteLength(input.password, 'utf8') >= 16 && Buffer.byteLength(input.password, 'utf8') <= 1024
    && !Array.from(input.password).some((character) => { const code = character.codePointAt(0) ?? 0; return code < 32 || (code >= 127 && code <= 159); })
    && (input.correlationId === undefined || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(input.correlationId));
}

async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const hash = await new Promise<Buffer>((resolve, reject) => {
    argon2('argon2id', { message: password, nonce: salt, parallelism: 1, tagLength: 32, memory: 19456, passes: 2 },
      (error, result) => { if (error) { reject(error); } else { resolve(result); } });
  });
  return `$argon2id$v=19$m=19456,t=2,p=1$${salt.toString('base64').replace(/=+$/, '')}$${hash.toString('base64').replace(/=+$/, '')}`;
}

/** Creates the initial administrator only; no recovery or administrator replacement. */
export async function bootstrapFirstAdmin(pool: Pick<Pool, 'connect'>, input: BootstrapAdminInput): Promise<BootstrapAdminResult> {
  if (!validInput(input)) { throw new BootstrapError('INVALID_INPUT'); }
  let client: PoolClient | undefined;
  let transaction = false;
  let discard = false;
  try {
    const passwordHash = await hashPassword(input.password);
    const staffId = randomUUID();
    const correlationId = input.correlationId ?? randomUUID();
    client = await pool.connect();
    await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
    transaction = true;
    // On schema 009 the BEFORE STATEMENT trigger makes even an independent staff
    // INSERT take this key. An explicit table lock here would invert lock order
    // with either a direct INSERT or an application command. No legacy fallback.
    await lockAccessPolicy(client, 'write');
    const marker = await client.query('SELECT 1 FROM foundation.staff_bootstrap_marker WHERE id = $1', [1]);
    const existing = await client.query('SELECT 1 FROM foundation.staff WHERE role = $1 LIMIT 1', ['ADMIN']);
    if (marker.rows.length !== 0 || existing.rows.length !== 0) { throw new BootstrapError('ALREADY_INITIALIZED'); }
    await client.query('INSERT INTO foundation.staff (id, role, employment_state, auth_version) VALUES ($1, $2, $3, $4)',
      [staffId, 'ADMIN', 'ACTIVE', 0]);
    await client.query('INSERT INTO foundation.staff_bootstrap_marker (id, staff_id) VALUES ($1, $2)', [1, staffId]);
    await client.query('INSERT INTO foundation.staff_web_credentials (staff_id, login, password_hash) VALUES ($1, $2, $3)',
      [staffId, input.login, passwordHash]);
    // Explicit initial assignment: not an implicit grant on seeing staff.role='ADMIN'.
    const assignment = await client.query<{ role_id: string }>(
      `INSERT INTO foundation.staff_role_assignments (id, staff_id, role_id)
       SELECT $1, $2, r.id FROM foundation.roles r WHERE r.role_type='SYSTEM' AND r.code='ADMIN' AND r.status='ACTIVE'
       RETURNING role_id`, [randomUUID(), staffId]);
    const roleId = assignment.rows[0]?.role_id;
    if (assignment.rowCount !== 1 || !roleId) { throw new BootstrapError('FAILED'); }
    await client.query('INSERT INTO foundation.audit_logs (id, operation, correlation_id, details) VALUES ($1, $2, $3, $4::jsonb)',
      [randomUUID(), 'STAFF_BOOTSTRAP', correlationId, JSON.stringify({ staffId, roleId })]);
    // Migration 012 and fresh provisioning use the same original-assignment/marker check.
    // A missing migration or failed issue rolls back the entire bootstrap; no permissive fallback.
    await client.query('SELECT foundation.issue_first_geo_permissions()');
    await client.query('COMMIT');
    transaction = false;
    return { staffId, correlationId };
  } catch (error) {
    if (client && transaction) {
      try { await client.query('ROLLBACK'); } catch { discard = true; }
    }
    if (error instanceof BootstrapError) { throw error; }
    throw new BootstrapError('FAILED');
  } finally {
    client?.release(discard);
  }
}
