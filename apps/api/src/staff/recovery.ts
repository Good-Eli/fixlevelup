import { argon2, randomBytes, randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';

export interface RecoverAdminInput {
  readonly login: string;
  readonly password: string;
}

/** All failure modes are intentionally indistinguishable to the caller. */
export class RecoveryError extends Error {
  constructor() { super('Staff recovery failed'); this.name = 'RecoveryError'; }
}

function validInput(input: RecoverAdminInput): boolean {
  return typeof input.login === 'string' && /^[A-Za-z0-9][A-Za-z0-9._@+-]{0,254}$/.test(input.login)
    && typeof input.password === 'string' && !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(input.password)
    && Buffer.byteLength(input.password, 'utf8') >= 16 && Buffer.byteLength(input.password, 'utf8') <= 1024
    // eslint-disable-next-line no-control-regex
    && !/[\u0000-\u001f\u007f-\u009f]/u.test(input.password);
}

async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const hash = await new Promise<Buffer>((resolve, reject) => {
    argon2('argon2id', { message: password, nonce: salt, parallelism: 1, tagLength: 32, memory: 19456, passes: 2 },
      (error, result) => { if (error) { reject(error); } else { resolve(result); } });
  });
  return `$argon2id$v=19$m=19456,t=2,p=1$${salt.toString('base64').replace(/=+$/, '')}$${hash.toString('base64').replace(/=+$/, '')}`;
}

/** Reset only an existing active administrator credential, with audit in the same transaction. */
export async function recoverAdmin(pool: Pick<Pool, 'connect'>, input: RecoverAdminInput): Promise<void> {
  if (!validInput(input)) { throw new RecoveryError(); }
  let client: PoolClient | undefined;
  let transaction = false;
  let discard = false;
  try {
    const passwordHash = await hashPassword(input.password);
    client = await pool.connect();
    await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
    transaction = true;
    const found = await client.query<{ id: string }>(
      `SELECT s.id FROM foundation.staff AS s
       JOIN foundation.staff_web_credentials AS c ON c.staff_id = s.id
       WHERE c.login = $1 AND s.role = 'ADMIN' AND s.employment_state = 'ACTIVE'
       FOR UPDATE OF s, c`, [input.login]);
    const row = found.rows[0];
    if (found.rows.length !== 1 || !row) { throw new RecoveryError(); }
    const staffId = row.id;
    const credential = await client.query('UPDATE foundation.staff_web_credentials SET password_hash = $1 WHERE staff_id = $2', [passwordHash, staffId]);
    const staff = await client.query('UPDATE foundation.staff SET auth_version = auth_version + 1 WHERE id = $1', [staffId]);
    if (credential.rowCount !== 1 || staff.rowCount !== 1) { throw new RecoveryError(); }
    await client.query('INSERT INTO foundation.audit_logs (id, operation, correlation_id, details) VALUES ($1, $2, $3, $4::jsonb)',
      [randomUUID(), 'STAFF_RECOVERY', randomUUID(), JSON.stringify({ staffId })]);
    await client.query('COMMIT');
    transaction = false;
  } catch {
    if (client && transaction) {
      try { await client.query('ROLLBACK'); } catch { discard = true; }
    }
    throw new RecoveryError();
  } finally {
    client?.release(discard);
  }
}
