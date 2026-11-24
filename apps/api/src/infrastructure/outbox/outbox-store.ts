import type { DatabaseConfig } from '../database/runtime-database.js';
import { admittedPool } from '../admission/pool-guard.js';
import type { GuardedPool } from '../admission/pool-guard.js';
import type { RuntimeAdmission } from '../admission/runtime-admission.js';

export interface OutboxLease {
  readonly id: string;
  readonly eventId: string;
  readonly eventType: string;
  readonly payload: unknown;
  readonly owner: string;
  readonly generation: bigint;
  readonly attemptCount: number;
}
interface ClaimedRow {
  id: string; event_id: string; event_type: string; payload: unknown;
  lease_owner: string | null; lease_generation: string; attempt_count: number; status: string;
}

const maxAttempts = 3;

/** Technical queue persistence. No transport calls or arbitrary error strings. */
export class OutboxStore {
  private readonly pool: GuardedPool;
  private closing = false;

  constructor(config: DatabaseConfig, admission: RuntimeAdmission) {
    // P05-01 §7: this pool is admitted per checkout by the launch gate.
    this.pool = admittedPool({ gate: admission.gate }, { ...config, max: 2, connectionTimeoutMillis: 1000,
      query_timeout: 2000, statement_timeout: 1000, idleTimeoutMillis: 1000,
      options: '-c lock_timeout=1000', application_name: 'fixlevelup-outbox-runtime' });
    this.pool.on('error', () => { /* driver errors may contain credentials */ });
  }

  async claim(owner: string, eventTypes: readonly string[], leaseMs = 30_000): Promise<OutboxLease | undefined> {
    if (this.closing || eventTypes.length === 0) { return undefined; }
    if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(owner) || !Number.isInteger(leaseMs) || leaseMs < 100 || leaseMs > 300_000
      || eventTypes.length > 64 || eventTypes.some((type) => type.length === 0 || type.length > 64 || type.includes('\0'))) {
      throw new Error('Invalid technical outbox claim configuration');
    }
    // The row lock and ownership update are one statement/transaction. PostgreSQL
    // time is authoritative, including expiry after a stalled or crashed worker.
    const result = await this.pool.query<ClaimedRow>(`
      WITH candidate AS (
        SELECT id FROM foundation.outbox_events
        WHERE status='PENDING' AND event_type=ANY($2::text[])
          AND next_attempt_at<=clock_timestamp()
          AND (lease_expires_at IS NULL OR lease_expires_at<=clock_timestamp())
        ORDER BY next_attempt_at,created_at,id FOR UPDATE SKIP LOCKED LIMIT 1
      )
      UPDATE foundation.outbox_events e SET
        status=CASE WHEN attempt_count >= $4 THEN 'FAILED' ELSE 'PENDING' END,
        lease_owner=CASE WHEN attempt_count >= $4 THEN NULL ELSE $1::uuid END,
        lease_expires_at=CASE WHEN attempt_count >= $4 THEN NULL ELSE clock_timestamp()+$3::int*interval '1 millisecond' END,
        lease_generation=lease_generation+CASE WHEN attempt_count >= $4 THEN 0 ELSE 1 END,
        attempt_count=attempt_count+CASE WHEN attempt_count >= $4 THEN 0 ELSE 1 END,
        last_error_code=CASE WHEN attempt_count >= $4 THEN 'ATTEMPTS_EXHAUSTED' ELSE last_error_code END
      FROM candidate c WHERE e.id=c.id RETURNING e.*`, [owner, [...eventTypes], leaseMs, maxAttempts]);
    const row = result.rows[0];
    if (!row || row.status !== 'PENDING' || !row.lease_owner) { return undefined; }
    return { id: row.id, eventId: row.event_id, eventType: row.event_type, payload: row.payload,
      owner: row.lease_owner, generation: BigInt(row.lease_generation), attemptCount: row.attempt_count };
  }

  async complete(lease: OutboxLease): Promise<boolean> {
    return this.fencedUpdate(lease, `UPDATE foundation.outbox_events
      SET status='EXPANDED',lease_owner=NULL,lease_expires_at=NULL,last_error_code=NULL
      WHERE id=$1 AND status='PENDING' AND lease_owner=$2 AND lease_generation=$3
        AND lease_expires_at>clock_timestamp()`);
  }

  async retry(lease: OutboxLease): Promise<boolean> {
    return this.fencedUpdate(lease, `UPDATE foundation.outbox_events SET
      status=CASE WHEN attempt_count >= $4 THEN 'FAILED' ELSE 'PENDING' END,
      last_error_code=CASE WHEN attempt_count >= $4 THEN 'ATTEMPTS_EXHAUSTED' ELSE 'HANDLER_FAILED' END,
      next_attempt_at=clock_timestamp()+LEAST(30000,power(2,LEAST(attempt_count-1,5))*1000)::int*interval '1 millisecond',
      lease_owner=NULL,lease_expires_at=NULL
      WHERE id=$1 AND status='PENDING' AND lease_owner=$2 AND lease_generation=$3
        AND lease_expires_at>clock_timestamp()`, [maxAttempts]);
  }

  private async fencedUpdate(lease: OutboxLease, sql: string, extra: readonly number[] = []): Promise<boolean> {
    if (this.closing) { return false; }
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const keys = [lease.id, lease.owner, lease.generation.toString()];
      // Lock first, then read the database clock in a separate statement. A
      // predicate evaluated before lock contention must not authorize an expired lease.
      const locked = await client.query(`SELECT id FROM foundation.outbox_events
        WHERE id=$1 AND status='PENDING' AND lease_owner=$2 AND lease_generation=$3 FOR UPDATE`, keys);
      const result = locked.rowCount === 1 ? await client.query(sql, [...keys, ...extra]) : undefined;
      await client.query('COMMIT');
      return result?.rowCount === 1;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally { client.release(); }
  }

  async close(): Promise<void> {
    if (this.closing) { return; }
    this.closing = true;
    await this.pool.end();
  }
}
