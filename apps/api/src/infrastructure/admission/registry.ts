/**
 * One-time launch proof registry (docs/P05-PLAN.md §7, "Однократный admission").
 *
 * Runs on a separate operator-owned control database; the caller passes the
 * pg connection (a dedicated Client or a checked-out PoolClient). The registry
 * is operator-only: DDL and data live in the `launch_control` schema with no
 * PUBLIC grants — the caller connects as the owner. This module never creates
 * pools and holds no credentials.
 *
 * Immutable key: (issuer_generation, launch_nonce). Issue is INSERT state
 * 'ISSUED' with the expiry stored in the row (future-dated, guard-checked);
 * consumption is exactly one conditional UPDATE 'ISSUED'→'CONSUMED'
 * behind FOR UPDATE, single-winner CAS with a confirmed COMMIT. A database
 * trigger rejects every other INSERT/UPDATE shape (SQLSTATE 23514). Every
 * write transaction forces synchronous_commit = on (plan §7).
 */
import type { PoolClient } from 'pg';

/** Minimal pg-like statement executor: a dedicated Client or checked-out PoolClient. */
export interface ControlStatement {
  query: PoolClient['query'];
}

export type RegistryErrorCode = 'ALREADY_ISSUED' | 'CAS_FAILED' | 'DIGEST_MISMATCH' | 'COMMIT_UNKNOWN';

export class RegistryError extends Error {
  readonly code: RegistryErrorCode;

  constructor(code: RegistryErrorCode, message: string) {
    super(message);
    this.name = 'RegistryError';
    this.code = code;
  }
}

export interface RegistryRow {
  readonly issuer_generation: string | number;
  readonly launch_nonce: string;
  readonly proof_digest: string;
  readonly consumer_kind: string;
  readonly instance_id: string;
  readonly channel_id: string;
  readonly state: string;
  readonly issued_at: Date;
  readonly expires_at: Date;
  readonly consumed_at: Date | null;
}

// A connection whose COMMIT outcome is indeterminate must be discarded by its
// owner. Never allow a subsequent operation through this registry on it.
const uncertainConnections = new WeakSet<ControlStatement>();

function requireKnownConnection(client: ControlStatement): void {
  if (uncertainConnections.has(client)) {
    throw new RegistryError('COMMIT_UNKNOWN', 'Discard control connection after unconfirmed COMMIT');
  }
}

async function confirmCommit(client: ControlStatement): Promise<void> {
  try {
    const result = await client.query('COMMIT');
    if (result.command === 'COMMIT') { return; }
  } catch {
    // Neither a driver failure nor an unexpected command tag is a positive ACK.
  }
  uncertainConnections.add(client);
  throw new RegistryError('COMMIT_UNKNOWN', 'Launch registry COMMIT was not confirmed');
}

function pgErrorCode(error: unknown): string | undefined {
  if (typeof error === 'object' && error !== null && 'code' in error) {
    const code = (error as { readonly code: unknown }).code;
    return typeof code === 'string' ? code : undefined;
  }
  return undefined;
}

/**
 * Creates the control schema, the launch_proofs table and the transition
 * guard. Idempotent; must run connected as the operator owner of the control
 * database. No PUBLIC/runtime grants are given; the caller grants the narrow
 * launcher role separately (schema USAGE + SELECT/INSERT + UPDATE of the
 * state/consumed_at columns only — never DELETE, TRUNCATE, or DDL).
 */
export async function ensureLaunchRegistry(client: ControlStatement): Promise<void> {
  await client.query(`
    CREATE SCHEMA IF NOT EXISTS launch_control;
    REVOKE ALL ON SCHEMA launch_control FROM PUBLIC;
    CREATE TABLE IF NOT EXISTS launch_control.launch_proofs (
      issuer_generation bigint NOT NULL,
      launch_nonce uuid NOT NULL,
      proof_digest varchar(64) NOT NULL,
      consumer_kind varchar(12) NOT NULL,
      instance_id uuid NOT NULL,
      channel_id uuid NOT NULL,
      state varchar(16) NOT NULL DEFAULT 'ISSUED' CHECK (state IN ('ISSUED','CONSUMED')),
      issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
      expires_at timestamptz NOT NULL,
      consumed_at timestamptz,
      PRIMARY KEY (issuer_generation, launch_nonce)
    );
    REVOKE ALL ON launch_control.launch_proofs FROM PUBLIC;
    CREATE OR REPLACE FUNCTION launch_control.guard_transition() RETURNS trigger
      LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog
      AS $guard$
      BEGIN
        IF TG_OP = 'INSERT' THEN
          IF NEW.state <> 'ISSUED' OR NEW.consumed_at IS NOT NULL
            OR NEW.expires_at <= clock_timestamp() THEN
            RAISE EXCEPTION 'invalid launch proof issue' USING ERRCODE = '23514';
          END IF;
        ELSE
          IF OLD.state <> 'ISSUED' OR NEW.state <> 'CONSUMED' OR NEW.consumed_at IS NULL
            OR NEW.consumed_at < OLD.issued_at OR NEW.consumed_at >= OLD.expires_at
            OR clock_timestamp() >= OLD.expires_at THEN
            RAISE EXCEPTION 'invalid launch proof transition' USING ERRCODE = '23514';
          END IF;
          IF NEW.issuer_generation IS DISTINCT FROM OLD.issuer_generation
            OR NEW.launch_nonce IS DISTINCT FROM OLD.launch_nonce
            OR NEW.proof_digest IS DISTINCT FROM OLD.proof_digest
            OR NEW.consumer_kind IS DISTINCT FROM OLD.consumer_kind
            OR NEW.instance_id IS DISTINCT FROM OLD.instance_id
            OR NEW.channel_id IS DISTINCT FROM OLD.channel_id
            OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
            OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
            RAISE EXCEPTION 'immutable launch proof columns' USING ERRCODE = '23514';
          END IF;
        END IF;
        RETURN NEW;
      END
      $guard$;
    DROP TRIGGER IF EXISTS launch_proof_guard ON launch_control.launch_proofs;
    CREATE TRIGGER launch_proof_guard
      BEFORE INSERT OR UPDATE ON launch_control.launch_proofs
      FOR EACH ROW EXECUTE FUNCTION launch_control.guard_transition();
    -- The guard is trigger-only: no direct EXECUTE for PUBLIC/launcher (a
    -- trigger fired by the table still runs it; explicit calls cannot).
    REVOKE EXECUTE ON FUNCTION launch_control.guard_transition() FROM PUBLIC;`);
}

export interface IssueProofInput {
  readonly issuerGeneration: number;
  readonly launchNonce: string;
  readonly proofDigest: string;
  readonly consumerKind: string;
  readonly instanceId: string;
  readonly channelId: string;
  /** Expiry stored in the registry row; the guard requires it in the future. */
  readonly expiresAt: Date;
}

/**
 * Records one issued proof (state 'ISSUED') with its expiry stored in the row.
 * A unique violation on the immutable key is reported as
 * RegistryError('ALREADY_ISSUED') after an explicit ROLLBACK, so no partial
 * state remains. The transaction forces synchronous_commit = on (plan §7) so
 * the confirmed COMMIT is durable on the control database.
 */
export async function issueProof(client: ControlStatement, input: IssueProofInput): Promise<void> {
  requireKnownConnection(client);
  await client.query('BEGIN');
  try {
    await client.query('SET LOCAL synchronous_commit = on');
    await client.query(`INSERT INTO launch_control.launch_proofs
      (issuer_generation, launch_nonce, proof_digest, consumer_kind, instance_id, channel_id, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [input.issuerGeneration, input.launchNonce, input.proofDigest,
      input.consumerKind, input.instanceId, input.channelId, input.expiresAt]);
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    if (pgErrorCode(error) === '23505') {
      throw new RegistryError('ALREADY_ISSUED', 'Launch nonce already issued');
    }
    throw error;
  }
  await confirmCommit(client);
}

export interface ConsumeProofInput {
  readonly issuerGeneration: number;
  readonly launchNonce: string;
  readonly expectedDigest: string;
  /** Exact binding of the row to the verified proof (round-5 audit MUST 2):
   * the consumed row must carry the verified consumer kind, instance and
   * channel — a row issued for another consumer/instance/channel can never
   * be consumed with this proof, even if digest and nonce match. */
  readonly binding: {
    readonly consumerKind: string;
    readonly instanceId: string;
    readonly channelId: string;
  };
}

/**
 * Single-winner CAS consumption. READ COMMITTED; exact row FOR UPDATE; the
 * next statement is one conditional UPDATE ISSUED→CONSUMED that also requires
 * the exact digest, the exact verified binding (consumer/instance/channel)
 * and clock_timestamp() < the row's stored expires_at (the expiry is the
 * registry's own, not a caller-supplied deadline). Returns true only when
 * exactly one row was updated AND the COMMIT was confirmed. Returns false for
 * an unknown/absent/expired/superseded row with no partial state; an expired
 * row simply stays ISSUED. Digest mismatch on a present row rejects with
 * RegistryError('DIGEST_MISMATCH'). Connection or transaction failure rejects
 * with RegistryError('CAS_FAILED'). The transaction forces synchronous_commit
 * = on (plan §7) so the confirmed COMMIT is durable.
 */
export async function consumeProof(client: ControlStatement, input: ConsumeProofInput): Promise<boolean> {
  return (await consumeProofWithExpiry(client, input)) !== undefined;
}

/** Returns the winning row's expiry only after a confirmed COMMIT. On
 * COMMIT_UNKNOWN the caller must discard the connection and the waiting launch. */
export async function consumeProofWithExpiry(client: ControlStatement, input: ConsumeProofInput): Promise<Date | undefined> {
  requireKnownConnection(client);
  let expiresAt: Date;
  try {
    await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
    await client.query('SET LOCAL synchronous_commit = on');
    const selected = await client.query<{ state: string; proof_digest: string }>(
      `SELECT state, proof_digest FROM launch_control.launch_proofs
       WHERE issuer_generation = $1 AND launch_nonce = $2 FOR UPDATE`,
      [input.issuerGeneration, input.launchNonce]);
    const row = selected.rows[0];
    if (!row) {
      await client.query('ROLLBACK');
      return undefined;
    }
    if (row.proof_digest !== input.expectedDigest) {
      await client.query('ROLLBACK');
      throw new RegistryError('DIGEST_MISMATCH', 'Launch proof digest mismatch');
    }
    const consumed = await client.query<{ expires_at: Date }>(
      `UPDATE launch_control.launch_proofs
       SET state = 'CONSUMED', consumed_at = clock_timestamp()
       WHERE issuer_generation = $1 AND launch_nonce = $2 AND state = 'ISSUED'
         AND proof_digest = $3 AND clock_timestamp() < expires_at
         AND consumer_kind = $4 AND instance_id = $5::uuid AND channel_id = $6::uuid
       RETURNING expires_at`,
      [input.issuerGeneration, input.launchNonce, input.expectedDigest,
        input.binding.consumerKind, input.binding.instanceId, input.binding.channelId]);
    if (consumed.rowCount !== 1) {
      await client.query('ROLLBACK');
      return undefined;
    }
    const expiry = consumed.rows[0]?.expires_at;
    if (!(expiry instanceof Date) || !Number.isFinite(expiry.getTime())) { throw new Error('Invalid registry expiry'); }
    expiresAt = expiry;
  } catch (error) {
    if (error instanceof RegistryError) { throw error; }
    await client.query('ROLLBACK').catch(() => undefined);
    throw new RegistryError('CAS_FAILED', 'Launch proof consumption failed');
  }
  await confirmCommit(client);
  return expiresAt;
}

/** Read-only registry state, for tests and operator teardown. */
export async function readRegistryState(
  client: ControlStatement,
  issuerGeneration: number,
  launchNonce: string,
): Promise<RegistryRow | undefined> {
  requireKnownConnection(client);
  const result = await client.query<RegistryRow>(
    `SELECT issuer_generation, launch_nonce, proof_digest, consumer_kind, instance_id, channel_id,
       state, issued_at, expires_at, consumed_at
     FROM launch_control.launch_proofs
     WHERE issuer_generation = $1 AND launch_nonce = $2`,
    [issuerGeneration, launchNonce]);
  return result.rows[0];
}
