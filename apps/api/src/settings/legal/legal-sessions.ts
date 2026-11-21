/**
 * Pre-submit consent anchor (`request_sessions`).
 *
 * This is the *minimal* anchor: a SHA-256 secret hash, the intake city and its
 * reviewed version, a database `created_at` and an expiry supplied explicitly by
 * the caller's trusted policy. There is no default TTL anywhere in this module and
 * no name, phone, address, request or customer column: the anchor identifies a
 * browser session for evidence purposes and nothing else. Issuing the raw token
 * once is the caller's (P05) responsibility; this module never generates, logs,
 * returns or stores it.
 *
 * Two proof styles are accepted by evidence operations:
 *
 * - a raw token presented by the server-side caller: it is hashed and compared in
 *   constant time with the stored digest;
 * - a capability-like `TrustedSessionProof` constructed by another mandatory
 *   trusted port that already authenticated the anchor. Its brand is a module-local
 *   symbol, so a plain `{sessionId}` object (or a browser UUID) can never satisfy it.
 *
 * Expiry and revocation are always evaluated against the *database* clock, so a
 * skewed application host cannot extend an anchor's life.
 */
import { randomUUID } from 'node:crypto';
import { LegalPortError } from './legal-contract.js';
import type {
  LegalSqlClient, RequestSessionReceipt, RequestSessionRevocation, SessionProof,
} from './legal-contract.js';
import { isTrustedSessionProof } from './legal-contract.js';
import { writeLegalAudit } from './legal-audit.js';
import { guard } from './legal-errors.js';
import { sessionSecretMatches } from './legal-hash.js';
import { requestSessionInput, uuidValue } from './legal-input.js';
import { assertCallerTransaction } from './legal-tx.js';

export type RequestSessionRow = {
  id: string;
  secret_hash: string;
  intake_city_id: string;
  intake_city_version_id: string;
  created_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
  /** Database clock sampled in the same statement as the row. */
  db_now: Date;
};

const SESSION_COLUMNS = 's.id,s.secret_hash,s.intake_city_id,s.intake_city_version_id,s.created_at,s.expires_at,s.revoked_at';

/**
 * Creates one anchor. `secretHash` is the digest of a raw token the caller issued
 * once; a raw token is not accepted here, so a caller mistake cannot persist a
 * bearer secret. `expiresAt` is mandatory and must be in the future relative to the
 * database clock (the schema CHECK additionally enforces `expires_at > created_at`).
 */
export async function createRequestSession(
  client: LegalSqlClient, input: unknown,
): Promise<RequestSessionReceipt> {
  const parsed = requestSessionInput(input);
  await assertCallerTransaction(client);
  const result = await guard(() => client.query<{ id: string; created_at: Date; expires_at: Date }>(
    `INSERT INTO foundation.request_sessions
       (id,secret_hash,intake_city_id,intake_city_version_id,expires_at)
     VALUES ($1,$2,$3,$4,$5)
     RETURNING id,created_at,expires_at`,
    [randomUUID(), parsed.secretHash, parsed.intakeCityId, parsed.intakeCityVersionId, parsed.expiresAt],
  ));
  const row = result.rows[0];
  if (!row) {
    throw new LegalPortError('CONFLICT');
  }
  await writeLegalAudit(client, 'REQUEST_SESSION_CREATED', {
    sessionId: row.id, cityId: parsed.intakeCityId, cityVersionId: parsed.intakeCityVersionId,
  });
  return { sessionId: row.id, createdAt: row.created_at.toISOString(), expiresAt: row.expires_at.toISOString() };
}

/**
 * Loads one anchor and its database clock. `FOR UPDATE` is the first step of the
 * mandated session → document lock order: every consent write locks the anchor
 * before it touches the document, so a revoke and a GIVEN of the same anchor
 * serialize instead of interleaving.
 */
export async function lockRequestSession(
  client: LegalSqlClient, sessionId: string,
): Promise<RequestSessionRow | null> {
  await assertCallerTransaction(client);
  const result = await guard(() => client.query<RequestSessionRow>(
    `SELECT ${SESSION_COLUMNS}, clock_timestamp() AS db_now
     FROM foundation.request_sessions s WHERE s.id=$1 FOR UPDATE`,
    [uuidValue(sessionId)],
  ));
  return result.rows[0] ?? null;
}

/** Read-only variant of `lockRequestSession` (no row lock). */
export async function readRequestSession(
  client: LegalSqlClient, sessionId: string,
): Promise<RequestSessionRow | null> {
  const result = await guard(() => client.query<RequestSessionRow>(
    `SELECT ${SESSION_COLUMNS}, clock_timestamp() AS db_now
     FROM foundation.request_sessions s WHERE s.id=$1`,
    [uuidValue(sessionId)],
  ));
  return result.rows[0] ?? null;
}

/** Typed anchor state derived from a locked row. */
export type AnchorState = 'LIVE' | 'EXPIRED' | 'REVOKED';

export function anchorState(row: RequestSessionRow): AnchorState {
  if (row.revoked_at !== null) {
    return 'REVOKED';
  }
  // The comparison is done in SQL-returned values against the same statement's
  // database clock, never against `Date.now()` on the application host.
  return row.expires_at.getTime() > row.db_now.getTime() ? 'LIVE' : 'EXPIRED';
}

/**
 * Proves the caller may act on this anchor and returns the locked row.
 *
 * A wrong raw token and a non-existent anchor are the same `NOT_FOUND`: the port
 * must not become an oracle for which session ids exist. A *correct* token gets a
 * precise refusal for expiry/revocation, which is information the holder of the
 * token is entitled to and which intake has to render.
 */
export async function requireLiveAnchor(
  client: LegalSqlClient, proof: SessionProof,
): Promise<RequestSessionRow> {
  const sessionId = uuidValue(proof.sessionId);
  const row = await lockRequestSession(client, sessionId);
  if (row === null) {
    throw new LegalPortError('NOT_FOUND');
  }
  if (isTrustedSessionProof(proof)) {
    // Trusted server proof: another mandatory port already authenticated this
    // anchor. The anchor state is still re-checked here on the database clock.
  } else if (!sessionSecretMatches(proof.token, row.secret_hash)) {
    // Indistinguishable from a missing anchor on purpose.
    throw new LegalPortError('NOT_FOUND');
  }
  const state = anchorState(row);
  if (state === 'REVOKED') {
    throw new LegalPortError('SESSION_REVOKED');
  }
  if (state === 'EXPIRED') {
    throw new LegalPortError('SESSION_EXPIRED');
  }
  return row;
}

/**
 * Re-samples the database clock and re-checks a *locked* anchor.
 *
 * `requireLiveAnchor` compares `expires_at` with the clock sampled by the same
 * statement that locked the anchor. Every consent write then takes a second lock
 * (the legal document), and that wait can be arbitrarily long: a GIVEN that started
 * while the anchor was live could otherwise commit after the expiry has passed.
 * Calling this after the document lock closes that window, so "live anchor" is
 * true at the moment the event is written, not only when the wait began.
 *
 * Only the clock is re-read: identity, hash, expiry and revocation of a locked
 * anchor cannot change (the 013 guard makes them immutable, and the row lock is
 * held), so `revoked_at` is checked for completeness rather than re-verified.
 */
export async function assertAnchorLiveAfterLock(
  client: LegalSqlClient, anchor: RequestSessionRow,
): Promise<void> {
  if (anchor.revoked_at !== null) {
    throw new LegalPortError('SESSION_REVOKED');
  }
  const clock = await guard(() => client.query<{ db_now: Date }>('SELECT clock_timestamp() AS db_now'));
  const now = clock.rows[0]?.db_now;
  if (!now) {
    throw new LegalPortError('CONFLICT');
  }
  if (anchor.expires_at.getTime() <= now.getTime()) {
    throw new LegalPortError('SESSION_EXPIRED');
  }
}

/**
 * Proves ownership of an anchor without requiring it to be live, for a read that
 * must still be possible after the intake window closed.
 *
 * The raw token is verified against the stored digest exactly as in
 * `requireLiveAnchor`; a wrong token is `NOT_FOUND`. Expiry and revocation are
 * deliberately *not* refused here: a person (or the staff surface acting for them)
 * is entitled to read the evidence this anchor produced after it expired, and the
 * write paths still refuse a dead anchor. Reads take no row lock.
 */
export async function requireAnchorProof(
  client: LegalSqlClient, proof: SessionProof,
): Promise<RequestSessionRow> {
  await assertCallerTransaction(client);
  const sessionId = uuidValue(proof.sessionId);
  const row = await readRequestSession(client, sessionId);
  if (row === null) {
    throw new LegalPortError('NOT_FOUND');
  }
  if (!isTrustedSessionProof(proof) && !sessionSecretMatches(proof.token, row.secret_hash)) {
    throw new LegalPortError('NOT_FOUND');
  }
  return row;
}

/**
 * One-shot revoke of an anchor. The first call stamps `revoked_at` with the
 * database clock; a repeat call with the same (correct) proof reports
 * `replayed: true` and changes nothing, so an idempotent caller cannot extend or
 * rewrite the revocation instant. A wrong token is `NOT_FOUND` exactly as above.
 */
export async function revokeRequestSession(
  client: LegalSqlClient, proof: SessionProof,
): Promise<RequestSessionRevocation> {
  const sessionId = uuidValue(proof.sessionId);
  const row = await lockRequestSession(client, sessionId);
  if (row === null) {
    throw new LegalPortError('NOT_FOUND');
  }
  if (!isTrustedSessionProof(proof) && !sessionSecretMatches(proof.token, row.secret_hash)) {
    throw new LegalPortError('NOT_FOUND');
  }
  if (row.revoked_at !== null) {
    return { sessionId: row.id, revokedAt: row.revoked_at.toISOString(), replayed: true };
  }
  const updated = await guard(() => client.query<{ revoked_at: Date }>(
    `UPDATE foundation.request_sessions SET revoked_at=clock_timestamp()
     WHERE id=$1 AND revoked_at IS NULL RETURNING revoked_at`,
    [sessionId],
  ));
  const revoked = updated.rows[0];
  if (!revoked) {
    // A concurrent revoke won the row lock first; report the persisted instant.
    const current = await readRequestSession(client, sessionId);
    if (current === null || current.revoked_at === null) {
      throw new LegalPortError('CONFLICT');
    }
    return { sessionId, revokedAt: current.revoked_at.toISOString(), replayed: true };
  }
  await writeLegalAudit(client, 'REQUEST_SESSION_REVOKED', { sessionId });
  return { sessionId, revokedAt: revoked.revoked_at.toISOString(), replayed: false };
}
