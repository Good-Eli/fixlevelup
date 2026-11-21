/**
 * Single translation point from driver/constraint failures to the typed legal
 * refusals. Nothing here echoes driver text, SQL, submitted values or secrets.
 *
 * Two 23505 cases are distinguished because they mean different things to the
 * caller: the idempotency key of a replay (`consent_records_session_evidence_key`)
 * versus a genuinely conflicting active GIVEN raised by the consent guard. The
 * constraint name is the only thing read from the driver error.
 *
 * 25001 (`SET TRANSACTION ISOLATION LEVEL` refused after a stronger snapshot was
 * already taken) is translated to a typed `CONFLICT` so the caller sees a safe,
 * retryable refusal instead of a raw driver error — and never a consent answer.
 */
import { LegalPortError } from './legal-contract.js';

interface DriverError {
  readonly code?: unknown;
  readonly constraint?: unknown;
}

function driverCode(error: unknown): string | null {
  if (typeof error !== 'object' || error === null) {
    return null;
  }
  const code = (error as DriverError).code;
  return typeof code === 'string' ? code : null;
}

function driverConstraint(error: unknown): string | null {
  if (typeof error !== 'object' || error === null) {
    return null;
  }
  const constraint = (error as DriverError).constraint;
  return typeof constraint === 'string' ? constraint : null;
}

/** Unique violation: a stable identity, an idempotency key or one revoke per GIVEN. */
function uniqueViolation(error: unknown): LegalPortError {
  const constraint = driverConstraint(error);
  if (constraint === 'consent_records_session_evidence_key') {
    return new LegalPortError('ALREADY_EXISTS');
  }
  if (constraint === 'consent_records_supersedes_id_key') {
    // The named GIVEN event already has its single REVOKED event.
    return new LegalPortError('CONSENT_REVOKED');
  }
  if (constraint === null) {
    // The consent guard raises a bare 23505 for a second active GIVEN of the same
    // session/purpose/document: a conflict, not a retryable duplicate key.
    return new LegalPortError('CONSENT_ALREADY_ACTIVE');
  }
  return new LegalPortError('ALREADY_EXISTS');
}

/** Foreign key / composite reference failure: a caller-supplied id does not fit. */
function referenceViolation(): LegalPortError {
  return new LegalPortError('INVALID_REFERENCE');
}

/** CHECK / type / length / range failures: the value is not acceptable. */
function invalidValue(): LegalPortError {
  return new LegalPortError('INVALID_INPUT');
}

/** Serialization/deadlock/lock timeout: retryable concurrency, not a client error. */
function retryable(): LegalPortError {
  return new LegalPortError('CONFLICT');
}

/**
 * 25001 = active_sql_transaction: `SET TRANSACTION ISOLATION LEVEL` was refused
 * because the transaction already acquired a snapshot under a stronger level. The
 * port therefore cannot prove it is deciding on current evidence, so it must fail
 * closed. `CONFLICT` is the right typed code: this is a caller-side transaction
 * mistake to retry in a fresh transaction (opened with `beginLegalTransaction`),
 * never a consent answer, so it can never surface as `GRANTED`.
 */
function isolationRefused(): LegalPortError {
  return new LegalPortError('CONFLICT');
}

export function mapLegalDbError(error: unknown): never {
  if (error instanceof LegalPortError) {
    throw error;
  }
  const code = driverCode(error);
  if (code === '23505') {
    throw uniqueViolation(error);
  }
  if (code === '23503') {
    throw referenceViolation();
  }
  if (code === '23514' || code === '22001' || code === '22007' || code === '22008' || code === '22P02') {
    throw invalidValue();
  }
  if (code === '40001' || code === '40P01' || code === '55P03') {
    throw retryable();
  }
  if (code === '25001') {
    throw isolationRefused();
  }
  throw error;
}

/** Runs one database call and translates only known constraint failures. */
export async function guard<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    mapLegalDbError(error);
  }
}
