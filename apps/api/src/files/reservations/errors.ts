/**
 * Single translation point from driver/legal failures to the typed reservation
 * refusals. Nothing here echoes driver text, SQL, submitted values or secrets.
 *
 * The interesting cases:
 *
 * - 23505 on a partial idempotency index is `IDEMPOTENCY_CONFLICT`; any other
 *   unique violation is `ALREADY_EXISTS`.
 * - 23503 is a caller-supplied reference that does not fit (`INVALID_REFERENCE`).
 * - 23514 (CHECK/trigger guard) is `INVALID_INPUT` unless the guard names a quota
 *   or idempotency rule, in which case the precise code is returned. The database
 *   guard is the second line of defence; the TypeScript checks under the session
 *   lock normally produce the precise refusal first.
 * - 25001 (a transaction that already pinned a stronger snapshot) and
 *   40001/40P01/55P03 (serialization/deadlock/lock timeout) are the retryable
 *   `CONFLICT`: the caller must retry in a fresh READ COMMITTED transaction, never
 *   reuse the aborted one.
 *
 * Legal-port refusals are translated to the same vocabulary so a caller never has
 * to catch two error classes: a wrong token and a foreign row stay one `NOT_FOUND`,
 * and a stale/revoked/missing consent stays a precise `CONSENT_*` code.
 */
import { LegalPortError } from '../../settings/legal/legal-contract.js';
import { FileReservationError } from './contract.js';
import type { FileReservationErrorCode } from './contract.js';

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

/**
 * Maps a migration-014 guard constraint name to the closest typed refusal.
 *
 * The database guard is the *second* line of defence and its constraint names are
 * coarser than the port's own pre-checks: one name can cover several situations.
 * This mapping is therefore only used on the bypass path (a caller that reached
 * the INSERT without the port's checks), and it must not be documented as exact:
 *
 * - `*_session` covers a revoked *and* an expired anchor (one constraint name, two
 *   RAISE sites), so it maps to `SESSION_EXPIRED`; the precise
 *   `SESSION_REVOKED`/`SESSION_EXPIRED` comes from the legal port pre-check.
 * - `*_policy` covers an expired policy, `expires_at > policy_expires_at` and
 *   `expires_at > anchor.expires_at`, so it maps to `NOT_CONFIGURED`.
 * - `*_expiry` covers `expires_at <= DB clock`, so it maps to `INTENT_EXPIRED`.
 * - `*_state_transition` covers any transition other than RESERVED→CANCELLED
 *   (including a direct READY attempt), so it maps to `STALE_VERSION`.
 * - `*_consent` covers a stale basis, a revoked GIVEN, a non-GIVEN event and a
 *   non-CONSENT_FORM document, so it maps to `CONSENT_NOT_CURRENT`.
 * - `*_quota` and `*_idempotency` are exact.
 */
function constraintCode(constraint: string | null): FileReservationErrorCode | null {
  if (constraint === null) {
    return null;
  }
  const name = constraint.toLowerCase();
  if (name.includes('idempotency')) {
    return 'IDEMPOTENCY_CONFLICT';
  }
  if (name.includes('quota')) {
    return 'QUOTA_EXCEEDED';
  }
  if (name.includes('consent')) {
    return 'CONSENT_NOT_CURRENT';
  }
  if (name.includes('policy')) {
    return 'NOT_CONFIGURED';
  }
  if (name.includes('expiry')) {
    return 'INTENT_EXPIRED';
  }
  if (name.includes('session')) {
    return 'SESSION_EXPIRED';
  }
  if (name.includes('state_transition')) {
    return 'STALE_VERSION';
  }
  return null;
}

/** Translates one database/driver failure; never returns. */
export function mapFileReservationDbError(error: unknown): never {
  if (error instanceof FileReservationError || error instanceof LegalPortError) {
    throw error;
  }
  const code = driverCode(error);
  if (code === '23505') {
    const named = constraintCode(driverConstraint(error));
    if (named === 'IDEMPOTENCY_CONFLICT') {
      throw new FileReservationError('IDEMPOTENCY_CONFLICT');
    }
    throw new FileReservationError('ALREADY_EXISTS');
  }
  if (code === '23503') {
    // The composite consent-basis FK is the one reference failure that can only mean
    // "this evidence is not this session's/version's/purpose's GIVEN": the anchor is
    // locked and proved before the INSERT, so a missing anchor cannot reach here.
    // A stale basis or a revoked GIVEN is refused by the guard as 23514 with a
    // 'consent' constraint name (CONSENT_NOT_CURRENT), which is the common path; this
    // is the bypass-path translation of the same denial.
    if (driverConstraint(error) === 'file_upload_intents_consent_basis_fkey') {
      throw new FileReservationError('CONSENT_NOT_CURRENT');
    }
    throw new FileReservationError('INVALID_REFERENCE');
  }
  if (code === '23514' || code === '23502' || code === '22001' || code === '22007' || code === '22008' || code === '22P02') {
    const named = constraintCode(driverConstraint(error));
    if (named !== null) {
      throw new FileReservationError(named);
    }
    throw new FileReservationError('INVALID_INPUT');
  }
  if (code === '40001' || code === '40P01' || code === '55P03' || code === '25001') {
    throw new FileReservationError('CONFLICT');
  }
  throw error;
}

/** Runs one database call and translates only known constraint failures. */
export async function guardFile<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    mapFileReservationDbError(error);
  }
}

/** Translates one legal-port failure into the reservation vocabulary; never returns. */
export function mapLegalPortError(error: unknown): never {
  if (error instanceof FileReservationError) {
    throw error;
  }
  if (error instanceof LegalPortError) {
    switch (error.code) {
      case 'NOT_FOUND':
        throw new FileReservationError('NOT_FOUND');
      case 'SESSION_EXPIRED':
        throw new FileReservationError('SESSION_EXPIRED');
      case 'SESSION_REVOKED':
        throw new FileReservationError('SESSION_REVOKED');
      case 'DOCUMENT_NOT_CURRENT':
        throw new FileReservationError('CONSENT_NOT_CURRENT');
      case 'DOCUMENT_NOT_PUBLISHED':
        throw new FileReservationError('CONSENT_NOT_PUBLISHED');
      case 'CONSENT_REVOKED':
        throw new FileReservationError('CONSENT_REVOKED');
      case 'INVALID_INPUT':
        throw new FileReservationError('INVALID_INPUT');
      case 'CONFLICT':
      case 'ALREADY_EXISTS':
      case 'STALE_VERSION':
      case 'INVALID_REFERENCE':
      case 'KIND_NOT_CONSENT_FORM':
      case 'REPLAY_MISMATCH':
      case 'CONSENT_ALREADY_ACTIVE':
      default:
        // A legal refusal the file surface must never reinterpret as an approval.
        throw new FileReservationError('CONFLICT');
    }
  }
  throw error;
}

/** Runs one legal-port call and translates its typed refusals. */
export async function legalCall<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    mapLegalPortError(error);
  }
}
