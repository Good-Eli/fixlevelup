/**
 * P03-04 slice A: the internal, no-byte file-upload reservation contract.
 *
 * This module owns exactly one thing: the *reservation* of a future upload by an
 * F-owned request session. It does not read or write object storage, does not
 * issue a signed URL, does not stream, does not create a file row, does not grant
 * access and never marks anything READY. There is no S3 client, no scanner, no
 * HTTP controller, no NestJS provider, no DI token and no authentication
 * decorator in this module; the caller opens the transaction and supplies the
 * trusted inputs (raw pre-submit session token, reviewed policy snapshot,
 * declared size/MIME, explicit expiry, idempotency key).
 *
 * ## What is authoritative
 *
 * - the caller's explicit READ COMMITTED transaction (see `legal-tx.ts`, reused);
 * - the raw session token hashed and compared against `request_sessions`;
 * - the *current* `REQUEST_PROCESSING` GIVEN consent of that exact session;
 * - the reviewed policy snapshot passed by trusted configuration (there is no
 *   default policy anywhere in this module);
 * - the database clock and the database guard (migration 014), which is the
 *   second, independent line of defence for liveness/consent/expiry/quota.
 *
 * ## What is never authority
 *
 * A browser-supplied session id, a staff id taken from a request body, a client
 * clock, a hash (a hash is integrity evidence, not permission) and any value the
 * module would have to default.
 *
 * ## Owner vocabulary
 *
 * Slice A implements the F-owned variant only (`request_sessions`). The schema
 * carries `owner_staff_id` for the future staff workflow, but this port refuses a
 * staff-owner request with `UNSUPPORTED_OWNER` before any database access: a
 * staff id in a request body is never a credential and the staff command with
 * real authorization belongs to P03-05.
 */
import type { PoolClient } from 'pg';

/**
 * Closed MIME vocabulary for slice A. This is a *bounded known* set used for the
 * policy snapshot and for input narrowing; it is not permission to upload or
 * serve any of these types, and the actual signature/bytes check belongs to slice
 * B. SVG/HTML/executables are deliberately absent: they must never be treated as
 * trusted inline content.
 */
export const FILE_MIME_TYPES = ['application/pdf', 'image/jpeg', 'image/png', 'image/webp'] as const;
export type FileMimeType = (typeof FILE_MIME_TYPES)[number];

/** The only states slice A can persist. There is no READY/UPLOADING/DELETED here. */
export const FILE_INTENT_STATES = ['RESERVED', 'CANCELLED'] as const;
export type FileIntentState = (typeof FILE_INTENT_STATES)[number];

/** The one consent purpose a file reservation may consume. Purposes are separate. */
export const FILE_RESERVATION_PURPOSE = 'REQUEST_PROCESSING' as const;
export type FileReservationPurpose = typeof FILE_RESERVATION_PURPOSE;

/**
 * Minimal `PoolClient` surface: exactly `query`. The caller's transaction is the
 * only connection this module can use; `pg.PoolClient` satisfies it directly.
 */
export type FileReservationSqlClient = Pick<PoolClient, 'query'>;

/**
 * Typed refusal codes. `message` is the code itself, so a failure can never echo
 * a submitted token, a source reference, a legal basis, a hash or a size.
 *
 * - `INVALID_INPUT` — malformed caller input (shape, unknown key, MIME outside the
 *   closed vocabulary, non-positive/unsafe number, expiry in the past).
 * - `NOT_CONFIGURED` — the trusted policy snapshot is absent or unusable. Raised
 *   before any intent/audit/outbox insert; nothing is written.
 * - `UNSUPPORTED_OWNER` — a staff-owner request. Slice A has no staff path.
 * - `NOT_FOUND` — a single safe answer for a missing *or* foreign session/intent;
 *   it never reveals whether somebody else's row exists.
 * - `IDEMPOTENCY_CONFLICT` — the same owner/key was used with a different payload.
 * - `QUOTA_EXCEEDED` — the owner's pending RESERVED bytes/count would exceed the
 *   policy snapshot.
 * - `STALE_VERSION` — cancel CAS failed; the caller must re-read.
 * - `INTENT_CANCELLED` / `INTENT_EXPIRED` — a replay of a dead intent; it is never
 *   revived.
 * - `SESSION_EXPIRED` / `SESSION_REVOKED` — the anchor is dead on the database clock.
 * - `CONSENT_*` — no current exact `REQUEST_PROCESSING` GIVEN basis.
 * - `POLICY_VERSION_CONFLICT` — the same policy version id arrived with a
 *   different canonical hash for the same owner; immutable versions must not
 *   contradict an already stored snapshot.
 * - `INVALID_REFERENCE` / `ALREADY_EXISTS` / `CONFLICT` — driver-level integrity,
 *   duplicate and retryable concurrency refusals.
 */
export type FileReservationErrorCode =
  | 'INVALID_INPUT'
  | 'NOT_CONFIGURED'
  | 'UNSUPPORTED_OWNER'
  | 'NOT_FOUND'
  | 'IDEMPOTENCY_CONFLICT'
  | 'QUOTA_EXCEEDED'
  | 'STALE_VERSION'
  | 'INTENT_CANCELLED'
  | 'INTENT_EXPIRED'
  | 'SESSION_EXPIRED'
  | 'SESSION_REVOKED'
  | 'CONSENT_NOT_GIVEN'
  | 'CONSENT_REVOKED'
  | 'CONSENT_NOT_CURRENT'
  | 'CONSENT_NOT_PUBLISHED'
  | 'POLICY_VERSION_CONFLICT'
  | 'INVALID_REFERENCE'
  | 'ALREADY_EXISTS'
  | 'CONFLICT';

export class FileReservationError extends Error {
  readonly code: FileReservationErrorCode;

  constructor(code: FileReservationErrorCode) {
    super(code);
    this.name = 'FileReservationError';
    this.code = code;
  }
}

/**
 * A raw pre-submit session token plus the anchor id. This is the only proof the
 * file ports accept: the module hashes the token and compares it with the stored
 * digest. A capability-like `TrustedSessionProof` from the legal module is
 * deliberately *not* accepted here — the file surface must not be able to skip
 * the raw token check.
 */
export interface FileOwnerSessionProof {
  readonly sessionId: string;
  readonly token: string;
}

/**
 * Trusted, reviewed policy snapshot for one file-upload policy version.
 *
 * Mandatory, closed and fully typed: there are no optional fields and no
 * defaults. It is supplied by trusted server configuration (never by a public
 * request body), validated by the port itself, and its canonical SHA-256 is
 * persisted with every intent so a stored reservation can be proven to belong to
 * exactly this snapshot.
 */
export interface FileReservationPolicy {
  /** Reviewed policy version id (UUID). */
  readonly versionId: string;
  /** Reviewed source reference of the policy text (bounded, stored verbatim). */
  readonly sourceRef: string;
  /** Non-empty closed subset of `FILE_MIME_TYPES`; no duplicates. */
  readonly allowedMimeTypes: readonly FileMimeType[];
  /** Per-file byte ceiling. */
  readonly maxFileBytes: number;
  /** Per-owner byte ceiling; must be >= `maxFileBytes`. */
  readonly maxOwnerBytes: number;
  /** Per-owner pending reservation count ceiling. */
  readonly maxOwnerFiles: number;
  /** Policy expiry; a reservation may never outlive it. */
  readonly expiresAt: Date | string;
}

/** Safe, non-secret projection of one reservation. */
export interface FileUploadIntentView {
  readonly intentId: string;
  readonly state: FileIntentState;
  readonly rowVersion: number;
  readonly declaredMime: FileMimeType;
  readonly declaredBytes: number;
  readonly expiresAt: string;
  readonly createdAt: string;
  readonly policyVersionId: string;
  readonly policySourceRef: string;
  /** Canonical SHA-256 of the policy snapshot the intent was reserved under. */
  readonly policySha256: string;
  readonly consentEvidenceId: string;
  readonly consentDocumentVersionId: string;
  readonly consentPurpose: FileReservationPurpose;
  readonly cancelledAt: string | null;
}

/** Reserve receipt: the view plus whether this call was an idempotent replay. */
export interface FileUploadReservation extends FileUploadIntentView {
  readonly replayed: boolean;
}

/**
 * Minimal cancel receipt: the fact of the withdrawal and nothing else.
 *
 * Cancel is a pure withdrawal, so it deliberately does not run the read guard: it
 * must still work after the person withdrew consent and after the policy snapshot
 * or the reservation itself expired. The receipt therefore must not carry the read
 * projection (declared MIME/bytes, policy version/hash/source, consent basis,
 * created/expires timestamps): returning that metadata from a call whose read path
 * is denied at that moment would leak through the cancel door exactly what
 * `readFileUploadIntent` refuses. Only the intent identity, its terminal state, the
 * CAS version, the database-stamped cancellation time and the replay flag remain,
 * and the shape is identical for the first cancel and for a repeat.
 */
export interface FileUploadCancellation {
  readonly intentId: string;
  readonly state: 'CANCELLED';
  readonly rowVersion: number;
  /** Database-stamped cancellation instant, ISO-8601 UTC; never null. */
  readonly cancelledAt: string;
  readonly replayed: boolean;
}

/* ------------------------------ input shapes ------------------------------ */

/**
 * Documented accepted shape of each port input.
 *
 * The port *signatures* deliberately take `unknown`, not these types: the runtime
 * parser is the mandatory gate and cannot be forgotten or bypassed by a cast, and
 * the same parser is what produces the typed refusals. These interfaces exist so
 * a caller has an exact, reviewed shape to build (and so a new field added here
 * without a matching parser entry is an obvious review point), not to assert that
 * an unvalidated object is safe.
 */
export interface ReserveFileUploadInput {
  readonly session: FileOwnerSessionProof;
  readonly policy: FileReservationPolicy;
  readonly declaredMime: FileMimeType;
  readonly declaredBytes: number;
  readonly expiresAt: Date | string;
  readonly idempotencyKey: string;
}

export interface ReadFileUploadIntentInput {
  readonly session: FileOwnerSessionProof;
  readonly intentId: string;
}

export interface CancelFileUploadIntentInput {
  readonly session: FileOwnerSessionProof;
  readonly intentId: string;
  /** CAS token: the `rowVersion` the caller last read. */
  readonly expectedVersion: number;
}
